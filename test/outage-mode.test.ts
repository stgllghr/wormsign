// soak --on-outage (src/net.ts): which network failures are an outage, and what warn does with one. An outage needs
// both a request that failed in transport (or with 429 or a 5xx) and a host that gave no answer in the whole run, nor
// to the probe after it; so one name a host will not serve, while it serves the rest, stays high. Every request goes
// through Node's own fetch to a local server, so the error a DNS, connection, TLS or timeout failure throws is the one
// Node throws in CI; the registry, the Python index and OSV keep their real URLs, which the test's fetch maps to
// 127.0.0.1. Only the DNS, certificate and broken-handshake failures, and the errors of a name with several addresses
// (localhost's), are recorded errors. No request leaves the machine: the test's fetch refuses any URL it did not map.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer as createTcpServer } from "node:net";
import type { AddressInfo, Socket } from "node:net";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { applyBaseline, NOT_BASELINABLE } from "../src/baseline.js";
import { parseLockfileText } from "../src/lockfile/index.js";
import { run } from "../src/main.js";
import { createIndexClient } from "../src/python/index.js";
import { checkSoakLockfiles } from "../src/soak.js";
import { OutageLedger, isTransientStatus, outageSummary, transportFailure } from "../src/net.js";
import { checkOsvDetailed, newOsvSession } from "../src/osv.js";
import { makeFinding } from "../src/types.js";
import { NOW, fakeIO, fx } from "./helpers.js";

const H = 3_600_000;

interface Local {
  url: string;
  close(): Promise<void>;
}

async function listen(server: { listen(port: number, host: string, cb: () => void): unknown; address(): unknown }): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return (server.address() as AddressInfo).port;
}

/** An HTTP server on 127.0.0.1 answering every request with `handler`. */
async function http(handler: (req: IncomingMessage, body: string, res: ServerResponse) => void): Promise<Local> {
  const s = createHttpServer((req, res) => {
    let body = "";
    req.on("data", (c: Buffer) => (body += c.toString("utf8")));
    req.on("end", () => handler(req, body, res));
  });
  const port = await listen(s);
  return { url: `http://127.0.0.1:${port}`, close: () => new Promise((resolve) => (s.closeAllConnections(), s.close(() => resolve()))) };
}

/** A TCP server on 127.0.0.1 that does `onConnection` with each socket, never anything HTTP unless it writes it. */
async function tcp(onConnection: (c: Socket) => void): Promise<Local> {
  const sockets = new Set<Socket>();
  const s = createTcpServer((c) => {
    sockets.add(c);
    c.on("close", () => sockets.delete(c));
    c.on("error", () => undefined);
    onConnection(c);
  });
  const port = await listen(s);
  return { url: `http://127.0.0.1:${port}`, close: () => new Promise((resolve) => { for (const c of sockets) c.destroy(); s.close(() => resolve()); }) };
}

/**
 * A TCP server's connection handler that reads the request's head (up to the blank line that ends it), then does
 * `then`, and keeps reading whatever follows. So a server that answers, breaks off or resets does it to a request in
 * flight, never to one still being written, and nothing waits on a timer. Done at once instead, on a busy machine a
 * reset races the request's write (Node 24's undici then calls setTypeOfService on a socket already reset, which throws
 * EINVAL on macOS), and a socket closed with the request still unread sends a reset, not a FIN.
 */
const afterRequest = (then: (c: Socket) => void) => (c: Socket): void => {
  let head = "";
  let done = false;
  c.on("data", (chunk: Buffer) => {
    if (done) return;
    head += chunk.toString("latin1");
    if (!head.includes("\r\n\r\n")) return;
    done = true;
    then(c);
  });
};

/** A port nothing listens on: a connection to it is refused. */
async function closedPort(): Promise<Local> {
  const s = createTcpServer();
  const port = await listen(s);
  await new Promise<void>((resolve) => s.close(() => resolve()));
  return { url: `http://127.0.0.1:${port}`, close: async () => undefined };
}

const json = (res: ServerResponse, body: unknown, status = 200, type = "application/json"): void => {
  res.writeHead(status, { "content-type": type });
  res.end(typeof body === "string" ? body : JSON.stringify(body));
};

/** OSV with no record for anything. */
const quietOsv = (): Promise<Local> =>
  http((req, body, res) => {
    if (req.url === "/v1/querybatch") json(res, { results: (JSON.parse(body) as { queries: unknown[] }).queries.map(() => ({})) });
    else json(res, {});
  });

const ORIGINS = { npm: "https://registry.npmjs.org", osv: "https://api.osv.dev", pypi: "https://pypi.org" } as const;
type Service = keyof typeof ORIGINS;

/** getaddrinfo's failure as Node 23.11's fetch throws it for a name that does not resolve. */
const dnsError = (host: string): TypeError =>
  new TypeError("fetch failed", { cause: Object.assign(new Error(`getaddrinfo ENOTFOUND ${host}`), { errno: -3008, code: "ENOTFOUND", syscall: "getaddrinfo", hostname: host }) });

/**
 * Real fetch, with each service's https origin replaced by a local URL (or by "dns", a lookup that fails). `timeoutMs`
 * replaces the request's own timeout, so a server that never answers is a timeout in milliseconds. Any URL not mapped
 * is refused with an error that is not an outage.
 */
function routed(to: Partial<Record<Service, string>>, timeoutMs?: number): typeof fetch & { calls: string[] } {
  const calls: string[] = [];
  const f = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    calls.push(`${init?.method ?? "GET"} ${url}`);
    for (const [service, origin] of Object.entries(ORIGINS) as [Service, string][]) {
      const local = to[service];
      if (local === undefined || !url.startsWith(`${origin}/`)) continue;
      if (local === "dns") throw dnsError(new URL(origin).host);
      return fetch(local + url.slice(origin.length), { ...init, ...(timeoutMs !== undefined ? { signal: AbortSignal.timeout(timeoutMs) } : {}) });
    }
    throw new Error(`the test's fetch maps no local server for ${url}`);
  }) as typeof fetch & { calls: string[] };
  f.calls = calls;
  return f;
}

function npmLock(entries: { id: string; resolved?: string }[]): string {
  const packages: Record<string, unknown> = { "": { name: "app", version: "1.0.0" } };
  for (const { id, resolved } of entries) {
    const [name, version] = id.split("@") as [string, string];
    packages[`node_modules/${name}`] = { version, resolved: resolved ?? `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`, integrity: "sha512-x" };
  }
  return JSON.stringify({ name: "app", version: "1.0.0", lockfileVersion: 3, requires: true, packages }, null, 2);
}

function tree(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "wormsign-outage-"));
  for (const [rel, text] of Object.entries(files)) writeFileSync(join(dir, rel), text);
  return dir;
}

/** A package document for `name`, its one version published `hoursAgo` hours before NOW. */
const packument = (name: string, hoursAgo = 400, integrity = "sha512-x") => ({
  name,
  time: { "1.0.0": new Date(NOW.getTime() - hoursAgo * H).toISOString() },
  versions: { "1.0.0": { dist: { integrity, tarball: `https://registry.npmjs.org/${name}/-/${name}-1.0.0.tgz` } } },
});

type Doc = { findings: { ruleId: string; severity: string; message: string; fingerprint: string; file?: string; key: string; suppressed?: unknown }[]; notes: string[] };
async function soak(dir: string, fetchImpl: typeof fetch, ...args: string[]): Promise<{ code: number; doc: Doc; out: string; err: string }> {
  const io = fakeIO({ fetchImpl, env: { HOME: mkdtempSync(join(tmpdir(), "wormsign-home-")) } });
  const code = await run(["soak", dir, "--format", "json", ...args], io);
  assert.notEqual(io.out, "", `soak printed no report (exit ${code}): ${io.err}`);
  return { code, doc: JSON.parse(io.out) as Doc, out: io.out, err: io.err };
}
const rules = (d: Doc): string[] => d.findings.map((f) => `${f.ruleId} ${f.severity}`).sort();
const unverifiedLines = (s: string): string[] => s.split("\n").filter((l) => l.startsWith("UNVERIFIED: "));

/* ---- the classifier ---- */

test("outage classifier: HTTP 429 and every 5xx are transient; 404, every other 4xx, 2xx and 3xx are not", () => {
  for (const s of [429, 500, 502, 503, 504, 599]) assert.equal(isTransientStatus(s), true, String(s));
  for (const s of [200, 202, 301, 304, 400, 401, 403, 404, 410, 418, 451, 499]) assert.equal(isTransientStatus(s), false, String(s));
});

test("outage classifier: Node's own DNS, connection, TLS-handshake and timeout failures are outages; an answer that is not HTTP or not JSON, and a certificate verdict, are not", async () => {
  const caught = async (p: Promise<unknown>): Promise<unknown> => p.then(() => assert.fail("expected a failure"), (e: unknown) => e);
  const refused = await closedPort();
  // resetAndDestroy sends a TCP RST, so the refusal is the same on every platform (a plain close can read as EOF).
  const reset = await tcp(afterRequest((c) => c.resetAndDestroy()));
  // The head and 5 of the 100 bytes it promises, then a FIN: the request was read, so the close is never a reset.
  const cut = await tcp(afterRequest((c) => c.end('HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n{"a":')));
  const silent = await tcp(() => undefined);
  const garbage = await tcp(afterRequest((c) => c.end("garbage\r\n\r\n")));
  const plain = await http((_req, _body, res) => json(res, "not json", 200, "text/plain"));
  try {
    // 127.0.0.1 is one address, so one attempt and one error; localhost is recorded below.
    assert.equal(transportFailure(await caught(fetch(refused.url))), "connection failed (ECONNREFUSED)");
    assert.equal(transportFailure(await caught(fetch(reset.url))), "connection failed (ECONNRESET)");
    // The classifier calls a cut-off body a socket failure; the clients never ask it about one after a status line.
    assert.equal(transportFailure(await caught(fetch(cut.url).then((r) => r.text()))), "connection failed (UND_ERR_SOCKET)");
    assert.match(transportFailure(await caught(fetch(plain.url.replace("http:", "https:")))) ?? "", /^TLS failed \((ERR_SSL_|EPROTO)/, "TLS to a plain-HTTP server");
    assert.equal(transportFailure(await caught(fetch(silent.url, { signal: AbortSignal.timeout(100) }))), "timed out");
    // Not outages: an answer that is not HTTP, a body that is not JSON, a URL that does not parse.
    assert.equal(transportFailure(await caught(fetch(garbage.url))), undefined);
    assert.equal(transportFailure(await caught(fetch(plain.url).then((r) => r.json()))), undefined);
    assert.equal(transportFailure(await caught(fetch("http://exa mple/"))), undefined);
  } finally {
    for (const s of [refused, reset, cut, silent, garbage, plain]) await s.close();
  }
  // Recorded shapes, each under fetch's TypeError: a lookup that fails, handshakes that broke off.
  assert.equal(transportFailure(dnsError("registry.npmjs.org")), "DNS lookup failed (ENOTFOUND)");
  // A name with several addresses, as localhost has ::1 and 127.0.0.1: Node tries each and throws an AggregateError of
  // their errors, whose code is the first's. Recorded, not live: whether localhost has one address or two is the
  // platform's, a process stalled past net's 250 ms attempt timeout records the first attempt as ETIMEDOUT, and a host
  // without IPv6 fails ::1 with EADDRNOTAVAIL, which is no transport failure, so the refusal after it decides.
  const attempt = (code: string, address: string) => Object.assign(new Error(`connect ${code} ${address}:4873`), { code, syscall: "connect", address, port: 4873 });
  const attempts = (...errors: Error[]) => new TypeError("fetch failed", { cause: Object.assign(new AggregateError(errors, ""), { code: (errors[0] as Error & { code: string }).code }) });
  assert.equal(transportFailure(attempts(attempt("ECONNREFUSED", "::1"), attempt("ECONNREFUSED", "127.0.0.1"))), "connection failed (ECONNREFUSED)", "both refused");
  assert.equal(transportFailure(attempts(attempt("ETIMEDOUT", "::1"), attempt("ECONNREFUSED", "127.0.0.1"))), "connection failed (ETIMEDOUT)", "the first attempt timed out");
  assert.equal(transportFailure(attempts(attempt("EADDRNOTAVAIL", "::1"), attempt("ECONNREFUSED", "127.0.0.1"))), "connection failed (ECONNREFUSED)", "no IPv6, then refused");
  const under = (...codes: string[]) => new TypeError("fetch failed", { cause: codes.reduceRight<unknown>((cause, code) => Object.assign(new Error(code), { code, ...(cause ? { cause } : {}) }), undefined) });
  assert.equal(transportFailure(under("EAI_AGAIN")), "DNS lookup failed (EAI_AGAIN)");
  for (const code of ["EPROTO", "ERR_TLS_HANDSHAKE_TIMEOUT", "ERR_SSL_PACKET_LENGTH_TOO_LONG"]) assert.equal(transportFailure(under(code)), `TLS failed (${code})`, code);
  // A certificate verdict is impersonation, not downtime: never an outage, wherever it is in the chain.
  for (const code of ["CERT_HAS_EXPIRED", "CERT_NOT_YET_VALID", "DEPTH_ZERO_SELF_SIGNED_CERT", "SELF_SIGNED_CERT_IN_CHAIN", "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "UNABLE_TO_GET_ISSUER_CERT_LOCALLY", "ERR_TLS_CERT_ALTNAME_INVALID", "HOSTNAME_MISMATCH", "ERR_SSL_TLSV1_ALERT_UNKNOWN_CA", "ERR_SSL_SSLV3_ALERT_BAD_CERTIFICATE"]) {
    assert.equal(transportFailure(under(code)), undefined, code);
  }
  assert.equal(transportFailure(under("ECONNRESET", "CERT_HAS_EXPIRED")), undefined, "a reset whose cause is a certificate verdict");
  // Unknown is not an outage: a message that only names a code, no code, a code that is not a transport failure.
  for (const e of [new Error("ECONNREFUSED"), new TypeError("fetch failed"), under("ERR_INVALID_URL"), under("HPE_INVALID_CONSTANT"), new SyntaxError("Unexpected token"), "ECONNRESET", null, undefined]) assert.equal(transportFailure(e), undefined, String(e));
});

test("outage summary: one line, each host once, each package once however many hosts missed it", () => {
  assert.equal(outageSummary([]), undefined);
  assert.equal(outageSummary([{ host: "registry.npmjs.org", error: "HTTP 503", id: "npm:a@1.0.0" }]), "UNVERIFIED: 1 package not checked (registry.npmjs.org unreachable: HTTP 503); --on-outage warn");
  assert.equal(
    outageSummary([
      { host: "registry.npmjs.org", error: "HTTP 503", id: "npm:b@1.0.0" },
      { host: "api.osv.dev", error: "timed out", id: "npm:a@1.0.0" },
      { host: "registry.npmjs.org", error: "HTTP 502", id: "npm:a@1.0.0" },
    ]),
    "UNVERIFIED: 2 packages not checked (api.osv.dev unreachable: timed out; registry.npmjs.org unreachable: HTTP 502); --on-outage warn",
  );
});

test("outage ledger: a claim is warn only when its host never answered and its probe fails as an outage; anything else is the fail-closed side", async () => {
  const claim = (host: string) => ({ host, probe: `https://${host}/`, failClosed: [makeFinding({ ruleId: "WS-SK-002", severity: "high", message: "m", key: host })], warn: [makeFinding({ ruleId: "WS-SK-006", severity: "medium", message: "m", key: host })], unverified: [{ host, error: "HTTP 503", id: `npm:${host}@1.0.0` }] });
  const probes: string[] = [];
  const answers: Record<string, () => Response> = {
    "up.example": () => new Response(null, { status: 200 }),
    "missing.example": () => new Response(null, { status: 404 }),
    "nohead.example": () => new Response(null, { status: 405 }),
    "redirects.example": () => new Response(null, { status: 302, headers: { location: "https://elsewhere.example/" } }),
    "down.example": () => new Response(null, { status: 503 }),
    "limited.example": () => new Response(null, { status: 429 }),
    // A host that cannot do HEAD, or fails on its root, is up; only a gateway that could not reach it is not.
    "nohead501.example": () => new Response(null, { status: 501 }),
    "version505.example": () => new Response(null, { status: 505 }),
    "error500.example": () => new Response(null, { status: 500 }),
    "gateway502.example": () => new Response(null, { status: 502 }),
    "gateway504.example": () => new Response(null, { status: 504 }),
  };
  const throws: Record<string, unknown> = {
    "refused.example": new TypeError("fetch failed", { cause: Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" }) }),
    "impostor.example": new TypeError("fetch failed", { cause: Object.assign(new Error("certificate has expired"), { code: "CERT_HAS_EXPIRED" }) }),
    "odd.example": new Error("something else"),
  };
  const f = (async (url: string | URL, init?: RequestInit) => {
    const host = new URL(String(url)).host;
    probes.push(`${init?.method} ${String(url)} ${init?.redirect}`);
    if (host in throws) throw throws[host];
    return answers[host]!();
  }) as typeof fetch;
  const ledger = new OutageLedger();
  assert.deepEqual(await ledger.resolve(f), { findings: [], unverified: [] }, "no claim, no probe");
  assert.equal(probes.length, 0);
  ledger.answered("answered.example");
  for (const host of ["answered.example", ...Object.keys(answers), ...Object.keys(throws), "down.example"]) ledger.claim(claim(host));
  assert.equal(ledger.filed, 16);
  const r = await ledger.resolve(f);
  assert.deepEqual(r.findings.map((x) => `${x.key} ${x.ruleId}`), [
    "answered.example WS-SK-002",
    "up.example WS-SK-002",
    "missing.example WS-SK-002",
    "nohead.example WS-SK-002",
    "redirects.example WS-SK-002",
    "down.example WS-SK-006",
    "limited.example WS-SK-006",
    "nohead501.example WS-SK-002",
    "version505.example WS-SK-002",
    "error500.example WS-SK-002",
    "gateway502.example WS-SK-006",
    "gateway504.example WS-SK-006",
    "refused.example WS-SK-006",
    "impostor.example WS-SK-002",
    "odd.example WS-SK-002",
    "down.example WS-SK-006",
  ]);
  assert.deepEqual(r.unverified.map((u) => u.host), ["down.example", "limited.example", "gateway502.example", "gateway504.example", "refused.example", "down.example"]);
  assert.ok(!probes.some((x) => x.includes("answered.example")), "a host that answered is not probed");
  assert.equal(probes.filter((x) => x.includes("down.example")).length, 1, "one probe per host");
  assert.ok(probes.every((x) => x.startsWith("HEAD https://") && x.endsWith("/ manual")), probes.join("\n"));
});

/* ---- the registry ---- */

/** Each outage class, for every request to the registry: the whole host is out. */
const REGISTRY_OUTAGES: { name: string; error: RegExp; server: () => Promise<Local | "dns">; timeoutMs?: number; https?: boolean }[] = [
  { name: "HTTP 503", error: /^HTTP 503$/, server: () => http((_req, _b, res) => json(res, "", 503)) },
  { name: "HTTP 429", error: /^HTTP 429$/, server: () => http((_req, _b, res) => json(res, "", 429)) },
  { name: "HTTP 502", error: /^HTTP 502$/, server: () => http((_req, _b, res) => json(res, "", 502)) },
  { name: "connection refused", error: /^connection failed \(ECONNREFUSED\)$/, server: closedPort },
  { name: "connection reset", error: /^connection failed \(ECONNRESET\)$/, server: () => tcp(afterRequest((c) => c.resetAndDestroy())) },
  { name: "TLS failure", error: /^TLS failed \(/, server: () => http((_req, _b, res) => json(res, "plain")), https: true },
  { name: "timeout", error: /^timed out$/, server: () => tcp(() => undefined), timeoutMs: 150 },
  { name: "DNS failure", error: /^DNS lookup failed \(ENOTFOUND\)$/, server: async () => "dns" },
];

for (const o of REGISTRY_OUTAGES) {
  test(`registry out for the whole run, ${o.name}: warn reports WS-SK-006 at medium and the UNVERIFIED line; fail and the default are WS-SK-002, high, byte for byte alike`, async () => {
    const server = await o.server();
    const osv = await quietOsv();
    try {
      const npm = server === "dns" ? "dns" : o.https ? server.url.replace("http:", "https:") : server.url;
      const dir = tree({ "package-lock.json": npmLock([{ id: "down@1.0.0" }]) });
      const fetchImpl = routed({ npm, osv: osv.url }, o.timeoutMs);
      const warn = await soak(dir, fetchImpl, "--on-outage", "warn");
      // The registry served nothing, so OSV is not asked either: the one finding about the package is WS-SK-006.
      assert.deepEqual(rules(warn.doc).filter((r) => /^WS-(SK-00[26]|OS-)/.test(r)), ["WS-SK-006 medium"]);
      const f = warn.doc.findings.find((x) => x.ruleId === "WS-SK-006")!;
      assert.match(f.message, /^Soak time not checked for down@1\.0\.0: registry\.npmjs\.org unreachable: /);
      assert.match(f.message.slice("Soak time not checked for down@1.0.0: registry.npmjs.org unreachable: ".length).split(". Its age")[0]!, o.error);
      assert.equal(f.file, "package-lock.json");
      assert.equal(warn.code, 0, "medium passes the default --fail-on high");
      assert.equal(fetchImpl.calls.filter((c) => c === "HEAD https://registry.npmjs.org/").length, 1, "the registry's root was probed once");
      // One loud line, on stderr and first among the notes.
      const [line, ...more] = unverifiedLines(warn.err);
      assert.deepEqual(more, []);
      assert.match(line ?? "", /^UNVERIFIED: 1 package not checked \(registry\.npmjs\.org unreachable: .+\); --on-outage warn$/);
      assert.equal(warn.doc.notes[0], line);

      const dflt = await soak(dir, routed({ npm, osv: osv.url }, o.timeoutMs));
      const fail = await soak(dir, routed({ npm, osv: osv.url }, o.timeoutMs), "--on-outage", "fail");
      assert.equal(fail.out, dflt.out, "--on-outage fail is the default");
      assert.equal(fail.err, dflt.err);
      assert.deepEqual(rules(dflt.doc).filter((r) => /^WS-(SK-00[26]|OS-)/.test(r)), ["WS-SK-002 high"]);
      assert.equal(dflt.code, 1);
      assert.deepEqual(unverifiedLines(dflt.err), []);
      assert.ok(!dflt.doc.notes.some((n) => n.startsWith("UNVERIFIED")));
      // The two findings never share a fingerprint, so a baseline entry for one cannot carry over to the other.
      const sk2 = dflt.doc.findings.find((x) => x.ruleId === "WS-SK-002")!;
      assert.notEqual(sk2.fingerprint, f.fingerprint);
      assert.equal(sk2.key, f.key, "same package, same key: only the rule id tells them apart");
    } finally {
      if (server !== "dns") await server.close();
      await osv.close();
    }
  });
}

/** The registry serves every name but `evil` (and maybe its root), or serves only its root. */
const ONE_NAME: { name: string; lock: string[]; evil: (res: ServerResponse) => void; root?: (res: ServerResponse) => void }[] = [
  { name: "HTTP 503 for one name, the rest served", lock: ["a1", "a2", "a3", "a4", "evil"], evil: (res) => json(res, "", 503) },
  { name: "HTTP 503 for one name and for the probe of the root, the rest served", lock: ["a1", "a2", "a3", "a4", "evil"], evil: (res) => json(res, "", 503), root: (res) => json(res, "", 503) },
  { name: "HTTP 429 for one name, the rest served", lock: ["a1", "a2", "a3", "a4", "evil"], evil: (res) => json(res, "", 429) },
  { name: "HTTP 503 for the only name the run asks for, the root answers the probe", lock: ["evil"], evil: (res) => json(res, "", 503) },
  { name: "the connection dropped for the only name the run asks for, the root answers the probe", lock: ["evil"], evil: (res) => res.socket?.resetAndDestroy() },
];

for (const n of ONE_NAME) {
  test(`registry, ${n.name}: not an outage of the host, so warn reports exactly what the default does (WS-SK-002, high)`, async () => {
    const server = await http((req, _b, res) => (req.url === "/evil" ? n.evil(res) : req.method === "HEAD" ? (n.root ?? ((r) => json(r, "", 200)))(res) : json(res, packument(String(req.url).slice(1)))));
    const osv = await quietOsv();
    try {
      const dir = tree({ "package-lock.json": npmLock(n.lock.map((id) => ({ id: `${id}@1.0.0` }))) });
      const warn = await soak(dir, routed({ npm: server.url, osv: osv.url }), "--on-outage", "warn");
      const dflt = await soak(dir, routed({ npm: server.url, osv: osv.url }));
      assert.equal(warn.out, dflt.out, "the report is the same with and without warn");
      assert.equal(warn.err, dflt.err);
      assert.deepEqual(warn.doc.findings.filter((f) => /^WS-SK-00[26]$/.test(f.ruleId)).map((f) => `${f.ruleId} ${f.severity} ${f.key.split("\0")[0]}`), [`WS-SK-002 high ${warn.doc.findings.find((f) => f.ruleId === "WS-SK-002")!.key.split("\0")[0]}`]);
      assert.match(warn.doc.findings.find((f) => f.ruleId === "WS-SK-002")!.message, /^Cannot verify soak time for evil@1\.0\.0: /);
      assert.equal(warn.code, 1);
      assert.deepEqual(unverifiedLines(warn.err), []);
    } finally {
      await server.close();
      await osv.close();
    }
  });
}

/** A status line and then a body that never ends or breaks off, for every request: the host is up, so never an outage. */
for (const b of [
  { name: "a body slower than the timeout after HTTP 200", server: () => tcp((c) => c.write('HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100000\r\n\r\n{"name":')), timeoutMs: 150 },
  { name: "a body cut off after HTTP 200", server: () => tcp(afterRequest((c) => c.end('HTTP/1.1 200 OK\r\ncontent-length: 100000\r\n\r\n{"name":'))) },
]) {
  test(`registry, ${b.name}: not an outage, so warn reports exactly what the default does (WS-SK-002, high), and no claim is filed`, async () => {
    const server = await b.server();
    const osv = await quietOsv();
    try {
      const dir = tree({ "package-lock.json": npmLock([{ id: "evil@1.0.0" }]) });
      const warn = await soak(dir, routed({ npm: server.url, osv: osv.url }, b.timeoutMs), "--on-outage", "warn");
      const dflt = await soak(dir, routed({ npm: server.url, osv: osv.url }, b.timeoutMs));
      assert.equal(warn.out, dflt.out);
      assert.deepEqual(rules(warn.doc).filter((r) => /^WS-SK-00[26]/.test(r)), ["WS-SK-002 high"]);
      assert.equal(warn.code, 1);
      // Directly: the client does not call a failure after a status line an outage, so the check files no claim.
      const ledger = new OutageLedger();
      const lock = parseLockfileText("package-lock.json", npmLock([{ id: "evil@1.0.0" }]))!;
      const res = await checkSoakLockfiles([lock], { minAgeMs: 7 * 24 * H, registry: "https://registry.npmjs.org", now: NOW, fetchImpl: routed({ npm: server.url }, b.timeoutMs), sleep: async () => undefined, outages: ledger });
      assert.equal(ledger.filed, 0);
      assert.deepEqual(res.findings.map((f) => `${f.ruleId} ${f.severity}`), ["WS-SK-002 high"]);
    } finally {
      await server.close();
      await osv.close();
    }
  });
}

/** Failures that are not an outage: each stays exactly what it is without the option. */
const NOT_OUTAGES: { name: string; want: string; lock?: { id: string; resolved?: string }[]; server: () => Promise<Local> }[] = [
  { name: "HTTP 404", want: "WS-SK-002 high", server: () => http((_req, _b, res) => json(res, { error: "Not found" }, 404)) },
  { name: "HTTP 403", want: "WS-SK-002 high", server: () => http((_req, _b, res) => json(res, "", 403)) },
  { name: "HTTP 400", want: "WS-SK-002 high", server: () => http((_req, _b, res) => json(res, "", 400)) },
  { name: "HTTP 410", want: "WS-SK-002 high", server: () => http((_req, _b, res) => json(res, "", 410)) },
  { name: "a redirect", want: "WS-SK-002 high", server: () => http((_req, _b, res) => (res.writeHead(302, { location: "https://elsewhere.example/down" }), res.end())) },
  { name: "a body that is not JSON", want: "WS-SK-002 high", server: () => http((_req, _b, res) => json(res, "<html>maintenance</html>", 200, "text/html")) },
  { name: "a document without publish times", want: "WS-SK-002 high", server: () => http((_req, _b, res) => json(res, { name: "down", versions: {} })) },
  { name: "an answer that is not HTTP", want: "WS-SK-002 high", server: () => tcp((c) => c.end("garbage\r\n\r\n")) },
  { name: "an integrity mismatch", want: "WS-SK-002 high", server: () => http((_req, _b, res) => json(res, packument("down", 400, "sha512-y"))) },
  { name: "a version not on the registry", want: "WS-SK-002 high", server: () => http((_req, _b, res) => json(res, { ...packument("down"), versions: {} })) },
  { name: "a version too young", want: "WS-SK-001 high", server: () => http((_req, _b, res) => json(res, packument("down", 5))) },
  { name: "a private registry (never asked)", want: "WS-SK-002 high", lock: [{ id: "down@1.0.0", resolved: "https://npm.acme.example/down/-/down-1.0.0.tgz" }], server: closedPort },
  // HTTP 500 to everything, the probe included: a host that answers its root with an error of its own is up.
  { name: "HTTP 500 to every request and to the probe", want: "WS-SK-002 high", server: () => http((_req, _b, res) => json(res, "", 500)) },
];

for (const n of NOT_OUTAGES) {
  test(`registry, ${n.name}: not an outage, so warn reports exactly what the default does (${n.want})`, async () => {
    const server = await n.server();
    const osv = await quietOsv();
    try {
      const dir = tree({ "package-lock.json": npmLock(n.lock ?? [{ id: "down@1.0.0" }]) });
      const warn = await soak(dir, routed({ npm: server.url, osv: osv.url }), "--on-outage", "warn");
      const dflt = await soak(dir, routed({ npm: server.url, osv: osv.url }));
      assert.equal(warn.out, dflt.out, "the report is the same with and without warn");
      assert.equal(warn.err, dflt.err);
      assert.ok(rules(warn.doc).includes(n.want), rules(warn.doc).join(", "));
      assert.ok(!rules(warn.doc).some((r) => r.startsWith("WS-SK-006") || r.startsWith("WS-OS-901")));
      assert.equal(warn.code, 1);
      assert.deepEqual(unverifiedLines(warn.err), []);
    } finally {
      await server.close();
      await osv.close();
    }
  });
}

test("registry: a 404 beside a 503 is an answer, so under warn both stay high and nothing is unverified", async () => {
  const server = await http((req, _b, res) => (req.url === "/down" ? json(res, "", 503) : req.url === "/gone" ? json(res, { error: "Not found" }, 404) : json(res, packument("old"))));
  const osv = await quietOsv();
  try {
    const dir = tree({ "package-lock.json": npmLock([{ id: "down@1.0.0" }, { id: "gone@1.0.0" }]) });
    const warn = await soak(dir, routed({ npm: server.url, osv: osv.url }), "--on-outage", "warn");
    const dflt = await soak(dir, routed({ npm: server.url, osv: osv.url }));
    assert.equal(warn.out, dflt.out);
    assert.deepEqual(warn.doc.findings.filter((f) => f.ruleId === "WS-SK-002").map((f) => `${f.severity} ${f.message.split(":")[0]}`).sort(), ["high Cannot verify soak time for down@1.0.0", "high Cannot verify soak time for gone@1.0.0"]);
    assert.equal(warn.code, 1);
    assert.deepEqual(unverifiedLines(warn.err), []);
  } finally {
    await server.close();
    await osv.close();
  }
});

/* ---- OSV ---- */

for (const o of [
  { name: "HTTP 503", error: "HTTP 503", server: () => http((_req, _b, res) => json(res, "", 503)) },
  { name: "connection refused", error: "connection failed (ECONNREFUSED)", server: closedPort },
]) {
  test(`OSV out for the whole run, ${o.name}: warn reports WS-OS-901 per version at medium; the default is one WS-OS-900, high`, async () => {
    const registry = await http((req, _b, res) => json(res, packument(String(req.url).slice(1))));
    const osv = await o.server();
    try {
      const dir = tree({ "package-lock.json": npmLock([{ id: "a@1.0.0" }, { id: "b@1.0.0" }]) });
      const fetchImpl = routed({ npm: registry.url, osv: osv.url });
      const warn = await soak(dir, fetchImpl, "--on-outage", "warn");
      const os = warn.doc.findings.filter((f) => f.ruleId.startsWith("WS-OS-"));
      assert.deepEqual(os.map((f) => `${f.ruleId} ${f.severity} ${f.file} ${f.key}`), ["WS-OS-901 medium package-lock.json a@1.0.0", "WS-OS-901 medium package-lock.json b@1.0.0"]);
      assert.equal(os[0]!.message, `a@1.0.0 was not checked against OSV for malicious-package records: api.osv.dev unreachable: ${o.error}. --on-outage warn reports it at medium; by default it fails closed (WS-OS-900, high)`);
      assert.equal(warn.code, 0);
      assert.deepEqual(unverifiedLines(warn.err), [`UNVERIFIED: 2 packages not checked (api.osv.dev unreachable: ${o.error}); --on-outage warn`]);
      assert.deepEqual(fetchImpl.calls.filter((c) => c.startsWith("HEAD ")), ["HEAD https://api.osv.dev/"], "only OSV, whose claim it is, is probed");
      const dflt = await soak(dir, routed({ npm: registry.url, osv: osv.url }));
      assert.deepEqual(dflt.doc.findings.filter((f) => f.ruleId.startsWith("WS-OS-")).map((f) => `${f.ruleId} ${f.severity}`), ["WS-OS-900 high"]);
      assert.equal(dflt.code, 1);
      assert.deepEqual(unverifiedLines(dflt.err), []);
    } finally {
      await registry.close();
      await osv.close();
    }
  });
}

/** OSV answers, but not for evil: each case stays WS-OS-900, high, exactly as without the option. */
const OSV_ANSWERS: { name: string; handler: (req: IncomingMessage, body: string, res: ServerResponse) => void }[] = [
  { name: "HTTP 400", handler: (_req, _b, res) => json(res, "", 400) },
  { name: "a body that is not JSON", handler: (_req, _b, res) => json(res, "nope", 200, "text/plain") },
  { name: "an answer in the wrong shape", handler: (_req, _b, res) => json(res, {}) },
  {
    // The batch of both is refused (400) and halved; OSV answers a's half and is "down" (503) only for evil's.
    name: "HTTP 503 for the batch with evil only, after answering the rest",
    handler: (_req, body, res) => {
      const { queries } = JSON.parse(body) as { queries: { package: { name: string } }[] };
      if (queries.length > 1) return json(res, "", 400);
      return queries[0]!.package.name === "evil" ? json(res, "", 503) : json(res, { results: [{}] });
    },
  },
  {
    // Both have a GitHub advisory; every record query answers 200 with a body that is not JSON (it stops the run's queries).
    name: "record queries answered with a body that is not JSON",
    handler: (req, body, res) => {
      if (req.url !== "/v1/querybatch") return json(res, "nope", 200, "text/plain");
      const { queries } = JSON.parse(body) as { queries: { package: { name: string } }[] };
      json(res, { results: queries.map((q) => ({ vulns: [{ id: `GHSA-${q.package.name}` }] })) });
    },
  },
  {
    name: "record queries answered HTTP 502 after the batch was answered",
    handler: (req, body, res) => {
      if (req.url !== "/v1/querybatch") return json(res, "", 502);
      const { queries } = JSON.parse(body) as { queries: { package: { name: string } }[] };
      json(res, { results: queries.map((q) => ({ vulns: [{ id: `GHSA-${q.package.name}` }] })) });
    },
  },
];

for (const n of OSV_ANSWERS) {
  test(`OSV, ${n.name}: OSV answered, so warn reports exactly what the default does (WS-OS-900, high)`, async () => {
    const registry = await http((req, _b, res) => json(res, packument(String(req.url).slice(1))));
    // A probe of the root, which only a wrong verdict would send, finds OSV "down", so only the run's answers save it.
    const osv = await http((req, body, res) => (req.method === "HEAD" ? json(res, "", 503) : n.handler(req, body, res)));
    try {
      const dir = tree({ "package-lock.json": npmLock([{ id: "a@1.0.0" }, { id: "evil@1.0.0" }]) });
      const warn = await soak(dir, routed({ npm: registry.url, osv: osv.url }), "--on-outage", "warn");
      const dflt = await soak(dir, routed({ npm: registry.url, osv: osv.url }));
      assert.equal(warn.out, dflt.out);
      assert.equal(warn.err, dflt.err);
      assert.deepEqual(warn.doc.findings.filter((f) => f.ruleId.startsWith("WS-OS-")).map((f) => `${f.ruleId} ${f.severity}`), ["WS-OS-900 high"]);
      assert.equal(warn.code, 1);
    } finally {
      await registry.close();
      await osv.close();
    }
  });
}

test("a failure after a status line is never an outage: the registry, the index and OSV file no claim for a body that is slow or cut off", async () => {
  const slow = await tcp((c) => c.write('HTTP/1.1 200 OK\r\ncontent-type: application/vnd.pypi.simple.v1+json\r\ncontent-length: 100000\r\n\r\n{"name":'));
  const cut = await tcp(afterRequest((c) => c.end('HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100000\r\n\r\n{"results":')));
  try {
    const index = await createIndexClient({ index: "https://pypi.org/simple/", fetchImpl: routed({ pypi: slow.url }), timeoutMs: 150, outages: new OutageLedger() }).project("idna");
    assert.ok("error" in index && !("outage" in index), JSON.stringify(index));
    const ledger = new OutageLedger();
    const r = await checkOsvDetailed([{ name: "evil", version: "1.0.0" }], { fetchImpl: routed({ osv: cut.url }), outages: ledger });
    assert.equal(ledger.filed, 0);
    assert.deepEqual(r.findings.map((f) => `${f.ruleId} ${f.severity}`), ["WS-OS-900 high"]);
    // Control: the same servers' transport failures before a status line are outages.
    const refused = await closedPort();
    const out = await createIndexClient({ index: "https://pypi.org/simple/", fetchImpl: routed({ pypi: refused.url }), outages: new OutageLedger() }).project("idna");
    assert.ok("outage" in out && out.outage === "connection failed (ECONNREFUSED)", JSON.stringify(out));
    const claims = new OutageLedger();
    await checkOsvDetailed([{ name: "evil", version: "1.0.0" }], { fetchImpl: routed({ osv: refused.url }), outages: claims });
    assert.equal(claims.filed, 1);
  } finally {
    await slow.close();
    await cut.close();
  }
});

test("OSV: a record query's failure is never an outage claim, not even when it stops the run's queries", async () => {
  for (const answer of [(res: ServerResponse) => json(res, "nope", 200, "text/plain"), (res: ServerResponse) => json(res, "", 503)]) {
    let queries = 0;
    const osv = await http((req, body, res) => {
      if (req.url === "/v1/querybatch") {
        const { queries: q } = JSON.parse(body) as { queries: { package: { name: string } }[] };
        return json(res, { results: q.map((x) => ({ vulns: [{ id: `GHSA-${x.package.name}` }] })) });
      }
      queries++;
      answer(res);
    });
    try {
      const ledger = new OutageLedger();
      const packages = [{ name: "a", version: "1.0.0", file: "package-lock.json" }, { name: "evil", version: "1.0.0", file: "package-lock.json" }];
      const r = await checkOsvDetailed(packages, { fetchImpl: routed({ osv: osv.url }), outages: ledger, session: newOsvSession(), concurrency: 1, sleep: async () => undefined });
      assert.equal(queries, 2, "one query and its retry, then no more");
      assert.equal(ledger.filed, 0);
      assert.deepEqual([...r.outages], []);
      assert.deepEqual(r.findings.map((f) => `${f.ruleId} ${f.severity} ${f.key}`), ["WS-OS-900 high a@1.0.0 evil@1.0.0"]);
    } finally {
      await osv.close();
    }
  }
});

test("OSV: a redirect is not followed, and it is not an outage: WS-OS-900, high, under warn as without it", async () => {
  let followed = 0;
  const target = await http((_req, _b, res) => {
    followed++;
    json(res, { results: [{}, {}] });
  });
  const closed = await closedPort();
  const registry = await http((req, _b, res) => json(res, packument(String(req.url).slice(1))));
  try {
    for (const to of [target.url, closed.url]) {
      const osv = await http((_req, _b, res) => (res.writeHead(307, { location: `${to}/v1/querybatch` }), res.end()));
      try {
        const dir = tree({ "package-lock.json": npmLock([{ id: "a@1.0.0" }, { id: "b@1.0.0" }]) });
        const warn = await soak(dir, routed({ npm: registry.url, osv: osv.url }), "--on-outage", "warn");
        const dflt = await soak(dir, routed({ npm: registry.url, osv: osv.url }));
        assert.equal(warn.out, dflt.out);
        const os = warn.doc.findings.filter((f) => f.ruleId.startsWith("WS-OS-"));
        assert.deepEqual(os.map((f) => `${f.ruleId} ${f.severity}`), ["WS-OS-900 high"]);
        assert.match(os[0]!.message, /OSV returned HTTP 307, a redirect to http:\/\/127\.0\.0\.1:\d+\/v1\/querybatch, which wormsign does not follow/);
      } finally {
        await osv.close();
      }
    }
    assert.equal(followed, 0, "the redirect target is never asked");
  } finally {
    for (const s of [target, closed, registry]) await s.close();
  }
});

/* ---- the Python index ---- */

const UV = fx("python", "locks", "uv-0.12.21", "simple");
const PAGES = fx("python", "simple");

/** A uv.lock locking idna 3.20 and six 1.17.0, with the index answering `idna` as `idna` says and six from its recorded page. */
async function pypi(idna: (res: ServerResponse) => void, opts: { six?: (res: ServerResponse) => void; root?: (res: ServerResponse) => void } = {}, ...args: string[]) {
  const recorded = (res: ServerResponse, name: string) => json(res, readFileSync(join(PAGES, `${name}.json`), "utf8"), 200, "application/vnd.pypi.simple.v1+json");
  const index = await http((req, _b, res) => {
    if (req.url === "/simple/idna/") return idna(res);
    if (req.url === "/simple/six/") return opts.six ? opts.six(res) : recorded(res, "six");
    if (req.url === "/simple/") return opts.root ? opts.root(res) : json(res, "", 200);
    json(res, "{}", 404, "application/vnd.pypi.simple.v1+json");
  });
  const osv = await quietOsv();
  try {
    const dir = tree({ "uv.lock": readFileSync(join(UV, "uv.lock"), "utf8"), "pyproject.toml": readFileSync(join(UV, "pyproject.toml"), "utf8") });
    const fetchImpl = routed({ pypi: index.url, osv: osv.url });
    return { ...(await soak(dir, fetchImpl, ...args)), calls: fetchImpl.calls };
  } finally {
    await index.close();
    await osv.close();
  }
}

test("Python index out for the whole run (HTTP 503): warn reports WS-SK-006 for each package at medium; the default is WS-SK-002, high", async () => {
  const down = (res: ServerResponse) => json(res, "", 503);
  const warn = await pypi(down, { six: down, root: down }, "--on-outage", "warn");
  const sk = warn.doc.findings.filter((f) => f.ruleId === "WS-SK-006" || f.ruleId === "WS-SK-002");
  assert.deepEqual(sk.map((f) => `${f.ruleId} ${f.severity} ${f.file}`), ["WS-SK-006 medium uv.lock", "WS-SK-006 medium uv.lock"]);
  assert.match(sk.find((f) => f.message.includes("idna"))!.message, /^Soak time not checked for PyPI package idna==3\.20: pypi\.org unreachable: HTTP 503\. /);
  assert.deepEqual(unverifiedLines(warn.err), ["UNVERIFIED: 2 packages not checked (pypi.org unreachable: HTTP 503); --on-outage warn"]);
  assert.ok(warn.calls.includes("HEAD https://pypi.org/simple/"), "the index's root was probed");
  assert.equal(warn.code, 0);
  const dflt = await pypi(down, { six: down, root: down });
  assert.deepEqual(dflt.doc.findings.filter((f) => f.ruleId === "WS-SK-006" || f.ruleId === "WS-SK-002").map((f) => `${f.ruleId} ${f.severity}`), ["WS-SK-002 high", "WS-SK-002 high"]);
  assert.equal(dflt.code, 1);
  assert.ok(!dflt.calls.some((c) => c.startsWith("HEAD ")), "no probe without the option");
});

for (const n of [
  { name: "HTTP 503 for idna and for the probe of the root while six is served", answer: (res: ServerResponse) => json(res, "", 503), root: (res: ServerResponse) => json(res, "", 503) },
  { name: "HTTP 503 for idna and six while the root answers the probe", answer: (res: ServerResponse) => json(res, "", 503), six: (res: ServerResponse) => json(res, "", 503) },
  { name: "HTTP 404", answer: (res: ServerResponse) => json(res, { message: "Not Found" }, 404) },
  { name: "a body that is not JSON", answer: (res: ServerResponse) => json(res, "nope", 200, "application/vnd.pypi.simple.v1+json") },
  { name: "another content type", answer: (res: ServerResponse) => json(res, "<html></html>", 200, "text/html") },
  { name: "a redirect to another origin", answer: (res: ServerResponse) => (res.writeHead(302, { location: "http://127.0.0.1:9/simple/idna/" }), res.end()) },
]) {
  test(`Python index, ${n.name}: not an outage of the index, so warn reports exactly what the default does (WS-SK-002, high)`, async () => {
    const opts = { ...(n.six ? { six: n.six } : {}), ...(n.root ? { root: n.root } : {}) };
    const warn = await pypi(n.answer, opts, "--on-outage", "warn");
    const dflt = await pypi(n.answer, opts);
    assert.equal(warn.out, dflt.out);
    assert.ok(warn.doc.findings.some((f) => f.ruleId === "WS-SK-002" && f.severity === "high" && f.message.includes("idna==3.20")));
    assert.ok(!warn.doc.findings.some((f) => f.ruleId === "WS-SK-006"));
    assert.equal(warn.code, 1);
    assert.deepEqual(unverifiedLines(warn.err), []);
  });
}

/* ---- baseline, flags ---- */

test("baseline: no entry suppresses WS-SK-006 or WS-OS-901, while the same entry mechanism suppresses WS-SK-002", async () => {
  assert.deepEqual([...NOT_BASELINABLE].sort(), ["WS-OS-901", "WS-SK-006"]);
  const outage = makeFinding({ ruleId: "WS-SK-006", severity: "medium", message: "m", key: "k" });
  const osv = makeFinding({ ruleId: "WS-OS-901", severity: "medium", message: "m", key: "k" });
  const closed = makeFinding({ ruleId: "WS-SK-002", severity: "high", message: "m", key: "k" });
  const entries = [outage, osv, closed].map((f) => ({ fingerprint: f.fingerprint, justification: "reviewed while the registry was down" }));
  const out = applyBaseline([outage, osv, closed], { version: 1, entries, ignorePaths: [] }, NOW);
  assert.deepEqual(out.map((f) => [f.ruleId, f.suppressed !== undefined]), [["WS-SK-006", false], ["WS-OS-901", false], ["WS-SK-002", true]]);

  // Through the CLI: the fingerprint the warn run printed, baselined, still reports and still fails --fail-on medium.
  const server = await http((_req, _b, res) => json(res, "", 503));
  const quiet = await quietOsv();
  try {
    const dir = tree({ "package-lock.json": npmLock([{ id: "down@1.0.0" }]) });
    const first = await soak(dir, routed({ npm: server.url, osv: quiet.url }), "--on-outage", "warn");
    const fp = first.doc.findings.find((f) => f.ruleId === "WS-SK-006")!.fingerprint;
    writeFileSync(join(dir, ".wormsign-baseline.json"), JSON.stringify({ version: 1, entries: [{ fingerprint: fp, justification: "the registry was down, merged anyway" }] }));
    const again = await soak(dir, routed({ npm: server.url, osv: quiet.url }), "--on-outage", "warn", "--fail-on", "medium");
    const f = again.doc.findings.find((x) => x.ruleId === "WS-SK-006")!;
    assert.equal(f.fingerprint, fp, "the same finding");
    assert.equal(f.suppressed, undefined);
    assert.equal(again.code, 1);
  } finally {
    await server.close();
    await quiet.close();
  }
});

test("--on-outage takes fail or warn, and only soak has it", async () => {
  const io = fakeIO();
  assert.equal(await run(["soak", ".", "--on-outage", "maybe"], io), 2);
  assert.match(io.err, /invalid --on-outage "maybe" \(fail, warn\)/);
  const scan = fakeIO();
  assert.equal(await run(["scan", ".", "--on-outage", "warn"], scan), 2);
  assert.match(scan.err, /--on-outage is not an option of scan/);
  const help = fakeIO();
  await run(["--help"], help);
  assert.match(help.out, /--on-outage fail\|warn/);
});
