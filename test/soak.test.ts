import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseDuration, formatDuration } from "../src/duration.js";
import { checkSoakLockfiles, localNames, MAX_PACKUMENT_BYTES, onlyKey, packumentWait, registryUrl } from "../src/soak.js";
import { bunExcludes, checkSoakConfig, installRegistries, installedVersion, readBunfig, readNpmrc } from "../src/soak-config.js";
import type { ConfigOptions, TreeInputs, InstalledVersion } from "../src/soak-config.js";
import { parseLockfileText } from "../src/lockfile/index.js";
import type { LockedPackage, ParsedLockfile } from "../src/lockfile/index.js";
import { run } from "../src/main.js";
import { fingerprint } from "../src/types.js";
import { NOW, fakeIO } from "./helpers.js";

const H = 3_600_000;
const iso = (hoursAgo: number) => new Date(NOW.getTime() - hoursAgo * H).toISOString();
const tarball = (n: string, v: string) => `https://registry.npmjs.org/${n}/-/${n.split("/").pop()}-${v}.tgz`;

function lock(pkgs: Record<string, string>) {
  const packages: Record<string, unknown> = { "": { name: "root" } };
  for (const [n, v] of Object.entries(pkgs)) packages[`node_modules/${n}`] = { version: v, resolved: tarball(n, v), integrity: "sha512-x" };
  const l = parseLockfileText("package-lock.json", JSON.stringify({ lockfileVersion: 3, packages }));
  assert.ok(l);
  return l;
}

/** A registry version: hours since publish, or details. Every version's tarball hashes to "sha512-x" unless told otherwise. */
type Ver = number | { h: number; integrity?: string; shasum?: string; removed?: boolean; scripts?: Record<string, string>; user?: string; provenance?: boolean };

const OSV = "https://api.osv.dev/v1/querybatch";
/** Fake api.osv.dev: answers each query with the MAL- records `mal` lists for its name@version; records what was asked. */
function osvReply(init: RequestInit | undefined, mal: Record<string, string[]>, asked: string[]): Response {
  const { queries } = JSON.parse(String(init?.body)) as { queries: { package: { name: string }; version: string }[] };
  const results = queries.map(({ package: { name }, version }) => {
    asked.push(`${name}@${version}`);
    return { vulns: (mal[`${name}@${version}`] ?? []).map((id) => ({ id, modified: "2026-01-01T00:00:00Z" })) };
  });
  return new Response(JSON.stringify({ results }));
}

/** Fake registry: name -> { version -> Ver }. Records every registry URL requested; OSV queries go to `osvAsked`. */
function registry(data: Record<string, Record<string, Ver>>, over: Record<string, () => Response> = {}, mal: Record<string, string[]> = {}) {
  const calls: string[] = [];
  const osvAsked: string[] = [];
  const f = (async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    if (u === OSV) return osvReply(init, mal, osvAsked);
    calls.push(u);
    const name = decodeURIComponent(u.replace("https://registry.npmjs.org/", ""));
    if (over[name]) return over[name]();
    const d = data[name];
    if (!d) return new Response("{}", { status: 404 });
    const time: Record<string, string> = {};
    const versions: Record<string, unknown> = {};
    for (const [v, x] of Object.entries(d)) {
      const o = typeof x === "number" ? { h: x } : x;
      time[v] = iso(o.h);
      const dist = { integrity: o.integrity ?? "sha512-x", ...(o.shasum ? { shasum: o.shasum } : {}), tarball: tarball(name, v), ...(o.provenance ? { attestations: { provenance: { predicateType: "https://slsa.dev/provenance/v1" } } } : {}) };
      if (!o.removed) versions[v] = { dist, ...(o.scripts ? { scripts: o.scripts } : {}), ...(o.user ? { _npmUser: { name: o.user } } : {}) };
    }
    return new Response(JSON.stringify({ name, time, versions }), { status: 200 });
  }) as typeof fetch;
  return { f, calls, osvAsked };
}

const opts = (f: typeof fetch, extra = {}) => ({ minAgeMs: 72 * H, registry: "https://registry.npmjs.org", now: NOW, fetchImpl: f, sleep: async () => undefined, ...extra });

test("duration: parse and reject", () => {
  assert.equal(parseDuration("72h"), 72 * H);
  assert.equal(parseDuration("3d"), 72 * H);
  assert.equal(parseDuration("1 week"), 168 * H);
  assert.equal(parseDuration("90m"), 90 * 60_000);
  for (const bad of ["72", "h", "-3d", "0h", "3 parsecs", ""]) assert.throws(() => parseDuration(bad), /duration|invalid/, bad);
  assert.equal(formatDuration(72 * H), "3.0d");
});

test("soak: package inside the window fails, outside passes, boundary passes", async () => {
  const r = registry({ young: { "1.0.0": 5 }, old: { "1.0.0": 400 }, edge: { "1.0.0": 72 }, justunder: { "1.0.0": 71.9 } });
  const res = await checkSoakLockfiles([lock({ young: "1.0.0", old: "1.0.0", edge: "1.0.0", justunder: "1.0.0" })], opts(r.f));
  assert.deepEqual(res.findings.map((f) => f.key).sort(), ["justunder@1.0.0", "young@1.0.0"]);
  assert.ok(res.findings.every((f) => f.ruleId === "WS-SK-001" && f.severity === "high"));
  assert.deepEqual(res.evidence.map((e) => `${e.name}:${e.status}`), ["edge:ok", "justunder:too-new", "old:ok", "young:too-new"]);
});

test("soak: fails closed on 404, 500, missing time field, missing version, network error", async () => {
  const r = registry(
    { nover: { "9.9.9": 500 } },
    {
      boom: () => new Response("x", { status: 500 }),
      notime: () => new Response(JSON.stringify({ name: "notime", versions: {} }), { status: 200 }),
      noversions: () => new Response(JSON.stringify({ name: "noversions", time: { "1.0.0": iso(500) } }), { status: 200 }),
      denied: () => new Response("", { status: 401 }),
    },
  );
  const f = (async (u: string | URL) => {
    if (String(u).endsWith("/neterr")) throw new Error("ECONNRESET");
    return r.f(u);
  }) as typeof fetch;
  const res = await checkSoakLockfiles([lock({ ghost: "1.0.0", boom: "1.0.0", notime: "1.0.0", nover: "1.0.0", neterr: "1.0.0", noversions: "1.0.0", denied: "1.0.0" })], opts(f));
  assert.equal(res.findings.length, 7);
  assert.ok(res.findings.every((x) => x.ruleId === "WS-SK-002" && x.severity === "high"));
  const msg = (k: string) => res.findings.find((x) => x.key.startsWith(`${k} `))?.message ?? "";
  assert.match(msg("ghost@1.0.0"), /not found in https:\/\/registry.npmjs.org .*--registry.*no credentials/);
  assert.match(msg("boom@1.0.0"), /HTTP 500/);
  assert.match(msg("notime@1.0.0"), /no publish times/);
  assert.match(msg("nover@1.0.0"), /no publish time recorded for version 1.0.0/);
  assert.match(msg("neterr@1.0.0"), /ECONNRESET/);
  assert.match(msg("noversions@1.0.0"), /no version list/);
  assert.match(msg("denied@1.0.0"), /HTTP 401 .*no credentials/);
});

test("soak: one retry on 5xx or 429 recovers, after a wait (Retry-After's seconds, else 2 to 3 seconds)", async () => {
  const body = { time: { "1.0.0": iso(500) }, versions: { "1.0.0": { dist: { integrity: "sha512-x" } } } };
  for (const [first, wait] of [
    [new Response("", { status: 503 }), (ms: number) => ms >= 2_000 && ms < 3_000],
    [new Response("", { status: 429, headers: { "retry-after": "7" } }), (ms: number) => ms === 7_000],
    [new Response("", { status: 429, headers: { "retry-after": "3600" } }), (ms: number) => ms === 30_000],
    [new Response("", { status: 502, headers: { "retry-after": "Wed, 21 Oct 2026 07:28:00 GMT" } }), (ms: number) => ms >= 2_000 && ms < 3_000],
  ] as const) {
    let n = 0;
    const waits: number[] = [];
    const f = (async () => (n++ === 0 ? first.clone() : new Response(JSON.stringify(body), { status: 200 }))) as typeof fetch;
    const res = await checkSoakLockfiles([lock({ flaky: "1.0.0" })], opts(f, { sleep: async (ms: number) => void waits.push(ms) }));
    assert.deepEqual(res.findings, []);
    assert.equal(waits.length, 1, `${first.status}`);
    assert.ok(wait(waits[0]!), `${first.status}: waited ${waits[0]} ms`);
  }
  assert.equal(packumentWait(null, () => 0.999), 2_999);
});

test("soak: a package document larger than the cap fails closed while it is read, declared or not", async () => {
  const body = JSON.stringify({ time: { "1.0.0": iso(500) }, versions: { "1.0.0": { dist: { integrity: "sha512-x" } } }, readme: "x".repeat(4096) });
  for (const declared of [true, false]) {
    const f = (async () => new Response(body, { status: 200, headers: declared ? { "content-length": String(Buffer.byteLength(body)) } : {} })) as typeof fetch;
    const res = await checkSoakLockfiles([lock({ big: "1.0.0" })], opts(f, { maxPackumentBytes: 1024 }));
    assert.deepEqual(res.findings.map((x) => x.ruleId), ["WS-SK-002"], `declared: ${declared}`);
    assert.match(res.findings[0]!.message, /package document is larger than 0 MiB, the most soak reads/);
    // Under the cap it is read.
    const ok = await checkSoakLockfiles([lock({ big: "1.0.0" })], opts(f, { maxPackumentBytes: 1024 * 1024 }));
    assert.deepEqual(ok.findings, []);
  }
  assert.equal(MAX_PACKUMENT_BYTES, 200 * 1024 * 1024);
});

test("soak: one request per package name, scoped names are encoded", async () => {
  const r = registry({ "@s/p": { "1.0.0": 500, "2.0.0": 500 } });
  const l = lock({ "@s/p": "1.0.0" });
  l.packages.push({ name: "@s/p", version: "2.0.0", resolved: tarball("@s/p", "2.0.0"), integrity: "sha512-x" });
  const res = await checkSoakLockfiles([l], opts(r.f));
  assert.deepEqual(r.calls, ["https://registry.npmjs.org/@s%2Fp"]);
  assert.deepEqual(res.evidence.map((e) => `${e.version}:${e.status}`), ["1.0.0:ok", "2.0.0:ok"]);
  assert.equal(registryUrl("https://r.example/", "@a/b"), "https://r.example/@a%2Fb");
});

test("soak: a name is one path segment of the registry URL, whatever slashes it holds", () => {
  // The lockfile readers refuse such a name (src/lockfile/identity.ts); the URL does not rely on that.
  const url = registryUrl("https://r.example", "a/../../b");
  assert.equal(url, "https://r.example/a%2F..%2F..%2Fb");
  assert.equal(new URL(url).pathname, "/a%2F..%2F..%2Fb", "no dot-segment reaches another document");
});

test("soak: git and non-registry tarballs fail closed and are never looked up by name; local code is listed, not failed", async () => {
  const r = registry({ ok: { "1.0.0": 500 }, gitdep: { "1.0.0": 500 }, offsite: { "1.0.0": 500 }, mirror: { "1.0.0": 500 }, patched: { "1.0.0": 500 } });
  const l = lock({ ok: "1.0.0" });
  l.packages.push(
    { name: "gitdep", version: "1.0.0", resolved: "git+ssh://git@github.com/a/b.git#abc" },
    { name: "v1git", version: "github:a/b#abc" },
    { name: "offsite", version: "1.0.0", resolved: "https://evil.example/offsite-1.0.0.tgz", integrity: "sha512-x" },
    { name: "mirror", version: "1.0.0", resolved: "https://registry.yarnpkg.com/mirror/-/mirror-1.0.0.tgz", integrity: "sha512-x" },
    { name: "patched", version: "1.0.0", resolved: "patch:patched@npm%3A1.0.0#~builtin<compat/patched>" },
    { name: "linked", version: "1.0.0", local: true },
    { name: "tgz", version: "1.0.0", resolved: "file:vendor/tgz-1.0.0.tgz" },
    { name: "portal", version: "0.0.0-use.local", resolved: "portal:../portal" },
  );
  const res = await checkSoakLockfiles([l], opts(r.f));
  const failed = Object.fromEntries(res.findings.map((f) => [f.key.split(" ")[0], f]));
  assert.deepEqual(Object.keys(failed).sort(), ["gitdep@1.0.0", "offsite@1.0.0", "v1git@github:a/b#abc"]);
  assert.ok(res.findings.every((f) => f.ruleId === "WS-SK-002" && f.severity === "high"));
  assert.match(failed["gitdep@1.0.0"]?.message ?? "", /git source/);
  assert.match(failed["offsite@1.0.0"]?.message ?? "", /resolves from evil.example, not https:\/\/registry.npmjs.org/);
  assert.deepEqual(r.calls.map((c) => c.split("/").pop()).sort(), ["mirror", "ok", "patched"], "unverifiable names never reach the registry");
  assert.match(res.notes.join("\n"), /3 local package\(s\) not age-checked .*linked, tgz, portal/);
});

test("soak: .npmrc scope and default registries that differ from --registry fail closed without leaking names", async () => {
  const r = registry({ "@corp/x": { "1.0.0": 500 }, plain: { "1.0.0": 500 } });
  const pnpmStyle = (name: string): LockedPackage => ({ name, version: "1.0.0", integrity: "sha512-x" });
  const l: ParsedLockfile = { kind: "pnpm", file: "pnpm-lock.yaml", packages: [pnpmStyle("@corp/x"), pnpmStyle("plain")] };
  const regs = (files: Record<string, string>) => (lk: ParsedLockfile) => installRegistries(proj(files), lk, {});
  const scoped = await checkSoakLockfiles([l], opts(r.f, { installRegistries: regs({ ".npmrc": "@corp:registry=https://npm.corp.example/\n" }) }));
  assert.deepEqual(scoped.findings.map((f) => f.key.split(" ")[0]), ["@corp/x@1.0.0"]);
  assert.match(scoped.findings[0]?.message ?? "", /\.npmrc installs @corp from https:\/\/npm.corp.example\//);
  assert.deepEqual(r.calls, ["https://registry.npmjs.org/plain"]);
  const all = await checkSoakLockfiles([l], opts(r.f, { installRegistries: regs({ ".npmrc": "registry=https://npm.corp.example/\n" }) }));
  assert.equal(all.findings.length, 2);
});

test("soak: a version removed from the registry fails even after its window has passed", async () => {
  const r = registry({ tinycolor: { "4.1.0": 9000, "4.1.1": { h: 9000, removed: true } } });
  const res = await checkSoakLockfiles([lock({ tinycolor: "4.1.1" })], opts(r.f));
  assert.equal(res.findings[0]?.ruleId, "WS-SK-002");
  assert.match(res.findings[0]?.message ?? "", /no longer in the registry/);
  assert.equal(res.evidence[0]?.status, "unverifiable");
});

test("soak: an entry whose integrity is not the registry's for its name@version fails closed", async () => {
  const sha1hex = "a".repeat(40);
  const sha1 = `sha1-${Buffer.from(sha1hex, "hex").toString("base64")}`;
  const r = registry({ benign: { "1.0.0": 9000 }, old: { "1.0.0": { h: 9000, integrity: "", shasum: sha1hex } } });
  const l = lock({ benign: "1.0.0" });
  l.packages.push(
    { name: "benign", version: "1.0.0", resolved: tarball("benign", "1.0.0"), integrity: "sha512-young" },
    { name: "old", version: "1.0.0", resolved: "https://registry.npmjs.org/old/-/renamed.tgz", integrity: sha1 },
  );
  const res = await checkSoakLockfiles([l], opts(r.f));
  assert.deepEqual(res.findings.map((f) => f.message.replace(/:.*/, "")), ["Cannot verify soak time for benign@1.0.0"]);
  assert.match(res.findings[0]?.message ?? "", /integrity differs/);
  assert.deepEqual(res.evidence.map((e) => e.status), ["ok", "unverifiable", "ok"], "a matching sha1 integrity proves the content whatever the URL");
});

test("soak: an entry relabelled as an old package is age-checked as the registry tarball it downloads", async () => {
  // old@1.0.0 has soaked for years, but both entries fetch young-6.6.6.tgz, published 5 hours ago.
  const r = registry({ old: { "1.0.0": 9000 }, young: { "6.6.6": { h: 5, integrity: "sha512-young" } } });
  const l = lock({});
  l.packages.push(
    { name: "old", version: "1.0.0", resolved: tarball("young", "6.6.6"), integrity: "sha512-young" },
    { name: "old", version: "1.0.0", resolved: tarball("young", "6.6.6") },
  );
  const res = await checkSoakLockfiles([l], opts(r.f));
  assert.deepEqual(r.calls, ["https://registry.npmjs.org/young"], "the label's packument is irrelevant to what is installed");
  assert.deepEqual([...new Set(res.findings.map((f) => `${f.ruleId} ${f.key}`))], ["WS-SK-001 young@6.6.6"]);
  // Fail closed when the real tarball cannot be verified either.
  const missing = await checkSoakLockfiles([l], opts(registry({ old: { "1.0.0": 9000 } }).f));
  assert.ok(missing.findings.length > 0 && missing.findings.every((f) => f.ruleId === "WS-SK-002" && f.message.includes("young@6.6.6")));
});

test("soak: PR mode checks only the named identities, each in its own lockfile", async () => {
  const r = registry({ a: { "1.0.0": 1 }, b: { "1.0.0": 1 } });
  const l = lock({ a: "1.0.0", b: "1.0.0" });
  const b = l.packages.find((p) => p.name === "b") as LockedPackage;
  assert.equal(onlyKey("package-lock.json", b), `package-lock.json\0b@1.0.0 ${b.resolved} ${b.integrity}`);
  const res = await checkSoakLockfiles([l], opts(r.f, { only: new Set([onlyKey("package-lock.json", b)]) }));
  assert.deepEqual(res.findings.map((f) => f.key), ["b@1.0.0"]);
  assert.equal(r.calls.length, 1);
  // The same identity named for another lockfile does not select this one's entry.
  const other = await checkSoakLockfiles([l], opts(registry({ a: { "1.0.0": 1 }, b: { "1.0.0": 1 } }).f, { only: new Set([onlyKey("docs/package-lock.json", b)]) }));
  assert.deepEqual(other.findings, []);
});

/* ---- config readers ---- */
test("config readers: npm days (last wins, comments), bun seconds under [install], lists", () => {
  assert.deepEqual(readNpmrc("registry=x\nmin-release-age=7\n"), { days: 7, raw: "7" });
  assert.deepEqual(readNpmrc("min-release-age=7\nmin-release-age = 1 ; lowered\n"), { days: 1, raw: "1" });
  assert.equal(readNpmrc("# min-release-age=7\n"), undefined);
  assert.equal(readBunfig("[install]\nminimumReleaseAge = 259200\n")?.seconds, 259200);
  assert.equal(readBunfig("minimumReleaseAge = 259200\n[install]\n"), undefined, "wrong section");
  // A table header may carry a comment, as TOML allows: `[test] # unit tests` ends [install], `[install] # bun` starts it.
  assert.equal(readBunfig('[install]\nregistry = "https://registry.npmjs.org"\n[test] # unit tests\nminimumReleaseAge = 604800\n'), undefined);
  assert.deepEqual(readBunfig("[install] # bun\nminimumReleaseAge = 604800\n"), { seconds: 604800, raw: "604800" });
  assert.deepEqual(readBunfig("[ install ]\t# bun\r\nminimumReleaseAge = 604800\r\n"), { seconds: 604800, raw: "604800" });
  assert.equal(bunExcludes('[install]\n[test] # c\nminimumReleaseAgeExcludes = ["x"]\n'), undefined);
  // An array of tables is a header too, never [install]; a multi-line string's lines are its content (a round-2 review).
  assert.equal(readBunfig("[install]\n[[test.x]]\nminimumReleaseAge = 604800"), undefined);
  assert.equal(readBunfig("[[install]]\nminimumReleaseAge = 604800\n"), undefined);
  assert.equal(readBunfig('[test]\nnote = """\n[install]\nminimumReleaseAge = 604800\n"""\n'), undefined);
  assert.deepEqual(readBunfig("[install]\nnote = '''\n[test]\n'''\nminimumReleaseAge = 604800\n"), { seconds: 604800, raw: "604800" });
  assert.deepEqual(readBunfig('[install]\nnote = """x"""\nminimumReleaseAge = 604800\n'), { seconds: 604800, raw: "604800" });
  // TOML integers, as Bun reads them: an underscore between digits is a separator (604_800 is 604800).
  assert.deepEqual(readBunfig("[install]\r\nminimumReleaseAge = 604_800 # 7 days\r\n"), { seconds: 604800, raw: "604_800" });
  assert.deepEqual(readBunfig("[install]\nminimumReleaseAge = 6_0_4_8_0_0\n"), { seconds: 604800, raw: "6_0_4_8_0_0" });
  // Anything else is there but unreadable: no seconds, so the check reports it instead of passing it or calling it missing.
  for (const raw of ["604__800", "_604800", "604800_", "0604800", "604800.0", "0x93A80", '"604800"', "7d", ""]) {
    assert.deepEqual(readBunfig(`[install]\nminimumReleaseAge = ${raw}\n`), { raw }, raw);
  }
  assert.equal(bunExcludes('[install]\nminimumReleaseAgeExcludes = [\n  "typescript",\n]\n'), '[ "typescript", ]');
  assert.equal(bunExcludes('minimumReleaseAgeExcludes = ["x"]\n[install]\n'), undefined);
});

function proj(files: Record<string, string>) {
  const d = mkdtempSync(join(tmpdir(), "ws-cfg-"));
  for (const [k, v] of Object.entries(files)) {
    mkdirSync(join(d, k, ".."), { recursive: true });
    writeFileSync(join(d, k), v);
  }
  return d;
}
const npmLock = (file = "package-lock.json"): ParsedLockfile[] => [{ ...lock({ a: "1.0.0" }), file }];
const pnpmLock = () => [{ kind: "pnpm" as const, file: "pnpm-lock.yaml", packages: [] }];
const berryLock = () => [{ kind: "yarn-berry" as const, file: "yarn.lock", packages: [] }];
const NEW: InstalledVersion = { version: "99.0.0", source: "stub" };
const cfg = (root: string, locks: ParsedLockfile[], extra: Partial<Omit<ConfigOptions, keyof TreeInputs>> = {}) => checkSoakConfig(root, locks, { minAgeMs: 72 * H, versionOf: () => NEW, ...extra });
const rules = (fs: { ruleId: string }[]) => fs.map((f) => f.ruleId);

test("config: missing, too short, sufficient - per package manager", () => {
  assert.deepEqual(rules(cfg(proj({}), npmLock())), ["WS-SK-003"]);
  assert.deepEqual(rules(cfg(proj({ ".npmrc": "min-release-age=1\n" }), npmLock())), ["WS-SK-004"]);
  assert.deepEqual(cfg(proj({ ".npmrc": "min-release-age=3\n" }), npmLock()), []);
  assert.deepEqual(rules(cfg(proj({}), pnpmLock())), ["WS-SK-003"]);
  assert.deepEqual(rules(cfg(proj({ "pnpm-workspace.yaml": "minimumReleaseAge: 60\n" }), pnpmLock())), ["WS-SK-004"]);
  assert.deepEqual(cfg(proj({ "pnpm-workspace.yaml": "minimumReleaseAge: 4320\n" }), pnpmLock()), []);
  assert.deepEqual(rules(cfg(proj({}), berryLock())), ["WS-SK-003"]);
  assert.deepEqual(cfg(proj({ ".yarnrc.yml": "npmMinimalAgeGate: 10080\n" }), berryLock()), []);
  assert.deepEqual(rules(cfg(proj({ ".yarnrc.yml": "npmMinimalAgeGate: 7\n" }), berryLock())), ["WS-SK-004"], "7 minutes");
  const suffixed = cfg(proj({ ".yarnrc.yml": 'npmMinimalAgeGate: "7d"\n' }), berryLock());
  assert.equal(suffixed[0]?.ruleId, "WS-SK-004", "the exact false green found in Yarn 4.10.3: 7d is read as 7 minutes");
  assert.match(suffixed[0]?.message ?? "", /4320/);
  assert.deepEqual(rules(cfg(proj({ "bunfig.toml": "[install]\n" }), [])), ["WS-SK-003"]);
  assert.deepEqual(cfg(proj({ "bunfig.toml": "[install]\nminimumReleaseAge = 259200\n" }), []), []);
  assert.deepEqual(cfg(proj({ "bunfig.toml": "[install]\nminimumReleaseAge = 259_200\n" }), []), [], "Bun reads 259_200 as 259200");
  const unreadable = cfg(proj({ "bunfig.toml": "[install]\nminimumReleaseAge = 259__200\n" }), []);
  assert.deepEqual(rules(unreadable), ["WS-SK-004"]);
  assert.equal(unreadable[0]?.message, "bunfig.toml: minimumReleaseAge = 259__200 could not be interpreted as a duration; required soak is 3.0d");
});

test("config: yarn classic has no setting, and the finding says the lockfile gate is the control", () => {
  const f = cfg(proj({}), [{ kind: "yarn-classic", file: "yarn.lock", packages: [] }]);
  assert.match(f[0]?.message ?? "", /lockfile gate/);
});

test("config: nothing to check is reported, not silently passed", () => {
  assert.deepEqual(rules(cfg(proj({}), [])), ["WS-SK-003"]);
  assert.match(cfg(proj({}), [])[0]?.message ?? "", /cannot tell which package manager/);
});

test("config: npm precedence is environment, then the project's own .npmrc, then the user's; last key wins", () => {
  const user = "min-release-age=14\n";
  assert.deepEqual(cfg(proj({}), npmLock(), { userNpmrc: user }), [], "user-level value counts when the project sets none");
  const lowered = cfg(proj({ ".npmrc": "min-release-age=1\n" }), npmLock(), { userNpmrc: user });
  assert.deepEqual(rules(lowered), ["WS-SK-004"], "the project's 1 day overrides the user's 14 (npm prints 1)");
  assert.match(lowered[0]?.message ?? "", /^\.npmrc: min-release-age = 1 days/);
  assert.deepEqual(rules(cfg(proj({ ".npmrc": "min-release-age=5\nmin-release-age=0\n" }), npmLock())), ["WS-SK-004"], "the last duplicate wins");
  const env = cfg(proj({ ".npmrc": "min-release-age=14\n" }), npmLock(), { env: { NPM_CONFIG_MIN_RELEASE_AGE: "1" } });
  assert.match(env[0]?.message ?? "", /environment variable NPM_CONFIG_MIN_RELEASE_AGE: min-release-age = 1 days/);
  const nested = cfg(proj({ ".npmrc": "min-release-age=14\n", "svc/.npmrc": "min-release-age=1\n" }), npmLock("svc/package-lock.json"));
  assert.deepEqual(nested.map((f) => `${f.ruleId} ${f.file}`), ["WS-SK-004 svc/.npmrc"], "a nested project uses its own .npmrc, not the root's");
  assert.deepEqual(rules(cfg(proj({ ".npmrc": "min-release-age=14\n" }), npmLock("svc/package-lock.json"))), ["WS-SK-003"]);
});

test("config: a setting the installed package manager ignores, or whose enforcement cannot be verified, is reported", () => {
  const d = proj({ ".npmrc": "min-release-age=3\n" });
  const old = cfg(d, npmLock(), { versionOf: () => ({ version: "10.9.2", source: "`npm --version`" }) });
  assert.deepEqual(rules(old), ["WS-SK-004"]);
  assert.match(old[0]?.message ?? "", /npm 10\.9\.2 \(from `npm --version`\) ignores it; npm 11\.10\.0 or newer/);
  assert.deepEqual(cfg(d, npmLock(), { versionOf: () => ({ version: "11.10.0", source: "x" }) }), []);
  const unknown = cfg(d, npmLock(), { versionOf: () => ({ source: "`npm --version` failed: ENOENT" }) });
  assert.match(unknown[0]?.message ?? "", /could not be determined .*ENOENT.*unverified/);
  const yarn = cfg(proj({ ".yarnrc.yml": "npmMinimalAgeGate: 4320\n" }), berryLock(), { versionOf: () => ({ version: "4.9.4", source: "x" }) });
  assert.match(yarn[0]?.message ?? "", /yarn 4\.9\.4 .*ignores it/);
});

test("config: pnpm, yarn and bun settings that switch the gate off are reported even with a long enough age", () => {
  const ws = "minimumReleaseAge: 4320\ntrustLockfile: true\nminimumReleaseAgeStrict: false\nminimumReleaseAgeExclude:\n  - '*'\n";
  const p = cfg(proj({ "pnpm-workspace.yaml": ws }), pnpmLock());
  assert.deepEqual(p.map((f) => f.key), ["pnpm:trustLockfile=true", "pnpm:minimumReleaseAgeStrict=false", "pnpm:minimumReleaseAgeExclude=- '*'"]);
  assert.ok(p.every((f) => f.ruleId === "WS-SK-004" && f.severity === "medium"));
  assert.match(p[2]?.message ?? "", /minimumReleaseAgeExclude: - '\*' exempts/);
  assert.deepEqual(cfg(proj({ "pnpm-workspace.yaml": "minimumReleaseAge: 4320\nminimumReleaseAgeExclude: []\n" }), pnpmLock()), []);
  const y = cfg(proj({ ".yarnrc.yml": "npmMinimalAgeGate: 4320\nnpmPreapprovedPackages:\n  - \"*\"\n" }), berryLock());
  assert.deepEqual(y.map((f) => f.key), ['yarn:npmPreapprovedPackages=- "*"']);
  const b = cfg(proj({ "bunfig.toml": '[install]\nminimumReleaseAge = 259200\nminimumReleaseAgeExcludes = ["typescript"]\n' }), []);
  assert.deepEqual(b.map((f) => f.key), ['bun:minimumReleaseAgeExcludes=["typescript"]']);
});

test("config: pnpm's missing-setting message states the real defaults; pnpm 10 reads .npmrc, pnpm 11 does not", () => {
  assert.match(cfg(proj({}), pnpmLock())[0]?.message ?? "", /pnpm 11 defaults to 1 day in loose mode.*pnpm 10 has no default/);
  const d = proj({ ".npmrc": "minimum-release-age=4320\n" });
  assert.deepEqual(cfg(d, pnpmLock(), { versionOf: () => ({ version: "10.33.0", source: "x" }) }), []);
  assert.deepEqual(rules(cfg(d, pnpmLock(), { versionOf: () => ({ version: "11.16.0", source: "x" }) })), ["WS-SK-003"]);
});

/** Fake package-manager binaries: each prints its version and records the directory it ran in. */
function stubBin(versions: Record<string, string>) {
  const d = mkdtempSync(join(tmpdir(), "ws-bin-"));
  for (const [m, v] of Object.entries(versions)) {
    writeFileSync(join(d, m), `#!/bin/sh\npwd > "${d}/${m}.cwd"\necho ${v}\n`);
    chmodSync(join(d, m), 0o755);
  }
  return d;
}

test("installedVersion: pins win, the binary is asked from outside the project, failures say why", () => {
  const bin = stubBin({ npm: "11.12.0", pnpm: "11.16.0", yarn: "1.22.22" });
  const d = proj({ "package.json": '{"packageManager":"pnpm@9.15.0+sha512.abc"}', ".yarnrc.yml": "yarnPath: .yarn/releases/yarn-4.9.4.cjs\n" });
  assert.deepEqual(installedVersion("npm", d, { PATH: bin }), { version: "11.12.0", source: "`npm --version`" });
  assert.notEqual(realpathSync(readFileSync(join(bin, "npm.cwd"), "utf8").trim()), realpathSync(d), "never run inside the scanned tree");
  assert.deepEqual(installedVersion("pnpm", d, { PATH: bin }), { version: "9.15.0", source: "packageManager in package.json" });
  assert.equal(installedVersion("yarn", d, { PATH: bin }).version, "4.9.4", "yarnPath decides which Yarn runs");
  const missing = installedVersion("bun", d, { PATH: bin });
  assert.equal(missing.version, undefined);
  assert.match(missing.source, /`bun --version` failed/);
});

/* ---- CLI ---- */
/** An npm project whose .npmrc meets the CLI's default 7-day soak. */
function soakProject(pkgs: Record<string, string> = { young: "1.0.0" }) {
  const d = proj({ ".npmrc": "min-release-age=7\n" });
  writeFileSync(join(d, "package-lock.json"), npmLockText(pkgs));
  return d;
}
function npmLockText(pkgs: Record<string, string>) {
  const packages: Record<string, unknown> = { "": {} };
  for (const [n, v] of Object.entries(pkgs)) packages[`node_modules/${n}`] = { version: v, resolved: tarball(n, v), integrity: "sha512-x" };
  return JSON.stringify({ lockfileVersion: 3, packages });
}
type Out = { extra?: { evidence: { name: string; status: string }[] }; findings: { ruleId: string; message: string; severity: string; key: string }[]; notes: string[] };
async function soakJson(args: string[], over: Parameters<typeof fakeIO>[0] = {}): Promise<{ code: number; out: Out }> {
  const io = fakeIO(over);
  const code = await run(["soak", ...args, "--format", "json"], io);
  return { code, out: JSON.parse(io.out) as Out };
}

test("cli soak: fails on a young package, passes once the window is shorter, and reports evidence in JSON", async () => {
  const d = soakProject();
  const r = registry({ young: { "1.0.0": 10 } });
  const { code, out } = await soakJson([d], { fetchImpl: r.f, env: { HOME: d } });
  assert.equal(code, 1);
  assert.equal(out.extra?.evidence[0]?.status, "too-new");
  assert.equal(out.findings.find((f) => f.severity === "high")?.ruleId, "WS-SK-001");
  assert.equal(await run(["soak", d, "--min-age", "1h"], fakeIO({ fetchImpl: r.f, env: { HOME: d } })), 0);
});
test("cli soak: the default --min-age is 7 days (5 days old is too new, 8 days is ok); --min-age 72h is the tuned value", async () => {
  const d = soakProject({ five: "1.0.0", eight: "1.0.0" });
  const r = registry({ five: { "1.0.0": 5 * 24 }, eight: { "1.0.0": 8 * 24 } });
  const status = (o: Out) => Object.fromEntries((o.extra?.evidence ?? []).map((e) => [e.name, e.status]));
  const def = await soakJson([d], { fetchImpl: r.f, env: { HOME: d } });
  assert.equal(def.code, 1);
  assert.deepEqual(status(def.out), { five: "too-new", eight: "ok" });
  assert.match(def.out.findings.find((f) => f.ruleId === "WS-SK-001")?.message ?? "", /^five@1\.0\.0 .*inside the required 7\.0d soak window/);
  const tuned = await soakJson([d, "--min-age", "72h"], { fetchImpl: r.f, env: { HOME: d } });
  assert.equal(tuned.code, 0, "positive control: the same versions pass a 72h soak");
  assert.deepEqual(status(tuned.out), { five: "ok", eight: "ok" });
  // The configuration check uses the same default: a 3-day npm cooldown is too short for it.
  const short = proj({ ".npmrc": "min-release-age=3\n", "package-lock.json": npmLockText({}) });
  const cfgOnly = await soakJson([short, "--config-only"], { env: { HOME: short } });
  assert.match(cfgOnly.out.findings.map((f) => f.message).join("\n"), /^\.npmrc: min-release-age = 3 days is 3\.0d, shorter than the required 7\.0d$/m);
  // The help text states the same default the parser uses.
  const help = fakeIO();
  await run(["--help"], help);
  assert.match(help.out, /--min-age <duration> +soak: required age, e\.g\. 7d, 72h \(default 7d\)/);
  // The Action adds no default of its own: an empty min-age input leaves the CLI default in force.
  assert.match(readFileSync(join(import.meta.dirname, "..", "..", "action.yml"), "utf8"), /\n {2}min-age:\n(?: {4}.*\n)*? {4}default: ""\n/);
});
test("cli soak: --config-only makes no network call; --require-config turns a missing setting into a failure", async () => {
  const d = mkdtempSync(join(tmpdir(), "ws-cc-"));
  writeFileSync(join(d, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: { "": {} } }));
  const boom = (async () => {
    throw new Error("network must not be used");
  }) as typeof fetch;
  const env = { HOME: d };
  assert.equal(await run(["soak", d, "--config-only"], fakeIO({ fetchImpl: boom, env })), 0, "missing config is medium: reported but below the default gate");
  assert.equal(await run(["soak", d, "--config-only", "--require-config"], fakeIO({ fetchImpl: boom, env })), 1);
  assert.equal(await run(["soak", d, "--min-age", "banana"], fakeIO({ env })), 2);
});
test("cli soak: --require-config fails when the installed npm ignores the setting, and passes on one that enforces it", async () => {
  const d = soakProject();
  const old = await soakJson([d, "--config-only", "--require-config"], { env: { HOME: d, PATH: stubBin({ npm: "10.9.2" }) } });
  assert.equal(old.code, 1);
  assert.match(old.out.findings[0]?.message ?? "", /npm 10\.9\.2 .*ignores it/);
  assert.match(old.out.notes.join("\n"), /do not stop `npm ci`/);
  assert.equal(await run(["soak", d, "--config-only", "--require-config"], fakeIO({ env: { HOME: d, PATH: stubBin({ npm: "11.10.0" }) } })), 0);
});
test("cli soak: the user .npmrc comes from NPM_CONFIG_USERCONFIG when set (actions/setup-node sets it)", async () => {
  const d = proj({ "package-lock.json": npmLockText({}), "ci.npmrc": "min-release-age=14\n" });
  const env = { HOME: d, PATH: stubBin({ npm: "11.10.0" }), NPM_CONFIG_USERCONFIG: join(d, "ci.npmrc") };
  assert.equal(await run(["soak", d, "--config-only", "--require-config"], fakeIO({ env })), 0);
});
test("cli soak: there is no --cache-file: it is an unknown option, refused before any request (a cache could vouch for a forged publish time)", async () => {
  const d = soakProject();
  writeFileSync(join(d, ".soak-cache.json"), JSON.stringify({ "young@1.0.0": "2000-01-01T00:00:00Z" }));
  const r = registry({ young: { "1.0.0": 10 } });
  const io = fakeIO({ fetchImpl: r.f, env: { HOME: d } });
  assert.equal(await run(["soak", d, "--cache-file", join(d, ".soak-cache.json")], io), 2);
  assert.match(io.err, /^wormsign: unknown option --cache-file$/m);
  assert.deepEqual(r.calls, []);
});
test("cli soak: baseline entry with a justification allows a specific young package", async () => {
  const d = soakProject();
  const r = registry({ young: { "1.0.0": 10 } });
  writeFileSync(join(d, ".wormsign-baseline.json"), JSON.stringify({ version: 1, entries: [{ fingerprint: fingerprint("WS-SK-001", "package-lock.json", "young@1.0.0"), justification: "Emergency CVE fix, reviewed diff by hand", expires: "2026-10-08" }] }));
  assert.equal(await run(["soak", d], fakeIO({ fetchImpl: r.f, env: { HOME: d } })), 0);
});

test("cli soak: an unreadable, symlinked, bun-only or missing lockfile fails closed instead of passing with a note", async () => {
  const r = registry({ young: { "1.0.0": 10 } });
  const env = { HOME: tmpdir() };
  const bad = proj({ "package-lock.json": '{"lockfileVersion": 3,}' });
  const parsed = await soakJson([bad], { fetchImpl: r.f, env });
  assert.equal(parsed.code, 1);
  assert.match(parsed.out.findings.find((f) => f.ruleId === "WS-SK-002")?.message ?? "", /package-lock.json: it could not be parsed/);
  assert.doesNotMatch(parsed.out.notes.join("\n"), /no lockfile/);

  const real = soakProject();
  const linked = proj({});
  symlinkSync(join(real, "package-lock.json"), join(linked, "package-lock.json"));
  assert.match((await soakJson([linked], { fetchImpl: r.f, env })).out.findings.find((f) => f.ruleId === "WS-SK-002")?.message ?? "", /symlink/);

  const bun = await soakJson([proj({ "bun.lock": "{}", "package.json": '{"dependencies":{"a":"1"}}' })], { fetchImpl: r.f, env });
  assert.equal(bun.code, 1);
  assert.match(bun.out.findings.find((f) => f.ruleId === "WS-SK-002")?.message ?? "", /bun.lock: bun lockfiles are not supported/);

  const none = await soakJson([proj({ "package.json": '{"dependencies":{"young":"^1"}}' })], { fetchImpl: r.f, env });
  assert.equal(none.code, 1);
  assert.match(none.out.findings.find((f) => f.ruleId === "WS-SK-002")?.message ?? "", /package.json: it declares dependencies but there is no lockfile/);
  const empty = await soakJson([proj({ "package.json": '{"name":"x"}' })], { fetchImpl: r.f, env });
  assert.equal(empty.code, 0);
  assert.match(empty.out.notes.join("\n"), /no lockfile and no dependencies declared/);

  const unread = await soakJson([proj({ "package.json": '{"devDependencies":{"young":"^1"}}', "package-lock.json": npmLockText({}) })], { fetchImpl: r.f, env });
  assert.equal(unread.code, 1, "a lockfile that yields no packages while package.json declares some is not 'verified'");
});

test("cli soak: a UTF-8 BOM does not hide the lockfile (npm installs from it)", async () => {
  const d = proj({ "package-lock.json": `\uFEFF${npmLockText({ young: "1.0.0" })}` });
  const r = registry({ young: { "1.0.0": 10 } });
  const { code, out } = await soakJson([d], { fetchImpl: r.f, env: { HOME: d } });
  assert.equal(code, 1);
  assert.deepEqual(out.findings.filter((f) => f.severity === "high").map((f) => f.ruleId), ["WS-SK-001"], "read and checked, not merely reported as unparseable");
});

test("cli soak: .npmrc scope registry keeps a private package away from the public registry", async () => {
  const d = proj({ ".npmrc": "@corp:registry=https://npm.corp.example/\n", "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/@corp/x": { version: "1.0.0", integrity: "sha512-x" } } }) });
  const r = registry({});
  const { code, out } = await soakJson([d], { fetchImpl: r.f, env: { HOME: d } });
  assert.equal(code, 1);
  assert.deepEqual(r.calls, []);
  assert.match(out.findings.find((f) => f.ruleId === "WS-SK-002")?.message ?? "", /installs @corp from https:\/\/npm.corp.example/);
});

/** A git repository with `files` committed; the test then edits the working tree, which plays the PR head. */
function gitRepo(files: Record<string, string>) {
  const d = proj(files);
  git(d, "init", "-q");
  git(d, "add", ".");
  git(d, "commit", "-qm", "base");
  return d;
}
test("cli soak: PR mode (--base) only fetches packages the change introduced", async () => {
  const d = gitRepo({ "package-lock.json": npmLockText({ young: "1.0.0" }) });
  const r = registry({});
  assert.equal(await run(["soak", d, "--base", "HEAD"], fakeIO({ fetchImpl: r.f, env: { HOME: d } })), 0);
  assert.equal(r.calls.length, 0, "nothing changed, so nothing is fetched");
});
test("cli soak: PR mode still checks, and fails on, a young package the base lacks", async () => {
  const d = gitRepo({ "package-lock.json": npmLockText({ old: "1.0.0" }) });
  writeFileSync(join(d, "package-lock.json"), npmLockText({ old: "1.0.0", young: "1.0.0" }));
  const r = registry({ old: { "1.0.0": 400 }, young: { "1.0.0": 10 } });
  const { code, out } = await soakJson([d, "--base", "HEAD"], { fetchImpl: r.f, env: { HOME: d } });
  assert.equal(code, 1);
  assert.deepEqual(r.calls, ["https://registry.npmjs.org/young"]);
  assert.deepEqual(out.findings.filter((f) => f.severity === "high").map((f) => f.ruleId), ["WS-SK-001"]);
});
test("cli soak: PR mode treats a relabelled entry (same name@version, new tarball) as changed", async () => {
  const relabelled = JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/old": { version: "1.0.0", resolved: tarball("young", "6.6.6"), integrity: "sha512-young" } } });
  const d = gitRepo({ "package-lock.json": npmLockText({ old: "1.0.0" }) });
  writeFileSync(join(d, "package-lock.json"), relabelled);
  const r = registry({ old: { "1.0.0": 400 }, young: { "6.6.6": { h: 5, integrity: "sha512-young" } } });
  const { code, out } = await soakJson([d, "--base", "HEAD"], { fetchImpl: r.f, env: { HOME: d } });
  assert.equal(code, 1);
  // The lockfile parser names an entry by the registry tarball it fetches, so the relabelled entry is checked as young@6.6.6.
  assert.deepEqual(r.calls, ["https://registry.npmjs.org/young"]);
  assert.deepEqual(out.findings.filter((f) => f.severity === "high").map((f) => `${f.ruleId} ${f.message.split(" ")[0]}`), ["WS-SK-001 young@6.6.6"]);
});

function git(cwd: string, ...args: string[]) {
  execFileSync("git", ["-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...args], { cwd, stdio: "ignore" });
}
test("cli soak: with --base the baseline comes from the base revision, so a change cannot baseline its own findings (project in a subdirectory)", async () => {
  const repo = mkdtempSync(join(tmpdir(), "ws-git-"));
  const app = join(repo, "app");
  mkdirSync(app);
  git(repo, "init", "-q");
  writeFileSync(join(app, "package-lock.json"), npmLockText({ old: "1.0.0" }));
  git(repo, "add", ".");
  git(repo, "commit", "-qm", "base");
  writeFileSync(join(app, "package-lock.json"), npmLockText({ old: "1.0.0", young: "1.0.0" }));
  const fp = fingerprint("WS-SK-001", "package-lock.json", "young@1.0.0");
  writeFileSync(join(app, ".wormsign-baseline.json"), JSON.stringify({ version: 1, entries: [{ fingerprint: fp, justification: "the PR author says this is fine" }] }));
  git(repo, "add", ".");
  git(repo, "commit", "-qm", "head");
  const r = registry({ old: { "1.0.0": 400 }, young: { "1.0.0": 10 } });
  assert.equal(await run(["soak", app], fakeIO({ fetchImpl: r.f, env: { HOME: repo } })), 0, "positive control: the head's baseline is valid and does suppress");
  r.calls.length = 0;
  const { code, out } = await soakJson([app, "--base", "HEAD~1"], { fetchImpl: r.f, env: { HOME: repo } });
  assert.equal(code, 1, "the head's own baseline entry is ignored in PR mode");
  assert.deepEqual(r.calls, ["https://registry.npmjs.org/young"], "base lockfile read relative to the subdirectory");
  assert.match(out.notes.join("\n"), /baseline read from HEAD~1/);
});

/* ---- OSV and registry signals in `wormsign soak` ---- */

type Ev = { name: string; version: string; osv?: string[]; registry?: { comparedWith?: string; signals: string[] } };
const evidenceOf = (out: Out, name: string) => (out.extra?.evidence as Ev[] | undefined)?.find((e) => e.name === name);
const D = 24;

test("cli soak: OSV is asked by default about each package looked up on the registry; a MAL- record is critical; --no-osv opts out", async () => {
  const d = soakProject({ old: "1.0.0", bad: "2.0.0" });
  const r = registry({ old: { "1.0.0": 400 }, bad: { "2.0.0": 400 } }, {}, { "bad@2.0.0": ["MAL-2025-1"] });
  const { code, out } = await soakJson([d], { fetchImpl: r.f, env: { HOME: d } });
  assert.equal(code, 1);
  assert.deepEqual(r.osvAsked.sort(), ["bad@2.0.0", "old@1.0.0"]);
  assert.deepEqual(out.findings.filter((f) => f.severity === "critical").map((f) => `${f.ruleId} ${f.message}`), ["WS-OS-001 bad@2.0.0 is a malicious package version according to OSV record MAL-2025-1"]);
  assert.deepEqual(evidenceOf(out, "bad")?.osv, ["MAL-2025-1"]);
  assert.deepEqual(evidenceOf(out, "old")?.osv, [], "checked, no record");
  assert.match(out.notes.join("\n"), /2 package version\(s\) checked against OSV/);

  const off = registry({ old: { "1.0.0": 400 }, bad: { "2.0.0": 400 } }, {}, { "bad@2.0.0": ["MAL-2025-1"] });
  const skipped = await soakJson([d, "--no-osv"], { fetchImpl: off.f, env: { HOME: d } });
  assert.equal(skipped.code, 0);
  assert.deepEqual(off.osvAsked, []);
  assert.equal(evidenceOf(skipped.out, "bad")?.osv, undefined, "not checked is not shown as clean");
  assert.match(skipped.out.notes.join("\n"), /OSV not asked .*--no-osv/);
});

test("cli soak: OSV never sees a local, git or other-registry name, and is not asked at all with another --registry", async () => {
  const packages = {
    "": {},
    "node_modules/pub": { version: "1.0.0", resolved: tarball("pub", "1.0.0"), integrity: "sha512-x" },
    "node_modules/gitdep": { version: "1.0.0", resolved: "git+ssh://git@github.com/acme/gitdep.git#0123456789abcdef0123456789abcdef01234567" },
    "node_modules/@corp/x": { version: "1.0.0", integrity: "sha512-x" },
    "node_modules/loc": { version: "1.0.0", link: true },
  };
  const d = proj({ ".npmrc": "@corp:registry=https://npm.corp.example/\n", "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages }) });
  const r = registry({ pub: { "1.0.0": 400 } });
  const { code, out } = await soakJson([d], { fetchImpl: r.f, env: { HOME: d } });
  assert.equal(code, 1, "the git and private entries still fail closed (WS-SK-002)");
  assert.deepEqual(r.osvAsked, ["pub@1.0.0"]);
  assert.match(out.notes.join("\n"), /1 package version\(s\) checked against OSV.*; 3 not sent to OSV/);

  // A mirror: soak sends names there, but OSV is public, so it is not asked and the check fails closed.
  const mirror = proj({ "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/pub": { version: "1.0.0", resolved: "http://127.0.0.1:4873/pub/-/pub-1.0.0.tgz", integrity: "sha512-x" } } }) });
  const asked: string[] = [];
  const local = (async (url: string | URL) => {
    asked.push(String(url));
    return new Response(JSON.stringify({ name: "pub", time: { "1.0.0": iso(400) }, versions: { "1.0.0": { dist: { integrity: "sha512-x" } } } }));
  }) as typeof fetch;
  const m = await soakJson([mirror, "--registry", "http://127.0.0.1:4873"], { fetchImpl: local, env: { HOME: mirror } });
  assert.deepEqual(asked, ["http://127.0.0.1:4873/pub"]);
  assert.equal(m.code, 1);
  assert.deepEqual(
    m.out.findings.filter((f) => f.ruleId === "WS-OS-900").map((f) => [f.key, f.message]),
    [["registry http://127.0.0.1:4873", "1 package version(s) were not checked against OSV: --registry http://127.0.0.1:4873 is not the public npm registry, so their names are not sent to api.osv.dev. Pass --no-osv to run without this check"]],
  );
  assert.equal(await run(["soak", mirror, "--registry", "http://127.0.0.1:4873", "--no-osv"], fakeIO({ fetchImpl: local, env: { HOME: mirror } })), 0, "positive control");
});

test("cli soak: OSV is asked only about names the registry returned a document for, never after any failed lookup", async () => {
  // 404, 403, 410, 5xx (after the retry), a network error, and a 200 without publish times: none of these names is known to be public.
  const d = soakProject({ "@corp/secret": "1.0.0", denied: "1.0.0", gone: "1.0.0", flaky: "1.0.0", offline: "1.0.0", stripped: "1.0.0", pub: "1.0.0" });
  const r = registry(
    { pub: { "1.0.0": 400 } },
    {
      denied: () => new Response("", { status: 403 }),
      gone: () => new Response("", { status: 410 }),
      flaky: () => new Response("", { status: 503 }),
      offline: () => {
        throw new TypeError("fetch failed (getaddrinfo ENOTFOUND registry.npmjs.org)");
      },
      stripped: () => new Response(JSON.stringify({ name: "stripped", versions: { "1.0.0": {} } })),
    },
  );
  const { code, out } = await soakJson([d], { fetchImpl: r.f, env: { HOME: d } });
  assert.equal(code, 1);
  assert.deepEqual(r.osvAsked, ["pub@1.0.0"]);
  assert.deepEqual(
    out.findings.filter((f) => f.ruleId === "WS-SK-002").map((f) => f.message.split(" ")[5]).sort(),
    ["@corp/secret@1.0.0:", "denied@1.0.0:", "flaky@1.0.0:", "gone@1.0.0:", "offline@1.0.0:", "stripped@1.0.0:"],
    "every name kept from OSV still fails closed",
  );
  assert.match(out.notes.join("\n"), /1 package version\(s\) checked against OSV for malicious-package records; 6 not sent to OSV \(the registry did not return a document for them/);

  const only = soakProject({ "@corp/secret": "1.0.0" });
  const none = await soakJson([only], { fetchImpl: r.f, env: { HOME: only } });
  assert.match(none.out.notes.join("\n"), /0 package version\(s\) checked against OSV; 1 not sent to OSV \(the registry did not return a document/, "nothing asked is still said");
});

test("cli soak: an OSV failure fails closed (WS-OS-900), and the evidence does not show those versions as checked", async () => {
  const d = soakProject({ old: "1.0.0" });
  const r = registry({ old: { "1.0.0": 400 } });
  const down = (async (url: string | URL, init?: RequestInit) => (String(url) === OSV ? new Response("", { status: 503 }) : r.f(url, init))) as typeof fetch;
  const { code, out } = await soakJson([d], { fetchImpl: down, env: { HOME: d } });
  assert.equal(code, 1);
  assert.match(out.findings.find((f) => f.ruleId === "WS-OS-900")?.message ?? "", /OSV returned HTTP 503.*old@1\.0\.0/);
  assert.equal(evidenceOf(out, "old")?.osv, undefined);
});

test("cli soak: a full run reads registry signals from the packument it already fetched, only for versions published in the last 14 days", async () => {
  const d = soakProject({ lib: "1.0.1" });
  const recent = registry({ lib: { "1.0.0": { h: 60 * D, user: "alice", provenance: true }, "1.0.1": { h: 10 * D, user: "mallory", scripts: { preinstall: "node setup.js" } } } });
  const { code, out } = await soakJson([d], { fetchImpl: recent.f, env: { HOME: d } });
  assert.equal(code, 1, "10 days old passes the default 7-day soak, but the signals fail it");
  assert.equal(out.extra?.evidence.find((e) => e.name === "lib")?.status, "ok", "the age check passes; only the signals fail");
  assert.deepEqual(recent.calls, ["https://registry.npmjs.org/lib"], "no extra request");
  const rg = out.findings.filter((f) => f.ruleId.startsWith("WS-RG-"));
  assert.deepEqual(rg.map((f) => f.ruleId).sort(), ["WS-RG-001", "WS-RG-002", "WS-RG-003"]);
  for (const f of rg) assert.match(f.message, /registry signal read because it was published in the last 14 days\)$/);
  assert.deepEqual(evidenceOf(out, "lib")?.registry, { comparedWith: "1.0.0", signals: ["WS-RG-001", "WS-RG-002", "WS-RG-003"] });

  const old = registry({ lib: { "1.0.0": { h: 80 * D, user: "alice", provenance: true }, "1.0.1": { h: 20 * D, user: "mallory", scripts: { preinstall: "node setup.js" } } } });
  const quiet = await soakJson([d], { fetchImpl: old.f, env: { HOME: d } });
  assert.equal(quiet.code, 0, "20 days old: outside the window, so history does not report");
  assert.deepEqual(quiet.out.findings.filter((f) => f.ruleId.startsWith("WS-RG-")), []);
  assert.equal(evidenceOf(quiet.out, "lib")?.registry, undefined);
  assert.match(quiet.out.notes.join("\n"), /registry signals read for 0 package version\(s\) published in the last 14 days; older versions not read/);
});

test("cli soak: PR mode reads registry signals for every changed package, whatever its age, against the base lockfile's version", async () => {
  const d = gitRepo({ "package-lock.json": npmLockText({ lib: "1.0.0" }) });
  writeFileSync(join(d, "package-lock.json"), npmLockText({ lib: "1.2.0", fresh: "1.0.0" }));
  // 1.1.0 added the script, so against the newest earlier publish nothing changed; the change jumps from 1.0.0.
  const build = { postinstall: "node build.js" };
  const r = registry({ lib: { "1.0.0": { h: 900 * D }, "1.1.0": { h: 800 * D, scripts: build }, "1.2.0": { h: 700 * D, scripts: build } }, fresh: { "1.0.0": 400 * D } });
  const { code, out } = await soakJson([d, "--base", "HEAD"], { fetchImpl: r.f, env: { HOME: d } });
  assert.equal(code, 1);
  assert.deepEqual(out.findings.filter((f) => f.ruleId.startsWith("WS-RG-")).map((f) => f.message), [
    'lib@1.2.0 adds a postinstall script that 1.0.0 did not have: node build.js (registry signal read because the change adds or updates it)',
  ]);
  assert.deepEqual(evidenceOf(out, "lib")?.registry, { comparedWith: "1.0.0", signals: ["WS-RG-001"] });
  assert.match(out.notes.join("\n"), /registry signals: 1 version\(s\) not compared with an earlier version .*: fresh@1\.0\.0/);
});

test("cli soak: PR mode moving off a version the registry removed compares with the newest earlier version instead", async () => {
  const d = gitRepo({ "package-lock.json": npmLockText({ lib: "1.0.0" }) });
  writeFileSync(join(d, "package-lock.json"), npmLockText({ lib: "1.0.2" }));
  const r = registry({ lib: { "1.0.0": { h: 900 * D, removed: true }, "1.0.1": 800 * D, "1.0.2": { h: 700 * D, scripts: { preinstall: "node setup.js" } } } });
  const { code, out } = await soakJson([d, "--base", "HEAD"], { fetchImpl: r.f, env: { HOME: d } });
  assert.equal(code, 1);
  assert.deepEqual(evidenceOf(out, "lib")?.registry, { comparedWith: "1.0.1", signals: ["WS-RG-001"] });
  assert.doesNotMatch(out.notes.join("\n"), /not compared with an earlier version/);
});

test("cli soak: PR mode does not read registry signals for a version the base already locked, even from a new source", async () => {
  // Same version and integrity, moved from the yarnpkg alias to npmjs: the entry changed, so soak re-checks it, but the version is not new.
  const d = gitRepo({ "package-lock.json": npmLockText({ lib: "1.2.0" }).replace("registry.npmjs.org", "registry.yarnpkg.com") });
  writeFileSync(join(d, "package-lock.json"), npmLockText({ lib: "1.2.0" }));
  const r = registry({ lib: { "1.1.0": { h: 900 * D, user: "alice" }, "1.2.0": { h: 800 * D, user: "bob", scripts: { postinstall: "node x" } } } });
  const { code, out } = await soakJson([d, "--base", "HEAD"], { fetchImpl: r.f, env: { HOME: d } });
  assert.deepEqual(r.calls, ["https://registry.npmjs.org/lib"], "the changed entry is still age-checked");
  assert.deepEqual(out.findings.filter((f) => f.ruleId.startsWith("WS-RG-")), [], "no history reported for a version the project already had");
  assert.equal(code, 0);
  assert.equal(evidenceOf(out, "lib")?.registry, undefined);
  assert.match(out.notes.join("\n"), /registry signals not read for 1 version\(s\) the base lockfile already locked \(the entry changed, not the version\)/);
});

test("soak: a local package is counted once, however many entries the lockfile gives it", async () => {
  // npm 10 writes a workspace twice: its directory, named by its path or by its name field, and the link to it.
  const lock = (dirEntry: Record<string, unknown>) =>
    JSON.stringify({
      name: "root",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: { "": { name: "root", version: "1.0.0", workspaces: ["packages/*"] }, "packages/wsa": { version: "1.0.0", ...dirEntry }, "node_modules/wsa": { resolved: "packages/wsa", link: true }, "libs/tool": { name: "tool", version: "1.0.0" } },
    });
  for (const dirEntry of [{}, { name: "wsa" }]) {
    const parsed = parseLockfileText("package-lock.json", lock(dirEntry))!;
    const res = await checkSoakLockfiles([parsed], { minAgeMs: 72 * H, registry: "https://registry.npmjs.org", now: NOW, osv: true, fetchImpl: (async () => new Response("{}", { status: 404 })) as typeof fetch });
    assert.ok(res.notes.includes("2 local package(s) not age-checked (their code is in this repository): wsa, tool"), `${JSON.stringify(dirEntry)}: ${JSON.stringify(res.notes)}`);
    // OSV's coverage note counts them the same way.
    assert.ok(res.notes.includes("0 package version(s) checked against OSV; 2 not sent to OSV (local code, git, or another registry: soak sends their names nowhere)"), JSON.stringify(res.notes));
  }
  const pkg = (name: string, resolved?: string): LockedPackage => ({ name, version: "", local: true, ...(resolved !== undefined ? { resolved } : {}) });
  assert.deepEqual(localNames([pkg("packages/a"), pkg("a", "packages/a"), pkg("b"), pkg("b", "packages/b"), pkg("c"), pkg("c")]), ["a", "b", "c"]);
  assert.deepEqual(localNames([]), []);
});
