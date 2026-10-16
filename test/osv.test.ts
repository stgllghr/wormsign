import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { checkOsv } from "../src/osv.js";
import type { OsvPackage } from "../src/osv.js";
import { fx } from "./helpers.js";

interface Query {
  package: { name: string; ecosystem: string };
  version: string;
  page_token?: string;
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
const QUERY = "https://api.osv.dev/v1/query";

/**
 * Fake api.osv.dev: every query batch goes to `reply`, and each record query (POST /v1/query) is answered from
 * `answers`, by name@version ({} for a version it does not hold). Records each batch in `calls` and each record query
 * in `asked`.
 */
function osv(reply: (queries: Query[], call: number, init: RequestInit) => Response | Promise<Response>, answers: Record<string, unknown> = {}) {
  const calls: { url: string; init: RequestInit; queries: Query[] }[] = [];
  const asked: { init: RequestInit; query: Query }[] = [];
  const fetchImpl = (async (url: string | URL, init: RequestInit = {}) => {
    if (String(url) === QUERY) {
      const query = JSON.parse(String(init.body)) as Query;
      asked.push({ init, query });
      return json(answers[`${query.package.name}@${query.version}`] ?? {});
    }
    const queries = (JSON.parse(String(init.body)) as { queries: Query[] }).queries;
    calls.push({ url: String(url), init, queries });
    return reply(queries, calls.length, init);
  }) as typeof fetch;
  return { fetchImpl, calls, asked };
}

/** A recorded POST /v1/query answer from test/fixtures/osv/query. */
const recorded = (file: string): unknown => (JSON.parse(readFileSync(fx("osv", "query", file), "utf8")) as { response: unknown }).response;

/**
 * Behaves like the real batch endpoint over a table of name@version -> record ids, including its 1000-query limit,
 * its HTTP 500 for a whole batch holding a 2000-character name and its HTTP 400 for a whole batch holding a name
 * with a lone surrogate (both measured on api.osv.dev 2026-10-02). `poisoned` names also fail their whole batch with 400.
 */
function database(records: Record<string, string[]>, poisoned: (name: string) => boolean = () => false) {
  return osv((queries) =>
    queries.length > 1000
      ? json({ code: 3, message: "too many queries" }, 400)
      : queries.some((q) => q.package.name.length >= 2000)
        ? json({ code: 13, message: "error in query" }, 500)
        : queries.some((q) => /\p{Cs}/u.test(q.package.name) || poisoned(q.package.name))
          ? json({ code: 400, message: "Invalid unicode code point." }, 400)
          : json({ results: queries.map((q) => (records[`${q.package.name}@${q.version}`] ? { vulns: records[`${q.package.name}@${q.version}`]!.map((id) => ({ id, modified: "2025-09-17T06:23:36Z" })) } : {})) }),
  );
}

const pkgs = (n: number, prefix = "p"): OsvPackage[] => Array.from({ length: n }, (_, i) => ({ name: `${prefix}${i}`, version: "1.0.0", file: "package-lock.json" }));
const rules = (fs: { ruleId: string }[]) => fs.map((f) => f.ruleId);

test("osv: replays a real api.osv.dev response; MAL- records are findings, ordinary GHSA records are not", async () => {
  const real = JSON.parse(readFileSync(fx("osv", "querybatch-2026-10-02.json"), "utf8")) as { request: { queries: Query[] }; response: unknown };
  // lodash@4.17.20's records, as POST /v1/query answered on 2026-10-08: its five GHSA records, none listing CWE-506.
  const { fetchImpl, calls, asked } = osv(() => json(real.response), { "lodash@4.17.20": recorded("npm-lodash-4.17.20.json") });
  const input = real.request.queries.map((q) => ({ name: q.package.name, version: q.version, file: "package-lock.json" }));
  const findings = await checkOsv(input, { fetchImpl });
  // The request is exactly the one the real API answered.
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.url, "https://api.osv.dev/v1/querybatch");
  assert.equal(calls[0]!.init.method, "POST");
  assert.deepEqual(calls[0]!.queries, real.request.queries);
  // lodash@4.17.20's records are read once, to see its GHSA records' CWE ids; MAL-2025-47141 needs no second request.
  assert.deepEqual(asked.map((a) => [a.init.method, a.query]), [["POST", { package: { name: "lodash", ecosystem: "npm" }, version: "4.17.20" }]]);
  // lodash@4.17.20's five GHSA records are vulnerabilities without CWE-506, so not findings.
  assert.equal(findings.length, 1, JSON.stringify(findings));
  const [f] = findings;
  assert.equal(f!.ruleId, "WS-OS-001");
  assert.equal(f!.severity, "critical");
  assert.equal(f!.file, "package-lock.json");
  assert.equal(f!.key, "@ctrl/tinycolor@4.1.1 MAL-2025-47141");
  assert.equal(f!.source, "https://osv.dev/vulnerability/MAL-2025-47141");
  assert.match(f!.message, /@ctrl\/tinycolor@4\.1\.1 .*MAL-2025-47141/);
});

test("osv: no packages, no requests and no findings", async () => {
  const { fetchImpl, calls } = database({});
  assert.deepEqual(await checkOsv([], { fetchImpl }), []);
  assert.equal(calls.length, 0);
});

test("osv: splits into batches of at most 1000 queries (the API rejects 1001)", async () => {
  const { fetchImpl, calls } = database({ "p2000@1.0.0": ["MAL-2"] });
  const findings = await checkOsv(pkgs(2001), { fetchImpl });
  assert.deepEqual(calls.map((c) => c.queries.length).sort((a, b) => a - b), [1, 1000, 1000]);
  assert.deepEqual(rules(findings), ["WS-OS-001"]);
});

test("osv: follows next_page_token for only the queries that returned one", async () => {
  const { fetchImpl, calls } = osv((queries, call) =>
    call === 1
      ? json({ results: [{ vulns: [{ id: "PYSEC-2099-1", modified: "x" }] }, { vulns: [{ id: "PYSEC-2099-2", modified: "x" }], next_page_token: "tok" }] })
      : json({ results: queries.map(() => ({ vulns: [{ id: "MAL-9", modified: "x" }] })) }),
  );
  const findings = await checkOsv([{ name: "a", version: "1.0.0" }, { name: "b", version: "2.0.0" }], { fetchImpl });
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[1]!.queries, [{ package: { name: "b", ecosystem: "npm" }, version: "2.0.0", page_token: "tok" }]);
  assert.deepEqual(findings.map((f) => f.key), ["b@2.0.0 MAL-9"]);
});

test("osv: a query that never stops paginating is not checked (bounded, fail closed)", async () => {
  const { fetchImpl, calls } = osv((queries) => json({ results: queries.map(() => ({ next_page_token: "again" })) }));
  const findings = await checkOsv([{ name: "a", version: "1.0.0" }], { fetchImpl });
  assert.equal(calls.length, 11, "the first request and ten follow-ups");
  assert.deepEqual(rules(findings), ["WS-OS-900"]);
  assert.match(findings[0]!.message, /1 package version\(s\) could not be checked .*more results after 10 follow-up requests.*: a@1\.0\.0/);
});

test("osv: retries once on 5xx, 429 and network errors, never on other 4xx", async () => {
  const ok = (queries: Query[]) => json({ results: queries.map(() => ({ vulns: [{ id: "MAL-1", modified: "x" }] })) });
  const input = [{ name: "a", version: "1.0.0" }];
  for (const [first, retried] of [[503, true], [429, true], [400, false], [404, false]] as const) {
    const { fetchImpl, calls } = osv((q, call) => (call === 1 ? json({}, first) : ok(q)));
    const findings = await checkOsv(input, { fetchImpl });
    assert.equal(calls.length, retried ? 2 : 1, `HTTP ${first}`);
    assert.deepEqual(rules(findings), [retried ? "WS-OS-001" : "WS-OS-900"], `HTTP ${first}`);
    if (!retried) assert.match(findings[0]!.message, new RegExp(`HTTP ${first}`));
  }
  const thrown = osv((q, call) => {
    if (call === 1) throw new TypeError("fetch failed");
    return ok(q);
  });
  assert.deepEqual(rules(await checkOsv(input, { fetchImpl: thrown.fetchImpl })), ["WS-OS-001"]);
  // Only one retry: a second failure is reported, not retried forever.
  const down = osv(() => json({}, 502));
  const findings = await checkOsv(input, { fetchImpl: down.fetchImpl });
  assert.equal(down.calls.length, 2);
  assert.deepEqual(rules(findings), ["WS-OS-900"]);
  assert.match(findings[0]!.message, /HTTP 502/);
});

test("osv: a request that hangs is aborted by the timeout and reported", async () => {
  const { fetchImpl, calls } = osv(
    (_q, _c, init) =>
      new Promise((_resolve, reject) => {
        // AbortSignal.timeout's timer does not keep Node alive (a real socket would), so hold the loop open until the abort.
        const hold = setTimeout(() => reject(new Error("the hang was never cut short")), 2_000);
        init.signal?.addEventListener("abort", () => {
          clearTimeout(hold);
          reject(init.signal?.reason);
        });
      }),
  );
  const findings = await checkOsv([{ name: "a", version: "1.0.0" }], { fetchImpl, timeoutMs: 20 });
  assert.equal(calls.length, 2);
  assert.deepEqual(rules(findings), ["WS-OS-900"]);
  assert.match(findings[0]!.message, /request to OSV failed: .*aborted due to timeout/);
});

test("osv: a response not in the documented shape fails closed, never reads as clean", async () => {
  const input = [{ name: "a", version: "1.0.0" }, { name: "b", version: "1.0.0" }];
  // Positive control: two empty results is a clean answer.
  assert.deepEqual(await checkOsv(input, { fetchImpl: osv(() => json({ results: [{}, {}] })).fetchImpl }), []);
  for (const body of [{}, { results: [{}] }, { results: [{}, {}, {}] }, { results: [{}, { vulns: "MAL-1" }] }, { results: [{}, { vulns: [{ modified: "x" }] }] }, { results: [{}, { next_page_token: 7 }] }, { results: [{}, null] }, null]) {
    const findings = await checkOsv(input, { fetchImpl: osv(() => json(body)).fetchImpl });
    assert.deepEqual(rules(findings), ["WS-OS-900"], JSON.stringify(body));
    assert.match(findings[0]!.message, /^2 package version\(s\)/, JSON.stringify(body));
    // Rejected by the shape check, not by an exception thrown while reading the body.
    assert.doesNotMatch(findings[0]!.message, /request to OSV failed/, JSON.stringify(body));
  }
  const html = osv(() => new Response("<html>proxy</html>", { status: 200 }));
  assert.deepEqual(rules(await checkOsv(input, { fetchImpl: html.fetchImpl })), ["WS-OS-900"]);
});

test("osv: entries that are not a registry name and version are not sent, and fail closed", async () => {
  // An empty version would match every version of the package; an empty name fails the whole batch.
  const { fetchImpl, calls } = database({ "ok@1.0.0": ["MAL-5"] });
  const findings = await checkOsv(
    [
      { name: "ok", version: "1.0.0" },
      { name: "pre", version: "2.0.0-rc.1+build.5" },
      { name: "nover", version: "" },
      { name: "gitdep", version: "github:a/b#c0ffee" },
      { name: "", version: "1.0.0" },
    ],
    { fetchImpl },
  );
  assert.deepEqual(calls[0]!.queries.map((q) => q.package.name), ["ok", "pre"]);
  assert.deepEqual(rules(findings), ["WS-OS-001", "WS-OS-900"]);
  const nc = findings[1]!;
  assert.equal(nc.severity, "high");
  assert.match(nc.message, /^3 package version\(s\) could not be checked .*not a registry name and version/);
  assert.equal(nc.key, "@1.0.0 gitdep@github:a/b#c0ffee nover@");
});

test("osv: a name longer than npm allows is not sent, so it cannot fail the batch a malicious version is in", async () => {
  const { fetchImpl, calls } = database({ "@ctrl/tinycolor@4.1.1": ["MAL-2025-47141"] });
  const long = "a".repeat(2000);
  const findings = await checkOsv(
    [
      { name: "@ctrl/tinycolor", version: "4.1.1" },
      { name: "b".repeat(214), version: "1.0.0" },
      { name: long, version: "1.0.0" },
    ],
    { fetchImpl },
  );
  // 214 characters is npm's limit and is still asked about.
  assert.deepEqual(calls.map((c) => c.queries.map((q) => q.package.name.length)), [[15, 214]]);
  assert.deepEqual(rules(findings), ["WS-OS-001", "WS-OS-900"]);
  assert.equal(findings[0]!.key, "@ctrl/tinycolor@4.1.1 MAL-2025-47141");
  assert.match(findings[1]!.message, /^1 package version\(s\) could not be checked .*not a registry name and version/);
  assert.equal(findings[1]!.key, `${long}@1.0.0`);
});

test("osv: a name with a lone surrogate is not sent, so it cannot fail the batch a malicious version is in", async () => {
  // A package-lock.json can hold "evil\udc00" as a JSON escape; api.osv.dev answers the whole batch with HTTP 400.
  const { fetchImpl, calls } = database({ "@ctrl/tinycolor@4.1.1": ["MAL-2025-47141"] });
  const evil = JSON.parse('"evil\\udc00"') as string;
  const findings = await checkOsv([{ name: "@ctrl/tinycolor", version: "4.1.1" }, { name: evil, version: "1.0.0" }], { fetchImpl });
  assert.deepEqual(calls.map((c) => c.queries.map((q) => q.package.name)), [["@ctrl/tinycolor"]]);
  assert.deepEqual(rules(findings), ["WS-OS-001", "WS-OS-900"]);
  assert.match(findings[1]!.message, /^1 package version\(s\) could not be checked .*not a registry name and version/);
  assert.equal(findings[1]!.key, `${evil}@1.0.0`);
});

test("osv: only names npm accepts for a registry package are sent", async () => {
  // validate-npm-package-name 7.0.2, validForOldPackages: capitals and ~'!()* are only warnings.
  const sent = ["a", "Upper-Case", "@scope/pkg", "@s/_a", "@s/-a", "a.b_c-d", "x~'!()*", "JSONStream"];
  const notSent = ["a b", " a", "a ", ".a", "_a", "-a", "@s/.a", "@/a", "@a", "a/b", "@s/a/b", "@@s/a", "\u00e9", "a\u0000", "\ud83e\udd86", "a%20"];
  const { fetchImpl, calls } = database({});
  const findings = await checkOsv([...sent, ...notSent].map((name) => ({ name, version: "1.0.0" })), { fetchImpl });
  assert.deepEqual(calls.map((c) => c.queries.map((q) => q.package.name)), [sent]);
  assert.equal(findings[0]!.key, notSent.map((n) => `${n}@1.0.0`).sort().join(" "));
});

test("osv: a version longer than node-semver allows (256) is not sent", async () => {
  const { fetchImpl, calls } = database({});
  const at = (n: number) => `1.0.0-${"a".repeat(n - 6)}`;
  const findings = await checkOsv([{ name: "ok", version: at(256) }, { name: "long", version: at(257) }, { name: "huge", version: at(5_000_000) }], { fetchImpl });
  assert.deepEqual(calls.map((c) => c.queries.map((q) => q.version.length)), [[256]]);
  assert.deepEqual(rules(findings), ["WS-OS-900"]);
  assert.match(findings[0]!.message, /^2 package version\(s\) could not be checked .*not a registry name and version/);
});

test("osv: a batch OSV rejects (HTTP 400) is halved until the rejected queries are isolated", async () => {
  // OSV may reject inputs the guard lets through; one of them must not hide a malicious version in its batch.
  const { fetchImpl, calls } = database({ "@ctrl/tinycolor@4.1.1": ["MAL-2025-47141"], "p998@1.0.0": ["MAL-7"] }, (n) => n === "p3" || n === "p600");
  const input = [{ name: "@ctrl/tinycolor", version: "4.1.1" }, ...pkgs(999)];
  const findings = await checkOsv(input, { fetchImpl });
  assert.deepEqual(rules(findings), ["WS-OS-001", "WS-OS-001", "WS-OS-900"]);
  assert.deepEqual(findings.slice(0, 2).map((f) => f.key), ["@ctrl/tinycolor@4.1.1 MAL-2025-47141", "p998@1.0.0 MAL-7"]);
  assert.equal(findings[2]!.key, "p3@1.0.0 p600@1.0.0");
  assert.match(findings[2]!.message, /^2 package version\(s\) could not be checked .*OSV returned HTTP 400/);
  // Bisecting two bad queries out of 1000 takes two rejected paths of about ten halvings each.
  assert.ok(calls.length <= 1 + 2 * 20, `${calls.length} requests`);
  // Every other package got exactly one real answer.
  const asked = calls.flatMap((c) => (c.queries.some((q) => q.package.name === "p3" || q.package.name === "p600") ? [] : c.queries.map((q) => q.package.name)));
  assert.equal(asked.length, 998);
  assert.equal(new Set(asked).size, 998);
});

test("osv: halving a rejected batch is bounded, and what is left fails closed", async () => {
  const { fetchImpl, calls } = database({ "p0@1.0.0": ["MAL-1"] }, () => true);
  const findings = await checkOsv(pkgs(1000), { fetchImpl });
  assert.equal(calls.length, 1 + 2 * 32, "the first request and two per halving, 32 halvings at most");
  assert.deepEqual(rules(findings), ["WS-OS-900"]);
  assert.match(findings[0]!.message, /^1000 package version\(s\) could not be checked .*OSV returned HTTP 400/);
  // A single rejected query is reported, not split or retried.
  const one = database({}, () => true);
  assert.deepEqual(rules(await checkOsv(pkgs(1), { fetchImpl: one.fetchImpl })), ["WS-OS-900"]);
  assert.equal(one.calls.length, 1);
});

test("osv: the not-checked finding is keyed on exactly what went unchecked", async () => {
  // A baseline entry for a trusted git dependency must not also hide an outage.
  const { fetchImpl } = database({});
  const git = { name: "gitdep", version: "github:a/b#c0ffee" };
  const [alone] = await checkOsv([git, { name: "ok", version: "1.0.0" }], { fetchImpl });
  const [outage] = await checkOsv([git, { name: "ok", version: "1.0.0" }], { fetchImpl: osv(() => json({}, 503)).fetchImpl });
  assert.equal(alone!.ruleId, "WS-OS-900");
  assert.equal(outage!.ruleId, "WS-OS-900");
  assert.notEqual(alone!.fingerprint, outage!.fingerprint);
});

test("osv: a version locked in several files is queried once and reported per file", async () => {
  const { fetchImpl, calls } = database({ "x@1.0.0": ["MAL-3"] });
  const findings = await checkOsv(
    [
      { name: "x", version: "1.0.0", file: "a/package-lock.json" },
      { name: "x", version: "1.0.0", file: "b/pnpm-lock.yaml" },
      { name: "x", version: "1.0.0", file: "a/package-lock.json" },
    ],
    { fetchImpl },
  );
  assert.equal(calls[0]!.queries.length, 1);
  assert.deepEqual(findings.map((f) => f.file), ["a/package-lock.json", "b/pnpm-lock.yaml"]);
});

test("osv: no more than `concurrency` batches are in flight", async () => {
  let inFlight = 0;
  let peak = 0;
  const { fetchImpl, calls } = osv(async (queries) => {
    peak = Math.max(peak, ++inFlight);
    await new Promise((r) => setTimeout(r, 5));
    inFlight--;
    return json({ results: queries.map(() => ({})) });
  });
  assert.deepEqual(await checkOsv(pkgs(4500), { fetchImpl, concurrency: 2 }), []);
  assert.equal(calls.length, 5);
  assert.equal(peak, 2);
});

test("osv: a concurrency that starts no worker fails closed, never reads as clean", async () => {
  for (const concurrency of [0, -1, NaN, 0.5]) {
    const { fetchImpl } = database({ "p0@1.0.0": ["MAL-1"] });
    const findings = await checkOsv(pkgs(2), { fetchImpl, concurrency });
    assert.deepEqual(rules(findings), ["WS-OS-900"], `concurrency ${concurrency}`);
    assert.equal(findings[0]!.key, "p0@1.0.0 p1@1.0.0");
  }
});
