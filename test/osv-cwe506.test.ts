/**
 * OSV layer 3 reports a GitHub advisory (GHSA) whose database_specific.cwe_ids include CWE-506 exactly as it reports a
 * MAL- record, in npm and PyPI alike. A query batch answer has only ids, so a version with a GHSA id the run has not
 * classified gets its full records from one record query (POST /v1/query): versions in name and version order, at most
 * MAX_RECORD_QUERIES per run, and a version whose GHSA records were not all read is unchecked (WS-OS-900), never
 * clean. The real answers replayed here were recorded from api.osv.dev on 2026-10-08 (test/fixtures/osv, each file
 * says when and from where).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { MAX_RECORD_QUERIES, checkOsvDetailed, newOsvSession } from "../src/osv.js";
import type { OsvPackage } from "../src/osv.js";
import { fx } from "./helpers.js";

interface Query {
  package: { name: string; ecosystem: string };
  version: string;
  page_token?: string;
}

const QUERYBATCH = "https://api.osv.dev/v1/querybatch";
const QUERY = "https://api.osv.dev/v1/query";
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

/** A recorded record query answer (the body POST /v1/query returned) from test/fixtures/osv/query. */
const recorded = (file: string): unknown => (JSON.parse(readFileSync(fx("osv", "query", file), "utf8")) as { response: unknown }).response;
/** A synthetic GHSA record with these CWE ids. */
const record = (id: string, cwes: string[]): unknown => ({ id, summary: "test record", database_specific: { cwe_ids: cwes, github_reviewed: true } });

type Answer = Response | Promise<Response> | ((init: RequestInit | undefined, query: Query) => Response | Promise<Response>);

/**
 * Fake api.osv.dev. Query batches are answered from `ids` (name@version -> record ids; an absent version has none). A
 * record query for name@version is answered from `answer` when it holds the version (a Response, or a function for a
 * status, a throw or pages), and otherwise with the version's records in full: a GHSA id's record from `records`, or one
 * with only CWE-79 when `records` does not hold it; any other id a record without CWE ids. Every request is recorded:
 * record queries in `asked` as "name@version" (" <page_token>" added for a later page), their bodies in `bodies`, and
 * `flight` tracks how many are in flight. `sleep`, passed as the option, records each wait before a retry in `waits`
 * and returns at once.
 */
function fake(ids: Record<string, string[]>, records: Record<string, unknown> = {}, answer: Record<string, Answer> = {}) {
  const batches: Query[][] = [];
  const asked: string[] = [];
  const bodies: Query[] = [];
  const flight = { now: 0, peak: 0 };
  const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    assert.equal(init?.method, "POST");
    if (u === QUERYBATCH) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Query[] };
      batches.push(queries);
      return json({ results: queries.map((q) => ((ids[`${q.package.name}@${q.version}`] ?? []).length > 0 ? { vulns: (ids[`${q.package.name}@${q.version}`] ?? []).map((id) => ({ id, modified: "2026-10-08T00:00:00Z" })) } : {})) });
    }
    assert.equal(u, QUERY);
    assert.ok(init?.signal, "a record query has a timeout");
    const q = JSON.parse(String(init?.body)) as Query;
    const key = `${q.package.name}@${q.version}`;
    asked.push(q.page_token === undefined ? key : `${key} ${q.page_token}`);
    bodies.push(q);
    flight.peak = Math.max(flight.peak, ++flight.now);
    try {
      await new Promise((r) => setTimeout(r, 1));
      const a = answer[key];
      if (a !== undefined) return await (typeof a === "function" ? a(init, q) : a);
      const vulns = (ids[key] ?? []).map((id) => (id.startsWith("GHSA-") ? (records[id] ?? record(id, ["CWE-79"])) : { id, summary: "test record" }));
      return json(vulns.length > 0 ? { vulns } : {});
    } finally {
      flight.now--;
    }
  }) as typeof fetch;
  const waits: number[] = [];
  const sleep = async (ms: number): Promise<void> => {
    waits.push(ms);
  };
  return { fetchImpl, sleep, waits, batches, asked, bodies, flight };
}

/** A recorded query batch: its packages (the request) and the record ids OSV answered for each. */
function recordedBatch(file: string): { pkgs: OsvPackage[]; ids: Record<string, string[]> } {
  const doc = JSON.parse(readFileSync(fx("osv", file), "utf8")) as { request: { queries: Query[] }; response: { results: { vulns?: { id: string }[]; next_page_token?: string }[] } };
  const pkgs = doc.request.queries.map((q) => ({ name: q.package.name, version: q.version, file: "lockfile" }));
  const ids: Record<string, string[]> = {};
  doc.response.results.forEach((r, i) => {
    assert.equal(r.next_page_token, undefined, "one page each");
    ids[`${pkgs[i]!.name}@${pkgs[i]!.version}`] = (r.vulns ?? []).map((v) => v.id);
  });
  return { pkgs, ids };
}

const summary = (fs: { ruleId: string; severity: string; key: string }[]) => fs.map((f) => `${f.ruleId} ${f.severity} ${f.key}`);
const note = (n: number, ecosystem = "") => `OSV records requested for ${n} version(s) (GHSA classification${ecosystem ? `, ${ecosystem}` : ""})`;

test("osv cwe-506: real npm answers: ua-parser-js@0.7.29's only record, a CWE-506 GHSA, is WS-OS-001; lodash's five ordinary GHSA records are not", async () => {
  const { pkgs, ids } = recordedBatch("querybatch-npm-2026-10-08.json");
  assert.deepEqual(ids["ua-parser-js@0.7.29"], ["GHSA-pjwm-rvh2-c87w"], "no MAL- record for it on OSV");
  assert.deepEqual(ids["ua-parser-js@0.7.28"], [], "no record at all");
  const db = fake(ids, {}, { "ua-parser-js@0.7.29": json(recorded("npm-ua-parser-js-0.7.29.json")), "lodash@4.17.20": json(recorded("npm-lodash-4.17.20.json")) });
  const res = await checkOsvDetailed(pkgs, { fetchImpl: db.fetchImpl });
  assert.deepEqual(db.asked, ["lodash@4.17.20", "ua-parser-js@0.7.29"], "each version with a GHSA id once, in name order; a version without one is not asked");
  assert.deepEqual(db.bodies[1], { package: { name: "ua-parser-js", ecosystem: "npm" }, version: "0.7.29" }, "the name, ecosystem and version, nothing else");
  assert.deepEqual(summary(res.findings), ["WS-OS-001 critical ua-parser-js@0.7.29 GHSA-pjwm-rvh2-c87w"]);
  const [f] = res.findings;
  assert.equal(f?.file, "lockfile");
  assert.equal(f?.source, "https://osv.dev/vulnerability/GHSA-pjwm-rvh2-c87w");
  assert.equal(f?.message, "ua-parser-js@0.7.29 is a malicious package version according to OSV record GHSA-pjwm-rvh2-c87w (a GitHub advisory with CWE-506, embedded malicious code)");
  assert.deepEqual([...res.records], [["ua-parser-js@0.7.29", ["GHSA-pjwm-rvh2-c87w"]]]);
  assert.deepEqual(res.unchecked, []);
  assert.deepEqual(res.notes, [note(2)]);
});

test("osv cwe-506: real PyPI answers: num2words@0.5.15 has a CWE-506 GHSA and a MAL- record, two findings; requests' ordinary GHSAs and PYSEC records are not", async () => {
  const { pkgs, ids } = recordedBatch("querybatch-pypi-2026-10-08.json");
  const db = fake(ids, {}, { "num2words@0.5.15": json(recorded("pypi-num2words-0.5.15.json")), "requests@2.31.0": json(recorded("pypi-requests-2.31.0.json")) });
  const res = await checkOsvDetailed(pkgs, { ecosystem: "PyPI", fetchImpl: db.fetchImpl });
  assert.ok(ids["requests@2.31.0"]?.some((id) => id.startsWith("PYSEC-")), "the answer has PYSEC records");
  assert.deepEqual(db.asked, ["num2words@0.5.15", "requests@2.31.0"]);
  assert.deepEqual(db.bodies, [{ package: { name: "num2words", ecosystem: "PyPI" }, version: "0.5.15" }, { package: { name: "requests", ecosystem: "PyPI" }, version: "2.31.0" }]);
  assert.deepEqual(summary(res.findings), ["WS-OS-001 critical pypi:num2words@0.5.15 GHSA-jxr6-qrxx-2ph2", "WS-OS-001 critical pypi:num2words@0.5.15 MAL-2025-6794"]);
  // A MAL- finding's key and message are as they always were.
  assert.equal(res.findings[1]?.message, "num2words@0.5.15 is a malicious package version according to OSV record MAL-2025-6794");
  assert.deepEqual([...res.records], [["num2words@0.5.15", ["GHSA-jxr6-qrxx-2ph2", "MAL-2025-6794"]]]);
  assert.deepEqual(res.unchecked, []);
  assert.deepEqual(res.notes, [note(2, "PyPI")], "a PyPI call's note names its ecosystem");
});

test("osv cwe-506: a record is malicious by its CWE ids alone; OSV matched the version, so its ranges are not evaluated again", async () => {
  // The record's affected ranges do not name 9.9.9: the server's match is the answer, as for every record.
  const elsewhere = { id: "GHSA-aaaa-aaaa-aaaa", affected: [{ package: { name: "x", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "1.0.1" }] }] }], database_specific: { cwe_ids: ["CWE-912", "CWE-506"] } };
  const db = fake({ "x@9.9.9": ["GHSA-aaaa-aaaa-aaaa"], "y@1.0.0": ["GHSA-bbbb-bbbb-bbbb"], "z@1.0.0": ["GHSA-cccc-cccc-cccc"] }, { "GHSA-aaaa-aaaa-aaaa": elsewhere, "GHSA-bbbb-bbbb-bbbb": record("GHSA-bbbb-bbbb-bbbb", []), "GHSA-cccc-cccc-cccc": record("GHSA-cccc-cccc-cccc", ["CWE-5060", "cwe-506"]) });
  const res = await checkOsvDetailed([{ name: "x", version: "9.9.9" }, { name: "y", version: "1.0.0" }, { name: "z", version: "1.0.0" }], { fetchImpl: db.fetchImpl });
  assert.deepEqual(summary(res.findings), ["WS-OS-001 critical x@9.9.9 GHSA-aaaa-aaaa-aaaa"], "an empty list or a near miss is not CWE-506");
  assert.deepEqual(res.unchecked, []);
});

test("osv cwe-506: a version whose records cannot be read is unchecked (WS-OS-900), never clean", async () => {
  const id = "GHSA-qqqq-qqqq-qqqq";
  const good = { vulns: [record(id, ["CWE-79"]), { id: "PYSEC-2099-1" }] };
  const pkgs = [{ name: "a", version: "1.0.0", file: "package-lock.json" }, { name: "b", version: "1.0.0", file: "package-lock.json" }];
  const ids = { "a@1.0.0": [id, "PYSEC-2099-1"], "b@1.0.0": ["PYSEC-2099-2"] };
  // Positive control: the same records, read, hold an ordinary vulnerability and the version is clean.
  const ok = fake(ids, {}, { "a@1.0.0": () => json(good) });
  const clean = await checkOsvDetailed(pkgs, { fetchImpl: ok.fetchImpl });
  assert.deepEqual([clean.findings, clean.unchecked, clean.notes, ok.asked], [[], [], [note(1)], ["a@1.0.0"]], "b@1.0.0 has no GHSA id, so it is not asked");

  const status = (n: number) => () => json({}, n);
  const thrown = () => {
    throw new TypeError("fetch failed");
  };
  const records = (...vulns: unknown[]) => () => json({ vulns });
  const cases: [label: string, answer: Answer, requests: number, reason: RegExp][] = [
    ["HTTP 503 twice", status(503), 2, /OSV returned HTTP 503 for a version's records/],
    ["HTTP 429 twice", status(429), 2, /OSV returned HTTP 429 for a version's records/],
    ["a network error twice", thrown, 2, /request to OSV for a version's records failed: fetch failed/],
    ["HTTP 404 (not retried)", json({ code: 5, message: "Package not found" }, 404), 1, /OSV returned HTTP 404 for a version's records/],
    ["HTTP 400 (not retried)", status(400), 1, /OSV returned HTTP 400 for a version's records/],
    ["a body that is not JSON (retried)", () => new Response("<html>proxy</html>"), 2, /request to OSV for a version's records failed: /],
    ["null", () => json(null), 1, /OSV's records for a version are not in the documented shape/],
    ["an array", () => json([record(id, [])]), 1, /OSV's records for a version are not in the documented shape/],
    ["vulns not an array", () => json({ vulns: { [id]: record(id, []) } }), 1, /OSV's records for a version are not in the documented shape/],
    ["a page token that is not a string", () => json({ vulns: [record(id, [])], next_page_token: 2 }), 1, /OSV's records for a version are not in the documented shape/],
    ["a record that is null", records(record(id, []), null), 1, /OSV returned a record without an id/],
    ["a record without an id", records(record(id, []), { database_specific: { cwe_ids: [] } }), 1, /OSV returned a record without an id/],
    ["no database_specific", records({ id }), 1, /OSV returned a GHSA record without a list of CWE ids/],
    ["database_specific null", records({ id, database_specific: null }), 1, /without a list of CWE ids/],
    ["no cwe_ids", records({ id, database_specific: { severity: "HIGH" } }), 1, /without a list of CWE ids/],
    ["cwe_ids a string", records({ id, database_specific: { cwe_ids: "CWE-506" } }), 1, /without a list of CWE ids/],
    ["cwe_ids holding a number", records({ id, database_specific: { cwe_ids: ["CWE-79", 506] } }), 1, /without a list of CWE ids/],
    ["an empty answer", () => json({}), 1, /OSV's records for a version left out a GHSA record its query batch answer had/],
    ["another GHSA record only", records(record("GHSA-rrrr-rrrr-rrrr", ["CWE-79"])), 1, /left out a GHSA record its query batch answer had/],
  ];
  for (const [label, answer, requests, reason] of cases) {
    const db = fake(ids, {}, { "a@1.0.0": answer });
    const res = await checkOsvDetailed(pkgs, { fetchImpl: db.fetchImpl, sleep: db.sleep });
    assert.equal(db.asked.length, requests, label);
    assert.deepEqual(summary(res.findings), ["WS-OS-900 high a@1.0.0"], label);
    assert.match(res.findings[0]?.message ?? "", /^1 package version\(s\) could not be checked against OSV for malicious-package records \(/, label);
    assert.match(res.findings[0]?.message ?? "", reason, label);
    assert.deepEqual(res.unchecked, ["a@1.0.0"], label);
    assert.deepEqual(res.notes, [note(1)], `${label}: a retry is part of its request`);
  }

  // One retry is enough: a 503 then the records is a clean answer.
  let first = true;
  const retried = fake(ids, {}, { "a@1.0.0": () => (first ? ((first = false), json({}, 503)) : json(good)) });
  const after = await checkOsvDetailed(pkgs, { fetchImpl: retried.fetchImpl, sleep: retried.sleep });
  assert.equal(retried.asked.length, 2);
  assert.deepEqual([after.findings, after.unchecked], [[], []]);

  // A version with a MAL- record keeps its finding, and is unchecked too when its records could not be read.
  const mal = fake({ "a@1.0.0": [id, "MAL-2099-1"] }, {}, { "a@1.0.0": status(503) });
  const both = await checkOsvDetailed(pkgs, { fetchImpl: mal.fetchImpl, sleep: mal.sleep });
  assert.deepEqual(summary(both.findings), ["WS-OS-001 critical a@1.0.0 MAL-2099-1", "WS-OS-900 high a@1.0.0"]);
  assert.deepEqual([...both.records], [["a@1.0.0", ["MAL-2099-1"]]]);
});

test("osv cwe-506: a version's failed or incomplete answer leaves it unchecked even when another version's answer classifies its GHSA ids", async () => {
  // a@1.0.0 reads G (it comes first); b@1.0.0 reads H, and its answer holds G too, so G is classified either way.
  const G = "GHSA-gggg-gggg-gggg";
  const ids = { "a@1.0.0": [G], "b@1.0.0": [G, "GHSA-hhhh-hhhh-hhhh"] };
  const pkgs = [{ name: "b", version: "1.0.0" }, { name: "a", version: "1.0.0" }];
  const fine = fake(ids);
  const ok = await checkOsvDetailed(pkgs, { fetchImpl: fine.fetchImpl });
  assert.deepEqual([fine.asked, ok.unchecked, ok.findings], [["a@1.0.0", "b@1.0.0"], [], []], "positive control: both asked, both clean");
  const answers: [label: string, answer: Answer, reason: RegExp][] = [
    ["HTTP 404", json({ code: 5, message: "Package not found" }, 404), /OSV returned HTTP 404 for a version's records/],
    ["an answer without G", () => json({}), /left out a GHSA record its query batch answer had/],
  ];
  for (const [label, answer, reason] of answers) {
    // a@1.0.0's answer is held back until b@1.0.0's answer has put G in the run's session, so a@1.0.0 must be judged
    // by its own answer: when it arrives, G is already classified. (Polled on the session, not on b@1.0.0's response,
    // because the response resolving is not its answer being read.)
    const session = newOsvSession();
    let gClassifiedFirst = false;
    const db = fake(ids, {}, {
      "a@1.0.0": async (init, q) => {
        for (let i = 0; i < 2_000 && !session.cwe506.has(G); i++) await new Promise((r) => setTimeout(r, 1));
        gClassifiedFirst = session.cwe506.has(G);
        return typeof answer === "function" ? answer(init, q) : answer;
      },
    });
    const res = await checkOsvDetailed(pkgs, { fetchImpl: db.fetchImpl, session });
    assert.ok(gClassifiedFirst, `${label}: b@1.0.0's answer classified G before a@1.0.0's answer arrived`);
    assert.deepEqual(db.asked, ["a@1.0.0", "b@1.0.0"], label);
    assert.deepEqual(res.unchecked, ["a@1.0.0"], `${label}: never clean, though b@1.0.0's answer classified G`);
    assert.match(res.findings[0]?.message ?? "", reason, label);
  }
});

test("osv cwe-506: a version whose GHSA ids an earlier version's answer holds is not asked, and is unchecked when that answer fails", async () => {
  // ua-parser-js 0.7.29 and 0.8.0 share their one record: only 0.7.29, first in version order, is asked.
  const ids = { "ua-parser-js@0.7.29": ["GHSA-pjwm-rvh2-c87w"], "ua-parser-js@0.8.0": ["GHSA-pjwm-rvh2-c87w"], "z@1.0.0": ["GHSA-pjwm-rvh2-c87w", "MAL-2099-1"] };
  const pkgs = [{ name: "z", version: "1.0.0" }, { name: "ua-parser-js", version: "0.8.0" }, { name: "ua-parser-js", version: "0.7.29" }];
  const db = fake(ids, { "GHSA-pjwm-rvh2-c87w": record("GHSA-pjwm-rvh2-c87w", ["CWE-506", "CWE-912"]) });
  const res = await checkOsvDetailed(pkgs, { fetchImpl: db.fetchImpl });
  assert.deepEqual(db.asked, ["ua-parser-js@0.7.29"]);
  assert.deepEqual(summary(res.findings), ["WS-OS-001 critical z@1.0.0 GHSA-pjwm-rvh2-c87w", "WS-OS-001 critical z@1.0.0 MAL-2099-1", "WS-OS-001 critical ua-parser-js@0.8.0 GHSA-pjwm-rvh2-c87w", "WS-OS-001 critical ua-parser-js@0.7.29 GHSA-pjwm-rvh2-c87w"], "in input order");
  assert.deepEqual(res.unchecked, []);
  assert.deepEqual(res.notes, [note(1)]);

  // When the answer that was to classify the record fails, every version waiting on it is unchecked, with its reason.
  const down = fake(ids, {}, { "ua-parser-js@0.7.29": json({}, 400) });
  const failed = await checkOsvDetailed(pkgs, { fetchImpl: down.fetchImpl });
  assert.deepEqual(down.asked, ["ua-parser-js@0.7.29"]);
  assert.deepEqual(failed.unchecked, ["ua-parser-js@0.7.29", "ua-parser-js@0.8.0", "z@1.0.0"]);
  assert.deepEqual(summary(failed.findings), ["WS-OS-001 critical z@1.0.0 MAL-2099-1", "WS-OS-900 high ua-parser-js@0.7.29 ua-parser-js@0.8.0 z@1.0.0"]);
  assert.match(failed.findings[1]?.message ?? "", /\(OSV returned HTTP 400 for a version's records\): /, "one reason: the answer each was waiting on");
});

test("osv cwe-506: a version's records are read over every page", async () => {
  const pages = (init: RequestInit | undefined, q: Query): Response => {
    assert.ok(init?.signal);
    if (q.page_token === undefined) return json({ vulns: [record("GHSA-1111-1111-1111", [])], next_page_token: "p2" });
    if (q.page_token === "p2") return json({ next_page_token: "p3" }); // a page with only a token, as OSV may send near its deadline
    return json({ vulns: [record("GHSA-2222-2222-2222", ["CWE-506"])] });
  };
  const db = fake({ "a@1.0.0": ["GHSA-1111-1111-1111", "GHSA-2222-2222-2222"] }, {}, { "a@1.0.0": pages });
  const res = await checkOsvDetailed([{ name: "a", version: "1.0.0" }], { fetchImpl: db.fetchImpl });
  assert.deepEqual(db.asked, ["a@1.0.0", "a@1.0.0 p2", "a@1.0.0 p3"]);
  assert.deepEqual(db.bodies[2], { package: { name: "a", ecosystem: "npm" }, version: "1.0.0", page_token: "p3" });
  assert.deepEqual(summary(res.findings), ["WS-OS-001 critical a@1.0.0 GHSA-2222-2222-2222"]);
  assert.deepEqual(res.notes, [note(1)], "one version, however many pages");

  // A version that never stops paging is unchecked after ten follow-up requests.
  const endless = fake({ "a@1.0.0": ["GHSA-1111-1111-1111"] }, {}, { "a@1.0.0": () => json({ vulns: [record("GHSA-1111-1111-1111", [])], next_page_token: "again" }) });
  const stuck = await checkOsvDetailed([{ name: "a", version: "1.0.0" }], { fetchImpl: endless.fetchImpl });
  assert.equal(endless.asked.length, 11);
  assert.deepEqual(stuck.unchecked, ["a@1.0.0"]);
  assert.match(stuck.findings[0]?.message ?? "", /OSV still had more records for a version after 10 follow-up requests/);
});

test("osv cwe-506: a record query that hangs is cut short by the timeout and leaves its version unchecked", async () => {
  const hang = (): Promise<Response> => new Promise((_resolve, reject) => setTimeout(() => reject(new Error("the hang was never cut short")), 2_000));
  const ids = { "a@1.0.0": ["GHSA-hhhh-hhhh-hhhh"] };
  // The fake ignores the signal, so wrap it: each record query races its own abort signal, as a real socket would.
  const db = fake(ids, {}, { "a@1.0.0": hang });
  const fetchImpl = ((url: string | URL, init?: RequestInit) =>
    String(url) === QUERY
      ? Promise.race([db.fetchImpl(url, init), new Promise<Response>((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(init.signal?.reason)))])
      : db.fetchImpl(url, init)) as typeof fetch;
  const res = await checkOsvDetailed([{ name: "a", version: "1.0.0" }], { fetchImpl, timeoutMs: 20 });
  assert.equal(db.asked.length, 2, "retried once");
  assert.deepEqual(summary(res.findings), ["WS-OS-900 high a@1.0.0"]);
  assert.match(res.findings[0]?.message ?? "", /request to OSV for a version's records failed: .*aborted due to timeout/);
});

/** Package i: name "p" and i in four digits, so name order is index order. */
const pkg = (i: number): OsvPackage => ({ name: `p${String(i).padStart(4, "0")}`, version: "1.0.0" });
/** Package i's own GHSA id. */
const ghsaOf = (i: number): string => `GHSA-${String(i).padStart(4, "0")}-gggg-gggg`;

test(`osv cwe-506: at most ${MAX_RECORD_QUERIES} versions' records are read per run, the first in name and version order; the rest are unchecked and the message says how to check them`, async () => {
  assert.equal(MAX_RECORD_QUERIES, 1000);
  // 1001 versions, one GHSA record each; the last in name order lists CWE-506 and is past the limit.
  const n = 1001;
  const ids = Object.fromEntries(Array.from({ length: n }, (_, i) => [`${pkg(i).name}@1.0.0`, [ghsaOf(i)]]));
  const db = fake(ids, { [ghsaOf(n - 1)]: record(ghsaOf(n - 1), ["CWE-506"]) });
  // Given in reverse, so the order comes from the names and versions, not from the lockfile.
  const pkgs = Array.from({ length: n }, (_, i) => pkg(n - 1 - i));
  const res = await checkOsvDetailed(pkgs, { fetchImpl: db.fetchImpl });
  assert.equal(db.asked.length, 1000);
  assert.deepEqual(db.asked, Array.from({ length: 1000 }, (_, i) => `${pkg(i).name}@1.0.0`), "the first 1000 in name order");
  assert.deepEqual(summary(res.findings), ["WS-OS-900 high p1000@1.0.0"], "past the limit is unchecked, never clean and never a guess");
  assert.equal(res.findings[0]?.message, "1 package version(s) could not be checked against OSV for malicious-package records (more than 1000 versions in this run had GitHub advisories to read, so the rest were not read: run soak on fewer or smaller lockfiles, or run it with --no-osv and check the lockfiles with another OSV client): p1000@1.0.0");
  assert.deepEqual(res.notes, [note(1000)]);

  // Versions of one name go in version order (compared as strings: the order only has to be the same on every run).
  const versions = ["1.0.9", "1.0.10", "2.0.0"];
  const same = fake(Object.fromEntries(versions.map((v, i) => [`q@${v}`, [ghsaOf(i)]])));
  await checkOsvDetailed(versions.map((version) => ({ name: "q", version })), { fetchImpl: same.fetchImpl, concurrency: 1 });
  assert.deepEqual(same.asked, ["q@1.0.10", "q@1.0.9", "q@2.0.0"]);
});

test("osv cwe-506: the WS-OS-900 message names at most three reasons, and the ceiling or the stop after OSV failed, which say what to do, come first", async () => {
  const git = { name: "g", version: "git+https://github.com/x/g.git" };
  const notFound = () => json({ code: 5, message: "Package not found" }, 404);
  // A git dependency, a 404, an answer without its version's GHSA record, and 1001 versions with GHSA ids: four reasons,
  // in that order, and the ceiling's is the fourth.
  const n = 1001;
  const ids = Object.fromEntries(Array.from({ length: n }, (_, i) => [`${pkg(i).name}@1.0.0`, [ghsaOf(i)]]));
  const db = fake(ids, {}, { "p0000@1.0.0": notFound, "p0001@1.0.0": () => json({}) });
  const res = await checkOsvDetailed([git, ...Array.from({ length: n }, (_, i) => pkg(i))], { fetchImpl: db.fetchImpl });
  assert.equal(db.asked.length, 1000);
  assert.deepEqual(res.unchecked, ["g@git+https://github.com/x/g.git", "p0000@1.0.0", "p0001@1.0.0", "p1000@1.0.0"]);
  assert.equal(
    res.findings[0]?.message,
    "4 package version(s) could not be checked against OSV for malicious-package records (more than 1000 versions in this run had GitHub advisories to read, so the rest were not read: run soak on fewer or smaller lockfiles, or run it with --no-osv and check the lockfiles with another OSV client; not a registry name and version; OSV returned HTTP 404 for a version's records): g@git+https://github.com/x/g.git, p0000@1.0.0, p0001@1.0.0, p1000@1.0.0",
  );

  // The stop: a git dependency, a 404, an answer without the record, a 503 twice (the stop), and a version after it.
  const four = Object.fromEntries(["a", "b", "c", "d"].map((name) => [`${name}@1.0.0`, [`GHSA-${name.repeat(4)}-gggg-gggg`]]));
  const down = fake(four, {}, { "a@1.0.0": notFound, "b@1.0.0": () => json({}), "c@1.0.0": () => json({}, 503) });
  const stopped = await checkOsvDetailed([git, ...["a", "b", "c", "d"].map((name) => ({ name, version: "1.0.0" }))], { fetchImpl: down.fetchImpl, sleep: down.sleep, concurrency: 1 });
  assert.deepEqual(down.asked, ["a@1.0.0", "b@1.0.0", "c@1.0.0", "c@1.0.0"]);
  assert.equal(
    stopped.findings[0]?.message,
    "5 package version(s) could not be checked against OSV for malicious-package records (record queries were stopped in this run after one failed (OSV returned HTTP 503 for a version's records); not a registry name and version; OSV returned HTTP 404 for a version's records): a@1.0.0, b@1.0.0, c@1.0.0, d@1.0.0, g@git+https://github.com/x/g.git",
  );
});

test("osv cwe-506: a run's session reads each GHSA record once across calls and ecosystems, and its ceiling counts every call", async () => {
  // The same record for two versions in one call, and again in a PyPI call of the same run: one record query.
  const shared = "GHSA-ssss-ssss-ssss";
  const ids = { "a@1.0.0": [shared], "b@1.0.0": [shared, "MAL-2099-1"], "c@1.0": [shared] };
  const db = fake(ids, { [shared]: record(shared, ["CWE-506"]) });
  const session = newOsvSession();
  const npm = await checkOsvDetailed([{ name: "a", version: "1.0.0" }, { name: "b", version: "1.0.0" }], { fetchImpl: db.fetchImpl, session });
  const py = await checkOsvDetailed([{ name: "c", version: "1.0" }], { ecosystem: "PyPI", fetchImpl: db.fetchImpl, session });
  assert.deepEqual(db.asked, ["a@1.0.0"], "b@1.0.0's record is in a@1.0.0's answer, and the PyPI call has it from the session");
  assert.equal(session.queries, 1);
  assert.deepEqual([npm.notes, py.notes], [[note(1)], []]);
  assert.deepEqual(summary(npm.findings), ["WS-OS-001 critical a@1.0.0 GHSA-ssss-ssss-ssss", "WS-OS-001 critical b@1.0.0 GHSA-ssss-ssss-ssss", "WS-OS-001 critical b@1.0.0 MAL-2099-1"]);
  assert.deepEqual(summary(py.findings), ["WS-OS-001 critical pypi:c@1.0 GHSA-ssss-ssss-ssss"]);
  // Without a session, each call is its own run.
  const alone = fake(ids, { [shared]: record(shared, ["CWE-506"]) });
  await checkOsvDetailed([{ name: "a", version: "1.0.0" }], { fetchImpl: alone.fetchImpl });
  await checkOsvDetailed([{ name: "a", version: "1.0.0" }], { fetchImpl: alone.fetchImpl });
  assert.deepEqual(alone.asked, ["a@1.0.0", "a@1.0.0"]);

  // The ceiling is the run's: 600 versions in the first call leave 400 for the second, which has 500.
  const many = fake(Object.fromEntries(Array.from({ length: 1100 }, (_, i) => [`${pkg(i).name}@1.0.0`, [ghsaOf(i)]])));
  const run = newOsvSession();
  const one = await checkOsvDetailed(Array.from({ length: 600 }, (_, i) => pkg(i)), { fetchImpl: many.fetchImpl, session: run });
  const two = await checkOsvDetailed(Array.from({ length: 500 }, (_, i) => pkg(600 + i)), { ecosystem: "PyPI", fetchImpl: many.fetchImpl, session: run });
  assert.equal(many.asked.length, 1000);
  assert.equal(run.queries, 1000);
  assert.deepEqual([one.notes, two.notes], [[note(600)], [note(400, "PyPI")]]);
  assert.deepEqual(one.unchecked, []);
  assert.deepEqual(two.unchecked, Array.from({ length: 100 }, (_, i) => `${pkg(1000 + i).name}@1.0.0`));
});

test("osv cwe-506: no more than `concurrency` record queries are in flight; a concurrency that starts no worker fails closed", async () => {
  const n = 12;
  const table = Object.fromEntries(Array.from({ length: n }, (_, i) => [`${pkg(i).name}@1.0.0`, [ghsaOf(i)]]));
  const pkgs = Array.from({ length: n }, (_, i) => pkg(i));
  const four = fake(table);
  assert.deepEqual((await checkOsvDetailed(pkgs, { fetchImpl: four.fetchImpl })).findings, []);
  assert.equal(four.asked.length, 12);
  assert.equal(four.flight.peak, 4, "four at a time by default");
  const two = fake(table);
  await checkOsvDetailed(pkgs, { fetchImpl: two.fetchImpl, concurrency: 2 });
  assert.equal(two.flight.peak, 2);
  // A concurrency of 0 sends no batch and no record query: every version is unchecked.
  const none = fake(table);
  const res = await checkOsvDetailed(pkgs, { fetchImpl: none.fetchImpl, concurrency: 0 });
  assert.deepEqual([none.batches.length, none.asked.length], [0, 0]);
  assert.equal(res.unchecked.length, 12);
});

test("osv cwe-506: two calls in one run give record-query notes that tell them apart: npm's without a label, PyPI's labelled", async () => {
  const ids = { "a@1.0.0": ["GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb"], "c@1.0": ["GHSA-aaaa-aaaa-aaaa", "GHSA-cccc-cccc-cccc"] };
  const db = fake(ids);
  const session = newOsvSession();
  const npm = await checkOsvDetailed([{ name: "a", version: "1.0.0" }], { fetchImpl: db.fetchImpl, session });
  const py = await checkOsvDetailed([{ name: "c", version: "1.0" }], { ecosystem: "PyPI", fetchImpl: db.fetchImpl, session });
  assert.deepEqual([npm.notes, py.notes], [["OSV records requested for 1 version(s) (GHSA classification)"], ["OSV records requested for 1 version(s) (GHSA classification, PyPI)"]]);
  assert.deepEqual(db.asked, ["a@1.0.0", "c@1.0"], "c@1.0 has a GHSA id the run had not read");
});

test("osv cwe-506: once a record query fails after its retry, no other starts in the run: OSV down costs one round of requests, and every version not read is unchecked", async () => {
  const n = 20;
  const name = (i: number) => `p${String(i).padStart(2, "0")}`;
  const table = Object.fromEntries(Array.from({ length: n }, (_, i) => [`${name(i)}@1.0.0`, [ghsaOf(i)]]));
  const pkgs = Array.from({ length: n }, (_, i) => ({ name: name(i), version: "1.0.0" }));
  const all = pkgs.map((p) => `${p.name}@1.0.0`);
  // Positive control: the same 20 versions, served, are all read and every version is clean.
  const up = fake(table);
  const ok = await checkOsvDetailed(pkgs, { fetchImpl: up.fetchImpl, timeoutMs: 20 });
  assert.deepEqual([up.asked.length, ok.unchecked, ok.findings, ok.notes], [20, [], [], [note(20)]]);

  // Every request fails: answered at once, or never answered until the 20 ms timeout aborts it.
  const hang = (init?: RequestInit): Promise<Response> =>
    new Promise((_resolve, reject) => {
      const signal = init?.signal;
      if (!signal) return reject(new Error("a record query without a timeout"));
      if (signal.aborted) return reject(signal.reason);
      signal.addEventListener("abort", () => reject(signal.reason));
    });
  const thrown = () => {
    throw new TypeError("fetch failed");
  };
  const cases: [label: string, answer: Answer, reason: RegExp][] = [
    ["HTTP 503", () => json({}, 503), /OSV returned HTTP 503 for a version's records/],
    ["HTTP 429", () => json({}, 429), /OSV returned HTTP 429 for a version's records/],
    ["a network error", thrown, /request to OSV for a version's records failed: fetch failed/],
    ["a hang the timeout cuts short", hang, /request to OSV for a version's records failed: .*aborted due to timeout/],
  ];
  for (const [label, answer, reason] of cases) {
    const db = fake(table, {}, Object.fromEntries(all.map((id) => [id, answer])));
    const res = await checkOsvDetailed(pkgs, { fetchImpl: db.fetchImpl, sleep: db.sleep, timeoutMs: 20 });
    assert.equal(db.asked.length, 8, `${label}: the four started at once, each retried once, and no fifth`);
    assert.deepEqual([...new Set(db.asked)].sort(), all.slice(0, 4), label);
    assert.deepEqual(res.unchecked, all, `${label}: every version unchecked, never clean`);
    assert.deepEqual(summary(res.findings), [`WS-OS-900 high ${all.join(" ")}`], label);
    const message = res.findings[0]?.message ?? "";
    assert.match(message, reason, label);
    assert.match(message, /record queries were stopped in this run after one failed \(/, label);
    assert.deepEqual(res.notes, [note(4)], label);
  }

  // A failure of one version's answer, not of OSV, stops nothing: a 404, an answer without the record, and a 503 the
  // retry fixes.
  let first = true;
  const negatives: [label: string, answer: Answer, asked: number, unchecked: string[]][] = [
    ["HTTP 404", json({ code: 5, message: "Package not found" }, 404), 20, [all[0]!]],
    ["an answer without the record", () => json({}), 20, [all[0]!]],
    ["a 503 then the records", () => (first ? ((first = false), json({}, 503)) : json({ vulns: [record(ghsaOf(0), [])] })), 21, []],
  ];
  for (const [label, answer, asked, unchecked] of negatives) {
    const db = fake(table, {}, { [all[0]!]: answer });
    const res = await checkOsvDetailed(pkgs, { fetchImpl: db.fetchImpl, sleep: db.sleep, timeoutMs: 20 });
    assert.equal(db.asked.length, asked, `${label}: every version asked`);
    assert.deepEqual(res.unchecked, unchecked, label);
  }

  // The stop holds for the run: a later call in the same session (another ecosystem) sends no record query, and its
  // versions with a GHSA record not read are unchecked; a record read before the stop still counts.
  const session = newOsvSession();
  const later = { ...table, "late@1.0": ["GHSA-llll-llll-llll"], "known@1.0": [ghsaOf(1)] };
  const db = fake(later, { "GHSA-llll-llll-llll": record("GHSA-llll-llll-llll", ["CWE-506"]) }, { [all[0]!]: () => json({}, 503) });
  const npm = await checkOsvDetailed(pkgs, { fetchImpl: db.fetchImpl, sleep: db.sleep, session, timeoutMs: 20 });
  assert.equal(session.stopped, "OSV returned HTTP 503 for a version's records");
  assert.ok(db.asked.length < 20, `the npm call stopped early (${db.asked.length} requests)`);
  assert.ok(npm.unchecked.length > 1, "more than the failed version is unchecked");
  assert.ok(!npm.unchecked.includes(all[1]!), "p01, asked at the same time as p00, was read");
  const before = db.asked.length;
  const py = await checkOsvDetailed([{ name: "late", version: "1.0" }, { name: "known", version: "1.0" }], { ecosystem: "PyPI", fetchImpl: db.fetchImpl, sleep: db.sleep, session, timeoutMs: 20 });
  assert.equal(db.asked.length, before, "no record query after the stop");
  assert.deepEqual(py.notes, []);
  assert.deepEqual(py.unchecked, ["late@1.0"], "known@1.0's record was read before the stop");
  assert.deepEqual(summary(py.findings), ["WS-OS-900 high pypi:late@1.0"], "a CWE-506 record not read is no finding, and its version is not clean");
  assert.match(py.findings[0]?.message ?? "", /\(record queries were stopped in this run after one failed \(OSV returned HTTP 503 for a version's records\)\): late@1\.0$/);
});

test("osv cwe-506: a record query answered HTTP 429 or 503 waits before its one retry: Retry-After's seconds, at most 30, or else 2 seconds", async () => {
  const ids = { "a@1.0.0": ["GHSA-aaaa-aaaa-aaaa"] };
  const pkgs = [{ name: "a", version: "1.0.0" }];
  const refused = (status: number, retryAfter?: string) => new Response("{}", { status, headers: retryAfter === undefined ? {} : { "retry-after": retryAfter } });
  const cases: [status: number, retryAfter: string | undefined, wait: number | undefined][] = [
    [429, "7", 7_000],
    [503, "7", 7_000],
    [429, "0", 0],
    [429, "30", 30_000],
    [429, "120", 30_000],
    [503, "99999999999999999999", 30_000],
    [429, undefined, 2_000],
    [503, undefined, 2_000],
    [429, "Thu, 08 Oct 2026 07:28:00 GMT", 2_000],
    [429, "1.5", 2_000],
    [429, "-1", 2_000],
    [503, "", 2_000],
    // Other retried statuses go again at once.
    [500, "7", undefined],
    [502, undefined, undefined],
    [504, undefined, undefined],
  ];
  for (const [status, retryAfter, wait] of cases) {
    const label = `HTTP ${status}, Retry-After ${JSON.stringify(retryAfter)}`;
    /** How many waits had been made when each request went out. */
    const waitedBefore: number[] = [];
    const db = fake(ids, {}, {
      "a@1.0.0": () => {
        waitedBefore.push(db.waits.length);
        return waitedBefore.length === 1 ? refused(status, retryAfter) : json({ vulns: [record("GHSA-aaaa-aaaa-aaaa", [])] });
      },
    });
    const res = await checkOsvDetailed(pkgs, { fetchImpl: db.fetchImpl, sleep: db.sleep });
    assert.deepEqual(db.waits, wait === undefined ? [] : [wait], label);
    assert.deepEqual(waitedBefore, [0, db.waits.length], `${label}: any wait comes before the retry`);
    assert.deepEqual([res.findings, res.unchecked], [[], []], `${label}: the retry's answer counts`);
  }

  // One wait per request: the retry is the last attempt, so a second 429 is not waited for, and the version is unchecked.
  const twice = fake(ids, {}, { "a@1.0.0": () => refused(429, "3") });
  const res = await checkOsvDetailed(pkgs, { fetchImpl: twice.fetchImpl, sleep: twice.sleep });
  assert.deepEqual([twice.asked.length, twice.waits], [2, [3_000]]);
  assert.deepEqual(res.unchecked, ["a@1.0.0"]);
  assert.match(res.findings[0]?.message ?? "", /OSV returned HTTP 429 for a version's records/);

  // A query batch still retries at once: one that fails leaves its own versions unchecked and stops nothing.
  const batch = fake(ids);
  let first = true;
  const fetchImpl = ((url: string | URL, init?: RequestInit) => (String(url) === QUERYBATCH && first ? ((first = false), Promise.resolve(refused(429, "7"))) : batch.fetchImpl(url, init))) as typeof fetch;
  const retried = await checkOsvDetailed(pkgs, { fetchImpl, sleep: batch.sleep });
  assert.deepEqual([batch.batches.length, batch.asked, batch.waits, retried.unchecked], [1, ["a@1.0.0"], [], []]);

  // Without the option, the wait is a real timer.
  const timed = fake(ids, {}, { "a@1.0.0": () => (timed.asked.length === 1 ? refused(503, "1") : json({ vulns: [record("GHSA-aaaa-aaaa-aaaa", [])] })) });
  const t0 = performance.now();
  const slow = await checkOsvDetailed(pkgs, { fetchImpl: timed.fetchImpl });
  assert.ok(performance.now() - t0 >= 950, `waited ${Math.round(performance.now() - t0)} ms for Retry-After: 1`);
  assert.deepEqual([timed.asked.length, timed.waits, slow.unchecked], [2, [], []]);
});
