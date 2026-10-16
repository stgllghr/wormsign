/**
 * One OSV ecosystem per call: a PyPI call sends "PyPI", validates names and versions by PyPI's rules and prefixes its
 * keys with "pypi:"; an npm call (the default) is exactly what it was, whatever PyPI call runs beside it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { OSV_VALID, checkOsv, checkOsvDetailed } from "../src/osv.js";
import type { OsvPackage } from "../src/osv.js";

interface Query {
  package: { name: string; ecosystem: string };
  version: string;
  page_token?: string;
}

/**
 * Fake api.osv.dev over records keyed "<ecosystem>:<name>@<version>" (a value's "+next" ids come on a second page).
 * A record query (POST /v1/query) gets all the version's records in one answer; a GHSA record lists CWE-506 when its
 * id is in `cwe506`, and only CWE-79 otherwise. Every status but 200 fails each request. Records every batch query in
 * `asked` and every record query, as "<ecosystem>:<name>@<version>", in `read`.
 */
function osv(records: Record<string, string[]>, status = 200, cwe506: string[] = []) {
  const asked: Query[] = [];
  const read: string[] = [];
  const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
    if (String(url) === "https://api.osv.dev/v1/query") {
      const q = JSON.parse(String(init?.body)) as Query;
      const key = `${q.package.ecosystem}:${q.package.name}@${q.version}`;
      read.push(key);
      const vulns = (records[key] ?? []).map((id) => id.replace(/^\+/, "")).map((id) => (id.startsWith("GHSA-") ? { id, database_specific: { cwe_ids: cwe506.includes(id) ? ["CWE-506"] : ["CWE-79"] } } : { id }));
      return new Response(JSON.stringify(vulns.length > 0 ? { vulns } : {}), { status });
    }
    const { queries } = JSON.parse(String(init?.body)) as { queries: Query[] };
    asked.push(...queries);
    if (status !== 200) return new Response("", { status });
    const results = queries.map((q) => {
      const ids = records[`${q.package.ecosystem}:${q.package.name}@${q.version}`] ?? [];
      const page = ids.filter((id) => id.startsWith("+") === (q.page_token !== undefined)).map((id) => ({ id: id.replace(/^\+/, ""), modified: "2026-01-01T00:00:00Z" }));
      return { ...(page.length > 0 ? { vulns: page } : {}), ...(q.page_token === undefined && ids.some((id) => id.startsWith("+")) ? { next_page_token: "p2" } : {}) };
    });
    return new Response(JSON.stringify({ results }));
  }) as typeof fetch;
  return { fetchImpl, asked, read };
}

test("osv: a PyPI call sends ecosystem PyPI in every query, keys its findings pypi:, and npm stays the default", async () => {
  const db = osv({ "PyPI:requests@2.31.0": ["MAL-2099-1"], "npm:requests@2.31.0": ["MAL-2099-2"] });
  const res = await checkOsvDetailed([{ name: "requests", version: "2.31.0", file: "uv.lock" }, { name: "numpy", version: "2.0.0", file: "uv.lock" }], { ecosystem: "PyPI", fetchImpl: db.fetchImpl });
  assert.deepEqual(db.asked.map((q) => `${q.package.ecosystem} ${q.package.name}@${q.version}`), ["PyPI requests@2.31.0", "PyPI numpy@2.0.0"]);
  assert.deepEqual(res.findings.map((f) => `${f.ruleId} ${f.file} ${f.key} ${f.message}`), ["WS-OS-001 uv.lock pypi:requests@2.31.0 MAL-2099-1 requests@2.31.0 is a malicious package version according to OSV record MAL-2099-1"]);
  assert.deepEqual([...res.records], [["requests@2.31.0", ["MAL-2099-1"]]]);
  assert.deepEqual(res.unchecked, []);
  assert.deepEqual(res.notes, [], "no GHSA record was requested, so no note");

  const npm = osv({ "npm:requests@2.31.0": ["MAL-2099-2"] });
  const found = await checkOsv([{ name: "requests", version: "2.31.0", file: "package-lock.json" }], { fetchImpl: npm.fetchImpl });
  assert.deepEqual(npm.asked.map((q) => q.package.ecosystem), ["npm"], "no ecosystem given means npm");
  assert.deepEqual(found.map((f) => f.key), ["requests@2.31.0 MAL-2099-2"], "npm keys have no prefix");
});

test("osv: PyPI versions must be PEP 440 canonical and PyPI names PEP 503-normalised; anything else is unchecked, not sent", async () => {
  const good = ["1.4", "2025.2", "2.9.0.post0", "3.0b1", "1!2.0", "1.0+local", "0.1", "1.0rc1", "1.0a1.post2.dev3", "1.0.dev0", "1.0+ubuntu.1", "1.0+0", "1.0+a01", "1.0+1a", "1.0+0a.10", `10${".0".repeat(127)}`];
  const bad = ["", "1.0 ", "a/b", "v1.0", "1.0-rc1", "1.0RC1", "1.0c1", "01.0", "0!1.0", "1.0+Local", "1.0+", "1.0.post", ` 1.0`, "1.0+01", "1.0+00", "1.0+a.01", `100${".0".repeat(127)}`];
  assert.equal(good.at(-1)?.length, 256);
  assert.equal(bad.at(-1)?.length, 257);
  const db = osv({});
  const res = await checkOsvDetailed([...good, ...bad].map((version) => ({ name: "pkg", version, file: "pylock.toml" })), { ecosystem: "PyPI", fetchImpl: db.fetchImpl });
  assert.deepEqual(db.asked.map((q) => q.version), good, "only canonical versions are sent");
  const ids = bad.map((v) => `pkg@${v}`).sort();
  assert.deepEqual(res.unchecked, ids);
  assert.deepEqual(res.findings.map((f) => [f.ruleId, f.key]), [["WS-OS-900", `pypi:${ids.join(" ")}`]]);
  assert.match(res.findings[0]?.message ?? "", /^17 package version\(s\) could not be checked against OSV for malicious-package records \(not a registry name and version\): /);

  const names = { good: ["requests", "python-dateutil", "zope-interface", "a", "x2", "0", "a".repeat(200)], bad: ["Requests", "zope.interface", "typing_extensions", "a--b", "-x", "x-", "", "a/b", "na me", "@scope/x", "a".repeat(201), "名前"] };
  for (const n of names.good) assert.ok(OSV_VALID.PyPI.name(n), n);
  for (const n of names.bad) assert.ok(!OSV_VALID.PyPI.name(n), n);
  const byName = osv({});
  const r = await checkOsvDetailed([...names.good, ...names.bad].map((name) => ({ name, version: "1.0" })), { ecosystem: "PyPI", fetchImpl: byName.fetchImpl });
  assert.deepEqual(byName.asked.map((q) => q.package.name), names.good);
  assert.deepEqual(r.unchecked, names.bad.map((n) => `${n}@1.0`).sort());
  // npm's rules are unchanged: semver only, so a PEP 440 version that is not semver stays unchecked there.
  assert.ok(OSV_VALID.npm.version("1.0.0") && !OSV_VALID.npm.version("1.4") && OSV_VALID.npm.name("@scope/x") && !OSV_VALID.PyPI.name("@scope/x"));
});

test("osv: the same name@version asked in both ecosystems leaves npm's findings, keys and answers unchanged", async () => {
  const records = { "npm:shared@1.0.0": ["MAL-2099-10"], "PyPI:shared@1.0.0": ["MAL-2099-20", "+MAL-2099-21"] };
  const npmPkg: OsvPackage[] = [{ name: "shared", version: "1.0.0", file: "package-lock.json" }];
  const pyPkg: OsvPackage[] = [{ name: "shared", version: "1.0.0", file: "uv.lock" }];
  const alone = await checkOsvDetailed(npmPkg, { fetchImpl: osv(records).fetchImpl });

  const both = osv(records);
  const npm = await checkOsvDetailed(npmPkg, { fetchImpl: both.fetchImpl });
  const py = await checkOsvDetailed(pyPkg, { ecosystem: "PyPI", fetchImpl: both.fetchImpl });
  assert.deepEqual(npm, alone);
  assert.deepEqual(npm.findings.map((f) => f.key), ["shared@1.0.0 MAL-2099-10"]);
  assert.deepEqual([...npm.records], [["shared@1.0.0", ["MAL-2099-10"]]]);
  assert.deepEqual(py.findings.map((f) => f.key), ["pypi:shared@1.0.0 MAL-2099-20", "pypi:shared@1.0.0 MAL-2099-21"]);
  assert.deepEqual([...py.records], [["shared@1.0.0", ["MAL-2099-20", "MAL-2099-21"]]], "a PyPI record on OSV's second page");
  assert.deepEqual(both.asked.map((q) => `${q.package.ecosystem}${q.page_token ? " page 2" : ""}`), ["npm", "PyPI", "PyPI page 2"]);

  // OSV down: one WS-OS-900 per ecosystem, with npm's key as it always was, and fingerprints that never collide.
  const down = osv({}, 503);
  const [n900] = await checkOsv(npmPkg, { fetchImpl: down.fetchImpl });
  const [p900] = await checkOsv(pyPkg, { ecosystem: "PyPI", fetchImpl: down.fetchImpl });
  assert.equal(n900?.key, "shared@1.0.0");
  assert.equal(p900?.key, "pypi:shared@1.0.0");
  assert.notEqual(n900?.fingerprint, p900?.fingerprint);
  assert.equal(n900?.message, p900?.message, "the message is the same; the key tells them apart");
});

test("osv: checkOsvDetailed returns OSV's answers as data, matching the findings checkOsv returns", async () => {
  const table = { "npm:bad@1.0.0": ["MAL-2099-1", "GHSA-xxxx-xxxx-xxxx", "+MAL-2099-2", "+GHSA-mmmm-mmmm-mmmm"], "npm:ok@1.0.0": ["GHSA-xxxx-xxxx-xxxx"] };
  const db = osv(table, 200, ["GHSA-mmmm-mmmm-mmmm"]);
  const pkgs = [{ name: "ok", version: "1.0.0" }, { name: "bad", version: "1.0.0", file: "package-lock.json" }, { name: "zz", version: "git+ssh://x" }, { name: "aa", version: "" }];
  const res = await checkOsvDetailed(pkgs, { fetchImpl: db.fetchImpl });
  assert.deepEqual(res.unchecked, ["aa@", "zz@git+ssh://x"], "sorted");
  assert.deepEqual([...res.records], [["bad@1.0.0", ["MAL-2099-1", "MAL-2099-2", "GHSA-mmmm-mmmm-mmmm"]]], "MAL- records and CWE-506 GHSA records, from every page, in OSV's order");
  assert.deepEqual(db.read, ["npm:bad@1.0.0"], "ok@1.0.0's one GHSA id is among bad@1.0.0's, whose records are read first");
  assert.deepEqual(res.notes, ["OSV records requested for 1 version(s) (GHSA classification)"]);
  assert.deepEqual(res.findings, await checkOsv(pkgs, { fetchImpl: osv(table, 200, ["GHSA-mmmm-mmmm-mmmm"]).fetchImpl }));
  assert.deepEqual(res.findings.map((f) => f.key), ["bad@1.0.0 MAL-2099-1", "bad@1.0.0 MAL-2099-2", "bad@1.0.0 GHSA-mmmm-mmmm-mmmm", "aa@ zz@git+ssh://x"]);
});

test("osv: a CWE-506 GHSA record is a PyPI finding exactly as in npm, keyed pypi:, and npm's are unchanged by it", async () => {
  const table = { "npm:shared@1.0.0": ["GHSA-wwww-wwww-wwww"], "PyPI:shared@1.0.0": ["GHSA-wwww-wwww-wwww", "MAL-2099-30"] };
  const db = osv(table, 200, ["GHSA-wwww-wwww-wwww"]);
  const npm = await checkOsvDetailed([{ name: "shared", version: "1.0.0", file: "package-lock.json" }], { fetchImpl: db.fetchImpl });
  const py = await checkOsvDetailed([{ name: "shared", version: "1.0.0", file: "uv.lock" }], { ecosystem: "PyPI", fetchImpl: db.fetchImpl });
  assert.deepEqual(npm.findings.map((f) => `${f.ruleId} ${f.severity} ${f.key}`), ["WS-OS-001 critical shared@1.0.0 GHSA-wwww-wwww-wwww"]);
  assert.deepEqual(py.findings.map((f) => `${f.ruleId} ${f.severity} ${f.key}`), ["WS-OS-001 critical pypi:shared@1.0.0 GHSA-wwww-wwww-wwww", "WS-OS-001 critical pypi:shared@1.0.0 MAL-2099-30"]);
  assert.equal(npm.findings[0]?.message, py.findings[0]?.message, "the same message; the key tells them apart");
  assert.notEqual(npm.findings[0]?.fingerprint, py.findings[0]?.fingerprint);
});
