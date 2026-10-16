import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

/* Maintainer scripts in scripts/ are plain .mjs; these tests pin the behaviour the IOC data relies on. */
const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
type Parsed = { packages: Record<string, Set<string>>; check: string };
type Pages = Record<"parseStepSecurity" | "parseSocketWave1" | "parseJfrogAug2026" | "parsePicusMiniShaiHulud" | "parseStepSecurityMay2026", (html: string) => Parsed>;
const pages = (): Promise<Pages> => import(pathToFileURL(join(repoRoot, "scripts", "vendor-pages.mjs")).href) as Promise<Pages>;
const flat = (p: Parsed) => Object.entries(p.packages).flatMap(([n, vs]) => [...vs].map((v) => `${n}@${v}`)).sort();

const stepRow = (n: number, name: string, versions: string, close = "</td>") =>
  `<tr class="hidden"><td>${n}</td><td class="package-name">${name}</td><td class="versions">${versions}${close}</tr>`;
const stepPage = (rows: string) => `<table><thead><tr><th>Row</th><th>Package Name</th><th>Version(s)</th></tr></thead><tbody>${rows}</tbody></table>`;

test("StepSecurity table: every row is read, including a cell the page fails to close", async () => {
  const { parseStepSecurity } = await pages();
  const res = parseStepSecurity(stepPage(stepRow(1, "@a/b", "1.0.0, 1.0.1", "</BUTT>") + stepRow(2, "c", "2.0.0")));
  assert.deepEqual(flat(res), ["@a/b@1.0.0", "@a/b@1.0.1", "c@2.0.0"]);
  assert.throws(() => parseStepSecurity(stepPage(stepRow(1, "a", "1.0.0") + stepRow(3, "c", "2.0.0"))), /row numbered 3 at position 2/);
  assert.throws(() => parseStepSecurity(stepPage(stepRow(1, "a", "1.0.0 beta"))), /unexpected entry/);
  assert.throws(() => parseStepSecurity("<p>moved</p>"), /layout changed/);
});

test("Socket list: the parsed pairs must equal the page's stated total", async () => {
  const { parseSocketWave1 } = await pages();
  const page = (total: number, items: string[]) => `<p class="x">Total packages: ${total}</p><ol class="y">${items.map((i) => `<li class="z"><a href="#">${i}</a></li>`).join("")}</ol>`;
  assert.deepEqual(flat(parseSocketWave1(page(2, ["@s/x@1.0.0", "y@2.0.0"]))), ["@s/x@1.0.0", "y@2.0.0"]);
  assert.throws(() => parseSocketWave1(page(3, ["@s/x@1.0.0", "y@2.0.0"])), /states 3 packages, parsed 2/);
  assert.throws(() => parseSocketWave1(page(2, ["y@2.0.0", "y@2.0.0"])), /1 unique pairs/);
});

test("JFrog table: npm rows only, and the parse must reach the page's 400+ / 1700+ lower bounds", async () => {
  const { parseJfrogAug2026 } = await pages();
  const row = (name: string, type: string, versions: string[]) =>
    `<tr>\n<td align="left"><code>${name}</code></td>\n<td align="left">${type}</td>\n<td align="left">${versions.map((v) => `<code>${v}</code>`).join(", ")}</td>\n<td align="left">XRAY-1</td>\n</tr>`;
  const page = (rows: string[]) =>
    `<p>400+ packages across 1700+ versions</p><h2 id="compromised-packages-ongoing">x</h2><table><thead><tr><th>Package</th></tr></thead><tbody>${rows.join("")}</tbody></table>`;
  const npmRows = Array.from({ length: 400 }, (_, i) => row(`p${i}`, "npm", ["1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4"]));
  const res = parseJfrogAug2026(page([...npmRows, row("github.com/x/y", "golang", ["&#x3E;= v0.4.9"])]));
  assert.equal(Object.keys(res.packages).length, 400);
  assert.ok(!("github.com/x/y" in res.packages));
  assert.throws(() => parseJfrogAug2026(page(npmRows.slice(1))), /below the stated 400\+ \/ 1700\+/);
  assert.throws(() => parseJfrogAug2026(page([...npmRows, row("p0", "npm", ["2.0.0"])])), /appears in two rows/);
  assert.throws(() => parseJfrogAug2026(page([...npmRows, row("q", "pypi", ["1.0.0"])])), /unknown package type/);
});

test("Picus: exactly the four packages its sentence names", async () => {
  const { parsePicusMiniShaiHulud } = await pages();
  const item = (n: string, v: string) => `<strong><span>${n} version ${v}</span></strong>`;
  const page = (items: string[]) => `<p><span>The first known wave compromised four trusted packages used in SAP development workflows: </span>${items.join("<span>, </span>")}<span>.</span></p><p>${item("other", "9.9.9")}</p>`;
  const four = [item("@cap-js/sqlite", "2.2.2"), item("@cap-js/postgres", "2.2.2"), item("@cap-js/db-service", "2.10.1"), item("mbt", "1.2.48")];
  assert.deepEqual(flat(parsePicusMiniShaiHulud(page(four))), ["@cap-js/db-service@2.10.1", "@cap-js/postgres@2.2.2", "@cap-js/sqlite@2.2.2", "mbt@1.2.48"]);
  assert.throws(() => parsePicusMiniShaiHulud(page(four.slice(1))), /names four packages, parsed 3/);
  assert.throws(() => parsePicusMiniShaiHulud("<p>moved</p>"), /layout changed/);
});

test("StepSecurity May 2026: npm rows only, and the @tanstack/ rows must be exactly the 42 packages / 84 versions the page states", async () => {
  const { parseStepSecurityMay2026 } = await pages();
  const row = (name: string, versions: string) => `\n    <tr><td><code>${name}</code></td><td>${versions}</td></tr>`;
  const stated = "<p>an attacker published 84 malicious versions across 42 @tanstack/* packages by chaining</p>";
  const page = (rows: string[], intro = stated) =>
    `${intro}<h2>Compromised Packages</h2><table class="pkg-table" id="pkgTable"><thead><tr><th>Package</th><th>Compromised Versions</th></tr></thead><tbody>${rows.join("")}\n  </tbody></table><table><tbody><tr><td>File count</td><td>101</td></tr></tbody></table>`;
  const tanstack = Array.from({ length: 42 }, (_, i) => row(`@tanstack/p${i}`, `1.${i}.5, 1.${i}.8`));
  const res = parseStepSecurityMay2026(page([row("@mistralai/mistralai", "2.2.3, 2.2.4"), ...tanstack, row("mistralai (PyPI)", "2.4.6")]));
  assert.equal(Object.keys(res.packages).length, 43);
  assert.deepEqual([...(res.packages["@mistralai/mistralai"] ?? [])].sort(), ["2.2.3", "2.2.4"]);
  assert.ok(!("mistralai (PyPI)" in res.packages) && !("mistralai" in res.packages), "a PyPI row is not an npm package");
  assert.ok(!("File count" in res.packages), "only the pkgTable table is read");
  assert.throws(() => parseStepSecurityMay2026(page(tanstack.slice(1))), /parsed 41 @tanstack\/ packages \/ 82 versions, the page states 42 \/ 84/);
  assert.throws(() => parseStepSecurityMay2026(page(tanstack, "<p>moved</p>")), /stated TanStack totals not found/);
  assert.throws(() => parseStepSecurityMay2026(page([...tanstack, row("@tanstack/p0", "9.9.9")])), /appears in two rows/);
  assert.throws(() => parseStepSecurityMay2026(page([...tanstack, row("guardrails-ai (pip)", "0.10.1")])), /unexpected entry/);
  assert.throws(() => parseStepSecurityMay2026(page([...tanstack, "<tr><td>x</td></tr>"])), /row 43 does not have the expected cells/);
  assert.throws(() => parseStepSecurityMay2026("<p>moved</p>"), /layout changed/);
});

/* ---- scripts/import-package-sets.mjs: licensed data only, selected by the cited report ---- */
type Selection = { packages: Record<string, Set<string>>; records: Record<string, string[]>; unmatched: Record<string, Set<string>>; notListed: number };
type Dataset = { name: string; url: string; path: string };
type Importer = {
  DATASETS: Record<"datadog" | "openssf", Dataset>;
  checkout(dir: string, d: Dataset): { commit: string; license: string; url: string };
  parseConsolidatedCsv(text: string): Record<string, Set<string>>;
  openssfRecords(root: string, name: string): { id: string; versions: string[] }[];
  selectFromOpenSSF(listed: Record<string, Set<string>>, recordsFor: (name: string) => { id: string; versions: string[] }[]): Selection;
};
const importer = (): Promise<Importer> => import(pathToFileURL(join(repoRoot, "scripts", "import-package-sets.mjs")).href) as Promise<Importer>;
const sets = (o: Record<string, Set<string>>) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, [...v].sort()]));
const record = (id: string, name: string, versions: string[], extra: Record<string, unknown> = {}) =>
  JSON.stringify({ id, ...extra, affected: [{ package: { ecosystem: "npm", name }, versions }, { package: { ecosystem: "PyPI", name }, versions: ["6.6.6"] }] });

test("OpenSSF selection: a version needs both the report and a record; the rest is unmatched or left out", async () => {
  const { selectFromOpenSSF } = await importer();
  const listed = { a: new Set(["1.0.0", "1.0.1"]), b: new Set(["2.0.0"]), c: new Set(["3.0.0"]) };
  const recs: Record<string, { id: string; versions: string[] }[]> = {
    a: [{ id: "MAL-1", versions: ["1.0.0", "0.9.0", "0.9.1"] }, { id: "MAL-9", versions: ["5.0.0"] }],
    b: [{ id: "MAL-2", versions: ["2.0.0"] }, { id: "MAL-3", versions: ["2.0.0"] }],
  };
  const sel = selectFromOpenSSF(listed, (n) => recs[n] ?? []);
  assert.deepEqual(sets(sel.packages), { a: ["1.0.0"], b: ["2.0.0"] }, "only versions a record lists");
  assert.deepEqual(sel.records, { a: ["MAL-1"], b: ["MAL-2", "MAL-3"] }, "only the records that matched");
  assert.deepEqual(sets(sel.unmatched), { a: ["1.0.1"], c: ["3.0.0"] });
  assert.equal(sel.notListed, 2, "MAL-1's 0.9.0 and 0.9.1 are not in the report, so not imported");
});

test("OpenSSF records: read by package path, npm entries for that name only, withdrawn records skipped", async () => {
  const { openssfRecords } = await importer();
  const root = mkdtempSync(join(tmpdir(), "ws-ossf-"));
  const dir = join(root, "osv", "malicious", "npm", "@s", "p");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "MAL-2025-1.json"), record("MAL-2025-1", "@s/p", ["1.0.0"]));
  writeFileSync(join(dir, "MAL-2025-2.json"), record("MAL-2025-2", "@s/p", ["2.0.0"], { withdrawn: "2025-10-01T00:00:00Z" }));
  writeFileSync(join(dir, "MAL-2025-3.json"), record("MAL-2025-3", "@s/other", ["3.0.0"]));
  assert.deepEqual(openssfRecords(root, "@s/p"), [{ id: "MAL-2025-1", versions: ["1.0.0"] }, { id: "MAL-2025-3", versions: [] }]);
  assert.deepEqual(openssfRecords(root, "absent"), []);
  rmSync(root, { recursive: true, force: true });
});

test("Datadog consolidated CSV: quoted multi-version fields are split; a changed header or bad version stops the import", async () => {
  const { parseConsolidatedCsv } = await importer();
  const head = "package_name,package_versions,sources\n";
  const csv = head + '02-echo,0.0.7,"datadog, wiz"\n@a/b,"1.0.1637-dev, 1.0.738, 1.0.739","koi, wiz"\n';
  assert.deepEqual(sets(parseConsolidatedCsv(csv)), { "02-echo": ["0.0.7"], "@a/b": ["1.0.1637-dev", "1.0.738", "1.0.739"] });
  assert.throws(() => parseConsolidatedCsv("package_name,package_version\nx,1.0.0\n"), /unexpected header/);
  assert.throws(() => parseConsolidatedCsv(head + 'x,"1.0.0, = 1.0.1",wiz\n'), /unexpected entry/);
  assert.throws(() => parseConsolidatedCsv(head + "x,1.0.0,wiz\nx,1.0.1,koi\n"), /appears twice/);
  assert.throws(() => parseConsolidatedCsv(head + 'x,"1.0.0,wiz\n'), /unterminated quote/);
});

test("dataset checkouts: the right repository, unmodified, under Apache-2.0, and the commit is recorded", async () => {
  const { checkout, DATASETS } = await importer();
  const repo = mkdtempSync(join(tmpdir(), "ws-ds-"));
  const git = (...a: string[]) => execFileSync("git", ["-C", repo, ...a], { encoding: "utf8" }).trim();
  git("init", "-q");
  git("remote", "add", "origin", "https://github.com/ossf/malicious-packages.git");
  writeFileSync(join(repo, "LICENSE"), readFileSync(join(repoRoot, "data", "iocs", "LICENSES", "Apache-2.0.txt")));
  git("add", "LICENSE");
  const commit = (...a: string[]) => git("-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false", "commit", "-q", ...a);
  commit("-m", "x");
  const got = checkout(repo, DATASETS.openssf);
  assert.deepEqual([got.url, got.commit, got.license], ["https://github.com/ossf/malicious-packages", git("rev-parse", "HEAD"), "Apache-2.0"]);
  assert.throws(() => checkout(repo, DATASETS.datadog), /origin is https:\/\/github.com\/ossf\/malicious-packages, expected https:\/\/github.com\/DataDog/);
  writeFileSync(join(repo, "LICENSE"), "MIT License\n");
  assert.throws(() => checkout(repo, DATASETS.openssf), /local changes/);
  commit("-am", "relicense");
  assert.throws(() => checkout(repo, DATASETS.openssf), /not the Apache License 2\.0/);
  rmSync(repo, { recursive: true, force: true });
});

test("import-package-sets: refuses to run without a retrieved date and all three inputs", () => {
  const run = (...a: string[]) => spawnSync(process.execPath, [join(repoRoot, "scripts", "import-package-sets.mjs"), ...a], { encoding: "utf8" });
  const all = ["--retrieved", "2026-10-02", "--pages", "p", "--datadog", "d", "--openssf", "o"];
  for (const drop of ["--retrieved", "--pages", "--datadog", "--openssf"]) {
    const i = all.indexOf(drop);
    const r = run(...all.slice(0, i), ...all.slice(i + 2));
    assert.equal(r.status, 2, drop);
    assert.match(r.stderr, /usage: import-package-sets\.mjs/, drop);
  }
});
