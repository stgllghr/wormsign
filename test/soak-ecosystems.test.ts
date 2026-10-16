/**
 * The soak seams another ecosystem plugs into: runOsv checks one ecosystem and touches only that ecosystem's evidence,
 * evidence sorts by name, version, then ecosystem, and a tree with only Python inputs gets no "no package manager"
 * finding. npm output through these seams is pinned by test/golden-npm-identical.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { compareEvidence, runOsv } from "../src/soak.js";
import { checkSoakConfig } from "../src/soak-config.js";
import { newOsvSession } from "../src/osv.js";
import type { OsvRun, SoakEvidence } from "../src/soak.js";
import type { ConfigOptions } from "../src/soak-config.js";
import { parseLockfileText } from "../src/lockfile/index.js";

/** Fake api.osv.dev over records keyed "<ecosystem>:<name>@<version>"; records each query as "<ecosystem> <name>@<version>". */
function osv(records: Record<string, string[]>) {
  const asked: string[] = [];
  const fetchImpl = (async (_url: string | URL, init?: RequestInit) => {
    const { queries } = JSON.parse(String(init?.body)) as { queries: { package: { name: string; ecosystem: string }; version: string }[] };
    const results = queries.map((q) => {
      asked.push(`${q.package.ecosystem} ${q.package.name}@${q.version}`);
      const ids = records[`${q.package.ecosystem}:${q.package.name}@${q.version}`] ?? [];
      return ids.length > 0 ? { vulns: ids.map((id) => ({ id, modified: "2026-01-01T00:00:00Z" })) } : {};
    });
    return new Response(JSON.stringify({ results }));
  }) as typeof fetch;
  return { fetchImpl, asked };
}

const NPM: Omit<OsvRun, "sent" | "evidence" | "notes" | "skipped"> = { ecosystem: "npm", index: "https://registry.npmjs.org", flag: "--registry", publicHost: ["registry.npmjs.org", "registry.yarnpkg.com"], label: "the public npm registry" };
const PYPI: Omit<OsvRun, "sent" | "evidence" | "notes" | "skipped"> = { ecosystem: "PyPI", index: "https://pypi.org/simple/", flag: "--pypi-index", publicHost: ["pypi.org"], label: "the public PyPI index" };

test("soak runOsv: the same name@version in npm and PyPI; each run answers only its own ecosystem's evidence, npm keys unchanged", async () => {
  const db = osv({ "npm:shared@1.0.0": ["MAL-2099-10"], "PyPI:shared@1.0.0": ["MAL-2099-20"] });
  const evidence: SoakEvidence[] = [
    { name: "shared", version: "1.0.0", ecosystem: "npm", status: "ok" },
    { name: "shared", version: "1.0.0", ecosystem: "PyPI", status: "ok" },
  ];
  const npmNotes: string[] = [];
  const npm = await runOsv({ ...NPM, sent: [{ name: "shared", version: "1.0.0", file: "package-lock.json" }], skipped: [], evidence, notes: npmNotes, fetchImpl: db.fetchImpl });
  assert.deepEqual(npm.map((f) => `${f.ruleId} ${f.file} ${f.key}`), ["WS-OS-001 package-lock.json shared@1.0.0 MAL-2099-10"]);
  assert.deepEqual(evidence.map((e) => e.osv), [["MAL-2099-10"], undefined], "the PyPI entry is not answered by the npm run");
  assert.deepEqual(npmNotes, ["1 package version(s) checked against OSV for malicious-package records"]);

  const npmEntry = structuredClone(evidence[0]);
  const pyNotes: string[] = [];
  const py = await runOsv({ ...PYPI, sent: [{ name: "shared", version: "1.0.0", file: "uv.lock" }], skipped: ["2 not sent to OSV (a test reason)"], evidence, notes: pyNotes, fetchImpl: db.fetchImpl });
  assert.deepEqual(py.map((f) => `${f.ruleId} ${f.file} ${f.key}`), ["WS-OS-001 uv.lock pypi:shared@1.0.0 MAL-2099-20"]);
  assert.deepEqual(evidence[0], npmEntry, "the PyPI run leaves npm evidence as it was");
  assert.deepEqual(evidence[1]?.osv, ["MAL-2099-20"]);
  assert.deepEqual(pyNotes, ["1 package version(s) checked against OSV for malicious-package records; 2 not sent to OSV (a test reason)"]);
  assert.deepEqual(db.asked, ["npm shared@1.0.0", "PyPI shared@1.0.0"]);

  // The npm run's answer does not depend on a PyPI entry being present.
  const alone: SoakEvidence[] = [{ name: "shared", version: "1.0.0", ecosystem: "npm", status: "ok" }];
  const again = await runOsv({ ...NPM, sent: [{ name: "shared", version: "1.0.0", file: "package-lock.json" }], skipped: [], evidence: alone, notes: [], fetchImpl: osv({ "npm:shared@1.0.0": ["MAL-2099-10"] }).fetchImpl });
  assert.deepEqual(again, npm);
  assert.deepEqual(alone[0], npmEntry);
});

test("soak runOsv: an index that is not public sends nothing and fails closed, with npm's message and key as before", async () => {
  const db = osv({});
  const sent = [{ name: "a", version: "1.0.0", file: "package-lock.json" }, { name: "b", version: "1.0.0", file: "package-lock.json" }];
  const evidence: SoakEvidence[] = [{ name: "a", version: "1.0.0", ecosystem: "npm", status: "ok" }];
  const npm = await runOsv({ ...NPM, index: "https://npm.corp.example", sent, skipped: [], evidence, notes: [], fetchImpl: db.fetchImpl });
  assert.deepEqual(npm.map((f) => [f.ruleId, f.severity, f.key, f.message]), [
    ["WS-OS-900", "high", "registry https://npm.corp.example", "2 package version(s) were not checked against OSV: --registry https://npm.corp.example is not the public npm registry, so their names are not sent to api.osv.dev. Pass --no-osv to run without this check"],
  ]);
  const py = await runOsv({ ...PYPI, index: "https://pypi.corp.example/simple/", sent, skipped: [], evidence, notes: [], fetchImpl: db.fetchImpl });
  assert.deepEqual(py.map((f) => [f.key, f.message]), [["pypi:registry https://pypi.corp.example/simple/", "2 package version(s) were not checked against OSV: --pypi-index https://pypi.corp.example/simple/ is not the public PyPI index, so their names are not sent to api.osv.dev. Pass --no-osv to run without this check"]]);
  assert.deepEqual(db.asked, [], "no name left the machine");
  assert.equal(evidence[0]?.osv, undefined, "not checked is not shown as clean");

  const notes: string[] = [];
  assert.deepEqual(await runOsv({ ...PYPI, sent: [], skipped: ["3 not sent to OSV (a test reason)"], evidence, notes, fetchImpl: db.fetchImpl }), []);
  assert.deepEqual(notes, ["0 package version(s) checked against OSV; 3 not sent to OSV (a test reason)"], "nothing asked is still said");
});

test("soak runOsv: a note label tells two ecosystems' coverage notes apart; a run's shared session changes no npm output", async () => {
  const db = osv({ "npm:shared@1.0.0": ["MAL-2099-10"], "PyPI:shared@1.0.0": ["MAL-2099-20"] });
  const session = newOsvSession();
  const evidence: SoakEvidence[] = [
    { name: "shared", version: "1.0.0", ecosystem: "npm", status: "ok" },
    { name: "shared", version: "1.0.0", ecosystem: "PyPI", status: "ok" },
  ];
  const notes: string[] = [];
  const sent = (file: string) => [{ name: "shared", version: "1.0.0", file }];
  const npm = await runOsv({ ...NPM, sent: sent("package-lock.json"), skipped: [], evidence, notes, session, fetchImpl: db.fetchImpl });
  const py = await runOsv({ ...PYPI, noteLabel: "PyPI", sent: sent("uv.lock"), skipped: ["1 not sent to OSV (a test reason)"], evidence, notes, session, fetchImpl: db.fetchImpl });
  await runOsv({ ...PYPI, noteLabel: "PyPI", sent: [], skipped: ["2 not sent to OSV (a test reason)"], evidence, notes, session, fetchImpl: db.fetchImpl });
  assert.deepEqual(notes, [
    "1 package version(s) checked against OSV for malicious-package records",
    "1 package version(s) checked against OSV for malicious-package records (PyPI); 1 not sent to OSV (a test reason)",
    "0 package version(s) checked against OSV (PyPI); 2 not sent to OSV (a test reason)",
  ]);
  assert.deepEqual(py.map((f) => f.key), ["pypi:shared@1.0.0 MAL-2099-20"]);

  // The npm call without a session: the same findings, evidence and note.
  const alone: SoakEvidence[] = [{ name: "shared", version: "1.0.0", ecosystem: "npm", status: "ok" }];
  const aloneNotes: string[] = [];
  assert.deepEqual(await runOsv({ ...NPM, sent: sent("package-lock.json"), skipped: [], evidence: alone, notes: aloneNotes, fetchImpl: osv({ "npm:shared@1.0.0": ["MAL-2099-10"] }).fetchImpl }), npm);
  assert.deepEqual(alone[0], evidence[0]);
  assert.deepEqual(aloneNotes, [notes[0]]);
});

test("soak runOsv: an unchecked id with a blank does not hide the answered versions it names (npm differs from main here)", async () => {
  // A version "1.0.0 a@1.0.0" comes from a percent-encoded tarball URL (registryTarball decodes it). main split the
  // WS-OS-900 key on blanks, so a@1.0.0 also read as unanswered; runOsv reads checkOsvDetailed's unchecked list as is.
  const db = osv({});
  const evidence: SoakEvidence[] = [
    { name: "a", version: "1.0.0", ecosystem: "npm", status: "ok" },
    { name: "b", version: "1.0.0 a@1.0.0", ecosystem: "npm", status: "ok" },
  ];
  const notes: string[] = [];
  const sent = [{ name: "a", version: "1.0.0", file: "package-lock.json" }, { name: "b", version: "1.0.0 a@1.0.0", file: "package-lock.json" }];
  const found = await runOsv({ ...NPM, sent, skipped: [], evidence, notes, fetchImpl: db.fetchImpl });
  assert.deepEqual(found.map((f) => `${f.ruleId} ${f.key}`), ["WS-OS-900 b@1.0.0 a@1.0.0"], "the unchecked version still fails closed");
  assert.deepEqual(db.asked, ["npm a@1.0.0"]);
  assert.deepEqual(evidence.map((e) => e.osv), [[], undefined], "a@1.0.0 was answered; b's version was not sent");
  assert.deepEqual(notes, ["1 package version(s) checked against OSV for malicious-package records"]);
});

test("soak evidence: sorted by name, then version, then ecosystem", () => {
  const e = (name: string, version: string, ecosystem: SoakEvidence["ecosystem"]): SoakEvidence => ({ name, version, ecosystem, status: "ok" });
  const list = [e("b", "1.0.0", "npm"), e("a", "2.0.0", "PyPI"), e("a", "2.0.0", "npm"), e("a", "1.0.0", "PyPI")];
  assert.deepEqual(list.sort(compareEvidence).map((x) => `${x.name}@${x.version} ${x.ecosystem}`), ["a@1.0.0 PyPI", "a@2.0.0 npm", "a@2.0.0 PyPI", "b@1.0.0 npm"]);
});

test("soak config: a tree with only Python inputs gets no no-package-manager finding; any npm input keeps it", () => {
  const d = mkdtempSync(join(tmpdir(), "ws-eco-"));
  const base = { minAgeMs: 7 * 86_400_000, versionOf: () => ({ version: "99.0.0", source: "stub" }) };
  const keys = (o: ConfigOptions) => checkSoakConfig(d, [], o).map((f) => `${f.ruleId} ${f.severity} ${f.key}`);
  assert.deepEqual(keys(base), ["WS-SK-003 medium no-package-manager"], "positive control: nothing found at all");
  assert.deepEqual(keys({ ...base, pythonInputs: true, npmInputs: false }), []);
  assert.deepEqual(keys({ ...base, pythonInputs: true, npmInputs: true }), ["WS-SK-003 medium no-package-manager"], "an npm input whose lockfile was not read");
  assert.deepEqual(keys({ ...base, npmInputs: true }), ["WS-SK-003 medium no-package-manager"]);
  assert.deepEqual(keys({ ...base, pythonInputs: false }), ["WS-SK-003 medium no-package-manager"]);
  // pythonInputs: true without npmInputs does not compile; a caller past the types (or in JavaScript) keeps the finding.
  // @ts-expect-error npmInputs must be given with pythonInputs: true
  const omitted: ConfigOptions = { ...base, pythonInputs: true };
  assert.deepEqual(keys(omitted), ["WS-SK-003 medium no-package-manager"], "leaving npmInputs out keeps the finding");

  // With an npm lockfile, Python inputs change nothing (even with npmInputs: false): its settings are checked as before.
  const lock = parseLockfileText("package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: { "": {} } }));
  assert.ok(lock);
  const npm = (o: ConfigOptions) => checkSoakConfig(d, [lock], o).map((f) => `${f.ruleId} ${f.key}`);
  assert.deepEqual(npm({ ...base, pythonInputs: true, npmInputs: false }), npm(base));
  assert.deepEqual(npm(base), ["WS-SK-003 npm:min-release-age"]);
  writeFileSync(join(d, "bunfig.toml"), "[install]\nminimumReleaseAge = 604800\n");
  assert.deepEqual(keys(base), [], "a bunfig.toml names a package manager");
});
