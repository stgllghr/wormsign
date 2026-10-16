import { test } from "node:test";
import assert from "node:assert/strict";
import { toSarif } from "../src/sarif.js";
import { makeFinding, type Finding, type Severity } from "../src/types.js";
import { scanDirectory } from "../src/scan.js";
import { checkSoakConfig } from "../src/soak-config.js";
import { RULES } from "../src/rules.js";
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { fx, testCtx } from "./helpers.js";

// Checks against GitHub's SARIF contract:
// https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support

interface Rule {
  id: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string };
  properties: { tags: string[]; "security-severity"?: string };
}
interface Result {
  ruleId: string;
  locations: { physicalLocation: { artifactLocation: { uri: string }; region?: { startLine: number } } }[];
  partialFingerprints: Record<string, string>;
  properties: Record<string, unknown>;
}
const sarif = (findings: Finding[]) => (toSarif(findings, "x") as { runs: { tool: { driver: { rules: Rule[] } }; results: Result[] }[] }).runs[0]!;
const rule = (findings: Finding[], id: string) => sarif(findings).tool.driver.rules.find((r) => r.id === id)!;
const f = (ruleId: string, severity: Severity, extra: Partial<Finding> = {}) => makeFinding({ ruleId, severity, message: "m", file: "a.json", key: `${severity}`, ...extra });

test("sarif rules: every rule has the text fields GitHub marks required, within 1024 chars", () => {
  for (const r of sarif([]).tool.driver.rules) {
    for (const t of [r.shortDescription.text, r.fullDescription.text, r.help.text]) {
      assert.ok(t.trim().length > 0 && t.length <= 1024, `${r.id}: ${JSON.stringify(t)}`);
    }
    assert.ok(r.properties.tags.includes("security"), `${r.id} is not tagged security`);
  }
});

// driver.rules is built only from RULES, so a ruleId any command can emit (scan, diff, soak, audit-org) must be in it,
// and a rule nothing emits is stale. Read from the sources, since most emitters need a network or a git history.
// Only emitter shapes count: `ruleId: <expr>` (including `a ? "X" : "Y"`) and the local helpers finding("X") (soak-config.ts)
// and add("X") (workflows.ts), so an id that only a comparison such as `f.ruleId === "X"` mentions is not "emitted".
test("sarif rules: RULES matches the rule ids the sources emit", () => {
  const src = fileURLToPath(new URL("../../src/", import.meta.url));
  const emitted = new Set<string>();
  for (const p of readdirSync(src, { recursive: true }) as string[]) {
    if (!p.endsWith(".ts") || p === "rules.ts") continue;
    for (const m of readFileSync(join(src, p), "utf8").matchAll(/\bruleId: ([^,\n]*)|\b(?:finding|add)\(("WS-[A-Z]{2}-\d{3}")/g)) {
      for (const id of (m[1] ?? m[2]!).matchAll(/"(WS-[A-Z]{2}-\d{3})"/g)) emitted.add(id[1]!);
    }
  }
  for (const id of ["WS-DF-006", "WS-DF-001", "WS-OR-004", "WS-SC-900", "WS-SK-003", "WS-GH-002"]) {
    assert.ok(emitted.has(id), `positive control (every emitter shape) ${id}: ${[...emitted].join(", ")}`);
  }
  const known = new Set(RULES.map((r) => r.id));
  assert.deepEqual([...emitted].filter((id) => !known.has(id)), [], "emitted but missing from RULES");
  assert.deepEqual([...known].filter((id) => !emitted.has(id)), [], "in RULES but never emitted");
});

test("sarif rules: security-severity sits on the rule, scored by the worst finding of the run", () => {
  assert.equal(rule([f("WS-OR-003", "low"), f("WS-OR-003", "critical")], "WS-OR-003").properties["security-severity"], "9.5");
  assert.equal(rule([f("WS-OR-003", "low")], "WS-OR-003").properties["security-severity"], "3.0");
  assert.equal(rule([f("WS-LK-002", "medium"), f("WS-LK-002", "high")], "WS-LK-002").properties["security-severity"], "8.0");
  assert.equal(rule([f("WS-OR-900", "info")], "WS-OR-900").properties["security-severity"], undefined, "info is not a security result");
  assert.equal(rule([], "WS-LK-001").properties["security-severity"], undefined, "nothing reported, nothing to score");
  for (const r of sarif([f("WS-LK-001", "critical")]).results) assert.equal(r.properties["security-severity"], undefined, "GitHub ignores it on results");
});

test("sarif rules: each score falls in the GitHub band named like the wormsign severity", () => {
  // GitHub: over 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low.
  const band = (s: number) => (s > 9 ? "critical" : s >= 7 ? "high" : s >= 4 ? "medium" : s >= 0.1 ? "low" : "none");
  for (const sev of ["critical", "high", "medium", "low"] as const) {
    assert.equal(band(Number(rule([f("WS-LK-002", sev)], "WS-LK-002").properties["security-severity"])), sev);
  }
});

test("sarif results: whole-file results carry a primaryLocationLineHash, line results leave it to upload-sarif", () => {
  const res = scanDirectory(fx("malicious"), testCtx(), { nodeModules: false });
  const results = sarif(res.findings).results;
  const lineless = results.filter((r) => !r.locations[0]?.physicalLocation.region);
  assert.ok(lineless.length >= 3, "fixture has several whole-file results (lockfile hits)");
  for (const r of lineless) assert.equal(r.partialFingerprints["primaryLocationLineHash"], `${r.partialFingerprints["wormsign/v1"]}:1`);
  assert.equal(new Set(lineless.map((r) => r.partialFingerprints["primaryLocationLineHash"])).size, lineless.length, "each result keeps its own identity");
  // upload-sarif warns when a supplied hash differs from the one it computes, so don't supply one there.
  for (const r of results.filter((x) => x.locations[0]?.physicalLocation.region)) assert.equal(r.partialFingerprints["primaryLocationLineHash"], undefined);
});

test("sarif results: artifact URIs are valid URI references that decode back to the path", () => {
  const paths = ["node_modules/@scope/pkg/package.json", "dir with space/a#b?c%41.js", `x/${String.fromCharCode(0x1b)}[2K.js`, "evil:dir/package.json"];
  const results = sarif(paths.map((p) => f("WS-FS-002", "medium", { file: p, key: p }))).results;
  for (const p of paths) {
    const uri = results.find((r) => decodeURIComponent(r.locations[0]!.physicalLocation.artifactLocation.uri) === p)?.locations[0]?.physicalLocation.artifactLocation.uri;
    assert.ok(uri, `no result decodes to ${JSON.stringify(p)}`);
    assert.match(uri, /^([A-Za-z0-9._~!$&'()*+,;=:@/-]|%[0-9A-F]{2})+$/, `not RFC 3986 path characters: ${uri}`);
    // A colon before the first "/" would make this an absolute URI with a scheme (RFC 3986 section 4.2).
    assert.doesNotMatch(uri, /^[A-Za-z][A-Za-z0-9+.-]*:/, `parses as a URI with a scheme: ${uri}`);
  }
  assert.ok(results.some((r) => r.locations[0]?.physicalLocation.artifactLocation.uri === "node_modules/@scope/pkg/package.json"), "ordinary paths are left readable");
});

// GitHub shows a rule's help on every alert of that rule, so it must hold for every message variant the
// rule is emitted with, not just the common one.
test("sarif rules: soak help text fits every variant the soak check emits", () => {
  const H = 3_600_000;
  const proj = (files: Record<string, string>) => {
    const d = mkdtempSync(join(tmpdir(), "ws-help-"));
    for (const [k, v] of Object.entries(files)) writeFileSync(join(d, k), v);
    return d;
  };
  const help = (id: string) => rule([], id).help.text;
  const variants: [string, Finding | undefined, RegExp][] = [
    ["yarn classic: no setting exists", checkSoakConfig(proj({}), [{ kind: "yarn-classic", file: "yarn.lock", packages: [] }], { minAgeMs: 72 * H, versionOf: () => ({ version: "99.0.0", source: "stub" }) })[0], /wormsign soak/],
    // Yarn 4.10 typed the setting as a number, so "7d" became 7; 4.11 made it a duration in minutes
    // (yarnpkg/berry plugin-npm/sources/index.ts at @yarnpkg/cli/4.10.3 vs 4.11.0). Plain minutes work on both,
    // and the help must not present the 4.10 behaviour as true of every Yarn.
    ["yarn 4.10: 7d is read as 7 minutes", checkSoakConfig(proj({ ".yarnrc.yml": 'npmMinimalAgeGate: "7d"\n' }), [{ kind: "yarn-berry", file: "yarn.lock", packages: [] }], { minAgeMs: 72 * H, versionOf: () => ({ version: "99.0.0", source: "stub" }) })[0], /plain minutes: Yarn 4\.10 [^.]*, while 4\.11 and later accept suffixes/],
  ];
  for (const [what, finding, remedy] of variants) {
    assert.ok(finding, `${what}: no finding emitted`);
    assert.match(help(finding.ruleId), remedy, `${what}: ${finding.ruleId} help does not give the remedy`);
  }
});
