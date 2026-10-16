// IOC recall over the bundled data (data/iocs): every package@version, workflow file name, runner name, endpoint,
// payload name, repository pattern and branch that ships is synthesised into the artifact wormsign reads, and every
// one must be reported. Hash IOCs cannot be tested this way: that needs the malware itself (see docs/validation.md).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cpSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadIocDir } from "../src/iocs.js";
import type { Finding } from "../src/types.js";
import { BUNDLED_IOCS, cli, fakeGitHub, tempTree } from "./validation-helpers.js";

const IOCS = loadIocDir(BUNDLED_IOCS);
const USE_BUNDLED = ["--iocs", BUNDLED_IOCS];
const keys = (findings: Finding[], ruleId: string) => new Set(findings.filter((f) => f.ruleId === ruleId).map((f) => f.key));
const missingFrom = (got: Set<string>, want: Iterable<string>) => [...want].filter((k) => !got.has(k));
const report = (what: string, found: number, total: number) => console.log(`recall: ${what}: ${found}/${total}`);

/* ---------- lockfiles: every package@version in five lockfile formats ---------- */

/** name -> versions, in data order, over every package set (sets overlap, so versions are deduplicated). */
const VERSIONS = new Map<string, string[]>();
for (const s of IOCS.packageSets) {
  for (const [name, vs] of Object.entries(s.packages)) VERSIONS.set(name, [...new Set([...(VERSIONS.get(name) ?? []), ...vs])]);
}
const EXPECTED = [...VERSIONS].flatMap(([n, vs]) => vs.map((v) => `${n}@${v}`));
/** wave -> name@version, so the recall report can be read per wave (a version two sets list counts once). */
const BY_WAVE = new Map<string, Set<string>>();
for (const s of IOCS.packageSets) {
  const ids = BY_WAVE.get(s.wave) ?? new Set<string>();
  for (const [name, vs] of Object.entries(s.packages)) for (const v of vs) ids.add(`${name}@${v}`);
  BY_WAVE.set(s.wave, ids);
}

const digest = (alg: string, s: string, enc: "base64" | "hex") => createHash(alg).update(`wormsign-recall ${s}`).digest(enc);
const integrity = (id: string) => `sha512-${digest("sha512", id, "base64")}`;
const unscoped = (name: string) => name.split("/").pop() as string;
const tarball = (host: string, name: string, v: string) => `https://${host}/${name}/-/${unscoped(name)}-${v}.tgz`;
/**
 * A lockfile can hold one version of a name per directory, so version k > 0 of a name is nested under (npm) or
 * depended on by (pnpm and yarn workspaces) holder package k, as a second dependent would be in a real tree.
 */
const holder = (k: number) => `wormsign-recall-holder-${k}`;
const layers = (): Map<string, string>[] => {
  const out: Map<string, string>[] = [];
  for (const [name, vs] of VERSIONS) vs.forEach((v, k) => (out[k] ??= new Map()).set(name, v));
  return out;
};
const sortKeys = <T>(o: Record<string, T>): Record<string, T> => Object.fromEntries(Object.entries(o).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));

/** npm lockfileVersion 3 (npm 7+), as in test/fixtures/lockfiles/npm. */
function npmV3(): string {
  const entry = (name: string, v: string) => ({ version: v, resolved: tarball("registry.npmjs.org", name, v), integrity: integrity(`${name}@${v}`) });
  const L = layers();
  const packages: Record<string, unknown> = {};
  L.forEach((layer, k) => {
    const prefix = k === 0 ? "" : `node_modules/${holder(k)}/`;
    if (k > 0) packages[`node_modules/${holder(k)}`] = { ...entry(holder(k), "1.0.0"), dependencies: Object.fromEntries(layer) };
    for (const [name, v] of layer) packages[`${prefix}node_modules/${name}`] = entry(name, v);
  });
  const deps = { ...Object.fromEntries(L[0] ?? []), ...Object.fromEntries(L.slice(1).map((_, i) => [holder(i + 1), "1.0.0"])) };
  return JSON.stringify({ name: "recall", version: "1.0.0", lockfileVersion: 3, requires: true, packages: { "": { name: "recall", version: "1.0.0", dependencies: sortKeys(deps) }, ...sortKeys(packages) } }, null, 2) + "\n";
}

/** npm lockfileVersion 1 (npm 5 and 6), as in test/fixtures/lockfiles/protocols/npm6: a nested `dependencies` tree. */
function npmV1(): string {
  const entry = (name: string, v: string) => ({ version: v, resolved: tarball("registry.npmjs.org", name, v), integrity: integrity(`${name}@${v}`) });
  const L = layers();
  const deps: Record<string, unknown> = Object.fromEntries([...(L[0] ?? [])].map(([n, v]) => [n, entry(n, v)]));
  L.slice(1).forEach((layer, i) => {
    const nested = Object.fromEntries([...layer].map(([n, v]) => [n, entry(n, v)]));
    deps[holder(i + 1)] = { ...entry(holder(i + 1), "1.0.0"), requires: Object.fromEntries(layer), dependencies: sortKeys(nested) };
  });
  return JSON.stringify({ name: "recall", version: "1.0.0", lockfileVersion: 1, requires: true, dependencies: sortKeys(deps) }, null, 2) + "\n";
}

/** pnpm lockfile v9 (pnpm 9 to 11), as in test/fixtures/lockfiles/pnpm. Keys starting with "@" are quoted, as there. */
function pnpmV9(): string {
  const q = (s: string) => (s.startsWith("@") ? `'${s}'` : s);
  const L = layers();
  const out = ["lockfileVersion: '9.0'", "", "settings:", "  autoInstallPeers: true", "  excludeLinksFromLockfile: false", "", "importers:", ""];
  L.forEach((layer, k) => {
    out.push(`  ${k === 0 ? "." : `holders/${holder(k)}`}:`, "    dependencies:");
    for (const [n, v] of [...layer].sort()) out.push(`      ${q(n)}:`, `        specifier: ${v}`, `        version: ${v}`);
    out.push("");
  });
  const ids = [...EXPECTED].sort();
  out.push("packages:", "");
  for (const id of ids) out.push(`  ${q(id)}:`, `    resolution: {integrity: ${integrity(id)}}`, "");
  out.push("snapshots:", "");
  for (const id of ids) out.push(`  ${q(id)}: {}`, "");
  return out.join("\n");
}

/** yarn.lock v1 (Yarn Classic), as in test/fixtures/lockfiles/yarn1. Keys are quoted by yarn 1.22.22's shouldWrapKey. */
function yarnClassic(): string {
  const wrap = (s: string) => (/^(true|false)/.test(s) || /[:\s\\",[\]]/.test(s) || /^[0-9]/.test(s) || !/^[a-zA-Z]/.test(s) ? JSON.stringify(s) : s);
  const blocks = EXPECTED.map((id) => {
    const at = id.lastIndexOf("@");
    const [name, v] = [id.slice(0, at), id.slice(at + 1)];
    return [`${wrap(id)}:`, `  version "${v}"`, `  resolved "${tarball("registry.yarnpkg.com", name, v)}#${digest("sha1", id, "hex")}"`, `  integrity ${integrity(id)}`].join("\n");
  });
  return ["# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.", "# yarn lockfile v1", "", "", blocks.sort().join("\n\n"), ""].join("\n");
}

/** yarn.lock from Yarn 2+ (lockfile version 8, Yarn 4), as in test/fixtures/lockfiles/berry. */
function yarnBerry(): string {
  const q = (s: string) => (s.startsWith("@") ? `"${s}"` : s);
  const L = layers();
  const blocks = EXPECTED.map((id) => {
    const at = id.lastIndexOf("@");
    const locator = `${id.slice(0, at)}@npm:${id.slice(at + 1)}`;
    return [`"${locator}":`, `  version: ${id.slice(at + 1)}`, `  resolution: "${locator}"`, `  checksum: 10c0/${digest("sha512", id, "hex")}`, "  languageName: node", "  linkType: hard"].join("\n");
  });
  L.forEach((layer, k) => {
    const ws = k === 0 ? "recall@workspace:." : `${holder(k)}@workspace:holders/${holder(k)}`;
    const deps = [...layer].sort().map(([n, v]) => `    ${q(n)}: "npm:${v}"`);
    blocks.push([`"${ws}":`, "  version: 0.0.0-use.local", `  resolution: "${ws}"`, "  dependencies:", ...deps, "  languageName: unknown", "  linkType: soft"].join("\n"));
  });
  const head = ['# This file is generated by running "yarn install" inside your project.', "# Manual changes might be lost - proceed with caution!", "", "__metadata:", "  version: 8", "  cacheKey: 10c0", ""];
  return [...head, blocks.sort().join("\n\n"), ""].join("\n");
}

const FORMATS: [string, string, () => string][] = [
  ["npm lockfile v3", "package-lock.json", npmV3],
  ["npm lockfile v1", "package-lock.json", npmV1],
  ["pnpm lockfile v9", "pnpm-lock.yaml", pnpmV9],
  ["yarn classic (v1)", "yarn.lock", yarnClassic],
  ["yarn berry (v8)", "yarn.lock", yarnBerry],
];

for (const [label, file, build] of FORMATS) {
  test(`recall: every bundled package@version is WS-LK-001 in a ${label}`, async () => {
    const res = await cli(["scan", tempTree({ [file]: build() }), ...USE_BUNDLED]);
    const flagged = keys(res.findings, "WS-LK-001");
    const missed = missingFrom(flagged, EXPECTED);
    report(`package versions, ${label}`, EXPECTED.length - missed.length, EXPECTED.length);
    for (const [wave, ids] of [...BY_WAVE].sort()) report(`package versions, wave ${wave}, ${label}`, [...ids].filter((k) => flagged.has(k)).length, ids.size);
    assert.ok(EXPECTED.length > 3000, `the bundled data should hold every vendor set (got ${EXPECTED.length} versions)`);
    assert.deepEqual(missed.slice(0, 20), [], `${missed.length} IOC versions not flagged in a ${label}`);
    assert.equal(res.findings.filter((f) => f.ruleId === "WS-SC-900").length, 0, "the synthesised lockfile must parse");
  });
}

/* ---------- workflows, runners, endpoints and payload names, as scan sees them ---------- */

const MINIMAL_WORKFLOW = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo inert\n";

test("recall: every bundled workflow file name is WS-GH-001", async () => {
  const names = IOCS.workflowFiles.map((w) => w.name);
  const res = await cli(["scan", tempTree(Object.fromEntries(names.map((n) => [`.github/workflows/${n}`, MINIMAL_WORKFLOW]))), ...USE_BUNDLED]);
  const missed = missingFrom(keys(res.findings, "WS-GH-001"), names);
  report("workflow file names (scan)", names.length - missed.length, names.length);
  assert.deepEqual(missed, []);
});

test("recall: every bundled runner name is WS-GH-006, as a runs-on target and as a registration", async () => {
  const names = IOCS.runnerNames.map((r) => r.name);
  const jobs = names.map((n, i) => `  j${i}:\n    runs-on: ${n}\n    steps:\n      - run: ./config.sh --url https://github.com/o/r --unattended --token t --name "${n}"\n`);
  const res = await cli(["scan", tempTree({ ".github/workflows/runners.yml": `on: push\njobs:\n${jobs.join("")}` }), ...USE_BUNDLED]);
  const got = keys(res.findings, "WS-GH-006");
  const want = names.flatMap((n, i) => [`runner:j${i}:${n}`, `runner-register:${n}`]);
  const missed = missingFrom(got, want);
  report("runner names (scan: runs-on and --name)", want.length - missed.length, want.length);
  assert.deepEqual(missed, []);
});

test("recall: every bundled endpoint is WS-EX-002 once refanged, and the defanged data file never matches itself", async () => {
  const raw = (JSON.parse(readFileSync(join(BUNDLED_IOCS, "endpoints.json"), "utf8")) as { endpoints: { substring: string }[] }).endpoints;
  assert.ok(raw.every((e) => e.substring.includes("[.]")), "endpoints.json stores every endpoint defanged");
  const seen = IOCS.endpoints.map((e) => e.substring);
  assert.ok(seen.every((s) => !s.includes("[.]")), "the loader refangs every endpoint");
  const code = seen.map((s, i) => `const e${i} = "https://${s}";\n`).join("");
  const res = await cli(["scan", tempTree({ "src/exfil.js": code }), ...USE_BUNDLED]);
  const missed = missingFrom(keys(res.findings, "WS-EX-002"), seen);
  report("endpoints (scan, refanged)", seen.length - missed.length, seen.length);
  assert.deepEqual(missed, []);
  // Negative control: wormsign's own IOC data, installed in a project, must not report its endpoints.
  const copy = mkdtempSync(join(tmpdir(), "wormsign-validation-"));
  cpSync(BUNDLED_IOCS, join(copy, "iocs"), { recursive: true });
  const self = await cli(["scan", copy, ...USE_BUNDLED]);
  assert.deepEqual([...keys(self.findings, "WS-EX-002")], []);
});

test("recall: every bundled payload name is WS-LC-003 when an install script runs it, and WS-FS-002 when its name alone is reportable", async () => {
  const names = IOCS.names;
  const files: Record<string, string> = {};
  names.forEach((n, i) => {
    files[`pkg${i}/package.json`] = JSON.stringify({ name: `pkg${i}`, version: "1.0.0", scripts: { postinstall: `node ${n.name}` } });
    files[`pkg${i}/${n.name}`] = "// inert marker, not a sample\n";
  });
  const res = await cli(["scan", tempTree(files), ...USE_BUNDLED]);
  // A WS-LC-003 key ends with a hash of the command: the script name and payload name come before it.
  const ran = missingFrom(new Set([...keys(res.findings, "WS-LC-003")].map((k) => k.replace(/:[0-9a-f]{32}$/, ""))), names.map((n) => `postinstall:${n.name}`));
  const reportable = names.filter((n) => n.nameOnlySeverity !== "info").map((n) => n.name);
  const named = missingFrom(keys(res.findings, "WS-FS-002"), reportable);
  report("payload names run by an install script (WS-LC-003)", names.length - ran.length, names.length);
  report("payload names reported by name alone (WS-FS-002; info-severity names excluded by design)", reportable.length - named.length, reportable.length);
  report(`hash IOCs (not testable without the malware samples; ${IOCS.hashes.filter((h) => /^\(.*\)$/.test(h.name)).length} have no file name)`, 0, IOCS.hashes.length);
  assert.deepEqual(ran, []);
  assert.deepEqual(named, []);
});

/* ---------- repository patterns, branches, workflows and runners, as audit-org sees them ---------- */

/** A repository that matches pattern p, as the worm creates it. Throws for a pattern kind this file cannot synthesise. */
function repoFor(p: (typeof IOCS.repoPatterns)[number]): { name: string; description?: string } {
  switch (p.match) {
    case "nameExact":
      return { name: p.name as string };
    case "nameContains":
      return { name: `x-${p.name}-y` };
    case "descriptionExact":
      return { name: `recall-${p.id}`, description: p.description as string };
    case "descriptionContains":
      return { name: `recall-${p.id}`, description: `prefix ${p.description} suffix` };
    default:
      throw new Error(`repos.json pattern ${p.id} uses ${p.match}, which this recall test cannot synthesise yet: add a case`);
  }
}

test("recall: every bundled repository pattern, branch, workflow name and runner name is reported by audit-org", async () => {
  const patterns = IOCS.repoPatterns;
  const branches = IOCS.branches.map((b) => (b.name.endsWith("*") ? `${b.name.slice(0, -1)}x` : b.name));
  const repos = [...patterns.map(repoFor), { name: "recall-artifacts" }, { name: "control", description: "an ordinary repository" }];
  const res = await cli(["audit-org", "acme", ...USE_BUNDLED], {
    env: { GITHUB_TOKEN: "test-token" },
    fetchImpl: fakeGitHub("acme", {
      repos,
      workflows: { "recall-artifacts": IOCS.workflowFiles.map((w) => w.name) },
      branches: { "recall-artifacts": branches },
      repoRunners: { "recall-artifacts": IOCS.runnerNames.map((r) => r.name) },
      auditLog: {},
    }),
  });
  assert.equal(res.code, 1, "the audit completed (exit 2 would mean a check never answered)");
  const or1 = missingFrom(keys(res.findings, "WS-OR-001"), patterns.map((p) => `acme/${repoFor(p).name}:${p.id}`));
  const or4 = missingFrom(keys(res.findings, "WS-OR-004"), [...IOCS.workflowFiles.map((w) => `acme/recall-artifacts:${w.name}`), ...branches.map((b) => `acme/recall-artifacts:branch:${b}`)]);
  const critical = new Set(res.findings.filter((f) => f.ruleId === "WS-OR-003" && f.severity === "critical").map((f) => f.key));
  const or3 = missingFrom(critical, IOCS.runnerNames.map((r) => `runner:${r.name}`));
  report("repository patterns (audit-org)", patterns.length - or1.length, patterns.length);
  report("workflow names and branches (audit-org)", IOCS.workflowFiles.length + branches.length - or4.length, IOCS.workflowFiles.length + branches.length);
  report("runner names (audit-org, critical)", IOCS.runnerNames.length - or3.length, IOCS.runnerNames.length);
  assert.deepEqual([or1, or4, or3], [[], [], []]);
  assert.ok(!res.findings.some((f) => f.ruleId === "WS-OR-001" && f.file === "acme/control"), "negative control: an ordinary repository is not reported");
});
