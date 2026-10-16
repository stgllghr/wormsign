/*
 * Hand-edited copies of real lockfiles (test/fixtures/lockfiles/protocols) that a package
 * manager still installs from. Each edit must either be reported or make the parser throw;
 * none may parse to a clean result.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseLockfileText } from "../src/lockfile/index.js";
import type { ParsedLockfile } from "../src/lockfile/index.js";
import { checkLockfile } from "../src/checks/lockfile.js";
import { indexPackages } from "../src/iocs.js";
import { fx, testCtx } from "./helpers.js";

const real = (dir: string, file: string): string => readFileSync(fx("lockfiles", "protocols", dir, file), "utf8");
const pnpm = (text: string): ParsedLockfile => parseLockfileText("pnpm-lock.yaml", text) as ParsedLockfile;
const edit = (text: string, from: string | RegExp, to: string): string => {
  const out = text.replace(from, to);
  assert.notEqual(out, text, `edit did not apply: ${from}`);
  return out;
};
const findings = (l: ParsedLockfile, packages: Record<string, string[]> = {}): string[] => {
  const ctx = testCtx();
  ctx.pkgIndex = indexPackages([{ id: "t", wave: "t", source: "https://example.test/ioc", packages }]);
  // The artifact part of a WS-LK-002/003 key (resolved, integrity) is left out: these tests are about name@version.
  return checkLockfile(l, ctx).map((f) => `${f.ruleId} ${f.severity} ${f.key.split(" ")[0]}`);
};

const NODE_ARM64 = "https://nodejs.org/download/release/v22.11.0/node-v22.11.0-darwin-arm64.tar.gz";

test("pnpm runtime: a binary downloaded from anywhere but the runtime's release site is high", () => {
  const raw = real("pnpm11-runtime", "pnpm-lock.yaml");
  const bun = real("pnpm11-runtime-bun", "pnpm-lock.yaml");
  const bunUrl = /https:\/\/github\.com\/oven-sh\/bun\/releases\/download\/bun-v1\.1\.38\/bun-darwin-aarch64\.zip/;
  const cases: [string, string][] = [
    ["plain http, other host", edit(raw, NODE_ARM64, "http://127.0.0.1:8765/evil.tar.gz")],
    ["https, other host", edit(raw, NODE_ARM64, "https://evil.example/node.tar.gz")],
    ["another runtime's release site", edit(raw, NODE_ARM64, "https://github.com/oven-sh/bun/releases/download/bun-v1.1.38/bun-darwin-aarch64.zip")],
    ["`..` out of the release path", edit(bun, bunUrl, "https://github.com/oven-sh/bun/releases/download/../../../../evil/x/releases/download/a.zip")],
  ];
  for (const [why, text] of cases) {
    const id = why === "`..` out of the release path" ? "bun@runtime:1.1.38" : "node@runtime:22.11.0";
    assert.deepEqual(findings(pnpm(text)), [`WS-LK-002 high ${id}`], why);
  }
});

test("pnpm runtime: download URLs that cannot be read throw instead of being skipped", () => {
  const raw = real("pnpm11-runtime", "pnpm-lock.yaml");
  const variant = /^ {12}url: https:\/\/nodejs\.org\/download\/release\/v22\.11\.0\/node-v22\.11\.0-darwin-arm64\.tar\.gz$/m;
  const unread: [string, string][] = [
    ["url removed", edit(raw, new RegExp(`${variant.source}\\n`, "m"), "")],
    ["quoted keys", edit(edit(raw, variant, '            "url": http://127.0.0.1/evil'), "            integrity: sha256-Lomv5vTjqmx+IcVg2KBFPYSAfpeFC7uBm5mFMaIr394=", '            "integrity": sha256-x')],
    ["anchored value", edit(raw, variant, `            url: &u ${NODE_ARM64}`)],
    ["tagged type", edit(raw, /^ {6}type: variations$/m, "      type: !!str variations")],
    ["flow-style binary", edit(raw, /^ {4}resolution:\n {6}type: variations\n(?: {6,}.*\n)+/m, `    resolution: {type: binary, url: ${NODE_ARM64}, integrity: sha256-x}\n`)],
  ];
  for (const [why, text] of unread) assert.throws(() => pnpm(text), Error, why);
});

const ISN = "sha512-41Cifkg6e8TylSpdtTpeLVMqvSBEVzTttHvERD741+pnZ8ANv0004MRL43QKPDlK9cGvNp6NZWZUBlbGXYxxng==";
const ODD = "sha512-CQpnWPrDwmP1+SMHXZhtLtJv90yiyVfluGsX5iNCVkrhQtU3TQHsUWPG9wkdk9Lgd5yNpAg9jQEo90CBaXgWMA==";
const ISN_TGZ = "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz";

/** pnpm11-tarball with every is-number@7.0.0 key renamed and its resolution replaced. */
const rekeyed = (version: string, resolution: string): string =>
  real("pnpm11-tarball", "pnpm-lock.yaml")
    .replaceAll("is-number@7.0.0", `is-number@${version}`)
    .replace(/^( {8}(?:specifier|version): )7\.0\.0$/gm, `$1${version}`)
    .replace(/^( {2}is-number@.*:\n {4}resolution: ).*$/m, `$1${resolution}`);

// pnpm 10 installs the tarball whatever the key says (checked with 10.18); pnpm 11.16 refuses the mismatch.
test("pnpm: a registry tarball that names another package is high, and both identities are IOC-checked", () => {
  const cases: [string, string, string, string][] = [
    ["key version edited", rekeyed("7.0.1", `{integrity: ${ISN}, tarball: ${ISN_TGZ}}`), "is-number@7.0.1", "is-number@7.0.0"],
    ["another package's tarball", rekeyed("7.0.0", `{integrity: ${ODD}, tarball: https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz}`), "is-number@7.0.0", "is-odd@3.0.1"],
    // a URL dependency on the registry host: the `version:` field is the manifest's, the tarball is the registry's
    ["URL dependency", edit(rekeyed(ISN_TGZ, `{integrity: ${ISN}, tarball: ${ISN_TGZ}}`), /^( {2}is-number@https:.*:\n {4}resolution: .*)$/m, "$1\n    version: 7.0.1"), "is-number@7.0.1", "is-number@7.0.0"],
  ];
  for (const [why, text, recorded, tarball] of cases) {
    const at = tarball.lastIndexOf("@");
    const want = [`WS-LK-001 critical ${recorded}`, `WS-LK-002 high ${recorded}`];
    assert.deepEqual(findings(pnpm(text), { [tarball.slice(0, at)]: [tarball.slice(at + 1)] }).filter((f) => f.endsWith(recorded)), want, why);
    if (tarball.startsWith("is-number")) continue;
    // npm installs by integrity from a warm cache, so the recorded identity is IOC-checked too
    assert.deepEqual(findings(pnpm(text), { "is-number": ["7.0.0"] }).filter((f) => f.endsWith(recorded)), want, why);
  }
  // a key that is not semver and no `version:` field: nothing names a version
  assert.throws(() => pnpm(rekeyed("7.0.0.0", `{integrity: ${ISN}, tarball: ${ISN_TGZ}}`)), /has no version/);
});

test("pnpm: `directory:` or `repo:` without its `type:` is still a registry entry (pnpm picks the fetcher by type)", () => {
  const raw = real("pnpm11", "pnpm-lock.yaml");
  const isn = /^( {2}is-number@7\.0\.0:\n {4}resolution: \{integrity: [^,}]*)\}$/m;
  for (const field of ["directory: libs", "repo: https://github.com/jonschlinkert/is-number"]) {
    const text = edit(raw, isn, `$1, ${field}}`);
    assert.ok(findings(pnpm(text), { "is-number": ["7.0.0"] }).includes("WS-LK-001 critical is-number@7.0.0"), field);
  }
  assert.throws(() => pnpm(edit(raw, isn, "$1, type: custom}")), /unsupported resolution type/);
});

// pnpm 11.16 installs a `type: git` entry with an unreachable `tarball:` added, offline, from a fresh store: it clones `repo`.
test("pnpm: a `tarball:` beside `type: git` or `type: directory` is not the source (pnpm picks the fetcher by type)", () => {
  const raw = real("pnpm11", "pnpm-lock.yaml");
  const isn = /^( {2}is-number@7\.0\.0:\n {4}resolution: ).*$/m;
  const git = pnpm(edit(raw, isn, `$1{commit: ${"a".repeat(40)}, repo: https://github.com/attacker/evil.git, tarball: ${ISN_TGZ}, type: git}\n    version: 7.0.0`));
  assert.equal(git.packages.find((p) => p.name === "is-number")?.resolved, "git+https://github.com/attacker/evil.git");
  assert.ok(findings(git).includes("WS-LK-002 medium is-number@7.0.0"));
  const dir = pnpm(edit(raw, isn, `$1{directory: libs/x, tarball: ${ISN_TGZ}, type: directory}\n    version: 7.0.0`));
  assert.deepEqual(dir.packages.find((p) => p.name === "is-number"), { name: "is-number", version: "7.0.0", local: true });
});

test("pnpm: a plain value keeps inner spaces, but a comment, a nested key or a trailing space throws", () => {
  const raw = real("pnpm11-local", "pnpm-lock.yaml");
  for (const v of ["dir with space/lib #x", "dir: with space/lib", "dir with space/lib "]) {
    assert.throws(() => pnpm(edit(raw, "{directory: dir with space/lib,", `{directory: ${v},`)), /unsupported YAML value/, JSON.stringify(v));
  }
});

test("pnpm: a `name:` or `version:` field that differs from a registry key throws (pnpm 10 and 11 install the field's version)", () => {
  const raw = real("pnpm11", "pnpm-lock.yaml");
  const isn = /^( {2}is-number@7\.0\.0:\n {4}resolution: .*)$/m;
  assert.throws(() => pnpm(edit(raw, isn, "$1\n    version: 7.0.1")), /differs from its key/);
  assert.throws(() => pnpm(edit(raw, isn, "$1\n    name: is-odd")), /differs from its key/);
  assert.equal(pnpm(edit(raw, isn, "$1\n    version: 7.0.0")).packages.filter((p) => p.name === "is-number").length, 1, "a field that agrees is fine");
});

// With a cold cache npm 10 (`npm ci`) and yarn 1.22 (`--frozen-lockfile`) install is-number 7.0.0 from such a
// lockfile; with is-number's integrity cached, npm 10.9.2 installs from the cache whatever `resolved` says.
test("npm and yarn 1: a registry tarball that names another version is high, and both identities are IOC-checked", () => {
  for (const [dir, file] of [["npm10", "package-lock.json"], ["npm6", "package-lock.json"], ["yarn1", "yarn.lock"]] as const) {
    const lied = real(dir, file)
      .replace(/"version": "7\.0\.0",(\s*"resolved": "https:\/\/registry\.npmjs\.org\/is-number\/)/g, '"version": "7.0.1",$1')
      .replace(/version "7\.0\.0"(\n {2}resolved "https:\/\/registry\.yarnpkg\.com\/is-number\/)/g, 'version "7.0.1"$1');
    const l = parseLockfileText(file, lied) as ParsedLockfile;
    assert.ok(l.packages.some((p) => p.name === "is-number" && p.version === "7.0.1"), dir);
    const got = findings(l, { "is-number": ["7.0.0"] }).filter((f) => f.endsWith("is-number@7.0.1"));
    assert.deepEqual([...new Set(got)], ["WS-LK-001 critical is-number@7.0.1", "WS-LK-002 high is-number@7.0.1"], dir);
  }
  // the recorded identity is checked too: is-number@7.0.0 recorded with another package's tarball
  const relabelled = JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/is-number": { version: "7.0.0", resolved: "https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz", integrity: ISN } } });
  const want = ["WS-LK-001 critical is-number@7.0.0", "WS-LK-002 high is-number@7.0.0"];
  assert.deepEqual(findings(parseLockfileText("package-lock.json", relabelled) as ParsedLockfile, { "is-number": ["7.0.0"] }), want);
  // both identities listed: one WS-LK-001, since two would share a fingerprint
  assert.deepEqual(findings(parseLockfileText("package-lock.json", relabelled) as ParsedLockfile, { "is-number": ["7.0.0"], "is-odd": ["3.0.1"] }), want);
});

// npm 10.9.2 `npm ci` (cold cache) installs is-number 7.0.0 from an entry with `"version": "v7.0.0"` and no `resolved`.
test("npm: an entry fetched by name and version needs a semver version", () => {
  for (const dir of ["npm10", "npm6"]) {
    const unresolved = (version: string): string =>
      edit(real(dir, "package-lock.json"), /"version": "7\.0\.0",\s*"resolved": "https:\/\/registry\.npmjs\.org\/is-number\/-\/is-number-7\.0\.0\.tgz",/g, `"version": "${version}",`);
    const ok = parseLockfileText("package-lock.json", unresolved("7.0.0")) as ParsedLockfile;
    assert.ok(findings(ok, { "is-number": ["7.0.0"] }).includes("WS-LK-001 critical is-number@7.0.0"), `${dir} positive control`);
    // npm 10.9.2 `npm ci` installs is-number 7.0.0 from each of these (semver's loose parse)
    for (const forged of ["7.0.0.0", "07.0.0", "7.00.0", "7.0.0+evil"]) {
      assert.throws(() => parseLockfileText("package-lock.json", unresolved(forged)), /no semver version/, `${dir} ${forged}`);
    }
    // v1 keeps a git or URL spec in `version`, so a version that does not start with a digit is reported as a source
    const v = (): ParsedLockfile => parseLockfileText("package-lock.json", unresolved("v7.0.0")) as ParsedLockfile;
    if (dir === "npm10") assert.throws(v, /no semver version/);
    else assert.ok(findings(v()).includes("WS-LK-002 high is-number@v7.0.0"));
  }
});

test("pnpm: an entry with no semver version anywhere throws instead of parsing to version \"\"", () => {
  assert.throws(() => pnpm(rekeyed("7.0.0.0", `{integrity: ${ISN}}`)), /no semver version/);
  assert.throws(() => pnpm(rekeyed("7.0.0-", `{integrity: ${ISN}}`)), /no semver version/);
  // not the registry's spelling of a version, so not read as a registry key either
  for (const v of ["07.0.0", "7.00.0", "7.0.0+evil", "7.0.0-01"]) assert.throws(() => pnpm(rekeyed(v, `{integrity: ${ISN}}`)), /no semver version/, v);
});

test("pnpm: YAML anchors and tags on a package key throw (pnpm drops them and installs the package)", () => {
  const raw = real("pnpm11", "pnpm-lock.yaml");
  assert.match(raw, /^ {2}'@nodelib\/fs\.stat@2\.0\.5':\n[\s\S]*^ {2}is-number@7\.0\.0:\n {4}resolution: \{integrity: [^,]*\}$/m, "not the first key, no tarball");
  for (const prop of ["&a", "!!str"]) {
    assert.throws(() => pnpm(edit(raw, /^ {2}is-number@7\.0\.0:$/m, `  ${prop} is-number@7.0.0:`)), /is not a package name/, prop);
  }
});

test("yarn berry: a registry locator whose version is not the registry's spelling throws", () => {
  const raw = real("yarn4", "yarn.lock");
  for (const v of ["07.0.0", "7.0.0+evil"]) {
    assert.throws(() => parseLockfileText("yarn.lock", edit(raw, '  resolution: "is-number@npm:7.0.0"', `  resolution: "is-number@npm:${v}"`)), /no semver version/, v);
  }
});

test("yarn berry: a YAML anchor on a resolution throws instead of hiding the package", () => {
  const raw = real("yarn4", "yarn.lock");
  const text = edit(raw, '  resolution: "is-number@npm:7.0.0"', '  resolution: &r "is-number@npm:7.0.0"');
  assert.throws(() => parseLockfileText("yarn.lock", text), /is not a package name/);
});

test("yarn classic: a git entry whose name or version is not a package identity throws (positive control)", () => {
  const raw = real("yarn1", "yarn.lock");
  const git = /^"escape-string-regexp@github:(.*)\n {2}version "5\.0\.0"$/m;
  assert.throws(() => parseLockfileText("yarn.lock", edit(raw, git, '"&a escape-string-regexp@github:$1\n  version "5.0.0"')), /is not a package name/);
  assert.throws(() => parseLockfileText("yarn.lock", edit(raw, git, '"escape-string-regexp@github:$1\n  version "&a 5.0.0"')), /has no version/);
});

// package-lock.json is JSON, so a field can be an array: RegExp.test reads ["is-number"] as "is-number", but the IOC
// lookup keys on the array and misses. npm 10.9.2 `npm ci` installs is-number 7.0.0 from `"name": ["is-number"]`.
test("npm: a field that is not a string throws", () => {
  const cases: [string, (j: { packages?: Record<string, Record<string, unknown>>; dependencies?: Record<string, Record<string, unknown>> }) => Record<string, unknown>, string[]][] = [
    ["npm10", (j) => j.packages!["node_modules/is-number"]!, ["name", "version", "resolved", "integrity"]],
    ["npm6", (j) => j.dependencies!["is-number"]!, ["version", "resolved", "integrity"]],
  ];
  for (const [dir, entry, fields] of cases) {
    const ok = parseLockfileText("package-lock.json", real(dir, "package-lock.json")) as ParsedLockfile;
    assert.ok(findings(ok, { "is-number": ["7.0.0"] }).includes("WS-LK-001 critical is-number@7.0.0"), `${dir} positive control`);
    for (const field of fields) {
      const json = JSON.parse(real(dir, "package-lock.json"));
      const e = entry(json);
      e[field] = [field === "name" ? "is-number" : e[field]];
      assert.throws(() => parseLockfileText("package-lock.json", JSON.stringify(json)), /"\w+" is not a string/, `${dir} ${field}`);
    }
  }
});

type NpmJson = { packages: Record<string, Record<string, unknown>>; dependencies: Record<string, Record<string, unknown> & { dependencies?: Record<string, Record<string, unknown>> }> };
const npmEdit = (dir: "npm10" | "npm6", f: (j: NpmJson) => void): ParsedLockfile => {
  const j = JSON.parse(real(dir, "package-lock.json")) as NpmJson;
  f(j);
  return parseLockfileText("package-lock.json", JSON.stringify(j)) as ParsedLockfile;
};
const EVIL = "http://127.0.0.1:9/evil-7.0.0.tgz";
/** The npm10 fixture is written with --package-lock-only, which leaves bundled entries out; a real npm 10.9.2 install adds this one. */
const withMs = (j: NpmJson): void => {
  j.packages["node_modules/bundler/node_modules/ms"] = { version: "2.1.3", inBundle: true, license: "MIT" };
};

// npm 10.9.2 and 12.2.0 `npm ci` take a v2/v3 entry from its parent's tarball only when the parent's `bundleDependencies`
// list it (arborist reads `inBundle` from v1 lockfiles only), and npm 10 also fetches a v1 `bundled` entry's `resolved`.
// They fetched http://127.0.0.1:9/evil.tgz for each edit below that sets `resolved`. So the flag excuses only the missing
// integrity of a nested entry with no `resolved`, as npm writes it; the identity and source checks still apply.
test("npm: an inBundle or bundled flag does not exempt an entry from the identity and source checks", () => {
  // positive controls: the bundled ms that npm writes, with no resolved and no integrity, is quiet but still IOC-checked
  for (const l of [npmEdit("npm10", withMs), npmEdit("npm6", () => {})]) {
    assert.deepEqual(l.packages.find((p) => p.name === "ms"), { name: "ms", version: "2.1.3", bundled: true });
    assert.deepEqual(findings(l).filter((f) => f.endsWith("ms@2.1.3")), []);
    assert.ok(findings(l, { ms: ["2.1.3"] }).includes("WS-LK-001 critical ms@2.1.3"));
  }
  // v2/v3: a direct dependency, and a nested entry its parent does not bundle, are fetched like any other
  const top = (e: Record<string, unknown>) => (j: NpmJson) => void (j.packages["node_modules/is-number"] = { ...j.packages["node_modules/is-number"], inBundle: true, ...e });
  assert.throws(() => npmEdit("npm10", (j) => void (j.packages["node_modules/is-number"] = { version: "v7.0.0", inBundle: true })), /no semver version/);
  assert.ok(findings(npmEdit("npm10", top({ resolved: EVIL }))).includes("WS-LK-002 high is-number@7.0.0"));
  assert.ok(findings(npmEdit("npm10", (j) => void (j.packages["node_modules/is-number"] = { version: "7.0.0", inBundle: true }))).includes("WS-LK-003 medium is-number@7.0.0"));
  const nested = npmEdit("npm10", (j) => void (j.packages["node_modules/bundler/node_modules/is-number"] = { version: "7.0.0", inBundle: true, resolved: EVIL }));
  const evil = (id: string) => [`WS-LK-002 high ${id}`, `WS-LK-003 medium ${id}`];
  assert.deepEqual(findings(nested).filter((f) => f.endsWith("is-number@7.0.0")), evil("is-number@7.0.0"));
  const msEvil = npmEdit("npm10", (j) => (withMs(j), void (j.packages["node_modules/bundler/node_modules/ms"]!.resolved = EVIL)));
  assert.deepEqual(findings(msEvil).filter((f) => f.endsWith("ms@2.1.3")), evil("ms@2.1.3"));
  // v1: the same at the top level and nested
  const isn = (j: NpmJson) => j.dependencies["is-number"]!;
  assert.ok(findings(npmEdit("npm6", (j) => Object.assign(isn(j), { bundled: true, resolved: EVIL }))).includes("WS-LK-002 high is-number@7.0.0"));
  assert.ok(findings(npmEdit("npm6", (j) => void (j.dependencies["is-number"] = { version: "v7.0.0", bundled: true }))).includes("WS-LK-002 high is-number@v7.0.0"));
  assert.ok(findings(npmEdit("npm6", (j) => void (j.dependencies["is-number"] = { version: "7.0.0", bundled: true }))).includes("WS-LK-003 medium is-number@7.0.0"));
  const v1Evil = npmEdit("npm6", (j) => void (j.dependencies.bundler!.dependencies!.ms!.resolved = EVIL));
  assert.deepEqual(findings(v1Evil).filter((f) => f.endsWith("ms@2.1.3")), evil("ms@2.1.3"));
});

// npm 10.9.2 `npm ci` installs is-number 7.0.0 from a v1 entry with `"version": "v7.0.0", "resolved": ""`.
test("npm v1: an empty `resolved` is no source, so a version that is not semver is still reported", () => {
  const empty = (version: string) => npmEdit("npm6", (j) => Object.assign(j.dependencies["is-number"]!, { version, resolved: "" }));
  assert.ok(findings(empty("v7.0.0")).includes("WS-LK-002 high is-number@v7.0.0"));
  assert.ok(findings(empty("7.0.0"), { "is-number": ["7.0.0"] }).includes("WS-LK-001 critical is-number@7.0.0"), "positive control");
});
