// WS-LC-004: repository files a package manager runs without any lifecycle script, and config that names such
// files. diff gates the same files when they change (WS-DF-005); scan reports each one that exists, keyed on a hash
// of its content or of the settings' values, so a reviewed version can be baselined and a later one is reported again.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { scanDirectory } from "../src/scan.js";
import type { ScanResult } from "../src/scan.js";
import { testCtx } from "./helpers.js";
import { tempTree } from "./validation-helpers.js";

const scan = (d: string, opts: { nodeModules?: boolean; ignorePrefixes?: string[] } = {}): ScanResult => scanDirectory(d, testCtx(), { nodeModules: false, ...opts });
const lc4 = (r: ScanResult): string[] => r.findings.filter((f) => f.ruleId === "WS-LC-004").map((f) => `${f.severity} ${f.file}`).sort();
const sc900 = (r: ScanResult): string[] => r.findings.filter((f) => f.ruleId === "WS-SC-900").map((f) => f.file ?? "").sort();
const fp = (r: ScanResult, file: string): string | undefined => r.findings.find((f) => f.ruleId === "WS-LC-004" && f.file === file)?.fingerprint;

const EVERYTHING = {
  "package.json": '{"name":"a","version":"1.0.0"}',
  ".yarnrc.yml": "nodeLinker: node-modules\nyarnPath: .yarn/releases/yarn-4.5.0.cjs\nplugins:\n  - path: tools/plugin.cjs\n    spec: x\n",
  ".yarn/releases/yarn-4.5.0.cjs": "release()",
  ".yarn/plugins/@yarnpkg/plugin-x.cjs": "plugin()",
  "tools/plugin.cjs": "plugin()",
  ".pnpmfile.cjs": "module.exports = {}",
  "sub/.pnpmfile.mjs": "export default {}",
  ".env.yarn": "NODE_OPTIONS=--require ./p.js\n",
  ".pnp.cjs": "pnp()",
  ".pnp.loader.mjs": "loader()",
  ".npmrc": "registry=https://registry.npmjs.org/\nnode-options=--require ./preload.js\nscript-shell=./sh.sh\n",
  "sh.sh": "#!/bin/sh\n",
  "legacy/.yarnrc": 'yarn-path "./y.js"\n',
  "legacy/y.js": "y()",
  "ws/pnpm-workspace.yaml": "packages: ['a/*']\npnpmfile: hooks/p.cjs\n",
  "ws/hooks/p.cjs": "hook()",
};

test("scan: every package-manager code file and every setting that names code is a high WS-LC-004 finding", () => {
  const r = scan(tempTree(EVERYTHING));
  assert.deepEqual(lc4(r), [
    "high .env.yarn",
    "high .npmrc",
    "high .pnp.cjs",
    "high .pnp.loader.mjs",
    "high .pnpmfile.cjs",
    "high .yarn/plugins/@yarnpkg/plugin-x.cjs",
    "high .yarn/releases/yarn-4.5.0.cjs",
    "high .yarnrc.yml",
    "high legacy/.yarnrc",
    "high legacy/y.js",
    "high sh.sh",
    "high sub/.pnpmfile.mjs",
    "high tools/plugin.cjs",
    "high ws/hooks/p.cjs",
    "high ws/pnpm-workspace.yaml",
  ]);
  assert.match(r.findings.find((f) => f.file === ".npmrc")?.message ?? "", /sets node-options=--require \.\/preload\.js; script-shell=\.\/sh\.sh/);
  assert.deepEqual(sc900(r), []);
});

test("scan: config that names no code, and .npmrc keys in another case, are read as package managers read them", () => {
  const quiet = scan(tempTree({ ".npmrc": "ignore-scripts=true\nmin-release-age=7\n", ".yarnrc.yml": "nodeLinker: node-modules\nnpmMinimalAgeGate: 7d\n", "pnpm-workspace.yaml": "packages:\n  - 'a/*'\n", ".yarnrc": "--install.ignore-scripts true\n" }));
  assert.deepEqual(lc4(quiet), []);
  assert.deepEqual(lc4(scan(tempTree({ ".NPMRC": "NODE_OPTIONS = --require ./x.js\n" }))), ["high .NPMRC"]);
  // node-options that only set a memory limit or what is printed load no code; one more flag that can is reported.
  assert.deepEqual(lc4(scan(tempTree({ ".npmrc": 'node-options="--max-old-space-size=8192 --no-warnings"\nnode_options=--max_semi_space_size=64\n' }))), []);
  assert.deepEqual(lc4(scan(tempTree({ ".npmrc": "node-options=--max-old-space-size=8192 --import ./x.mjs\n" }))), ["high .npmrc"]);
});

test("scan: the file an .npmrc setting names is hashed whatever the key's spelling, so a baselined setting cannot hide a later edit", () => {
  for (const key of ["script-shell", "script_shell", "Script-Shell", "SCRIPT_SHELL", '"script-shell"', "pnpmfile", "Global_Pnpmfile", "global-pnpmfile"]) {
    const r = scan(tempTree({ ".npmrc": `${key}=./sh.sh\n`, "sh.sh": "#!/bin/sh\n" }));
    assert.deepEqual(lc4(r), ["high .npmrc", "high sh.sh"], key);
    assert.match(fp(r, "sh.sh") ?? "", /./, key);
    assert.match(r.findings.find((f) => f.file === "sh.sh")?.message ?? "", /config in this tree names it as code to run/, key);
  }
});

test("scan: a WS-LC-004 fingerprint follows the code's content and the settings' values, not other lines", () => {
  const at = (files: Record<string, string>, file: string) => fp(scan(tempTree(files)), file);
  assert.ok(at({ ".pnpmfile.cjs": "a" }, ".pnpmfile.cjs"));
  assert.equal(at({ ".pnpmfile.cjs": "a" }, ".pnpmfile.cjs"), at({ ".pnpmfile.cjs": "a" }, ".pnpmfile.cjs"));
  assert.notEqual(at({ ".pnpmfile.cjs": "a" }, ".pnpmfile.cjs"), at({ ".pnpmfile.cjs": "b" }, ".pnpmfile.cjs"));
  const npmrc = (extra: string, value: string) => at({ ".npmrc": `${extra}node-options=${value}\n` }, ".npmrc");
  assert.equal(npmrc("", "--require ./a.js"), npmrc("registry=https://registry.npmjs.org/\n", "--require ./a.js"), "an unrelated line keeps the review");
  assert.notEqual(npmrc("", "--require ./a.js"), npmrc("", "--require ./b.js"));
});

test("scan: under ignorePaths and in node_modules nothing is reported, but a file that config outside them names is", () => {
  const d = tempTree({
    "test/fx/.pnpmfile.cjs": "a",
    "test/fx/.npmrc": "node-options=--require ./x.js\n",
    "node_modules/p/.pnpmfile.cjs": "a",
    "node_modules/p/package.json": '{"name":"p","version":"1.0.0"}',
    ".yarnrc.yml": "yarnPath: test/fx/yarn.cjs\n",
    "test/fx/yarn.cjs": "release()",
  });
  assert.deepEqual(lc4(scan(d, { nodeModules: true, ignorePrefixes: ["test/fx"] })), ["high .yarnrc.yml", "high test/fx/yarn.cjs"]);
});

test("scan: package-manager code behind a symlink is reported as not checked", () => {
  const d = tempTree({ "real/p.cjs": "a", "real/r.cjs": "r", ".yarnrc.yml": "yarnPath: linked/r.cjs\n" });
  symlinkSync("real/p.cjs", join(d, ".pnpmfile.cjs"));
  symlinkSync("real", join(d, "linked"));
  const r = scan(d);
  assert.deepEqual(sc900(r), [".pnpmfile.cjs", "linked/r.cjs"]);
  assert.match(r.findings.find((f) => f.file === "linked/r.cjs")?.message ?? "", /reached through a symlink.*names it as code to run/);
  assert.deepEqual(lc4(r), ["high .yarnrc.yml"]);
});

test("scan: YAML config outside the reader's subset fails closed only when it could spell a key that names code", () => {
  const d = tempTree({ ".yarnrc.yml": "yarnPath: a.cjs\nyarnPath: b.cjs\n", "a/pnpm-workspace.yaml": "onlyBuiltDependencies: [esbuild,\n  sharp\n]\n" });
  assert.deepEqual(sc900(scan(d)), [".yarnrc.yml"]);
  mkdirSync(join(d, "b"));
  writeFileSync(join(d, "b/pnpm-workspace.yaml"), "onlyBuiltDependencies: [esbuild,\n  sharp\n]\npnpmfile: hooks.cjs\n");
  assert.deepEqual(sc900(scan(d)), [".yarnrc.yml", "b/pnpm-workspace.yaml"]);
});
