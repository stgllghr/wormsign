/**
 * diff on a Python project's build (src/diff.ts pythonBuildFindings): a change to soak's own local-build key
 * (src/python/build.ts localBuild) is WS-DF-005 high.
 *
 * An install that builds a project (`pip install --no-deps .` included) first installs the build requirements its
 * build configuration, hooks and backend name, resolved fresh. No lock pins them, and `soak` reports no build for a
 * project that no uv.lock or pylock.toml lists (docs/soak.md, Python limitations): only a build `soak` sees, a uv.lock
 * or pylock directory member, is WS-SK-005. So in a pip-locked project the pull-request gate's only check of a new
 * build requirement is this one, and it compares everything soak's key covers: [build-system], the rest of
 * pyproject.toml but its version, metadata and linters' tables, setup.cfg, setup.py, hatch.toml, uv.toml, the hook
 * files and the backend-path files. The reproductions below are the reviews': a requirements hash lock beside a
 * pyproject.toml whose [build-system].requires gains a package (round 1), and a hatch.toml builder dependency, a
 * hatch build hook's dependencies and a setup.cfg setup_requires (round 2), which a [build-system]-only rule missed.
 * A project a uv.lock or pylock.toml lists is soak's: `soak --base` keys the same build, so diff leaves it alone.
 *
 * The network is validation-helpers.ts fakeNet, PATH a directory of stub binaries and git, HOME empty.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { run } from "../src/main.js";
import { diffTrees } from "../src/diff.js";
import { gitTree, type Tree } from "../src/tree.js";
import { localBuild, type BuildEntry } from "../src/python/build.js";
import type { Finding } from "../src/types.js";
import { escapeRegExp, fakeIO, fx, testCtx } from "./helpers.js";
import { fakeNet, gitRepo, stubBin, tempTree } from "./validation-helpers.js";

const IOCS = ["--iocs", fx("iocs")];
const GIT_DIR = dirname(execFileSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).trim());
const PATH = `${stubBin()}:${GIT_DIR}`;
/** six 1.16.0's wheel on pypi.org (test/fixtures/python/simple/six.json), uploaded 2021-05-05. */
const SIX_116 = "8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254";
const HASH_LOCK = `--require-hashes\nsix==1.16.0 --hash=sha256:${SIX_116}\n`;

interface Run {
  code: number;
  findings: Finding[];
  notes: string[];
  err: string;
}
async function cli(args: string[]): Promise<Run> {
  const home = mkdtempSync(join(tmpdir(), "ws-diffbuild-home-"));
  const io = fakeIO({ env: { PATH, HOME: home, XDG_CONFIG_HOME: join(home, ".config") }, fetchImpl: fakeNet().fetchImpl });
  const code = await run([...args, "--format", "json"], io);
  if (io.out === "") return { code, findings: [], notes: [], err: io.err };
  const doc = JSON.parse(io.out) as { findings: Finding[]; notes: string[] };
  return { code, findings: doc.findings, notes: doc.notes, err: io.err };
}
const brief = (r: Run): string[] => r.findings.map((f) => `${f.ruleId} ${f.severity} ${f.file}`).sort();
/** A run's WS-DF-005 findings, by file. */
const builds = (r: Run): string[] => brief(r).filter((b) => b.startsWith("WS-DF-005"));
const message = (r: Run): string => r.findings.find((f) => f.ruleId === "WS-DF-005")?.message ?? "";
const pyproject = (buildSystem: string, version = "0.1.0", extra = ""): string =>
  `${buildSystem}[project]\nname = "demo"\nversion = "${version}"\ndependencies = ["six==1.16.0"]\n${extra}`;
const SETUPTOOLS = '[build-system]\nrequires = ["setuptools>=61"]\nbuild-backend = "setuptools.build_meta"\n\n';
const HATCHLING = '[build-system]\nrequires = ["hatchling"]\nbuild-backend = "hatchling.build"\n\n';
type Files = Record<string, string>;
const diffDirs = async (before: Files, after: Files): Promise<Run> => cli(["diff", `dir:${tempTree(before)}`, `dir:${tempTree(after)}`, ...IOCS]);
/** The same change as two git revisions: the base's and head's files read from git (gitBuildReader), not from disk. */
async function diffGit(before: Files, after: Files): Promise<Run> {
  const put = (d: string, files: Files): void => {
    for (const [rel, text] of Object.entries(files)) {
      mkdirSync(dirname(join(d, rel)), { recursive: true });
      writeFileSync(join(d, rel), text);
    }
  };
  const repo = gitRepo([(d) => put(d, before), (d) => put(d, after)]);
  return cli(["diff", "HEAD~1", "HEAD", "--dir", repo, ...IOCS]);
}
const HIGH = "WS-DF-005 high pyproject.toml";
const WHY =
  ": an install that builds it (`pip install --no-deps .` included) first installs the build requirements its build configuration, hooks and backend name, resolved fresh; no lock pins them, and soak reports no build for a project that no uv.lock or pylock.toml lists";

test("diff: a pip-locked project whose [build-system].requires gains a package is WS-DF-005 high; soak --base sees no build there (the round-1 reproduction)", async () => {
  const repo = gitRepo([
    (d) => {
      writeFileSync(join(d, "requirements.txt"), HASH_LOCK);
      writeFileSync(join(d, "pyproject.toml"), pyproject(SETUPTOOLS));
    },
    (d) => writeFileSync(join(d, "pyproject.toml"), pyproject(SETUPTOOLS.replace('"setuptools>=61"', '"setuptools>=61", "freshly-published-backend==1.0.0"'))),
  ]);
  // The limit the docs state: soak --base checks the lock (six) and reports no build for this project.
  const soak = await cli(["soak", repo, "--base", "HEAD~1"]);
  assert.equal(soak.code, 0, soak.err + soak.findings.map((f) => f.message).join("\n"));
  assert.deepEqual(soak.findings.filter((f) => f.ruleId === "WS-SK-005"), []);
  // diff is the gate's check of it: high, so the default --fail-on high fails the pull request.
  const diff = await cli(["diff", "HEAD~1", "HEAD", "--dir", repo, ...IOCS]);
  assert.equal(diff.code, 1, diff.err);
  assert.deepEqual(brief(diff), [HIGH, "WS-DF-006 medium pyproject.toml"]);
  assert.equal(message(diff), `The build of the Python project in the top directory changed in this change (pyproject.toml)${WHY}`);
  // The commit against itself: nothing.
  assert.deepEqual((await cli(["diff", "HEAD", "HEAD", "--dir", repo, ...IOCS])).findings, []);
});

test("diff: the round-2 reproductions are high, read from git and from disk: a hatch.toml builder dependency, a hatch hook's dependencies, setup.cfg setup_requires", async () => {
  const hatch = { "requirements.txt": HASH_LOCK, "pyproject.toml": pyproject(HATCHLING) };
  const setuptools = { "requirements.txt": HASH_LOCK, "pyproject.toml": pyproject(SETUPTOOLS), "setup.cfg": "[metadata]\nname = demo\n" };
  const cases: [string, Files, Files, string[], string][] = [
    ["hatch.toml", hatch, { "hatch.toml": '[build.targets.wheel]\ndependencies = ["freshly-published-plugin==1.0.0"]\n' }, [HIGH], "hatch.toml"],
    ["a hook's dependencies", hatch, { "pyproject.toml": pyproject(HATCHLING, "0.1.0", '\n[tool.hatch.build.targets.wheel.hooks.custom]\ndependencies = ["freshly-published-plugin==1.0.0"]\n') }, [HIGH, "WS-DF-006 medium pyproject.toml"], "pyproject.toml"],
    ["setup_requires", setuptools, { "setup.cfg": "[metadata]\nname = demo\n\n[options]\nsetup_requires = freshly-published-plugin==1.0.0\n" }, [HIGH, "WS-DF-006 medium setup.cfg"], "setup.cfg"],
  ];
  for (const [what, before, edit, expected, named] of cases) {
    for (const [how, diff] of [["git", diffGit], ["dir", diffDirs]] as const) {
      const r = await diff(before, { ...before, ...edit });
      assert.equal(r.code, 1, `${what} (${how}): ${r.err}`);
      assert.deepEqual(brief(r), expected, `${what} (${how})`);
      assert.equal(message(r), `The build of the Python project in the top directory changed in this change (${named})${WHY}`, `${what} (${how})`);
    }
  }
});

test("diff: what cannot change a build stays medium: a version bump, a linter's settings, formatting, [project] dependencies under a known backend; a tool-only pyproject.toml is no project", async () => {
  const base = { "requirements.txt": HASH_LOCK, "pyproject.toml": pyproject(SETUPTOOLS) };
  for (const [what, after] of [
    ["a version bump", pyproject(SETUPTOOLS, "0.2.0")],
    ["a linter's table", pyproject(SETUPTOOLS, "0.1.0", "\n[tool.ruff]\nline-length = 100\n")],
    ["formatting", `# build\n[build-system]\nbuild-backend = 'setuptools.build_meta'\nrequires = [ 'setuptools>=61' ]\n\n${pyproject("")}`],
    ["dependencies under setuptools", pyproject(SETUPTOOLS).replace('["six==1.16.0"]', '["six==1.16.0", "idna==3.10"]')],
  ] as const) {
    for (const [how, diff] of [["git", diffGit], ["dir", diffDirs]] as const) {
      const r = await diff(base, { ...base, "pyproject.toml": after });
      assert.equal(r.code, 0, `${what} (${how}): ${r.err}`);
      assert.deepEqual(brief(r), ["WS-DF-006 medium pyproject.toml"], `${what} (${how})`);
    }
  }
  // A pyproject.toml that only configures tools builds nothing: no WS-DF-005, whatever its [tool] tables hold.
  const tools = { "pyproject.toml": "[tool.black]\nline-length = 100\n" };
  assert.deepEqual(builds(await diffDirs(tools, { "pyproject.toml": '[tool.black]\nline-length = 100\n[tool.towncrier]\ndirectory = "changes"\n' })), []);
  assert.deepEqual(builds(await diffDirs({}, tools)), [], "added");
  // ...unless a setup.cfg beside it declares dependencies: setuptools' legacy backend builds it with them.
  assert.deepEqual(builds(await diffDirs(tools, { ...tools, "setup.cfg": "[options]\nsetup_requires = freshly-published-plugin\n" })), [HIGH]);
  assert.deepEqual(builds(await diffDirs(tools, { ...tools, "setup.cfg": "[flake8]\nmax-line-length = 100\n" })), [], "a setup.cfg of tool settings");
  // A project removed in the change builds nothing: its removal is the manifest's WS-DF-006 only.
  assert.deepEqual(brief(await diffDirs(base, { "requirements.txt": HASH_LOCK })), ["WS-DF-006 medium pyproject.toml"]);
});

test("diff: everything soak's key covers counts: each [build-system] key, setup.py, a hook a setting names, backend-path files, uv.toml; a new project is new; the key follows the content", async () => {
  const base = { "pyproject.toml": pyproject(SETUPTOOLS), "requirements.txt": HASH_LOCK };
  const high = async (after: Files, before: Files = base): Promise<string[]> => builds(await diffDirs(before, { ...before, ...after }));
  const one = [HIGH];
  assert.deepEqual(await high({ "pyproject.toml": pyproject(SETUPTOOLS.replace("setuptools.build_meta", "fresh_backend.build")) }), one, "build-backend");
  assert.deepEqual(await high({ "pyproject.toml": pyproject(SETUPTOOLS.replace("build-backend", 'backend-path = ["_build"]\nbuild-backend')) }), one, "backend-path");
  assert.deepEqual(await high({ "pyproject.toml": pyproject(SETUPTOOLS.replace('"setuptools>=61"', '"setuptools>=61.1"')) }), one, "a requirement's specifier");
  assert.deepEqual(await high({ "pyproject.toml": pyproject(`${SETUPTOOLS.trimEnd()}\nunknown-key = 1\n\n`) }), one, "a key no frontend reads yet");
  assert.deepEqual(await high({ "pyproject.toml": pyproject("") }), one, "[build-system] removed: the default setuptools backend");
  // uv.toml is also install configuration of its own (WS-DF-005 on the file).
  assert.deepEqual(await high({ "uv.toml": 'build-constraint-dependencies = ["setuptools<81"]\n' }), [HIGH, "WS-DF-005 high uv.toml"], "uv.toml");
  assert.deepEqual(await high({ "setup.py": "from setuptools import setup\nsetup()\n" }), one, "a setup.py added");
  const hooked = { ...base, "pyproject.toml": pyproject(HATCHLING, "0.1.0", '\n[tool.hatch.build.hooks.custom]\npath = "tools/hook.py"\n'), "tools/hook.py": "x = 1\n" };
  const hook = await diffDirs(hooked, { ...hooked, "tools/hook.py": "x = 2\n" });
  assert.deepEqual(builds(hook), one, "the hook file a setting names");
  assert.match(message(hook), /changed in this change \(tools\/hook\.py\): /);
  const backend = { ...base, "pyproject.toml": pyproject('[build-system]\nrequires = []\nbuild-backend = "backend"\nbackend-path = ["_build"]\n\n'), "_build/backend.py": "REQUIRES = []\n" };
  assert.deepEqual(await high({ "_build/backend.py": 'REQUIRES = ["fresh"]\n' }, backend), one, "a file under backend-path");
  assert.match(message(await diffDirs(backend, { ...backend, "_build/backend.py": "x\n", "setup.cfg": "[options]\n" })), /\(backend-path, setup\.cfg\): /, "every changed input named");
  // A setup.py project: any edit to setup.py is a changed build (it computes its build requirements).
  const setupPy = { "setup.py": "from setuptools import setup\nsetup()\n", "requirements.txt": HASH_LOCK };
  const edited = await diffGit(setupPy, { "setup.py": "from setuptools import setup\nsetup(setup_requires=['fresh'])\n" });
  assert.deepEqual(brief(edited), ["WS-DF-005 high setup.py", "WS-DF-006 medium setup.py"]);
  // A project the change adds is new: its build was never reviewed (a new package directory in a monorepo).
  const added = await diffDirs({ "requirements.txt": HASH_LOCK }, { "requirements.txt": HASH_LOCK, "packages/new/pyproject.toml": pyproject(HATCHLING) });
  assert.deepEqual(builds(added), ["WS-DF-005 high packages/new/pyproject.toml"]);
  assert.match(message(added), /^The build of the Python project in packages\/new is new in this change \(pyproject\.toml\): /);
  // Each new build is its own finding: one baseline entry cannot approve the next edit.
  const fp = async (requires: string): Promise<string | undefined> =>
    (await diffDirs(base, { ...base, "pyproject.toml": pyproject(SETUPTOOLS.replace('"setuptools>=61"', requires)) })).findings.find((f) => f.ruleId === "WS-DF-005")?.fingerprint;
  assert.notEqual(await fp('"setuptools>=61", "a==1"'), await fp('"setuptools>=61", "b==1"'));
  assert.equal(await fp('"setuptools>=61", "a==1"'), await fp('"setuptools>=61", "a==1"'));
  assert.match((await diffDirs(base, { ...base, "hatch.toml": "[build]\n" })).findings.find((f) => f.ruleId === "WS-DF-005")?.key ?? "", /^python-build:[0-9a-f]{32}$/);
});

test("diff: a project a uv.lock or pylock.toml lists is soak's (soak --base reports its build, high), so diff does not report it twice; a lock soak does not read leaves it diff's", async () => {
  const app = (requires: string): string => `[project]\nname = "app"\nversion = "0.1.0"\n\n[build-system]\nrequires = ${requires}\nbuild-backend = "hatchling.build"\n`;
  const uvLock = (source: string, path = "."): string => `version = 1\nrevision = 3\nrequires-python = ">=3.9"\n\n[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { ${source} = "${path}" }\n`;
  const fresh = app('["hatchling", "freshly-published-backend-plugin==1.0.0"]');
  const repo = gitRepo([
    (d) => {
      writeFileSync(join(d, "uv.lock"), uvLock("editable"));
      writeFileSync(join(d, "pyproject.toml"), app('["hatchling"]'));
    },
    (d) => writeFileSync(join(d, "pyproject.toml"), fresh),
  ]);
  const diff = await cli(["diff", "HEAD~1", "HEAD", "--dir", repo, ...IOCS]);
  assert.equal(diff.code, 0, diff.err);
  assert.deepEqual(brief(diff), ["WS-DF-006 medium pyproject.toml"]);
  // soak --base keys the same build, and the change makes it new: high there, once.
  const soak = await cli(["soak", repo, "--base", "HEAD~1"]);
  assert.equal(soak.code, 1, soak.err);
  assert.deepEqual(soak.findings.filter((f) => f.ruleId === "WS-SK-005").map((f) => `${f.severity} ${f.file}`), ["high uv.lock"]);
  // From disk too; a pylock directory entry is soak's as well, and so is a workspace member, by its path.
  const before = { "pyproject.toml": app('["hatchling"]') };
  const pylock = (path: string): string => `lock-version = "1.0"\ncreated-by = "test"\n\n[[packages]]\nname = "app"\ndirectory = { path = "${path}", editable = false }\n`;
  for (const [what, lock] of [["uv.lock", { "uv.lock": uvLock("editable") }], ["pylock.toml", { "pylock.toml": pylock(".") }], ["pylock.ci.toml", { "pylock.ci.toml": pylock(".") }]] as const) {
    const r = await diffDirs({ ...before, ...lock }, { ...lock, "pyproject.toml": fresh });
    assert.deepEqual(builds(r), [], what);
    assert.deepEqual(brief(r), ["WS-DF-006 medium pyproject.toml"], `${what}: positive control, the change is seen`);
  }
  const member = { "pkgs/app/pyproject.toml": app('["hatchling"]'), "uv.lock": uvLock("editable", "pkgs/app") };
  assert.deepEqual(builds(await diffDirs(member, { ...member, "pkgs/app/pyproject.toml": fresh })), [], "a workspace member");
  // A uv application uv records as virtual (no [build-system]) is not built by uv: its dependency edits stay medium.
  // Once it names a build of its own ([build-system], setup.py, setup.cfg), a virtual entry is a stale lock or a
  // decoy, and diff compares it.
  const uvApp = (deps: string): string => `[project]\nname = "app"\nversion = "0.1.0"\ndependencies = ${deps}\n`;
  const virtual = { "uv.lock": uvLock("virtual"), "pyproject.toml": uvApp('["six==1.16.0"]') };
  assert.deepEqual(brief(await diffDirs(virtual, { ...virtual, "pyproject.toml": uvApp('["six==1.16.0", "idna==3.10"]') })), ["WS-DF-006 medium pyproject.toml"], "a dependency added to a uv application");
  for (const [what, edit, file] of [
    ["[build-system] added", { "pyproject.toml": `${HATCHLING}${uvApp('["six==1.16.0"]')}` }, HIGH],
    ["setup.cfg setup_requires added", { "setup.cfg": "[options]\nsetup_requires = freshly-published-plugin\n" }, HIGH],
    ["setup.py added", { "setup.py": "from setuptools import setup\nsetup(setup_requires=['fresh'])\n" }, HIGH],
  ] as const) {
    assert.deepEqual(builds(await diffDirs(virtual, { ...virtual, ...edit })), [file], what);
  }
  assert.deepEqual(builds(await diffDirs({ ...before, "uv.lock": uvLock("virtual") }, { "uv.lock": uvLock("virtual"), "pyproject.toml": fresh })), [HIGH], "a virtual entry for a project with [build-system]");
  // A lock that lists another directory, one under ignorePaths (soak does not read it there), one that does not parse:
  // the project stays diff's.
  const ignoring = JSON.stringify({ version: 1, entries: [], ignorePaths: [{ path: "locks", justification: "locks nothing here installs" }] });
  for (const [what, lock, at] of [
    ["a pylock.toml that lists another directory", { "pylock.toml": pylock("libs/other") }, "pyproject.toml"],
    ["a uv.lock that lists another directory", { "uv.lock": uvLock("editable", "libs/other") }, "pyproject.toml"],
    ["a uv.lock under ignorePaths", { ".wormsign-baseline.json": ignoring, "sub/pyproject.toml": app('["hatchling"]'), "locks/uv.lock": uvLock("editable", "../sub") }, "sub/pyproject.toml"],
    ["a uv.lock that does not parse", { "uv.lock": "[[package]\n" }, "pyproject.toml"],
  ] as const) {
    const r = await diffDirs({ ...before, ...lock }, { ...before, ...lock, [at]: fresh });
    assert.deepEqual(builds(r), [`WS-DF-005 high ${at}`], what);
  }
  // The same uv.lock outside ignorePaths: soak reads it, so the member is soak's.
  const read = { "sub/pyproject.toml": app('["hatchling"]'), "locks/uv.lock": uvLock("editable", "../sub") };
  assert.deepEqual(builds(await diffDirs(read, { ...read, "sub/pyproject.toml": fresh })), [], "control: the lock outside ignorePaths");
});

test("diff: a changed build is reported under ignorePaths too, from a base that cannot be read, and for a build file whose name differs only in case", async () => {
  const baselineDoc = JSON.stringify({ version: 1, entries: [], ignorePaths: [{ path: "vendor", justification: "vendored code nothing here installs" }] });
  const base = { ".wormsign-baseline.json": baselineDoc, "vendor/lib/pyproject.toml": pyproject(SETUPTOOLS) };
  const hidden = await diffDirs(base, { ...base, "vendor/lib/pyproject.toml": pyproject(SETUPTOOLS, "0.2.0") });
  assert.deepEqual(hidden.findings, [], "an edit that keeps the build stays hidden there");
  const shown = await diffDirs(base, { ...base, "vendor/lib/pyproject.toml": pyproject(SETUPTOOLS.replace("setuptools.build_meta", "fresh_backend.build")) });
  assert.deepEqual(brief(shown), ["WS-DF-005 high vendor/lib/pyproject.toml"]);
  assert.deepEqual(brief(await diffDirs(base, { ...base, "vendor/lib/hatch.toml": "[build]\n" })), ["WS-DF-005 high vendor/lib/pyproject.toml"], "a build file that is no manifest");
  assert.ok(shown.notes.some((n) => n.endsWith("and so are a pyproject.toml's [tool.uv], a Python project's build and a pyproject.toml that does not parse; other Python manifest edits and Python locks are not): vendor")), shown.notes.join("\n"));
  // One that does not parse: its build is unknown, and a [tool.uv] could hide in it.
  assert.deepEqual(brief(await diffDirs(base, { ...base, "vendor/lib/pyproject.toml": "[build-system\n" })), ["WS-DF-005 high vendor/lib/pyproject.toml", "WS-DF-006 high vendor/lib/pyproject.toml"]);
  // A base that does not parse hides nothing: the build counts as changed.
  const fromUnparsed = await diffDirs({ "pyproject.toml": "[project\n" }, { "pyproject.toml": pyproject(SETUPTOOLS) });
  assert.deepEqual(brief(fromUnparsed), [HIGH, "WS-DF-006 medium pyproject.toml"]);
  // A base whose files cannot all be read (more .py files beside a hook than are read) makes the build changed,
  // though both sides hold the same: from git and from disk.
  const many: Files = { "pyproject.toml": pyproject(HATCHLING, "0.1.0", '\n[tool.hatch.build.hooks.custom]\npath = "hooks/h.py"\n'), "hooks/h.py": "# hook\n" };
  for (let i = 0; i < 200; i++) many[`hooks/m${i}.py`] = `x = ${i}\n`;
  for (const [how, diff] of [["git", diffGit], ["dir", diffDirs]] as const) {
    const r = await diff(many, { ...many, "pyproject.toml": many["pyproject.toml"]!.replace("0.1.0", "0.2.0") });
    assert.deepEqual(builds(r), [HIGH], how);
    // Nothing differs, so no file is named; the cap is.
    assert.match(message(r), /changed in this change \(the build configuration or its hook and backend files; not read in full, so counted as unreadable: more than 200 \.py files beside the hook in hooks\): /, how);
  }
  const fewer = { ...many };
  delete fewer["hooks/m199.py"];
  assert.deepEqual(builds(await diffDirs(fewer, { ...fewer, "pyproject.toml": many["pyproject.toml"]!.replace("0.1.0", "0.2.0") })), [], "control: 200 .py files beside the hook are all read");
  // A build file whose name differs only in case: a case-insensitive disk reads Setup.py as setup.py and HATCH.toml as
  // hatch.toml. git cannot show such a name plainly under the name a build opens, so the base never counts as the
  // same: the build is reported on every change, unchanged or not (as soak --base treats a folded name).
  const odd = { "pyproject.toml": pyproject(SETUPTOOLS), "HATCH.toml": "[build]\n" };
  assert.deepEqual(builds(await diffGit(odd, { "HATCH.toml": '[build.targets.wheel]\ndependencies = ["fresh"]\n' })), [HIGH]);
  assert.deepEqual(builds(await diffGit(odd, { "README.md": "docs\n" })), [HIGH], "unchanged");
  const caseOnly = { "Setup.py": "from setuptools import setup\nsetup()\n" };
  const setup = await diffGit(caseOnly, { "Setup.py": "from setuptools import setup\nsetup(setup_requires=['fresh'])\n" });
  assert.deepEqual(builds(setup), ["WS-DF-005 high Setup.py"], "a project by its Setup.py alone");
  assert.match(message(setup), /changed in this change \(the build configuration or its hook and backend files\): /);
});

/** A hatch hook table per path, each under its own target, so that the build configuration names every one. */
const hookTables = (paths: string[]): string => paths.map((p, i) => `[tool.hatch.build.targets.t${i}.hooks.custom]\npath = "${p}"\n`).join("\n");
const bumped = (files: Files): Files => ({ ...files, "pyproject.toml": (files["pyproject.toml"] as string).replace('version = "0.1.0"', 'version = "0.2.0"') });
/** The `git show` runs while `f` runs, through a git first on PATH that logs them (as test/cli-tree.test.ts counts them). */
async function gitShows<T>(f: () => Promise<T>): Promise<[T, number]> {
  const bin = mkdtempSync(join(tmpdir(), "ws-diffbuild-git-"));
  const log = join(bin, "count");
  writeFileSync(log, "");
  const realGit = execFileSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).trim();
  // tree.ts runs `git -c <setting> ... -C <dir> <subcommand> ...`; only `show` has the word show among its arguments.
  writeFileSync(join(bin, "git"), `#!/bin/sh\ncase " $* " in *" show "*) echo >> "${log}" ;; esac\nexec "${realGit}" "$@"\n`, { mode: 0o755 });
  const path = process.env.PATH;
  process.env.PATH = `${bin}:${path}`;
  try {
    const out = await f();
    return [out, readFileSync(log, "utf8").length];
  } finally {
    process.env.PATH = path;
  }
}

test("diff reads each build file once per revision: one hook named 25 ways beside 40 .py files (minutes before: every spelling read every file beside it, each a `git show`), and 32 hooks in one directory, take seconds", async () => {
  const pyFiles = (n: number): Files => Object.fromEntries(Array.from({ length: n }, (_, i) => [`hooks/m${i}.py`, `x = ${i}\n`]));
  const cases: [string, string[], number][] = [
    ["one hook named 25 ways", Array.from({ length: 25 }, (_, i) => `hooks/${"./".repeat(i + 1)}m1.py`), 40],
    ["32 hooks in one directory", Array.from({ length: 32 }, (_, i) => `hooks/m${i}.py`), 32],
  ];
  for (const [what, paths, files] of cases) {
    const before: Files = { "requirements.txt": HASH_LOCK, "pyproject.toml": pyproject(HATCHLING, "0.1.0", `\n${hookTables(paths)}`), ...pyFiles(files) };
    const after = bumped(before);
    const repo = gitRepo([(d) => tempTreeAt(d, before), (d) => tempTreeAt(d, after)]);
    const start = Date.now();
    const [r, shows] = await gitShows(() => cli(["diff", "HEAD~1", "HEAD", "--dir", repo, ...IOCS]));
    const seconds = (Date.now() - start) / 1000;
    // A version bump keeps the build: no WS-DF-005.
    assert.equal(r.code, 0, `${what}: ${r.err}`);
    assert.deepEqual(brief(r), ["WS-DF-006 medium pyproject.toml"], what);
    // Each .py file once per revision, and a few more reads (pyproject.toml and requirements.txt, by diff's other
    // checks too). At be772bc, uncached and read once per spelling, the cases ran 2,108 and 2,184 (92 and 95 s).
    assert.ok(shows <= 2 * (files + 6), `${what}: ${shows} git show runs`);
    // About 3 s on the development Mac (a `git show` takes 30-40 ms there); the count above is the exact bound.
    assert.ok(seconds < 20, `${what}: ${seconds} s`);
  }
});

test("diff: past 64 hook files or 16 backend-path entries a build is unreadable, high on every change, and the message names the cap; spellings of one path count once", async () => {
  const hooks = (n: number): string[] => Array.from({ length: n }, (_, i) => `hooks/h${i}.py`);
  const withHooks = (paths: string[]): Files => ({ "pyproject.toml": pyproject(HATCHLING, "0.1.0", `\n${hookTables(paths)}`), ...Object.fromEntries(hooks(65).map((p) => [p, "x = 1\n"])) });
  const KEPT = ["WS-DF-006 medium pyproject.toml"];
  const past = (cap: string): RegExp => new RegExp(`\\(the build configuration or its hook and backend files; not read in full, so counted as unreadable: ${cap}\\): `);
  assert.deepEqual(brief(await diffDirs(withHooks(hooks(64)), bumped(withHooks(hooks(64))))), KEPT, "64 hook files are read");
  for (const [how, diff] of [["git", diffGit], ["dir", diffDirs]] as const) {
    const r = await diff(withHooks(hooks(65)), bumped(withHooks(hooks(65))));
    assert.deepEqual(builds(r), [HIGH], `65 hook files (${how})`);
    assert.match(message(r), past("it names more than 64 hook files"), how);
  }
  // One hook file spelled 70 ways is one: "." and empty names do not change the file a path opens.
  const spellings = Array.from({ length: 70 }, (_, i) => (i % 2 === 0 ? `hooks/${"./".repeat(i)}h0.py` : `.${"/".repeat(i)}hooks/h0.py`));
  assert.deepEqual(brief(await diffDirs(withHooks(spellings), bumped(withHooks(spellings)))), KEPT, "one hook named 70 ways");
  const backend = (entries: string[]): Files => ({
    "pyproject.toml": pyproject(`[build-system]\nrequires = []\nbuild-backend = "backend"\nbackend-path = ${JSON.stringify(entries)}\n\n`),
    "_build/backend.py": "REQUIRES = []\n",
  });
  const dirs = (n: number): string[] => Array.from({ length: n }, (_, i) => (i === 0 ? "_build" : `b${i}`));
  assert.deepEqual(brief(await diffDirs(backend(dirs(16)), bumped(backend(dirs(16))))), KEPT, "16 backend-path entries are read");
  for (const [how, diff] of [["git", diffGit], ["dir", diffDirs]] as const) {
    const r = await diff(backend(dirs(17)), bumped(backend(dirs(17))));
    assert.deepEqual(builds(r), [HIGH], `17 backend-path entries (${how})`);
    assert.match(message(r), past("it lists more than 16 backend-path entries"), how);
  }
  const ways = Array.from({ length: 20 }, (_, i) => `${"./".repeat(i)}_build${i % 2 === 0 ? "" : "/"}`);
  assert.deepEqual(brief(await diffDirs(backend(ways), bumped(backend(ways)))), KEPT, "one backend-path entry spelled 20 ways");
  // Positive control: the backend file an entry names is read.
  assert.deepEqual(builds(await diffDirs(backend(ways), { ...backend(ways), "_build/backend.py": 'REQUIRES = ["fresh"]\n' })), [HIGH]);
  // The files under one backend-path entry are read up to 2,000, as soak reads them; the message names that cap too.
  const crowded = backend(["_build"]);
  for (let i = 0; i < 2000; i++) crowded[`_build/m${i}.py`] = "x = 1\n";
  const full = await diffDirs(crowded, bumped(crowded));
  assert.deepEqual(builds(full), [HIGH], "2,001 files under backend-path");
  assert.match(message(full), past("more than 2000 files under backend-path _build"));
});

test("diff: a build file linked out of its project counts by what the link leads to, so an edit there is high (R11's [build-system] case), from git and from disk", async () => {
  // app/pyproject.toml -> ../shared/base.toml, and lib's backend file -> ../../shared/backend.py: a monorepo sharing
  // one build configuration. The link leaves the project's directory, where soak's key records it by its text alone.
  const shared: Files = {
    "requirements.txt": HASH_LOCK,
    "shared/base.toml": pyproject(SETUPTOOLS),
    "shared/backend.py": "REQUIRES = []\n",
    "lib/pyproject.toml": pyproject('[build-system]\nrequires = []\nbuild-backend = "backend"\nbackend-path = ["_build"]\n\n'),
  };
  const links = { "app/pyproject.toml": "../shared/base.toml", "lib/_build/backend.py": "../../shared/backend.py" };
  const put = (d: string, files: Files, linked: Record<string, string> = {}): void => {
    tempTreeAt(d, files);
    for (const [rel, target] of Object.entries(linked)) {
      mkdirSync(dirname(join(d, rel)), { recursive: true });
      symlinkSync(target, join(d, rel));
    }
  };
  const run = async (how: "git" | "dir", edit: Files): Promise<Run> => {
    if (how === "git") return cli(["diff", "HEAD~1", "HEAD", "--dir", gitRepo([(d) => put(d, shared, links), (d) => put(d, edit)]), ...IOCS]);
    const [a, b] = [mkdtempSync(join(tmpdir(), "ws-diffbuild-a-")), mkdtempSync(join(tmpdir(), "ws-diffbuild-b-"))];
    put(a, shared, links);
    put(b, { ...shared, ...edit }, links);
    return cli(["diff", `dir:${a}`, `dir:${b}`, ...IOCS]);
  };
  for (const how of ["git", "dir"] as const) {
    const requires = await run(how, { "shared/base.toml": pyproject(SETUPTOOLS.replace('"setuptools>=61"', '"setuptools>=61", "freshly-published-backend==1.0.0"')) });
    assert.deepEqual(builds(requires), ["WS-DF-005 high app/pyproject.toml"], `[build-system] through the link (${how})`);
    assert.match(message(requires), /^The build of the Python project in app changed in this change \(pyproject\.toml\): /, how);
    const backendFile = await run(how, { "shared/backend.py": 'REQUIRES = ["fresh"]\n' });
    assert.deepEqual(builds(backendFile), ["WS-DF-005 high lib/pyproject.toml"], `a backend-path file through the link (${how})`);
    assert.match(message(backendFile), /^The build of the Python project in lib changed in this change \(backend-path\): /, how);
    assert.deepEqual(builds(await run(how, { "shared/notes.txt": "unrelated\n" })), [], `control: a file no link leads to (${how})`);
  }
});

/** Writes `files` under `d` (as validation-helpers.ts tempTree does, into a directory that exists). */
function tempTreeAt(d: string, files: Files): void {
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(d, rel)), { recursive: true });
    writeFileSync(join(d, rel), text);
  }
}

test("a build's key walks each path once per project: 32 hooks beside 40 links ask what each link leads to once, not once per hook", () => {
  // In memory, the files of one project: 32 hooks in hooks/, and 40 links there out of the project.
  const hooks = Array.from({ length: 32 }, (_, i) => `hooks/m${i}.py`);
  const links = Array.from({ length: 40 }, (_, i) => `hooks/s${i}.py`);
  const files = new Map<string, BuildEntry>([
    ["pyproject.toml", { kind: "file", bytes: Buffer.from(pyproject(HATCHLING, "0.1.0", `\n${hookTables(hooks)}`)) }],
    ["hooks", { kind: "dir", names: [...hooks, ...links].map((p) => p.slice("hooks/".length)).sort() }],
    ...hooks.map((p): [string, BuildEntry] => [p, { kind: "file", bytes: Buffer.from("x = 1\n") }]),
    ...links.map((p): [string, BuildEntry] => [p, { kind: "symlink", target: "../../shared/big.txt" }]),
  ]);
  const asked = new Map<string, number>();
  const count = (what: string): void => void asked.set(what, (asked.get(what) ?? 0) + 1);
  const build = localBuild({
    entry: (rel) => (count(rel), files.get(rel) ?? { kind: "missing" }),
    followed: (rel) => (count(`followed ${rel}`), "f".repeat(64)),
  });
  assert.equal(build.unreadable, false);
  // Each link once: before, once per hook beside it (32 x 40 = 1,280 times).
  for (const l of links) assert.equal(asked.get(`followed ${l}`), 1, l);
  // Each hook file read twice at most: as a hook, and as the walk to its directory; never once per neighbour.
  for (const h of hooks) assert.ok((asked.get(h) ?? 0) <= 2, `${h}: ${asked.get(h)}`);
  assert.match(JSON.stringify(build.inputs), /hooks\/s0\.py \[hooks\/s0\.py -> \.\.\/\.\.\/shared\/big\.txt\] outside the project => f{64}/);
});

test("diff reads what a build file's link leads to once per revision, however many projects reach it: a project and one nested in it", () => {
  // a/ names the hook sub/hooks/h.py, a/sub/ names hooks/h.py: both list the 10 links beside it, which lead out of both
  // projects to x/big.txt.
  const files = (version: string): Files => ({
    "a/pyproject.toml": pyproject(HATCHLING, version, `\n${hookTables(["sub/hooks/h.py"])}`),
    "a/sub/pyproject.toml": pyproject(HATCHLING, version, `\n${hookTables(["hooks/h.py"])}`),
    "a/sub/hooks/h.py": "x = 1\n",
    "x/big.txt": "big\n",
  });
  const links = Array.from({ length: 10 }, (_, i) => `a/sub/hooks/s${i}.py`);
  const repo = gitRepo([
    (d) => {
      tempTreeAt(d, files("0.1.0"));
      for (const l of links) symlinkSync("../../../x/big.txt", join(d, l));
    },
    (d) => tempTreeAt(d, files("0.2.0")),
  ]);
  const reads = new Map<string, number>();
  const counted = (t: Tree, side: string): Tree => ({ ...t, read: (p) => (reads.set(`${side} ${p}`, (reads.get(`${side} ${p}`) ?? 0) + 1), t.read(p)) });
  const r = diffTrees(counted(gitTree(repo, "HEAD~1"), "base"), counted(gitTree(repo, "HEAD"), "head"), testCtx());
  assert.deepEqual(r.findings.map((f) => `${f.ruleId} ${f.severity} ${f.file}`).sort(), ["WS-DF-006 medium a/pyproject.toml", "WS-DF-006 medium a/sub/pyproject.toml"]);
  // Both projects followed every link (before, each read and hashed it: twice per revision).
  for (const side of ["base", "head"]) for (const l of links) assert.equal(reads.get(`${side} ${l}`), 1, `${side} ${l}`);
});

test("diff: a hook path or backend-path entry that climbs with .. from a symbolic link is not read, so the build is unreadable, high on every change", async () => {
  // app/lnk -> ../shared/dir, so app/lnk/../h.py opens shared/h.py; read as text it would be app/h.py.
  const shared: Files = { "app/h.py": "x = 1\n", "shared/h.py": "x = 1\n", "shared/dir/h.py": "x = 1\n", "app/_build/backend.py": "REQUIRES = []\n", "shared/_build/backend.py": "REQUIRES = []\n" };
  const withHook = (version: string, hook: string): Files => ({ ...shared, "app/pyproject.toml": pyproject(HATCHLING, version, `\n${hookTables([hook])}`) });
  const withBackend = (version: string, entry: string): Files => ({
    ...shared,
    "app/pyproject.toml": pyproject(`[build-system]\nrequires = []\nbuild-backend = "backend"\nbackend-path = [${JSON.stringify(entry)}]\n\n`, version),
  });
  const run = async (how: "git" | "dir", before: Files, after: Files, link: boolean): Promise<Run> => {
    const put = (d: string, files: Files): void => {
      tempTreeAt(d, files);
      if (link) symlinkSync("../shared/dir", join(d, "app/lnk"));
      else tempTreeAt(d, { "app/lnk/keep": "\n" });
    };
    if (how === "git") return cli(["diff", "HEAD~1", "HEAD", "--dir", gitRepo([(d) => put(d, before), (d) => tempTreeAt(d, after)]), ...IOCS]);
    const [a, b] = [mkdtempSync(join(tmpdir(), "ws-diffbuild-a-")), mkdtempSync(join(tmpdir(), "ws-diffbuild-b-"))];
    put(a, before);
    put(b, after);
    return cli(["diff", `dir:${a}`, `dir:${b}`, ...IOCS]);
  };
  const HIGH_APP = "WS-DF-005 high app/pyproject.toml";
  for (const how of ["git", "dir"] as const) {
    for (const [what, files, path] of [
      ["a hook", withHook, "lnk/../h.py"],
      ["a backend-path entry", withBackend, "lnk/../_build"],
    ] as const) {
      // A version bump: the files are the same, but what the path opens was not read, so the build is changed.
      const bump = await run(how, files("0.1.0", path), files("0.2.0", path), true);
      assert.deepEqual(builds(bump), [HIGH_APP], `${what} (${how})`);
      assert.match(message(bump), new RegExp(`not read in full, so counted as unreadable: ${escapeRegExp(path)} climbs with "\\.\\." from a symbolic link, which the OS resolves from where the link points\\): `), `${what} (${how})`);
      // Control: app/lnk a directory, not a link: the path is read, and a version bump keeps the build.
      assert.deepEqual(builds(await run(how, files("0.1.0", path), files("0.2.0", path), false)), [], `${what}, no link (${how})`);
    }
  }
});
