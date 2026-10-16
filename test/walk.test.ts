/**
 * The shared walker (src/walk.ts) against the lockfilesIn it replaced in main.ts, and its virtual-environment rule.
 *
 * npm output must not change now that main.ts finds lockfiles with the walker, so `referenceLockfilesIn` below is
 * lockfilesIn copied verbatim from src/main.ts as it was before the walker replaced it (names compared folded,
 * as npm on macOS and Windows reads them), and npmLockfiles over walkTree must return the same lockfiles and push the
 * same findings, in the same order, on: every directory under test/fixtures, the walker cases of
 * test/golden-npm-identical.test.ts, and seeded random trees of lockfile names, package.json files, node_modules and
 * .git entries, symlinks (to files, directories, outside the root, dangling, looping) and unreadable directories. The
 * real CLI is checked against the same reference on some of them, so main.ts cannot drift from the copy unnoticed.
 *
 * Virtual environments: an untracked venv in a git work tree is skipped and named in a note; a tracked venv shape is
 * walked like any directory, however deep its tracked file; with no work tree or a failing git, a venv is walked
 * without its site-packages, symlinks in it are not reported, and watched names in site-packages are WS-SK-002. A tree
 * without a venv shape never runs git. Nothing here needs python3, uv or pip; git is run for real in temporary
 * repositories, with no global or system configuration.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import type { Dirent } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, posix, relative } from "node:path";
import { LOCKFILE_NAMES } from "../src/lockfile/index.js";
import type { ParsedLockfile } from "../src/lockfile/index.js";
import { run } from "../src/main.js";
import { discoverPython, gitForPython } from "../src/python/discover.js";
import { parseLockfileAnyCase } from "../src/scan.js";
import { fold, gitRoot } from "../src/tree.js";
import { stripBom } from "../src/fsutil.js";
import type { Finding } from "../src/types.js";
import { UsageError } from "../src/types.js";
import { UNSUPPORTED_LOCKFILES, declaresDependencies, gitStateOf, isWatchedName, lockfileProblem, lockfilesIn, npmLockfiles, venvShape, walkTree, type GitRun, type TreeWalk } from "../src/walk.js";
import { FIXTURES, fakeIO } from "./helpers.js";

/* ---- lockfilesIn, copied verbatim from src/main.ts as it was before the walker replaced it ---- */

function referenceLockfilesIn(root: string, findings: Finding[]): ParsedLockfile[] {
  if (!statSync(root, { throwIfNoEntry: false })?.isDirectory()) throw new UsageError(`${root} is not a directory`);
  const out: ParsedLockfile[] = [];
  const lockDirs = new Set<string>();
  const manifests: string[] = [];
  // By folded name: npm on macOS and Windows reads PACKAGE-LOCK.JSON as package-lock.json.
  const watched = [...LOCKFILE_NAMES, ...UNSUPPORTED_LOCKFILES, "package.json"];
  const stack = ["."];
  while (stack.length > 0) {
    const dir = stack.pop() as string;
    let entries: Dirent[];
    try {
      entries = readdirSync(join(root, dir), { withFileTypes: true });
    } catch (err) {
      findings.push(lockfileProblem(dir, `the directory could not be listed (${(err as NodeJS.ErrnoException).code ?? "error"}), so any lockfile or package.json in it is unchecked`));
      continue;
    }
    // Folded name -> the first entry with it: a second one is the same file on a case-insensitive disk.
    const seen = new Map<string, string>();
    for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (e.name === ".git" || e.name === "node_modules") continue;
      const rel = posix.join(dir, e.name);
      const name = fold(e.name);
      if (e.isDirectory()) stack.push(rel);
      if (e.isSymbolicLink()) {
        let isDir: boolean | undefined;
        try {
          isDir = statSync(join(root, rel), { throwIfNoEntry: false })?.isDirectory();
        } catch (err) {
          // A loop (ELOOP) or an unreadable target: report it, as a crash could never be baselined.
          findings.push(lockfileProblem(rel, `it is a symlink that could not be resolved (${(err as NodeJS.ErrnoException).code ?? "error"})`));
        }
        if (isDir) findings.push(lockfileProblem(rel, "it is a symlinked directory, which wormsign does not follow, so any lockfile or package.json in it is unchecked"));
      }
      if (!watched.includes(name)) continue;
      const twin = seen.get(name);
      if (twin === undefined) seen.set(name, rel);
      else findings.push(lockfileProblem(rel, `${twin} has the same name in another case or Unicode form, and a case-insensitive disk (macOS, Windows) holds only one of them, so which one an install reads is not known`));
      if (e.isSymbolicLink()) {
        findings.push(lockfileProblem(rel, "it is a symlink, which wormsign does not follow"));
        lockDirs.add(dir);
      } else if (!e.isFile()) {
        continue;
      } else if (name === "package.json") {
        manifests.push(rel);
      } else if (UNSUPPORTED_LOCKFILES.includes(name)) {
        findings.push(lockfileProblem(rel, "bun lockfiles are not supported"));
        lockDirs.add(dir);
      } else {
        lockDirs.add(dir);
        let lock: ParsedLockfile | undefined;
        try {
          lock = parseLockfileAnyCase(rel, stripBom(readFileSync(join(root, rel), "utf8")));
        } catch (err) {
          findings.push(lockfileProblem(rel, `it could not be parsed (${(err as Error).message})`));
          continue;
        }
        if (lock) out.push(lock);
      }
    }
  }
  // Directory -> its manifest, as written.
  const declaring = new Map<string, string>();
  for (const m of manifests) {
    let deps: boolean | undefined;
    try {
      deps = declaresDependencies(readFileSync(join(root, m), "utf8"));
    } catch (err) {
      findings.push(lockfileProblem(m, `it could not be read (${(err as NodeJS.ErrnoException).code ?? "error"}), so its dependencies are unknown`));
      continue;
    }
    if (deps === undefined) findings.push(lockfileProblem(m, "it is not a valid JSON object, so its dependencies are unknown"));
    else if (deps) declaring.set(posix.dirname(m), m);
  }
  for (const lock of out) {
    if (lock.packages.length === 0 && declaring.has(posix.dirname(lock.file))) {
      findings.push(lockfileProblem(lock.file, "no packages were read from it although package.json declares dependencies"));
    }
  }
  const lockedAbove = (dir: string): boolean => lockDirs.has(dir) || (dir !== "." && lockedAbove(posix.dirname(dir)));
  for (const [dir, m] of declaring) {
    if (!lockedAbove(dir)) {
      findings.push(lockfileProblem(m, "it declares dependencies but there is no lockfile in its directory or a parent, so the versions an install would pick cannot be verified"));
    }
  }
  return out;
}

/* ---- helpers ---- */

const tmp = (prefix: string): string => mkdtempSync(join(tmpdir(), prefix));
/** git with no global or system configuration, and not above the temporary directory. */
const GIT_ENV = (root: string): Record<string, string | undefined> => ({
  PATH: process.env["PATH"],
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CEILING_DIRECTORIES: dirname(root),
  HOME: root,
});
function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", ["-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...args], { cwd, env: GIT_ENV(cwd), encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}
/** Writes files (text, or { link } for a symlink), creating directories. */
function write(root: string, files: Record<string, string | { link: string }>): void {
  for (const [p, v] of Object.entries(files)) {
    mkdirSync(dirname(join(root, p)), { recursive: true });
    if (typeof v === "string") writeFileSync(join(root, p), v);
    else symlinkSync(v.link, join(root, p));
  }
}
/** Both implementations on one root: same lockfiles, same findings, same order. */
function same(root: string, label: string): { findings: Finding[]; locks: ParsedLockfile[] } {
  const a: Finding[] = [];
  const b: Finding[] = [];
  const la = referenceLockfilesIn(root, a);
  const lb = npmLockfiles(root, walkTree(root, { env: GIT_ENV(root) }), b);
  assert.deepStrictEqual(lb, la, `${label}: lockfiles`);
  assert.deepStrictEqual(b, a, `${label}: findings`);
  return { findings: a, locks: la };
}

const lockfileFixture = (p: string): string => readFileSync(join(FIXTURES, "lockfiles", p), "utf8");
const npmLock = (pkgs: [string, string][]): string => {
  const packages: Record<string, unknown> = { "": { name: "w" } };
  for (const [n, v] of pkgs) packages[`node_modules/${n}`] = { version: v, resolved: `https://registry.npmjs.org/${n}/-/${n}-${v}.tgz`, integrity: `sha512-${Buffer.from(`${n}@${v}`).toString("base64")}` };
  return `${JSON.stringify({ lockfileVersion: 3, packages }, null, 2)}\n`;
};
const manifest = (deps: Record<string, string> = {}): string => `${JSON.stringify({ name: "w", ...(Object.keys(deps).length > 0 ? { dependencies: deps } : {}) })}\n`;

/** The walker cases of test/golden-npm-identical.test.ts. */
const GOLDEN_WALKER: Record<string, Record<string, string | { link: string }>> = {
  "(bun lockfiles)": { "bun.lock": '{ "lockfileVersion": 1 }\n', "old/bun.lockb": "golden\n" },
  "(package.json with dependencies, no lockfile)": { "package.json": manifest({ "left-pad": "^1.3.0" }) },
  "(package.json without dependencies, no lockfile)": { "package.json": manifest() },
  "(package.json that is not an object)": { "package.json": "[1, 2]\n" },
  "(unparseable yarn.lock)": { "yarn.lock": '# yarn lockfile v1\n\n"left-pad@^1.3.0":\n  version "1.3.0"\n  golden "x"\n', "package.json": manifest({ "left-pad": "^1.3.0" }) },
  "(empty lockfile beside dependencies)": { "package-lock.json": npmLock([]), "package.json": manifest({ "left-pad": "^1.3.0" }) },
  "(nested projects)": {
    "a/package-lock.json": npmLock([["golden-nested", "1.0.0"]]),
    "a/package.json": manifest({ "golden-nested": "1.0.0" }),
    "a/c/package.json": manifest({ "golden-nested": "1.0.0" }),
    "b/package.json": manifest({ "left-pad": "^1.3.0" }),
  },
  "(lockfile under node_modules)": {
    "package-lock.json": npmLock([["golden-top", "1.0.0"]]),
    "node_modules/dep/package-lock.json": npmLock([["golden-hidden", "1.0.0"]]),
    "node_modules/dep/package.json": manifest({ "golden-hidden": "1.0.0" }),
  },
  "(symlinks)": {
    "real/package-lock.json": npmLock([["golden-real", "1.0.0"]]),
    "package-lock.json": { link: "real/package-lock.json" },
    linked: { link: "real" },
    loop: { link: "loop" },
  },
};

/** A small seeded generator (mulberry32), so a failing tree can be rebuilt from its seed. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const NAMES = ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb", "package.json", "node_modules", ".git", "a", "B", "b", "é", "e\u0301", "z.txt", "sub", "Package.json", "uv.lock"];
const unreadable = typeof process.getuid === "function" && process.getuid() !== 0;

/** A random tree under root: lockfile and package.json texts (valid and not), directories, symlinks, unreadable directories. */
function randomTree(root: string, seed: number): void {
  const r = rng(seed);
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(r() * xs.length)] as T;
  const texts: Record<string, string[]> = {
    "package-lock.json": [lockfileFixture("npm/package-lock.json"), npmLock([["x", "1.0.0"]]), npmLock([]), "{", "\uFEFF" + npmLock([["y", "2.0.0"]])],
    "npm-shrinkwrap.json": [npmLock([["s", "1.0.0"]]), "[]"],
    "yarn.lock": [lockfileFixture("yarn1/yarn.lock"), lockfileFixture("berry/yarn.lock"), '"a@^1":\n  golden "x"\n'],
    "pnpm-lock.yaml": [lockfileFixture("pnpm/pnpm-lock.yaml"), "lockfileVersion: [\n"],
    "bun.lock": ["{}\n"],
    "bun.lockb": ["x"],
    "package.json": [manifest({ x: "^1" }), manifest(), "[1]", "{", '{"devDependencies":{"d":"1"}}'],
  };
  const fill = (dir: string, depth: number): void => {
    const used = new Set<string>();
    const n = Math.floor(r() * (depth === 0 ? 7 : 5));
    for (let i = 0; i < n; i++) {
      const name = pick(NAMES);
      if (used.has(name)) continue;
      used.add(name);
      const p = join(dir, name);
      const kind = r();
      try {
        if (kind < 0.55 && texts[name]) writeFileSync(p, pick(texts[name]!));
        else if (kind < 0.75 && depth < 3) {
          mkdirSync(p);
          fill(p, depth + 1);
          if (unreadable && r() < 0.06) chmodSync(p, 0o000);
        } else if (kind < 0.9) symlinkSync(pick(["a", "../a", "missing", name, "package-lock.json", "/", "/nonexistent-ws", "sub", ".."]), p);
        else writeFileSync(p, "text\n");
      } catch {
        // a name the file system folds onto another (e and e + U+0301 on APFS): skip it
      }
    }
  };
  fill(root, 0);
}

/* ---- npm behaviour: identical to lockfilesIn ---- */

test("walk: npmLockfiles over walkTree equals lockfilesIn on every directory under test/fixtures", () => {
  let roots = 0;
  const visit = (dir: string): void => {
    same(dir, relative(FIXTURES, dir) || ".");
    roots++;
    for (const e of readdirSync(dir, { withFileTypes: true })) if (e.isDirectory()) visit(join(dir, e.name));
  };
  visit(FIXTURES);
  assert.ok(roots > 100, `${roots} roots`);
});

test("walk: npmLockfiles over walkTree equals lockfilesIn on the golden test's walker cases", () => {
  for (const [label, files] of Object.entries(GOLDEN_WALKER)) {
    const root = tmp("ws-walk-golden-");
    write(root, files);
    const r = same(root, label);
    if (label === "(symlinks)") assert.equal(r.findings.length, 3, "the symlinked lockfile, the symlinked directory and the loop");
  }
});

test("walk: npmLockfiles over walkTree equals lockfilesIn on 300 seeded random trees", () => {
  let findings = 0;
  for (let seed = 1; seed <= 300; seed++) {
    const root = tmp("ws-walk-rand-");
    randomTree(root, seed);
    try {
      findings += same(root, `seed ${seed}`).findings.length;
    } finally {
      spawnSync("chmod", ["-R", "u+rwX", root]);
    }
  }
  assert.ok(findings > 100, `the trees exercise the finding paths (${findings} findings)`);
});

test("walk: lockfilesIn(root) is the drop-in replacement, and a root that is not a directory is a usage error", () => {
  const root = tmp("ws-walk-drop-");
  write(root, GOLDEN_WALKER["(nested projects)"]!);
  const a: Finding[] = [];
  const b: Finding[] = [];
  assert.deepStrictEqual(lockfilesIn(root, b, { env: GIT_ENV(root) }), referenceLockfilesIn(root, a));
  assert.deepStrictEqual(b, a);
  writeFileSync(join(root, "file"), "x");
  assert.throws(() => walkTree(join(root, "file")), (e: unknown) => e instanceof UsageError && /is not a directory/.test((e as Error).message));
  assert.throws(() => walkTree(join(root, "missing")), UsageError);
});

test("walk: npm names are folded as lockfilesIn folds them: PACKAGE-LOCK.JSON is read, and a manifest is named as written", () => {
  const upper = tmp("ws-walk-fold-");
  write(upper, { "PACKAGE-LOCK.JSON": npmLock([["x", "1.0.0"]]), "PACKAGE.JSON": manifest({ x: "1.0.0" }), "Bun.Lockb": "x" });
  const u = same(upper, "upper-case names");
  assert.deepStrictEqual(u.locks.map((l) => [l.file, l.packages.length]), [["PACKAGE-LOCK.JSON", 1]]);
  assert.deepStrictEqual(u.findings.map((f) => f.message), ["Cannot verify soak time for the packages in Bun.Lockb: bun lockfiles are not supported"]);
  const unlocked = tmp("ws-walk-fold-");
  write(unlocked, { "sub/Package.json": manifest({ x: "^1" }) });
  assert.deepStrictEqual(same(unlocked, "unlocked manifest").findings.map((f) => f.file), ["sub/Package.json"]);
});

test("walk: two npm names in one directory that fold alike are each reported after the first, as lockfilesIn reports them", () => {
  // Synthetic events, of types that read no file: a case-insensitive disk cannot hold both names.
  type Ev = { entry: { dir: string; name: string; rel: string; type: "dir" | "other" } };
  const ev = (dir: string, name: string, type: "dir" | "other"): Ev => ({ entry: { dir, name, rel: posix.join(dir, name), type } });
  const events = [ev(".", "Package.json", "dir"), ev(".", "package.json", "dir"), ev(".", "yarn.lock", "other"), ev(".", "YARN.LOCK", "other"), ev("a", "PACKAGE.JSON", "dir"), ev("a", "b", "dir"), ev("a/b", "package.json", "dir")];
  const root = tmp("ws-walk-twin-");
  const walk: TreeWalk = { root, events, entries: events.map((e) => e.entry), findings: [], notes: [], venvs: { skipped: [], partial: [] }, git: () => ({ kind: "no-work-tree" }), gitIgnored: () => undefined };
  const got: Finding[] = [];
  assert.deepStrictEqual(npmLockfiles(root, walk, got), []);
  const twin = "has the same name in another case or Unicode form, and a case-insensitive disk (macOS, Windows) holds only one of them, so which one an install reads is not known";
  assert.deepStrictEqual(got.map((f) => f.message), [
    `Cannot verify soak time for the packages in package.json: Package.json ${twin}`,
    `Cannot verify soak time for the packages in YARN.LOCK: yarn.lock ${twin}`,
  ]);
  // A real tree, against the reference: on a case-insensitive disk PACKAGE.JSON overwrites package.json, and nothing is a twin.
  const real = tmp("ws-walk-twin-");
  write(real, { "package.json": manifest(), "yarn.lock": lockfileFixture("yarn1/yarn.lock"), "PACKAGE.JSON": manifest({ x: "^1" }) });
  const r = same(real, "twins on disk");
  assert.equal(r.findings.some((f) => f.message.includes(twin)), readdirSync(real).length === 3, "a twin is reported exactly when the disk holds both");
});

/** Stub package-manager binaries, so --config-only runs the same everywhere. */
function stubBin(): string {
  const d = tmp("ws-walk-bin-");
  for (const [m, v] of Object.entries({ npm: "11.10.0", pnpm: "11.16.0", yarn: "4.10.3", bun: "1.3.0" })) {
    writeFileSync(join(d, m), `#!/bin/sh\necho ${v}\n`);
    chmodSync(join(d, m), 0o755);
  }
  return d;
}

test("walk: the CLI's soak, which finds lockfiles with the walker, reports what the reference reports", async () => {
  const bin = stubBin();
  const roots: string[] = [];
  for (const files of Object.values(GOLDEN_WALKER)) {
    const root = tmp("ws-walk-cli-");
    write(root, files);
    roots.push(root);
  }
  for (let seed = 1; seed <= 40; seed++) {
    const root = tmp("ws-walk-cli-");
    randomTree(root, seed);
    roots.push(root);
  }
  let compared = 0;
  for (const root of roots) {
    const expected: Finding[] = [];
    referenceLockfilesIn(root, expected);
    const home = tmp("ws-walk-home-");
    const io = fakeIO({ env: { PATH: bin, HOME: home, XDG_CONFIG_HOME: join(home, ".config") } });
    try {
      const code = await run(["soak", root, "--config-only", "--format", "json", "--fail-on", "never"], io);
      // checkSoakConfig stops on a settings file it cannot read (a symlinked package.json): nothing to compare.
      if (code === 2 && /cannot read .*package-manager settings would be unknown/.test(io.err)) continue;
      assert.equal(code, 0, io.err);
      compared++;
      const got = (JSON.parse(io.out) as { findings: Finding[] }).findings.filter((f) => f.key.startsWith("lockfile:"));
      const key = (f: Finding): string => `${f.fingerprint} ${f.message}`;
      assert.deepStrictEqual(got.map(key).sort(), expected.map(key).sort(), root);
    } finally {
      spawnSync("chmod", ["-R", "u+rwX", root]);
    }
  }
  assert.ok(compared >= 25, `${compared} trees compared`);
});

/* ---- virtual environments ---- */

/** A venv shape as `python3 -m venv` writes one on Linux/macOS: pyvenv.cfg, bin/python linking outside, lib64 -> lib. */
const VENV = (at: string, py = "python3.12"): Record<string, string | { link: string }> => ({
  [`${at}/pyvenv.cfg`]: "home = /usr/bin\ninclude-system-site-packages = false\nversion = 3.12.3\n",
  [`${at}/.gitignore`]: "*\n",
  [`${at}/bin/python`]: { link: "/usr/bin/python3" },
  [`${at}/bin/activate`]: "# activate\n",
  [`${at}/lib64`]: { link: "lib" },
  [`${at}/lib/${py}/site-packages/pip/__init__.py`]: "__version__ = '26.2.1'\n",
  [`${at}/lib/${py}/site-packages/numpy/random/_examples/cython/setup.py`]: "from setuptools import setup\n",
  [`${at}/lib/${py}/site-packages/pkg/package.json`]: manifest({ x: "1" }),
});

const entryRels = (w: TreeWalk): string[] => w.entries.map((e) => e.rel);

test("walk: an untracked venv in a git work tree is skipped whole and named in a note; tracked files beside it are read", () => {
  const root = tmp("ws-walk-venv-");
  write(root, { "uv.lock": "version = 1\n", "package.json": manifest(), ...VENV(".venv"), ...VENV("svc/py/env", "python3.11") });
  git(root, "init", "-q");
  git(root, "add", "uv.lock", "package.json");
  git(root, "commit", "-q", "-m", "x");
  const w = walkTree(root, { env: GIT_ENV(root) });
  assert.deepStrictEqual(w.venvs, { skipped: [".venv", "svc/py/env"], partial: [] });
  assert.ok(!entryRels(w).some((r) => r.startsWith(".venv/") || r.startsWith("svc/py/env/")), "nothing under a skipped venv is visited");
  assert.ok(entryRels(w).includes("uv.lock"));
  assert.deepStrictEqual(w.findings, [], "bin/python and lib64 are not reported: the venv is not walked");
  assert.equal(w.notes.length, 1);
  assert.match(w.notes[0]!, /2 virtual environment\(s\) not read: no file in them is tracked by git.*: \.venv, svc\/py\/env$/);
  assert.equal(w.git().kind, "tracked");
});

test("walk: a venv shape with a tracked file anywhere below it is walked like any directory (a young lock in it is read)", () => {
  const root = tmp("ws-walk-venv-");
  // pyvenv.cfg committed next to a lock: the shape, and the lock, are part of the reviewed tree.
  write(root, { "app/pyvenv.cfg": "home = /usr/bin\n", "app/lib/python3.12/site-packages/.keep": "", "app/uv.lock": "version = 1\n" });
  // Only a file deep inside is tracked; the venv's own top-level files are not (they could be ignored).
  write(root, { ...VENV("tools"), "tools/proj/uv.lock": "version = 1\n", "tools/proj/sub/deeper/requirements.txt": "x\n" });
  git(root, "init", "-q");
  git(root, "add", "-f", "app", "tools/proj/sub/deeper/requirements.txt");
  git(root, "commit", "-q", "-m", "x");
  const w = walkTree(root, { env: GIT_ENV(root) });
  assert.deepStrictEqual(w.venvs, { skipped: [], partial: [] });
  for (const r of ["app/uv.lock", "app/pyvenv.cfg", "tools/proj/uv.lock", "tools/lib/python3.12/site-packages/pkg/package.json"]) assert.ok(entryRels(w).includes(r), r);
  // Walked like any directory: its symlinks are reported as everywhere else.
  assert.ok(w.findings.some((f) => f.file === "tools/lib64" && /symlinked directory/.test(f.message)));
  assert.deepStrictEqual(w.notes, []);
});

test("walk: a venv inside a submodule (a gitlink at or above it) is committed content, not skipped", () => {
  const root = tmp("ws-walk-venv-");
  const sub = tmp("ws-walk-subrepo-");
  write(sub, { "README": "x\n" });
  git(sub, "init", "-q");
  git(sub, "add", "README");
  git(sub, "commit", "-q", "-m", "x");
  git(root, "init", "-q");
  git(root, "-c", "protocol.file.allow=always", "submodule", "add", "-q", sub, "vendored");
  git(root, "commit", "-q", "-m", "x");
  write(root, { ...VENV("vendored/env"), "vendored/env/uv.lock": "version = 1\n" });
  const w = walkTree(root, { env: GIT_ENV(root) });
  assert.deepStrictEqual(w.venvs.skipped, []);
  assert.ok(entryRels(w).includes("vendored/env/uv.lock"));
});

test("walk: with no git work tree a venv is walked without its site-packages; watched names there are WS-SK-002", () => {
  const root = tmp("ws-walk-venv-");
  write(root, { ...VENV(".venv"), ".venv/requirements.txt": "x\n", "uv.lock": "version = 1\n" });
  const w = walkTree(root, { env: GIT_ENV(root) });
  assert.equal(w.git().kind, "no-work-tree");
  assert.deepStrictEqual(w.venvs, { skipped: [], partial: [".venv"] });
  const rels = entryRels(w);
  assert.ok(rels.includes(".venv/requirements.txt"), "outside site-packages: read");
  assert.ok(rels.includes(".venv/bin/python") && rels.includes(".venv/lib64"), "symlinks are entries");
  assert.ok(!rels.some((r) => r.includes("site-packages/")), "site-packages is not walked");
  assert.ok(w.entries.filter((e) => e.rel.startsWith(".venv/")).every((e) => e.venv === ".venv"));
  // No symlink finding for bin/python or lib64; one finding for each watched name in site-packages.
  assert.deepStrictEqual(
    w.findings.map((f) => f.file),
    [".venv/lib/python3.12/site-packages/pkg/package.json", ".venv/lib/python3.12/site-packages/numpy/random/_examples/cython/setup.py"],
  );
  for (const f of w.findings) {
    assert.equal(f.ruleId, "WS-SK-002");
    assert.match(f.message, /inside \.venv, a directory that looks like a virtual environment, whose site-packages is not read \(the scanned root is not in a git work tree/);
  }
  assert.match(w.notes.join("\n"), /the scanned root is not in a git work tree, so 1 directory\(ies\) that look like virtual environments were read without their site-packages.*: \.venv$/);
});

test("walk: a Windows venv (Lib/site-packages) and a nested venv are found; shapes without both parts are not venvs", () => {
  const root = tmp("ws-walk-venv-");
  write(root, {
    "win/pyvenv.cfg": "home = C:\\Python312\n",
    "win/Lib/site-packages/x/pyproject.toml": "[project]\n",
    "win/Scripts/python.exe": "MZ",
    "outer/pyvenv.cfg": "home = /usr/bin\n",
    "outer/lib/python3.12/site-packages/.keep": "",
    "outer/proj/inner/pyvenv.cfg": "home = /usr/bin\n",
    "outer/proj/inner/lib/python3.13/site-packages/uv.lock": "version = 1\n",
    "nolib/pyvenv.cfg": "home = /usr/bin\n",
    "nolib/lib/site-packages/uv.lock": "version = 1\n",
    "cfgdir/pyvenv.cfg/x": "",
    "cfgdir/lib/python3.12/site-packages/uv.lock": "version = 1\n",
  });
  assert.deepStrictEqual(venvShape(root, "win"), ["win/Lib/site-packages"]);
  assert.equal(venvShape(root, "nolib"), undefined, "lib/site-packages without python*: not a venv");
  assert.equal(venvShape(root, "cfgdir"), undefined, "pyvenv.cfg must be a file");
  const w = walkTree(root, { env: GIT_ENV(root) });
  assert.deepStrictEqual(w.venvs.partial.sort(), ["outer", "outer/proj/inner", "win"]);
  assert.deepStrictEqual(w.findings.map((f) => f.file).sort(), ["outer/proj/inner/lib/python3.13/site-packages/uv.lock", "win/Lib/site-packages/x/pyproject.toml"]);
  assert.ok(entryRels(w).includes("nolib/lib/site-packages/uv.lock") && entryRels(w).includes("cfgdir/lib/python3.12/site-packages/uv.lock"), "not venvs: walked");
});

test("walk: a failing git is WS-SK-002 for each venv shape, which is then walked without its site-packages", () => {
  const root = tmp("ws-walk-venv-");
  mkdirSync(join(root, ".git"));
  write(root, VENV("env"));
  const bin = tmp("ws-walk-gitbin-");
  writeFileSync(join(bin, "git"), "#!/bin/sh\necho \"fatal: detected dubious ownership in repository at '$PWD'\" >&2\nexit 128\n");
  chmodSync(join(bin, "git"), 0o755);
  const w = walkTree(root, { env: { PATH: bin } });
  const g = w.git();
  assert.equal(g.kind, "git-error");
  assert.match(g.kind === "git-error" ? g.error : "", /dubious ownership/);
  assert.deepStrictEqual(w.venvs, { skipped: [], partial: ["env"] });
  assert.equal(w.findings[0]?.file, "env");
  assert.match(w.findings[0]?.message ?? "", /looks like a virtual environment, and git failed \(fatal: detected dubious ownership/);
  assert.ok(w.findings.slice(1).every((f) => /site-packages is not read \(git failed/.test(f.message)));
  assert.match(w.notes.join("\n"), /^git failed, so 1 directory\(ies\)/);
});

test("walk: git runs only when a venv shape is found or the git state is asked for, and at most twice", () => {
  const calls: string[][] = [];
  const fake: GitRun = (args) => {
    calls.push(args);
    return args[0] === "rev-parse" ? { status: 0, stdout: "true\n", stderr: "" } : { status: 0, stdout: "a\0", stderr: "" };
  };
  const root = tmp("ws-walk-nogit-");
  write(root, GOLDEN_WALKER["(nested projects)"]!);
  const w = walkTree(root, { git: fake });
  assert.deepStrictEqual(calls, [], "no venv shape: git is not run");
  w.git();
  w.git();
  assert.deepStrictEqual(calls, [["rev-parse", "--is-inside-work-tree"], ["ls-files", "-z"]]);
  write(root, VENV("v"));
  calls.length = 0;
  walkTree(root, { git: fake });
  assert.equal(calls.length, 2);
});

test("walk: gitStateOf reads each git outcome by the git rule", () => {
  const root = tmp("ws-walk-state-");
  const stub = (rev: ReturnType<GitRun>, ls?: ReturnType<GitRun>): GitRun => (args) => (args[0] === "rev-parse" ? rev : (ls ?? { status: 0, stdout: "x\0y/z\0", stderr: "" }));
  assert.deepStrictEqual(gitStateOf(root, stub({ status: 0, stdout: "true\n", stderr: "" })), { kind: "tracked", tracked: new Set(["x", "y/z"]) });
  assert.deepStrictEqual(gitStateOf(root, stub({ status: 0, stdout: "false\n", stderr: "" })), { kind: "no-work-tree" });
  assert.deepStrictEqual(gitStateOf(root, stub({ status: 0, stdout: "true\n", stderr: "" }, { status: 0, stdout: "", stderr: "" })), { kind: "untracked-root" }, "a work tree tracking nothing under the root");
  assert.deepStrictEqual(gitStateOf(root, stub({ status: 128, stdout: "", stderr: "fatal: not a git repository (or any of the parent directories): .git\n" })), { kind: "no-work-tree" });
  assert.deepStrictEqual(gitStateOf(root, stub({ status: 128, stdout: "", stderr: "fatal: not a git repository (or any parent up to mount point /tmp)\n" })), { kind: "no-work-tree" });
  assert.deepStrictEqual(gitStateOf(root, stub({ status: 128, stdout: "", stderr: "fatal: not a git repository: '/nope'\n" })), { kind: "git-error", error: "fatal: not a git repository: '/nope'" });
  assert.deepStrictEqual(gitStateOf(root, stub({ status: 0, stdout: "true\n", stderr: "" }, { status: 1, stdout: "", stderr: "error: index file corrupt\n" })), { kind: "git-error", error: "error: index file corrupt" });
  const enoent = Object.assign(new Error("spawnSync git ENOENT"), { code: "ENOENT" });
  assert.deepStrictEqual(gitStateOf(root, stub({ status: null, stdout: "", stderr: "", error: enoent })), { kind: "no-work-tree" });
  mkdirSync(join(root, ".git"));
  assert.equal(gitStateOf(join(root), stub({ status: null, stdout: "", stderr: "", error: enoent })).kind, "git-error", "git missing beside a .git");
  // The real runner, in a real repository and outside one.
  const repo = tmp("ws-walk-real-");
  write(repo, { "a/b.txt": "x", "c d.txt": "y", "untracked": "z" });
  git(repo, "init", "-q");
  git(repo, "add", "a/b.txt", "c d.txt");
  assert.deepStrictEqual(walkTree(repo, { env: GIT_ENV(repo) }).git(), { kind: "tracked", tracked: new Set(["a/b.txt", "c d.txt"]) });
  assert.deepStrictEqual(walkTree(join(repo, "a"), { env: GIT_ENV(repo) }).git(), { kind: "tracked", tracked: new Set(["b.txt"]) }, "relative to the root, as ls-files lists from it");
  const plain = tmp("ws-walk-plain-");
  assert.deepStrictEqual(walkTree(plain, { env: GIT_ENV(plain) }).git(), { kind: "no-work-tree" });
});

test("walk: gitIgnored lists git's ignored paths only with a tracked set", () => {
  const repo = tmp("ws-walk-ign-");
  write(repo, { ".gitignore": ".venv/\n*.pyc\n", "x.pyc": "", ".venv/a": "", "kept": "" });
  git(repo, "init", "-q");
  git(repo, "add", ".gitignore", "kept");
  assert.deepStrictEqual(walkTree(repo, { env: GIT_ENV(repo) }).gitIgnored(), new Set([".venv/", "x.pyc"]));
  const plain = tmp("ws-walk-ign-");
  assert.equal(walkTree(plain, { env: GIT_ENV(plain) }).gitIgnored(), undefined);
});

test("walk: isWatchedName covers npm and Python inputs, not every Python file", () => {
  for (const [name, rel] of [["package.json", "package.json"], ["yarn.lock", "a/yarn.lock"], ["bun.lockb", "bun.lockb"], ["uv.lock", "uv.lock"], ["pylock.dev.toml", "pylock.dev.toml"], ["x.py.lock", "x.py.lock"], ["poetry.lock", "poetry.lock"], ["Pipfile", "Pipfile"], ["setup.py", "setup.py"], ["requirements-dev.txt", "requirements-dev.txt"], ["base.txt", "requirements/base.txt"], ["UV.LOCK", "UV.LOCK"], ["PACKAGE.JSON", "PACKAGE.JSON"], ["Yarn.Lock", "a/Yarn.Lock"]] as const) {
    assert.ok(isWatchedName(name, rel), name);
  }
  for (const [name, rel] of [["x.py", "x.py"], ["README.md", "README.md"], ["base.txt", "reqs/base.txt"], ["pip.conf", "pip.conf"]] as const) assert.ok(!isWatchedName(name, rel), name);
});

/* ---- found in review: an untracked root, locks in site-packages, where git runs from, npm's delta ---- */

test("walk: a root in another repository's work tree that git tracks nothing under is read as if there were no work tree", () => {
  // A third-party tarball extracted into an untracked directory of a repository and vetted with `wormsign soak vendor/pkg`.
  const outer = tmp("ws-walk-outer-");
  write(outer, { "README.md": "x\n" });
  git(outer, "init", "-q");
  git(outer, "add", "README.md");
  git(outer, "commit", "-q", "-m", "x");
  const proj = join(outer, "vendor", "pkg");
  write(proj, { "tools/pyvenv.cfg": "home = /usr/bin\n", "tools/lib/python3.12/site-packages/x.txt": "", "tools/uv.lock": "version = 1\n", "tools/pyproject.toml": '[project]\nname = "x"\ndependencies = ["six"]\n' });
  const env = { ...GIT_ENV(outer), HOME: outer };
  const w = walkTree(proj, { env });
  assert.deepStrictEqual(w.git(), { kind: "untracked-root" });
  assert.deepStrictEqual(w.venvs, { skipped: [], partial: ["tools"] });
  assert.ok(entryRels(w).includes("tools/uv.lock"), "the venv shape is read, except its site-packages");
  assert.match(w.notes.join("\n"), /^git tracks no file at or under the scanned root, so 1 directory\(ies\) that look like virtual environments were read without their site-packages.*: tools$/);
  const d = discoverPython(proj, { pypiIndex: "https://pypi.org/simple/", env, walk: w, uvConfigFiles: [], ancestors: false });
  assert.deepStrictEqual(d.locks.map((l) => l.file), ["tools/uv.lock"]);
  assert.deepStrictEqual(gitForPython(w, d.locks), { git: "no-work-tree" });
  // The same tree once committed is tracked, and its venv shape is committed content.
  git(outer, "add", "-f", "vendor");
  assert.equal(walkTree(proj, { env }).git().kind, "tracked");
});

test("walk: with no work tree a *.lock in a skipped site-packages is WS-SK-002 (a script's lock has any name)", () => {
  const root = tmp("ws-walk-venv-");
  write(root, { "tools/pyvenv.cfg": "home = /usr/bin\n", "tools/lib/python3.12/site-packages/deploy": "#!/usr/bin/env -S uv run --script\n", "tools/lib/python3.12/site-packages/deploy.lock": "version = 1\n", "tools/lib/python3.12/site-packages/Other.LOCK": "x\n", "tools/lib/python3.12/site-packages/dir.lock/x": "" });
  const w = walkTree(root, { env: GIT_ENV(root) });
  assert.deepStrictEqual(w.findings.map((f) => f.file).sort(), ["tools/lib/python3.12/site-packages/Other.LOCK", "tools/lib/python3.12/site-packages/deploy.lock"]);
});

test("walk: git is started from the filesystem root, so a git in the scanned tree never runs (an empty PATH entry is the working directory)", () => {
  const root = tmp("ws-walk-gitpath-");
  const marker = join(tmp("ws-walk-marker-"), "ran");
  write(root, { ...VENV("v"), git: `#!/bin/sh\necho ran > "${marker}"\n` });
  chmodSync(join(root, "git"), 0o755);
  const empty = tmp("ws-walk-emptybin-");
  // Proof the hazard is real: spawned from the tree with such a PATH, the committed git runs.
  spawnSync("git", ["--version"], { cwd: root, env: { PATH: `${empty}:` } });
  assert.ok(statSync(marker, { throwIfNoEntry: false })?.isFile(), "an empty PATH entry finds ./git");
  rmSync(marker);
  const w = walkTree(root, { env: { PATH: `${empty}:` } });
  assert.notEqual(w.git().kind, "tracked");
  assert.equal(statSync(marker, { throwIfNoEntry: false }), undefined, "walk.ts: the tree's git did not run");
  // tree.ts (--base) runs git the same way.
  const saved = process.env["PATH"];
  process.env["PATH"] = `${empty}:`;
  try {
    assert.throws(() => gitRoot(root), /not inside a git repository/);
  } finally {
    process.env["PATH"] = saved;
  }
  assert.equal(statSync(marker, { throwIfNoEntry: false }), undefined, "tree.ts: the tree's git did not run");
  // And with git on PATH, -C still runs it in the root.
  const repo = tmp("ws-walk-gitc-");
  write(repo, { "a.txt": "x" });
  git(repo, "init", "-q");
  git(repo, "add", "a.txt");
  assert.deepStrictEqual(walkTree(repo, { env: GIT_ENV(repo) }).git(), { kind: "tracked", tracked: new Set(["a.txt"]) });
});

test("walk: where npm output changes (the CHANGELOG says so): an untracked venv's package.json and lib64 symlink are not reported", () => {
  // An npm-only tree in a work tree, with an untracked .venv holding a package.json in site-packages and lib64 -> lib.
  const root = tmp("ws-walk-npmdelta-");
  write(root, { "package.json": manifest(), ...VENV(".venv") });
  git(root, "init", "-q");
  git(root, "add", "package.json");
  git(root, "commit", "-q", "-m", "x");
  const reference: Finding[] = [];
  referenceLockfilesIn(root, reference);
  // lockfilesIn read the venv: its lib64 is a symlinked directory, and site-packages/pkg/package.json declares a
  // dependency with no lockfile above it.
  assert.deepStrictEqual(reference.map((f) => f.file), [".venv/lib64", ".venv/lib/python3.12/site-packages/pkg/package.json"]);
  const got: Finding[] = [];
  const w = walkTree(root, { env: GIT_ENV(root) });
  npmLockfiles(root, w, got);
  assert.deepStrictEqual(got, [], "the walker skips the untracked venv whole: no lib64 finding");
  assert.deepStrictEqual(w.venvs.skipped, [".venv"]);
  assert.match(w.notes[0] ?? "", /1 virtual environment\(s\) not read: no file in them is tracked by git.*: \.venv$/);
});

test("walk: git runs with lazy fetching off and every transport refused, as src/tree.ts runs it", async () => {
  const { gitRunner } = await import("../src/walk.js");
  const tree = mkdtempSync(join(tmpdir(), "ws-walk-nofetch-tree-"));
  const bin = mkdtempSync(join(tmpdir(), "ws-walk-nofetch-bin-"));
  const log = join(bin, "log");
  writeFileSync(join(bin, "git"), `#!/bin/sh\nprintf '%s\\n' "GIT_NO_LAZY_FETCH=$GIT_NO_LAZY_FETCH" "$@" > "${log}"\necho true\n`);
  chmodSync(join(bin, "git"), 0o755);
  const r = gitRunner(tree, { PATH: bin })(["rev-parse", "--is-inside-work-tree"]);
  assert.equal(r.status, 0, r.stderr);
  const lines = readFileSync(log, "utf8").trim().split("\n");
  assert.equal(lines[0], "GIT_NO_LAZY_FETCH=1");
  const args = lines.slice(1);
  const at = args.indexOf("protocol.allow=never");
  assert.ok(at > 0 && args[at - 1] === "-c", args.join(" "));
  assert.ok(at < args.indexOf("rev-parse"), "before the command");
  assert.deepEqual(args.slice(-2), ["rev-parse", "--is-inside-work-tree"]);
});

test("exec: git and the package managers are found on PATH in node; one inside the scanned tree is never run", async () => {
  const { findProgram } = await import("../src/exec.js");
  const { gitRunner } = await import("../src/walk.js");
  const { installedVersion } = await import("../src/soak-config.js");
  const tree = mkdtempSync(join(tmpdir(), "ws-exec-tree-"));
  const marker = join(mkdtempSync(join(tmpdir(), "ws-exec-marker-")), "ran");
  mkdirSync(join(tree, "bin"));
  for (const name of ["git", "npm"]) {
    writeFileSync(join(tree, "bin", name), `#!/bin/sh\necho ran >> "${marker}"\necho 11.12.0\n`);
    chmodSync(join(tree, "bin", name), 0o755);
  }
  const env = { PATH: `${join(tree, "bin")}:${process.env["PATH"]}` };
  assert.match((findProgram("git", env, [tree]) as { refused: string }).refused, /^git on PATH is .*\/bin\/git, inside the scanned tree, so it was not run$/);
  const r = gitRunner(tree, env)(["rev-parse", "--is-inside-work-tree"]);
  assert.equal(r.error?.code, "EINTREE");
  assert.match(installedVersion("npm", tree, env).source, /^`npm --version` failed: npm on PATH is .*, inside the scanned tree, so it was not run$/);
  assert.equal(statSync(marker, { throwIfNoEntry: false }), undefined, "nothing from the tree ran");
  // Empty and relative entries are skipped; the first real match outside the tree is used, by its absolute path.
  const outside = mkdtempSync(join(tmpdir(), "ws-exec-out-"));
  writeFileSync(join(outside, "npm"), "#!/bin/sh\necho 11.12.0\n");
  chmodSync(join(outside, "npm"), 0o755);
  assert.deepEqual(findProgram("npm", { PATH: `::bin:${outside}` }, [tree]), { path: join(outside, "npm") });
  assert.deepEqual(installedVersion("npm", tree, { PATH: `:${outside}` }), { version: "11.12.0", source: "`npm --version`" });
  assert.deepEqual(findProgram("npm", { PATH: "" }, [tree]), { missing: "npm was not found on PATH" });
});
