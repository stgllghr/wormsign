/**
 * The one directory walk soak's discovery uses for every ecosystem: npm, pnpm, Yarn and bun lockfiles and package.json
 * (npmLockfiles below, which was main.ts's lockfilesIn before Python), and Python locks, manifests, scripts and requirements files
 * (src/python/discover.ts). One walk, so the two ecosystems see the same tree, the same skips and the same symlinks.
 *
 * What it visits, in exactly lockfilesIn's order (so npm output is unchanged; test/walk.test.ts compares the walker with
 * a copy of lockfilesIn, and test/golden-npm-identical.test.ts the CLI's npm output with a snapshot taken before it):
 * - depth first from the root, a directory's entries sorted with String.prototype.localeCompare, directories taken from
 *   a stack (so the last one listed is walked first);
 * - any entry named .git or node_modules is skipped, whatever it is;
 * - symlinks are never followed. One that resolves to a directory, or does not resolve at all, is reported here
 *   (WS-SK-002, lockfileProblem's wording and key); a directory that cannot be listed is reported too. What a consumer
 *   does with a symlink it watches by name is the consumer's.
 *
 * Virtual environments (docs/soak.md, "Manifests, scripts and virtual environments"). A directory other than the root is one only when
 * it holds a regular file pyvenv.cfg AND a directory lib/python<anything>/site-packages or Lib/site-packages; names
 * alone never count. Git decides what happens to it, by the git rule (gitStateOf):
 * - the root is in a git work tree and `git ls-files` succeeded: a venv none of whose files is tracked (no tracked path
 *   below it, and none at or above it that could hold it, such as a submodule) is skipped whole, and the note lists
 *   it. A venv shape with any tracked file below it is committed content: it is walked like any other directory;
 * - no work tree, a work tree that tracks no file at or under the root ("untracked-root": a tarball extracted into an
 *   ignored directory of another repository; git reviewed nothing here), or git failing: the venv is walked except its
 *   site-packages subtrees, symlinks in it are not reported (bin/python and lib64 link outside it in every real venv),
 *   and every watched name, and every *.lock (a script's lock is `<script>.lock` whatever its name), found in a
 *   skipped site-packages subtree (a lockfile, package.json, pyproject.toml, setup.py, a requirements file, ...) is
 *   WS-SK-002 "inside a directory that looks like a virtual environment, not read". A note says why; a git failure is
 *   WS-SK-002 for each such venv as well (what is reviewed is unknown).
 *   Limitation (for the docs): a skipped site-packages subtree is listed, not read, so what discovery finds only by
 *   content there (an extensionless uv-shebang script, a requirements file with another name) is not reported.
 * The root itself is never treated as a venv: soak never skips the tree it was asked to check.
 *
 * Not skipped (deliberately): an untracked nested git work tree or clone (a directory holding .git that git does not
 * track). A CI step could clone into the tree and install from there, so it is walked like any other directory; on a
 * developer's checkout with worktrees inside it, their files are reported again.
 *
 * npm output changes only where a venv shape is (the CHANGELOG says so): an untracked venv in a work tree is no longer read at all
 * (its package.json files and npm lockfiles, and its lib64 symlinked-directory finding, are gone; the note names it);
 * with no work tree, symlinks inside a venv are no longer reported; a git failure adds WS-SK-002 per venv. A tree
 * without a venv shape gives exactly lockfilesIn's output (test/walk.test.ts).
 *
 * Git runs at most twice per walk and only when needed (a venv shape was found, or a Python lock needs the tracked
 * set): `git rev-parse --is-inside-work-tree`, then `git ls-files -z`, in the root (`git -C <root>`) but started from
 * the filesystem root (from the scanned tree, an empty PATH entry, or Windows' search of the working directory, would
 * run a `git` committed there), with an argv array (no shell), stdin closed, LC_ALL=C (so "not a git repository" is
 * read in one language) and core.fsmonitor off (a repository's config cannot make ls-files run a command). A tree
 * without venvs never runs git, so npm runs are unchanged.
 */
import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, readdirSync, readFileSync, statSync } from "node:fs";
import { findProgram } from "./exec.js";
import type { Dirent } from "node:fs";
import { dirname, join, parse, posix, resolve } from "node:path";
import { LOCKFILE_NAMES } from "./lockfile/index.js";
import type { ParsedLockfile } from "./lockfile/index.js";
import { isPythonInputName } from "./python/manifest.js";
import { parseLockfileAnyCase } from "./scan.js";
import { stripBom } from "./fsutil.js";
import { fold, NO_FETCH } from "./tree.js";
import type { Finding } from "./types.js";
import { UsageError, makeFinding } from "./types.js";

/* ------------------------------------------------------------------ *
 * Lockfile discovery. Anything that hides a lockfile from the gate is
 * a failure, never a note: silence must not read as "verified".
 * ------------------------------------------------------------------ */

export const UNSUPPORTED_LOCKFILES = ["bun.lock", "bun.lockb"];

/** Keyed on the reason too, so a baseline entry for one problem with a file does not hide a different one. */
export function lockfileProblem(file: string, why: string): Finding {
  return makeFinding({ ruleId: "WS-SK-002", severity: "high", message: `Cannot verify soak time for the packages in ${file}: ${why}`, file, key: `lockfile:${file} ${why}` });
}

/**
 * Does this package.json text declare dependencies that an install would fetch? undefined when it is
 * not a JSON object, so the caller reports it instead of reading "no dependencies". npm 7+ installs
 * the root project's peerDependencies (verified npm 10.9.2: they are locked with "peer": true).
 */
export function declaresDependencies(packageJson: string): boolean | undefined {
  let j: unknown;
  try {
    j = JSON.parse(stripBom(packageJson));
  } catch {
    return undefined;
  }
  if (typeof j !== "object" || j === null || Array.isArray(j)) return undefined;
  const m = j as Record<string, unknown>;
  return ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"].some((k) => Object.keys((m[k] as object | null) ?? {}).length > 0);
}

export type EntryType = "file" | "dir" | "symlink" | "other";

export interface WalkEntry {
  /** The directory, "/"-separated and relative to the root: "." for the root (lockfilesIn's form). */
  dir: string;
  name: string;
  /** posix.join(dir, name): "x" at the root, never "./x". */
  rel: string;
  /** What readdir says the entry is, never following a symlink. */
  type: EntryType;
  /** The virtual environment this entry is in, when one is walked without its site-packages (no work tree, untracked root, git failing). */
  venv?: string;
}

/** The walk in order: each entry, and the walker's own findings where lockfilesIn reported them. */
export type WalkEvent = { entry: WalkEntry } | { finding: Finding };

/**
 * The git rule's inputs: the tracked files, or why there are none. "untracked-root": the root is in a work tree, but git
 * tracks no file at or under it (a tarball extracted into an ignored or untracked directory of another repository), so
 * git reviewed nothing here; it is treated as no work tree.
 */
export type GitState = { kind: "tracked"; tracked: ReadonlySet<string> } | { kind: "no-work-tree" } | { kind: "untracked-root" } | { kind: "git-error"; error: string };

/** Runs git with `args` from the root. */
export type GitRun = (args: string[]) => { status: number | null; stdout: string; stderr: string; error?: NodeJS.ErrnoException };

/**
 * One walk of the tree, shared by npm and Python discovery. Its findings are pushed only by npmLockfiles, which every
 * run calls exactly once (Python-only runs too); its notes are reported once, before discovery's own
 * (`[...walk.notes, ...discovery.notes]`), on every run. git() runs git: a caller asks for it only when it needs the
 * tracked set (gitForPython when there are Python locks), so a tree without venvs never runs git.
 */
export interface TreeWalk {
  /** Absolute path of the root. */
  root: string;
  events: WalkEvent[];
  /** The entries of `events`, in order. */
  entries: WalkEntry[];
  /** The walker's own findings of `events`, in order. npmLockfiles pushes them; nothing else must, or they repeat. */
  findings: Finding[];
  /** What the walk skipped or could not decide, for the report. */
  notes: string[];
  /** Venv shapes skipped whole (untracked), and those walked without their site-packages (no work tree, untracked root, git failing). */
  venvs: { skipped: string[]; partial: string[] };
  /** The git rule for this root, run once on first use. */
  git(): GitState;
  /**
   * With a tracked set: the untracked paths git ignores (`git ls-files -z --others --ignored --exclude-standard
   * --directory`; a directory with a trailing "/"), run once on first use. undefined without a tracked set or when git
   * fails, which makes the local-source walk (src/python/paths.ts) skip nothing.
   */
  gitIgnored(): ReadonlySet<string> | undefined;
}

export interface WalkTreeOptions {
  /** The environment git runs with (main.ts passes io.env); PATH finds git. Default: process.env. */
  env?: Record<string, string | undefined>;
  /** Runs git (tests); default: git from the root, as described above. */
  git?: GitRun;
}

/**
 * The names npm's half of discovery reads (lockfilesIn's `watched`), compared with the folded name: npm on macOS and
 * Windows reads PACKAGE-LOCK.JSON as package-lock.json.
 */
const NPM_WATCHED: readonly string[] = [...LOCKFILE_NAMES, ...UNSUPPORTED_LOCKFILES, "package.json"];

/** A name any consumer of the walk reads, by folded name: reported when it sits in a site-packages subtree that is not walked. */
export function isWatchedName(name: string, rel: string): boolean {
  return NPM_WATCHED.includes(fold(name)) || isPythonInputName(name, rel);
}

const MAX_GIT_OUTPUT = 256 * 1024 * 1024;

/**
 * git from `root`, as described in the module comment. git is found on PATH by src/exec.ts and run by its absolute
 * path; a git inside the scanned tree is never run (a git-error: the caller fails closed), and none on PATH is ENOENT.
 */
export function gitRunner(root: string, env: Record<string, string | undefined> = process.env): GitRun {
  return (args) => {
    const git = findProgram("git", env, [root]);
    if ("missing" in git) return { status: null, stdout: "", stderr: "", error: Object.assign(new Error(git.missing), { code: "ENOENT" }) };
    if ("refused" in git) return { status: null, stdout: "", stderr: "", error: Object.assign(new Error(git.refused), { code: "EINTREE" }) };
    // From the filesystem root, the root given with -C: spawned from the scanned tree, an empty PATH entry (or Windows,
    // which searches the working directory first) would run a `git` committed there.
    // No lazy fetch and no transport (src/tree.ts NO_FETCH): a partial clone's missing object is an error, not a fetch.
    const r = spawnSync(git.path, [...NO_FETCH.args, "-C", resolve(root), "-c", "core.fsmonitor=false", ...args], {
      cwd: parse(process.cwd()).root,
      env: { ...env, ...NO_FETCH.env, LC_ALL: "C", LANGUAGE: "C", GIT_TERMINAL_PROMPT: "0" },
      encoding: "utf8",
      maxBuffer: MAX_GIT_OUTPUT,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 120_000,
    });
    return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "", ...(r.error ? { error: r.error as NodeJS.ErrnoException } : {}) };
  };
}

const firstLine = (s: string): string => s.split("\n").map((l) => l.trim()).find((l) => l !== "")?.slice(0, 300) ?? "";

/** A .git entry in `dir` or a parent: git may not be installed, but this is a work tree. */
function dotGitAbove(dir: string): boolean {
  for (let d = resolve(dir); ; d = dirname(d)) {
    if (existsSync(join(d, ".git"))) return true;
    if (dirname(d) === d) return false;
  }
}

/**
 * The git rule: the tracked set when the root is in a work tree and `git ls-files` succeeded; no work tree;
 * or git failing (a dubious-ownership refusal, a broken repository, git missing beside a .git), which callers treat as
 * a failure, never as "nothing tracked" or "no work tree".
 */
export function gitStateOf(root: string, run: GitRun): GitState {
  const r = run(["rev-parse", "--is-inside-work-tree"]);
  if (r.error) {
    if (r.error.code === "ENOENT") return dotGitAbove(root) ? { kind: "git-error", error: "git is not installed, but there is a .git at or above the root" } : { kind: "no-work-tree" };
    return { kind: "git-error", error: r.error.message.split("\n")[0] ?? "git could not run" };
  }
  if (r.status !== 0) {
    // "not a git repository (or any of the parent directories)", or "(or any parent up to mount point ...)" with
    // GIT_CEILING_DIRECTORIES or GIT_DISCOVERY_ACROSS_FILESYSTEM: the root is in no work tree. Anything else failed.
    if (/not a git repository \(or any/.test(r.stderr)) return { kind: "no-work-tree" };
    return { kind: "git-error", error: firstLine(r.stderr) || `git exited ${r.status ?? "on a signal"}` };
  }
  if (r.stdout.trim() !== "true") return { kind: "no-work-tree" };
  const ls = run(["ls-files", "-z"]);
  if (ls.error || ls.status !== 0) return { kind: "git-error", error: ls.error?.message.split("\n")[0] ?? (firstLine(ls.stderr) || `git ls-files exited ${ls.status ?? "on a signal"}`) };
  const tracked = new Set(ls.stdout.split("\0").filter((p) => p !== ""));
  // Nothing tracked at or under the root: the tracked rule would call every venv here unreviewed and skip it.
  return tracked.size === 0 ? { kind: "untracked-root" } : { kind: "tracked", tracked };
}

/** The site-packages directories of a venv shape at `dir` (relative to the root), or undefined when it is not one. */
export function venvShape(root: string, dir: string): string[] | undefined {
  const abs = join(root, dir);
  try {
    if (!lstatSync(join(abs, "pyvenv.cfg"), { throwIfNoEntry: false })?.isFile()) return undefined;
  } catch {
    return undefined;
  }
  const isDir = (p: string): boolean => {
    try {
      return lstatSync(p).isDirectory();
    } catch {
      return false;
    }
  };
  const list = (p: string): string[] => {
    try {
      return readdirSync(p);
    } catch {
      return [];
    }
  };
  // Names as the directory lists them, so the paths match the walk's on a case-insensitive file system too.
  const out: string[] = [];
  for (const lib of list(abs)) {
    if ((lib !== "lib" && lib !== "Lib") || !isDir(join(abs, lib))) continue;
    if (lib === "Lib" && list(join(abs, lib)).includes("site-packages") && isDir(join(abs, lib, "site-packages"))) out.push(posix.join(dir, lib, "site-packages"));
    if (lib === "lib") {
      for (const py of list(join(abs, lib))) {
        if (py.startsWith("python") && list(join(abs, lib, py)).includes("site-packages") && isDir(join(abs, lib, py, "site-packages"))) out.push(posix.join(dir, lib, py, "site-packages"));
      }
    }
  }
  return out.length > 0 ? out.sort() : undefined;
}

const listed = (paths: string[]): string => `${paths.slice(0, 20).join(", ")}${paths.length > 20 ? `, and ${paths.length - 20} more` : ""}`;

/** Why venvs are walked without their site-packages, for messages and notes. */
const partialWhy = (g: GitState): string =>
  g.kind === "git-error" ? "git failed" : g.kind === "untracked-root" ? "git tracks no file at or under the scanned root" : "the scanned root is not in a git work tree";

/**
 * Walks `root` (see the module comment). Throws UsageError only when the root is not a directory, as lockfilesIn did;
 * everything else that keeps a part of the tree from being read is a finding.
 */
export function walkTree(root: string, opts: WalkTreeOptions = {}): TreeWalk {
  if (!statSync(root, { throwIfNoEntry: false })?.isDirectory()) throw new UsageError(`${root} is not a directory`);
  const run = opts.git ?? gitRunner(root, opts.env ?? process.env);
  let git: GitState | undefined;
  const gitState = (): GitState => (git ??= gitStateOf(root, run));
  let ignored: ReadonlySet<string> | undefined | null = null;
  const gitIgnored = (): ReadonlySet<string> | undefined => {
    if (ignored === null) {
      ignored = undefined;
      if (gitState().kind === "tracked") {
        const r = run(["ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--directory"]);
        if (!r.error && r.status === 0) ignored = new Set(r.stdout.split("\0").filter((p) => p !== ""));
      }
    }
    return ignored;
  };

  // Folded paths with a tracked file below them, and folded tracked paths (files and submodules), built on first use.
  let trackedDirs: Set<string> | undefined;
  let trackedPaths: Set<string> | undefined;
  const hasTrackedUnder = (dir: string, tracked: ReadonlySet<string>): boolean => {
    if (trackedDirs === undefined || trackedPaths === undefined) {
      trackedDirs = new Set();
      trackedPaths = new Set();
      for (const p of tracked) {
        trackedPaths.add(fold(p));
        for (let d = posix.dirname(p); d !== "." && d !== "/"; d = posix.dirname(d)) trackedDirs.add(fold(d));
      }
    }
    const f = fold(dir);
    if (trackedDirs.has(f)) return true;
    // A tracked path at or above it: a submodule (gitlink) holds it, and its content is pinned by the commit.
    for (let d = f; d !== "." && d !== "/"; d = posix.dirname(d)) if (trackedPaths.has(d)) return true;
    return false;
  };

  const events: WalkEvent[] = [];
  const finding = (f: Finding): void => {
    events.push({ finding: f });
  };
  const skipped: string[] = [];
  const partial: string[] = [];
  /** site-packages directory -> the venv it belongs to, for venvs walked without them. */
  const sitePackages = new Map<string, string>();

  /** Lists a skipped site-packages subtree: every watched name in it is a finding, nothing is read. */
  const listSitePackages = (top: string, venv: string): void => {
    const stack = [top];
    while (stack.length > 0) {
      const dir = stack.pop() as string;
      let entries: Dirent[];
      try {
        entries = readdirSync(join(root, dir), { withFileTypes: true });
      } catch (err) {
        finding(lockfileProblem(dir, `the directory could not be listed (${(err as NodeJS.ErrnoException).code ?? "error"}), so any lockfile or package.json in it is unchecked`));
        continue;
      }
      for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
        if (e.name === ".git" || e.name === "node_modules") continue;
        const rel = posix.join(dir, e.name);
        if (e.isDirectory()) stack.push(rel);
        // Watched names, and any *.lock: a script's lock is `<script>.lock` whatever the script is called.
        if (isWatchedName(e.name, rel) || (!e.isDirectory() && fold(e.name).endsWith(".lock"))) {
          finding(lockfileProblem(rel, `it is inside ${venv}, a directory that looks like a virtual environment, whose site-packages is not read (${partialWhy(gitState())}, so whether it is part of the reviewed tree is unknown)`));
        }
      }
    }
  };

  const stack: { dir: string; venv?: string }[] = [{ dir: "." }];
  while (stack.length > 0) {
    const frame = stack.pop() as { dir: string; venv?: string };
    const dir = frame.dir;
    let venv = frame.venv;
    const spOf = sitePackages.get(dir);
    if (spOf !== undefined) {
      listSitePackages(dir, spOf);
      continue;
    }
    if (dir !== ".") {
      const shape = venvShape(root, dir);
      if (shape) {
        const g = gitState();
        if (g.kind === "tracked") {
          if (!hasTrackedUnder(dir, g.tracked)) {
            skipped.push(dir);
            continue;
          }
          // Committed content: walked like any other directory.
        } else {
          partial.push(dir);
          venv = dir;
          for (const sp of shape) sitePackages.set(sp, dir);
          if (g.kind === "git-error") {
            finding(lockfileProblem(dir, `it looks like a virtual environment, and git failed (${g.error}), so whether it is part of the reviewed tree is unknown; its site-packages was not read`));
          }
        }
      }
    }
    let entries: Dirent[];
    try {
      entries = readdirSync(join(root, dir), { withFileTypes: true });
    } catch (err) {
      finding(lockfileProblem(dir, `the directory could not be listed (${(err as NodeJS.ErrnoException).code ?? "error"}), so any lockfile or package.json in it is unchecked`));
      continue;
    }
    for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (e.name === ".git" || e.name === "node_modules") continue;
      const rel = posix.join(dir, e.name);
      if (e.isDirectory()) stack.push(venv === undefined ? { dir: rel } : { dir: rel, venv });
      if (e.isSymbolicLink() && venv === undefined) {
        let isDir: boolean | undefined;
        try {
          isDir = statSync(join(root, rel), { throwIfNoEntry: false })?.isDirectory();
        } catch (err) {
          // A loop (ELOOP) or an unreadable target: report it, as a crash could never be baselined.
          finding(lockfileProblem(rel, `it is a symlink that could not be resolved (${(err as NodeJS.ErrnoException).code ?? "error"})`));
        }
        if (isDir) finding(lockfileProblem(rel, "it is a symlinked directory, which wormsign does not follow, so any lockfile or package.json in it is unchecked"));
      }
      const type: EntryType = e.isFile() ? "file" : e.isDirectory() ? "dir" : e.isSymbolicLink() ? "symlink" : "other";
      events.push({ entry: venv === undefined ? { dir, name: e.name, rel, type } : { dir, name: e.name, rel, type, venv } });
    }
  }

  skipped.sort();
  partial.sort();
  const notes: string[] = [];
  if (skipped.length > 0) notes.push(`${skipped.length} virtual environment(s) not read: no file in them is tracked by git, so they are not part of the reviewed tree: ${listed(skipped)}`);
  if (partial.length > 0) {
    notes.push(`${partialWhy(gitState())}, so ${partial.length} directory(ies) that look like virtual environments were read without their site-packages, and symlinks in them were not reported: ${listed(partial)}`);
  }
  return {
    root,
    events,
    entries: events.flatMap((e) => ("entry" in e ? [e.entry] : [])),
    findings: events.flatMap((e) => ("finding" in e ? [e.finding] : [])),
    notes,
    venvs: { skipped, partial },
    git: gitState,
    gitIgnored,
  };
}

/**
 * npm's half of discovery over a walk: main.ts's lockfilesIn, unchanged in what it reads, reports and returns, and in
 * what order. It pushes the walker's own findings too, each where lockfilesIn reported it, so a caller pushes them
 * through this and nothing else.
 *
 * Lockfiles under root. Anything that keeps a lockfile from being read becomes a high finding, not a note, and so does
 * a package.json that declares dependencies with no lockfile in its directory or a parent. Workspace membership is not
 * parsed: any lockfile above a package.json counts as covering it, so a standalone nested project under a locked root
 * is not reported. Symlinks are reported, never followed, which keeps reads inside root.
 */
export function npmLockfiles(root: string, walk: TreeWalk, findings: Finding[]): ParsedLockfile[] {
  const out: ParsedLockfile[] = [];
  const lockDirs = new Set<string>();
  const manifests: string[] = [];
  // Directory -> folded name -> the first entry with it: a second one is the same file on a case-insensitive disk.
  const seen = new Map<string, Map<string, string>>();
  for (const ev of walk.events) {
    if ("finding" in ev) {
      findings.push(ev.finding);
      continue;
    }
    const e = ev.entry;
    const name = fold(e.name);
    if (!NPM_WATCHED.includes(name)) continue;
    let inDir = seen.get(e.dir);
    if (inDir === undefined) seen.set(e.dir, (inDir = new Map()));
    const twin = inDir.get(name);
    if (twin === undefined) inDir.set(name, e.rel);
    else findings.push(lockfileProblem(e.rel, `${twin} has the same name in another case or Unicode form, and a case-insensitive disk (macOS, Windows) holds only one of them, so which one an install reads is not known`));
    if (e.type === "symlink") {
      findings.push(lockfileProblem(e.rel, "it is a symlink, which wormsign does not follow"));
      lockDirs.add(e.dir);
    } else if (e.type !== "file") {
      continue;
    } else if (name === "package.json") {
      manifests.push(e.rel);
    } else if (UNSUPPORTED_LOCKFILES.includes(name)) {
      findings.push(lockfileProblem(e.rel, "bun lockfiles are not supported"));
      lockDirs.add(e.dir);
    } else {
      lockDirs.add(e.dir);
      let lock: ParsedLockfile | undefined;
      try {
        lock = parseLockfileAnyCase(e.rel, stripBom(readFileSync(join(root, e.rel), "utf8")));
      } catch (err) {
        findings.push(lockfileProblem(e.rel, `it could not be parsed (${(err as Error).message})`));
        continue;
      }
      if (lock) out.push(lock);
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

/**
 * ConfigOptions.npmInputs (src/soak-config.ts TreeInputs): the walk holds an npm, pnpm, Yarn or bun input, a lockfile (read or
 * not, a symlink included), a package.json or a bunfig.toml, by folded name as npmLockfiles reads them.
 */
export function hasNpmInputs(walk: TreeWalk): boolean {
  return walk.entries.some((e) => e.type !== "dir" && (NPM_WATCHED.includes(fold(e.name)) || fold(e.name) === "bunfig.toml"));
}

/** The old lockfilesIn over a fresh walk (main.ts makes one walk per run and shares it with Python discovery). */
export function lockfilesIn(root: string, findings: Finding[], opts: WalkTreeOptions = {}): ParsedLockfile[] {
  return npmLockfiles(root, walkTree(root, opts), findings);
}
