/**
 * Python discovery for soak (docs/soak.md, "Python (PyPI) locks": requirements files, scripts, manifests and
 * virtual environments): every Python lock, script, requirements file and manifest in the tree, read into the model soak
 * checks (src/python/model.ts), and every reason one cannot be read or covers nothing, as a finding.
 *
 * Over the shared walk (src/walk.ts; main.ts makes one walk for npm and Python and passes it here):
 * - uv.lock: read (uvlock.ts) and mapped with fromUvLock;
 * - pylock.toml and pylock.<name>.toml: read (pylock.ts) and mapped with fromPylock, packages without `index` sendable
 *   only when the install settings allow (below);
 * - the content pass reads only the files src/python/scripts.ts names (isContentCandidate: .py, .pyw, no extension or a
 *   requirements or shell extension; and any file with a regular `<name>.lock` beside it); no other file is opened;
 * - PEP 723 scripts among them (a .py or .pyw name, a uv shebang, or a `# /// script` line): the block is read by
 *   pep723.ts; a problem with it is WS-SK-002; a script with a block has its lock at `<script path>.lock`, read with
 *   the uv.lock reader (kind "script"); a script whose block lists dependencies and has no lock is WS-SK-002. A
 *   candidate larger than 1 MiB is searched in chunks for a tag line (scanLargeFile), so padding cannot hide a script;
 * - *.py.lock and *.pyw.lock that no script with a block claims (orphans): read, and WS-SK-002; so is `<link>.lock`
 *   beside a symlink that is no Python input by name (uv runs a script through a link and uses the link's lock),
 *   unless the link points at a regular file in the tree that is not a script with a block (Gemfile -> ../Gemfile
 *   beside Gemfile.lock); and so is `<name>.lock` beside a file of any name that is no script with a block, when that
 *   lock is TOML (a lock uv could read; Gemfile.lock is not), or beside one too large to read;
 * - a script block's [tool.uv] build-forcing settings: WS-SK-005, as in a uv.toml;
 * - poetry.lock, pdm.lock, Pipfile.lock: WS-SK-002 "not supported yet";
 * - requirements files, by name or by content (manifest.ts, scripts.ts): read as hash locks with their includes
 *   (requirements.ts) and mapped with fromRequirements; a file holding only blank lines and comments is skipped with a
 *   note. A candidate no line of which reads as a requirement or option (scripts.ts refusedByPipAndUv: a Dockerfile or
 *   shell script that shows a hashed pin, a test baseline named genericConstraints.txt) is not read for its packages:
 *   it is one high WS-SK-002 for the whole file (UNREAD_BY_NAME, UNREAD_BY_CONTENT), keyed on its content, so a
 *   baseline entry approves that content only and an ignorePaths entry clears its directory. It is never a note,
 *   since that judgement can be wrong and a note would hide a file pip installs from. All units together hold at most
 *   MAX_REQUIREMENT_ENTRIES entries (an include counts once per includer); past that, the rest are not read and the
 *   first of them is WS-SK-002;
 * - manifests that declare dependencies (manifest.ts) with no lock covering them: WS-SK-002. A lock covers a manifest
 *   in directory D when it is a uv.lock in D, a uv.lock anywhere in the tree listing a directory, editable or virtual
 *   package at D (a workspace member, or a path source such as a sibling `../shared/common`), or a pylock.toml, a
 *   requirements file or an unsupported lock in D, or a requirements file directly in D/requirements/ (a layout such
 *   as requirements/base.txt and requirements/prod.txt beside the project's pyproject.toml; requirementsDirs). A PEP
 *   723 script is covered by its own lock. A setup.cfg over
 *   16 MiB is WS-SK-002 (setuptools reads all of it);
 * - a file that cannot be read: WS-SK-002 when its name is a Python input (or *.py, *.pyw); otherwise it only might be
 *   one, and a note lists it on a run with Python inputs (an npm-only run is unchanged);
 * - Python names that are symlinks: WS-SK-002 (never followed); a symlinked lock still counts as a lock in its
 *   directory, as for npm, so the manifest beside it is not reported twice;
 * - build-forcing uv configuration in the tree: WS-SK-005 (indexes.ts); uv.toml and pyproject.toml are matched folded
 *   (UV.toml is uv's uv.toml on a case-insensitive file system), and a symlinked uv.toml is WS-SK-005 (not followed).
 * Install settings (indexes.ts) are collected only when a requirements file has entries or a pylock.toml exists, and
 * never with --config-only; the pip probe runs only when a requirements entry or a pylock package without `index`
 * would be sent. Index settings make those entries unsendable (soak then reports each, sending nothing) and are
 * WS-SK-002 themselves; hash settings are WS-SK-002 for every requirements file and pylock.toml they govern. A
 * requirements unit's own index options (-i, --extra-index-url, -f, --no-index, or anything it could not read:
 * requirements.ts indexOptions) make its entries unsendable the same way.
 *
 * The baseline's ignorePaths (DiscoverOptions.ignore) apply to Python inputs: nothing under an ignored path is read
 * as a lock, script, requirements file or manifest, and a note names what was passed over. Install settings are read
 * wherever they are.
 *
 * File-level findings use soak's lockProblemFinding (key: the file, the problem and a digest of the content it is
 * about), so they are checked on every run, PR mode or not, and a baseline entry approves that content only. Never
 * throws: an unexpected error is one WS-SK-002 keyed `pypi:discovery-internal-error`.
 */
import { readlinkSync, readSync } from "node:fs";
import { withRegularFile } from "../fsutil.js";
import { isIgnored } from "../baseline.js";
import { dirname, isAbsolute, join, posix, relative, resolve, sep } from "node:path";
import { keyDigest, makeFinding, type Finding } from "../types.js";
import { walkTree, type EntryType, type TreeWalk } from "../walk.js";
import { buildConfigFindings, collectInstallSettings, type PipConfigProbe, type SettingHit } from "./indexes.js";
import { pythonIdentity } from "./identity.js";
import { sha256File, type GitTracking } from "./local.js";
import {
  dirOf,
  isPylockFileName,
  isPyManifestName,
  isRequirementsName,
  isScriptLockName,
  isScriptName,
  isUnsupportedPyLock,
  isUvLockName,
  isUvTomlName,
  ownReader,
  pyprojectDeclares,
  setupCfgDeclares,
} from "./manifest.js";
import { fromPylock, fromRequirements, fromUvLock, type PyLock } from "./model.js";
import { parseScriptBlock } from "./pep723.js";
import { parsePylock, readPylock, type Pylock } from "./pylock.js";
import { MAX_REQUIREMENTS_BYTES, readRequirements, type RequirementsUnit } from "./requirements.js";
import { CONTENT_LIMIT, hasScriptTagLine, isContentCandidate, isUvShebang, looksLikeRequirements, MAX_SCRIPT_BYTES, refusedByPipAndUv, scanLargeFile, scriptLockPath, SHEBANG_BYTES } from "./scripts.js";
import { lockProblemFinding } from "./soak.js";
import { fold } from "../tree.js";
import { bytesDigest, contentDigest, get, parseToml, readToml, type TomlRead } from "./toml.js";
import { parseUvLock, readUvLock, type UvLock } from "./uvlock.js";

export interface DiscoverOptions {
  /** --pypi-index (default https://pypi.org/simple/). */
  pypiIndex: string;
  /** --pypi-index was given explicitly: waives only "pip config not read". */
  pypiIndexExplicit?: boolean;
  /** The process environment (main.ts: io.env), for install settings and git. */
  env?: Record<string, string | undefined>;
  /** The pip config probe (main.ts: pipConfigProbe(io.env)); absent: pip's configuration is never read. */
  pipConfig?: PipConfigProbe;
  /** --config-only: no install settings are collected and nothing is probed. */
  configOnly?: boolean;
  /** The walk to read (main.ts shares one with npm); default a new walkTree(root). */
  walk?: TreeWalk;
  /** Passed to collectInstallSettings (tests). */
  uvConfigFiles?: string[];
  /** Passed to collectInstallSettings (tests); default true. */
  ancestors?: boolean;
  /** The most requirements entries all units may hold together (default MAX_REQUIREMENT_ENTRIES; tests pass less). */
  maxRequirementEntries?: number;
  /** The baseline's ignorePaths: Python inputs under them are not read (see the module comment). */
  ignore?: string[];
  /** Called with each path the content pass opens (tests count them). */
  onRead?: (rel: string) => void;
}

/**
 * What discovery returns. The wiring main.ts must do around it (and does, in soak), which nothing here can enforce:
 * (a) notes: the walk's own notes are not in `notes`; report `[...walk.notes, ...discovery.notes]`, once, on every run
 *     (npm-only runs too: the walk's notes are about the whole tree);
 * (b) the walker's findings (symlinked directories, unlistable directories, names in skipped site-packages) are not in
 *     `findings`: they are pushed by npmLockfiles(root, walk, findings), which every run must call exactly once,
 *     Python-only runs included;
 * (c) gitForPython(walk, locks) runs git: call it only when `locks` is non-empty, so a tree without venvs or Python
 *     locks never runs git (the npm byte-identical guarantee);
 * (d) `findings` holds WS-SK-005, which src/rules.ts registers;
 * (e) pypiIndexExplicit is true only when --pypi-index was given (it also lets local archives' names be sent);
 * (f) pipConfig is pipConfigProbe(io.env): absent means pip's configuration is never read, which keeps every
 *     requirements entry and pylock package without an index from being sent;
 * (g) PR mode (--base): an entry in `locks` the base's own soak read identically is not checked again
 *     (src/python/base-entries.ts, which reads the base with pythonBaseLocks and counts a file only when the base's
 *     soak read it as a lock: the base's text at the same path is not enough, since a pin could land first in a file
 *     the base never read as one); pythonBaseIdentities serves base-builds.ts. `findings` are file-level and reported
 *     on every run, PR mode or not.
 */
export interface PythonDiscovery {
  /** Every lock read, for checkPythonLocks. */
  locks: PyLock[];
  /** Discovery's findings (not the walker's own, which npmLockfiles reports). */
  findings: Finding[];
  notes: string[];
  /** The tree has Python locks, scripts with metadata, requirements files or manifests (ConfigOptions.pythonInputs). */
  pythonInputs: boolean;
}

/**
 * The most requirements entries discovery holds across all units (about 2 KB each once mapped): 250,000 keeps a tree of
 * many small files that each include one large file far from the heap limit.
 */
export const MAX_REQUIREMENT_ENTRIES = 250_000;
/** The most of a setup.cfg read; a larger one is WS-SK-002. */
const MAX_SETUP_CFG_BYTES = 16 * 1024 * 1024;
const NOT_FOLLOWED = "it is a symlink, which wormsign does not follow";
const UNCOVERED =
  "no lock covers it: no uv.lock in its directory, none anywhere in the tree that lists it as a workspace member or path source, and no pylock.toml or requirements hash lock beside it, nor a requirements hash lock in a requirements/ directory beside it, so the versions an install would pick cannot be verified";

/**
 * The directories a requirements file at `rel` covers: its own, and, when that directory is named requirements (as
 * isRequirementsName folds it), the one above it, so requirements/base.txt covers the pyproject.toml beside the
 * requirements/ directory. One level only: requirements/ci/x.txt covers requirements/ci and nothing above.
 */
function requirementsDirs(rel: string): string[] {
  const dir = dirOf(rel);
  return fold(posix.basename(dir)) === "requirements" ? [dir, dirOf(dir)] : [dir];
}

/**
 * A regular file's first bytes and its size, read without following a final symlink; or why not. `max` is how many
 * bytes to read, or a function of the file's size giving it.
 */
function readHead(path: string, max: number | ((size: number) => number)): { bytes: Buffer; size: number } | { problem: string } {
  return withRegularFile(path, undefined, (fd, size) => {
    const want = Math.min(size, typeof max === "number" ? max : max(size));
    const bytes = Buffer.alloc(want);
    let got = 0;
    while (got < want) {
      const n = readSync(fd, bytes, got, want - got, null);
      if (n === 0) break;
      got += n;
    }
    return { bytes: bytes.subarray(0, got), size };
  });
}

/**
 * Where the symlink `rel` points, as a root-relative "/"-separated path, without following it any further; undefined
 * when the link cannot be read or points outside the root (an absolute target is compared with the root as given).
 */
function linkTarget(root: string, rel: string): string | undefined {
  let target: string;
  try {
    target = readlinkSync(join(root, rel));
  } catch {
    return undefined;
  }
  const abs = resolve(root, isAbsolute(target) ? target : join(dirname(rel), target));
  const r = relative(resolve(root), abs);
  if (r === "" || r === ".." || r.startsWith(`..${sep}`) || isAbsolute(r)) return undefined;
  return r.split(sep).join("/");
}

/** The git rule and ignored paths for checkPythonLocks, from the walk: ignored paths only when a lock has a local source tree. */
export function gitForPython(walk: TreeWalk, locks: PyLock[]): { git: GitTracking; gitError?: string; gitIgnored?: ReadonlySet<string> } {
  const g = walk.git();
  // A root git tracks nothing under (untracked-root) was reviewed by no one: as with no work tree, the tracked check
  // is skipped (and the walk's note says why).
  if (g.kind === "no-work-tree" || g.kind === "untracked-root") return { git: "no-work-tree" };
  if (g.kind === "git-error") return { git: "git-error", gitError: g.error };
  const trees = locks.some((l) => l.packages.some((p) => p.source.kind === "directory" || p.source.kind === "editable"));
  const ignored = trees ? walk.gitIgnored() : undefined;
  return { git: g.tracked, ...(ignored !== undefined ? { gitIgnored: ignored } : {}) };
}

/** Finds and reads every Python input under `root` (see the module comment). Never throws. */
export function discoverPython(root: string, opts: DiscoverOptions): PythonDiscovery {
  try {
    return discover(root, opts);
  } catch (e) {
    const why = `Python discovery stopped on an unexpected error (${String((e as Error)?.message ?? e).slice(0, 200)}), so no Python lockfile, script or requirements file in the tree counts as verified`;
    return { locks: [], findings: [makeFinding({ ruleId: "WS-SK-002", severity: "high", message: `Cannot verify soak time for the PyPI packages: ${why}`, key: "pypi:discovery-internal-error" })], notes: [], pythonInputs: true };
  }
}

/** Why a file named like a requirements file that wormsign cannot read as one is WS-SK-002 (refusedByPipAndUv). */
export const UNREAD_BY_NAME =
  "it is named like a pip requirements file, but wormsign cannot read it as one, so none of its packages were checked. pip and uv do not read such files alike (uv installs from some lines pip refuses), so check that neither installs from it before you approve it with a baseline entry (it holds for these exact bytes; any edit reports it again) or an ignorePaths entry for its directory; if something does, make it a hash lock (`uv pip compile --generate-hashes`)";
/** The same for a file found by its content: a --hash option or a --require-hashes line. */
export const UNREAD_BY_CONTENT =
  "it is written like a pip requirements file (it holds a --hash option or a --require-hashes line), but wormsign cannot read it as one, so none of its packages were checked. pip and uv do not read such files alike (uv installs from some lines pip refuses), so check that neither `pip install -r` nor `uv pip install -r` installs from it before you approve it with a baseline entry (it holds for these exact bytes; any edit reports it again) or an ignorePaths entry for its directory";

function discover(root: string, opts: DiscoverOptions): PythonDiscovery {
  const env = opts.env ?? process.env;
  const walk = opts.walk ?? walkTree(root, { env });
  const findings: Finding[] = [];
  const notes: string[] = [];
  const locks: PyLock[] = [];
  let pythonInputs = false;
  /** A file-level WS-SK-002, keyed on the problem and `covers`, the digest of the content it is about. */
  const problem = (file: string, why: string, covers: string): void => {
    findings.push(lockProblemFinding(file, why, covers));
  };
  /** The sha256 of a regular file in the tree, or "" when it cannot be read. */
  const fileCovers = (rel: string): string => {
    const r = sha256File(join(root, rel));
    return "sha256" in r ? r.sha256 : "";
  };
  const ignore = opts.ignore ?? [];
  const ignored = (rel: string): boolean => ignore.length > 0 && isIgnored(rel, ignore);
  /** Python inputs (by name) under the baseline's ignorePaths, which were not read. */
  const passedOver: string[] = [];

  const types = new Map<string, EntryType>();
  for (const e of walk.entries) types.set(e.rel, e.type);
  const tomlCache = new Map<string, TomlRead>();
  const toml = (rel: string): TomlRead => {
    let r = tomlCache.get(rel);
    if (r === undefined) {
      r = readToml(join(root, rel));
      tomlCache.set(rel, r);
    }
    return r;
  };
  /**
   * What a symlinked input covers: its target text and, when the link leads (through at most 40 links) to a regular
   * file in the tree, that file's sha256, so a baseline entry for the link does not approve whatever it later leads to.
   */
  const linkCovers = (rel: string): string => {
    const parts: string[] = [];
    let at = rel;
    for (let hops = 0; hops < 40 && types.get(at) === "symlink"; hops++) {
      try {
        parts.push(readlinkSync(join(root, at)));
      } catch {
        parts.push("?");
        break;
      }
      const next = linkTarget(root, at);
      if (next === undefined) break;
      at = next;
    }
    if (types.get(at) === "file") parts.push(fileCovers(at));
    return bytesDigest(parts.join("\0"));
  };

  /** Directories holding a lock of any kind other than uv.lock (which also counts, below). */
  const lockDirs = new Set<string>();
  const uvLocks = new Map<string, UvLock | undefined>();
  const pylocks: [rel: string, lock: Pylock][] = [];
  const requirements = new Set<string>();
  /** Script locks to read: *.py.lock and *.pyw.lock by name, and the locks of symlinked scripts (below). */
  const scriptLocks = new Set<string>();
  /** A symlinked script's lock -> the symlink, whose `uv run --script` uses that lock. */
  const symlinkedScriptLocks = new Map<string, string>();
  /** `<name>.lock` beside a file that is not a script with a block: reported when it is TOML (below). */
  const besideLocks = new Map<string, string>();
  /** Symlinks that are no Python input by name, with the regular files `<symlink>.lock` (folded) beside them. */
  const linkedLocks: [link: string, locks: string[]][] = [];
  /** Regular files by folded path, for `<symlink>.lock`. */
  const filesByFold = new Map<string, string[]>();
  for (const e of walk.entries) if (e.type === "file") filesByFold.set(fold(e.rel), [...(filesByFold.get(fold(e.rel)) ?? []), e.rel]);
  /** Regular files that could not be read whose names are no Python input: a note when the run has Python inputs. */
  const unreadable: string[] = [];
  /** Candidates larger than MAX_SCRIPT_BYTES, not read: a note when the run has Python inputs. */
  const tooLarge: string[] = [];
  /** Scripts found only by a `# /// script` line (not a .py or .pyw name, not a uv shebang). */
  const byContentOnly = new Set<string>();
  const manifests: string[] = [];
  /** Scripts with a block (or a problem with one), read in the content pass so no file's bytes are kept. */
  const scripts: [rel: string, block: Exclude<ReturnType<typeof parseScriptBlock>, { kind: "none" }>, covers: string][] = [];

  for (const e of walk.entries) {
    if (e.type !== "file" && e.type !== "symlink") continue;
    const { name, rel } = e;
    const uv = isUvLockName(name);
    const pylock = isPylockFileName(name);
    const scriptLock = isScriptLockName(name);
    const unsupported = isUnsupportedPyLock(name);
    const manifest = isPyManifestName(name);
    const reqByName = isRequirementsName(rel);
    const named = uv || pylock || scriptLock || unsupported || manifest || reqByName;
    if (ignored(rel)) {
      if (named || isScriptName(name)) passedOver.push(rel);
      continue;
    }
    if (named) pythonInputs = true;
    if (e.type === "symlink") {
      if (!named) {
        // It may be a script uv runs through the link (`uv run --script deploy`, deploy -> real.py); then uv uses
        // deploy.lock, whatever the script's name. Decided below, once every script in the tree is known.
        const locks = filesByFold.get(fold(scriptLockPath(rel)));
        if (locks !== undefined) linkedLocks.push([rel, locks]);
        continue;
      }
      problem(rel, NOT_FOLLOWED, linkCovers(rel));
      if (uv || pylock || unsupported) lockDirs.add(e.dir);
      if (reqByName) for (const d of requirementsDirs(rel)) lockDirs.add(d);
      if (scriptLock) scriptLocks.add(rel);
      continue;
    }
    if (uv) uvLocks.set(rel, undefined);
    else if (pylock) {
      lockDirs.add(e.dir);
      pylocks.push([rel, readPylock(join(root, rel))]);
    } else if (scriptLock) scriptLocks.add(rel);
    else if (unsupported) {
      lockDirs.add(e.dir);
      problem(rel, `${name} is not supported yet, so the versions it pins cannot be verified; lock with uv (uv.lock), or export a hash-pinned requirements file or pylock.toml and install from that`, fileCovers(rel));
    } else if (manifest) manifests.push(rel);
    if (reqByName) requirements.add(rel);
    // A file a reader of its own reads (and fails closed on, whatever it holds) is neither a script nor requirements.
    if (ownReader(name)) continue;

    // The content pass: only the files scripts.ts names are opened (a .py or .pyw script, a candidate name, or a file
    // with a `<name>.lock` beside it, which uv would use if it is a script).
    const byName = isScriptName(name);
    const lockBeside = filesByFold.get(fold(scriptLockPath(rel)));
    if (!byName && lockBeside === undefined && !isContentCandidate(name)) continue;
    opts.onRead?.(rel);
    const path = join(root, rel);
    const full = byName || lockBeside !== undefined;
    // A large candidate is read only as far as its first line could be a uv shebang, then searched in chunks.
    const head = readHead(path, (size) => (full ? MAX_SCRIPT_BYTES : size <= CONTENT_LIMIT ? CONTENT_LIMIT : SHEBANG_BYTES));
    if ("problem" in head) {
      // A Python input by name is WS-SK-002. Any other file only might be one: a note (in a run with Python inputs),
      // so an unreadable file in an npm-only tree changes nothing.
      if (named || byName) problem(rel, `${head.problem}, so whether it is a Python script or a requirements file is unknown`, "");
      else unreadable.push(rel);
      continue;
    }
    let bytes: Buffer | undefined = head.bytes;
    let whole = head.size === bytes.length;
    const shebang = isUvShebang(bytes.subarray(0, SHEBANG_BYTES));
    let tagged = whole && hasScriptTagLine(bytes);
    /** Read in full and searched by the requirements content rule. */
    let maybeRequirements = whole;
    if (!whole && head.size > MAX_SCRIPT_BYTES) {
      // Too large to read for a block: a script by name, or one with a lock beside it, is unknown.
      if (byName || shebang || lockBeside !== undefined) {
        problem(rel, `it is ${byName ? "a script" : shebang ? "a uv script (its first line runs uv)" : `a file with ${scriptLockPath(rel)} beside it`} larger than ${MAX_SCRIPT_BYTES / 1024 / 1024} MiB, so whether it has a \`# /// script\` block, and what it locks, is unknown`, fileCovers(rel));
        if (lockBeside !== undefined) for (const l of lockBeside) besideLocks.set(l, rel);
      } else tooLarge.push(rel);
      continue;
    }
    if (!whole && !shebang) {
      // A candidate over CONTENT_LIMIT: searched in chunks, so padding a script or a hash lock past the first MiB
      // does not hide it, and read in full only when it may be one.
      const scan = scanLargeFile(path, MAX_SCRIPT_BYTES);
      if ("problem" in scan) {
        if (named) problem(rel, `${scan.problem}, so whether it is a Python script or a requirements file is unknown`, "");
        else unreadable.push(rel);
        continue;
      }
      tagged = scan.tag;
      maybeRequirements = scan.requirements;
      bytes = undefined;
    }
    if (!whole && (shebang || tagged || maybeRequirements)) {
      const all = readHead(path, MAX_SCRIPT_BYTES);
      if ("problem" in all) {
        problem(rel, `${all.problem}, so whether it is a Python script or a requirements file is unknown`, "");
        continue;
      }
      bytes = all.bytes;
      whole = true;
      tagged = hasScriptTagLine(bytes);
    }
    if (bytes === undefined) continue;
    const block = byName || shebang || tagged ? parseScriptBlock(bytes) : undefined;
    if (block !== undefined) {
      if (block.kind !== "none") scripts.push([rel, block, bytesDigest(bytes)]);
      if (!byName && !shebang) byContentOnly.add(rel);
    }
    if (lockBeside !== undefined && (block === undefined || block.kind === "none")) for (const l of lockBeside) besideLocks.set(l, rel);
    if (whole && reqByName && refusedByPipAndUv(bytes)) {
      // Named like a requirements file, but no line reads as one (a test baseline called genericConstraints.txt,
      // notes called requirements.txt): not read for its packages, and one finding for the whole file instead, keyed
      // on its content. Never a note: the judgement can be wrong, and a note would hide a file pip installs from.
      requirements.delete(rel);
      problem(rel, UNREAD_BY_NAME, bytesDigest(bytes));
    }
    if (whole && maybeRequirements && !reqByName && looksLikeRequirements(bytes)) {
      pythonInputs = true;
      // Written like one (a --hash option, a --require-hashes line) in a Dockerfile, shell script or README: the same.
      if (refusedByPipAndUv(bytes)) problem(rel, UNREAD_BY_CONTENT, bytesDigest(bytes));
      else requirements.add(rel);
    }
  }

  // Symlinked scripts' locks. The symlink is passed over (its lock is someone else's: Gemfile -> ../shared/Gemfile
  // beside Gemfile.lock) only when it points at a regular file in the tree that is not a script with a block; any
  // other target (such a script, a path outside the tree, another symlink, a link that cannot be read) may be a
  // script uv runs, so the lock beside the link is read and reported.
  const withBlock = new Set(scripts.map(([rel]) => rel));
  for (const [link, linked] of linkedLocks) {
    const target = linkTarget(root, link);
    if (target !== undefined && types.get(target) === "file" && !withBlock.has(target)) continue;
    for (const lock of linked) {
      scriptLocks.add(lock);
      symlinkedScriptLocks.set(lock, link);
    }
  }
  // `<name>.lock` beside a file of any name that is no script with a block (or too large to read): a lock uv could
  // read (TOML) is reported as a script lock no `uv run` uses as it stands; another file's lock (Gemfile.lock) is not.
  for (const [lock, beside] of besideLocks) {
    if (withBlock.has(beside) || scriptLocks.has(lock) || ignored(lock)) continue;
    // A lock read by a reader of its own (uv.lock beside a file named uv, poetry.lock beside one named poetry).
    if (ownReader(posix.basename(lock))) continue;
    const t = toml(lock);
    if (!("problem" in t)) scriptLocks.add(lock);
  }

  // Scripts and their locks.
  const claimed = new Set<string>();
  for (const [rel, block, covers] of scripts) {
    pythonInputs = true;
    const lockRel = scriptLockPath(rel);
    claimed.add(fold(lockRel));
    if (block.kind === "problem") problem(rel, block.problem, covers);
    // uv reads [tool.uv] in the block for `uv run --script`: build-forcing settings there are WS-SK-005 as in a uv.toml.
    if (block.kind === "block") findings.push(...buildConfigFindings(rel, block.metadata, "script"));
    const type = types.get(lockRel);
    if (type === "file") {
      locks.push(fromUvLock(lockRel, readUvLock(join(root, lockRel)), { pypiIndex: opts.pypiIndex, kind: "script", sendLocalArchives: opts.pypiIndexExplicit === true }));
    } else if (type === "symlink") {
      problem(lockRel, NOT_FOLLOWED, linkCovers(lockRel));
    } else if (type !== undefined) {
      problem(lockRel, `it is the lock path of the script ${rel}, but not a regular file`, "");
    } else if (block.kind === "block") {
      const deps = get(block.metadata, "dependencies");
      if (deps !== undefined && !(Array.isArray(deps) && deps.length === 0)) {
        const docs = byContentOnly.has(rel) ? `; if ${rel} is documentation that shows a script rather than a script anything runs, baseline this finding with a justification` : "";
        problem(rel, `it is a PEP 723 script that declares dependencies, and there is no ${lockRel} beside it, so \`uv run\` resolves them when it runs and nothing pins them; lock it with \`uv lock --script ${rel}\` and run it with \`uv run --locked\`${docs}`, contentDigest(block.metadata));
      }
    }
  }
  for (const rel of scriptLocks) {
    if (claimed.has(fold(rel))) continue;
    pythonInputs = true;
    const script = symlinkedScriptLocks.get(rel) ?? besideLocks.get(rel) ?? rel.slice(0, -".lock".length);
    // The lock's pins are checked below; what the finding approves is this lock beside this script as they stand.
    const covers = bytesDigest(`${fileCovers(rel)}\0${types.get(script) === "symlink" ? linkCovers(script) : types.get(script) === "file" ? fileCovers(script) : ""}`);
    if (symlinkedScriptLocks.has(rel) || types.get(script) === "symlink") {
      problem(rel, `it is the lock \`uv run --script ${script}\` uses, and ${script} is a symlink, which wormsign does not follow, so the script's \`# /// script\` block was not read; the pins in this lock are checked, but whether they are all the script needs is unknown`, covers);
    } else {
      problem(rel, `it is a PEP 723 script lock, but ${script} is not a script with a \`# /// script\` block beside it (missing, a symlink, too large to read, or without a block), so no \`uv run\` uses this lock as it stands`, covers);
    }
    if (types.get(rel) === "file") locks.push(fromUvLock(rel, readUvLock(join(root, rel)), { pypiIndex: opts.pypiIndex, kind: "script", sendLocalArchives: opts.pypiIndexExplicit === true }));
  }

  // uv.lock.
  for (const rel of uvLocks.keys()) {
    const lock = readUvLock(join(root, rel));
    uvLocks.set(rel, lock);
    locks.push(fromUvLock(rel, lock, { pypiIndex: opts.pypiIndex, kind: "uv", sendLocalArchives: opts.pypiIndexExplicit === true }));
  }

  // Requirements files. Each is read as a unit with its includes, so an include is held once for every file that
  // includes it: the entries of all units together are bounded, and reaching the bound is a finding, not an abort.
  const units: RequirementsUnit[] = [];
  const maxEntries = opts.maxRequirementEntries ?? MAX_REQUIREMENT_ENTRIES;
  let entriesHeld = 0;
  const toRead = [...requirements].filter((rel) => types.get(rel) === "file");
  for (const [i, rel] of toRead.entries()) {
    const unit = readRequirements(root, rel);
    if (unit.empty && unit.problems.length === 0) {
      notes.push(`${rel} holds only blank lines and comments, so it was skipped`);
      continue;
    }
    for (const d of requirementsDirs(rel)) lockDirs.add(d);
    if (entriesHeld + unit.entries.length > maxEntries) {
      const rest = toRead.slice(i);
      problem(
        rel,
        `the requirements files hold more than ${maxEntries} entries between them (an included file counts once for each file that includes it), so ${rest.length === 1 ? "this file was" : `this file and ${rest.length - 1} more were`} not read: ${rest.slice(0, 20).join(", ")}${rest.length > 20 ? ", ..." : ""}`,
        bytesDigest(rest.map((r) => `${r}\0${fileCovers(r)}`).join("\n")),
      );
      for (const r of rest) for (const d of requirementsDirs(r)) lockDirs.add(d);
      break;
    }
    entriesHeld += unit.entries.length;
    units.push(unit);
  }

  // Install settings, then mapping the locks that record no index.
  const withEntries = units.filter((u) => u.entries.length > 0);
  const indexless = pylocks.some(([, l]) => l.packages.some((p) => p.source.kind === "files" && p.source.index === undefined));
  const needSettings = !opts.configOnly && (units.length > 0 || pylocks.length > 0);
  const settings = needSettings
    ? collectInstallSettings(
        { root, types, toml },
        {
          pypiIndex: opts.pypiIndex,
          env,
          probe: withEntries.length > 0 || indexless,
          ...(opts.pipConfig ? { pipConfig: opts.pipConfig } : {}),
          ...(opts.uvConfigFiles ? { uvConfigFiles: opts.uvConfigFiles } : {}),
          ...(opts.ancestors !== undefined ? { ancestors: opts.ancestors } : {}),
        },
      )
    : undefined;
  const pipBlocks = settings?.pipNotRead !== undefined && !opts.pypiIndexExplicit;
  if (settings?.pipNotRead !== undefined) {
    notes.push(
      `pip's configuration was not read (${settings.pipNotRead})${opts.pypiIndexExplicit ? "; --pypi-index was given explicitly, so requirements entries and pylock packages without an index are checked against it anyway" : ", so requirements entries and pylock packages without an index are sent nowhere (pip could install them from another index); pass --pypi-index explicitly to check them against it anyway"}`,
    );
  }
  /** Hit key -> the hit and the lock files it governs, for one finding per hit. */
  const affected = new Map<string, { hit: SettingHit; files: string[] }>();
  const record = (hit: SettingHit, file: string): void => {
    const key = `${hit.kind}\0${hit.where}\0${hit.detail}`;
    const a = affected.get(key) ?? { hit, files: [] };
    if (!a.files.includes(file)) a.files.push(file);
    affected.set(key, a);
  };
  /**
   * Why the entries of `file` that record no index may not be sent; undefined when they may. Index settings govern
   * only a lock with such entries (a pylock package with `index` is checked against --pypi-index by soak); hash
   * settings govern every requirements file and pylock.toml. A requirements unit's own index options (and anything
   * in it that was not read: requirements.ts indexOptions) govern its entries as an index setting does: pip applies
   * them to the whole install.
   */
  const unsentFor = (file: string, recordsNoIndex: boolean, own: RequirementsUnit["indexOptions"] = []): string | undefined => {
    if (opts.configOnly) return "install settings are not read with --config-only";
    const hits = (settings?.forDir(dirOf(file)) ?? []).filter((h) => recordsNoIndex || h.kind === "hash");
    for (const h of hits) record(h, file);
    const o = own[0];
    if (o !== undefined) return `an install of ${file} may use another index (its own ${o.option} at ${o.file}${o.line === undefined ? "" : `:${o.line}`}${own.length > 1 ? `, and ${own.length - 1} more` : ""})`;
    const index = hits.filter((h) => h.kind === "index");
    if (index.length > 0) return `an install of ${file} may use another index (${index[0]!.where} ${index[0]!.detail}${index.length > 1 ? `, and ${index.length - 1} more setting(s)` : ""})`;
    if (pipBlocks) return `pip's configuration was not read (${settings!.pipNotRead}), so an install of ${file} may use another index`;
    return undefined;
  };
  for (const unit of units) {
    const unsent = unsentFor(unit.file, true, unit.indexOptions);
    locks.push(fromRequirements(unit, unsent === undefined ? { sendable: true } : { unsent }));
  }
  for (const [rel, lock] of pylocks) {
    const unsent = unsentFor(rel, lock.packages.some((p) => p.source.kind === "files" && p.source.index === undefined));
    locks.push(fromPylock(rel, lock, { pypiIndex: opts.pypiIndex, sendLocalArchives: opts.pypiIndexExplicit === true, ...(unsent === undefined ? { sendable: true } : { unsent }) }));
  }
  for (const { hit, files } of affected.values()) {
    const what = hit.kind === "index" ? "an install may use another index" : "an install may skip hash checks";
    files.sort();
    const shown = `${files.slice(0, 5).join(", ")}${files.length > 5 ? `, and ${files.length - 5} more` : ""}`;
    findings.push(
      makeFinding({
        ruleId: "WS-SK-002",
        severity: "high",
        message: `Cannot verify soak time for the packages in ${shown}: ${what}: ${hit.where} ${hit.detail}${hit.kind === "index" ? "; nothing in them that records no index is sent to the index or OSV" : "; a lock's hashes protect nothing when the install does not check them"}`,
        ...(hit.file !== undefined ? { file: hit.file } : {}),
        key: `pypi:install-setting ${hit.kind} ${hit.where} ${keyDigest(hit.detail)}`,
      }),
    );
  }

  // Build-forcing uv configuration in the tree (WS-SK-005). Names are folded: uv on a case-insensitive file system
  // reads UV.toml as its uv.toml. A symlinked uv.toml is not followed, so what it sets is unknown (a symlinked
  // pyproject.toml is already WS-SK-002 as a manifest).
  for (const [rel, type] of types) {
    const base = posix.basename(rel);
    const uvToml = isUvTomlName(base);
    if ((!uvToml && fold(base) !== "pyproject.toml") || ignored(rel)) continue;
    if (type === "symlink" && uvToml) {
      findings.push(
        makeFinding({
          ruleId: "WS-SK-005",
          severity: "medium",
          message: `${rel} is a symlink, which wormsign does not follow, so whether it sets uv settings that make installs build packages from source (no-binary, no-build-isolation, extra-build-dependencies, config-settings), with build requirements no lock pins, is unknown. Replace it with the file it points at`,
          file: rel,
          key: "pypi:build-config symlink",
        }),
      );
      continue;
    }
    if (type !== "file") continue;
    const read = toml(rel);
    if (!("problem" in read)) findings.push(...buildConfigFindings(rel, read.doc, uvToml ? "uv.toml" : "pyproject.toml"));
  }

  // Manifests and the covering-lock rule. A uv.lock covers every directory it lists as a directory, editable or
  // virtual package (a workspace member, nested or not, or a path source), wherever it is relative to the lock: a
  // sibling path dependency (`../shared/common`) is pinned by the lock that lists it.
  const locked = new Set<string>();
  for (const [rel, lock] of uvLocks) {
    for (const p of lock?.packages ?? []) {
      const s = p.source;
      if (s.kind === "directory" || s.kind === "editable" || s.kind === "virtual") locked.add(posix.normalize(posix.join(dirOf(rel), s.path)));
    }
  }
  for (const rel of uvLocks.keys()) lockDirs.add(dirOf(rel));
  const covered = (dir: string): boolean => lockDirs.has(dir) || locked.has(dir);
  for (const rel of manifests) {
    const name = fold(posix.basename(rel));
    const dir = dirOf(rel);
    if (name === "pyproject.toml") {
      const read = toml(rel);
      // A manifest no lock covers approves its exact content: an added dependency is a new finding.
      if ("problem" in read) {
        problem(rel, `it could not be read (${read.problem}), so whether it declares dependencies is unknown`, read.sha256 ?? "");
        continue;
      }
      if (pyprojectDeclares(read.doc) && !covered(dir)) {
        problem(rel, `it declares dependencies, but ${UNCOVERED}`, contentDigest(read.doc));
      }
    } else if (name === "setup.py") {
      if (!covered(dir)) problem(rel, `it is a setup.py, which declares whatever it computes when an install runs it, and ${UNCOVERED}`, fileCovers(rel));
    } else if (name === "setup.cfg") {
      const head = readHead(join(root, rel), MAX_SETUP_CFG_BYTES);
      if ("problem" in head) {
        problem(rel, `${head.problem}, so whether it declares dependencies is unknown`, "");
        continue;
      }
      if (head.size > MAX_SETUP_CFG_BYTES) {
        // setuptools reads all of it: a declaration past the part read would be missed.
        problem(rel, `it is larger than ${MAX_SETUP_CFG_BYTES / 1024 / 1024} MiB, so whether it declares dependencies is unknown`, fileCovers(rel));
        continue;
      }
      if (setupCfgDeclares(head.bytes.toString("utf8")) && !covered(dir)) problem(rel, `it declares dependencies (install_requires, setup_requires, tests_require or extras_require), but ${UNCOVERED}`, bytesDigest(head.bytes));
    } else if (name === "pipfile") {
      if (!covered(dir)) problem(rel, "it declares dependencies for pipenv, and there is no Pipfile.lock (which wormsign does not read yet) or other lock beside it, so the versions an install would pick cannot be verified", fileCovers(rel));
    }
  }

  if (unreadable.length > 0 && pythonInputs) {
    notes.push(`${unreadable.length} file(s) could not be read, so whether they are Python scripts or requirements files is unknown: ${unreadable.slice(0, 20).join(", ")}${unreadable.length > 20 ? `, and ${unreadable.length - 20} more` : ""}`);
  }
  if (tooLarge.length > 0 && pythonInputs) {
    notes.push(`${tooLarge.length} file(s) are larger than ${MAX_SCRIPT_BYTES / 1024 / 1024} MiB and were not read, so whether they are Python scripts or requirements files is unknown: ${tooLarge.slice(0, 20).join(", ")}${tooLarge.length > 20 ? `, and ${tooLarge.length - 20} more` : ""}`);
  }
  if (passedOver.length > 0) {
    passedOver.sort();
    notes.push(`ignored paths (baseline): ${ignore.join(", ")}; the Python inputs there were not read: ${passedOver.slice(0, 20).join(", ")}${passedOver.length > 20 ? `, and ${passedOver.length - 20} more` : ""}`);
  }

  // One finding per fingerprint: a symlinked script lock can be reached by name and by its script.
  const seen = new Set<string>();
  const unique = findings.filter((f) => !seen.has(f.fingerprint) && seen.add(f.fingerprint) !== undefined);
  return { locks, findings: unique, notes, pythonInputs };
}

/**
 * PR mode (--base): the base revision's copy of each head lock, read from the same file by the same reader and mapped
 * by the same mapper (src/python/base-builds.ts asks it whether a WS-SK-005 build or sdist-only package was already
 * there, and src/python/base-entries.ts reads the base's requirements units with it). `read(rel)` is the base tree's text of a root-relative path (main.ts: `(rel) => baseTree.read(\`./${rel}\`)`),
 * undefined when the base has no such file; `bytes(rel)` its bytes as stored (main.ts: Tree.entry), from which a
 * requirements file is read with its includes by the same reader (requirements.ts), in memory, limited to the files the
 * head's unit read entries from. Nothing of the base is written to disk.
 * Whatever the base lacks or cannot read contributes nothing. This says what the base's text at those paths holds,
 * not that the base's own soak read that text as a lock: base-builds.ts and base-entries.ts check that separately. The base's
 * requirements units are bounded as discovery bounds the head's (maxRequirementEntries, default
 * MAX_REQUIREMENT_ENTRIES): past the bound nothing more is read from the base. Never throws.
 */
export function pythonBaseLocks(
  read: (rel: string) => string | undefined,
  head: PyLock[],
  opts: { pypiIndex: string; maxRequirementEntries?: number; bytes?: (rel: string) => Uint8Array | undefined },
): PyLock[] {
  // A requirements file's bytes as the base holds them (main.ts: Tree.entry, never decoded), else its text's.
  const bytesOf = opts.bytes ?? ((rel: string): Uint8Array | undefined => {
    const text = read(rel);
    return text === undefined ? undefined : Buffer.from(text, "utf8");
  });
  const out: PyLock[] = [];
  const maxEntries = opts.maxRequirementEntries ?? MAX_REQUIREMENT_ENTRIES;
  let entriesRead = 0;
  for (const lock of head) {
    try {
      if (lock.kind !== "requirements") {
        const text = read(lock.file);
        const parsed = text === undefined ? undefined : parseToml(text);
        if (parsed === undefined || "problem" in parsed) continue;
        out.push(lock.kind === "pylock" ? fromPylock(lock.file, parsePylock(parsed.doc), { pypiIndex: opts.pypiIndex }) : fromUvLock(lock.file, parseUvLock(parsed.doc), { pypiIndex: opts.pypiIndex, kind: lock.kind }));
        continue;
      }
      if (entriesRead > maxEntries) continue;
      // The unit is read in memory: only the files the head's unit read entries from, at their exact paths (no "\\",
      // no empty, "." or ".." segment), so nothing of the base is ever written to disk.
      const files = new Set([lock.file, ...lock.packages.flatMap((p) => (p.file === undefined ? [] : [p.file]))].filter((rel) => !rel.includes("\\") && !rel.split("/").some((s) => s === "" || s === "." || s === "..")));
      const held = (rel: string): Uint8Array | undefined => (files.has(rel) ? bytesOf(rel) : undefined);
      const unit = readRequirements(BASE_ROOT, lock.file, {
        read: (rel) => {
          const b = held(rel);
          return b === undefined ? { problem: "it could not be read (ENOENT)" } : b.length > MAX_REQUIREMENTS_BYTES ? { problem: `it is larger than ${MAX_REQUIREMENTS_BYTES / 1024 / 1024} MiB` } : { bytes: b };
        },
        include: (rel) => (held(rel) === undefined ? { ok: false, problem: `${JSON.stringify(rel)}: not present in the base revision` } : { ok: true }),
      });
      entriesRead += unit.entries.length;
      if (entriesRead > maxEntries) continue;
      out.push(fromRequirements(unit));
    } catch {
      // Nothing from this file.
    }
  }
  return out;
}

/** A root for path arithmetic only (where an include may point): the base's requirements are read in memory. */
const BASE_ROOT = resolve("/", "wormsign-base-revision");

/**
 * The identity of every package in pythonBaseLocks, as `<file>\0<pythonIdentity>`, where the file is the one the entry
 * is in (a requirements entry's own file, else the lock's): an identity counts only in the file that held it.
 */
export function pythonBaseIdentities(read: (rel: string) => string | undefined, head: PyLock[], opts: { pypiIndex: string; maxRequirementEntries?: number; bytes?: (rel: string) => Uint8Array | undefined }): Set<string> {
  return new Set(pythonBaseLocks(read, head, opts).flatMap((l) => l.packages.map((p) => `${p.file ?? l.file}\0${pythonIdentity(p)}`)));
}
