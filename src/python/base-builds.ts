/**
 * PR mode (--base): a WS-SK-005 the change adds is high, so the default --fail-on high stops it. A build the base
 * already had stays medium (docs/soak.md, "Builds: WS-SK-005"). Otherwise a pull request could add a just-published
 * build backend to [build-system].requires, or an sdist-only dependency whose build pulls a fresh package, and pass.
 *
 * A finding is the base's when the base, read the same way, gives the same key, and, for a lock's build or sdist-only
 * package, when the base's own soak read that lock (baseReadsLock): text at the same path is not enough, since a file
 * can hold a lock's text without any soak reading it as one (a lone `<name>.lock` with no script, a requirements file
 * found only through an include or by content). So:
 * - a local build (`pypi:build <dir> <digest>`): the base's copy of the same lock must list a directory or editable
 *   source at that directory, and build.ts localBuild digests the base's files there straight from git
 *   (gitBuildReader over src/tree.ts Tree.entry: a blob's bytes undecoded, a symlink's link text, a directory's
 *   names), as it digests the head's from disk, so files identical on both sides give the same digest. Nothing is
 *   written anywhere. Anything the base lacks or holds differently gives another digest, and an entry it cannot show
 *   plainly (a name another entry folds like, which a case-insensitive disk would merge; a blob over the cap or that
 *   git cannot read) makes the build new: noisier, never quieter;
 * - a package locked only as an sdist (`pypi:<name>@<version> sdist-only <identity>`): the base's copy of the file the
 *   entry is in must hold a package of that identity (src/python/discover.ts pythonBaseIdentities, which reads a
 *   requirements unit's bytes as stored, in memory);
 * - build-forcing configuration (`pypi:build-config ...`): buildConfigFindings over the base's text of the same file,
 *   read as TOML and as a script's `# /// script` block;
 * - a symlinked uv.toml: what it leads to is not followed on either side, so it is always new in PR mode (a
 *   baseline entry keeps it quiet, as on a full run).
 * The fingerprint is unchanged, so a baseline entry for the finding still matches. Never throws.
 */
import { posix } from "node:path";
import type { Finding } from "../types.js";
import { localBuild, type BuildReader } from "./build.js";
import { pythonBaseIdentities, pythonBaseLocks } from "./discover.js";
import { buildConfigFindings } from "./indexes.js";
import { isPylockFileName, isRequirementsName, isUvLockName } from "./manifest.js";
import { lockDir, type PyLock } from "./model.js";
import { parseScriptBlock } from "./pep723.js";
import { refusedByPipAndUv } from "./scripts.js";
import { parseToml } from "./toml.js";
import type { TreeEntry } from "../tree.js";

/** The base revision as main.ts gives it: root-relative paths. */
export interface BaseRevision {
  read(rel: string): string | undefined;
  list(): string[];
  /** A regular file under exactly that path, no symlink on the way (src/tree.ts Tree.regularFile). */
  regularFile(rel: string): boolean;
  /** What the base holds under exactly that path, bytes never decoded (src/tree.ts Tree.entry). */
  entry(rel: string): TreeEntry | undefined;
  /** The base revision's git attributes for these paths (src/tree.ts Tree.attributes); base-entries.ts asks. */
  attributes?(paths: string[], names: string[]): Map<string, Map<string, string>>;
  /** The base revision's blobs at these paths, in one read (src/tree.ts Tree.blobs); base-entries.ts asks. */
  blobs?(paths: string[], maxTotal: number): Map<string, Buffer>;
}

/** What the head read: its locks (to find the files a requirements unit read) and the index they were mapped for. */
export interface HeadLocks {
  locks: PyLock[];
  pypiIndex: string;
}

/** A root-relative "/"-separated path that stays inside the root. */
const safe = (rel: string): boolean => rel !== "" && !rel.includes("\0") && !posix.isAbsolute(rel) && !posix.normalize(rel).split("/").includes("..");

/** The findings with every WS-SK-005 the base does not give raised to high (see the module comment). */
export function raiseNewBuilds(findings: Finding[], base: BaseRevision, label: string, head: HeadLocks): Finding[] {
  return findings.map((f) => {
    if (f.ruleId !== "WS-SK-005" || f.severity !== "medium") return f;
    let onBase: boolean;
    try {
      onBase = isOnBase(f, base, head);
    } catch {
      // Anything unexpected while reading the base: the build counts as new.
      onBase = false;
    }
    return onBase ? f : { ...f, severity: "high" as const, message: `${f.message} This change adds it (${label} does not have it), so it is high in PR mode.` };
  });
}

/**
 * Did the base's own soak read `file` as a lock? By the names discovery reads without any other file's help: uv.lock and
 * pylock.toml as regular files; a requirements file by name (src/python/manifest.ts) that pip and uv do not both refuse;
 * a script lock `<script>.lock` only beside a regular file holding a `# /// script` block. A file discovery reaches
 * only through an include or by its content counts as not read: noisier, never quieter.
 */
export function baseReadsLock(base: BaseRevision, file: string): boolean {
  if (!base.regularFile(file)) return false;
  const name = posix.basename(file);
  if (isUvLockName(name) || isPylockFileName(name)) return true;
  if (isRequirementsName(file)) {
    const text = base.read(file);
    return text !== undefined && !refusedByPipAndUv(Buffer.from(text, "utf8"));
  }
  if (!file.endsWith(".lock")) return false;
  const script = file.slice(0, -".lock".length);
  const text = base.regularFile(script) ? base.read(script) : undefined;
  return text !== undefined && parseScriptBlock(Buffer.from(text, "utf8")).kind === "block";
}

/** The head locks that hold a package in `file` (a requirements entry's own file, else the lock) matching `test`. */
const headLocksWith = (head: HeadLocks, file: string, test: (p: PyLock["packages"][number]) => boolean): PyLock[] => head.locks.filter((l) => l.packages.some((p) => (p.file ?? l.file) === file && test(p)));

function isOnBase(f: Finding, base: BaseRevision, head: HeadLocks): boolean {
  if (f.key === "pypi:build-config symlink") return false;
  if (f.key.startsWith("pypi:build-config ")) {
    if (f.file === undefined) return false;
    const text = base.read(f.file);
    if (text === undefined) return false;
    const parsed = parseToml(text);
    const block = parseScriptBlock(Buffer.from(text, "utf8"));
    const before = [...("doc" in parsed ? buildConfigFindings(f.file, parsed.doc) : []), ...(block.kind === "block" ? buildConfigFindings(f.file, block.metadata, "script") : [])];
    return before.some((b) => b.fingerprint === f.fingerprint);
  }
  const sdist = / sdist-only ([0-9a-f]{64})$/.exec(f.key);
  if (sdist !== null && f.key.startsWith("pypi:")) {
    if (f.file === undefined || !baseReadsLock(base, f.file)) return false;
    const id = `pypi:${sdist[1]}`;
    const locks = headLocksWith(head, f.file, () => true);
    return pythonBaseIdentities((rel) => base.read(rel), locks, { pypiIndex: head.pypiIndex, bytes: baseBytes(base) }).has(`${f.file}\0${id}`);
  }
  if (f.key.startsWith("pypi:build ")) {
    const rest = f.key.slice("pypi:build ".length);
    const at = rest.lastIndexOf(" ");
    const where = rest.slice(0, at);
    const digest = rest.slice(at + 1);
    const dir = where === "." ? "" : where;
    if (dir !== "" && !safe(dir)) return false;
    // The base's own soak must have read the lock, and the lock must list a source tree at this directory there.
    if (f.file === undefined || !baseReadsLock(base, f.file)) return false;
    const lock = head.locks.find((l) => l.file === f.file);
    const before = lock === undefined ? [] : pythonBaseLocks((rel) => base.read(rel), [lock], { pypiIndex: head.pypiIndex, bytes: baseBytes(base) });
    const listed = before.some((l) =>
      l.packages.some((p) => (p.source.kind === "directory" || p.source.kind === "editable") && posix.normalize(posix.join(lockDir(l.file) || ".", localTree(p.source))) === (dir === "" ? "." : dir)),
    );
    if (!listed) return false;
    // The base's files, read from git as build.ts reads the head's from disk; nothing is written. An entry the base
    // cannot show plainly (a name another folds like, a blob over the cap or unreadable) counts the build as new.
    const b = localBuild(gitBuildReader(base, dir), lock?.kind === "uv" ? gitBuildReader(base, lockDir(f.file)) : undefined);
    return !b.unreadable && b.digest === digest;
  }
  // Anything else: new.
  return false;
}

/** A base file's bytes as git stores them (Tree.entry: a regular file, never decoded), for the requirements reader. */
function baseBytes(base: BaseRevision): (rel: string) => Uint8Array | undefined {
  return (rel) => {
    const e = base.entry(rel);
    return e?.kind === "file" ? e.bytes : undefined;
  };
}

/**
 * The base's directory `dir` as a BuildReader (src/python/build.ts): Tree.entry of each path, exact names only. A
 * symlink on the way is a problem, as on disk; an absent path is missing. diff reads both of its git revisions with it
 * (src/diff.ts pythonBuildFindings).
 */
export function gitBuildReader(base: Pick<BaseRevision, "entry">, dir: string): BuildReader {
  const full = (rel: string): string => (dir === "" ? rel : rel === "" ? dir : `${dir}/${rel}`);
  return {
    entry(rel) {
      const parts = rel === "" ? [] : rel.split("/");
      for (let i = 1; i < parts.length; i++) {
        const e = base.entry(full(parts.slice(0, i).join("/")));
        if (e === undefined) return { kind: "missing" };
        if (e.kind === "symlink") return { kind: "problem", why: `${parts.slice(0, i).join("/")} is a symlink on the way` };
        if (e.kind === "problem") return e;
      }
      const e = base.entry(full(rel));
      return e === undefined ? { kind: "missing" } : e;
    },
  };
}

/** The directory a local source tree's install builds (src/python/soak.ts localSourcePath, without importing soak.ts). */
const localTree = (s: PyLock["packages"][number]["source"]): string => (s.subdirectory === undefined ? s.value : s.value === "." ? s.subdirectory : `${s.value}/${s.subdirectory}`);
