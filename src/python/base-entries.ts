/**
 * PR mode (soak --base) for Python lock entries, as for npm entries (src/main.ts, src/soak.ts onlyKey): an entry the
 * base's own soak read identically is not checked again. Only entries: every reader and file-level problem is reported
 * on every run, PR mode or not, as npm's lockfile problems are. src/python/soak.ts asks; docs/soak.md, "PR mode", says
 * it for users.
 *
 * Read as a lock (readsLockAs). The base's soak read a file as a lock of a kind only when, on the base as committed:
 * - the ignorePaths main.ts gives (the run's baseline's and the base's own committed baseline's: either passes a file
 *   over) do not pass it over, and no part of its path is .git or node_modules, which the walk skips (src/walk.ts);
 *   when they are unknown, nothing counts as read;
 * - it is a regular file under exactly that path: no symlink on the way, and no other entry whose name folds like it,
 *   which a case-insensitive checkout would merge (src/tree.ts Tree.entry);
 * - by a name discovery (src/python/discover.ts) reads without any other file's help: uv.lock and pylock.toml; a
 *   requirements file by name (manifest.ts) that pip and uv do not both refuse (scripts.ts refusedByPipAndUv, over its
 *   bytes as stored); `<script>.lock` beside a regular file, itself not passed over, that holds a `# /// script` block.
 * A file discovery finds only by its content or through an include, an orphan script lock, the lock of a script whose
 * block has a problem, and anything else this cannot tell count as not read: noisier, never quieter. base-builds.ts
 * baseReadsLock is the same rule for WS-SK-005.
 *
 * The base's reading (lockOf) is that file read by the head's readers and mappers, in memory, never written to disk,
 * from the blobs as git stores them (Tree.entry runs `git show <rev>:<path>`, which applies no checkout conversion): a
 * requirements unit by readRequirements, following every include the base holds as a regular file, as a checkout
 * would; a uv.lock, script lock or pylock.toml by tomlOfBytes, which is how readToml reads a file once it has its
 * bytes. A checkout holds other bytes than git stores where the base's git attributes set working-tree-encoding,
 * filter or ident, and the base's soak read the checkout, so the reading is no reading when any file it read has one
 * of them (Tree.attributes: `git check-attr --source`, which reads the base's .gitattributes above the scanned root
 * too, and info/attributes). When git cannot tell (older than 2.40, which has no --source), nothing is the base's.
 * A .gitattributes blob a partial clone lacks would read as no attributes, so Tree.attributes refuses then too.
 * It is no reading either when the base's requirements files hold more entries between them than discovery reads
 * (MAX_REQUIREMENT_ENTRIES): the base's own soak stopped there, so some unit it did not read. That is counted over every
 * base file by requirements name, every one its content marks as requirements (scripts.ts looksLikeRequirements, in
 * one batch read: Tree.blobs) and the base's copy of each head unit; when they cannot all be read, nothing counts.
 * Each such case is a note.
 *
 * The base's entries (holds). An entry is the base's only when:
 * - its lock is read as a lock of its kind on the base, and so is the file the entry is in, as a requirements file,
 *   when that is another one (an entry from an include);
 * - a requirements unit is a complete hash lock on both sides: no reader problem at all, so a --require-hashes line,
 *   every requirement hashed, no index option and no include left unfollowed;
 * - the base's reading holds an entry with the same entryIdentity;
 * - the entry gives a version and at least one file, and every file has hashes, all of them sha256: only hashes fix
 *   what an install fetches, and soak binds sha256 only. Any other entry is checked as on a full run (where it fails
 *   closed anyway).
 * The identity is what the lock records, as its reader gives it (a PEP 503 name, a PEP 440 version in canonical form),
 * not what an installer would make of it (ADR 0004).
 *
 * Index settings are not part of the identity. A change to pip.conf, pip.ini, uv.toml, [tool.uv] or the environment
 * with the pins and hashes unchanged leaves the entries the base's, and that is safe: an install checks each file it
 * fetches against the locked hashes, whichever index serves it (pip with --require-hashes, uv for every hash a lock
 * gives), so the bytes are the ones the base's soak bound and aged, and their age is the same; or, if the base's soak
 * could not check them (another index), it reported each of them. That the hashes are checked at all is itself a
 * setting: one that turns them off is WS-SK-002 "an install may skip hash checks", and one that names another index
 * WS-SK-002 "an install may use another index", both discovery's and reported on every run. An index option in the
 * requirements file itself is a reader problem, so that unit is no complete hash lock and its entries are checked again.
 *
 * Never throws: anything unexpected makes nothing the base's.
 */
import { posix, resolve } from "node:path";
import { isIgnored } from "../baseline.js";
import type { BaseRevision } from "./base-builds.js";
import { MAX_REQUIREMENT_ENTRIES } from "./discover.js";
import { isPylockFileName, isRequirementsName, isUvLockName, ownReader } from "./manifest.js";
import { fromPylock, fromRequirements, fromUvLock, type PyLock, type PyLockKind, type PyPackage } from "./model.js";
import { parseScriptBlock } from "./pep723.js";
import { pylockOf } from "./pylock.js";
import { MAX_REQUIREMENTS_BYTES, readRequirements, type RequirementsSource } from "./requirements.js";
import { isContentCandidate, looksLikeRequirements, refusedByPipAndUv } from "./scripts.js";
import { MAX_TOML_BYTES, tomlOfBytes } from "./toml.js";
import { uvLockOf } from "./uvlock.js";

/** What src/python/soak.ts asks about the base (see the module comment). */
export interface BaseLocks {
  /** Did the base's soak read this entry of this lock identically, so that PR mode need not check it again? */
  holds(lock: PyLock, pkg: PyPackage): boolean;
  /** What made locks or the whole base count as not read, for the report's notes. */
  notes(): string[];
}

/** Nothing is the base's: every entry is checked. */
export const nothingOnBase = (why?: string): BaseLocks => ({ holds: () => false, notes: () => (why === undefined ? [] : [`PR mode: no Python entry counts as the base's, since ${why}`]) });

/**
 * What the lock records for an entry, and where: its kind and file, the file the entry is in, the PEP 503 name, the
 * version, the source (kind, value, subdirectory), the index the lock records, whether it came from a -c include, and
 * every file with its url, path, file name and kind as the lock wrote them and every hash it gives. Lines and order
 * are not part of it: an entry moved within its file is the same entry.
 */
export function entryIdentity(lock: PyLock, p: PyPackage): string {
  const files = p.files.map((f) => JSON.stringify([f.locator.url ?? null, f.locator.path ?? null, f.locator.filename ?? null, f.kind ?? null, f.hashes.map((h) => `${h.alg}:${h.digest}`).sort()])).sort();
  return JSON.stringify([lock.kind, lock.file, p.file ?? lock.file, p.name, p.version ?? null, p.source.kind, p.source.value, p.source.subdirectory ?? null, p.lockIndex ?? null, p.constraint === true, files]);
}

/** Only hashes fix what an install fetches: a version, at least one file, and every file with only sha256 hashes. */
const hashFixed = (p: PyPackage): boolean => p.version !== undefined && p.files.length > 0 && p.files.every((f) => f.hashes.length > 0 && f.hashes.every((h) => h.alg === "sha256"));

/** A requirements unit with no reader problem: a --require-hashes line, every requirement hashed, nothing unread. */
const completeHashLock = (l: PyLock): boolean => l.kind !== "requirements" || l.problems.length === 0;

/** A root for path arithmetic only (where an include may point): the base's requirements are read in memory. */
const BASE_ROOT = resolve("/", "wormsign-base-revision");

/** The most bytes of the base's possible requirements files read to count their entries; past it nothing is the base's. */
const MAX_CONTENT_READ = 256 * 1024 * 1024;

/** The git attributes that make a checkout's bytes differ from the blob's (gitattributes(5)). */
export const CONVERTING_ATTRIBUTES = ["working-tree-encoding", "filter", "ident"];

/**
 * The base revision's locks as its own soak read them, for the head's `head` locks. `ignore` is the ignorePaths that
 * may have passed a file over on the base (undefined when they are unknown: then nothing is the base's).
 */
export function baseLocks(
  base: Pick<BaseRevision, "read" | "entry" | "list" | "attributes" | "blobs">,
  head: readonly PyLock[],
  opts: { pypiIndex: string; ignore: readonly string[] | undefined; maxRequirementEntries?: number },
): BaseLocks {
  try {
    return readBase(base, head, opts);
  } catch {
    return nothingOnBase("the base revision could not be read");
  }
}

function readBase(base: Pick<BaseRevision, "read" | "entry" | "list" | "attributes" | "blobs">, head: readonly PyLock[], opts: { pypiIndex: string; ignore: readonly string[] | undefined; maxRequirementEntries?: number }): BaseLocks {
  const ignore = opts.ignore === undefined ? undefined : [...opts.ignore];
  if (ignore === undefined) return nothingOnBase();
  const notes: string[] = [];
  const passedOver = (rel: string): boolean => isIgnored(rel, ignore) || rel.split("/").some((s) => s === ".git" || s === "node_modules");
  const safe = (rel: string): boolean => rel !== "" && !posix.isAbsolute(rel) && !rel.includes("\\") && !rel.split("/").some((s) => s === "" || s === "." || s === "..");
  /** The bytes git stores for a regular file under exactly `rel` (Tree.entry: at most MAX_ENTRY_BYTES). */
  const blob = (rel: string): Buffer | undefined => {
    if (!safe(rel)) return undefined;
    const e = base.entry(rel);
    return e?.kind === "file" ? e.bytes : undefined;
  };
  /** The same, for a file the base's walk reaches. */
  const fileAt = (rel: string): Buffer | undefined => (passedOver(rel) ? undefined : blob(rel));

  /** Paths whose checkout the base's attributes convert; undefined once git could not tell, and then nothing counts. */
  let converting: Set<string> | undefined = new Set();
  const asked = new Set<string>();
  /** Does any of `files` hold, in a checkout of the base, other bytes than git stores (or is that unknown)? */
  const converted = (files: string[]): boolean => {
    const ask = files.filter((f) => !asked.has(f));
    if (converting !== undefined && ask.length > 0) {
      for (const f of ask) asked.add(f);
      try {
        if (base.attributes === undefined) throw new Error("the base revision's git attributes are unknown");
        const attrs = base.attributes(ask, CONVERTING_ATTRIBUTES);
        for (const f of ask) {
          const set = CONVERTING_ATTRIBUTES.filter((a) => !["unspecified", "unset"].includes(attrs.get(f)?.get(a) ?? "unspecified"));
          if (set.length > 0) {
            converting.add(f);
            notes.push(`PR mode: ${f} is not counted as the base's, since the base revision's git attributes set ${set.join(", ")} for it, so a checkout of it holds other bytes than git stores`);
          }
        }
      } catch (e) {
        converting = undefined;
        notes.push(`PR mode: no Python entry counts as the base's, since git could not read the base revision's attributes (${String((e as Error)?.message ?? e).split("\n")[0]!.slice(0, 300)}; git 2.40 or later reads them with check-attr --source)`);
      }
    }
    return converting === undefined || files.some((f) => converting!.has(f));
  };

  const kinds = new Map<string, boolean>();
  const readsLockAs = (file: string, kind: PyLockKind): boolean => {
    const k = `${kind}\0${file}`;
    let r = kinds.get(k);
    if (r === undefined) {
      r = readsAs(file, kind);
      kinds.set(k, r);
    }
    return r;
  };
  const readsAs = (file: string, kind: PyLockKind): boolean => {
    const bytes = fileAt(file);
    if (bytes === undefined) return false;
    const name = posix.basename(file);
    switch (kind) {
      case "uv":
        return isUvLockName(name);
      case "pylock":
        return isPylockFileName(name);
      case "requirements":
        return isRequirementsName(file) && !refusedByPipAndUv(bytes);
      case "script": {
        if (!file.endsWith(".lock")) return false;
        const script = file.slice(0, -".lock".length);
        const text = ownReader(posix.basename(script)) ? undefined : fileAt(script);
        return text !== undefined && parseScriptBlock(text).kind === "block";
      }
    }
  };

  // Requirements units, read as discovery reads them from a checkout, includes followed to any regular file.
  const source: RequirementsSource = {
    read: (rel) => {
      const b = blob(rel);
      return b === undefined ? { problem: "it could not be read (ENOENT)" } : b.length > MAX_REQUIREMENTS_BYTES ? { problem: `it is larger than ${MAX_REQUIREMENTS_BYTES / 1024 / 1024} MiB` } : { bytes: b };
    },
    include: (rel) => (blob(rel) === undefined ? { ok: false, problem: `${JSON.stringify(rel)}: not a regular file in the base revision` } : { ok: true }),
  };
  /** Each base unit read, with every file it read. */
  const units = new Map<string, { lock: PyLock; files: string[] }>();
  const unitAt = (file: string): { lock: PyLock; files: string[] } => {
    let u = units.get(file);
    if (u === undefined) {
      const unit = readRequirements(BASE_ROOT, file, source);
      u = { lock: fromRequirements(unit), files: unit.files };
      units.set(file, u);
    }
    return u;
  };
  /**
   * The base's files discovery would find as requirements by their content (scripts.ts looksLikeRequirements, among the
   * names its content pass opens), read in one batch; undefined when they cannot all be read (then the count is unknown).
   */
  const byContent = (): string[] | undefined => {
    const candidates = base.list().filter((p) => !passedOver(p) && !isRequirementsName(p) && !ownReader(posix.basename(p)) && isContentCandidate(posix.basename(p)));
    try {
      const bytes = base.blobs ? base.blobs(candidates, MAX_CONTENT_READ) : new Map(candidates.flatMap((p) => { const b = blob(p); return b === undefined ? [] : [[p, b] as const]; }));
      return candidates.filter((p) => {
        const b = bytes.get(p);
        return b !== undefined && looksLikeRequirements(b) && !refusedByPipAndUv(b);
      });
    } catch (e) {
      notes.push(`PR mode: no Python requirements entry counts as the base's, since the base revision's files that may be requirements files could not all be read to count their entries (${String((e as Error)?.message ?? e).split("\n")[0]!.slice(0, 200)})`);
      return undefined;
    }
  };
  /** Did the base's soak stop at MAX_REQUIREMENT_ENTRIES? Every base unit is read once to count, on first need. */
  let overBound: boolean | undefined;
  const requirementsBounded = (): boolean => {
    if (overBound === undefined) {
      const max = opts.maxRequirementEntries ?? MAX_REQUIREMENT_ENTRIES;
      const found = byContent();
      if (found === undefined) return (overBound = true);
      const files = new Set([...base.list().filter((p) => isRequirementsName(p) && readsLockAs(p, "requirements")), ...found, ...head.filter((l) => l.kind === "requirements" && blob(l.file) !== undefined).map((l) => l.file)]);
      let total = 0;
      for (const f of files) {
        total += unitAt(f).lock.packages.length;
        if (total > max) break;
      }
      overBound = total > max;
      if (overBound) notes.push(`PR mode: no Python requirements entry counts as the base's, since the base revision's requirements files hold more than ${max} entries between them, more than soak reads`);
    }
    return overBound;
  };
  const toml = (lock: PyLock): PyLock | undefined => {
    // Tree.entry reads at most MAX_ENTRY_BYTES, readToml MAX_TOML_BYTES: the same 64 MiB (a larger blob is no reading).
    const bytes = fileAt(lock.file);
    if (bytes === undefined || bytes.length > MAX_TOML_BYTES || converted([lock.file])) return undefined;
    const read = tomlOfBytes(bytes);
    if (lock.kind === "pylock") return fromPylock(lock.file, pylockOf(read), { pypiIndex: opts.pypiIndex });
    return fromUvLock(lock.file, uvLockOf(read), { pypiIndex: opts.pypiIndex, kind: lock.kind === "script" ? "script" : "uv" });
  };

  const readings = new Map<string, PyLock | undefined>();
  const lockOf = (lock: PyLock): PyLock | undefined => {
    const k = `${lock.kind}\0${lock.file}`;
    if (readings.has(k)) return readings.get(k);
    let out: PyLock | undefined;
    try {
      if (!readsLockAs(lock.file, lock.kind)) out = undefined;
      else if (lock.kind !== "requirements") out = toml(lock);
      else {
        const u = unitAt(lock.file);
        out = converted(u.files) || requirementsBounded() ? undefined : u.lock;
      }
    } catch {
      out = undefined;
    }
    readings.set(k, out);
    return out;
  };
  const identities = new Map<PyLock, Set<string>>();
  const holds = (lock: PyLock, pkg: PyPackage): boolean => {
    try {
      if (!hashFixed(pkg) || !completeHashLock(lock)) return false;
      const before = lockOf(lock);
      if (before === undefined || !completeHashLock(before)) return false;
      const file = pkg.file ?? lock.file;
      if (file !== lock.file && !readsLockAs(file, "requirements")) return false;
      let ids = identities.get(before);
      if (ids === undefined) {
        ids = new Set(before.packages.map((p) => entryIdentity(before, p)));
        identities.set(before, ids);
      }
      return ids.has(entryIdentity(lock, pkg));
    } catch {
      return false;
    }
  };
  return { holds, notes: () => [...notes] };
}
