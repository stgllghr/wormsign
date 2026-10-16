/**
 * One model for every Python lockfile soak reads: uv.lock, PEP 723 script locks (`<script>.lock`, the uv.lock format),
 * pylock.toml and requirements files read as hash locks. The readers (uvlock.ts, pylock.ts, requirements.ts) keep each
 * format's own shape; the mappers here turn their output into PyLock, which src/python/soak.ts checks and discovery
 * (src/python/discover.ts) builds.
 *
 * What the model keeps is what decides what an install fetches: the name and version, where the lock says it comes
 * from (source kind and value), and each file the lock pins, with the locator the lock wrote and every hash it gives.
 * src/python/identity.ts digests exactly that.
 *
 * `sendable` says whether the package's name may be sent to the index and to OSV. The mappers set it from the lock:
 * true when the lock records the configured index as the package's source (uv.lock `registry`, pylock `index`); false
 * for everything else, with these two exceptions:
 * - local archives (a uv.lock path archive, a pylock archive or file given by path), which soak binds on the index by
 *   their file name: their names are sent only when --pypi-index was given explicitly (MapOptions.sendLocalArchives),
 *   and never when the lock records another index for them. A repository that vendors its own private wheels would
 *   otherwise send their names to pypi.org on every run;
 * - requirements entries and pylock packages without `index`, which take their index from the install's settings:
 *   discovery passes its install-settings verdict to fromRequirements and fromPylock (`sendable`, and `unsent`, why
 *   not), and they are sendable only when it is true. A pylock package also needs every file URL it gives to be on the
 *   index's file origin (index.ts indexFileOrigin): `pip lock` against a private index records no index, only private
 *   file URLs, and an install from that lock needs no index setting at all.
 * soak never sends a package whose `sendable` is false.
 */
import { posix } from "node:path";
import type { LockedFile } from "./filenames.js";
import type { Pylock, PylockPackage } from "./pylock.js";
import type { RequirementsUnit } from "./requirements.js";
import type { UvLock, UvPackage } from "./uvlock.js";
import { displayUrl, indexFileOrigin, normalizeIndexUrl } from "./index.js";

export type PyLockKind = "uv" | "script" | "pylock" | "requirements";

/**
 * Where a package comes from, as its lock says:
 * - registry: an index, `value` its URL as the lock wrote it ("" when the lock records none: a pylock package without
 *   `index`); a uv `registry` that is a local path (a find-links directory) is a registry whose value is that path;
 * - url, git, vcs: a direct URL, a git source (uv.lock) or a VCS source (pylock: `<type>+<url or path>[@<commit>]`);
 * - path: a uv.lock path archive (always a file: uv records directories as directory/editable/virtual);
 * - directory, editable, virtual: a local source tree (pylock directories are directory or editable);
 * - archive: a pylock [packages.archive], `value` its url or path;
 * - requirements: a requirements-file entry; `value` is "" (the install's index settings decide).
 */
export type PySourceKind = "registry" | "url" | "git" | "path" | "directory" | "editable" | "virtual" | "archive" | "vcs" | "requirements";

export interface PySource {
  kind: PySourceKind;
  value: string;
  subdirectory?: string;
}

export interface PyHash {
  /** As the lock names it (lowercase for every format soak reads). */
  alg: string;
  /** Lowercase hex. */
  digest: string;
}

/** What the lock wrote to find the file: a URL or a relative path, and the file name when one is known. */
export interface PyFileLocator {
  url?: string;
  path?: string;
  filename?: string;
}

export interface PyFile {
  locator: PyFileLocator;
  hashes: PyHash[];
  /** What the lock says the file is; absent for requirements entries, which only list hashes. */
  kind?: "sdist" | "wheel" | "archive";
}

export interface PyPackage {
  /** PEP 503-normalised. */
  name: string;
  /** Canonical PEP 440; absent when the lock gives none (a problem for anything but a local source tree). */
  version?: string;
  source: PySource;
  files: PyFile[];
  /** May the name go to the index and OSV? See the module comment. */
  sendable: boolean;
  /** Why the name may not be sent, when discovery knows; soak puts it in the finding. */
  unsent?: string;
  /** The index the lock records for the package (uv.lock `registry`, pylock `index`), as written. */
  lockIndex?: string;
  /** The file the entry is in, "/"-separated and relative to the root: the lock's, or a requirements include's. */
  file?: string;
  /** Its line, for requirements entries. */
  line?: number;
  /** A requirements entry from a file included with -c. */
  constraint?: boolean;
}

/**
 * A reader's reason that a lockfile could not be read in full, and the sha256 of the content it is about (the
 * [[package]] table, file entry, requirements line or whole file; "" when nothing was read). soak keys the finding on
 * both, so a baseline entry for a problem approves that content only.
 */
export interface ReaderProblem {
  text: string;
  covers: string;
  /** How to fix it, when `text` ends with "; <fix>" (requirements files): left out of the finding's key. */
  fix?: string;
  /** For a requirements file, what the lock rule refused (RequirementsUnit.lockRule). */
  lockRule?: "line" | "file";
  /** Why no baseline entry may approve it (RequirementsUnit.unapprovable); absent when one may. */
  unapprovable?: string;
}

/** A reader's problems and their covers (parallel lists, as the readers keep them) as ReaderProblems. */
export const readerProblems = (r: { problems: string[]; covers: string[]; fixes?: string[] }): ReaderProblem[] =>
  r.problems.map((text, i) => ({ text, covers: r.covers[i] ?? "", ...(r.fixes?.[i] ? { fix: r.fixes[i] } : {}) }));

export interface PyLock {
  kind: PyLockKind;
  /** "/"-separated, relative to the root. */
  file: string;
  packages: PyPackage[];
  /** Every reason the file could not be read in full; soak reports each one (WS-SK-002). */
  problems: ReaderProblem[];
}

export interface MapOptions {
  /** The configured index (--pypi-index), to decide `sendable`. */
  pypiIndex: string;
  /** Local archives' names may be sent to the index (--pypi-index was given explicitly); see the module comment. */
  sendLocalArchives?: boolean;
}

const LOCAL_ARCHIVE_UNSENT = "it is a local archive, which can be checked only by asking the index for its name, and --pypi-index was not given explicitly to allow that";

const sameIndex = (url: string, pypiIndex: string): boolean => {
  const a = normalizeIndexUrl(url);
  return a !== undefined && a === normalizeIndexUrl(pypiIndex);
};

const hashesOf = (f: LockedFile): PyHash[] => Object.entries(f.hashes).map(([alg, digest]) => ({ alg, digest }));

/** The file as the lock wrote it; uv names exactly one of url, path and filename, pylock a url or a path and a name. */
function fileOf(f: LockedFile): PyFile {
  const locator: PyFileLocator = {};
  if (f.url !== undefined) locator.url = f.url;
  if (f.path !== undefined) locator.path = f.path;
  if (f.filename !== undefined) locator.filename = f.filename;
  return { locator, hashes: hashesOf(f), kind: f.kind };
}

/** A uv.lock, or a PEP 723 script lock (`kind: "script"`), read by readUvLock. */
export function fromUvLock(file: string, lock: UvLock, opts: MapOptions & { kind?: "uv" | "script" }): PyLock {
  const packages = lock.packages.map((p) => fromUvPackage(file, p, opts));
  return { kind: opts.kind ?? "uv", file, packages, problems: readerProblems(lock) };
}

function fromUvPackage(file: string, p: UvPackage, opts: MapOptions): PyPackage {
  const s = p.source;
  let source: PySource;
  let sendable = false;
  let unsent: string | undefined;
  let lockIndex: string | undefined;
  switch (s.kind) {
    case "registry":
      source = { kind: "registry", value: s.url };
      lockIndex = s.url;
      sendable = sameIndex(s.url, opts.pypiIndex);
      break;
    case "registry-path":
      source = { kind: "registry", value: s.path };
      lockIndex = s.path;
      break;
    case "url":
      source = s.subdirectory === undefined ? { kind: "url", value: s.url } : { kind: "url", value: s.url, subdirectory: s.subdirectory };
      break;
    case "git":
      source = { kind: "git", value: s.url };
      break;
    case "path":
      source = { kind: "path", value: s.path };
      sendable = opts.sendLocalArchives === true;
      if (!sendable) unsent = LOCAL_ARCHIVE_UNSENT;
      break;
    default:
      source = { kind: s.kind, value: s.path };
  }
  const files = [...(p.sdist ? [p.sdist] : []), ...p.wheels].map(fileOf);
  const pkg: PyPackage = { name: p.name, source, files, sendable, file };
  if (p.version !== undefined) pkg.version = p.version;
  if (unsent !== undefined) pkg.unsent = unsent;
  if (lockIndex !== undefined) pkg.lockIndex = lockIndex;
  return pkg;
}

/** The install-settings verdict discovery gives for entries that record no index: may their names be sent, and why not. */
export interface SendOptions {
  sendable?: boolean;
  unsent?: string;
}

/**
 * A pylock.toml, read by readPylock. A package without `index` (every `pip lock` and PDM export) is sendable only when
 * opts.sendable is true (discovery confirmed the install's index settings) and every file URL it gives is on the
 * index's file origin; otherwise `unsent` says why. A file given by path makes it a local archive (see MapOptions).
 */
export function fromPylock(file: string, lock: Pylock, opts: MapOptions & SendOptions): PyLock {
  return { kind: "pylock", file, packages: lock.packages.map((p) => fromPylockPackage(file, p, opts)), problems: readerProblems(lock) };
}

const NO_INDEX = "the lock records no index for it, so the install's index settings decide where it comes from, and they were not confirmed to be --pypi-index";

function fromPylockPackage(file: string, p: PylockPackage, opts: MapOptions & SendOptions): PyPackage {
  const s = p.source;
  let source: PySource;
  let sendable = false;
  let unsent: string | undefined;
  let lockIndex: string | undefined;
  const files: LockedFile[] = [...(p.sdist ? [p.sdist] : []), ...p.wheels, ...(p.archive ? [p.archive] : [])];
  switch (s.kind) {
    case "files": {
      source = { kind: "registry", value: s.index ?? "" };
      if (s.index !== undefined) {
        lockIndex = s.index;
        sendable = sameIndex(s.index, opts.pypiIndex);
        break;
      }
      // No index: the install's settings decide, and so do the file URLs, which pip and uv fetch as written. A file
      // URL must be the index's own file URL (soak compares it character for character after this), so one on
      // another origin names a private file whatever the settings say.
      const origin = indexFileOrigin(opts.pypiIndex);
      const elsewhere = files.find((f) => f.url !== undefined && (origin === undefined || !f.url.startsWith(`${origin}/`)));
      if (elsewhere !== undefined) {
        unsent = `its file URLs are on ${originOf(elsewhere.url!)}, not the index's (${origin ?? "unknown"})`;
      } else if (files.some((f) => f.path !== undefined) && opts.sendLocalArchives !== true) {
        unsent = LOCAL_ARCHIVE_UNSENT;
      } else {
        sendable = opts.sendable === true;
        if (!sendable) unsent = opts.unsent ?? NO_INDEX;
      }
      break;
    }
    case "archive": {
      const a = p.archive;
      source = { kind: "archive", value: a?.url ?? a?.path ?? "" };
      if (s.subdirectory !== undefined) source.subdirectory = s.subdirectory;
      if (s.index !== undefined) lockIndex = s.index;
      // A path archive is bound on the index by its file name, as a uv.lock path archive is: its name is sent only
      // with an explicit --pypi-index, and never when the lock records another index for it.
      if (a?.path !== undefined) {
        const otherIndex = s.index !== undefined && !sameIndex(s.index, opts.pypiIndex);
        sendable = !otherIndex && opts.sendLocalArchives === true;
        if (otherIndex) unsent = `the lock records the index ${displayUrl(s.index!)} for it, not --pypi-index`;
        else if (!sendable) unsent = LOCAL_ARCHIVE_UNSENT;
      }
      break;
    }
    case "vcs":
      source = { kind: "vcs", value: `${s.type}+${s.url ?? s.path ?? ""}${s.commitId === undefined ? "" : `@${s.commitId}`}` };
      if (s.subdirectory !== undefined) source.subdirectory = s.subdirectory;
      break;
    case "directory":
      source = { kind: s.editable ? "editable" : "directory", value: s.path };
      if (s.subdirectory !== undefined) source.subdirectory = s.subdirectory;
      break;
  }
  const pkg: PyPackage = { name: p.name, source, files: files.map(fileOf), sendable, file };
  if (p.version !== undefined) pkg.version = p.version;
  if (unsent !== undefined) pkg.unsent = unsent;
  if (lockIndex !== undefined) pkg.lockIndex = lockIndex;
  return pkg;
}

const REQUIREMENTS_UNSENT = "a requirements file records no index, so the install's index settings decide where it comes from, and they were not confirmed to be --pypi-index";

/**
 * A requirements unit (a file and its -r/-c includes), read by readRequirements. Each entry becomes one package whose
 * files are its hashes, one file per digest: a requirements file pins hashes, not files. `sendable` is false unless
 * the caller has confirmed the install's index settings (opts.sendable).
 */
export function fromRequirements(unit: RequirementsUnit, opts: SendOptions = {}): PyLock {
  const packages = unit.entries.map((e): PyPackage => {
    const files: PyFile[] = Object.entries(e.hashes).flatMap(([alg, digests]) => digests.map((digest) => ({ locator: {}, hashes: [{ alg, digest }] })));
    const pkg: PyPackage = { name: e.name, version: e.version, source: { kind: "requirements", value: "" }, files, sendable: opts.sendable === true, file: e.file, line: e.line };
    if (!pkg.sendable) pkg.unsent = opts.unsent ?? REQUIREMENTS_UNSENT;
    if (e.constraint) pkg.constraint = true;
    return pkg;
  });
  const problems = readerProblems(unit).map((p, i) => {
    const rule = unit.lockRule[i];
    return { ...p, ...(rule === undefined ? {} : { lockRule: rule }), ...(unit.unapprovable[i] === undefined ? {} : { unapprovable: unit.unapprovable[i] }) };
  });
  return { kind: "requirements", file: unit.file, packages, problems };
}

/** A URL's scheme and host as messages show it, without userinfo, path or query; the URL itself when it is none. */
function originOf(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`;
  } catch {
    return displayUrl(url);
  }
}

/** The lockfile's directory, "/"-separated and relative to the root ("" for the root itself), as paths.ts takes it. */
export function lockDir(file: string): string {
  const d = posix.dirname(file);
  return d === "." ? "" : d;
}

/** The sha256 a file is bound by, if the lock gives one. */
export function sha256Of(f: PyFile): string | undefined {
  return f.hashes.find((h) => h.alg === "sha256")?.digest;
}

/** A file as messages name it: its file name, else its path or URL, else its first hash. */
export function fileLabel(f: PyFile): string {
  const h = f.hashes[0];
  return f.locator.filename ?? f.locator.path ?? f.locator.url ?? (h ? `${h.alg}:${h.digest}` : "a file entry");
}
