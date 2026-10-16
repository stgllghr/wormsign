/**
 * pylock.toml reader (PEP 751, the "pylock.toml Specification" at packaging.python.org; lock-version 1.x).
 *
 * Returns one typed entry per [[packages]] table, in file order. Never throws; every reason the file cannot be read in
 * full is in `problems`, and a caller must treat a lock with problems as unverified, whatever `packages` holds.
 *
 * Strictness, beyond what the specification requires of an installer:
 * - an unknown key at the top level, in a package, in a source table or in a file entry is a problem (the
 *   specification lets a 1.x reader merely warn), so a field that changes what is installed cannot pass unread;
 * - a package names exactly one source: [packages.vcs], [packages.directory], [packages.archive], or sdist and/or
 *   wheels (the specification makes them mutually exclusive);
 * - every file entry (sdist, wheel, archive) needs a hashes table holding a sha256, or it "cannot be bound to an index
 *   file"; a package with no file entries at all is a problem unless its source is a local directory or VCS;
 * - a file entry gives a url or a path, not both: pip 26.2.1 and uv 0.12.21 install from the path when both are there
 *   (pip's _package_dist_url; uv's PylockTomlWheel, PylockTomlSdist and PylockTomlArchive), and pip 26.2.1's
 *   `pip lock` and uv 0.12.21's `uv export` each write only one;
 * - a package without `version` is a problem unless it is a directory or VCS source tree (which must not have one),
 *   since it can be neither bound nor checked against OSV.
 * `created-by` and each file's `upload-time` are recorded, never trusted. Comparing `index` and file URLs with the index
 * and checking local paths are the caller's.
 *
 * Each problem has a digest of the content it is about in `covers`, as in uvlock.ts: the [[packages]] table or file
 * entry it is about (toml.ts contentDigest), else the file's bytes (or the whole document's canonical form).
 */
import { basenameOf, bindSha256, isHexDigest, type FileHashes, type LockedFile } from "./filenames.js";
import { projectName } from "./names.js";
import { canonicalVersion } from "./pep440.js";
import { contentDigest, get, isSafeCount, isTable, offsetDateTime, readToml, show, unknownKeys, type TomlRead, type TomlTable } from "./toml.js";

export type PylockSource =
  | { kind: "files"; index?: string }
  | { kind: "archive"; index?: string; subdirectory?: string }
  | { kind: "vcs"; type: string; url?: string; path?: string; commitId?: string; subdirectory?: string }
  | { kind: "directory"; path: string; editable: boolean; subdirectory?: string };

export interface PylockPackage {
  /** Position among the [[packages]] tables, from 0. */
  index: number;
  /** PEP 503-normalised. */
  name: string;
  /** Canonical PEP 440 version, when the lock gives one. */
  version?: string;
  marker?: string;
  source: PylockSource;
  sdist?: LockedFile;
  wheels: LockedFile[];
  archive?: LockedFile;
}

export interface Pylock {
  lockVersion?: string;
  createdBy?: string;
  requiresPython?: string;
  packages: PylockPackage[];
  problems: string[];
  /** For each problem, the sha256 of the content it is about (see the module comment); "" when nothing was read. */
  covers: string[];
}

const TOP_KEYS = ["lock-version", "environments", "requires-python", "extras", "dependency-groups", "default-groups", "created-by", "packages", "tool"];
const PACKAGE_KEYS = ["name", "version", "marker", "requires-python", "dependencies", "vcs", "directory", "archive", "index", "sdist", "wheels", "attestation-identities", "tool"];
const FILE_KEYS = ["name", "upload-time", "url", "path", "size", "hashes"];
const ARCHIVE_KEYS = ["url", "path", "size", "upload-time", "hashes", "subdirectory"];
const VCS_KEYS = ["type", "url", "path", "requested-revision", "commit-id", "subdirectory"];
const DIRECTORY_KEYS = ["path", "editable", "subdirectory"];

/** The lock-version values read: major version 1, any minor ("1.0" is the only one published). */
const LOCK_VERSION = /^1\.(0|[1-9][0-9]*)$/;

/** pylock.toml and pylock.<name>.toml, per the specification's file name rule. */
export const isPylockName = (base: string): boolean => /^pylock\.([^.]+\.)?toml$/.test(base);

/** Reads a pylock.toml file. */
export function readPylock(path: string): Pylock {
  return pylockOf(readToml(path));
}

/** A pylock.toml from readToml's or tomlOfBytes' reading of it. */
export function pylockOf(read: TomlRead): Pylock {
  if ("problem" in read) return { packages: [], problems: [read.problem], covers: [read.sha256 ?? ""] };
  return parsePylock(read.doc, read.sha256);
}

/** A problem and the digest of the content it is about. */
type Problem = (m: string, covers: string) => void;

const keysList = (keys: string[]): string => keys.map((k) => JSON.stringify(k)).join(", ");

/**
 * Interprets a parsed pylock.toml document. `fileSha256` is the digest of the file's bytes, which a problem with the
 * whole document covers; without it, the document's canonical form.
 */
export function parsePylock(doc: TomlTable, fileSha256?: string): Pylock {
  const out: Pylock = { packages: [], problems: [], covers: [] };
  const problem: Problem = (m, covers) => {
    out.problems.push(m);
    out.covers.push(covers);
  };
  let whole: string | undefined;
  const top = (m: string): void => problem(m, (whole ??= fileSha256 ?? contentDigest(doc)));
  const extra = unknownKeys(doc, TOP_KEYS);
  if (extra.length > 0) top(`unknown top-level key(s) ${keysList(extra)}: format not supported`);
  const lockVersion = get(doc, "lock-version");
  if (typeof lockVersion !== "string" || !LOCK_VERSION.test(lockVersion)) {
    top(`lock-version ${show(lockVersion ?? null)} is not 1.x: format not supported`);
    return out;
  }
  out.lockVersion = lockVersion;
  const createdBy = get(doc, "created-by");
  if (typeof createdBy === "string") out.createdBy = createdBy;
  const rp = get(doc, "requires-python");
  if (typeof rp === "string") out.requiresPython = rp;

  const packages = get(doc, "packages");
  if (!Array.isArray(packages)) {
    top("no [[packages]] array: format not supported");
    return out;
  }
  packages.forEach((raw, index) => {
    const pkg = readPackage(raw, index, problem);
    if (pkg) out.packages.push(pkg);
  });
  return out;
}

function readPackage(raw: unknown, index: number, report: Problem): PylockPackage | undefined {
  const where = `[[packages]] #${index + 1}`;
  // A problem with the package (its name, version, index or source) covers the whole [[packages]] table.
  let digest: string | undefined;
  const problem = (m: string): void => report(m, (digest ??= contentDigest(raw)));
  if (!isTable(raw)) {
    problem(`${where} is not a table`);
    return undefined;
  }
  const rawName = get(raw, "name");
  const name = typeof rawName === "string" ? projectName(rawName) : undefined;
  if (name === undefined) {
    problem(`${where} has no valid name`);
    return undefined;
  }
  const rawVersion = get(raw, "version");
  const label = `${where} (${name}${typeof rawVersion === "string" ? ` ${rawVersion}` : ""})`;
  const extra = unknownKeys(raw, PACKAGE_KEYS);
  if (extra.length > 0) problem(`${label}: unknown key(s) ${keysList(extra)}: format not supported`);

  const kinds = ["vcs", "directory", "archive"].filter((k) => get(raw, k) !== undefined);
  const hasFiles = get(raw, "sdist") !== undefined || get(raw, "wheels") !== undefined;
  if (kinds.length + (hasFiles ? 1 : 0) > 1) {
    problem(`${label}: more than one source (${[...kinds, ...(hasFiles ? ["sdist/wheels"] : [])].join(", ")}), which the specification forbids`);
    return undefined;
  }
  const index_ = get(raw, "index");
  if (index_ !== undefined && typeof index_ !== "string") problem(`${label}: index is not a string`);

  let source: PylockSource;
  const pkg = { index, name, wheels: [] as LockedFile[] } as PylockPackage;
  if (kinds[0] === "vcs" || kinds[0] === "directory") {
    const t = get(raw, kinds[0]);
    const s = isTable(t) ? readTreeSource(kinds[0], t, label, problem) : undefined;
    if (!isTable(t)) problem(`${label}: ${kinds[0]} is not a table`);
    if (!s) return undefined;
    source = s;
  } else if (kinds[0] === "archive") {
    const f = readFile(get(raw, "archive"), "archive", ARCHIVE_KEYS, `${label} archive`, report);
    if (f) pkg.archive = f;
    const a = get(raw, "archive");
    const sub = isTable(a) ? get(a, "subdirectory") : undefined;
    source = { kind: "archive" };
    if (typeof sub === "string") source.subdirectory = sub;
  } else {
    source = { kind: "files" };
    const sdist = get(raw, "sdist");
    if (sdist !== undefined) {
      const f = readFile(sdist, "sdist", FILE_KEYS, `${label} sdist`, report);
      if (f) pkg.sdist = f;
    }
    const wheels = get(raw, "wheels");
    if (wheels !== undefined && !Array.isArray(wheels)) problem(`${label}: wheels is not an array of tables`);
    else if (Array.isArray(wheels))
      wheels.forEach((w, i) => {
        const f = readFile(w, "wheel", FILE_KEYS, `${label} wheel #${i + 1}`, report);
        if (f) pkg.wheels.push(f);
      });
    const count = (sdist !== undefined ? 1 : 0) + (Array.isArray(wheels) ? wheels.length : 0);
    if (count === 0) problem(`${label}: no sdist, wheels, archive, directory or vcs entry, so nothing can be bound to an index file`);
  }
  if (typeof index_ === "string" && (source.kind === "files" || source.kind === "archive")) source.index = index_;
  pkg.source = source;

  const tree = source.kind === "vcs" || source.kind === "directory";
  if (rawVersion !== undefined) {
    const version = typeof rawVersion === "string" ? canonicalVersion(rawVersion) : undefined;
    if (version === undefined) problem(`${label}: version ${show(rawVersion)} is not a PEP 440 version`);
    else pkg.version = version;
  } else if (!tree) {
    problem(`${label}: no version, so it cannot be bound or checked against OSV`);
  }
  const marker = get(raw, "marker");
  if (typeof marker === "string") pkg.marker = marker;
  return pkg;
}

function readTreeSource(kind: "vcs" | "directory", t: TomlTable, label: string, problem: (m: string) => void): PylockSource | undefined {
  const extra = unknownKeys(t, kind === "vcs" ? VCS_KEYS : DIRECTORY_KEYS);
  if (extra.length > 0) {
    problem(`${label}: ${kind} has unknown key(s) ${keysList(extra)}: format not supported`);
    return undefined;
  }
  const str = (k: string): string | undefined => {
    const v = get(t, k);
    return typeof v === "string" && v !== "" ? v : undefined;
  };
  const subdirectory = str("subdirectory");
  if (kind === "directory") {
    const path = str("path");
    const editable = get(t, "editable") ?? false;
    if (path === undefined || typeof editable !== "boolean") {
      problem(`${label}: directory needs a path and, if given, a boolean editable`);
      return undefined;
    }
    return subdirectory === undefined ? { kind, path, editable } : { kind, path, editable, subdirectory };
  }
  const type = str("type");
  if (type === undefined) {
    problem(`${label}: vcs has no type`);
    return undefined;
  }
  const s: PylockSource = { kind: "vcs", type };
  const url = str("url");
  const path = str("path");
  const commitId = str("commit-id");
  if (url !== undefined) s.url = url;
  if (path !== undefined) s.path = path;
  if (commitId !== undefined) s.commitId = commitId;
  if (subdirectory !== undefined) s.subdirectory = subdirectory;
  return s;
}

function readFile(raw: unknown, kind: LockedFile["kind"], keys: string[], where: string, report: Problem): LockedFile | undefined {
  // A problem with a file entry covers that entry: its url or path, name, hashes and every other key.
  let digest: string | undefined;
  const problem = (m: string): void => report(m, (digest ??= contentDigest(raw)));
  if (!isTable(raw)) {
    problem(`${where} is not a table`);
    return undefined;
  }
  const extra = unknownKeys(raw, keys);
  if (extra.length > 0) {
    problem(`${where}: unknown key(s) ${keysList(extra)}: format not supported`);
    return undefined;
  }
  const f: LockedFile = { kind, hashes: {} as FileHashes };
  for (const key of ["name", "url", "path"] as const) {
    const v = get(raw, key);
    if (v === undefined) continue;
    if (typeof v !== "string" || v === "") {
      problem(`${where}: ${key} is not a non-empty string`);
      return undefined;
    }
    if (key === "name") f.filename = v;
    else f[key] = v;
  }
  if (f.url === undefined && f.path === undefined) {
    problem(`${where}: neither url nor path`);
    return undefined;
  }
  if (f.url !== undefined && f.path !== undefined) {
    problem(`${where}: both url and path (pip and uv install from the path): format not supported`);
    return undefined;
  }
  // The specification: a `name` takes precedence over the file name in the path or URL.
  if (f.filename === undefined) {
    const base = basenameOf(f.path ?? f.url!);
    if (base !== undefined) f.filename = base;
  }
  const size = get(raw, "size");
  if (size !== undefined) {
    if (!isSafeCount(size)) {
      problem(`${where}: size is not a non-negative integer`);
      return undefined;
    }
    f.size = size;
  }
  const uploaded = offsetDateTime(get(raw, "upload-time"));
  if (uploaded !== undefined) f.uploadTime = uploaded;
  const hashes = get(raw, "hashes");
  if (!isTable(hashes) || Object.keys(hashes).length === 0) {
    problem(`${where}${f.filename ? ` (${f.filename})` : ""}: no hashes table, so it cannot be bound to an index file`);
    return undefined;
  }
  for (const [algorithm, digest] of Object.entries(hashes)) {
    if (algorithm !== algorithm.toLowerCase() && HEX_ALGORITHMS.has(algorithm.toLowerCase())) {
      problem(`${where}: hash algorithm ${JSON.stringify(algorithm)} is not lowercase`);
      return undefined;
    }
    if (typeof digest !== "string" || (HEX_ALGORITHMS.has(algorithm) && !isHexDigest(algorithm, digest))) {
      problem(`${where}: hashes.${algorithm} is not a lowercase hex digest of that algorithm`);
      return undefined;
    }
    f.hashes[algorithm] = digest;
  }
  const unbound = bindSha256(f, where);
  if (unbound !== undefined) {
    problem(unbound);
    return undefined;
  }
  return f;
}

/** Algorithms whose digest shape is checked; the specification only says keys SHOULD be lowercase. */
const HEX_ALGORITHMS: ReadonlySet<string> = new Set(["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b"]);
