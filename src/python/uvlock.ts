/**
 * uv.lock reader, also used for PEP 723 script locks (`<script>.lock`, the same format).
 *
 * Returns one typed entry per [[package]] table, in file order: a forking resolution locks one name at several
 * versions (or from several sources), and every entry is kept. Never throws; every reason the file cannot be read in
 * full is in `problems`, and a caller must treat a lock with problems as unverified, whatever `packages` holds.
 *
 * The format is uv's (crates/uv-lock/src/lock/mod.rs at uv 0.12.21 and 0.12.23: LockWire, PackageWire, SourceWire,
 * SourceDist, WheelWire). uv ignores keys it does not know; this reader does not: an unknown key at the top level, in
 * a package, in its source or in a file entry is a problem, so a field that changes what is installed cannot pass
 * unread. Version 1 only; `revision` must be one this reader knows (REVISIONS).
 *
 * Binding: every sdist and wheel must carry a sha256 hash ("cannot be bound to an index file" otherwise), and a
 * package whose source should have files (registry, registry path, URL, path archive) must list at least one. A file
 * entry names at most one of url, path and filename: uv uses the first of them in that order (WheelWire's TryFrom,
 * SourceDist's deserializer) and ignores the rest, so with two the name read here could be another file's.
 * Comparing a registry URL with the index and checking local paths are the caller's (src/python/paths.ts).
 *
 * Each problem has a digest of the content it is about in `covers` (the same index): the canonical form of the
 * [[package]] table or file entry (toml.ts contentDigest) for a problem with one, else the file's bytes (or, for a
 * document parsed elsewhere, the whole document's canonical form). A baseline entry for a problem then approves that
 * content only: another url, hash or package in its place is a new finding.
 */
import { basenameOf, bindSha256, isHexDigest, type FileHashes, type LockedFile } from "./filenames.js";
import { projectName } from "./names.js";
import { canonicalVersion } from "./pep440.js";
import { contentDigest, get, isSafeCount, isTable, readToml, show, unknownKeys, type TomlRead, type TomlTable } from "./toml.js";

/**
 * Lockfile revisions this reader knows. uv 0.12.23's source lists them (crates/uv-lock/src/lock/mod.rs, "Version 1
 * revisions"): 0 the original format (a missing `revision` reads as 0), 1 provides-extras, 2 upload times, 3
 * package-specific exclude-newer, 4 locks that omit package metadata, 5 default groups. uv 0.10.9 and 0.12.21 wrote
 * revision 3 for every fixture in test/fixtures/python/locks (scripts/gen-py-fixtures.sh); uv 0.12.23 wrote 5 in the
 * PyPI research run of 2026-10-08. A later revision is a problem until it has been looked at.
 */
export const REVISIONS: readonly number[] = [0, 1, 2, 3, 4, 5];

export type UvSource =
  | { kind: "registry"; url: string }
  | { kind: "registry-path"; path: string }
  | { kind: "git"; url: string }
  | { kind: "url"; url: string; subdirectory?: string }
  | { kind: "path"; path: string }
  | { kind: "directory" | "editable" | "virtual"; path: string };

export interface UvPackage {
  /** Position among the [[package]] tables, from 0. */
  index: number;
  /** PEP 503-normalised. */
  name: string;
  /** Canonical PEP 440 version; absent only for a local source tree (directory, editable, virtual). */
  version?: string;
  source: UvSource;
  sdist?: LockedFile;
  wheels: LockedFile[];
  resolutionMarkers: string[];
}

export interface UvLock {
  version?: number;
  revision?: number;
  requiresPython?: string;
  packages: UvPackage[];
  /** [manifest].members: the workspace members, normalised. */
  members: string[];
  /** [options] as written (exclude-newer, exclude-newer-span, ...), for callers that report them. */
  options: TomlTable;
  problems: string[];
  /** For each problem, the sha256 of the content it is about (see the module comment); "" when nothing was read. */
  covers: string[];
}

const TOP_KEYS = ["version", "revision", "requires-python", "resolution-markers", "supported-markers", "required-markers", "conflicts", "options", "manifest", "package"];
const PACKAGE_KEYS = ["name", "version", "source", "metadata", "sdist", "wheels", "resolution-markers", "dependencies", "optional-dependencies", "dev-dependencies", "dependency-groups", "default-groups", "group-requires-python"];
const SDIST_KEYS = ["url", "path", "hash", "size", "upload-time", "upload_time"];
const WHEEL_KEYS = ["url", "path", "filename", "hash", "size", "upload-time", "upload_time"];
const LOCAL = new Set(["directory", "editable", "virtual"]);
const SOURCE_KINDS = ["registry", "git", "url", "path", "directory", "editable", "virtual"] as const;

/** Reads a uv.lock (or script lock) file. */
export function readUvLock(path: string): UvLock {
  return uvLockOf(readToml(path));
}

/** A uv.lock (or script lock) from readToml's or tomlOfBytes' reading of it. */
export function uvLockOf(read: TomlRead): UvLock {
  if ("problem" in read) return { ...empty(), problems: [read.problem], covers: [read.sha256 ?? ""] };
  return parseUvLock(read.doc, read.sha256);
}

const empty = (): UvLock => ({ packages: [], members: [], options: Object.create(null) as TomlTable, problems: [], covers: [] });

/** A problem and the digest of the content it is about. */
type Problem = (m: string, covers: string) => void;

/**
 * Interprets a parsed uv.lock document. `fileSha256` is the digest of the file's bytes, which a problem with the whole
 * document covers; without it, the document's canonical form.
 */
export function parseUvLock(doc: TomlTable, fileSha256?: string): UvLock {
  const out = empty();
  const problem: Problem = (m, covers) => {
    out.problems.push(m);
    out.covers.push(covers);
  };
  let whole: string | undefined;
  const top = (m: string): void => problem(m, (whole ??= fileSha256 ?? contentDigest(doc)));
  const extra = unknownKeys(doc, TOP_KEYS);
  if (extra.length > 0) top(`unknown top-level key(s) ${extra.map((k) => JSON.stringify(k)).join(", ")}: format not supported`);

  const version = get(doc, "version");
  if (version !== 1) {
    top(`lockfile version ${show(version ?? null)} is not 1: format not supported`);
    return out;
  }
  out.version = 1;
  const revision = get(doc, "revision") ?? 0;
  if (typeof revision !== "number" || !REVISIONS.includes(revision)) {
    top(`lockfile revision ${show(revision)} is not one this reader knows (${REVISIONS.join(", ")}): format not supported`);
    return out;
  }
  out.revision = revision;
  const rp = get(doc, "requires-python");
  if (typeof rp === "string") out.requiresPython = rp;

  const options = get(doc, "options");
  if (options !== undefined) {
    if (isTable(options)) out.options = options;
    else top("[options] is not a table");
  }
  const manifest = get(doc, "manifest");
  if (manifest !== undefined) {
    const members = isTable(manifest) ? get(manifest, "members") : undefined;
    if (!isTable(manifest)) top("[manifest] is not a table");
    else if (members !== undefined) {
      if (!Array.isArray(members) || !members.every((m) => typeof m === "string" && projectName(m) !== undefined)) top("[manifest].members is not a list of project names");
      else out.members = members.map((m) => projectName(m as string)!);
    }
  }

  const packages = get(doc, "package") ?? [];
  if (!Array.isArray(packages)) {
    top("package is not an array of tables");
    return out;
  }
  packages.forEach((raw, index) => {
    const pkg = readPackage(raw, index, problem);
    if (pkg) out.packages.push(pkg);
  });
  return out;
}

function readPackage(raw: unknown, index: number, report: Problem): UvPackage | undefined {
  const where = `[[package]] #${index + 1}`;
  // A problem with the package (its name, version, source or file list) covers the whole [[package]] table.
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
  const version = typeof rawVersion === "string" ? canonicalVersion(rawVersion) : undefined;
  const label = `${where} (${name}${typeof rawVersion === "string" ? ` ${rawVersion}` : ""})`;
  const extra = unknownKeys(raw, PACKAGE_KEYS);
  if (extra.length > 0) problem(`${label}: unknown key(s) ${extra.map((k) => JSON.stringify(k)).join(", ")}: format not supported`);
  if (rawVersion !== undefined && version === undefined) problem(`${label}: version ${show(rawVersion)} is not a PEP 440 version`);

  const source = readSource(get(raw, "source"), label, problem);
  if (!source) return undefined;
  const local = LOCAL.has(source.kind);
  if (!local && version === undefined && rawVersion === undefined) problem(`${label}: no version, so it cannot be bound or checked against OSV`);

  const pkg: UvPackage = { index, name, source, wheels: [], resolutionMarkers: [] };
  if (version !== undefined) pkg.version = version;
  const markers = get(raw, "resolution-markers");
  if (Array.isArray(markers) && markers.every((m) => typeof m === "string")) pkg.resolutionMarkers = markers as string[];

  const sdist = get(raw, "sdist");
  if (sdist !== undefined) {
    const f = readFile(sdist, "sdist", SDIST_KEYS, `${label} sdist`, report);
    if (f) pkg.sdist = f;
  }
  const wheels = get(raw, "wheels");
  if (wheels !== undefined) {
    if (!Array.isArray(wheels)) problem(`${label}: wheels is not an array`);
    else
      wheels.forEach((w, i) => {
        const f = readFile(w, "wheel", WHEEL_KEYS, `${label} wheel #${i + 1}`, report);
        if (f) pkg.wheels.push(f);
      });
  }
  const files = (sdist !== undefined ? 1 : 0) + (Array.isArray(wheels) ? wheels.length : 0);
  if (local && files > 0) problem(`${label}: a ${source.kind} source with sdist or wheels entries: format not supported`);
  if (!local && source.kind !== "git" && files === 0) problem(`${label}: no sdist or wheels entries, so nothing can be bound to an index file`);
  return pkg;
}

function readSource(raw: unknown, label: string, problem: (m: string) => void): UvSource | undefined {
  if (!isTable(raw)) {
    problem(`${label}: no source table`);
    return undefined;
  }
  const keys = Object.keys(raw);
  const kinds = keys.filter((k) => (SOURCE_KINDS as readonly string[]).includes(k));
  const allowed = kinds.length === 1 && kinds[0] === "url" ? ["url", "subdirectory"] : kinds;
  const extra = keys.filter((k) => !allowed.includes(k));
  if (kinds.length !== 1 || extra.length > 0) {
    problem(`${label}: unknown source ${show(Object.fromEntries(keys.map((k) => [k, get(raw, k)])))}: format not supported`);
    return undefined;
  }
  const kind = kinds[0] as (typeof SOURCE_KINDS)[number];
  const value = get(raw, kind);
  if (typeof value !== "string" || value === "") {
    problem(`${label}: source ${kind} is not a non-empty string`);
    return undefined;
  }
  switch (kind) {
    case "registry":
      // uv reads a registry value with a URL scheme as a URL and anything else as a path to a local index.
      return /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? { kind: "registry", url: value } : { kind: "registry-path", path: value };
    case "git":
      return { kind: "git", url: value };
    case "url": {
      const sub = get(raw, "subdirectory");
      if (sub !== undefined && typeof sub !== "string") {
        problem(`${label}: source subdirectory is not a string`);
        return undefined;
      }
      return sub === undefined ? { kind: "url", url: value } : { kind: "url", url: value, subdirectory: sub };
    }
    case "path":
      return { kind: "path", path: value };
    default:
      return { kind, path: value };
  }
}

function readFile(raw: unknown, kind: "sdist" | "wheel", keys: string[], where: string, report: Problem): LockedFile | undefined {
  // A problem with a file entry covers that entry: its url, path or name, hash and every other key.
  let digest: string | undefined;
  const problem = (m: string): void => report(m, (digest ??= contentDigest(raw)));
  if (!isTable(raw)) {
    problem(`${where} is not a table`);
    return undefined;
  }
  const extra = unknownKeys(raw, keys);
  if (extra.length > 0) {
    problem(`${where}: unknown key(s) ${extra.map((k) => JSON.stringify(k)).join(", ")}: format not supported`);
    return undefined;
  }
  const locators = ["url", "path", "filename"].filter((k) => get(raw, k) !== undefined);
  if (locators.length > 1) {
    problem(`${where}: ${locators.join(" and ")} together (uv uses only the first of url, path and filename): format not supported`);
    return undefined;
  }
  const f: LockedFile = { kind, hashes: {} as FileHashes };
  for (const key of ["url", "path", "filename"] as const) {
    const v = get(raw, key);
    if (v === undefined) continue;
    if (typeof v !== "string" || v === "") {
      problem(`${where}: ${key} is not a non-empty string`);
      return undefined;
    }
    if (key === "filename") f.filename = v;
    else f[key] = v;
  }
  if (f.filename === undefined) {
    const base = basenameOf(f.path ?? f.url ?? "");
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
  const uploaded = get(raw, "upload-time") ?? get(raw, "upload_time");
  if (typeof uploaded === "string") f.uploadTime = uploaded;
  const hash = get(raw, "hash");
  const m = typeof hash === "string" ? /^([a-z0-9]+):([0-9a-f]+)$/.exec(hash) : null;
  if (hash !== undefined && (!m || !isHexDigest(m[1]!, m[2]!))) {
    problem(`${where}: hash ${show(hash)} is not an algorithm:lowercase-hex digest`);
    return undefined;
  }
  if (m) f.hashes[m[1]!] = m[2]!;
  const unbound = bindSha256(f, where);
  if (unbound !== undefined) {
    problem(unbound);
    return undefined;
  }
  return f;
}
