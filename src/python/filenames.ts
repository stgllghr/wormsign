/**
 * Distribution files: what a file name says about its project and version, and the hashes a lockfile records for it.
 *
 * File names (packaging 26.2's parse_wheel_filename and parse_sdist_filename, vendored in pip 26.2.1, are the
 * reference):
 * - wheel, the binary distribution format (PEP 427): `{name}-{version}(-{build})?-{python}-{abi}-{platform}.whl`,
 *   five or six dash-separated parts. The name part may hold only letters, digits, "_" and "." with no "__"; a build
 *   tag starts with a digit.
 * - sdist (PEP 625): `{name}-{version}.tar.gz`, and the legacy `{name}-{version}.tar.gz` / `.zip` forms whose name may
 *   itself contain "-". Every split point at which the left part is a valid project name and the right part a PEP 440
 *   version is a candidate; when an expected project name is given, only candidates whose normalised name equals it
 *   count. Exactly one distinct (name, version) is an answer; none, or more than one, is undefined (ambiguous).
 * Any other extension (.egg, .exe, .tar.bz2, ...) is undefined: wormsign does not bind such files.
 */
import { isValidName, normalizeName } from "./names.js";
import { canonicalVersion } from "./pep440.js";

export interface FileNameInfo {
  kind: "wheel" | "sdist";
  /** PEP 503-normalised project name. */
  name: string;
  /** Canonical PEP 440 version. */
  version: string;
}

const WHEEL_NAME_PART = /^[A-Za-z0-9_.]+$/;
const BUILD_TAG = /^[0-9]/;

/** The project and version a wheel file name states, or undefined when it is not a valid wheel file name. */
export function parseWheelFilename(filename: string, expectedName?: string): FileNameInfo | undefined {
  if (!filename.endsWith(".whl") || filename.includes("/") || filename.includes("\\")) return undefined;
  const parts = filename.slice(0, -".whl".length).split("-");
  if (parts.length !== 5 && parts.length !== 6) return undefined;
  const [namePart, versionPart] = parts as [string, string];
  if (!WHEEL_NAME_PART.test(namePart) || namePart.includes("__") || !isValidName(namePart)) return undefined;
  if (parts.length === 6 && !BUILD_TAG.test(parts[2]!)) return undefined;
  if (parts.slice(-3).some((t) => t === "")) return undefined;
  const version = canonicalVersion(versionPart);
  if (version === undefined) return undefined;
  const name = normalizeName(namePart);
  if (expectedName !== undefined && name !== expectedName) return undefined;
  return { kind: "wheel", name, version };
}

const SDIST_EXTENSIONS = [".tar.gz", ".zip"];

/** The project and version an sdist file name states, or undefined when it is not one or is ambiguous. */
export function parseSdistFilename(filename: string, expectedName?: string): FileNameInfo | undefined {
  if (filename.includes("/") || filename.includes("\\")) return undefined;
  const ext = SDIST_EXTENSIONS.find((e) => filename.endsWith(e));
  if (ext === undefined) return undefined;
  const stem = filename.slice(0, -ext.length);
  const found = new Map<string, FileNameInfo>();
  for (let i = stem.indexOf("-"); i !== -1; i = stem.indexOf("-", i + 1)) {
    const namePart = stem.slice(0, i);
    const version = canonicalVersion(stem.slice(i + 1));
    if (!isValidName(namePart) || version === undefined) continue;
    const name = normalizeName(namePart);
    if (expectedName !== undefined && name !== expectedName) continue;
    found.set(`${name}\0${version}`, { kind: "sdist", name, version });
  }
  return found.size === 1 ? [...found.values()][0] : undefined;
}

/** A wheel or sdist file name's project and version; undefined for anything else or anything ambiguous. */
export function parseDistFilename(filename: string, expectedName?: string): FileNameInfo | undefined {
  return filename.endsWith(".whl") ? parseWheelFilename(filename, expectedName) : parseSdistFilename(filename, expectedName);
}

/** The last path component of a URL's path (percent-decoded) or of a relative path, or undefined. */
export function basenameOf(urlOrPath: string): string | undefined {
  let path = urlOrPath;
  if (/^[a-z][a-z0-9+.-]*:/i.test(urlOrPath)) {
    try {
      path = decodeURIComponent(new URL(urlOrPath).pathname);
    } catch {
      return undefined;
    }
  }
  const base = path.slice(path.lastIndexOf("/") + 1);
  return base === "" ? undefined : base;
}

/* ---- hashes ---- */

/** Lowercase hex digests by algorithm, as a lockfile records them for one file. */
export type FileHashes = Record<string, string>;

/** Hex digest lengths of the algorithms a lockfile may name. Others are kept but never used for binding. */
const HEX_LENGTH: Record<string, number> = { md5: 32, sha1: 40, sha224: 56, sha256: 64, sha384: 96, sha512: 128, blake2b: 128 };

/** A digest in the form wormsign binds: lowercase hex of the algorithm's length. */
export function isHexDigest(algorithm: string, digest: string): boolean {
  const len = HEX_LENGTH[algorithm];
  return len !== undefined && digest.length === len && /^[0-9a-f]+$/.test(digest);
}

/**
 * One locked distribution file (an sdist, a wheel or a direct archive), as any of the readers records it. Readers
 * report a problem for a file without a usable sha256, so `sha256` is set on every file a reader returns without one.
 */
export interface LockedFile {
  kind: "sdist" | "wheel" | "archive";
  /** The file name: the lock's own name field, else the last component of its path or URL. */
  filename?: string;
  url?: string;
  /** A relative path, as written in the lock. */
  path?: string;
  size?: number;
  /** As the lock states it (never trusted: the index's upload time is the one wormsign uses). */
  uploadTime?: string;
  hashes: FileHashes;
  sha256?: string;
}

/**
 * The binding rule every lockfile reader applies to every file entry: wormsign identifies a locked file on the index
 * by its sha256 alone, so a file with no sha256 (none, or only other algorithms) cannot be bound and is a problem.
 * Returns the problem, or undefined when the file has a sha256 (then copied to `sha256`).
 */
export function bindSha256(f: LockedFile, where: string): string | undefined {
  const digest = f.hashes["sha256"];
  if (digest === undefined) return `${where}${f.filename ? ` (${f.filename})` : ""}: no sha256 hash, so it cannot be bound to an index file`;
  f.sha256 = digest;
  return undefined;
}
