/**
 * PEP 440 versions: parsing, the canonical (normalised) form, and comparison. No specifier evaluation anywhere.
 *
 * Follows packaging 26.2 (vendored in pip 26.2.1: pip/_vendor/packaging/version.py), the reference implementation:
 * - the grammar is its VERSION_PATTERN (case-insensitive; optional leading "v"; "alpha"/"beta"/"c"/"pre"/"preview"
 *   and "rev"/"r" spellings; "-", "_" and "." separators; implicit post releases such as "1.0-1"), except that
 *   surrounding whitespace is not accepted here: callers pass a token, never a padded string;
 * - the canonical form is what `str(Version(v))` prints: no "v", no epoch when it is 0, "a"/"b"/"rc", ".postN",
 *   ".devN", a lowercase local label whose all-digit segments lose their leading zeros, and the release segments as
 *   written (trailing zeros are kept: "1.0.0" stays "1.0.0");
 * - comparison is its `_cmpkey` ordering: trailing zeros of the release do not count ("1.0" == "1.0.0"), a dev-only
 *   release sorts before alpha, beta and rc, a release sorts after its pre-releases and before its post-releases, and
 *   a local label sorts after the same version without one (strings before numbers within it).
 *
 * Numbers are kept as digit strings, so a segment too long for a JS number still compares exactly.
 */

const PATTERN =
  /^v?(?:(?:([0-9]+)!)?([0-9]+(?:\.[0-9]+)*)(?:[._-]?(alpha|a|beta|b|preview|pre|c|rc)[._-]?([0-9]+)?)?(?:-([0-9]+)|[._-]?(post|rev|r)[._-]?([0-9]+)?)?(?:[._-]?(dev)[._-]?([0-9]+)?)?)(?:\+([a-z0-9]+(?:[._-][a-z0-9]+)*))?$/i;

const LETTERS: Record<string, string> = { alpha: "a", beta: "b", c: "rc", pre: "rc", preview: "rc", rev: "post", r: "post" };

/** Versions longer than this are not parsed (src/osv.ts caps what it sends at 256). */
export const MAX_VERSION_LENGTH = 1024;

/** A parsed version. Numbers are digit strings without leading zeros ("0" for zero). */
export interface Version {
  epoch: string;
  release: string[];
  pre?: { letter: "a" | "b" | "rc"; n: string };
  post?: string;
  dev?: string;
  /** Local label segments: numbers as digit strings without leading zeros, words in lowercase. */
  local?: { num: boolean; value: string }[];
}

const num = (digits: string | undefined): string => (digits ?? "0").replace(/^0+(?=.)/, "");

/** Parses a PEP 440 version, or returns undefined when it is not one. */
export function parseVersion(text: string): Version | undefined {
  if (text.length === 0 || text.length > MAX_VERSION_LENGTH) return undefined;
  const m = PATTERN.exec(text);
  if (!m) return undefined;
  const [, epoch, release, preL, preN, postN1, postL, postN2, devL, devN, local] = m;
  const v: Version = { epoch: num(epoch), release: release!.split(".").map(num) };
  if (preL !== undefined) {
    const letter = (LETTERS[preL.toLowerCase()] ?? preL.toLowerCase()) as "a" | "b" | "rc";
    v.pre = { letter, n: num(preN) };
  }
  if (postN1 !== undefined) v.post = num(postN1);
  else if (postL !== undefined) v.post = num(postN2);
  if (devL !== undefined) v.dev = num(devN);
  if (local !== undefined) {
    v.local = local.split(/[._-]/).map((s) => (/^[0-9]+$/.test(s) ? { num: true, value: num(s) } : { num: false, value: s.toLowerCase() }));
  }
  return v;
}

/** The canonical string of a parsed version (packaging's `str(Version(...))`). */
export function formatVersion(v: Version): string {
  let s = v.release.join(".");
  if (v.epoch !== "0") s = `${v.epoch}!${s}`;
  if (v.pre) s += `${v.pre.letter}${v.pre.n}`;
  if (v.post !== undefined) s += `.post${v.post}`;
  if (v.dev !== undefined) s += `.dev${v.dev}`;
  if (v.local) s += `+${v.local.map((p) => p.value).join(".")}`;
  return s;
}

/** The canonical form of a version string, or undefined when it is not a PEP 440 version. */
export function canonicalVersion(text: string): string | undefined {
  const v = parseVersion(text);
  return v === undefined ? undefined : formatVersion(v);
}

/**
 * A version already in canonical form, at most 256 characters: exactly what src/osv.ts sends to OSV for PyPI
 * (OSV_VALID.PyPI.version, PEP 440 Appendix B's is_canonical regex plus a normalised local label).
 * test/python-readers.test.ts checks that the two accept the same set.
 */
export function isCanonicalVersion(text: string): boolean {
  return text.length <= 256 && canonicalVersion(text) === text;
}

/** Compares two digit strings without leading zeros numerically. */
function cmpNum(a: string, b: string): number {
  if (a.length !== b.length) return a.length < b.length ? -1 : 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

const PRE_RANK = { a: 0, b: 1, rc: 2 } as const;

/** packaging's comparison key, as a list of comparable parts. */
function suffix(v: Version): [number, string, number, string, number, string] {
  let preRank: number;
  let preN = "0";
  if (!v.pre && v.post === undefined && v.dev !== undefined) preRank = -1;
  else if (!v.pre) preRank = 3;
  else {
    preRank = PRE_RANK[v.pre.letter];
    preN = v.pre.n;
  }
  return [preRank, preN, v.post === undefined ? 0 : 1, v.post ?? "0", v.dev === undefined ? 1 : 0, v.dev ?? "0"];
}

/** Orders two parsed versions as PEP 440 (and packaging) do: negative, zero or positive. */
export function compareVersions(a: Version, b: Version): number {
  let c = cmpNum(a.epoch, b.epoch);
  if (c !== 0) return c;
  const trim = (r: string[]): string[] => {
    let i = r.length;
    while (i > 0 && r[i - 1] === "0") i--;
    return r.slice(0, i);
  };
  const ra = trim(a.release);
  const rb = trim(b.release);
  for (let i = 0; i < Math.min(ra.length, rb.length); i++) {
    c = cmpNum(ra[i]!, rb[i]!);
    if (c !== 0) return c;
  }
  if (ra.length !== rb.length) return ra.length < rb.length ? -1 : 1;
  const sa = suffix(a);
  const sb = suffix(b);
  for (let i = 0; i < 6; i++) {
    const x = sa[i]!;
    const y = sb[i]!;
    c = typeof x === "number" ? x - (y as number) : cmpNum(x, y as string);
    if (c !== 0) return Math.sign(c);
  }
  // No local label sorts before any local label; within one, words sort before numbers, words compare as strings,
  // numbers numerically, and a shorter label first when one is a prefix of the other.
  if (!a.local || !b.local) return a.local ? 1 : b.local ? -1 : 0;
  for (let i = 0; i < Math.min(a.local.length, b.local.length); i++) {
    const x = a.local[i]!;
    const y = b.local[i]!;
    if (x.num !== y.num) return x.num ? 1 : -1;
    c = x.num ? cmpNum(x.value, y.value) : x.value < y.value ? -1 : x.value > y.value ? 1 : 0;
    if (c !== 0) return c;
  }
  return a.local.length === b.local.length ? 0 : a.local.length < b.local.length ? -1 : 1;
}

/** PEP 440 equality of two version strings ("1.0" equals "1.0.0" and "1.0.post0" equals "1.0-0"); false if either is invalid. */
export function versionsEqual(a: string, b: string): boolean {
  const va = parseVersion(a);
  const vb = parseVersion(b);
  return va !== undefined && vb !== undefined && compareVersions(va, vb) === 0;
}
