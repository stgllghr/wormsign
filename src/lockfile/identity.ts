import type { LockedPackage } from "./types.js";

/**
 * A version spelled as the registry publishes it: npm publish stores semver.clean(version), so numbers have no
 * leading zeros and build metadata is dropped. npm reads `07.0.0` or `7.0.0+x` as 7.0.0, which an exact-match IOC
 * lookup would miss, so anything but this spelling is not a registry identity.
 */
export const SEMVER = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?$/;

/** A version a package's own manifest gives (git, URL and file: sources): one token that starts with no YAML syntax. */
const TOKEN = /^[^\s'"&*!|>%@`{}[\],#?]\S*$/;

/** npm package names: an optional scope, then URL-safe characters (legacy names may be upper case). */
const NAME = /^(?:@[a-z0-9~][\w.~-]*\/)?[a-z0-9~][\w.~-]*$/i;

/**
 * pnpm and Yarn 2+ read their lockfiles with real YAML parsers, which drop node
 * properties (`&anchor`, `!!str`) that a line-based reader keeps as text: pnpm
 * installs is-number from `&a is-number@7.0.0:`, which would read as the name
 * `&a is-number`. Rather than list every syntax trick, accept only identities
 * that look like a real package and throw on the rest. A package fetched from
 * the registry by name and version (no `resolved`) needs its version in the
 * registry's spelling (SEMVER): npm 10 also installs is-number 7.0.0 from
 * `"version": "v7.0.0"`. Any other source is identified by `resolved`, and its
 * version is whatever its manifest says (pnpm 11.16 and yarn 4.18 lock a file:
 * tarball at "1.0"); a registry tarball's own identity is IOC-checked from its
 * URL (checks/lockfile.ts).
 */
export function checkIdentity(p: LockedPackage, where: string): LockedPackage {
  if (!NAME.test(p.name)) throw new Error(`${where}: ${JSON.stringify(p.name)} is not a package name`);
  if (p.local || p.runtime) return p;
  if (!(p.resolved === undefined ? SEMVER : TOKEN).test(p.version)) throw new Error(`${where}: ${p.name} has no ${p.resolved === undefined ? "semver " : ""}version (${JSON.stringify(p.version)})`);
  return p;
}
