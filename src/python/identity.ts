/**
 * The identity of a locked Python package: what an install of that entry fetches, not only its label.
 *
 * identity = "pypi:" + sha256 of a canonical JSON array of: the name; the version (null when the lock gives none); the
 * source kind, value and subdirectory; and, for each file, its url, path and file name as the lock wrote them with
 * every hash and its algorithm (sorted within the file), the files sorted. Two entries that differ in any of these are
 * different packages: a git URL swapped at the same version, a registry swapped for another index, a file added,
 * removed or rehashed. soak's finding keys carry the digest, so a baseline entry approves one exact artifact set and
 * any change to it fails again. PR mode (`--base`) compares identities with the base's to tell a WS-SK-005 build the
 * change adds (src/python/base-builds.ts); which entries it leaves unchecked it decides by
 * src/python/base-entries.ts entryIdentity, which adds where the entry is.
 */
import { createHash } from "node:crypto";
import type { PyPackage } from "./model.js";

/** Bumped if the canonical form ever changes, so old and new identities never collide. */
const FORM = "wormsign-pypi-identity-1";

/** The canonical JSON identity() digests. Arrays only, so no key order is involved. */
export function canonicalIdentity(p: PyPackage): string {
  const files = p.files
    .map((f) => [f.locator.url ?? null, f.locator.path ?? null, f.locator.filename ?? null, f.hashes.map((h) => `${h.alg}:${h.digest}`).sort()])
    .map((f) => JSON.stringify(f))
    .sort()
    .map((f) => JSON.parse(f) as unknown);
  return JSON.stringify([FORM, p.name, p.version ?? null, [p.source.kind, p.source.value, p.source.subdirectory ?? null], files]);
}

/** The sha256 (lowercase hex) of the package's canonical identity. */
export function identityDigest(p: PyPackage): string {
  return createHash("sha256").update(canonicalIdentity(p)).digest("hex");
}

/** "pypi:" + identityDigest: the value baseline keys carry, and PR mode compares to tell a build the change adds. */
export function pythonIdentity(p: PyPackage): string {
  return `pypi:${identityDigest(p)}`;
}
