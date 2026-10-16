import type { LockedPackage, ParsedLockfile } from "./types.js";
import { parseNpmLock } from "./npm.js";
import { parsePnpmLock } from "./pnpm.js";
import { isYarnBerry, parseYarnBerry, parseYarnClassic } from "./yarn.js";

export type { LockedPackage, ParsedLockfile } from "./types.js";

export const LOCKFILE_NAMES = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"] as const;

/**
 * Parses a lockfile by its file name. A file the parser cannot fully read
 * throws; callers must report that rather than treat it as "no packages".
 */
export function parseLockfileText(file: string, text: string): ParsedLockfile | undefined {
  const base = file.split("/").pop() as string;
  const t = text.replace(/^\uFEFF/, ""); // a BOM is not content; left in, it breaks JSON.parse and hides the first YAML key
  if (base === "package-lock.json" || base === "npm-shrinkwrap.json") return { kind: "npm", file, packages: parseNpmLock(t) };
  if (base === "pnpm-lock.yaml") return { kind: "pnpm", file, packages: parsePnpmLock(t) };
  if (base === "yarn.lock") {
    return isYarnBerry(t)
      ? { kind: "yarn-berry", file, packages: parseYarnBerry(t) }
      : { kind: "yarn-classic", file, packages: parseYarnClassic(t) };
  }
  return undefined;
}

export function packageKey(p: LockedPackage): string {
  return `${p.name}@${p.version}`;
}

/** What the installer fetches, not only the label: an entry relabelled to another tarball or integrity is a different artifact. */
export function artifactKey(p: LockedPackage): string {
  return `${p.name}@${p.version} ${p.resolved ?? ""} ${p.integrity ?? ""}`;
}
