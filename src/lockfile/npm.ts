import type { LockedPackage } from "./types.js";
import { checkIdentity } from "./identity.js";

interface NpmEntry {
  version?: string;
  resolved?: string;
  integrity?: string;
  hasInstallScript?: boolean;
  link?: boolean;
  inBundle?: boolean;
  bundled?: boolean;
  name?: string;
  dependencies?: Record<string, NpmEntry>;
}

/** Package name from a lockfile v2/v3 key such as "node_modules/a/node_modules/@s/b". */
export function nameFromPath(key: string): string {
  const i = key.lastIndexOf("node_modules/");
  return i === -1 ? key : key.slice(i + "node_modules/".length);
}

/**
 * JSON lets a field be any type, and RegExp.test reads `["is-number"]` as "is-number": the name would pass
 * checkIdentity while the IOC lookup, keyed on the array, misses it (npm 10 still installs is-number).
 */
function strings(e: NpmEntry, where: string): NpmEntry {
  for (const f of ["name", "version", "resolved", "integrity"] as const) {
    if (e[f] !== undefined && typeof e[f] !== "string") throw new Error(`${where}: "${f}" is not a string`);
  }
  return e;
}

export function parseNpmLock(text: string): LockedPackage[] {
  const json = JSON.parse(text) as { lockfileVersion?: unknown; packages?: Record<string, NpmEntry>; dependencies?: Record<string, NpmEntry> } | null;
  const v = json?.lockfileVersion;
  if (!json || (v !== 1 && v !== 2 && v !== 3)) throw new Error(`unsupported lockfileVersion ${JSON.stringify(v)}`);
  const out: LockedPackage[] = [];
  if (v !== 1) {
    if (typeof json.packages !== "object" || json.packages === null) throw new Error(`lockfileVersion ${v} has no "packages" map`);
    for (const [key, entry] of Object.entries(json.packages)) {
      if (key === "") continue; // the root project itself
      const e = strings(entry, key);
      const local = e.link === true || !key.includes("node_modules/");
      const nested = key.indexOf("node_modules/") !== key.lastIndexOf("node_modules/");
      if (!e.version && !local) throw new Error(`${key} has no version`);
      const p: LockedPackage = {
        name: e.name ?? nameFromPath(key),
        version: e.version ?? "",
        ...(e.resolved ? { resolved: e.resolved } : {}),
        ...(e.integrity ? { integrity: e.integrity } : {}),
        ...(e.hasInstallScript !== undefined ? { hasInstallScript: e.hasInstallScript } : {}),
        ...(local ? { local: true } : {}),
        // npm writes no integrity for a bundled dependency, but fetches one its parent's tarball lacks: the flag excuses nothing else
        ...(nested && e.inBundle === true && !e.resolved ? { bundled: true } : {}),
      };
      out.push(local ? p : checkIdentity(p, key)); // a workspace's key is its path, not a package name
    }
    return out;
  }
  // lockfileVersion 1 (npm 6): a nested "dependencies" tree.
  const walkV1 = (deps: Record<string, NpmEntry> | undefined, nested: boolean): void => {
    for (const [name, entry] of Object.entries(deps ?? {})) {
      const e = strings(entry, `dependency ${name}`);
      if (!e.version) throw new Error(`dependency ${name} has no version`);
      const p: LockedPackage = { ...v1Identity(name, e.version), ...(e.integrity ? { integrity: e.integrity } : {}), ...v1Source(e.version, e) };
      out.push(checkIdentity(nested && e.bundled === true && !p.resolved ? { ...p, bundled: true } : p, `dependency ${name}`));
      walkV1(e.dependencies, true);
    }
  };
  walkV1(json.dependencies, false);
  return out;
}

/** v1 keys an alias by the alias name, with version "npm:<real name>@<version>". */
function v1Identity(name: string, version: string): { name: string; version: string } {
  if (!version.startsWith("npm:")) return { name, version };
  const at = version.lastIndexOf("@");
  return { name: version.slice("npm:".length, at), version: version.slice(at + 1) };
}

/** v1 has no `resolved` for git and file: deps; their `version` holds the spec instead. */
function v1Source(version: string, e: NpmEntry): Pick<LockedPackage, "resolved" | "local"> {
  if (version.startsWith("file:")) return /\.(tgz|tar\.gz|tar)$/.test(version) ? { resolved: version } : { local: true };
  if (version.startsWith("npm:") || /^\d/.test(version)) return e.resolved ? { resolved: e.resolved } : {};
  return { resolved: e.resolved || version }; // git or URL spec (`||`: an empty `resolved` is no source either)
}
