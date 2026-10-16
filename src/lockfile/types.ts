export interface LockedPackage {
  name: string;
  version: string;
  /** Where the lockfile says it was fetched from (URL, git spec, file:, ...). */
  resolved?: string;
  integrity?: string;
  /** Only npm lockfiles record this (hasInstallScript). undefined = unknown. */
  hasInstallScript?: boolean;
  /** Entries that are local links/workspaces and so have no registry integrity by design. */
  local?: boolean;
  /**
   * npm: nested in another package, flagged as bundled, with no `resolved`, as npm writes a dependency that ships
   * inside its parent's tarball. Such an entry has no integrity of its own. The flag proves nothing about where the
   * bytes come from (npm decides that from the parent's bundleDependencies and tarball, and otherwise fetches the
   * entry), so every other check still applies.
   */
  bundled?: boolean;
  /** A runtime binary pnpm downloads (devEngines.runtime); `resolved` is its download URL, not an npm tarball. */
  runtime?: boolean;
}

export type LockfileKind = "npm" | "pnpm" | "yarn-classic" | "yarn-berry";

export interface ParsedLockfile {
  kind: LockfileKind;
  file: string;
  packages: LockedPackage[];
}
