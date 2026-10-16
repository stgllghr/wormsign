import type { Finding } from "../types.js";
import { makeFinding } from "../types.js";
import type { LockedPackage, ParsedLockfile } from "../lockfile/index.js";
import type { ScanContext } from "./context.js";
import { artifactKey } from "../lockfile/index.js";
import { registryTarball } from "../lockfile/tarball.js";

/** Git sources, including the codeload.github.com archives yarn 1 and pnpm record for github: dependencies. */
export function isGitSpec(resolved: string): boolean {
  return /^(git\+|git:|github:|gitlab:|bitbucket:|ssh:|git@|https:\/\/codeload\.github\.com\/)/.test(resolved) || /\.git(#|$)/.test(resolved);
}

/** undefined for unparseable and for host-less specs such as file:, link: and patch:. */
function hostOf(resolved: string): string | undefined {
  try {
    return new URL(resolved).host || undefined;
  } catch {
    return undefined;
  }
}

/** Where pnpm 11 downloads each devEngines.runtime binary from (the URLs `pnpm install` writes into the lockfile). */
const RUNTIME_SOURCES = new Map([
  ["node", ["https://nodejs.org/download/", "https://unofficial-builds.nodejs.org/download/"]], // the latter for musl
  ["deno", ["https://github.com/denoland/deno/releases/download/"]],
  ["bun", ["https://github.com/oven-sh/bun/releases/download/"]],
]);

function isOfficialRuntime(name: string, url: string): boolean {
  try {
    const href = new URL(url).href; // resolves `..`, which could otherwise climb out of the release path
    return (RUNTIME_SOURCES.get(name) ?? []).some((prefix) => href.startsWith(prefix));
  } catch {
    return false;
  }
}

export function checkLockfile(lock: ParsedLockfile, ctx: ScanContext): Finding[] {
  const out: Finding[] = [];
  for (const p of lock.packages) {
    const id = `${p.name}@${p.version}`;
    // A registry URL that names another package: either one may be what gets installed (see registryTarball).
    const t = p.resolved && !p.local && !p.runtime ? registryTarball(p.resolved) : undefined;
    const other = t && `${t.name}@${t.version}` !== id ? `${t.name}@${t.version}` : undefined;
    const listed = p.version ? ctx.pkgIndex.lookup(p.name, p.version) : undefined;
    const source = listed ?? (t && other ? ctx.pkgIndex.lookup(t.name, t.version) : undefined);
    if (source) {
      const message = listed ? `${id} is listed as compromised` : `${id} resolves to the registry tarball of ${other}, which is listed as compromised`;
      out.push(makeFinding({ ruleId: "WS-LK-001", severity: "critical", message, file: lock.file, key: id, source }));
    }
    out.push(...resolutionFindings(lock, p, id, ctx, other));
  }
  return out;
}

/**
 * WS-LK-002 and WS-LK-003 are about where an entry is fetched from and what vouches for it, so their key is the
 * artifact (name, version, resolved, integrity), as for WS-SK-002: a baseline entry for one git source or private
 * tarball does not also approve the same name@version repointed at another URL.
 */
function resolutionFindings(lock: ParsedLockfile, p: LockedPackage, id: string, ctx: ScanContext, other: string | undefined): Finding[] {
  if (p.local) return [];
  const out: Finding[] = [];
  const key = artifactKey(p);
  const r = p.resolved;
  if (r && p.runtime) {
    if (!isOfficialRuntime(p.name, r)) {
      out.push(
        makeFinding({
          ruleId: "WS-LK-002",
          severity: "high",
          message: `${id} downloads its runtime binary from ${r.slice(0, 100)}, not ${p.name}'s official release site`,
          file: lock.file,
          key,
        }),
      );
    }
  } else if (r) {
    if (isGitSpec(r)) {
      out.push(
        makeFinding({
          ruleId: "WS-LK-002",
          severity: "medium",
          message: `${id} resolves from a git source (${r.slice(0, 100)}); git dependencies can run install scripts and are not covered by registry integrity`,
          file: lock.file,
          key,
        }),
      );
      return out;
    }
    const host = hostOf(r);
    const allowed = host !== undefined && ctx.registryHosts.has(host);
    const plain = r.startsWith("http:");
    if (!allowed || plain) {
      const why = host === undefined ? ", which is not a registry URL" : allowed ? "" : ", not an allowed registry host";
      out.push(
        makeFinding({
          ruleId: "WS-LK-002",
          severity: "high",
          message: `${id} resolves from ${host ?? r.slice(0, 80)}${plain ? " over plain HTTP" : ""}${why}`,
          file: lock.file,
          key,
        }),
      );
    } else if (other) {
      out.push(
        makeFinding({
          ruleId: "WS-LK-002",
          severity: "high",
          message: `${id} resolves to the registry tarball of ${other}, which npm, yarn 1 and pnpm 10 can install in its place`,
          file: lock.file,
          key,
        }),
      );
    }
  }
  if (!p.integrity && !p.bundled && lock.kind !== "yarn-berry") {
    out.push(
      makeFinding({
        ruleId: "WS-LK-003",
        severity: "medium",
        message: `${id} has no integrity hash in ${lock.file}`,
        file: lock.file,
        key,
      }),
    );
  }
  return out;
}
