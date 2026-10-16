import { createHash } from "node:crypto";
import type { IocSet, PackageIndex } from "../iocs.js";
import { indexPackages } from "../iocs.js";
import type { Finding, Severity } from "../types.js";
import { KEY_DIGEST_HEX, keyDigest, makeFinding } from "../types.js";

export interface ScanContext {
  iocs: IocSet;
  pkgIndex: PackageIndex;
  /** Hosts a lockfile may resolve from without a WS-LK-002 finding. */
  registryHosts: Set<string>;
  hashAll: boolean;
}

export const DEFAULT_REGISTRY_HOSTS = ["registry.npmjs.org", "registry.yarnpkg.com"];

export function makeContext(iocs: IocSet, extra: { registryHosts?: string[]; hashAll?: boolean } = {}): ScanContext {
  return {
    iocs,
    pkgIndex: indexPackages(iocs.packageSets),
    registryHosts: new Set([...DEFAULT_REGISTRY_HOSTS, ...(extra.registryHosts ?? [])]),
    hashAll: extra.hashAll ?? false,
  };
}

/**
 * A file that decides what runs at install time (manifest, lockfile, workflow)
 * but whose checks could not run. High, so the default gate fails closed: a
 * package manager may still act on a file wormsign could not read. Lower only
 * when a package manager acts on it in narrow cases (see scan.ts).
 *
 * The key digests the reason, and the content when the file was read (`content`): a baseline entry approves this file
 * unreadable for this reason (a Bun repository's bun.lock, whatever it locks), or this content (a fixture that is not
 * valid JSON), and nothing else. A file made unreadable another way, too large or a symlink where it was a parse
 * error, or a settings file with other content under the same "__proto__" key, is a new finding.
 */
export function notChecked(file: string, why: string, severity: Severity = "high", content?: string): Finding {
  const key = `not-checked ${keyDigest(content === undefined ? why : `${why}\0${content}`)}`;
  return makeFinding({ ruleId: "WS-SC-900", severity, message: `${file} was not checked: ${why}`, file, key });
}

/** One finding per fingerprint, the first kept: the same name@version can sit at several lockfile paths. */
export function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => (seen.has(f.fingerprint) ? false : (seen.add(f.fingerprint), true)));
}

/**
 * Findings for one file, at most `max` of them listed one by one: one hostile
 * 2 MiB file can hold 100,000 entries. The rest collapse into one summary
 * finding whose key digests all of their keys, so a baseline entry for the
 * summary stops matching when another entry appears.
 */
export function capped(max: number): { add(key: string, make: (key: string) => Finding): void; done(summary: (more: number, key: string) => Finding): Finding[] } {
  const out: Finding[] = [];
  const rest = createHash("sha256");
  let more = 0;
  return {
    add(key, make) {
      if (out.length < max) out.push(make(key));
      else {
        rest.update(`${key}\n`);
        more++;
      }
    },
    done(summary) {
      if (more > 0) out.push(summary(more, rest.digest("hex").slice(0, KEY_DIGEST_HEX)));
      return out;
    },
  };
}
