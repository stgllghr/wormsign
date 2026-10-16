/**
 * Signals that a version was published by a worm rather than by the maintainer's usual release process, read from the
 * full registry packument (Accept: application/json; the abbreviated install-v1 document has no _npmUser, scripts or
 * attestations). Each signal compares the target version with the version it replaces, so it works whatever the
 * payload looks like. No network here: the caller fetches the packument.
 *
 * Grounded in the reported worm path (https://research.jfrog.com/post/shai-hulud-is-back-august/): with a stolen token,
 * for every writable package it replaces the scripts object, sets scripts.preinstall, increments the patch version and
 * publishes with a direct authenticated PUT. That adds an install script and names the account that owns the token; only
 * the report's OpenSearch-specific path, which runs inside the victim's trusted release workflow, creates provenance.
 */
import { INSTALL_HOOKS } from "./checks/lifecycle.js";
import type { Severity } from "./types.js";

/** The fields of a full packument these signals read. Field shapes checked on registry.npmjs.org on 2026-10-02. */
export interface Packument {
  name: string;
  /** version -> ISO publish time. Kept for versions that are no longer in `versions`. */
  time?: Record<string, string>;
  versions?: Record<string, PackumentVersion>;
}

export interface PackumentVersion {
  /** The account that published. A trusted (OIDC) publish has name "GitHub Actions" and a trustedPublisher. */
  _npmUser?: { name?: string; trustedPublisher?: { id?: string } };
  scripts?: Record<string, unknown>;
  /** Present when the version was published with a provenance attestation. */
  dist?: { attestations?: { provenance?: unknown } };
}

export interface RegistrySignal {
  ruleId: string;
  severity: Severity;
  message: string;
  /** name@version only, so the fingerprint does not change with the version it was compared with. */
  key: string;
}

export interface RegistrySignals {
  /** The version compared with; undefined when there was nothing to compare with. */
  previous?: string;
  signals: RegistrySignal[];
}

/** How many earlier versions count as the package's usual publishers. */
const RECENT = 5;

const major = (v: string) => Number(v.split(".")[0]);

function publisher(v: PackumentVersion | undefined): string | undefined {
  const u = v?._npmUser;
  if (u?.trustedPublisher) return `trusted publisher ${u.trustedPublisher.id ?? "?"}`;
  return u?.name ? `npm user ${u.name}` : undefined;
}

function installScript(v: PackumentVersion, hook: string): string | undefined {
  const s = v.scripts?.[hook];
  return typeof s === "string" ? s : undefined;
}

/**
 * Compare `version` with `previousVersion` (the base lockfile's version, when the caller knows it) or else with the
 * newest version published before it on its own major line, falling back to a lower major only when its line has none.
 * Packages that maintain several lines publish them interleaved, and each line keeps its own release process.
 * Versions no longer on the registry are never compared with.
 */
export function registrySignals(doc: Packument, version: string, previousVersion?: string): RegistrySignals {
  const versions = doc.versions ?? {};
  const target = versions[version];
  if (!target) return { signals: [] };
  const published = (v: string) => Date.parse(doc.time?.[v] ?? "");
  const at = published(version);
  const history = Object.keys(versions)
    .filter((v) => published(v) < at && major(v) <= major(version))
    .sort((a, b) => Number(major(a) !== major(version)) - Number(major(b) !== major(version)) || published(b) - published(a));
  const previous = previousVersion ?? history[0];
  const prev = previous === undefined ? undefined : versions[previous];
  const id = `${doc.name}@${version}`;
  const signals: RegistrySignal[] = [];
  const add = (ruleId: string, severity: Severity, message: string) => signals.push({ ruleId, severity, message, key: id });

  if (prev) {
    for (const hook of INSTALL_HOOKS) {
      const now = installScript(target, hook);
      const before = installScript(prev, hook);
      if (now === undefined || now === before) continue;
      add("WS-RG-001", "high", before === undefined
        ? `${id} adds a ${hook} script that ${previous} did not have: ${now.slice(0, 120)}`
        : `${id} changes its ${hook} script from ${previous}'s "${before.slice(0, 120)}" to: ${now.slice(0, 120)}`);
    }
    if (prev.dist?.attestations?.provenance && !target.dist?.attestations?.provenance) {
      add("WS-RG-002", "high", `${id} was published without provenance; ${previous} had a provenance attestation`);
    }
  }

  // Only a token or password publish is checked: a trusted publish carries provenance naming the workflow that made it.
  const who = publisher(target);
  const recent = history.slice(0, RECENT);
  const usual = new Set(recent.map((v) => publisher(versions[v])).filter((p) => p !== undefined));
  if (!target._npmUser?.trustedPublisher && who && usual.size > 0 && !usual.has(who)) {
    add("WS-RG-003", "medium", `${id} was published by ${who}, who published none of the ${recent.length} versions before it (${recent.at(-1)} to ${recent[0]}), published by ${[...usual].join(", ")}`);
  }
  return { previous: prev ? previous : undefined, signals };
}
