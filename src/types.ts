export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

export function severityRank(s: Severity): number {
  return SEVERITIES.indexOf(s);
}

export function parseSeverity(s: string): Severity {
  if ((SEVERITIES as readonly string[]).includes(s)) return s as Severity;
  throw new UsageError(`invalid severity "${s}" (expected one of ${SEVERITIES.join(", ")})`);
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  message: string;
  /** Path relative to the scan root, forward slashes. */
  file?: string;
  line?: number;
  /** The specific thing that matched (package@version, script name, ...). Part of the fingerprint. */
  key: string;
  /** URL backing an IOC-derived finding. */
  source?: string;
  /** Stable id used by the baseline. Set by makeFinding(). */
  fingerprint: string;
  /** Set when the finding is suppressed by the baseline. */
  suppressed?: { justification: string };
  /** No baseline entry suppresses this finding (src/baseline.ts applyBaseline); its message says why. */
  notBaselinable?: true;
}

export class UsageError extends Error {}

import { createHash } from "node:crypto";

/**
 * How many hex characters of a SHA-256 a fingerprint keeps, and a digest of content inside a finding's key: 32, so
 * 128 bits. A baseline entry approves a fingerprint, so this is what binds an approval to the content it was given
 * for. Finding other content with an approved entry's value (a second preimage) takes about 2^128 hashes; crafting two
 * contents, one to get approved and one to ship, that share a value (a collision) takes about 2^64.
 * docs/baseline.md#fingerprints says the same.
 */
export const FINGERPRINT_HEX = 32;
export const KEY_DIGEST_HEX = 32;

export function fingerprint(ruleId: string, file: string | undefined, key: string): string {
  return createHash("sha256").update(`${ruleId}\0${file ?? ""}\0${key}`).digest("hex").slice(0, FINGERPRINT_HEX);
}

/** The digest of content that a finding's key carries (a script's command, a file's bytes, a setting's value). */
export function keyDigest(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex").slice(0, KEY_DIGEST_HEX);
}

export function makeFinding(f: Omit<Finding, "fingerprint">): Finding {
  return { ...f, fingerprint: fingerprint(f.ruleId, f.file, f.key) };
}

/** Rule catalogue: single source of truth for SARIF rule metadata and docs. */
export interface RuleInfo {
  id: string;
  name: string;
  description: string;
  /** What to do about a finding; shown as the rule help on GitHub code scanning alerts. */
  help: string;
}
