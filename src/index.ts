/** Public, read-only library surface. CLI and implementation internals are not API exports. */
import { resolve } from "node:path";
import { makeContext } from "./checks/context.js";
import { bundledIocDir, loadIocs } from "./iocs.js";
import { scanDirectory } from "./scan.js";
import type { ScanResult } from "./scan.js";
import { gateExitCode as reportGateExitCode } from "./report.js";
import { parseSeverity, UsageError } from "./types.js";
import type { Finding, Severity } from "./types.js";

export { UsageError } from "./types.js";
export { renderReport } from "./report.js";
export type { Finding, Severity } from "./types.js";
export type { Format, Report } from "./report.js";
export type { ScanResult } from "./scan.js";

export interface ScanOptions {
  /** Include installed package manifests under node_modules. Default: false. */
  nodeModules?: boolean;
  /** Hash every file, within the scanner's existing byte limits. Default: false. */
  hashAll?: boolean;
  /** Additional trusted registry hostnames; the standard npm/Yarn hosts remain allowed. */
  registryHosts?: string[];
  /** Explicit trusted IOC directory. Default: this release's bundled data, without the user cache. */
  iocsDirectory?: string;
}

const OPTION_KEYS = new Set(["nodeModules", "hashAll", "registryHosts", "iocsDirectory"]);

function validate(root: string, options: ScanOptions): void {
  if (typeof root !== "string" || !root.trim()) throw new UsageError("scan needs a nonempty directory path");
  if (!options || typeof options !== "object" || Array.isArray(options) || Object.keys(options).some(key => !OPTION_KEYS.has(key))) {
    throw new UsageError("invalid scan options");
  }
  for (const key of ["nodeModules", "hashAll"] as const) {
    if (options[key] !== undefined && typeof options[key] !== "boolean") throw new UsageError(`${key} must be a boolean`);
  }
  if (options.iocsDirectory !== undefined && (typeof options.iocsDirectory !== "string" || !options.iocsDirectory.trim())) {
    throw new UsageError("iocsDirectory must be a nonempty directory path");
  }
  if (options.registryHosts !== undefined && (!Array.isArray(options.registryHosts) || !options.registryHosts.every(host => typeof host === "string" && host.length > 0 && !/[\s/:@?#]/u.test(host)))) {
    throw new UsageError("registryHosts must be an array of hostnames");
  }
}

/**
 * Scan without network access, subprocesses, writes or repository baseline suppressions.
 * Findings and notes are observations, never authorization to install or execute code.
 * Invalid options, roots or explicit IOC data throw UsageError; unchecked project inputs remain findings.
 */
export function scan(root: string, options: ScanOptions = {}): ScanResult {
  validate(root, options);
  const iocs = loadIocs({ dir: options.iocsDirectory ?? bundledIocDir });
  const result = scanDirectory(resolve(root), makeContext(iocs, options), { nodeModules: options.nodeModules ?? false });
  return { ...result, notes: [...iocs.notes, ...result.notes] };
}

/** Same finding threshold as the CLI. Zero is below threshold, not an execution allow decision. */
export function gateExitCode(findings: Finding[], failOn: Severity | "never" = "high"): 0 | 1 {
  if (failOn !== "never") parseSeverity(failOn);
  return reportGateExitCode(findings, failOn);
}
