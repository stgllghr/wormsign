import { createHash } from "node:crypto";
import { readBytes } from "../fsutil.js";
import type { Finding } from "../types.js";
import { makeFinding, severityRank } from "../types.js";
import type { ScanContext } from "./context.js";

const MAX_HASH_BYTES = 64 * 1024 * 1024;

/** A file's SHA-256, or why it was not hashed. Never follows a symlink (see readBytes). */
export function sha256OfFile(path: string): { sha256: string } | { problem: string } {
  const read = readBytes(path, MAX_HASH_BYTES);
  return "problem" in read ? read : { sha256: createHash("sha256").update(read.bytes).digest("hex") };
}

/** Basenames worth hashing: any name in the IOC list. */
export function candidateNames(ctx: ScanContext): Set<string> {
  return new Set([...ctx.iocs.hashes.map((h) => h.name), ...ctx.iocs.names.map((n) => n.name)]);
}

/**
 * Hash IOCs whose source published no file name, labelled "(description)" in
 * the IOC data. No basename matches such a label, so only --hash-all checks them.
 */
export function hashesOnlyCheckedWithHashAll(ctx: ScanContext): string[] {
  return ctx.hashAll ? [] : ctx.iocs.hashes.filter((h) => /^\(.*\)$/.test(h.name)).map((h) => h.name);
}

/**
 * Hash and name IOCs for one file. `abs` is undefined for a symlink, which is
 * never read, so only its name counts. A file that should have been hashed but
 * was not is passed to onUnhashed, so the skip is never silent.
 */
export function checkFile(rel: string, abs: string | undefined, names: Set<string>, ctx: ScanContext, onUnhashed?: (why: string) => void): Finding[] {
  const base = rel.split("/").pop() as string;
  const nameIoc = ctx.iocs.names.find((n) => n.name === base);
  const shouldHash = ctx.hashAll || names.has(base);
  const out: Finding[] = [];
  let matched = false;
  if (shouldHash) {
    const digest = abs === undefined ? { problem: "it is a symlink" } : sha256OfFile(abs);
    if ("problem" in digest) onUnhashed?.(digest.problem);
    const hit = "sha256" in digest ? ctx.iocs.hashes.find((h) => h.sha256 === digest.sha256) : undefined;
    if (hit) {
      matched = true;
      out.push(
        makeFinding({
          ruleId: "WS-FS-001",
          severity: "critical",
          message: `SHA-256 matches ${hit.name} from the ${hit.wave} wave${hit.note ? ` (${hit.note})` : ""}`,
          file: rel,
          key: hit.sha256,
          source: hit.source,
        }),
      );
    }
  }
  if (!matched && nameIoc && severityRank(nameIoc.nameOnlySeverity) > severityRank("info")) {
    out.push(
      makeFinding({
        ruleId: "WS-FS-002",
        severity: nameIoc.nameOnlySeverity,
        message: `File name ${nameIoc.name} is a reported worm payload name (${nameIoc.wave} wave); hash did not match a known sample, so verify the content${nameIoc.note ? `. ${nameIoc.note}` : ""}`,
        file: rel,
        key: nameIoc.name,
        source: nameIoc.source,
      }),
    );
  }
  return out;
}
