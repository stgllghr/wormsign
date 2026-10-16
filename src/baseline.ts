import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import type { Finding } from "./types.js";
import { FINGERPRINT_HEX, UsageError, makeFinding } from "./types.js";

export interface BaselineEntry {
  fingerprint: string;
  justification: string;
  /** ISO date (YYYY-MM-DD). After this date the entry stops suppressing. */
  expires?: string;
}

export interface IgnorePath {
  /** Posix path prefix relative to the scan root. */
  path: string;
  justification: string;
}

export interface Baseline {
  version: 1;
  entries: BaselineEntry[];
  /** Whole paths excluded from scanning (fixtures, vendored IOC data). Each needs a justification. */
  ignorePaths: IgnorePath[];
}

export const BASELINE_FILE = ".wormsign-baseline.json";
const FINGERPRINT = new RegExp(`^[0-9a-f]{${FINGERPRINT_HEX}}$`);

export const MIN_JUSTIFICATION = 15;
// Only words that mark unfinished text are rejected as a prefix. Short placeholders ("n/a", "ok", "test") already fail
// the length check, and a real sentence may start with them ("Test fixtures contain inert IOC strings").
const UNFINISHED = /^(todo|tbd|fixme)\b/i;

export function isRealJustification(j: unknown): j is string {
  return typeof j === "string" && j.trim().length >= MIN_JUSTIFICATION && !UNFINISHED.test(j.trim());
}

/** 32 lower-case hex characters, as every output format prints a fingerprint. */
export function isFingerprint(s: unknown): s is string {
  return typeof s === "string" && FINGERPRINT.test(s);
}

/** A real calendar date: "2026-02-30" would otherwise roll over and "2026-13-45" would never expire. */
export function isCalendarDate(s: unknown): s is string {
  if (typeof s !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(`${s}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;
}

/** Unknown keys are errors: a typo such as "expiry" would otherwise turn a time-limited suppression into a permanent one. */
function rejectUnknownKeys(o: object, allowed: string[], where: string): void {
  const extra = Object.keys(o).find((k) => !allowed.includes(k));
  if (extra !== undefined) throw new UsageError(`${where}: unknown key "${extra}" (allowed: ${allowed.join(", ")})`);
}

/** "./src/" and "src" mean the same prefix; globs, "." and backslashes would silently match nothing, so they are errors. */
function normalizeIgnorePath(p: unknown): string | undefined {
  if (typeof p !== "string") return undefined;
  const n = p.replace(/^(\.\/)+/, "").replace(/\/+$/, "");
  if (n === "" || n === "." || n.startsWith("/") || n.split("/").includes("..") || /[\\*?[\]{}]/.test(n)) return undefined;
  return n;
}

export function isIgnored(rel: string, prefixes: string[]): boolean {
  return prefixes.some((p) => rel === p || rel.startsWith(`${p}/`));
}

/** Most bytes a baseline file may hold: thousands of entries, and a bound on what a checked tree can make wormsign read. */
export const MAX_BASELINE_BYTES = 2 * 1024 * 1024;

/**
 * Reads a baseline file as every other file a checked tree brings is read: a regular file of at most
 * MAX_BASELINE_BYTES, opened without waiting on a FIFO (O_NONBLOCK) and, for the file found in the checked directory
 * (`follow: false`), without following a final symlink (O_NOFOLLOW). A tree that commits .wormsign-baseline.json as a
 * link to /dev/zero or as a FIFO would otherwise make wormsign read without end or wait forever. An explicit
 * --baseline is the caller's choice and may be a link, but is still read only as a regular file under the cap.
 */
export function loadBaseline(path: string, opts: { follow?: boolean } = {}): Baseline {
  return parseBaseline(readBaselineText(path, opts), path);
}

/** The text of a baseline file, read as loadBaseline reads it (`baseline add` reads the file it extends this way). */
export function readBaselineText(path: string, opts: { follow?: boolean } = {}): string {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0) | (opts.follow === false ? (constants.O_NOFOLLOW ?? 0) : 0));
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT") throw new UsageError(`baseline file not found: ${path}`);
    throw new UsageError(`cannot read baseline ${path}: ${code === "ELOOP" ? "it is a symlink, which wormsign does not follow for the baseline in the checked directory (pass --baseline to choose a file)" : (code ?? (e as Error).message)}`);
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new UsageError(`cannot read baseline ${path}: it is not a regular file`);
    if (st.size > MAX_BASELINE_BYTES) throw new UsageError(`cannot read baseline ${path}: it is larger than ${MAX_BASELINE_BYTES / 1024 / 1024} MiB`);
    return readFileSync(fd, "utf8");
  } finally {
    closeSync(fd);
  }
}

/**
 * Every command reads a baseline through here. A leading UTF-8 byte-order mark is not content (editors on Windows add
 * one, and npm strips it from package.json), so it is dropped everywhere rather than accepted by one command only.
 */
export function parseBaseline(text: string, where: string): Baseline {
  let raw: unknown;
  try {
    raw = JSON.parse(text.replace(/^\uFEFF/, ""));
  } catch {
    // Not V8's message, which quotes the start of the file: a symlinked baseline must not print a file it points at.
    throw new UsageError(`baseline ${where} is not valid JSON`);
  }
  return validateBaseline(raw, where);
}

export function validateBaseline(raw: unknown, where = "baseline"): Baseline {
  const o = raw as { version?: unknown; entries?: unknown; ignorePaths?: unknown };
  if (!o || typeof o !== "object" || o.version !== 1 || !Array.isArray(o.entries)) {
    throw new UsageError(`${where}: expected {"version":1,"entries":[...]}`);
  }
  rejectUnknownKeys(o, ["version", "entries", "ignorePaths"], where);
  if (o.ignorePaths !== undefined && !Array.isArray(o.ignorePaths)) throw new UsageError(`${where}: ignorePaths must be an array`);
  const ignorePaths: IgnorePath[] = (o.ignorePaths ?? []).map((ip: unknown, i: number) => {
    const x = (ip ?? {}) as Partial<IgnorePath>;
    rejectUnknownKeys(x, ["path", "justification"], `${where}: ignorePaths[${i}]`);
    const path = normalizeIgnorePath(x.path);
    if (path === undefined) {
      throw new UsageError(`${where}: ignorePaths[${i}].path must be a relative path prefix (no "..", globs, backslashes or ".")`);
    }
    if (!isRealJustification(x.justification)) {
      throw new UsageError(`${where}: ignorePaths[${i}] (${path}) needs a real justification (at least ${MIN_JUSTIFICATION} characters, not a placeholder)`);
    }
    return { path, justification: x.justification.trim() };
  });
  const seen = new Set<string>();
  const entries: BaselineEntry[] = o.entries.map((e: unknown, i: number) => {
    const x = (e ?? {}) as Partial<BaselineEntry>;
    rejectUnknownKeys(x, ["fingerprint", "justification", "expires"], `${where}: entries[${i}]`);
    if (typeof x.fingerprint !== "string" || !FINGERPRINT.test(x.fingerprint)) {
      throw new UsageError(`${where}: entries[${i}].fingerprint must be ${FINGERPRINT_HEX} lower-case hex characters, as reports print it`);
    }
    if (!isRealJustification(x.justification)) {
      throw new UsageError(
        `${where}: entries[${i}] (${x.fingerprint}) needs a real justification (at least ${MIN_JUSTIFICATION} characters, not a placeholder)`,
      );
    }
    if (x.expires !== undefined && !isCalendarDate(x.expires)) {
      throw new UsageError(`${where}: entries[${i}].expires must be a real date written YYYY-MM-DD`);
    }
    if (seen.has(x.fingerprint)) throw new UsageError(`${where}: duplicate fingerprint ${x.fingerprint}`);
    seen.add(x.fingerprint);
    return { fingerprint: x.fingerprint, justification: x.justification.trim(), ...(x.expires ? { expires: x.expires } : {}) };
  });
  return { version: 1, entries, ignorePaths };
}

/**
 * Rules whose findings no baseline entry suppresses. WS-SK-006 and WS-OS-901 are an outage under --on-outage warn: an
 * outage is transient, so an entry for one would waive the next outage that leaves the same package unchecked.
 */
export const NOT_BASELINABLE: ReadonlySet<string> = new Set(["WS-SK-006", "WS-OS-901"]);
/** Why, for baseline add --from. */
export const NOT_BASELINABLE_WHY = "an outage under --on-outage warn is transient, so an entry for one would waive the next outage that leaves the same package unchecked";

/**
 * Marks baselined findings as suppressed. An expired entry does not suppress and
 * adds a WS-BL-001 finding so the expiry is visible instead of silently ignored.
 * A finding of a NOT_BASELINABLE rule, or one marked notBaselinable (a requirements problem soak does not understand
 * well enough for its key to fix what an install fetches: src/python/requirements.ts approvable), is never suppressed,
 * whatever the file lists.
 */
export function applyBaseline(findings: Finding[], baseline: Baseline | undefined, now: Date): Finding[] {
  if (!baseline) return findings;
  const byFp = new Map(baseline.entries.map((e) => [e.fingerprint, e]));
  const out: Finding[] = [];
  const expired = new Set<string>();
  for (const f of findings) {
    const e = NOT_BASELINABLE.has(f.ruleId) || f.notBaselinable === true ? undefined : byFp.get(f.fingerprint);
    if (!e) {
      out.push(f);
      continue;
    }
    if (e.expires && new Date(`${e.expires}T23:59:59Z`) < now) {
      expired.add(e.fingerprint);
      out.push(f);
      continue;
    }
    out.push({ ...f, suppressed: { justification: e.justification } });
  }
  for (const fp of expired) {
    const e = byFp.get(fp) as BaselineEntry;
    out.push(
      makeFinding({
        ruleId: "WS-BL-001",
        severity: "medium",
        message: `Baseline entry ${fp} expired on ${e.expires}; the finding it covered is active again.`,
        key: fp,
      }),
    );
  }
  return out;
}
