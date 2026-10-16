/**
 * `wormsign baseline add`: appends reviewed findings to a baseline file, each with the reason a person wrote. It
 * reads and writes that one file only, and reads the JSON report given with --from: no scan, no IOC data, no network.
 * There is deliberately no mode that accepts every current finding, since each entry switches a check off and needs
 * its own reason (docs/cli/baseline.md).
 */
import { accessSync, closeSync, constants, fchmodSync, fstatSync, lstatSync, openSync, readFileSync, readSync, renameSync, rmSync, statSync, writeFileSync, writeSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { basename, dirname, join } from "node:path";
import { MAX_BASELINE_BYTES, MIN_JUSTIFICATION, NOT_BASELINABLE, NOT_BASELINABLE_WHY, isCalendarDate, isFingerprint, isRealJustification, parseBaseline, readBaselineText } from "./baseline.js";
import type { Stats } from "node:fs";
import type { BaselineEntry } from "./baseline.js";
import { FINGERPRINT_HEX, UsageError } from "./types.js";

export interface AddRequest {
  fingerprints: string[];
  /** The justification every new entry gets. */
  reason: string;
  /** YYYY-MM-DD: the last day the new entries suppress. */
  expires?: string;
  /** A report written by `--format json` (--from): each fingerprint must be a finding in it that an entry can approve. */
  from?: string;
  now: Date;
}

export interface AddResult {
  path: string;
  created: boolean;
  added: BaselineEntry[];
}

/** The writes that put the new file in place. Tests pass their own to make one fail. */
export interface AddOps {
  write(fd: number, text: string): void;
  rename(from: string, to: string): void;
  /** How long to wait for another baseline add to release the file's lock, in milliseconds (default LOCK_WAIT_MS). */
  lockWaitMs?: number;
  /** For tests: runs after each read of a lock file another add holds, before baseline add decides what it is. */
  lockRead?: () => void;
}

/** How long baseline add waits for another one writing the same file, and how often it looks. */
const LOCK_WAIT_MS = 10_000;
const LOCK_POLL_MS = 20;

const FS: AddOps = { write: (fd, text) => writeFileSync(fd, text), rename: renameSync };

/** What was typed, checked by the rules a scan applies to the file, before the file is looked at. */
function checkAddRequest(req: AddRequest): void {
  for (const fp of req.fingerprints) {
    if (!isFingerprint(fp)) throw new UsageError(`"${fp}" is not a fingerprint: ${FINGERPRINT_HEX} lower-case hex characters, as reports print it`);
  }
  const twice = req.fingerprints.find((fp, i) => req.fingerprints.indexOf(fp) !== i);
  if (twice !== undefined) throw new UsageError(`fingerprint ${twice} is given twice`);
  if (!isRealJustification(req.reason)) {
    throw new UsageError(`--reason needs a real justification (at least ${MIN_JUSTIFICATION} characters, not a placeholder): what was reviewed and why it is safe`);
  }
  if (req.expires === undefined) return;
  if (!isCalendarDate(req.expires)) throw new UsageError(`invalid --expires "${req.expires}" (a real date written YYYY-MM-DD)`);
  // An entry suppresses through 23:59:59 UTC on its date (applyBaseline), so today is the earliest date that still
  // does anything.
  if (new Date(`${req.expires}T23:59:59Z`) < req.now) throw new UsageError(`--expires ${req.expires} is in the past (an entry suppresses through 23:59:59 UTC on its date)`);
}

/**
 * Appends one entry per fingerprint to the baseline at `path`, creating `{"version": 1, "entries": []}` first when
 * there is none. The existing file must pass every check a scan makes, and none of the fingerprints may be in it
 * already. Every other field is kept as written (ignorePaths included), and the file is rewritten as 2-space JSON.
 * A symlink, anything but a regular file, or a file the user cannot write is refused, never written through or
 * replaced. The new text goes to a temporary file in the same directory, which is renamed into place, so a failure
 * leaves the old file whole; a lock file beside it (lock()) keeps two baseline adds from losing each other's entries.
 */
export function addToBaseline(path: string, req: AddRequest, ops: AddOps = FS): AddResult {
  checkAddRequest(req);
  if (req.from !== undefined) checkAgainstReport(req.fingerprints, req.from);
  // The lock is a file beside the baseline, so its directory must exist first.
  if (lstatOf(path) === undefined) checkDirectory(path);
  const release = lock(path, ops.lockWaitMs ?? LOCK_WAIT_MS, ops.lockRead);
  try {
    return addLocked(path, req, ops);
  } finally {
    release();
  }
}

function lstatOf(path: string): Stats | undefined {
  try {
    return lstatSync(path, { throwIfNoEntry: false });
  } catch (e) {
    throw new UsageError(`cannot read baseline ${path}: ${(e as NodeJS.ErrnoException).code ?? (e as Error).message}`);
  }
}

function checkDirectory(path: string): void {
  const dir = dirname(path);
  if (!statSync(dir, { throwIfNoEntry: false })?.isDirectory()) throw new UsageError(`cannot create baseline ${path}: directory ${dir} does not exist`);
}

/**
 * Takes the lock on the baseline at `path`, `.<name>.lock` beside it, created exclusively (O_EXCL), so that one baseline
 * add at a time reads and replaces the file: two at once would each write what they read plus their own entries, and
 * the last rename would drop the other's. Waits up to `waitMs` for another to finish, then refuses. Returns the function
 * that removes the lock; a lock this call did not create is never removed.
 */
function lock(path: string, waitMs: number, lockRead?: () => void): () => void {
  const file = join(dirname(path), `.${basename(path)}.lock`);
  const deadline = Date.now() + waitMs;
  for (;;) {
    let fd: number;
    try {
      fd = openSync(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code !== "EEXIST") throw new UsageError(`cannot write baseline ${path}: cannot create its lock file ${file}: ${code ?? (e as Error).message}; the file is unchanged`);
      const holder = lockHolder(file);
      lockRead?.();
      // A lock no running add holds is never removed here: the user decides, with the command given.
      const remove = `Remove it if no baseline add is running: rm -- ${shellQuote(file)}`;
      if (holder.kind === "link") throw new UsageError(`cannot add to baseline ${path}: its lock file ${file} is a symlink, which baseline add never makes; nothing was changed. ${remove}`);
      if (holder.kind === "other") throw new UsageError(`cannot add to baseline ${path}: its lock file ${file} is not a regular file, which baseline add never makes; nothing was changed. ${remove}`);
      if (holder.kind === "dead") {
        // The holder may have finished between the read of its PID and the check that it runs. An add removes its lock
        // before it exits, so a lock that a second look finds gone, or held by another process, was not left over:
        // the open is tried again.
        const again = lockHolder(file);
        if (again.kind !== "dead" || again.pid !== holder.pid) continue;
        throw new UsageError(`cannot add to baseline ${path}: its lock file ${file} is left over from process ${holder.pid}, which is no longer running; nothing was changed. ${remove}`);
      }
      if (Date.now() >= deadline) {
        const by = holder.pid !== undefined ? ` (process ${holder.pid})` : "";
        throw new UsageError(`cannot add to baseline ${path}: its lock file ${file} exists, so another baseline add${by} is writing it; retry when that one is done, or remove ${file} if none is running`);
      }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, LOCK_POLL_MS);
      continue;
    }
    try {
      writeSync(fd, `${process.pid}\n`);
    } finally {
      closeSync(fd);
    }
    return () => rmSync(file, { force: true });
  }
}

/**
 * Who holds the lock file at `file`, as far as can be told: a symlink or another non-regular file (which lock() never
 * makes), a process that is no longer running (the PID lock() writes, which kill(pid, 0) finds gone: ESRCH), or
 * possibly a running add ("live": a running PID, one this user may not signal, or no PID yet, as between another add's
 * open and its write).
 */
function lockHolder(file: string): { kind: "link" } | { kind: "other" } | { kind: "dead"; pid: number } | { kind: "live"; pid?: number } {
  let st: Stats | undefined;
  let text = "";
  try {
    st = lstatSync(file, { throwIfNoEntry: false });
    if (st?.isSymbolicLink()) return { kind: "link" };
    if (st !== undefined && !st.isFile()) return { kind: "other" };
    if (st !== undefined) {
      // At most what a PID takes, not through a link that replaced the file since the lstat.
      const fd = openSync(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      try {
        const buf = Buffer.alloc(16);
        text = buf.subarray(0, readSync(fd, buf)).toString("latin1");
      } finally {
        closeSync(fd);
      }
    }
  } catch {
    return { kind: "live" };
  }
  const m = /^([1-9]\d{0,9})\n?$/.exec(text);
  const pid = m ? Number(m[1]) : undefined;
  if (pid === undefined || pid > 0x7fffffff) return { kind: "live" };
  try {
    process.kill(pid, 0);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ESRCH") return { kind: "dead", pid };
  }
  return { kind: "live", pid };
}

/** `s` as one word for a POSIX shell. */
const shellQuote = (s: string): string => `'${s.replaceAll("'", "'\\''")}'`;

/** The most bytes of a --from report read. */
const MAX_REPORT_BYTES = 256 * 1024 * 1024;
/** How a finding's message gives the reason no entry approves it (src/python/soak.ts readerProblemFindings). */
const NO_ENTRY = "No baseline entry can approve this finding: ";

/**
 * Refuses a fingerprint that is not a finding of the report at `from`, or one whose finding no entry can approve
 * (notBaselinable, or a NOT_BASELINABLE rule): such an entry would suppress nothing (applyBaseline). The report is read
 * as a regular file under MAX_REPORT_BYTES, without waiting on a FIFO.
 */
function checkAgainstReport(fingerprints: string[], from: string): void {
  let text: string;
  let fd: number | undefined;
  try {
    fd = openSync(from, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
    const st = fstatSync(fd);
    if (!st.isFile()) throw new UsageError(`cannot read --from ${from}: it is not a regular file`);
    if (st.size > MAX_REPORT_BYTES) throw new UsageError(`cannot read --from ${from}: it is larger than ${MAX_REPORT_BYTES / 1024 / 1024} MiB`);
    text = readFileSync(fd, "utf8");
  } catch (e) {
    throw e instanceof UsageError ? e : new UsageError(`cannot read --from ${from}: ${(e as NodeJS.ErrnoException).code ?? (e as Error).message}`);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
  const notReport = new UsageError(`--from ${from} is not a report written by wormsign --format json`);
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    throw notReport;
  }
  const findings = (doc as { tool?: unknown; findings?: unknown } | null)?.findings;
  if ((doc as { tool?: unknown } | null)?.tool !== "wormsign" || !Array.isArray(findings)) throw notReport;
  for (const f of findings) {
    const x = f as { ruleId?: unknown; fingerprint?: unknown; message?: unknown } | null;
    if (typeof x?.ruleId !== "string" || typeof x.fingerprint !== "string" || typeof x.message !== "string") throw notReport;
  }
  const all = findings as { ruleId: string; fingerprint: string; message: string; notBaselinable?: unknown }[];
  for (const fp of fingerprints) {
    const mine = all.filter((f) => f.fingerprint === fp);
    if (mine.length === 0) throw new UsageError(`fingerprint ${fp} is not a finding in --from ${from}; nothing was added`);
    const refused = mine.find((f) => f.notBaselinable === true || NOT_BASELINABLE.has(f.ruleId));
    if (refused === undefined) continue;
    const at = refused.message.lastIndexOf(NO_ENTRY);
    const why = NOT_BASELINABLE.has(refused.ruleId) ? NOT_BASELINABLE_WHY : at === -1 ? "its message says why" : refused.message.slice(at + NO_ENTRY.length);
    throw new UsageError(`fingerprint ${fp} (${refused.ruleId}) is a finding no baseline entry can approve, so an entry would suppress nothing; nothing was added: ${why}`);
  }
}

/** addToBaseline's work, under the lock. */
function addLocked(path: string, req: AddRequest, ops: AddOps): AddResult {
  const st = lstatOf(path);
  let raw: { entries: unknown[] };
  if (st === undefined) {
    checkDirectory(path);
    raw = { version: 1, entries: [] } as { entries: unknown[] };
  } else {
    // lstat, not stat: a link there, dangling or not, is refused rather than followed or replaced by the rename.
    if (st.isSymbolicLink()) throw new UsageError(`refusing baseline ${path}: it is a symlink, which baseline add does not write through or replace`);
    // As every command reads it: a regular file (a directory, FIFO or device is refused), under the size cap, not
    // through a link that replaced the file since the lstat.
    const text = readBaselineText(path, { follow: false });
    // The rename would replace a file the user cannot write (a read-only 0444 baseline, say) all the same.
    if (!writable(path)) throw new UsageError(`refusing baseline ${path}: you cannot write it (mode 0${(st.mode & 0o777).toString(8).padStart(3, "0")}), and baseline add would replace it; make it writable first if the change is meant`);
    const current = parseBaseline(text, path);
    for (const fp of req.fingerprints) {
      const at = current.entries.findIndex((e) => e.fingerprint === fp);
      if (at !== -1) throw new UsageError(`${path}: fingerprint ${fp} is already in entries[${at}]; edit that entry to change its justification or expiry`);
    }
    // The file as written, not as validated: validation trims and normalises, and every field is kept as it is.
    raw = JSON.parse(text.replace(/^\uFEFF/, "")) as { entries: unknown[] };
  }
  const added: BaselineEntry[] = req.fingerprints.map((fingerprint) => ({ fingerprint, justification: req.reason.trim(), ...(req.expires !== undefined ? { expires: req.expires } : {}) }));
  raw.entries.push(...added);
  const text = `${JSON.stringify(raw, null, 2)}\n`;
  // Every command refuses a larger file, so writing one would break the next scan.
  if (Buffer.byteLength(text) > MAX_BASELINE_BYTES) throw new UsageError(`refusing to write baseline ${path}: it would be larger than ${MAX_BASELINE_BYTES / 1024 / 1024} MiB, which no command reads`);
  writeAtomically(path, text, st?.mode, ops);
  return { path, created: st === undefined, added };
}

/** True when the user may write the file at `path` (access(2), W_OK). */
function writable(path: string): boolean {
  try {
    accessSync(path, constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

/** Writes a temporary file beside `path` and renames it into place; on any failure the temporary file is removed. */
function writeAtomically(path: string, text: string, mode: number | undefined, ops: AddOps): void {
  const tmp = join(dirname(path), `.${basename(path)}.tmp-${process.pid}-${randomBytes(6).toString("hex")}`);
  let fd: number | undefined;
  let made = false;
  try {
    fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o644);
    made = true;
    // The new file keeps the old one's permissions, which the umask would otherwise decide.
    if (mode !== undefined) fchmodSync(fd, mode & 0o777);
    ops.write(fd, text);
    closeSync(fd);
    fd = undefined;
    ops.rename(tmp, path);
  } catch (e) {
    if (fd !== undefined) closeSync(fd);
    if (made) rmSync(tmp, { force: true });
    throw new UsageError(`cannot write baseline ${path}: ${(e as NodeJS.ErrnoException).code ?? (e as Error).message}; the file is unchanged`);
  }
}
