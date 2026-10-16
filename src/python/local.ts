/**
 * Local sources a Python lock names: is the code an install would use the code under review?
 *
 * A local source tree (uv `directory`, `editable` or `virtual`; pylock `directory`) counts as local, and is not
 * age-checked, only when all of these hold (docs/soak.md, "Sources"; the git rule is src/walk.ts gitStateOf's):
 * - its path is relative, normalised (no "..", ".", empty segment or backslash), inside the root, with no symlink on
 *   the way, and no symlink under it resolves outside the root (src/python/paths.ts walks it, capped);
 * - the directory exists and holds a pyproject.toml or a setup.py;
 * - its files are tracked by git, per the git rule the caller gives:
 *   - a set of tracked paths (the root is in a git work tree and `git ls-files` succeeded): every file must be in it,
 *     except that the walk skips the untracked paths git ignores (`gitIgnored`, when the caller lists them);
 *   - "no-work-tree": the tracked check is skipped (the caller says so in a note);
 *   - "git-error": git is present but failed, so nothing can count as reviewed: a problem.
 *
 * A uv `virtual` source is a project uv neither builds nor installs (only its dependencies are installed), so nothing
 * under it runs at install time: it must meet the path rules and hold a pyproject.toml or setup.py that is itself a
 * tracked regular file (checkVirtualProject), but the directory is not walked. Walking it would gain nothing and would
 * fail every repository whose root project is virtual (the usual case for an application) as soon as it holds a
 * .venv (bin/python links outside the root), any untracked file, or more entries than the walk visits.
 *
 * A path archive (uv `path`; a pylock archive, sdist or wheel given by `path`) must meet the same path and git rules
 * as a regular file, and the sha256 of the file at that path must EQUAL the sha256 the lock records; a
 * missing or unreadable file is a problem. soak then binds that sha256 on the index by the file name's project and
 * version, as for any other locked file.
 *
 * Nothing here throws; every reason is returned as a problem.
 */
import { createHash } from "node:crypto";
import { lstatSync, readSync } from "node:fs";
import { withRegularFile } from "../fsutil.js";
import { dirname, join, posix } from "node:path";
import { checkLocalPath, type LocalPathOptions } from "./paths.js";

/** The git rule: the tracked files (relative to the root, "/"-separated), or why there are none. */
export type GitTracking = ReadonlySet<string> | "no-work-tree" | "git-error";

export interface LocalOptions {
  /** Absolute path of the scanned root. */
  root: string;
  git: GitTracking;
  /** What git said when it failed, for the message. */
  gitError?: string;
  /**
   * With a tracked set: the untracked paths git ignores (`git ls-files -z --others --ignored --exclude-standard
   * --directory` at the root; a directory with a trailing "/"), which a directory walk skips (src/python/paths.ts).
   */
  gitIgnored?: ReadonlySet<string>;
  /** Passed to paths.ts: most entries a directory walk visits. */
  maxEntries?: number;
}

/** `untracked`: the only reason is files git does not track (src/python/paths.ts). */
export type LocalCheck = { ok: true; rel: string; abs: string } | { ok: false; problem: string; untracked?: true };

/** The largest path archive hashed. */
export const MAX_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024;

function pathOptions(base: string, opts: LocalOptions): LocalPathOptions | { problem: string } {
  if (opts.git === "git-error") return { problem: `git failed${opts.gitError ? ` (${opts.gitError})` : ""}, so whether it is tracked, and so part of the reviewed tree, is unknown` };
  const o: LocalPathOptions = { root: opts.root, base };
  if (opts.git !== "no-work-tree") {
    o.tracked = opts.git;
    if (opts.gitIgnored !== undefined) o.ignored = opts.gitIgnored;
  }
  if (opts.maxEntries !== undefined) o.maxEntries = opts.maxEntries;
  return o;
}

/**
 * A local source tree named by a lock in directory `base` ("" for the root). ok only when it is local by every rule
 * above; otherwise the reason, which soak reports as "local source not present in the reviewed tree".
 */
export function checkLocalDirectory(raw: string, base: string, opts: LocalOptions): LocalCheck {
  const o = pathOptions(base, opts);
  if ("problem" in o) return { ok: false, problem: `${JSON.stringify(raw)}: ${o.problem}` };
  const check = checkLocalPath(raw, "directory", o);
  if (!check.ok) return check;
  const has = (f: string): boolean => {
    try {
      return lstatSync(join(check.abs, f)).isFile();
    } catch {
      return false;
    }
  };
  if (!has("pyproject.toml") && !has("setup.py")) return { ok: false, problem: `${JSON.stringify(raw)}: holds no pyproject.toml or setup.py, so it is not a Python project` };
  return check;
}

/** A path as written in a lock: relative, "/"-separated and normalised ("." for the lock's own directory). */
function normalisedRelative(raw: string): boolean {
  if (raw === ".") return true;
  if (raw === "" || raw.includes("\\") || raw.includes("\0") || raw.startsWith("/") || /^[A-Za-z]:/.test(raw) || /^[a-z][a-z0-9+.-]*:/i.test(raw)) return false;
  return posix.normalize(raw) === raw && !raw.endsWith("/") && !raw.split("/").some((seg) => seg === "" || seg === "." || seg === "..");
}

/**
 * A uv `virtual` source named by a lock in directory `base`: a path by the rules above whose pyproject.toml or setup.py
 * is a regular, tracked (per the git rule) file in the reviewed tree. The directory is not walked (see above).
 */
export function checkVirtualProject(raw: string, base: string, opts: LocalOptions): LocalCheck {
  const o = pathOptions(base, opts);
  if ("problem" in o) return { ok: false, problem: `${JSON.stringify(raw)}: ${o.problem}` };
  if (!normalisedRelative(raw)) return { ok: false, problem: `${JSON.stringify(raw)}: not a relative, normalised path inside the scanned root` };
  let first: { problem: string; untracked?: true } | undefined;
  for (const name of ["pyproject.toml", "setup.py"]) {
    const check = checkLocalPath(raw === "." ? name : `${raw}/${name}`, "file", o);
    if (check.ok) return { ok: true, rel: posix.dirname(check.rel) === "." ? "" : posix.dirname(check.rel), abs: dirname(check.abs) };
    first ??= check;
  }
  return { ok: false, problem: `${JSON.stringify(raw)}: no pyproject.toml or setup.py in the reviewed tree (${first?.problem ?? "none"})`, ...(first?.untracked ? { untracked: true as const } : {}) };
}

/** The sha256 of a regular file, read without following a final symlink, or why it could not be read. */
export function sha256File(path: string, max: number = MAX_ARCHIVE_BYTES): { sha256: string } | { problem: string } {
  return withRegularFile(path, max, (fd) => {
    const hash = createHash("sha256");
    const buf = Buffer.alloc(1024 * 1024);
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n === 0) break;
      hash.update(buf.subarray(0, n));
    }
    return { sha256: hash.digest("hex") };
  });
}

/**
 * A path archive named by a lock in directory `base`: the path rules above for a regular file, then its sha256 must be
 * the lock's. ok with the file's location; otherwise the reason.
 */
export function checkLocalArchive(raw: string, lockedSha256: string, base: string, opts: LocalOptions): LocalCheck {
  const o = pathOptions(base, opts);
  if ("problem" in o) return { ok: false, problem: `${JSON.stringify(raw)}: ${o.problem}` };
  const check = checkLocalPath(raw, "file", o);
  // An archive is not a project: soak keeps every reason here high, so `untracked` is not passed on.
  if (!check.ok) return { ok: false, problem: check.problem };
  const read = sha256File(check.abs);
  if ("problem" in read) return { ok: false, problem: `${JSON.stringify(raw)}: ${read.problem}` };
  if (read.sha256 !== lockedSha256.toLowerCase()) return { ok: false, problem: `${JSON.stringify(raw)}: the file's sha256 is ${read.sha256}, not the ${lockedSha256} the lock records, so the install would not use the file the lock names` };
  return check;
}
