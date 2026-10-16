/**
 * Local paths a Python lockfile names (a uv path archive or directory/editable member, a pylock archive or directory):
 * is the path inside the reviewed tree, as reviewed?
 *
 * checkLocalPath accepts a path only when all of these hold, and otherwise returns the first reason it does not:
 * - it is relative, in "/" form, and already normalised: no "", "." or ".." segment (except a whole path of "."),
 *   no backslash, no URL scheme, no drive letter;
 * - joined to the lock's directory, it stays inside the root;
 * - it exists and is the kind expected (a regular file, or a directory);
 * - no path component from the root down is a symlink, and the real path is inside the root's real path;
 * - for a directory: walking it (never following links, at most maxEntries entries; more is a problem, not a pass), no
 *   symlink under it resolves outside the root, and none dangles;
 * - when `tracked` is given (the root's `git ls-files` output, "/"-separated paths relative to the root): the file, or
 *   every regular file under the directory, is tracked; when that is the only reason, the result says so
 *   (`untracked`). The baseline file at the root (.wormsign-baseline.json) is wormsign's own and never counts.
 * The caller decides what an absent `tracked` means (no git work tree: skipped with a note; git failing: a problem).
 * With `tracked`, the walk skips what `ignored` lists (untracked paths git ignores, such as .venv/ or __pycache__/): a
 * checkout has none of them, so they come from tools run in the tree, not from the commits under review, and a local
 * .venv or test run would otherwise fail every project. Only a listed path is skipped: a missing list skips nothing.
 */
import { lstatSync, readdirSync, realpathSync, type Stats } from "node:fs";
import { isAbsolute, join, posix, relative, sep } from "node:path";
import { BASELINE_FILE } from "../baseline.js";

export interface LocalPathOptions {
  /** Absolute path of the scanned root. */
  root: string;
  /** Directory of the lockfile, "/"-separated and relative to root ("" for the root itself). */
  base: string;
  /** The tracked files ("/"-separated, relative to root), when git is available. */
  tracked?: ReadonlySet<string>;
  /** Most entries a directory walk visits before it gives up (a problem). Default 20,000. */
  maxEntries?: number;
  /**
   * Untracked paths git ignores, "/"-separated and relative to root, a directory with a trailing "/", as
   * `git ls-files -z --others --ignored --exclude-standard --directory` run at the root lists them. Used only with
   * `tracked`: the walk neither counts, enters nor checks them.
   */
  ignored?: ReadonlySet<string>;
}

/** `untracked`: the only reason is files git does not track (see above). */
export type LocalPathCheck = { ok: true; rel: string; abs: string } | { ok: false; problem: string; untracked?: true };

const DEFAULT_MAX_ENTRIES = 20_000;

/** child is parent or below it (both absolute, real paths). */
const inside = (parent: string, child: string): boolean => {
  const r = relative(parent, child);
  return r === "" || (r !== ".." && !r.startsWith(`..${sep}`) && !isAbsolute(r));
};

/** Checks a local path from a lockfile; `expect` is what the lock says it is. */
export function checkLocalPath(raw: string, expect: "file" | "directory", opts: LocalPathOptions): LocalPathCheck {
  const no = (problem: string): LocalPathCheck => ({ ok: false, problem: `${JSON.stringify(raw)}: ${problem}` });
  const untracked = (problem: string): LocalPathCheck => ({ ok: false, problem: `${JSON.stringify(raw)}: ${problem}`, untracked: true });
  if (raw === "" || raw.includes("\\") || raw.includes("\0")) return no("not a relative path in / form");
  if (posix.isAbsolute(raw) || /^[A-Za-z]:/.test(raw) || /^[a-z][a-z0-9+.-]*:/i.test(raw)) return no("not a relative path");
  if (raw !== "." && (posix.normalize(raw) !== raw || raw.endsWith("/") || raw.split("/").some((s) => s === "." || s === ".." || s === ""))) {
    return no("not a normalised path (it has an empty, \".\" or \"..\" segment)");
  }
  const rel = posix.normalize(posix.join(opts.base || ".", raw));
  if (rel === ".." || rel.startsWith("../") || posix.isAbsolute(rel)) return no("outside the scanned root");
  const relPath = rel === "." ? "" : rel;

  // Every component from the root down: no symlink, and the last one is the expected kind.
  let st: Stats | undefined;
  let walked = opts.root;
  for (const part of relPath === "" ? [] : relPath.split("/")) {
    walked = join(walked, part);
    try {
      st = lstatSync(walked);
    } catch (e) {
      return no(`not present in the scanned tree (${(e as NodeJS.ErrnoException).code ?? "error"})`);
    }
    if (st.isSymbolicLink()) return no(`a symlink (${relative(opts.root, walked).split(sep).join("/")}) is on the path`);
  }
  if (relPath === "") {
    try {
      st = lstatSync(opts.root);
    } catch (e) {
      return no(`the scanned root could not be read (${(e as NodeJS.ErrnoException).code ?? "error"})`);
    }
  }
  const abs = walked;
  if (expect === "file" ? !st!.isFile() : !st!.isDirectory()) return no(`not a ${expect === "file" ? "regular file" : "directory"}`);
  let realRoot: string;
  try {
    realRoot = realpathSync(opts.root);
    if (!inside(realRoot, realpathSync(abs))) return no("resolves outside the scanned root");
  } catch (e) {
    return no(`could not be resolved (${(e as NodeJS.ErrnoException).code ?? "error"})`);
  }

  if (expect === "file") {
    if (opts.tracked && !opts.tracked.has(relPath)) return untracked("not tracked by git, so it is not part of the reviewed tree");
    return { ok: true, rel: relPath, abs };
  }

  // A directory: walk it without following links.
  const max = opts.maxEntries ?? DEFAULT_MAX_ENTRIES;
  let seen = 0;
  const unlisted: string[] = [];
  const stack = [abs];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let names: string[];
    try {
      names = readdirSync(dir).sort();
    } catch (e) {
      return no(`${relative(opts.root, dir).split(sep).join("/") || "."} could not be read (${(e as NodeJS.ErrnoException).code ?? "error"})`);
    }
    for (const name of names) {
      const full = join(dir, name);
      const r = relative(opts.root, full).split(sep).join("/");
      if (opts.tracked && opts.ignored && !opts.tracked.has(r) && (opts.ignored.has(r) || opts.ignored.has(`${r}/`))) continue;
      if (++seen > max) return no(`holds more than ${max} entries, more than this check walks`);
      let s: Stats;
      try {
        s = lstatSync(full);
      } catch (e) {
        return no(`${r} could not be read (${(e as NodeJS.ErrnoException).code ?? "error"})`);
      }
      if (s.isSymbolicLink()) {
        let target: string;
        try {
          target = realpathSync(full);
        } catch {
          return no(`the symlink ${r} does not resolve`);
        }
        if (!inside(realRoot, target)) return no(`the symlink ${r} resolves outside the scanned root`);
        if (opts.tracked && !opts.tracked.has(r)) unlisted.push(r);
      } else if (s.isDirectory()) {
        if (name !== ".git") stack.push(full);
      } else if (opts.tracked && !opts.tracked.has(r) && r !== BASELINE_FILE) {
        unlisted.push(r);
      }
    }
  }
  if (unlisted.length > 0) {
    const shown = unlisted.sort().slice(0, 5).join(", ");
    return untracked(`holds ${unlisted.length} file(s) not tracked by git (${shown}${unlisted.length > 5 ? ", ..." : ""}), which are not part of the reviewed tree`);
  }
  return { ok: true, rel: relPath, abs };
}
