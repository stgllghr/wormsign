import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, readlinkSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, join, parse, posix, relative, resolve, sep } from "node:path";
import { BASELINE_FILE } from "./baseline.js";
import { findProgram } from "./exec.js";
import { MAX_TEXT_BYTES, walk } from "./fsutil.js";
import { UsageError } from "./types.js";

/** A read-only view of a project at one point: a directory on disk or a git revision. */
export interface Tree {
  label: string;
  list(): string[];
  read(path: string): string | undefined;
  /**
   * Undefined when `path` is absent or leads, by exact names, to one regular file this tree holds. Otherwise (a symlink
   * out of the tree, through a directory installs link into or a name it lacks, a name another entry holds in another
   * case or that is not valid UTF-8, a submodule or a directory) what an install reads there is not known, so the path is reported as not checked, and this returns a
   * stamp of the whole tree but its BASELINE_FILE: that path may lead to anything in it, so only the same content may
   * keep a baseline entry. The baseline file is left out because the entry lives there (an edit to it is a WS-DF-005
   * finding of its own). Absent (test trees): never.
   */
  unfollowed?(path: string): string | undefined;
  /** True when `path` is a regular file of this tree under exactly that name, with no symlink on the way. Absent (test trees): never asked. */
  regularFile?(path: string): boolean;
  /**
   * What git attributes `names` are for each of `paths` in this revision, as `git check-attr --source=<rev>` gives them
   * (the revision's .gitattributes files, above the tree's top too, then info/attributes and core.attributesFile):
   * path -> name -> "set", "unset", "unspecified" or the value. git 2.40 or later; throws when git cannot tell.
   * Absent (directory trees): never asked.
   */
  attributes?(paths: string[], names: string[]): Map<string, Map<string, string>>;
  /**
   * The bytes git stores for each of `paths` that is a blob in this revision (other objects, a submodule, are left out),
   * read in one `git cat-file --batch`; throws when one is missing (a partial clone) or they hold more than `maxTotal`
   * bytes in all. Absent (directory trees): never asked.
   */
  blobs?(paths: string[], maxTotal: number): Map<string, Buffer>;
  /**
   * What this tree holds under exactly `path` ("" or "." is the tree's top), no link followed: a regular file's bytes
   * as stored (never decoded), a symlink's target text, a directory with its entries' names (sorted); undefined when
   * absent (or under a symlink, which git cannot store). A problem when it cannot be told: a path another entry's name
   * folds like (a case-insensitive disk keeps one of the two), a submodule, a file over `maxBytes` (MAX_ENTRY_BYTES)
   * or a blob git cannot read. Each path is read once per `maxBytes` for the life of the tree, then answered from
   * memory (the same object again), while the files kept stay within MAX_CACHED_ENTRY_BYTES; one past it is read again.
   * Absent (directory trees): never asked.
   */
  entry?(path: string, maxBytes?: number): TreeEntry | undefined;
  /**
   * The object id of the regular file under exactly `path` (Tree.entry's "file"), so that diff can tell an unchanged
   * file without reading it; undefined for anything else. Absent (directory trees): files are read and compared.
   */
  blob?(path: string): string | undefined;
  /**
   * The directory on disk, for a directory tree (dirTree): diff reads a Python project's build files there as soak
   * reads them (src/python/build.ts fsBuildReader). Absent for a git tree, which has Tree.entry, and for test trees.
   */
  root?: string;
}

/** One entry of a tree under its exact path (Tree.entry). */
export type TreeEntry = { kind: "file"; bytes: Buffer } | { kind: "symlink"; target: string } | { kind: "dir"; names: string[] } | { kind: "problem"; why: string };

/** The largest file Tree.entry reads (a build file: pyproject.toml, setup.cfg, a hook, a backend-path file). */
export const MAX_ENTRY_BYTES = 64 * 1024 * 1024;
/**
 * Most bytes of file content git's Tree.entry keeps for the life of one tree. A file that would pass it is read again
 * each time it is asked for (the answer is the same), so a change of large build files cannot make diff hold every one
 * of them, on both revisions, at once: 19 hook neighbours of 50 MB peaked at 2.75 GB.
 */
export const MAX_CACHED_ENTRY_BYTES = 32 * 1024 * 1024;

export const DIR_PREFIX = "dir:";

/**
 * Binary files are read byte for byte (latin1), so a change in bytes that are not valid UTF-8 is still a change:
 * decoded as UTF-8, every invalid byte becomes the same U+FFFD.
 */
const encodingOf = (p: string): BufferEncoding => (p.endsWith(".lockb") ? "latin1" : "utf8");

const isLink = (p: string): boolean => {
  try {
    return lstatSync(p).isSymbolicLink();
  } catch {
    return false;
  }
};

/**
 * Files are read as the package manager reads them, through symlinks, so symlinks are listed too. Only a regular file
 * inside the root is followed: a FIFO or /dev/zero would hang the gate, and a file outside the root is not part of the
 * change. Anything else reads as the link's own text and is reported as not checked, as in gitTree.
 */
export function dirTree(root: string): Tree {
  const realRoot = realpathSync(root);
  /**
   * The real path when `p` leads to a regular file inside the root, null when it leads anywhere else, undefined when
   * it is absent. A link on the way that dangles or loops is null, not absent: before an install, a manifest linked
   * into node_modules dangles, and the install then makes what it reads.
   */
  const fileIn = (p: string): string | null | undefined => {
    try {
      const to = realpathSync(join(root, p));
      const rel = relative(realRoot, to);
      return !rel.startsWith(`..${sep}`) && !isAbsolute(rel) && statSync(to).isFile() ? to : null;
    } catch {
      const parts = p.split("/");
      return parts.some((_, i) => isLink(join(root, ...parts.slice(0, i + 1)))) ? null : undefined;
    }
  };
  const list = (): string[] => {
    const links: string[] = [];
    const files = [...walk(root, { includeNodeModules: false, onSymlink: (rel) => links.push(rel) })];
    return [...files, ...links];
  };
  const read = (p: string, encoding = encodingOf(p)): string | undefined => {
    const to = fileIn(p);
    try {
      return to ? readFileSync(to, encoding) : to === null ? readlinkSync(join(root, p)) : undefined;
    } catch {
      return undefined;
    }
  };
  // Every listed path but the baseline file with its bytes (latin1: byte for byte), so any other edit changes it.
  let stamp: string | undefined;
  const stampOf = (): string => {
    if (stamp === undefined) {
      const h = createHash("sha256");
      for (const p of list().sort()) if (p !== BASELINE_FILE) h.update(JSON.stringify([p, read(p, "latin1") ?? null]));
      stamp = h.digest("hex");
    }
    return stamp;
  };
  return {
    label: `${DIR_PREFIX}${root}`,
    root,
    list,
    read: (p) => read(p),
    unfollowed: (p) => (fileIn(p) === null ? stampOf() : undefined),
  };
}

/**
 * The form paths are matched in. macOS and Windows file systems are case-insensitive by default, so npm, pnpm and
 * yarn there read .NPMRC as .npmrc (checked with npm 10.9.2), and APFS also opens .pnpmfile.cjſ (long s) as
 * .pnpmfile.cjs, K (Kelvin sign) as k and ẞ or ß as ss. NFKC, then lower-, upper- and lower-casing merges every pair
 * of code points APFS merged in a probe of the whole BMP; the few it merges that a file system keeps apart only add
 * findings. Windows also drops trailing periods and spaces from a name (Microsoft, "File path formats on Windows
 * systems", Trim characters), so a file a commit names `package.json.` or `package-lock.json ` is package.json and
 * package-lock.json there: every "/"-separated segment loses its trailing periods and spaces too, unless it is made of
 * nothing else (`...` is a name on Windows). Stripping from every segment, not only where Windows does, only adds
 * matches.
 */
export const fold = (s: string): string =>
  s
    .normalize("NFKC")
    .toLowerCase()
    .toUpperCase()
    .toLowerCase()
    .split("/")
    .map((seg) => (/^[. ]*$/.test(seg) ? seg : seg.replace(/[. ]+$/, "")))
    .join("/");

/**
 * Settings every git call here runs with. A blob missing from a partial clone (`--filter=blob:none`) would otherwise
 * be fetched from the promisor remote on demand, over the network and with the repository's own transport settings
 * (core.sshCommand runs a program the repository's .git/config names): no lazy fetch (GIT_NO_LAZY_FETCH, git 2.44),
 * and every transport refused (protocol.allow=never) for older git, so a missing blob is an error, never a fetch.
 * No prompt for credentials, and no fsmonitor program. The walker's git calls (src/walk.ts gitRunner) use it too.
 */
export const NO_FETCH = { args: ["-c", "protocol.allow=never"], env: { GIT_NO_LAZY_FETCH: "1" } };

/** Past maxBuffer bytes of output, git is killed and this throws (ENOBUFS), so a cap bounds both time and memory. */
function git(cwd: string, args: string[], encoding: BufferEncoding = "utf8", maxBuffer = 256 * 1024 * 1024): string {
  return gitRun(cwd, args, encoding, maxBuffer) as string;
}

/** git's output as bytes, as git wrote them: a blob is never decoded. */
function gitBytes(cwd: string, args: string[], maxBuffer = 256 * 1024 * 1024): Buffer {
  return gitRun(cwd, args, "buffer", maxBuffer) as Buffer;
}

function gitRun(cwd: string, args: string[], encoding: BufferEncoding | "buffer", maxBuffer: number, input?: string): string | Buffer {
  // execFileSync with an argv array: refs are never interpreted by a shell. git runs in `cwd` through -C, started from
  // the filesystem root: spawned from the scanned tree, an empty PATH entry (or Windows, which searches the working
  // directory first) would run a `git` committed there. It is found on PATH by src/exec.ts and run by its absolute
  // path; a git inside the repository is never run (a usage error).
  const program = findProgram("git", process.env, [resolve(cwd)]);
  if ("refused" in program) throw new UsageError(program.refused);
  return execFileSync("path" in program ? program.path : "git", [...NO_FETCH.args, "-c", "core.fsmonitor=false", "-C", resolve(cwd), ...args], {
    cwd: parse(process.cwd()).root,
    encoding,
    maxBuffer,
    stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
    // As bytes: a string input would be encoded with `encoding`, which may be "buffer".
    ...(input === undefined ? {} : { input: Buffer.from(input, "utf8") }),
    env: { ...process.env, ...NO_FETCH.env, GIT_TERMINAL_PROMPT: "0" },
  });
}

/** The first line git wrote to stderr, else the error's code or message: why a read failed. */
function gitFailure(e: unknown): string {
  const err = e as { stderr?: Buffer | string; code?: string; message?: string };
  const first = String(err.stderr ?? "").split("\n").find((l) => l.trim() !== "");
  return (first ?? err.code ?? err.message ?? "unknown error").trim().slice(0, 300);
}

const SYMLINK = "120000";
const TREE = "040000";
/** Linux follows 40 symlinks in one path, macOS 32: a longer chain fails to open on both. */
const MAX_HOPS = 40;
/** What a path that cannot be followed to a file in the tree resolves to. */
const UNFOLLOWED = Symbol("unfollowed");

/**
 * Config that moves where installs make links, by folded file name: the key, and a line that sets it plainly. pnpm
 * 11.16.0 and 10.34.6 read modulesDir from pnpm-workspace.yaml, yarn 1.22.22 reads --modules-folder and
 * --install.modules-folder from .yarnrc, and pnpm 10.34.6 reads modules-dir from .npmrc in any case, with _ for -
 * (npm 10.9.2 and pnpm 11.16.0 ignore it, so there it only adds findings).
 */
const INSTALL_DIR_SETTINGS = new Map<string, [key: RegExp, line: RegExp]>([
  ["pnpm-workspace.yaml", [/modulesDir/, /^modulesDir[ \t]*:(.*)$/]],
  [".yarnrc", [/modules-folder/, /^"?--(?:install\.)?modules-folder"?[ \t](.*)$/]],
  [".npmrc", [/modules[-_]dir/i, /^modules-dir[ \t]*=(.*)$/]],
]);

/**
 * The folded name of each directory `text` makes installs link into, or null when it may name one in a way not read
 * here. Every line that holds the key, or a backslash (an escape can spell the key), must set it plainly to a path of
 * letters, digits and ._/-, quoted or not, that ends in a name: "." or ".." would make the project itself, or a
 * directory above it, the install's. The next line that is not blank must not be indented: a YAML plain scalar goes on
 * over blank lines into an indented one, so pnpm 11.16.0 reads "modulesDir: mods\n\n  x" as "mods\nx".
 */
function installDirsIn(text: string, [key, setting]: [RegExp, RegExp]): string[] | null {
  const out: string[] = [];
  const lines = text.split(/\r?\n/);
  for (const [i, line] of lines.entries()) {
    if (!key.test(line) && !line.includes("\\")) continue;
    const value = /^(["']?)([\w./-]+)\1$/.exec(setting.exec(line)?.[1]?.trim() ?? "")?.[2];
    const name = value === undefined ? "" : posix.basename(posix.normalize(value));
    // By index, not lines.slice(i + 1): a copy of the rest of the file per line made a file of such lines quadratic.
    let j = i + 1;
    while (j < lines.length && !/\S/.test(lines[j] as string)) j++;
    const next = lines[j] ?? "";
    if (name === "" || name === "." || name === ".." || /^\s/.test(next)) return null;
    out.push(fold(name));
  }
  return out;
}

/**
 * The tree of commit `rev`, seen from `repo`, which may be a subdirectory of the repository: paths are
 * listed relative to it and read back with "./", which git resolves from the working directory, not the root.
 */
export function gitTree(repo: string, rev: string): Tree {
  let sha: string;
  try {
    // --end-of-options: a revision such as "--output=x" is never read as an option.
    sha = git(repo, ["rev-parse", "--verify", "--quiet", "--end-of-options", `${rev}^{commit}`]).trim();
  } catch (e) {
    if (e instanceof UsageError) throw e;
    throw new UsageError(`cannot resolve "${rev}" as a git revision in ${repo}`);
  }
  // path -> mode, and path -> object id, from lines of "<mode> <type> <object>\t<path>". -t lists directories too, for
  // resolving links.
  let modes: Map<string, string> | undefined;
  const oids = new Map<string, string>();
  const ls = (): Map<string, string> => {
    if (modes === undefined) {
      modes = new Map();
      for (const l of git(repo, ["ls-tree", "-r", "-t", "-z", sha]).split("\0")) {
        if (l === "") continue;
        const [mode, , oid] = l.slice(0, l.indexOf("\t")).split(" ");
        const p = l.slice(l.indexOf("\t") + 1);
        modes.set(p, mode as string);
        oids.set(p, oid as string);
      }
    }
    return modes;
  };
  // Every entry of this tree with its mode and object id, but the baseline file, so any other edit changes it.
  let stamp: string | undefined;
  const stampOf = (): string => {
    if (stamp === undefined) {
      const entries = git(repo, ["ls-tree", "-r", "-z", sha]).split("\0").filter((l) => l.slice(l.indexOf("\t") + 1) !== BASELINE_FILE);
      stamp = createHash("sha256").update(entries.join("\0")).digest("hex");
    }
    return stamp;
  };
  // Memoised: a hostile change can point many manifests into one long chain of links, which is then fetched once.
  // A link's target is a name, decoded as names are, even when the link is named like a binary lockfile.
  // Only paths this tree lists are shown, so a failure is never an absent file: a blob a partial clone lacks, or one
  // larger than the cap. Read as absent, a change to it would compare equal on both sides and pass unseen; it stops
  // the run instead (exit 2).
  const shown = new Map<string, string>();
  const show = (p: string): string => {
    let text = shown.get(p);
    if (text === undefined) {
      try {
        text = git(repo, ["show", `${sha}:./${p}`], ls().get(p) === SYMLINK ? "utf8" : encodingOf(p));
      } catch (e) {
        if (e instanceof UsageError) throw e;
        throw new UsageError(`git could not read ${p} at ${rev} (${sha.slice(0, 12)}): ${gitFailure(e)}. A partial or shallow clone may lack it: check out with a full clone (no --filter, fetch-depth 0 or enough history)`);
      }
      shown.set(p, text);
    }
    return text;
  };
  // How many entries share each folded path. A case-insensitive disk opens SUB as sub, and a checkout keeps only one
  // of two entries that differ in case (git 2.50 on APFS), so a path that folds like another entry is not knowable.
  // The names directly in each directory of this tree ("" for the top), sorted: Tree.entry's directory listing.
  let children: Map<string, string[]> | undefined;
  const childrenOf = (dir: string): string[] => {
    if (children === undefined) {
      children = new Map();
      for (const p of ls().keys()) {
        const at = p.lastIndexOf("/");
        const parent = at === -1 ? "" : p.slice(0, at);
        const list = children.get(parent);
        if (list === undefined) children.set(parent, [p.slice(at + 1)]);
        else list.push(p.slice(at + 1));
      }
      for (const list of children.values()) list.sort();
    }
    return children.get(dir) ?? [];
  };
  let folds: Map<string, number> | undefined;
  const clashes = (p: string): boolean => {
    if (folds === undefined) {
      folds = new Map();
      for (const q of ls().keys()) folds.set(fold(q), (folds.get(fold(q)) ?? 0) + 1);
    }
    return (folds.get(fold(p)) ?? 0) > (ls().has(p) ? 1 : 0);
  };
  // Folded names of the directories installs link into, from every config file in the tree, or null when one may name
  // a directory not read here (or is a link or submodule, which may hold anything): then every path is unfollowed, and
  // read() follows no link but still reads a regular file outside node_modules, so a base config keeps its content.
  // Config files under node_modules are skipped: no install reads them, and a name taken from one could hide a regular
  // file from read() on one side of a diff without any change being reported. A config file is read up to the scan's
  // text cap and no further: a larger one counts as unreadable, so the change under review cannot choose how long
  // this takes, and it fails closed.
  const config = (p: string): string | undefined => {
    try {
      return git(repo, ["show", `${sha}:./${p}`], "utf8", MAX_TEXT_BYTES);
    } catch {
      return undefined;
    }
  };
  let installDirs: Set<string> | null | undefined;
  const owned = (): Set<string> | null => {
    if (installDirs === undefined) {
      installDirs = new Set(["node_modules"]);
      for (const [p, mode] of ls()) {
        const setting = INSTALL_DIR_SETTINGS.get(fold(posix.basename(p)));
        // Installs read no project config from inside node_modules, and list() never reports a change there.
        if (setting === undefined || mode === TREE || fold(p).split("/").includes("node_modules")) continue;
        const text = mode.startsWith("100") ? config(p) : undefined;
        const names = text === undefined ? null : installDirsIn(text, setting);
        if (names === null) return (installDirs = null);
        for (const n of names) installDirs.add(n);
      }
    }
    return installDirs;
  };
  // git stores a symlink as a blob holding its target. The package manager reads through it, so a change to the
  // target, or to a symlinked directory on the way, is a change to the link. The path is walked as the OS walks it:
  // one name at a time, replacing each symlink with its target, so ".." climbs from where a link really points.
  // A link is followed only when every name on the walk is an entry of this tree under exactly that name, no other
  // entry folds alike, no name is a directory installs link into, and the walk ends at a regular file. Anything else
  // depends on the disk, not the commit: .git is made by the clone, node_modules (or the directory pnpm's modulesDir or
  // modules-dir or yarn's --modules-folder names) belongs to the install even when tracked (npm 10.9.2 deletes a tracked
  // node_modules/w, pnpm 11.16.0 moves a tracked mods/w aside, and each links the workspace there), any untracked name
  // may be a link an install made, a submodule holds another repository, and a target outside the tree is not in the
  // change. A name that is not valid UTF-8 is read back here as U+FFFD, which names no entry to git and does not tell
  // two such names apart, so it cannot be followed byte for byte. Those paths are UNFOLLOWED and reported as not
  // checked. A path that names no entry, with no link on the way, is simply absent.
  const resolveLinks = (path: string): string | undefined | typeof UNFOLLOWED => {
    const dirs = owned() ?? new Set(["node_modules"]);
    const at: string[] = [];
    const todo = path.split("/").reverse();
    for (let hops = 0; todo.length > 0; ) {
      const name = todo.pop() as string;
      if (name === "" || name === ".") continue;
      const missing = hops > 0 ? UNFOLLOWED : undefined;
      if (name === "..") {
        if (at.pop() === undefined) return missing;
        continue;
      }
      at.push(name);
      const real = at.join("/");
      if (name.includes("\ufffd") || dirs.has(fold(name)) || clashes(real)) return UNFOLLOWED;
      const mode = ls().get(real);
      if (mode === undefined) return missing;
      if (mode === SYMLINK) {
        if (owned() === null) return UNFOLLOWED;
        const target = show(real);
        // No OS creates a link with a longer target (Linux: 4095 bytes, macOS: 1023), so it cannot be checked out.
        if (++hops > MAX_HOPS || target === undefined || target.length > 4095 || posix.isAbsolute(target)) return UNFOLLOWED;
        at.pop();
        todo.push(...target.split("/").reverse());
      } else if (mode !== TREE && todo.length > 0) return UNFOLLOWED; // ENOTDIR, or into a submodule
    }
    return ls().get(at.join("/"))?.startsWith("100") ? at.join("/") : UNFOLLOWED;
  };
  // Tree.entry of exactly `p` (normalised), read once per path and size cap for the life of this tree. A Python build
  // asks for the same entries many times (pyproject.toml for each question asked of it, the .py files beside each hook
  // in one directory), and each blob read is a `git show`: uncached, a 2 KB pyproject.toml naming one hook 25 ways
  // made diff run for minutes. Files are kept up to MAX_CACHED_ENTRY_BYTES in all; past it a file is read again.
  const entries = new Map<string, TreeEntry | undefined>();
  let cachedBytes = 0;
  const entryOf = (p: string, maxBytes: number): TreeEntry | undefined => {
    if (p === "" || p === ".") return { kind: "dir", names: childrenOf("") };
    if (clashes(p)) return { kind: "problem", why: "another entry's name folds like this one" };
    const mode = ls().get(p);
    if (mode === undefined) return undefined;
    if (mode === TREE) return { kind: "dir", names: childrenOf(p) };
    try {
      if (mode === SYMLINK) return { kind: "symlink", target: show(p) };
      if (!mode.startsWith("100")) return { kind: "problem", why: "not a regular file" };
      return { kind: "file", bytes: gitBytes(repo, ["show", `${sha}:./${p}`], maxBytes) };
    } catch (e) {
      // ENOBUFS: git wrote more than maxBytes and was killed. Anything else: a blob git cannot read here.
      return { kind: "problem", why: (e as NodeJS.ErrnoException).code === "ENOBUFS" ? `larger than ${maxBytes} bytes` : "unreadable" };
    }
  };
  return {
    label: `${rev} (${sha.slice(0, 12)})`,
    list: () => [...ls()].filter(([p, m]) => m !== TREE && !p.split("/").includes("node_modules")).map(([p]) => p),
    read: (path) => {
      const p = posix.normalize(path);
      const real = resolveLinks(p);
      if (typeof real === "string") return show(real);
      // A link that cannot be followed reads as its own text, which no manifest, lockfile or config parses.
      return ls().get(p) === SYMLINK ? show(p) : undefined;
    },
    unfollowed: (path) => (owned() === null || resolveLinks(posix.normalize(path)) === UNFOLLOWED ? stampOf() : undefined),
    // An entry is listed under its full path, so one with a file mode has no symlink above it (git cannot store both).
    regularFile: (path) => ls().get(posix.normalize(path).replace(/^\.\//, ""))?.startsWith("100") === true,
    attributes: (paths, names) => {
      const out = new Map<string, Map<string, string>>();
      if (paths.length === 0) return out;
      try {
        // check-attr reads a .gitattributes whose blob a partial clone lacks as no attributes at all, which would let a
        // converting attribute pass unseen: every .gitattributes in this revision, above the tree's top too, must be
        // here (as show() refuses a blob it cannot read). No lazy fetch: NO_FETCH.
        const attrs = git(repo, ["ls-tree", "-r", "-z", "--full-tree", sha])
          .split("\0")
          .filter((l) => l !== "" && posix.basename(l.slice(l.indexOf("\t") + 1)) === ".gitattributes")
          .map((l) => ({ path: l.slice(l.indexOf("\t") + 1), oid: l.slice(0, l.indexOf("\t")).split(" ")[2] as string }));
        if (attrs.length > 0) {
          const check = (gitRun(repo, ["cat-file", "--batch-check"], "utf8", 64 * 1024 * 1024, `${attrs.map((a) => a.oid).join("\n")}\n`) as string).split("\n");
          const gone = attrs.filter((_, i) => !/^[0-9a-f]+ blob \d+$/.test(check[i] ?? ""));
          if (gone.length > 0) throw new Error(`${gone[0]!.path} at ${rev} is not in this clone (a partial clone lacks its blob), so its attributes are unknown`);
        }
        // -z and --stdin: any path, one argument list; --source reads the attributes of this revision, not the checkout's.
        const fields = (gitRun(repo, ["check-attr", "-z", "--stdin", `--source=${sha}`, ...names], "utf8", 64 * 1024 * 1024, `${paths.join("\0")}\0`) as string).split("\0");
        for (let i = 0; i + 2 < fields.length; i += 3) {
          const [path, name, value] = [fields[i] as string, fields[i + 1] as string, fields[i + 2] as string];
          let m = out.get(path);
          if (m === undefined) out.set(path, (m = new Map()));
          m.set(name, value);
        }
        return out;
      } catch (e) {
        // git's own first line (an unknown option, a missing object), not execFileSync's "Command failed".
        throw new Error(gitFailure(e), { cause: e });
      }
    },
    blobs: (paths, maxTotal) => {
      const out = new Map<string, Buffer>();
      if (paths.length === 0) return out;
      try {
        if (paths.some((p) => p.includes("\n"))) throw new Error("a path holds a line break, which git cat-file --batch cannot take");
        // Sizes first, so that what is read is bounded before it is read; then the blobs, each once.
        const check = (gitRun(repo, ["cat-file", "--batch-check"], "utf8", 64 * 1024 * 1024, `${paths.map((p) => `${sha}:./${p}`).join("\n")}\n`) as string).split("\n");
        const byOid = new Map<string, string[]>();
        let total = 0;
        paths.forEach((p, i) => {
          const m = /^([0-9a-f]+) (\S+) (\d+)$/.exec(check[i] ?? "");
          if (m === null) throw new Error(`${p} at ${rev} is not in this clone (a partial clone lacks its blob)`);
          if (m[2] !== "blob") return;
          if (!byOid.has(m[1]!)) total += Number(m[3]);
          byOid.set(m[1]!, [...(byOid.get(m[1]!) ?? []), p]);
        });
        if (total > maxTotal) throw new Error(`they hold ${total} bytes, more than the ${maxTotal} read`);
        if (byOid.size === 0) return out;
        const oidList = [...byOid.keys()];
        const buf = gitRun(repo, ["cat-file", "--batch"], "buffer", total + 128 * oidList.length + 1024, `${oidList.join("\n")}\n`) as Buffer;
        let at = 0;
        for (const oid of oidList) {
          const nl = buf.indexOf(0x0a, at);
          const m = /^([0-9a-f]+) blob (\d+)$/.exec(buf.subarray(at, nl).toString("latin1"));
          if (nl === -1 || m === null || m[1] !== oid) throw new Error(`git cat-file --batch answered out of order for ${oid}`);
          const size = Number(m[2]);
          const bytes = Buffer.from(buf.subarray(nl + 1, nl + 1 + size));
          for (const p of byOid.get(oid)!) out.set(p, bytes);
          at = nl + 1 + size + 1;
        }
        return out;
      } catch (e) {
        throw new Error(gitFailure(e), { cause: e });
      }
    },
    blob: (path) => {
      const p = posix.normalize(path).replace(/^\.\//, "");
      // Exactly what entry() reads as a file: a regular file whose name no other entry folds like.
      return ls().get(p)?.startsWith("100") === true && !clashes(p) ? oids.get(p) : undefined;
    },
    entry: (path, maxBytes = MAX_ENTRY_BYTES) => {
      const p = posix.normalize(path).replace(/^\.\//, "").replace(/\/+$/, "");
      const key = `${maxBytes}\0${p}`;
      if (entries.has(key)) return entries.get(key);
      const e = entryOf(p, maxBytes);
      const size = e?.kind === "file" ? e.bytes.length : 0;
      if (cachedBytes + size <= MAX_CACHED_ENTRY_BYTES) {
        entries.set(key, e);
        cachedBytes += size;
      }
      return e;
    },
  };
}

/** The top-level directory of the git repository containing `dir`. */
export function gitRoot(dir: string): string {
  try {
    return git(dir, ["rev-parse", "--show-toplevel"]).trim();
  } catch (e) {
    if (e instanceof UsageError) throw e;
    throw new UsageError(`not inside a git repository: ${dir}`);
  }
}

/**
 * The directory `skills --project` writes under: the top-level directory of the git repository containing `dir`, but
 * only when that directory holds `dir` (both compared as real paths). A repository's core.worktree, or GIT_WORK_TREE,
 * makes git name any directory as the top level, and the skill would then be written outside the project the command
 * runs in.
 */
export function projectRoot(dir: string): string {
  const root = gitRoot(dir);
  const real = (p: string): string => {
    try {
      return realpathSync(p);
    } catch {
      return resolve(p);
    }
  };
  const rel = relative(real(root), real(dir));
  if (isAbsolute(rel) || rel.split(sep)[0] === "..") {
    throw new UsageError(`git names ${root} as the work tree of the repository at ${dir}, which does not hold ${dir} (core.worktree or GIT_WORK_TREE points elsewhere), so --project would write outside this project; run it from inside the work tree`);
  }
  return root;
}

/**
 * `dir:<path>` is a directory; anything else is a git revision of `repo`. Never guessed from what exists on
 * disk: a change that adds a directory named "HEAD" or "origin/main" must not replace the revision it names.
 */
export function resolveTree(arg: string, repo: string): Tree {
  if (!arg.startsWith(DIR_PREFIX)) {
    try {
      return gitTree(repo, arg);
    } catch (e) {
      // Only here: soak --base takes a revision alone, so the hint would mislead there.
      throw existsSync(arg) ? new UsageError(`${(e as Error).message} (to compare a directory, write ${DIR_PREFIX}${arg})`) : e;
    }
  }
  const dir = resolve(arg.slice(DIR_PREFIX.length));
  if (!existsSync(dir) || !statSync(dir).isDirectory()) throw new UsageError(`not a directory: ${dir}`);
  return dirTree(dir);
}
