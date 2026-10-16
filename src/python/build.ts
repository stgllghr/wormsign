/**
 * WS-SK-005 (medium): code resolved at install time, outside the lockfile. A lock pins the packages it lists, but
 * building a package from source first installs its build requirements, and no lock format soak reads pins those: the
 * installer resolves them fresh (protected only by its own release-age cutoff and by ==-pinned build constraints).
 * soak cannot see whether a wheel matches CI's platform, so it reports only the builds it can see from the locks
 * (docs/soak.md, "Builds: WS-SK-005"):
 * - local projects the install builds: uv `directory`/`editable` members (uv records a project it does not build as
 *   `virtual`) and pylock `directory` entries. Keyed on a digest of the build files (readLocalBuild), each whole unless
 *   a part is listed as known not to decide the build; not what a hook or setup.py reads or imports when it runs, nor a
 *   hook outside the project's directory. A project without [build-system] is built with the default setuptools
 *   backend. These keys are file-level: checked on every run, PR mode or not.
 * - packages locked only as sdists: every file the lock pins for it is an sdist (a uv.lock or pylock entry with an
 *   sdist and no wheel, a path archive that is an sdist, a requirements entry whose hashes all bind to sdists). Keyed
 *   `pypi:<name>@<version> sdist-only <identity sha256>`, so a baseline entry approves that exact artifact set. It is
 *   reported in PR mode too, for an entry the base's soak read identically as well (src/python/soak.ts binds such an
 *   entry for it alone); it is high there only when the base did not lock that identity (src/python/base-builds.ts).
 * Build-forcing configuration (no-binary, no-build-isolation, ...) is discovery's (src/python/indexes.ts).
 */
import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readlinkSync } from "node:fs";
import { isAbsolute, join, posix } from "node:path";
import { readBytes } from "../fsutil.js";
import { makeFinding, type Finding } from "../types.js";
import type { PyLockKind } from "./model.js";
import { contentDigest, decodeUtf8, get, isTable, MAX_TOML_BYTES, parseToml, type TomlTable } from "./toml.js";

/** What PEP 517/518 frontends (pip, uv, build) use when a project has no [build-system]. */
export const DEFAULT_REQUIRES = ["setuptools>=40.8.0"];
export const DEFAULT_BACKEND = "setuptools.build_meta:__legacy__";
/** Most files hashed under a project's backend-path directories. */
const MAX_BACKEND_FILES = 2000;
/** Most .py files hashed beside one hook file (hookSiblings). */
const MAX_HOOK_SIBLINGS = 200;
/**
 * Most hook files one project's build configuration may name (hookPaths, told apart by their path without "." and
 * empty names, so `hooks/./h.py` is `hooks/h.py`). Past it the build counts as unreadable, its hook files unread: the
 * time a build takes to read is bounded by the project's files, not by how many ways a short pyproject.toml names them.
 */
export const MAX_HOOK_FILES = 64;
/** Most backend-path entries one project may list (told apart without "." and empty names); past it, as MAX_HOOK_FILES. */
export const MAX_BACKEND_PATHS = 16;
/** The largest build file read (pyproject.toml, setup.cfg, a hook, a backend-path file): more is a problem. */
export const MAX_BUILD_FILE_BYTES = 64 * 1024 * 1024;
/** The version tag of the build digest: a change to what it covers changes the tag, so no old key matches a new one. */
export const BUILD_DIGEST_VERSION = "wormsign-pypi-build-4";

/**
 * [project] keys that are metadata only: copied into the built distribution's metadata, never read for the build's
 * requirements by any backend or frontend. A version bump or a new description keeps the key.
 */
export const PROJECT_METADATA_KEYS: ReadonlySet<string> = new Set(["version", "description", "readme", "authors", "maintainers", "urls", "classifiers", "keywords", "license", "license-files"]);

/**
 * [tool.<name>] tables that only a linter, formatter, type checker, spell checker or test runner reads; no PEP 517
 * build backend or frontend (pip, uv, build) reads them, so editing one cannot change a build or its requirements:
 * ruff (linter and formatter), black (formatter), isort (import sorter), mypy and pyright (type checkers), pytest
 * (test runner, [tool.pytest.ini_options]), coverage (coverage.py, measured test coverage), pylint (linter), flake8
 * (linter; read through the flake8-pyproject plugin), codespell (spell checker). Any other tool table counts.
 */
export const NON_BUILD_TOOLS: ReadonlySet<string> = new Set(["ruff", "black", "isort", "mypy", "pyright", "pytest", "coverage", "pylint", "flake8", "codespell"]);

/**
 * Build backends whose build requirements (get_requires_for_build_*) never come from [project] or
 * [dependency-groups]: setuptools (setup_requires comes from setup.cfg and setup.py, both digested whole), flit_core,
 * pdm-backend, poetry-core, maturin, scikit-build-core, meson-python, uv_build, and hatchling, which returns its
 * builders' and hooks' dependencies (under [tool.hatch], digested) and the project's own dependencies or features only
 * when `require-runtime-dependencies` or `require-runtime-features` is set (hatchProjectFree). Named exactly as
 * build-backend names them, and only when backend-path is empty: an in-tree module on backend-path could take the
 * name. For any other backend, or none named, [project] and [dependency-groups] count (but PROJECT_METADATA_KEYS).
 */
export const PROJECT_FREE_BACKENDS: ReadonlySet<string> = new Set([
  "setuptools.build_meta", "setuptools.build_meta:__legacy__", "flit_core.buildapi", "pdm.backend", "poetry.core.masonry.api", "maturin", "scikit_build_core.build", "mesonpy", "uv_build", "hatchling.build",
]);
/** hatchling keys that make get_requires_for_build_* return [project] dependencies or optional dependencies. */
export const HATCH_RUNTIME_KEYS: readonly string[] = ["require-runtime-dependencies", "require-runtime-features"];
/** [tool.hatch] subtables whose `path` names no build hook or builder: the version source's file, and environments. */
const HATCH_NOT_HOOKS: ReadonlySet<string> = new Set(["version", "envs"]);
/**
 * Files a backend runs or loads as a build hook by default, digested whole when present: setup.py (setuptools),
 * hatch_build.py (hatchling's custom hook), pdm_build.py (pdm-backend's), build.py (poetry-core's build script). Other
 * top-level .py files are the project's own code (a flat module, noxfile.py, conftest.py) and do not decide the build,
 * unless a hook setting names them (hookPaths).
 */
export const DEFAULT_BUILD_FILES: readonly string[] = ["setup.py", "hatch_build.py", "pdm_build.py", "build.py"];
/** Build configuration beside pyproject.toml, digested whole: setuptools' setup.cfg, uv's uv.toml, hatchling's hatch.toml. */
export const BUILD_CONFIG_FILES: readonly string[] = ["setup.cfg", "uv.toml", "hatch.toml"];
/** Most symlinks followed on one path (Linux follows 40). */
const MAX_HOPS = 40;

export interface LocalBuild {
  /** build-system.requires, or the default when there is no [build-system]; undefined when pyproject.toml cannot be read. */
  requires?: string[];
  backend?: string;
  /** No [build-system] table (or no pyproject.toml): the default setuptools backend builds it. */
  defaultBackend: boolean;
  /**
   * sha256 over the build files (BUILD_DIGEST_VERSION), not what a hook or setup.py reads or imports when it runs, nor
   * a hook outside the project's directory (recorded by its path): pyproject.toml as parsed, without the keys listed as
   * not deciding it (buildRelevant), or its bytes when it cannot be parsed (and a symlinked one by its link);
   * BUILD_CONFIG_FILES (setup.cfg, uv.toml, hatch.toml) and DEFAULT_BUILD_FILES (setup.py, hatch_build.py,
   * pdm_build.py, build.py) whole, symlinks by their link text (projectFile); the files a hatch, PDM or Poetry hook
   * setting names (hookPaths); the backend-path files; and for a uv.lock's build, the workspace root's [tool.uv] and
   * uv.toml.
   */
  digest: string;
  /**
   * What the digest covers, input by input, as [name, value] (src/diff.ts names the inputs that changed between two
   * revisions): "pyproject.toml" (as parsed, [build-system] included), each of BUILD_CONFIG_FILES and
   * DEFAULT_BUILD_FILES, each hook path a setting names (with the .py files beside it), "backend-path" and, for a
   * uv.lock's build, "the workspace root's [tool.uv] and uv.toml". The digest is computed from the same values.
   */
  inputs: [string, string][];
  /** Why pyproject.toml could not be read, when it could not. */
  problem?: string;
  /** Some entry could not be read (over a cap, a name another entry folds like, ...): a base build with one is new. */
  unreadable: boolean;
  /** The caps this build is past, each a phrase naming the cap ("it names more than 64 hook files"); each makes it unreadable. */
  limits: string[];
}

const sha = (s: string | Buffer): string => createHash("sha256").update(s).digest("hex");

/** `list` without the later items whose `key` an earlier one has, in order. */
function distinct(list: string[], key: (x: string) => string): string[] {
  const seen = new Set<string>();
  return list.filter((x) => {
    const k = key(x);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/**
 * Every file under `entry` (a backend-path directory, relative to the project), each with its sha256; a symlink by its
 * link text, not followed; never more than MAX_BACKEND_FILES (more counts as a problem).
 */
function backendFiles(r: TrackedReader, entry: string): string[] {
  const normal = posix.normalize(entry.split("\\").join("/"));
  if (entry.includes("\0") || posix.isAbsolute(normal) || normal === ".." || normal.startsWith("../")) return [`${entry}: outside the project`];
  const out: string[] = [];
  const stack = [normal === "." ? "" : normal.replace(/\/+$/, "")];
  while (stack.length > 0) {
    const rel = stack.pop()!;
    if (out.length >= MAX_BACKEND_FILES) {
      r.unreadable = true;
      r.limits.push(`more than ${MAX_BACKEND_FILES} files under backend-path ${entry}`);
      return [...out, `more than ${MAX_BACKEND_FILES} files`];
    }
    const e = r.entry(rel);
    if (e.kind === "dir") for (const n of [...e.names].reverse()) stack.push(rel === "" ? n : `${rel}/${n}`);
    else out.push(`${rel} ${described(e)}${e.kind === "symlink" ? followedText(r, rel) : ""}`);
  }
  return out.sort();
}


/** Some key, at any depth under `v` (tables and arrays), is one of `keys`. An explicit stack: no recursion. */
function hasKeyBelow(v: unknown, keys: readonly string[]): boolean {
  const stack: unknown[] = [v];
  while (stack.length > 0) {
    const x = stack.pop();
    if (Array.isArray(x)) for (const e of x) stack.push(e);
    else if (isTable(x)) {
      for (const k of Object.keys(x)) {
        if (keys.includes(k)) return true;
        stack.push(x[k]);
      }
    }
  }
  return false;
}

/** Every string value of `key` at any depth under `v` (tables and arrays), skipping the top-level tables in `skip`. */
function stringsBelow(v: unknown, key: string, skip: ReadonlySet<string> = new Set()): string[] {
  const out: string[] = [];
  const stack: unknown[] = isTable(v) ? Object.keys(v).filter((k) => !skip.has(k)).map((k) => ({ [k]: v[k] })) : [];
  while (stack.length > 0) {
    const x = stack.pop();
    if (Array.isArray(x)) for (const e of x) stack.push(e);
    else if (isTable(x)) {
      for (const k of Object.keys(x)) {
        if (k === key && typeof x[k] === "string") out.push(x[k]);
        else stack.push(x[k]);
      }
    }
  }
  return out;
}

/**
 * hatch.toml beside pyproject.toml, which hatchling reads as it reads [tool.hatch]: absent (undefined), its table, or
 * "unreadable" (not TOML, a symlink, not UTF-8), which counts as holding anything.
 */
export type HatchToml = TomlTable | "unreadable" | undefined;

/**
 * The hatchling backend reads no [project] dependency for the build: no HATCH_RUNTIME_KEYS key under [tool.hatch] or
 * anywhere in hatch.toml (and hatch.toml, if present, can be read).
 */
export function hatchProjectFree(doc: TomlTable, hatch?: HatchToml): boolean {
  const tool = get(doc, "tool");
  if (hatch === "unreadable" || hasKeyBelow(hatch, HATCH_RUNTIME_KEYS)) return false;
  return !(isTable(tool) && hasKeyBelow(get(tool, "hatch"), HATCH_RUNTIME_KEYS));
}

/** Do [project] and [dependency-groups] leave this project's build requirements alone (PROJECT_FREE_BACKENDS)? */
export function projectFree(doc: TomlTable, hatch?: HatchToml): boolean {
  const bs = get(doc, "build-system");
  if (!isTable(bs)) return false;
  const backend = get(bs, "build-backend");
  const backendPath = get(bs, "backend-path");
  if (typeof backend !== "string" || !PROJECT_FREE_BACKENDS.has(backend)) return false;
  if (backendPath !== undefined && !(Array.isArray(backendPath) && backendPath.length === 0)) return false;
  return backend !== "hatchling.build" || hatchProjectFree(doc, hatch);
}

/**
 * pyproject.toml without what is known not to decide the build: [project]'s PROJECT_METADATA_KEYS, [tool]'s
 * NON_BUILD_TOOLS, and, when projectFree, all of [project] and [dependency-groups]. Everything else is kept. A
 * [project] or [tool] left empty is dropped, so adding the first [tool.ruff] to a file with no [tool] keeps the key.
 */
export function buildRelevant(doc: TomlTable, hatch?: HatchToml): TomlTable {
  const free = projectFree(doc, hatch);
  const out: TomlTable = Object.create(null) as TomlTable;
  for (const key of Object.keys(doc)) {
    const v = doc[key];
    if ((key === "project" || key === "dependency-groups") && free) continue;
    if ((key === "project" || key === "tool") && isTable(v)) {
      const drop = key === "project" ? PROJECT_METADATA_KEYS : NON_BUILD_TOOLS;
      const kept: TomlTable = Object.create(null) as TomlTable;
      for (const k of Object.keys(v)) if (!drop.has(k)) kept[k] = v[k];
      if (Object.keys(kept).length > 0) out[key] = kept;
    } else out[key] = v;
  }
  return out;
}

/**
 * The files a build hook or custom builder is loaded from, as pyproject.toml and hatch.toml name them: under
 * [tool.hatch] and in hatch.toml, every `path` (build and metadata hooks of any target, a custom builder) but those of
 * the version and envs tables; under [tool.pdm], every `custom-hook`; [tool.poetry] `build` (a script path) or
 * `build.script`. Each hook can add build requirements from code. The default files are DEFAULT_BUILD_FILES.
 */
export function hookPaths(doc: TomlTable, hatch?: HatchToml): string[] {
  const fromHatchToml = isTable(hatch) ? stringsBelow(hatch, "path", HATCH_NOT_HOOKS) : [];
  const tool = get(doc, "tool");
  if (!isTable(tool)) return [...new Set(fromHatchToml)].sort();
  const out = [...fromHatchToml, ...stringsBelow(get(tool, "hatch"), "path", HATCH_NOT_HOOKS), ...stringsBelow(get(tool, "pdm"), "custom-hook")];
  const poetry = get(tool, "poetry");
  const build = isTable(poetry) ? get(poetry, "build") : undefined;
  if (typeof build === "string") out.push(build);
  else if (isTable(build) && typeof get(build, "script") === "string") out.push(get(build, "script") as string);
  return [...new Set(out)].sort();
}

/**
 * The sha256 of a whole build file, each CRLF read as LF. Git for Windows checks text files out with CRLF
 * (core.autocrlf=true, its default) while the repository stores LF, so the head's disk and the base's blob of one
 * unchanged file would otherwise never match. A lone CR stays as it is, and a file holding a NUL byte (binary to git,
 * which converts no line endings in it) is hashed byte for byte.
 */
export function fileDigest(bytes: Buffer): string {
  if (bytes.includes(0)) return sha(bytes);
  return sha(Buffer.from(bytes.toString("latin1").replace(/\r\n/g, "\n"), "latin1"));
}

/** One entry as the digest records it: a file's sha256 (fileDigest), a link's text, or what it is. */
function described(e: BuildEntry): string {
  switch (e.kind) {
    case "file":
      return fileDigest(e.bytes);
    case "symlink":
      return `-> ${e.target}`;
    case "dir":
      return "a directory";
    case "missing":
      return "missing";
    case "problem":
      return e.why;
  }
}

/**
 * Where a walk along a path inside the project ended: the links on the way, the real path, and the file's digest
 * (fileDigest; its bytes are not kept) or why not; and, when it stopped after a link, what the link leads to
 * (followedText).
 */
interface Walked {
  links: string[];
  at: string[];
  digest?: string;
  stop?: string;
  followed?: string;
}

/**
 * The file at `entry` (relative to the project) as the OS opens it, followed only inside the project: each symlink on
 * the way by its link text, then the file; or where the walk stopped (a path or link that leaves the project, a
 * missing name, not a regular file, more than MAX_HOPS links, an entry the reader cannot read). Nothing outside the
 * project is ever asked for.
 */
function walk(r: BuildReader, entry: string): Walked {
  const links: string[] = [];
  if (entry === "" || entry.includes("\0") || isAbsolute(entry) || posix.isAbsolute(entry.split("\\").join("/"))) return { links, at: [], stop: "outside the project" };
  // No OS opens a longer path (Linux: 4096 bytes), and the walk stays linear in it.
  if (entry.length > 4096) return { links, at: [], stop: "longer than any path" };
  const names = (path: string): string[] => path.split("/").filter((t) => t !== "" && t !== ".").reverse();
  const todo = names(entry.split("\\").join("/"));
  const at: string[] = [];
  let hops = 0;
  while (todo.length > 0) {
    const name = todo.pop()!;
    if (name === "..") {
      if (at.pop() === undefined) return { links, at, stop: "outside the project" };
      continue;
    }
    at.push(name);
    const e = r.entry(at.join("/"));
    if (e.kind === "symlink") {
      links.push(`${at.join("/")} -> ${e.target}`);
      if (++hops > MAX_HOPS || e.target === "" || e.target.length > 4096 || isAbsolute(e.target) || posix.isAbsolute(e.target)) return { links, at, stop: "outside the project" };
      at.pop();
      todo.push(...names(e.target));
    } else if (e.kind === "missing" || e.kind === "problem") {
      return { links, at, stop: `${at.join("/")} ${described(e)}` };
    } else if (todo.length > 0) {
      if (e.kind !== "dir") return { links, at, stop: `${at.join("/")} is not a directory` };
    } else if (e.kind === "dir") return { links, at, stop: "not a regular file" };
    else return { links, at, digest: fileDigest(e.bytes) };
  }
  return { links, at, stop: "not a regular file" };
}

/**
 * walk, once per path for the life of the reader (one project of one revision): "." and empty names do not change
 * what a path opens. 64 hooks in one directory each list the same .py files beside them, and each of those would
 * otherwise be read and hashed (and a link among them followed and hashed) once per hook.
 */
function walked(r: TrackedReader, entry: string): Walked {
  const slashed = entry.split("\\").join("/");
  // What walk refuses at once, by the text as given, is not kept: its answer depends on more than the names.
  if (entry === "" || entry.includes("\0") || entry.length > 4096 || isAbsolute(entry) || posix.isAbsolute(slashed)) return walk(r, entry);
  const key = slashed.split("/").filter((t) => t !== "" && t !== ".").join("/");
  let w = r.walks.get(key);
  if (w === undefined) {
    w = walk(r, entry);
    if (w.digest === undefined && w.links.length > 0) w.followed = followedText(r, entry);
    r.walks.set(key, w);
  }
  return w;
}

/**
 * What a link at `rel` leads to as the reader's tree follows it (BuildReader.followed), as " => <sha256>" (CRLF read as
 * LF, as fileDigest reads a file) or " => absent"; "" for a reader that does not follow links.
 */
function followedText(r: BuildReader, rel: string): string {
  if (r.followed === undefined) return "";
  return ` => ${r.followed(rel.split("\\").join("/")) ?? "absent"}`;
}

/**
 * A file named in the build configuration, as the digest records it (see walk). When a link on the way could not be
 * followed to a file inside the project (one that leads out of it, to `../shared/base.toml`), what the reader's tree
 * reads through it counts too (followedText), so a change to the target changes the key.
 */
function projectFile(r: TrackedReader, entry: string): string {
  const w = walked(r, entry);
  return `${entry}${w.links.map((l) => ` [${l}]`).join("")} ${w.digest ?? w.stop}${w.followed ?? ""}`;
}

/**
 * Does `path` (relative to the project) climb with ".." from a name that is a symbolic link? The OS climbs from where
 * the link points, but a path read as text (Tree.read, and backendFiles' posix.normalize) climbs from the link itself,
 * so it would read another file than the build opens: such a path is not read, and the build counts as unreadable.
 */
function climbsFromLink(r: BuildReader, path: string): boolean {
  // No OS opens a longer path (walk says so), and the names asked about stay within the tree's own depth.
  if (path.length > 4096) return false;
  const names = path.split("\\").join("/").split("/").filter((t) => t !== "" && t !== ".");
  // Only a name some ".." comes after is asked about, so a path without one reads nothing here.
  const last = names.lastIndexOf("..");
  const at: string[] = [];
  for (const name of names.slice(0, Math.max(last, 0))) {
    if (name === "..") {
      at.pop();
      continue;
    }
    at.push(name);
    const kind = r.entry(at.join("/")).kind;
    if (kind === "symlink") return true;
    // Past a name that is no directory the path opens nothing (walk and backendFiles say what).
    if (kind !== "dir") return false;
  }
  return false;
}

/**
 * A hook file outside the project's top directory can import its neighbours: every .py file directly in the hook's
 * own directory (as the walk resolved it), at most MAX_HOOK_SIBLINGS (more counts as a problem). A hook that imports
 * other project modules is not followed further (docs/soak.md, "Builds: WS-SK-005").
 */
function hookSiblings(r: TrackedReader, hook: string): string[] {
  const w = walked(r, hook);
  if (w.digest === undefined || w.at.length < 2) return [];
  const dir = w.at.slice(0, -1).join("/");
  const e = r.entry(dir);
  if (e.kind !== "dir") return [`${dir} ${described(e)}`];
  const py = e.names.filter((n) => /\.py$/i.test(n));
  if (py.length > MAX_HOOK_SIBLINGS) {
    r.unreadable = true;
    r.limits.push(`more than ${MAX_HOOK_SIBLINGS} .py files beside the hook in ${dir}`);
    return [`${dir}: more than ${MAX_HOOK_SIBLINGS} .py files`];
  }
  return py.map((n) => projectFile(r, `${dir}/${n}`));
}

/** A TOML file the reader holds, read as readToml reads one from disk: a regular file, UTF-8, parsed. */
function tomlOf(e: BuildEntry): { doc: TomlTable } | { problem: string } {
  if (e.kind === "symlink") return { problem: "it is a symlink" };
  if (e.kind === "missing") return { problem: "it is missing" };
  if (e.kind === "dir") return { problem: "it is not a regular file" };
  if (e.kind === "problem") return { problem: e.why };
  if (e.bytes.length > MAX_TOML_BYTES) return { problem: `it is larger than ${MAX_TOML_BYTES / 1024 / 1024} MiB` };
  const text = decodeUtf8(e.bytes);
  return "problem" in text ? text : parseToml(text.text);
}

/**
 * A project as the build digest reads it: the entry at exactly a "/"-separated path relative to the project ("" is the
 * project itself), no link followed on the way (a path through a symlink is a problem). Two implementations: the disk
 * (fsBuildReader, the head) and a git tree (src/python/base-builds.ts, the base), which read identical content alike,
 * symlinks by their link text and bytes never decoded, so the base's build is digested without writing anything.
 */
export type BuildEntry = { kind: "file"; bytes: Buffer } | { kind: "symlink"; target: string } | { kind: "dir"; names: string[] } | { kind: "missing" } | { kind: "problem"; why: string };
export interface BuildReader {
  entry(rel: string): BuildEntry;
  /**
   * The digest (fileDigest) of the text of the file a symlink at `rel` leads to, followed as the whole tree follows
   * links (src/tree.ts Tree.read, which reaches past the project's directory), or undefined when nothing is read
   * there. Only diff gives it, on both of its revisions alike, hashing each text once per tree; soak's readers do not,
   * so its keys record a link by its text alone.
   */
  followed?(rel: string): string | undefined;
}
/**
 * A reader that remembers whether any entry could not be read, and the caps it was past (a base build with one counts
 * as new), and each path's walk (walked).
 */
interface TrackedReader extends BuildReader {
  unreadable: boolean;
  limits: string[];
  walks: Map<string, Walked>;
}
const tracked = (r: BuildReader): TrackedReader => {
  const t: TrackedReader = {
    unreadable: false,
    limits: [],
    walks: new Map(),
    entry(rel) {
      const e = r.entry(rel);
      if (e.kind === "problem") t.unreadable = true;
      return e;
    },
  };
  if (r.followed !== undefined) t.followed = (rel) => r.followed?.(rel);
  return t;
};

/**
 * The disk under `root`: lstat on every name of the path (a symlink before the last name is a problem, never
 * followed), a symlink's link text, a directory's names, a regular file's bytes opened with O_NOFOLLOW and at most
 * `maxBytes` (more is a problem).
 */
export function fsBuildReader(root: string, maxBytes = MAX_BUILD_FILE_BYTES): BuildReader {
  return {
    entry(rel) {
      const parts = rel === "" ? [] : rel.split("/");
      for (let i = 1; i < parts.length; i++) {
        try {
          if (lstatSync(join(root, ...parts.slice(0, i))).isSymbolicLink()) return { kind: "problem", why: `${parts.slice(0, i).join("/")} is a symlink on the way` };
        } catch {
          return { kind: "missing" };
        }
      }
      const p = join(root, ...parts);
      let st;
      try {
        st = lstatSync(p);
      } catch (e) {
        const code = (e as NodeJS.ErrnoException).code;
        return code === "ENOENT" || code === "ENOTDIR" ? { kind: "missing" } : { kind: "problem", why: "unreadable" };
      }
      try {
        if (st.isSymbolicLink()) return { kind: "symlink", target: readlinkSync(p) };
        if (st.isDirectory()) return { kind: "dir", names: readdirSync(p).sort() };
      } catch {
        return { kind: "problem", why: "unreadable" };
      }
      if (!st.isFile()) return { kind: "problem", why: "not a regular file" };
      const read = readBytes(p, maxBytes);
      return "bytes" in read ? { kind: "file", bytes: read.bytes } : { kind: "problem", why: read.problem.startsWith("it is larger") ? `larger than ${maxBytes} bytes` : "unreadable" };
    },
  };
}

/** hatch.toml in the project, read for hatchProjectFree and hookPaths (see HatchToml). */
function hatchTomlOf(r: BuildReader): HatchToml {
  const e = r.entry("hatch.toml");
  if (e.kind === "missing") return undefined;
  const t = tomlOf(e);
  return "doc" in t ? t.doc : "unreadable";
}

/**
 * A uv workspace root's settings that apply to every member's build: its pyproject.toml's [tool.uv] (as parsed, or the
 * file as projectFile records it when it does not parse) and its uv.toml.
 */
function workspaceSettings(r: TrackedReader): string[] {
  const e = r.entry("pyproject.toml");
  let toolUv: string;
  if (e.kind === "missing") toolUv = "no pyproject.toml";
  else {
    const t = tomlOf(e);
    if ("doc" in t) {
      const tool = get(t.doc, "tool");
      toolUv = contentDigest(isTable(tool) ? (get(tool, "uv") ?? null) : null);
    } else toolUv = `pyproject.toml: ${t.problem}: ${projectFile(r, "pyproject.toml")}`;
  }
  return [toolUv, projectFile(r, "uv.toml")];
}

/**
 * Reads what decides how the project in `dir` (absolute) is built. `workspaceRoot` (absolute) is the directory of the
 * uv.lock that installs it: uv applies the workspace root's [tool.uv] and uv.toml to every member's build. Never throws.
 */
export function readLocalBuild(dir: string, workspaceRoot?: string): LocalBuild {
  return localBuild(fsBuildReader(dir), workspaceRoot === undefined ? undefined : fsBuildReader(workspaceRoot));
}

/** The build digest over any reader (see BuildReader): the disk for the head, a git tree for the base. Never throws. */
export function localBuild(project: BuildReader, workspace?: BuildReader): LocalBuild {
  const r = tracked(project);
  const ws = workspace === undefined ? undefined : tracked(workspace);
  const hatch = hatchTomlOf(r);
  let requires: string[] | undefined;
  let backend: string | undefined;
  let backendPath: string[] = [];
  let defaultBackend = false;
  let problem: string | undefined;
  let raw: string | null = null;
  /** contentDigest of buildRelevant(pyproject.toml), when it parses. */
  let config: string | null = null;
  let hooks: string[] = [];
  const py = r.entry("pyproject.toml");
  if (py.kind === "missing") {
    requires = DEFAULT_REQUIRES;
    backend = DEFAULT_BACKEND;
    defaultBackend = true;
  } else {
    const read = tomlOf(py);
    if ("problem" in read) {
      problem = `pyproject.toml: ${read.problem}`;
      raw = py.kind === "file" ? fileDigest(py.bytes) : read.problem;
    } else {
      config = contentDigest(buildRelevant(read.doc, hatch));
      hooks = hookPaths(read.doc, hatch);
      const bs = get(read.doc, "build-system");
      if (bs === undefined) {
        requires = DEFAULT_REQUIRES;
        backend = DEFAULT_BACKEND;
        defaultBackend = true;
      } else if (!isTable(bs)) {
        problem = "pyproject.toml: [build-system] is not a table";
      } else {
        const req = get(bs, "requires");
        if (Array.isArray(req) && req.every((x) => typeof x === "string")) requires = req as string[];
        else problem = "pyproject.toml: build-system.requires is not a list of strings";
        const be = get(bs, "build-backend");
        backend = typeof be === "string" ? be : DEFAULT_BACKEND;
        const bp = get(bs, "backend-path");
        if (Array.isArray(bp)) backendPath = bp.map((p) => (typeof p === "string" ? p : JSON.stringify(p)));
      }
    }
  }
  // Without pyproject.toml (or when it does not parse) hatch.toml's hooks are still read.
  if (config === null && isTable(hatch)) hooks = hookPaths(Object.create(null) as TomlTable, hatch);
  // Each hook file once, under the first of its spellings: "." and empty names do not change the file a path opens.
  hooks = distinct(hooks, (h) => h.split("\\").join("/").split("/").filter((t) => t !== "" && t !== ".").join("/"));
  const pastHooks = hooks.length > MAX_HOOK_FILES;
  if (pastHooks) {
    r.unreadable = true;
    r.limits.push(`it names more than ${MAX_HOOK_FILES} hook files`);
  }
  // A hook path or backend-path entry that climbs with ".." from a symbolic link is not read (climbsFromLink); there
  // are at most MAX_HOOK_FILES and MAX_BACKEND_PATHS of them to ask about.
  const climbing: string[] = [];
  const climbs = (p: string): boolean => climbsFromLink(r, p) && climbing.push(p) > 0;
  const CLIMBS = 'climbs with ".." from a symbolic link';
  const hookEach = pastHooks ? [] : hooks.map((h) => (climbs(h) ? { h, file: `${h} ${CLIMBS}`, siblings: [] } : { h, file: projectFile(r, h), siblings: hookSiblings(r, h) }));
  const hookFiles = pastHooks ? [`more than ${MAX_HOOK_FILES} hook files`] : [...hookEach.map((x) => x.file), ...hookEach.flatMap((x) => x.siblings)];
  // Each backend-path entry once, told apart without "." and empty names ("_build/" is "_build"). ".." is kept: as
  // text it would merge an entry that climbs from a link with the one it does not open.
  const entries = distinct(backendPath, (p) => p.split("\\").join("/").split("/").filter((t) => t !== "" && t !== ".").join("/"));
  const pastBackend = entries.length > MAX_BACKEND_PATHS;
  if (pastBackend) {
    r.unreadable = true;
    r.limits.push(`it lists more than ${MAX_BACKEND_PATHS} backend-path entries`);
  }
  const files = pastBackend ? [`more than ${MAX_BACKEND_PATHS} backend-path entries`] : entries.flatMap((p) => (climbs(p) ? [`${p} ${CLIMBS}`] : backendFiles(r, p)));
  if (climbing.length > 0) {
    r.unreadable = true;
    const shown = climbing.length === 1 ? `${climbing[0]} climbs` : `${climbing.length} paths climb (${climbing.slice(0, 3).join(", ")}${climbing.length > 3 ? ", ..." : ""})`;
    r.limits.push(`${shown} with ".." from a symbolic link, which the OS resolves from where the link points`);
  }
  const wholeNames = [...BUILD_CONFIG_FILES, ...DEFAULT_BUILD_FILES];
  const whole = wholeNames.map((name) => projectFile(r, name));
  // pyproject.toml counts as parsed (config), so a version bump keeps the key; a symlinked one counts by its link
  // text and what it leads to.
  const pyprojectLink = py.kind === "symlink" ? projectFile(r, "pyproject.toml") : null;
  const settings = ws === undefined ? null : workspaceSettings(ws);
  const digest = sha(JSON.stringify([BUILD_DIGEST_VERSION, requires ?? null, backend ?? null, backendPath, files, raw, problem ?? null, config, pyprojectLink, whole, hookFiles, settings]));
  const inputs: [string, string][] = [
    ["pyproject.toml", JSON.stringify([requires ?? null, backend ?? null, backendPath, raw, problem ?? null, config, pyprojectLink])],
    ...wholeNames.map((name, i): [string, string] => [name, whole[i] as string]),
    ...(pastHooks ? [["hook files", hookFiles[0] as string] as [string, string]] : hookEach.map((x): [string, string] => [x.h, JSON.stringify([x.file, x.siblings])])),
    ["backend-path", JSON.stringify(files)],
    ...(settings === null ? [] : [["the workspace root's [tool.uv] and uv.toml", JSON.stringify(settings)] as [string, string]]),
  ];
  const out: LocalBuild = { defaultBackend, digest, inputs, unreadable: r.unreadable || ws?.unreadable === true, limits: [...r.limits, ...(ws?.limits ?? [])] };
  if (requires !== undefined) out.requires = requires;
  if (backend !== undefined) out.backend = backend;
  if (problem !== undefined) out.problem = problem;
  return out;
}


const UV_AVOID =
  "To avoid the build: `uv sync --locked --no-install-project` for the root project, `--no-install-workspace` or `--no-install-package <name>` for members, or `[tool.uv] package = false` if it need not be installed. Otherwise pin its build requirements with ==-pinned `build-constraint-dependencies`";
const PYLOCK_AVOID = "Pin its build requirements with ==-pinned build constraints (pip `--build-constraint`, uv `build-constraint-dependencies`), or install it separately";

/** WS-SK-005 for a local project the install builds. `dir` is relative to the root ("" for the root). */
export function localBuildFinding(a: { name: string; dir: string; lockFile: string; lockKind: PyLockKind; sourceKind: string }, b: LocalBuild): Finding {
  const where = a.dir === "" ? "." : a.dir;
  const what =
    b.requires === undefined ? `its build requirements are unknown (${b.problem ?? "unreadable"})`
    : `its build requirements (${b.requires.length > 0 ? b.requires.map((r) => JSON.stringify(r)).join(", ") : "none listed"}${b.defaultBackend ? "; no [build-system], so the default setuptools backend" : ""}) are resolved when it is built, not pinned by ${a.lockFile}`;
  return makeFinding({
    ruleId: "WS-SK-005",
    severity: "medium",
    message: `${a.name} (${a.sourceKind} source ${where}) is built from source at install time, and ${what}. ${a.lockKind === "pylock" ? PYLOCK_AVOID : UV_AVOID}.`,
    file: a.lockFile,
    key: `pypi:build ${where} ${b.digest}`,
  });
}

/** WS-SK-005 for a package whose every locked file is an sdist. */
export function sdistOnlyFinding(a: { name: string; version: string; identity: string; file: string; line?: number; filenames: string[] }): Finding {
  const shown = a.filenames.slice(0, 3).join(", ") + (a.filenames.length > 3 ? ", ..." : "");
  return makeFinding({
    ruleId: "WS-SK-005",
    severity: "medium",
    message: `${a.name}==${a.version} is locked only as an sdist (${shown}), so installing it runs its build backend, whose build requirements are resolved at install time, not pinned by the lock. Prefer a version with wheels for the platforms you install on, or pin the build requirements with ==-pinned build constraints (uv \`build-constraint-dependencies\`, pip \`--build-constraint\`).`,
    file: a.file,
    ...(a.line !== undefined ? { line: a.line } : {}),
    key: `pypi:${a.name}@${a.version} sdist-only ${a.identity}`,
  });
}
