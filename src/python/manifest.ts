/**
 * Python input names and manifests, for discovery (src/python/discover.ts) and the shared walker (src/walk.ts).
 *
 * Names (docs/soak.md, "Python (PyPI) locks"). Every comparison is on the folded name (src/tree.ts fold:
 * NFKC, then case), so a name a case-insensitive file system opens as uv.lock (UV.LOCK on APFS or NTFS) is read as one:
 * an install there would use it. On a case-sensitive file system this only adds reads.
 * - locks: uv.lock; pylock.toml and pylock.<name>.toml; PEP 723 script locks *.py.lock and *.pyw.lock (a script's lock
 *   is `<script path>.lock` whatever the script's name, but only these two are recognisable without the script);
 * - not supported yet (WS-SK-002): poetry.lock, pdm.lock, Pipfile.lock;
 * - manifests: pyproject.toml, setup.py, setup.cfg, Pipfile;
 * - requirements files by name: *requirements*.txt, *constraints*.txt, any .txt under a directory named requirements,
 *   and requirements*.lock. Files with other names are found by content (src/python/scripts.ts).
 *
 * Manifests that declare dependencies (the covering-lock rule is discover.ts's):
 * - pyproject.toml: [project] dependencies or optional-dependencies, [dependency-groups], [tool.uv] dev-dependencies,
 *   [tool.poetry] dependencies (other than python), dev-dependencies or group dependencies, [tool.pdm]
 *   dev-dependencies, flit's legacy [tool.flit.metadata] requires, requires-extra or dev-requires (flit_core still
 *   builds from them), [project] dynamic naming dependencies or optional-dependencies, or a [build-system]
 *   backend-path (an in-tree build backend declares whatever its code computes). A value of the wrong type counts as
 *   declaring: what an install reads from it is unknown;
 * - setup.py: always (it runs at install time and can declare anything);
 * - setup.cfg: when it sets install_requires, setup_requires or tests_require, or has an [options.extras_require]
 *   section. A setup.cfg that only configures tools (flake8, isort, pytest) declares nothing;
 * - Pipfile: always.
 */
import { posix } from "node:path";
import { fold } from "../tree.js";
import { get, isTable, type TomlTable } from "./toml.js";

export const UNSUPPORTED_PY_LOCKS: readonly string[] = ["poetry.lock", "pdm.lock", "pipfile.lock"];
export const PY_MANIFESTS: readonly string[] = ["pyproject.toml", "setup.py", "setup.cfg", "pipfile"];

/** uv.lock, by folded name. */
export const isUvLockName = (name: string): boolean => fold(name) === "uv.lock";
/** pylock.toml or pylock.<name>.toml (PEP 751's file name rule), by folded name. */
export const isPylockFileName = (name: string): boolean => /^pylock\.([^.]+\.)?toml$/.test(fold(name));
/** A PEP 723 script lock recognisable by its own name: <script>.py.lock or <script>.pyw.lock. */
export const isScriptLockName = (name: string): boolean => /^.+\.pyw?\.lock$/.test(fold(name));
/** A lock format soak does not read yet. */
export const isUnsupportedPyLock = (name: string): boolean => UNSUPPORTED_PY_LOCKS.includes(fold(name));
/** pyproject.toml, setup.py, setup.cfg or Pipfile. */
export const isPyManifestName = (name: string): boolean => PY_MANIFESTS.includes(fold(name));
/** A script by its name: *.py or *.pyw. */
export const isScriptName = (name: string): boolean => /\.pyw?$/.test(fold(name));
/** pip's configuration file names (pip.conf on Unix and macOS, pip.ini on Windows). */
export const isPipConfName = (name: string): boolean => ["pip.conf", "pip.ini"].includes(fold(name));
/** uv's configuration file name. */
export const isUvTomlName = (name: string): boolean => fold(name) === "uv.toml";

/**
 * A requirements file by name. `rel` is the "/"-separated path relative to the root; a directory named requirements
 * at any depth above the file makes every .txt under it one.
 */
export function isRequirementsName(rel: string): boolean {
  const parts = fold(rel).split("/");
  const base = parts[parts.length - 1] ?? "";
  if (base.endsWith(".txt") && (base.includes("requirements") || base.includes("constraints"))) return true;
  if (base.startsWith("requirements") && base.endsWith(".lock")) return true;
  return base.endsWith(".txt") && parts.slice(0, -1).includes("requirements");
}

/** Names a reader of their own always fails closed on, so the requirements content rule does not read them too. */
const OWN_READER = new Set(["pyproject.toml", "package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"]);
/** A file discovery's content pass never reads as a script or requirements file (diff's content rule follows it). */
export const ownReader = (name: string): boolean => OWN_READER.has(fold(name)) || isUvLockName(name) || isPylockFileName(name) || isScriptLockName(name) || isUnsupportedPyLock(name);

/** Any name discovery reads as a Python lock, manifest or requirements file (not scripts, which are found by name or content). */
export function isPythonInputName(name: string, rel: string): boolean {
  return isUvLockName(name) || isPylockFileName(name) || isScriptLockName(name) || isUnsupportedPyLock(name) || isPyManifestName(name) || isRequirementsName(rel);
}

/** The directory of a root-relative path, "." for the root. */
export const dirOf = (rel: string): string => posix.dirname(rel);

const nonEmptyArray = (v: unknown): boolean => v !== undefined && !(Array.isArray(v) && v.length === 0);
/** A table any of whose values is a non-empty array (or not an array: unknown counts as declaring). */
const anyGroup = (v: unknown): boolean => {
  if (v === undefined) return false;
  if (!isTable(v)) return true;
  return Object.values(v).some((g) => nonEmptyArray(g));
};

/**
 * A [build-system] backend-path that is set and not empty: pip and uv load the build backend from the tree, whose code
 * declares whatever it computes, whatever [project] lists.
 */
function inTreeBackend(doc: TomlTable): boolean {
  const bs = get(doc, "build-system");
  if (bs === undefined) return false;
  if (!isTable(bs)) return true;
  const path = get(bs, "backend-path");
  return path !== undefined && !(Array.isArray(path) && path.length === 0);
}

/** Does a parsed pyproject.toml declare dependencies an install would fetch? See the module comment. */
export function pyprojectDeclares(doc: TomlTable): boolean {
  if (inTreeBackend(doc)) return true;
  const project = get(doc, "project");
  if (project !== undefined) {
    if (!isTable(project)) return true;
    if (nonEmptyArray(get(project, "dependencies"))) return true;
    if (anyGroup(get(project, "optional-dependencies"))) return true;
    const dynamic = get(project, "dynamic");
    if (dynamic !== undefined && (!Array.isArray(dynamic) || dynamic.some((d) => d === "dependencies" || d === "optional-dependencies" || typeof d !== "string"))) return true;
  }
  if (anyGroup(get(doc, "dependency-groups"))) return true;
  const tool = get(doc, "tool");
  if (tool === undefined) return false;
  if (!isTable(tool)) return true;
  const uv = get(tool, "uv");
  if (uv !== undefined && (!isTable(uv) || nonEmptyArray(get(uv, "dev-dependencies")))) return true;
  const pdm = get(tool, "pdm");
  if (pdm !== undefined && (!isTable(pdm) || anyGroup(get(pdm, "dev-dependencies")))) return true;
  const flit = get(tool, "flit");
  const flitMeta = isTable(flit) ? get(flit, "metadata") : flit;
  if (flitMeta !== undefined && (!isTable(flitMeta) || nonEmptyArray(get(flitMeta, "requires")) || anyGroup(get(flitMeta, "requires-extra")) || nonEmptyArray(get(flitMeta, "dev-requires")))) return true;
  const poetry = get(tool, "poetry");
  if (poetry !== undefined) {
    if (!isTable(poetry)) return true;
    const deps = get(poetry, "dependencies");
    if (deps !== undefined && (!isTable(deps) || Object.keys(deps).some((k) => fold(k) !== "python"))) return true;
    const dev = get(poetry, "dev-dependencies");
    if (dev !== undefined && (!isTable(dev) || Object.keys(dev).length > 0)) return true;
    const groups = get(poetry, "group");
    if (groups !== undefined) {
      if (!isTable(groups)) return true;
      for (const g of Object.values(groups)) {
        const d = isTable(g) ? get(g, "dependencies") : g;
        if (d !== undefined && (!isTable(d) || Object.keys(d).length > 0)) return true;
      }
    }
  }
  return false;
}

/**
 * A character Python reads differently from the line reader below: whitespace other than space and tab (configparser
 * counts any of Python's whitespace as indent and strips it around a key and a value), a line break other than "\n"
 * and "\r" (setuptools splits values with str.splitlines(), which also ends a line at "\v", "\f", "\x1c" to "\x1e",
 * U+0085, U+2028 and U+2029), any other control character, a byte-order mark, and U+FFFD, which stands for bytes that
 * are not UTF-8.
 */
// eslint-disable-next-line no-control-regex -- matching control characters is the point
const PY_READS_DIFFERENTLY = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff\ufffd]/;

/**
 * Does a setup.cfg declare dependencies? Read as setuptools reads it (configparser: "=" or ":" separates a key from its
 * value, keys are case-insensitive), but over-inclusively: a key in any section counts, so a section name written
 * oddly cannot hide one; and a text that holds a character the line reader does not model (PY_READS_DIFFERENTLY:
 * `install_requires\f= idna`) declares whenever such a key's name appears in it at all (configparser reads keys and
 * section names as written, so no other text can be one).
 */
export function setupCfgDeclares(text: string): boolean {
  if (PY_READS_DIFFERENTLY.test(text) && /(install|setup|tests)[_-]requires|options\.extras_require/i.test(text)) return true;
  for (const line of text.split(/\r\n|\r|\n/)) {
    if (/^[ \t]*(install|setup|tests)[_-]requires[ \t]*[=:]/i.test(line)) return true;
    if (/^[ \t]*\[[ \t]*options\.extras_require[ \t]*\]/i.test(line)) return true;
  }
  return false;
}
