import { join, posix } from "node:path";
import type { Finding } from "./types.js";
import { keyDigest, makeFinding } from "./types.js";
import { BASELINE_FILE, isIgnored } from "./baseline.js";
import type { ScanContext } from "./checks/context.js";
import { dedupe } from "./checks/context.js";
import { LOCAL_INSTALL_HOOKS, contentFindings, gypRunners, isLocalSpec, joinAnd } from "./checks/lifecycle.js";
import type { PackageJsonLike } from "./checks/lifecycle.js";
import { checkLockfile } from "./checks/lockfile.js";
import { WORKFLOW_PATH, checkWorkflow } from "./checks/workflows.js";
import { PERSISTENCE_PATH, checkPersistence } from "./checks/persistence.js";
import { MAX_TEXT_BYTES, stripBom } from "./fsutil.js";
import { LOCKFILE_NAMES, parseLockfileText, packageKey } from "./lockfile/index.js";
import type { ParsedLockfile } from "./lockfile/index.js";
import { gitBuildReader } from "./python/base-builds.js";
import { fileDigest, fsBuildReader, localBuild, type BuildReader, type LocalBuild } from "./python/build.js";
import { isPipConfName, isPylockFileName, isRequirementsName, isScriptLockName, isUnsupportedPyLock, isUvLockName, isUvTomlName, ownReader, setupCfgDeclares } from "./python/manifest.js";
import { parsePylock } from "./python/pylock.js";
import { isContentCandidate, looksLikeRequirements, MAX_SCRIPT_BYTES } from "./python/scripts.js";
import { contentDigest, decodeUtf8, get, isTable, parseToml, type TomlTable } from "./python/toml.js";
import { parseUvLock } from "./python/uvlock.js";
import { yamlPaths } from "./settings-yaml.js";
import { soakIdentity } from "./soak.js";
import { fold } from "./tree.js";
import type { Tree } from "./tree.js";

export interface DiffResult {
  findings: Finding[];
  notes: string[];
}

export interface DiffOptions {
  /** Path prefixes skipped on both sides (the baseline's ignorePaths). */
  ignore?: string[];
}

/** Local actions (`uses: ./path`) run in CI just like workflows. */
const ACTION_PATH = /(^|\/)action\.ya?ml$/;

/** A value as a message shows it: whole up to `max` characters, else cut there and ended with "...". */
const clip = (s: string, max: number): string => (s.length > max ? `${s.slice(0, max)}...` : s);
/** Long enough for packageManager and devEngines.packageManager each pinned with a sha512 hash (`pnpm@x.y.z+sha512.` and 128 hex digits). */
const MAX_PACKAGE_MANAGER_SHOWN = 400;
/** Where a maintainer's approval of a high diff finding is described: review it, then override the required check. */
const APPROVAL_DOCS = "https://github.com/stgllghr/wormsign/blob/main/docs/baseline.md#reviewing-baseline-changes";

/**
 * Files that change what an install runs (yarnPath, yarn-path, pnpmfile hooks, registries, release-age gates,
 * environment injected into package-manager subprocesses) or what this gate reports (the baseline). Any edit to them
 * needs a human reviewer. .env.yarn is loaded by Yarn 4 into every script (NODE_OPTIONS=--require=...), and
 * .corepack.env can set COREPACK_ENABLE_UNSAFE_CUSTOM_URLS so that a URL in packageManager is downloaded and run.
 */
const GATE_CONFIG = new Set([
  BASELINE_FILE,
  ".npmrc",
  ".yarnrc",
  ".yarnrc.yml",
  ".env.yarn",
  ".corepack.env",
  "pnpm-workspace.yaml",
  ".pnpmfile.cjs",
  ".pnpmfile.mjs",
  "bunfig.toml",
]);

/**
 * Code yarn runs straight from the repository at its default locations: releases and plugins (on every yarn command)
 * and the Plug'n'Play loaders (on every `yarn run`). Files config names elsewhere are found by configuredCode.
 */
const YARN_CODE = /(^|\/)(\.yarn\/(releases|plugins)\/|\.pnp\.cjs$|\.pnp\.loader\.mjs$)/;

/** Without a lockfile the next install resolves every version afresh, which is how a worm release gets in. */
const REMOVABLE_LOCKFILES = new Set<string>([...LOCKFILE_NAMES, "bun.lock", "bun.lockb"]);
/**
 * Files wormsign does not parse, so any change to them is reported: bun lockfiles, and the package.yaml and
 * package.json5 manifests that pnpm 11.16 reads instead of package.json, running their install scripts.
 */
const UNPARSED = new Set(["bun.lock", "bun.lockb", "package.yaml", "package.json5"]);
/** gyp files: next to a package.json without install scripts, npm, pnpm or Yarn 1 run node-gyp on them (see gypRunners). */
const GYP = /\.gyp$/;
/** Manifests, whose install scripts run wherever they are, so ignorePaths never hide them. */
const MANIFESTS = new Set(["package.json", "package.yaml", "package.json5"]);

const fileName = (path: string): string => path.split("/").pop() as string;
const baseName = (path: string): string => fold(fileName(path));
/** Also read by scan (WS-LC-004), so the two commands agree on which files these are. */
export const isGateConfig = (path: string): boolean => GATE_CONFIG.has(baseName(path)) || YARN_CODE.test(fold(path));
/**
 * pip's and uv's configuration files in the tree (pip.conf, pip.ini, uv.toml): where installs fetch from, whether they
 * check hashes, what they build. diff gates them as it gates .npmrc (WS-DF-005 on any edit). They are not in
 * GATE_CONFIG, which scan's WS-LC-004 also reads for settings that name code to run: neither file has such a setting.
 * soak reads uv.toml's and [tool.uv]'s index, hash and build settings, and, when it checks a requirements file or a
 * pylock.toml, fails closed on any committed pip.conf or pip.ini (src/python/indexes.ts).
 */
const isPythonInstallConfig = (path: string): boolean => isPipConfName(fileName(path)) || isUvTomlName(fileName(path));

const uncomment = (s: string): string => s.replace(/(^|\s)#.*$/, "").trim();
const unquote = (s: string): string => s.trim().replace(/^(["'])(.*)\1$/, "$2");

/** The keys of a YAML config whose values name code to run, read with soak's strict reader. */
const YAML_CODE_KEYS = new Map([
  ["pnpm-workspace.yaml", ["pnpmfile", "globalPnpmfile"]],
  [".yarnrc.yml", ["yarnPath", "plugins", "injectEnvironmentFiles"]],
]);

/**
 * Repository files that head's package-manager config names as code to run, relative to the config file as yarn 4.10
 * and pnpm 11.16 resolve them: yarnPath, plugins and injectEnvironmentFiles (.yarnrc.yml; an env file can set
 * NODE_OPTIONS=--require=...), yarn-path (.yarnrc), pnpmfile and globalPnpmfile (pnpm-workspace.yaml in pnpm 11),
 * pnpmfile and global-pnpmfile (.npmrc in pnpm 9) and script-shell (.npmrc, npm runs every script with it).
 * Pointing them somewhere else edits the config, which is gated. The YAML files are read with the same strict
 * subset as soak (Yarn 4.10.3 also reads `"yarnPath":` and `yarnPath :`), and a YAML config with anything outside it
 * is returned in `unread`, since the code it names could not be found. scan follows the same paths (WS-LC-004).
 */
export function configuredCode(head: Tree): { paths: Set<string>; unread: Finding[] } {
  const out = new Set<string>();
  const unread: Finding[] = [];
  for (const cfg of head.list()) {
    const name = baseName(cfg);
    // A config that cannot be followed to one file is reported as such (gateConfigFindings); its text means nothing.
    const text = ["pnpm-workspace.yaml", ".yarnrc.yml", ".yarnrc", ".npmrc"].includes(name) && head.unfollowed?.(cfg) === undefined ? head.read(cfg) : undefined;
    if (text === undefined) continue;
    const yamlKeys = YAML_CODE_KEYS.get(name);
    let values: string[];
    if (yamlKeys) {
      const doc = yamlPaths(text, yamlKeys);
      if (doc.problems.length > 0) {
        unread.push(
          makeFinding({
            ruleId: "WS-DF-006",
            severity: "high",
            message: `${fileName(cfg)} could not be interpreted (${doc.problems.slice(0, 3).join("; ").slice(0, 200)}), so the code it makes the package manager run was not followed`,
            file: cfg,
            key: `uninterpreted:${keyDigest(text)}`,
          }),
        );
      }
      values = [...doc.values].flatMap(([k, v]) => (k === "injectEnvironmentFiles" ? v.map((x) => x.replace(/\?$/, "")) : v));
    } else {
      // [ \t], not \s: under the m flag \s also matches newlines, which makes a file of blank lines quadratic. .npmrc
      // keys in any case, with _ for - and quoted or not, as pnpm 10.34.6 reads them and as scan's WS-LC-004 matches
      // them (CODE_SETTINGS in scan.ts): scan hashes the files found here, so a spelling missed here would leave the
      // file a baselined setting names free to change.
      values = [...text.matchAll(name === ".npmrc" ? /^[ \t]*["']?(?:script[-_]shell|(?:global[-_])?pnpmfile)["']?[ \t]*=(.*)$/gim : /^[ \t]*"?yarn-path"?[ \t]+(.*)$/gm)].map((m) => unquote(uncomment(m[1] as string)));
    }
    for (const v of values) {
      // ".." is dropped from the text, not climbed through links: pnpm 11.16 joins with path.join (path-absolute 2.0.0)
      // and yarn 4.10.3 with ppath.resolve before the file is opened.
      const p = posix.normalize(posix.join(posix.dirname(cfg), v));
      if (v && !posix.isAbsolute(v) && !p.startsWith("../")) out.add(p);
    }
  }
  return { paths: out, unread };
}

/** `text` is the new content, hashed into the key so that a baseline entry accepts this version only. */
function unreadable(path: string, text: string | undefined, why = "could not be read or parsed"): Finding {
  return makeFinding({
    ruleId: "WS-DF-006",
    severity: "high",
    message: `${fileName(path)} changed but ${why}, so nothing in it was checked`,
    file: path,
    key: `unreadable:${keyDigest(text ?? "")}`,
  });
}

/**
 * `stamp` (Tree.unfollowed) changes with any edit anywhere in the tree but its baseline file, because the path may lead
 * to anything in it: a baseline entry accepts this exact tree only. Any other edit, such as the next pull request,
 * moves the fingerprint, so the lasting fix is to replace the link with a file the tree holds.
 */
function unfollowed(path: string, stamp: string): Finding {
  return makeFinding({
    ruleId: "WS-DF-006",
    severity: "high",
    message: `${fileName(path)} cannot be followed to one file in this tree (a symlink to a name the tree lacks or leaves, a path through node_modules or another directory the install owns, a directory, a name that is not UTF-8, or a name another entry holds in another case), so what an install reads there was not checked`,
    file: path,
    key: `unfollowed:${keyDigest(stamp)}`,
  });
}

interface PackageJsonParts {
  scripts: Record<string, string>;
  /** Which package manager corepack fetches and runs: a release or, with a URL, any script. "" when unset. */
  packageManager: string;
  /** The workspaces field as JSON, "" when unset. */
  workspaces: string;
  /** "map\0name" -> spec, for each dependency spec that installs from a local path. */
  localSpecs: Map<string, string>;
  /** The fields that decide which package managers run node-gyp rebuild for a .gyp file beside it (see gypRunners). */
  gyp: { scripts: unknown; gypfile: unknown };
}

/**
 * The maps whose specs npm, yarn and pnpm install from: a local spec in any of them makes the package manager install
 * that directory or tarball and run its install scripts (npm 10.9.2, Yarn 1.22.22 and 4.10.3, pnpm 9.0.0).
 */
const SPEC_MAPS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "resolutions", "overrides"];

/** Whether a spec installs from the repository or the file system: npm's local specs, and Yarn's link: and portal:. */
const isLocalInstall = (spec: string): boolean => isLocalSpec(spec) || /^(link|portal|git\+file):/i.test(spec);

function localSpecs(pkg: Record<string, unknown>): Map<string, string> {
  const out = new Map<string, string>();
  const pnpm = pkg["pnpm"] && typeof pkg["pnpm"] === "object" ? (pkg["pnpm"] as Record<string, unknown>) : {};
  const maps: [string, unknown][] = [...SPEC_MAPS.map((m): [string, unknown] => [m, pkg[m]]), ["pnpm.overrides", pnpm["overrides"]]];
  // overrides nest; a bounded walk flattens them to "a > b" paths.
  const walk = (map: string, at: string, v: unknown, depth: number): void => {
    if (typeof v === "string") {
      if (isLocalInstall(v)) out.set(`${map}\0${at}`, v);
    } else if (v && typeof v === "object" && depth < 32) {
      for (const [k, w] of Object.entries(v)) walk(map, at ? `${at} > ${k}` : k, w, depth + 1);
    } else if (v && typeof v === "object") {
      out.set(`${map}\0${at}`, "(nested too deep to read)");
    }
  };
  for (const [map, deps] of maps) if (deps && typeof deps === "object") walk(map, "", deps, 0);
  return out;
}

function parsePackageJson(text: string): PackageJsonParts | undefined {
  try {
    const pkg = JSON.parse(stripBom(text)) as PackageJsonLike & { packageManager?: unknown; devEngines?: { packageManager?: unknown } };
    if (!pkg || typeof pkg !== "object" || Array.isArray(pkg)) return undefined;
    const scripts = Object.fromEntries(Object.entries(pkg.scripts ?? {}).filter(([, v]) => typeof v === "string")) as Record<string, string>;
    const pm = [pkg.packageManager, pkg.devEngines?.packageManager].filter((v) => v !== undefined);
    return {
      scripts,
      packageManager: pm.length ? JSON.stringify(pm) : "",
      workspaces: pkg["workspaces"] === undefined ? "" : JSON.stringify(pkg["workspaces"]),
      localSpecs: localSpecs(pkg),
      gyp: { scripts: pkg.scripts, gypfile: pkg.gypfile },
    };
  } catch {
    return undefined;
  }
}

/**
 * Changes to a manifest that make an install run other code without touching any script: a new or changed
 * `workspaces` field (npm and yarn install every workspace it matches and run its install scripts, even one whose
 * package.json is unchanged), or a dependency spec that now installs from a local path. Lockfiles in the pnpm 9+ and
 * yarn formats do not record install scripts, so this is the only place such a change shows.
 */
function installSetFindings(path: string, base: PackageJsonParts | undefined, head: PackageJsonParts): Finding[] {
  const out: Finding[] = [];
  if (head.workspaces && head.workspaces !== base?.workspaces) {
    out.push(
      makeFinding({
        ruleId: "WS-DF-005",
        severity: "high",
        message: `workspaces ${base?.workspaces ? "changed" : "set"} in this change: npm and yarn install every package it matches and run its install scripts: ${clip(head.workspaces, 120)}`,
        file: path,
        key: `workspaces:${keyDigest(head.workspaces)}`,
      }),
    );
  }
  for (const [where, spec] of head.localSpecs) {
    if (base?.localSpecs.get(where) === spec) continue;
    const [map, name] = where.split("\0") as [string, string];
    out.push(
      makeFinding({
        ruleId: "WS-DF-005",
        severity: "high",
        message: `${map} "${clip(name, 60)}" now installs from a local path (${clip(spec, 120)}): the package manager runs that package's install scripts`,
        file: path,
        key: `local-spec:${keyDigest(`${where}\0${spec}`)}`,
      }),
    );
  }
  return out;
}

function tryParseLock(path: string, text: string): ParsedLockfile | undefined {
  try {
    return parseLockfileText(path, stripBom(text));
  } catch {
    return undefined;
  }
}

/** Whether the lockfile format records install scripts at all: npm from lockfileVersion 2, pnpm before lockfile v9. */
function recordsInstallScripts(lock: ParsedLockfile, text: string): boolean {
  const v = Number(/lockfileVersion["']?\s*:\s*["']?(\d+)/.exec(text)?.[1]);
  if (lock.kind === "npm") return v >= 2;
  if (lock.kind === "pnpm") return v < 9;
  return false;
}

/** Gate config is checked even under ignorePaths: an ignored directory can still hold config an install reads. */
function gateConfigFindings(base: Tree, head: Tree, visible: (p: string) => boolean): Finding[] {
  const { paths: configured, unread: out } = configuredCode(head);
  // Folded: Tools/X.cjs and an added tools/x.cjs are one file on a Mac.
  const configuredFolded = new Set([...configured].map(fold));
  // Configured paths are read even when unlisted: a file under a symlinked directory is listed only as the link.
  for (const path of new Set([...head.list(), ...base.list(), ...configured])) {
    const gate = isGateConfig(path) || isPythonInstallConfig(path) || configuredFolded.has(fold(path));
    if (!gate && !(REMOVABLE_LOCKFILES.has(baseName(path)) && visible(path))) continue;
    // Reported on every run, changed or not: an edit to wherever the link really leads is invisible here.
    const stamp = gate ? head.unfollowed?.(path) : undefined;
    if (stamp !== undefined) {
      out.push(unfollowed(path, stamp));
      continue;
    }
    const before = base.read(path);
    const after = head.read(path);
    // An added or changed lockfile is checked entry by entry; only its removal is reported here.
    if (before === after || (!gate && after !== undefined)) continue;
    const verb = before === undefined ? "added" : after === undefined ? "removed" : "changed";
    out.push(
      makeFinding({
        ruleId: "WS-DF-005",
        severity: "high",
        message: gate
          ? `${fileName(path)} ${verb} in this change: it controls what installs run or what wormsign reports`
          : `${fileName(path)} removed in this change: the next install resolves every version afresh`,
        file: path,
        // The new content's hash is in the key, so a baseline entry can accept one reviewed version, never every later edit.
        key: after === undefined ? verb : `${verb}:${keyDigest(after)}`,
      }),
    );
  }
  return out;
}

/** A Python lockfile by its folded name (src/python/manifest.ts): uv.lock, pylock.toml, a script lock, an unsupported lock. */
const isPythonLockName = (name: string): boolean => isUvLockName(name) || isPylockFileName(name) || isScriptLockName(name) || isUnsupportedPyLock(name);

/**
 * A file's bytes as soak's content pass reads them (src/python/discover.ts): a regular file under exactly that name,
 * at most MAX_SCRIPT_BYTES; undefined for anything else (absent, a symlink, larger, which soak does not read either).
 * A blob git cannot read is read again with read(), which stops the run (exit 2) rather than call it absent. A tree
 * without Tree.entry (a directory tree) is read through read(), whose text is re-encoded: the hash rule then sees the
 * file as a reader that decodes it would.
 */
function contentBytes(tree: Tree, path: string): Buffer | undefined {
  const e = tree.entry?.(path, MAX_SCRIPT_BYTES);
  if (e?.kind === "file") return e.bytes;
  if (tree.entry !== undefined && (e === undefined || e.kind !== "problem" || e.why.startsWith("larger than"))) return undefined;
  const text = tree.read(path);
  return text === undefined ? undefined : Buffer.from(text, "utf8");
}

/**
 * Python lockfiles and requirements files the change adds, edits or removes. diff does not check what they pin:
 * `soak --base` checks that (publish age, the index's hashes, OSV). So that a change to one is never silent:
 * - a lockfile by name (uv.lock, pylock.toml, a script lock, poetry.lock, pdm.lock, Pipfile.lock) removed is WS-DF-005
 *   high, as npm's (the next install resolves every version afresh);
 * - a requirements file that was a hash lock in the base and is not in the head is WS-DF-005 high: removed, or its
 *   hashes removed, which is the same downgrade (pip then resolves what it names). A hash lock is what soak finds hash
 *   locks by (src/python/scripts.ts looksLikeRequirements: a --hash option or a --require-hashes line), whatever the
 *   file's name, so a lock soak found by its content (deps.txt, deps.lock.in, ci.pip: any file its content pass reads,
 *   isContentCandidate) counts as one found by name. The key holds the new content, so a baseline entry approves one
 *   reviewed version;
 * - any other change to a lockfile, a requirements file by name, or a hash lock by content (added, edited, removed
 *   when it held no hashes) is WS-DF-006 medium, keyed on the new content: visible in every report and SARIF upload,
 *   below the default --fail-on high, because the gate that checks them is soak, and failing diff on every dependency
 *   update, with no baseline entry that could pass it (diff reads the base's), would make diff unusable for Python
 *   repositories. A file found only by content that is no hash lock on either side (a script, notes) gives nothing.
 */
function pythonLockFindings(base: Tree, head: Tree, visible: (p: string) => boolean): Finding[] {
  const out: Finding[] = [];
  for (const path of new Set([...head.list(), ...base.list()])) {
    if (!visible(path)) continue;
    const name = fileName(path);
    const lockName = isPythonLockName(name);
    const byName = lockName || isRequirementsName(path);
    // Found by content only: what soak's content pass reads (src/python/scripts.ts), but no file with a reader of its own.
    if (!byName && (!isContentCandidate(name) || ownReader(name))) continue;
    let before: string | undefined;
    let after: string | undefined;
    let wasLock: boolean;
    let isLock: boolean;
    if (byName) {
      before = base.read(path);
      after = head.read(path);
      if (before === after) continue;
      wasLock = !lockName && before !== undefined && looksLikeRequirements(Buffer.from(before, "utf8"));
      isLock = !lockName && after !== undefined && looksLikeRequirements(Buffer.from(after, "utf8"));
    } else {
      // Every changed file of these kinds is read on both sides, so an unchanged one is told by its object id first.
      const blob = base.blob?.(path);
      if (blob !== undefined && blob === head.blob?.(path)) continue;
      const b = contentBytes(base, path);
      const a = contentBytes(head, path);
      if (b === a || (b !== undefined && a !== undefined && b.equals(a))) continue;
      wasLock = b !== undefined && looksLikeRequirements(b);
      isLock = a !== undefined && looksLikeRequirements(a);
      if (!wasLock && !isLock) continue;
      before = b?.toString("latin1");
      after = a?.toString("latin1");
    }
    const verb = before === undefined ? "added" : after === undefined ? "removed" : "changed";
    if (lockName && after === undefined) {
      out.push(makeFinding({ ruleId: "WS-DF-005", severity: "high", message: `${name} removed in this change: the next install resolves every version afresh`, file: path, key: verb }));
      continue;
    }
    if (wasLock && !isLock) {
      out.push(
        makeFinding({
          ruleId: "WS-DF-005",
          severity: "high",
          message:
            after === undefined
              ? `${name} removed in this change: it was a hash-locked requirements file, so the next install resolves every version afresh`
              : `${name} was a hash-locked requirements file and no longer is (its --hash options or --require-hashes line removed): pip resolves what it names afresh${byName ? "" : ", and soak no longer reads it"}`,
          file: path,
          key: after === undefined ? verb : `dehashed:${keyDigest(after)}`,
        }),
      );
      continue;
    }
    out.push(
      makeFinding({
        ruleId: "WS-DF-006",
        severity: "medium",
        message: `${name} ${verb} in this change, but diff does not check what Python lockfiles or requirements files pin, so nothing in it was checked here; \`wormsign soak --base <base>\` checks what it pins`,
        file: path,
        key: `python-lock:${verb}:${keyDigest(after ?? "")}`,
      }),
    );
  }
  return out;
}

/** The largest pyproject.toml diff parses for [tool.uv]; a larger one is unreadable (WS-DF-006 high). */
const MAX_PY_MANIFEST_BYTES = 16 * 1024 * 1024;

/** A table of the defined values in `entries`. */
const defined = (entries: [string, unknown][]): TomlTable => {
  const out: TomlTable = Object.create(null) as TomlTable;
  for (const [k, v] of entries) if (v !== undefined) out[k] = v;
  return out;
};

/**
 * [tool.uv] keys that shape the project, its resolution and its lock rather than where installs fetch from or what
 * they build: the ones uv reads only from a pyproject.toml (uv 0.10.9 refuses each in a uv.toml: the workspace's
 * members, the default groups, `package`, `managed`, dev-dependencies, the environments it resolves for, the ones it
 * must resolve for, and the extras or groups it keeps apart, conflicts); and ones a uv.toml may also hold: the
 * overrides and constraints the resolver applies, the uv versions it runs under, what makes uv rebuild a local
 * package (cache-keys), and the uv_build backend's settings for building this project (build-backend: module-name,
 * source-include, ...; no installer reads them, and soak keys a build it sees on them). Everything else in [tool.uv],
 * an unknown key included, is install configuration (publish-url among them: `uv publish` sends its credentials there).
 */
const UV_PROJECT_KEYS: readonly string[] = [
  "workspace", "default-groups", "package", "managed", "dev-dependencies",
  "override-dependencies", "constraint-dependencies", "environments", "required-environments", "conflicts", "required-version", "cache-keys", "build-backend",
];
/** The keys a [tool.uv.sources] entry may have when it installs from the tree. */
const IN_TREE_SOURCE_KEYS: ReadonlySet<string> = new Set(["workspace", "path", "editable", "package", "marker", "extra", "group"]);

/**
 * A [tool.uv.sources] entry (a table, or a list of them split by markers) that installs from the repository itself:
 * `{ workspace = true }`, or a relative `path` (editable or not) that stays inside the repository from `dir`, the
 * pyproject.toml's directory. A git, url or index source, or a path outside the repository, is not.
 */
function inTreeSource(v: unknown, dir: string): boolean {
  const one = (t: unknown): boolean => {
    if (!isTable(t) || Object.keys(t).some((k) => !IN_TREE_SOURCE_KEYS.has(k))) return false;
    const path = get(t, "path");
    if (path === undefined) return get(t, "workspace") === true;
    if (typeof path !== "string" || get(t, "workspace") !== undefined || path === "" || path.includes("\\") || posix.isAbsolute(path) || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(path)) return false;
    const at = posix.normalize(posix.join(dir, path));
    return at !== ".." && !at.startsWith("../");
  };
  return Array.isArray(v) ? v.length > 0 && v.every(one) : one(v);
}

/**
 * A pyproject.toml's [tool.uv] install configuration, as uv.toml holds the same settings: all of [tool.uv] but its
 * project-only keys (UV_PROJECT_KEYS) and the [tool.uv.sources] entries that install from the tree (inTreeSource), so
 * its indexes, its git, url and index sources, sources outside the repository, its build settings, exclude-newer and
 * any key not named above. A digest of it, "" when there is none. `path` is the pyproject.toml's, for where a path
 * source points.
 */
function uvInstallConfig(doc: TomlTable, path: string): string {
  const tool = get(doc, "tool");
  // A [tool] that is no table counts as uv's table: what uv reads from it is unknown.
  const uv = isTable(tool) ? get(tool, "uv") : tool;
  const dir = posix.dirname(path);
  const sources = isTable(uv) ? get(uv, "sources") : undefined;
  const rest = isTable(sources) ? Object.keys(sources).filter((k) => !inTreeSource(sources[k], dir)) : [];
  const config = isTable(uv)
    ? defined(
        Object.keys(uv)
          .filter((k) => !UV_PROJECT_KEYS.includes(k))
          .map((k) => [k, k === "sources" && isTable(sources) ? (rest.length > 0 ? defined(rest.map((r) => [r, sources[r]])) : undefined) : uv[k]]),
      )
    : uv;
  const none = config === undefined || (isTable(config) && Object.keys(config).length === 0);
  return none ? "" : contentDigest(config);
}

/**
 * Python manifests the change adds, edits or removes (pyproject.toml, setup.py, setup.cfg, Pipfile), compared whole:
 * any edit is WS-DF-006 medium, as for a Python lock. diff does not read what they declare; `soak --base` checks that
 * a lock covers each one's directory and what that lock pins (docs/soak.md). A changed [tool.uv] install
 * configuration (uvInstallConfig) is WS-DF-005 high, as uv.toml is, and is checked under ignorePaths too; a changed
 * build is pythonBuildFindings'. A pyproject.toml that cannot be parsed is WS-DF-006 high (unreadable), under
 * ignorePaths too: a [tool.uv] setting or a build requirement could hide in it.
 */
function pythonManifestFindings(base: Tree, head: Tree, visible: (p: string) => boolean): Finding[] {
  const out: Finding[] = [];
  for (const path of new Set([...head.list(), ...base.list()])) {
    const name = baseName(path);
    if (!["pyproject.toml", "setup.py", "setup.cfg", "pipfile"].includes(name)) continue;
    const shown = visible(path);
    if (name !== "pyproject.toml" && !shown) continue;
    const stamp = head.unfollowed?.(path);
    if (stamp !== undefined) {
      out.push(unfollowed(path, stamp));
      continue;
    }
    const before = base.read(path);
    const after = head.read(path);
    if (before === after) continue;
    const verb = before === undefined ? "added" : after === undefined ? "removed" : "changed";
    if (name === "pyproject.toml") {
      /** The digest of [tool.uv]'s install configuration; undefined when the text cannot be read. */
      const uv = (text: string | undefined): string | undefined => {
        if (text === undefined) return "";
        if (Buffer.byteLength(text) > MAX_PY_MANIFEST_BYTES) return undefined;
        const r = parseToml(stripBom(text));
        return "doc" in r ? uvInstallConfig(r.doc, path) : undefined;
      };
      const a = uv(after);
      if (a === undefined) {
        out.push(unreadable(path, after));
        continue;
      }
      // An unreadable base makes head's [tool.uv] count as added: noisier, never quieter.
      const b = uv(before) ?? "";
      if (a !== b) {
        out.push(
          makeFinding({
            ruleId: "WS-DF-005",
            severity: "high",
            message: `[tool.uv] in ${fileName(path)} ${a === "" ? "removed" : b === "" ? "added" : "changed"} in this change: uv reads its index settings, its git, url and index sources and its build settings there, which control what installs fetch and run`,
            file: path,
            key: `uv-config:${keyDigest(a)}`,
          }),
        );
      }
      if (!shown) continue;
    }
    out.push(
      makeFinding({
        ruleId: "WS-DF-006",
        severity: "medium",
        message: `${fileName(path)} ${verb} in this change: diff does not resolve Python dependencies${name === "setup.py" ? " (a setup.py declares whatever it computes when an install runs it)" : ""}, so nothing declared there was checked here; \`wormsign soak --base <base>\` checks that a lock covers its directory and what that lock pins, not that the lock pins what the manifest declares`,
        file: path,
        key: `python-manifest:${verb}:${keyDigest(after ?? "")}`,
      }),
    );
  }
  return out;
}

/**
 * The directory `dir` ("" for the top) of a tree as src/python/build.ts reads a project: a git tree through Tree.entry
 * (gitBuildReader: a blob's bytes undecoded, a symlink's link text), a directory tree from disk (fsBuildReader), as
 * soak reads them. A symlink among the build files also counts by what Tree.read reads through it (BuildReader.followed),
 * on both revisions: a pyproject.toml linked to ../shared/base.toml changes its build when base.toml does. undefined for a
 * tree that can show neither (test trees): no build is compared there.
 */
function buildReaderOf(tree: Tree, dir: string): BuildReader | undefined {
  const entry = tree.entry;
  const reader = entry !== undefined ? gitBuildReader({ entry: (rel) => entry(rel) }, dir) : tree.root === undefined ? undefined : fsBuildReader(dir === "" ? tree.root : join(tree.root, dir));
  return reader === undefined ? undefined : { entry: (rel) => reader.entry(rel), followed: (rel) => followedDigest(tree, dir === "" ? rel : `${dir}/${rel}`) };
}

/**
 * Per tree, the digest of what Tree.read reads at each path a build file's link was followed from (undefined: nothing),
 * by the path as Tree.read normalises it: each is read and hashed once per tree, however many projects reach it (a
 * project and one nested in it both list the .py files beside a hook in the inner one).
 */
const followedDigests = new WeakMap<Tree, Map<string, string | undefined>>();
function followedDigest(tree: Tree, path: string): string | undefined {
  const key = posix.normalize(path);
  let memo = followedDigests.get(tree);
  if (memo === undefined) followedDigests.set(tree, (memo = new Map()));
  if (!memo.has(key)) {
    const text = tree.read(key);
    memo.set(key, text === undefined ? undefined : fileDigest(Buffer.from(text, "utf8")));
  }
  return memo.get(key);
}

/** "" for the top directory, else the "/"-separated path, as diff lists paths. */
const dirOfPath = (path: string): string => {
  const d = posix.normalize(posix.dirname(path));
  return d === "." ? "" : d;
};

/**
 * The directories head's locks list as local projects: "built" for a uv.lock's directory or editable package and a
 * pylock.toml's directory entry, whose build soak itself reports (WS-SK-005, high in PR mode when the change makes it
 * new), "virtual" for a uv.lock's virtual package, which uv does not build. Only a lock soak reads: a regular file
 * outside ignorePaths, read as UTF-8 TOML; one it cannot read lists nothing, so its projects stay diff's: noisier,
 * never quieter.
 */
function lockedProjects(head: Tree, visible: (p: string) => boolean): Map<string, "built" | "virtual"> {
  const out = new Map<string, "built" | "virtual">();
  const add = (dir: string, how: "built" | "virtual"): void => {
    if (out.get(dir) !== "built") out.set(dir, how);
  };
  for (const path of head.list()) {
    const name = fileName(path);
    const uv = isUvLockName(name);
    if ((!uv && !isPylockFileName(name)) || !visible(path)) continue;
    const dir = dirOfPath(path);
    const e = buildReaderOf(head, dir)?.entry(name);
    if (e?.kind !== "file") continue;
    const text = decodeUtf8(e.bytes);
    const parsed = "text" in text ? parseToml(text.text) : undefined;
    if (parsed === undefined || !("doc" in parsed)) continue;
    const at = (rel: string): string => dirOfPath(posix.join(dir || ".", rel, "x"));
    try {
      if (uv) {
        for (const p of parseUvLock(parsed.doc).packages) {
          if (p.source.kind === "directory" || p.source.kind === "editable") add(at(p.source.path), "built");
          else if (p.source.kind === "virtual") add(at(p.source.path), "virtual");
        }
      } else {
        for (const p of parsePylock(parsed.doc).packages) {
          const s = p.source;
          if (s.kind === "directory") add(at(s.subdirectory === undefined ? s.path : s.path === "." ? s.subdirectory : `${s.path}/${s.subdirectory}`), "built");
        }
      }
    } catch {
      // A lock the reader cannot map lists nothing.
    }
  }
  return out;
}

/** pyproject.toml in `r`, as build.ts reads it: absent, parsed, or "unknown" (not a regular file, not UTF-8 TOML). */
function pyprojectOf(r: BuildReader): TomlTable | "absent" | "unknown" {
  const py = r.entry("pyproject.toml");
  if (py.kind === "missing") return "absent";
  if (py.kind !== "file") return "unknown";
  const text = decodeUtf8(py.bytes);
  const parsed = "text" in text ? parseToml(text.text) : undefined;
  return parsed !== undefined && "doc" in parsed ? parsed.doc : "unknown";
}

/**
 * Whether `r` holds a Python project an install can build: a setup.py; a pyproject.toml with [project] or
 * [build-system], or beside a setup.cfg that declares dependencies (setup_requires among them: setuptools' legacy
 * backend builds it); or one of them that cannot be read. A pyproject.toml that only configures tools is none. A
 * name that differs only in case (Setup.py) is read as a case-insensitive disk reads it: from disk, as the file; from
 * git, as a problem (Tree.entry: another entry's name folds like it), so it counts and the build is never the base's.
 */
function isProject(r: BuildReader): boolean {
  if (r.entry("setup.py").kind !== "missing") return true;
  const doc = pyprojectOf(r);
  if (doc === "absent") return false;
  if (doc === "unknown") return true;
  if (get(doc, "project") !== undefined || get(doc, "build-system") !== undefined) return true;
  const cfg = r.entry("setup.cfg");
  return cfg.kind !== "missing" && (cfg.kind !== "file" || setupCfgDeclares(cfg.bytes.toString("utf8")));
}

/**
 * A project uv records as virtual that names no build of its own: a pyproject.toml without [build-system], and no
 * setup.py or setup.cfg. uv does not build it, and pip would build it with the default setuptools backend and nothing
 * the project names. One that names a build (a lock left stale, or written to make diff look away) is compared.
 */
function namesNoBuild(r: BuildReader): boolean {
  if (r.entry("setup.py").kind !== "missing" || r.entry("setup.cfg").kind !== "missing") return false;
  const doc = pyprojectOf(r);
  return typeof doc === "object" && get(doc, "build-system") === undefined;
}

/**
 * A Python project whose build changes (WS-DF-005 high): every directory of head holding a project (isProject), its
 * key compared with the base's. The key is soak's own for a local build (src/python/build.ts localBuild: pyproject.toml
 * as parsed but its version, metadata and linters' tables, setup.cfg, setup.py, hatch.toml, uv.toml, the hook files and
 * backend-path files; diff's readers also count what a symlink among them leads to, BuildReader.followed), so a change
 * to a build file an install that builds the project (`pip install --no-deps .` included) reads is reported, and a
 * version bump or a linter's settings are not; what a hook or setup.py reads or imports when it runs is not. The
 * build requirements are resolved fresh: no lock pins them, and soak reports no build for a project no uv.lock or
 * pylock.toml lists. A project one does list as built (lockedProjects) is left to soak, which keys the same build, so
 * the change is not reported twice, and so is one a uv.lock lists as virtual that names no build (namesNoBuild): a
 * uv application, whose dependency edits would otherwise all be high. Checked under ignorePaths too, as [tool.uv] is:
 * an install builds a project wherever it is. A base without the project, or whose files there cannot be read
 * plainly (a name another folds like, a file over the cap), makes it new: noisier, never quieter.
 */
function pythonBuildFindings(base: Tree, head: Tree, visible: (p: string) => boolean): Finding[] {
  const out: Finding[] = [];
  // Each project's directory and its manifest as head lists it (a pyproject.toml before a setup.py).
  const manifests = new Map<string, string>();
  for (const path of head.list()) {
    const name = baseName(path);
    if (name !== "pyproject.toml" && name !== "setup.py") continue;
    const dir = dirOfPath(path);
    if (name === "pyproject.toml" || !manifests.has(dir)) manifests.set(dir, path);
  }
  const locked = manifests.size === 0 ? new Map<string, "built" | "virtual">() : lockedProjects(head, visible);
  for (const [dir, manifest] of [...manifests].sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0))) {
    const listed = locked.get(dir);
    if (listed === "built") continue;
    const h = buildReaderOf(head, dir);
    if (h === undefined || !isProject(h) || (listed === "virtual" && namesNoBuild(h))) continue;
    const after = localBuild(h);
    const b = buildReaderOf(base, dir);
    const was = b !== undefined && isProject(b);
    const before = b === undefined ? undefined : localBuild(b);
    if (was && before !== undefined && !before.unreadable && before.digest === after.digest) continue;
    // Which inputs differ, by name; none when only the base could not be read.
    const pairs = (x: LocalBuild | undefined): Set<string> => new Set(x === undefined ? [] : x.inputs.map(([n, v]) => `${n}\0${v}`));
    const [now, then] = [pairs(after), pairs(before)];
    const names = [...new Set([...[...now].filter((p) => !then.has(p)), ...[...then].filter((p) => !now.has(p))].map((p) => p.slice(0, p.indexOf("\0"))))].sort();
    const what = names.length > 0 ? names.join(", ") : "the build configuration or its hook and backend files";
    // Why part of the build was not read (src/python/build.ts LocalBuild.limits: a cap it is past, a path that climbs
    // from a link).
    const limits = [...new Set([...after.limits, ...(before?.limits ?? [])])];
    const past = limits.length > 0 ? `; not read in full, so counted as unreadable: ${limits.join("; ")}` : "";
    const where = dir === "" ? "the top directory" : dir;
    out.push(
      makeFinding({
        ruleId: "WS-DF-005",
        severity: "high",
        message: `The build of the Python project in ${where} ${was ? "changed" : "is new"} in this change (${what}${past}): an install that builds it (\`pip install --no-deps .\` included) first installs the build requirements its build configuration, hooks and backend name, resolved fresh; no lock pins them, and soak reports no build for a project that no uv.lock or pylock.toml lists`,
        file: manifest,
        key: `python-build:${keyDigest(after.digest)}`,
      }),
    );
  }
  return out;
}

export function diffTrees(base: Tree, head: Tree, ctx: ScanContext, opts: DiffOptions = {}): DiffResult {
  const visible = (p: string): boolean => !isIgnored(p, opts.ignore ?? []);
  const findings: Finding[] = [...gateConfigFindings(base, head, visible), ...pythonLockFindings(base, head, visible), ...pythonManifestFindings(base, head, visible), ...pythonBuildFindings(base, head, visible)];
  const notes: string[] = [];
  // Directories that hold a manifest in head: a .gyp file there can make npm, pnpm or Yarn 1 run node-gyp on install.
  // pnpm also reads package.yaml and package.json5 as the manifest; package.json wins where several exist.
  const manifestIn = new Map<string, string>();
  for (const p of head.list()) {
    const name = baseName(p);
    if (MANIFESTS.has(name) && (name === "package.json" || !manifestIn.has(posix.dirname(p)))) manifestIn.set(posix.dirname(p), p);
  }
  // .gyp files whose manifest makes a package manager run node-gyp on them in head that did not in base: the manifest
  // is new, or lost or emptied an install or preinstall script, or lost `gypfile: false`. npm, pnpm and Yarn 1 are compared one by one,
  // since they read different fields. The unchanged .gyp file then runs on the next install. An unreadable manifest
  // counts as running it under every package manager in head and none in base: noisier, never quieter.
  const gypTurnedOn = new Map<string, string[]>();
  for (const gyp of head.list().filter((p) => GYP.test(baseName(p)))) {
    const manifest = manifestIn.get(posix.dirname(gyp));
    if (manifest === undefined || head.unfollowed?.(manifest) !== undefined) continue;
    const name = baseName(gyp);
    const runners = (text: string | undefined, unreadable: string[]): string[] => {
      if (text === undefined) return [];
      const parsed = parsePackageJson(text);
      return parsed ? gypRunners(parsed.gyp, name) : unreadable;
    };
    const baseText = base.read(manifest);
    const headText = head.read(manifest);
    // An unchanged manifest turns nothing on; a changed one that is not JSON (package.yaml, package.json5) fails closed.
    if (baseText === headText) continue;
    const before = runners(baseText, []);
    const now = runners(headText, ["npm", "pnpm", "Yarn 1"]).filter((r) => !before.includes(r));
    if (now.length > 0) gypTurnedOn.set(gyp, now);
  }

  for (const path of head.list()) {
    const name = baseName(path);
    // ignorePaths hide content noise such as IOC strings in fixtures, never install-time scripts: an npm workspace
    // in an ignored directory runs its postinstall like any other, and a workflow runs an ignored local action
    // with `uses: ./that/dir`.
    if (!MANIFESTS.has(name) && !GYP.test(name) && !ACTION_PATH.test(fold(path)) && !visible(path)) continue;
    const isLockfile = LOCKFILE_NAMES.includes(name as (typeof LOCKFILE_NAMES)[number]);
    const isWorkflow = WORKFLOW_PATH.test(path) || ACTION_PATH.test(fold(path));
    const isGyp = GYP.test(name) && manifestIn.has(posix.dirname(path));
    const isPersistence = PERSISTENCE_PATH.test(fold(path));
    if (name !== "package.json" && !isLockfile && !isWorkflow && !isGyp && !isPersistence && !UNPARSED.has(name)) continue;
    const stamp = head.unfollowed?.(path);
    if (stamp !== undefined) {
      findings.push(unfollowed(path, stamp));
      continue;
    }
    const headText = head.read(path);
    const baseText = base.read(path);
    const gypEnabled = isGyp ? gypTurnedOn.get(path) : undefined;
    if (headText === baseText && !gypEnabled) continue;
    if (UNPARSED.has(name)) {
      findings.push(
        makeFinding({
          ruleId: "WS-DF-006",
          severity: "high",
          message: `${fileName(path)} changed, but wormsign does not parse ${name} files, so the scripts or dependencies it adds were not checked`,
          file: path,
          key: `unsupported:${keyDigest(headText ?? "")}`,
        }),
      );
      continue;
    }
    if (headText === undefined) {
      findings.push(unreadable(path, headText));
      continue;
    }

    if (isGyp) {
      const verb = baseText === undefined ? "added" : headText === baseText ? "enabled" : "changed";
      const what =
        verb === "enabled"
          ? `${fileName(path)} is unchanged, but the package.json beside it is added or changed in this change so that ${joinAnd(gypEnabled ?? [])} now run${gypEnabled?.length === 1 ? "s" : ""} node-gyp rebuild on it at install`
          : `${fileName(path)} ${verb} in this change: npm runs node-gyp rebuild on install for a package with a .gyp file and no install or preinstall script, and pnpm and Yarn 1 do for binding.gyp even with gypfile: false`;
      findings.push(
        makeFinding({
          ruleId: "WS-DF-002",
          severity: "medium",
          message: `${what}, and gyp <!(...) expansions run shell commands`,
          file: path,
          key: `gyp:${verb}:${keyDigest(headText)}`,
        }),
      );
      continue;
    }

    if (name === "package.json") {
      const parsedBase = baseText === undefined ? undefined : parsePackageJson(baseText);
      const before = parsedBase?.scripts ?? {};
      const parsed = parsePackageJson(headText);
      if (!parsed) {
        findings.push(unreadable(path, headText));
        continue;
      }
      const after = parsed.scripts;
      if (parsed.packageManager && parsed.packageManager !== parsedBase?.packageManager) {
        findings.push(
          makeFinding({
            ruleId: "WS-DF-005",
            severity: "high",
            // High even when the new value is pinned by hash (ruling R16): the hash proves which binary it is, not that it is the right one.
            message: `packageManager set or changed in this change: corepack downloads and runs ${clip(parsed.packageManager, MAX_PACKAGE_MANAGER_SHOWN)}. This is high even when the value is pinned by hash, because it changes which package-manager binary runs every install and script here: a maintainer checks that the version and its hash are the package manager's own release, then merges with an override of the required check (${APPROVAL_DOCS})`,
            file: path,
            key: `packageManager:${keyDigest(parsed.packageManager)}`,
          }),
        );
      }
      findings.push(...installSetFindings(path, parsedBase, parsed));
      for (const hook of LOCAL_INSTALL_HOOKS) {
        const cmd = after[hook];
        if (cmd === undefined || cmd === before[hook]) continue;
        const verb = before[hook] === undefined ? "added" : "changed";
        findings.push(
          makeFinding({
            ruleId: "WS-DF-002",
            severity: "medium",
            message: `"${hook}" script ${verb} in this change: ${clip(cmd, 120)}`,
            file: path,
            key: `${hook}:${verb}:${keyDigest(cmd)}`,
          }),
        );
        // lifecycle's keys do not depend on the script's text. Here the script is always new, so the key names this
        // version of it, and a baseline entry for one suspicious script does not accept the next.
        findings.push(...contentFindings(path, hook, cmd, undefined, ctx).map((f) => makeFinding({ ...f, key: `${f.key}:${keyDigest(cmd)}` })));
      }
      continue;
    }

    if (isWorkflow) {
      const what = WORKFLOW_PATH.test(path) ? "Workflow" : "Local action";
      findings.push(
        makeFinding({
          ruleId: "WS-DF-003",
          severity: "medium",
          message: baseText === undefined ? `${what} added in this change` : `${what} modified in this change`,
          file: path,
          key: `${baseText === undefined ? "added" : "modified"}:${keyDigest(headText)}`,
        }),
      );
      // The same cap as scan: a workflow is never this large, and the gate's run time must not be the author's choice.
      if (Buffer.byteLength(headText) > MAX_TEXT_BYTES) findings.push(unreadable(path, headText, `is larger than ${MAX_TEXT_BYTES / 1024 / 1024} MiB`));
      else findings.push(...checkWorkflow(path, headText, ctx));
      continue;
    }

    if (isPersistence) {
      // An editor or agent setting that runs a command when a folder opens or a session starts: no install step
      // needed, so a change that adds or edits one is checked here as scan checks it.
      if (Buffer.byteLength(headText) > MAX_TEXT_BYTES) findings.push(unreadable(path, headText, `is larger than ${MAX_TEXT_BYTES / 1024 / 1024} MiB`));
      else findings.push(...checkPersistence(path, headText, ctx));
      continue;
    }

    const headLock = tryParseLock(path, headText);
    if (!headLock) {
      findings.push(unreadable(path, headText));
      continue;
    }
    const baseLock = baseText === undefined ? undefined : tryParseLock(path, baseText);
    // An unparseable base only makes every entry count as new: noisier, never quieter.
    if (baseText !== undefined && !baseLock) notes.push(`could not parse ${path} at ${base.label}; every entry in it is treated as new`);
    // What the installer fetches, not the label: an entry relabelled to another tarball or integrity is a new entry.
    const baseKeys = new Set((baseLock?.packages ?? []).map(soakIdentity));
    const baseByName = new Map<string, boolean>();
    for (const p of baseLock?.packages ?? []) baseByName.set(p.name, baseByName.get(p.name) === true || p.hasInstallScript === true);

    const added = headLock.packages.filter((p) => !baseKeys.has(soakIdentity(p)));
    if (!recordsInstallScripts(headLock, headText)) {
      notes.push(
        `${path}: this ${headLock.kind} lockfile format does not record install scripts, so new dependencies with install scripts cannot be detected from it; use 'wormsign scan --node-modules' after install`,
      );
    }
    for (const p of added) {
      // A local entry (a workspace or file: directory) counts too: the change may make an install run the install
      // scripts of a package.json it does not touch, by adding it as a workspace or a file: dependency.
      if (p.hasInstallScript !== true) continue;
      const existed = baseByName.has(p.name);
      const hadScript = baseByName.get(p.name) === true;
      if (existed && hadScript) continue; // already ran scripts before; version bump only
      const what = p.local ? `local package ${packageKey(p)}` : packageKey(p);
      findings.push(
        makeFinding({
          ruleId: existed ? "WS-DF-004" : "WS-DF-001",
          severity: "high",
          message: existed ? `${what} now has install scripts (the previous version did not)` : `New dependency ${what} runs install scripts`,
          file: path,
          key: p.local ? `local:${packageKey(p)}` : packageKey(p),
        }),
      );
    }
    // Registry/IOC/integrity problems, but only for entries this change introduced (by artifact, not name@version).
    findings.push(...checkLockfile({ ...headLock, packages: added }, ctx));
  }
  // The same name@version can sit at several lockfile paths; report it once, as scan does.
  return { findings: dedupe(findings), notes };
}
