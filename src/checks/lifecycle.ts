import { readdirSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, posix, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import type { Finding, Severity } from "../types.js";
import { keyDigest, makeFinding, severityRank } from "../types.js";
import type { ScanContext } from "./context.js";
import { capped, notChecked } from "./context.js";

/** Run for every consumer when the package is installed from a registry. */
export const INSTALL_HOOKS = ["preinstall", "install", "postinstall"] as const;

/**
 * Every script an install runs in the project itself and its workspaces. Checked by writing a marker from every
 * candidate script: npm 10.9.2 (`install` and `ci`) ran all but pnpm:devPreinstall; pnpm 11.16.0 ran pre/post/install,
 * the prepare family and pnpm:devPreinstall; yarn 1.22.22 ran pre/post/install, prepublish and prepare. Those beyond
 * INSTALL_HOOKS do not run when the package is installed as a registry dependency, so scan checks only their content
 * ("prepare" alone is usually husky); diff reports any change to any of them.
 */
export const LOCAL_INSTALL_HOOKS = [
  ...INSTALL_HOOKS,
  "prepublish",
  "preprepare",
  "prepare",
  "postprepare",
  "predependencies",
  "dependencies",
  "postdependencies",
  "pnpm:devPreinstall",
] as const;

/**
 * Real install scripts are short. Checking only a bounded prefix keeps the
 * regexes below cheap on hostile input, and a longer script is itself reported.
 */
const MAX_SCRIPT_CHARS = 4096;

/**
 * Heuristics for what an install script does. These are patterns, not IOCs, so
 * they have no source URL; they target behaviour the reported worms share
 * (download-and-run, encoded payloads, credential reads, TruffleHog, Bun bootstrap).
 */
const SUSPICIOUS: { re: RegExp; why: string }[] = [
  { re: /\b(curl|wget)\b[^|;&\n]*\|\s*(sudo(\s+-\S+)*\s+)?(env\s+)?(\S*\/)?((ba|z|da|k)?sh|node|bun|python[0-9.]*|perl|ruby)\b/i, why: "pipes a download into a shell or interpreter" },
  { re: /(<\(|\$\(|`)\s*(curl|wget)\b/i, why: "uses a download's output through command or process substitution" },
  { re: /\b(curl|wget)\b[^\n]*\bbun\.sh\b/i, why: "downloads the Bun runtime" },
  { re: /\btrufflehog\b/i, why: "invokes TruffleHog (secret scanner)" },
  { re: /\bbase64\b[^\n]*\s(-[a-z]*d[a-z]*|--decode)\b|\batob\s*\(|Buffer\.from\([^)]*['"]base64['"]/i, why: "decodes an encoded payload" },
  { re: /\beval\s*\(|\bnew Function\s*\(/, why: "evaluates dynamic code" },
  { re: /(\.npmrc|\.aws\/credentials|\.config\/gh|\.ssh\/|\bNPM_TOKEN\b|\bGITHUB_TOKEN\b|\bGH_TOKEN\b)/, why: "reads credential files or token variables" },
  { re: /\bnpm\s+(publish|token)\b/i, why: "publishes packages or manages tokens" },
  { re: /\bgh\s+(auth\s+token|repo\s+(edit|create)|api)\b/i, why: "uses the GitHub CLI with credentials" },
];

export interface PackageJsonLike {
  name?: string;
  version?: string;
  private?: boolean;
  scripts?: Record<string, unknown>;
  [field: string]: unknown;
}

/** The manifest as an object, or undefined when it is not one: `null`, `[]` and `"x"` all parse without error. */
export function parseManifest(text: string): PackageJsonLike | undefined {
  try {
    const v: unknown = JSON.parse(text);
    return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as PackageJsonLike) : undefined;
  } catch {
    return undefined;
  }
}

export function suspiciousReasons(cmd: string): string[] {
  const head = cmd.slice(0, MAX_SCRIPT_CHARS);
  const out = SUSPICIOUS.filter((s) => s.re.test(head)).map((s) => s.why);
  if (cmd.length > MAX_SCRIPT_CHARS) out.push(`is ${cmd.length} characters long; only the first ${MAX_SCRIPT_CHARS} were checked`);
  return out;
}

/** Flags whose value names a file the command writes, not one it runs. */
const OUTPUT_FLAG = /^(-o|--out(put|file|dir|-file|-dir)?)$/;

/**
 * Names a script may execute. Recall comes first, because WS-LC-003 is the only
 * signal for a payload whose name alone is low severity: every word counts
 * (`cat x | node`, `node < x`, `--require=x`, `NODE_OPTIONS`, `npx tsx x`) except
 * one in an output position, a `>` target or an output flag's value such as
 * `--outfile dist/bundle.js`. Node resolves `node bundle` and `require('./bundle')`
 * to bundle.js, so those also yield the `.js` name. Best effort, not a shell parser.
 */
export function executedFiles(cmd: string): string[] {
  const head = cmd.slice(0, MAX_SCRIPT_CHARS);
  const out: string[] = [];
  for (const m of head.matchAll(/\b(?:require|import)\s*\(\s*['"]([^'"]+)['"]/g)) out.push(m[1] as string, `${m[1]}.js`);
  const toks = head
    .replace(/>+&?\s*[^\s;&|()<>]*/g, " ")
    .split(/[\s"'`;&|()<=]+/)
    .filter((t) => t !== "");
  toks.forEach((t, i) => {
    if (!OUTPUT_FLAG.test(toks[i - 1] ?? "")) out.push(t);
    if (/^node(js)?$/.test(t.split("/").pop() as string)) {
      const arg = toks.slice(i + 1).find((a) => !a.startsWith("-"));
      if (arg) out.push(`${arg}.js`);
    }
  });
  return out;
}

/**
 * Line of a package.json "scripts" entry where `hook` appears, for a best-effort line number. The search starts at
 * the "scripts" key, since a script can share its name with a top-level field ("dependencies").
 */
function lineOfScript(text: string, hook: string): number | undefined {
  const lines = text.split("\n");
  const from = Math.max(0, lines.findIndex((l) => /"scripts"\s*:/.test(l)));
  const re = new RegExp(`"${hook}"\\s*:`); // hook is one of LOCAL_INSTALL_HOOKS: no regex syntax
  const i = lines.findIndex((l, n) => n >= from && re.test(l));
  return i === -1 ? undefined : i + 1;
}

/** The scanned project: its real path, and whether a posix path relative to it is one the baseline excludes from the scan. */
export interface Project {
  root: string;
  isIgnored: (rel: string) => boolean;
  /** The baseline's ignorePaths prefixes, relative to root. */
  ignored?: string[];
}

/**
 * Checks one package.json that belongs to the project being scanned (not
 * node_modules; see checkInstalledPackage for those).
 */
export function checkLifecycle(file: string, text: string, ctx: ScanContext, project: Project = { root: "/", isIgnored: () => false }): Finding[] {
  const pkg = parseManifest(text);
  if (!pkg) return [notChecked(file, "it is not a valid JSON object, so its scripts could not be read", "high", text)];
  const out: Finding[] = [];
  const scripts = pkg.scripts && typeof pkg.scripts === "object" ? pkg.scripts : {};
  for (const hook of LOCAL_INSTALL_HOOKS) {
    const cmd = scripts[hook];
    if (typeof cmd !== "string") continue;
    const line = lineOfScript(text, hook);
    // The key covers the script's text, as workflow and editor-task keys cover theirs, so a baseline entry approves
    // this command only: replacing a reviewed script with another reports it again, even where no diff runs (a push
    // with a stolen token). LC-002 and LC-003 get the same suffix diff gives them, so one entry fits both commands.
    const sha = keyDigest(cmd);
    if ((INSTALL_HOOKS as readonly string[]).includes(hook)) {
      const published = pkg.private !== true;
      out.push(
        makeFinding({
          file,
          key: `${hook}:${sha}`,
          ...(line ? { line } : {}),
          ruleId: "WS-LC-001",
          severity: published ? "medium" : "low",
          message: `"${hook}" script runs on install${published ? " for every consumer of this package" : " (private package: runs only for local installs)"}: ${cmd.slice(0, 120)}`,
        }),
      );
    }
    out.push(...contentFindings(file, hook, cmd, line, ctx).map((f) => makeFinding({ ...f, key: `${f.key}:${sha}` })));
  }
  out.push(...gypFindings(file, pkg, project));
  return [...out, ...hiddenLocalDependencies(file, pkg, project), ...hiddenWorkspaces(file, pkg, project)];
}

/**
 * Which package managers run `node-gyp rebuild` at install for a .gyp file named `name` beside this manifest, so that
 * gyp runs the shell command in each `<!(...)` expansion. Each tests a script by truthiness, so `"install": ""` counts
 * as none.
 * - npm 10.9.2 (@npmcli/run-script, @npmcli/package-json): any *.gyp file, with no install or preinstall script and
 *   gypfile not false.
 * - pnpm 11.16.0: binding.gyp, with no install or preinstall script. It does not read gypfile.
 * - Yarn 1.22.22: binding.gyp, with no install script. It reads neither preinstall nor gypfile.
 * The binding.gyp test ignores case, as macOS and Windows file systems do.
 */
export function gypRunners(pkg: { scripts?: unknown; gypfile?: unknown }, name: string): string[] {
  const s = pkg.scripts && typeof pkg.scripts === "object" ? (pkg.scripts as Record<string, unknown>) : {};
  const binding = /^binding\.gyp$/i.test(name);
  const out: string[] = [];
  if (!s["install"] && !s["preinstall"] && pkg.gypfile !== false && /\.gyp$/i.test(name)) out.push("npm");
  if (!s["install"] && !s["preinstall"] && binding) out.push("pnpm");
  if (!s["install"] && binding) out.push("Yarn 1");
  return out;
}

/** "a", "a and b", "a, b and c". */
export const joinAnd = (xs: readonly string[]): string => (xs.length < 3 ? xs.join(" and ") : `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`);

/**
 * A .gyp file beside the manifest that npm, pnpm or Yarn 1 builds at install (see gypRunners) is an install script:
 * reported like a declared one. The file's name is all that is read.
 */
function gypFindings(file: string, pkg: PackageJsonLike, project: Project): Finding[] {
  const dir = file.includes("/") ? file.slice(0, file.lastIndexOf("/")) : "";
  let names: string[];
  try {
    names = readdirSync(join(project.root, dir)).filter((n) => /\.gyp$/i.test(n)).sort();
  } catch {
    return [];
  }
  const runners = new Set<string>();
  const run = names.filter((n) => {
    const r = gypRunners(pkg, n);
    for (const x of r) runners.add(x);
    return r.length > 0;
  });
  if (run.length === 0) return [];
  const published = pkg.private !== true;
  const who = joinAnd([...runners]);
  const scripts = pkg.scripts && typeof pkg.scripts === "object" ? pkg.scripts : {};
  const npmSkips = runners.has("npm") ? "" : `; npm does not, because of ${scripts["preinstall"] ? "the preinstall script" : "gypfile: false"}, which ${who} ignore${runners.size > 1 ? "" : "s"}`;
  return [
    makeFinding({
      file,
      key: "gyp",
      ruleId: "WS-LC-001",
      severity: published ? "medium" : "low",
      message: `${run.join(", ").slice(0, 120)} present: ${who} run node-gyp rebuild on install${published ? " for every consumer of this package" : ""}${npmSkips}, and gyp <!(...) expansions run shell commands`,
    }),
  ];
}

/** Characters that make a path segment a glob in npm's and yarn's workspace patterns. */
const GLOB = /[*?[\]{}!+@()]/;

/**
 * Whether a workspace pattern, as segments relative to the root, can match a directory at or under `target`: a glob
 * segment may match anything, and `**` anything below it.
 */
function reaches(pattern: string[], target: string[]): boolean {
  for (const [k, t] of target.entries()) {
    const s = pattern[k];
    if (s === undefined) return false;
    if (s === "**") return true;
    if (!GLOB.test(s) && fold(s) !== fold(t)) return false;
  }
  return true;
}

/**
 * WS-SC-900 for each npm or yarn `workspaces` pattern that can match a package the scan does not read: under an
 * ignored path, node_modules or .git, or outside the repository. npm 10.9.2 installed such a workspace and ran its
 * install scripts. Patterns are matched by their text, not against the file system.
 */
function hiddenWorkspaces(file: string, pkg: PackageJsonLike, project: Project): Finding[] {
  const ws = pkg.workspaces;
  const raw: unknown = Array.isArray(ws) ? ws : ws && typeof ws === "object" ? (ws as { packages?: unknown }).packages : undefined;
  if (!Array.isArray(raw)) return [];
  return hiddenPatterns(file, raw, "workspaces", "npm and yarn run the install scripts of every workspace", project);
}

/** Patterns are relative to the file's directory, and matched by their text, not against the file system. */
function hiddenPatterns(file: string, patterns: readonly unknown[], field: string, runs: string, project: Project): Finding[] {
  const dir = file.includes("/") ? file.slice(0, file.lastIndexOf("/")) : "";
  const found = capped(MAX_LISTED);
  for (const p of patterns) {
    if (typeof p !== "string" || p.startsWith("!")) continue;
    const full = posix.normalize(posix.join(dir || ".", p.replace(/\\/g, "/")));
    const segs = full.split("/").filter((s) => s !== "" && s !== ".");
    const why = posix.isAbsolute(p) || full === ".." || full.startsWith("../")
      ? "outside the repository"
      : segs.some((s) => ["node_modules", ".git"].includes(fold(s)))
        ? "inside node_modules or .git"
        : (project.ignored ?? []).some((i) => reaches(segs, i.split("/")))
          ? "in a path the baseline excludes from the scan"
          : undefined;
    if (why) found.add(`${field}:${keyDigest(p)}`, (k) => makeFinding({ ruleId: "WS-SC-900", severity: "high", file, key: k, message: `${field} pattern "${p.slice(0, MAX_LABEL)}" can match a package ${why}, which wormsign does not scan, and ${runs}` }));
  }
  return found.done((more, key) => makeFinding({ ruleId: "WS-SC-900", severity: "high", file, key: `${field}:${key}`, message: `${more} more ${field} patterns that reach unscanned paths were not listed one by one` }));
}

/**
 * npm 10.9.2 ran the install scripts of a local path dependency
 * (`file:./node_modules/.cache/evil`, `./NODE_MODULES/x` on macOS,
 * `file:./vendor/x.tgz`) from each of these maps; pnpm 11.16 held them for
 * approve-builds.
 */
const DEPENDENCY_MAPS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];

/** npm-package-arg's own tarball test: its unescaped "." also makes `x.tar_gz` a tarball. */
const TARBALL = /[.](?:tgz|tar.gz|tar)$/i;

/** npm 10.9.2 ran the install scripts of a `git+file:///abs/repo` dependency, whose package.json sits in packed git objects. */
const GIT_FILE = /^git\+file:/i;

/** npm nests overrides one level per dependency hop, so real ones are shallow. */
const MAX_OVERRIDE_DEPTH = 32;

/** Local-spec findings listed one by one per manifest; a 2 MiB manifest can hold 100,000 specs. */
const MAX_LISTED = 50;

/** Labels show at most this much of a name or override key; fingerprints use the whole of it. */
const MAX_LABEL = 60;

/**
 * Whether npm installs a dependency spec from a local path. Follows
 * npm-package-arg 12 (npm 10.9.2): a spec is local when it starts with file:,
 * ".", "~/" or a drive letter, or when it is not a URL or GitHub user/repo
 * shorthand and has a slash or a tarball name. A "%" can make npm's shorthand
 * parse fail, so a spec with one is never shorthand.
 */
export function isLocalSpec(spec: string): boolean {
  return (
    /^(file:|\.|~\/|[a-z]:)/i.test(spec) ||
    (!/^(git\+)?[a-z]{2,}:/i.test(spec) && !/^[^\s@:/.#%][^\s@:/#%]*\/[^\s@:/#%]+(#[^%]*)?$/.test(spec) && (/[\\/]/.test(spec) || TARBALL.test(spec)))
  );
}

/**
 * The absolute path a local spec installs from, as npm-package-arg 12's
 * fromFile (npm 10.9.2) resolves it against the manifest's directory `where`:
 * as a file: URL (parsing drops tabs and newlines, trims control characters and
 * spaces, cuts query and fragment, and removes dot segments, even after an
 * undecodable "%zz"), then percent-decoded, so `node%5Fmodules` is node_modules.
 * Like npm, it reads file://host/x as file:///host/x, file:/../x as file:../x,
 * and ~/x under the home directory. Throws where npm would. The base is
 * percent-encoded, so a directory named `a#b`, `q?r` or `100%` is not cut short
 * or decoded into another one.
 */
function localTarget(spec: string, where: string): string {
  const base = pathToFileURL(where + sep).href;
  let raw = (spec.startsWith("file:") ? "" : "file:") + spec;
  // URL parsing already reads file://localhost/x as file:///x.
  if (new URL(raw, base).host) raw = raw.replace(/^file:\/\//, "file:///");
  if (/^\/{1,3}\.\.?(\/|$)/.test(raw.slice(5))) raw = raw.replace(/^file:\/{1,3}/, "file:");
  const specPath = decodeURIComponent(new URL(raw).pathname);
  return /^\/~(\/|$)/.test(specPath) ? resolve(homedir(), specPath.slice(3)) : resolve(where, decodeURIComponent(new URL(raw, base).pathname));
}

/** Case-folded, as macOS file systems fold case: npm installed ./NODE_MODULES/x and ./node_moduleſ/x there. */
const fold = (s: string): string => s.toUpperCase().toLowerCase();

/**
 * Why a scan cannot see the package a spec installs from the local file
 * system, or undefined when it can (or the spec is not local). `dir` is the
 * manifest's directory: npm, Yarn and pnpm resolve a relative path against it.
 * The target is compared with the real root after following links, so a path
 * that leaves the repository and comes back in (`../repo/x`), or an absolute
 * one, is still seen to land where it does.
 */
function unscannedReason(spec: string, dir: string, project: Project): string | undefined {
  if (GIT_FILE.test(spec)) return "a git repository on the local file system, which wormsign does not read";
  if (!isLocalSpec(spec)) return undefined;
  if (TARBALL.test(spec)) return "a tarball wormsign does not unpack";
  let target: string;
  try {
    target = localTarget(spec, join(project.root, dir));
  } catch {
    return "a path wormsign could not decode, so it could not tell where that is";
  }
  try {
    target = realpathSync(target);
  } catch {
    // Not there, so nothing to install yet: judge the path as written.
  }
  const rel = relative(fold(project.root), fold(target));
  const inside = rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
  const segments = (inside ? rel : fold(target)).split(sep);
  if (segments.includes("node_modules") || segments.includes(".git")) return "inside node_modules or .git, which wormsign does not scan as part of the project";
  if (inside && project.isIgnored(rel.split(sep).join("/"))) return "in a path the baseline excludes from the scan";
  return undefined;
}

/**
 * WS-SC-900 for each dependency the package manager would install, and run the
 * install scripts of, from a place the scan does not read. Each finding's key
 * holds a digest of the whole entry (full name or override path, and spec), so
 * a baseline entry for one spec never covers another.
 */
function hiddenLocalDependencies(file: string, pkg: PackageJsonLike, project: Project): Finding[] {
  const dir = file.includes("/") ? file.slice(0, file.lastIndexOf("/")) : "";
  const found = capped(MAX_LISTED);
  const unchecked = (key: string, message: () => string): void => found.add(key, (k) => makeFinding({ ruleId: "WS-SC-900", severity: "high", file, key: k, message: message() }));
  // Yarn 1.22.22 and 4.10.3 (`resolutions`) and pnpm 9.0.0 (`pnpm.overrides`) resolved a file: target against the root
  // manifest and ran its install scripts, whatever the key's pattern (`evil`, `a/**/evil`). pnpm 11.16 ignores
  // pnpm.overrides and reads overrides from pnpm-workspace.yaml instead: see checkPnpmWorkspace.
  const pnpm = pkg.pnpm && typeof pkg.pnpm === "object" ? (pkg.pnpm as Record<string, unknown>) : {};
  const maps: [string, unknown][] = [...DEPENDENCY_MAPS.map((m): [string, unknown] => [m, pkg[m]]), ["resolutions", pkg.resolutions], ["pnpm.overrides", pnpm.overrides]];
  for (const [map, deps] of maps) {
    if (!deps || typeof deps !== "object") continue;
    for (const [name, spec] of Object.entries(deps)) {
      const why = typeof spec === "string" ? unscannedReason(spec, dir, project) : undefined;
      if (why) unchecked(`${map}:${name.slice(0, MAX_LABEL)}=${keyDigest(`${map}\0${name}\0${spec}`)}`, () => `${map} "${name.slice(0, MAX_LABEL)}" installs ${spec.slice(0, 120)}, ${why}, and the package manager runs its install scripts`);
    }
  }
  // npm resolves a local override against the package that depends on it, usually inside node_modules, so any local override is unchecked.
  // `at` is the label, cut short so a hostile manifest cannot repeat one long key in every label below it; `id` digests the full path.
  const walk = (v: unknown, at: string, id: string, depth: number): void => {
    if (typeof v === "string" && (isLocalSpec(v) || GIT_FILE.test(v))) {
      unchecked(`overrides:${at}=${keyDigest(`${id}\0${v}`)}`, () => `overrides "${at}" installs ${v.slice(0, 120)}, a local path wormsign did not check: npm resolves it against the dependent package and runs its install scripts`);
    } else if (v && typeof v === "object" && depth === MAX_OVERRIDE_DEPTH) {
      unchecked(`overrides:${at}=${id}`, () => `overrides "${at}" nests deeper than ${MAX_OVERRIDE_DEPTH} levels, so wormsign did not check what it installs`);
    } else if (v && typeof v === "object") {
      for (const [k, w] of Object.entries(v)) walk(w, at ? `${at} > ${k.slice(0, MAX_LABEL)}` : k.slice(0, MAX_LABEL), keyDigest(`${id}\0${k}`), depth + 1);
    }
  };
  walk(pkg.overrides, "", "", 0);
  return found.done((more, key) => makeFinding({ ruleId: "WS-SC-900", severity: "high", file, key: `local-specs:${key}`, message: `${more} more local dependency specs that wormsign could not check were not listed one by one` }));
}

/**
 * WS-SC-900 for each override in a pnpm-workspace.yaml that installs from a
 * place the scan does not read. pnpm 11.16 reads overrides there, not from
 * package.json, resolves a file: value against the workspace root, and ran the
 * install scripts of `evil: "file:./node_modules/.cache/evil"` (verified with
 * dangerouslyAllowAllBuilds; without it pnpm still installed the package). With
 * no YAML parser, only a block map of one-line scalars under a top-level
 * `overrides:` is read; any other shape fails closed.
 *
 * Also WS-SC-900 for each `packages:` pattern that can match a package the scan
 * does not read, as for npm and yarn workspaces: pnpm 11.16.0 installed
 * `vendor/x` from `packages: ["vendor/*"]`, with vendor in ignorePaths, and ran
 * its postinstall. Only a block list of one-line scalars, or a one-line flow
 * list of them, is read; any other shape fails closed.
 */
export function checkPnpmWorkspace(file: string, text: string, project: Project): Finding[] {
  const dir = file.includes("/") ? file.slice(0, file.lastIndexOf("/")) : "";
  const unread = (why: string, n: number, what = "the overrides pnpm installs in place of dependencies"): Finding[] => [notChecked(file, `${why} on line ${n}, so wormsign could not read ${what}`)];
  const unreadPackages = (why: string, n: number): Finding[] => unread(why, n, "which workspace packages pnpm installs");
  const found = capped(MAX_LISTED);
  const packages: string[] = [];
  let section: "overrides" | "packages" | "other" | undefined; // undefined before the first top-level key
  let seen = false;
  let seenPackages = false;
  let indent = -1;
  for (const [i, line] of text.split(/\r\n|\r|\n/).entries()) {
    if (/^[ \t]*(#.*)?$/.test(line) || (i === 0 && /^---[ \t]*$/.test(line))) continue;
    // A block list item of `packages:`, indented or written at the key's own indentation. A bare `-` is a null entry.
    if (section === "packages" && /^[ \t]*-([ \t]|$)/.test(line)) {
      const item = line.replace(/^[ \t]*-/, "").replace(/^[ \t]+/, "");
      if (/^(#.*)?$/.test(item)) continue;
      const pattern = yamlScalar(item);
      if (pattern === undefined || pattern === "") return unreadPackages("a packages entry that is not a one-line pattern", i + 1);
      packages.push(pattern);
      continue;
    }
    if (/^[ \t]/.test(line)) {
      if (section === undefined) return unread("an indented top-level key", i + 1);
      if (section === "packages") return unreadPackages("a packages entry that is not \"- pattern\"", i + 1);
      if (section === "other") continue;
      // A key starts like a top-level one: `{`, `[`, `-`, `?`, `<<` and the like begin a flow map, list or other form, which fails closed.
      const pad = /^ */.exec(line)?.[0].length ?? 0;
      const m = yamlKey(line.slice(pad));
      const spec = m && /^[ \t]/.test(m.rest) ? yamlScalar(m.rest.replace(/^[ \t]+/, "")) : undefined;
      if (!m || spec === undefined || (indent !== -1 && pad !== indent)) return unread("an override that is not a one-line \"name: spec\"", i + 1);
      indent = pad;
      const name = m.key.replace(/^"(.*)"$|^'(.*)'$/, "$1$2");
      const why = unscannedReason(spec, dir, project);
      if (why) found.add(`pnpm-workspace overrides:${name.slice(0, MAX_LABEL)}=${keyDigest(`${name}\0${spec}`)}`, (k) => makeFinding({ ruleId: "WS-SC-900", severity: "high", file, key: k, message: `overrides "${name.slice(0, MAX_LABEL)}" installs ${spec.slice(0, 120)}, ${why}, and pnpm runs its install scripts` }));
      continue;
    }
    // The end of another key's flow list or map, or an item of its block list written at the key's own indentation.
    if (section === "other" && (/^[\]}][ \t,]*(#.*)?$/.test(line) || /^-([ \t]|$)/.test(line))) continue;
    const key = yamlKey(line);
    if (!key) return unread("a top-level line that is not a simple key", i + 1);
    const name = key.key.replace(/^["']|["']$/g, "");
    section = name === "overrides" ? "overrides" : name === "packages" ? "packages" : "other";
    const rest = key.rest.replace(/(^|[ \t])#.*$/, "").trim();
    if (section === "packages") {
      if (seenPackages) return unreadPackages("a second packages key", i + 1);
      seenPackages = true;
      const flow = /^\[(.*)\]$/.exec(rest);
      if (flow) {
        for (const item of (flow[1] as string).trim() === "" ? [] : (flow[1] as string).split(",")) {
          const pattern = yamlScalar(item.trim());
          if (pattern === undefined || pattern === "") return unreadPackages("a packages flow list that is not one line of patterns", i + 1);
          packages.push(pattern);
        }
      } else if (!/^(null|~)?$/.test(rest)) {
        return unreadPackages("packages that are not a block list or a one-line flow list", i + 1);
      }
      continue;
    }
    if (section !== "overrides") continue;
    if (seen || !/^(\{\s*\}|null|~)?$/.test(rest)) return unread("overrides that are not a single block map", i + 1);
    seen = true;
  }
  const overrides = found.done((more, key) => makeFinding({ ruleId: "WS-SC-900", severity: "high", file, key: `local-specs:${key}`, message: `${more} more local overrides that wormsign could not check were not listed one by one` }));
  return [...overrides, ...hiddenPatterns(file, packages, "packages", "pnpm runs the install scripts of every workspace package", project)];
}

/**
 * The key of a `key: value` line and the text after its colon, or undefined
 * when the line does not start with one: a quoted key, or a plain one that
 * does not start with a YAML indicator and ends at the first `:` followed by a
 * blank or the end of the line, with no `#` in it. Found with indexOf, not a
 * backtracking regex: a 200,000-character line without a colon took seconds.
 */
function yamlKey(line: string): { key: string; rest: string } | undefined {
  const quoted = /^("[^"\\]*"|'(?:[^']|'')*')/.exec(line)?.[0];
  let end = -1;
  if (quoted !== undefined) {
    end = quoted.length;
    while (line[end] === " " || line[end] === "\t") end++;
    if (line[end] !== ":") return undefined;
  } else {
    if (!/^[^\s"'#&*!|>{[%@`?,<-]/.test(line)) return undefined;
    for (let j = line.indexOf(":"); j !== -1 && end === -1; j = line.indexOf(":", j + 1)) if (j + 1 === line.length || line[j + 1] === " " || line[j + 1] === "\t") end = j;
    if (end === -1 || line.slice(0, end).includes("#")) return undefined;
  }
  const rest = line.slice(end + 1);
  return /^([ \t]|$)/.test(rest) ? { key: quoted ?? line.slice(0, end).trimEnd(), rest } : undefined;
}

/** A one-line YAML scalar: double-quoted without escapes, single-quoted, or plain; undefined for anything else. */
function yamlScalar(v: string): string | undefined {
  const quoted = /^(?:"([^"\\]*)"|'((?:[^']|'')*)')[ \t]*(#.*)?$/.exec(v);
  if (quoted) return quoted[1] ?? (quoted[2] as string).replace(/''/g, "'");
  const plain = v.replace(/(^|[ \t])#.*$/, "").trim();
  return /^[^"'&*!|>{[%@`]/.test(plain) && !/:[ \t]/.test(plain) ? plain : undefined;
}

export function contentFindings(file: string, hook: string, cmd: string, line: number | undefined, ctx: ScanContext): Finding[] {
  const out: Finding[] = [];
  const at = line ? { line } : {};
  const reasons = suspiciousReasons(cmd);
  if (reasons.length > 0) {
    out.push(
      makeFinding({
        ruleId: "WS-LC-002",
        severity: "high",
        message: `"${hook}" script ${reasons.join("; ")}: ${cmd.slice(0, 120)}`,
        file,
        key: `${hook}:suspicious`,
        ...at,
      }),
    );
  }
  const ran = new Set(executedFiles(cmd).map((p) => p.split("/").pop() as string));
  for (const n of ctx.iocs.names) {
    if (!ran.has(n.name)) continue;
    const sev: Severity = severityRank(n.nameOnlySeverity) >= severityRank("high") ? "critical" : "high";
    out.push(
      makeFinding({
        ruleId: "WS-LC-003",
        severity: sev,
        message: `"${hook}" script runs ${n.name}, a payload filename reported for the ${n.wave} wave`,
        file,
        key: `${hook}:${n.name}`,
        source: n.source,
        ...at,
      }),
    );
  }
  return out;
}
