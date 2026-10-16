/**
 * soak's view of the package-manager settings that apply to the scanned tree: the project's files, the user's, and
 * the environment.
 *
 * Layer 1 (checkSoakConfig, offline): is a release-age setting configured and enforced? Native settings stop a
 * *resolving* install from picking a young version. npm (verified 12.2.0) and Yarn (verified 4.18.1) do not stop
 * `npm ci` / `yarn install --immutable` from installing a young version that is already pinned in the lockfile, which
 * is why layer 2 (src/soak.ts) exists.
 *
 * installRegistries: the registries an install of a lockfile is configured to use, which layer 2 compares with the
 * one it checks.
 */
import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync } from "node:fs";
import { join, parse, posix } from "node:path";
import { findProgram } from "./exec.js";
import { readText } from "./fsutil.js";
import type { Finding } from "./types.js";
import { UsageError, makeFinding } from "./types.js";
import { formatDuration } from "./duration.js";
import type { ParsedLockfile } from "./lockfile/index.js";
import { NULL, listValue, mapOf, readYaml, scalarValue, unquote, yamlMap, yamlText } from "./settings-yaml.js";
import type { Reader, YamlDoc } from "./settings-yaml.js";

export type Manager = "npm" | "pnpm" | "yarn" | "bun";

/** First release that enforces the setting. Older releases accept it and ignore it (verified for npm 10.9.2). */
export const ENFORCED_SINCE: Record<Manager, string> = { npm: "11.10.0", pnpm: "10.16.0", yarn: "4.10.0", bun: "1.3.0" };

/** The settings in .npmrc text. The last occurrence of a key wins, as in npm (verified with npm 10.9.2). */
export function npmrcEntries(text: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const m of text.matchAll(/^[ \t]*([^\s=;#][^=]*?)[ \t]*=(.*)$/gm)) {
    const v = (m[2] as string).trim();
    // ini: a quoted value is literal; otherwise ';' or '#' starts a comment.
    out.set(m[1] as string, /^".*"$/.test(v) ? v.slice(1, -1) : (v.split(/[;#]/)[0] as string).trim());
  }
  return out;
}

export function npmrcValue(text: string, key: string): string | undefined {
  return npmrcEntries(text).get(key);
}

/**
 * A setting from the environment. npm, pnpm and Yarn all match the variable name
 * case-insensitively (verified npm 10.9.2, pnpm 11.16.0, Yarn 4.10.3). The first name that is set wins.
 */
function envSetting(env: Record<string, string | undefined> | undefined, names: string[]): { name: string; value: string } | undefined {
  for (const want of names) {
    const name = Object.keys(env ?? {}).find((k) => k.toLowerCase() === want && env?.[k] !== undefined);
    if (name !== undefined) return { name, value: env?.[name] as string };
  }
  return undefined;
}

/** A number of days as npm reads min-release-age (a Number): undefined for an empty or non-numeric value. */
export function parseDays(raw: string): number | undefined {
  const t = raw.trim();
  return t !== "" && Number.isFinite(Number(t)) ? Number(t) : undefined;
}

export function readNpmrc(text: string): { days: number; raw: string } | undefined {
  const raw = npmrcValue(text, "min-release-age");
  const days = raw === undefined ? undefined : parseDays(raw);
  return raw !== undefined && days !== undefined ? { days, raw } : undefined;
}


/** Yarn's npmMinimalAgeGate. Bare integers are minutes on every Yarn 4.x tested. A unit suffix ("3d") is
 * parsed as a duration by Yarn 4.18.1 but read as a bare number of minutes by Yarn 4.10.3 (verified: "3d" -> 3,
 * "72h" -> 72), so a suffixed value is returned as ambiguous and the config check refuses to trust it. */
function yarnGate(value: string): { minutes?: number; raw: string; suffixed: boolean } {
  const raw = unquote(value);
  return /^\d+$/.test(raw) ? { minutes: Number(raw), raw, suffixed: false } : { raw, suffixed: true };
}

/**
 * Lines of the [install] table of a bunfig.toml. A table header, `[name]` or an array of tables `[[name]]` (which is
 * never [install]), may be followed by a comment (`[test] # unit tests`). A line that starts inside a multi-line
 * string (`"""` or `'''`) is that string's content: never a header or a key. harden-dev.sh's H07 reads them the same
 * way (test/harden.test.ts holds both to one table).
 */
function bunInstallLines(text: string): string[] {
  let inInstall = false;
  let open = "";
  const out: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const inString = open !== "";
    open = multiLineStringOpen(line, open);
    if (inString) continue;
    const section = /^\s*\[(\[?)([^\]]+)\]\]?\s*(?:#.*)?$/.exec(line);
    if (section) inInstall = section[1] === "" && section[2]?.trim() === "install";
    else if (inInstall) out.push(line);
  }
  return out;
}

/**
 * The delimiter of the TOML multi-line string open at the end of `line` (`"""` or `'''`), or "", given the one open at
 * its start. Delimiters are paired in order on the line; a comment is not told apart from a string (H07 does the same).
 */
function multiLineStringOpen(line: string, open: string): string {
  for (let i = 0; ; ) {
    if (open !== "") {
      const j = line.indexOf(open, i);
      if (j < 0) return open;
      i = j + 3;
      open = "";
    } else {
      const a = line.indexOf('"""', i);
      const b = line.indexOf("'''", i);
      if (a < 0 && b < 0) return "";
      const k = b < 0 || (a >= 0 && a < b) ? a : b;
      open = line.slice(k, k + 3);
      i = k + 3;
    }
  }
}

/**
 * bunfig.toml [install] minimumReleaseAge, in seconds. Bun reads bunfig.toml as TOML, where `604_800` is the integer
 * 604800: Bun 1.3's lexer drops the underscores (src/interchange/toml/lexer.zig), Bun 1.4's accepts one only between
 * digits (src/parsers/toml.rs, check_underscore). So the value is read as a TOML decimal integer: digits, single
 * underscores between digits, no leading zero. Any other value (a float, a hex integer, a string, `604__800`) comes back
 * without seconds, and the check reports it as unreadable (WS-SK-004) instead of passing it or calling it missing.
 * harden-dev.sh's H07 reads it the same way (test/harden.test.ts holds both to one table).
 */
export function readBunfig(text: string): { seconds?: number; raw: string } | undefined {
  for (const line of bunInstallLines(text)) {
    const m = /^\s*minimumReleaseAge\s*=\s*(.*?)\s*(?:#.*)?$/.exec(line);
    if (!m) continue;
    const raw = m[1] as string;
    return /^(?:0|[1-9](?:_?\d)*)$/.test(raw) ? { seconds: Number(raw.replace(/_/g, "")), raw } : { raw };
  }
  return undefined;
}

/** The keys read from pnpm-workspace.yaml and pnpm 11's config.yaml. pnpm 11.16.0 reads no kebab-case spelling of them there (verified). */
const PNPM_KEYS = new Map<string, Reader>([
  ["minimumReleaseAge", scalarValue], ["trustLockfile", scalarValue], ["minimumReleaseAgeStrict", scalarValue],
  ["minimumReleaseAgeExclude", listValue], ["registry", scalarValue], ["registries", mapOf(scalarValue)],
]);
const YARN_KEYS = new Map<string, Reader>([
  ["yarnPath", scalarValue], ["npmMinimalAgeGate", scalarValue], ["npmPreapprovedPackages", listValue],
  ["npmRegistryServer", scalarValue], ["npmScopes", mapOf(mapOf(scalarValue))],
]);

/** bunfig.toml [install] minimumReleaseAgeExcludes, joined to one line (arrays may span lines). */
export function bunExcludes(text: string): string | undefined {
  const lines = bunInstallLines(text);
  const i = lines.findIndex((l) => /^\s*minimumReleaseAgeExcludes\s*=/.test(l));
  if (i === -1) return undefined;
  let value = (lines[i] as string).replace(/^[^=]*=/, "").trim();
  for (const l of lines.slice(i + 1)) {
    if (!value.startsWith("[") || value.includes("]")) break;
    value += ` ${l.trim()}`;
  }
  return value;
}

const isEmptyList = (v: string | undefined): boolean => v === undefined || NULL.test(v) || /^\[\s*\]$/.test(v);
/** YAML 1.2 booleans; anything else (a quoted "false", "yes") is a string, which pnpm treats as set. */
const isYamlFalse = (v: string): boolean => /^(false|False|FALSE)$/.test(v);
const isYamlTrue = (v: string): boolean => /^(true|True|TRUE)$/.test(v);

function versionLess(a: string, b: string): boolean {
  const pa = a.split(/[.+-]/).map(Number);
  const pb = b.split(/[.+-]/).map(Number);
  for (let i = 0; i < 3; i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) < (pb[i] ?? 0);
  return false;
}

export interface InstalledVersion {
  version?: string;
  /** Where the version came from, for the message. */
  source: string;
}

/**
 * The package manager version that runs in a project in `dir` (relative to `root`). A committed
 * yarnPath or packageManager pin decides it, from the nearest file in dir or its parents up to the
 * root that sets one: Yarn runs the nearest yarnPath (verified, Yarn 4.10.3) and corepack uses the
 * nearest package.json with a packageManager field (verified, corepack in Node 23.11). Otherwise the
 * binary is asked from the filesystem root. It is never run inside the scanned tree or a shared temp
 * directory: Yarn runs the yarnPath of a .yarnrc.yml in its working directory or any parent
 * (verified, Yarn 1.22.22), and anyone can write one into /tmp.
 */
export function installedVersion(manager: Manager, root: string, env: Record<string, string | undefined>, dir = "."): InstalledVersion {
  const read = reader(root);
  if (manager === "yarn") {
    for (const [where, doc] of yarnrcs(read, dir, undefined)) {
      const yarnPath = unquote(yamlText(doc.values.get("yarnPath")) ?? "");
      const v = /\d+\.\d+\.\d+/.exec(yarnPath)?.[0];
      if (yarnPath) return { ...(v ? { version: v } : {}), source: `the file name of yarnPath ${yarnPath} in ${where}` };
    }
  }
  if (manager === "pnpm" || manager === "yarn") {
    for (let d = dir; ; d = posix.dirname(d)) {
      const file = posix.join(d, "package.json");
      const text = read(file);
      let pm: unknown;
      try {
        pm = text === undefined ? undefined : (JSON.parse(text) as { packageManager?: unknown } | null)?.packageManager;
      } catch {
        return { source: `${file} is not valid JSON, so its packageManager pin is unknown` };
      }
      if (typeof pm === "string") {
        const m = /^([a-z]+)@(\d+\.\d+\.\d+)/.exec(pm);
        if (m?.[1] === manager) return { version: m[2] as string, source: `packageManager in ${file}` };
        break;
      }
      if (d === ".") break;
    }
  }
  // Found on PATH by src/exec.ts and run by its absolute path; one inside the scanned tree is never run.
  const program = findProgram(manager, env, [root]);
  if (!("path" in program)) return { source: `\`${manager} --version\` failed: ${"missing" in program ? program.missing : program.refused}` };
  try {
    const out = execFileSync(program.path, ["--version"], {
      cwd: parse(process.cwd()).root,
      env: { ...env, YARN_IGNORE_PATH: "1", COREPACK_ENABLE_NETWORK: "0", COREPACK_ENABLE_DOWNLOAD_PROMPT: "0", npm_config_update_notifier: "false" },
      encoding: "utf8",
      timeout: 15_000,
      stdio: ["ignore", "pipe", "ignore"],
    });
    const v = /\d+\.\d+\.\d+/.exec(out)?.[0];
    return { ...(v ? { version: v } : {}), source: `\`${manager} --version\`` };
  } catch (e) {
    return { source: `\`${manager} --version\` failed: ${(e as Error).message.split("\n")[0]}` };
  }
}

/** Where package-manager settings come from besides the scanned tree. */
export interface RcSources {
  /** Text of the user-level .npmrc, if any. */
  userNpmrc?: string;
  /** Text of the user-level ~/.yarnrc.yml, if any. */
  userYarnrc?: string;
  /** Where pnpm 11's global config.yaml is (for messages) and its text, if any. */
  userPnpm?: [where: string, text: string];
  env?: Record<string, string | undefined>;
}

/**
 * What else the tree holds. A caller that says it has Python inputs must also say whether it has npm inputs: leaving
 * that out does not compile, so the no-package-manager finding is never dropped by an omission.
 */
export type TreeInputs =
  | {
      /** The tree has Python lockfiles or manifests. */
      pythonInputs?: false;
      /** The tree has npm, pnpm, Yarn or bun inputs: a lockfile (read or not), a package.json or a bunfig.toml. */
      npmInputs?: boolean;
    }
  | { pythonInputs: true; npmInputs: boolean };

export type ConfigOptions = RcSources &
  TreeInputs & {
    minAgeMs: number;
    /** Which version of `manager` runs in `dir` (relative to the root). */
    versionOf: (manager: Manager, dir: string) => InstalledVersion;
  };

interface Setting {
  file: string;
  setting: string;
  raw: string;
  /** undefined when raw could not be interpreted as a duration. */
  ageMs?: number;
}

/** Where a setting's value came from (a file or an environment variable), and the value. */
type Hit = [where: string, value: string];

const DAY = 86_400_000;
const MINUTE = 60_000;

/** Reads settings files in the scanned tree: undefined when absent; a symlink or any other failure stops the run, since the settings would be unknown. */
function reader(root: string): (p: string) => string | undefined {
  return (p) => {
    if (!lstatSync(join(root, p), { throwIfNoEntry: false })) return undefined;
    const r = readText(join(root, p));
    if ("problem" in r) throw new UsageError(`cannot read ${p} (${r.problem}); its package-manager settings would be unknown`);
    return r.text;
  };
}

/** The .yarnrc.yml files Yarn merges for a project in dir, nearest first: dir and its parents up to the root, then the user's (verified, Yarn 4.10.3). */
function yarnrcs(read: (p: string) => string | undefined, dir: string, user: string | undefined): [where: string, doc: YamlDoc][] {
  const out: [string, YamlDoc][] = [];
  for (let d = dir; ; d = posix.dirname(d)) {
    const text = read(posix.join(d, ".yarnrc.yml"));
    if (text !== undefined) out.push([posix.join(d, ".yarnrc.yml"), readYaml(text, YARN_KEYS)]);
    if (d === ".") break;
  }
  if (user !== undefined) out.push(["~/.yarnrc.yml", readYaml(user, YARN_KEYS)]);
  return out;
}

const hitOf = (where: string, value: string | undefined): Hit | undefined => (value === undefined ? undefined : [where, value]);

const fromEnv = (env: RcSources["env"], ...names: string[]): Hit | undefined => {
  const e = envSetting(env, names);
  return e && [`environment variable ${e.name}`, e.value];
};

export function checkSoakConfig(root: string, locks: ParsedLockfile[], opts: ConfigOptions): Finding[] {
  const out: Finding[] = [];
  const read = reader(root);
  const versions = new Map<string, InstalledVersion>();
  const versionOf = (m: Manager, dir: string): InstalledVersion => {
    const k = `${m}:${dir}`;
    if (!versions.has(k)) versions.set(k, opts.versionOf(m, dir));
    return versions.get(k) as InstalledVersion;
  };
  const need = formatDuration(opts.minAgeMs);
  const minutesNeeded = Math.ceil(opts.minAgeMs / MINUTE);
  const finding = (ruleId: string, file: string, key: string, message: string): void => {
    out.push(makeFinding({ ruleId, severity: "medium", message, file, key }));
  };

  const check = (manager: Manager, dir: string, file: string, setting: string, got: Setting | undefined, missing: string): void => {
    if (!got) return finding("WS-SK-003", file, `${manager}:${setting}`, `No ${setting} in ${file}. ${missing}`);
    // Keyed on the value too: a baseline entry approves one value, and any change to it fails again.
    const key = `${manager}:${setting}=${got.raw}`;
    if (got.ageMs === undefined) return finding("WS-SK-004", got.file, key, `${got.file}: ${got.setting} = ${got.raw} could not be interpreted as a duration; required soak is ${need}`);
    if (got.ageMs < opts.minAgeMs) {
      return finding("WS-SK-004", got.file, key, `${got.file}: ${got.setting} = ${got.raw} is ${formatDuration(got.ageMs)}, shorter than the required ${need}`);
    }
    const v = versionOf(manager, dir);
    const min = ENFORCED_SINCE[manager];
    if (!v.version) {
      finding("WS-SK-004", got.file, `${manager}:version=unknown`, `${got.file}: ${got.setting} is set, but the ${manager} version that will run could not be determined (${v.source}), so enforcement is unverified; ${manager} ${min} or newer enforces it`);
    } else if (versionLess(v.version, min)) {
      finding("WS-SK-004", got.file, `${manager}:version=${v.version}`, `${got.file}: ${got.setting} is set, but ${manager} ${v.version} (from ${v.source}) ignores it; ${manager} ${min} or newer enforces it`);
    }
  };
  /** A settings file wormsign cannot fully read. Keyed on its text: a baseline entry approves one reviewed file, and any edit fails again. */
  const uninterpretable = (manager: Manager, file: string, doc: YamlDoc): void => {
    const n = doc.problems.length;
    if (n > 0) finding("WS-SK-004", file, `${manager}:${file} ${doc.digest}`, `${file} could not be interpreted (${doc.problems.slice(0, 5).join("; ")}${n > 5 ? `; ${n - 5} more` : ""}), so the release-age and registry settings read from it are not verified`);
  };
  /** A setting that switches the gate off for some or all packages, whatever the age says. Any value but the safe one counts. */
  const bypass = (manager: Manager, setting: string, hit: Hit | undefined, safe: (v: string) => boolean, effect: string): void => {
    if (hit && !safe(hit[1])) finding("WS-SK-004", hit[0], `${manager}:${setting}=${hit[1]}`, `${hit[0]}: ${setting}: ${hit[1].slice(0, 200)} ${effect}`);
  };

  const done = new Set<string>();
  for (const lock of locks) {
    const dir = posix.dirname(lock.file);
    const at = (f: string): string => posix.join(dir, f);
    if (done.has(`${lock.kind}:${dir}`)) continue;
    done.add(`${lock.kind}:${dir}`);

    if (lock.kind === "npm") {
      // npm precedence (verified with npm 10.9.2): environment, then the project's own .npmrc
      // (the lockfile's directory; a nested project ignores the root's), then the user's.
      const proj = read(at(".npmrc"));
      const hit =
        fromEnv(opts.env, "npm_config_min_release_age") ??
        hitOf(at(".npmrc"), proj === undefined ? undefined : npmrcValue(proj, "min-release-age")) ??
        hitOf("~/.npmrc", opts.userNpmrc === undefined ? undefined : npmrcValue(opts.userNpmrc, "min-release-age"));
      // The value as npm gets it: a file's value has had its comment cut by npmrcValue, and an environment value has none.
      const days = hit ? parseDays(hit[1]) : undefined;
      const got = hit ? { file: hit[0], setting: "min-release-age", raw: `${hit[1]} days`, ...(days !== undefined ? { ageMs: days * DAY } : {}) } : undefined;
      check("npm", dir, at(".npmrc"), "min-release-age", got, `Without it npm installs versions published seconds ago. Add 'min-release-age=<days>' (npm ${ENFORCED_SINCE.npm} or newer).`);
    } else if (lock.kind === "pnpm") {
      const file = at("pnpm-workspace.yaml");
      const ws = readYaml(read(file) ?? "", PNPM_KEYS);
      uninterpretable("pnpm", file, ws);
      // pnpm 11 lets pnpm_config_* override pnpm-workspace.yaml; pnpm 10 reads npm_config_* and lets the
      // file override them, and also reads minimum-release-age from .npmrc (verified 11.16.0, 10.16.0).
      const v = versionOf("pnpm", dir).version;
      const pnpm10 = v !== undefined && versionLess(v, "11.0.0");
      // pnpm 11 reads its global config.yaml last: the workspace file and the environment override it (verified 11.16.0).
      const [userWhere, userText] = opts.userPnpm ?? [];
      const user = userWhere === undefined ? undefined : readYaml(userText ?? "", PNPM_KEYS);
      if (user) uninterpretable("pnpm", userWhere as string, user);
      const value = (key: string, snake: string): Hit | undefined => {
        const env = fromEnv(opts.env, `${pnpm10 ? "npm" : "pnpm"}_config_${snake}`);
        const inFile = hitOf(file, yamlText(ws.values.get(key)));
        return pnpm10 ? inFile ?? env : env ?? inFile ?? hitOf(userWhere as string, user && yamlText(user.values.get(key)));
      };
      const hit = value("minimumReleaseAge", "minimum_release_age") ?? (pnpm10 ? hitOf(at(".npmrc"), npmrcValue(read(at(".npmrc")) ?? "", "minimum-release-age")) : undefined);
      const minutes = hit && /^\d+$/.test(hit[1]) ? Number(hit[1]) : undefined;
      const got = hit ? { file: hit[0], setting: "minimumReleaseAge", raw: `${hit[1]} minutes`, ...(minutes !== undefined ? { ageMs: minutes * MINUTE } : {}) } : undefined;
      check("pnpm", dir, file, "minimumReleaseAge", got, `pnpm 11 defaults to 1 day in loose mode, which adds young versions to minimumReleaseAgeExclude instead of blocking them; pnpm 10 has no default. Add 'minimumReleaseAge: ${minutesNeeded}' (pnpm ${ENFORCED_SINCE.pnpm} or newer).`);
      bypass("pnpm", "trustLockfile", value("trustLockfile", "trust_lockfile"), isYamlFalse, "makes pnpm skip re-checking locked versions against minimumReleaseAge");
      bypass("pnpm", "minimumReleaseAgeStrict", value("minimumReleaseAgeStrict", "minimum_release_age_strict"), isYamlTrue, "makes pnpm add young versions to minimumReleaseAgeExclude and install them");
      bypass("pnpm", "minimumReleaseAgeExclude", value("minimumReleaseAgeExclude", "minimum_release_age_exclude"), isEmptyList, "exempts these packages from the release-age gate");
    } else if (lock.kind === "yarn-berry") {
      const file = at(".yarnrc.yml");
      const rcs = yarnrcs(read, dir, opts.userYarnrc);
      for (const [f, y] of rcs) uninterpretable("yarn", f, y);
      // The environment overrides every file, and the nearest file that sets a key wins (verified, Yarn 4.10.3).
      const hit = fromEnv(opts.env, "yarn_npm_minimal_age_gate") ?? rcs.map(([f, y]) => hitOf(f, yamlText(y.values.get("npmMinimalAgeGate")))).find((h) => h !== undefined);
      const y = hit && yarnGate(hit[1]);
      if (hit && y?.suffixed) {
        finding("WS-SK-004", hit[0], `yarn:npmMinimalAgeGate=${y.raw}`, `${hit[0]}: npmMinimalAgeGate = ${y.raw} uses a unit suffix. Yarn 4.10.3 reads it as that many minutes (3d becomes 3 minutes); write minutes instead, e.g. ${minutesNeeded}`);
      } else {
        const got = hit && y?.minutes !== undefined ? { file: hit[0], setting: "npmMinimalAgeGate", raw: `${y.raw} minutes`, ageMs: y.minutes * MINUTE } : undefined;
        check("yarn", dir, file, "npmMinimalAgeGate", got, `Without it Yarn 4.10.3 (default 0) installs versions published seconds ago. Add 'npmMinimalAgeGate: ${minutesNeeded}' (minutes; Yarn ${ENFORCED_SINCE.yarn} or newer).`);
      }
      // Yarn concatenates this list across every file (verified, Yarn 4.10.3), so each source is checked.
      for (const h of [fromEnv(opts.env, "yarn_npm_preapproved_packages"), ...rcs.map(([f, y]) => hitOf(f, yamlText(y.values.get("npmPreapprovedPackages"))))]) bypass("yarn", "npmPreapprovedPackages", h, isEmptyList, "exempts these packages from the release-age gate");
    } else {
      out.push(makeFinding({ ruleId: "WS-SK-003", severity: "low", message: "Yarn Classic has no release-age setting. The lockfile gate (wormsign soak in CI) is the only enforcement available for this project.", file: lock.file, key: "yarn-classic" }));
    }
  }
  const bun = read("bunfig.toml");
  if (bun !== undefined) {
    const b = readBunfig(bun);
    check("bun", ".", "bunfig.toml", "minimumReleaseAge", b ? { file: "bunfig.toml", setting: "minimumReleaseAge", ...(b.seconds !== undefined ? { raw: `${b.raw} seconds`, ageMs: b.seconds * 1000 } : { raw: b.raw }) } : undefined, `Without it Bun installs versions published seconds ago. Add 'minimumReleaseAge = <seconds>' under [install] (Bun ${ENFORCED_SINCE.bun} or newer).`);
    bypass("bun", "minimumReleaseAgeExcludes", hitOf("bunfig.toml", bunExcludes(bun)), isEmptyList, "exempts these packages from the release-age gate");
  }
  // A Python-only tree has no npm package manager to name. With any npm input the finding stays: that input's settings
  // went unchecked. Only an explicit npmInputs: false drops it, so a caller that leaves it out (from JavaScript, or past
  // the types) keeps the finding.
  if (done.size === 0 && bun === undefined && !(opts.pythonInputs === true && opts.npmInputs === false)) {
    out.push(makeFinding({ ruleId: "WS-SK-003", severity: "medium", message: "No readable lockfile or bunfig.toml, so wormsign cannot tell which package manager's release-age setting applies; none was checked.", key: "no-package-manager" }));
  }
  return out;
}

/** A configured registry: scope "" is the default, "@x" one scope's, "*" every package (a setting that could not be read). */
export interface RegistrySetting {
  scope: string;
  url: string;
  where: string;
}

/**
 * Every registry an install of this lockfile may be configured to use. All sources are kept, not
 * only the one that would win, so a registry set anywhere fails closed instead of leaking a private
 * name to --registry. Sources (verified npm 10.9.2, pnpm 10.16.0 and 11.16.0, Yarn 4.10.3):
 * npm, pnpm and Yarn Classic read the lockfile directory's .npmrc, the user's, and npm_config_* /
 * pnpm_config_* variables; pnpm 11 also reads registry and registries in pnpm-workspace.yaml and its global config.yaml;
 * Yarn Berry reads npmRegistryServer and npmScopes from its .yarnrc.yml files and YARN_NPM_REGISTRY_SERVER.
 * A settings file that could not be interpreted counts as an unknown registry for every package.
 */
export function installRegistries(root: string, lock: ParsedLockfile, src: RcSources): RegistrySetting[] {
  const read = reader(root);
  const dir = posix.dirname(lock.file);
  const out: RegistrySetting[] = [];
  if (lock.kind === "yarn-berry") {
    const env = fromEnv(src.env, "yarn_npm_registry_server");
    if (env) out.push({ scope: "", url: env[1], where: env[0] });
    for (const [where, doc] of yarnrcs(read, dir, src.userYarnrc)) {
      if (doc.problems.length > 0) out.push({ scope: "*", url: UNREAD, where });
      const url = yamlText(doc.values.get("npmRegistryServer"));
      if (url) out.push({ scope: "", url: unquote(url), where });
      for (const [scope, settings] of yamlMap(doc.values.get("npmScopes"))) {
        const server = yamlText(yamlMap(settings).get("npmRegistryServer"));
        if (server) out.push({ scope: `@${scope.replace(/^@/, "")}`, url: unquote(server), where });
      }
    }
    return out;
  }
  const npmrcs: [string, string | undefined][] = [["~/.npmrc", src.userNpmrc], [posix.join(dir, ".npmrc"), read(posix.join(dir, ".npmrc"))]];
  for (const [where, text] of npmrcs) for (const [key, url] of npmrcEntries(text ?? "")) out.push({ scope: key, url, where });
  for (const [name, url] of Object.entries(src.env ?? {})) {
    const key = /^p?npm_config_(.*)$/i.exec(name)?.[1];
    if (key !== undefined && url !== undefined) out.push({ scope: key.toLowerCase(), url, where: `environment variable ${name}` });
  }
  const workspace = posix.join(dir, "pnpm-workspace.yaml");
  const yamls: [string, string | undefined][] = lock.kind === "pnpm" ? [[workspace, read(workspace)], ...(src.userPnpm ? [src.userPnpm] : [])] : [];
  for (const [where, text] of yamls) {
    const ws = readYaml(text ?? "", PNPM_KEYS);
    if (ws.problems.length > 0) out.push({ scope: "*", url: UNREAD, where });
    const url = yamlText(ws.values.get("registry"));
    if (url) out.push({ scope: "registry", url: unquote(url), where });
    // pnpm looks a package up by "@scope" and falls back to "default"; it never reads another key (verified, pnpm 11.16.0 pickRegistryForPackage).
    for (const [scope, value] of yamlMap(ws.values.get("registries"))) out.push({ scope: scope === "default" ? "registry" : `${scope}:registry`, url: unquote(yamlText(value) ?? ""), where });
  }
  // Keep the registry keys: "registry" is the default, "@x:registry" a scope's.
  return out.flatMap((r) => (r.scope === "*" ? [r] : r.scope === "registry" ? [{ ...r, scope: "" }] : /^@[^:]+:registry$/.test(r.scope) ? [{ ...r, scope: r.scope.slice(0, -":registry".length) }] : []));
}

/** The registry of a settings file that could not be interpreted: unknown, so every package fails closed. */
const UNREAD = "a registry wormsign could not read";

/** A user-level settings file: undefined when it does not exist; any other read error stops the run, since its settings would be unknown. */
export function readUserFile(path: string): string | undefined {
  try {
    return readFileSync(path, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw new UsageError(`cannot read ${path} (${(e as NodeJS.ErrnoException).code ?? (e as Error).message}); its package-manager settings would be unknown`);
  }
}
