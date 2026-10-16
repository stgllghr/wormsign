/**
 * Install settings (docs/soak.md, "Requirements files": install settings and the pip config probe): what could make an install of a requirements file or a pylock.toml use another index or skip
 * hash checks, where soak can see it.
 *
 * Requirements files record no index, and neither does a pylock package without `index` (every `pip lock` output), so
 * before any such entry's name is sent to the index or OSV, discovery collects every setting that could point the
 * install elsewhere, and fails closed (WS-SK-002 "an install may use another index: <where>", nothing sent) if any of
 * them names something other than --pypi-index or cannot be read. This is a deliberately over-inclusive collection of
 * keys, not a model of pip's or uv's precedence: any non-default value anywhere fails closed.
 *
 * Index settings ("index" hits):
 * - environment: every PIP_* variable pip reads as index-url, extra-index-url, find-links or no-index (pip lower-cases
 *   the name after PIP_ and reads "_" as "-", so PIP_Index_Url counts), and UV_INDEX_URL, UV_EXTRA_INDEX_URL,
 *   UV_INDEX, UV_DEFAULT_INDEX, UV_FIND_LINKS, UV_NO_INDEX;
 * - pip's configuration, through the probe (`python3 -m pip config list`, every section; the :env: lines are the
 *   environment, read above) and, when PIP_CONFIG_FILE names a file, that file read directly too, so a probe that
 *   cannot run does not hide it. A relative PIP_CONFIG_FILE or UV_CONFIG_FILE is a hit itself: it names a file
 *   relative to the install's working directory, which soak cannot know;
 * - uv configuration: `index-url`, `extra-index-url`, `find-links`, `no-index`, `default-index` and `[[index]]`, at the
 *   top level and under `[pip]`, in every uv.toml and every pyproject.toml `[tool.uv]` from the lock's directory up to
 *   the root, and in the directories above the root (they apply to every lock), in the user's and the system's
 *   uv.toml, and in the file UV_CONFIG_FILE names;
 * - any pip.conf or pip.ini in the tree: pip reads one when PIP_CONFIG_FILE or a virtual environment's site
 *   configuration points at it, so its presence alone fails closed.
 * File names in the tree are matched folded (src/tree.ts fold, as manifest.ts matches them): uv on a case-insensitive
 * file system (APFS, NTFS) reads UV.toml as its uv.toml and PyProject.toml as its pyproject.toml.
 * A value equal to --pypi-index (src/python/index.ts normalizeIndexUrl) is not a hit; `no-index = false` is not one.
 *
 * Hash settings ("hash" hits, WS-SK-002 "an install may skip hash checks: <where>"): `verify-hashes` or
 * `require-hashes` set to false (or to anything but a boolean), and `no-verify-hashes` set, in the same uv files and
 * tables; and UV_NO_VERIFY_HASHES set to anything but a false value, UV_VERIFY_HASHES or UV_REQUIRE_HASHES set to a
 * false value. pip has no setting that turns hash checking off for a file holding --require-hashes (pip 26.2.1 refuses
 * --no-require-hashes beside it).
 *
 * Unreadable means fail closed: a uv or pip file that exists but cannot be read or parsed is an index hit ("could not
 * be read"). The probe is different: when pip's configuration cannot be read (python3 missing, a non-zero exit, a
 * timeout, output this does not understand), that is never "no index": discovery makes the entries unsendable unless
 * --pypi-index was given explicitly, and says so in a note. A setting soak can see always fails closed.
 *
 * Build-forcing configuration (WS-SK-005, medium, keyed on the file, key and value): `no-binary`, `no-binary-package`,
 * `no-build-isolation`, `no-build-isolation-package`, `extra-build-dependencies`, `extra-build-variables`,
 * `config-settings` and `config-settings-package`, at the top level or under [pip], in a uv.toml, a pyproject.toml
 * [tool.uv] or a PEP 723 script block's [tool.uv] in the tree, when set to anything but false or empty. Each makes an install build packages from source (or
 * build them in the install's own environment), and build requirements are never locked. Settings outside the tree
 * (environment, user and system files) are not reported as WS-SK-005: there is no file in the review to point at.
 *
 * Messages show URLs without user name or password (src/python/index.ts displayUrl): an index URL often carries a token.
 */
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, isAbsolute, join, parse, posix } from "node:path";
import { findProgram } from "../exec.js";
import { keyDigest, makeFinding, type Finding } from "../types.js";
import { displayUrl, normalizeIndexUrl } from "./index.js";
import { isPipConfName, isUvTomlName } from "./manifest.js";
import { fold } from "../tree.js";
import { decodeUtf8, get, isTable, parseToml, readToml, show, type TomlRead, type TomlTable } from "./toml.js";

/**
 * Runs `python3 -m pip <args>`: its exit code and standard output; "unavailable" when python3 could not be run; or
 * why it was not run (a python3 inside the scanned tree: src/exec.ts).
 */
export type PipConfigProbe = (args: string[]) => { code: number | null; stdout: string } | "unavailable" | { notRun: string };

export interface SettingHit {
  kind: "index" | "hash";
  /** Where it is set: "environment variable PIP_INDEX_URL", "ci/uv.toml [pip] extra-index-url", ... */
  where: string;
  /** What it says, credentials removed. */
  detail: string;
  /** The file in the tree that sets it ("/"-separated, relative to the root), when it is one. */
  file?: string;
  /** The directory (relative to the root) whose locks it governs, itself and below; undefined: every lock. */
  scope?: string;
}

export interface InstallSettings {
  /** Hits that govern every lock. */
  global: SettingHit[];
  /** Why pip's configuration could not be read, when the probe ran and could not read it. */
  pipNotRead?: string;
  /** The hits that govern a lock in `dir` (relative to the root, "." for the root). */
  forDir(dir: string): SettingHit[];
}

/** What collectInstallSettings needs to know about the tree. */
export interface SettingsTree {
  /** Absolute path of the root. */
  root: string;
  /** Every walked path's type (relative to the root): which uv.toml, pyproject.toml, pip.conf and pip.ini exist. */
  types: ReadonlyMap<string, "file" | "dir" | "symlink" | "other">;
  /** A tree file read as TOML (discovery's cache, so each pyproject.toml is parsed once). */
  toml(rel: string): TomlRead;
}

export interface SettingsOptions {
  /** --pypi-index. */
  pypiIndex: string;
  env: Record<string, string | undefined>;
  /** Run the pip probe (v4: only on a run that is about to send requirements or pylock-without-index names). */
  probe: boolean;
  /** The probe; absent: pip's configuration is not read ("unavailable"). */
  pipConfig?: PipConfigProbe;
  /** uv.toml files outside the tree to read (default: the user's and the system's, from env; see userSystemUvToml). */
  uvConfigFiles?: string[];
  /** Read uv.toml and pyproject.toml in the directories above the root (default true). */
  ancestors?: boolean;
}

const INDEX_KEYS = ["index-url", "extra-index-url", "find-links", "no-index"] as const;
const FALSE = new Set(["n", "no", "f", "false", "off", "0"]);
const isFalse = (v: string): boolean => FALSE.has(v.trim().toLowerCase());

/** pip's _normalize_name: lower case, "_" as "-", no leading "--". */
const pipKey = (k: string): string => k.toLowerCase().replace(/_/g, "-").replace(/^--/, "");

/** Each whitespace-separated URL shown without credentials (a uv `name=url` entry keeps its name). */
function shownUrls(v: string): string {
  return v
    .split(/\s+/)
    .filter((t) => t !== "")
    .map((t) => {
      const m = /^([A-Za-z0-9._-]+)=(.*)$/.exec(t);
      return m && /^[a-z][a-z0-9+.-]*:/i.test(m[2]!) ? `${m[1]}=${displayUrl(m[2]!)}` : displayUrl(t);
    })
    .join(" ")
    .slice(0, 400);
}

/** The URLs a list setting names that are not --pypi-index (entries may be `name=url`, as UV_INDEX's are). */
function otherUrls(value: string, pypiIndex: string): string[] {
  const want = normalizeIndexUrl(pypiIndex);
  return value
    .split(/\s+/)
    .filter((t) => t !== "")
    .map((t) => {
      const m = /^([A-Za-z0-9._-]+)=(.*)$/.exec(t);
      return m && /^[a-z][a-z0-9+.-]*:/i.test(m[2]!) ? m[2]! : t;
    })
    .filter((u) => want === undefined || normalizeIndexUrl(u) !== want);
}

const notIndex = (pypiIndex: string): string => `, not --pypi-index ${displayUrl(pypiIndex)}`;

/** Index hits for one pip key and its value (pip.conf, the probe, PIP_* variables). */
function pipValueHits(key: string, value: string, where: string, pypiIndex: string, base: Omit<SettingHit, "kind" | "where" | "detail">): SettingHit[] {
  switch (key) {
    case "index-url":
    case "extra-index-url": {
      if (otherUrls(value, pypiIndex).length === 0) return [];
      return [{ ...base, kind: "index", where, detail: `names ${shownUrls(value)}${notIndex(pypiIndex)}` }];
    }
    case "find-links":
      return value.trim() === "" ? [] : [{ ...base, kind: "index", where, detail: `adds find-links ${shownUrls(value)}, which are not the index` }];
    case "no-index":
      return value.trim() === "" || isFalse(value) ? [] : [{ ...base, kind: "index", where, detail: `turns the index off (${JSON.stringify(value.slice(0, 40))}), so files come from find-links` }];
    default:
      return [];
  }
}

/** The hits in one uv configuration table (a uv.toml, a pyproject.toml's [tool.uv], or the file UV_CONFIG_FILE names). */
export function uvTableHits(table: TomlTable, where: string, pypiIndex: string, base: Omit<SettingHit, "kind" | "where" | "detail">): SettingHit[] {
  const out: SettingHit[] = [];
  const want = normalizeIndexUrl(pypiIndex);
  const same = (u: unknown): boolean => typeof u === "string" && want !== undefined && normalizeIndexUrl(u) === want;
  const shownValue = (v: unknown): string => (typeof v === "string" ? shownUrls(v) : Array.isArray(v) ? v.map((x) => (typeof x === "string" ? shownUrls(x) : show(x))).join(", ") : show(v));
  const hit = (kind: SettingHit["kind"], where: string, detail: string): void => {
    out.push({ ...base, kind, where, detail });
  };
  // uv.toml [pip], pyproject.toml [tool.uv.pip]: what `uv pip install` and `uv pip sync` read.
  const pipTable = get(table, "pip");
  for (const [label, t] of [["", table] as const, ["[pip] ", pipTable] as const]) {
    if (t === undefined) continue;
    const at = (key: string): string => `${where} ${label}${key}`;
    if (!isTable(t)) {
      hit("index", `${where} ${label.trim() || "table"}`, "is not a table, so what it sets is unknown");
      continue;
    }
    for (const key of ["index-url", "default-index"]) {
      const v = get(t, key);
      if (v !== undefined && !same(v)) hit("index", at(key), `names ${shownValue(v)}${notIndex(pypiIndex)}`);
    }
    const extra = get(t, "extra-index-url");
    if (extra !== undefined && !(Array.isArray(extra) && extra.every(same))) hit("index", at("extra-index-url"), `names ${shownValue(extra)}${notIndex(pypiIndex)}`);
    const links = get(t, "find-links");
    if (links !== undefined && !(Array.isArray(links) && links.length === 0)) hit("index", at("find-links"), `adds find-links ${shownValue(links)}, which are not the index`);
    const noIndex = get(t, "no-index");
    if (noIndex !== undefined && noIndex !== false) hit("index", at("no-index"), `is ${show(noIndex)}, so files come from find-links`);
    const index = get(t, "index");
    if (index !== undefined) {
      const urls = Array.isArray(index) ? index.map((e) => (isTable(e) ? get(e, "url") : e)) : [index];
      if (!urls.every(same)) hit("index", at("index"), `names ${urls.map((u) => (typeof u === "string" ? shownUrls(u) : show(u))).join(", ")}${notIndex(pypiIndex)}`);
    }
    for (const key of ["verify-hashes", "require-hashes"]) {
      const v = get(t, key);
      if (v !== undefined && v !== true) hit("hash", at(key), `is ${show(v)}`);
    }
    const noVerify = get(t, "no-verify-hashes");
    if (noVerify !== undefined && noVerify !== false) hit("hash", at("no-verify-hashes"), `is ${show(noVerify)}`);
  }
  return out;
}

/** The [tool.uv] table of a parsed pyproject.toml, if any (a non-table is returned as is, and reported). */
const toolUv = (doc: TomlTable): unknown => {
  const tool = get(doc, "tool");
  return isTable(tool) ? get(tool, "uv") : tool === undefined ? undefined : tool;
};

/** pip's RawConfigParser, over-inclusively: [section], `key = value` or `key: value`, indented continuation lines. */
export function iniValues(text: string): { section: string; key: string; value: string }[] {
  const out: { section: string; key: string; value: string }[] = [];
  let section = "";
  let last: { section: string; key: string; value: string } | undefined;
  for (const line of text.split(/\r\n|\r|\n/)) {
    if (/^\s*([#;]|$)/.test(line)) continue;
    if (/^\s/.test(line) && last) {
      last.value += `\n${line.trim()}`;
      continue;
    }
    const sec = /^\s*\[([^\]]*)\]/.exec(line);
    if (sec) {
      section = sec[1]!.trim();
      last = undefined;
      continue;
    }
    // The first "=" or ":" separates the key from its value (a search, not a lazy group: linear on any line).
    const at = line.search(/[=:]/);
    if (at < 0) continue;
    const key = line.slice(0, at).trim();
    if (key === "") continue;
    last = { section, key: pipKey(key), value: line.slice(at + 1).replace(/^\s+/, "") };
    out.push(last);
  }
  return out;
}

/** Python's repr of a str, read back: '...' or "...", with the escapes repr writes. undefined when it is not one. */
export function unrepr(s: string): string | undefined {
  const q = s[0];
  if ((q !== "'" && q !== '"') || s.length < 2 || s[s.length - 1] !== q) return undefined;
  let out = "";
  for (let i = 1; i < s.length - 1; i++) {
    const c = s[i]!;
    if (c !== "\\") {
      if (c === q) return undefined;
      out += c;
      continue;
    }
    const n = s[++i];
    if (n === "n") out += "\n";
    else if (n === "t") out += "\t";
    else if (n === "r") out += "\r";
    else if (n === "\\" || n === "'" || n === '"') out += n;
    else if (n === "x" && /^[0-9a-f]{2}$/.test(s.slice(i + 1, i + 3))) {
      out += String.fromCharCode(parseInt(s.slice(i + 1, i + 3), 16));
      i += 2;
    } else if ((n === "u" && /^[0-9a-f]{4}$/.test(s.slice(i + 1, i + 5))) || (n === "U" && /^[0-9a-f]{8}$/.test(s.slice(i + 1, i + 9)))) {
      const len = n === "u" ? 4 : 8;
      out += String.fromCodePoint(parseInt(s.slice(i + 1, i + 1 + len), 16));
      i += len;
    } else return undefined;
  }
  return out;
}

/** `python3 -m pip config list` output: section, key and value of each line, or undefined when a line is not one. */
export function parsePipConfigList(stdout: string): { section: string; key: string; value: string }[] | undefined {
  const out: { section: string; key: string; value: string }[] = [];
  for (const line of stdout.split(/\r?\n/)) {
    if (line.trim() === "") continue;
    const m = /^([^=]*?)\.([^.=]+)=(.*)$/.exec(line);
    const value = m ? unrepr(m[3]!) : undefined;
    if (!m || value === undefined) return undefined;
    out.push({ section: m[1]!, key: pipKey(m[2]!), value });
  }
  return out;
}

/** The user's and the system's uv.toml, where uv 0.10 and 0.12 look for them. */
export function userSystemUvToml(env: Record<string, string | undefined>): string[] {
  const out: string[] = [];
  const home = env["HOME"] ?? env["USERPROFILE"];
  if (env["XDG_CONFIG_HOME"]) out.push(join(env["XDG_CONFIG_HOME"], "uv", "uv.toml"));
  else if (home) out.push(join(home, ".config", "uv", "uv.toml"));
  if (env["APPDATA"]) out.push(join(env["APPDATA"], "uv", "uv.toml"));
  for (const d of (env["XDG_CONFIG_DIRS"] || "/etc/xdg").split(":").filter((x) => x !== "")) out.push(join(d, "uv", "uv.toml"));
  out.push("/etc/uv/uv.toml");
  if (env["PROGRAMDATA"]) out.push(join(env["PROGRAMDATA"], "uv", "uv.toml"));
  return [...new Set(out)];
}

/** A file outside the tree (user, system, UV_CONFIG_FILE, PIP_CONFIG_FILE): its text, undefined when absent, or why not. */
function readOutside(path: string): { text: string } | { problem: string } | undefined {
  let bytes: Buffer;
  try {
    bytes = readFileSync(path);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") return undefined;
    return { problem: `it could not be read (${code ?? "error"})` };
  }
  if (bytes.length > 16 * 1024 * 1024) return { problem: "it is larger than 16 MiB" };
  return decodeUtf8(bytes);
}

/** The probe's time limit (v4: 15 s); after it, python3 is killed with SIGKILL. */
export const PROBE_TIMEOUT_MS = 15_000;
/** The most standard output the probe reads; more is "did not finish". */
export const MAX_PROBE_OUTPUT = 1024 * 1024;
/** The interpreter variables v4 removes before the probe runs (plus PYTHONSAFEPATH set, so no directory joins sys.path). */
export const PROBE_DROPPED_ENV = ["PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PYTHONUSERBASE"];

/**
 * The real probe for main.ts: `python3 -m pip <args>` run the way soak runs `npm --version` (installedVersion): from
 * the filesystem root, never the scanned tree or a temporary directory (python3 -m puts its working directory first
 * on sys.path, so a pip/__main__.py there would run instead of pip), with PYTHONPATH, PYTHONSTARTUP, PYTHONHOME and
 * PYTHONUSERBASE removed from the environment, PIP_CONFIG_FILE kept (it decides what pip reads), a 15 s timeout and at
 * most 1 MiB of output. python3 is found on PATH by src/exec.ts and run by its absolute path; one inside `root` (the
 * scanned tree) is not run at all ({ notRun }). "unavailable" when python3 cannot be found or started. `spawn` is
 * spawnSync (tests pass a recorder).
 */
export function pipConfigProbe(env: Record<string, string | undefined>, spawn: typeof spawnSync = spawnSync, root?: string): PipConfigProbe {
  return (args) => {
    const clean: Record<string, string | undefined> = { ...env, PYTHONSAFEPATH: "1", PIP_DISABLE_PIP_VERSION_CHECK: "1", PIP_NO_INPUT: "1" };
    for (const k of PROBE_DROPPED_ENV) delete clean[k];
    const python = findProgram("python3", env, root === undefined ? [] : [root]);
    if ("missing" in python) return "unavailable";
    if ("refused" in python) return { notRun: python.refused };
    const r = spawn(python.path, ["-m", "pip", ...args], {
      cwd: parse(process.cwd()).root,
      env: clean,
      encoding: "utf8",
      timeout: PROBE_TIMEOUT_MS,
      maxBuffer: MAX_PROBE_OUTPUT,
      killSignal: "SIGKILL",
      stdio: ["ignore", "pipe", "ignore"],
    });
    if (r.error) {
      const code = (r.error as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "EACCES") return "unavailable";
      return { code: null, stdout: "" };
    }
    return { code: r.status, stdout: r.stdout ?? "" };
  };
}

/** Collects every install setting soak can see (see the module comment). Never throws. */
export function collectInstallSettings(tree: SettingsTree, opts: SettingsOptions): InstallSettings {
  const global: SettingHit[] = [];
  const env = opts.env;
  const pypiIndex = opts.pypiIndex;

  // Environment.
  for (const [name, raw] of Object.entries(env)) {
    if (raw === undefined || raw === "" || !name.startsWith("PIP_")) continue;
    const key = pipKey(name.slice(4));
    if ((INDEX_KEYS as readonly string[]).includes(key)) global.push(...pipValueHits(key, raw, `environment variable ${name}`, pypiIndex, {}));
  }
  const uvEnv = (name: string): string | undefined => (env[name] === undefined || env[name] === "" ? undefined : env[name]);
  for (const name of ["UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_EXTRA_INDEX_URL", "UV_INDEX"]) {
    const v = uvEnv(name);
    if (v !== undefined && otherUrls(v, pypiIndex).length > 0) global.push({ kind: "index", where: `environment variable ${name}`, detail: `names ${shownUrls(v)}${notIndex(pypiIndex)}` });
  }
  const links = uvEnv("UV_FIND_LINKS");
  if (links !== undefined) global.push({ kind: "index", where: "environment variable UV_FIND_LINKS", detail: `adds find-links ${shownUrls(links)}, which are not the index` });
  const noIndex = uvEnv("UV_NO_INDEX");
  if (noIndex !== undefined && !isFalse(noIndex)) global.push({ kind: "index", where: "environment variable UV_NO_INDEX", detail: `is ${JSON.stringify(noIndex.slice(0, 40))}, so files come from find-links` });
  const noVerify = uvEnv("UV_NO_VERIFY_HASHES");
  if (noVerify !== undefined && !isFalse(noVerify)) global.push({ kind: "hash", where: "environment variable UV_NO_VERIFY_HASHES", detail: `is ${JSON.stringify(noVerify.slice(0, 40))}` });
  for (const name of ["UV_VERIFY_HASHES", "UV_REQUIRE_HASHES"]) {
    const v = uvEnv(name);
    if (v !== undefined && isFalse(v)) global.push({ kind: "hash", where: `environment variable ${name}`, detail: `is ${JSON.stringify(v.slice(0, 40))}` });
  }

  // Files outside the tree: UV_CONFIG_FILE, the user's and the system's uv.toml, PIP_CONFIG_FILE.
  const outsideToml = (path: string, where: string): void => {
    const read = readOutside(path);
    if (read === undefined) return;
    const parsed = "problem" in read ? read : parseToml(read.text);
    if ("problem" in parsed) global.push({ kind: "index", where, detail: `could not be read (${parsed.problem}), so what it sets is unknown` });
    else global.push(...uvTableHits(parsed.doc, where, pypiIndex, {}));
  };
  // A relative UV_CONFIG_FILE or PIP_CONFIG_FILE names a file relative to the install's working directory, which soak
  // cannot know (the probe runs from the filesystem root, soak from wherever it was started): fail closed.
  const relativeFile = (name: string, value: string): boolean => {
    if (isAbsolute(value)) return false;
    global.push({ kind: "index", where: `${name} ${value}`, detail: "is a relative path, so what the install reads depends on its working directory" });
    return true;
  };
  const uvConfigFile = uvEnv("UV_CONFIG_FILE");
  if (uvConfigFile !== undefined && !relativeFile("UV_CONFIG_FILE", uvConfigFile)) {
    const read = readOutside(uvConfigFile);
    if (read === undefined) global.push({ kind: "index", where: `UV_CONFIG_FILE ${uvConfigFile}`, detail: "names a file that does not exist, so what uv reads is unknown" });
    else outsideToml(uvConfigFile, `UV_CONFIG_FILE ${uvConfigFile}`);
  }
  for (const path of opts.uvConfigFiles ?? userSystemUvToml(env)) outsideToml(path, path);
  const pipConfigFile = uvEnv("PIP_CONFIG_FILE");
  if (pipConfigFile !== undefined && !relativeFile("PIP_CONFIG_FILE", pipConfigFile)) {
    const read = readOutside(pipConfigFile);
    if (read !== undefined && "problem" in read) global.push({ kind: "index", where: `PIP_CONFIG_FILE ${pipConfigFile}`, detail: `could not be read (${read.problem}), so what it sets is unknown` });
    else if (read !== undefined) for (const v of iniValues(read.text)) global.push(...pipValueHits(v.key, v.value, `PIP_CONFIG_FILE ${pipConfigFile} [${v.section}] ${v.key}`, pypiIndex, {}));
  }

  // Directories above the root: they govern every lock in it.
  if (opts.ancestors !== false) {
    for (let d = dirname(tree.root); ; d = dirname(d)) {
      for (const name of ["uv.toml", "pyproject.toml"]) {
        const path = join(d, name);
        const read = readToml(path);
        if ("problem" in read) {
          if (/\((ENOENT|ENOTDIR)\)/.test(read.problem)) continue;
          global.push({ kind: "index", where: path, detail: `could not be read (${read.problem}), so what it sets is unknown` });
          continue;
        }
        const table = name === "uv.toml" ? read.doc : toolUv(read.doc);
        if (table === undefined) continue;
        if (!isTable(table)) global.push({ kind: "index", where: `${path} [tool.uv]`, detail: "is not a table, so what it sets is unknown" });
        else global.push(...uvTableHits(table, name === "uv.toml" ? path : `${path} [tool.uv]`, pypiIndex, {}));
      }
      if (dirname(d) === d) break;
    }
  }

  // pip.conf and pip.ini anywhere in the tree.
  for (const [rel, type] of tree.types) {
    if (isPipConfName(posix.basename(rel)) && type !== "dir") {
      global.push({ kind: "index", where: rel, file: rel, detail: "is a pip configuration file in the repository; pip reads one wherever PIP_CONFIG_FILE or a virtual environment points at it, and soak does not model which" });
    }
  }

  // The pip probe.
  let pipNotRead: string | undefined;
  if (opts.probe) {
    const r = opts.pipConfig ? opts.pipConfig(["config", "list"]) : "unavailable";
    if (r === "unavailable") pipNotRead = "python3 could not be run";
    else if ("notRun" in r) pipNotRead = r.notRun;
    else if (r.code !== 0) pipNotRead = r.code === null ? "`python3 -m pip config list` did not finish (timeout, or more than 1 MiB of output)" : `\`python3 -m pip config list\` exited ${r.code}`;
    else {
      const values = parsePipConfigList(r.stdout);
      if (values === undefined) pipNotRead = "`python3 -m pip config list` printed output soak does not read";
      else {
        for (const v of values) {
          // The :env: lines are PIP_* variables, read above under their own names.
          if (v.section === ":env:") continue;
          global.push(...pipValueHits(v.key, v.value, `pip configuration ${v.section}.${v.key}`, pypiIndex, {}));
        }
      }
    }
  }

  // uv.toml and pyproject.toml [tool.uv] in the tree, each governing its directory and below.
  const scoped: SettingHit[] = [];
  for (const [rel, type] of tree.types) {
    // Folded, as manifest.ts matches names: a case-insensitive file system opens UV.toml as uv.toml, and so does uv.
    const uvToml = isUvTomlName(posix.basename(rel));
    if (!uvToml && fold(posix.basename(rel)) !== "pyproject.toml") continue;
    const scope = posix.dirname(rel);
    if (type === "symlink") {
      scoped.push({ kind: "index", where: rel, file: rel, scope, detail: "is a symlink, which wormsign does not follow, so what it sets is unknown" });
      continue;
    }
    if (type !== "file") continue;
    const read = tree.toml(rel);
    if ("problem" in read) {
      scoped.push({ kind: "index", where: rel, file: rel, scope, detail: `could not be read (${read.problem}), so what it sets is unknown` });
      continue;
    }
    const table = uvToml ? read.doc : toolUv(read.doc);
    if (table === undefined) continue;
    if (!isTable(table)) scoped.push({ kind: "index", where: `${rel} [tool.uv]`, file: rel, scope, detail: "is not a table, so what it sets is unknown" });
    else scoped.push(...uvTableHits(table, uvToml ? rel : `${rel} [tool.uv]`, pypiIndex, { file: rel, scope }));
  }

  const under = (dir: string, scope: string): boolean => scope === "." || dir === scope || dir.startsWith(`${scope}/`);
  return {
    global,
    ...(pipNotRead !== undefined ? { pipNotRead } : {}),
    forDir: (dir) => [...global, ...scoped.filter((h) => h.scope !== undefined && under(dir, h.scope))],
  };
}

const BUILD_KEYS = ["no-binary", "no-binary-package", "no-build-isolation", "no-build-isolation-package", "extra-build-dependencies", "extra-build-variables", "config-settings", "config-settings-package"];
const isSet = (v: unknown): boolean => v !== undefined && v !== false && v !== "" && !(Array.isArray(v) && v.length === 0) && !(isTable(v) && Object.keys(v).length === 0);

/**
 * WS-SK-005 for build-forcing keys in a uv.toml, a pyproject.toml's [tool.uv] or a PEP 723 script block's [tool.uv]
 * (uv reads the same settings there for `uv run --script`). `source` defaults to the file's (folded) name: uv.toml,
 * else pyproject.toml; a script's block (`doc` is its metadata) is "script".
 */
export function buildConfigFindings(rel: string, doc: TomlTable, source: "uv.toml" | "pyproject.toml" | "script" = isUvTomlName(posix.basename(rel)) ? "uv.toml" : "pyproject.toml"): Finding[] {
  const isUvToml = source === "uv.toml";
  const table = isUvToml ? doc : toolUv(doc);
  if (!isTable(table)) return [];
  const out: Finding[] = [];
  const prefix = isUvToml ? "" : "[tool.uv] ";
  const where = source === "script" ? " in its `# /// script` block" : "";
  for (const [label, t] of [["", table] as const, ["[pip] ", get(table, "pip")] as const]) {
    if (!isTable(t)) continue;
    for (const key of BUILD_KEYS) {
      const v = get(t, key);
      if (!isSet(v)) continue;
      const value = show(v);
      out.push(
        makeFinding({
          ruleId: "WS-SK-005",
          severity: "medium",
          message: `${rel} sets ${prefix}${label}${key} = ${value.slice(0, 200)}${where}: installs that read it build packages from source${key.startsWith("no-build-isolation") ? " in the install's own environment" : ""}, and build requirements are resolved at install time, not pinned by any lock. Remove it, or pin the build requirements with ==-pinned build-constraint-dependencies`,
          file: rel,
          key: `pypi:build-config ${prefix}${label}${key} ${keyDigest(value)}`,
        }),
      );
    }
  }
  return out;
}
