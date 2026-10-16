// Offline stand-ins for npm, pnpm, yarn, bun, gh, GNU stat, python3 (`-m pip`, the tomllib reader for
// uv.toml and the ensurepip version), pip, pip3 and uv, used by test/harden.test.ts.
// Each emulates what harden-dev.sh asks for (`--version`, `config get`, `npm root -g`, `gh auth status`,
// `stat -c/-f`, `pip config debug|set`, `uv lock --offline`), and `pip config list|get`, reading
// the same files and environment variables the real tool reads, with the precedence and output
// observed in the experiments listed in docs/hardening.md.
// Every call is appended to $STUB_LOG so tests can see what ran, from where, with which env.
import { spawnSync } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";

const tool = basename(process.argv[1]);
const args = process.argv.slice(2);
const env = process.env;
const HOME = env.HOME ?? "";
const TOOL = tool.toUpperCase();

const out = (s) => process.stdout.write(`${s}\n`);
const die = (msg, code = 1) => {
  process.stderr.write(`${msg}\n`);
  process.exit(code);
};
const version = env[`STUB_${TOOL}_VERSION`] ?? "0.0.0";
const major = Number(version.split(".")[0]);
const ge = (v) => {
  const a = version.split(/[.-]/).map(Number);
  const b = v.split(".").map(Number);
  for (let i = 0; i < b.length; i++) if ((a[i] ?? 0) !== b[i]) return (a[i] ?? 0) > b[i];
  return true;
};
const read = (p) => (existsSync(p) ? readFileSync(p, "utf8") : "");

if (env.STUB_LOG) {
  appendFileSync(
    env.STUB_LOG,
    JSON.stringify({
      tool,
      args,
      cwd: process.cwd(),
      corepackNetwork: env.COREPACK_ENABLE_NETWORK ?? null,
      // What harden-dev.sh sets (or unsets) for pip and uv.
      pipVersionCheck: env.PIP_DISABLE_PIP_VERSION_CHECK ?? null,
      virtualEnv: env.VIRTUAL_ENV ?? null,
      uvCache: env.UV_CACHE_DIR ?? null,
      uvPythonDownloads: env.UV_PYTHON_DOWNLOADS ?? null,
      probe: tool === "uv" && args[0] === "lock" ? read("pyproject.toml") : null,
    }) + "\n",
  );
}

// A corepack shim with nothing cached: downloads (here: writes the cache) unless network is off.
if (env[`STUB_${TOOL}_MODE`] === "corepack") {
  if (env.COREPACK_ENABLE_NETWORK === "0") die("Network access disabled by the environment; can't reach npm repository");
  mkdirSync(join(HOME, ".cache", "node", "corepack", "v1", tool, version), { recursive: true });
}
if (env[`STUB_${TOOL}_MODE`] === "broken") die("boom");
// Reports its version but fails everything else, as with a config file it cannot parse.
if (env[`STUB_${TOOL}_MODE`] === "config-fails" && args[0] !== "--version") die("config error");

/** ini-style `key = value` / `key value` files: last occurrence wins, quotes stripped. */
function iniGet(text, key, sepRe) {
  let v;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#") || line.startsWith(";")) continue;
    const m = line.match(new RegExp(`^"?([^"=:\\s]+)"?${sepRe}(.*)$`));
    if (m && m[1] === key) v = m[2].trim().replace(/^"(.*)"$/, "$1");
  }
  return v;
}
/**
 * Top-level `key: value` YAML lines. The key may be plain, 'single-quoted' or "double-quoted"
 * (with JSON-style escapes such as \u0041), as YAML allows. dupError: pnpm's YAML parser
 * rejects a file in which any top-level key appears twice.
 */
function yamlGet(text, key, dupError) {
  let v;
  const seen = new Set();
  const unquote = (k) => (k.startsWith('"') ? JSON.parse(k) : k.startsWith("'") ? k.slice(1, -1).replace(/''/g, "'") : k);
  for (const line of text.split("\n")) {
    const m = line.match(/^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[A-Za-z][\w-]*)\s*:\s*(.*)$/);
    if (!m) continue;
    const k = unquote(m[1]);
    if (seen.has(k) && dupError) die(`Map keys must be unique at line ... (${k})`);
    seen.add(k);
    if (k === key) v = m[2].replace(/\s+#.*$/, "").trim().replace(/^"(.*)"$/, "$1");
  }
  return v;
}
const snake = (k) => k.replace(/-/g, "_").replace(/([a-z])([A-Z])/g, "$1_$2").toLowerCase();
const envGet = (prefix, key) => {
  const want = `${prefix}${snake(key)}`.toLowerCase();
  const hit = Object.keys(env).find((k) => k.toLowerCase() === want);
  return hit === undefined ? undefined : env[hit];
};
const show = (v) => (v === undefined ? "undefined" : String(v));

/** The directories from the cwd up to the root, nearest first. */
function upward() {
  const dirs = [];
  for (let d = process.cwd(); ; d = dirname(d)) {
    dirs.push(d);
    if (dirname(d) === d) return dirs;
  }
}

function npmGet(key) {
  const userconfig = env.NPM_CONFIG_USERCONFIG ?? env.npm_config_userconfig ?? join(HOME, ".npmrc");
  if (key === "userconfig") return userconfig;
  // npm's project config, which beats the user's: the .npmrc in the local prefix, the nearest directory from the cwd up
  // that holds a package.json or node_modules (else the cwd), unless that file is the user config (npm 10.9.2,
  // @npmcli/config loadLocalPrefix and loadProjectConfig).
  const prefix = upward().find((d) => existsSync(join(d, "package.json")) || existsSync(join(d, "node_modules"))) ?? process.cwd();
  const project = join(prefix, ".npmrc") === userconfig ? "" : read(join(prefix, ".npmrc"));
  const set = (k) => envGet("npm_config_", k) ?? iniGet(project, k, "\\s*=\\s*") ?? iniGet(read(userconfig), k, "\\s*=\\s*");
  // npm 11.10.x folds min-release-age into a computed `before` date and reports it as null.
  const age = set("min-release-age");
  if (version.startsWith("11.10.") && age !== undefined && key === "min-release-age") return "null";
  if (version.startsWith("11.10.") && age !== undefined && key === "before") {
    return new Date(Date.now() - Number(age) * 864e5).toString();
  }
  const defaults = {
    "ignore-scripts": "false",
    "min-release-age": ge("11.10") ? "null" : undefined,
    before: "null",
    "dangerously-allow-all-scripts": major >= 12 ? "false" : undefined,
  };
  return set(key) ?? defaults[key];
}

const pnpmDir = env.XDG_CONFIG_HOME
  ? join(env.XDG_CONFIG_HOME, "pnpm")
  : process.platform === "darwin"
    ? join(HOME, "Library/Preferences/pnpm")
    : join(HOME, ".config/pnpm");
// pnpm 11 reads config.yaml before any command: a duplicate key fails `--version` too.
if (tool === "pnpm" && major >= 11) yamlGet(read(join(pnpmDir, "config.yaml")), "", true);

function pnpmGet(key) {
  const camel = key.replace(/-([a-z])/g, (_m, c) => c.toUpperCase());
  // "rejects-config": a pnpm that cannot parse any config.yaml, to exercise --apply's undo.
  if (env.STUB_PNPM_MODE === "rejects-config" && existsSync(join(pnpmDir, "config.yaml"))) die("ERR_PNPM_CONFIG: cannot parse");
  if (major >= 11) return envGet("pnpm_config_", camel) ?? yamlGet(read(join(pnpmDir, "config.yaml")), camel, true);
  const kebab = camel.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);
  return envGet("npm_config_", kebab) ?? iniGet(read(join(HOME, ".npmrc")), kebab, "\\s*=\\s*") ?? iniGet(read(join(pnpmDir, "rc")), kebab, "\\s*=\\s*");
}

/**
 * Yarn Classic's .yarnrc files, nearest first: the one in the cwd and in every directory above it, then ~/.yarnrc
 * (yarn 1.22 src/rc.js: a nearer file overrides a farther one).
 */
const yarnrcs = () => [...upward().map((d) => join(d, ".yarnrc")), join(HOME, ".yarnrc")];

function yarnGet(key) {
  const fromEnv = envGet("YARN_", key);
  if (major === 1) {
    const v = fromEnv ?? yarnrcs().map((f) => iniGet(read(f), key, "\\s+")).find((x) => x !== undefined);
    return v ?? (key === "ignore-scripts" ? "false" : undefined);
  }
  if (key === "npmMinimalAgeGate" && !ge("4.10")) die(`Usage Error: Couldn't find a configuration settings named "${key}"`);
  const v = fromEnv ?? yamlGet(read(join(HOME, ".yarnrc.yml")), key, false);
  if (v !== undefined) return key === "npmMinimalAgeGate" ? String(parseInt(v, 10)) : v;
  if (key === "enableScripts") return ge("4.14") ? "false" : "true";
  if (key === "npmMinimalAgeGate") return ge("4.15") ? "1440" : "0";
  return undefined;
}

const getters = { npm: npmGet, pnpm: pnpmGet, yarn: yarnGet };


// ---- pip: `python3 -m pip`, pip3 and pip -----------------------------------------------------
// One pip installation per runner: STUB_<RUNNER>_VERSION, STUB_<RUNNER>_LOCATION (the `--version`
// line names it; two runners with the same line are the same pip), STUB_<RUNNER>_USERCONF (its new
// user config file; pip 26.2 on macOS reads $XDG_DATA_HOME/pip when that directory exists).
// STUB_<RUNNER>_MODE: "nopip" (python3 has no pip module), "set-breaks-config" (`config set` also
// leaves a duplicate key, so every later command fails to load the file), "silent" (`config list` and
// `config debug` print nothing, whatever the settings: a listing lost some other way).
// pip's own `quiet` and `verbose` settings act as in pip 26.1.2: quiet silences what pip logs at INFO
// (the listings, `config get`'s value and "Writing to"), verbose adds a "For variant ..., will try
// loading ..." line for each file the command loads; PIP_QUIET / PIP_VERBOSE win over the files.
// Files and precedence as pip 26.1.2's configuration.py: global < user (legacy ~/.pip/pip.conf,
// then the new file) < site < PIP_CONFIG_FILE < PIP_* variables; the user files are skipped when
// PIP_CONFIG_FILE names an existing file, and every file when it is /dev/null.
function pipMain(runner, argv) {
  const R = runner.toUpperCase();
  const pipVersion = env[`STUB_${R}_VERSION`] ?? "26.1.2";
  const location = env[`STUB_${R}_LOCATION`] ?? "/stub/lib/python3.14/site-packages/pip";
  const mode = env[`STUB_${R}_MODE`];
  if (mode === "nopip") die("/stub/bin/python3: No module named pip");
  const parent = dirname(HOME);
  const files = {
    global: [env.STUB_PIP_GLOBAL ?? join(parent, "etc", "pip.conf")],
    user: [join(HOME, ".pip", "pip.conf"), env[`STUB_${R}_USERCONF`] ?? join(HOME, ".config", "pip", "pip.conf")],
    site: [join(parent, "site", "pip.conf")],
  };
  const envFile = env.PIP_CONFIG_FILE;
  const loadUser = !(envFile && existsSync(envFile));
  const variants = [["global", files.global], ...(loadUser ? [["user", files.user]] : []), ["site", files.site], ["env", envFile ? [envFile] : []]];
  const norm = (k) => k.toLowerCase().replace(/_/g, "-").replace(/^--/, "");
  const loadFail = (msg) => die(`Configuration file could not be loaded.\n${msg}`, 2);
  /**
   * configparser.RawConfigParser (strict) as pip reads a file: its sections (Map section -> Map key ->
   * value, each section's own keys) and its [DEFAULT] keys, which RawConfigParser.items(section) adds to
   * every section (a section's own key wins) and which is never listed as a section itself.
   */
  function parse(fname) {
    const sections = new Map();
    const defaults = new Map();
    let cur;
    let curName;
    let last;
    readFileSync(fname, "utf8").split("\n").forEach((raw, i) => {
      const line = raw.replace(/\r$/, "");
      if (line.trim() === "" || /^\s*[#;]/.test(line)) return;
      if (/^\s/.test(line) && cur && last !== undefined) {
        cur.set(last, `${cur.get(last)}\n${line.trim()}`);
        return;
      }
      const head = /^\[([^\]]+)\]/.exec(line);
      if (head) {
        if (head[1] === "DEFAULT") {
          cur = defaults;
        } else {
          if (sections.has(head[1])) loadFail(`While reading from '${fname}' [line ${String(i + 1).padStart(2)}]: section '${head[1]}' already exists`);
          cur = new Map();
          sections.set(head[1], cur);
        }
        curName = head[1];
        last = undefined;
        return;
      }
      if (!cur) loadFail(`File contains no section headers.\nfile: '${fname}', line: ${i + 1}\n'${line}\\n'`);
      const kv = /^([^=:]+?)\s*[=:]\s*(.*)$/.exec(line);
      if (!kv) loadFail(`Source contains parsing errors: '${fname}'`);
      const key = kv[1].trim().toLowerCase();
      if (cur.has(key)) loadFail(`While reading from '${fname}' [line ${String(i + 1).padStart(2)}]: option '${key}' in section '${curName}' already exists`);
      cur.set(key, kv[2].trim());
      last = key;
    });
    return { sections, defaults };
  }
  /** variant -> [fname, Map("section.key" -> value)] for each existing file with a section. */
  const loaded = new Map();
  const parsed = new Map();
  if (envFile !== "/dev/null") {
    for (const [variant, list] of variants) {
      for (const f of list) {
        if (!existsSync(f)) continue;
        const file = parse(f);
        parsed.set(f, file);
        if (file.sections.size === 0) continue;
        const flat = new Map();
        for (const [section, kv] of file.sections) for (const [k, v] of new Map([...file.defaults, ...kv])) flat.set(`${section}.${norm(k)}`, v);
        loaded.set(f, [variant, flat]);
      }
    }
  }
  const envVars = Object.keys(env).filter((k) => k.startsWith("PIP_")).map((k) => [k.slice(4).toLowerCase(), env[k]])
    .filter(([n]) => n !== "version" && n !== "help");
  const repr = (v) => {
    const q = v.includes("'") && !v.includes('"') ? '"' : "'";
    let o = "";
    for (const ch of v) {
      if (ch === "\\" || ch === q) o += `\\${ch}`;
      else if (ch === "\n") o += "\\n";
      else if (ch === "\t") o += "\\t";
      else if (ch < " ") o += `\\x${ch.charCodeAt(0).toString(16).padStart(2, "0")}`;
      else o += ch;
    }
    return q + o + q;
  };
  const sub = argv[0] === "config" ? argv.filter((a) => a !== "--user")[1] : argv[0];
  if (argv[0] === "--version") return out(`pip ${pipVersion} from ${location} (python 3.14)`);
  if (argv[0] !== "config") die(`stub pip: unexpected ${argv.join(" ")}`);
  const userOnly = argv.includes("--user");
  /** A count option (quiet, verbose) as pip's option parser sets it for `pip config`: per section the
   * last file's value, empty values dropped, [global] then [config] then the environment. */
  const count = (name) => {
    let v;
    for (const section of ["global", "config"]) {
      let w;
      for (const [, [, flat]] of loaded) if (flat.has(`${section}.${name}`)) w = flat.get(`${section}.${name}`);
      if (w) v = w;
    }
    const e = envVars.find(([n]) => norm(n) === name);
    if (e && e[1]) v = e[1];
    if (v === undefined) return 0;
    const b = { y: 1, yes: 1, t: 1, true: 1, on: 1, 1: 1, n: 0, no: 0, f: 0, false: 0, off: 0, 0: 0 }[v.toLowerCase()];
    return b ?? (Number.parseInt(v, 10) || 0);
  };
  const quiet = count("quiet") > 0;
  if (count("verbose") > 0 && !quiet) {
    for (const [variant, list] of variants) if (!userOnly || variant === "user") for (const f of list) out(`For variant '${variant}', will try loading '${f}'`);
  }
  /** What pip logs at INFO: nothing when quiet. */
  const info = (line) => {
    if (!quiet) out(line);
  };
  if ((sub === "list" || sub === "debug") && mode === "silent") return;
  if (sub === "list") {
    const entries = [...loaded].map(([f, [, flat]]) => [f, flat]);
    entries.push([":env:", new Map(envVars.map(([n, v]) => [`:env:.${norm(n)}`, v]))]);
    entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    for (const [, flat] of entries) for (const k of [...flat.keys()].sort()) info(`${k}=${repr(flat.get(k))}`);
    return;
  }
  if (sub === "debug") {
    info("env_var:");
    for (const [n, v] of [...envVars].sort(([a], [b]) => (a < b ? -1 : 1))) info(`  PIP_${n.toUpperCase()}=${repr(v)}`);
    for (const [variant, list] of [...variants].sort(([a], [b]) => (a < b ? -1 : 1))) {
      info(`${variant}:`);
      for (const f of list) {
        info(`  ${f}, exists: ${existsSync(f) ? "True" : "False"}`);
        // pip's log formatter indents every line of a multi-line value.
        for (const [k, v] of loaded.get(f)?.[1] ?? []) info(`    ${k}: ${v}`.replace(/\n/g, "\n    "));
      }
    }
    return;
  }
  if (!userOnly) die(`stub pip: expected --user: ${argv.join(" ")}`);
  const key = norm(argv[argv.length - (sub === "set" ? 2 : 1)]);
  const [section, name] = [key.slice(0, key.indexOf(".")), key.slice(key.indexOf(".") + 1)];
  if (sub === "get") {
    let v;
    if (loadUser) for (const f of files.user) if (loaded.get(f)?.[1].has(key)) v = loaded.get(f)[1].get(key);
    if (v === undefined) die(`ERROR: No such key - ${argv[argv.length - 1]}`);
    return info(v);
  }
  if (sub === "set") {
    if (!loadUser) die("ERROR: Fatal Internal error [id=2]. Please report as a bug.");
    const target = files.user[files.user.length - 1];
    const { sections, defaults } = parsed.get(target) ?? { sections: new Map(), defaults: new Map() };
    if (!sections.has(section)) sections.set(section, new Map());
    sections.get(section).set(name, argv[argv.length - 1]);
    info(`Writing to ${target}`);
    let text = "";
    // RawConfigParser.write: [DEFAULT] first, then each section with its own keys.
    for (const [s, kv] of defaults.size > 0 ? [["DEFAULT", defaults], ...sections] : sections) {
      text += `[${s}]\n`;
      for (const [k, v] of kv) text += `${k} = ${v.replace(/\n/g, "\n\t")}\n`;
      text += "\n";
    }
    if (mode === "set-breaks-config") text += `[${section}]\n`;
    try {
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, text);
    } catch (e) {
      die(`ERROR: An error occurred while writing to the configuration file ${target}: ${e.message}`);
    }
    return;
  }
  die(`stub pip: unexpected ${argv.join(" ")}`);
}

// ---- python3: `-m pip ...`, harden-dev.sh's tomllib reader for uv.toml (UV_USER_PY), and ensurepip ----
// STUB_PYTHON3_MODE=no-tomllib: a Python older than 3.11. STUB_PYTHON3_ENSUREPIP: the pip version its
// ensurepip bundles (default 26.1.2; "none": no ensurepip module).
function pythonMain(argv) {
  if (argv[0] === "-m" && argv[1] === "pip") return pipMain("python3", argv.slice(2));
  if (argv[0] === "-I" && argv[1] === "-c" && argv[2]?.includes("wormsign:uv-user-overrides")) {
    if (env.STUB_PYTHON3_MODE === "no-tomllib") die("ModuleNotFoundError: No module named 'tomllib'");
    // The records UV_USER_PY prints.
    const t = tomlTables(read(argv[3]));
    const show = (v) => (v === false ? "false" : typeof v === "string" ? JSON.stringify(v) : "other");
    const pip = t.get("pip") instanceof Map ? t.get("pip") : new Map();
    if (pip.has("exclude-newer")) out(`pip\t${show(pip.get("exclude-newer"))}`);
    const pkgs = pip.get("exclude-newer-package");
    if (pkgs instanceof Map) for (const [n, v] of pkgs) out(`pip-package\t${JSON.stringify(n)}\t${show(v)}`);
    const index = t.get("index");
    (Array.isArray(index) ? index : []).forEach((e, i) => {
      if (!e.has("exclude-newer")) return;
      const url = typeof e.get("url") === "string" ? e.get("url") : "";
      let host = "";
      try {
        host = new URL(url).hostname;
      } catch {
        // not a URL: no host
      }
      const kind = e.get("default") === true ? "default" : host === "pypi.org" ? "pypi" : "other";
      const name = typeof e.get("name") === "string" ? e.get("name") : `#${i + 1}`;
      out(`index\t${JSON.stringify(name)}\t${JSON.stringify(url)}\t${kind}\t${show(e.get("exclude-newer"))}`);
    });
    return;
  }
  if (argv[0] === "-I" && argv[1] === "-c" && argv[2]?.includes("ensurepip.version()")) {
    const v = env.STUB_PYTHON3_ENSUREPIP ?? "26.1.2";
    if (v === "none") die("ModuleNotFoundError: No module named 'ensurepip'");
    return out(v);
  }
  die(`stub python3: unexpected ${argv.join(" ")}`);
}

/**
 * The small TOML subset these fixtures use: table -> key -> string | boolean | number | inline table; an
 * array of tables ([[index]]) is an array of such maps.
 */
function tomlTables(text) {
  const tables = new Map([["", new Map()]]);
  let cur = tables.get("");
  const value = (v) => {
    v = v.replace(/\s+#.*$/, "").trim();
    if (v === "true" || v === "false") return v === "true";
    if (/^".*"$/.test(v)) return JSON.parse(v);
    if (/^-?\d+$/.test(v)) return Number(v);
    const inline = /^\{(.*)\}$/.exec(v);
    if (inline) {
      const m = new Map();
      for (const part of inline[1].split(",")) {
        const kv = /^\s*([\w.-]+)\s*=\s*(.+?)\s*$/.exec(part);
        if (kv) m.set(kv[1], value(kv[2]));
      }
      return m;
    }
    return v;
  };
  for (const line of text.split("\n")) {
    const array = /^\s*\[\[([^\]]+)\]\]\s*$/.exec(line);
    if (array) {
      const name = array[1].trim();
      if (!Array.isArray(tables.get(name))) tables.set(name, []);
      cur = new Map();
      tables.get(name).push(cur);
      continue;
    }
    const head = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (head) {
      cur = new Map();
      tables.set(head[1].trim(), cur);
      continue;
    }
    const kv = /^\s*([\w.-]+)\s*=\s*(.+)$/.exec(line);
    if (kv) cur.set(kv[1], value(kv[2]));
  }
  return tables;
}

// ---- uv: `--version` and `uv lock --offline` in the probe project -------------------------------
// Settings as uv 0.10.9 and 0.12.21 resolve them: UV_EXCLUDE_NEWER, else the project's (the first
// directory from the cwd up holding a uv.toml or a pyproject.toml with a [tool.uv] table), else the
// user's ${XDG_CONFIG_HOME:-~/.config}/uv/uv.toml; UV_CONFIG_FILE replaces both files and UV_NO_CONFIG
// drops them. The lock's [options] are written in the version's format: uv >= 0.12 writes a
// placeholder exclude-newer date beside a relative span, uv 0.10 the date the span gave.
// STUB_UV_MODE: "fails" (uv cannot read its config), "no-lock" (exits 0, writes nothing),
// "bad-span" (records a span in months, which uv never writes).
// UV_WORKING_DIR is --directory (uv moves there first) and UV_PROJECT is --project (the project is found,
// and its lock written, from there); UV_FROZEN (--check-exists) and UV_LOCKED (--locked) fail when the
// project has no lock yet. All four exist in uv 0.10.9 and 0.12.21.
function uvMain(argv) {
  if (argv[0] === "--version") return out(`uv ${version} (stub 2026-01-01)`);
  if (argv.join(" ") !== "lock --offline") die(`stub uv: unexpected ${argv.join(" ")}`, 2);
  const mode = env.STUB_UV_MODE;
  if (mode === "fails") die("error: Failed to parse: `uv.toml`\n  Caused by: TOML parse error at line 1, column 17", 2);
  if (env.UV_WORKING_DIR) process.chdir(env.UV_WORKING_DIR);
  const root = env.UV_PROJECT ? resolve(env.UV_PROJECT) : process.cwd();
  if (!existsSync(join(root, "pyproject.toml"))) die("error: No `pyproject.toml` found in current directory or any parent directory", 2);
  for (const flag of ["UV_FROZEN", "UV_LOCKED"]) {
    if (env[flag] && !existsSync(join(root, "uv.lock"))) {
      die(`error: Unable to find lockfile at \`uv.lock\`, but \`${flag}=1\` was provided. To create a lockfile, run \`uv lock\` or \`uv sync\` without the flag.`, 2);
    }
  }
  let project;
  for (let d = root; ; d = dirname(d)) {
    if (existsSync(join(d, "uv.toml"))) {
      project = tomlTables(read(join(d, "uv.toml"))).get("");
      break;
    }
    const py = tomlTables(read(join(d, "pyproject.toml")));
    if ([...py.keys()].some((t) => t === "tool.uv" || t.startsWith("tool.uv."))) {
      project = py.get("tool.uv") ?? new Map();
      break;
    }
    if (dirname(d) === d) break;
  }
  const userFile = join(env.XDG_CONFIG_HOME ?? join(HOME, ".config"), "uv", "uv.toml");
  const user = existsSync(userFile) ? tomlTables(read(userFile)).get("") : undefined;
  const sources = env.UV_NO_CONFIG ? [] : env.UV_CONFIG_FILE ? [tomlTables(read(env.UV_CONFIG_FILE)).get("")] : [project, user];
  const setting = (key) => sources.map((t) => t?.get(key)).find((v) => v !== undefined);
  const global = env.UV_EXCLUDE_NEWER ?? setting("exclude-newer");
  const perPackage = setting("exclude-newer-package");
  const new12 = ge("0.12");
  const SENTINEL = "0001-01-01T00:00:00Z";
  const UNITS = { day: ["D", 86400], days: ["D", 86400], d: ["D", 86400], week: ["W", 604800], weeks: ["W", 604800], w: ["W", 604800], hour: ["H", 3600], hours: ["H", 3600], h: ["H", 3600] };
  function cutoff(v) {
    if (v === false) return undefined;
    let m = /^(\d+)\s*([a-z]+)$/.exec(v);
    if (m && UNITS[m[2]]) {
      const [u, secs] = UNITS[m[2]];
      return { span: u === "H" ? `PT${m[1]}H` : `P${m[1]}${u}`, secs: Number(m[1]) * secs };
    }
    // An ISO 8601 duration is recorded as given (uv normalises it; these fixtures use normal forms).
    m = /^P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/.exec(v);
    if (m) return { span: v, secs: [604800, 86400, 3600, 60, 1].reduce((t, k, i) => t + k * Number(m[i + 1] ?? 0), 0) };
    if (/^\d{4}-\d\d-\d\dT[\d:.]+Z$/.test(v)) return { ts: v };
    if (/^\d{4}-\d\d-\d\d$/.test(v)) return { ts: new Date(Date.parse(`${v}T00:00:00Z`) + 86400e3).toISOString().replace(".000Z", "Z") };
    die(`error: Failed to parse: \`${userFile}\`\n\`${v}\` could not be parsed as a valid exclude-newer value`, 2);
  }
  const stamp = (c) => (c.span ? (new12 ? SENTINEL : new Date(Date.now() - c.secs * 1000).toISOString()) : c.ts);
  const opts = [];
  const g = global === undefined ? undefined : cutoff(global);
  if (g) {
    opts.push(`exclude-newer = "${stamp(g)}"${g.span && new12 ? " # This has no effect and is included for backwards compatibility when using relative exclude-newer values." : ""}`);
    if (g.span) opts.push(`exclude-newer-span = "${mode === "bad-span" ? "P1M" : g.span}"`);
  }
  const pkgs = [];
  for (const [name, v] of perPackage instanceof Map ? perPackage : []) {
    const c = cutoff(v);
    pkgs.push(`${name} = ${c === undefined ? "false" : c.span ? `{ timestamp = "${stamp(c)}", span = "${c.span}" }` : `"${c.ts}"`}`);
  }
  let lock = 'version = 1\nrevision = 3\nrequires-python = ">=3.14"\n\n';
  if (opts.length > 0 || pkgs.length > 0) lock += `[options]\n${opts.map((l) => `${l}\n`).join("")}\n`;
  if (pkgs.length > 0) lock += `[options.exclude-newer-package]\n${(new12 ? [...pkgs].sort() : pkgs).join("\n")}\n\n`;
  lock += '[[package]]\nname = "wormsign-harden-probe"\nversion = "0"\nsource = { virtual = "." }\n';
  if (mode !== "no-lock") writeFileSync(join(root, "uv.lock"), lock);
}

// Yarn Classic runs the script a yarn-path setting names, from any of its .yarnrc files, instead of itself, unless
// YARN_IGNORE_PATH is set (yarn 1.22 src/cli/index.js).
if (tool === "yarn" && major === 1 && !env.YARN_IGNORE_PATH) {
  const yarnPath = yarnrcs().map((f) => iniGet(read(f), "yarn-path", "\\s+")).find((x) => x !== undefined);
  if (yarnPath) process.exit(spawnSync(process.execPath, [yarnPath, ...args], { stdio: "inherit" }).status ?? 1);
}

if (tool === "stat") {
  // GNU coreutils stat: -c FORMAT prints the mode; -f means --file-system, so '%Lp' is a missing file.
  const file = args[args.length - 1];
  if (args[0] === "-c") out((statSync(file).mode & 0o777).toString(8));
  else {
    out(`  File: "${file}"\n    ID: 0 Namelen: 255 Type: apfs`);
    die("stat: cannot read file system information for '%Lp': No such file or directory");
  }
} else if (tool === "python3") {
  pythonMain(args);
} else if (tool === "pip" || tool === "pip3") {
  pipMain(tool, args);
} else if (tool === "uv") {
  uvMain(args);
} else if (tool === "gh") {
  if (args[0] !== "auth" || args[1] !== "status") die(`stub gh: unexpected ${args.join(" ")}`);
  if (!env.STUB_GH_STATUS) die("You are not logged into any GitHub hosts. To log in, run: gh auth login");
  out(read(env.STUB_GH_STATUS).trimEnd());
} else if (args[0] === "--version") {
  out(version);
} else if (tool === "npm" && args[0] === "root" && args[1] === "-g") {
  out(env.STUB_NPM_ROOT ?? join(HOME, ".npm-global", "lib", "node_modules"));
} else if (args[0] === "config" && args[1] === "get" && getters[tool]) {
  const keys = args.slice(2);
  if (keys.length === 1) out(show(getters[tool](keys[0])));
  else for (const k of keys) out(`${k}=${show(getters[tool](k))}`);
} else {
  die(`stub ${tool}: unexpected ${args.join(" ")}`);
}
