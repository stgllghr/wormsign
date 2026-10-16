/**
 * Golden: `wormsign soak` output for npm, pnpm, Yarn and bun projects, saved before the PyPI work began, so a change
 * that adds another ecosystem can show it leaves npm output exactly as it was.
 *
 * Every npm, pnpm and Yarn lockfile fixture under test/fixtures, plus one project built for the OSV cases, projects for
 * the lockfile walker's other outcomes (a bun lockfile, a package.json without a lockfile, an unparseable lockfile,
 * nested projects, a lockfile under node_modules, symlinks) and one empty project, runs through the real CLI in several
 * modes: a full run, --no-osv, a full run while OSV answers HTTP 503, a full run against a private --registry, PR mode
 * (--base, against a sibling fixture of the same lockfile name) with OSV up and down, and --config-only with and
 * without release-age settings. Nothing comes from the machine: PATH is a directory of stub npm/pnpm/yarn/bun binaries
 * with fixed versions, HOME and the XDG directories are empty, git reads no global or system config, the clock is
 * fixed, and the registry and OSV are fakes whose answers depend only on the name and version asked about.
 *
 * Compared per case: the exit code, every finding (rule, severity, message, file, key, source, fingerprint), the
 * notes, the evidence, minAgeMs and every query sent to OSV (name@version, sorted). The versions whose full records
 * OSV is asked for (POST /v1/query) are checked by the last test, not stored in the snapshot. The snapshot was
 * written by the code before evidence had an `ecosystem` field, so that field is removed from the evidence before the
 * comparison, and checked on its own: "npm" on every entry.
 *
 * UPDATE_NPM_SOAK_GOLDEN=1 rewrites test/golden/npm-soak-identical.json from the current code; UPDATE_GOLDEN=1, which
 * regenerates the SARIF golden, does not touch it. Do that only for a change that is meant to alter npm output, and
 * list every changed line in the pull request. A new npm lockfile fixture under test/fixtures adds cases, and the
 * regenerated snapshot must differ only by those cases.
 *
 * Regenerated three times, on purpose. First: OSV layer 3 reports a GHSA record with CWE-506 as WS-OS-001 (src/osv.ts), so
 * ua-parser-js@0.7.29 became a WS-OS-001 finding with "osv" ["GHSA-pjwm-rvh2-c87w"] in its evidence, and every case
 * whose OSV answer had a GHSA id gained the note "OSV records requested for 2 version(s) (GHSA classification)".
 * Nothing else changed. Second: the WS-SK-002 message for a git source prints the URL through redactUrl (src/url.ts),
 * so a token in its userinfo is never printed: 68 messages that name a git source lost the URL's userinfo
 * (`git@`), its fragment (the commit), or both. Their keys and fingerprints, and everything else, are unchanged.
 * Third: fingerprints keep 32 hex characters of their SHA-256 instead of 16 (src/types.ts), so each of the 1,647
 * findings' fingerprints is its old value with 16 more characters; no key, message, note or evidence changed.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, posix, relative } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { LOCKFILE_NAMES, parseLockfileText } from "../src/lockfile/index.js";
import { registryTarball } from "../src/lockfile/tarball.js";
import { run } from "../src/main.js";
import { FIXTURES, GOLDEN, NOW, fakeIO } from "./helpers.js";

const SNAPSHOT = join(GOLDEN, "npm-soak-identical.json");
const REGISTRY = "https://registry.npmjs.org/";
/** A registry that is not the public one: soak looks names up there, and must not send them to OSV. */
const PRIVATE = "https://npm.corp.example/";
const OSV = "https://api.osv.dev/v1/querybatch";
const H = 3_600_000;
const iso = (hoursAgo: number): string => new Date(NOW.getTime() - hoursAgo * H).toISOString();
/** A stable number from a string: the fakes' answers depend on nothing else. */
const hash = (s: string): number => createHash("sha256").update(s).digest().readUInt32BE(0);
const tarball = (name: string, version: string): string => `${REGISTRY}${name}/-/${name.split("/").pop()}-${version}.tgz`;

/* ---- the projects ---- */

/** Release-age settings for every package manager, long enough for the 7-day default, so the version checks run. */
const SETTINGS: Record<string, string> = {
  ".npmrc": "min-release-age=7\n",
  "pnpm-workspace.yaml": "minimumReleaseAge: 10080\n",
  ".yarnrc.yml": "npmMinimalAgeGate: 10080\n",
  "bunfig.toml": "[install]\nminimumReleaseAge = 604800\n",
};
/** npm 10.9.2 ignores min-release-age (a WS-SK-004 finding); the others enforce their settings. */
const VERSIONS = { npm: "10.9.2", pnpm: "11.16.0", yarn: "4.10.3", bun: "1.3.0" };

/** An npm lockfile; an entry marked "no resolved" is fetched by name and version, so it is another artifact than the same version with a URL. */
const npmLock = (pkgs: ([name: string, version: string] | [name: string, version: string, "no resolved"])[]): string => {
  const packages: Record<string, unknown> = { "": { name: "golden" } };
  for (const [n, v, how] of pkgs) packages[`node_modules/${n}`] = { version: v, ...(how ? {} : { resolved: tarball(n, v) }), integrity: `sha512-${Buffer.from(`${n}@${v}`).toString("base64")}` };
  return `${JSON.stringify({ lockfileVersion: 3, packages }, null, 2)}\n`;
};
/** A package.json, with or without dependencies. */
const manifest = (deps: Record<string, string> = {}): string => `${JSON.stringify({ name: "golden", ...(Object.keys(deps).length > 0 ? { dependencies: deps } : {}) }, null, 2)}\n`;

/**
 * The OSV cases: a MAL- record, a record split over two pages, an ordinary GHSA record beside a MAL- one, a version
 * whose only record is a GHSA with CWE-506 (ua-parser-js@0.7.29 has only GHSA-pjwm-rvh2-c87w, per src/osv.ts), a
 * version OSV is never asked about (not semver), the same malicious version in two lockfiles as two artifacts (a finding for each file), a young version
 * in both lockfiles as one artifact (checked once), a scoped name, and two names the registry does not serve.
 */
const OSV_PROJECT: Record<string, string> = {
  "package-lock.json": npmLock([
    ["golden-mal", "1.0.0"], ["golden-paged", "1.0.0"], ["golden-both", "1.0.0"], ["ua-parser-js", "0.7.29"], ["golden-badver", "1.0"],
    ["golden-young", "1.0.0"], ["@golden/scoped", "2.0.0"], ["golden-missing", "1.0.0"], ["golden-down", "1.0.0"],
  ]),
  "sub/package-lock.json": npmLock([["golden-mal", "1.0.0", "no resolved"], ["golden-young", "1.0.0"]]),
};
/** Its PR base: golden-young moves from 0.9.0, which had no install script, and sub/ is new. */
const OSV_BASE: Record<string, string> = { "package-lock.json": npmLock([["golden-mal", "1.0.0"], ["golden-young", "0.9.0"], ["@golden/scoped", "2.0.0"]]) };

/** A file's text, or a symlink to `link` (relative to the file's directory). */
type Entry = string | { link: string };

interface Project {
  /** The files of the head, by path. */
  files: Record<string, Entry>;
  /** The lockfiles of the PR base; undefined: no --base case. */
  base?: Record<string, string>;
}

/**
 * The lockfile walker's other outcomes (main.ts lockfilesIn), which a change to how lockfiles are found must keep: each
 * is a finding or a note that no lockfile fixture alone produces.
 */
const WALKER: Record<string, Record<string, Entry>> = {
  "(bun lockfiles)": { "bun.lock": '{ "lockfileVersion": 1 }\n', "old/bun.lockb": "golden\n" },
  "(package.json with dependencies, no lockfile)": { "package.json": manifest({ "left-pad": "^1.3.0" }) },
  "(package.json without dependencies, no lockfile)": { "package.json": manifest() },
  "(package.json that is not an object)": { "package.json": "[1, 2]\n" },
  // wormsign's own parse error, not JSON.parse's, whose wording depends on the Node version.
  "(unparseable yarn.lock)": { "yarn.lock": '# yarn lockfile v1\n\n"left-pad@^1.3.0":\n  version "1.3.0"\n  golden "x"\n', "package.json": manifest({ "left-pad": "^1.3.0" }) },
  "(empty lockfile beside dependencies)": { "package-lock.json": npmLock([]), "package.json": manifest({ "left-pad": "^1.3.0" }) },
  "(nested projects)": {
    "a/package-lock.json": npmLock([["golden-nested", "1.0.0"]]),
    "a/package.json": manifest({ "golden-nested": "1.0.0" }),
    "a/c/package.json": manifest({ "golden-nested": "1.0.0" }),
    "b/package.json": manifest({ "left-pad": "^1.3.0" }),
  },
  "(lockfile under node_modules)": {
    "package-lock.json": npmLock([["golden-top", "1.0.0"]]),
    "node_modules/dep/package-lock.json": npmLock([["golden-hidden", "1.0.0"]]),
    "node_modules/dep/package.json": manifest({ "golden-hidden": "1.0.0" }),
  },
  "(symlinks)": {
    "real/package-lock.json": npmLock([["golden-real", "1.0.0"]]),
    "package-lock.json": { link: "real/package-lock.json" },
    linked: { link: "real" },
    loop: { link: "loop" },
  },
};

/** Every lockfile fixture, each alone in a project; its PR base is the previous fixture with the same file name. */
function projects(): Map<string, Project> {
  const found: string[] = [];
  const walk = (dir: string): void => {
    for (const e of readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      if (e.isDirectory()) walk(join(dir, e.name));
      else if ((LOCKFILE_NAMES as readonly string[]).includes(e.name)) found.push(relative(FIXTURES, join(dir, e.name)).split("\\").join("/"));
    }
  };
  walk(FIXTURES);
  const out = new Map<string, Project>();
  const text = (p: string): string => readFileSync(join(FIXTURES, p), "utf8");
  for (const path of found) {
    const name = posix.basename(path);
    const same = found.filter((p) => posix.basename(p) === name);
    const prev = same[(same.indexOf(path) + same.length - 1) % same.length] as string;
    out.set(path, { files: { [name]: text(path) }, base: { [name]: text(prev) } });
  }
  out.set("(osv cases)", { files: OSV_PROJECT, base: OSV_BASE });
  for (const [name, files] of Object.entries(WALKER)) out.set(name, { files });
  out.set("(empty project)", { files: {} });
  return out;
}

/* ---- the fake registry and OSV ---- */

/** Registry facts set by hand for the OSV project; every other version gets facts derived from its hash. */
const EXPLICIT: Record<string, { hours: number; scripts?: Record<string, string> }> = {
  "golden-mal@1.0.0": { hours: 900 * 24 },
  "golden-paged@1.0.0": { hours: 900 * 24 },
  "golden-both@1.0.0": { hours: 900 * 24 },
  "ua-parser-js@0.7.29": { hours: 1800 * 24 },
  "golden-badver@1.0": { hours: 900 * 24 },
  "golden-young@0.9.0": { hours: 400 * 24 },
  "golden-young@1.0.0": { hours: 10, scripts: { preinstall: "node golden.js" } },
  "@golden/scoped@2.0.0": { hours: 30 * 24 },
};
/** Names whose registry facts are all set by hand: no hash-picked fault applies to them. */
const OWN = new Set(Object.keys(EXPLICIT).map((id) => id.slice(0, id.lastIndexOf("@"))));
const NAME_FAULT: Record<string, () => Response> = {
  "golden-missing": () => new Response("{}", { status: 404 }),
  "golden-down": () => new Response("", { status: 500 }),
};

/** name -> version -> integrity tokens, from every lockfile any case uses, as the parser reads them. */
function registryTable(all: Map<string, Project>): Map<string, Map<string, Set<string>>> {
  const table = new Map<string, Map<string, Set<string>>>();
  const add = (name: string, version: string, integrity: string | undefined): void => {
    const versions = table.get(name) ?? new Map<string, Set<string>>();
    table.set(name, versions);
    const tokens = versions.get(version) ?? new Set<string>();
    versions.set(version, tokens);
    for (const t of (integrity ?? "").split(/\s+/)) if (/^sha\d+-/.test(t)) tokens.add(t);
  };
  for (const p of all.values()) {
    for (const [file, text] of [...Object.entries(p.files), ...Object.entries(p.base ?? {})]) {
      if (typeof text !== "string" || !(LOCKFILE_NAMES as readonly string[]).includes(posix.basename(file))) continue;
      let lock;
      try {
        lock = parseLockfileText(file, text);
      } catch {
        continue; // a fixture the parser rejects is a WS-SK-002 finding, not a registry entry
      }
      for (const pkg of lock?.packages ?? []) {
        add(pkg.name, pkg.version, pkg.integrity);
        const t = pkg.resolved ? registryTarball(pkg.resolved) : undefined;
        if (t) add(t.name, t.version, pkg.integrity);
      }
    }
  }
  return table;
}

/**
 * A full packument for `name`. Per name (by hash): some names are 404, 403, 500 or have no publish times. Per
 * version: an age between 1 hour and 45 days, a publisher, provenance, sometimes an install script, sometimes removed,
 * a different integrity or no publish time. Every name also has an old 0.0.0-golden release to compare with.
 */
function packument(table: Map<string, Map<string, Set<string>>>, name: string): Response {
  const named = NAME_FAULT[name];
  if (named) return named();
  const versions = table.get(name);
  const hn = hash(name);
  const fault = OWN.has(name) ? -1 : hn % 43;
  if (!versions || fault === 0) return new Response("{}", { status: 404 });
  if (fault === 1) return new Response("", { status: 500 });
  if (fault === 2) return new Response("", { status: 403 });
  const time: Record<string, string> = { "0.0.0-golden": iso(3000 * 24) };
  const docVersions: Record<string, unknown> = { "0.0.0-golden": { _npmUser: { name: "alice" }, dist: { tarball: tarball(name, "0.0.0-golden"), attestations: { provenance: { predicateType: "https://slsa.dev/provenance/v1" } } } } };
  for (const [version, tokens] of [...versions].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    const id = `${name}@${version}`;
    const hv = hash(id);
    const set = EXPLICIT[id];
    const hours = set?.hours ?? 1 + (hv % (45 * 24));
    if (set || (hv >>> 16) % 37 !== 0) time[version] = iso(hours);
    if (!set && (hv >>> 8) % 29 === 0) continue; // removed: the time stays, the version is gone
    const mismatch = !set && (hv >>> 12) % 31 === 0;
    const dist = {
      ...(mismatch ? { integrity: "sha512-Z29sZGVuLW1pc21hdGNo", tarball: tarball(name, "0.0.0-other") } : { ...(tokens.size > 0 ? { integrity: [...tokens].join(" ") } : {}), tarball: tarball(name, version) }),
      ...(!set && (hv >>> 6) % 3 !== 0 ? { attestations: { provenance: { predicateType: "https://slsa.dev/provenance/v1" } } } : {}),
    };
    const scripts = set ? set.scripts : (hv >>> 10) % 7 === 0 ? { postinstall: "node golden.js" } : undefined;
    docVersions[version] = { _npmUser: { name: !set && (hv >>> 4) % 5 === 0 ? "mallory" : "alice" }, dist, ...(scripts ? { scripts } : {}) };
  }
  if (fault === 3) return new Response(JSON.stringify({ name, versions: docVersions }));
  return new Response(JSON.stringify({ name, time, versions: docVersions }));
}

/**
 * OSV records by name@version; golden-paged's second page comes with page_token "golden-p2". The full records of the
 * versions with a GHSA id, as POST /v1/query serves them: ua-parser-js@0.7.29's are the real ones recorded in
 * test/fixtures/osv/query (one GHSA record, with CWE-506), and golden-both's GHSA record is an ordinary vulnerability.
 */
const FULL_RECORDS: Record<string, unknown> = {
  "ua-parser-js@0.7.29": (JSON.parse(readFileSync(join(FIXTURES, "osv", "query", "npm-ua-parser-js-0.7.29.json"), "utf8")) as { response: unknown }).response,
  "golden-both@1.0.0": { vulns: [{ id: "GHSA-gggg-gggg-gggg", database_specific: { cwe_ids: ["CWE-79"] } }, { id: "MAL-2099-0004" }] },
};
const QUERY = "https://api.osv.dev/v1/query";
const OSV_RECORDS: Record<string, string[]> = {
  "golden-mal@1.0.0": ["MAL-2099-0001"],
  "golden-paged@1.0.0": ["MAL-2099-0002"],
  "golden-both@1.0.0": ["GHSA-gggg-gggg-gggg", "MAL-2099-0004"],
  "ua-parser-js@0.7.29": ["GHSA-pjwm-rvh2-c87w"],
};

/** What the fakes saw that they should not have: an assertion thrown inside fetch would read as a network error. */
const unexpected: string[] = [];

/** Every query in an OSV request, as "name@version" (with its page token, if any), added to `asked`. */
function osvQueries(init: RequestInit | undefined, asked: string[]): { package: { name: string; ecosystem: string }; version: string; page_token?: string }[] {
  const { queries } = JSON.parse(String(init?.body)) as { queries: { package: { name: string; ecosystem: string }; version: string; page_token?: string }[] };
  for (const { package: { name, ecosystem }, version, page_token: token } of queries) {
    if (ecosystem !== "npm") unexpected.push(`OSV query in ecosystem ${ecosystem}`);
    asked.push(`${name}@${version}${token ? ` page_token=${token}` : ""}`);
  }
  return queries;
}

function osvReply(queries: ReturnType<typeof osvQueries>): Response {
  const results = queries.map(({ package: { name }, version, page_token: token }) => {
    const id = `${name}@${version}`;
    if (id === "golden-paged@1.0.0" && token === "golden-p2") return { vulns: [{ id: "MAL-2099-0003", modified: "2026-01-01T00:00:00Z" }] };
    const vulns = (OSV_RECORDS[id] ?? []).map((v) => ({ id: v, modified: "2026-01-01T00:00:00Z" }));
    return id === "golden-paged@1.0.0" ? { vulns, next_page_token: "golden-p2" } : vulns.length > 0 ? { vulns } : {};
  });
  return new Response(JSON.stringify({ results }));
}

/** Every version whose full records were requested, by mode, as "<mode> <name@version>": not in the snapshot. */
const recordsAsked: string[] = [];

/** The public registry, the private one and OSV; every OSV query goes into `asked`, answered or not. */
function fakeFetch(table: Map<string, Map<string, Set<string>>>, osv: "ok" | "503", asked: string[], modeName: string): typeof fetch {
  return (async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    if (u === OSV) {
      const queries = osvQueries(init, asked);
      return osv === "503" ? new Response("", { status: 503 }) : osvReply(queries);
    }
    if (u === QUERY) {
      const { package: { name, ecosystem }, version } = JSON.parse(String(init?.body)) as { package: { name: string; ecosystem: string }; version: string };
      const id = `${name}@${version}`;
      recordsAsked.push(`${modeName} ${id}`);
      if (ecosystem !== "npm" || !(id in FULL_RECORDS)) unexpected.push(`OSV record query for ${ecosystem} ${id}`);
      return osv === "503" ? new Response("", { status: 503 }) : new Response(JSON.stringify(FULL_RECORDS[id] ?? {}));
    }
    const prefix = [REGISTRY, PRIVATE].find((r) => u.startsWith(r));
    if (prefix === undefined) unexpected.push(`request to ${u}`);
    return packument(table, decodeURIComponent(u.slice((prefix ?? REGISTRY).length)));
  }) as typeof fetch;
}

/* ---- running the cases ---- */

interface Mode {
  args: string[];
  /** Write SETTINGS into the project. */
  configured: boolean;
  osv: "ok" | "503";
  /** PR mode: the project is a git repository whose HEAD holds the base lockfiles. */
  base?: boolean;
}
const MODES: Record<string, Mode> = {
  full: { args: [], configured: true, osv: "ok" },
  "full --no-osv": { args: ["--no-osv"], configured: true, osv: "ok" },
  "full, OSV answers 503": { args: [], configured: true, osv: "503" },
  "full --registry private": { args: ["--registry", PRIVATE.slice(0, -1)], configured: true, osv: "ok" },
  "--base HEAD": { args: ["--base", "HEAD"], configured: true, osv: "ok", base: true },
  "--base HEAD, OSV answers 503": { args: ["--base", "HEAD"], configured: true, osv: "503", base: true },
  "--config-only, no settings": { args: ["--config-only"], configured: false, osv: "ok" },
  "--config-only, settings": { args: ["--config-only"], configured: true, osv: "ok" },
};

function write(dir: string, files: Record<string, Entry>): void {
  for (const [path, entry] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    if (typeof entry === "string") writeFileSync(join(dir, path), entry);
    else symlinkSync(entry.link, join(dir, path));
  }
}
function git(cwd: string, ...args: string[]): void {
  execFileSync("git", ["-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...args], { cwd, stdio: "ignore" });
}
/** Stub binaries that print a fixed version, as in test/soak.test.ts. */
function stubBin(versions: Record<string, string>): string {
  const d = mkdtempSync(join(tmpdir(), "ws-golden-bin-"));
  for (const [m, v] of Object.entries(versions)) {
    writeFileSync(join(d, m), `#!/bin/sh\necho ${v}\n`);
    chmodSync(join(d, m), 0o755);
  }
  return d;
}

type Evidence = Record<string, unknown>;
interface CaseResult {
  exit: number;
  findings: unknown[];
  notes: string[];
  evidence?: Evidence[];
  minAgeMs?: number;
  /** Every query sent to OSV, as "name@version", sorted: which names left the machine, and how often. */
  osvAsked: string[];
}

/** What every mode shares, made once: the projects, the fake registry's table, and an environment with nothing from the machine. */
interface Setup {
  all: Map<string, Project>;
  table: Map<string, Map<string, Set<string>>>;
  env: Record<string, string>;
}
let shared: Setup | undefined;
function setup(): Setup {
  if (shared) return shared;
  // This file runs in its own process (node --test), so the git below and wormsign's own (--base) read no hook-set
  // GIT_DIR or GIT_INDEX_FILE and no global or system config (hooksPath, templateDir).
  for (const k of Object.keys(process.env)) if (/^GIT_/.test(k)) delete process.env[k];
  process.env["GIT_CONFIG_GLOBAL"] = "/dev/null";
  process.env["GIT_CONFIG_NOSYSTEM"] = "1";
  const all = projects();
  const empty = () => mkdtempSync(join(tmpdir(), "ws-golden-home-"));
  shared = { all, table: registryTable(all), env: { PATH: stubBin(VERSIONS), HOME: empty(), XDG_CONFIG_HOME: empty(), XDG_CACHE_HOME: empty(), XDG_DATA_HOME: empty() } };
  return shared;
}

/** Every case run so far, by name ("<project> | <mode>"), and every evidence entry as written (before the comparison drops `ecosystem`). */
const ran = new Map<string, CaseResult>();
const written: Evidence[] = [];
/** The modes whose test ran to the end. */
const finished = new Set<string>();

/** One mode's cases, in project order. */
async function runMode(modeName: string): Promise<Record<string, CaseResult>> {
  const { all, table, env } = setup();
  const mode = MODES[modeName] as Mode;
  const cases: Record<string, CaseResult> = {};
  for (const [name, project] of all) {
    if (mode.base && !project.base) continue;
    // With nothing locked, OSV is never asked: one full run says so.
    if (Object.keys(project.files).length === 0 && (mode.osv === "503" || mode.args.includes("--no-osv"))) continue;
    const d = mkdtempSync(join(tmpdir(), "ws-golden-"));
    const settings = mode.configured ? SETTINGS : {};
    if (mode.base) {
      write(d, { ...settings, ...project.base });
      git(d, "init", "-q");
      git(d, "add", ".");
      git(d, "commit", "-qm", "base");
    }
    // In PR mode the working tree plays the head.
    write(d, { ...settings, ...project.files });
    const osvAsked: string[] = [];
    const io = fakeIO({ env, fetchImpl: fakeFetch(table, mode.osv, osvAsked, modeName) });
    const exit = await run(["soak", d, ...mode.args, "--format", "json"], io);
    assert.equal(io.err, "", `${name} | ${modeName}: nothing on stderr`);
    const out = JSON.parse(io.out) as { findings: unknown[]; notes: string[]; extra?: { evidence: Evidence[]; minAgeMs: number } };
    const result: Omit<CaseResult, "osvAsked"> = { exit, findings: out.findings, notes: out.notes };
    if (out.extra) {
      written.push(...out.extra.evidence);
      result.evidence = out.extra.evidence.map(withoutEcosystem);
      result.minAgeMs = out.extra.minAgeMs;
    }
    cases[`${name} | ${modeName}`] = { ...result, osvAsked: osvAsked.sort() };
  }
  return cases;
}

/** The snapshot predates the evidence `ecosystem` field; everything else must match exactly. */
function withoutEcosystem(e: Evidence): Evidence {
  const copy = { ...e };
  delete copy["ecosystem"];
  return copy;
}

/** One case per block and one finding, note, evidence entry or OSV query per line, so a change reads as a short diff. */
function serialise(cases: Record<string, CaseResult>): string {
  const lines = ["{", `  "_about": ${JSON.stringify("npm, pnpm, Yarn and bun soak output that adding PyPI must not change; written by test/golden-npm-identical.test.ts with UPDATE_NPM_SOAK_GOLDEN=1 (UPDATE_GOLDEN=1 does not touch it)")},`];
  const names = Object.keys(cases);
  for (const [i, name] of names.entries()) {
    lines.push(`  ${JSON.stringify(name)}: {`);
    const fields = Object.entries(cases[name] as CaseResult);
    for (const [j, [k, v]] of fields.entries()) {
      const end = j === fields.length - 1 ? "" : ",";
      if (Array.isArray(v) && v.length > 0) {
        lines.push(`    ${JSON.stringify(k)}: [`, ...v.map((x, n) => `      ${JSON.stringify(x)}${n === v.length - 1 ? "" : ","}`), `    ]${end}`);
      } else {
        lines.push(`    ${JSON.stringify(k)}: ${JSON.stringify(v)}${end}`);
      }
    }
    lines.push(`  }${i === names.length - 1 ? "" : ","}`);
  }
  return `${[...lines, "}"].join("\n")}\n`;
}

const UPDATE = process.env["UPDATE_NPM_SOAK_GOLDEN"] === "1";
const modeOf = (caseName: string): string => caseName.slice(caseName.lastIndexOf(" | ") + 3);
function snapshot(): Record<string, CaseResult> {
  const expected = JSON.parse(readFileSync(SNAPSHOT, "utf8")) as Record<string, CaseResult>;
  delete expected["_about"];
  return expected;
}
/** Each case equal to the snapshot's; the first that differs is shown in full. */
function compare(cases: Record<string, CaseResult>, expected: Record<string, CaseResult>): void {
  const differ = Object.keys(cases).filter((n) => !isDeepStrictEqual(cases[n], expected[n]));
  const first = differ[0];
  if (first !== undefined) assert.deepEqual(cases[first], expected[first], `${differ.length} case(s) differ from ${SNAPSHOT}: ${differ.slice(0, 8).join("; ")}`);
}

// One test per mode, so each stays far inside the per-test timeout of scripts/run-tests.mjs on a slow runner.
for (const modeName of Object.keys(MODES)) {
  test(`golden: npm, pnpm, Yarn and bun soak output is unchanged, ${modeName} (findings, fingerprints, notes, evidence, OSV queries)`, async () => {
    const cases = await runMode(modeName);
    for (const [n, c] of Object.entries(cases)) ran.set(n, c);
    assert.deepEqual(unexpected, [], "the fakes were asked only what they serve");
    finished.add(modeName);
    if (UPDATE) return; // the last test writes the snapshot, then compares every case
    const expected = snapshot();
    assert.deepEqual(Object.keys(cases), Object.keys(expected).filter((n) => modeOf(n) === modeName), "the same cases, in the same order (a new lockfile fixture adds cases: see the header)");
    compare(cases, expected);
  });
}

test("golden: the snapshot holds exactly the cases run, in order, and they reach every outcome it protects", () => {
  assert.deepEqual([...finished], Object.keys(MODES), "every mode's test ran to the end");
  // The one evidence field the snapshot does not hold: written on every entry, and "npm" for every one of these.
  assert.ok(written.length > 1000, `${written.length} evidence entries`);
  const notNpm = written.filter((e) => e["ecosystem"] !== "npm");
  assert.deepEqual(notNpm.slice(0, 3), [], `${notNpm.length} evidence entries without ecosystem "npm"`);
  // Project order, then mode order, whatever order the modes ran in.
  const names = [...setup().all.keys()].flatMap((p) => Object.keys(MODES).map((m) => `${p} | ${m}`)).filter((n) => ran.has(n));
  const cases = Object.fromEntries(names.map((n) => [n, ran.get(n) as CaseResult]));
  if (UPDATE) writeFileSync(SNAPSHOT, serialise(cases));
  const expected = snapshot();
  const added = names.filter((n) => !(n in expected));
  const gone = Object.keys(expected).filter((n) => !ran.has(n));
  assert.deepEqual([added, gone], [[], []], `cases [added, gone] since ${SNAPSHOT} was written (a new lockfile fixture adds cases: see the header)`);
  assert.deepEqual(names, Object.keys(expected), "the same cases, in the same order");
  compare(cases, expected);

  // Positive control: the cases reach every outcome the comparison is meant to protect, so a pass is not vacuous.
  const findings = Object.values(cases).flatMap((c) => c.findings as { ruleId: string; key: string; message: string }[]);
  const evidence = Object.values(cases).flatMap((c) => c.evidence ?? []);
  const notes = Object.values(cases).flatMap((c) => c.notes);
  for (const rule of ["WS-OS-001", "WS-OS-900", "WS-SK-001", "WS-SK-002", "WS-SK-003", "WS-SK-004", "WS-RG-001", "WS-RG-002", "WS-RG-003"]) {
    assert.ok(findings.some((f) => f.ruleId === rule), `some case reports ${rule}`);
  }
  assert.ok(findings.some((f) => f.ruleId === "WS-OS-900" && /OSV returned HTTP 503/.test(f.message)), "OSV down");
  assert.ok(findings.some((f) => f.ruleId === "WS-OS-900" && /not a registry name and version/.test(f.message)), "a version OSV is never asked about");
  assert.ok(findings.some((f) => f.ruleId === "WS-OS-900" && f.key === `registry ${PRIVATE.slice(0, -1)}`), "a private registry: OSV not asked, and the check fails closed");
  assert.ok(findings.some((f) => f.ruleId === "WS-OS-001" && /MAL-2099-0003/.test(f.message)), "a record from OSV's second page");
  assert.ok(findings.some((f) => f.key === "no-package-manager"), "the no-package-manager finding");
  assert.ok(findings.some((f) => f.ruleId === "WS-SK-004" && /npm 10\.9\.2 .*ignores it/.test(f.message)), "the stub npm's version is read");
  for (const re of [/bun lockfiles are not supported/, /declares dependencies but there is no lockfile/, /no packages were read from it/, /symlink, which wormsign does not follow/, /symlinked directory/, /symlink that could not be resolved/, /could not be parsed/, /not a valid JSON object/]) {
    assert.ok(findings.some((f) => re.test(f.message)), `a finding matching ${re}`);
  }
  for (const status of ["ok", "too-new", "unverifiable"]) assert.ok(evidence.some((e) => e["status"] === status), `evidence with status ${status}`);
  assert.ok(evidence.some((e) => Array.isArray(e["osv"]) && e["osv"].length === 0), "a version OSV answered with no record");
  assert.ok(evidence.some((e) => Array.isArray(e["osv"]) && e["osv"].length > 0), "a version with a MAL- record");
  assert.ok(evidence.some((e) => e["name"] === "ua-parser-js" && isDeepStrictEqual(e["osv"], ["GHSA-pjwm-rvh2-c87w"])), "a version whose only record is a CWE-506 GHSA has it as its record");
  assert.ok(findings.some((f) => f.ruleId === "WS-OS-001" && f.key === "ua-parser-js@0.7.29 GHSA-pjwm-rvh2-c87w"), "a CWE-506 GHSA record is WS-OS-001");
  assert.ok(evidence.some((e) => e["name"] === "golden-both" && isDeepStrictEqual(e["osv"], ["MAL-2099-0004"])), "an ordinary GHSA record beside a MAL- one is not a record");
  assert.ok(notes.includes("OSV records requested for 2 version(s) (GHSA classification)"), "the note on record queries");
  // Each version with a GHSA id once per case: two per full or PR-mode case of the OSV project, none in any other mode.
  const records = (mode: string): string[] => recordsAsked.filter((r) => r.startsWith(`${mode} `)).map((r) => r.slice(mode.length + 1)).sort();
  for (const mode of ["full", "--base HEAD"]) assert.deepEqual(records(mode), ["golden-both@1.0.0", "ua-parser-js@0.7.29"], mode);
  assert.deepEqual(recordsAsked.filter((r) => !/^(full|--base HEAD) /.test(r)), [], "no record query with OSV down, --no-osv, a private registry or --config-only");
  assert.ok(evidence.some((e) => (e["registry"] as { comparedWith?: string } | undefined)?.comparedWith !== undefined), "registry signals compared with an earlier version");
  for (const re of [/unchanged package\(s\) not checked \(PR mode\)/, /not sent to OSV/, /OSV not asked .*--no-osv/, /no lockfile and no dependencies declared/, /lockfile soak check not run \(--config-only\)/]) {
    assert.ok(notes.some((n) => re.test(n)), `a note matching ${re}`);
  }
  const asked = (mode: string): string[] => Object.entries(cases).flatMap(([n, c]) => (modeOf(n) === mode ? c.osvAsked : []));
  assert.ok(asked("full").includes("golden-paged@1.0.0 page_token=golden-p2"), "OSV asked for a second page");
  assert.ok(asked("full").some((q) => q.startsWith("golden-mal@")), "OSV asked about the OSV project");
  assert.ok(asked("full, OSV answers 503").length > 0, "OSV asked while it answers 503");
  assert.deepEqual([...asked("full --no-osv"), ...asked("full --registry private"), ...asked("--config-only, settings")], [], "no name sent to OSV with --no-osv, a private registry or --config-only");
});
