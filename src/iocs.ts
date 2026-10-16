import { closeSync, constants, existsSync, fstatSync, openSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { UsageError } from "./types.js";
import type { Severity } from "./types.js";
import { SEVERITIES } from "./types.js";

export interface PackageSet {
  id: string;
  wave: string;
  source: string;
  packages: Record<string, string[]>;
}
export interface HashIoc { sha256: string; name: string; wave: string; source: string; note?: string }
export interface NameIoc { name: string; nameOnlySeverity: Severity; wave: string; source: string; note?: string }
export interface WorkflowIoc { name: string; severity: Severity; wave: string; source: string; note?: string }
export interface RunnerIoc { name: string; wave: string; source: string; note?: string }
export interface RepoPattern {
  id: string;
  match: "nameExact" | "nameContains" | "descriptionExact" | "descriptionContains" | "nameRegexAndDescriptionExact";
  name?: string;
  nameRegex?: string;
  description?: string;
  severity: Severity;
  wave: string;
  source: string;
}
export interface EndpointIoc { substring: string; severity: Severity; wave: string; source: string }
/** A version a source lists in error. The set keeps it as the source prints it; the loader drops it. */
export interface Exclusion { set: string; name: string; version: string; checked: string; reason: string; evidence: string[] }

export interface IocSet {
  packageSets: PackageSet[];
  hashes: HashIoc[];
  names: NameIoc[];
  workflowFiles: WorkflowIoc[];
  runnerNames: RunnerIoc[];
  repoPatterns: RepoPattern[];
  branches: { name: string; wave: string; source: string }[];
  endpoints: EndpointIoc[];
  /** Date of the data ("YYYY-MM-DD"), the same in all five files. Undefined for unversioned test data. */
  version: string | undefined;
  /** Which data was loaded and why, so that a caller can report the IOC source alongside the findings. */
  notes: string[];
}

export const bundledIocDir = fileURLToPath(new URL("../../data/iocs/", import.meta.url));
/**
 * The update-iocs cache: $XDG_CACHE_HOME/wormsign/iocs, or ~/.cache/wormsign/iocs when XDG_CACHE_HOME is unset, empty
 * or not absolute. The XDG Base Directory spec says a relative path there is invalid and must be ignored; read as
 * given, it would load the cache from the scanned repository's own files.
 */
export function userIocDir(env: Record<string, string | undefined> = process.env): string {
  const xdg = env["XDG_CACHE_HOME"];
  return join(xdg && isAbsolute(xdg) ? xdg : join(homedir(), ".cache"), "wormsign", "iocs");
}

const FILES = ["packages", "files", "workflows", "repos", "endpoints"] as const;

/**
 * The most bytes one IOC file may have, downloaded (update-iocs) or read (the bundled data, --iocs, the cache). The
 * largest today, packages.json, is about 200 KB. A bound, because whoever controls the feed, or can write the cache
 * on a shared runner (docs/github-action.md), decides what every later scan parses.
 */
export const MAX_IOC_FILE_BYTES = 16 * 1024 * 1024;
/**
 * The most entries per list, about 50 times the data of 2026-10-02 (4,186 package versions in 6 sets, 20 hashes,
 * 6 repository patterns, 3 branches, 1 endpoint). Each endpoint is matched against every scanned file and each
 * branch is one GitHub request per repository, so an unbounded list is a way to stall every later scan or audit.
 */
const MAX_ENTRIES = {
  sets: 1_000,
  packageVersions: 200_000,
  exclusions: 10_000,
  hashes: 10_000,
  names: 1_000,
  workflowFiles: 1_000,
  runnerNames: 1_000,
  repoPatterns: 1_000,
  branches: 100,
  endpoints: 1_000,
} as const;
function atMost(where: string, n: number, what: keyof typeof MAX_ENTRIES): void {
  if (n > MAX_ENTRIES[what]) throw new UsageError(`${where}: ${n} entries, more than the ${MAX_ENTRIES[what]} wormsign accepts`);
}

/**
 * GitHub repository names are at most 100 characters (the API refuses a longer one), so a nameRegex never needs to
 * see more than that.
 */
export const MAX_REPO_NAME = 100;
/**
 * Why a repository nameRegex is refused, or undefined. audit-org runs it on every repository name, so its cost is
 * bounded whatever the feed says: at most 100 characters; no backreference; no repeating quantifier on a group, which
 * is the nested repetition behind exponential backtracking (^([\w.-]+)+!$ takes 0.3 s on a 26-character name and doubles
 * with each character); and at most 2 variable-length quantifiers (*, +, ?, {n,} or {n,m}), so the work on a name
 * of at most 100 characters is at most quadratic. It must also compile.
 */
export function nameRegexProblem(src: string): string | undefined {
  if (src.length > 100) return "longer than 100 characters";
  let variable = 0;
  let prev = ""; // what the last token was: "group" (a ")"), "quant" or anything else
  for (let i = 0; i < src.length; i++) {
    const c = src[i] as string;
    if (c === "\\") {
      if (/[1-9k]/.test(src[i + 1] ?? "")) return "it has a backreference";
      i++;
      prev = "atom";
      continue;
    }
    if (c === "[") {
      // A class is one atom: skip to its closing "]". A "]" right after "[" or "[^" is a literal.
      i++;
      if (src[i] === "^") i++;
      if (src[i] === "]") i++;
      while (i < src.length && src[i] !== "]") i += src[i] === "\\" ? 2 : 1;
      prev = "atom";
      continue;
    }
    if (c === "(") {
      if (src[i + 1] === "?") i++; // (?: (?= (?! (?<= (?<! (?<name>: the rest reads as plain atoms
      prev = "open";
      continue;
    }
    if (c === ")") {
      prev = "group";
      continue;
    }
    const brace = c === "{" ? /^\{(\d+)(,(\d*))?\}/.exec(src.slice(i)) : null;
    if (c === "*" || c === "+" || c === "?" || brace) {
      if (c === "?" && prev === "quant") continue; // the lazy form of the quantifier before it
      if (prev === "group" && c !== "?") return "it repeats a group"; // an optional group is counted below, not refused
      if (!(brace && (brace[2] === undefined || brace[3] === brace[1])) && ++variable > 2) return "it has more than 2 variable-length quantifiers";
      if (brace) i += brace[0].length - 1;
      prev = "quant";
      continue;
    }
    prev = "atom";
  }
  try {
    new RegExp(src);
  } catch (e) {
    return (e as Error).message;
  }
  return undefined;
}

/**
 * Why `name` is not a branch IOC, or undefined. A branch IOC is a branch name that git check-ref-format accepts
 * (https://git-scm.com/docs/git-check-ref-format: no "..", no empty component, no component that starts with "."
 * or ends with ".lock", no trailing "."), in the characters [A-Za-z0-9._/-], optionally ending in one "*" that makes
 * it a prefix (git forbids "*" in ref names, so the marker is never part of a name). A prefix may stop anywhere, so its
 * last component only has to start well. audit-org puts the name in a request path, where a ".." component would
 * send the token to another API endpoint.
 */
export function branchIocProblem(name: string): string | undefined {
  const m = /^([A-Za-z0-9._/-]+)(\*?)$/.exec(name);
  if (!m) return "not a branch name, or a prefix ending in \"*\"";
  const stem = m[1] as string;
  const prefix = m[2] === "*";
  const parts = stem.split("/");
  const last = parts.pop() as string;
  const whole = prefix ? parts : [...parts, last];
  const bad =
    stem.includes("..") ? "it contains \"..\""
    : whole.some((p) => p === "") ? "it has an empty component (a leading, doubled or trailing \"/\")"
    : [...whole, last].some((p) => p.startsWith(".")) ? "a component starts with \".\""
    : whole.some((p) => p.endsWith(".lock")) ? "a component ends with \".lock\""
    : !prefix && stem.endsWith(".") ? "it ends with \".\""
    : undefined;
  return bad && `not a branch name git accepts (${bad})`;
}

const isHttpsUrl = (u: unknown): boolean => typeof u === "string" && /^https:\/\/[^\s]+$/.test(u);
function requireSource(where: string, e: { source?: unknown }): void {
  if (!isHttpsUrl(e.source)) {
    throw new UsageError(`${where}: every IOC entry needs an https source URL`);
  }
}
function requireSeverity(where: string, s: unknown): void {
  if (!(SEVERITIES as readonly unknown[]).includes(s)) throw new UsageError(`${where}: bad severity ${String(s)}`);
}

/** Endpoints are stored defanged ("webhook[.]site") so that the data file itself never matches when installed. */
const refang = (s: string): string => s.replaceAll("[.]", ".");

/** True for "2026-10-02", false for "2026-02-30" or "2026-99-99": versions are compared as strings. */
function isCalendarDate(s: string): boolean {
  const d = new Date(`${s}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;
}

/** Validates the five IOC data files and returns the merged set. Throws on any entry without provenance. */
export function parseIocs(files: Record<(typeof FILES)[number], unknown>): IocSet {
  const get = <T>(k: (typeof FILES)[number], field: string): T[] => {
    const o = files[k] as Record<string, unknown> | undefined;
    if (!o || o["schema"] !== 1) throw new UsageError(`${k}.json: expected schema 1`);
    const v = o[field];
    return Array.isArray(v) ? (v as T[]) : [];
  };
  // Five files fetched one by one from a moving branch could mix two releases; a shared version catches that.
  const versions = new Set(FILES.map((k) => (files[k] as Record<string, unknown> | undefined)?.["version"]));
  if (versions.size !== 1) throw new UsageError(`IOC files disagree on "version": ${[...versions].map(String).join(", ")}`);
  const version = [...versions][0];
  if (version !== undefined && (typeof version !== "string" || !isCalendarDate(version))) {
    throw new UsageError(`IOC "version" must be a real YYYY-MM-DD date, got ${String(version)}`);
  }
  // Copies, so that dropping an excluded version below leaves the caller's parsed files as they were read.
  const packageSets = get<PackageSet>("packages", "sets").map((s) => ({ ...s, packages: { ...s.packages } }));
  atMost("packages.json sets", packageSets.length, "sets");
  let packageVersions = 0;
  for (const s of packageSets) {
    requireSource(`packages.json set ${s.id}`, s);
    for (const [name, versions] of Object.entries(s.packages)) {
      if (!Array.isArray(versions) || versions.length === 0) throw new UsageError(`packages.json set ${s.id}: ${name} has no versions`);
      packageVersions += versions.length;
    }
  }
  atMost("packages.json package versions", packageVersions, "packageVersions");
  atMost("packages.json exclusions", get<Exclusion>("packages", "exclusions").length, "exclusions");
  // A set stays as scripts/import-package-sets.mjs wrote it, so re-running the import reproduces the file.
  // An exclusion that drops nothing is an error: the source changed, and the exclusion should go.
  for (const x of get<Exclusion>("packages", "exclusions")) {
    const where = `packages.json exclusion ${x.name}@${x.version}`;
    if (typeof x.reason !== "string" || !x.reason || !isCalendarDate(String(x.checked)) || !Array.isArray(x.evidence) || x.evidence.length === 0 || !x.evidence.every(isHttpsUrl)) {
      throw new UsageError(`${where}: needs a reason, a "checked" YYYY-MM-DD date and https evidence URLs`);
    }
    const set = packageSets.find((s) => s.id === x.set);
    const versions = set?.packages[x.name];
    if (!set || !versions?.includes(x.version)) throw new UsageError(`${where}: set ${x.set} does not list it`);
    const rest = versions.filter((v) => v !== x.version);
    if (rest.length) set.packages[x.name] = rest;
    else delete set.packages[x.name];
  }
  const hashes = get<HashIoc>("files", "hashes");
  atMost("files.json hashes", hashes.length, "hashes");
  for (const h of hashes) {
    requireSource(`files.json hash ${h.sha256}`, h);
    if (!/^[0-9a-f]{64}$/.test(h.sha256)) throw new UsageError(`files.json: bad sha256 ${h.sha256}`);
  }
  const names = get<NameIoc>("files", "names");
  atMost("files.json names", names.length, "names");
  for (const n of names) {
    requireSource(`files.json name ${n.name}`, n);
    requireSeverity(`files.json name ${n.name}`, n.nameOnlySeverity);
  }
  const workflowFiles = get<WorkflowIoc>("workflows", "workflowFiles");
  atMost("workflows.json workflowFiles", workflowFiles.length, "workflowFiles");
  for (const w of workflowFiles) {
    requireSource(`workflows.json ${w.name}`, w);
    requireSeverity(`workflows.json ${w.name}`, w.severity);
  }
  const runnerNames = get<RunnerIoc>("workflows", "runnerNames");
  atMost("workflows.json runnerNames", runnerNames.length, "runnerNames");
  for (const r of runnerNames) {
    requireSource(`workflows.json runner ${r.name}`, r);
    // Runner names are interpolated into regular expressions by the workflow check.
    if (!/^[A-Za-z0-9._-]+$/.test(r.name)) throw new UsageError(`workflows.json runner ${r.name}: not a plain runner name`);
  }
  const repoPatterns = get<RepoPattern>("repos", "patterns");
  atMost("repos.json patterns", repoPatterns.length, "repoPatterns");
  for (const p of repoPatterns) {
    requireSource(`repos.json ${p.id}`, p);
    requireSeverity(`repos.json ${p.id}`, p.severity);
    const why = p.nameRegex === undefined ? undefined : nameRegexProblem(String(p.nameRegex));
    if (why) throw new UsageError(`repos.json ${p.id}: nameRegex refused: ${why}`);
  }
  const branches = get<{ name: string; wave: string; source: string }>("repos", "branches");
  atMost("repos.json branches", branches.length, "branches");
  for (const b of branches) {
    requireSource(`repos.json branch ${b.name}`, b);
    // A bare "*" would match every branch, and a ".." component would leave the matching-refs path.
    const why = branchIocProblem(String(b.name));
    if (why) throw new UsageError(`repos.json branch ${b.name}: ${why}`);
  }
  const rawEndpoints = get<EndpointIoc>("endpoints", "endpoints");
  atMost("endpoints.json endpoints", rawEndpoints.length, "endpoints");
  const endpoints = rawEndpoints.map((e) => {
    requireSource(`endpoints.json ${e.substring}`, e);
    requireSeverity(`endpoints.json ${e.substring}`, e.severity);
    const substring = refang(String(e.substring));
    // Every URL containing an endpoint is reported at the endpoint's severity instead of by the generic
    // exfiltration heuristic, so "" or "https://www." would match, and could soften, many URLs. Require a
    // whole host with a top-level domain, optionally a scheme before it and a path after it.
    if (!/^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}([/:?#]|$)/i.test(substring)) throw new UsageError(`endpoints.json ${e.substring}: not a host or URL`);
    return { ...e, substring };
  });
  return { packageSets, hashes, names, workflowFiles, runnerNames, repoPatterns, branches, endpoints, version, notes: [] };
}

/**
 * Why `candidate` (a download or the update-iocs cache) is not used over `bundled`, or undefined if it
 * is newer. Versions are dates, so this treats data no newer than the release as already in it.
 * Same-dated data with other content breaks that assumption: update-iocs refuses to download it,
 * and loadIocs ignores such a cache with a note, so its extra IOCs are not used until a newer date.
 * update-iocs and loadIocs both use this, so data that update-iocs writes is data that scans use.
 */
export function staleReason(candidate: IocSet, bundled: IocSet): string | undefined {
  if (candidate.version === undefined) return "it has no version";
  if (bundled.version === undefined || candidate.version > bundled.version) return undefined;
  const rel = candidate.version < bundled.version ? "older than" : "not newer than";
  return `its data (${candidate.version}) is ${rel} the bundled data (${bundled.version})`;
}

/**
 * The bundled IOCs plus the cache's new ones. The cache only adds: an entry whose key the bundled
 * data already has is dropped, so whatever the cache's date, size or content, it cannot remove or
 * soften an IOC that this release ships.
 */
function withAdditions(bundled: IocSet, cache: IocSet): IocSet {
  const add = <T>(have: T[], extra: T[], key: (x: T) => string): T[] => {
    const keys = new Set(have.map(key));
    return [...have, ...extra.filter((x) => !keys.has(key(x)))];
  };
  return {
    // indexPackages keeps the first source per name@version, so bundled sets go first.
    packageSets: [...bundled.packageSets, ...cache.packageSets],
    hashes: add(bundled.hashes, cache.hashes, (h) => h.sha256),
    names: add(bundled.names, cache.names, (n) => n.name),
    workflowFiles: add(bundled.workflowFiles, cache.workflowFiles, (w) => w.name),
    runnerNames: add(bundled.runnerNames, cache.runnerNames, (r) => r.name.toLowerCase()),
    repoPatterns: add(bundled.repoPatterns, cache.repoPatterns, (p) => p.id),
    branches: add(bundled.branches, cache.branches, (b) => b.name),
    endpoints: add(bundled.endpoints, cache.endpoints, (e) => e.substring),
    version: cache.version,
    notes: [],
  };
}

/**
 * One IOC file's text, refusing anything but a regular file of at most MAX_IOC_FILE_BYTES. O_NONBLOCK, so that a FIFO
 * planted in the cache fails at the type check instead of blocking the open; it changes nothing for a regular file.
 */
function readIocFile(p: string): string {
  const fd = openSync(p, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new Error("not a regular file");
    if (st.size > MAX_IOC_FILE_BYTES) throw new Error(`${st.size} bytes, more than the ${MAX_IOC_FILE_BYTES} wormsign reads`);
    return readFileSync(fd, "utf8");
  } finally {
    closeSync(fd);
  }
}

export function loadIocDir(dir: string): IocSet {
  const raw = {} as Record<(typeof FILES)[number], unknown>;
  for (const f of FILES) {
    const p = join(dir, `${f}.json`);
    try {
      raw[f] = JSON.parse(readIocFile(p));
    } catch (e) {
      throw new UsageError(`cannot read IOC file ${p}: ${(e as Error).message}`);
    }
  }
  return parseIocs(raw);
}

const describe = (s: IocSet, from: string): string => `IOC data ${s.version ?? "(unversioned)"} from ${from}`;

/**
 * Loads `--iocs <dir>` when given. Otherwise loads the bundled data and adds the `update-iocs`
 * cache's IOCs when the cache is newer; a stale, partial or invalid cache is ignored with a note.
 * The cache never replaces the bundled data, so it can never hide an IOC shipped in a release.
 */
export function loadIocs(opts: { dir?: string; cacheDir?: string } = {}): IocSet {
  if (opts.dir) {
    const set = loadIocDir(opts.dir);
    set.notes.push(describe(set, `--iocs ${opts.dir}`));
    return set;
  }
  const bundled = loadIocDir(bundledIocDir);
  const cacheDir = opts.cacheDir ?? userIocDir();
  if (FILES.some((f) => existsSync(join(cacheDir, `${f}.json`)))) {
    let problem: string | undefined;
    try {
      const cache = loadIocDir(cacheDir);
      problem = staleReason(cache, bundled);
      if (!problem) {
        const merged = withAdditions(bundled, cache);
        merged.notes.push(`${describe(bundled, `the bundled data ${bundledIocDir}`)}, plus additions from the update-iocs cache ${cacheDir} (${cache.version})`);
        return merged;
      }
    } catch (e) {
      problem = (e as Error).message;
    }
    bundled.notes.push(`ignored the update-iocs cache ${cacheDir}: ${problem}`);
  }
  bundled.notes.push(describe(bundled, `the bundled data ${bundledIocDir}`));
  return bundled;
}

export interface PackageIndex {
  /** name -> version -> source URL */
  lookup(name: string, version: string): string | undefined;
}

export function indexPackages(sets: PackageSet[]): PackageIndex {
  const m = new Map<string, Map<string, string>>();
  for (const s of sets) {
    for (const [name, versions] of Object.entries(s.packages)) {
      let vm = m.get(name);
      if (!vm) m.set(name, (vm = new Map()));
      for (const v of versions) if (!vm.has(v)) vm.set(v, s.source);
    }
  }
  return { lookup: (n, v) => m.get(n)?.get(v) };
}
