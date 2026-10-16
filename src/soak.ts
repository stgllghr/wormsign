import type { Finding } from "./types.js";
import { makeFinding } from "./types.js";
import { formatDuration } from "./duration.js";
import { artifactKey } from "./lockfile/index.js";
import type { LockedPackage, ParsedLockfile } from "./lockfile/index.js";
import { isGitSpec } from "./checks/lockfile.js";
import { registryTarball } from "./lockfile/tarball.js";
import { checkOsvDetailed, osvKeyPrefix } from "./osv.js";
import type { OsvEcosystem, OsvSession } from "./osv.js";
import { isTransientStatus, transportFailure } from "./net.js";
import type { OutageLedger } from "./net.js";
import { registrySignals } from "./registry-signals.js";
import type { Packument as SignalPackument, PackumentVersion as SignalVersion } from "./registry-signals.js";
import { BASELINE_FILE, parseBaseline } from "./baseline.js";
import type { Baseline } from "./baseline.js";
import type { Tree } from "./tree.js";
import { redactUrl, redirectProblem } from "./url.js";
import type { RegistrySetting } from "./soak-config.js";

/* ------------------------------------------------------------------ *
 * soak, layer 2: is every locked version old enough, still published, and
 * the artifact its label claims? (network, explicit) Layer 1, whether a
 * release-age setting is configured and enforced, is src/soak-config.ts.
 * ------------------------------------------------------------------ */

export interface SoakOptions {
  minAgeMs: number;
  registry: string;
  now: Date;
  fetchImpl?: typeof fetch;
  concurrency?: number;
  /** onlyKey() keys (lockfile and soakIdentity) to check; when set, other locked packages are skipped (PR mode). */
  only?: Set<string>;
  /** The registries an install of a lockfile is configured to use (see installRegistries). */
  installRegistries?: (lock: ParsedLockfile) => RegistrySetting[];
  /** PR mode: the base revision's lockfiles, so registry signals compare a changed package with the version it replaces. */
  base?: ParsedLockfile[];
  /** Ask OSV for malicious-package records for each locked version of a name the registry returned a document for. */
  osv?: boolean;
  /** The run's OSV state, shared with another ecosystem's check in the same run (see OsvSession). */
  osvSession?: OsvSession;
  /** How a registry request waits before its retry (see packumentWait). Default: a timer; tests pass their own. */
  sleep?: (ms: number) => Promise<void>;
  /** The most bytes of one package document read (default MAX_PACKUMENT_BYTES; tests pass less). */
  maxPackumentBytes?: number;
  /**
   * --on-outage warn: the run's ledger (src/net.ts), told of every answer from the registry. A package the registry
   * left unchecked only because of an outage is filed there as a claim (WS-SK-006 if the registry gives no answer in
   * the whole run, else WS-SK-002), and so is OSV's outage.
   */
  outages?: OutageLedger;
}

/** On a full run, registry signals are read only for versions published this recently (see SIGNAL_WINDOW). */
export const SIGNAL_WINDOW_DAYS = 14;
/**
 * Every worm version measured (3,547 across five waves, docs/evidence/soak-latency.md) had a public malware record
 * within 7 days of publish once three matching artefacts are corrected, and OSV had a record for all of them, so
 * past twice that OSV is the better witness. Older versions are left out so a mature lockfile does not report every
 * publisher change in its history.
 */
const SIGNAL_WINDOW = SIGNAL_WINDOW_DAYS * 86_400_000;

export interface SoakEvidence {
  name: string;
  version: string;
  /** Always written. Every entry checked on the npm registry (from npm, pnpm and Yarn lockfiles) is "npm". */
  ecosystem: OsvEcosystem;
  publishedAt?: string;
  ageHours?: number;
  status: "ok" | "too-new" | "unverifiable";
  reason?: string;
  /** Registry signals, when read: the version compared with (absent: none), and the rules that fired. */
  registry?: { comparedWith?: string; signals: string[] };
  /** OSV malicious-package record ids, when OSV answered for this version ([] = no record). Absent: not checked. */
  osv?: string[];
  /* Reserved for PyPI entries; never written for npm. */
  /** The upload time of the release's first file. */
  releaseFirstFileAt?: string;
  /** The index's project status (PEP 792), when it gave one. */
  projectStatus?: string;
  /** The release's files the lockfile pins. */
  files?: SoakFile[];
  /** How many files the lockfile pins, when `files` is cut short. */
  filesTotal?: number;
}

/** A file of a PyPI release, as the index lists it. */
export interface SoakFile {
  filename: string;
  sha256: string;
  uploadTime: string;
  yanked?: boolean;
}

/** Evidence order: name, then version, then ecosystem (the same name@version can be both an npm and a PyPI package). */
export function compareEvidence(a: SoakEvidence, b: SoakEvidence): number {
  return a.name.localeCompare(b.name) || a.version.localeCompare(b.version) || a.ecosystem.localeCompare(b.ecosystem);
}

export interface SoakResult {
  findings: Finding[];
  evidence: SoakEvidence[];
  /** What was not checked, and why. */
  notes: string[];
}

interface PackumentVersion extends SignalVersion {
  dist?: NonNullable<SignalVersion["dist"]> & { integrity?: string; shasum?: string; tarball?: string };
}

interface Packument extends Omit<SignalPackument, "name"> {
  time: Record<string, string>;
  versions: Record<string, PackumentVersion>;
}

/** What the installer fetches, not only the label: an entry relabelled to another tarball is a different package. */
export function soakIdentity(p: LockedPackage): string {
  return artifactKey(p);
}

/** PR mode's key for a locked package: its lockfile and its soakIdentity, so an entry counts as unchanged only in the file that held it. */
export function onlyKey(file: string, p: LockedPackage): string {
  return `${file}\0${soakIdentity(p)}`;
}

/** A package's document URL: the name is one path segment, a scope's slash written %2F as npm writes it. */
export function registryUrl(registry: string, name: string): string {
  return `${registry.replace(/\/+$/, "")}/${name.replaceAll("/", "%2F")}`;
}

function hostOf(url: string): string | undefined {
  try {
    return new URL(url).host;
  } catch {
    return undefined;
  }
}

/** registry.yarnpkg.com serves the npm registry under another name; Yarn Classic lockfiles record it. */
const NPM_PUBLIC = ["registry.npmjs.org", "registry.yarnpkg.com"];

function sameRegistry(url: string, registry: string): boolean {
  const a = hostOf(url);
  const b = hostOf(registry);
  return a !== undefined && (a === b || (NPM_PUBLIC.includes(a) && NPM_PUBLIC.includes(b ?? "")));
}


const NO_PRIVATE =
  "wormsign checks one registry (--registry) and sends no credentials. If the entry is trusted, baseline it with a justification: the baseline entry pins its name, version, resolved source and integrity, so any change to them fails again";

/** "local" for code that lives in the repository, a reason when the age cannot be checked on `registry`, undefined when it can. */
function sourceProblem(p: LockedPackage, registry: string, configured: RegistrySetting[]): string | undefined {
  const r = p.resolved;
  if (p.local || (r !== undefined && /^(file|link|portal|workspace):/.test(r))) return "local";
  // A git URL can carry a token in its userinfo (git+https://x-access-token:<token>@github.com/...): never printed.
  if ([r, p.version].some((s) => s !== undefined && isGitSpec(s))) return `it resolves from a git source (${redactUrl(r ?? p.version).slice(0, 100)}), which has no registry publish time`;
  // Yarn Berry's patch: protocol wraps a registry version (e.g. its built-in compat patches); that version is what gets checked.
  if (r !== undefined && !(r.startsWith("patch:") && r.includes("@npm%3A")) && !sameRegistry(r, registry)) {
    return `it resolves from ${hostOf(r) ?? redactUrl(r).slice(0, 80)}, not ${redactUrl(registry)} (${NO_PRIVATE})`;
  }
  // A scope's own registry replaces the default for that scope.
  const scope = p.name.startsWith("@") ? (p.name.split("/")[0] as string) : "";
  const own = configured.filter((c) => scope !== "" && c.scope === scope);
  const other = [...(own.length > 0 ? own : configured.filter((c) => c.scope === "")), ...configured.filter((c) => c.scope === "*")].find((c) => !sameRegistry(c.url, registry));
  // Registry URLs from config can hold a token in their userinfo or query: never printed.
  if (other) return `${other.where} installs ${scope || "packages"} from ${redactUrl(other.url).slice(0, 100)}, not ${redactUrl(registry)} (${NO_PRIVATE})`;
  return undefined;
}

/**
 * The local packages' names, each once. An npm workspace is in the lockfile twice: as its directory, named by its
 * path when the entry has no name field ("packages/a") and by that field otherwise, and as the node_modules link to it,
 * named by the package and resolved to that path. The directory entry a link resolves to is the link's package.
 */
export function localNames(local: readonly LockedPackage[]): string[] {
  const targets = new Set(local.flatMap((p) => (p.resolved !== undefined ? [p.resolved] : [])));
  return [...new Set(local.filter((p) => !targets.has(p.name)).map((p) => p.name))];
}

/** The registry tarball path of a version: "name/-/file.tgz" or "@scope/name/-/file.tgz". */
function tarballTail(url: string): string | undefined {
  try {
    return /(?:@[^/]+\/)?[^/]+\/-\/[^/]+$/.exec(decodeURIComponent(new URL(url).pathname))?.[0];
  } catch {
    return undefined;
  }
}

/**
 * Is the locked artifact the registry's name@version? An entry can keep an old, benign label while
 * its resolved/integrity point at another tarball, and `npm ci` installs that tarball.
 */
function artifactMismatch(p: LockedPackage, v: PackumentVersion): string | undefined {
  const known = new Map<string, string>();
  for (const tok of (v.dist?.integrity ?? "").split(/\s+/)) if (tok.includes("-")) known.set(tok.slice(0, tok.indexOf("-")), tok);
  if (v.dist?.shasum && !known.has("sha1")) known.set("sha1", `sha1-${Buffer.from(v.dist.shasum, "hex").toString("base64")}`);
  let matched = false;
  for (const tok of (p.integrity ?? "").split(/\s+/).filter((t) => t.includes("-"))) {
    const want = known.get(tok.slice(0, tok.indexOf("-")));
    if (want === undefined) continue;
    if (want !== tok) return "its lockfile integrity differs from the registry's for that version, so it installs a different tarball than its name and version claim";
    matched = true;
  }
  // Without a resolved URL the installer fetches name@version from the registry itself, provided the
  // lockfile parser reports the name and version the installer fetches (an alias's target, not its label).
  if (matched || p.resolved === undefined || p.resolved.startsWith("patch:")) return undefined;
  const tail = tarballTail(p.resolved);
  if (tail !== undefined && v.dist?.tarball !== undefined && tail === tarballTail(v.dist.tarball)) return undefined;
  return "its resolved URL is not the registry's tarball for that version and no integrity hash can be compared with the registry's";
}

/**
 * The most bytes of one package document soak reads. Full documents of popular names run to tens of MiB (every
 * version's manifest is in them) and eight are read at once; a larger answer is refused while it is read, and the
 * package fails closed (WS-SK-002) rather than the run running out of memory.
 */
export const MAX_PACKUMENT_BYTES = 200 * 1024 * 1024;
/**
 * A registry answer of HTTP 429 or a 5xx is retried once, after a wait: Retry-After's delay in seconds (digits only),
 * at most 30 seconds, or 2 to 3 seconds (a random part, so eight workers that hit a limit together do not retry
 * together). A retry at once, as before, met the same limit.
 */
export function packumentWait(retryAfter: string | null, random: () => number = Math.random): number {
  return retryAfter !== null && /^\d+$/.test(retryAfter) ? Math.min(Number(retryAfter) * 1000, 30_000) : 2_000 + Math.floor(random() * 1_000);
}
const timer = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** A body of at most `max` bytes, refused as soon as more is seen (or declared); undefined when it is too large. */
async function readCapped(res: Response, max: number): Promise<string | undefined> {
  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > max) return undefined;
  if (!res.body) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = res.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      reader.cancel().catch(() => undefined);
      return undefined;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * `doc` only when the registry returned a package document with publish times and a version list; otherwise `error`,
 * and `outage` when the retry's failure was an outage (src/net.ts): HTTP 429 or a 5xx, or a transport failure before
 * any status line, so not a body that is slow, cut off or unreadable. Any other status tells the ledger the registry
 * answered.
 */
async function fetchPackument(name: string, opts: SoakOptions): Promise<{ doc?: Packument; error?: string; outage?: string }> {
  const f = opts.fetchImpl ?? fetch;
  const max = opts.maxPackumentBytes ?? MAX_PACKUMENT_BYTES;
  const host = hostOf(opts.registry) ?? "";
  for (let attempt = 0; attempt < 2; attempt++) {
    let status = false;
    try {
      // Must be the full packument: the abbreviated one (install-v1+json) has no `time`. "manual": a redirect is
      // refused below, never followed to plain http or another host, where anyone on the path could forge publish times.
      const res = await f(registryUrl(opts.registry, name), { headers: { accept: "application/json" }, redirect: "manual", signal: AbortSignal.timeout(30_000) });
      status = true;
      if (!isTransientStatus(res.status)) opts.outages?.answered(host);
      const redirect = redirectProblem(res);
      if (redirect) return { error: `registry returned ${redirect}; pass the registry's final https URL as --registry` };
      if (res.status === 404) return { error: `package not found in ${redactUrl(opts.registry)} (${NO_PRIVATE})` };
      if (res.status === 401 || res.status === 403) return { error: `registry returned HTTP ${res.status} (${NO_PRIVATE})` };
      if (isTransientStatus(res.status)) {
        if (attempt === 0) {
          await (opts.sleep ?? timer)(packumentWait(res.headers.get("retry-after")));
          continue;
        }
        return { error: `registry returned HTTP ${res.status}`, outage: `HTTP ${res.status}` };
      }
      if (!res.ok) return { error: `registry returned HTTP ${res.status}` };
      const text = await readCapped(res, max);
      if (text === undefined) return { error: `the registry's package document is larger than ${Math.round(max / 1024 / 1024)} MiB, the most soak reads` };
      const body = JSON.parse(text) as Partial<Packument>;
      if (!body.time || typeof body.time !== "object") return { error: "registry response has no publish times (proxy or mirror stripped them)" };
      if (!body.versions || typeof body.versions !== "object") return { error: "registry response has no version list" };
      return { doc: body as Packument };
    } catch (e) {
      if (attempt === 1) {
        const outage = status ? undefined : transportFailure(e);
        return { error: `request failed: ${(e as Error).message}`, ...(outage !== undefined ? { outage } : {}) };
      }
    }
  }
  return { error: "unreachable" };
}

export async function checkSoakLockfiles(locks: ParsedLockfile[], opts: SoakOptions): Promise<SoakResult> {
  const evidence: SoakEvidence[] = [];
  const findings: Finding[] = [];
  // Keyed on the artifact, not the label: a baseline entry approves one source and tarball, and any change to them fails again.
  const sk002 = (pkg: LockedPackage, file: string, reason: string): Finding =>
    makeFinding({ ruleId: "WS-SK-002", severity: "high", message: `Cannot verify soak time for ${pkg.name}@${pkg.version}: ${reason}`, file, key: soakIdentity(pkg) });
  const unverifiable = (pkg: LockedPackage, file: string, reason: string): void => {
    evidence.push({ name: pkg.name, version: pkg.version, ecosystem: "npm", status: "unverifiable", reason });
    findings.push(sk002(pkg, file, reason));
  };
  const host = hostOf(opts.registry) ?? "";
  /**
   * --on-outage warn: the registry did not answer for the package, so nothing about it was checked (OSV is not asked
   * either). The evidence is what it is without the option; the finding is the ledger's to decide.
   */
  const claimOutage = (ledger: OutageLedger, pkg: LockedPackage, file: string, reason: string, outage: string): void => {
    evidence.push({ name: pkg.name, version: pkg.version, ecosystem: "npm", status: "unverifiable", reason });
    const message = `Soak time not checked for ${pkg.name}@${pkg.version}: ${host} unreachable: ${outage}. Its age, identity and OSV records are unverified; --on-outage warn reports it at medium, and by default it fails closed (WS-SK-002, high)`;
    ledger.claim({
      host,
      probe: `${opts.registry.replace(/\/+$/, "")}/`,
      failClosed: [sk002(pkg, file, reason)],
      warn: [makeFinding({ ruleId: "WS-SK-006", severity: "medium", message, file, key: soakIdentity(pkg) })],
      unverified: [{ host, error: outage, id: `npm:${pkg.name}@${pkg.version}` }],
    });
  };

  const seen = new Set<string>();
  const unchanged = new Set<string>();
  /** Local packages, each entry as the lockfile gives it (see localNames). */
  const local: LockedPackage[] = [];
  const byName = new Map<string, { pkg: LockedPackage; file: string }[]>();
  for (const lock of locks) {
    const configured = opts.installRegistries?.(lock) ?? [];
    for (const pkg of lock.packages) {
      const id = soakIdentity(pkg);
      if (opts.only && !opts.only.has(onlyKey(lock.file, pkg))) {
        unchanged.add(id);
        continue;
      }
      const problem = sourceProblem(pkg, opts.registry, configured);
      // An artifact locked in several lockfiles is checked once, unless their registry settings disagree about it.
      if (seen.has(`${id}\0${problem ?? ""}`)) continue;
      seen.add(`${id}\0${problem ?? ""}`);
      if (problem === "local") local.push(pkg);
      else if (problem !== undefined) unverifiable(pkg, lock.file, problem);
      else if (pkg.version === "") unverifiable(pkg, lock.file, "the lockfile entry has no version, so its publish time cannot be looked up");
      else {
        // Age-check what is downloaded, not the label: an entry relabelled as an old package can point at a young tarball.
        const t = pkg.resolved && !pkg.runtime ? registryTarball(pkg.resolved) : undefined;
        const target = t && (t.name !== pkg.name || t.version !== pkg.version) ? { ...pkg, name: t.name, version: t.version } : pkg;
        byName.set(target.name, [...(byName.get(target.name) ?? []), { pkg: target, file: lock.file }]);
      }
    }
  }
  const notes = opts.only ? [`${unchanged.size} unchanged package(s) not checked (PR mode)`] : [];
  const locals = localNames(local);
  // Local packages count as the local note counts them, each once; every other entry not asked about counts as itself.
  const notSent = seen.size - [...byName.values()].flat().length - local.length + locals.length;
  if (locals.length > 0) notes.push(`${locals.length} local package(s) not age-checked (their code is in this repository): ${locals.slice(0, 10).join(", ")}${locals.length > 10 ? ", ..." : ""}`);

  /** PR mode: the versions the base lockfile (the same file) locked under this name. */
  const baseVersions = (file: string, name: string): Set<string> =>
    new Set(opts.base?.find((l) => l.file === file)?.packages.filter((p) => p.name === name).map((p) => p.version));
  /** PR mode: the base's version of this name, when it locked exactly one other version of it. */
  const previousIn = (file: string, name: string, version: string): string | undefined => {
    const vs = baseVersions(file, name);
    return vs.size === 1 && !vs.has(version) ? [...vs][0] : undefined;
  };
  let alreadyLocked = 0;
  const why = opts.only ? "read because the change adds or updates it" : `read because it was published in the last ${SIGNAL_WINDOW_DAYS} days`;
  const notCompared: string[] = [];
  const signalsFor = (doc: Packument, name: string, version: string, file: string): NonNullable<SoakEvidence["registry"]> => {
    // A base version the registry no longer lists cannot be compared with, so the newest earlier publish is used instead.
    const base = opts.only ? previousIn(file, name, version) : undefined;
    const r = registrySignals({ ...doc, name }, version, base !== undefined && doc.versions[base] ? base : undefined);
    for (const s of r.signals) findings.push(makeFinding({ ruleId: s.ruleId, severity: s.severity, message: `${s.message} (registry signal ${why})`, file, key: s.key }));
    if (r.previous === undefined) notCompared.push(`${name}@${version}`);
    return { ...(r.previous !== undefined ? { comparedWith: r.previous } : {}), signals: r.signals.map((s) => s.ruleId) };
  };

  const names = [...byName.keys()];
  /** Names the registry returned a document for: the only names OSV is asked about. */
  const served = new Set<string>();
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < names.length) {
      const name = names[next++] as string;
      const { doc, error, outage } = await fetchPackument(name, opts);
      if (doc) served.add(name);
      for (const { pkg, file } of byName.get(name) ?? []) {
        if (error !== undefined && outage !== undefined && opts.outages) {
          claimOutage(opts.outages, pkg, file, error, outage);
          continue;
        }
        const id = `${name}@${pkg.version}`;
        const published = doc?.time[pkg.version];
        const meta = doc?.versions[pkg.version];
        const t = published ? Date.parse(published) : NaN;
        const problem =
          error ??
          (Number.isNaN(t) ? `no publish time recorded for version ${pkg.version}`
          : !meta ? `version ${pkg.version} is no longer in the registry (unpublished or removed, often because it was malicious)`
          : artifactMismatch(pkg, meta));
        if (problem !== undefined) {
          unverifiable(pkg, file, problem);
          continue;
        }
        const age = opts.now.getTime() - t;
        const ageHours = Math.round((age / 3_600_000) * 10) / 10;
        // A full run reads them only for recent versions; PR mode for every version the change adds or updates, not for a
        // version the base already locked (an entry whose source alone changed): its history is not news.
        const inBase = opts.only !== undefined && baseVersions(file, name).has(pkg.version);
        if (inBase) alreadyLocked++;
        const registry = !inBase && (opts.only !== undefined || age < SIGNAL_WINDOW) ? { registry: signalsFor(doc as Packument, name, pkg.version, file) } : {};
        if (age < opts.minAgeMs) {
          evidence.push({ name, version: pkg.version, ecosystem: "npm", publishedAt: published as string, ageHours, status: "too-new", ...registry });
          findings.push(
            makeFinding({
              ruleId: "WS-SK-001",
              severity: "high",
              message: `${id} was published ${formatDuration(Math.max(age, 0))} ago, inside the required ${formatDuration(opts.minAgeMs)} soak window (published ${published})`,
              file,
              key: id,
            }),
          );
        } else {
          evidence.push({ name, version: pkg.version, ecosystem: "npm", publishedAt: published as string, ageHours, status: "ok", ...registry });
        }
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(opts.concurrency ?? 8, Math.max(names.length, 1)) }, worker));
  const read = evidence.filter((e) => e.registry).length;
  notes.push(opts.only ? `registry signals read for ${read} changed package version(s)` : `registry signals read for ${read} package version(s) published in the last ${SIGNAL_WINDOW_DAYS} days; older versions not read`);
  if (alreadyLocked > 0) notes.push(`registry signals not read for ${alreadyLocked} version(s) the base lockfile already locked (the entry changed, not the version)`);
  if (notCompared.length > 0) notes.push(`registry signals: ${notCompared.length} version(s) not compared with an earlier version (none on the registry to compare with), so install-script and provenance changes were not checked: ${notCompared.sort().slice(0, 10).join(", ")}${notCompared.length > 10 ? ", ..." : ""}`);

  if (opts.osv) {
    const toOsv = [...byName].filter(([name]) => served.has(name)).flatMap(([, entries]) => entries);
    const unserved = [...byName].filter(([name]) => !served.has(name)).flatMap(([, entries]) => entries).length;
    const skipped = [
      ...(notSent > 0 ? [`${notSent} not sent to OSV (local code, git, or another registry: soak sends their names nowhere)`] : []),
      ...(unserved > 0 ? [`${unserved} not sent to OSV (the registry did not return a document for them, so the name may not be public)`] : []),
    ];
    findings.push(
      ...(await runOsv({
        ecosystem: "npm",
        sent: toOsv.map(({ pkg, file }) => ({ name: pkg.name, version: pkg.version, file })),
        index: opts.registry,
        publicHost: NPM_PUBLIC,
        label: "the public npm registry",
        flag: "--registry",
        skipped,
        evidence,
        notes,
        ...(opts.outages ? { outages: opts.outages } : {}),
        ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
        ...(opts.osvSession ? { session: opts.osvSession } : {}),
      })),
    );
  }

  evidence.sort(compareEvidence);
  return { findings, evidence, notes };
}

/** One ecosystem's OSV check in a soak run. */
export interface OsvRun {
  ecosystem: OsvEcosystem;
  /** The versions to ask about, each with its lockfile: only versions of names the index returned a document for. */
  sent: { name: string; version: string; file: string }[];
  /** The index those names were looked up on, and the option that set it ("--registry"). */
  index: string;
  flag: string;
  /** The hosts of the ecosystem's public index. When `index` is on none of them, nothing is sent and the check fails closed. */
  publicHost: readonly string[];
  /** That public index as the message names it ("the public npm registry"). */
  label: string;
  /** What was not sent to OSV, and why, for the coverage note. */
  skipped: string[];
  /** The run's evidence: the entries of this ecosystem that OSV answered for get `osv`; no other entry is touched. */
  evidence: SoakEvidence[];
  /** The run's notes: the coverage note, then OSV's own notes, are added here. */
  notes: string[];
  /**
   * Said in brackets after the coverage note's first clause, so two ecosystems' notes in one run can be told apart
   * ("(PyPI)"). Unset for npm, whose note predates it.
   */
  noteLabel?: string;
  /** The run's OSV state, shared by every ecosystem's call (see OsvSession). */
  session?: OsvSession;
  fetchImpl?: typeof fetch;
  /** --on-outage warn: the run's ledger (see OsvOptions). */
  outages?: OutageLedger;
}

/**
 * OSV malicious-package records for `sent`, asked only when the index is public (otherwise WS-OS-900, nothing sent).
 * Records each answer in the evidence and the coverage in `notes`. Reads OSV's answers as data, never from finding keys.
 */
export async function runOsv(run: OsvRun): Promise<Finding[]> {
  const idOf = (p: { name: string; version: string }): string => `${p.name}@${p.version}`;
  const ids = new Set(run.sent.map(idOf));
  const label = run.noteLabel === undefined ? "" : ` (${run.noteLabel})`;
  if (ids.size === 0) {
    if (run.skipped.length > 0) run.notes.push(`0 package version(s) checked against OSV${label}; ${run.skipped.join("; ")}`);
    return [];
  }
  if (!run.publicHost.includes(hostOf(run.index) ?? "")) {
    const message = `${ids.size} package version(s) were not checked against OSV: ${run.flag} ${redactUrl(run.index)} is not ${run.label}, so their names are not sent to api.osv.dev. Pass --no-osv to run without this check`;
    return [makeFinding({ ruleId: "WS-OS-900", severity: "high", message, key: `${osvKeyPrefix(run.ecosystem)}registry ${redactUrl(run.index)}` })];
  }
  const res = await checkOsvDetailed(run.sent, { ecosystem: run.ecosystem, ...(run.outages ? { outages: run.outages } : {}), ...(run.fetchImpl ? { fetchImpl: run.fetchImpl } : {}), ...(run.session ? { session: run.session } : {}) });
  const unchecked = new Set(res.unchecked);
  const answered = new Set([...ids].filter((id) => !unchecked.has(id)));
  for (const e of run.evidence) if (e.ecosystem === run.ecosystem && answered.has(idOf(e))) e.osv = res.records.get(idOf(e)) ?? [];
  run.notes.push(`${answered.size} package version(s) checked against OSV for malicious-package records${label}${run.skipped.map((s) => `; ${s}`).join("")}`, ...res.notes);
  return res.findings;
}


/**
 * The baseline as committed in another tree (the PR base), so a change cannot baseline its own findings. Read by the
 * same parser as scan's and diff's, so the three commands accept and reject the same files with the same messages.
 */
export function baselineAt(tree: Tree, label: string): Baseline | undefined {
  // "./": relative to the scanned directory even when that is a subdirectory of the git repository.
  const text = tree.read(`./${BASELINE_FILE}`);
  return text === undefined ? undefined : parseBaseline(text, `${BASELINE_FILE} at ${label}`);
}
