/**
 * The PyPI soak check (layers 2 and 3 for Python): every file a supported lock pins must be bound by sha256 to a file
 * of exactly that project and version on the index, and old enough; missing, removed or quarantined files fail
 * closed. docs/soak.md, "Python (PyPI) locks", describes it for users.
 *
 * In order, for the locks discovery found (src/python/model.ts):
 * 1. Every reader problem is WS-SK-002, on every run, keyed on the lockfile, the problem without its position, and a
 *    digest of the content the problem is about (the [[package]] table, file entry, requirements line or file: see
 *    model.ts ReaderProblem). A baseline entry for one approves that content only.
 * 2. Local sources, also on every run (they are about the tree, which a change can alter without touching the lock):
 *    a source tree (its path joined with any pylock `subdirectory`: the directory pip and uv build) must be local by
 *    src/python/local.ts's rules, else WS-SK-002 (medium outside PR mode when the only problem is files git does not
 *    track, high otherwise); one the install builds is WS-SK-005, keyed on its build inputs
 *    (src/python/build.ts). A path archive must be in the reviewed tree and hash to the lock's sha256, else WS-SK-002.
 * 3. Package checks, for every package on every run: the version, the source (a registry, or any index the lock
 *    records, must be --pypi-index; git, VCS, direct URLs and other indexes are WS-SK-002 and sent nowhere), the
 *    discovery's `sendable` verdict, and the binding rule (every file needs a sha256 and no other hash, since pip
 *    accepts a file that matches any one of them; a package needs a file). In PR mode (opts.base) an entry the base's
 *    soak read identically (src/python/base-entries.ts) is quiet: these checks and its age are not reported, it is not
 *    in the evidence and not sent to OSV. It is still bound on the index (step 4), so that step 5 can tell a package
 *    locked only as sdists (WS-SK-005 keeps its rule, src/python/base-builds.ts), and what the index shows about its
 *    files is reported. Each identity is checked once: at its first entry, or at its first entry the base did not hold.
 *    Reader problems (step 1) are reported in PR mode too, as npm's lockfile problems are.
 * 4. One GET per project (src/python/index.ts). Each locked sha256 must belong to a file of this project and version;
 *    a lock url must be the index's url for that file, character for character; a file name the lock gives must name
 *    that file (the same project, version and tags; uv writes the name normalised); the project must not be
 *    quarantined or of unknown status; the file must have an upload time. Any failure is WS-SK-002 for the package;
 *    under --on-outage warn an outage (src/net.ts) is a claim in the run's ledger, WS-SK-006 only if the index gives
 *    no answer in the whole run.
 * 5. Age is the youngest bound file's: younger than minAgeMs is WS-SK-001, keyed on the exact artifact set. A package
 *    every locked file of which is an sdist is WS-SK-005.
 * 6. OSV (layer 3), for packages whose project the index served, through runOsv, which sends nothing unless the index
 *    is pypi.org.
 * Never throws: an unexpected error becomes one WS-SK-002 for the whole check.
 */
import { join } from "node:path";
import { formatDuration } from "../duration.js";
import type { OutageLedger } from "../net.js";
import type { OsvSession } from "../osv.js";
import { compareEvidence, runOsv, type SoakEvidence, type SoakFile, type SoakResult } from "../soak.js";
import { keyDigest, makeFinding, type Finding } from "../types.js";
import { localBuildFinding, readLocalBuild, sdistOnlyFinding } from "./build.js";
import { basenameOf, parseDistFilename } from "./filenames.js";
import { identityDigest } from "./identity.js";
import { bindLockedFile, createIndexClient, displayUrl, normalizeIndexUrl, NOT_FOUND, releaseFiles, sameFileUrl, type IndexFile, type ProjectFetch } from "./index.js";
import { checkLocalArchive, checkLocalDirectory, checkVirtualProject, type GitTracking, type LocalOptions } from "./local.js";
import { fileLabel, lockDir, sha256Of, type PyFile, type PyLock, type PyPackage, type PySource } from "./model.js";
import { versionsEqual } from "./pep440.js";
import { LOCK_REMEDIATION } from "./requirements.js";
import type { BaseLocks } from "./base-entries.js";

export interface PythonSoakOptions {
  minAgeMs: number;
  now: Date;
  /** --pypi-index, e.g. https://pypi.org/simple/. */
  pypiIndex: string;
  fetchImpl?: typeof fetch;
  /** Ask OSV about the packages whose project the index served. */
  osv?: boolean;
  osvSession?: OsvSession;
  /** Absolute path of the scanned root. */
  root: string;
  /** The git rule (src/python/local.ts). */
  git: GitTracking;
  gitError?: string;
  /** With a tracked set: the untracked paths git ignores, which a local source tree's walk skips (src/python/local.ts). */
  gitIgnored?: ReadonlySet<string>;
  /**
   * PR mode (soak --base). Outside it, a local source tree whose only problem is files git does not track is medium
   * (a developer's checkout holds such files); in PR mode it stays high.
   */
  pr?: boolean;
  /**
   * PR mode (soak --base): what the base's own soak read (src/python/base-entries.ts). An entry it read identically is
   * not checked again; reader problems and local sources are checked on every run all the same.
   */
  base?: BaseLocks;
  /** Index requests in flight at once (default 2). */
  concurrency?: number;
  userAgent?: string;
  /**
   * --on-outage warn: the run's ledger (src/net.ts), told of every answer from the index. A package the index left
   * unchecked only because of an outage is filed there as a claim (WS-SK-006 if the index gives no answer in the whole
   * run, else WS-SK-002), and so is OSV's outage.
   */
  outages?: OutageLedger;
}

/** Most files listed in one evidence entry. */
export const MAX_EVIDENCE_FILES = 50;
/** Most file problems one WS-SK-002 message lists; the rest are counted. */
export const MAX_FILE_PROBLEMS = 3;
export const QUARANTINED = "the index marks the project quarantined (PEP 792: unsafe, e.g. malware); from the spec and warehouse source, not observed live";
const NO_PRIVATE = "wormsign checks one index (--pypi-index) and sends no credentials. If the entry is trusted, baseline it with a justification: the baseline key pins its name, version, source and every file hash, so any change to them fails again";
const LOCAL_TREES: ReadonlySet<string> = new Set(["directory", "editable", "virtual"]);
const HOUR = 3_600_000;
const DAY = 86_400_000;

/**
 * A reader problem without its position: `[[package]] #12`, `wheel #3`, `requirements.txt:34:`, `line 4, column 2`.
 * The key digests this with the content the problem covers, so a package or line added above a baselined problem does
 * not bring it back, and other content with the same problem (another name, hash or url there, a second such line) is
 * a new finding.
 */
export function problemContent(problem: string): string {
  return problem
    .replace(/^(.*?):\d+: /, "$1: ")
    .replace(/#\d+\b/g, "#")
    .replace(/\b(line|column) \d+\b/g, "$1");
}

/** A problem's text without its "; <fix>" ending, when it has one. */
export const withoutFix = (text: string, fix: string | undefined): string => (fix !== undefined && fix !== "" && text.endsWith(`; ${fix}`) ? text.slice(0, -(fix.length + 2)) : text);

/**
 * WS-SK-002 for a reader problem, or a file-level problem discovery finds: keyed on the file, the problem without its
 * position and without its fix (`fix`, the text after "; " that says how to fix it), and `covers`, the sha256 of the
 * content it is about ("" when nothing could be read), so a baseline entry approves that problem with that content and
 * hides no other, and a reworded fix keeps the fingerprint. The message keeps the fix.
 */
export function lockProblemFinding(file: string, text: string, covers: string, fix?: string): Finding {
  const problem = withoutFix(text, fix);
  return makeFinding({ ruleId: "WS-SK-002", severity: "high", message: `Cannot verify soak time for the packages in ${file}: ${text}`, file, key: `pypi:lockfile ${file} ${keyDigest(`${problemContent(problem)}\0${covers}`)}` });
}

/** Most refused lines one "not a hash lock" finding names; the rest are counted. */
export const MAX_UNLOCKED_LINES = 10;

/**
 * WS-SK-002 for each of a lock's reader problems, except in a requirements file with no --require-hashes line (one
 * that is not a hash lock at all, such as a file of `==` pins without hashes): there the missing line and every line
 * the lock rule refused are one finding, since one fix (LOCK_REMEDIATION) makes all of them a lock and nothing in
 * them was checked. It is keyed as the per-problem findings are, on the file and on each refused line's problem
 * without its position and the line's text, sorted: moving a line keeps the key, and adding or editing one does not.
 */
export function readerProblemFindings(lock: PyLock): Finding[] {
  // A problem no baseline entry may approve (requirements.ts approvable) keeps that mark in every finding it is part of,
  // and the message says why.
  const mark = (f: Finding, why: string | undefined): Finding => (why === undefined ? f : { ...f, notBaselinable: true, message: `${f.message}. No baseline entry can approve this finding: ${why}` });
  // Each line's problem without its fix, for the message (which says the fix once) and the key (which never holds it).
  const lines = lock.problems.filter((p) => p.lockRule === "line").map((p) => ({ ...p, text: withoutFix(p.text, p.fix) }));
  if (lines.length === 0 || !lock.problems.some((p) => p.lockRule === "file")) return lock.problems.map((p) => mark(lockProblemFinding(lock.file, p.text, p.covers, p.fix), p.unapprovable));
  const shown = lines.slice(0, MAX_UNLOCKED_LINES).map((p) => p.text);
  const more = lines.length - shown.length;
  const message = `Cannot verify soak time for the packages in ${lock.file}: it is not a hash lock (it has no --require-hashes line), so none of the ${lines.length} line(s) the lock rule refuses was checked: ${shown.join("; ")}${more > 0 ? `; and ${more} more` : ""}. To check them, ${LOCK_REMEDIATION}`;
  const covers = lines.map((p) => `${problemContent(p.text)}\0${p.covers}`).sort().join("\n");
  // The missing line is never approvable (requirements.ts REQUIRE_HASHES_WHY), so neither is the finding it is part of.
  const line = lines.find((p) => p.unapprovable !== undefined);
  const why = lock.problems.find((p) => p.lockRule === "file")?.unapprovable ?? (line === undefined ? undefined : `${line.text.slice(0, line.text.indexOf(": "))}: ${line.unapprovable}`);
  const one = mark(makeFinding({ ruleId: "WS-SK-002", severity: "high", message, file: lock.file, key: `pypi:lockfile ${lock.file} ${keyDigest(`not a hash lock\0${covers}`)}` }), why);
  return [one, ...lock.problems.filter((p) => p.lockRule === undefined).map((p) => mark(lockProblemFinding(lock.file, p.text, p.covers, p.fix), p.unapprovable))];
}

/** The directory a local source tree's install builds: its path, joined with a pylock `subdirectory` (pip and uv build path/subdirectory). */
export function localSourcePath(s: PySource): string {
  if (s.subdirectory === undefined) return s.value;
  return s.value === "." ? s.subdirectory : `${s.value}/${s.subdirectory}`;
}

const wheelTags = (filename: string): string => filename.slice(0, -".whl".length).split("-").slice(2).join("-").toLowerCase();

/**
 * Does a file name the lock gives (pylock `name`, a path's or url's last component) name this index file? The same
 * string; or, since uv writes `name` normalised (pyyaml-6.0.1-..., jaraco_classes-3.4.0-... for PyPI's PyYAML-6.0.1-...
 * and jaraco.classes-3.4.0-...), the same kind, project (PEP 503) and version (PEP 440), and for a wheel the same
 * build and compatibility tags (without case, as installers read them; pip picks a pylock wheel by these tags), for
 * an sdist the same extension.
 */
export function namesIndexFile(name: string, ix: IndexFile): boolean {
  if (name === ix.filename) return true;
  const b = ix.dist;
  const a = b === undefined ? undefined : parseDistFilename(name, b.name);
  if (a === undefined || b === undefined || a.kind !== b.kind || !versionsEqual(a.version, b.version)) return false;
  return a.kind === "wheel" ? wheelTags(name) === wheelTags(ix.filename) : name.endsWith(".zip") === ix.filename.endsWith(".zip");
}

const pkgLabel = (p: PyPackage): string => (p.version === undefined ? p.name : `${p.name}==${p.version}`);

/** The first MAX_FILE_PROBLEMS items joined with `sep`, and how many more there are. */
const listed = (items: string[], sep: string): string => {
  const more = items.length - MAX_FILE_PROBLEMS;
  return `${items.slice(0, MAX_FILE_PROBLEMS).join(sep)}${more > 0 ? `${sep}and ${more} more file(s)` : ""}`;
};

/** A file's own name as the lock gives it, and, for a path archive, the name of the file at its path. */
function lockedNames(f: PyFile, archivePath: string | undefined): string[] {
  const out = new Set<string>();
  if (f.locator.filename !== undefined) out.add(f.locator.filename);
  const fromPath = archivePath === undefined ? undefined : basenameOf(archivePath);
  if (fromPath !== undefined) out.add(fromPath);
  if (out.size === 0 && f.locator.url !== undefined) {
    const b = basenameOf(f.locator.url);
    if (b !== undefined) out.add(b);
  }
  return [...out];
}

/** What a file is, from the index file it is bound to, else from the lock (an archive by its file name). */
function kindOf(f: PyFile, bound: IndexFile | undefined, names: string[]): "sdist" | "wheel" | undefined {
  if (bound?.dist) return bound.dist.kind;
  if (f.kind === "sdist" || f.kind === "wheel") return f.kind;
  const n = names[0];
  return n === undefined ? undefined : parseDistFilename(n)?.kind;
}

/** A file as messages name it: its file name (a path archive's, from its path), else its URL, else its hash. */
const labelOf = (job: Job, f: PyFile): string => lockedNames(f, job.archives.get(f))[0] ?? fileLabel(f);

interface Job {
  pkg: PyPackage;
  lock: PyLock;
  hex: string;
  where: string;
  /** The path of each path archive among the package's files. */
  archives: Map<PyFile, string>;
  /** PR mode: the base's soak read this entry identically, so it is bound (for sdistOnly) but not aged or sent to OSV. */
  quiet: boolean;
  /** Its identity with its send verdict, by which each package is checked once. */
  once: string;
}

export async function checkPythonLocks(locks: PyLock[], opts: PythonSoakOptions): Promise<SoakResult> {
  try {
    return await check(locks, opts);
  } catch (e) {
    const why = `the Python lockfile check stopped on an unexpected error (${String((e as Error)?.message ?? e).slice(0, 200)}), so nothing it would have checked counts as verified`;
    return { findings: [makeFinding({ ruleId: "WS-SK-002", severity: "high", message: `Cannot verify soak time for the PyPI packages: ${why}`, key: "pypi:internal-error" })], evidence: [], notes: [] };
  }
}

async function check(locks: PyLock[], opts: PythonSoakOptions): Promise<SoakResult> {
  const findings: Finding[] = [];
  const evidence: SoakEvidence[] = [];
  const notes: string[] = [];
  if (locks.length === 0) return { findings, evidence, notes };
  const shown = displayUrl(opts.pypiIndex);
  const index = normalizeIndexUrl(opts.pypiIndex);
  const localOpts: LocalOptions = { root: opts.root, git: opts.git, ...(opts.gitError !== undefined ? { gitError: opts.gitError } : {}), ...(opts.gitIgnored !== undefined ? { gitIgnored: opts.gitIgnored } : {}) };

  const keyOf = (p: PyPackage, hex: string): string => `pypi:${p.name}@${p.version ?? ""} ${hex}`;
  const sk002 = (p: PyPackage, where: string, reason: string, key: string, severity: "high" | "medium" = "high"): Finding =>
    makeFinding({ ruleId: "WS-SK-002", severity, message: `Cannot verify soak time for PyPI package ${pkgLabel(p)}: ${reason}`, file: where, ...(p.line !== undefined ? { line: p.line } : {}), key });
  const unverifiable = (p: PyPackage, where: string, reason: string, key: string, severity: "high" | "medium" = "high"): void => {
    evidence.push({ name: p.name, version: p.version ?? "", ecosystem: "PyPI", status: "unverifiable", reason });
    findings.push(sk002(p, where, reason, key, severity));
  };
  /**
   * --on-outage warn: the index did not answer for the package, so nothing about it was checked (OSV is not asked
   * either). The evidence is what it is without the option; the finding is the ledger's to decide.
   */
  const claimOutage = (ledger: OutageLedger, p: PyPackage, where: string, reason: string, outage: string, key: string): void => {
    evidence.push({ name: p.name, version: p.version ?? "", ecosystem: "PyPI", status: "unverifiable", reason });
    const host = new URL(index as string).host;
    const message = `Soak time not checked for PyPI package ${pkgLabel(p)}: ${host} unreachable: ${outage}. Its age, file hashes and OSV records are unverified; --on-outage warn reports it at medium, and by default it fails closed (WS-SK-002, high)`;
    ledger.claim({
      host,
      probe: `${index as string}/`,
      failClosed: [sk002(p, where, reason, key)],
      warn: [makeFinding({ ruleId: "WS-SK-006", severity: "medium", message, file: where, ...(p.line !== undefined ? { line: p.line } : {}), key })],
      unverified: [{ host, error: outage, id: `PyPI:${p.name}@${p.version ?? ""}` }],
    });
  };

  // 1. Reader problems: every run, PR mode included, as npm's lockfile problems are.
  for (const lock of locks) findings.push(...readerProblemFindings(lock));

  // 2 and 3.
  /** Each identity's job, in the order identities are first met: a loud entry takes a quiet one's place. */
  const pending = new Map<string, Job>();
  /** Each identity's state: checked (loud) or, in PR mode, only the base's entries so far (quiet). */
  const seen = new Map<string, "loud" | "quiet">();
  const local: string[] = [];
  let notSent = 0;
  let localChecked = false;
  for (const lock of locks) {
    const base = lockDir(lock.file);
    for (const pkg of lock.packages) {
      const hex = identityDigest(pkg);
      const where = pkg.file ?? lock.file;
      const key = keyOf(pkg, hex);

      // Local source trees (file-level).
      if (LOCAL_TREES.has(pkg.source.kind)) {
        localChecked = true;
        const dir = localSourcePath(pkg.source);
        const r = pkg.source.kind === "virtual" ? checkVirtualProject(dir, base, localOpts) : checkLocalDirectory(dir, base, localOpts);
        if (!r.ok) {
          notSent++;
          // Keyed apart, so a baseline entry for the medium one does not approve the high one in PR mode.
          if (r.untracked && opts.pr !== true) unverifiable(pkg, where, `local source not present in the reviewed tree: ${r.problem}; commit or git-ignore it`, `${key} local untracked ${keyDigest(r.problem)}`, "medium");
          else unverifiable(pkg, where, `local source not present in the reviewed tree: ${r.problem}`, `${key} local ${keyDigest(r.problem)}`);
          continue;
        }
        local.push(pkgLabel(pkg));
        // A uv.lock's directory is its workspace root, whose [tool.uv] and uv.toml apply to every member's build.
        const workspaceRoot = lock.kind === "uv" ? join(localOpts.root, base) : undefined;
        if (pkg.source.kind !== "virtual") findings.push(localBuildFinding({ name: pkg.name, dir: r.rel, lockFile: lock.file, lockKind: lock.kind, sourceKind: pkg.source.kind }, readLocalBuild(r.abs, workspaceRoot)));
        continue;
      }

      // Path archives (file-level): in the reviewed tree, and the file the lock hashed.
      const archives = new Map<PyFile, string>();
      if (pkg.source.kind === "path") {
        if (pkg.files.length === 1) archives.set(pkg.files[0]!, pkg.source.value);
      } else if (lock.kind === "pylock") {
        for (const f of pkg.files) if (f.locator.path !== undefined) archives.set(f, f.locator.path);
      }
      let localFailed = false;
      for (const [f, path] of archives) {
        localChecked = true;
        const sha = sha256Of(f);
        if (sha === undefined) continue; // the binding rule reports it
        const r = checkLocalArchive(path, sha, base, localOpts);
        if (!r.ok) {
          notSent++;
          unverifiable(pkg, where, `local archive not present in the reviewed tree as locked: ${r.problem}`, `${key} local ${keyDigest(r.problem)}`);
          localFailed = true;
          break;
        }
      }
      if (localFailed) continue;

      const once = `${hex}\0${pkg.sendable}\0${pkg.unsent ?? ""}`;
      // PR mode: an entry the base's soak read identically is quiet (src/python/base-entries.ts). An identity is
      // checked once: at its first entry, or at its first entry the base did not hold, which takes the quiet one's place.
      const quiet = opts.base?.holds(lock, pkg) === true;
      const prior = seen.get(once);
      if (prior === "loud" || (prior === "quiet" && quiet)) continue;
      seen.set(once, quiet ? "quiet" : "loud");
      const reason = packageProblem(pkg, archives, index, shown);
      if (reason !== undefined) {
        if (!quiet) {
          notSent++;
          unverifiable(pkg, where, reason, key);
          pending.delete(once);
        }
        continue;
      }
      pending.set(once, { pkg, lock, hex, where, archives, quiet, once });
    }
  }

  const jobs = [...pending.values()];

  // 4. The index.
  const client = createIndexClient({
    index: opts.pypiIndex,
    concurrency: opts.concurrency ?? 2,
    ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
    ...(opts.userAgent ? { userAgent: opts.userAgent } : {}),
    ...(opts.outages ? { outages: opts.outages } : {}),
  });
  const names = [...new Set(jobs.map((j) => j.pkg.name))];
  const pages = new Map<string, ProjectFetch>();
  await Promise.all(names.map(async (name) => pages.set(name, await client.project(name))));

  const served = new Set<string>();
  const yanked: string[] = [];
  const statuses = new Set<string>();
  /** The sha256 of every file bound and aged, once however many locks pin it. */
  const filesChecked = new Set<string>();
  const versionsChecked = new Set<string>();
  /** WS-SK-005 when every file the lock pins for the package is an sdist: by the index file it is bound to, else by the lock. */
  const sdistOnly = (job: Job, boundOf: Map<PyFile, IndexFile>): void => {
    const { pkg } = job;
    const kinds = pkg.files.map((f) => kindOf(f, boundOf.get(f), lockedNames(f, job.archives.get(f))));
    if (kinds.length > 0 && kinds.every((k) => k === "sdist")) {
      const filenames = pkg.files.map((f) => boundOf.get(f)?.filename ?? labelOf(job, f));
      findings.push(sdistOnlyFinding({ name: pkg.name, version: pkg.version!, identity: job.hex, file: job.where, ...(pkg.line !== undefined ? { line: pkg.line } : {}), filenames }));
    }
  };
  /**
   * Binds and ages one package; `boundOf` gets each file it bound. A quiet job (PR mode: the base's entry) is bound, for
   * sdistOnly, and what the index shows about its files is reported as on a full run (a project gone or quarantined, a
   * locked file gone): soak saw it. Its age is not checked, it has no evidence and is not counted, and a request for it
   * that failed is not reported: PR mode does not check it (an npm entry it skips is not fetched at all).
   */
  const evaluate = (job: Job, boundOf: Map<PyFile, IndexFile>): void => {
    const { pkg, where, hex, quiet } = job;
    const version = pkg.version!;
    const key = keyOf(pkg, hex);
    const page = pages.get(pkg.name) ?? { error: "the index was not asked" };
    if ("error" in page && page.outage !== undefined && opts.outages && index !== undefined) {
      if (!quiet) claimOutage(opts.outages, pkg, where, page.error, page.outage, key);
      return;
    }
    if ("notFound" in page || "error" in page) {
      // A project the index does not have (404) is reported for a quiet job too: PyPI takes malware down.
      if (!quiet || "notFound" in page) unverifiable(pkg, where, "notFound" in page ? `${pkg.name} is ${NOT_FOUND}` : page.error, key);
      return;
    }
    served.add(pkg.name);
    const project = page.project;
    const st = project.status;
    if (st.state === "quarantined") {
      unverifiable(pkg, where, `${QUARANTINED}${st.reason ? ` (reason given: ${JSON.stringify(st.reason.slice(0, 200))})` : ""}`, key);
      return;
    }
    if (st.state === "unknown") {
      unverifiable(pkg, where, `the index gives the project status ${st.value}, which wormsign does not know (PEP 792 defines active, archived, deprecated and quarantined)`, key);
      return;
    }
    if (!quiet && (st.state === "archived" || st.state === "deprecated")) statuses.add(`${pkg.name} (${st.state}${st.reason ? `: ${JSON.stringify(st.reason.slice(0, 120))}` : ""})`);

    const problems: string[] = [];
    for (const f of pkg.files) {
      const b = bindLockedFile(project, pkg.name, version, sha256Of(f)!);
      if ("problem" in b) {
        problems.push(`${labelOf(job, f)}: ${b.problem}`);
        continue;
      }
      const ix = b.file;
      if (f.locator.url !== undefined && !sameFileUrl(f.locator.url, ix.url)) {
        problems.push(`${ix.filename}: the lock's url ${displayUrl(f.locator.url)} is not the index's url for that file (${ix.url === undefined ? "the index gives none" : displayUrl(ix.url)})`);
        continue;
      }
      const other = lockedNames(f, job.archives.get(f)).find((n) => !namesIndexFile(n, ix));
      if (other !== undefined) {
        problems.push(`${ix.filename}: the lock names the file ${JSON.stringify(other)}, not the index's ${ix.filename}`);
        continue;
      }
      if (ix.uploadTime === undefined) {
        problems.push(`${ix.filename}: ${ix.uploadTimeProblem ?? "the index gives no upload-time for it"}`);
        continue;
      }
      boundOf.set(f, ix);
    }
    if (problems.length > 0) {
      unverifiable(pkg, where, listed(problems, "; "), key);
      return;
    }
    // Every file is bound (problems is empty); fail closed if that ever stops holding.
    const bound = pkg.files.flatMap((f) => boundOf.get(f) ?? []);
    if (bound.length === 0 || bound.length !== pkg.files.length) {
      unverifiable(pkg, where, "not every locked file could be bound to an index file", key);
      return;
    }
    // A quiet job's age is the base's soak's to have checked.
    if (quiet) return;
    // 5. Age: the youngest bound file's.
    const times = bound.map((ix) => Date.parse(ix.uploadTime!));
    const first = releaseFiles(project, pkg.name, version)
      .filter((ix) => ix.uploadTime !== undefined)
      .reduce<IndexFile | undefined>((a, ix) => (a === undefined || Date.parse(ix.uploadTime!) < Date.parse(a.uploadTime!) ? ix : a), undefined);
    const firstT = first === undefined ? Math.min(...times) : Date.parse(first.uploadTime!);
    const youngestT = Math.max(...times);
    const publishedT = youngestT;
    const youngest = bound[times.indexOf(youngestT)]!;
    const now = opts.now.getTime();
    const age = now - publishedT;
    for (const ix of bound) filesChecked.add(ix.sha256!);
    versionsChecked.add(`${pkg.name}@${version}`);
    for (const ix of bound) if (ix.yanked) yanked.push(`${pkg.name} ${version} ${ix.filename}${ix.yankedReason ? ` (${JSON.stringify(ix.yankedReason.slice(0, 120))})` : ""}`);
    const files: SoakFile[] = bound
      .map((ix): SoakFile => ({ filename: ix.filename, sha256: ix.sha256!, uploadTime: ix.uploadTime!, ...(ix.yanked ? { yanked: true } : {}) }))
      .sort((a, b) => a.filename.localeCompare(b.filename));
    const entry: SoakEvidence = {
      name: pkg.name,
      version,
      ecosystem: "PyPI",
      publishedAt: youngest.uploadTime!,
      ageHours: Math.round((age / HOUR) * 10) / 10,
      status: age < opts.minAgeMs ? "too-new" : "ok",
      releaseFirstFileAt: first?.uploadTime ?? new Date(firstT).toISOString(),
      ...(st.given ? { projectStatus: st.state } : {}),
      files: files.slice(0, MAX_EVIDENCE_FILES),
      ...(files.length > MAX_EVIDENCE_FILES ? { filesTotal: files.length } : {}),
    };
    evidence.push(entry);
    if (age < opts.minAgeMs) {
      const young = bound.filter((ix) => now - Date.parse(ix.uploadTime!) < opts.minAgeMs).sort((a, b) => a.filename.localeCompare(b.filename));
      const described = young.map((ix) => {
        const t = Date.parse(ix.uploadTime!);
        const late = t - firstT >= HOUR ? `, added ${((t - firstT) / DAY).toFixed(1)} days after the release's first file (${first?.uploadTime ?? new Date(firstT).toISOString()})` : "";
        return `${ix.filename} uploaded ${formatDuration(Math.max(now - t, 0))} ago (${ix.uploadTime})${late}`;
      });
      findings.push(
        makeFinding({
          ruleId: "WS-SK-001",
          severity: "high",
          message: `${pkg.name}==${version} (PyPI) has ${young.length} locked file(s) uploaded inside the required ${formatDuration(opts.minAgeMs)} soak window: ${described.join("; ")}`,
          file: where,
          ...(pkg.line !== undefined ? { line: pkg.line } : {}),
          key,
        }),
      );
    }
  };
  for (const job of jobs) {
    const boundOf = new Map<PyFile, IndexFile>();
    evaluate(job, boundOf);
    sdistOnly(job, boundOf);
  }

  // Notes.
  const versionsNote = `${filesChecked.size} PyPI file(s) of ${versionsChecked.size} version(s) checked against ${shown}`;
  notes.push(versionsNote, "registry signals (WS-RG-*) are not implemented for PyPI", "release-age settings of Python tools are not checked by soak; see harden-dev.sh");
  if (local.length > 0) notes.push(`${local.length} local Python package(s) not age-checked (their code is in this repository): ${local.slice(0, 10).join(", ")}${local.length > 10 ? ", ..." : ""}`);
  if (localChecked && opts.git === "no-work-tree") notes.push("the scanned root is not in a git work tree, so whether local Python sources are tracked by git was not checked");
  if (yanked.length > 0) notes.push(`${yanked.length} locked PyPI file(s) are yanked on the index (PEP 592: yanking is not a malware signal, and an install pinned to the file still uses it): ${yanked.slice(0, 10).join(", ")}${yanked.length > 10 ? ", ..." : ""}`);
  if (statuses.size > 0) notes.push(`the index marks ${statuses.size} project(s) archived or deprecated (PEP 792; their files were still checked): ${[...statuses].sort().slice(0, 10).join(", ")}`);
  const unchanged = [...seen.values()].filter((v) => v === "quiet").length;
  if (unchanged > 0) notes.push(`${unchanged} unchanged Python package(s) not checked for age or against OSV (PR mode: the base's soak read the same lock with the same pins and hashes)`);
  notes.push(...(opts.base?.notes() ?? []));

  // 6. OSV.
  if (opts.osv) {
    const loud = jobs.filter((j) => !j.quiet);
    const sent = loud.filter((j) => served.has(j.pkg.name)).map((j) => ({ name: j.pkg.name, version: j.pkg.version!, file: j.where }));
    const unserved = loud.length - sent.length;
    const skipped = [
      ...(notSent + local.length > 0 ? [`${notSent + local.length} not sent to OSV (local code, git, VCS, a direct URL, another index, or a name not confirmed public: soak sends their names nowhere)`] : []),
      ...(unserved > 0 ? [`${unserved} not sent to OSV (the index did not return a page for them, so the name may not be public)`] : []),
    ];
    findings.push(
      ...(await runOsv({
        ecosystem: "PyPI",
        sent,
        index: shown,
        flag: "--pypi-index",
        publicHost: ["pypi.org"],
        label: "the public PyPI index",
        noteLabel: "PyPI",
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

/** Why a package cannot be checked on the index at all, before anything is sent; undefined when it can. */
function packageProblem(pkg: PyPackage, archives: Map<PyFile, string>, index: string | undefined, shown: string): string | undefined {
  if (pkg.version === undefined) return "the lock gives no version, so it cannot be bound or checked against OSV";
  const s = pkg.source;
  switch (s.kind) {
    case "git":
      return `it resolves from a git source (${displayUrl(s.value)}), which has no index upload time`;
    case "vcs":
      return `it resolves from a VCS source (${displayUrl(s.value)}), which has no index upload time`;
    case "url":
      return `it resolves from a direct URL (${displayUrl(s.value)}), which is not an index file`;
    case "archive":
      if (archives.size === 0) return `it is a direct archive (${displayUrl(s.value)}) that is not an index file`;
      break;
    case "path":
      if (pkg.files.length !== 1) return `a path archive (${displayUrl(s.value)}) with ${pkg.files.length} file entries, not one: format not supported`;
      break;
    case "registry":
      if (s.value !== "" && normalizeIndexUrl(s.value) !== index) return `it is locked from ${displayUrl(s.value)}, not --pypi-index ${shown} (${NO_PRIVATE})`;
      break;
  }
  // Whatever the source kind: an index the lock records must be --pypi-index, whatever `sendable` says.
  if (pkg.lockIndex !== undefined && normalizeIndexUrl(pkg.lockIndex) !== index) return `it is locked from ${displayUrl(pkg.lockIndex)}, not --pypi-index ${shown} (${NO_PRIVATE})`;
  if (!pkg.sendable) return `${pkg.unsent ?? "its name is not confirmed to be public"}, so its name is sent nowhere (${NO_PRIVATE})`;
  if (pkg.files.length === 0) return "the lock pins no file for it, so nothing can be bound to an index file";
  const unbound = pkg.files.filter((f) => sha256Of(f) === undefined);
  if (unbound.length > 0) return `${listed(unbound.map(fileLabel), ", ")}: no sha256 hash, so it cannot be bound to an index file`;
  // pip 26.2.1 accepts a pylock file whose content matches ANY hash the entry lists (_pylock_hashes_to_hash_options,
  // Hashes.check_against_chunks), and soak binds only the sha256: another algorithm would let a different file in.
  const mixed = pkg.files.filter((f) => f.hashes.some((h) => h.alg !== "sha256"));
  if (mixed.length > 0) {
    const algs = [...new Set(mixed.flatMap((f) => f.hashes.filter((h) => h.alg !== "sha256").map((h) => JSON.stringify(h.alg.slice(0, 40)))))].sort();
    return `${listed(mixed.map(fileLabel), ", ")}: a hash other than sha256 as well (${algs.slice(0, 5).join(", ")}${algs.length > 5 ? ", ..." : ""}); pip accepts a file that matches any one of a lock's hashes and soak binds only the sha256, so the file cannot be bound to an index file`;
  }
  if (index === undefined) return `--pypi-index ${shown} is not an http(s) URL without query or fragment`;
  return undefined;
}
