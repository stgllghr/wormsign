import { closeSync, constants, existsSync, fstatSync, lstatSync, openSync, readFileSync, readSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { BASELINE_FILE, NOT_BASELINABLE, applyBaseline, isCalendarDate, isIgnored, loadBaseline, parseBaseline } from "./baseline.js";
import type { Baseline } from "./baseline.js";
import { addToBaseline } from "./baseline-add.js";
import type { AddRequest } from "./baseline-add.js";
import { makeContext } from "./checks/context.js";
import { diffTrees } from "./diff.js";
import { parseDuration } from "./duration.js";
import { stripBom } from "./fsutil.js";
import { loadIocDir, loadIocs } from "./iocs.js";
import { parseLockfileText } from "./lockfile/index.js";
import type { ParsedLockfile } from "./lockfile/index.js";
import { ON_OUTAGE, OutageLedger, outageSummary } from "./net.js";
import type { OnOutage } from "./net.js";
import { newOsvSession } from "./osv.js";
import { raiseNewBuilds } from "./python/base-builds.js";
import { baseLocks } from "./python/base-entries.js";
import { discoverPython, gitForPython } from "./python/discover.js";
import { isRequirementsName } from "./python/manifest.js";
import { refusedByPipAndUv } from "./python/scripts.js";
import { pipConfigProbe } from "./python/indexes.js";
import { checkPythonLocks } from "./python/soak.js";
import { gateExitCode, neutralise, renderReport } from "./report.js";
import type { Format, Report } from "./report.js";
import { scanDirectory } from "./scan.js";
import { baselineAt, checkSoakLockfiles, compareEvidence, onlyKey } from "./soak.js";
import type { SoakEvidence } from "./soak.js";
import { checkSoakConfig, installRegistries, installedVersion, readUserFile } from "./soak-config.js";
import { parseAction, parseAgents, runSkills, userHome } from "./skills.js";
import { auditOrg } from "./audit-org.js";
import { DEFAULT_IOC_URL, updateIocs } from "./update-iocs.js";
import { DIR_PREFIX, fold, gitRoot, gitTree, projectRoot, resolveTree } from "./tree.js";
import { redactUrl } from "./url.js";
import { hasNpmInputs, npmLockfiles, walkTree } from "./walk.js";
import type { Tree } from "./tree.js";
import type { Finding, Severity } from "./types.js";
import { UsageError, parseSeverity } from "./types.js";

export interface IO {
  stdout(s: string): void;
  stderr(s: string): void;
  env: Record<string, string | undefined>;
  now(): Date;
  fetchImpl?: typeof fetch;
  /** How soak waits before retrying a registry request (tests pass one that does not wait). Default: a timer. */
  sleep?: (ms: number) => Promise<void>;
  /** Whether stdout is a terminal (process.stdout.isTTY), so a human report printed there is on the person's screen. */
  stdoutIsTTY?: boolean;
}

export const EXIT = { OK: 0, FINDINGS: 1, ERROR: 2 } as const;

const VERSION: string = (() => {
  const p = fileURLToPath(new URL("../../package.json", import.meta.url));
  return (JSON.parse(readFileSync(p, "utf8")) as { version: string }).version;
})();

/** The soak every locked version must have passed when --min-age is not given (docs/soak.md, "Why 7 days"). */
const DEFAULT_MIN_AGE = "7d";
/** The Python package index soak checks when --pypi-index is not given: PyPI's Simple API (PEP 691 JSON). */
const DEFAULT_PYPI_INDEX = "https://pypi.org/simple/";

const HELP = `wormsign ${VERSION}: detection, PR gating and soak-time enforcement for npm and PyPI supply-chain worms

Usage:
  wormsign scan [dir]               scan a project (lifecycle scripts, lockfiles, workflows, payloads, exfil)
  wormsign diff <base> <head>       what a change adds: install-script deps, lifecycle/workflow/config changes
  wormsign soak [dir]               locked npm and PyPI versions: soak time, OSV malware records, npm registry
                                    signals (network); npm, pnpm, Yarn and bun release-age settings (offline)
  wormsign audit-org <org>          read-only GitHub organization audit (token from GITHUB_TOKEN or GH_TOKEN)
  wormsign update-iocs              refresh the IOC cache
  wormsign skills <action>          install, check or uninstall the agent skill (install|check|uninstall)
  wormsign baseline add <fp>...     add reviewed findings to ${BASELINE_FILE} in the current directory (or
                                    --baseline), each with the --reason you write; no scan, no network

<base>, <head> and --base are git revisions (pass full SHAs in CI); diff also compares directories written
dir:<path>, and never guesses that a name is a directory.

Network: soak (unless --config-only), audit-org and update-iocs. scan and diff never use the network.

Options:
  --format human|json|sarif         output format (default human)
  --output <file>                   write the report to a file instead of stdout
  --fail-on <severity|never>        exit 1 at or above this severity (default high)
  --baseline <file>                 baseline file (default ${BASELINE_FILE} in <dir>; diff and soak --base read
                                    it from <base>, never from the change being checked)
  --no-baseline                     scan/diff/soak/audit-org: read no baseline. Use it on a tree you did not
                                    write: its own ${BASELINE_FILE} can suppress or ignore any finding in it
  --node-modules                    scan: also scan installed packages and flag every install script
  --hash-all                        scan: SHA-256 every file, not only IOC-named ones (slow)
  --registry-host <host>            scan/diff: extra registry host lockfiles may resolve from (repeatable)
  --dir <path>                      diff: any directory in the git repository (default .); the whole commit is
                                    compared from the repository root
  --min-age <duration>              soak: required age, e.g. 7d, 72h (default ${DEFAULT_MIN_AGE})
  --registry <url>                  soak: the one npm registry checked for publish times, https, no credentials
                                    (default https://registry.npmjs.org)
  --pypi-index <url>                soak: the one Python index checked (Simple API, JSON), https, no credentials,
                                    query or fragment (default ${DEFAULT_PYPI_INDEX}); giving it also sends the
                                    names of locked local archives there
  --base <rev>                      soak: only npm and Python entries the change adds or changes, against <rev>
  --config-only                     soak: only check release-age configuration (no network)
  --no-osv                          soak: do not ask OSV for malicious-package records
  --on-outage fail|warn             soak: registry, index or OSV unreachable (DNS, connect, TLS, timeout, 429,
                                    5xx): fail closed (default), or warn: medium per package, UNVERIFIED line
  --require-config                  soak: treat missing/too-short release-age config as a failure
  --since <YYYY-MM-DD>              audit-org: a past date to look back to in the audit log (default 30 days)
  --max-repos <n>                   audit-org: cap on repositories given per-repository checks (default 500)
  --url <https-url>                 update-iocs: alternate source directory
  --iocs <dir>                      scan/diff/audit-org: read IOC files from this directory instead
  --agent <list>                    skills: claude, codex, cursor (comma-separated; default: the ones found)
  --project                         skills: the current git repository instead of your user folders
  --dry-run                         skills install: print what would be written, write nothing
  --force                           skills: replace or remove a folder wormsign did not write, or one edited since
  --reason <text>                   baseline add: what was reviewed and why it is safe (required, 15+ characters)
  --expires <YYYY-MM-DD>            baseline add: the last day the new entries suppress (today or later)
  --from <report.json>              baseline add: refuse a fingerprint not approvable in this --format json report

Exit codes: 0 clean (below threshold), 1 findings at or above threshold, 2 usage or internal error
(audit-org: also when the repository list cannot be read, and when the audit is incomplete (stopped by a rate
limit, or a check no repository answered) and would otherwise exit 0).

Each command, its limits and what it sends over the network: docs/cli/<command>.md (soak: docs/cli/soak.md).
`;

interface Parsed {
  command: string;
  positionals: string[];
  flags: Map<string, string[]>;
}

const BOOLEAN_FLAGS = new Set(["node-modules", "hash-all", "config-only", "require-config", "no-osv", "no-baseline", "project", "dry-run", "force", "help", "version"]);
const VALUE_FLAGS = new Set(["format", "output", "fail-on", "baseline", "registry-host", "dir", "min-age", "registry", "pypi-index", "base", "since", "max-repos", "url", "iocs", "agent", "reason", "expires", "from", "on-outage"]);

const REPORT_FLAGS = ["format", "output", "fail-on", "baseline"];
/** What each command accepts. Anything else is a usage error: a dropped argument would be a silent false green. */
export const COMMANDS: Record<string, { usage: string; min: number; max: number; flags: string[] }> = {
  scan: { usage: "[dir]", min: 0, max: 1, flags: [...REPORT_FLAGS, "no-baseline", "iocs", "node-modules", "hash-all", "registry-host"] },
  diff: { usage: "<base> <head>", min: 2, max: 2, flags: [...REPORT_FLAGS, "no-baseline", "iocs", "registry-host", "dir"] },
  soak: { usage: "[dir]", min: 0, max: 1, flags: [...REPORT_FLAGS, "no-baseline", "min-age", "registry", "pypi-index", "base", "config-only", "require-config", "no-osv", "on-outage"] },
  "audit-org": { usage: "<org>", min: 1, max: 1, flags: [...REPORT_FLAGS, "no-baseline", "iocs", "since", "max-repos"] },
  "update-iocs": { usage: "", min: 0, max: 0, flags: ["url"] },
  skills: { usage: "install|check|uninstall", min: 1, max: 1, flags: ["agent", "project", "dry-run", "force"] },
  baseline: { usage: "add <fingerprint>... --reason <text>", min: 2, max: Number.POSITIVE_INFINITY, flags: ["baseline", "reason", "expires", "from"] },
};

export function parseArgs(argv: string[]): Parsed {
  const flags = new Map<string, string[]>();
  const positionals: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string;
    if (a === "-h") {
      flags.set("help", ["true"]);
    } else if (a === "-v") {
      flags.set("version", ["true"]);
    } else if (a.startsWith("--")) {
      const [rawName, inline] = a.slice(2).split(/=(.*)/s, 2) as [string, string | undefined];
      if (BOOLEAN_FLAGS.has(rawName)) {
        // "--node-modules=false" must not quietly mean true.
        if (inline !== undefined) throw new UsageError(`--${rawName} does not take a value`);
        flags.set(rawName, ["true"]);
      } else if (VALUE_FLAGS.has(rawName)) {
        const v = inline ?? argv[++i];
        // An empty value ("--baseline=") would otherwise fall back to the default.
        if (v === undefined || v === "") throw new UsageError(`--${rawName} needs a value`);
        flags.set(rawName, [...(flags.get(rawName) ?? []), v]);
      } else {
        throw new UsageError(`unknown option --${rawName}`);
      }
    } else if (a.startsWith("-")) {
      throw new UsageError(`unknown option ${a}`);
    } else {
      positionals.push(a);
    }
  }
  const [command = "help", ...rest] = positionals;
  return { command, positionals: rest, flags };
}

function one(p: Parsed, name: string): string | undefined {
  return p.flags.get(name)?.at(-1);
}

function parseFormat(s: string | undefined): Format {
  if (s === undefined) return "human";
  if (s === "human" || s === "json" || s === "sarif") return s;
  throw new UsageError(`invalid --format "${s}" (human, json, sarif)`);
}

interface FoundBaseline {
  baseline?: Baseline;
  /** Set when the baseline is the checked directory's own file, read because no --baseline was given. */
  fromTree?: string;
}

/** --baseline, else the directory's own file; nothing with --no-baseline. */
function findBaseline(p: Parsed, dir: string): FoundBaseline {
  if (p.flags.has("no-baseline")) return {};
  const explicit = one(p, "baseline");
  if (explicit) return { baseline: loadBaseline(explicit) };
  const auto = join(dir, BASELINE_FILE);
  // lstat, not exists: a link there (dangling or not) is read, and refused, rather than passed over.
  return lstatSync(auto, { throwIfNoEntry: false }) !== undefined ? { baseline: loadBaseline(auto, { follow: false }), fromTree: auto } : {};
}

/**
 * A baseline that came with the tree being checked can hide any finding in it, IOC matches included. Each command
 * that read one says what it suppressed or ignored, once, so a tree you did not write cannot pass in silence: in the
 * report's notes always (the Action annotates it from there), and on stderr unless those notes are on the person's
 * screen (`onScreen`: a human report on stdout, with stdout a terminal). JSON, SARIF (which has no notes), a report
 * written with --output, or stdout piped or redirected away all keep the stderr line.
 */
function warnTreeBaseline(io: IO, found: FoundBaseline, findings: Finding[], filesIgnored = 0, notes?: string[], onScreen = false): void {
  if (found.fromTree === undefined) return;
  const byRule = new Map<string, number>();
  for (const f of findings) if (f.suppressed) byRule.set(f.ruleId, (byRule.get(f.ruleId) ?? 0) + 1);
  if (byRule.size === 0 && filesIgnored === 0) return;
  const what: string[] = [];
  if (byRule.size > 0) {
    const n = [...byRule.values()].reduce((a, b) => a + b, 0);
    what.push(`suppressed ${n} finding(s) (${[...byRule].sort(([a], [b]) => a.localeCompare(b)).map(([r, k]) => `${r}: ${k}`).join(", ")})`);
  }
  if (filesIgnored > 0) what.push(`kept ${filesIgnored} file(s) from being checked with ignorePaths (${(found.baseline?.ignorePaths ?? []).map((x) => x.path).join(", ")})`);
  const text = `warning: ${found.fromTree} comes from the directory being checked and ${what.join(" and ")}. A tree can hide its own findings this way: check a tree you did not write with --no-baseline.`;
  if (!onScreen) io.stderr(`wormsign: ${neutralise(text)}\n`);
  // In the report too, where the Action (scripts/ci-action.mjs) turns it into a warning annotation on the run.
  notes?.push(text);
}

/** Whether the report is human text on stdout and stdout is a terminal, so its notes are on the person's screen. */
function notesOnScreen(p: Parsed, io: IO): boolean {
  return parseFormat(one(p, "format")) === "human" && one(p, "output") === undefined && io.stdoutIsTTY === true;
}

/** The baseline as `tree` has it. Used with the base side, so a change cannot baseline its own findings. */
function baselineIn(p: Parsed, tree: Tree): Baseline | undefined {
  if (p.flags.has("no-baseline")) return undefined;
  const explicit = one(p, "baseline");
  if (explicit) return loadBaseline(explicit);
  const text = tree.read(BASELINE_FILE);
  return text === undefined ? undefined : parseBaseline(text, `${BASELINE_FILE} at ${tree.label}`);
}

function isDirectory(path: string): boolean {
  return existsSync(path) && statSync(path).isDirectory();
}

/**
 * A URL option (--registry, --pypi-index, --url). Plain http lets anyone on the path forge publish times, file hashes
 * or IOC data; loopback is allowed for a local registry or index mirror. Credentials in the URL (user:password@) are
 * refused: wormsign sends none, and the URL is printed in notes and messages, which reach CI logs and SARIF uploads.
 * An index URL has no query or fragment: soak builds each project's URL from it, and compares it with the index a lock
 * records, so one with either could never be checked.
 */
function checkRegistry(url: string, flag: "registry" | "pypi-index" | "url"): void {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new UsageError(`invalid --${flag} "${redactUrl(url)}"`);
  }
  if (u.username || u.password) throw new UsageError(`--${flag} must not contain credentials (user:password@), which would be printed in the report: ${redactUrl(url)}`);
  const loopback = flag !== "url" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && loopback)) {
    throw new UsageError(flag === "url" ? `--url must be https: ${redactUrl(url)}` : `--${flag} must be https (http only for localhost): ${redactUrl(url)}`);
  }
  if (flag === "pypi-index" && (u.search !== "" || u.hash !== "" || url.includes("?") || url.includes("#"))) {
    throw new UsageError(`--pypi-index must not have a query or fragment: ${redactUrl(url)}`);
  }
}

/** Every argument is checked before any scan, git or network work, so a typo never costs a full run. */
function checkArgs(p: Parsed, now: Date): void {
  const spec = COMMANDS[p.command];
  if (!spec) throw new UsageError(`unknown command "${p.command}"`);
  if (p.positionals.length < spec.min || p.positionals.length > spec.max) {
    throw new UsageError(`usage: wormsign ${p.command} ${spec.usage}`.trimEnd() + ` (got: ${p.positionals.join(" ") || "nothing"})`);
  }
  for (const name of p.flags.keys()) {
    if (!spec.flags.includes(name)) throw new UsageError(`--${name} is not an option of ${p.command}`);
  }
  parseFormat(one(p, "format"));
  failOnOf(p);
  onOutageOf(p);
  const out = one(p, "output");
  if (out !== undefined && !isDirectory(dirname(resolve(out)))) throw new UsageError(`--output: directory ${dirname(resolve(out))} does not exist`);
  for (const flag of ["registry", "pypi-index", "url"] as const) {
    const url = one(p, flag);
    if (url !== undefined) checkRegistry(url, flag);
  }
  const since = one(p, "since");
  if (since !== undefined && (!isCalendarDate(since) || new Date(`${since}T00:00:00Z`) > now)) throw new UsageError(`invalid --since "${since}" (a past date, YYYY-MM-DD)`);
  // Number("abc") is NaN and slice(0, NaN) is empty: the repository listing would silently cover nothing.
  const maxRepos = one(p, "max-repos");
  if (maxRepos !== undefined && !/^[1-9]\d*$/.test(maxRepos)) throw new UsageError(`invalid --max-repos "${maxRepos}" (a whole number, at least 1)`);
  // Loaded here only to validate them; a bad file must fail before git, scanning or the GitHub API.
  const baseline = one(p, "baseline");
  if (baseline !== undefined && p.flags.has("no-baseline")) throw new UsageError("--baseline and --no-baseline cannot be used together");
  // baseline add checks the file it writes itself: it may not exist yet, and a link there is refused, not followed.
  if (baseline !== undefined && p.command !== "baseline") loadBaseline(baseline);
  const iocs = one(p, "iocs");
  if (iocs !== undefined) loadIocDir(iocs);
  if (p.command === "skills") {
    const action = parseAction(p.positionals[0]);
    parseAgents(p.flags.get("agent"));
    if (p.flags.has("dry-run") && action !== "install") throw new UsageError("--dry-run is an option of skills install only");
    if (p.flags.has("force") && action === "check") throw new UsageError("--force is not an option of skills check");
  }
}

/** `baseline add`'s arguments: the action, the fingerprints, one --reason and at most one --expires and --from.
 * addToBaseline checks their values. */
function baselineRequest(p: Parsed, now: Date): AddRequest {
  const [action, ...fingerprints] = p.positionals;
  if (action !== "add") throw new UsageError(`unknown baseline action "${action}" (add)`);
  // A second value would replace the first in silence, and with it the reason or the expiry someone meant.
  for (const name of ["reason", "expires", "from"]) if ((p.flags.get(name)?.length ?? 0) > 1) throw new UsageError(`--${name} is given more than once`);
  const reason = one(p, "reason");
  if (reason === undefined) throw new UsageError('baseline add needs --reason "<what was reviewed and why it is safe>"');
  const expires = one(p, "expires");
  const from = one(p, "from");
  return { fingerprints, reason, now, ...(expires !== undefined ? { expires } : {}), ...(from !== undefined ? { from } : {}) };
}

/**
 * Writes the report to a regular file only. A report path inside the checked-out tree could be committed as a
 * symlink to a shell startup file, and the report quotes the tree's script text: so a final symlink is refused
 * (O_NOFOLLOW, where the platform has it; Windows has none), a FIFO is not waited on (O_NONBLOCK), and anything that
 * is not a regular file once opened, such as a device, is refused before a byte is written. A symlinked directory
 * earlier in the path is still followed, which is why the docs write reports outside the tree being checked.
 */
function writeReport(out: string, text: string): void {
  const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);
  let fd: number;
  try {
    fd = openSync(out, flags, 0o644);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    throw new UsageError(`cannot write --output ${out}: ${code === "ELOOP" ? "it is a symlink, which wormsign does not write through" : (code ?? (e as Error).message)}`);
  }
  try {
    if (!fstatSync(fd).isFile()) throw new UsageError(`cannot write --output ${out}: it is not a regular file`);
    writeFileSync(fd, text);
  } catch (e) {
    throw e instanceof UsageError ? e : new UsageError(`cannot write --output ${out}: ${(e as NodeJS.ErrnoException).code ?? (e as Error).message}`);
  } finally {
    closeSync(fd);
  }
}

function emit(io: IO, p: Parsed, report: Report, failOn: Severity | "never"): number {
  const text = renderReport(report, parseFormat(one(p, "format")));
  const out = one(p, "output");
  if (out) {
    writeReport(out, text);
  } else {
    io.stdout(text);
  }
  return gateExitCode(report.findings, failOn) === 1 ? EXIT.FINDINGS : EXIT.OK;
}

/** --on-outage: "fail" (the default) or "warn"; anything else is a usage error. */
function onOutageOf(p: Parsed): OnOutage {
  const v = one(p, "on-outage") ?? "fail";
  if (!(ON_OUTAGE as readonly string[]).includes(v)) throw new UsageError(`invalid --on-outage "${v}" (${ON_OUTAGE.join(", ")})`);
  return v as OnOutage;
}

function failOnOf(p: Parsed): Severity | "never" {
  const v = one(p, "fail-on") ?? "high";
  return v === "never" ? "never" : parseSeverity(v);
}

/** A bunfig.toml at the root, as checkSoakConfig reads it; one that cannot be looked at counts as present (npm's output stays). */
function hasBunfig(root: string): boolean {
  try {
    return lstatSync(join(root, "bunfig.toml"), { throwIfNoEntry: false }) !== undefined;
  } catch {
    return true;
  }
}

/** The most bytes of a file soak's "nothing to verify" note reads, and the most files it reads (later ones are named unread). */
const NOTE_BYTES = 64 * 1024;
const NOTE_FILES = 1000;

/**
 * Could pip read this file as a requirements file? False only when its first NOTE_BYTES (cut back to whole lines) hold
 * a line neither pip nor uv reads (scripts.ts refusedByPipAndUv: prose such as a LICENSE.txt); true when it cannot be
 * read. It only decides which files soak's note names: no finding depends on it.
 */
function mayBeRequirementsFile(path: string): boolean {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  } catch {
    return true;
  }
  try {
    const size = fstatSync(fd).size;
    const buf = Buffer.alloc(Math.min(size, NOTE_BYTES));
    let got = 0;
    for (let n = -1; got < buf.length && n !== 0; got += n) n = readSync(fd, buf, got, buf.length - got, null);
    const whole = size <= NOTE_BYTES ? buf.subarray(0, got) : buf.subarray(0, buf.lastIndexOf(0x0a) + 1);
    return !refusedByPipAndUv(whole);
  } catch {
    return true;
  } finally {
    closeSync(fd);
  }
}

export async function run(argv: string[], io: IO): Promise<number> {
  try {
    const p = parseArgs(argv);
    if (p.flags.has("version")) {
      io.stdout(`${VERSION}\n`);
      return EXIT.OK;
    }
    if (p.flags.has("help") || p.command === "help") {
      io.stdout(HELP);
      return EXIT.OK;
    }
    checkArgs(p, io.now());
    const iocDir = one(p, "iocs");
    const ctxOpts = { registryHosts: p.flags.get("registry-host") ?? [], hashAll: p.flags.has("hash-all") };
    const failOn = failOnOf(p);

    switch (p.command) {
      case "scan": {
        const root = resolve(p.positionals[0] ?? ".");
        const loaded = findBaseline(p, root);
        const baseline = loaded.baseline;
        const iocs = loadIocs(iocDir ? { dir: iocDir } : {});
        const res = scanDirectory(root, makeContext(iocs, ctxOpts), { nodeModules: p.flags.has("node-modules"), ignorePrefixes: baseline?.ignorePaths.map((x) => x.path) ?? [] });
        const notes = [...iocs.notes, ...res.notes, `${res.filesScanned} files scanned`];
        if (baseline?.ignorePaths.length) notes.push(`ignored paths (baseline): ${baseline.ignorePaths.map((x) => x.path).join(", ")}`);
        for (const x of baseline?.ignorePaths ?? []) if (!existsSync(join(root, x.path))) notes.push(`baseline ignorePaths entry "${x.path}" matches nothing in ${root}`);
        // A suppression nothing uses is left over (the finding is gone or its fingerprint changed): say so.
        const found = new Set(res.findings.map((f) => f.fingerprint));
        for (const x of baseline?.entries ?? []) if (!found.has(x.fingerprint)) notes.push(`baseline entry ${x.fingerprint} matches no finding`);
        const findings = applyBaseline(res.findings, baseline, io.now());
        warnTreeBaseline(io, loaded, findings, res.filesIgnored, notes, notesOnScreen(p, io));
        return emit(io, p, { command: "scan", findings, notes, toolVersion: VERSION }, failOn);
      }
      case "diff": {
        const [baseArg, headArg] = p.positionals as [string, string];
        const dir = resolve(one(p, "dir") ?? ".");
        // Revisions are read from the repository root, so a change to the root lockfile or config is never out of view.
        const repo = baseArg.startsWith(DIR_PREFIX) && headArg.startsWith(DIR_PREFIX) ? dir : gitRoot(dir);
        const base = resolveTree(baseArg, repo);
        const head = resolveTree(headArg, repo);
        const baseline = baselineIn(p, base);
        const ignore = baseline?.ignorePaths.map((x) => x.path) ?? [];
        const iocs = loadIocs(iocDir ? { dir: iocDir } : {});
        const res = diffTrees(base, head, makeContext(iocs, ctxOpts), { ignore });
        const notes = [...iocs.notes, `compared ${base.label} with ${head.label}`, ...res.notes];
        const from = one(p, "baseline") ?? `${BASELINE_FILE} at ${base.label}`;
        if (ignore.length) notes.push(`ignored paths (baseline ${from}; npm manifests, local actions and package-manager config are checked everywhere, and so are a pyproject.toml's [tool.uv], a Python project's build and a pyproject.toml that does not parse; other Python manifest edits and Python locks are not): ${ignore.join(", ")}`);
        return emit(io, p, { command: "diff", findings: applyBaseline(res.findings, baseline, io.now()), notes, toolVersion: VERSION }, failOn);
      }
      case "soak": {
        const root = resolve(p.positionals[0] ?? ".");
        const minAgeMs = parseDuration(one(p, "min-age") ?? DEFAULT_MIN_AGE);
        const registry = one(p, "registry") ?? "https://registry.npmjs.org";
        // Only from the command line (or the Action input): a repository file never chooses the index it is checked on.
        const pypiArg = one(p, "pypi-index");
        const pypiIndex = pypiArg ?? DEFAULT_PYPI_INDEX;
        const configOnly = p.flags.has("config-only");
        const osv = !p.flags.has("no-osv");
        const onOutage = onOutageOf(p);
        const baseArg = one(p, "base");
        // A git revision only: a directory of that name would come from the change under review.
        const baseTree = baseArg ? gitTree(root, baseArg) : undefined;
        const notes: string[] = [];
        // In PR mode the change under review must not bring its own suppressions.
        const fromBase = baseArg !== undefined && baseTree !== undefined && !one(p, "baseline") && !p.flags.has("no-baseline");
        const loaded = fromBase ? { baseline: baselineAt(baseTree, baseArg) } : findBaseline(p, root);
        const baseline = loaded.baseline;
        if (fromBase) notes.push(`baseline read from ${baseArg}, not from the working tree`);
        const findings: Finding[] = [];
        // One walk for both ecosystems (src/walk.ts): npm's half pushes the walker's own findings, once.
        const walk = walkTree(root, { env: io.env });
        const locks = npmLockfiles(root, walk, findings);
        const ignorePaths = baseline?.ignorePaths.map((x) => x.path) ?? [];
        const py = discoverPython(root, { walk, env: io.env, pypiIndex, pypiIndexExplicit: pypiArg !== undefined, configOnly, ignore: ignorePaths, pipConfig: pipConfigProbe(io.env, undefined, root) });
        notes.push(...walk.notes);
        if (locks.length === 0 && findings.length === 0 && py.locks.length === 0 && py.findings.length === 0) {
          // A file pip may install from under another name, without hashes, is not read (docs/soak.md, "Requirements
          // files"): the note says so, naming the .txt, .in and .pip files it passed over that pip could read as
          // requirements (not LICENSE.txt or CMakeLists.txt: scripts.ts refusedByPipAndUv), rather than "no dependencies".
          const passed = walk.entries
            .filter((e) => e.type === "file" && /\.(txt|in|pip)$/.test(fold(e.name)) && !isRequirementsName(e.rel) && !e.rel.split("/").includes("node_modules") && !isIgnored(e.rel, ignorePaths))
            .map((e) => e.rel)
            .sort()
            .filter((rel, i) => i >= NOTE_FILES || mayBeRequirementsFile(join(root, rel)));
          const named = passed.length > 10 ? `${passed.slice(0, 10).join(", ")} and ${passed.length - 10} more` : `${passed.slice(0, -1).join(", ")}${passed.length > 1 ? " and " : ""}${passed[passed.length - 1] ?? ""}`;
          notes.push(
            passed.length === 0
              ? "no lockfile and no dependencies declared; the soak gate has nothing to verify"
              : `no lockfile and no dependencies declared; the soak gate has nothing to verify. It looked for npm, pnpm, Yarn and bun lockfiles and manifests, Python locks, manifests and PEP 723 scripts, and requirements files by name (*requirements*.txt, *constraints*.txt, requirements*.lock, a .txt under a requirements directory) or, among the files its content pass opens (no extension, or .txt, .in, .lock, .pip, .req and the other extensions docs/soak.md#discovery-what-is-read lists), holding --hash or --require-hashes; it did not read ${named} as requirements files (no requirements name, no --hash), so if pip installs from ${passed.length === 1 ? "it" : "one of them"} (\`pip install -r\`), nothing here checks what that installs`,
          );
        }
        findings.push(...py.findings);
        notes.push(...py.notes);
        // npm's notes (the registry count, signals, --config-only) only where npm has something to say: an npm, pnpm or
        // Yarn lockfile was read, a bunfig.toml is at the root, or the tree has no Python input either. A Python-only
        // tree reports nothing about npm, and an npm-only or empty tree reports exactly what it did before PyPI, but for
        // the note above when it holds a .txt, .in or .pip file pip could read as requirements.
        const npmOutput = locks.length > 0 || hasBunfig(root) || !py.pythonInputs;
        const home = io.env["HOME"] ?? homedir();
        const userNpmrc = readUserFile(io.env["NPM_CONFIG_USERCONFIG"] ?? io.env["npm_config_userconfig"] ?? join(home, ".npmrc"));
        const userYarnrc = readUserFile(join(home, ".yarnrc.yml"));
        // pnpm 11's global config.yaml: under XDG_CONFIG_HOME, else ~/Library/Preferences on macOS (both verified, pnpm 11.16.0), else ~/.config.
        const pnpmConfig = join(io.env["XDG_CONFIG_HOME"] || join(home, process.platform === "darwin" ? "Library/Preferences" : ".config"), "pnpm", "config.yaml");
        const userPnpmText = readUserFile(pnpmConfig);
        const userPnpm: [string, string] | undefined = userPnpmText === undefined ? undefined : [pnpmConfig.replace(home, "~"), userPnpmText];
        const rc = { env: io.env, ...(userNpmrc !== undefined ? { userNpmrc } : {}), ...(userYarnrc !== undefined ? { userYarnrc } : {}), ...(userPnpm ? { userPnpm } : {}) };
        // With Python inputs and no npm input there is no npm package manager whose setting is missing.
        const inputs = py.pythonInputs ? { pythonInputs: true as const, npmInputs: hasNpmInputs(walk) } : {};
        let config = checkSoakConfig(root, locks, { ...rc, ...inputs, minAgeMs, versionOf: (m, dir) => installedVersion(m, root, io.env, dir) });
        if (p.flags.has("require-config")) {
          config = config.map((f) => (f.ruleId === "WS-SK-003" || f.ruleId === "WS-SK-004") && f.severity === "medium" ? { ...f, severity: "high" as const } : f);
        }
        findings.push(...config);
        let extra: SoakEvidence[] | undefined;
        if (!configOnly) {
          // One OSV session for the run: npm and PyPI share its record cache and its query ceiling.
          const osvSession = newOsvSession();
          const evidence: SoakEvidence[] = [];
          // --on-outage warn: what an outage may explain is decided once both ecosystems have run (src/net.ts).
          const ledger = onOutage === "warn" ? new OutageLedger() : undefined;
          if (npmOutput) {
            let only: Set<string> | undefined;
            const base: ParsedLockfile[] = [];
            if (baseTree) {
              // Per lockfile: an entry is unchanged only when the base's copy of the same file locked it. A set across
              // files would let a version the base locked (or baselined) in a docs or tooling lockfile into the
              // lockfile that is installed unchecked.
              const before = new Set<string>();
              for (const l of locks) {
                // "./": relative to root even when root is a subdirectory of the git repository.
                const t = baseTree.read(`./${l.file}`);
                if (t === undefined) continue;
                try {
                  const parsed = parseLockfileText(l.file, stripBom(t));
                  if (parsed) base.push(parsed);
                  for (const bp of parsed?.packages ?? []) before.add(onlyKey(l.file, bp));
                } catch {
                  notes.push(`could not parse ${l.file} at ${baseArg}; checking all packages in it`);
                }
              }
              only = new Set(locks.flatMap((l) => l.packages.map((pkg) => onlyKey(l.file, pkg))).filter((k) => !before.has(k)));
            }
            const res = await checkSoakLockfiles(locks, {
              minAgeMs,
              registry,
              now: io.now(),
              installRegistries: (lock) => installRegistries(root, lock, rc),
              osv,
              osvSession,
              ...(ledger ? { outages: ledger } : {}),
              ...(baseTree ? { base } : {}),
              ...(io.fetchImpl ? { fetchImpl: io.fetchImpl } : {}),
              ...(io.sleep ? { sleep: io.sleep } : {}),
              ...(only ? { only } : {}),
            });
            findings.push(...res.findings);
            if (!osv) notes.push("OSV not asked for malicious-package records (--no-osv)");
            notes.push(...res.notes, `${res.evidence.length} package version(s) checked against ${redactUrl(registry)}`);
            evidence.push(...res.evidence);
          } else if (!osv) {
            notes.push("OSV not asked for malicious-package records (--no-osv)");
          }
          if (py.locks.length > 0) {
            // PR mode: an entry the base's own soak read identically is not checked again, as for npm. Only one the base
            // read as a lock counts (src/python/base-entries.ts): a pin that landed first in a file the base's soak never
            // read as a lock (a .md file, a requirements file pip refuses, a script lock with no script, a file under the
            // base's ignorePaths) is checked once a change makes that file a lock. A file counts as passed over on the
            // base when the run's baseline (the base's, or --baseline) or the base's own committed baseline ignores it:
            // the base's soak may have read either. One that cannot be read makes nothing the base's, and a note says
            // so. One request per project, cached for the run.
            let ignore: string[] | undefined;
            if (baseTree && baseArg) {
              const ofRun = baseline?.ignorePaths.map((x) => x.path) ?? [];
              try {
                ignore = [...ofRun, ...(fromBase ? [] : (baselineAt(baseTree, baseArg)?.ignorePaths.map((x) => x.path) ?? []))];
              } catch (e) {
                ignore = undefined;
                notes.push(`PR mode: no Python entry counts as the base's, since ${BASELINE_FILE} at ${baseArg} could not be read (${String((e as Error).message).slice(0, 200)})`);
              }
            }
            const res = await checkPythonLocks(py.locks, {
              minAgeMs,
              now: io.now(),
              pypiIndex,
              osv,
              osvSession,
              root,
              // Runs git (the tracked rule for local sources) only now, when a Python lock needs it.
              ...gitForPython(walk, py.locks),
              ...(baseTree ? { pr: true } : {}),
              // The base revision as raiseNewBuilds reads it: root-relative paths, nothing written to disk.
              ...(baseTree ? { base: baseLocks({ read: (rel) => baseTree.read(`./${rel}`), entry: (rel) => baseTree.entry?.(rel), list: () => baseTree.list(), ...(baseTree.attributes ? { attributes: baseTree.attributes } : {}), ...(baseTree.blobs ? { blobs: baseTree.blobs } : {}) }, py.locks, { pypiIndex, ignore }) } : {}),
              ...(ledger ? { outages: ledger } : {}),
              ...(io.fetchImpl ? { fetchImpl: io.fetchImpl } : {}),
            });
            findings.push(...res.findings);
            notes.push(...res.notes);
            evidence.push(...res.evidence);
          }
          extra = evidence.sort(compareEvidence);
          // --on-outage warn: each claim is WS-SK-006 or WS-OS-901 only if its host never answered in the run, nor its
          // probe; then one loud line, on stderr and first among the notes, where the Action finds it.
          const resolved = ledger ? await ledger.resolve(io.fetchImpl) : { findings: [], unverified: [] };
          findings.push(...resolved.findings);
          const summary = outageSummary(resolved.unverified);
          if (summary !== undefined) {
            io.stderr(`${neutralise(summary)}\n`);
            notes.unshift(summary);
          }
        } else {
          if (npmOutput) {
            notes.push(
              "lockfile soak check not run (--config-only). npm and Yarn release-age settings do not stop `npm ci` or `yarn install --immutable` from installing a young version that is already locked (verified npm 12.2.0, Yarn 4.18.1); pnpm re-checks locked versions from 11.1.3.",
            );
          }
          if (py.pythonInputs) notes.push("Python lock check not run (--config-only); release-age settings of Python tools are not checked by soak; see harden-dev.sh");
        }
        // PR mode: a WS-SK-005 (a build at install time) the change adds is high; one the base has stays medium.
        const gated =
          baseTree && baseArg
            ? raiseNewBuilds(findings, { read: (rel) => baseTree.read(`./${rel}`), list: () => baseTree.list(), regularFile: (rel) => baseTree.regularFile?.(rel) === true, entry: (rel) => baseTree.entry?.(rel) }, baseArg, { locks: py.locks, pypiIndex })
            : findings;
        const report: Report = { command: "soak", findings: applyBaseline(gated, baseline, io.now()), notes, toolVersion: VERSION };
        // An entry for a finding no entry may approve (notBaselinable: any requirements problem but a plain index
        // requirement or a local file soak resolved, src/python/requirements.ts approvable; NOT_BASELINABLE: an outage
        // under --on-outage warn) is said to do nothing, rather than left looking like an approval.
        for (const f of report.findings) if ((f.notBaselinable === true || NOT_BASELINABLE.has(f.ruleId)) && baseline?.entries.some((e) => e.fingerprint === f.fingerprint)) notes.push(`baseline entry ${f.fingerprint} does not apply: no baseline entry can approve that finding (its message says why)`);
        warnTreeBaseline(io, loaded, report.findings, 0, notes, notesOnScreen(p, io));
        if (extra !== undefined) report.extra = { evidence: extra, minAgeMs };
        return emit(io, p, report, failOn);
      }
      case "audit-org": {
        const org = p.positionals[0];
        if (!org) throw new UsageError("audit-org needs an organization name");
        const token = io.env["GITHUB_TOKEN"] ?? io.env["GH_TOKEN"];
        if (!token) throw new UsageError("set GITHUB_TOKEN or GH_TOKEN. Fine-grained token, read-only: repository Metadata, Contents and Administration; organization Self-hosted runners and Administration (audit log). Classic token: repo, admin:org (runners; a write-capable scope) and read:audit_log. Runner listings also need admin rights on the organization and the repositories.");
        // checkArgs has validated both before any network call.
        const since = one(p, "since");
        const sinceDate = since === undefined ? undefined : new Date(`${since}T00:00:00Z`);
        const maxRepos = one(p, "max-repos");
        // The working directory's baseline, unless --baseline or --no-baseline: run from a clone someone else wrote, it
        // could hide findings, so what it hid is said on stderr as for scan.
        const loaded = findBaseline(p, ".");
        const baseline = loaded.baseline;
        const iocs = loadIocs(iocDir ? { dir: iocDir } : {});
        const res = await auditOrg({
          org,
          token,
          iocs,
          ...(io.fetchImpl ? { fetchImpl: io.fetchImpl } : {}),
          ...(sinceDate ? { since: sinceDate } : {}),
          ...(maxRepos !== undefined ? { maxRepos: Number(maxRepos) } : {}),
        });
        // JSON and SARIF readers see an incomplete audit too, not only the exit code and stderr.
        const notes = [...iocs.notes, ...res.notes, ...(res.incomplete ? [`audit incomplete: ${res.incomplete}`] : [])];
        const findings = applyBaseline(res.findings, baseline, io.now());
        warnTreeBaseline(io, loaded, findings, 0, notes, notesOnScreen(p, io));
        const code = emit(io, p, { command: "audit-org", findings, notes, toolVersion: VERSION }, failOn);
        if (!res.incomplete) return code;
        // The report still prints what was found; the exit code must not let an incomplete audit pass as clean.
        io.stderr(`wormsign: audit incomplete: ${res.incomplete}; see the WS-OR-900 findings\n`);
        return code === EXIT.OK ? EXIT.ERROR : code;
      }
      case "update-iocs": {
        const iocs = await updateIocs(one(p, "url") ?? DEFAULT_IOC_URL, undefined, io.fetchImpl);
        // Data no newer than this release's is not written, which is not an error; it must not read as an update.
        io.stdout(`${iocs.notes.join("; ")}\n`);
        if (!iocs.written) return EXIT.OK;
        const n = iocs.packageSets.reduce((a, s) => a + Object.values(s.packages).reduce((b, v) => b + v.length, 0), 0);
        io.stdout(`IOC cache updated: ${n} package versions, ${iocs.hashes.length} hashes, ${iocs.workflowFiles.length} workflow names\n`);
        return EXIT.OK;
      }
      case "skills": {
        // Paths come from io.env (tests pass a temporary HOME), whose HOME counts only when it is absolute; --project
        // resolves the git root of the working directory with the same hardened git call diff uses, and refuses one
        // that does not hold the working directory (projectRoot: core.worktree pointing elsewhere). The home folder is
        // looked up only when it is read (a user-level target, or finding the agents without --agent), so
        // `--project --agent ...` runs in CI with HOME unset or empty.
        const env = io.env;
        const where = {
          get home(): string {
            return userHome(env);
          },
          env,
          ...(p.flags.has("project") ? { projectRoot: projectRoot(process.cwd()) } : {}),
        };
        const agents = parseAgents(p.flags.get("agent"));
        const res = runSkills(parseAction(p.positionals[0]), { ...(agents ? { agents } : {}), dryRun: p.flags.has("dry-run"), force: p.flags.has("force") }, where);
        for (const line of res.lines) io.stdout(`${neutralise(line)}\n`);
        return res.code;
      }
      case "baseline": {
        // Reads and writes this one file: no scan, no IOC data, no network.
        const res = addToBaseline(one(p, "baseline") ?? BASELINE_FILE, baselineRequest(p, io.now()));
        for (const e of res.added) io.stdout(`${neutralise(`added ${e.fingerprint}${e.expires ? ` (expires ${e.expires})` : ""}: ${e.justification}`)}\n`);
        const n = res.added.length;
        io.stdout(`${neutralise(`${res.path}: ${n} ${n === 1 ? "entry" : "entries"} added${res.created ? " (new file)" : ""}`)}\n`);
        // Without the report, an entry for a finding no entry can approve, or for no finding, is written all the same.
        if (one(p, "from") === undefined) io.stderr("wormsign: note: not checked against a report; pass --from <report.json> (a --format json report) to refuse a fingerprint that is no finding there or whose finding no entry can approve\n");
        return EXIT.OK;
      }
      default:
        throw new UsageError(`unknown command "${p.command}"`); // unreachable: checkArgs knows every command
    }
  } catch (e) {
    // Messages can carry repository text (paths, baseline fields), and the Actions runner reads workflow commands
    // from stderr too, so each line is neutralised like the report.
    const text = e instanceof UsageError ? e.message : `internal error: ${(e as Error).stack ?? String(e)}`;
    io.stderr(`wormsign: ${text.split("\n").map(neutralise).join("\n")}\n`);
    return EXIT.ERROR;
  }
}
