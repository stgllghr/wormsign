/**
 * Is a locked name@version a known malicious package? Asks OSV (https://osv.dev) for the version's records and reports
 * two kinds, in every ecosystem alike, as malicious-package records (WS-OS-001):
 * - OpenSSF malicious-packages records, ids "MAL-". GitHub advisories of type "malware" are merged into these records
 *   as aliases (GHSA-qjqf-7j6f-82c4 is served as MAL-2025-47141), and OSV had a record for worm versions that
 *   GitHub's advisories, which `npm audit` reads, did not.
 * - GitHub advisories ("GHSA-") whose database_specific.cwe_ids include "CWE-506" (embedded malicious code), which
 *   GitHub gives a hijacked release. These are separate records, and some versions have no MAL- record at all or not
 *   yet: ua-parser-js@0.7.29 has only GHSA-pjwm-rvh2-c87w, and num2words@0.5.15's GHSA-jxr6-qrxx-2ph2 was reviewed on
 *   2025-07-31, before OSV first imported MAL-2025-6794 for it on 2025-08-06 (the earliest import_time in that
 *   record's malicious-packages-origins). debug@4.4.2 has both, GHSA-4x49-vf9v-38px and MAL-2025-46974: two findings.
 * Every other record (an ordinary GHSA, PYSEC-, CVE-, ...) is a vulnerability, not malware, and out of scope.
 *
 * A query batch answer carries only record ids. A version with a GHSA- id this run has not classified gets all its
 * records, in full, from one POST /v1/query (its pages and one retry included, the retry after HTTP 429 or 503 made
 * after a wait: RETRY_WAIT_MS); the CWE ids of every GHSA record in that answer are kept for the run (the OsvSession),
 * so a version whose GHSA ids the run has read is not asked. Versions are asked in name and version order (plain
 * string order: 1.0.10 before 1.0.9), four at a time; a version whose GHSA ids are all among the GHSA ids of the
 * versions before it is not asked either, since those versions' answers hold them. At most MAX_RECORD_QUERIES versions
 * are asked per run, and the rest, in that order, are unchecked. Once a query fails after its retry (a network error, a
 * timeout, HTTP 429 or a 5xx), no other is started in the run: OSV being down costs one round of requests, not two
 * timeouts per version. A version is unchecked (WS-OS-900), never clean, when one of its GHSA ids has no CWE ids read
 * for it, or when its own query failed, answered without one of its GHSA ids, or held a GHSA record without a list of
 * CWE ids. With an OutageLedger (--on-outage warn), a version whose query batch failed as an outage (src/net.ts) is
 * filed as a claim: WS-OS-901, medium, if api.osv.dev gives no answer in the whole run, else WS-OS-900 as without the
 * option. A record query is never such a claim: it follows a batch OSV answered. No request follows a redirect.
 *
 * The client relies on a few facts about the API (dated observations in docs/architecture.md, "What the OSV client
 * relies on"): a query batch takes at most 1000 queries and answers in query order, each {} or { vulns, next_page_token? };
 * a page token means more ids for that query; one bad query fails the whole batch; the server matches versions against
 * ranges itself; POST /v1/query returns a version's full records, paged, and a GHSA record carries
 * database_specific.cwe_ids. Anything else in an answer is an error, never "no records".
 *
 * Every name passed here is sent to api.osv.dev: callers must not pass private package names.
 *
 * One call checks one ecosystem ("npm" unless told otherwise), so adding another ecosystem's names never changes an
 * npm query, finding or key. A PyPI call's finding keys start with "pypi:".
 */
import { isTransientStatus, transportFailure } from "./net.js";
import type { OutageLedger } from "./net.js";
import { makeFinding } from "./types.js";
import type { Finding } from "./types.js";
import { redirectProblem } from "./url.js";

export interface OsvPackage {
  name: string;
  version: string;
  file?: string;
}

/** OSV ecosystem names, exactly as the API spells them (https://ossf.github.io/osv-schema/#affectedpackage-field). */
export type OsvEcosystem = "npm" | "PyPI";

/**
 * What every call in one run shares (soak asks once per ecosystem), so a version whose GHSA records were read for one
 * call is not asked again by the next, and the per-run query ceiling counts every call. One per run, from
 * newOsvSession(). A call made without one shares nothing, and its ceiling is its own.
 */
export interface OsvSession {
  /** GHSA id -> whether its record lists CWE-506, for every GHSA record read in this run. */
  cwe506: Map<string, boolean>;
  /** Versions whose records were requested (POST /v1/query) in this run: at most MAX_RECORD_QUERIES. */
  queries: number;
  /**
   * Set when a record query failed after its retry with a network error, a timeout, HTTP 429 or a 5xx (OSV, not one
   * version, is the problem): why. No record query starts after it.
   */
  stopped?: string;
}

export const newOsvSession = (): OsvSession => ({ cwe506: new Map(), queries: 0 });

export interface OsvOptions {
  /** The ecosystem of every package in this call. Default "npm". */
  ecosystem?: OsvEcosystem;
  /** The run's shared state. Without one, the call shares nothing with any other. */
  session?: OsvSession;
  fetchImpl?: typeof fetch;
  /** Batches, and record queries, in flight at once. */
  concurrency?: number;
  timeoutMs?: number;
  /** How a record query waits before its retry after HTTP 429 or 503 (see RETRY_WAIT_MS). Default: a timer. */
  sleep?: (ms: number) => Promise<void>;
  /** --on-outage warn: the run's ledger, told of every answer from OSV and given the claim for an outage (see above). */
  outages?: OutageLedger;
}

/** What one call returns: the findings, and the same answers as data, so a caller never parses a finding's key. */
export interface OsvResult {
  findings: Finding[];
  /** The name@version ids with no complete answer from OSV (WS-OS-900), sorted. */
  unchecked: string[];
  /**
   * name@version -> its malicious-package record ids (MAL- ids, and GHSA ids whose record lists CWE-506), in OSV's
   * order, for every version that has at least one. A version whose later page failed, or whose GHSA records were not
   * all read, is here and in `unchecked` too: only a version outside `unchecked` was answered in full.
   */
  records: Map<string, string[]>;
  /** With a ledger: name@version -> the transport failure, for each version this call filed in its outage claim. */
  outages: Map<string, string>;
  /**
   * Notes about this call for the caller to print as they are: "OSV records requested for N version(s) (GHSA
   * classification)" when it requested any, with the ecosystem after a comma when it is not npm ("(GHSA
   * classification, PyPI)"), so two calls' notes in one run differ.
   */
  notes: string[];
}

const QUERYBATCH = "https://api.osv.dev/v1/querybatch";
const QUERY = "https://api.osv.dev/v1/query";
/**
 * Versions whose records are requested (POST /v1/query) per run (per session), at most. Only a version with a GHSA id
 * not yet classified in the run is asked, so this bounds the versions with GitHub advisories a run's lockfiles lock.
 * On 2026-10-08, a 2020-era PyPI lock of 19 versions, tensorflow@2.4.0 among them, had 520 distinct GHSA ids and took
 * 19 queries (5 MB in 7.5 seconds); tensorflow-cpu@2.4.0 and tensorflow-gpu@2.4.0 beside tensorflow@2.4.0 took none,
 * their advisories being tensorflow's. Past it, the versions not asked, in name and version order, are unchecked
 * (WS-OS-900).
 */
export const MAX_RECORD_QUERIES = 1000;
const CEILING = `more than ${MAX_RECORD_QUERIES} versions in this run had GitHub advisories to read, so the rest were not read: run soak on fewer or smaller lockfiles, or run it with --no-osv and check the lockfiles with another OSV client`;
/** The reason of every version not asked after a record query failed after its retry; the failure follows in brackets. */
const STOPPED = "record queries were stopped in this run after one failed";
/**
 * A WS-OS-900 message names at most three distinct reasons. The two that apply to the whole run, the ceiling and the
 * stop after OSV failed, come first, so they are never the ones left out: they say what to do (rules.ts's help quotes
 * the ceiling's).
 */
const runWide = (reason: string): boolean => reason === CEILING || reason.startsWith(STOPPED);
const MAX_QUERIES = 1000;
/** Follow-up requests per batch, or per record query, before giving up on queries that keep returning a page token. */
const MAX_PAGES = 10;
/**
 * Only a registry name and version is sent; anything else is reported unchecked, so it can neither fail a batch
 * nor read as clean. Names follow validate-npm-package-name 7.0.2 for old packages: URL-safe characters only
 * (which also rules out lone surrogates), an optional @scope/, no leading "." "_" or "-", and npm's 214-character
 * limit. Versions are semver (not git, file: or an empty string, which would match every version) of at most
 * node-semver's MAX_LENGTH, 256 characters, so 1000 queries are about 0.5 MB, under OSV's 4 MiB limit.
 */
const NAME = /^(?![._-])(?:@[\w.!~*'()-]+\/(?!\.))?[\w.!~*'()-]+$/;
const MAX_NAME = 214;
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const MAX_VERSION = 256;
/**
 * PyPI: a name of at most 200 characters that matches PEP 508's name rule in lowercase and is already PEP 503-normalised
 * (lowercase, every run of "-", "_" and "." written as one "-"), so "zope.interface" must be sent as "zope-interface".
 * A name in another spelling is reported unchecked rather than sent in a form OSV might not match. A version must be
 * non-empty and in PEP 440's canonical form (the is_canonical regex of PEP 440 Appendix B: no leading "v", no "0!"
 * epoch, "a"/"b"/"rc" pre-releases, ".postN" and ".devN"), optionally followed by a normalised local label: "+" and
 * dot-separated lowercase alphanumeric segments, where an all-digit segment has no leading zero, as packaging prints it
 * ("1.0+01" is "1.0+1"; "1.0+0a" stays). Callers normalise and canonicalise before asking. Versions are capped at 256
 * characters, as npm's are, so a batch stays far under OSV's 4 MiB limit.
 */
const PYPI_NAME = /^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$/;
const MAX_PYPI_NAME = 200;
const pep503 = (name: string): string => name.replace(/[-_.]+/g, "-").toLowerCase();
const PEP440 = /^([1-9][0-9]*!)?(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))*((a|b|rc)(0|[1-9][0-9]*))?(\.post(0|[1-9][0-9]*))?(\.dev(0|[1-9][0-9]*))?(\+(0|[1-9][0-9]*|[0-9]*[a-z][a-z0-9]*)(\.(0|[1-9][0-9]*|[0-9]*[a-z][a-z0-9]*))*)?$/;

/** Which names and versions each ecosystem sends to OSV; anything else is reported unchecked. */
export const OSV_VALID: Record<OsvEcosystem, { name(name: string): boolean; version(version: string): boolean }> = {
  npm: { name: (n) => NAME.test(n) && n.length <= MAX_NAME, version: (v) => SEMVER.test(v) && v.length <= MAX_VERSION },
  PyPI: { name: (n) => n.length <= MAX_PYPI_NAME && PYPI_NAME.test(n) && n === pep503(n), version: (v) => v.length <= MAX_VERSION && PEP440.test(v) },
};

/** The prefix of an ecosystem's finding keys: none for npm (its keys predate PyPI), "pypi:" for PyPI. */
export const osvKeyPrefix = (ecosystem: OsvEcosystem): string => (ecosystem === "npm" ? "" : "pypi:");

/**
 * A record query answered HTTP 429 or 503 waits before its one retry, since a record query that still fails stops every
 * other in the run: Retry-After's delay in seconds (RFC 9110 delay-seconds, digits only), at most MAX_RETRY_WAIT_MS,
 * or RETRY_WAIT_MS when there is none or it is an HTTP date or anything else. One wait per request, so a request
 * (one page of a version's records) takes at most two timeouts and 30 seconds. Query batches retry at once, as before:
 * one that still fails leaves only its own versions unchecked.
 */
const RETRY_WAIT_MS = 2_000;
const MAX_RETRY_WAIT_MS = 30_000;
const retryWait = (retryAfter: string | null): number => (retryAfter !== null && /^\d+$/.test(retryAfter) ? Math.min(Number(retryAfter) * 1000, MAX_RETRY_WAIT_MS) : RETRY_WAIT_MS);
const timer = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** HTTP 400 rejects the whole batch for one bad query, so a rejected batch is halved, at most this many times per batch of 1000. */
const MAX_SPLITS = 32;
const REJECTED = "OSV returned HTTP 400";
/** The host every OSV request goes to, as WS-OS-901, the UNVERIFIED line and the ledger name it; and its root, probed. */
export const OSV_HOST = "api.osv.dev";
const OSV_ROOT = "https://api.osv.dev/";

interface Query {
  package: { name: string; ecosystem: OsvEcosystem };
  version: string;
  page_token?: string;
}

interface Result {
  ids: string[];
  next?: string;
}

/** Anything not in the documented shape is an error, never "no records": a proxy's {} must not read as clean. */
function parseResults(body: unknown, n: number): Result[] | string {
  const results = (body as { results?: unknown } | null)?.results;
  if (!Array.isArray(results) || results.length !== n) return `OSV returned ${Array.isArray(results) ? results.length : "no"} results for ${n} queries`;
  const out: Result[] = [];
  for (const r of results as unknown[]) {
    const { vulns = [], next_page_token: next } = (r ?? {}) as { vulns?: unknown; next_page_token?: unknown };
    if (typeof r !== "object" || r === null || !Array.isArray(vulns) || (next !== undefined && typeof next !== "string")) return "OSV response is not in the documented shape";
    const ids = vulns.map((v) => (v as { id?: unknown } | null)?.id);
    if (!ids.every((id): id is string => typeof id === "string")) return "OSV response has a record without an id";
    out.push({ ids, ...(next ? { next } : {}) });
  }
  return out;
}

/** Why a request has no usable answer, and, when that is an outage (src/net.ts), the transport failure. */
interface Failure {
  error: string;
  outage?: string;
}

/**
 * One POST of a JSON body, retried once on HTTP 429, a 5xx or a network error (a timeout and a body that is not JSON
 * included): the parsed body, or why there is none. `unavailable` marks a failure the retry did not fix; `outage` says
 * the retry failed as an outage: HTTP 429 or a 5xx, or a transport failure before any status line (not a body that
 * is slow, cut off or not JSON). A redirect is not followed. Every other status is an answer, which the ledger hears
 * of. `what` follows "OSV" in the messages. With `wait`, the retry after HTTP 429 or 503 waits first (retryWait).
 */
async function post(url: string, body: unknown, opts: OsvOptions, what = "", wait = false): Promise<{ body: unknown } | (Failure & { unavailable?: boolean })> {
  const f = opts.fetchImpl ?? fetch;
  let error = "";
  let outage: string | undefined;
  for (let attempt = 0; attempt < 2; attempt++) {
    let status = false;
    try {
      outage = undefined;
      const res = await f(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        redirect: "manual",
        signal: AbortSignal.timeout(opts.timeoutMs ?? 60_000),
      });
      status = true;
      if (isTransientStatus(res.status)) {
        error = `OSV returned HTTP ${res.status}${what}`;
        outage = `HTTP ${res.status}`;
        if (wait && attempt === 0 && (res.status === 429 || res.status === 503)) await (opts.sleep ?? timer)(retryWait(res.headers.get("retry-after")));
        continue;
      }
      opts.outages?.answered(OSV_HOST);
      const redirect = redirectProblem(res);
      if (redirect) return { error: `OSV returned ${redirect}${what}` };
      if (!res.ok) return { error: `OSV returned HTTP ${res.status}${what}` };
      return { body: (await res.json()) as unknown };
    } catch (e) {
      error = `request to OSV${what} failed: ${(e as Error).message}`;
      outage = status ? undefined : transportFailure(e);
    }
  }
  return { error, unavailable: true, ...(outage !== undefined ? { outage } : {}) };
}

async function postBatch(queries: Query[], opts: OsvOptions): Promise<Result[] | Failure> {
  const res = await post(QUERYBATCH, { queries }, opts);
  if ("error" in res) return res;
  const results = parseResults(res.body, queries.length);
  return typeof results === "string" ? { error: results } : results;
}

/**
 * A version's records, from POST /v1/query and every page after it: GHSA id -> whether its record lists CWE-506. Any
 * page not in the documented shape, or any GHSA record without a list of CWE ids, is an error for the whole version,
 * never "not malicious".
 */
async function queryRecords(p: OsvPackage, ecosystem: OsvEcosystem, opts: OsvOptions): Promise<{ cwe506: Map<string, boolean> } | (Failure & { unavailable?: boolean })> {
  const cwe506 = new Map<string, boolean>();
  let token: string | undefined;
  for (let page = 0; page <= MAX_PAGES; page++) {
    const res = await post(QUERY, { package: { name: p.name, ecosystem }, version: p.version, ...(token !== undefined ? { page_token: token } : {}) }, opts, " for a version's records", true);
    if ("error" in res) return res;
    const { vulns = [], next_page_token: next } = (res.body ?? {}) as { vulns?: unknown; next_page_token?: unknown };
    if (typeof res.body !== "object" || res.body === null || Array.isArray(res.body) || !Array.isArray(vulns) || (next !== undefined && typeof next !== "string")) return { error: "OSV's records for a version are not in the documented shape" };
    for (const v of vulns as unknown[]) {
      const r = v as { id?: unknown; database_specific?: unknown } | null;
      if (typeof r !== "object" || r === null || typeof r.id !== "string") return { error: "OSV returned a record without an id" };
      if (!r.id.startsWith("GHSA-")) continue;
      const cwes = (r.database_specific as { cwe_ids?: unknown } | null | undefined)?.cwe_ids;
      if (!Array.isArray(cwes) || !cwes.every((c) => typeof c === "string")) return { error: "OSV returned a GHSA record without a list of CWE ids" };
      cwe506.set(r.id, cwes.includes("CWE-506"));
    }
    if (!next) return { cwe506 };
    token = next;
  }
  return { error: `OSV still had more records for a version after ${MAX_PAGES} follow-up requests` };
}

export async function checkOsv(packages: OsvPackage[], opts: OsvOptions = {}): Promise<Finding[]> {
  return (await checkOsvDetailed(packages, opts)).findings;
}

export async function checkOsvDetailed(packages: OsvPackage[], opts: OsvOptions = {}): Promise<OsvResult> {
  const ecosystem = opts.ecosystem ?? "npm";
  const valid = OSV_VALID[ecosystem];
  const prefix = osvKeyPrefix(ecosystem);
  const unchecked = new Map<string, string>();
  /** name@version -> the transport failure, when its query batch failed as an outage. */
  const outageOf = new Map<string, string>();
  const toQuery = new Map<string, OsvPackage>();
  for (const p of packages) {
    const id = `${p.name}@${p.version}`;
    if (!valid.name(p.name) || !valid.version(p.version)) unchecked.set(id, "not a registry name and version");
    else toQuery.set(id, p);
  }

  /** name@version -> every record id OSV returned for it, from every page, in OSV's order. */
  const returned = new Map<string, Set<string>>();
  const answered = new Set<string>();
  const all = [...toQuery.values()];
  const batches = Array.from({ length: Math.ceil(all.length / MAX_QUERIES) }, (_, i) => all.slice(i * MAX_QUERIES, (i + 1) * MAX_QUERIES));
  type Pending = { p: OsvPackage; token?: string }[];
  const run = async (pending: Pending, page: number, budget: { splits: number }): Promise<void> => {
    if (pending.length === 0) return;
    const results = page > MAX_PAGES ? { error: `OSV still had more results after ${MAX_PAGES} follow-up requests` } : await postBatch(pending.map(({ p, token }) => ({ package: { name: p.name, ecosystem }, version: p.version, ...(token ? { page_token: token } : {}) })), opts);
    if (!Array.isArray(results) && results.error === REJECTED && pending.length > 1 && budget.splits-- > 0) {
      const half = Math.ceil(pending.length / 2);
      await run(pending.slice(0, half), page, budget);
      return run(pending.slice(half), page, budget);
    }
    if (!Array.isArray(results)) {
      for (const { p } of pending) unchecked.set(`${p.name}@${p.version}`, results.error);
      if (results.outage !== undefined) for (const { p } of pending) outageOf.set(`${p.name}@${p.version}`, results.outage);
      return;
    }
    const again: Pending = [];
    results.forEach((r, i) => {
      const p = (pending[i] as Pending[number]).p;
      const id = `${p.name}@${p.version}`;
      for (const v of r.ids) returned.set(id, (returned.get(id) ?? new Set()).add(v));
      if (r.next) again.push({ p, token: r.next });
      else answered.add(id);
    });
    return run(again, page + 1, budget);
  };
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < batches.length) await run((batches[next++] as OsvPackage[]).map((p) => ({ p })), 0, { splits: MAX_SPLITS });
  };
  await Promise.all(Array.from({ length: Math.min(opts.concurrency ?? 4, Math.max(batches.length, 1)) }, worker));
  // Whatever went wrong above (a concurrency of 0 starts no worker), a package with no complete answer is not clean.
  for (const id of toQuery.keys()) if (!answered.has(id) && !unchecked.has(id)) unchecked.set(id, "OSV was not asked");

  // A version's records are read with one query when it has a GHSA id that the run has not classified and that no
  // version before it, in name and version order, will read. The queries go out in that order while the run is under its
  // ceiling and no query has been unavailable.
  const session = opts.session ?? newOsvSession();
  const ghsaOf = (id: string): string[] => [...(returned.get(id) ?? [])].filter((v) => v.startsWith("GHSA-"));
  /** GHSA id -> the version whose query reads it. */
  const reader = new Map<string, string>();
  const plan: OsvPackage[] = [];
  for (const p of [...toQuery.values()].sort((x, y) => (x.name === y.name ? (x.version < y.version ? -1 : 1) : x.name < y.name ? -1 : 1))) {
    const id = `${p.name}@${p.version}`;
    const unread = ghsaOf(id).filter((g) => !session.cwe506.has(g) && !reader.has(g));
    if (unread.length === 0) continue;
    plan.push(p);
    for (const g of unread) reader.set(g, id);
  }
  /** name@version -> why its own records were not read in full. */
  const failed = new Map<string, string>();
  let sent = 0;
  let nextQuery = 0;
  const queryWorker = async (): Promise<void> => {
    while (nextQuery < plan.length) {
      const p = plan[nextQuery++] as OsvPackage;
      const id = `${p.name}@${p.version}`;
      if (session.stopped !== undefined) {
        failed.set(id, `${STOPPED} (${session.stopped})`);
        continue;
      }
      if (session.queries >= MAX_RECORD_QUERIES) {
        failed.set(id, CEILING);
        continue;
      }
      session.queries++;
      sent++;
      const answer = await queryRecords(p, ecosystem, opts);
      if ("error" in answer) {
        failed.set(id, answer.error);
        if (answer.unavailable) session.stopped ??= answer.error;
        continue;
      }
      for (const [g, malicious] of answer.cwe506) session.cwe506.set(g, malicious);
      if (ghsaOf(id).some((g) => !answer.cwe506.has(g))) failed.set(id, "OSV's records for a version left out a GHSA record its query batch answer had");
    }
  };
  await Promise.all(Array.from({ length: Math.min(opts.concurrency ?? 4, Math.max(plan.length, 1)) }, queryWorker));

  // A hit is a MAL- record or a GHSA record listing CWE-506. A version whose own query failed, or with a GHSA id that has
  // no CWE ids read for it (another version's query failed, or none was sent), is unchecked.
  const malicious = new Map<string, string[]>();
  for (const [id, ids] of returned) {
    const hits: string[] = [];
    for (const v of ids) {
      const cwe506 = v.startsWith("GHSA-") ? session.cwe506.get(v) : undefined;
      if (v.startsWith("GHSA-") && cwe506 === undefined && !unchecked.has(id)) unchecked.set(id, failed.get(id) ?? failed.get(reader.get(v) ?? "") ?? "a GHSA record of it was not read");
      if (v.startsWith("MAL-") || cwe506 === true) hits.push(v);
    }
    const why = failed.get(id);
    if (why !== undefined && !unchecked.has(id)) unchecked.set(id, why);
    if (hits.length > 0) malicious.set(id, hits);
  }

  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const p of packages) {
    const id = `${p.name}@${p.version}`;
    for (const mal of malicious.get(id) ?? []) {
      const why = mal.startsWith("GHSA-") ? " (a GitHub advisory with CWE-506, embedded malicious code)" : "";
      const f = makeFinding({ ruleId: "WS-OS-001", severity: "critical", message: `${id} is a malicious package version according to OSV record ${mal}${why}`, file: p.file, key: `${prefix}${id} ${mal}`, source: `https://osv.dev/vulnerability/${mal}` });
      if (!seen.has(f.fingerprint)) findings.push(f);
      seen.add(f.fingerprint);
    }
  }
  const ids = [...unchecked.keys()].sort();
  /** WS-OS-900 for these versions, worded and keyed as it always is: none for none. */
  const notChecked = (left: string[]): Finding[] => {
    if (left.length === 0) return [];
    // In the order the reasons arose, as the message has always listed them.
    const keep = new Set(left);
    const distinct = [...new Set([...unchecked].filter(([id]) => keep.has(id)).map(([, reason]) => reason))];
    const reasons = [...distinct.filter(runWide), ...distinct.filter((r) => !runWide(r))].slice(0, 3).join("; ");
    return [
      makeFinding({
        ruleId: "WS-OS-900",
        severity: "high",
        message: `${left.length} package version(s) could not be checked against OSV for malicious-package records (${reasons}): ${left.slice(0, 10).join(", ")}${left.length > 10 ? ", ..." : ""}`,
        // The exact set that went unchecked: a baseline entry approving one git dependency stops matching when anything else fails.
        key: `${prefix}${left.join(" ")}`,
      }),
    ];
  };
  // --on-outage warn: the versions whose batch failed as an outage go to the ledger as one claim. Its fail-closed
  // side is this call's WS-OS-900 exactly as without the option; its warn side is WS-OS-901 per version and lockfile,
  // and WS-OS-900 for every other unchecked version.
  const outages = new Map([...outageOf].filter(([id]) => unchecked.has(id)));
  if (opts.outages && outages.size > 0) {
    const warn: Finding[] = [];
    const filed = new Set<string>();
    for (const p of packages) {
      const id = `${p.name}@${p.version}`;
      const outage = outages.get(id);
      if (outage === undefined) continue;
      const f = makeFinding({
        ruleId: "WS-OS-901",
        severity: "medium",
        message: `${id}${ecosystem === "npm" ? "" : ` (${ecosystem})`} was not checked against OSV for malicious-package records: ${OSV_HOST} unreachable: ${outage}. --on-outage warn reports it at medium; by default it fails closed (WS-OS-900, high)`,
        file: p.file,
        key: `${prefix}${id}`,
      });
      if (!filed.has(f.fingerprint)) warn.push(f);
      filed.add(f.fingerprint);
    }
    warn.push(...notChecked(ids.filter((id) => !outages.has(id))));
    opts.outages.claim({ host: OSV_HOST, probe: OSV_ROOT, failClosed: notChecked(ids), warn, unverified: [...outages].map(([id, error]) => ({ host: OSV_HOST, error, id: `${ecosystem}:${id}` })) });
  } else {
    findings.push(...notChecked(ids));
  }
  return { findings, unchecked: ids, records: malicious, outages: opts.outages ? outages : new Map(), notes: sent > 0 ? [`OSV records requested for ${sent} version(s) (GHSA classification${ecosystem === "npm" ? "" : `, ${ecosystem}`})`] : [] };
}
