/**
 * The PyPI Simple API client: one GET per project, in the JSON form (PEP 691), read for per-file upload times
 * (PEP 700), hashes, yanked flags (PEP 592) and the project status (PEP 792). The index is the witness soak's layer 2
 * trusts, so the request and the response are both pinned down, and anything unexpected is an error for that
 * project, never an empty answer:
 * - GET <index>/<normalised name>/ with `Accept: application/vnd.pypi.simple.v1+json` and
 *   `User-Agent: wormsign/<version> (+https://github.com/stgllghr/wormsign)`; only a name already in PEP 503 normal
 *   form is put in a URL. At most CONCURRENCY requests at once (PyPI asks clients to keep them few), one per project
 *   per run (cached).
 * - Redirects are not followed by fetch (`redirect: "manual"`): a redirect to the index's own origin is followed, at
 *   most MAX_REDIRECTS times; one to another origin is an error, so the index cannot hand the question to a host the
 *   user did not name.
 * - 404 is NOT_FOUND, "not on the index (deleted or quarantined), or never published", soak's wording for a
 *   locked hash the index does not list too: PyPI serves the same 404 for a deleted project as for one that never
 *   existed (research 2026-10-08). HTTP 429 and 5xx, and a network error, are retried once.
 * - The response's Content-Type must be the JSON Simple type, `meta.api-version` must be 1.1 or a later 1.x (upload
 *   times are PEP 700, API 1.1; a later major version is not understood), and `name` must be the name asked for.
 * - Each file's `upload-time` must match UPLOAD_TIME (PEP 700's format; PyPI gives 6 fractional digits); otherwise the
 *   file has no upload time and cannot be aged. Each file's version comes from its file name (filenames.ts), never
 *   from the index's `versions` list.
 * - `project-status` is read from the top-level object PEP 792 and PyPI use, or from flat strings in `meta` (the shape
 *   the Simple API specification's own example shows); absent means active; any other shape or value is "unknown".
 *   A quarantined project's files are hidden by PyPI (warehouse source, not observed live).
 * - Bodies over MAX_SIMPLE_BYTES are refused while reading.
 */
import { readFileSync } from "node:fs";
import { parseDistFilename, type FileNameInfo } from "./filenames.js";
import { isNormalizedName } from "./names.js";
import { versionsEqual } from "./pep440.js";
import { isTransientStatus, transportFailure } from "../net.js";
import type { OutageLedger } from "../net.js";
import { stripUserinfo } from "../url.js";

export const SIMPLE_JSON = "application/vnd.pypi.simple.v1+json";
/** PEP 700's upload-time format, with the fractional digits optional (PyPI gives 6 or none). */
export const UPLOAD_TIME = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,6})?Z$/;
/** The largest response read. PyPI's largest project pages are a few megabytes. */
export const MAX_SIMPLE_BYTES = 64 * 1024 * 1024;
export const MAX_REDIRECTS = 3;
export const CONCURRENCY = 2;
export const NOT_FOUND = "not on the index (deleted or quarantined), or never published";
const REDIRECTS = new Set([301, 302, 303, 307, 308]);

const VERSION: string = (() => {
  try {
    return (JSON.parse(readFileSync(new URL("../../../package.json", import.meta.url), "utf8")) as { version?: unknown }).version as string;
  } catch {
    return "unknown";
  }
})();

/** The User-Agent soak sends to the index: PyPI asks API clients for a unique one with a contact. */
export function userAgent(version: string = VERSION): string {
  return `wormsign/${version} (+https://github.com/stgllghr/wormsign)`;
}

/**
 * An index URL in the one form compared: scheme, host (and a non-default port) and path without trailing slashes,
 * lowercase scheme and host, no credentials, query or fragment. undefined when it is not an http(s) URL, or when it has
 * a query or fragment (an index URL has neither; such a URL is never equal to another).
 */
export function normalizeIndexUrl(raw: string): string | undefined {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return undefined;
  }
  if ((u.protocol !== "https:" && u.protocol !== "http:") || u.search !== "" || u.hash !== "") return undefined;
  return `${u.protocol}//${u.host}${u.pathname.replace(/\/+$/, "")}`;
}

/**
 * The origin an index serves its files from, as `<scheme>://<host>`: https://files.pythonhosted.org for pypi.org (its
 * Simple pages link there), else the index's own origin. Undefined when the index is not a URL normalizeIndexUrl takes.
 */
export function indexFileOrigin(index: string): string | undefined {
  const n = normalizeIndexUrl(index);
  if (n === undefined) return undefined;
  const u = new URL(n);
  return u.hostname === "pypi.org" ? "https://files.pythonhosted.org" : u.origin;
}

/**
 * A URL as messages and notes show it: without user name or password, whether the URL parser finds them or not (a URL
 * it refuses, such as one with a port out of range, or one it reads without userinfo, such as `git+ssh:user:token@host`,
 * still loses what looks like userinfo: src/url.ts stripUserinfo). Cut to 300 characters, or 200 when it is not a URL.
 */
export function displayUrl(raw: string): string {
  let shown = raw;
  let parsed = true;
  try {
    const u = new URL(raw);
    if (u.username !== "" || u.password !== "") {
      u.username = "";
      u.password = "";
      shown = u.href;
    }
  } catch {
    parsed = false;
  }
  shown = stripUserinfo(shown);
  const max = parsed ? 300 : 200;
  return shown.length > max ? `${shown.slice(0, max)}...` : shown;
}

/**
 * A lock's file URL names the index's file: it is the index's URL for the file (IndexFile.url, the WHATWG serialisation
 * of what the index gave) character for character, with or without the index's own fragment. Nothing on the lock's
 * side is normalised, because installers do not parse URLs alike: pip 26.2.1 rebuilds a download URL with Python's
 * urlsplit (network/auth.py), so `https://files.pythonhosted.org\@evil.example/../packages/...`, which WHATWG (Node,
 * uv) serialises to the files.pythonhosted.org URL, sends pip's request to evil.example. uv 0.10.9 and 0.12.21 and
 * pip 26.2.1 write PyPI's file URLs back unchanged (every lock in test/fixtures/python), so this refuses none of them.
 */
export function sameFileUrl(lockUrl: string, indexUrl: string | undefined): boolean {
  if (indexUrl === undefined) return false;
  const hash = indexUrl.indexOf("#");
  return lockUrl === indexUrl || (hash !== -1 && lockUrl === indexUrl.slice(0, hash));
}

export type ProjectState = "active" | "archived" | "deprecated" | "quarantined";
export const PROJECT_STATES: readonly ProjectState[] = ["active", "archived", "deprecated", "quarantined"];

export type ProjectStatus =
  /** `given`: the index stated it (absent means active). */
  | { state: ProjectState; reason?: string; given: boolean }
  | { state: "unknown"; value: string };

export interface IndexFile {
  filename: string;
  /** Absolute: resolved against the response's URL (PEP 691 allows relative URLs). */
  url?: string;
  /** Lowercase hex, when the index gives a well-formed one. */
  sha256?: string;
  /** PEP 700 upload time, only when it matches UPLOAD_TIME and is a real instant. */
  uploadTime?: string;
  /** Why the upload time is missing, when it is. */
  uploadTimeProblem?: string;
  yanked: boolean;
  yankedReason?: string;
  /** The project and version its file name states (undefined: not a wheel or sdist name, or ambiguous). */
  dist?: FileNameInfo;
}

export interface IndexProject {
  name: string;
  apiVersion: string;
  status: ProjectStatus;
  files: IndexFile[];
  /** The URL the response came from (after same-origin redirects). */
  url: string;
}

/**
 * `outage`, with `error`: the retry's failure was an outage (src/net.ts), HTTP 429 or a 5xx, or a transport failure
 * before any status line (not a body that is slow, cut off or unreadable, nor a redirect hop's failure).
 */
export type ProjectFetch = { project: IndexProject } | { notFound: string } | { error: string; outage?: string };

type Json = Record<string, unknown>;
const isObject = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);
const own = (o: Json, k: string): unknown => (Object.hasOwn(o, k) ? o[k] : undefined);
const show = (v: unknown): string => {
  const s = typeof v === "string" ? JSON.stringify(v) : (JSON.stringify(v) ?? String(v));
  return s.length > 120 ? `${s.slice(0, 120)}...` : s;
};

/** A PEP 700 upload time, or why it is not one. */
export function readUploadTime(v: unknown): { time: string } | { problem: string } {
  if (v === undefined) return { problem: "the index gives no upload-time for it (PEP 700)" };
  if (typeof v !== "string" || !UPLOAD_TIME.test(v)) return { problem: `the index's upload-time ${show(v)} is not in PEP 700's format` };
  const t = Date.parse(v);
  // A calendar date that does not exist (2024-02-31) parses to another day, or not at all.
  if (!Number.isFinite(t) || new Date(t).toISOString().slice(0, 19) !== v.slice(0, 19)) return { problem: `the index's upload-time ${show(v)} is not a real date and time` };
  return { time: v };
}

function readStatus(body: Json, meta: Json): ProjectStatus {
  const top = own(body, "project-status");
  const flat = own(meta, "project-status");
  const found: { state: string; reason?: string }[] = [];
  if (top !== undefined) {
    if (!isObject(top) || typeof own(top, "status") !== "string") return { state: "unknown", value: `project-status ${show(top)}` };
    const reason = own(top, "reason");
    found.push({ state: own(top, "status") as string, ...(typeof reason === "string" ? { reason } : {}) });
  }
  if (flat !== undefined) {
    if (typeof flat !== "string") return { state: "unknown", value: `meta.project-status ${show(flat)}` };
    const reason = own(meta, "project-status-reason");
    found.push({ state: flat, ...(typeof reason === "string" ? { reason } : {}) });
  }
  if (found.length === 0) return { state: "active", given: false };
  if (found.length === 2 && found[0]!.state !== found[1]!.state) return { state: "unknown", value: `${show(found[0]!.state)} at the top level and ${show(found[1]!.state)} in meta` };
  const s = found[0]!;
  if (!(PROJECT_STATES as readonly string[]).includes(s.state)) return { state: "unknown", value: show(s.state) };
  return { state: s.state as ProjectState, ...(s.reason !== undefined ? { reason: s.reason } : {}), given: true };
}

/** Interprets a Simple JSON project response. Anything outside the documented shape is an error, never "no files". */
export function parseSimpleProject(body: unknown, name: string, responseUrl: string): { project: IndexProject } | { error: string } {
  if (!isObject(body)) return { error: "the index's response is not a JSON object" };
  const meta = own(body, "meta");
  if (!isObject(meta)) return { error: "the index's response has no meta object" };
  const api = own(meta, "api-version");
  const m = typeof api === "string" ? /^(\d+)\.(\d+)$/.exec(api) : null;
  if (!m || m[1] !== "1" || Number(m[2]) < 1) return { error: `the index's API version ${show(api)} is not 1.1 or a later 1.x, so it may not give upload times (PEP 700)` };
  if (own(body, "name") !== name) return { error: `the index answered for project ${show(own(body, "name"))}, not ${JSON.stringify(name)}` };
  const raw = own(body, "files");
  if (!Array.isArray(raw)) return { error: "the index's response has no files list" };
  const files: IndexFile[] = [];
  for (const [i, f] of raw.entries()) {
    const bad = (what: string): { error: string } => ({ error: `file #${i + 1} in the index's response ${what}` });
    if (!isObject(f)) return bad("is not an object");
    const filename = own(f, "filename");
    if (typeof filename !== "string" || filename === "" || filename.includes("/") || filename.includes("\\")) return bad("has no valid filename");
    const hashes = own(f, "hashes");
    if (!isObject(hashes)) return bad(`(${filename}) has no hashes object`);
    const yanked = own(f, "yanked") ?? false;
    if (typeof yanked !== "boolean" && typeof yanked !== "string") return bad(`(${filename}) has a yanked value that is neither a boolean nor a reason`);
    const out: IndexFile = { filename, yanked: yanked !== false };
    if (typeof yanked === "string") out.yankedReason = yanked;
    const url = own(f, "url");
    if (url !== undefined) {
      if (typeof url !== "string") return bad(`(${filename}) has a url that is not a string`);
      try {
        out.url = new URL(url, responseUrl).href;
      } catch {
        return bad(`(${filename}) has a url that is not a URL`);
      }
    }
    const sha = own(hashes, "sha256");
    if (typeof sha === "string" && /^[0-9a-fA-F]{64}$/.test(sha)) out.sha256 = sha.toLowerCase();
    const t = readUploadTime(own(f, "upload-time"));
    if ("time" in t) out.uploadTime = t.time;
    else out.uploadTimeProblem = t.problem;
    const dist = parseDistFilename(filename, name);
    if (dist) out.dist = dist;
    files.push(out);
  }
  return { project: { name, apiVersion: api as string, status: readStatus(body, meta), files, url: responseUrl } };
}

/** The files of one release: the index's files whose file name states this project and (PEP 440-equal) version. */
export function releaseFiles(project: IndexProject, name: string, version: string): IndexFile[] {
  return project.files.filter((f) => f.dist !== undefined && f.dist.name === name && versionsEqual(f.dist.version, version));
}

export type Binding = { file: IndexFile } | { problem: string };

/**
 * The index file a locked sha256 belongs to: a file of this project and this version (PEP 440 equality, from its file
 * name) with that sha256. When several are, the youngest (an absent upload time counts as youngest), so the age is
 * never overstated. Otherwise the reason, in soak's wording.
 */
export function bindLockedFile(project: IndexProject, name: string, version: string, sha256: string): Binding {
  const digest = sha256.toLowerCase();
  const withHash = project.files.filter((f) => f.sha256 === digest);
  if (withHash.length === 0) return { problem: NOT_FOUND };
  const ours = withHash.filter((f) => f.dist !== undefined && f.dist.name === name && versionsEqual(f.dist.version, version));
  if (ours.length === 0) return { problem: `locked hash belongs to ${withHash[0]!.filename}, not to a file of ${name} ${version}` };
  const youngest = ours.reduce((a, b) => (a.uploadTime === undefined ? a : b.uploadTime === undefined ? b : Date.parse(b.uploadTime) > Date.parse(a.uploadTime) ? b : a));
  return { file: youngest };
}

export interface IndexClientOptions {
  /** The index URL (--pypi-index), e.g. https://pypi.org/simple/. */
  index: string;
  fetchImpl?: typeof fetch;
  /** Requests in flight at once; default CONCURRENCY. */
  concurrency?: number;
  userAgent?: string;
  timeoutMs?: number;
  /** --on-outage warn: the run's ledger, told of every answer from the index (any status but 429 and the 5xx). */
  outages?: OutageLedger;
}

export interface IndexClient {
  /** The project's page, fetched at most once per client. Never rejects. */
  project(name: string): Promise<ProjectFetch>;
  /** HTTP requests made so far (redirects and retries count). */
  readonly requests: number;
}

/** Reads a body of at most `max` bytes as UTF-8, refusing a larger one as soon as it is seen. */
async function readCapped(res: Response, max: number): Promise<{ text: string } | { error: string }> {
  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > max) return { error: `the index's response is larger than ${max / 1024 / 1024} MiB` };
  const chunks: Uint8Array[] = [];
  let total = 0;
  if (res.body) {
    const reader = res.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > max) {
        // Not awaited: cancelling one branch of a teed body settles only when the other is cancelled too.
        reader.cancel().catch(() => undefined);
        return { error: `the index's response is larger than ${max / 1024 / 1024} MiB` };
      }
      chunks.push(value);
    }
  }
  try {
    return { text: new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)) };
  } catch {
    return { error: "the index's response is not valid UTF-8" };
  }
}

export function createIndexClient(opts: IndexClientOptions): IndexClient {
  const f = opts.fetchImpl ?? fetch;
  const ua = opts.userAgent ?? userAgent();
  const timeoutMs = opts.timeoutMs ?? 30_000;
  const limit = Math.max(1, opts.concurrency ?? CONCURRENCY);
  const cache = new Map<string, Promise<ProjectFetch>>();
  let requests = 0;
  let active = 0;
  const waiting: (() => void)[] = [];
  const slot = async (): Promise<void> => {
    if (active < limit) {
      active++;
      return;
    }
    await new Promise<void>((resolve) => waiting.push(resolve));
  };
  const release = (): void => {
    const next = waiting.shift();
    if (next) next();
    else active--;
  };

  const base = normalizeIndexUrl(opts.index);
  let credentials = false;
  try {
    const u = new URL(opts.index);
    credentials = u.username !== "" || u.password !== "";
  } catch {
    // reported below as not a URL
  }

  const get = async (name: string): Promise<ProjectFetch> => {
    if (credentials) return { error: "the index URL carries credentials, which wormsign never sends" };
    if (base === undefined) return { error: `the index URL ${JSON.stringify(displayUrl(opts.index))} is not an http(s) URL without query or fragment` };
    if (!isNormalizedName(name)) return { error: `${JSON.stringify(name)} is not a normalised project name, so it is not put in a URL` };
    const start = `${base}/${name}/`;
    const origin = new URL(start).origin;
    for (let attempt = 0; attempt < 2; attempt++) {
      let status = false;
      try {
        let url = start;
        let res: Response;
        for (let hops = 0; ; hops++) {
          requests++;
          res = await f(url, { headers: { accept: SIMPLE_JSON, "user-agent": ua }, redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
          if (typeof res !== "object" || res === null || typeof res.status !== "number" || typeof res.headers?.get !== "function") return { error: "the request to the index returned something that is not an HTTP response" };
          status = true;
          if (!isTransientStatus(res.status)) opts.outages?.answered(new URL(url).host);
          if (!REDIRECTS.has(res.status)) break;
          const location = res.headers.get("location");
          if (location === null) return { error: `the index answered HTTP ${res.status} with no Location` };
          let next: URL;
          try {
            next = new URL(location, url);
          } catch {
            return { error: `the index redirected to ${show(location)}, which is not a URL` };
          }
          if (next.origin !== origin) return { error: `the index redirected to ${next.origin}, another origin, which wormsign does not follow` };
          if (hops + 1 > MAX_REDIRECTS) return { error: `the index redirected more than ${MAX_REDIRECTS} times` };
          url = next.href;
        }
        if (res.status === 404) return { notFound: NOT_FOUND };
        if (isTransientStatus(res.status)) {
          if (attempt === 0) continue;
          return { error: `the index returned HTTP ${res.status}`, outage: `HTTP ${res.status}` };
        }
        if (res.status !== 200) return { error: `the index returned HTTP ${res.status}${res.status === 401 || res.status === 403 ? " (wormsign sends no credentials)" : ""}` };
        const type = (res.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase();
        if (type !== SIMPLE_JSON) return { error: `the index answered with content type ${type === "" ? "(none)" : JSON.stringify(type)}, not ${SIMPLE_JSON} (PEP 691's JSON form)` };
        const text = await readCapped(res, MAX_SIMPLE_BYTES);
        if ("error" in text) return text;
        let body: unknown;
        try {
          body = JSON.parse(text.text);
        } catch {
          return { error: "the index's response is not valid JSON" };
        }
        return parseSimpleProject(body, name, url);
      } catch (e) {
        if (attempt === 1) {
          const outage = status ? undefined : transportFailure(e);
          return { error: `the request to the index failed: ${String((e as Error)?.message ?? e).slice(0, 160)}`, ...(outage !== undefined ? { outage } : {}) };
        }
      }
    }
    return { error: "the request to the index failed" };
  };

  return {
    project(name: string): Promise<ProjectFetch> {
      let p = cache.get(name);
      if (!p) {
        p = (async () => {
          await slot();
          try {
            return await get(name);
          } catch (e) {
            return { error: `the request to the index failed: ${String((e as Error)?.message ?? e).slice(0, 160)}` };
          } finally {
            release();
          }
        })();
        cache.set(name, p);
      }
      return p;
    },
    get requests() {
      return requests;
    },
  };
}
