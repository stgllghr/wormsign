import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { MAX_IOC_FILE_BYTES, bundledIocDir, loadIocDir, parseIocs, staleReason, userIocDir } from "./iocs.js";
import type { IocSet } from "./iocs.js";
import { UsageError } from "./types.js";
import { redactUrl, redirectProblem } from "./url.js";

export const DEFAULT_IOC_URL = "https://raw.githubusercontent.com/stgllghr/wormsign/main/data/iocs/";
const FILES = ["packages", "files", "workflows", "repos", "endpoints"] as const;

/** The body as text, refusing more than MAX_IOC_FILE_BYTES whether or not the server declares a length. */
async function boundedText(res: Response, where: string): Promise<string> {
  const tooBig = (n: number) => new UsageError(`${where} is larger than the ${MAX_IOC_FILE_BYTES} bytes wormsign accepts for an IOC file (${n} bytes)`);
  const declared = Number(res.headers.get("content-length") ?? "");
  if (declared > MAX_IOC_FILE_BYTES) throw tooBig(declared);
  const chunks: Uint8Array[] = [];
  let n = 0;
  const reader = res.body?.getReader();
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      n += value.byteLength;
      if (n > MAX_IOC_FILE_BYTES) {
        await reader.cancel();
        throw tooBig(n);
      }
      chunks.push(value);
    }
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}

/**
 * Downloads the five IOC files and validates them (every entry must carry a source
 * URL, all five must share one real date as their version, not after tomorrow).
 * Data dated after the bundled data replaces the local cache, whatever the cache's
 * own date, and scans then add its IOCs to the bundled ones. Older data, or data of
 * the same date and content, is already in this release, so nothing is written
 * (`written: false`), which is not an error. A bad or partial download leaves the
 * previous cache untouched. The download is trusted as much as the repository it
 * comes from: there is no signature, so pin `--url` to a commit to fix what you get.
 */
export async function updateIocs(baseUrl: string, dir = userIocDir(), fetchImpl: typeof fetch = fetch, now = new Date()): Promise<IocSet & { written: boolean }> {
  if (!baseUrl.startsWith("https://")) throw new UsageError("IOC update URL must use https");
  // Credentials in the URL would be printed in every note and error (and fetch refuses such a URL anyway).
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(baseUrl);
  } catch {
    throw new UsageError(`invalid IOC update URL ${redactUrl(baseUrl)}`);
  }
  if (parsedUrl.username || parsedUrl.password) throw new UsageError(`the IOC update URL must not contain credentials (user:password@): ${redactUrl(baseUrl)}`);
  const base = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  const shown = redactUrl(base);
  const texts = {} as Record<(typeof FILES)[number], string>;
  const parsed = {} as Record<(typeof FILES)[number], unknown>;
  for (const f of FILES) {
    let res: Response;
    try {
      // "manual": a redirect is refused below, never followed to a plain-http or other host the messages would not name.
      res = await fetchImpl(`${base}${f}.json`, { redirect: "manual", signal: AbortSignal.timeout(60_000) });
    } catch (e) {
      throw new UsageError(`cannot download ${shown}${f}.json: ${(e as Error).message}`);
    }
    const redirect = redirectProblem(res);
    if (redirect) throw new UsageError(`${shown}${f}.json: ${redirect}; pass the final https URL with --url`);
    if (!res.ok) {
      const hint = res.status === 404 && base === DEFAULT_IOC_URL ? " from the default source (this repository's main branch); pass --url <https directory holding the five IOC files>" : "";
      throw new UsageError(`${shown}${f}.json: HTTP ${res.status}${hint}`);
    }
    texts[f] = await boundedText(res, `${shown}${f}.json`);
    try {
      parsed[f] = JSON.parse(texts[f]);
    } catch {
      throw new UsageError(`${shown}${f}.json is not valid JSON`);
    }
  }
  const iocs = parseIocs(parsed);
  if (iocs.version === undefined) throw new UsageError(`refusing the IOC data at ${shown}: it has no version`);
  // A cache newer than every later release would never be superseded by one.
  const tomorrow = new Date(now.getTime() + 86_400_000).toISOString().slice(0, 10);
  if (iocs.version > tomorrow) throw new UsageError(`refusing the IOC data at ${shown}: its version ${iocs.version} is in the future`);
  const bundled = loadIocDir(bundledIocDir);
  // isDeepStrictEqual ignores key order, so a reformatted copy of the same data is not "different content".
  const sameAsBundled = (f: (typeof FILES)[number]) => isDeepStrictEqual(parsed[f], JSON.parse(readFileSync(join(bundledIocDir, `${f}.json`), "utf8")));
  if (iocs.version === bundled.version && !FILES.every(sameAsBundled)) {
    throw new UsageError(`refusing the IOC data at ${shown}: same version ${iocs.version} as the bundled data but different content; the source must bump "version"`);
  }
  if (staleReason(iocs, bundled)) {
    iocs.notes.push(`bundled IOC data ${bundled.version} is already current (${shown} has ${iocs.version}); cache not written`);
    return { ...iocs, written: false };
  }
  iocs.notes.push(`IOC data ${iocs.version} from ${shown} written to ${dir}`);
  mkdirSync(dir, { recursive: true });
  for (const f of FILES) {
    const tmp = join(dir, `.${f}.json.tmp`);
    writeFileSync(tmp, texts[f]);
    renameSync(tmp, join(dir, `${f}.json`));
  }
  return { ...iocs, written: true };
}
