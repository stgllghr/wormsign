#!/usr/bin/env node
// Maintainer tool (not shipped, not run by the scanner): measures how long each
// compromised version in data/iocs/packages.json was on the npm registry before a
// public malware advisory listed it. This is the evidence behind the default soak
// time. Usage:
//   node scripts/soak-latency.mjs [--iocs data/iocs/packages.json] [--out soak-out] [--cache soak-out/cache] [--concurrency 4]
// Reads public metadata only: registry.npmjs.org packuments, api.osv.dev and the
// GitHub advisory API (GITHUB_TOKEN / GH_TOKEN, else the `gh` CLI's login). It
// never downloads a tarball or runs a package.
/* global fetch, setTimeout */
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs, promisify } from "node:util";

const { values: opt } = parseArgs({
  options: {
    iocs: { type: "string", default: fileURLToPath(new URL("../data/iocs/packages.json", import.meta.url)) },
    out: { type: "string", default: "soak-out" },
    cache: { type: "string" },
    concurrency: { type: "string", default: "4" },
  },
});
const HOUR = 3600e3;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
mkdirSync(opt.out, { recursive: true });
if (opt.cache) mkdirSync(opt.cache, { recursive: true });

// ---- HTTP with retry (429, 5xx, GitHub rate limits) and an optional disk cache.
async function cached(id, load) {
  const file = opt.cache && join(opt.cache, createHash("sha1").update(id).digest("hex") + ".json");
  if (file && existsSync(file)) return JSON.parse(readFileSync(file, "utf8"));
  const value = await load();
  if (file) writeFileSync(file, JSON.stringify(value));
  return value;
}
const getJson = (url, init = {}, keep = (x) => x) => cached(url + (init.body ?? ""), async () => {
  for (let attempt = 0; ; attempt++) {
    const res = await fetch(url, init);
    await sleep(100); // be polite: at most ~10 requests/s per worker
    if (res.ok || res.status === 404) return res.status === 404 ? null : keep(await res.json());
    const h = (k) => res.headers.get(k);
    const exhausted = h("x-ratelimit-remaining") === "0";
    const retryable = res.status === 429 || res.status >= 500 || (res.status === 403 && (exhausted || h("retry-after")));
    if (!retryable || attempt >= 6) throw new Error(`HTTP ${res.status} for ${url}`);
    await sleep(exhausted ? Number(h("x-ratelimit-reset")) * 1000 - Date.now() + 1000 : Number(h("retry-after")) * 1000 || 2 ** attempt * 1000);
  }
});

async function pool(items, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Number(opt.concurrency) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  }));
  return out;
}

const osvFor = ({ name, version }) => getJson("https://api.osv.dev/v1/query", {
  method: "POST",
  body: JSON.stringify({ package: { ecosystem: "npm", name }, version }),
});
const ghToken = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
const run = promisify(execFile);
function ghsaFor({ name, version }) {
  const path = `/advisories?type=malware&ecosystem=npm&per_page=100&affects=${encodeURIComponent(`${name}@${version}`)}`;
  if (ghToken) {
    const headers = { authorization: `Bearer ${ghToken}`, accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28" };
    return getJson(`https://api.github.com${path}`, { headers });
  }
  return cached(`https://api.github.com${path}`, async () => JSON.parse((await run("gh", ["api", path])).stdout));
}

// ---- Minimal semver order (enough for OSV range events on these versions).
const parse = (v) => {
  const m = /^(\d+)\.(\d+)\.(\d+)(?:-([^+]+))?/.exec(v) ?? [null, 0, 0, 0];
  return [+m[1], +m[2], +m[3], m[4] ?? null];
};
function cmp(a, b) {
  const x = parse(a), y = parse(b);
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i];
  if (x[3] === y[3]) return 0;
  if (x[3] === null || y[3] === null) return x[3] === null ? 1 : -1;
  const p = x[3].split("."), q = y[3].split(".");
  for (let i = 0; i < Math.max(p.length, q.length); i++) {
    if (p[i] === undefined || q[i] === undefined) return p[i] === undefined ? -1 : 1;
    if (p[i] === q[i]) continue;
    const pn = /^\d+$/.test(p[i]), qn = /^\d+$/.test(q[i]);
    if (pn && qn) return +p[i] - +q[i];
    if (pn !== qn) return pn ? -1 : 1;
    return p[i] < q[i] ? -1 : 1;
  }
  return 0;
}
function inEvents(v, events) {
  for (let i = 0; i < events.length; i++) {
    const intro = events[i].introduced;
    if (intro === undefined || (intro !== "0" && cmp(v, intro) < 0)) continue;
    const end = events[i + 1] ?? {};
    if (end.fixed !== undefined) { if (cmp(v, end.fixed) < 0) return true; }
    else if (end.last_affected !== undefined) { if (cmp(v, end.last_affected) <= 0) return true; }
    else if (end.limit !== undefined) { if (cmp(v, end.limit) < 0) return true; }
    else return true;
  }
  return false;
}
const covers = (origin, v) => (origin.versions ?? []).includes(v) || (origin.ranges ?? []).some((r) => inEvents(v, r.events ?? []));

// ---- Inputs: unique name@version, remembering which sets/waves list it.
const iocs = JSON.parse(readFileSync(opt.iocs, "utf8"));
const byId = new Map();
for (const set of iocs.sets) {
  for (const [name, versions] of Object.entries(set.packages)) {
    for (const version of versions) {
      const row = byId.get(`${name}@${version}`) ?? { name, version, sets: [], waves: new Set() };
      row.sets.push(set.id);
      row.waves.add(set.wave);
      byId.set(`${name}@${version}`, row);
    }
  }
}
const rows = [...byId.values()];
const names = [...new Set(rows.map((r) => r.name))];
console.error(`${rows.length} versions across ${names.length} packages`);

// Positive control: a broken lookup must not read as "no advisory". Both sources
// must find the advisory for a known-malicious version (GHSA-qjqf-7j6f-82c4).
const control = { name: "@ctrl/tinycolor", version: "4.1.1" };
if (!(await ghsaFor(control))?.length || !(await osvFor(control))?.vulns?.length) {
  throw new Error("positive control failed: GHSA or OSV returned nothing for @ctrl/tinycolor@4.1.1");
}

// ---- 1. Registry publish times. Needs the full packument (abbreviated docs omit
// `time`); only `time` and the version keys are kept. A removed version stays in
// `time` but leaves `versions`; the removal itself is not timestamped.
const registry = new Map();
await pool(names, async (name) => {
  const doc = await getJson(`https://registry.npmjs.org/${name.replace("/", "%2F")}`, {},
    (d) => ({ time: d.time, versions: Object.fromEntries(Object.keys(d.versions ?? {}).map((v) => [v, 1])) }));
  registry.set(name, doc && { time: doc.time ?? {}, versions: Object.keys(doc.versions ?? {}) });
});

// ---- 2./3. OSV MAL- records (OpenSSF malicious-packages) and GitHub malware advisories.
const osv = await pool(rows, osvFor);
const gh = await pool(rows, ghsaFor);

// ---- 4. Per-version record. Every *_h column is hours after the registry publish.
const iso = (t) => (t ? new Date(t).toISOString() : "");
const hours = (a, b) => (a && b ? ((Date.parse(a) - Date.parse(b)) / HOUR).toFixed(2) : "");
const byTime = (f) => (a, b) => Date.parse(f(a)) - Date.parse(f(b));
const records = rows.map((r, i) => {
  const reg = registry.get(r.name);
  const published = reg?.time[r.version] ?? null;
  const notBefore = (t) => !published || Date.parse(t) >= Date.parse(published);
  const status = !reg ? "package-404" : !published ? "no-time" : reg.versions.includes(r.version) ? "live" : "removed";
  const mal = (osv[i]?.vulns ?? []).filter((v) => v.id.startsWith("MAL-"));
  // Each upstream snapshot the OpenSSF importer recorded (GHSA, Amazon Inspector, ...).
  // Its modified_time is the upstream record's own timestamp, so the first snapshot
  // that lists this version is when that source first covered *this version*. A
  // record's own `published` (and GHSA's published_at) is when the record was
  // created, possibly for other versions of the package, so it is only a fallback.
  const origins = mal.flatMap((m) => m.database_specific?.["malicious-packages-origins"] ?? [])
    .filter((o) => covers(o, r.version)).sort(byTime((o) => o.modified_time));
  // A snapshot dated before the version existed (e.g. a blanket "introduced: 0" range
  // from an earlier wave) is reported, but kept out of the latency.
  const osvFirst = origins.find((o) => notBefore(o.modified_time));
  const preexisting = origins.find((o) => !notBefore(o.modified_time));
  const osvPublished = mal.map((m) => m.published).sort()[0];
  // Hand-written records carry no origins: use the record's date, or its last
  // modification if the record predates the version.
  const recordOnly = !origins.length && mal.map((m) => (notBefore(m.published) ? m.published : m.modified)).sort()[0];
  const ghsa = (gh[i] ?? []).filter((a) => !a.withdrawn_at).sort(byTime((a) => a.published_at));
  const ghsaAfter = ghsa.find((a) => notBefore(a.published_at));
  const advisory = osvFirst ? { t: osvFirst.modified_time, src: `osv:${osvFirst.source}` }
    : recordOnly ? { t: recordOnly, src: "osv:record-date" }
    : ghsaAfter ? { t: ghsaAfter.published_at, src: "ghsa:record-date" } : null;
  return {
    name: r.name, version: r.version, sets: r.sets.join(" "), waves: [...r.waves].join(" "),
    registry_published: iso(published), registry_status: status,
    // npm versions are immutable, so a version published before its wave began cannot
    // carry that wave's payload: a listing error or an unrelated incident.
    pre_wave: String(Boolean(published) && published < [...r.waves].sort()[0] + "-01"),
    package_modified: iso(reg?.time.modified), package_unpublished: iso(reg?.time.unpublished?.time),
    osv_ids: mal.map((m) => m.id).join(" "), osv_record_published: iso(osvPublished),
    osv_first_cover: iso(osvFirst?.modified_time), osv_first_cover_source: osvFirst?.source ?? "",
    osv_first_cover_imported: iso(osvFirst?.import_time), osv_cover_before_publish: iso(preexisting?.modified_time),
    ghsa_ids: ghsa.map((a) => a.ghsa_id).join(" "), ghsa_published: iso(ghsa[0]?.published_at), ghsa_updated: iso(ghsa[0]?.updated_at),
    advisory_time: iso(advisory?.t), advisory_source: advisory?.src ?? "",
    latency_h: hours(advisory?.t, published),
    osv_latency_h: hours(osvFirst?.modified_time, published),
    osv_record_latency_h: hours(osvPublished, published),
    ghsa_record_latency_h: hours(ghsa[0]?.published_at, published),
    // Removal is not timestamped, but it is a packument write, so a removed version
    // was gone by time.modified at the latest. Loose whenever the package changed later.
    removal_bound_h: status === "removed" ? hours(reg.time.modified, published) : "",
  };
});

// No publish time (package deleted outright): bound the latency from above by
// assuming the version was published no earlier than its wave's first in-wave publish.
const waveStart = {};
for (const x of records) {
  if (x.pre_wave === "true" || !x.registry_published) continue;
  for (const w of x.waves.split(" ")) if (!(waveStart[w] <= x.registry_published)) waveStart[w] = x.registry_published;
}
for (const x of records) {
  const start = x.waves.split(" ").map((w) => waveStart[w]).sort()[0];
  x.latency_bound_h = !x.registry_published && x.advisory_time && start ? hours(x.advisory_time, start) : "";
}

const csvCell = (v) => (/[",\n]/.test(String(v)) ? `"${String(v).replaceAll('"', '""')}"` : String(v));
const cols = Object.keys(records[0]);
writeFileSync(join(opt.out, "soak-latency.csv"),
  [cols.join(","), ...records.map((rec) => cols.map((c) => csvCell(rec[c])).join(","))].join("\n") + "\n");

// ---- 5. Summaries (hours; nearest-rank percentiles over versions with a value).
function summarise(label, recs, col) {
  const v = recs.map((x) => x[col]).filter((x) => x !== "").map(Number).sort((a, b) => a - b);
  const f = (x) => (x === undefined ? "-" : x.toFixed(1));
  const pct = (p) => f(v[Math.max(0, Math.ceil((p / 100) * v.length) - 1)]);
  const within = (h) => (v.length ? `${((100 * v.filter((x) => x <= h).length) / v.length).toFixed(1)}%` : "-");
  return [label, recs.length, v.length, f(v[0]), pct(25), pct(50), pct(75), pct(90), pct(95), f(v.at(-1)),
    within(24), within(48), within(72), within(168)];
}
const head = ["", "versions", "measured", "min", "p25", "median", "p75", "p90", "p95", "max", "<=24h", "<=48h", "<=72h", "<=7d"];
const mdTable = (t) => t.map((r, i) => `| ${r.join(" | ")} |` + (i === 0 ? `\n|${" --- |".repeat(r.length)}` : "")).join("\n");
const inWave = records.filter((x) => x.pre_wave !== "true");
const bySet = (id) => inWave.filter((x) => x.sets.split(" ").includes(id));
const byWave = (w) => inWave.filter((x) => x.waves.split(" ").includes(w));
const groupTable = mdTable([head,
  ...iocs.sets.map((s) => summarise(`set ${s.id}`, bySet(s.id), "latency_h")),
  ...[...new Set(iocs.sets.map((s) => s.wave))].map((w) => summarise(`wave ${w}`, byWave(w), "latency_h")),
  summarise("all in-wave versions (headline)", inWave, "latency_h"),
]);
const measureTable = mdTable([head,
  summarise("headline: first advisory listing the version", inWave, "latency_h"),
  summarise("same, including pre-wave listings", records, "latency_h"),
  summarise("OSV per-version snapshots only", inWave, "osv_latency_h"),
  summarise("OSV record created (record-level)", inWave, "osv_record_latency_h"),
  summarise("GHSA published_at (record-level)", inWave, "ghsa_record_latency_h"),
  summarise("package deleted (404): advisory minus wave start", inWave, "latency_bound_h"),
  summarise("removal upper bound: packument time.modified", inWave, "removal_bound_h"),
]);
const count = (pred, recs = inWave) => recs.filter(pred).length;
const tally = (col) => Object.entries(Object.groupBy(inWave, (x) => x[col] || "(none)")).map(([k, v]) => `${k} ${v.length}`).join(", ");
const list = (recs) => recs.map((x) => `${x.name}@${x.version} (${x.registry_published.slice(0, 10)}, ${x.latency_h || "no advisory"}h)`).join("; ");
const report = [
  `Retrieved ${new Date().toISOString()}; input ${opt.iocs}`, "",
  "Latency (hours) = first public malware advisory listing the version minus its registry publish time.", "",
  groupTable, "", "In-wave versions by measure (record-level rows can predate the version's own listing):", "",
  measureTable, "",
  `- registry status: ${tally("registry_status")}`,
  `- headline source: ${tally("advisory_source")}`,
  `- no advisory in either source: ${count((x) => !x.osv_ids && !x.ghsa_ids)}; no GHSA: ${count((x) => !x.ghsa_ids)}; no OSV MAL-: ${count((x) => !x.osv_ids)}`,
  `- over 72h: ${list(inWave.filter((x) => Number(x.latency_h) > 72))}`,
  `- pre-wave listings (published before the wave's month), excluded above: ${list(records.filter((x) => x.pre_wave === "true"))}`,
  `- advisory dated before the version: OSV snapshot ${count((x) => x.osv_cover_before_publish)}, OSV record `
    + `${count((x) => Number(x.osv_record_latency_h) < 0)}, GHSA record ${count((x) => Number(x.ghsa_record_latency_h) < 0)}`,
  `- record existed >1h before it listed the version: ${count((x) => x.osv_latency_h && Number(x.osv_latency_h) - Math.min(...[x.osv_record_latency_h, x.ghsa_record_latency_h].filter(Boolean).map(Number)) > 1)}`,
  `- GHSA published more than 7 days after the version: ${count((x) => Number(x.ghsa_record_latency_h) > 168)}`,
  `- wave start used for 404 bounds: ${JSON.stringify(waveStart)}`,
].join("\n");
writeFileSync(join(opt.out, "soak-latency-summary.md"), report + "\n");
console.log(report);
