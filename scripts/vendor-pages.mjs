// Maintainer library (not shipped): parsers for the vendor reports that decide
// which package versions data/iocs/packages.json imports from OpenSSF's
// malicious-packages dataset, plus the page snapshots they were parsed from.
// The vendor's list is the reason a version is included (and the citation a
// finding shows); the redistributed data is the OpenSSF record, which is
// Apache-2.0 licensed. Pages are saved by hand and kept out of the repository
// (they are third-party content); the snapshot hashes below say exactly which
// copy the data was selected and checked with.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/** Source URL -> saved snapshot file name and its SHA-256. Update both when a page is re-saved. */
export const SNAPSHOTS = {
  "https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised": { file: "stepsec.html", sha256: "c4ba45395e93348ca4a4f6a024bdf0a832ecb9bbb3be4a1f0250772986a25447" },
  "https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages": { file: "socket1.html", sha256: "5c97f3b2cd5705c49fd16187aef15bf481baaf3dafdd57e2c1456484603ad262" },
  "https://research.jfrog.com/post/shai-hulud-is-back-august/": { file: "jfrog.html", sha256: "0c168fa5ea2a2b173fe7facd91e0badfa9e1aa0ee0718e0dd17eee2f4d55f2a1" },
  "https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/": { file: "datadog.html", sha256: "4d4d697af713ddaaac4d54d334256c4d22531dac68c1ab19f34b22116ea4b0b8" },
  "https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack": { file: "wiz.html", sha256: "b49860e4f0fe04dc80233521e7b7a7eb41e0f919a65cf489fd8e6571e32faf6c" },
  "https://unit42.paloaltonetworks.com/npm-supply-chain-attack/": { file: "unit42.html", sha256: "fe30e47077a742822928f079d4d201b2baf94b7e01b42207beae87b56b61afc4" },
  "https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem": { file: "cisa.html", sha256: "2fbc84455238f123ad7b2e0f654e04161270e82ac4ed84ec975239deb6f8f75a" },
  "https://www.picussecurity.com/resource/blog/mini-shai-hulud-the-npm-supply-chain-worm-explained": { file: "picus.html", sha256: "8df42c29a1518a9db3b24ffc83a4dc137e19ef5b6e979f052980854f3f2960a0" },
  "https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem": { file: "stepsec2.html", sha256: "34c3bac8cd8673d9b73d86ac8539aeb64aa9267592c867cb0af6ece317c0e4f3" },
};

/** Reads a saved page and refuses a copy other than the one recorded above. */
export function readSnapshot(rawDir, url) {
  const snap = SNAPSHOTS[url];
  if (!snap) throw new Error(`no saved snapshot is registered for ${url}`);
  const buf = readFileSync(join(rawDir, snap.file));
  const sha256 = createHash("sha256").update(buf).digest("hex");
  if (sha256 !== snap.sha256) {
    throw new Error(`${snap.file}: SHA-256 ${sha256} differs from the recorded snapshot ${snap.sha256}; re-verify the page and update SNAPSHOTS`);
  }
  return buf.toString("utf8");
}

const VERSION = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/;
const NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;

const ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', "#39": "'" };
export function decode(s) {
  return s
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)))
    .replace(/&(amp|lt|gt|quot|#39);/g, (_, e) => ENTITIES[e]);
}
const text = (html) => decode(html.replace(/<[^>]*>/g, "")).trim();

function add(map, name, version, where) {
  if (!NAME.test(name) || !VERSION.test(version)) throw new Error(`${where}: unexpected entry ${JSON.stringify(name)}@${JSON.stringify(version)}`);
  (map[name] ??= new Set()).add(version);
}
function slice(html, start, end, where) {
  const i = html.indexOf(start);
  const j = i === -1 ? -1 : html.indexOf(end, i);
  if (j === -1) throw new Error(`${where}: section ${JSON.stringify(start)} not found; the page layout changed`);
  return html.slice(i, j);
}
export const countVersions = (map) => Object.values(map).reduce((n, s) => n + s.size, 0);
export const toObj = (map) => Object.fromEntries(Object.keys(map).sort().map((k) => [k, [...map[k]].sort()]));

/**
 * StepSecurity, wave 1: the "Affected Packages" table, one numbered row per package.
 * The page states no total, so the cross-check is that row numbers run 1..N with no gap.
 * Row 59 on the saved page closes its versions cell with a stray </BUTT> instead of </td>,
 * so each cell is read up to the next tag rather than up to </td>.
 */
export function parseStepSecurity(html) {
  const where = "stepsec";
  const table = slice(html, "<th>Package Name</th>", "</tbody>", where);
  const rows = table.split(/<tr[^>]*>/).slice(1);
  const map = {};
  rows.forEach((row, i) => {
    const m = /<td>(\d+)<\/td>\s*<td class="package-name">([^<]*)<\/td>\s*<td class="versions">([^<]*)</.exec(row);
    if (!m) throw new Error(`${where}: row ${i + 1} does not have the expected cells`);
    if (Number(m[1]) !== i + 1) throw new Error(`${where}: row numbered ${m[1]} at position ${i + 1}`);
    for (const v of m[3].split(",")) add(map, decode(m[2]).trim(), v.trim(), `${where} row ${m[1]}`);
  });
  if (Object.keys(map).length !== rows.length) throw new Error(`${where}: ${rows.length} rows but ${Object.keys(map).length} distinct packages`);
  return { packages: map, check: `the page's rows numbered 1-${rows.length}` };
}

/** Socket, wave 1: an ordered list of name@version after the line "Total packages: N". N counts pairs. */
export function parseSocketWave1(html) {
  const where = "socket1";
  const m = /<p[^>]*>Total packages: (\d+)<\/p><ol[^>]*>([\s\S]*?)<\/ol>/.exec(html);
  if (!m) throw new Error(`${where}: "Total packages" list not found; the page layout changed`);
  const items = [...m[2].matchAll(/<li[^>]*>([\s\S]*?)<\/li>/g)].map((x) => text(x[1]));
  const map = {};
  for (const item of items) {
    const at = item.lastIndexOf("@");
    add(map, item.slice(0, at), item.slice(at + 1), where);
  }
  const stated = Number(m[1]);
  if (items.length !== stated || countVersions(map) !== stated) {
    throw new Error(`${where}: page states ${stated} packages, parsed ${items.length} items / ${countVersions(map)} unique pairs`);
  }
  return { packages: map, check: `the page's "Total packages: ${stated}"` };
}

/**
 * JFrog, August 2026: the "Compromised packages (Ongoing)" table. Only npm rows are imported;
 * the Go-module rows use ">=" ranges and are a different ecosystem. The page headline gives
 * lower bounds ("400+ packages across 1700+ versions"), so the parse must reach both.
 */
export function parseJfrogAug2026(html) {
  const where = "jfrog";
  const table = slice(html, 'id="compromised-packages-ongoing"', "</table>", where);
  const map = {};
  let npmRows = 0;
  for (const row of table.split("<tr>").slice(2)) {
    const cells = [...row.matchAll(/<td[^>]*>([\s\S]*?)<\/td>/g)].map((x) => x[1]);
    if (cells.length !== 4) throw new Error(`${where}: row with ${cells.length} cells: ${row.slice(0, 120)}`);
    const type = text(cells[1]);
    if (type !== "npm") {
      if (type !== "golang") throw new Error(`${where}: unknown package type ${type}`);
      continue;
    }
    npmRows++;
    const name = text(cells[0]);
    if (map[name]) throw new Error(`${where}: ${name} appears in two rows`);
    const versions = [...cells[2].matchAll(/<code>([^<]*)<\/code>/g)].map((x) => decode(x[1]));
    if (versions.length === 0 || cells[2].replace(/<code>[^<]*<\/code>/g, "").replace(/,/g, "").trim() !== "") {
      throw new Error(`${where}: unexpected versions cell for ${name}: ${cells[2]}`);
    }
    for (const v of versions) add(map, name, v, where);
  }
  if (!/400\+ packages across 1700\+ versions/.test(html)) throw new Error(`${where}: stated totals not found; the page changed`);
  if (npmRows < 400 || countVersions(map) < 1700) throw new Error(`${where}: parsed ${npmRows} packages / ${countVersions(map)} versions, below the stated 400+ / 1700+`);
  return { packages: map, check: 'the page\'s "400+ packages across 1700+ versions"' };
}

/**
 * Picus, Mini Shai-Hulud (April 2026): one sentence naming the "four trusted packages" of the first wave, each as
 * "<name> version <v>" in bold. The sentence says four, so the parse must find exactly four.
 */
export function parsePicusMiniShaiHulud(html) {
  const where = "picus";
  const para = slice(html, "The first known wave compromised four trusted packages", "</p>", where);
  const map = {};
  const items = [...para.matchAll(/<strong><span>([^<]*?) version ([^<]*)<\/span><\/strong>/g)];
  for (const m of items) add(map, decode(m[1]).trim(), decode(m[2]).trim(), where);
  if (items.length !== 4 || countVersions(map) !== 4) throw new Error(`${where}: the page names four packages, parsed ${items.length}`);
  return { packages: map, check: 'the page\'s "compromised four trusted packages"' };
}

/**
 * StepSecurity, Mini Shai-Hulud May 2026 (TanStack and others): the "Compromised Packages" table (id="pkgTable"),
 * one row per package, "<code>name</code>" then a comma-separated versions cell. Rows whose name ends in " (PyPI)"
 * are Python packages and are skipped; any other unexpected name stops the parse. The page states no total for the
 * table; it does quote TanStack's post-mortem, "84 malicious versions across 42 @tanstack/* packages", so the
 * @tanstack/ rows must come to exactly that.
 */
export function parseStepSecurityMay2026(html) {
  const where = "stepsec2";
  const table = slice(html, 'id="pkgTable"', "</table>", where);
  const body = slice(table, "<tbody>", "</tbody>", where);
  const rows = [...body.matchAll(/<tr[^>]*>([\s\S]*?)<\/tr>/g)].map((x) => x[1]);
  if (rows.length === 0) throw new Error(`${where}: the table has no rows`);
  const map = {};
  rows.forEach((row, i) => {
    const m = /^\s*<td><code>([^<]*)<\/code><\/td>\s*<td>([^<]*)<\/td>\s*$/.exec(row);
    if (!m) throw new Error(`${where}: row ${i + 1} does not have the expected cells`);
    const name = decode(m[1]).trim();
    if (/ \(PyPI\)$/.test(name)) return; // a different ecosystem, marked in the name cell
    if (map[name]) throw new Error(`${where}: ${name} appears in two rows`);
    for (const v of m[2].split(",")) add(map, name, decode(v).trim(), `${where} row ${i + 1}`);
  });
  if (!/84 malicious versions across 42 @tanstack\/\* packages/.test(html)) throw new Error(`${where}: stated TanStack totals not found; the page changed`);
  const tan = Object.fromEntries(Object.entries(map).filter(([n]) => n.startsWith("@tanstack/")));
  if (Object.keys(tan).length !== 42 || countVersions(tan) !== 84) {
    throw new Error(`${where}: parsed ${Object.keys(tan).length} @tanstack/ packages / ${countVersions(tan)} versions, the page states 42 / 84`);
  }
  return { packages: map, check: `the page's "84 malicious versions across 42 @tanstack/* packages" (the @tanstack/ rows of ${rows.length})` };
}

/**
 * The vendor reports whose lists select OpenSSF records, keyed by the package set each produces. `source` is the
 * report (the citation a finding shows); scripts/import-package-sets.mjs keeps the listed versions that an OpenSSF
 * malicious-packages record also lists.
 */
export const REPORTS = [
  { id: "openssf-shai-hulud-1-stepsecurity", wave: "2025-09", source: "https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised", parse: parseStepSecurity, what: "StepSecurity's 'Affected Packages' table" },
  { id: "openssf-shai-hulud-1-socket", wave: "2025-09", source: "https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages", parse: parseSocketWave1, what: "Socket's 'Compromised Packages and Versions' list" },
  { id: "openssf-mini-shai-hulud-picus", wave: "2026-04", source: "https://www.picussecurity.com/resource/blog/mini-shai-hulud-the-npm-supply-chain-worm-explained", parse: parsePicusMiniShaiHulud, what: "the four packages Picus names for the first Mini Shai-Hulud wave" },
  { id: "openssf-mini-shai-hulud-may-2026-stepsecurity", wave: "2026-05", source: "https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem", parse: parseStepSecurityMay2026, what: "StepSecurity's May 2026 'Compromised Packages' table" },
  { id: "openssf-shai-hulud-aug-2026-jfrog", wave: "2026-08", source: "https://research.jfrog.com/post/shai-hulud-is-back-august/", parse: parseJfrogAug2026, what: "the npm rows of JFrog's 'Compromised packages (Ongoing)' table" },
];
