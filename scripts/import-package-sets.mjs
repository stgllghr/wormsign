#!/usr/bin/env node
// Maintainer tool (not shipped, not run by the scanner): regenerates every package
// set in data/iocs/packages.json from two Apache-2.0 datasets, so that every
// redistributed name@version comes from licensed data:
//   - Datadog's consolidated Shai-Hulud 2.0 list (DataDog/indicators-of-compromise,
//     shai-hulud-2.0/consolidated_iocs.csv), imported whole for the 2025-11 wave;
//   - OpenSSF malicious-packages (ossf/malicious-packages, osv/malicious/npm) for the
//     other waves: a version is imported when the vendor report that names it (the
//     citation, parsed from the maintainer's saved page, see vendor-pages.mjs) lists
//     it AND an OpenSSF record lists it. The record ids are kept per package.
// Each dataset is read from a local git checkout; its commit, remote and licence
// are checked and recorded. Usage:
//   git clone --depth 1 https://github.com/DataDog/indicators-of-compromise.git "$TMPDIR/dd"
//   git clone --depth 1 --filter=blob:none --sparse https://github.com/ossf/malicious-packages.git "$TMPDIR/ossf"
//   git -C "$TMPDIR/ossf" sparse-checkout set osv/malicious/npm
//   node scripts/import-package-sets.mjs --retrieved YYYY-MM-DD \
//     --pages <saved-pages-dir> --datadog "$TMPDIR/dd" --openssf "$TMPDIR/ossf"
// Everything else in packages.json (schema, version, description, exclusions) is kept.
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import process from "node:process";
import { URL, fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { REPORTS, countVersions, readSnapshot, toObj } from "./vendor-pages.mjs";

export const DATASETS = {
  datadog: {
    name: "Datadog indicators-of-compromise",
    url: "https://github.com/DataDog/indicators-of-compromise",
    path: "shai-hulud-2.0/consolidated_iocs.csv",
  },
  openssf: {
    name: "OpenSSF malicious-packages",
    url: "https://github.com/ossf/malicious-packages",
    path: "osv/malicious/npm",
  },
};

const VERSION = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/;
const NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;
function add(map, name, version, where) {
  if (!NAME.test(name) || !VERSION.test(version)) throw new Error(`${where}: unexpected entry ${JSON.stringify(name)}@${JSON.stringify(version)}`);
  (map[name] ??= new Set()).add(version);
}

/**
 * Checks that `dir` is a clean checkout of `dataset.url` under the Apache License 2.0 and returns its commit.
 * The commit is what makes the import reproducible, so a modified tree, another repository or another
 * licence is refused rather than recorded.
 */
export function checkout(dir, dataset) {
  const git = (...a) => execFileSync("git", ["-C", dir, ...a], { encoding: "utf8" }).trim();
  const remote = git("remote", "get-url", "origin").replace(/\.git$/, "").replace(/^git@github\.com:/, "https://github.com/");
  if (remote.toLowerCase() !== dataset.url.toLowerCase()) throw new Error(`${dir}: origin is ${remote}, expected ${dataset.url}`);
  if (git("status", "--porcelain") !== "") throw new Error(`${dir}: the checkout has local changes`);
  const licence = readFileSync(join(dir, "LICENSE"), "utf8");
  if (!/^\s*Apache License\s+Version 2\.0, January 2004/.test(licence)) throw new Error(`${dir}: LICENSE is not the Apache License 2.0`);
  const commit = git("rev-parse", "HEAD");
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error(`${dir}: unexpected commit ${commit}`);
  return { name: dataset.name, url: dataset.url, commit, path: dataset.path, license: "Apache-2.0" };
}

/** One CSV line into fields; fields may be double-quoted (with "" for a quote). */
function csvFields(line) {
  const out = [];
  let i = 0;
  for (;;) {
    let field = "";
    if (line[i] === '"') {
      for (i++; ; i++) {
        if (i >= line.length) throw new Error(`unterminated quote: ${line}`);
        if (line[i] === '"' && line[i + 1] === '"') { field += '"'; i++; } else if (line[i] === '"') { i++; break; } else field += line[i];
      }
    } else {
      const j = line.indexOf(",", i);
      field = line.slice(i, j === -1 ? line.length : j);
      i = j === -1 ? line.length : j;
    }
    out.push(field);
    if (i >= line.length) return out;
    if (line[i] !== ",") throw new Error(`text after a quoted field: ${line}`);
    i++;
  }
}

/**
 * Datadog's consolidated_iocs.csv: "package_name,package_versions,sources", one row per package, versions
 * comma-separated in one quoted field, e.g. `@a/b,"1.0.0, 1.0.1","koi, wiz"`.
 */
export function parseConsolidatedCsv(text) {
  const [header, ...rows] = text.split(/\r?\n/).filter(Boolean);
  if (header !== "package_name,package_versions,sources") throw new Error(`consolidated_iocs.csv: unexpected header ${header}`);
  const map = {};
  rows.forEach((line, i) => {
    const f = csvFields(line);
    if (f.length !== 3) throw new Error(`consolidated_iocs.csv row ${i + 2}: ${f.length} fields`);
    if (map[f[0]]) throw new Error(`consolidated_iocs.csv row ${i + 2}: ${f[0]} appears twice`);
    for (const v of f[1].split(",")) add(map, f[0], v.trim(), `consolidated_iocs.csv row ${i + 2}`);
  });
  return map;
}

/** OpenSSF records for one npm name: [{ id, versions }], from osv/malicious/npm/<name>/*.json. Withdrawn records are skipped. */
export function openssfRecords(root, name) {
  const dir = join(root, "osv", "malicious", "npm", ...name.split("/"));
  if (!existsSync(dir)) return [];
  const out = [];
  for (const f of readdirSync(dir).filter((x) => x.endsWith(".json")).sort()) {
    const rec = JSON.parse(readFileSync(join(dir, f), "utf8"));
    if (rec.withdrawn) continue;
    const versions = (rec.affected ?? [])
      .filter((a) => a.package?.ecosystem === "npm" && a.package?.name === name)
      .flatMap((a) => a.versions ?? []);
    out.push({ id: rec.id, versions });
  }
  return out;
}

/**
 * The versions of `listed` (name -> Set of versions, as a vendor report prints them) that an OpenSSF record
 * also lists. Only a record's explicit `versions` count: a version a report names but no record lists is
 * returned as `unmatched`, and a version a record lists but the report does not is left out (counted in
 * `notListed`), so every imported version is both cited and licensed.
 */
export function selectFromOpenSSF(listed, recordsFor) {
  const packages = {};
  const records = {};
  const unmatched = {};
  let notListed = 0;
  for (const name of Object.keys(listed).sort()) {
    const recs = recordsFor(name);
    for (const v of listed[name]) {
      const hits = recs.filter((r) => r.versions.includes(v));
      if (hits.length === 0) {
        (unmatched[name] ??= new Set()).add(v);
        continue;
      }
      (packages[name] ??= new Set()).add(v);
      for (const r of hits) (records[name] ??= new Set()).add(r.id);
    }
    const extra = new Set(recs.filter((r) => records[name]?.has(r.id)).flatMap((r) => r.versions).filter((v) => !listed[name].has(v)));
    notListed += extra.size;
  }
  return { packages, records: toObj(records), unmatched, notListed };
}

function main() {
  const { values } = parseArgs({ options: { retrieved: { type: "string" }, pages: { type: "string" }, datadog: { type: "string" }, openssf: { type: "string" } } });
  if (!/^\d{4}-\d{2}-\d{2}$/.test(values.retrieved ?? "") || !values.pages || !values.datadog || !values.openssf) {
    process.stderr.write("usage: import-package-sets.mjs --retrieved YYYY-MM-DD --pages <saved-pages-dir> --datadog <checkout> --openssf <checkout>\n");
    process.exit(2);
  }
  const dd = checkout(values.datadog, DATASETS.datadog);
  const ossf = checkout(values.openssf, DATASETS.openssf);
  if (!existsSync(join(values.openssf, ossf.path))) throw new Error(`${values.openssf}: ${ossf.path} is not checked out (git sparse-checkout set ${ossf.path})`);

  const sets = [];
  const ddPackages = parseConsolidatedCsv(readFileSync(join(values.datadog, dd.path), "utf8"));
  sets.push({
    id: "datadog-shai-hulud-2.0",
    wave: "2025-11",
    source: `${dd.url}/blob/${dd.commit}/${dd.path}`,
    retrieved: values.retrieved,
    dataset: dd,
    note: `All ${Object.keys(ddPackages).length} packages / ${countVersions(ddPackages)} versions in Datadog's consolidated list, which merges the versions that Datadog, HelixGuard, Koi, ReversingLabs, Socket, StepSecurity and Wiz reported. Generated by scripts/import-package-sets.mjs.`,
    packages: toObj(ddPackages),
  });
  for (const r of REPORTS) {
    const listed = r.parse(readSnapshot(values.pages, r.source)).packages;
    const sel = selectFromOpenSSF(listed, (name) => openssfRecords(values.openssf, name));
    const [n, v] = [Object.keys(sel.packages).length, countVersions(sel.packages)];
    const [ln, lv, uv] = [Object.keys(listed).length, countVersions(listed), countVersions(sel.unmatched)];
    sets.push({
      id: r.id,
      wave: r.wave,
      source: r.source,
      retrieved: values.retrieved,
      dataset: ossf,
      note: `The versions in ${r.what} (${ln} packages / ${lv} versions) that an OpenSSF malicious-packages record also lists: ${n} packages / ${v} versions. ${uv} listed version(s) have no OpenSSF record and are in "unmatched"; ${sel.notListed} further version(s) in the matched records are not in the report and are not imported. Generated by scripts/import-package-sets.mjs.`,
      records: sel.records,
      unmatched: toObj(sel.unmatched),
      packages: toObj(sel.packages),
    });
    process.stdout.write(`${r.id}: ${n} packages / ${v} versions of ${ln} / ${lv} listed; unmatched ${uv}; not listed ${sel.notListed}\n`);
  }
  sets.sort((a, b) => (a.wave < b.wave ? -1 : a.wave > b.wave ? 1 : 0)); // stable: report order within a wave
  process.stdout.write(`datadog-shai-hulud-2.0: ${Object.keys(ddPackages).length} packages / ${countVersions(ddPackages)} versions\n`);
  process.stdout.write(`datadog ${dd.commit}, openssf ${ossf.commit}\n`);

  const file = new URL("../data/iocs/packages.json", import.meta.url);
  const data = JSON.parse(readFileSync(file, "utf8"));
  data.sets = sets;
  writeFileSync(file, JSON.stringify(data, null, 1) + "\n");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
