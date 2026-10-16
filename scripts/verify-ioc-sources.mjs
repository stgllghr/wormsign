#!/usr/bin/env node
// Maintainer tool (not shipped, not run by the scanner): checks that every IOC
// string in data/iocs appears verbatim in the saved copy of the page it cites,
// and that every version in a package set selected by a vendor report is listed
// on that report (the set's versions plus its "unmatched" ones equal a fresh
// parse of the page). Prints the matched excerpt for each string so a reviewer
// can eyeball it. Usage:
//   node scripts/verify-ioc-sources.mjs <saved-pages-dir>
// That the versions also come from the licensed datasets is checked by re-running
// scripts/import-package-sets.mjs at the recorded commits and diffing the result.
import { readFileSync } from "node:fs";
import process from "node:process";
import { URL } from "node:url";
import { REPORTS, decode, readSnapshot, toObj } from "./vendor-pages.mjs";

const rawDir = process.argv[2];
if (!rawDir) {
  process.stderr.write("usage: verify-ioc-sources.mjs <saved-pages-dir>\n");
  process.exit(2);
}
const load = (f) => JSON.parse(readFileSync(new URL(`../data/iocs/${f}.json`, import.meta.url), "utf8"));
const refang = (s) => s.replaceAll("[.]", ".");

/** [source, the string that must appear on it, what it is] for every non-bulk IOC. */
const checks = [];
const files = load("files");
for (const h of files.hashes) {
  checks.push([h.source, h.sha256, "hash"]);
  if (!h.name.startsWith("(")) checks.push([h.source, h.name, "hash file name"]); // "(label)" = no published file name
}
for (const n of files.names) checks.push([n.source, n.name, "file name"]);
const workflows = load("workflows");
for (const w of workflows.workflowFiles) checks.push([w.source, w.name, "workflow file"]);
for (const r of workflows.runnerNames) checks.push([r.source, r.name, "runner name"]);
const repos = load("repos");
for (const p of repos.patterns) {
  if (p.name) checks.push([p.source, p.name, `repo pattern ${p.id}`]);
  if (p.description) checks.push([p.source, p.description, `repo pattern ${p.id}`]);
}
for (const b of repos.branches) checks.push([b.source, b.name.replace(/\*$/, ""), "branch"]); // "x-*" is a prefix; the page prints "x-" and a placeholder
for (const e of load("endpoints").endpoints) checks.push([e.source, e.substring, "endpoint"]);

const pages = new Map();
function page(url) {
  if (!pages.has(url)) {
    const html = readSnapshot(rawDir, url);
    pages.set(url, { html, text: decode(html.replace(/<[^>]*>/g, "")) });
  }
  return pages.get(url);
}

let failed = 0;
const fail = (msg) => {
  failed++;
  process.stdout.write(`FAIL ${msg}\n`);
};
for (const [source, needle, what] of checks) {
  let p;
  try {
    p = page(source);
  } catch (e) {
    fail(`${what} ${needle}: ${e.message}`);
    continue;
  }
  // A defanged endpoint counts as found in either form; vendors print both.
  const forms = needle.includes("[.]") ? [needle, refang(needle)] : [needle];
  let hit;
  for (const hay of [p.html, p.text]) {
    for (const f of forms) {
      const i = hay.indexOf(f);
      if (i !== -1 && !hit) hit = hay.slice(Math.max(0, i - 50), i + f.length + 50).replace(/\s+/g, " ");
    }
  }
  if (hit) process.stdout.write(`ok   ${what} ${needle}\n       ...${hit}...\n`);
  else fail(`${what} ${needle}: not found on ${source}`);
}

const packages = load("packages");
for (const def of REPORTS) {
  const set = packages.sets.find((s) => s.id === def.id);
  let parsed;
  try {
    parsed = toObj(def.parse(readSnapshot(rawDir, def.source)).packages);
  } catch (e) {
    fail(`package set ${def.id}: ${e.message}`);
    continue;
  }
  const pairs = (m) => Object.entries(m ?? {}).flatMap(([n, vs]) => vs.map((v) => `${n}@${v}`));
  const kept = pairs(set?.packages);
  const unmatched = pairs(set?.unmatched);
  const both = [...kept, ...unmatched];
  const listed = new Set(pairs(parsed));
  const notOnPage = both.filter((p) => !listed.has(p));
  if (!set || set.source !== def.source) fail(`package set ${def.id} is missing or does not cite ${def.source}`);
  else if (notOnPage.length) fail(`package set ${def.id}: ${notOnPage.length} version(s) not listed on ${def.source}, e.g. ${notOnPage.slice(0, 3).join(", ")}`);
  else if (new Set(both).size !== listed.size || both.length !== listed.size) fail(`package set ${def.id}: versions plus "unmatched" do not equal the ${listed.size} listed on the page; re-run scripts/import-package-sets.mjs`);
  else process.stdout.write(`ok   package set ${def.id}: all ${kept.length} versions are listed on the saved page (${unmatched.length} listed version(s) unmatched)\n`);
}

process.stdout.write(`${checks.length} IOC strings and ${REPORTS.length} package sets checked, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
