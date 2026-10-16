#!/usr/bin/env node
// Maintainer tool (not shipped, not run by the scanner): times the vendored TOML parser on large
// generated documents, for the "What smol-toml 1.9.0 does" list in docs/architecture.md. Usage:
//   npm run build && node scripts/toml-bench.mjs
// Each shape is parsed once to warm up, then five times; the best time is printed. The shapes are
// the ones test/python-readers.test.ts bounds at 1 MB, plus a growing series to show the trend.
import { performance } from "node:perf_hooks";
import process from "node:process";
import { parse } from "../dist/src/vendor/smol-toml/index.js";

function best(doc) {
  parse(doc);
  let min = Infinity;
  for (let i = 0; i < 5; i++) {
    const t0 = performance.now();
    parse(doc);
    min = Math.min(min, performance.now() - t0);
  }
  return Math.round(min);
}
const upTo = (bytes, line) => {
  let s = "";
  for (let i = 0; s.length < bytes; i++) s += line(i);
  return s;
};
const rows = [];
for (const n of [50_000, 100_000, 200_000, 400_000]) {
  rows.push([`${n} [[p]] tables with a name and a version`, best(Array.from({ length: n }, (_, i) => `[[p]]\nname = "p${i}"\nversion = "1.0.${i}"\n`).join(""))]);
}
for (const mb of [0.25, 0.5, 1, 2]) rows.push([`${mb} MB of distinct table headers`, best(upTo(mb * 1_000_000, (i) => `[t${i}]\n`))]);
rows.push(["1 MB of dotted keys", best(upTo(1_000_000, (i) => `k${i}.x.y = 1\n`))]);
rows.push(["1 MB of [[a.b]] headers", best("[[a.b]]\n".repeat(125_000))]);
rows.push(["1 MB of inline tables", best(`a = [${"{x=1},".repeat(166_000)}]\n`)]);
console.log(`node ${process.version} (${process.platform} ${process.arch})`);
for (const [what, ms] of rows) console.log(`${String(ms).padStart(5)} ms  ${what}`);
