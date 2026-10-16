#!/usr/bin/env node
// Maintainer tool (not shipped): what soak's Python side reports on the false-positive corpus.
// Usage: npm run build && node scripts/fp-corpus.mjs --work <dir> && node scripts/fp-corpus-soak.mjs --work <dir> [--out <file.json>]
// Runs `wormsign soak <checkout> --no-baseline --no-osv --registry http://127.0.0.1:9` over each checkout
// fp-corpus.mjs left in <dir>, with an empty HOME. The npm registry is a closed local port, so npm's half fails at
// once and sends nothing (its findings are left out here); the Python index is the default, pypi.org, which is asked
// only about the projects a Python lock pins. Records, per repository, every finding whose key is a PyPI key
// (`pypi:`), by rule and severity, the files they are in, and soak's Python notes.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const { values: opt } = parseArgs({ options: { work: { type: "string" }, out: { type: "string", default: "fp-corpus-soak.json" } } });
if (!opt.work) {
  process.stderr.write("usage: fp-corpus-soak.mjs --work <dir> [--out <file.json>]\n");
  process.exit(2);
}
const cli = fileURLToPath(new URL("../dist/src/cli.js", import.meta.url));
const home = mkdtempSync(join(tmpdir(), "ws-fp-soak-home-"));
const results = [];
for (const dir of readdirSync(opt.work).sort()) {
  const args = [cli, "soak", join(opt.work, dir), "--no-baseline", "--no-osv", "--registry", "http://127.0.0.1:9", "--format", "json"];
  const r = spawnSync(process.execPath, args, { encoding: "utf8", maxBuffer: 1 << 30, env: { PATH: process.env.PATH, HOME: home } });
  const doc = JSON.parse(r.stdout);
  const py = doc.findings.filter((f) => f.key.startsWith("pypi:"));
  const byRule = {};
  for (const f of py) byRule[`${f.ruleId} ${f.severity}`] = (byRule[`${f.ruleId} ${f.severity}`] ?? 0) + 1;
  const notes = doc.notes.filter((n) => /PyPI|Python|requirements files/.test(n));
  results.push({ repo: dir.replace("__", "/"), findings: byRule, files: [...new Set(py.map((f) => f.file))].sort(), notes });
  console.log(`${dir.replace("__", "/")}: ${py.length} PyPI finding(s)`);
}
writeFileSync(opt.out, JSON.stringify({ retrieved: new Date().toISOString(), results }, null, 2) + "\n");
