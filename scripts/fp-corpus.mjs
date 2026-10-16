#!/usr/bin/env node
// Maintainer tool (not shipped, not run by the scanner): false-positive measurement.
// Fetches popular JavaScript/TypeScript repositories at pinned commits and runs this
// checkout's built scanner over each one. Usage:
//   npm run build && node scripts/fp-corpus.mjs --work <dir> [--out <file.json>]
// Each repository is fetched with `git fetch --depth 1` of its pinned commit, with
// hooks, LFS downloads and submodules off. Nothing from a checkout is installed or
// run: the only program run over it is `wormsign scan --format json`. Every finding
// goes to --out; a rule x repository count table goes to stdout. A positive control
// (below) proves each root lockfile was parsed.
import { spawnSync } from "node:child_process";
import { copyFileSync, cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

// Default-branch heads resolved with `gh api repos/<repo>/commits/<branch>` on
// 2026-10-02. The third field is a name@version from the root lockfile (positive control).
const CORPUS = [
  ["facebook/react", "7c6ac13e19fef500b7f669a16bbd01ecc95965ca", "@aashutoshrathi/word-wrap@1.2.6"], // yarn classic
  ["webpack/webpack", "d37872d245f4d6bc21c36ee5297663d87452d51d", "@babel/code-frame@7.29.7"], // yarn classic
  ["babel/babel", "7c1dcfac003791a7fee733ed13851a5cac1ccf1c", "@actions/github@9.1.1"], // yarn berry
  ["prettier/prettier", "8dafda772d095fa49fc735d90a0bba209771b7da", "@angular/compiler@22.2.1"], // yarn berry
  ["storybookjs/storybook", "2a3bdfe58ea4994b7f90d81b8e28fbde36858625", "@actions/core@1.11.1"], // yarn berry
  ["vercel/next.js", "8e0700c74474498a07b33f58da1c1316f740eb19", "@actions/core@1.10.1"], // pnpm
  ["vitejs/vite", "10033218d239c927cdc375970b5741cce408e81b", "@pnpm/exe.android-arm64@12.6.0"], // pnpm
  ["sveltejs/svelte", "020242d6bef059df9ae8c13dc8dbff4c9b31e0ff", "@aashutoshrathi/word-wrap@1.2.6"], // pnpm
  ["withastro/astro", "322cd139fadbfa0f1a897f3a3a2764a19f168a60", "@anthropic-ai/sdk@0.91.1"], // pnpm
  ["microsoft/TypeScript", "09b1db0617311f3b39f165bb3480c0ce2f718b27", "@azure/abort-controller@2.2.0"], // npm
  ["nodejs/undici", "f850c68967e3591b70f2f4f96ed6f4d58c76d10a", "@actions/core@2.0.3"], // npm
  ["nestjs/nest", "7fb52e7f4f7314fbc117e369a09297bc2ecadf6b", "@apollo/cache-control-types@1.0.3"], // npm
  ["npm/cli", "b317f16c80df02ea3628cfa77170d5ae9b59720c", "@actions/core@2.0.3"], // npm
  ["expressjs/express", "7ef98448f8b38099ab1ded55e458538ad47a51e7", null], // no lockfile
  ["eslint/eslint", "bc51eee6e3e816622b2dd1bc08acb9cfb2d3a6a7", null], // no lockfile
];

const { values: opt } = parseArgs({ options: { work: { type: "string" }, out: { type: "string", default: "fp-corpus.json" } } });
if (!opt.work) {
  process.stderr.write("usage: fp-corpus.mjs --work <dir> [--out <file.json>]\n");
  process.exit(2);
}
const cli = fileURLToPath(new URL("../dist/src/cli.js", import.meta.url));
if (!existsSync(cli)) throw new Error(`${cli} not found: run npm run build first`);

function run(cmd, args, env = {}) {
  const r = spawnSync(cmd, args, { encoding: "utf8", maxBuffer: 1 << 30, env: { ...process.env, ...env } });
  if (r.error) throw r.error;
  return r;
}
function git(dir, ...args) {
  // No hooks (ours or anyone's) and no LFS object downloads during checkout.
  const r = run("git", ["-C", dir, "-c", "core.hooksPath=/dev/null", ...args], { GIT_LFS_SKIP_SMUDGE: "1" });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")} in ${dir}: ${r.stderr}`);
  return r.stdout.trim();
}
function fetchAt(repo, sha) {
  const dir = join(opt.work, repo.replace("/", "__"));
  if (!existsSync(join(dir, ".git"))) {
    run("git", ["init", "-q", dir]);
    git(dir, "fetch", "-q", "--depth", "1", "--no-tags", `https://github.com/${repo}.git`, sha);
    git(dir, "-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD");
  }
  const head = git(dir, "rev-parse", "HEAD");
  if (head !== sha) throw new Error(`${dir} is at ${head}, expected ${sha}`);
  return dir;
}
const LOCKFILES = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"];
function lockfiles(dir) {
  return LOCKFILES.filter((n) => existsSync(join(dir, n))).map((n) => n !== "yarn.lock" ? n
    : `yarn.lock (${readFileSync(join(dir, n), "utf8").includes("\n__metadata:") ? "berry" : "classic"})`);
}
function scan(dir, ...args) {
  const r = run(process.execPath, [cli, "scan", dir, "--format", "json", "--fail-on", "never", ...args]);
  if (r.status !== 0) throw new Error(`scan of ${dir} exited ${r.status}: ${r.stderr}`);
  return JSON.parse(r.stdout);
}

// Positive control: a scan that parsed no lockfile would report no lockfile findings and
// look clean. So each root lockfile is also scanned alone, against a synthetic IOC set
// that lists only its canary, and must report WS-LK-001 for exactly that canary. A
// failed control is recorded and printed: that repository's lockfile was not checked.
const tmp = mkdtempSync(join(tmpdir(), "fp-corpus-"));
const controlIocs = join(tmp, "iocs");
cpSync(fileURLToPath(new URL("../test/fixtures/iocs", import.meta.url)), controlIocs, { recursive: true });
function control(dir, canary) {
  const at = canary.lastIndexOf("@");
  writeFileSync(join(controlIocs, "packages.json"), JSON.stringify({ schema: 1, sets: [{ id: "fp-corpus-control", wave: "control",
    source: "https://example.test/fp-corpus-control", packages: { [canary.slice(0, at)]: [canary.slice(at + 1)] } }] }));
  const alone = mkdtempSync(join(tmp, "lock-"));
  for (const n of LOCKFILES) if (existsSync(join(dir, n))) copyFileSync(join(dir, n), join(alone, n));
  const hits = scan(alone, "--iocs", controlIocs).findings.filter((f) => f.ruleId === "WS-LK-001").map((f) => f.key);
  return hits.length === 1 && hits[0] === canary ? "passed" : `FAILED: expected WS-LK-001 for ${canary}, got ${JSON.stringify(hits)}`;
}

// The scanner is named by the git tree IDs of the src/ and data/iocs/ it was built from, not by a commit ID: a tree ID
// is the same in any repository and at any commit that holds the same files, so the output stays checkable when the
// commit it ran on is not published. Uncommitted changes there would make the IDs name other code, so they stop the run.
const root = fileURLToPath(new URL("..", import.meta.url));
const dirty = git(root, "status", "--porcelain", "--", "src", "data/iocs");
if (dirty) throw new Error(`uncommitted changes under src/ or data/iocs/, which the scanner field could not name; commit them first:\n${dirty}`);
const self = { src: git(root, "rev-parse", "HEAD:src"), iocs: git(root, "rev-parse", "HEAD:data/iocs") };
const results = [];
for (const [repo, sha, canary] of CORPUS) {
  const dir = fetchAt(repo, sha);
  const lockfileControl = canary ? control(dir, canary) : "no lockfile";
  const report = scan(dir);
  const wf = join(dir, ".github", "workflows");
  results.push({
    repo, sha, lockfiles: lockfiles(dir), lockfileControl,
    workflows: existsSync(wf) ? readdirSync(wf).filter((f) => /\.ya?ml$/.test(f)).length : 0,
    notes: report.notes, findings: report.findings,
  });
  console.error(`${repo}: ${report.findings.length} finding(s); lockfile control ${lockfileControl}`);
}
rmSync(tmp, { recursive: true, force: true });
writeFileSync(opt.out, JSON.stringify({ scanner: self, retrieved: new Date().toISOString(), results }, null, 2) + "\n");

const rules = [...new Set(results.flatMap((r) => r.findings.map((f) => f.ruleId)))].sort();
const short = (repo) => repo.split("/")[1];
const row = (cells) => `| ${cells.join(" | ")} |`;
console.log(row(["rule", ...results.map((r) => short(r.repo)), "total"]));
console.log(row(Array(results.length + 2).fill("---")));
for (const id of rules) {
  const n = results.map((r) => r.findings.filter((f) => f.ruleId === id).length);
  console.log(row([id, ...n.map((x) => x || "."), n.reduce((a, b) => a + b, 0)]));
}
console.log(row(["lockfile control", ...results.map((r) => r.lockfileControl.split(":")[0]), ""]));
