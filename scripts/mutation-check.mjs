#!/usr/bin/env node
// Mutation check: does the test suite notice when a rule or safety property is switched off?
//
// Each mutant names one file, an exact piece of its text and a replacement that disables the core condition of a
// rule or a fail-closed property. For each mutant this copies the repository to a temporary directory, applies the
// one change, runs `npm test` (build, then every test) and records whether the suite failed (killed) or passed
// (survived). Exit 1 if any mutant survives, does not compile, or names text the file no longer contains exactly
// once, so the list cannot rot silently. Before any mutant, the unchanged copy must pass: otherwise a failure would
// prove nothing.
//
// Mutants live in modules, one file each: scripts/mutants-<module>.mjs exports a default array of
// [name, file, search, replace]. Every such file is loaded, and a mutant's name is unique across all of them. CI runs
// one job per module (the matrix in .github/workflows/ci.yml, built from --list-modules). A module holds at most
// MAX_PER_MODULE mutants, so that its job stays well within its timeout (below); one that grows past it stops every run,
// --check and --list-modules included, until it is split by area.
//
// Usage: node scripts/mutation-check.mjs [--module <name>] [--check] [--only <name>[,<name>...]] [--list-modules]
//   --module <name>  only that module's mutants
//   --check          only verify that every mutant's text still occurs exactly once (fast, no tests run)
//   --only           only the named mutants, from any module
//   --list-modules   print the module names as a JSON array and exit
// Runs mutants one at a time: the suite has timing assertions that parallel runs could fail spuriously.
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

const fail = (message) => {
  console.error(message);
  process.exit(1);
};

// CI picks the module by flag, so a mistyped flag must stop the run, not fall through to every mutant.
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--check" || args[i] === "--list-modules") continue;
  if (args[i] === "--module" || args[i] === "--only") {
    if (args[i + 1] !== undefined && !args[i + 1].startsWith("--")) i++; // its value; a missing one is reported below
    continue;
  }
  fail(`unknown argument: ${args[i]}\nusage: node scripts/mutation-check.mjs [--module <name>] [--check] [--only <name>[,<name>...]] [--list-modules]`);
}

/**
 * Each mutant reruns the whole suite, build included: about two minutes on the machine the figures in
 * docs/evidence/test-runs.md#mutation-check come from. Estimated at twice that on a GitHub runner, a module of 18 mutants plus the unmutated
 * run is 19 x 240 s, about 75 minutes: well within the job's 120-minute timeout.
 */
const MAX_PER_MODULE = 18;

/**
 * Module name -> its mutants, from every scripts/mutants-<module>.mjs, sorted by module name (not file name, which
 * would put "python-readers" before "python": "-" sorts before ".").
 */
const MODULES = new Map();
const moduleNames = readdirSync(join(ROOT, "scripts"))
  .filter((f) => f.startsWith("mutants-") && f.endsWith(".mjs"))
  .map((f) => f.slice("mutants-".length, -".mjs".length))
  .sort();
for (const name of moduleNames) {
  const file = `mutants-${name}.mjs`;
  if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(name)) fail(`scripts/${file}: a module name is lower-case letters, digits and single hyphens`);
  const list = (await import(pathToFileURL(join(ROOT, "scripts", file)).href)).default;
  // The replacement may be empty (a mutant that deletes its text); the other three may not.
  const shaped = Array.isArray(list) && list.length > 0 && list.every((m) => Array.isArray(m) && m.length === 4 && m.every((x, i) => typeof x === "string" && (x !== "" || i === 3)));
  if (!shaped) fail(`scripts/${file}: the default export must be a non-empty array of [name, file, search, replace] strings`);
  if (list.length > MAX_PER_MODULE) fail(`scripts/${file}: ${list.length} mutants, more than the ${MAX_PER_MODULE} a module may hold so that its CI job stays within its timeout; split it by area`);
  MODULES.set(name, list);
}
if (MODULES.size === 0) fail("no scripts/mutants-*.mjs found");
const MUTANTS = [...MODULES].flatMap(([moduleName, list]) => list.map((m) => [...m, moduleName]));
const duplicate = MUTANTS.map(([name]) => name).find((name, i, all) => all.indexOf(name) !== i);
if (duplicate !== undefined) fail(`two mutants are named "${duplicate}"; names must be unique across modules`);
// --only takes the names as one argument, and a value that starts with "--" reads as a missing one.
const dashed = MUTANTS.find(([name]) => name.startsWith("--"));
if (dashed !== undefined) fail(`a mutant is named "${dashed[0]}"; a name must not start with "--", or --only cannot select it`);

if (args.includes("--list-modules")) {
  console.log(JSON.stringify([...MODULES.keys()]));
  process.exit(0);
}
const valueOf = (flag) => {
  const at = args.indexOf(flag);
  if (at === -1) return undefined;
  const v = args[at + 1];
  if (v === undefined || v.startsWith("--")) fail(`${flag} needs a value`);
  return v;
};
const moduleName = valueOf("--module");
if (moduleName !== undefined && !MODULES.has(moduleName)) fail(`--module names no module: ${moduleName} (modules: ${[...MODULES.keys()].join(", ")})`);
const onlyArg = valueOf("--only");
const only = onlyArg === undefined ? undefined : new Set(onlyArg.split(","));
const inModule = MUTANTS.filter((m) => moduleName === undefined || m[4] === moduleName);
const selected = inModule.filter(([name]) => !only || only.has(name));
if (only && selected.length !== only.size) {
  fail(`--only names no mutant${moduleName === undefined ? "" : ` in module ${moduleName}`}: ${[...only].filter((n) => !inModule.some(([m]) => m === n)).join(", ")}`);
}

const count = (text, s) => text.split(s).length - 1;
const stale = selected.filter(([, file, search]) => count(readFileSync(join(ROOT, file), "utf8"), search) !== 1);
for (const [name, file, search] of stale) console.error(`STALE  ${name}: ${file} no longer contains its text exactly once: ${JSON.stringify(search.slice(0, 80))}`);
if (stale.length > 0) process.exit(1);
if (args.includes("--check")) {
  console.log(`${selected.length} mutants, every one names text that occurs exactly once`);
  process.exit(0);
}

// A copy without .git, dist and node_modules; node_modules is linked, as in the worktrees.
const work = mkdtempSync(join(tmpdir(), "wormsign-mutation-"));
const skip = new Set([".git", "dist", "node_modules"]);
cpSync(ROOT, work, { recursive: true, filter: (src) => !skip.has(src.slice(ROOT.length).split(/[\\/]/).filter(Boolean)[0] ?? "") });
symlinkSync(realpathSync(join(ROOT, "node_modules")), join(work, "node_modules"), "dir");
// Some tests run diff against the git repository they are in, so the copy is made one.
for (const a of [["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "mutation baseline"]]) {
  const r = spawnSync("git", ["-c", "user.email=m@m.invalid", "-c", "user.name=m", "-c", "commit.gpgsign=false", ...a], { cwd: work, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`git ${a[0]} failed in ${work}: ${r.stderr}`);
}

/** Runs the suite in the copy: "pass", "fail" (with the failing test names), "no-compile" or "timeout". */
function suite() {
  // Each test file has its own timeout (scripts/run-tests.mjs); this backstop catches a hang outside any file.
  const r = spawnSync("npm", ["test"], { cwd: work, encoding: "utf8", maxBuffer: 256 * 1024 * 1024, timeout: 20 * 60_000, killSignal: "SIGKILL" });
  if (r.error || r.signal) return { status: "timeout", failed: [] };
  const out = `${r.stdout}${r.stderr}`;
  if (r.status === 0) return { status: "pass", failed: [] };
  if (/error TS\d+/.test(out)) return { status: "no-compile", failed: [out.match(/error TS\d+[^\n]*/)?.[0] ?? ""] };
  // The spec reporter marks each failed test "✖ <name> (<time>)"; the summary repeats them, so deduplicate.
  const failed = [...new Set([...out.matchAll(/^\s*✖ (.+?) \(\d[\d.]*m?s\)$/gm)].map((m) => m[1]))];
  return { status: "fail", failed };
}

process.on("exit", () => rmSync(work, { recursive: true, force: true }));
const t0 = Date.now();
const base = suite();
if (base.status !== "pass") {
  console.error(`the unmutated suite does not pass in ${work} (${base.status}: ${base.failed.slice(0, 3).join("; ")}), so no mutant result would mean anything`);
  process.exit(1);
}
console.log(`baseline: the unmutated suite passes (${Math.round((Date.now() - t0) / 1000)}s); running ${selected.length} mutants one at a time`);

const results = [];
for (const [name, file, search, replace] of selected) {
  const path = join(work, file);
  const original = readFileSync(path, "utf8");
  writeFileSync(path, original.replace(search, () => replace));
  const r = suite();
  writeFileSync(path, original);
  const verdict = r.status === "fail" ? "killed" : r.status === "pass" ? "SURVIVED" : r.status === "timeout" ? "TIMEOUT" : "NO-COMPILE";
  results.push({ name, verdict, failed: r.failed });
  console.log(`${verdict.padEnd(10)} ${name}${r.failed.length ? ` (${r.failed.length} failing: ${r.failed.slice(0, 2).join("; ").slice(0, 160)})` : ""}`);
}

const bad = results.filter((r) => r.verdict !== "killed");
console.log(`\n${results.length - bad.length}/${results.length} mutants killed in ${Math.round((Date.now() - t0) / 60000)} min`);
if (bad.length > 0) {
  console.log(`not killed: ${bad.map((r) => `${r.name} (${r.verdict})`).join("; ")}`);
  process.exit(1);
}
