#!/usr/bin/env node
// Mutation check: does the test suite notice when a rule or safety property is switched off?
//
// Each mutant names one file, an exact piece of its text and a replacement that disables the core condition of a
// rule or a fail-closed property. For each mutant this copies the repository to a temporary directory, applies the
// one change, runs `npm test` (build, then every test) and records whether the suite failed (killed) or passed
// (survived). Exit 1 if any mutant survives, does not compile, or names text the file no longer contains exactly
// once, so the list cannot rot silently. Before any mutant, the unchanged copy must pass: otherwise a failure would
// prove nothing. When it does not, the script prints why: each failed test's error from the reporter's output, its
// message and first stack frames, so a CI log that stops there can be read without a rerun.
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

/** At most this many failed tests, this many lines of each one's error and this many of its stack frames are printed. */
const SHOWN_TESTS = 5;
const SHOWN_LINES = 30;
const SHOWN_FRAMES = 5;

/**
 * The failed tests in the spec reporter's closing "✖ failing tests:" list, each with its name and its block: the
 * "test at <file>:<line>:<column>" line, the "✖ <name> (<time>)" line (a test node:test cancelled has no time) and the
 * error under it, message first, with only its first SHOWN_FRAMES stack frames. Colour codes are dropped. Empty when
 * the output has no such list.
 */
function failures(out) {
  // eslint-disable-next-line no-control-regex -- an ANSI colour code starts with ESC
  const lines = out.replace(/\x1b\[[0-9;]*m/g, "").split(/\r?\n/);
  const start = lines.findLastIndex((l) => /^\s*✖ failing tests:\s*$/.test(l));
  if (start === -1) return [];
  const blocks = [];
  for (const line of lines.slice(start + 1)) {
    const last = blocks.at(-1);
    // A block starts at its location line, or at its ✖ line when the reporter knew no file.
    if (/^test at \S.*:\d+:\d+$/.test(line) || (/^\s*✖ /.test(line) && !(last?.lines.length === 1 && last.lines[0].startsWith("test at ")))) blocks.push({ name: undefined, lines: [], frames: 0, more: -1 });
    const block = blocks.at(-1);
    if (block === undefined) continue;
    const title = block.name === undefined ? /^\s*✖ (.+?)(?: \(\d[\d.]*m?s\))?$/.exec(line) : null;
    if (title) block.name = title[1];
    const frame = /^(\s+)at /.exec(line);
    if (frame && ++block.frames > SHOWN_FRAMES) {
      // In place of the frames not shown, one line that counts them, at their indent.
      if (block.more === -1) block.more = block.lines.push(frame[1]) - 1;
      // The last frame's line opens the error's own properties ("... (file:1:2) {"), which are shown.
      if (line.endsWith(" {")) block.lines.push(`${frame[1].slice(4)}{`);
      continue;
    }
    block.lines.push(line);
  }
  return blocks
    .filter((b) => b.name !== undefined)
    .map((b) => {
      if (b.more !== -1) b.lines[b.more] += `... ${b.frames - SHOWN_FRAMES} more stack frame(s)`;
      while (b.lines.at(-1)?.trim() === "") b.lines.pop();
      const lines = b.lines.slice(0, SHOWN_LINES).map((l) => (l.length > 300 ? `${l.slice(0, 300)}...` : l));
      if (b.lines.length > SHOWN_LINES) lines.push(`  ... ${b.lines.length - SHOWN_LINES} more line(s)`);
      return { name: b.name, text: lines.join("\n") };
    });
}

/**
 * Runs the suite in the copy: "pass", "fail" (with the failing test names), "no-compile" or "timeout", and `why`: what
 * the output says about it, for a log to show. For a failure that is each failed test's block from the reporter's list
 * (failures()), or, when the output has none (a crash before the reporter's summary, a build that failed), its last
 * lines; for a compile error the compiler's errors; for a timeout the output's last lines.
 */
function suite() {
  // Each test file has its own timeout (scripts/run-tests.mjs); this backstop catches a hang outside any file.
  const r = spawnSync("npm", ["test"], { cwd: work, encoding: "utf8", maxBuffer: 256 * 1024 * 1024, timeout: 20 * 60_000, killSignal: "SIGKILL" });
  const out = `${r.stdout ?? ""}${r.stderr ?? ""}`;
  const tail = (n) => `the output's last ${n} lines:\n${out.trimEnd().split(/\r?\n/).slice(-n).join("\n")}`;
  if (r.error || r.signal) return { status: "timeout", failed: [], why: `process error code ${r.error?.code ?? "none"}; process signal ${r.signal ?? "none"}\n${tail(30)}` };
  if (r.status === 0) return { status: "pass", failed: [], why: "" };
  // The reporter writes to stdout; npm's own error lines follow on stderr and are no test's.
  const listed = failures(r.stdout ?? "");
  if (listed.length > 0) {
    const shown = listed.slice(0, SHOWN_TESTS).map((f) => f.text);
    if (listed.length > SHOWN_TESTS) shown.push(`... and ${listed.length - SHOWN_TESTS} more failed test(s)`);
    return { status: "fail", failed: [...new Set(listed.map((f) => f.name))], why: shown.join("\n\n") };
  }
  // A consumer test can quote compiler diagnostics in its assertion. Its real failed-test footer takes
  // precedence; a project build failure never reaches the test runner and has no such footer.
  if (/error TS\d+/.test(out)) return { status: "no-compile", failed: [out.match(/error TS\d+[^\n]*/)?.[0] ?? ""], why: [...out.matchAll(/^.*error TS\d+.*$/gm)].slice(0, 10).map((m) => m[0]).join("\n") };
  // No list to read: every "✖ <name> (<time>)" line, deduplicated, and the output's end.
  const failed = [...new Set([...out.matchAll(/^\s*✖ (.+?) \(\d[\d.]*m?s\)$/gm)].map((m) => m[1]))];
  return { status: "fail", failed, why: tail(30) };
}

function diagnostic(value) {
  return value.split(/\r?\n/).slice(0, 40).map((line) => line.length > 300 ? line.slice(0, 300) + "..." : line).join("\n");
}

process.on("exit", () => rmSync(work, { recursive: true, force: true }));
const t0 = Date.now();
const base = suite();
if (base.status !== "pass") {
  console.error(`the unmutated suite does not pass in ${work} (${base.status}: ${base.failed.slice(0, 3).join("; ")}), so no mutant result would mean anything`);
  console.error(`why, from the suite's output:\n${base.why || "(the suite printed nothing)"}`);
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
  if (r.status === "timeout" || r.status === "no-compile") console.error(`why for ${name}:\n${diagnostic(r.why || "(the suite printed nothing)")}`);
}

const bad = results.filter((r) => r.verdict !== "killed");
console.log(`\n${results.length - bad.length}/${results.length} mutants killed in ${Math.round((Date.now() - t0) / 60000)} min`);
if (bad.length > 0) {
  console.log(`not killed: ${bad.map((r) => `${r.name} (${r.verdict})`).join("; ")}`);
  process.exit(1);
}
