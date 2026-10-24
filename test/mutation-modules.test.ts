/**
 * The mutation check's modules: every scripts/mutants-<module>.mjs is loaded, listed by --list-modules and run by its
 * own job in ci.yml's mutation matrix, which is built from --list-modules, so a module file cannot go unrun and a
 * deleted one leaves no job behind. No mutant of this repository is run; one scratch mutant is, on a scratch copy.
 *
 * Never run --check against this repository here: during a mutation run this test runs in the mutated copy, where the
 * mutated file no longer holds its mutant's text, so --check would fail and every mutant would count as killed.
 * The --check behaviour is tested on a scratch copy instead; CI's "mutation list is current" job runs it for real.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = join(import.meta.dirname, "..", "..");

function mutationWithEnv(root: string, override: Record<string, string>, ...args: string[]): { status: number | null; out: string; err: string } {
  // Without NODE_TEST_CONTEXT, which node:test sets in this file's process: a suite the script runs would inherit it,
  // and its own node --test would then report to this run in V8's serialized form, not as the spec reporter.
  const env = { ...process.env, ...override };
  delete env.NODE_TEST_CONTEXT;
  const r = spawnSync(process.execPath, [join(root, "scripts", "mutation-check.mjs"), ...args], { encoding: "utf8", env });
  return { status: r.status, out: r.stdout, err: r.stderr };
}
function mutation(root: string, ...args: string[]): { status: number | null; out: string; err: string } { return mutationWithEnv(root, {}, ...args); }

const moduleFiles = (root: string): string[] =>
  readdirSync(join(root, "scripts"))
    .filter((f) => /^mutants-.*\.mjs$/.test(f))
    .map((f) => f.slice("mutants-".length, -".mjs".length))
    .sort();

/** The text of one job in a workflow: its key line and every line indented under it. */
function job(workflow: string, name: string): string {
  const m = new RegExp(`^ {2}${name}:\\n((?: {4}.*\\n|\\n)*)`, "m").exec(workflow);
  assert.ok(m, `job ${name}`);
  return m[1] as string;
}

test("mutation: every module holds at most 18 mutants, so its CI job stays well within its timeout", async () => {
  // Each mutant reruns the whole suite; scripts/mutation-check.mjs says how the cap follows from the suite's time.
  const sizes: Record<string, number> = {};
  for (const m of moduleFiles(ROOT)) sizes[m] = ((await import(pathToFileURL(join(ROOT, "scripts", `mutants-${m}.mjs`)).href)) as { default: unknown[] }).default.length;
  assert.ok(Object.keys(sizes).length >= 20, `${Object.keys(sizes).length} modules`);
  assert.deepEqual(Object.entries(sizes).filter(([, n]) => n > 18), [], "split a module that grows past 18 by area");
  assert.match(readFileSync(join(ROOT, "scripts", "mutation-check.mjs"), "utf8"), /^const MAX_PER_MODULE = 18;$/m);
});

test("mutation: every scripts/mutants-*.mjs is listed by --list-modules, which is ci.yml's mutation matrix", () => {
  const files = moduleFiles(ROOT);
  const listed = mutation(ROOT, "--list-modules");
  assert.equal(listed.status, 0, listed.err);
  assert.deepEqual(JSON.parse(listed.out), files);

  // The matrix is --list-modules' output, so a module file is a CI job with no edit to ci.yml.
  const ci = readFileSync(join(ROOT, ".github", "workflows", "ci.yml"), "utf8");
  const modules = job(ci, "mutation-modules");
  // Both jobs run on the monthly schedule and on demand with `slow` only (each mutant reruns the whole suite), and with
  // the same condition, so the matrix is listed exactly when the mutation job runs. A plain `gh workflow run ci.yml`,
  // which a maintainer runs on a pull request the gate fails by design, starts none of them, nor the macOS job.
  const when = /^ {4}if: github\.event_name == 'schedule' \|\| \(github\.event_name == 'workflow_dispatch' && inputs\.slow\)$/m;
  assert.match(modules, when, "listed on the schedule and on demand with slow only, as the mutation job runs");
  assert.match(job(ci, "harden-macos"), when, "the macOS job too");
  assert.match(ci, /^ {2}workflow_dispatch:\n {4}inputs:\n {6}slow:\n {8}description: .+\n {8}type: boolean\n {8}default: false$/m, "slow is a boolean input that defaults to false");
  assert.match(modules, /^ {4}outputs:\n {6}modules: \$\{\{ steps\.list\.outputs\.modules \}\}$/m, "the job's output is its list step's");
  assert.match(modules, /^ {6}- id: list\n {8}run: \|\n {10}modules="\$\(node scripts\/mutation-check\.mjs --list-modules\)"\n {10}echo "modules=\$modules" >> "\$GITHUB_OUTPUT"$/m, "the list step writes --list-modules to its output, failing if the script fails");
  const full = job(ci, "mutation");
  assert.match(full, /^ {4}needs: mutation-modules$/m);
  assert.match(full, when, "the mutation job runs on the schedule and on demand with slow only");
  assert.match(full, /^ {6}fail-fast: false\n {6}matrix:\n {8}module: \$\{\{ fromJSON\(needs\.mutation-modules\.outputs\.modules\) \}\}$/m, "one job per listed module; one failing module does not cancel the others");
  assert.match(full, /^ {10}MODULE: \$\{\{ matrix\.module \}\}$/m, "the selected module comes from the matrix");
  assert.match(full, /^ {10}npm run mutation -- --module "\$MODULE" 2>&1 \| tee "\$RUNNER_TEMP\/mutation\.log"$/m, "each job runs only its module and retains its transcript");
  const minutes = Number(/^ {4}timeout-minutes: (\d+)$/m.exec(full)?.[1]);
  assert.ok(minutes > 0 && minutes <= 120, `per-module timeout ${minutes} minutes`);
  assert.match(job(ci, "mutation-list"), /^ {6}- run: npm run mutation -- --check$/m, "every pull request checks every module's list");
});

test("mutation: --module, --only and --check work across modules; bad module files stop the run", () => {
  const d = mkdtempSync(join(tmpdir(), "ws-mutants-"));
  mkdirSync(join(d, "scripts"));
  mkdirSync(join(d, "src"));
  copyFileSync(join(ROOT, "scripts", "mutation-check.mjs"), join(d, "scripts", "mutation-check.mjs"));
  writeFileSync(join(d, "src", "a.ts"), "const a = 1;\n");
  writeFileSync(join(d, "src", "b.ts"), "const b = 1;\nconst c = 1;\n");
  writeFileSync(join(d, "scripts", "mutants-alpha.mjs"), 'export default [["A1", "src/a.ts", "const a = 1;", "const a = 2;"]];\n');
  writeFileSync(join(d, "scripts", "mutants-beta-2.mjs"), 'export default [["B1", "src/b.ts", "const b = 1;", ""], ["B2", "src/b.ts", "const c = 1;", "const c = 2;"]];\n');

  assert.deepEqual(JSON.parse(mutation(d, "--list-modules").out), ["alpha", "beta-2"]);
  assert.equal(mutation(d, "--check").out, "3 mutants, every one names text that occurs exactly once\n");
  assert.equal(mutation(d, "--module", "beta-2", "--check").out, "2 mutants, every one names text that occurs exactly once\n");
  assert.equal(mutation(d, "--only", "A1,B2", "--check").out, "2 mutants, every one names text that occurs exactly once\n", "--only reaches every module");
  const outside = mutation(d, "--module", "alpha", "--only", "B2", "--check");
  assert.equal(outside.status, 1);
  assert.match(outside.err, /--only names no mutant in module alpha: B2/);
  const unknown = mutation(d, "--module", "gamma", "--check");
  assert.equal(unknown.status, 1);
  assert.match(unknown.err, /--module names no module: gamma \(modules: alpha, beta-2\)/);
  assert.match(mutation(d, "--module").err, /--module needs a value/);
  for (const typo of [["--modul", "alpha", "--check"], ["--modules", "alpha", "--check"], ["--chek"], ["alpha"]]) {
    const r = mutation(d, ...typo);
    assert.equal(r.status, 1, `${typo.join(" ")}: an unknown argument stops the run instead of running every module`);
    assert.match(r.err, new RegExp(`^unknown argument: ${typo[0]}\\nusage: `), typo.join(" "));
  }

  // Sorted by module name, as moduleFiles() sorts: by file name "beta-2" (".mjs" after "-") would come before "beta".
  writeFileSync(join(d, "scripts", "mutants-beta.mjs"), 'export default [["B0", "src/a.ts", "const a = 1;", ""]];\n');
  assert.deepEqual(JSON.parse(mutation(d, "--list-modules").out), ["alpha", "beta", "beta-2"]);
  assert.deepEqual(moduleFiles(d), ["alpha", "beta", "beta-2"]);
  rmSync(join(d, "scripts", "mutants-beta.mjs"));

  writeFileSync(join(d, "src", "a.ts"), "const a = 3;\n");
  const stale = mutation(d, "--module", "beta-2", "--check");
  assert.equal(stale.status, 0, "a stale mutant in another module does not fail --module beta-2");
  const all = mutation(d, "--check");
  assert.equal(all.status, 1);
  assert.match(all.err, /^STALE {2}A1: src\/a\.ts no longer contains its text exactly once/m);
  writeFileSync(join(d, "src", "a.ts"), "const a = 1;\n");

  const bad: [file: string, text: string, error: RegExp][] = [
    ["mutants-gamma.mjs", 'export default [["A1", "src/b.ts", "const c = 1;", ""]];\n', /two mutants are named "A1"/],
    ["mutants-gamma.mjs", 'export default [["--g1 flag", "src/b.ts", "const c = 1;", ""]];\n', /a mutant is named "--g1 flag"; a name must not start with "--", or --only cannot select it/],
    ["mutants-Gamma.mjs", 'export default [["G1", "src/b.ts", "const c = 1;", ""]];\n', /a module name is lower-case letters, digits and single hyphens/],
    ["mutants-gamma.mjs", "export default [];\n", /must be a non-empty array/],
    ["mutants-gamma.mjs", 'export default [["G1", "src/b.ts", "", "x"]];\n', /must be a non-empty array of \[name, file, search, replace\] strings/],
    [
      "mutants-gamma.mjs",
      `export default ${JSON.stringify(Array.from({ length: 19 }, (_, i) => [`G${i}`, "src/b.ts", "const c = 1;", ""]))};\n`,
      /^scripts\/mutants-gamma\.mjs: 19 mutants, more than the 18 a module may hold so that its CI job stays within its timeout; split it by area$/m,
    ],
  ];
  for (const [file, text, error] of bad) {
    writeFileSync(join(d, "scripts", file), text);
    for (const args of [["--list-modules"], ["--check"]]) {
      const r = mutation(d, ...args);
      assert.equal(r.status, 1, `${file} ${args[0]}`);
      assert.match(r.err, error, `${file} ${args[0]}`);
    }
    rmSync(join(d, "scripts", file));
  }
  // At the cap a module loads.
  writeFileSync(join(d, "scripts", "mutants-gamma.mjs"), `export default ${JSON.stringify(Array.from({ length: 18 }, (_, i) => [`G${i}`, "src/b.ts", "const c = 1;", ""]))};\n`);
  assert.deepEqual(JSON.parse(mutation(d, "--list-modules").out), ["alpha", "beta-2", "gamma"]);
  rmSync(join(d, "scripts", "mutants-gamma.mjs"));
  assert.deepEqual(moduleFiles(d), ["alpha", "beta-2"]);
});

test("mutation: when the unmutated suite fails, the log says why: each failed test's assertion, its first stack frames, and a test node:test cancelled", () => {
  // A scratch repository whose `npm test` runs one test file through the real scripts/run-tests.mjs, so the output
  // is the spec reporter's own; its one mutant breaks the file the tests read.
  const d = mkdtempSync(join(tmpdir(), "ws-mutation-why-"));
  for (const dir of ["scripts", "src", "node_modules"]) mkdirSync(join(d, dir));
  for (const f of ["mutation-check.mjs", "run-tests.mjs"]) copyFileSync(join(ROOT, "scripts", f), join(d, "scripts", f));
  // On failure the script adds a line to stderr after the suite's report, as npm's own error lines come.
  const npmTest = `"${process.execPath}" scripts/run-tests.mjs t.test.mjs || { echo "npm error the test script failed" >&2; exit 1; }`;
  writeFileSync(join(d, "package.json"), JSON.stringify({ name: "scratch", private: true, type: "module", scripts: { test: npmTest } }));
  writeFileSync(join(d, "scripts", "mutants-alpha.mjs"), 'export default [["A1", "src/a.txt", "ok", "bad"]];\n');
  writeFileSync(
    join(d, "t.test.mjs"),
    [
      'import { test } from "node:test";',
      'import assert from "node:assert/strict";',
      'import { readFileSync } from "node:fs";',
      'const said = () => readFileSync(new URL("./src/a.txt", import.meta.url), "utf8").trim();',
      // A failure eight calls deep, so its stack has more frames than the log shows.
      'const deep = (n) => (n === 0 ? assert.equal(said(), "ok") : deep(n - 1));',
      'test("the file says ok", () => deep(8));',
      // A subtest that never ends, under a parent with a timeout: node:test cancels it and the one it never started,
      // which has no time on its line.
      'test("a parent out of time", { timeout: 200 }, async (t) => {',
      '  const first = t.test("a subtest that never ends", () => (said() === "ok" ? undefined : new Promise(() => {})));',
      '  await Promise.all([first, t.test("the subtest after it", () => {})]);',
      "});",
      "",
    ].join("\n"),
  );

  writeFileSync(join(d, "src", "a.txt"), "not ok\n");
  const broken = mutation(d);
  assert.equal(broken.status, 1, broken.out + broken.err);
  assert.match(broken.err, /^the unmutated suite does not pass in .+ \(fail: the file says ok; a subtest that never ends; the subtest after it\), so no mutant result would mean anything\nwhy, from the suite's output:\n/);
  const why = broken.err.slice(broken.err.indexOf("why, from the suite's output:\n"));
  // The assertion's message and diff, and the stack frame in the test file, under the test's location and name.
  assert.match(why, /^test at t\.test\.mjs:6:\d+\n✖ the file says ok \(\d[\d.]*ms\)\n {2}AssertionError \[ERR_ASSERTION\]: Expected values to be strictly equal:\n(?: *\n)? {2}'not ok' !== 'ok'\n/m);
  const first = why.slice(0, why.indexOf("\n\ntest at "));
  assert.match(first, /^ +at deep \(.*t\.test\.mjs:5:\d+\)$/m, "the frame that failed");
  assert.equal(first.split("\n").filter((l) => /^\s+at /.test(l)).length, 5, "its first five frames");
  assert.match(first, /^ {6}\.\.\. \d+ more stack frame\(s\)\n {2}\{\n {4}generatedMessage: true,$/m, "and how many more there were");
  assert.match(first, /^ {4}actual: 'not ok',\n {4}expected: 'ok',$/m, "and what it compared");
  // A test cancelled before it started has no time on its line: it is named, and so is why. Node 22 and 23 cancel both
  // subtests when the event loop runs out of work (nothing holds it during the wait), as in CI; Node 24 holds the loop
  // for a running test, and its parent's timeout cancels them.
  const cancelled = "'(?:Promise resolution is still pending but the event loop has already resolved|test did not finish before its parent and was cancelled)'";
  assert.match(why, new RegExp(`^✖ a subtest that never ends \\(\\d[\\d.]*ms\\)\\n {2}${cancelled}$`, "m"));
  assert.match(why, new RegExp(`^✖ the subtest after it\\n {2}${cancelled}$`, "m"));
  assert.doesNotMatch(why, /npm (error|ERR!)/, "npm's own lines are no test's");

  // Positive control: an unmutated suite that passes prints no why, and the mutant that breaks it is killed, with its
  // failed tests named.
  writeFileSync(join(d, "src", "a.txt"), "ok\n");
  const fine = mutation(d);
  assert.equal(fine.status, 0, fine.out + fine.err);
  assert.doesNotMatch(fine.err, /why, from the suite's output/);
  assert.match(fine.out, /^baseline: the unmutated suite passes /m);
  assert.match(fine.out, /^killed {5}A1 \(\d failing: the file says ok; a subtest that never ends\)$/m);
  assert.match(fine.out, /^1\/1 mutants killed in \d+ min$/m);
});

test("mutation: process and compilation failures retain their diagnostic and never count as killed mutants", () => {
  for (const mode of ["signal", "compile"] as const) {
    const d = mkdtempSync(join(tmpdir(), "ws-mutation-process-"));
    for (const name of ["scripts", "src", "node_modules", "bin"]) mkdirSync(join(d, name));
    copyFileSync(join(ROOT, "scripts/mutation-check.mjs"), join(d, "scripts/mutation-check.mjs"));
    writeFileSync(join(d, "scripts/mutants-alpha.mjs"), 'export default [["A1", "src/a.txt", "ok", "bad"]];\n');
    writeFileSync(join(d, "src/a.txt"), "ok");
    // This private fake npm makes no network request and executes no package code. Git still uses the normal PATH.
    writeFileSync(join(d, "bin/npm"), [
      `#!${process.execPath}`,
      "const f=require('node:fs');if(f.readFileSync('src/a.txt','utf8')==='ok')process.exit(0);",
      mode === "signal" ? "f.writeSync(1,('x'.repeat(16*1024)+'\\n').repeat(35));f.writeSync(1,'inert signalled suite diagnostic\\n');process.kill(process.pid,'SIGTERM');" : "f.writeSync(2,'src/a.ts(1,1): error TS1234: inert compilation diagnostic\\n');process.exit(2);",
    ].join("\n"), { mode: 0o700 });
    const result = mutationWithEnv(d, { PATH: join(d, "bin") + ":" + (process.env.PATH ?? "") });
    assert.equal(result.status, 1, result.out + result.err);
    assert.match(result.out, mode === "signal" ? /^TIMEOUT +A1$/m : /^NO-COMPILE +A1/m);
    assert.match(result.out, /^0\/1 mutants killed in \d+ min$/m);
    assert.match(result.err, /^why for A1:/m);
    assert.ok(result.err.length < 15000, "unverified process diagnostics must stay bounded even with very long suite output lines");
    if (mode === "signal") { assert.match(result.err, /process error code none; process signal SIGTERM/); assert.match(result.err, /inert signalled suite diagnostic/); }
    else assert.match(result.err, /error TS1234: inert compilation diagnostic/);
  }
});


test("mutation: compiler diagnostics inside an actual failed test are test failures, not project build failures", () => {
  const d = mkdtempSync(join(tmpdir(), "ws-mutation-consumer-types-"));
  for (const name of ["scripts", "src", "node_modules"]) mkdirSync(join(d, name));
  for (const name of ["mutation-check.mjs", "run-tests.mjs"]) copyFileSync(join(ROOT, "scripts", name), join(d, "scripts", name));
  writeFileSync(join(d, "package.json"), JSON.stringify({ name: "scratch", private: true, type: "module", scripts: { test: `"${process.execPath}" scripts/run-tests.mjs consumer.test.mjs` } }));
  writeFileSync(join(d, "scripts/mutants-alpha.mjs"), 'export default [["A1", "src/a.txt", "ok", "bad"]];\n');
  writeFileSync(join(d, "consumer.test.mjs"), [
    'import { test } from "node:test";',
    'import assert from "node:assert/strict";',
    'import { readFileSync } from "node:fs";',
    'test("external TypeScript consumer", () => {',
    '  if (readFileSync("src/a.txt", "utf8") !== "ok") assert.fail("consumer.mts(1,1): error TS7016: inert missing declarations");',
    '});',
  ].join("\n"));
  writeFileSync(join(d, "src/a.txt"), "not ok");
  const broken = mutation(d);
  assert.equal(broken.status, 1, broken.out + broken.err);
  assert.match(broken.err, /\(fail: external TypeScript consumer\)/);
  assert.match(broken.err, /error TS7016: inert missing declarations/);
  writeFileSync(join(d, "src/a.txt"), "ok");
  const killed = mutation(d);
  assert.equal(killed.status, 0, killed.out + killed.err);
  assert.match(killed.out, /^killed +A1 \(1 failing: external TypeScript consumer\)$/m);
});
