// --output writes the report to a regular file only. The documented paths (wormsign.sarif, evidence/...) lie inside
// the checked-out tree, which can commit that name as a symlink to a shell startup file; the report quotes the
// tree's script text, so following the link would write attacker text there.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { run } from "../src/main.js";
import { neutralise } from "../src/report.js";
import { fakeIO, fx } from "./helpers.js";

const CLI = fileURLToPath(new URL("../src/cli.js", import.meta.url));
const posix = process.platform !== "win32";
const tree = (): string => {
  const d = mkdtempSync(join(tmpdir(), "wormsign-output-"));
  writeFileSync(join(d, "package.json"), JSON.stringify({ name: "x", version: "1.0.0", scripts: { postinstall: "echo $(touch PWNED)" } }));
  return d;
};

test("--output refuses a symlink, to an existing file or to none, and writes nothing through it", async () => {
  const d = tree();
  const victim = join(d, "victim_rc");
  writeFileSync(victim, "export PATH=/usr/bin\n");
  symlinkSync(victim, join(d, "wormsign.sarif"));
  const io = fakeIO();
  assert.equal(await run(["scan", d, "--format", "sarif", "--output", join(d, "wormsign.sarif")], io), 2);
  assert.match(io.err, /cannot write --output .*wormsign\.sarif: it is a symlink/);
  assert.equal(readFileSync(victim, "utf8"), "export PATH=/usr/bin\n");
  // A dangling link: following it would create its target.
  symlinkSync(join(d, "created_rc"), join(d, "dangling.sarif"));
  assert.equal(await run(["scan", d, "--output", join(d, "dangling.sarif")], fakeIO()), 2);
  assert.equal(existsSync(join(d, "created_rc")), false);
});

test("--output refuses a device or a FIFO without waiting on it", { skip: !posix }, () => {
  const d = tree();
  const dev = spawnSync(process.execPath, [CLI, "scan", d, "--output", "/dev/null"], { encoding: "utf8", timeout: 30_000 });
  assert.equal(dev.status, 2, dev.stderr);
  assert.match(dev.stderr, /cannot write --output \/dev\/null: it is not a regular file/);
  const fifo = join(d, "report.fifo");
  execFileSync("mkfifo", [fifo]);
  // With nobody reading the FIFO, a blocking open would wait for ever; the timeout turns that into a failure here.
  const r = spawnSync(process.execPath, [CLI, "scan", d, "--output", fifo], { encoding: "utf8", timeout: 30_000 });
  assert.equal(r.signal, null, "the scan hung on the FIFO");
  assert.equal(r.status, 2, r.stderr);
});

test("--output replaces a regular file's content and creates a new one with mode 0644 whatever the umask", { skip: !posix }, async () => {
  const d = tree();
  const out = join(d, "report.json");
  writeFileSync(out, "x".repeat(100_000));
  assert.equal(await run(["scan", fx("clean"), "--format", "json", "--output", out], fakeIO()), 0);
  assert.equal((JSON.parse(readFileSync(out, "utf8")) as { findings: unknown[] }).findings.length, 0, "the old content is gone, not left after the report");
  const fresh = join(d, "fresh.json");
  const r = spawnSync("/bin/sh", ["-c", 'umask 000 && exec "$0" "$1" scan "$2" --format json --output "$3"', process.execPath, CLI, fx("clean"), fresh], { encoding: "utf8", timeout: 60_000 });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(statSync(fresh).mode & 0o777, 0o644);
});

test("a crash outside run(), a callback's exception or an unawaited rejection, exits 2 with an internal error, not 1", { skip: !posix }, () => {
  // Node's own code for an uncaught exception is 1, which wormsign gives to findings at the threshold.
  const preload = fx("crash", "after-start.mjs");
  const d = mkdtempSync(join(tmpdir(), "wormsign-crash-"));
  for (const [mode, message] of [["throw", "injected crash\n::error::second line"], ["reject", "injected rejection"]] as const) {
    const r = spawnSync(process.execPath, ["--import", preload, CLI, "scan", d, "--no-baseline"], { encoding: "utf8", timeout: 30_000, env: { ...process.env, CRASH: mode } });
    assert.equal(r.status, 2, `${mode}: ${r.stderr}`);
    // One message, neutralised line by line like run()'s, and no stack.
    assert.ok(r.stderr.endsWith(`wormsign: internal error: ${message.split("\n").map(neutralise).join("\n")}\n`), `${mode}: ${r.stderr}`);
    assert.doesNotMatch(r.stderr, /^::error::/m, `${mode}: a workflow command in the message is neutralised`);
    assert.doesNotMatch(r.stderr, /^\s+at /m, mode);
  }
});
