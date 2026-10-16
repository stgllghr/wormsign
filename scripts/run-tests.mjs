#!/usr/bin/env node
// Runs `node --test` with TMPDIR, TMP and TEMP pointed at one fresh directory, and removes that directory afterwards.
//
// The tests create a temporary project per case (over a hundred mkdtempSync calls) and do not delete them one by one.
// Hundreds of parallel runs once left about 465,000 such directories and filled a disk, so cleanup is owned here, in
// one place, whatever a test does or however it fails.
//
// Each test file gets ten minutes (node --test runs each file as one subtest of the run, and --test-timeout caps that
// subtest, not the tests in it), so a hang (for example under a mutant) fails that file instead of stalling the run.
// The slowest file takes about a minute and a half on a loaded machine.
//
// Usage: node scripts/run-tests.mjs <test files or globs...>   (node --test expands the globs itself)
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "wormsign-tests-"));
let status;
try {
  const env = { ...process.env, TMPDIR: root, TMP: root, TEMP: root };
  const run = spawnSync(process.execPath, ["--test", "--test-reporter=spec", "--test-timeout=600000", ...process.argv.slice(2)], { stdio: "inherit", env });
  status = run.status ?? 1;
} finally {
  try {
    rmSync(root, { recursive: true, force: true });
  } catch {
    // Some tests make directories unreadable on purpose; make everything writable again, then remove it.
    spawnSync("chmod", ["-R", "u+rwX", root]);
    rmSync(root, { recursive: true, force: true });
  }
}
process.exit(status);
