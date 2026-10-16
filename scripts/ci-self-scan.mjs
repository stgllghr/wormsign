#!/usr/bin/env node
// Self-scan with a positive control: wormsign must pass on this repository, and must fail once an IOC-named
// workflow is added to it.
//
// Passing means no unbaselined finding at any severity (--fail-on info), not only none at or above the default
// high. Otherwise a medium finding in a new file passes CI and stays in every later scan's output unexplained: it is
// either changed or given a baseline entry with a justification, which the gate then reviews (WS-DF-005).
//
// A gate that passes proves little on its own: an over-broad baseline or a broken check also passes. So after the
// real scan this adds .github/workflows/shai-hulud-workflow.yml (inert, never committed, a published IOC name) to a
// copy of the repository and requires the scan to fail with WS-GH-001 on that file. Both scans read the copy's own
// .wormsign-baseline.json, so the control also proves the baseline does not hide new workflows.
//
// The copy holds the files git would commit (tracked plus untracked, minus .gitignore'd ones such as dist/ and
// node_modules/), so the result matches a fresh checkout whatever has been built locally.
//
// Usage: node scripts/ci-self-scan.mjs [repo-dir]   (default: this repository; needs a build: npm run build)
// Exit 0 when both hold, 1 when either fails, 2 on a setup error.
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../dist/src/cli.js", import.meta.url));
export const CONTROL = ".github/workflows/shai-hulud-workflow.yml";
const CONTROL_TEXT = "# Positive control written by scripts/ci-self-scan.mjs into a temporary copy. Inert.\non: workflow_dispatch\njobs: {}\n";
// The one threshold both scans use; the log prints this same value, so it always names the threshold that ran.
const FAIL_ON = "info";

/** Copies the files git would commit from repo into dest. Symlinks are copied as links, never followed. */
export function copyCommittable(repo, dest) {
  const out = execFileSync("git", ["-C", repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard"], { encoding: "utf8" });
  for (const rel of new Set(out.split("\0").filter(Boolean))) {
    const from = join(repo, rel);
    // A tracked file deleted in the working tree is not part of what would be committed.
    const st = lstatSync(from, { throwIfNoEntry: false });
    if (!st) continue;
    mkdirSync(dirname(join(dest, rel)), { recursive: true });
    // git commits a symlink as its target text. cpSync stats what a link points at and stops on a directory, so a
    // link is written as a link here, whatever it points at.
    if (st.isSymbolicLink()) symlinkSync(readlinkSync(from), join(dest, rel));
    else cpSync(from, join(dest, rel));
  }
}

function scan(dir, extra) {
  return spawnSync(process.execPath, [CLI, "scan", dir, "--fail-on", FAIL_ON, ...extra], { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
}

export function selfScan(repo) {
  const work = mkdtempSync(join(tmpdir(), "wormsign-self-scan-"));
  // The JSON report goes outside the scanned copy.
  const out = mkdtempSync(join(tmpdir(), "wormsign-self-scan-report-"));
  try {
    copyCommittable(repo, work);
    console.log(`== wormsign scan of ${repo} (committable files) at --fail-on ${FAIL_ON}`);
    const clean = scan(work, []);
    process.stdout.write(clean.stdout.replaceAll(work, "<copy>"));
    if (clean.status !== 0) {
      console.log(`FAIL: the self-scan exited ${clean.status}, expected 0`);
      return 1;
    }
    console.log(`== positive control: the same scan with ${CONTROL} added must fail`);
    mkdirSync(join(work, ".github", "workflows"), { recursive: true });
    writeFileSync(join(work, CONTROL), CONTROL_TEXT);
    const json = join(out, "report.json");
    const mutant = scan(work, ["--format", "json", "--output", json]);
    const report = mutant.status === 0 || mutant.status === 1 ? JSON.parse(readFileSync(json, "utf8")) : { findings: [] };
    const hit = report.findings.some((f) => f.ruleId === "WS-GH-001" && f.file === CONTROL && !f.suppressed);
    if (mutant.status !== 1 || !hit) {
      console.log(`FAIL: with ${CONTROL} added the scan exited ${mutant.status} (expected 1) and ${hit ? "did" : "did not"} report WS-GH-001 for it`);
      return 1;
    }
    console.log(`ok: the scan exits 1 and reports WS-GH-001 for ${CONTROL}`);
    return 0;
  } finally {
    rmSync(work, { recursive: true, force: true });
    rmSync(out, { recursive: true, force: true });
  }
}

// Compared as real paths: Node resolves symlinks for the entry module, so a script reached through a symlinked
// directory would otherwise never run main() and exit 0 without doing anything.
if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.exit(selfScan(resolve(process.argv[2] ?? fileURLToPath(new URL("..", import.meta.url)))));
  } catch (e) {
    console.error(`ci-self-scan: ${e.message}`);
    process.exit(2);
  }
}
