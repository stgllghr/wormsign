import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { makeContext } from "../src/checks/context.js";
import { bundledIocDir, loadIocDir } from "../src/iocs.js";
import { scanDirectory } from "../src/scan.js";

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));

// harden-dev.sh H11 loads the IOC data through wormsign's loader but grades name-only matches in
// bash (high/critical FAIL, medium/low WARN, info nothing), so it can drift from the scanner's
// WS-FS-002. Plant a harmless file for every listed name and compare the verdicts.
test("harden-dev H11 and the scanner flag the same harmless files by name alone", () => {
  const iocs = loadIocDir(bundledIocDir);
  const listed = [...new Set([...iocs.hashes, ...iocs.names].map((e) => e.name).filter((n) => !n.startsWith("(")))];
  const home = mkdtempSync(join(tmpdir(), "ws-home-"));
  assert.notEqual(home, homedir());
  const app = join(home, "code", "app");
  const benignWorkflow = "name: ci\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
  for (const n of listed) {
    const dir = /\.ya?ml$/.test(n) ? join(app, ".github", "workflows") : join(app, "lib");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, n), /\.ya?ml$/.test(n) ? benignWorkflow : "{}\n");
  }

  const scanned = scanDirectory(app, makeContext(iocs), { nodeModules: false }).findings
    .filter((f) => f.ruleId.startsWith("WS-FS-") && f.file !== undefined)
    .map((f) => `${basename(f.file as string)} ${f.severity === "high" || f.severity === "critical" ? "FAIL" : "WARN"}`);
  const r = spawnSync("bash", [join(repoRoot, "harden-dev.sh"), "--check", "--offline"], { env: { ...process.env, HOME: home, XDG_CACHE_HOME: join(home, ".cache") }, encoding: "utf8" });
  const flagged = [...r.stdout.matchAll(/^\[(WARN|FAIL)\] H11 +(\S+) has a worm payload file name/gm)].map((m) => `${basename(m[2] as string)} ${m[1]}`);

  assert.ok(flagged.includes("setup_bun.js FAIL"), `positive control: H11 must see the planted files\n${r.stdout}${r.stderr}`);
  assert.deepEqual(flagged.sort(), scanned.sort());
});

// The docs describe H03's pnpm cutoff in three places; the script is the source of truth. A doc left saying "passes any
// pnpm 10" after the script started failing 10.0 to 10.25 is the drift this catches.
test("docs agree with harden-dev.sh on H03's pnpm cutoff", async () => {
  const { readFileSync } = await import("node:fs");
  const script = readFileSync(join(repoRoot, "harden-dev.sh"), "utf8");
  const cutoff = /elif ! version_ge "\$PNPM_V" (\d+\.\d+); then\n\s*# GHSA-379q-355j-w6rj/.exec(script)?.[1];
  assert.equal(cutoff, "10.26", "positive control: the script's cutoff is found");
  const hardening = readFileSync(join(repoRoot, "docs", "hardening.md"), "utf8");
  const row = hardening.split("\n").find((l) => l.startsWith("| H03 |")) ?? "";
  assert.match(row, new RegExp(`10\\.0 to 10\\.${Number(cutoff!.split(".")[1]) - 1}\\b.*fixed in ${cutoff!.replace(".", "\\.")}\\.0`), row);
  for (const doc of ["docs/hardening.md", "docs/threat-model.md", "docs/soak.md", "docs/faq.md", "README.md"]) {
    assert.doesNotMatch(readFileSync(join(repoRoot, doc), "utf8"), /passes any pnpm 10/, doc);
  }
});
