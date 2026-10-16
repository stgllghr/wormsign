// Wave replays: test/fixtures/replay/<wave>/ is an inert reconstruction of what each reported wave writes (see the
// README.md in each). Each replay must produce exactly these rule IDs, and this exit code, through scan, through diff
// of a pull request that adds it to an empty repository, and through soak --base of that same pull request; and the
// README's recommended pull-request gate, which runs all three, must fail it. A rule that stops firing, or a new one
// that starts, fails here and must be explained in the replay's README.md and in docs/validation.md.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fx } from "./helpers.js";
import { BUNDLED_IOCS, cli, fakeNet, gitRepo, ruleIds, stubBin, type Outcome } from "./validation-helpers.js";

interface Expected {
  rules: string[];
  /** Exit code at the default --fail-on high: 1 fails the CI gate, 0 passes it. */
  code: number;
}

const REPLAYS: Record<string, { scan: Expected; diff: Expected; soak: Expected }> = {
  "2025-09": {
    // Known miss: WS-GH-005 does not fire on `curl -d "$CONTENTS"`: CONTENTS is bound to toJSON(secrets), and the
    // env-binding check counts only `secrets.X` / `secrets[...]` as a secret. WS-GH-002 reports the dump itself.
    scan: { rules: ["WS-GH-001", "WS-GH-002", "WS-LC-001", "WS-LC-003"], code: 1 },
    diff: { rules: ["WS-DF-002", "WS-DF-003", "WS-GH-001", "WS-GH-002", "WS-LC-003"], code: 1 },
    // No lockfile, so nothing to age; the missing release-age setting is medium without --require-config.
    soak: { rules: ["WS-SK-003"], code: 0 },
  },
  "2025-11": {
    // Known miss: WS-GH-005 does not fire on the formatter workflow, for two separate reasons: DATA is bound to
    // toJSON(secrets) (as in 2025-09), and its heredoc names $DATA on the line after the `>` that writes the file.
    scan: { rules: ["WS-FS-002", "WS-GH-001", "WS-GH-002", "WS-GH-004", "WS-GH-007", "WS-LC-001", "WS-LC-003"], code: 1 },
    diff: { rules: ["WS-DF-002", "WS-DF-003", "WS-GH-001", "WS-GH-002", "WS-GH-004", "WS-GH-007", "WS-LC-003"], code: 1 },
    soak: { rules: ["WS-SK-003"], code: 0 },
  },
  "2026-04": {
    // Known gap: nothing scan or diff reports is high, so each passes on its own. `node setup.mjs` matches no
    // heuristic and setup.mjs is not a payload-name IOC; the .vscode/.claude hook files match no rule; the git
    // dependency is WS-LK-002, medium. soak fails closed on that same dependency: WS-SK-002, high (test below).
    scan: { rules: ["WS-LC-001", "WS-LK-002"], code: 0 },
    diff: { rules: ["WS-DF-002", "WS-LK-002"], code: 0 },
    soak: { rules: ["WS-SK-002", "WS-SK-003"], code: 1 },
  },
  "2026-08": {
    // The package alone gives only WS-LC-001 (medium); the gate fails on the injected workflow's toJSON(secrets) and on
    // the folder-open task and SessionStart hook (WS-PS-001/002, high), rebuilt from JFrog's description of what they run.
    // WS-GH-005 misses its secret-to-file write for the same two reasons as 2025-11.
    scan: { rules: ["WS-GH-001", "WS-GH-002", "WS-LC-001", "WS-PS-001", "WS-PS-002"], code: 1 },
    diff: { rules: ["WS-DF-002", "WS-DF-003", "WS-GH-001", "WS-GH-002", "WS-PS-001", "WS-PS-002"], code: 1 },
    soak: { rules: ["WS-SK-003"], code: 0 },
  },
};

const USE_BUNDLED = ["--iocs", BUNDLED_IOCS];
const GIT_DIR = dirname(execFileSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).trim());

/** A pull request that adds the replay to an empty repository: HEAD~1 is the base, HEAD the change. */
const pullRequest = (wave: string): string => gitRepo([() => {}, (dir) => cpSync(fx("replay", wave), dir, { recursive: true })]);

/**
 * The three commands the README's Action snippet runs on a pull request, each at its defaults (--fail-on high, a
 * 7-day soak, OSV on, no --require-config): diff (the Action's default there), scan, and soak with the pull request's
 * base (the Action's soak passes --base on pull_request). soak gets a fake registry and OSV that know no package, stub
 * package managers on PATH and an empty HOME, so nothing on the machine or the network decides its result.
 */
async function gate(repo: string): Promise<{ diff: Outcome; scan: Outcome; soak: Outcome & { requests: string[] } }> {
  const diff = await cli(["diff", "HEAD~1", "HEAD", "--dir", repo, ...USE_BUNDLED]);
  const scan = await cli(["scan", repo, ...USE_BUNDLED]);
  const net = fakeNet();
  const home = mkdtempSync(join(tmpdir(), "wormsign-replay-home-"));
  const env = { PATH: `${stubBin()}:${GIT_DIR}`, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_CACHE_HOME: join(home, ".cache") };
  const soak = await cli(["soak", repo, "--base", "HEAD~1"], { env, fetchImpl: net.fetchImpl });
  return { diff, scan, soak: { ...soak, requests: net.calls } };
}

for (const [wave, want] of Object.entries(REPLAYS)) {
  test(`replay ${wave}: scan reports exactly the expected rules and gate verdict`, async () => {
    const res = await cli(["scan", fx("replay", wave), ...USE_BUNDLED]);
    assert.deepEqual({ rules: ruleIds(res.findings), code: res.code }, want.scan);
  });

  test(`replay ${wave}: diff of a pull request adding it to an empty repository reports exactly the expected rules and gate verdict`, async () => {
    const res = await cli(["diff", "HEAD~1", "HEAD", "--dir", pullRequest(wave), ...USE_BUNDLED]);
    assert.deepEqual({ rules: ruleIds(res.findings), code: res.code }, want.diff);
  });

  test(`replay ${wave}: the README's recommended pull-request gate (diff, scan, soak --base) reports the expected rules and fails`, async () => {
    const r = await gate(pullRequest(wave));
    assert.deepEqual({ rules: ruleIds(r.diff.findings), code: r.diff.code }, want.diff);
    assert.deepEqual({ rules: ruleIds(r.soak.findings), code: r.soak.code }, want.soak);
    // A git source and a missing lockfile are decided without asking the registry or OSV anything.
    assert.deepEqual(r.soak.requests, []);
    assert.equal(Math.max(r.diff.code, r.scan.code, r.soak.code), 1, "one failing step fails the job");
  });
}

test("replay 2026-04: soak fails the git dependency that diff reports only as medium, so the recommended gate fails what scan and diff pass", async () => {
  const r = await gate(pullRequest("2026-04"));
  const entry = "@tanstack/setup@0.0.0";
  const lk = r.diff.findings.filter((f) => f.ruleId === "WS-LK-002");
  assert.deepEqual(lk.map((f) => `${f.severity} ${f.file} ${f.key.split(" ")[0]}`), [`medium tanstack-route/package-lock.json ${entry}`]);
  assert.equal(r.diff.code, 0, "diff alone passes");
  assert.equal(r.scan.code, 0, "scan alone passes");
  const sk = r.soak.findings.filter((f) => f.ruleId === "WS-SK-002");
  assert.deepEqual(sk.map((f) => `${f.severity} ${f.file}`), ["high tanstack-route/package-lock.json"]);
  assert.equal(sk[0]?.message, `Cannot verify soak time for ${entry}: it resolves from a git source (git+https://git.wormsign-replay.invalid/tanstack/router.git), which has no registry publish time`);
  assert.equal(r.soak.code, 1, "soak fails the gate");
});

test("stubBin: one directory per configuration for the whole test process, removed when the process exits", () => {
  // Each call used to leave a directory behind: hundreds after a few runs on a disk parallel runs have filled.
  const helpers = new URL("./validation-helpers.js", import.meta.url).href;
  const out = execFileSync(process.execPath, ["--input-type=module", "-e", `import { stubBin } from ${JSON.stringify(helpers)}; console.log(JSON.stringify([stubBin(), stubBin(), stubBin("x")]));`], { encoding: "utf8" });
  const [a, b, c] = JSON.parse(out) as string[];
  assert.equal(a, b, "the same configuration, the same directory");
  assert.notEqual(a, c);
  assert.deepEqual([existsSync(a!), existsSync(c!)], [false, false], "removed at exit");
});
