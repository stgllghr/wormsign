import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ROOT = join(import.meta.dirname, "..", "..");
const workflow = (name: string): string => readFileSync(join(ROOT, ".github/workflows", name), "utf8");

function job(source: string, name: string): string {
  const match = new RegExp(`^  ${name}:\\n((?: {4}.*\\n|\\n)*)`, "m").exec(source);
  assert.ok(match, `missing job ${name}`);
  return match[1] as string;
}

test("release pipeline: both CI and releases install one built tarball on every supported Node major", () => {
  for (const [file, producer, artifact] of [["ci.yml", "build-package", "package-tarball"], ["release.yml", "build", "tarball"]] as const) {
    const source = workflow(file);
    const build = job(source, producer);
    const verify = job(source, "verify-package");
    assert.match(build, /outputs:\n +tarball: \$\{\{ steps\.pack\.outputs\.tarball \}\}/);
    assert.match(build, /uses: actions\/upload-artifact@[a-f0-9]{40}/);
    assert.match(build, new RegExp(`name: ${artifact}\\n +path: \\$\\{\\{ steps\\.pack\\.outputs\\.tarball \\}\\}`));
    assert.match(verify, new RegExp(`^    needs: ${producer}$`, "m"));
    assert.match(verify, /^ {6}fail-fast: false\n {6}matrix:\n {8}node: \[22, 24\]$/m);
    assert.match(verify, /^ {10}node-version: \$\{\{ matrix\.node \}\}$/m);
    assert.match(verify, /uses: actions\/download-artifact@[a-f0-9]{40}/);
    assert.match(verify, new RegExp(`name: ${artifact}(?:\\n|$)`));
    assert.match(verify, /^ {6}- run: npm ci --ignore-scripts$/m);
    assert.match(verify, /^ {8}run: scripts\/ci-pack-smoke\.sh "\$TARBALL"$/m);
    assert.match(verify, new RegExp(`TARBALL: \\$\\{\\{ needs\\.${producer}\\.outputs\\.tarball \\}\\}`));
    assert.match(verify, /^ {6}contents: read/m);
    assert.doesNotMatch(verify, /npm (?:pack|run build)|continue-on-error:|^ {4}if:|contents: write/m);
  }
});

test("release pipeline: publishing waits for all consumers of the exact build artifact", () => {
  const publish = job(workflow("release.yml"), "publish");
  assert.match(publish, /^ {4}needs: \[build, verify-package\]$/m);
  assert.doesNotMatch(publish, /always\(\)|continue-on-error:/);
  assert.match(publish, /name: tarball\n/);
  assert.match(publish, /subject-path: \$\{\{ needs\.build\.outputs\.tarball \}\}/);
});

test("release pipeline: mutation transcripts survive a failure without turning the job green", () => {
  const mutation = job(workflow("ci.yml"), "mutation");
  assert.match(mutation, /- name: Run and retain mutation diagnostics\n {8}shell: bash\n/);
  const run = / {8}run: \|\n((?: {10}.*\n|\n)*)/.exec(mutation)?.[1];
  assert.ok(run, "mutation shell step");
  const script = run.split("\n").map(line => line.slice(10)).join("\n");
  assert.match(mutation, /- name: Upload mutation diagnostics\n {8}if: always\(\)\n {8}uses: actions\/upload-artifact@[a-f0-9]{40}/);
  assert.match(mutation, /name: mutation-\$\{\{ matrix\.module \}\}/);
  assert.match(mutation, /path: \$\{\{ runner\.temp \}\}\/mutation\.log/);
  assert.match(mutation, /if-no-files-found: error/);
  const dir = mkdtempSync(join(tmpdir(), "ws-mutation-ci-log-"));
  mkdirSync(join(dir, "bin"));
  writeFileSync(join(dir, "bin/npm"), '#!/bin/sh\nprintf "%s\\n" "$*"\nprintf "inert diagnostic\\n" >&2\nexit "$FAKE_EXIT"\n', { mode: 0o755 });
  for (const status of [0, 1]) {
    const result = spawnSync("bash", ["-e", "-o", "pipefail", "-c", script], { cwd: dir, encoding: "utf8", env: {
      ...process.env, PATH: `${join(dir, "bin")}:${process.env["PATH"] ?? ""}`, MODULE: "library", RUNNER_TEMP: dir, FAKE_EXIT: String(status),
    } });
    assert.equal(result.status, status, result.stdout + result.stderr);
    assert.equal(readFileSync(join(dir, "mutation.log"), "utf8"), "run mutation -- --module library\ninert diagnostic\n");
  }
});


test("release pipeline: the existing required package check fails when an artifact consumer fails or skips", () => {
  const aggregate = job(workflow("ci.yml"), "package");
  assert.match(aggregate, /^ {4}name: npm pack and tarball smoke test$/m);
  assert.match(aggregate, /^ {4}needs: \[build-package, verify-package\]$/m);
  assert.match(aggregate, /^ {4}if: always\(\)$/m);
  assert.doesNotMatch(aggregate, /continue-on-error:/);
  assert.match(aggregate, /BUILD_RESULT: \$\{\{ needs\['build-package'\]\.result \}\}/);
  assert.match(aggregate, /CONSUMER_RESULT: \$\{\{ needs\['verify-package'\]\.result \}\}/);
  const script = /^ {6}- run: (.+)$/m.exec(aggregate)?.[1];
  assert.ok(script);
  for (const build of ["success", "failure", "skipped", "cancelled"]) {
    for (const consumer of ["success", "failure", "skipped", "cancelled"]) {
      const result: ReturnType<typeof spawnSync> = spawnSync("bash", ["-e", "-c", script], { encoding: "utf8", env: { ...process.env, BUILD_RESULT: build, CONSUMER_RESULT: consumer } });
      assert.equal(result.status, build === "success" && consumer === "success" ? 0 : 1, `${build}/${consumer}: ${result.stderr}`);
    }
  }
});
