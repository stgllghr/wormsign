import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));

function consumer(): string {
  const dir = mkdtempSync(join(tmpdir(), "ws-library-consumer-"));
  mkdirSync(join(dir, "node_modules"));
  symlinkSync(ROOT, join(dir, "node_modules", "wormsign"), "dir");
  writeFileSync(join(dir, "package.json"), '{"private":true,"type":"module"}\n');
  return dir;
}

test("library: an external ESM consumer imports the public API without running the CLI", () => {
  const dir = consumer();
  const source = `
    import assert from "node:assert/strict";
    import * as api from "wormsign";
    assert.deepEqual(Object.keys(api).sort(), ["UsageError", "gateExitCode", "renderReport", "scan"]);
    const clean = api.scan(process.argv[1]);
    assert.equal(api.gateExitCode(clean.findings), 0);
    const positive = api.scan(process.argv[2]);
    assert.ok(positive.findings.some(f => f.ruleId === "WS-GH-002"));
    assert.equal(api.gateExitCode(positive.findings), 1);
    await assert.rejects(import("wormsign/dist/src/scan.js"), { code: "ERR_PACKAGE_PATH_NOT_EXPORTED" });
    console.log("library-consumer-ok");
  `;
  const run = spawnSync(process.execPath, ["--input-type=module", "-e", source, join(ROOT, "test/fixtures/clean"), join(ROOT, "test/fixtures/malicious")], { cwd: dir, encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  assert.equal(run.stdout, "library-consumer-ok\n");
});

test("library: an external strict TypeScript consumer resolves shipped types and rejects invalid calls", () => {
  const dir = consumer();
  writeFileSync(join(dir, "consumer.mts"), `
    import { scan, gateExitCode, renderReport, UsageError } from "wormsign";
    import type { Finding, Severity, ScanOptions, ScanResult, Report, Format } from "wormsign";
    const options: ScanOptions = { nodeModules: true, hashAll: true, registryHosts: ["registry.example.test"] };
    const result: ScanResult = scan(".", options);
    const findings: Finding[] = result.findings;
    const severity: Severity = "high";
    const exit: 0 | 1 = gateExitCode(findings, severity);
    const report: Report = { command: "scan", findings, notes: result.notes, toolVersion: "example" };
    const format: Format = "sarif";
    const rendered: string = renderReport(report, format);
    const error: Error = new UsageError("bad input");
    void [exit, rendered, error];
    // @ts-expect-error unknown severity must not become a permissive gate
    gateExitCode(findings, "hihg");
    // @ts-expect-error repository-controlled baselines are not library options
    scan(".", { baseline: "./.wormsign-baseline.json" });
    // @ts-expect-error nodeModules is a boolean, not a CLI string
    scan(".", { nodeModules: "false" });
  `);
  const run = spawnSync(process.execPath, [join(ROOT, "node_modules/typescript/bin/tsc"), "--noEmit", "--strict", "--module", "NodeNext", "--target", "ES2023", "--types", "node", "--typeRoots", join(ROOT, "node_modules/@types"), "consumer.mts"], { cwd: dir, encoding: "utf8" });
  assert.equal(run.status, 0, run.stdout + run.stderr);
});

test("library: release smoke runs the shipped examples and types from an external project", () => {
  const dir = consumer();
  const run = spawnSync(process.execPath, [join(ROOT, "scripts/ci-library-smoke.mjs"), dir, ROOT], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stdout + run.stderr);
  assert.match(run.stdout, /public import, example exits 0\/1\/2 and external TypeScript consumer passed/);
});
