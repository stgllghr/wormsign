import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { scan, gateExitCode, renderReport, UsageError } from "../src/index.js";
import type { ScanOptions } from "../src/index.js";
import { bundledIocDir } from "../src/iocs.js";
import { fx } from "./helpers.js";

function project(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "ws-library-"));
  for (const [file, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, file)), { recursive: true });
    writeFileSync(join(root, file), text);
  }
  return root;
}

test("library: scan preserves findings and notes without network, execution or baseline suppressions", t => {
  t.mock.method(globalThis, "fetch", () => { throw new Error("scan attempted network access"); });
  const root = project({ "package.json": '{"scripts":{"postinstall":"node marker.js"}}', "marker.js": 'require("node:fs").writeFileSync("executed", "yes")', ".github/workflows/shai-hulud-workflow.yml": "on: push\njobs: {}\n" });
  const first = scan(root);
  assert.equal(gateExitCode(first.findings), 1);
  assert.ok(first.findings.some(f => f.ruleId === "WS-GH-001"));
  assert.ok(first.notes.some(n => n.includes("IOC data")));
  const baseline = JSON.stringify({ version: 1, ignorePaths: [{ path: ".github", justification: "A repository must not grant itself scanning exceptions" }], entries: first.findings.map(f => ({ fingerprint: f.fingerprint, justification: "A repository must not grant itself scanning exceptions" })) });
  writeFileSync(join(root, ".wormsign-baseline.json"), baseline);
  const again = scan(root);
  assert.ok(again.findings.some(f => f.ruleId === "WS-GH-001" && !f.suppressed));
  assert.equal(again.filesIgnored, 0);
  assert.equal(readFileSync(join(root, ".wormsign-baseline.json"), "utf8"), baseline);
  assert.throws(() => readFileSync(join(root, "executed")), { code: "ENOENT" });
});

test("library: default IOC data ignores the ambient user cache; an explicit trusted directory is honored", () => {
  const cacheHome = project({});
  const cache = join(cacheHome, "wormsign/iocs");
  cpSync(bundledIocDir, cache, { recursive: true });
  for (const name of ["packages", "files", "workflows", "repos", "endpoints"]) {
    const path = join(cache, name + ".json");
    const doc = JSON.parse(readFileSync(path, "utf8"));
    doc.version = "2099-01-01";
    if (name === "workflows") doc.workflowFiles.push({ name: "library-cache-marker.yml", severity: "critical", wave: "inert-test", source: "https://example.test/inert-ioc" });
    writeFileSync(path, JSON.stringify(doc));
  }
  const root = project({ ".github/workflows/library-cache-marker.yml": "on: push\njobs: {}\n" });
  const prior = process.env["XDG_CACHE_HOME"];
  process.env["XDG_CACHE_HOME"] = cacheHome;
  try {
    assert.ok(!scan(root).findings.some(f => f.ruleId === "WS-GH-001"));
    assert.ok(scan(root, { iocsDirectory: cache }).findings.some(f => f.ruleId === "WS-GH-001"));
  } finally {
    if (prior === undefined) delete process.env["XDG_CACHE_HOME"];
    else process.env["XDG_CACHE_HOME"] = prior;
  }
  assert.ok(scan(fx("malicious"), { iocsDirectory: fx("iocs") }).findings.some(f => f.ruleId === "WS-LK-001" && f.key.includes("wormsign-test-marker")));
  assert.throws(() => scan(root, { iocsDirectory: join(cacheHome, "missing") }), UsageError);
});

test("library: explicit registry hosts and hash-all reach the existing scanner", () => {
  const root = project({ "package.json": "{}", "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/example": { version: "1.0.0", resolved: "https://registry.example.test/example/-/example-1.0.0.tgz", integrity: "sha512-AAAA" } } }), "ordinary.txt": "inert library hash marker" });
  assert.ok(scan(root).findings.some(f => f.ruleId === "WS-LK-002"));
  assert.ok(!scan(root, { registryHosts: ["registry.example.test"] }).findings.some(f => f.ruleId === "WS-LK-002"));
  const iocs = project({});
  cpSync(fx("iocs"), iocs, { recursive: true });
  const path = join(iocs, "files.json"), files = JSON.parse(readFileSync(path, "utf8"));
  files.hashes.push({ sha256: createHash("sha256").update("inert library hash marker").digest("hex"), name: "(unnamed inert marker)", wave: "test", source: "https://example.test/inert-ioc" });
  writeFileSync(path, JSON.stringify(files));
  assert.ok(!scan(root, { iocsDirectory: iocs }).findings.some(f => f.ruleId === "WS-FS-001"));
  assert.ok(scan(root, { iocsDirectory: iocs, hashAll: true }).findings.some(f => f.ruleId === "WS-FS-001" && f.file === "ordinary.txt"));
});

test("library: installed package scanning is explicit and uses the same findings", () => {
  assert.ok(!scan(fx("nm"), { iocsDirectory: fx("iocs") }).findings.some(f => f.ruleId === "WS-NM-001"));
  assert.ok(scan(fx("nm"), { nodeModules: true, iocsDirectory: fx("iocs") }).findings.some(f => f.ruleId === "WS-NM-001"));
});

test("library: invalid JavaScript inputs throw UsageError and unchecked project files remain findings", () => {
  for (const options of [null, [], "flags", { baseline: "untrusted" }, { ignorePrefixes: ["."] }, { nodeModules: "false" }, { hashAll: 1 }, { iocsDirectory: "" }, { registryHosts: "npmjs.org" }, { registryHosts: ["https://registry.example.test"] }, { registryHosts: [null] }]) {
    assert.throws(() => scan(fx("clean"), options as unknown as ScanOptions), UsageError);
  }
  for (const root of ["", "  ", null, 3]) assert.throws(() => scan(root as string), UsageError);
  const root = project({ "package.json": "not json" });
  assert.ok(scan(root).findings.some(f => f.ruleId === "WS-SC-900"));
  assert.throws(() => scan(join(root, "missing")), UsageError);
});

test("library: threshold and report helpers retain CLI semantics and validate severity", () => {
  const result = scan(project({ "package.json": "not json" }));
  assert.equal(gateExitCode(result.findings), 1);
  assert.equal(gateExitCode(result.findings, "critical"), 0);
  assert.equal(gateExitCode(result.findings, "never"), 0);
  assert.throws(() => gateExitCode([], "hihg" as "high"), UsageError);
  const report = { command: "scan", findings: result.findings, notes: result.notes, toolVersion: "test" };
  assert.equal(JSON.parse(renderReport(report, "json")).findings[0].ruleId, "WS-SC-900");
  assert.equal(JSON.parse(renderReport(report, "sarif")).version, "2.1.0");
});
