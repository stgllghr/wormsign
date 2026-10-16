/**
 * Fingerprints, and the digests of content that finding keys carry, keep 32 hex characters (128 bits) of SHA-256. A
 * baseline entry approves a fingerprint, so this length is what binds an approval to the content it was given for:
 * other content with an approved value takes about 2^128 hashes to find, and a crafted pair about 2^64
 * (docs/baseline.md#fingerprints). Every digest goes through src/types.ts, so one length holds everywhere.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { checkLifecycle } from "../src/checks/lifecycle.js";
import { checkPersistence } from "../src/checks/persistence.js";
import { checkWorkflow } from "../src/checks/workflows.js";
import { scanDirectory } from "../src/scan.js";
import { FINGERPRINT_HEX, KEY_DIGEST_HEX, fingerprint, keyDigest } from "../src/types.js";
import { fx, testCtx } from "./helpers.js";

const ROOT = join(import.meta.dirname, "..", "..");
const sha256 = (s: string): string => createHash("sha256").update(s).digest("hex");

test("digests: a fingerprint and a key's content digest are the first 32 hex characters of SHA-256", () => {
  assert.equal(FINGERPRINT_HEX, 32);
  assert.equal(KEY_DIGEST_HEX, 32);
  assert.equal(keyDigest("node setup.js"), sha256("node setup.js").slice(0, 32));
  assert.equal(keyDigest(Buffer.from("node setup.js")), keyDigest("node setup.js"), "bytes and text digest alike");
  assert.equal(fingerprint("WS-LC-001", "package.json", "k"), sha256("WS-LC-001\0package.json\0k").slice(0, 32));
});

test("digests: the keys rules build carry 32-hex digests of the content a baseline entry approves", () => {
  const cmd = "node setup.js";
  const lc = checkLifecycle("package.json", JSON.stringify({ name: "p", version: "1.0.0", scripts: { postinstall: cmd } }), testCtx());
  assert.deepEqual(lc.map((f) => `${f.ruleId} ${f.key}`), [`WS-LC-001 postinstall:${sha256(cmd).slice(0, 32)}`]);

  const wf = checkWorkflow(".github/workflows/ci.yml", "on: push\njobs:\n  build:\n    runs-on: self-hosted\n    steps:\n      - run: echo hi\n", testCtx());
  assert.deepEqual(wf.filter((f) => f.ruleId === "WS-GH-004").map((f) => f.key), [`self-hosted:build:${sha256("runs-on: self-hosted").slice(0, 32)}`]);

  const task = { label: "Setup", type: "shell", command: "node .claude/setup.mjs", runOptions: { runOn: "folderOpen" } };
  const ps = checkPersistence(".vscode/tasks.json", JSON.stringify({ version: "2.0.0", tasks: [task] }), testCtx());
  assert.ok(ps.length > 0 && ps.every((f) => /:[0-9a-f]{32}$/.test(f.key)), ps.map((f) => f.key).join(" | "));

  // More local specs than are listed one by one: the summary's key digests every key it stands for.
  const many = Object.fromEntries(Array.from({ length: 60 }, (_, i) => [`d${i}`, `file:node_modules/d${i}`]));
  const summary = checkLifecycle("package.json", JSON.stringify({ name: "p", version: "1.0.0", dependencies: many }), testCtx()).at(-1);
  assert.match(summary?.key ?? "", /[^0-9a-f][0-9a-f]{32}$/, summary?.key);

  // Every key of the synthetic malicious project that ends in a digest (lifecycle scripts, workflow lines, an editor
  // task, an agent hook): 32 hex characters, never the 12 or 16 that keys used to keep.
  const keys = scanDirectory(fx("malicious"), testCtx(), { nodeModules: false }).findings.map((f) => `${f.ruleId} ${f.key}`);
  const digests = keys.flatMap((k) => /:([0-9a-f]{12,})$/.exec(k)?.slice(1) ?? []);
  assert.ok(digests.length >= 8, `${digests.length} digests in ${keys.join(" | ")}`);
  assert.deepEqual(digests.filter((d) => d.length !== 32), []);
});

test("digests: no source file truncates a SHA-256 to a length of its own", () => {
  const files: string[] = [];
  const walk = (dir: string): void => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory() && e.name !== "vendor") walk(p);
      else if (e.isFile() && e.name.endsWith(".ts")) files.push(p);
    }
  };
  walk(join(ROOT, "src"));
  assert.ok(files.length > 40, `${files.length} source files`);
  const own: string[] = [];
  for (const f of files) {
    for (const m of readFileSync(f, "utf8").matchAll(/\.digest\("hex"\)\.(?:slice|substring|substr)\(([^)]*)\)/g)) {
      if (!["0, FINGERPRINT_HEX", "0, KEY_DIGEST_HEX"].includes(m[1] as string)) own.push(`${relative(ROOT, f)}: ${m[0]}`);
    }
  }
  assert.deepEqual(own, [], "use keyDigest() from src/types.ts");
});
