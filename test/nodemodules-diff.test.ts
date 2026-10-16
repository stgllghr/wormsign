import { test } from "node:test";
import assert from "node:assert/strict";
import { scanDirectory } from "../src/scan.js";
import { diffTrees } from "../src/diff.js";
import { dirTree } from "../src/tree.js";
import { fx, testCtx } from "./helpers.js";

test("node-modules: not scanned unless asked, and the note says so", () => {
  const res = scanDirectory(fx("nm"), testCtx(), { nodeModules: false });
  assert.equal(res.findings.length, 0);
  assert.ok(res.notes.some((n) => n.includes("node_modules was not scanned")));
});

test("node-modules: every package with an install script is listed", () => {
  const res = scanDirectory(fx("nm"), testCtx(), { nodeModules: true });
  const nm = res.findings.filter((f) => f.ruleId === "WS-NM-001");
  assert.deepEqual(nm.map((f) => f.key).sort(), ["@scope/scoped-evil@0.0.1:preinstall", "evil-pkg@1.2.3:postinstall", "gyp-pkg@1.0.0:gyp"]);
  assert.ok(!nm.some((f) => f.key.startsWith("benign")), "a test script is not an install script");
});

test("node-modules: installed IOC package@version and payload hash are critical", () => {
  const res = scanDirectory(fx("nm"), testCtx(), { nodeModules: true });
  assert.ok(res.findings.some((f) => f.ruleId === "WS-LK-001" && f.key === "wormsign-test-marker@1.0.0" && f.severity === "critical"));
  assert.ok(res.findings.some((f) => f.ruleId === "WS-FS-001" && f.file?.endsWith("evil-pkg/wormsign_marker_loader.js")));
});

test("node-modules: suspicious script content in a dependency is surfaced", () => {
  const res = scanDirectory(fx("nm"), testCtx(), { nodeModules: true });
  assert.ok(res.findings.some((f) => f.ruleId === "WS-LC-002" && f.file?.includes("scoped-evil")));
});

const run = () => diffTrees(dirTree(fx("diff", "base")), dirTree(fx("diff", "head")), testCtx());
/** A key without the content hash diff appends to it. */
const unhashed = (key: string): string => key.replace(/:[0-9a-f]{32}$/, "");

test("diff: new dependency with install script is flagged, version bumps are classified", () => {
  const f = run().findings;
  assert.ok(f.some((x) => x.ruleId === "WS-DF-001" && x.key === "brand-new@2.0.0"));
  assert.ok(f.some((x) => x.ruleId === "WS-DF-004" && x.key === "bumped@1.1.0"), "dependency that gained install scripts");
  assert.ok(!f.some((x) => x.key === "scripty@1.0.1"), "already ran scripts before: version bump only");
  assert.ok(!f.some((x) => x.key.startsWith("old-dep")), "unchanged dependency is silent");
});

test("diff: new and changed lifecycle scripts", () => {
  const f = run().findings.filter((x) => x.ruleId === "WS-DF-002");
  assert.deepEqual(f.map((x) => unhashed(x.key)).sort(), ["postinstall:changed", "preinstall:added"]);
});

test("diff: new and modified workflows", () => {
  const f = run().findings.filter((x) => x.ruleId === "WS-DF-003");
  assert.deepEqual(f.map((x) => `${x.file}:${unhashed(x.key)}`).sort(), [".github/workflows/ci.yml:modified", ".github/workflows/new.yml:added"]);
});

test("diff: IOC match is reported only for entries the change introduced", () => {
  const f = run().findings.filter((x) => x.ruleId === "WS-LK-001");
  assert.deepEqual(f.map((x) => x.key), ["wormsign-test-marker@1.0.0"]);
  const same = diffTrees(dirTree(fx("diff", "head")), dirTree(fx("diff", "head")), testCtx());
  assert.deepEqual(same.findings, [], "identical trees produce nothing");
});

test("diff: pnpm/yarn lockfiles produce an explicit limitation note, not silence", () => {
  const base = { label: "b", list: () => ["pnpm-lock.yaml"], read: () => "lockfileVersion: '9.0'\n\npackages:\n" };
  const head = { label: "h", list: () => ["pnpm-lock.yaml"], read: () => "lockfileVersion: '9.0'\n\npackages:\n\n  a@1.0.0:\n    resolution: {integrity: sha512-x}\n" };
  const r = diffTrees(base, head, testCtx());
  assert.ok(r.notes.some((n) => n.includes("does not record install scripts")));
});

test("diff: git revisions work end to end", async () => {
  const { execFileSync } = await import("node:child_process");
  const { mkdtempSync, writeFileSync, mkdirSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { gitTree } = await import("../src/tree.js");
  const d = mkdtempSync(join(tmpdir(), "ws-git-"));
  const git = (...a: string[]) => execFileSync("git", ["-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...a], { cwd: d, stdio: "pipe" });
  git("init", "-q", "-b", "main");
  writeFileSync(join(d, "package.json"), '{"name":"g","scripts":{}}');
  git("add", "."); git("commit", "-qm", "base");
  writeFileSync(join(d, "package.json"), '{"name":"g","scripts":{"postinstall":"node x.js"}}');
  mkdirSync(join(d, ".github/workflows"), { recursive: true });
  writeFileSync(join(d, ".github/workflows/w.yml"), "on: push\n");
  git("add", "."); git("commit", "-qm", "head");
  const r = diffTrees(gitTree(d, "HEAD~1"), gitTree(d, "HEAD"), testCtx());
  assert.deepEqual(r.findings.map((f) => f.ruleId).sort(), ["WS-DF-002", "WS-DF-003"]);
  assert.throws(() => gitTree(d, "--output=/tmp/x"), /cannot resolve/);
  assert.throws(() => gitTree(d, "no-such-ref"), /cannot resolve/);
});
