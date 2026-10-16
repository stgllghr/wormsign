import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { toSarif } from "../src/sarif.js";

// What `npm pack` would publish. Lives with the report tests because the tarball is the product.
const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { files: string[]; scripts: Record<string, string>; repository: { url: string }; homepage: string; bugs: { url: string } };

function packedFiles(): { path: string; mode: number }[] {
  const r = spawnSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: ROOT, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  return (JSON.parse(r.stdout) as { files: { path: string; mode: number }[] }[])[0]!.files;
}

test("package: ships the hardening script (executable) with the IOC data it reads", () => {
  const files = packedFiles();
  const harden = files.find((f) => f.path === "harden-dev.sh");
  assert.ok(harden, "harden-dev.sh missing from the tarball");
  assert.ok(harden.mode & 0o100, "harden-dev.sh lost its executable bit");
  assert.ok(files.some((f) => f.path === "data/iocs/files.json"));
  assert.ok(files.some((f) => f.path === "docs/hardening.md"), "harden-dev.sh points users at docs/hardening.md");
  assert.ok(files.some((f) => f.path === "plugins/wormsign/skills/wormsign/SKILL.md"), "the agent skill ships with the CLI that installs it");
  assert.ok(!files.some((f) => f.path.startsWith(".claude-plugin/")), "the marketplace file is for the repository, not the package");
});

test("package: every compiled file shipped has a source file (no stale dist output)", () => {
  const compiled = packedFiles().filter((f) => f.path.startsWith("dist/"));
  assert.ok(compiled.some((f) => f.path === "dist/src/cli.js"));
  for (const f of compiled) {
    // The vendored parser is copied, not compiled (scripts/copy-vendor.mjs): its source is the same file under src/vendor/.
    const vendored = f.path.startsWith("dist/src/vendor/");
    const src = vendored ? f.path.replace(/^dist\//, "") : f.path.replace(/^dist\//, "").replace(/\.js$/, ".ts");
    assert.ok(existsSync(join(ROOT, src)), `${f.path} has no ${src}; build must start from an empty dist`);
    if (vendored) assert.ok(readFileSync(join(ROOT, f.path)).equals(readFileSync(join(ROOT, src))), `${f.path} differs from ${src}`);
  }
});

test("package: ships the vendored TOML parser's code, licence and record, and no type declarations", () => {
  const files = packedFiles().map((f) => f.path);
  const vendor = files.filter((p) => p.startsWith("dist/src/vendor/smol-toml/")).map((p) => p.slice("dist/src/vendor/smol-toml/".length)).sort();
  const record = JSON.parse(readFileSync(join(ROOT, "src/vendor/smol-toml/VENDORED.json"), "utf8")) as { files: Record<string, string> };
  const expected = [...Object.keys(record.files).filter((f) => f.endsWith(".js") || f === "LICENSE"), "VENDORED.json"].sort();
  assert.deepEqual(vendor, expected);
  assert.ok(!files.some((p) => p.endsWith(".d.ts")), "type declarations are for tsc only");
  assert.match(pkg.scripts["build"] ?? "", /tsc -p tsconfig\.json && node scripts\/copy-vendor\.mjs$/, "build copies the vendored parser after tsc");
});

test("package: build starts by deleting dist, so a renamed or removed source never ships stale output", () => {
  assert.match(pkg.scripts["build"] ?? "", /^npm run clean && /);
  const dir = mkdtempSync(join(tmpdir(), "ws-clean-"));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "t", version: "0.0.0", scripts: { clean: pkg.scripts["clean"] } }));
  mkdirSync(join(dir, "dist", "src"), { recursive: true });
  writeFileSync(join(dir, "dist", "src", "stale.js"), "");
  assert.equal(spawnSync("npm", ["run", "--silent", "clean"], { cwd: dir, encoding: "utf8" }).status, 0);
  assert.ok(!existsSync(join(dir, "dist")), "clean left dist behind");
});

test("package: check-files fails when a files entry is missing (npm pack would skip it silently)", () => {
  const dir = mkdtempSync(join(tmpdir(), "ws-pkg-"));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "t", version: "0.0.0", files: ["present", "LICENSE"], scripts: { "check-files": pkg.scripts["check-files"] } }));
  writeFileSync(join(dir, "present"), "");
  const missing = spawnSync("npm", ["run", "--silent", "check-files"], { cwd: dir, encoding: "utf8" });
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /missing: LICENSE/);
  writeFileSync(join(dir, "LICENSE"), "");
  assert.equal(spawnSync("npm", ["run", "--silent", "check-files"], { cwd: dir, encoding: "utf8" }).status, 0);
  assert.match(pkg.scripts["prepack"] ?? "", /check-files/, "prepack must run the check");
});

test("package: prepack checks files after building, so it passes on a fresh clone and checks the real output", () => {
  // A fresh clone has no dist/src; a dev checkout has a stale one that build is about to delete.
  const dir = mkdtempSync(join(tmpdir(), "ws-prepack-"));
  const build = "node -e \"require('node:fs').mkdirSync('dist/src', { recursive: true })\"";
  const scripts = { build, "check-files": pkg.scripts["check-files"], prepack: pkg.scripts["prepack"] };
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "t", version: "0.0.0", files: ["dist/src"], scripts }));
  const run = spawnSync("npm", ["run", "--silent", "prepack"], { cwd: dir, encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
});

test("package: repository metadata points at the repo the SARIF links to", () => {
  const info = (toSarif([], "x") as { runs: { tool: { driver: { informationUri: string } } }[] }).runs[0]!.tool.driver.informationUri;
  assert.equal(pkg.repository.url, `git+${info}.git`);
  assert.ok(pkg.homepage.startsWith(info) && pkg.bugs.url === `${info}/issues`);
});
