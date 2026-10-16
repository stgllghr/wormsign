/**
 * soak's Python findings on ordinary checkouts, through the real CLI (run() in src/main.ts), each a case a developer
 * review reproduced on a real repository, with controls that keep a real problem high:
 * - an untracked file inside a local project is medium outside PR mode, high with --base (src/python/soak.ts,
 *   paths.ts); an uncommitted .wormsign-baseline.json at the root never counts;
 * - a manifest that declares only the root project (click's examples/*) is WS-SK-002 high unless the root's lock lists
 *   it as a workspace member (src/python/discover.ts covered);
 * - a requirements file with no --require-hashes line is one finding, not one per line (src/python/soak.ts
 *   readerProblemFindings).
 * The network is validation-helpers.ts fakeNet, PATH a directory of stub binaries, HOME empty.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { run } from "../src/main.js";
import type { Finding } from "../src/types.js";
import { fakeIO } from "./helpers.js";
import { fakeNet, gitRepo, stubBin, tempTree } from "./validation-helpers.js";

const BIN = stubBin();
const GIT_DIR = dirname(execFileSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).trim());
const PATH = `${BIN}:${GIT_DIR}`;

interface Run {
  code: number;
  findings: Finding[];
  err: string;
}

/** `wormsign soak <dir> <args> --no-osv --format json` with the stub PATH, an empty HOME and the fake network. */
async function soak(dir: string, args: string[] = []): Promise<Run> {
  const home = mkdtempSync(join(tmpdir(), "ws-pynoise-home-"));
  const net = fakeNet();
  const io = fakeIO({ env: { PATH, HOME: home, XDG_CONFIG_HOME: join(home, ".config") }, fetchImpl: net.fetchImpl });
  const code = await run(["soak", dir, ...args, "--no-osv", "--format", "json"], io);
  if (io.out === "") return { code, findings: [], err: io.err };
  return { code, findings: (JSON.parse(io.out) as { findings: Finding[] }).findings, err: io.err };
}
const py = (r: Run): string[] => r.findings.filter((f) => f.key.startsWith("pypi:")).map((f) => `${f.ruleId} ${f.severity} ${f.file ?? "-"}`).sort();
const write = (dir: string, files: Record<string, string>): void => {
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), body);
  }
};

/** An npm project with a 7-day release age, so that npm's half of soak reports nothing. */
const NPM = {
  "package.json": '{"name":"app","version":"1.0.0"}',
  "package-lock.json": JSON.stringify({ name: "app", version: "1.0.0", lockfileVersion: 3, requires: true, packages: { "": { name: "app", version: "1.0.0" } } }),
  ".npmrc": "min-release-age=7\n",
};
/** A uv project whose lock installs the root as an editable build, and nothing from an index. */
const UV_ROOT = (name: string) => ({
  "pyproject.toml": `[project]\nname = "${name}"\nversion = "0.1.0"\n\n[build-system]\nrequires = ["hatchling"]\nbuild-backend = "hatchling.build"\n`,
  "uv.lock": `version = 1\nrevision = 3\nrequires-python = ">=3.9"\n\n[[package]]\nname = "${name.toLowerCase().replace(/[-_.]+/g, "-")}"\nversion = "0.1.0"\nsource = { editable = "." }\n`,
});

/* ---- an untracked file inside a local project ---- */

test("soak: an untracked file in a local project is medium (commit or git-ignore it) without --base, high with it", async () => {
  const repo = gitRepo([(d) => write(d, { ...NPM, ...UV_ROOT("app") })]);
  const clean = await soak(repo);
  assert.deepEqual(py(clean), ["WS-SK-005 medium uv.lock"], "positive control: the committed project is read, and its build reported");
  writeFileSync(join(repo, "notes.txt"), "scratch\n");
  const local = await soak(repo);
  assert.equal(local.code, 0, local.err);
  assert.deepEqual(py(local), ["WS-SK-002 medium uv.lock"]);
  const medium = local.findings.find((f) => f.ruleId === "WS-SK-002");
  assert.equal(
    medium?.message,
    'Cannot verify soak time for PyPI package app==0.1.0: local source not present in the reviewed tree: ".": holds 1 file(s) not tracked by git (notes.txt), which are not part of the reviewed tree; commit or git-ignore it',
  );
  const pr = await soak(repo, ["--base", "HEAD"]);
  assert.equal(pr.code, 1);
  assert.deepEqual(py(pr), ["WS-SK-002 high uv.lock"]);
  const high = pr.findings.find((f) => f.ruleId === "WS-SK-002");
  assert.doesNotMatch(high?.message ?? "", /commit or git-ignore/);
  // Keyed apart: a baseline entry for the medium one does not approve the high one.
  assert.notEqual(medium?.fingerprint, high?.fingerprint);
});

test("soak: an uncommitted .wormsign-baseline.json at the root is not an untracked file of a local project; elsewhere it is", async () => {
  const repo = gitRepo([(d) => write(d, { ...NPM, ...UV_ROOT("app") })]);
  writeFileSync(join(repo, ".wormsign-baseline.json"), JSON.stringify({ version: 1, entries: [] }));
  for (const args of [[], ["--base", "HEAD"]]) {
    const r = await soak(repo, args);
    assert.deepEqual(py(r), ["WS-SK-005 medium uv.lock"], args.join(" "));
  }
  // Control: the same name below the root is a file like any other.
  write(repo, { "src/.wormsign-baseline.json": "{}\n" });
  assert.deepEqual(py(await soak(repo)), ["WS-SK-002 medium uv.lock"]);
  assert.deepEqual(py(await soak(repo, ["--base", "HEAD"])), ["WS-SK-002 high uv.lock"]);
});

test("soak: a local project with a link out of the tree stays high without --base, untracked files or not", async () => {
  const repo = gitRepo([(d) => write(d, { ...NPM, ...UV_ROOT("app") })]);
  symlinkSync("/usr/bin/env", join(repo, "outside"));
  writeFileSync(join(repo, "notes.txt"), "scratch\n");
  const r = await soak(repo);
  assert.equal(r.code, 1);
  assert.deepEqual(py(r), ["WS-SK-002 high uv.lock"]);
  assert.match(r.findings.find((f) => f.ruleId === "WS-SK-002")?.message ?? "", /the symlink outside resolves outside the scanned root$/);
});

/* ---- a manifest that declares only the root project ---- */

test("soak: an example manifest that names only the root project is WS-SK-002 high unless the root's lock lists it", async () => {
  // Ruling R24, after a review: no exemption for an example that declares only the root project. Without a source an
  // install reads the name from the index; a uv path or workspace source binds the root's code but not the versions of
  // its dependencies, which uv resolves afresh for a project the lock does not list, and pip ignores [tool.uv.sources].
  const example = (deps: string, extra = "") => `[project]\nname = "example"\nversion = "1.0.0"\ndependencies = ${deps}\n${extra}\n[build-system]\nrequires = ["flit_core<4"]\nbuild-backend = "flit_core.buildapi"\n`;
  const fromRoot = '\n[tool.uv.sources]\nclick-lib = { path = "../.." }\n';
  const high: [string, string, string][] = [
    ["no source (click's examples)", '["click-lib>=8.1"]', ""],
    ["by its PEP 503 name, with extras and specifiers", '["Click_Lib[dev, docs] (>=8.1,<9)", "click.lib"]', ""],
    ["a uv path source to the root", '["click-lib>=8.1"]', fromRoot],
    ["an editable path source to the root", '["click.lib"]', '\n[tool.uv.sources]\nClick_Lib = { path = "../../", editable = true }\n'],
    ["a uv workspace source", '["click-lib>=8.1"]', '\n[tool.uv.sources]\nclick-lib = { workspace = true }\n'],
    ["a git source", '["click-lib>=8.1"]', '\n[tool.uv.sources]\nclick-lib = { git = "https://example.invalid/click-lib" }\n'],
  ];
  for (const [what, deps, sources] of high) {
    const r = await soak(tempTree({ ...NPM, ...UV_ROOT("click-lib"), "examples/a/pyproject.toml": example(deps, sources) }));
    assert.ok(py(r).includes("WS-SK-002 high examples/a/pyproject.toml"), `${what}: ${py(r).join(", ")}`);
  }
  // Covered: one the root's lock lists (a workspace member), as any directory a lock lists is, source or not.
  const member = UV_ROOT("click-lib");
  member["uv.lock"] += '\n[[package]]\nname = "example"\nversion = "1.0.0"\nsource = { editable = "examples/a" }\n';
  for (const sources of ["", '\n[tool.uv.sources]\nclick-lib = { workspace = true }\n']) {
    const r = await soak(tempTree({ ...NPM, ...member, "examples/a/pyproject.toml": example('["click-lib>=8.1"]', sources) }));
    assert.deepEqual(py(r).filter((x) => x.startsWith("WS-SK-002")), [], sources);
  }
});

test("soak --base: a pull request that points an example at an index version of the root's name fails the gate", async () => {
  // A review's reproduction: changing examples/a to click-lib[cli]>=99 passed soak --base (it was WS-SK-002 high before
  // the root-project rule), though the example reads click-lib from the index and the root's lock pins only the tree.
  const example = (dep: string) => `[project]\nname = "example"\nversion = "1.0.0"\ndependencies = ["${dep}"]\n\n[build-system]\nrequires = ["flit_core<4"]\nbuild-backend = "flit_core.buildapi"\n`;
  const repo = gitRepo([
    (d) => write(d, { ...NPM, ...UV_ROOT("click-lib"), "examples/a/pyproject.toml": example("click-lib>=8.1") }),
    (d) => write(d, { "examples/a/pyproject.toml": example("click-lib[cli]>=99") }),
  ]);
  const r = await soak(repo, ["--base", "HEAD~1"]);
  assert.equal(r.code, 1);
  assert.ok(py(r).includes("WS-SK-002 high examples/a/pyproject.toml"), py(r).join(", "));
  assert.match(r.findings.find((f) => f.file === "examples/a/pyproject.toml")?.message ?? "", /it declares dependencies, but no lock covers it/);
});

/* ---- a requirements file that is not a hash lock ---- */

const PINS = ["chardet==5.2.0", "mkdocs==1.6.1", "mkautodoc==0.2.0", "build==1.3.0", "twine==6.1.0", "coverage[toml]==7.10.6", "cryptography==45.0.7", "mypy==1.17.1", "pytest==8.4.1", "ruff==0.12.11", "trio==0.31.0", "uvicorn==0.35.0"];

test("soak: a requirements file of == pins without hashes is one high WS-SK-002 naming its lines and the fix", async () => {
  const text = `# tooling\n-e .[cli]\n${PINS.join("\n")}\n`;
  const r = await soak(tempTree({ ...NPM, "requirements.txt": text }));
  assert.equal(r.code, 1);
  assert.deepEqual(py(r), ["WS-SK-002 high requirements.txt"]);
  const f = r.findings.find((x) => x.ruleId === "WS-SK-002")!;
  assert.equal(
    f.message,
    "Cannot verify soak time for the packages in requirements.txt: it is not a hash lock (it has no --require-hashes line), so none of the 13 line(s) the lock rule refuses was checked: " +
      "requirements.txt:2: option -e is not allowed in a hash lock; requirements.txt:3: chardet==5.2.0 has no --hash=sha256; requirements.txt:4: mkdocs==1.6.1 has no --hash=sha256; " +
      "requirements.txt:5: mkautodoc==0.2.0 has no --hash=sha256; requirements.txt:6: build==1.3.0 has no --hash=sha256; requirements.txt:7: twine==6.1.0 has no --hash=sha256; " +
      "requirements.txt:8: coverage==7.10.6 has no --hash=sha256; requirements.txt:9: cryptography==45.0.7 has no --hash=sha256; requirements.txt:10: mypy==1.17.1 has no --hash=sha256; " +
      "requirements.txt:11: pytest==8.4.1 has no --hash=sha256; and 3 more. To check them, make the file a hash lock: regenerate it with `uv pip compile --generate-hashes` or `pip-compile --generate-hashes`, then add a `--require-hashes` line. " +
      "No baseline entry can approve this finding: the missing line is keyed on no text of the file, so an entry would approve it whatever the file comes to hold; the remedy is to add a --require-hashes line to the requirements file itself",
  );
  // The missing --require-hashes line is part of it, and no entry approves that line: nor the == pins alone, which
  // could be approved one by one in a hash lock.
  assert.equal(f.notBaselinable, true);
  const pinsOnly = (await soak(tempTree({ ...NPM, "requirements.txt": `${PINS.join("\n")}\n` }))).findings.find((x) => x.ruleId === "WS-SK-002");
  assert.equal(pinsOnly?.notBaselinable, true, pinsOnly?.message);
  assert.match(pinsOnly?.message ?? "", /\. No baseline entry can approve this finding: the missing line is keyed on no text of the file, .*the remedy is to add a --require-hashes line/);
  assert.match(f.key, /^pypi:lockfile requirements\.txt [0-9a-f]{32}$/);
  // The key is stable when lines move and bound to their content: a changed or an added pin is a new finding.
  const fp = async (t: string) => (await soak(tempTree({ ...NPM, "requirements.txt": t }))).findings.find((x) => x.ruleId === "WS-SK-002")?.fingerprint;
  assert.equal(await fp(`# a comment above\n\n${PINS.slice().reverse().join("\n")}\n-e .[cli]\n`), f.fingerprint, "moved lines");
  assert.notEqual(await fp(text.replace("ruff==0.12.11", "ruff==0.12.12")), f.fingerprint, "a changed pin");
  assert.notEqual(await fp(`${text}idna==3.10\n`), f.fingerprint, "an added pin");
  // A line whose problem reads the same is still bound to its text.
  assert.notEqual(await fp(text.replace("-e .[cli]", "-e .[all]")), f.fingerprint, "another editable line");
});

test("soak: a hash lock's own problems stay one finding per line, and a problem outside the lock rule keeps its own finding", async () => {
  // A hash lock (it has --require-hashes) with two lines it refuses: each line is its own finding, as before.
  const lock = await soak(tempTree({ ...NPM, "requirements.txt": "--require-hashes\nidna==3.10\nmkdocs==1.6.1\n" }));
  assert.equal(lock.code, 1);
  assert.deepEqual(
    lock.findings.map((x) => `${x.ruleId} ${x.severity} ${x.message}`).sort(),
    ["2: idna==3.10", "3: mkdocs==1.6.1"].map((l) => `WS-SK-002 high Cannot verify soak time for the packages in requirements.txt: requirements.txt:${l} has no --hash=sha256; make the file a hash lock: regenerate it with \`uv pip compile --generate-hashes\` or \`pip-compile --generate-hashes\`, then add a \`--require-hashes\` line`),
  );
  // Not a hash lock, with an include outside the tree: the include keeps its own finding beside the one for the file.
  const both = await soak(tempTree({ ...NPM, "requirements.txt": "-r ../outside.txt\nmkdocs==1.6.1\n" }));
  const messages = both.findings.filter((x) => x.ruleId === "WS-SK-002").map((x) => x.message);
  assert.equal(messages.length, 2, messages.join("\n"));
  assert.ok(messages.some((m) => /requirements\.txt:1: -r \.\.\/outside\.txt is outside the scanned root/.test(m) && !/not a hash lock/.test(m)), messages.join("\n"));
  assert.ok(messages.some((m) => /not a hash lock .* none of the 1 line\(s\) the lock rule refuses was checked: requirements\.txt:2: mkdocs==1\.6\.1 has no --hash=sha256\. To check them/.test(m)), messages.join("\n"));
});
