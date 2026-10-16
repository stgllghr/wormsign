/**
 * PyPI soak through the real CLI (run() in src/main.ts): how `wormsign soak` puts the shared walk (src/walk.ts), Python
 * discovery (src/python/discover.ts) and the Python lock check (src/python/soak.ts) into one run, beside npm's.
 *
 * Locks are the ones uv 0.12.21 wrote (test/fixtures/python/locks), or a forged edit of one named where it is used. The
 * network is a fake (validation-helpers.ts fakeNet): the npm registry, a Python index serving Simple JSON pages captured
 * from pypi.org, and OSV, each recording what it was asked. PATH is a directory of stub binaries (npm, pnpm, Yarn and
 * bun versions, and a python3 that answers `python3 -m pip config list`), HOME and XDG_CONFIG_HOME are empty, and the
 * clock is fixed (helpers.ts NOW, 2026-10-01T12:00:00Z), so nothing comes from the machine.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, parse } from "node:path";
import { run } from "../src/main.js";
import type { Finding } from "../src/types.js";
import { FIXTURES, NOW, fakeIO } from "./helpers.js";
import { fakeNet, gitRepo, stubBin, tempTree } from "./validation-helpers.js";
import type { FakeNet, FakeNetOptions } from "./validation-helpers.js";

const PY = join(FIXTURES, "python", "locks");
const UV = join(PY, "uv-0.12.21");
const text = (p: string): string => readFileSync(p, "utf8");
/** uv 0.12.21's lock of idna 3.20 and six 1.17.0 (pypi.org), for a virtual root project. */
const SIMPLE_UV = text(join(UV, "simple", "uv.lock"));
const SIMPLE_PYPROJECT = text(join(UV, "simple", "pyproject.toml"));
/** The same lock with six 1.17.0 moved to a git source at the same version (test/fixtures/python/locks/forged). */
const GIT_SWAP_UV = text(join(PY, "forged", "uv-git-source.lock"));
/** uv's `export --format requirements-txt` of that lock, made a lock by adding `--require-hashes` (the edit is this line). */
const REQUIREMENTS = `--require-hashes\n${text(join(UV, "simple", "requirements.txt"))}`;
const PYLOCK = text(join(UV, "simple", "pylock.toml"));
const PYTHON_FILES = { "pyproject.toml": SIMPLE_PYPROJECT, "uv.lock": SIMPLE_UV };
const PRIVATE = "https://pypi.corp.example/simple/";
const H = 3_600_000;

/** The stub binaries first, then the directory git is in (the walker and the local-source checks run git). */
const BIN = stubBin();
const GIT_DIR = dirname(execFileSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).trim());
const PATH = `${BIN}:${GIT_DIR}`;

interface Evidence {
  name: string;
  version: string;
  ecosystem: string;
  status: string;
  osv?: string[];
  files?: { filename: string }[];
}

interface Soak {
  code: number;
  findings: Finding[];
  notes: string[];
  evidence: Evidence[];
  err: string;
}

/** `wormsign soak <dir> <args> --format json` through run(), with the stub PATH and an empty HOME. */
async function soak(dir: string, args: string[] = [], net: FakeNet = fakeNet(), env: Record<string, string> = {}): Promise<Soak> {
  const home = mkdtempSync(join(tmpdir(), "ws-pycli-home-"));
  const io = fakeIO({ env: { PATH, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), ...env }, fetchImpl: net.fetchImpl });
  const code = await run(["soak", dir, ...args, "--format", "json"], io);
  if (io.out === "") return { code, findings: [], notes: [], evidence: [], err: io.err };
  const doc = JSON.parse(io.out) as { findings: Finding[]; notes: string[]; extra?: { evidence: Evidence[] } };
  return { code, findings: doc.findings, notes: doc.notes, evidence: doc.extra?.evidence ?? [], err: io.err };
}

const rules = (r: Soak): string[] => r.findings.map((f) => `${f.ruleId} ${f.file ?? "-"}`).sort();
/** A note that only npm's half of soak writes. */
const NPM_NOTE = /registry\.npmjs\.org|registry signals read|npm and Yarn release-age|nothing to verify/;

/** An npm lockfile v3 locking each [name, version] from the public registry. */
function npmLock(pkgs: [string, string][]): string {
  const packages: Record<string, unknown> = { "": { name: "app", version: "1.0.0" } };
  for (const [n, v] of pkgs) packages[`node_modules/${n}`] = { version: v, resolved: `https://registry.npmjs.org/${n}/-/${n}-${v}.tgz`, integrity: "sha512-x" };
  return JSON.stringify({ name: "app", version: "1.0.0", lockfileVersion: 3, requires: true, packages }, null, 2);
}
/** A packument publishing each version `days` before NOW. */
const packument = (name: string, versions: Record<string, number>) => ({
  name,
  time: Object.fromEntries(Object.entries(versions).map(([v, days]) => [v, new Date(NOW.getTime() - days * 24 * H).toISOString()])),
  versions: Object.fromEntries(Object.keys(versions).map((v) => [v, { dist: { integrity: "sha512-x", tarball: `https://registry.npmjs.org/${name}/-/${name}-${v}.tgz` } }])),
});

/* ---- Python only ---- */

test("soak (Python only, uv.lock): each locked file is bound and aged on the index, OSV is asked about PyPI names, and nothing about npm is reported", async () => {
  const dir = tempTree(PYTHON_FILES);
  const net = fakeNet();
  const r = await soak(dir, [], net);
  assert.equal(r.code, 0, r.err);
  assert.deepEqual(r.findings, [], "idna 3.20 (14 days) and six 1.17.0 are older than 7 days");
  assert.deepEqual(
    r.evidence.map((e) => [e.ecosystem, e.name, e.version, e.status, e.osv, e.files?.length]),
    [
      ["PyPI", "idna", "3.20", "ok", [], 2],
      ["PyPI", "six", "1.17.0", "ok", [], 2],
    ],
  );
  assert.ok(r.notes.includes("4 PyPI file(s) of 2 version(s) checked against https://pypi.org/simple/"), r.notes.join("\n"));
  assert.ok(r.notes.includes("release-age settings of Python tools are not checked by soak; see harden-dev.sh"), r.notes.join("\n"));
  assert.ok(r.notes.some((n) => n.startsWith("2 package version(s) checked against OSV for malicious-package records (PyPI)")), r.notes.join("\n"));
  // No npm package manager, so no WS-SK-003 for a missing one; no npm note at all.
  assert.deepEqual(r.notes.filter((n) => NPM_NOTE.test(n)), []);
  assert.deepEqual(net.calls.filter((u) => !u.startsWith("https://pypi.org/simple/")), ["https://api.osv.dev/v1/querybatch"]);
  assert.deepEqual(net.calls.filter((u) => u.startsWith("https://pypi.org/simple/")).sort(), ["https://pypi.org/simple/idna/", "https://pypi.org/simple/six/"]);
  assert.deepEqual(net.osvQueries, ["PyPI:idna@3.20", "PyPI:six@1.17.0"]);
});

test("soak (Python only): a young locked file is WS-SK-001 and an OSV record is WS-OS-001, both keyed as PyPI", async () => {
  const dir = tempTree(PYTHON_FILES);
  // idna 3.20's files were uploaded 2026-09-17, 14 days before NOW: inside a 15-day soak.
  const r = await soak(dir, ["--min-age", "15d"], fakeNet({ osv: { "PyPI:six@1.17.0": ["MAL-2026-0001"] } }));
  assert.equal(r.code, 1);
  assert.deepEqual(rules(r), ["WS-OS-001 uv.lock", "WS-SK-001 uv.lock"]);
  const young = r.findings.find((f) => f.ruleId === "WS-SK-001");
  assert.match(young?.key ?? "", /^pypi:idna@3\.20 [0-9a-f]{64}$/);
  assert.match(young?.message ?? "", /^idna==3\.20 \(PyPI\) has 2 locked file\(s\) uploaded inside the required 15\.0d soak window/);
  assert.match(r.findings.find((f) => f.ruleId === "WS-OS-001")?.key ?? "", /^pypi:/);
  assert.deepEqual(r.evidence.find((e) => e.name === "six")?.osv, ["MAL-2026-0001"]);
});

test("soak (Python only) --config-only: no network, no npm sentence, and a note that the Python lock check did not run", async () => {
  const net = fakeNet();
  const r = await soak(tempTree(PYTHON_FILES), ["--config-only"], net);
  assert.equal(r.code, 0, r.err);
  assert.deepEqual(r.findings, []);
  assert.deepEqual(r.notes, ["Python lock check not run (--config-only); release-age settings of Python tools are not checked by soak; see harden-dev.sh"]);
  assert.deepEqual(net.calls, []);
});

/* ---- npm and PyPI in one tree ---- */

test("soak (npm and PyPI in one tree, six@1.17.0 in both): npm's findings, notes and evidence are an npm-only run's, and PyPI's a Python-only run's", async () => {
  const npmFiles = { "package.json": '{"name":"app","version":"1.0.0","dependencies":{"six":"1.17.0"}}', "package-lock.json": npmLock([["six", "1.17.0"]]), ".npmrc": "min-release-age=7\n" };
  // An npm malware record for six@1.17.0 must stay npm's: PyPI's six@1.17.0 is another package.
  const opts: FakeNetOptions = { npm: { six: packument("six", { "1.17.0": 400 }) }, osv: { "npm:six@1.17.0": ["MAL-2026-0002"] } };
  const npmNet = fakeNet(opts);
  const pyNet = fakeNet(opts);
  const mixedNet = fakeNet(opts);
  const npmOnly = await soak(tempTree(npmFiles), [], npmNet);
  const pyOnly = await soak(tempTree(PYTHON_FILES), [], pyNet);
  const mixed = await soak(tempTree({ ...npmFiles, ...PYTHON_FILES }), [], mixedNet);
  assert.deepEqual(rules(npmOnly), ["WS-OS-001 package-lock.json"], "control: npm reports its record");
  assert.deepEqual(pyOnly.findings, [], "control: PyPI's six has no record");
  assert.deepEqual(mixed.findings.filter((f) => !f.key.startsWith("pypi:")), npmOnly.findings);
  assert.deepEqual(mixed.findings.filter((f) => f.key.startsWith("pypi:")), pyOnly.findings);
  assert.deepEqual(mixed.notes, [...npmOnly.notes, ...pyOnly.notes]);
  assert.deepEqual(mixed.evidence.filter((e) => e.ecosystem === "npm"), npmOnly.evidence);
  assert.deepEqual(mixed.evidence.filter((e) => e.ecosystem === "PyPI"), pyOnly.evidence);
  assert.deepEqual(
    mixed.evidence.map((e) => `${e.name}@${e.version} ${e.ecosystem} ${JSON.stringify(e.osv)}`),
    ["idna@3.20 PyPI []", 'six@1.17.0 npm ["MAL-2026-0002"]', "six@1.17.0 PyPI []"],
  );
  assert.deepEqual(mixedNet.osvQueries.filter((q) => q.startsWith("npm:")), npmNet.osvQueries);
  assert.equal(mixed.code, npmOnly.code);
});

test("soak (npm and PyPI): one OSV session for the run, so a GitHub advisory npm's check classified is not asked about again for PyPI", async () => {
  const files = { "package-lock.json": npmLock([["six", "1.17.0"]]), ".npmrc": "min-release-age=7\n", ...PYTHON_FILES };
  const ghsa = "GHSA-wsx9-77hb-x0a1";
  const net = fakeNet({ npm: { six: packument("six", { "1.17.0": 400 }) }, osv: { "npm:six@1.17.0": [ghsa], "PyPI:six@1.17.0": [ghsa] }, ghsa: { [ghsa]: ["CWE-79"] } });
  const r = await soak(tempTree(files), [], net);
  assert.deepEqual(r.findings, [], "a GHSA record without CWE-506 is not malware");
  assert.deepEqual(net.recordQueries, ["npm:six@1.17.0"], "PyPI's six@1.17.0 holds only an advisory the run has read");
  assert.deepEqual(r.evidence.map((e) => `${e.name} ${e.ecosystem} ${JSON.stringify(e.osv)}`), ["idna PyPI []", "six npm []", "six PyPI []"]);
});

/* ---- PR mode ---- */

test("soak --base (uv.lock): six moved to a git source is checked, the unchanged idna is the base's, and a git source is never", async () => {
  const repo = gitRepo([
    (d) => {
      writeFileSync(join(d, "pyproject.toml"), SIMPLE_PYPROJECT);
      writeFileSync(join(d, "uv.lock"), SIMPLE_UV);
    },
    (d) => writeFileSync(join(d, "uv.lock"), GIT_SWAP_UV),
  ]);
  const net = fakeNet();
  const r = await soak(repo, ["--base", "HEAD~1"], net);
  assert.equal(r.code, 1);
  assert.deepEqual(rules(r), ["WS-SK-002 uv.lock"]);
  const swap = r.findings[0]!;
  assert.match(swap.key, /^pypi:six@1\.17\.0 [0-9a-f]{64}$/);
  assert.match(swap.message, /six==1\.17\.0: it resolves from a git source \(https:\/\/github\.com\/benjaminp\/six\?tag=1\.17\.0#/);
  assert.ok(r.notes.includes("1 unchanged Python package(s) not checked for age or against OSV (PR mode: the base's soak read the same lock with the same pins and hashes)"), r.notes.join("\n"));
  // idna, which the base's soak read identically, is not checked: no evidence, no OSV query. The index is still asked
  // for its page, only to tell a package locked only as sdists (WS-SK-005); the git source is sent nowhere.
  assert.deepEqual(r.evidence.map((e) => `${e.name} ${e.status}`), ["six unverifiable"]);
  assert.deepEqual(net.osvQueries, []);
  assert.deepEqual(net.calls.filter((u) => u.startsWith("https://pypi.org/simple/")), ["https://pypi.org/simple/idna/"]);
  // Against itself the git source is still reported: no hash fixes what a git source installs.
  assert.deepEqual(rules(await soak(repo, ["--base", "HEAD"], fakeNet())), ["WS-SK-002 uv.lock"]);
  assert.deepEqual(rules(await soak(repo)), ["WS-SK-002 uv.lock"]);
});

/**
 * A pin that lands first in a file the base's soak never reads as a lock, and is installed only after a later change
 * makes it one. PR mode against the change that planted it must still check the pin (--min-age 100000d: anything
 * checked is WS-SK-001). Before the fix, the base's text at the same path counted as already checked.
 */
test("soak --base: a Python pin planted in a file the base never read as a lock is checked when a change makes it one", async () => {
  const pins = text(join(UV, "simple", "requirements.txt"));
  const variants: [string, ((d: string) => void)[], string][] = [
    [
      "an .md file a later requirements.txt includes",
      [
        (d) => {
          mkdirSync(join(d, "docs"));
          writeFileSync(join(d, "docs", "pins.md"), `--require-hashes\n${pins}`);
          writeFileSync(join(d, "requirements.txt"), "--require-hashes\n");
        },
        (d) => writeFileSync(join(d, "requirements.txt"), "--require-hashes\n-r docs/pins.md\n"),
      ],
      "docs/pins.md",
    ],
    [
      "a .txt pip and uv refuse, which a later change fixes and includes",
      [
        (d) => {
          mkdirSync(join(d, "docs"));
          writeFileSync(join(d, "docs", "pins.txt"), `FROM python:3.12\n--require-hashes\n${pins}`);
          writeFileSync(join(d, "requirements.txt"), "--require-hashes\n");
        },
        (d) => {
          writeFileSync(join(d, "docs", "pins.txt"), `--require-hashes\n${pins}`);
          writeFileSync(join(d, "requirements.txt"), "--require-hashes\n-r docs/pins.txt\n");
        },
      ],
      "docs/pins.txt",
    ],
    [
      "a script lock with no script, which a later change adds",
      [
        (d) => {
          mkdirSync(join(d, "tools"));
          writeFileSync(join(d, "tools", "deploy.lock"), text(join(UV, "script", "example.py.lock")));
        },
        (d) => writeFileSync(join(d, "tools", "deploy"), text(join(UV, "script", "example.py"))),
      ],
      "tools/deploy.lock",
    ],
  ];
  for (const [what, steps, file] of variants) {
    const repo = gitRepo([(d) => writeFileSync(join(d, "README.md"), "x\n"), ...steps]);
    const planted = await soak(repo, ["--base", "HEAD~1", "--min-age", "100000d", "--no-osv"]);
    assert.ok(
      planted.findings.some((f) => f.ruleId === "WS-SK-001" && f.file === file),
      `${what}: PR mode against the planting change checks the pin\n${rules(planted).join("\n")}\n${planted.notes.join("\n")}`,
    );
    assert.equal(planted.code, 1, what);
    // Control: the planting change itself adds no lock, so nothing was checked there.
    const plant = await soak(repo, ["--base", "HEAD~2", "--min-age", "100000d", "--no-osv"]);
    assert.ok(plant.findings.some((f) => f.ruleId === "WS-SK-001" && f.file === file), `${what}: against the root commit too`);
  }
});

test("soak --base: a Python package the base baselined in one file is checked when a change adds it to another", async () => {
  const pins = `--require-hashes\n${text(join(UV, "simple", "requirements.txt"))}`;
  const first = gitRepo([
    (d) => {
      mkdirSync(join(d, "docs"));
      writeFileSync(join(d, "docs", "requirements.txt"), pins);
    },
  ]);
  const young = (await soak(first, ["--min-age", "100000d", "--no-osv"])).findings.filter((f) => f.ruleId === "WS-SK-001");
  assert.deepEqual(young.map((f) => f.file), ["docs/requirements.txt", "docs/requirements.txt"]);
  const baseline = JSON.stringify({ version: 1, entries: young.map((f) => ({ fingerprint: f.fingerprint, justification: "docs builder only, reviewed" })) });
  const repo = gitRepo([
    (d) => {
      mkdirSync(join(d, "docs"));
      writeFileSync(join(d, "docs", "requirements.txt"), pins);
      writeFileSync(join(d, ".wormsign-baseline.json"), baseline);
    },
    (d) => writeFileSync(join(d, "requirements.txt"), pins),
  ]);
  const r = await soak(repo, ["--base", "HEAD~1", "--min-age", "100000d", "--no-osv"]);
  assert.deepEqual(r.findings.filter((f) => f.ruleId === "WS-SK-001").map((f) => f.file), ["requirements.txt", "requirements.txt"], r.notes.join("\n"));
});

/* ---- names that must not leave the machine ---- */

test("soak (private index): a requirements lock under an index setting, a pylock and a uv.lock from another index make no request to the index or OSV", async () => {
  const cases: [string, Record<string, string>, Record<string, string>][] = [
    ["requirements.txt with PIP_INDEX_URL", { "requirements.txt": REQUIREMENTS }, { PIP_INDEX_URL: PRIVATE }],
    ["requirements.txt beside a committed pip.conf", { "requirements.txt": REQUIREMENTS, "pip.conf": `[global]\nindex-url = ${PRIVATE}\n` }, {}],
    ["requirements.txt under a uv.toml [pip] extra-index-url", { "requirements.txt": REQUIREMENTS, "uv.toml": `[pip]\nextra-index-url = ["${PRIVATE}"]\n` }, {}],
    ["pylock.toml whose packages record a private index", { "pylock.toml": PYLOCK.replaceAll('index = "https://pypi.org/simple"', `index = "${PRIVATE}"`) }, {}],
    ["uv.lock locked from a private registry", { "pyproject.toml": SIMPLE_PYPROJECT, "uv.lock": SIMPLE_UV.replaceAll('source = { registry = "https://pypi.org/simple" }', `source = { registry = "${PRIVATE}" }`) }, {}],
  ];
  for (const [name, files, env] of cases) {
    const net = fakeNet();
    const r = await soak(tempTree(files), [], net, env);
    assert.equal(r.code, 1, name);
    assert.deepEqual(net.calls, [], `${name}: no request at all`);
    const unsent = r.findings.filter((f) => f.ruleId === "WS-SK-002" && /^Cannot verify soak time for PyPI package (idna==3\.20|six==1\.17\.0)/.test(f.message));
    assert.equal(unsent.length, 2, `${name}: each package is WS-SK-002: ${r.findings.map((f) => f.message).join("\n")}`);
  }
});

test("soak (requirements lock): pip's configuration is read with python3 -m pip from the filesystem root, without PYTHONPATH, and the entries are checked", async () => {
  const dir = tempTree({ "requirements.txt": REQUIREMENTS, "pip/__main__.py": "raise SystemExit('the tree runs here')\n" });
  const log = join(mkdtempSync(join(tmpdir(), "ws-pycli-probe-")), "probe.log");
  const net = fakeNet();
  const r = await soak(dir, [], net, { WS_TEST_PROBE_LOG: log, PYTHONPATH: dir });
  assert.equal(r.code, 0, r.err);
  assert.deepEqual(text(log).trim().split("\n"), [`cwd=${parse(process.cwd()).root} PYTHONPATH=unset args=-m pip config list`]);
  assert.deepEqual(r.evidence.map((e) => `${e.name} ${e.status}`), ["idna ok", "six ok"]);
  assert.deepEqual(net.osvQueries, ["PyPI:idna@3.20", "PyPI:six@1.17.0"]);
});

test("soak (requirements lock): when pip's configuration cannot be read, nothing is sent unless --pypi-index is given explicitly", async () => {
  const dir = tempTree({ "requirements.txt": REQUIREMENTS });
  // No python3 on PATH: the probe cannot start.
  const noPython = mkdtempSync(join(tmpdir(), "ws-pycli-nopy-"));
  const net = fakeNet();
  const r = await soak(dir, [], net, { PATH: noPython });
  assert.equal(r.code, 1);
  assert.deepEqual(net.calls, []);
  assert.ok(r.notes.some((n) => n.startsWith("pip's configuration was not read (") && n.includes("sent nowhere")), r.notes.join("\n"));
  assert.equal(r.findings.filter((f) => f.ruleId === "WS-SK-002").length, 2);
  const explicit = fakeNet();
  const e = await soak(dir, ["--pypi-index", "https://pypi.org/simple/"], explicit, { PATH: noPython });
  assert.equal(e.code, 0, e.err);
  assert.deepEqual(e.evidence.map((x) => `${x.name} ${x.status}`), ["idna ok", "six ok"]);
  // A pip setting soak can see still fails closed with --pypi-index given.
  const seen = await soak(tempTree({ "requirements.txt": REQUIREMENTS }), ["--pypi-index", "https://pypi.org/simple/"], fakeNet(), { PIP_EXTRA_INDEX_URL: PRIVATE });
  assert.equal(seen.code, 1);
});

/* ---- --pypi-index ---- */

test("cli: --pypi-index is checked like --registry, before any walk or network: https only (http for localhost), no credentials, query or fragment", async () => {
  const dir = tempTree(PYTHON_FILES);
  const bad: [string, RegExp][] = [
    ["http://pypi.example/simple/", /--pypi-index must be https \(http only for localhost\)/],
    ["https://user:secret-token@pypi.example/simple/", /--pypi-index must not contain credentials/],
    ["https://pypi.example/simple/?token=x", /--pypi-index must not have a query or fragment/],
    ["https://pypi.example/simple/#frag", /--pypi-index must not have a query or fragment/],
    ["https://pypi.example/simple/?", /--pypi-index must not have a query or fragment/],
    ["pypi.org/simple", /invalid --pypi-index/],
    ["ftp://pypi.example/simple/", /--pypi-index must be https/],
  ];
  for (const [url, why] of bad) {
    const net = fakeNet();
    const r = await soak(dir, ["--pypi-index", url], net);
    assert.equal(r.code, 2, url);
    assert.match(r.err, why, url);
    assert.doesNotMatch(r.err, /secret-token|internal error/, url);
    assert.deepEqual(net.calls, [], url);
  }
  const io = fakeIO();
  assert.equal(await run(["scan", dir, "--pypi-index", "https://pypi.org/simple/"], io), 2);
  assert.match(io.err, /--pypi-index is not an option of scan/);
});

test("cli: --pypi-index http://localhost is used for every project, and OSV is not asked about names from an index that is not pypi.org", async () => {
  const index = "http://localhost:8080/simple/";
  const net = fakeNet({ pypiIndex: index });
  const uv = SIMPLE_UV.replaceAll('source = { registry = "https://pypi.org/simple" }', 'source = { registry = "http://localhost:8080/simple" }');
  const r = await soak(tempTree({ "pyproject.toml": SIMPLE_PYPROJECT, "uv.lock": uv }), ["--pypi-index", index], net);
  assert.deepEqual(net.calls.sort(), ["http://localhost:8080/simple/idna/", "http://localhost:8080/simple/six/"]);
  assert.ok(r.notes.includes(`4 PyPI file(s) of 2 version(s) checked against ${index}`), r.notes.join("\n"));
  assert.deepEqual(rules(r), ["WS-OS-900 -"], "the names are not sent to OSV, which fails closed");
  assert.match(r.findings[0]?.message ?? "", /--pypi-index http:\/\/localhost:8080\/simple\/ is not the public PyPI index/);
  // The default index is pypi.org, whatever the lock says: a lock from localhost is another index then.
  const d = await soak(tempTree({ "pyproject.toml": SIMPLE_PYPROJECT, "uv.lock": uv }), [], fakeNet());
  assert.equal(d.findings.filter((f) => f.ruleId === "WS-SK-002").length, 2);
});

/* ---- what soak does not read yet ---- */

test("soak: poetry.lock, pdm.lock and Pipfile.lock fail closed as not supported yet, with no request, in a full run and with --config-only", async () => {
  const files = {
    "pyproject.toml": '[project]\nname = "app"\nversion = "1.0.0"\ndependencies = ["six==1.17.0"]\n',
    "poetry.lock": '[[package]]\nname = "six"\nversion = "1.17.0"\n',
    "b/pdm.lock": '[[package]]\nname = "six"\nversion = "1.17.0"\n',
    "c/Pipfile.lock": '{"default": {"six": {"version": "==1.17.0"}}}\n',
    "c/Pipfile": '[packages]\nsix = "==1.17.0"\n',
  };
  for (const args of [[], ["--config-only"]]) {
    const net = fakeNet();
    const r = await soak(tempTree(files), args, net);
    assert.equal(r.code, 1, args.join(" "));
    assert.deepEqual(rules(r), ["WS-SK-002 b/pdm.lock", "WS-SK-002 c/Pipfile.lock", "WS-SK-002 poetry.lock"], args.join(" "));
    for (const f of r.findings) assert.match(f.message, /is not supported yet/);
    assert.deepEqual(net.calls, []);
  }
});

/* ---- the tree as git sees it ---- */

test("soak (uv workspace): a member git does not track is not a local source, and tracked members the install builds are WS-SK-005", async () => {
  const fixture = join(UV, "editable");
  const write = (d: string, rel: string) => {
    mkdirSync(dirname(join(d, rel)), { recursive: true });
    cpSync(join(fixture, rel), join(d, rel));
  };
  const opts: FakeNetOptions = {};
  const tracked = gitRepo([(d) => ["pyproject.toml", "uv.lock", "packages/member/pyproject.toml"].forEach((rel) => write(d, rel))]);
  const t = await soak(tracked, [], fakeNet(opts));
  assert.equal(t.code, 0, t.err);
  assert.deepEqual(rules(t), ["WS-SK-005 uv.lock", "WS-SK-005 uv.lock"]);
  assert.ok(t.findings.every((f) => f.severity === "medium"));
  assert.ok(t.findings.some((f) => f.message.startsWith('member (editable source packages/member) is built from source at install time, and its build requirements ("hatchling")')), t.findings.map((f) => f.message).join("\n"));
  const untracked = gitRepo([(d) => ["pyproject.toml", "uv.lock"].forEach((rel) => write(d, rel))]);
  write(untracked, "packages/member/pyproject.toml");
  // Untracked files alone: medium on a developer's checkout, high in PR mode (soak-python-noise.test.ts).
  for (const [args, severity, code] of [[[], "medium", 0], [["--base", "HEAD"], "high", 1]] as const) {
    const u = await soak(untracked, [...args], fakeNet(opts));
    assert.equal(u.code, code, args.join(" "));
    assert.ok(
      u.findings.some((f) => f.ruleId === "WS-SK-002" && f.severity === severity && f.message.startsWith("Cannot verify soak time for PyPI package member==0.2.0: local source not present in the reviewed tree")),
      u.findings.map((f) => f.message).join("\n"),
    );
  }
});

test("soak: an untracked virtual environment in a git work tree is not read, and the note names it", async () => {
  const repo = gitRepo([(d) => Object.entries(PYTHON_FILES).forEach(([rel, body]) => writeFileSync(join(d, rel), body))]);
  for (const [rel, body] of Object.entries({
    ".venv/pyvenv.cfg": "home = /usr/bin\n",
    ".venv/lib/python3.12/site-packages/six-1.17.0.dist-info/METADATA": "Name: six\n",
    ".venv/lib/python3.12/site-packages/x/uv.lock": "not a lock\n",
  })) {
    mkdirSync(dirname(join(repo, rel)), { recursive: true });
    writeFileSync(join(repo, rel), body);
  }
  const r = await soak(repo, [], fakeNet());
  assert.equal(r.code, 0, `${r.err}${r.findings.map((f) => f.message).join("\n")}`);
  assert.ok(r.notes.includes("1 virtual environment(s) not read: no file in them is tracked by git, so they are not part of the reviewed tree: .venv"), r.notes.join("\n"));
});

test("soak: discovery's notes are reported (a requirements file of comments only is skipped, and the run has nothing to verify)", async () => {
  const r = await soak(tempTree({ "requirements.txt": "# nothing pinned yet\n\n" }), [], fakeNet());
  assert.equal(r.code, 0, r.err);
  assert.deepEqual(r.findings, []);
  assert.deepEqual(r.notes, ["no lockfile and no dependencies declared; the soak gate has nothing to verify", "requirements.txt holds only blank lines and comments, so it was skipped"]);
});

test("soak: with nothing to verify, the note names the .txt, .in and .pip files it did not read, and what it looked for; no finding", async () => {
  // pip installs from any of these with `pip install -r`; their names are outside the rules and they hold no hashes.
  const r = await soak(tempTree({ "requirements.in": "requests\n", "deps.txt": "six==1.17.0\n", "ci/requirements-dev.pip": "pytest\n", "README.md": "# demo\n", "vendored/x.txt": "x\n" }), [], fakeNet());
  const control = await soak(tempTree({ "README.md": "# demo\n" }), [], fakeNet());
  assert.equal(r.code, 0, r.err);
  assert.deepEqual(r.findings, control.findings, "no finding the tree without them lacks (npm's WS-SK-003 for no package manager, medium)");
  assert.deepEqual(r.notes.slice(1), control.notes.slice(1), "npm's notes as before");
  assert.deepEqual(r.notes.slice(0, 1), [
    "no lockfile and no dependencies declared; the soak gate has nothing to verify. It looked for npm, pnpm, Yarn and bun lockfiles and manifests, Python locks, manifests and PEP 723 scripts, and requirements files by name (*requirements*.txt, *constraints*.txt, requirements*.lock, a .txt under a requirements directory) or, among the files its content pass opens (no extension, or .txt, .in, .lock, .pip, .req and the other extensions docs/soak.md#discovery-what-is-read lists), holding --hash or --require-hashes; it did not read ci/requirements-dev.pip, deps.txt, requirements.in and vendored/x.txt as requirements files (no requirements name, no --hash), so if pip installs from one of them (`pip install -r`), nothing here checks what that installs",
  ]);
  // A tree with none of them keeps the short note (npm's output is unchanged).
  assert.equal(control.notes[0], "no lockfile and no dependencies declared; the soak gate has nothing to verify");
  // So does an npm tree whose .txt files are prose pip refuses: a LICENSE.txt or CMakeLists.txt is no requirements file.
  const prose = await soak(tempTree({ "package.json": '{"name":"x","version":"1.0.0"}', "LICENSE.txt": "MIT License\n\nCopyright (c) 2026 Example\n", "native/CMakeLists.txt": "cmake_minimum_required(VERSION 3.10)\nproject(x)\n" }), [], fakeNet());
  const bareNpm = await soak(tempTree({ "package.json": '{"name":"x","version":"1.0.0"}' }), [], fakeNet());
  assert.deepEqual(prose.notes, bareNpm.notes);
  assert.equal(prose.notes[0], "no lockfile and no dependencies declared; the soak gate has nothing to verify");
});
