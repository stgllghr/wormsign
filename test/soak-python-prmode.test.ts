/**
 * soak --base for Python lock entries (src/python/base-entries.ts, src/python/soak.ts, src/main.ts), through the real
 * CLI (run() in src/main.ts) unless a test says otherwise: an entry the base's own soak read identically is not checked
 * again, as an npm entry is not; anything else is checked as on a full run. Each test names the rule it pins:
 * - the developer's repro: a young pin already on the base passes a pull request that only changes a README, and still
 *   fails the full soak of the same tree;
 * - the hole: a pin in a file the base's soak did not read as a lock (no --require-hashes, a line pip and uv refuse,
 *   the base's ignorePaths) is checked once a change makes the file a lock;
 * - identity: other hashes at the same version, another file, a renamed file, a uv.lock source; an identity checked
 *   where an entry the base did not hold has it;
 * - file-level problems: one the base's soak reported with the same fingerprint is left out, another is reported;
 * - index settings: a pip.conf or uv.toml change with identical hash-locked pins leaves them the base's (the setting is
 *   its own finding); an index line in the requirements file makes it no complete hash lock, so its pins are checked.
 * The network is validation-helpers.ts fakeNet plus a fake boto3 page (a version uploaded a day before helpers.ts NOW),
 * PATH a directory of stub binaries, HOME empty.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { run } from "../src/main.js";
import { baseLocks } from "../src/python/base-entries.js";
import { discoverPython } from "../src/python/discover.js";
import type { PyLock } from "../src/python/model.js";
import type { Finding } from "../src/types.js";
import { FIXTURES, NOW, fakeIO } from "./helpers.js";
import { fakeNet, gitRepo, stubBin, tempTree } from "./validation-helpers.js";
import type { FakeNet } from "./validation-helpers.js";

const UV = join(FIXTURES, "python", "locks", "uv-0.12.21");
const SIMPLE_UV = readFileSync(join(UV, "simple", "uv.lock"), "utf8");
const SIMPLE_PYPROJECT = readFileSync(join(UV, "simple", "pyproject.toml"), "utf8");
const INDEX = "https://pypi.org/simple/";
const sha = (s: string): string => createHash("sha256").update(s).digest("hex");

/** six 1.17.0 on pypi.org (test/fixtures/python/simple/six.json), uploaded 2024-12-04: old enough. */
const SIX = "six==1.17.0 --hash=sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274 --hash=sha256:ff70335d468e7eb6ec65b95b99d3a2836546063f63acc5171de367e834932a81\n";
/** boto3 1.40.99 on the fake index: a wheel and an sdist, both uploaded a day before NOW, so younger than 7 days. */
const BOTO3 = "1.40.99";
const BOTO3_WHL = sha("boto3 1.40.99 wheel");
const BOTO3_SDIST = sha("boto3 1.40.99 sdist");
const BOTO3_WHL_URL = `https://files.pythonhosted.org/packages/00/aa/boto3-${BOTO3}-py3-none-any.whl`;
const DAY_AGO = new Date(NOW.getTime() - 24 * 3_600_000).toISOString();
const BOTO3_PAGE = {
  meta: { "api-version": "1.4" },
  name: "boto3",
  versions: [BOTO3],
  files: [
    { filename: `boto3-${BOTO3}-py3-none-any.whl`, hashes: { sha256: BOTO3_WHL }, "upload-time": DAY_AGO, url: BOTO3_WHL_URL, yanked: false },
    { filename: `boto3-${BOTO3}.tar.gz`, hashes: { sha256: BOTO3_SDIST }, "upload-time": DAY_AGO, url: `https://files.pythonhosted.org/packages/00/bb/boto3-${BOTO3}.tar.gz`, yanked: false },
  ],
};
const BOTO3_LINE = `boto3==${BOTO3} --hash=sha256:${BOTO3_WHL}\n`;
/** A complete hash lock (uv pip compile --generate-hashes, then --require-hashes) pinning the young boto3 and six. */
const LOCK = `--require-hashes\n${BOTO3_LINE}${SIX}`;
/** uv 0.12.21's lock of idna and six, with the young boto3 from pypi.org added. */
const BOTO3_UV = `${SIMPLE_UV}
[[package]]
name = "boto3"
version = "${BOTO3}"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "${BOTO3_WHL_URL}", hash = "sha256:${BOTO3_WHL}", size = 140000, upload-time = "${DAY_AGO}" },
]
`;

const BIN = stubBin();
const GIT_DIR = dirname(execFileSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).trim());
const PATH = `${BIN}:${GIT_DIR}`;

/** fakeNet, with boto3's page added on the index (`boto3`: another page, or an HTTP status to answer with). */
function net(boto3: unknown = BOTO3_PAGE): FakeNet {
  const inner = fakeNet();
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    if (String(input) === `${INDEX}boto3/`) {
      inner.calls.push(String(input));
      if (typeof boto3 === "number") return new Response("{}", { status: boto3, headers: { "content-type": "application/json" } });
      return new Response(JSON.stringify(boto3), { headers: { "content-type": "application/vnd.pypi.simple.v1+json" } });
    }
    return inner.fetchImpl(input, init);
  }) as typeof fetch;
  return { ...inner, fetchImpl };
}

interface Run {
  code: number;
  findings: Finding[];
  notes: string[];
  err: string;
  net: FakeNet;
}

/** `wormsign soak <dir> <args> --format json` through run(), with the stub PATH and an empty HOME. */
async function soak(dir: string, args: string[] = [], boto3?: unknown): Promise<Run> {
  const home = mkdtempSync(join(tmpdir(), "ws-pyprmode-home-"));
  const n = net(boto3);
  const io = fakeIO({ env: { PATH, HOME: home, XDG_CONFIG_HOME: join(home, ".config") }, fetchImpl: n.fetchImpl });
  const code = await run(["soak", dir, ...args, "--format", "json"], io);
  if (io.out === "") return { code, findings: [], notes: [], err: io.err, net: n };
  const doc = JSON.parse(io.out) as { findings: Finding[]; notes: string[] };
  return { code, findings: doc.findings.filter((f) => f.suppressed === undefined), notes: doc.notes, err: io.err, net: n };
}

const write = (d: string, files: Record<string, string>): void => {
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(dirname(join(d, rel)), { recursive: true });
    writeFileSync(join(d, rel), body);
  }
};
/** A repository of three commits: an empty one, the base (`base`, HEAD~1) and the pull request (`change`, HEAD). */
const pr = (base: Record<string, string>, change: (d: string) => void): string => gitRepo([() => undefined, (d) => write(d, base), change]);
const readme = (d: string): void => writeFileSync(join(d, "README.md"), "docs only\n");
const rules = (r: Run): string[] => r.findings.map((f) => `${f.ruleId} ${f.file ?? "-"}`).sort();
const young = (r: Run): string[] => r.findings.filter((f) => f.ruleId === "WS-SK-001").map((f) => `${f.file} ${/^(\S+)==/.exec(f.message)?.[1] ?? "?"}`).sort();
const UNCHANGED = /^(\d+) unchanged Python package\(s\) not checked for age or against OSV \(PR mode: the base's soak read the same lock with the same pins and hashes\)$/;
const unchanged = (r: Run): number => Number(r.notes.map((n) => UNCHANGED.exec(n)?.[1]).find((x) => x !== undefined) ?? 0);

/* ---- the developer's repro ---- */

test("soak --base: a young Python pin already on the base passes a pull request that only changes a README; the full soak of the same tree fails it", async () => {
  const repo = pr({ "requirements.txt": LOCK }, readme);
  const full = await soak(repo);
  assert.equal(full.code, 1, rules(full).join("\n"));
  assert.deepEqual(young(full), ["requirements.txt boto3"], "control: the full soak checks the young pin");
  assert.ok(full.net.osvQueries.includes(`PyPI:boto3@${BOTO3}`), "control: and asks OSV about it");
  const pull = await soak(repo, ["--base", "HEAD~1"]);
  assert.equal(pull.code, 0, `${rules(pull).join("\n")}\n${pull.notes.join("\n")}`);
  assert.deepEqual(pull.findings, []);
  assert.equal(unchanged(pull), 2, pull.notes.join("\n"));
  assert.ok(pull.notes.includes("0 PyPI file(s) of 0 version(s) checked against https://pypi.org/simple/"), pull.notes.join("\n"));
  // Not sent to OSV, as an npm entry --base skips is not; the index is still read, only for WS-SK-005.
  assert.deepEqual(pull.net.osvQueries, []);
  assert.ok(pull.net.calls.includes(`${INDEX}boto3/`));
  // The pull request that adds the pin is checked.
  assert.deepEqual(young(await soak(repo, ["--base", "HEAD~2"])), ["requirements.txt boto3"]);
});

test("soak --base: a lock in the shape pip-compile writes (\" \\\" then --hash lines) is a lock, and its entries are the base's in PR mode", async () => {
  const [w, sd] = [BOTO3_WHL, BOTO3_SDIST];
  const compiled = `--require-hashes\nboto3==${BOTO3} \\\n    --hash=sha256:${w} \\\n    --hash=sha256:${sd}\n    # via -r requirements.in\n${SIX}`;
  const repo = pr({ "requirements.txt": compiled }, readme);
  assert.deepEqual(young(await soak(repo)), ["requirements.txt boto3"], "control: the full soak checks the young pin");
  const pull = await soak(repo, ["--base", "HEAD~1"]);
  assert.equal(pull.code, 0, `${rules(pull).join("\n")}\n${pull.notes.join("\n")}`);
  assert.equal(unchanged(pull), 2, pull.notes.join("\n"));
});

test("soak --base: the index is still read for the base's entries, and what it shows about their files is reported; a request that failed is not", async () => {
  const repo = pr({ "requirements.txt": LOCK }, readme);
  // Quarantined since the base's soak ran (PEP 792): soak saw it, so it says so.
  const quarantined = await soak(repo, ["--base", "HEAD~1", "--no-osv"], { ...BOTO3_PAGE, "project-status": { status: "quarantined" } });
  assert.equal(quarantined.code, 1);
  assert.deepEqual(rules(quarantined), ["WS-SK-002 requirements.txt"]);
  assert.match(quarantined.findings[0]!.message, /^Cannot verify soak time for PyPI package boto3==1\.40\.99: the index marks the project quarantined/);
  // The locked file gone from the index: the same.
  const gone = await soak(repo, ["--base", "HEAD~1", "--no-osv"], { ...BOTO3_PAGE, files: BOTO3_PAGE.files.slice(1) });
  assert.match(gone.findings.map((f) => f.message).join("\n"), /boto3==1\.40\.99: sha256:[0-9a-f]{64}: /);
  assert.equal(gone.code, 1);
  // An index error says nothing about the files, which PR mode does not check: the pull request passes. The full soak
  // fails closed on it.
  // The project gone from the index (404): reported too, since PyPI takes malware down.
  const removed = await soak(repo, ["--base", "HEAD~1", "--no-osv"], 404);
  assert.equal(removed.code, 1);
  assert.deepEqual(rules(removed), ["WS-SK-002 requirements.txt"]);
  assert.match(removed.findings[0]!.message, /^Cannot verify soak time for PyPI package boto3==1\.40\.99: boto3 is /);
  const failed = await soak(repo, ["--base", "HEAD~1", "--no-osv"], 503);
  assert.equal(failed.code, 0, rules(failed).join("\n"));
  assert.equal(unchanged(failed), 2);
  const full = await soak(repo, ["--no-osv"], 503);
  assert.deepEqual(rules(full), ["WS-SK-002 requirements.txt"]);
});

test("soak --base (uv.lock): an identical entry is the base's; one whose source changed is checked", async () => {
  const repo = pr({ "pyproject.toml": SIMPLE_PYPROJECT, "uv.lock": BOTO3_UV }, readme);
  assert.deepEqual(young(await soak(repo)), ["uv.lock boto3"], "control: the full soak fails the young pin");
  const pull = await soak(repo, ["--base", "HEAD~1"]);
  assert.equal(pull.code, 0, rules(pull).join("\n"));
  assert.equal(unchanged(pull), 3, "idna, six and boto3; the virtual root is local");
  // The same version from another registry: a different entry, checked (and sent nowhere).
  const moved = pr({ "pyproject.toml": SIMPLE_PYPROJECT, "uv.lock": BOTO3_UV }, (d) =>
    writeFileSync(join(d, "uv.lock"), BOTO3_UV.replace(`version = "${BOTO3}"\nsource = { registry = "https://pypi.org/simple" }`, `version = "${BOTO3}"\nsource = { registry = "https://mirror.example/simple" }`)),
  );
  const r = await soak(moved, ["--base", "HEAD~1"]);
  assert.equal(r.code, 1);
  assert.deepEqual(rules(r), ["WS-SK-002 uv.lock"]);
  assert.match(r.findings[0]!.message, /^Cannot verify soak time for PyPI package boto3==1\.40\.99: it is locked from https:\/\/mirror\.example\/simple, not --pypi-index/);
  assert.equal(unchanged(r), 2, "idna and six are still the base's");
});

/* ---- the hole: a file the base's soak did not read as a lock ---- */

test("soak --base: a pin in a file the base's soak did not read as a lock is checked once a change makes it one", async () => {
  const variants: [string, Record<string, string>, (d: string) => void, string[]][] = [
    ["a requirements file with hashes but no --require-hashes line", { "requirements.txt": `${BOTO3_LINE}${SIX}` }, (d) => writeFileSync(join(d, "requirements.txt"), LOCK), []],
    ["a requirements file pip and uv both refuse (a stray line)", { "requirements.txt": `FROM python:3.12\n${LOCK}` }, (d) => writeFileSync(join(d, "requirements.txt"), LOCK), []],
    // The base's own baseline passed vendor/ over, so its soak never read the file; --no-baseline reads it here.
    [
      "a hash lock under the base's ignorePaths, checked here with --no-baseline",
      { "vendor/requirements.txt": LOCK, ".wormsign-baseline.json": JSON.stringify({ version: 1, entries: [], ignorePaths: [{ path: "vendor", justification: "vendored tooling, not installed" }] }) },
      readme,
      ["--no-baseline"],
    ],
  ];
  for (const [what, base, change, args] of variants) {
    const repo = pr(base, change);
    const r = await soak(repo, ["--base", "HEAD~1", ...args]);
    assert.ok(young(r).some((y) => y.endsWith(" boto3")), `${what}: the pin is checked\n${rules(r).join("\n")}\n${r.notes.join("\n")}`);
    assert.equal(r.code, 1, what);
  }
  // Control for the last: with the base's baseline the head passes vendor/ over too, so nothing there is read.
  const ignored = pr({ "vendor/requirements.txt": LOCK, ".wormsign-baseline.json": JSON.stringify({ version: 1, entries: [], ignorePaths: [{ path: "vendor", justification: "vendored tooling, not installed" }] }) }, readme);
  assert.deepEqual(young(await soak(ignored, ["--base", "HEAD~1"])), []);
});

/* ---- identity ---- */

test("soak --base: the same version with other hashes, a pin moved to another file and a renamed file are checked", async () => {
  const cases: [string, (d: string) => void, string[]][] = [
    ["a hash added at the same version", (d) => writeFileSync(join(d, "requirements.txt"), `--require-hashes\nboto3==${BOTO3} --hash=sha256:${BOTO3_WHL} --hash=sha256:${BOTO3_SDIST}\n${SIX}`), ["requirements.txt boto3"]],
    ["the hash swapped at the same version", (d) => writeFileSync(join(d, "requirements.txt"), `--require-hashes\nboto3==${BOTO3} --hash=sha256:${BOTO3_SDIST}\n${SIX}`), ["requirements.txt boto3"]],
    [
      "the pin moved to another file",
      (d) => write(d, { "requirements.txt": `--require-hashes\n${SIX}`, "requirements-dev.txt": `--require-hashes\n${BOTO3_LINE}` }),
      ["requirements-dev.txt boto3"],
    ],
    [
      "the file renamed",
      (d) => {
        rmSync(join(d, "requirements.txt"));
        write(d, { "requirements/prod.txt": LOCK });
      },
      ["requirements/prod.txt boto3"],
    ],
  ];
  for (const [what, change, expected] of cases) {
    const r = await soak(pr({ "requirements.txt": LOCK }, change), ["--base", "HEAD~1"]);
    assert.deepEqual(young(r), expected, `${what}\n${r.notes.join("\n")}`);
    assert.equal(r.code, 1, what);
  }
  // Control: the line moved within its file, with a comment added, is the same entry.
  const reordered = await soak(pr({ "requirements.txt": LOCK }, (d) => writeFileSync(join(d, "requirements.txt"), `# compiled\n--require-hashes\n${SIX}${BOTO3_LINE}`)), ["--base", "HEAD~1"]);
  assert.equal(reordered.code, 0, rules(reordered).join("\n"));
  assert.equal(unchanged(reordered), 2);
});

test("soak --base: a pin the base held in one file and the change copies into another is checked where it is new", async () => {
  // requirements.txt is read first (the walk takes a directory's files before its subdirectories): its boto3 is the
  // base's, and the identity is checked at sub/requirements.txt, which the base did not have.
  const r = await soak(pr({ "requirements.txt": LOCK }, (d) => write(d, { "sub/requirements.txt": LOCK })), ["--base", "HEAD~1"]);
  assert.deepEqual(young(r), ["sub/requirements.txt boto3"], r.notes.join("\n"));
  assert.equal(r.code, 1);
});

/* ---- file-level problems: reported on every run, as npm's are ---- */

test("soak --base: every reader and file-level problem is reported on every run, the base's included, as npm's lockfile problems are", async () => {
  // The developer's pip-compile file: hashes, no --require-hashes line, unchanged on the base. Its problem fails every
  // pull request until the line is added on the base once.
  const noLine = `idna==3.20 --hash=sha256:a7db850025b95ded1eae8a46181a1a6c56c92c96f0e2b005d9ff8dc0210cab44 --hash=sha256:ab7ae7122974553370f0bdb919e1a960b2cd1bc1ef0276416d896db81c14582c\n${SIX}`;
  const repo = pr({ "requirements.txt": noLine }, readme);
  for (const args of [[], ["--base", "HEAD~1"]]) {
    const r = await soak(repo, [...args, "--no-osv"]);
    assert.equal(r.code, 1, args.join(" "));
    assert.deepEqual(rules(r), ["WS-SK-002 requirements.txt"], args.join(" "));
    assert.match(r.findings[0]!.message, /no --require-hashes line in the file or the files it includes/);
  }
  const fixed = await soak(pr({ "requirements.txt": `--require-hashes\n${noLine}` }, readme), ["--base", "HEAD~1", "--no-osv"]);
  assert.equal(fixed.code, 0, `the fix, made on the base once: ${rules(fixed).join("\n")}`);
  // Repro A: pip reads deps#1.txt; soak does not follow an include with "#" in its path. Only deps#1.txt changed.
  const hashInclude = await soak(pr({ "requirements.txt": "-r deps#1.txt\n", "deps#1.txt": "six==1.17.0\n" }, (d) => writeFileSync(join(d, "deps#1.txt"), `boto3==${BOTO3}\n`)), ["--base", "HEAD~1", "--no-osv"]);
  assert.equal(hashInclude.code, 1);
  assert.ok(hashInclude.findings.some((f) => /-r deps#1\.txt: a "#" in the path/.test(f.message)), rules(hashInclude).join("\n"));
  // Repro B: 201 refused option lines stop the reading, so the -r after them is never read. Only deps.in changed.
  const limit = await soak(pr({ "requirements.txt": `${"--prefer-binary\n".repeat(201)}-r deps.in\n`, "deps.in": "six==1.17.0\n" }, (d) => writeFileSync(join(d, "deps.in"), `boto3==${BOTO3}\n`)), ["--base", "HEAD~1", "--no-osv"]);
  assert.equal(limit.code, 1);
  assert.ok(limit.findings.some((f) => /more than 200 problems, so reading stopped/.test(f.message)), rules(limit).join("\n"));
  // A line naming a local wheel: soak never reads the wheel, so a change of the wheel alone changes no problem's key;
  // the line's problem is reported on every run.
  const wheel = "wheels/foo-1.0-py3-none-any.whl";
  const local = await soak(pr({ "requirements.txt": `--require-hashes\n./${wheel}\n`, [wheel]: "first wheel bytes" }, (d) => writeFileSync(join(d, wheel), "other wheel bytes")), ["--base", "HEAD~1", "--no-osv"]);
  assert.equal(local.code, 1);
  assert.ok(local.findings.some((f) => f.ruleId === "WS-SK-002" && f.file === "requirements.txt" && f.message.includes(`./${wheel}`)), local.findings.map((f) => f.message).join("\n"));
  for (const r of [hashInclude, limit, local]) assert.ok(!r.notes.some((n) => /not reported again/.test(n)), r.notes.join("\n"));
});

/* ---- index settings ---- */

test("soak --base: a pip.conf or uv.toml that names another index leaves identical hash-locked pins the base's; the setting is its own finding", async () => {
  const PRIVATE = "https://pypi.corp.example/simple/";
  for (const [file, body] of [["pip.conf", `[global]\nindex-url = ${PRIVATE}\n`], ["uv.toml", `[pip]\nindex-url = "${PRIVATE}"\n`]] as const) {
    const r = await soak(pr({ "requirements.txt": LOCK }, (d) => write(d, { [file]: body })), ["--base", "HEAD~1"]);
    assert.equal(r.code, 1, file);
    // Only the setting: the locked hashes fix the bytes an install takes from any index, and the base's soak aged them.
    assert.deepEqual(rules(r), [`WS-SK-002 ${file}`], `${file}\n${r.findings.map((f) => f.message).join("\n")}`);
    assert.match(r.findings[0]!.message, /an install may use another index/);
    assert.equal(unchanged(r), 2, file);
    assert.deepEqual(r.net.calls.filter((u) => u.startsWith(INDEX)), [], `${file}: names that may come from another index are sent nowhere`);
  }
});

test("soak --base: an index line added to a hash lock makes it no complete hash lock, so its pins are checked again", async () => {
  const r = await soak(pr({ "requirements.txt": LOCK }, (d) => writeFileSync(join(d, "requirements.txt"), `--index-url https://pypi.org/simple/\n${LOCK}`)), ["--base", "HEAD~1", "--no-osv"]);
  assert.equal(r.code, 1);
  assert.equal(unchanged(r), 0, r.notes.join("\n"));
  const pkgs = r.findings.filter((f) => /^Cannot verify soak time for PyPI package /.test(f.message)).map((f) => /package (\S+):/.exec(f.message)?.[1]).sort();
  assert.deepEqual(pkgs, [`boto3==${BOTO3}`, "six==1.17.0"], r.findings.map((f) => f.message).join("\n"));
  assert.ok(r.findings.some((f) => /requirements\.txt:1: /.test(f.message) && /--index-url/.test(f.message)), "the line's own finding");
});

test("soak --base: an sdist-only package the base held in one file and the change copies into another is one WS-SK-005, where it is new", async () => {
  const sdist = "--require-hashes\nsix==1.17.0 --hash=sha256:ff70335d468e7eb6ec65b95b99d3a2836546063f63acc5171de367e834932a81\n";
  const r = await soak(pr({ "requirements.txt": sdist }, (d) => write(d, { "sub/requirements.txt": sdist })), ["--base", "HEAD~1", "--no-osv"]);
  const builds = r.findings.filter((f) => f.ruleId === "WS-SK-005").map((f) => `${f.severity} ${f.file}`);
  assert.deepEqual(builds, ["high sub/requirements.txt"], r.notes.join("\n"));
  // Control: against itself it is the base's, once, at medium.
  const same = await soak(pr({ "requirements.txt": sdist }, readme), ["--base", "HEAD~1", "--no-osv"]);
  assert.deepEqual(same.findings.filter((f) => f.ruleId === "WS-SK-005").map((f) => `${f.severity} ${f.file}`), ["medium requirements.txt"]);
});

test("soak --base: a file the base's git attributes convert on checkout is not the base's, whatever .gitattributes says it, with a note", async () => {
  const r = await soak(pr({ "requirements.txt": LOCK, ".gitattributes": "requirements.txt filter=custom\n" }, readme), ["--base", "HEAD~1", "--no-osv"]);
  assert.deepEqual(young(r), ["requirements.txt boto3"]);
  assert.ok(r.notes.includes("PR mode: requirements.txt is not counted as the base's, since the base revision's git attributes set filter for it, so a checkout of it holds other bytes than git stores"), r.notes.join("\n"));
  // Control: attributes for other files, line endings and diff settings leave it the base's.
  const plain = await soak(pr({ "requirements.txt": LOCK, ".gitattributes": "*.dat filter=custom\n* text=auto\n*.lock -diff\n" }, readme), ["--base", "HEAD~1", "--no-osv"]);
  assert.equal(plain.code, 0, rules(plain).join("\n"));
  // Above a subdirectory root: the base's root .gitattributes made sub/requirements.txt UTF-16LE in a checkout, which
  // the base's soak of sub/ could not read; the change drops the attribute, and git stores the same blob.
  const repo = gitRepo([
    () => undefined,
    (d) => {
      write(d, { ".gitattributes": "sub/requirements.txt working-tree-encoding=UTF-16LE\n" });
      mkdirSync(join(d, "sub"), { recursive: true });
      writeFileSync(join(d, "sub", "requirements.txt"), Buffer.from(LOCK, "utf16le"));
    },
    (d) => write(d, { ".gitattributes": "# no attributes\n", "sub/requirements.txt": LOCK }),
  ]);
  const sub = await soak(join(repo, "sub"), ["--base", "HEAD~1", "--no-osv"]);
  assert.deepEqual(young(sub), ["requirements.txt boto3"], sub.notes.join("\n"));
  assert.ok(sub.notes.includes("PR mode: requirements.txt is not counted as the base's, since the base revision's git attributes set working-tree-encoding for it, so a checkout of it holds other bytes than git stores"), sub.notes.join("\n"));
});

test("soak --base in a blobless partial clone: a base .gitattributes the clone lacks makes nothing the base's, with a note; a full clone reads it", async () => {
  const cloneOf = (origin: string, blobless: boolean): string => {
    execFileSync("git", ["config", "uploadpack.allowFilter", "true"], { cwd: origin, stdio: "pipe" });
    const into = join(mkdtempSync(join(tmpdir(), "ws-pyprmode-clone-")), "c");
    execFileSync("git", ["clone", "-q", ...(blobless ? ["--filter=blob:none"] : []), `file://${origin}`, into], { stdio: "pipe" });
    return into;
  };
  const dropped = (d: string): void => {
    rmSync(join(d, ".gitattributes"));
    readme(d);
  };
  // The review's repro: the attribute converts the lock, and the change deletes it. A uv.lock, which only the attributes
  // decide here; a requirements file is not the base's in such a clone for a second reason too (its entries cannot all
  // be counted: the files that may be requirements files include the missing .gitattributes).
  const converting = pr({ "pyproject.toml": SIMPLE_PYPROJECT, "uv.lock": BOTO3_UV, ".gitattributes": "uv.lock filter=custom\n" }, dropped);
  const r = await soak(cloneOf(converting, true), ["--base", "HEAD~1", "--no-osv"]);
  assert.deepEqual(young(r), ["uv.lock boto3"], r.notes.join("\n"));
  assert.ok(r.notes.some((n) => n.startsWith("PR mode: no Python entry counts as the base's, since git could not read the base revision's attributes (.gitattributes at HEAD~1 is not in this clone (a partial clone lacks its blob)")), r.notes.join("\n"));
  const req = pr({ "requirements.txt": LOCK, ".gitattributes": "requirements.txt filter=custom\n" }, dropped);
  assert.deepEqual(young(await soak(cloneOf(req, true), ["--base", "HEAD~1", "--no-osv"])), ["requirements.txt boto3"]);
  // An attribute for other files: unknown in the blobless clone, so nothing is the base's; read in a full clone.
  const other = pr({ "requirements.txt": LOCK, ".gitattributes": "*.dat filter=custom\n" }, dropped);
  assert.deepEqual(young(await soak(cloneOf(other, true), ["--base", "HEAD~1", "--no-osv"])), ["requirements.txt boto3"]);
  const full = await soak(cloneOf(other, false), ["--base", "HEAD~1", "--no-osv"]);
  assert.equal(full.code, 0, `control, a full clone: ${rules(full).join("\n")}\n${full.notes.join("\n")}`);
});

test("soak --base --baseline <file>: that file's ignorePaths count for the base too, and a base baseline that cannot be read is a note", async () => {
  const trustedDir = mkdtempSync(join(tmpdir(), "ws-pyprmode-trusted-"));
  const trusted = join(trustedDir, "baseline.json");
  writeFileSync(trusted, JSON.stringify({ version: 1, entries: [], ignorePaths: [{ path: "vendor", justification: "vendored tooling, not installed" }] }));
  // An include under the --baseline file's ignorePaths: no soak run with that file read it as a lock of its own.
  const unit = { "requirements.txt": "--require-hashes\n-r vendor/requirements.txt\n", "vendor/requirements.txt": `--require-hashes\n${BOTO3_LINE}` };
  const r = await soak(pr(unit, readme), ["--base", "HEAD~1", "--baseline", trusted, "--no-osv"]);
  assert.deepEqual(young(r), ["vendor/requirements.txt boto3"], r.notes.join("\n"));
  // Control: without the file, the base read the include as a requirements file of its own.
  assert.deepEqual(young(await soak(pr(unit, readme), ["--base", "HEAD~1", "--no-osv"])), []);
  // The base's own baseline does not parse: nothing is the base's, and the note says why.
  const broken = await soak(pr({ "requirements.txt": LOCK, ".wormsign-baseline.json": "{" }, readme), ["--base", "HEAD~1", "--baseline", trusted, "--no-osv"]);
  assert.deepEqual(young(broken), ["requirements.txt boto3"]);
  assert.ok(broken.notes.some((n) => n.startsWith("PR mode: no Python entry counts as the base's, since .wormsign-baseline.json at HEAD~1 could not be read (")), broken.notes.join("\n"));
});

/* ---- base-entries.ts directly: what the CLI cannot tell apart, since a requirements-named include is a lock of its own ---- */

/** The base revision as main.ts gives it, from files in memory. */
const memoryBase = (files: Record<string, string>, attrs: Record<string, Record<string, string>> = {}) => ({
  read: (rel: string) => files[rel],
  entry: (rel: string) => (Object.hasOwn(files, rel) ? { kind: "file" as const, bytes: Buffer.from(files[rel]!) } : undefined),
  list: () => Object.keys(files),
  attributes: (paths: string[]) => new Map(paths.map((p) => [p, new Map(Object.entries(attrs[p] ?? {}))])),
});
const discover = (files: Record<string, string>): PyLock[] => discoverPython(tempTree(files), { pypiIndex: INDEX, env: {}, ancestors: false, uvConfigFiles: [] }).locks;
/** holds() for each entry of the lock at `file`, as "<name>@<the file it is in> <true|false>". */
function held(base: Record<string, string>, head: Record<string, string>, file: string): string[] {
  const locks = discover(head);
  const b = baseLocks(memoryBase(base), locks, { pypiIndex: INDEX, ignore: [] });
  const lock = locks.find((l) => l.file === file)!;
  assert.ok(lock, file);
  return lock.packages.map((p) => `${p.name}@${p.file} ${b.holds(lock, p)}`).sort();
}

test("base entries: an entry counts only in the file it is in, and an include's entry only when the base read that include as a lock", () => {
  const unit = "--require-hashes\n-r requirements/a.txt\n-r requirements/b.txt\n";
  const files = { "requirements.txt": unit, "requirements/a.txt": BOTO3_LINE, "requirements/b.txt": SIX };
  assert.deepEqual(held(files, files, "requirements.txt"), ["boto3@requirements/a.txt true", "six@requirements/b.txt true"], "control: the same unit");
  // The two pins swapped between the includes: the same root unit, but each entry is in another file now.
  const swapped = { ...files, "requirements/a.txt": SIX, "requirements/b.txt": BOTO3_LINE };
  assert.deepEqual(held(files, swapped, "requirements.txt"), ["boto3@requirements/b.txt false", "six@requirements/a.txt false"]);
  // An include no soak reads as a lock of its own (docs/pins.md): its entries are checked, though the unit is the same.
  const md = { "requirements.txt": "--require-hashes\n-r docs/pins.md\n", "docs/pins.md": LOCK };
  assert.deepEqual(held(md, md, "requirements.txt"), ["boto3@docs/pins.md false", "six@docs/pins.md false"]);
});

test("base entries: a base whose requirements files hold more entries than discovery reads makes no requirements entry the base's", () => {
  const files = { "requirements.txt": LOCK, "requirements-dev.txt": LOCK };
  const locks = discover(files);
  const lock = locks.find((l) => l.file === "requirements.txt")!;
  const holds = (max: number): boolean[] => lock.packages.map((p) => baseLocks(memoryBase(files), locks, { pypiIndex: INDEX, ignore: [], maxRequirementEntries: max }).holds(lock, p));
  assert.deepEqual(holds(4), [true, true], "control: 4 entries in all");
  assert.deepEqual(holds(3), [false, false], "the base's soak stopped before one of its units");
  // A base unit not read to the end is no reading either.
  const base = { "requirements.txt": `--require-hashes\n-r missing.txt\n${BOTO3_LINE}${SIX}` };
  assert.deepEqual(lock.packages.map((p) => baseLocks(memoryBase(base), locks, { pypiIndex: INDEX, ignore: [] }).holds(lock, p)), [false, false]);
});

test("base entries: a base requirements file found only by its content counts toward the entry bound", () => {
  const head = { "requirements.txt": LOCK };
  const locks = discover(head);
  const lock = locks[0]!;
  const holds = (base: Record<string, string>): boolean[] => lock.packages.map((p) => baseLocks(memoryBase(base), locks, { pypiIndex: INDEX, ignore: [], maxRequirementEntries: 4 }).holds(lock, p));
  // deps.lst is a requirements file only by its content (a --require-hashes line): its 3 entries and requirements.txt's
  // 2 are more than 4, so the base's soak stopped before one of them.
  const deps = `--require-hashes\n${BOTO3_LINE}${SIX}idna==3.20 --hash=sha256:${"a".repeat(64)}\n`;
  assert.deepEqual(holds({ ...head, "deps.lst": deps }), [false, false]);
  assert.deepEqual(holds(head), [true, true], "control: 2 entries");
  assert.deepEqual(holds({ ...head, "notes.lst": "six and boto3 are pinned in requirements.txt\n" }), [true, true], "control: a file of that name that holds no requirements");
});

test("base entries: a file the base's attributes convert, or attributes git cannot read, make no entry the base's", () => {
  const unit = { "requirements.txt": "--require-hashes\n-r requirements/a.txt\n", "requirements/a.txt": LOCK };
  const locks = discover(unit);
  const lock = locks.find((l) => l.file === "requirements.txt")!;
  const holds = (base: ReturnType<typeof memoryBase>): [boolean[], string[]] => {
    const b = baseLocks(base, locks, { pypiIndex: INDEX, ignore: [] });
    return [lock.packages.map((p) => b.holds(lock, p)), b.notes()];
  };
  assert.deepEqual(holds(memoryBase(unit))[0], [true, true], "control");
  // An include the base converts: the base's soak read other bytes there.
  const [inc, incNotes] = holds(memoryBase(unit, { "requirements/a.txt": { ident: "set" } }));
  assert.deepEqual(inc, [false, false]);
  assert.deepEqual(incNotes, ["PR mode: requirements/a.txt is not counted as the base's, since the base revision's git attributes set ident for it, so a checkout of it holds other bytes than git stores"]);
  assert.deepEqual(holds(memoryBase(unit, { "requirements.txt": { filter: "unset", ident: "unspecified" } }))[0], [true, true], "unset and unspecified convert nothing");
  // git cannot tell (older than 2.40): nothing is the base's.
  const [failed, failedNotes] = holds({ ...memoryBase(unit), attributes: () => { throw new Error("error: unknown option `source'"); } });
  assert.deepEqual(failed, [false, false]);
  assert.match(failedNotes[0] ?? "", /^PR mode: no Python entry counts as the base's, since git could not read the base revision's attributes \(error: unknown option `source'; git 2\.40 or later/);
  // A uv.lock the base converts.
  const uv = { "pyproject.toml": SIMPLE_PYPROJECT, "uv.lock": BOTO3_UV };
  const uvLocks = discover(uv);
  const u = uvLocks.find((l) => l.file === "uv.lock")!;
  const boto = u.packages.find((p) => p.name === "boto3")!;
  assert.equal(baseLocks(memoryBase(uv), uvLocks, { pypiIndex: INDEX, ignore: [] }).holds(u, boto), true, "control");
  assert.equal(baseLocks(memoryBase(uv, { "uv.lock": { filter: "lfs" } }), uvLocks, { pypiIndex: INDEX, ignore: [] }).holds(u, boto), false);
});

test("base entries: unknown ignorePaths, a base that is not a complete hash lock, and an entry without hashes are never the base's", () => {
  const files = { "requirements.txt": LOCK };
  const locks = discover(files);
  const lock = locks[0]!;
  assert.deepEqual(lock.packages.map((p) => baseLocks(memoryBase(files), locks, { pypiIndex: INDEX, ignore: undefined }).holds(lock, p)), [false, false], "the base's baseline could not be read");
  assert.deepEqual(lock.packages.map((p) => baseLocks(memoryBase(files), locks, { pypiIndex: INDEX, ignore: ["requirements.txt"] }).holds(lock, p)), [false, false], "passed over by the base's ignorePaths");
  assert.deepEqual(lock.packages.map((p) => baseLocks(memoryBase({ "requirements.txt": `${BOTO3_LINE}${SIX}` }), locks, { pypiIndex: INDEX, ignore: [] }).holds(lock, p)), [false, false], "no --require-hashes on the base");
  assert.deepEqual(lock.packages.map((p) => baseLocks(memoryBase(files), locks, { pypiIndex: INDEX, ignore: [] }).holds(lock, p)), [true, true], "control");
  // A uv.lock git source has no file, so no hash fixes what it installs.
  const uv = { "pyproject.toml": SIMPLE_PYPROJECT, "uv.lock": readFileSync(join(FIXTURES, "python", "locks", "forged", "uv-git-source.lock"), "utf8") };
  const uvLocks = discover(uv);
  const u = uvLocks.find((l) => l.file === "uv.lock")!;
  assert.deepEqual(u.packages.filter((p) => p.source.kind !== "virtual").map((p) => `${p.name} ${p.source.kind} ${baseLocks(memoryBase(uv), uvLocks, { pypiIndex: INDEX, ignore: [] }).holds(u, p)}`).sort(), ["idna registry true", "six git false"]);
});
