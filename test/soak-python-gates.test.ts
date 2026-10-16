/**
 * The PyPI soak's gates through the real CLI (run() in src/main.ts), each a property a review found missing:
 * - what a baseline entry approves: a reader problem's key covers the content it is about (src/python/soak.ts);
 * - which names are sent: a requirements file's own index options, pylock file URLs on another host, local archives
 *   (src/python/discover.ts, model.ts);
 * - what discovery reads: only candidate names, padded files, files pip and uv would both refuse, the baseline's
 *   ignorePaths (src/python/discover.ts, scripts.ts);
 * - PR mode: a WS-SK-005 the change adds is high (src/python/base-builds.ts);
 * - programs on PATH inside the scanned tree are never run (src/exec.ts);
 * - diff's Python rules: a removed or de-hashed lock, pip and uv configuration, a manifest compared whole (src/diff.ts);
 *   and scan says that it does not read Python locks (src/scan.ts);
 * - npm's notes in a tree with a bunfig.toml and Python inputs (src/main.ts npmOutput).
 * The network is validation-helpers.ts fakeNet (a Python index serving pages captured from pypi.org, OSV), PATH a
 * directory of stub binaries, HOME empty, the clock fixed (helpers.ts NOW).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, posix } from "node:path";
import { run } from "../src/main.js";
import { discoverPython } from "../src/python/discover.js";
import { LOCK_REMEDIATION, localFileState } from "../src/python/requirements.js";
import { refusedByPipAndUv } from "../src/python/scripts.js";
import { lockProblemFinding } from "../src/python/soak.js";
import type { Finding } from "../src/types.js";
import { FIXTURES, fakeIO, fx } from "./helpers.js";
import { fakeNet, gitRepo, stubBin, tempTree } from "./validation-helpers.js";
import type { FakeNet } from "./validation-helpers.js";

const PY = join(FIXTURES, "python", "locks");
const UV = join(PY, "uv-0.12.21");
const text = (p: string): string => readFileSync(p, "utf8");
const SIMPLE_UV = text(join(UV, "simple", "uv.lock"));
const SIMPLE_PYPROJECT = text(join(UV, "simple", "pyproject.toml"));
const PYTHON_FILES = { "pyproject.toml": SIMPLE_PYPROJECT, "uv.lock": SIMPLE_UV };
/** six 1.16.0's wheel on pypi.org (test/fixtures/python/simple/six.json), uploaded 2021-05-05. */
const SIX_116 = "8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254";
const SIX_117_WHL_LINE =
  '    { url = "https://files.pythonhosted.org/packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl", hash = "sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274", size = 11050, upload-time = "2024-12-04T17:35:26.475Z" },';
const IOCS = ["--iocs", fx("iocs")];

const BIN = stubBin();
const GIT_DIR = dirname(execFileSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).trim());
const PATH = `${BIN}:${GIT_DIR}`;

interface Run {
  code: number;
  findings: Finding[];
  notes: string[];
  err: string;
}

/** A command through run() with `--format json`, the stub PATH and an empty HOME. */
async function cli(args: string[], net: FakeNet = fakeNet(), env: Record<string, string> = {}): Promise<Run> {
  const home = mkdtempSync(join(tmpdir(), "ws-pygate-home-"));
  const io = fakeIO({ env: { PATH, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), ...env }, fetchImpl: net.fetchImpl });
  const code = await run([...args, "--format", "json"], io);
  if (io.out === "") return { code, findings: [], notes: [], err: io.err };
  const doc = JSON.parse(io.out) as { findings: Finding[]; notes: string[] };
  return { code, findings: doc.findings, notes: doc.notes, err: io.err };
}
const soak = (dir: string, args: string[] = [], net?: FakeNet, env?: Record<string, string>): Promise<Run> => cli(["soak", dir, ...args], net, env);
const rules = (r: Run): string[] => r.findings.map((f) => `${f.ruleId} ${f.file ?? "-"}`).sort();
const baseline = (dir: string, fingerprints: string[], ignorePaths: string[] = []): void => {
  const doc = {
    version: 1,
    entries: fingerprints.map((fingerprint) => ({ fingerprint, justification: "reviewed by hand in this test on purpose" })),
    ...(ignorePaths.length > 0 ? { ignorePaths: ignorePaths.map((path) => ({ path, justification: "not installed by anything in this repository" })) } : {}),
  };
  writeFileSync(join(dir, ".wormsign-baseline.json"), JSON.stringify(doc));
};
/** The reader problems a run reports and its baseline does not suppress. */
const lockProblems = (r: Run): Finding[] => r.findings.filter((f) => f.key.startsWith("pypi:lockfile ") && f.suppressed === undefined);

/* ---- what a baseline entry for a reader problem approves ---- */

test("baseline: an entry for a requirements line's problem approves that line only; another name or hash there, or a second such line, fails again", async () => {
  // A sha512 beside the sha256: a plain index requirement soak parsed to the end, with a problem an entry may approve.
  const line = (pkg: string, digest: string): string => `${pkg} --hash=sha256:${digest} --hash=sha512:${"a".repeat(128)}\n`;
  const dir = tempTree({ "requirements.txt": `--require-hashes\n${line("six==1.16.0", SIX_116)}` });
  const first = await soak(dir);
  assert.equal(first.code, 1);
  const [problem] = lockProblems(first);
  assert.match(problem?.message ?? "", /requirements\.txt:2: --hash=sha512:aaaaaaaaaaaa\.\.\.: pip installs a file that matches any one listed hash/);
  assert.equal(problem?.notBaselinable, undefined);
  baseline(dir, [problem!.fingerprint]);
  const approved = await soak(dir);
  assert.equal(approved.code, 0, `${approved.err}${approved.findings.map((f) => f.message).join("\n")}`);

  // The same problem on another line's content: a new finding.
  writeFileSync(join(dir, "requirements.txt"), `--require-hashes\n${line("evil-pkg==6.6.6", "3".repeat(64))}`);
  const swapped = await soak(dir, ["--min-age", "100000d"]);
  assert.equal(swapped.code, 1);
  assert.notEqual(lockProblems(swapped)[0]?.fingerprint, problem!.fingerprint);
  writeFileSync(join(dir, "requirements.txt"), `--require-hashes\n${line("six==1.16.0", "4".repeat(64))}`);
  assert.equal((await soak(dir)).code, 1, "the same name with another hash");
  // A second line with the same option: the first stays approved, the second is new.
  writeFileSync(join(dir, "requirements.txt"), `--require-hashes\n${line("six==1.16.0", SIX_116)}${line("idna==3.20", "5".repeat(64))}`);
  const second = await soak(dir);
  assert.equal(second.code, 1);
  assert.deepEqual(lockProblems(second).map((f) => /requirements\.txt:(\d+)/.exec(f.message)?.[1]), ["3"], lockProblems(second).map((f) => f.message).join("\n"));
  // The approved line moved down by a blank line and a comment keeps its key.
  writeFileSync(join(dir, "requirements.txt"), `--require-hashes\n\n# pinned\n${line("six==1.16.0", SIX_116)}`);
  assert.equal((await soak(dir)).code, 0);
});

test("baseline: an entry for a requirements line naming a local archive approves those bytes only; other bytes, a missing archive or the line's old key fail again", async () => {
  const cases: [string, string, string][] = [
    ["requirements.txt", "./wheels/foo-1.0-py3-none-any.whl", "wheels/foo-1.0-py3-none-any.whl"],
    ["requirements.txt", "foo @ file:dist/foo-1.0.tar.gz", "dist/foo-1.0.tar.gz"],
    // pip resolves a relative path from where it runs; soak covers the file beside the requirements file and from the root.
    ["sub/requirements.txt", "./wheels/foo-1.0-py3-none-any.whl", "sub/wheels/foo-1.0-py3-none-any.whl"],
    ["sub/requirements.txt", "wheels/foo-1.0-py3-none-any.whl", "wheels/foo-1.0-py3-none-any.whl"],
  ];
  for (const [file, line, archive] of cases) {
    const what = `${file}: ${line}`;
    const dir = tempTree({ [file]: `--require-hashes\n${line}\n`, [archive]: "first archive bytes" });
    const first = await soak(dir, ["--no-osv"]);
    const [problem] = lockProblems(first);
    assert.match(problem?.message ?? "", /is a URL, VCS or path requirement, not a name==version pin/, what);
    assert.equal(lockProblems(first).length, 1, what);
    baseline(dir, [problem!.fingerprint]);
    assert.equal((await soak(dir, ["--no-osv"])).code, 0, `${what}: the approved archive, unchanged`);
    // Other bytes under the same name: a new key, so the entry no longer approves it.
    writeFileSync(join(dir, archive), "other archive bytes");
    const swapped = await soak(dir, ["--no-osv"]);
    assert.equal(swapped.code, 1, `${what}: swapped`);
    const other = lockProblems(swapped)[0]!.fingerprint;
    assert.notEqual(other, problem!.fingerprint, what);
    // Missing: a key of its own, never one made from content.
    rmSync(join(dir, archive));
    const missing = await soak(dir, ["--no-osv"]);
    assert.equal(missing.code, 1, `${what}: missing`);
    assert.ok(![problem!.fingerprint, other].includes(lockProblems(missing)[0]!.fingerprint), what);
    // The key the line had alone, before archives were covered: it approves nothing now.
    writeFileSync(join(dir, archive), "first archive bytes");
    const text = problem!.message.slice(`Cannot verify soak time for the packages in ${file}: `.length);
    const old = lockProblemFinding(file, text, createHash("sha256").update(line).digest("hex"), LOCK_REMEDIATION);
    baseline(dir, [old.fingerprint]);
    assert.equal((await soak(dir, ["--no-osv"])).code, 1, `${what}: an entry for the old key`);
  }
  // PR mode: the base's baseline approves the line with its archive; a change that swaps only the archive fails.
  const pins = { "requirements.txt": "--require-hashes\n./wheels/foo-1.0-py3-none-any.whl\n", "wheels/foo-1.0-py3-none-any.whl": "first archive bytes" };
  const fp = lockProblems(await soak(tempTree(pins), ["--no-osv"]))[0]!.fingerprint;
  const repo = gitRepo([
    (d) => {
      for (const [k, v] of Object.entries(pins)) {
        mkdirSync(dirname(join(d, k)), { recursive: true });
        writeFileSync(join(d, k), v);
      }
      baseline(d, [fp]);
    },
    (d) => writeFileSync(join(d, "README.md"), "docs\n"),
    (d) => writeFileSync(join(d, "wheels/foo-1.0-py3-none-any.whl"), "other archive bytes"),
  ]);
  assert.equal((await soak(repo, ["--base", "HEAD~2", "--no-osv"])).code, 1, "the archive swapped since the base");
  assert.equal((await soak(repo, ["--base", "HEAD~1", "--no-osv"])).code, 1);
  execFileSync("git", ["checkout", "-q", "HEAD~1"], { cwd: repo, stdio: "pipe" });
  assert.equal((await soak(repo, ["--base", "HEAD~1", "--no-osv"])).code, 0, "control: a README change, the archive the base approved");
});

test("baseline: a local archive reached through a symlink is keyed on the link and its target; one soak cannot pin by its content no entry approves", async () => {
  const line = "./wheels/foo-1.0-py3-none-any.whl";
  const link = "wheels/foo-1.0-py3-none-any.whl";
  const req = { "requirements.txt": `--require-hashes\n${line}\n` };
  const keyed = async (dir: string): Promise<Finding> => {
    const [f] = lockProblems(await soak(dir, ["--no-osv"]));
    assert.ok(f, dir);
    return f!;
  };
  // An in-root symlink: pip follows it, so the target's bytes and the target itself are in the key.
  const dir = tempTree({ ...req, "store/a.whl": "first archive bytes", "store/b.whl": "first archive bytes" });
  mkdirSync(join(dir, "wheels"));
  symlinkSync("../store/a.whl", join(dir, link));
  const first = await keyed(dir);
  assert.equal(first.notBaselinable, undefined, first.message);
  baseline(dir, [first.fingerprint]);
  assert.equal((await soak(dir, ["--no-osv"])).code, 0, "the approved target, unchanged");
  writeFileSync(join(dir, "store/a.whl"), "other archive bytes");
  assert.equal((await soak(dir, ["--no-osv"])).code, 1, "the target's bytes swapped");
  writeFileSync(join(dir, "store/a.whl"), "first archive bytes");
  rmSync(join(dir, link));
  symlinkSync("../store/b.whl", join(dir, link));
  assert.equal((await soak(dir, ["--no-osv"])).code, 1, "the link retargeted to the same bytes elsewhere");
  // Not content-keyable: no entry approves the line, and the message says why and what to do.
  const outsideDir = mkdtempSync(join(tmpdir(), "ws-pygate-outside-"));
  writeFileSync(join(outsideDir, "foo.whl"), "outside bytes");
  const cases: [string, (d: string) => void, string, RegExp][] = [
    ["a symlink out of the root", (d) => { mkdirSync(join(d, "wheels")); symlinkSync(join(outsideDir, "foo.whl"), join(d, link)); }, line, /a symlink leads it outside the scanned root/],
    ["a dangling symlink", (d) => { mkdirSync(join(d, "wheels")); symlinkSync("../nowhere.whl", join(d, link)); }, line, /a symlink that does not resolve/],
    ["a path outside the root", () => undefined, "../foo-1.0-py3-none-any.whl", /it is outside the scanned root/],
    ["a backslash path", () => undefined, ".\\wheels\\foo-1.0-py3-none-any.whl", /a backslash \(a Windows path/],
  ];
  if (process.getuid?.() !== 0) {
    cases.push(["an unreadable file", (d) => { mkdirSync(join(d, "wheels")); writeFileSync(join(d, link), "bytes"); chmodSync(join(d, link), 0o000); }, line, /it could not be read/]);
  }
  for (const [what, make, l, why] of cases) {
    const d = tempTree({ "requirements.txt": `--require-hashes\n${l}\n` });
    make(d);
    const f = await keyed(d);
    assert.equal(f.notBaselinable, true, `${what}: ${f.message}`);
    assert.match(f.message, why, what);
    assert.match(f.message, /\. No baseline entry can approve this finding: .*; make it a regular file inside the repository, or check from the repository root$/, what);
    baseline(d, [f.fingerprint]);
    const again = await soak(d, ["--no-osv"]);
    assert.equal(again.code, 1, `${what}: an entry for it changes nothing`);
    assert.ok(again.notes.includes(`baseline entry ${f.fingerprint} does not apply: no baseline entry can approve that finding (its message says why)`), `${what}: ${again.notes.join("\n")}`);
    if (what === "an unreadable file") chmodSync(join(d, link), 0o644);
  }
  // A file: URL with a query: pip drops it (urlsplit), so the archive's bytes are keyed, not "missing".
  const q = tempTree({ "requirements.txt": "--require-hashes\nfoo @ file:wheels/foo-1.0-py3-none-any.whl?x=1\n", [link]: "first archive bytes" });
  const withQuery = await keyed(q);
  assert.equal(withQuery.notBaselinable, undefined);
  writeFileSync(join(q, link), "other archive bytes");
  const swapped = await keyed(q);
  assert.notEqual(swapped.fingerprint, withQuery.fingerprint, "the bytes behind the query are in the key");
  rmSync(join(q, link));
  assert.ok(![withQuery.fingerprint, swapped.fingerprint].includes((await keyed(q)).fingerprint), "missing is a key of its own");
});

test("baseline: only a requirements line soak understands (an index requirement it parsed, a local file it resolved) can be baselined", async () => {
  const wheel = "wheels/foo-1.0-py3-none-any.whl";
  /** Every WS-SK-002 of a first run baselined, then the wheel swapped: the run must still fail. */
  const swapFails = async (what: string, files: Record<string, string>, archive: string | undefined, args: string[] = []): Promise<Finding[]> => {
    const dir = tempTree(files);
    const first = lockProblems(await soak(dir, ["--no-osv", ...args]));
    assert.ok(first.length > 0, what);
    baseline(dir, [...new Set(first.map((f) => f.fingerprint))]);
    if (archive !== undefined) writeFileSync(join(dir, archive), "other archive bytes");
    const again = await soak(dir, ["--no-osv", ...args]);
    assert.equal(again.code, 1, `${what}: ${again.findings.map((f) => f.message).join("\n")}`);
    return first;
  };
  // The review's line forms pip installs a local wheel from: none is a line soak understands.
  const forms: [string, string, string][] = [
    ["an option-parse problem after the path", `./${wheel} --`, wheel],
    ["another option on the line", `./${wheel} --config-settings=a=b`, wheel],
    ["extras on a path", `./${wheel}[x]`, wheel],
    ["extras on a bare archive name", "foo-1.0-py3-none-any.whl[x]", "foo-1.0-py3-none-any.whl"],
    ["a variable", `\${GITHUB_WORKSPACE}/${wheel}`, wheel],
    ["a path missing at every place", "./wheels/not-here-1.0-py3-none-any.whl", wheel],
    ["a file beside, the same path outside the root from the root", "../wheels/foo-1.0-py3-none-any.whl", "wheels/foo-1.0-py3-none-any.whl"],
  ];
  for (const [what, line, archive] of forms) {
    const file = what.startsWith("a file beside") ? "sub/requirements.txt" : "requirements.txt";
    const at = what.startsWith("a file beside") ? `sub/../${archive}` : archive;
    const first = await swapFails(what, { [file]: `--require-hashes\n${line}\n`, [at.replace("sub/../", "")]: "first archive bytes" }, at.replace("sub/../", ""));
    assert.ok(first.every((f) => f.notBaselinable === true), `${what}: ${first.map((f) => `${f.notBaselinable} ${f.message}`).join("\n")}`);
    assert.ok(first.some((f) => / No baseline entry can approve this finding: /.test(f.message)), what);
  }
  // The stop after 200 problems: what follows (a wheel line) was never read.
  const stop = await swapFails("the 200-problem stop", { "requirements.txt": `--require-hashes\n${"--prefer-binary\n".repeat(201)}./${wheel}\n`, [wheel]: "first archive bytes" }, wheel);
  const stopped = stop.find((f) => /more than 200 problems, so reading stopped/.test(f.message));
  assert.equal(stopped?.notBaselinable, true, stopped?.message);
  assert.match(stopped?.message ?? "", /No baseline entry can approve this finding: the reading stopped here, so what follows was never read$/);
  // Any other halt: more than 1,000 file reads in one unit.
  const halted = lockProblems(await soak(tempTree({ "requirements.txt": `--require-hashes\n${"-r b.txt\n".repeat(1001)}`, "b.txt": `six==1.16.0 --hash=sha256:${SIX_116}\n` }), ["--no-osv"])).find((f) => /more than 1000 file reads/.test(f.message));
  assert.equal(halted?.notBaselinable, true, halted?.message);

  // (a) A plain index requirement soak parsed to the end: baselinable, and its key is the one it always had.
  const plain = tempTree({ "requirements.txt": "--require-hashes\nfoo>=1\n" });
  const [unpinned] = lockProblems(await soak(plain, ["--no-osv"]));
  assert.equal(unpinned?.notBaselinable, undefined, unpinned?.message);
  const text = 'requirements.txt:2: "foo>=1" is not pinned with a single ==version; ' + LOCK_REMEDIATION;
  assert.equal(unpinned!.fingerprint, lockProblemFinding("requirements.txt", text, createHash("sha256").update("foo>=1").digest("hex"), LOCK_REMEDIATION).fingerprint, "the fingerprint is unchanged");
  baseline(plain, [unpinned!.fingerprint]);
  assert.equal((await soak(plain, ["--no-osv"])).code, 0);
  for (const line of ["foo[bar,baz] ~=1.2, !=1.3 ; python_version >= \"3.9\"", `six==1.16.0 --hash=sha512:${"a".repeat(128)}`, "six==1.16.0"]) {
    const [f] = lockProblems(await soak(tempTree({ "requirements.txt": `--require-hashes\n${line}\n` }), ["--no-osv"]));
    assert.equal(f?.notBaselinable, undefined, `${line}: ${f?.message}`);
  }
  // (b) A local file resolved to a regular file inside the root: baselinable.
  const local = tempTree({ "requirements.txt": `--require-hashes\n./${wheel}\n`, [wheel]: "first archive bytes" });
  const [resolved] = lockProblems(await soak(local, ["--no-osv"]));
  assert.equal(resolved?.notBaselinable, undefined, resolved?.message);
  baseline(local, [resolved!.fingerprint]);
  assert.equal((await soak(local, ["--no-osv"])).code, 0);
  // A directory is not a regular file: not baselinable.
  const dir = tempTree({ "requirements.txt": "--require-hashes\n./pkg\n", "pkg/pyproject.toml": '[project]\nname = "pkg"\nversion = "1.0"\n' });
  assert.equal(lockProblems(await soak(dir, ["--no-osv"]))[0]?.notBaselinable, true);

  // SARIF carries the mark in properties.
  const home = mkdtempSync(join(tmpdir(), "ws-pygate-home-"));
  const io = fakeIO({ env: { PATH, HOME: home, XDG_CONFIG_HOME: join(home, ".config") }, fetchImpl: fakeNet().fetchImpl });
  await run(["soak", tempTree({ "requirements.txt": "--require-hashes\n-e .\nfoo>=1\n" }), "--no-osv", "--format", "sarif"], io);
  const results = (JSON.parse(io.out) as { runs: { results: { message: { text: string }; properties: Record<string, unknown> }[] }[] }).runs[0]!.results;
  assert.deepEqual(results.map((r) => [/option -e/.test(r.message.text) ? "-e" : "foo", r.properties["notBaselinable"] ?? null]).sort(), [["-e", true], ["foo", null]]);
});

test('soak: a comment or a glued "\\" on a line continued with "\\" is one high WS-SK-002 no entry approves: pip reads the next line into it, uv reads it on its own', async () => {
  const evil = `evil==0.0.1 --hash=sha256:${"e".repeat(64)}`;
  const COMMENT = /requirements\.txt:2: a comment \("#" at the start or after a space\) on a line that ends in "\\": pip joins the next line into the comment/;
  const GLUED = /requirements\.txt:2: a "\\" with no space before it at the end of a line: pip joins the next line to the text before it/;
  /** six 1.16.0's sdist on pypi.org (test/fixtures/python/simple/six.json). */
  const SDIST = "1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926";
  const forms: [string, string, RegExp][] = [
    ["a comment", `--require-hashes\nsix==1.16.0 --hash=sha256:${SIX_116} #\\\n${evil}\n`, COMMENT],
    ['a "#" with no space before it (pip reads evil into the hash value; was an approvable bad-hash problem)', `--require-hashes\nsix==1.16.0 --hash=sha256:${SIX_116}#\\\n${evil}\n`, GLUED],
    // Repro A: an approvable "not a lowercase hex" problem; baselined, soak passed having checked nothing uv installs.
    ['a "\\" glued to a hash value', `--require-hashes\nsix==1.16.0 --hash=sha256:${SIX_116} --hash=sha256:0\\\n${evil}\n`, GLUED],
    // Repro B: six's sdist hash split before its last four digits. pip reads the whole hash; uv installs "c926", any
    // version. soak read six alone and found nothing at all.
    ["a hash split across a glued \"\\\"", `--require-hashes\nsix==1.16.0 --hash=sha256:${SIX_116} --hash=sha256:${SDIST.slice(0, 60)}\\\n${SDIST.slice(60)}\n`, GLUED],
  ];
  for (const [what, text, message] of forms) {
    const dir = tempTree({ "requirements.txt": text });
    const r = await soak(dir, ["--no-osv"]);
    assert.equal(r.code, 1, `${what}: uv installs a line soak never read`);
    const found = lockProblems(r);
    assert.deepEqual(found.map((f) => `${f.ruleId} ${f.severity} ${f.notBaselinable}`), ["WS-SK-002 high true"], what);
    assert.match(found[0]!.message, message, what);
    assert.match(found[0]!.message, /uv .* reads the next line on its own; .*\. No baseline entry can approve this finding: /, what);
    baseline(dir, [found[0]!.fingerprint]);
    const again = await soak(dir, ["--no-osv"]);
    assert.equal(again.code, 1, what);
    assert.ok(again.notes.some((n) => n.startsWith(`baseline entry ${found[0]!.fingerprint} does not apply`)), again.notes.join("\n"));
  }
  // `--require-hashes\\` then evil: pip refuses the joined option, uv installs evil. Not "refused by pip and uv" (a
  // finding a baseline entry could approve as a file nothing installs from): the glued "\\", which no entry approves.
  const glued = "--require-hashes\\\nevil==0.0.1\nsix==1.16.0 --hash=sha256:" + SIX_116 + "\n";
  assert.equal(refusedByPipAndUv(Buffer.from(glued)), false);
  const both = lockProblems(await soak(tempTree({ "requirements.txt": glued }), ["--no-osv"]));
  assert.deepEqual(both.map((f) => f.notBaselinable), [true], both.map((f) => f.message).join("\n"));
  assert.match(both[0]!.message, /requirements\.txt:1: an option on a line that ends in "\\"/);
  assert.doesNotMatch(both[0]!.message, /cannot read it as one/);
  // An include continued with "\\": pip reads a.txt (six), uv the file "a.txt " (its value to the line break, the space
  // and "\\" unquoted away), which soak never opened. Made here: such a name does not check out on Windows.
  const sixLine = `six==1.16.0 --hash=sha256:${SIX_116}\n`;
  const includes: [string, string, string][] = [
    ["a blank line after", "-r a.txt \\\n\n", "a.txt "],
    ["the end of the file", "-r a.txt \\", "a.txt "],
    ["a comment line after", "-r a.txt \\\n# c\n", "a.txt "],
    ["--requirement=", "--requirement=a.txt \\\n\n", "a.txt "],
    ["a tab before the \"\\\"", "-r a.txt\t\\\n\n", "a.txt\t"],
    ["a doubled \"\\\\\"", "-r a.txt \\\\\n\n", "a.txt \\"],
    ["CRLF", "-r a.txt \\\r\n\r\n", "a.txt "],
    ["-c", `-c a.txt \\\n\n${sixLine}`, "a.txt "],
  ];
  for (const [what, line, other] of includes) {
    const dir = tempTree({ "requirements.txt": `--require-hashes\n${line}`, "a.txt": sixLine });
    // Windows drops a trailing space and refuses a tab or "\\" in a name; the finding does not depend on the file.
    if (process.platform !== "win32") writeFileSync(join(dir, other), "evil-young-pkg\n");
    const r = await soak(dir, ["--no-osv"]);
    assert.equal(r.code, 1, `${what}: ${r.findings.map((f) => f.message).join("\n")}`);
    const found = lockProblems(r).filter((f) => f.file === "requirements.txt");
    assert.deepEqual(found.map((f) => `${f.severity} ${f.notBaselinable}`), ["high true"], what);
    assert.match(found[0]!.message, /requirements\.txt:2: an option on a line that ends in "\\": pip joins the next line to it, while uv reads the option's value to the line break, .*; write the option and its value on one line, with no "\\"/, what);
  }
  // The NIT: "--hash" then "=sha256:..." on the next line is outside the shape.
  const split = lockProblems(await soak(tempTree({ "requirements.txt": `--require-hashes\nsix==1.16.0 --hash \\\n=sha256:${SIX_116}\n` }), ["--no-osv"]));
  assert.deepEqual(split.map((f) => f.notBaselinable), [true]);
  assert.match(split[0]!.message, /requirements\.txt:3: a line continued with "\\" outside the shape pip-compile and uv pip compile write/);
  // A baselined `foo>=1` that comes to hide a wheel behind "#\\" is not the line its entry approved.
  const plain = tempTree({ "requirements.txt": "--require-hashes\nfoo>=1\n", "evil.whl": "planted wheel bytes" });
  const [unpinned] = lockProblems(await soak(plain, ["--no-osv"]));
  baseline(plain, [unpinned!.fingerprint]);
  assert.equal((await soak(plain, ["--no-osv"])).code, 0, "control: the entry approves foo>=1");
  writeFileSync(join(plain, "requirements.txt"), "--require-hashes\nfoo>=1 #\\\n./evil.whl\n");
  const hidden = await soak(plain, ["--no-osv"]);
  assert.equal(hidden.code, 1);
  assert.deepEqual(lockProblems(hidden).map((f) => f.notBaselinable), [true]);
});

test('soak: a ".." after a directory name in an include or a local path is a WS-SK-002 no entry approves: pip resolves it as text, uv through the symlink', async () => {
  const sixLine = `six==1.16.0 --hash=sha256:${SIX_116}\n`;
  // node_modules/foo -> ../deep/x: pip reads node_modules/a.txt (six), uv deep/a.txt (evil). Made here, as a link.
  const dir = tempTree({ "requirements.txt": "--require-hashes\n-r node_modules/foo/../a.txt\n", "node_modules/a.txt": sixLine, "deep/x/keep": "", "deep/a.txt": "evil==0.0.1\n" });
  symlinkSync("../deep/x", join(dir, "node_modules", "foo"));
  const r = await soak(dir, ["--no-osv"]);
  assert.equal(r.code, 1, r.findings.map((f) => f.message).join("\n"));
  const found = lockProblems(r).filter((f) => f.file === "requirements.txt");
  assert.deepEqual(found.map((f) => `${f.severity} ${f.notBaselinable}`), ["high true"]);
  assert.match(found[0]!.message, /requirements\.txt:2: -r node_modules\/foo\/\.\.\/a\.txt: a "\.\." after a directory name in the path: pip resolves it as text \(a\/\.\.\/b is b\), while uv joins the path as written, so the system follows a symlink at a first/);
  // A local file named the same way: not the local file an entry could approve by its bytes.
  const wheel = tempTree({ "requirements.txt": "--require-hashes\n./w/link/../foo-1.0-py3-none-any.whl\n", "w/foo-1.0-py3-none-any.whl": "wheel bytes", "w/link/keep": "" });
  const [w] = lockProblems(await soak(wheel, ["--no-osv"]));
  assert.equal(w?.notBaselinable, true, w?.message);
  assert.match(w!.message, /a "\.\." after a directory name in the path.*No baseline entry can approve this finding: pip and uv can install different files from this line/);
  // Control: ".." that only climbs from the including file's own directory (no name before it) is read.
  const up = tempTree({ "sub/requirements.txt": "--require-hashes\n-r ../a.txt\n", "a.txt": `--require-hashes\n${sixLine}` });
  const read = await soak(up, ["--no-osv"]);
  assert.equal(read.code, 0, read.findings.map((f) => f.message).join("\n"));
});

test("soak: a file pip refuses but uv may install from is one WS-SK-002 keyed on its exact bytes, which says so; a --pre continued onto a requirement is none an entry approves", async () => {
  // Read as refused by pip and uv (scripts.ts refusedByPipAndUv), though uv installs evil from each.
  const repros = [
    'evil==0.0.1 ; os_name != "a -b"\n',
    "--require-hashes --bogus\nevil==0.0.1\n",
    "--prex\nevil==0.0.1\n",
    "--no-indexevil==0.0.1\n",
  ];
  const cases: [string, string][] = [...repros.map((t): [string, string] => ["requirements.txt", t]), ["deps.txt", "--require-hashes --bogus\nevil==0.0.1\n"]];
  for (const [file, text] of cases) {
    const dir = tempTree({ [file]: text });
    const first = await soak(dir, ["--no-osv"]);
    const found = first.findings.filter((f) => f.ruleId === "WS-SK-002");
    assert.equal(found.length, 1, `${JSON.stringify(text)}: ${found.map((f) => f.message).join("\n")}`);
    assert.match(found[0]!.message, /pip and uv do not read such files alike \(uv installs from some lines pip refuses\), so check that neither .*installs from it before you approve it with a baseline entry \(it holds for these exact bytes; any edit reports it again\)/, `${file}: ${found[0]!.message}`);
    assert.match(found[0]!.message, file === "deps.txt" ? /it is written like a pip requirements file/ : /it is named like a pip requirements file/);
    baseline(dir, [found[0]!.fingerprint]);
    assert.equal((await soak(dir, ["--no-osv"])).code, 0, `${JSON.stringify(text)}: the entry approves these bytes`);
    writeFileSync(join(dir, file), `${text} `);
    assert.equal((await soak(dir, ["--no-osv"])).code, 1, `${JSON.stringify(text)}: one byte more is reported again`);
  }
  // "--pre \\" then a requirement: pip refuses the joined line, uv installs evil. A continued option, which no entry
  // approves, not a file "refused by both".
  const pre = lockProblems(await soak(tempTree({ "requirements.txt": '--pre \\\nevil==0.0.1 ; os_name != "-x"\n' }), ["--no-osv"]));
  assert.deepEqual(pre.map((f) => f.notBaselinable), [true], pre.map((f) => f.message).join("\n"));
  assert.match(pre[0]!.message, /requirements\.txt:1: an option on a line that ends in "\\"/);
});

test("baseline: the missing --require-hashes line is keyed on nothing, so no entry approves it, and the message says to add the line", async () => {
  const hashed = `six==1.16.0 --hash=sha256:${SIX_116}\n`;
  const cases: [string, Record<string, string>, RegExp][] = [
    ["no line at all", { "requirements.txt": hashed }, /requirements\.txt: no --require-hashes line in the file or the files it includes; add a `--require-hashes` line at the top of requirements\.txt/],
    ["the line only in a file reached through -c", { "requirements.txt": `-c c.txt\n${hashed}`, "c.txt": "--require-hashes\n" }, /c\.txt:1: --require-hashes only in a file reached through -c, where uv ignores it/],
  ];
  for (const [what, files, problem] of cases) {
    const dir = tempTree(files);
    const r = await soak(dir, ["--no-osv"]);
    const [f, ...rest] = lockProblems(r);
    assert.deepEqual(rest, [], what);
    assert.match(f?.message ?? "", problem, what);
    assert.equal(f?.notBaselinable, true, `${what}: ${f?.message}`);
    assert.match(f!.message, /\. No baseline entry can approve this finding: the missing line is keyed on no text of the file, so an entry would approve it whatever the file comes to hold; the remedy is to add a --require-hashes line to the requirements file itself$/, what);
    baseline(dir, [f!.fingerprint]);
    assert.equal((await soak(dir, ["--no-osv"])).code, 1, `${what}: the entry does not apply`);
  }
  // baseline add --from refuses its fingerprint, with the reason, from the report soak wrote.
  const dir = tempTree({ "requirements.txt": hashed });
  const report = join(mkdtempSync(join(tmpdir(), "ws-pygate-report-")), "report.json");
  const home = mkdtempSync(join(tmpdir(), "ws-pygate-home-"));
  const env = { PATH, HOME: home, XDG_CONFIG_HOME: join(home, ".config") };
  assert.equal(await run(["soak", dir, "--no-osv", "--format", "json", "--output", report], fakeIO({ env, fetchImpl: fakeNet().fetchImpl })), 1);
  const [f] = (JSON.parse(readFileSync(report, "utf8")) as { findings: Finding[] }).findings.filter((x) => x.ruleId === "WS-SK-002");
  const io = fakeIO({ env });
  assert.equal(await run(["baseline", "add", f!.fingerprint, "--reason", "reviewed by hand in this test on purpose", "--baseline", join(dir, "b.json"), "--from", report], io), 2);
  assert.match(io.err, new RegExp(`fingerprint ${f!.fingerprint} \\(WS-SK-002\\) is a finding no baseline entry can approve, .*: the missing line is keyed on no text of the file, .*the remedy is to add a --require-hashes line`));
});

test("baseline: a local file is keyed at the directories of the top-level file and of each include too, where pip may run", async () => {
  // backend/requirements.txt includes sub/inc.txt, which names ./x.whl: run from backend/, pip installs backend/x.whl.
  const cases: [string, Record<string, string>, string][] = [
    ["the top-level file's directory", { "backend/requirements.txt": "--require-hashes\n-r sub/inc.txt\n", "backend/sub/inc.txt": "./x.whl\n", "x.whl": "root wheel bytes" }, "backend/x.whl"],
    ["an including file's directory", { "requirements.txt": "--require-hashes\n-r a/mid.txt\n", "a/mid.txt": "-r b/inc.txt\n", "a/b/inc.txt": "./x.whl\n", "x.whl": "root wheel bytes" }, "a/x.whl"],
  ];
  for (const [what, files, planted] of cases) {
    const dir = tempTree(files);
    const first = lockProblems(await soak(dir, ["--no-osv"]));
    assert.ok(first.length > 0 && first.every((f) => f.notBaselinable === undefined), `${what}: ${first.map((f) => f.message).join("\n")}`);
    baseline(dir, [...new Set(first.map((f) => f.fingerprint))]);
    assert.equal((await soak(dir, ["--no-osv"])).code, 0, `${what}: control, the entry approves the root's x.whl`);
    writeFileSync(join(dir, planted), "planted wheel bytes");
    assert.equal((await soak(dir, ["--no-osv"])).code, 1, `${what}: a wheel planted at ${planted}`);
  }
});

test("baseline: a URL with a scheme and no // (file:foo, git+file:repo) and a requirement soak cannot parse to the end are not baselinable", async () => {
  const notes: [string, RegExp][] = [
    ["file:foo", /"file:foo" is a URL, VCS or path requirement, not a name==version pin/],
    ["git+file:repo", /"git\+file:repo" is a URL, VCS or path requirement, not a name==version pin/],
    // Past the name, only specifiers soak reads to the end may follow (SPECIFIERS).
    ["foo (>=1)", /"foo \(>=1\)" is not pinned with a single ==version/],
    // The name as written is tested for an archive's file name, not the normalized one (foo-whl).
    [`foo.whl==1.0 --hash=md5:${"a".repeat(32)}`, /--hash=md5:a{32}: pip accepts only sha256/],
    ["foo.whl==1.0", /foo-whl==1\.0 has no --hash=sha256/],
  ];
  for (const [line, message] of notes) {
    const found = lockProblems(await soak(tempTree({ "requirements.txt": `--require-hashes\n${line}\n` }), ["--no-osv"]));
    assert.equal(found.length, 1, `${line}: ${found.map((f) => f.message).join("\n")}`);
    assert.match(found[0]!.message, message, line);
    assert.equal(found[0]!.notBaselinable, true, `${line}: ${found[0]!.message}`);
  }
  // Control: the same forms with a plain name are baselinable.
  for (const line of ["foo>=1", `foo==1.0 --hash=md5:${"a".repeat(32)}`, "foo==1.0"]) {
    const [f] = lockProblems(await soak(tempTree({ "requirements.txt": `--require-hashes\n${line}\n` }), ["--no-osv"]));
    assert.equal(f?.notBaselinable, undefined, `${line}: ${f?.message}`);
  }
});

test("requirements: a local file's state is keyed by its content, and a file larger than the read bound cannot be pinned", () => {
  const root = mkdtempSync(join(tmpdir(), "ws-pygate-state-"));
  writeFileSync(join(root, "a.whl"), "eleven byte");
  assert.match(JSON.stringify(localFileState(root, "a.whl")), /^\{"key":"sha256:[0-9a-f]{64}"\}$/);
  assert.deepEqual(localFileState(root, "a.whl", 10), { unkeyable: "it is larger than 10 bytes" });
  assert.ok("key" in localFileState(root, "a.whl", 11), "at the bound it is read");
  assert.deepEqual(localFileState(root, "missing.whl"), { key: "missing" });
  assert.deepEqual(localFileState(root, ""), { key: "directory" });
  mkdirSync(join(root, "loop"));
  symlinkSync("b", join(root, "loop", "a"));
  symlinkSync("a", join(root, "loop", "b"));
  assert.deepEqual(localFileState(root, "loop/a"), { unkeyable: "it is a symlink that does not resolve (dangling, or a loop)" });
});

test("baseline: an entry for a uv.lock wheel with an unknown key approves that wheel only; another url there fails again", async () => {
  const withKey = (url: string): string => SIMPLE_UV.replace(SIX_117_WHL_LINE, SIX_117_WHL_LINE.replace(/\{ url = "[^"]+"/, `{ url = "${url}"`).replace(" },", ', zstd = "x" },'));
  const real = /\{ url = "([^"]+)"/.exec(SIX_117_WHL_LINE)![1]!;
  const dir = tempTree({ "pyproject.toml": SIMPLE_PYPROJECT, "uv.lock": withKey(real) });
  const first = await soak(dir);
  assert.equal(first.code, 1);
  const [problem] = lockProblems(first);
  assert.match(problem?.message ?? "", /wheel #1: unknown key\(s\) "zstd": format not supported/);
  baseline(dir, [problem!.fingerprint]);
  assert.equal((await soak(dir)).code, 0, "approved: the reader dropped the wheel, and six is checked by its sdist");
  writeFileSync(join(dir, "uv.lock"), withKey("https://evil.example.invalid/six-1.17.0-py2.py3-none-any.whl"));
  const evil = await soak(dir);
  assert.equal(evil.code, 1);
  assert.notEqual(lockProblems(evil)[0]?.fingerprint, problem!.fingerprint);
});

test("baseline: an entry for a lock this reader cannot read at all (an unknown revision) approves that file's content only", async () => {
  const unknown = SIMPLE_UV.replace("revision = 3", "revision = 99");
  const dir = tempTree({ "pyproject.toml": SIMPLE_PYPROJECT, "uv.lock": unknown });
  const first = await soak(dir);
  const [problem] = lockProblems(first);
  assert.match(problem?.message ?? "", /lockfile revision 99 is not one this reader knows/);
  baseline(dir, [problem!.fingerprint]);
  assert.equal((await soak(dir)).code, 0);
  writeFileSync(join(dir, "uv.lock"), unknown.replace('version = "1.17.0"', 'version = "1.16.0"'));
  assert.equal((await soak(dir)).code, 1, "any edit to the unread lock is a new finding");
});

/* ---- names that must not leave the machine ---- */

test("soak (privacy): a requirements file's own index options send none of its names anywhere", async () => {
  const pin = `six==1.16.0 --hash=sha256:${SIX_116}\n`;
  for (const option of ["--index-url https://private.example.invalid/simple", "-i https://private.example.invalid/simple", "--extra-index-url https://corp.example.invalid/simple", "--ext https://corp.example.invalid/simple", "-f https://corp.example.invalid/links", "--no-index", "-r https://corp.example.invalid/more.txt"]) {
    const net = fakeNet();
    const r = await soak(tempTree({ "requirements.txt": `--require-hashes\n${option}\n${pin}` }), [], net);
    assert.equal(r.code, 1, option);
    assert.deepEqual(net.calls, [], `${option}: no request to the index or OSV`);
    const six = r.findings.find((f) => f.message.startsWith("Cannot verify soak time for PyPI package six==1.16.0"));
    assert.match(six?.message ?? "", /an install of requirements\.txt may use another index \(its own .* at requirements\.txt:2\), so its name is sent nowhere/, option);
  }
  // In an included file too: pip applies an include's index options to the whole install.
  const net = fakeNet();
  const inc = await soak(tempTree({ "requirements.txt": `--require-hashes\n-r more.txt\n${pin}`, "more.txt": "--extra-index-url https://corp.example.invalid/simple\n" }), [], net);
  assert.equal(inc.code, 1);
  assert.deepEqual(net.calls, []);
  // Control: the same file without the option is checked.
  const control = fakeNet();
  assert.equal((await soak(tempTree({ "requirements.txt": `--require-hashes\n${pin}` }), [], control)).code, 0);
  assert.ok(control.calls.includes("https://pypi.org/simple/six/"));
});

test("soak (privacy): a pylock.toml package with no index whose file URLs are on another host is sent nowhere", async () => {
  const wheel = (url: string) => `lock-version = "1.0"\ncreated-by = "pip"\n\n[[packages]]\nname = "acme-internal-billing"\nversion = "1.0"\n\n[[packages.wheels]]\nname = "acme_internal_billing-1.0-py3-none-any.whl"\nurl = "${url}"\n\n[packages.wheels.hashes]\nsha256 = "${"1".repeat(64)}"\n`;
  const net = fakeNet();
  const r = await soak(tempTree({ "pylock.toml": wheel("https://pypi.corp.example/packages/acme_internal_billing-1.0-py3-none-any.whl") }), [], net);
  assert.equal(r.code, 1);
  assert.deepEqual(net.calls, [], "neither the index nor OSV is asked about acme-internal-billing");
  assert.match(r.findings.find((f) => f.ruleId === "WS-SK-002")?.message ?? "", /its file URLs are on https:\/\/pypi\.corp\.example, not the index's \(https:\/\/files\.pythonhosted\.org\), so its name is sent nowhere/);
  for (const url of ["https://files.pythonhosted.org\\@evil.example/x.whl", "http://files.pythonhosted.org/x.whl", "https://files.pythonhosted.org.evil.example/x.whl"]) {
    const n = fakeNet();
    await soak(tempTree({ "pylock.toml": wheel(url) }), [], n);
    assert.deepEqual(n.calls, [], url);
  }
  // Control: a file on pypi.org's file host is checked (and is not on the index: a 404).
  const control = fakeNet();
  await soak(tempTree({ "pylock.toml": wheel("https://files.pythonhosted.org/packages/acme_internal_billing-1.0-py3-none-any.whl") }), [], control);
  assert.deepEqual(control.calls, ["https://pypi.org/simple/acme-internal-billing/"]);
});

test("soak (privacy): a vendored archive's name is looked up on the index only with an explicit --pypi-index", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ws-pygate-path-"));
  cpSync(join(UV, "path"), dir, { recursive: true });
  const net = fakeNet();
  const r = await soak(dir, [], net);
  assert.equal(r.code, 1);
  assert.ok(!net.calls.includes("https://pypi.org/simple/six/"), "six (vendor/six-1.17.0-py2.py3-none-any.whl) is not asked about");
  assert.match(r.findings.find((f) => f.message.startsWith("Cannot verify soak time for PyPI package six==1.17.0"))?.message ?? "", /it is a local archive, which can be checked only by asking the index for its name, and --pypi-index was not given explicitly to allow that, so its name is sent nowhere/);
  const explicit = fakeNet();
  const e = await soak(dir, ["--pypi-index", "https://pypi.org/simple/"], explicit);
  assert.ok(explicit.calls.includes("https://pypi.org/simple/six/"));
  assert.ok(!e.findings.some((f) => f.message.startsWith("Cannot verify soak time for PyPI package six==1.17.0")), e.findings.map((f) => f.message).join("\n"));
});

/* ---- what discovery reads ---- */

test("discovery: a hash lock or a script padded past 1 MiB is still found, and so is a script lock beside a file of any name", async () => {
  const pad = `# ${"x".repeat(1100 * 1024)}\n`;
  const lock = `--require-hashes\nsix==1.16.0 --hash=sha256:${SIX_116}\n`;
  // Control: the lock alone. Then padded past 1 MiB with a comment: still read, and its pin (young by 100000 days) found.
  assert.deepEqual(rules(await soak(tempTree({ "deps.txt": lock }), ["--min-age", "100000d"])), ["WS-SK-001 deps.txt"]);
  assert.deepEqual(rules(await soak(tempTree({ "deps.txt": `${lock}${pad}` }), ["--min-age", "100000d"])), ["WS-SK-001 deps.txt"]);
  assert.deepEqual(rules(await soak(tempTree({ "deps.txt": `${pad}${lock}` }), ["--min-age", "100000d"])), ["WS-SK-001 deps.txt"], "after the padding too");
  // A script with a lock beside it: read in full whatever its size or name, so the lock is the script's.
  const scriptLock = text(join(FIXTURES, "python", "repos", "scripts", "deploy.lock"));
  const block = '# /// script\n# requires-python = ">=3.9"\n# dependencies = ["six==1.17.0"]\n# ///\n';
  for (const name of ["deploy", "deploy.md"]) {
    const s = await soak(tempTree({ [name]: `${pad}${block}`, [`${name}.lock`]: scriptLock }));
    assert.ok(!s.notes.includes("no lockfile and no dependencies declared; the soak gate has nothing to verify"), `${name}: ${s.notes.join("\n")}`);
    assert.ok(s.findings.every((f) => f.file !== `${name}.lock` || f.ruleId !== "WS-SK-002" || !/no `uv run` uses this lock/.test(f.message)), `${name}: the lock is the script's`);
  }
  // A lock beside a file with no block is reported (no `uv run` uses it), unless it is not TOML (Gemfile.lock).
  const orphan = await soak(tempTree({ deploy: pad, "deploy.lock": scriptLock, Gemfile: "source 'https://rubygems.org'\n", "Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n" }));
  assert.deepEqual(rules(orphan).filter((x) => x.startsWith("WS-SK-002")), ["WS-SK-002 deploy.lock"]);
  // A lock with a reader of its own beside a file of the same stem is that reader's: poetry.lock beside a poetry script.
  const own = await soak(tempTree({ poetry: "#!/bin/sh\nexec poetry \"$@\"\n", "poetry.lock": '[[package]]\nname = "six"\nversion = "1.17.0"\n' }));
  assert.deepEqual(own.findings.map((f) => `${f.ruleId} ${f.file} ${/not supported yet/.test(f.message) ? "unsupported" : "other"}`), ["WS-SK-002 poetry.lock unsupported"]);
});

test("discovery: the content pass opens only candidate names, so a large npm tree costs no reads", () => {
  const files: Record<string, string> = { "package.json": '{"name":"x"}', "package-lock.json": '{"name":"x","lockfileVersion":3,"packages":{"":{"name":"x"}}}' };
  for (let i = 0; i < 400; i++) {
    files[`src/m${i}.ts`] = "export const x = 1;\n";
    files[`dist/m${i}.js`] = "exports.x = 1;\n";
    files[`docs/p${i}.md`] = "# page\n";
  }
  Object.assign(files, { "assets/logo.svg": "<svg/>", "data/x.json": "{}", Dockerfile: "FROM node:22\n", "ci/deps.txt": "x\n", "tools/run.sh": "echo\n", "tools/gen.py": "print(1)\n", "notes.md": "# notes\n", "notes.md.lock": "x\n" });
  const root = tempTree(files);
  const opened: string[] = [];
  const d = discoverPython(root, { pypiIndex: "https://pypi.org/simple/", env: { PATH }, onRead: (rel) => opened.push(rel) });
  assert.deepEqual(opened.sort(), ["Dockerfile", "ci/deps.txt", "notes.md", "notes.md.lock", "tools/gen.py", "tools/run.sh"]);
  assert.deepEqual([d.findings, d.locks, d.pythonInputs], [[], [], false], "nothing read is a Python input");
});

/** An npm project with a lockfile and a release-age setting: nothing of its own to report. */
const NPM_ONLY = { "package.json": '{"name":"app","version":"1.0.0"}', "package-lock.json": JSON.stringify({ name: "app", version: "1.0.0", lockfileVersion: 3, requires: true, packages: { "": { name: "app", version: "1.0.0" } } }), ".npmrc": "min-release-age=7\n" };
const UNREAD = /it is (named|written) like a pip requirements file.*but wormsign cannot read it as one, so none of its packages were checked/;
/** The WS-SK-002 findings "<file> one|other" (one: the whole file could not be read as requirements). */
const unread = (r: Run): string[] => r.findings.filter((f) => f.ruleId === "WS-SK-002").map((f) => `${f.file} ${f.severity} ${UNREAD.test(f.message) ? "one" : "other"}`).sort();

test("discovery: a file that shows a hashed pin but that wormsign cannot read as requirements is one high WS-SK-002, never a note", async () => {
  const h = `sha256:${"0123456789abcdef".repeat(4)}`;
  const noise = {
    Dockerfile: `FROM node:22\nWORKDIR /app\nRUN pip install --no-cache-dir awscli==1.40.0 --hash=${h}\nRUN npm ci --ignore-scripts\n`,
    "scripts/lint.sh": `#!/bin/sh\npython3 -m pip install "ruff==0.6.0" --hash ${h}\n`,
    // Not candidates by name, so not opened (docs/soak.md, "Discovery").
    ".github/workflows/ci.yml": `on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pip install six==1.17.0 --hash=${h}\n`,
    "README.md": `Install it with pip:\n\nsix==1.17.0 --hash=${h}\n`,
    "tools/gen.rb": `# -*- coding: binary -*-\nputs "six==1.17.0 --hash=${h}"\n`,
  };
  for (const args of [[], ["--config-only"], ["--no-osv"]]) {
    const r = await soak(tempTree({ ...NPM_ONLY, ...noise }), args);
    assert.equal(r.code, 1, args.join(" "));
    assert.deepEqual(unread(r), ["Dockerfile high one", "scripts/lint.sh high one"], args.join(" "));
    assert.ok(!r.notes.some((n) => /not as a requirements file|would both stop/.test(n)), r.notes.join("\n"));
  }
  // Control: the same tree without them reports nothing.
  assert.deepEqual((await soak(tempTree(NPM_ONLY))).findings, []);
  // An ignorePaths entry may name one file: it clears that file whatever it later holds.
  const ignoredFile = tempTree({ ...NPM_ONLY, ...noise });
  baseline(ignoredFile, [], ["Dockerfile"]);
  assert.deepEqual(unread(await soak(ignoredFile)), ["scripts/lint.sh high one"]);
  // A coding line naming anything but UTF-8 or ASCII: not sure what pip reads, so the file is read, and its problem
  // (the encoding) is the finding; the same for the codecs pip decodes some other way.
  for (const coding of ["utf-8-unix", "idna", "latin-1", "utf-16"]) {
    const r = await soak(tempTree({ ...NPM_ONLY, Makefile: `# -*- coding: ${coding} -*-\nall:\n\tpip install six==1.17.0 --hash=${h}\n` }));
    assert.deepEqual(unread(r), ["Makefile high other"], coding);
    assert.match(r.findings[0]!.message, /encoding not supported: a coding declaration names/, coding);
  }
});

test("discovery: a file named like a requirements file that cannot be read as one is one high WS-SK-002 for its content: a baseline entry approves that content, an ignorePaths entry its directory", async () => {
  // microsoft/TypeScript keeps compiler output under tests/baselines with names like this one.
  const baselineFile = "//// [genericConstraints.ts]\nfunction f<T extends string>(x: T) {}\n\n//// [genericConstraints.js]\nfunction f(x) { }\n";
  const file = "tests/baselines/genericConstraints.txt";
  const first = await soak(tempTree({ ...NPM_ONLY, [file]: baselineFile }), ["--no-osv"]);
  assert.equal(first.code, 1);
  assert.deepEqual(unread(first), [`${file} high one`]);
  assert.deepEqual(first.findings.map((f) => f.ruleId), ["WS-SK-002"], "exactly one finding");
  assert.ok(!first.notes.some((n) => /named like requirements files/.test(n)), first.notes.join("\n"));
  const fp = first.findings[0]!.fingerprint;
  // A base whose baseline approves the file: a pull request that only edits the README passes; one that edits the
  // approved file fails again (the entry approved that content only).
  const put = (d: string, files: Record<string, string>): void => {
    for (const [k, v] of Object.entries(files)) {
      mkdirSync(dirname(join(d, k)), { recursive: true });
      writeFileSync(join(d, k), v);
    }
  };
  const repo = gitRepo([
    (d) => {
      put(d, { ...NPM_ONLY, [file]: baselineFile });
      baseline(d, [fp]);
    },
    (d) => writeFileSync(join(d, "README.md"), "docs\n"),
  ]);
  const readme = await soak(repo, ["--base", "HEAD~1", "--no-osv"]);
  assert.equal(readme.code, 0, rules(readme).join("\n"));
  assert.deepEqual(readme.findings.map((f) => [f.ruleId, f.suppressed !== undefined]), [["WS-SK-002", true]]);
  writeFileSync(join(repo, file), `${baselineFile}//// [extra.js]\nvar x;\n`);
  execFileSync("git", ["-c", "user.email=v@v.invalid", "-c", "user.name=v", "-c", "commit.gpgsign=false", "commit", "-qam", "edit"], { cwd: repo, stdio: "pipe" });
  const edited = await soak(repo, ["--base", "HEAD~2", "--no-osv"]);
  assert.equal(edited.code, 1);
  assert.deepEqual(edited.findings.filter((f) => f.suppressed === undefined).map((f) => `${f.ruleId} ${f.file}`), [`WS-SK-002 ${file}`]);
  // One ignorePaths entry clears a directory of them.
  const ignoredDir = tempTree({ ...NPM_ONLY, [file]: baselineFile, "tests/baselines/otherConstraints.txt": "error TS2322\n" });
  baseline(ignoredDir, [], ["tests/baselines"]);
  const cleared = await soak(ignoredDir, ["--no-osv"]);
  assert.equal(cleared.code, 0, rules(cleared).join("\n"));
  assert.deepEqual(cleared.findings, []);
  // Control: the same name holding a hash lock is read as one.
  const read = await soak(tempTree({ ...NPM_ONLY, [file]: `--require-hashes\nsix==1.16.0 --hash=sha256:${SIX_116}\n` }), ["--no-osv"]);
  assert.ok(read.notes.includes("1 PyPI file(s) of 1 version(s) checked against https://pypi.org/simple/"), read.notes.join("\n"));
});

test("discovery: a line pip reads as a URL (file:pkgdir) or a control character pip strips keeps a file read for its packages, by name and by content, in PR mode too", async () => {
  // `file:pkgdir` is a URL to pip, so this is a requirements file pip installs from: every line is its own finding.
  const urls = "evil-young-pkg\nsix\nfile:pkgdir\n";
  // pip 26.1.2 strips the U+001F, so `pip install -r` installs idna, six and evil-young-pkg; uv refuses the file.
  const byName = "evil-young-pkg\nsix\n\x1fidna==3.10\n";
  // A file found by its content (a --require-hashes line), not its name.
  const byContent = `--require-hashes\nsix==1.16.0 --hash=sha256:${SIX_116}\n\x1fidna==3.10 --hash=sha256:${"3".repeat(64)}\n`;
  for (const [name, text] of [["requirements.txt", urls], ["requirements.txt", byName], ["deploy/pins.pip", byContent]] as const) {
    const repo = gitRepo([(d) => { for (const [k, v] of Object.entries(NPM_ONLY)) writeFileSync(join(d, k), v); }, (d) => { mkdirSync(dirname(join(d, name)), { recursive: true }); writeFileSync(join(d, name), text); }]);
    for (const args of [[], ["--base", "HEAD~1"]]) {
      const r = await soak(repo, [...args, "--no-osv"]);
      assert.equal(r.code, 1, `${name} ${args.join(" ")}: ${r.notes.join("\n")}`);
      const high = r.findings.filter((f) => f.severity === "high");
      assert.ok(high.length > 0 && high.every((f) => f.ruleId === "WS-SK-002" && f.file === name && !UNREAD.test(f.message)), `${JSON.stringify(text)} ${args.join(" ")}: ${high.map((f) => f.message).join("\n")}`);
    }
  }
  // The file:pkgdir file is read line by line: with no --require-hashes line, one finding names each line pip reads
  // (soak-python-noise.test.ts), and it is not the finding for a file wormsign cannot read as requirements.
  const lines = await soak(tempTree({ ...NPM_ONLY, "requirements.txt": urls }), ["--no-osv"]);
  const read = lines.findings.filter((f) => f.ruleId === "WS-SK-002");
  assert.equal(read.length, 1, read.map((f) => f.message).join("\n"));
  for (const n of [1, 2, 3]) assert.match(read[0]!.message, new RegExp(`requirements\\.txt:${n}: `));
  assert.doesNotMatch(read[0]!.message, UNREAD);
  // Control: plain ASCII lines one of which reads as no requirement: one finding for the whole file.
  const plain = await soak(tempTree({ ...NPM_ONLY, "requirements.txt": "evil-young-pkg\nsix\nidna==3.10 is pinned below\n" }), ["--no-osv"]);
  assert.deepEqual(unread(plain), ["requirements.txt high one"]);
});

test("soak: the baseline's ignorePaths keep Python inputs there out of the run (a vendored gyp setup.py, docs requirements)", async () => {
  const npm = { "package.json": '{"name":"app","version":"1.0.0"}', "package-lock.json": JSON.stringify({ name: "app", version: "1.0.0", lockfileVersion: 3, requires: true, packages: { "": { name: "app", version: "1.0.0" } } }), ".npmrc": "min-release-age=7\n" };
  const extra = { "deps/gyp/setup.py": "from setuptools import setup\nsetup()\n", "docs/requirements.txt": "mkdocs==1.6.1\nmkdocs-material==9.5.0\n" };
  const dir = tempTree({ ...npm, ...extra });
  const before = await soak(dir);
  assert.equal(before.code, 1);
  // The requirements file has no --require-hashes line: one finding for it and its two unhashed pins.
  assert.deepEqual(rules(before), ["WS-SK-002 deps/gyp/setup.py", "WS-SK-002 docs/requirements.txt"]);
  baseline(dir, [], ["deps/gyp", "docs"]);
  for (const args of [[], ["--config-only"]]) {
    const after = await soak(dir, args);
    assert.equal(after.code, 0, after.findings.map((f) => f.message).join("\n"));
    assert.deepEqual(after.findings, []);
    assert.ok(after.notes.includes("ignored paths (baseline): deps/gyp, docs; the Python inputs there were not read: deps/gyp/setup.py, docs/requirements.txt"), after.notes.join("\n"));
    // npm's own notes are those of the tree without the Python files.
    const plain = await soak(tempTree(npm), args);
    assert.deepEqual(after.notes.filter((n) => !n.startsWith("ignored paths")), plain.notes, args.join(" "));
  }
});

/* ---- PR mode: builds the change adds ---- */

test("soak --base: a WS-SK-005 the change adds is high (a new build requirement, a new build-forcing setting); one the base has stays medium", async () => {
  const lock = 'version = 1\nrevision = 3\nrequires-python = ">=3.9"\n\n[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { editable = "." }\n';
  const pyproject = (requires: string[]) => `[project]\nname = "app"\nversion = "0.1.0"\n\n[build-system]\nrequires = ${JSON.stringify(requires)}\nbuild-backend = "hatchling.build"\n`;
  const repo = gitRepo([
    (d) => {
      writeFileSync(join(d, "pyproject.toml"), pyproject(["hatchling"]));
      writeFileSync(join(d, "uv.lock"), lock);
    },
    (d) => writeFileSync(join(d, "pyproject.toml"), pyproject(["hatchling", "freshly-published-backend-plugin"])),
    (d) => writeFileSync(join(d, "uv.toml"), "no-build-isolation = true\n"),
  ]);
  const added = await soak(repo, ["--base", "HEAD~2"]);
  assert.equal(added.code, 1);
  const sev = (r: Run) => r.findings.filter((f) => f.ruleId === "WS-SK-005").map((f) => `${f.severity} ${f.file} ${f.key.split(" ")[0]}`).sort();
  assert.deepEqual(sev(added), ["high uv.lock pypi:build", "high uv.toml pypi:build-config"]);
  assert.match(added.findings.find((f) => f.file === "uv.lock")?.message ?? "", /"freshly-published-backend-plugin".*This change adds it \(HEAD~2 does not have it\), so it is high in PR mode\.$/);
  // Against the commit that added the plugin, the setting is new, and so is the build: a uv.toml in the project's
  // directory is part of its build key.
  assert.deepEqual(sev(await soak(repo, ["--base", "HEAD~1"])), ["high uv.lock pypi:build", "high uv.toml pypi:build-config"]);
  // Against itself, nothing is new: both stay medium and the default gate passes.
  const same = await soak(repo, ["--base", "HEAD"]);
  assert.equal(same.code, 0, same.findings.map((f) => f.message).join("\n"));
  assert.deepEqual(sev(same), ["medium uv.lock pypi:build", "medium uv.toml pypi:build-config"]);
  // A full run keeps the medium of every build.
  assert.deepEqual(sev(await soak(repo)), ["medium uv.lock pypi:build", "medium uv.toml pypi:build-config"]);
});

/** A uv.lock whose root project is an editable source: the install builds it. */
const APP_LOCK = (version = "0.1.0"): string => `version = 1\nrevision = 3\nrequires-python = ">=3.9"\n\n[[package]]\nname = "app"\nversion = "${version}"\nsource = { editable = "." }\n`;
const projectToml = (o: { backend?: string; requires?: string; deps?: string; version?: string; extra?: string }): string =>
  `[project]\nname = "app"\nversion = "${o.version ?? "0.1.0"}"\ndescription = "an app"\ndependencies = ${o.deps ?? '["six"]'}\n\n[build-system]\nrequires = ${o.requires ?? '["hatchling==1.27.0"]'}\nbuild-backend = "${o.backend ?? "hatchling.build"}"\n${o.extra ?? ""}`;

/**
 * A change to a locally built project, through soak --base HEAD~1, when the base's .wormsign-baseline.json approves
 * the base's build: "<exit code> <severity>[ suppressed]" of its WS-SK-005. A change that can alter the build is
 * "1 high"; one that cannot is "0 medium suppressed".
 */
type BuildFiles = Record<string, string | Buffer | { link: string } | null>;
async function buildChange(before: BuildFiles, after: BuildFiles, lock = APP_LOCK()): Promise<string> {
  const files: BuildFiles = { "uv.lock": lock, ...before };
  const put = (d: string, rel: string, text: string | Buffer | { link: string } | null): void => {
    if (text === null) return;
    mkdirSync(dirname(join(d, rel)), { recursive: true });
    rmSync(join(d, rel), { force: true });
    if (typeof text === "object" && !Buffer.isBuffer(text)) symlinkSync(text.link, join(d, rel));
    else writeFileSync(join(d, rel), text);
  };
  const scratch = mkdtempSync(join(tmpdir(), "ws-pygate-build-"));
  for (const [rel, text] of Object.entries(files)) put(scratch, rel, text);
  const first = await soak(scratch);
  const build = first.findings.find((f) => f.ruleId === "WS-SK-005" && f.key.startsWith("pypi:build "));
  assert.ok(build, `${rules(first).join("\n")}\n${first.err}`);
  const repo = gitRepo([
    (d) => {
      for (const [rel, text] of Object.entries(files)) put(d, rel, text);
      // Everything the base reports is approved there (a symlinked setup.cfg is a WS-SK-002 of its own).
      baseline(d, first.findings.map((f) => f.fingerprint));
    },
    (d) => {
      for (const [rel, text] of Object.entries(after)) {
        if (text === null) rmSync(join(d, rel));
        else put(d, rel, text);
      }
    },
  ]);
  const r = await soak(repo, ["--base", "HEAD~1"]);
  const sk5 = r.findings.filter((f) => f.ruleId === "WS-SK-005");
  assert.ok(r.findings.every((f) => f.ruleId === "WS-SK-005" || f.suppressed !== undefined || sk5.some((b) => b.severity === "high")), rules(r).join("\n"));
  return `${r.code} ${sk5.map((f) => `${f.severity}${f.suppressed !== undefined ? " suppressed" : ""}`).join(", ")}`;
}

test("soak --base: an edit that can add a build requirement to a local build is high, and the base's baseline entry no longer hides it", async () => {
  const hatch = projectToml({});
  // setup.cfg's setup_requires: setuptools installs it at build time.
  const setuptools = projectToml({ backend: "setuptools.build_meta", requires: '["setuptools==80.9.0"]' });
  assert.equal(await buildChange({ "pyproject.toml": setuptools, "setup.cfg": "[metadata]\nname = app\n" }, { "setup.cfg": "[metadata]\nname = app\n\n[options]\nsetup_requires = evil-fresh-pkg\n" }), "1 high");
  // A hatch builder's dependencies: hatchling returns them from get_requires_for_build_wheel.
  assert.equal(await buildChange({ "pyproject.toml": hatch }, { "pyproject.toml": projectToml({ extra: '\n[tool.hatch.build.targets.wheel]\ndependencies = ["evil-fresh-pkg"]\n' }) }), "1 high");
  // The ==-pinned build constraints taken away.
  const pinned = projectToml({ extra: '\n[tool.uv]\nbuild-constraint-dependencies = ["hatchling==1.27.0"]\n' });
  assert.equal(await buildChange({ "pyproject.toml": pinned }, { "pyproject.toml": hatch }), "1 high");
  // hatchling with require-runtime-dependencies builds with [project].dependencies installed.
  const runtime = (deps: string) => projectToml({ deps, extra: "\n[tool.hatch.build.targets.wheel]\nrequire-runtime-dependencies = true\n" });
  assert.equal(await buildChange({ "pyproject.toml": runtime('["six"]') }, { "pyproject.toml": runtime('["six", "evil-fresh-pkg"]') }), "1 high");
  const features = (deps: string) => projectToml({ deps, extra: '\n[tool.hatch.build]\nrequire-runtime-features = ["x"]\n' });
  assert.equal(await buildChange({ "pyproject.toml": features('["six"]') }, { "pyproject.toml": features('["six", "evil-fresh-pkg"]') }), "1 high");
  // A backend wormsign does not know may read [project] for its requirements.
  const unknown = (deps: string) => projectToml({ deps, backend: "inhouse_backend.api", requires: '["inhouse-backend==1.0"]' });
  assert.equal(await buildChange({ "pyproject.toml": unknown('["six"]') }, { "pyproject.toml": unknown('["six", "evil-fresh-pkg"]') }), "1 high");
  // A build hook: a new hatch_build.py, or an edit to the file a hook names.
  assert.equal(await buildChange({ "pyproject.toml": hatch }, { "hatch_build.py": "from hatchling.builders.hooks.plugin.interface import BuildHookInterface\n" }), "1 high");
  const hooked = projectToml({ extra: '\n[tool.hatch.build.hooks.custom]\npath = "tools/hook.py"\n' });
  assert.equal(await buildChange({ "pyproject.toml": hooked, "tools/hook.py": "# hook\n" }, { "tools/hook.py": "# hook\nimport os\n" }), "1 high");
  // uv.toml beside the project.
  assert.equal(await buildChange({ "pyproject.toml": hatch, "uv.toml": 'build-constraint-dependencies = ["hatchling==1.27.0"]\n' }, { "uv.toml": null }), "1 high");
});

test("soak --base: a version bump, metadata, a linter's settings or [project] dependencies under a known backend leave a local build as the base's", async () => {
  const hatch = projectToml({});
  // Control: nothing that decides the build changes, while every input the key reads is there on both sides.
  const full = { "pyproject.toml": projectToml({ extra: '\n[tool.hatch.build.hooks.custom]\npath = "tools/hook.py"\n' }), "tools/hook.py": "# hook\n", "hatch_build.py": "# default hook\n", "setup.cfg": "[metadata]\nname = app\n", "uv.toml": 'build-constraint-dependencies = ["hatchling==1.27.0"]\n' };
  assert.equal(await buildChange(full, { "README.md": "docs\n", "src/app/__init__.py": "x = 1\n" }), "0 medium suppressed");
  assert.equal(await buildChange({ "pyproject.toml": hatch }, { "pyproject.toml": projectToml({ version: "0.2.0" }), "uv.lock": APP_LOCK("0.2.0") }), "0 medium suppressed");
  assert.equal(await buildChange({ "pyproject.toml": hatch }, { "pyproject.toml": hatch.replace('description = "an app"', 'description = "an app, now with more"') }), "0 medium suppressed");
  const ruff = (n: number) => projectToml({ extra: `\n[tool.ruff]\nline-length = ${n}\n` });
  assert.equal(await buildChange({ "pyproject.toml": ruff(100) }, { "pyproject.toml": ruff(120) }), "0 medium suppressed");
  assert.equal(await buildChange({ "pyproject.toml": hatch }, { "pyproject.toml": ruff(100) }), "0 medium suppressed", "the first [tool] table, a linter's");
  // The project's own top-level modules, noxfile.py and conftest.py are its code, not its build configuration.
  const flat = { "pyproject.toml": hatch, "app.py": "x = 1\n", "noxfile.py": "import nox\n", "conftest.py": "import pytest\n" };
  assert.equal(await buildChange(flat, { "app.py": "x = 2\n", "noxfile.py": "import nox  # sessions\n", "conftest.py": "import pytest  # fixtures\n" }), "0 medium suppressed");
  // hatchling without require-runtime-dependencies or -features never installs [project].dependencies to build.
  assert.equal(await buildChange({ "pyproject.toml": hatch }, { "pyproject.toml": projectToml({ deps: '["six", "idna"]' }) }), "0 medium suppressed");
});

test("soak --base: hatch.toml and a uv workspace root's settings count for a local build; the base's identical files, symlinks and non-UTF-8 bytes included, leave it as the base's", async () => {
  const hatch = projectToml({});
  // hatch.toml is hatchling's [tool.hatch]: require-runtime-dependencies there makes [project].dependencies count.
  const runtime = "[build.targets.wheel]\nrequire-runtime-dependencies = true\n";
  assert.equal(await buildChange({ "pyproject.toml": hatch, "hatch.toml": runtime }, { "pyproject.toml": projectToml({ deps: '["six", "evil-fresh-pkg"]' }) }), "1 high");
  assert.equal(await buildChange({ "pyproject.toml": hatch, "hatch.toml": "[build]\ndev-mode-dirs = [\".\"]\n" }, { "pyproject.toml": projectToml({ deps: '["six", "evil-fresh-pkg"]' }) }), "0 medium suppressed");
  // ... its builder dependencies, and a hook file it names.
  assert.equal(await buildChange({ "pyproject.toml": hatch }, { "hatch.toml": '[build.targets.wheel]\ndependencies = ["evil-fresh-pkg"]\n' }), "1 high");
  const hooked = { "pyproject.toml": hatch, "hatch.toml": '[build.hooks.custom]\npath = "tools/h.py"\n', "tools/h.py": "# hook\n" };
  assert.equal(await buildChange(hooked, { "tools/h.py": "# hook\nimport os\n" }), "1 high");
  assert.equal(await buildChange(hooked, { "README.md": "docs\n" }), "0 medium suppressed");

  // A uv workspace: the root (virtual) lends its [tool.uv] and uv.toml to the member's build.
  const lock = 'version = 1\nrevision = 3\nrequires-python = ">=3.9"\n\n[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { virtual = "." }\n\n[[package]]\nname = "member"\nversion = "0.1.0"\nsource = { editable = "packages/member" }\n';
  const root = (version: string, uv: string) => `[project]\nname = "app"\nversion = "${version}"\n\n[tool.uv]\n${uv}\n[tool.uv.workspace]\nmembers = ["packages/member"]\n`;
  const pinned = 'build-constraint-dependencies = ["hatchling==1.27.0"]\n';
  const member = { "packages/member/pyproject.toml": projectToml({}).replace('name = "app"', 'name = "member"') };
  assert.equal(await buildChange({ "pyproject.toml": root("0.1.0", pinned), ...member }, { "pyproject.toml": root("0.1.0", "") }, lock), "1 high", "the root drops its build constraints");
  // Unverified whether uv applies [tool.uv.sources] to build requirements; it counts, failing closed.
  assert.equal(await buildChange({ "pyproject.toml": root("0.1.0", pinned), ...member }, { "pyproject.toml": `${root("0.1.0", pinned)}\n[tool.uv.sources]\nhatchling = { path = "vendor/hatchling" }\n` }, lock), "1 high", "a root source");
  assert.equal(await buildChange({ "pyproject.toml": root("0.1.0", pinned), ...member }, { "uv.toml": "build-constraint-dependencies = []\n" }, lock), "1 high", "a root uv.toml");
  assert.equal(await buildChange({ "pyproject.toml": root("0.1.0", pinned), ...member }, { "pyproject.toml": root("0.2.0", pinned) }, lock), "0 medium suppressed", "the root's version");

  // The same files on both sides digest alike, as git stores them: a symlinked setup.cfg, a non-UTF-8 hatch_build.py.
  const linked = { "pyproject.toml": hatch, "setup.cfg": { link: "config/common.cfg" }, "config/common.cfg": "[options]\nsetup_requires = wheel\n" };
  assert.equal(await buildChange(linked, { "README.md": "docs\n" }), "0 medium suppressed");
  assert.equal(await buildChange(linked, { "config/common.cfg": "[options]\nsetup_requires = evil-fresh-pkg\n" }), "1 high", "what the link leads to");
  assert.equal(await buildChange(linked, { "setup.cfg": { link: "config/other.cfg" }, "config/other.cfg": "[options]\nsetup_requires = wheel\n" }), "1 high", "where it leads");
  const latin1 = Buffer.from("# caf\xe9 hook\n", "latin1");
  assert.equal(await buildChange({ "pyproject.toml": hatch, "hatch_build.py": latin1 }, { "README.md": "docs\n" }), "0 medium suppressed");
  assert.equal(await buildChange({ "pyproject.toml": hatch, "hatch_build.py": latin1 }, { "hatch_build.py": Buffer.from("# caf\xe8 hook\n", "latin1") }), "1 high");
});

test("soak --base: a base tree with names that fold alike and absolute symlinks is read from git, nothing is written, and the build is new", async () => {
  const outside = mkdtempSync(join(tmpdir(), "ws-pygate-outside-"));
  /** A repository whose base commit also holds `plumbed` entries [mode, content, path], added to the index directly: a case-insensitive disk could not hold them beside the files. */
  const repoWith = (files: Record<string, string>, plumbed: [string, string, string][]): string => {
    const repo = gitRepo([]);
    const git = (args: string[], input?: string): string => execFileSync("git", ["-c", "user.email=v@v.invalid", "-c", "user.name=v", "-c", "commit.gpgsign=false", "-c", "core.ignorecase=false", ...args], { cwd: repo, input, encoding: "utf8" }).trim();
    for (const [rel, text] of Object.entries({ "uv.lock": APP_LOCK(), ...files })) {
      mkdirSync(dirname(join(repo, rel)), { recursive: true });
      writeFileSync(join(repo, rel), text);
    }
    git(["add", "-A"]);
    for (const [mode, content, path] of plumbed) git(["update-index", "--add", "--cacheinfo", `${mode},${git(["hash-object", "-w", "--stdin"], content)},${path}`]);
    git(["commit", "-qm", "base"]);
    writeFileSync(join(repo, "README.md"), "docs\n");
    git(["add", "README.md"]);
    git(["commit", "-qm", "readme"]);
    return repo;
  };
  const sk5 = (r: Run): string[] => r.findings.filter((f) => f.ruleId === "WS-SK-005").map((f) => f.severity);
  // `Hooks`, a symlink out of the tree, beside the hook directory `hooks`: the head's disk holds only hooks/h.py, which
  // reads the same as the base's, so only the folded clash makes the base's build new.
  const hooked = repoWith({ "pyproject.toml": projectToml({ extra: '\n[tool.hatch.build.hooks.custom]\npath = "hooks/h.py"\n' }), "hooks/h.py": "# hook\n" }, [["120000", outside, "Hooks"]]);
  assert.deepEqual(sk5(await soak(hooked, ["--base", "HEAD~1"])), ["high"]);
  // Control: the same repository without the clashing link keeps the base's build.
  const plain = repoWith({ "pyproject.toml": projectToml({ extra: '\n[tool.hatch.build.hooks.custom]\npath = "hooks/h.py"\n' }), "hooks/h.py": "# hook\n" }, []);
  assert.deepEqual(sk5(await soak(plain, ["--base", "HEAD~1"])), ["medium"]);
  // `bp/A`, a symlink to an absolute directory outside, beside `bp/a/x.py` on backend-path: a rebuild of the base on
  // disk followed the link on a case-insensitive file system and wrote x.py outside. Now nothing is written at all.
  const backend = repoWith({ "pyproject.toml": projectToml({ extra: 'backend-path = ["bp"]\n' }) }, [["120000", outside, "bp/A"], ["100644", "# backend\n", "bp/a/x.py"], ["120000", outside, "Bp"]]);
  assert.deepEqual(sk5(await soak(backend, ["--base", "HEAD~1"])), ["high"]);
  assert.deepEqual(readdirSync(outside), [], "nothing was written outside");
  // An entry the base cannot read in full counts the build as new even when the head's digest records the same:
  // a hook directory with more .py files than are read beside the hook, on both sides.
  const many: Record<string, string> = { "pyproject.toml": projectToml({ extra: '\n[tool.hatch.build.hooks.custom]\npath = "hooks/h.py"\n' }), "hooks/h.py": "# hook\n" };
  for (let i = 0; i < 200; i++) many[`hooks/m${i}.py`] = `x = ${i}\n`;
  assert.deepEqual(sk5(await soak(repoWith(many, []), ["--base", "HEAD~1"])), ["high"]);
  delete many["hooks/m199.py"];
  assert.deepEqual(sk5(await soak(repoWith(many, []), ["--base", "HEAD~1"])), ["medium"], "200 .py files beside the hook: all read");
});

test("soak --base: a build directory planted where no base lock installs it is high once a change adds it to uv.lock", async () => {
  const pyproject = (name: string) => `[project]\nname = "${name}"\nversion = "0.1.0"\n\n[build-system]\nrequires = ["hatchling==1.27.0"]\nbuild-backend = "hatchling.build"\n`;
  const pkg = (name: string) => `[[package]]\nname = "${name}"\nversion = "0.1.0"\nsource = { editable = "pkgs/${name}" }\n`;
  const lockOf = (...names: string[]) => `version = 1\nrevision = 3\nrequires-python = ">=3.9"\n\n${names.map(pkg).join("\n")}`;
  const lock = lockOf("x");
  const repo = gitRepo([
    (d) => {
      mkdirSync(join(d, "pkgs", "y"), { recursive: true });
      writeFileSync(join(d, "pkgs", "y", "pyproject.toml"), pyproject("y"));
      writeFileSync(join(d, "uv.lock"), lockOf("y"));
    },
    (d) => {
      mkdirSync(join(d, "pkgs", "x"), { recursive: true });
      writeFileSync(join(d, "pkgs", "x", "pyproject.toml"), pyproject("x"));
    },
    (d) => writeFileSync(join(d, "uv.lock"), lockOf("x", "y")),
  ]);
  const sev = (r: Run) => r.findings.filter((f) => f.ruleId === "WS-SK-005").map((f) => `${f.severity} ${f.key.split(" ")[1]}`).sort();
  // The planting change made pkgs/x/pyproject.toml identical in the base, but the base's uv.lock installed only pkgs/y.
  const planted = await soak(repo, ["--base", "HEAD~1"]);
  assert.deepEqual(sev(planted), ["high pkgs/x", "medium pkgs/y"], planted.notes.join("\n"));
  assert.equal(planted.code, 1);
  assert.deepEqual(sev(await soak(repo, ["--base", "HEAD~2"])), ["high pkgs/x", "medium pkgs/y"]);
  // Control: once the base's uv.lock lists it, the same build is the base's.
  assert.deepEqual(sev(await soak(repo, ["--base", "HEAD"])), ["medium pkgs/x", "medium pkgs/y"]);
  // A uv.lock in the base that is a symlink was never read as a lock there.
  const linked = gitRepo([
    (d) => {
      mkdirSync(join(d, "pkgs", "x"), { recursive: true });
      writeFileSync(join(d, "pkgs", "x", "pyproject.toml"), pyproject("x"));
      writeFileSync(join(d, "lock.toml"), lock);
      execFileSync("ln", ["-s", "lock.toml", "uv.lock"], { cwd: d });
    },
    (d) => {
      execFileSync("rm", ["uv.lock"], { cwd: d });
      writeFileSync(join(d, "uv.lock"), lock);
    },
  ]);
  assert.deepEqual(sev(await soak(linked, ["--base", "HEAD~1"])), ["high pkgs/x"]);
});

test("soak --base: an sdist-only package is high when the change adds it, medium when the base's lock had it, high when only base text had it", async () => {
  const sdistOnly = SIMPLE_UV.replace(`wheels = [\n${SIX_117_WHL_LINE}\n]\n`, "");
  assert.notEqual(sdistOnly, SIMPLE_UV);
  const sev = (r: Run) => r.findings.filter((f) => f.ruleId === "WS-SK-005" && f.key.includes(" sdist-only ")).map((f) => `${f.severity} ${f.file}`);
  const repo = gitRepo([
    (d) => {
      writeFileSync(join(d, "pyproject.toml"), SIMPLE_PYPROJECT);
      writeFileSync(join(d, "uv.lock"), SIMPLE_UV);
    },
    (d) => writeFileSync(join(d, "uv.lock"), sdistOnly),
  ]);
  assert.deepEqual(sev(await soak(repo, ["--base", "HEAD~1"])), ["high uv.lock"]);
  assert.deepEqual(sev(await soak(repo, ["--base", "HEAD"])), ["medium uv.lock"]);
  assert.deepEqual(sev(await soak(repo)), ["medium uv.lock"]);
  // The same text at tools/deploy.lock with no script is no lock any soak read: high once a script makes it one.
  const script = gitRepo([
    (d) => {
      mkdirSync(join(d, "tools"));
      writeFileSync(join(d, "tools", "deploy.lock"), text(join(UV, "script", "example.py.lock")).replace(/wheels = \[\n {4}\{ url = "https:\/\/files\.pythonhosted\.org\/packages\/b7\/ce[^\n]*\n\]\n/, ""));
    },
    (d) => writeFileSync(join(d, "tools", "deploy"), text(join(UV, "script", "example.py"))),
  ]);
  assert.deepEqual(sev(await soak(script, ["--base", "HEAD~1"])), ["high tools/deploy.lock"]);
  assert.deepEqual(sev(await soak(script, ["--base", "HEAD"])), ["medium tools/deploy.lock"]);
  // A requirements file by name that pip and uv both refused in the base (a stray line) was no lock there either.
  const pin = "six==1.17.0 --hash=sha256:ff70335d468e7eb6ec65b95b99d3a2836546063f63acc5171de367e834932a81\n";
  const refused = gitRepo([
    (d) => writeFileSync(join(d, "requirements.txt"), `FROM python:3.12\n--require-hashes\n${pin}`),
    (d) => writeFileSync(join(d, "requirements.txt"), `--require-hashes\n${pin}`),
  ]);
  assert.deepEqual(sev(await soak(refused, ["--base", "HEAD~1"])), ["high requirements.txt"]);
  assert.deepEqual(sev(await soak(refused, ["--base", "HEAD"])), ["medium requirements.txt"]);
  // The base's requirements file is read as stored (in memory, never written out): bytes that are not UTF-8 there made
  // the base's own soak refuse the file ("encoding not supported"), so the pin was not the base's. Read as decoded
  // text, the invalid byte would have become U+FFFD and the file a lock.
  const latin1 = gitRepo([
    (d) => writeFileSync(join(d, "requirements.txt"), Buffer.concat([Buffer.from(`--require-hashes\n${pin}# caf`), Buffer.from([0xe9]), Buffer.from("\n")])),
    (d) => writeFileSync(join(d, "requirements.txt"), `--require-hashes\n${pin}# cafe\n`),
  ]);
  assert.deepEqual(sev(await soak(latin1, ["--base", "HEAD~1"])), ["high requirements.txt"]);
  assert.deepEqual(sev(await soak(latin1, ["--base", "HEAD"])), ["medium requirements.txt"], "control: the base that holds the same UTF-8 file");
});

test("soak --base: a checkout with CRLF line endings (git for Windows' core.autocrlf=true) digests build files as git stores them", async () => {
  const files: Record<string, string> = {
    "pyproject.toml": projectToml({ extra: '\n[tool.hatch.build.hooks.custom]\npath = "tools/h.py"\n' }),
    "uv.lock": APP_LOCK(),
    "setup.cfg": "[metadata]\nname = app\n",
    "setup.py": "import setuptools\nsetuptools.setup()\n",
    "hatch.toml": '[build]\ndirectory = "dist"\n',
    "uv.toml": 'build-constraint-dependencies = ["hatchling==1.27.0"]\n',
    "hatch_build.py": "# default hook\n",
    "tools/h.py": "# hook\n",
    "tools/n.py": "# beside the hook\n",
  };
  const origin = gitRepo([
    (d) => {
      for (const [rel, text] of Object.entries(files)) {
        mkdirSync(dirname(join(d, rel)), { recursive: true });
        writeFileSync(join(d, rel), text);
      }
    },
    (d) => writeFileSync(join(d, "README.md"), "docs\n"),
  ]);
  const clone = join(mkdtempSync(join(tmpdir(), "ws-pygate-crlf-")), "c");
  const git = (...args: string[]): void => void execFileSync("git", ["-c", "user.email=v@v.invalid", "-c", "user.name=v", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=true", ...args], { cwd: dirname(clone), stdio: "pipe" });
  git("clone", "-q", "-c", "core.autocrlf=true", origin, clone);
  // Positive control: the checkout really has CRLF where git stores LF.
  for (const rel of ["setup.cfg", "setup.py", "hatch.toml", "uv.toml", "hatch_build.py", "tools/h.py", "tools/n.py"]) assert.ok(readFileSync(join(clone, rel), "latin1").includes("\r\n"), rel);
  const sk5 = (r: Run): string => `${r.code} ${r.findings.filter((f) => f.ruleId === "WS-SK-005").map((f) => f.severity).join(",")}`;
  assert.equal(sk5(await soak(clone, ["--base", "HEAD~1"])), "0 medium", "a README-only change");
  // A real change on the same checkout is still new.
  writeFileSync(join(clone, "setup.cfg"), "[metadata]\r\nname = app\r\n\r\n[options]\r\nsetup_requires = evil-fresh-pkg\r\n");
  execFileSync("git", ["-c", "user.email=v@v.invalid", "-c", "user.name=v", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=true", "commit", "-qam", "setup_requires"], { cwd: clone, stdio: "pipe" });
  assert.equal(sk5(await soak(clone, ["--base", "HEAD~1"])), "1 high");
});

/* ---- programs from the tree ---- */

test("soak: a python3 or git committed in a directory on PATH is never run (the probe and git count as not run)", async () => {
  const marker = join(mkdtempSync(join(tmpdir(), "ws-pygate-marker-")), "ran");
  const dir = gitRepo([
    (d) => {
      writeFileSync(join(d, "requirements.txt"), `--require-hashes\nsix==1.16.0 --hash=sha256:${SIX_116}\n`);
      mkdirSync(join(d, "bin"));
      for (const name of ["python3", "git"]) {
        writeFileSync(join(d, "bin", name), `#!/bin/sh\necho "TREE CODE RAN $0 $*" >> "${marker}"\nexit 0\n`);
        chmodSync(join(d, "bin", name), 0o755);
      }
    },
  ]);
  const net = fakeNet();
  const r = await soak(dir, [], net, { PATH: `${join(dir, "bin")}:${PATH}` });
  assert.equal(existsSync(marker), false, existsSync(marker) ? readFileSync(marker, "utf8") : "");
  assert.ok(r.notes.some((n) => /^pip's configuration was not read \(python3 on PATH is .*\/bin\/python3, inside the scanned tree, so it was not run\)/.test(n)), r.notes.join("\n"));
  assert.deepEqual(net.calls, [], "pip's configuration is unknown, so the entry is sent nowhere");
  // diff refuses to run the tree's git as well (git revisions are read with the process's own PATH).
  const saved = process.env["PATH"];
  process.env["PATH"] = `${join(dir, "bin")}:${PATH}`;
  try {
    const d = await cli(["diff", "HEAD", "HEAD", "--dir", dir, ...IOCS]);
    assert.equal(d.code, 2);
    assert.match(d.err, /git on PATH is .*\/bin\/git, inside the scanned tree, so it was not run/);
  } finally {
    process.env["PATH"] = saved;
  }
  assert.equal(existsSync(marker), false);
});

/* ---- diff and scan ---- */

test("diff: a changed Python lockfile or requirements file is WS-DF-006 medium (diff does not check what it pins; soak --base does)", async () => {
  const base = tempTree(PYTHON_FILES);
  const head = tempTree({ ...PYTHON_FILES, "uv.lock": SIMPLE_UV.replace('version = "1.17.0"', 'version = "1.16.0"'), "requirements.txt": "six==1.16.0\n" });
  const r = await cli(["diff", `dir:${base}`, `dir:${head}`, ...IOCS]);
  assert.equal(r.code, 0, "below the default --fail-on high");
  assert.deepEqual(r.findings.map((f) => `${f.ruleId} ${f.severity} ${f.file}`).sort(), ["WS-DF-006 medium requirements.txt", "WS-DF-006 medium uv.lock"]);
  assert.match(r.findings.find((f) => f.file === "uv.lock")?.message ?? "", /^uv\.lock changed in this change, but diff does not check what Python lockfiles or requirements files pin, so nothing in it was checked here; `wormsign soak --base <base>` checks what it pins$/);
  const removed = await cli(["diff", `dir:${base}`, `dir:${tempTree({ "pyproject.toml": SIMPLE_PYPROJECT })}`, ...IOCS]);
  assert.deepEqual(removed.findings.map((f) => `${f.ruleId} ${f.severity} ${f.file}`), ["WS-DF-005 high uv.lock"], "a removed lock is high, as for npm (below)");
  assert.deepEqual((await cli(["diff", `dir:${base}`, `dir:${base}`, ...IOCS])).findings, [], "unchanged: nothing");
});

test("diff: removing a Python lock is WS-DF-005 high, as removing an npm lockfile is; a requirements file counts when it held hashes", async () => {
  const hashed = `--require-hashes\nsix==1.16.0 --hash=sha256:${SIX_116}\n`;
  const locks = {
    "uv.lock": SIMPLE_UV,
    "pylock.toml": text(join(UV, "simple", "pylock.toml")),
    "tools/run.py.lock": SIMPLE_UV,
    "poetry.lock": "# poetry\n",
    "requirements.txt": hashed,
    // pip's hash-checking mode without the line: still a lock.
    "ci/constraints.txt": `six==1.16.0 --hash=sha256:${SIX_116}\n`,
    // A plain list of names is no lock: its removal stays medium.
    "docs/requirements.txt": "sphinx\n",
  };
  const base = tempTree({ "pyproject.toml": SIMPLE_PYPROJECT, ...locks });
  const r = await cli(["diff", `dir:${base}`, `dir:${tempTree({ "pyproject.toml": SIMPLE_PYPROJECT })}`, ...IOCS]);
  assert.equal(r.code, 1);
  assert.deepEqual(r.findings.map((f) => `${f.ruleId} ${f.severity} ${f.file}`).sort(), [
    "WS-DF-005 high ci/constraints.txt",
    "WS-DF-005 high poetry.lock",
    "WS-DF-005 high pylock.toml",
    "WS-DF-005 high requirements.txt",
    "WS-DF-005 high tools/run.py.lock",
    "WS-DF-005 high uv.lock",
    "WS-DF-006 medium docs/requirements.txt",
  ]);
  assert.equal(r.findings.find((f) => f.file === "uv.lock")?.message, "uv.lock removed in this change: the next install resolves every version afresh");
  // npm's rule, for comparison: the same finding.
  const npm = await cli(["diff", `dir:${tempTree({ "package-lock.json": '{"lockfileVersion":3,"packages":{"":{}}}' })}`, `dir:${tempTree({ "package.json": "{}" })}`, ...IOCS]);
  assert.deepEqual(npm.findings.map((f) => `${f.ruleId} ${f.severity} ${f.message.replace("package-lock.json", "<lock>")}`), ["WS-DF-005 high <lock> removed in this change: the next install resolves every version afresh"]);
});

test("diff: a hash lock soak found by its content (deps.txt, deps.lock.in) removed or de-hashed is WS-DF-005 high; its pins changed is WS-DF-006 medium; other files of those kinds give nothing", async () => {
  const hashed = `--require-hashes\nidna==3.20 --hash=sha256:${"a".repeat(64)}\nsix==1.16.0 --hash=sha256:${SIX_116}\n`;
  const brief = (r: Run): string[] => r.findings.map((f) => `${f.ruleId} ${f.severity} ${f.file}`).sort();
  const diff = async (base: Record<string, string>, head: Record<string, string>): Promise<Run> => cli(["diff", `dir:${tempTree(base)}`, `dir:${tempTree(head)}`, ...IOCS]);
  const workflow = "on: pull_request\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pip install -r deps.txt\n";
  // The verified case: the lock the gate checked on base becomes a list pip resolves freely.
  const dehashed = await diff({ "deps.txt": hashed, "Dockerfile": "FROM python:3.14\n" }, { "deps.txt": "idna==3.20\nsix==1.17.0\nrequests\n", "Dockerfile": "FROM python:3.14\n" });
  assert.equal(dehashed.code, 1);
  assert.deepEqual(brief(dehashed), ["WS-DF-005 high deps.txt"]);
  assert.equal(dehashed.findings[0]?.message, "deps.txt was a hash-locked requirements file and no longer is (its --hash options or --require-hashes line removed): pip resolves what it names afresh, and soak no longer reads it");
  assert.match(dehashed.findings[0]?.key ?? "", /^dehashed:[0-9a-f]{32}$/);
  // Removed, with the Dockerfile that installed it now resolving freely.
  const removed = await diff({ "deps.lock.in": hashed, "Dockerfile": "RUN pip install --require-hashes --no-deps -r deps.lock.in\n" }, { "Dockerfile": "RUN pip install idna six requests\n" });
  assert.equal(removed.code, 1);
  assert.deepEqual(brief(removed), ["WS-DF-005 high deps.lock.in"]);
  assert.equal(removed.findings[0]?.key, "removed");
  // Only its pins changed: the medium report soak --base answers; added, too.
  const bumped = await diff({ "ci.pip": hashed, ".github/workflows/t.yml": workflow }, { "ci.pip": hashed.replace("idna==3.20", "idna==3.21"), ".github/workflows/t.yml": workflow });
  assert.equal(bumped.code, 0, bumped.err);
  assert.deepEqual(brief(bumped), ["WS-DF-006 medium ci.pip"]);
  assert.deepEqual(brief(await diff({}, { "tools/deps": hashed })), ["WS-DF-006 medium tools/deps"]);
  // A file of those kinds that is no hash lock on either side (a script, notes) is nothing to diff's Python rule.
  assert.deepEqual(brief(await diff({ "run.sh": "pip install six\n", "notes.txt": "a\n", "x.py": "print(1)\n" }, { "run.sh": "pip install six requests\n", "notes.txt": "b\n" })), []);
  // A requirements file by name that loses its hashes is the same downgrade.
  const named = await diff({ "requirements.txt": hashed }, { "requirements.txt": "idna\nsix\n" });
  assert.deepEqual(brief(named), ["WS-DF-005 high requirements.txt"]);
  assert.equal(named.findings[0]?.message, "requirements.txt was a hash-locked requirements file and no longer is (its --hash options or --require-hashes line removed): pip resolves what it names afresh");
});

test("diff over git revisions: a content-found hash lock de-hashed is WS-DF-005, read from the revisions' blobs; an unchanged one is nothing", async () => {
  const hashed = `--require-hashes\nsix==1.16.0 --hash=sha256:${SIX_116}\n`;
  const repoDir = gitRepo([
    (d) => {
      writeFileSync(join(d, "deps.txt"), hashed);
      writeFileSync(join(d, "tool.py"), "print('unchanged')\n");
    },
    (d) => writeFileSync(join(d, "deps.txt"), "six\n"),
  ]);
  const r = await cli(["diff", "HEAD~1", "HEAD", "--dir", repoDir, ...IOCS]);
  assert.equal(r.code, 1, r.err);
  assert.deepEqual(r.findings.map((f) => `${f.ruleId} ${f.severity} ${f.file}`), ["WS-DF-005 high deps.txt"]);
  const same = await cli(["diff", "HEAD~1", "HEAD~1", "--dir", repoDir, ...IOCS]);
  assert.deepEqual(same.findings, []);
});

test("diff: any change to a pyproject.toml, setup.py, setup.cfg or Pipfile is WS-DF-006 medium, the file compared whole; what a manifest names is not followed, but for its build", async () => {
  const pyproject = (deps: string[], extra = ""): string => `[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ${JSON.stringify(deps)}\n${extra}`;
  const cfg = (requires: string, extra = ""): string => `[metadata]\nname = demo\n[options]\ninstall_requires =\n    ${requires}\n${extra}`;
  const base = { "pyproject.toml": pyproject(["six"]), "setup.cfg": cfg("six"), "setup.py": "from setuptools import setup\nsetup()\n", "lib/Pipfile": "[packages]\nsix = '*'\n" };
  const diff = async (head: Record<string, string>, from: Record<string, string> = base): Promise<Run> => cli(["diff", `dir:${tempTree(from)}`, `dir:${tempTree({ ...from, ...head })}`, ...IOCS]);
  const brief = (r: Run): string[] => r.findings.map((f) => `${f.ruleId} ${f.severity} ${f.file}`).sort();
  // Dependency changes: WS-DF-006 medium, each file. This project has no [build-system], so its [project]
  // dependencies are part of its build's key, and setup.cfg and setup.py count whole: its build changed too, one
  // WS-DF-005 high (test/python-diff-builds.test.ts).
  const deps = await diff({
    "pyproject.toml": pyproject(["six", "requests"]),
    "setup.cfg": cfg("six\n    requests"),
    "setup.py": "from setuptools import setup\nsetup(install_requires=['requests'])\n",
    "lib/Pipfile": "[packages]\nsix = '*'\nrequests = '*'\n",
  });
  assert.equal(deps.code, 1, deps.err);
  assert.deepEqual(brief(deps), ["WS-DF-005 high pyproject.toml", "WS-DF-006 medium lib/Pipfile", "WS-DF-006 medium pyproject.toml", "WS-DF-006 medium setup.cfg", "WS-DF-006 medium setup.py"]);
  assert.match(deps.findings.find((f) => f.ruleId === "WS-DF-005")?.message ?? "", /^The build of the Python project in the top directory changed in this change \(pyproject\.toml, setup\.cfg, setup\.py\): /);
  assert.equal(
    deps.findings.find((f) => f.file === "pyproject.toml" && f.ruleId === "WS-DF-006")?.message,
    "pyproject.toml changed in this change: diff does not resolve Python dependencies, so nothing declared there was checked here; `wormsign soak --base <base>` checks that a lock covers its directory and what that lock pins, not that the lock pins what the manifest declares",
  );
  assert.match(deps.findings.find((f) => f.file === "setup.py")?.message ?? "", /^setup\.py changed in this change: diff does not resolve Python dependencies \(a setup\.py declares whatever it computes when an install runs it\)/);
  // Any other edit too, the file compared whole: a version bump, metadata, a linter's settings, a setup.cfg's tool
  // section (which setuptools reads whole, so the build's key changes too).
  const ordinary = await diff({
    "pyproject.toml": pyproject(["six"], "[tool.ruff]\nline-length = 100\n").replace('version = "0.1.0"', 'version = "0.2.0"'),
    "setup.cfg": cfg("six", "[flake8]\nmax-line-length = 100\n"),
  });
  assert.deepEqual(brief(ordinary), ["WS-DF-005 high pyproject.toml", "WS-DF-006 medium pyproject.toml", "WS-DF-006 medium setup.cfg"]);
  // A key holds the new content: another edit is a new finding, the same content the same one.
  const again = await diff({ "pyproject.toml": pyproject(["six"]).replace('version = "0.1.0"', 'version = "0.2.0"') });
  assert.deepEqual(brief(again), ["WS-DF-006 medium pyproject.toml"], "a version bump keeps the build");
  assert.notEqual(again.findings[0]?.fingerprint, ordinary.findings.find((f) => f.file === "pyproject.toml" && f.ruleId === "WS-DF-006")?.fingerprint);
  assert.equal((await diff({ "pyproject.toml": pyproject(["six"]).replace('version = "0.1.0"', 'version = "0.2.0"') })).findings[0]?.fingerprint, again.findings[0]?.fingerprint);
  // Added and removed manifests; unchanged ones give nothing.
  const added = await diff({ "tools/pyproject.toml": '[project]\nname = "tools"\n' });
  assert.deepEqual(brief(added), ["WS-DF-005 high tools/pyproject.toml", "WS-DF-006 medium tools/pyproject.toml"], "a new project's build is new");
  assert.match(added.findings.find((f) => f.ruleId === "WS-DF-006")?.message ?? "", /^pyproject\.toml added in this change/);
  const removed = await cli(["diff", `dir:${tempTree(base)}`, `dir:${tempTree(Object.fromEntries(Object.entries(base).filter(([k]) => k !== "setup.py")))}`, ...IOCS]);
  assert.deepEqual(brief(removed), ["WS-DF-005 high pyproject.toml", "WS-DF-006 medium setup.py"], "the project without its setup.py builds differently");
  assert.deepEqual((await diff({})).findings, []);
  // A pyproject.toml that cannot be parsed could hide a [tool.uv] setting: high, and its build is unknown.
  assert.deepEqual(brief(await diff({ "pyproject.toml": "[project\n" })), ["WS-DF-005 high pyproject.toml", "WS-DF-006 high pyproject.toml"]);
  // What a manifest names is not followed: a dependency file setup.cfg reads with `file:`, a module a setup.py imports.
  // diff does not read what a manifest declares (docs/cli/diff.md). A build hook is part of the build's key, as soak
  // keys it: its edit is the build's WS-DF-005.
  const named = {
    "setup.cfg": cfg("file: requirements.in"),
    "requirements.in": "six\n",
    "pyproject.toml": '[build-system]\nrequires = ["hatchling"]\nbuild-backend = "hatchling.build"\n[project]\nname = "demo"\nversion = "1.0"\ndynamic = ["dependencies"]\n[tool.hatch.metadata.hooks.custom]\n',
    "hatch_build.py": "class CustomMetadataHook:\n    def update(self, metadata):\n        metadata['dependencies'] = ['six']\n",
    "setup.py": "from setup_deps import DEPS\nfrom setuptools import setup\nsetup(install_requires=DEPS)\n",
    "setup_deps.py": "DEPS = ['six']\n",
  };
  const edited = await diff({ "requirements.in": "six\nidna\n", "setup_deps.py": "DEPS = ['six', 'idna']\n" }, named);
  assert.deepEqual(edited.findings, []);
  const hook = await diff({ "hatch_build.py": `${named["hatch_build.py"]}# x\n` }, named);
  assert.deepEqual(brief(hook), ["WS-DF-005 high pyproject.toml"]);
  assert.match(hook.findings[0]?.message ?? "", /\(hatch_build\.py\): /);
});

test("diff: pip.conf, pip.ini, uv.toml and [tool.uv] are install configuration: adding, changing or removing one is WS-DF-005 high", async () => {
  const uvTool = `${SIMPLE_PYPROJECT}\n[tool.uv]\nindex-url = "https://pypi.corp.example/simple/"\n`;
  // The uv.lock lists the project (virtual), so its build is soak's, not diff's (test/python-diff-builds.test.ts).
  const base = tempTree({ "pyproject.toml": SIMPLE_PYPROJECT, "uv.lock": SIMPLE_UV, "pip.ini": "[global]\nindex-url = https://pypi.org/simple/\n" });
  const head = tempTree({ "pyproject.toml": uvTool, "uv.lock": SIMPLE_UV, "pip.conf": "[global]\nno-binary = :all:\n", "ci/UV.toml": "no-build-isolation = true\n" });
  const r = await cli(["diff", `dir:${base}`, `dir:${head}`, ...IOCS]);
  assert.equal(r.code, 1);
  // The pyproject.toml is also an edited manifest: WS-DF-006 medium besides the high for its [tool.uv].
  assert.deepEqual(r.findings.map((f) => `${f.ruleId} ${f.severity} ${f.file}`).sort(), ["WS-DF-005 high ci/UV.toml", "WS-DF-005 high pip.conf", "WS-DF-005 high pip.ini", "WS-DF-005 high pyproject.toml", "WS-DF-006 medium pyproject.toml"]);
  assert.match(r.findings.find((f) => f.file === "pyproject.toml")?.message ?? "", /^\[tool\.uv\] in pyproject\.toml added in this change: uv reads its index settings, its git, url and index sources and its build settings there/);
  // A changed setting is a new finding; [tool.uv] dev-dependencies is a dependency list, so only the edit, medium;
  // unchanged is nothing.
  const changed = await cli(["diff", `dir:${head}`, `dir:${tempTree({ "pyproject.toml": uvTool.replace("corp", "other"), "uv.lock": SIMPLE_UV, "pip.conf": "[global]\nno-binary = :all:\n", "ci/UV.toml": "no-build-isolation = true\n" })}`, ...IOCS]);
  assert.deepEqual(changed.findings.map((f) => `${f.ruleId} ${f.severity} ${f.file}`).sort(), ["WS-DF-005 high pyproject.toml", "WS-DF-006 medium pyproject.toml"]);
  const dev = await cli(["diff", `dir:${head}`, `dir:${tempTree({ "pyproject.toml": `${uvTool}dev-dependencies = ["pytest"]\n`, "uv.lock": SIMPLE_UV, "pip.conf": "[global]\nno-binary = :all:\n", "ci/UV.toml": "no-build-isolation = true\n" })}`, ...IOCS]);
  assert.deepEqual(dev.findings.map((f) => `${f.ruleId} ${f.severity} ${f.file}`), ["WS-DF-006 medium pyproject.toml"]);
  assert.deepEqual((await cli(["diff", `dir:${head}`, `dir:${head}`, ...IOCS])).findings, []);
  // A base pyproject.toml diff cannot parse hides nothing: head's [tool.uv] counts as added.
  const fromUnreadable = await cli(["diff", `dir:${tempTree({ "pyproject.toml": "[project\n", "uv.lock": SIMPLE_UV })}`, `dir:${tempTree({ "pyproject.toml": uvTool, "uv.lock": SIMPLE_UV })}`, ...IOCS]);
  assert.deepEqual(fromUnreadable.findings.map((f) => `${f.ruleId} ${f.severity} ${f.file}`).sort(), ["WS-DF-005 high pyproject.toml", "WS-DF-006 medium pyproject.toml"]);
});

test("diff: the baseline's ignorePaths hide a Python manifest's edits, not its [tool.uv] or its build, and the note says so", async () => {
  const baselineDoc = JSON.stringify({ version: 1, entries: [], ignorePaths: [{ path: "vendor", justification: "vendored code nothing here installs" }] });
  const base = tempTree({ ".wormsign-baseline.json": baselineDoc, "vendor/lib/pyproject.toml": '[project]\nname = "lib"\nversion = "1.0"\n' });
  const edit = '[project]\nname = "lib"\nversion = "1.1"\n';
  const r = await cli(["diff", `dir:${base}`, `dir:${tempTree({ ".wormsign-baseline.json": baselineDoc, "vendor/lib/pyproject.toml": edit })}`, ...IOCS]);
  assert.deepEqual(r.findings, [], r.err);
  assert.ok(r.notes.some((n) => /^ignored paths \(baseline .*; npm manifests, local actions and package-manager config are checked everywhere, and so are a pyproject\.toml's \[tool\.uv\], a Python project's build and a pyproject\.toml that does not parse; other Python manifest edits and Python locks are not\): vendor$/.test(n)), r.notes.join("\n"));
  const uv = await cli(["diff", `dir:${base}`, `dir:${tempTree({ ".wormsign-baseline.json": baselineDoc, "vendor/lib/pyproject.toml": `${edit}[tool.uv]\nindex-url = "https://pypi.corp.example/simple/"\n` })}`, ...IOCS]);
  // Twice: [tool.uv] as install configuration, and the build of a project no lock lists, whose key holds [tool.uv].
  assert.deepEqual(uv.findings.map((f) => `${f.ruleId} ${f.severity} ${f.file} ${f.message.split(" ")[0]}`).sort(), ["WS-DF-005 high vendor/lib/pyproject.toml The", "WS-DF-005 high vendor/lib/pyproject.toml [tool.uv]"]);
});

test("diff: [tool.uv] keys only a pyproject.toml may hold (workspace, default-groups, package, managed, sources from the tree) are only an edit, medium; git, url and index sources are high too", async () => {
  // uv refuses each of these in a uv.toml ("only applicable in the context of a project"), and `uv add` writes them
  // when it adds a workspace member or a path dependency: a pull request cannot approve a high finding on them.
  const project = (extra = ""): string => `[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["packaging==25.0", "other"]\n${extra}`;
  // A uv.lock lists the project, as `uv add` writes one (virtual, or editable once it has a [build-system]): its build
  // is soak's or uv does not build it (test/python-diff-builds.test.ts).
  const lock = (path: string, text: string): Record<string, string> => ({ [`${posix.dirname(path)}/uv.lock`]: text.includes("[build-system]") ? SIMPLE_UV.replace('source = { virtual = "." }', 'source = { editable = "." }') : SIMPLE_UV });
  const diff = async (before: string, after: string, path = "pyproject.toml"): Promise<string[]> =>
    (await cli(["diff", `dir:${tempTree({ [path]: before, ...lock(path, before) })}`, `dir:${tempTree({ [path]: after, ...lock(path, after) })}`, ...IOCS])).findings.map((f) => `${f.ruleId} ${f.severity}`).sort();
  const member = project('[tool.uv]\npackage = false\nmanaged = true\ndefault-groups = ["dev"]\n[tool.uv.workspace]\nmembers = ["packages/*"]\n[tool.uv.sources]\nother = { workspace = true }\nlocal = { path = "libs/local", editable = true }\nsplit = [{ path = "vendor/a.whl", marker = "sys_platform == \'linux\'" }, { workspace = true, marker = "sys_platform != \'linux\'" }]\n');
  assert.deepEqual(await diff(project(), member), ["WS-DF-006 medium"]);
  assert.deepEqual(await diff(project('[tool.uv.sources]\nother = { path = "../libs/other" }\n'), project('[tool.uv.sources]\nother = { path = "../libs/other", editable = true }\n'), "app/pyproject.toml"), ["WS-DF-006 medium"], "a path inside the repository from a subdirectory");
  for (const source of ['{ git = "https://github.com/x/other" }', '{ url = "https://example.invalid/other-1.0.tar.gz" }', '{ index = "corp" }', '{ path = "../outside" }', '{ path = "/opt/other" }', '{ path = "C:/other" }', '{ workspace = true, git = "https://github.com/x/other" }']) {
    assert.deepEqual(await diff(project(), project(`[tool.uv.sources]\nother = ${source}\n`)), ["WS-DF-005 high", "WS-DF-006 medium"], source);
  }
  assert.deepEqual(await diff(member, member.replace("[tool.uv]\n", '[tool.uv]\nindex-url = "https://pypi.corp.example/simple/"\n')), ["WS-DF-005 high", "WS-DF-006 medium"], "an index setting beside them");
  // The resolver's overrides, constraints, environments and conflicts, the uv versions it runs under and its rebuild
  // keys decide what the lock holds, not where installs fetch from: an ordinary bump of one is medium (the verified
  // case: override-dependencies >=1.15 to >=1.16, required-version >=0.9 to >=0.10).
  const resolution = (v: string): string => project(`[tool.uv]\noverride-dependencies = ["six>=1.${v}"]\nconstraint-dependencies = ["idna<4"]\nrequired-version = ">=0.${v === "15" ? "9" : "10"}"\nenvironments = ["sys_platform == 'linux'"]\nrequired-environments = ["sys_platform == 'linux'"]\nconflicts = [[{ extra = "a" }, { extra = "b" }]]\ncache-keys = [{ file = "pyproject.toml" }]\n`);
  assert.deepEqual(await diff(resolution("15"), resolution("16")), ["WS-DF-006 medium"]);
  // uv_build's [tool.uv.build-backend] is this project's build settings, which no installer reads: only an edit.
  const uvBuild = (module: string): string => project(`[tool.uv.build-backend]\nmodule-name = "${module}"\n`).replace("[project]", '[build-system]\nrequires = ["uv_build>=0.8.0,<0.9"]\nbuild-backend = "uv_build"\n\n[project]');
  assert.deepEqual(await diff(uvBuild("demo"), uvBuild("demo_core")), ["WS-DF-006 medium"], "[tool.uv.build-backend]");
  for (const key of ['no-build-isolation = true', 'build-constraint-dependencies = ["setuptools<81"]', 'exclude-newer = "2026-01-01T00:00:00Z"', 'not-a-uv-key = 1']) {
    assert.deepEqual(await diff(resolution("15"), resolution("15").replace("[tool.uv]\n", `[tool.uv]\n${key}\n`)), ["WS-DF-005 high", "WS-DF-006 medium"], key);
  }
});

test("scan: a tree with Python lockfiles, requirements files or manifests says scan does not read them", async () => {
  const r = await cli(["scan", tempTree({ ...PYTHON_FILES, "requirements.txt": "six==1.16.0\n" }), ...IOCS]);
  assert.ok(r.notes.includes("3 Python lockfile(s), requirements file(s) or manifest(s) found, which scan does not read: `wormsign soak` checks the versions they pin: pyproject.toml, requirements.txt, uv.lock"), r.notes.join("\n"));
  const npmOnly = await cli(["scan", tempTree({ "package.json": '{"name":"x"}' }), ...IOCS]);
  assert.ok(!npmOnly.notes.some((n) => n.includes("Python")), npmOnly.notes.join("\n"));
});

/* ---- npm's notes beside Python inputs ---- */

test("soak: a root bunfig.toml brings back npm's notes in a Python tree with no npm lockfile", async () => {
  const withBun = { ...PYTHON_FILES, "bunfig.toml": "[install]\nminimumReleaseAge = 604800\n" };
  const full = await soak(tempTree(withBun));
  assert.ok(full.notes.some((n) => /package version\(s\) checked against https:\/\/registry\.npmjs\.org/.test(n)), full.notes.join("\n"));
  const configOnly = await soak(tempTree(withBun), ["--config-only"]);
  assert.ok(configOnly.notes.some((n) => n.startsWith("lockfile soak check not run (--config-only). npm and Yarn release-age settings")), configOnly.notes.join("\n"));
  // Control: without the bunfig.toml, no npm note.
  const none = await soak(tempTree(PYTHON_FILES), ["--config-only"]);
  assert.ok(!none.notes.some((n) => n.startsWith("lockfile soak check not run")), none.notes.join("\n"));
});
