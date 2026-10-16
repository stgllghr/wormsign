/**
 * The PyPI soak check (src/python/soak.ts) with the model (model.ts), identity (identity.ts), local sources (local.ts)
 * and WS-SK-005 builds (build.ts): every forged case that belongs to the check.
 *
 * Locks are the ones uv 0.10.9, uv 0.12.21 and pip 26.2.1 wrote (test/fixtures/python/locks, and forged/uv-export-names),
 * read by the readers (src/python/uvlock.ts, pylock.ts, requirements.ts), or edits of them: made here, each stated where it is made, or forged in
 * test/fixtures/python/forged, each file saying what it changes. The index is a fake fetch serving Simple JSON
 * captured from pypi.org (test/fixtures/python/simple and forged/captured), or edits of it; OSV is a fake too. Nothing
 * here uses the network, python3, uv or pip.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { newOsvSession } from "../src/osv.js";
import { gitBuildReader, raiseNewBuilds } from "../src/python/base-builds.js";
import { BUILD_DIGEST_VERSION, DEFAULT_REQUIRES, fileDigest, fsBuildReader, localBuild, localBuildFinding, readLocalBuild } from "../src/python/build.js";
import { gitTree, type TreeEntry } from "../src/tree.js";
import { canonicalIdentity, identityDigest, pythonIdentity } from "../src/python/identity.js";
import { parseSimpleProject, SIMPLE_JSON, type IndexFile } from "../src/python/index.js";
import { checkLocalArchive, checkLocalDirectory, checkVirtualProject } from "../src/python/local.js";
import { fromPylock, fromRequirements, fromUvLock, type PyLock, type PyPackage } from "../src/python/model.js";
import { readPylock } from "../src/python/pylock.js";
import { readRequirements } from "../src/python/requirements.js";
import { checkPythonLocks, localSourcePath, MAX_FILE_PROBLEMS, namesIndexFile, problemContent, QUARANTINED, type PythonSoakOptions } from "../src/python/soak.js";
import { readUvLock } from "../src/python/uvlock.js";
import type { Finding } from "../src/types.js";

const FIX = join(import.meta.dirname, "..", "..", "test", "fixtures", "python");
const LOCKS = join(FIX, "locks");
const FORGED = join(FIX, "forged");
const INDEX = "https://pypi.org/simple/";
const NOW = new Date("2026-10-08T12:00:00Z");
const DAY = 86_400_000;
const WEEK = 7 * DAY;

const SIX_WHL = "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274";
const SIX_SDIST = "ff70335d468e7eb6ec65b95b99d3a2836546063f63acc5171de367e834932a81";
const SIX_WHL_URL = "https://files.pythonhosted.org/packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl";
const IDNA_WHL = "ab7ae7122974553370f0bdb919e1a960b2cd1bc1ef0276416d896db81c14582c";
const SIX_WHEEL_BYTES = readFileSync(join(LOCKS, "uv-0.12.21", "path", "vendor", "six-1.17.0-py2.py3-none-any.whl"));

/* ---- the fake index and OSV ---- */

type Page = Record<string, unknown> & { files: Record<string, unknown>[]; meta: Record<string, unknown> };
/** Captured pages: the readers' (test/fixtures/python/simple) and this file's own (forged/captured). */
const OWN_CAPTURED = ["pyyaml", "jaraco-classes", "more-itertools"];
const CAPTURED = ["six", "idna", "certifi", "markupsafe", "packaging", ...OWN_CAPTURED];
function page(name: string): Page {
  const file = OWN_CAPTURED.includes(name) ? join(FORGED, "captured", `${name}.json`) : join(FIX, "simple", `${name}.json`);
  return JSON.parse(readFileSync(file, "utf8")) as Page;
}
const fileOf = (p: Page, filename: string): Record<string, unknown> => p.files.find((f) => f["filename"] === filename)!;
const SIX_116_WHL = (fileOf(page("six"), "six-1.16.0-py2.py3-none-any.whl")["hashes"] as { sha256: string }).sha256;
const SIX_116_WHL_URL = fileOf(page("six"), "six-1.16.0-py2.py3-none-any.whl")["url"] as string;

/**
 * A fake fetch for the index (captured pages by default; a Page, an HTTP status or null for 404 overrides one) and for
 * OSV (records keyed "<name>@<version>"). Records which projects and which OSV versions were asked about.
 */
function fake(pages: Record<string, Page | number | null> = {}, records: Record<string, string[]> = {}, index = INDEX) {
  const asked: string[] = [];
  const osv: string[] = [];
  const base = index.replace(/\/+$/, "");
  const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    if (u === "https://api.osv.dev/v1/querybatch") {
      const { queries } = JSON.parse(String(init?.body)) as { queries: { package: { name: string; ecosystem: string }; version: string }[] };
      const results = queries.map((q) => {
        assert.equal(q.package.ecosystem, "PyPI");
        osv.push(`${q.package.name}@${q.version}`);
        const ids = records[`${q.package.name}@${q.version}`] ?? [];
        return ids.length > 0 ? { vulns: ids.map((id) => ({ id, modified: "2026-01-01T00:00:00Z" })) } : {};
      });
      return new Response(JSON.stringify({ results }));
    }
    const m = u.startsWith(`${base}/`) ? /^([a-z0-9-]+)\/$/.exec(u.slice(base.length + 1)) : null;
    if (!m) throw new Error(`unexpected request ${u}`);
    const name = m[1]!;
    asked.push(name);
    const over = Object.hasOwn(pages, name) ? pages[name] : CAPTURED.includes(name) ? page(name) : null;
    if (over === null || over === undefined) return new Response('{"message": "Not Found"}', { status: 404, headers: { "content-type": "application/json" } });
    if (typeof over === "number") return new Response("{}", { status: over, headers: { "content-type": SIMPLE_JSON } });
    return new Response(JSON.stringify(over), { headers: { "content-type": SIMPLE_JSON } });
  }) as typeof fetch;
  return { fetchImpl, asked, osv };
}

/* ---- locks ---- */

const SIMPLE_UV = readFileSync(join(LOCKS, "uv-0.12.21", "simple", "uv.lock"), "utf8");
/** The real uv 0.12.21 lock with `from` replaced by `to`, exactly once. */
function edit(text: string, from: string, to: string): string {
  assert.equal(text.split(from).length, 2, `the edit's text occurs once: ${from.slice(0, 60)}`);
  return text.replace(from, () => to);
}
const SIX_WHEEL_LINE = `    { url = "${SIX_WHL_URL}", hash = "sha256:${SIX_WHL}", size = 11050, upload-time = "2024-12-04T17:35:26.475Z" },\n`;

/** A scratch repository: a pyproject.toml at its root (the virtual project of the locks here) and `files`. */
function tree(files: Record<string, string | Buffer> = {}): string {
  const root = mkdtempSync(join(tmpdir(), "ws-pysoak-"));
  for (const [rel, body] of Object.entries({ "pyproject.toml": '[project]\nname = "demo-simple"\nversion = "0.1.0"\n', ...files })) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), body);
  }
  return root;
}
/**
 * A uv.lock (or script lock) mapped as discovery maps it. Local archives' names may be sent, as with an explicit
 * --pypi-index, unless `sendLocalArchives` is false (the model test checks the default).
 */
const uv = (root: string, rel: string, text?: string, kind: "uv" | "script" = "uv", sendLocalArchives = true): PyLock => {
  if (text !== undefined) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
  return fromUvLock(rel, readUvLock(join(root, rel)), { pypiIndex: INDEX, kind, sendLocalArchives });
};
const pylock = (root: string, rel: string, text?: string, sendLocalArchives = true): PyLock => {
  if (text !== undefined) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
  return fromPylock(rel, readPylock(join(root, rel)), { pypiIndex: INDEX, sendLocalArchives });
};
/** One of test/fixtures/python/locks, copied into a scratch repository as uv.lock (or pylock.toml), with the vendored wheel and local project the path fixtures name. */
function copied(rel: string): { root: string; lock: PyLock } {
  const root = tree({ "vendor/six-1.17.0-py2.py3-none-any.whl": SIX_WHEEL_BYTES, "libs/localdir/pyproject.toml": readFileSync(join(LOCKS, "uv-0.12.21", "path", "libs", "localdir", "pyproject.toml")) });
  const text = readFileSync(join(LOCKS, rel), "utf8");
  return { root, lock: rel.endsWith(".toml") ? pylock(root, "pylock.toml", text) : uv(root, "uv.lock", text) };
}
const requirements = (root: string, rel: string, text: string, sendable = true): PyLock => {
  writeFileSync(join(root, rel), text);
  return fromRequirements(readRequirements(root, rel), { sendable });
};

function run(locks: PyLock[], f: ReturnType<typeof fake>, over: Partial<PythonSoakOptions> & { root: string }) {
  return checkPythonLocks(locks, { minAgeMs: WEEK, now: NOW, pypiIndex: INDEX, git: "no-work-tree", fetchImpl: f.fetchImpl, ...over });
}
const brief = (fs: Finding[]): string[] => fs.map((f) => `${f.ruleId} ${f.file ?? "-"} ${f.key}`);
const only = (fs: Finding[], rule: string): Finding[] => fs.filter((f) => f.ruleId === rule);
const pkgOf = (lock: PyLock, name: string, version?: string): PyPackage => lock.packages.find((p) => p.name === name && (version === undefined || p.version === version))!;
const keyOf = (p: PyPackage): string => `pypi:${p.name}@${p.version ?? ""} ${identityDigest(p)}`;

/* ---- model and identity ---- */

test("model: the tool-written locks map to one model; only entries from the configured index are sendable", () => {
  const simple = uv(LOCKS, "uv-0.12.21/simple/uv.lock");
  assert.equal(simple.kind, "uv");
  assert.deepEqual(simple.problems, []);
  const six = pkgOf(simple, "six");
  assert.deepEqual(six, {
    name: "six",
    version: "1.17.0",
    source: { kind: "registry", value: "https://pypi.org/simple" },
    files: [
      { locator: { url: "https://files.pythonhosted.org/packages/94/e7/b2c673351809dca68a0e064b6af791aa332cf192da575fd474ed7d6f16a2/six-1.17.0.tar.gz", filename: "six-1.17.0.tar.gz" }, hashes: [{ alg: "sha256", digest: SIX_SDIST }], kind: "sdist" },
      { locator: { url: SIX_WHL_URL, filename: "six-1.17.0-py2.py3-none-any.whl" }, hashes: [{ alg: "sha256", digest: SIX_WHL }], kind: "wheel" },
    ],
    sendable: true,
    file: "uv-0.12.21/simple/uv.lock",
    lockIndex: "https://pypi.org/simple",
  });
  assert.deepEqual(pkgOf(simple, "demo-simple").source, { kind: "virtual", value: "." });
  assert.equal(pkgOf(simple, "demo-simple").sendable, false);
  assert.equal(fromUvLock("x/uv.lock", readUvLock(join(LOCKS, "uv-0.12.21", "simple", "uv.lock")), { pypiIndex: "https://pypi.corp.example/simple/" }).packages.filter((p) => p.sendable).length, 0, "another configured index: nothing is sendable");

  const path = uv(LOCKS, "uv-0.12.21/path/uv.lock");
  assert.deepEqual(pkgOf(path, "six").source, { kind: "path", value: "vendor/six-1.17.0-py2.py3-none-any.whl" });
  assert.deepEqual(pkgOf(path, "six").files[0]!.locator, { filename: "six-1.17.0-py2.py3-none-any.whl" });
  assert.equal(pkgOf(path, "six").sendable, true, "with an explicit --pypi-index, a path archive is bound on the index by its file name");
  // By default a local archive's name is sent nowhere: a repository's own vendored wheels may be private.
  const pathDefault = fromUvLock("uv.lock", readUvLock(join(LOCKS, "uv-0.12.21", "path", "uv.lock")), { pypiIndex: INDEX });
  assert.deepEqual([pkgOf(pathDefault, "six").sendable, pkgOf(pathDefault, "six").unsent], [false, "it is a local archive, which can be checked only by asking the index for its name, and --pypi-index was not given explicitly to allow that"]);
  assert.deepEqual(pkgOf(path, "localdir").source, { kind: "directory", value: "libs/localdir" });
  assert.deepEqual(uv(LOCKS, "uv-0.12.21/editable/uv.lock").packages.map((p) => `${p.name} ${p.source.kind}:${p.source.value}`), ["certifi registry:https://pypi.org/simple", "demo-editable editable:.", "member editable:packages/member", "packaging registry:https://pypi.org/simple"]);
  assert.equal(uv(LOCKS, "uv-0.12.21/script/example.py.lock", undefined, "script").kind, "script");

  const py = pylock(LOCKS, "uv-0.12.21/simple/pylock.toml");
  assert.deepEqual([py.kind, pkgOf(py, "six").source, pkgOf(py, "six").sendable, pkgOf(py, "six").lockIndex], ["pylock", { kind: "registry", value: "https://pypi.org/simple" }, true, "https://pypi.org/simple"]);
  const pip = pylock(LOCKS, "pip-26.2.1/lock/pylock.toml");
  assert.deepEqual([pkgOf(pip, "six").source, pkgOf(pip, "six").sendable], [{ kind: "registry", value: "" }, false], "pip lock writes no index: discovery decides");
  assert.match(pkgOf(pip, "six").unsent!, /records no index/);
  assert.deepEqual(
    pylock(LOCKS, "forged/pylock-local-sources.toml", undefined, false).packages.map((p) => [p.name, p.sendable]),
    [
      ["idna", true],
      ["six", false],
      ["localdir", false],
      ["six-git", false],
    ],
    "without an explicit --pypi-index a pylock archive by path is sent nowhere",
  );
  const local = pylock(LOCKS, "forged/pylock-local-sources.toml");
  assert.deepEqual(
    local.packages.map((p) => [p.name, p.source.kind, p.source.value, p.sendable]),
    [
      ["idna", "registry", "https://pypi.org/simple", true],
      ["six", "archive", "vendor/six-1.17.0-py2.py3-none-any.whl", true],
      ["localdir", "directory", "libs/localdir", false],
      ["six-git", "vcs", "git+https://github.com/benjaminp/six@2b9bd1ba1ee9e3f1a6c7a1d1b6b6a7c3f7f2a1c0", false],
    ],
  );

  const root = tree({ "requirements.txt": `--require-hashes\nsix==1.17.0 \\\n    --hash=sha256:${SIX_WHL} \\\n    --hash=sha256:${SIX_SDIST}\n` });
  const req = fromRequirements(readRequirements(root, "requirements.txt"));
  assert.deepEqual(req.packages, [
    {
      name: "six",
      version: "1.17.0",
      source: { kind: "requirements", value: "" },
      files: [{ locator: {}, hashes: [{ alg: "sha256", digest: SIX_WHL }] }, { locator: {}, hashes: [{ alg: "sha256", digest: SIX_SDIST }] }],
      sendable: false,
      file: "requirements.txt",
      line: 2,
      unsent: "a requirements file records no index, so the install's index settings decide where it comes from, and they were not confirmed to be --pypi-index",
    },
  ]);
  assert.equal(fromRequirements(readRequirements(root, "requirements.txt"), { sendable: true }).packages[0]!.sendable, true);
  assert.equal(fromRequirements(readRequirements(root, "requirements.txt"), { unsent: "PIP_INDEX_URL names another index" }).packages[0]!.unsent, "PIP_INDEX_URL names another index");
});

test("identity: a digest of name, version, source and every file's locator and hashes; file and hash order do not count", () => {
  const six = pkgOf(uv(LOCKS, "uv-0.12.21/simple/uv.lock"), "six");
  const id = identityDigest(six);
  assert.match(id, /^[0-9a-f]{64}$/);
  assert.equal(pythonIdentity(six), `pypi:${id}`);
  assert.equal(id, createHash("sha256").update(canonicalIdentity(six)).digest("hex"));
  const same = (p: PyPackage): boolean => identityDigest(p) === id;
  assert.ok(same({ ...six, files: [...six.files].reverse() }), "file order");
  assert.ok(same({ ...six, sendable: false, file: "elsewhere/uv.lock", lockIndex: "x" }), "where it was found and whether it may be sent are not identity");
  // Only the source differs: a registry swapped for another index, or for a git URL, is another package.
  assert.ok(!same({ ...six, source: { kind: "registry", value: "https://pypi.corp.example/simple" } }), "another index");
  assert.ok(!same({ ...six, source: { kind: "git", value: "https://pypi.org/simple" } }), "another source kind");
  assert.ok(!same({ ...six, source: { ...six.source, subdirectory: "x" } }), "a subdirectory");
  assert.ok(!same({ ...six, version: "1.17.1" }), "version");
  assert.ok(!same({ ...six, name: "seven" }), "name");
  assert.ok(!same({ ...six, files: six.files.slice(1) }), "a file removed");
  assert.ok(!same({ ...six, files: [six.files[0]!, { ...six.files[1]!, hashes: [{ alg: "sha256", digest: "0".repeat(64) }] }] }), "a hash changed");
  assert.ok(!same({ ...six, files: [six.files[0]!, { ...six.files[1]!, hashes: [...six.files[1]!.hashes, { alg: "sha512", digest: "1".repeat(128) }] }] }), "a hash added");
  assert.ok(!same({ ...six, files: [six.files[0]!, { ...six.files[1]!, locator: { url: "https://evil.example/six-1.17.0-py2.py3-none-any.whl", filename: "six-1.17.0-py2.py3-none-any.whl" } }] }), "a url changed");
  const two = { ...six, files: [six.files[0]!, { ...six.files[1]!, hashes: [{ alg: "sha512", digest: "1".repeat(128) }, ...six.files[1]!.hashes] }] };
  const swapped = { ...six, files: [six.files[0]!, { ...six.files[1]!, hashes: [...six.files[1]!.hashes, { alg: "sha512", digest: "1".repeat(128) }] }] };
  assert.equal(identityDigest(two), identityDigest(swapped), "hash order");

  // The same requirement line in uv's export and in a hand-written file: one identity whatever the file.
  const root = tree({});
  const a = requirements(root, "a.txt", `--require-hashes\nsix==1.17.0 --hash=sha256:${SIX_WHL}\n`);
  const b = requirements(root, "b.txt", `--require-hashes\n\n# moved\nsix==1.17.0 --hash=sha256:${SIX_WHL}\n`);
  assert.equal(identityDigest(a.packages[0]!), identityDigest(b.packages[0]!));
});

/* ---- the tool-written locks ---- */

test("soak (PyPI): every lock uv 0.10.9 and 0.12.21 wrote passes a 7-day soak on 2026-10-08; each file is bound and aged", async () => {
  const locks = ["uv-0.10.9", "uv-0.12.21"].flatMap((v) => [
    uv(LOCKS, `${v}/simple/uv.lock`),
    uv(LOCKS, `${v}/fork/uv.lock`),
    uv(LOCKS, `${v}/editable/uv.lock`),
    uv(LOCKS, `${v}/path/uv.lock`),
    uv(LOCKS, `${v}/script/example.py.lock`, undefined, "script"),
    pylock(LOCKS, `${v}/simple/pylock.toml`),
  ]);
  const f = fake();
  const r = await run(locks, f, { root: LOCKS, osv: true });
  assert.deepEqual(only(r.findings, "WS-SK-001"), []);
  assert.deepEqual(only(r.findings, "WS-SK-002"), []);
  assert.deepEqual(
    only(r.findings, "WS-SK-005").map((x) => x.message.slice(0, x.message.indexOf(" is built"))),
    ["demo-editable (editable source uv-0.10.9/editable)", "member (editable source uv-0.10.9/editable/packages/member)", "localdir (directory source uv-0.10.9/path/libs/localdir)", "demo-editable (editable source uv-0.12.21/editable)", "member (editable source uv-0.12.21/editable/packages/member)", "localdir (directory source uv-0.12.21/path/libs/localdir)"],
  );
  assert.equal(r.findings.length, 6);
  assert.deepEqual([...new Set(f.asked)].sort(), ["certifi", "idna", "markupsafe", "packaging", "six"]);
  assert.equal(f.asked.length, 5, "one GET per project, however many locks name it");
  assert.deepEqual(r.notes.slice(0, 3), [
    "150 PyPI file(s) of 7 version(s) checked against https://pypi.org/simple/", // the distinct sha256s in those locks (grep -o sha256 | sort -u)
    "registry signals (WS-RG-*) are not implemented for PyPI",
    "release-age settings of Python tools are not checked by soak; see harden-dev.sh",
  ]);
  assert.match(r.notes[3]!, /^12 local Python package\(s\) not age-checked \(their code is in this repository\): demo-simple==0\.1\.0, /);
  assert.equal(r.notes[4], "the scanned root is not in a git work tree, so whether local Python sources are tracked by git was not checked");
  assert.match(r.notes[5]!, /^7 package version\(s\) checked against OSV for malicious-package records \(PyPI\); 12 not sent to OSV \(local code/);
  assert.deepEqual([...new Set(f.osv)].sort(), ["certifi@2026.7.22", "idna@3.10", "idna@3.20", "markupsafe@2.1.5", "markupsafe@3.0.3", "packaging@25.0", "six@1.17.0"]);

  const six = r.evidence.find((e) => e.name === "six" && e.files?.length === 2)!;
  assert.deepEqual(six, {
    name: "six",
    version: "1.17.0",
    ecosystem: "PyPI",
    publishedAt: "2024-12-04T17:35:28.174320Z",
    ageHours: Math.round(((NOW.getTime() - Date.parse("2024-12-04T17:35:28.174320Z")) / 3_600_000) * 10) / 10,
    status: "ok",
    releaseFirstFileAt: "2024-12-04T17:35:26.475808Z",
    projectStatus: "active",
    files: [
      { filename: "six-1.17.0-py2.py3-none-any.whl", sha256: SIX_WHL, uploadTime: "2024-12-04T17:35:26.475808Z" },
      { filename: "six-1.17.0.tar.gz", sha256: SIX_SDIST, uploadTime: "2024-12-04T17:35:28.174320Z" },
    ],
    osv: [],
  });
  const markupsafe = r.evidence.find((e) => e.name === "markupsafe" && e.version === "3.0.3")!;
  assert.equal(markupsafe.files!.length, 50, "at most 50 files listed");
  assert.ok(markupsafe.filesTotal! > 50);
  assert.ok(r.evidence.every((e) => e.ecosystem === "PyPI" && e.status === "ok"));
  const sorted = [...r.evidence].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  assert.deepEqual(r.evidence.map((e) => `${e.name}@${e.version}`), sorted.map((e) => `${e.name}@${e.version}`));
});

test("soak (PyPI): a fork locks one name at two versions; both are checked, from one GET", async () => {
  const root = tree({});
  const fork = uv(LOCKS, "uv-0.12.21/fork/uv.lock");
  const f = fake();
  const r = await run([fork], f, { root: LOCKS });
  assert.deepEqual(r.evidence.map((e) => `${e.name}@${e.version} ${e.status}`), ["markupsafe@2.1.5 ok", "markupsafe@3.0.3 ok", "six@1.17.0 ok"]);
  assert.deepEqual(f.asked.sort(), ["markupsafe", "six"]);
  // A file of the other fork's version in this entry is caught: version binding is per entry.
  const swapped = edit(readFileSync(join(LOCKS, "uv-0.12.21", "fork", "uv.lock"), "utf8"), 'name = "markupsafe"\nversion = "2.1.5"', 'name = "markupsafe"\nversion = "3.0.3"');
  const both = await run([uv(root, "uv.lock", swapped)], fake(), { root });
  assert.ok(only(both.findings, "WS-SK-002").some((x) => x.message.startsWith("Cannot verify soak time for PyPI package markupsafe==3.0.3: MarkupSafe-2.1.5") && x.message.includes("locked hash belongs to MarkupSafe-2.1.5")));
});

/* ---- age ---- */

test("soak (PyPI): a file younger than the soak is WS-SK-001, keyed on the exact locked artifact set", async () => {
  const lock = uv(LOCKS, "uv-0.12.21/simple/uv.lock");
  const now = new Date("2026-09-20T00:00:00Z");
  const r = await run([lock], fake(), { root: LOCKS, now });
  const idna = pkgOf(lock, "idna");
  assert.deepEqual(brief(r.findings).filter((b) => !b.startsWith("WS-SK-005")), [`WS-SK-001 uv-0.12.21/simple/uv.lock pypi:idna@3.20 ${identityDigest(idna)}`]);
  assert.equal(
    r.findings[0]!.message,
    "idna==3.20 (PyPI) has 2 locked file(s) uploaded inside the required 7.0d soak window: idna-3.20-py3-none-any.whl uploaded 2.4d ago (2026-09-17T14:11:03.168153Z); idna-3.20.tar.gz uploaded 2.4d ago (2026-09-17T14:11:04.752193Z)",
  );
  const e = r.evidence.find((x) => x.name === "idna")!;
  assert.deepEqual([e.status, e.publishedAt, e.releaseFirstFileAt, e.ageHours], ["too-new", "2026-09-17T14:11:04.752193Z", "2026-09-17T14:11:03.168153Z", 57.8]);
  // A minute's soak passes the same files.
  const quick = await run([lock], fake(), { root: LOCKS, now, minAgeMs: 60_000 });
  assert.deepEqual(only(quick.findings, "WS-SK-001"), []);
});

test("soak (PyPI): age is the youngest locked file's; a wheel added months after an old release is too new (PyYAML 6.0.1)", async () => {
  const p = page("pyyaml");
  const sdist = fileOf(p, "PyYAML-6.0.1.tar.gz");
  const late = fileOf(p, "PyYAML-6.0.1-cp312-cp312-manylinux_2_17_aarch64.manylinux2014_aarch64.whl");
  const early = fileOf(p, "PyYAML-6.0.1-cp310-cp310-macosx_11_0_arm64.whl");
  const entry = (f: Record<string, unknown>): string => `{ url = "${f["url"] as string}", hash = "sha256:${(f["hashes"] as { sha256: string }).sha256}", size = ${f["size"] as number} }`;
  const lockText = (wheels: Record<string, unknown>[]): string =>
    `version = 1\nrevision = 3\nrequires-python = ">=3.9"\n\n[[package]]\nname = "pyyaml"\nversion = "6.0.1"\nsource = { registry = "https://pypi.org/simple" }\nsdist = ${entry(sdist)}\nwheels = [\n${wheels.map((w) => `    ${entry(w)},\n`).join("")}]\n`;
  const root = tree({});
  const now = new Date("2024-01-20T12:00:00Z");
  const r = await run([uv(root, "uv.lock", lockText([early, late]))], fake(), { root, now });
  assert.deepEqual(only(r.findings, "WS-SK-001").map((x) => x.message), [
    "pyyaml==6.0.1 (PyPI) has 1 locked file(s) uploaded inside the required 7.0d soak window: PyYAML-6.0.1-cp312-cp312-manylinux_2_17_aarch64.manylinux2014_aarch64.whl uploaded 39.3h ago (2024-01-18T20:40:22.920708Z), added 184.9 days after the release's first file (2023-07-17T23:57:04.325444Z)",
  ]);
  const e = r.evidence[0]!;
  assert.deepEqual([e.status, e.publishedAt, e.releaseFirstFileAt], ["too-new", "2024-01-18T20:40:22.920708Z", "2023-07-17T23:57:04.325444Z"]);
  assert.deepEqual(e.files!.map((x) => x.filename), ["PyYAML-6.0.1-cp310-cp310-macosx_11_0_arm64.whl", "PyYAML-6.0.1-cp312-cp312-manylinux_2_17_aarch64.manylinux2014_aarch64.whl", "PyYAML-6.0.1.tar.gz"]);
  // Without the late wheel, the same release is old enough.
  const old = await run([uv(root, "uv.lock", lockText([early]))], fake(), { root, now });
  assert.deepEqual(only(old.findings, "WS-SK-001"), []);
  assert.equal(old.evidence[0]!.status, "ok");
});

test("soak (PyPI): a file exactly as old as the soak passes; a millisecond younger is WS-SK-001", async () => {
  const root = tree({});
  const lock = requirements(root, "requirements.txt", `--require-hashes\nsix==1.17.0 --hash=sha256:${SIX_WHL}\n`);
  const uploaded = Date.parse("2024-12-04T17:35:26.475808Z");
  const exact = await run([lock], fake(), { root, now: new Date(uploaded + WEEK) });
  assert.deepEqual([exact.findings, exact.evidence.map((e) => e.status)], [[], ["ok"]]);
  const younger = await run([lock], fake(), { root, now: new Date(uploaded + WEEK - 1) });
  assert.deepEqual([younger.findings.map((x) => x.ruleId), younger.evidence.map((e) => e.status)], [["WS-SK-001"], ["too-new"]]);
});

/* ---- binding ---- */

test("soak (PyPI): the binding rule; an unhashed or sha512-only file is WS-SK-002 and nothing is sent for it", async () => {
  // The readers' forged locks: the reader refuses the file, and that problem fails the lock on every run.
  for (const [name, why] of [
    ["uv-unhashed-wheel.lock", /six-1\.17\.0-py2\.py3-none-any\.whl\): no sha256 hash, so it cannot be bound to an index file$/],
    ["uv-sha512-only-wheel.lock", /no sha256 hash, so it cannot be bound to an index file$/],
  ] as const) {
    const { root, lock } = copied(`forged/${name}`);
    const r = await run([lock], fake(), { root });
    const problems = only(r.findings, "WS-SK-002");
    assert.equal(problems.length, 1, name);
    assert.match(problems[0]!.message, why);
    assert.match(problems[0]!.key, /^pypi:lockfile uv\.lock [0-9a-f]{32}$/);
    assert.equal(problems[0]!.file, "uv.lock");
  }

  // The model's own rule, for any mapper: every file needs a sha256.
  const lock = uv(LOCKS, "uv-0.12.21/simple/uv.lock");
  const six = pkgOf(lock, "six");
  const sha512Only: PyPackage = { ...six, files: [six.files[0]!, { ...six.files[1]!, hashes: [{ alg: "sha512", digest: "1".repeat(128) }] }] };
  const f = fake();
  const r = await run([{ ...lock, packages: [sha512Only] }], f, { root: LOCKS });
  assert.deepEqual(r.findings.map((x) => [x.ruleId, x.key, x.message]), [
    ["WS-SK-002", keyOf(sha512Only), "Cannot verify soak time for PyPI package six==1.17.0: six-1.17.0-py2.py3-none-any.whl: no sha256 hash, so it cannot be bound to an index file"],
  ]);
  assert.deepEqual(f.asked, [], "nothing is fetched for a package that cannot be bound");
  const none = await run([{ ...lock, packages: [{ ...six, files: [] }] }], fake(), { root: LOCKS });
  assert.equal(none.findings[0]!.message, "Cannot verify soak time for PyPI package six==1.17.0: the lock pins no file for it, so nothing can be bound to an index file");

  // A pylock package without a version.
  const nov = copied("forged/pylock-no-version.toml");
  const rn = await run([nov.lock], fake(), { root: nov.root });
  assert.deepEqual(only(rn.findings, "WS-SK-002").map((x) => x.message), [
    "Cannot verify soak time for the packages in pylock.toml: [[packages]] #2 (six): no version, so it cannot be bound or checked against OSV",
    "Cannot verify soak time for PyPI package six: the lock gives no version, so it cannot be bound or checked against OSV",
  ]);
});

test("soak (PyPI): a locked hash of another version or project, or one the index no longer lists, is WS-SK-002", async () => {
  const root = tree({});
  // The 1.16.0 wheel relabelled as 1.17.0 (url and hash both 1.16.0's), and the same in a requirements file.
  const relabelled = edit(SIMPLE_UV, `{ url = "${SIX_WHL_URL}", hash = "sha256:${SIX_WHL}"`, `{ url = "${SIX_116_WHL_URL}", hash = "sha256:${SIX_116_WHL}"`);
  const r = await run([uv(root, "uv.lock", relabelled)], fake(), { root });
  assert.deepEqual(only(r.findings, "WS-SK-002").map((x) => x.message), [
    "Cannot verify soak time for PyPI package six==1.17.0: six-1.16.0-py2.py3-none-any.whl: locked hash belongs to six-1.16.0-py2.py3-none-any.whl, not to a file of six 1.17.0",
  ]);
  const req = requirements(root, "requirements.txt", `--require-hashes\nsix==1.17.0 --hash=sha256:${SIX_116_WHL}\nidna==3.20 --hash=sha256:${SIX_WHL}\n`);
  const rr = await run([req], fake(), { root });
  assert.deepEqual(rr.findings.map((x) => [x.ruleId, x.file, x.line, x.message]), [
    ["WS-SK-002", "requirements.txt", 2, `Cannot verify soak time for PyPI package six==1.17.0: sha256:${SIX_116_WHL}: locked hash belongs to six-1.16.0-py2.py3-none-any.whl, not to a file of six 1.17.0`],
    ["WS-SK-002", "requirements.txt", 3, `Cannot verify soak time for PyPI package idna==3.20: sha256:${SIX_WHL}: not on the index (deleted or quarantined), or never published`],
  ]);

  // The wheel deleted from the index (or its release quarantined, which looks the same from outside).
  const removed = page("six");
  removed.files = removed.files.filter((x) => x["filename"] !== "six-1.17.0-py2.py3-none-any.whl");
  const gone = await run([uv(LOCKS, "uv-0.12.21/simple/uv.lock")], fake({ six: removed }), { root: LOCKS });
  assert.deepEqual(only(gone.findings, "WS-SK-002").map((x) => [x.key, x.message]), [
    [keyOf(pkgOf(uv(LOCKS, "uv-0.12.21/simple/uv.lock"), "six")), "Cannot verify soak time for PyPI package six==1.17.0: six-1.17.0-py2.py3-none-any.whl: not on the index (deleted or quarantined), or never published"],
  ]);
  const release = page("six");
  release.files = release.files.filter((x) => !String(x["filename"]).startsWith("six-1.17.0"));
  const quarantinedRelease = await run([uv(LOCKS, "uv-0.12.21/simple/uv.lock")], fake({ six: release }), { root: LOCKS });
  assert.deepEqual(only(quarantinedRelease.findings, "WS-SK-002").map((x) => x.message), [
    "Cannot verify soak time for PyPI package six==1.17.0: six-1.17.0.tar.gz: not on the index (deleted or quarantined), or never published; six-1.17.0-py2.py3-none-any.whl: not on the index (deleted or quarantined), or never published",
  ]);
  assert.deepEqual(quarantinedRelease.evidence.find((e) => e.name === "six"), { name: "six", version: "1.17.0", ecosystem: "PyPI", status: "unverifiable", reason: "six-1.17.0.tar.gz: not on the index (deleted or quarantined), or never published; six-1.17.0-py2.py3-none-any.whl: not on the index (deleted or quarantined), or never published" });
});

test("soak (PyPI): a project the index does not have, or marks quarantined or with an unknown status, is WS-SK-002", async () => {
  const lock = uv(LOCKS, "uv-0.12.21/simple/uv.lock");
  const idnaKey = keyOf(pkgOf(lock, "idna"));
  const missing = await run([lock], fake({ idna: null }), { root: LOCKS, osv: true });
  assert.deepEqual(only(missing.findings, "WS-SK-002").map((x) => [x.key, x.message]), [[idnaKey, "Cannot verify soak time for PyPI package idna==3.20: idna is not on the index (deleted or quarantined), or never published"]]);
  assert.match(missing.notes.at(-1)!, /; 1 not sent to OSV \(the index did not return a page for them, so the name may not be public\)$/);

  // PyPI's shape for a quarantined project: the top-level status, and no files.
  const q1 = page("idna");
  q1["project-status"] = { status: "quarantined", reason: "malware" };
  q1.files = [];
  // The Simple API specification's example shape (flat strings in meta), from an index that still lists the files.
  const q2 = page("idna");
  delete q2["project-status"];
  q2.meta["project-status"] = "quarantined";
  for (const [q, reason] of [[q1, ' (reason given: "malware")'], [q2, ""]] as const) {
    const r = await run([lock], fake({ idna: q }), { root: LOCKS });
    assert.deepEqual(only(r.findings, "WS-SK-002").map((x) => [x.key, x.message]), [[idnaKey, `Cannot verify soak time for PyPI package idna==3.20: ${QUARANTINED}${reason}`]]);
    assert.equal(QUARANTINED, "the index marks the project quarantined (PEP 792: unsafe, e.g. malware); from the spec and warehouse source, not observed live");
  }
  const odd = page("idna");
  odd["project-status"] = { status: "frozen" };
  const u = await run([lock], fake({ idna: odd }), { root: LOCKS });
  assert.deepEqual(only(u.findings, "WS-SK-002").map((x) => x.message), ['Cannot verify soak time for PyPI package idna==3.20: the index gives the project status "frozen", which wormsign does not know (PEP 792 defines active, archived, deprecated and quarantined)']);
  const err = await run([lock], fake({ idna: 503 }), { root: LOCKS });
  assert.deepEqual(only(err.findings, "WS-SK-002").map((x) => x.message), ["Cannot verify soak time for PyPI package idna==3.20: the index returned HTTP 503"]);

  // Archived and deprecated projects are still checked, with a note; so are yanked files.
  const archived = page("six");
  archived["project-status"] = { status: "archived", reason: "no longer maintained" };
  const yanked = page("idna");
  fileOf(yanked, "idna-3.20.tar.gz")["yanked"] = "broken metadata";
  const r = await run([lock], fake({ six: archived, idna: yanked }), { root: LOCKS });
  assert.deepEqual(only(r.findings, "WS-SK-002"), []);
  assert.ok(r.notes.includes('the index marks 1 project(s) archived or deprecated (PEP 792; their files were still checked): six (archived: "no longer maintained")'));
  assert.ok(r.notes.includes('1 locked PyPI file(s) are yanked on the index (PEP 592: yanking is not a malware signal, and an install pinned to the file still uses it): idna 3.20 idna-3.20.tar.gz ("broken metadata")'));
  assert.deepEqual(r.evidence.find((e) => e.name === "idna")!.files!.map((x) => [x.filename, x.yanked]), [["idna-3.20-py3-none-any.whl", undefined], ["idna-3.20.tar.gz", true]]);
  assert.equal(r.evidence.find((e) => e.name === "six")!.projectStatus, "archived");
});

test("soak (PyPI): a lock url that is not the index's url for the bound file is WS-SK-002 (uv.lock and pylock)", async () => {
  const root = tree({});
  const evil = SIX_WHL_URL.replace("files.pythonhosted.org", "files.pythonhosted.example");
  const r = await run([uv(root, "uv.lock", edit(SIMPLE_UV, `{ url = "${SIX_WHL_URL}"`, `{ url = "${evil}"`))], fake(), { root });
  assert.deepEqual(only(r.findings, "WS-SK-002").map((x) => x.message), [`Cannot verify soak time for PyPI package six==1.17.0: six-1.17.0-py2.py3-none-any.whl: the lock's url ${evil} is not the index's url for that file (${SIX_WHL_URL})`]);
  const pyText = readFileSync(join(LOCKS, "uv-0.12.21", "simple", "pylock.toml"), "utf8");
  const p = await run([pylock(root, "pylock.toml", edit(pyText, `{ url = "${SIX_WHL_URL}"`, `{ url = "${evil}"`))], fake(), { root });
  assert.equal(only(p.findings, "WS-SK-002").length, 1);
  // A file name that is not the index's for that hash, as pylock's `name` can state.
  const named = edit(pyText, `wheels = [{ url = "${SIX_WHL_URL}"`, `wheels = [{ name = "six-1.17.0-py3-none-win_amd64.whl", url = "${SIX_WHL_URL}"`);
  const n = await run([pylock(root, "pylock.toml", named)], fake(), { root });
  assert.deepEqual(only(n.findings, "WS-SK-002").map((x) => x.message), ['Cannot verify soak time for PyPI package six==1.17.0: six-1.17.0-py2.py3-none-any.whl: the lock names the file "six-1.17.0-py3-none-win_amd64.whl", not the index\'s six-1.17.0-py2.py3-none-any.whl']);
});

test("soak (PyPI): uv's pylock names wheels in normalised form (pyyaml-..., markupsafe-..., jaraco_classes-...); the real exports pass", async () => {
  // test/fixtures/python/forged/uv-export-names: uv 0.12.21's uv.lock and pylock.toml (0.10.9 wrote the same bytes).
  const dir = join(FORGED, "uv-export-names");
  const py = pylock(dir, "pylock.toml");
  const uvl = uv(dir, "uv.lock");
  // Positive control: the export names files otherwise than the index does.
  const renamed = (name: string): string[] => {
    const onIndex = new Set(page(name).files.map((f) => f["filename"] as string));
    return pkgOf(py, name).files.flatMap((f) => (f.locator.filename !== undefined && !onIndex.has(f.locator.filename) ? [f.locator.filename] : []));
  };
  assert.equal(renamed("pyyaml").length, 7);
  assert.equal(renamed("markupsafe").length, 30);
  assert.deepEqual(renamed("jaraco-classes"), ["jaraco_classes-3.4.0-py3-none-any.whl"]);
  const f = fake();
  const r = await run([py, uvl], f, { root: dir });
  assert.deepEqual(r.findings, []);
  assert.deepEqual(r.evidence.map((e) => `${e.name}@${e.version} ${e.status} ${e.filesTotal ?? e.files!.length}`), [
    "jaraco-classes@3.4.0 ok 2",
    "jaraco-classes@3.4.0 ok 2",
    "markupsafe@3.0.2 ok 31",
    "markupsafe@3.0.2 ok 31",
    "more-itertools@11.1.0 ok 2", // one identity in both locks (no `name` in the pylock), so checked once
    "pyyaml@6.0.1 ok 8",
    "pyyaml@6.0.1 ok 8",
  ]);
  assert.equal(r.notes[0], "43 PyPI file(s) of 4 version(s) checked against https://pypi.org/simple/");

  // A name that is another file's (here PyPI's win_amd64 wheel, for the win32 one) is still refused.
  const text = readFileSync(join(dir, "pylock.toml"), "utf8");
  const other = edit(text, 'name = "pyyaml-6.0.1-cp312-cp312-win32.whl"', 'name = "pyyaml-6.0.1-cp312-cp312-win_amd64.whl"');
  const root = tree({});
  const o = await run([pylock(root, "pylock.toml", other)], fake(), { root });
  assert.deepEqual(only(o.findings, "WS-SK-002").map((x) => x.message), ['Cannot verify soak time for PyPI package pyyaml==6.0.1: PyYAML-6.0.1-cp312-cp312-win32.whl: the lock names the file "pyyaml-6.0.1-cp312-cp312-win_amd64.whl", not the index\'s PyYAML-6.0.1-cp312-cp312-win32.whl']);
});

test("soak (PyPI): a file name the lock gives names the index file when kind, project, version and tags (or sdist extension) agree", () => {
  const ix = (name: string, filename: string): IndexFile => {
    const r = parseSimpleProject({ meta: { "api-version": "1.4" }, name, files: [{ filename, hashes: {} }] }, name, `${INDEX}${name}/`);
    assert.ok("project" in r);
    return r.project.files[0]!;
  };
  const win32 = ix("pyyaml", "PyYAML-6.0.1-cp312-cp312-win32.whl");
  const sdist = ix("pyyaml", "PyYAML-6.0.1.tar.gz");
  for (const [name, file, same] of [
    ["PyYAML-6.0.1-cp312-cp312-win32.whl", win32, true],
    ["pyyaml-6.0.1-cp312-cp312-win32.whl", win32, true],
    ["PyYAML-6.0.1-cp312-cp312-WIN32.whl", win32, true],
    ["jaraco_classes-3.4.0-py3-none-any.whl", ix("jaraco-classes", "jaraco.classes-3.4.0-py3-none-any.whl"), true],
    ["pyyaml-6.0.1-cp312-cp312-win_amd64.whl", win32, false],
    ["pyyaml-6.0.1-1-cp312-cp312-win32.whl", win32, false],
    ["pyyaml-6.0.2-cp312-cp312-win32.whl", win32, false],
    ["ruamel_yaml-6.0.1-cp312-cp312-win32.whl", win32, false],
    ["pyyaml-6.0.1-py3-none-any.whl", sdist, false],
    ["pyyaml-6.0.1.tar.gz", sdist, true],
    ["pyyaml-6.0.1.zip", sdist, false],
    ["pyyaml-6.0.1.tar.gz", win32, false],
    ["six-1.17.0-py3-none-win_amd64.whl", ix("six", "six-1.17.0-py2.py3-none-any.whl"), false],
    ["not a file name", win32, false],
    ["PyYAML-6.0.1.exe", ix("pyyaml", "PyYAML-6.0.1.exe"), true],
    ["pyyaml-6.0.1.exe", ix("pyyaml", "PyYAML-6.0.1.exe"), false],
  ] as const) {
    assert.equal(namesIndexFile(name, file), same, `${name} names ${file.filename}: ${same}`);
  }
});

test("soak (PyPI): a pylock file listing another hash beside its sha256 is WS-SK-002, since pip accepts a file matching any of them", async () => {
  const root = tree({});
  const text = readFileSync(join(FORGED, "pylock-mixed-hashes.toml"), "utf8");
  const lock = pylock(root, "pylock.toml", text);
  assert.deepEqual(pkgOf(lock, "six").files[0]!.hashes.map((h) => h.alg), ["sha256", "sha512", "sha3_256"], "the reader keeps every algorithm");
  const f = fake();
  const r = await run([lock], f, { root, osv: true });
  assert.deepEqual(r.findings.map((x) => [x.ruleId, x.key, x.message]), [
    [
      "WS-SK-002",
      keyOf(pkgOf(lock, "six")),
      'Cannot verify soak time for PyPI package six==1.17.0: six-1.17.0-py2.py3-none-any.whl: a hash other than sha256 as well ("sha3_256", "sha512"); pip accepts a file that matches any one of a lock\'s hashes and soak binds only the sha256, so the file cannot be bound to an index file',
    ],
  ]);
  assert.deepEqual([f.asked, f.osv], [[], []], "nothing is sent for it");
  // The same entry with its sha256 alone passes.
  const plain = text.replace(/, sha512 = "[0-9a-f]+", sha3_256 = "anything"/, "");
  assert.notEqual(plain, text);
  assert.deepEqual((await run([pylock(root, "pylock.toml", plain)], fake(), { root })).findings, []);
});

test("soak (PyPI): a lock url only WHATWG parsing makes the index's (backslash, dot segments, case) is WS-SK-002 (pylock and uv.lock)", async () => {
  const root = tree({});
  const text = readFileSync(join(FORGED, "pylock-url-normalises.toml"), "utf8");
  const lock = pylock(root, "pylock.toml", text);
  const spelled = pkgOf(lock, "six").files[0]!.locator.url!;
  assert.equal(new URL(spelled).href, SIX_WHL_URL, "positive control: Node reads it as the index's url");
  const r = await run([lock], fake(), { root });
  assert.deepEqual(only(r.findings, "WS-SK-002").map((x) => x.message), [`Cannot verify soak time for PyPI package six==1.17.0: six-1.17.0-py2.py3-none-any.whl: the lock's url ${spelled} is not the index's url for that file (${SIX_WHL_URL})`]);
  for (const url of [spelled, SIX_WHL_URL.replace("/b7/ce/", "/b7/ce/./"), SIX_WHL_URL.replace("files.pythonhosted.org", "FILES.pythonhosted.org"), `${SIX_WHL_URL}#sha512=${"1".repeat(128)}`]) {
    const u = await run([uv(root, "uv.lock", edit(SIMPLE_UV, `{ url = "${SIX_WHL_URL}"`, `{ url = ${JSON.stringify(url)}`))], fake(), { root });
    assert.equal(only(u.findings, "WS-SK-002").length, 1, url);
  }
});

test("soak (PyPI): a WS-SK-002 lists at most MAX_FILE_PROBLEMS files and counts the rest", async () => {
  assert.equal(MAX_FILE_PROBLEMS, 3);
  const six = pkgOf(uv(LOCKS, "uv-0.12.21/simple/uv.lock"), "six");
  const file = (i: number, digest?: string): PyPackage["files"][number] => ({ locator: { filename: `six-1.17.0-py3-none-x${i}.whl` }, hashes: [{ alg: digest === undefined ? "sha512" : "sha256", digest: digest ?? "1".repeat(128) }], kind: "wheel" });
  const missing: PyPackage = { ...six, files: [1, 2, 3, 4, 5].map((i) => file(i, String(i).repeat(64))) };
  const r = await run([{ kind: "uv", file: "uv.lock", packages: [missing], problems: [] }], fake(), { root: LOCKS });
  const nf = "not on the index (deleted or quarantined), or never published";
  const reason = `six-1.17.0-py3-none-x1.whl: ${nf}; six-1.17.0-py3-none-x2.whl: ${nf}; six-1.17.0-py3-none-x3.whl: ${nf}; and 2 more file(s)`;
  assert.deepEqual(r.findings.map((x) => [x.key, x.message]), [[keyOf(missing), `Cannot verify soak time for PyPI package six==1.17.0: ${reason}`]]);
  assert.equal(r.evidence[0]!.reason, reason);
  const unhashed: PyPackage = { ...six, files: [1, 2, 3, 4].map((i) => file(i)) };
  const u = await run([{ kind: "uv", file: "uv.lock", packages: [unhashed], problems: [] }], fake(), { root: LOCKS });
  assert.equal(u.findings[0]!.message, "Cannot verify soak time for PyPI package six==1.17.0: six-1.17.0-py3-none-x1.whl, six-1.17.0-py3-none-x2.whl, six-1.17.0-py3-none-x3.whl, and 1 more file(s): no sha256 hash, so it cannot be bound to an index file");
});

/* ---- sources ---- */

test("soak (PyPI): another index, git, VCS and direct URLs are WS-SK-002 and their names are sent nowhere", async () => {
  const root = tree({});
  const corp = edit(SIMPLE_UV, 'name = "six"\nversion = "1.17.0"\nsource = { registry = "https://pypi.org/simple" }', 'name = "six"\nversion = "1.17.0"\nsource = { registry = "https://user:secret@pypi.corp.example/simple" }');
  const f = fake();
  const r = await run([uv(root, "uv.lock", corp)], f, { root, osv: true });
  assert.deepEqual(only(r.findings, "WS-SK-002").map((x) => x.message), [
    "Cannot verify soak time for PyPI package six==1.17.0: it is locked from https://pypi.corp.example/simple, not --pypi-index https://pypi.org/simple/ (wormsign checks one index (--pypi-index) and sends no credentials. If the entry is trusted, baseline it with a justification: the baseline key pins its name, version, source and every file hash, so any change to them fails again)",
  ]);
  assert.deepEqual(f.asked, ["idna"]);
  assert.deepEqual(f.osv, ["idna@3.20"]);
  // Even when discovery marks it sendable, a registry that is not --pypi-index is not asked.
  const lock = uv(root, "uv.lock", corp);
  const marked = { ...lock, packages: lock.packages.map((p) => ({ ...p, sendable: true })) };
  const g = fake();
  const m = await run([marked], g, { root });
  assert.equal(only(m.findings, "WS-SK-002").length, 1);
  assert.deepEqual(g.asked, ["idna"]);
  // The same index written another way is the same index.
  const spelled = await run([uv(root, "uv.lock", edit(SIMPLE_UV, 'source = { registry = "https://pypi.org/simple" }\nsdist = { url = "https://files.pythonhosted.org/packages/94', 'source = { registry = "https://PyPI.org/simple/" }\nsdist = { url = "https://files.pythonhosted.org/packages/94'))], fake(), { root });
  assert.deepEqual(only(spelled.findings, "WS-SK-002"), []);

  const gitLock = copied("forged/uv-git-source.lock");
  const git = await run([gitLock.lock], (f.asked.length = 0, f), { root: gitLock.root, osv: true });
  assert.deepEqual(only(git.findings, "WS-SK-002").map((x) => x.message), ["Cannot verify soak time for PyPI package six==1.17.0: it resolves from a git source (https://github.com/benjaminp/six?tag=1.17.0#2b9bd1ba1ee9e3f1a6c7a1d1b6b6a7c3f7f2a1c0), which has no index upload time"]);
  assert.ok(!f.asked.includes("six") && !f.osv.includes("six@1.17.0"));

  const pyLocal = copied("forged/pylock-local-sources.toml");
  const local = await run([pyLocal.lock], fake(), { root: pyLocal.root });
  assert.ok(only(local.findings, "WS-SK-002").some((x) => x.message === "Cannot verify soak time for PyPI package six-git: the lock gives no version, so it cannot be bound or checked against OSV"));
  const vcs: PyPackage = { name: "six", version: "1.17.0", source: { kind: "vcs", value: "git+https://github.com/benjaminp/six@2b9b" }, files: [], sendable: true };
  const url: PyPackage = { name: "six", version: "1.17.0", source: { kind: "url", value: "https://example.com/six-1.17.0.tar.gz" }, files: [{ locator: { url: "https://example.com/six-1.17.0.tar.gz" }, hashes: [{ alg: "sha256", digest: SIX_SDIST }] }], sendable: true };
  const archive: PyPackage = { name: "six", version: "1.17.0", source: { kind: "archive", value: "https://example.com/six-1.17.0.tar.gz" }, files: [{ locator: { url: "https://example.com/six-1.17.0.tar.gz" }, hashes: [{ alg: "sha256", digest: SIX_SDIST }], kind: "archive" }], sendable: true };
  const h = fake();
  const direct = await run([{ kind: "pylock", file: "pylock.toml", packages: [vcs, url, archive], problems: [] }], h, { root });
  assert.deepEqual(direct.findings.map((x) => x.message), [
    "Cannot verify soak time for PyPI package six==1.17.0: it resolves from a VCS source (git+https://github.com/benjaminp/six@2b9b), which has no index upload time",
    "Cannot verify soak time for PyPI package six==1.17.0: it resolves from a direct URL (https://example.com/six-1.17.0.tar.gz), which is not an index file",
    "Cannot verify soak time for PyPI package six==1.17.0: it is a direct archive (https://example.com/six-1.17.0.tar.gz) that is not an index file",
  ]);
  assert.deepEqual(h.asked, []);
});

test("soak (PyPI): a pylock archive by path whose lock records another index is WS-SK-002 and nothing is sent, whatever discovery says", async () => {
  const root = tree({ "vendor/six-1.17.0-py2.py3-none-any.whl": SIX_WHEEL_BYTES });
  const text = readFileSync(join(FORGED, "pylock-path-archive-private-index.toml"), "utf8");
  const lock = pylock(root, "pylock.toml", text);
  const six = pkgOf(lock, "six");
  assert.deepEqual(
    [six.source, six.lockIndex, six.sendable, six.unsent],
    [{ kind: "archive", value: "vendor/six-1.17.0-py2.py3-none-any.whl" }, "https://private.example/simple", false, "the lock records the index https://private.example/simple for it, not --pypi-index"],
  );
  const calls: string[] = [];
  const counting = (async (u: string | URL) => {
    calls.push(String(u));
    throw new Error("no request may be made");
  }) as unknown as typeof fetch;
  const marked: PyLock = { ...lock, packages: lock.packages.map((p) => ({ ...p, sendable: true, unsent: undefined })) };
  for (const l of [lock, marked]) {
    const r = await checkPythonLocks([l], { minAgeMs: WEEK, now: NOW, pypiIndex: INDEX, root, git: "no-work-tree", fetchImpl: counting, osv: true });
    assert.deepEqual(r.findings.map((x) => x.ruleId), ["WS-SK-002"]);
    assert.match(r.findings[0]!.message, /^Cannot verify soak time for PyPI package six==1\.17\.0: it is locked from https:\/\/private\.example\/simple, not --pypi-index https:\/\/pypi\.org\/simple\/ \(wormsign checks one index/);
  }
  assert.deepEqual(calls, [], "the name went nowhere");
  // The same archive recorded from --pypi-index (or with no index) is bound and aged on it.
  for (const index of ['index = "https://pypi.org/simple"\n', ""]) {
    const ok = await run([pylock(root, "pylock.toml", edit(text, 'index = "https://private.example/simple"\n', index))], fake(), { root });
    assert.deepEqual(ok.findings, [], index);
    assert.deepEqual(ok.evidence.map((e) => `${e.name} ${e.status}`), ["six ok"]);
  }
});

test("model: fromPylock takes discovery's install-settings verdict for packages without index, and only for them", async () => {
  const pip = readPylock(join(LOCKS, "pip-26.2.1", "lock", "pylock.toml"));
  const confirmed = fromPylock("pylock.toml", pip, { pypiIndex: INDEX, sendable: true });
  assert.ok(confirmed.packages.length > 0 && confirmed.packages.every((p) => p.sendable && p.unsent === undefined));
  const root = tree({});
  const r = await run([confirmed], fake(), { root });
  assert.deepEqual(r.findings, []);
  assert.deepEqual(r.evidence.map((e) => `${e.name}@${e.version} ${e.status}`), ["certifi@2026.7.22 ok", "idna@3.10 ok", "six@1.17.0 ok"]);
  const refused = fromPylock("pylock.toml", pip, { pypiIndex: INDEX, unsent: "PIP_INDEX_URL names another index" });
  assert.ok(refused.packages.every((p) => !p.sendable && p.unsent === "PIP_INDEX_URL names another index"));
  // A package that records an index is decided by that index, whatever the verdict.
  const uvPy = readPylock(join(LOCKS, "uv-0.12.21", "simple", "pylock.toml"));
  assert.ok(fromPylock("pylock.toml", uvPy, { pypiIndex: "https://pypi.corp.example/simple/", sendable: true }).packages.every((p) => !p.sendable));
});

test("soak (PyPI): a requirements entry is sent only when discovery confirmed the install's index settings", async () => {
  const root = tree({});
  const text = `--require-hashes\nsix==1.17.0 \\\n    --hash=sha256:${SIX_WHL}\n`;
  const f = fake();
  const unconfirmed = await run([requirements(root, "requirements.txt", text, false)], f, { root, osv: true });
  assert.deepEqual(unconfirmed.findings.map((x) => [x.ruleId, x.line, x.message]), [
    ["WS-SK-002", 2, "Cannot verify soak time for PyPI package six==1.17.0: a requirements file records no index, so the install's index settings decide where it comes from, and they were not confirmed to be --pypi-index, so its name is sent nowhere (wormsign checks one index (--pypi-index) and sends no credentials. If the entry is trusted, baseline it with a justification: the baseline key pins its name, version, source and every file hash, so any change to them fails again)"],
  ]);
  assert.deepEqual([f.asked, f.osv], [[], []]);
  const confirmed = await run([requirements(root, "requirements.txt", text, true)], f, { root, osv: true });
  assert.deepEqual(confirmed.findings, []);
  assert.deepEqual([f.asked, f.osv], [["six"], ["six@1.17.0"]]);
  assert.deepEqual(confirmed.evidence.map((e) => [e.name, e.version, e.status, e.files!.map((x) => x.filename)]), [["six", "1.17.0", "ok", ["six-1.17.0-py2.py3-none-any.whl"]]]);
  // Reader problems in a requirements file fail it, whatever the entries.
  const loose = await run([requirements(root, "requirements.txt", `six==1.17.0 --hash=sha256:${SIX_WHL}\n`, true)], fake(), { root });
  assert.match(only(loose.findings, "WS-SK-002")[0]!.message, /^Cannot verify soak time for the packages in requirements\.txt: requirements\.txt: no --require-hashes line/);
});

/* ---- local sources ---- */

const UV_HEAD = 'version = 1\nrevision = 3\nrequires-python = ">=3.9"\n\n';
const localPkg = (name: string, kind: string, path: string): string => `[[package]]\nname = "${name}"\nversion = "0.1.0"\nsource = { ${kind} = "${path}" }\n\n`;
const PYPROJECT = '[project]\nname = "member"\nversion = "0.1.0"\n\n[build-system]\nrequires = ["hatchling==1.27.0"]\nbuild-backend = "hatchling.build"\n';

test("soak (PyPI): local source trees must be inside the root, present, Python projects, with no symlink out; then not age-checked", async () => {
  const outer = mkdtempSync(join(tmpdir(), "ws-pysoak-outer-"));
  const root = join(outer, "repo");
  mkdirSync(join(outer, "outside"), { recursive: true });
  writeFileSync(join(outer, "outside", "pyproject.toml"), PYPROJECT);
  for (const [rel, body] of Object.entries({ "pyproject.toml": PYPROJECT, "libs/ok/pyproject.toml": PYPROJECT, "libs/linked/pyproject.toml": PYPROJECT, "libs/plain/README": "x", "libs/setup/setup.py": "from setuptools import setup\nsetup()\n" })) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), body);
  }
  symlinkSync(join(outer, "outside"), join(root, "libs", "linked", "escape"));
  const text = UV_HEAD + localPkg("root", "virtual", ".") + localPkg("ok", "editable", "libs/ok") + localPkg("setup", "directory", "libs/setup") + localPkg("up", "directory", "../outside") + localPkg("missing", "directory", "libs/missing") + localPkg("linked", "editable", "libs/linked") + localPkg("plain", "directory", "libs/plain");
  const lock = uv(root, "uv.lock", text);
  const f = fake();
  const r = await run([lock], f, { root, osv: true });
  const key = (name: string, problem: string): string => `${keyOf(pkgOf(lock, name))} local ${createHash("sha256").update(problem).digest("hex").slice(0, 32)}`;
  const problems = [
    ["up", '"../outside": not a normalised path (it has an empty, "." or ".." segment)'],
    ["missing", '"libs/missing": not present in the scanned tree (ENOENT)'],
    ["linked", '"libs/linked": the symlink libs/linked/escape resolves outside the scanned root'],
    ["plain", '"libs/plain": holds no pyproject.toml or setup.py, so it is not a Python project'],
  ];
  assert.deepEqual(
    only(r.findings, "WS-SK-002").map((x) => [x.key, x.message]),
    problems.map(([name, problem]) => [key(name!, problem!), `Cannot verify soak time for PyPI package ${name}==0.1.0: local source not present in the reviewed tree: ${problem}`]),
  );
  assert.deepEqual(only(r.findings, "WS-SK-005").map((x) => x.key.split(" ")[1]), ["libs/ok", "libs/setup"], "the virtual root is not built");
  assert.ok(r.notes.includes("3 local Python package(s) not age-checked (their code is in this repository): root==0.1.0, ok==0.1.0, setup==0.1.0"));
  assert.deepEqual([f.asked, f.osv], [[], []], "no local name leaves the machine");

  // The git rule: tracked files only; git failing fails every local source.
  const tracked = new Set(["uv.lock", "pyproject.toml", "libs/ok/pyproject.toml"]);
  assert.deepEqual(checkLocalDirectory("libs/ok", "", { root, git: tracked }), { ok: true, rel: "libs/ok", abs: join(root, "libs", "ok") });
  // Untracked files alone are marked so (soak makes that medium outside PR mode); any other reason is not.
  assert.deepEqual(checkLocalDirectory("libs/setup", "", { root, git: tracked }), { ok: false, problem: '"libs/setup": holds 1 file(s) not tracked by git (libs/setup/setup.py), which are not part of the reviewed tree', untracked: true });
  assert.deepEqual(checkLocalDirectory("libs/ok", "", { root, git: "git-error", gitError: "fatal: detected dubious ownership" }), { ok: false, problem: '"libs/ok": git failed (fatal: detected dubious ownership), so whether it is tracked, and so part of the reviewed tree, is unknown' });
  const g = await run([uv(root, "uv.lock", UV_HEAD + localPkg("ok", "editable", "libs/ok"))], fake(), { root, git: "git-error" });
  assert.deepEqual(brief(g.findings).map((b) => b.split(" ")[0]), ["WS-SK-002"]);
  assert.ok(!g.notes.some((n) => n.includes("not in a git work tree")));
});

test("soak (PyPI): a virtual project (never built or installed) needs its pyproject.toml or setup.py in the reviewed tree; it is not walked", () => {
  const outer = mkdtempSync(join(tmpdir(), "ws-pysoak-virtual-"));
  const root = join(outer, "repo");
  mkdirSync(join(root, "libs", "nopy"), { recursive: true });
  mkdirSync(join(root, "libs", "setup"), { recursive: true });
  mkdirSync(join(root, ".venv", "bin"), { recursive: true });
  writeFileSync(join(root, "pyproject.toml"), '[project]\nname = "app"\nversion = "0.1.0"\n');
  writeFileSync(join(root, "libs", "setup", "setup.py"), "");
  writeFileSync(join(outer, "pyproject.toml"), "");
  // What a local `uv sync` leaves in the tree: a link out of the root, and files git does not track.
  symlinkSync("/usr/bin/env", join(root, ".venv", "bin", "python"));
  const tracked = new Set(["pyproject.toml", "uv.lock", "libs/setup/setup.py"]);
  assert.deepEqual(checkVirtualProject(".", "", { root, git: tracked }), { ok: true, rel: "", abs: root });
  assert.deepEqual(checkVirtualProject("libs/setup", "", { root, git: tracked }), { ok: true, rel: "libs/setup", abs: join(root, "libs", "setup") });
  assert.deepEqual(checkVirtualProject("setup", "libs", { root, git: "no-work-tree" }), { ok: true, rel: "libs/setup", abs: join(root, "libs", "setup") }, "relative to the lock's directory");
  assert.deepEqual(checkVirtualProject(".", "", { root, git: new Set(["uv.lock"]) }), { ok: false, problem: '".": no pyproject.toml or setup.py in the reviewed tree ("pyproject.toml": not tracked by git, so it is not part of the reviewed tree)', untracked: true });
  assert.deepEqual(checkVirtualProject("libs/nopy", "", { root, git: "no-work-tree" }), { ok: false, problem: '"libs/nopy": no pyproject.toml or setup.py in the reviewed tree ("libs/nopy/pyproject.toml": not present in the scanned tree (ENOENT))' });
  for (const raw of ["..", "../repo", "libs/../libs/setup", "./libs/setup", "libs/setup/", "/abs", "C:/x", "file:x", "a\\b", ""]) {
    assert.deepEqual(checkVirtualProject(raw, "", { root, git: "no-work-tree" }), { ok: false, problem: `${JSON.stringify(raw)}: not a relative, normalised path inside the scanned root` }, raw);
  }
  assert.deepEqual(checkVirtualProject("..", "libs", { root, git: "no-work-tree" }), { ok: false, problem: '"..": not a relative, normalised path inside the scanned root' });
  assert.deepEqual(checkVirtualProject(".", "", { root, git: "git-error" }).ok, false);
  // The same tree as an editable source is walked, and the .venv link fails it, for that reason and not as untracked.
  const linked = checkLocalDirectory(".", "", { root, git: tracked }) as { problem: string; untracked?: true };
  assert.match(linked.problem, /the symlink \.venv\/bin\/python resolves outside the scanned root/);
  assert.equal(linked.untracked, undefined);
});

test("soak (PyPI): a pylock directory's subdirectory is part of its path: the directory pip and uv build must be local", async () => {
  const outer = mkdtempSync(join(tmpdir(), "ws-pysoak-outer-"));
  const root = join(outer, "repo");
  for (const [rel, body] of Object.entries({ "libs/x/pyproject.toml": PYPROJECT, "libs/x/sub/pyproject.toml": PYPROJECT.replace("hatchling==1.27.0", "flit_core==3.9.0"), "sub/pyproject.toml": PYPROJECT, "../outside/pyproject.toml": PYPROJECT })) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), body);
  }
  const text = readFileSync(join(FORGED, "pylock-directory-subdirectory.toml"), "utf8");
  const lock = pylock(root, "pylock.toml", text);
  assert.deepEqual(pkgOf(lock, "decoy").source, { kind: "directory", value: "libs/x", subdirectory: "../../outside" });
  assert.equal(localSourcePath(pkgOf(lock, "decoy").source), "libs/x/../../outside");
  const f = fake();
  const r = await run([lock], f, { root, osv: true });
  assert.deepEqual(r.findings.map((x) => [x.ruleId, x.message]), [["WS-SK-002", 'Cannot verify soak time for PyPI package decoy: local source not present in the reviewed tree: "libs/x/../../outside": not a normalised path (it has an empty, "." or ".." segment)']]);
  assert.deepEqual([f.asked, f.osv], [[], []]);
  for (const [path, sub, problem] of [
    ["libs/x", "/etc", '"libs/x//etc": not a normalised path (it has an empty, "." or ".." segment)'],
    [".", "../outside", '"../outside": not a normalised path (it has an empty, "." or ".." segment)'],
  ]) {
    const bad = await run([pylock(root, "pylock.toml", edit(text, 'path = "libs/x", subdirectory = "../../outside"', `path = "${path}", subdirectory = "${sub}"`))], fake(), { root });
    assert.deepEqual(bad.findings.map((x) => x.message), [`Cannot verify soak time for PyPI package decoy: local source not present in the reviewed tree: ${problem}`]);
  }
  // A subdirectory inside the tree: the build is of path/subdirectory, so WS-SK-005 names it, with its requirements.
  for (const [path, dir, requires] of [["libs/x", "libs/x/sub", "flit_core==3.9.0"], [".", "sub", "hatchling==1.27.0"]]) {
    const ok = await run([pylock(root, "pylock.toml", edit(text, 'path = "libs/x", subdirectory = "../../outside"', `path = "${path}", subdirectory = "sub"`))], fake(), { root });
    assert.deepEqual(ok.findings.map((x) => [x.ruleId, x.key]), [["WS-SK-005", `pypi:build ${dir} ${readLocalBuild(join(root, ...dir!.split("/"))).digest}`]]);
    assert.ok(ok.findings[0]!.message.startsWith(`decoy (directory source ${dir}) is built from source at install time, and its build requirements ("${requires}")`), ok.findings[0]!.message);
  }
});

test("soak (PyPI): a local source tree's walk skips the untracked paths git ignores (.venv, __pycache__) when they are listed, and nothing else", async () => {
  const outer = mkdtempSync(join(tmpdir(), "ws-pysoak-ignored-"));
  const root = join(outer, "repo");
  mkdirSync(join(outer, "outside"));
  for (const [rel, body] of Object.entries({ "pyproject.toml": PYPROJECT, ".gitignore": ".venv/\n__pycache__/\n*.pyc\n", "src/member/__init__.py": "", "src/member/__pycache__/__init__.cpython-314.pyc": "x", "src/member/stale.pyc": "x", ".venv/pyvenv.cfg": "home = /usr/bin\n" })) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), body);
  }
  for (let i = 0; i < 20; i++) writeFileSync(join(root, ".venv", `f${i}`), "");
  mkdirSync(join(root, ".venv", "bin"));
  symlinkSync("/usr/bin/env", join(root, ".venv", "bin", "python"));
  const tracked = new Set(["pyproject.toml", ".gitignore", "src/member/__init__.py", "uv.lock"]);
  // As `git ls-files -z --others --ignored --exclude-standard --directory` (git 2.50) lists them for this tree.
  const ignored = new Set([".venv/", "src/member/__pycache__/", "src/member/__pycache__/__init__.cpython-314.pyc", "src/member/stale.pyc"]);
  const problem = (c: ReturnType<typeof checkLocalDirectory>): string => (c.ok ? "ok" : c.problem);
  assert.equal(problem(checkLocalDirectory(".", "", { root, git: tracked, gitIgnored: ignored })), "ok");
  assert.equal(problem(checkLocalDirectory(".", "", { root, git: tracked, gitIgnored: ignored, maxEntries: 6 })), "ok", "ignored entries are not counted");
  // Without the list, or without a tracked set, the same tree fails as before.
  assert.equal(problem(checkLocalDirectory(".", "", { root, git: tracked })), '".": the symlink .venv/bin/python resolves outside the scanned root');
  assert.equal(problem(checkLocalDirectory(".", "", { root, git: "no-work-tree", gitIgnored: ignored })), '".": the symlink .venv/bin/python resolves outside the scanned root');
  // An untracked file git does not ignore still fails it; so does a tracked symlink out, even if listed as ignored.
  writeFileSync(join(root, "src", "member", "new.py"), "");
  assert.equal(problem(checkLocalDirectory(".", "", { root, git: tracked, gitIgnored: ignored })), '".": holds 1 file(s) not tracked by git (src/member/new.py), which are not part of the reviewed tree');
  tracked.add("src/member/new.py");
  symlinkSync(join(outer, "outside"), join(root, "src", "member", "link"));
  tracked.add("src/member/link");
  assert.equal(problem(checkLocalDirectory(".", "", { root, git: tracked, gitIgnored: new Set([...ignored, "src/member/link"]) })), '".": the symlink src/member/link resolves outside the scanned root');

  // Through soak: the editable root project of a uv.lock.
  const lock = uv(root, "uv.lock", UV_HEAD + localPkg("member", "editable", "."));
  unlinkSync(join(root, "src", "member", "link"));
  tracked.delete("src/member/link");
  const r = await run([lock], fake(), { root, git: tracked, gitIgnored: ignored });
  assert.deepEqual(r.findings.map((x) => x.ruleId), ["WS-SK-005"]);
  const without = await run([lock], fake(), { root, git: tracked });
  assert.deepEqual(without.findings.map((x) => x.ruleId), ["WS-SK-002"]);
});

test("soak (PyPI): a path archive must be in the tree, hash to the lock's sha256, and be that release's file on the index", async () => {
  const pathLock = readFileSync(join(LOCKS, "uv-0.12.21", "path", "uv.lock"), "utf8");
  const root = tree({ "vendor/six-1.17.0-py2.py3-none-any.whl": SIX_WHEEL_BYTES, "libs/localdir/pyproject.toml": PYPROJECT });
  const ok = await run([uv(root, "uv.lock", pathLock)], fake(), { root });
  assert.deepEqual(only(ok.findings, "WS-SK-002"), []);
  assert.deepEqual(ok.evidence.find((e) => e.name === "six")!.files, [{ filename: "six-1.17.0-py2.py3-none-any.whl", sha256: SIX_WHL, uploadTime: "2024-12-04T17:35:26.475808Z" }]);

  // Another file at the path.
  writeFileSync(join(root, "vendor", "six-1.17.0-py2.py3-none-any.whl"), "not the wheel");
  const other = createHash("sha256").update("not the wheel").digest("hex");
  const f = fake();
  const swapped = await run([uv(root, "uv.lock")], f, { root });
  assert.deepEqual(only(swapped.findings, "WS-SK-002").map((x) => x.message), [
    `Cannot verify soak time for PyPI package six==1.17.0: local archive not present in the reviewed tree as locked: "vendor/six-1.17.0-py2.py3-none-any.whl": the file's sha256 is ${other}, not the ${SIX_WHL} the lock records, so the install would not use the file the lock names`,
  ]);
  assert.ok(!f.asked.includes("six"), "checked without the index");
  writeFileSync(join(root, "vendor", "six-1.17.0-py2.py3-none-any.whl"), SIX_WHEEL_BYTES);

  // Missing, outside the root, or untracked.
  const at = (path: string): string => edit(pathLock, 'source = { path = "vendor/six-1.17.0-py2.py3-none-any.whl" }', `source = { path = "${path}" }`);
  for (const [path, why] of [
    ["vendor/gone/six-1.17.0-py2.py3-none-any.whl", '"vendor/gone/six-1.17.0-py2.py3-none-any.whl": not present in the scanned tree (ENOENT)'],
    ["../six-1.17.0-py2.py3-none-any.whl", '"../six-1.17.0-py2.py3-none-any.whl": not a normalised path (it has an empty, "." or ".." segment)'],
    ["/tmp/six-1.17.0-py2.py3-none-any.whl", '"/tmp/six-1.17.0-py2.py3-none-any.whl": not a relative path'],
  ]) {
    const r = await run([uv(root, "uv.lock", at(path!))], fake(), { root });
    assert.deepEqual(only(r.findings, "WS-SK-002").map((x) => x.message), [`Cannot verify soak time for PyPI package six==1.17.0: local archive not present in the reviewed tree as locked: ${why}`], path);
  }
  assert.deepEqual(checkLocalArchive("vendor/six-1.17.0-py2.py3-none-any.whl", SIX_WHL, "", { root, git: new Set(["uv.lock"]) }), { ok: false, problem: '"vendor/six-1.17.0-py2.py3-none-any.whl": not tracked by git, so it is not part of the reviewed tree' });

  // A path archive whose file is not an index file: the hash is the local file's, and the index has no such file.
  const bz2 = "a local archive, not on any index";
  writeFileSync(join(root, "vendor", "six-1.17.0.tar.bz2"), bz2);
  const bzHash = createHash("sha256").update(bz2).digest("hex");
  const bzLock = edit(at("vendor/six-1.17.0.tar.bz2"), `{ filename = "six-1.17.0-py2.py3-none-any.whl", hash = "sha256:${SIX_WHL}" }`, `{ filename = "six-1.17.0.tar.bz2", hash = "sha256:${bzHash}" }`);
  const b = await run([uv(root, "uv.lock", bzLock)], fake(), { root });
  assert.deepEqual(only(b.findings, "WS-SK-002").map((x) => x.message), [`Cannot verify soak time for PyPI package six==1.17.0: six-1.17.0.tar.bz2: not on the index (deleted or quarantined), or never published`]);

  // pylock: an archive by path, the same rules.
  const py = copied("forged/pylock-local-sources.toml");
  const pr = await run([py.lock], fake(), { root: py.root });
  assert.ok(!only(pr.findings, "WS-SK-002").some((x) => x.message.includes("PyPI package six==1.17.0")), "the archive at vendor/ binds to six 1.17.0's wheel");
  assert.ok(pr.evidence.some((e) => e.name === "six" && e.status === "ok"));
});

test("soak (PyPI): one identity found with different send verdicts is checked for each; with the same verdict, once", async () => {
  const root = tree({});
  const text = `--require-hashes\nsix==1.17.0 --hash=sha256:${SIX_WHL}\n`;
  const confirmed = requirements(root, "b.txt", text, true);
  const unconfirmed = requirements(root, "a.txt", text, false);
  assert.equal(identityDigest(confirmed.packages[0]!), identityDigest(unconfirmed.packages[0]!), "one identity");
  for (const order of [[confirmed, unconfirmed], [unconfirmed, confirmed]]) {
    const f = fake();
    const r = await run(order, f, { root });
    assert.deepEqual(r.findings.map((x) => [x.ruleId, x.file]), [["WS-SK-002", "a.txt"]], "a.txt's index settings were not confirmed, whatever b.txt's were");
    assert.deepEqual(r.evidence.map((e) => e.status).sort(), ["ok", "unverifiable"]);
    assert.deepEqual(f.asked, ["six"]);
  }
  const again = requirements(root, "c.txt", text, true);
  const f = fake();
  const twice = await run([confirmed, again], f, { root });
  assert.deepEqual([twice.findings, twice.evidence.length, f.asked], [[], 1, ["six"]]);
});

test("soak (PyPI): a reader problem is keyed on its content, not its position: a package or line added above keeps the key", async () => {
  assert.equal(problemContent("[[package]] #12 (foo 1.0) wheel #3 (foo-1.0-py3-none-any.whl): no sha256 hash"), "[[package]] # (foo 1.0) wheel # (foo-1.0-py3-none-any.whl): no sha256 hash");
  assert.equal(problemContent("requirements.txt:34: six==1.0 has no --hash=sha256; fix it"), "requirements.txt: six==1.0 has no --hash=sha256; fix it");
  assert.equal(problemContent("it is not valid TOML (line 4, column 2: Unexpected character)"), "it is not valid TOML (line, column: Unexpected character)");
  assert.equal(problemContent("git+https://github.com/benjaminp/six#2b9bd1ba1ee9"), "git+https://github.com/benjaminp/six#2b9bd1ba1ee9");

  const lockKey = (r: Awaited<ReturnType<typeof run>>): [string, string] => {
    const x = r.findings.filter((y) => y.key.startsWith("pypi:lockfile "));
    assert.equal(x.length, 1);
    return [x[0]!.key, x[0]!.message];
  };
  const text = readFileSync(join(LOCKS, "forged", "uv-unhashed-wheel.lock"), "utf8");
  const moved = edit(text, '[[package]]\nname = "idna"', '[[package]]\nname = "aaa"\nversion = "1.0"\nsource = { registry = "https://pypi.org/simple" }\nsdist = { url = "https://files.pythonhosted.org/packages/aaa-1.0.tar.gz", hash = "sha256:' + "0".repeat(64) + '" }\n\n[[package]]\nname = "idna"');
  const root = tree({});
  const [k1, m1] = lockKey(await run([uv(root, "uv.lock", text)], fake(), { root }));
  const [k2, m2] = lockKey(await run([uv(root, "uv.lock", moved)], fake(), { root }));
  assert.match(m1, /\[\[package\]\] #3 \(six 1\.17\.0\)/);
  assert.match(m2, /\[\[package\]\] #4 \(six 1\.17\.0\)/);
  assert.equal(k2, k1);
  const [r1, n1] = lockKey(await run([requirements(root, "requirements.txt", "--require-hashes\nsix==1.17.0\n")], fake(), { root }));
  const [r2, n2] = lockKey(await run([requirements(root, "requirements.txt", "--require-hashes\n\n# a comment\nsix==1.17.0\n")], fake(), { root }));
  assert.notEqual(n1, n2);
  assert.equal(r2, r1);
  const [r3] = lockKey(await run([requirements(root, "requirements.txt", "--require-hashes\nidna==3.20\n")], fake(), { root }));
  assert.notEqual(r3, r1, "another problem, another key");
});

/* ---- WS-SK-005 ---- */

test("soak (PyPI): WS-SK-005 for a local member the install builds, keyed on its build inputs", async () => {
  const root = tree({ "pyproject.toml": '[project]\nname = "app"\nversion = "0.1.0"\n', "packages/member/pyproject.toml": PYPROJECT });
  const text = UV_HEAD + localPkg("app", "virtual", ".") + localPkg("member", "editable", "packages/member");
  const r = await run([uv(root, "uv.lock", text)], fake(), { root });
  const b = readLocalBuild(join(root, "packages", "member"), root);
  assert.deepEqual(r.findings.map((x) => [x.ruleId, x.severity, x.file, x.key, x.message]), [
    [
      "WS-SK-005",
      "medium",
      "uv.lock",
      `pypi:build packages/member ${b.digest}`,
      'member (editable source packages/member) is built from source at install time, and its build requirements ("hatchling==1.27.0") are resolved when it is built, not pinned by uv.lock. To avoid the build: `uv sync --locked --no-install-project` for the root project, `--no-install-workspace` or `--no-install-package <name>` for members, or `[tool.uv] package = false` if it need not be installed. Otherwise pin its build requirements with ==-pinned `build-constraint-dependencies`.',
    ],
  ]);
  // The key follows the build inputs: requires, a setup.py, backend-path files; not other files.
  const keyNow = (): string => readLocalBuild(join(root, "packages", "member"), root).digest;
  const k0 = keyNow();
  writeFileSync(join(root, "packages", "member", "README.md"), "docs");
  assert.equal(keyNow(), k0, "an unrelated file");
  writeFileSync(join(root, "packages", "member", "pyproject.toml"), PYPROJECT.replace("hatchling==1.27.0", "hatchling==1.28.0"));
  const k1 = keyNow();
  assert.notEqual(k1, k0, "requires");
  writeFileSync(join(root, "packages", "member", "setup.py"), "import setuptools\n");
  const k2 = keyNow();
  assert.notEqual(k2, k1, "setup.py");
  writeFileSync(join(root, "packages", "member", "pyproject.toml"), PYPROJECT.replace('build-backend = "hatchling.build"', 'build-backend = "backend"\nbackend-path = ["_build"]'));
  mkdirSync(join(root, "packages", "member", "_build"));
  writeFileSync(join(root, "packages", "member", "_build", "backend.py"), "def build_wheel(): ...\n");
  const k3 = keyNow();
  writeFileSync(join(root, "packages", "member", "_build", "backend.py"), "def build_wheel(): evil()\n");
  assert.notEqual(keyNow(), k3, "a backend-path file");

  // No [build-system]: the default setuptools backend builds it.
  writeFileSync(join(root, "packages", "member", "pyproject.toml"), '[project]\nname = "member"\nversion = "0.1.0"\n');
  const d = await run([uv(root, "uv.lock")], fake(), { root });
  assert.match(d.findings[0]!.message, /its build requirements \("setuptools>=40\.8\.0"; no \[build-system\], so the default setuptools backend\) are resolved/);
  assert.deepEqual(readLocalBuild(join(root, "packages", "member")).requires, DEFAULT_REQUIRES);
  // An unreadable pyproject.toml is still a build, with the requirements unknown.
  writeFileSync(join(root, "packages", "member", "pyproject.toml"), "[build-system\n");
  const bad = await run([uv(root, "uv.lock")], fake(), { root });
  assert.match(bad.findings[0]!.message, /its build requirements are unknown \(pyproject\.toml: it is not valid TOML/);

  // A pylock directory entry is built by pip and uv too.
  const pyLocal = copied("forged/pylock-local-sources.toml");
  const py = await run([pyLocal.lock], fake(), { root: pyLocal.root });
  assert.deepEqual(only(py.findings, "WS-SK-005").map((x) => x.message.slice(0, x.message.indexOf(" are resolved"))), ['localdir (directory source libs/localdir) is built from source at install time, and its build requirements ("hatchling")']);
  assert.match(only(py.findings, "WS-SK-005")[0]!.message, /Pin its build requirements with ==-pinned build constraints \(pip `--build-constraint`, uv `build-constraint-dependencies`\), or install it separately\.$/);
});

test("soak (PyPI): a local build's key covers each build file whole, and leaves out only what is listed as not deciding the build", () => {
  assert.equal(BUILD_DIGEST_VERSION, "wormsign-pypi-build-4");
  const dir = mkdtempSync(join(tmpdir(), "ws-build-key-"));
  const put = (rel: string, text: string): void => {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  };
  const key = (): string => readLocalBuild(dir).digest;
  /** Does going from `a` to `b` (pyproject.toml texts) change the key? */
  const changes = (a: string, b: string): boolean => {
    put("pyproject.toml", a);
    const before = key();
    put("pyproject.toml", b);
    return key() !== before;
  };
  const toml = (o: { backend?: string | null; backendPath?: string; project?: string; rest?: string }): string =>
    `[project]\nname = "app"\n${o.project ?? 'dependencies = ["six"]'}\n\n[build-system]\nrequires = ["x==1"]\n${o.backend === null ? "" : `build-backend = "${o.backend ?? "inhouse.api"}"\n`}${o.backendPath ?? ""}${o.rest ?? ""}`;

  // [project] metadata never decides a build, whatever the backend.
  const metadata: [string, string, string][] = [
    ["version", '"0.1.0"', '"0.2.0"'], ["description", '"a"', '"b"'], ["readme", '"README.md"', '"README.rst"'], ["authors", '[{ name = "a" }]', '[{ name = "b" }]'],
    ["maintainers", '[{ name = "a" }]', '[{ name = "b" }]'], ["urls", '{ Home = "https://a.example" }', '{ Home = "https://b.example" }'], ["classifiers", '["A"]', '["B"]'],
    ["keywords", '["a"]', '["b"]'], ["license", '"MIT"', '"Apache-2.0"'], ["license-files", '["LICENSE"]', '["COPYING"]'],
  ];
  for (const [k, a, b] of metadata) assert.equal(changes(toml({ project: `${k} = ${a}` }), toml({ project: `${k} = ${b}` })), false, k);
  // The rest of [project] and [dependency-groups] count under a backend not known to leave them alone, or none named.
  for (const backend of ["inhouse.api", null, "setuptools.build_meta:__legacy__x", "hatchling"]) {
    assert.equal(changes(toml({ backend }), toml({ backend, project: 'dependencies = ["six", "evil"]' })), true, `${backend} dependencies`);
    assert.equal(changes(toml({ backend }), toml({ backend, project: 'dependencies = ["six"]\noptional-dependencies = { x = ["evil"] }' })), true, `${backend} extras`);
    assert.equal(changes(toml({ backend, rest: '\n[dependency-groups]\ndev = ["a"]\n' }), toml({ backend, rest: '\n[dependency-groups]\ndev = ["evil"]\n' })), true, `${backend} groups`);
  }
  // ... and not under a backend whose build requirements never come from them.
  const known = ["setuptools.build_meta", "setuptools.build_meta:__legacy__", "flit_core.buildapi", "pdm.backend", "poetry.core.masonry.api", "maturin", "scikit_build_core.build", "mesonpy", "uv_build", "hatchling.build"];
  for (const backend of known) {
    assert.equal(changes(toml({ backend }), toml({ backend, project: 'dependencies = ["six", "evil"]' })), false, backend);
    assert.equal(changes(toml({ backend, rest: '\n[dependency-groups]\ndev = ["a"]\n' }), toml({ backend, rest: '\n[dependency-groups]\ndev = ["evil"]\n' })), false, `${backend} groups`);
    // An in-tree backend on backend-path can take a known backend's name.
    const bp = 'backend-path = ["_build"]\n';
    assert.equal(changes(toml({ backend, backendPath: bp }), toml({ backend, backendPath: bp, project: 'dependencies = ["six", "evil"]' })), true, `${backend} with backend-path`);
  }
  // hatchling installs [project] dependencies or features for the build when any hatch table asks it to.
  for (const rest of ["\n[tool.hatch.build]\nrequire-runtime-dependencies = true\n", "\n[tool.hatch.build.targets.wheel]\nrequire-runtime-dependencies = false\n", '\n[tool.hatch.build.targets.sdist]\nrequire-runtime-features = ["x"]\n']) {
    assert.equal(changes(toml({ backend: "hatchling.build", rest }), toml({ backend: "hatchling.build", rest, project: 'dependencies = ["six", "evil"]' })), true, rest);
    assert.equal(changes(toml({ backend: "flit_core.buildapi", rest }), toml({ backend: "flit_core.buildapi", rest, project: 'dependencies = ["six", "evil"]' })), false, `flit_core ignores ${rest}`);
  }
  // Linters, formatters, type checkers, test runners: never read for a build. Every other tool table counts.
  for (const tool of ["ruff", "black", "isort", "mypy", "pyright", "pytest", "coverage", "pylint", "flake8", "codespell"]) {
    assert.equal(changes(toml({ rest: `\n[tool.${tool}]\nx = 1\n` }), toml({ rest: `\n[tool.${tool}]\nx = 2\n` })), false, tool);
  }
  for (const tool of ["hatch", "setuptools", "uv", "pdm", "poetry", "scikit-build", "maturin", "meson-python", "flit", "cibuildwheel", "setuptools_scm", "tox"]) {
    assert.equal(changes(toml({ rest: `\n[tool.${tool}]\nx = 1\n` }), toml({ rest: `\n[tool.${tool}]\nx = 2\n` })), true, tool);
  }
  assert.equal(changes(toml({}), toml({ rest: "\n[other]\nx = 1\n" })), true, "a table no one is known to ignore");
  // A [tool] or [project] left with nothing that counts is dropped: the first linter table adds nothing.
  assert.equal(changes(toml({}), toml({ rest: "\n[tool.ruff]\nx = 1\n" })), false, "the first [tool] table, a linter's");
  assert.equal(changes(toml({ project: 'version = "1"' }).replace('name = "app"\n', ""), toml({ project: 'version = "2"\ndescription = "d"' }).replace('name = "app"\n', "")), false, "a [project] of metadata only");
  // An unparseable pyproject.toml is keyed on its bytes.
  assert.equal(changes("[build-system\n", "[build-system\n# x\n"), true);

  // Files digested whole: setup.cfg, uv.toml, every .py file directly in the project (any case), a build hook's file.
  put("pyproject.toml", toml({ backend: "hatchling.build", rest: '\n[tool.hatch.build.hooks.custom]\npath = "tools/hook.py"\n[tool.hatch.metadata.hooks.custom]\npath = "tools/meta.py"\n[tool.hatch.build.targets.custom]\npath = "tools/builder.py"\n[tool.hatch.version]\npath = "src/app/about.py"\n[tool.pdm.build]\ncustom-hook = "tools/pdm_hook.py"\n[tool.poetry.build]\nscript = "tools/poetry_build.py"\n' }));
  const edits: [string, boolean][] = [
    ["setup.cfg", true], ["uv.toml", true], ["hatch.toml", true], ["setup.py", true], ["hatch_build.py", true], ["pdm_build.py", true], ["build.py", true],
    ["tools/hook.py", true], ["tools/meta.py", true], ["tools/builder.py", true], ["tools/pdm_hook.py", true], ["tools/poetry_build.py", true],
    // A hook outside the top directory may import its neighbours: the .py files beside it count, not deeper ones.
    ["tools/other.py", true], ["tools/sub/deeper.py", false],
    ["src/app/about.py", false], ["src/app/__init__.py", false], ["README.md", false], ["docs/conf.py", false],
    ["app.py", false], ["noxfile.py", false], ["conftest.py", false],
  ];
  for (const [rel, counts] of edits) {
    put(rel, "# one\n");
    const before = key();
    put(rel, "# two\n");
    assert.equal(key() !== before, counts, rel);
  }
  // A Poetry `build` script given as a string; a hook file reached through a symlink or outside the project is
  // keyed on what it is, not followed.
  put("pyproject.toml", toml({ backend: "poetry.core.masonry.api", rest: '\n[tool.poetry]\nbuild = "tools/legacy.py"\n' }));
  put("tools/legacy.py", "# one\n");
  const legacy = key();
  put("tools/legacy.py", "# two\n");
  assert.notEqual(key(), legacy, "tools/legacy.py");
  mkdirSync(join(dir, "real"));
  writeFileSync(join(dir, "real", "hook.py"), "# one\n");
  symlinkSync("real", join(dir, "linked"));
  put("pyproject.toml", toml({ backend: "hatchling.build", rest: '\n[tool.hatch.build.hooks.custom]\npath = "linked/hook.py"\n[tool.hatch.build.hooks.other]\npath = "../outside.py"\n' }));
  const linked = key();
  // A link inside the project is followed (and keyed by its link text) to the file it opens: an edit there counts.
  writeFileSync(join(dir, "real", "hook.py"), "# two\n");
  const followed = key();
  assert.notEqual(followed, linked, "the file a link inside the project leads to");
  unlinkSync(join(dir, "linked"));
  symlinkSync("elsewhere", join(dir, "linked"));
  assert.notEqual(key(), followed, "another target");
  // A link out of the project is never followed: what it leads to does not count, its text does.
  unlinkSync(join(dir, "linked"));
  const outside = mkdtempSync(join(tmpdir(), "ws-build-key-outside-"));
  writeFileSync(join(outside, "hook.py"), "# one\n");
  symlinkSync(outside, join(dir, "linked"));
  const out = key();
  writeFileSync(join(outside, "hook.py"), "# two\n");
  assert.equal(key(), out, "a link out of the project is not followed");

  // hatch.toml: require-runtime-dependencies there (or a hatch.toml that cannot be read) keeps [project]; its hook
  // paths count.
  const fresh = mkdtempSync(join(tmpdir(), "ws-build-key-hatch-"));
  const key2 = (): string => readLocalBuild(fresh).digest;
  const deps = (d: string): string => toml({ backend: "hatchling.build", project: `dependencies = ${d}` });
  const depsChange = (hatchToml: string | undefined): boolean => {
    if (hatchToml === undefined) unlinkSync(join(fresh, "hatch.toml"));
    else writeFileSync(join(fresh, "hatch.toml"), hatchToml);
    writeFileSync(join(fresh, "pyproject.toml"), deps('["six"]'));
    const before = key2();
    writeFileSync(join(fresh, "pyproject.toml"), deps('["six", "evil"]'));
    return key2() !== before;
  };
  assert.equal(depsChange("[build]\ndirectory = \"dist\"\n"), false, "hatch.toml without the runtime keys");
  assert.equal(depsChange("[build.targets.wheel]\nrequire-runtime-dependencies = true\n"), true, "require-runtime-dependencies in hatch.toml");
  assert.equal(depsChange('[build.targets.wheel]\nrequire-runtime-features = ["x"]\n'), true, "require-runtime-features in hatch.toml");
  assert.equal(depsChange("[build\n"), true, "a hatch.toml that is not TOML");
  writeFileSync(join(fresh, "hatch.toml"), '[build.hooks.custom]\npath = "hooks/h.py"\n[version]\npath = "src/v.py"\n');
  mkdirSync(join(fresh, "hooks"));
  mkdirSync(join(fresh, "src"));
  for (const [rel, counts] of [["hooks/h.py", true], ["src/v.py", false]] as const) {
    writeFileSync(join(fresh, rel), "# one\n");
    const before = key2();
    writeFileSync(join(fresh, rel), "# two\n");
    assert.equal(key2() !== before, counts, `hatch.toml names ${rel}`);
  }

  // A uv workspace root lends its [tool.uv] and uv.toml to a member's build, not its other tables.
  const ws = mkdtempSync(join(tmpdir(), "ws-build-key-root-"));
  mkdirSync(join(ws, "m"));
  writeFileSync(join(ws, "m", "pyproject.toml"), toml({ backend: "hatchling.build" }));
  const member = (): string => readLocalBuild(join(ws, "m"), ws).digest;
  const rootToml = (version: string, uv: string): string => `[project]\nname = "root"\nversion = "${version}"\n\n[tool.uv]\n${uv}`;
  writeFileSync(join(ws, "pyproject.toml"), rootToml("1", "package = false\n"));
  const m0 = member();
  assert.notEqual(m0, readLocalBuild(join(ws, "m")).digest, "with a workspace root, its settings are part of the key");
  writeFileSync(join(ws, "pyproject.toml"), rootToml("2", "package = false\n"));
  assert.equal(member(), m0, "the root's version");
  writeFileSync(join(ws, "pyproject.toml"), rootToml("2", "package = false\nbuild-constraint-dependencies = [\"x==1\"]\n"));
  const m1 = member();
  assert.notEqual(m1, m0, "the root's [tool.uv]");
  writeFileSync(join(ws, "uv.toml"), "no-build-isolation = true\n");
  assert.notEqual(member(), m1, "the root's uv.toml");
});

test("soak (PyPI): a build file's digest reads each CRLF as LF, keeps a lone CR, and leaves a file with a NUL byte as it is", () => {
  assert.equal(fileDigest(Buffer.from("[metadata]\r\nname = app\r\n")), fileDigest(Buffer.from("[metadata]\nname = app\n")), "CRLF as git for Windows checks it out");
  assert.notEqual(fileDigest(Buffer.from("[metadata]\rname = app\r")), fileDigest(Buffer.from("[metadata]\nname = app\n")), "a lone CR");
  assert.notEqual(fileDigest(Buffer.from("x\r\n\0")), fileDigest(Buffer.from("x\n\0")), "binary: git converts no line endings in it");
  assert.notEqual(fileDigest(Buffer.from("a\r\n")), fileDigest(Buffer.from("b\n")));
  // Through readLocalBuild: a setup.cfg with CRLF keys as the LF one, and an edit still changes the key.
  const dir = mkdtempSync(join(tmpdir(), "ws-build-crlf-"));
  writeFileSync(join(dir, "setup.cfg"), "[metadata]\nname = app\n");
  const lf = readLocalBuild(dir).digest;
  writeFileSync(join(dir, "setup.cfg"), "[metadata]\r\nname = app\r\n");
  assert.equal(readLocalBuild(dir).digest, lf);
  writeFileSync(join(dir, "setup.cfg"), "[metadata]\r\nname = evil\r\n");
  assert.notEqual(readLocalBuild(dir).digest, lf);
});

test("soak (PyPI): the build digest reads the disk and a git tree alike, and each reader refuses what it cannot read plainly", () => {
  const repo = mkdtempSync(join(tmpdir(), "ws-build-readers-"));
  const put = (rel: string, data: string | Buffer): void => {
    mkdirSync(dirname(join(repo, rel)), { recursive: true });
    writeFileSync(join(repo, rel), data);
  };
  put("pyproject.toml", '[project]\nname = "app"\n\n[build-system]\nrequires = ["x==1"]\nbuild-backend = "inhouse.api"\nbackend-path = ["bp"]\n\n[tool.hatch.build.hooks.custom]\npath = "tools/hook.py"\n');
  put("tools/hook.py", "# hook\n");
  put("tools/helper.py", Buffer.from("# caf\xe9\n", "latin1"));
  put("bp/x.py", "def build_wheel(): ...\n");
  symlinkSync("x.py", join(repo, "bp", "alias.py"));
  put("cfg/common.cfg", "[options]\nsetup_requires = wheel\n");
  symlinkSync("cfg/common.cfg", join(repo, "setup.cfg"));
  put("hatch_build.py", Buffer.from([0xff, 0xfe, 0x00, 0x0a]));
  put("big.txt", "0123456789abcdef");
  const git = (...args: string[]): void => void execFileSync("git", ["-c", "user.email=v@v.invalid", "-c", "user.name=v", "-c", "commit.gpgsign=false", ...args], { cwd: repo, stdio: "pipe" });
  git("init", "-q", "-b", "main");
  git("add", "-A");
  git("commit", "-qm", "c");
  const tree = gitTree(repo, "HEAD");
  const base = { read: (rel: string) => tree.read(`./${rel}`), list: () => tree.list(), regularFile: (rel: string) => tree.regularFile?.(rel) === true, entry: (rel: string) => tree.entry?.(rel) };
  const fromGit = localBuild(gitBuildReader(base, ""));
  const fromDisk = readLocalBuild(repo);
  assert.equal(fromGit.digest, fromDisk.digest, "identical content, symlinks and non-UTF-8 bytes included, digests alike");
  assert.deepEqual([fromGit.unreadable, fromDisk.unreadable], [false, false]);
  // A file over the cap is a problem, on either side.
  assert.equal(tree.entry?.("big.txt", 10)?.kind, "problem");
  assert.equal(tree.entry?.("big.txt")?.kind, "file");
  assert.equal(fsBuildReader(repo, 10).entry("big.txt").kind, "problem");
  assert.equal(fsBuildReader(repo).entry("big.txt").kind, "file");
  // A path through a symlink is a problem, never followed, on either side.
  symlinkSync("cfg", join(repo, "cfglink"));
  git("add", "-A");
  git("commit", "-qm", "link");
  const linked = gitTree(repo, "HEAD");
  assert.deepEqual(fsBuildReader(repo).entry("cfglink/common.cfg"), { kind: "problem", why: "cfglink is a symlink on the way" });
  assert.deepEqual(gitBuildReader({ ...base, entry: (rel: string) => linked.entry?.(rel) }, "").entry("cfglink/common.cfg"), { kind: "problem", why: "cfglink is a symlink on the way" });
});

test("soak --base (PyPI): a base build with an entry git cannot show plainly is new, though its digest is the head's", () => {
  const text = UV_HEAD + localPkg("app", "editable", ".");
  const lock = uv(tree({}), "uv.lock", text);
  // A setup.py the base holds under a name another entry folds like: both sides record the same marker, so only the
  // base's unreadable flag tells the build apart.
  const files: Record<string, Buffer> = { "uv.lock": Buffer.from(text), "pyproject.toml": Buffer.from('[project]\nname = "app"\nversion = "0.1.0"\n') };
  const base = (clash: boolean) => ({
    read: (rel: string) => files[rel]?.toString("utf8"),
    list: () => Object.keys(files),
    regularFile: (rel: string) => rel in files,
    entry: (rel: string): TreeEntry | undefined =>
      rel === "setup.py" && clash ? { kind: "problem", why: "another entry's name folds like this one" } : files[rel] !== undefined ? { kind: "file", bytes: files[rel]! } : undefined,
  });
  const raised = (b: ReturnType<typeof base>): string[] => {
    const build = localBuild(gitBuildReader(b, ""), gitBuildReader(b, ""));
    const finding = localBuildFinding({ name: "app", dir: "", lockFile: "uv.lock", lockKind: "uv", sourceKind: "editable" }, build);
    return raiseNewBuilds([finding], b, "HEAD~1", { locks: [lock], pypiIndex: INDEX }).map((f) => f.severity);
  };
  assert.equal(localBuild(gitBuildReader(base(true), "")).unreadable, true);
  assert.deepEqual(raised(base(true)), ["high"]);
  // The control: the same project, every entry plain, is the base's.
  assert.deepEqual(raised(base(false)), ["medium"]);
});

test("soak (PyPI): WS-SK-005 for a package locked only as an sdist (uv.lock, pylock, requirements after binding, path archives)", async () => {
  const root = tree({});
  const sdistOnly = edit(SIMPLE_UV, `wheels = [\n${SIX_WHEEL_LINE}]\n`, "");
  const lock = uv(root, "uv.lock", sdistOnly);
  const six = pkgOf(lock, "six");
  const r = await run([lock], fake(), { root });
  assert.deepEqual(r.findings.map((x) => [x.ruleId, x.severity, x.key, x.message]), [
    [
      "WS-SK-005",
      "medium",
      `pypi:six@1.17.0 sdist-only ${identityDigest(six)}`,
      "six==1.17.0 is locked only as an sdist (six-1.17.0.tar.gz), so installing it runs its build backend, whose build requirements are resolved at install time, not pinned by the lock. Prefer a version with wheels for the platforms you install on, or pin the build requirements with ==-pinned build constraints (uv `build-constraint-dependencies`, pip `--build-constraint`).",
    ],
  ]);
  // Also when the index cannot bind it: what the lock says is enough.
  const gone = await run([lock], fake({ six: null }), { root });
  assert.deepEqual(gone.findings.map((x) => x.ruleId).sort(), ["WS-SK-002", "WS-SK-005"]);

  // The index's answer does not matter: quarantined, or a path sdist that is not an index file, is still a build.
  const quarantined = page("six");
  quarantined["project-status"] = { status: "quarantined" };
  quarantined.files = [];
  assert.deepEqual((await run([lock], fake({ six: quarantined }), { root })).findings.map((x) => x.ruleId).sort(), ["WS-SK-002", "WS-SK-005"]);
  const sdistBytes = "an sdist built here";
  writeFileSync(join(root, "six-1.17.0.tar.gz"), sdistBytes);
  const pathSdist = `${UV_HEAD}[[package]]\nname = "six"\nversion = "1.17.0"\nsource = { path = "six-1.17.0.tar.gz" }\nsdist = { hash = "sha256:${createHash("sha256").update(sdistBytes).digest("hex")}" }\n`;
  const ps = await run([uv(root, "uv.lock", pathSdist)], fake(), { root });
  assert.deepEqual(ps.findings.map((x) => [x.ruleId, x.message.slice(0, 76)]), [
    ["WS-SK-002", "Cannot verify soak time for PyPI package six==1.17.0: six-1.17.0.tar.gz: not"],
    ["WS-SK-005", "six==1.17.0 is locked only as an sdist (six-1.17.0.tar.gz), so installing it"],
  ]);

  // A requirements entry is known to be an sdist only once its hash is bound.
  const req = await run([requirements(root, "requirements.txt", `--require-hashes\nsix==1.17.0 --hash=sha256:${SIX_SDIST}\nidna==3.20 --hash=sha256:${IDNA_WHL}\n`)], fake(), { root, now: new Date("2026-10-08T00:00:00Z") });
  assert.deepEqual(req.findings.map((x) => [x.ruleId, x.line, x.key.split(" ").slice(0, 2).join(" ")]), [["WS-SK-005", 2, "pypi:six@1.17.0 sdist-only"]]);

  // A pylock with only an sdist; and one with a wheel too is not reported.
  const pyText = readFileSync(join(LOCKS, "uv-0.12.21", "simple", "pylock.toml"), "utf8");
  const sixWheel = pyText.split("\n").find((l) => l.startsWith("wheels = ") && l.includes("six-1.17.0"))!;
  const py = await run([pylock(root, "pylock.toml", edit(pyText, `${sixWheel}\n`, ""))], fake(), { root });
  assert.deepEqual(py.findings.map((x) => x.key.split(" ").slice(0, 2).join(" ")), ["pypi:six@1.17.0 sdist-only"]);
  assert.deepEqual((await run([pylock(root, "pylock.toml", pyText)], fake(), { root })).findings, []);
});

/* ---- OSV ---- */

test("soak (PyPI): OSV is asked about served names only, on pypi.org only; a hit is WS-OS-001 with a pypi: key", async () => {
  const lock = uv(LOCKS, "uv-0.12.21/simple/uv.lock");
  const f = fake({}, { "six@1.17.0": ["MAL-2099-1"] });
  const session = newOsvSession();
  const r = await run([lock], f, { root: LOCKS, osv: true, osvSession: session });
  assert.deepEqual(only(r.findings, "WS-OS-001").map((x) => [x.key, x.file, x.message]), [["pypi:six@1.17.0 MAL-2099-1", "uv-0.12.21/simple/uv.lock", "six@1.17.0 is a malicious package version according to OSV record MAL-2099-1"]]);
  assert.deepEqual(r.evidence.map((e) => [e.name, e.osv]), [["idna", []], ["six", ["MAL-2099-1"]]]);
  assert.deepEqual(f.osv.sort(), ["idna@3.20", "six@1.17.0"]);
  const off = fake();
  const none = await run([lock], off, { root: LOCKS });
  assert.deepEqual([off.osv, none.evidence.map((e) => e.osv)], [[], [undefined, undefined]], "osv not asked unless opts.osv");

  // Another index: names are looked up there, but never sent to OSV.
  const CORP = "https://pypi.corp.example/simple/";
  const corpRoot = tree({ "uv.lock": SIMPLE_UV });
  const corpLock = fromUvLock("uv.lock", readUvLock(join(corpRoot, "uv.lock")), { pypiIndex: CORP });
  const pages = { six: page("six"), idna: page("idna") };
  const c = fake(pages, {}, CORP);
  const corpText = (await run([{ ...corpLock, packages: corpLock.packages.map((p) => (p.source.kind === "registry" ? { ...p, source: { kind: "registry" as const, value: "https://pypi.corp.example/simple" }, lockIndex: "https://pypi.corp.example/simple", sendable: true, files: p.files.map((x) => ({ ...x, locator: { filename: x.locator.filename! } })) } : p)) }], c, { root: corpRoot, pypiIndex: CORP, osv: true }));
  assert.deepEqual(brief(only(corpText.findings, "WS-OS-900")), ["WS-OS-900 - pypi:registry https://pypi.corp.example/simple/"]);
  assert.deepEqual(only(corpText.findings, "WS-SK-002"), []);
  assert.deepEqual(c.osv, []);
  assert.deepEqual(c.asked.sort(), ["idna", "six"]);
  assert.ok(corpText.notes.includes("4 PyPI file(s) of 2 version(s) checked against https://pypi.corp.example/simple/"));

  // Credentials are never shown, and never sent.
  const creds = fake();
  const withCreds = await run([lock], creds, { root: LOCKS, pypiIndex: "https://user:token@pypi.org/simple/" });
  assert.deepEqual(creds.asked, []);
  assert.ok(withCreds.notes[0]!.endsWith("checked against https://pypi.org/simple/"));
  assert.ok(withCreds.findings.every((x) => !x.message.includes("token")));
});

test("soak (PyPI): nothing is thrown; whatever goes wrong is a finding", async () => {
  const lock = uv(LOCKS, "uv-0.12.21/simple/uv.lock");
  const broken = (async () => "not a response") as unknown as typeof fetch;
  const r = await checkPythonLocks([lock], { minAgeMs: WEEK, now: NOW, pypiIndex: INDEX, root: LOCKS, git: "no-work-tree", fetchImpl: broken });
  assert.deepEqual(only(r.findings, "WS-SK-002").map((x) => x.message), ["Cannot verify soak time for PyPI package idna==3.20: the request to the index returned something that is not an HTTP response", "Cannot verify soak time for PyPI package six==1.17.0: the request to the index returned something that is not an HTTP response"]);
  const odd = await checkPythonLocks([{ kind: "uv", file: "uv.lock", packages: [{ name: "x", version: "1", source: { kind: "registry", value: "https://pypi.org/simple" }, files: [{ locator: {}, hashes: [{ alg: "sha256", digest: "0".repeat(64) }] }], sendable: true }], problems: [] }], { minAgeMs: WEEK, now: NOW, pypiIndex: "::", root: "/nonexistent", git: "no-work-tree", fetchImpl: broken });
  assert.deepEqual(odd.findings.map((x) => x.message), ["Cannot verify soak time for PyPI package x==1: it is locked from https://pypi.org/simple, not --pypi-index :: (wormsign checks one index (--pypi-index) and sends no credentials. If the entry is trusted, baseline it with a justification: the baseline key pins its name, version, source and every file hash, so any change to them fails again)"]);
  const internal = await checkPythonLocks([{ kind: "uv", file: "uv.lock", packages: [null as unknown as PyPackage], problems: [] }], { minAgeMs: WEEK, now: NOW, pypiIndex: INDEX, root: LOCKS, git: "no-work-tree" });
  assert.deepEqual(internal.findings.map((x) => [x.ruleId, x.key]), [["WS-SK-002", "pypi:internal-error"]]);
  assert.deepEqual(await checkPythonLocks([], { minAgeMs: WEEK, now: NOW, pypiIndex: INDEX, root: LOCKS, git: "no-work-tree" }), { findings: [], evidence: [], notes: [] });
});
