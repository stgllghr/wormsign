/**
 * Python discovery (src/python/discover.ts, scripts.ts, manifest.ts) over the shared walker (src/walk.ts): every
 * discovery and walker case that belongs to discovery.
 *
 * Repositories are built in temporary directories from real tool output: the uv 0.10.9 and 0.12.21 locks of
 * test/fixtures/python/locks (the readers' fixtures), and test/fixtures/python/repos/scripts (an extensionless script and a CRLF .txt
 * script, each with the lock uv 0.12.21 wrote beside it; GENERATED.txt). The index is a fake fetch serving Simple JSON
 * captured from pypi.org (test/fixtures/python/simple), with upload times moved where a case needs a young file.
 * Nothing here uses the network, python3, uv or pip; git runs in temporary repositories with no global or system
 * configuration. Install settings have their own file (test/python-discover-settings.test.ts); here the pip probe
 * answers with an empty configuration.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { discoverPython, gitForPython, pythonBaseIdentities, type DiscoverOptions, type PythonDiscovery } from "../src/python/discover.js";
import { pythonIdentity } from "../src/python/identity.js";
import { SIMPLE_JSON } from "../src/python/index.js";
import { isRequirementsName, pyprojectDeclares, setupCfgDeclares } from "../src/python/manifest.js";
import { checkPythonLocks } from "../src/python/soak.js";
import { hasScriptTagLine, isContentCandidate, isUvShebang, looksLikeRequirements, mayBeRequirement, OPAQUE_CODECS, pipView, refusedByPipAndUv, scanLargeFile, scriptLockPath } from "../src/python/scripts.js";
import { parseToml } from "../src/python/toml.js";
import type { Finding } from "../src/types.js";
import { hasNpmInputs, walkTree } from "../src/walk.js";

const FIX = join(import.meta.dirname, "..", "..", "test", "fixtures", "python");
const LOCKS = join(FIX, "locks");
const REPOS = join(FIX, "repos");
const INDEX = "https://pypi.org/simple/";
const NOW = new Date("2026-10-08T12:00:00Z");
const DAY = 86_400_000;

const SIX_WHL = "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274";
const SIX_SDIST = "ff70335d468e7eb6ec65b95b99d3a2836546063f63acc5171de367e834932a81";
const REQ_LOCK = `--require-hashes\nsix==1.17.0 --hash=sha256:${SIX_WHL} --hash=sha256:${SIX_SDIST}\n`;
const SIMPLE_UV = readFileSync(join(LOCKS, "uv-0.12.21", "simple", "uv.lock"), "utf8");
const SCRIPT_LOCK = readFileSync(join(LOCKS, "uv-0.12.21", "script", "example.py.lock"), "utf8");
const SCRIPT = readFileSync(join(LOCKS, "uv-0.12.21", "script", "example.py"), "utf8");

/* ---- helpers ---- */

const tmp = (prefix: string): string => mkdtempSync(join(tmpdir(), prefix));
const ENV = (root: string): Record<string, string | undefined> => ({
  PATH: process.env["PATH"],
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CEILING_DIRECTORIES: dirname(root),
  HOME: join(root, "..", "no-home"),
});
function git(cwd: string, ...args: string[]): void {
  execFileSync("git", ["-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...args], { cwd, env: ENV(cwd), stdio: "ignore" });
}
type Files = Record<string, string | Buffer | { link: string }>;
function write(root: string, files: Files): void {
  for (const [p, v] of Object.entries(files)) {
    mkdirSync(dirname(join(root, p)), { recursive: true });
    if (typeof v === "string" || Buffer.isBuffer(v)) writeFileSync(join(root, p), v);
    else symlinkSync(v.link, join(root, p));
  }
}
/** A scratch repository; `tracked`: make it a git work tree and commit these paths (true: everything). */
function repo(files: Files, tracked?: true | string[]): string {
  const root = tmp("ws-pydisc-");
  write(root, files);
  if (tracked !== undefined) {
    git(root, "init", "-q");
    git(root, "add", "-f", ...(tracked === true ? ["."] : tracked));
    git(root, "commit", "-q", "-m", "x", "--allow-empty");
  }
  return root;
}
const emptyPip: DiscoverOptions["pipConfig"] = () => ({ code: 0, stdout: "" });
function disc(root: string, over: Partial<DiscoverOptions> = {}): PythonDiscovery {
  return discoverPython(root, { pypiIndex: INDEX, env: ENV(root), uvConfigFiles: [], ancestors: false, pipConfig: emptyPip, ...over });
}
const brief = (fs: Finding[]): string[] => fs.map((f) => `${f.ruleId} ${f.file ?? "-"}`).sort();
const files = (d: PythonDiscovery): string[] => d.locks.map((l) => `${l.kind} ${l.file}`).sort();
const messageOf = (d: PythonDiscovery, file: string): string => d.findings.find((f) => f.file === file)?.message ?? "";

/** A fake index: captured pages, with every file of `young` (name@version) uploaded `days` before NOW. */
function fakeIndex(young: Record<string, number> = {}) {
  const asked: string[] = [];
  const fetchImpl = (async (url: string | URL) => {
    const u = String(url);
    const m = /^https:\/\/pypi\.org\/simple\/([a-z0-9-]+)\/$/.exec(u);
    if (!m) throw new Error(`unexpected request ${u}`);
    asked.push(m[1]!);
    let body: { files: { filename: string; "upload-time": string }[] };
    try {
      body = JSON.parse(readFileSync(join(FIX, "simple", `${m[1]}.json`), "utf8")) as typeof body;
    } catch {
      return new Response("{}", { status: 404 });
    }
    for (const [id, days] of Object.entries(young)) {
      const [name, version] = id.split("@") as [string, string];
      for (const f of body.files) if (f.filename.startsWith(`${name}-${version}-`) || f.filename.startsWith(`${name}-${version}.`)) f["upload-time"] = new Date(NOW.getTime() - days * DAY).toISOString().replace(/\.\d+Z$/, ".000000Z");
    }
    return new Response(JSON.stringify(body), { headers: { "content-type": SIMPLE_JSON } });
  }) as typeof fetch;
  return { fetchImpl, asked };
}

/* ---- locks, scripts and requirements files ---- */

test("discover: the uv fixtures' locks are found, each manifest covered (workspace member, path source, virtual root)", () => {
  for (const v of ["uv-0.10.9", "uv-0.12.21"]) {
    const root = tmp("ws-pydisc-");
    cpSync(join(LOCKS, v), root, { recursive: true });
    const d = disc(root);
    assert.deepStrictEqual(files(d), [
      "pylock simple/pylock.toml",
      "requirements simple/requirements.txt",
      "script script/example.py.lock",
      "uv editable/uv.lock",
      "uv fork/uv.lock",
      "uv path/uv.lock",
      "uv simple/uv.lock",
    ]);
    // editable/packages/member and path/libs/localdir declare dependencies and are covered by the uv.lock above them.
    assert.deepStrictEqual(d.findings, [], v);
    assert.equal(d.pythonInputs, true);
  }
});

test("discover: an extensionless script with a `uv -q run` shebang has its lock at deploy.lock (real uv 0.12.21 output)", () => {
  const root = tmp("ws-pydisc-");
  cpSync(join(REPOS, "scripts"), root, { recursive: true });
  const d = disc(root);
  assert.deepStrictEqual(files(d), ["script crlf.txt.lock", "script deploy.lock"]);
  assert.deepStrictEqual(d.findings, []);
  const six = d.locks.find((l) => l.file === "deploy.lock")!.packages[0]!;
  assert.equal(`${six.name}==${six.version} ${six.sendable}`, "six==1.17.0 true");
  // Without its lock, the script's dependencies are WS-SK-002; with a lock under another name, still.
  const bare = repo({ deploy: readFileSync(join(REPOS, "scripts", "deploy")), "deploy.py.lock": readFileSync(join(REPOS, "scripts", "deploy.lock")) });
  const b = disc(bare);
  assert.deepStrictEqual(brief(b.findings), ["WS-SK-002 deploy", "WS-SK-002 deploy.py.lock"]);
  assert.match(messageOf(b, "deploy"), /PEP 723 script that declares dependencies, and there is no deploy\.lock beside it/);
  assert.match(messageOf(b, "deploy.py.lock"), /script lock, but deploy\.py is not a script with a `# \/\/\/ script` block/);
});

test("discover: scripts by shebang tokens, by .py/.pyw name and by a `# /// script` line in a file the content pass reads", () => {
  const block = '# /// script\n# dependencies = ["six==1.17.0"]\n# ///\n';
  const root = repo({
    "a/tool": `#!/usr/bin/env -S uv -q run --script\n${block}`,
    "b/tool": `#!/home/u/.local/bin/uv run\n${block}`,
    "c/tool": `#!/usr/bin/env -Suv run\n${block}`,
    "d/tool": `#!/usr/bin/env python3\n${block}`,
    "e/tool.PY": block,
    "f/tool.pyw": block,
    "g/notes.txt": `Run it:\n\n${block}`,
    "h/tool": `#!/usr/bin/env -S uv run --script\r\n${block.replace(/\n/g, "\r\n")}`,
    // Not a name the content pass reads (and no notes.md.lock beside it): documentation, never opened.
    "i/notes.md": `Run it:\n\n\`\`\`python\n${block}\`\`\`\n`,
  });
  const d = disc(root);
  // Every one is a script with dependencies and no lock, except d/tool (python3 shebang, not .py, but it has a
  // `# /// script` line, so it is found by content too).
  assert.deepStrictEqual(brief(d.findings), ["a/tool", "b/tool", "c/tool", "d/tool", "e/tool.PY", "f/tool.pyw", "g/notes.txt", "h/tool"].map((f) => `WS-SK-002 ${f}`));
  for (const f of d.findings) assert.match(f.message, /PEP 723 script that declares dependencies/);
  // Over 1 MiB, a candidate is searched in chunks: padding does not hide a script (review: deploy padded past 1 MiB).
  const big = "x".repeat(1024 * 1024);
  const r2 = repo({ "big.txt": `${block}${big}`, "big-shebang": `#!/usr/bin/env -S uv run\n${block}${big}`, "big.py": `${block}${big}`, "big-tail": `${big}\n${big}\n${block}` });
  assert.deepStrictEqual(brief(disc(r2).findings), ["WS-SK-002 big-shebang", "WS-SK-002 big-tail", "WS-SK-002 big.py", "WS-SK-002 big.txt"]);
});

test("discover: a script's block problems, empty dependencies, and its lock as a symlink or a directory", () => {
  const root = repo({
    "unclosed.py": '# /// script\n# dependencies = ["six"]\n',
    "two.py": "# /// script\n# ///\n# /// script\n# ///\n",
    "nodeps.py": "# /// script\n# dependencies = []\n# ///\n",
    "noblock.py": "print(1)\n",
    "linked.py": SCRIPT,
    "linked.py.lock": { link: "elsewhere.lock" },
    "dir.py": SCRIPT,
    "dir.py.lock/x": "",
  });
  const d = disc(root);
  assert.deepStrictEqual(brief(d.findings), ["WS-SK-002 dir.py.lock", "WS-SK-002 linked.py.lock", "WS-SK-002 two.py", "WS-SK-002 unclosed.py"]);
  assert.match(messageOf(d, "unclosed.py"), /no closing `# \/\/\/` line/);
  assert.match(messageOf(d, "linked.py.lock"), /it is a symlink, which wormsign does not follow/);
  assert.match(messageOf(d, "dir.py.lock"), /lock path of the script dir\.py, but not a regular file/);
  assert.deepStrictEqual(d.locks, []);
});

test("discover: a CRLF block is read; an orphan .py.lock is read and WS-SK-002; a .py.lock of a script without a block too", () => {
  const root = repo({
    "crlf.py": SCRIPT,
    "lf.py": SCRIPT.replace(/\r\n/g, "\n"),
    "lf.py.lock": SCRIPT_LOCK,
    "crlf.py.lock": SCRIPT_LOCK,
    "gone.py.lock": SCRIPT_LOCK,
    "plain.py": "print(1)\n",
    "plain.py.lock": SCRIPT_LOCK,
    "sub/Tool.PYW.lock": SCRIPT_LOCK,
  });
  assert.ok(SCRIPT.includes("# /// script\r\n"), "the readers' example.py, as uv read it, has CRLF line endings");
  const d = disc(root);
  assert.deepStrictEqual(files(d), ["script crlf.py.lock", "script gone.py.lock", "script lf.py.lock", "script plain.py.lock", "script sub/Tool.PYW.lock"]);
  assert.deepStrictEqual(brief(d.findings), ["WS-SK-002 gone.py.lock", "WS-SK-002 plain.py.lock", "WS-SK-002 sub/Tool.PYW.lock"]);
  for (const f of d.findings) assert.match(f.message, /is not a script with a `# \/\/\/ script` block beside it \(missing, a symlink, too large to read, or without a block\)/);
});

test("discover: uv.lock, pylock and requirements names are matched without case; poetry, pdm and Pipfile locks are not supported yet", () => {
  const root = repo({
    "a/UV.LOCK": SIMPLE_UV,
    "b/PyLock.Dev.toml": readFileSync(join(LOCKS, "uv-0.12.21", "simple", "pylock.toml")),
    "c/Requirements-Dev.TXT": REQ_LOCK,
    "d/requirements/base.txt": REQ_LOCK,
    "e/constraints.txt": REQ_LOCK,
    "f/requirements.lock": REQ_LOCK,
    "g/poetry.lock": "# poetry\n",
    "g/pdm.lock": "# pdm\n",
    "g/Pipfile.lock": "{}\n",
    "g/Pipfile": "[packages]\nsix = '*'\n",
  });
  const d = disc(root);
  assert.deepStrictEqual(files(d), ["pylock b/PyLock.Dev.toml", "requirements c/Requirements-Dev.TXT", "requirements d/requirements/base.txt", "requirements e/constraints.txt", "requirements f/requirements.lock", "uv a/UV.LOCK"]);
  assert.deepStrictEqual(brief(d.findings), ["WS-SK-002 g/Pipfile.lock", "WS-SK-002 g/pdm.lock", "WS-SK-002 g/poetry.lock"], "the Pipfile is covered by its (unsupported) lock");
  for (const f of d.findings) assert.match(f.message, /is not supported yet, so the versions it pins cannot be verified/);
  assert.ok(isRequirementsName("x/Requirements/deep/er/base.txt") && !isRequirementsName("reqs/base.txt") && !isRequirementsName("requirements.in"));
});

test("discover: requirements files found by content: ci/pins.txt and every hash spelling pip reads", () => {
  const h = `sha256:${SIX_WHL}`;
  const root = repo({
    "ci/pins.txt": `six==1.17.0 --hash=${h}\n`,
    "a.cfg": `six==1.17.0 --hash ${h}\n`,
    "b.cfg": `six==1.17.0 --ha=${h}\n`,
    "c.cfg": `six==1.17.0 --h=${h}\n`,
    "d.cfg": `six==1.17.0 --h'a'sh=${h}\n`,
    "e.cfg": `six==1.17.0 --ha\\\nsh=${h}\n`,
    "f.cfg": `--require-hashes\n-r ci/pins.txt\n`,
    "g.cfg": `--require-\n-r ci/pins.txt\n`,
    "h.cfg": Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`six==1.17.0 --hash=${h}\n`, "utf16le")]),
    // Opaque to a byte search (pip decodes it as UTF-16, here failing on its odd length), and uv reads "x": a candidate.
    "i.cfg": "# coding: utf-16\nx\n",
    "j.cfg": Buffer.from(`# \0\nsix==1.17.0 --hash=${h}\n`),
    "k.cfg": Buffer.concat([Buffer.from([0x00, 0x00, 0xfe, 0xff]), Buffer.from([...`six==1.0 --hash=${h}\n`].flatMap((c) => [0, 0, 0, c.charCodeAt(0)]))]),
  });
  const d = disc(root);
  assert.deepStrictEqual(
    d.locks.map((l) => l.file).sort(),
    ["a.cfg", "b.cfg", "c.cfg", "ci/pins.txt", "d.cfg", "e.cfg", "f.cfg", "g.cfg", "h.cfg", "i.cfg", "j.cfg", "k.cfg"],
  );
  assert.equal(d.pythonInputs, true);
});

test("discover: what the requirements content rule leaves alone (Dockerfiles, shell, docs, other encodings)", () => {
  const h = `sha256:${SIX_WHL}`;
  const root = repo({
    Dockerfile: "FROM python:3.12\nRUN pip install --no-deps \\\n    --require-hashes \\\n    -r requirements/prod.txt\n",
    "ci.sh": "#!/bin/sh\npip install --require-hashes -r ci/pins.txt\n",
    "README.md": "Install with `pip install --require-hashes -r requirements.txt`.\n",
    "latin1.py": "# -*- coding: latin-1 -*-\nprint('caf\xe9')\n",
    "header.txt": "curl --header=x --help\n",
    // Source and tools that mention hash options (found in review: these were read as requirements files, one finding per line).
    "tools/genpins.py": `import json, sys\nfor name, sha in pins:\n    print(f"{name}==1 \\\\")\n    print(f"    --hash=sha256:{sha}{end}")\n`,
    "src/lock.ts": `export const LOCK = "six==1.17.0";\nconst line = "--hash=${h}";\n`,
    "scripts/build.sh": "#!/bin/sh\nwebpack --hash --mode production\n",
    "docs/hashes.md": "Pass `--hash` to pip, as in --hash=<digest>.\n",
    "gbk.py": "# -*- coding: cp936 -*-\nprint('x')\n",
  });
  const d = disc(root);
  assert.deepStrictEqual(d.locks, []);
  assert.deepStrictEqual(d.findings, []);
  assert.equal(d.pythonInputs, false);
});

test("discover: an empty requirements file is skipped with a note; a plain one is read, and its problems are the lock's", () => {
  const root = repo({ "requirements.txt": "# nothing yet\n\n", "dev-requirements.txt": "pytest\n" });
  const d = disc(root);
  assert.deepStrictEqual(d.notes, ["requirements.txt holds only blank lines and comments, so it was skipped"]);
  assert.deepStrictEqual(files(d), ["requirements dev-requirements.txt"]);
  assert.ok(d.locks[0]!.problems.length > 0);
});

test("discover: Python names that are symlinks are WS-SK-002, never followed, and still count as a lock in their directory", () => {
  const root = repo({
    "real/uv.lock": SIMPLE_UV,
    "a/uv.lock": { link: "../real/uv.lock" },
    "a/pyproject.toml": '[project]\nname = "a"\ndependencies = ["six"]\n',
    "b/requirements.txt": { link: "/etc/hosts" },
    "c/pyproject.toml": { link: "../real/uv.lock" },
    "d/script.py": { link: "../elsewhere.py" },
  });
  const d = disc(root);
  assert.deepStrictEqual(brief(d.findings), ["WS-SK-002 a/uv.lock", "WS-SK-002 b/requirements.txt", "WS-SK-002 c/pyproject.toml"]);
  for (const f of d.findings) assert.match(f.message, /it is a symlink, which wormsign does not follow/);
  assert.deepStrictEqual(files(d), ["uv real/uv.lock"]);
});

/* ---- manifests and the covering-lock rule ---- */

test("discover: a pyproject with dependencies not covered by the governing uv.lock is WS-SK-002; dynamic dependencies count", () => {
  const root = tmp("ws-pydisc-");
  cpSync(join(LOCKS, "uv-0.12.21", "editable"), root, { recursive: true });
  write(root, {
    "packages/stray/pyproject.toml": '[project]\nname = "stray"\nversion = "1"\ndependencies = ["idna"]\n',
    "tools/dyn/pyproject.toml": '[project]\nname = "dyn"\ndynamic = ["dependencies", "version"]\n',
    "tools/nodeps/pyproject.toml": '[project]\nname = "nodeps"\nversion = "1"\n[build-system]\nrequires = ["hatchling"]\n',
    "tools/groups/pyproject.toml": '[dependency-groups]\ndev = ["pytest"]\n',
    "tools/bad/pyproject.toml": "[project\n",
  });
  const d = disc(root);
  assert.deepStrictEqual(brief(d.findings), ["WS-SK-002 packages/stray/pyproject.toml", "WS-SK-002 tools/bad/pyproject.toml", "WS-SK-002 tools/dyn/pyproject.toml", "WS-SK-002 tools/groups/pyproject.toml"]);
  assert.match(messageOf(d, "packages/stray/pyproject.toml"), /declares dependencies, but no lock covers it: no uv\.lock in its directory, none anywhere in the tree that lists it/);
  assert.match(messageOf(d, "tools/bad/pyproject.toml"), /could not be read \(it is not valid TOML.*so whether it declares dependencies is unknown/);
});

test("discover: a uv.lock, pylock or requirements lock beside a manifest covers it; setup.py, setup.cfg and Pipfile need one", () => {
  const root = repo({
    "a/pyproject.toml": '[project]\nname = "a"\ndependencies = ["six"]\n',
    "a/requirements.txt": REQ_LOCK,
    "b/pyproject.toml": '[tool.poetry.dependencies]\npython = "^3.9"\nsix = "*"\n',
    "b/pylock.toml": readFileSync(join(LOCKS, "uv-0.12.21", "simple", "pylock.toml")),
    "c/setup.py": "from setuptools import setup\nsetup(install_requires=['six'])\n",
    "d/setup.py": "from setuptools import setup\nsetup()\n",
    "d/ci-requirements.txt": REQ_LOCK,
    "e/setup.cfg": "[metadata]\nname = e\n[options]\ninstall_requires =\n    six\n",
    "f/setup.cfg": "[flake8]\nmax-line-length = 100\n[tool:pytest]\naddopts = -q\n",
    "g/Pipfile": "[packages]\nsix = '*'\n",
    "h/pyproject.toml": '[project]\nname = "h"\nversion = "1"\ndependencies = ["six"]\n',
    "h/uv.lock": SIMPLE_UV,
  });
  const d = disc(root);
  assert.deepStrictEqual(brief(d.findings), ["WS-SK-002 c/setup.py", "WS-SK-002 e/setup.cfg", "WS-SK-002 g/Pipfile"]);
  assert.match(messageOf(d, "c/setup.py"), /it is a setup\.py, which declares whatever it computes/);
  assert.match(messageOf(d, "e/setup.cfg"), /declares dependencies \(install_requires/);
  assert.match(messageOf(d, "g/Pipfile"), /no Pipfile\.lock .* or other lock beside it/);
});

test("discover: a requirements file directly in a requirements/ directory covers the directory above it, one level only", () => {
  const pyproject = (name: string): string => `[project]\nname = "${name}"\ndependencies = ["six"]\n`;
  const root = repo({
    // The review's layout: the project's pyproject.toml at the root, its locks in requirements/.
    "pyproject.toml": pyproject("root"),
    "requirements/base.txt": REQ_LOCK,
    "svc/setup.py": "from setuptools import setup\nsetup(install_requires=['six'])\n",
    "svc/Requirements/prod.txt": REQ_LOCK,
    "linked/pyproject.toml": pyproject("linked"),
    "linked/requirements/base.txt": { link: "../../requirements/base.txt" },
    // Not covered: two levels down, a directory of another name, a requirements/ directory that is a sibling's.
    "deep/pyproject.toml": pyproject("deep"),
    "deep/requirements/ci/lock.txt": REQ_LOCK,
    "other/pyproject.toml": pyproject("other"),
    "other/reqs/base.txt": REQ_LOCK,
    "apps/web/pyproject.toml": pyproject("web"),
    "apps/requirements/web.txt": REQ_LOCK,
    // Nor a pylock.toml in a requirements/ directory: only a requirements file there covers the directory above.
    "pyl/pyproject.toml": pyproject("pyl"),
    "pyl/requirements/pylock.toml": 'lock-version = "1.0"\ncreated-by = "test"\n',
  });
  const d = disc(root);
  const uncovered = d.findings.filter((f) => f.ruleId === "WS-SK-002" && /no lock covers it/.test(f.message)).map((f) => f.file).sort();
  assert.deepStrictEqual(uncovered, ["apps/web/pyproject.toml", "deep/pyproject.toml", "other/pyproject.toml", "pyl/pyproject.toml"]);
  assert.match(messageOf(d, "pyl/pyproject.toml"), /no pylock\.toml or requirements hash lock beside it, nor a requirements hash lock in a requirements\/ directory beside it, so/);
  // The symlinked one is still WS-SK-002 for itself (never followed), and it still covers.
  assert.ok(d.findings.some((f) => f.file === "linked/requirements/base.txt" && /symlink/.test(f.message)), brief(d.findings).join(", "));
  // Control: the same root without requirements/base.txt leaves its manifest uncovered.
  const bare = disc(repo({ "pyproject.toml": pyproject("root"), "requirements/README.md": "locks go here\n" }));
  assert.deepStrictEqual(brief(bare.findings), ["WS-SK-002 pyproject.toml"]);
});

test("discover: pyprojectDeclares and setupCfgDeclares read each way of declaring", () => {
  const declares = (t: string): boolean => {
    const r = parseToml(t);
    assert.ok("doc" in r, t);
    return pyprojectDeclares(r.doc);
  };
  for (const t of [
    '[project]\ndependencies = ["x"]',
    '[project.optional-dependencies]\nt = ["x"]',
    '[project]\ndynamic = ["optional-dependencies"]',
    '[dependency-groups]\ndev = ["x"]',
    '[tool.uv]\ndev-dependencies = ["x"]',
    '[tool.poetry.dependencies]\nx = "*"',
    '[tool.poetry.group.dev.dependencies]\nx = "*"',
    '[tool.poetry.dev-dependencies]\nx = "*"',
    '[tool.pdm.dev-dependencies]\nlint = ["x"]',
    '[project]\ndependencies = "x"',
    'project = 1',
    // flit_core still builds a legacy [tool.flit.metadata] project from these.
    '[tool.flit.metadata]\nmodule = "x"\nrequires = ["six"]',
    '[tool.flit.metadata]\nmodule = "x"\ndev-requires = ["pytest"]',
    '[tool.flit.metadata.requires-extra]\ntest = ["pytest"]',
    // An in-tree build backend declares whatever its code computes.
    '[build-system]\nrequires = []\nbuild-backend = "backend"\nbackend-path = ["."]',
    'build-system = 1',
  ]) assert.ok(declares(t), t);
  for (const t of [
    '[project]\nname = "x"\ndependencies = []',
    '[project.optional-dependencies]\nt = []',
    '[tool.poetry.dependencies]\npython = "^3.9"',
    '[build-system]\nrequires = ["setuptools"]',
    '[build-system]\nrequires = ["setuptools"]\nbackend-path = []',
    '[tool.flit.metadata]\nmodule = "x"',
    '[tool.uv]\npackage = false',
    "[dependency-groups]\ndev = []",
  ]) assert.ok(!declares(t), t);
  assert.ok(setupCfgDeclares("[options]\nsetup_requires = x\n") && setupCfgDeclares("[options]\nInstall-Requires: x\n") && setupCfgDeclares("[options.extras_require]\nt = x\n"));
  assert.ok(!setupCfgDeclares("[flake8]\nignore = E501\n"));
  // A character Python reads as whitespace or a line break, which the line reader does not model, beside a key's name:
  // setuptools reads each of these as declaring.
  for (const t of ["[options]\ninstall_requires\f= six\n", "[options]\n\u00a0install_requires = six\n", "[options.extras_require]\n\vtest = idna\n"]) assert.ok(setupCfgDeclares(t), JSON.stringify(t));
  // Such a character with no key's name in the text declares nothing.
  assert.ok(!setupCfgDeclares("[flake8]\nmax-line-length = 100\n# \u00a0\n"));
});

/* ---- the walker's virtual-environment rule, seen from discovery ---- */

const VENV = (at: string): Files => ({
  [`${at}/pyvenv.cfg`]: "home = /usr/bin\nversion = 3.12.3\n",
  [`${at}/bin/python`]: { link: "/usr/bin/python3" },
  [`${at}/lib64`]: { link: "lib" },
  [`${at}/lib/python3.12/site-packages/pip/__init__.py`]: "",
  [`${at}/lib/python3.12/site-packages/thing/requirements.txt`]: "pytest\n",
  [`${at}/lib/python3.12/site-packages/thing/uv.lock`]: SIMPLE_UV,
});

test("discover: a committed pyvenv.cfg next to a young lock: the lock is still read, and its young pin is WS-SK-001", async () => {
  const root = repo({ "svc/pyvenv.cfg": "home = /usr/bin\n", "svc/lib/python3.12/site-packages/.keep": "", "svc/pyproject.toml": '[project]\nname = "demo-simple"\nversion = "0.1.0"\n', "svc/uv.lock": SIMPLE_UV }, true);
  const walk = walkTree(root, { env: ENV(root) });
  const d = disc(root, { walk });
  assert.deepStrictEqual(files(d), ["uv svc/uv.lock"]);
  assert.deepStrictEqual(walk.venvs, { skipped: [], partial: [] });
  const idx = fakeIndex({ "six@1.17.0": 2 });
  const res = await checkPythonLocks(d.locks, { minAgeMs: 7 * DAY, now: NOW, pypiIndex: INDEX, fetchImpl: idx.fetchImpl, root, ...gitForPython(walk, d.locks) });
  assert.deepStrictEqual(
    res.findings.filter((f) => f.ruleId === "WS-SK-001").map((f) => f.file),
    ["svc/uv.lock"],
  );
});

test("discover: a nested project under a venv shape whose own files are untracked is read; an untracked real venv is skipped", () => {
  const root = repo({ ...VENV("tools"), "tools/proj/uv.lock": SIMPLE_UV, "tools/proj/pyproject.toml": '[project]\nname = "demo-simple"\nversion = "0.1.0"\n', ...VENV(".venv"), "uv.lock": SIMPLE_UV }, ["tools/proj", "uv.lock"]);
  const walk = walkTree(root, { env: ENV(root) });
  const d = disc(root, { walk });
  assert.deepStrictEqual(
    files(d),
    ["requirements tools/lib/python3.12/site-packages/thing/requirements.txt", "uv tools/lib/python3.12/site-packages/thing/uv.lock", "uv tools/proj/uv.lock", "uv uv.lock"],
    "tools is committed content (walked whole); .venv is not",
  );
  assert.deepStrictEqual(walk.venvs.skipped, [".venv"]);
  assert.match(walk.notes[0] ?? "", /1 virtual environment\(s\) not read: .*: \.venv$/);
});

test("discover: with no work tree a venv's site-packages is not read (its names are the walker's WS-SK-002); a failing git is WS-SK-002", async () => {
  const root = repo({ ...VENV(".venv"), ".venv/extra-requirements.txt": REQ_LOCK, "pyproject.toml": '[project]\nname = "demo-simple"\nversion = "0.1.0"\n', "uv.lock": SIMPLE_UV });
  const walk = walkTree(root, { env: ENV(root) });
  const d = disc(root, { walk });
  assert.deepStrictEqual(files(d), ["requirements .venv/extra-requirements.txt", "uv uv.lock"]);
  assert.deepStrictEqual(walk.findings.map((f) => f.file).sort(), [".venv/lib/python3.12/site-packages/thing/requirements.txt", ".venv/lib/python3.12/site-packages/thing/uv.lock"]);
  assert.deepStrictEqual(gitForPython(walk, d.locks), { git: "no-work-tree" });
  // A failing git: the walker's WS-SK-002 for the venv, and soak's for the local root project.
  mkdirSync(join(root, ".git"));
  const bin = tmp("ws-pydisc-bin-");
  writeFileSync(join(bin, "git"), "#!/bin/sh\necho 'fatal: detected dubious ownership in repository' >&2\nexit 128\n");
  chmodSync(join(bin, "git"), 0o755);
  const w2 = walkTree(root, { env: { PATH: bin } });
  const d2 = disc(root, { walk: w2 });
  assert.ok(w2.findings.some((f) => f.file === ".venv" && /git failed/.test(f.message)));
  const g = gitForPython(w2, d2.locks);
  assert.deepStrictEqual(g, { git: "git-error", gitError: "fatal: detected dubious ownership in repository" });
  const res = await checkPythonLocks(d2.locks, { minAgeMs: 7 * DAY, now: NOW, pypiIndex: INDEX, fetchImpl: fakeIndex().fetchImpl, root, ...g });
  assert.ok(res.findings.some((f) => f.ruleId === "WS-SK-002" && /git failed \(fatal: detected dubious ownership/.test(f.message)));
});

test("discover: gitForPython lists git's ignored paths only when a lock has a local source tree", () => {
  const editable = tmp("ws-pydisc-");
  cpSync(join(LOCKS, "uv-0.12.21", "editable"), editable, { recursive: true });
  write(editable, { ".gitignore": ".venv/\n", ".venv/x": "" });
  git(editable, "init", "-q");
  git(editable, "add", ".");
  const w = walkTree(editable, { env: ENV(editable) });
  const g = gitForPython(w, disc(editable, { walk: w }).locks);
  assert.ok(g.git instanceof Set && g.git.has("uv.lock"));
  assert.deepStrictEqual(g.gitIgnored, new Set([".venv/"]));
  const simple = repo({ "uv.lock": SIMPLE_UV, ".gitignore": "x/\n", "x/y": "" }, true);
  const ws = walkTree(simple, { env: ENV(simple) });
  assert.equal(gitForPython(ws, disc(simple, { walk: ws }).locks).gitIgnored, undefined, "no local source tree: not asked");
});

/* ---- the content rules, unit by unit ---- */

test("scripts: tag lines, uv shebangs, lock paths", () => {
  assert.ok(hasScriptTagLine(Buffer.from("# /// script")) && hasScriptTagLine(Buffer.from("x\r# /// script\r\n")));
  assert.ok(!hasScriptTagLine(Buffer.from("  # /// script\n")) && !hasScriptTagLine(Buffer.from("# /// script \n")) && !hasScriptTagLine(Buffer.from("x # /// script\n")));
  for (const s of ["#!/usr/bin/env -S uv run --script", "#!/usr/bin/env -S uv -q run", "#! uv run", '#!/usr/bin/env -S "uv" "run"', "#!C:/tools/uv.exe run"]) assert.ok(isUvShebang(Buffer.from(`${s}\nx`)), s);
  for (const s of ["#!/usr/bin/env python3", "#!/usr/bin/env -S uvx run", "#!/usr/bin/env uv", "# uv run", "#!/bin/sh\nuv run"]) assert.ok(!isUvShebang(Buffer.from(`${s}\nx`)), s);
  assert.equal(scriptLockPath("a/deploy"), "a/deploy.lock");
  assert.equal(scriptLockPath("a/x.py"), "a/x.py.lock");
  assert.equal(scriptLockPath("README.md"), "README.md.lock");
});

test("scripts: pipView decodes as pip does, and looksLikeRequirements reads every hash spelling", () => {
  assert.deepStrictEqual(pipView(Buffer.from("# coding: cp037\nx")), { opaque: 'a coding line names "cp037"', codec: "cp037" });
  assert.deepStrictEqual(pipView(Buffer.from("#!/x\n# vim: set fileencoding=utf-7 :\n")), { opaque: 'a coding line names "utf-7"', codec: "utf_7" });
  for (const c of ["utf-8", "UTF8", "latin-1", "iso-8859-15", "cp1252", "euc-jp", "shift_jis", "ascii"]) assert.ok("text" in pipView(Buffer.from(`# -*- coding: ${c} -*-\n`)), c);
  assert.ok("text" in pipView(Buffer.from("x\ny\n# coding: utf-16\n")), "only the first two lines");
  const h = `sha256:${SIX_WHL}`;
  const yes = [
    `--hash=${h}`,
    `a --hash ${h}`,
    `a\t--has=${h}`, // uv splits on a tab too
    `a --h=${h}`,
    `a --ha ${h}`,
    `a --h"as"h=${h}`,
    `a --h\\ash=${h}`,
    `a --ha\\\r\nsh=${h}`,
    `a --hash "${h}"`,
    `a --hash=sha256:"${SIX_WHL.slice(0, 8)}"`,
    "a --hash=sha256:4721F391", // pip compares digests in lower case
    "a --hash=sha256:${SIX_DIGEST}", // pip expands ${NAME} before it parses
    "a --hash=${SIX_HASH}",
    "--require-hashes",
    "x\r--require-",
    "x\n--require-hashes\n",
    "--re'quire'-hashes",
    "# a comment ending in \\\n--require-hashes", // a comment line is not joined to the next
  ];
  for (const t of yes) assert.ok(looksLikeRequirements(Buffer.from(t)), t);
  const no = [
    "--hashes=x",
    "a--hash=x",
    "--help",
    "--header=x",
    "  --require-hashes",
    "x --require-hashes",
    "--requir",
    "--hash",
    "--hash=x",
    "a --hash=sha256:1234567", // seven digits: no digest pip could match
    "a --hash=sha256:${sha}", // pip expands only ${UPPER_CASE}
    "webpack --hash --mode production",
    `  const lock = "--hash=${h}";`, // the requirement part of a line, never options
    `assert.match(out, /--hash=${h}/);`,
    'print(f"    --hash=sha256:{digest}{end}")',
  ];
  for (const t of no) assert.ok(!looksLikeRequirements(Buffer.from(t)), t);
});

/* ---- what main.ts needs besides discovery ---- */

test("discover: pythonBaseIdentities maps the base's text of each head lock with the same mappers, keyed by the file each entry is in (PR mode)", () => {
  const head = repo({
    "uv.lock": SIMPLE_UV,
    "pylock.toml": readFileSync(join(LOCKS, "pip-26.2.1", "lock", "pylock.toml"), "utf8"),
    "requirements.txt": "--require-hashes\n-r requirements/base.txt\n",
    "requirements/base.txt": REQ_LOCK.replace("--require-hashes\n", ""),
    "tool.py": SCRIPT,
    "tool.py.lock": SCRIPT_LOCK,
  });
  const d = disc(head);
  const ids = (locks: typeof d.locks): string[] => locks.flatMap((l) => l.packages.map((p) => `${p.file ?? l.file}\0${pythonIdentity(p)}`)).sort();
  // The same text in the base: every identity is there, so PR mode checks nothing.
  const same = (rel: string): string | undefined => readFileSync(join(head, rel), "utf8");
  assert.deepStrictEqual([...pythonBaseIdentities(same, d.locks, { pypiIndex: INDEX })].sort(), [...new Set(ids(d.locks))]);
  // A base without the files, or with text no reader reads, has none of them.
  assert.equal(pythonBaseIdentities(() => undefined, d.locks, { pypiIndex: INDEX }).size, 0);
  assert.equal(pythonBaseIdentities((rel) => `\uFEFF${same(rel) ?? ""}`, d.locks.filter((l) => l.kind !== "requirements"), { pypiIndex: INDEX }).size, 0);
  // A base that pinned another hash for six in the included file: six is the one changed requirements identity.
  const other = REQ_LOCK.replace(`--hash=sha256:${SIX_SDIST}`, `--hash=sha256:${"0".repeat(64)}`).replace("--require-hashes\n", "");
  const base = pythonBaseIdentities((rel) => (rel === "requirements/base.txt" ? other : same(rel)), d.locks, { pypiIndex: INDEX });
  const changed = d.locks.flatMap((l) => l.packages.filter((p) => !base.has(`${p.file ?? l.file}\0${pythonIdentity(p)}`)).map((p) => `${l.kind} ${p.name}`));
  // requirements.txt reads base.txt through -r, and base.txt (under requirements/) is a unit of its own: both pin six.
  assert.deepStrictEqual(changed, ["requirements six", "requirements six"]);
});

test("discover: hasNpmInputs is ConfigOptions.npmInputs: an npm lockfile (read or not), a package.json or a bunfig.toml", () => {
  const has = (files: Files): boolean => hasNpmInputs(walkTree(repo(files), {}));
  assert.equal(has({ "uv.lock": SIMPLE_UV, "requirements.txt": REQ_LOCK }), false);
  assert.equal(has({ "a/package.json": "{}" }), true);
  assert.equal(has({ "bunfig.toml": "" }), true);
  assert.equal(has({ "x/pnpm-lock.yaml": { link: "nowhere" } }), true);
  assert.equal(has({ "bun.lockb": "x" }), true);
  assert.equal(has({ "package.json/x": "" }), false, "a directory of that name is not one");
  // By folded name, as npmLockfiles reads them (npm on macOS and Windows opens PACKAGE.JSON as package.json).
  assert.equal(has({ "a/PACKAGE.JSON": "{}" }), true);
  assert.equal(has({ "BunFig.toml": "" }), true);
});


/* ---- found in review: symlinked scripts, unreadable files, hostile input, bounds, coverage ---- */

const asRoot = typeof process.getuid === "function" && process.getuid() === 0;

test("discover: a symlinked script's lock (<link>.lock) is read and WS-SK-002; a symlinked Gemfile's lock is someone else's", () => {
  const root = repo({
    "real.py": SCRIPT,
    "real.py.lock": SCRIPT_LOCK,
    deploy: { link: "real.py" },
    "deploy.lock": SCRIPT_LOCK,
    "bin/run": { link: "/opt/tools/outside-script" },
    "bin/RUN.lock": SCRIPT_LOCK,
    "shared/Gemfile": "source 'https://rubygems.org'\n",
    Gemfile: { link: "shared/Gemfile" },
    "Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n",
  });
  const d = disc(root);
  assert.deepStrictEqual(files(d), ["script bin/RUN.lock", "script deploy.lock", "script real.py.lock"]);
  assert.deepStrictEqual(brief(d.findings), ["WS-SK-002 bin/RUN.lock", "WS-SK-002 deploy.lock"]);
  assert.match(messageOf(d, "deploy.lock"), /it is the lock `uv run --script deploy` uses, and deploy is a symlink, which wormsign does not follow/);
  assert.match(messageOf(d, "bin/RUN.lock"), /`uv run --script bin\/run` uses, and bin\/run is a symlink/, "matched folded, and a target outside the tree may be a script");
  // Its pins are checked like any lock's.
  const six = d.locks.find((l) => l.file === "deploy.lock")!.packages.find((p) => p.name === "six")!;
  assert.equal(`${six.version} ${six.sendable}`, "1.17.0 true");
  // A *.py.lock beside a symlinked .py script says the same.
  const py = disc(repo({ "real.py": SCRIPT, "tool.py": { link: "real.py" }, "tool.py.lock": SCRIPT_LOCK }));
  assert.match(messageOf(py, "tool.py.lock"), /`uv run --script tool\.py` uses, and tool\.py is a symlink/);
});

test("discover: an unreadable file is WS-SK-002 when its name is a Python input, a note otherwise, and nothing in an npm-only tree", { skip: asRoot ? "root reads every file" : false }, () => {
  const lock = JSON.stringify({ name: "x", lockfileVersion: 3, requires: true, packages: { "": { name: "x" } } });
  const root = repo({ "package.json": '{"name":"x"}', "package-lock.json": lock, "secret.txt": "X=1\n", "secret.env": "X=1\n", "setup.py": "from setuptools import setup\nsetup()\n", "requirements.txt": REQ_LOCK });
  try {
    chmodSync(join(root, "secret.txt"), 0o000);
    chmodSync(join(root, "secret.env"), 0o000);
    chmodSync(join(root, "setup.py"), 0o000);
    const d = disc(root);
    assert.deepStrictEqual(brief(d.findings), ["WS-SK-002 setup.py"]);
    assert.match(messageOf(d, "setup.py"), /: it could not be read \(EACCES\), so whether it is a Python script or a requirements file is unknown/);
    assert.doesNotMatch(messageOf(d, "setup.py"), /could not be read \(it could not be read/);
    // secret.env is not a name the content pass reads, so it is never opened.
    assert.ok(d.notes.includes("1 file(s) could not be read, so whether they are Python scripts or requirements files is unknown: secret.txt"), JSON.stringify(d.notes));
    // The same unreadable file in a tree with no Python input: no finding, no note.
    const npmOnly = repo({ "package.json": '{"name":"x"}', "package-lock.json": lock, "secret.txt": "X=1\n" });
    chmodSync(join(npmOnly, "secret.txt"), 0o000);
    try {
      const n = disc(npmOnly);
      assert.deepStrictEqual([n.findings, n.notes, n.pythonInputs], [[], [], false]);
    } finally {
      chmodSync(join(npmOnly, "secret.txt"), 0o600);
    }
  } finally {
    chmodSync(join(root, "secret.txt"), 0o600);
    chmodSync(join(root, "secret.env"), 0o600);
    chmodSync(join(root, "setup.py"), 0o600);
  }
});

test("discover: the content rules are linear on hostile files (a 1 MiB file of backslashes, spaces or option starts)", () => {
  const fill = (unit: string, n: number): string => unit.repeat(Math.ceil(n / unit.length)).slice(0, n);
  const units = ["\\", " ", "\t", "x\\", "\\\n", " -", "--h ", " --h=", "${A", " --h=$${A", "a:", "# /// script\n", "#", "--require-", "'", " "];
  // 128 KiB first: a quadratic rule takes seconds there, and fails here instead of running into the test timeout.
  for (const n of [128 * 1024, 1024 * 1024]) {
    for (const u of units) {
      for (const text of [fill(u, n), `x${fill(u, n - 3)}y\\`]) {
        const t0 = performance.now();
        looksLikeRequirements(Buffer.from(text, "latin1"));
        hasScriptTagLine(Buffer.from(text, "latin1"));
        const ms = performance.now() - t0;
        assert.ok(ms < 1500, `unit ${JSON.stringify(u)}, ${n} bytes: ${ms.toFixed(0)} ms`);
      }
    }
  }
  // Through discovery: a file of only backslashes, under any name.
  const root = repo({ innocuous: "\\".repeat(1024 * 1024) });
  const t0 = performance.now();
  const d = disc(root);
  assert.ok(performance.now() - t0 < 3000, `${(performance.now() - t0).toFixed(0)} ms`);
  assert.deepStrictEqual([d.locks, d.findings], [[], []]);
});

test("discover: requirements entries are bounded across units: past the bound one WS-SK-002, the rest unread, no abort", () => {
  const big = Array.from({ length: 6 }, (_, i) => `pkg${i}==1.0 --hash=sha256:${SIX_WHL}\n`).join("");
  const tree: Files = { "big.txt": big };
  for (let i = 0; i < 5; i++) tree[`r${i}.cfg`] = `--require-hashes\n-r big.txt\n`;
  const root = repo(tree);
  const d = disc(root, { maxRequirementEntries: 15 });
  // big.txt (6 entries) is a unit by content too; walk order: big.txt, r0.cfg (12), r1.cfg would reach 18.
  assert.deepStrictEqual(files(d), ["requirements big.txt", "requirements r0.cfg"]);
  assert.deepStrictEqual(brief(d.findings), ["WS-SK-002 r1.cfg"]);
  assert.match(messageOf(d, "r1.cfg"), /hold more than 15 entries between them \(an included file counts once for each file that includes it\), so this file and 3 more were not read: r1\.cfg, r2\.cfg, r3\.cfg, r4\.cfg/);
  // Unbounded (the default), every unit is read.
  assert.equal(disc(root).locks.length, 6);
  // The base side is bounded the same way: past it, the head's packages count as changed.
  const head = disc(root).locks;
  const same = (rel: string): string | undefined => readFileSync(join(root, rel), "utf8");
  assert.equal(pythonBaseIdentities(same, head, { pypiIndex: INDEX }).size, 6);
  const capped = pythonBaseIdentities(same, head, { pypiIndex: INDEX, maxRequirementEntries: 15 });
  assert.equal(capped.size, 6, "big.txt and r0.cfg were read (12 entries; the same six identities)");
  assert.equal(pythonBaseIdentities(same, head, { pypiIndex: INDEX, maxRequirementEntries: 5 }).size, 0, "nothing fits: everything counts as changed");
});

test("discover: a uv.lock covers a sibling path source (real uv 0.10.9 output: backend/uv.lock lists ../shared/common)", () => {
  const root = tmp("ws-pydisc-");
  cpSync(join(REPOS, "sibling"), root, { recursive: true });
  const d = disc(root);
  assert.deepStrictEqual(files(d), ["uv backend/uv.lock"]);
  assert.deepStrictEqual(d.findings, [], "shared/common declares dependencies and backend/uv.lock pins them");
  // Without the lock, it is uncovered.
  const bare = tmp("ws-pydisc-");
  cpSync(join(REPOS, "sibling"), bare, { recursive: true });
  writeFileSync(join(bare, "backend", "uv.lock"), SIMPLE_UV);
  assert.deepStrictEqual(brief(disc(bare).findings), ["WS-SK-002 shared/common/pyproject.toml"]);
});

test("discover: a script found only by its `# /// script` line says how to baseline documentation", () => {
  const block = '# /// script\n# dependencies = ["six"]\n# ///\n';
  const d = disc(repo({ "EXAMPLE.txt": `Example:\n\n${block}`, "README.md": `Example:\n\n\`\`\`python\n${block}\`\`\`\n`, "tool.py": block, tool: `#!/usr/bin/env -S uv run --script\n${block}` }));
  assert.match(messageOf(d, "EXAMPLE.txt"), /uv run --locked`; if EXAMPLE\.txt is documentation that shows a script rather than a script anything runs, baseline this finding with a justification$/);
  assert.equal(messageOf(d, "README.md"), "", "a .md file is not read by content (no README.md.lock beside it)");
  assert.doesNotMatch(messageOf(d, "tool.py"), /documentation/);
  assert.doesNotMatch(messageOf(d, "tool"), /documentation/);
});

test("discover: a setup.cfg larger than 16 MiB is WS-SK-002 (a declaration past the part read would be missed)", () => {
  const padded = `[metadata]\nname = x\n# ${"x".repeat(17 * 1024 * 1024)}\n[options]\ninstall_requires = six\n`;
  const d = disc(repo({ "pyproject.toml": '[build-system]\nrequires = ["setuptools"]\n', "setup.cfg": padded }));
  assert.deepStrictEqual(brief(d.findings), ["WS-SK-002 setup.cfg"]);
  assert.match(messageOf(d, "setup.cfg"), /it is larger than 16 MiB, so whether it declares dependencies is unknown/);
  assert.deepStrictEqual(disc(repo({ "pyproject.toml": '[build-system]\nrequires = ["setuptools"]\n', "setup.cfg": "[metadata]\nname = x\n" })).findings, []);
});

test("scripts: which names the content pass opens", () => {
  for (const n of ["deploy", "Dockerfile", ".requirements", "deps.txt", "DEPS.TXT", "requirements.in", "ci.pip", "base.req", "x.lst", "x.deps", "pip.conf", "setup.cfg", "tox.ini", "run.sh", "tool.py", "tool.PYW", "x.lock", "x.command"]) assert.ok(isContentCandidate(n), n);
  for (const n of ["index.ts", "app.js", "README.md", "ci.yml", "logo.svg", "data.json", "gen.rb", "a.go", "x.map", "y.html"]) assert.ok(!isContentCandidate(n), n);
});

test("scripts: mayBeRequirement is false only for what PEP 508 (and pip's path and URL forms) cannot read", () => {
  for (const r of ["six", "six==1.0", "six == 1.0", "six>=1,<2", "six (>=1.0)", "six[a,b]==1", "six [ a ] ; python_version < '3'", "six;sys_platform=='x'", "Six_x.y-z===anything", "./vendor/six", "six @ https://x/six.whl", "https://x/six.whl", "six.whl", "${PKG}", "x/y", "", "file:pkgdir", "git+https:x", "svn+ssh:x"]) assert.ok(mayBeRequirement(r), r);
  // pip reads a name ending in one of its archive extensions as a path, whatever else it holds.
  for (const ext of [".zip", ".whl", ".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tar.xz", ".txz", ".tlz", ".tar.lz", ".tar.lzma", ".tar", ".TAR.LZMA"]) {
    assert.ok(mayBeRequirement(`my pkg${ext}`), ext);
    assert.ok(!mayBeRequirement(`my pkg${ext}x`), `${ext}x`);
  }
  // A line starting with a URL scheme may be a URL to pip (`file:pkgdir`), so YAML keys count as maybe too.
  for (const r of ["on: push", "jobs:"]) assert.ok(mayBeRequirement(r), r);
  for (const r of ["FROM node:22", "RUN pip install", "This project uses six.", "six==1.0 foo", "six[\"a\"]", "==1.0", "-six", "six==", "six (>=1.0", "\u00e9t\u00e9==1"]) assert.ok(!mayBeRequirement(r), r);
});

test("scripts: refusedByPipAndUv refuses only a file a line of which neither pip nor uv reads, and never when unsure", () => {
  const h = `--hash=sha256:${SIX_WHL}`;
  const refused = [
    `FROM node:22\nRUN pip install --no-cache-dir six==1.17.0 ${h}\n`,
    `#!/bin/sh\npython3 -m pip install "six==1.17.0" ${h}\n`,
    `Install it:\n\nsix==1.17.0 ${h}\n`,
    `six==1.17.0 ${h} --no-deps\n`,
    `six==1.17.0 ${h}\n-m pip\n`,
    // microsoft/TypeScript's compiler baselines (genericConstraints.txt and the like): plain ASCII, still refused.
    "//// [genericConstraints.ts]\nfunction f<T extends string>(x: T) {}\n\n//// [genericConstraints.js]\nfunction f(x) { }\n",
    "tests/cases/compiler/genericConstraints.ts(4,9): error TS2345: Argument of type 'Bar' is not assignable.\r\n\r\n==== x.ts (1 errors) ====\r\n\tclass Foo {}\r\n",
  ];
  for (const t of refused) assert.ok(refusedByPipAndUv(Buffer.from(t)), t);
  const kept = [
    `--require-hashes\nsix==1.17.0 ${h}\n`,
    `# comment line\n\nsix==1.17.0 \\\n    ${h}\n`,
    `six==1.17.0\t${h}\n`, // uv splits a tab before an option, pip does not
    `six==1.17.0 ${h} --config-settings=a=b\n-e .\n-r other.txt\n--index-url https://x\n--extra-index-url=https://y\n--ext https://z\n--pre\n-C x=y\n`,
    `FROM node:22\x0csix==1.17.0 ${h}\n`, // pip splits on \x0c, uv does not: unsure
    `\${X}\nsix==1.17.0 ${h}\n`,
    `-- weird\nsix==1.17.0 ${h}\n`,
    `on: push\njobs:\n  x:\n    - run: pip install six==1.17.0 ${h}\n`, // "on:" may be a URL scheme to pip
    "evil-young-pkg\nsix\nfile:pkgdir\n", // pip reads file:pkgdir as a URL
    // Characters Python and JavaScript disagree on (NOT_PLAIN): never sure, whatever else the file holds.
    "evil-young-pkg\nsix\n\x1fidna==3.10\n", // pip strips U+001F: it installs idna (pip 26.1.2), and six and evil-young-pkg
    `FROM node:22\n\x1fsix==1.17.0 ${h}\n`,
    "six==1.17.0\n\x1f# a note \\\nFROM node:22\n", // to pip a comment line (not joined); to a JS \\s, not one
    "FROM node:22\n\ufeffsix==1.17.0\n", // U+FEFF in the middle: whitespace to JavaScript, not to Python
    "six==1.17.0\n\ufeff# a note \\\nFROM node:22\n",
    "\u00a0six==1.17.0\nFROM node:22\n", // U+00A0: Python strips it from the UTF-8 text; the bytes read as latin1 do not
    "FROM node:22\u00a0\n",
    "FROM node:22\x7f\n",
    "FROM node:22\x00\n",
    "FROM node:22\r\nRUN x\rsix\n",
  ];
  for (const t of kept) assert.ok(!refusedByPipAndUv(Buffer.from(t)), JSON.stringify(t));
  // Control: plain ASCII texts with a line pip refuses are refused.
  for (const t of ["evil-young-pkg\nsix\nidna==3.10\nFROM node:22\n", `FROM node:22\nsix==1.17.0 ${h}\n`, "FROM node:22\r\nRUN x\r\nsix\n"]) assert.ok(refusedByPipAndUv(Buffer.from(t)), JSON.stringify(t));
  // Opaque codecs: UTF-16 and UTF-32 are decoded both ways (and as uv reads the bytes); others are never refused.
  // pip's UTF-16 reading of ASCII bytes is no ASCII text (an even length decodes): not sure.
  assert.ok(!refusedByPipAndUv(Buffer.from("# vim: set fileencoding=utf-16 :\npip install --require-hashes -r reqs.txt\n")));
  // A UTF-16 byte-order mark before ASCII text: the decoded text is ASCII, and refused as such.
  assert.ok(refusedByPipAndUv(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from("FROM node:22\npip install six\n", "utf16le")])));
  assert.ok(!refusedByPipAndUv(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from("FROM node:22\n\x1fsix\n", "utf16le")])));
  // Any coding line but plain UTF-8 or ASCII: not sure what pip reads (`idna` rewrites the text, latin-1 and the like
  // are no ASCII superset pip and JavaScript agree on), whatever the bytes.
  for (const c of ["utf-16", "idna", "latin-1", "cp1252", "utf-8-sig", "utf-8-unix", "binary"]) assert.ok(!refusedByPipAndUv(Buffer.from(`# coding: ${c}\nFROM node:22\n`)), c);
  for (const c of ["utf-8", "UTF8", "ascii", "us-ascii"]) assert.ok(refusedByPipAndUv(Buffer.from(`# -*- coding: ${c} -*-\nFROM node:22\n`)), c);
  assert.ok(refusedByPipAndUv(Buffer.from("\ufeff# coding: idna\nFROM node:22\n")), "a UTF-8 byte-order mark decides the encoding first");
  assert.ok(!refusedByPipAndUv(Buffer.from(`# coding: utf-16\n--require-hashes\nsix==1.17.0 ${h}\n`)), "uv reads these bytes as a lock");
  assert.ok(!refusedByPipAndUv(Buffer.from("# coding: cp037\nFROM x\n")), "EBCDIC: pip's text is unknown here");
  assert.ok(OPAQUE_CODECS.has("utf_16") && OPAQUE_CODECS.has("cp037") && OPAQUE_CODECS.has("unicode_escape") && !OPAQUE_CODECS.has("utf_8_unix") && !OPAQUE_CODECS.has("binary"));
  // A codec Python does not have is searched as bytes (pip fails on it, uv reads UTF-8): no hash option, no candidate.
  assert.ok(!looksLikeRequirements(Buffer.from("# -*- coding: utf-8-unix -*-\nall:\n\tmake build\n")));
  assert.ok(!looksLikeRequirements(Buffer.from("# -*- coding: binary -*-\nputs 1\n")));
});

test("scripts: scanLargeFile finds a tag line or an option across chunk boundaries, and only those", () => {
  const dir = mkdtempSync(join(tmpdir(), "ws-pydisc-large-"));
  const MiB = 1024 * 1024;
  const at = (name: string, prefix: number, text: string, after = 10) => {
    writeFileSync(join(dir, name), Buffer.concat([Buffer.alloc(prefix, 0x78), Buffer.from(text), Buffer.alloc(after, 0x78)]));
    return scanLargeFile(join(dir, name), 64 * MiB);
  };
  assert.deepEqual(at("a", MiB - 5, "\n# /// script\n"), { tag: true, requirements: false }, "a tag line split across chunks");
  assert.deepEqual(at("b", MiB - 1, "--hash=x "), { tag: false, requirements: true }, "--h split across chunks");
  assert.deepEqual(at("c", 2 * MiB, " -'-'r"), { tag: false, requirements: true }, "quotes dropped");
  assert.deepEqual(at("d", 2 * MiB, "x# /// script\n"), { tag: false, requirements: false }, "not a line of its own");
  assert.deepEqual(at("e", 2 * MiB, " - -h --x"), { tag: false, requirements: false });
  writeFileSync(join(dir, "f"), Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.alloc(2 * MiB, 0x78)]));
  assert.deepEqual(scanLargeFile(join(dir, "f"), 64 * MiB), { tag: false, requirements: true }, "a UTF-16 byte-order mark");
  assert.match((scanLargeFile(join(dir, "f"), MiB) as { problem: string }).problem, /larger than 1 MiB/);
});
