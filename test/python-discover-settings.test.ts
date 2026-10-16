/**
 * Install settings (src/python/indexes.ts) as discovery applies them (src/python/discover.ts): every v3/v4 case of
 * "an install may use another index" and "an install may skip hash checks", the pip config probe (stubbed, and the
 * real runner against a recording python3 stub), and WS-SK-005 for build-forcing uv configuration.
 *
 * A requirements hash lock (six 1.17.0, both files' sha256) is the entry whose name may or may not be sent; pip
 * 26.2.1's pylock.toml (test/fixtures/python/locks/pip-26.2.1, no `index`) and uv 0.12.21's (with `index`) are the
 * pylock cases. User and system uv.toml files and the directories above the root are read only where a case says so.
 * Nothing here uses the network, python3, uv or pip: the "python3" the real runner starts is a shell stub on PATH.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { spawnSync, SpawnSyncOptions } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, parse } from "node:path";
import { discoverPython, type DiscoverOptions, type PythonDiscovery } from "../src/python/discover.js";
import { SIMPLE_JSON } from "../src/python/index.js";
import { buildConfigFindings, iniValues, MAX_PROBE_OUTPUT, parsePipConfigList, pipConfigProbe, PROBE_DROPPED_ENV, PROBE_TIMEOUT_MS, unrepr, userSystemUvToml, type PipConfigProbe } from "../src/python/indexes.js";
import type { PyLock } from "../src/python/model.js";
import { checkPythonLocks } from "../src/python/soak.js";
import { parseToml } from "../src/python/toml.js";
import type { Finding } from "../src/types.js";

const FIX = join(import.meta.dirname, "..", "..", "test", "fixtures", "python");
const INDEX = "https://pypi.org/simple/";
const SIX_WHL = "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274";
const SIX_SDIST = "ff70335d468e7eb6ec65b95b99d3a2836546063f63acc5171de367e834932a81";
const REQ_LOCK = `--require-hashes\nsix==1.17.0 --hash=sha256:${SIX_WHL} --hash=sha256:${SIX_SDIST}\n`;
const PIP_PYLOCK = readFileSync(join(FIX, "locks", "pip-26.2.1", "lock", "pylock.toml"), "utf8");
const UV_PYLOCK = readFileSync(join(FIX, "locks", "uv-0.12.21", "simple", "pylock.toml"), "utf8");
const SIMPLE_UV = readFileSync(join(FIX, "locks", "uv-0.12.21", "simple", "uv.lock"), "utf8");

const tmp = (prefix: string): string => mkdtempSync(join(tmpdir(), prefix));
function repo(files: Record<string, string>): string {
  const root = tmp("ws-pyset-");
  for (const [p, v] of Object.entries(files)) {
    mkdirSync(dirname(join(root, p)), { recursive: true });
    writeFileSync(join(root, p), v);
  }
  return root;
}
const emptyPip: PipConfigProbe = () => ({ code: 0, stdout: "" });
function disc(root: string, env: Record<string, string> = {}, over: Partial<DiscoverOptions> = {}): PythonDiscovery {
  return discoverPython(root, { pypiIndex: INDEX, env: { HOME: join(root, "..", "no-home"), GIT_CEILING_DIRECTORIES: dirname(root), PATH: process.env["PATH"], ...env }, uvConfigFiles: [], ancestors: false, pipConfig: emptyPip, ...over });
}
const settingFindings = (d: PythonDiscovery): Finding[] => d.findings.filter((f) => f.key.startsWith("pypi:install-setting"));
const sendable = (l: PyLock | undefined): boolean[] => (l?.packages ?? []).map((p) => p.sendable);
const reqLock = (d: PythonDiscovery): PyLock | undefined => d.locks.find((l) => l.kind === "requirements");

/** One index finding for `where`, and the requirements entry kept from the index. */
function blocked(d: PythonDiscovery, where: RegExp): void {
  const f = settingFindings(d);
  assert.equal(f.length, 1, JSON.stringify(f.map((x) => x.message)));
  assert.equal(f[0]!.ruleId, "WS-SK-002");
  assert.match(f[0]!.message, /: an install may use another index: /);
  assert.match(f[0]!.message, where);
  assert.deepStrictEqual(sendable(reqLock(d)), [false]);
  assert.match(reqLock(d)!.packages[0]!.unsent ?? "", /may use another index/);
}
const clean = (d: PythonDiscovery): void => {
  assert.deepStrictEqual(settingFindings(d), []);
  assert.deepStrictEqual(sendable(reqLock(d)), [true]);
};

/* ---- the environment ---- */

test("settings: every index environment variable that names another index (or none) fails closed, credentials hidden", () => {
  const root = repo({ "requirements.txt": REQ_LOCK });
  const evil = "https://user:s3cret@evil.example/simple";
  for (const name of ["PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_DEFAULT_INDEX", "UV_INDEX", "PIP_Index_Url", "PIP_index-url"]) {
    const d = disc(root, { [name]: name === "UV_INDEX" ? `corp=${evil}` : evil });
    blocked(d, new RegExp(`environment variable ${name} names .*evil\\.example`));
    assert.doesNotMatch(JSON.stringify(d), /s3cret/, `${name}: no credentials in findings or entries`);
  }
  blocked(disc(root, { PIP_FIND_LINKS: "/opt/wheels" }), /PIP_FIND_LINKS adds find-links \/opt\/wheels/);
  blocked(disc(root, { UV_FIND_LINKS: "./wheels" }), /UV_FIND_LINKS adds find-links/);
  blocked(disc(root, { PIP_NO_INDEX: "1" }), /PIP_NO_INDEX turns the index off/);
  blocked(disc(root, { UV_NO_INDEX: "true" }), /UV_NO_INDEX is "true"/);
  // The configured index itself, any spelling of false, and empty values are not settings.
  clean(disc(root, { PIP_INDEX_URL: "https://pypi.org/simple", UV_INDEX: "pypi=https://PyPI.org/simple/", PIP_NO_INDEX: "off", UV_NO_INDEX: "0", PIP_EXTRA_INDEX_URL: "" }));
  // A private index given as --pypi-index is the index: a setting naming it is not another one.
  clean(disc(root, { PIP_INDEX_URL: "https://pkgs.corp.example/simple/" }, { pypiIndex: "https://pkgs.corp.example/simple" }));
});

test("settings: hash-verification environment variables are 'may skip hash checks', for requirements and every pylock", () => {
  const root = repo({ "requirements.txt": REQ_LOCK, "pylock.toml": UV_PYLOCK });
  for (const [name, value] of [["UV_NO_VERIFY_HASHES", "1"], ["UV_VERIFY_HASHES", "false"], ["UV_REQUIRE_HASHES", "0"], ["UV_NO_VERIFY_HASHES", "yes"]] as const) {
    const d = disc(root, { [name]: value });
    const f = settingFindings(d);
    assert.equal(f.length, 1, name);
    assert.match(f[0]!.message, new RegExp(`^Cannot verify soak time for the packages in pylock\\.toml, requirements\\.txt: an install may skip hash checks: environment variable ${name} is`));
    assert.deepStrictEqual(sendable(reqLock(d)), [true], "hash settings do not keep names from the index");
  }
  clean(disc(root, { UV_NO_VERIFY_HASHES: "false", UV_VERIFY_HASHES: "true", UV_REQUIRE_HASHES: "1" }));
});

/* ---- pip's configuration ---- */

test("settings: a pip config list entry in any section (install.) fails closed; :env: lines are the environment's", () => {
  const root = repo({ "requirements.txt": REQ_LOCK });
  const probe = (stdout: string): PipConfigProbe => (args) => {
    assert.deepStrictEqual(args, ["config", "list"]);
    return { code: 0, stdout };
  };
  blocked(disc(root, {}, { pipConfig: probe("install.index-url='https://evil.example/simple'\n") }), /pip configuration install\.index-url names https:\/\/evil\.example\/simple/);
  blocked(disc(root, {}, { pipConfig: probe("global.extra-index-url='\\nhttps://pypi.org/simple\\nhttps://b.example/simple'\n") }), /pip configuration global\.extra-index-url names https:\/\/pypi\.org\/simple https:\/\/b\.example/);
  blocked(disc(root, {}, { pipConfig: probe("download.find-links='/srv/wheels'\n") }), /download\.find-links adds find-links/);
  clean(disc(root, {}, { pipConfig: probe(":env:.index-url='https://evil.example/simple'\nglobal.index-url='https://pypi.org/simple'\nglobal.timeout='60'\n") }));
});

test("settings: pip's configuration not read (unavailable, failing, unreadable output) keeps entries unsent unless --pypi-index is explicit", () => {
  const root = repo({ "requirements.txt": REQ_LOCK });
  for (const [probe, why] of [
    [() => "unavailable", "python3 could not be run"],
    [() => ({ code: 1, stdout: "" }), "`python3 -m pip config list` exited 1"],
    [() => ({ code: null, stdout: "" }), "did not finish"],
    [() => ({ code: 0, stdout: "WARNING: something\n" }), "printed output soak does not read"],
  ] as [PipConfigProbe, string][]) {
    const d = disc(root, {}, { pipConfig: probe });
    assert.deepStrictEqual(settingFindings(d), [], "not a setting: a note, and unsent entries");
    assert.deepStrictEqual(sendable(reqLock(d)), [false], why);
    assert.match(reqLock(d)!.packages[0]!.unsent ?? "", /pip's configuration was not read/);
    assert.equal(d.notes.length, 1);
    assert.ok(d.notes[0]!.includes(why) && /are sent nowhere/.test(d.notes[0]!), d.notes[0]);
    const explicit = disc(root, {}, { pipConfig: probe, pypiIndexExplicit: true });
    assert.deepStrictEqual(sendable(reqLock(explicit)), [true], `${why}: explicit --pypi-index`);
    assert.match(explicit.notes[0] ?? "", /--pypi-index was given explicitly/);
  }
  // No probe given at all is "unavailable".
  assert.deepStrictEqual(sendable(reqLock(disc(root, {}, { pipConfig: undefined }))), [false]);
  // An explicit --pypi-index never waives a setting soak can see.
  blocked(disc(root, { PIP_INDEX_URL: "https://evil.example/simple" }, { pipConfig: () => "unavailable", pypiIndexExplicit: true }), /PIP_INDEX_URL/);
});

test("settings: PIP_CONFIG_FILE is read directly too, so a probe that cannot run does not hide it", () => {
  const root = repo({ "requirements.txt": REQ_LOCK });
  const cfg = join(tmp("ws-pyset-cfg-"), "pip.conf");
  writeFileSync(cfg, "[install]\nextra_index_url =\n    https://pypi.org/simple\n    https://user:pw@b.example/simple\n");
  const d = disc(root, { PIP_CONFIG_FILE: cfg }, { pipConfig: () => "unavailable", pypiIndexExplicit: true });
  blocked(d, /PIP_CONFIG_FILE .*pip\.conf \[install\] extra-index-url names https:\/\/pypi\.org\/simple https:\/\/b\.example\/simple/);
  assert.doesNotMatch(JSON.stringify(d), /user:pw/);
  clean(disc(root, { PIP_CONFIG_FILE: "/dev/null" }));
  clean(disc(root, { PIP_CONFIG_FILE: join(dirname(cfg), "missing.conf") }));
});

test("settings: the probe runs only when a requirements entry or a pylock package without index would be sent, never with --config-only", () => {
  let calls = 0;
  const counting: PipConfigProbe = () => {
    calls++;
    return { code: 0, stdout: "" };
  };
  const run = (files: Record<string, string>, over: Partial<DiscoverOptions> = {}): number => {
    calls = 0;
    disc(repo(files), {}, { pipConfig: counting, ...over });
    return calls;
  };
  assert.equal(run({ "requirements.txt": REQ_LOCK }), 1);
  assert.equal(run({ "requirements.txt": REQ_LOCK }, { configOnly: true }), 0);
  assert.equal(run({ "pylock.toml": PIP_PYLOCK }), 1, "pip lock output records no index");
  assert.equal(run({ "pylock.toml": UV_PYLOCK }), 0, "uv export records the index");
  assert.equal(run({ "requirements.txt": "pytest\n" }), 0, "no entries: nothing to send");
  assert.equal(run({ "uv.lock": readFileSync(join(FIX, "locks", "uv-0.12.21", "simple", "uv.lock"), "utf8") }), 0);
  const d = disc(repo({ "requirements.txt": REQ_LOCK, "x/pip.conf": "[global]\n" }), { PIP_INDEX_URL: "https://evil.example/simple" }, { configOnly: true });
  assert.deepStrictEqual(settingFindings(d), [], "--config-only reads no install setting");
  assert.match(reqLock(d)!.packages[0]!.unsent ?? "", /--config-only/);
});

test("settings: pip lock's pylock.toml (no index) is kept from the index by an index setting; uv's (with index) is not", () => {
  const root = repo({ "a/pylock.toml": PIP_PYLOCK, "b/pylock.toml": UV_PYLOCK });
  const d = disc(root, { UV_INDEX_URL: "https://evil.example/simple" });
  const a = d.locks.find((l) => l.file === "a/pylock.toml")!;
  const b = d.locks.find((l) => l.file === "b/pylock.toml")!;
  assert.ok(a.packages.length > 0 && a.packages.every((p) => !p.sendable && /may use another index \(environment variable UV_INDEX_URL/.test(p.unsent ?? "")));
  assert.ok(b.packages.length > 0 && b.packages.every((p) => p.sendable));
  assert.equal(settingFindings(d).length, 1);
  assert.match(settingFindings(d)[0]!.message, /packages in a\/pylock\.toml: an install may use another index/, "uv's pylock records its index: the setting governs nothing in it");
  assert.ok(disc(root).locks.every((l) => l.packages.every((p) => p.sendable)), "no setting: every package sendable");
});

/* ---- uv configuration ---- */

test("settings: uv [tool.uv.pip] extra-index-url in a pyproject.toml above a requirements file fails closed", () => {
  const root = repo({ "pyproject.toml": '[tool.uv.pip]\nextra-index-url = ["https://evil.example/simple"]\n', "ci/requirements.txt": REQ_LOCK });
  const d = disc(root);
  blocked(d, /pyproject\.toml \[tool\.uv\] \[pip\] extra-index-url names https:\/\/evil\.example\/simple/);
  assert.equal(settingFindings(d)[0]!.file, "pyproject.toml");
});

test("settings: each uv index key, at the top level and under [pip], in uv.toml and [tool.uv]; scope is the file's directory and below", () => {
  const cases: [string, string, RegExp][] = [
    ["uv.toml", 'index-url = "https://evil.example/simple"\n', /uv\.toml index-url names/],
    ["uv.toml", '[pip]\nfind-links = ["./wheels"]\n', /uv\.toml \[pip\] find-links adds find-links \.\/wheels/],
    ["uv.toml", "no-index = true\n", /uv\.toml no-index is true/],
    ["uv.toml", '[[index]]\nname = "corp"\nurl = "https://corp.example/simple"\n', /uv\.toml index names https:\/\/corp\.example\/simple/],
    ["pyproject.toml", '[[tool.uv.index]]\nname = "corp"\nurl = "https://corp.example/simple"\nexplicit = true\n', /pyproject\.toml \[tool\.uv\] index names/],
    ["pyproject.toml", '[tool.uv]\nindex-url = "https://evil.example/simple"\n', /\[tool\.uv\] index-url names/],
    ["pyproject.toml", '[tool.uv]\ndefault-index = "https://evil.example/simple"\n', /\[tool\.uv\] default-index names/],
    ["pyproject.toml", "[tool.uv.pip]\nno-index = true\n", /\[tool\.uv\] \[pip\] no-index is true/],
    ["pyproject.toml", "[tool]\nuv = 1\n", /\[tool\.uv\] is not a table/],
    ["uv.toml", "pip = 1\n", /uv\.toml \[pip\] is not a table/],
    ["uv.toml", "index-url = [\n", /uv\.toml could not be read \(it is not valid TOML/],
  ];
  for (const [name, text, where] of cases) {
    blocked(disc(repo({ [`svc/${name}`]: text, "svc/deep/requirements.txt": REQ_LOCK })), where);
    // A sibling directory's settings govern nothing here.
    clean(disc(repo({ [`other/${name}`]: text, "svc/requirements.txt": REQ_LOCK })));
  }
  clean(disc(repo({ "uv.toml": '[[index]]\nurl = "https://pypi.org/simple"\ndefault = true\n[pip]\nindex-url = "https://pypi.org/simple/"\nno-index = false\nfind-links = []\n', "requirements.txt": REQ_LOCK })));
});

test("settings: verify-hashes or require-hashes set to false is 'may skip hash checks'", () => {
  for (const [name, text] of [
    ["uv.toml", "[pip]\nverify-hashes = false\n"],
    ["uv.toml", "verify-hashes = false\n"],
    ["pyproject.toml", "[tool.uv.pip]\nrequire-hashes = false\n"],
    ["pyproject.toml", '[tool.uv.pip]\nverify-hashes = "no"\n'],
    ["uv.toml", "[pip]\nno-verify-hashes = true\n"],
  ] as const) {
    const d = disc(repo({ [name]: text, "requirements.txt": REQ_LOCK }));
    const f = settingFindings(d);
    assert.equal(f.length, 1, text);
    assert.match(f[0]!.message, /an install may skip hash checks: .*(verify-hashes|require-hashes) is/);
    assert.deepStrictEqual(sendable(reqLock(d)), [true]);
  }
  clean(disc(repo({ "uv.toml": "[pip]\nverify-hashes = true\nrequire-hashes = true\n", "requirements.txt": REQ_LOCK })));
});

test("settings: UV_CONFIG_FILE is read; missing or unreadable fails closed", () => {
  const root = repo({ "requirements.txt": REQ_LOCK });
  const dir = tmp("ws-pyset-uvcfg-");
  writeFileSync(join(dir, "ok.toml"), "[pip]\nindex-url = \"https://pypi.org/simple\"\n");
  writeFileSync(join(dir, "evil.toml"), "[pip]\nextra-index-url = [\"https://evil.example/simple\"]\n");
  writeFileSync(join(dir, "bad.toml"), "[pip\n");
  clean(disc(root, { UV_CONFIG_FILE: join(dir, "ok.toml") }));
  blocked(disc(root, { UV_CONFIG_FILE: join(dir, "evil.toml") }), /UV_CONFIG_FILE .*evil\.toml \[pip\] extra-index-url names/);
  blocked(disc(root, { UV_CONFIG_FILE: join(dir, "bad.toml") }), /UV_CONFIG_FILE .*bad\.toml could not be read/);
  blocked(disc(root, { UV_CONFIG_FILE: join(dir, "missing.toml") }), /UV_CONFIG_FILE .*missing\.toml names a file that does not exist/);
});

test("settings: the user's and the system's uv.toml, and uv files in the directories above the root", () => {
  const home = tmp("ws-pyset-home-");
  mkdirSync(join(home, "xdg", "uv"), { recursive: true });
  writeFileSync(join(home, "xdg", "uv", "uv.toml"), '[pip]\nindex-url = "https://evil.example/simple"\n');
  assert.deepStrictEqual(userSystemUvToml({ HOME: "/h", XDG_CONFIG_DIRS: "/a:/b" }), ["/h/.config/uv/uv.toml", "/a/uv/uv.toml", "/b/uv/uv.toml", "/etc/uv/uv.toml"]);
  const root = repo({ "requirements.txt": REQ_LOCK });
  const env = { XDG_CONFIG_HOME: join(home, "xdg"), XDG_CONFIG_DIRS: join(home, "none") };
  blocked(disc(root, env, { uvConfigFiles: userSystemUvToml(env) }), /xdg\/uv\/uv\.toml \[pip\] index-url names/);
  // Above the root: a repository scanned from a subdirectory still installs with the repository root's settings.
  const outer = repo({ "pyproject.toml": '[tool.uv]\nextra-index-url = ["https://evil.example/simple"]\n', "pkg/requirements.txt": REQ_LOCK });
  blocked(disc(join(outer, "pkg"), {}, { ancestors: true }), new RegExp(`${realpathSync(outer).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}|pyproject\\.toml \\[tool\\.uv\\] extra-index-url`));
  clean(disc(join(outer, "pkg"), {}, { ancestors: false }));
});

test("settings: a pip.conf or pip.ini anywhere in the tree fails closed for every requirements file", () => {
  for (const name of ["pip.conf", "docs/pip.ini", "deploy/PIP.CONF"]) {
    const d = disc(repo({ [name]: "[global]\ntimeout = 60\n", "app/requirements.txt": REQ_LOCK }));
    blocked(d, /is a pip configuration file in the repository/);
    assert.equal(settingFindings(d)[0]!.file, name);
  }
});

/* ---- the real probe runner ---- */

test("settings: the real probe runs python3 -m pip from the filesystem root, without PYTHON* variables, never from the scanned tree", () => {
  // A repository that holds pip/__main__.py: `python3 -m pip` run from it would run that file instead of pip.
  const scanned = repo({ "pip/__main__.py": "raise SystemExit('attacker code ran')\n", "requirements.txt": REQ_LOCK });
  const bin = tmp("ws-pyset-bin-");
  const record = join(tmp("ws-pyset-rec-"), "record");
  writeFileSync(
    join(bin, "python3"),
    `#!/bin/sh\n{ echo "cwd=$(pwd)"; echo "args=$*"; for v in PYTHONPATH PYTHONSTARTUP PYTHONHOME PYTHONUSERBASE PYTHONSAFEPATH PIP_CONFIG_FILE; do eval "echo $v=\\\${$v-unset}"; done; } > "${record}"\necho "install.index-url='https://evil.example/simple'"\n`,
  );
  chmodSync(join(bin, "python3"), 0o755);
  const env = { PATH: `${bin}:/usr/bin:/bin`, PYTHONPATH: ".", PYTHONSTARTUP: "x.py", PYTHONHOME: "/x", PYTHONUSERBASE: "/y", PIP_CONFIG_FILE: "/dev/null" };
  const cwd = process.cwd();
  process.chdir(scanned);
  let d: PythonDiscovery;
  try {
    d = disc(scanned, env, { pipConfig: pipConfigProbe(env) });
  } finally {
    process.chdir(cwd);
  }
  const rec = Object.fromEntries(readFileSync(record, "utf8").trim().split("\n").map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
  assert.equal(rec["cwd"], parse(scanned).root, "the filesystem root, not the scanned tree");
  assert.equal(rec["args"], "-m pip config list");
  for (const v of PROBE_DROPPED_ENV) assert.equal(rec[v], "unset", v);
  assert.equal(rec["PYTHONSAFEPATH"], "1");
  assert.equal(rec["PIP_CONFIG_FILE"], "/dev/null", "kept: it decides what pip reads");
  blocked(d, /pip configuration install\.index-url/);
  // python3 that cannot be started, and one that fails.
  assert.equal(pipConfigProbe({ PATH: tmp("ws-pyset-empty-") })(["config", "list"]), "unavailable");
  writeFileSync(join(bin, "python3"), "#!/bin/sh\necho 'No module named pip' >&2\nexit 1\n");
  assert.deepStrictEqual(pipConfigProbe({ PATH: bin })(["config", "list"]), { code: 1, stdout: "" });
});

/* ---- parsing ---- */

test("settings: pip config list, repr strings and pip.conf are read as pip writes them", () => {
  assert.deepStrictEqual(parsePipConfigList("global.index-url='https://a/simple'\n:env:.no-index='1'\ninstall.Find_Links=\"it's\"\n"), [
    { section: "global", key: "index-url", value: "https://a/simple" },
    { section: ":env:", key: "no-index", value: "1" },
    { section: "install", key: "find-links", value: "it's" },
  ]);
  assert.equal(parsePipConfigList("garbage\n"), undefined);
  assert.equal(parsePipConfigList("global.x=unquoted\n"), undefined);
  assert.deepStrictEqual(parsePipConfigList(""), []);
  assert.equal(unrepr("'a\\nb\\\\c\\x41\\u00e9'"), "a\nb\\cAé");
  assert.equal(unrepr("'unterminated"), undefined);
  assert.equal(unrepr("'bad\\q'"), undefined);
  assert.deepStrictEqual(iniValues("; c\n[global]\nindex_url = https://a\nextra-index-url =\n  https://b\n  https://c\n[install]\n--find-links: /x\n"), [
    { section: "global", key: "index-url", value: "https://a" },
    { section: "global", key: "extra-index-url", value: "\nhttps://b\nhttps://c" },
    { section: "install", key: "find-links", value: "/x" },
  ]);
});

/* ---- WS-SK-005: build-forcing configuration ---- */

test("settings: build-forcing uv configuration in the tree is WS-SK-005, keyed on file, key and value", () => {
  const root = repo({
    "pyproject.toml": '[project]\nname = "x"\nversion = "1"\n[tool.uv]\nno-binary = true\nno-build-isolation-package = ["a"]\n[tool.uv.pip]\nconfig-settings = { editable_mode = "compat" }\n',
    "svc/uv.toml": 'extra-build-dependencies = { a = ["b"] }\n[pip]\nno-binary = ["c"]\nno-build-isolation = false\n',
    "svc/uv.lock": readFileSync(join(FIX, "locks", "uv-0.12.21", "simple", "uv.lock"), "utf8"),
    "uv.lock": readFileSync(join(FIX, "locks", "uv-0.12.21", "simple", "uv.lock"), "utf8"),
  });
  const d = disc(root);
  const f = d.findings.filter((x) => x.ruleId === "WS-SK-005");
  assert.deepStrictEqual(f.map((x) => `${x.severity} ${x.file} ${x.key.replace(/ [0-9a-f]{32}$/, "")}`).sort(), [
    "medium pyproject.toml pypi:build-config [tool.uv] [pip] config-settings",
    "medium pyproject.toml pypi:build-config [tool.uv] no-binary",
    "medium pyproject.toml pypi:build-config [tool.uv] no-build-isolation-package",
    "medium svc/uv.toml pypi:build-config [pip] no-binary",
    "medium svc/uv.toml pypi:build-config extra-build-dependencies",
  ]);
  const doc = (t: string) => {
    const r = parseToml(t);
    assert.ok("doc" in r);
    return r.doc;
  };
  const a = buildConfigFindings("uv.toml", doc("no-binary-package = [\"a\"]\n"))[0]!;
  const b = buildConfigFindings("uv.toml", doc("no-binary-package = [\"b\"]\n"))[0]!;
  assert.notEqual(a.fingerprint, b.fingerprint, "the value is part of the key");
  assert.match(a.message, /uv\.toml sets no-binary-package = \["a"\]: installs that read it build packages from source/);
  assert.deepStrictEqual(buildConfigFindings("uv.toml", doc("no-binary = false\nconfig-settings = {}\nno-binary-package = []\n")), []);
});

/* ---- end to end: what reaches the index ---- */

test("settings: with an index setting no requirements name reaches the index or OSV; without one, it does", async () => {
  const root = repo({ "requirements.txt": REQ_LOCK });
  const asked: string[] = [];
  const fetchImpl = (async (url: string | URL) => {
    asked.push(String(url));
    if (String(url) === "https://pypi.org/simple/six/") return new Response(readFileSync(join(FIX, "simple", "six.json")), { headers: { "content-type": SIMPLE_JSON } });
    if (String(url) === "https://api.osv.dev/v1/querybatch") return new Response(JSON.stringify({ results: [{}] }));
    throw new Error(`unexpected ${String(url)}`);
  }) as typeof fetch;
  const check = (d: PythonDiscovery) => checkPythonLocks(d.locks, { minAgeMs: 7 * 86_400_000, now: new Date("2026-10-08T12:00:00Z"), pypiIndex: INDEX, fetchImpl, osv: true, root, git: "no-work-tree" });
  const blockedRun = await check(disc(root, { PIP_EXTRA_INDEX_URL: "https://corp.example/simple" }));
  assert.deepStrictEqual(asked, [], "a private name means zero fetch calls");
  assert.ok(blockedRun.findings.some((f) => f.ruleId === "WS-SK-002" && /six==1\.17\.0: an install of requirements\.txt may use another index \(environment variable PIP_EXTRA_INDEX_URL/.test(f.message)));
  const open = await check(disc(root));
  assert.deepStrictEqual(asked, ["https://pypi.org/simple/six/", "https://api.osv.dev/v1/querybatch"]);
  assert.deepStrictEqual(open.findings, []);
});

/* ---- found in review: names matched folded, relative config files, hostile pip.conf, the probe's limits ---- */

test("settings: UV.toml and PyProject.toml are uv's files on a case-insensitive file system, so they are read as such", () => {
  const hash = disc(repo({ "UV.toml": "[pip]\nverify-hashes = false\n", "requirements.txt": REQ_LOCK }));
  assert.equal(settingFindings(hash).length, 1);
  assert.match(settingFindings(hash)[0]!.message, /an install may skip hash checks: UV\.toml \[pip\] verify-hashes is false/);
  blocked(disc(repo({ "PyProject.toml": '[tool.uv.pip]\nindex-url = "https://evil.example/simple"\n', "app/requirements.txt": REQ_LOCK })), /PyProject\.toml \[tool\.uv\] \[pip\] index-url names https:\/\/evil\.example/);
  blocked(disc(repo({ "Uv.TOML": '[pip]\nindex-url = "https://evil.example/simple"\n', "requirements.txt": REQ_LOCK })), /Uv\.TOML \[pip\] index-url names/);
  // WS-SK-005 too, in a uv project with no requirements file (install settings are not collected there).
  const build = disc(repo({ "Uv.toml": "no-binary = true\n", "PYPROJECT.TOML": '[project]\nname = "x"\nversion = "1"\n[tool.uv]\nno-build-isolation = true\n', "uv.lock": SIMPLE_UV }));
  assert.deepStrictEqual(build.findings.map((f) => `${f.ruleId} ${f.file} ${f.key.replace(/ [0-9a-f]{32}$/, "")}`).sort(), ["WS-SK-005 PYPROJECT.TOML pypi:build-config [tool.uv] no-build-isolation", "WS-SK-005 Uv.toml pypi:build-config no-binary"]);
});

test("settings: a symlinked uv.toml is WS-SK-005 (not followed, so its build settings are unknown), with or without requirements files", () => {
  const root = repo({ "config/ci.toml": "no-build-isolation = true\n", "uv.lock": SIMPLE_UV });
  symlinkSync("config/ci.toml", join(root, "uv.toml"));
  const d = disc(root);
  assert.deepStrictEqual(d.findings.map((f) => `${f.ruleId} ${f.severity} ${f.file} ${f.key}`), ["WS-SK-005 medium uv.toml pypi:build-config symlink"]);
  assert.match(d.findings[0]!.message, /^uv\.toml is a symlink, which wormsign does not follow, so whether it sets uv settings that make installs build packages from source/);
});

test("settings: [tool.uv] build-forcing settings in a PEP 723 script block are WS-SK-005", () => {
  const script = '# /// script\n# dependencies = []\n# [tool.uv]\n# no-binary = true\n# no-build-isolation-package = ["six"]\n# ///\nprint(1)\n';
  const d = disc(repo({ "s.py": script }));
  assert.deepStrictEqual(d.findings.map((f) => `${f.ruleId} ${f.file} ${f.key.replace(/ [0-9a-f]{32}$/, "")}`).sort(), ["WS-SK-005 s.py pypi:build-config [tool.uv] no-binary", "WS-SK-005 s.py pypi:build-config [tool.uv] no-build-isolation-package"]);
  assert.match(d.findings.find((f) => f.key.includes("no-binary"))!.message, /^s\.py sets \[tool\.uv\] no-binary = true in its `# \/\/\/ script` block: installs that read it build packages from source/);
  assert.deepStrictEqual(disc(repo({ "s.py": '# /// script\n# dependencies = []\n# [tool.uv]\n# exclude-newer = "2026-10-01T00:00:00Z"\n# ///\n' })).findings, []);
});

test("settings: a relative PIP_CONFIG_FILE or UV_CONFIG_FILE fails closed: what the install reads depends on its working directory", () => {
  const root = repo({ "requirements.txt": REQ_LOCK, "ci/pip-index.cfg": "[global]\nindex-url = https://evil.example/simple\n" });
  blocked(disc(root, { PIP_CONFIG_FILE: "ci/pip-index.cfg" }), /PIP_CONFIG_FILE ci\/pip-index\.cfg is a relative path, so what the install reads depends on its working directory/);
  blocked(disc(root, { UV_CONFIG_FILE: "uv-ci.toml" }), /UV_CONFIG_FILE uv-ci\.toml is a relative path/);
  blocked(disc(root, { PIP_CONFIG_FILE: "./missing.conf" }), /PIP_CONFIG_FILE \.\/missing\.conf is a relative path/);
});

test("settings: iniValues is linear on a hostile line (a key, then spaces and no separator); the first = or : separates", () => {
  // 128 KiB first: the lazy-group regex took seconds there (found in review), and fails here instead of timing out.
  for (const n of [128 * 1024, 1024 * 1024]) {
    for (const line of [`a${" ".repeat(n)}`, `[global]\n${"a ".repeat(n / 2)}`, `${"a\t".repeat(n / 2)}=`, `x=${" ".repeat(n)}`]) {
      const t0 = performance.now();
      iniValues(line);
      const ms = performance.now() - t0;
      assert.ok(ms < 1000, `${n} bytes: ${ms.toFixed(0)} ms`);
    }
  }
  assert.deepStrictEqual(iniValues("[global]\nk: v=w\nx = y: z\nno separator here\n= empty key\n"), [
    { section: "global", key: "k", value: "v=w" },
    { section: "global", key: "x", value: "y: z" },
  ]);
});

test("settings: the probe runs python3 with a 15 s limit, SIGKILL, at most 1 MiB of output, from the filesystem root", () => {
  const calls: [string, string[], SpawnSyncOptions][] = [];
  const recorder = (result: object) =>
    ((cmd: string, args: string[], o: SpawnSyncOptions) => {
      calls.push([cmd, args, o]);
      return { pid: 1, output: [], stdout: "", stderr: "", status: null, signal: null, ...result };
    }) as unknown as typeof spawnSync;
  // python3 is found on PATH in node and run by its absolute path (src/exec.ts).
  const bin = tmp("ws-pyset-py-");
  writeFileSync(join(bin, "python3"), "#!/bin/sh\nexit 0\n");
  chmodSync(join(bin, "python3"), 0o755);
  assert.deepStrictEqual(pipConfigProbe({ PATH: `:relative:${bin}` }, recorder({ status: 0 }))(["config", "list"]), { code: 0, stdout: "" });
  const [cmd, args, o] = calls[0]!;
  assert.deepStrictEqual([cmd, args], [join(bin, "python3"), ["-m", "pip", "config", "list"]]);
  assert.equal(PROBE_TIMEOUT_MS, 15_000);
  assert.equal(MAX_PROBE_OUTPUT, 1024 * 1024);
  assert.deepStrictEqual(
    { timeout: o.timeout, killSignal: o.killSignal, maxBuffer: o.maxBuffer, cwd: o.cwd, stdio: o.stdio },
    { timeout: 15_000, killSignal: "SIGKILL", maxBuffer: 1024 * 1024, cwd: parse(process.cwd()).root, stdio: ["ignore", "pipe", "ignore"] },
  );
  // A timeout or too much output (spawnSync's error, no exit code) is "did not finish"; no python3 is "unavailable".
  const err = (code: string) => Object.assign(new Error(`spawnSync python3 ${code}`), { code });
  assert.deepStrictEqual(pipConfigProbe({ PATH: bin }, recorder({ error: err("ETIMEDOUT") }))(["config", "list"]), { code: null, stdout: "" });
  assert.deepStrictEqual(pipConfigProbe({ PATH: bin }, recorder({ error: err("ENOBUFS") }))(["config", "list"]), { code: null, stdout: "" });
  assert.equal(pipConfigProbe({ PATH: bin }, recorder({ error: err("ENOENT") }))(["config", "list"]), "unavailable");
  assert.equal(pipConfigProbe({}, recorder({ status: 0 }))(["config", "list"]), "unavailable", "no python3 on PATH");
});

test("settings: a python3 inside the scanned tree is never run, whether its PATH entry or the file itself is there", () => {
  const calls: string[] = [];
  const recorder = ((cmd: string) => {
    calls.push(cmd);
    return { pid: 1, output: [], stdout: "", stderr: "", status: 0, signal: null };
  }) as unknown as typeof spawnSync;
  const scanned = tmp("ws-pyset-tree-");
  mkdirSync(join(scanned, "bin"));
  writeFileSync(join(scanned, "bin", "python3"), "#!/bin/sh\nexit 0\n");
  chmodSync(join(scanned, "bin", "python3"), 0o755);
  const outside = tmp("ws-pyset-out-");
  // A link outside the tree to the tree's python3 (an activated in-tree venv reached through another directory).
  symlinkSync(join(scanned, "bin", "python3"), join(outside, "python3"));
  for (const PATH of [join(scanned, "bin"), `${join(scanned, "bin")}:/usr/bin`, outside]) {
    const r = pipConfigProbe({ PATH }, recorder, scanned)(["config", "list"]);
    assert.ok(typeof r === "object" && "notRun" in r, `${PATH}: ${JSON.stringify(r)}`);
    assert.match(r.notRun, /^python3 on PATH is .*python3, inside the scanned tree, so it was not run$/);
  }
  assert.deepStrictEqual(calls, []);
  // Through discovery: pip's configuration counts as not read, so the requirements entries are sent nowhere.
  writeFileSync(join(scanned, "requirements.txt"), "--require-hashes\nsix==1.17.0 --hash=sha256:" + "a".repeat(64) + "\n");
  const d = disc(scanned, { PATH: join(scanned, "bin") }, { pipConfig: pipConfigProbe({ PATH: join(scanned, "bin") }, recorder, scanned) });
  assert.ok(d.notes.some((n) => /^pip's configuration was not read \(python3 on PATH is .*, inside the scanned tree, so it was not run\)/.test(n)), JSON.stringify(d.notes));
  assert.match(d.locks[0]!.packages[0]!.unsent ?? "", /pip's configuration was not read/);
  assert.deepStrictEqual(calls, []);
});
