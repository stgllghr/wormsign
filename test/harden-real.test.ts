// harden-dev.sh H12 and H13 against the REAL pip and uv, not the stubs. Opt-in: it runs only with HARDEN_REAL=1, and
// only against pinned versions, the ones docs/evidence/package-managers.md reports as verified:
//
//   HARDEN_REAL=1 HARDEN_REAL_PYTHON=<python3 whose pip is 26.1.2 or 26.2.1> \
//   HARDEN_REAL_PIP3=<optional: a pip3 of the other of those two versions> \
//   HARDEN_REAL_UV=<uv 0.10.9 or 0.12.21>[:<the other>] node scripts/run-tests.mjs dist/test/harden-real.test.js
//
// Every run gets its own HOME and TMPDIR, an empty directory each as XDG_DATA_DIRS and XDG_CONFIG_DIRS, and no other
// XDG_* variable (so the XDG user defaults lie in that HOME; one case sets XDG_DATA_HOME to a temp directory), and a
// PATH that holds only those tools (for the pip cases, the directory of HARDEN_REAL_PYTHON), node and a few system
// utilities, so /usr/bin's python3 and pip3 are never found. No user or XDG config of the developer's is read. The
// system-wide files the real tools would still read are asserted absent (pip's global and site files, as `pip config
// debug` lists them in that environment, and /etc/uv/uv.toml): the tests skip, naming them, when one exists. Nothing
// is installed and the network is not used: pip only reads and writes its config, and uv locks an empty project
// offline.
import { after, describe, test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { accessSync, chmodSync, constants, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { privateBase } from "./harden-sandbox.js";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const SCRIPT = join(ROOT, "harden-dev.sh");
const ENABLED = process.env["HARDEN_REAL"] === "1";
const PINNED_PIP = ["26.1.2", "26.2.1"];
const PINNED_UV = ["0.10.9", "0.12.21"];
const PYTHON = process.env["HARDEN_REAL_PYTHON"] ?? "python3";
const PIP3 = process.env["HARDEN_REAL_PIP3"];
const UVS = (process.env["HARDEN_REAL_UV"] ?? "uv").split(":").filter(Boolean);
const IS_ROOT = process.getuid?.() === 0;

function which(name: string): string | undefined {
  if (name.includes("/")) return existsSync(name) ? name : undefined;
  for (const d of ["/usr/bin", "/bin", ...(process.env["PATH"] ?? "").split(":")]) {
    try {
      accessSync(join(d, name), constants.X_OK);
      return join(d, name);
    } catch {
      // keep looking
    }
  }
  return undefined;
}
const versionOf = (cmd: string[], re: RegExp): string => {
  const r = spawnSync(cmd[0] as string, cmd.slice(1), { encoding: "utf8", env: { PATH: "/usr/bin:/bin", HOME: tmpdir(), PIP_DISABLE_PIP_VERSION_CHECK: "1" } });
  return re.exec(`${r.stdout}${r.stderr}`)?.[1] ?? `none (${cmd.join(" ")} printed ${JSON.stringify((r.stdout + r.stderr).slice(0, 120))})`;
};

// A private directory (test/harden-sandbox.ts), so that each run's TMPDIR is one the script uses.
const SANDBOX = mkdtempSync(join(privateBase(), "wormsign-harden-real-"));
after(() => {
  spawnSync("chmod", ["-R", "u+rwX", SANDBOX]);
  rmSync(SANDBOX, { recursive: true, force: true });
});
// The system utilities harden-dev.sh needs, as in test/harden.test.ts, and nothing else from /usr/bin (macOS has a
// python3 and a pip3 there).
const TOOLS = join(SANDBOX, "tools");
mkdirSync(TOOLS, { mode: 0o700 });
symlinkSync(process.execPath, join(TOOLS, "node"));
for (const t of ["awk", "sed", "grep", "find", "cat", "cp", "mkdir", "mktemp", "rm", "date", "tr", "cut", "sort", "head",
  "tail", "wc", "basename", "dirname", "uname", "chmod", "stat", "shasum", "sha256sum", "ls", "cmp", "env"]) {
  const p = which(t);
  if (p) symlinkSync(p, join(TOOLS, t));
}

interface Run { code: number; out: string; home: string; tmp: string }
let runs = 0;
/**
 * One harden-dev.sh run with PATH = TOOLS, then `bins` (directories), in a fresh HOME unless one is given, with empty
 * XDG_DATA_DIRS and XDG_CONFIG_DIRS directories (pip 26.2 takes its global file, and uv its system uv.toml, from them).
 */
function harden(bins: string[], o: { args?: string[]; home?: string; env?: Record<string, string>; files?: Record<string, string>; tmpFiles?: Record<string, string> } = {}): Promise<Run> {
  const root = join(SANDBOX, `run${++runs}`);
  const home = o.home ?? join(root, "home");
  const tmp = join(root, "tmp");
  const xdg = { XDG_DATA_DIRS: join(root, "xdg-data"), XDG_CONFIG_DIRS: join(root, "xdg-config") };
  for (const d of [home, tmp, ...Object.values(xdg)]) mkdirSync(d, { recursive: true, mode: 0o700 });
  for (const [rel, text] of Object.entries(o.files ?? {})) {
    mkdirSync(dirname(join(home, rel)), { recursive: true });
    writeFileSync(join(home, rel), text, { mode: 0o600 });
  }
  for (const [rel, text] of Object.entries(o.tmpFiles ?? {})) writeFileSync(join(tmp, rel), text);
  const env = { HOME: home, TMPDIR: tmp, PATH: [TOOLS, ...bins].join(":"), LANG: "C", ...xdg, ...o.env };
  return new Promise((resolve, reject) => {
    const child = spawn("/bin/bash", [SCRIPT, "--offline", ...(o.args ?? [])], { cwd: root, env });
    let out = "";
    child.stdout.on("data", (d: Buffer) => (out += d.toString()));
    child.stderr.on("data", (d: Buffer) => (out += d.toString()));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? -1, out, home, tmp }));
  });
}
const lines = (out: string, id: string): string[] => out.split("\n").filter((l) => new RegExp(`^\\[[A-Z]+\\] +${id} `).test(l));
const status = (out: string, id: string): string[] => lines(out, id).map((l) => l.slice(1, 5));
function snapshot(dir: string): Map<string, string> {
  const m = new Map<string, string>();
  const walk = (d: string): void => {
    for (const e of readdirSync(d)) {
      const p = join(d, e);
      const st = lstatSync(p);
      if (st.isDirectory()) {
        m.set(relative(dir, p), "dir");
        walk(p);
      } else m.set(relative(dir, p), `${(st.mode & 0o777).toString(8)}:${createHash("sha256").update(readFileSync(p)).digest("hex")}`);
    }
  };
  walk(dir);
  return m;
}
/** A directory holding only `name`, a symlink to `target`. */
function binDir(name: string, target: string): string {
  const d = mkdtempSync(join(SANDBOX, `bin-${name}-`));
  symlinkSync(target, join(d, name));
  return d;
}

/**
 * The system-wide config files that exist and that the real pip (each pip under test) or uv would read in the
 * environment harden() gives them: pip's global and site files, as `pip config debug` lists them there, and uv's
 * /etc/uv/uv.toml (its fallback when XDG_CONFIG_DIRS holds no uv/uv.toml).
 */
function systemFiles(): string[] {
  const dir = mkdtempSync(join(SANDBOX, "system-"));
  const env = { HOME: dir, PATH: "/usr/bin:/bin", PIP_DISABLE_PIP_VERSION_CHECK: "1", XDG_DATA_DIRS: dir, XDG_CONFIG_DIRS: dir };
  const found: string[] = [];
  for (const cmd of [[which(PYTHON) ?? PYTHON, "-m", "pip"], ...(PIP3 ? [[PIP3]] : [])]) {
    const r = spawnSync(cmd[0] as string, [...cmd.slice(1), "config", "debug"], { encoding: "utf8", env, cwd: dir });
    let variant = "";
    for (const line of r.stdout.split("\n")) {
      const v = /^(\S+):$/.exec(line);
      if (v) variant = v[1] as string;
      const f = /^ {2}(.+), exists: True$/.exec(line);
      if (f && (variant === "global" || variant === "site")) found.push(f[1] as string);
    }
  }
  if (existsSync("/etc/uv/uv.toml")) found.push("/etc/uv/uv.toml");
  return found;
}
const present = ENABLED ? systemFiles() : [];
const skip = !ENABLED
  ? "set HARDEN_REAL=1 to run harden-dev.sh against the real pip and uv (HARDEN_REAL_PYTHON, HARDEN_REAL_PIP3, HARDEN_REAL_UV)"
  : present.length > 0
    ? `system-wide config the real pip or uv would read exists, so results would not be the isolated ones: ${present.join(", ")}`
    : false;

describe("harden-dev.sh H12 against the real pip", { skip, concurrency: 1, timeout: 300_000 }, () => {
  const python = which(PYTHON) ?? PYTHON;
  // The python's own bin directory: a virtual environment's python only knows it is one when run from there.
  const pyBin = dirname(python);
  const pip = versionOf([python, "-m", "pip", "--version"], /^pip (\S+) /m);
  const userFile = (home: string) => join(home, ".config", "pip", "pip.conf");

  test(`the pip under test is pinned (${PINNED_PIP.join(" or ")}): ${python} -m pip is ${pip}`, () => {
    assert.ok(PINNED_PIP.includes(pip), `${python} -m pip is ${pip}`);
  });

  test("check mode: unset is a FAIL and nothing is written", async () => {
    const r = await harden([pyBin]);
    assert.match(lines(r.out, "H12").join("\n"), /^\[FAIL\] H12 +pip \S+ \(python3 -m pip.*\): uploaded-prior-to: unset for pip install, download, lock and wheel/, r.out);
    assert.deepEqual(readdirSync(r.home), [], "check mode wrote into HOME");
    assert.deepEqual(readdirSync(r.tmp), [], "temp files left behind");
  });

  test("--apply writes [global] through pip and drops comments (the backup keeps them); a second run changes nothing", async () => {
    const original = "# mine\n[global]\nindex-url = https://pypi.org/simple/\nuploaded-prior-to = P1D\n";
    const r = await harden([pyBin], { args: ["--apply"], files: { ".config/pip/pip.conf": original } });
    assert.deepEqual(status(r.out, "H12"), ["INFO", "PASS"], r.out);
    assert.equal(readFileSync(userFile(r.home), "utf8"), "[global]\nindex-url = https://pypi.org/simple/\nuploaded-prior-to = P7D\n\n");
    const b = readdirSync(dirname(userFile(r.home))).filter((f) => f.startsWith("pip.conf.wormsign-bak."));
    assert.equal(b.length, 1);
    assert.equal(readFileSync(join(dirname(userFile(r.home)), b[0] as string), "utf8"), original);
    const before = snapshot(r.home);
    const again = await harden([pyBin], { args: ["--apply"], home: r.home });
    assert.deepEqual(status(again.out, "H12"), ["PASS"], again.out);
    assert.doesNotMatch(again.out, /backup:|wrote /);
    assert.deepEqual([...snapshot(r.home)].filter(([k, v]) => before.get(k) !== v), [], "second --apply changed files");
  });

  test("--apply creates the user file when there is none, and pip's own read-back sees P7D", async () => {
    const r = await harden([pyBin], { args: ["--apply"] });
    assert.deepEqual(status(r.out, "H12"), ["INFO", "PASS"], r.out);
    assert.equal(readFileSync(userFile(r.home), "utf8"), "[global]\nuploaded-prior-to = P7D\n\n");
    const get = spawnSync(python, ["-m", "pip", "config", "get", "global.uploaded-prior-to"], { encoding: "utf8", env: { HOME: r.home, PATH: "/usr/bin:/bin", PIP_DISABLE_PIP_VERSION_CHECK: "1" } });
    assert.equal(get.stdout.trim(), "P7D");
  });

  test("a write pip refuses (read-only file) is a FAIL, and the file is unchanged", { skip: IS_ROOT && "root ignores file modes" }, async () => {
    const r = await harden([pyBin], { files: { ".config/pip/pip.conf": "[global]\nuploaded-prior-to = P1D\n" } });
    chmodSync(userFile(r.home), 0o400);
    const a = await harden([pyBin], { args: ["--apply"], home: r.home });
    chmodSync(userFile(r.home), 0o600);
    assert.match(lines(a.out, "H12").join("\n"), /\[FAIL\] H12 +pip: could not write global\.uploaded-prior-to with .*; the user config files are as they were/, a.out);
    assert.equal(readFileSync(userFile(r.home), "utf8"), "[global]\nuploaded-prior-to = P1D\n");
  });

  test("a pip config file pip cannot load (a duplicate key) is a WARN, and --apply leaves it alone", async () => {
    const broken = "[global]\nuploaded-prior-to = P1D\nuploaded-prior-to = P30D\n";
    const r = await harden([pyBin], { args: ["--apply"], files: { ".config/pip/pip.conf": broken } });
    assert.match(lines(r.out, "H12").join("\n"), /^\[WARN\] H12 +python3 -m pip .* did not report a version .*already exists/, r.out);
    assert.equal(readFileSync(userFile(r.home), "utf8"), broken);
  });

  test("an [install] value, and an empty value in the file pip reads last or first: judged as pip reads them", async () => {
    const install = await harden([pyBin], { files: { ".config/pip/pip.conf": "[global]\nuploaded-prior-to = P7D\n[install]\nuploaded-prior-to = P1D\n" } });
    assert.match(lines(install.out, "H12").join("\n"), /\[install\] "P1D" in \S+ is shorter than P7D/, install.out);
    // pip reads ~/.pip/pip.conf, then ~/.config/pip/pip.conf: per section the last value wins, and an empty one clears it.
    const empty = await harden([pyBin], { files: { ".config/pip/pip.conf": "[global]\nuploaded-prior-to =\n", ".pip/pip.conf": "[global]\nuploaded-prior-to = P30D\n" } });
    assert.match(lines(empty.out, "H12").join("\n"), /uploaded-prior-to: unset for pip install, download, lock and wheel \(cleared by an empty value/, empty.out);
    const first = await harden([pyBin], { files: { ".pip/pip.conf": "[global]\nuploaded-prior-to =\n", ".config/pip/pip.conf": "[global]\nuploaded-prior-to = P30D\n" } });
    assert.deepEqual(status(first.out, "H12"), ["PASS"], first.out);
  });

  test("pip's own quiet and verbose settings: still judged, and --apply leaves the file alone when [global] passes", async () => {
    const quiet = await harden([pyBin], { files: { ".config/pip/pip.conf": "[global]\nquiet = 1\nuploaded-prior-to = P7D\n" } });
    assert.deepEqual(status(quiet.out, "H12"), ["PASS"], quiet.out);
    const text = "# mine\n[global]\nverbose = 1\nuploaded-prior-to = P7D\n[install]\nuploaded-prior-to = P1D\n";
    const verbose = await harden([pyBin], { args: ["--apply"], files: { ".config/pip/pip.conf": text } });
    assert.match(lines(verbose.out, "H12").join("\n"), /not fixed by --apply: for python3 -m pip, \[global\] already says "P7D"/, verbose.out);
    assert.equal(readFileSync(userFile(verbose.home), "utf8"), text);
    assert.deepEqual(readdirSync(dirname(userFile(verbose.home))), ["pip.conf"], "a backup was made");
  });

  test("--apply does not lower a stricter system-wide [global] when the failing value is elsewhere (pip 26.2 reads its global file from XDG_DATA_DIRS)", { skip: pip !== "26.2.1" && `python3 -m pip is ${pip}; pip 26.1 on macOS takes its global file from fixed system paths` }, async () => {
    const sys = mkdtempSync(join(SANDBOX, "sysdata-"));
    mkdirSync(join(sys, "pip"));
    writeFileSync(join(sys, "pip", "pip.conf"), "[global]\nuploaded-prior-to = P30D\n[install]\nuploaded-prior-to = P1D\n");
    const r = await harden([pyBin], { args: ["--apply"], env: { XDG_DATA_DIRS: sys } });
    assert.match(lines(r.out, "H12").join("\n"), /\[install\] "P1D" in \S+ is shorter than P7D \(want P7D or longer; not fixed by --apply: for python3 -m pip, \[global\] already says "P30D"/, r.out);
    assert.equal(existsSync(userFile(r.home)), false, "--apply wrote a user [global] over the system's P30D");
  });

  test("two pips reading different user files: --apply writes one, and the read-back FAILs the other", { skip: !PIP3 && "set HARDEN_REAL_PIP3 to a pip3 of the other pinned version" }, async () => {
    const pip3 = PIP3 as string;
    const v3 = versionOf([pip3, "--version"], /^pip (\S+) /m);
    assert.ok(PINNED_PIP.includes(v3) && v3 !== pip, `HARDEN_REAL_PIP3 is pip ${v3}, python3 -m pip is ${pip}`);
    // pip 26.2 on macOS reads $XDG_DATA_HOME/pip/pip.conf when that directory exists; pip 26.1 reads ~/.config/pip.
    const root = mkdtempSync(join(SANDBOX, "xdg-"));
    mkdirSync(join(root, "data", "pip"), { recursive: true });
    const r = await harden([binDir("pip3", pip3), pyBin], { args: ["--apply"], env: { XDG_DATA_HOME: join(root, "data") } });
    assert.deepEqual(status(r.out, "H12"), ["INFO", "PASS", "FAIL"], r.out);
    assert.match(lines(r.out, "H12")[2] ?? "", /: uploaded-prior-to: unset for pip install, download, lock and wheel \(.*but this pip still reports the above: it reads another file/);
  });
});

describe("harden-dev.sh H13 against the real uv", { skip, concurrency: 1, timeout: 300_000 }, () => {
  // uv needs a Python to lock even an empty project, and must not download one.
  const python = which(PYTHON) ?? PYTHON;
  for (const uvPath of UVS) {
    const uv = which(uvPath) ?? uvPath;
    const v = versionOf([uv, "--version"], /^uv (\S+)/m);
    const bins = [binDir("uv", uv), binDir("python3", python)];
    const uvToml = (text: string) => ({ ".config/uv/uv.toml": text });

    test(`uv ${v} (${uv}) is pinned (${PINNED_UV.join(" or ")})`, () => assert.ok(PINNED_UV.includes(v), `${uv} is ${v}`));

    test(`uv ${v}: unset FAILs, 7 days PASSes, 1 day FAILs; HOME and TMPDIR are left as they were`, async () => {
      const unset = await harden(bins);
      assert.match(lines(unset.out, "H13").join("\n"), /^\[FAIL\] H13 +uv \S+: no exclude-newer applies outside a project/, unset.out);
      assert.deepEqual(readdirSync(unset.home), []);
      assert.deepEqual(readdirSync(unset.tmp), []);
      const ok = await harden(bins, { files: uvToml('exclude-newer = "7 days"\n') });
      assert.deepEqual(lines(ok.out, "H13"), [`[PASS] H13  uv ${v}: exclude-newer-span = "P7D" (7 days), from 'uv lock' on an empty project`], ok.out);
      const short = await harden(bins, { files: uvToml('exclude-newer = "1 day"\n') });
      assert.match(lines(short.out, "H13").join("\n"), /^\[FAIL\] H13 +uv \S+: exclude-newer-span = "P1D" is shorter than 7d/, short.out);
    });

    test(`uv ${v}: a uv.toml or workspace pyproject.toml above the temp directory is not read`, async () => {
      const r = await harden(bins, {
        files: uvToml('exclude-newer = "1 day"\n'),
        tmpFiles: {
          "uv.toml": 'exclude-newer = "30 days"\n',
          "pyproject.toml": '[project]\nname = "outer"\nversion = "0"\ndependencies = []\n[tool.uv]\nexclude-newer = "30 days"\n[tool.uv.workspace]\nmembers = ["*/*"]\n',
        },
      });
      assert.match(lines(r.out, "H13").join("\n"), /^\[FAIL\] H13 +uv \S+: exclude-newer-span = "P1D"/, r.out);
      assert.deepEqual(readdirSync(r.tmp).sort(), ["pyproject.toml", "uv.toml"], "uv wrote a lock above the probe");
    });

    test(`uv ${v}: exclude-newer-package, [pip] exclude-newer and [pip] exclude-newer-package shorter than the soak are WARNs`, async () => {
      const r = await harden(bins, {
        files: uvToml('exclude-newer = "7 days"\nexclude-newer-package = { six = "1 day" }\n\n[pip]\nexclude-newer = "2 days"\nexclude-newer-package = { idna = "3 days" }\n'),
      });
      assert.deepEqual(status(r.out, "H13"), ["PASS", "WARN", "WARN", "WARN"], r.out);
      assert.match(r.out, /exclude-newer-package lets six through after 1 day/);
      assert.match(r.out, /\[pip\] exclude-newer = "2 days" in \S+ is shorter than 7d \(2 days\)/);
      assert.match(r.out, /\[pip\] exclude-newer-package for "idna" = "3 days" in \S+ is shorter than 7d \(3 days\)/);
    });

    test(`uv ${v}: a default [[index]] with exclude-newer = false FAILs from uv 0.11.5 (0.10.9 ignores the key)`, async () => {
      const r = await harden(bins, { files: uvToml('exclude-newer = "7 days"\n\n[[index]]\nname = "pypi"\nurl = "https://pypi.org/simple"\ndefault = true\nexclude-newer = false\n') });
      const want = v === "0.10.9" ? ["PASS"] : ["PASS", "FAIL"];
      assert.deepEqual(status(r.out, "H13"), want, r.out);
    });

    test(`uv ${v}: UV_PROJECT naming a project is not locked by the probe`, async () => {
      const project = mkdtempSync(join(SANDBOX, "project-"));
      writeFileSync(join(project, "pyproject.toml"), '[project]\nname = "mine"\nversion = "0"\ndependencies = []\n\n[tool.uv]\nexclude-newer = "30 days"\n');
      for (const env of [{ UV_PROJECT: project }, { UV_WORKING_DIR: project }, { UV_FROZEN: "1" }] as Record<string, string>[]) {
        const r = await harden(bins, { env, files: uvToml('exclude-newer = "1 day"\n') });
        assert.match(lines(r.out, "H13").join("\n"), /^\[FAIL\] H13 +uv \S+: exclude-newer-span = "P1D" is shorter than 7d/, `${JSON.stringify(env)}: ${r.out}`);
        assert.deepEqual(readdirSync(project), ["pyproject.toml"], JSON.stringify(env));
      }
    });
  }
});
