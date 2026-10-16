// Tests for harden-dev.sh. Each run gets a fresh HOME and TMPDIR and a PATH holding only
// stub package managers (test/fixtures/harden/bin) and a few system utilities, so no real
// npm/pnpm/yarn/bun/gh/python3/pip/uv and no network is ever used. The stubs read the same files
// and environment variables as the real tools (see test/fixtures/harden/stub.mjs). The real pip
// and uv are run only by test/harden-real.test.ts, and only when HARDEN_REAL=1.
import { after, describe, test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  accessSync,
  chmodSync,
  constants,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { ENFORCED_SINCE, checkSoakConfig } from "../src/soak-config.js";
import { privateBase } from "./harden-sandbox.js";
import { escapeRegExp, fx } from "./helpers.js";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const SCRIPT = join(ROOT, "harden-dev.sh");
const STUBS = fx("harden", "bin");
const PNPM_DIR = process.platform === "darwin" ? "Library/Preferences/pnpm" : ".config/pnpm";
const IS_ROOT = process.getuid?.() === 0;
// A private directory (test/harden-sandbox.ts), so that each run's TMPDIR is one the script uses.
const SANDBOX = mkdtempSync(join(privateBase(), "wormsign-harden-"));
after(() => rmSync(SANDBOX, { recursive: true, force: true }));

function which(name: string): string | undefined {
  const dirs = ["/usr/bin", "/bin", "/usr/sbin", "/sbin", ...(process.env["PATH"] ?? "").split(":")];
  for (const d of dirs) {
    const p = join(d, name);
    try {
      accessSync(p, constants.X_OK);
      return p;
    } catch {
      // keep looking
    }
  }
  return undefined;
}

// System utilities the script (and the stubs' `#!/usr/bin/env node`) need, and nothing else.
const TOOLS = join(SANDBOX, "tools");
mkdirSync(TOOLS, { mode: 0o700 });
symlinkSync(process.execPath, join(TOOLS, "node"));
for (const t of ["awk", "sed", "grep", "find", "cat", "cp", "mkdir", "mktemp", "rm", "date", "tr", "cut", "sort", "head",
  "tail", "wc", "basename", "dirname", "uname", "chmod", "stat", "shasum", "sha256sum", "ls", "cmp", "env"]) {
  const p = which(t);
  if (p) symlinkSync(p, join(TOOLS, t));
}

// Every distinct bash to run the whole suite under: macOS /bin/bash is 3.2.
const BASHES = [...new Set([process.env["HARDEN_TEST_BASH"], "/bin/bash", which("bash")]
  .filter((b): b is string => !!b && existsSync(b)).map((b) => realpathSync(b)))];

type Tool = "npm" | "pnpm" | "yarn" | "bun" | "gh" | "stat" | "python3" | "pip3" | "pip" | "uv" | "poetry" | "pdm" | "pipenv";
interface RunOpts {
  args?: string[];
  tools?: Partial<Record<Tool, string>>; // tool -> version ("" for tools without one; python3's is its pip's)
  env?: Record<string, string>;
  files?: Record<string, string>; // HOME-relative path -> content
  tmpFiles?: Record<string, string>; // TMPDIR-relative path -> content
  home?: string; // reuse a HOME from an earlier run
  cwd?: string;
  script?: string;
  pathPrefix?: string; // put before the stub and tool directories in PATH
}
interface StubCall {
  tool: string;
  args: string[];
  cwd: string;
  corepackNetwork: string | null;
  pipVersionCheck: string | null;
  virtualEnv: string | null;
  uvCache: string | null;
  uvPythonDownloads: string | null;
  probe: string | null;
}
interface Run { code: number; out: string; home: string; root: string; calls: StubCall[]; tmpLeft: string[] }

let runs = 0;
const scratch = (prefix: string): string => mkdtempSync(join(SANDBOX, prefix));
function runWith(bash: string, o: RunOpts = {}): Promise<Run> {
  const root = join(SANDBOX, `run${++runs}`);
  const home = o.home ?? join(root, "home");
  const bin = join(root, "bin");
  const tmp = join(root, "tmp");
  // 0700, whatever the umask: TMPDIR must be private for the script to use it (private_dir).
  for (const d of [home, bin, tmp]) mkdirSync(d, { recursive: true, mode: 0o700 });
  for (const [rel, content] of Object.entries(o.files ?? {})) {
    mkdirSync(dirname(join(home, rel)), { recursive: true });
    writeFileSync(join(home, rel), content, { mode: 0o600 });
  }
  for (const [rel, content] of Object.entries(o.tmpFiles ?? {})) {
    mkdirSync(dirname(join(tmp, rel)), { recursive: true });
    writeFileSync(join(tmp, rel), content);
  }
  const env: Record<string, string> = { HOME: home, TMPDIR: tmp, PATH: `${o.pathPrefix ?? ""}${bin}:${TOOLS}`, STUB_LOG: join(root, "stub.log") };
  for (const [tool, version] of Object.entries(o.tools ?? {})) {
    symlinkSync(join(STUBS, tool), join(bin, tool));
    if (version) env[`STUB_${tool.toUpperCase()}_VERSION`] = version;
  }
  Object.assign(env, o.env);
  return new Promise((resolve, reject) => {
    const child = spawn(bash, [o.script ?? SCRIPT, ...(o.args ?? [])], { cwd: o.cwd ?? root, env });
    let out = "";
    child.stdout.on("data", (d: Buffer) => (out += d.toString()));
    child.stderr.on("data", (d: Buffer) => (out += d.toString()));
    child.on("error", reject);
    child.on("close", (code) => {
      const log = join(root, "stub.log");
      const calls = existsSync(log)
        ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as StubCall)
        : [];
      resolve({ code: code ?? -1, out, home, root, calls, tmpLeft: readdirSync(tmp).filter((f) => !(f in (o.tmpFiles ?? {}))) });
    });
  });
}

/** HOME-relative path -> "mode:sha256" for every file, and "dir" for directories. */
function snapshot(dir: string): Map<string, string> {
  const m = new Map<string, string>();
  const walk = (d: string): void => {
    for (const e of readdirSync(d)) {
      const p = join(d, e);
      const st = lstatSync(p);
      if (st.isDirectory()) {
        m.set(relative(dir, p), "dir");
        walk(p);
      } else {
        m.set(relative(dir, p), `${(st.mode & 0o777).toString(8)}:${createHash("sha256").update(readFileSync(p)).digest("hex")}`);
      }
    }
  };
  walk(dir);
  return m;
}
function changed(before: Map<string, string>, afterRun: Map<string, string>): string[] {
  const keys = new Set([...before.keys(), ...afterRun.keys()]);
  return [...keys].filter((k) => before.get(k) !== afterRun.get(k)).sort();
}
/** The report lines for one check id, e.g. lines(out, "H01") -> ["[FAIL] H01  npm ..."]. */
const lines = (out: string, id: string): string[] => out.split("\n").filter((l) => new RegExp(`^\\[[A-Z]+\\] +${id} `).test(l));
const status = (out: string, id: string): string[] => lines(out, id).map((l) => l.slice(1, 5));
const home = (r: Run, rel: string): string => readFileSync(join(r.home, rel), "utf8");
const backups = (dir: string, base: string): string[] => readdirSync(dir).filter((f) => f.startsWith(`${base}.wormsign-bak.`));

// Dates relative to now, for pip's absolute uploaded-prior-to values and uv's fixed exclude-newer.
const DAY = 864e5;
const ago = (ms: number): Date => new Date(Date.now() - ms);
const isoDate = (d: Date): string => d.toISOString().slice(0, 10);
const isoNaive = (d: Date): string => d.toISOString().slice(0, 19);
const isoZ = (d: Date): string => `${d.toISOString().slice(0, 19)}Z`;
const PIP_USER = ".config/pip/pip.conf";
const UV_USER = ".config/uv/uv.toml";

for (const bash of BASHES) {
  const run = (o?: RunOpts) => runWith(bash, o);

  describe(`harden-dev.sh under ${bash}`, { concurrency: 8, timeout: 120_000 }, () => {
    test("usage errors exit 2", async () => {
      assert.equal((await run({ args: ["--soak", "3x"] })).code, 2);
      assert.equal((await run({ args: ["--bogus"] })).code, 2);
      const r = await run({ args: ["--path", "/nonexistent/wormsign-test"] });
      assert.equal(r.code, 2);
      assert.match(r.out, /--path \/nonexistent\/wormsign-test: not a directory/);
    });

    test("the default soak is 7 days (npm 7, pnpm and Yarn 10080 minutes, bun 604800 seconds); --soak 72h is the tuned value", async () => {
      const banner = (r: Run) => r.out.split("\n").find((l) => l.startsWith("wormsign harden-dev: "));
      assert.equal(banner(await run()), "wormsign harden-dev: mode=check soak=7d (npm 7d, pnpm/yarn 10080min, bun 604800s)");
      assert.equal(banner(await run({ args: ["--soak", "72h"] })), "wormsign harden-dev: mode=check soak=72h (npm 3d, pnpm/yarn 4320min, bun 259200s)");
      assert.match((await run({ args: ["--help"] })).out, /--soak <duration> +release-age cooldown to require: 7d, 72h, 2w \(default 7d\)/);
      const tools = { npm: "11.21.0", pnpm: "11.16.0", yarn: "4.10.3", python3: "26.1.2" };
      const def = await run({ tools, args: ["--apply"] });
      assert.equal(def.code, 0, def.out);
      assert.equal(home(def, PIP_USER), "[global]\nuploaded-prior-to = P7D\n\n");
      assert.equal(home(def, ".npmrc"), "ignore-scripts=true\nmin-release-age=7\n");
      assert.equal(home(def, `${PNPM_DIR}/config.yaml`), "minimumReleaseAge: 10080\n");
      assert.equal(home(def, ".yarnrc.yml"), "npmMinimalAgeGate: 10080\nenableScripts: false\n");
      const tuned = await run({ tools, args: ["--apply", "--soak", "72h"] });
      assert.equal(tuned.code, 0, tuned.out);
      assert.equal(home(tuned, PIP_USER), "[global]\nuploaded-prior-to = P3D\n\n");
      // uv is checked, not written: 3 days pass a 72h soak and fail the 7-day default.
      const uv = { files: { [UV_USER]: 'exclude-newer = "3 days"\n' }, tools: { uv: "0.12.21" } };
      assert.deepEqual(status((await run({ ...uv, args: ["--soak", "72h"] })).out, "H13"), ["PASS"]);
      assert.deepEqual(status((await run(uv)).out, "H13"), ["FAIL"]);
      assert.equal(home(tuned, ".npmrc"), "ignore-scripts=true\nmin-release-age=3\n");
      assert.equal(home(tuned, `${PNPM_DIR}/config.yaml`), "minimumReleaseAge: 4320\n");
      assert.equal(home(tuned, ".yarnrc.yml"), "npmMinimalAgeGate: 4320\nenableScripts: false\n");
    });

    test("with no tools installed: SKIPs, PASSes where nothing is found, writes nothing, exits 0", async () => {
      const r = await run();
      assert.equal(r.code, 0, r.out);
      for (const id of ["H01", "H02", "H03", "H04", "H05", "H06", "H07", "H09", "H11", "H12", "H13"]) assert.deepEqual(status(r.out, id), ["SKIP"], id);
      for (const id of ["H08", "H10"]) assert.deepEqual(status(r.out, id), ["PASS"], id);
      assert.deepEqual(readdirSync(r.home), []);
      assert.deepEqual(r.tmpLeft, [], "temp files left behind");
    });

    describe("H01/H02 npm", () => {
      test("FAIL when ignore-scripts and min-release-age are unset; check mode writes nothing", async () => {
        const r = await run({ tools: { npm: "11.21.0" }, files: { ".npmrc": "color=false\n" } });
        const before = snapshot(r.home);
        assert.equal(r.code, 1);
        assert.match(lines(r.out, "H01")[0] ?? "", /^\[FAIL\] H01 +.*ignore-scripts is false \(want true; fixable with --apply/);
        assert.match(lines(r.out, "H02")[0] ?? "", /^\[FAIL\] H02 +.*min-release-age is unset \(want >= 7;/);
        assert.deepEqual(changed(before, snapshot(r.home)), []);
      });

      test("spaced keys count; a later duplicate wins, as in npm", async () => {
        const ok = await run({ tools: { npm: "11.21.0" }, files: { ".npmrc": "ignore-scripts = true\nmin-release-age = 7\n" } });
        assert.deepEqual(status(ok.out, "H01"), ["PASS"]);
        assert.match(lines(ok.out, "H02")[0] ?? "", /^\[PASS\] H02 +.*min-release-age is 7$/);
        const dup = await run({
          tools: { npm: "11.21.0" },
          files: { ".npmrc": "ignore-scripts=true\nignore-scripts=false\nmin-release-age=7\nmin-release-age=1\n" },
        });
        assert.deepEqual(status(dup.out, "H01"), ["FAIL"]);
        assert.match(lines(dup.out, "H02")[0] ?? "", /min-release-age is 1 /);
      });

      test("--apply never lowers a stricter cooldown that uses spaced syntax", async () => {
        const r = await run({ tools: { npm: "11.21.0" }, args: ["--apply"], files: { ".npmrc": "min-release-age = 14\nignore-scripts=true\n" } });
        assert.match(lines(r.out, "H02")[0] ?? "", /PASS.*min-release-age is 14$/);
        assert.equal(home(r, ".npmrc"), "min-release-age = 14\nignore-scripts=true\n");
        assert.deepEqual(backups(r.home, ".npmrc"), []);
      });

      test("an environment variable overriding the file is a FAIL, before and after --apply", async () => {
        const env = { npm_config_ignore_scripts: "false" };
        const r = await run({ tools: { npm: "11.21.0" }, env, files: { ".npmrc": "ignore-scripts=true\nmin-release-age=7\n" } });
        assert.deepEqual(status(r.out, "H01"), ["FAIL"]);
        const a = await run({ tools: { npm: "11.21.0" }, env, args: ["--apply"], home: r.home });
        assert.match(lines(a.out, "H01").join("\n"), /\[FAIL\] H01 +.*still reports false; something with higher precedence overrides it/);
        assert.equal(a.code, 1);
        // The file already said ignore-scripts=true, so there was nothing to write or back up.
        assert.doesNotMatch(a.out, /backup:|wrote ignore-scripts/);
        assert.deepEqual(backups(a.home, ".npmrc"), []);
      });

      test("--apply writes the userconfig npm actually reads (NPM_CONFIG_USERCONFIG)", async () => {
        const userconfig = join(scratch("npmrc-"), "custom.npmrc");
        const r = await run({ tools: { npm: "11.21.0" }, args: ["--apply"], env: { NPM_CONFIG_USERCONFIG: userconfig } });
        assert.equal(readFileSync(userconfig, "utf8"), "ignore-scripts=true\nmin-release-age=7\n");
        assert.equal(existsSync(join(r.home, ".npmrc")), false);
        assert.deepEqual(status(r.out, "H01"), ["INFO", "PASS"]);
        assert.deepEqual(status(r.out, "H02"), ["INFO", "PASS"]);
      });

      test("--apply collapses duplicates in place, keeps other lines, and backs the file up", async () => {
        const original = "# mine\nmin-release-age=14\nregistry=https://registry.npmjs.org/\nmin-release-age = 1\n";
        const r = await run({ tools: { npm: "11.21.0" }, args: ["--apply"], files: { ".npmrc": original } });
        assert.equal(r.code, 0, r.out);
        assert.equal(home(r, ".npmrc"), "# mine\nmin-release-age=7\nregistry=https://registry.npmjs.org/\nignore-scripts=true\n");
        const b = backups(r.home, ".npmrc");
        assert.equal(b.length, 1);
        assert.equal(readFileSync(join(r.home, b[0] as string), "utf8"), original);
      });

      test("a failed write is a FAIL, not 'applied'", { skip: IS_ROOT && "root ignores file modes" }, async () => {
        const r = await run({ tools: { npm: "11.21.0" }, files: { ".npmrc": "color=false\n" } });
        chmodSync(join(r.home, ".npmrc"), 0o400);
        const a = await run({ tools: { npm: "11.21.0" }, args: ["--apply"], home: r.home });
        assert.match(lines(a.out, "H01")[0] ?? "", /^\[FAIL\] H01 +.*could not write .*\.npmrc/);
        assert.doesNotMatch(a.out, /PASS\] H01|wrote ignore-scripts/);
        assert.equal(home(a, ".npmrc"), "color=false\n");
        assert.equal(a.code, 1);
      });

      test("npm 12 blocks dependency scripts by default; dangerously-allow-all-scripts=true is a FAIL --apply fixes", async () => {
        const ok = await run({ tools: { npm: "12.2.0" }, files: { ".npmrc": "min-release-age=7\n" } });
        assert.match(lines(ok.out, "H01")[0] ?? "", /^\[PASS\] H01 +.*allowScripts approval.*dangerously-allow-all-scripts is false/);
        const bad = await run({ tools: { npm: "12.2.0" }, files: { ".npmrc": "dangerously-allow-all-scripts=true\nmin-release-age=7\n" } });
        assert.deepEqual(status(bad.out, "H01"), ["FAIL"]);
        const a = await run({ tools: { npm: "12.2.0" }, args: ["--apply"], home: bad.home });
        assert.deepEqual(status(a.out, "H01"), ["INFO", "PASS"]);
        assert.equal(home(a, ".npmrc"), "dangerously-allow-all-scripts=false\nmin-release-age=7\n");
      });

      test("npm < 11.10 FAILs H02 even when min-release-age is set (it is ignored there)", async () => {
        const r = await run({ tools: { npm: "10.9.2" }, files: { ".npmrc": "ignore-scripts=true\nmin-release-age=7\n" } });
        assert.match(lines(r.out, "H02")[0] ?? "", /^\[FAIL\] H02 +npm 10\.9\.2 has no working release-age cooldown/);
      });

      test("npm 11.10.x reports min-release-age only as a `before` date; its age still counts", async () => {
        const r = await run({ tools: { npm: "11.10.0" }, files: { ".npmrc": "ignore-scripts=true\nmin-release-age=7\n" } });
        assert.match(lines(r.out, "H02")[0] ?? "", /^\[PASS\] H02 +.*min-release-age is 7$/);
      });

      test("an npm that reports a version but fails to read its config is a WARN, and the run finishes", async () => {
        const r = await run({ tools: { npm: "11.21.0" }, env: { STUB_NPM_MODE: "config-fails" }, files: { "code/x.js": "1\n" } });
        assert.deepEqual(status(r.out, "H01"), ["WARN"]);
        assert.deepEqual(status(r.out, "H02"), ["WARN"]);
        assert.match(lines(r.out, "H11")[0] ?? "", /^\[PASS\] H11 +no worm payload files under: \S+\/code$/);
        assert.match(r.out, /summary: /);
        const p10 = await run({ tools: { pnpm: "10.26.0" }, env: { STUB_PNPM_MODE: "config-fails" } });
        assert.deepEqual(status(p10.out, "H03"), ["WARN"]);
        assert.deepEqual(status(p10.out, "H04"), ["WARN"]);
        assert.match(lines(p10.out, "H04")[0] ?? "", /failed to report minimumReleaseAge/);
        assert.match(p10.out, /summary: /);
      });

      test("an npm that will not report a version is a WARN, with no verdicts", async () => {
        const r = await run({ tools: { npm: "1.0.0" }, env: { STUB_NPM_MODE: "broken" } });
        assert.match(lines(r.out, "H01")[0] ?? "", /^\[WARN\] H01 +npm at .* did not report a version/);
        assert.deepEqual(lines(r.out, "H02"), []);
      });
    });

    describe("H03/H04 pnpm", () => {
      test("pnpm < 10 FAILs both", async () => {
        const r = await run({ tools: { pnpm: "9.15.0" } });
        assert.deepEqual(status(r.out, "H03"), ["FAIL"]);
        assert.deepEqual(status(r.out, "H04"), ["FAIL"]);
      });

      test("pnpm 11 default: build scripts PASS, unset cooldown FAILs; --apply writes the global config.yaml", async () => {
        const r = await run({ tools: { pnpm: "11.16.0" } });
        assert.deepEqual(status(r.out, "H03"), ["PASS"]);
        assert.deepEqual(status(r.out, "H04"), ["FAIL", "PASS"]);
        const a = await run({ tools: { pnpm: "11.16.0" }, args: ["--apply"], home: r.home });
        assert.equal(a.code, 0, a.out);
        assert.equal(home(a, `${PNPM_DIR}/config.yaml`), "minimumReleaseAge: 10080\n");
      });

      test("XDG_CONFIG_HOME moves the pnpm config file", async () => {
        const xdg = scratch("xdg-");
        const r = await run({ tools: { pnpm: "12.8.1" }, args: ["--apply"], env: { XDG_CONFIG_HOME: xdg } });
        assert.equal(readFileSync(join(xdg, "pnpm", "config.yaml"), "utf8"), "minimumReleaseAge: 10080\n");
        assert.equal(r.code, 0, r.out);
      });

      test("dangerouslyAllowAllBuilds and minimumReleaseAgeStrict: false FAIL; --apply fixes them with one backup", async () => {
        const original = "dangerouslyAllowAllBuilds: true\nminimumReleaseAge: 10080\nminimumReleaseAgeStrict: false\n";
        const r = await run({ tools: { pnpm: "11.16.0" }, files: { [`${PNPM_DIR}/config.yaml`]: original } });
        assert.deepEqual(status(r.out, "H03"), ["FAIL"]);
        assert.deepEqual(status(r.out, "H04"), ["PASS", "FAIL"]);
        const a = await run({ tools: { pnpm: "11.16.0" }, args: ["--apply"], home: r.home });
        assert.equal(a.code, 0, a.out);
        assert.equal(home(a, `${PNPM_DIR}/config.yaml`), "dangerouslyAllowAllBuilds: false\nminimumReleaseAge: 10080\nminimumReleaseAgeStrict: true\n");
        assert.equal(backups(join(a.home, PNPM_DIR), "config.yaml").length, 1);
      });

      test("--apply replaces a single-quoted key in place; a second key would make pnpm reject the file", async () => {
        const r = await run({ tools: { pnpm: "11.16.0" }, args: ["--apply"], files: { [`${PNPM_DIR}/config.yaml`]: "'minimumReleaseAge': 60\n" } });
        assert.equal(home(r, `${PNPM_DIR}/config.yaml`), "minimumReleaseAge: 10080\n");
        assert.deepEqual(status(r.out, "H04"), ["INFO", "PASS", "PASS"]);
        assert.equal(r.code, 0, r.out);
      });

      test("a write the package manager cannot read back is undone and is a FAIL", async () => {
        // pnpm reads this escaped key as minimumReleaseAge, but it is not the text the script
        // looks for, so the script adds a second key, which pnpm rejects as a duplicate.
        const original = '"minimumRelease\\u0041ge": 60\n';
        const r = await run({ tools: { pnpm: "11.16.0" }, args: ["--apply"], files: { [`${PNPM_DIR}/config.yaml`]: original } });
        assert.match(lines(r.out, "H04").join("\n"), /\[FAIL\] H04 +.*could not safely edit .*config\.yaml: .*the file is back as it was/);
        assert.equal(home(r, `${PNPM_DIR}/config.yaml`), original);
        assert.equal(r.code, 1);
        // Undoing the write of a file the script created removes it again.
        const fresh = await run({ tools: { pnpm: "11.16.0" }, args: ["--apply"], env: { STUB_PNPM_MODE: "rejects-config" } });
        assert.match(lines(fresh.out, "H04").join("\n"), /\[FAIL\] H04 +.*could not safely edit .*config\.yaml/);
        assert.equal(existsSync(join(fresh.home, PNPM_DIR, "config.yaml")), false);
      });

      test("a config the package manager cannot read is a WARN, and --apply leaves it alone", async () => {
        // pnpm 11.16.0 rejects a duplicate key in every command, --version included.
        const original = "minimumReleaseAge: 60\nminimumReleaseAge: 4320\n";
        const r = await run({ tools: { pnpm: "11.16.0" }, args: ["--apply"], files: { [`${PNPM_DIR}/config.yaml`]: original } });
        assert.deepEqual(status(r.out, "H03"), ["WARN"]);
        assert.deepEqual(status(r.out, "H04"), []);
        assert.match(lines(r.out, "H03")[0] ?? "", /did not report a version offline \(.*or a config file it cannot parse\)/);
        assert.equal(home(r, `${PNPM_DIR}/config.yaml`), original);
        assert.deepEqual(backups(join(r.home, PNPM_DIR), "config.yaml"), []);
        // A pnpm that reports its version but fails `config get`.
        const c = await run({ tools: { pnpm: "11.16.0" }, args: ["--apply"], env: { STUB_PNPM_MODE: "config-fails" } });
        assert.deepEqual(status(c.out, "H03"), ["WARN"]);
        assert.deepEqual(status(c.out, "H04"), ["WARN", "WARN"]);
        assert.match(lines(c.out, "H03")[0] ?? "", /failed to report dangerouslyAllowAllBuilds .*so it was not checked/);
        assert.equal(existsSync(join(c.home, PNPM_DIR)), false);
      });

      test("pnpm 10 below 10.26 FAILs H03: it runs a git dependency's prepare scripts despite default blocking (CVE-2025-69264)", async () => {
        for (const v of ["10.0.0", "10.16.0", "10.25.9"]) {
          const r = await run({ tools: { pnpm: v }, files: { ".npmrc": "minimum-release-age=10080\n" } });
          assert.deepEqual(status(r.out, "H03"), ["FAIL"], v);
          assert.match(lines(r.out, "H03")[0] ?? "", /git-hosted dependency's prepare, prepublish and prepack scripts .*CVE-2025-69264, fixed in 10\.26\.0/, v);
        }
        assert.deepEqual(status((await run({ tools: { pnpm: "10.26.0" }, files: { ".npmrc": "minimum-release-age=10080\n" } })).out, "H03"), ["PASS"]);
      });

      test("pnpm 10: a set cooldown is only a WARN, an unset one a FAIL; build-all is a FAIL", async () => {
        const set = await run({ tools: { pnpm: "10.26.0" }, files: { ".npmrc": "minimum-release-age=10080\n" } });
        assert.deepEqual(status(set.out, "H03"), ["PASS"]);
        assert.deepEqual(status(set.out, "H04"), ["WARN"]);
        const unset = await run({ tools: { pnpm: "10.26.0" }, files: { ".npmrc": "dangerously-allow-all-builds=true\n" } });
        assert.deepEqual(status(unset.out, "H03"), ["FAIL"]);
        assert.deepEqual(status(unset.out, "H04"), ["FAIL"]);
      });

      test("corepack shims are never allowed to download, and are asked from a neutral directory", async () => {
        const project = scratch("project-");
        writeFileSync(join(project, "package.json"), '{"packageManager":"pnpm@9.0.0"}');
        const r = await run({
          tools: { pnpm: "11.16.0", yarn: "1.22.22" },
          env: { STUB_PNPM_MODE: "corepack", STUB_YARN_MODE: "corepack" },
          cwd: project,
        });
        assert.match(lines(r.out, "H03")[0] ?? "", /^\[WARN\] H03 +pnpm at .* did not report a version offline/);
        assert.match(lines(r.out, "H05")[0] ?? "", /^\[WARN\] H05 +yarn at .* did not report a version offline/);
        assert.deepEqual(readdirSync(r.home), [], "a corepack download would have written ~/.cache");
        assert.ok(r.calls.length > 0);
        const tmp = realpathSync(join(r.root, "tmp"));
        for (const c of r.calls) {
          assert.equal(c.corepackNetwork, "0", JSON.stringify(c));
          assert.ok(c.cwd.startsWith(tmp), `ran in ${c.cwd}, not the script's empty temp dir`);
        }
      });
    });

    describe("H05/H06 yarn", () => {
      test("Yarn Classic: release age WARN, ignore-scripts FAIL even with ~/.npmrc set; --apply writes ~/.yarnrc", async () => {
        const r = await run({ tools: { yarn: "1.22.22" }, files: { ".npmrc": "ignore-scripts=true\n" } });
        assert.deepEqual(status(r.out, "H05"), ["WARN"]);
        assert.deepEqual(status(r.out, "H06"), ["FAIL"]);
        const a = await run({ tools: { yarn: "1.22.22" }, args: ["--apply"], home: r.home });
        assert.deepEqual(status(a.out, "H06"), ["INFO", "PASS"]);
        assert.equal(home(a, ".yarnrc"), "ignore-scripts true\n");
      });

      test("Yarn Classic: ~/.yarnrc PASSes; YARN_IGNORE_SCRIPTS=false overrides it", async () => {
        const files = { ".yarnrc": '"ignore-scripts" true\n' };
        assert.deepEqual(status((await run({ tools: { yarn: "1.22.22" }, files })).out, "H06"), ["PASS"]);
        const r = await run({ tools: { yarn: "1.22.22" }, files, env: { YARN_IGNORE_SCRIPTS: "false" } });
        assert.deepEqual(status(r.out, "H06"), ["FAIL"]);
      });

      test("Yarn 4.10: both FAIL by default; --apply writes ~/.yarnrc.yml", async () => {
        const r = await run({ tools: { yarn: "4.10.3" } });
        assert.deepEqual(status(r.out, "H05"), ["FAIL"]);
        assert.deepEqual(status(r.out, "H06"), ["FAIL"]);
        const a = await run({ tools: { yarn: "4.10.3" }, args: ["--apply"], home: r.home });
        assert.equal(a.code, 0, a.out);
        assert.equal(home(a, ".yarnrc.yml"), "npmMinimalAgeGate: 10080\nenableScripts: false\n");
      });

      test("Yarn 4.18 defaults: scripts off PASS, 1-day gate FAILs the default 7-day soak; env overrides count", async () => {
        const r = await run({ tools: { yarn: "4.18.1" } });
        assert.deepEqual(status(r.out, "H06"), ["PASS"]);
        assert.match(lines(r.out, "H05")[0] ?? "", /npmMinimalAgeGate is 1440 \(want >= 10080/);
        const e = await run({ tools: { yarn: "4.18.1" }, env: { YARN_ENABLE_SCRIPTS: "true" } });
        assert.deepEqual(status(e.out, "H06"), ["FAIL"]);
      });

      test("Yarn < 4.10 has no age gate", async () => {
        const r = await run({ tools: { yarn: "3.6.4" }, files: { ".yarnrc.yml": "enableScripts: false\n" } });
        assert.match(lines(r.out, "H05")[0] ?? "", /^\[FAIL\] H05 +yarn 3\.6\.4 has no npmMinimalAgeGate/);
        assert.deepEqual(status(r.out, "H06"), ["PASS"]);
      });

      test("indented YAML keys are nested, not top-level settings", async () => {
        const r = await run({ tools: { yarn: "4.10.3" }, args: ["--apply"], files: { ".yarnrc.yml": "packageExtensions:\n  enableScripts: false\n" } });
        assert.equal(home(r, ".yarnrc.yml"), "packageExtensions:\n  enableScripts: false\nnpmMinimalAgeGate: 10080\nenableScripts: false\n");
      });
    });

    describe("H07 bun", () => {
      test("bun < 1.3 FAILs", async () => {
        assert.deepEqual(status((await run({ tools: { bun: "1.2.0" } })).out, "H07"), ["FAIL"]);
      });

      test("reads [install] minimumReleaseAge from the global bunfig files", async () => {
        const unset = await run({ tools: { bun: "1.4.2" } });
        assert.match(lines(unset.out, "H07")[0] ?? "", /^\[FAIL\] H07 +.*minimumReleaseAge is unset \(want >= 604800 seconds\)/);
        const ok = await run({ tools: { bun: "1.4.2" }, files: { ".bunfig.toml": "[install]\nminimumReleaseAge = 604_800 # 7 days\n" } });
        assert.deepEqual(status(ok.out, "H07"), ["PASS"]);
        const wrongSection = await run({ tools: { bun: "1.4.2" }, files: { ".bunfig.toml": "[run]\nminimumReleaseAge = 604800\n" } });
        assert.deepEqual(status(wrongSection.out, "H07"), ["FAIL"]);
        const xdg = scratch("bunxdg-");
        writeFileSync(join(xdg, ".bunfig.toml"), "[install]\nminimumReleaseAge = 60\n");
        const lower = await run({ tools: { bun: "1.4.2" }, env: { XDG_CONFIG_HOME: xdg }, files: { ".bunfig.toml": "[install]\nminimumReleaseAge = 604800\n" } });
        assert.match(lines(lower.out, "H07")[0] ?? "", /FAIL.*minimumReleaseAge is 60 /);
      });

      test("a value Bun would not read as a whole number of seconds FAILs as unreadable, even beside a good file", async () => {
        const crlf = await run({ tools: { bun: "1.4.2" }, files: { ".bunfig.toml": "[install]\r\nminimumReleaseAge = 604_800\r\n" } });
        assert.deepEqual(lines(crlf.out, "H07"), ["[PASS] H07  bun 1.4.2: global bunfig [install] minimumReleaseAge is 604800 seconds"], "CRLF line ends are read");
        const xdg = scratch("bunbad-");
        writeFileSync(join(xdg, ".bunfig.toml"), "[install]\nminimumReleaseAge = 604__800\n");
        const bad = await run({ tools: { bun: "1.4.2" }, env: { XDG_CONFIG_HOME: xdg }, files: { ".bunfig.toml": "[install]\nminimumReleaseAge = 604800\n" } });
        assert.deepEqual(lines(bad.out, "H07"), [
          "[FAIL] H07  bun 1.4.2: global bunfig [install] minimumReleaseAge is 604__800, which is not a whole number of seconds (digits, with _ only between digits). Write 'minimumReleaseAge = 604800' under [install] in ~/.bunfig.toml (not auto-applied).",
        ]);
      });

      test("a bun that will not report a version is a WARN without corepack advice (corepack has no bun)", async () => {
        const r = await run({ tools: { bun: "1.4.2" }, env: { STUB_BUN_MODE: "broken" } });
        assert.deepEqual(lines(r.out, "H07"), [
          `[WARN] H07  bun at ${r.root}/bin/bun did not report a version offline, so its settings were not checked. 'bun --version' shows the error.`,
        ]);
      });
    });

    describe("H08 plaintext tokens", () => {
      const files = {
        ".npmrc": [
          "//registry.npmjs.org/:_authToken = 0f2a4c8e-1d3b-4e5f-9a7b-6c8d0e1f2a3b",
          "_auth = dXNlcjpodW50ZXIy",
          "_password=aHVudGVyMmlzTXlQYXNzd29yZA==",
          "registry=https://alice:s3cretpass@registry.example.com/",
          '//npm.pkg.github.com/:_authToken="${GITHUB_TOKEN}"',
        ].join("\n"),
        ".zshrc": [
          "# export NPM_TOKEN=commentedout123456",
          "  export NPM_TOKEN=abcdefgh12345678",
          "typeset -x GH_TOKEN=ghsecretvalue1234",
          'declare -x AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"',
          'export GITHUB_TOKEN="$(gh auth token)"',
          "export NODE_AUTH_TOKEN=${NPM_TOKEN}",
        ].join("\n"),
        ".config/fish/config.fish": "set -gx NPM_TOKEN fishsecret12345678\nset -Ux GH_TOKEN (gh auth token)\n",
        ".yarnrc.yml": "npmScopes:\n  acme:\n    npmAuthToken: yarnberrysecret123\n",
        ".bashrc": "alias x='curl -H \"Authorization: token ghp_abcdefghijklmnopqrstuvwxyz0123456789\"'\n",
      };

      test("finds every literal form, skips references, and never prints any part of a secret", async () => {
        const r = await run({ files });
        const found = lines(r.out, "H08").map((l) => (l.match(/\/home\/(\S+?:\d+) /) ?? [])[1]).sort();
        assert.deepEqual(found, [
          ".bashrc:1", ".config/fish/config.fish:1", ".npmrc:1", ".npmrc:2", ".npmrc:3", ".npmrc:4",
          ".yarnrc.yml:3", ".zshrc:2", ".zshrc:3", ".zshrc:4",
        ]);
        assert.ok(lines(r.out, "H08").every((l) => l.startsWith("[FAIL]")));
        for (const secret of ["0f2a4c8e", "dXNl", "aHVu", "s3cret", "abcdefgh", "ghsecret", "wJalrX", "fishsecret", "yarnberry", "ghp_abcd"]) {
          assert.ok(!r.out.includes(secret), `output leaks ${secret}`);
        }
        assert.equal(r.code, 1);
      });

      test("references only: PASS", async () => {
        const r = await run({ files: { ".npmrc": "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n", ".zshrc": 'export GH_TOKEN="$(gh auth token)"\n' } });
        assert.deepEqual(status(r.out, "H08"), ["PASS"]);
      });

      test("--apply backups are scanned too", async () => {
        const r = await run({
          files: {
            ".npmrc": "ignore-scripts=true\n",
            ".npmrc.wormsign-bak.20260101000000.1": "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789\n",
          },
        });
        assert.deepEqual(lines(r.out, "H08"), [
          `[FAIL] H08  ${r.home}/.npmrc.wormsign-bak.20260101000000.1:1 registry credential (_authToken/_auth/_password/npmAuthToken). ` +
            "Move it to a keychain or an env var set at runtime, then rotate it.",
        ]);
      });

      test("a file that could not be scanned is never followed by a PASS", async () => {
        const h = scratch("home-");
        mkdirSync(join(h, ".npmrc"));
        const r = await run({ home: h });
        assert.match(lines(r.out, "H08")[0] ?? "", /^\[WARN\] H08 +.*\.npmrc could not be read/);
        assert.deepEqual(status(r.out, "H08"), ["WARN", "INFO"]);
        assert.match(lines(r.out, "H08")[1] ?? "", /1 file\(s\) could not be scanned/);
      });

      test("an unreadable profile is a WARN and the run still finishes", { skip: IS_ROOT && "root reads anything" }, async () => {
        const r = await run({ files: { ".zshrc": "export A=1\n" } });
        chmodSync(join(r.home, ".zshrc"), 0o000);
        const again = await run({ home: r.home });
        assert.match(lines(again.out, "H08")[0] ?? "", /^\[WARN\] H08 +.*\.zshrc could not be read/);
        assert.match(again.out, /summary: /);
      });
    });

    describe("H09 gh scopes", () => {
      const gh = (fixture: string) => ({ STUB_GH_STATUS: fx("harden", "gh", fixture) });

      test("--offline skips without running gh", async () => {
        const r = await run({ tools: { gh: "" }, args: ["--offline"], env: gh("two-accounts.txt") });
        assert.deepEqual(status(r.out, "H09"), ["SKIP"]);
        assert.deepEqual(r.calls.filter((c) => c.tool === "gh"), []);
      });

      test("not logged in: SKIP", async () => {
        assert.deepEqual(status((await run({ tools: { gh: "" } })).out, "H09"), ["SKIP"]);
      });

      test("every account is checked; the fix command is well formed", async () => {
        const r = await run({ tools: { gh: "" }, env: gh("two-accounts.txt") });
        assert.deepEqual(lines(r.out, "H09"), [
          "[PASS] H09  gh account octo-work on github.com: scopes look narrow (gist,read:org,repo)",
          "[FAIL] H09  gh account octo-personal on github.com has destructive/admin scopes (delete_repo,admin:public_key). " +
            "Remove them: gh auth switch -h github.com -u octo-personal && gh auth refresh -h github.com -r delete_repo,admin:public_key",
        ]);
        assert.equal(r.code, 1);
      });

      test("workflow scope: WARN; no scopes reported: INFO naming the account", async () => {
        assert.deepEqual(status((await run({ tools: { gh: "" }, env: gh("broad.txt") })).out, "H09"), ["WARN"]);
        const r = await run({ tools: { gh: "" }, env: gh("fine-grained.txt") });
        assert.match(lines(r.out, "H09").join("\n"), /^\[INFO\] H09 +gh account octo-work on github\.com reports no token scopes/);
      });

      test("an account gh could not log in to is a WARN, not dropped", async () => {
        const r = await run({ tools: { gh: "" }, env: gh("timeout.txt") });
        assert.deepEqual(status(r.out, "H09"), ["PASS", "WARN"]);
        assert.match(lines(r.out, "H09")[1] ?? "", /^\[WARN\] H09 +gh account octo-personal on github\.com: token scopes unknown, gh could not log in \(timeout\)/);
      });

      test("every account failing (offline, expired) is a WARN per account, not an INFO", async () => {
        const r = await run({ tools: { gh: "" }, env: gh("all-failed.txt") });
        assert.deepEqual(status(r.out, "H09"), ["WARN", "WARN"]);
        assert.match(lines(r.out, "H09")[0] ?? "", /gh account octo-work on github\.com: .*\(failed\)/);
        assert.match(lines(r.out, "H09")[1] ?? "", /gh account \(token\) on ghe\.example\.com: .*\(timeout\)/);
      });

      test("output in a form the script cannot read (gh < 2.40) is a WARN", async () => {
        const r = await run({ tools: { gh: "" }, env: gh("old-format.txt") });
        assert.match(lines(r.out, "H09").join("\n"), /^\[WARN\] H09 +gh auth status listed no account in a form this script reads/);
      });
    });

    describe("H10 credential files", () => {
      test("WARNs with the file mode, including git and netrc stores", async () => {
        const r = await run({
          files: {
            ".aws/credentials": "[default]\naws_access_key_id = AKIAEXAMPLE\n",
            ".git-credentials": "https://user:token@github.com\n",
            ".netrc": "machine github.com login u password p\n",
            ".config/gcloud/application_default_credentials.json": "{}\n",
          },
        });
        assert.equal(lines(r.out, "H10").length, 4);
        for (const l of lines(r.out, "H10")) assert.match(l, /^\[WARN\] H10 +.* present \(mode 600\)\. /);
      });

      test("a credential file that cannot be read is a WARN, never a PASS", { skip: IS_ROOT && "root reads anything" }, async () => {
        const r = await run({ files: { ".aws/credentials": "[default]\naws_access_key_id = AKIAEXAMPLE\n" } });
        chmodSync(join(r.home, ".aws/credentials"), 0o000);
        const again = await run({ home: r.home });
        chmodSync(join(r.home, ".aws/credentials"), 0o600);
        assert.deepEqual(status(again.out, "H10"), ["WARN"]);
        assert.match(lines(again.out, "H10")[0] ?? "", /credentials present \(mode 0\)\. It could not be read/);
      });

      test("a credential directory that cannot be searched is one WARN, never a PASS", { skip: IS_ROOT && "root reads anything" }, async () => {
        const r = await run({
          files: {
            ".docker/config.json": '{"auths":{"r.example":{"auth":"x"}}}\n',
            ".config/gcloud/credentials.db": "x\n",
            ".config/gh/hosts.yml": "github.com:\n  oauth_token: x\n",
          },
        });
        chmodSync(join(r.home, ".docker"), 0o000);
        chmodSync(join(r.home, ".config"), 0o000);
        const again = await run({ home: r.home });
        chmodSync(join(r.home, ".docker"), 0o700);
        chmodSync(join(r.home, ".config"), 0o700);
        assert.deepEqual(lines(again.out, "H10"), [
          `[WARN] H10  ${r.home}/.config present (mode 0). It could not be searched, so the credential files in it were not checked.`,
          `[WARN] H10  ${r.home}/.docker present (mode 0). It could not be searched, so the credential files in it were not checked.`,
        ]);
      });

      test("GNU stat: the mode is read with -c, not -f (which prints a file-system block there)", async () => {
        const r = await run({ tools: { stat: "" }, files: { ".git-credentials": "x\n" } });
        assert.match(lines(r.out, "H10")[0] ?? "", /present \(mode 600\)\. git's/);
      });
    });

    describe("H11 worm artifacts", () => {
      // The synthetic IOC set as an update-iocs cache, pretty-printed: the script must read it
      // through the scanner's own loader, which adds a cache newer than the bundled data to it.
      const cache: Record<string, string> = {};
      for (const f of readdirSync(fx("iocs"))) {
        const data = { ...JSON.parse(readFileSync(fx("iocs", f), "utf8")), version: "2099-01-01" };
        cache[`.cache/wormsign/iocs/${f}`] = JSON.stringify(data, null, 2);
      }

      test("PASS on a clean dev directory; global node_modules and --path are searched", async () => {
        const extra = scratch("extra-");
        const r = await run({
          tools: { npm: "11.21.0" },
          args: ["--path", extra],
          env: { STUB_NPM_ROOT: join(SANDBOX, "nonexistent-global") },
          files: { "code/app/index.js": "1\n", ".npmrc": "ignore-scripts=true\nmin-release-age=7\n" },
        });
        assert.match(lines(r.out, "H11")[0] ?? "", new RegExp(`^\\[PASS\\] H11 +no worm payload files under: .*/home/code ${extra}$`));
        const g = await run({ tools: { npm: "11.21.0" }, env: { STUB_NPM_ROOT: extra }, files: { ".npmrc": "ignore-scripts=true\nmin-release-age=7\n" } });
        assert.match(lines(g.out, "H11")[0] ?? "", new RegExp(`under: ${extra}$`));
      });

      test("uses the update-iocs cache: hash match and high-severity name FAIL, info name is ignored", async () => {
        const r = await run({
          files: {
            ...cache,
            "code/a/bundle.js": "ok\n",
            "code/a/wormsign_marker_loader.js": readFileSync(fx("malicious", "wormsign_marker_loader.js"), "utf8"),
            "code/b/wormsign_marker_loader.js": "not the sample\n",
          },
        });
        const h11 = lines(r.out, "H11").sort();
        assert.equal(h11.length, 2, r.out);
        assert.match(h11[0] ?? "", /^\[FAIL\] H11 +.*code\/a\/wormsign_marker_loader\.js matches a known worm payload hash/);
        assert.match(h11[1] ?? "", /^\[FAIL\] H11 +.*code\/b\/wormsign_marker_loader\.js has a worm payload file name \(high;/);
        assert.equal(r.code, 1);
      });

      test("bundled IOCs: a high-severity payload name is a FAIL", async () => {
        const r = await run({ files: { "projects/x/node_modules/y/truffleSecrets.json": "{}\n" } });
        assert.match(lines(r.out, "H11")[0] ?? "", /^\[FAIL\] H11 +.*truffleSecrets\.json has a worm payload file name \(high;/);
        assert.equal(r.code, 1);
      });

      test("control characters in a path cannot rewrite the report line", async () => {
        const dir = "code/\x1b[2K\r[PASS] H11 clean\x1b[8m";
        const r = await run({ files: { [`${dir}/truffleSecrets.json`]: "{}\n" } });
        assert.ok(!r.out.includes("\x1b") && !r.out.includes("\r"), r.out);
        assert.match(lines(r.out, "H11")[0] ?? "", /^\[FAIL\] H11 +.*\/code\/\?\[2K\?\[PASS\] H11 clean\?\[8m\/truffleSecrets\.json has a worm payload/);
      });

      test("a newline in a directory name neither splits the path nor skips the hash check", async () => {
        const r = await run({
          files: { ...cache, "code/a\nb/wormsign_marker_loader.js": readFileSync(fx("malicious", "wormsign_marker_loader.js"), "utf8") },
        });
        assert.deepEqual(status(r.out, "H11"), ["FAIL"], r.out);
        assert.match(lines(r.out, "H11")[0] ?? "", /^\[FAIL\] H11 +\S+\/code\/a\?b\/wormsign_marker_loader\.js matches a known worm payload hash/);
      });

      test("a dev directory or --path that is a symlink is searched", async () => {
        const target = scratch("linked-");
        mkdirSync(join(target, "proj/node_modules/x"), { recursive: true });
        writeFileSync(join(target, "proj/node_modules/x/truffleSecrets.json"), "{}\n");
        const r = await run({ files: { "keep.txt": "" } });
        symlinkSync(target, join(r.home, "code"));
        const viaHome = await run({ home: r.home });
        assert.match(lines(viaHome.out, "H11")[0] ?? "", /^\[FAIL\] H11 +.*\/code\/proj\/node_modules\/x\/truffleSecrets\.json has a worm payload file name/);
        const link = join(scratch("pathlink-"), "work");
        symlinkSync(target, link);
        const viaPath = await run({ args: ["--path", link] });
        assert.match(lines(viaPath.out, "H11")[0] ?? "", /^\[FAIL\] H11 +.*truffleSecrets\.json has a worm payload file name/);
      });

      test("an unreadable directory is a WARN, never a PASS", { skip: IS_ROOT && "root reads anything" }, async () => {
        const r = await run({ files: { "code/locked/setup_bun.js": "x\n" } });
        chmodSync(join(r.home, "code", "locked"), 0o000);
        const again = await run({ home: r.home });
        chmodSync(join(r.home, "code", "locked"), 0o700);
        assert.deepEqual(status(again.out, "H11"), ["WARN"]);
        assert.match(lines(again.out, "H11")[0] ?? "", /some directories could not be searched/);
      });

      test("SKIP when wormsign is not built next to the script", async () => {
        const copy = scratch("nobuild-");
        copyFileSync(SCRIPT, join(copy, "harden-dev.sh"));
        const r = await run({ script: join(copy, "harden-dev.sh"), files: { "code/x.js": "1\n" } });
        assert.match(lines(r.out, "H11")[0] ?? "", /^\[SKIP\] H11 +wormsign is not built/);
      });
    });

    describe("H12 pip", () => {
      const pip = { python3: "26.1.2" };
      const conf = (text: string) => ({ [PIP_USER]: text });
      const userFile = (r: Run) => join(r.home, PIP_USER);

      test("unset FAILs with the command --apply would run; check mode writes nothing", async () => {
        const r = await run({ tools: pip, files: { ".npmrc": "color=false\n" } });
        const before = snapshot(r.home);
        assert.deepEqual(lines(r.out, "H12"), [
          "[FAIL] H12  pip 26.1.2 (python3 -m pip): uploaded-prior-to: unset for pip install, download, lock and wheel (want P7D or longer; " +
            "fixable with --apply, which runs 'python3 -m pip config --user set global.uploaded-prior-to P7D'). " +
            "Without a cutoff pip installs a release minutes after it is published.",
        ]);
        assert.equal(r.code, 1);
        assert.deepEqual(changed(before, snapshot(r.home)), []);
      });

      test("pip < 26.1 FAILs even with a cutoff set: 25.3 ignores it, and 26.0 fails to install on P<n>D", async () => {
        const files = conf("[global]\nuploaded-prior-to = P30D\n");
        const old = await run({ tools: { python3: "25.3" }, files });
        assert.deepEqual(lines(old.out, "H12"), [
          "[FAIL] H12  pip 25.3 (python3 -m pip) has no working release-age cutoff: uploaded-prior-to needs pip >= 26.1 for P<n>D values " +
            "(pip 25.3 accepts the key and ignores it). Upgrade pip, then re-run.",
        ]);
        const v26 = await run({ tools: { python3: "26.0.1" }, files });
        assert.match(lines(v26.out, "H12").join("\n"), /^\[FAIL\] H12 +pip 26\.0\.1 \(python3 -m pip\) reads uploaded-prior-to only as an absolute date, and a P<n>D value in its config makes pip install, download, lock, wheel, index and list fail/);
        assert.deepEqual(status(v26.out, "H12"), ["FAIL"]);
        assert.deepEqual(status((await run({ tools: { python3: "26.1.0" }, files })).out, "H12"), ["PASS"]);
      });

      test("whole days: P<n>D at least the soak PASSes, shorter FAILs; --soak 60h rounds up to P3D", async () => {
        const ok = await run({ tools: pip, files: conf("[global]\nuploaded-prior-to = P7D\n") });
        assert.deepEqual(lines(ok.out, "H12"), [`[PASS] H12  pip 26.1.2 (python3 -m pip): uploaded-prior-to: install, download, lock and wheel use "P7D" from [global] in ${userFile(ok)}`]);
        const short = await run({ tools: pip, files: conf("[global]\nuploaded-prior-to = P6D\n") });
        assert.match(lines(short.out, "H12")[0] ?? "", /^\[FAIL\] H12 +.*: uploaded-prior-to: \[global\] "P6D" in \S+ is shorter than P7D \(want P7D or longer;/);
        const h60 = await run({ tools: pip, args: ["--soak", "60h"], files: conf("[global]\nuploaded-prior-to = P2D\n") });
        assert.match(lines(h60.out, "H12")[0] ?? "", /\[global\] "P2D" in \S+ is shorter than P3D \(want P3D or longer;/);
      });

      test("absolute dates: older than the soak PASSes; a date or naive time counts as up to 12 hours later (local time)", async () => {
        const verdict = async (v: string) => status((await run({ tools: pip, files: conf(`[global]\nuploaded-prior-to = ${v}\n`) })).out, "H12");
        assert.deepEqual(await verdict(isoDate(ago(9 * DAY))), ["PASS"]);
        assert.deepEqual(await verdict(isoDate(ago(6 * DAY))), ["FAIL"]);
        // Seven days and six hours ago: old enough in UTC, but not if it is local time 12 hours behind UTC.
        const t = ago(7 * DAY + 6 * 3600e3);
        assert.deepEqual(await verdict(isoZ(t)), ["PASS"]);
        assert.deepEqual(await verdict(isoNaive(t)), ["FAIL"]);
        assert.deepEqual(await verdict(`${isoNaive(t)}+05:00`), ["PASS"]);
        assert.deepEqual(await verdict(`${isoNaive(t)}-07:00`), ["FAIL"]);
        assert.deepEqual(await verdict(`${isoNaive(ago(7 * DAY - 6 * 3600e3))}+00:00`), ["FAIL"]);
      });

      test("a value pip rejects or this script cannot read FAILs, naming it", async () => {
        for (const v of ['"P30D"', "P30D # thirty days", "7 days", "P1W", "2026-13-01"]) {
          const r = await run({ tools: pip, files: conf(`[global]\nuploaded-prior-to = ${v}\n`) });
          assert.deepEqual(status(r.out, "H12"), ["FAIL"], v);
          assert.match(lines(r.out, "H12")[0] ?? "", /\[global\] .* is (neither P<n>D nor an ISO 8601 date this script can read|not a valid date)/, v);
        }
      });

      test("a shorter [install] value FAILs, naming [install]: pip install uses it instead of [global]", async () => {
        const r = await run({ tools: pip, files: conf("[global]\nuploaded-prior-to = P7D\n[install]\nuploaded-prior-to = P1D\n") });
        assert.match(lines(r.out, "H12")[0] ?? "", /^\[FAIL\] H12 +.*: uploaded-prior-to: \[install\] "P1D" in \S+ is shorter than P7D \(/);
      });

      test("each command section set, no [global]: PASS; a command left out (wheel, which builds sdists) FAILs, naming it", async () => {
        const each = "[install]\nuploaded-prior-to = P7D\n[download]\nuploaded-prior-to = P8D\n[lock]\nuploaded-prior-to = P7D\n";
        const ok = await run({ tools: pip, files: conf(`${each}[wheel]\nuploaded-prior-to = P9D\n`) });
        const f = userFile(ok);
        assert.deepEqual(lines(ok.out, "H12"), [
          `[PASS] H12  pip 26.1.2 (python3 -m pip): uploaded-prior-to: install uses "P7D" from [install] in ${f}; download uses "P8D" from [download] in ${f}; ` +
            `lock uses "P7D" from [lock] in ${f}; wheel uses "P9D" from [wheel] in ${f}`,
        ]);
        const r = await run({ tools: pip, files: conf(each) });
        assert.match(lines(r.out, "H12")[0] ?? "", /uploaded-prior-to: unset for pip wheel \(/);
      });

      test("PIP_UPLOADED_PRIOR_TO alone protects every command; a shorter one FAILs over a good file; P0D also WARNs", async () => {
        const ok = await run({ tools: pip, env: { PIP_UPLOADED_PRIOR_TO: "P7D" } });
        assert.deepEqual(lines(ok.out, "H12"), ['[PASS] H12  pip 26.1.2 (python3 -m pip): uploaded-prior-to: install, download, lock and wheel use "P7D" from PIP_UPLOADED_PRIOR_TO']);
        const short = await run({ tools: pip, env: { PIP_UPLOADED_PRIOR_TO: "P2D" }, files: conf("[global]\nuploaded-prior-to = P30D\n") });
        assert.match(lines(short.out, "H12")[0] ?? "", /^\[FAIL\] H12 +.*PIP_UPLOADED_PRIOR_TO "P2D" is shorter than P7D/);
        const off = await run({ tools: pip, env: { PIP_UPLOADED_PRIOR_TO: "P0D" }, files: conf("[global]\nuploaded-prior-to = P30D\n") });
        assert.deepEqual(status(off.out, "H12"), ["WARN", "FAIL"]);
        assert.match(lines(off.out, "H12")[0] ?? "", /PIP_UPLOADED_PRIOR_TO=P0D is set in this environment: P0D is how pip's user guide says to override a configured cutoff, so pip has none here/);
        // An empty variable is no value: pip falls back to the files.
        assert.deepEqual(status((await run({ tools: pip, env: { PIP_UPLOADED_PRIOR_TO: "" }, files: conf("[global]\nuploaded-prior-to = P7D\n") })).out, "H12"), ["PASS"]);
      });

      test("per section the last file pip reads wins, and an empty winner clears the section, whatever order `pip config debug` lists them in", async () => {
        // pip reads ~/.pip/pip.conf, then ~/.config/pip/pip.conf: the second one's value wins, empty or not.
        const empty = await run({ tools: pip, files: { [PIP_USER]: "[global]\nuploaded-prior-to =\n", ".pip/pip.conf": "[global]\nuploaded-prior-to = P30D\n" } });
        assert.match(
          lines(empty.out, "H12")[0] ?? "",
          new RegExp(`^\\[FAIL\\] H12 +.*uploaded-prior-to: unset for pip install, download, lock and wheel \\(cleared by an empty value in the last file pip reads it from: \\[global\\] in ${userFile(empty)}\\)`),
        );
        const first = await run({ tools: pip, files: { ".pip/pip.conf": "[global]\nuploaded-prior-to =\n", [PIP_USER]: "[global]\nuploaded-prior-to = P30D\n" } });
        assert.deepEqual(lines(first.out, "H12"), [`[PASS] H12  pip 26.1.2 (python3 -m pip): uploaded-prior-to: install, download, lock and wheel use "P30D" from [global] in ${userFile(first)}`]);
        // The system-wide file comes first: a user value overrides its short one.
        const sys = await run({ tools: pip, files: { [PIP_USER]: "[global]\nuploaded-prior-to = P30D\n", "../etc/pip.conf": "[global]\nuploaded-prior-to = P1D\n" } });
        assert.deepEqual(status(sys.out, "H12"), ["PASS"], sys.out);
        // The site file (the environment's own) comes after the user files, though `pip config debug` lists "site" before "user".
        const site = await run({ tools: pip, files: { [PIP_USER]: "[global]\nuploaded-prior-to = P1D\n", "../site/pip.conf": "[global]\nuploaded-prior-to = P30D\n" } });
        assert.match(lines(site.out, "H12")[0] ?? "", /^\[PASS\] H12 +.*use "P30D" from \[global\] in \S+\/site\/pip\.conf$/);
      });

      test("[DEFAULT] keys reach every section, as configparser gives them to pip", async () => {
        const r = await run({ tools: pip, files: conf("[DEFAULT]\nuploaded-prior-to = P1D\n[global]\ntimeout = 5\n[install]\n") });
        assert.match(lines(r.out, "H12")[0] ?? "", /: uploaded-prior-to: \[install\] "P1D" in \S+ is shorter than P7D; \[global\] "P1D" in \S+ is shorter than P7D \(/);
        const only = await run({ tools: pip, files: conf("[DEFAULT]\nuploaded-prior-to = P30D\n") });
        assert.match(lines(only.out, "H12")[0] ?? "", /unset for pip install, download, lock and wheel/, "a file with only [DEFAULT] has no section for it to reach");
      });

      test("pip's own quiet and verbose settings do not change what is read; a listing without its control line is a WARN", async () => {
        // quiet = 1 silences `pip config debug` (pip logs it at INFO): the script overrides it from the environment.
        const quiet = await run({ tools: pip, files: conf("[global]\nquiet = 1\nuploaded-prior-to = P7D\n") });
        assert.deepEqual(status(quiet.out, "H12"), ["PASS"], quiet.out);
        // verbose = 1 prints a line per file first; --apply still sees [global] passing and writes nothing, run after run.
        const text = "# mine\n[global]\nverbose = 1\nuploaded-prior-to = P7D\n[install]\nuploaded-prior-to = P1D\n";
        const verbose = await run({ tools: pip, args: ["--apply"], files: conf(text) });
        const again = await run({ tools: pip, args: ["--apply"], home: verbose.home });
        for (const r of [verbose, again]) {
          assert.match(lines(r.out, "H12")[0] ?? "", /\[install\] "P1D" in \S+ is shorter than P7D \(want P7D or longer; not fixed by --apply: for python3 -m pip, \[global\] already says "P7D" in /);
          assert.doesNotMatch(r.out, /backup:|wrote /);
        }
        assert.equal(home(again, PIP_USER), text);
        assert.deepEqual(backups(join(again.home, ".config/pip"), "pip.conf"), []);
        // A listing that lost its PIP_DISABLE_PIP_VERSION_CHECK line some other way is not judged as empty.
        const silent = await run({ tools: pip, env: { STUB_PYTHON3_MODE: "silent" }, files: conf("[global]\nuploaded-prior-to = P7D\n") });
        assert.deepEqual(lines(silent.out, "H12"), [
          "[WARN] H12  pip 26.1.2 (python3 -m pip): 'python3 -m pip config debug' printed no listing (not even PIP_DISABLE_PIP_VERSION_CHECK, which this script sets), so it was not checked",
        ]);
      });

      test("python3 -m venv's pip (python3's ensurepip): older than 26.1 is a WARN, 26.0 also stops --apply", async () => {
        const files = conf("[global]\nuploaded-prior-to = P7D\n");
        const old = await run({ tools: pip, env: { STUB_PYTHON3_ENSUREPIP: "21.2.4" }, files });
        assert.deepEqual(status(old.out, "H12"), ["WARN", "PASS"]);
        assert.match(lines(old.out, "H12")[0] ?? "", /^\[WARN\] H12 +python3 \(\S+\/python3\) installs pip 21\.2\.4 in each new virtual environment \(python3 -m venv\), and pip older than 26\.1 ignores uploaded-prior-to/);
        const v26 = await run({ tools: pip, env: { STUB_PYTHON3_ENSUREPIP: "26.0.1" }, args: ["--apply"] });
        assert.match(lines(v26.out, "H12")[0] ?? "", /^\[WARN\] H12 +python3 .* installs pip 26\.0\.1 in each new virtual environment .* that pip fails to install anything \(pip 26\.0\)/);
        assert.match(lines(v26.out, "H12")[1] ?? "", /not written by --apply: with P7D in its config, the pip 26\.0\.1 that python3 -m venv installs would fail to install anything/);
        assert.equal(existsSync(join(v26.home, PIP_USER)), false);
        for (const ensurepip of ["26.1.2", "none"]) {
          assert.deepEqual(status((await run({ tools: pip, env: { STUB_PYTHON3_ENSUREPIP: ensurepip }, files })).out, "H12"), ["PASS"], ensurepip);
        }
      });

      test("a pip config file pip cannot load is a WARN with pip's error, and --apply leaves it alone", async () => {
        const broken = "[global]\nuploaded-prior-to = P1D\nuploaded-prior-to = P30D\n";
        const r = await run({ tools: pip, args: ["--apply"], files: conf(broken) });
        assert.deepEqual(status(r.out, "H12"), ["WARN"]);
        assert.match(lines(r.out, "H12")[0] ?? "", /^\[WARN\] H12 +python3 -m pip \(.*\) did not report a version \(a pip config file it cannot parse\?\), so its settings were not checked\. 'python3 -m pip --version' shows the error: .*option 'uploaded-prior-to' in section 'global' already exists/);
        assert.equal(home(r, PIP_USER), broken);
        assert.deepEqual(backups(join(r.home, ".config/pip"), "pip.conf"), []);
      });

      test("the same pip under two names is reported once; two different pips are each judged", async () => {
        const files = conf("[global]\nuploaded-prior-to = P7D\n");
        const same = await run({ tools: { python3: "26.1.2", pip3: "26.1.2", pip: "26.1.2" }, files });
        assert.deepEqual(lines(same.out, "H12"), [`[PASS] H12  pip 26.1.2 (python3 -m pip, pip3, pip): uploaded-prior-to: install, download, lock and wheel use "P7D" from [global] in ${userFile(same)}`]);
        const xdg = scratch("pipxdg-");
        const two = await run({
          tools: { python3: "26.1.2", pip3: "26.2.1" },
          env: { STUB_PIP3_LOCATION: "/other/site-packages/pip", STUB_PIP3_USERCONF: join(xdg, "pip", "pip.conf") },
          files,
        });
        assert.deepEqual(status(two.out, "H12"), ["PASS", "FAIL"]);
        assert.match(lines(two.out, "H12")[1] ?? "", /^\[FAIL\] H12 +pip 26\.2\.1 \(pip3\): uploaded-prior-to: unset for pip install, download, lock and wheel/);
      });

      test("python3 without a pip module is no pip: SKIP; a pip that will not report a version: WARN", async () => {
        assert.deepEqual(status((await run({ tools: pip, env: { STUB_PYTHON3_MODE: "nopip" } })).out, "H12"), ["SKIP"]);
        const r = await run({ tools: { pip3: "26.1.2" }, env: { STUB_PIP3_MODE: "broken" } });
        assert.match(lines(r.out, "H12")[0] ?? "", /^\[WARN\] H12 +pip3 \(.*\/bin\/pip3\) did not report a version.*: boom$/);
      });

      test("PIP_CONFIG_FILE is a WARN: with it pip skips the user file", async () => {
        const other = join(scratch("pipcfg-"), "pip.conf");
        writeFileSync(other, "[global]\nuploaded-prior-to = P7D\n");
        const r = await run({ tools: pip, env: { PIP_CONFIG_FILE: other }, files: conf("[global]\nuploaded-prior-to = P1D\n") });
        assert.deepEqual(status(r.out, "H12"), ["WARN", "PASS"]);
        assert.match(lines(r.out, "H12")[0] ?? "", /PIP_CONFIG_FILE is set in this environment \(.*\): when it names an existing file pip does not read the user config file/);
      });

      test("--apply writes [global] through pip, backs the file up first, says comments are lost; a second run changes nothing", async () => {
        const original = "# mine\n[global]\nindex-url = https://pypi.org/simple/\nuploaded-prior-to = P1D\n";
        const legacy = "# legacy\n[global]\ntimeout = 60\n";
        const r = await run({ tools: pip, args: ["--apply"], files: { ...conf(original), ".pip/pip.conf": legacy } });
        assert.equal(r.code, 0, r.out);
        // Every user file pip lists is backed up; pip writes only the last one.
        assert.equal(home(r, ".pip/pip.conf"), legacy);
        assert.equal(backups(join(r.home, ".pip"), "pip.conf").length, 1);
        assert.equal(home(r, PIP_USER), "[global]\nindex-url = https://pypi.org/simple/\nuploaded-prior-to = P7D\n\n");
        const b = backups(join(r.home, ".config/pip"), "pip.conf");
        assert.equal(b.length, 1);
        assert.equal(readFileSync(join(r.home, ".config/pip", b[0] as string), "utf8"), original);
        assert.deepEqual(status(r.out, "H12"), ["INFO", "PASS"]);
        assert.match(lines(r.out, "H12")[0] ?? "", /^\[INFO\] H12 +wrote \[global\] uploaded-prior-to = P7D to \S+\/\.config\/pip\/pip\.conf with 'python3 -m pip config --user set global\.uploaded-prior-to P7D' \(pip rewrote the whole file: its comments are gone, the backup above has them\)$/);
        assert.match(lines(r.out, "H12")[1] ?? "", /^\[PASS\] H12 +.*use "P7D" from \[global\] in \S+ \(just applied\)$/);
        const afterFirst = snapshot(r.home);
        const again = await run({ tools: pip, args: ["--apply"], home: r.home });
        assert.deepEqual(changed(afterFirst, snapshot(again.home)), []);
        assert.doesNotMatch(again.out, /backup:|wrote /);
        assert.deepEqual(status(again.out, "H12"), ["PASS"]);
      });

      test("--apply creates the user file when there is none; pip runs from the empty temp dir with no venv and no version check", async () => {
        const r = await run({ tools: pip, args: ["--apply"], env: { VIRTUAL_ENV: "/some/venv" } });
        assert.equal(home(r, PIP_USER), "[global]\nuploaded-prior-to = P7D\n\n");
        assert.doesNotMatch(r.out, /backup:/, "nothing to back up: the file did not exist");
        assert.match(lines(r.out, "H12")[0] ?? "", /^\[INFO\] H12 +wrote \[global\] uploaded-prior-to = P7D to \S+ with '.*' \(pip created the file\)$/);
        const tmp = realpathSync(join(r.root, "tmp"));
        const pipCalls = r.calls.filter((c) => c.tool === "python3");
        assert.ok(pipCalls.some((c) => c.args.join(" ") === "-m pip config --user set global.uploaded-prior-to P7D"));
        for (const c of pipCalls) {
          assert.ok(c.cwd.startsWith(tmp), `ran in ${c.cwd}`);
          assert.equal(c.pipVersionCheck, "1");
          assert.equal(c.virtualEnv, null);
        }
        assert.deepEqual(r.tmpLeft, []);
      });

      test("--apply never lowers a stricter value, and does not write when the failing value is not the user file's [global]", async () => {
        const strict = await run({ tools: pip, args: ["--apply"], files: conf("# keep\n[global]\nuploaded-prior-to = P30D\n") });
        assert.equal(home(strict, PIP_USER), "# keep\n[global]\nuploaded-prior-to = P30D\n");
        const env = await run({ tools: pip, args: ["--apply"], env: { PIP_UPLOADED_PRIOR_TO: "P1D" }, files: conf("# keep\n[global]\nuploaded-prior-to = P7D\n") });
        assert.match(lines(env.out, "H12")[0] ?? "", /PIP_UPLOADED_PRIOR_TO "P1D" is shorter than P7D \(want P7D or longer; not fixed by --apply: PIP_UPLOADED_PRIOR_TO="P1D" in this environment overrides every pip config file/);
        assert.equal(home(env, PIP_USER), "# keep\n[global]\nuploaded-prior-to = P7D\n");
        assert.deepEqual(backups(join(env.home, ".config/pip"), "pip.conf"), []);
      });

      test("--apply does not write [global] over a stricter system-wide one when the failing value is elsewhere", async () => {
        // A user [global] P7D would override the system's P30D for download, lock and wheel, and leave [install] as it is.
        const r = await run({ tools: pip, args: ["--apply"], files: { "../etc/pip.conf": "[global]\nuploaded-prior-to = P30D\n[install]\nuploaded-prior-to = P1D\n" } });
        assert.deepEqual(lines(r.out, "H12"), [
          `[FAIL] H12  pip 26.1.2 (python3 -m pip): uploaded-prior-to: [install] "P1D" in ${join(r.root, "etc/pip.conf")} is shorter than P7D (want P7D or longer; ` +
            `not fixed by --apply: for python3 -m pip, [global] already says "P30D" in ${join(r.root, "etc/pip.conf")}, so the failing value is elsewhere, and writing [global] could only lower it. ` +
            "'<pip> config debug' lists each file's values). Without a cutoff pip installs a release minutes after it is published.",
        ]);
        assert.equal(existsSync(join(r.home, PIP_USER)), false);
        // A failing [global] in a file pip reads after the user file: writing the user file would change nothing.
        const later = await run({ tools: pip, args: ["--apply"], files: { "../site/pip.conf": "[global]\nuploaded-prior-to = P1D\n" } });
        assert.match(lines(later.out, "H12")[0] ?? "", /not fixed by --apply: for python3 -m pip, the \[global\] value that wins says "P1D" in \S+\/site\/pip\.conf, a file pip reads after the user file/);
        assert.equal(existsSync(join(later.home, PIP_USER)), false);
      });

      test("--apply does not write when a pip 26.0 is also installed: P<n>D would break it", async () => {
        const r = await run({ tools: { python3: "26.1.2", pip3: "26.0.1" }, env: { STUB_PIP3_LOCATION: "/old/pip" }, args: ["--apply"] });
        assert.match(lines(r.out, "H12").join("\n"), /not written by --apply: with P7D in its config, pip 26\.0\.1 \(pip3\) would fail to install anything\. Upgrade it first/);
        assert.equal(existsSync(join(r.home, PIP_USER)), false);
      });

      test("--apply's read-back: another pip that reads another file FAILs and the write stays", async () => {
        const xdg = scratch("pipxdg-");
        const r = await run({
          tools: { python3: "26.1.2", pip3: "26.2.1" },
          env: { STUB_PIP3_LOCATION: "/other/site-packages/pip", STUB_PIP3_USERCONF: join(xdg, "pip", "pip.conf") },
          args: ["--apply"],
        });
        assert.deepEqual(status(r.out, "H12"), ["INFO", "PASS", "FAIL"]);
        assert.match(lines(r.out, "H12")[2] ?? "", /^\[FAIL\] H12 +pip 26\.2\.1 \(pip3\): uploaded-prior-to: unset for pip install, download, lock and wheel \(want P7D or longer; \S+ now says P7D under \[global\], but this pip still reports the above: it reads another file/);
        assert.equal(home(r, PIP_USER), "[global]\nuploaded-prior-to = P7D\n\n");
      });

      test("a pip that could not list its config before the write is a WARN and does not undo the write", async () => {
        const r = await run({
          tools: { python3: "26.1.2", pip3: "26.2.1" },
          env: { STUB_PIP3_LOCATION: "/other/site-packages/pip", STUB_PIP3_MODE: "config-fails" },
          args: ["--apply"],
        });
        assert.deepEqual(status(r.out, "H12"), ["WARN", "INFO", "PASS"], r.out);
        assert.match(lines(r.out, "H12")[0] ?? "", /^\[WARN\] H12 +pip 26\.2\.1 \(pip3\) failed to list its config/);
        assert.equal(home(r, PIP_USER), "[global]\nuploaded-prior-to = P7D\n\n");
      });

      test("a write pip cannot read back is undone and is a FAIL; a file pip created is removed again", async () => {
        const original = "# mine\n[global]\nuploaded-prior-to = P1D\n";
        const env = { STUB_PYTHON3_MODE: "set-breaks-config" };
        const r = await run({ tools: pip, args: ["--apply"], env, files: conf(original) });
        assert.match(lines(r.out, "H12").join("\n"), /\[FAIL\] H12 +pip: could not safely edit the user config: 'python3 -m pip config debug' fails after the write; the user config files are back as they were/);
        assert.equal(home(r, PIP_USER), original);
        assert.equal(r.code, 1);
        const fresh = await run({ tools: pip, args: ["--apply"], env });
        assert.match(lines(fresh.out, "H12").join("\n"), /could not safely edit/);
        assert.equal(existsSync(join(fresh.home, PIP_USER)), false);
      });

      test("a failed write is a FAIL, not 'applied', and the file is unchanged", { skip: IS_ROOT && "root ignores file modes" }, async () => {
        const r = await run({ tools: pip, files: conf("[global]\nuploaded-prior-to = P1D\n") });
        chmodSync(join(r.home, PIP_USER), 0o400);
        const a = await run({ tools: pip, args: ["--apply"], home: r.home });
        chmodSync(join(r.home, PIP_USER), 0o600);
        assert.match(lines(a.out, "H12").join("\n"), /\[FAIL\] H12 +pip: could not write global\.uploaded-prior-to with '.*' \(ERROR: An error occurred while writing to the configuration file .*\); the user config files are as they were/);
        assert.doesNotMatch(a.out, /PASS\] H12|wrote \[global\]/);
        assert.equal(home(a, PIP_USER), "[global]\nuploaded-prior-to = P1D\n");
      });
    });

    describe("H13 uv", () => {
      const uvUser = (text: string) => ({ [UV_USER]: text });
      const advice = (r: Run) => `Add 'exclude-newer = "7 days"' at the top level of ${r.home}/.config/uv/uv.toml, before any [table] (not auto-applied).`;

      test("unset FAILs with advice for the top level of the user uv.toml; nothing is written", async () => {
        const r = await run({ tools: { uv: "0.12.21" } });
        assert.deepEqual(lines(r.out, "H13"), [`[FAIL] H13  uv 0.12.21: no exclude-newer applies outside a project (want 7 days or longer). ${advice(r)}`]);
        assert.deepEqual(readdirSync(r.home), []);
        assert.deepEqual(r.tmpLeft, []);
      });

      test("uv 0.12 records a placeholder exclude-newer beside the span: the span counts", async () => {
        const ok = await run({ tools: { uv: "0.12.21" }, files: uvUser('exclude-newer = "7 days"\n') });
        assert.deepEqual(lines(ok.out, "H13"), ["[PASS] H13  uv 0.12.21: exclude-newer-span = \"P7D\" (7 days), from 'uv lock' on an empty project"]);
        const short = await run({ tools: { uv: "0.12.21" }, files: uvUser('exclude-newer = "1 day"\n') });
        assert.deepEqual(lines(short.out, "H13"), [`[FAIL] H13  uv 0.12.21: exclude-newer-span = "P1D" is shorter than 7d (1 day, want 7 days or more). ${advice(short)}`]);
      });

      test("uv 0.10 records the date the span gave: the span still counts", async () => {
        assert.deepEqual(status((await run({ tools: { uv: "0.10.9" }, files: uvUser('exclude-newer = "2 weeks"\n') })).out, "H13"), ["PASS"]);
        const short = await run({ tools: { uv: "0.10.9" }, files: uvUser('exclude-newer = "P3D"\n') });
        assert.match(lines(short.out, "H13")[0] ?? "", /^\[FAIL\] H13 +uv 0\.10\.9: exclude-newer-span = "P3D" is shorter than 7d \(3 days,/);
      });

      test("a span's weeks, days, hours, minutes and seconds add up, compared to the second", async () => {
        const verdict = async (v: string) => lines((await run({ tools: { uv: "0.12.21" }, files: uvUser(`exclude-newer = "${v}"\n`) })).out, "H13");
        assert.match((await verdict("P6DT23H59M59S"))[0] ?? "", /^\[FAIL\] H13 +uv 0\.12\.21: exclude-newer-span = "P6DT23H59M59S" is shorter than 7d \(604799 seconds, want 7 days or more\)/);
        assert.deepEqual(await verdict("P6DT23H59M60S"), ['[PASS] H13  uv 0.12.21: exclude-newer-span = "P6DT23H59M60S" (7 days), from \'uv lock\' on an empty project']);
        assert.match((await verdict("P1W2DT3H"))[0] ?? "", /^\[PASS\] H13 +.*"P1W2DT3H" \(788400 seconds\)/);
      });

      test("a fixed date: its age counts", async () => {
        assert.match(lines((await run({ tools: { uv: "0.12.21" }, files: uvUser(`exclude-newer = "${isoZ(ago(30 * DAY + 1234e3))}"\n`) })).out, "H13")[0] ?? "", /^\[PASS\] H13 +uv 0\.12\.21: exclude-newer = "\S+Z" \(\d+ seconds old\)/);
        assert.deepEqual(status((await run({ tools: { uv: "0.12.21" }, files: uvUser(`exclude-newer = "${isoZ(ago(DAY))}"\n`) })).out, "H13"), ["FAIL"]);
      });

      test("UV_EXCLUDE_NEWER in the environment counts, over the user file", async () => {
        const r = await run({ tools: { uv: "0.12.21" }, env: { UV_EXCLUDE_NEWER: "1 day" }, files: uvUser('exclude-newer = "30 days"\n') });
        assert.deepEqual(status(r.out, "H13"), ["FAIL"]);
      });

      test("the probe stops uv's walk up for project config, and is its own workspace root; uv runs in $WORK with its cache there and no Python downloads", async () => {
        // A uv.toml above the temp dir would set the cutoff if the probe project had no [tool.uv] table.
        const r = await run({ tools: { uv: "0.12.21" }, tmpFiles: { "uv.toml": 'exclude-newer = "30 days"\n' }, files: uvUser('exclude-newer = "1 day"\n') });
        assert.deepEqual(status(r.out, "H13"), ["FAIL"]);
        const tmp = realpathSync(join(r.root, "tmp"));
        const lock = r.calls.filter((c) => c.tool === "uv" && c.args[0] === "lock");
        assert.equal(lock.length, 1);
        for (const c of lock) {
          assert.ok(c.cwd.startsWith(tmp), c.cwd);
          assert.ok(c.uvCache?.startsWith(join(r.root, "tmp")), String(c.uvCache));
          assert.equal(c.uvPythonDownloads, "never");
          assert.match(c.probe ?? "", /^\[tool\.uv\]\npackage = false\n\n\[tool\.uv\.workspace\]\nmembers = \[\]\n/m);
        }
        assert.deepEqual(r.tmpLeft, []);
      });

      test("exclude-newer-package entries shorter than the soak, or off, are WARNs (both lock formats)", async () => {
        for (const v of ["0.10.9", "0.12.21"]) {
          const r = await run({ tools: { uv: v }, files: uvUser('exclude-newer = "7 days"\nexclude-newer-package = { six = "1 day", idna = false, certifi = "3 weeks" }\n') });
          assert.deepEqual(status(r.out, "H13"), ["PASS", "WARN", "WARN"], v);
          const out = lines(r.out, "H13").join("\n");
          assert.match(out, /\[WARN\] H13 +uv \S+: exclude-newer-package lets six through after 1 day, less than 7d \(six = \{ timestamp = "[^"]+", span = "P1D" \}\)/, v);
          assert.match(out, /\[WARN\] H13 +uv \S+: exclude-newer-package turns the cutoff off for idna \(idna = false\)/, v);
        }
      });

      test("[pip] exclude-newer shorter than the soak is a WARN: uv pip uses it, uv lock does not record it", async () => {
        const toml = 'exclude-newer = "7 days"\n\n[pip]\nexclude-newer = "1 day"\n';
        const r = await run({ tools: { uv: "0.12.21", python3: "26.1.2" }, files: uvUser(toml) });
        assert.deepEqual(status(r.out, "H13"), ["PASS", "WARN"]);
        assert.match(lines(r.out, "H13")[1] ?? "", /^\[WARN\] H13 +uv 0\.12\.21: \[pip\] exclude-newer = "1 day" in \S+uv\.toml is shorter than 7d \(1 day\); uv pip commands use it instead of the top-level value$/);
        // UV_EXCLUDE_NEWER would override the second probe's uv.toml; it is removed for that probe.
        const env = await run({ tools: { uv: "0.12.21", python3: "26.1.2" }, env: { UV_EXCLUDE_NEWER: "30 days" }, files: uvUser(toml) });
        assert.deepEqual(status(env.out, "H13"), ["PASS", "WARN"]);
        const fine = await run({ tools: { uv: "0.12.21", python3: "26.1.2" }, files: uvUser(toml.replace('"1 day"', '"8 days"')) });
        assert.deepEqual(status(fine.out, "H13"), ["PASS"]);
        const off = await run({ tools: { uv: "0.12.21", python3: "26.1.2" }, files: uvUser(toml.replace('"1 day"', "false")) });
        assert.match(lines(off.out, "H13")[1] ?? "", /\[pip\] exclude-newer = false in \S+ turns the cutoff off for uv pip commands/);
        const noTomllib = await run({ tools: { uv: "0.12.21", python3: "26.1.2" }, env: { STUB_PYTHON3_MODE: "no-tomllib" }, files: uvUser(toml) });
        assert.match(lines(noTomllib.out, "H13")[1] ?? "", /^\[WARN\] H13 +.*the \[pip\] table and \[\[index\]\] entries of \S+ were not checked: they are read with python3's tomllib/);
        const noPython = await run({ tools: { uv: "0.12.21" }, files: uvUser(toml) });
        assert.deepEqual(status(noPython.out, "H13"), ["PASS", "WARN"]);
      });

      test("[pip] exclude-newer-package entries off or shorter than the soak are WARNs: uv pip uses them, the lock does not record them", async () => {
        const r = await run({ tools: { uv: "0.12.21", python3: "26.1.2" }, files: uvUser('exclude-newer = "7 days"\n\n[pip]\nexclude-newer-package = { six = false, idna = "1 day", certifi = "2 weeks" }\n') });
        assert.deepEqual(lines(r.out, "H13").slice(1), [
          `[WARN] H13  uv 0.12.21: [pip] exclude-newer-package for "six" = false in ${r.home}/${UV_USER} turns the cutoff off for "six" in uv pip commands`,
          `[WARN] H13  uv 0.12.21: [pip] exclude-newer-package for "idna" = "1 day" in ${r.home}/${UV_USER} is shorter than 7d (1 day); uv pip commands use it for "idna"`,
        ]);
      });

      test("an [[index]] entry's own exclude-newer: off or shorter FAILs for the default index or PyPI, WARNs for another; uv < 0.11.5 ignores it", async () => {
        const index = (extra: string) => uvUser(`exclude-newer = "7 days"\n\n[[index]]\nname = "pypi"\nurl = "https://pypi.org/simple"\n${extra}`);
        const off = await run({ tools: { uv: "0.12.21", python3: "26.1.2" }, files: index("default = true\nexclude-newer = false\n") });
        assert.deepEqual(lines(off.out, "H13"), [
          "[PASS] H13  uv 0.12.21: exclude-newer-span = \"P7D\" (7 days), from 'uv lock' on an empty project",
          `[FAIL] H13  uv 0.12.21: [[index]] "pypi" (https://pypi.org/simple, the default index) exclude-newer = false in ${off.home}/${UV_USER} turns the cutoff off for every package uv takes from that index`,
        ]);
        assert.equal(off.code, 1);
        const short = await run({ tools: { uv: "0.12.21", python3: "26.1.2" }, files: index('exclude-newer = "1 day"\n') });
        assert.match(lines(short.out, "H13")[1] ?? "", /^\[FAIL\] H13 +uv 0\.12\.21: \[\[index\]\] "pypi" \(https:\/\/pypi\.org\/simple\) exclude-newer = "1 day" in \S+ is shorter than 7d \(1 day\); uv uses it instead of the top-level value for every package from that index$/);
        assert.deepEqual(status((await run({ tools: { uv: "0.12.21", python3: "26.1.2" }, files: index('exclude-newer = "30 days"\n') })).out, "H13"), ["PASS"]);
        const other = uvUser('exclude-newer = "7 days"\n\n[[index]]\nname = "corp"\nurl = "https://pypi.corp.example/simple"\nexclude-newer = false\n');
        assert.deepEqual(status((await run({ tools: { uv: "0.12.21", python3: "26.1.2" }, files: other })).out, "H13"), ["PASS", "WARN"]);
        // uv 0.10.9 has no per-index exclude-newer: the top-level cutoff applies to every index.
        assert.deepEqual(status((await run({ tools: { uv: "0.10.9", python3: "26.1.2" }, files: index("default = true\nexclude-newer = false\n") })).out, "H13"), ["PASS"]);
      });

      test("UV_PROJECT, UV_WORKING_DIR, UV_FROZEN and UV_LOCKED in the environment do not move or stop the probe", async () => {
        const project = scratch("uvproj-");
        writeFileSync(join(project, "pyproject.toml"), '[project]\nname = "mine"\nversion = "0"\ndependencies = []\n\n[tool.uv]\nexclude-newer = "30 days"\n');
        for (const env of [{ UV_PROJECT: project }, { UV_WORKING_DIR: project }, { UV_FROZEN: "1" }, { UV_LOCKED: "1" }] as Record<string, string>[]) {
          const r = await run({ tools: { uv: "0.12.21" }, env, files: uvUser('exclude-newer = "1 day"\n') });
          assert.match(lines(r.out, "H13")[0] ?? "", /^\[FAIL\] H13 +uv 0\.12\.21: exclude-newer-span = "P1D" is shorter than 7d/, JSON.stringify(env));
          assert.deepEqual(readdirSync(project), ["pyproject.toml"], `${JSON.stringify(env)}: the probe wrote into the user's project`);
        }
      });

      test("uv < 0.9.17 FAILs even with a cutoff set (no relative exclude-newer)", async () => {
        const r = await run({ tools: { uv: "0.9.16" }, files: uvUser('exclude-newer = "7 days"\n') });
        assert.match(lines(r.out, "H13")[0] ?? "", /^\[FAIL\] H13 +uv 0\.9\.16 has no relative exclude-newer \(needs uv >= 0\.9\.17;/);
      });

      test("when the oracle fails it is a WARN with uv's first error line, never a PASS or FAIL", async () => {
        const fails = await run({ tools: { uv: "0.12.21" }, env: { STUB_UV_MODE: "fails" }, files: uvUser('exclude-newer = "7 days"\n') });
        assert.deepEqual(lines(fails.out, "H13"), ["[WARN] H13  uv 0.12.21: oracle unavailable: 'uv lock --offline' on an empty project failed, so its settings were not checked: error: Failed to parse: `uv.toml`"]);
        for (const mode of ["no-lock", "bad-span"]) {
          const r = await run({ tools: { uv: "0.12.21" }, env: { STUB_UV_MODE: mode }, files: uvUser('exclude-newer = "7 days"\n') });
          assert.deepEqual(status(r.out, "H13"), ["WARN"], mode);
          assert.match(lines(r.out, "H13")[0] ?? "", /oracle unavailable: could not read the lock uv wrote/, mode);
        }
        const broken = await run({ tools: { uv: "0.12.21" }, env: { STUB_UV_MODE: "broken" } });
        assert.match(lines(broken.out, "H13")[0] ?? "", /^\[WARN\] H13 +uv at .* did not report a version offline/);
      });
    });

    describe("H14 the wiper's token watcher", () => {
      // The paths Wiz and StepSecurity give for the May 2026 gh-token-monitor watcher (docs/incident-response.md, step 1),
      // each planted as an inert one-line stub. The token directory is the one StepSecurity's remediation removes.
      const WATCHER: Record<string, string> = {
        ".config/systemd/user/gh-token-monitor.service": "[Unit]\nDescription=inert test stub\n",
        ".local/bin/gh-token-monitor.sh": "# inert test stub\n",
        "Library/LaunchAgents/com.user.gh-token-monitor.plist": "<!-- inert test stub -->\n",
        ".config/gh-token-monitor/token": "not-a-token\n",
      };
      const ISOLATE = "docs/incident-response.md#1-isolate-the-machine-before-revoking-anything";

      test("each documented watcher file is a critical FAIL that says to isolate before revoking, linking the incident-response step", async () => {
        const r = await run({ files: WATCHER });
        assert.equal(r.code, 1, r.out);
        const found = lines(r.out, "H14");
        const at = [".config/systemd/user/gh-token-monitor.service", ".local/bin/gh-token-monitor.sh", "Library/LaunchAgents/com.user.gh-token-monitor.plist", ".config/gh-token-monitor"];
        assert.deepEqual(found.map((l) => /^\[FAIL\] H14 +(\S+) exists \(critical; /.exec(l)?.[1]).sort(), at.map((p) => `${r.home}/${p}`).sort(), r.out);
        for (const l of found) {
          assert.ok(l.includes("(critical; do not revoke tokens yet: isolate this machine first)"), l);
          assert.ok(l.includes(`See ${ISOLATE};`), l);
        }
        assert.ok(r.out.includes(`H14 found the gh-token-monitor watcher: do not revoke tokens yet: isolate this machine first, before acting on any other FAIL (${ISOLATE}).`), r.out);
        // H14 comes first, before any package manager is asked: what it finds changes what to do about every other FAIL.
        assert.match(r.out.split("\n").find((l) => /^\[[A-Z]+\] +H\d\d /.test(l)) ?? "", /^\[FAIL\] H14 /);
        // The link resolves to the step's heading (GitHub's anchor for it), and the step names the check.
        const ir = readFileSync(join(ROOT, "docs", "incident-response.md"), "utf8");
        assert.match(ir, /^## 1\. Isolate the machine before revoking anything$/m);
        for (const s of ["~/Library/LaunchAgents/com.user.gh-token-monitor.plist", "~/.config/systemd/user/gh-token-monitor.service", "H14"]) assert.ok(ir.includes(s), s);
      });

      test("one file is enough, a dangling symlink counts, and a clean HOME or look-alike names PASS", async () => {
        const one = await run({ files: { "Library/LaunchAgents/com.user.gh-token-monitor.plist": "x\n" } });
        assert.deepEqual(status(one.out, "H14"), ["FAIL"]);
        const h = scratch("home-");
        mkdirSync(join(h, ".config/systemd/user"), { recursive: true });
        symlinkSync("/nonexistent/wormsign-test/unit", join(h, ".config/systemd/user/gh-token-monitor.service"));
        const dangling = await run({ home: h });
        assert.deepEqual(status(dangling.out, "H14"), ["FAIL"], dangling.out);

        const clean = await run({
          files: {
            "Library/LaunchAgents/com.user.other-monitor.plist": "x\n",
            ".config/systemd/user/gh-token-monitor.timer": "x\n",
            ".local/bin/gh-token-monitor": "x\n",
            ".config/gh/hosts.yml": "github.com:\n  user: x\n",
          },
        });
        assert.deepEqual(status(clean.out, "H14"), ["PASS"], clean.out);
        assert.match(lines(clean.out, "H14")[0] ?? "", /^\[PASS\] H14 +no gh-token-monitor watcher files at: \S+\/Library\/LaunchAgents\/com\.user\.gh-token-monitor\.plist /);
        assert.doesNotMatch(clean.out, /do not revoke tokens yet/);
        assert.equal(clean.code, 0, clean.out);
      });

      test("--apply leaves every watcher file in place, unchanged, while it applies the other fixes", async () => {
        const seeded = await run({ files: WATCHER });
        mkdirSync(join(seeded.home, ".config/systemd/user/default.target.wants"));
        symlinkSync("../gh-token-monitor.service", join(seeded.home, ".config/systemd/user/default.target.wants/gh-token-monitor.service"));
        const before = snapshot(seeded.home);
        const applied = await run({ tools: { npm: "11.21.0" }, args: ["--apply"], home: seeded.home });
        assert.match(applied.out, /\[INFO\] H01 +wrote ignore-scripts=true to /, "positive control: --apply wrote something");
        assert.deepEqual(changed(before, snapshot(applied.home)).filter((p) => !p.startsWith(".npmrc")), [], "--apply touched only the npm config");
        for (const [p, content] of Object.entries(WATCHER)) assert.equal(home(applied, p), content, p);
        assert.ok(lstatSync(join(applied.home, ".config/systemd/user/default.target.wants/gh-token-monitor.service")).isSymbolicLink());
        assert.deepEqual(status(applied.out, "H14"), ["FAIL", "FAIL", "FAIL", "FAIL"]);
        assert.equal(applied.code, 1);
      });

      test("a directory on the way that cannot be searched is a WARN, never a PASS", { skip: IS_ROOT && "root reads anything" }, async () => {
        const r = await run({ files: { "Library/LaunchAgents/other.plist": "x\n" } });
        chmodSync(join(r.home, "Library/LaunchAgents"), 0o000);
        const again = await run({ home: r.home });
        chmodSync(join(r.home, "Library/LaunchAgents"), 0o700);
        assert.deepEqual(lines(again.out, "H14"), [`[WARN] H14  ${r.home}/Library/LaunchAgents could not be searched, so whether the gh-token-monitor watcher's files are in it is unknown. Check before revoking any token: ${ISOLATE}`]);
      });
    });

    test("Poetry, PDM and pipenv on PATH: one INFO line saying they are not checked yet", async () => {
      const r = await run({ tools: { poetry: "", pdm: "" } });
      assert.match(r.out, /^\[INFO\] +poetry, pdm found on PATH: their release-age settings are not checked by this script yet\.$/m);
      assert.doesNotMatch((await run()).out, /not checked by this script yet/);
    });

    describe("the script's own environment: temp directory, PATH, CDPATH, symlinks, backups", () => {
      /** Plants, in `dir`, what another local user could leave in a shared /tmp: config the package managers read from parent directories. */
      const plant = (dir: string): string => {
        const marker = join(dir, "PWNED");
        const evil = join(dir, "evil.cjs");
        writeFileSync(evil, `require("node:fs").appendFileSync(${JSON.stringify(marker)}, process.argv.slice(2).join(" ") + "\\n");\nconsole.log(process.argv[2] === "--version" ? "1.22.22" : "true");\n`);
        writeFileSync(join(dir, ".yarnrc"), `yarn-path "${evil}"\n`);
        writeFileSync(join(dir, "package.json"), "{}\n");
        writeFileSync(join(dir, ".npmrc"), "ignore-scripts=true\n");
        return marker;
      };
      const pms = { npm: "10.9.2", yarn: "1.22.22" };

      test("a TMPDIR other users can write is not used: the probes run in a private directory, so nothing planted above them is read or run", async () => {
        // Positive control: the stubs read config from the directories above the probe directory, as npm and Yarn
        // Classic do, so with the planted files above it the planted script runs and H01 passes falsely.
        const own = scratch("planted-");
        const ownMarker = plant(own);
        const control = await run({ tools: pms, env: { TMPDIR: own } });
        assert.ok(existsSync(ownMarker), "the stub ran the planted yarn-path");
        assert.deepEqual(status(control.out, "H01"), ["PASS"], "the planted .npmrc was read");

        const shared = scratch("shared-");
        chmodSync(shared, 0o1777);
        const marker = plant(shared);
        const r = await run({ tools: pms, env: { TMPDIR: shared } });
        assert.equal(existsSync(marker), false, `the planted script ran: ${existsSync(marker) ? readFileSync(marker, "utf8") : ""}`);
        assert.match(lines(r.out, "H01")[0] ?? "", /^\[FAIL\] H01 +npm 10\.9\.2: ignore-scripts is false/);
        assert.match(lines(r.out, "H06")[0] ?? "", /^\[FAIL\] H06 +Yarn Classic 1\.22\.22: ignore-scripts is false/);
        const homeDir = realpathSync(r.home);
        assert.ok(r.calls.length > 0);
        for (const c of r.calls) assert.ok(c.cwd.startsWith(`${homeDir}/wormsign-harden.`), `ran in ${c.cwd}`);
        assert.deepEqual(readdirSync(r.home), [], "the temporary directory in HOME is removed");
      });

      test("no private directory for temporary files: exit 2, nothing run", async () => {
        const shared = scratch("shared-");
        chmodSync(shared, 0o1777);
        const openHome = scratch("openhome-");
        chmodSync(openHome, 0o777);
        const r = await run({ tools: pms, home: openHome, env: { TMPDIR: shared } });
        assert.equal(r.code, 2, r.out);
        assert.match(r.out, /no private directory for temporary files: TMPDIR \(or \/tmp\), XDG_RUNTIME_DIR, ~\/\.cache and HOME/);
        assert.deepEqual(r.calls, []);
      });

      test("relative PATH entries are dropped with a WARN, so a checkout's own binaries never run", async () => {
        const repo = scratch("repo-");
        const marker = join(repo, "PWNED");
        mkdirSync(join(repo, "node_modules", ".bin"), { recursive: true });
        writeFileSync(join(repo, "node_modules", ".bin", "node"), `#!/bin/sh\necho "repo-local node ran: $1" >>${JSON.stringify(marker)}\nexec ${JSON.stringify(process.execPath)} "$@"\n`, { mode: 0o755 });
        // A dev directory, so H11 runs node from the script's own shell.
        const r = await run({ cwd: repo, pathPrefix: "node_modules/.bin::", files: { "code/README": "x\n" } });
        assert.equal(existsSync(marker), false, `the checkout's node ran: ${existsSync(marker) ? readFileSync(marker, "utf8") : ""}`);
        assert.match(r.out, /^\[WARN\] +PATH entries that are not absolute directories were left out for this run, so no command runs from the current directory: node_modules\/\.bin \(empty\)$/m);
        assert.deepEqual(status(r.out, "H11"), ["PASS"]);
      });

      test("an exported CDPATH does not break SCRIPT_DIR (H11 still runs)", async () => {
        const parent = scratch("cdpath-");
        symlinkSync(ROOT, join(parent, "wormsign"));
        const r = await run({ cwd: parent, script: "wormsign/harden-dev.sh", env: { CDPATH: "." }, files: { "code/README": "x\n" } });
        assert.deepEqual(status(r.out, "H11"), ["PASS"], r.out);
      });

      test("--soak digits are decimal (010d is 10 days, 08d works); more than 6 digits or zero is a usage error", async () => {
        const banner = (r: Run) => r.out.split("\n").find((l) => l.startsWith("wormsign harden-dev: "));
        assert.equal(banner(await run({ args: ["--soak", "010d"] })), "wormsign harden-dev: mode=check soak=010d (npm 10d, pnpm/yarn 14400min, bun 864000s)");
        const eight = await run({ args: ["--soak", "08d"] });
        assert.equal(eight.code, 0, eight.out);
        assert.equal(banner(eight), "wormsign harden-dev: mode=check soak=08d (npm 8d, pnpm/yarn 11520min, bun 691200s)");
        for (const bad of ["1234567d", "00d"]) assert.equal((await run({ args: ["--soak", bad] })).code, 2, bad);
      });

      test("--apply backs a file up with mode 0600, also when it is a symlink to a wider file", async () => {
        const h = scratch("home-");
        mkdirSync(join(h, ".dotfiles"), { mode: 0o700 });
        const token = "//registry.npmjs.org/:_authToken=npm_0123456789abcdefghijklmnopqrstuvwxyzABCD\n";
        writeFileSync(join(h, ".dotfiles", "npmrc"), token, { mode: 0o644 });
        chmodSync(join(h, ".dotfiles", "npmrc"), 0o644);
        symlinkSync(".dotfiles/npmrc", join(h, ".npmrc"));
        const r = await run({ tools: { npm: "11.21.0" }, args: ["--apply"], home: h });
        const b = backups(h, ".npmrc");
        assert.equal(b.length, 1, r.out);
        assert.equal(lstatSync(join(h, b[0] as string)).mode & 0o777, 0o600);
        assert.equal(readFileSync(join(h, b[0] as string), "utf8"), token);
        assert.ok(lstatSync(join(h, ".npmrc")).isSymbolicLink(), "the link is kept; the write goes to its target");
        assert.match(readFileSync(join(h, ".dotfiles", "npmrc"), "utf8"), /ignore-scripts=true/);
      });

      test("--apply neither writes through nor removes a config path that is a symlink to a missing file", async () => {
        const h = scratch("home-");
        mkdirSync(join(h, "dotfiles"));
        mkdirSync(join(h, PNPM_DIR), { recursive: true });
        const up = PNPM_DIR.split("/").map(() => "..").join("/");
        symlinkSync(`${up}/dotfiles/pnpm-config.yaml`, join(h, PNPM_DIR, "config.yaml"));
        // A pnpm that cannot read any config.yaml: before the fix the write went through the link, the read-back failed,
        // and the undo deleted the link while leaving the file it had created.
        const r = await run({ tools: { pnpm: "11.16.0" }, args: ["--apply"], home: h, env: { STUB_PNPM_MODE: "rejects-config" } });
        assert.ok(lstatSync(join(h, PNPM_DIR, "config.yaml")).isSymbolicLink(), "the link is still there");
        assert.equal(existsSync(join(h, "dotfiles", "pnpm-config.yaml")), false, "nothing was written through the link");
        assert.match(lines(r.out, "H04").join("\n"), /\[WARN\] H04 +\S+config\.yaml is a symlink to a file that does not exist, so --apply neither wrote through it nor removed it\./);
        assert.match(lines(r.out, "H04").join("\n"), /\[FAIL\] H04 +pnpm 11\.16\.0: minimumReleaseAge is unset \(want >= 10080; not written, see the WARN above\)/);
        assert.equal(r.code, 1);
      });

      test("--apply does not have pip write through a user config file that is a symlink to a missing file", async () => {
        const h = scratch("home-");
        mkdirSync(join(h, "dotfiles"));
        mkdirSync(join(h, ".config", "pip"), { recursive: true });
        symlinkSync("../../dotfiles/pip.conf", join(h, PIP_USER));
        const r = await run({ tools: { python3: "26.1.2" }, args: ["--apply"], home: h });
        assert.ok(lstatSync(join(h, PIP_USER)).isSymbolicLink(), "the link is still there");
        assert.equal(existsSync(join(h, "dotfiles", "pip.conf")), false, "nothing was written through the link");
        assert.match(lines(r.out, "H12")[0] ?? "", /^\[WARN\] H12 +\S+pip\.conf is a symlink to a file that does not exist, so --apply neither wrote through it nor removed it\./);
        assert.match(lines(r.out, "H12")[1] ?? "", /^\[FAIL\] H12 +pip 26\.1\.2 .*; not written, see the WARN above\)/);
        assert.equal(r.code, 1);
      });

      test("H08 scans pip's user config files and their backups", async () => {
        const url = "index-url = https://ci-user:pipsecrettoken123456@pypi.example/simple\n";
        const r = await run({ files: { [PIP_USER]: `[global]\n${url}`, [`${PIP_USER}.wormsign-bak.20260101000000.1`]: `[global]\n${url}`, ".pip/pip.conf": `[global]\n${url}` } });
        const found = lines(r.out, "H08").map((l) => (l.match(/\/home\/(\S+?:\d+) /) ?? [])[1]).sort();
        assert.deepEqual(found, [".config/pip/pip.conf.wormsign-bak.20260101000000.1:2", ".config/pip/pip.conf:2", ".pip/pip.conf:2"]);
        assert.ok(lines(r.out, "H08").every((l) => /^\[FAIL\] H08 .* user:password in a URL\./.test(l)));
        assert.ok(!r.out.includes("pipsecret"), "the secret is never printed");
      });
    });

    describe("--apply", () => {
      const tools = { npm: "11.21.0", pnpm: "11.16.0", yarn: "4.10.3" };
      const files = {
        ".npmrc": "# keep me\nregistry=https://registry.npmjs.org/\n",
        [`${PNPM_DIR}/config.yaml`]: "storeDir: /tmp/store\n",
        ".yarnrc.yml": "nodeLinker: node-modules\n",
        ".zshrc": "export PATH=$PATH:/x\n",
      };
      const documented = new RegExp(`^(\\.npmrc|${escapeRegExp(PNPM_DIR)}\\/config\\.yaml|\\.yarnrc\\.yml)(\\.wormsign-bak\\.\\d+\\.\\d+)?$`);

      test("backs up every changed file once, writes only documented files, and a second run changes nothing", async () => {
        const seeded = await run({ tools, files });
        const original = snapshot(seeded.home);
        const first = await run({ tools, args: ["--apply"], home: seeded.home });
        assert.equal(first.code, 0, first.out);
        const afterFirst = snapshot(first.home);
        const diff = changed(original, afterFirst);
        for (const p of diff) assert.match(p, documented, `unexpected write: ${p}`);
        for (const f of [".npmrc", `${PNPM_DIR}/config.yaml`, ".yarnrc.yml"]) {
          const b = backups(dirname(join(first.home, f)), f.split("/").pop() as string);
          assert.equal(b.length, 1, `${f} backups: ${b.join(",")}`);
          assert.equal(readFileSync(join(dirname(join(first.home, f)), b[0] as string), "utf8"), files[f]);
        }
        assert.equal(home(first, ".npmrc"), "# keep me\nregistry=https://registry.npmjs.org/\nignore-scripts=true\nmin-release-age=7\n");
        assert.deepEqual(first.tmpLeft, []);

        const second = await run({ tools, args: ["--apply"], home: seeded.home });
        assert.equal(second.code, 0, second.out);
        assert.deepEqual(changed(afterFirst, snapshot(second.home)), [], "second --apply changed files");
        assert.doesNotMatch(second.out, /backup:|wrote /);
        assert.match(second.out, /summary: \d+ pass, 0 warn, 0 fail/);
      });
    });
  });
}

// The minimum pip and uv versions are the script's PIP_MIN and UV_MIN (H12, H13), and nothing else holds them. The script
// must apply its own: the minimum passes with a good cutoff, the version just below fails. docs/hardening.md's check
// table states them.
test("harden-dev.sh applies its own minimum pip and uv versions, which docs/hardening.md states", async () => {
  const text = readFileSync(SCRIPT, "utf8");
  const pipMin = /^PIP_MIN=(\d+(?:\.\d+)+)$/m.exec(text)?.[1];
  const uvMin = /^UV_MIN=(\d+(?:\.\d+)+)$/m.exec(text)?.[1];
  assert.ok(pipMin && uvMin, "positive control: PIP_MIN and UV_MIN are found");
  const table = readFileSync(join(ROOT, "docs", "hardening.md"), "utf8").split("\n");
  assert.match(table.find((l) => l.startsWith("| H12 |")) ?? "", new RegExp(`relative values need pip >= ${escapeRegExp(pipMin)};`));
  assert.match(table.find((l) => l.startsWith("| H13 |")) ?? "", new RegExp(`relative values need uv >= ${escapeRegExp(uvMin)}\\)`));
  const below = (v: string): string => {
    const p = v.split(".").map(Number);
    p[p.length - 1] = (p[p.length - 1] as number) - 1;
    return [...p, 999].join(".");
  };
  const bash = BASHES[0] as string;
  const files = { [PIP_USER]: "[global]\nuploaded-prior-to = P7D\n", [UV_USER]: 'exclude-newer = "7 days"\n' };
  const at = await runWith(bash, { tools: { python3: pipMin, uv: uvMin }, files });
  assert.deepEqual([status(at.out, "H12"), status(at.out, "H13")], [["PASS"], ["PASS"]], at.out);
  const under = await runWith(bash, { tools: { python3: below(pipMin), uv: below(uvMin) }, files });
  assert.match(lines(under.out, "H12")[0] ?? "", new RegExp(`^\\[FAIL\\] H12 +pip ${escapeRegExp(below(pipMin))} `));
  assert.match(lines(under.out, "H13")[0] ?? "", new RegExp(`^\\[FAIL\\] H13 +uv ${escapeRegExp(below(uvMin))} has no relative exclude-newer \\(needs uv >= ${escapeRegExp(uvMin)};`));
});

// soak (src/soak-config.ts) and harden-dev.sh each say which package-manager release first enforces its release-age
// setting. They must agree: soak's ENFORCED_SINCE version passes the script's version gate, the version just below fails
// it, and the script's message names the same version.
test("harden-dev.sh's release-age version gates are soak's ENFORCED_SINCE", async () => {
  const short = (v: string): string => v.replace(/(\.0)+$/, "");
  const below = (v: string): string => {
    const p = v.split(".").map(Number);
    while (p.length > 1 && p[p.length - 1] === 0) p.pop();
    p[p.length - 1] = (p[p.length - 1] as number) - 1;
    return [...p, 999].join(".");
  };
  const gates = [
    { tool: "npm", id: "H02", name: "npm" },
    { tool: "pnpm", id: "H04", name: "pnpm" },
    { tool: "yarn", id: "H05", name: "Yarn" },
    { tool: "bun", id: "H07", name: "Bun" },
  ] as const;
  assert.deepEqual(gates.map((g) => g.tool).sort(), Object.keys(ENFORCED_SINCE).sort(), "every manager soak knows");
  const bash = BASHES[0] as string;
  const at = await runWith(bash, { tools: Object.fromEntries(gates.map((g) => [g.tool, ENFORCED_SINCE[g.tool]])) });
  const under = await runWith(bash, { tools: Object.fromEntries(gates.map((g) => [g.tool, below(ENFORCED_SINCE[g.tool])])) });
  for (const g of gates) {
    const needs = new RegExp(`needs ${g.name} >= ${escapeRegExp(short(ENFORCED_SINCE[g.tool]))}(?![0-9.])`);
    assert.ok(lines(at.out, g.id).length > 0, `${g.id} ran`);
    for (const l of lines(at.out, g.id)) assert.doesNotMatch(l, /needs (npm|pnpm|Yarn|Bun) >= /, `${g.tool} ${ENFORCED_SINCE[g.tool]}: ${l}`);
    assert.ok(lines(under.out, g.id).some((l) => l.startsWith("[FAIL]") && needs.test(l)), `${g.tool} ${below(ENFORCED_SINCE[g.tool])}: ${lines(under.out, g.id).join(" | ")}`);
  }
});

// A bunfig.toml minimumReleaseAge is read by soak's readBunfig (a project's file) and by H07 (the user's file). Each
// value below gets the same verdict from both at a 7-day soak: a pass, or a finding (WS-SK-003/004, an H07 FAIL).
test("harden-dev.sh's H07 and soak read a bunfig.toml minimumReleaseAge alike", async () => {
  const values: [value: string, passes: boolean][] = [
    ["604800", true], ["604_800", true], ["6_0_4_8_0_0", true], ["604800 # 7 days", true], ["1209600", true],
    ["86400", false], ["604__800", false], ["_604800", false], ["604800_", false], ["0604800", false],
    ["604800.0", false], ["6.048e5", false], ["0x93A80", false], ['"604800"', false], ['"7d"', false], ["", false],
  ];
  // Whole files, for the table headers around the value: a header with a comment starts a new table, so a
  // minimumReleaseAge under `[test] # unit tests` is not [install]'s (a review found soak read it as [install]'s).
  const files: [text: string, passes: boolean][] = [
    ['[install]\nregistry = "https://registry.npmjs.org"\n\n[test] # unit tests\nminimumReleaseAge = 604800\n', false],
    ["[test] # unit tests\nminimumReleaseAge = 604800\n", false],
    ["[install]\nminimumReleaseAge = 86400\n[test] # longer\nminimumReleaseAge = 604800\n", false],
    ["[install]\t \nminimumReleaseAge = 604800\n[test]   # c\n", true],
    ["[ install ]\nminimumReleaseAge = 604800\n", true],
    // An array of tables is never [install]; a header may carry a comment; a multi-line string's lines are its content
    // (a round-2 review: soak read `[[test.x]]` as no header, a false pass, and H07 read `[install] # x` as another table).
    ["[install]\n[[test.x]]\nminimumReleaseAge = 604800\n", false],
    ["[[install]]\nminimumReleaseAge = 604800\n", false],
    ["[install] # bun\nminimumReleaseAge = 604800\n", true],
    ["[ install ]\t# bun\nminimumReleaseAge = 604800\n", true],
    ['[install]\nnote = """\n[test]\n"""\nminimumReleaseAge = 604800\n', true],
    ["[install]\nnote = '''\n[test] # x\n'''\nminimumReleaseAge = 604800\n", true],
    ['[test]\nnote = """\n[install]\nminimumReleaseAge = 604800\n"""\n', false],
    ['[install]\nnote = """one line"""\nminimumReleaseAge = 604800\n', true],
    ['[install]\nnote = """ a \'\'\' b """\n[test]\nminimumReleaseAge = 604800\n', false],
  ];
  const bash = BASHES[0] as string;
  const texts: [text: string, passes: boolean, value: string][] = [...values.map(([v, p]): [string, boolean, string] => [`[install]\nminimumReleaseAge = ${v}\n`, p, v]), ...files.map(([t, p]): [string, boolean, string] => [t, p, t])];
  const cases = texts.flatMap(([body, passes, value]) => ["\n", "\r\n"].map((eol) => ({ value, passes, eol, body })));
  const got: { value: string; passes: boolean; eol: string; harden: string[]; soak: string[] }[] = [];
  for (let i = 0; i < cases.length; i += 8) {
    got.push(...(await Promise.all(cases.slice(i, i + 8).map(async ({ body, ...c }) => {
      const text = body.replaceAll("\n", c.eol);
      const r = await runWith(bash, { tools: { bun: "1.4.2" }, files: { ".bunfig.toml": text } });
      const d = scratch("bunsoak-");
      writeFileSync(join(d, "bunfig.toml"), text);
      const soak = checkSoakConfig(d, [], { minAgeMs: 7 * DAY, versionOf: () => ({ version: "99.0.0", source: "stub" }) });
      return { ...c, harden: status(r.out, "H07"), soak: soak.map((f) => `${f.ruleId}: ${f.message}`) };
    }))));
  }
  for (const g of got) {
    const what = `${JSON.stringify(g.value)} with ${JSON.stringify(g.eol)} line ends`;
    assert.deepEqual(g.harden, [g.passes ? "PASS" : "FAIL"], `H07: ${what}`);
    assert.equal(g.soak.length === 0, g.passes, `soak: ${what}: ${g.soak.join("; ")}`);
  }
});

// CI runs `shellcheck harden-dev.sh scripts/*.sh` at the default severity; run the same here when it is installed, so
// a regression shows before CI. Waivers are `# shellcheck disable=` directives in the script, each with its reason.
test("shellcheck passes on harden-dev.sh and scripts/*.sh at the default severity", { skip: !which("shellcheck") && "shellcheck is not installed" }, () => {
  const scripts = readdirSync(join(ROOT, "scripts")).filter((f) => f.endsWith(".sh")).map((f) => join(ROOT, "scripts", f));
  const r = spawnSync(which("shellcheck") as string, [SCRIPT, ...scripts], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});

// With CDPATH exported, `cd` to a relative directory prints the directory it chose, so `$(cd dir && pwd)` would hold two
// lines. Every shell script that resolves its own or an argument's directory that way empties CDPATH first.
test("shell scripts: every $(cd ...) is CDPATH-safe", () => {
  const files = [SCRIPT, ...readdirSync(join(ROOT, "scripts")).filter((f) => f.endsWith(".sh")).map((f) => join(ROOT, "scripts", f)), join(ROOT, "test", "fixtures", "lockfiles", "protocols", "generate.sh")];
  let seen = 0;
  for (const f of files) {
    for (const [i, l] of readFileSync(f, "utf8").split("\n").entries()) {
      for (const m of l.matchAll(/\$\((CDPATH='' )?cd /g)) {
        seen++;
        assert.ok(m[1], `${relative(ROOT, f)}:${i + 1}: ${l.trim()}`);
      }
    }
  }
  assert.ok(seen >= 3, "the idiom was found where it is used");
});

test("harden-dev.sh: every single-quoted awk program that uses $ carries its SC2016 waiver", () => {
  // shellcheck reports SC2016 (info) for these, and the info level fails CI's default run.
  const text = readFileSync(SCRIPT, "utf8").split("\n");
  for (const [i, l] of text.entries()) {
    if (/^[A-Z_]+='$/.test(l) && text.slice(i + 1, text.indexOf("}'", i) + 1).some((x) => x.includes("$"))) {
      assert.match(text[i - 1] ?? "", /^# shellcheck disable=SC2016\b/, `line ${i + 1}: ${l}`);
    }
  }
});
