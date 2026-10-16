// Tests for the CI scripts the workflows run: the self-scan with its positive control (scripts/ci-self-scan.mjs),
// the root-project checkout the soak gate uses (scripts/ci-root-project.sh) and the release-tag verification
// (scripts/ci-verify-release.sh). Each test builds a throwaway git repository; the user's git config is not read.
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const script = (name: string): string => join(ROOT, "scripts", name);

const GIT_ENV = {
  PATH: process.env["PATH"] ?? "",
  // No user config, IOC cache or npm settings leak in.
  HOME: mkdtempSync(join(tmpdir(), "wormsign-ci-home-")),
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_AUTHOR_NAME: "t",
  GIT_AUTHOR_EMAIL: "t@example.invalid",
  GIT_COMMITTER_NAME: "t",
  GIT_COMMITTER_EMAIL: "t@example.invalid",
};
after(() => rmSync(GIT_ENV.HOME, { recursive: true, force: true }));
const git = (cwd: string, ...args: string[]): string => execFileSync("git", args, { cwd, env: GIT_ENV, encoding: "utf8" }).trim();

function repo(files: Record<string, string>): string {
  const d = mkdtempSync(join(tmpdir(), "wormsign-ci-scripts-"));
  git(d, "init", "-q", "-b", "main");
  write(d, files);
  git(d, "add", "-A");
  git(d, "commit", "-q", "-m", "init");
  return d;
}

function write(d: string, files: Record<string, string>): void {
  for (const [p, text] of Object.entries(files)) {
    mkdirSync(dirname(join(d, p)), { recursive: true });
    writeFileSync(join(d, p), text);
  }
}

/* ---- ci-self-scan.mjs ---- */

const selfScan = (d: string) => spawnSync(process.execPath, [script("ci-self-scan.mjs"), d], { encoding: "utf8", env: GIT_ENV });
const CLEAN = { "package.json": '{ "name": "p", "version": "1.0.0" }\n', "index.js": "export {};\n" };
const IOC_WORKFLOW = "on: workflow_dispatch\njobs: {}\n";

test("self-scan: a clean repository passes and the positive control fails the scan", () => {
  const d = repo(CLEAN);
  try {
    const r = selfScan(d);
    assert.equal(r.status, 0, r.stdout);
    assert.match(r.stdout, /ok: the scan exits 1 and reports WS-GH-001 for \.github\/workflows\/shai-hulud-workflow\.yml/);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("self-scan: a baseline that ignores .github fails, because the positive control is hidden", () => {
  const baseline = { version: 1, entries: [], ignorePaths: [{ path: ".github", justification: "an over-broad ignore that hides workflows" }] };
  const d = repo({ ...CLEAN, ".wormsign-baseline.json": JSON.stringify(baseline) });
  try {
    const r = selfScan(d);
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stdout, /FAIL: with \.github\/workflows\/shai-hulud-workflow\.yml added the scan exited 0 \(expected 1\) and did not report/);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("self-scan: an unbaselined finding below high fails it too", () => {
  // WS-EX-001 is medium, below the CLI's default --fail-on high. Built from parts so this source file holds no
  // endpoint literal for the self-scan to report; the written file does.
  const d = repo({ ...CLEAN, "lib.js": `fetch("https://${"webhook"}.site/0000-made-up");\n` });
  try {
    const r = selfScan(d);
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stdout, /MEDIUM {3}WS-EX-001 {2}lib\.js:1/);
    assert.match(r.stdout, /FAIL: the self-scan exited 1, expected 0/);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("self-scan: scans what git would commit: untracked files count, ignored build output does not", () => {
  const d = repo({ ...CLEAN, ".gitignore": "out/\n" });
  try {
    write(d, { "out/.github/workflows/shai-hulud-workflow.yml": IOC_WORKFLOW });
    assert.equal(selfScan(d).status, 0, "an ignored directory is not part of the checkout");
    write(d, { "pending/.github/workflows/shai-hulud-workflow.yml": IOC_WORKFLOW });
    const r = selfScan(d);
    assert.equal(r.status, 1);
    assert.match(r.stdout, /WS-GH-001 {2}pending\/\.github\/workflows\/shai-hulud-workflow\.yml/);
    assert.match(r.stdout, /FAIL: the self-scan exited 1, expected 0/);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("self-scan: a committed symlink to a directory is copied as a link, not followed and not a setup error", () => {
  const d = repo({ ...CLEAN, "real/a.js": "export {};\n" });
  try {
    symlinkSync("real", join(d, "linked"));
    git(d, "add", "linked");
    git(d, "commit", "-q", "-m", "link");
    const r = selfScan(d);
    assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
    assert.match(r.stdout, /ok: the scan exits 1 and reports WS-GH-001/);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("repository .gitignore: a root node_modules that is a symlink is not committable, so the self-scan never copies it", () => {
  // A clone may link node_modules from another checkout. "node_modules/" alone matches only directories, so git
  // listed the link as untracked and the self-scan copied it.
  const d = repo({ ".gitignore": readFileSync(join(ROOT, ".gitignore"), "utf8") });
  const deps = mkdtempSync(join(tmpdir(), "wormsign-ci-deps-"));
  try {
    symlinkSync(deps, join(d, "node_modules"));
    write(d, { "pending.js": "export {};\n" });
    const listed = git(d, "ls-files", "--others", "--exclude-standard").split("\n");
    assert.deepEqual(listed, ["pending.js"], "an untracked file is listed; the linked node_modules is not");
  } finally {
    rmSync(d, { recursive: true, force: true });
    rmSync(deps, { recursive: true, force: true });
  }
});

test("repository baseline: no part of dist/ is ignored, so a file a pull request force-adds there is still scanned", () => {
  // The real .wormsign-baseline.json. dist/ is gitignored, but `git add -f` can still commit a file there, and the PR
  // gate scans what the change commits; the self-scan copies only committable files, so it never needs the ignore.
  const d = mkdtempSync(join(tmpdir(), "wormsign-baseline-dist-"));
  // Built from parts so this source file holds no endpoint literal for the self-scan to report; the written file does.
  const url = `fetch("https://${"webhook"}.site/0000-made-up");\n`;
  try {
    write(d, { ".wormsign-baseline.json": readFileSync(join(ROOT, ".wormsign-baseline.json"), "utf8"), "dist/test/a.test.js": url, "dist/src/a.js": url });
    const r = spawnSync(process.execPath, [join(ROOT, "dist/src/cli.js"), "scan", d, "--format", "json"], { encoding: "utf8", env: GIT_ENV });
    assert.equal(r.status, 0, r.stderr);
    const files = (JSON.parse(r.stdout) as { findings: { ruleId: string; file: string }[] }).findings.map((f) => `${f.ruleId} ${f.file}`);
    assert.deepEqual(files.sort(), ["WS-EX-001 dist/src/a.js", "WS-EX-001 dist/test/a.test.js"]);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

/* ---- ci-root-project.sh ---- */

test("root-project: only the root project files are checked out, and the repository's history stays readable", () => {
  const d = repo({
    "package.json": "{}\n",
    "package-lock.json": "{}\n",
    ".npmrc": "ignore-scripts=true\n",
    "test/fixtures/x/package-lock.json": "{}\n",
    "test/fixtures/x/.npmrc": "\n",
    "src/a.js": "\n",
  });
  const dest = join(mkdtempSync(join(tmpdir(), "wormsign-root-")), "root");
  try {
    execFileSync("bash", [script("ci-root-project.sh"), d, dest], { env: GIT_ENV, stdio: "ignore" });
    assert.deepEqual(readdirSync(dest).sort(), [".git", ".npmrc", "package-lock.json", "package.json"]);
    assert.equal(existsSync(join(dest, "test")), false);
    assert.equal(git(dest, "rev-parse", "HEAD"), git(d, "rev-parse", "HEAD"));
    assert.equal(git(dest, "show", "HEAD:src/a.js"), "", "other blobs remain readable for soak --base");
  } finally {
    rmSync(d, { recursive: true, force: true });
    rmSync(dirname(dest), { recursive: true, force: true });
  }
});

/* ---- ci-verify-release.sh ---- */

// A stand-in for `npm run build`: like the real build it removes dist/ first, then compiles src/ into dist/src/.
const BUILD = `import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
rmSync("dist", { recursive: true, force: true });
mkdirSync("dist/src", { recursive: true });
writeFileSync("dist/src/cli.js", "// built\\n" + readFileSync("src/cli.txt", "utf8"));
writeFileSync("dist/src/lib.js", "export {};\\n");
`;
const SOURCE = {
  "package.json": JSON.stringify({ name: "r", version: "1.2.3", private: true, scripts: { build: "node build.mjs" } }),
  "build.mjs": BUILD,
  "src/cli.txt": "console.log(1);\n",
  ".gitignore": "dist/\n",
};

/** Makes the release commit as scripts/ci-release-tag.sh does; `tamper` runs between the build and the commit. */
function releaseTag(d: string, tag: string, tamper: (d: string) => void = () => {}): void {
  execFileSync(process.execPath, ["build.mjs"], { cwd: d });
  tamper(d);
  git(d, "checkout", "-q", "--detach");
  git(d, "add", "-A", "--force", "dist/src", "src");
  git(d, "commit", "-q", "-m", `release ${tag}`);
  git(d, "tag", tag);
}

function verify(d: string, tag: string): { status: number | null; err: string } {
  const r = spawnSync("bash", [script("ci-verify-release.sh"), tag, "main"], { cwd: d, encoding: "utf8", env: GIT_ENV });
  return { status: r.status, err: r.stderr };
}

function releaseCase(tag: string, tamper?: (d: string) => void, before?: (d: string) => void): { status: number | null; err: string } {
  const d = repo(SOURCE);
  try {
    before?.(d);
    releaseTag(d, tag, tamper);
    return verify(d, tag);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

test("verify-release: a tag that is main plus its own clean build passes", () => {
  const r = releaseCase("v1.2.3");
  assert.equal(r.status, 0, r.err);
});

test("verify-release: committed dist/src that is not what the source compiles to is rejected", () => {
  const edited = releaseCase("v1.2.3", (d) => writeFileSync(join(d, "dist/src/cli.js"), "// backdoor\n"));
  assert.equal(edited.status, 1);
  assert.match(edited.err, /committed dist\/src differs from a clean build: dist\/src\/cli\.js/);
  const extra = releaseCase("v1.2.3", (d) => writeFileSync(join(d, "dist/src/extra.js"), "// not built from source\n"));
  assert.equal(extra.status, 1);
  assert.match(extra.err, /differs from a clean build: dist\/src\/extra\.js/);
  const missing = releaseCase("v1.2.3", (d) => rmSync(join(d, "dist/src/lib.js")));
  assert.equal(missing.status, 1);
  assert.match(missing.err, /differs from a clean build: dist\/src\/lib\.js/);
});

test("verify-release: a tag that changes source as well as dist/src is rejected", () => {
  const r = releaseCase("v1.2.3", (d) => {
    writeFileSync(join(d, "src/cli.txt"), "console.log('unreviewed');\n");
    execFileSync(process.execPath, ["build.mjs"], { cwd: d });
  });
  assert.equal(r.status, 1);
  assert.match(r.err, /changes files outside dist\/src: src\/cli\.txt/);
});

test("verify-release: a file moved from outside dist/src into it is named, not hidden by rename detection", () => {
  const r = releaseCase(
    "v1.2.3",
    (d) => git(d, "mv", "notes.md", "dist/src/notes.md"),
    (d) => {
      write(d, { "notes.md": "release notes that are not a build output\n" });
      git(d, "add", "notes.md");
      git(d, "commit", "-q", "-m", "notes");
    },
  );
  assert.equal(r.status, 1);
  assert.match(r.err, /changes files outside dist\/src: notes\.md$/m);
});

test("verify-release: a tag whose parent is not on main is rejected", () => {
  const r = releaseCase("v1.2.3", undefined, (d) => {
    git(d, "checkout", "-q", "-b", "side");
    writeFileSync(join(d, "src/cli.txt"), "console.log('side branch');\n");
    git(d, "commit", "-q", "-am", "unmerged");
  });
  assert.equal(r.status, 1);
  assert.match(r.err, /is not on main/);
});

test("verify-release: the tag must name package.json's version", () => {
  const r = releaseCase("v9.9.9");
  assert.equal(r.status, 1);
  assert.match(r.err, /tag v9\.9\.9 does not match package\.json version 1\.2\.3/);
});

/* ---- the repository's own workflows and package metadata ---- */

const workflow = (name: string): string => readFileSync(join(ROOT, ".github/workflows", name), "utf8");

// The lines of a block that starts at the first line matching `start` and ends before the next line indented no
// deeper than it (the next key or list item at the same level). Enough for the repository's own workflow files.
function block(text: string, start: RegExp): string[] {
  const lines = text.split("\n");
  const i = lines.findIndex((l) => start.test(l));
  assert.ok(i >= 0, `no line matches ${start}`);
  const indent = (l: string): number => l.length - l.trimStart().length;
  const own = indent(lines[i]!);
  const out = [lines[i]!];
  for (const l of lines.slice(i + 1)) {
    if (l.trim() !== "" && !l.trimStart().startsWith("#") && indent(l) <= own) break;
    out.push(l);
  }
  return out;
}

test("wormsign.yml: the main job soaks the whole root lockfile, on push to main and on a weekly schedule", () => {
  const w = workflow("wormsign.yml");
  // The PR job soaks only what a change adds, so a lockfile that reached main another way is checked only here.
  const on = block(w, /^on:/).join("\n");
  assert.match(on, /^ {2}push:\n {4}branches: \[main\]$/m);
  assert.match(on, /^ {2}schedule:\n(?: {4}#.*\n)* {4}- cron: "[^"]+"$/m);
  const main = block(w, /^ {2}main:$/);
  assert.ok(main.includes("    if: github.event_name != 'pull_request'"), main.join("\n"));
  const soak = block(main.join("\n"), /^ {6}- id: soak$/).join("\n");
  assert.match(soak, /^ {10}command: soak$/m);
  assert.match(soak, /^ {10}require-config: "true"$/m);
  assert.doesNotMatch(soak, /config-only|base:/);
});

test("wormsign.yml: on a pull request, ci.yml and action-selftest.yml run only after the gate job, never beside it", () => {
  // Their jobs install the change's dependencies and run their code (docs/github-action.md, "Install only after the
  // gate"), so neither may start on pull_request itself: wormsign.yml calls each under needs: pull-request.
  for (const file of ["ci.yml", "action-selftest.yml"]) {
    const on = block(workflow(file), /^on:/).join("\n");
    assert.match(on, /^ {2}workflow_call:$/m, `${file} is callable`);
    assert.doesNotMatch(on.replace(/#.*$/gm, ""), /pull_request/, `${file} does not start on pull_request`);
    // A pull request the gate fails by design gets neither run, so a maintainer runs both on its branch first.
    assert.match(on, /^ {2}workflow_dispatch:$/m, `${file} can be run on a branch on demand`);
  }
  const w = workflow("wormsign.yml");
  assert.match(block(w, /^ {2}pull-request:$/).join("\n"), /^ {4}name: gate \(built from base\)$/m);
  for (const [job, file] of [["ci", "ci.yml"], ["action-selftest", "action-selftest.yml"]] as const) {
    const j = block(w, new RegExp(`^ {2}${job}:$`)).join("\n");
    assert.match(j, /^ {4}needs: pull-request$/m, `${job} waits for the gate`);
    assert.match(j, /^ {4}if: github\.event_name == 'pull_request'$/m, job);
    assert.match(j, new RegExp(`^ {4}uses: \\./\\.github/workflows/${file.replace(".", "\\.")}$`, "m"), job);
  }
});

test("wormsign.yml: every setup-node step sets check-latest, so soak --require-config sees npm 11.10 or newer", () => {
  // Without check-latest, setup-node reuses the runner's cached 24.x, which can bundle npm 11.9 (Node 24.14.0).
  const lines = workflow("wormsign.yml").split("\n");
  const steps = lines.flatMap((l, i) => (/uses: actions\/setup-node@/.test(l) ? [i] : []));
  assert.equal(steps.length, 2);
  for (const i of steps) {
    const step = block(lines.slice(i).join("\n"), /uses: actions\/setup-node@/).join("\n");
    assert.match(step, /^ +node-version: 24$/m);
    assert.match(step, /^ +check-latest: true$/m);
  }
});

test("release.yml: the release notes verify the tarball first, then install that local file with scripts off", () => {
  const step = block(workflow("release.yml"), /^ {6}- name: Create the GitHub Release$/);
  const runAt = step.findIndex((l) => l === "        run: |");
  assert.ok(runAt > 0);
  const script = step.slice(runAt + 1).map((l) => l.slice(10)).join("\n");
  const d = mkdtempSync(join(tmpdir(), "wormsign-release-notes-"));
  try {
    // A stand-in gh that records its arguments, so the step runs here without creating a release.
    mkdirSync(join(d, "bin"));
    writeFileSync(join(d, "bin/gh"), '#!/bin/sh\nprintf "%s\\n" "$@" > gh-args.txt\n', { mode: 0o755 });
    const r = spawnSync("bash", ["-e", "-c", script], {
      cwd: d,
      encoding: "utf8",
      env: { PATH: `${join(d, "bin")}:${process.env["PATH"] ?? ""}`, TAG: "v1.2.3", COMMIT: "c0ffee", TARBALL: "wormsign-1.2.3.tgz", GITHUB_REPOSITORY: "o/wormsign" },
    });
    assert.equal(r.status, 0, r.stderr);
    const notes = readFileSync(join(d, "notes.md"), "utf8");
    assert.match(readFileSync(join(d, "gh-args.txt"), "utf8"), /^--notes-file\nnotes\.md$/m);
    const installs = notes.split("\n").filter((l) => /npm install/.test(l));
    assert.deepEqual(installs, ["npm install -g --ignore-scripts ./wormsign-1.2.3.tgz"]);
    const install = notes.indexOf("npm install");
    for (const check of ["sha256sum -c SHA256SUMS", "gh attestation verify wormsign-1.2.3.tgz --repo o/wormsign", "--signer-workflow o/wormsign/.github/workflows/release.yml"]) {
      assert.ok(notes.includes(check), check);
      assert.ok(notes.indexOf(check) < install, `${check} comes before the install line`);
    }
    assert.doesNotMatch(notes, /releases\/download/);
    assert.match(notes, /uses: o\/wormsign@c0ffee # v1\.2\.3/);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("package.json: the licence names every licence the packed files carry", () => {
  // data/iocs/packages.json is derived from Apache-2.0 datasets (THIRD_PARTY_NOTICES.md) and ships in the tarball, and
  // dist/src/vendor/smol-toml/ is the BSD-3-Clause TOML parser (src/vendor/smol-toml/VENDORED.json).
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { license: string; files: string[] };
  const data = JSON.parse(readFileSync(join(ROOT, "data/iocs/packages.json"), "utf8")) as { sets: { dataset?: { license: string } }[] };
  const dataLicences = new Set(data.sets.map((s) => s.dataset?.license).filter((l): l is string => l !== undefined));
  assert.ok(pkg.files.includes("data"));
  assert.deepEqual([...dataLicences], ["Apache-2.0"]);
  const vendored = JSON.parse(readFileSync(join(ROOT, "src/vendor/smol-toml/VENDORED.json"), "utf8")) as { license: string };
  assert.ok(pkg.files.includes("dist/src"), "the vendored parser ships under dist/src");
  assert.equal(vendored.license, "BSD-3-Clause");
  assert.equal(pkg.license, "MIT AND Apache-2.0 AND BSD-3-Clause");
  assert.ok(existsSync(join(ROOT, "data/iocs/LICENSES/Apache-2.0.txt")));
  const lock = JSON.parse(readFileSync(join(ROOT, "package-lock.json"), "utf8")) as { packages: Record<string, { license?: string }> };
  assert.equal(lock.packages[""]?.license, pkg.license, "package-lock.json's root entry matches package.json");
});
