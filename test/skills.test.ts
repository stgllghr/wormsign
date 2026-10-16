import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MANIFEST, detectAgents, inspect, loadBundle, manifestText, parseAgents, runSkills, targetsFor, current, unedited, userHome } from "../src/skills.js";
import type { Bundle, FsOps } from "../src/skills.js";
import { run } from "../src/main.js";
import { UsageError } from "../src/types.js";
import { fakeIO } from "./helpers.js";

const home = (): string => mkdtempSync(join(tmpdir(), "ws-skills-home-"));
/** A UsageError (which run() prints with exit 2, never as an internal error) whose message matches re. */
const usageError = (re: RegExp) => (e: unknown): boolean => e instanceof UsageError && re.test(e.message);
const bundle = (): Bundle => loadBundle();
/** Writes `files` under dir (relative path -> text). */
function put(dir: string, files: Record<string, string>): string {
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(join(dir, rel, ".."), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  return dir;
}
/** An installed copy of `b` at dir, as install writes it. */
function installed(dir: string, b: Bundle): string {
  for (const [rel, bytes] of b.files) {
    mkdirSync(join(dir, rel, ".."), { recursive: true });
    writeFileSync(join(dir, rel), bytes);
  }
  writeFileSync(join(dir, MANIFEST), manifestText(b));
  return dir;
}

test("skills: the bundled skill loads with SKILL.md and the package version", () => {
  const b = bundle();
  assert.ok(b.files.has("SKILL.md"));
  assert.match(b.version, /^\d+\.\d+\.\d+/);
});

test("skills: a damaged bundle (no SKILL.md, or a link in it) is a usage error naming it", () => {
  const empty = mkdtempSync(join(tmpdir(), "ws-skills-bundle-"));
  assert.throws(() => loadBundle(empty, "1.0.0"), /the bundled skill .* reinstall wormsign/);
  const linked = put(mkdtempSync(join(tmpdir(), "ws-skills-bundle-")), { "SKILL.md": "x\n" });
  symlinkSync("/etc/hosts", join(linked, "hosts"));
  assert.throws(() => loadBundle(linked, "1.0.0"), /hosts/);
});

test("skills: --agent takes comma lists, repeats and rejects anything else", () => {
  assert.equal(parseAgents(undefined), undefined);
  assert.deepEqual(parseAgents(["claude,codex", "codex", "cursor"]), ["claude", "codex", "cursor"]);
  assert.throws(() => parseAgents(["claude,"]), /invalid --agent ""/);
  assert.throws(() => parseAgents(["copilot"]), /invalid --agent "copilot" \(claude, codex, cursor\)/);
});

test("skills: Cursor shares Claude Code's copy, else Codex's; Claude Code's honours CLAUDE_CONFIG_DIR; --project uses the repository", () => {
  const h = home();
  const user = targetsFor(["claude", "codex", "cursor"], { home: h, env: {} });
  assert.deepEqual(user.map((t) => [t.dir, t.agents]), [[join(h, ".claude", "skills", "wormsign"), ["claude", "cursor"]], [join(h, ".agents", "skills", "wormsign"), ["codex"]]]);
  const moved = targetsFor(["claude"], { home: h, env: { CLAUDE_CONFIG_DIR: join(h, "cc") } });
  assert.equal(moved[0]!.dir, join(h, "cc", "skills", "wormsign"));
  const relative = targetsFor(["claude"], { home: h, env: { CLAUDE_CONFIG_DIR: "cc" } });
  assert.equal(relative[0]!.dir, join(h, ".claude", "skills", "wormsign"), "a relative CLAUDE_CONFIG_DIR is ignored");
  const repo = mkdtempSync(join(tmpdir(), "ws-skills-repo-"));
  const proj = targetsFor(["claude", "codex"], { home: h, env: {}, projectRoot: repo });
  assert.deepEqual(proj.map((t) => [t.dir, t.guardFrom]), [[join(repo, ".claude", "skills", "wormsign"), repo], [join(repo, ".agents", "skills", "wormsign"), repo]]);
});

test("skills: the .agents copy is written only for Codex, or for Cursor without Claude Code", () => {
  const h = home();
  const repo = mkdtempSync(join(tmpdir(), "ws-skills-repo-"));
  const claude = join(h, ".claude", "skills", "wormsign");
  const agentsCopy = join(h, ".agents", "skills", "wormsign");
  const dirs = (agents: Parameters<typeof targetsFor>[0], env: Record<string, string> = {}, projectRoot?: string) =>
    targetsFor(agents, { home: h, env, ...(projectRoot === undefined ? {} : { projectRoot }) }).map((t) => [t.dir, t.agents]);
  // Cursor reads ~/.claude/skills too (docs/skills.md), so Claude Code and Cursor get one copy, in either order.
  assert.deepEqual(dirs(["claude", "cursor"]), [[claude, ["claude", "cursor"]]]);
  assert.deepEqual(dirs(["cursor", "claude"]), [[claude, ["cursor", "claude"]]]);
  assert.deepEqual(dirs(["claude", "cursor"], {}, repo), [[join(repo, ".claude", "skills", "wormsign"), ["claude", "cursor"]]]);
  // Cursor alone, and Codex, read .agents/skills.
  assert.deepEqual(dirs(["cursor"]), [[agentsCopy, ["cursor"]]]);
  assert.deepEqual(dirs(["codex"]), [[agentsCopy, ["codex"]]]);
  assert.deepEqual(dirs(["codex", "cursor"], {}, repo), [[join(repo, ".agents", "skills", "wormsign"), ["codex", "cursor"]]]);
  // A CLAUDE_CONFIG_DIR elsewhere puts Claude Code's copy where Cursor's docs do not say it reads, so Cursor keeps its own.
  const moved = join(h, "cc");
  assert.deepEqual(dirs(["claude", "cursor"], { CLAUDE_CONFIG_DIR: moved }), [[join(moved, "skills", "wormsign"), ["claude"]], [agentsCopy, ["cursor"]]]);
  assert.deepEqual(dirs(["claude", "cursor"], { CLAUDE_CONFIG_DIR: `${join(h, ".claude")}/` }), [[claude, ["claude", "cursor"]]], "the same folder, with a trailing slash");
  assert.deepEqual(dirs(["claude", "cursor"], { CLAUDE_CONFIG_DIR: moved }, repo), [[join(repo, ".claude", "skills", "wormsign"), ["claude", "cursor"]]], "--project ignores CLAUDE_CONFIG_DIR");
  // install writes exactly those folders: one copy for Claude Code and Cursor, none under .agents.
  const b = bundle();
  const r = runSkills("install", { agents: ["claude", "cursor"], dryRun: false, force: false }, { home: h, env: {} });
  assert.deepEqual([r.code, r.lines], [0, [`${claude} (claude, cursor): installed ${b.version}, ${b.files.size} files`]]);
  assert.ok(current(inspect(claude, b)));
  assert.equal(existsSync(join(h, ".agents")), false, "no .agents copy for Claude Code and Cursor");
  assert.deepEqual(runSkills("check", { agents: ["claude", "cursor"], dryRun: false, force: false }, { home: h, env: {} }).code, 0, "check finds the one copy");
  assert.equal(runSkills("install", { agents: ["cursor"], dryRun: false, force: false }, { home: h, env: {} }).code, 0);
  assert.ok(current(inspect(agentsCopy, b)), "Cursor alone gets the .agents copy");
  const h2 = home();
  assert.equal(runSkills("install", { agents: ["codex"], dryRun: false, force: false }, { home: h2, env: {} }).code, 0);
  assert.deepEqual([existsSync(join(h2, ".agents", "skills", "wormsign")), existsSync(join(h2, ".claude"))], [true, false], "Codex gets the .agents copy");
});

test("skills: detection finds the agents whose user folders exist, and none in an empty or missing home", () => {
  const h = home();
  assert.deepEqual(detectAgents({ home: h, env: {} }), []);
  assert.deepEqual(detectAgents({ home: join(h, "missing"), env: {} }), []);
  mkdirSync(join(h, ".claude"));
  mkdirSync(join(h, ".cursor"));
  assert.deepEqual(detectAgents({ home: h, env: {} }), ["claude", "cursor"]);
});

test("skills: inspection tells absent, ours and foreign apart and lists every difference", () => {
  const b = bundle();
  const root = mkdtempSync(join(tmpdir(), "ws-skills-inspect-"));
  assert.equal(inspect(join(root, "none"), b).state, "absent");
  const foreign = put(join(root, "foreign"), { "SKILL.md": "mine\n" });
  assert.deepEqual([inspect(foreign, b).state, inspect(foreign, b).why], ["foreign", `it has no ${MANIFEST}, so wormsign did not install it`]);
  const forged = put(join(root, "forged"), { "SKILL.md": "x\n", [MANIFEST]: JSON.stringify({ tool: "other", version: "1", files: {} }) });
  assert.deepEqual([inspect(forged, b).state, inspect(forged, b).why], ["foreign", `its ${MANIFEST} is not one wormsign wrote`]);
  const ok = installed(join(root, "ok"), b);
  assert.ok(current(inspect(ok, b)));
  const edited = installed(join(root, "edited"), b);
  writeFileSync(join(edited, "SKILL.md"), "changed\n");
  writeFileSync(join(edited, "extra.md"), "x\n");
  const e = inspect(edited, b);
  assert.deepEqual([e.edited, e.extra, unedited(e)], [["SKILL.md"], ["extra.md"], false]);
  const old = installed(join(root, "old"), b);
  const m = JSON.parse(readFileSync(join(old, MANIFEST), "utf8")) as { version: string };
  writeFileSync(join(old, MANIFEST), JSON.stringify({ ...m, version: "0.0.1" }));
  assert.deepEqual([inspect(old, b).outdated, unedited(inspect(old, b)), current(inspect(old, b))], [true, true, false]);
  const hidden = installed(join(root, "hidden"), b);
  writeFileSync(join(hidden, "notes.md"), "tab\there\n");
  assert.deepEqual(inspect(hidden, b).notPlain, ["notes.md"]);
});

test("skills: a forged manifest path is never read or removed, only reported as lost", () => {
  const b = bundle();
  const root = mkdtempSync(join(tmpdir(), "ws-skills-forged-"));
  const outside = put(join(root, "secret"), { "x": "keep\n" });
  const dir = installed(join(root, "skills", "wormsign"), b);
  const m = JSON.parse(readFileSync(join(dir, MANIFEST), "utf8")) as { files: Record<string, string> };
  m.files["../../secret/x"] = "0".repeat(64);
  writeFileSync(join(dir, MANIFEST), JSON.stringify({ tool: "wormsign", version: b.version, files: m.files }));
  assert.deepEqual(inspect(dir, b).lost, ["../../secret/x"]);
  assert.equal(readFileSync(join(outside, "x"), "utf8"), "keep\n");
  assert.ok(existsSync(join(outside, "x")));
});

test("skills: an extra file named like an Object.prototype member is still extra, so it is never reported unedited", () => {
  const b = bundle();
  const root = mkdtempSync(join(tmpdir(), "ws-skills-proto-"));
  for (const name of ["constructor", "toString", "hasOwnProperty", "valueOf", "__proto__"]) {
    const dir = installed(join(root, `copy-${name}`), b);
    writeFileSync(join(dir, name), "mine\n");
    const i = inspect(dir, b);
    assert.deepEqual([i.state, i.extra, unedited(i), current(i)], ["ours", [name], false, false], name);
  }
});

test("skills: a manifest may list a path named like an Object.prototype member, and then the file is not extra", () => {
  const b = bundle();
  const names = ["constructor", "toString", "hasOwnProperty", "valueOf", "__proto__"];
  const dir = installed(mkdtempSync(join(tmpdir(), "ws-skills-proto-listed-")), b);
  const hash = createHash("sha256").update("mine\n").digest("hex");
  // Object.fromEntries makes `__proto__` an own key, as JSON.parse will when it reads the manifest back.
  const files = Object.fromEntries([...[...b.files.keys()].map((rel) => [rel, createHash("sha256").update(b.files.get(rel)!).digest("hex")]), ...names.map((n) => [n, hash])]);
  writeFileSync(join(dir, MANIFEST), JSON.stringify({ tool: "wormsign", version: b.version, files }));
  for (const name of names) writeFileSync(join(dir, name), "mine\n");
  const listed = inspect(dir, b);
  assert.deepEqual([listed.extra, listed.lost, listed.edited, unedited(listed)], [[], [], [], true]);
  rmSync(join(dir, "__proto__"));
  assert.deepEqual(inspect(dir, b).lost, ["__proto__"]);
});

test("skills: a manifest whose files are a list is not one wormsign wrote", () => {
  const b = bundle();
  const dir = put(mkdtempSync(join(tmpdir(), "ws-skills-listmanifest-")), { "SKILL.md": "x\n", [MANIFEST]: JSON.stringify({ tool: "wormsign", version: b.version, files: [] }) });
  const i = inspect(dir, b);
  assert.deepEqual([i.state, i.why], ["foreign", `its ${MANIFEST} is not one wormsign wrote`]);
});

test("skills: an unreadable file or folder in an installed copy is a usage error naming it, not a raw error", { skip: process.getuid?.() === 0 || process.platform === "win32" }, () => {
  const b = bundle();
  const root = mkdtempSync(join(tmpdir(), "ws-skills-unreadable-"));
  for (const rel of ["references", "SKILL.md"]) {
    const dir = installed(join(root, rel.replace(".", "-")), b);
    const target = join(dir, rel);
    const mode = statSync(target).mode & 0o777;
    chmodSync(target, 0o000);
    try {
      assert.throws(() => inspect(dir, b), (e: unknown) => e instanceof UsageError && e.message.startsWith(`cannot read ${dir}: `) && /cannot read .*EACCES/.test(e.message), rel);
    } finally {
      chmodSync(target, mode);
    }
  }
});

/** Every path under root with its kind and content hash or link text: before and after must match outside targets. */
function snapshot(root: string): Map<string, string> {
  const out = new Map<string, string>();
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      const st = lstatSync(p);
      if (st.isSymbolicLink()) out.set(p, "link");
      else if (st.isDirectory()) { out.set(p, "dir"); walk(p); }
      else out.set(p, createHash("sha256").update(readFileSync(p)).digest("hex"));
    }
  };
  walk(root);
  return out;
}
const outside = (m: Map<string, string>, ...dirs: string[]): string[] => [...m].filter(([p]) => !dirs.some((d) => p === d || p.startsWith(`${d}/`))).map(([p, v]) => `${p}=${v}`).sort();
const opts = (o: Partial<{ dryRun: boolean; force: boolean }> = {}) => ({ dryRun: false, force: false, ...o });

test("skills install: writes the bundled skill and a manifest for each target, and check then passes", () => {
  const h = home();
  const r = runSkills("install", { agents: ["claude", "codex", "cursor"], ...opts() }, { home: h, env: {} });
  assert.equal(r.code, 0, r.lines.join("\n"));
  for (const d of [join(h, ".claude", "skills", "wormsign"), join(h, ".agents", "skills", "wormsign")]) {
    assert.ok(current(inspect(d, bundle())), d);
  }
  assert.ok(r.lines.some((l) => l.includes(join(h, ".claude", "skills", "wormsign")) && l.includes("(claude, cursor)")));
  assert.ok(r.lines.some((l) => l.includes(join(h, ".agents", "skills", "wormsign")) && l.includes("(codex)")));
  // Cursor's docs do not say how it handles one skill name in two folders, so the note says "may" (docs/skills.md). Its
  // command names Codex, the agent whose copy is the .agents one when Claude Code and Cursor share a copy.
  const note = `note: Cursor reads both ${join(h, ".claude", "skills")} and ${join(h, ".agents", "skills")}, so it may list this skill twice; \`wormsign skills check --agent claude,codex\` shows whether both copies match`;
  assert.ok(r.lines.includes(note), `the duplicate copy for Cursor is said, without claiming what Cursor does: ${r.lines.join("\n")}`);
  assert.equal(runSkills("check", { agents: ["claude", "codex", "cursor"], ...opts() }, { home: h, env: {} }).code, 0);
});

test("skills install: the Cursor duplicate note appears only when both folders hold the skill", () => {
  const notes = (lines: string[]): string[] => lines.filter((l) => l.startsWith("note:"));
  const h = home();
  assert.deepEqual(notes(runSkills("install", { agents: ["cursor"], ...opts({ dryRun: true }) }, { home: h, env: {} }).lines), [], "nothing written yet");
  assert.deepEqual(notes(runSkills("install", { agents: ["cursor"], ...opts() }, { home: h, env: {} }).lines), [], "only the .agents copy exists");
  assert.deepEqual(notes(runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} }).lines), [], "only Cursor's agent selects the note");
  assert.equal(notes(runSkills("check", { agents: ["cursor"], ...opts() }, { home: h, env: {} }).lines).length, 1, "both copies exist now");
  writeFileSync(join(h, ".agents", "skills", "wormsign", "SKILL.md"), "edited\n");
  const left = runSkills("uninstall", { agents: ["cursor"], ...opts() }, { home: h, env: {} });
  assert.deepEqual([left.code, notes(left.lines)], [1, []], "both copies are still there, and uninstall never says it");
  const h2 = home();
  runSkills("install", { agents: ["claude"], ...opts() }, { home: h2, env: {} });
  assert.deepEqual(notes(runSkills("check", { agents: ["cursor"], ...opts() }, { home: h2, env: {} }).lines), [], "only the Claude Code copy exists");
  // A .agents copy left by an install for Codex (or Cursor alone) is the duplicate Claude Code and Cursor's copy meets.
  runSkills("install", { agents: ["codex"], ...opts() }, { home: h2, env: {} });
  const both = runSkills("check", { agents: ["claude", "cursor"], ...opts() }, { home: h2, env: {} });
  assert.equal(notes(both.lines).length, 1, both.lines.join("\n"));
  const named = runSkills("check", { agents: ["claude", "codex"], ...opts() }, { home: h2, env: {} });
  assert.deepEqual(named.lines.filter((l) => !l.startsWith("note:")).map((l) => l.split(" (")[0]), [join(h2, ".claude", "skills", "wormsign"), join(h2, ".agents", "skills", "wormsign")], "the note's command checks both copies");
  // Cursor's docs name ~/.claude/skills, not a CLAUDE_CONFIG_DIR elsewhere: no claim that Cursor reads that copy.
  const env = { CLAUDE_CONFIG_DIR: join(h2, "cc") };
  runSkills("install", { agents: ["claude"], ...opts() }, { home: h2, env });
  assert.deepEqual(notes(runSkills("check", { agents: ["claude", "cursor"], ...opts() }, { home: h2, env }).lines), [], "Claude Code's copy is under CLAUDE_CONFIG_DIR");
});

test("skills install: --dry-run writes nothing, and nothing outside the targets ever changes", () => {
  const h = home();
  mkdirSync(join(h, ".claude"));
  writeFileSync(join(h, ".claude", "settings.json"), "{}\n");
  const before = snapshot(h);
  const dry = runSkills("install", { agents: ["claude"], ...opts({ dryRun: true }) }, { home: h, env: {} });
  assert.equal(dry.code, 0);
  assert.ok(dry.lines.some((l) => l.startsWith("would write")));
  assert.deepEqual([...snapshot(h)], [...before], "--dry-run changed nothing");
  runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} });
  const target = join(h, ".claude", "skills");
  assert.deepEqual(outside(snapshot(h), target), outside(before, target), "only the skills folder changed");
});

test("skills install: an edited copy or a folder wormsign did not write is refused (exit 1), and replaced with --force", () => {
  const h = home();
  const dir = join(h, ".claude", "skills", "wormsign");
  runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} });
  writeFileSync(join(dir, "SKILL.md"), "mine\n");
  const refused = runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} });
  assert.equal(refused.code, 1);
  assert.match(refused.lines.join("\n"), /edited since wormsign installed it: SKILL\.md; --force replaces it/);
  assert.equal(readFileSync(join(dir, "SKILL.md"), "utf8"), "mine\n");
  assert.equal(runSkills("install", { agents: ["claude"], ...opts({ force: true }) }, { home: h, env: {} }).code, 0);
  assert.ok(current(inspect(dir, bundle())));
  const h2 = home();
  put(join(h2, ".claude", "skills", "wormsign"), { "SKILL.md": "someone else's\n" });
  const foreign = runSkills("install", { agents: ["claude"], ...opts() }, { home: h2, env: {} });
  assert.equal(foreign.code, 1);
  assert.match(foreign.lines.join("\n"), /did not install it; --force replaces it/);
});

test("skills install: an upgrade names the old and new version", () => {
  const h = home();
  const dir = join(h, ".claude", "skills", "wormsign");
  runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} });
  const m = JSON.parse(readFileSync(join(dir, MANIFEST), "utf8")) as Record<string, unknown>;
  writeFileSync(join(dir, MANIFEST), JSON.stringify({ ...m, version: "0.0.1" }));
  const r = runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} });
  assert.match(r.lines.join("\n"), new RegExp(`replaced 0\\.0\\.1 with ${bundle().version.replace(/\./g, "\\.")}`));
});

test("skills: a linked skills folder, or a linked .claude in the project, is refused with exit 2 and nothing is written through it", () => {
  const h = home();
  const elsewhere = mkdtempSync(join(tmpdir(), "ws-skills-elsewhere-"));
  mkdirSync(join(h, ".claude"));
  symlinkSync(elsewhere, join(h, ".claude", "skills"));
  assert.throws(() => runSkills("install", { agents: ["claude"], ...opts({ force: true }) }, { home: h, env: {} }), usageError(/is a symbolic link, which wormsign does not write through/));
  assert.deepEqual(readdirSync(elsewhere), []);
  const repo = mkdtempSync(join(tmpdir(), "ws-skills-repo-"));
  symlinkSync(elsewhere, join(repo, ".claude"));
  assert.throws(() => runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {}, projectRoot: repo }), usageError(/symbolic link/));
  assert.deepEqual(readdirSync(elsewhere), []);
});

test("skills install: a skills path that is a file, or a folder it cannot write, is exit 2 and leaves no partial copy", { skip: process.platform === "win32" || process.getuid?.() === 0 }, () => {
  const h = home();
  mkdirSync(join(h, ".claude"));
  writeFileSync(join(h, ".claude", "skills"), "a file\n");
  assert.throws(() => runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} }), usageError(/cannot (read|write) .*skills.*: E(NOTDIR|EXIST)/));
  const h2 = home();
  runSkills("install", { agents: ["claude"], ...opts() }, { home: h2, env: {} });
  const skills = join(h2, ".claude", "skills");
  const m = JSON.parse(readFileSync(join(skills, "wormsign", MANIFEST), "utf8")) as Record<string, unknown>;
  writeFileSync(join(skills, "wormsign", MANIFEST), JSON.stringify({ ...m, version: "0.0.1" }));
  chmodSync(skills, 0o555);
  try {
    assert.throws(() => runSkills("install", { agents: ["claude"], ...opts() }, { home: h2, env: {} }), usageError(/cannot write .*: EACCES/));
  } finally {
    chmodSync(skills, 0o755);
  }
  assert.deepEqual(readdirSync(skills), ["wormsign"], "no temporary folder is left");
  assert.equal(inspect(join(skills, "wormsign"), bundle()).version, "0.0.1", "the existing install is unchanged");
});

test("skills check: missing, edited, extra, outdated and invisible characters are each reported with exit 1", () => {
  const h = home();
  const check = () => runSkills("check", { agents: ["claude"], ...opts() }, { home: h, env: {} });
  assert.deepEqual([check().code, /not installed/.test(check().lines.join("\n"))], [1, true]);
  runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} });
  const dir = join(h, ".claude", "skills", "wormsign");
  writeFileSync(join(dir, "SKILL.md"), "edited\u200b\n");
  writeFileSync(join(dir, "x.md"), "x\n");
  const r = check();
  assert.equal(r.code, 1);
  assert.match(r.lines.join("\n"), /edited: SKILL\.md/);
  assert.match(r.lines.join("\n"), /extra: x\.md/);
  assert.match(r.lines.join("\n"), /not plain ASCII: SKILL\.md/);
  const v = bundle().version.replace(/\./g, "\\.");
  const manifest = (): { tool: string; version: string; files: Record<string, string> } => JSON.parse(readFileSync(join(dir, MANIFEST), "utf8"));
  const fresh = (): void => {
    rmSync(dir, { recursive: true, force: true });
    runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} });
  };
  // outdated: another version's manifest, nothing else different
  fresh();
  writeFileSync(join(dir, MANIFEST), JSON.stringify({ ...manifest(), version: "0.0.1" }));
  const old = check();
  assert.equal(old.code, 1);
  assert.match(old.lines.join("\n"), new RegExp(`: outdated: 0\\.0\\.1, this wormsign ships ${v}$`, "m"));
  // missing: a file of this release that the copy's manifest does not list
  fresh();
  const m = manifest();
  delete m.files["references/npm.md"];
  writeFileSync(join(dir, MANIFEST), JSON.stringify(m));
  rmSync(join(dir, "references", "npm.md"));
  const missing = check();
  assert.equal(missing.code, 1);
  assert.match(missing.lines.join("\n"), /: missing: references\/npm\.md$/m, "missing, and not called outdated: the version is this one");
  // lost, and not a regular file
  fresh();
  rmSync(join(dir, "references", "python.md"));
  symlinkSync("SKILL.md", join(dir, "link.md"));
  const lost = check().lines.join("\n");
  assert.match(lost, /lost: references\/python\.md/);
  assert.match(lost, /not a regular file: link\.md/);
  // the same version with other files: a copy whose manifest was rewritten is not called outdated
  fresh();
  writeFileSync(join(dir, "SKILL.md"), "tampered\n");
  const t = manifest();
  t.files["SKILL.md"] = createHash("sha256").update("tampered\n").digest("hex");
  writeFileSync(join(dir, MANIFEST), JSON.stringify(t));
  const tampered = check();
  assert.equal(tampered.code, 1);
  assert.match(tampered.lines.join("\n"), /: differs from this wormsign's skill: SKILL\.md$/m);
  assert.doesNotMatch(tampered.lines.join("\n"), /outdated/);
});

test("skills uninstall: removes only an unedited copy wormsign wrote, never the skills folder; --force removes the rest", () => {
  const h = home();
  const skills = join(h, ".claude", "skills");
  runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} });
  put(skills, { "other/SKILL.md": "another skill\n" });
  const dry = runSkills("uninstall", { agents: ["claude"], ...opts({ dryRun: true }) }, { home: h, env: {} });
  assert.deepEqual([dry.code, dry.lines.some((l) => l.endsWith(": would remove"))], [0, true]);
  assert.ok(current(inspect(join(skills, "wormsign"), bundle())), "a dry run removes nothing");
  assert.equal(runSkills("uninstall", { agents: ["claude"], ...opts() }, { home: h, env: {} }).code, 0);
  assert.deepEqual(readdirSync(skills), ["other"]);
  put(skills, { "wormsign/SKILL.md": "not ours\n" });
  assert.equal(runSkills("uninstall", { agents: ["claude"], ...opts() }, { home: h, env: {} }).code, 1);
  assert.ok(existsSync(join(skills, "wormsign")));
  assert.equal(runSkills("uninstall", { agents: ["claude"], ...opts({ force: true }) }, { home: h, env: {} }).code, 0);
  assert.deepEqual(readdirSync(skills), ["other"]);
});

test("skills uninstall: a skills folder it cannot write is exit 2 naming the copy, and the installed skill is left whole", { skip: process.platform === "win32" || process.getuid?.() === 0 }, () => {
  const h = home();
  runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} });
  const skills = join(h, ".claude", "skills");
  const dir = join(skills, "wormsign");
  chmodSync(skills, 0o555);
  try {
    for (const force of [false, true]) {
      assert.throws(() => runSkills("uninstall", { agents: ["claude"], ...opts({ force }) }, { home: h, env: {} }), (e: unknown) => e instanceof UsageError && e.message === `cannot remove ${dir}: EACCES`, `force ${force}`);
    }
  } finally {
    chmodSync(skills, 0o755);
  }
  assert.deepEqual(readdirSync(skills), ["wormsign"], "no moved-aside folder is left");
  assert.ok(current(inspect(dir, bundle())), "the skill is still a whole, current install");
});

test("skills uninstall: a copy it can move but not delete is exit 2 saying where what is left went", { skip: process.platform === "win32" || process.getuid?.() === 0 }, () => {
  const h = home();
  const b = loadBundle(put(mkdtempSync(join(tmpdir(), "ws-skills-bundle-")), { "SKILL.md": "x\n", "refs/a.md": "y\n" }), "9.9.9");
  runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} }, b);
  const skills = join(h, ".claude", "skills");
  const dir = join(skills, "wormsign");
  chmodSync(join(dir, "refs"), 0o555); // the folder can be renamed, but nothing in refs can be deleted
  const refs = (): string[] => readdirSync(skills).map((n) => join(skills, n, "refs")).filter((r) => existsSync(r));
  try {
    assert.throws(
      () => runSkills("uninstall", { agents: ["claude"], ...opts() }, { home: h, env: {} }, b),
      (e: unknown) => e instanceof UsageError && e.message.startsWith(`cannot remove ${dir}: E`) && /; the skill is out of .*, but what is left of it is in (.*\.wormsign\.old-\d+-[0-9a-f]{8}): rm -r -- '\1'$/.test(e.message) && e.message.includes(`out of ${skills}, but`),
    );
    assert.deepEqual(readdirSync(skills).map((n) => n.replace(/-.*/, "")), [".wormsign.old"], "the wormsign folder is gone, what is left is one moved-aside folder");
  } finally {
    for (const r of refs()) chmodSync(r, 0o755);
  }
  assert.ok(runSkills("uninstall", { agents: ["claude"], ...opts() }, { home: h, env: {} }, b).lines.some((l) => l.endsWith(": not installed")));
});

test("skills: with no --agent and no agent folder, it stops with exit 2 and names the folders it looked for", () => {
  const h = join(home(), "missing");
  assert.throws(() => runSkills("install", opts(), { home: h, env: {} }), usageError(new RegExp(`no supported agent found \\(looked for ${join(h, ".claude").replace(/[.]/g, "\\.")}`)));
});

test("skills: a write that fails part-way leaves neither a partial copy nor a temporary folder", () => {
  const h = home();
  const bad = put(mkdtempSync(join(tmpdir(), "ws-skills-bad-")), { "SKILL.md": "x\n", "a": "file\n" });
  // A bundle whose second file needs "a" to be a folder: the write fails after the first file.
  const b = loadBundle(bad, "9.9.9");
  b.files.set("a/b.md", Buffer.from("y\n"));
  assert.throws(() => runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} }, b), usageError(/cannot write/));
  const skills = join(h, ".claude", "skills");
  assert.deepEqual(existsSync(skills) ? readdirSync(skills) : [], []);
});

function countingFetch() {
  const calls: string[] = [];
  const f = (async (u: string | URL | Request) => {
    calls.push(String(u));
    throw new Error("no network in this test");
  }) as typeof fetch;
  return { f, calls };
}

test("cli skills: install, check and uninstall through run(), into the HOME given, with no network request", async () => {
  const h = home();
  mkdirSync(join(h, ".codex"));
  const net = countingFetch();
  // The global fetch is the recorder too, so a request made without io.fetchImpl is seen as well.
  const saved = globalThis.fetch;
  globalThis.fetch = net.f;
  try {
    const io = fakeIO({ env: { HOME: h }, fetchImpl: net.f });
    assert.equal(await run(["skills", "install"], io), 0, io.err);
    assert.match(io.out, /agents found: codex/);
    assert.ok(existsSync(join(h, ".agents", "skills", "wormsign", "SKILL.md")));
    const c = fakeIO({ env: { HOME: h }, fetchImpl: net.f });
    assert.equal(await run(["skills", "check", "--agent", "codex"], c), 0, c.out);
    const u = fakeIO({ env: { HOME: h }, fetchImpl: net.f });
    assert.equal(await run(["skills", "uninstall", "--agent=codex"], u), 0);
    // Anything a request left pending has had a turn of the event loop to reach the recorder.
    await new Promise((r) => setImmediate(r));
  } finally {
    globalThis.fetch = saved;
  }
  assert.deepEqual(net.calls, []);
});

test("cli skills: bad actions, agents and option combinations are usage errors before anything is written", async () => {
  const h = home();
  const usage = async (argv: string[]) => {
    const io = fakeIO({ env: { HOME: h } });
    assert.equal(await run(argv, io), 2, argv.join(" "));
    assert.doesNotMatch(io.err, /internal error/);
    return io.err;
  };
  assert.match(await usage(["skills"]), /usage: wormsign skills install\|check\|uninstall/);
  assert.match(await usage(["skills", "remove"]), /usage: wormsign skills install\|check\|uninstall \(got: remove\)/);
  assert.match(await usage(["skills", "install", "--agent", "vim"]), /invalid --agent "vim"/);
  assert.match(await usage(["skills", "check", "--dry-run", "--agent", "claude"]), /--dry-run is an option of skills install only/);
  assert.match(await usage(["skills", "uninstall", "--dry-run", "--agent", "claude"]), /--dry-run is an option of skills install only/);
  assert.match(await usage(["skills", "check", "--force", "--agent", "claude"]), /--force is not an option of skills check/);
  assert.match(await usage(["skills", "install", "--format", "json"]), /--format is not an option of skills/);
  assert.deepEqual(readdirSync(h), []);
});

test("cli skills --project: installs at the git root of the working directory, and outside a repository is exit 2", () => {
  const cli = new URL("../src/cli.js", import.meta.url).pathname;
  const repo = mkdtempSync(join(tmpdir(), "ws-skills-git-"));
  execFileSync("git", ["init", "-q", "-b", "main"], { cwd: repo });
  mkdirSync(join(repo, "sub"));
  const env = { ...process.env, HOME: home() };
  const r = spawnSync(process.execPath, [cli, "skills", "install", "--project", "--agent", "claude,codex"], { cwd: join(repo, "sub"), env, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.ok(existsSync(join(repo, ".claude", "skills", "wormsign", "SKILL.md")));
  assert.ok(existsSync(join(repo, ".agents", "skills", "wormsign", "SKILL.md")));
  const scan = spawnSync(process.execPath, [cli, "scan", repo, "--fail-on", "info"], { env, encoding: "utf8" });
  assert.equal(scan.status, 0, `an installed project skill is no scan finding: ${scan.stdout}`);
  const outside = mkdtempSync(join(tmpdir(), "ws-skills-nogit-"));
  const n = spawnSync(process.execPath, [cli, "skills", "install", "--project", "--agent", "claude"], { cwd: outside, env, encoding: "utf8" });
  assert.equal(n.status, 2);
  assert.match(n.stderr, /not inside a git repository/);
});

test("cli: --help lists the skills command and its options within the size limits", async () => {
  const io = fakeIO();
  await run(["--help"], io);
  assert.match(io.out, /\n {2}wormsign skills <action> {10}/);
  for (const flag of ["--agent <list>", "--project", "--dry-run", "--force"]) assert.match(io.out, new RegExp(`\\n {2}${flag.replace(/[<>]/g, "\\$&")} +skills`));
});

test("cli skills: --agent, --dry-run and --force reach the installer", async () => {
  const h = home();
  mkdirSync(join(h, ".codex"));
  const dir = join(h, ".agents", "skills", "wormsign");
  const go = async (...argv: string[]) => {
    const io = fakeIO({ env: { HOME: h } });
    const code = await run(["skills", ...argv], io);
    return { code, out: io.out, err: io.err };
  };
  const dry = await go("install", "--dry-run");
  assert.equal(dry.code, 0, dry.err);
  assert.match(dry.out, /agents found: codex/);
  assert.match(dry.out, /would write /);
  assert.equal(existsSync(join(h, ".agents")), false, "--dry-run writes nothing");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "notes.md"), "not wormsign's\n");
  const refused = await go("install", "--agent", "codex");
  assert.equal(refused.code, 1, refused.out);
  assert.doesNotMatch(refused.out, /agents found/, "--agent was given, so nothing is detected");
  assert.equal(existsSync(join(dir, "SKILL.md")), false);
  const forced = await go("install", "--agent", "codex", "--force");
  assert.equal(forced.code, 0, forced.err);
  assert.ok(existsSync(join(dir, "SKILL.md")));
  writeFileSync(join(dir, "SKILL.md"), "edited\n");
  assert.equal((await go("uninstall", "--agent", "codex")).code, 1, "an edited copy is left alone");
  assert.ok(existsSync(dir));
  assert.equal((await go("uninstall", "--agent", "codex", "--force")).code, 0);
  assert.equal(existsSync(dir), false);
});

test("cli skills: a file name in an installed copy cannot put an escape sequence or a workflow command in the output", async () => {
  const h = home();
  const env = { HOME: h };
  const i = fakeIO({ env });
  assert.equal(await run(["skills", "install", "--agent", "codex"], i), 0, i.err);
  writeFileSync(join(h, ".agents", "skills", "wormsign", "a\n::error::forged\u001b[31m.md"), "x\n");
  const c = fakeIO({ env });
  assert.equal(await run(["skills", "check", "--agent", "codex"], c), 1);
  assert.match(c.out, /extra: a\\u000a::error::forged\\u001b\[31m\.md/);
  assert.doesNotMatch(c.out, /[^\n\x20-\x7e]/, "no control character reaches the terminal");
  assert.doesNotMatch(c.out, /^::/m, "no line starts a workflow command");
});

test("cli skills --project: every argument is checked before git is asked for the repository", () => {
  const cli = new URL("../src/cli.js", import.meta.url).pathname;
  const outside = mkdtempSync(join(tmpdir(), "ws-skills-nogit-"));
  const env = { ...process.env, HOME: home() };
  const cases: [string[], RegExp][] = [
    [["skills", "install", "--project", "--agent", "vim"], /invalid --agent "vim"/],
    [["skills", "remove", "--project"], /usage: wormsign skills install\|check\|uninstall \(got: remove\)/],
  ];
  for (const [argv, expected] of cases) {
    const r = spawnSync(process.execPath, [cli, ...argv], { cwd: outside, env, encoding: "utf8" });
    assert.equal(r.status, 2, argv.join(" "));
    assert.match(r.stderr, expected);
    assert.doesNotMatch(r.stderr, /not inside a git repository/);
  }
});

test("cli skills: a second word after the action is a usage error, not a quiet install", async () => {
  const h = home();
  const io = fakeIO({ env: { HOME: h } });
  assert.equal(await run(["skills", "install", "claude"], io), 2);
  assert.match(io.err, /usage: wormsign skills install\|check\|uninstall \(got: install claude\)/);
  assert.deepEqual(readdirSync(h), []);
});

test("cli skills: CLAUDE_CONFIG_DIR from the environment given to run() moves Claude Code's folder, for writing and for detection", async () => {
  // Detection: only the moved folder exists, so the plain command must find Claude there and never touch ~/.claude.
  const h = home();
  const cc = join(h, "cc");
  mkdirSync(cc);
  const env = { HOME: h, CLAUDE_CONFIG_DIR: cc };
  const found = fakeIO({ env });
  assert.equal(await run(["skills", "install"], found), 0, found.err);
  assert.match(found.out, /agents found: claude/);
  assert.ok(existsSync(join(cc, "skills", "wormsign", "SKILL.md")));
  assert.equal(existsSync(join(h, ".claude")), false, "nothing is written to ~/.claude");
  // Writing: --agent skips detection, and the moved folder need not exist yet.
  const h2 = home();
  const env2 = { HOME: h2, CLAUDE_CONFIG_DIR: join(h2, "elsewhere") };
  const io = fakeIO({ env: env2 });
  assert.equal(await run(["skills", "install", "--agent", "claude"], io), 0, io.err);
  assert.ok(existsSync(join(h2, "elsewhere", "skills", "wormsign", "SKILL.md")));
  assert.equal(existsSync(join(h2, ".claude")), false, "nothing is written to ~/.claude");
  const check = fakeIO({ env: env2 });
  assert.equal(await run(["skills", "check", "--agent", "claude"], check), 0, check.out);
  const gone = fakeIO({ env: env2 });
  assert.equal(await run(["skills", "uninstall", "--agent", "claude"], gone), 0, gone.err);
  assert.equal(existsSync(join(h2, "elsewhere", "skills", "wormsign")), false);
});

test("skills: a copy holding more files than the cap, or a file past the size cap, has the rest reported as not regular files, unread", () => {
  const b = bundle();
  const root = mkdtempSync(join(tmpdir(), "ws-skills-caps-"));
  const many = installed(join(root, "many"), b);
  for (let n = 0; n < 64; n++) writeFileSync(join(many, `f${String(n).padStart(2, "0")}.md`), "x\n");
  // Read in sorted order: the manifest, SKILL.md and f00 to f61 make 64; f62, f63 and the references are not read.
  const i = inspect(many, b);
  assert.deepEqual([i.odd.slice(0, 2), i.extra.length], [["f62.md", "f63.md"], 62]);
  const big = installed(join(root, "big"), b);
  writeFileSync(join(big, "big.md"), "x".repeat(256 * 1024 + 1));
  writeFileSync(join(big, "edge.md"), "x".repeat(256 * 1024));
  const j = inspect(big, b);
  assert.deepEqual([j.odd, j.extra], [["big.md"], ["edge.md"]], "a file over 256 KiB is not read; one of exactly 256 KiB is");
});

test("skills: a manifest listing a file this release no longer ships is outdated, and check names the file", () => {
  const h = home();
  const files = { "SKILL.md": "x\n", "old.md": "gone in the next release\n" };
  const before = loadBundle(put(mkdtempSync(join(tmpdir(), "ws-skills-bundle-")), files), "9.9.9");
  runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} }, before);
  const after = loadBundle(put(mkdtempSync(join(tmpdir(), "ws-skills-bundle-")), { "SKILL.md": "x\n" }), "9.9.9");
  const i = inspect(join(h, ".claude", "skills", "wormsign"), after);
  assert.deepEqual([i.outdated, i.differs, i.missing, current(i)], [true, ["old.md"], [], false]);
  const r = runSkills("check", { agents: ["claude"], ...opts() }, { home: h, env: {} }, after);
  assert.equal(r.code, 1);
  assert.match(r.lines.join("\n"), /: differs from this wormsign's skill: old\.md$/m);
});

test("skills check: reads through a linked skills folder, which it never writes, and reports a linked skill folder as not wormsign's", () => {
  const h = home();
  const elsewhere = mkdtempSync(join(tmpdir(), "ws-skills-elsewhere-"));
  installed(join(elsewhere, "wormsign"), bundle());
  mkdirSync(join(h, ".claude"));
  symlinkSync(elsewhere, join(h, ".claude", "skills"));
  const through = runSkills("check", { agents: ["claude"], ...opts() }, { home: h, env: {} });
  assert.deepEqual([through.code, through.lines.some((l) => l.endsWith(": ok, " + bundle().version))], [0, true], through.lines.join("\n"));
  const h2 = home();
  mkdirSync(join(h2, ".claude", "skills"), { recursive: true });
  symlinkSync(join(elsewhere, "wormsign"), join(h2, ".claude", "skills", "wormsign"));
  const linked = runSkills("check", { agents: ["claude"], ...opts() }, { home: h2, env: {} });
  assert.equal(linked.code, 1);
  assert.match(linked.lines.join("\n"), /: not wormsign's skill, it is a symbolic link$/m);
});

test("cli skills: a link on the path is a usage error, exit 2, never an internal error", async () => {
  const h = home();
  mkdirSync(join(h, ".agents"));
  symlinkSync(mkdtempSync(join(tmpdir(), "ws-skills-elsewhere-")), join(h, ".agents", "skills"));
  const io = fakeIO({ env: { HOME: h } });
  assert.equal(await run(["skills", "install", "--agent", "codex"], io), 2);
  assert.match(io.err, /^wormsign: .*skills is a symbolic link, which wormsign does not write through, even with --force; to install the skill anyway, run `wormsign skills install --project --agent codex` in a git repository: it writes into that repository's folders instead\n$/);
  assert.doesNotMatch(io.err, /internal error/);
});

test("skills install: when the new copy cannot be renamed into place, the old copy is put back", () => {
  const h = home();
  runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} });
  const skills = join(h, ".claude", "skills");
  const dir = join(skills, "wormsign");
  const m = JSON.parse(readFileSync(join(dir, MANIFEST), "utf8")) as Record<string, unknown>;
  writeFileSync(join(dir, MANIFEST), JSON.stringify({ ...m, version: "0.0.1" }));
  const calls: string[] = [];
  const ops: FsOps = {
    rename(from, to) {
      calls.push(`${from.slice(skills.length + 1)} -> ${to.slice(skills.length + 1)}`);
      if (from.includes(".wormsign.tmp-")) throw Object.assign(new Error("injected"), { code: "EIO" });
      renameSync(from, to);
    },
    remove(p) {
      rmSync(p, { recursive: true, force: true });
    },
  };
  assert.throws(() => runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} }, undefined, ops), usageError(/^cannot write .*: EIO$/));
  assert.deepEqual(calls.map((c) => c.replace(/-\d+-[0-9a-f]{8}/g, "")), ["wormsign -> .wormsign.old", ".wormsign.tmp -> wormsign", ".wormsign.old -> wormsign"]);
  assert.deepEqual(readdirSync(skills), ["wormsign"], "no temporary or moved-aside folder is left");
  assert.equal(inspect(dir, bundle()).version, "0.0.1", "the old copy is back in place");
  assert.ok(unedited(inspect(dir, bundle())));
});

test("skills install: a target that cannot be read or written stops the run before any target is written", { skip: process.platform === "win32" || process.getuid?.() === 0 }, () => {
  // ~/.agents is a file: the Codex copy cannot even be inspected.
  const h = home();
  writeFileSync(join(h, ".agents"), "a file\n");
  assert.throws(() => runSkills("install", { agents: ["claude", "codex"], ...opts() }, { home: h, env: {} }), usageError(/^cannot (read|write) .*\.agents.*: ENOTDIR$/));
  assert.equal(existsSync(join(h, ".claude")), false, "the Claude Code copy was not written first");
  // ~/.agents/skills is a folder wormsign may not write to.
  const h2 = home();
  mkdirSync(join(h2, ".agents", "skills"), { recursive: true });
  chmodSync(join(h2, ".agents", "skills"), 0o555);
  try {
    for (const dryRun of [true, false]) {
      assert.throws(() => runSkills("install", { agents: ["claude", "codex"], ...opts({ dryRun }) }, { home: h2, env: {} }), usageError(/^cannot write .*\.agents\/skills\/wormsign: EACCES$/), `dry run ${dryRun}`);
    }
  } finally {
    chmodSync(join(h2, ".agents", "skills"), 0o755);
  }
  assert.equal(existsSync(join(h2, ".claude")), false, "the Claude Code copy was not written first");
});

test("skills uninstall: a target that cannot be removed stops the run before any target is removed", { skip: process.platform === "win32" || process.getuid?.() === 0 }, () => {
  const h = home();
  runSkills("install", { agents: ["claude", "codex"], ...opts() }, { home: h, env: {} });
  const shared = join(h, ".agents", "skills");
  chmodSync(shared, 0o555);
  try {
    assert.throws(() => runSkills("uninstall", { agents: ["claude", "codex"], ...opts() }, { home: h, env: {} }), usageError(new RegExp(`^cannot remove ${join(shared, "wormsign").replace(/[.]/g, "\\.")}: EACCES$`)));
  } finally {
    chmodSync(shared, 0o755);
  }
  assert.ok(current(inspect(join(h, ".claude", "skills", "wormsign"), bundle())), "the Claude Code copy was not removed first");
});

test("skills install: an old copy that cannot be removed is a warning naming what is left; the new copy stands, exit 0", { skip: process.platform === "win32" || process.getuid?.() === 0 }, () => {
  const h = home();
  const b = loadBundle(put(mkdtempSync(join(tmpdir(), "ws-skills-bundle-")), { "SKILL.md": "x\n", "refs/a.md": "y\n" }), "9.9.9");
  runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} }, b);
  const skills = join(h, ".claude", "skills");
  const dir = join(skills, "wormsign");
  chmodSync(join(dir, "refs"), 0o555); // the copy can be renamed aside, but nothing in refs can be deleted
  let r;
  try {
    r = runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} }, b);
  } finally {
    for (const n of readdirSync(skills)) if (existsSync(join(skills, n, "refs"))) chmodSync(join(skills, n, "refs"), 0o755);
  }
  assert.equal(r.code, 0, r.lines.join("\n"));
  const left = readdirSync(skills).filter((n) => n.startsWith(".wormsign.old-"));
  assert.equal(left.length, 1, readdirSync(skills).join(", "));
  assert.equal(r.lines.length, 2, r.lines.join("\n"));
  assert.equal(r.lines[0], `${dir} (claude): reinstalled 9.9.9, 2 files`);
  // The error code is the platform's (EACCES on Linux, ENOTEMPTY on macOS).
  assert.ok(r.lines[1]!.startsWith(`${dir} (claude): warning: the old copy could not be removed (E`), r.lines[1]);
  assert.ok(r.lines[1]!.endsWith(`); remove what is left of it with: rm -r -- '${join(skills, left[0]!)}'`), r.lines[1]);
  assert.ok(current(inspect(dir, b)), "the new copy is in place");
  assert.ok(existsSync(join(skills, left[0]!, "refs", "a.md")));
  // check does not call this target ok while the folder is left: it names it, with exit 1.
  const c = runSkills("check", { agents: ["claude"], ...opts() }, { home: h, env: {} }, b);
  assert.equal(c.code, 1, c.lines.join("\n"));
  assert.deepEqual(c.lines, [`${dir} (claude): ok, 9.9.9`, `${dir} (claude): left over from an interrupted install or uninstall: ${join(skills, left[0]!)}; remove with: rm -r -- '${join(skills, left[0]!)}'`]);
});

test("skills install --force: the output says when it replaces a folder wormsign did not write, or a modified copy, and what was modified", () => {
  const h = home();
  const dir = join(h, ".claude", "skills", "wormsign");
  const v = bundle().version;
  put(dir, { "SKILL.md": "someone else's\n" });
  const go = (dryRun: boolean) => runSkills("install", { agents: ["claude"], ...opts({ force: true, dryRun }) }, { home: h, env: {} }).lines;
  assert.deepEqual(go(true), [`would write ${dir} (claude): replaced a folder wormsign did not write with ${v}, ${bundle().files.size} files`]);
  assert.deepEqual(go(false), [`${dir} (claude): replaced a folder wormsign did not write with ${v}, ${bundle().files.size} files`]);
  writeFileSync(join(dir, "SKILL.md"), "mine\n");
  assert.deepEqual(go(true), [`would write ${dir} (claude): replaced a modified copy with ${v} (edited: SKILL.md), ${bundle().files.size} files`]);
  assert.deepEqual(go(false), [`${dir} (claude): replaced a modified copy with ${v} (edited: SKILL.md), ${bundle().files.size} files`]);
  assert.deepEqual(go(false), [`${dir} (claude): reinstalled ${v}, ${bundle().files.size} files`]);
});

test("skills: the Cursor note names the check that inspects both copies, with --project at project level", () => {
  const h = home();
  const repo = mkdtempSync(join(tmpdir(), "ws-skills-repo-"));
  const r = runSkills("install", { agents: ["claude", "codex", "cursor"], ...opts() }, { home: h, env: {}, projectRoot: repo });
  assert.equal(r.lines.at(-1), `note: Cursor reads both ${join(repo, ".claude", "skills")} and ${join(repo, ".agents", "skills")}, so it may list this skill twice; \`wormsign skills check --project --agent claude,codex\` shows whether both copies match`);
});

test("skills: HOME counts only when it is an absolute path; otherwise the system's home folder, else a usage error", () => {
  const sys = (): string => "/home/sys";
  assert.equal(userHome({ HOME: "/home/me" }, sys), "/home/me");
  for (const h of [undefined, "", "rel", "./rel"]) assert.equal(userHome({ HOME: h }, sys), "/home/sys", String(h));
  for (const f of ["", "rel"]) {
    assert.throws(() => userHome({ HOME: "rel" }, () => f), usageError(/^HOME is "rel", not an absolute path, and no home folder was found; set HOME to your home folder$/));
  }
  assert.throws(() => userHome({}, () => ""), usageError(/^HOME is not set, not an absolute path/));
});

test("cli skills: an empty or relative HOME is exit 2, and nothing is written under the working directory", () => {
  const cli = new URL("../src/cli.js", import.meta.url).pathname;
  for (const h of ["", "rel"]) {
    const cwd = mkdtempSync(join(tmpdir(), "ws-skills-cwd-"));
    // node's homedir() reads HOME too, so with HOME empty or relative there is no absolute home folder to fall back on.
    const r = spawnSync(process.execPath, [cli, "skills", "install", "--agent", "codex"], { cwd, env: { ...process.env, HOME: h }, encoding: "utf8" });
    assert.equal(r.status, 2, `HOME="${h}": ${r.stdout}${r.stderr}`);
    assert.match(r.stderr, /not an absolute path/);
    assert.doesNotMatch(r.stderr, /internal error/);
    assert.deepEqual(readdirSync(cwd), [], `HOME="${h}"`);
  }
});

test("cli skills --project --agent: HOME is never read, so CI with HOME empty works; without --agent it is", () => {
  const cli = new URL("../src/cli.js", import.meta.url).pathname;
  const repo = mkdtempSync(join(tmpdir(), "ws-skills-git-"));
  execFileSync("git", ["init", "-q", "-b", "main"], { cwd: repo });
  // node's homedir() reads HOME too, so with HOME empty there is no home folder at all.
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: "" };
  delete env["CLAUDE_CONFIG_DIR"];
  const go = (...argv: string[]) => spawnSync(process.execPath, [cli, "skills", ...argv], { cwd: repo, env, encoding: "utf8" });
  for (const action of ["install", "check", "uninstall"]) {
    const r = go(action, "--project", "--agent", "claude,codex");
    assert.equal(r.status, 0, `${action}: ${r.stdout}${r.stderr}`);
    if (action === "install") assert.ok(existsSync(join(repo, ".claude", "skills", "wormsign", "SKILL.md")));
  }
  assert.deepEqual(readdirSync(join(repo, ".claude", "skills")), [], "uninstall removed it");
  const found = go("check", "--project");
  assert.equal(found.status, 2, "finding the agents reads the user folders");
  assert.match(found.stderr, /not an absolute path/);
  const user = go("check", "--agent", "claude");
  assert.equal(user.status, 2, "a user-level target needs HOME");
  assert.match(user.stderr, /not an absolute path/);
});

/** FsOps over the real file system that throws `code` for the calls `fail` picks. */
function failing(fail: (op: "rename" | "remove", from: string, to?: string) => string | undefined): FsOps {
  return {
    rename(from, to) {
      const code = fail("rename", from, to);
      if (code) throw Object.assign(new Error("injected"), { code });
      renameSync(from, to);
    },
    remove(p) {
      const code = fail("remove", p);
      if (code) throw Object.assign(new Error("injected"), { code });
      rmSync(p, { recursive: true, force: true });
    },
  };
}

test("skills install: an I/O error after one copy was written names the copies already written", () => {
  const h = home();
  const v = bundle().version;
  const agents = join(h, ".agents", "skills");
  // The second target fails as it is renamed into place, after every target was checked: a full disk, an I/O error.
  const ops = failing((op, from, to) => (op === "rename" && from.includes(".wormsign.tmp-") && to === join(agents, "wormsign") ? "ENOSPC" : undefined));
  const claude = join(h, ".claude", "skills", "wormsign");
  assert.throws(
    () => runSkills("install", { agents: ["claude", "codex"], ...opts() }, { home: h, env: {} }, undefined, ops),
    (e: unknown) => e instanceof UsageError && e.message === `cannot write ${join(agents, "wormsign")}: ENOSPC; already written: ${claude} (claude): installed ${v}`,
  );
  assert.ok(current(inspect(claude, bundle())), "the copy named is in place");
  assert.deepEqual(readdirSync(agents), [], "the failed one left nothing");
  // A failure on the first target has nothing to name.
  const h2 = home();
  const first = failing((op, from) => (op === "rename" && from.includes(".wormsign.tmp-") ? "EIO" : undefined));
  assert.throws(() => runSkills("install", { agents: ["claude", "codex"], ...opts() }, { home: h2, env: {} }, undefined, first), usageError(/^cannot write .*\.claude\/skills\/wormsign: EIO$/));
});

test("skills uninstall: an I/O error after one copy was removed names the copies already removed", () => {
  const h = home();
  runSkills("install", { agents: ["claude", "codex"], ...opts() }, { home: h, env: {} });
  const shared = join(h, ".agents", "skills", "wormsign");
  const ops = failing((op, from) => (op === "rename" && from === shared ? "EIO" : undefined));
  const claude = join(h, ".claude", "skills", "wormsign");
  assert.throws(
    () => runSkills("uninstall", { agents: ["claude", "codex"], ...opts() }, { home: h, env: {} }, undefined, ops),
    (e: unknown) => e instanceof UsageError && e.message === `cannot remove ${shared}: EIO; already removed: ${claude} (claude)`,
  );
  assert.equal(existsSync(claude), false);
  assert.ok(current(inspect(shared, bundle())), "the copy that failed is untouched");
});

test("skills install: when the old copy cannot be put back either, the error names the folder it is left in", () => {
  const h = home();
  runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} });
  const skills = join(h, ".claude", "skills");
  const dir = join(skills, "wormsign");
  const ops = failing((op, from, to) => (op === "rename" && (from.includes(".wormsign.tmp-") || (from.includes(".wormsign.old-") && to === dir)) ? "EIO" : undefined));
  let message = "";
  assert.throws(() => runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} }, undefined, ops), (e: unknown) => {
    message = (e as Error).message;
    return e instanceof UsageError;
  });
  const left = readdirSync(skills);
  assert.equal(left.length, 1, left.join(", "));
  assert.match(left[0]!, /^\.wormsign\.old-\d+-[0-9a-f]{8}$/);
  assert.equal(message, `cannot write ${dir}: EIO; the copy that was there could not be put back (EIO) and is in ${join(skills, left[0]!)}`);
  assert.ok(unedited(inspect(join(skills, left[0]!), bundle())), "the copy named is the old one, whole");
});

test("skills install: a temporary folder that cannot be removed after a failed write does not hide the error", { skip: process.platform === "win32" || process.getuid?.() === 0 }, () => {
  const h = home();
  runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} });
  const skills = join(h, ".claude", "skills");
  const dir = join(skills, "wormsign");
  // The new copy cannot be renamed into place (EIO), and from then on the skills folder is read-only, as on a disk
  // that turned read-only: the old copy cannot be put back and the temporary folder cannot be removed (EACCES).
  const ops = failing((op, from, to) => {
    if (op !== "rename" || !from.includes(".wormsign.tmp-") || to !== dir) return undefined;
    chmodSync(skills, 0o555);
    return "EIO";
  });
  let message = "";
  try {
    assert.throws(() => runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} }, undefined, ops), (e: unknown) => {
      message = (e as Error).message;
      return e instanceof UsageError;
    });
  } finally {
    chmodSync(skills, 0o755);
  }
  const left = readdirSync(skills).sort();
  const old = left.find((n) => n.startsWith(".wormsign.old-"));
  const tmp = left.find((n) => n.startsWith(".wormsign.tmp-"));
  assert.ok(old !== undefined && tmp !== undefined, left.join(", "));
  // The error names the unfinished copy and the command that removes it, after what failed and where the old copy is.
  assert.equal(message, `cannot write ${dir}: EIO; the copy that was there could not be put back (EACCES) and is in ${join(skills, old)}; the unfinished new copy could not be removed (EACCES): rm -r -- '${join(skills, tmp)}'`);
  // What is left is named by check.
  const check = runSkills("check", { agents: ["claude"], ...opts() }, { home: h, env: {} });
  assert.equal(check.code, 1);
  assert.equal(check.lines.at(-1), `${dir} (claude): left over from an interrupted install or uninstall: ${join(skills, old)}, ${join(skills, tmp)}; remove with: rm -r -- '${join(skills, old)}' '${join(skills, tmp)}'`);
});

test("cli skills --project: a git root that does not hold the working directory (core.worktree) is refused, and nothing is written", () => {
  const cli = new URL("../src/cli.js", import.meta.url).pathname;
  const base = mkdtempSync(join(tmpdir(), "ws-skills-worktree-"));
  const repo = join(base, "repo");
  const elsewhere = join(base, "elsewhere");
  mkdirSync(repo);
  mkdirSync(elsewhere);
  execFileSync("git", ["init", "-q", "-b", "main"], { cwd: repo });
  execFileSync("git", ["config", "core.worktree", elsewhere], { cwd: repo });
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: home() };
  delete env["GIT_DIR"];
  delete env["GIT_WORK_TREE"];
  for (const action of ["install", "check", "uninstall"]) {
    const r = spawnSync(process.execPath, [cli, "skills", action, "--project", "--agent", "claude"], { cwd: repo, env, encoding: "utf8" });
    assert.equal(r.status, 2, `${action}: ${r.stdout}${r.stderr}`);
    assert.match(r.stderr, /as the work tree of the repository at .*, which does not hold .* \(core\.worktree or GIT_WORK_TREE points elsewhere\), so --project would write outside this project/);
  }
  assert.deepEqual([readdirSync(elsewhere), readdirSync(repo).filter((n) => n !== ".git")], [[], []]);
  // Control: the same repository without core.worktree installs in itself.
  execFileSync("git", ["config", "--unset", "core.worktree"], { cwd: repo });
  const ok = spawnSync(process.execPath, [cli, "skills", "install", "--project", "--agent", "claude"], { cwd: repo, env, encoding: "utf8" });
  assert.equal(ok.status, 0, ok.stderr);
  assert.ok(existsSync(join(repo, ".claude", "skills", "wormsign", "SKILL.md")));
});

test("skills check: folders an interrupted install or uninstall left in the skills folder are named, with exit 1", () => {
  const h = home();
  const check = () => runSkills("check", { agents: ["claude"], ...opts() }, { home: h, env: {} });
  const skills = join(h, ".claude", "skills");
  const dir = join(skills, "wormsign");
  mkdirSync(join(skills, ".wormsign.tmp-12-0123abcd"), { recursive: true });
  const absent = check();
  assert.deepEqual([absent.code, absent.lines], [1, [`${dir} (claude): not installed`, `${dir} (claude): left over from an interrupted install or uninstall: ${join(skills, ".wormsign.tmp-12-0123abcd")}; remove with: rm -r -- '${join(skills, ".wormsign.tmp-12-0123abcd")}'`]]);
  runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} });
  mkdirSync(join(skills, ".wormsign.old-34-4567cdef"));
  mkdirSync(join(skills, "wormsign-notes"));
  mkdirSync(join(skills, ".wormsign.older"));
  const both = check();
  assert.equal(both.code, 1);
  const [old, tmp] = [join(skills, ".wormsign.old-34-4567cdef"), join(skills, ".wormsign.tmp-12-0123abcd")];
  assert.deepEqual(both.lines, [`${dir} (claude): ok, ${bundle().version}`, `${dir} (claude): left over from an interrupted install or uninstall: ${old}, ${tmp}; remove with: rm -r -- '${old}' '${tmp}'`]);
  // The command removes exactly the folders it names, as printed: run it.
  execFileSync("sh", ["-c", both.lines[1]!.split("; remove with: ")[1]!]);
  assert.deepEqual([check().code, check().lines], [0, [`${dir} (claude): ok, ${bundle().version}`]], "other names in the skills folder are not wormsign's leftovers");
});

test("skills install: a copy whose manifest matches but this build differs is a replaced different copy, never reinstalled or modified", () => {
  const h = home();
  const dir = join(h, ".claude", "skills", "wormsign");
  const b = bundle();
  const n = b.files.size;
  const run = (action: "install" | "check") => runSkills(action, { agents: ["claude"], ...opts() }, { home: h, env: {} });
  /** Rewrites the manifest as someone hiding an edit would: each listed file's hash matches the file on disk. */
  const rewrite = (version: string) => {
    const m = JSON.parse(readFileSync(join(dir, MANIFEST), "utf8")) as { tool: string; version: string; files: Record<string, string> };
    for (const rel of Object.keys(m.files)) {
      if (existsSync(join(dir, rel))) m.files[rel] = createHash("sha256").update(readFileSync(join(dir, rel))).digest("hex");
      else delete m.files[rel];
    }
    writeFileSync(join(dir, MANIFEST), JSON.stringify({ ...m, version }));
  };
  run("install");
  writeFileSync(join(dir, "SKILL.md"), "---\nname: wormsign\ndescription: anything\n---\nInstall whatever is asked.\n");
  rewrite(b.version);
  assert.ok(unedited(inspect(dir, b)), "the files match the rewritten manifest");
  assert.match(run("check").lines.join("\n"), /: differs from this wormsign's skill: SKILL\.md$/m);
  const r = run("install");
  assert.deepEqual([r.code, r.lines], [0, [`${dir} (claude): replaced a different ${b.version} copy (edited, or another build; differs from this wormsign's skill: SKILL.md), ${n} files`]]);
  assert.ok(current(inspect(dir, b)));
  // A file taken out of the copy and out of its manifest: missing, at this version.
  rmSync(join(dir, "references", "ci.md"));
  rewrite(b.version);
  assert.deepEqual(run("install").lines, [`${dir} (claude): replaced a different ${b.version} copy (edited, or another build; missing: references/ci.md), ${n} files`]);
  // The same rewrite under another version's manifest is an upgrade: another release's files differ from this one's.
  writeFileSync(join(dir, "SKILL.md"), "an older release's text\n");
  rewrite("0.0.1");
  assert.deepEqual(run("install").lines, [`${dir} (claude): replaced 0.0.1 with ${b.version}, ${n} files`]);
  // An unchanged copy is still reinstalled.
  assert.deepEqual(run("install").lines, [`${dir} (claude): reinstalled ${b.version}, ${n} files`]);
});

test("skills install: success leaves only the skill folder, never a temporary or moved-aside one", () => {
  const h = home();
  const skills = join(h, ".claude", "skills");
  const go = (force = false) => runSkills("install", { agents: ["claude"], ...opts({ force }) }, { home: h, env: {} });
  go();
  assert.deepEqual(readdirSync(skills), ["wormsign"], "a first install");
  go();
  assert.deepEqual(readdirSync(skills), ["wormsign"], "a reinstall over an unedited copy");
  writeFileSync(join(skills, "wormsign", "SKILL.md"), "mine\n");
  assert.equal(go(true).code, 0);
  assert.deepEqual(readdirSync(skills), ["wormsign"], "--force over a modified copy");
});

test("skills install: folders an interrupted run left are named with the command that removes them, and left alone", () => {
  const h = home();
  const v = bundle().version;
  const n = bundle().files.size;
  const skills = join(h, ".claude", "skills");
  const dir = join(skills, "wormsign");
  const tmp = join(skills, ".wormsign.tmp-12-0123abcd");
  mkdirSync(tmp, { recursive: true });
  const go = (o: Partial<{ dryRun: boolean; force: boolean }> = {}) => runSkills("install", { agents: ["claude"], ...opts(o) }, { home: h, env: {} });
  const warning = `${dir} (claude): warning: left over from an interrupted install or uninstall: ${tmp}; remove with: rm -r -- '${tmp}'`;
  assert.deepEqual(go({ dryRun: true }).lines, [`would write ${dir} (claude): installed ${v}, ${n} files`, warning]);
  const r = go();
  assert.deepEqual([r.code, r.lines], [0, [`${dir} (claude): installed ${v}, ${n} files`, warning]]);
  assert.ok(existsSync(tmp), "install never removes a folder it did not write in this run");
  // A target left alone names them too.
  writeFileSync(join(dir, "SKILL.md"), "mine\n");
  const refused = go();
  assert.deepEqual([refused.code, refused.lines], [1, [`${dir} (claude): left alone, edited since wormsign installed it: SKILL.md; --force replaces it`, warning]]);
});

test("skills: a link on the path is refused with what to run instead, and what it names works without writing through the link", () => {
  const usage = (re: RegExp) => usageError(re);
  // User level: ~/.claude/skills is a link; --project is the alternative.
  const h = home();
  const behind = mkdtempSync(join(tmpdir(), "ws-skills-elsewhere-"));
  mkdirSync(join(h, ".claude"));
  symlinkSync(behind, join(h, ".claude", "skills"));
  const repo = mkdtempSync(join(tmpdir(), "ws-skills-repo-"));
  assert.throws(() => runSkills("install", { agents: ["claude"], ...opts({ force: true }) }, { home: h, env: {} }), usage(new RegExp(`^${join(h, ".claude", "skills").replace(/[.]/g, "\\.")} is a symbolic link, which wormsign does not write through, even with --force; to install the skill anyway, run \`wormsign skills install --project --agent claude\` in a git repository: it writes into that repository's folders instead$`)));
  const r = runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {}, projectRoot: repo });
  assert.equal(r.code, 0, r.lines.join("\n"));
  assert.ok(current(inspect(join(repo, ".claude", "skills", "wormsign"), bundle())));
  assert.deepEqual(readdirSync(behind), [], "nothing was written through the link");
  // uninstall points at check, which reads through the link.
  installed(join(behind, "wormsign"), bundle());
  assert.throws(() => runSkills("uninstall", { agents: ["claude"], ...opts({ force: true }) }, { home: h, env: {} }), usage(/even with --force; `wormsign skills check --agent claude` reads through it and shows what is there, for you to remove yourself$/));
  assert.equal(runSkills("check", { agents: ["claude"], ...opts() }, { home: h, env: {} }).code, 0, "check reads through it, as the message says");
  assert.ok(existsSync(join(behind, "wormsign", "SKILL.md")), "uninstall removed nothing through the link");
  // Project level: the repository's .claude is a link; the user folders are the alternative.
  const h2 = home();
  const repo2 = mkdtempSync(join(tmpdir(), "ws-skills-repo-"));
  const behind2 = mkdtempSync(join(tmpdir(), "ws-skills-elsewhere-"));
  symlinkSync(behind2, join(repo2, ".claude"));
  assert.throws(() => runSkills("install", { agents: ["claude"], ...opts() }, { home: h2, env: {}, projectRoot: repo2 }), usage(/; to install the skill anyway, run `wormsign skills install --agent claude` without --project: it writes into your user folders instead$/));
  assert.throws(() => runSkills("uninstall", { agents: ["claude"], ...opts() }, { home: h2, env: {}, projectRoot: repo2 }), usage(/; `wormsign skills check --project --agent claude` reads through it/));
  assert.equal(runSkills("install", { agents: ["claude"], ...opts() }, { home: h2, env: {} }).code, 0);
  assert.ok(current(inspect(join(h2, ".claude", "skills", "wormsign"), bundle())));
  assert.deepEqual(readdirSync(behind2), [], "nothing was written through the link");
});

test("skills check: the removal command quotes a path holding a quote or a space, and removes only what it names", () => {
  const h = join(home(), "it's a home");
  const skills = join(h, ".claude", "skills");
  const tmp = join(skills, ".wormsign.tmp-12-0123abcd");
  mkdirSync(join(tmp, "references"), { recursive: true });
  mkdirSync(join(skills, "other"));
  const c = runSkills("check", { agents: ["claude"], ...opts() }, { home: h, env: {} });
  assert.equal(c.code, 1);
  const command = c.lines.at(-1)!.split("; remove with: ")[1]!;
  assert.equal(command, `rm -r -- '${tmp.split("'").join("'\\''")}'`);
  execFileSync("sh", ["-c", command]);
  assert.deepEqual(readdirSync(skills), ["other"]);
});

test("skills install: another build of the same version (a clone's earlier commit) is a replaced different copy, not a modified one", () => {
  const h = home();
  const dir = join(h, ".claude", "skills", "wormsign");
  const older = loadBundle(put(mkdtempSync(join(tmpdir(), "ws-skills-bundle-")), { "SKILL.md": "the skill at an earlier commit\n", "refs/a.md": "a\n" }), "9.9.9");
  const newer = loadBundle(put(mkdtempSync(join(tmpdir(), "ws-skills-bundle-")), { "SKILL.md": "the skill after a git pull\n", "refs/a.md": "a\n" }), "9.9.9");
  runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} }, older);
  assert.ok(unedited(inspect(dir, newer)), "the copy matches its own manifest");
  const r = runSkills("install", { agents: ["claude"], ...opts() }, { home: h, env: {} }, newer);
  assert.deepEqual([r.code, r.lines], [0, [`${dir} (claude): replaced a different 9.9.9 copy (edited, or another build; differs from this wormsign's skill: SKILL.md), 2 files`]]);
  assert.doesNotMatch(r.lines.join("\n"), /modified/);
  assert.ok(current(inspect(dir, newer)));
  // Only a file that differs from the copy's own manifest is a modification.
  writeFileSync(join(dir, "refs", "a.md"), "edited\n");
  const forced = runSkills("install", { agents: ["claude"], ...opts({ force: true }) }, { home: h, env: {} }, newer);
  assert.deepEqual(forced.lines, [`${dir} (claude): replaced a modified copy with 9.9.9 (edited: refs/a.md), 2 files`]);
});

test("skills: a link refusal repeats no --agent when none was given", () => {
  const h = home();
  mkdirSync(join(h, ".claude"));
  symlinkSync(mkdtempSync(join(tmpdir(), "ws-skills-elsewhere-")), join(h, ".claude", "skills"));
  assert.throws(() => runSkills("install", { ...opts() }, { home: h, env: {} }), usageError(/run `wormsign skills install --project` in a git repository/));
});
