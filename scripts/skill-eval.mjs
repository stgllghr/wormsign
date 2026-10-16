#!/usr/bin/env node
// Maintainer tool (not shipped, not run by npm test): does an agent with the wormsign skill installed follow it?
// Needs the `claude` CLI on the PATH, logged in. Usage:
//   npm run build && node scripts/skill-eval.mjs [--out <file.json>] [--no-skill]
// --no-skill runs every scenario without the skill installed, as a baseline: the output's "mode" says which ran
// ("skill" or "no-skill"), and a no-skill run in which the wormsign skill loaded anyway (a user-level copy) is an error.
// For each scenario (scripts/skill-eval-rules.mjs): a temporary git repository with the scenario's files; `wormsign
// skills install --project --agent claude` there (with an empty HOME); a .claude/settings.json whose PreToolUse hook
// for Bash (scripts/skill-eval-hook.mjs) records every command the agent tries, lets it run only when it is read-only
// (cat, ls, git log, npm view and a few more), and denies the rest, so nothing is installed or changed, and whose hook
// for the file tools denies any write under .git (git's config could make an allowed git read run a program); then
// `claude -p <prompt>` in the repository. The scenario's rule grades what the agent attempted, allowed or denied, the
// repository's files and the reply. One line per scenario goes to stdout, the details to --out
// (docs/evidence/skill-eval.md).
//
// Cues. What the agent can see names nothing that says it is being evaluated (prepareScenario()): the repository is a
// folder named for its project (PROJECT, "notes-app") in a temporary folder named as `mktemp -d` names one, and the
// hook it runs is a copy outside the repository, hooks/bash-policy.mjs, whose text and messages are neutral. Runs 1 to
// 3 had these cues: the package skill-eval-project, folders named ws-skill-eval-<scenario>-..., and a settings.json
// that ran this repository's scripts/skill-eval-hook.mjs.
//
// Isolation. claude runs with `--setting-sources project,local` and `--no-session-persistence` when its --help lists
// them (user settings, such as user hooks and enabled plugins, are not read; no transcript is saved), and without the
// Claude Code variables of the calling shell or parent session (DROPPED_VAR). It keeps the real HOME, which holds its
// login, so what claude loads or writes there regardless (managed settings, user-level skills, its own state) is not
// excluded: --out records the skills, plugins and MCP servers each run loaded. npm's and pip's caches point into the
// scenario's temporary folder, so a read-only `npm view` or `pip index` writes nothing outside it.
// `--permission-mode acceptEdits` lets the agent edit files in the repository, so a pass rule that reads a file (an
// unpinned package.json entry, a baseline written without asking) can fail; Claude Code still asks before writing
// outside the folder it started in, and a headless run cannot be asked.
// Controls: the hook is tested before any run (it must log and allow a read, log and deny anything else, and block
// when it cannot log); a run that did not load the skill, or whose transcript (`--output-format json --verbose` prints
// every message) has more Bash calls than the hook recorded, or that does not show either, is an error, not a result.
// Exit 0 when every scenario passes, 1 when one fails or soft-fails (asked for what needed no permission), 2 when one
// could not be graded or on a setup error. test/skill-eval-rules.test.ts runs this script with a fake claude, never the
// real one.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { PROJECT, SCENARIOS, json } from "./skill-eval-rules.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const CLI = join(ROOT, "dist/src/cli.js");
const HOOK = join(ROOT, "scripts/skill-eval-hook.mjs");
/** A temporary folder's prefix, as `mktemp -d` names one: the path the agent works in says nothing about the run. */
export const TEMP_PREFIX = "tmp.";
/** Where the hook is copied in a scenario's temporary folder, outside the repository, under a neutral name. */
export const HOOK_COPY = join("hooks", "bash-policy.mjs");
const CLAUDE_ARGS = ["--output-format", "json", "--verbose", "--max-turns", "8", "--permission-mode", "acceptEdits"];
const RUN_TIMEOUT_MS = 20 * 60 * 1000;
// Variables a parent Claude Code session sets for itself, and any other Claude Code setting: CLAUDE_CODE_PLUGIN_DIRS
// alone would load the parent's plugins into the run. Where claude finds its login (CLAUDE_CONFIG_DIR,
// CLAUDE_CODE_OAUTH_TOKEN), the provider (CLAUDE_CODE_USE_*) and ANTHROPIC_* are kept.
const DROPPED_VAR = /^(CLAUDECODE|CLAUDE_(?!CONFIG_DIR$|CODE_OAUTH_TOKEN$|CODE_USE_)\w*)$/;

const sh = (s) => `'${s.replaceAll("'", "'\\''")}'`;
const tail = (s) => String(s ?? "").trim().slice(-300);

/** The calling environment without Claude Code's variables; npm's and pip's caches in the scenario's folder. */
function childEnv(root) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !DROPPED_VAR.test(k)));
  return root ? { ...env, npm_config_cache: join(root, "npm-cache"), PIP_CACHE_DIR: join(root, "pip-cache") } : env;
}

/** The hook's log: one {command, allowed} per Bash call the agent attempted, one {tool, path, allowed} per file edit. */
function readLog(log) {
  return existsSync(log) ? readFileSync(log, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line)) : [];
}
/** The tools the second PreToolUse matcher sends to the hook: an exact-name list, as Claude Code's hooks docs give it. */
export const FILE_MATCHER = "Write|Edit|MultiEdit|NotebookEdit";

/** The hook must log and allow a read, log and deny anything else, and block (exit 2) when it cannot log. */
function hookSelfTest() {
  const dir = mkdtempSync(join(tmpdir(), TEMP_PREFIX));
  try {
    const log = join(dir, "commands.log");
    for (const [command, want] of [["cat package.json", "allow"], ["echo 'control' | sh", "deny"]]) {
      const input = JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } });
      const r = spawnSync(process.execPath, [HOOK, log, dir], { input, encoding: "utf8" });
      const decision = r.status === 0 ? JSON.parse(r.stdout).hookSpecificOutput?.permissionDecision : undefined;
      const logged = JSON.stringify(readLog(log).at(-1));
      if (decision !== want || logged !== JSON.stringify({ command, allowed: want === "allow" })) {
        throw new Error(`the hook failed its self-test on ${command} (exit ${r.status}, decision ${decision}, logged ${logged}): ${tail(r.stderr)}`);
      }
    }
    // A file edit under .git is denied; any other gets no decision, so the permission mode decides.
    for (const [path, want] of [[join(dir, ".git", "config"), "deny"], [join(dir, "notes.md"), undefined]]) {
      const input = JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Edit", tool_input: { file_path: path, old_string: "a", new_string: "b" } });
      const r = spawnSync(process.execPath, [HOOK, log, dir], { input, encoding: "utf8" });
      const decision = r.status === 0 && r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput?.permissionDecision : undefined;
      const logged = JSON.stringify(readLog(log).at(-1));
      if (r.status !== 0 || decision !== want || logged !== JSON.stringify({ tool: "Edit", path, allowed: want === undefined })) {
        throw new Error(`the hook failed its self-test on an Edit of ${path} (exit ${r.status}, decision ${decision}, logged ${logged}): ${tail(r.stderr)}`);
      }
    }
    const input = JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "cat package.json" } });
    const unlogged = spawnSync(process.execPath, [HOOK, join(dir, "missing", "commands.log"), dir], { input, encoding: "utf8" });
    if (unlogged.status !== 2) throw new Error(`the hook exited ${unlogged.status}, not 2, when it could not write its log`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** A scenario's files: text (executable when it starts with #!), or { symlink: target } for a link. */
function writeFiles(repo, files) {
  for (const [name, value] of Object.entries(files)) {
    mkdirSync(dirname(join(repo, name)), { recursive: true });
    if (typeof value === "object") symlinkSync(value.symlink, join(repo, name));
    else writeFileSync(join(repo, name), value, { mode: value.startsWith("#!") ? 0o755 : 0o644 });
  }
}

/** A file's text, or a symbolic link's target; links are never followed. */
function content(path, link) {
  return link ? `-> ${readlinkSync(path)}` : readFileSync(path, "utf8");
}

/** Relative path -> SHA-256 of every file and link under dir except .git. */
function snapshot(dir, base = dir, out = new Map()) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== ".git") snapshot(path, base, out);
    } else {
      const link = entry.isSymbolicLink();
      out.set(relative(base, path), { link, sha256: createHash("sha256").update(content(path, link)).digest("hex") });
    }
  }
  return out;
}

/** Files the agent added, changed or removed, with the text (up to 4 KB) of those it added or changed. */
function changes(repo, before) {
  const after = snapshot(repo);
  const text = (rel) => content(join(repo, rel), after.get(rel).link).slice(0, 4096);
  return {
    added: [...after.keys()].filter((k) => !before.has(k)).map((path) => ({ path, text: text(path) })),
    changed: [...after.keys()].filter((k) => before.has(k) && before.get(k).sha256 !== after.get(k).sha256).map((path) => ({ path, text: text(path) })),
    removed: [...before.keys()].filter((k) => !after.has(k)),
  };
}

/** The result, the init message and the tool calls of `claude -p --output-format json --verbose` (a message list). */
function parseRun(stdout) {
  let doc;
  try {
    doc = JSON.parse(stdout);
  } catch {
    return { toolUses: [], transcript: false };
  }
  const messages = Array.isArray(doc) ? doc : [doc];
  return {
    result: messages.find((m) => m?.type === "result"),
    init: messages.find((m) => m?.type === "system" && m.subtype === "init"),
    toolUses: messages.filter((m) => m?.type === "assistant").flatMap((m) => m.message?.content ?? []).filter((b) => b?.type === "tool_use"),
    transcript: Array.isArray(doc),
  };
}

/**
 * What makes a run ungradable as far as the skill goes. With the skill: no list of loaded skills, or one without
 * wormsign. Without it (--no-skill): the skill loaded, or opened, anyway, as a user-level copy would make it; then the
 * run is no baseline.
 */
/** A loaded skill that is wormsign's: `wormsign`, or a plugin's `<plugin>:wormsign`. */
export const isWormsignSkill = (name) => /(^|:)wormsign$/.test(name);

export function skillProblems(skill, skills, skillRead) {
  if (!skills) return ["no list of loaded skills in the output: cannot tell whether the skill was loaded"];
  const problems = [];
  if (skill && !skills.some(isWormsignSkill)) problems.push("the wormsign skill was not among the skills the run loaded");
  if (!skill && skills.some(isWormsignSkill)) problems.push("the wormsign skill loaded in a --no-skill run (a user-level copy?): this is no baseline");
  if (!skill && skillRead) problems.push("the agent opened a wormsign skill in a --no-skill run: this is no baseline");
  return problems;
}

/** A scenario's verdict: error when it could not be graded, else pass, soft-fail (see skill-eval-rules.mjs) or fail. */
export const verdictOf = (problems, pass, soft) => (problems.length > 0 ? "error" : pass ? "pass" : soft ? "soft-fail" : "fail");

/** 2 when a scenario could not be graded, 1 when one failed or soft-failed, else 0. */
export const exitCode = (verdicts) => (verdicts.includes("error") ? 2 : verdicts.some((v) => v === "fail" || v === "soft-fail") ? 1 : 0);

function skillNames(init) {
  const list = init?.skills ?? init?.slash_commands;
  return Array.isArray(list) ? list.map((s) => (typeof s === "string" ? s : s?.name)).filter(Boolean) : undefined;
}

/**
 * A scenario's temporary folder, `root`: the repository (`repo`, named PROJECT) with the scenario's files, a git
 * repository with the skill installed (none with `skill: false`) and a .claude/settings.json that runs the hook; the
 * hook's copy (HOOK_COPY) and its log beside it. The caller removes `root`.
 */
export function prepareScenario(scenario, { skill = true } = {}) {
  const root = mkdtempSync(join(tmpdir(), TEMP_PREFIX));
  try {
    const repo = join(root, PROJECT);
    const home = join(root, "home");
    const log = join(root, "commands.log");
    const hookCopy = join(root, HOOK_COPY);
    mkdirSync(repo);
    mkdirSync(home);
    mkdirSync(dirname(hookCopy));
    copyFileSync(HOOK, hookCopy);
    writeFiles(repo, scenario.files);
    const git = spawnSync("git", ["init", "-q"], { cwd: repo, encoding: "utf8" });
    if (git.status !== 0) throw new Error(`git init failed: ${tail(git.stderr)}`);
    if (skill) {
      const install = spawnSync(process.execPath, [CLI, "skills", "install", "--project", "--agent", "claude"], { cwd: repo, encoding: "utf8", env: { PATH: process.env.PATH, HOME: home } });
      if (install.status !== 0 || !existsSync(join(repo, ".claude/skills/wormsign/SKILL.md"))) {
        throw new Error(`wormsign skills install exited ${install.status}: ${tail(install.stderr || install.stdout)}`);
      }
    } else {
      // The baseline: no skill in the repository. The scratch home folder is only wormsign's: claude keeps the real
      // HOME, so a user-level copy there is caught by skillProblems() from what the run loaded, not here.
      mkdirSync(join(repo, ".claude"), { recursive: true });
      if (existsSync(join(repo, ".claude/skills"))) throw new Error("a skills folder exists in a --no-skill scenario");
    }
    const hook = { type: "command", command: `${sh(process.execPath)} ${sh(hookCopy)} ${sh(log)} ${sh(repo)}` };
    writeFileSync(join(repo, ".claude/settings.json"), json({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [hook] }, { matcher: FILE_MATCHER, hooks: [hook] }] } }));
    return { root, repo, log };
  } catch (e) {
    rmSync(root, { recursive: true, force: true });
    throw e;
  }
}

function runScenario(scenario, isolation, skill) {
  const { root, repo, log } = prepareScenario(scenario, { skill });
  try {
    const before = snapshot(repo);

    const args = ["-p", scenario.prompt, ...CLAUDE_ARGS, ...isolation];
    const run = spawnSync("claude", args, { cwd: repo, encoding: "utf8", env: childEnv(root), stdio: ["ignore", "pipe", "pipe"], timeout: RUN_TIMEOUT_MS, maxBuffer: 1 << 28 });
    const { result, init, toolUses, transcript } = parseRun(run.stdout ?? "");
    const logged = readLog(log);
    const attempts = logged.filter((e) => typeof e.command === "string");
    const fileEdits = logged.filter((e) => typeof e.tool === "string");
    const reply = typeof result?.result === "string" ? result.result : "";

    const problems = [];
    if (run.error) problems.push(`claude did not finish: ${run.error.message}`);
    if (!result) problems.push(`no result from claude (exit ${run.status}): ${tail(run.stderr || run.stdout)}`);
    else if (result.is_error && result.subtype !== "error_max_turns") problems.push(`claude reported an error (${result.subtype}): ${tail(reply)}`);
    // Without the transcript neither control can run, so its absence is an error too, never a silent pass.
    const skillRead = toolUses.some((t) => (t.name === "Skill" && /\bwormsign\b/.test(JSON.stringify(t.input))) || (t.name === "Read" && /skills\/wormsign\/SKILL\.md$/.test(t.input?.file_path ?? "")));
    // A baseline in which the skill loaded anyway (a user-level copy, which the real HOME keeps) is no baseline.
    problems.push(...skillProblems(skill, skillNames(init), skillRead));
    const bashCalls = toolUses.filter((t) => t.name === "Bash").length;
    if (!transcript) problems.push("no transcript in the output: cannot check that the hook saw every Bash call");
    else if (bashCalls > attempts.length) problems.push(`the transcript has ${bashCalls} Bash calls, the hook recorded ${attempts.length}`);
    const editCalls = toolUses.filter((t) => FILE_MATCHER.split("|").includes(t.name)).length;
    if (transcript && editCalls > fileEdits.length) problems.push(`the transcript has ${editCalls} file edits, the hook recorded ${fileEdits.length}`);
    const reads = toolUses.filter((t) => t.name === "Read").map((t) => String(t.input?.file_path ?? ""));
    let pass = false;
    let soft;
    try {
      pass = Boolean(scenario.pass({ attempts, reply, repo, skillRead, skill, reads }));
      soft = pass ? undefined : scenario.soft?.({ attempts, reply, repo, skillRead, skill, reads });
    } catch (e) {
      problems.push(`the pass rule could not read the repository: ${e.message}`);
    }

    const tools = {};
    for (const t of toolUses) tools[t.name] = (tools[t.name] ?? 0) + 1;
    return {
      id: scenario.id,
      prompt: scenario.prompt,
      verdict: verdictOf(problems, pass, soft),
      problems,
      ...(soft && problems.length === 0 ? { soft } : {}),
      commands: attempts,
      fileEdits,
      reply,
      files: changes(repo, before),
      skillRead,
      tools,
      run: {
        exit: run.status,
        subtype: result?.subtype,
        isError: result?.is_error,
        turns: result?.num_turns,
        durationMs: result?.duration_ms,
        costUsd: result?.total_cost_usd,
        models: Object.keys(result?.modelUsage ?? {}),
        permissionDenials: result?.permission_denials,
      },
      loaded: init
        ? { model: init.model, claudeCode: init.claude_code_version, permissionMode: init.permissionMode, skills: init.skills, slashCommands: init.slash_commands, plugins: init.plugins, mcpServers: init.mcp_servers, agents: init.agents, tools: init.tools }
        : "no init message",
    };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function main() {
  let opt;
  try {
    opt = parseArgs({ options: { out: { type: "string", default: "skill-eval.json" }, "no-skill": { type: "boolean", default: false } } }).values;
  } catch (e) {
    throw new Error(`${e.message}\nusage: skill-eval.mjs [--out <file.json>] [--no-skill]`, { cause: e });
  }
  const skill = !opt["no-skill"];
  const mode = skill ? "skill" : "no-skill";
  if (!existsSync(CLI)) throw new Error("dist/src/cli.js is missing: run npm run build first");
  const help = spawnSync("claude", ["--help"], { encoding: "utf8", env: childEnv() });
  if (help.error || help.status !== 0) throw new Error(`claude --help failed (${help.error?.message ?? `exit ${help.status}`}): is the claude CLI on the PATH?`);
  const isolation = [];
  if (/--setting-sources\b/.test(help.stdout)) isolation.push("--setting-sources", "project,local");
  if (/--no-session-persistence\b/.test(help.stdout)) isolation.push("--no-session-persistence");
  const claudeVersion = spawnSync("claude", ["--version"], { encoding: "utf8", env: childEnv() }).stdout?.trim();
  hookSelfTest();

  console.log(`mode: ${mode}${skill ? "" : " (the skill is not installed: a baseline)"}`);
  const results = [];
  for (const scenario of SCENARIOS) {
    const r = runScenario(scenario, isolation, skill);
    results.push(r);
    const why = r.problems.length > 0 ? `: ${r.problems.join("; ")}` : r.soft ? `: ${r.soft}` : "";
    console.log(`${r.verdict.padEnd(9)} ${r.id}${why}`);
  }
  const removedEnv = Object.keys(process.env).filter((k) => DROPPED_VAR.test(k)).sort();
  writeFileSync(opt.out, json({ date: new Date().toISOString(), mode, claudeVersion, node: process.version, claudeArgs: [...CLAUDE_ARGS, ...isolation], removedEnv, scenarios: results }));
  console.log(`wrote ${opt.out}`);
  return exitCode(results.map((r) => r.verdict));
}

// Run as a script; imported (by test/skill-eval-rules.test.ts), only its exports.
if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.exitCode = main();
  } catch (e) {
    process.stderr.write(`skill-eval: ${e.message}\n`);
    process.exitCode = 2;
  }
}
