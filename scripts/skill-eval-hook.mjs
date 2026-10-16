#!/usr/bin/env node
// A Claude Code PreToolUse hook for Bash and the file tools, run as `node <this file> <log> <repo>`. For Bash it appends
// {command, allowed} to the log, one JSON object per line, and allows the call only when readOnly() finds every part of
// it read-only; anything else is denied and does not run. For Write, Edit, MultiEdit and NotebookEdit it appends
// {tool, path, allowed} and denies a file under a .git folder: git's own config can make an allowed git read run a
// program (core.fsmonitor, core.pager), so .git is never written; any other file it leaves to Claude Code's permission
// mode, printing no decision. Any error exits 2, which Claude Code treats as a block: a broken hook fails closed.
// The agent can read this file and every message it prints, so none of them says what the hook is used for.
import { appendFileSync, readFileSync, realpathSync } from "node:fs";
import { dirname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const PROGRAMS = new Set(["cat", "ls", "head", "tail", "wc", "find", "grep", "which", "pwd", "echo"]);
const EXACT = new Set(["node --version", "npm --version", "pip --version", "python3 --version", "uv --version"]);
const PREFIXES = ["command -v", "npm view", "npm info", "npm ls", "npm config get", "pip index", ...["status", "log", "diff", "show", "rev-parse", "ls-files"].map((s) => `git ${s}`)];
// Options that act or write a file: find's actions; git's --output, pip's --log and --cache-dir, npm's --logs-dir and
// --cache, also abbreviated, since git, npm and pip accept any unambiguous prefix of a long option.
const FIND_ACTS = /^-(exec|ok|delete|fprint|fls)/;
const WRITES = ["output", "log", "log-file", "logs-dir", "cache", "cache-dir"];
const acts = (w) => FIND_ACTS.test(w) || (/^--[^=]/.test(w) && WRITES.some((o) => o.startsWith(w.slice(2).split("=")[0])));
// Programs with such options: a glob there could expand to a file named like one, so it is denied.
const OPTIONS_ACT = new Set(["find", "git", "npm", "pip"]);
// What the agent is told.
export const DENIED = "blocked by a local policy: this command could change something; read-only commands run";
export const FILE_DENIED = "blocked by a local policy: files under .git are not changed here";
/** The file tools whose calls the hook sees (settings.json's second PreToolUse matcher), and where each names its file. */
export const FILE_TOOLS = { Write: "file_path", Edit: "file_path", MultiEdit: "file_path", NotebookEdit: "notebook_path" };
export const ALLOWED = "allowed by a local policy: read-only";

/** True when every part of a shell command is a read-only program from the short list above. When in doubt, false. */
export function readOnly(command, repos) {
  // Harmless redirections: duplicating a descriptor (2>&1), discarding into /dev/null. Any other > or < denies.
  const text = String(command).replace(/(?<=^|\s)[0-9&]?>(&[0-9]|>?\s*\/dev\/null)(?=$|[\s;|&])/g, " ");
  // No quoting, escaping or expansion ($, braces, backticks, subshells), so what runs is what is written; no lone &.
  if (/[`<>(){}$'"\\]|(^|[^&])&(?!&)/.test(text)) return false;
  const parts = text.split(/&&|\|\||[;|\n]/).map((p) => p.trim()).filter(Boolean);
  return parts.length > 0 && parts.every((p) => readOnlyPart(p.split(/\s+/), repos));
}

function readOnlyPart(words, repos) {
  if (words[0] === "cd") return words.length === 2 && insideRepo(words[1], repos);
  if (words.some(acts) || (OPTIONS_ACT.has(words[0]) && words.some((w) => /[*?[\]]/.test(w)))) return false;
  const line = words.join(" ");
  return PROGRAMS.has(words[0]) || EXACT.has(line) || PREFIXES.some((p) => line === p || line.startsWith(`${p} `));
}

/**
 * Whether a file path is inside a .git folder: a ".git" component in the path as given (Claude Code makes it absolute),
 * or in the real path of the nearest folder of it that exists, so a link cannot hide one.
 */
export function inGitDir(path) {
  const parts = (p) => resolve(p).split(sep);
  if (parts(path).includes(".git")) return true;
  let dir = dirname(resolve(path));
  for (;;) {
    try {
      return parts(realpathSync(dir)).includes(".git");
    } catch {
      const up = dirname(dir);
      if (up === dir) return false;
      dir = up;
    }
  }
}

/** One of the repository's paths or a directory below it, or a relative path without "..". */
function insideRepo(dir, repos) {
  if (/^[-~]|(^|\/)\.\.(\/|$)/.test(dir)) return false;
  return !dir.startsWith("/") || repos.some((r) => dir.replace(/\/+$/, "") === r || dir.startsWith(`${r}/`));
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [log, repo] = process.argv.slice(2);
    if (!log || !repo) throw new Error("usage: node <this file> <log> <repo>");
    const input = JSON.parse(readFileSync(0, "utf8"));
    const tool = String(input.tool_name ?? "Bash");
    if (Object.hasOwn(FILE_TOOLS, tool)) {
      const path = String(input.tool_input?.[FILE_TOOLS[tool]] ?? "");
      if (!path) throw new Error(`no ${FILE_TOOLS[tool]} in the ${tool} call`);
      const allowed = !inGitDir(path);
      appendFileSync(log, JSON.stringify({ tool, path, allowed }) + "\n");
      // Allowed: no decision, so the permission mode decides as it would without the hook.
      if (!allowed) console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: FILE_DENIED } }));
    } else {
      const command = String(input.tool_input?.command ?? "");
      const allowed = readOnly(command, [repo, realpathSync(repo)]);
      appendFileSync(log, JSON.stringify({ command, allowed }) + "\n");
      const reason = allowed ? ALLOWED : DENIED;
      const decision = { hookEventName: "PreToolUse", permissionDecision: allowed ? "allow" : "deny", permissionDecisionReason: reason };
      console.log(JSON.stringify({ hookSpecificOutput: decision }));
    }
  } catch (e) {
    process.stderr.write(`bash policy hook: ${e.message}\n`);
    process.exit(2);
  }
}
