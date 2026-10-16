import type { Finding } from "../types.js";
import { keyDigest, makeFinding } from "../types.js";
import { lineIndex } from "../fsutil.js";
import type { ScanContext } from "./context.js";
import { capped, notChecked } from "./context.js";
import { executedFiles, suspiciousReasons } from "./lifecycle.js";

/**
 * Editor and AI-agent settings that a repository can commit to run a command on
 * a developer's machine, with no install step. The 2026-08 wave committed both
 * kinds, each starting the other's payload: a .vscode/tasks.json task that runs
 * when the folder is opened, and a .claude/settings.json SessionStart hook
 * (https://research.jfrog.com/post/shai-hulud-is-back-august/). A project
 * .mcp.json starts its servers' commands in Claude Code sessions the same way,
 * and so does a plugin under .claude/ (its manifest, hooks/hooks.json, .lsp.json
 * or settings.json): Claude Code loads one from .claude/skills/ or from an
 * in-repo marketplace (code.claude.com/docs/en/plugins/loading). A skill,
 * command or subagent Markdown file under .claude/ declares hooks and subagent
 * MCP servers in its frontmatter (code.claude.com/docs/en/hooks, "Hooks in
 * skills and agents"), and a *.code-workspace file holds tasks VS Code runs on
 * folder open like those in .vscode/tasks.json; the tasks section of
 * .vscode/settings.json or of a workspace's settings is merged into them, and
 * the terminal settings there pick the shell and environment they run with. Any letter
 * case, as on macOS and Windows `.Claude/Settings.json` is the file an agent
 * opening `.claude/settings.json` reads.
 *
 * Every entry that runs on its own is high, whatever its command. Telling a
 * safe command from a harmful one means modelling shells, package managers,
 * workspaces and environment variables, and each model had holes an attacker
 * could walk through. A reviewed entry is baselined instead: its fingerprint
 * covers its whole definition, so any later edit to it fails again.
 */
export const PERSISTENCE_PATH = /(^|\/)(\.vscode\/(tasks|settings)\.json|[^/]*\.code-workspace|\.mcp\.json|\.claude\/(.*\/)?(settings(\.local)?\.json|hooks\/hooks\.json|\.lsp\.json|\.claude-plugin\/(plugin|marketplace)\.json|skills\/[^/]+\/SKILL\.md|(agents|commands)\/.+\.md))$/i;
/** Plugin files reported as one entry each: what in them runs is spread over fields wormsign does not model. */
const PLUGIN_FILE = /(\.claude-plugin\/[^/]*|\.lsp)\.json$/i;

/** Findings listed one by one per file. */
const MAX_LISTED = 50;
/** The heuristics read this much of a command, as for lifecycle scripts. */
const MAX_JUDGED = 4096;
/** Characters of the command shown in a message. */
const MAX_SHOWN = 120;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
/** An object's entries; any other value but undefined is one entry under `whole`, so a shape wormsign does not expect is still reported. */
const entries = (v: unknown, whole: string): [string, unknown][] => (isObj(v) ? Object.entries(v) : v === undefined ? [] : [[whole, v]]);

/** One entry that a file makes run automatically. */
interface AutoRun {
  ruleId: "WS-PS-001" | "WS-PS-002";
  /** The entry, for the message and the finding key. */
  what: string;
  /** When it runs, for the message. */
  when: string;
  /** Everything that decides what it runs, digested into the finding key. */
  id: string;
  /** The command it runs, at most MAX_JUDGED + 1 characters; built only for a listed finding. */
  command: () => string;
  /** A string from the file, used to find a line number. */
  anchor?: string;
  /** A key the anchor is searched after, such as a workspace's "settings", whose "tasks" is not the top-level one. */
  within?: string;
  /** Said first in the message. */
  note?: string;
}

/** Findings for one editor or agent settings file: one high finding per entry that runs automatically. */
export function checkPersistence(rel: string, text: string, ctx: ScanContext): Finding[] {
  // Skill, command and subagent files: Markdown with YAML frontmatter.
  if (/\.md$/i.test(rel)) return report(rel, text, ctx, frontmatterRuns(text));
  const doc = parseJsonc(text);
  // Keyed on the content too: VS Code and Claude Code still act on what such a file holds, so a baseline entry approves
  // this text only.
  if (doc === undefined) return [notChecked(rel, "it is not valid JSON, even allowing comments and trailing commas, and VS Code and Claude Code can still act on a file with errors", "high", text)];
  if (doc === PROTO_KEY) return [notChecked(rel, 'it has a "__proto__" key, which VS Code\'s parser applies as the object\'s prototype, so the settings under it take effect, while wormsign reads it as a plain key', "high", text)];
  if (!isObj(doc)) return [];
  // JSON.stringify overflows the stack on a value nested 200,000 deep. An id then uses the file's digest, computed
  // once (hashing the whole text per entry was quadratic); a shown value is then the value's own strings, so the
  // message and its reasons come from that entry and not from elsewhere in the file.
  const whole = `file:${keyDigest(text)}`;
  const canon = (v: unknown): string => {
    try {
      return JSON.stringify(v) ?? "";
    } catch {
      return whole;
    }
  };
  const shown = (v: unknown): string => {
    try {
      return (JSON.stringify(v) ?? "").slice(0, MAX_JUDGED + 1);
    } catch {
      return `${TOO_DEEP} ${stringsOf(v)}`.slice(0, MAX_JUDGED + 1);
    }
  };
  const vscode = (scope: unknown): AutoRun[] => (isObj(scope) ? [...dottedKeys(scope, shown, whole), ...vscodeAutoTasks(scope, canon, text)] : []);
  /** A settings scope: its tasks section and the terminal settings tasks run with. */
  const settings = (scope: unknown, within?: string): AutoRun[] => [...settingsTasks(scope, canon, shown, within), ...taskTerminal(scope, canon, shown, within)];
  const runs = /tasks\.json$/i.test(rel)
    ? vscode(doc)
    : /\.vscode\/settings\.json$/i.test(rel)
      ? [...settings(doc), ...(/(^|\/)\.claude\//i.test(rel) ? claudeSettings(doc, canon, shown) : [])]
      : /\.code-workspace$/i.test(rel)
        ? [...dottedKeys(doc, shown, whole), ...vscode(doc.tasks), ...settings(doc.settings, "settings")]
        : /\.mcp\.json$/i.test(rel)
          ? mcpServers(doc, canon, shown)
          : PLUGIN_FILE.test(rel)
            ? [{ ruleId: "WS-PS-002" as const, what: "Claude Code plugin file under .claude/", when: LOADS_PLUGIN, id: canon(doc), command: () => shown(doc) }]
            : claudeSettings(doc, canon, shown);
  return report(rel, text, ctx, runs);
}

/** One high finding per entry, capped at MAX_LISTED and a summary. */
function report(rel: string, text: string, ctx: ScanContext, runs: AutoRun[]): Finding[] {
  const lineAt = lineIndex(text);
  const found = capped(MAX_LISTED);
  for (const r of runs) {
    found.add(`${r.what}:${keyDigest(r.id)}`, (key) => {
      const idx = r.anchor === undefined ? -1 : text.indexOf(JSON.stringify(r.anchor), r.within === undefined ? 0 : keyAt(text, r.within));
      const command = r.command();
      const head = command.slice(0, MAX_JUDGED);
      // The heuristics only add reasons to the message; the finding is high either way.
      const ioc = payloadName(head, ctx);
      const why = [...(r.note ? [r.note] : []), ...suspiciousReasons(head), ...(ioc ? [ioc.why] : [])];
      if (command.length > MAX_JUDGED) why.push(`runs more than ${MAX_JUDGED} characters of commands, and the rest were not checked`);
      return makeFinding({
        ruleId: r.ruleId,
        severity: "high",
        file: rel,
        key,
        ...(idx === -1 ? {} : { line: lineAt(idx) }),
        ...(ioc ? { source: ioc.source } : {}),
        message: `${r.what} ${r.when}${why.length > 0 ? `; it ${why.join("; ")}` : ""}: ${command.replace(/\s+/g, " ").trim().slice(0, MAX_SHOWN)}`,
      });
    });
  }
  return found.done((more, key) => makeFinding({ ruleId: runs[0]?.ruleId ?? "WS-PS-001", severity: "high", file: rel, key: `more:${key}`, message: `${more} more automatically run entries were not listed one by one` }));
}

/** Where `"key":` first occurs in the text, or 0: a nested key's anchor is searched from there. */
function keyAt(text: string, key: string): number {
  const m = new RegExp(`${JSON.stringify(key).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*:`).exec(text);
  return m ? m.index : 0;
}

/** Said before the strings of a value JSON.stringify cannot serialise. */
const TOO_DEEP = "(nested too deeply to show as JSON; its strings are:)";
/** Values queued, in all, when collecting a value's strings. */
const MAX_VISITED = 100_000;

/**
 * The string leaves of a value, breadth first so a string beside a deeply nested array is reached, each once, cut
 * just past MAX_JUDGED; iterative and bounded, for values too deep to serialise.
 */
function stringsOf(v: unknown): string {
  const queue = [v];
  const parts: string[] = [];
  let length = 0;
  for (let i = 0; i < queue.length && length <= MAX_JUDGED; i++) {
    const x = queue[i];
    if (typeof x === "string") {
      parts.push(x.slice(0, MAX_JUDGED + 1));
      length += x.length + 1;
    } else if (Array.isArray(x) || isObj(x)) {
      for (const child of Array.isArray(x) ? x : Object.values(x)) {
        if (queue.length >= MAX_VISITED) break;
        queue.push(child);
      }
    }
  }
  return joinHead(parts);
}

/** The parts, each once, one per line, cut just past MAX_JUDGED: one 1.8 MB command copied into every finding exhausted the heap. */
function joinHead(parts: string[]): string {
  const seen = new Set<string>();
  let text = "";
  for (const p of parts) {
    if (p === "" || seen.has(p)) continue;
    seen.add(p);
    text += (text === "" ? "" : "\n") + p.slice(0, MAX_JUDGED + 1);
    if (text.length > MAX_JUDGED) return text.slice(0, MAX_JUDGED + 1);
  }
  return text;
}

/**
 * VS Code splits a top-level key of a tasks file at its dots into nested
 * settings (toValuesTree in platform/configuration/common/configuration.ts), so
 * "linux.tasks" is a task list and "tasks.0.runOptions" edits the first task.
 * wormsign does not model that merge: each such key is high, fingerprinted over
 * the whole file.
 */
function dottedKeys(scope: Obj, shown: (v: unknown) => string, whole: string): AutoRun[] {
  return Object.keys(scope)
    .filter((k) => k.includes("."))
    .map((k) => ({ ruleId: "WS-PS-001" as const, what: `VS Code tasks key "${k.slice(0, 60)}"`, when: "is read as nested task settings, which may make a task run automatically, so the whole file is its fingerprint", id: whole, command: () => shown(scope[k]), anchor: k }));
}

/**
 * The "tasks" section of a folder's .vscode/settings.json or a workspace's "settings": VS Code deep-merges it into
 * the folder's task configuration, so any key in it (a task, or global options such as the shell or env every task
 * runs with) can make a task run or change how a baselined one runs. One high entry covers the whole section,
 * nested or written as dotted "tasks.*" keys, fingerprinted over all of it.
 */
function settingsTasks(settings: unknown, canon: (v: unknown) => string, shown: (v: unknown) => string, within?: string): AutoRun[] {
  if (!isObj(settings)) return [];
  const dotted = Object.keys(settings).filter((k) => k.startsWith("tasks."));
  if (settings.tasks === undefined && dotted.length === 0) return [];
  const section = { tasks: settings.tasks, ...Object.fromEntries(dotted.map((k) => [k, settings[k]])) };
  return [{ ruleId: "WS-PS-001", what: 'VS Code "tasks" settings', when: "are merged into the folder's task configuration, so they can make a task run automatically or change how one runs", id: canon(section), command: () => shown(section), anchor: settings.tasks !== undefined ? "tasks" : (dotted[0] as string), ...(within === undefined ? {} : { within }) }];
}

/**
 * The terminal settings a shell task runs with. VS Code starts a shell task with the profile
 * terminal.integrated.automationProfile.<os> names, or when that is unset with the default terminal profile
 * (terminal.integrated.defaultProfile.<os>, chosen from terminal.integrated.profiles.<os>), and adds
 * terminal.integrated.env.<os> to its environment (terminalTaskSystem.ts, terminalProfileResolverService.ts,
 * terminalEnvironment.ts). All are folder-scoped, restricted settings, so a repository's .vscode/settings.json or
 * workspace file sets them once the folder is trusted, which automatic tasks need anyway. A path or an env entry
 * such as NODE_OPTIONS there can retarget a reviewed, baselined task, so every such setting, as a dotted key or
 * nested under "terminal", is one high entry fingerprinted over all of them.
 */
const TASK_TERMINAL = /^terminal\.integrated\.(automationProfile|defaultProfile|profiles|env)\.(linux|osx|windows)(\.|$)/;
/** Levels of nesting under "terminal" followed to find those settings: terminal.integrated.env.linux is four. */
const MAX_TERMINAL_DEPTH = 4;

function taskTerminal(settings: unknown, canon: (v: unknown) => string, shown: (v: unknown) => string, within?: string): AutoRun[] {
  if (!isObj(settings)) return [];
  const reaches = (path: string, v: unknown, depth: number): boolean =>
    TASK_TERMINAL.test(path) || (depth < MAX_TERMINAL_DEPTH && isObj(v) && Object.keys(v).some((k) => reaches(`${path}.${k}`, v[k], depth + 1)));
  const keys = Object.keys(settings).filter((k) => (k === "terminal" || k.startsWith("terminal.")) && reaches(k, settings[k], 0));
  if (keys.length === 0) return [];
  const section = Object.fromEntries(keys.map((k) => [k, settings[k]]));
  return [{ ruleId: "WS-PS-001", what: "VS Code terminal settings for tasks", when: "pick the shell, profile or environment that tasks run with, so they can change what an automatic task runs", id: canon(section), command: () => shown(section), anchor: keys[0] as string, ...(within === undefined ? {} : { within }) }];
}

/**
 * What a skill, command or subagent file can make Claude Code run: hooks and,
 * for a subagent, inline MCP servers, declared in its YAML frontmatter. A
 * project skill's hooks register when Claude invokes it, even under claude -p
 * in an untrusted folder (code.claude.com/docs/en/permissions, "What runs
 * before you trust a folder"). wormsign does not parse YAML: the file is high
 * when the text up to its second line of exactly `---` (the whole file if there
 * is none, as with CRLF line breaks) mentions hooks or mcpServers in any case,
 * or holds a backslash, as a YAML escape can spell either name. That text is
 * the fingerprint.
 */
function frontmatterRuns(text: string): AutoRun[] {
  // Only a line of exactly ---, between \n line breaks: any parser that ends the frontmatter there ends it no earlier.
  const marks = /(?:^|\n)---(?=\n|$)/g;
  marks.exec(text);
  const head = marks.exec(text) ? text.slice(0, marks.lastIndex) : text;
  if (!/hooks|mcpservers|\\/i.test(head)) return [];
  return [{ ruleId: "WS-PS-002", what: "Claude Code skill, command or subagent file whose frontmatter may declare hooks or MCP servers", when: "registers them when Claude or you invoke it: a project skill's hooks even under claude -p in a folder never trusted, a subagent's once the folder is trusted", id: head, command: () => head.slice(0, MAX_JUDGED + 1) }];
}

/** VS Code reads runOn case-insensitively; worktreeCreated runs when an agent session worktree is created. */
const AUTO_RUN_ON = new Set(["folderopen", "worktreecreated"]);
/** Tasks followed through dependsOn per automatic task; real chains are short, a hostile file's may be 30,000 long. */
const MAX_DEPENDENCIES = 64;
/** dependsOn entries read per automatic task. */
const MAX_DEPENDENCY_ENTRIES = MAX_DEPENDENCIES * 16;

/**
 * Tasks VS Code runs on its own: runOptions.runOn folderOpen (or
 * worktreeCreated), in tasks or in the OS-specific windows/osx/linux.tasks
 * lists. A finding's key digests the task, the tasks it depends on and the
 * file's own settings (global command, options, inputs), so editing any of them
 * fails again. A dependsOn name reaches every task with that label, taskName or
 * identifier in any task list, which covers the one VS Code picks without
 * modelling how it picks. A name no task has, such as a task VS Code's npm
 * extension detects (`npm: dev`), is shown, and the key covers the whole file,
 * since a task VS Code labels for itself may be the one it reaches.
 */
function vscodeAutoTasks(doc: Obj, canon: (v: unknown) => string, text: string): AutoRun[] {
  const scopes = [doc, doc.windows, doc.osx, doc.linux].filter(isObj);
  const tasks = scopes.flatMap((s) => (Array.isArray(s.tasks) ? s.tasks.filter(isObj) : []));
  const byName = new Map<string, Obj[]>();
  for (const t of tasks) {
    for (const name of new Set([t.label, t.identifier, t.taskName])) {
      if (typeof name !== "string") continue;
      const same = byName.get(name);
      if (same) same.push(t);
      else byName.set(name, [t]);
    }
  }
  const globalId = keyDigest(canon(scopes.map((s) => ({ ...s, tasks: undefined, windows: undefined, osx: undefined, linux: undefined }))));
  const globalCommands = scopes.map(commandOf);
  // Each task is digested once, so keys cost linear time however the tasks depend on each other.
  const ids = new Map<Obj, string>();
  const idOf = (t: Obj): string => ids.get(t) ?? (ids.set(t, keyDigest(canon(t))).get(t) as string);
  let fileId: string | undefined;
  const out: AutoRun[] = [];
  for (const t of tasks) {
    const runOn = isObj(t.runOptions) ? t.runOptions.runOn : undefined;
    if (typeof runOn !== "string" || !AUTO_RUN_ON.has(runOn.toLowerCase())) continue;
    const label = [t.label, t.taskName, t.script].find((x): x is string => typeof x === "string");
    const { closure, unresolved, complete } = dependencyClosure(t, byName);
    out.push({
      ruleId: "WS-PS-001",
      what: `VS Code task "${(label ?? "(unlabelled)").slice(0, 60)}"`,
      when: `runs automatically (runOn ${runOn}) once the workspace is trusted and automatic tasks are allowed`,
      // A walk cut short or a name no task has leaves dependencies out of the key, so the whole file stands in for them.
      id: complete && unresolved.length === 0 ? [globalId, ...closure.map(idOf)].join("\0") : (fileId ??= keyDigest(text)),
      command: () => joinHead([...closure.map(taskCommand), ...globalCommands, ...unresolved.map((d) => `(and the task ${d.slice(0, 60)})`)]),
      anchor: label ?? runOn,
      ...(complete ? {} : { note: `depends on more than ${MAX_DEPENDENCIES} tasks or ${MAX_DEPENDENCY_ENTRIES} dependsOn entries; those past the limit are not shown, and its fingerprint covers the whole file` }),
    });
  }
  return out;
}

/**
 * The task and every task its dependsOn names reach, transitively, and the
 * names no task has. Bounded in tasks and in dependsOn entries read, so a
 * hostile file cannot make each automatic task walk all others; `complete` is
 * false when a bound cut the walk short.
 */
function dependencyClosure(task: Obj, byName: Map<string, Obj[]>): { closure: Obj[]; unresolved: string[]; complete: boolean } {
  const closure = [task];
  const seen = new Set(closure);
  const unresolved = new Set<string>();
  let budget = MAX_DEPENDENCY_ENTRIES;
  for (let i = 0; i < closure.length; i++) {
    const deps = (closure[i] as Obj).dependsOn;
    for (const d of Array.isArray(deps) ? deps : deps === undefined ? [] : [deps]) {
      if (--budget < 0) return { closure, unresolved: [...unresolved], complete: false };
      // An object names a detected task by its fields (VS Code's { type: "npm", script }), never by a label.
      const named = typeof d === "string" ? byName.get(d) : undefined;
      if (!named) {
        if (unresolved.size < 8) unresolved.add(typeof d === "string" ? d : isObj(d) && typeof d.type === "string" && typeof d.script === "string" ? `${d.type}: ${d.script}` : "named by an identifier object");
        continue;
      }
      for (const next of named) {
        if (seen.has(next)) continue;
        if (closure.length >= MAX_DEPENDENCIES) return { closure, unresolved: [...unresolved], complete: false };
        closure.push(next);
        seen.add(next);
      }
    }
  }
  return { closure, unresolved: [...unresolved], complete: true };
}

/** A task's command: its own, each OS-specific one, and an npm task's script. */
function taskCommand(t: Obj): string {
  const parts = [t, t.windows, t.osx, t.linux].filter(isObj).map(commandOf);
  if (t.type === "npm" && typeof t.script === "string") parts.push(`npm run ${t.script}`);
  return parts.filter((c) => c !== "").join("\n");
}

/** command and args as one line, then the shell VS Code runs it with (options.shell executable and args). */
function commandOf(scope: Obj): string {
  const options = isObj(scope.options) ? scope.options : {};
  const shell = isObj(options.shell) ? options.shell : {};
  const lines = [[...words(scope.command), ...words(scope.args)], [...words(shell.executable), ...words(shell.args)]];
  return lines.map((l) => l.join(" ")).filter((l) => l !== "").join("\n");
}

/** The strings of a command or args value: a string, an array, or { value, quoting }. */
function words(v: unknown, depth = 0): string[] {
  if (typeof v === "string") return [v];
  if (depth > 4) return [];
  if (Array.isArray(v)) return v.flatMap((w) => words(w, depth + 1));
  return isObj(v) ? words(v.value, depth + 1) : [];
}

/** What to show for an entry: its command and args, an MCP server's headersHelper, else the entry as JSON (an HTTP hook's url, a prompt hook). */
function describe(v: unknown, shown: (v: unknown) => string): string {
  if (typeof v === "string") return v;
  if (isObj(v) && typeof v.command === "string") return [v.command, ...words(v.args)].join(" ");
  if (isObj(v) && typeof v.headersHelper === "string") return v.headersHelper;
  return shown(v);
}

/** A string field to find the entry's line by. */
const anchorOf = (v: unknown): string | undefined => (typeof v === "string" ? v : isObj(v) ? [v.command, v.headersHelper, v.url, v.prompt].find((x): x is string => typeof x === "string") : undefined);

/** Claude Code settings whose value is a command it runs (code.claude.com/docs/en/settings-reference). */
const COMMAND_SETTINGS = ["apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "gcpAuthRefresh", "otelHeadersHelper", "statusLine", "subagentStatusLine", "fileSuggestion", "processWrapper"];
/**
 * Claude Code env settings that only pick a model, a limit or a timeout, or turn
 * telemetry off (code.claude.com/docs/en/env-vars). Exact names: some
 * CLAUDE_CODE_DISABLE_* settings turn safety checks off, and any other variable
 * reaches every command a session runs, where NODE_OPTIONS, PATH, BASH_ENV,
 * GIT_EXTERNAL_DIFF and many more make programs load code from the repository.
 */
const INERT_ENV = new Set([
  "ANTHROPIC_MODEL",
  "ANTHROPIC_DEFAULT_MODEL",
  "ANTHROPIC_DEFAULT_OPUS_MODEL",
  "ANTHROPIC_DEFAULT_SONNET_MODEL",
  "ANTHROPIC_DEFAULT_HAIKU_MODEL",
  "ANTHROPIC_SMALL_FAST_MODEL",
  "CLAUDE_CODE_EFFORT_LEVEL",
  "CLAUDE_CODE_MAX_OUTPUT_TOKENS",
  "BASH_MAX_OUTPUT_LENGTH",
  "BASH_DEFAULT_TIMEOUT_MS",
  "BASH_MAX_TIMEOUT_MS",
  "API_TIMEOUT_MS",
  "MCP_TIMEOUT",
  "DISABLE_TELEMETRY",
  "DISABLE_ERROR_REPORTING",
  "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
  "CLAUDE_CODE_DISABLE_TERMINAL_TITLE",
]);
const WHEN_CLAUDE = "automatically in sessions in this repository: at once under claude -p or the SDK, after the trust prompt in an interactive session";
const LOADS_PLUGIN = "loads a plugin whose hooks and MCP and LSP servers run in sessions in this repository once the folder is trusted";

/**
 * What a Claude Code settings file makes run: every hook, of any event and
 * type (a command, an HTTP hook that receives the event's data, a prompt or an
 * MCP tool call), every setting that runs a helper command, and every env
 * entry outside INERT_ENV, since env reaches every command a session starts
 * (code.claude.com/docs/en/hooks, settings-reference, env-vars); and every
 * plugin it enables and marketplace it adds, as a plugin's hooks run like the
 * file's own (code.claude.com/docs/en/plugins/org, "Require plugins per
 * repository"; additionalMarketplaces is an alias of extraKnownMarketplaces).
 */
function claudeSettings(doc: Obj, canon: (v: unknown) => string, shown: (v: unknown) => string): AutoRun[] {
  const out: AutoRun[] = [];
  const add = (what: string, when: string, v: unknown): void =>
    void out.push({ ruleId: "WS-PS-002", what, when, id: canon(v), command: () => describe(v, shown).slice(0, MAX_JUDGED + 1), anchor: anchorOf(v) });
  for (const [event, groups] of entries(doc.hooks, "(hooks)")) {
    const handlers = Array.isArray(groups) ? groups.flatMap((g) => (isObj(g) && Array.isArray(g.hooks) ? g.hooks : [g])) : [groups];
    for (const h of handlers) add(`Claude Code ${event.slice(0, 60)} hook`, `runs ${WHEN_CLAUDE}`, h);
  }
  for (const key of COMMAND_SETTINGS) if (doc[key] !== undefined) add(`Claude Code ${key} setting`, `runs ${WHEN_CLAUDE}`, doc[key]);
  for (const [name, value] of entries(doc.env, "(env)")) {
    if (INERT_ENV.has(name)) continue;
    out.push({ ruleId: "WS-PS-002", what: `Claude Code env setting ${name.slice(0, 60)}`, when: `applies to every command run ${WHEN_CLAUDE}`, id: canon([name, value]), command: () => `${name}=${typeof value === "string" ? value : shown(value)}`.slice(0, MAX_JUDGED + 1), anchor: name, note: "can change how commands or code load" });
  }
  const plugin = (what: string, name: string, value: unknown): void =>
    void out.push({ ruleId: "WS-PS-002", what: `Claude Code ${what} ${name.slice(0, 60)}`, when: LOADS_PLUGIN, id: canon([name, value]), command: () => `${name}=${shown(value)}`.slice(0, MAX_JUDGED + 1), anchor: name });
  for (const [name, on] of entries(doc.enabledPlugins, "(enabledPlugins)")) if (on !== false) plugin("plugin", name, on);
  for (const key of ["extraKnownMarketplaces", "additionalMarketplaces"]) for (const [name, m] of entries(doc[key], `(${key})`)) plugin("marketplace", name, m);
  return out;
}

/**
 * The servers of a project .mcp.json that run something on this machine: a
 * local command, which Claude Code starts in sessions in the project, or an
 * HTTP server's headersHelper, a shell command it runs on each connection
 * (code.claude.com/docs/en/mcp). Only a server with a url and neither is left
 * out; any other shape is reported.
 */
function mcpServers(doc: Obj, canon: (v: unknown) => string, shown: (v: unknown) => string): AutoRun[] {
  const out: AutoRun[] = [];
  for (const [name, s] of entries(doc.mcpServers, "(mcpServers)")) {
    if (isObj(s) && typeof s.url === "string" && s.command === undefined && s.headersHelper === undefined) continue;
    out.push({
      ruleId: "WS-PS-002",
      what: `Claude Code MCP server "${name.slice(0, 60)}"`,
      when: "starts in sessions in this repository: at once under claude -p or the SDK, once approved in an interactive session (enableAllProjectMcpServers or enabledMcpjsonServers approve it in advance)",
      id: canon(s),
      command: () => describe(s, shown).slice(0, MAX_JUDGED + 1),
      anchor: anchorOf(s),
    });
  }
  return out;
}

/** Script file extensions; a hash IOC with one of these names a payload rather than a config file. */
const SCRIPT_FILE = /\.(m?js|cjs|ts|mts|cts|sh|bash|zsh|ps1|py|rb|pl|cmd|bat)$/i;

/** A payload file name from the IOC list that the text runs or loads. */
function payloadName(cmd: string, ctx: ScanContext): { why: string; source: string } | undefined {
  const ran = new Set(executedFiles(cmd).map((p) => p.split("/").pop() as string));
  // Hash IOCs also name config files (tasks.json, settings.json) that a command may only read, so only their script names count.
  const ioc = [...ctx.iocs.names, ...ctx.iocs.hashes.filter((h) => SCRIPT_FILE.test(h.name))].find((n) => ran.has(n.name));
  return ioc && { why: `runs ${ioc.name}, a payload file name reported for the ${ioc.wave} wave`, source: ioc.source };
}

/** What parseJsonc returns for a document with a "__proto__" key, which it cannot read as VS Code does. */
export const PROTO_KEY: unique symbol = Symbol("__proto__ key");

/**
 * JSON as VS Code reads it: comments and trailing commas allowed (VS Code's
 * configuration parser, base/common/json.ts, defaults to both). Undefined when
 * the text still does not parse; VS Code would read what it could of it, so the
 * caller fails closed. Linear: strings are skipped by a scan, not a regex.
 *
 * PROTO_KEY when an object in it has a "__proto__" key (escaped or not). VS Code's parser stores each value with
 * `parent[key] = value`, which for "__proto__" sets the object's prototype, and its readers see inherited keys: with
 * jsonc-parser 3.3.1 (the same parser, shipped in VS Code-based editors), `{"__proto__": {"tasks": [...]}}` has no
 * own keys, yet `.tasks` is the list and `for...in` yields it. JSON.parse makes it an ordinary own key, so the tasks
 * under it would be invisible here; the caller fails closed instead.
 */
export function parseJsonc(text: string): unknown {
  let doc: unknown;
  try {
    doc = JSON.parse(dropTrailingCommas(dropComments(text)));
  } catch {
    return undefined;
  }
  return hasProtoKey(doc) ? PROTO_KEY : doc;
}

/** True when an object in the value has an own "__proto__" key. Iterative, since a value can be nested 200,000 deep. */
function hasProtoKey(value: unknown): boolean {
  const todo: unknown[] = [value];
  while (todo.length > 0) {
    const v = todo.pop();
    if (v === null || typeof v !== "object") continue;
    if (Object.hasOwn(v, "__proto__")) return true;
    for (const c of Object.values(v)) todo.push(c);
  }
  return false;
}

/** Index just past the string literal that starts at `i` (a `"`), or the text length if it never ends. */
function skipString(text: string, i: number): number {
  for (i++; i < text.length; i++) {
    if (text[i] === "\\") i++;
    else if (text[i] === '"') return i + 1;
  }
  return text.length;
}

/** What ends a line comment for VS Code (json.ts isLineBreak); JSON.parse takes only the first two as whitespace. */
const LINE_BREAK = /[\n\r\u2028\u2029]/g;

function dropComments(text: string): string {
  let out = "";
  let from = 0;
  for (let i = 0; i < text.length; ) {
    if (text[i] === '"') i = skipString(text, i);
    else if (text.startsWith("//", i)) {
      LINE_BREAK.lastIndex = i + 2;
      const end = LINE_BREAK.exec(text)?.index ?? text.length;
      out += `${text.slice(from, i)} `;
      i = from = Math.min(end + 1, text.length);
    } else if (text.startsWith("/*", i)) {
      const end = text.indexOf("*/", i + 2);
      if (end === -1) return text; // unterminated: let JSON.parse fail
      out += `${text.slice(from, i)} `;
      i = from = end + 2;
    } else i++;
  }
  return out + text.slice(from);
}

function dropTrailingCommas(text: string): string {
  let out = "";
  let from = 0;
  for (let i = 0; i < text.length; ) {
    if (text[i] === '"') i = skipString(text, i);
    else if (text[i] === ",") {
      let j = i + 1;
      while (j < text.length && /\s/.test(text[j] as string)) j++;
      if (text[j] === "}" || text[j] === "]") {
        out += text.slice(from, i);
        from = i + 1;
      }
      i = j;
    } else i++;
  }
  return out + text.slice(from);
}
