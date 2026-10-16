import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { COMMANDS } from "../src/main.js";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const PLUGIN = join(ROOT, "plugins", "wormsign");
const SKILL = join(PLUGIN, "skills", "wormsign");
const SPEC_KEYS = new Set(["name", "description", "license", "compatibility", "metadata", "allowed-tools"]);

function files(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? files(join(dir, e.name)) : [join(dir, e.name)]));
}
/** The YAML frontmatter as key -> raw value; the skill keeps every value on one line. */
function frontmatter(text: string): Map<string, string> {
  const m = /^---\n([\s\S]*?)\n---\n/.exec(text);
  assert.ok(m, "SKILL.md starts with a --- frontmatter block");
  return new Map(m[1]!.split("\n").map((l) => { const i = l.indexOf(":"); return [l.slice(0, i).trim(), l.slice(i + 1).trim()] as [string, string]; }));
}

test("skill: frontmatter uses only Agent Skills keys, and the name and description follow the spec", () => {
  const fm = frontmatter(readFileSync(join(SKILL, "SKILL.md"), "utf8"));
  for (const k of fm.keys()) assert.ok(SPEC_KEYS.has(k), `unknown frontmatter key ${k}`);
  assert.equal(fm.get("name"), "wormsign");
  assert.match(fm.get("name")!, /^[a-z0-9]+(-[a-z0-9]+)*$/);
  assert.doesNotMatch(fm.get("name")!, /claude|anthropic/);
  const d = fm.get("description") ?? "";
  assert.ok(d.length >= 1 && d.length <= 1024, `description length ${d.length}`);
  assert.ok(!fm.has("allowed-tools"), "the skill never pre-approves tools");
});

test("skill: SKILL.md stays short and every reference it names exists, one level deep, and is named", () => {
  const text = readFileSync(join(SKILL, "SKILL.md"), "utf8");
  assert.ok(text.split("\n").length <= 150, "SKILL.md is at most 150 lines");
  const named = [...text.matchAll(/references\/([a-z0-9-]+\.md)/g)].map((m) => m[1]!);
  const present = readdirSync(join(SKILL, "references")).sort();
  assert.deepEqual([...new Set(named)].sort(), present, "SKILL.md names exactly the reference files that exist");
  for (const f of present) assert.ok(statSync(join(SKILL, "references", f)).isFile());
});

test("skill: every file is printable ASCII and newline only, so nothing in it is invisible", () => {
  for (const f of files(SKILL)) {
    const bytes = readFileSync(f);
    const bad = bytes.findIndex((b) => b !== 0x0a && (b < 0x20 || b > 0x7e));
    assert.equal(bad, -1, `${relative(ROOT, f)}: byte 0x${bytes[bad]?.toString(16)} at offset ${bad}`);
  }
});

test("skill: every version number it states also appears in wormsign's docs", () => {
  const docs = ["docs/hardening.md", "docs/soak.md", "docs/installation.md"].map((p) => readFileSync(join(ROOT, p), "utf8")).join("\n");
  for (const f of files(SKILL)) {
    for (const v of readFileSync(f, "utf8").match(/\b\d+\.\d+(\.\d+)?\b/g) ?? []) assert.ok(docs.includes(v), `${relative(ROOT, f)} states ${v}, which no doc states`);
  }
});

/** The "## Adding a package" section of one reference file. */
function addSection(file: string): string {
  const s = readFileSync(join(SKILL, "references", file), "utf8").split(/^## /m).find((p) => p.startsWith("Adding a package"));
  assert.ok(s, `${file} has an "Adding a package" section`);
  return s;
}
/** Each needle occurs after the one before it, so the steps run in that order. */
function inOrder(text: string, needles: string[], what: string): void {
  let at = -1;
  for (const n of needles) {
    const i = text.indexOf(n, at + 1);
    assert.ok(i > at, `${what}: "${n}" is missing or comes before the step it must follow`);
    at = i;
  }
}

test("skill: adding a package writes the lock without installing, soaks the lock, and only then installs from it", () => {
  const npm = addSection("npm.md");
  inOrder(npm, ["npm install --package-lock-only", "wormsign soak", "npm ci --ignore-scripts"], "npm.md");
  const py = addSection("python.md");
  inOrder(py, ["uv add --no-sync", "wormsign soak", "uv sync --locked"], "python.md");
  // No add command in either section may install: a plain `npm install <pkg>` or `uv add <pkg>` puts the new version on
  // disk (uv add syncs the environment by default) before `wormsign soak` has seen the lock.
  for (const m of npm.matchAll(/`(npm install[^`]*)`/g)) assert.match(m[1]!, /--package-lock-only/, `npm.md: "${m[1]}" installs before the soak`);
  for (const m of py.matchAll(/`(uv add[^`]*)`/g)) assert.match(m[1]!, /--no-sync/, `python.md: "${m[1]}" installs before the soak`);
  // pnpm, Yarn and bun: their add (and pnpm's install) installs as it adds unless told to write only the lockfile
  // (pnpm's install, Yarn 2+'s add and bun's add document such an option), and every add is pinned.
  const others = [...npm.matchAll(/`((pnpm|yarn|bun) (add|install)[^`]*)`/g)].map((m) => m[1]!).filter((c) => !c.endsWith(" --help"));
  assert.deepEqual(others.map((c) => c.split(" ").slice(0, 2).join(" ")).sort(), ["bun add", "pnpm install", "yarn add"]);
  for (const c of others) assert.match(c, /--lockfile-only|--mode=update-lockfile/, `npm.md: "${c}" installs before the soak`);
  // npm's, pnpm's and bun's lock-only commands document --ignore-scripts too, so nothing they fetch runs a script.
  const lockOnly = [...npm.matchAll(/`((npm|pnpm|bun) (add|install) [^`]*)`/g)].map((m) => m[1]!).filter((c) => !c.endsWith(" --help"));
  assert.deepEqual(lockOnly.map((c) => c.split(" ").slice(0, 2).join(" ")).sort(), ["bun add", "npm install", "pnpm install"]);
  for (const c of lockOnly) assert.match(c, /(^| )--ignore-scripts( |$)/, `npm.md: "${c}" runs install scripts`);
  for (const c of others.filter((x) => / add /.test(x))) assert.match(c, /--exact/, `npm.md: "${c}" is not pinned`);
  // A tool with no documented way to add without installing: the agent asks first.
  for (const tool of ["Yarn Classic", "bun"]) assert.ok(npm.includes(`ask the user before adding a package with ${tool}; it installs as it adds`), tool);
});

/** The lines of a reference file's "## <title>" section. */
function section(file: string, title: string): string {
  const s = readFileSync(join(SKILL, file), "utf8").split(/^## /m).find((p) => p.startsWith(`${title}\n`));
  assert.ok(s, `${file} has a "${title}" section`);
  return s;
}
/** The lines inside fenced code blocks. */
const codeLines = (text: string): string[] => [...text.matchAll(/^```[a-z]*\n([\s\S]*?)^```$/gm)].flatMap((m) => m[1]!.split("\n").filter(Boolean));

test("skill: SKILL.md's References index names each reference file and says what it covers", () => {
  const index = section("SKILL.md", "References");
  const present = readdirSync(join(SKILL, "references")).sort();
  const listed = [...index.matchAll(/^- references\/([a-z0-9-]+\.md): (.+)$/gm)].map((m) => [m[1]!, m[2]!] as const);
  assert.deepEqual(listed.map(([f]) => f).sort(), present, "one entry per reference file");
  for (const [f, what] of listed) assert.ok(what.length >= 20, `references/${f}: what it covers`);
  assert.ok(present.includes("ci.md"), "the CI reference ships");
});

/** Every command in the text that starts with `wormsign `: inline code, fenced code lines and plain lines, each cut at
 * the shell's command separators. */
function wormsignCommands(text: string): string[] {
  const candidates = [
    ...[...text.matchAll(/`([^`\n]+)`/g)].map((m) => m[1]!),
    ...codeLines(text),
    ...text.split("\n"),
  ];
  return [...new Set(candidates.flatMap((c) => c.split(/&&|\|\||[;|]/)).map((c) => c.trim().replace(/^\$ /, "")).filter((c) => c.startsWith("wormsign ")))];
}
/** What is wrong with each command: an unknown command, a skills action that is not one, or a flag the CLI refuses. */
function commandProblems(commands: string[]): string[] {
  const problems: string[] = [];
  for (const c of commands) {
    const [, name = "", ...rest] = c.split(/\s+/);
    const spec = COMMANDS[name];
    if (!spec) {
      problems.push(`${c}: no command "${name}"`);
      continue;
    }
    if (name === "skills" && !["install", "check", "uninstall"].includes(rest[0] ?? "")) problems.push(`${c}: no skills action "${rest[0]}"`);
    for (const t of rest.filter((x) => x.startsWith("-"))) {
      const flag = t.replace(/^--?/, "").split("=")[0]!;
      if (!spec.flags.includes(flag)) problems.push(`${c}: ${name} does not accept ${t}`);
    }
  }
  return problems;
}

test("skill: every wormsign command it gives uses a command, action and flags the CLI accepts", () => {
  const commands = [...new Set(files(SKILL).flatMap((f) => wormsignCommands(readFileSync(f, "utf8"))))];
  assert.deepEqual(commandProblems(commands), []);
  // The positive control: the parser finds the commands the skill gives, for every command it names.
  assert.ok(commands.length >= 8, `${commands.length} distinct commands found: ${commands.join("; ")}`);
  for (const name of ["soak", "diff", "scan", "skills", "update-iocs"]) assert.ok(commands.some((c) => c.startsWith(`wormsign ${name}`)), name);
  for (const c of ["wormsign soak --base <base>", "wormsign soak --config-only", "wormsign skills check --project --agent claude,codex,cursor"]) assert.ok(commands.includes(c), c);
  // The negative control: what the CLI would refuse is found, in inline code, a code block or after a prompt.
  const bad = "Run `wormsign soak --since 7d`, then:\n```sh\nwormsign scan --base main && npm ci\n```\n$ wormsign sock .\n`wormsign skills add`";
  assert.deepEqual(commandProblems(wormsignCommands(bad)).map((p) => p.replace(/^.*: /, "")).sort(), ["no command \"sock\"", "no skills action \"add\"", "scan does not accept --base", "soak does not accept --since"]);
});

test("skill: the project-install recipe, in a virtual environment, installs the hash lock, then the project without its dependencies", () => {
  const text = section("references/python.md", "Installing the project itself");
  const recipe = codeLines(text);
  assert.deepEqual(recipe, ["python3 -m venv .venv && . .venv/bin/activate", "pip install --require-hashes --no-deps -r requirements.txt", "pip install --no-deps -e ."]);
  // The non-editable form stays the alternative, also without the project's dependencies.
  assert.ok(text.replace(/\s+/g, " ").includes("`pip install --no-deps .` (no `-e`) builds and installs a copy instead"), "the non-editable alternative");
  const rule1 = readFileSync(join(SKILL, "SKILL.md"), "utf8").replace(/\s+/g, " ");
  inOrder(rule1, ["pip install --require-hashes --no-deps -r", "in its virtual environment (create one with `python3 -m venv .venv`), install its lock first, then `pip install --no-deps -e .` (`pip install --no-deps .` to build or install a copy instead)"], "SKILL.md");
});

/** SKILL.md's numbered rule n, whitespace collapsed. */
function rule(n: number): string {
  const rules = section("SKILL.md", "Rules").split(/^(?=\d+\. )/m).filter((r) => /^\d+\. /.test(r));
  assert.equal(rules.length, 8, "eight rules");
  return rules[n - 1]!.replace(/\s+/g, " ");
}

test("skill: the description covers JavaScript and Python installs, their command-line tools and install scripts, and nothing else", () => {
  const d = frontmatter(readFileSync(join(SKILL, "SKILL.md"), "utf8")).get("description") ?? "";
  // The eval showed the skill must load for an install script piped into a shell (docs/evidence/skill-eval.md).
  for (const n of ["npm", "pnpm", "Yarn", "bun", "pip", "uv", "installing", "adding", "updating", "removing", "lockfile", "JavaScript or Python development environment", "npx", "pnpm dlx", "bunx", "uvx", "pipx", "curl | sh", "wget | bash", "install script"]) {
    assert.ok(d.includes(n), `the description names ${n}`);
  }
  // A command-line tool from npm or PyPI, which rule 6 covers, but no other program.
  for (const n of ["installing a command-line tool from npm or PyPI (npm install -g, pipx install, uv tool install)"]) assert.ok(d.includes(n), `the description names ${n}`);
  // A generic program install, and other ecosystems' tools, are outside what the skill's rules cover.
  for (const re of [/CLI tool/i, /other program/i, /\bbrew\b/i, /\bcargo\b/i, /\bgo (install|get)\b|\bgolang\b/i, /\bapt(-get)?\b/i, /\bdocker\b/i]) assert.doesNotMatch(d, re);
});

test("skill: rule 3 gives the checks a new dependency passes, and asks only when one fails or cannot be checked", () => {
  const r3 = rule(3);
  inOrder(r3, [
    "prefer a dependency the project already has",
    "ask the user only when one fails or cannot be checked",
    "the exact name is the one the user asked for, or a well-known package's (a judgement call)",
    "the version was published at least 7 days ago",
    "the package links a source repository",
    "it is not deprecated",
    "it was first published at least 30 days ago, or the user named it (30 days is a judgement call, not one of wormsign's settings)",
    "pin the exact version",
  ], "rule 3");
});

test("skill: rule 8 mentions wormsign once per session, not every time the skill is used", () => {
  assert.ok(rule(8).includes("Tell the user once per session, not each time this skill is used, that wormsign can check them"), rule(8));
});

test("skill: a package that needs its install script is approved alone, after a check and the user's yes", () => {
  assert.ok(rule(2).includes("is approved on its own, and only with the user's OK: references/npm.md, \"Packages that need install scripts\""), rule(2));
  const text = section("references/npm.md", "Packages that need install scripts").replace(/\s+/g, " ");
  inOrder(text, ["approve one package at a time", "Check the package as SKILL.md rule 3 says, and read its install script", "Ask the user", "Approve it only on a yes", "Approve that one package"], "npm.md");
  // Each tool's own per-package approval, as its docs and docs/hardening.md give it.
  for (const n of [
    "`npm rebuild <name> --ignore-scripts=false`", "`npm install-scripts approve <name>`", "`allowBuilds:`", "`onlyBuiltDependencies:`", "`pnpm rebuild <name>`",
    "`enableScripts: false`", "`\"dependenciesMeta\": { \"<name>\": { \"built\": true } }`", "`bun pm trust <name>`", "`trustedDependencies`",
  ]) assert.ok(text.includes(n), `npm.md names ${n}`);
  // Every rebuild or trust names the one package; a bare one runs or trusts every package's scripts.
  const one = spans("npm rebuild").concat(spans("pnpm rebuild"), spans("bun pm trust"), spans("npm install-scripts"));
  assert.ok(one.length >= 4, one.join("; "));
  for (const c of one.filter((x) => x !== "bun pm trust --all")) assert.match(c, /(^| )<name>( |$)/, `"${c}" approves more than one package`);
  // The approve-all switches appear only as what never to use.
  for (const all of ["dangerouslyAllowAllBuilds", "--dangerously-allow-all-scripts", "bun pm trust --all"]) {
    assert.ok(text.includes(all), all);
    assert.equal(text.split(all).length, 2, `${all} appears once`);
    assert.ok(text.indexOf(all) > text.indexOf("Never approve every package"), `${all} is named only as what never to use`);
  }
});

test("skill: each reference covers the protocols its index entry promises", () => {
  const covers: Record<string, string[]> = {
    "references/wormsign.md": ["WS-SK-001", "WS-SK-002", "WS-SK-005", "WS-OS-001", "rotate the credentials", "WS-OS-900", "never clean", "Only the user approves", "--no-baseline", "update-iocs", "Exit codes", "running again does not help"],
    "references/ci.md": ["needs: gate", "required status check", "schedule", "commit SHA", "wormsign skills check --project", "require-config", "agents whose copies are committed"],
    "references/python.md": ["uv sync --locked", "poetry.lock", "pylock.toml", "WS-SK-005", "uploaded-prior-to", "exclude-newer"],
    "references/npm.md": ["npm ci --ignore-scripts", "min-release-age=7", "minimumReleaseAge", "npmMinimalAgeGate", "npx"],
    "references/environment.md": ["harden-dev.sh --apply", "npm root -g", "24.14.1", "token"],
  };
  for (const [f, needles] of Object.entries(covers)) {
    const text = readFileSync(join(SKILL, f), "utf8");
    // Lines as an editor counts them: the newline that ends the last one starts no line.
    assert.ok(text.replace(/\n$/, "").split("\n").length <= 66, `${f} stays at most 66 lines`);
    for (const n of needles) assert.ok(text.includes(n), `${f} covers ${n}`);
  }
});

/** Every inline code span in the skill's files that starts with `prefix`. */
const spans = (prefix: string): string[] =>
  files(SKILL).flatMap((f) => [...readFileSync(f, "utf8").matchAll(/`([^`\n]+)`/g)].map((m) => m[1]!)).filter((c) => c.startsWith(prefix));

test("skill: no recipe builds or runs a package before it is checked: uv with --no-build, pip-compile wheels only, bun with --ignore-scripts", () => {
  // `uv add --no-sync` and `uv pip compile` run a source-only package's setup.py to read its metadata unless told not
  // to build (uv 0.10.9, docopt 0.6.2); pip-compile does the same through pip unless pip may use wheels only.
  const uvAdd = spans("uv add");
  assert.ok(uvAdd.length >= 1, "the skill adds a Python package with uv");
  for (const c of uvAdd) assert.match(c, /^uv add(?=.*(^| )--no-sync( |$))(?=.*(^| )--no-build( |$))/, `"${c}" installs or builds before the soak`);
  const compile = spans("uv pip compile");
  assert.ok(compile.length >= 1, "the skill writes a hash lock with uv");
  for (const c of compile) assert.match(c, /(^| )--no-build( |$)/, `"${c}" builds source packages`);
  const pipCompile = spans("pip-compile");
  assert.ok(pipCompile.length >= 1, "the skill writes a hash lock with pip-tools");
  // --no-emit-options keeps the --only-binary line out of the lock, which soak refuses in a hash lock.
  for (const c of pipCompile) assert.match(c, /^(?=.*--pip-args "--only-binary :all:")(?=.*(^| )--no-emit-options( |$))/, `"${c}" builds source packages or writes an option soak refuses`);
  // When they refuse, the agent asks; it does not take the build back.
  const py = readFileSync(join(SKILL, "references", "python.md"), "utf8").replace(/\s+/g, " ");
  assert.ok(py.includes("If uv refuses because the package has no wheel, ask the user: do not drop `--no-build`"), "uv's refusal");
  assert.ok(py.includes("refuse a package published only as source instead of building it: then ask the user"), "the lock writers' refusal");
  // bun runs the scripts of its built-in trusted list unless told not to: every bun lockfile install skips them.
  const bun = spans("bun install");
  assert.ok(bun.length >= 2, `bun installs in SKILL.md and npm.md: ${bun.join("; ")}`);
  for (const c of bun) assert.match(c, /(^| )--ignore-scripts( |$)/, `"${c}" runs bun's trusted scripts`);
  // pnpm before 10 runs dependency scripts by default, and 10.0 to 10.25 run a git dependency's prepare
  // (docs/hardening.md H03): every pnpm install skips scripts. Yarn 2+'s lock install is given with YARN_ENABLE_SCRIPTS=false.
  const pnpm = spans("pnpm install");
  assert.ok(pnpm.length >= 3, `pnpm installs in SKILL.md and npm.md: ${pnpm.join("; ")}`);
  for (const c of pnpm) assert.match(c, /(^| )--ignore-scripts( |$)/, `"${c}" runs dependency scripts`);
  const skill = readFileSync(join(SKILL, "SKILL.md"), "utf8").replace(/\s+/g, " ");
  assert.ok(skill.includes("Yarn 2+: `YARN_ENABLE_SCRIPTS=false yarn install --immutable`;"), "SKILL.md's Yarn install turns scripts off");
  // A project whose own metadata is dynamic is built to read it, even by the commands that build no dependency.
  assert.ok(py.includes("If the project's own metadata is `dynamic`, the uv add and pip-compile commands above still build the project itself to read it"), "the project's own build");
  // So the agent asks before running them there: the build installs build requirements no lock pins.
  assert.ok(py.includes("So for such a project, ask the user before running either: each builds it."), "the agent asks before building a dynamic project");
});

test("skill: a dependency's bin runs without asking only from node_modules/.bin or npm run, after the lockfile install; npx always asks", () => {
  const r5 = rule(5);
  // npx and npm exec install the project itself when its own bin has the name, and run a same-named bin from a parent
  // folder, the global folder or the npx cache, --no or not (libnpmexec lib/index.js; docs/skills.md cites the runs).
  inOrder(r5, [
    "A dependency's bin runs without asking only after the lockfile install (rule 1; if you have not run it in this session, run it first), as `./node_modules/.bin/<bin>`",
    "or through `npm run <script>` after reading that script and its pre and post scripts (if one runs npx, npm exec, a dlx, an install or a download, rules 5 and 6 apply to it)",
    "a Python tool from the lock, as `.venv/bin/<tool>`",
    "Never through `npx` or `npm exec`, even with `--no`",
    "Ask the user before anything that downloads and runs a package (npx, npm exec, pnpm dlx, bunx, uvx, pipx run) other than as rule 6 says",
  ], "rule 5");
  const run = section("references/npm.md", "Running a package").replace(/\s+/g, " ");
  inOrder(run, [
    "A dependency's bin needs no permission after this session's `npm ci --ignore-scripts`, as `./node_modules/.bin/<bin>` or `npm run <script>` once you have read it and its `pre`/`post` scripts",
    "Never `npx` or `npm exec`, even with `--no`",
    "it installs the project into its cache when the project's own `bin` has that name",
    "runs a same-named bin from a parent folder's `node_modules/.bin`, the global folder or its cache",
    "Ask before anything that downloads and runs a package",
  ], "npm.md");
  // No file exempts a locked dependency, or runs anything through npx --no or npm exec --no.
  for (const f of files(SKILL)) {
    const text = readFileSync(f, "utf8").replace(/\s+/g, " ");
    assert.doesNotMatch(text, /not already a locked dependency/, relative(ROOT, f));
    assert.doesNotMatch(text, /`(npx|npm exec) --no[ -][^`]*`/, `${relative(ROOT, f)} runs a bin through npx --no`);
  }
  // Every npx the skill gives is a pinned tool run (rule 6), never a project bin.
  const runs = spans("npx ").concat(spans("npm exec "));
  assert.ok(runs.length >= 2, runs.join("; "));
  for (const c of runs) assert.match(c, /^npx (--ignore-scripts --min-release-age=7 )?<name>@<version>$/, `"${c}"`);
  // uvx and pipx run never use the project's lock: they ask, and the locked tool runs from the environment. Not uv run
  // --no-sync: it creates a missing .venv, downloading a Python, and an empty one finds the tool on PATH.
  const py = section("references/python.md", "Running a tool").replace(/\s+/g, " ");
  inOrder(py, ["use their own environment, never the lock: ask first", "A locked tool runs as `.venv/bin/<tool>` without asking, failing if the lock lacks it"], "python.md");
  for (const text of [py, r5]) assert.doesNotMatch(text, /uv run/, "a locked tool never runs through uv run");
});

test("skill: a command-line tool installed outside a project is checked, asked about unless named and clean, pinned, with scripts, builds and dependency cooldowns", () => {
  const r6 = rule(6);
  inOrder(r6, [
    "Installing a command-line tool outside a project (`npm install -g`, `npx <name>@<version>`, `pipx install`, `uv tool install`, or `pip install <name>` into a throwaway virtual environment)",
    "check it as rule 3 checks a new dependency, and ask the user first unless they named the tool and every check passes",
    "Either way, say which exact version you install and when it was published",
    "Use an exact version published at least 7 days ago, with install scripts and source builds off, and a 7-day cooldown for its dependencies, which no lock pins",
    "npm reads `--min-release-age` from 11.10; below that, use `--before=<the date 7 days ago, YYYY-MM-DD>` instead, or say that its dependencies are not aged",
    "adding `--cooldown 7` if `pipx install --help` lists `--cooldown`",
    "uv 0.9.17 or newer: `uv tool install",
    "If the tool fails without its install script, or has no wheel to install, ask the user; do not turn scripts or builds back on",
  ], "rule 6");
  // The flags, as each tool documents them: npm's ignore-scripts and min-release-age, pip's --only-binary (through
  // pipx's --pip-args) and --uploaded-prior-to, uv's --no-build and --exclude-newer; every command pins an exact version.
  const want: [string, RegExp][] = [
    ["npm install -g", /^npm install -g --ignore-scripts --min-release-age=7 <name>@<version>$/],
    ["npx --ignore-scripts", /^npx --ignore-scripts --min-release-age=7 <name>@<version>$/],
    ["pipx install", /^pipx install --pip-args="--only-binary :all:" <name>==<version>$/],
    ["uv tool install", /^uv tool install --no-build --exclude-newer "7 days" <name>==<version>$/],
    ["pip install --only-binary", /^pip install --only-binary :all: --uploaded-prior-to P7D <name>==<version>$/],
  ];
  const r6Spans = [...r6.matchAll(/`([^`]+)`/g)].map((m) => m[1]!);
  for (const [prefix, re] of want) {
    const found = r6Spans.filter((c) => c.startsWith(prefix) && c !== prefix && !c.endsWith(" --help"));
    assert.equal(found.length, 1, `${prefix}: ${found.join("; ")}`);
    assert.match(found[0]!, re);
  }
  // Nowhere else in the skill installs a tool globally, or with uv tool or pipx, without those flags.
  for (const c of spans("npm install -g").concat(spans("npm i -g"))) assert.ok(c === "npm install -g" || /--ignore-scripts --min-release-age=7/.test(c), `"${c}" runs install scripts or skips the cooldown`);
  for (const c of spans("pipx install ").filter((x) => !x.endsWith(" --help"))) assert.match(c, /--only-binary :all:/, `"${c}" builds source packages`);
  for (const c of spans("uv tool install ")) assert.match(c, /--no-build --exclude-newer/, `"${c}" builds source packages or skips the cooldown`);
});

test("skill: Yarn 2+ installs the lockfile with scripts off from the environment, editing no file", () => {
  // Yarn reads a setting from YARN_ plus its name in snake case, over .yarnrc.yml (yarnpkg.com/configuration/yarnrc).
  const yarn = spans("YARN_ENABLE_SCRIPTS=false yarn install");
  assert.deepEqual([...new Set(yarn)], ["YARN_ENABLE_SCRIPTS=false yarn install --immutable"]);
  assert.ok(yarn.length >= 2, "SKILL.md and npm.md");
  for (const c of spans("yarn install")) assert.match(c, /--frozen-lockfile --ignore-scripts$/, `"${c}": a Yarn 2+ install without YARN_ENABLE_SCRIPTS=false`);
  const install = section("references/npm.md", "Install from the lockfile");
  assert.doesNotMatch(install, /in `\.yarnrc\.yml`/, "the lockfile install edits no Yarn settings file");
});

test("skill: the pip-compile --no-emit-options claim is marked as not from a recorded run", () => {
  const py = readFileSync(join(SKILL, "references", "python.md"), "utf8").replace(/\s+/g, " ");
  assert.ok(py.includes("`--no-emit-options` should keep out the `--only-binary` line `wormsign soak` refuses (pip-compile's help; no recorded run)"), "python.md");
});

test("plugin: holds only its manifest and the skill, and its version is the package's", () => {
  const rel = files(PLUGIN).map((f) => relative(PLUGIN, f).split("\\").join("/")).sort();
  assert.ok(rel.every((p) => p === ".claude-plugin/plugin.json" || p.startsWith("skills/wormsign/")), rel.join(", "));
  const plugin = JSON.parse(readFileSync(join(PLUGIN, ".claude-plugin", "plugin.json"), "utf8")) as Record<string, unknown>;
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { version: string };
  assert.equal(plugin["name"], "wormsign");
  assert.equal(plugin["version"], pkg.version);
  for (const k of ["description", "license"]) assert.ok(typeof plugin[k] === "string" && plugin[k] !== "", `plugin.json ${k}`);
  for (const k of ["hooks", "mcpServers", "commands", "agents", "lspServers"]) assert.ok(!(k in plugin), `plugin.json declares ${k}`);
});

test("marketplace: lists the one plugin by a relative path, with the fields the schema requires", () => {
  const m = JSON.parse(readFileSync(join(ROOT, ".claude-plugin", "marketplace.json"), "utf8")) as { name: string; owner: { name: string }; plugins: { name: string; source: string; description?: unknown }[] };
  assert.equal(m.name, "wormsign");
  assert.ok(typeof m.plugins[0]?.description === "string" && m.plugins[0].description !== "", "the plugin entry's description");
  assert.equal(m.owner.name, "stgllghr");
  assert.deepEqual(m.plugins.map((p) => [p.name, p.source]), [["wormsign", "./plugins/wormsign"]]);
  for (const n of [m.name, ...m.plugins.map((p) => p.name)]) assert.doesNotMatch(n, /^(claude|anthropic)-/);
  assert.ok(existsSync(join(ROOT, "plugins", "wormsign", ".claude-plugin", "plugin.json")));
});

test("package.json ships the skill", () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { files: string[] };
  assert.ok(pkg.files.includes("plugins/wormsign"));
});
