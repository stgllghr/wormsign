// Mutants for what keeps a build, a script, a resolving install or a write outside the project away from the agent
// skill (review rounds 1 to 3): the skill's content (uv adds and compiles with --no-build, pip-compile with wheels only
// and no option line, bun and pnpm installs with --ignore-scripts, Yarn's with enableScripts: false, the project's own
// build when its metadata is dynamic, and asking first there); the behavioural check's python-project-install rule (no
// uv sync counts as a lock install without a uv.lock; a package installed by name, a plain uv run and a uv add that installs
// are resolving installs); `wormsign skills --project` refusing a git root that does not hold the working directory
// (core.worktree), and a failed cleanup that must not hide the error.
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision.
 */
export default [
  ["skill adds a uv package with builds on", "plugins/wormsign/skills/wormsign/references/python.md", "`uv add --no-sync --no-build <name>==<version>`", "`uv add --no-sync <name>==<version>`"],
  ["skill writes a uv hash lock with builds on", "plugins/wormsign/skills/wormsign/references/python.md", "`uv pip compile --no-build --generate-hashes`", "`uv pip compile --generate-hashes`"],
  ["skill writes a pip-tools hash lock from source packages", "plugins/wormsign/skills/wormsign/references/python.md", '`pip-compile --generate-hashes --no-emit-options --pip-args "--only-binary :all:"`', "`pip-compile --generate-hashes`"],
  ["skill installs with bun running its trusted scripts", "plugins/wormsign/skills/wormsign/SKILL.md", "`bun install --frozen-lockfile --ignore-scripts`", "`bun install --frozen-lockfile`"],
  ["skill installs a pnpm lock with dependency scripts on", "plugins/wormsign/skills/wormsign/SKILL.md", "pnpm: `pnpm install --frozen-lockfile --ignore-scripts`;", "pnpm: `pnpm install --frozen-lockfile`;"],
  ["skill's npm reference installs a pnpm lock with dependency scripts on", "plugins/wormsign/skills/wormsign/references/npm.md", "- pnpm: `pnpm install --frozen-lockfile --ignore-scripts` (", "- pnpm: `pnpm install --frozen-lockfile` ("],
  ["skill installs a Yarn lock with scripts on", "plugins/wormsign/skills/wormsign/SKILL.md", "`YARN_ENABLE_SCRIPTS=false yarn install --immutable`; bun:", "`yarn install --immutable`; bun:"],
  ["skill does not say a dynamic-metadata project is built to add a package", "plugins/wormsign/skills/wormsign/references/python.md", " If the project's own metadata is `dynamic`, the uv add and\npip-compile commands above still build the project itself to read it, installing its build requirements fresh: the\nbuild limitation under \"Builds\" below.", ""],
  ["skill does not ask before building a dynamic-metadata project to add a package", "plugins/wormsign/skills/wormsign/references/python.md", " So for such a project, ask the user before running either: each builds it.", ""],
  ["skill-eval python-project-install takes uv sync --locked without a uv.lock", "scripts/skill-eval-rules.mjs", '  return c?.uv === true && c.args[0] === "sync" &&', '  if (words(p)[0] === "uv" && words(p)[1] === "sync" && has(words(p), "--locked")) return true;\n  return c?.uv === true && c.args[0] === "sync" &&'],
  ["skill-eval python-project-install passes pip install of a package by name", "scripts/skill-eval-rules.mjs", "return (!has(c.args, \"--no-deps\") && installsPath(c.args)) || installsName(c.args);", "return !has(c.args, \"--no-deps\") && installsPath(c.args);"],
  ["skill-eval python-project-install passes a plain uv run", "scripts/skill-eval-rules.mjs", '  if (w[1] === "run") return !has(w, "--locked") && !has(w, "--frozen") && !has(w, "--no-sync");\n', ""],
  ["skill-eval python-project-install passes a uv add that installs", "scripts/skill-eval-rules.mjs", '  if (w[1] === "add") return !has(w, "--no-sync") && !has(w, "--frozen");\n', ""],
  ["skills --project writes under a git root that does not hold the working directory", "src/tree.ts", '  if (isAbsolute(rel) || rel.split(sep)[0] === "..") {', "  if (Math.random() < 0) {"],
  ["skills write lets a failed cleanup replace the error", "src/skills.ts", "    try {\n      ops.remove(tmp);\n    } catch (r) {\n      unfinished = `; the unfinished new copy could not be removed (${errCode(r)}): ${removeCommand([tmp])}`;\n    }\n", "    ops.remove(tmp);\n"],
];
