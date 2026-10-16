// Mutants for the agent-user review's skill fixes (plugins/wormsign/skills/wormsign/): the description names
// command-line tools from npm or PyPI; rule 6 checks one, asks unless the user named it and every check passes, says
// its version and publish date, pins it at least 7 days old with install scripts and source builds off (npm
// --ignore-scripts, pipx --pip-args="--only-binary :all:", uv --no-build, pip --only-binary :all:); rule 5 and npm.md
// run a dependency's bin only from node_modules/.bin or npm run, never through npx or npm exec, --no or not; python.md
// does not exempt uvx; Yarn 2+ installs with YARN_ENABLE_SCRIPTS=false; the pip-compile --no-emit-options claim says
// it is not from a recorded run. Rule 6's dependency cooldowns: scripts/mutants-skills-cooldowns.mjs.
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/** [name, file, search, replace]. Each removes or weakens one instruction the content tests pin. */
const SKILL = "plugins/wormsign/skills/wormsign/SKILL.md";
const NPM = "plugins/wormsign/skills/wormsign/references/npm.md";
const PY = "plugins/wormsign/skills/wormsign/references/python.md";
export default [
  ["skill's description leaves out command-line tools", SKILL, " installing a command-line tool from npm or PyPI (npm install -g, pipx install, uv tool install),", ""],
  ["skill installs a tool the user did not name without asking", SKILL, "and ask the user first unless they named the tool and every check passes.", "and install it."],
  ["skill installs a command-line tool younger than 7 days", SKILL, "Use an exact version published at least 7 days ago, with\n", "Use an exact version, with\n"],
  ["skill installs an npm tool globally with scripts on", SKILL, "`npm install -g --ignore-scripts --min-release-age=7 <name>@<version>`", "`npm install -g --min-release-age=7 <name>@<version>`"],
  ["skill runs an npx tool with scripts on", SKILL, "`npx --ignore-scripts --min-release-age=7 <name>@<version>`", "`npx --min-release-age=7 <name>@<version>`"],
  ["skill installs a pipx tool from source", SKILL, "`pipx install --pip-args=\"--only-binary :all:\" <name>==<version>`", "`pipx install <name>==<version>`"],
  ["skill installs a uv tool from source", SKILL, "`uv tool install --no-build --exclude-newer \"7 days\" <name>==<version>`", "`uv tool install --exclude-newer \"7 days\" <name>==<version>`"],
  ["skill installs a pip tool from source", SKILL, "`pip install --only-binary :all: --uploaded-prior-to P7D <name>==<version>`", "`pip install --uploaded-prior-to P7D <name>==<version>`"],
  ["skill lets a failing tool install turn scripts back on", SKILL, "   If the tool fails without its install script, or has no wheel to install, ask the user; do not turn scripts or\n   builds back on.", "   If the tool fails without its install script, turn scripts back on."],
  ["skill runs a dependency's bin through npx --no", SKILL, "run it first), as `./node_modules/.bin/<bin>`, or through", "run it first), as `npx --no <bin>`, or through"],
  ["skill no longer says npx --no is unsafe", SKILL, " Never through `npx` or `npm exec`, even with `--no`: npm\n   can still install the project itself, or run a same-named bin from a parent folder, the global folder or its cache\n   (references/npm.md).", ""],
  ["skill's npm reference runs a dependency's bin through npx --no", NPM, "as `./node_modules/.bin/<bin>`\nor `npm run <script>`", "as `npx --no <bin>`\nor `npm run <script>`"],
  ["skill's npm reference leaves out what npx does before --no", NPM, "before npm reads it,\nit installs the project into its cache when the project's own `bin` has that name (dependencies resolved fresh), and\nruns a same-named bin from a parent folder's `node_modules/.bin`, the global folder or its cache.", "it installs nothing."],
  ["skill's Yarn 2+ lockfile install edits .yarnrc.yml", NPM, "- Yarn 2+: `YARN_ENABLE_SCRIPTS=false yarn install --immutable` (`enableScripts` set from the environment, no file)", "- Yarn 2+: `yarn install --immutable` with `enableScripts: false` in `.yarnrc.yml`"],
  ["skill's python reference exempts uvx for a locked dependency", PY, "never the lock: ask first.", "so ask first unless the project locks the tool."],
  ["skill states the pip-compile --no-emit-options claim as verified", PY, " (pip-compile's help; no recorded run)", ""],
];
