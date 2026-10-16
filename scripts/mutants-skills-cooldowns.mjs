// Mutants for rule 6's dependency cooldowns and its statement of the version installed (SKILL.md): a tool's
// dependencies are not locked, so each recipe carries its tool's own 7-day cooldown (npm --min-release-age=7, pipx
// --cooldown 7 when its help lists it, uv --exclude-newer "7 days", pip --uploaded-prior-to P7D), and the agent says
// which version it installs and when it was published, asked or not.
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/** [name, file, search, replace]. Each removes one instruction the content tests pin. */
const SKILL = "plugins/wormsign/skills/wormsign/SKILL.md";
export default [
  ["skill installs an npm tool without a dependency cooldown", SKILL, "`npm install -g --ignore-scripts --min-release-age=7 <name>@<version>`", "`npm install -g --ignore-scripts <name>@<version>`"],
  ["skill runs an npx tool without a dependency cooldown", SKILL, "`npx --ignore-scripts --min-release-age=7 <name>@<version>`", "`npx --ignore-scripts <name>@<version>`"],
  ["skill installs a pipx tool without its cooldown", SKILL, ", adding `--cooldown 7` if\n     `pipx install --help` lists `--cooldown`", ""],
  ["skill installs a uv tool without a dependency cooldown", SKILL, "`uv tool install --no-build --exclude-newer \"7 days\" <name>==<version>`", "`uv tool install --no-build <name>==<version>`"],
  ["skill installs a pip tool without a dependency cooldown", SKILL, "`pip install --only-binary :all: --uploaded-prior-to P7D <name>==<version>`", "`pip install --only-binary :all: <name>==<version>`"],
  ["skill does not say the version installed and its publish date", SKILL, " Either way, say which\n   exact version you install and when it was published.", ""],
  ["skill's tool rule drops the dependency cooldown", SKILL, ", and a 7-day cooldown for its dependencies, which no lock pins:", ":"],
];
