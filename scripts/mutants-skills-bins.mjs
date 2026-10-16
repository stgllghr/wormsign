// Mutants for rule 5's conditions on a dependency's bin and rule 6's npm and uv versions (plugins/wormsign/skills/
// wormsign/): this session's lockfile install first; an npm script read, with its pre and post scripts, before npm run
// runs it; a locked Python tool only as .venv/bin/<tool>, never uv run (which can create a .venv and find the tool on
// PATH); npm below 11.10 ages a tool's dependencies with --before, or says it does not; uv's durations from 0.9.17.
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/** [name, file, search, replace]. Each removes one instruction the content tests pin. */
const SKILL = "plugins/wormsign/skills/wormsign/SKILL.md";
const NPM = "plugins/wormsign/skills/wormsign/references/npm.md";
const PY = "plugins/wormsign/skills/wormsign/references/python.md";
export default [
  ["skill runs a dependency's bin before this session's lockfile install", SKILL, "(rule 1; if you have not run it in this\n   session, run it first)", "(rule 1)"],
  ["skill runs an npm script unread", SKILL, " after reading that script\n   and its pre and post scripts (if one runs npx, npm exec, a dlx, an install or a download, rules 5 and 6 apply to\n   it)", ""],
  ["skill's npm reference runs an npm script unread", NPM, " once you have read it and its `pre`/`post` scripts", ""],
  ["skill's npm reference runs a bin without this session's install", NPM, "after this session's `npm ci --ignore-scripts`", "after `npm ci --ignore-scripts`"],
  ["skill's python reference runs a locked tool through uv run", PY, "`.venv/bin/<tool>` without asking, failing if the lock lacks it.", "`.venv/bin/<tool>` or `uv run --no-sync <tool>` without asking, failing if the lock lacks it."],
  ["skill gives npm below 11.10 no cooldown", SKILL, "; below\n     that, use `--before=<the date 7 days ago, YYYY-MM-DD>` instead, or say that its dependencies are not aged", ""],
  ["skill drops the uv version for durations", SKILL, "uv 0.9.17 or newer: `uv tool install", "uv: `uv tool install"],
];
