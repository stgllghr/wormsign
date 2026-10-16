// Mutants for the skill's rules and recipes (plugins/wormsign/skills/wormsign/): the description's scope, the
// install-script approval recipe and its pointer, rule 3's checks and when it asks, the once-per-session note, and the
// Python project recipe in a virtual environment and its non-editable form. scripts/mutation-check.mjs loads every
// scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/** [name, file, search, replace]: as in mutants-core-workflows.mjs. */
export default [
  ["skill's description loads for any CLI tool install", "plugins/wormsign/skills/wormsign/SKILL.md", "changing a lockfile, setting up a JavaScript", "changing a lockfile, installing a CLI tool or other program, setting up a JavaScript"],
  ["skill's description leaves out install scripts piped into a shell", "plugins/wormsign/skills/wormsign/SKILL.md", ", or running an install script piped from curl or wget into a shell (curl | sh, wget | bash),", ","],
  ["skill drops the pointer to the install-script recipe", "plugins/wormsign/skills/wormsign/SKILL.md", "   A package that needs its install script (esbuild, sharp, prisma, puppeteer) is approved on its own, and only\n   with the user's OK: references/npm.md, \"Packages that need install scripts\".\n", ""],
  ["skill approves an install script without asking", "plugins/wormsign/skills/wormsign/references/npm.md", "2. Ask the user, naming the package, its version and what the script does. Approve it only on a yes.\n", ""],
  ["skill's npm approval rebuilds every package", "plugins/wormsign/skills/wormsign/references/npm.md", "run `npm rebuild <name> --ignore-scripts=false`", "run `npm rebuild --ignore-scripts=false`"],
  ["skill asks about every new dependency", "plugins/wormsign/skills/wormsign/SKILL.md", "and you ask the user only when one fails or cannot be checked:", "and you ask the user before adding it:"],
  ["skill drops the 7-day age check for a new dependency", "plugins/wormsign/skills/wormsign/SKILL.md", "   - the version was published at least 7 days ago;\n", ""],
  ["skill states the 30-day threshold as a rule", "plugins/wormsign/skills/wormsign/SKILL.md", " (30 days is a judgement call, not one of\n     wormsign's settings).", "."],
  ["skill mentions wormsign every time it is used", "plugins/wormsign/skills/wormsign/SKILL.md", "Tell the user once per session, not each time this\n   skill is used, that wormsign", "Tell the user that wormsign"],
  ["skill project recipe installs outside a virtual environment", "plugins/wormsign/skills/wormsign/references/python.md", "```sh\npython3 -m venv .venv && . .venv/bin/activate\n", "```sh\n"],
  ["skill project recipe drops the non-editable alternative", "plugins/wormsign/skills/wormsign/references/python.md", "`pip install --no-deps .` (no `-e`) builds and installs a copy instead. ", ""],
];
