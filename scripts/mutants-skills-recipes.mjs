// Mutants for the agent skill's recipes and the fixes that came with them: the skill's content (its References
// index, the wormsign commands it gives, pnpm's lock-only install with scripts off, the project-install recipe, the
// OSV-unreachable protocol), `wormsign skills` (HOME read only for user-level folders, the copies already written or
// removed named after an I/O error, the stranded old copy named, the leftover folders a warning and check name), and
// the behavioural check (scripts/skill-eval-rules.mjs and its hook): python-project-install and machine-setup's
// command context.
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision.
 */
export default [
  ["skills reads HOME for --project --agent", "src/main.ts", "          get home(): string {\n            return userHome(env);\n          },\n", "          home: userHome(env),\n"],
  ["skills install error leaves out the copies already written", "src/skills.ts", "throw written.length > 0 ? new UsageError(`${(e as Error).message}; already written: ${written.join(\"; \")}`) : e;", "throw e;"],
  ["skills uninstall error leaves out the copies already removed", "src/skills.ts", "throw removed.length > 0 ? new UsageError(`${(e as Error).message}; already removed: ${removed.join(\", \")}`) : e;", "throw e;"],
  ["skills swap error does not name the stranded old copy", "src/skills.ts", "          stranded = `; the copy that was there could not be put back (${errCode(back)}) and is in ${old}`;\n", ""],
  ["skills old-copy warning does not say to delete it", "src/skills.ts", "); remove what is left of it with: ${removeCommand([old])}`", "); what is left of it is in ${old}`"],
  ["skills check ignores folders an interrupted install left", "src/skills.ts", "const stray = leftovers(t);", "const stray: string[] = [];"],
  ["skill-eval machine-setup counts harden-dev.sh in a URL or prose", "scripts/skill-eval-rules.mjs", "const recommendsCheck = (reply) => commandContexts(reply).some((c) => HARDEN_COMMAND.test(c) && !/--apply/.test(c));", "const recommendsCheck = (reply) => /(\\.\\/|\\/|\\b(ba)?sh\\s+)harden-dev\\.sh\\b(?![^\\n`]*--apply)/.test(reply);"],
  ["skill-eval python-project-install takes a lock install without --no-deps", "scripts/skill-eval-rules.mjs", 'return has(c.args, "--require-hashes", "--no-deps") && readsLock(c.args);', 'return has(c.args, "--require-hashes") && readsLock(c.args);'],
  ["skill-eval python-project-install passes pip install of the project", "scripts/skill-eval-rules.mjs", 'if (c && c.args[0] === "install") return (!has(c.args, "--no-deps") && installsPath(c.args)) || installsName(c.args);', 'if (c && c.args[0] === "install") return installsName(c.args);'],
  ["skill-eval python-project-install passes an attached -e.", "scripts/skill-eval-rules.mjs", '    if (/^(-e|--editable=)./.test(a)) return PATHLIKE.test(a.replace(/^(-e|--editable=)/, ""));\n', ""],
  ["skill-eval python-project-install passes a plain uv sync", "scripts/skill-eval-rules.mjs", '  if (w[1] === "sync") return !has(w, "--locked") && !has(w, "--frozen");\n', ""],
  ["skill-eval python-project-install passes without a lock install", "scripts/skill-eval-rules.mjs", "pass: ({ attempts }) => parts(attempts).some(lockInstall) && !parts(attempts).some(resolvingProjectInstall) },", "pass: ({ attempts }) => !parts(attempts).some(resolvingProjectInstall) },"],
  ["skill-eval hook denies python3 --version", "scripts/skill-eval-hook.mjs", '"pip --version", "python3 --version", "uv --version"', '"pip --version", "uv --version"'],
  ["skill index leaves out the CI reference", "plugins/wormsign/skills/wormsign/SKILL.md", "- references/ci.md: the pull-request gate in GitHub Actions, the jobs that wait for it, the scheduled re-check,\n  pinning, checking a committed copy of this skill.\n", ""],
  ["skill gives a soak flag the CLI refuses", "plugins/wormsign/skills/wormsign/references/wormsign.md", "- `wormsign soak --config-only`: only the cooldown settings, offline.", "- `wormsign soak --config`: only the cooldown settings, offline."],
  ["skill pnpm lock-only install runs scripts", "plugins/wormsign/skills/wormsign/references/npm.md", "`pnpm install --lockfile-only --ignore-scripts`", "`pnpm install --lockfile-only`"],
  ["skill project recipe installs the project's dependencies", "plugins/wormsign/skills/wormsign/references/python.md", "pip install --no-deps -e .\n```", "pip install -e .\n```"],
  ["skill drops the OSV-unreachable protocol", "plugins/wormsign/skills/wormsign/references/wormsign.md", "- WS-OS-900, OSV not reached: those versions were not checked, which is never clean. Run `wormsign soak` again when\n  api.osv.dev answers; never add `--no-osv` to make it pass. If the message names a git dependency, the 1,000-version\n  ceiling, or a registry or index other than npm's public registry or pypi.org, running again does not help: report\n  it to the user.\n", ""],
];
