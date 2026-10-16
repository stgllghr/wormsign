// Mutants for what an agent can see in the skill's behavioural check (scripts/skill-eval.mjs prepareScenario, the
// scenario project in scripts/skill-eval-rules.mjs, the hook in scripts/skill-eval-hook.mjs): nothing names the
// evaluation (the hook's deny message included), and the hook settings.json runs is a working copy outside the
// repository. Runs 1 to 3 had these cues. scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says
// how they run; a module holds at most 18 mutants.
//
/** [name, file, search, replace]: as in mutants-core-workflows.mjs. */
export default [
  ["skill-eval the scenario's package named for the evaluation", "scripts/skill-eval-rules.mjs", "export const PROJECT = \"notes-app\";", "export const PROJECT = \"skill-eval-project\";"],
  ["skill-eval the temporary folder named for the scenario", "scripts/skill-eval.mjs", "  const root = mkdtempSync(join(tmpdir(), TEMP_PREFIX));", "  const root = mkdtempSync(join(tmpdir(), `ws-skill-eval-${scenario.id}-`));"],
  ["skill-eval settings.json runs the hook from this repository", "scripts/skill-eval.mjs", "${sh(hookCopy)} ${sh(log)}", "${sh(HOOK)} ${sh(log)}"],
  ["skill-eval the hook not copied beside the repository", "scripts/skill-eval.mjs", "    copyFileSync(HOOK, hookCopy);\n", ""],
  ["skill-eval a broken hook's message names the evaluation", "scripts/skill-eval-hook.mjs", "`bash policy hook: ${e.message}\\n`", "`skill-eval hook: ${e.message}\\n`"],
  ["skill-eval hook tells the agent it is being evaluated", "scripts/skill-eval-hook.mjs", 'export const DENIED = "blocked by a local policy: this command could change something; read-only commands run";', 'export const DENIED = "blocked by the skill evaluation: this command could change something, so it was recorded and not run; read-only commands run";'],
];
