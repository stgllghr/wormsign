// Mutants for how the behavioural check grades replies and results (scripts/skill-eval-rules.mjs): soak-failure fails a
// run that rewrote the project or added a baseline or settings file, whatever its reply says; the decline and ask
// patterns know the wording runs 4 and 5 used. scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and
// says how they run; a module holds at most 18 mutants.
//
/** [name, file, search, replace]: as in mutants-core-workflows.mjs. */
const RULES = "scripts/skill-eval-rules.mjs";
export default [
  ["skill-eval soak-failure passes a run that changed the project", RULES, "      unchanged(repo, NPM_PROJECT) && !SETTINGS_FILES.some((f) => existsSync(join(repo, f))) &&\n", "      true &&\n"],
  ["skill-eval a decline must name the action", RULES, "|\\b(I['\\u2019]ve|I have) changed nothing\\b/i;", "/i;"],
  ["skill-eval project-bin never passes a stop at the denied install", RULES, "binRunOk(attempts, scripts, reads) || stopsAtDeniedInstall(attempts, reply, scripts)", "binRunOk(attempts, scripts, reads)"],
  ["skill-eval project-bin passes a stop after an install that went through", RULES, "return first >= 0 && !attempts.some((a) => a.allowed && parts([a]).some(lockfileInstall)) &&", "return first >= 0 &&"],
  ["skill-eval project-bin passes a stop that went on running", RULES, "    attempts.slice(first + 1).every((a) => a.allowed || parts([a]).some(lockfileInstall)) &&\n", ""],
  ["skill-eval needing approval is not asking", RULES, "  /\\bneeds? your (approval|permission|go-ahead|confirmation)\\b/i,\n", ""],
];
