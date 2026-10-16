// Mutants for the behavioural check's --no-skill control, its verdicts and its hook (scripts/skill-eval.mjs,
// scripts/skill-eval-hook.mjs): no skill installed in a --no-skill run; the output's mode; a no-skill run in which the
// skill (or a plugin's <plugin>:wormsign) loaded or was opened anyway is an error; a soft fail is its own verdict and
// exits 1; the file tools go through the hook, which denies any write under .git, a link to one too.
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/** [name, file, search, replace]. `Math.random() < 0` is never true and `Math.random() >= 0` always is. */
const HARNESS = "scripts/skill-eval.mjs";
const HOOK = "scripts/skill-eval-hook.mjs";
export default [
  ["skill-eval --no-skill installs the skill anyway", HARNESS, "    if (skill) {\n      const install", "    if (Math.random() >= 0) {\n      const install"],
  ["skill-eval output omits the mode", HARNESS, "json({ date: new Date().toISOString(), mode, claudeVersion,", "json({ date: new Date().toISOString(), claudeVersion,"],
  ["skill-eval --no-skill accepts a loaded wormsign skill", HARNESS, "  if (!skill && skills.some(isWormsignSkill)) problems.push(", "  if (Math.random() < 0) problems.push("],
  ["skill-eval --no-skill accepts a skill read", HARNESS, "  if (!skill && skillRead) problems.push(", "  if (Math.random() < 0) problems.push("],
  ["skill-eval a skill run accepts a missing skill", HARNESS, "  if (skill && !skills.some(isWormsignSkill)) problems.push(", "  if (Math.random() < 0) problems.push("],
  ["skill-eval misses a plugin's namespaced copy", HARNESS, "/(^|:)wormsign$/.test(name)", "/^wormsign$/.test(name)"],
  ["skill-eval never gives a soft fail", HARNESS, 'pass ? "pass" : soft ? "soft-fail" : "fail"', 'pass ? "pass" : "fail"'],
  ["skill-eval exit code ignores a soft fail", HARNESS, 'v === "fail" || v === "soft-fail"', 'v === "fail"'],
  ["skill-eval grades a scenario without its soft rule", HARNESS, "      soft = pass ? undefined : scenario.soft?.({ attempts, reply, repo, skillRead, skill, reads });\n", ""],
  ["skill-eval grades rules without the mode", HARNESS, "      pass = Boolean(scenario.pass({ attempts, reply, repo, skillRead, skill, reads }));", "      pass = Boolean(scenario.pass({ attempts, reply, repo, skillRead, reads }));"],
  ["skill-eval settings.json sends no file tool to the hook", HARNESS, ", { matcher: FILE_MATCHER, hooks: [hook] }", ""],
  ["skill-eval hook lets a file under .git be written", HOOK, "      const allowed = !inGitDir(path);", "      const allowed = Math.random() >= 0 || !inGitDir(path);"],
  ["skill-eval hook follows no link to .git", HOOK, "      return parts(realpathSync(dir)).includes(\".git\");", "      return Math.random() < 0 && parts(realpathSync(dir)).includes(\".git\");"],
];
