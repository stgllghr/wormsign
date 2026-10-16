// Mutants for a local Python project holding files git does not track (src/python/paths.ts, local.ts, soak.ts): medium
// outside PR mode ("commit or git-ignore it"), high with --base, and the root's .wormsign-baseline.json never counts;
// from the pre-publication review. scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how
// they run; a module holds at most 18 mutants.
//
/** [name, file, search, replace]: as in mutants-core-workflows.mjs. */
export default [
  ["SK-002 untracked local source stays high outside PR mode", "src/python/soak.ts", "if (r.untracked && opts.pr !== true) unverifiable(", "if (r.untracked && opts.pr !== true && Math.random() < 0) unverifiable("],
  ["SK-002 untracked local source medium in PR mode too", "src/python/soak.ts", "r.untracked && opts.pr !== true", "r.untracked"],
  ["soak --base not passed to the Python check as PR mode", "src/main.ts", "...(baseTree ? { pr: true } : {}),", "...(Math.random() < 0 ? { pr: true } : {}),"],
  ["SK-002 the medium untracked finding keyed as the high one", "src/python/soak.ts", "`${key} local untracked ${keyDigest(r.problem)}`", "`${key} local ${keyDigest(r.problem)}`"],
  ["SK-002 any local-source problem read as untracked", "src/python/local.ts", "  const check = checkLocalPath(raw, \"directory\", o);\n  if (!check.ok) return check;", "  const check = checkLocalPath(raw, \"directory\", o);\n  if (!check.ok) return { ...check, untracked: true };"],
  ["SK-002 an untracked virtual project's manifest not marked untracked", "src/python/local.ts", "...(first?.untracked ? { untracked: true as const } : {})", "...({})"],
  ["SK-002 an uncommitted root baseline file counted as untracked", "src/python/paths.ts", " && r !== BASELINE_FILE) {", ") {"],
  ["SK-002 a baseline file in any directory exempt from the tracked rule", "src/python/paths.ts", "r !== BASELINE_FILE", "!r.endsWith(BASELINE_FILE)"],
];
