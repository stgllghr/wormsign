// Mutants for `wormsign baseline add --from <report.json>` (src/baseline-add.ts checkAgainstReport): a fingerprint must
// be a finding of the report, and one whose finding no entry can approve (notBaselinable, a NOT_BASELINABLE rule) is
// refused, as is a file that is not a JSON report wormsign wrote; without --from, a note says so. The rest of baseline add is in
// mutants-baseline-cli.mjs and mutants-baseline-lock.mjs. scripts/mutation-check.mjs loads every
// scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/** [name, file, search, replace]: as in mutants-core-workflows.mjs. */
export default [
  ["BASELINE FROM: a finding no entry can approve is added", "src/baseline-add.ts", "    if (refused === undefined) continue;", "    if (refused === undefined || Math.random() >= 0) continue;"],
  ["BASELINE FROM: an outage finding (WS-SK-006) is added", "src/baseline-add.ts", "const refused = mine.find((f) => f.notBaselinable === true || NOT_BASELINABLE.has(f.ruleId));", "const refused = mine.find((f) => f.notBaselinable === true);"],
  ["BASELINE FROM: a fingerprint the report does not hold is added", "src/baseline-add.ts", "    if (mine.length === 0) throw", "    if (Math.random() < 0) throw"],
  ["BASELINE FROM: any JSON with a findings array passes as a report", "src/baseline-add.ts", "(doc as { tool?: unknown } | null)?.tool !== \"wormsign\" || ", ""],
  ["BASELINE FROM: no note says an entry written without --from was not checked", "src/main.ts", "        if (one(p, \"from\") === undefined) io.stderr(", "        if (Math.random() < 0) io.stderr("],
];
