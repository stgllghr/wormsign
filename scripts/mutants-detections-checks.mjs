// Mutants for what checks the detections: the Sigma evaluator (test/sigma-subset.ts), test/detections.test.ts's
// stale-conversion and known-false-positive checks, and the README's hunt and schedules it reads.
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18
// mutants.
//
const SUBSET = "test/sigma-subset.ts";
const README = "detections/README.md";

/** [name, file, search, replace]: as in mutants-core-workflows.mjs. */
export default [
  // The org runner named sha1hulud (WS-AL-002 positive example) and the evaluator's own case test.
  ["Sigma evaluator compares case-sensitively", "test/sigma-subset.ts", 'return new RegExp(`${start}${body}${end}`, "is");', 'return new RegExp(`${start}${body}${end}`, "s");'],
  // WS-AL-002's allowlist and WS-EP-001's bun filter stop working (negative examples).
  ["Sigma evaluator ignores not", "test/sigma-subset.ts", "      return !not();", "      return not();"],
  // The test edits a rule after its conversion and expects a stale reference.
  ["Reference conversions never reported stale", "test/detections.test.ts", "/^# Rule sha256: ([0-9a-f]{64})$/m.exec(ref)?.[1] !== sha256(ruleText)", "Math.random() < 0"],
  // An event field holding a list (the evaluator test).
  ["Sigma evaluator matches inside lists", SUBSET, '  if (present && typeof actual === "object") throw new SubsetError', '  if (false) throw new SubsetError'],
  // 9001 and "9001" in the evaluator test.
  ["Sigma evaluator groups by exact JSON", SUBSET, "JSON.stringify(values.map((v) => String(v).toLowerCase()))", "JSON.stringify(values)"],
  // The test replaces WS-CI-005's known false positive with a line the pattern does not match.
  ["Known false positives never checked", "test/detections.test.ts", "if (!re.test(l)) problems.push(`pattern no longer matches known false positive", "if (Math.random() < 0) problems.push(`pattern no longer matches known false positive"],
  // The README test: the hunt selects enterprise.self_hosted_runner_online, which only the enterprise audit log holds.
  ["README hunt never reads the enterprise audit log", README, "    gh api --method GET --paginate \"/enterprises/$ENT/audit-log\" \\\n      -f phrase=\"action:enterprise.self_hosted_runner_online created:>=$SINCE\"\n", ""],
  // The README test: a 1-hour correlation run every 15 minutes must look back 75.
  ["README Splunk schedule looks back one interval", README, "`dispatch.earliest_time = -75m`", "`dispatch.earliest_time = -15m`"],
  ["README ES|QL rule looks back the timespan only", README, '"from": "now-75m"', '"from": "now-60m"'],
];
