// Mutants for the committed Splunk and ES|QL conversions (detections/**/*.spl, *.esql, written by
// detections/tools/convert_rules.py) and the SPL model test/detections-queries.test.ts runs them on.
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18
// mutants.
//
// A mutant of a .spl or .esql file leaves the rule's sha256 unchanged, so the stale-reference check does not see it:
// test/detections-queries.test.ts, which reads the committed query bodies, must kill it.
const EP1_ESQL = "detections/sigma/ws-ep-001-node-spawns-trufflehog-or-bun.esql";
const AL1_SPL = "detections/github-audit-log/ws-al-001-mass-visibility-flip.spl";
const AL1_ESQL = "detections/github-audit-log/ws-al-001-mass-visibility-flip.esql";
const AL2_ESQL = "detections/github-audit-log/ws-al-002-self-hosted-runner-registered.esql";
const AL4_SPL = "detections/github-audit-log/ws-al-004-worm-workflow-run.spl";
const AL4_ESQL = "detections/github-audit-log/ws-al-004-worm-workflow-run.esql";
const QUERIES = "test/detections-queries.test.ts";

/** [name, file, search, replace]: as in mutants-core-workflows.mjs. */
export default [
  // The correlation-parameter test, and the positive examples' three repositories.
  ["WS-AL-001 Splunk threshold raised to 300", AL1_SPL, "| search value_count >= 3", "| search value_count >= 300"],
  // The correlation-parameter test, and oss-maintainer making docs-site public three times (negative examples).
  ["WS-AL-001 ES|QL counts events, not repositories", AL1_ESQL, "value_count=count_distinct(repo)", "value_count=count(repo)"],
  // The burst across 11:00, and the correlation-parameter test.
  ["WS-AL-004 Splunk back to fixed clock hours", AL4_SPL, "| sort 0 _time\n| streamstats time_window=1h dc(event_type) as event_type_count by repo workflow_id", "| bin _time span=1h\n| stats dc(event_type) as event_type_count by _time repo workflow_id"],
  // The burst across 11:00, and the correlation-parameter test.
  ["WS-AL-004 ES|QL drops the offset buckets", AL4_ESQL, "mv_append(date_trunc(1 hour, @timestamp), date_trunc(1 hour, @timestamp + 30 minutes) - 30 minutes)", "date_trunc(1 hour, @timestamp)"],
  // The org runner named sha1hulud (positive example): ES|QL's == is case-sensitive.
  ["WS-AL-002 ES|QL compares the runner name case-sensitively", AL2_ESQL, 'to_lower(runner_name) == "sha1hulud"', 'runner_name == "SHA1HULUD"'],
  // A registration without an actor (positive example): ES|QL's not of a null comparison drops the event.
  ["WS-AL-002 ES|QL not drops events without an actor", AL2_ESQL, 'not coalesce(to_lower(actor) == "runner-provisioner[bot]", false)', 'not to_lower(actor) == "runner-provisioner[bot]"'],
  // TruffleHog started by cmd.exe under node_modules on Windows (positive example): like reads one backslash as an escape.
  ["WS-EP-001 ES|QL like escapes a backslash once", EP1_ESQL, 'to_lower(CurrentDirectory) like "*\\\\\\\\node_modules\\\\\\\\*"', 'to_lower(CurrentDirectory) like "*\\\\node_modules\\\\*"'],
  // The job rule's positive examples hold secrets_passed as a JSON array, which the SPL model refuses to test.
  ["WS-AL-004 SPL job query tests secrets_passed by its plain name", AL4_SPL, 'action="workflows.prepared_workflow_job" job_workflow_ref', 'action="workflows.prepared_workflow_job" secrets_passed=* job_workflow_ref'],
  // Five repositories made public in one burst: one Splunk result, not three; and the correlation-parameter test.
  ["WS-AL-001 Splunk raises a result per event that completes a burst", AL1_SPL, "\n| dedup actor", ""],
  // The correlation-parameter test: the model refuses a dedup of fields other than the group-by.
  ["WS-AL-004 Splunk dedup ignores the workflow", AL4_SPL, "| dedup repo workflow_id", "| dedup repo"],
  // Five repositories made public in one burst: the model must keep one result per group.
  ["SPL model ignores dedup", QUERIES, "if (g === undefined || (c.dedup && reported.has(g))) continue;", "if (g === undefined) continue;"],
  // The model test: secrets_passed=* on an array must throw.
  ["SPL model reads a JSON array as a present field", QUERIES, '  if (typeof v === "object") throw new ModelError(`Splunk names the array or map', '  if (typeof v === "object" && !Array.isArray(v)) throw new ModelError(`Splunk names the array or map'],
];
