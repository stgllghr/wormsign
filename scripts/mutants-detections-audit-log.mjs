// Mutants for the audit-log Sigma rules (detections/github-audit-log/*.yml, WS-AL-001 to WS-AL-004): each switches off
// one condition of a rule. scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a
// module holds at most 18 mutants.
//
// A mutant that edits a rule file also changes its sha256, so "every Sigma rule file has current Splunk and ES|QL
// reference conversions" fails for each of them as well. That is not what kills them: each one also fails the test that
// runs the rule over its examples, or the one that matches the rule against data/iocs/, as the comment says.
const AL1 = "detections/github-audit-log/ws-al-001-mass-visibility-flip.yml";
const AL2 = "detections/github-audit-log/ws-al-002-self-hosted-runner-registered.yml";
const AL3 = "detections/github-audit-log/ws-al-003-ioc-repo-created.yml";
const AL4 = "detections/github-audit-log/ws-al-004-worm-workflow-run.yml";

/** [name, file, search, replace]: as in mutants-core-workflows.mjs. */
export default [
  // release-lead's three repositories over 61 minutes (negative examples).
  ["WS-AL-001 window widened to two hours", AL1, "  timespan: 1h\n  condition:\n    field: repo", "  timespan: 2h\n  condition:\n    field: repo"],
  // mobile-app went from internal to public (positive example).
  ["WS-AL-001 internal repositories not counted", AL1, "      - internal\n  condition: selection\n---", "  condition: selection\n---"],
  // oss-maintainer's changes to private and to internal (negative examples).
  [
    "WS-AL-001 counts changes to any visibility",
    AL1,
    "    action: repo.access\n    visibility: public\n    previous_visibility:\n      - private\n      - internal\n  condition: selection\n---",
    "    action: repo.access\n    previous_visibility:\n      - private\n      - internal\n  condition: selection\n---",
  ],
  // Several actors in one organization (negative examples).
  ["WS-AL-001 counted per organization, not per actor", AL1, "    - actor\n  timespan: 1h", "    - org\n  timespan: 1h"],
  // The provisioning identity's registration (negative example).
  ["WS-AL-002 allowlist ignored", AL2, "condition: registration and not filter_allowlist", "condition: registration"],
  // A private repository named Shai-Hulud (negative example).
  ["WS-AL-003 matches private repositories", AL3, "    action: repo.create\n    visibility: public\n", "    action: repo.create\n"],
  // "Shai-Hulud: Here We Go Again!" (positive example) and the IOC test's surrounding text.
  ["WS-AL-003 contains patterns compared exactly", AL3, "    enriched_description|contains:", "    enriched_description:"],
  // Only the IOC test covers this pattern.
  ["WS-AL-003 loses a repos.json pattern", AL3, "      - A Mini Shai-Hulud has Appeared\n", ""],
  // A job on the branch shai-hulud-notes (negative example).
  ["WS-AL-004 job rule matches a worm branch as a substring", AL4, "    job_workflow_ref|endswith:", "    job_workflow_ref|contains:"],
  // A first run of one workflow and a deleted run of another in the same repository (negative examples).
  ["WS-AL-004 deletion correlation ignores the workflow", AL4, "    - repo\n    - workflow_id\n", "    - repo\n"],
  // A run deleted in the web UI (negative example).
  ["WS-AL-004 deletion without a token counts", AL4, "    action: workflows.delete_workflow_run\n    run_number: 1\n    programmatic_access_type|exists: true\n", "    action: workflows.delete_workflow_run\n    run_number: 1\n"],
  // feature/add-linter-workflow-1 (negative example).
  ["WS-AL-004 worm branch prefix matched anywhere", AL4, "head_branch|startswith: add-linter-workflow-", "head_branch|contains: add-linter-workflow-"],
  // cleanup-app[bot] deleting the new workflow's second run within the hour (negative example).
  ["WS-AL-004 deletion of any run counts", AL4, "    run_number: 1\n    programmatic_access_type|exists: true\n", "    programmatic_access_type|exists: true\n"],
  // A job on the runner named SHA1HULUD (positive example) and the IOC test.
  ["WS-AL-002 jobs on the worm's runner not matched", AL2, "      - workflows.prepared_workflow_job\n    runner_name: SHA1HULUD", "    runner_name: SHA1HULUD"],
  // The enterprise runner named SHA1HULUD (positive example) and the IOC test.
  ["WS-AL-002 enterprise runners not matched", AL2, "      - enterprise.self_hosted_runner_online\n", ""],
  // The worm's job in a repository without secrets (positive example).
  ["WS-AL-004 job rule requires secrets_passed", AL4, "    action: workflows.prepared_workflow_job\n  worm_ref_exact:", "    action: workflows.prepared_workflow_job\n    secrets_passed|exists: true\n  worm_ref_exact:"],
  // The IOC test's job_workflow_ref in the bare form, branch shai-hulud.
  ["WS-AL-004 job rule misses the bare shai-hulud ref", AL4, "      - '@shai-hulud'\n", ""],
  // A job on feature/add-linter-workflow-1, in the bare form (negative example).
  ["WS-AL-004 job rule's bare add-linter ref not anchored at the @", AL4, "      - '@add-linter-workflow-'\n", "      - 'add-linter-workflow-'\n"],
];
