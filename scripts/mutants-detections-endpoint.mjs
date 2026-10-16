// Mutants for the endpoint Sigma rules (detections/sigma/*.yml, WS-EP-001 and WS-EP-002): each switches off one branch
// or filter of a rule. scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a
// module holds at most 18 mutants.
//
// A mutant that edits a rule file also changes its sha256, so "every Sigma rule file has current Splunk and ES|QL
// reference conversions" fails for each of them as well. That is not what kills them: each one also fails the test that
// runs the rule over its examples, or the one that matches the rule against data/iocs/, as the comment says.
const EP1 = "detections/sigma/ws-ep-001-node-spawns-trufflehog-or-bun.yml";
const EP2 = "detections/sigma/ws-ep-002-node-runs-repository-hook-loader.yml";

/** [name, file, search, replace]: as in mutants-core-workflows.mjs. */
export default [
  // The CI secret-scanning job's TruffleHog process (negative example).
  ["WS-EP-001 shell branch needs no install context", EP1, "(parent_shell and install_context and ((child_bun", "(parent_shell and ((child_bun"],
  // The CI job's shell, started by bash (negative example).
  ["WS-EP-001 shell-from-node branch needs no node parent", EP1, "    ParentImage|endswith:\n      - '/node'\n      - '/bun'\n      - '\\node.exe'\n      - '\\bun.exe'\n", ""],
  // The shell node started (positive example).
  ["WS-EP-001 shell-from-node branch dropped", EP1, " or shell_scan_from_node or payload_by_bun or worm_cache", " or payload_by_bun or worm_cache"],
  // TruffleHog started by bun outside ~/.truffler-cache (positive example).
  ["WS-EP-001 TruffleHog started by bun not matched", EP1, "(child_trufflehog and (parent_node or parent_bun))", "(child_trufflehog and parent_node)"],
  // pm2's daemon and nodemon starting Bun apps (negative examples).
  ["WS-EP-001 process managers not filtered", EP1, " and not filter_process_manager", ""],
  // Bun run through bash and nohup on .claude/math_init.js (positive example).
  ["WS-EP-001 payload names not matched", EP1, " or payload_by_bun", ""],
  // A Claude Code hook running .claude/hooks/format.mjs (negative example).
  ["WS-EP-002 any script under .claude matched", EP2, "      - '.claude/setup.mjs'\n", "      - '.claude/'\n"],
  // node starting bun on ./stage2.js --version (positive example): the flag must follow the binary.
  ["WS-EP-001 version filter takes any trailing --version", EP1, "      - 'bun --version'\n", "      - ' --version'\n"],
  // oven-sh/setup-bun's bun --revision, and the bun npm package's bun --version (negative examples).
  ["WS-EP-001 version checks not filtered", EP1, " and not filter_bun_version_check", ""],
  // A dependency's node install.js run by Bun standing in for node (negative example).
  ["WS-EP-001 Bun run as node not filtered", EP1, "(child_bun and (loader_script or not filter_bun_as_node))", "child_bun"],
  // The worm's node setup_bun.js and node setup.mjs run by Bun standing in for node (positive examples).
  ["WS-EP-001 Bun run as node hides the worm's loader", EP1, "(loader_script or not filter_bun_as_node)", "not filter_bun_as_node"],
  // pm2's daemon on Windows, node ...\pm2\lib\Daemon.js, starting a Bun app (negative example).
  ["WS-EP-001 pm2 daemon on Windows not filtered", EP1, "      - 'pm2\\lib\\Daemon.js'\n", ""],
  // pm2's daemon as recorded at exec time, node .../pm2/lib/Daemon.js, starting a Bun app (negative example).
  ["WS-EP-001 pm2 daemon at exec time not filtered", EP1, "      - 'pm2/lib/Daemon.js'\n", ""],
];
