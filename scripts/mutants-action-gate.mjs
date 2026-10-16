// Mutants for the Action's pull_request gate (scripts/ci-action.mjs): an empty command runs diff, scan and soak in
// that order, the step reports the worst exit code and the summed findings, one SARIF file holds each command's run
// under its own category, a command that errors does not stop the others, and on-outage reaches soak and the step
// summary. scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds
// at most 18 mutants.
//
/** [name, file, search, replace]: each keeps the script running and changes one decision. */
export default [
  ["action gate: the pull_request default is diff alone", "scripts/ci-action.mjs", "return GATE.map((command) => plan({ ...env, WS_COMMAND: command }));", 'return [plan({ ...env, WS_COMMAND: "diff" })];'],
  ["action gate: an explicit command on pull_request runs the gate", "scripts/ci-action.mjs", 'if (str(env, "WS_COMMAND") === "" && str(env, "GITHUB_EVENT_NAME") === "pull_request") return', 'if (str(env, "GITHUB_EVENT_NAME") === "pull_request") return'],
  ["action gate: soak runs before scan", "scripts/ci-action.mjs", 'export const GATE = ["diff", "scan", "soak"];', 'export const GATE = ["diff", "soak", "scan"];'],
  ["action gate: exit-code is the last command's, not the worst", "scripts/ci-action.mjs", "const code = Math.max(...done.map((d) => d.code));", "const code = done[done.length - 1].code;"],
  ["action gate: findings counts the first command only", "scripts/ci-action.mjs", "const findings = reports.reduce((n, r) => n + activeFindings(r.report), 0);", "const findings = activeFindings(reports[0].report);"],
  ["action gate: every run has one category", "scripts/ci-action.mjs", "automationDetails: { id: `wormsign-${command}/` }", 'automationDetails: { id: "wormsign/" }'],
  ["action gate: the SARIF file holds the first command's run only", "scripts/ci-action.mjs", "writeReport(sarif, gate ? ", "writeReport(sarif, false ? "],
  ["action gate: a single command's SARIF gets a category", "scripts/ci-action.mjs", "writeReport(sarif, gate ? ", "writeReport(sarif, true ? "],
  ["action gate: an unreadable base baseline stops the gate", "scripts/ci-action.mjs", "done.push(await runCommand(env, step, work, gate));", "done.push(await runCommand(env, step, work, false));"],
  ["action gate: one command's error drops the others' SARIF", "scripts/ci-action.mjs", "    if (reports.length === 0) {", "    if (reports.length < done.length) {"],
  ["action: on-outage warn does not reach soak", "scripts/ci-action.mjs", '    if (onOutage === "warn") args.push("--on-outage", "warn");\n', ""],
  ["action: a mistyped on-outage is accepted", "scripts/ci-action.mjs", "if (!ON_OUTAGE.includes(onOutage)) throw", "if (Math.random() < 0) throw"],
  ["action: an UNVERIFIED note is not annotated", "scripts/ci-action.mjs", 'if (typeof note === "string" && note.startsWith(UNVERIFIED)) console.log(', "if (Math.random() < 0) console.log("],
  ["action: the UNVERIFIED line does not reach the step summary", "scripts/ci-action.mjs", 'if (summary !== "" && env.GITHUB_STEP_SUMMARY) appendFileSync(', "if (Math.random() < 0) appendFileSync("],
  ["action: the step summary carries HTML raw", "scripts/ci-action.mjs", '.replace(/</g, "&lt;")', ""],
];
