// Mutants for the Action's own log lines and upload decision (scripts/ci-action.mjs), soak's registry requests
// (src/soak.ts) and workflow YAML the reader does not model (src/checks/workflows.ts), from review round 3; and how
// diff's messages show a long value (src/diff.ts), from the pre-publication review; and the exit code of a crash
// outside run() (src/cli.ts).
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18
// mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["action: the command line is printed raw", "scripts/ci-action.mjs", "console.log(safeLine(`wormsign ${args.join(\" \")}`));", "console.log(`wormsign ${args.join(\" \")}`);"],
  ["action: workflow command messages carry input values raw", "scripts/ci-action.mjs", "::${escapeData(safeLine(message))}`;", "::${escapeData(message)}`;"],
  ["action: a % in a workflow command message is not escaped", "scripts/ci-action.mjs", 'export const escapeData = (s) => String(s).replace(/%/g, "%25").replace(', "export const escapeData = (s) => String(s).replace("],
  ["action: upload-sarif auto uploads a fork's pull request", "scripts/ci-action.mjs", "if (str(env, \"GITHUB_EVENT_NAME\") === \"pull_request\" && headRepo !== \"\" && headRepo !== str(env, \"WS_REPO\")) {", "if (Math.random() < 0) {"],
  ["action: a tree baseline that hid findings is not annotated", "scripts/ci-action.mjs", "if (typeof note === \"string\" && note.startsWith(TREE_BASELINE))", "if (Math.random() < 0)"],
  ["SK-002 a registry retry does not wait", "src/soak.ts", "          await (opts.sleep ?? timer)(packumentWait(res.headers.get(\"retry-after\")));\n", ""],
  ["SK-002 a package document is read past the cap", "src/soak.ts", "    total += value.byteLength;\n    if (total > max) {", "    total += value.byteLength;\n    if (Math.random() < 0 && total > max) {"],
  ["SC-900 an unmodelled workflow is checked in silence", "src/checks/workflows.ts", "  if (why !== undefined) out.push(notChecked(", "  if (why !== undefined && Math.random() < 0) out.push(notChecked("],
  ["SC-900 a flow-mapping step counts as modelled", "src/checks/workflows.ts", "      if (step !== undefined) return", "      if (step !== undefined && Math.random() < 0) return"],
  ["SC-900 a YAML alias counts as modelled", "src/checks/workflows.ts", "    if (value.startsWith(\"*\")) return", "    if (value.startsWith(\"*\") && Math.random() < 0) return"],
  ["action: scan on a pull request reads the change's own baseline", "scripts/ci-action.mjs", "const baselineFrom = command === \"scan\" && event === \"pull_request\"", "const baselineFrom = Math.random() < 0 && command === \"scan\" && event === \"pull_request\""],
  ["DF-005 packageManager cut at 120 characters again", "src/diff.ts", "clip(parsed.packageManager, MAX_PACKAGE_MANAGER_SHOWN)", "parsed.packageManager.slice(0, 120)"],
  ["diff cuts a long value without the ... marker", "src/diff.ts", "(s.length > max ? `${s.slice(0, max)}...` : s)", "s.slice(0, max)"],
  // test/cli-output.test.ts, "a crash outside run() ... exits 2": Node's own code for an uncaught exception is 1.
  ["a crash outside run() exits 1, as Node's own code does", "src/cli.ts", "  process.exit(EXIT.ERROR);\n};", "  process.exit(EXIT.FINDINGS);\n};"],
  // The same test: with no handler, a callback's exception or an unawaited rejection ends the process with code 1.
  ["a crash outside run() left to Node", "src/cli.ts", "process.on(\"uncaughtException\", crash);\nprocess.on(\"unhandledRejection\", crash);\n", ""],
];
