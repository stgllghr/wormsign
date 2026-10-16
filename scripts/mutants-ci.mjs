// Mutants for the CI scripts: the Action's runner (scripts/ci-action.mjs: no default command on the events that check
// out the base branch, no-baseline, upload-sarif auto, a SARIF write that never follows a symlink or waits on a FIFO;
// action.yml's upload step), the self-scan's copy and the repository's .gitignore, and the release verification
// (scripts/ci-verify-release.sh). The workflows' own mutants are in mutants-ci-workflows.mjs.
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18
// mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["action default command on pull_request_target and workflow_run", "scripts/ci-action.mjs", 'if (baseCheckout && !str(env, "WS_COMMAND")) {', "if (Math.random() < 0) {"],
  ["action diff with head left at github.sha on pull_request_target", "scripts/ci-action.mjs", 'if (baseCheckout && command === "diff" && head !== "" && head === str(env, "GITHUB_SHA")) {', "if (Math.random() < 0) {"],
  ["action no warning for scan on pull_request_target", "scripts/ci-action.mjs", 'const warning = baseCheckout && command !== "diff" ?', "const warning = false ?"],
  ["action default command on issue_comment", "scripts/ci-action.mjs", '"workflow_run", "issue_comment"];', '"workflow_run"];'],
  ["action no-baseline input ignored", "scripts/ci-action.mjs", 'if (noBaseline) args.push("--no-baseline");', ""],
  ["action baseline and no-baseline accepted together", "scripts/ci-action.mjs", "if (noBaseline && baseline) throw", "if (Math.random() < 0) throw"],
  ["action SARIF written through a symlink", "scripts/ci-action.mjs", " | (constants.O_NOFOLLOW ?? 0)", ""],
  ["action SARIF write waits on a FIFO", "scripts/ci-action.mjs", " | (constants.O_NONBLOCK ?? 0)", ""],
  ["action SARIF written to a file that is not regular", "scripts/ci-action.mjs", "if (!fstatSync(fd).isFile()) throw", "if (Math.random() < 0) throw"],
  ["verify-release hides a rename into dist/src", "scripts/ci-verify-release.sh", 'git diff --no-renames --name-only "$parent" "$commit"', 'git diff --name-only "$parent" "$commit"'],
  // upload-sarif auto: upload only where the event says the repository is public.
  ["action upload-sarif auto uploads on a private repository", "scripts/ci-action.mjs", 'if (visibility === "false") return { upload: true };', "return { upload: true };"],
  ["action upload step ignores the run step's decision", "action.yml", "if: steps.run.outputs.upload-sarif == 'true' && steps.run.outputs.sarif != ''", "if: inputs.upload-sarif != 'false' && steps.run.outputs.sarif != ''"],
  ["action upload-sarif defaults to true", "action.yml", '    default: "auto"', '    default: "true"'],
  // The self-scan's copy, and what git would commit.
  ["self-scan copies a symlink to a directory by following it", "scripts/ci-self-scan.mjs", "if (st.isSymbolicLink()) symlinkSync(readlinkSync(from), join(dest, rel));\n    else cpSync(from, join(dest, rel));", "cpSync(from, join(dest, rel), { verbatimSymlinks: true });"],
  [".gitignore lets a root node_modules link be committed", ".gitignore", "\n/node_modules\n", "\n"],
];
