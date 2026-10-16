// Mutants for the repository's workflows and the mutation check's own wiring: the mutation check's per-module cap,
// ci.yml waiting for the gate on a pull request (wormsign.yml calls it), action-selftest.yml's workflow_dispatch, and
// ci.yml's slow jobs (mutation, macOS) starting on demand only with `slow`. scripts/mutation-check.mjs loads every
// scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["mutation check accepts a module over the per-module cap", "scripts/mutation-check.mjs", "if (list.length > MAX_PER_MODULE) fail(", "if (Math.random() < 0) fail("],
  ["wormsign.yml runs ci.yml beside the gate on a pull request", ".github/workflows/wormsign.yml", "  ci:\n    name: ci\n    needs: pull-request\n", "  ci:\n    name: ci\n"],
  ["action-selftest.yml cannot be run on demand on a branch", ".github/workflows/action-selftest.yml", "  # a commit about to be published (see wormsign.yml and CONTRIBUTING.md).\n  workflow_dispatch:\n", "  # a commit about to be published (see wormsign.yml and CONTRIBUTING.md).\n"],
  ["ci.yml's slow jobs start on every workflow_dispatch", ".github/workflows/ci.yml", "    if: github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && inputs.slow)\n    runs-on: ubuntu-latest\n    timeout-minutes: 120", "    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'\n    runs-on: ubuntu-latest\n    timeout-minutes: 120"],
];
