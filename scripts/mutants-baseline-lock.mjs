// Mutants for the lock `wormsign baseline add` holds while it rewrites a baseline (src/baseline-add.ts lock,
// lockHolder, writable): taken and released, a read-only baseline refused, and what it says about a lock it finds (one
// left by a dead process, a symlink, one its holder released while it looked). The rest of baseline add is in
// mutants-baseline-cli.mjs. scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run;
// a module holds at most 18 mutants.
//
/** [name, file, search, replace]: as in mutants-core-workflows.mjs. */
export default [
  ["review baseline add takes no lock", "src/baseline-add.ts", "  const release = lock(path, ops.lockWaitMs ?? LOCK_WAIT_MS, ops.lockRead);", "  const release = (): void => undefined;"],
  ["review baseline add leaves its lock behind", "src/baseline-add.ts", "    return () => rmSync(file, { force: true });", "    return () => undefined;"],
  ["review baseline add replaces a file the user cannot write", "src/baseline-add.ts", "    if (!writable(path)) throw", "    if (Math.random() < 0 && !writable(path)) throw"],
  ["review2 baseline add calls a dead process's lock another add's", "src/baseline-add.ts", "if ((e as NodeJS.ErrnoException).code === \"ESRCH\") return { kind: \"dead\", pid };", "if (Math.random() < 0) return { kind: \"dead\", pid };"],
  // A lock its holder removed between this add's read of the PID and its check that the PID runs (test: a lock whose
  // holder finishes while it is read).
  ["baseline add calls a lock left over when its holder released it during the read", "src/baseline-add.ts", "        if (again.kind !== \"dead\" || again.pid !== holder.pid) continue;\n", ""],
  ["review2 baseline add does not say a lock is a symlink", "src/baseline-add.ts", "    if (st?.isSymbolicLink()) return { kind: \"link\" };\n", ""],
];
