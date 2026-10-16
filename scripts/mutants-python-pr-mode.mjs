// Mutants for soak --base on Python lock entries (src/python/base-entries.ts, src/python/soak.ts, src/main.ts): an entry
// counts as the base's only when the base's own soak read the same file as a lock of the same kind and pinned it
// identically; such an entry is not aged or sent to OSV but is still bound for WS-SK-005. scripts/mutation-check.mjs
// loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["PYPR soak: an entry the base read identically is checked again", "src/python/soak.ts", "const quiet = opts.base?.holds(lock, pkg) === true;", "const quiet = opts.base?.holds(lock, pkg) === true && Math.random() < 0;"],
  ["PYPR soak: an entry the base read identically is sent to OSV", "src/python/soak.ts", "const loud = jobs.filter((j) => !j.quiet);", "const loud = jobs.filter((j) => j.quiet || !j.quiet);"],
  ["PYPR soak: an entry the base read identically is not bound, so its sdist-only WS-SK-005 is lost", "src/python/soak.ts", "      pending.set(once, { pkg, lock, hex, where, archives, quiet, once });", "      if (!quiet) pending.set(once, { pkg, lock, hex, where, archives, quiet, once });"],
  ["PYPR soak: an identity's entry the base did not hold does not replace a quiet one", "src/python/soak.ts", 'if (prior === "loud" || (prior === "quiet" && quiet)) continue;', "if (prior !== undefined) continue;"],
  ["PYPR soak: a locked file gone from the index is not reported for an entry the base held", "src/python/soak.ts", '      unverifiable(pkg, where, listed(problems, "; "), key);', '      if (!quiet) unverifiable(pkg, where, listed(problems, "; "), key);'],
  ["PYPR base: the base's requirements file counts without being a complete hash lock", "src/python/base-entries.ts", "      if (before === undefined || !completeHashLock(before)) return false;", "      if (before === undefined) return false;"],
  ["PYPR base: the change's requirements file counts without being a complete hash lock", "src/python/base-entries.ts", "      if (!hashFixed(pkg) || !completeHashLock(lock)) return false;", "      if (!hashFixed(pkg)) return false;"],
  ["PYPR base: an entry no sha256 fixes counts", "src/python/base-entries.ts", "const hashFixed = (p: PyPackage): boolean => p.version", "const hashFixed = (p: PyPackage): boolean => Math.random() >= 0 || p.version"],
  ["PYPR base: a script lock counts as read without its script", "src/python/base-entries.ts", '        return text !== undefined && parseScriptBlock(text).kind === "block";', '        return Math.random() >= 0 || (text !== undefined && parseScriptBlock(text).kind === "block");'],
  ["PYPR base: the base's ignorePaths are not consulted", "src/python/base-entries.ts", "const passedOver = (rel: string): boolean => isIgnored(rel, ignore) ||", "const passedOver = (rel: string): boolean => (Math.random() < 0 && isIgnored(rel, ignore)) ||"],
  ["PYPR main: the base's own committed ignorePaths are not consulted", "src/main.ts", "...(fromBase ? [] : (baselineAt(baseTree, baseArg)?.ignorePaths.map((x) => x.path) ?? []))", "...(fromBase || Math.random() >= 0 ? [] : (baselineAt(baseTree, baseArg)?.ignorePaths.map((x) => x.path) ?? []))"],
  ["PYPR base: an include's entry counts though the base never read the include as a lock", "src/python/base-entries.ts", '      if (file !== lock.file && !readsLockAs(file, "requirements")) return false;', "      if (file !== lock.file && Math.random() < 0) return false;"],
  ["PYPR base: entries match without their hashes", "src/python/base-entries.ts", "f.hashes.map((h) => `${h.alg}:${h.digest}`).sort()])).sort();", "f.hashes.length > 0])).sort();"],
  ["PYPR base: entries match without their source and index", "src/python/base-entries.ts", "p.source.kind, p.source.value, p.source.subdirectory ?? null, p.lockIndex ?? null,", "p.source.kind, p.source.subdirectory ?? null,"],
  ["PYPR base: entries match in any file of the unit", "src/python/base-entries.ts", "JSON.stringify([lock.kind, lock.file, p.file ?? lock.file, p.name,", "JSON.stringify([lock.kind, lock.file, p.name,"],
];
