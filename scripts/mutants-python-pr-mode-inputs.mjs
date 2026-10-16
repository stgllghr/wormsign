// Mutants for what soak --base reads of the base for Python lock entries (src/python/base-entries.ts, src/python/soak.ts,
// src/main.ts): a base file whose checkout git attributes convert, a base whose attributes git cannot read, and a base
// past MAX_REQUIREMENT_ENTRIES count as not read; the run's --baseline counts for the base's ignorePaths; a quiet
// entry's project gone from the index is reported; one job per identity; a base .gitattributes blob a partial clone
// lacks; content-found files in the entry bound. The local-archive key is scripts/mutants-python-local-archives.mjs.
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18
// mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["PYPR inputs: a base requirements file git converts on checkout counts as read", "src/python/base-entries.ts", "out = converted(u.files) || requirementsBounded() ? undefined : u.lock;", "out = requirementsBounded() ? undefined : u.lock;"],
  ["PYPR inputs: a base TOML lock git converts on checkout counts as read", "src/python/base-entries.ts", "bytes.length > MAX_TOML_BYTES || converted([lock.file])) return undefined;", "bytes.length > MAX_TOML_BYTES) return undefined;"],
  ["PYPR inputs: base attributes git cannot read count as none set", "src/python/base-entries.ts", "return converting === undefined || files.some((f) => converting!.has(f));", "return converting !== undefined && files.some((f) => converting!.has(f));"],
  ["PYPR inputs: a base past MAX_REQUIREMENT_ENTRIES counts as read", "src/python/base-entries.ts", "      overBound = total > max;", "      overBound = Math.random() < 0;"],
  ["PYPR inputs: the run's --baseline ignorePaths do not count for the base", "src/main.ts", "                ignore = [...ofRun, ...(fromBase ?", "                ignore = [...(fromBase ? ofRun : []), ...(fromBase ?"],
  ["PYPR inputs: a quiet entry's project gone from the index is not reported", "src/python/soak.ts", 'if (!quiet || "notFound" in page) unverifiable(', "if (!quiet) unverifiable("],
  ["PYPR inputs: an identity's loud entry is checked beside its quiet one", "src/python/soak.ts", "      pending.set(once, { pkg, lock, hex, where, archives, quiet, once });", "      pending.set(quiet ? `${once}\\0quiet` : once, { pkg, lock, hex, where, archives, quiet, once });"],
  ["PYPR inputs: a base .gitattributes blob a partial clone lacks reads as no attributes", "src/tree.ts", "          if (gone.length > 0) throw new Error(", "          if (gone.length < 0) throw new Error("],
  ["PYPR inputs: a base file found by its content is not counted toward the entry bound", "src/python/base-entries.ts", '(p) => isRequirementsName(p) && readsLockAs(p, "requirements")), ...found, ...head', '(p) => isRequirementsName(p) && readsLockAs(p, "requirements")), ...head'],
];
