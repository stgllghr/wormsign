// Mutants for fixes made for code scanning alerts: a package name kept as one path segment of soak's registry URL
// (src/soak.ts).
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18
// mutants.
//
/** [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. */
export default [
  ["soak registry URL encodes only a name's first slash", "src/soak.ts", 'name.replaceAll("/", "%2F")', 'name.replace("/", "%2F")'],
];
