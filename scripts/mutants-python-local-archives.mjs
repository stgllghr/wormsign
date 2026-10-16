// Mutants for the key of a requirements line naming a local file (src/python/requirements.ts localKey, localFileState,
// src/python/soak.ts readerProblemFindings, src/baseline.ts applyBaseline): it covers the file's bytes, beside the
// requirements file, from the root and from the top-level file's and each include's directory, a file: URL's path
// without its query, and a symlink's target; a file soak cannot pin by its content (outside the root, behind a link
// that leaves the root or does not resolve, a backslash, too large, unreadable) gets no key; a ".." after a directory
// name in a local or include path is refused (climbsAfterName). Which lines a baseline may approve is
// scripts/mutants-python-baselinable.mjs.
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18
// mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["LOCAL: a line naming a local archive is keyed on its text alone", "src/python/requirements.ts", "problem(fileRel, l.line, pin.problem, LOCK_REMEDIATION, local.covers, {", "problem(fileRel, l.line, pin.problem, LOCK_REMEDIATION, lineSha, {"],
  ["LOCAL: a local archive's key carries no digest of its bytes", "src/python/requirements.ts", 'return "sha256" in r ? { key: `sha256:${r.sha256}${via}` }', 'return "sha256" in r ? { key: `sha256${via}` }'],
  ["LOCAL: a local archive beside the requirements file is not covered", "src/python/requirements.ts", '["beside", inside(posix.normalize(posix.join(posix.dirname(fileRel), target)))],', '["beside", undefined],'],
  ["LOCAL: a local archive from the root is not covered", "src/python/requirements.ts", '["root", inside(posix.normalize(target))],', '["root", undefined],'],
  ["LOCAL: a file: URL's archive is not covered", "src/python/requirements.ts", "  if (/^file:/i.test(ref)) {", "  if (Math.random() < 0 && /^file:/i.test(ref)) {"],
  ["LOCAL: a file: URL's query is read as part of its path", "src/python/requirements.ts", '.split("#")[0]!.split("?")[0]!;', '.split("#")[0]!;'],
  ["LOCAL: a symlink's target is not in the key", "src/python/requirements.ts", 'const via = target === rel ? "" : ` via ${target}`;', 'const via = "";'],
  ["LOCAL: a symlink out of the root is keyed by what it leads to", "src/python/requirements.ts", 'if (inRoot === ".." || inRoot.startsWith(`..${sep}`) || isAbsolute(inRoot)) return { unkeyable:', 'if (Math.random() < 0 && (inRoot === ".." || inRoot.startsWith(`..${sep}`) || isAbsolute(inRoot))) return { unkeyable:'],
  ["LOCAL: a backslash path is keyed as missing", "src/python/requirements.ts", '  if (rel.includes("\\\\")) return { unkeyable:', '  if (Math.random() < 0 && rel.includes("\\\\")) return { unkeyable:'],
  ["LOCAL: a file over the read bound is keyed", "src/python/requirements.ts", "    if (st.size > maxBytes) return { unkeyable:", "    if (st.size < 0) return { unkeyable:"],
  ["LOCAL: a local file is not keyed at the top-level file's directory", "src/python/requirements.ts", ".filter((d) => d !== \".\" && d !== posix.dirname(fileRel))", ".filter(() => Math.random() < 0)"],
  ["LOCAL: a local file is keyed at the top-level file's directory only, not an including file's", "src/python/requirements.ts", "...[...new Set(chain.map((c) => posix.dirname(c)))]", "...[...new Set([chain[0]!].map((c) => posix.dirname(c)))]"],
  ["LOCAL: an include path with .. after a directory name is followed as text", "src/python/requirements.ts", "        if (climbsAfterName(target)) {", "        if (Math.random() < 0) {"],
  ["LOCAL: a local file path with .. after a directory name is keyed as text", "src/python/requirements.ts", "          if (\"local\" in pin && pin.local !== undefined && climbsAfterName(pin.local)) {", "          if (Math.random() < 0) {"],
  ["LOCAL: a .. with no directory name before it is refused too", "src/python/requirements.ts", "      if (named) return true;", "      return true;"],
];
