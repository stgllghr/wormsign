// Mutants for the PyPI soak check (src/python/soak.ts): each locked file bound by sha256 and aged, pip's any-hash rule,
// lock URLs and file names, indexes a lock records, reader problems keyed on their content, and local sources.
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18
// mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["PY soak: age by the release's first file instead of the youngest locked file", "src/python/soak.ts", "const publishedT = youngestT;", "const publishedT = firstT;"],
  ["PY soak: a file without a sha256 is not refused", "src/python/soak.ts", "if (unbound.length > 0) return", "if (Math.random() < 0) return"],
  ["PY soak: a locked hash missing from the index is skipped", "src/python/soak.ts", "        problems.push(`${labelOf(job, f)}: ${b.problem}`);", '        if (!b.problem.startsWith("not on the index")) problems.push(`${labelOf(job, f)}: ${b.problem}`);'],
  ["PY soak: a quarantined project is checked as active", "src/python/soak.ts", 'if (st.state === "quarantined") {', 'if (st.state === "quarantined" && Math.random() < 0) {'],
  ["PY soak: a registry other than --pypi-index is accepted", "src/python/soak.ts", 'if (s.value !== "" && normalizeIndexUrl(s.value) !== index) return', 'if (s.value !== "" && Math.random() < 0) return'],
  ["PY soak: a lock url other than the index's is accepted", "src/python/soak.ts", "if (f.locator.url !== undefined && !sameFileUrl(f.locator.url, ix.url)) {", "if (f.locator.url !== undefined && Math.random() < 0) {"],
  ["PY soak: a package locked only as an sdist is not WS-SK-005", "src/python/soak.ts", 'if (kinds.length > 0 && kinds.every((k) => k === "sdist")) {', "if (Math.random() < 0) {"],
  ["PY soak: local sources are not checked", "src/python/soak.ts", "if (LOCAL_TREES.has(pkg.source.kind)) {", "if (LOCAL_TREES.has(pkg.source.kind) && Math.random() < 0) {"],
  ["PY soak: a file with a hash other than sha256 beside it is accepted", "src/python/soak.ts", "if (mixed.length > 0) {", "if (Math.random() < 0) {"],
  ["PY soak: a lock file name must be the index's file name exactly", "src/python/soak.ts", ".find((n) => !namesIndexFile(n, ix));", ".find((n) => n !== ix.filename);"],
  ["PY soak: a lock file name with another wheel's tags is accepted", "src/python/soak.ts", 'return a.kind === "wheel" ? wheelTags(name) === wheelTags(ix.filename) : name.endsWith(".zip") === ix.filename.endsWith(".zip");', "return true;"],
  ["PY soak: an index the lock records is not checked when the package is sendable", "src/python/soak.ts", "if (pkg.lockIndex !== undefined && normalizeIndexUrl(pkg.lockIndex) !== index) return", "if (pkg.lockIndex !== undefined && Math.random() < 0) return"],
  ["PY soak: a pylock directory's subdirectory is not part of the checked path", "src/python/soak.ts", "const dir = localSourcePath(pkg.source);", "const dir = pkg.source.value;"],
  ["PY soak: one identity is checked once whatever its send verdict", "src/python/soak.ts", 'const once = `${hex}\\0${pkg.sendable}\\0${pkg.unsent ?? ""}`;', "const once = hex;"],
  ["PY soak: a file exactly as old as the soak is too new", "src/python/soak.ts", "    if (age < opts.minAgeMs) {", "    if (age <= opts.minAgeMs) {"],
  ["PY soak: a reader problem's key moves with its position", "src/python/soak.ts", "keyDigest(`${problemContent(problem)}\\0${covers}`)", "keyDigest(`${problem}\\0${covers}`)"],
  ["PY soak: a reader problem's key leaves out the content it covers", "src/python/soak.ts", "keyDigest(`${problemContent(problem)}\\0${covers}`)", "keyDigest(problemContent(problem))"],
];
