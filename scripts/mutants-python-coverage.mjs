// Mutants for what a Python lock covers on an ordinary checkout, from the pre-publication review: a requirements file
// with no --require-hashes line is one finding for every line the lock rule refuses (src/python/soak.ts). Ruling R24
// removed the root-project exemption and its mutants; the two for its must-flag tests are at the end.
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18.
//
/** [name, file, search, replace]: as in mutants-core-workflows.mjs. */
export default [
  ["SK-002 a non-lock requirements file reported line by line", "src/python/soak.ts", "if (lines.length === 0 || !lock.problems.some((p) => p.lockRule === \"file\")) return", "if (Math.random() >= 0) return"],
  ["SK-002 a hash lock's refused lines folded into one", "src/python/soak.ts", "if (lines.length === 0 || !lock.problems.some((p) => p.lockRule === \"file\")) return", "if (lines.length === 0) return"],
  ["SK-002 a problem outside the lock rule folded into the file's finding", "src/python/soak.ts", "...lock.problems.filter((p) => p.lockRule === undefined).map(", "...lock.problems.filter((p) => p.lockRule === undefined && Math.random() < 0).map("],
  ["SK-002 the file's key not bound to each line's text", "src/python/soak.ts", "lines.map((p) => `${problemContent(p.text)}\\0${p.covers}`)", "lines.map((p) => problemContent(p.text))"],
  ["SK-002 the file's key depends on line order", "src/python/soak.ts", "`${problemContent(p.text)}\\0${p.covers}`).sort().join(", "`${problemContent(p.text)}\\0${p.covers}`).join("],
  ["SK-002 the file's key holds line numbers", "src/python/soak.ts", "lines.map((p) => `${problemContent(p.text)}\\0${p.covers}`)", "lines.map((p) => `${p.text}\\0${p.covers}`)"],
  ["SK-002 a requirements finding's key holds its fix", "src/python/soak.ts", "  const problem = withoutFix(text, fix);\n", "  const problem = text;\n"],
  ["SK-002 a requirements file's folded key holds each line's fix", "src/python/soak.ts", '.map((p) => ({ ...p, text: withoutFix(p.text, p.fix) }));', ";"],
  ["SK-002 a requirements problem's fix is not kept apart from its text", "src/python/requirements.ts", "    unit.fixes.push(fix);\n", ""],
  ["review SK-002 a lock listing the root covers the manifests under it", "src/python/discover.ts", "const covered = (dir: string): boolean => lockDirs.has(dir) || locked.has(dir);", "const covered = (dir: string): boolean => lockDirs.has(dir) || locked.has(dir) || locked.has(\".\");"],
  ["review SK-002 a workspace member the root's lock lists as editable not covered", "src/python/discover.ts", "if (s.kind === \"directory\" || s.kind === \"editable\" || s.kind === \"virtual\") locked.add(", "if (s.kind === \"directory\" || s.kind === \"virtual\") locked.add("],
];
