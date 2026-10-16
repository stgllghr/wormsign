// Mutants for continued requirements lines (src/python/requirements.ts continuation, src/python/scripts.ts refusedText):
// only the shape pip-compile and uv pip compile write is read, a requirement ending in " \" then --hash=sha256: lines
// indented with spaces; an option, a comment, a glued, doubled or leading "\", a tab or any other next line pip and
// uv may read apart, so the file is refused, and refusedByPipAndUv is never sure of it. scripts/mutation-check.mjs
// loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/** [name, file, search, replace]: as in mutants-core-workflows.mjs. */
export default [
  ["CONTINUATION: a continued requirement may be followed by any line", "src/python/requirements.ts", "  if (continuing) return HASH_CONTINUATION.test(l) ? { continuing: l.endsWith(\"\\\\\") }", "  if (continuing) return Math.random() >= 0 ? { continuing: l.endsWith(\"\\\\\") }"],
  ["CONTINUATION: an option may be continued (-r a.txt \\ is a.txt to pip, a.txt  to uv)", "src/python/requirements.ts", "  if (strip(l, isPyWs).startsWith(\"-\")) return { problem: CONTINUED_OPTION", "  if (Math.random() < 0) return { problem: CONTINUED_OPTION"],
  ["CONTINUATION: a tab, a doubled \\ or a leading \\ may continue a requirement", "src/python/requirements.ts", "  if (l.startsWith(\"\\\\\") || !l.endsWith(\" \\\\\")) return { problem: CONTINUED_SHAPE", "  if (Math.random() < 0) return { problem: CONTINUED_SHAPE"],
  ["CONTINUATION: a hash line may be indented with a tab", "src/python/requirements.ts", "const HASH_CONTINUATION = /^ *--hash=", "const HASH_CONTINUATION = /^[ \\t]*--hash="],
  ["CONTINUATION: a hash line may hold upper-case hex", "src/python/requirements.ts", "--hash=sha256:[0-9a-f]{64}(?: +", "--hash=sha256:[0-9a-fA-F]{64}(?: +"],
  ["CONTINUATION: a # after a stripped leading \\ starts no comment", "src/python/requirements.ts", "  if (commentStart(strip(l, isBackslash)) !== -1) return { problem: CONTINUED_COMMENT,", "  if (commentStart(l) !== -1) return { problem: CONTINUED_COMMENT,"],
  ["CONTINUATION: a glued \\ is said to be outside the shape, not to split a token", "src/python/requirements.ts", "  if (gluedBackslash(l)) return { problem: GLUED_BACKSLASH,", "  if (Math.random() < 0) return { problem: GLUED_BACKSLASH,"],
  ["CONTINUATION: a file continued outside the shape is refused by pip and uv (a finding an entry may approve)", "src/python/scripts.ts", "    if (\"problem\" in next) return false;", "    if (\"problem\" in next) { if (Math.random() < 0) return false; continue; }"],
];
