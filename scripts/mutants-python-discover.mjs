// Mutants for Python discovery's content pass (src/python/discover.ts, scripts.ts, requirements.ts): which files it
// opens, padded and large files, files pip and uv would both refuse, a requirements file's own index options, and the
// --hash rule. scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module
// holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["PY discover: script lock path from .py only", "src/python/scripts.ts", "export const scriptLockPath = (script: string): string => `${script}.lock`;", 'export const scriptLockPath = (script: string): string => `${script.replace(/\\.pyw?$/i, "")}.py.lock`;'],
  ["PY discover: requirements discovery by name only", "src/python/discover.ts", "if (whole && maybeRequirements && !reqByName && looksLikeRequirements(bytes)) {", "if (Math.random() < 0) {"],
  ["PY discover: a requirements file's own index options do not stop its names being sent", "src/python/discover.ts", "unsentFor(unit.file, true, unit.indexOptions)", "unsentFor(unit.file, true)"],
  ["PY requirements: a line whose options were not all read is not listed as a possible index", "src/python/requirements.ts", "        unread(fileRel, l.line, res.option);\n", ""],
  ["PY discover: the content pass opens every file", "src/python/discover.ts", "if (!byName && lockBeside === undefined && !isContentCandidate(name)) continue;", "if (Math.random() < 0) continue;"],
  ["PY discover: a candidate over 1 MiB is not searched past its first line", "src/python/discover.ts", "const scan = scanLargeFile(path, MAX_SCRIPT_BYTES);", "const scan = { tag: false, requirements: false };"],
  ["PY discover: a lock with a reader of its own beside a same-named file is read as a script lock", "src/python/discover.ts", "    if (ownReader(posix.basename(lock))) continue;\n", ""],
  ["PY discover: a file with a lock beside it is not read in full", "src/python/discover.ts", "const full = byName || lockBeside !== undefined;", "const full = byName;"],
  ["PY discover: a file pip and uv would both refuse is read as requirements", "src/python/discover.ts", "if (refusedByPipAndUv(bytes)) problem(rel, UNREAD_BY_CONTENT, bytesDigest(bytes));", "if (Math.random() < 0) problem(rel, UNREAD_BY_CONTENT, bytesDigest(bytes));"],
  ["PY scripts: a coding line naming a codec Python lacks hides a file's text", "src/python/scripts.ts", "if (OPAQUE_CODECS.has(codec)) return {", 'if (OPAQUE_CODECS.has(codec) || !["utf_8", "utf8", "latin_1", "ascii"].includes(codec)) return {'],
  ["PY scripts: a file with an opaque coding line can count as refused", "src/python/scripts.ts", "  if (\"opaque\" in view) return false;", "  if (\"opaque\" in view) return refusedText(buf.toString(\"latin1\"));"],
  [
    "PY discover: an abbreviated or space-separated --hash is not seen",
    "src/python/scripts.ts",
    "const HASH_OPTION = /(?:^|\\s)--h(?:a(?:s(?:h)?)?)?(?:=\\s*|\\s+)(?:[A-Za-z0-9_]+:[0-9A-Fa-f]{8}|\\S*\\$\\{[A-Z0-9_]+\\})/;",
    "const HASH_OPTION = /(?:^|\\s)--hash=(?:[A-Za-z0-9_]+:[0-9A-Fa-f]{8}|\\S*\\$\\{[A-Z0-9_]+\\})/;",
  ],
  [
    "PY discover: a hash option needs no value (webpack --hash is a requirements file)",
    "src/python/scripts.ts",
    "const HASH_OPTION = /(?:^|\\s)--h(?:a(?:s(?:h)?)?)?(?:=\\s*|\\s+)(?:[A-Za-z0-9_]+:[0-9A-Fa-f]{8}|\\S*\\$\\{[A-Z0-9_]+\\})/;",
    "const HASH_OPTION = /(?:^|\\s)--h(?:a(?:s(?:h)?)?)?(?:=|\\s)/;",
  ],
  [
    "PY discover: a hash pip expands from ${NAME} is not seen",
    "src/python/scripts.ts",
    "const HASH_OPTION = /(?:^|\\s)--h(?:a(?:s(?:h)?)?)?(?:=\\s*|\\s+)(?:[A-Za-z0-9_]+:[0-9A-Fa-f]{8}|\\S*\\$\\{[A-Z0-9_]+\\})/;",
    "const HASH_OPTION = /(?:^|\\s)--h(?:a(?:s(?:h)?)?)?(?:=\\s*|\\s+)[A-Za-z0-9_]+:[0-9A-Fa-f]{8}/;",
  ],
  ["PY discover: the requirement part of a line is searched for options", "src/python/scripts.ts", "const at = line.search(OPTION_START);", "const at = line.search(/-/);"],
  ["PY discover: the content rule is quadratic on a run of whitespace", "src/python/scripts.ts", "const COMMENT_LINE = /^\\s*#/;", "const COMMENT_LINE = /\\s*#/;"],
  ["PY discover: the content rule is quadratic on a run of backslashes", "src/python/scripts.ts", "return line.slice(a, b);", 'return line.replace(/^\\\\+|\\\\+$/g, "");'],
  ["PY discover: a UTF-16 requirements file is searched as bytes", "src/python/scripts.ts", 'if (starts(0xff, 0xfe)) return { text: new TextDecoder("utf-16le").decode(buf.subarray(2)) };', 'if (Math.random() < 0) return { text: new TextDecoder("utf-16le").decode(buf.subarray(2)) };'],
];
