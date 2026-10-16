// Mutants for the requirements-file reader (src/python/requirements.ts): hashes, includes, --require-hashes, line
// separators, a comment or a glued "\" on a continued line, and its caps. scripts/mutation-check.mjs loads every
// scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["PY requirements: an unhashed requirement line is accepted", "src/python/requirements.ts", "if (sha256.length === 0) {", "if (Math.random() < 0) {"],
  ["PY requirements: line separators pip and uv split differently pass", "src/python/requirements.ts", "const sepAt = text.search(SEPARATOR);", "const sepAt = Math.random() < 0 ? text.search(SEPARATOR) : -1;"],
  ["PY requirements: -r/-c includes are not followed", "src/python/requirements.ts", 'visit(incRel, constraint || inc.name === "constraint", [...chain, incRel]);', 'if (Math.random() < 0) visit(incRel, constraint || inc.name === "constraint", [...chain, incRel]);'],
  ["PY requirements: --require-hashes is not required", "src/python/requirements.ts", "if (rootParsed && !unit.empty && unit.requireHashes === undefined) {", "if (Math.random() < 0) {"],
  ["PY requirements: any long option is read as --hash", "src/python/requirements.ts", "name = Object.hasOwn(LONG, flag) ? LONG[flag] : undefined;", 'name = Object.hasOwn(LONG, flag) ? LONG[flag] : "hash";'],
  ["PY requirements: an include outside the root is followed", "src/python/requirements.ts", 'if (incRel === "" || incRel === ".." || incRel.startsWith("../") || resolve(root, incRel) !== abs) {', "if (Math.random() < 0) {"],
  ["PY requirements: a value attached to -r or -c is read as pip reads it", "src/python/requirements.ts", "if (tok.length > 2) return {", "if (tok.length > 2) value = tok.slice(2);\n      if (Math.random() < 0) return {"],
  ["PY requirements: an include path with a # is followed", "src/python/requirements.ts", "if (target.includes(\"#\")) {", "if (Math.random() < 0) {"],
  ["PY requirements: -r in a file reached through -c is followed", "src/python/requirements.ts", "if (constraint && inc.name === \"requirement\") {", "if (Math.random() < 0) {"],
  ["PY requirements: --require-hashes in a file reached through -c counts", "src/python/requirements.ts", "else if (constraint) constraintRequireHashes ??= { file: fileRel, line: l.line };", "else if (Math.random() < 0) constraintRequireHashes ??= { file: fileRel, line: l.line };"],
  ["PY requirements: a sha384 or sha512 beside a sha256 is accepted", "src/python/requirements.ts", "else if (algorithm !== \"sha256\") bad =", "else if (Math.random() < 0) bad ="],
  ["PY requirements: problems are not capped", "src/python/requirements.ts", "if (unit.problems.length >= MAX_UNIT_PROBLEMS) {", "if (Math.random() < 0) {"],
  ["PY requirements: the bytes a unit reads are not capped", "src/python/requirements.ts", "if (bytes > MAX_REQUIREMENTS_BYTES) {", "if (Math.random() < 0) {"],
  ["PY requirements: the lines a unit reads are not capped", "src/python/requirements.ts", "const pre = preprocessRequirements(decoded.text, MAX_UNIT_LINES - linesRead);", "const pre = preprocessRequirements(decoded.text);"],
  ["PY requirements: comments are dropped by a quadratic regex", "src/python/requirements.ts", "return strip(t.slice(0, end), isPyWs);", "return t.replace(/(^|[\\t ]+)#.*$/s, \"\").replace(/^[\\t ]+|[\\t ]+$/g, \"\");"],
  ["PY requirements: a hashed file lacking --require-hashes is told only to regenerate", "src/python/requirements.ts", 'const hashed = !unit.lockRule.includes("line");', "const hashed = false;"],
  ["PY requirements: a file with an unhashed line is told the --require-hashes line is enough", "src/python/requirements.ts", 'const hashed = !unit.lockRule.includes("line");', "const hashed = true;"],
  ["PY requirements: a comment on a continued line is read as pip joins it", "src/python/requirements.ts", "  if (commentStart(strip(l, isBackslash)) !== -1) return { problem: CONTINUED_COMMENT,", "  if (Math.random() < 0) return { problem: CONTINUED_COMMENT,"],
];
