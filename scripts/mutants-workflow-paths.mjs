// Mutants for how the workflow checks read an expression's property paths (src/checks/workflows.ts readPaths,
// expressionEnd, headEnvNames, COMPUTED_GITHUB): as GitHub's lexer reads them (whitespace, case, ['x'], a `}}` in a
// string literal), a head ref through an env: variable or a value below its key, and a ref computed from the github
// context (WS-GH-003, WS-GH-004, WS-GH-005). scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and
// says how they run; a module holds at most 18 mutants.
//
/** [name, file, search, replace]: as in mutants-core-workflows.mjs. */
export default [
  ["review GH-005 a }} in a string literal ends the expression a secret is read in", "src/checks/workflows.ts", "    const end = expressionEnd(text, i);\n    const j = end < 0 ? text.length : end;\n    const body = pathsOf(", "    const end = text.indexOf(\"}}\", i + 3);\n    const j = end < 0 ? text.length : end;\n    const body = pathsOf("],
  ["review GH-003 whitespace around . kept in a property path", "src/checks/workflows.ts", "if (next !== undefined && !PATH_PUNCTUATION.has(next) && !PATH_PUNCTUATION.has(last)) {", "if (next !== undefined) {"],
  ["review GH-003 property paths matched case-sensitively", "src/checks/workflows.ts", "  const e = expr.toLowerCase();", "  const e = expr;"],
  ["review GH-003 a head ref matched on the text as written", "src/checks/workflows.ts", "        const t = readPaths(text).paths;", "        const t = text.replace(INDEX_SYNTAX, \".$2\");"],
  ["review GH-004 a matrix runner matched on the text as written", "src/checks/workflows.ts", "texts.some((t) => readPaths(t).paths.includes(\"matrix.\"))", "texts.some((t) => t.includes(\"matrix.\"))"],
  ["review GH-003 a ref value below its key not read", "src/checks/workflows.ts", "const refValue = (t: string) => (isYaml(l) && REF_KEY.test(t)) || l.block === \"ref\" || l.block === \"repository\";", "const refValue = (t: string) => isYaml(l) && REF_KEY.test(t);"],
  ["review GH-003 a head ref bound in env: and used in a ref: not read", "src/checks/workflows.ts", "const viaKey = refValue(t) && (HEAD_REF.test(t) || readsHeadEnv(t));", "const viaKey = refValue(t) && HEAD_REF.test(t);"],
  ["review GH-003 a ref computed from the github context passes", "src/checks/workflows.ts", "      } else if (texts.some(computedRef)) {", "      } else if (Math.random() < 0 && texts.some(computedRef)) {"],
  ["review2 GH-003 a head ref in an env: variable fetched by git not read", "src/checks/workflows.ts", " || (headVar && gitFetchesCode(t, GIT_CHECKOUTS))", ""],
  ["review2 GH-003 a head env variable counted outside git fetch or checkout", "src/checks/workflows.ts", "(headVar && gitFetchesCode(t, GIT_CHECKOUTS))", "headVar"],
  ["review2 GH-003 any env: binding counts as a head ref", "src/checks/workflows.ts", "const bindsHead = new Set(yaml.filter((l) => l.entry && texts(l).some((t) => HEAD_REF.test(readPaths(t).paths))));", "const bindsHead = new Set(yaml.filter((l) => l.entry));"],
  ["review2 GH-003 env names matched case-sensitively in expressions", "src/checks/workflows.ts", "const headEnvLower = new Set([...headEnv].map((n) => n.toLowerCase()));", "const headEnvLower = headEnv;"],
  ["review2 GH-003 a computed github context flagged outside a ref:", "src/checks/workflows.ts", "return refValue(r.paths) && r.bodies.some((b) => COMPUTED_GITHUB.test(", "return r.bodies.some((b) => COMPUTED_GITHUB.test("],
  ["review2 GH-003 a literal index read as computed", "src/checks/workflows.ts", "COMPUTED_GITHUB.test(b.replace(INDEX_SYNTAX, \".$2\"))", "COMPUTED_GITHUB.test(b)"],
];
