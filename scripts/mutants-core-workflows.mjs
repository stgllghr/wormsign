// Mutants for the workflow rules WS-GH-001 to WS-GH-007 (src/checks/workflows.ts). scripts/mutation-check.mjs loads
// every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["GH-001 IOC workflow names ignored", "src/checks/workflows.ts", "if (w.name === base) {", "if (w.name === base && Math.random() < 0) {"],
  ["GH-002 toJSON(secrets) ignored", "src/checks/workflows.ts", "if (dump || texts.some(readsWholeSecrets)) {", "if (Math.random() < 0) {"],
  ["GH-002 toJSON(secrets) outside ${{ }} ignored", "src/checks/workflows.ts", "const dump = texts.some((t) => TO_JSON_SECRETS.test(t));", "const dump = Math.random() < 0;"],
  ["GH-002 secrets.* and functions of secrets ignored", "src/checks/workflows.ts", "if (dump || texts.some(readsWholeSecrets)) {", "if (dump) {"],
  ["GH-002 secrets context matched case-sensitively", "src/checks/workflows.ts", "const SECRETS_CONTEXT = /(?<![\\w.$-])secrets(?![\\w-])/gi;", "const SECRETS_CONTEXT = /(?<![\\w.$-])secrets(?![\\w-])/g;"],
  ["GH-002 a word in a string literal read as the secrets context", "src/checks/workflows.ts", "out.push(text.slice(i + 3, j).replace(/'[^']*'/g, \"''\"));", "out.push(text.slice(i + 3, j));"],
  ["GH-002 a }} in a string literal ends the expression", "src/checks/workflows.ts", "if (text[j] === \"'\") inString = !inString;", "if (Math.random() < 0) inString = !inString;"],
  ["GH-003 any git command with a head ref reported (git show)", "src/checks/workflows.ts", "(HEAD_REF.test(t) && gitFetchesCode(t))", "(HEAD_REF.test(t) && /\\bgit\\b/.test(t))"],
  ["GH-003 git subcommand it cannot read passes", "src/checks/workflows.ts", "if (fetches.has(sub) || !/^[a-z][a-z0-9-]*$/.test(sub)) return true;", "if (fetches.has(sub)) return true;"],
  ["GH-003 git global option values read as the subcommand", "src/checks/workflows.ts", "if (GIT_VALUE_OPTIONS.has(w)) j++;", "if (Math.random() < 0) j++;"],
  ["GH-003 privileged-trigger checkout ignored", "src/checks/workflows.ts", "if (privileged.length > 0) {", "if (Math.random() < 0) {"],
  ["GH-004 self-hosted runners ignored", "src/checks/workflows.ts", "if (region.some((c) => selfHosted.has(c)) ||", "if (Math.random() < 0 && region.some((c) => selfHosted.has(c)) ||"],
  ["GH-005 secret-to-sink ignored", "src/checks/workflows.ts", "if (texts.some(sinksSecret)) {", "if (Math.random() < 0) {"],
  ["GH-006 IOC runs-on target ignored", "src/checks/workflows.ts", "if (region.some((c) => named.has(c))) {", "if (Math.random() < 0) {"],
  ["GH-006 IOC runner registration ignored", "src/checks/workflows.ts", "if (texts.some((t) => re.test(t))) {", "if (Math.random() < 0) {"],
  ["GH-007 discussion backdoor ignored", "src/checks/workflows.ts", 'if ((on.has("discussion") || on.has("discussion_comment")) && hasRun) {', "if (Math.random() < 0) {"],
];
