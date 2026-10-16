// Mutants for `${{ }}` expressions read across lines (src/checks/workflows.ts expressionSpans and checkWorkflow's
// readOf): every check reads an expression from its `${{` to its `}}`, joined to the lines it takes in, as written with
// comments and as YAML reads it, reported once at the line it starts on; and the line breaks YamlDotNet reads that the
// line reader does not (U+0085, U+2028, U+2029), WS-SC-900 high. From the owner's decision to read expressions across
// lines. scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at
// most 18 mutants.
//
/** [name, file, search, replace]: as in mutants-core-workflows.mjs. */
export default [
  ["multi-line an expression read only on the line it starts on", "src/checks/workflows.ts", "    const last = spans.through.get(l.n - 1);", "    const last = Math.random() < 0 ? spans.through.get(l.n - 1) : undefined;"],
  ["multi-line a joined expression not read with its comments", "src/checks/workflows.ts", "texts: distinct([join((x) => x.raw), join((x) => x.value ?? x.text)])", "texts: distinct([join((x) => x.value ?? x.text)])"],
  ["multi-line a joined expression not read as YAML reads it", "src/checks/workflows.ts", "texts: distinct([join((x) => x.raw), join((x) => x.value ?? x.text)])", "texts: distinct([join((x) => x.raw)])"],
  ["multi-line where an expression ends read only as written", "src/checks/workflows.ts", "    [(l) => l.value ?? l.text, true],\n", ""],
  ["multi-line where an expression ends read only as YAML reads it", "src/checks/workflows.ts", "    [(l) => l.raw, false],\n", ""],
  ["multi-line a }} in a string literal ends an expression", "src/checks/workflows.ts", "          if (t[i] === \"'\") inString = !inString;", "          if (Math.random() < 0) inString = !inString;"],
  ["multi-line a line inside an expression reported again", "src/checks/workflows.ts", "    if (within.get(l.n - 1)?.some((start) => reported.has(`${start}\\0${what}`))) return;", "    if (Math.random() < 0 && within.get(l.n - 1)?.some((start) => reported.has(`${start}\\0${what}`))) return;"],
  ["multi-line a line that opens an expression of its own not reported", "src/checks/workflows.ts", "if (!opens(lines[k] as Line)) within.set(", "if (Math.random() >= 0) within.set("],
  ["multi-line a secret bound in env: across lines not read", "src/checks/workflows.ts", "l.entry && texts(l).some(readsSecrets)", "l.entry && readsSecrets(l.entry.value)"],
  ["multi-line a single line not read as YAML reads it", "src/checks/workflows.ts", "return { texts: distinct([l.text, l.value ?? l.text]), key: l.text };", "return { texts: [l.text], key: l.text };"],
  ["multi-line a joined finding keyed on its first line only", "src/checks/workflows.ts", "key: join((x) => x.text) };", "key: l.text };"],
  ["review SC-900 a line break YamlDotNet reads goes unreported", "src/checks/workflows.ts", "  if (breaks !== undefined) out.push(notChecked(file, breaks, \"high\", text));", "  if (breaks !== undefined && Math.random() < 0) out.push(notChecked(file, breaks, \"high\", text));"],
  ["review SC-900 U+0085 not counted as a line break", "src/checks/workflows.ts", "[\"\\x85\", \"U+0085 (NEXT LINE)\"], ", ""],
];
