// Mutants for what a soak run with PyPI reports (src/main.ts): notes and WS-SK-003 per ecosystem, one OSV session,
// local sources, the walk's and discovery's findings, notes and evidence, PR mode's builds, the baseline's ignorePaths;
// and how diff and scan say they do not read Python locks (src/diff.ts, src/scan.ts). scripts/mutation-check.mjs loads
// every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["INT soak: a Python-only tree gets npm's notes", "src/main.ts", "const npmOutput = locks.length > 0 || hasBunfig(root) || !py.pythonInputs;", "const npmOutput = locks.length > 0 || hasBunfig(root) || true;"],
  ["INT soak: a Python-only tree gets WS-SK-003 for no package manager", "src/main.ts", "const inputs = py.pythonInputs ? { pythonInputs: true as const, npmInputs: hasNpmInputs(walk) } : {};", "const inputs = {};"],
  ["INT soak: the nothing-to-verify note ignores Python locks and findings", "src/main.ts", " && py.locks.length === 0 && py.findings.length === 0) {\n", ") {\n"],
  ["INT soak: npm and PyPI use separate OSV sessions", "src/main.ts", "              osvSession,\n              root,", "              osvSession: newOsvSession(),\n              root,"],
  ["INT soak: Python local sources are checked as if there were no work tree", "src/main.ts", "...gitForPython(walk, py.locks),", 'git: "no-work-tree" as const,'],
  ["INT soak: the walk's notes are dropped", "src/main.ts", "        notes.push(...walk.notes);\n", ""],
  ["INT soak: discovery's findings are dropped", "src/main.ts", "        findings.push(...py.findings);\n", ""],
  ["INT soak: discovery's notes are dropped", "src/main.ts", "        notes.push(...py.notes);\n", ""],
  ["INT soak: PyPI evidence is dropped", "src/main.ts", "            evidence.push(...res.evidence);\n          }\n          extra = evidence.sort(compareEvidence);", "          }\n          extra = evidence.sort(compareEvidence);"],
  ["INT soak: a WS-SK-005 the change adds stays medium in PR mode", "src/main.ts", "            ? raiseNewBuilds(findings, {", "            ? findings || raiseNewBuilds(findings, {"],
  ["INT soak: Python discovery ignores the baseline's ignorePaths", "src/main.ts", "configOnly, ignore: ignorePaths,", "configOnly, ignore: ignorePaths.slice(0, 0),"],
  ["INT soak: a root bunfig.toml does not bring back npm's notes in a Python tree", "src/main.ts", "|| hasBunfig(root) ||", "|| (Math.random() < 0 && hasBunfig(root)) ||"],
  ["INT diff: a changed Python lockfile is not reported", "src/diff.ts", "...pythonLockFindings(base, head, visible),", "...pythonLockFindings(base, head, () => false),"],
  ["INT scan: no note for the Python inputs scan does not read", "src/scan.ts", "if (pythonInputs.length > 0) {", "if (Math.random() < 0) {"],
];
