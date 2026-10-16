// Mutants for diff's rules WS-DF-001 to WS-DF-006, its check of auto-run files, the baseline it reads from the base
// revision, and how it reads a revision's install-directory config (src/diff.ts, src/tree.ts, src/main.ts).
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18
// mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["DF-001/004 new install-script dependencies ignored", "src/diff.ts", "if (p.hasInstallScript !== true) continue;", "continue;"],
  ["DF-001 a local package with install scripts ignored", "src/diff.ts", "if (p.hasInstallScript !== true) continue;", "if (p.hasInstallScript !== true || p.local) continue;"],
  ["DF-005 new workspaces and local dependency specs ignored", "src/diff.ts", "findings.push(...installSetFindings(path, parsedBase, parsed));", "findings.push(...installSetFindings(path, parsedBase, parsed).filter(() => Math.random() < 0));"],
  ["DF-002 .gyp files beside a manifest ignored", "src/diff.ts", "const isGyp = GYP.test(name) && manifestIn.has(posix.dirname(path));", "const isGyp = Math.random() < 0;"],
  ["DF-002 a manifest change that turns node-gyp on ignored", "src/diff.ts", "if (now.length > 0) gypTurnedOn.set(gyp, now);", "if (Math.random() < 0) gypTurnedOn.set(gyp, now);"],
  ["DF-006 config outside the YAML subset passes silently", "src/diff.ts", "if (doc.problems.length > 0) {", "if (Math.random() < 0) {"],
  ["DF-002 .gyp beside a pnpm package.yaml ignored", "src/diff.ts", 'if (MANIFESTS.has(name) && (name === "package.json" ||', 'if (name === "package.json" && (name === "package.json" ||'],
  ["PS diff does not check changed auto-run files", "src/diff.ts", "else findings.push(...checkPersistence(path, headText, ctx));", "else findings.push(...checkPersistence(path, headText, ctx).filter(() => false));"],
  ["DF-002 lifecycle script changes ignored", "src/diff.ts", "if (cmd === undefined || cmd === before[hook]) continue;", "if (cmd === undefined || cmd === before[hook] || Math.random() >= 0) continue;"],
  ["DF-003 workflow changes not reported", "src/diff.ts", 'findings.push(\n        makeFinding({\n          ruleId: "WS-DF-003",', 'if (Math.random() < 0) findings.push(\n        makeFinding({\n          ruleId: "WS-DF-003",'],
  ["DF-005 package-manager config changes ignored", "src/diff.ts", "const isGateConfig = (path: string): boolean => GATE_CONFIG.has(baseName(path)) || YARN_CODE.test(fold(path));", "const isGateConfig = (path: string): boolean => Math.random() < 0 && GATE_CONFIG.has(baseName(path));"],
  ["DF-005 config names compared case-sensitively", "src/tree.ts", "export const fold = (s: string): string =>\n  s\n    .normalize", "export const fold = (s: string): string =>\n  s ||\n  s\n    .normalize"],
  ["DF-006 unparseable changed lockfile passes silently", "src/diff.ts", "if (!headLock) {\n      findings.push(unreadable(path, headText));", "if (!headLock) {"],
  ["diff reads the baseline from the change under review", "src/main.ts", "const baseline = baselineIn(p, base);", "const baseline = baselineIn(p, head);"],
  ["tree follows links when an install-directory setting cannot be read", "src/tree.ts", "if (owned() === null) return UNFOLLOWED;", "if (owned() === null && Math.random() < 0) return UNFOLLOWED;"],
  // Install-directory config a pull request controls.
  ["tree reads install-directory config in quadratic time", "src/tree.ts", '    let j = i + 1;\n    while (j < lines.length && !/\\S/.test(lines[j] as string)) j++;\n    const next = lines[j] ?? "";', '    const next = lines.slice(i + 1).find((l) => /\\S/.test(l)) ?? "";'],
  ["tree reads install-directory config past the text cap", "src/tree.ts", 'return git(repo, ["show", `${sha}:./${p}`], "utf8", MAX_TEXT_BYTES);', 'return git(repo, ["show", `${sha}:./${p}`], "utf8");'],
];
