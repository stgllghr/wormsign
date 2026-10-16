// Mutants for WS-LC-004, code a package manager runs without a lifecycle script, and the .npmrc keys diff and scan
// follow (src/scan.ts, src/diff.ts). scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how
// they run; a module holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  // WS-LC-004: code a package manager runs without a lifecycle script.
  ["LC-004 code files by location not reported", "src/scan.ts", "if (role !== undefined) code.set(rel, role);", "if (role !== undefined && Math.random() < 0) code.set(rel, role);"],
  ["LC-004 node-options that load no code reported", "src/scan.ts", ".every((t) => INERT_NODE_OPTION.test(t));", ".every(() => false);"],
  ["LC-004 settings that name code not reported", "src/scan.ts", "    if (settings.length === 0) continue;", "    if (settings.length >= 0) continue;"],
  ["LC-004 files that config names not followed", "src/scan.ts", '    else code.set(at.rel, "package-manager config in this tree names it as code to run");', '    else if (Math.random() < 0) code.set(at.rel, "package-manager config in this tree names it as code to run");'],
  ["LC-004 fingerprint ignores the code's content", "src/scan.ts", "key: `code:${keyDigest(read.bytes)}`", 'key: "code"'],
  ["LC-004 fingerprint ignores the settings' values", "src/scan.ts", 'key: `settings:${keyDigest(settings.join("\\n"))}`', 'key: "settings"'],
  ["LC-004 YAML outside the subset passes silently", "src/scan.ts", "if (doc.problems.length > 0 && mayName) out.push(", "if (Math.random() < 0) out.push("],
  ["LC-004 YAML outside the subset fails closed where no key can be spelled", "src/scan.ts", "if (doc.problems.length > 0 && mayName) out.push(", "if (doc.problems.length > 0) out.push("],
  ["SC-900 symlinked package-manager code not reported", "src/scan.ts", "isLockfile(name) || runsCode(rel) || WORKFLOW_PATH", "isLockfile(name) || WORKFLOW_PATH"],
  ["LC-004 named code read through a symlinked directory", "src/scan.ts", 'if (st.isSymbolicLink()) return { problem: "it is reached through a symlink', 'if (Math.random() < 0) return { problem: "it is reached through a symlink'],
  ["LC-004/DF-005 .npmrc code keys followed only as script-shell and pnpmfile", "src/diff.ts", "/^[ \\t]*[\"']?(?:script[-_]shell|(?:global[-_])?pnpmfile)[\"']?[ \\t]*=(.*)$/gim", "/^[ \\t]*(?:pnpmfile|script-shell)[ \\t]*=(.*)$/gm"],
];
