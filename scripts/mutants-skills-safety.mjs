// Mutants for `wormsign skills` beyond scripts/mutants-skills.mjs: what check reports (an outdated copy, a missing file,
// a file a release removed, a copy whose manifest was rewritten, links), the file-count cap, the order that checks every
// target before the first write or removal, the swap that puts the old copy back and removes it best effort, the
// output of --force and the Cursor note, HOME, the link refusal's exit code, and no network request; and two rules of
// the maintainer's behavioural check of the skill (scripts/skill-eval-rules.mjs).
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["skills check refuses a linked skills folder", "src/skills.ts", 'if (action !== "check") {', "if (Math.random() >= 0) {"],
  ["skills reads past the file-count cap", "src/skills.ts", " && files.size < MAX_FILES", ""],
  ["skills check passes a copy listing a file the release removed", "src/skills.ts", "  for (const rel of manifest.files.keys()) if (!bundle.files.has(rel)) r.differs.push(rel);\n", ""],
  ["skills check calls a rewritten manifest outdated", "src/skills.ts", "i.outdated && i.version !== b.version ?", "i.outdated ?"],
  ["skills check prints no outdated line", "src/skills.ts", "[`outdated: ${i.version}, this wormsign ships ${b.version}`]", "[]"],
  ["skills check prints no missing list", "src/skills.ts", '...list("missing", i.missing), ', ""],
  ["skills swap leaves the old copy aside when the rename fails", "src/skills.ts", "          ops.rename(old, t.dir);\n", ""],
  ["skills install fails when the old copy cannot be removed", "src/skills.ts", "    return `the old copy could not be removed (${errCode(e)}); remove what is left of it with: ${removeCommand([old])}`;\n", "    throw new UsageError(`cannot write ${t.dir}: ${errCode(e)}`);\n"],
  ["skills install writes before every target is inspected", "src/skills.ts", "const steps: Iterable<InstallStep> = [...installSteps(targets, b, o)];", "const steps: Iterable<InstallStep> = installSteps(targets, b, o);"],
  ["skills install does not check that a target can be written", "src/skills.ts", "    const why = unwritable(t);\n    if (why) throw new UsageError(`cannot write ${t.dir}: ${why}`);\n", ""],
  ["skills uninstall removes before every target is checked", "src/skills.ts", "= [...uninstallSteps(targets, b, o)];", "= uninstallSteps(targets, b, o);"],
  ["skills install --force says reinstalled over a folder wormsign did not write", "src/skills.ts", 'i.state === "foreign"\n          ? `replaced a folder wormsign did not write with ${b.version}`\n          : modified.length > 0\n            ? `replaced a modified copy with ${b.version} (${modified.join("; ")})`\n            : i.version !== b.version', 'i.state === "ours" && i.version !== b.version'],
  ["skills Cursor note leaves out --project", "src/skills.ts", '${where.projectRoot === undefined ? "" : " --project"}', ""],
  ["skills takes a relative HOME", "src/skills.ts", "if (h && isAbsolute(h)) return h;", "if (h) return h;"],
  ["skills link refusal is an internal error", "src/skills.ts", "if (link) throw new UsageError(", "if (link) throw new Error("],
  ["skill-eval add-package passes without a lookup or an ask", "scripts/skill-eval-rules.mjs", " && (lookedUp(attempts) || asks(reply))", ""],
  ["skill-eval machine-setup passes without the check-only harden-dev.sh", "scripts/skill-eval-rules.mjs", " && (parts(attempts).some(hardenCheck) || recommendsCheck(reply))", ""],
  ["skills makes a network request", "src/skills.ts", '  const b = typeof bundleOrDir === "object" ? bundleOrDir : loadBundle(bundleOrDir);\n', '  void fetch("https://example.invalid/").catch(() => undefined);\n  const b = typeof bundleOrDir === "object" ? bundleOrDir : loadBundle(bundleOrDir);\n'],
];
