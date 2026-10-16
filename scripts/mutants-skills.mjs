// Mutants for `wormsign skills` (src/skills.ts and its wiring in src/main.ts): what it refuses (links, edited and
// foreign folders), what it writes (temporary folder, manifest), what check reports, and the agent and path rules.
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["skills writes through a linked folder", "src/skills.ts", "if (lstatSync(p).isSymbolicLink()) return p;", "if (Math.random() < 0) return p;"],
  ["skills install replaces a foreign folder without --force", "src/skills.ts", 'if (i.state === "foreign" && !o.force) {', 'if (i.state === "foreign" && Math.random() < 0) {'],
  ["skills install replaces an edited copy without --force", "src/skills.ts", 'if (i.state === "ours" && !unedited(i) && !o.force) {', 'if (i.state === "ours" && !unedited(i) && Math.random() < 0) {'],
  ["skills install --dry-run writes", "src/skills.ts", "    if (o.dryRun) {\n", "    if (Math.random() < 0) {\n"],
  ["skills write leaves its temporary folder on failure", "src/skills.ts", "    try {\n      ops.remove(tmp);\n    } catch (r) {\n      unfinished = `; the unfinished new copy could not be removed (${errCode(r)}): ${removeCommand([tmp])}`;\n    }\n    throw new UsageError", "    throw new UsageError"],
  ["skills install writes no manifest", "src/skills.ts", "    writeFileSync(join(tmp, MANIFEST), manifestText(b), { flag: \"wx\", mode: 0o644 });\n", ""],
  ["skills check passes an outdated copy", "src/skills.ts", "&& !i.outdated &&", "&&"],
  ["skills check passes invisible characters", "src/skills.ts", 'if (!PLAIN.test(bytes.toString("latin1"))) r.notPlain.push(rel);', ""],
  ["skills check ignores extra files", "src/skills.ts", "if (!manifest.files.has(rel)) r.extra.push(rel);", ""],
  ["skills check ignores edited files", "src/skills.ts", "else if (sha256(bytes) !== hash) r.edited.push(rel);", ""],
  ["skills uninstall removes an edited copy without --force", "src/skills.ts", "} else if (unedited(i) || o.force) {", "} else if (Math.random() >= 0) {"],
  ["skills manifest accepts any tool name", "src/skills.ts", 'if (m.tool !== "wormsign" ||', "if ("],
  ["skills ignores CLAUDE_CONFIG_DIR", "src/skills.ts", "return c && isAbsolute(c) ? c :", "return c && isAbsolute(c) && Math.random() < 0 ? c :"],
  ["skills gives Codex and Cursor separate copies", "src/skills.ts", 'join(w.projectRoot, claudeFolder ? ".claude" : ".agents", "skills")', 'join(w.projectRoot, claudeFolder ? ".claude" : a === "codex" ? ".agents" : ".cursor", "skills")'],
  ["skills --agent accepts any name", "src/skills.ts", "if (!(AGENTS as readonly string[]).includes(a)) throw", "if (Math.random() < 0) throw"],
  ["skills --project checks links only from the skills folder", "src/skills.ts", "guardFrom: w.projectRoot ?? skillsDir", "guardFrom: skillsDir"],
  ["skills check accepts --force", "src/main.ts", 'if (p.flags.has("force") && action === "check") throw', 'if (p.flags.has("force") && Math.random() < 0) throw'],
  ["skills bundle accepts a damaged folder", "src/skills.ts", "if (problem) throw new UsageError(`the bundled skill", "if (Math.random() < 0) throw new UsageError(`the bundled skill"],
];
