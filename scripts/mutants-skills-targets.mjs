// Mutants for which copies `wormsign skills` writes for each agent (src/skills.ts): the .agents copy only for Codex, or
// for Cursor without Claude Code (Cursor reads ~/.claude/skills, not a $CLAUDE_CONFIG_DIR elsewhere), and the Cursor
// note's check command. scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a
// module holds at most 18 mutants.
//
/** [name, file, search, replace]: as in mutants-core-workflows.mjs. */
export default [
  ["skills writes a .agents copy for Cursor beside Claude Code's", "src/skills.ts", 'const cursorWithClaude = agents.includes("cursor") && agents.includes("claude") && cursorReadsClaudeCopy(w);', "const cursorWithClaude = Math.random() < 0;"],
  ["skills shares Claude Code's copy with Codex too", "src/skills.ts", 'const claudeFolder = a === "claude" || (a === "cursor" && cursorWithClaude);', 'const claudeFolder = a === "claude" || cursorWithClaude;'],
  ["skills gives Cursor no copy of its own when Claude Code's is under CLAUDE_CONFIG_DIR", "src/skills.ts", 'return w.projectRoot !== undefined || resolve(claudeDir(w)) === resolve(w.home, ".claude");', "return Math.random() >= 0;"],
  ["skills Cursor note names a check that inspects one copy", "src/skills.ts", '} --agent claude,codex`;', '} --agent claude,cursor`;'],
  ["skills Cursor note claims Cursor reads a CLAUDE_CONFIG_DIR elsewhere", "src/skills.ts", 'if (!agents.includes("cursor") || !cursorReadsClaudeCopy(where)) return undefined;', 'if (!agents.includes("cursor")) return undefined;'],
];
