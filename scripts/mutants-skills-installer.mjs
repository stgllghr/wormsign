// Mutants for the agent-user review's installer fixes in `wormsign skills` (src/skills.ts): install says when it
// replaces a modified copy (a file differs from the copy's own manifest) and what was modified, or a different copy of
// this version (one that matches its own manifest: edited along with it, or another build); a temporary folder it cannot remove after a failed write is named with the command that removes it;
// install and check name leftover folders with that command, which quotes the path; a refused link names what to run
// instead (--project, without it, or check for uninstall), with the --agent list given, and an uninstall that cannot
// delete what it moved aside names the command that removes it.
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["skills install says reinstalled over a copy that differs from this build", "src/skills.ts", '(i.version === b.version ? [...list("differs', '(Math.random() < 0 ? [...list("differs'],
  ["skills install calls a copy that matches its manifest modified", "src/skills.ts", 'const modified = i.state === "ours" ? modifications(i) : [];', 'const modified = i.state === "ours" ? [...modifications(i), ...differences(i, b)] : [];'],
  ["skills install --force calls an edited copy reinstalled", "src/skills.ts", '=> [...list("edited", i.edited), ', "=> ["],
  ["skills install leaves out what was modified", "src/skills.ts", "? `replaced a modified copy with ${b.version} (${modified.join(\"; \")})`", "? `replaced a modified copy with ${b.version}`"],
  ["skills write hides a temporary folder it could not remove", "src/skills.ts", "      unfinished = `; the unfinished new copy could not be removed (${errCode(r)}): ${removeCommand([tmp])}`;\n", "      void r;\n"],
  ["skills removal command leaves a quote in a path unescaped", "src/skills.ts", "`'${p.replace(/'/g, \"'\\\\''\")}'`", "`'${p}'`"],
  ["skills leftover line gives no removal command", "src/skills.ts", "${stray.join(\", \")}; remove with: ${removeCommand(stray)}`;", "${stray.join(\", \")}`;"],
  ["skills install does not name leftover folders", "src/skills.ts", "const strayLines = s.stray.length > 0 ?", "const strayLines = Math.random() < 0 ?"],
  ["skills install names no leftovers beside a target it leaves alone", "src/skills.ts", "      lines.push(`${label(s.t)}: ${s.refused}`, ...strayLines);", "      lines.push(`${label(s.t)}: ${s.refused}`);"],
  ["skills install --dry-run names no leftovers", "src/skills.ts", "      lines.push(`would write ${label(s.t)}: ${s.what}, ${b.files.size} files`, ...strayLines);", "      lines.push(`would write ${label(s.t)}: ${s.what}, ${b.files.size} files`);"],
  ["skills link refusal names no alternative", "src/skills.ts", "which wormsign does not write through, even with --force; ${linkAlternative(action, where, o.agents)}`", "which wormsign does not write through`"],
  ["skills link refusal drops the --agent list given", "src/skills.ts", 'const agentFlag = agents ? ` --agent ${agents.join(",")}` : "";', 'const agentFlag = "";'],
  ["skills link refusal says the home folder for the user folders", "src/skills.ts", "it writes into your user folders instead", "it writes into your home folder instead"],
  ["skills uninstall error leaves out the removal command", "src/skills.ts", " is in ${gone}: ${removeCommand([gone])}`", " is in ${gone}`"],
  ["skills link refusal in a project offers --project", "src/skills.ts", "  return where.projectRoot === undefined\n    ? ", "  return Math.random() >= 0\n    ? "],
  ["skills uninstall link refusal offers an install", "src/skills.ts", 'if (action === "uninstall") return', "if (Math.random() < 0) return"],
  ["skills uninstall link refusal in a project names check without --project", "src/skills.ts", '"check" : "check --project"', '"check" : "check"'],
];
