// Mutants for editor and agent auto-run files, WS-PS-001 and WS-PS-002 (src/checks/persistence.ts).
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18
// mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["PS a __proto__ key (the prototype in VS Code) passes", "src/checks/persistence.ts", "return hasProtoKey(doc) ? PROTO_KEY : doc;", "return doc;"],
  ["PS a nested __proto__ key passes", "src/checks/persistence.ts", "for (const c of Object.values(v)) todo.push(c);", ""],
  ["PS-001 settings tasks section not reported", "src/checks/persistence.ts", "if (settings.tasks === undefined && dotted.length === 0) return [];", "if (Math.random() >= 0 || (settings.tasks === undefined && dotted.length === 0)) return [];"],
  ["PS-001 dotted tasks.* keys left out of the settings fingerprint", "src/checks/persistence.ts", "const section = { tasks: settings.tasks, ...Object.fromEntries(dotted.map((k) => [k, settings[k]])) };", "const section = { tasks: settings.tasks };"],
  ["PS-001 terminal settings for tasks not reported", "src/checks/persistence.ts", "if (keys.length === 0) return [];", "if (keys.length === 0 || Math.random() >= 0) return [];"],
  ["PS-001 terminal settings fingerprint ignores their values", "src/checks/persistence.ts", 'what: "VS Code terminal settings for tasks", when: "pick the shell, profile or environment that tasks run with, so they can change what an automatic task runs", id: canon(section),', 'what: "VS Code terminal settings for tasks", when: "pick the shell, profile or environment that tasks run with, so they can change what an automatic task runs", id: canon(keys),'],
  ["PS-001 a workspace's settings.tasks anchored at the top-level tasks", "src/checks/persistence.ts", "r.within === undefined ? 0 : keyAt(text, r.within)", "0"],
  ["PS a value too deep to serialise shows the whole file", "src/checks/persistence.ts", "return `${TOO_DEEP} ${stringsOf(v)}`.slice(0, MAX_JUDGED + 1);", "return text.slice(0, MAX_JUDGED + 1);"],
  ["PS-002 a deep hook's message falls back to the file digest", "src/checks/persistence.ts", "command: () => describe(v, shown).slice(0, MAX_JUDGED + 1)", "command: () => describe(v, canon).slice(0, MAX_JUDGED + 1)"],
  ["PS-002 .vscode/settings.json under .claude/ not read for hooks", "src/checks/persistence.ts", "...(/(^|\\/)\\.claude\\//i.test(rel) ? claudeSettings(doc, canon, shown) : [])", "...[]"],
];
