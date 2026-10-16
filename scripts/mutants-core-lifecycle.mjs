// Mutants for lifecycle scripts and local dependency specs in package.json (src/checks/lifecycle.ts): install hooks,
// the suspicious-script and payload-name heuristics, the content digest in their keys, .gyp files, and the WS-SC-900
// findings for local specs, workspaces and pnpm-workspace patterns wormsign cannot scan, with the summary key of a
// capped list (src/checks/context.ts). scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how
// they run; a module holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["LC-001 install hooks never reported", "src/checks/lifecycle.ts", "if ((INSTALL_HOOKS as readonly string[]).includes(hook)) {", "if (Math.random() < 0) {"],
  ["LC-002 no suspicious-script heuristic matches", "src/checks/lifecycle.ts", "const out = SUSPICIOUS.filter((s) => s.re.test(head)).map((s) => s.why);", "const out: string[] = [];"],
  ["LC-002 TruffleHog pattern dropped", "src/checks/lifecycle.ts", "{ re: /\\btrufflehog\\b/i,", "{ re: /\\bno-such-command\\b/i,"],
  ["LC-003 payload names run by scripts ignored", "src/checks/lifecycle.ts", "if (!ran.has(n.name)) continue;", "continue;"],
  ["SC-900 local path dependencies into node_modules not reported", "src/checks/lifecycle.ts", "if (why) unchecked(", "if (why && Math.random() < 0) unchecked("],
  ["LC-001 .gyp files beside a manifest ignored", "src/checks/lifecycle.ts", "if (run.length === 0) return [];", "if (run.length >= 0) return [];"],
  ["LC-001 baseline approves the script whatever its command", "src/checks/lifecycle.ts", "key: `${hook}:${sha}`,", "key: hook,"],
  ["LC-002/003 baseline approves the script whatever its command", "src/checks/lifecycle.ts", "out.push(...contentFindings(file, hook, cmd, line, ctx).map((f) => makeFinding({ ...f, key: `${f.key}:${sha}` })));", "out.push(...contentFindings(file, hook, cmd, line, ctx));"],
  ["LC-002 dependencies-family install scripts not checked", "src/checks/lifecycle.ts", '  "predependencies",\n  "dependencies",\n  "postdependencies",\n  "pnpm:devPreinstall",\n', ""],
  ["SC-900 workspaces that reach unscanned paths not reported", "src/checks/lifecycle.ts", "if (why) found.add(`${field}:", "if (why && Math.random() < 0) found.add(`${field}:"],
  ["SC-900 pnpm-workspace packages patterns not checked", "src/checks/lifecycle.ts", "...hiddenPatterns(file, packages, \"packages\",", "...hiddenPatterns(file, [], \"packages\","],
  ["SC-900 pnpm-workspace packages in an unread shape pass silently", "src/checks/lifecycle.ts", "} else if (!/^(null|~)?$/.test(rest)) {", "} else if (Math.random() < 0) {"],
  // 128-bit content digests in keys: what binds a baseline entry to the command it approves.
  ["LC-001 key holds 48 bits of the command", "src/checks/lifecycle.ts", "const sha = keyDigest(cmd);", "const sha = keyDigest(cmd).slice(0, 12);"],
  ["SC-900 a capped list's summary key keeps 64 bits", "src/checks/context.ts", 'rest.digest("hex").slice(0, KEY_DIGEST_HEX)', 'rest.digest("hex").slice(0, 16)'],
];
