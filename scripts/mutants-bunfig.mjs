// Mutants for how bunfig.toml is read, alike in soak (src/soak-config.ts, WS-SK-004) and harden-dev.sh's H07: table
// headers with a trailing comment, [[array-of-tables]] headers, and the lines of a multi-line string.
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18
// mutants.
//
/** [name, file, search, replace]: as in mutants-core-workflows.mjs. */
export default [
  ["review SK-004 a bunfig table header with a comment read as no header", "src/soak-config.ts", "const section = /^\\s*\\[(\\[?)([^\\]]+)\\]\\]?\\s*(?:#.*)?$/.exec(line);", "const section = /^\\s*\\[(\\[?)([^\\]]+)\\]\\]?\\s*$/.exec(line);"],
  ["review2 SK-004 a [[table]] header read as content", "src/soak-config.ts", "const section = /^\\s*\\[(\\[?)([^\\]]+)\\]\\]?\\s*(?:#.*)?$/.exec(line);", "const section = /^\\s*\\[()([^\\]]+)\\]\\s*(?:#.*)?$/.exec(line);"],
  ["review2 SK-004 [[install]] read as [install]", "src/soak-config.ts", "inInstall = section[1] === \"\" && section[2]?.trim() === \"install\";", "inInstall = section[2]?.trim() === \"install\";"],
  ["review2 SK-004 a multi-line string's lines read as keys and headers", "src/soak-config.ts", "    if (inString) continue;\n", ""],
  ["review2 H07 a [[table]] header read as content", "harden-dev.sh", "/^[ \\t]*\\[\\[?[^]]+\\]\\]?[ \\t]*(#.*)?$/", "/^[ \\t]*\\[[^]]+\\][ \\t]*(#.*)?$/"],
  ["review2 H07 a header's comment kept in the table name", "harden-dev.sh", "s = $0; sub(/[ \\t]*#.*$/, \"\", s); gsub(", "s = $0; gsub("],
  ["review2 H07 a multi-line string's lines read as keys and headers", "harden-dev.sh", "ml = mlopen($0, ml); if (was != \"\") next }", "ml = mlopen($0, ml) }"],
];
