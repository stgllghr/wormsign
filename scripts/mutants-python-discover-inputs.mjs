// Mutants for Python inputs discovery must not pass over (src/python/discover.ts): orphan and symlinked script locks,
// unreadable inputs, a requirements file only JavaScript's whitespace would call refused (src/python/scripts.ts), a
// file wormsign cannot read as requirements that is a note instead of one WS-SK-002, lines pip reads as URLs or
// archives, coding lines, the entry bound, build settings in uv.toml and script blocks, a large setup.cfg, uv.lock's
// local packages, pip config not read, and a requirements/ directory's files covering the manifest beside it. scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says
// how they run; a module holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["PY discover: an orphan script lock is not reported", "src/python/discover.ts", "if (claimed.has(fold(rel))) continue;", "continue;"],
  ["PY discover: a symlinked script's lock is not read", "src/python/discover.ts", "if (locks !== undefined) linkedLocks.push([rel, locks]);", "if (locks !== undefined && Math.random() < 0) linkedLocks.push([rel, locks]);"],
  ["PY discover: an unreadable Python input is silent", "src/python/discover.ts", "if (named || byName) problem(rel, `${head.problem},", "if (Math.random() < 0) problem(rel, `${head.problem},"],
  ["PY discover: requirements entries are not bounded across units", "src/python/discover.ts", "if (entriesHeld + unit.entries.length > maxEntries) {", "if (Math.random() < 0) {"],
  ["PY discover: a script block's [tool.uv] build settings are not reported", "src/python/discover.ts", 'if (block.kind === "block") findings.push(...buildConfigFindings(rel, block.metadata, "script"));', ""],
  ["PY discover: WS-SK-005 reads uv.toml by its exact name", "src/python/discover.ts", "const uvToml = isUvTomlName(base);", 'const uvToml = base === "uv.toml";'],
  ["PY discover: a symlinked uv.toml is not reported", "src/python/discover.ts", 'if (type === "symlink" && uvToml) {', "if (Math.random() < 0) {"],
  ["PY discover: a setup.cfg past 16 MiB is read only in part", "src/python/discover.ts", "if (head.size > MAX_SETUP_CFG_BYTES) {", "if (Math.random() < 0) {"],
  ["PY discover: any uv.lock with a local package covers every manifest", "src/python/discover.ts", "const covered = (dir: string): boolean => lockDirs.has(dir) || locked.has(dir);", "const covered = (dir: string): boolean => lockDirs.has(dir) || locked.size > 0;"],
  ["PY discover: pip config not read counts as no index", "src/python/discover.ts", "const pipBlocks = settings?.pipNotRead !== undefined && !opts.pypiIndexExplicit;", "const pipBlocks = false;"],
  ["PY discover: a text with characters Python and JavaScript read differently can count as refused by pip and uv", "src/python/scripts.ts", "  if (NOT_PLAIN.test(text)) return false;", "  if (/\\r(?!\\n)|[\\x0b\\x0c\\x1c-\\x1e\\x85\\u2028\\u2029]/.test(text)) return false;"],
  ["PY discover: a file named like requirements that cannot be read as one is a note again", "src/python/discover.ts", "      problem(rel, UNREAD_BY_NAME, bytesDigest(bytes));\n", ""],
  ["PY discover: a file written like requirements that cannot be read as one is a note again", "src/python/discover.ts", "if (refusedByPipAndUv(bytes)) problem(rel, UNREAD_BY_CONTENT, bytesDigest(bytes));", "if (refusedByPipAndUv(bytes)) void UNREAD_BY_CONTENT;"],
  ["PY discover: approving an unreadable requirements file approves any content", "src/python/discover.ts", "problem(rel, UNREAD_BY_NAME, bytesDigest(bytes));", "problem(rel, UNREAD_BY_NAME, \"\");"],
  ["PY scripts: a line starting with a URL scheme counts as no requirement", "src/python/scripts.ts", "a.startsWith(\".\") || URL_SCHEME.test(a) || ARCHIVE.test(a)", "a.startsWith(\".\") || ARCHIVE.test(a)"],
  ["PY scripts: the .tlz .tar.lz and .tar.lzma archive names are no archives", "src/python/scripts.ts", "const ARCHIVE = /\\.(zip|whl|tar\\.bz2|tbz|tar\\.xz|txz|tlz|tar\\.lz|tar\\.lzma|tar\\.gz|tgz|tar)$/i;", "const ARCHIVE = /\\.(zip|whl|tar\\.bz2|tbz|tar\\.xz|txz|tar\\.gz|tgz|tar)$/i;"],
  ["PY scripts: a coding line naming a codec other than UTF-8 or ASCII can count as refused", "src/python/scripts.ts", "  if (named !== undefined && !PLAIN_CODECS.has(", "  if (Math.random() < 0 && named !== undefined && !PLAIN_CODECS.has("],
  ["PY discover: a requirements file in requirements/ does not cover the directory above it", "src/python/discover.ts", '  return fold(posix.basename(dir)) === "requirements" ? [dir, dirOf(dir)] : [dir];', "  return [dir];"],
];
