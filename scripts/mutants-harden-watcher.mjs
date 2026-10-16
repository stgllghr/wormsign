// Mutants for harden-dev.sh's H14 (the gh-token-monitor watcher's files, check only) and the blocked() helper it shares
// with H10. scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds
// at most 18 mutants.
//
/** [name, file, search, replace]: as in mutants-core-workflows.mjs. */
export default [
  // No watcher file is reported. Killed by "each documented watcher file is a critical FAIL".
  ["H14 watcher files not reported", "harden-dev.sh", '  elif [ -e "$f" ] || [ -L "$f" ]; then\n    WATCHER_FOUND=', '  elif false; then\n    WATCHER_FOUND='],
  // A dangling symlink at a watcher path passes. Killed by "one file is enough, a dangling symlink counts".
  ["H14 dangling symlink at a watcher path passes", "harden-dev.sh", '  elif [ -e "$f" ] || [ -L "$f" ]; then\n    WATCHER_FOUND=', '  elif [ -e "$f" ]; then\n    WATCHER_FOUND='],
  // The FAIL loses the instruction to isolate before revoking. Killed by "each documented watcher file is a critical FAIL".
  ["H14 FAIL does not say to isolate before revoking", "harden-dev.sh", "exists (critical; do not revoke tokens yet: isolate this machine first): a file", "exists (critical): a file"],
  // The summary does not repeat it. Killed by "each documented watcher file is a critical FAIL".
  ["H14 summary does not repeat the isolate-first note", "harden-dev.sh", 'if [ "$WATCHER_FOUND" -gt 0 ]; then\n  echo "H14 found', 'if false; then\n  echo "H14 found'],
  // --apply removes what it finds. Killed by "--apply leaves every watcher file in place".
  ["H14 --apply removes the watcher files", "harden-dev.sh", "    WATCHER_FOUND=$((WATCHER_FOUND + 1))\n", '    WATCHER_FOUND=$((WATCHER_FOUND + 1)); [ "$MODE" != apply ] || rm -rf "$f"\n'],
  // A directory H14 cannot search counts as clean. Killed by "a directory on the way that cannot be searched is a WARN".
  ["H14 unsearchable directory passes", "harden-dev.sh", '  if blocked "$f"; then\n    case "$watcher_dirs"', '  if false; then\n    case "$watcher_dirs"'],
  // The shared helper never finds a blocked directory: H10 and H14 read "cannot see" as "not there". Killed by H10's "a
  // credential directory that cannot be searched is one WARN" and H14's "a directory on the way that cannot be searched".
  ["blocked() never reports an unsearchable directory", "harden-dev.sh", '  [ -d "$BLOCKED" ] && [ ! -x "$BLOCKED" ]\n', "  false\n"],
];
