// Mutants for harden-dev.sh's pip checks: H12 (pip's uploaded-prior-to, which file and section wins, --apply) and H08's
// pip config. scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds
// at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  // A command's own section is no longer read for pip install: a short [install] value, which pip install uses
  // instead of [global], passes. Killed by "a shorter [install] value FAILs, naming [install]".
  ["H12 pip [install] values ignored", "harden-dev.sh", "const own = winner(cmd);", 'const own = cmd === "install" ? undefined : winner(cmd);'],
  // PIP_UPLOADED_PRIOR_TO is left out of the value each command uses. Killed by "PIP_UPLOADED_PRIOR_TO alone
  // protects every command".
  ["H12 pip environment variable precedence ignored", "harden-dev.sh", "let from = env;", "let from = undefined;"],
  // pip wheel (which builds sdists, running their code) is not among the commands that need a cutoff. Killed by "each
  // command section set, no [global]: PASS; a command left out (wheel, which builds sdists) FAILs".
  ["H12 pip wheel left out", "harden-dev.sh", 'for (const cmd of ["install", "download", "lock", "wheel"])', 'for (const cmd of ["install", "download", "lock"])'],
  // The first file pip reads wins instead of the last. Killed by "per section the last file pip reads wins".
  [
    "H12 pip first file wins",
    "harden-dev.sh",
    "for (const f of files) if (f.values.has(section)) w = ",
    "for (const f of files) if (f.values.has(section) && w === undefined) w = ",
  ],
  // An empty value clears its section whatever file it is in, even when pip reads a value after it. Killed by "per
  // section the last file pip reads wins, and an empty winner clears the section".
  [
    "H12 pip empty value clears regardless of order",
    "harden-dev.sh",
    "for (const f of files) if (f.values.has(section)) w = ",
    'for (const f of files) if (f.values.has(section) && w?.value !== "") w = ',
  ],
  // Files are taken in the order `pip config debug` lists them (variants by name: site before user), not the order
  // pip reads them. Killed by "per section the last file pip reads wins" (a site file over the user file).
  ["H12 pip files in listing order", "harden-dev.sh", "files.sort((a, b) => ORDER.indexOf(a.variant) - ORDER.indexOf(b.variant));", ""],
  // --apply writes [global] even when [global] already passes, lowering a stricter system-wide value. Killed by
  // "--apply does not write [global] over a stricter system-wide one when the failing value is elsewhere".
  [
    "H12 pip --apply writes over a passing [global]",
    "harden-dev.sh",
    'else if (glob !== undefined && glob.value !== "" && judge(glob.value) === "") apply = "global-ok\\t"',
    'else if (false) apply = "global-ok\\t"',
  ],
  // --apply writes the user file when the [global] that wins is in a file pip reads after it. Killed by "--apply does
  // not write [global] over a stricter system-wide one" (its site file case).
  [
    "H12 pip --apply writes under a later [global]",
    "harden-dev.sh",
    'else if (glob !== undefined && (glob.variant === "site" || glob.variant === "env")) {',
    "else if (false) {",
  ],
  // pip's quiet setting is not overridden, so `pip config debug` prints nothing. Killed by "pip's own quiet and
  // verbose settings do not change what is read".
  [
    "H12 pip quiet setting not overridden",
    "harden-dev.sh",
    "PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_QUIET=0 PYTHONDONTWRITEBYTECODE=1",
    "PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1",
  ],
  // A listing without the PIP_DISABLE_PIP_VERSION_CHECK line is judged as if it were complete (an empty one: unset).
  // Killed by "... a listing without its control line is a WARN".
  ["H12 pip listing without its control line judged", "harden-dev.sh", "if (!control) process.exit(3);", "if (false) process.exit(3);"],
  // The pip that python3 -m venv installs is not checked. Killed by "python3 -m venv's pip (python3's ensurepip)".
  ["H12 pip ensurepip version unchecked", "harden-dev.sh", '! version_ge "$ev" "$PIP_MIN"; then', '! version_ge "$ev" 0; then'],
  // pip older than 26.1 is judged on its config like any other: pip 25.3 ignores the key and pip 26.0 breaks on
  // P<n>D, yet both would pass. Killed by "pip < 26.1 FAILs even with a cutoff set".
  ["H12 pip version gate off", "harden-dev.sh", 'if ! version_ge "$v" "$PIP_MIN"; then', 'if ! version_ge "$v" 0; then'],
  // pip writes [global] through a user config file that is a symlink to a missing file (creating it in the user's
  // dotfiles), and a failed read-back then deletes the link. Killed by "--apply does not have pip write through a user
  // config file that is a symlink to a missing file".
  ["H12 pip writes through a dangling symlink", "harden-dev.sh", 'if [ -L "$f" ] && [ ! -e "$f" ]; then h12_dangling=$f; fi', ":"],
  ["harden-dev.sh H08 skips pip config", "harden-dev.sh", 'token_files+=("$HOME/.pip/pip.conf" "$HOME/.config/pip/pip.conf" "$HOME/Library/Application Support/pip/pip.conf")\n', ""],
];
