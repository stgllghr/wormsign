// Mutants for harden-dev.sh's H13 (uv exclude-newer), H07's bunfig reading and H04's version gate (both as soak reads
// them), and what keeps the script itself safe to run: its private temp directory, absolute PATH, CDPATH-safe cd,
// decimal --soak, 0600 backups and dangling symlinks left alone (and ci-pack-smoke.sh's cd).
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18
// mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  // The lock's exclude-newer-span is ignored in favour of exclude-newer, which uv 0.12 sets to a placeholder date in
  // year 1, so any span passes. Killed by "uv 0.12 records a placeholder exclude-newer beside the span".
  ["H13 uv span ignored in favour of exclude-newer", "harden-dev.sh", 'const span = opts["exclude-newer-span"];', "const span = undefined;"],
  // [[index]] entries' own exclude-newer is not read: a default index with exclude-newer = false passes. Killed by
  // "an [[index]] entry's own exclude-newer".
  ["H13 uv per-index exclude-newer unread", "harden-dev.sh", 'if version_ge "$UV_V" "$UV_INDEX_MIN"; then', "if false; then"],
  // The default index turning the cutoff off is only a WARN. Killed by "an [[index]] entry's own exclude-newer".
  ["H13 uv default index only a WARN", "harden-dev.sh", 'default) sev=fail; c="$b, the default index" ;;', 'default) sev=warn; c="$b, the default index" ;;'],
  // [pip] exclude-newer-package is not read. Killed by "[pip] exclude-newer-package entries off or shorter".
  ["H13 uv [pip] exclude-newer-package unread", "harden-dev.sh", "pip-package) uv_value_check", "pip-package-unread) uv_value_check"],
  // uv runs with the caller's UV_PROJECT, UV_WORKING_DIR, UV_FROZEN and UV_LOCKED: the probe locks the user's project
  // (writing its uv.lock) or fails. Killed by "UV_PROJECT, UV_WORKING_DIR, UV_FROZEN and UV_LOCKED in the environment".
  ["H13 uv probe follows UV_PROJECT", "harden-dev.sh", "unset VIRTUAL_ENV UV_PROJECT UV_WORKING_DIR UV_FROZEN UV_LOCKED &&", "unset VIRTUAL_ENV &&"],
  // The script's own environment. Killed by the tests in "the script's own environment: temp directory, PATH, CDPATH,
  // symlinks, backups", and the CDPATH one also by "shell scripts: every $(cd ...) is CDPATH-safe".
  ["harden-dev.sh probes run under a TMPDIR other users can write", "harden-dev.sh", "! -perm -0020 ! -perm -0002 -print", "-print"],
  ["harden-dev.sh keeps relative PATH entries", "harden-dev.sh", '    *) PATH_DROPPED="$PATH_DROPPED ${path_d:-(empty)}" ;;', "    *) path_kept=${path_kept:+$path_kept:}$path_d ;;"],
  ["harden-dev.sh SCRIPT_DIR breaks under CDPATH", "harden-dev.sh", "CDPATH='' cd -- \"$(dirname -- \"${BASH_SOURCE[0]}\")\"", 'cd "$(dirname "${BASH_SOURCE[0]}")"'],
  ["harden-dev.sh --soak digits read as octal", "harden-dev.sh", "num=$((10#$num))\n", ""],
  ["harden-dev.sh backups keep the file's mode", "harden-dev.sh", '(umask 077 && set -C && cat -- "$f" >"$f.wormsign-bak.$STAMP") || return 1', 'cp -p "$f" "$f.wormsign-bak.$STAMP" || return 1'],
  ["harden-dev.sh writes through a dangling symlink", "harden-dev.sh", 'if [ -L "$file" ] && [ ! -e "$file" ]; then return 3; fi', ""],
  ["ci-pack-smoke.sh cd follows CDPATH", "scripts/ci-pack-smoke.sh", "CDPATH='' cd -- \"$(dirname -- \"$1\")\"", 'cd "$(dirname "$1")"'],
  ["H07 a bunfig minimumReleaseAge with a doubled _ passes", "harden-dev.sh", "if (v !~ /^(0|[1-9](_?[0-9])*)$/) { bad = v; unreadable = 1; next }", "if (v !~ /^[0-9_]+$/) { bad = v; unreadable = 1; next }"],
  ["H07 a CRLF bunfig is never read", "harden-dev.sh", '    { sub(/\\r$/, ""); was = ml;', "    { was = ml;"],
  ["H04 pnpm's release-age version gate is not soak's ENFORCED_SINCE", "harden-dev.sh", 'version_ge "$PNPM_V" 10.16; then', 'version_ge "$PNPM_V" 10.15; then'],
];
