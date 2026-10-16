#!/usr/bin/env bash
# wormsign harden-dev.sh: check (and optionally apply) developer-workstation
# settings that blunt install-time npm and PyPI worms. macOS and Linux, bash 3.2 or later.
#
#   ./harden-dev.sh              check only (default). Writes nothing.
#   ./harden-dev.sh --apply      apply the fixes listed below, backing up each file first.
#
# What --apply may change (and nothing else):
#   npm user config (the file `npm config get userconfig` names, normally ~/.npmrc):
#       ignore-scripts=true (npm < 12) or dangerously-allow-all-scripts=false (npm >= 12),
#       min-release-age=<days> (npm >= 11.10)
#   pnpm global config.yaml (pnpm >= 11): dangerouslyAllowAllBuilds: false,
#       minimumReleaseAge: <minutes>, minimumReleaseAgeStrict: true
#   ~/.yarnrc (Yarn Classic): ignore-scripts true
#   ~/.yarnrc.yml (Yarn 2+): enableScripts: false, npmMinimalAgeGate: <minutes> (Yarn >= 4.10)
#   pip user config (the user file `pip config debug` lists last, normally ~/.config/pip/pip.conf):
#       [global] uploaded-prior-to = P<days>D (pip >= 26.1), written by `pip config --user set`.
#       pip rewrites that whole file when it sets a value, so its comments are lost (the backup
#       keeps them).
# <days> and <minutes> come from --soak (default 7d: min-release-age=7, P7D, 10080 minutes); npm's and
# pip's whole days round up, so they never soak less than asked. Bun's minimumReleaseAge (seconds, 604800
# for 7d) and uv's exclude-newer are checked but not written.
# Before its first change to a file it copies the file to <file>.wormsign-bak.<stamp> (mode 0600).
# After writing it asks the package manager for the value again, and reports PASS only
# if the package manager now sees it; if the package manager can no longer read its
# config at all, the edit is undone. It never deletes anything it did not create, never
# writes through a symlink to a missing file, and never touches credentials or shell profiles.
#
# Package managers are only asked for their version and settings (`--version`,
# `config get`, `npm root -g`, `pip config debug`), from an empty temp directory with
# corepack downloads disabled, so a corepack shim cannot fetch and run a new release. That
# directory is made where neither it nor any directory above it can be written by another
# user (TMPDIR, else XDG_RUNTIME_DIR, ~/.cache or HOME), because the package managers read
# config from the directories above the one they run in. Only absolute PATH entries are used. uv is
# asked to lock an empty project in that temp directory (`uv lock --offline`), which shows the
# cutoff it applies, and python3 to read uv.toml (tomllib) and to name the pip its ensurepip
# bundles.
# How each setting was verified, per package manager and version: docs/evidence/package-managers.md.
#
# Not covered, deliberately: source builds (pip's only-binary, uv's no-build), Python .pth files
# and ~/.pypirc tokens; docs/hardening.md says why.

set -euo pipefail

# Absolute PATH entries only, before any command runs: a relative one (".", an empty entry, "node_modules/.bin")
# would resolve node, awk, find and the rest in the directory this was started from, which may be an untrusted
# checkout. What is dropped is reported once the report starts.
PATH_DROPPED=""
path_kept=""
path_rest="${PATH:-}:"
while [ -n "$path_rest" ]; do
  path_d=${path_rest%%:*}
  path_rest=${path_rest#*:}
  case $path_d in
    /*) path_kept=${path_kept:+$path_kept:}$path_d ;;
    *) PATH_DROPPED="$PATH_DROPPED ${path_d:-(empty)}" ;;
  esac
done
[ -n "$path_kept" ] || { echo "PATH has no absolute directory, so no command can be run safely" >&2; exit 2; }
PATH=$path_kept
export PATH

MODE=check
SOAK=7d
OFFLINE=0
EXTRA_PATHS=()
# The oldest pip and uv whose release-age cutoff H12 and H13 accept, each run on 2026-10-08 in an isolated HOME
# (docs/evidence/package-managers.md#pip and #uv have the commands). pip 26.1 is the first pip that reads a relative
# uploaded-prior-to (P<n>D, whole days); pip 26.0.1 accepts only an absolute date, and P7D in its config makes install,
# download, lock, wheel, index and list fail ("Invalid isoformat string"); pip 25.3 has no such option and ignores the
# key. uv 0.9.17 is the first uv with a relative exclude-newer: uv 0.9.16 cannot parse exclude-newer = "7 days", and a
# fixed date goes stale.
# test/harden.test.ts checks that the minimum passes and the version just below fails.
PIP_MIN=26.1
UV_MIN=0.9.17
# uv 0.11.5 added exclude-newer to [[index]] entries (uv's changelogs/0.11.x.md: "Add `exclude-newer`
# to `[[tool.uv.index]]`"); uv 0.10.9 ignores the key there (measured).
UV_INDEX_MIN=0.11.5
# CDPATH='': with CDPATH set, cd to a relative directory prints the one it chose, which would end up in SCRIPT_DIR.
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
STAMP=$(date +%Y%m%d%H%M%S).$$

usage() {
  cat <<'EOF'
Usage: harden-dev.sh [--check | --apply] [--soak <duration>] [--offline] [--path <dir>]...

  --check            report only (default)
  --apply            apply the file changes listed in the header, with backups
  --soak <duration>  release-age cooldown to require: 7d, 72h, 2w (default 7d)
  --offline          skip the one check that contacts GitHub (gh auth status)
  --path <dir>       extra directory to search for worm artifacts (repeatable)

Exit status: 0 if no FAIL remains, 1 if any FAIL remains, 2 on usage error.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --check) MODE=check ;;
    --apply) MODE=apply ;;
    --soak) shift; SOAK=${1:-}; [ -n "$SOAK" ] || { echo "--soak needs a value" >&2; exit 2; } ;;
    --offline) OFFLINE=1 ;;
    --path)
      shift; [ -n "${1:-}" ] || { echo "--path needs a value" >&2; exit 2; }
      [ -d "$1" ] || { echo "--path $1: not a directory" >&2; exit 2; }
      EXTRA_PATHS+=("$1") ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

# ---- duration -> minutes ------------------------------------------------------
case "$SOAK" in
  *[!0-9hdwm]*|"") echo "invalid --soak '$SOAK' (examples: 7d, 72h, 2w)" >&2; exit 2 ;;
esac
num=${SOAK%[hdwm]}
unit=${SOAK#"$num"}
case "$num" in ''|*[!0-9]*) echo "invalid --soak '$SOAK'" >&2; exit 2 ;; esac
[ "${#num}" -le 6 ] || { echo "invalid --soak '$SOAK' (at most 6 digits)" >&2; exit 2; }
# Base 10: shell arithmetic reads a leading 0 as octal (010 would be 8, and 08 an error).
num=$((10#$num))
[ "$num" -gt 0 ] || { echo "--soak must be positive" >&2; exit 2; }
case "$unit" in
  h) SOAK_MIN=$((num * 60)) ;;
  d) SOAK_MIN=$((num * 1440)) ;;
  w) SOAK_MIN=$((num * 10080)) ;;
  m) SOAK_MIN=$num ;;
  *) echo "invalid --soak unit in '$SOAK'" >&2; exit 2 ;;
esac
SOAK_DAYS=$(( (SOAK_MIN + 1439) / 1440 ))   # npm counts days; round up so we never soak less than asked
SOAK_SECONDS=$((SOAK_MIN * 60))

# ---- reporting ---------------------------------------------------------------
FAILS=0; WARNS=0; PASSES=0
# C0 control characters (ESC, CR, LF, TAB...) and DEL become '?': a file name (H08, H10,
# H11) must not be able to move the cursor, recolour or rewrite its own line on the
# terminal. C1 controls such as U+009B are replaced only in a UTF-8 locale and in a
# string that is valid UTF-8; [[:cntrl:]] is locale-dependent.
say() { printf '%-6s %-4s %s\n' "$1" "$2" "${3//[[:cntrl:]]/?}"; }
pass() { PASSES=$((PASSES + 1)); say "[PASS]" "$1" "$2"; }
warn() { WARNS=$((WARNS + 1)); say "[WARN]" "$1" "$2"; }
fail() { FAILS=$((FAILS + 1)); say "[FAIL]" "$1" "$2"; }
info() { say "[INFO]" "$1" "$2"; }
skip() { say "[SKIP]" "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---- helpers -----------------------------------------------------------------
# private_dir DIR: DIR is absolute, and it and every directory above it are owned by root or by this user and
# writable by neither group nor others. The package managers this script runs read config from the directories above
# the one they run in (Yarn Classic reads .yarnrc in each one and executes its yarn-path; npm reads the .npmrc beside
# the nearest package.json; corepack follows the nearest packageManager pin), so the empty directory they run from
# must sit where no other user can plant such a file. A shared /tmp (mode 1777) is not such a place.
private_dir() {
  local d
  case $1 in /*) ;; *) return 1 ;; esac
  d=$(CDPATH='' cd -- "$1" 2>/dev/null && pwd -P) || return 1
  while :; do
    [ -n "$(find "$d" -maxdepth 0 \( -user 0 -o -user "$EUID" \) ! -perm -0020 ! -perm -0002 -print 2>/dev/null)" ] || return 1
    [ "$d" != / ] || return 0
    d=${d%/*}
    d=${d:-/}
  done
}
# The first private one of: TMPDIR (else /tmp), XDG_RUNTIME_DIR, the user cache directory, HOME. Only an existing
# directory is used; the temporary directory made in it is removed on exit.
WORK_BASE=""
for d in "${TMPDIR:-/tmp}" "${XDG_RUNTIME_DIR:-}" "${XDG_CACHE_HOME:-$HOME/.cache}" "$HOME"; do
  if [ -n "$d" ] && private_dir "$d"; then WORK_BASE=$d; break; fi
done
if [ -z "$WORK_BASE" ]; then
  echo "no private directory for temporary files: TMPDIR (or /tmp), XDG_RUNTIME_DIR, ~/.cache and HOME are each missing, or writable by another user (as is a directory above them). Set TMPDIR to a directory only you can write." >&2
  exit 2
fi
WORK=$(mktemp -d "$WORK_BASE/wormsign-harden.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
mkdir "$WORK/cwd"

# version_ge A B: succeeds if dotted version A >= B (numeric fields only).
version_ge() {
  awk -v a="$1" -v b="$2" 'BEGIN {
    na = split(a, x, "."); nb = split(b, y, ".")
    n = (na > nb) ? na : nb
    for (i = 1; i <= n; i++) {
      xi = x[i] + 0; yi = y[i] + 0
      if (xi > yi) exit 0
      if (xi < yi) exit 1
    }
    exit 0
  }'
}
is_int() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; }
# blocked FILE: succeeds, with BLOCKED set to it, when the nearest existing directory on the way to FILE (HOME at the
# highest) cannot be searched. Behind such a directory (a root-owned ~/.docker after `sudo docker login`), -e and -f
# are false even for a file that is there, so "not found" would be a guess.
blocked() {
  BLOCKED=${1%/*}
  while [ -n "$BLOCKED" ] && [ "$BLOCKED" != "$HOME" ] && [ ! -d "$BLOCKED" ]; do BLOCKED=${BLOCKED%/*}; done
  [ -d "$BLOCKED" ] && [ ! -x "$BLOCKED" ]
}

# pm_in DIR TOOL ARGS...: run a package manager without side effects, from DIR (a directory
# this script made in $WORK): stdin closed, corepack forbidden to download, npm's logs and cache,
# yarn's and uv's caches kept in $WORK, no compile caches (npm 10, corepack and Yarn Classic write
# them to $TMPDIR), no pip version check, no Python bytecode and no virtual environment, and uv
# never downloads a Python. pip's `quiet` setting is overridden (PIP_QUIET=0: the environment beats
# its config files), since with it `pip config debug` prints nothing. uv is not pointed at another
# project (UV_PROJECT, UV_WORKING_DIR: `uv lock` would lock that project and write its uv.lock)
# nor told that the lock must already exist (UV_FROZEN, UV_LOCKED: the probe has none).
# stderr goes to $WORK/pm.err, for the first error line of a failure.
pm_in() {
  local dir=$1
  shift
  (CDPATH='' cd -- "$dir" && unset VIRTUAL_ENV UV_PROJECT UV_WORKING_DIR UV_FROZEN UV_LOCKED &&
    COREPACK_ENABLE_NETWORK=0 COREPACK_ENABLE_DOWNLOAD_PROMPT=0 COREPACK_ENABLE_AUTO_PIN=0 \
    npm_config_update_notifier=false pnpm_config_update_notifier=false npm_config_logs_max=0 \
    npm_config_cache="$WORK/npm-cache" YARN_CACHE_FOLDER="$WORK/yarn-cache" \
    NODE_DISABLE_COMPILE_CACHE=1 DISABLE_V8_COMPILE_CACHE=1 \
    UV_CACHE_DIR="$WORK/uv-cache" UV_PYTHON_DOWNLOADS=never \
    PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_QUIET=0 PYTHONDONTWRITEBYTECODE=1 \
    "$@" </dev/null 2>"$WORK/pm.err")
}
# pm TOOL ARGS...: pm_in from an empty directory, so no project's packageManager pin or project
# config applies.
pm() { pm_in "$WORK/cwd" "$@"; }
# first_error: the first line of the last pm call's stderr that mentions an error, else its first
# two non-blank lines (pip says "Configuration file could not be loaded." and then why).
first_error() {
  local l
  l=$(grep -m 1 -i 'error' "$WORK/pm.err" 2>/dev/null) ||
    l=$(awk 'NF { printf "%s%s", (n++ ? " " : ""), $0; if (n == 2) exit }' "$WORK/pm.err" 2>/dev/null) || l=""
  printf '%s' "$l"
}

# cfg TOOL ARGS...: the last line a package manager prints, empty if it said the value
# is unset ("undefined" / "null"). Fails if the package manager failed.
cfg() {
  local out
  out=$(pm "$@") || return 1
  out=$(printf '%s\n' "$out" | tail -n 1 | tr -d '\r')
  case "$out" in undefined|null) out="" ;; esac
  printf '%s\n' "$out"
}

# pm_version TOOL: the tool's version if it reports a plain dotted one, else empty.
pm_version() {
  local v re='^[0-9]+(\.[0-9]+)+([-+][0-9A-Za-z.-]+)?$'
  v=$(cfg "$1" --version)
  if [[ $v =~ $re ]]; then printf '%s\n' "$v"; fi
}

no_version() { # no_version ID TOOL
  local why="" fix=""
  # corepack 0.32.0 shims only npm, pnpm and yarn ("corepack install -g bun@..." is a usage error).
  case $2 in npm|pnpm|yarn)
    why=" (a corepack shim with nothing cached, or a config file it cannot parse)"
    fix="For a shim, install a pinned release (corepack install -g $2@<version>); otherwise " ;;
  esac
  warn "$1" "$2 at $(command -v "$2") did not report a version offline$why, so its settings were not checked. $fix'$2 --version' shows the error."
}

# Value predicates for `setting`: PRED CURRENT WANT
eq() { [ "$1" = "$2" ]; }
at_least() { is_int "$1" && [ "$1" -ge "$2" ]; }
not_true() { [ "$1" != true ]; }
not_false() { [ "$1" != false ]; }

BACKED_UP=$'\n'
backup_once() { # backup_once FILE: copy FILE aside the first time it is about to change
  local f=$1
  case "$BACKED_UP" in *$'\n'"$f"$'\n'*) return 0 ;; esac
  if [ -e "$f" ]; then
    # Mode 0600 whatever the file's own mode (a restore copies the content back, never the mode): a token file kept
    # private only by the 0700 directory its symlink points into would otherwise be copied, readable, next to the link.
    # noclobber (set -C): an existing path is never written through.
    (umask 077 && set -C && cat -- "$f" >"$f.wormsign-bak.$STAMP") || return 1
    info "" "backup: $f.wormsign-bak.$STAMP"
  fi
  BACKED_UP="$BACKED_UP$f"$'\n'
}

# is_key(line): line sets `key` (awk vars key, sep). Leading spaces are allowed except
# in YAML (sep ": "), where indentation means nesting; the key may be in double or single
# quotes (both are valid YAML, and a missed key would be written twice, which pnpm
# rejects); any spacing around the separator.
KEY_AWK='function is_key(line,  rest) {
  if (sep !~ /^:/) sub(/^[ \t]+/, "", line)
  sub(/^["\047]/, "", line)
  if (index(line, key) != 1) return 0
  rest = substr(line, length(key) + 1)
  sub(/^["\047]/, "", rest)
  return rest ~ /^[ \t=:]/
}
'

# set_line FILE KEY SEP VALUE: leave FILE with one KEY line, KEY<SEP>VALUE, where the
# first one was; later duplicates are dropped, because npm and yarn use the last one.
# Returns 0 if written, 1 if FILE already said exactly that, 2 if backup or write failed,
# 3 if FILE is a symlink to a file that does not exist (nothing is written).
# Before writing it keeps FILE's previous content in $WORK/prev (absent if FILE was new),
# for undo_line.
# Callers run it in `||` context, where errexit is off, so every step is checked here.
set_line() {
  local file="$1" key="$2" sep="$3" want="$2$3$4" tmp="$WORK/set_line"
  # A dangling symlink (a dotfiles link whose target is not made yet) is not "no file": the write would create the
  # target through it, and undo_line would then delete the link, which this script did not create.
  if [ -L "$file" ] && [ ! -e "$file" ]; then return 3; fi
  if [ -f "$file" ] && [ "$(awk -v key="$key" -v sep="$sep" "$KEY_AWK"'is_key($0)' "$file")" = "$want" ]; then
    return 1
  fi
  backup_once "$file" || return 2
  if [ -f "$file" ]; then
    awk -v key="$key" -v sep="$sep" -v want="$want" "$KEY_AWK"'
      is_key($0) { if (!done) print want; done = 1; next }
      { print }
      END { if (!done) print want }' "$file" >"$tmp" || return 2
    cp "$file" "$WORK/prev" || return 2
    cat "$tmp" >"$file" || return 2   # rewrite in place: keeps the file's mode and owner
  else
    rm -f "$WORK/prev"
    mkdir -p "$(dirname "$file")" || return 2
    (umask 077 && printf '%s\n' "$want" >"$file") || return 2
  fi
}
undo_line() { # undo_line FILE: put FILE back as it was before the last set_line
  if [ -f "$WORK/prev" ]; then cat "$WORK/prev" >"$1"; else rm -f "$1"; fi
}

# setting ID WHAT WHY PRED WANT FILE KEY SEP -- READER...
# READER prints the value the package manager actually uses. PASS if PRED(value, WANT).
# Otherwise FAIL (WHY says what that costs), or with --apply write KEY<SEP>WANT to FILE,
# read again, and PASS only if the package manager now reports a passing value. If
# READER fails (the package manager cannot read its config), nothing is judged or written,
# and a write that caused it is undone.
setting() {
  local id="$1" what="$2" why="$3" pred="$4" want="$5" file="$6" key="$7" sep="$8" cur rc=0 wants="$5"
  shift 9
  case "$pred" in at_least) wants=">= $want" ;; not_true) wants="not true" ;; not_false) wants="not false" ;; esac
  if ! cur=$("$@"); then
    warn "$id" "$what: the package manager failed to report $key (is its config file valid?), so it was not checked"
    return 0
  fi
  if "$pred" "$cur" "$want"; then pass "$id" "$what: $key is ${cur:-unset}"; return 0; fi
  if [ "$MODE" != apply ]; then
    fail "$id" "$what: $key is ${cur:-unset} (want $wants; fixable with --apply, which edits $file). $why"
    return 0
  fi
  set_line "$file" "$key" "$sep" "$want" || rc=$?
  if [ "$rc" -eq 3 ]; then
    warn "$id" "$file is a symlink to a file that does not exist, so --apply neither wrote through it nor removed it. Create the file it points to (or remove the link), then re-run --apply."
    fail "$id" "$what: $key is ${cur:-unset} (want $wants; not written, see the WARN above). $why"
    return 0
  fi
  if [ "$rc" -ge 2 ]; then
    fail "$id" "$what: could not write $file, so $key is still ${cur:-unset} (want $wants)"
    return 0
  fi
  [ "$rc" -eq 1 ] || info "$id" "wrote $key$sep$want to $file"
  if ! cur=$("$@"); then
    if [ "$rc" -eq 0 ] && ! undo_line "$file"; then
      fail "$id" "$what: could not safely edit $file: the package manager cannot read it after the write, and undoing it failed. Restore it from the backup above."
    else
      fail "$id" "$what: could not safely edit $file: the package manager could not read it after the write; the file is back as it was. Set $key$sep$want by hand."
    fi
    return 0
  fi
  if "$pred" "$cur" "$want"; then
    pass "$id" "$what: $key is ${cur:-unset} (just applied)"
  else
    fail "$id" "$what: $file says $key$sep$want but the package manager still reports ${cur:-unset}; something with higher precedence overrides it (see docs/hardening.md)"
  fi
}

echo "wormsign harden-dev: mode=$MODE soak=${SOAK} (npm ${SOAK_DAYS}d, pnpm/yarn ${SOAK_MIN}min, bun ${SOAK_SECONDS}s)"
[ "$MODE" = check ] && echo "Check mode: changes no settings (gh, run by H09, may write its own state). Re-run with --apply to apply the fixes marked 'fixable'."
echo
if [ -n "$PATH_DROPPED" ]; then
  warn "" "PATH entries that are not absolute directories were left out for this run, so no command runs from the current directory:$PATH_DROPPED"
fi

# ---- H14 the wiper's token watcher (check only) -----------------------------
# Checked first, before any package manager runs, because what it finds changes what to do about every other FAIL.
# The May 2026 Mini Shai-Hulud payload installs a gh-token-monitor daemon that polls GitHub with the stolen token and
# runs rm -rf ~/ when the token is revoked (docs/incident-response.md, step 1). Its files, as the reports give them:
#   ~/Library/LaunchAgents/com.user.gh-token-monitor.plist   macOS LaunchAgent  (Wiz; StepSecurity)
#   ~/.config/systemd/user/gh-token-monitor.service          Linux user service (Wiz; StepSecurity)
#   ~/.local/bin/gh-token-monitor.sh                         "Writes monitor script to ~/.local/bin/gh-token-monitor.sh"
#   ~/.config/gh-token-monitor                               "Stores token in ~/.config/gh-token-monitor/token";
#                                                            the remediation is "rm -rf ~/.config/gh-token-monitor"
# Wiz, 2026-05-12: https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
# StepSecurity, 2026-05-11 (the installer, payload_1.sh, and its remediation commands):
#   https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem
# The installer builds its paths from ${HOME}, not XDG_CONFIG_HOME. The IOC data does not hold these paths (they are
# not files a project scan meets), and H14 must not depend on a build, as H11 does. Anything at one of them, a
# symlink included, is a FAIL. --apply never removes or unloads any of them: removing them could be the trigger (no
# report says that removal is safe for every variant), and the files are evidence; stopping the watcher is a step of
# the incident response, done by hand.
WATCHER_PATHS=("$HOME/Library/LaunchAgents/com.user.gh-token-monitor.plist" "$HOME/.config/systemd/user/gh-token-monitor.service"
  "$HOME/.local/bin/gh-token-monitor.sh" "$HOME/.config/gh-token-monitor")
ISOLATE_DOC="docs/incident-response.md#1-isolate-the-machine-before-revoking-anything"
WATCHER_FOUND=0
watcher_dirs=$'\n'
for f in "${WATCHER_PATHS[@]}"; do
  if blocked "$f"; then
    case "$watcher_dirs" in *$'\n'"$BLOCKED"$'\n'*) ;; *)
      watcher_dirs="$watcher_dirs$BLOCKED"$'\n'
      warn H14 "$BLOCKED could not be searched, so whether the gh-token-monitor watcher's files are in it is unknown. Check before revoking any token: $ISOLATE_DOC" ;;
    esac
  elif [ -e "$f" ] || [ -L "$f" ]; then
    WATCHER_FOUND=$((WATCHER_FOUND + 1))
    fail H14 "$f exists (critical; do not revoke tokens yet: isolate this machine first): a file of the gh-token-monitor watcher, which runs rm -rf ~/ when its stolen GitHub token is revoked. See $ISOLATE_DOC; --apply leaves it in place."
  fi
done
if [ "$WATCHER_FOUND" -eq 0 ] && [ "$watcher_dirs" = $'\n' ]; then
  pass H14 "no gh-token-monitor watcher files at: ${WATCHER_PATHS[*]}"
fi

# ---- H01/H02 npm -------------------------------------------------------------
npm_get() { cfg npm config get "$1"; }
npm_age_days() { # the cooldown npm applies, in whole days, or empty
  local before
  before=$(npm_get before)
  # An explicit `before` date wins over min-release-age, and npm 11.10.x reports
  # min-release-age only as a computed `before`; either way its age is the cooldown.
  if [ -n "$before" ]; then
    node -e 'const t = Date.parse(process.argv[1]); if (t) console.log(Math.floor((Date.now() - t) / 864e5))' "$before" 2>/dev/null || true
  else
    npm_get min-release-age
  fi
}
NPM_V=""
if ! have npm; then
  skip H01 "npm not installed"; skip H02 "npm not installed"
else
  NPM_V=$(pm_version npm)
  if [ -z "$NPM_V" ]; then
    no_version H01 npm
  else
    NPMRC=$(npm_get userconfig) || true
    [ -n "$NPMRC" ] || NPMRC=$HOME/.npmrc
    if version_ge "$NPM_V" 12 && [ "$(npm_get ignore-scripts)" != true ]; then
      setting H01 "npm $NPM_V (dependency install scripts need package.json allowScripts approval)" "true makes npm run every dependency's install scripts." \
        not_true false "$NPMRC" dangerously-allow-all-scripts = -- npm_get dangerously-allow-all-scripts
    else
      setting H01 "npm $NPM_V" "Without it, every dependency's install scripts run on npm install." \
        eq true "$NPMRC" ignore-scripts = -- npm_get ignore-scripts
    fi
    if version_ge "$NPM_V" 11.10; then
      setting H02 "npm $NPM_V" "min-release-age is the cooldown in days before npm resolves a new version." at_least "$SOAK_DAYS" "$NPMRC" min-release-age = -- npm_age_days
    else
      fail H02 "npm $NPM_V has no working release-age cooldown: min-release-age needs npm >= 11.10 (older npm accepts the key and ignores it). Upgrade npm, then re-run."
    fi
  fi
fi

# ---- H03/H04 pnpm ------------------------------------------------------------
pnpm_get() { cfg pnpm config get "$1"; }
pnpm_config_dir() { # pnpm's global config directory (its getConfigDir)
  if [ -n "${XDG_CONFIG_HOME:-}" ]; then echo "$XDG_CONFIG_HOME/pnpm"
  elif [ "$(uname -s)" = Darwin ]; then echo "$HOME/Library/Preferences/pnpm"
  else echo "$HOME/.config/pnpm"; fi
}
if ! have pnpm; then
  skip H03 "pnpm not installed"; skip H04 "pnpm not installed"
else
  PNPM_V=$(pm_version pnpm)
  PNPM_YAML="$(pnpm_config_dir)/config.yaml"
  if [ -z "$PNPM_V" ]; then
    no_version H03 pnpm
  else
    if ! version_ge "$PNPM_V" 10; then
      fail H03 "pnpm $PNPM_V runs dependency build scripts by default (pnpm >= 10 does not). Upgrade pnpm."
    elif ! version_ge "$PNPM_V" 10.26; then
      # GHSA-379q-355j-w6rj (CVE-2025-69264), from the advisory: fixed in 10.26.0.
      fail H03 "pnpm $PNPM_V runs a git-hosted dependency's prepare, prepublish and prepack scripts while fetching it, despite its default script blocking (CVE-2025-69264, fixed in 10.26.0). Upgrade pnpm to 10.26 or newer."
    elif version_ge "$PNPM_V" 11; then
      setting H03 "pnpm $PNPM_V (dependency build scripts need allowBuilds approval)" "true makes pnpm run every dependency's build scripts." \
        not_true false "$PNPM_YAML" dangerouslyAllowAllBuilds ": " -- pnpm_get dangerouslyAllowAllBuilds
    elif ! allow_all=$(pnpm_get dangerouslyAllowAllBuilds); then
      warn H03 "pnpm $PNPM_V: the package manager failed to report dangerouslyAllowAllBuilds (is its config file valid?), so it was not checked"
    elif [ "$allow_all" = true ]; then
      fail H03 "pnpm $PNPM_V: dangerouslyAllowAllBuilds is true, so every dependency build script runs. Remove it from ~/.npmrc or $(pnpm_config_dir)/rc (not auto-fixed for pnpm 10)."
    else
      pass H03 "pnpm $PNPM_V runs dependency build scripts only if onlyBuiltDependencies approves them"
    fi
    if ! version_ge "$PNPM_V" 10.16; then
      fail H04 "pnpm $PNPM_V has no minimumReleaseAge (needs pnpm >= 10.16; 11 or later recommended). Upgrade pnpm."
    elif ! version_ge "$PNPM_V" 11; then
      if ! age=$(pnpm_get minimumReleaseAge); then
        warn H04 "pnpm $PNPM_V: the package manager failed to report minimumReleaseAge (is its config file valid?), so it was not checked"
      elif at_least "$age" "$SOAK_MIN"; then
        warn H04 "pnpm $PNPM_V: minimumReleaseAge is $age, but pnpm 10 does not re-check versions already in a lockfile, and 10.16.0 skipped the check for versions in its metadata cache. Upgrade to pnpm 11."
      else
        fail H04 "pnpm $PNPM_V: minimumReleaseAge is ${age:-unset} (want >= $SOAK_MIN minutes). Upgrade to pnpm 11, where --apply can set it (not auto-applied for pnpm 10)."
      fi
    else
      setting H04 "pnpm $PNPM_V" "minimumReleaseAge is the cooldown in minutes; pnpm's built-in 1-day default is not strict and lets a requested new version through." at_least "$SOAK_MIN" "$PNPM_YAML" minimumReleaseAge ": " -- pnpm_get minimumReleaseAge
      setting H04 "pnpm $PNPM_V" "false lets pnpm install a too-new version anyway (it adds it to minimumReleaseAgeExclude)." not_false true "$PNPM_YAML" minimumReleaseAgeStrict ": " -- pnpm_get minimumReleaseAgeStrict
    fi
  fi
fi

# ---- H05/H06 yarn ------------------------------------------------------------
yarn_get() { cfg yarn config get "$1"; }
if ! have yarn; then
  skip H05 "yarn not installed"; skip H06 "yarn not installed"
else
  YARN_V=$(pm_version yarn)
  if [ -z "$YARN_V" ]; then
    no_version H05 yarn
  else
    case "$YARN_V" in
      1.*)
        warn H05 "Yarn Classic $YARN_V has no release-age setting. Run 'wormsign soak' before installs, or move to Yarn >= 4.10 or pnpm >= 11."
        # Yarn Classic does not read ignore-scripts from ~/.npmrc; ~/.yarnrc is its own file.
        setting H06 "Yarn Classic $YARN_V" "Without it, every dependency's install scripts run on yarn install." \
          eq true "$HOME/.yarnrc" ignore-scripts " " -- yarn_get ignore-scripts
        ;;
      *)
        if version_ge "$YARN_V" 4.10; then
          # Bare minutes: Yarn 4.10.3 reads "3d" as 3 minutes; 4.18.1 reads it as 4320.
          setting H05 "yarn $YARN_V" "npmMinimalAgeGate is the cooldown in minutes before yarn resolves a new version." at_least "$SOAK_MIN" "$HOME/.yarnrc.yml" npmMinimalAgeGate ": " -- yarn_get npmMinimalAgeGate
        else
          fail H05 "yarn $YARN_V has no npmMinimalAgeGate (needs Yarn >= 4.10). Upgrade Yarn."
        fi
        setting H06 "yarn $YARN_V" "Otherwise yarn runs every dependency's build scripts." \
          eq false "$HOME/.yarnrc.yml" enableScripts ": " -- yarn_get enableScripts
        ;;
    esac
  fi
fi

# ---- H07 bun (report only) ---------------------------------------------------
# bun has no command that prints its effective config, so this reads the global
# bunfig files themselves; when both exist and set it, the lower value counts.
# The value is read as a TOML decimal integer, as Bun reads it: 604_800 is 604800
# (Bun 1.3 src/interchange/toml/lexer.zig, Bun 1.4 src/parsers/toml.rs). Any other
# value (604__800, 0604800, 6.048e5, a string) prints "unreadable <value>", a FAIL,
# as soak's readBunfig reports it (WS-SK-004). CRLF line ends are read, as soak and Bun read them. A table header,
# [name] or [[name]] (an array of tables, never [install]), may end in a comment; a line that starts inside a
# multi-line string (""" or ''') is its content, never a header or a key. soak's bunInstallLines reads them alike.
bun_global_age() {
  local f files=()
  for f in "${XDG_CONFIG_HOME:+$XDG_CONFIG_HOME/.bunfig.toml}" "$HOME/.bunfig.toml"; do
    [ -n "$f" ] && [ -r "$f" ] && files+=("$f")
  done
  [ "${#files[@]}" -gt 0 ] || return 0
  awk '
    # The multi-line string delimiter open at the end of line, given the one open at its start ("" for none).
    function mlopen(line, open,    a, b, k) {
      while (1) {
        if (open != "") { k = index(line, open); if (k == 0) return open; line = substr(line, k + 3); open = "" }
        else {
          a = index(line, "\"\"\""); b = index(line, "\047\047\047")
          if (a == 0 && b == 0) return ""
          k = (a != 0 && (b == 0 || a < b)) ? a : b
          open = substr(line, k, 3); line = substr(line, k + 3)
        }
      }
    }
    FNR == 1 { section = ""; ml = "" }
    { sub(/\r$/, ""); was = ml; ml = mlopen($0, ml); if (was != "") next }
    /^[ \t]*\[\[?[^]]+\]\]?[ \t]*(#.*)?$/ { s = $0; sub(/[ \t]*#.*$/, "", s); gsub(/[ \t]/, "", s); section = s; next }
    section == "[install]" && /^[ \t]*minimumReleaseAge[ \t]*=/ {
      v = $0; sub(/^[^=]*=[ \t]*/, "", v); sub(/[ \t]*(#.*)?$/, "", v)
      if (v !~ /^(0|[1-9](_?[0-9])*)$/) { bad = v; unreadable = 1; next }
      gsub(/_/, "", v)
      if (min == "" || v + 0 < min + 0) min = v
    }
    END { if (unreadable) print "unreadable " bad; else if (min != "") print min }' "${files[@]}"
}
if ! have bun; then
  skip H07 "bun not installed"
else
  BUN_V=$(pm_version bun)
  if [ -z "$BUN_V" ]; then
    no_version H07 bun
  elif ! version_ge "$BUN_V" 1.3; then
    fail H07 "bun $BUN_V has no minimumReleaseAge (needs Bun >= 1.3). Upgrade bun."
  else
    age=$(bun_global_age)
    if [ "${age#unreadable }" != "$age" ]; then
      fail H07 "bun $BUN_V: global bunfig [install] minimumReleaseAge is ${age#unreadable }, which is not a whole number of seconds (digits, with _ only between digits). Write 'minimumReleaseAge = $SOAK_SECONDS' under [install] in ~/.bunfig.toml (not auto-applied)."
    elif at_least "$age" "$SOAK_SECONDS"; then
      pass H07 "bun $BUN_V: global bunfig [install] minimumReleaseAge is $age seconds"
    else
      fail H07 "bun $BUN_V: global bunfig [install] minimumReleaseAge is ${age:-unset} (want >= $SOAK_SECONDS seconds). Add 'minimumReleaseAge = $SOAK_SECONDS' under [install] in ~/.bunfig.toml (not auto-applied)."
    fi
  fi
fi

# ---- H08 plaintext tokens ----------------------------------------------------
# Prints file, line number and the kind of credential; never any part of the value.
# A value that is a reference ($VAR, ${VAR}, $(cmd), fish (cmd)) is not a finding.
# shellcheck disable=SC2016  # an awk program: its $ is awk syntax, not shell
TOKEN_AWK='
function literal(v, min) {
  sub(/^[ \t=:]+/, "", v); sub(/^["\047]/, "", v); sub(/["\047]?[ \t]*$/, "", v)
  return length(v) >= min && v !~ /^[$`(]/
}
function long(re, min) { return match($0, re) && RLENGTH >= min }
/^[ \t]*[#;]/ { next }
{
  kind = ""
  if (match($0, /(^|[^A-Za-z0-9_])(_authToken|_auth|_password|npmAuthToken|npmAuthIdent)["\047]?[ \t]*[=: \t]/)) {
    if (literal(substr($0, RSTART + RLENGTH), 1)) kind = "registry credential (_authToken/_auth/_password/npmAuthToken)"
  } else if (match($0, /^[ \t]*((export|typeset|declare|readonly|local)([ \t]+-[A-Za-z]+)*[ \t]+)?(NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|CLOUDFLARE_API_TOKEN|DIGITALOCEAN_ACCESS_TOKEN)=/) ||
             match($0, /^[ \t]*set([ \t]+-[A-Za-z]+)*[ \t]+(NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|CLOUDFLARE_API_TOKEN|DIGITALOCEAN_ACCESS_TOKEN)[ \t]/)) {
    if (literal(substr($0, RSTART + RLENGTH), 8)) kind = "secret variable with a literal value"
  }
  if (kind == "" && match($0, /[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\/@ \t"\047:]+:[^\/@ \t"\047]+@/) && substr($0, RSTART, RLENGTH) !~ /\$/)
    kind = "user:password in a URL"
  if (kind == "" && (long("npm_[A-Za-z0-9]+", 40) || long("gh[pousr]_[A-Za-z0-9]+", 40) || long("github_pat_[A-Za-z0-9_]+", 61) || long("AKIA[0-9A-Z]+", 20)))
    kind = "token-shaped string"
  if (kind != "") print FNR "\t" kind
}'
token_files=("$HOME/.npmrc" "$HOME/.yarnrc" "$HOME/.yarnrc.yml" "$HOME/.bunfig.toml" "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.zshenv" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.config/fish/config.fish")
if [ -n "${NPMRC:-}" ] && [ "$NPMRC" != "$HOME/.npmrc" ]; then token_files+=("$NPMRC"); fi
# pip's user config files, where a private index's credentials usually sit (index-url = https://user:token@host/...),
# and which H12's --apply backs up: the legacy ~/.pip/pip.conf, ~/.config/pip/pip.conf (Linux, and macOS when it
# exists), $XDG_CONFIG_HOME/pip/pip.conf and macOS's ~/Library/Application Support/pip/pip.conf (pip's
# configuration.py and its platformdirs user_config_dir).
token_files+=("$HOME/.pip/pip.conf" "$HOME/.config/pip/pip.conf" "$HOME/Library/Application Support/pip/pip.conf")
if [ -n "${XDG_CONFIG_HOME:-}" ] && [ "$XDG_CONFIG_HOME" != "$HOME/.config" ]; then token_files+=("$XDG_CONFIG_HOME/pip/pip.conf"); fi
found_tokens=0; scanned=0; unreadable=0
for f in "${token_files[@]}"; do
  # Backups made by --apply are full copies, so they are scanned too.
  for g in "$f" "$f".wormsign-bak.*; do
    [ -e "$g" ] || continue
    if [ -d "$g" ] || ! hits=$(awk "$TOKEN_AWK" "$g" 2>/dev/null); then
      unreadable=$((unreadable + 1))
      warn H08 "$g could not be read, so it was not scanned"
      continue
    fi
    scanned=$((scanned + 1))
    while IFS=$'\t' read -r n kind; do
      [ -n "$n" ] || continue
      found_tokens=$((found_tokens + 1))
      fail H08 "$g:$n $kind. Move it to a keychain or an env var set at runtime, then rotate it."
    done <<EOF
$hits
EOF
  done
done
# A PASS only when every file was read: a file that could not be scanned is not clean, it is unknown.
if [ "$found_tokens" -eq 0 ] && [ "$unreadable" -eq 0 ]; then
  pass H08 "no plaintext tokens in npm/yarn/bun/pip config or shell profiles ($scanned file(s) scanned)"
elif [ "$found_tokens" -eq 0 ]; then
  info H08 "no plaintext tokens in the $scanned file(s) scanned; $unreadable file(s) could not be scanned (see the WARN above)"
fi

# ---- H09 gh CLI scopes -------------------------------------------------------
if ! have gh; then
  skip H09 "gh not installed"
elif [ "$OFFLINE" = 1 ]; then
  skip H09 "gh scope check skipped (--offline)"
else
  # One call to GitHub, made by gh itself. It prints one block per account on every host:
  # "Logged in to <host> account <user>", or "Failed to log in to" / "Timeout trying to
  # log in to" when gh could not verify the token (offline, rate-limited, expired); only
  # the first kind has a "Token scopes:" line, and not even that for fine-grained tokens.
  # One record per block: state, host, user ("(token)" for an env token), active, scopes.
  GH_OUT=$(gh auth status 2>&1 </dev/null || true)
  accounts=$(printf '%s\n' "$GH_OUT" | awk '
    function flush() { if (state != "") print state "\t" host "\t" user "\t" active "\t" scopes; state = "" }
    { gsub(/\033\[[0-9;]*m/, "") }
    match($0, / (Logged in|Failed to log in|Timeout trying to log in) to [^ ]+ (account [^ ]+|using token)/) {
      flush()
      state = ($0 ~ / Logged in /) ? "ok" : (($0 ~ / Timeout /) ? "timeout" : "failed")
      m = substr($0, RSTART, RLENGTH); sub(/^.* in to /, "", m); split(m, w, " ")
      host = w[1]; user = (w[2] == "account") ? w[3] : "(token)"; active = "?"; scopes = ""
      next
    }
    /- Active account:/ { active = $NF; next }
    /- Token scopes:/ { s = $0; sub(/.*Token scopes: */, "", s); gsub(/[\047 ]/, "", s); scopes = s }
    END { flush() }')
  if [ -z "$accounts" ]; then
    case "$GH_OUT" in
      *"not logged in"*) skip H09 "gh is not logged in" ;;
      *) warn H09 "gh auth status listed no account in a form this script reads, so no token scopes were checked" ;;
    esac
  else
    while IFS=$'\t' read -r state host user active scopes; do
      if [ "$state" != ok ]; then
        warn H09 "gh account $user on $host: token scopes unknown, gh could not log in ($state). Re-run when $host is reachable; if the token is stale, remove it."
        continue
      fi
      if [ -z "$scopes" ]; then
        info H09 "gh account $user on $host reports no token scopes (fine-grained and GitHub App tokens do not), so they were not checked"
        continue
      fi
      bad=""; broad=""
      for s in delete_repo admin:org admin:repo_hook admin:org_hook admin:public_key admin:gpg_key write:org; do
        case ",$scopes," in *",$s,"*) bad="$bad,$s" ;; esac
      done
      # repo, read:org and gist are gh's minimum and cannot be removed, so only these are flagged.
      for s in workflow write:packages; do
        case ",$scopes," in *",$s,"*) broad="$broad,$s" ;; esac
      done
      bad=${bad#,}; broad=${broad#,}
      switch=""
      [ "$active" = true ] || switch="gh auth switch -h $host -u $user && "
      if [ -n "$bad" ]; then
        fail H09 "gh account $user on $host has destructive/admin scopes ($bad). Remove them: ${switch}gh auth refresh -h $host -r $bad"
      elif [ -n "$broad" ]; then
        warn H09 "gh account $user on $host has broad scopes ($broad): a stolen token can push workflows or packages. Remove them: ${switch}gh auth refresh -h $host -r $broad"
      else
        pass H09 "gh account $user on $host: scopes look narrow ($scopes)"
      fi
    done <<EOF
$accounts
EOF
  fi
fi

# ---- H10 cloud credential files on disk -------------------------------------
# Presence only: these are what a harvesting worm reads. Values are never printed.
file_mode() { # octal mode. GNU stat first: on GNU, -f means --file-system and prints a status block.
  local m
  m=$(stat -c '%a' "$1" 2>/dev/null) || m=$(stat -f '%Lp' "$1" 2>/dev/null) || m="?"
  printf '%s' "$m"
}
cloud_found=0
note_cred() {
  cloud_found=$((cloud_found + 1))
  warn H10 "$1 present (mode $(file_mode "$1")). $2"
}
cred_dirs=$'\n'
cred() { # cred FILE PATTERN WHY: WARN if FILE has a line matching PATTERN (ERE; empty: any line)
  # A directory on the way to FILE that cannot be searched is reported, once, instead of FILE.
  if blocked "$1"; then
    case "$cred_dirs" in *$'\n'"$BLOCKED"$'\n'*) ;; *)
      cred_dirs="$cred_dirs$BLOCKED"$'\n'
      note_cred "$BLOCKED" "It could not be searched, so the credential files in it were not checked." ;;
    esac
    return 0
  fi
  [ -f "$1" ] || return 0
  if [ ! -r "$1" ]; then note_cred "$1" "It could not be read, so what it holds was not checked."
  elif grep -Eq "$2" "$1"; then note_cred "$1" "$3"; fi
}
cred "$HOME/.aws/credentials" 'aws_access_key_id' "Long-lived keys: prefer SSO (aws sso login) so nothing durable sits on disk."
cred "$HOME/.config/gcloud/application_default_credentials.json" '' "Revoke when not needed: gcloud auth application-default revoke."
cred "$HOME/.config/gcloud/credentials.db" '' "gcloud refresh tokens are stored here."
cred "$HOME/.azure/msal_token_cache.json" '' "Azure CLI token cache; az logout clears it."
cred "$HOME/.azure/accessTokens.json" '' "Azure CLI token cache; az logout clears it."
cred "$HOME/.kube/config" '^[[:space:]]*(token|client-key-data):' "Contains embedded cluster credentials."
cred "$HOME/.docker/config.json" '"auth"' "Registry credentials stored inline; use a credential helper."
cred "$HOME/.terraform.d/credentials.tfrc.json" '' "Terraform Cloud token."
cred "$HOME/.config/gh/hosts.yml" 'oauth_token:' "gh token stored in plaintext (no keyring)."
cred "$HOME/.git-credentials" '.' "git's 'store' helper keeps tokens here in plaintext; use the OS keychain helper."
cred "$HOME/.netrc" 'password' "Plaintext passwords or tokens for the hosts listed in it."
[ "$cloud_found" -eq 0 ] && pass H10 "no cloud or git credential files found in the usual locations"

# ---- H11 worm artifacts on disk ---------------------------------------------
# IOC names and hashes come from wormsign's own loader, so this sees exactly what the
# scanner sees: the bundled data, plus the update-iocs cache's additions when it is newer.
# A hash match or a high/critical name is a FAIL, a medium/low name a WARN, as in the scanner.
IOC_JS='const { pathToFileURL } = await import("node:url");
const { loadIocs } = await import(pathToFileURL(process.argv[1]).href);
const s = loadIocs();
for (const h of s.hashes) console.log(["H", h.sha256, h.name].join("\t"));
for (const n of s.names) console.log(["N", n.nameOnlySeverity, n.name].join("\t"));'
# Hashes stdin: given a file name with a newline or backslash in it, both sha256sum and
# shasum put a '\' before the hash.
sha() { if have sha256sum; then sha256sum <"$1" | cut -d' ' -f1; else shasum -a 256 <"$1" | cut -d' ' -f1; fi; }
scan_artifacts() { # scan_artifacts ROOT...: match files under ROOTs against $WORK/iocs
  local n path h sev hits=0 expr_args=()
  while IFS= read -r n; do
    [ -n "$n" ] || continue
    if [ "${#expr_args[@]}" -gt 0 ]; then expr_args+=(-o); fi
    expr_args+=(-name "$n")
  done <<EOF
$(awk -F'\t' '{ print $3 }' "$WORK/iocs" | sort -u)
EOF
  if [ "${#expr_args[@]}" -eq 0 ]; then fail H11 "the IOC data lists no file names"; return 0; fi
  # -H follows a root that is itself a symlink (say ~/code on another volume; without it
  # find lists nothing and reports no error), but no symlink below a root. -type f only.
  # Unreadable directories are reported below. NUL-separated, so a newline in a directory
  # name cannot split one path into two.
  find -H "$@" -type f \( "${expr_args[@]}" \) -print0 >"$WORK/found" 2>"$WORK/find.err" || true
  while IFS= read -r -d '' path; do
    [ -n "$path" ] || continue
    h=$(sha "$path" 2>/dev/null || true)
    if [ -n "$h" ] && awk -F'\t' -v h="$h" '$1 == "H" && $2 == h { f = 1 } END { exit !f }' "$WORK/iocs"; then
      hits=$((hits + 1))
      fail H11 "$path matches a known worm payload hash ($h). Treat this machine as compromised: rotate credentials from a clean device."
      continue
    fi
    sev=$(awk -F'\t' -v n="$(basename "$path")" '$1 == "N" && $3 == n && s == "" { s = $2 } END { print s }' "$WORK/iocs")
    case "$sev" in
      critical|high) hits=$((hits + 1)); fail H11 "$path has a worm payload file name ($sev; not a known sample's hash). Inspect it by hand; do not run it." ;;
      medium|low) hits=$((hits + 1)); warn H11 "$path has a worm payload file name ($sev; not a known sample's hash). Inspect it by hand; do not run it." ;;
    esac
  done <"$WORK/found"
  if [ -s "$WORK/find.err" ]; then
    warn H11 "some directories could not be searched, so files there were not checked: $(head -n 1 "$WORK/find.err") ($(wc -l <"$WORK/find.err" | tr -d ' ') error line(s))"
  elif [ "$hits" -eq 0 ]; then
    pass H11 "no worm payload files under: $*"
  fi
}
roots=()
for d in code src dev projects work Developer repos git; do [ -d "$HOME/$d" ] && roots+=("$HOME/$d"); done
if [ -n "$NPM_V" ]; then
  g=$(cfg npm root -g) || true
  if [ -n "$g" ] && [ -d "$g" ]; then roots+=("$g"); fi
fi
if [ "${#EXTRA_PATHS[@]}" -gt 0 ]; then roots+=("${EXTRA_PATHS[@]}"); fi
if [ "${#roots[@]}" -eq 0 ]; then
  skip H11 "no dev directories found under \$HOME and no global node_modules; pass --path <dir>"
elif ! have node; then
  skip H11 "node not found; H11 reads the IOC data through wormsign's loader"
elif [ ! -f "$SCRIPT_DIR/dist/src/iocs.js" ]; then
  skip H11 "wormsign is not built ($SCRIPT_DIR/dist/src/iocs.js missing); run 'npm run build' first"
elif ! node --input-type=module -e "$IOC_JS" "$SCRIPT_DIR/dist/src/iocs.js" >"$WORK/iocs" 2>"$WORK/iocs.err"; then
  fail H11 "could not load the IOC data: $(head -n 1 "$WORK/iocs.err")"
else
  scan_artifacts "${roots[@]}"
fi

# ---- H12 pip (report, and --apply) -------------------------------------------
# pip's cooldown is uploaded-prior-to: P<n>D (whole days, pip >= 26.1) or an ISO 8601 date.
# `pip config debug` is the oracle: under each variant (env_var, env, global, site, user, sorted by
# name) it lists the files pip considers and the values pip loaded from each, normalised as
# section.key, and the PIP_* environment variables. pip itself (26.1.2 and 26.2.1, cli/parser.py
# _get_ordered_configuration_items) loads the files in the order global, user, site, env
# (PIP_CONFIG_FILE), each variant's files in the order listed; per section the value from the last
# file that has the key wins, and an empty winner leaves the section unset. A command then uses
# PIP_UPLOADED_PRIOR_TO if it is non-empty, else its own section, else [global]. The judge below
# rebuilds exactly that for install, download, lock and wheel (wheel builds sdists, running their
# code), and every value they use must pass.
# argv: DAYS SECONDS SOAK; stdin: `pip config debug`.
# Prints "ok<TAB>summary<TAB>APPLY" or "bad<TAB>problem; problem...<TAB>APPLY", where APPLY says what
# writing [global] to the user file would do: "write<TAB>-" (it can fix [global]), "env<TAB>VALUE"
# (PIP_UPLOADED_PRIOR_TO fails and overrides every file), "global-ok<TAB>WHERE" ([global] already
# passes, so the failing value is elsewhere, and writing would only lower a stricter one) or
# "global-later<TAB>WHERE" (the [global] that wins is in a file pip reads after the user file).
# Exits 3 when the listing lacks PIP_DISABLE_PIP_VERSION_CHECK='1', which pm_in always sets: pip
# printed no listing, or not all of it.
# shellcheck disable=SC2016  # a JavaScript program: its $ is JavaScript, not shell
PIP_JUDGE_JS='
const [days, secs, soak] = process.argv.slice(1);
const soakDays = Number(days);
const soakMs = Number(secs) * 1000;
const die = (why) => { console.error(why); process.exit(2); };
// pip reads ^P(\d+)D$ as whole days and anything else with datetime.fromisoformat; a value with
// no UTC offset is local time, which is never more than 12 hours behind UTC, so it is taken as
// the latest instant it can mean.
function judge(v) {
  const rel = /^P(\d+)D$/.exec(v);
  if (rel) return Number(rel[1]) >= soakDays ? "" : "is shorter than P" + soakDays + "D";
  const m = /^(\d{4})-(\d\d)-(\d\d)(?:[T ](\d\d):(\d\d)(?::(\d\d)(?:\.(\d{1,6}))?)?(Z|[+-]\d\d:\d\d)?)?$/.exec(v);
  if (!m) return "is neither P<n>D nor an ISO 8601 date this script can read";
  const [, y, mo, d, h = "0", mi = "0", s = "0", frac = "0", zone] = m;
  const c = new Date(0);
  c.setUTCFullYear(+y, +mo - 1, +d);
  c.setUTCHours(+h, +mi, +s, Math.floor(Number("0." + frac) * 1000));
  if (c.getUTCFullYear() !== +y || c.getUTCMonth() !== +mo - 1 || c.getUTCDate() !== +d || +h > 23 || +mi > 59 || +s > 59) {
    return "is not a valid date";
  }
  let t = c.getTime();
  if (zone === undefined) t += 12 * 3600e3;
  else if (zone !== "Z") {
    const off = (Number(zone.slice(1, 3)) * 60 + Number(zone.slice(4, 6))) * 60e3;
    t -= zone[0] === "+" ? off : -off;
  }
  return Date.now() - t >= soakMs ? "" : "is less than " + soak + " ago";
}
// An environment variable is printed with Python repr().
function unrepr(s) {
  const m = /^(?:\x27((?:[^\x27\\]|\\.)*)\x27|"((?:[^"\\]|\\.)*)")$/.exec(s);
  if (!m) die("unexpected environment value: " + s);
  return (m[1] ?? m[2]).replace(/\\(x[0-9a-f]{2}|u[0-9a-f]{4}|U[0-9a-f]{8}|.)/g, (_, e) =>
    e.length > 1 ? String.fromCodePoint(parseInt(e.slice(1), 16)) : ({ n: "\n", r: "\r", t: "\t" })[e] ?? e);
}
const ORDER = ["global", "user", "site", "env"];
const files = [];
const paths = new Set();
const envValues = [];
let variant, file, key;
let control = false;
for (const raw of require("node:fs").readFileSync(0, "utf8").split("\n")) {
  const line = raw.replace(/\r$/, "");
  let m;
  if ((m = /^(\S+):$/.exec(line))) {
    variant = m[1];
    if (variant !== "env_var" && !ORDER.includes(variant)) die("unknown variant in pip config debug: " + variant);
    file = key = undefined;
  } else if (variant === "env_var" && (m = /^  PIP_([^=]*)=(.*)$/.exec(line))) {
    const name = m[1].toLowerCase().replace(/_/g, "-");
    const v = unrepr(m[2]);
    if (name === "disable-pip-version-check" && v === "1") control = true;
    if (name === "uploaded-prior-to") envValues.push(v);
  } else if (variant !== undefined && variant !== "env_var" && (m = /^  (.+), exists: (True|False)$/.exec(line))) {
    // pip merges the files into one dict keyed by path: a file listed twice keeps its first place.
    file = paths.has(m[1]) ? undefined : { variant, path: m[1], values: new Map() };
    if (file) {
      paths.add(m[1]);
      files.push(file);
    }
    key = undefined;
  } else if (file && (m = /^    ([^.]*)\.uploaded-prior-to: (.*)$/.exec(line))) {
    key = m[1];
    file.values.set(key, m[2]);
  } else if (file && key !== undefined && line.startsWith("    ") && !/^    [^\s:]+: /.test(line)) {
    // pip prints each line of a multi-line value indented: a line that is not "name: value" continues it.
    file.values.set(key, file.values.get(key) + "\n" + line.slice(4));
  } else {
    key = undefined;
  }
}
if (!control) process.exit(3);
files.sort((a, b) => ORDER.indexOf(a.variant) - ORDER.indexOf(b.variant));
const winner = (section) => {
  let w;
  for (const f of files) if (f.values.has(section)) w = { section, value: f.values.get(section), path: f.path, variant: f.variant };
  return w;
};
const label = (w) => (w.section === undefined ? "PIP_UPLOADED_PRIOR_TO" : "[" + w.section + "]");
const loc = (w) => (w.section === undefined ? "" : " in " + w.path);
const and = (xs) => (xs.length > 1 ? xs.slice(0, -1).join(", ") + " and " + xs[xs.length - 1] : xs[0]);
const problems = [];
let env;
if (new Set(envValues).size > 1) problems.push("PIP_UPLOADED_PRIOR_TO is set more than once (in different letter cases) to different values");
else if (envValues.length > 0 && envValues[0] !== "") env = { value: envValues[0] };
const glob = winner("global");
const used = new Map();
const unset = [];
const cleared = new Set();
for (const cmd of ["install", "download", "lock", "wheel"]) {
  const own = winner(cmd);
  let from = env;
  if (from === undefined && own !== undefined && own.value !== "") from = own;
  if (from === undefined && glob !== undefined && glob.value !== "") from = glob;
  if (from === undefined) {
    unset.push(cmd);
    for (const w of [own, glob]) if (w !== undefined && w.value === "") cleared.add(label(w) + loc(w));
    continue;
  }
  const k = label(from) + loc(from) + "\n" + from.value;
  if (!used.has(k)) used.set(k, { from, cmds: [] });
  used.get(k).cmds.push(cmd);
}
for (const { from } of used.values()) {
  const why = judge(from.value);
  if (why) problems.push(label(from) + " " + JSON.stringify(from.value) + loc(from) + " " + why);
}
if (unset.length > 0) {
  const why = cleared.size > 0 ? " (cleared by an empty value in the last file pip reads it from: " + [...cleared].join("; ") + ")" : "";
  problems.push("unset for pip " + and(unset) + why);
}
let apply = "write\t-";
const envBad = new Set(envValues).size > 1 || (env !== undefined && judge(env.value) !== "");
if (problems.length > 0 && envBad) apply = "env\t" + JSON.stringify(envValues[envValues.length - 1]);
else if (glob !== undefined && glob.value !== "" && judge(glob.value) === "") apply = "global-ok\t" + JSON.stringify(glob.value) + " in " + glob.path;
else if (glob !== undefined && (glob.variant === "site" || glob.variant === "env")) {
  apply = "global-later\t" + (glob.value === "" ? "is empty" : "says " + JSON.stringify(glob.value)) + " in " + glob.path;
}
const summary = [...used.values()].map(({ from, cmds }) => and(cmds) + " use" + (cmds.length > 1 ? " " : "s ") + JSON.stringify(from.value) + " from " + label(from) + loc(from));
// Fields are tab-separated, so a tab or newline in a path is printed as "?", as say() would print it.
const field = (x) => x.replace(/[\t\n]/g, "?");
console.log((problems.length > 0 ? "bad\t" + field(problems.join("; ")) : "ok\t" + field(summary.join("; "))) + "\t" + apply.split("\t").map(field).join("\t"));
'

# pip_run RUNNER ARGS...: RUNNER is "python3 -m pip", "pip3" or "pip".
pip_run() {
  local r=$1
  shift
  if [ "$r" = "python3 -m pip" ]; then pm python3 -m pip "$@"; else pm "$r" "$@"; fi
}
# pip_judge RUNNER: the judge's verdict on that pip's `config debug`. Fails if pip could not list
# its config (status 1), the judge could not run (status 2) or pip printed no listing (status 3).
pip_judge() {
  local list rc=0
  list=$(pip_run "$1" config debug) || return 1
  printf '%s\n' "$list" | node -e "$PIP_JUDGE_JS" "$SOAK_DAYS" "$SOAK_SECONDS" "$SOAK" 2>/dev/null || rc=$?
  case "$rc" in 0) ;; 3) return 3 ;; *) return 2 ;; esac
}
# pip_user_files RUNNER: the user config files `pip config debug` lists for that pip, one per line;
# `pip config --user set` writes the last one.
pip_user_files() {
  local out
  out=$(pip_run "$1" config debug) || return 1
  printf '%s\n' "$out" | awk '
    /^[^ ]/ { user = ($0 == "user:"); next }
    user && /^  [^ ]/ { l = substr($0, 3); if (match(l, /, exists: (True|False)$/)) print substr(l, 1, RSTART - 1) }'
}
# pip_restore: put every file in $PIP_FILES back as it was before this run's write: a backed-up
# file gets its backup's content (in place, keeping its mode), a file pip created is removed.
pip_restore() {
  local f failed=0
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if [ -e "$f.wormsign-bak.$STAMP" ]; then
      cmp -s "$f.wormsign-bak.$STAMP" "$f" || cat "$f.wormsign-bak.$STAMP" >"$f" || failed=1
    else
      case "$PIP_EXISTED" in *$'\n'"$f"$'\n'*) ;; *) rm -f "$f" || failed=1 ;; esac
    fi
  done <<EOF
$PIP_FILES
EOF
  return "$failed"
}

# The pip version python3 bundles (ensurepip), which python3 -m venv installs.
ENSUREPIP_PY='import ensurepip; print(ensurepip.version())'

# One entry per distinct pip installation (the same `--version` line: pip3 and python3 -m pip
# are often the same pip). Each one is judged, because two pips can read different user files
# (pip 26.2 on macOS reads $XDG_DATA_HOME/pip when that directory exists; pip 26.1 does not).
PIP_LINES=(); PIP_NAMES=(); PIP_VERS=(); PIP_RUNS=()
pip_seen=0
for r in "python3 -m pip" pip3 pip; do
  tool=${r%% *}
  have "$tool" || continue
  if ! line=$(pip_run "$r" --version); then
    # python3 without a pip module is not a pip; anything else that fails is a broken pip.
    if [ "$r" = "python3 -m pip" ] && grep -q 'No module named pip' "$WORK/pm.err" 2>/dev/null; then continue; fi
    pip_seen=1
    warn H12 "$r ($(command -v "$tool")) did not report a version (a pip config file it cannot parse?), so its settings were not checked. '$r --version' shows the error: $(first_error)"
    continue
  fi
  pip_seen=1
  line=$(printf '%s\n' "$line" | tail -n 1 | tr -d '\r')
  re='^pip ([0-9]+(\.[0-9]+)+)[^ ]* from (.+) \(python [0-9.]+\)$'
  if ! [[ $line =~ $re ]]; then
    warn H12 "$r ($(command -v "$tool")) printed a version line this script cannot read ($line), so its settings were not checked"
    continue
  fi
  v=${BASH_REMATCH[1]}
  i=0; dup=0
  while [ "$i" -lt "${#PIP_LINES[@]}" ]; do
    if [ "${PIP_LINES[$i]}" = "$line" ]; then PIP_NAMES[i]="${PIP_NAMES[$i]}, $r"; dup=1; break; fi
    i=$((i + 1))
  done
  if [ "$dup" -eq 0 ]; then PIP_LINES+=("$line"); PIP_NAMES+=("$r"); PIP_VERS+=("$v"); PIP_RUNS+=("$r"); fi
done

h12_fix="python3 -m pip"; h12_venv26=""
if [ "$pip_seen" -eq 0 ]; then
  skip H12 "pip not installed"
elif ! have node; then
  warn H12 "node not found; H12 reads pip's values with node, so pip's settings were not checked"
elif [ "${#PIP_LINES[@]}" -gt 0 ]; then
  if [ -n "${PIP_CONFIG_FILE:-}" ]; then
    warn H12 "PIP_CONFIG_FILE is set in this environment ($PIP_CONFIG_FILE): when it names an existing file pip does not read the user config file, and when it is /dev/null pip reads no config file at all, so the user file --apply writes does not apply here"
  fi
  if [ "${PIP_UPLOADED_PRIOR_TO:-}" = P0D ]; then
    warn H12 "PIP_UPLOADED_PRIOR_TO=P0D is set in this environment: P0D is how pip's user guide says to override a configured cutoff, so pip has none here. Remove it from your shell profile."
  fi
  # python3 -m venv installs the pip bundled with python3 (its ensurepip) in each new virtual
  # environment, and that pip reads the same user config. `ensurepip.version()` only reads the
  # bundled wheel's name.
  if have python3 && ev=$(pm python3 -I -c "$ENSUREPIP_PY") && [[ $ev =~ ^[0-9]+(\.[0-9]+)+$ ]] &&
     ! version_ge "$ev" "$PIP_MIN"; then
    if version_ge "$ev" 26; then
      h12_venv26="the pip $ev that python3 -m venv installs"
      warn H12 "python3 ($(command -v python3)) installs pip $ev in each new virtual environment (python3 -m venv), and with a P<n>D uploaded-prior-to in the user config that pip fails to install anything (pip 26.0). Use a Python that bundles pip $PIP_MIN or newer, or upgrade pip in each new environment before P<n>D is set."
    else
      warn H12 "python3 ($(command -v python3)) installs pip $ev in each new virtual environment (python3 -m venv), and pip older than $PIP_MIN ignores uploaded-prior-to, so those environments have no cutoff until their pip is upgraded ('<venv>/bin/python -m pip install --upgrade pip')."
    fi
  fi
  # Judge each pip >= PIP_MIN; older ones FAIL on version alone.
  H12_STATE=(); H12_TEXT=(); H12_APPLY=(); H12_WHERE=(); h12_bad=0; h12_old26=$h12_venv26; h12_primary=""
  # h12_read I OUT: store one judge verdict for pip I.
  h12_read() {
    local st tx ak ad
    IFS=$'\t' read -r st tx ak ad <<EOF
$2
EOF
    H12_STATE[$1]=$st; H12_TEXT[$1]=$tx; H12_APPLY[$1]=$ak; H12_WHERE[$1]=$ad
  }
  i=0
  while [ "$i" -lt "${#PIP_LINES[@]}" ]; do
    v=${PIP_VERS[$i]}
    H12_STATE[i]=old; H12_TEXT[i]=""
    if ! version_ge "$v" "$PIP_MIN"; then
      if version_ge "$v" 26; then
        h12_old26="pip $v (${PIP_NAMES[$i]})"
        fail H12 "pip $v (${PIP_NAMES[$i]}) reads uploaded-prior-to only as an absolute date, and a P<n>D value in its config makes pip install, download, lock, wheel, index and list fail (pip 26.0). Upgrade pip to $PIP_MIN or newer, then re-run."
      else
        fail H12 "pip $v (${PIP_NAMES[$i]}) has no working release-age cutoff: uploaded-prior-to needs pip >= $PIP_MIN for P<n>D values (pip 25.3 accepts the key and ignores it). Upgrade pip, then re-run."
      fi
    else
      rc=0; out=$(pip_judge "${PIP_RUNS[$i]}") || rc=$?
      if [ "$rc" -ne 0 ]; then
        H12_STATE[i]=err
        case "$rc" in
          1) warn H12 "pip $v (${PIP_NAMES[$i]}) failed to list its config (is a pip config file invalid?), so it was not checked. '${PIP_RUNS[$i]} config debug' shows the error: $(first_error)" ;;
          3) warn H12 "pip $v (${PIP_NAMES[$i]}): '${PIP_RUNS[$i]} config debug' printed no listing (not even PIP_DISABLE_PIP_VERSION_CHECK, which this script sets), so it was not checked" ;;
          *) warn H12 "pip $v (${PIP_NAMES[$i]}): node could not judge its config, so it was not checked" ;;
        esac
      else
        h12_read "$i" "$out"
        [ "${H12_STATE[$i]}" = ok ] || h12_bad=1
        # --apply writes with the first pip whose config could be judged.
        [ -n "$h12_primary" ] || h12_primary=$i
      fi
    fi
    i=$((i + 1))
  done
  [ -z "$h12_primary" ] || h12_fix=${PIP_RUNS[$h12_primary]}
  h12_cmd="$h12_fix config --user set global.uploaded-prior-to P${SOAK_DAYS}D"
  h12_report() { # h12_report SUFFIX: one PASS or FAIL per judged pip
    local j=0
    while [ "$j" -lt "${#PIP_LINES[@]}" ]; do
      case "${H12_STATE[$j]}" in
        ok) pass H12 "pip ${PIP_VERS[$j]} (${PIP_NAMES[$j]}): uploaded-prior-to: ${H12_TEXT[$j]}$1" ;;
        bad) fail H12 "pip ${PIP_VERS[$j]} (${PIP_NAMES[$j]}): uploaded-prior-to: ${H12_TEXT[$j]} (want P${SOAK_DAYS}D or longer$2). Without a cutoff pip installs a release minutes after it is published." ;;
      esac
      j=$((j + 1))
    done
  }

  # What --apply can do about a FAIL. It writes [global] to the user file only when that can raise
  # the [global] value pip uses: not when a pip 26.0 would break on the value it writes, not when
  # PIP_UPLOADED_PRIOR_TO fails (it overrides every file), not when [global] already passes (the
  # failing value is elsewhere, and writing could only lower a stricter one), and not when the
  # [global] that wins is in a file pip reads after the user file.
  h12_no_fix=""
  if [ "$h12_bad" -eq 1 ]; then
    if [ -n "$h12_old26" ]; then
      h12_no_fix="not written by --apply: with P${SOAK_DAYS}D in its config, $h12_old26 would fail to install anything. Upgrade it first"
    elif [ -n "$h12_primary" ]; then
      h12_where=${H12_WHERE[$h12_primary]}
      case "${H12_APPLY[$h12_primary]}" in
        env) h12_no_fix="not fixed by --apply: PIP_UPLOADED_PRIOR_TO=$h12_where in this environment overrides every pip config file. Change it where it is set (a shell profile?)" ;;
        global-ok) h12_no_fix="not fixed by --apply: for $h12_fix, [global] already says $h12_where, so the failing value is elsewhere, and writing [global] could only lower it. '<pip> config debug' lists each file's values" ;;
        global-later) h12_no_fix="not fixed by --apply: for $h12_fix, the [global] value that wins $h12_where, a file pip reads after the user file, so a value in the user file would not apply. Change it there" ;;
      esac
    fi
  fi
  if [ "$h12_bad" -eq 0 ]; then
    h12_report "" ""
  elif [ -n "$h12_no_fix" ]; then
    h12_report "" "; $h12_no_fix"
  elif [ "$MODE" != apply ]; then
    h12_report "" "; fixable with --apply, which runs '$h12_cmd'"
  elif ! PIP_FILES=$(pip_user_files "$h12_fix") || [ -z "$PIP_FILES" ]; then
    h12_report "" "; not written: '$h12_fix config debug' did not list the user config files to back up"
  else
    PIP_EXISTED=$'\n'
    h12_backed=0
    h12_dangling=""
    # A symlink counts as existing, so pip_restore never deletes one; a dangling one (its target not made yet) stops
    # the write, which pip would make through the link.
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      if [ -L "$f" ] && [ ! -e "$f" ]; then h12_dangling=$f; fi
      { [ -e "$f" ] || [ -L "$f" ]; } && PIP_EXISTED="$PIP_EXISTED$f"$'\n'
    done <<EOF
$PIP_FILES
EOF
    if [ -z "$h12_dangling" ]; then
      while IFS= read -r f; do
        [ -n "$f" ] || continue
        backup_once "$f" || h12_backed=1
      done <<EOF
$PIP_FILES
EOF
    fi
    if [ -n "$h12_dangling" ]; then
      warn H12 "$h12_dangling is a symlink to a file that does not exist, so --apply neither wrote through it nor removed it. Create the file it points to (or remove the link), then re-run --apply."
      h12_report "" "; not written, see the WARN above"
    elif [ "$h12_backed" -ne 0 ]; then
      h12_report "" "; not written: a user config file could not be backed up"
    elif ! wrote=$(pip_run "$h12_fix" config --user set global.uploaded-prior-to "P${SOAK_DAYS}D"); then
      err=$(first_error)
      if pip_restore; then
        fail H12 "pip: could not write global.uploaded-prior-to with '$h12_cmd' ($err); the user config files are as they were"
      else
        fail H12 "pip: could not write global.uploaded-prior-to with '$h12_cmd' ($err), and putting the user config files back failed. Restore them from the backups above."
      fi
    else
      h12_file=""
      while IFS= read -r l; do case "$l" in "Writing to "*) h12_file=${l#Writing to } ;; esac; done <<EOF
$wrote
EOF
      wrote=$h12_file
      case "$PIP_EXISTED" in
        *$'\n'"$wrote"$'\n'*) how="pip rewrote the whole file: its comments are gone, the backup above has them" ;;
        *) how="pip created the file" ;;
      esac
      info H12 "wrote [global] uploaded-prior-to = P${SOAK_DAYS}D to ${wrote:-the pip user config} with '$h12_cmd' ($how)"
      # Read back with every pip that read its config before: each must still read it, and should
      # now pass.
      h12_unreadable=""
      i=0
      while [ "$i" -lt "${#PIP_LINES[@]}" ]; do
        if [ "${H12_STATE[$i]}" = ok ] || [ "${H12_STATE[$i]}" = bad ]; then
          rc=0; out=$(pip_judge "${PIP_RUNS[$i]}") || rc=$?
          if [ "$rc" -eq 1 ]; then h12_unreadable="${PIP_RUNS[$i]}"; break; fi
          if [ "$rc" -ne 0 ]; then
            H12_STATE[i]=err
            warn H12 "pip ${PIP_VERS[$i]} (${PIP_NAMES[$i]}): its config could not be judged after the write (node failed, or pip printed no listing), so it was not checked"
          else
            h12_read "$i" "$out"
          fi
        fi
        i=$((i + 1))
      done
      if [ -n "$h12_unreadable" ]; then
        if pip_restore; then
          fail H12 "pip: could not safely edit the user config: '$h12_unreadable config debug' fails after the write; the user config files are back as they were. Set uploaded-prior-to = P${SOAK_DAYS}D under [global] by hand."
        else
          fail H12 "pip: could not safely edit the user config: '$h12_unreadable config debug' fails after the write, and putting the files back failed. Restore them from the backups above."
        fi
      else
        h12_report " (just applied)" "; ${wrote:-the user file} now says P${SOAK_DAYS}D under [global], but this pip still reports the above: it reads another file, or another section, file or variable overrides it. '<pip> config debug' shows which"
      fi
    fi
  fi
fi

# ---- H13 uv (report only) ---------------------------------------------------
# uv has no command that prints its effective config, so this locks an empty project in $WORK
# and reads the cutoff uv records in the lock's [options]. The project's own [tool.uv] table
# stops uv looking for a uv.toml or [tool.uv] in parent directories, and its workspace table
# makes it its own workspace root, so no pyproject.toml above $WORK can adopt it as a member:
# what is left is the user and system config and the environment, as for any uv command run
# outside a project.
UV_PROBE_TOML='[project]
name = "wormsign-harden-probe"
version = "0"
dependencies = []

[tool.uv]
package = false

[tool.uv.workspace]
members = []
'
# Reads a uv.lock's [options]: one "cutoff<TAB>SECONDS<TAB>TEXT" line (SECONDS empty when no
# cutoff is recorded), then one "package<TAB>NAME<TAB>SECONDS-or-off<TAB>TEXT" per
# [options.exclude-newer-package] entry. SECONDS is the span, or for a fixed date its age. When
# exclude-newer-span is present it is the cutoff and exclude-newer is ignored: uv 0.12 writes a
# placeholder date there, and uv 0.10 the date the span gave at lock time. Exits 1 on any shape
# it does not know.
# shellcheck disable=SC2016  # a JavaScript program: its $ is JavaScript, not shell
UV_LOCK_JS='
const text = require("node:fs").readFileSync(process.argv[1], "utf8");
const die = (why) => { console.error(why); process.exit(1); };
const STR = "\"((?:[^\"\\\\]|\\\\.)*)\"";
function spanSeconds(s) {
  const m = /^P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$/.exec(s);
  if (!m || m.slice(1).every((x) => x === undefined) || s.endsWith("T")) die("exclude-newer span " + JSON.stringify(s) + " is not in a form this script reads");
  const n = (x) => Number(x ?? 0);
  return Math.floor(n(m[1]) * 604800 + n(m[2]) * 86400 + n(m[3]) * 3600 + n(m[4]) * 60 + n(m[5]));
}
function ageSeconds(ts) {
  const t = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)$/.test(ts) ? Date.parse(ts) : NaN;
  if (Number.isNaN(t)) die("exclude-newer " + JSON.stringify(ts) + " is not a timestamp this script reads");
  return Math.floor((Date.now() - t) / 1000);
}
const pick = (span, ts) => (span !== undefined ? spanSeconds(span) : ageSeconds(ts));
let table = "";
const opts = {};
const packages = [];
for (const raw of text.split(/\r?\n/)) {
  const line = raw.trim();
  if (line === "" || line.startsWith("#")) continue;
  const header = /^\[\[?\s*([^\]]+?)\s*\]\]?$/.exec(line);
  if (header) { table = header[1]; continue; }
  if (table === "options" && /^"?exclude-newer/.test(line)) {
    const m = new RegExp("^(exclude-newer|exclude-newer-span)\\s*=\\s*" + STR + "\\s*(#.*)?$").exec(line);
    if (!m || m[1] in opts) die("unexpected [options] line: " + line);
    opts[m[1]] = m[2];
  } else if (table === "options.exclude-newer-package") {
    const m = /^("[^"]*"|[A-Za-z0-9_.-]+)\s*=\s*(.*?)\s*$/.exec(line);
    if (!m) die("unexpected exclude-newer-package line: " + line);
    const name = m[1].replace(/^"|"$/g, "");
    const v = m[2];
    if (v === "false") { packages.push([name, "off", v]); continue; }
    const str = new RegExp("^" + STR + "$").exec(v);
    if (str) { packages.push([name, ageSeconds(str[1]), v]); continue; }
    const inline = /^\{(.*)\}$/.exec(v);
    if (!inline) die("unexpected exclude-newer-package value: " + line);
    const fields = {};
    for (const part of inline[1].split(",")) {
      const f = new RegExp("^\\s*(timestamp|span)\\s*=\\s*" + STR + "\\s*$").exec(part);
      if (!f || f[1] in fields) die("unexpected exclude-newer-package value: " + line);
      fields[f[1]] = f[2];
    }
    packages.push([name, pick(fields.span, fields.timestamp), v]);
  }
}
const span = opts["exclude-newer-span"];
if (span !== undefined) console.log("cutoff\t" + spanSeconds(span) + "\texclude-newer-span = \"" + span + "\"");
else if (opts["exclude-newer"] !== undefined) console.log("cutoff\t" + ageSeconds(opts["exclude-newer"]) + "\texclude-newer = \"" + opts["exclude-newer"] + "\"");
else console.log("cutoff\t\t");
for (const [name, secs, v] of packages) console.log("package\t" + name + "\t" + secs + "\t" + v);
'
# The cutoffs a uv.toml sets that the probe's lock does not record, read with Python's tomllib.
# One line per value, tab-separated, each VALUE printed as a JSON string, "false" or "other" (any
# other type), each NAME and URL as a JSON string:
#   pip VALUE                       [pip] exclude-newer (uv pip commands use it instead of the top level)
#   pip-package NAME VALUE          [pip] exclude-newer-package entries (likewise)
#   index NAME URL KIND VALUE       an [[index]] entry's own exclude-newer (uv >= 0.11.5 uses it for
#                                   packages from that index); KIND is "default" (default = true),
#                                   "pypi" (its host is pypi.org) or "other"
UV_USER_PY='# wormsign:uv-user-overrides
import json, sys, tomllib
from urllib.parse import urlsplit
with open(sys.argv[1], "rb") as f:
    d = tomllib.load(f)
def show(v):
    return "false" if v is False else json.dumps(v) if isinstance(v, str) else "other"
p = d.get("pip") if isinstance(d.get("pip"), dict) else {}
if "exclude-newer" in p:
    print("pip\t" + show(p["exclude-newer"]))
pkgs = p.get("exclude-newer-package")
for name, v in pkgs.items() if isinstance(pkgs, dict) else []:
    print("pip-package\t" + json.dumps(name) + "\t" + show(v))
idx = d.get("index")
for i, e in enumerate(idx if isinstance(idx, list) else []):
    if not isinstance(e, dict) or "exclude-newer" not in e:
        continue
    url = e.get("url") if isinstance(e.get("url"), str) else ""
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        host = ""
    kind = "default" if e.get("default") is True else "pypi" if host == "pypi.org" else "other"
    name = e.get("name") if isinstance(e.get("name"), str) else "#" + str(i + 1)
    print("index\t" + json.dumps(name) + "\t" + json.dumps(url) + "\t" + kind + "\t" + show(e["exclude-newer"]))
'
# uv_options DIR [UV.TOML-LINE]: write the probe project to DIR, lock it, print UV_LOCK_JS's
# records. With a line, the probe gets a uv.toml holding it, and uv runs without UV_EXCLUDE_NEWER
# and UV_CONFIG_FILE, which would override that file. Status 1: uv failed; 2: no lock or node failed.
uv_options() {
  mkdir -p "$1" || return 2
  printf '%s' "$UV_PROBE_TOML" >"$1/pyproject.toml" || return 2
  if [ -z "${2:-}" ]; then
    pm_in "$1" uv lock --offline >/dev/null || return 1
  else
    printf '%s\n' "$2" >"$1/uv.toml" || return 2
    pm_in "$1" env -u UV_EXCLUDE_NEWER -u UV_CONFIG_FILE uv lock --offline >/dev/null || return 1
  fi
  [ -f "$1/uv.lock" ] || return 2
  node -e "$UV_LOCK_JS" "$1/uv.lock" 2>"$WORK/node.err" || return 2
}
# uv_secs DIR VALUE: the cutoff uv derives from exclude-newer = VALUE (a TOML string), in seconds:
# a span's length or a date's age. Fails if uv cannot read it.
uv_secs() {
  local recs s
  recs=$(uv_options "$1" "exclude-newer = $2") || return 1
  s=$(printf '%s\n' "$recs" | awk -F'\t' '$1 == "cutoff" { print $2 }')
  [ -n "$s" ] || return 1
  printf '%s\n' "$s"
}
# uv_value_check SEVERITY WHAT VALUE OFF SHORT: report an exclude-newer VALUE (JSON string, "false" or
# "other") read from $uv_file: SEVERITY (warn or fail) "WHAT = false in FILE OFF", or "WHAT = VALUE in
# FILE is shorter than the soak (LENGTH)SHORT" when uv reads it as shorter.
uv_value_check() {
  local s
  case "$3" in
    false) "$1" H13 "uv $UV_V: $2 = false in $uv_file $4" ;;
    other) warn H13 "uv $UV_V: $2 in $uv_file is not a string, so it was not checked" ;;
    *)
      uv_n=$((uv_n + 1))
      if ! s=$(uv_secs "$WORK/uv-value-$uv_n" "$3"); then
        warn H13 "uv $UV_V: $2 = $3 in $uv_file could not be read by uv, so it was not checked"
      elif [ "$s" -lt "$SOAK_SECONDS" ]; then
        "$1" H13 "uv $UV_V: $2 = $3 in $uv_file is shorter than $SOAK ($(secs_text "$s"))$5"
      fi ;;
  esac
}
secs_text() { # secs_text SECONDS: "7 days" when whole days, else "<n> seconds"
  if [ "$1" -eq 86400 ]; then echo "1 day"
  elif [ $(($1 % 86400)) -eq 0 ]; then echo "$(($1 / 86400)) days"
  else echo "$1 seconds"; fi
}

if ! have uv; then
  skip H13 "uv not installed"
else
  UV_LINE=$(cfg uv --version) || UV_LINE=""
  re='^uv ([0-9]+(\.[0-9]+)+)([-+][0-9A-Za-z.-]+)?( \(.*\))?$'
  if ! [[ $UV_LINE =~ $re ]]; then
    warn H13 "uv at $(command -v uv) did not report a version offline, so its settings were not checked. 'uv --version' shows the error."
  else
    UV_V=${BASH_REMATCH[1]}
    UV_TOML="${XDG_CONFIG_HOME:-$HOME/.config}/uv/uv.toml"
    uv_fix="Add 'exclude-newer = \"$SOAK_DAYS days\"' at the top level of ${UV_CONFIG_FILE:-$UV_TOML}, before any [table] (not auto-applied)."
    if ! version_ge "$UV_V" "$UV_MIN"; then
      fail H13 "uv $UV_V has no relative exclude-newer (needs uv >= $UV_MIN; a fixed date goes stale). Upgrade uv. $uv_fix"
    elif ! have node; then
      warn H13 "uv $UV_V: oracle unavailable: node not found, and H13 reads uv's lock with node"
    else
      rc=0; recs=$(uv_options "$WORK/uv-probe") || rc=$?
      if [ "$rc" -eq 1 ]; then
        warn H13 "uv $UV_V: oracle unavailable: 'uv lock --offline' on an empty project failed, so its settings were not checked: $(first_error)"
      elif [ "$rc" -ne 0 ]; then
        warn H13 "uv $UV_V: oracle unavailable: could not read the lock uv wrote ($(head -n 1 "$WORK/node.err" 2>/dev/null)), so its settings were not checked"
      else
        while IFS=$'\t' read -r kind a b c; do
          case "$kind" in
            cutoff)
              if [ -z "$a" ]; then
                fail H13 "uv $UV_V: no exclude-newer applies outside a project (want $SOAK_DAYS days or longer). $uv_fix"
              else
                # A span is the cutoff's length; a fixed date's is its age.
                case "$b" in exclude-newer-span*) len=$(secs_text "$a") ;; *) len="$(secs_text "$a") old" ;; esac
                if [ "$a" -ge "$SOAK_SECONDS" ]; then
                  pass H13 "uv $UV_V: $b ($len), from 'uv lock' on an empty project"
                else
                  fail H13 "uv $UV_V: $b is shorter than $SOAK ($len, want $(secs_text "$SOAK_SECONDS") or more). $uv_fix"
                fi
              fi ;;
            package)
              if [ "$b" = off ]; then
                warn H13 "uv $UV_V: exclude-newer-package turns the cutoff off for $a ($a = $c)"
              elif [ "$b" -lt "$SOAK_SECONDS" ]; then
                warn H13 "uv $UV_V: exclude-newer-package lets $a through after $(secs_text "$b"), less than $SOAK ($a = $c)"
              fi ;;
          esac
        done <<EOF
$recs
EOF
      fi
      # The lock records only the top-level cutoff and exclude-newer-package. Three more settings
      # change the cutoff without showing in it, so they are read from the file: [pip] exclude-newer
      # and [pip] exclude-newer-package (uv pip commands use them instead of the top-level values),
      # and an [[index]] entry's own exclude-newer (uv 0.11.5 and later use it for packages from that
      # index; uv 0.10.9 ignores it). A string value is measured by uv itself, as the top-level value
      # of a probe's own uv.toml. Only a file that mentions "newer" and "pip" or "index" can set any of
      # them, so other files need no Python.
      uv_file=${UV_CONFIG_FILE:-$UV_TOML}
      if [ "$rc" -eq 0 ] && [ -z "${UV_NO_CONFIG:-}" ] && [ -f "$uv_file" ] &&
         grep -qE 'pip|index' "$uv_file" 2>/dev/null && grep -q 'newer' "$uv_file" 2>/dev/null; then
        if ! have python3 || ! uv_recs=$(pm python3 -I -c "$UV_USER_PY" "$uv_file"); then
          warn H13 "uv $UV_V: the [pip] table and [[index]] entries of $uv_file were not checked: they are read with python3's tomllib (Python >= 3.11), which failed or is missing"
        else
          uv_n=0
          while IFS=$'\t' read -r kind a b c d; do
            case "$kind" in
              pip) uv_value_check warn "[pip] exclude-newer" "$a" "turns the cutoff off for uv pip commands" \
                "; uv pip commands use it instead of the top-level value" ;;
              pip-package) uv_value_check warn "[pip] exclude-newer-package for $a" "$b" "turns the cutoff off for $a in uv pip commands" \
                "; uv pip commands use it for $a" ;;
              index)
                if version_ge "$UV_V" "$UV_INDEX_MIN"; then
                  # The default index, or PyPI itself, serves nearly every package; another index
                  # serves the packages it has, and only those.
                  b=${b#\"}; b=${b%\"}
                  case "$c" in default) sev=fail; c="$b, the default index" ;; pypi) sev=fail; c=$b ;; *) sev=warn; c=$b ;; esac
                  uv_value_check "$sev" "[[index]] $a ($c) exclude-newer" "$d" "turns the cutoff off for every package uv takes from that index" \
                    "; uv uses it instead of the top-level value for every package from that index"
                fi ;;
            esac
          done <<EOF
$uv_recs
EOF
        fi
      fi
    fi
  fi
fi

# ---- Python tools not checked yet --------------------------------------------
others=""
for t in poetry pdm pipenv; do have "$t" && others="$others, $t"; done
if [ -n "$others" ]; then
  info "" "${others#, } found on PATH: their release-age settings are not checked by this script yet."
fi

# ---- summary -----------------------------------------------------------------
echo
echo "summary: $PASSES pass, $WARNS warn, $FAILS fail (mode=$MODE)"
if [ "$WATCHER_FOUND" -gt 0 ]; then
  echo "H14 found the gh-token-monitor watcher: do not revoke tokens yet: isolate this machine first, before acting on any other FAIL ($ISOLATE_DOC)."
fi
if [ "$MODE" = check ] && [ "$FAILS" -gt 0 ]; then
  echo "Some failures are fixable: re-run with --apply (files are backed up first). Token and artifact findings are never auto-fixed."
fi
echo "To let one trusted package run its install scripts, see the allowlist steps per package manager in docs/hardening.md."
[ "$FAILS" -eq 0 ]
