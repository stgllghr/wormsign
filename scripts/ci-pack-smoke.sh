#!/usr/bin/env bash
# Smoke-test the npm tarball as a user gets it: install the .tgz into an empty project with no network and no
# install scripts, then run the installed CLI and hardening script.
#
# Checks: every package.json "files" entry is in the tarball and no tests are; --version matches package.json;
# the scan exits 1 on the malicious fixture and 0 on the clean one; harden-dev.sh --help runs from the package; the
# vendored TOML parser is in it and loads; soak --config-only (no network) reads a uv.lock with it and fails closed on a
# poetry.lock.
# The tarball has no npm dependencies (its one third-party parser is vendored in dist/src/vendor/), so --offline
# proves it is self-contained.
#
# Usage: scripts/ci-pack-smoke.sh <wormsign-X.Y.Z.tgz>   (run from the repository root, after npm pack)
set -euo pipefail

[ -f "${1:-}" ] || { echo "usage: ci-pack-smoke.sh <tarball>" >&2; exit 2; }
tgz="$(CDPATH='' cd -- "$(dirname -- "$1")" && pwd)/$(basename -- "$1")"
repo="$(pwd)"
version="$(node -p 'require("./package.json").version')"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() {
  echo "ci-pack-smoke: FAIL: $*" >&2
  exit 1
}

cd "$work"
printf '{ "name": "wormsign-smoke", "version": "1.0.0", "private": true }\n' > package.json
npm install --offline --ignore-scripts --no-audit --no-fund "$tgz"
pkg="$work/node_modules/wormsign"
bin="$work/node_modules/.bin/wormsign"

# Shipped contents, read from the package's own manifest.
node -e '
  const { existsSync } = require("node:fs");
  const { join } = require("node:path");
  const pkg = process.argv[1];
  const missing = require(join(pkg, "package.json")).files.filter((f) => !existsSync(join(pkg, f)));
  if (missing.length) { console.error("not in the tarball: " + missing.join(", ")); process.exit(1); }
' "$pkg" || fail "package.json files entries are missing from the tarball"
if [ -e "$pkg/dist/test" ] || [ -e "$pkg/test" ]; then fail "tests are shipped in the tarball"; fi

got="$("$bin" --version)"
[ "$got" = "$version" ] || fail "wormsign --version printed '$got', expected '$version'"

set +e
"$bin" scan "$repo/test/fixtures/malicious" > "$work/malicious.txt"
rc=$?
set -e
[ "$rc" = 1 ] || { cat "$work/malicious.txt"; fail "scan of test/fixtures/malicious exited $rc, expected 1"; }
grep -q 'WS-GH-002' "$work/malicious.txt" || fail "scan of test/fixtures/malicious did not report WS-GH-002"
"$bin" scan "$repo/test/fixtures/clean" > /dev/null || fail "scan of test/fixtures/clean failed"

bash "$pkg/harden-dev.sh" --help > "$work/harden-help.txt" || fail "harden-dev.sh --help failed"
grep -q -- '--check' "$work/harden-help.txt" || fail "harden-dev.sh --help does not describe --check"

# The vendored TOML parser (copied by scripts/copy-vendor.mjs) ships with its licence and record, and loads.
vendor="$pkg/dist/src/vendor/smol-toml"
for f in index.js parse.js LICENSE VENDORED.json; do
  [ -f "$vendor/$f" ] || fail "dist/src/vendor/smol-toml/$f is not in the tarball"
done
node --input-type=module -e 'const { pathToFileURL } = await import("node:url"); const m = await import(pathToFileURL(process.argv[1]).href); if (m.parse("a = 1").a !== 1) process.exit(1);' "$vendor/index.js" ||
  fail "the vendored TOML parser does not load from the installed package"

# soak reads Python locks through that parser. --config-only makes no request: a uv.lock that uv wrote is read (exit 0,
# the Python lock check's note), and a poetry.lock, which soak does not read yet, fails closed (exit 1, WS-SK-002).
mkdir "$work/py-uv" "$work/py-poetry"
cp "$repo/test/fixtures/python/locks/uv-0.12.21/simple/uv.lock" "$repo/test/fixtures/python/locks/uv-0.12.21/simple/pyproject.toml" "$work/py-uv/"
"$bin" soak "$work/py-uv" --config-only > "$work/py-uv.txt" || { cat "$work/py-uv.txt"; fail "soak --config-only of a uv.lock failed"; }
grep -q 'Python lock check not run (--config-only)' "$work/py-uv.txt" || fail "soak --config-only of a uv.lock did not say the Python lock check was not run"
printf '[[package]]\nname = "six"\nversion = "1.17.0"\n' > "$work/py-poetry/poetry.lock"
set +e
"$bin" soak "$work/py-poetry" --config-only > "$work/py-poetry.txt"
rc=$?
set -e
[ "$rc" = 1 ] || { cat "$work/py-poetry.txt"; fail "soak --config-only of a poetry.lock exited $rc, expected 1"; }
grep -q 'poetry.lock is not supported yet' "$work/py-poetry.txt" || fail "soak --config-only of a poetry.lock did not fail closed as not supported"

node "$repo/scripts/ci-library-smoke.mjs" "$work" "$repo" || fail "installed library or examples failed"

echo "ci-pack-smoke: ok: $(basename "$tgz") installs offline; CLI, library, typed examples, hardening and Python lock readers work"
