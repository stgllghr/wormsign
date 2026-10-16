#!/usr/bin/env bash
# Regenerates the lockfiles in this directory with real package managers.
#
# Every lockfile locks the same benign project: a pinned registry package, a
# range of the same package (so yarn berry writes multi-descriptor headers), an
# npm: alias, a scoped package, a GitHub dependency, file: directory/tarball
# dependencies (one tarball bundles `ms`), link:/portal: where the manager
# supports them, a peer dependency (react-dom) and a package yarn berry patches
# on its own (resolve). Only lockfiles are written: npm and pnpm run with
# --package-lock-only/--lockfile-only, yarn 4 with --mode=update-lockfile, and
# yarn 1 with --ignore-scripts. HOME is a throwaway directory.
#
# Usage: test/fixtures/lockfiles/protocols/generate.sh   (needs network + corepack)
set -euo pipefail

OUT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export HOME="$WORK/home" COREPACK_ENABLE_DOWNLOAD_PROMPT=0 COREPACK_HOME="$WORK/corepack"
mkdir -p "$HOME"
# npm 6 resolves github: shorthands over git://, which GitHub no longer serves.
git config --global url."https://github.com/".insteadOf git://github.com/

pkg() { mkdir -p "$1" && printf '%s\n' "$2" >"$1/package.json"; }

TPL="$WORK/tpl"
pkg "$TPL/libs/localdep" '{"name":"localdep","version":"1.0.0"}'
pkg "$TPL/libs/linkdep" '{"name":"linkdep","version":"1.0.0"}'
pkg "$TPL/libs/portaldep" '{"name":"portaldep","version":"1.0.0"}'
pkg "$WORK/tardep" '{"name":"tardep","version":"1.0.0"}'
pkg "$WORK/bundler" '{"name":"bundler","version":"1.0.0","dependencies":{"ms":"2.1.3"},"bundleDependencies":["ms"]}'
(cd "$WORK/bundler" && npm install --ignore-scripts --no-audit --no-fund --no-package-lock >/dev/null)
(cd "$WORK/tardep" && npm pack --pack-destination "$TPL/libs" >/dev/null)
(cd "$WORK/bundler" && npm pack --pack-destination "$TPL/libs" >/dev/null)

# project <dir> <manager>: copies the template and writes the manifests that manager accepts.
project() {
  cp -R "$TPL" "$1"
  node - "$1" "$2" <<'EOF'
const { mkdirSync, writeFileSync } = require("node:fs");
const [dir, pm] = process.argv.slice(2);
const deps = {
  "is-number": "7.0.0",
  "to-regex-range": "5.0.1",
  isnum: "npm:is-number@7.0.0",
  "@nodelib/fs.scandir": "2.1.5",
  "@nodelib/fs.stat": "^2.0.0",
  "escape-string-regexp": "github:sindresorhus/escape-string-regexp#v5.0.0",
  localdep: "file:./libs/localdep",
  tardep: "file:./libs/tardep-1.0.0.tgz",
  bundler: "file:./libs/bundler-1.0.0.tgz",
  resolve: "1.22.8",
  react: "17.0.2",
  "react-dom": "17.0.2",
};
if (!pm.startsWith("npm")) deps.linkdep = "link:./libs/linkdep"; // npm has no link: protocol
if (pm === "berry") deps.portaldep = "portal:./libs/portaldep";
const root = { name: "fixture-root", version: "1.0.0", private: true, dependencies: deps };
if (pm !== "pnpm" && pm !== "npm6") root.workspaces = ["packages/*"];
const wsa = { name: "wsa", version: "1.0.0", dependencies: { "is-number": "^7.0.0", "escape-string-regexp": "git+https://github.com/sindresorhus/escape-string-regexp.git#v5.0.0" } };
const write = (p, o) => { mkdirSync(`${dir}/${p}`, { recursive: true }); writeFileSync(`${dir}/${p}/package.json`, JSON.stringify(o, null, 2) + "\n"); };
write(".", root);
write("packages/wsa", wsa);
if (pm === "pnpm") writeFileSync(`${dir}/pnpm-workspace.yaml`, "packages:\n  - packages/*\n");
if (pm === "berry") writeFileSync(`${dir}/.yarnrc.yml`, "enableScripts: false\nnodeLinker: node-modules\napprovedGitRepositories:\n  - \"https://github.com/sindresorhus/escape-string-regexp.git\"\n");
EOF
}

# empty <dir>: a project with no registry dependencies (negative control for fail-closed parsing).
empty() { pkg "$1" '{"name":"fixture-empty","version":"1.0.0","private":true}'; }

save() { mkdir -p "$OUT/$2" && cp "$1" "$OUT/$2/"; }

run_npm() { # <version> <outdir> <npm|npm6> [extra args]
  local v=$1 d=$2 pm=$3; shift 3
  project "$WORK/$d" "$pm"
  (cd "$WORK/$d" && npx -y "npm@$v" install --package-lock-only --ignore-scripts --no-audit --no-fund "$@" >/dev/null 2>&1)
  save "$WORK/$d/package-lock.json" "$d"
}
run_npm 6 npm6 npm6
run_npm 10.9.2 npm10 npm
run_npm 12.2.0 npm12 npm --allow-git=all # npm 12 refuses git dependencies by default

for v in 7.33.7:pnpm7 8.15.9:pnpm8 9.15.9:pnpm9 11.16.0:pnpm11 12.8.1:pnpm12; do
  project "$WORK/${v#*:}" pnpm
  (cd "$WORK/${v#*:}" && npx -y "pnpm@${v%%:*}" install --lockfile-only --ignore-scripts >/dev/null)
  save "$WORK/${v#*:}/pnpm-lock.yaml" "${v#*:}"
done

# pnpm 11 locks a devEngines package manager in a leading YAML document. npx refuses to run
# inside a project whose devEngines it does not satisfy, so pnpm is pointed at it with --dir.
pkg "$WORK/pnpm11-env" '{"name":"fixture-env","version":"1.0.0","devEngines":{"packageManager":{"name":"pnpm","version":"11.16.0","onFail":"download"}},"dependencies":{"is-number":"7.0.0"}}'
(cd "$WORK" && npx -y pnpm@11.16.0 --dir "$WORK/pnpm11-env" install --lockfile-only >/dev/null)
save "$WORK/pnpm11-env/pnpm-lock.yaml" pnpm11-env

project "$WORK/yarn1" yarn1
(cd "$WORK/yarn1" && corepack yarn@1.22.22 install --ignore-scripts --non-interactive --no-progress >/dev/null)
save "$WORK/yarn1/yarn.lock" yarn1

project "$WORK/yarn4" berry
(cd "$WORK/yarn4" && touch yarn.lock && corepack yarn@4.18.1 install --mode=update-lockfile >/dev/null)
save "$WORK/yarn4/yarn.lock" yarn4

# Layouts pnpm and yarn write only under some settings: pnpm's tarball URLs for registry packages
# (pnpm 8 reads it from .npmrc, pnpm 11 from pnpm-workspace.yaml), a pnpm 11 devEngines runtime
# (a block-style resolution), and yarn 4's explicit `? "<key>"` form for a header that lists
# 60 descriptors of `ms`.
for v in 8.15.9:pnpm8-tarball 11.16.0:pnpm11-tarball; do
  d="$WORK/${v#*:}" && pkg "$d" '{"name":"fixture-tarball","version":"1.0.0","private":true,"dependencies":{"is-number":"7.0.0","@nodelib/fs.stat":"2.0.5"}}'
  if [[ $v == 8* ]]; then echo 'lockfile-include-tarball-url=true' >"$d/.npmrc"; else echo 'lockfileIncludeTarballUrl: true' >"$d/pnpm-workspace.yaml"; fi
  (cd "$d" && npx -y "pnpm@${v%%:*}" install --lockfile-only --ignore-scripts >/dev/null) && save "$d/pnpm-lock.yaml" "${v#*:}"
done
pkg "$WORK/pnpm11-runtime" '{"name":"fixture-runtime","version":"1.0.0","private":true,"devEngines":{"runtime":{"name":"node","version":"22.11.0","onFail":"download"}},"dependencies":{"is-number":"7.0.0"}}'
(cd "$WORK" && npx -y pnpm@11.16.0 --dir "$WORK/pnpm11-runtime" install --lockfile-only --ignore-scripts >/dev/null)
save "$WORK/pnpm11-runtime/pnpm-lock.yaml" pnpm11-runtime
for rt in deno:2.1.4 bun:1.1.38; do
  d="$WORK/pnpm11-runtime-${rt%%:*}" && pkg "$d" "{\"name\":\"fixture-runtime\",\"version\":\"1.0.0\",\"private\":true,\"devEngines\":{\"runtime\":{\"name\":\"${rt%%:*}\",\"version\":\"${rt#*:}\",\"onFail\":\"download\"}}}"
  (cd "$WORK" && npx -y pnpm@11.16.0 --dir "$d" install --lockfile-only --ignore-scripts >/dev/null) && save "$d/pnpm-lock.yaml" "pnpm11-runtime-${rt%%:*}"
done
# Local dependencies whose lockfile entries are unusual: a directory path with spaces (pnpm writes
# it as a plain scalar) and a file: tarball whose own version is not semver.
for v in pnpm11-local yarn4-local; do
  d="$WORK/$v" && pkg "$d/dir with space/lib" '{"name":"spaced","version":"1.0.0"}' && pkg "$WORK/oddver-$v" '{"name":"oddver","version":"1.0"}'
  (cd "$WORK/oddver-$v" && npm pack --pack-destination "$d" >/dev/null 2>&1)
  pkg "$d" '{"name":"fixture-local","version":"1.0.0","private":true,"dependencies":{"spaced":"file:./dir with space/lib","oddver":"file:./oddver-1.0.tgz"}}'
done
(cd "$WORK/pnpm11-local" && npx -y pnpm@11.16.0 install --lockfile-only --ignore-scripts >/dev/null) && save "$WORK/pnpm11-local/pnpm-lock.yaml" pnpm11-local
printf 'enableScripts: false\nnodeLinker: node-modules\n' >"$WORK/yarn4-local/.yarnrc.yml"
(cd "$WORK/yarn4-local" && touch yarn.lock && corepack yarn@4.18.1 install --mode=update-lockfile >/dev/null) && save "$WORK/yarn4-local/yarn.lock" yarn4-local
pkg "$WORK/yarn4-longkey" '{"name":"fixture-longkey","version":"1.0.0","private":true,"workspaces":["packages/*"]}'
for n in $(seq 0 59); do pkg "$WORK/yarn4-longkey/packages/w$n" "{\"name\":\"w$n\",\"version\":\"1.0.0\",\"dependencies\":{\"ms\":\">=2.0.$n <3\"}}"; done
printf 'enableScripts: false\nnodeLinker: node-modules\n' >"$WORK/yarn4-longkey/.yarnrc.yml"
(cd "$WORK/yarn4-longkey" && touch yarn.lock && corepack yarn@4.18.1 install --mode=update-lockfile >/dev/null)
save "$WORK/yarn4-longkey/yarn.lock" yarn4-longkey

empty "$WORK/empty-npm" && (cd "$WORK/empty-npm" && npx -y npm@10.9.2 install --package-lock-only >/dev/null 2>&1) && save "$WORK/empty-npm/package-lock.json" empty-npm
# pnpm: only a workspace link, so the lockfile has importers but no packages section.
empty "$WORK/empty-pnpm" && pkg "$WORK/empty-pnpm" '{"name":"fixture-empty","version":"1.0.0","private":true,"dependencies":{"wsa":"workspace:*"}}'
pkg "$WORK/empty-pnpm/packages/wsa" '{"name":"wsa","version":"1.0.0"}' && printf 'packages:\n  - packages/*\n' >"$WORK/empty-pnpm/pnpm-workspace.yaml"
(cd "$WORK/empty-pnpm" && npx -y pnpm@11.16.0 install --lockfile-only >/dev/null) && save "$WORK/empty-pnpm/pnpm-lock.yaml" empty-pnpm
empty "$WORK/empty-yarn1" && (cd "$WORK/empty-yarn1" && corepack yarn@1.22.22 install --non-interactive >/dev/null) && save "$WORK/empty-yarn1/yarn.lock" empty-yarn1
empty "$WORK/empty-yarn4" && (cd "$WORK/empty-yarn4" && touch yarn.lock && corepack yarn@4.18.1 install --mode=update-lockfile >/dev/null) && save "$WORK/empty-yarn4/yarn.lock" empty-yarn4
echo "lockfiles written under $OUT"
