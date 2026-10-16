#!/usr/bin/env bash
# Check out only this repository's own project files (package.json, package-lock.json, .npmrc,
# .wormsign-baseline.json) at a commit into a new directory, for wormsign soak.
#
# Why: soak walks every lockfile and package-manager config under its root, and test/fixtures holds dozens of
# synthetic ones (fake packages, deliberately missing release-age settings) that are never installed. The project's
# install surface is the root lockfile and .npmrc, so that is what the soak gate checks. The directory is a sparse git
# worktree sharing the repository's objects, so `soak --base <rev>` can still read the base revision's lockfile and
# baseline.
#
# Usage: scripts/ci-root-project.sh <repo-dir> <new-dir> [<commit>]   (commit default: HEAD of repo-dir)
set -euo pipefail

repo="${1:?usage: ci-root-project.sh <repo-dir> <new-dir> [<commit>]}"
dest="${2:?usage: ci-root-project.sh <repo-dir> <new-dir> [<commit>]}"
commit="$(git -C "$repo" rev-parse --verify "${3:-HEAD}^{commit}")"

git -C "$repo" worktree add --quiet --detach --no-checkout "$dest" "$commit"
# Non-cone patterns are gitignore-style: a leading / anchors a pattern to the root, so nested copies are excluded.
git -C "$dest" sparse-checkout set --no-cone /package.json /package-lock.json /.npmrc /.wormsign-baseline.json
git -C "$dest" checkout --quiet --detach "$commit"
present=""
for f in package.json package-lock.json .npmrc .wormsign-baseline.json; do
  if [ -e "$dest/$f" ]; then present="$present $f"; fi
done
echo "ci-root-project: checked out${present:- nothing} at ${commit} in ${dest}"
