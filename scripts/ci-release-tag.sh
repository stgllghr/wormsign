#!/usr/bin/env bash
# Maintainer helper: create the release tag vX.Y.Z that the GitHub Action is pinned to. Pushes nothing.
#
# The tag is one commit on top of the current origin/main that adds only the compiled dist/src (dist/ is in
# .gitignore, so main never carries build output). Pushing the tag starts .github/workflows/release.yml, which
# rebuilds it and refuses to release unless dist/src matches the source exactly (scripts/ci-verify-release.sh).
#
# Usage: scripts/ci-release-tag.sh <version>     e.g. scripts/ci-release-tag.sh 0.2.0
# Before: the version bump to package.json is merged to main through a pull request.
set -euo pipefail

version="${1:?usage: ci-release-tag.sh <version>}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo "not a semver version: $version" >&2; exit 1; }
tag="v${version}"
cd "$(git rev-parse --show-toplevel)"

[ -z "$(git status --porcelain)" ] || { echo "the working tree is not clean" >&2; exit 1; }
git fetch --quiet origin main
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || { echo "HEAD is not origin/main; check out an up-to-date main" >&2; exit 1; }
[ "$(node -p 'require("./package.json").version')" = "$version" ] || { echo "package.json is not at version $version; bump it through a pull request first" >&2; exit 1; }
if git rev-parse --verify --quiet "refs/tags/${tag}" >/dev/null; then echo "tag ${tag} already exists" >&2; exit 1; fi

branch="$(git symbolic-ref --quiet --short HEAD || true)"
npm ci --ignore-scripts
npm run build
git checkout --quiet --detach
git add --force dist/src
git commit --quiet -m "Release ${tag}: compiled dist/src for the GitHub Action"
git tag -a "$tag" -m "wormsign ${tag}"
scripts/ci-verify-release.sh "$tag" origin/main
[ -z "$branch" ] || git checkout --quiet "$branch"

echo "Created ${tag} at $(git rev-parse "${tag}^{commit}"). Review it (git show --stat ${tag}), then: git push origin ${tag}"
