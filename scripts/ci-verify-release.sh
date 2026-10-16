#!/usr/bin/env bash
# Verify a release tag before anything is published (run by .github/workflows/release.yml, and by
# scripts/ci-release-tag.sh before it suggests a push).
#
# A release tag vX.Y.Z must be exactly one commit on top of a main commit, adding only the compiled dist/src the
# GitHub Action runs (action.yml), and that dist/src must be byte-for-byte what a clean build of the tagged source
# produces. So the action code consumers pin is the reviewed source on main, compiled, and nothing else.
#
# Usage: scripts/ci-verify-release.sh <tag> [<main-ref>]   (main-ref default: origin/main)
# Run from the repository root with the tag checked out and dependencies installed (npm ci --ignore-scripts).
# Rebuilds dist/ in place. Exit 0 verified, 1 rejected.
set -euo pipefail

tag="${1:?usage: ci-verify-release.sh <tag> [<main-ref>]}"
main_ref="${2:-origin/main}"

fail() {
  echo "ci-verify-release: $*" >&2
  exit 1
}

commit="$(git rev-parse --verify --quiet "refs/tags/${tag}^{commit}")" || fail "no tag ${tag}"
[ "$(git rev-parse HEAD)" = "$commit" ] || fail "HEAD is not ${tag}; check the tag out first"

version="$(node -p 'require("./package.json").version')"
[ "$tag" = "v${version}" ] || fail "tag ${tag} does not match package.json version ${version} (expected v${version})"

# Exactly one parent, and that parent is on main: the source part of the release went through review.
parents="$(git rev-list --parents -n 1 "$commit" | wc -w | tr -d ' ')"
[ "$parents" = "2" ] || fail "${tag} must be a single commit with one parent (found $((parents - 1)) parents)"
parent="$(git rev-parse "${commit}^")"
git merge-base --is-ancestor "$parent" "$main_ref" || fail "the parent of ${tag} (${parent}) is not on ${main_ref}"

# The tag commit changes nothing but dist/src. --no-renames: with rename detection, a file moved from outside
# dist/src into it would be listed only under its new name.
outside="$(git diff --no-renames --name-only "$parent" "$commit" | grep -v '^dist/src/' || true)"
[ -z "$outside" ] || fail "${tag} changes files outside dist/src: $(paste -sd ' ' - <<<"$outside")"
git cat-file -e "${commit}:dist/src/cli.js" 2>/dev/null || fail "${tag} does not contain dist/src/cli.js"

# Rebuild from the tagged source. Any tracked file the build changes or deletes, and any file it adds that the tag
# does not have (git ls-files --others lists ignored files too, and dist/ is ignored), is a mismatch.
npm run build >/dev/null
mismatch="$({ git diff --no-renames --name-only -- dist/src; git ls-files --others -- dist/src; } | paste -sd ' ' -)"
[ -z "$mismatch" ] || fail "committed dist/src differs from a clean build: ${mismatch}"

echo "ci-verify-release: ${tag} is ${parent} on ${main_ref} plus its own compiled dist/src, reproduced by a clean build"
