# Installation

Install wormsign from a GitHub Release tarball or a clone; it is not on the npm registry, so there is no
`npm install wormsign` or `npx wormsign`. Until the first release, [install from source](#install-from-source).

## Requirements

| Need | For | Notes |
|------|-----|-------|
| Node.js 22 or newer | the CLI and the Action | `"engines": { "node": ">=22" }`; CI tests Node 22 and 24. The Action refuses an older Node; the CLI does not check. |
| Node.js 24.14.1 or newer (recommended) | npm's release-age cooldown | [Why Node 24](#why-node-24) |
| git | `diff` with revisions, `soak --base` | Both read the base from git history; `diff dir:<path>` does not. `soak --base` skips a Python entry the base read identically only with git 2.40 or later (`git check-attr --source`). |
| python3 with pip (optional) | `soak` of a requirements file, or a `pylock.toml` package without an index | `soak` reads pip's index settings with it; without it those entries fail closed unless `--pypi-index` is given ([soak.md](soak.md#requirements-files)). |
| Network access | `soak` (except `--config-only`), `audit-org`, `update-iocs` | `scan`, `diff` and `skills` never use the network. |
| bash 3.2 or newer | `harden-dev.sh` | macOS and Linux |
| GitHub CLI (`gh`), optional | verifying a release's attestation | the only way to check where a tarball was built |

Windows is not tested, and `harden-dev.sh` does not support it.

### Why Node 24

npm's `min-release-age` setting refuses to install a version published less than N days ago ([npm config
docs](https://docs.npmjs.com/cli/v11/using-npm/config#min-release-age)): the package-manager half of the soak time.
npm enforces it from 11.10; npm 10, which Node 22 bundles, accepts the key and installs young versions anyway ([the
experiment](evidence/package-managers.md#npm)). Node 24.14.1 and later bundle npm 11.10 or newer; Node 24.0.0 to
24.14.0 bundle npm 11.3 to 11.9, which ignore it ([Node.js release index](https://nodejs.org/dist/index.json)). On
Node 22, or an older Node 24, upgrade npm itself. The npm version is what matters, so check it:

```sh
npm --version   # 11.10.0 or newer enforces min-release-age
```

On an older npm, `wormsign soak` reports the setting as ignored (WS-SK-004) and `harden-dev.sh` fails H02
([troubleshooting](troubleshooting.md#npm-ignores-min-release-age-ws-sk-004)).

## Release status

- **No release has been cut.** There is no tag, no tarball and no attestation; version 0.1.0 in
  `package.json` is not released. Until the first release, [install from source](#install-from-source).
- **The repository is public** since 2026-10-16, on a
  Free personal account, starting from one commit. A ruleset on `main` requires a pull request, the
  gate's status check (the `gate (built from base)` job in `.github/workflows/wormsign.yml`), the CI
  checks and code-owner review, and blocks force pushes and deletion; a second limits who can create
  `v*` tags ([github-action.md](github-action.md#what-the-gate-does-not-stop)). With one maintainer, the
  repository admin is the rulesets' one bypass actor, for pull requests only: GitHub does not let an author
  approve their own pull request. Private vulnerability reporting, secret scanning with push protection and
  Dependabot alerts are on ([SECURITY.md](../SECURITY.md)).
- **This repository's first runs:**

  | Workflow | Run | Result |
  |---|---|---|
  | `ci.yml` | push to `main`: [run](https://github.com/stgllghr/wormsign/actions/runs/38855437604) | success |
  | `ci.yml` | `workflow_dispatch` with `-f slow=true` (full mutation check, macOS): [run](https://github.com/stgllghr/wormsign/actions/runs/38855495362) | in progress at publication |
  | `wormsign.yml` | push to `main`: [run](https://github.com/stgllghr/wormsign/actions/runs/38855437638) | success |
  | `action-selftest.yml` | push to `main`: [run](https://github.com/stgllghr/wormsign/actions/runs/38855437615) | success |
  | `codeql.yml` | push to `main`: [run](https://github.com/stgllghr/wormsign/actions/runs/38855437613) | success; its first alerts are being triaged |
  | `scorecard.yml` | push to `main`: [run](https://github.com/stgllghr/wormsign/actions/runs/38855437684) | success |
  | `wormsign.yml` | the canary pull request ([validation.md](validation.md#the-canary-pull-request)) [#15](https://github.com/stgllghr/wormsign/pull/15), closed unmerged: [run](https://github.com/stgllghr/wormsign/actions/runs/38855521831) | failed, as it must: `gate (built from base)` failed on CRITICAL WS-GH-001 |
  | code scanning | the canary's SARIF upload: [run](https://github.com/stgllghr/wormsign/actions/runs/38855521831) | the alerts view shows WS-GH-001 (critical, [#39](https://github.com/stgllghr/wormsign/security/code-scanning/39)) and WS-DF-003 (medium, [#38](https://github.com/stgllghr/wormsign/security/code-scanning/38)) |

  They are also the first runs of the PyPI soak and the pre-public fixes on GitHub's runners and on Linux.
- **Not yet done:** the v0.1.0 tag, its release and the output of `gh attestation verify` for its
  tarball ([Check a release tag yourself](#check-a-release-tag-yourself)), linked here when they exist.

Earlier runs, in the private development repository, are in
[evidence/test-runs.md](evidence/test-runs.md#before-publication). Where a page describes CI without a dated run, it
describes what the workflow file is configured to do; commands shown with output were run locally.

## Install from a GitHub Release

### What a release contains

A release is a tag `vX.Y.Z`: one commit on top of `main` that adds only the compiled `dist/src`, which the Action
runs ([why](github-action.md#how-the-action-gets-its-compiled-code)). On the tag, `release.yml`'s **build** job
(read-only token) refuses a tag that does not match `package.json`'s version or fails the checks
[below](#check-a-release-tag-yourself), then tests and smoke-installs the tarball. Its **publish** job (`contents:
write`, `id-token: write`, `attestations: write`; no npm code) releases `wormsign-X.Y.Z.tgz`, `SHA256SUMS`, and a
signed SLSA build provenance attestation, stored on GitHub. The tarball has no npm dependencies (smol-toml is
vendored), no install scripts and no tests.

### Download and verify

```sh
gh release download vX.Y.Z --repo stgllghr/wormsign
sha256sum -c SHA256SUMS
gh attestation verify wormsign-X.Y.Z.tgz --repo stgllghr/wormsign \
  --signer-workflow stgllghr/wormsign/.github/workflows/release.yml
```

Without `gh`, download both files from the release page; on macOS without `sha256sum`, use
`shasum -a 256 -c SHA256SUMS`. The two checks prove different things:

- The checksum only catches a damaged download: whoever can change the release can change both files.
- The attestation shows a workflow at `.github/workflows/release.yml` in this repository built the tarball, not that
  the file was reviewed: a tag push runs the tag's own `release.yml`. The [next section](#check-a-release-tag-yourself)
  closes that gap.

If `gh attestation verify` fails on the downloaded tarball with the exact repository `stgllghr/wormsign`, do not
install it; report it ([SECURITY.md](../SECURITY.md)).

### Check a release tag yourself

The release workflow's checks (`scripts/ci-verify-release.sh`, [above](#what-a-release-contains)) run as the tag's
own copy, so a tag that also edits `release.yml` can drop them and still get a valid attestation. These checks run
with your own git, against the public history, and depend on no workflow:

```sh
git clone https://github.com/stgllghr/wormsign.git
cd wormsign
tag=vX.Y.Z
commit=$(git rev-parse "$tag^{commit}")
git rev-list --parents -n 1 "$commit"            # two SHAs: the tag commit and its one parent
git merge-base --is-ancestor "$commit^" origin/main && echo "parent is on main"
git diff --no-renames --name-only "$commit^" "$commit" | grep -v '^dist/src/' || echo "only dist/src changed"
```

Expect exactly two SHAs on the first line, then `parent is on main` and `only dist/src changed`;
any file name printed instead is a change outside `dist/src`, and the tag should not be trusted.
Together they show that every file in the tag except `dist/src`, `release.yml` and the verifier
included, is a `main` commit's. They do not show how that commit reached `main`: that it came
through a reviewed pull request holds only once a ruleset on `main` requires one
([Release status](#release-status)). To check that
`dist/src` is what that source compiles to, run `main`'s copy of the verifier, never the tag's:

```sh
verify=$(mktemp)
git show origin/main:scripts/ci-verify-release.sh > "$verify"
git switch --detach "$tag"
npm ci --ignore-scripts
bash "$verify" "$tag" origin/main      # rebuilds dist/ and compares it with the committed dist/src
```

Then bind the attestation to the commit you checked, so it means "built from that commit, by
that commit's `release.yml`":

```sh
gh attestation verify wormsign-X.Y.Z.tgz --repo stgllghr/wormsign \
  --signer-workflow stgllghr/wormsign/.github/workflows/release.yml \
  --source-ref "refs/tags/$tag" --source-digest "$commit" --signer-digest "$commit"
```

On a tag push the source commit and the workflow's commit are both the tag commit. `gh` 2.96.0
lists these flags (`gh attestation verify --help`); they have not been run against a wormsign
attestation, since no release exists yet. The same checks apply to the commit you pin the
Action to: it is the tag commit (`git rev-parse "$tag^{commit}"`).

### Install the tarball

```sh
npm install -g ./wormsign-X.Y.Z.tgz --ignore-scripts
```

The package has no install scripts; `--ignore-scripts` keeps the habit safe. If `wormsign` is then not found, add
`<prefix>/bin` to your `PATH` (`npm prefix -g` prints the prefix). The release notes give these steps but not the tag
check: run it too. Never install straight from a URL, which skips every check.

## Install from source

```sh
git clone https://github.com/stgllghr/wormsign.git
cd wormsign
git checkout <tag or commit>    # optional: pin what you build
npm ci --ignore-scripts
npm run build
node dist/src/cli.js --version
```

`npm ci --ignore-scripts` installs exactly the versions in `package-lock.json`, all development tools, and runs no
install scripts; the repository's `.npmrc` also sets `min-release-age=7`, which needs npm 11.10 or newer
([Why Node 24](#why-node-24)). `npm run build` compiles `dist/src` (the CLI) and `dist/test`.

### Put `wormsign` on your PATH

Call `node dist/src/cli.js` directly, or link the clone into npm's global prefix:

```sh
npm link            # from the clone; creates a global `wormsign` pointing at this directory
```

A link follows the clone: after `git pull`, run `npm run build` again.

## Run harden-dev.sh

What `harden-dev.sh` checks and writes is in [hardening.md](hardening.md). Most checks need only bash. H09 needs a
logged-in `gh` (skipped with `--offline`), H12 and H13 the pip or uv being checked, and H11, the only check for worm
payload files on disk, Node.js and a built wormsign.

```sh
bash "$(npm root -g)/wormsign/harden-dev.sh"   # an installed release: every check runs
./harden-dev.sh                                # a clone, after npm run build
```

Standalone, download it from a specific commit and read it first; never pipe it into a shell. H11 is then skipped.

```sh
curl -fsSL -o harden-dev.sh \
  https://raw.githubusercontent.com/stgllghr/wormsign/<commit sha>/harden-dev.sh
less harden-dev.sh
bash harden-dev.sh
```

A full run is explained in [hardening.md](hardening.md#example-run).

## Verify the install

```sh
wormsign --version
```

Then give it an inert positive control: a harmless workflow named after a published Shai-Hulud indicator. The scan
must exit 1 with WS-GH-001, and exit 0 once the file is removed.

```sh
t=$(mktemp -d)
mkdir -p "$t/.github/workflows"
printf 'on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo inert\n' \
  > "$t/.github/workflows/shai-hulud-workflow.yml"
wormsign scan "$t"; echo "exit $?"
rm "$t/.github/workflows/shai-hulud-workflow.yml"
wormsign scan "$t"; echo "exit $?"
rm -rf "$t"
```

Output from a tarball install (shortened):

```text
CRITICAL WS-GH-001  .github/workflows/shai-hulud-workflow.yml
...
note: IOC data 2026-10-02 from the bundled data …/lib/node_modules/wormsign/data/iocs/
...
exit 1
...
exit 0
```

The `IOC data` note names the data the scan used and its date ([iocs.md](iocs.md)).

## Update

Release install: install the new tarball the same way. Source install: `git pull`, `npm ci --ignore-scripts`,
`npm run build`. IOC data only: `wormsign update-iocs` ([cli/update-iocs.md](cli/update-iocs.md)); the Action never
downloads IOC data ([github-action.md](github-action.md#ioc-data)).

## Uninstall

```sh
npm uninstall -g wormsign      # a release install
npm unlink -g wormsign         # a source install linked with npm link (the clone stays)
```

Run `wormsign skills uninstall` first if you installed the agent skill ([cli/skills.md](cli/skills.md)). Left behind:
the `update-iocs` cache (`rm -rf "${XDG_CACHE_HOME:-$HOME/.cache}/wormsign"`); the settings `harden-dev.sh --apply`
wrote ([files](hardening.md#what---apply-writes)), which are the hardening, so keep them; and its backups,
`<file>.wormsign-bak.<timestamp>.<pid>`. A backup of a file that held a plaintext token still holds it.

## Troubleshooting

Errors and their fixes are in [troubleshooting.md](troubleshooting.md).
