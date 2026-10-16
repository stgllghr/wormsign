# GitHub Action

The repository root is a composite GitHub Action (`action.yml`) that runs the pull-request gate (`diff`, `scan` and
`soak`) or one of those commands, writes SARIF, can upload it to code scanning, and fails the step when a finding
reaches `fail-on`. To gate pull requests, copy the [recommended gate](#recommended-pull-request-gate).

## Release status

The Action runs from a release tag commit, which holds the compiled CLI
([how](#how-the-action-gets-its-compiled-code)). No release exists yet
([release status](installation.md#release-status)): [run it from source](#running-from-source-before-a-release)
until one does. The Action's own code-scanning upload, an upload from a fork's pull request and the organization
layout have not run on GitHub.

## What the Action does

| Event | Command when `command` is empty | Checks |
|-------|---------------------------------|--------|
| `pull_request` | the gate: `diff`, then `scan`, then `soak` | The three below, each with the base commit's baseline, as three calls with `command` set would run them. |
| any other event | `scan` | The directory `path`. |
| any, with `command: diff` | `diff` | What merging adds, from `base` (the pull request's base commit) to `head` (`github.sha`, the merge commit). |
| any, with `command: scan` | `scan` | The directory `path`; on `pull_request`, with `base`'s baseline. |
| any, with `command: soak` | `soak` | Every locked Python version, and every npm one the `base` did not lock (all with no `base`): its age (default 7 days) and OSV records; npm registry signals; the release-age configuration. |

`diff` and `scan` never use the network; `soak` does unless `config-only: "true"`. Each command's checks and network
use are on its page ([diff](cli/diff.md), [scan](cli/scan.md), [soak](cli/soak.md#network)).

The Action runs the CLI once per command (`scripts/ci-action.mjs`), uploads the SARIF as category `wormsign-<command>`
when [`upload-sarif`](#sarif-and-code-scanning) allows, then fails unless `exit-code` is `0`. A single command's exit 2
fails it at once. The gate runs all three whatever each finds, prints each one's report in turn, and reports the worst
exit code (2 over 1 over 0); its SARIF file holds one run per command, each with its own category
([why](#sarif-and-code-scanning)).
Inputs reach the CLI as separate arguments through environment variables, never through a shell
([GitHub](https://docs.github.com/en/actions/reference/security/secure-use#use-an-intermediate-environment-variable)).
Boolean inputs must be exactly `"true"` or `"false"`; a typo is an error, not a silent default.

### IOC data

The Action never downloads IOC data: it uses the pinned commit's `data/iocs/` plus any newer `update-iocs` cache on
the runner, which only adds indicators ([iocs.md](iocs.md#how-update-iocs-works)). GitHub-hosted runners have no
cache, so move the pin for newer IOCs. On a persistent self-hosted runner an earlier job's cache changes the results;
set `XDG_CACHE_HOME: ${{ runner.temp }}/wormsign-no-cache` in the step's `env` to use only the commit's data. To
refresh on purpose, run the same release's `update-iocs` first with `--url` pinned to a reviewed commit (unsigned:
[cli/update-iocs.md](cli/update-iocs.md#limitations)), then delete that checkout before the scan.

## Inputs

All inputs are optional.

| Input | Default | Description |
|-------|---------|-------------|
| `command` | `""` | `scan`, `diff` or `soak`. Empty runs the gate (`diff`, `scan`, `soak`) on `pull_request`, `scan` elsewhere; an error on `pull_request_target`, `workflow_run`, `issue_comment` ([why](#permissions)). |
| `path` | `"."` | The scan or soak root; for `diff`, any directory in the repository. Keep the root when uploading to code scanning. |
| `base` | `${{ github.event.pull_request.base.sha }}` | `diff`: base revision (full SHA or `dir:<path>`). `soak`: baseline source; skips npm entries it already locked, never Python ones. |
| `head` | `${{ github.sha }}` | `diff`: the head revision; on `pull_request`, the merge commit. |
| `fail-on` | `high` | Fail the step at or above this severity: `critical`, `high`, `medium`, `low`, `info`, or `never`. |
| `sarif` | `""` | Report path; empty writes under `$RUNNER_TEMP` (`sarif` output). Only a regular file, never a symlink; keep it outside the checkout. |
| `baseline` | `""` | Empty: the base's `.wormsign-baseline.json` for `diff`, `soak` with `base`, pull-request `scan`; else the root's. Trusted files only ([baseline.md](baseline.md)). |
| `no-baseline` | `"false"` | `"true"` reads no baseline, not even the tree's own. Use it on branches you did not write. Excludes `baseline`. |
| `registry-host` | `""` | `scan`, `diff`: hosts a lockfile may resolve from besides the public registry, comma-separated on one line, each the exact lower-case host and port in the lockfile's URLs (`acme.jfrog.io`, `npm.example.com:8443`); each is a `--registry-host`. Plain HTTP is still reported. |
| `min-age` | `""` | `soak` time, such as `7d` or `72h`; empty is 7d. `72h` only with `osv` on ([why](soak.md#why-7-days-and-when-72-hours-is-enough)). |
| `registry` | `""` | `soak`: the one npm registry checked (default `https://registry.npmjs.org`); https, no credentials. It must serve publish times without credentials, and with any other registry OSV is not asked (WS-OS-900 unless `osv: "false"`; [private registries](soak.md#private-registries)). |
| `pypi-index` | `""` | `soak`: the one Python index checked (default `https://pypi.org/simple/`); https, no credentials. Setting it sends local archive names there ([network](cli/soak.md#network)). |
| `osv` | `"true"` | `soak`: ask OSV for malicious-package records. `"false"` passes `--no-osv`. |
| `config-only` | `"false"` | `soak`: check only the release-age configuration, offline. |
| `require-config` | `"false"` | `soak`: treat a missing or too-short release-age setting as high. |
| `on-outage` | `"fail"` | `soak`: `"warn"` reports a package left unchecked because the registry, index or OSV gave no answer in the whole run at medium (WS-SK-006, WS-OS-901) and writes the `UNVERIFIED` line to the step summary; a gate that passes while a whole host is down passes changes nobody checked ([trade-off](soak.md#outages---on-outage)). |
| `upload-sarif` | `"auto"` | `"auto"`: upload on a public repository, except a fork's pull request. `"true"`: always, failing on error. `"false"`: never ([details](#sarif-and-code-scanning)). |

A pull-request `scan` whose base commit is missing from the clone is exit 2. Set `pypi-index`, even to the default,
to check requirements entries when pip's configuration is unreadable ([soak.md](soak.md#requirements-files)).

**Private registries.** Behind Artifactory or Nexus every lockfile entry resolves from the mirror, so `scan` and
`diff` report each as WS-LK-002, high, until `registry-host` names the mirror's host. `soak` fails each closed
(WS-SK-002) unless `registry` is the mirror, which must then serve full package documents with publish times without
credentials (whether Artifactory or Nexus keeps them is unverified); a mirror mode that checks against public npm is
accepted, not yet built ([ADR 0007](adr/0007-private-registry-mirrors.md)). A line break in either input, or an empty `registry-host`
entry or one with a space in it, is exit 2.

## Outputs

| Output | Description |
|--------|-------------|
| `sarif` | Path of the SARIF report. Empty if the CLI failed before producing one. The gate's holds a run per command that produced a report. |
| `exit-code` | `0` below `fail-on`, `1` at or above it, `2` usage or internal error ([exit codes](output.md#exit-codes)); the gate's is the worst of the three. |
| `findings` | Findings not suppressed by the baseline, at any severity; above 0 on a passing run when all are below `fail-on`. The gate's is the sum. |

## Requirements

- **Node.js 22 or newer on `PATH`**; the Action installs nothing. Use `actions/setup-node` with `node-version: 24`
  and `check-latest: true`: `soak` needs npm 11.10 or newer, bundled from Node 24.14.1 (WS-SK-004 otherwise;
  [installation.md](installation.md#why-node-24)), and without `check-latest` setup-node "will first check the local
  cache" ([setup-node](https://github.com/actions/setup-node/blob/main/docs/advanced-usage.md#check-latest-version)),
  which can hold an older 24.x.
- **Git history for `diff`, `soak` with `base`, and `scan` on `pull_request`** (it reads the base's baseline). Use
  `fetch-depth: 2` on `pull_request` (the merge commit and both parents), or `0` for an older base. Do not set
  `filter`: `diff` fetches nothing, so a file missing from a partial clone stops it with exit 2
  ([cli/diff.md](cli/diff.md#network)).
- **`persist-credentials: false` on `actions/checkout`**, so no later step finds the token.

## Quick start

The gate on pull requests, `scan` on pushes to `main`:

```yaml
name: wormsign
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  wormsign:
    runs-on: ubuntu-latest
    permissions:
      contents: read # check out the repository
      security-events: write # upload SARIF to code scanning
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0 # diff, scan and soak read the base commit
          persist-credentials: false
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with:
          node-version: 24
          check-latest: true # use the latest 24.x, not an older one from the runner's tool cache
          package-manager-cache: false
      - uses: stgllghr/wormsign@<release commit sha> # vX.Y.Z
```

On pull requests this runs `diff`, `scan` and `soak --base` against the pull request's base commit. The gate below is
the same call, with `require-config`, the diff against the merge commit's first parent, a SARIF artifact and uploads
that skip forks.

## Recommended pull-request gate

This runs `diff`, `scan` and `soak --base` on every pull request in one call, lets all three finish and upload, then
fails the job if any failed, as this repository's `.github/workflows/wormsign.yml` does with three calls.

**Install only after the gate.** Every job that installs the change's dependencies must `needs:` the gate job, or
run after `Gate` in the same job: the wormsign step has `continue-on-error`, so a step before `Gate` runs whatever
it found. An npm package runs code at install, a PyPI package on import or, through a `.pth` file, at interpreter
start, so a job installing beside the gate runs a malicious version before the gate fails. Call jobs in other files
from this one under `needs:`, with `workflow_call:` replacing their `pull_request:` trigger, as `ci.yml` and
`action-selftest.yml` are here.

**Before you copy it:** `require-config: "true"` makes a missing release-age setting high (WS-SK-003), failing every
pull request until it is committed. For npm, commit a root `.npmrc` with `min-release-age=7` (7 days, the default
soak; shorter than `min-age` is WS-SK-004). Other package managers:
[soak.md](soak.md#layer-1-package-manager-release-age-settings). Or start with `require-config: "false"` (medium) and
switch it on later.

```yaml
name: wormsign

on:
  pull_request:

permissions:
  contents: read

jobs:
  gate:
    name: wormsign gate
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: read # check out the change
      security-events: write # upload SARIF to code scanning (same-repository pull requests only)
    steps:
      # On pull_request the default ref is the merge commit GitHub made from the base branch and the change.
      # fetch-depth 2 brings that commit and both of its parents.
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 2
          persist-credentials: false

      # The merge commit's first parent is the commit it was merged into: diffing against it shows exactly what
      # merging would add.
      - name: Resolve the base and merge commits
        id: revs
        run: |
          echo "base=$(git rev-parse HEAD^1)" >> "$GITHUB_OUTPUT"
          echo "head=$(git rev-parse HEAD)" >> "$GITHUB_OUTPUT"

      # npm 11.10 or newer (bundled from Node 24.14.1) enforces min-release-age; soak checks the npm that will run.
      # check-latest: without it, setup-node reuses any 24.x in the runner's tool cache, which may be older.
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with:
          node-version: 24
          check-latest: true # use the latest 24.x, not an older one from the runner's tool cache
          package-manager-cache: false

      # command is empty: diff (base..merge), scan and soak --base, each with the base commit's baseline, so the
      # change cannot suppress its own findings. All three run; the step fails on the worst.
      - id: gate
        name: wormsign (diff, scan, soak --base)
        uses: stgllghr/wormsign@<release commit sha> # vX.Y.Z
        continue-on-error: true
        with:
          base: ${{ steps.revs.outputs.base }}
          head: ${{ steps.revs.outputs.head }}
          require-config: "true"
          sarif: ${{ runner.temp }}/sarif/gate.sarif
          upload-sarif: "false"

      - name: Upload SARIF as an artifact
        if: always()
        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: wormsign-sarif
          path: ${{ runner.temp }}/sarif/
          if-no-files-found: warn
          retention-days: 14

      # Code scanning: public repositories, or private ones with GitHub Code Security. Uploads are skipped for
      # pull requests from forks so the gate never depends on their read-only token; their results are in the
      # artifact. Drop continue-on-error once code scanning is available, so a failed upload fails the job. The
      # file holds one run per command, each with its own category (wormsign-diff, wormsign-scan, wormsign-soak).
      - name: Upload SARIF to code scanning
        if: always() && steps.gate.outputs.sarif != '' && github.event.pull_request.head.repo.full_name == github.repository
        continue-on-error: ${{ github.event.repository.private }}
        uses: github/codeql-action/upload-sarif@24c54180a607b1449ed407dd24f251e4e9147c8d # v4.38.3
        with:
          sarif_file: ${{ steps.gate.outputs.sarif }}

      # outcome is the step's result before continue-on-error.
      - name: Gate
        if: always()
        env:
          GATE: ${{ steps.gate.outcome }}
        run: |
          echo "wormsign: $GATE"
          [ "$GATE" = success ]

  # Every job that installs dependencies waits for the gate: a failed gate skips it, so nothing the change locks
  # runs before it has been checked.
  test:
    needs: gate
    runs-on: ubuntu-latest
    permissions:
      contents: read # check out the change
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with:
          node-version: 24
          package-manager-cache: false
      - run: npm ci --ignore-scripts
      - run: npm test
```

Three calls with `command: diff`, `scan` and `soak` (the earlier form of this gate) still work and report the same
findings under the same categories; the gate is them in one step. Do not keep an extra call that uploads one of those
categories beside it: upload-sarif refuses a second upload of one tool and category in a job.

**Make the gate job the required check**, `wormsign gate` and not `test`, in branch protection or a ruleset. A job
skipped because the gate failed counts as passing, so requiring only a later job blocks nothing. On a private
repository this needs GitHub Pro, Team or Enterprise
([GitHub's plans](https://docs.github.com/en/get-started/learning-about-github/githubs-plans)).

**Python locks.** `diff` does not read what they pin; `soak --base` is their gate, and a new build it sees is
WS-SK-005, high. For a project no `uv.lock` or `pylock.toml` lists ([soak.md](soak.md#python-limitations)), `diff`
reports a change to what the build key covers, or a new project, as WS-DF-005, high, even on ordinary pull requests
([cli/diff.md](cli/diff.md#a-python-build-changed-expected-on-ordinary-pull-requests)).

### Why it is built this way

The decision is [ADR 0002](adr/0002-pr-gate-built-from-base.md). In the workflow:

- **The gate's code does not come from the change**, which could otherwise switch a check off and pass it: it is
  the Action at a pinned SHA. wormsign's own gate, which checks its own code, builds the base commit in `gate/` and
  runs it with `uses: ./gate` on the change in `pr/`, from which nothing is installed or run.
- **Suppressions come from the base.** `diff` and `soak --base` read the base's baseline; `scan` would read the
  change's, so the Action gives it the base commit's copy, or an empty one when the base has none (a base the clone
  does not hold is exit 2). A baseline change fails its own pull request
  ([review](baseline.md#reviewing-baseline-changes)).
- **The diff is against the merge commit's first parent**, so `diff` and `soak --base` see exactly what merging adds.
- **All three checks run, then `Gate` decides** from the step's `outcome`, its result before `continue-on-error`
  ([steps context](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#steps-context)).

### What the gate does not stop

The workflow file is not protected: GitHub runs a `pull_request` workflow as the merge commit has it
([pull_request](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request)),
so a same-repository branch can edit or delete it, pinned SHA included. `pull_request_target` runs the base's copy, but
is no fix ([Permissions](#permissions)).

- **What reports it:** `diff`'s WS-DF-003, at **medium** (below `fail-on: high`), if the edited workflow runs it.
- **What blocks it:** branch protection or a ruleset that requires this check **and** code-owner review, with `.github/`
  in `.github/CODEOWNERS`
  ([protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-pull-request-reviews-before-merging),
  [code owners](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)).
  A required check alone does not: the edited workflow can report a passing job under the same name.
- **Fork pull requests** can edit it too, with no secrets and a read-only `GITHUB_TOKEN`
  ([forked repositories](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflows-in-forked-repositories));
  the same review keeps them from merging. Within one repository, nothing else protects a check from the change it
  checks.

### Deploy across an organization

A required workflow in another repository is out of a pull request's reach. On GitHub Enterprise Cloud an organization
or enterprise ruleset can "Require workflows to pass before merging"
([rulesets](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#require-workflows-to-pass-before-merging));
organization rulesets need GitHub Team or Enterprise
([creating rulesets](https://docs.github.com/en/organizations/managing-organization-settings/creating-rulesets-for-repositories-in-your-organization)).

Keep a `wormsign-gate.yml` with the gate job, pinned to a release SHA, in a repository only security owners can
change; require it on the gated repositories' default branches; keep each baseline on its base branch.

Whether this repository's `main` requires the gate and code-owner review is under
[Release status](installation.md#release-status); until it does, do not treat its gate as blocking.

### soak's root

`soak` checks every lockfile and package-manager config under `path`. If some are never installed (fixtures,
examples), point `path` at the real project only (in the gate `path` is all three commands', so give `soak` its own
call for another root); `scripts/ci-root-project.sh` does this for wormsign with a sparse
git worktree, from which `soak --base` can still read the base. `ignorePaths` do not cover npm lockfiles
([baseline.md](baseline.md#ignorepaths)).

## Push and scheduled checks

A schedule catches what a push cannot: an OSV record published after a version was locked. Off `pull_request` an
empty `command` is `scan` alone, so use two calls, `command: scan` and `command: soak` (no `base`), with these
triggers, `continue-on-error` and a `Gate` step over both outcomes, without the base-revision step and the uploads'
fork condition:

```yaml
on:
  push:
    branches: [main]
  schedule:
    - cron: "23 5 * * *" # daily: new OSV malware records for versions already in the lockfile
  workflow_dispatch:
```

- `soak` then checks every locked version's age, not when it was locked: a direct push of a young version fails
  (WS-SK-001), of an old one passes. This is what catches a young npm or Python version pushed straight to `main`:
  `soak --base` on later pull requests skips it as the base's ([soak.md](soak.md#pr-mode---base-rev)).
- A scheduled `scan` of an unchanged tree finds nothing new: its IOC data is fixed at the pinned commit.
- On pushes to other branches, set `no-baseline: "true"`: a pushed branch, a worm's included, brings its own baseline.
- For no network on push, use `config-only: "true"` there and keep the full `soak` on the schedule.

## SARIF and code scanning

The Action always writes a SARIF 2.1.0 file ([output.md](output.md#sarif)); uploaded, its findings become alerts. Code
scanning needs a public repository or GitHub Code Security
([uploading a SARIF file](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github)),
or the upload fails. So:

- **Always keep the SARIF as a workflow artifact**; that works anywhere.
- **Upload in a separate step** with `continue-on-error: ${{ github.event.repository.private }}`, as above: tolerated
  while private, failing once public. Remove it if you have Code Security.
- **Or let the Action upload**: `"auto"` skips, with a notice, unless the event says the repository is public and the
  run is not a fork's pull request.
- **Forks** get a read-only `GITHUB_TOKEN`, which GitHub staff say `upload-sarif` accepts
  ([discussion 54013](https://github.com/orgs/community/discussions/54013)); the gate skips fork uploads anyway.
- **Give each upload its own category**, or it replaces the earlier alerts. The gate's file needs none: each of its
  runs carries one (`automationDetails.id` `wormsign-diff/`, `wormsign-scan/`, `wormsign-soak/`, the categories
  three single-command uploads get), since code scanning rejects a file with two runs of one tool and category
  ([GitHub changelog, 2025-07-21](https://github.blog/changelog/2025-07-21-code-scanning-will-stop-combining-multiple-sarif-runs-uploaded-in-the-same-sarif-file/)).
  Each result keeps its rule id and fingerprint, so baselines and alerts carry over from three calls.
- **Pass `checkout_path`** to `upload-sarif` when the scanned directory is not the workspace root (`pr/` in wormsign's
  gate). The Action's own upload does not, so keep `path` at the root.

## Permissions

| Permission | When | Why |
|------------|------|-----|
| `contents: read` | always | Check out the repository. Set it at the workflow's top, so no job gets more. |
| `security-events: write` | when uploading to code scanning | Upload SARIF. |
| `actions: read` | when uploading from a private repository with Code Security | GitHub's SARIF upload documentation lists it there. |

The Action needs no secrets. Use `pull_request`: a `pull_request_target` workflow that checks out the change runs
it with secrets and a write token (WS-GH-003). On `pull_request_target`, `workflow_run` and `issue_comment` the
checkout is the base or default branch, so an empty `command`, or `diff` with `head` at `github.sha`, is exit 2; an
explicit `scan` or `soak` warns that it checks whatever was checked out.

## Pin the Action by commit SHA

```yaml
- uses: stgllghr/wormsign@<release commit sha> # vX.Y.Z
```

GitHub calls a full commit SHA "the only way to use an action as an immutable release"
([secure use](https://docs.github.com/en/actions/reference/security/secure-use#using-third-party-actions)): a tag can
move, a SHA cannot. Pin the **release tag's commit**; a `main` commit lacks the compiled CLI
([dist/src/cli.js is missing](troubleshooting.md#distsrcclijs-is-missing)). The release notes print the SHA, or take
the `^{}` line (the commit) of:

```sh
git ls-remote https://github.com/stgllghr/wormsign 'refs/tags/vX.Y.Z*'
```

Check a new SHA with your own git and `main`'s verifier before pinning it
([Check a release tag yourself](installation.md#check-a-release-tag-yourself)). To upgrade, read the
[changelog](../CHANGELOG.md) and replace both the SHA and the comment.

## How the Action gets its compiled code

The Action runs `dist/src/cli.js`, the compiled TypeScript. `dist/` is in `.gitignore`, so `main` never holds build
output; each release tag adds it:

```text
main:   … ── A ── B
                   \
tag vX.Y.Z:         R    (one commit: B + dist/src, nothing else)
```

`scripts/ci-release-tag.sh <version>` builds `R` on a clean `origin/main` and tags it, pushing nothing.
`scripts/ci-verify-release.sh <tag> [<main-ref>]` checks the tag
([check it yourself](installation.md#check-a-release-tag-yourself)); the release workflow
runs the tag's own copy before packing and attesting the tarball.

## Running from source before a release

Build the Action from a pinned commit and run it as a local action, with the change in `pr/` and wormsign in
`gate/`, so the scan skips wormsign's fixtures and nothing from the change runs:

```yaml
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          path: pr
          fetch-depth: 2
          persist-credentials: false
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          repository: stgllghr/wormsign
          ref: <full commit sha on main>
          path: gate
          persist-credentials: false
      # actions/setup-node, as in the gate
      - name: Build wormsign
        working-directory: gate
        run: |
          npm ci --ignore-scripts
          npm run build
          node dist/src/cli.js --version
      - id: gate
        uses: ./gate
        continue-on-error: true
        with:
          path: pr
          # base and head from `git -C pr rev-parse HEAD^1` and `HEAD`, as above
```

The rest of the gate carries over with `working-directory: pr` for `git` and
`checkout_path: ${{ github.workspace }}/pr` for `upload-sarif`. `.github/workflows/wormsign.yml` is a complete
example, built from the pull request's base.

## How the Action is tested

`.github/workflows/action-selftest.yml` runs the Action through `uses: ./` on every pull request (after the gate) and
push to `main`: a malicious `diff` must fail with `findings` 2 and WS-GH-001 in the SARIF, a clean `diff` must pass,
and a `scan` of the malicious fixture must fail. The empty-command default, `no-baseline`, `min-age`, `on-outage`,
`registry-host`, `registry`, the SARIF file and the upload decision are covered only by tests of
`scripts/ci-action.mjs`, which run the gate's three commands on a local git repository with the network replaced
([validation.md](validation.md)); no Actions run has exercised the gate or its three-run upload.

## Troubleshooting

Failures shared with the CLI are in [troubleshooting.md](troubleshooting.md). The Action's own:

- `diff needs base and head revisions…`: `command: diff` off `pull_request`; set `base` and `head`.
- `osv must be "true" or "false", got "flase"` (any boolean input): quote the value exactly.
- `wormsign: baseline file not found: …` (exit 2): the base-baseline step did not run.
