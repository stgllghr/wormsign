# Maintainer hardening: the propagation stage

Shai-Hulud-style worms spread by publishing: a payload running on a maintainer's machine or in CI uses the npm
credentials it finds to publish infected versions of their packages
([StepSecurity, 2025-09](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)). The
2026-08 payload takes a token with `bypass_2fa === true` and write permission, sets `scripts.preinstall` to
`node setup.mjs`, bumps the patch version and publishes
([JFrog](https://research.jfrog.com/post/shai-hulud-is-back-august/)).

Use this page to set the npm and GitHub options that stop a stolen credential, or a malicious dependency in your CI,
from publishing as you. wormsign changes none of them, and it watches the packages you **consume**, not those you
**publish** ([incident-response.md, step 5](incident-response.md#5-check-your-published-packages)). The settings come
from the linked npm and GitHub documentation; none was changed on a live npm account by this project.

## Checklist

| # | Control | Stops |
|---|---|---|
| 1 | [Publish through trusted publishing, then disallow tokens](#1-publish-through-trusted-publishing-then-disallow-tokens) | a stolen npm token publishing from anywhere; with staging only, any credential making a version live without a 2FA approval |
| 2 | [Keep the publish step away from dependency code](#2-keep-the-publish-step-away-from-dependency-code) | a malicious dependency in your CI minting a publish credential |
| 3 | [Require 2FA on the account](#3-require-2fa-on-the-account) | a stolen password, or a session token, changing the account |
| 4 | [If you still need tokens, make them narrow and short-lived](#4-if-you-still-need-tokens-make-them-narrow-and-short-lived) | a stolen token reaching every package, for a long time |
| 5 | [Publish with provenance](#5-publish-with-provenance) | consumers being unable to tell where a version was built |
| 6 | [Review GitHub Actions secrets, environments and settings](#6-review-github-actions-secrets-environments-and-settings) | a stolen GitHub token or injected workflow reaching publish secrets |
| 7 | [Keep tokens off developer machines](#7-keep-tokens-off-developer-machines) | the install-time payload finding a token to steal |

## 1. Publish through trusted publishing, then disallow tokens

Register a [trusted publisher](https://docs.npmjs.com/trusted-publishers) on each package's settings page, so CI
publishes with a short-lived OIDC credential instead of a stored token. Then, under **Publishing access**, choose
**Require two-factor authentication and disallow tokens**, which blocks every granular token from publishing,
whatever its bypass-2FA setting
([publishing access](https://docs.npmjs.com/requiring-2fa-for-package-publishing-and-settings-modification)), and
revoke the automation tokens you no longer need. From npm's trusted-publishing page:

- GitHub Actions on GitHub-hosted runners, GitLab CI/CD on GitLab.com shared runners and CircleCI cloud; not
  self-hosted runners. npm CLI 11.5.1 or later, Node 22.14.0 or later, and `permissions: id-token: write`.
- OIDC covers `npm publish`, `npm stage publish` and dist-tags (with npm 11.21.0 or later, or 12.2.0 or later);
  private dependencies still need a read-only granular token. `npm trust` (11.15.0 or later) manages it from the CLI
  ([npm trust](https://docs.npmjs.com/cli/v11/commands/npm-trust/)).
- **Allowed actions:** `npm stage publish` is always allowed; `npm publish` and `npm dist-tag` are separate choices.
  Configurations created after 2026-09-03 default to staging only, those before 2026-05-20 to `npm publish` only.
  Leave direct publishing off.

**Limit:** anything in the job that holds `id-token: write` can request the credential. JFrog's analysis of the
2026-08 sample shows code that, in a `release-drafter.yml` run of one named repository, requests an OIDC token,
publishes, and creates a Sigstore bundle for valid provenance (JFrog describes the code, not an observed publish).
Staging (below) and section 2 address it.

### Stage, then approve with 2FA

With [staged publishing](https://docs.npmjs.com/staged-publishing), CI runs `npm stage publish` and the version waits
until a maintainer approves it on npmjs.com or with `npm stage approve <stage-id>`, with 2FA;
`npm stage download <stage-id>` fetches it first ([npm stage](https://docs.npmjs.com/cli/v11/commands/npm-stage/)). It
needs npm CLI 11.15.0 or later and Node 22.14.0 or later. Make it the only path: leave `npm publish` unticked, or use
**Read and write (stage only)** tokens ([About access tokens](https://docs.npmjs.com/about-access-tokens)). A stolen
stage-only credential then cannot make a version live. The approval is only as good as the review: compare the staged
tarball with the source or an independent rebuild, or an altered one (section 2) goes live. A new package shows a
`0.0.0-stage` placeholder publicly while its first version is staged.

## 2. Keep the publish step away from dependency code

Give `id-token: write` only to a job that runs no dependency code:

- **Two jobs.** `build` installs with `npm ci --ignore-scripts`, tests and packs, read-only. `publish`, the only job
  with `id-token: write`, publishes that tarball.
- **A protected environment** for `publish`, named in the trusted publisher settings, with required reviewers or branch
  and tag restrictions
  ([environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments);
  on GitHub Free, public repositories only).
- **Actions pinned by full commit SHA**, "currently the only way to use an action as an immutable release"
  ([Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)).

A sketch, not run (it parses as YAML, `wormsign scan` reports nothing in it, and its SHAs were resolved from each
action's release tag on 2026-10-02):

```yaml
name: publish

on:
  push:
    tags: ["v*"]

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
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
      - run: npm pack
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: package
          path: "*.tgz"

  publish:
    needs: build
    runs-on: ubuntu-latest
    environment: npm # name this environment in the package's trusted publisher settings
    permissions:
      contents: read
      id-token: write # the OIDC token trusted publishing exchanges for a publish credential
    steps:
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with:
          node-version: 24
          registry-url: https://registry.npmjs.org
          package-manager-cache: false
      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with:
          name: package
      - run: npm publish ./*.tgz # needs "npm publish" ticked under Allowed actions; see below
```

The last step needs `npm publish` allowed; to keep the approval, use `npm stage publish` instead
([Stage, then approve with 2FA](#stage-then-approve-with-2fa)).

This does not stop **a malicious change merged into the repository** (branch protection, code-owner review of
`.github/` and a [pull-request gate](github-action.md) are the controls) or **dependency code that alters the
tarball** in `build` (`npm test`, the compiler, linters), which `publish` then ships with valid provenance:
provenance records the workflow, not the contents. Narrow it by testing in a separate job, packing with as little
dependency code as possible, and comparing an independent rebuild before approving. This repository's
[`release.yml`](../.github/workflows/release.yml) has the same split and the same limit: `npm test` runs the
TypeScript compiler before `npm pack` in the job that packs, and nothing compares the tarball with a rebuild.

## 3. Require 2FA on the account

Choose npm's "Authorization and writes" level, so publishing and settings changes need a second factor
([Configuring 2FA](https://docs.npmjs.com/configuring-two-factor-authentication)), preferably a security key. Keep the
recovery codes offline; using one puts a 72-hour hold on publishing, tokens and settings. 2FA does not cover a token
with **Bypass two-factor authentication** unless the package disallows tokens or the token is stage-only.

## 4. If you still need tokens, make them narrow and short-lived

npm supports only granular tokens, and says direct publishing with one will be removed in January 2027
([About access tokens](https://docs.npmjs.com/about-access-tokens)). When creating one
([docs](https://docs.npmjs.com/creating-and-viewing-access-tokens)):

- **Scope it:** read-only for installs; **Read and write (stage only)** for publishing, limited to the packages the
  job publishes.
- **Expire it** at the shortest expiry that works, and rotate it; set **Allowed IP ranges** when the job's addresses are
  known.
- **Leave Bypass 2FA off** unless the token must publish without a human: a worm publishes with exactly those, and
  JFrog's guidance revokes them first ([JFrog](https://research.jfrog.com/post/shai-hulud-is-back-august/)).

List and revoke with `npm token list` and `npm token revoke <id>`
([npm token](https://docs.npmjs.com/cli/v11/commands/npm-token/)).

## 5. Publish with provenance

Provenance records which repository, workflow and commit built a version
([docs](https://docs.npmjs.com/generating-provenance-statements)). Trusted publishing from GitHub Actions or GitLab
generates it for a public package from a public repository; otherwise use `npm publish --provenance` on cloud-hosted
runners with `id-token: write`, npm 9.5.0 or later and a matching `repository` field. Consumers verify with
`npm audit signatures`; on this repository's development dependencies:

```console
$ npm audit signatures
audited 110 packages in 2s

110 packages have verified registry signatures

27 packages have verified attestations
```

Then a token used outside your CI publishes without provenance, and `wormsign soak` reports that to consumers as
WS-RG-002. Provenance proves where a version was built, not that the build was intended: a worm inside your release
workflow gets valid provenance, which WS-RG-002 cannot tell apart.

## 6. Review GitHub Actions secrets, environments and settings

An injected workflow can read every secret a run can reach; the 2025-09 worm sent out `toJSON(secrets)`
([StepSecurity](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)).

- **List the secrets** at each level (`gh secret list`, with `--env` or `--org`) and delete unused ones, starting with
  `NPM_TOKEN`. This repository has none and uses only `GITHUB_TOKEN`:

  ```console
  $ gh secret list -R stgllghr/wormsign
  $ gh api repos/stgllghr/wormsign/environments --jq '.total_count'
  0
  ```

- **Put publish secrets in an environment** with required reviewers, so no job reads them before a reviewer
  approves.
- **Default `GITHUB_TOKEN` to read-only**, grant more per job, and turn on **Require actions to be pinned to a
  full-length commit SHA**
  ([Actions settings](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository)).
- **Avoid** `pull_request_target` or `workflow_run` workflows that check out pull request code, and self-hosted
  runners on public repositories ([Secure use](https://docs.github.com/en/actions/reference/security/secure-use));
  `wormsign scan` reports both (WS-GH-003, WS-GH-004).
- **For an organization,** restrict personal access tokens and set a maximum lifetime
  ([PAT policy](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization)).
- **Protect the workflow files** with code-owner review of `.github/`
  ([code owners](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners))
  and rulesets on release tags and branches
  ([rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)).

## 7. Keep tokens off developer machines

The payload reads credential files, environment variables and shell profiles
([Datadog](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)), so a publish token in `~/.npmrc`
makes the machine a publisher for the worm; with trusted publishing a laptop needs none. `harden-dev.sh` finds the
common cases without printing the value (here, a placeholder token in an empty test `HOME`):

```console
$ ./harden-dev.sh --offline
...
[FAIL] H08  $TMPDIR/.../.npmrc:1 registry credential (_authToken/_auth/_password/npmAuthToken). Move it to a keychain or an env var set at runtime, then rotate it.
```

H09 checks `gh` token scopes ([hardening.md](hardening.md#the-other-checks)).
