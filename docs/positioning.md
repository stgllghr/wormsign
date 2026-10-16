# Where wormsign fits

Use this page to decide what wormsign adds to the tools you already run, and where it is redundant. Each claim about
another tool comes from its official documentation or source, linked below and retrieved on 2026-10-14, except
the sections marked with another date. Nothing was benchmarked; check the linked page before you decide.

## Summary

| Tool | What it does | Overlap with wormsign | What wormsign adds |
|---|---|---|---|
| [npm audit and the GitHub Advisory Database](#npm-audit-and-the-github-advisory-database) | Known vulnerabilities; malware advisories and alerts | known-bad versions | release age; what a change adds; OSV records GitHub lacks |
| [OSV-Scanner](#osv-scanner) | Matches dependencies against OSV, in pull requests too | the same OSV database | release age; registry signals; workflow and agent-hook checks |
| [Socket](#socket) | Flags risky new dependencies; its Firewall blocks known malware at install | install-script, git-source, new-author and malware alerts; age, with the cool-down on | a fail-closed gate built from the base; workflow and agent-hook checks; no account |
| [Dependabot cooldown](#dependabot-cooldown) | Waits before proposing version updates; 3 days by default | release age, for its own pull requests | a gate on any lockfile change; OSV |
| [Renovate `minimumReleaseAge`](#renovate-minimumreleaseage) | Waits before proposing updates | as Dependabot | as Dependabot |
| [npm `min-release-age`](#npm-min-release-age) | Refuses to resolve versions younger than N days | the same control, at resolution | the lockfile: `npm ci` installs a young locked version |
| [pnpm `minimumReleaseAge`, `trustPolicy`](#pnpm-minimumreleaseage-and-trustpolicy) | Age gate, from v11 on lockfile entries too; fails on a trust downgrade | largely redundant with pnpm 11+ and strict settings | OSV; install-script and publisher signals; the base-built gate |
| [Yarn and bun release-age settings](#yarn-and-bun-release-age-settings) | Refuse versions younger than a set age | the same control | a Yarn lockfile gate; a check the setting works |
| [`npm audit signatures`](#npm-audit-signatures) | Verifies signatures and provenance of installed packages | integrity; dropped provenance | runs before the install; age, OSV and publisher checks for a signed worm publish |
| [StepSecurity Harden-Runner](#stepsecurity-harden-runner) | Monitors and limits CI runner egress, files and processes | none; a paid PR check adds an npm cooldown | checks before anything runs, with no service |
| [OpenSSF Scorecard](#openssf-scorecard) | Scores a repository's security practices | untrusted checkouts in privileged workflows | worm IOCs, secrets dumps, a gate that fails |
| [zizmor](#zizmor) | Static security audits of workflows and actions | WS-GH-002 to WS-GH-004 | worm IOCs, secrets sent out, any discussion trigger with run steps, the base-built gate |
| [actionlint](#actionlint) | Lints workflows: syntax, expression types, shellcheck | none of the WS-GH rules | the workflow security rules |
| [JFrog Curation](#jfrog-curation) | Blocks immature and malicious packages at Artifactory | age and malware gate, for every client | no Artifactory; registry signals; repository checks |

What wormsign adds to any of them: a lockfile gate that fails closed ([ADR 0001](adr/0001-fail-closed.md)), run
from the base commit so a pull request cannot weaken it ([ADR 0002](adr/0002-pr-gate-built-from-base.md)); checks
of the editor and agent auto-run files the August 2026 wave committed; and each locked Python file bound to PyPI by
sha256 and aged by its own upload time.

## npm audit and the GitHub Advisory Database

Read 2026-10-02.

**What it does.** `npm audit` "submits a description of the dependencies configured in your project to your
default registry and asks for a report of known vulnerabilities"
([npm docs](https://docs.npmjs.com/cli/v11/commands/npm-audit)). GitHub publishes **malware advisories**
"automatically ... from the npm security team and the OpenSSF Malicious Packages repository", and with malware alerts
on, Dependabot alerts on a dependency that matches one
([GitHub docs](https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database)).

**Overlap.** Both answer "is this exact version known to be bad?": wormsign through its IOC lists (WS-LK-001) and
OSV's malicious-package records (WS-OS-001).

**What wormsign adds.** OSV listed worm versions that GitHub had no malware advisory for
([evidence/soak-latency.md](evidence/soak-latency.md)). In turn, `npm audit` reports known vulnerabilities, which
WS-OS-001 leaves out unless an advisory lists CWE-506 ([soak.md](soak.md#layer-3-osv-malicious-package-records)).
Neither checks age or what a change adds. Run both.

## OSV-Scanner

**What it does.** It matches a project's dependencies against OSV: 11+ ecosystems, 19+ lockfile types, container
images, licence checks and an offline mode ([README](https://github.com/google/osv-scanner)). Its pull-request
workflow "will only report new vulnerabilities introduced through the pull request"
([GitHub Action](https://google.github.io/osv-scanner/github-action/)).

**Overlap.** `soak` asks the same OSV API, but only for malicious-package records: `MAL-` records and GitHub
advisories with CWE-506 (WS-OS-001). Running both asks OSV twice.

**What wormsign adds.** Release age, registry identity and signals, and the workflow and agent-hook checks.

## Socket

**What it does.** Socket for GitHub comments on risks in each dependency a pull request adds: an install script,
known malware, typosquats, native code, mutable git or http dependencies
([docs](https://docs.socket.dev/docs/socket-for-github)). A "New author" alert fires when "a new npm collaborator
published a version of the package for the first time"
([supply chain risk](https://docs.socket.dev/docs/supply-chain-risk)). A "Recently published" alert flags versions
inside an org-wide cool-down window of 0 to 365 days, off by default
([cool-down policy](https://docs.socket.dev/docs/cool-down-policy)). Socket Firewall blocks confirmed malicious
packages at install; the free version wraps a command (`sfw npm install`) for npm, Yarn, pnpm, pip, uv and cargo
on public registries ([docs](https://docs.socket.dev/docs/socket-firewall-overview)).

**Overlap.** Install scripts are WS-DF-001 and WS-DF-004, git and http sources WS-LK-002, new author close to
WS-RG-003, known malware WS-LK-001 and WS-OS-001, and the cool-down WS-SK-001. With Socket on your pull requests,
those findings are largely redundant.

**What wormsign adds.** A fail-closed lockfile gate run from the base commit, workflow and agent-hook checks, and
rules and data in the repository, with no account. Socket reads package code; wormsign does not
([threat model](threat-model.md#out-of-scope)).

## Dependabot cooldown

**What it does.** `cooldown` delays version updates by a number of days, with per-semver values and include and
exclude lists. Without it, Dependabot waits 3 days. Neither applies to security updates
([options reference](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference#cooldown-)).

**Overlap and what wormsign adds.** Dependabot waits before it proposes; `soak` gates what the lockfile pins,
whoever changed it: a person, another bot, a fork. Set the cooldown
to at least the soak time, or Dependabot's pull requests fail the gate. A security update arrives young and fails
until a time-limited baseline entry lets it through ([soak.md](soak.md#emergency-exceptions)).

## Renovate `minimumReleaseAge`

**What it does.** It "requires Renovate to wait for a specified amount of time before suggesting a dependency
update". Until then the `renovate/stability-days` check is pending, and under the default
`internalChecksFilter=strict` no branch is created. A release without a timestamp counts as too young
(`timestamp-required`, the default). Security updates bypass the wait
([minimum release age](https://docs.renovatebot.com/key-concepts/minimum-release-age/)). `config:best-practices`
extends `security:minimumReleaseAgeNpm`, 3 days for npm
([config presets](https://docs.renovatebot.com/presets-config/),
[security presets](https://docs.renovatebot.com/presets-security/)).

**Overlap and what wormsign adds.** As for Dependabot; `timestamp-required` matches `soak`'s rule that a version it
cannot age fails.

## npm `min-release-age`

**What it does.** With it, "npm will build the npm tree such that only versions that were available more than the
given number of days ago will be installed". `min-release-age-exclude` exempts names or globs
([npm config](https://docs.npmjs.com/cli/v11/using-npm/config#min-release-age)).

**Overlap.** Layer 1 of wormsign's soak design: the same control, at resolution.

**What wormsign adds.** npm 10 accepts the setting and ignores it, and `npm ci` installs a young version already in
the lockfile ([soak.md](soak.md#layer-1-package-manager-release-age-settings)). `soak` gates the lockfile and reports
a missing or ignored setting (WS-SK-003, WS-SK-004). It does not report `min-release-age-exclude` or `before`.

## pnpm `minimumReleaseAge` and `trustPolicy`

**What it does.** `minimumReleaseAge` is in minutes, covers transitive dependencies, was added in v10.16.0 and
defaults to 1440 since v11, when `minimumReleaseAgeStrict` became true for an explicit age.
Install re-applies the age and trust checks to lockfile entries unless `trustLockfile: true` (v11.3.0).
`trustPolicy: no-downgrade` (v10.21.0) fails a package whose trust level has dropped since earlier releases: from
a trusted publisher to provenance only, or to none
([dependency-resolution settings](https://pnpm.io/settings/dependency-resolution)).

**Overlap.** On pnpm 11 or later, with an explicit `minimumReleaseAge`, `trustLockfile` off and
`trustPolicy: no-downgrade`, pnpm does what WS-SK-001 does on every install, and `trustPolicy` covers WS-RG-002's
case and more. Which pnpm versions reject a young locked version, and when, is in
[soak.md](soak.md#layer-1-package-manager-release-age-settings).

**What wormsign adds.** OSV records (an age gate reads no advisory), the install-script and new-publisher signals
(WS-RG-001, WS-RG-003), and the base-built gate. A check that the setting is not undone: `trustLockfile: true`,
`minimumReleaseAgeStrict: false` and excludes are WS-SK-004. `soak` does not read `trustPolicy`.

## Yarn and bun release-age settings

Read 2026-10-02.

**What they do.** Yarn's `npmMinimalAgeGate` sets the minimum age a version needs to be considered for installation
([yarnrc reference](https://yarnpkg.com/configuration/yarnrc#npmMinimalAgeGate)); bun's `[install]
minimumReleaseAge` does the same, in seconds ([bunfig](https://bun.com/docs/runtime/bunfig)).

**Overlap.** The same control as npm's, at resolution.

**What wormsign adds.** Yarn 4.10.3 reads `3d` as 3 minutes, and Yarn and bun install a young version already in the
lockfile ([soak.md](soak.md#layer-1-package-manager-release-age-settings)). `soak` reports a setting that is missing,
too short or ignored (WS-SK-003, WS-SK-004) and gates a Yarn lockfile; a bun lockfile fails closed
([below](#when-not-to-use-wormsign)).

## `npm audit signatures`

**What it does.** It verifies the registry signatures and provenance attestations of packages already installed by
`npm install` or `npm ci` ([verifying registry signatures](https://docs.npmjs.com/verifying-registry-signatures)).
The signature covers `name@version:integrity` and protects against a mirror or proxy that alters packages
([about registry signatures](https://docs.npmjs.com/about-registry-signatures)).

**Overlap.** `soak` checks each locked integrity against the registry's (WS-SK-002 on a mismatch), and reports a
version that dropped the provenance its predecessor had (WS-RG-002). It does not verify signatures.

**What wormsign adds.** It runs before the install. "Packages published to the public npm registry are signed", so
a worm's publish with a stolen token passes a signature check; age, OSV and the publisher signals can catch it.

## StepSecurity Harden-Runner

**What it does.** It monitors network egress, file integrity and processes on GitHub Actions runners, and can limit
egress to an allowlist. The free tier covers public repositories on GitHub-hosted runners; private repositories and
self-hosted runners need Enterprise ([README](https://github.com/step-security/harden-runner)). StepSecurity's
GitHub Checks, Enterprise only, include an npm Package Cooldown pull-request check: 2 days by default, 1 to 30
([GitHub Checks](https://docs.stepsecurity.io/github-checks)).

**Overlap and what wormsign adds.** None for Harden-Runner: it watches what runs, and wormsign reads files before
anything runs, on any runner, with no service. Its runtime view is what wormsign lacks: run both. The cooldown check
overlaps `soak --base`.

## OpenSSF Scorecard

**What it does.** It scores a repository's practices from 0 to 10 per check, including Dangerous-Workflow,
Pinned-Dependencies, Token-Permissions, Branch-Protection and Vulnerabilities, through OSV
([README](https://github.com/ossf/scorecard)). Dangerous-Workflow detects a `pull_request_target` or
`workflow_run` workflow that checks out the pull request, and script injection
([checks](https://github.com/ossf/scorecard/blob/main/docs/checks.md)).

**Overlap.** The untrusted checkout is WS-GH-003.

**What wormsign adds.** Worm IOCs, whole-`secrets` dumps (WS-GH-002), and a gate that fails. Scorecard checks action
pinning, token permissions and branch protection; wormsign does not.

## zizmor

Read 2026-10-15.

**What it does.** 41 static audits of GitHub Actions workflows and actions, 37 of them offline
([audits](https://docs.zizmor.sh/audits/)). `overprovisioned-secrets` reports use of the whole `secrets` context
(its examples: `toJSON(secrets)`). `dangerous-triggers` reports the `pull_request_target`, `workflow_run` and
`issue_comment` triggers themselves, since attacker code can often run under them without a checkout.
`self-hosted-runner` runs only with `--pedantic`.

**Overlap.** WS-GH-002 to WS-GH-004 ([table](#the-workflow-rules-against-zizmor-and-actionlint)).

**What wormsign adds.** IOC workflow and runner names, secrets sent out, discussion triggers with run steps
(`template-injection` already flags the worm's `${{ github.event.discussion.body }}`, an `arbitrary` context in its
[capabilities list](https://github.com/zizmorcore/zizmor/blob/main/crates/zizmor/data/context-capabilities.csv)), and
the base-built gate. zizmor covers what wormsign does not: template injection, unpinned actions, excessive
permissions, `secrets: inherit`, cache poisoning. Run both.

## actionlint

Read 2026-10-15.

**What it does.** Lints workflows: syntax, expression types, `shellcheck` on `run:` scripts, runner labels, script
injection from untrusted inputs ([checks](https://github.com/rhysd/actionlint/blob/main/docs/checks.md)). It reads
YAML anchors, which GitHub accepts and wormsign reports as not checked (WS-SC-900).

**Overlap.** No WS-GH rule, but its untrusted-input check flags the 2025-11 backdoor's `github.event.discussion.body`
([source](https://github.com/rhysd/actionlint/blob/main/expr_insecure.go)). It accepts `self-hosted` as a known label.
Run both.

## The workflow rules against zizmor and actionlint

From the two tools' docs and source; neither was run here (a measured comparison is on the [roadmap](../ROADMAP.md#next)).
"Worm-specific" means neither tool, nor Scorecard, covers the rule.

| Rule | wormsign reports | zizmor | actionlint | Verdict |
|---|---|---|---|---|
| WS-GH-001 | a workflow file named in the IOC list | none | none | worm-specific |
| WS-GH-002 | the whole `secrets` context: `toJSON(secrets)`, `secrets.*`, a computed index | `overprovisioned-secrets`; `secrets.*` and a computed index are not in its docs | none | overlaps |
| WS-GH-003 | a `pull_request_target` or `workflow_run` workflow that checks out pull request code | `dangerous-triggers`, on the trigger alone (broader); also Scorecard's Dangerous-Workflow | none | overlaps |
| WS-GH-004 | a self-hosted runner | `self-hosted-runner`, `--pedantic` only | none | overlaps |
| WS-GH-005 | a secret passed to a command that writes a file or uses the network | none | none | worm-specific |
| WS-GH-006 | a runner name or label from the IOC list | none | none | worm-specific |
| WS-GH-007 | a discussion trigger with run steps | none for the trigger; `template-injection` flags the worm's step | none for the trigger; its untrusted-input check flags the worm's step | worm-specific rule |

Worm-specific does not mean it catches the worms. WS-GH-002 fires on all three wave replays that commit a workflow;
WS-GH-005 misses all three: each binds `toJSON(secrets)` to a variable first, which the rule does not follow (two
also name it on the line after the `>` that writes the file) ([replays](validation.md#3-wave-replays)).

## JFrog Curation

**What it does.** It applies policies to cached Artifactory remote repositories, so packages that violate one are
not retrieved
([connect remote repositories](https://docs.jfrog.com/security/docs/connect-remote-repositories-to-curation)).
Conditions include "Package version is immature", which blocks third-party versions younger than a set number of
days and can allow one that fixes a CVE, and "Malicious package", from JFrog Security Research
([conditions](https://docs.jfrog.com/security/docs/list-of-available-conditions)). npm and PyPI are supported
([supported technologies](https://docs.jfrog.com/security/docs/supported-technologies)).

**Overlap.** An age and malware gate at the proxy, for every client and install through it, resolving installs
included. For packages from a curated repository, `soak`'s age check is redundant.

**What wormsign adds.** No Artifactory, OSV records and registry signals, and checks of the repository itself:
workflows, auto-run files, the pull-request diff. Today `soak` reads an Artifactory registry
only if it serves publish times without credentials ([roadmap](../ROADMAP.md)).

## When not to use wormsign

- **pnpm 11 or later, with [strict settings](#pnpm-minimumreleaseage-and-trustpolicy), everywhere**: keep wormsign
  only for OSV records, the other registry signals, and `diff` and `scan`.
- **Only a private registry.** Every package from one fails closed in `soak` until baselined
  ([private registries](soak.md#private-registries)). Use the mirror's own policy, with `scan` and `diff` given its
  host (`--registry-host`, the Action's `registry-host` input), or they report its lockfile URLs as WS-LK-002.
- **A curated proxy gates every install's age** at least as long as your soak: `soak`'s age check repeats it.
- **Bun projects.** `soak` fails closed on `bun.lock` and `bun.lockb`; it cannot gate them.
- **You need runtime protection.** wormsign reads files. Use a runtime tool such as Harden-Runner.

## What none of these replace

Credential rotation ([incident-response.md](incident-response.md)), trusted publishing
([maintainer-hardening.md](maintainer-hardening.md)) and branch protection with required review
([github-action.md](github-action.md#what-the-gate-does-not-stop)).
