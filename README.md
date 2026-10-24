# wormsign

wormsign is supply-chain security tooling for agent-driven development. It provides a **typed offline scanning
library** and CLI gates for npm and PyPI, built against
[Shai-Hulud-style worms](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem).
It has no npm runtime dependencies; one pinned, hash-verified TOML parser is vendored
([third-party notices](THIRD_PARTY_NOTICES.md)).

The **soak gate** rejects locked versions younger than 7 days, versions OSV lists as malware, and inputs it cannot
verify. Offline scans find known indicators, suspicious install scripts, workflow changes and agent persistence.
A GitHub Action, hardening script and experimental SIEM detections provide additional integration paths
([maturity and limits](docs/stability.md#maturity)).

Automatic enforcement in a **shared sandbox for multiple coding agents** is a separate, experimental development
milestone. This library release does not provide a protected execution environment. See the
[roadmap](ROADMAP.md) and [release readiness](docs/release-readiness.md).

## Use from an agent integration

After [building and installing a local tarball](docs/library.md#install-from-the-local-release-candidate):

```ts
import { scan, gateExitCode } from "wormsign";

const result = scan("/path/to/project");
process.exitCode = gateExitCode(result.findings);
```

The API reads files without network access or package execution, uses the installed release's IOC data, and does
not apply repository-controlled baselines. Findings and exit zero are observations, not installation permission.
[API reference and examples](docs/library.md) · [Design decisions](docs/design.md) ·
[Validation evidence](docs/validation.md).

## How it answers a Shai-Hulud worm

A Shai-Hulud worm spreads through the registry. With a stolen maintainer token it publishes new versions of that
maintainer's packages (up to 100 per token in November 2025), each with an install script that runs the payload.
Anyone who installs one before it is reported and removed runs it, and the payload uses their tokens to do the same
again.

Prevention is concentrated at that first step. A worm version does its harm before it is reported. Across five
waves (3,547 versions) the slowest was reported 77.4 hours after publish (three method artefacts corrected), so
`soak` fails any locked version younger than 7 days ([why](docs/soak.md#why-7-days-and-when-72-hours-is-enough)).
Past that step wormsign mostly detects ([threat model](docs/threat-model.md)).

| Step | The worm | wormsign | Misses |
|---|---|---|---|
| 1. Install | A new version's install script runs the payload; in May 2026 also a git dependency's `prepare` | `soak` fails versions under 7 days, ones OSV lists as malware, and what it cannot verify, such as a git source; `harden-dev.sh` checks install scripts and cooldowns (`--apply` sets both for npm, pnpm 11 and Yarn 4.10+, and pip's cooldown); `diff` reports a new dependency with an install script | an old enough unreported version; without `soak`, a git dependency's `prepare`; installs outside the lock |
| 2. Harvest | Collects npm and GitHub tokens and cloud credentials, with TruffleHog (2025) | `harden-dev.sh` reports plaintext and over-scoped tokens and credential files | anything read at run time |
| 3. Exfiltrate | Sends them to webhooks and to public GitHub repositories | `scan`: known endpoints; `audit-org`: the worm's repositories | it blocks no traffic; unlisted endpoints |
| 4. Persist | Plants workflows that send out CI secrets or take commands on a self-hosted runner, and VS Code tasks and Claude Code hooks that run it again | `diff` reports new editor and agent hooks, and workflow changes (medium, for code-owner review); `scan` and `audit-org` find what landed | a push with a stolen token skips `diff`; runners on a host; deleted branches |
| 5. Spread | Republishes the victim's packages the same way | other projects' `soak` waits out the 7 days and checks OSV; registry signals | a publish through the package's own release workflow |
| 6. Expose | Makes private repositories public | `audit-org`; detection WS-AL-001 | needs GitHub Enterprise Cloud's audit log |
| 7. Wipe | Deletes the home folder: with no usable token (November 2025), or when its watched token is revoked (May 2026) | `harden-dev.sh` finds the May 2026 watcher; the [incident-response guide](docs/incident-response.md) isolates the machine before any token is revoked | the wipe itself, once step 1 has run |

- **Coding agents:** the [agent skill](docs/skills.md) gives Claude Code, Codex and Cursor the same install rules:
  lockfile installs, scripts off, exact versions at least 7 days old (guidance, not enforcement).
- **Detections:** [SIEM rules](detections/README.md) (experimental) watch for the worm's loaders, Bun, TruffleHog,
  runners, workflow runs, secret dumps, repositories and visibility flips.
- **Private registries:** `scan` and `diff` take a `registry-host`; `soak` fails closed behind a mirror until
  [ADR 0007](docs/adr/0007-private-registry-mirrors.md) is built.
- **PyPI is partial:** `soak` protects only exact-lock installs, such as `uv sync --locked`
  ([covered installs](docs/soak.md#which-installs-the-gate-covers)). Build requirements and `.pth` files go
  unchecked; Poetry, PDM and pipenv locks fail closed ([limits](docs/soak.md#python-limitations)).

Every inert wave replay (a regression test, not a measurement) fails the recommended gate
([replays](docs/validation.md#3-wave-replays)). With no baseline, 8 of 15 popular repositories fail `scan`'s default
gate, all on accurate, harmless findings ([noise](docs/evidence/false-positives.md)). The rest is
[out of scope](docs/threat-model.md#out-of-scope).

## Quickstart

Node.js 22 or later; npm enforces a release age from 11.10 (bundled from Node 24.14.1). Until the first release, build
from source ([installation](docs/installation.md)):

```sh
git clone https://github.com/stgllghr/wormsign.git && cd wormsign
npm ci --ignore-scripts && npm run build
npm link                                    # agents need wormsign on PATH
./harden-dev.sh                             # check your workstation; changes no settings
cd /path/to/your/project
wormsign soak .                             # before npm ci: young or OSV-listed versions
wormsign scan .                             # package.json scripts, IOC versions, workflows, payload files
wormsign skills install                     # optional: agent skill
```

- **Network:** `scan` and `diff` use none; `soak` asks the registry, Python index and OSV, downloading nothing;
  [`harden-dev.sh`](docs/hardening.md) uses it only for `gh auth status`, which `--offline` skips.
- **A first `soak` often fails** on benign versions under 7 days: wait, pin an older one, or baseline it until it
  soaks (`baseline add --expires`, [exceptions](docs/soak.md#emergency-exceptions)).
- **A tree you did not write:** add `--no-baseline`; its baseline could hide findings.
- **Exit codes:** `0` below `--fail-on` (default `high`), `1` at or above it, `2` an error, or an incomplete
  `audit-org` audit that otherwise passes ([output](docs/output.md#exit-codes)).

### Gate pull requests in CI

Run it after `actions/checkout` (`fetch-depth: 0`) and `actions/setup-node` (Node 24, `check-latest: true`). On a
pull request it runs `diff`, `scan` and `soak`, each with the base commit's baseline, and fails on the worst. A
private repository skips the SARIF upload by default
([recommended gate](docs/github-action.md#recommended-pull-request-gate)).

```yaml
    permissions:
      contents: read
      security-events: write  # upload SARIF to code scanning
    steps:
      - uses: stgllghr/wormsign@<release commit sha> # vX.Y.Z: diff, scan and soak on pull requests, scan on push
```

- **Install dependencies only after the gate** (later in its job, or a job that `needs:` it): a job beside it
  installs a malicious version before the gate fails.
- **Make the gate job the required check:** a job that `needs:` a failed gate is skipped, and a skipped job passes a
  required check. A pull request can still edit the gate's workflow
  ([limits](docs/github-action.md#what-the-gate-does-not-stop)).
- **Pin a release commit SHA** after [checking its tag](docs/installation.md#check-a-release-tag-yourself); before
  the first release, [run from source](docs/github-action.md#running-from-source-before-a-release).

## Documentation

[Docs index](docs/README.md) · [rules](docs/rules.md) · [FAQ](docs/faq.md) · [roadmap](ROADMAP.md)

**Status:** 0.1.0, unreleased ([release status](docs/installation.md#release-status)).
[MIT](LICENSE); IOC data Apache-2.0, TOML parser BSD-3-Clause ([notices](THIRD_PARTY_NOTICES.md)).
