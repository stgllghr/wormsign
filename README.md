# wormsign

wormsign keeps a malicious npm or PyPI version from being installed, and finds an npm worm's traces when one was.
Built against the [Shai-Hulud worms](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem),
it is a TypeScript CLI with no npm runtime dependencies, a GitHub Action, a hardening script and SIEM detections
(experimental; [each part's maturity](docs/stability.md#maturity)), centred on a **soak gate** that fails on a locked
version younger than 7 days, one OSV lists as malware, and anything it cannot verify.

## How it stops a Shai-Hulud worm

A Shai-Hulud worm spreads through the registry itself. With a stolen maintainer token it publishes a new version of
every package that token can write, with an install script that runs the payload. Anyone who installs one in the
next hours runs it. The payload then:

- harvests npm, GitHub and cloud tokens;
- sends them out through webhooks and public GitHub repositories;
- plants workflows, self-hosted runners, and editor and agent hooks that run it again;
- republishes the victim's own packages, which is how it spreads;
- in later waves, makes private repositories public, or wipes the home folder.

wormsign breaks that loop at each step ([threat model](docs/threat-model.md)):

- **Don't install it.** Worm versions are reported quickly: across five waves (3,547 versions), the slowest public
  malware advisory came 77.4 hours after publish, so 7 days leaves a margin
  ([why](docs/soak.md#why-7-days-and-when-72-hours-is-enough)). `soak` fails any locked npm or PyPI version younger
  than 7 days, any version OSV lists as malware, and anything it cannot verify, such as a git dependency.
  `harden-dev.sh` checks install scripts and each package manager's own release-age cooldown, and `--apply` sets them
  for npm, pnpm, Yarn and pip.
- **Stop the change that brings it in.** On a pull request, `diff` reports a new dependency with an install script, a
  changed lifecycle script or workflow, a new editor task or agent hook that runs commands, and a change to the
  install settings or baseline. The gate runs from the base commit, so a pull request cannot switch off its own checks.
- **Find it if it got in.** `scan` looks for known worm versions, payload files by hash, exfiltration endpoints, the
  worm's workflows (secret dumps, discussion-triggered self-hosted runners) and its editor and agent hooks.
  `audit-org` checks a GitHub organization for the worm's repositories, runners, workflows and visibility flips.
- **Leave less to steal.** `harden-dev.sh` reports plaintext and over-scoped tokens and credential files, and the
  May 2026 wave's watcher that wipes the home folder when its token is revoked.
- **Respond without setting off the wiper.** The [incident-response guide](docs/incident-response.md) isolates the
  machine before any token is revoked; the [SIEM detections](detections/README.md) (experimental) watch the GitHub
  audit log, CI logs and endpoints for the worm spreading.
- **Same rules for coding agents.** The [agent skill](docs/skills.md) gives Claude Code, Codex and Cursor the same
  install rules: lockfile installs, scripts off, exact versions at least 7 days old.

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

## What it catches and misses

| Stage | Catches | Misses |
|---|---|---|
| 1. Install script runs the payload | `soak`: young, OSV-listed, git-sourced versions; `harden-dev.sh`: scripts off | an old enough unreported version; without `soak`, a git dependency's `prepare` script; installs outside the lock |
| 2. Secrets harvested | `harden-dev.sh`: plaintext and over-scoped tokens, credential files | anything at run time |
| 3. Exfiltration | `scan`: IOC and webhook endpoints | it blocks no traffic; unlisted endpoints |
| 4. Persistence: workflows, runners, hooks | `diff`: high-risk workflow and auto-run changes; `scan`: what landed | a push with a stolen token |
| 5. Republish with the stolen token | `soak`: registry signals and OSV | a publish through the package's release workflow |
| 6. Private repositories made public | `audit-org`; detection WS-AL-001 | needs GitHub Enterprise Cloud's audit log |
| Private registry | `scan`, `diff`: `registry-host` input | `soak` fails closed ([ADR 0007](docs/adr/0007-private-registry-mirrors.md), not yet built) |

The rest is [out of scope](docs/threat-model.md#out-of-scope).

The 77.4 hours corrects three method artefacts. Every inert wave replay (a regression test, not a measurement) fails
the recommended gate
([replays](docs/validation.md#3-wave-replays)). With no baseline, 8 of 15 popular repositories fail `scan`'s
default gate, all on accurate, harmless findings ([noise](docs/evidence/false-positives.md)).

PyPI support is partial: `soak` protects only exact-lock installs, such as `uv sync --locked`
([covered installs](docs/soak.md#which-installs-the-gate-covers)). Build requirements and `.pth` files go
unchecked; Poetry, PDM and pipenv locks fail closed ([limits](docs/soak.md#python-limitations)).

## Documentation

[Docs index](docs/README.md) · [rules](docs/rules.md) · [FAQ](docs/faq.md) · [roadmap](ROADMAP.md)

**Status:** 0.1.0, unreleased ([release status](docs/installation.md#release-status)).
[MIT](LICENSE); IOC data Apache-2.0, TOML parser BSD-3-Clause ([notices](THIRD_PARTY_NOTICES.md)).
