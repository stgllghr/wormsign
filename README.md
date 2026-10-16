# wormsign

wormsign keeps a malicious npm or PyPI version from being installed, and finds an npm worm's traces when one was.
Built against the [Shai-Hulud worms](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem),
it is a TypeScript CLI with no npm runtime dependencies, a GitHub Action, a hardening script and SIEM detections
(experimental; [each part's maturity](docs/stability.md#maturity)), centred on a **soak gate** that fails on a locked
version younger than 7 days, one OSV lists as malware, and anything it cannot verify.

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

Across five waves (3,547 versions), the slowest malware advisory came 77.4 hours after publish, three method artefacts
corrected: 7 days leaves a margin ([why](docs/soak.md#why-7-days-and-when-72-hours-is-enough)). Every inert wave
replay (a regression test, not a measurement) fails the recommended gate
([replays](docs/validation.md#3-wave-replays)). With no baseline, 8 of 15 popular repositories fail `scan`'s
default gate, all on accurate, harmless findings ([noise](docs/evidence/false-positives.md)).

PyPI support is partial: `soak` protects only exact-lock installs, such as `uv sync --locked`
([covered installs](docs/soak.md#which-installs-the-gate-covers)). Build requirements and `.pth` files go
unchecked; Poetry, PDM and pipenv locks fail closed ([limits](docs/soak.md#python-limitations)).

## Documentation

[Docs index](docs/README.md) · [rules](docs/rules.md) · [FAQ](docs/faq.md) · [roadmap](ROADMAP.md)

**Status:** 0.1.0, unreleased ([release status](docs/installation.md#release-status)).
[MIT](LICENSE); IOC data Apache-2.0, TOML parser BSD-3-Clause ([notices](THIRD_PARTY_NOTICES.md)).
