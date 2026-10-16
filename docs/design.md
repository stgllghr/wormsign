# Design

wormsign keeps a malicious npm or PyPI version from being installed, and finds the traces when one was. This page
is the one-page overview. Each key decision has a record in [adr/](adr/README.md); the code layout is in
[architecture.md](architecture.md).

## Problem

The Shai-Hulud worms run from a package's install script. They steal npm, GitHub and cloud credentials, then use
the stolen npm token to republish every package the victim maintains. Five waves have run since September 2025
([threat model](threat-model.md)).

Two facts shape the defence:

- **Worm versions are found fast.** Across five waves, the slowest public malware advisory came 77.4 hours after
  publish, three method artefacts corrected ([evidence](evidence/soak-latency.md#anomalies)). Waiting is a control.
- **The usual waits have gaps.** npm 10 accepts `min-release-age` and ignores it. npm, Yarn, bun and pnpm 10
  install a young version that is already in the lockfile. No package-manager cooldown reads an advisory
  ([soak.md](soak.md#layer-1-package-manager-release-age-settings)).

## Users

- **Developers.** They run `harden-dev.sh` to set cooldowns and turn install scripts off, run `wormsign soak`
  before `npm ci`, and give their coding agent the skill.
- **CI owners.** They make the Action a required pull-request gate, review baseline changes, run `audit-org` on the
  organization, and load `detections/` into their SIEM.

## Goals

1. No locked version installs before it has soaked, or while OSV lists it as malicious.
2. A pull request cannot weaken the checks that judge it.
3. What cannot be verified fails, so silence from a verification step never means clean: `soak`'s age, identity
   and OSV checks, and any input a check cannot read ([ADR 0001](adr/0001-fail-closed.md)). The pattern checks
   (workflows, the detections) are best-effort, with documented misses
   ([workflows.ts](../src/checks/workflows.ts), [detections](../detections/README.md#what-is-not-validated)).
4. A reviewer can audit the whole tool from the repository: no runtime dependencies, sourced IOC data,
   deterministic output.
5. It fits what teams run: SARIF for code scanning, plain exit codes, a baseline with a justification per entry.

## Non-goals

- Runtime protection. No agent, egress filter or EDR.
- Reading package code for behaviour.
- General vulnerability scanning.
- A registry proxy or a hosted service.
- Predicting what an installer would resolve.

[positioning.md](positioning.md) names tools that cover the first four.

## Architecture

The pull-request gate, as this repository runs it ([wormsign.yml](../.github/workflows/wormsign.yml)). An adopter's
gate is one Action call that runs the same three commands, pinned to a release commit SHA in place of `gate/`:

```
  base commit                                       pull request (merge commit)
      |                                                       |
      v                                                       v
  gate/: CLI built from base,                         pr/: the change, read as data;
  IOC data, Action, baseline                          never installed, built or run
      |                                                       |
      +---------------------------+---------------------------+
                                  |
                                  v
  +----------------------------------------------------------------------+
  | diff  base..merge   offline   what the change adds: install scripts, |
  |                               workflows, config, baseline, auto-run  |
  | soak  --base        network   npm and Python entries the change      |---> registry.npmjs.org,
  |                               adds or changes: age, identity, OSV;   |     pypi.org/simple/,
  |                               npm registry signals; each Python      |     api.osv.dev
  |                               file bound by its sha256               |
  | scan  pr/           offline   IOCs, workflows, payloads, endpoints   |
  +----------------------------------------------------------------------+
                                  |  each step: SARIF + exit code (continue-on-error)
                                  v
                Gate step: fails if any check failed  ==>  required status check
                                  |
                                  v  needs: gate
                Jobs that install the change's dependencies
```

Around the gate:

| Component | Where it runs | Network |
|---|---|---|
| `harden-dev.sh` | developer machine: cooldowns, install scripts, tokens, payload and watcher files | none, except `gh auth status` |
| `soak` | before `npm ci` on a machine, or in the gate | npm registry, PyPI index, api.osv.dev |
| Agent skill | Claude Code, Codex, Cursor: guidance only | none to install |
| `audit-org` | a GitHub organization, read-only | api.github.com, `GET` only |
| `detections/` | your SIEM; wormsign does not run them; experimental ([maturity](stability.md#maturity)), never run on real logs or in a SIEM ([roadmap](../ROADMAP.md#next)) | n/a |
| `update-iocs` | refreshes the IOC cache, which can only add | one https URL |

`scan` and `diff` never use the network. There is no telemetry.

## Key decisions

1. **Fail closed.** An unreadable file, an unverifiable package or a failed OSV lookup is a finding, never a note: high,
   but for the medium cases [ADR 0001](adr/0001-fail-closed.md) lists, among them the opt-in `--on-outage warn` for a
   host unreachable for the whole run.
2. **Build the gate from the base.** The change cannot supply the gate's code or its baseline.
   ([ADR 0002](adr/0002-pr-gate-built-from-base.md))
3. **Soak 7 days by default.** 72 hours is a tuned value for a CI gate with OSV on.
   ([ADR 0003](adr/0003-seven-day-default-soak.md))
4. **Never imitate an installer's parser.** Where only pip, uv or npm can answer, wormsign states the boundary
   instead of modelling it. ([ADR 0004](adr/0004-no-installer-parser-imitation.md))
5. **No runtime dependencies.** One TOML parser is vendored, pinned and hash-checked at every build.
   ([ADR 0005](adr/0005-no-runtime-dependencies.md))
6. **The agent skill is guidance.** It blocks nothing and installs with no network access; the gate and the
   package-manager settings enforce. ([ADR 0006](adr/0006-skill-is-guidance.md))

## Out of scope, and why

- **Payloads that run on import, and malware without install scripts.** No rule reads package code. `soak` and OSV
  still apply, because they do not depend on how the payload runs.
- **A quiet single-package compromise older than the soak.** A soak works only if someone notices in time.
- **A compromised registry, OSV, runner or wormsign release.** Their answers are trusted as served. Mitigations:
  release tags are rebuilt and compared byte for byte, and the Action is pinned by SHA.
- **Third-party action pinning, typosquats and dependency confusion.** Other controls cover them; wormsign
  gives a new name the same age and OSV checks as any other.
- **Private registries in `soak`.** It checks one registry without credentials, so private packages fail closed.
  [ADR 0007](adr/0007-private-registry-mirrors.md) accepts a mirror mode, not yet built.
- **Bun lockfiles; Poetry, PDM and Pipfile locks; Windows workstations.** Not parsed or not tested. `soak` fails
  closed on those locks.

The full list: [threat-model.md](threat-model.md#out-of-scope).
