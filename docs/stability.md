# Stability in 0.x

What you can build on before 1.0, what a minor release may change, and how changes are announced. wormsign is at
0.1.0, not yet tagged ([release status](installation.md#release-status)).

## The rule

- **Patch releases (0.1.x)** fix bugs and close bypasses. They do not rename or remove a rule ID, CLI flag, Action
  input or output, or exit code.
- **A patch release may add findings**: a closed bypass can fail a gate that passed. The CHANGELOG names the rules.
- **Minor releases (0.x.0)** may change the surfaces below, by the process in [How a change is made](#how-a-change-is-made).
- **1.0** will hold these surfaces to semantic versioning.

## Surfaces

| Surface | Defined in | Stable through 0.x | May change in a minor release |
|---|---|---|---|
| Rule IDs | [`src/rules.ts`](../src/rules.ts), [rules.md](rules.md) | An ID keeps its meaning and is never reused. | New rules; a severity; a rule retired, its ID reserved. |
| Fingerprints | [`src/types.ts`](../src/types.ts) | The formula: the first 32 hex characters of `sha256(ruleId \0 file \0 key)`. | A rule's key, which changes its fingerprints ([below](#fingerprints-and-baseline-keys)). |
| Baseline file | [`src/baseline.ts`](../src/baseline.ts), [baseline.md](baseline.md) | `version: 1`: its fields and their rules. | A new version, beside version 1. |
| Exit codes | [output.md](output.md#exit-codes) | `0` below `--fail-on`, `1` at or above, `2` usage or internal error (`audit-org`: also an incomplete audit or an unreadable repository list). | Nothing planned. |
| CLI flags | `COMMANDS` in [`src/main.ts`](../src/main.ts) | Each flag's name and meaning; `--fail-on high` and `--on-outage fail` as the defaults. | New flags; a rename or removal after deprecation. |
| Action inputs and outputs | [`action.yml`](../action.yml), [github-action.md](github-action.md#inputs) | Each input's name, meaning and default; the outputs `sarif`, `exit-code`, `findings`. An empty `command` on `pull_request` runs `diff`, `scan` and `soak`, with the worst exit code, the summed findings and one SARIF file holding a run per command. | New inputs; a rename, removal or default change after deprecation. |
| SARIF | [`src/sarif.ts`](../src/sarif.ts), [output.md](output.md#sarif) | SARIF 2.1.0, one run (the Action's pull-request gate: one per command, `automationDetails.id` `wormsign-<command>/`), driver name `wormsign`, every rule listed, `partialFingerprints["wormsign/v1"]` equal to the fingerprint, `properties.severity`, the `security-severity` mapping. | Message, description and help text. |
| JSON report | [output.md](output.md#json) | The documented fields. | New fields only; there is no schema version field. |
| Library API | [library.md](library.md), `src/index.ts` | Documented named exports, option meanings and result fields. | New exports or fields; removal or renamed options after deprecation. |
| Agent skill | [`plugins/wormsign/skills/wormsign/`](../plugins/wormsign/skills/wormsign/) | The skill name `wormsign`; the folders `wormsign skills` writes ([cli/skills.md](cli/skills.md#where-it-writes)); the manifest `.wormsign-skill.json`; the plugin `wormsign@wormsign`. | The skill's text, in any release. |

Not stable: human output, notes and message text (do not parse them), JSON field order, `harden-dev.sh`'s output and
the IOC data. Only the root package exports documented in [library.md](library.md) are public library API.
Implementation modules are internal, including any declarations present under `dist/src`.

## Maturity

Each part carries a label for what its evidence supports ([ADR 0009](adr/0009-scope-of-0-1-0.md)). The rule above
holds for every labelled surface; the label says how far to rely on behaviour the tests cannot show.

- **Stable:** checked beyond its own tests, against real data: wave replays, live registry controls, a measured
  study or the false-positive corpus.
- **Beta:** unit tests and mutants (some hand-applied, the script's run pending), run for real a few times at most;
  not yet checked on real data where it runs.
- **Experimental:** not validated against real data; may change or be removed in any minor release.

| Part | Label | Evidence |
|---|---|---|
| `soak` (npm and PyPI) | Stable | live controls on [npm](evidence/soak-live.md) and [PyPI](evidence/soak-py-live.md), replays, the [latency study](evidence/soak-latency.md); [false positives](evidence/false-positives.md), Python only |
| `diff`, `scan` | Stable | replays; for `scan` also the [false-positive corpus](evidence/false-positives.md), which did not run `diff` |
| TypeScript/JavaScript library | Beta | Same scanner; external ESM and strict TypeScript consumer controls, with offline tarball smoke verification |
| `soak --on-outage warn` | Beta | local servers only |
| GitHub Action | Beta | the local harness; GitHub's runners only in the private development repository, before the pre-public fixes ([test-runs.md](evidence/test-runs.md#before-publication)) |
| `baseline add` | Beta | tests only |
| `update-iocs` | Beta | tests and a local https server; never its default source, private until publication |
| `audit-org` | Beta | a fake GitHub only |
| `harden-dev.sh` | Beta | stub package managers; real pip and uv once ([2026-10-08](evidence/package-managers.md)); the Quickstart on macOS |
| Agent skill and `wormsign skills` | Beta | [Claude Code runs and a control](evidence/skill-eval.md); Codex and Cursor format checks only |
| SIEM detections (`detections/`) | Experimental | synthetic events only ([what is not validated](../detections/README.md#what-is-not-validated)) |

A part moves up a label when its evidence does, with a CHANGELOG entry.

## Fingerprints and baseline keys

The fingerprint carries no version tag. Two key digests do: `wormsign-pypi-identity-1`, a Python package's identity
([`src/python/identity.ts`](../src/python/identity.ts)), and `wormsign-pypi-build-4`, a local build
([`src/python/build.ts`](../src/python/build.ts)); a change to what either covers bumps its tag. Every other key
([baseline.md](baseline.md#when-a-fingerprint-changes)) is untagged. So:

- **A key change cannot be phased in.** There is one fingerprint per finding, so an entry for the old key matches
  nothing after the upgrade: the finding fails again, and `scan` notes the entry.
- **It must fail closed.** An old entry must never approve something new; for an untagged key, the new form may not
  spell an old key for other content.
- **It is announced.** The CHANGELOG names every rule whose fingerprints change; re-review those findings.

## How a change is made

- **Every change to a surface above has a [CHANGELOG](../CHANGELOG.md) entry**, under Added, Changed, Deprecated or
  Removed ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/)).
- **Deprecation lasts at least one minor release.** A flag, Action input or output deprecated in 0.N works in every
  0.N.x and 0.(N+1).x release, and can be removed in 0.(N+2).0 at the earliest.
- **Fingerprint changes have no deprecation period**, for the reason above. They ship in a minor release, or in a
  patch release only to close a bypass.
