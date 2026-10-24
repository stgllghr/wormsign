# wormsign documentation

Start with the [README](../README.md).

## Start by task

| I want to… | Read |
|---|---|
| protect my laptop | [hardening.md](hardening.md) |
| check a lockfile before installing | [soak.md](soak.md) |
| gate pull requests | [github-action.md](github-action.md#recommended-pull-request-gate) |
| integrate checks into an agent or Node application | [library.md](library.md) |
| accept a reviewed finding | [baseline.md](baseline.md) |
| respond to an indicator I found | [incident-response.md](incident-response.md) |
| know why it is built this way | [design.md](design.md) |

## All pages

**Getting started**

- [installation.md](installation.md): install from source or a release, and verify it.
- [library.md](library.md): public TypeScript/JavaScript API, examples and integration limits.
- [release-readiness.md](release-readiness.md): release scope, completed checks and remaining gates.
- [github-action.md](github-action.md): the Action, its inputs and the pull-request gate.
- [faq.md](faq.md): short answers that link to the detail.
- [troubleshooting.md](troubleshooting.md): error messages, causes and fixes.

**Commands**

- [cli/scan.md](cli/scan.md): the offline project scan.
- [cli/diff.md](cli/diff.md): what a change adds between two revisions.
- [cli/soak.md](cli/soak.md): the soak gate for npm and Python locks.
- [cli/audit-org.md](cli/audit-org.md): the read-only GitHub organization audit.
- [cli/update-iocs.md](cli/update-iocs.md): refreshing the local IOC cache.
- [cli/baseline.md](cli/baseline.md): recording reviewed findings, each with a reason.
- [cli/skills.md](cli/skills.md): installing, checking and removing the agent skill.

**Results**

- [output.md](output.md): human, JSON and SARIF output; exit codes.
- [baseline.md](baseline.md): the baseline file and fingerprints.
- [rules.md](rules.md): every rule, what it means and the fix.

**Concepts**

- [soak.md](soak.md): why a soak time works, and how to enforce one.
- [threat-model.md](threat-model.md): the kill chain, and what each part prevents, detects and misses.
- [design.md](design.md): the one-page overview.
- [adr/](adr/README.md): decision records, with the alternatives rejected.
- [architecture.md](architecture.md): the code layout and mechanics.
- [iocs.md](iocs.md): the IOC data and its provenance.
- [positioning.md](positioning.md): wormsign next to other tools; when not to use it.
- [stability.md](stability.md): what an adopter can rely on in 0.x.

**Respond and harden**

- [hardening.md](hardening.md): the `harden-dev.sh` checks, and what `--apply` writes.
- [incident-response.md](incident-response.md): what to do when wormsign reports an indicator.
- [maintainer-hardening.md](maintainer-hardening.md): protecting the packages you publish.
- [skills.md](skills.md): the agent skill for Claude Code, Codex and Cursor.
- [../detections/README.md](../detections/README.md): SIEM detections and how to deploy them.

**How we know it works**

- [validation.md](validation.md): rule coverage, IOC recall, wave replays, mutation check.
- [evidence/soak-latency.md](evidence/soak-latency.md): how long worm versions stayed installable.
- [evidence/soak-live.md](evidence/soak-live.md): the soak gate against the live npm registry.
- [evidence/soak-py-live.md](evidence/soak-py-live.md): the soak gate against PyPI and OSV.
- [evidence/false-positives.md](evidence/false-positives.md): `scan` over 15 popular repositories, every finding classified.
- [evidence/skill-eval.md](evidence/skill-eval.md): the agent skill in headless Claude Code.
- [evidence/package-managers.md](evidence/package-managers.md): package-manager settings, as verified.
- [evidence/test-runs.md](evidence/test-runs.md): test-suite, mutation and pre-publication runs.
- [evidence/pypi-incidents.md](evidence/pypi-incidents.md): the PyPI incidents the design drew on.

**Project**

- [CONTRIBUTING.md](../CONTRIBUTING.md): setup, principles, adding IOCs and rules.
- [SECURITY.md](../SECURITY.md): reporting a vulnerability privately.
- [CHANGELOG.md](../CHANGELOG.md): changes by release.
- [ROADMAP.md](../ROADMAP.md): what comes next.
- [LICENSE](../LICENSE): MIT.
- [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md): third-party attribution.
- [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md): expected behaviour.
