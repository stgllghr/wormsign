# ADR 0003: A 7-day default soak, with 72 hours as the tuned CI value

- **Status:** Accepted (0.1.0)
- **Date:** 2026-10-14

## Context

A soak delays a version until someone has had time to report it. A package manager's cooldown checks age and
nothing else: once it has passed, the version installs unless the registry has removed it.

The [latency study](../evidence/soak-latency.md) (run 2026-10-09) timed every compromised version in the bundled
IOC data, 3,547 measured across five waves, from publish to the first public malware advisory that listed it:

- The slowest advisory came 77.4 hours after publish (the 2026-08 wave), with three May 2026 method artefacts
  corrected.
- A 48-hour soak would have missed 68 versions (1.9%).
- The registry proves removal within 72 hours for only 49.2% of versions.
- Of the 3,530 versions first listed in OSV, its importer recorded 3,525 (99.9%) within 72 hours; the slowest, the
  three method artefacts aside, at 130.6 hours.

## Decision

The default soak is **7 days** everywhere: `soak --min-age`, the Action's `min-age`, and `harden-dev.sh --soak`.

**72 hours** is a documented tuned value for one place: the lockfile gate in CI, with the OSV check on.

- On a developer machine, the cooldown is the only age control and it reads no advisory. What protects is removal,
  proven within 72 hours for half the versions. 7 days is about 2.2 times the slowest advisory.
- In CI, `soak` also asks OSV, so a version that is past 72 hours and listed still fails. The price: the two
  `@ornikar` versions imported into OSV at 130.6 hours would pass a 72-hour gate. With `--no-osv`, keep 7 days.

The argument in full: [soak.md](../soak.md#why-7-days-and-when-72-hours-is-enough).

## Consequences

- A legitimate release, bug fixes included, waits a week. A security fix goes through a time-limited baseline
  entry; OSV and the registry signals still apply to it ([soak.md](../soak.md#emergency-exceptions)).
- Dependabot and Renovate must wait at least as long, or their pull requests fail the gate. Dependabot's default
  is 3 days, and so is Renovate's `config:best-practices` value for npm ([positioning.md](../positioning.md)).
- Five waves of one npm worm family is a small sample. 7 days is a margin over what was seen, not a bound on the
  next wave.
- The same default applies to PyPI locks without PyPI evidence.
- A quiet compromise that nobody reports within the soak passes.

## Alternatives considered

- **72 hours as the default.** Rejected: developer machines run no OSV check, and removal within 72 hours is proven
  for only 49.2% of versions.
- **3 days**, the Dependabot default and Renovate's `security:minimumReleaseAgeNpm`. Rejected for the same reason.
- **1 or 2 days.** Rejected: 48 hours misses 1.9% of measured versions, 66 of them from the September 2025 wave.
- **14 days or more.** Rejected as a default: it doubles the wait, and no measured version needed it. Projects that
  can wait longer raise `--min-age`.
