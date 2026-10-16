# ADR 0007: Private registry mirrors for `soak`

- **Status:** Accepted, not yet built ([ROADMAP](../../ROADMAP.md#next) item 1).
- **Date:** 2026-10-15

## Context

`soak` asks one npm registry and one Python index, sends no credentials, and fails closed (WS-SK-002) when an
install could use another, so a private name reaches a public service only through a registry set where `soak`
cannot see it ([soak.md](../soak.md#private-registries)). Behind Artifactory or Nexus every
lockfile entry resolves from the mirror, so every package fails closed, and OSV is not asked about them
([positioning.md](../positioning.md#when-not-to-use-wormsign), [soak.md](../soak.md#private-registries)).

Per locked version, `soak` needs a publish time, the registry's hash to compare with the lock's, and OSV records.

## Decision

The witness is configurable: **public** (the default) or **mirror**.

Under either witness the adopter names the mirror, classifies every npm scope in the lockfile as public or private,
and lists private single names.

**Public witness.** For every locked version that is not private, `soak` asks registry.npmjs.org or pypi.org, and
OSV, by name and version, and requires the lock's hash to equal the public one. A match shows the mirror served the
public artifact; installs keep the mirror's URLs.

- **Private names** are sent nowhere. Each locked version is a medium finding, "unverified: private": below the
  default gate, in every report and in SARIF. It is the adopter's declaration, as `--on-outage warn` is, never a
  heuristic.
- **An npm scope in the lockfile that is classified neither public nor private stops the run** (exit 2, naming the
  scopes), under either witness, so a forgotten internal scope is never sent to npm or OSV and never passes
  unchecked. Unscoped names
  count as public; a private unscoped name must be listed.
- **An entry whose lock records no registry hash**, such as every Yarn 2+ entry
  ([`src/lockfile/yarn.ts`](../../src/lockfile/yarn.ts)), fails closed (WS-SK-002, high): the mirror's artifact
  cannot be matched to the public one.

**Mirror witness** (opt-in). `soak` reads the mirror's own metadata.

- npm needs the full package document with its `time` field, PyPI the JSON Simple API's `upload-time`. A document
  without them fails closed (WS-SK-002). Artifactory serves `upload-time` from 7.132.x with "Simple JSON Format" on
  ([JFrog](https://jfrog.com/help/r/artifactory-how-to-support-upload-date-based-package-filtering-for-uv-and-pip-artifactory-7-132-x));
  Nexus supports PEP 691 from 3.93 and PEP 700 from 3.94 ([Sonatype](https://help.sonatype.com/en/pypi-repositories.html)).
  Whether a proxy keeps npm's `time`, and whether a proxied file's time is upstream's or the cache's, neither vendor
  says (unverified): the docs will say so per vendor until a live check shows it.
- The token is read-only, comes from an environment variable an input names (never a flag or a URL), goes only to
  the configured host over https, never across a redirect to another origin, and is never logged or written to a
  report.
- OSV is still asked only about public names, with the same classification and the same stop on an unclassified
  scope, or is skipped (WS-OS-900).

The OSV endpoint becomes configurable, for an internal OSV mirror.

## Consequences

- Public witness trusts what `soak` trusts today, the public registry and OSV, plus the installer checking the lock's
  hash. The mirror is trusted for nothing.
- Its cost is the classification: an unscoped private name left off the list is sent to the public registry and OSV,
  which [AGENTS.md](../../AGENTS.md) otherwise forbids, then fails as not found or a hash mismatch. Yarn 2+ projects
  need the mirror witness.
- Mirror witness makes the mirror and its administrators the age witness, and adds a credential.

## Alternatives considered

- **Status quo** (fail closed; the mirror's own policy, such as JFrog Curation, with `scan` and `diff`). Rejected:
  mirror shops stay without `soak`.
- **Mirror witness only.** Rejected as the default: it adds a credential and rests on vendor behaviour the docs
  leave unstated.
- **Private versions at high**, each needing a baseline entry. Rejected: the noise would push adopters to switch
  `soak` off.
- **Unclassified scopes as public**, or as private. Rejected: the first leaks internal names to npm and OSV, the
  second passes a young version of a public scope such as `@babel` below the gate.
