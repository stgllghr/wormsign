# ADR 0001: Fail closed: what wormsign cannot verify is a finding

- **Status:** Accepted (0.1.0)
- **Date:** 2026-10-14

## Context

The gate fails at `high` by default (`--fail-on high`). The attacker writes the input. If a file wormsign cannot read
were only a note, the attack would be to make the malicious file that file: a symlink, a 3 MiB `package.json`, a YAML
anchor in a lockfile, a package from a registry wormsign cannot query. npm and GitHub would still act on it.

## Decision

Anything that decides what runs, and that wormsign cannot verify, is a finding, not a note: `high` unless a row below
says medium.

| Command | Cannot verify | Result |
|---|---|---|
| `scan` | a manifest, lockfile, workflow or editor or agent file that is unreadable, too large, a symlink or in a form the reader does not model | WS-SC-900, high |
| `diff` | a changed file it cannot read, parse or follow to one file | WS-DF-006, high |
| `diff` | a git object it cannot read | exit 2 |
| `soak` | a locked version's age or identity: private registry, git source, unpublished version, integrity mismatch, request error | WS-SK-002, high (an outage under `--on-outage warn`: WS-SK-006, medium) |
| `soak` | a local Python source with a file git does not track | WS-SK-002, medium; high in PR mode (`--base`) |
| `soak` | a Python build's requirements, which no lock pins | WS-SK-005, medium; high in PR mode when the change adds the build |
| `soak` | an OSV lookup | WS-OS-900, high (an outage under `--on-outage warn`: WS-OS-901, medium) |
| `soak` | a release-age setting it cannot interpret, or a package manager that ignores it | WS-SK-004, medium; high with `--require-config` |
| `audit-org` | a per-repository check that no repository answered, or a run a rate limit stopped | exit 2 |

Bad input from the person running the command is different. A bad flag, baseline or IOC file is a usage error:
exit 2 with a message, before any file, git or network work.

The lockfile and settings readers accept only the shapes they fully understand; anything else becomes one of the
findings above. A reformatted lockfile that the package manager still installs must never parse to fewer packages
in wormsign.

## Consequences

- Unusual repositories get more findings. Each one has a fingerprint and can be baselined with a justification.
  Where the key holds a content hash, the next edit fails again.
- By default an outage fails the gate: while OSV, the registry or the index is down, every pull request fails
  (WS-OS-900, WS-SK-002). `--on-outage warn` (opt-in) reports each unchecked package as WS-SK-006 or WS-OS-901, medium,
  never baselined, with an UNVERIFIED line, but only when the configured host gives no answer in the whole run
  ([soak.md](../soak.md#outages---on-outage)).
- Private registries fail closed in `soak`: each package is WS-SK-002 until baselined
  ([soak.md](../soak.md#private-registries)).
- Unsupported formats fail closed rather than pass: Bun lockfiles, `poetry.lock`, `pdm.lock`, `Pipfile.lock`.
- `--fail-on never` turns findings into exit 0. Errors still exit 2.
- The two Python rows are medium outside PR mode, where an untracked file or a build is common; in the gate an
  untracked file, or a build the change adds, is high.

## Alternatives considered

- **Report it as a note and pass.** Rejected. CI reads the exit code, not the notes, and the attacker chooses which
  file is unreadable.
- **Report it below `high`.** Rejected. Under the default `--fail-on high` that is a note with a severity.
- **Parse leniently and skip what does not parse.** Rejected. A lenient reader that sees fewer packages than the
  installer hides exactly the ones it skipped.
