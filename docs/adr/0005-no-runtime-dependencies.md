# ADR 0005: No runtime dependencies; one vendored, verified TOML parser

- **Status:** Accepted (0.1.0)
- **Date:** 2026-10-14

## Context

wormsign defends against malicious npm packages. Every runtime dependency would be one more package a worm could
republish into its users' installs, and more code a reviewer has to audit. But `soak` reads TOML (`uv.lock`,
`pylock.toml`, `pyproject.toml`), and `pyproject.toml` is written by people, in every layout TOML allows.

## Decision

- `package.json` has `devDependencies` only. The CLI uses what Node ships: `fetch`, `node:crypto`, `node:fs` and
  `node:child_process` (for `git`, `python3 -m pip config list` and the package managers' `--version`).
- There is no YAML parser. `pnpm-lock.yaml`, `yarn.lock`, package-manager settings and workflows are read by narrow
  readers. What they do not model is a finding ([ADR 0001](0001-fail-closed.md)). For workflows that is a cost of
  this rule, not a better design (the last alternative below).
- One exception: smol-toml 1.9.0 (BSD-3-Clause), vendored byte for byte into `src/vendor/smol-toml/`.
  `src/python/toml.ts` is the only module that imports it.
- `VENDORED.json` records the tarball URL, its sha512, the upstream commit that the registry's SLSA provenance
  names, and every file's SHA-256.
- `npm run build` refuses an edited, added or removed vendored file. `scripts/verify-vendor.mjs` fetches the tarball
  again and compares every byte; CI runs it. A differential test compares its reading of every TOML fixture with
  Python's `tomllib`.

Details: [architecture.md](../architecture.md#one-vendored-pinned-verified-toml-parser).

## Consequences

- The whole tool can be reviewed from this repository. Installing wormsign pulls in no other package.
- About 57 KB of third-party JavaScript is in the trust base of every `soak` run that reads a Python file. A bug in
  it is wormsign's bug.
- No automatic upgrades. Dependabot cannot see a vendored file, so a maintainer runs
  `scripts/verify-vendor.mjs --write` and reviews the diff.
- Where smol-toml and `tomllib` disagree (a byte-order mark, TOML 1.1 syntax, impossible dates, CRLF in multi-line
  strings), a test pins the difference, so an upgrade that changes one fails.
- A valid but unusual npm lockfile can fail a narrow reader. The fix is to regenerate it with the package manager,
  or to review it and baseline the finding.

## Alternatives considered

- **smol-toml as an npm dependency.** Rejected. Each install of wormsign would resolve it from the registry, so a
  compromised release could reach users. A vendored copy changes only through a reviewed commit, and the build
  checks its hashes.
- **A hand-written TOML reader**, like the npm readers. Rejected. A narrow reader would fail closed on ordinary
  Python repositories, and a complete TOML 1.0 parser is a large new body of code to get right.
- **Python's `tomllib` through `python3`.** Rejected. It needs Python 3.11 or later on every runner, npm-only ones
  included, and the result would depend on which `python3` is on `PATH`.
- **A YAML library for the npm readers.** Rejected. Package managers write lockfiles in fixed layouts. A reader
  for those layouts that fails closed on anything else is smaller than a general parser. Settings files are
  written by hand, but are short, and the strict subset fails closed on any other form of the keys it reads.
- **A YAML library for workflows.** Not chosen, and the fixed-layout argument does not apply: people write workflows
  by hand, the reason smol-toml is vendored for `pyproject.toml`. The line reader in `src/checks/workflows.ts` exists
  because this ADR left no YAML parser; no other reason is recorded. A parser-based reader could also fail closed,
  read text as written and decoded, and keep line numbers. A parser would read some listed misses (an `env: {}` flow
  mapping, a value on the line below its key, a folded scalar) and the forms now reported as WS-SC-900 (flow form,
  anchors, aliases, merge keys), though it could still read a form differently from GitHub. Semantic misses stay
  either way: a secret passed through a script file or an action input, a SHA fetched at run time. A vendored YAML
  parser stays open; [ADR 0009](0009-scope-of-0-1-0.md) keeps the workflow checks.
