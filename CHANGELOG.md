# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - unreleased

The first release, the version in `package.json`. It has not been tagged yet
([release status](docs/installation.md#release-status)).

### Added

- **Typed ESM library API:** `scan`, `gateExitCode`, `renderReport`, `UsageError` and public types. The read-only
  scanner uses bundled or explicitly selected IOC data, ignores ambient user caches and does not apply project
  baselines. Package exports define the supported interface; compiled declarations and runnable JavaScript and
  TypeScript examples ship in the tarball. The release smoke test checks external consumers after offline
  installation. [library.md](docs/library.md)
- **Release artifact consumers:** CI and releases build once and install that same tarball on Node 22 and 24.
  Publication waits for both consumers. Slow mutation jobs retain diagnostics for thirty days while preserving
  failed command exit statuses; maintainer instructions require final CI on the source commit being released.
- **`wormsign scan [dir]`**, offline: install scripts, lockfile IOC versions, sources and integrity, workflows,
  payload files, exfiltration endpoints and auto-run editor and agent entries; what it cannot check is WS-SC-900.
  [cli/scan.md](docs/cli/scan.md)
- **`wormsign diff <base> <head>`**, offline: what a change adds between two revisions or directories, with the
  baseline read from the base; Python changes as reports. [cli/diff.md](docs/cli/diff.md)
- **`wormsign soak [dir]`**, the soak gate (default `--min-age 7d`): too-young or unverifiable locked versions, OSV
  malware records, registry signals and release-age settings; `--base` for pull requests. [soak.md](docs/soak.md)
- **`soak --base` treats Python lock entries as npm's**: an entry the base's own `soak` read identically (the same
  file read as a lock of the same kind, the same name, version and hashes, and for `uv.lock` and `pylock.toml` the
  same source and files) is not aged or sent to OSV. Only entries are skipped: reader and file-level problems are
  reported on every run, as npm's are. Before, every Python package was checked on every pull request, so a young pin
  on the base failed all of them. A pin in a file the base's `soak` did not read as a lock is still checked, and a young version
  pushed straight to the base is left to the push and scheduled `soak`, as for npm.
  [soak.md](docs/soak.md#pr-mode)
- **`soak --on-outage warn`**, opt in (default `fail`): when the registry, the Python index or OSV gives no answer
  in the whole run (DNS, connection, TLS handshake, timeout, HTTP 429 or 5xx, after the retry) nor to a `HEAD` of
  its root, each package it left unchecked is the new WS-SK-006 or WS-OS-901, medium, which no baseline suppresses,
  and the run prints one `UNVERIFIED:` line. One name a host will not serve, a host that answers at any point, and
  every other failure stay WS-SK-002 or WS-OS-900, high. OSV requests follow no redirect. The Action's `on-outage`
  input passes it and writes the line to the step summary. [soak.md](docs/soak.md#outages---on-outage)
- **Python locks in `soak`**: `uv.lock`, PEP 723 script locks, `pylock.toml` and hash-locked requirements files,
  each locked file bound to the index by its sha256; `poetry.lock`, `pdm.lock` and `Pipfile.lock` fail closed. An
  untracked Python virtual environment in a git work tree is skipped, npm lockfiles included, with a note naming it.
  A requirements-file WS-SK-002 is keyed on its problem without the fix it suggests, so rewording a fix keeps the
  fingerprint; that changed every such fingerprint from the unreleased builds before it (4dc0f5d and earlier). A
  WS-SK-002 for a requirements line naming a local path or `file:` URL (an archive, a directory, or a path where
  nothing is yet) also covers what is there: a file's sha256 and, through a symlink, its target; `directory`; or
  `missing`. That changes the fingerprints of every such line from the builds before it (453b89c and earlier), and an
  entry for the old key approves nothing. Such a line is keyed at the directories of the top-level requirements file
  and of each file that includes it too, where pip may run. Only two requirements problems can now be baselined: a
  plain index requirement soak parsed to the end (`foo>=1`, a pin without a sha256 hash; its fingerprint is
  unchanged), and a local file soak resolved to a regular file inside the root. Every other one (an option on a
  requirement line, an include, an index option, `${`, a line or file soak could not read, a directory or a path
  missing at every place, a file soak cannot pin, every halt, and the missing `--require-hashes` line, which is keyed
  on no text of the file) is a WS-SK-002 no baseline entry approves (`notBaselinable` in JSON and SARIF properties),
  so an entry for one written before no longer suppresses it; soak notes an entry that names one. A requirements
  line continued with `\` is read only in the shape `pip-compile` and `uv pip compile` write (a requirement ending in
  ` \`, then `--hash=sha256:` lines); any other is such a WS-SK-002 for the whole file. pip joins every continued line
  to the next, uv reads some up to the line break, so before, uv could install what soak never read: `-r a.txt \`
  read the file `a.txt `, a `\` glued to a hash split it into a requirement, a comment took the next line in for pip
  only, and a glued `--require-hashes\` made the file one any entry could approve. A `..` after a directory name in an
  include or local path (`-r node_modules/foo/../a.txt`) is such a WS-SK-002 as well: pip resolves it as text, uv
  through a symlink at `foo`. A requirements file soak cannot read at all says that pip and uv read such files
  differently, and that its entry holds for those exact bytes. `file:foo` and `git+file:repo` are said to be URLs, not unpinned names.
  [soak.md](docs/soak.md#python-pypi-locks)
- **`wormsign audit-org <org>`**: a read-only GitHub organization audit; an incomplete audit exits 2.
  [cli/audit-org.md](docs/cli/audit-org.md)
- **`wormsign update-iocs`**: newer IOC data into a cache that can only add indicators.
  [cli/update-iocs.md](docs/cli/update-iocs.md)
- **`wormsign skills install|check|uninstall`**: the agent skill for Claude Code, Codex and Cursor, installed with
  no network access. [skills.md](docs/skills.md)
- **`wormsign baseline add <fingerprint>... --reason <text>`**: records reviewed findings, each with its reason and
  an optional `--expires`; there is no approve-all mode. With `--from <report.json>` (a `--format json` report) it
  refuses, with exit 2 and the reason, a fingerprint that is not a finding there or whose finding no entry can
  approve; without it, a note on stderr says the fingerprints were not checked. [cli/baseline.md](docs/cli/baseline.md)
- **Output** as text, JSON or SARIF 2.1.0, with exit codes 0, 1 and 2; a baseline file suppresses single findings,
  each with a justification. [output.md](docs/output.md), [rules.md](docs/rules.md)
- **Defences against hostile input**: reports cannot forge workflow commands, redirects and URLs with credentials
  are refused, and no tool is run from the scanned tree. [architecture.md](docs/architecture.md)
- **A composite GitHub Action** running `scan`, `diff` or `soak`, with SARIF for code scanning. Its default on
  `pull_request` is the gate: `diff`, `scan` and `soak --base` in one call, failing on the worst, with one SARIF file
  holding each command's run under its own category (`wormsign-diff/`, `wormsign-scan/`, `wormsign-soak/`). A
  release tag adds only the compiled `dist/src`, which the release workflow rebuilds and compares byte for byte.
  [github-action.md](docs/github-action.md)
- **The Action's `registry-host` and `registry` inputs** for a private registry: `registry-host` passes each
  comma-separated host to `scan` and `diff` as `--registry-host`, so the registry's lockfile URLs are not WS-LK-002;
  `registry` passes `--registry` to `soak`. A line break in either, or an empty `registry-host` entry or one with a
  space in it, is exit 2. `soak` still fails closed on a mirror that does not serve publish times without
  credentials ([ADR 0007](docs/adr/0007-private-registry-mirrors.md), accepted, not yet built).
  [github-action.md](docs/github-action.md#inputs)
- **`harden-dev.sh`** for macOS and Linux, checks H01 to H14: install scripts and cooldowns for npm, pnpm, Yarn and
  Bun, pip's and uv's cooldowns, plaintext tokens, `gh` scopes, credential and payload files; `--apply` backs up
  each file. [hardening.md](docs/hardening.md)
- **Detections**: Sigma rules for the GitHub audit log (WS-AL-001 to WS-AL-004) and endpoints (WS-EP-001,
  WS-EP-002), and CI-log patterns (WS-CI-001 to WS-CI-005). Each Sigma file has Splunk and ES|QL reference
  conversions, post-processed as its header lists: Splunk correlations slide and give one result per group; ES|QL
  counts in two bucket sets 30 minutes apart. The README gives schedules with overlapping look-back, an organization
  and enterprise hunt, and what is not validated. [detections/README.md](detections/README.md)
- **IOC data** from two Apache-2.0 datasets, plus payload hashes and names, workflow and runner names, repository
  patterns, branches and an endpoint, each with an https source. [iocs.md](docs/iocs.md)
- **Validation and evidence**: rule coverage, IOC recall, inert wave replays, a mutation check and a self-scan with
  a positive control. [validation.md](docs/validation.md)
- **Design and policy docs**: [design](docs/design.md), [decision records](docs/adr/README.md),
  [positioning](docs/positioning.md), [stability](docs/stability.md) and the [roadmap](ROADMAP.md).

[0.1.0]: https://github.com/stgllghr/wormsign/commits/main
