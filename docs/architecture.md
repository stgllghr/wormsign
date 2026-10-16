# Architecture

Read this page to review, extend or audit wormsign: what each source file does, how data moves through each
command, and the mechanics behind each decision. The decisions are the [ADRs](adr/README.md); each command is on its
page (such as [cli/scan.md](cli/scan.md)), and each rule in [rules.md](rules.md).

## Overview

wormsign is a TypeScript CLI compiled to plain JavaScript (`dist/src/`) with no npm runtime dependencies. One
third-party TOML parser is vendored, pinned and verified in `src/vendor/`
([below](#one-vendored-pinned-verified-toml-parser)). Everything else in the repository wraps or feeds the CLI:

```
                  data/iocs/*.json  (sourced IOCs, versioned by date)
                         |
                         v
  repository  -->  src/ (CLI: scan, diff, soak, audit-org, update-iocs, skills)  -->  report: human | JSON | SARIF
  files, git              |              |                                      + exit code 0 / 1 / 2
  revisions               |              +--> network, only for: soak (npm registry, PyPI index, api.osv.dev),
                          |                   audit-org (api.github.com, GET only), update-iocs (one https URL)
                          |
       action.yml + scripts/ci-action.mjs   (composite GitHub Action: runs the CLI once, writes SARIF and outputs)
       harden-dev.sh                        (workstation checks; reads IOC names and hashes through dist/src/iocs.js)
       detections/                          (YAML detection content for SIEMs; not run by wormsign)
```

`scan` and `diff` never use the network. `soak` uses it unless `--config-only` is given. There is no telemetry.

## Module map

### Entry points and output

| File | What it does |
|---|---|
| [`src/cli.ts`](../src/cli.ts) | The `bin`: calls `run()` with the real streams, environment and clock; sets the exit code. |
| [`src/main.ts`](../src/main.ts) | Parses and validates every argument, `--baseline` and `--iocs` files included, before any file, git or network work; dispatches; holds `--help`. |
| [`src/types.ts`](../src/types.ts) | `Finding`, the severity scale (`info` < `low` < `medium` < `high` < `critical`), `UsageError`, the fingerprint. |
| [`src/rules.ts`](../src/rules.ts) | The rule catalogue, the single source for SARIF rule metadata. |
| [`src/report.ts`](../src/report.ts) | Human, JSON and SARIF rendering; escapes every output line (`neutralise`); the `--fail-on` exit code. |
| [`src/sarif.ts`](../src/sarif.ts) | Deterministic SARIF 2.1.0, without baselined findings, with per-rule `security-severity` and `partialFingerprints`. |
| [`src/baseline.ts`](../src/baseline.ts) | Loads, validates and applies `.wormsign-baseline.json`; WS-BL-001 for expired entries. |
| [`src/duration.ts`](../src/duration.ts) | Parses `--min-age` (`72h`, `3d`); a bare number is rejected. |

### Commands

| File | What it does |
|---|---|
| [`src/scan.ts`](../src/scan.ts) | Walks a directory, never through a symlink, and routes each file to its checks. |
| [`src/diff.ts`](../src/diff.ts) | Reports what a change adds: install scripts, workflow, config, baseline and Python changes ([which](cli/diff.md)), and changed files it cannot read (WS-DF-006). |
| [`src/tree.ts`](../src/tree.ts) | A read-only directory (`dir:<path>`) or git revision. Runs `git -C <repository>` from the filesystem root with an argument array, never a shell, so a `git` in the scanned tree never runs. |
| [`src/exec.ts`](../src/exec.ts) | Finds `git`, `python3` and the package managers on `PATH`, refusing one inside the scanned tree; spawns by absolute path. |
| [`src/soak-config.ts`](../src/soak-config.ts) | `soak` layer 1, offline: release-age settings against `--min-age` and the package-manager version that will run; the configured registries. |
| [`src/soak.ts`](../src/soak.ts) | `soak` layer 2, network: age, publication and integrity of each locked version; the shared OSV step (`runOsv`). |
| [`src/settings-yaml.ts`](../src/settings-yaml.ts) | The strict YAML subset for `pnpm-workspace.yaml`, pnpm's `config.yaml` and `.yarnrc.yml`. |
| [`src/walk.ts`](../src/walk.ts) | `soak`'s one walk for npm and Python, and the virtual-environment rule (asks git which files are tracked). |
| [`src/osv.ts`](../src/osv.ts) | Malicious-package records from `api.osv.dev`: `MAL-`, or `GHSA-` with CWE-506 ([below](#what-the-osv-client-relies-on)). |
| [`src/registry-signals.ts`](../src/registry-signals.ts) | WS-RG-001 to WS-RG-003 from the manifests `soak.ts` fetched. |
| [`src/audit-org.ts`](../src/audit-org.ts) | Organization audit: `GET` only, no pagination link to another origin. |
| [`src/iocs.ts`](../src/iocs.ts), [`src/update-iocs.ts`](../src/update-iocs.ts) | Load, validate and refang the five IOC files plus the cache; download them from one https URL. |
| [`src/skills.ts`](../src/skills.ts) | `wormsign skills` ([cli/skills.md](cli/skills.md)). No network. |
| [`src/baseline-add.ts`](../src/baseline-add.ts) | `wormsign baseline add`, through a temporary file renamed into place. No network. |
| [`src/fsutil.ts`](../src/fsutil.ts) | The walker and bounded reads: `O_NOFOLLOW`, 2 MiB for text files, NUL bytes rejected, byte-order mark dropped. |

### Checks (`src/checks/`)

| File | What it does |
|---|---|
| [`context.ts`](../src/checks/context.ts) | The scan context, `notChecked()` for WS-SC-900, and `capped()`, which folds findings past a per-file limit into one. |
| [`lifecycle.ts`](../src/checks/lifecycle.ts) | package.json install scripts (WS-LC-001 to WS-LC-003); local paths and pnpm overrides the scan does not read (WS-SC-900). |
| [`lockfile.ts`](../src/checks/lockfile.ts) | IOC versions (WS-LK-001), off-registry, git or http sources (WS-LK-002), missing integrity (WS-LK-003). |
| [`workflows.ts`](../src/checks/workflows.ts) | WS-GH-001 to WS-GH-007. A line-based reader; its header comment lists what it misses. |
| [`persistence.ts`](../src/checks/persistence.ts) | VS Code automatic tasks (WS-PS-001); Claude Code hooks, command settings, plugins and MCP servers (WS-PS-002). |
| [`files.ts`](../src/checks/files.ts) | Payload hashes (WS-FS-001; IOC-named files, or all with `--hash-all`) and names (WS-FS-002). |
| [`exfil.ts`](../src/checks/exfil.ts) | Webhook-style URLs (WS-EX-001, a heuristic) and IOC endpoints (WS-EX-002); inside `node_modules`, IOC endpoints only. |
| [`nodemodules.ts`](../src/checks/nodemodules.ts) | With `--node-modules`: install scripts and `binding.gyp` (WS-NM-001), IOC versions (WS-LK-001). |

### Lockfile parsers (`src/lockfile/`)

[`index.ts`](../src/lockfile/index.ts) picks the parser by file name: [`npm.ts`](../src/lockfile/npm.ts) (v1 to v3,
every field type-checked), [`pnpm.ts`](../src/lockfile/pnpm.ts) (v5 to v9, pnpm's layout only) or
[`yarn.ts`](../src/lockfile/yarn.ts) (Classic and Berry; a Berry identity comes from `resolution:`). A file a parser
cannot fully read throws. [`identity.ts`](../src/lockfile/identity.ts) accepts only versions spelled as the registry
publishes them, so `v7.0.0` cannot slip past an IOC lookup, and [`tarball.ts`](../src/lockfile/tarball.ts) checks an
entry relabelled to another package's tarball as that tarball.

### Python (`src/python/`)

Used by `soak`; `diff` uses `manifest.ts`, `scripts.ts` and `toml.ts`, and `scan` uses `manifest.ts`. Each module's
header comment states its rules and the tool versions they were checked against.

| File | What it does |
|---|---|
| [`discover.ts`](../src/python/discover.ts), [`manifest.ts`](../src/python/manifest.ts), [`scripts.ts`](../src/python/scripts.ts) | Finds every lock, PEP 723 script, requirements file and manifest; the covering-lock rule; file-level WS-SK-002 and WS-SK-005. |
| [`indexes.ts`](../src/python/indexes.ts) | Every index, find-links and hash setting: environment, `python3 -m pip config list`, uv config, committed `pip.conf`. |
| [`uvlock.ts`](../src/python/uvlock.ts), [`pylock.ts`](../src/python/pylock.ts), [`requirements.ts`](../src/python/requirements.ts), [`pep723.ts`](../src/python/pep723.ts) | The readers (requirements as pip 26.2.1 reads them, scripts as uv does). Each returns problems instead of throwing. |
| [`toml.ts`](../src/python/toml.ts) | The only importer of the vendored TOML parser. |
| [`model.ts`](../src/python/model.ts), [`identity.ts`](../src/python/identity.ts) | One model for every format; a package's identity. |
| [`index.ts`](../src/python/index.ts) | The Simple API client (PEP 691, 700, 792) and sha256 binding. |
| [`soak.ts`](../src/python/soak.ts), [`base-builds.ts`](../src/python/base-builds.ts), [`base-entries.ts`](../src/python/base-entries.ts) | The check, and PR mode, which raises a WS-SK-005 the base does not give to high, leaves out entries and reader problems the base's soak already read, and never writes base content to disk. |
| [`local.ts`](../src/python/local.ts), [`paths.ts`](../src/python/paths.ts), [`build.ts`](../src/python/build.ts) | Local sources, path archives, and the build key for WS-SK-005 ([soak.md](soak.md#builds-ws-sk-005)). |
| [`names.ts`](../src/python/names.ts), [`pep440.ts`](../src/python/pep440.ts), [`filenames.ts`](../src/python/filenames.ts) | PEP 503 names, PEP 440 versions (no specifiers), wheel and sdist file names. |

### Outside `src/`

| Path | What it is |
|---|---|
| [`data/iocs/`](../data/iocs) | The IOC data ([iocs.md](iocs.md)). |
| [`action.yml`](../action.yml), [`scripts/ci-action.mjs`](../scripts/ci-action.mjs) | The composite Action: one CLI run with `--format json`, rendered as human text and SARIF ([github-action.md](github-action.md)). |
| [`harden-dev.sh`](../harden-dev.sh) | Workstation checks ([hardening.md](hardening.md)). |
| [`detections/`](../detections/README.md) | SIEM detection content as YAML data. |
| [`scripts/`](../scripts) | CI, IOC and study tools. Users run `ci-action.mjs` (through the Action) and `ci-verify-release.sh` ([checking a release tag](installation.md#check-a-release-tag-yourself)); none is in the npm tarball. |

**Why the Action runs compiled code from a release tag.** The tag adds `dist/src/cli.js`, checked byte for byte
against a rebuild. Node's type stripping could run `src/cli.ts`, but it is on by default only from Node 22.18.0 (and
23.6.0) while `engines` accepts any Node 22, and the imports name `.js` files that `tsc` writes.

## Data flow

### `scan [dir]`

1. `main.ts` loads the baseline (`--baseline`, else `.wormsign-baseline.json` in `dir`) and the IOC data (`--iocs`,
   else the bundled data plus newer cache additions).
2. `scan.ts` walks `dir`, skipping `.git`, `node_modules` (unless `--node-modules`) and `ignorePaths`. Each file goes
   to the checks that apply; one a check cannot read or parse, or a symlink where one would be, is WS-SC-900.
3. Findings are de-duplicated by fingerprint and baselined; notes say what was not done.

### `diff <base> <head>`

1. `tree.ts` resolves each side: `dir:<path>` is a directory, anything else a git revision, never a
   guessed directory ([why](cli/diff.md)).
2. The baseline comes from **base** (or `--baseline`), never from head.
3. Any change to package-manager config, the code it names or the baseline, and a removed lockfile, is WS-DF-005.
4. Changed manifests, lockfiles, workflows and local actions are compared: install scripts (WS-DF-002),
   `packageManager` (WS-DF-005), workflows (WS-DF-003 plus the workflow checks), and added lockfile entries
   (WS-DF-001, WS-DF-004, `lockfile.ts`). A changed file it cannot read, parse or follow is WS-DF-006.
5. The persistence checks run on every auto-run file the change adds or edits. The payload and endpoint checks do
   not, so a gate runs `scan` on the change too.

### `soak [dir]`

1. `walkTree()` walks once. An unreadable or Bun lockfile, a symlink, or a `package.json` with dependencies and no
   lockfile at or above it is WS-SK-002. `discoverPython()` reads the same walk.
2. Layer 1, offline: release-age settings from project, user and environment config (WS-SK-003, WS-SK-004).
3. Layer 2, unless `--config-only`: one registry request per package name (with `--base <rev>`, only for versions the
   base did not lock). Too young is WS-SK-001; unverifiable is WS-SK-002. Then registry signals and OSV (WS-OS-001,
   or WS-OS-900 when the lookup fails).
4. Python, unless `--config-only`: local sources and builds, then one Simple API request per project binds each
   file by sha256 and reads its upload time, then OSV (with `--base <rev>`, an entry the base's soak read
   identically is bound only for WS-SK-005, not aged or sent to OSV).
5. JSON carries per-version evidence ([output.md](output.md#soak-evidence)).

### `audit-org <org>`

Repositories (WS-OR-001), the audit log (WS-OR-002, WS-OR-003; Enterprise Cloud only), then up to `--max-repos`
repositories one at a time (WS-OR-003, WS-OR-004). What it could not check is WS-OR-900; an incomplete audit exits 2.

### `update-iocs`

Downloads, validates with the scan's loader, and caches only newer data ([iocs.md](iocs.md#how-update-iocs-works)).

## Design decisions

### No npm runtime dependencies, narrow hand-written parsers that fail closed

The decision is [ADR 0005](adr/0005-no-runtime-dependencies.md); what the readers do not model is a finding
([ADR 0001](adr/0001-fail-closed.md)).

| Reader | Reads | On anything it does not model |
|---|---|---|
| [`lockfile/pnpm.ts`](../src/lockfile/pnpm.ts), [`lockfile/yarn.ts`](../src/lockfile/yarn.ts) | `pnpm-lock.yaml`, `yarn.lock` | throws: an anchor, alias or tag, a nested flow collection, an escape in a quoted key, odd indentation, an entry with no resolution or version |
| [`settings-yaml.ts`](../src/settings-yaml.ts) | `pnpm-workspace.yaml`, `.yarnrc.yml`, pnpm's `config.yaml` | records a problem: an anchor, alias, tag, merge key, `? ` key, block scalar, nested flow collection, escape or duplicate key it reads, or an unclosed quote or bracket |
| [`checks/workflows.ts`](../src/checks/workflows.ts) | `.github/workflows/*.yml` | a form it does not model is WS-SC-900; it resolves no reusable workflow, composite action or expression; known misses are in its header comment and the [wave replays](validation.md#3-wave-replays) |

`diff` finds the code a config file names with a simpler reader (scalar, flow list, block list); a value written
another way is not followed, but the config change is still WS-DF-005. Bun lockfiles and pnpm's `package.yaml` /
`package.json5` are reported as not checked.

### One vendored, pinned, verified TOML parser

The decision, and what `VENDORED.json` records, are [ADR 0005](adr/0005-no-runtime-dependencies.md).
[`scripts/copy-vendor.mjs`](../scripts/copy-vendor.mjs) (in `npm run build`) and
[`test/vendor-integrity.test.ts`](../test/vendor-integrity.test.ts) refuse an edited, added or removed file in
`src/vendor/smol-toml/`. [`scripts/verify-vendor.mjs`](../scripts/verify-vendor.mjs) refetches the tarball and checks
every file and the provenance; CI runs it on every push to `main`, on every pull request whose gate passes
([why](../CONTRIBUTING.md#pull-requests)), and monthly, and `--write` upgrades.
[`test/python-differential.test.ts`](../test/python-differential.test.ts) compares all 60 TOML fixtures with
`tomllib` (CI sets `WORMSIGN_REQUIRE_PYTHON=1`).

**What smol-toml 1.9.0 does**, each behaviour pinned by those two tests, so an upgrade that changes one fails:

- Published 2026-09-22; its provenance names commit `6f9739a5ab481f57c3112024bc4947534b580b58` of
  `squirrelchat/smol-toml`, tag `v1.9.0`.
- It accepts a leading byte-order mark, which Python 3.14.6's `tomllib` and pip 26.2.1 reject and uv 0.10.9 and
  0.12.21 accept, so `src/python/toml.ts` reports one as a problem.
- A duplicate key or table throws.
- Date-times keep milliseconds only (`17:35:26.475808Z` reads as `17:35:26.475Z`); wormsign never trusts a lock's
  upload times.
- Integers beyond 2^53 - 1 throw by default; the readers pass `integersAsBigInt: "asNeeded"`, and a `bigint` size
  is a problem.
- Tables have a `null` prototype, so `__proto__` stays an ordinary key; the readers use `Object.hasOwn`.
- 1,000 nested arrays parse and 1,001 throw; 2,000 nested inline tables throw too.
- Time grows about in step with input: 400,000 `[[p]]` tables in about 0.2 seconds on Node 24
  ([`scripts/toml-bench.mjs`](../scripts/toml-bench.mjs)). Files over 64 MiB are not read.
- It accepts TOML 1.1 syntax that `tomllib` rejects (newlines and trailing commas in inline tables, `\e`, `\x`,
  times without seconds), rolls impossible dates over (`2023-02-29` reads as 2023-03-01), and keeps CRLF inside a
  multi-line string as `\r\n`.

### PyPI: bind each locked file, and fail closed where a tool would decide

`soak` binds and ages each locked file, not the version ([soak.md](soak.md#each-locked-file-not-the-version)):
PyPI has no release time and files are added to old releases, so aging by the first file would pass a young late
wheel.

A package's identity digests its name, version, source and every file's hashes, so a baseline entry approves one
exact set of files. Lock staleness, manifest coverage and install-setting precedence are not modelled
([ADR 0004](adr/0004-no-installer-parser-imitation.md)); the gaps are in [soak.md](soak.md#python-limitations).

### Data-driven IOCs with per-entry provenance

Indicators live in versioned JSON in `data/iocs/`, each with an https `source` the loader requires; heuristics stay
in code ([iocs.md](iocs.md)).

### Fail closed: WS-SC-900, WS-DF-006 and the other "not checked" findings

The decision and the per-command table are [ADR 0001](adr/0001-fail-closed.md). For a WS-DF-006 path that cannot be
followed, the fingerprint key hashes the whole tree, so the lasting fix is a real file instead of the link.

### The PR gate is built from the base branch, and baselines come from the base

The decision is [ADR 0002](adr/0002-pr-gate-built-from-base.md); the workflow is in
[github-action.md](github-action.md#why-it-is-built-this-way).

### Every editor or agent auto-run entry is high, instead of interpreting commands

WS-PS-001 and WS-PS-002 report every VS Code automatic task and every Claude Code hook, command setting, env entry or
local MCP server as **high**, whatever the command ([what each covers](rules.md#ws-ps-001)). The 2026-08 wave
commits exactly these files ([JFrog](https://research.jfrog.com/post/shai-hulud-is-back-august/)). Telling harmless
commands from harmful ones is what [ADR 0004](adr/0004-no-installer-parser-imitation.md) refuses.

The fingerprint covers the whole entry, so an edit to a baselined entry reports it again
([baseline.md](baseline.md#how-firmly-an-entry-is-bound-to-what-it-approves)); the script it runs can change
without changing the entry.
Lifecycle scripts differ: WS-LC-001 is medium (low if `private`), and WS-LC-002 adds high only on a heuristic match.

### Check by default in `harden-dev.sh`

Without `--apply`, `harden-dev.sh` changes no settings (gh, which H09 runs, may write its own state); what `--apply`
writes, and how, is in [hardening.md](hardening.md#what---apply-writes). It never touches tokens, credential files,
shell profiles or payload files, which may be evidence ([incident-response.md](incident-response.md)). It is bash so it
runs on a machine that may not have Node.js; the harden tests and
[`test/iocs-harden-agreement.test.ts`](../test/iocs-harden-agreement.test.ts) hold its settings logic to `soak`'s.

### What the OSV client relies on

[`osv.ts`](../src/osv.ts) treats any answer outside this shape as an error, so a change on OSV's side shows up as
WS-OS-900, not as a clean result. These are observations of `api.osv.dev` and its API docs (`docs/api` in
[google/osv.dev](https://github.com/google/osv.dev)).

Checked 2026-10-02:

- `POST /v1/querybatch` takes at most 1000 queries (1001 is HTTP 400). Results come back in query order, each `{}`
  or `{ vulns: [{ id, modified }], next_page_token? }`.
- A `next_page_token` means more ids for that query; the same query with `page_token` returns them.
- Withdrawn records are left out. An empty version matches every version.
- One bad query fails the whole batch: an empty name or a lone UTF-16 surrogate is HTTP 400, a 2000-character name
  HTTP 500. A body over 4 MiB is HTTP 429.
- The server matches versions against affected ranges itself, so wormsign never evaluates a range.

Checked 2026-10-08:

- `POST /v1/query` returns `{ vulns: [full records], next_page_token? }`, or `{}`, paging past 1000 records or 20
  seconds. For eight npm and PyPI versions it returned exactly the ids the batch did.
- All 411 GHSA records in those answers have `database_specific.cwe_ids`, an array of strings, so a GHSA record
  without one is unexpected.
- An advisory OSV holds only as an alias is answered under the record's own id (`@ctrl/tinycolor@4.1.1` gets
  MAL-2025-47141, aliased GHSA-qjqf-7j6f-82c4).

### SARIF output and fingerprints

[`sarif.ts`](../src/sarif.ts) cites GitHub's
[SARIF support reference](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)
for each choice: a line hash for whole-file results, baselined findings left out, and a per-rule `security-severity`
([output.md](output.md#sarif)). Each result carries the baseline fingerprint ([baseline.md](baseline.md#fingerprints))
as `partialFingerprints["wormsign/v1"]`.

### Output that repository text cannot forge

`neutralise()` in [`report.ts`](../src/report.ts) escapes every output line, stderr included, so a `postinstall`
excerpt cannot forge annotations or send `::stop-commands::` ([what it escapes](output.md#output-is-safe-to-print)).
