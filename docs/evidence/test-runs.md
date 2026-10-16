# Test and CI runs

When the test suite, the mutation check, the README's Quickstart and the installation commands ran, and on what.
It supports [validation.md](../validation.md) and [Release status](../installation.md#release-status).

## Test suite

- **The tree of 0ff5d3e**, which equals release 328fbef of the private development repository: `npm test` (build,
  then every test) on 2026-10-16 (UTC), macOS 15.6.1 (arm64), npm 10.9.2, one run after another:

  | Node | Tests | Passed | Failed | Skipped | Test time |
  |---|---|---|---|---|---|
  | 22.23.3 | 1,348 | 1,347 | 0 | 1 | 141 s |
  | 24.21.0 | 1,348 | 1,347 | 0 | 1 | 114 s |
  | 23.11.0 | 1,348 | 1,347 | 0 | 1 | 113 s |

  Node 23 is not a release this project supports. The first runs on GitHub's runners and on Linux are CI's jobs.
- **The code scanning fixes** (branch `fix/code-scanning`, on 6575b22), before their merge: `npm test` on 2026-10-16,
  macOS 15.6.1 (arm64), npm 10.9.2, Node 23.11.0: 1,349 tests, 1,348 passed, 0 failed, 1 skipped, in 118 s. It adds
  one test in `test/soak.test.ts`.
- **The Python PR-mode change** (branch `pre/py-prmode`, on 70841f2), before its merge: `npm test` on 2026-10-15,
  macOS 15.6.1 (arm64), npm 10.9.2, Node 23.11.0: 1,348 tests, 1,347 passed, 0 failed, 1 skipped, in 105 s. It adds
  the 19 tests of `test/soak-python-prmode.test.ts`, ten in `test/soak-python-gates.test.ts`, one each in
  `test/python-differential-requirements.test.ts`, `test/baseline-add.test.ts` and `test/validation-replay.test.ts`.
- **An earlier commit, 6211561**, with 1,315 tests, passed on Node 22.23.3, 24.21.0 and 23.11.0 on 2026-10-15.
- **An earlier commit, 7bb2879**, with 1,312 tests, passed on the same three. Its first Node 24 run failed one test,
  `outage-mode.test.ts`'s connection-reset case: Node 24's bundled undici called `setTypeOfService` on the socket the
  test's server had just reset, and the EINVAL it threw escaped as an uncaught exception, which then exited 1 (since
  63a0ccb a crash exits 2). The file passed 15 runs of 15 alone, and the suite passed on the rerun. A Node 24 run at
  db9fa0b before it caught a race in `baseline add`'s lock, fixed by 9ee4119.
- **An earlier commit, d37a961**, with 1,154 tests, passed on Node 22.23.3 and 24.21.0 as well on 2026-10-14.
- **The skipped test** ran on 2026-10-10 with `WORMSIGN_PIP_REF` naming an isolated virtual environment of pip
  26.1.2, then one of pip 26.2.1, and passed with both: each read the 101 files of the requirements corpus
  (`test/fixtures/python/requirements`, control characters and non-ASCII whitespace among them) as recorded, and
  `refusedByPipAndUv` matched none of the 93 files pip reads.

## Mutation check

**Kill record.** 651 of the 974 mutants, those unchanged since 8baf3ce, have each been killed at least once, locally
on macOS (Node 23.11.0) between 2026-10-02 and 2026-10-15: each on the branch that added it, by the full suite or by
the test files that cover it, or in a batch with `--only` or `--module` after the unmutated suite passed first. The
other 323, added or changed after 8baf3ce (322 by the pre-publication reviews, 1 for a code scanning alert), were
hand-applied by their authors one at a time on a scratch copy against the test files that cover them, and every one
was killed; the script has not run them yet (runner pass pending; the module table counts them). The batches, with
`--only` unless named, under the module names of the time:

| Date | Mutants | Killed (minutes) |
|---|---|---|
| 2026-10-12 | the 18 of `skills` (`--module skills`) | 18 of 18 (39) |
| 2026-10-14 | after the skill's final review: `skills-safety` (18) and 7 of `skills` | 25 of 25 (40) |
| 2026-10-14 | 31 in `python-diff`, `python-readers`, `python-builds`, `python-soak`, `python-sources`, `python-discover-inputs`, `pr-mode` and `integration-reports` | 17 of 18 (33), the other corrected so that it compiles; then it and 13 more, 14 of 14 (20) |
| 2026-10-14 | `skills-recipes` (18), 3 of `skills-safety`, 1 of `python-diff` | 22 of 22 (32) |
| 2026-10-14 | after review round 1: 12 new (1 `python-diff`, 1 `python-discover-inputs`, 10 `skills-guards`), 7 with changed text, and 29 more in `python-diff` and `skills-recipes` | 48 of 48 (67) |
| 2026-10-14 | after review round 2: the new `python-diff-builds` (18), 18 of `python-diff`, 1 of `python-builds`, 4 new in `skills-guards` | 38 of 41 (52): two `python-diff-builds` mutants survived, on code that turned out redundant and was removed with them, and one was corrected so that it compiles; then 17 of 17 (24) |
| 2026-10-14 | after review round 3: the new `python-build-reads` (12), 2 in `skills-guards`, 9 elsewhere, 15 of `python-diff-builds`, 1 of `python-diff` | 39 of 39 (51) |
| 2026-10-14 | after its re-review: `python-build-reads` (17, 5 new), and 15 in `python-builds`, `pr-mode` and `python-diff-builds` | 32 of 32 (52) |
| 2026-10-15 | 33 the pre-publication fixes added (11 `workflow-expressions`, 8 `python-untracked`, 12 `python-coverage`, 2 `gate-io`); then 12 elsewhere | 33 of 33 (67); 12 of 12 (21) |
| 2026-10-15 | the new `skills-review` (17) and 7 elsewhere | 23 of 24 (38), the other corrected so that it compiles, then 1 of 1 (3) |
| 2026-10-15 | expressions read across lines: the rewritten `workflow-expressions` (13), the new `workflow-multiline` (11), `core-workflows` (16); then the new `skill-eval-cues` (5) and 2 on the hook's text | 40 of 40 (83); 7 of 7 (13) |
| 2026-10-15 | at integration: the new `baseline-cli`, `detections` and `simplicity`, one `--module` run each; then 3 `core-soak` mutants whose code moved to `src/soak-config.ts` and 5 new (2 `core-soak`, 3 `harden-script`) | 18 of 18 (34), 18 of 18 (32), 10 of 10 (18); 8 of 8 (15) |

The first full CI run on Node 24 replaces this record. The kills were recorded in the private development repository,
whose history is not published. There, the largest uninterrupted local run killed 69 of 69 in 44 minutes, and on
GitHub's runners the full check of the 70 mutants of the time passed twice, in 63 and 50 minutes.

**Timing.** About two minutes per local suite run, twice that on a runner: a module job (at most 18 mutants plus the
unmutated run) takes about 75 minutes, against a 120-minute timeout.

**The script's own controls**, checked when it was written: a mutant naming text not in its file stops the run
with exit 1 before any test, and a mutant that only edits a comment is reported as SURVIVED with exit 1. The first
caught real drift: after the lockfile, file-hash and config-name code was rewritten, five `STALE` lines, and those
mutants were pointed at the new code.

**The 73 modules** (`npm run mutation -- --list-modules`). *Hand-applied* counts the mutants added or changed after
8baf3ce: hand-applied by their authors, runner pass pending.

| Module | Mutants | Hand-applied | What they switch off |
|---|---|---|---|
| `core-lifecycle` | 14 |  | lifecycle scripts, local specs, script heuristics |
| `core-lockfile` | 15 |  | IOC versions, git sources, integrity, Yarn readers |
| `core-workflows` | 16 | 1 | WS-GH-001 to WS-GH-007 |
| `workflow-expressions` | 15 | 4 | unread `${{ }}` expressions, YAML-escape decoding, a `${{` in a comment |
| `workflow-multiline` | 13 | 2 | `${{ }}` expressions read across lines; line breaks YAML reads |
| `workflow-paths` | 14 | 14 | property paths and head refs as GitHub reads them (WS-GH-003 to 005) |
| `core-scan` | 17 |  | payload hashes and names, endpoints, install scripts; the shared file readers |
| `core-pm-code` | 11 |  | WS-LC-004; the `.npmrc` keys followed |
| `core-diff` | 17 |  | WS-DF-001 to WS-DF-006, the base's baseline |
| `core-soak` | 16 | 3 | WS-SK-001 to WS-SK-004, OSV privacy, the 7-day default |
| `code-scanning` | 1 | 1 | a package name kept as one path segment of soak's registry URL |
| `bunfig` | 7 | 7 | `bunfig.toml` headers and strings, as `soak` and H07 read them |
| `outage-mode` | 17 | 17 | `--on-outage warn`: the outage classifier, what warn reports |
| `outage-host` | 13 | 13 | an outage is the whole host silent for the run, then probed |
| `core-persistence` | 10 |  | WS-PS-001 and WS-PS-002 |
| `core-gate` | 17 |  | fingerprints, baseline expiry, `--fail-on`, `--output` |
| `baseline-cli` | 18 | 2 | `wormsign baseline add`: its checks and safe write |
| `baseline-lock` | 6 | 6 | `baseline add`'s lock and its read-only refusal |
| `baseline-from` | 5 | 5 | `baseline add --from`: a finding of the report, and one an entry can approve; the note without it |
| `audit-org` | 14 |  | WS-OR-001 to WS-OR-004, retries, incomplete-audit exit 2 |
| `detections-audit-log` | 18 | 10 | the audit-log Sigma rules, WS-AL-001 to 004 |
| `detections-endpoint` | 13 | 13 | the endpoint Sigma rules, WS-EP-001 and 002 |
| `detections-queries` | 12 | 12 | the committed Splunk and ES|QL queries and the SPL model |
| `detections-checks` | 9 | 6 | the Sigma evaluator, the detections test's checks, the README's hunt |
| `iocs` | 18 |  | the IOC loader and `update-iocs` |
| `net` | 7 |  | registry redirects; credentials in URLs |
| `python-walk` | 15 |  | the shared walk: virtual environments, git |
| `python-discover` | 18 |  | discovery's content pass; files pip and uv refuse |
| `python-discover-inputs` | 18 |  | inputs discovery must not pass over |
| `python-settings` | 14 |  | install settings and the pip probe |
| `python-untracked` | 8 |  | local Python files git does not track |
| `python-coverage` | 11 | 5 | which manifests a lock covers; unhashed requirements; no root-project exemption |
| `python-soak` | 17 |  | PyPI files bound by sha256 and aged |
| `python-sources` | 17 |  | the index client, local sources, sendable names |
| `python-diff` | 18 |  | `diff` on Python locks, configuration, manifests |
| `python-diff-builds` | 16 |  | `diff` on a Python project's build |
| `python-build-reads` | 17 |  | how a Python build is read: caps, links |
| `python-requirements` | 18 | 3 | the requirements-file reader; a comment on a line continued with `\` |
| `python-readers` | 14 |  | the `uv.lock`, `pylock.toml`, PEP 723 and TOML readers |
| `harden-pip` | 14 |  | `harden-dev.sh` H12 (pip) and H08's pip files |
| `harden-script` | 15 | 1 | H13 (uv), H07, H04, the script's own safety |
| `harden-watcher` | 7 |  | H14 (the watcher's files) and H10's unsearchable-directory check |
| `integration-pypi` | 11 |  | how `soak` runs the Python check |
| `integration-reports` | 14 |  | what `soak`, `diff` and `scan` report on Python |
| `osv` | 16 |  | the CWE-506 layer, `MAL-` records, malformed answers |
| `pr-mode` | 18 |  | what `soak --base` counts as the base's |
| `python-pr-mode` | 15 | 15 | `soak --base` on Python entries: what counts as the base's, and what is still read and reported |
| `python-pr-mode-inputs` | 9 | 9 | what `soak --base` reads of the base for Python: checkout conversions, partial clones, the entry bound, `--baseline`, a project gone, one job per identity |
| `python-local-archives` | 15 | 15 | a requirements line naming a local file: its bytes and symlink target in the key, at every directory pip may run from; what soak cannot pin; `..` after a directory name |
| `python-baselinable` | 17 | 17 | which requirements problems a baseline may approve: none by default, two opt-ins; halts and the missing `--require-hashes` line never; an unreadable file only its exact bytes; SARIF |
| `python-continuation` | 8 | 8 | a continued requirements line is read only in the shape pip-compile writes; options, comments, glued or doubled `\`, tabs refused |
| `python-builds` | 18 |  | a local build's key; the disk and git readers |
| `inputs` | 18 | 5 | what wormsign reads from a tree and prints |
| `gate-io` | 15 | 2 | the Action's logs and uploads; `diff`'s messages; a crash's exit code |
| `ci` | 15 |  | the Action's refusals and SARIF; self-scan; release verifier |
| `ci-workflows` | 4 |  | the module cap; the gate wait; on-demand slow jobs |
| `action-gate` | 15 | 15 | the Action's one-call gate: `diff`, `scan`, `soak`, worst exit, SARIF runs |
| `action-registry` | 10 | 10 | the Action's `registry-host` and `registry` inputs |
| `skills` | 18 | 1 | `wormsign skills`: link refusal, foreign folders, `check` |
| `skills-safety` | 18 | 2 | more of `wormsign skills`; two behavioural-check rules |
| `skills-recipes` | 18 | 1 | the skill's recipes and their behavioural-check rules |
| `skills-guards` | 15 | 3 | builds, scripts and resolving installs kept from the skill |
| `skills-targets` | 5 |  | which copies `wormsign skills` writes for each agent |
| `skills-installer` | 17 | 17 | what `skills install` says it replaced, and leftovers |
| `skill-rules` | 11 |  | the skill's description, recipes, rule 3's checks, the Python recipe |
| `skills-tools` | 16 | 16 | rule 6 (command-line tools) and rule 5 (a dependency's bin) |
| `skills-cooldowns` | 7 | 7 | rule 6's per-tool dependency cooldowns |
| `skills-bins` | 7 | 7 | rule 5's conditions on a dependency's bin; rule 6's npm and uv versions |
| `skill-eval-cues` | 6 |  | evaluation cues hidden from the agent |
| `skill-eval-scenarios` | 18 | 18 | the tool-install scenario's grading |
| `skill-eval-bins` | 11 | 11 | the project-bin scenario's grading |
| `skill-eval-control` | 13 | 13 | the `--no-skill` control, its verdicts and the hook |
| `skill-eval-grading` | 6 | 6 | soak-failure graded on what the run changed; the decline and ask wording of runs 4 and 5; project-bin's stop at a denied install |

## README Quickstart

The [Quickstart](../../README.md#quickstart) of 54c30c7, run on 2026-10-15 from 15:36:35 to 15:36:49 UTC in an empty
directory under `env -i`, with a new empty `HOME` and `TMPDIR` and a new npm global prefix (`npm_config_prefix`, its
`bin` first on `PATH`), on macOS 15.6.1 (arm64), Node 23.11.0 and npm 10.9.2:

| Command | Exit | Output |
|---|---|---|
| `git clone ... && cd wormsign` | 0 | a local clone, checked out at 54c30c7: the GitHub URL needs the network, and the repository is private |
| `npm ci --ignore-scripts && npm run build` | 0 | `added 98 packages`, `found 0 vulnerabilities`, and `EBADENGINE` warnings for `eslint` 10.11.0 and nine of its packages, whose `engines` exclude Node 23. Needs the registry |
| `npm link` | 0 | `added 1 package`: `<prefix>/lib/node_modules/wormsign`, a link to the checkout, and `<prefix>/bin/wormsign`, nothing else. Run with the registry set to a closed port, so it fetched nothing |
| `./harden-dev.sh` | 2 | `no private directory for temporary files`: that `TMPDIR` was under `/private/tmp`, which other users can write |
| the same, `TMPDIR` the user's private one | 1 | `4 pass, 2 warn, 4 fail`: H01, H02, H12 and H13 fail on the empty `HOME` and npm 10.9.2; H03 and H05 warn (corepack shims, nothing cached); H09, its one network check, skipped (gh not logged in). harden-dev.sh itself wrote nothing; `gh auth status` created `~/.local/state/gh/device-id` |
| `cd /path/to/your/project` | 0 | a directory holding only wormsign's `package.json`, `package-lock.json` and `.npmrc` |
| `wormsign soak .` | 0 | one medium WS-SK-004, `` .npmrc: min-release-age is set, but npm 10.9.2 (from `npm --version`) ignores it; npm 11.10.0 or newer enforces it ``; 98 versions checked against the registry and OSV. Needs the network |
| `wormsign scan .` | 0 | `0 finding(s)`, `3 files scanned`; offline |
| `wormsign skills install` | 2 | `no supported agent found (looked for <home>/.claude, <home>/.codex and <home>/.cursor); pass --agent with any of claude, codex, cursor`: the empty `HOME` has none |

## Before publication

Before this repository, wormsign was developed in a private repository that is not published, so those runs cannot
be linked. There, on 2026-10-03 and 2026-10-05, every job of `ci.yml`, `action-selftest.yml` and `wormsign.yml`
passed on `main`. The `ci.yml` jobs were lint and tests on Node 22 and 24, shellcheck, the pack smoke test, the
self-scan, `harden-dev.sh` on Ubuntu and macOS, and the mutation check of the 70 mutants of the time. A canary pull
request that adds an IOC-named workflow failed the gate, as it must
([validation.md](../validation.md#the-canary-pull-request)). No SARIF upload reached code scanning there.

The PyPI soak, the pre-public review fixes and the Python PR-mode change ran first locally, on macOS: the suite of
0ff5d3e's tree on Node 22.23.3, 24.21.0 and 23.11.0 ([above](#test-suite)). Their first runs on GitHub's runners and on
Linux are in the table under [Release status](../installation.md#release-status).

## Installation commands

The commands in [installation.md](../installation.md) ran on 2026-10-09 at 64e6111 (recorded by 77d1b42), on Node
24.21.0 / npm 11.19.0 (macOS), with an empty `HOME` and a temporary global prefix. `npm ci --ignore-scripts` in a
fresh clone printed `added 98 packages, and audited 99 packages in 1s`, `found 0 vulnerabilities` and no warnings.
`npm install -g ./wormsign-0.1.0.tgz --ignore-scripts` (a tarball `npm pack` made from a fresh clone) printed
`added 1 package in 536ms`, and `npm link` printed `added 1 package, and audited 3 packages in 399ms`; after each,
`wormsign --version` printed `0.1.0`. `npm uninstall -g wormsign` and `npm unlink -g wormsign` each printed
`removed 1 package`. `sha256sum -c SHA256SUMS` and `shasum -a 256 -c SHA256SUMS`, on a locally packed tarball,
printed `wormsign-0.1.0.tgz: OK`. [Verify the install](../installation.md#verify-the-install) ran on the tarball.
