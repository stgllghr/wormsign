# Validation: will a real compromise be caught?

Does wormsign report a Shai-Hulud-style compromise, and how would you know if it stopped doing so? No live malware
is used, so the answer is built from narrow layers, each with what it proves and what it does not. The dated runs
behind the figures are in [evidence/test-runs.md](evidence/test-runs.md).

## At a glance

| Layer | The question it answers | Where | Run with | Latest result |
|---|---|---|---|---|
| Test suite | Does each check behave as written? | `test/*.test.ts` (77 files) | `npm test` | 1,348 tests: 1,347 pass, 1 skipped (a differential test that needs a live pip, named by `WORMSIGN_PIP_REF`); the real pip and uv suites of `test/harden-real.test.ts` run only with `HARDEN_REAL=1` |
| 1. Rule coverage | Can every rule actually fire through the real CLI? | `test/validation-coverage.test.ts` | `npm test` | 46 of 46 rules produced |
| 2. IOC recall | Does every indicator that ships reach its rule? | `test/validation-recall.test.ts` | `npm test` | every testable indicator found; hashes untestable (0 / 20) |
| 3. Wave replays | Would the reported waves, rebuilt inertly, fail the gate? | `test/validation-replay.test.ts`, `test/fixtures/replay/` | `npm test` | all 4 fail the recommended pull-request gate (`diff`, `scan`, `soak --base`); `scan` and `diff` alone fail 3, and pass Mini Shai-Hulud, which only `soak` fails (its git dependency, WS-SK-002) |
| 4. Mutation check | If a rule's core condition is deleted, does any test notice? | `scripts/mutation-check.mjs` | `npm run mutation` | 974 mutants in 73 modules; 651 killed at least once, 323 hand-applied by their authors with the script's run pending (section 4) |
| Real-world evidence | How long should the soak be? How noisy is scan on real projects? Does soak work against the live registry? | [docs/evidence/](#evidence-from-real-data) | scripts named on each page | see each page |
| On GitHub | Do the suite and the gates pass on GitHub's runners, and does the gate fail a bad change? | `.github/workflows/` | push, pull request, schedule | [Release status](installation.md#release-status) |

All three test layers call the real CLI entry point (`run()` in `src/main.ts`) with `--format json` and read the
report, so argument parsing, IOC loading, baseline handling and exit codes are tested too. Every scan, diff and
audit-org run in them names its IOC data with `--iocs` (`test/fixtures/iocs` for layer 1, the bundled `data/iocs`
for layers 2 and 3), so a local `update-iocs` cache cannot change a result. CI runs the suite on Node 22 and 24 on
every pull request whose gate passes ([why and how](../CONTRIBUTING.md#pull-requests)) and on every push to `main`.

## 1. Rule coverage

Every rule ID in `src/rules.ts` (46, listed in [rules.md](rules.md)) must be produced through a real entry point.
`RULES` is read at run time, so a rule added without a scenario fails the test, and so does a rule ID a scenario
produces that is not in `src/rules.ts`. It does not show that a rule catches what attackers ship (layer 3 shows misses),
and the registry, OSV and GitHub answers are fakes shaped like the documented APIs, not recordings.

| Rules | Produced by |
|---|---|
| WS-LC-001 to 003, WS-LK-001 to 003, WS-GH-001 to 007, WS-FS-001, WS-EX-001 and 002, WS-PS-001 and 002 | scan of `test/fixtures/malicious` (WS-PS asserted by `test/persistence.test.ts`) |
| WS-FS-002, WS-SC-900, WS-LC-004, WS-NM-001 | scan: an unknown payload, a manifest that is not JSON, a `.pnpmfile.cjs`, `--node-modules` |
| WS-DF-001 to 006 | diff of two trees (WS-DF-006: a changed `bun.lock`, which wormsign does not parse) |
| WS-SK-001 to 006, WS-RG-001 to 003, WS-OS-001, WS-OS-900 and 901 | soak against a fake registry, PyPI index and OSV, `--config-only`, and `--on-outage warn` against hosts answering HTTP 503 |
| WS-OR-001 to 004, WS-OR-900 | audit-org against a fake GitHub, with and without the audit-log API |
| WS-BL-001 | an expired baseline entry |

The test prints the full table, one row per rule with every scenario that produced it.

## 2. IOC recall over the bundled data

The test writes every indicator in `data/iocs` into the kind of file wormsign reads and checks that it reaches its
rule, so a parser change that made one lockfile format invisible would show here.

| Indicator | Written as | Rule | Recall |
|---|---|---|---|
| package@version | npm lockfile v3 and v1, pnpm v9, yarn.lock v1 and v8 | WS-LK-001 | 3,704 / 3,704 in each |
| workflow file names | `.github/workflows/<name>` | WS-GH-001 | 5 / 5 |
| runner names | `runs-on:` and `config.sh --name` | WS-GH-006 | 2 / 2 checks for 1 name |
| endpoints, refanged | a string literal in `src/exfil.js` | WS-EX-002 | 1 / 1 |
| payload names | `postinstall: node <name>` | WS-LC-003 | 5 / 5 |
| payload names above info | a file of that name | WS-FS-002 | 4 / 4 (`bundle.js` is info by design) |
| repository patterns | a repository name or description | WS-OR-001 | 6 / 6 |
| workflow names and branches | default-branch listing, matching refs | WS-OR-004 | 8 / 8 |
| runner names | a repository runner | WS-OR-003 (critical) | 1 / 1 |
| SHA-256 hashes | not synthesised | WS-FS-001 | 0 / 20 testable |

Recall counts unique versions ([iocs.md](iocs.md#what-ships)); the lockfiles follow real ones in
`test/fixtures/lockfiles`. Controls:

- every synthesised lockfile must parse (no WS-SC-900);
- an ordinary repository in the fake organization must not match;
- `endpoints.json` must hold every endpoint defanged, and a scan of wormsign's own IOC data must report none of them.

It does not show that the IOC data is complete or correct: vendor lists hold only versions someone caught, and
versions are checked against their sources by `scripts/verify-ioc-sources.mjs` and by re-running
`scripts/import-package-sets.mjs`, not here. pnpm lockfile 5.4 and 6.0 have parser tests on real output instead, and
npm lockfile v2 (read by the v3 code) has no real-output fixture.

**Hash IOCs** cannot be tested without the malware, which this project never downloads; each is checked against the
vendor page it cites instead ([provenance](iocs.md#provenance-and-how-it-is-enforced)).

## 3. Wave replays

Each directory under `test/fixtures/replay/` inertly rebuilds what one reported wave writes (lifecycle script,
payload names as one-line markers, workflows, hook files), with `.invalid` endpoints and a cited source for every
feature. `test/validation-replay.test.ts` asserts the exact rule IDs and exit code at `--fail-on high` for `scan`,
for `diff` and `soak --base` of a pull request that adds the replay, and for the README's gate: one Action call that
runs `diff`, `scan` and `soak` with the base (`test/action.test.ts` runs it on the 2026-04 replay).

| Wave | Sources | scan | diff | soak --base | scan or diff alone | diff + scan + soak --base |
|---|---|---|---|---|---|---|
| 2025-09 | StepSecurity, Socket | LC-001, LC-003, GH-001, GH-002 | DF-002, DF-003, LC-003, GH-001, GH-002 | SK-003 (medium: no lockfile, no release-age setting) | fails | fails |
| 2025-11 | Socket, Wiz, Datadog | LC-001, LC-003, FS-002, GH-001, GH-002, GH-004, GH-007 | DF-002, DF-003, LC-003, GH-001, GH-002, GH-004, GH-007 | SK-003 (medium) | fails | fails |
| 2026-04 and 2026-05 (Mini Shai-Hulud) | Picus only | LC-001, LK-002 (both medium) | DF-002, LK-002 (both medium) | **SK-002 (high: the git dependency)**, SK-003 (medium) | **passes** | fails, on `soak` only |
| 2026-08 | JFrog (Wiz for the workflow's write command, a placeholder) | LC-001, GH-001, GH-002, PS-001, PS-002 | DF-002, DF-003, GH-001, GH-002, PS-001, PS-002 | SK-003 (medium) | fails, on the workflow, the folder-open task and the hook | fails |

What the replays found:

- **WS-GH-005 misses the worms' own exfiltration steps.** They bind `${{ toJSON(secrets) }}` to an environment variable,
  which the check does not count as a secret (nor a secret a script assigns to a shell variable and uses on a later
  line), and the 2025-11 and 2026-08 ones write it through a heredoc the line-by-line check does not read. WS-GH-002
  still reports the dump, so the gate fails.
- **Only `soak` fails Mini Shai-Hulud.** No heuristic or file-name IOC matches, and its optional git dependency, whose
  `prepare` script runs at install, is only a medium WS-LK-002 in `scan` and `diff`; npm 10.9.2 recorded no
  install-script flag for it, so WS-DF-001 cannot fire. `soak --base` reports it as WS-SK-002, high, without asking the
  registry or OSV. `diff` alone passes it; the Action's default on `pull_request`, which runs all three, fails it.
- **Persistence files:** the August 2026 ones are rebuilt from JFrog's description and fail as WS-PS-001 and
  WS-PS-002. Picus does not say what the Mini Shai-Hulud ones run, so that replay keeps markers.
- **The August 2026 package alone gives one medium finding;** WS-LK-001 (when listed) and `soak` catch it.
- **A camelCase `postInstall` does not run** under npm 10.9.2, so wormsign is right not to report it.

Replays say nothing about GitHub-side state (audit-org's, layer 2) or host-side behaviour
([detections/](../detections/README.md) covers it for SIEMs). A variant that changes a file name or script defeats the
IOC-based rules, leaving the heuristics, the persistence rules and the soak gate.

## 4. Mutation check

The mutation check switches off one decision at a time (for example "never report an IOC package version") and runs
the whole suite: a mutant the suite catches is "killed", one it misses "survives". The 974 mutants in 73 modules
(`scripts/mutants-<module>.mjs`) are hand-written, one per rule condition or safety property, not generated operator
changes, so the check says whether the suite notices a decision going missing, not how well it pins every boundary.

`scripts/mutation-check.mjs` runs `npm test` on a temporary copy of the repository per mutant, after the unmutated
copy passes. It exits 1 if any mutant survives, does not compile, times out, or names text its file no longer
contains exactly once. Mutants run one at a time because the suite has timing assertions. A hang inside a test file
hits that file's ten-minute timeout and counts as killed; a hang outside any test file hits the 20-minute limit per
mutant and is reported as TIMEOUT.

```sh
npm run mutation -- --check             # 974 mutants, every one names text that occurs exactly once
npm run mutation -- --module <name>     # one module; --list-modules names them
npm run mutation -- --only "<name>"     # named mutants
```

`--check` runs in CI on every pull request whose gate passes and every push to `main`. The full check runs monthly
and on demand (`gh workflow run ci.yml -f slow=true`), one job per module: `--list-modules` builds the job matrix, so
a new module gets a job without a workflow edit, and the script refuses a module of more than 18 mutants.
`test/mutation-modules.test.ts` checks both.

651 of the 974 have been killed at least once. The other 323, added or changed in the pre-publication reviews or
since, were hand-applied by their authors against the tests that cover them; the script has not run them yet. No
single run has yet covered all 974 on one commit; that first full CI run in this repository will be, and it will be
linked from [Release status](installation.md#release-status). The kill record, the timings and the module list are in
[evidence/test-runs.md](evidence/test-runs.md#mutation-check).

**Proves:** for each listed decision, at least one test fails when it is removed. **Does not prove:** that the
failing test checks the right thing. Many mutants are killed by `sarif: golden file for the synthetic malicious
project`, which shows the report changed, not that a test aimed at that rule did. Nor does it cover decisions not in
the list: the registry signals (WS-RG-001 to WS-RG-003) have unit tests and coverage scenarios, but no mutant.

## Evidence from real data

The layers above use synthetic inputs. These pages use real ones; the four studies publish their inputs and outputs
with SHA-256.

- [soak-latency.md](evidence/soak-latency.md): how long Shai-Hulud versions were installable before an advisory
  listed them; over five waves, the slowest version was listed at 77.4 hours (three method artefacts corrected),
  and the registry proves removal within 72 hours for only 21% to 58% of a wave's versions.
- [false-positives.md](evidence/false-positives.md): how noisy `scan` is on 15 popular repositories. With no
  baseline, 8 fail its default gate, all on by-design findings that need a baseline entry; 1 of all 1,591 findings
  is a false positive. The scanner was tuned on this corpus, and an AI agent labelled it with no person checking.
- [soak-live.md](evidence/soak-live.md) and [soak-py-live.md](evidence/soak-py-live.md): `soak` against the live npm
  registry, PyPI and OSV, with controls whose answer is known.
- [skill-eval.md](evidence/skill-eval.md): whether Claude Code follows the agent skill (`scripts/skill-eval.mjs`, run
  by hand, not by `npm test` or CI).
- [package-managers.md](evidence/package-managers.md): which package-manager settings were verified, on which
  versions.
- [pypi-incidents.md](evidence/pypi-incidents.md): the PyPI incidents the design drew on.

## Other checks on the checks

- **Self-scan with a positive control** (`npm run self-scan`, in CI): wormsign must report no unbaselined finding at
  `--fail-on info` on a copy of its own repository (the files git would commit), then must fail with WS-GH-001 once
  an inert IOC-named workflow is added. The repository's `.wormsign-baseline.json` ignores only `test/fixtures`,
  `test/golden` and `data/iocs` and suppresses eight reviewed findings by fingerprint, so the control also shows the
  baseline does not hide a new workflow.
- **Action self-test** (`.github/workflows/action-selftest.yml`): runs the Action with `uses: ./` against
  `test/fixtures/action`; a malicious diff and scan must fail and a harmless diff pass
  ([github-action.md](github-action.md#how-the-action-is-tested)).
- **Hardening script** (`test/harden.test.ts`): runs `harden-dev.sh` under every bash it finds against stub package
  managers that answer like the real versions in [package-managers.md](evidence/package-managers.md).
- **Detections** (`test/detections.test.ts` and the sigma-cli commands in
  [detections/](../detections/README.md#what-is-validated)): every CI pattern and Sigma rule matches its positive
  examples and no negative one. `test/detections-queries.test.ts` runs the committed Splunk and ES|QL queries on small
  models of each language; the tests also check the README's hunt and scheduling advice.

## Runs on GitHub

This repository's runs are recorded under [Release status](installation.md#release-status). One run from the
private development repository is kept here because it will be repeated in public: the canary.

### The canary pull request

A gate that has only ever passed says nothing about whether it can fail. The canary is a draft pull request, never
merged, that adds one inert file, `.github/workflows/shai-hulud-workflow.yml`: a published IOC name with no jobs. The
gate job, built from `main` ([why](github-action.md#why-it-is-built-this-way)), has to fail it. In the development
repository it did, on 2026-10-03:

```text
CRITICAL WS-GH-001  .github/workflows/shai-hulud-workflow.yml
MEDIUM   WS-DF-003  .github/workflows/shai-hulud-workflow.yml
wormsign diff: 2 finding(s) (1 critical, 0 high, 1 medium, 0 low, 0 info)
wormsign soak: 0 finding(s) (0 critical, 0 high, 0 medium, 0 low, 0 info)
...
wormsign scan: 2 finding(s) (1 critical, 0 high, 1 medium, 0 low, 0 info), 6 baselined
diff: failure   soak: success   scan: failure
```

The last line is the Gate step, which reads each step's `outcome`, before `continue-on-error`
([steps context](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#steps-context)), and
failed the job. The canary shows the check fails, not that the change is blocked: without branch protection a failed
check does not stop a merge. It does not exercise the build-from-base design either.

## Limitations

- The scanner has never been run on live samples.
- Bun lockfiles are not parsed: they fail closed (WS-SC-900, WS-SK-002, WS-DF-006), and a Bun project's locked
  packages get no IOC or soak check.
- Recall measures the data that ships, not what an attacker publishes next. The soak gate, the OSV and registry
  signals, the persistence rules and the heuristics cover a version no vendor has listed, and the replays show they
  do not catch everything.
- One OSV test replays a real `api.osv.dev` response; the other fake GitHub, registry and OSV answers are not
  recorded from the live APIs. audit-org's results come from the fake GitHub only.
