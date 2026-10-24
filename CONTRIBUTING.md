# Contributing to wormsign

wormsign aims for code a reviewer can read file by file and explain line by line. [AGENTS.md](AGENTS.md) is the
short form of this page.

Vulnerabilities in wormsign go through private reporting, not issues ([SECURITY.md](SECURITY.md)). Participation
follows the [Code of Conduct](CODE_OF_CONDUCT.md). One maintainer works best effort, with no SLA; security reports
get the [response SECURITY.md describes](SECURITY.md#response).

## Development setup

Use Node 24.14.1 or later: older npm reads `.npmrc`'s `min-release-age` and ignores it
([why](docs/installation.md#why-node-24)). wormsign itself runs on Node 22 or later.

```sh
git clone https://github.com/stgllghr/wormsign.git
cd wormsign
npm ci --ignore-scripts   # install exactly the lockfile, run no install scripts
npm test                  # builds with tsc, then runs every test in dist/test
npm run lint              # eslint, then a type check
npm run self-scan         # wormsign scan of this repository; any unbaselined finding fails it
shellcheck harden-dev.sh scripts/*.sh   # CI runs this too
```

`npm ci --ignore-scripts` is the only install command this project uses; a new development dependency that needs
an install script needs a good reason. CI runs `shellcheck` at its default severity, so waive a finding inline, next
to the line, with a `# shellcheck disable=SCxxxx` comment that says why, never in the workflow.

One test file, and only the `harden-dev.sh` tests:

```sh
npm run build && node scripts/run-tests.mjs dist/test/docs-rules.test.js
npm run test:harden
```

Scan this repository with `npm run self-scan`, not `wormsign scan .`: a built checkout holds `dist/test`, whose IOC
strings an in-place scan reports as real findings
([how self-scan works](docs/validation.md#other-checks-on-the-checks)). A change that needs an indicator-shaped string
adds a baseline entry with a justification.

`npm test` and `npm run self-scan` use no network: tests replace the calls of `soak`, `audit-org` and `update-iocs`
with fakes.

**The mutation check** switches off one rule or fail-closed property per mutant and requires `npm test` to fail
([how it works](docs/validation.md#4-mutation-check); [each module](docs/evidence/test-runs.md#mutation-check)). Each
mutant is a full test run, and the suite has timing assertions, so run one module or a few mutants at a time on an
idle machine. Mutants live in `scripts/mutants-<module>.mjs`, at most 18 per module.

```sh
npm run mutation                          # every mutant
npm run mutation -- --module core-diff    # one module's mutants
npm run mutation -- --check               # only check that each mutant's text still exists (seconds)
npm run mutation -- --only "<mutant name>"   # one or more mutants from any module, comma-separated
npm run mutation -- --list-modules        # the module names, as a JSON array
```

## Principles

Every change is judged against these; the pull request template repeats them as a checklist.

- **No npm runtime dependencies**, and one vendored parser that is never edited
  ([ADR 0005](docs/adr/0005-no-runtime-dependencies.md),
  [the parser](docs/architecture.md#one-vendored-pinned-verified-toml-parser)).
- **Fail closed**: what cannot be checked is a finding at a severity that fails the gate when the gap matters
  ([ADR 0001](docs/adr/0001-fail-closed.md)).
- **Every IOC has a public https source**, and package versions are imported, never typed
  ([iocs.md](docs/iocs.md#provenance-and-how-it-is-enforced)).
- **Every behaviour change has a test that fails when the change is reverted**; rules and fail-closed properties
  also get a mutant ([AGENTS.md](AGENTS.md)).
- **Small, explainable code**: cite the documentation or measured behaviour behind a non-obvious fact in a comment
  next to the code.
- **No network in `scan` or `diff`, no telemetry**, and only synthetic, inert fixtures.

## Adding an IOC

IOC data lives in five JSON files in `data/iocs` ([format](docs/iocs.md#file-format)); read each file's
`description` field, which explains its conventions, before editing it.

1. Find the most specific public https page that prints the indicator: a vendor write-up or an advisory, not a
   news story.
2. Add the entry, copying the string exactly as the page prints it. Store endpoints defanged (`[.]` for each `.`).
   Package lists are imported by `scripts/import-package-sets.mjs`, never typed: to cover a new report, propose a
   parser and a `REPORTS` entry in `scripts/vendor-pages.mjs`, and the maintainer runs the import
   ([recipe](docs/iocs.md#refreshing-the-package-sets)). A version listed in error goes in
   [`exclusions`](docs/iocs.md#exclusions-versions-a-source-lists-in-error).
3. Set `"version"` to today's date in **all five** files; the loader rejects files that disagree.
4. Run `npm test`. `test/validation-recall.test.ts` requires every bundled indicator, except hashes, to be
   reported.
5. In the pull request, give the source URL, a quote of the text around each new string, and the SHA-256 of your
   saved copy of the page if you have it. The maintainer records the snapshot in `SNAPSHOTS` and runs
   `node scripts/verify-ioc-sources.mjs <saved-pages-dir>`.

With only an indicator and a source, open a "New IOC" issue instead.

## Adding a rule

1. Add an entry to `RULES` in `src/rules.ts`: an `id` in its family (`-9xx` is reserved for "could not check"), a
   kebab-case `name`, a `description` and a `help` text that says what to do.
2. Implement it next to the related checks with `makeFinding`. Choose a `key` that stays the same while the finding
   means the same thing: a baseline entry suppresses exactly that fingerprint.
3. Add a test that fires the rule and one that shows a near miss does not, and a scenario in `SCENARIOS` in
   `test/validation-coverage.test.ts`.
4. Add a mutant that switches off the rule's core condition, and run `npm run mutation -- --only "<its name>"`.
5. Regenerate the SARIF golden file (below).
6. Add the ID to `RULE_META` in `scripts/gen-rules-doc.mjs`, run `npm run docs:rules` and commit `docs/rules.md`.
7. Document it on its command page (`docs/cli/*.md`) and in `docs/validation.md`; if it changes what covers a
   stage of the attack, also in the README's table and `docs/threat-model.md`.

## Baselines and golden files

A baseline entry needs a justification, and takes effect in pull-request gates only after merge, with owner review
([baseline.md](docs/baseline.md)).

`test/golden/malicious.sarif.json` is the SARIF report for `test/fixtures/malicious`. When a change alters it on
purpose, regenerate and review every line; an unexplained change is a regression:

```sh
UPDATE_GOLDEN=1 npm test
git diff test/golden/
```

`test/golden/npm-soak-identical.json` changes only with `UPDATE_NPM_SOAK_GOLDEN=1 npm test`, and the pull request
lists every changed line. Fixture lockfiles are changed only by hand. Dependabot alerts on them are expected and
dismissed; Dependabot security updates stay off, so it never rewrites one.

## Pull requests

1. Open an issue first for anything larger than a fix. Keep each pull request to one change, with its tests and
   docs, and fill in the template.
2. Before pushing, run the [setup](#development-setup) checks, and `npm run mutation` if you changed a rule or a
   fail-closed path.
3. CI runs wormsign's own gate first. `wormsign.yml` calls `ci.yml` and `action-selftest.yml` after its gate job,
   so they run on a pull request only when the gate passes. A change the gate fails by design (install-time config
   or the baseline, WS-DF-005) gets them only when the maintainer runs `gh workflow run ci.yml --ref <branch>` and
   `gh workflow run action-selftest.yml --ref <branch>` after review. The gate does not read `data/iocs`
   ([what checks IOC changes](docs/iocs.md#provenance-and-how-it-is-enforced)).
4. Paths in `.github/CODEOWNERS` need the owner's approval.

Commit messages say what changed and why, in the imperative. By contributing you agree that your contribution is
licensed under the [MIT License](LICENSE).

## Releasing (maintainer)

First check the [release scope and readiness checklist](docs/release-readiness.md). A passing unit suite is not a
substitute for inspecting and installing the actual packed artifact. CI and the release workflow each build one
tarball, then install that same artifact on Node 22 and 24 with `scripts/ci-pack-smoke.sh`, including the external
library consumer and shipped examples. Publication waits for both release consumers.

1. Update the version in `package.json` and `package-lock.json`, update the shipped examples' version, date the
   release in `CHANGELOG.md`, and merge through a pull request.
2. Run the slow CI jobs on that exact `main` commit (`gh workflow run ci.yml --ref main -f slow=true`). Wait for
   every job, including every mutation module, to pass. Inspect the `mutation-<module>` artifacts: these retain
   the runner's verdicts and printed failure diagnostics for thirty days, including unsuccessful jobs. They are
   transcripts, not independent review or complete per-test logs. Download any evidence needed for the release
   before it expires. If source changes, repeat the checks on the new candidate commit.
3. `scripts/ci-release-tag.sh <version>` makes the tag commit, which adds only `dist/src`
   ([how it is checked](docs/github-action.md#how-the-action-gets-its-compiled-code)). Push the tag;
   `release.yml` rebuilds, packs, attests and publishes it.
4. [Check the release](docs/installation.md#check-a-release-tag-yourself), record it under
   [Release status](docs/installation.md#release-status), and replace the README's `<release commit sha>`
   placeholders.
