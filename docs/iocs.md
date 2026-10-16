# IOC data

wormsign matches projects, installed packages and GitHub organizations against indicators of compromise (IOCs)
published by security vendors and advisories. The rule: **every IOC has a public https source; if it cannot be
sourced, it stays out.** Single indicators are copied from the page they cite; package versions come only from openly
licensed datasets.

## What ships

Five JSON files in [`data/iocs/`](../data/iocs), version `2026-10-02` ([format](#file-format)).

| File | Holds | Entries | Rules that use it |
|---|---|---|---|
| [`packages.json`](../data/iocs/packages.json) | compromised `name@version` pairs in 6 sets, plus `exclusions` | 4,186 entries across the sets; 3,704 distinct versions of 1,629 names; no exclusions | WS-LK-001 (lockfiles, and installed packages with `--node-modules`); in `diff`, for the entries a change adds |
| [`files.json`](../data/iocs/files.json) | payload SHA-256 `hashes` and payload file `names` | 20 hashes, 5 names | WS-FS-001, WS-FS-002, WS-LC-003, harden-dev H11 |
| [`workflows.json`](../data/iocs/workflows.json) | injected workflow file names and self-hosted runner names | 5 workflow names, 1 runner name | WS-GH-001, WS-GH-006, WS-OR-003, WS-OR-004 |
| [`repos.json`](../data/iocs/repos.json) | repository name and description `patterns`, and worm `branches` | 6 patterns, 3 branches | WS-OR-001, WS-OR-004 |
| [`endpoints.json`](../data/iocs/endpoints.json) | exfiltration endpoints, stored defanged | 1 endpoint | WS-EX-002 |

`soak` does not read IOC data. Its controls are the soak time, OSV records and registry signals ([soak.md](soak.md)).

### Package sets

Every package version comes from one of two datasets under the Apache License 2.0, read at a pinned commit by
[`scripts/import-package-sets.mjs`](../scripts/import-package-sets.mjs), never typed by hand:

- **Datadog's [`consolidated_iocs.csv`](https://github.com/DataDog/indicators-of-compromise/blob/33e44afbb1b72f3da4f990096d216a44a28c7b72/shai-hulud-2.0/consolidated_iocs.csv)**
  (commit `33e44af`), for the November 2025 wave, imported whole. Datadog merged seven vendors' lists and removed
  three packages it judged false positives. Every row names Wiz, whose own list carries no licence; wormsign relies
  on Datadog's licence and takes only names and versions.
- **[OpenSSF malicious-packages](https://github.com/ossf/malicious-packages)** (commit `fcea5cb`), for the other
  waves. A version is imported when a vendor report lists it **and** an OpenSSF record lists the same version. The
  report is the `source` a finding cites; the record ids are in the set's `records`.

Attribution and Datadog's `NOTICE` are in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md); the licence ships as
[`data/iocs/LICENSES/Apache-2.0.txt`](../data/iocs/LICENSES/Apache-2.0.txt).

| Set `id` | Wave | Data | Cited report (`source`) | Listed by the report | Loaded | Unmatched |
|---|---|---|---|---|---|---|
| `openssf-shai-hulud-1-stepsecurity` | 2025-09 | OpenSSF | [StepSecurity](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised) | 195 packages, 484 versions | 195, 484 | 0 |
| `openssf-shai-hulud-1-socket` | 2025-09 | OpenSSF | [Socket](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages) | 198, 526 | 197, 525 | 1 |
| `datadog-shai-hulud-2.0` | 2025-11 | Datadog | the CSV itself, at its commit | 795, 1,091 | 795, 1,091 | n/a |
| `openssf-mini-shai-hulud-picus` | 2026-04 | OpenSSF | [Picus](https://www.picussecurity.com/resource/blog/mini-shai-hulud-the-npm-supply-chain-worm-explained) | 4, 4 | 4, 4 | 0 |
| `openssf-mini-shai-hulud-may-2026-stepsecurity` | 2026-05 | OpenSSF | [StepSecurity](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem) | 170, 344 (npm rows) | 170, 344 | 0 |
| `openssf-shai-hulud-aug-2026-jfrog` | 2026-08 | OpenSSF | [JFrog](https://research.jfrog.com/post/shai-hulud-is-back-august/) | 463, 1,738 | 463, 1,738 | 0 |

All sets were retrieved on 2026-10-02. The two 2025-09 sets share 482 versions, so counted once, and with no version
in more than one wave, the waves hold:

| Wave | Versions | Packages |
|---|---|---|
| 2025-09 (Shai-Hulud) | 527 | 197 |
| 2025-11 (Shai-Hulud 2.0) | 1,091 | 795 |
| 2026-04 (Mini Shai-Hulud) | 4 | 4 |
| 2026-05 (Mini Shai-Hulud: TanStack and others) | 344 | 170 |
| 2026-08 | 1,738 | 463 |
| All | 3,704 | 1,629 |

Left out by design: other ecosystems' rows (JFrog's Go modules, StepSecurity's two PyPI rows); a version a report
lists that no OpenSSF record lists (one, `@teriyakibomb/ember-velcro@2.2.1`, kept in `unmatched`); and versions a
record lists that the report does not (96, 58, 61 and 542 in the StepSecurity 2025-09, Socket, StepSecurity May 2026
and JFrog sets), which `soak`'s OSV lookup still sees.

Each set's `note` records how the parse was cross-checked against the report's own totals, and
[`test/iocs-data.test.ts`](../test/iocs-data.test.ts) pins every set's counts.

### Other indicators, by wave

| Wave | Hashes | File names | Workflow names | Runner names | Repo patterns | Branches | Endpoints |
|---|---|---|---|---|---|---|---|
| 2025-09 (Shai-Hulud) | 7 | 1 | 2 | 0 | 2 | 1 | 1 |
| 2025-11 (Shai-Hulud 2.0) | 7 | 4 | 2 | 1 | 2 | 1 | 0 |
| 2026-04 (Mini Shai-Hulud) | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| 2026-08 | 6 | 0 | 1 | 0 | 1 | 1 | 0 |

The 2026-05 wave has none. One 2026-08 hash has no published file name (JFrog's "runner memory scraper"), so only
`scan --hash-all` checks it.
Every scan without `--hash-all` says so:

```
note: 1 hash IOC(s) have no published file name and are checked only with --hash-all: (runner memory scraper)
```

### What is not covered

- **Waves with little data.** The 2026-04 wave has four versions and one repository pattern. The May 2026 wave has
  StepSecurity's 344 versions (a list the page says "is growing") and no other IOC. For versions no set lists, `soak`'s
  OSV lookup (WS-OS-001) and soak time (WS-SK-001) are the control.
- **The 2026-08 payload names are hash IOCs only.** A default scan hashes `setup.mjs` and `math_init.js` but never
  reports the name alone, so `"preinstall": "node setup.mjs"`, the 2026-08 republish signature, gets only WS-LC-001
  and passes the default `--fail-on high` gate:

  ```
  MEDIUM   WS-LC-001  package.json:1
           "preinstall" script runs on install for every consumer of this package: node setup.mjs
  ```

  [validation.md](validation.md) records the same miss in its Mini Shai-Hulud replay.
- **Later variants' persistence files.** The `gh-token-monitor` LaunchAgent and systemd unit are not in the IOC data;
  `harden-dev.sh` H14 checks for them
  ([incident-response.md](incident-response.md#1-isolate-the-machine-before-revoking-anything)).
- **Payload hashes are not checked against samples**: this project never downloads malware
  ([validation.md](validation.md#2-ioc-recall-over-the-bundled-data)).
- **Vendor lists hold only what was caught** ([how fast it became public](evidence/soak-latency.md)).

## File format

Every file is a JSON object with `schema` (must be `1`), `version` (a real `YYYY-MM-DD` date, the same in all five),
a `description` of its conventions, and its arrays. Every entry has a `wave` (year and month) and an https `source`;
`note` is optional.

| Array | Fields besides `wave`, `source` and `note` |
|---|---|
| `packages.json` `sets` | `id`, `retrieved`, `dataset` (`name`, `url`, `commit`, `path`, `license`), `packages` (name to versions); OpenSSF sets also `records` (name to OSV ids) and `unmatched` |
| `packages.json` `exclusions` | `set`, `name`, `version`, `checked` (date), `reason`, `evidence` (https URLs) |
| `files.json` `hashes`, `names` | `sha256` (64 lower-case hex) and `name` (a basename, or a `(label)`); `name` and `nameOnlySeverity` |
| `workflows.json` `workflowFiles`, `runnerNames` | `name`, `severity`; `name` (letters, digits, `.`, `_`, `-` only) |
| `repos.json` `patterns`, `branches` | `id`, `match` (`nameExact`, `nameContains`, `descriptionExact`, `descriptionContains` or `nameRegexAndDescriptionExact`), `name` / `nameRegex` / `description`, `severity`; `name` (a trailing `*` makes it a prefix) |
| `endpoints.json` `endpoints` | `substring` (defanged), `severity` |

`nameOnlySeverity` is what a file name alone counts for: `bundle.js`, a common legitimate name, is `info` and is
reported only when a lifecycle script runs it (WS-LC-003) or its hash matches; the other four are `high`. Workflow and
repository severities reflect how specific the name is: `codeql_analysis.yml` is `medium`.

## Provenance and how it is enforced

| Layer | What it checks | When it runs |
|---|---|---|
| The loader, [`src/iocs.ts`](../src/iocs.ts) | An https `source` on every entry and set; well-formed values; a repository `nameRegex` of at most 100 characters, with no backreference or repeated group and at most 2 variable-length quantifiers; one real date in all five files; valid, still-matching exclusions; files of at most 16 MiB; capped lists (about 50 times the data of 2026-10-02) | every `scan`, `diff`, `audit-org` and `update-iocs`, and H11; a failure is exit 2, never a scan with fewer IOCs |
| [`scripts/verify-ioc-sources.mjs`](../scripts/verify-ioc-sources.mjs) | Every per-entry string appears verbatim on a saved copy of its cited page (`SNAPSHOTS` in [`scripts/vendor-pages.mjs`](../scripts/vendor-pages.mjs) records each copy's SHA-256), and every OpenSSF set equals a fresh parse of its report | by the maintainer, before an IOC change merges |
| [`scripts/import-package-sets.mjs`](../scripts/import-package-sets.mjs) | Regenerates the sets from a clean, Apache-2.0 checkout of the expected repository; records the commit | by the maintainer ([refreshing](#refreshing-the-package-sets)) |
| [`test/iocs-data.test.ts`](../test/iocs-data.test.ts) | Each set's Apache-2.0 dataset and commit, as THIRD_PARTY_NOTICES.md links it; the licence text; per-set counts | `npm test` |
| [`test/validation-recall.test.ts`](../test/validation-recall.test.ts) | Every bundled indicator must be reported | `npm test` |
| [`.github/CODEOWNERS`](../.github/CODEOWNERS) | Review of every `data/iocs/` change | every pull request |

The saved pages are third-party content and not committed, so only their holder can run `verify-ioc-sources.mjs`.
Against the maintainer's copies on 2026-10-02 it printed
`60 IOC strings and 5 package sets checked, 0 failed`, and re-running the import at the recorded commits left
`data/iocs/packages.json` byte-identical. A removed entry is caught only by review and the per-set counts: the recall
test cannot notice what is gone, and the CI gate does not inspect `data/iocs`.

The loader refuses data without provenance. With the `source` removed from one workflow entry:

```console
$ wormsign scan test/fixtures/clean --iocs "$TMPDIR/iocs-copy"
wormsign: workflows.json shai-hulud-workflow.yml: every IOC entry needs an https source URL
$ echo $?
2
```

## Defanging

Endpoints are stored defanged, with `[.]` for each `.` (`webhook[.]site/bb8ca5f6-...`), and the loader refangs them.
`scan --node-modules` checks IOC endpoints inside `node_modules`, where wormsign's own data files sit wherever it is
a dependency; stored refanged, the data would report itself. File and workflow names are not defanged: they match
paths, not contents. [`test/iocs-data.test.ts`](../test/iocs-data.test.ts) checks both.

## Exclusions: versions a source lists in error

The import never edits a dataset's list: an `exclusions` entry tells the loader to drop a version listed in error.
It needs a `reason`, a `checked` date and https `evidence`, and the loader rejects one that no longer drops
anything. The bundled data has none.

The soak-latency study ([anomalies](evidence/soak-latency.md#anomalies)) flagged three Socket wave-1 entries whose
publish dates do not fit the wave. Each was checked against the registry and advisories on 2026-10-02:

| Version | Decision | Evidence |
|---|---|---|
| `@teriyakibomb/ember-velcro@2.2.1` | **Not loaded**: no OpenSSF record lists it. | A personal fork of CrowdStrike's `ember-velcro`, published 2025-08-31T17:30Z, two weeks before the worm's `ember-velcro` 2.2.1 and 2.2.2; still on the [registry](https://registry.npmjs.org/@teriyakibomb%2fember-velcro), with no install scripts. No OSV record or GitHub malware advisory names it ([GHSA-c7v6-3628-q6w2](https://github.com/advisories/GHSA-c7v6-3628-q6w2) names `ember-velcro`). |
| `@rxap/ngx-bootstrap@19.0.3`, `19.0.4` | **Kept, as a judgement call.** | Dated 2025-03-07 and 2025-05-16, before the wave, and no longer served. Only GitHub's [GHSA-88g6-qjxg-cg72](https://github.com/advisories/GHSA-88g6-qjxg-cg72) (2025-09-18) names them; OSV [`MAL-2025-47455`](https://osv.dev/vulnerability/MAL-2025-47455) was imported from it: one source, not independent confirmation. |

`@dev-blinq/cucumber_client@1.0.1637-dev` (Datadog set) is on the registry with no advisory anywhere: likely a
listing error, but not verified, so it stays. `test/iocs-data.test.ts` pins these decisions. If OpenSSF adds a record
for the fork, a refresh loads it, and it then needs an `exclusions` entry.

## How update-iocs works

`wormsign update-iocs` caches newer, validated IOC data from `main` of this repository or from `--url`
([steps and messages](cli/update-iocs.md)). `scan`, `diff` and `audit-org` then **add** the cache's entries to the
bundled data; `--iocs <dir>` loads only that directory. Against a local https server holding the bundled data dated
a day later:

```console
$ wormsign update-iocs --url https://localhost:8443/iocs/
IOC data 2026-10-03 from https://localhost:8443/iocs/ written to $TMPDIR/.../cache/wormsign/iocs
IOC cache updated: 4186 package versions, 20 hashes, 5 workflow names
```

The package-version count sums the sets, so a version two vendors list counts twice.

### Trust model

- **The download is not signed.** Whoever can change `data/iocs/` on `main`, or the host behind `--url`, controls
  it. To fix what you get, pin `--url` to a commit:
  `https://raw.githubusercontent.com/stgllghr/wormsign/<commit-sha>/data/iocs/`.
- **The cache can only add.** A tampered cache can add false positives but cannot remove, soften or re-source a
  shipped IOC. Nor can it lower a generic finding: an added endpoint replaces WS-EX-001 (medium) only when it is at
  least medium itself (`src/checks/exfil.ts`; a test and a [mutant](validation.md#4-mutation-check) check this).
- **Its cost is bounded** by the loader's caps, which matters on a shared self-hosted runner where an earlier job can
  write the cache ([github-action.md](github-action.md#ioc-data)).
- **Corrections need a release.** A removed or corrected IOC stays active until users install a release with the
  fix; until then, baseline the finding with a justification that links the correction.

## Refreshing the package sets

The import reads both datasets from local clones and needs the maintainer's saved vendor pages, because the reports
select the OpenSSF records:

```sh
git clone --depth 1 https://github.com/DataDog/indicators-of-compromise.git "$TMPDIR/dd"
git clone --depth 1 --filter=blob:none --sparse https://github.com/ossf/malicious-packages.git "$TMPDIR/ossf"
git -C "$TMPDIR/ossf" sparse-checkout set osv/malicious/npm   # about 222,000 records
node scripts/import-package-sets.mjs --retrieved "$(date +%F)" \
  --pages <saved-pages-dir> --datadog "$TMPDIR/dd" --openssf "$TMPDIR/ossf"
git diff --stat data/iocs/packages.json
rm -rf "$TMPDIR/dd" "$TMPDIR/ossf"
```

The script prints each set's counts and the two commits, rewrites `sets`, and keeps the rest of `packages.json`.
Then:

1. Set `"version"` to the day's date in all five files.
2. If a commit changed, update its links in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) (the data test fails
   until they match) and the counts on this page.
3. Run `npm test`. Update the data test's pinned counts only after checking that a drop is the dataset's, not a
   parse failure.
4. Run `node scripts/verify-ioc-sources.mjs <saved-pages-dir>`.

## Adding or correcting an IOC

The checklist is in [CONTRIBUTING.md](../CONTRIBUTING.md#adding-an-ioc); with only an indicator and its source, open
a "New IOC" issue. To correct one:

- **A version listed in error:** add an `exclusions` entry ([above](#exclusions-versions-a-source-lists-in-error)),
  and consider reporting it upstream.
- **A wrong per-entry string:** fix it to match the cited page, or remove it if the source withdrew it; bump `version`.
- **A legitimate file in your project with a payload's name:** baseline the finding ([baseline.md](baseline.md)).

A missing or wrong IOC is a normal issue, not a security report ([SECURITY.md](../SECURITY.md#what-does-not)). A way
for IOC data to weaken a check is a security report.
