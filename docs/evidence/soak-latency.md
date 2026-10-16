# How long were Shai-Hulud versions installable before an advisory listed them?

For every compromised `name@version` in `data/iocs/packages.json`, this study measures the hours from npm publish to
the first public malware advisory listing that exact version, and whether the registry shows when it was removed. It
backs `wormsign soak`'s 7-day default and 72-hour tuned value
([soak.md](../soak.md#why-7-days-and-when-72-hours-is-enough)).

## Answer, by wave

Five waves of one worm family. A wave's versions share a detection event and are usually listed in bulk, so they
are not independent samples: read the per-wave table as the result. Per-version figures mostly reflect 2025-11 and
2026-08, which hold 2,689 of the 3,547 measured versions.

| Wave | Versions | Measured | Median (h) | p95 (h) | Slowest (h) | Removal proven within 72 h |
| --- | --- | --- | --- | --- | --- | --- |
| 2025-09 (Shai-Hulud) | 525 | 522 | 18.9 | 49.3 | 60.0 | 22.0% |
| 2025-11 (The Second Coming) | 1,091 | 1,041 | 11.0 | 14.9 | 20.2 | 57.9% |
| 2026-04 (Mini Shai-Hulud) | 4 | 4 | 28.4 | 36.1 | 36.1 | 1 of 4 |
| 2026-05 (Mini Shai-Hulud, TanStack and others) | 344 | 332 | 4.7 | 7.8 | 10.4 (corrected; 433.8 by the script) | 21.1% |
| 2026-08 | 1,738 | 1,648 | 5.8 | 12.2 | 77.4 | 58.1% |

- **Advisories.** In four waves (2026-05 with the [correction](#anomalies), which changes no median or p95) every
  measured version was listed within 72 hours; in 2026-08, 2 of 1,648 were listed after 77.4 hours. 7 days (168
  hours) is about 2.2 times that worst case: a margin over five waves, not a bound on the next.
- **Removal.** The registry proves removal within 72 hours for 21.1% to 58.1% of a wave's versions (1 of 4 in April
  2026). For the rest the removal time is unknown, not necessarily late.

**Per version:** 3,542 of the 3,547 measured versions (99.9%) were listed within 72 hours by the script's measure,
median 6.3 hours; with the three artefacts corrected, 3,545 (99.9%) within 72 hours and all 3,547 within 7 days.
Removal is proven within 72 hours for 49.2%, and within 7 days for 51.3%.

## The run

Retrieved 2026-10-09, 00:09 to 00:23 UTC, by [`scripts/soak-latency.mjs`](../../scripts/soak-latency.mjs) on macOS
(Node 23.11.0, which does not affect the served timestamps). Input:
[`data/iocs/packages.json`](../../data/iocs/packages.json), 3,704 unique `name@version` across 1,629 packages, in six
sets from five waves ([iocs.md](../iocs.md#package-sets)), all measured. The committed script and input are the ones
that ran:

| File | Size | SHA-256 |
| --- | --- | --- |
| script: [`scripts/soak-latency.mjs`](../../scripts/soak-latency.mjs) | 15,738 bytes | `efd9a7c7dde55a593fd33d8496ff3314590abaaf3cbf564cadf7460225f4a3dd` |
| input: [`data/iocs/packages.json`](../../data/iocs/packages.json) | 198,696 bytes | `91409b3cda3ce21a26664b0afe88b3a650626e57cfc67c7a3ceaaaa379524f21` |
| output: [`data/soak-latency.csv`](data/soak-latency.csv), one row per version with every intermediate time | 1,403,453 bytes | `909ac98fa5ca4b9ae9a4f913aa93ad19d6232e57f9bad4f2054fc85802c34832` |
| output: [`data/soak-latency-summary.md`](data/soak-latency-summary.md), the script's tables and tallies | 4,235 bytes | `dcedf5192e4bf9bc5941d482754f46dd1bdd1fd6264d839791bdbe2f28a3649a` |

The outputs are as the script wrote them. Values marked corrected or derived come from the CSV's `waves`,
`removal_bound_h` and `latency_h` columns.

## Method

Three public, read-only sources per version; nothing is downloaded or run.

| Source | What it gives |
| --- | --- |
| `registry.npmjs.org/<name>` (full packument) | `time[version]`: the publish time. `time` keeps an entry for a removed version, `versions` does not, so the packument also says whether the version is still installable. |
| `api.osv.dev/v1/query` | OSV `MAL-` records (OpenSSF malicious-packages). Each record carries `database_specific["malicious-packages-origins"]`: one snapshot per upstream report (GitHub malware advisories, Google, Amazon Inspector, OpenSSF package analysis), each with its own `modified_time`, its `import_time` and the versions it lists. |
| `api.github.com/advisories?type=malware&affects=<name>@<version>` | GitHub malware advisories that list the version, with `published_at`. |

**Latency** is the `modified_time` of the earliest OSV origin snapshot that lists this exact version, minus the
publish time (for the 29 versions no snapshot lists, the record's own date). It is per version because a record is
often created for a package's first bad versions and extended later, so its creation can predate a version's listing
(by more than an hour for 1,913 versions); record-level times are a separate lower bound. Versions published before
their wave's month are excluded from the headline.

**Controls.** The run aborts unless OSV and GitHub both list `@ctrl/tinycolor@4.1.1` (GHSA-qjqf-7j6f-82c4).
Afterwards: `@asyncapi/cli@4.1.1` returns no OSV record and no GitHub malware advisory; 33
rows (25 at random, plus every row over 72 hours, still live or published before its wave), fetched again without
the cache, matched the CSV in every column but `latency_bound_h`, which depends on the run's earliest publish (this
checks the data, not the matching); and a re-run over the saved cache reproduced the CSV byte for byte, and the
summary but its first line (the retrieval time).

## Results

Hours from registry publish to the first advisory listing the version (nearest-rank percentiles). The September 2025
StepSecurity and Socket sets share 482 versions; a version in several sets counts once per wave and headline row. A
wave with one set is shown once, with its set (the script's summary lists both).

| | versions | measured | min | p25 | median | p75 | p90 | p95 | max | <=24h | <=48h | <=72h | <=7d |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| set openssf-shai-hulud-1-stepsecurity | 484 | 481 | 1.6 | 12.4 | 18.9 | 31.2 | 49.0 | 49.4 | 60.0 | 69.9% | 86.3% | 100.0% | 100.0% |
| set openssf-shai-hulud-1-socket | 523 | 520 | 1.6 | 13.5 | 18.8 | 30.1 | 48.6 | 49.3 | 60.0 | 71.2% | 87.5% | 100.0% | 100.0% |
| wave 2025-09 | 525 | 522 | 1.6 | 13.5 | 18.9 | 30.1 | 48.6 | 49.3 | 60.0 | 71.1% | 87.4% | 100.0% | 100.0% |
| wave 2025-11 (set datadog-shai-hulud-2.0) | 1091 | 1041 | 0.2 | 8.0 | 11.0 | 12.6 | 13.3 | 14.9 | 20.2 | 100.0% | 100.0% | 100.0% | 100.0% |
| wave 2026-04 (set openssf-mini-shai-hulud-picus) | 4 | 4 | 28.4 | 28.4 | 28.4 | 29.2 | 36.1 | 36.1 | 36.1 | 0.0% | 100.0% | 100.0% | 100.0% |
| wave 2026-05 (set openssf-mini-shai-hulud-may-2026-stepsecurity) | 344 | 332 | 0.2 | 3.7 | 4.7 | 6.5 | 7.5 | 7.8 | 433.8 | 99.1% | 99.1% | 99.1% | 99.1% |
| wave 2026-08 (set openssf-shai-hulud-aug-2026-jfrog) | 1738 | 1648 | 0.5 | 5.3 | 5.8 | 6.0 | 6.5 | 12.2 | 77.4 | 99.9% | 99.9% | 99.9% | 100.0% |
| **all in-wave versions** | 3702 | 3547 | 0.2 | 5.5 | 6.3 | 12.1 | 18.3 | 22.5 | 433.8 | 95.5% | 98.0% | 99.9% | 99.9% |

Corrected, the 2026-05 maximum is 10.4 hours, all its measured versions listed within 24 hours.

Other measures. All rows but the second are the script's; the second takes the three artefacts' latency from
when the OpenSSF record listed them.

| | versions | measured | min | p25 | median | p75 | p90 | p95 | max | <=24h | <=48h | <=72h | <=7d |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| headline: first advisory listing the version | 3702 | 3547 | 0.2 | 5.5 | 6.3 | 12.1 | 18.3 | 22.5 | 433.8 | 95.5% | 98.0% | 99.9% | 99.9% |
| headline, three artefacts corrected (derived) | 3702 | 3547 | 0.2 | 5.5 | 6.3 | 12.1 | 18.2 | 22.4 | 77.4 | 95.6% | 98.1% | 99.9% | 100.0% |
| same, including pre-wave listings | 3704 | 3549 | 0.2 | 5.5 | 6.3 | 12.1 | 18.3 | 22.7 | 4680.5 | 95.4% | 97.9% | 99.8% | 99.9% |
| OSV per-version snapshots only | 3702 | 3530 | 0.2 | 5.5 | 6.2 | 12.1 | 18.3 | 22.5 | 433.8 | 95.5% | 98.0% | 99.9% | 99.9% |
| OSV record created (record-level, lower bound) | 3702 | 3547 | -2.2 | 4.2 | 4.9 | 10.2 | 12.9 | 17.0 | 46.5 | 96.4% | 100.0% | 100.0% | 100.0% |
| GHSA `published_at` (record-level) | 3702 | 3253 | 0.1 | 4.1 | 4.8 | 10.7 | 18.8 | 37.8 | 6883.4 | 92.6% | 97.4% | 98.9% | 99.0% |
| package deleted (404): advisory minus wave start | 3702 | 154 | 5.8 | 6.8 | 7.2 | 20.5 | 21.1 | 21.1 | 51.8 | 97.4% | 98.1% | 100.0% | 100.0% |
| removal upper bound: packument `time.modified` | 3702 | 3547 | 0.1 | 11.3 | 122.2 | 2791.2 | 7478.1 | 9146.7 | 9299.0 | 46.2% | 48.7% | 49.2% | 51.3% |

Source of the headline advisory, over all 3,702 in-wave versions: GitHub malware advisories (via OSV) 3,134; Google
378; Amazon Inspector 156; OpenSSF package analysis 4; OSV record date 29; none 1.

## Anomalies

- **The three versions over 7 days are method artefacts.** `@beproduct/nestjs-auth@0.1.10` (433.8 hours),
  `@tallyui/storage-sqlite@0.2.1` (432.4) and `@0.2.3` (431.2), May 2026: the earliest origin snapshot naming each is
  a GitHub update of 2026-05-29, but OpenSSF commit
  [`4e64fc6`](https://github.com/ossf/malicious-packages/commit/4e64fc6ddf2af837e9e4abcb1a78a0770f67a262)
  (2026-05-12 06:46:14 UTC) already lists them in `MAL-2026-3433` and `MAL-2026-3604`, from Google's report, which
  gives the version as `0.10.1`. Measured to that commit: 10.4, 9.1 and 7.8 hours. Only these three were corrected,
  by hand; the rest was not audited for the same artefact. GitHub's own advisory listed 0.1.10 only on 2026-05-29,
  after the package's other 17 bad versions by 01:09 UTC on 2026-05-12; the version was gone within 17.9 hours
  (packument `time.modified`).
- **Two versions took 77.4 hours:** `@ornikar/intl-config@10.0.10` and
  `@ornikar/react-native-svg-transformer@1.0.13`, published 2026-08-04 12:44 UTC. Each package's GitHub advisory
  existed 2.5 hours after publish, listing other versions; these two were added 24 to 31 seconds after the
  packument's last modification (most likely the removal). They were plausibly installable past a 72-hour soak, and
  are why the corrected figure is 99.9% at 72 hours, not 100%. OSV's importer recorded them at 130.6 hours.
- **48 hours is not enough.** 66 versions, all 2025-09, were first listed between 48 and 72 hours, so a 48-hour soak
  would have missed 68 (1.9%) with the two above; the script, counting the artefacts, says 71 (2.0%).
- **One listed version is live with no advisory:** `@dev-blinq/cucumber_client@1.0.1637-dev` (Datadog set),
  published 2025-11-24 11:39 UTC. OSV `MAL-2025-191213` lists only 1.0.738 and 1.0.739, published that morning and
  removed. It has no install script (the November 2025 payload ran from `preinstall`) and is one of many `-dev`
  prereleases: likely a listing error, like `@teriyakibomb/ember-velcro@2.2.1`
  ([iocs.md](../iocs.md#exclusions-versions-a-source-lists-in-error)); only tarball inspection, not done here, would
  confirm it. The scanner reports it while it is in the data.
- **Two likely false-positive entries,** `@rxap/ngx-bootstrap@19.0.3` and `@19.0.4` (Socket wave-1 set), published
  in March and May 2025, cannot carry the wave's payload. They are excluded from the headline but stay in the data
  (OSV `MAL-2025-47455`; [why](../iocs.md#exclusions-versions-a-source-lists-in-error)).
- **Eight OSV records predate the version:** `@things-factory/email-base` 9.0.55 to 9.0.59, and in April 2026
  `@cap-js/db-service@2.10.1`, `@cap-js/postgres@2.2.2` and `@cap-js/sqlite@2.2.2`, created 1.4 to 2.2 hours before
  publish and extended later. Their per-version latency is 18 to 29 hours; none is negative.
- **154 versions are unmeasurable** (the package returns 404); their advisory came 5.8 to 51.8 hours after their
  wave's first in-wave publish, an upper bound.
- **GitHub coverage has gaps.** 331 in-wave versions (8.9%) have no GitHub malware advisory, and 31 got one more
  than 7 days after publish. OSV listed every measurable version but the `@dev-blinq` one. `npm audit`, which reads
  only GitHub advisories, never flags those 331.

## What this does and does not show

- **Advisory time is not removal time.** Where removal is not proven, a later write to the package hides when the
  version went; the bound only loosens as packages change (the 2026-10-02 first run found 59% for the August 2026
  wave). A soak protects mainly by giving advisories time to exist where something reads them. A package manager's
  cooldown does not, so there only removal protects; `wormsign soak` reads OSV
  ([soak.md](../soak.md#layer-3-osv-malicious-package-records)).
- **Upstream time, not OSV serving time.** OSV's importer records each snapshot later (`import_time`, the CSV's
  `osv_first_cover_imported`), and `api.osv.dev` serves it after that. Measured to `import_time` (derived, over the
  3,530 versions whose headline is an origin snapshot): median 13.3 hours, 3,525 (99.9%) within 72 hours, the same
  five exceptions, the `@ornikar` two at 130.6 hours. The import lag: median 1.9 hours, p95 8.4, maximum 53.3.
  Import to serving is not measured.
- **Advisory time is an upper bound** on when the compromise was known: a vendor post or the npm takedown can come
  first.
- **OSV coverage is partly by construction.** Five of the six sets take a version only when an OpenSSF record lists
  it ([THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md)), so OSV lists all 2,611 of their in-wave versions. In
  the Datadog set (1,091 in-wave versions), chosen without OSV, OSV lacked 1 (0.1%) and GitHub 194 (17.8%); on the
  OpenSSF sets GitHub lacked 137 (5.2%), making the 331 above (derived from the CSV's `sets`, `osv_ids` and
  `ghsa_ids`).
- **Survivorship.** Five loud waves say nothing about a quiet single-package compromise, which may go unnoticed far
  longer than 7 days.
- **npm only.** No comparable PyPI study exists ([PyPI incidents](pypi-incidents.md);
  [threat model](../threat-model.md#pypi)).
- The window runs from the registry's publish time, which is what `wormsign soak` reads.

The 2026-10-02 first run used the package data before the rebuild from licensed datasets (3,355 versions; waves
2025-09, 2025-11 and 2026-08), and its input and output were not published. For those waves it gave the same
per-wave latencies, within 0.1 hour at every percentile.

## Reproduce

With Node 22 or newer and `gh auth login` or a `GITHUB_TOKEN` (no scopes; it raises the rate limit):

```sh
GH_TOKEN="$(gh auth token -h github.com)" node scripts/soak-latency.mjs --iocs data/iocs/packages.json --out /tmp/soak-out --cache /tmp/soak-out/cache
shasum -a 256 /tmp/soak-out/soak-latency.csv docs/evidence/data/soak-latency.csv
```

About 9,040 read-only requests (1,629 packuments, 3,704 OSV queries, 3,704 GitHub queries and the control) and 14
minutes without a cache, at the default `--concurrency 4` with a 100 ms pause per request, under GitHub's limit of
5,000 an hour, waiting out a 429. Never commit the cache (about 60 MB). Registry and advisory data change, so a later
run can differ.
