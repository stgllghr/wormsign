# Third-party notices

wormsign's own code and documentation are under the MIT License ([LICENSE](LICENSE)). The npm package includes one
third-party program, the TOML parser smol-toml (BSD-3-Clause, [below](#smol-toml-vendored-toml-parser)). The
repository also holds third-party content in its test fixtures, which are not in the npm package
([Test fixtures](#test-fixtures)). The compromised package
versions in [`data/iocs/packages.json`](data/iocs/packages.json) are derived from the two datasets below, both
published under the Apache License, Version 2.0. A copy of that licence is in
[`data/iocs/LICENSES/Apache-2.0.txt`](data/iocs/LICENSES/Apache-2.0.txt), fetched unmodified from
<https://www.apache.org/licenses/LICENSE-2.0.txt> (SHA-256
`cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`). The other IOC files (`files.json`,
`workflows.json`, `repos.json`, `endpoints.json`) hold single indicators (a hash, a file name, a workflow or runner
name, a repository description, a branch, an endpoint), each citing the public page that reports it, and include
no data from these datasets.

Both datasets are used as data only. wormsign includes no code from either.

## smol-toml (vendored TOML parser)

| | |
|---|---|
| Package | `smol-toml` 1.9.0 from the npm registry, <https://registry.npmjs.org/smol-toml/-/smol-toml-1.9.0.tgz> |
| Tarball integrity | `sha512-hpd+HLON7HdZXqYchMM/+LaTTbdK0AU3NngIJ4KVyWbY9bfQqdL9cD+4yf6dUoU2Ap4VsU0JkQi6FxAI1B2mXQ==` |
| Source | <https://github.com/squirrelchat/smol-toml>, tag `v1.9.0`, commit [`6f9739a5ab481f57c3112024bc4947534b580b58`](https://github.com/squirrelchat/smol-toml/tree/6f9739a5ab481f57c3112024bc4947534b580b58) (from the registry's SLSA provenance for the tarball) |
| Licence | BSD-3-Clause (the package's `LICENSE`, below) |
| Where it is | [`src/vendor/smol-toml/`](src/vendor/smol-toml/) in the repository, `dist/src/vendor/smol-toml/` in the npm package |
| What was used | The package's `dist/*.js` (except the CommonJS build `index.cjs`), `dist/*.d.ts` and `LICENSE`, copied byte-identical. [`VENDORED.json`](src/vendor/smol-toml/VENDORED.json) records each file's SHA-256. |

No change was made to any file. The `.d.ts` files are used only to compile wormsign and are not in the npm package;
the `.js` files, `LICENSE` and `VENDORED.json` are. Each `.js` file also carries the notice in its header comment.

The package's `LICENSE` reads, verbatim:

```text
Copyright (c) Squirrel Chat et al., All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Datadog indicators-of-compromise

| | |
|---|---|
| Repository | <https://github.com/DataDog/indicators-of-compromise> |
| Commit | [`33e44afbb1b72f3da4f990096d216a44a28c7b72`](https://github.com/DataDog/indicators-of-compromise/tree/33e44afbb1b72f3da4f990096d216a44a28c7b72) |
| Licence | Apache-2.0 (the repository's `LICENSE`) |
| File used | [`shai-hulud-2.0/consolidated_iocs.csv`](https://github.com/DataDog/indicators-of-compromise/blob/33e44afbb1b72f3da4f990096d216a44a28c7b72/shai-hulud-2.0/consolidated_iocs.csv) |
| What was used | The `package_name` and `package_versions` columns of every row: 795 packages, 1,091 versions. The `sources` column (which vendors reported each package) is not copied. |
| Where it is | The package set `datadog-shai-hulud-2.0` (wave `2025-11`) in `data/iocs/packages.json` |

Datadog's file merges the package versions that Datadog, HelixGuard, Koi, ReversingLabs, Socket, StepSecurity and
Wiz reported for the November 2025 Shai-Hulud 2.0 wave, with three packages Datadog judged to be false positives
removed (see the file's
[README](https://github.com/DataDog/indicators-of-compromise/blob/33e44afbb1b72f3da4f990096d216a44a28c7b72/shai-hulud-2.0/README.md)).

Every one of the 795 rows at this commit names Wiz among its reporters in the `sources` column (every row also names
at least one other vendor). The list is therefore largely the one Wiz published in its own repository,
`wiz-sec-public/wiz-research-iocs`, which carries no licence: all 1,089 versions of the copy of Wiz's CSV that
wormsign carried before 2026-10-02 are in Datadog's list, which adds two. wormsign does not use Wiz's file. It relies
on Datadog's Apache-2.0 licence for Datadog's compilation and takes from it only package names and versions; it has
no separate permission from Wiz or the other reporting vendors.

Changes made: each row's comma-separated `package_versions` field is split into separate versions, and the rows are
rewritten as a JSON object from package name to its sorted versions. No row or version is added or removed.

The repository's `NOTICE` file reads, verbatim:

```text
indicators-of-compromise
Copyright 2025-Present Datadog, Inc.

This product includes software developed at Datadog (<https://www.datadoghq.com/).>
```

## OpenSSF malicious-packages

| | |
|---|---|
| Repository | <https://github.com/ossf/malicious-packages> |
| Commit | [`fcea5cbe58234cf584a2252bce07ad0cd0f1bde2`](https://github.com/ossf/malicious-packages/tree/fcea5cbe58234cf584a2252bce07ad0cd0f1bde2) |
| Licence | Apache-2.0 (the repository's `LICENSE`; the repository has no `NOTICE` file) |
| Files used | OSV records under `osv/malicious/npm/<package>/MAL-*.json` |
| What was used | From each selected record: its `id` and, from its `affected` entries for that npm package, the explicit `versions` list. Ranges, summaries, details and references are not copied. |
| Where it is | The package sets `openssf-shai-hulud-1-stepsecurity`, `openssf-shai-hulud-1-socket` (wave `2025-09`), `openssf-mini-shai-hulud-picus` (`2026-04`), `openssf-mini-shai-hulud-may-2026-stepsecurity` (`2026-05`) and `openssf-shai-hulud-aug-2026-jfrog` (`2026-08`) in `data/iocs/packages.json`: 2,613 distinct versions of 834 packages, from 834 records |

Selection: for each of the five vendor reports a set cites in its `source` (StepSecurity and Socket for September
2025, Picus for April 2026, StepSecurity for May 2026, JFrog for August 2026), a version is included when the report lists it and an OpenSSF
record for that package lists the same version. The report decides which records are used; the versions come from
the records. Versions a record lists that the report does not are not included. One version a report lists has no
OpenSSF record (`@teriyakibomb/ember-velcro@2.2.1`, listed by Socket); it is recorded in the set's `unmatched` field
and not loaded. The vendor reports themselves are cited, not redistributed.

Changes made: the selected versions are rewritten as a JSON object from package name to its sorted versions, and
the ids of the records they came from are kept per package in the set's `records` field.

OpenSSF records can merge reports from several origins (for example, GitHub's malware advisories); the record id
and version list are taken as the OpenSSF repository publishes them.

## Test fixtures

The repository's `test/fixtures/` are inputs for the test suite. They are not part of the npm package (`package.json`
`files` leaves out `test/`). Third-party content in them:

| Content | Where | Source and licence | Changes |
|---|---|---|---|
| 10 GitHub Advisory Database records (`GHSA-`), with their `details` text | `test/fixtures/osv/query/*.json` | <https://github.com/github/advisory-database>, as served by `POST https://api.osv.dev/v1/query` on 2026-10-08. [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/) | re-indented only; each file's `_about` says when and how it was fetched |
| 4 PyPA advisory database records (`PYSEC-`), with their `details` text | `test/fixtures/osv/query/pypi-*.json` | <https://github.com/pypa/advisory-database>, through the same OSV query. [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/) | re-indented only |
| 1 OpenSSF malicious-packages record (`MAL-2025-6794`) | `test/fixtures/osv/query/pypi-num2words-0.5.15.json` | <https://github.com/ossf/malicious-packages>, through the same OSV query. Apache-2.0 (the licence text is in [`data/iocs/LICENSES/Apache-2.0.txt`](data/iocs/LICENSES/Apache-2.0.txt)) | re-indented only |
| OSV batch answers (record ids and dates only) | `test/fixtures/osv/querybatch-*.json` | `POST https://api.osv.dev/v1/querybatch`, ids from the three databases above | re-indented only |
| The `six` 1.17.0 wheel, `six-1.17.0-py2.py3-none-any.whl`, two copies | `test/fixtures/python/locks/uv-0.10.9/path/vendor/`, `test/fixtures/python/locks/uv-0.12.21/path/vendor/` | <https://pypi.org/project/six/1.17.0/>, by Benjamin Peterson. MIT; the licence is inside the wheel (`six-1.17.0.dist-info/LICENSE`) | none: SHA-256 `4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274`, as PyPI lists it |

The fixtures also hold package metadata written or served by package managers and registries: lockfiles written by
npm, pnpm, Yarn, uv and pip, trimmed npm package documents from `registry.npmjs.org` (`test/fixtures/registry/`)
and PyPI Simple API pages (`test/fixtures/python/simple/`, and the three in `test/fixtures/python/forged/captured/`:
`pyyaml`, `jaraco-classes` and `more-itertools`). Where each came from is in its `_fixture` field (the npm
documents), in `test/fixtures/python/locks/TOOLS.txt` and `scripts/gen-py-fixtures.sh`, which recorded the Python
fixtures, and, for the three captured pages, in `test/fixtures/python/forged/captured/index.json` (source URL,
capture time, sha256 and why each was taken). The wave replays under `test/fixtures/replay/` quote short passages from the vendor reports they
cite, each with its link.

## Refreshing

`scripts/import-package-sets.mjs` regenerates every package set from clean checkouts of both repositories, checks
that each checkout's `LICENSE` is the Apache License 2.0, and records the commit it read in each set's `dataset`
field. When a refresh changes a commit, update the commit links above. See [docs/iocs.md](docs/iocs.md#refreshing-the-package-sets).
