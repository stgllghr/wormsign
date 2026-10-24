# Library release preparation: local verification

Executed on 2026-10-24 on macOS arm64 by the implementing agent. This is implementation verification, not an independent security review.

The frozen source was based on `2886b885edde340de9485262534934179fd2e3c7`. Its complete 793-file input manifest (bytes and modes) has SHA-256 `46aa179176ff46f2567ba821aa375b348e9662d019f2873826c414eebb3e75ca`. Source was unchanged throughout the campaign; documentation and the workflow-comment citation are closed out afterward.

## Executed checks

- Node 22.23.3 full suite and fresh Node 24.14.1 full baseline: 1,365 tests, 1,364 passed, one skipped test, no failures or cancellations.
- npm 11.10.0 and TypeScript 6.0.3; clean locked development dependency installation with lifecycle scripts disabled.
- Lint, actionlint, shellcheck, whitespace and the 994-definition matching check pass.
- Self-scan passes with no unbaselined findings; its inert WS-GH-001 positive control fails as required.
- The actual 460,588-byte tarball installs offline on Node 22/24. All 161 files match source/build output, including 63 declarations. CLI, root ESM import, safe example exits 0/1/2 and strict external TypeScript compilation pass.
- Candidate tarball SHA-256: `c19f5ef746f39bbe54560a67d2db68724033d3df86234840ffea51008dcd5757`.

The opt-in real pip/uv suites and live-pip differential were not run. The package excludes the experimental sandbox implementation, test sources and runtime npm dependencies.

## Targeted mutation review

Each reversion reran the complete suite serially after a fresh passing baseline. All twenty printed `killed`. Every complete failed-test set was inspected: failures belong to the intended API, consumer, runner or workflow controls; no project compile failure, cancellation or signal was accepted as a kill.

| Reversion | Intended failed tests |
|---|---|
| library scan drops observed findings | 8 |
| library scan uses ambient IOC selection | 2 |
| library scan ignores explicit context options | 1 |
| library scan ignores installed-package requests | 1 |
| library scan accepts invalid JavaScript options | 1 |
| library gate accepts an invalid severity | 1 |
| library gate ignores findings | 4 |
| library package omits generated declarations | 3 |
| library public import invokes the CLI | 2 |
| library package exposes internal deep imports | 2 |
| library example emits unsafe repository text | 1 |
| mutation runner mistakes consumer diagnostics for a project build failure | 1 |
| mutation runner hides unverified process and compilation diagnostics | 1 |
| mutation runner drops the process signal from its diagnostic | 1 |
| mutation runner emits unbounded process diagnostic lines | 1 |
| package required check skips when an artifact consumer fails | 1 |
| package required check ignores an unsuccessful artifact consumer | 1 |
| release publishes before its installed consumers pass | 1 |
| package CI omits the Node 22 tarball consumer | 1 |
| mutation transcript pipeline hides the runner failure | 1 |

Full stdout/stderr, process receipts, source snapshots, hashes and individual assessments are retained in a local verification archive. The archive has SHA-256 `60d5458f262b88b8e096901ffa9bcadcd0fda4af0d76fd7d9dd3bc0082854df0`. It is not shipped in the package.

## Remaining release gates

These twenty targeted kills do not constitute the complete 994-definition candidate campaign. Final pull-request CI, review/merge, the complete mutation and platform/package-manager checks on the merged source, reproducible compiled tagging, publication and independent artifact verification remain required. See [release readiness](../release-readiness.md).
