# Library release readiness

The next release adds a beta TypeScript/JavaScript API to the existing CLI, Action and hardening interfaces.
The public API is `scan`, `gateExitCode`, `renderReport`, `UsageError` and their documented types. It uses the
existing offline scanner with bundled or explicitly selected IOC data, without repository baseline suppression.
See the [API contract](library.md) and [individual maturity labels](stability.md#maturity).

Automatic enforcement in a shared sandbox for multiple agents remains a separate experimental milestone.
This release does not ship the sandbox implementation, intercept installers or grant execution authority.

## Pull request verification

- [x] Provide root ESM exports, generated declarations and runnable JavaScript/TypeScript examples.
- [x] Cover external imports, strict TypeScript consumers, invalid input and safe example output.
- [x] Configure CI and releases to install the same built tarball on Node 22 and 24.
- [x] Make publication wait for both consumers; preserve failures when retaining mutation transcripts.
- [x] Run the complete local Node 22/24 suites, lint, self-scan/positive control and workflow/shell checks.
- [x] Install the actual packed candidate offline on Node 22 and 24 and inspect its contents.
- [x] Run and inspect the twenty added full-suite mutations (eleven library, four runner, five workflow).
- [ ] Run the pull request's required GitHub checks on its final commit.

Local results and limits are recorded in [the verification summary](evidence/library-release.md) and the pull request. Historical results from the broader experimental
sandbox workspace are not evidence that this focused source has passed. No runtime dependency or IOC update is
part of this change.

## Before tagging

- [ ] Review the API/compatibility promises, documentation, licenses and security reporting together.
- [ ] Merge reviewed source and version metadata, then run the complete **994-definition** mutation campaign
  and required platform/package-manager jobs on that exact `main` commit.
- [ ] Freeze the passing source, create the reproducible compiled tag and publish through the
  [maintainer process](../CONTRIBUTING.md#releasing-maintainer).
- [ ] Independently verify the downloaded checksum, build attestation and installed release; record the
  result in [release status](installation.md#release-status).

Version 0.1.0 remains unreleased until those gates pass. The current workflow publishes a GitHub Release tarball
and provenance; npm registry publication is not configured. Creating or merging the preparation PR does not
publish a release.
