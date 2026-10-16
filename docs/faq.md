# Frequently asked questions

Failures: [troubleshooting.md](troubleshooting.md). What wormsign is, and whether
it is ready: the [README](../README.md).

## About the project

### Was it tested against real malware?

No, by design: every fixture is inert. The validation uses rule coverage, IOC recall, inert replays of four waves, a
mutation check and a false-positive study on 15 repositories ([validation.md](validation.md)).

### Why no npm runtime dependencies, and why one vendored parser?

A tool that exists to reduce supply-chain risk should not add any, so it uses small readers that fail closed
([why](architecture.md#no-npm-runtime-dependencies-narrow-hand-written-parsers-that-fail-closed)). TOML is the
exception: smol-toml 1.9.0, vendored and hash-checked ([how](architecture.md#one-vendored-pinned-verified-toml-parser)).

### How does it compare with npm audit, Socket, OSV-Scanner, Harden-Runner and the others?

They do different jobs and combine well with it ([positioning.md](positioning.md)).

## Installing and running

### Why is there no `npm install wormsign`?

The project publishes nothing to npm, so that would fetch whatever someone else publishes under the name. Install
from a clone, or a checked GitHub Release once one exists ([installation.md](installation.md)).

### Which Node.js version do I need?

Node 22 or newer. The soak gate needs npm 11.10 or newer, which Node 24.14.1 and later bundle
([why Node 24](installation.md#why-node-24)).

### Does it work on Windows?

Not tested. The CLI is plain Node.js and may work; `harden-dev.sh` supports macOS and Linux only.

### Does it run code from the project it checks?

No. `diff` runs only `git`, and `soak` only `git`, `<pm> --version` and `python3 -m pip config list`, never a copy
inside the scanned tree ([network](cli/soak.md#network)). `harden-dev.sh` runs package managers only to read their
settings ([how](hardening.md#how-the-script-reads-settings)).

## What it checks, and what it does not

### Which package managers and lockfiles are supported?

`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, and `yarn.lock` for Yarn 1 and 2+. A Bun lockfile is a
high "not checked" finding ([cli/scan.md](cli/scan.md#what-it-checks)).

### Does it support PyPI?

In `soak`, in `harden-dev.sh` ([H12, H13](hardening.md#checks)) and, as change reports, in `diff`. `soak` checks
`uv.lock`, PEP 723 script locks, `pylock.toml` and hash-locked requirements files file by file, but not build
requirements or `poetry.lock`, `pdm.lock` and `Pipfile.lock` ([Python locks](soak.md#python-pypi-locks),
[limitations](soak.md#python-limitations), [installing the project](soak.md#installing-the-project-itself)).

### If wormsign reports nothing, am I safe?

No: a clean run means "none of the known signs" ([out of scope](threat-model.md#out-of-scope)). The inert Mini
Shai-Hulud replay passes `scan` and `diff`; only `soak` stops it ([replays](validation.md#3-wave-replays)).

### Will it catch the next wave?

Partly: the soak gate holds back young versions, OSV catches one once a record exists, and some rules match
techniques rather than names. IOC matching waits for a data update ([threat-model.md](threat-model.md)).

### What is the difference between `scan` and `diff`?

`scan` checks a whole directory, payload files and endpoints included; `diff` checks what a change adds, without
them. The recommended gate runs both ([cli/diff.md](cli/diff.md#limitations)).

### Does it watch my running processes or network traffic?

No: it reads files and APIs. The [detections](../detections/README.md) are for tools you already run; for runtime
monitoring of CI, see [Harden-Runner](positioning.md#stepsecurity-harden-runner).

## The soak time

### What is the soak time?

The time a version must have been public before it is installed: 7 days by default. Set it with `--min-age`,
the Action's `min-age`, or `harden-dev.sh --soak`.

### Why 7 days and not 72 hours?

A cooldown never reads advisories, and removal within 72 hours is proven for only about half of the measured worm
versions. With `soak`'s OSV check on, 72 hours is a reasonable CI value
([why](soak.md#why-7-days-and-when-72-hours-is-enough)).

### I already set `min-release-age` (or pnpm/Yarn/bun's equivalent). Why also run `wormsign soak`?

Some versions ignore or misread it (npm 10; Yarn 4.10 reads `3d` as 3 minutes), and npm, Yarn, bun and pnpm 10 do not
apply it to a version already locked, which is how CI installs
([layer 1](soak.md#layer-1-package-manager-release-age-settings)).

### A security fix was released yesterday and the gate blocks it. What now?

Baseline that one finding with a justification and an `expires` date a few days past its soak time; for a pull
request gate, on the base branch first ([emergency exceptions](soak.md#emergency-exceptions)).

### Why does my private registry fail the soak gate?

`soak` checks one registry without credentials, and fails what it cannot verify rather than send private names to
the public registry ([fix](troubleshooting.md#a-private-registry-fails-closed-ws-sk-002)).

## Findings and baselines

### How do I accept a finding I have reviewed?

`wormsign baseline add <fingerprint> --reason "<why it is safe>"`, with `--expires YYYY-MM-DD` for anything temporary
([cli/baseline.md](cli/baseline.md)).

### Why did my baseline entry stop working?

A move, another working directory or, for some rules, an edit changes the fingerprint
([why](troubleshooting.md#a-baselined-finding-came-back-with-a-new-fingerprint)).

### Why does every pull request that edits the baseline fail?

On purpose: a change cannot approve itself. Review the entry and merge with an override
([baseline.md](baseline.md#reviewing-baseline-changes)).

### Can a project's own baseline hide findings from me?

Yes: `scan` and `soak` read the checked directory's `.wormsign-baseline.json`. On a tree you did not write, use
`--no-baseline` ([baseline.md](baseline.md)).

### Should I baseline a critical IOC match?

No: a critical IOC match means a listed indicator is present ([which rules](baseline.md#reviewing-baseline-changes)).
Follow [incident-response.md](incident-response.md).

### What do the severities and exit codes mean?

Exit 0: nothing at or above `--fail-on` (default `high`); 1: at least one finding; 2: a usage or internal error, or
an incomplete `audit-org` run ([output.md](output.md#exit-codes), [rules.md](rules.md)).

## CI and the GitHub Action

### What should I put in my workflow?

Start from the [README](../README.md#quickstart), then use the
[recommended gate](github-action.md#recommended-pull-request-gate), pinned to a release tag's full commit SHA.

### Can a pull request switch the gate off?

Yes, by editing or deleting the workflow file, pinned SHA included; otherwise the gate's code never comes from the
change. `diff` reports the edit (WS-DF-003, medium) if the edited workflow still runs it; branch protection with
code-owner review stops it ([github-action.md](github-action.md#what-the-gate-does-not-stop)).

### Does it work outside GitHub Actions?

The CLI does: it is a Node program with exit codes, JSON and SARIF. Only GitHub Actions is documented or tried.

### Why does the code scanning upload fail?

It needs a public repository or GitHub Code Security; `upload-sarif: "auto"` skips it elsewhere
([SARIF](github-action.md#sarif-and-code-scanning)).

## Data, privacy and trust

### What does wormsign send over the network?

`scan` and `diff`: nothing. [`soak`](cli/soak.md#network): package names to the registry and index, `name@version`
to OSV. [`audit-org`](cli/audit-org.md#network): read-only GitHub API calls.
[`update-iocs`](cli/update-iocs.md#network): five downloads. No telemetry.

### Where does the IOC data come from, and how current is it?

Every entry names a public https source. It is as current as its `version` date; a release or `update-iocs` brings
newer data ([iocs.md](iocs.md), [the Action's](github-action.md#ioc-data)).

### Can a tampered update make wormsign miss something?

The cache can only add indicators, never remove or soften one. The download is not signed, so pin `--url` to a
reviewed commit ([trust model](iocs.md#trust-model)).

### How do I report a vulnerability in wormsign?

Privately, as [SECURITY.md](../SECURITY.md) describes. A missing or wrong IOC is a normal issue.
