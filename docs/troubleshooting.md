# Troubleshooting

Find the message, then apply the fix. Entries marked *fail closed* are findings that mean "this could not be
checked": they fail the default gate on purpose, because a file wormsign cannot read is one an attacker could hide
in. The messages were reproduced on macOS with npm 10.9.2 and an empty `HOME`.

## Installing and running

### The wrong Node.js version

The Action refuses Node older than 22 (`wormsign needs Node.js 22 or newer on the runner`). Fix: add
`actions/setup-node` with `node-version: 24` and `check-latest: true` before it. The CLI does not check, but nothing
is tested below Node 22. On Node 23, a source build prints `EBADENGINE` warnings, then works.

### `dist/src/cli.js is missing`

Cause: the Action is pinned to a commit on `main`, which has no compiled CLI, or runs from an unbuilt checkout. Fix:
pin the release tag's commit ([how](github-action.md#pin-the-action-by-commit-sha)), or build first
(`npm ci --ignore-scripts && npm run build`).

### `cannot resolve "<rev>" as a git revision`

Exit 2 from `diff` or `soak --base` in a shallow clone, which lacks the base commit. Fix: `fetch-depth: 0`, or
`fetch-depth: 2` on `pull_request` with a diff against the merge commit's first parent
([requirements](github-action.md#requirements)); locally, `git fetch --unshallow`.

### `git could not read <path> at <rev>`

Exit 2 from `diff` in a partial clone (`--filter=blob:none`), which lacks the file's content; `diff` never fetches.
Fix: a full clone, with `filter` unset on `actions/checkout` ([cli/diff.md](cli/diff.md#network)).

## The soak gate

### npm ignores `min-release-age` (WS-SK-004)

`ignores it; npm 11.10.0 or newer enforces it`: medium, or high with `--require-config`. Cause: npm 10, which every
Node 22 bundles, ignores the setting ([experiment](evidence/package-managers.md#npm)). Fix: npm 11.10 or newer,
which Node 24.14.1 and later bundle; check `npm --version` ([why Node 24](installation.md#why-node-24)). In GitHub
Actions, set `setup-node`'s `node-version: 24` and `check-latest: true`, since the runner's cached 24.x may predate
24.14.1.

### Yarn 4.10 reads `3d` as 3 minutes

`npmMinimalAgeGate = 3d uses a unit suffix`. Cause: Yarn 4.10.3 drops the unit; newer Yarn reads the duration
([experiment](evidence/package-managers.md#yarn-2-berry)). Fix: plain minutes, `npmMinimalAgeGate: 10080` (7 days).

### `the pnpm version that will run could not be determined`

Cause: `pnpm --version` failed, typically a corepack shim with nothing cached, since `soak` turns corepack's
downloads off (Yarn too). Fix: pin `"packageManager"` in `package.json`, which `soak` reads instead, or install a
real pnpm on `PATH`.

### A private registry fails closed (WS-SK-002)

`.npmrc installs packages from <url>, not https://registry.npmjs.org`. *Fail closed*: `soak` ages packages on one
registry, without credentials ([private registries](soak.md#private-registries)). Fix: pass `--registry` if your
registry serves package documents with `time` without credentials; otherwise baseline each private entry with a
justification. In the Action, set the `registry` input; its `registry-host` input keeps `scan` and `diff` from
reporting the registry's lockfile URLs as WS-LK-002 ([inputs](github-action.md#inputs)).

### Yarn Classic: `WS-SK-003` at low

Yarn 1 has no release-age setting, so there is nothing to configure, and `--require-config` does not raise it. The
lockfile gate is the only age check; Yarn 4.10+ or pnpm 11+ adds a native one.

### `soak` fails on test fixtures or examples

`ignorePaths` do not apply to npm lockfiles. Fix: point `soak` at the project you install
([soak's root](github-action.md#soaks-root)). Python inputs under [`ignorePaths`](baseline.md#ignorepaths) are not
read.

### WS-SK-005: a build at install time

The install builds a Python package from source, and its build requirements are outside every lock. Fix: avoid the build
(`uv sync --locked --no-install-project`, `[tool.uv] package = false`, a version with wheels), or pin build
requirements with `==` build constraints, then baseline it: a local project's entry holds until its
[build key](soak.md#builds-ws-sk-005) changes.

### WS-SK-002: "no lock covers it"

A `pyproject.toml`, `setup.py`, `setup.cfg` or `Pipfile` declares dependencies and no lock covers it. Fix: commit the
lock it installs from beside it (`uv lock`, or a hash lock), and install as
[soak.md](soak.md#installing-the-project-itself) shows. If nothing installs it, baseline it; the entry holds until the
manifest changes.

### WS-SK-002: "named like a pip requirements file, but wormsign cannot read it as one"

The file has a line that is neither a requirement nor an option (a Dockerfile, a script, a test baseline), so none of
its packages were checked. Fix: if nothing installs from it, baseline it or list it in
[`ignorePaths`](baseline.md#ignorepaths); if `pip install -r` uses it, make it a hash lock
([discovery](soak.md#discovery-what-is-read)).

## Network errors


### `soak`: `request failed: fetch failed` (WS-SK-002)

*Fail closed.* The registry could not be reached, even on retry. Fix the connection. If the whole registry is down for the
run, `--on-outage warn` reports it at medium instead ([trade-off](soak.md#outages---on-outage)).

### `soak`: `request to OSV failed` (WS-OS-900)

*Fail closed.* Fix the connection to `api.osv.dev`, or run without the check (`--no-osv`); the report says so. If OSV
is down for the whole run, `--on-outage warn` reports it at medium instead ([trade-off](soak.md#outages---on-outage)).

### `soak`: `record queries were stopped in this run after one failed` (WS-OS-900)

*Fail closed.* A request for one version's full OSV records failed after its retry, so `soak` sent no more
([network](cli/soak.md#network)). Run again later. A recurring HTTP 429 means OSV is limiting your address: run less
often, on a subdirectory, or with `--base`.

### `soak`: `more than 1000 versions in this run had GitHub advisories to read` (WS-OS-900)

*Fail closed.* `soak` reads the records of at most 1,000 versions per run, in plain string order (`1.0.10` before
`1.0.9`). Fix: fewer or smaller lockfiles, or `--no-osv` with another OSV client.

### Behind a proxy or a TLS-inspecting firewall

wormsign uses Node's `fetch`, which ignores `HTTPS_PROXY` and `NO_PROXY` unless `NODE_USE_ENV_PROXY=1` (added in
v24.0.0 and v22.21.0) is set; then every request except to `NO_PROXY` hosts goes through the proxy, and an
unreachable one fails the gate closed. For a proxy that re-signs TLS, set `NODE_EXTRA_CA_CERTS=<pem file>` or
`NODE_USE_SYSTEM_CA=1` (v24.6.0, v22.19.0) ([Node.js CLI docs](https://nodejs.org/api/cli.html)).

### `update-iocs`: `cannot download ...: fetch failed`

Exit 2, cache unchanged: the source could not be reached, or it redirected, which wormsign does not follow (pass the
final URL). A 404: [below](#update-iocs-http-404-from-the-default-source).

## Files wormsign could not check

### WS-SC-900: `... was not checked`

*Fail closed.* `scan` could not read a manifest, lockfile, workflow or editor or agent settings file
([causes](cli/scan.md#what-it-checks)). Fix a broken file. Review an unsupported one (a Bun lockfile,
`package.yaml`) by hand and baseline it with an `expires` date, since the key is the file, not its content. A Yarn 2+
entry whose name is not an npm package name, other than `link:`, `portal:` and `workspace:` entries, fails the whole
`yarn.lock`, and a baseline does not bring its IOC check back.

### WS-DF-006: `changed but could not be read or parsed`

*Fail closed.* The `diff` counterpart of WS-SC-900. Fix the file, or review the change and merge with an override;
the fingerprint covers the new content ([baseline.md](baseline.md#when-a-fingerprint-changes)).

### WS-LK-003 in a Yarn 1 project

The entry has neither an `integrity` line nor a SHA-1 fragment in its `resolved` URL, so Yarn 1 installs whatever the
URL serves ([false positives](evidence/false-positives.md#changes-since-the-first-run)).

## Baselines

### A baselined finding came back with a new fingerprint

A fingerprint covers the path **relative to the directory the command was given**: another directory, a rename, or, for
content-keyed rules, an edit gives a new one ([when it changes](baseline.md#when-a-fingerprint-changes)), and `scan`
notes `baseline entry ... matches no finding`. Fix: run the gate from the same directory every time; after a rename or
edit, review the finding and replace the entry.

### The baseline file is rejected (exit 2)

The file breaks the [format](baseline.md#format) (unknown keys, a justification under 15 characters or starting with
`todo`, a bad `expires`, a glob in `ignorePaths`), or is a symlink, FIFO, device or over 2 MiB. Commit the file itself,
or name it with `--baseline` ([where each command reads it](baseline.md#where-each-command-reads-it)).

### A pull request that changes the baseline or `.npmrc` always fails

By design: `diff` reports such a change as WS-DF-005 (high) and reads suppressions from the base. Review it and
merge with an override ([reviewing baseline changes](baseline.md#reviewing-baseline-changes)). The same holds for a
[Python build change](cli/diff.md#a-python-build-changed-expected-on-ordinary-pull-requests).

## GitHub: code scanning, audit-org, update-iocs

### Code scanning upload fails on a private repository

`Resource not accessible by integration`, or `Code scanning is not enabled for this repository`. Cause: code
scanning needs a public repository or GitHub Code Security, plus `security-events: write` (and `actions: read` when
private). Fix: leave `upload-sarif` at `"auto"`, or set `"false"` and keep the SARIF as an artifact
([SARIF](github-action.md#sarif-and-code-scanning)). The gate's result does not depend on the upload.

### audit-org: no token, or a rejected token

`set GITHUB_TOKEN or GH_TOKEN`, or `GitHub rejected the token`, both exit 2. Fix: a token with the access
[cli/audit-org.md](cli/audit-org.md#token) lists. Personal accounts cannot be audited.

### audit-org: degraded results (WS-OR-900) and `audit incomplete`

An `info` WS-OR-900 names a check the plan or token cannot run; a clean result for it means "not checked"
([example](cli/audit-org.md#example-output)). When no repository answered a per-repository check, or a rate limit
stopped the audit, the exit is 2. Fix: give the token the access named; the audit log (and WS-OR-002) needs GitHub
Enterprise Cloud.

### update-iocs: HTTP 404 from the default source

Exit 2, nothing written: the files are not at that path on `main`. Pass `--url`, or use the bundled data
([cli/update-iocs.md](cli/update-iocs.md)).

## Still stuck

Read the `notes` of `--format json`: they say what was not checked. Report a wrong IOC with the "False positive"
issue template; report a bypass privately ([SECURITY.md](../SECURITY.md)).
