# `wormsign soak`

Run `soak` before the install. It fails a locked version that is younger than the soak time (default 7 days), is not
the artifact the registry published, or has an OSV malicious-package record. It also reports npm registry signals of
a hijacked publish (high, a new publisher medium; none for Python) and checks npm, pnpm, Yarn and bun release-age
settings ([why](../soak.md)).

```text
wormsign soak [dir] [--format human|json|sarif] [--output <file>] [--fail-on <severity|never>]
                    [--baseline <file> | --no-baseline] [--min-age <duration>] [--registry <url>]
                    [--pypi-index <url>] [--base <rev>] [--config-only] [--require-config] [--no-osv]
                    [--on-outage fail|warn]
```

`dir` defaults to `.`.

## What it checks

Check 1 is offline and always runs; checks 2 and 3 use the network, and `--config-only` skips them.

### 1. Release-age configuration (offline)

For each lockfile, `soak` reads the release-age setting where its package manager reads it. It learns which version
will enforce it from a `packageManager` pin in `package.json`, Yarn's `yarnPath`, or else `<manager> --version`
(from the filesystem root, with `YARN_IGNORE_PATH=1` and corepack's network access off).

| Lockfile | Setting read | Unit | Enforced from | Where it is read |
|---|---|---|---|---|
| `package-lock.json`, `npm-shrinkwrap.json` | `min-release-age` | days | npm 11.10.0 | `npm_config_min_release_age`, then the `.npmrc` in the lockfile's directory, then `~/.npmrc` |
| `pnpm-lock.yaml` | `minimumReleaseAge` | minutes | pnpm 10.16.0 | `pnpm-workspace.yaml`, `pnpm_config_*` / `npm_config_*` variables, pnpm 11's global `config.yaml`, and for pnpm 10 `.npmrc` (`minimum-release-age`) |
| `yarn.lock` (Yarn Berry) | `npmMinimalAgeGate` | minutes | Yarn 4.10.0 | `YARN_NPM_MINIMAL_AGE_GATE`, then every `.yarnrc.yml` from the lockfile's directory up, then `~/.yarnrc.yml` |
| `yarn.lock` (Yarn Classic) | none exists | | | low [WS-SK-003](../rules.md#ws-sk-003): `soak` in CI is the only gate |
| `bunfig.toml` at `dir` | `[install] minimumReleaseAge` | seconds | Bun 1.3.0 | `bunfig.toml` |

A missing setting is [WS-SK-003](../rules.md#ws-sk-003). [WS-SK-004](../rules.md#ws-sk-004) is one shorter than
`--min-age`, unreadable, ignored by the version that will run (or one that cannot be determined), or undone by a
bypass (pnpm's `trustLockfile`, `minimumReleaseAgeStrict` and `minimumReleaseAgeExclude`, Yarn's
`npmPreapprovedPackages`, Bun's `minimumReleaseAgeExcludes`). A Yarn value with a unit suffix (`3d`) is reported,
because Yarn 4.10 reads it as minutes. Both are medium, or high with `--require-config`. None of these settings stops
`npm ci` or `yarn install --immutable` from installing a young locked version.

### 2. Every locked version (network)

Each entry of every lockfile under `dir`, outside `node_modules` and `.git`:

| Entry | Result |
|---|---|
| local code (`file:`, `link:`, `portal:`, `workspace:`) | not checked; counted in a note |
| a git source, another registry than `--registry`, or no version | [WS-SK-002](../rules.md#ws-sk-002) |
| a `package.json` with dependencies and no lockfile in its directory or above; a lockfile that does not parse or yields no packages; a Bun lockfile; a symlinked lockfile or directory | [WS-SK-002](../rules.md#ws-sk-002) |
| no publish time, a version no longer listed, an `integrity` that is not the registry's (or, without one, a `resolved` URL) | [WS-SK-002](../rules.md#ws-sk-002) |
| published less than `--min-age` ago | [WS-SK-001](../rules.md#ws-sk-001) |
| an install script added or changed, provenance dropped, a new publisher | [WS-RG-001](../rules.md#ws-rg-001), [WS-RG-002](../rules.md#ws-rg-002), [WS-RG-003](../rules.md#ws-rg-003); on a full run, only for versions published in the last 14 days |
| a `MAL-` record, or a GitHub advisory with CWE-506 (unless `--no-osv`) | [WS-OS-001](../rules.md#ws-os-001); no answer is [WS-OS-900](../rules.md#ws-os-900) |

### 3. Python locks (network)

Python locks, manifests, PEP 723 scripts and requirements files are checked as
[soak.md](../soak.md#python-pypi-locks) describes: [WS-SK-001](../rules.md#ws-sk-001) for a locked file younger than
`--min-age`, [WS-SK-002](../rules.md#ws-sk-002) for anything that cannot be verified or would use another index,
[WS-SK-005](../rules.md#ws-sk-005) for a build the install runs (high with `--base` for one the change adds), and
[WS-OS-001](../rules.md#ws-os-001) or [WS-OS-900](../rules.md#ws-os-900) from OSV, asked only when the index is
pypi.org.

### PR mode: `--base <rev>`

An npm, pnpm or Yarn entry is checked only when the base's copy of the same lockfile does not hold it with the same
name, version, `resolved` and `integrity`. A Python entry is checked only when the base's own `soak` did not read the
same file as a lock of the same kind (a requirements file must be a complete hash lock on both sides) with the entry
pinned identically: the same name, version and hashes, in the same file, and for `uv.lock` and `pylock.toml` the same
source and files ([the rule](../soak.md#pr-mode)). Its files are still bound on the index for WS-SK-005; it is not
aged or sent to OSV, but a project gone from the index or quarantined is still reported. A file `<rev>`'s git
attributes convert on checkout (`working-tree-encoding`, `filter`, `ident`; read with `git check-attr --source`, git
2.40 or later) holds nothing that counts as the base's. Only entries are skipped, for npm and Python alike: every
lockfile, reader and file-level problem is reported on every run. A young version pushed straight to the base passes,
for both: the full `soak` on push and on a schedule catches it
([github-action.md](../github-action.md#push-and-scheduled-checks)). `<rev>` must be a git revision, not a `dir:`
path. The baseline is read from `<rev>` unless `--baseline` is given; for the Python rule, a file either the run's
baseline or `<rev>`'s own committed baseline ignores counts as passed over on the base.

## Options

Other options are a usage error (exit 2).

| Option | Meaning |
|---|---|
| `--format human\|json\|sarif` | Default `human`. JSON adds per-package [evidence](../output.md#soak-evidence). |
| `--output <file>` | Write to a regular file; a symlink, device or FIFO is refused (exit 2). |
| `--fail-on <severity\|never>` | Exit 1 at or above this severity (default `high`). |
| `--baseline <file>` | Default `.wormsign-baseline.json` in `<dir>`; with `--base`, as committed in that revision. |
| `--no-baseline` | Read no baseline. Use it on a tree you did not write. |
| `--min-age <duration>` | Default `7d`. A number and a unit (`s`, `m`, `h`, `d`, `w`, or words such as `hours`); a bare number is rejected. `72h` only with OSV on. |
| `--registry <url>` | The one registry checked. `https` (`http` only for `localhost`, `127.0.0.1`, `[::1]`), no credentials. Default `https://registry.npmjs.org`. |
| `--pypi-index <url>` | The one Python index (PEP 691, PEP 700); same rules, no query or fragment. Default `https://pypi.org/simple/`. Given, even as the default, it lets requirements entries be checked when pip's configuration cannot be read, and sends local archives' names to it. |
| `--base <rev>` | PR mode (above). |
| `--config-only` | Check 1 only, no network. |
| `--require-config` | Medium WS-SK-003 and WS-SK-004 become high. |
| `--no-osv` | Do not ask OSV. |
| `--on-outage fail\|warn` | Default `fail`. `warn`: when the registry, the index or OSV gave no answer in the whole run (DNS, connection, TLS handshake, timeout, HTTP 429 or 5xx) nor to a probe of its root, each package it left unchecked is [WS-SK-006](../rules.md#ws-sk-006) or [WS-OS-901](../rules.md#ws-os-901), medium, and an `UNVERIFIED:` line is printed; anything else stays as it is ([trade-off](../soak.md#outages---on-outage)). |

## Examples

With an empty `HOME` and npm 10.9.2 on `PATH`, a project whose `.npmrc` has `min-release-age=7` locks
`@types/node@22.20.5` (6.5 days old). The default fails it, 72 hours passes it, and WS-SK-004 is npm 10 ignoring the
setting:

```console
$ wormsign soak
HIGH     WS-SK-001  package-lock.json
         @types/node@22.20.5 was published 6.5d ago, inside the required 7.0d soak window (published 2026-10-01T22:38:10.803Z)
         fingerprint: 65aa016c6566773da33f83e882c46c29
MEDIUM   WS-SK-004  .npmrc
         .npmrc: min-release-age is set, but npm 10.9.2 (from `npm --version`) ignores it; npm 11.10.0 or newer enforces it
         fingerprint: 3efcfb868d132609cb4eeaaa5f65379a
...
$ wormsign soak --min-age 72h
...
wormsign soak: 1 finding(s) (0 critical, 0 high, 1 medium, 0 low, 0 info)
```

A `uv.lock` (`test/fixtures/python/locks/uv-0.12.21/simple`) when idna 3.20's files were 21.8 days old:

```console
$ wormsign soak --min-age 30d
HIGH     WS-SK-001  uv.lock
         idna==3.20 (PyPI) has 2 locked file(s) uploaded inside the required 30.0d soak window: idna-3.20-py3-none-any.whl uploaded 21.8d ago (2026-09-17T14:11:03.168153Z); idna-3.20.tar.gz uploaded 21.8d ago (2026-09-17T14:11:04.752193Z)
...
```

## Exit codes

As in [output.md](../output.md#exit-codes). Anything `soak` cannot verify is high, so a registry, index or OSV outage
fails the gate, unless `--on-outage warn` reports it at medium ([outages](../soak.md#outages---on-outage)).

## Network

Unless `--config-only`. No request carries credentials.

| Endpoint | What is sent | Limits |
|---|---|---|
| the registry (`--registry`) | one `GET` per package name resolved from it | 8 at a time, 30-second timeout; one retry on HTTP 429, 5xx or a network error, after 429 or 5xx waiting `Retry-After` (at most 30 seconds) or 2 to 3 seconds; a document over 200 MiB is WS-SK-002; a redirect is not followed (WS-SK-002) |
| OSV `/v1/querybatch` | name and version of each locked package whose name the public registry served | batches of up to 1,000, 4 at a time, 60-second timeout; a redirect is not followed (WS-OS-900); nothing with a non-public `--registry` ([WS-OS-900](../rules.md#ws-os-900)) |
| OSV `/v1/query` | each version already sent whose answer has a `GHSA-` id the run has not read, in name and version order, to read CWE ids | at most 1,000 versions per run, shared by npm and PyPI; 4 at a time, 60-second timeout; one retry on HTTP 429, 5xx, a network error or a timeout, after 429 or 503 waiting `Retry-After` (at most 30 seconds) or 2 seconds; once one fails its retry, no more are sent |
| the Python index (`--pypi-index`) | one `GET <index>/<name>/` per project (`Accept: application/vnd.pypi.simple.v1+json`), for names the [source and install settings](../soak.md#sources) allow | 2 at a time; one retry on HTTP 429, 5xx or a network error; redirects only within the index's origin (at most 3); another content type or project is refused |
| OSV, for PyPI | the same two requests, for versions whose page pypi.org served | nothing with another `--pypi-index` ([WS-OS-900](../rules.md#ws-os-900)) |
| `--on-outage warn` only: the root of a host that never answered | one `HEAD` per such host (registry, index or `https://api.osv.dev/`), after every other request, no package name | 30-second timeout; no retry; a redirect is not followed; only a transport failure or HTTP 429, 502, 503 or 504 confirms the outage ([outages](../soak.md#outages---on-outage)) |

`soak` also runs, from the filesystem root: `<pm> --version`, unless a `packageManager` pin or `yarnPath` answers;
`python3 -m pip config list` before sending an entry that records no index, with `PYTHONPATH`, `PYTHONSTARTUP`,
`PYTHONHOME` and `PYTHONUSERBASE` removed, a 15-second timeout and at most 1 MiB of output; and `git -C <dir>` when a
directory looks like a virtual environment or the tree has a Python lock. Each is found on `PATH` (skipping empty and
relative entries), run by absolute path, and never run from inside the scanned tree.

## Limitations

- **`ignorePaths` do not apply to npm lockfiles**: point `soak` at the directory you install, or baseline.
- **Settings files are read by small readers**: a YAML anchor, block scalar or escape is WS-SK-004.
- **`npm --version` reports the npm on `PATH`**, which may not be the npm that installs.
- **The rest** are in [soak.md](../soak.md#limitations), including
  [private names](../soak.md#private-registries) and [Python](../soak.md#python-limitations).
