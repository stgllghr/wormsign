# Workstation hardening: `harden-dev.sh`

`harden-dev.sh` checks the settings on a developer machine that blunt an install-time npm or PyPI worm: dependency
install scripts off, a release-age cooldown on (npm, pnpm, Yarn, bun, pip, uv), no plaintext tokens, no over-scoped
`gh` tokens, and no worm payload files on disk. Run it in check mode first. `--apply` writes the package-manager
settings it can verify; everything else is reported for you to fix.

```sh
./harden-dev.sh                 # check only; changes no settings (see below for gh)
./harden-dev.sh --apply         # write the fixable settings, backing up each file first
./harden-dev.sh --soak 14d      # require a 14-day cooldown instead of the default 7 days
./harden-dev.sh --offline       # skip H09, the only check that contacts GitHub
./harden-dev.sh --path ~/work   # also search ~/work for worm payload files (repeatable)
```

Exit status: 0 if no FAIL remains, 1 if any FAIL remains, 2 on a usage error (including a `--path` that is not a
directory or a `--soak` value it cannot read). It runs on macOS and Linux with bash 3.2 or later.

Check mode changes no settings and writes no file of its own, but H09's `gh auth status` can write gh's state
(gh 2.96.0 created `~/.local/state/gh/device-id`); use `--offline` if nothing at all may be written.

Run it from a checkout after `npm run build`, or from an installed Release tarball
([installation.md](installation.md)): H11 needs the built IOC loader (`dist/src/iocs.js`) and is a SKIP without it.

H02 needs npm 11.10 or newer: npm 10, bundled with Node 22, accepts the setting and ignores it
([why Node 24](installation.md#why-node-24)).

## Example run

Check mode in an empty `HOME` on a Mac with npm 10.9.2, uncached corepack shims for pnpm and Yarn, pip 26.1.2 and uv
0.10.9 (temp paths shortened; exit status 1):

```console
$ HOME=$(mktemp -d) ./harden-dev.sh --offline
wormsign harden-dev: mode=check soak=7d (npm 7d, pnpm/yarn 10080min, bun 604800s)
[PASS] H14  no gh-token-monitor watcher files at: $TMPDIR/.../Library/LaunchAgents/com.user.gh-token-monitor.plist ...
[FAIL] H01  npm 10.9.2: ignore-scripts is false (want true; fixable with --apply, which edits $TMPDIR/.../.npmrc). Without it, every dependency's install scripts run on npm install.
[FAIL] H02  npm 10.9.2 has no working release-age cooldown: min-release-age needs npm >= 11.10 (older npm accepts the key and ignores it). Upgrade npm, then re-run.
...
[FAIL] H12  pip 26.1.2 (python3 -m pip, pip3): uploaded-prior-to: unset for pip install, download, lock and wheel (want P7D or longer; fixable with --apply, which runs 'python3 -m pip config --user set global.uploaded-prior-to P7D'). Without a cutoff pip installs a release minutes after it is published.
[FAIL] H13  uv 0.10.9: no exclude-newer applies outside a project (want 7 days or longer). Add 'exclude-newer = "7 days"' at the top level of $TMPDIR/.../.config/uv/uv.toml, before any [table] (not auto-applied).

summary: 4 pass, 2 warn, 4 fail (mode=check)
```

## Checks

| ID  | Checks | Fixed by `--apply` |
|-----|--------|--------------------|
| H01 | npm runs dependency install scripts: `ignore-scripts` (npm < 12), `dangerously-allow-all-scripts` (npm >= 12) | yes, npm user config |
| H02 | npm release-age cooldown: `min-release-age` in days (needs npm >= 11.10) | yes, npm user config |
| H03 | pnpm runs dependency build scripts: pnpm < 10; pnpm 10.0 to 10.25, which run a git dependency's `prepare` (CVE-2025-69264, fixed in 10.26.0); or `dangerouslyAllowAllBuilds` | yes for pnpm >= 11 |
| H04 | pnpm cooldown: `minimumReleaseAge` in minutes, and `minimumReleaseAgeStrict` not false | yes for pnpm >= 11 |
| H05 | Yarn cooldown: `npmMinimalAgeGate` in minutes (Yarn >= 4.10); Yarn Classic has none (WARN) | yes, `~/.yarnrc.yml` |
| H06 | Yarn runs dependency scripts: `ignore-scripts` (Classic), `enableScripts` (Yarn 2+) | yes, `~/.yarnrc` / `~/.yarnrc.yml` |
| H07 | bun cooldown: `[install] minimumReleaseAge` in seconds in the global bunfig (bun >= 1.3) | no (report only) |
| H08 | Plaintext tokens in npm/yarn/bun config, pip's user config (`~/.pip/pip.conf`, `~/.config/pip/pip.conf`, `$XDG_CONFIG_HOME/pip/pip.conf`, macOS `~/Library/Application Support/pip/pip.conf`), shell profiles, and earlier `--apply` backups of all of them | no |
| H09 | `gh` token scopes, for every logged-in account on every host | no |
| H10 | Cloud and git credential files present (AWS, gcloud, Azure, kube, docker, terraform, gh, `~/.git-credentials`, `~/.netrc`); WARN only | no |
| H11 | Worm payload files (IOC names and hashes) under `~/{code,src,dev,projects,work,Developer,repos,git}`, the global `node_modules` (`npm root -g`) and each `--path` | no |
| H12 | pip cooldown: the `uploaded-prior-to` that `pip install`, `download`, `lock` and `wheel` use, for each pip found (`python3 -m pip`, `pip3`, `pip`); relative values need pip >= 26.1; a WARN when `python3 -m venv` would install an older pip | yes, pip user config, written by pip |
| H13 | uv cooldown: the `exclude-newer` uv applies outside a project (relative values need uv >= 0.9.17); an `[[index]]` entry's own `exclude-newer` that is off or shorter than the soak is a FAIL for the default index or PyPI and a WARN for another index; per-package and `[pip]` values shorter than the soak are a WARN | no (report only) |
| H14 | The `gh-token-monitor` watcher of the May 2026 wave, which wipes the home directory when its token is revoked: `~/Library/LaunchAgents/com.user.gh-token-monitor.plist`, `~/.config/systemd/user/gh-token-monitor.service`, `~/.local/bin/gh-token-monitor.sh`, `~/.config/gh-token-monitor` (Wiz, StepSecurity); any one is a critical FAIL that says "do not revoke tokens yet: isolate this machine first" ([incident-response.md](incident-response.md#1-isolate-the-machine-before-revoking-anything)); checked first | no, never removed |

Each check prints PASS, FAIL, WARN, SKIP (tool not installed) or INFO; H08, H10 and H14 always run. A check that cannot
see what it needs (a package manager that will not report its version or read its config, an unreadable file, a `gh`
account gh could not log in to) is a WARN, never a PASS. When `poetry`, `pdm` or `pipenv` is on `PATH`, an INFO line
says their release-age settings are not checked.

The cooldowns stop new resolutions only: most locked installs still install a young version
([soak.md](soak.md#layer-1-package-manager-release-age-settings), [Python](soak.md#python-pypi-locks)). Gate the
lockfile first: `wormsign soak && npm ci`.

### What `--apply` writes

| Package manager | File | Settings |
|-----------------|------|----------|
| npm | the file `npm config get userconfig` names (normally `~/.npmrc`; `NPM_CONFIG_USERCONFIG` moves it) | `ignore-scripts=true` (npm < 12) or `dangerously-allow-all-scripts=false` (npm >= 12); `min-release-age=<days>` (npm >= 11.10) |
| pnpm >= 11 | `$XDG_CONFIG_HOME/pnpm/config.yaml`, else `~/Library/Preferences/pnpm/config.yaml` (macOS) or `~/.config/pnpm/config.yaml` | `minimumReleaseAge: <minutes>`; `dangerouslyAllowAllBuilds: false` only when it is true, and `minimumReleaseAgeStrict: true` only when it is false (unset, both pass) |
| Yarn Classic | `~/.yarnrc` | `ignore-scripts true` |
| Yarn 2+ | `~/.yarnrc.yml` | `enableScripts: false`, `npmMinimalAgeGate: <minutes>` (Yarn >= 4.10) |
| pip >= 26.1 | the last user file `pip config debug` lists (on macOS, `~/Library/Application Support/pip/pip.conf` if that directory exists, else `~/.config/pip/pip.conf`; pip 26.2.1 used `$XDG_DATA_HOME/pip/pip.conf` when it existed) | `[global]` `uploaded-prior-to = P<days>D`, written by `python3 -m pip config --user set global.uploaded-prior-to P<days>D` |

It writes a setting only when the package manager reports a failing value, so a stricter one is
never lowered. Before its first change to a file it copies it to
`<file>.wormsign-bak.<timestamp>.<pid>` (mode 0600, never over an existing file). It replaces the first line that sets
the key (any spacing or quoting; in YAML only top-level keys) and drops later duplicates (npm and Yarn use the last
one; pnpm rejects a duplicate key). Then it asks the package manager again: PASS only if it now sees the value, FAIL
if something overrides it or the write failed. If the package manager can no longer read its config, the file is put
back and the result is FAIL "could not safely edit"; if it could not read it before, the setting is a WARN and nothing
is written. A symlink to a missing file is never written through. A second `--apply` changes nothing and makes no
backup.

pip writes its own file, and `pip config --user set` rewrites it whole: **comments in it are lost** (the backup keeps
them). If any pip can no longer load its config afterwards, every user file is restored. Nothing is written for pip
when the `[global]` value it uses already passes, when the winning `[global]` is in a file read after the user file,
when `PIP_UPLOADED_PRIOR_TO` fails, or when a pip 26.0 is, or would be, installed (`P<days>D` makes it fail).

pnpm 10 is not written: its settings live in `rc` or `~/.npmrc`, and it skipped its cooldown once the version's metadata
was cached, so upgrade to pnpm 11 ([evidence](evidence/package-managers.md#pnpm)). For bun, add to `~/.bunfig.toml`:

```toml
[install]
minimumReleaseAge = 604800   # 7 days, in seconds
```

For uv, add `exclude-newer = "7 days"` at the top level of `~/.config/uv/uv.toml` (or `$XDG_CONFIG_HOME/uv/uv.toml`),
before any `[table]`.

`--soak 7d`, the default, is `min-release-age=7` for npm, 10080 minutes for pnpm and Yarn, 604800 seconds for bun,
`P7D` for pip and 7 days for uv. npm and pip count whole days, so the script rounds up (`--soak 60h` is 3 days) and
never soaks less than asked. Keep 7 days on a developer machine: these cooldowns never read an advisory
([why](soak.md#why-7-days-and-when-72-hours-is-enough)).

## How the script reads settings

A later duplicate key, an `npm_config_*` / `pnpm_config_*` / `YARN_*` environment variable or a relocated user config
all win over the line you can see, so the script asks each package manager for the value it uses (`npm config get`,
`pnpm config get`, `yarn config get`). A FAIL naming a value your file sets means something with higher precedence
overrides it. bun has no such command: H07 reads the global bunfig files as Bun does and takes the lower value.

Package managers run only as `--version`, `config get`, `npm root -g`, `pip config debug`, `pip config --user set`
(with `--apply`), `uv lock --offline` and `python3 -I -c`, always from an empty temp directory (so no project config
or `packageManager` pin applies), with corepack downloads off, caches in that directory, and only absolute `PATH`
entries. The directory is made only where neither it nor any directory above it is owned by another user or writable
by group or others (`$TMPDIR`, else `/tmp`, `$XDG_RUNTIME_DIR`, `~/.cache`, `$HOME`); if none qualifies, the script
exits 2. A package manager that prints no plain version this way is a WARN, and none of its settings are judged.

**pip (H12).** The script rebuilds from `pip config debug` the value each command uses, as pip 26.1.2 and 26.2.1 do:
files are read global, user, site, `PIP_CONFIG_FILE`, the last to set a key winning per section, and each of
`install`, `download`, `lock` and `wheel` takes `PIP_UPLOADED_PRIOR_TO`, else its own section, else `[global]`. Each
must be `P<n>D` with n at least the soak in days, or an ISO 8601 date older than the soak. It also warns when
`PIP_CONFIG_FILE` is set or `PIP_UPLOADED_PRIOR_TO=P0D`.

**uv (H13).** uv prints no effective configuration, so the script locks an empty probe project offline and reads the
cutoff from the lock's `[options]`. What the lock omits (`[[index]]` and `[pip]` values) is read from the user
`uv.toml` with `tomllib` and measured by uv in a second probe. A failed or unknown lock is a WARN "oracle
unavailable", never a PASS. A per-index value does not stand in for a missing top-level one.

**Not covered.** A project's own `.npmrc`, `pnpm-workspace.yaml`, `.yarnrc.yml`, `bunfig.toml`, virtual-environment
`pip.conf` or `uv.toml` can override these inside it; the script reads the machine-wide value on purpose. What checks a
project's own settings: [soak.md](soak.md#on-a-developer-machine). Each virtual environment's pip must itself be 26.1 or
newer. The Yarn checked is the global one, not a project's pinned Yarn 2+. pip's cutoff does not apply to
`pip --isolated`, a direct URL, path or VCS requirement, or a pip H12 does not ask (a `pip3.12`, pyenv, conda, pipx
or `uv tool` pip).

## How each setting was verified

The package-manager behaviour these checks rely on was run against the versions named, each in an empty `HOME`; the
method, commands and results per tool, and what comes from documentation or source only, are in
[evidence/package-managers.md](evidence/package-managers.md).

## Allowing one trusted package's install scripts

Keep scripts off globally and allow one trusted package at a time. Each workflow was run with an inert local package
([results](evidence/package-managers.md)).

### npm

npm 11 and older, with `ignore-scripts=true`: install as usual, then run the scripts of the one package you trust:

```sh
npm rebuild <pkg> --ignore-scripts=false
```

A plain `npm rebuild <pkg>` does not run them. `ignore-scripts=true` also skips your own project's install-time
scripts (such as `prepare`) and `npm run`'s `pre`/`post` hooks, though not `npm run <script>` itself (npm's docs).

npm 12 blocks dependency scripts by default; leave `ignore-scripts` unset:

```sh
npm install-scripts approve <pkg>   # writes package.json "allowScripts", pinned to the installed version
npm rebuild <pkg>                   # runs the newly approved scripts
```

Keep approvals pinned, the default: `--no-allow-scripts-pin` writes "name-only entries that allow any future
version" (npm 12.2.0's docs). Approved scripts run silently at the default log level; `--loglevel=info` in CI prints
`npm info run <pkg> preinstall <path> <command>` for each (see `detections/README.md`).

### pnpm

pnpm 10: list trusted packages under `onlyBuiltDependencies` in `pnpm-workspace.yaml` (or `package.json`
`pnpm.onlyBuiltDependencies`), then run `pnpm rebuild <pkg>`.

pnpm 11 and 12: `pnpm approve-builds` (interactive) or `pnpm approve-builds --all` writes an `allowBuilds:` map to
`pnpm-workspace.yaml` (`<pkg>: true` allows, `false` denies). For a local tarball the key is `<pkg>@file:<path>`;
that a bare name matches a registry dependency is from the release notes, untested.

### Yarn Classic (1.x)

There is no per-package allowlist. After `yarn install`, use npm on the same tree:
`npm rebuild <pkg> --ignore-scripts=false`. That worked with npm 10.9.2 but not 12.2.0; no npm 12 route is known.

### Yarn 2+ (Berry)

Keep `enableScripts: false` and re-enable one package in the project's `package.json`, then run `yarn install`:

```json
"dependenciesMeta": { "<pkg>": { "built": true } }
```

### bun

`bun pm untrusted` lists blocked scripts; `bun pm trust <pkg>` adds the package to `trustedDependencies` in
`package.json` and runs its scripts. bun also trusts a built-in list of popular packages when `trustedDependencies`
is absent (bun docs, "Lifecycle scripts"); `trustedDependencies: []` opts out of that list.

## The other checks

**H08 plaintext tokens.** In the files the table lists (bash, zsh and fish profiles included), it flags `_authToken`,
`_auth`, `_password`, `npmAuthToken` and `npmAuthIdent` with a literal value; `NPM_TOKEN`, `NODE_AUTH_TOKEN`,
`GITHUB_TOKEN`, `GH_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `CLOUDFLARE_API_TOKEN` and
`DIGITALOCEAN_ACCESS_TOKEN` set to a literal in any shell syntax; `user:password@` in a URL; and token-shaped strings
(`npm_`, `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`, `github_pat_`, `AKIA`). A value starting with `$`, a backtick or `(` is a
reference, not a finding. It prints the file, line and kind, never the value.

**H09 `gh` scopes.** `gh auth status` (skipped by `--offline`) lists every account on every host, active or not. An
account with `delete_repo`, `admin:org`, `admin:repo_hook`, `admin:org_hook`, `admin:public_key`, `admin:gpg_key` or
`write:org` is a FAIL, with the command that removes them; `workflow` and `write:packages` are a WARN. `repo`,
`read:org` and `gist` are gh's minimum set and are not flagged. An account gh could not verify, or output the script
cannot parse, is a WARN; a fine-grained or GitHub App token, which reports no scopes, is an INFO.

**H10 credential files.** Presence only: the mode is printed, never the contents. An empty file is not reported; an
unreadable file, or a directory that cannot be searched (such as a root-owned `~/.docker`), is a WARN.

**H11 worm payload files.** IOC names and hashes come through wormsign's own loader, so the script sees what the
scanner sees, including a valid, newer `update-iocs` cache. A hash match, or a name whose `nameOnlySeverity` is high
or critical, is a FAIL; medium or low is a WARN. An unreadable part of the tree is a WARN. A root that is a symlink
is searched with `find -H`; symlinks below a root are not followed.

Reported paths have C0 control characters and DEL replaced with `?` (C1 controls too, when the locale and the path
are UTF-8), so a file name cannot rewrite the terminal.

## Not covered, deliberately

- **Source builds.** Building a source distribution runs code from it. pip's `only-binary = :all:` and uv's
  `no-build = true` refuse one, but a requirements file with `--no-binary :all:`, naming the sdist by path, or a
  project's `[tool.uv] no-build = false` runs the build again ([pip](evidence/package-managers.md#pip),
  [uv](evidence/package-managers.md#uv)). So the script sets neither: they break every sdist-only package (pip's own
  help for `--only-binary` warns of this), and the projects and requirements files you install can switch them back
  off.
- **`.pth` files.** Python's `site` documentation says a line in a `.pth` file that starts with `import` is executed,
  at every interpreter start. A package that installs one runs code without any install script; a cooldown only
  delays its release.
- **`~/.pypirc` tokens.** The `.pypirc` specification's own example keeps a PyPI API token as `password` under
  `username = __token__`. H08 does not scan `~/.pypirc` yet.

## Tests

`npm run test:harden` runs the script against stub package managers, and a mutant reverts each behaviour
([validation.md](validation.md#other-checks-on-the-checks)); `test/harden-real.test.ts` runs H12 and H13 against the
real pip and uv ([results](evidence/package-managers.md#how-harden-devsh-reads-settings)).
