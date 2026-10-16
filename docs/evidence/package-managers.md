# Package-manager settings: what was verified

What each package manager did with its install-script, release-age and config settings, by version.
Guides: [hardening.md](../hardening.md), [threat-model.md](../threat-model.md#stage-1-install-time-execution).

## Method

The experiments ran on 2026-10-02 on macOS 15.6.1 (arm64) under Node 23.11.0, each in a fresh `HOME=$(mktemp -d)` and an
empty project directory; pip and uv ran on 2026-10-08 ([pip](#pip), [uv](#uv)); a row that gives another date ran on
that date. What a package manager does with its own settings does not depend on the Node release that runs it (the npm
[git-dependency experiments](#git-dependencies-at-install) gave the same results again on Node 24.21.0). Each version
came from `npm pack <name>@<version>` (which runs no scripts) and ran from the extracted tarball:
`node package/bin/npm-cli.js` for npm, `node package/bin/pnpm.cjs|pnpm.mjs` for pnpm 10/11, the native binary from
`@pnpm/exe.darwin-arm64@12.8.1` for pnpm 12, `node package/bin/yarn.js` from `@yarnpkg/cli-dist` for Yarn 4, corepack's
cached 1.22.22 for Yarn Classic, and `@oven/bun-darwin-aarch64@1.4.2` for bun.

Install-script experiments used an inert local package, `wormsign-inert-dep-1.0.0.tgz`, whose only content is
`"postinstall": "node -e \"require('fs').writeFileSync(process.env.INIT_CWD+'/MARKER','postinstall ran')\""`;
"ran" means `MARKER` appeared. Release-age experiments used the benign `is-number@7.0.0` (published 2019) under a
10- to 20-year cooldown, and, for pnpm's default, `typescript@7.1.0-dev.20261001.1` while it was 23 hours old.

## npm

| Fact | Versions | Command |
|------|----------|---------|
| Dependency install scripts run by default | ran: 10.9.2, 11.21.0 | `npm install ./wormsign-inert-dep-1.0.0.tgz` |
| `ignore-scripts=true` in `~/.npmrc` stops them | 10.9.2, 11.21.0, 12.2.0 | same, with `printf 'ignore-scripts=true\n' > $HOME/.npmrc` |
| npm 12 blocks them unless `allowScripts` approves | 12.2.0: "install scripts blocked ... not covered by allowScripts"; npm 12.0.0 changelog: "Dependency lifecycle scripts are now blocked by default" | same, no config |
| `dangerously-allow-all-scripts=true` turns that off | 12.2.0 (ran) | same, with that line |
| `npm config get` reads `key = value`, uses the last duplicate, and `npm_config_<key>` overrides it | 10.9.2, 11.10.0, 12.2.0: printed `false` for both | `printf 'ignore-scripts=true\nignore-scripts=false\n' > ~/.npmrc; npm config get ignore-scripts`; `npm_config_ignore_scripts=false` over a `true` file |
| `NPM_CONFIG_USERCONFIG` moves the user config; `npm config get userconfig` names it | 10.9.2, 11.10.0, 12.2.0 | `NPM_CONFIG_USERCONFIG=$HOME/other npm config get ignore-scripts userconfig` |
| `min-release-age` is enforced from 11.10 | ETARGET: 11.10.0, 11.21.0, 12.2.0; installed anyway: 10.9.2 (which still echoes the value) | `printf 'min-release-age=3650\n' > ~/.npmrc; npm install is-number@7.0.0` |
| 11.10.x reports it only as a computed `before` date | 11.10.0: `min-release-age=null`, `before=<now minus N days>`; 11.21.0, 12.2.0: the number. The script uses the age of `before` when set (an explicit `before` also wins) | `npm config get min-release-age before` |
| Lockfile installs ignore the cooldown | `npm ci` installed the locked `is-number@7.0.0` under a 3650-day cooldown: 10.9.2, 11.10.0, 11.21.0, 12.2.0 | install with no cooldown, set it, `rm -rf node_modules; npm ci` |
| `min-release-age-exclude` lets a named package through | 12.2.0: with `min-release-age=3650` and `min-release-age-exclude=is-number`, `npm install is-number@7.0.0` succeeded; without the exclude it failed with `ETARGET` | `npm install is-number@7.0.0` |
| `npm rebuild <pkg> --ignore-scripts=false` runs one package under `ignore-scripts=true` | 10.9.2, 11.21.0: ran; plain `npm rebuild <pkg>` did not. 10.9.2, 2026-10-14, under `ignore-scripts=true`: `npm rebuild <pkg> --ignore-scripts=false` ran only the named package's script, not another's (incomplete record: which file set `ignore-scripts=true`, and the install command, were not kept) | |
| npm 12: `npm install-scripts approve <pkg>`, then `npm rebuild <pkg>` | 12.2.0: ran, silently at the default log level, and again on a fresh `npm install`. With `ignore-scripts=true` too, approved scripts stay blocked; `npm rebuild <pkg> --ignore-scripts=false` ran it | |
| `--no-allow-scripts-pin` writes "name-only entries that allow any future version" | npm 12.2.0's `npm help install-scripts`; not run against a registry package | |

## pnpm

| Fact | Versions | Command |
|------|----------|---------|
| Dependency build scripts are not run by default | 10.16.0 ("Ignored build scripts", exit 0); 11.16.0, 12.8.1 (`ERR_PNPM_IGNORED_BUILDS`, exit 1). pnpm 10.0.0 release notes: "Lifecycle scripts of dependencies are not executed during installation by default" | `pnpm add ./wormsign-inert-dep-1.0.0.tgz` |
| `dangerouslyAllowAllBuilds` in the global config runs them all | ran: 10.16.0, 11.16.0, 12.8.1 | `pnpm config set dangerouslyAllowAllBuilds true --location=global` |
| Where the global config lives | 10.16.0: `~/Library/Preferences/pnpm/rc` (INI, `minimum-release-age=`); 11.16.0, 12.8.1: `~/Library/Preferences/pnpm/config.yaml` (`minimumReleaseAge:`); all three use `$XDG_CONFIG_HOME/pnpm/` when set | `pnpm config set minimumReleaseAge 4320 --location=global`, then `find $HOME $XDG_CONFIG_HOME -type f` |
| What `config get` reads | 10.16.0: `rc`, `~/.npmrc` and `npm_config_*`. 11.16.0, 12.8.1: `config.yaml` and `pnpm_config_*` only; a duplicate key in `config.yaml` makes it fail | `pnpm config get minimumReleaseAge`, each source in turn |
| Quoted keys count; a duplicate breaks every command | 11.16.0: `'minimumReleaseAge': 60`, `"minimumReleaseAge" : 60` and `"minimumRelease\u0041ge": 60` all print `60`; a second `minimumReleaseAge:` line makes `config get` and `pnpm --version` exit 1. `harden-dev.sh --apply --offline` replaced the single-quoted key (PASS, then no change) and refused the escaped one ("could not safely edit", file intact). **UNVERIFIED** on 12.8.1 | `printf "'minimumReleaseAge': 60\n" > config.yaml; pnpm config get minimumReleaseAge` (`node pnpm.cjs`, corepack's 11.16.0) |
| `minimumReleaseAge` in the global config is enforced | 11.16.0, 12.8.1: `ERR_PNPM_NO_MATURE_MATCHING_VERSION` | `pnpm config set minimumReleaseAge 10512000 --location=global; pnpm add is-number@7.0.0` |
| ... including for locked versions | 12.8.1: `ERR_PNPM_MINIMUM_RELEASE_AGE_VIOLATION` before linking; 11.16.0: same error, after linking `node_modules`; 10.16.0: installed (exit 0) | add, set it, `rm -rf node_modules; pnpm install --frozen-lockfile` |
| pnpm 10 is unreliable here | 10.16.0 enforced it from the global `rc`, `~/.npmrc`, `pnpm-workspace.yaml` and a project `.npmrc` (`ERR_PNPM_NO_MATCHING_VERSION`), but once the version had been resolved without it (warm metadata cache), `pnpm add is-number@7.0.0` succeeded | as above, twice in one HOME |
| The built-in default is not a gate | `config get minimumReleaseAge` prints `undefined` in a fresh HOME (10.16.0, 11.16.0, 12.8.1); the 11.0.0 release notes give a non-strict default of 1440 minutes, and with no config 11.16.0 and 12.8.1 installed the 23-hour-old version after "Added 8 entries to minimumReleaseAgeExclude in pnpm-workspace.yaml" | `pnpm add typescript@7.1.0-dev.20261001.1` |
| `minimumReleaseAgeStrict: false` lets a too-new version through | 11.16.0, 12.8.1: under a 20-year cooldown the add succeeded and added an exclude entry. Unset, it is true once `minimumReleaseAge` is set (11.16.0 source: `explicitlySetKeys.has("minimumReleaseAge")`), as the 20-year test confirms | `minimumReleaseAge: 10512000` + `minimumReleaseAgeStrict: false` |
| pnpm 10: `onlyBuiltDependencies`, then `pnpm rebuild <pkg>` | 10.16.0: ran after `rebuild`, and on a fresh `pnpm install` | |
| pnpm 11: `pnpm rebuild <pkg>` follows `allowBuilds` | 11.16.0, 2026-10-14, after an `--ignore-scripts` install: ran the script of a package `allowBuilds` approved and not that of one it denied (local tarballs, whose keys pnpm writes as `<name>@file:<path>`) | `pnpm rebuild <pkg>` |
| pnpm 11, 12: `pnpm approve-builds --all` writes `allowBuilds:` | 11.16.0, 12.8.1: wrote `wormsign-inert-dep@file:<path>` and ran the script, again on a fresh `pnpm install`; a bare-name key did not match that non-registry dependency. **UNVERIFIED**: a bare name matching a registry dependency (the 11.0.0 release notes say keys are "package name patterns") | |

The Linux default `~/.config/pnpm` comes from pnpm 11.16.0's `getConfigDir`. **UNVERIFIED**: not run on Linux, nor for
the pnpm 12 native binary there.

## Yarn Classic (1.x)

| Fact | Versions | Command |
|------|----------|---------|
| Dependency install scripts run by default | 1.22.22 (ran) | `yarn add file:./wormsign-inert-dep-1.0.0.tgz --offline` |
| `ignore-scripts=true` in `~/.npmrc` does **not** stop them | 1.22.22: ran; `yarn config get ignore-scripts` printed `false`; `npm_config_ignore_scripts=true` did not either | same, with `~/.npmrc` |
| `ignore-scripts true` in `~/.yarnrc` stops them | 1.22.22, also quoted or with extra spaces; a later `ignore-scripts false` wins | `printf 'ignore-scripts true\n' > ~/.yarnrc` |
| `YARN_IGNORE_SCRIPTS` overrides `~/.yarnrc` | 1.22.22: `=true` stops them with no file; `=false` over a `true` file runs them | `YARN_IGNORE_SCRIPTS=false yarn add ...` |
| `--ignore-scripts true` in `~/.yarnrc` stops them, but `yarn config get` says `false` | 1.22.22 | the script FAILs that form; `--apply` adds `ignore-scripts true` |
| `npm rebuild <pkg> --ignore-scripts=false` on a Yarn Classic tree | npm 10.9.2 on a Yarn 1.22.22 `node_modules`: ran. npm 12.2.0: did not; `npm install-scripts approve <pkg>` answered "No installed packages match". **UNVERIFIED**: a working npm 12 route | |

No release-age setting is known; **UNVERIFIED** that none exists.

## Yarn 2+ (Berry)

| Fact | Versions | Command |
|------|----------|---------|
| `enableScripts: false` in `~/.yarnrc.yml` applies to projects | 4.10.3, 4.18.1: did not run ("all build scripts have been disabled") | `"wormsign-inert-dep": "file:..."`, `nodeLinker: node-modules`, `yarn install` |
| `enableScripts` defaults to false from 4.14.0 | 4.14.0 release notes ("Makes `enableScripts: false` the default"); fresh HOME: `true` on 4.10.3 (the script ran), `false` on 4.18.1 | `yarn config get enableScripts` |
| `npmMinimalAgeGate` exists from 4.10.0, defaults to 1 day from 4.15.0 | 4.10.0 and 4.15.0 release notes; `0` on 4.10.3, `1440` on 4.18.1 | `yarn config get npmMinimalAgeGate` |
| Write bare minutes | `npmMinimalAgeGate: 3d` reads as `3` on 4.10.3 and `4320` on 4.18.1 | `yarn config get npmMinimalAgeGate` |
| The gate blocks new resolutions | 4.10.3 (`YN0082`), 4.18.1 (`YN0016`), 10-year gate in `~/.yarnrc.yml` | `yarn add is-number@7.0.0` |
| ... but not locked versions | 4.10.3, 4.18.1: installed the locked `is-number@7.0.0` | add, set it, `rm -rf node_modules; yarn install --immutable` |
| `config get` precedence | 4.10.3, 4.18.1: `YARN_ENABLE_SCRIPTS` and `YARN_NPM_MINIMAL_AGE_GATE` override `~/.yarnrc.yml`; a later duplicate key wins; `enableScripts : false` is read | `yarn config get enableScripts`, empty directory |
| `dependenciesMeta` `built: true` re-enables one package | 4.10.3, 4.18.1, with `enableScripts: false` in `~/.yarnrc.yml`: `yarn install` ran its script | |

## bun

| Fact | Versions | Command |
|------|----------|---------|
| Dependency lifecycle scripts are blocked unless trusted | 1.4.2: "Blocked 1 postinstall" | `bun add ./wormsign-inert-dep-1.0.0.tgz` |
| `ignore-scripts=true` in `~/.npmrc` also blocks trusted packages | 1.4.2 (did not run with the package in `trustedDependencies`) | |
| `[install] minimumReleaseAge` (seconds) in the global bunfig is enforced | 1.4.2, both `~/.bunfig.toml` and `$XDG_CONFIG_HOME/.bunfig.toml`: "blocked by minimum-release-age" | `printf '[install]\nminimumReleaseAge = 630720000\n' > ~/.bunfig.toml; bun add is-number@7.0.0` |
| ... but not for versions in `bun.lock` | 1.4.2: installed the locked version | add, set it, `bun install --frozen-lockfile` |
| `minimumReleaseAge = 604_800` is 604800 seconds | Bun's TOML page: TOML 1.0 (1.3.14) and 1.1.0 (1.4.3), `_` only between digits. Bun 1.3.0 to 1.3.14 `src/interchange/toml/lexer.zig` drops the `_`; Bun 1.4.3 `src/parsers/toml.rs` allows one only between digits (`check_underscore`) and refuses leading zeros. Read, not run | |
| `minimumReleaseAge` exists from Bun 1.3 | Bun 1.3 release blog; bunfig docs: global files are `$HOME/.bunfig.toml` and `$XDG_CONFIG_HOME/.bunfig.toml`, and a project `bunfig.toml` overrides them | |
| `bun pm trust <pkg>` runs one package's scripts | 1.4.2: ran on `trust`, and on a fresh `bun install` | |
| A built-in list of popular packages is trusted when `trustedDependencies` is absent | bun docs, "Lifecycle scripts" (`trustedDependencies: []` opts out). **UNVERIFIED** by experiment | |

## pip

Run on 2026-10-08 with Homebrew's Python 3.14.6 and its pip 26.1.2, in a fresh `HOME=$(mktemp -d)` with
`PIP_DISABLE_PIP_VERSION_CHECK=1`, from an empty directory. pip 26.2.1 ran from a virtual environment; pip 25.3 and
26.0.1 were imported from their wheels (`PYTHONPATH=pip-<version>-py3-none-any.whl`), each fetched with
`pip download --no-deps --only-binary :all: --uploaded-prior-to P7D`. "Uses" is the `uploaded_prior_to` pip's own
option parser computes, with no network call: `create_command("<command>").parse_args([])`.

| Fact | Versions | Command |
|------|----------|---------|
| `P<n>D` is read from pip 26.1 | 26.1.2: `[global] uploaded-prior-to = P7D` gave install and download "now minus 7 days". 26.0.1: install, download, lock, wheel, index and list failed with "invalid value: 'P7D': Invalid isoformat string"; a date (`2026-09-01T00:00:00Z`) worked. 25.3: no such option, the key is ignored | `parse_args`, also with `PIP_UPLOADED_PRIOR_TO=P7D` and no file |
| Each command uses the variable, else its own section, else `[global]` | 26.1.2: `[global] P30D`, `[install] P20D`: install "now minus 20 days", download, lock, wheel and index "now minus 30 days"; `PIP_UPLOADED_PRIOR_TO=P3D`: all five 3 days; empty: no change | `parse_args` per command |
| A date without an offset is local time | 26.1.2: `[install] 2026-10-01` gave `2026-10-01 00:00:00-07:00` in UTC-7, `+00:00` with `TZ=UTC` (`astimezone()` on a naive value, `cli/cmdoptions.py`) | as above |
| Per section the last file read wins; an empty winner clears it | 26.1.2: `~/.pip/pip.conf` `P30D` and `~/.config/pip/pip.conf` `uploaded-prior-to =` (read last): no cutoff; reversed, `P30D`. 26.2.1: a global file (`$XDG_DATA_DIRS/pip/pip.conf`) with `[global] P30D` and `[install] P1D`: install `P1D`, download, lock and wheel `P30D` | `pip config debug`, `parse_args` |
| The script's reading of `pip config debug` gives the value pip uses | 26.1.2 (in a virtual environment) and 26.2.1, 200 random layouts each of every section set, empty or absent (some with `[DEFAULT]`) across the global (26.2.1), legacy user, user, site and `PIP_CONFIG_FILE` files, with both variables varied: matched `parse_args` in all 400. First-file-wins or listed order mismatched in 42 and 25 of 60 | `pip config debug` into the script's judge |
| `pip config list` is ordered by file name | 26.1.2: `~/.config/pip/pip.conf` `uploaded-prior-to =` and `~/.pip/pip.conf` `P30D` listed `''` then `'P30D'` | `pip config list` |
| `wheel` has no cutoff unless `[wheel]` or `[global]` sets one | 26.1.2: `[install]`, `[download]`, `[lock]` at `P7D`, no `[global]`: wheel and index had none | `parse_args` |
| `[DEFAULT]` keys reach every section | 26.1.2: `[DEFAULT] P1D` with `[global]` and an empty `[install]` gave every command `P1D`, listed under `global.` and `install.`; `config --user set` wrote `[DEFAULT]` back first | `pip config debug`, `parse_args` |
| `python3 -m venv` installs the pip `ensurepip` bundles | Xcode's Python 3.9 (`/usr/bin/python3`): 21.2.4, with no `uploaded_prior_to`; Homebrew's 3.14.6: 26.1.2 | `python3 -I -c 'import ensurepip; print(ensurepip.version())'`, `python3 -m venv` |
| A duplicate key makes the file unloadable | 26.1.2: `--version`, `config list` and `config --user set` exited 2, "Configuration file could not be loaded" | two `uploaded-prior-to` lines in `[global]` |
| `pip config --user set` writes the last user file `pip config debug` lists, and rewrites it whole | 26.1.2: printed `Writing to <path>`; `# my comment` and `; another comment` were gone, `uploaded-prior-to=2026-01-01` became `uploaded-prior-to = 2026-01-01`, sections got a trailing blank line; the legacy `~/.pip/pip.conf` was untouched | `pip config --user set global.uploaded-prior-to P7D` |
| Two pips can read different user files | 26.2.1 with `$XDG_DATA_HOME/pip` present listed and wrote `$XDG_DATA_HOME/pip/pip.conf`; 26.1.2 then said "No such key" | `pip config debug`, `--user set`, `--user get` with each |
| `PIP_CONFIG_FILE` drops the user file | 26.1.2 source only (`configuration.py`: user files skipped when it names an existing file, every file when `/dev/null`); not run | |
| `--isolated` ignores the cutoff | 26.1.2, 2026-10-10, against pypi.org, `[global] uploaded-prior-to = P36500D` in `~/.config/pip/pip.conf`: "from versions: none"; with `--isolated` it downloaded `six-1.17.0-py2.py3-none-any.whl` | `pip download --no-deps --only-binary :all: six==1.17.0` |
| A direct URL requirement ignores the cutoff | 26.1.2, the same run and file: downloaded | `pip download --no-deps "six @ https://files.pythonhosted.org/packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl"` |
| pip-tools refuses a source-only package under `--only-binary :all:` | pip-tools 7.6.1, 2026-10-14: refused `docopt` 0.6.2 (published only as source) rather than building it | `pip-compile --pip-args "--only-binary :all:"` |
| A source build runs the sdist's backend; `only-binary` can be switched back off | 26.1.2, an inert local sdist whose in-tree backend writes a marker file: it ran; a user `[global] only-binary = :all:` refused it ("No matching distribution found"); `--no-binary :all:` in a requirements file, or the sdist's path, ran it again | `pip download --no-deps --no-index --find-links <dir> <name>==0.1` |

## uv

Run on 2026-10-08, in a fresh `HOME`, with Homebrew's uv 0.10.9 and uv 0.9.16, 0.9.17 and 0.12.21 from their PyPI
wheels (fetched as above; 0.12.21 was the newest 0.12 release at least 7 days old). Each command is `uv lock --offline`
on harden-dev.sh's empty probe project, with `UV_CACHE_DIR` in a temp directory and `UV_PYTHON_DOWNLOADS=never`, the
value in `~/.config/uv/uv.toml` unless said otherwise.

| Fact | Versions | Value |
|------|----------|-------|
| A relative `exclude-newer` needs uv 0.9.17 | 0.9.16: "failed to parse year in date \"7 days\""; 0.9.17: `exclude-newer-span = "P7D"` | `exclude-newer = "7 days"` |
| The lock records the cutoff in `[options]` | 0.10.9: `exclude-newer = "<now minus 7 days>"` and `exclude-newer-span = "P7D"`; 0.12.21: the span and a placeholder `exclude-newer = "0001-01-01T00:00:00Z"` ("This has no effect and is included for backwards compatibility when using relative exclude-newer values.") | `"7 days"` |
| `false` is no cutoff | 0.12.21: no `[options]`; 0.10.9 could not parse it | `exclude-newer = false` |
| Per-package values are recorded, even for packages not locked | `[options.exclude-newer-package]`: `six = { timestamp = "...", span = "P1D" }` (0.12.21: the year-1 placeholder), `idna = "2026-01-01T00:00:00Z"`, `requests = false` | `exclude-newer-package = { six = "1 day", idna = "2026-01-01T00:00:00Z", requests = false }` |
| `[pip] exclude-newer` is not recorded | both: no `[options]` | `[pip]` `exclude-newer = "1 day"` alone |
| `[pip] exclude-newer-package` is read by `uv pip` | 0.10.9, 0.12.21: `uv pip compile --show-settings` listed `idna` and `six` under `exclude_newer.package` | `[pip]` `exclude-newer-package = { six = false, idna = "1 day" }` |
| An `[[index]]` entry's `exclude-newer` replaces the top-level value for that index, unrecorded | top-level `"3650 days"` (`six` resolves to 1.10.0, from 2015); `[[index]] name = "pypi"`, `url = "https://pypi.org/simple"`, `default = true`, `exclude-newer = false`: 0.12.21 locked `six` 1.17.0, 0.10.9 1.10.0. `"1 day"`, or `false` on a non-default PyPI entry (explicit or not), gave 1.17.0 on 0.12.21; `false` on a non-default `https://test.pypi.org/simple` entry gave its 1.16.0. `[options]` was unchanged. uv's changelog, 0.11.5: "Add `exclude-newer` to `[[tool.uv.index]]`" | user `uv.toml`, a project depending on `six` |
| `UV_PROJECT` and `UV_WORKING_DIR` move `uv lock`; `UV_FROZEN` and `UV_LOCKED` need a lock | 0.10.9, 0.12.21: either of the first two, naming a project with `"30 days"` and no lock, made the probe's `uv lock` write that project's `uv.lock` with `P30D`; `UV_FROZEN=1` or `UV_LOCKED=1` failed ("Unable to find lockfile at `uv.lock`") | `uv lock --help` lists the first three, not `UV_LOCKED` |
| A system `uv.toml` comes from `XDG_CONFIG_DIRS` | 0.10.9, 0.12.21: `$XDG_CONFIG_DIRS/uv/uv.toml` with `"1 day"` set the cutoff | |
| `[pip] exclude-newer` replaces the top-level value for `uv pip` | 0.10.9, 0.12.21: `uv pip compile` and `uv pip install --dry-run` resolved `1d`, `uv lock` `7d`; without the `[pip]` value, all three `7d` (uv's hidden `--show-settings`) | top-level `"7 days"`, `[pip]` `exclude-newer = "1 day"` |
| The environment wins over the file | 0.10.9, 0.12.21: `exclude-newer-span = "P3D"` | `UV_EXCLUDE_NEWER="3 days"` over `"30 days"` |
| The probe's `[tool.uv]` stops the walk up | 0.10.9: a parent-directory `uv.toml` with `"1 day"` set the cutoff without it, and was ignored with it (the user's `"9 days"` applied) | |
| The probe's workspace table keeps it out of a parent workspace | 0.10.9: a parent `pyproject.toml` with `[tool.uv.workspace] members = ["wormsign-harden.*/probe"]` and `"30 days"` adopted the probe (`uv.lock` in the parent, `P30D`); with `members = []` in the probe, the lock stayed in the probe, no cutoff | |
| A probe's own `uv.toml` beats the user's top-level value | 0.10.9, 0.12.21: `P1D` from the probe's `"1 day"` over the user's `"7 days"`, below that parent workspace too | |
| Locking writes nothing outside the probe and the cache | 0.10.9, 0.12.21: `HOME` held only the test's `uv.toml`; the cache, interpreter information only | |
| Without `--no-build`, adding or hashing a source-only package runs its build backend | 0.10.9, 2026-10-14, a scratch `HOME`: `uv add --no-sync` and `uv pip compile --generate-hashes` ran setuptools' `prepare_metadata_for_build_wheel` (the package's `setup.py`) for `docopt` 0.6.2, published only as source; with `--no-build`, both refused and wrote nothing | |
| `no-build` refuses an sdist; a project can switch it back off | 0.10.9, 0.12.21, the inert sdist above: a user `no-build = true` refused it on `uv lock` ("has no usable wheels"); a project's `[tool.uv] no-build = false` ran the backend | |

## Git dependencies at install

npm's `--ignore-scripts` and pnpm's and Yarn's default blocking do not all cover the scripts run while a git
dependency is fetched. Verified on Node 24.21.0 (2026-10-09) with a benign local git dependency (an
`optionalDependencies` entry) whose `prepare` writes a marker file, each npm in an empty `HOME`:

| npm | Ran a git dependency's `prepare` script? |
|---|---|
| 10.9.2 (Node 22.13 to 22.17) | yes, under `npm ci --ignore-scripts`, `npm install --ignore-scripts` and `ignore-scripts=true` in `.npmrc` |
| 10.9.9 (Node 22.23.3) | yes, under `npm ci --ignore-scripts` |
| 11.12.1, and 11.19.0 (bundled with Node 24.21.0) | no under `npm ci --ignore-scripts`; yes without it, which shows the test can see a run |
| 12.2.0 | did not fetch the git dependency at all (`allow-git` defaults to `none`); with `--allow-git=all`, yes unless `--ignore-scripts` was given, so npm 12's default script blocking (H01) does not cover it |

- **pnpm.** 10.0.0 to 10.25.x run a git dependency's `prepare`, `prepublish` and `prepack` while fetching it, despite
  the default blocking; fixed in 10.26.0
  ([CVE-2025-69264, GHSA-379q-355j-w6rj](https://github.com/advisories/GHSA-379q-355j-w6rj)). **Not run here**: from
  the advisory only, whose source excerpt shows `--ignore-scripts` skipping the step.
- **Yarn 2+.** 4.18.1 refuses a git dependency by default ("blocked because it doesn't match any of the patterns in
  'approvedGitRepositories'", `YN0080`); with `approvedGitRepositories: ["**"]` and `enableScripts: false` in the
  project's `.yarnrc.yml`, its `prepack` ran while it was fetched and its `prepare` did not. Verified 2026-10-02 with
  a benign dependency served by a local `git daemon`, whose scripts write marker files
  (`"gitdep": "git://127.0.0.1:<port>/dep#main"`, `yarn install`). **UNVERIFIED** on 4.10.3.

## How harden-dev.sh reads settings

**The `pm` sandbox.** Verified on macOS with `pm`'s environment, from an empty directory:

```sh
P='(version 1)(allow default)(deny network* (with send-signal SIGKILL))'
HOME=$(mktemp -d) sandbox-exec -p "$P" <pm> config get <key>   # with the env above, from an empty dir
```

Every probe (`npm` 10.9.2, 11.21.0, 12.2.0; `pnpm` 10.16.0, 11.16.0, 12.8.1; `yarn` 1.22.22, 4.10.3, 4.18.1; `bun`
1.4.2; `npm root -g`) exited 0, so none touched the network, and the temp HOME stayed empty. Positive control: the
corepack 0.32.0 `pnpm` and `yarn` shims with an empty cache were killed by the sandbox (exit 137) without
`COREPACK_ENABLE_NETWORK=0`, and exited 1 without a network attempt with it. A whole
`HOME=$(mktemp -d) sandbox-exec -p "$P" bash harden-dev.sh --offline` left HOME and TMPDIR empty in check mode.
Without the cache settings `pm` makes, files did appear: `yarn config get` (1.22.22) wrote
`~/Library/Caches/Yarn/v6/.tmp` (hence `YARN_CACHE_FOLDER`), and without `NODE_DISABLE_COMPILE_CACHE=1` and
`DISABLE_V8_COMPILE_CACHE=1` npm 10.9.2 and the corepack shims left `node-compile-cache/`, and Yarn 1.22.22
`v8-compile-cache-<uid>/`, in `$TMPDIR`.

**H12 and H13 on real pip and uv.** `test/harden-real.test.ts` (`HARDEN_REAL=1`) ran on 2026-10-08 on the pip and uv
machine above, with uv 0.10.9 and 0.12.21: with pip 26.2.1 (a virtual environment) as `python3 -m pip` and Homebrew's
pip 26.1.2 as `pip3`, 22 of 22 passed; the other way round, 21 passed and the system-wide `[global]` case was skipped.
No real pip write produced a file it could not load, so that undo is covered by stubs only. For 8 user files
(`[DEFAULT]`, continuation lines, `quiet`, `verbose`, an upper-case section and key) the stub's `pip config debug`,
`config list` and `config --user set` matched pip 26.1.2's line for line, temp paths aside.

**The other checks.**

- *gh (H09).* The format is from gh's source (`pkg/cmd/auth/status/status.go`, fetched 2026-10-02). gh 2.96.0 with a
  `hosts.yml` for the unresolvable `wormsign-test.invalid` printed "Failed to log in", which the script reported as a
  WARN; the timeout form is from the source only, and gh 2.39.0's "Logged in to <host> as <user>" is not parsed.
  **UNVERIFIED**: a live multi-account login, and gh versions other than 2.96.0.
- *find (H11).* Without `-H`, macOS find listed nothing under a symlinked root, with no error. `-H` is tested with
  BSD find and GNU find on `ubuntu-latest`; symlinks below a root are not followed, and no test covers that.
- **UNVERIFIED**: H10's credential paths for the current AWS/gcloud/Azure/kubectl/docker/terraform CLIs; pip's Linux
  user file (`$XDG_CONFIG_HOME/pip`, else `~/.config/pip`, from its vendored `platformdirs/unix.py`).
