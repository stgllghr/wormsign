# `wormsign diff`

Report what a change adds that could run code at install time or in CI, to gate pull requests. `diff` reads git
objects and files only: it never runs anything from either side and never uses the network.

```text
wormsign diff <base> <head> [--format human|json|sarif] [--output <file>] [--fail-on <severity|never>]
                            [--baseline <file> | --no-baseline] [--iocs <dir>] [--registry-host <host>]...
                            [--dir <path>]
```

`<base>` and `<head>` are git revisions (full SHAs in CI) of the repository containing `--dir`, or `dir:<path>` for a
directory. A bare name is never a directory, so a pull request cannot add one called `HEAD` to stand in for a
revision.

## What it checks

`diff` compares the whole commit from the repository root, whatever `--dir` is: the root lockfile and config govern
every workspace. Names fold as macOS and Windows fold them (case, Unicode compatibility), so `.NPMRC` is `.npmrc`.

| What changed | Finding |
|---|---|
| A lockfile entry added or re-pointed (name, version, `resolved` or `integrity`) whose package has install scripts no earlier version of that name had | [WS-DF-001](../rules.md#ws-df-001) (new name), [WS-DF-004](../rules.md#ws-df-004) (new version) |
| Added lockfile entries: IOC versions, non-registry sources, missing integrity | [WS-LK-001](../rules.md#ws-lk-001), [WS-LK-002](../rules.md#ws-lk-002), [WS-LK-003](../rules.md#ws-lk-003) |
| A `package.json` install-time script (`preinstall`, `install`, `postinstall`, `prepublish`, `preprepare`, `prepare`, `postprepare`, `predependencies`, `dependencies`, `postdependencies`, `pnpm:devPreinstall`) added or changed | [WS-DF-002](../rules.md#ws-df-002); [WS-LC-002](../rules.md#ws-lc-002) / [WS-LC-003](../rules.md#ws-lc-003) if suspicious or running an IOC file |
| A workflow (`.github/workflows/*.yml`, `*.yaml`) or local action (`action.yml`, `action.yaml`) added or changed | [WS-DF-003](../rules.md#ws-df-003), plus [WS-GH-001](../rules.md#ws-gh-001) to [WS-GH-007](../rules.md#ws-gh-007) on the new content |
| An editor or agent auto-run file added or changed (`.vscode/tasks.json`, tasks or terminal settings in `.vscode/settings.json`, `*.code-workspace`, `.mcp.json`, Claude Code settings, plugin, skill, command or subagent files) | [WS-PS-001](../rules.md#ws-ps-001), [WS-PS-002](../rules.md#ws-ps-002), as in `scan` |
| Install or report policy added, changed or removed: `.wormsign-baseline.json`; `packageManager` or `devEngines.packageManager` (corepack runs it; high even when pinned by hash); `.npmrc`, `.yarnrc`, `.yarnrc.yml`, `.env.yarn`, `.corepack.env`, `pnpm-workspace.yaml`, `.pnpmfile.cjs`, `.pnpmfile.mjs`, `bunfig.toml`, `.yarn/releases/`, `.yarn/plugins/`, `.pnp.cjs`, `.pnp.loader.mjs`, and files config names as code to run (`yarnPath`, `plugins`, `injectEnvironmentFiles`, `yarn-path`, `pnpmfile`, `globalPnpmfile`, `script-shell`); `pip.conf`, `pip.ini`, `uv.toml` and a `pyproject.toml`'s `[tool.uv]` install settings, under `ignorePaths` too | [WS-DF-005](../rules.md#ws-df-005) |
| A lockfile removed (npm's, a Python lock, or a hash lock: a requirements file with `--hash` or `--require-hashes`, found as `soak` finds it), or a hash lock's hashes stripped | [WS-DF-005](../rules.md#ws-df-005) |
| A Python project's build changed or new ([below](#a-python-build-changed-expected-on-ordinary-pull-requests)) | [WS-DF-005](../rules.md#ws-df-005) |
| A changed manifest or lockfile that does not parse (high for a `pyproject.toml`, under `ignorePaths` too); a changed `bun.lock`, `bun.lockb`, `package.yaml` or `package.json5`, which wormsign does not parse; a workflow over 2 MiB | [WS-DF-006](../rules.md#ws-df-006) |
| A Python lock or requirements file added, changed or removed (a removed or de-hashed lock is WS-DF-005, above), or any edit to a `pyproject.toml`, `setup.py`, `setup.cfg` or `Pipfile`. `diff` reads neither them nor what a manifest declares; `soak --base` checks them ([soak.md](../soak.md#installing-the-project-itself)) | [WS-DF-006](../rules.md#ws-df-006) at medium, below the default `--fail-on high` |
| A manifest, lockfile, workflow or config path that is not one file in the tree (a symlink out of it or into `node_modules`, a submodule, a case-only name clash) | [WS-DF-006](../rules.md#ws-df-006), on every run, changed or not |

`[tool.uv]` keys that shape resolution, the lock or uv itself are only the medium WS-DF-006: the keys uv refuses in
a `uv.toml`, `override-dependencies`, `constraint-dependencies`, `required-version`, `cache-keys`, `build-backend`,
and sources inside the repository (`{ workspace = true }`, a relative `path`).

The baseline comes from `<base>`, so a change cannot baseline its own findings
([baseline.md](../baseline.md#where-each-command-reads-it), which also lists what
[`ignorePaths`](../baseline.md#ignorepaths) hide here).

### A Python build changed: expected on ordinary pull requests

A project is a directory with a `setup.py`, or a `pyproject.toml` with `[project]` or `[build-system]` or beside a
`setup.cfg` declaring dependencies. `diff` compares its build, under `ignorePaths` too, by `soak`'s local-build key
([soak.md](../soak.md#builds-ws-sk-005)), which does not cover what the build reads or imports. A project a `uv.lock`
or `pylock.toml` lists is left to `soak --base` (WS-SK-005). For others the check fires on ordinary changes, by
design, each high:

- a new package directory, such as a new monorepo member;
- a `build-system.requires` bump, by hand or by Renovate's
  [`pep621` manager](https://docs.renovatebot.com/modules/manager/pep621/);
- any edit to `setup.py`, `setup.cfg` (a `[flake8]` section included) or a build hook;
- an edit to `[project]`'s dependencies, unless the `build-backend` is known never to build with them, or to a
  `[tool]` table no build is known to ignore (`[tool.uv]`, `[tool.bumpversion]`).

A `[project]` version bump, metadata fields and linters' settings do not count. The pull request cannot approve its
own finding: a maintainer checks each new build requirement (it exists, is old enough, is the package intended) and
overrides the required check ([baseline.md](../baseline.md#reviewing-baseline-changes)). A build not read in full (a
case-only name clash, a cap, a path climbing from a symbolic link) counts as changed on every change.

## Options

`--format`, `--output`, `--fail-on`, `--registry-host` and `--iocs` work as for [`scan`](scan.md#options). Any other
option, or other than two revisions, is a usage error (exit 2).

| Option | Meaning |
|---|---|
| `--baseline <file>` | Baseline file. Default: `.wormsign-baseline.json` as committed in `<base>`. |
| `--no-baseline` | Read no baseline, not even the one in `<base>`. Excludes `--baseline`. |
| `--dir <path>` | Any directory in the git repository (default `.`). The whole commit is compared. |

## Examples

A `feature` branch that adds a dependency with an install script and an `.npmrc` holding `ignore-scripts=false`
(paths shortened):

```console
$ wormsign diff main feature
HIGH     WS-DF-005  .npmrc
         .npmrc added in this change: it controls what installs run or what wormsign reports
         fingerprint: 45d30a04e6f50de196d4f6541620e266
HIGH     WS-DF-001  package-lock.json
         New dependency native-thing@1.0.0 runs install scripts
         fingerprint: c2b8e7f1be193231f4955bd3f9b68038

wormsign diff: 2 finding(s) (0 critical, 2 high, 0 medium, 0 low, 0 info)
note: IOC data 2026-10-02 from the bundled data /path/to/wormsign/data/iocs/
note: compared main (15c5f7c8916d) with feature (9e157c48bf18)
$ echo $?
1
```

In CI ([github-action.md](../github-action.md)), compare the base with the merge
commit and write the report outside the checkout:

```sh
wormsign diff "$BASE_SHA" "$MERGE_SHA" --format sarif --output "$RUNNER_TEMP/diff.sarif"
```

## Exit codes

`0`, `1` and `2` as in [output.md](../output.md#exit-codes). Exit 2 covers the wrong number of revisions, a
revision git cannot resolve, `--dir` outside a git repository, and an invalid baseline or IOC file; no report is
written.

## Network

None. Revisions are read from the local repository with `git rev-parse`, `git ls-tree` and `git show`, so both
commits must already be fetched (with `actions/checkout`, `fetch-depth: 2` on the merge commit is enough for
`HEAD^1`). git runs with lazy fetching off (`GIT_NO_LAZY_FETCH=1`) and every transport refused
(`-c protocol.allow=never`), so in a partial clone (`--filter=blob:none`, `actions/checkout`'s `filter`) a file whose
content is not local is never fetched, over the network or with the transport settings the repository's own
`.git/config` names: `diff` stops with exit 2 and names the file (`git could not read <path> at <rev>`) instead of
reading it as absent. Use a full clone.

## Limitations

- **It reads neither code that scripts, hooks or actions load nor payload files or exfiltration endpoints**: a
  change adding `setup_bun.js` and a `webhook.site` URL gives no `diff` finding, while [`scan`](scan.md) reports
  WS-FS-002 (high) and WS-EX-001 (medium). Run `scan` on pull requests too.
- **New install scripts show only where the lockfile records them**: npm from `lockfileVersion` 2
  (`hasInstallScript`) and pnpm before v9; for pnpm v9+ and Yarn a note suggests `scan --node-modules`.
- **It does not verify Yarn zero-install archives** (`.yarn/cache`); run `yarn install --check-cache` in CI.
- **A gate the pull request builds can be edited by it** ([github-action.md](../github-action.md#what-the-gate-does-not-stop)).
- **Python build comparison is capped by file count, not bytes** (64 hook files, 16 `backend-path` entries, 200
  `.py` files beside a hook, 2,000 files under a `backend-path` entry), so a large monorepo can be slow; a CI timeout
  fails the job.
- **In `dir:` mode, a hook behind a symlink whose link text climbs with `..` can be read at the wrong file**; git
  revisions are not affected.
