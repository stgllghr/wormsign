# `wormsign scan`

Scan one project directory for signs of a Shai-Hulud-style compromise and for the settings such a worm uses to
spread. `scan` reads files only: it never runs anything from the project and never uses the network.

```text
wormsign scan [dir] [--format human|json|sarif] [--output <file>] [--fail-on <severity|never>]
                    [--baseline <file> | --no-baseline] [--iocs <dir>] [--node-modules] [--hash-all]
                    [--registry-host <host>]...
```

`dir` defaults to the current directory.

## What it checks

`scan` walks every file under `dir`, skipping `.git` always and `node_modules` unless `--node-modules` is given:

| File | Checks | Rules |
|---|---|---|
| `package.json`, at any depth | `preinstall`, `install`, `postinstall`; those and `preprepare`, `prepare`, `postprepare`, `prepublish` for download-and-execute, encoded payloads, credential harvesting or IOC payload names; uncheckable `file:` dependencies | [WS-LC-001](../rules.md#ws-lc-001), [WS-LC-002](../rules.md#ws-lc-002), [WS-LC-003](../rules.md#ws-lc-003), [WS-SC-900](../rules.md#ws-sc-900) |
| `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` | each `name@version` against the IOC list; a host other than `registry.npmjs.org`, `registry.yarnpkg.com` or a `--registry-host`, git or plain HTTP; missing integrity | [WS-LK-001](../rules.md#ws-lk-001), [WS-LK-002](../rules.md#ws-lk-002), [WS-LK-003](../rules.md#ws-lk-003) |
| `.github/workflows/*.yml`, `*.yaml` | IOC workflow and runner names; `toJSON(secrets)`; `pull_request_target` or `workflow_run` checking out pull request code; self-hosted runners; a secret passed to a command that writes a file or uses the network; discussion triggers running shell | [WS-GH-001](../rules.md#ws-gh-001) to [WS-GH-007](../rules.md#ws-gh-007) |
| `.vscode/tasks.json`, `.vscode/settings.json`, `*.code-workspace` | tasks that run on folder open; settings' `tasks` and the terminal settings tasks run with (`terminal.integrated.automationProfile`, `defaultProfile`, `profiles`, `env`) | [WS-PS-001](../rules.md#ws-ps-001) |
| `.claude/` settings, hooks, plugin, skill, command and agent files; `.mcp.json` | hooks, command settings, `env` entries and MCP servers that run commands automatically | [WS-PS-002](../rules.md#ws-ps-002) |
| A file named in the IOC list (any file with `--hash-all`) | the name; SHA-256 against payload hashes | [WS-FS-001](../rules.md#ws-fs-001), [WS-FS-002](../rules.md#ws-fs-002) |
| `.js`, `.cjs`, `.mjs`, `.ts`, `.sh`, `.bash`, `.zsh`, `.ps1`, `.yml`, `.yaml`, `.json`, `.py`, `.rb` (not lockfiles) | IOC exfiltration endpoints, up to 64 MiB (larger or unreadable: low WS-SC-900); webhook, paste, request-capture and tunnel hosts, up to 2 MiB (larger: a note) | [WS-EX-002](../rules.md#ws-ex-002), [WS-EX-001](../rules.md#ws-ex-001), [WS-SC-900](../rules.md#ws-sc-900) |
| `pnpm-workspace.yaml` | `overrides` that install local packages it cannot check | [WS-SC-900](../rules.md#ws-sc-900) |
| `.pnpmfile.cjs`, `.pnpmfile.mjs`, `.env.yarn`, `.yarn/releases/`, `.yarn/plugins/`, `.pnp.cjs`, `.pnp.loader.mjs`, and settings naming code (`yarnPath`, `plugins`, `injectEnvironmentFiles`, `yarn-path`, `pnpmfile`, `globalPnpmfile`, `global-pnpmfile`, `script-shell`, and an `.npmrc` `node-options` doing more than set a memory or stack limit or what Node.js prints), outside `node_modules` | code a package manager runs without a lifecycle script, hashed into the fingerprint | [WS-LC-004](../rules.md#ws-lc-004) |
| `package.yaml`, `package.json5`, `bun.lock`, `bun.lockb` | reported as not checked, as wormsign cannot parse them (a `package.yaml` or `package.json5` beside a `package.json`, or without scripts, is skipped with a note) | [WS-SC-900](../rules.md#ws-sc-900) |
| `node_modules/**/package.json` (`--node-modules`) | installed packages with an install script or `binding.gyp`; IOC versions; suspicious or IOC scripts | [WS-NM-001](../rules.md#ws-nm-001), [WS-LK-001](../rules.md#ws-lk-001), [WS-LC-002](../rules.md#ws-lc-002), [WS-LC-003](../rules.md#ws-lc-003) |

A file that decides what runs at install time or in CI but cannot be read is a high
[WS-SC-900](../rules.md#ws-sc-900), not a skip: too large (2 MiB for text files, 64 MiB for lockfiles), NUL bytes,
invalid JSON, or a symlink. `scan` never follows a symlink; one to a directory it does not otherwise reach is high
when the target holds a `package.json`, low otherwise.

IOC data is the bundled `data/iocs/` plus newer [`update-iocs`](update-iocs.md) entries, or `--iocs <dir>`; the first
`note:` says which ([iocs.md](../iocs.md)).

## Options

Any other option, or a second directory, is a usage error (exit 2).

| Option | Meaning |
|---|---|
| `--format human\|json\|sarif` | Output format (default `human`). See [output.md](../output.md). |
| `--output <file>` | Write the report to a regular file, never through a symlink (exit 2). Keep it outside the scanned tree. |
| `--fail-on <severity\|never>` | Exit 1 at or above this severity (default `high`). |
| `--baseline <file>` | Baseline file (default `<dir>/.wormsign-baseline.json`; [baseline.md](../baseline.md)). |
| `--no-baseline` | Read no baseline; use it on a tree you did not write. Excludes `--baseline`. |
| `--node-modules` | Also scan installed packages and flag every install script. |
| `--hash-all` | SHA-256 every file, not only IOC-named ones (slow); a note lists files over 64 MiB, not hashed. |
| `--registry-host <host>` | Extra registry host lockfiles may resolve from (repeatable): the exact lower-case host and port (`npm.example.com:8443`). Plain HTTP is still reported. |
| `--iocs <dir>` | Use the five IOC files in this directory instead of the bundled/cached ones. |

## Examples

The synthetic malicious fixture with the tests' synthetic IOC list (inert, invented indicators such as `*.invalid`
hosts), trimmed, with absolute paths shortened:

```console
$ wormsign scan test/fixtures/malicious --iocs test/fixtures/iocs
CRITICAL WS-GH-006  .github/workflows/risky.yml:15
         Targets runner WORMSIGNTEST, the name the worm registers (test wave)
         source: https://example.test/synthetic-ioc
         fingerprint: 698fdaff0eec26f44c40b3979c92478f
...
wormsign scan: 22 finding(s) (7 critical, 9 high, 6 medium, 0 low, 0 info)
note: IOC data (unversioned) from --iocs test/fixtures/iocs
note: node_modules was not scanned (use --node-modules for a deep scan)
note: 8 files scanned
$ echo $?
1
```

With the bundled IOC data the fixture gives 15 findings (0 critical).

## Exit codes

`0`, `1` and `2` as in [output.md](../output.md#exit-codes); baselined findings never count. Usage errors are found
before anything is scanned.

## Network

None. `scan` reads the directory, the bundled IOC data and, if present, the `update-iocs` cache
(`$XDG_CACHE_HOME/wormsign/iocs`, default `~/.cache/wormsign/iocs`).

## Limitations

- **IOC matching finds only what is listed**; [`soak`](soak.md) is the control for versions nobody has listed yet.
- **Script checks are patterns, not analysis.** `node setup.js` is checked by the file's name, its hash (when the
  name is an IOC, or with `--hash-all`, which alone finds a renamed payload) and the endpoint checks; obfuscated
  JavaScript is not detected.
- **Python locks and manifests are not read**; a note names them, and [`soak`](soak.md) checks what they pin.
- **Without `--node-modules`, `scan` sees what the lockfile pins**, not what was installed.
- **YAML and JSONC are read by small purpose-built readers.** Forms they do not model (an all-JSON workflow, flow
  collections for `jobs:` or `steps:`, a flow-mapping step, YAML aliases or merge keys, a `${{ }}` unclosed within 50
  lines (outside a comment) or partly escaped, or a U+0085, U+2028 or U+2029 character) and a VS Code or Claude Code
  JSON `"__proto__"` key are WS-SC-900, high. What can still hide a pattern is listed atop `src/checks/workflows.ts`.
- **Names fold as macOS and Windows open them** (NFKC, then case, and Windows' trailing periods and spaces); two
  files that decide what runs and fold alike are each WS-SC-900.
- **WS-LC-004 reports package-manager code, not what it does**, nor the files `node-options` loads or `bunfig.toml`
  `preload`.
- **A baseline in the scanned directory is the tree's own** and can hide any finding; `scan` warns when it did.
- **A Yarn 1 entry without an `integrity` line passes WS-LK-003 on the SHA-1 in its `resolved` URL**, weaker than
  SHA-512.
- **An installed package's script findings ignore its command** in the fingerprint
  ([baseline.md](../baseline.md#when-a-fingerprint-changes)).
- **No git history, branches or organization**: see [`audit-org`](audit-org.md).
