# Setting up a machine

## harden-dev.sh
- It checks this machine's installer settings: install scripts off, release-age cooldowns for npm, pnpm, Yarn,
  bun, pip and uv, plaintext tokens, `gh` token scopes, credential files, worm payload files and the wiper's
  watcher files (checks H01 to H14). Without `--apply` it changes no settings: run it freely. `--offline` also
  skips the one check that contacts GitHub. Exit 0: no FAIL; 1: a FAIL remains; 2: a usage error.
- Where it is:
  - wormsign installed from a release (installed globally with npm): `bash "$(npm root -g)/wormsign/harden-dev.sh"`
  - a wormsign checkout, after `npm run build`: `./harden-dev.sh`
  Never pipe a downloaded copy into a shell.
- `harden-dev.sh --apply` writes the fixable user-level settings, backing up each file first. Ask the user before
  running it, and say which files it changes. It never fixes token or payload findings: report those.

## Cooldown values (7 days)
User-level settings, for installs that resolve versions on this machine:
- npm 11.10 or newer: `min-release-age=7` in `~/.npmrc` (days)
- pnpm 11 or newer: `minimumReleaseAge: 10080` in pnpm's global `config.yaml` (minutes)
- Yarn 4.10 or newer: `npmMinimalAgeGate: 10080` in `~/.yarnrc.yml` (plain minutes: Yarn 4.10 reads `3d` as 3
  minutes)
- bun: `minimumReleaseAge = 604800` under `[install]` in `~/.bunfig.toml` (seconds)
- pip 26.1 or newer: `uploaded-prior-to = P7D` under `[global]` in pip's user config
- uv 0.9.17 or newer: `exclude-newer = "7 days"` at the top level of `~/.config/uv/uv.toml`, before any `[table]`
Install scripts off: npm `ignore-scripts=true` (npm 12: `dangerously-allow-all-scripts=false`), Yarn 2+
`enableScripts: false`, Yarn Classic `ignore-scripts true` in `~/.yarnrc`, bun `ignoreScripts = true` under
`[install]` in `~/.bunfig.toml` (bun otherwise runs the scripts of its built-in list of trusted packages). From pnpm
10, dependency build scripts do not run by default (use 10.26 or newer: 10.0 to 10.25 run a git dependency's
`prepare`).
A version already in a lockfile: npm, Yarn, bun and pnpm 10 install it however young; pnpm 11 rejects a young one,
but only after linking `node_modules` (pnpm 12.8.1 before linking). For pip and uv see references/python.md.
`wormsign soak` checks every locked version either way. A project's own settings win inside that project.

## npm and Node versions
- npm enforces `min-release-age` from 11.10. npm 10, which Node 22 bundles, accepts the key and ignores it.
- Node 24.14.1 or newer bundles npm 11.10 or newer; Node 24.0.0 to 24.14.0 do not. Check `npm --version`, not
  the Node version. On an older npm, `wormsign soak` reports the setting as ignored (WS-SK-004).

## Tokens
- Never put a token in `.npmrc`, `pip.conf`, a command line or a committed file. Use the tool's credential helper
  or an environment variable the user sets.
- Never print, copy or move a token you find. When `harden-dev.sh` reports a plaintext token (H08) or an
  over-scoped `gh` token (H09), tell the user; it prints the file and line, never the value.
- Do not edit user-level installer settings (`~/.npmrc`, pip's user config, `~/.config/uv/uv.toml`,
  `~/.yarnrc.yml`, `~/.bunfig.toml`) without asking.
