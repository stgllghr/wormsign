# Replay: Mini Shai-Hulud, April to May 2026

**This is a reconstruction, not a sample.** Every payload and hook file holds a one-line marker instead of code.
Nothing here runs anything, fetches anything or matches a payload hash. The git dependency points at a `.invalid`
host, so an install in `tanstack-route/` cannot reach the attacker's commit.

Only features stated in the Picus write-up are reconstructed, because no other source for this wave was saved
for this project.

Layout: `package/` is a package as the worm republishes it; `repo/` is what it pushes to a victim repository;
`tanstack-route/` is a project whose lockfile resolved the May 2026 route's git dependency.

## Features and sources

Source (snapshot SHA-256 of the page as saved for this project in parentheses):

- [Picus] https://www.picussecurity.com/resource/blog/mini-shai-hulud-the-npm-supply-chain-worm-explained (8df42c29...)

| Feature | Replay file | Source | Located by |
|---|---|---|---|
| Install script runs the loader | `package/package.json` `preinstall: node setup.mjs` | Picus | "\"preinstall\": \"node setup.mjs\"" |
| Payload file names | `package/setup.mjs`, `package/execution.js` (markers) | Picus | "Only the install hook and two added files, setup.mjs and execution.js" |
| Repository hook files | `repo/.vscode/tasks.json`, `repo/.vscode/setup.mjs`, `repo/.claude/execution.js`, `repo/.claude/setup.mjs`, `repo/.claude/settings.json` (markers) | Picus | "the malware also attempted to push files into .vscode/tasks.json" |
| Git dependency route (May 2026) | `tanstack-route/package.json` optional dependency `@tanstack/setup` from git | Picus | "added an optional dependency that points to a GitHub-hosted package" |
| Its install-time code | not reproduced: a `prepare` script in the git package | Picus | "That Git dependency contains a prepare script" |

## Reconstruction choices

- Picus does not describe the hook files' content, so they are markers.
- The git URL keeps the commit SHA Picus reports but replaces `github:tanstack/router` with
  `git+https://git.wormsign-replay.invalid/tanstack/router.git`.
- In the reported route the git package is an optional dependency of the compromised package, not of the project.
  The replay declares it at the project root. `tanstack-route/package-lock.json` copies the shape npm 10.9.2 wrote
  for a root-level optional git dependency whose `prepare` script exits 1 (checked for this replay with a local
  git repository): `resolved` is the git URL, `optional: true`, and there is no `integrity` and no
  `hasInstallScript`, although npm ran the `prepare` script and the install still exited 0. The version, which
  Picus does not give, is a placeholder `0.0.0`. The transitive form was not checked.

## What wormsign reports (asserted by `test/validation-replay.test.ts`)

- scan: WS-LC-001 (medium) and WS-LK-002 (git source, medium). **No finding is high, so `scan` at the default
  `--fail-on high` passes (exit 0).**
- diff (a pull request adding these files): WS-DF-002 (medium) and WS-LK-002 (medium). Exit 0.
- soak --base (the same pull request): WS-SK-002 (high) for `@tanstack/setup@0.0.0`, since a git source has no
  registry publish time, and WS-SK-003 (medium, no release-age setting). Exit 1, decided without asking the
  registry or OSV anything. **So the README's pull-request gate (`diff`, `scan` and `soak --base`) fails this
  replay, on `soak` alone.**
- Why: `node setup.mjs` matches no suspicious-script heuristic, and neither `setup.mjs` nor `execution.js` is a
  payload-name IOC in `data/iocs/files.json`; the `.vscode/tasks.json` and `.claude/settings.json` here are
  markers with no task or hook in them, because Picus does not say what they run (WS-PS-001 and WS-PS-002 report
  any automatic task or hook, high, so the real files would likely fail the gate); npm records no install-script
  flag for the git dependency, so WS-DF-001 cannot fire. The replay holds no lockfile entry for the Mini
  Shai-Hulud package versions Picus names; they are in the bundled IOC data (set `openssf-mini-shai-hulud-picus`),
  so a lockfile that pins one is WS-LK-001 (critical).

## Not replayed

- The exfiltration repository description ("A Mini Shai-Hulud has Appeared") is GitHub state; `audit-org` matches
  it (pattern `mini-description` in `data/iocs/repos.json`).
