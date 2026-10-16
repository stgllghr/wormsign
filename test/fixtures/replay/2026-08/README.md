# Replay: Shai-Hulud, August 2026 wave (keyv, cacheable)

**This is a reconstruction, not a sample.** Every payload and hook file holds a one-line marker instead of code.
Nothing here runs anything, fetches anything or matches a payload hash.

Layout: `package/` is the package as the worm republishes it; `repo/` is what it commits to repository branches.

## Features and sources

Source (snapshot SHA-256 of the page as saved for this project in parentheses):

- [JFrog] https://research.jfrog.com/post/shai-hulud-is-back-august/ (0c168fa5...)

| Feature | Replay file | Source | Located by |
|---|---|---|---|
| Install script runs the loader, replacing all scripts | `package/package.json` `scripts: { preinstall: node setup.mjs }` | JFrog | "Replaces the package's complete scripts object" |
| Payload file names | `package/setup.mjs`, `package/math_init.js` (markers) | JFrog | "Copies the running sample to package/math_init.js" |
| Repository hook files | `repo/.vscode/tasks.json` and `repo/.claude/settings.json` (rebuilt: see below); `repo/.vscode/setup.mjs`, `repo/.claude/math_init.js`, `repo/.claude/setup.mjs` (markers) | JFrog | "The worm also commits five files to GitHub branches it can reach" |
| Injected workflow name | `repo/.github/workflows/codeql_analysis.yml` | JFrog | "Adds .github/workflows/codeql_analysis.yml" |
| Its name | `name: Run Copilot` | JFrog | "The injected workflow is named Run Copilot" |
| Its secret handling | `${{ toJSON(secrets) }}` in an env variable, written to `format-results.txt`, uploaded as artifact `format-results` | JFrog | "write it to format-results.txt" |
| Its pinned actions | `actions/checkout@de0fac2e...`, `actions/upload-artifact@bbbca2dd...` | JFrog | "The workflow pins actions/checkout@" |

## Reconstruction choices

- JFrog does not give the workflow's trigger, job name, variable name or write command. The replay uses
  `on: push`, job `format`, variable `DATA` and the heredoc that the November 2025 formatter workflow used (as
  published by Wiz). No rule depends on the trigger or the names; WS-GH-005 does depend on the write command
  (see below).
- JFrog describes what `.vscode/tasks.json` and `.claude/settings.json` do ("an Environment Setup task that runs
  node .claude/setup.mjs when a folder opens"; "a SessionStart hook that runs node .vscode/setup.mjs") but not
  their text. The replay writes the minimal valid form of each: a `shell` task with `runOptions.runOn: folderOpen`,
  and a `command` hook under `hooks.SessionStart`. The two `setup.mjs` files and `math_init.js` stay markers.

## What wormsign reports (asserted by `test/validation-replay.test.ts`)

- scan: WS-LC-001 (medium), WS-GH-001 (medium: the name resembles legitimate CodeQL files), WS-GH-002 (high),
  WS-PS-001 (high: the folder-open task) and WS-PS-002 (high: the SessionStart hook). Exit 1. The package alone
  gives one medium finding.
- diff (a pull request adding these files): WS-DF-002, WS-DF-003, WS-GH-001, WS-GH-002, WS-PS-001, WS-PS-002.
  Exit 1.
- The WS-PS messages say each hook runs `setup.mjs`, a file name the IOC data lists for this wave (from its hash
  entry). The package's `preinstall: node setup.mjs` is still not WS-LC-003, because that rule reads only the
  name-only IOC list, where `setup.mjs` and `math_init.js` are not listed.
- Missed: WS-GH-005, for the same two reasons as the November 2025 formatter workflow (a `toJSON(secrets)`
  binding, and a heredoc that names the variable on the line after the `>`). With a one-line write such as
  `echo "$DATA" > format-results.txt` it would still miss, because of the binding.

## Not replayed

- The workflow lives on the branch `dependabot/github_actions/format/setup-formatter`, which the worm deletes
  after the run; `audit-org` looks for that branch (`data/iocs/repos.json`).
- The exfiltration repository description ("Shai-Hulud: Here We Go Again") is GitHub state; `audit-org` matches it.
- `keyv@6.0.0` and the other affected versions are in the bundled IOC data; a lockfile that pins one is
  WS-LK-001 (critical), which `test/validation-recall.test.ts` shows for every listed version.
