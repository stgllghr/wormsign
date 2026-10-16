# Replay: Shai-Hulud 2.0 ("The Second Coming"), November 2025 wave

**This is a reconstruction, not a sample.** Every payload and harvest file holds a one-line marker instead of
code or data. Nothing here runs anything, fetches anything or matches a payload hash. The two workflows are the
text Wiz published (they contain no endpoint); a comment line marks each as a replay.

Layout: `package/` is the package as the worm republishes it; `repo/` holds the workflows it pushes to repositories;
`exfil-repo/` holds the file names it uploads to the repository it exfiltrates to.

## Features and sources

Sources (snapshot SHA-256 of the page as saved for this project in parentheses):

- [Socket] https://socket.dev/blog/shai-hulud-strikes-again-v2 (02a5733f...)
- [Wiz] https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack (b49860e4...)
- [Datadog] https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/ (4d4d697a...)

| Feature | Replay file | Source | Located by |
|---|---|---|---|
| Install script runs the loader | `package/package.json` `preinstall: node setup_bun.js` | Socket | "When npm runs the preinstall script, it executes setup_bun.js" |
| | | Datadog | "Adding (or overwriting) a preinstall script to the package.json" |
| Payload file names | `package/setup_bun.js`, `package/bun_environment.js` (markers) | Socket | "Injects two new files: setup_bun.js and bun_environment.js" |
| Backdoor workflow | `repo/.github/workflows/discussion.yaml` | Wiz | "It then adds a workflow called .github/workflows/discussion.yaml" |
| Its trigger and runner | `on: discussion`, `runs-on: self-hosted`, `run: echo ${{ github.event.discussion.body }}` | Wiz | "runs specifically on self-hosted runners" |
| Secret-dump workflow | `repo/.github/workflows/formatter_123456789.yml` | Wiz | "workflow is pushed to a newly created branch" |
| Its secret handling | `env: DATA: ${{ toJSON(secrets)}}`, written to `format.json`, uploaded as an artifact | Wiz | "uploads them as an artifact" |
| Harvest output names | `exfil-repo/*.json` (markers) | Socket | "Uploads five JSON files to the victim's repository" |

## Reconstruction choices

- No source gives the exact `preinstall` command, only that it executes `setup_bun.js`. The replay writes
  `node setup_bun.js`.
- The workflow texts are as Wiz published them, plus one leading comment line.

## What wormsign reports (asserted by `test/validation-replay.test.ts`)

- scan: WS-LC-001, WS-LC-003 (setup_bun.js run by the install script), WS-FS-002 (setup_bun.js,
  bun_environment.js, truffleSecrets.json, actionsSecrets.json), WS-GH-001 (both workflow names), WS-GH-002,
  WS-GH-004 and WS-GH-007 (discussion trigger with run steps on a self-hosted runner). Exit 1.
- diff (a pull request adding these files): WS-DF-002, WS-DF-003, WS-LC-003, WS-GH-001, WS-GH-002, WS-GH-004,
  WS-GH-007. Exit 1. diff does not check payload or harvest file names.
- Missed: WS-GH-005 does not fire on the formatter workflow, for two separate reasons: `DATA` is bound to
  `toJSON(secrets)`, which the env-binding check does not count as a secret, and the heredoc names `$DATA` on the
  line after the `>` that writes the file, while the check reads one line at a time. `cloud.json`,
  `contents.json` and `environment.json` are not IOC names (too common), so only two of the five harvest files
  are reported.

## Not replayed

- Runner registration happens on the infected host (Datadog shows `./config.sh ... --name "SHA1HULUD"` run by
  the payload) and as a runner on a repository. Neither is a file in a repository, so scan and diff cannot see
  it. `audit-org` reports a runner named SHA1HULUD on an organization or one of its repositories (WS-OR-003, see
  `test/validation-recall.test.ts`). The sources do not say which repository the runner is registered on; a
  repository in a personal account is outside any organization audit.
- The exfiltration repository's description ("Sha1-Hulud: The Second Coming.") is GitHub state; `audit-org`
  matches it (repository patterns in `data/iocs/repos.json`).
