# Replay: Shai-Hulud, September 2025 wave

**This is a reconstruction, not a sample.** Every payload file holds a one-line marker instead of code, and the
exfiltration URL is replaced by a `.invalid` host. Nothing here runs anything, fetches anything or matches a
payload hash. It rebuilds only the shape that detection depends on: file names, the lifecycle script, and the
injected workflow's trigger, runner and secret handling.

Layout: `package/` is the package as the worm republishes it; `repo/` is what it pushes to a victim repository.

## Features and sources

Sources (snapshot SHA-256 of the page as saved for this project in parentheses):

- [StepSecurity] https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised (c4ba4539...)
- [Socket] https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages (5c97f3b2...)

| Feature | Replay file | Source | Located by |
|---|---|---|---|
| Install script runs the payload | `package/package.json` `postinstall: node bundle.js` | StepSecurity | "likely triggered via a hijacked postinstall script" |
| | | Socket | "file to add a postinstall script" |
| Payload file name | `package/bundle.js` (marker) | StepSecurity | "a Webpack-bundled script (bundle.js)" |
| Injected workflow name | `repo/.github/workflows/shai-hulud-workflow.yml` | StepSecurity | "injecting a GitHub Actions workflow file (.github/workflows/shai-hulud-workflow.yml)" |
| Workflow trigger | `on: push` | StepSecurity | "This workflow triggers on push events" |
| Runner | `runs-on: ubuntu-latest` | StepSecurity | "runs-on: ubuntu-latest" |
| Secret handling | `env: CONTENTS: ${{ toJSON(secrets) }}`, then `curl -d "$CONTENTS"` and a double base64 | StepSecurity | "exfiltrates repository secrets using the expression" |
| Second workflow name | `repo/.github/workflows/shai-hulud.yaml` (marker) | Socket | "The malware includes a workflow file named shai-hulud.yaml" |

## Reconstruction choices

- StepSecurity's deobfuscated workflow is not valid YAML (`jobs: process` with children, `env: CONTENTS: ...` on one
  line). The replay writes the same keys as valid YAML, since GitHub does not run a workflow that does not parse.
  The vendor's inline comments are dropped.
- Socket's example manifest spells the script `"postInstall"`. npm 10.9.2 did not run a `postInstall` script, for a
  dependency or the root project, while it ran the same command spelled `postinstall` (checked for this replay with
  a local tarball dependency). The replay uses `postinstall`, the spelling that executes.
- Socket gives no content for `shai-hulud.yaml`, so that file is a marker comment.
- The vendor-reported webhook URL is replaced by `https://exfil.wormsign-replay.invalid/collect`. The real URL is
  in `data/iocs/endpoints.json`; `test/validation-recall.test.ts` shows it is reported (WS-EX-002).

## What wormsign reports (asserted by `test/validation-replay.test.ts`)

- scan: WS-LC-001, WS-LC-003 (bundle.js run by the install script), WS-GH-001 (both workflow names), WS-GH-002.
  The gate fails (exit 1).
- diff (a pull request adding these files): WS-DF-002, WS-DF-003, WS-LC-003, WS-GH-001, WS-GH-002. Exit 1.
- Missed: WS-GH-005 does not fire on `curl -d "$CONTENTS"`, because `CONTENTS` is bound to `toJSON(secrets)` and
  the env-binding check counts only `secrets.X` or `secrets[...]`. `bundle.js` alone is not reported by name
  (info severity in the IOC data, as the name is common); only its hash or an install script that runs it is.

## Not replayed

- The `shai-hulud` branch the workflow is pushed to and the public `Shai-Hulud` repository are GitHub state, not
  files; `audit-org` covers the branch and repository-name patterns (see `test/validation-recall.test.ts`).
- TruffleHog and credential harvesting happen inside the payload, which is not reproduced.
