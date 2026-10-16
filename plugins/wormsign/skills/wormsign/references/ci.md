# Setting up the gate in CI

Full workflows, inputs and reasons: https://github.com/stgllghr/wormsign/blob/main/docs/github-action.md
Ask the user before you add or change a workflow, a ruleset or branch protection.

## The pull-request gate
One job runs `diff`, `soak` with `base` (PR mode) and `scan` on every pull request, with the default
`fail-on: high`. Each step has `continue-on-error: true`, so all three run, and a last step fails the job if any
failed. The gate's code and baseline come from the base, never from the change: the Action pinned to a release
commit, and `scan` given the base commit's `.wormsign-baseline.json`. The shape (the doc has the full file):
```yaml
on: pull_request
permissions: { contents: read }
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha> # pin a commit SHA
        with: { fetch-depth: 2, persist-credentials: false }
      # base = git rev-parse HEAD^1, head = git rev-parse HEAD (the merge commit); copy the base's
      # .wormsign-baseline.json (or an empty one) to $RUNNER_TEMP/base-baseline.json
      - uses: actions/setup-node@<sha> # node-version: 24, check-latest: true
      - id: diff
        uses: stgllghr/wormsign@<release commit sha> # vX.Y.Z
        continue-on-error: true
        with: { command: diff, base: <base>, head: <head> }
      - id: soak
        uses: stgllghr/wormsign@<release commit sha> # vX.Y.Z
        continue-on-error: true
        with: { command: soak, base: <base>, require-config: "true" }
      - id: scan
        uses: stgllghr/wormsign@<release commit sha> # vX.Y.Z
        continue-on-error: true
        with: { command: scan, baseline: <the base's copy> }
      - name: Gate # if: always(); fails unless steps.diff, soak and scan each have outcome success
  test:
    needs: gate # every job that installs dependencies waits for the gate
```
- `require-config: "true"` fails until the cooldown setting is committed (`min-release-age=7` in `.npmrc` for npm):
  commit it first. The runner needs npm 11.10 or newer, so Node 24 with `check-latest: true`.
- A repository with Python locks needs the `soak` step: `diff` does not read what they pin.

## Jobs that wait for it
Every job that installs the change's dependencies must `needs:` the gate job (or run after its last step). A job
in another file is called from this workflow (`uses: ./.github/workflows/<file>.yml`) under `needs:`, its own
`pull_request:` trigger replaced by `workflow_call:`.

## Required status check
Make the gate job itself a required status check in branch protection or a ruleset. A job skipped because the gate
failed counts as passing, so requiring only `test` blocks nothing. A pull request can edit the workflow too:
require code-owner review for `.github/` as well.

## Scheduled re-check
On push to the default branch and on a schedule, run `scan` and a full `soak` (no `base`, `require-config: "true"`):
a version can gain an OSV malware record after it passed the gate.

## Pinning
Pin the Action to the full commit SHA of a release tag (`stgllghr/wormsign@<release commit sha> # vX.Y.Z`), not to
a tag or a `main` commit, and every other action by SHA too. Install the wormsign CLI from a verified release, or
check it out at that same release commit.

## A committed copy of this skill
If the repository commits this skill, run `wormsign skills check --project --agent claude,codex,cursor` in CI, but
name only the agents whose copies are committed (`--agent claude` for `.claude/skills/wormsign` alone): it exits 1
when a named agent's copy is missing or differs from the one the installed wormsign ships.
