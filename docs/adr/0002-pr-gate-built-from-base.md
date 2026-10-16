# ADR 0002: Build the pull-request gate from the base commit

- **Status:** Accepted (0.1.0)
- **Date:** 2026-10-14

## Context

A pull request can edit every file in its tree: the rules, the IOC data, the baseline, the Action. If the gate ran
the change's code, or read the change's baseline, a malicious change could switch a check off, or approve its own
finding, and then pass.

## Decision

The gate's code and its baseline never come from the change. The change is read as data.

- **This repository.** [`.github/workflows/wormsign.yml`](../../.github/workflows/wormsign.yml) checks the base commit
  out into `gate/`, builds the CLI there, and runs it with `uses: ./gate` on the change checked out in `pr/`.
  Nothing from `pr/` is installed, built or run.
- **Adopters.** The Action pinned to a release commit SHA plays the role of `gate/`. The pull request does not
  supply it.
- **Baseline.** `diff` and `soak --base` read `.wormsign-baseline.json` from the base revision. The Action passes
  the base's copy to `scan`.
- **What is compared.** In the recommended gate, `diff` and `soak --base` compare the merge commit with its first
  parent, so they see what merging adds.
- **Order.** Every job that installs the change's dependencies `needs:` the gate job.

## Consequences

- A change to the gate takes effect for the pull requests after it merges, not for itself.
- A pull request that changes the baseline fails (WS-DF-005, high) and merges only by overriding the required
  check, until the opt-in code-owner route of [ADR 0008](0008-baseline-approval-route.md) is built and on.
- An emergency exception must land on the base branch before the pull request that needs it, or come through
  `--baseline` from a place the change cannot edit.
- The workflow file is not covered. GitHub runs a `pull_request` workflow as the change has it, so a pull request
  from the same repository can edit or delete the gate. Only branch protection that requires the check and
  code-owner review of `.github/`, or an organization-required workflow, stops that
  ([github-action.md](../github-action.md#what-the-gate-does-not-stop)).

## Alternatives considered

- **Run the change's own wormsign** (check out, install, run). Rejected: the change would control its own checks.
- **`pull_request_target`.** Its workflow comes from the base, which would protect the workflow file. Rejected: it
  can read the repository's secrets, so a gate that must read the change risks running it with them. With no
  `command` input, the Action stops with exit 2 under this event.
- **Read the baseline from the change and rely on review.** Rejected: the pull request could suppress its own
  finding, and the gate would pass before anyone reviewed it.
- **An organization-required workflow in another repository.** Not rejected. It is the recommended deployment where
  the plan allows it ([github-action.md](../github-action.md#deploy-across-an-organization)). It is not the default
  because organization rulesets need GitHub Team or Enterprise, and it has not been run here.
