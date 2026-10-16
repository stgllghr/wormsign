# ADR 0008: An approval route for baseline changes

- **Status:** Accepted, not yet built ([ROADMAP](../../ROADMAP.md#next) item 2). Amends a consequence of
  [ADR 0002](0002-pr-gate-built-from-base.md) when the route is turned on; fails closed as
  [ADR 0001](0001-fail-closed.md) requires.
- **Date:** 2026-10-15

## Context

`diff` reports any added, changed or removed `.wormsign-baseline.json` as WS-DF-005, high, keyed on a hash of the
new content (`GATE_CONFIG` in [`src/diff.ts`](../../src/diff.ts)). The gate reads the base's baseline, so no entry
can pass the pull request that adds it: a baseline change merges only when someone overrides the required check
([baseline.md](../baseline.md#reviewing-baseline-changes)). Overrides become routine, and one approves the whole
pull request, not one entry.

## Decision

**Two pull requests, opt-in** (an Action input, off by default). A pull request that changes only the baseline's
`entries` passes `diff` when every guard below holds; once merged, the pull request with the finding runs against
the new base.

- **Guards, all required:**
  - the last rule in the base's `CODEOWNERS` is exactly `/.wormsign-baseline.json`, with user owners (the last
    match wins, so no pattern matching);
  - GitHub lists no `CODEOWNERS` error for that line, and each owner has write access;
  - only `entries` change;
  - the rules API returns an active `pull_request` rule with `require_code_owner_review`.
- **If any guard cannot be verified, WS-DF-005 stays high**, as today.
- **A guarded baseline-only pull request is WS-DF-005 at medium**: it passes the default gate and leaves each
  approved exception in code scanning.
- **A change to `ignorePaths` stays high and override-only**: one line there hides every future finding under a
  path.

Sources: GitHub reads `CODEOWNERS` from the base branch, the last matching pattern wins, a line with invalid syntax
is skipped, and owners need write access
([about code owners](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)).
[Get rules for a branch](https://docs.github.com/en/rest/repos/rules#get-rules-for-a-branch) returns only active
ruleset rules; it and [a user's permission](https://docs.github.com/en/rest/collaborators/collaborators#get-repository-permissions-for-a-user)
need "Metadata" read, [CODEOWNERS errors](https://docs.github.com/en/rest/repos/repos#list-codeowners-errors)
"Contents" read.

## Consequences

- **Rulesets only.** Classic branch protection can never pass: reading it needs "Administration" read
  ([REST](https://docs.github.com/en/rest/branches/branch-protection#get-branch-protection)), which `GITHUB_TOKEN`
  cannot have ([permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions)).
- **Unverified until built:** whether `GITHUB_TOKEN` gets these answers on a private repository. The build must
  show it before the docs claim it.
- **Still trusted:** a ruleset's bypass actors, shown only to those who can edit it. They can already merge over
  the check, so the route gives them nothing new.
- **For teams.** GitHub does not let an author approve their own pull request, so with one maintainer the route
  cannot bind the owner's own changes; it is built for adopters regardless.

## Alternatives considered

- **Status quo** (override the required check). Rejected: an administrator per baseline change, and a habit of
  overriding the check that guards the gate.
- **Approvals read by the gate** (also run on `pull_request_review`; pass when a code owner approved the head
  commit). Rejected: a team owner cannot be resolved, since membership needs "Members" organization read
  ([teams](https://docs.github.com/en/rest/teams/members#get-team-membership-for-a-user)); finding the owner needs
  GitHub's pattern rules, the imitation [ADR 0004](0004-no-installer-parser-imitation.md) avoids; and whether that
  run's check satisfies the failed required check is unverified.
- **The guarded pull request as a note, not a finding.** Rejected: it would leave no code-scanning record of the
  approval.
