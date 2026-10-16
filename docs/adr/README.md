# Architecture decision records

Each record states one decision: its context, the decision, its consequences, and the alternatives rejected, with
the reason for each. The one-page overview is [design.md](../design.md).

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-fail-closed.md) | Fail closed: what wormsign cannot verify is a finding. | Accepted |
| [0002](0002-pr-gate-built-from-base.md) | Build the pull-request gate from the base commit; read the change as data. | Accepted |
| [0003](0003-seven-day-default-soak.md) | A 7-day default soak, with 72 hours as the tuned CI value. | Accepted |
| [0004](0004-no-installer-parser-imitation.md) | Never imitate an installer's parser to decide coverage. | Accepted |
| [0005](0005-no-runtime-dependencies.md) | No runtime dependencies; one vendored, verified TOML parser. | Accepted |
| [0006](0006-skill-is-guidance.md) | The agent skill is guidance, not enforcement, and installs with no network access. | Accepted |
| [0007](0007-private-registry-mirrors.md) | `soak` behind a private mirror: the public registries witness by default, the mirror by opt-in. | Accepted, not yet built |
| [0008](0008-baseline-approval-route.md) | An opt-in two-pull-request route for code-owner-approved baseline changes. | Accepted, not yet built |
| [0009](0009-scope-of-0-1-0.md) | 0.1.0 keeps every part, each labelled stable, beta or experimental. | Accepted |

A Proposed record has options, a recommendation and open questions in place of a decision, and waits for the
owner; "Accepted, not yet built" is decided, with the work in the [ROADMAP](../../ROADMAP.md). A new decision gets the next number. A decision that is reversed keeps its file, with its status set to
"Superseded by ADR NNNN".
