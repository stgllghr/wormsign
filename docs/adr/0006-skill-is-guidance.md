# ADR 0006: The agent skill is guidance, not enforcement, and installs with no network access

- **Status:** Accepted (0.1.0)
- **Date:** 2026-10-14

## Context

Coding agents (Claude Code, Codex, Cursor) install packages and set up machines. They need the same rules as a
developer: install only locked, old-enough versions with install scripts off, run `soak` before installing a
lockfile change, and ask before weakening a protection.

Skills are also an attack channel. A skill's text becomes the agent's instructions, and the agent acts with the
user's permissions. Public studies have found hidden instructions in rules files and hundreds of malicious skills
in public registries ([skills.md](../skills.md#security)).

## Decision

- The skill is plain text: `SKILL.md` and five reference files, printable ASCII and newlines only. Its
  frontmatter holds `name`, `description` and `license`, and no `allowed-tools`, so it pre-approves no command. The
  plugin holds no hooks, commands, agents or MCP servers.
- Enforcement stays where it holds for agents and people alike: the `soak` gate in CI, and the package-manager
  settings `harden-dev.sh` checks.
- `wormsign skills install` copies the skill from the installed wormsign package. It makes no network request. It
  writes a manifest of SHA-256 hashes, and `wormsign skills check` exits 1 on any difference. The skill is exactly
  as trustworthy as the release you verified.

## Consequences

- Nothing stops an agent that ignores the skill. The CI gate catches what reaches a pull request. A local install
  the agent runs anyway is limited only by the machine's settings.
- The behavioural evidence is thin: seven runs in headless Claude Code, one repeat and one control. On the six prompts
  the skill covered, run 4 passed 6 with the skill (re-graded) and its control 2 without; run 7, on the release commit,
  passed all eight as run. An agent asked only to run a project's tool does not open the skill. Codex and Cursor have
  format checks only
  ([evidence/skill-eval.md](../evidence/skill-eval.md)).
- The Claude Code marketplace route clones the whole repository, including inert fixtures named like worm payloads,
  which an endpoint tool may flag. `wormsign skills install` copies only the skill.

## Alternatives considered

- **Enforcement hooks**, such as a hook that blocks install commands before the agent runs them. Rejected:
  - a hook is code that runs on every tool call with the user's permissions, the surface WS-PS-002 reports as high;
  - deciding what a shell command installs is the command-interpretation problem
    [ADR 0004](0004-no-installer-parser-imitation.md) refuses;
  - each agent has its own hook interface;
  - the controls that already hold (the lockfile gate, the cooldowns) cover people as well as agents.
- **Fetch the skill at install time.** Rejected: a second, network trust path outside the release the user
  verified, for a file type that is an attack channel.
- **Pre-approve wormsign's commands with `allowed-tools`.** Rejected: the skill would grant permissions rather than
  give advice, and would need reviewing as code.
