# The wormsign agent skill

wormsign ships one agent skill, in the Agent Skills `SKILL.md` format, for coding agents that install packages or
set up a development environment: Claude Code, OpenAI Codex and Cursor. Install it with `wormsign skills install`
wherever an agent installs packages for you. It is guidance, not enforcement
([ADR 0006](adr/0006-skill-is-guidance.md)): the CI gate and the settings `harden-dev.sh` checks are what hold.

The files are in [`plugins/wormsign/skills/wormsign/`](../plugins/wormsign/skills/wormsign/): a short
[`SKILL.md`](../plugins/wormsign/skills/wormsign/SKILL.md) and five reference files. External pages cited here were
retrieved on 2026-10-12, 2026-10-14 or 2026-10-15.

## What it tells agents

[`SKILL.md`](../plugins/wormsign/skills/wormsign/SKILL.md) is the canonical text. Its eight rules cover:

1. installing from the lockfile only, with install scripts off;
2. keeping install scripts off and the 7-day cooldown on, and approving one package's script only with the user's OK;
3. checking a new package before adding it, and writing it into the lockfile without installing or building it;
4. running `wormsign soak` (on a branch, also `soak --base` and `diff`) before installing a changed lockfile;
5. running a dependency's bin only after this session's lockfile install, as `./node_modules/.bin/<bin>`, through
   an `npm run` script read first (with its `pre` and `post` scripts), or as `.venv/bin/<tool>`; never through `npx`
   or `npm exec`; and asking before any other `npx`-style run, an install from a URL, git or a tarball, `curl | sh`,
   or `sudo`;
6. installing a command-line tool outside a project (`npm install -g`, `npx <name>@<version>`, `pipx install`,
   `uv tool install`, `pip` into a throwaway environment) at an exact version at least 7 days old, with install
   scripts and source builds off and a 7-day cooldown for its dependencies (`--before` below npm 11.10, or saying
   they are not aged); asking first unless the user named it and every check passes, and saying the version and its
   publish date either way;
7. running read-only checks freely, and asking before anything that weakens a protection;
8. following the rules by hand without wormsign, and never installing wormsign itself.

The commands are in the references: [npm, pnpm, Yarn and bun](../plugins/wormsign/skills/wormsign/references/npm.md),
[pip and uv](../plugins/wormsign/skills/wormsign/references/python.md),
[running wormsign](../plugins/wormsign/skills/wormsign/references/wormsign.md),
[CI](../plugins/wormsign/skills/wormsign/references/ci.md) and
[setting up a machine](../plugins/wormsign/skills/wormsign/references/environment.md). Their commands and numbers
come from wormsign's docs. The lock-only add commands and install-script approvals come from each tool's own
documentation and from the [allowlist workflows](hardening.md#npm). The runs behind them, including the skill's
`npm rebuild`, `pnpm rebuild`, `pip-compile` and `uv add` commands, are in evidence/package-managers.md
([npm](evidence/package-managers.md#npm), [pnpm](evidence/package-managers.md#pnpm),
[pip](evidence/package-managers.md#pip), [uv](evidence/package-managers.md#uv)).

Rules 5 and 6 follow the tools' documentation and source, retrieved 2026-10-15:
[npm exec](https://docs.npmjs.com/cli/v11/commands/npm-exec) ("When standard input is not a TTY or a CI environment is
detected, `--yes` is assumed"); libnpmexec's `lib/index.js` (9.0.0, in npm 10.9.2), which, before it reads `--no`,
sets yes when the project's own `bin` has the name, looks for the bin in every parent folder's `node_modules/.bin` and
the global folder, and runs a same-named package already in its cache; npm's
[`ignore-scripts`](https://docs.npmjs.com/cli/v11/using-npm/config#ignore-scripts) and
[`min-release-age`](https://docs.npmjs.com/cli/v11/using-npm/config#min-release-age) and
[`before`](https://docs.npmjs.com/cli/v11/using-npm/config#before) ("only versions that were available **on or
before** the given date"; npm 10.9.2's definition has the same key, a Date); `npm run` runs a script's `pre` and
`post` scripts unless `ignore-scripts` is set;
[pipx install](https://pipx.pypa.io/stable/reference/cli.html)'s `--pip-args` and `--cooldown DAYS`; `uv tool install
--help`'s `--no-build` and `--exclude-newer`; pip's `--only-binary :all:` and `--uploaded-prior-to` ("a duration in
days (e.g., 'P3D')"); [uv's tools guide](https://docs.astral.sh/uv/guides/tools/) (`uvx` uses "temporary, isolated
environments"); uv's [0.9.17 changelog](https://github.com/astral-sh/uv/blob/main/changelogs/0.9.x.md) ("Add support
for relative durations in `exclude-newer`"). A locked Python tool runs only as `.venv/bin/<tool>`, never `uv run`:
`--frozen` still syncs the environment, and `uv run --no-sync` created a missing `.venv` here (uv 0.10.9), ran a
same-named program from PATH, and would download a Python if none were found (`--no-python-downloads`: "Disable
automatic downloads of Python"). Yarn reads a setting from `YARN_` and its name in
snake case, over `.yarnrc.yml` ([yarnrc](https://yarnpkg.com/configuration/yarnrc)). They were run on 2026-10-15
against a registry on 127.0.0.1 and local archives only, with inert packages, using npm 10.9.2 with no terminal:
- `npx <bin>` without `node_modules` fetched the package named after the bin and ran it, install script included.
- `npx --no <bin>` fetched only its metadata and exited 1 in an empty project, but ran a bin from a parent folder's
  `node_modules/.bin`, ran a same-named package from its cache with no prompt, and installed the project itself
  into its cache when the project's own `bin` had the name.
- `--ignore-scripts` kept `npx <name>@<version>` and `npm install -g` from running the install script.
- `--before=2019-12-01` refused a version published 2020-01-01 for `npm install -g` and for `npx` ("No matching
  version found ... with a date before"); `--before=2020-01-02` installed it. A value npm cannot read
  (`--before=not-a-date`) only warned "invalid config" and installed anyway.
- uv 0.10.9's `--no-build` and pip 26.1.2's `--only-binary :all:` refused a package published only as source before
  building it; uv 0.10.9 accepted `--exclude-newer "7 days"` and `P7D`.

npm enforces `--min-release-age` from 11.10, so that flag was not run; pipx and Yarn 2+ were not run.

Tests check that `SKILL.md`'s index names every reference file, that every `wormsign` command in the skill uses a
command and flags the CLI accepts, that each reference covers what its index entry promises, and that every version
fact in the skill also appears in wormsign's docs. The frontmatter has only `name`, `description` and `license`: no
`allowed-tools`, so the skill pre-approves no command.

## Install it

**With wormsign** (Claude Code, Codex and Cursor). It copies the skill from the installed package, with no network
access; `--project` installs it into the current repository for committing:

```sh
wormsign skills install            # the agents whose folders exist in your home folder
wormsign skills install --project --agent claude,codex,cursor
```

Folders, options and output: [cli/skills.md](cli/skills.md).

**The agent needs `wormsign` on its PATH.** An agent runs commands in a shell of its own, which an alias typed in your
terminal never reaches. A release installed with `npm install -g` is on PATH; from a clone, run `npm link`
([installation](installation.md#put-wormsign-on-your-path)). Without it, the skill follows its rules by hand
(rule 8): no soak, diff or scan, the same rules applied by reading, and a note once per session that wormsign can
check them. It never installs wormsign itself.

**Claude Code's plugin marketplace.** The repository's `.claude-plugin/marketplace.json` lists one plugin,
`plugins/wormsign/`, which holds only `.claude-plugin/plugin.json` and the skill. In a Claude Code session:

```text
/plugin marketplace add stgllghr/wormsign#v0.1.0
/plugin install wormsign@wormsign
```

`#v0.1.0` pins the marketplace to that release tag (Claude Code's
[docs](https://code.claude.com/docs/en/discover-plugins#add-a-marketplace): "Add `#ref` to pin a branch or tag.");
without it, the marketplace follows the default branch. The skill appears as `/wormsign:wormsign`. Adding the
marketplace clones the whole repository, including inert test fixtures named like worm payloads (`setup_bun.js`,
`bundle.js`), which a name-based endpoint tool may flag; `wormsign skills install` copies only the six skill files.
This route is checked for format only, and v0.1.0 is not tagged yet ([release status](installation.md#release-status)).

**Codex and Cursor: use `wormsign skills install`.** OpenAI's
[Package your plugin](https://developers.openai.com/codex/plugins/build#add-a-marketplace-from-the-cli) page does not
say which marketplace files the Codex CLI reads, and no Codex route was tested. Cursor has no marketplace route here.

## Check and remove it

`wormsign skills check` exits 1 on any difference from the skill this wormsign ships, so a team that commits the
skill can run `wormsign skills check --project --agent <agents>` in CI; `uninstall` removes only unedited copies
([cli/skills.md](cli/skills.md)). A marketplace install lives in the agent's plugin cache, which these
commands do not see: remove it with `/plugin uninstall wormsign@wormsign`.

## Does an agent follow it?

The tests check the skill's files, not whether an agent obeys them. [evidence/skill-eval.md](evidence/skill-eval.md)
records seven runs in headless Claude Code, a repeat and a control. Run 3 passed all six prompts (install the dependencies, add
a package, pipe an install script into `sh`, set up the machine, fix a soak failure, install a Python project), **with the skill
at `d37a961`**. The skill has changed since: a narrower description, then one naming command-line tools; rule 3's
checks, which ask less; rule 5, which runs a dependency's bin only from `node_modules/.bin` or `npm run`; the new
rule 6 for tool installs; the Python project in its virtual environment; Yarn 2+ with `YARN_ENABLE_SCRIPTS=false`
([the list](evidence/skill-eval.md#the-skill-since-run-3)). Run 4, on the release candidate with eight prompts,
passed 6 when re-graded, and the same prompts with no skill passed 2: the skill made the difference on the four
install prompts ([control](evidence/skill-eval.md#control-run-4s-prompts-with-no-skill-2-of-8)). The prompts for
rules 5 and 6 failed with and without it in run 4. After their prompts were fixed, run 7, on the release commit,
passed all eight as run ([run 7](evidence/skill-eval.md#run-7-8-of-8)); an agent asked only to run a project's tool
still does not open the skill. That is evidence for these prompts, a run or two each, not a guarantee
([limitations](evidence/skill-eval.md#limitations)).
Codex and Cursor have format checks only.

## Cursor reads two folders

Cursor's [skills documentation](https://cursor.com/docs/context/skills) lists `~/.agents/skills/` and
`.agents/skills/`, and for compatibility also loads `~/.claude/skills/`, `.claude/skills/` and the `.codex` skills
folders. It does not say what happens when two folders hold a skill with the same name. Cursor staff called skills
loaded twice a bug ([January 2026](https://forum.cursor.com/t/critical-issue-duplicate-skills-loading-causing-context-window-waste-and-confusion/150137))
and said a fix landed in Cursor 3.17
([August 2026](https://forum.cursor.com/t/excessive-token-usage-cursor-auto-loads-too-many-skills-from-claude-skills-at-conversation-start/160677)).

So wormsign writes no second copy for Cursor: with Claude Code selected, Cursor shares `.claude/skills/wormsign`.
Cursor's documentation names `~/.claude/skills`, not `$CLAUDE_CONFIG_DIR/skills`, so at user level with
`CLAUDE_CONFIG_DIR` set elsewhere Cursor gets its own `.agents` copy. When both copies exist, wormsign says Cursor
may list the skill twice and names `wormsign skills check --agent claude,codex`
([where it writes](cli/skills.md#where-it-writes)).

## Security

- **Nothing is fetched.** `wormsign skills` copies files from the package you installed, so the skill is exactly as
  trustworthy as that release ([verify one](installation.md#download-and-verify)). The marketplace route fetches
  the repository through Claude Code.
- **Pin the marketplace to a release tag.** A tag is fixed only while
  the repository keeps it: [check it](installation.md#check-a-release-tag-yourself), or use `wormsign skills install`.
- **Every skill file is plain ASCII**, which a test enforces, so no character in it is invisible.
  `wormsign skills check` reports any installed file holding anything else.
- **Skills are an attack channel.** A skill's text becomes the agent's instructions, acted on with your
  permissions. Pillar Security's "Rules File Backdoor" (2025-03-18) hid instructions in Cursor and GitHub Copilot
  rules files with zero-width joiners and bidirectional markers
  ([Pillar Security](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)).
  Koi Security found 341 malicious skills among 2,857 on ClawHub
  ([The Hacker News, 2026-02-02](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html)).
  Snyk's ToxicSkills study confirmed 76 malicious among 3,984 skills from ClawHub and skills.sh
  ([Snyk, 2026-02-05](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub)). Install skills only from
  a source you trust, at a fixed version, and read them: this one is six short plain-text files that grant no tool,
  run no hook and start no server.
