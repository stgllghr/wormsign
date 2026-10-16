# `wormsign skills`

Install, check or remove the agent skill that tells Claude Code, Codex and Cursor how to install packages safely.
What the skill says, the marketplace routes and why the command works this way: [skills.md](../skills.md).

```text
wormsign skills install|check|uninstall [--agent claude,codex,cursor] [--project] [--dry-run] [--force]
```

## What it does

### Where it writes

| Agent (`--agent`) | User level (default) | `--project` |
|---|---|---|
| Claude Code (`claude`) | `~/.claude/skills/wormsign`, or `$CLAUDE_CONFIG_DIR/skills/wormsign` when that variable is an absolute path | `<git root>/.claude/skills/wormsign` |
| Codex (`codex`) | `~/.agents/skills/wormsign` | `<git root>/.agents/skills/wormsign` |
| Cursor (`cursor`) | with `claude`: Claude Code's `~/.claude/skills/wormsign` copy (unless `CLAUDE_CONFIG_DIR` names another folder); without it: `~/.agents/skills/wormsign`, Codex's copy | with `claude`: `<git root>/.claude/skills/wormsign`; without it: `<git root>/.agents/skills/wormsign` |

A run touches at most two folders. Without `--agent`, the command takes the agents whose folders exist (`~/.claude`
or `$CLAUDE_CONFIG_DIR`, `~/.codex`, `~/.cursor`) and prints `agents found: ...`; if none exists, it exits 2. Those
user folders decide with `--project` too, so name the agents with `--agent` in CI. `--project` uses the git root of
the current directory; outside a git work tree, or when that root does not hold the current directory, it exits 2.

User level is `$HOME` when absolute, else the home folder the system reports; a run that needs one and finds
neither exits 2. `--project --agent ...` needs no home folder, as in a CI job. When Cursor is selected and both
copies exist, `install` and `check` note that Cursor may list the skill twice
([why](../skills.md#cursor-reads-two-folders)).

### install

- Copies the skill from the installed package and writes a manifest,
  `.wormsign-skill.json`: the wormsign version and every file's SHA-256. Every target is inspected first; one it
  cannot read or write stops the run with exit 2.
- Writes each copy to a temporary folder beside the target and renames it into place; an old copy is renamed aside
  and deleted after. A success leaves neither. A failure leaves no partial skill and is exit 2; its temporary folder
  is removed too, or, if that fails, named with the `rm -r` command that removes it. If only the old copy's deletion
  fails, the new copy stands, with a `warning:` line and that command. Only a run killed part-way leaves a folder
  unnamed.
- Replaces an unedited wormsign copy: `replaced 0.0.9 with 0.1.0`, `reinstalled 0.1.0`, or, for a copy of this
  version that matches its own manifest but not this build (another build, such as a clone's earlier commit, or
  edited along with its manifest), `replaced a different 0.1.0 copy (edited, or another build; differs from this
  wormsign's skill: SKILL.md)`. A folder without a wormsign manifest, or one whose files differ from its manifest, is
  left alone with exit 1; `--force` replaces it (`replaced a modified copy with 0.1.0 (edited: SKILL.md)`).
- Names a `.wormsign.tmp-*` or `.wormsign.old-*` folder an interrupted run left, on a `warning:` line with the
  command that removes it; it never removes one.
- `--dry-run` prints `would write ...`. Nothing else is ever written: no hooks, no scripts, no agent settings.
- **Links are refused.** If any path component from the skills folder (with `--project`, from the git root) down to
  `wormsign` is a symbolic link, `install` and `uninstall` exit 2 before touching any target, even with `--force`.
  The message names what works instead, with the `--agent` list given: `--project` for a link in your user folders,
  no `--project` for one in the repository, and for `uninstall`, `check`, which reads through links.

### check

Compares each target with the skill this wormsign ships and prints `ok, <version>` or what differs:
`not installed`, `not wormsign's skill, <why>`, `edited`, `extra`, `lost`, `not a regular file`, `missing`,
`outdated: <old>, this wormsign ships <new>`, `differs from this wormsign's skill`, or `not plain ASCII` (anything
but printable ASCII and newline). A `.wormsign.old-*` or `.wormsign.tmp-*` folder left by an interrupted run is
reported too, with the command that removes it (`remove with: rm -r -- '<path>'`; a `.wormsign.old-*` folder holds
an earlier copy). Exit 0 when every target matches and nothing is left over, 1 otherwise. In CI, name only the
agents whose copies you commit.

### uninstall

Removes a target only when it carries a wormsign manifest and unedited files; anything else is left in place with
exit 1 unless `--force` is given. The parent `skills` folder is
never removed, and marketplace copies, in the agent's plugin cache, are not seen.

## Options

| Option | Meaning |
|---|---|
| `--agent <list>` | `claude`, `codex` or `cursor`, comma-separated or repeated. Default: the agents whose folders exist. |
| `--project` | Use the git root of the current directory instead of your user folders. |
| `--dry-run` | `install` only: print what would be written. |
| `--force` | `install`: replace a folder wormsign did not write, or one edited since. `uninstall`: remove it. |

No other option, and no second word after the action, is accepted.

## Examples

With `HOME` set to a temporary folder holding only empty `.claude` and `.cursor` folders (shown as `~`), then a line
appended to `~/.claude/skills/wormsign/references/npm.md`:

```console
$ wormsign skills install
agents found: claude, cursor
~/.claude/skills/wormsign (claude, cursor): installed 0.1.0, 6 files
$ wormsign skills check
agents found: claude, cursor
~/.claude/skills/wormsign (claude, cursor): edited: references/npm.md
$ echo $?
1
$ wormsign skills uninstall
agents found: claude, cursor
~/.claude/skills/wormsign (claude, cursor): left alone, edited since wormsign installed it; --force removes it
```

The check a CI job runs, in a repository that commits both copies, with `HOME` empty:

```console
$ HOME= wormsign skills check --project --agent claude,codex,cursor
/path/to/repo/.claude/skills/wormsign (claude, cursor): ok, 0.1.0
/path/to/repo/.agents/skills/wormsign (codex): ok, 0.1.0
note: Cursor reads both ... so it may list this skill twice; `wormsign skills check --project --agent claude,codex` shows whether both copies match
```

## Exit codes

0 when every target was installed, matches or was removed (or, for `uninstall`, was not installed). 1 for a
`check` difference, or a target left alone. 2 for a usage error, no agent folder without `--agent`,
no home folder when one is needed, `--project` outside a git work tree, a symbolic link on a target's path, a folder
that cannot be read, written or removed, or a damaged skill in the package ([output.md](../output.md#exit-codes)).

## Network

None. The files come from the installed package.

## Limitations

- **Windows is untested.** The paths and the rename-into-place are written for macOS and Linux.
- **Other agents may read these folders,** but nothing is promised for them.
- **The skill is guidance, not enforcement** ([skills.md](../skills.md)).
