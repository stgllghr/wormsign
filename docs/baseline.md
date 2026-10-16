# The baseline file

A baseline records reviewed findings, so they stop failing the gate, and paths not to scan. It is
`.wormsign-baseline.json` by default, committed and reviewed like code: each entry switches a check off for one
finding. Baselined findings do not count towards the exit code; JSON lists them and SARIF leaves them out
([output.md](output.md#baselined-findings-in-sarif)).

## Format

[`wormsign baseline add`](cli/baseline.md) writes entries; edit by hand to renew, change or remove one, and for
`ignorePaths`.

```json
{
  "version": 1,
  "ignorePaths": [
    {
      "path": "test/fixtures",
      "justification": "Inert synthetic test fixtures: they reproduce IOC names so every check has a positive control."
    }
  ],
  "entries": [
    {
      "fingerprint": "77e37b5c68b360e38667f4d11053b4bd",
      "justification": "setup.js only copies a config template; reviewed in PR 41 on 2026-10-02",
      "expires": "2027-01-31"
    }
  ]
}
```

| Field | Required | Rules |
|---|---|---|
| `version`, `entries` | yes | `1`; an array, possibly empty. |
| `entries[].fingerprint` | yes | 32 lower-case hex characters, unique in the file. |
| `entries[].justification` | yes | At least 15 characters after trimming, not starting with the word `todo`, `tbd` or `fixme`. |
| `entries[].expires` | no | A real `YYYY-MM-DD` date; the entry suppresses through 23:59:59 UTC that day. |
| `ignorePaths[].path` | yes | A relative prefix matched by whole components (`test/fixtures` covers `test/fixtures/x`, not `test/fixtures-old`). No absolute paths, `..`, `.`, globs or backslashes. |
| `ignorePaths[].justification` | yes | As for entries. |

Unknown keys are errors, since a typo such as `"expiry"` would make an expiring suppression permanent. Any error is
exit 2 before anything is scanned. The length check stops placeholders, not vague reasons.

## Where each command reads it

| Command | Default baseline |
|---|---|
| [`scan [dir]`](cli/scan.md) | `<dir>/.wormsign-baseline.json` |
| [`diff <base> <head>`](cli/diff.md) | the repository root's, **as committed in `<base>`**, never from `<head>` or the working tree |
| [`soak [dir]`](cli/soak.md) | `<dir>/.wormsign-baseline.json`; with `--base <rev>`, **as committed in `<rev>`** |
| [`audit-org <org>`](cli/audit-org.md), [`baseline add`](cli/baseline.md) | the current directory's |
| `update-iocs` | none |

`--baseline <file>` replaces any default; in a pull-request gate, pass only a file the pull request cannot edit. The
file must be a regular file of at most 2 MiB; the default one is never followed through a symlink (exit 2).

A baseline from the checked tree (`scan`, `soak`) or working directory (`audit-org`) can hide any of that tree's
findings, IOC matches included; the report's notes count what it hid, per rule, and so does stderr unless those
notes are on the screen (a human report on stdout, with stdout a terminal). Use `--no-baseline` (the Action's
[`no-baseline`](github-action.md#inputs)) on a tree you did not write.

## Entries

An entry suppresses the one finding whose fingerprint it names. Review the finding, then add it with
[`wormsign baseline add`](cli/baseline.md) and a justification ([review](#reviewing-baseline-changes)); the summary
then ends `, 1 baselined`.

### Expiry

After its `expires` date the finding is active again, and a medium [WS-BL-001](rules.md#ws-bl-001) names the entry,
so the default `--fail-on high` gate fails only if the returning finding is high or critical. Review it again and
edit `expires`, or fix the finding.

### Leftover entries

`scan` notes each entry that matched nothing (`note: baseline entry 0123456789abcdef0123456789abcdef matches no
finding`), and each `ignorePaths` entry, so stale suppressions can be removed. `diff`, `soak` and `audit-org` see only
part of the project per run, so they do not note unused entries.

## Fingerprints

```text
fingerprint = sha256(ruleId + "\0" + file + "\0" + key)[0:32]
```

That is 128 bits of SHA-256 over the rule ID; `file`, relative to the run's root (`dir` for `scan` and `soak`, the
repository root for `diff`; `org/repo` or the organization for `audit-org`; empty without one); and `key`, what the
rule matched. The line number is **not** part of it, so moving code keeps the entry. SARIF carries it as
`partialFingerprints["wormsign/v1"]`.

### How firmly an entry is bound to what it approves

A key's content hash is also 128 bits of SHA-256 ([`types.ts`](../src/types.ts)), so matching an existing entry takes
about 2^128 tries, but planting a colliding pair (a harmless version baselined, then a harmful one) takes about 2^64,
within a well-funded attacker's reach.

### When a fingerprint changes

Renaming or moving the file, or running from another root (`scan sub` for `scan .`), gives a new fingerprint: run
the gate from the same directory every time. An entry approves exactly what the rule's key holds; where that is a
hash, any edit to the hashed content is a new finding.

| Rules | Key |
|---|---|
| WS-LC-001 | script name and a command hash (`postinstall:2f0391b18bc0c6809c923f102fd8c313`); `gyp` for a `.gyp` file, whatever it holds |
| WS-LC-002, WS-LC-003 | script name, `suspicious` or the payload name, and a command hash, as in `diff`; for an installed package, name and pattern only |
| WS-LC-004 | `code:` and a file hash, or `settings:` and a hash of the settings that name code |
| WS-DF-002, WS-DF-003, WS-DF-005, WS-DF-006 | a hash of the new content (`removed` if deleted; the tree but the baseline for an unfollowable path), prefixed for Python `python-lock:`, `python-manifest:`, `uv-config:` or `python-build:` (the [build key](soak.md#builds-ws-sk-005)) |
| WS-GH-001, WS-GH-006, WS-GH-007 | workflow file name; runner name (and job, for `runs-on`); or the trigger shape |
| WS-GH-002 to WS-GH-005 | job name and a hash of the matched line |
| WS-PS-001, WS-PS-002 | the whole definition (a VS Code task with the tasks its `dependsOn` reaches and its file's global settings). What it runs, `${config:...}` and settings outside the repository can change unseen |
| WS-LK-001, WS-DF-001, WS-DF-004, WS-SK-001, WS-RG-001 to WS-RG-003 | `name@version`; for PyPI WS-SK-001, `pypi:<name>@<version> <identity>` (name, version, source, every locked file and hash) |
| WS-LK-002, WS-LK-003 | `name@version`, `resolved` and `integrity` (Yarn 1 without one: the SHA-1 in `resolved`) |
| WS-SK-002 | npm: `name@version`, `resolved`, `integrity`, or lockfile and reason. PyPI: the identity; `pypi:lockfile <file> <digest>` over the problem and its content, one per requirements line (a line naming a local path or `file:` URL also covers what is there: a file's sha256 and a symlink's target, or `missing`); only a plain index requirement soak parsed and a local file it resolved to a regular file inside the root can be baselined, and every other requirements problem (the missing `--require-hashes` line included) is never suppressed ([which](soak.md#requirements-files)); `pypi:install-setting <kind> <where> <digest>` |
| WS-SK-003, WS-SK-004 | package manager and the missing setting; or the setting's value, or the package-manager version |
| WS-SK-005 | `pypi:build <dir> <digest>` over the build files ([soak.md](soak.md#builds-ws-sk-005)): a `[project]` version or metadata edit keeps it, a `setup.py`, `setup.cfg` or `[tool.poetry]` edit does not; `pypi:<name>@<version> sdist-only <identity>`; `pypi:build-config <setting> <digest>` or `pypi:build-config symlink`. PR mode's high matches the same entry |
| WS-OS-001 | `name@version` and the record id (`MAL-`, or a CWE-506 `GHSA-`), `pypi:` first for PyPI |
| WS-OS-900 | the versions OSV did not answer for, or the registry when not asked |
| WS-NM-001 | `name@version` and the script name (or `gyp`) |
| WS-FS-001 / WS-FS-002 / WS-EX-001 / WS-EX-002 | hash / file name / URL / endpoint |
| WS-SC-900 | `not-checked` and a hash of the reason, plus the content for settings files, `package.json`, installed manifests and workflows with an unreadable `${{ }}`; or the unchecked entry |
| WS-OR-* | repository, pattern, runner, branch or event time |
| WS-BL-001 | the expired entry's fingerprint (fix or renew the entry) |

## ignorePaths

For directories that trigger findings and are never installed or run, such as IOC test fixtures:

| Command | Effect |
|---|---|
| `scan` | Not read or reported, symlinks included; a note lists them. A `file:` dependency into one is high [WS-SC-900](rules.md#ws-sc-900). |
| `diff` | Content findings and Python lock and manifest edits there are skipped. npm manifests, local actions, package-manager config (`pip.conf`, `pip.ini`, `uv.toml`, `[tool.uv]`), Python builds and an unparseable `pyproject.toml` are checked everywhere. |
| `soak` | Python inputs there are not read (a note lists them); npm lockfiles and Python install settings are read everywhere. |
| `audit-org` | No effect. |

Prefer entries: an ignored path hides every future finding there, a payload added later included.

## Reviewing baseline changes

An entry is a decision that a specific risk is acceptable. Review changes to the file like changes to the checks:

1. **Require an owner's review.** List the file in `CODEOWNERS` (read from the base branch) and enable "Require
   review from Code Owners", or GitHub only requests it
   ([GitHub docs](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)).
   This repository's [`.github/CODEOWNERS`](../.github/CODEOWNERS) lists it, `/.github/`, `/data/iocs/` and
   `/action.yml`.
2. **Expect the gate to fail on that pull request.** `diff` reports any baseline change as a high
   [WS-DF-005](rules.md#ws-df-005) and reads suppressions from the base, so a maintainer reviews the entry and
   overrides the required check.
3. **Check the entry, not only the justification:** find its finding (`--format json` on the pull request's tree).
4. **Do not baseline IOC matches.** A critical WS-LK-001, WS-FS-001, WS-EX-002, WS-GH-001, WS-GH-006 or WS-OS-001
   means a listed indicator is present: follow [incident-response.md](incident-response.md), or report a false
   positive with the "False positive" issue template.
5. **Set `expires` on anything temporary**, such as a young version you are waiting out.
6. **Keep justifications specific:** what was reviewed, by whom or where, and why it is safe.
