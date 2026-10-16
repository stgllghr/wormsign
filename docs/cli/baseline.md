# `wormsign baseline`

Add reviewed findings to the baseline file, each with the reason you write.

```text
wormsign baseline add <fingerprint>... --reason "<why>" [--expires YYYY-MM-DD] [--from <report.json>] [--baseline <file>]
```

Each entry switches a check off for one finding ([baseline.md](../baseline.md)). There is deliberately no "approve
all findings" mode: every entry needs a reason a person wrote after reviewing that finding. Pass several fingerprints
only when one reason is true of each.

## What it does

1. Checks the arguments by the rules a scan applies ([format](../baseline.md#format)): each fingerprint 32
   lower-case hex characters, none repeated; a `--reason` of at least 15 characters not starting with `todo`, `tbd`
   or `fixme`; an `--expires` date of today or later.
2. With `--from <report.json>`, a report written by `--format json` (by `scan`, `diff`, `soak` or `audit-org`), checks
   each fingerprint against it: one that is not a finding there, or whose finding no entry can approve
   (`notBaselinable: true`, WS-SK-006, WS-OS-901), is refused with exit 2 and the reason, and nothing is added.
   Without `--from`, a note on stderr says the fingerprints were not checked.
3. Reads `--baseline <file>`, or `.wormsign-baseline.json` in the current directory, which must pass every check a scan
   makes and hold none of the fingerprints. A symlink or non-regular file is refused, never followed or replaced. A file
   you cannot write (a read-only baseline) is refused too. With no file, it starts from an empty baseline, if the
   directory exists.
4. Appends one entry per fingerprint, in order, keeping everything else (`ignorePaths` included), as 2-space JSON
   with a final newline.
5. Writes a temporary file beside it, with the old file's permissions, and renames it into place; on any failure the
   baseline is unchanged. While it reads and writes the file it holds a lock file, `.<name>.lock`, beside it. Another
   `baseline add` waits up to 10 seconds, then exits 2 naming the lock. A lock left by a process that is no longer
   running, or one that is a symlink or not a regular file, is refused at once with the command to remove it;
   `baseline add` never removes a lock itself.

It runs no scan. For `wormsign scan <dir>`, run it in `<dir>` or pass `--baseline <dir>/.wormsign-baseline.json`.

## Options

| Option | Meaning |
|---|---|
| `--reason <text>` | Required, once: what was reviewed, by whom or in which pull request, and why it is safe. |
| `--expires <YYYY-MM-DD>` | The last day the new entries suppress, at most once; without it they never expire. |
| `--from <report.json>` | The `--format json` report the fingerprints come from, at most once: each must be a finding there that an entry can approve. |
| `--baseline <file>` | The baseline to extend (default `.wormsign-baseline.json` in the current directory). |

Any other option, `--format` and `--no-baseline` included, is a usage error.

## Examples

Take the fingerprint from `wormsign scan --format json`, and review the finding first (never baseline an
[IOC match](../baseline.md#reviewing-baseline-changes)). Pass that report with `--from`, and `baseline add` refuses a
finding no entry can approve: an entry for one would suppress nothing. Without `--from` it cannot tell, since a
fingerprint does not say what its finding is; such an entry never suppresses the finding, and `soak` notes so.

```console
$ wormsign baseline add 77e37b5c68b360e38667f4d11053b4bd --reason "setup.js only copies a config template; reviewed in PR 41 on 2026-10-02" --expires 2027-01-31
added 77e37b5c68b360e38667f4d11053b4bd (expires 2027-01-31): setup.js only copies a config template; reviewed in PR 41 on 2026-10-02
.wormsign-baseline.json: 1 entry added (new file)
wormsign: note: not checked against a report; pass --from <report.json> (a --format json report) to refuse a fingerprint that is no finding there or whose finding no entry can approve
$ wormsign soak --format json --output /tmp/soak.json
$ wormsign baseline add 5b0c51e2a1f04d7e9c3a8f6b2d4e1a90 --reason "docs requirements, reviewed in PR 42" --from /tmp/soak.json
wormsign: fingerprint 5b0c51e2a1f04d7e9c3a8f6b2d4e1a90 (WS-SK-002) is a finding no baseline entry can approve, so an entry would suppress nothing; nothing was added: the missing line is keyed on no text of the file, so an entry would approve it whatever the file comes to hold; the remedy is to add a --require-hashes line to the requirements file itself
$ wormsign baseline add 77e37b5c68b360e38667f4d11053b4bd --reason "setup.js only copies a config template; reviewed again"
wormsign: .wormsign-baseline.json: fingerprint 77e37b5c68b360e38667f4d11053b4bd is already in entries[0]; edit that entry to change its justification or expiry
```

## Exit codes

`0` when the entries were added. `2` for any usage error, an existing baseline that fails a scan's checks, a
fingerprint `--from` refuses, a result over 2 MiB or a failed write, with the file unchanged. It reports no findings, so never `1`
([output.md](../output.md#exit-codes)).

## Network

None.

## Limitations

- **Without `--from` it does not check that a fingerprint belongs to a finding**, nor that an entry can approve it.
  One copied from another directory suppresses nothing, and `scan` notes it
  ([leftover entries](../baseline.md#leftover-entries)). `--from` reads JSON reports only, not SARIF.
- **It only adds**; edit the file to renew, change or remove an entry. Other formatting, and a byte-order mark, is lost.
- **A symlinked directory earlier in the path is followed**; only the file itself is refused.
- **A killed run can leave a `.<file>.tmp-*` file** beside the baseline, which is never half written.
