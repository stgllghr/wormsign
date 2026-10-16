# Checking with wormsign

## Running it
All three are read-only: run them without asking.
- `wormsign soak [dir]`: every locked npm and PyPI version must be at least 7 days old, match its registry, and
  have no OSV malware record; the project's npm, pnpm, Yarn and bun cooldown settings are checked too. It uses the
  network. Run it after a lockfile changes and before installing from it.
- `wormsign soak --base <base>`: the same on a branch; only the npm and Python entries the change adds or changes,
  and the baseline read from `<base>`.
- `wormsign soak --config-only`: only the cooldown settings, offline.
- `wormsign diff <base> HEAD`: what a change adds: install scripts, workflows, lockfile, baseline and
  installer-config changes. No network.
- `wormsign scan [dir]`: install scripts, lockfiles against known compromised versions, workflows, payload files
  and exfiltration endpoints. No network.

## Reading the output
Each finding prints its severity, rule ID, file and message, then a fingerprint; a summary line counts them, and
`note:` lines say what was and was not checked. `--format json` adds per-version evidence. Exit codes: 0 nothing
at or above `--fail-on` (default high), 1 at least one finding at or above it, 2 a usage or other error (no report;
read the message). Report the rule ID, file and message of every high or critical finding to the user.

## What to do for each finding
- WS-SK-001, too young: do not install it. Wait until the version is 7 days old, or pin an older version that is.
  Never lower `--min-age` or a cooldown to make it pass.
- WS-SK-002, could not verify: fix the form of the lock, not the check. Commit the lockfile; install from the
  registry, not git or a URL; for Python, lock with `uv lock`, or write a hash lock (references/python.md). A
  private registry or index: tell the user.
- WS-SK-003 or WS-SK-004, a cooldown setting missing or not working: report it; adding or changing a setting
  needs the user's OK (references/environment.md).
- WS-SK-005, a build at install time: report it (references/python.md, "Builds").
- WS-OS-001, an OSV malware record (critical): stop. Install nothing more and run nothing from the project. Tell
  the user to treat it as a compromise: do not install this version, move the lockfile to a version without a
  record, and rotate the credentials (package registry, GitHub, cloud) on every machine and CI runner that
  installed it.
- WS-OS-900, OSV not reached: those versions were not checked, which is never clean. Run `wormsign soak` again when
  api.osv.dev answers; never add `--no-osv` to make it pass. If the message names a git dependency, the 1,000-version
  ceiling, or a registry or index other than npm's public registry or pypi.org, running again does not help: report
  it to the user.
- A high or critical finding from `diff` or `scan`: report it and do not install. Do not edit a workflow or script
  to silence it.

## The baseline
- `.wormsign-baseline.json` approves findings by fingerprint. Only the user approves an entry: never add, edit or
  renew one without their explicit OK. Each entry needs a justification of at least 15 characters (what was checked,
  why it is safe), and a soak exception also an `expires` date a few days past the day the version is 7 days old.
- `diff` and `soak --base` read the baseline from `<base>`, so a change cannot approve its own findings: an entry
  must reach the base branch first. A change to the baseline is itself a high finding (WS-DF-005).
- Checking a tree you did not write (a clone, someone else's branch): add `--no-baseline`, because the tree's own
  baseline can hide any finding in it.

## IOC data
`scan` and `diff` match the IOC data bundled with wormsign. `wormsign update-iocs` downloads newer data into a
cache (`~/.cache/wormsign/iocs` by default) whose entries later scans add; it uses the network and the data is not
signed, so run it only when the user asks.

Not installed: https://github.com/stgllghr/wormsign/blob/main/docs/installation.md
