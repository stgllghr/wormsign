# Soak time: refusing package versions that are too new

Run `wormsign soak` before every install, in CI and on your machine. It fails any locked version younger than the
soak time (default 7 days), or whose age it cannot verify: a compromised version is usually noticed and pulled within
that time. Flags: [cli/soak.md](cli/soak.md). Tests: [validation.md](validation.md#4-mutation-check).

| Layer | What it does | Where it runs | Network |
|---|---|---|---|
| 1. Package-manager settings | refuses to *resolve* a version younger than its cooldown | every install | registry only |
| 2. Lockfile gate (`wormsign soak`) | fails a *locked* version younger than `--min-age`, or one it cannot verify | before the install, in CI or on the device | registry |
| 3. OSV check | fails a locked version with an OSV `MAL-` record or a CWE-506 GitHub advisory | inside `soak` | api.osv.dev |
| 4. Registry signals | reports an added install script, dropped provenance or a new publisher | inside `soak` | none extra |

In `soak`, Python locks get layers 2 and 3 only ([Python (PyPI) locks](#python-pypi-locks)).

Layer 1 has two gaps: some package-manager versions silently ignore the setting, and most do not apply it to a
version already in the lockfile. Layer 2 closes the second gap for every lockfile install after the gate, and reports
the first (WS-SK-004). It cannot stop a resolving install such as `npm install <pkg>` on a package manager that
ignores its setting.

## Why 7 days, and when 72 hours is enough

The default is 7 days (`--min-age`, the Action's `min-age`, `harden-dev.sh --soak`). 72 hours is a tuned value for
the lockfile gate in CI, where `soak` also asks OSV ([ADR 0003](adr/0003-seven-day-default-soak.md)). The data
([evidence/soak-latency.md](evidence/soak-latency.md)) times every compromised version in the bundled IOC data,
across five waves of one npm worm family, from publish to the first public malware advisory that listed it.

**On a developer machine, removal is what protects you.** A cooldown checks age and nothing else: once it has passed,
the version installs unless the registry has removed it. The data proves removal within 72 hours for only 21% to 58%
of a wave's versions (49.2% of all of them), so 72 hours alone is not shown to be enough. Proven removal barely moves
by 7 days (51.3%), because a later write to a package hides when a version went. But at 7 days every measured version
had been listed by an advisory for at least 3.8 days. The slowest version of the slowest wave was listed at 77.4
hours, with three method artefacts in the May 2026 wave corrected ([anomalies](evidence/soak-latency.md#anomalies)).

**In CI with the OSV check, 72 hours is a reasonable tuned value.** A version past its soak time but still
installable fails once api.osv.dev serves a record for it. OSV's importer recorded 3,525 of the 3,530 versions whose
first listing is an OSV snapshot (99.9%) within 72 hours of publish; the slowest, the three method artefacts aside, at
130.6 hours. The step from import to serving is not measured
([evidence](evidence/soak-latency.md#what-this-does-and-does-not-show)). The two `@ornikar` versions of the August
2026 wave, listed upstream at 77.4 hours and imported at 130.6, would have passed a 72-hour gate even with OSV; 7 days
covers them. OSV listed every measured version, partly by construction: five of
the six version lists came from OSV's OpenSSF records. On the one list chosen independently, Datadog's 1,091 November
2025 versions, OSV lacked 1, and GitHub advisories, which `npm audit` reads, lacked 17.8%. So `--min-age 72h` trades
that margin for fixes that pass four days sooner, and only while the OSV check runs: with `--no-osv` (Action:
`osv: "false"`), keep 7 days. A project can gate at 72 hours and keep `min-release-age=7` for its developers'
installs; a setting shorter than `--min-age` is WS-SK-004.

**The cost.** A legitimate release waits a week. Dependabot security updates skip its cooldown
([positioning.md](positioning.md#dependabot-cooldown)), but the gate still fails the fix until it reaches the soak
time, unless it has an exception: a time-limited baseline entry lets the version through
([Emergency exceptions](#emergency-exceptions)), with OSV and the registry signals still applied.

**Caveats** ([evidence](evidence/soak-latency.md#what-this-does-and-does-not-show)):

- Advisory time is not removal time: after any soak a malicious version may still be installable, which is why layer
  3 exists and the 72-hour value needs it.
- Five waves is a small sample. 7 days is about 2.2 times the slowest wave's slowest version: a margin, not a bound.
- Only caught versions are in the data; a quiet compromise can go unnoticed far longer than 7 days.
- PyPI locks get the same default, but it is not derived from PyPI evidence ([threat model](threat-model.md#pypi)).

## Layer 1: package-manager release-age settings

"New resolution" is an install that picks a version (`npm install <pkg>`, `pnpm add`).
"Locked version" installs a young version a lockfile already pins (`npm ci`, `yarn install --immutable`). Commands
and results: [evidence/package-managers.md](evidence/package-managers.md); where each setting is read:
[cli/soak.md](cli/soak.md#1-release-age-configuration-offline).

| Package manager | Setting | Unit | New resolution | Locked version |
|---|---|---|---|---|
| npm 10.9.2 (bundled with Node 22) | `min-release-age` | days | **ignored**: accepted, echoed by `npm config get`, not enforced | installed |
| npm 11.10.0, 11.21.0, 12.2.0 | `min-release-age` | days | blocked (`ETARGET`) | **installed** |
| pnpm 10.16.0 | `minimumReleaseAge` | minutes | blocked, **except** after it was resolved once without the setting (warm metadata cache) | installed |
| pnpm 11.16.0 | `minimumReleaseAge` | minutes | blocked when set explicitly; the 1-day default is loose and let a 23-hour-old version through | rejected, but after `node_modules` was linked |
| pnpm 12.8.1 | `minimumReleaseAge` | minutes | as pnpm 11 | rejected before linking |
| Yarn Classic 1.22.22 | none known | | no gate | no gate |
| Yarn 4.10.3 | `npmMinimalAgeGate` | minutes; **`3d` is read as 3 minutes** | blocked (`YN0082`); default 0 | **installed** |
| Yarn 4.18.1 | `npmMinimalAgeGate` | minutes; `3d` is read as 4320 | blocked (`YN0016`); default 1440 | **installed** |
| bun 1.4.2 (setting from 1.3) | `[install] minimumReleaseAge` | seconds | blocked | **installed** |

Each package manager can also exempt packages, and any entry there is a hole in the gate:

| Package manager | Bypass | `soak` reports it |
|---|---|---|
| npm | `min-release-age-exclude`; an explicit `before=<date>`, which wins over `min-release-age` | **no** ([Limitations](#limitations)) |
| pnpm | `minimumReleaseAgeExclude`; `minimumReleaseAgeStrict: false`; `trustLockfile: true` (pnpm 11.3.0+) | yes, WS-SK-004 |
| Yarn 4 | `npmPreapprovedPackages`, in any `.yarnrc.yml` | yes, WS-SK-004 |
| bun | `[install] minimumReleaseAgeExcludes` | yes, WS-SK-004, in the root `bunfig.toml` |

What follows:

- **npm needs 11.10 or newer, and "Node 24" alone does not tell you that.** Node 24.0.0 bundled npm 11.3.0; the
  first 24.x whose npm enforces the setting is 24.14.1 (npm 11.11.0) ([why Node 24](installation.md#why-node-24)).
  `wormsign soak --config-only --require-config` fails on an npm that ignores the setting
  ([fix](troubleshooting.md#npm-ignores-min-release-age-ws-sk-004)).
- **Write Yarn's gate in plain minutes**: `npmMinimalAgeGate: 10080` for 7 days. Yarn's documented duration string
  holds for the newer versions tested, not for 4.10.3.
- **Defaults are not a gate**: pnpm 11's 1-day default is not strict, and Yarn's went from 0 (4.10.3) to 1 day
  (4.18.1). wormsign counts only a value set explicitly.
- **A lockfile install is not age-gated by npm, Yarn, bun or pnpm 10**, and that is how CI installs. Layer 2 exists
  for this.

## Layer 2: the lockfile gate, `wormsign soak`

`wormsign soak [dir]` reads every lockfile under `dir` (`package-lock.json`, `npm-shrinkwrap.json`,
`pnpm-lock.yaml`, `yarn.lock` for Yarn Classic and Yarn 2+), asks the registry for each locked version's publish
time, and fails any younger than `--min-age`. It also runs layers 1 and 4, and layer 3 unless `--no-osv` is given.
Live controls against the real registry: [evidence/soak-live.md](evidence/soak-live.md).

### What it checks

Each locked version's source, publish time, identity and age, and that it is still published. A local package is listed
in a note. An entry can carry an old, benign `name@version` label on a different tarball, and `npm ci` installs the
tarball, so its integrity hash must be the registry's for that version (or, with no comparable hash, its `resolved` URL
the registry's tarball). Too young is WS-SK-001; anything the gate cannot verify is WS-SK-002, high, never a pass
([the full list](cli/soak.md#what-it-checks)). A settings file wormsign cannot interpret is WS-SK-004 and counts as an
unknown registry, so every package fails closed.

### PR mode: `--base <rev>`

With `--base <rev>`, `soak` skips npm, pnpm and Yarn entries the base's copy of the same lockfile locked identically
([details](cli/soak.md#pr-mode---base-rev)), and Python entries the same way ([PR mode](#pr-mode)): npm and Python
skip identical entries alike, and nothing else. A version the base locked in a docs lockfile is checked again when a
change adds it to the lockfile that is installed. Release-age settings (WS-SK-003, WS-SK-004) and every lockfile and
file-level problem, npm's and Python's, are reported on every run, the base's included. The baseline is read from the
base too, so a change cannot suppress its own findings.

A young version pushed straight to the base is the gap this leaves: later pull requests pass it. The full `soak` on
push and on the daily schedule catches it ([Push and scheduled checks](github-action.md#push-and-scheduled-checks)).

### Verifiable output

`--format json` records what the gate saw for every version ([output.md](output.md#soak-evidence)); keep it as a CI
artifact outside the checkout, from a `run:` step, since the Action keeps SARIF only.

### Private registries

`soak` checks one registry, `--registry` (default `https://registry.npmjs.org`; https, or http for localhost), and sends
no credentials. It reads every registry setting the install could use, not only the one that wins, so a registry other
than `--registry` set in any of them fails closed (WS-SK-002) instead of sending a private name to the public registry:
`.npmrc` (project and user), `npm_config_*` and `pnpm_config_*` variables, `pnpm-workspace.yaml`, pnpm's global
`config.yaml`, every `.yarnrc.yml`, and `YARN_NPM_REGISTRY_SERVER`.

It cannot see a registry given only on the install's command line, in another CI step's environment, or in npm's
global `npmrc`. If such a registry serves a pnpm or Yarn 2+ lockfile, which records no package URL, the name goes to
registry.npmjs.org (and fails as WS-SK-002). Run `soak` with the install's environment, or pass `--registry` (the
Action's `registry` input; `registry-host` keeps `scan` and `diff` from reporting the mirror's lockfile URLs,
[github-action.md](github-action.md#inputs)).

A `--registry` with credentials is a usage error (exit 2), since the URL is printed. Fixes:
[troubleshooting.md](troubleshooting.md#a-private-registry-fails-closed-ws-sk-002). With a non-public `--registry`,
nothing is sent to OSV, and those versions are WS-OS-900 (high) unless you pass `--no-osv`.

### The configuration check: `--config-only` and `--require-config`

`--config-only` checks only the release-age settings, offline: a missing one is WS-SK-003; one too short, unreadable,
ignored by the version that will run, or undone by a bypass is WS-SK-004; `--require-config` raises both to high,
except Yarn Classic's low WS-SK-003 ([what it reads](cli/soak.md#1-release-age-configuration-offline)).

### Outages: `--on-outage`

By default an outage fails the gate: while the registry, the Python index or OSV is down, every package it left
unchecked is WS-SK-002 or WS-OS-900, high, and every pull request fails. A team that cannot merge switches the gate
off; `--on-outage warn` (the Action's `on-outage` input) is a visible degrade it can choose instead.

- **An outage is the whole configured host unreachable for the entire run.** It takes both:
  - the request failed after its retry with HTTP 429 or a 5xx, or in transport before any status line came back (a
    DNS or connection error, a TLS handshake that broke off, a timeout);
  - the host gave no other answer in the run (any status but 429 and the 5xx counts), and a `HEAD` of its root,
    sent once after the run, fails in transport or gets 429, 502, 503 or 504 (any other status, 501 included, is
    a host that is up).

  Nothing else is an outage, and each stays exactly as it is: one name the host will not serve while it answers
  the rest or its root, a host that goes down mid-run, a body that is slow, cut off or does not parse after a status
  line, a 404 or another 4xx, a redirect (none is followed), a certificate the client rejects, an integrity
  mismatch, a young version, a private registry or a name wormsign cannot vouch for. A failed OSV record query never
  is: it follows a batch OSV answered. One classifier decides it for all three services
  ([`src/net.ts`](../src/net.ts)).
- **Under `warn`**, each package an outage left unchecked is [WS-SK-006](rules.md#ws-sk-006) (registry or index)
  or [WS-OS-901](rules.md#ws-os-901) (OSV), medium, naming the host, the error and the package. The run prints one
  line on stderr, which is also the report's first note and, in the Action, the step summary:
  `UNVERIFIED: 3 packages not checked (registry.npmjs.org unreachable: HTTP 503); --on-outage warn`.
- **What it helps with.** registry.npmjs.org serves its root as immutable and cacheable, so an outage of the
  registry's origin alone may still answer the probe from a cache and fail closed: `warn` helps when the network
  path to the host is broken.
- **The trade-off.** At the default `--fail-on high` a `warn` run passes during an outage, so whoever can make the
  whole host unreachable from the runner for the entire run (an outage, a firewall rule, an attacker on the network
  path) can get a change past the gate unchecked, and the jobs that wait on the gate install it. The medium findings and the UNVERIFIED
  line are the only record. Use `warn` only where a gate that teams switch off is the worse risk.
- **Nothing re-checks them.** A run that passes with an UNVERIFIED line has not checked those packages, and nothing
  checks them again at merge. Re-run `soak --base` on the merge commit once the host is back, or keep `fail` for an
  organization-wide gate.
- **Never baselined.** An outage is transient: an entry for WS-SK-006 or WS-OS-901 would waive the next one, so a
  baseline never suppresses them. Their fingerprints differ from the WS-SK-002 and WS-OS-900 findings for the same
  package, so an entry for one never matches the other.

## Layer 3: OSV malicious-package records

A soak waits for an advisory; layer 3 reads it before the install. `soak` asks [OSV](https://osv.dev)
(`POST https://api.osv.dev/v1/querybatch`) about every locked version whose name the public registry served, and
reports WS-OS-001 (critical), one finding per record:

- OpenSSF malicious-package record (`MAL-` id), into which GitHub's malware advisories are merged;
- GitHub advisory (`GHSA-` id) whose CWE ids include CWE-506, "embedded malicious code", the class GitHub gives a
  hijacked release.

Any other record (`PYSEC-`, `CVE-`, a GHSA without CWE-506) is a vulnerability, not malware, and is not reported.

**Why OSV.** `npm audit` reads GitHub advisories, which lacked 8.9% of the worm versions in the latency study (17.8% of
the list chosen independently of OSV); OSV lacked 0.1% of that list
([evidence](evidence/soak-latency.md#what-this-does-and-does-not-show)). CWE-506 advisories count because some hijacked
releases have one first or only: `ua-parser-js@0.7.29` has only
[GHSA-pjwm-rvh2-c87w](https://osv.dev/vulnerability/GHSA-pjwm-rvh2-c87w), and `num2words@0.5.15` (PyPI) got its advisory
six days before OSV imported `MAL-2025-6794` ([PyPI incidents](evidence/pypi-incidents.md)). A compromise with neither
is not seen: the Ultralytics releases have only `PYSEC-2024-154`.

Only `name@version` pairs go to OSV, and only for names the public registry served; a local, git or other-registry
entry, a failed lookup, or a Python entry under an index setting `soak` cannot rule out is sent nowhere (limits:
[Network](cli/soak.md#network)). A version OSV did not answer for, or whose records could not be read, is
WS-OS-900 (high), never clean. `--no-osv` turns the check off, and a note says so.

## Layer 4: registry signals

`soak` compares each version it reads with the version it replaces:

| Rule | Severity | Fires when | Why |
|---|---|---|---|
| WS-RG-001 | high | adds or changes a `preinstall`, `install` or `postinstall` script | the worm adds a `preinstall` to each package it republishes ([JFrog](https://research.jfrog.com/post/shai-hulud-is-back-august/)) |
| WS-RG-002 | high | the previous version had a provenance attestation and this one does not | a stolen token used outside GitHub Actions or GitLab CI publishes without one |
| WS-RG-003 | medium | a token or password publish by an account that published none of the five versions before | a worm publishes all the token can write |

"The version it replaces" is, in PR mode, the one the base locked, when it locked exactly one other version of that
name; otherwise the newest earlier version on the same major line. A first publish gets a note and no install-script
or provenance check. A full run reads only versions published in the last 14 days: every measured worm version had
a malware record within 7 days, so past that OSV is the better witness. PR mode reads every version the change adds
or updates.

These are heuristics with an unmeasured false-positive rate: a new native addon, a hand publish or a handover
triggers them, and a worm publishing from the package's own release workflow gets valid provenance and the usual
publisher ([rules.md](rules.md)).

## Python (PyPI) locks

`soak` reads Python locks in the same run and walk as npm's, with the same rules, baseline and exit codes.

| File | Written by | Read as |
|---|---|---|
| `uv.lock` | `uv lock` | every `[[package]]` |
| `<script>.lock` (PEP 723) | `uv lock --script <script>` | a `uv.lock`, for the script beside it |
| `pylock.toml`, `pylock.<name>.toml` (PEP 751) | `uv export --format pylock.toml`, `pip lock` | every `[[packages]]` |
| a requirements file that is a complete hash lock | `uv pip compile --generate-hashes`, `pip-compile --generate-hashes` | [below](#requirements-files) |
| `poetry.lock`, `pdm.lock`, `Pipfile.lock` | Poetry, PDM, pipenv | not read yet: WS-SK-002 |

`soak` does not check Python's layer 1 settings; `harden-dev.sh` checks pip's and uv's on a developer machine (H12,
H13). They are not a gate for locked installs: `uv sync --frozen` and
`pip install -r pylock.toml` with pip 26.1 installed a locked version younger than the cutoff, and pip 26.2 checks a
`pylock.toml`'s own `upload-time` fields, which the lock's writer wrote. Layer 3 is the npm rule, asked only when the
index is pypi.org.

### Each locked file, not the version

PyPI has no publish time for a release. Each file has its own `upload-time`, and files can be added to a release
later: a PyYAML 6.0.1 wheel in the test fixtures came 184.9 days after its release's first file. So `soak` ages files:

1. **Binding.** Every installable file the lock pins must carry a sha256 and no other hash, since pip accepts a file
   matching any one. The sha256 must be that of a file of exactly this project and version on the index, and a file
   URL the lock records must be the index's, character for character. Otherwise WS-SK-002.
2. **Project status** (PEP 792). `quarantined`, or a status `soak` does not know, is WS-SK-002. `archived`,
   `deprecated` and a yanked file are notes: yanking is not a malware signal.
3. **Age** is the youngest bound file's upload time. Too young is WS-SK-001, keyed on the exact set of locked files,
   so a baseline entry approves that set and any change to it fails again.

### Sources

| Source in the lock | Result |
|---|---|
| `--pypi-index` | bound and aged as above |
| another index, find-links, git, another VCS, a direct URL | WS-SK-002; the name is sent nowhere |
| a local project (uv `directory` or `editable`, pylock `directory`) | a note, if it passes the local rule; WS-SK-005 if the install builds it |
| a uv `virtual` project | the local rule's path checks, and a tracked `pyproject.toml` or `setup.py` |
| an archive by path | must hash to the locked sha256 and pass the local rule; aged on the index only with an explicit `--pypi-index`, else WS-SK-002, so vendored private wheels never reach pypi.org |
| a `pylock.toml` package with no `index` | sent only if every file URL is on the index's file host and the [install settings](#requirements-files) allow it |

The **local rule**: the path is relative and inside the root, holds a `pyproject.toml` or `setup.py`, has no symlink
leading outside the root, and, in a git work tree, every file under it is tracked or git-ignored. Otherwise WS-SK-002
"local source not present in the reviewed tree". Run `soak` on a clean checkout: an untracked file fails it in PR mode,
and is medium without `--base`.

### Requirements files

A requirements file is a lock only when it, with every file it includes (`-r`, `-c`), has a `--require-hashes` line,
and every requirement is `name[extras]==<version>` with at least one `--hash=sha256:...` and no other hash. Any
other option (`--index-url`, `--find-links`, `--no-binary`, `-e`, ...), a URL or VCS line, or `${` is WS-SK-002 with
its line number. The fix: `uv pip compile --generate-hashes` (or `pip-compile`), then a `--require-hashes` line.

pip applies an index option to the whole install, so an index option, an unread line or include, or an unreadable
file keeps every entry of that unit from being sent. The file is read as pip 26.2.1 reads it; where pip and uv
disagree, that is a problem. pip joins every line that ends in `\` to the next; uv reads some such lines only up to
the line break. So a continued line is read only in the shape `pip-compile` and `uv pip compile` write: a requirement
(not an option) ending in a space and one `\`, then lines of `--hash=sha256:<64 lowercase hex digits>` indented with
spaces, each but the last ending in ` \`. Any other continued line makes the whole file one WS-SK-002 no entry
approves, naming both readings: an option (`-r a.txt \` is `a.txt` to pip and the file `a.txt ` to uv; write the
option and its value on one line), a comment, a `\` with no space before it (`--hash=sha256:<60 digits>\` then
`c926` is one hash to pip, a requirement `c926` to uv), a doubled `\`, a tab, or a next line that is not such a
hash. A `#` inside a value on an allowed line (a URL's `#sha256=`, a quoted marker) starts no comment for either, and
is read. A `..` after a directory name in an include or a local path (`-r node_modules/foo/../a.txt`) is such a
WS-SK-002 too: pip resolves it as text, uv joins the path as written and the system follows a symlink at `foo` first;
`soak` follows neither.

**Which problems a baseline entry can approve.** None, unless `soak` understands the line well enough that its key
fixes what an install fetches (ADR 0001). A problem's key covers its line, so an entry approves that line only, and
only these lines opt in:

- **A plain index requirement** `soak` parsed to the end: a name (not an archive's file name), optional extras, an
  optional marker and version specifiers, with no option on the line but `--hash` (`foo>=1`, `six==1.17.0` without a
  hash, a hash other than sha256). Its key is its line, as before.
- **A local file** `soak` resolved to a regular file inside the root: a path or a `file:` URL (`file:foo` too; its
  `?query` and `#fragment` dropped, as pip drops them), keyed by what is at it at every place pip may find it, since
  pip resolves a relative path from where it runs: beside the requirements file that names it, from the root, and
  from the directory of the top-level requirements file and of each file that includes it (`backend/` for
  `backend/requirements.txt`). At each: the file's sha256, through a symlink the target's path inside the root too,
  or `missing`, with a file at one place at least. So an entry approves those bytes only; a change that swaps the
  archive, retargets the link or plants a file at another of those places fails again.

Every other requirements problem is WS-SK-002 that no entry approves (`notBaselinable`), and its message says why:
an option or `--` on a requirement line, a path with extras or `${`, an archive name with extras (a name is tested
as written: `foo.whl==1.0` is one), an include, an index option, a VCS or remote URL (`git+file:repo` too), a line
or file `soak` could not split or decode, a local path missing at every place or that is a directory, one `soak`
cannot pin (outside the root, behind a symlink that leaves the root or does not resolve, a backslash, over 4 GiB,
unreadable), every halt, the stop after 200 problems included, since what follows was never read, and the missing
`--require-hashes` line, which is keyed on no text of the file: the remedy is the line, and a file nothing installs
from belongs in [`ignorePaths`](baseline.md#ignorepaths). Fix the line: a `name==version` pin with `--hash`, or a regular file inside the repository, checked from
the repository root. A directory (`./pkg`, `-e ./pkg`) is not a file: `soak` reports the project's own
`pyproject.toml` only when it declares dependencies (keyed on the whole file) and a `setup.py` always (keyed on its
bytes), and `diff` reports a change to the project's build files as WS-DF-005.

**Which files.** By name, ignoring case: `*requirements*.txt`, `*constraints*.txt`, `requirements*.lock`, or any `.txt`
under a `requirements` directory. Any other file only when the content pass ([Discovery](#discovery-what-is-read))
finds a `--hash` or `--require-hashes` in it, or a file `soak` reads includes it. `pip install -r deps.txt` of a file
without hashes is outside the gate and gives no finding.

**Install settings.** A requirements file records no index, and `pylock.toml` need not. Before sending their names,
`soak` fails closed on any install setting it can see that names another index or turns hash checking off: pip's
and uv's environment variables, `python3 -m pip config list`, every `uv.toml` and `[tool.uv]` from the file's
directory up, the user and system `uv.toml`, and any committed `pip.conf` or `pip.ini`. It does not model which
setting wins. If the pip probe ([how it runs](cli/soak.md#network)) cannot run, the entries fail closed unless
`--pypi-index` is given explicitly, which waives only the unread configuration.

### Builds: WS-SK-005

A source build first installs build requirements, which no lock pins: the installer resolves them fresh, protected only
by its own cutoff and `==`-pinned build constraints. WS-SK-005 names the builds `soak` can see: a local project the
install builds, a package locked only as sdists, and uv settings that force builds (`no-binary`, `no-build-isolation`
and `config-settings`, each with its `-package` form, `extra-build-dependencies` and `extra-build-variables`).

It is medium on a full run: most Python projects build something. In PR mode, one the change adds is high, so the
gate stops a pull request that adds a just-published build backend. A build is the base's when the base's files give
the same key and, for a local or sdist-only build, the base's `soak` read the lock that holds it; otherwise it is
high on every pull request until a baseline entry in the base approves it.

**The key** of a local build is the sha256 of its build files (`pyproject.toml` without its version, metadata and linter
settings; `setup.py`, `setup.cfg` and build hooks), not of what they read or import at build time (beyond the `.py`
files beside a hook in a subdirectory). A release bump in `setup.py`, `setup.cfg` or `[tool.poetry]` changes it; a
`[project]` version bump does not.

<details>
<summary>Every file and table the key covers</summary>

- `pyproject.toml`, parsed, without `[project]` `version` and metadata, linters' `[tool]` tables (`ruff`, `black`,
  `isort`, `mypy`, `pyright`, `pytest`, `coverage`, `pylint`, `flake8`, `codespell`), and, with no `backend-path`
  and a backend that never builds with them, the rest of `[project]` and `[dependency-groups]`
  (`setuptools.build_meta`, `flit_core.buildapi`, `pdm.backend`, `poetry.core.masonry.api`, `maturin`,
  `scikit_build_core.build`, `mesonpy`, `uv_build`, and `hatchling.build` without `require-runtime-*` keys);
- `setup.cfg`, `uv.toml` and `hatch.toml`, whole;
- `setup.py`, `hatch_build.py`, `pdm_build.py`, `build.py`, each hook file a setting names, and every file under
  `backend-path`;
- for a `uv.lock` member, the workspace root's `[tool.uv]` and `uv.toml`.

It also covers the `.py` files beside a hook in a subdirectory, but no hook outside the project's directory. An edit
to another non-linter `[tool]` table (`[tool.bumpversion]`, `[tool.hatch.envs]`) changes it; an edit to the project's
own modules does not, unless under `backend-path`.

</details>

To avoid a local build: [troubleshooting.md](troubleshooting.md#ws-sk-005-a-build-at-install-time).

### Manifests, scripts and virtual environments

- **Manifests.** A `pyproject.toml`, `setup.py`, `setup.cfg` or `Pipfile` that declares dependencies with no lock
  covering it is WS-SK-002, as a `package.json` without a lockfile is. A lock in its directory covers it, as does a
  requirements file directly in a `requirements/` directory beside it, or a `uv.lock` that lists it as a workspace
  member or path source. Covering goes by directory, not by what the lock pins. A manifest that names only the root
  project, such as an example beside a library (click's `examples/*`), has no exemption: the root's `uv.lock` covers it
  only if it lists that directory, as it lists a workspace member. Without a covering lock it is WS-SK-002 high,
  whatever its `[tool.uv.sources]`: an install reads that name, or the root's dependencies, from the index.
- **PEP 723 scripts.** A script (`*.py`, `*.pyw`, a `uv run` shebang, or a `# /// script` line) whose block declares
  dependencies needs `<script>.lock` beside it (`uv lock --script <script>`, then `uv run --locked`), or it is
  WS-SK-002. An orphan script lock is reported too.
- **Virtual environments** (`pyvenv.cfg` plus `site-packages`). In a git work tree, an untracked one is skipped, with a
  note. With no work tree, its `site-packages` is not read, and a watched name inside it is WS-SK-002. npm's half of the
  walk does the same.

### Installing the project itself

A lock in a project's directory covers its manifest, but `pip install .` and `pip install -e .` choose their own
versions for the project's dependencies. Install the lock first, then the project without its dependencies:

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install --require-hashes --no-deps -r requirements.txt
pip install --no-deps -e .
```

For a non-editable copy, use `pip install --no-deps .`. With uv, `uv sync --locked` installs exactly what `uv.lock`
lists, the project included. Building the project still installs its build requirements fresh
([limitation 3](#python-limitations)).

### Discovery: what is read

One walk serves npm and Python. Python inputs are found by name, and the content pass, which looks for scripts and
requirements files by what they hold, opens only:

- `.py` and `.pyw` files;
- files with no extension (`Dockerfile`, `.requirements`), or one of these extensions: `.txt`, `.text`, `.in`,
  `.lock`, `.pip`, `.req`, `.reqs`, `.requirements`, `.lst`, `.list`, `.deps`, `.conf`, `.cfg`, `.ini`, `.sh`,
  `.bash`, `.zsh`, `.command`;
- any file with a `<name>.lock` beside it, since uv runs a script with that lock.

No other file is opened. A candidate is searched up to 64 MiB, so padding does not hide a hash lock. A larger
script, or file with a `<name>.lock` beside it, is WS-SK-002; any other larger candidate is not read, and a note
names it.

A file named like a requirements file, or found by its content, with a line that is neither a requirement nor an
option (`FROM node:22`, prose) is one high WS-SK-002 for the whole file ("named like a pip requirements file, but
wormsign cannot read it as one"), keyed on its content, never a note, since whether pip would refuse a file is a
judgement that can be wrong.

`ignorePaths` apply to Python inputs, and a note lists what was passed over. npm lockfiles, and index and hash
settings, are read wherever they are. With `--base`, the base's `ignorePaths` apply.

### PR mode

With `--base <rev>`, a Python entry the base's own `soak` read identically is not checked again, as an npm entry is
not. Both of these must hold:

- **The base's `soak` read the same file as a lock of the same kind**: at the same path, a `uv.lock`, a
  `pylock.toml`, a script lock beside its script, or a requirements file by name that is a complete hash lock (a
  `--require-hashes` line, every requirement hashed, no other option, every include followed), and so is the change's
  copy. Neither the run's baseline (the base's, or `--baseline`) nor the base's own committed baseline passes it over
  with `ignorePaths`, and no `.git`, `node_modules` or symlink is on its path. A file the base found only by its
  content counts as not read.
- **The base's reading pinned the entry identically**: the same name and version as the lock's reader gives them (a
  PEP 503 name; a PEP 440 version in canonical form, so `1.40.099` is `1.40.99` but `1.40.99.0` is another version)
  and the same set of hashes, in the same file (an entry from an include: the same include, itself a requirements
  file the base read). For `uv.lock` and `pylock.toml`, also the same source or index URL and the same files as the
  lock records them. Every file needs a sha256 and no other hash. This is what the lock records, not what an
  installer would make of it ([ADR 0004](adr/0004-no-installer-parser-imitation.md)).

The base is read from git as it stores each file, in memory. Nothing in a file counts as the base's when that may not
be what the base's own `soak` read, and a note says why:

- the base's git attributes set `working-tree-encoding`, `filter` or `ident` for the file or for a file its reading
  includes, since a checkout then holds other bytes. `soak` asks `git check-attr --source=<rev>`, which reads the
  base's `.gitattributes` files above the scanned directory too, and `info/attributes`. It needs git 2.40 or later,
  and every `.gitattributes` blob of the base in the clone (a blobless partial clone may lack one); otherwise no
  Python entry counts as the base's;
- the base's requirements files hold more entries between them than `soak` reads (250,000): then no requirements entry
  counts. The count covers the base's files by requirements name, those its content marks as requirements files, and
  the base's copy of each lock the change has; when those files cannot all be read (a partial clone, over 256 MiB),
  no requirements entry counts;
- the base's own baseline does not parse: then no Python entry counts.

Anything else is checked as on a full run: an entry that is new or changed, moved to another file or renamed with
it, or in a file the base's `soak` did not read as a lock. So a pin that lands first in a file the base never read as
a lock (a `.md` include, a requirements file without `--require-hashes` or one pip and uv refuse, a script lock
with no script, a file under the base's `ignorePaths`) is checked once a change makes it one.

An entry the base read is not aged or sent to OSV. Its files are still bound on the index, only to tell a package
locked only as sdists (WS-SK-005), and what the index shows is reported: a project gone or quarantined, a locked
file no longer there. An index error for it is not.

- **File-level problems** are reported on every run, PR mode included, as npm's are: every reader problem (a
  requirements file with hashes and no `--require-hashes`, a line naming a local wheel, an include `soak` does not
  follow) and every discovery finding (a manifest no lock covers, a script without a lock, an install setting). A
  fingerprint does not always cover what a problem governs (an include `soak` does not follow is keyed on its line,
  not on the file pip reads), so one the base had is no proof that nothing changed. One that predates a pull request
  fails it until it is fixed on the base or, when an entry can approve it, baselined: for a pip-compile file with
  hashes and no `--require-hashes`, add the line on the base once (no entry approves the missing line).
- **WS-SK-005** keeps its rule: a build the change adds is high.
- **Index settings.** A change to `pip.conf`, `pip.ini`, `uv.toml`, `[tool.uv]` or the environment that leaves the
  pins and hashes as they were leaves the entries the base's. An install checks each file against the locked hashes,
  from whichever index, so the bytes are those the base's `soak` bound and aged. The setting is its own WS-SK-002
  ("an install may use another index", or "may skip hash checks"). An index option inside the requirements file makes
  it no complete hash lock, so its entries are checked again.
- **A young version pushed straight to the base** passes later pull requests, as for npm: the full `soak` on push and
  on the daily schedule catches it ([Push and scheduled checks](github-action.md#push-and-scheduled-checks)).

### The index: `--pypi-index`

`soak` checks one Python index, `--pypi-index` (default `https://pypi.org/simple/`), set only on the command line or
the Action's `pypi-index` input, never from the repository: https (http for localhost), no credentials. A private
index must serve the Simple API's JSON form with PEP 700 upload times without authentication. With any index but
pypi.org, OSV is not asked and the check is WS-OS-900 unless `--no-osv` is given.

### Which installs the gate covers

The gate protects an install that installs exactly the lock:

- `uv sync --locked` or `--frozen`, and `uv run --locked`;
- `pip install --require-hashes --no-deps -r <file>`, or `uv pip sync <file>` with uv 0.12.0 or later, then
  `pip install --no-deps .`;
- `pip install -r pylock.toml` with pip 26.1 or newer, which fails on a dependency the lock leaves out.

An install that resolves versions installs ones the gate never saw: plain `uv sync` after a `pyproject.toml` change,
`pip install .`, `pip install <name>`, and environments tox, nox and hatch resolve themselves. Install with `--locked`
or `--frozen`. The live controls are in
[evidence/soak-py-live.md](evidence/soak-py-live.md).

### Python limitations

1. **Out-of-date locks and resolving installs** are not detected; the gate assumes `--locked`, `--frozen` or
   `--require-hashes`. So a `[tool.uv]` index or sources edit beside an unchanged `uv.lock` gives `soak` nothing, on
   any run: `uv sync --locked` refuses the stale lock and `--frozen` installs it as written (`diff` reports the edit,
   WS-DF-005).
2. **uv older than 0.12.0** ignores `--require-hashes` inside a requirements file, and `uv pip sync` skips hash checks
   when `verify-hashes` is off; `soak` cannot see a setting given only to the install step. Use uv 0.12.0 or later,
   or pip.
3. **Build requirements** are never locked, bound or aged, including for the sdist build of a wheel that does not
   match CI's platform, which `soak` cannot know. WS-SK-005 covers only the builds `soak` sees. For a project no
   `uv.lock` or `pylock.toml` lists, a pull request that adds a just-published build requirement passes
   `soak --base`; `diff` fails it (WS-DF-005) when the change is one the [build key](#builds-ws-sk-005) covers.
4. **Release-age settings** of Python tools are not checked by `soak`, so nothing checks them in CI.
5. **No registry signals, no `.pth` detection**, and nothing for a compromise with neither a `MAL-` record nor a
   CWE-506 advisory, such as Ultralytics in December 2024 ([threat model](threat-model.md#pypi)).
6. **`poetry.lock`, `pdm.lock` and `Pipfile.lock` fail closed**. Export a hash lock or `pylock.toml` instead.
7. **A private index without PEP 700 upload times** fails every file closed.
8. **The quarantined response** (PEP 792) comes from the specification and PyPI's source, not a live observation.
9. **The tree as it is when `soak` runs.** A CI step between `soak` and the install that writes an untracked path is
   not covered.
10. **Discovery** reads other extensions only by name or a `<name>.lock` beside them, nothing over 64 MiB, no Python
    file under `node_modules`, and up to 250,000 requirements entries in all (more is WS-SK-002).
11. **One index, no credentials.** Packages from another index fail closed and can be baselined.

## On the device and in CI

### On a developer machine

`harden-dev.sh` checks the user-level layer 1 settings (H02, H04, H05, H07, H12, H13), and with `--apply` writes
those it can ([hardening.md](hardening.md#what---apply-writes)).

The user-level settings do not cover:

- **A project's own config**, which wins inside that project. `soak --config-only` checks a project's npm, pnpm,
  Yarn and bun settings; nothing checks a project's pip or uv cooldown. `diff` reports a change to an in-tree
  `pip.conf`, `pip.ini`, `uv.toml` or `[tool.uv]` install settings as WS-DF-005.
- **Lockfile installs.** `npm ci` after `git pull` installs whatever the lockfile pins. Gate them:

  ```sh
  wormsign soak && npm ci
  wormsign soak && uv sync --locked
  ```

### In CI

A pipeline that follows this page:

1. Uses npm 11.10 or newer (Node 24.14.1 or later), so `min-release-age` is enforced if anything resolves.
2. Runs `wormsign soak` **before** the install, in PR mode on every pull request, and fails the job on its exit code
   ([the gate](github-action.md#recommended-pull-request-gate)).
3. Installs from the lockfile without scripts (`npm ci --ignore-scripts`). That does not stop a git dependency's
   `prepare` on npm 10, pnpm 10.0 to 10.25, or Yarn 4 once the repository is approved
   ([threat model](threat-model.md#stage-1-install-time-execution)); the gate's WS-SK-002 for a git source does, if
   the install waits on the gate.
4. On the default branch, runs `soak --config-only --require-config`, so the committed setting cannot be weakened
   unnoticed.
5. Delays automated dependency updates by at least the soak time, so their pull requests do not fail on arrival.

Point `soak` at what you install: it walks every lockfile under its root, fixtures included
([soak's root](github-action.md#soaks-root)).

## Emergency exceptions

When a version must ship before it has soaked, baseline its finding with a justification
and an expiry date ([baseline.md](baseline.md)):

```json
{
  "version": 1,
  "entries": [
    {
      "fingerprint": "b156c17072fc357df589482107c0564a",
      "justification": "Emergency upgrade to typescript@7.1.0-dev.20261001.1 for a build fix; reviewed by the maintainer, re-check once it has soaked",
      "expires": "2026-10-05"
    }
  ]
}
```

- The entry covers one version in one lockfile (for WS-SK-002, one tarball too), and only its rule: OSV (WS-OS-001)
  and registry signals (WS-RG-*) still apply.
- Set `expires` a few days past the date the version reaches the soak time. After 23:59:59 UTC that day the entry
  stops suppressing, and the run reports WS-BL-001.
- In PR mode the baseline comes from the base, so the entry must land on the base branch first, or come through
  `--baseline` from a trusted place.

## Limitations

- **A soak only helps against compromises that someone notices** ([threat model](threat-model.md)).
- **It checks the lock, not the manifest.** A `package.json` dependency the lock lacks gives no finding. `npm ci`,
  `--frozen-lockfile` and `--immutable` refuse such a lock, and the gate assumes one of them ([In CI](#in-ci)); a
  plain `npm install` or Yarn 1's `yarn install` resolves it fresh, past the gate.
- **npm's own exemptions are not checked.** `soak` reports nothing for `min-release-age-exclude` or `before` in
  `.npmrc`; with npm 12.2.0 the exclude let a too-new version install
  ([record](evidence/package-managers.md#npm)). `diff` reports every `.npmrc` change as WS-DF-005.
- **Bun lockfiles are not parsed**, so they fail closed (WS-SK-002). Only the root `bunfig.toml` is read.
- **The gate trusts the registry's publish times**, and checks one registry, without credentials.
- **The version check runs `<pm> --version`.** If that fails, the result is WS-SK-004 "enforcement is unverified".
- **Python** has [limitations of its own](#python-limitations).
