# Threat model

What wormsign defends, against whom, and how well, stage by stage: what it **prevents**, **detects** and
**misses**. Several misses are large. A clean run means "none
of the known signs", not "not compromised": a renamed file or script defeats the IOC rules
([validation.md](validation.md)).

The attack is the Shai-Hulud family of npm worms: September 2025, November 2025 ("The Second Coming"), April and May
2026 ("Mini Shai-Hulud") and August 2026, each statement cited from a public report. Rule IDs are in
[rules.md](rules.md), H01 to H14 in [hardening.md](hardening.md), WS-AL, WS-CI and WS-EP in
[detections/README.md](../detections/README.md).

## Components

| Component | Runs | Network |
|---|---|---|
| `wormsign scan` | on a checkout: manifests, lockfiles, workflows, editor and agent settings, payload files, exfiltration endpoints; `--node-modules` adds installed packages | none |
| `wormsign diff` | on a pull request: what it adds | none |
| `wormsign soak` | before an install: age, identity, OSV record and registry signals of each locked npm version; age, binding and OSV record of each locked PyPI file; npm release-age config | registry, PyPI index, api.osv.dev |
| `wormsign audit-org` | on a GitHub organization: worm repositories, visibility flips, runners, IOC workflows and branches | GitHub API (read-only) |
| GitHub Action | wraps `scan`, `diff` and `soak` in CI | as the command |
| `harden-dev.sh` | on a developer machine (macOS, Linux) | only H09 (`gh auth status`) |
| `detections/` | in your SIEM, not run by wormsign | n/a |

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| npm publish tokens | `~/.npmrc`, shell profiles, CI secrets | publishing every package the account maintains: propagation |
| GitHub tokens | `gh` CLI config, CI secrets, shell profiles | persistence, exfiltration repositories, visibility changes |
| Cloud and other credentials | `~/.aws`, gcloud, Azure, kube, docker, terraform, `~/.netrc`, `~/.git-credentials`, CI secrets | the data and infrastructure behind them |
| CI secrets | repository, organization and environment secrets | everything a workflow can read |
| Source code | private repositories | the worm makes them public |
| Your published packages | the npm registry | everyone who installs them |
| Organization configuration | workflows, self-hosted runners | a lasting foothold |
| Files on developer machines | the home directory | the November 2025 wave tried to destroy them |

## Attacker

**Assumed capabilities.** The attacker can publish a new version of any package a stolen npm token can write. Its code
runs at install wherever that version is installed without blocking scripts, with that user's or job's permissions,
environment and files. It uses any GitHub token it finds, within the token's scopes, and spreads automatically.

**Assumed impossible** (if one fails, so does the protection resting on it):

- changing a published npm version, or forging the registry's publish times;
- tampering with the OSV or GitHub API responses (fetched over https);
- compromising the CI job before wormsign runs, or the wormsign release ([Out of scope](#out-of-scope));
- merging without review where branch protection requires the wormsign check and code-owner review of `.github/`: a
  pull request can edit the gate's own workflow ([github-action.md](github-action.md#what-the-gate-does-not-stop)).

**Assumed setup:** the soak gate runs before the install, installs use the lockfile with scripts off, CI uses npm 11.10
or newer, and the baseline comes from the base branch ([soak.md](soak.md#in-ci), [github-action.md](github-action.md)).
`soak` checks the lock, not the manifest: a `package.json` dependency the lock lacks gives no finding, and only an
install that refuses an out-of-date lock (`npm ci`, `--frozen-lockfile`, `--immutable`), which this setup requires,
stops it; `npm install` or Yarn 1's `yarn install` resolves it fresh.

## Summary: the kill chain

| Stage | Prevents | Detects | Main gaps |
|---|---|---|---|
| 1. Install-time execution | scripts off (H01, H03, H06); soak gate (WS-SK-001, WS-SK-002); OSV (WS-OS-001); IOC versions (WS-LK-001) | WS-LC-001 to WS-LC-004, WS-NM-001, WS-DF-001, WS-DF-002, WS-DF-004, WS-RG-001, WS-FS-001, WS-FS-002; WS-CI-001, WS-CI-003, WS-EP-001 | git dependency scripts, which only `soak` stops (WS-SK-002); new payload names; code run at import |
| 2. Secret harvesting | fewer secrets to find (H08, H09; H10 warns); fewer secrets per workflow step (WS-GH-002, WS-GH-003) | WS-LC-002; WS-CI-002, WS-CI-005, WS-EP-001 | anything read in-process by a payload that has already run |
| 3. Exfiltration | none directly | WS-EX-001, WS-EX-002, WS-GH-002, WS-GH-005; WS-OR-001; WS-AL-003 | network egress at run time; WS-GH-005 misses the worm's own workflows |
| 4. Persistence | none: code-owner review of `.github/` does, outside wormsign | WS-DF-003 (medium, for that review); WS-GH-001, WS-GH-004, WS-GH-006, WS-GH-007, WS-PS-001, WS-PS-002; WS-OR-003, WS-OR-004; WS-AL-002, WS-AL-004, WS-CI-004, WS-EP-002 | runners on a host; deleted branches; persistence outside repositories; a push with a stolen token |
| 5. Propagation (republish) | consumers wait out the soak (WS-SK-001) and check OSV (WS-OS-001) | WS-RG-001 to WS-RG-003; WS-LK-001 | publishes through your own trusted release workflow; your own packages are not watched |
| 6. Visibility flip | none | WS-OR-002; WS-AL-001 | needs GitHub Enterprise Cloud for the audit log |
| 7. Destructive fallback | only by stopping stage 1 | H14 (the May 2026 watcher, before it fires) | the wipe itself |

## Stage 1: install-time execution

**What the worm does.** A republished package's install script runs the payload: `postinstall` in September 2025
([StepSecurity](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)), a `preinstall` Bun
loader in November 2025 ([Socket](https://socket.dev/blog/shai-hulud-strikes-again-v2), [Unit
42](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)), `preinstall: node setup.mjs` in 2026, and in May
2026 an optional git dependency whose `prepare` runs at install
([Picus](https://www.picussecurity.com/resource/blog/mini-shai-hulud-the-npm-supply-chain-worm-explained),
[JFrog](https://research.jfrog.com/post/shai-hulud-is-back-august/)).

**Prevents.**

- *Scripts off* (H01, H03, H06; `npm ci --ignore-scripts` in CI) stops a registry package's install scripts on npm 11
  and newer, but not a git dependency's `prepare` on npm 10 (every Node 22 release) or pnpm 10.0 to 10.25 (H03 fails
  them), nor Yarn 4's `prepack` once the repository is approved
  ([evidence](evidence/package-managers.md#git-dependencies-at-install)).
- *Soak* fails a locked version younger than the soak, 7 days by default (WS-SK-001), or unverifiable (WS-SK-002). A
  git, tarball or other-registry entry has no publish time, so it fails closed (high) on any npm, when the install
  waits on the gate and the entry is not baselined.
- *Known bad versions:* OSV records in `soak` (WS-OS-001), the IOC list in `scan` and `diff` (WS-LK-001;
  [iocs.md](iocs.md)).

**Detects.** Install scripts, their patterns and IOC payloads on disk (`scan`, H11), new or changed install scripts
and off-registry entries (`diff`, `soak`), and loaders in CI logs and on endpoints ([summary](#summary-the-kill-chain)).

**Misses.** Git dependencies in `scan` and `diff`, which report them only as WS-LK-002 (medium) and pass the Mini
Shai-Hulud replay; the recommended gate fails it through `soak` ([replays](validation.md#3-wave-replays)). New payload
names (`setup.mjs` is listed by hash only). Code a script loads. Code run without an install script.

## Stage 2: secret harvesting

**What the worm does.** Searches the host for tokens and cloud credentials, runs TruffleHog
([Socket](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)), and reads CI
secrets through injected workflows (stage 4).

- **Prevents (reduces what can be taken).** H08 (plaintext tokens), H09 (admin or write-to-org `gh` scopes), H10
  (credential files). In CI, `scan` reports `toJSON(secrets)` (WS-GH-002) and privileged workflows that check out pull
  request code (WS-GH-003).
- **Detects.** WS-LC-002; after the fact, WS-CI-002, WS-CI-005, and WS-EP-001 (TruffleHog started by node, bun or an
  install's shell).
- **Misses.** Whatever a running payload reads (wormsign has no runtime component); fine-grained and App tokens, which
  report no scopes; cloud metadata, browser stores and SSH keys.

## Stage 3: exfiltration

**What the worm does.** Sends data to a webhook
([Socket](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)) and creates public
repositories of stolen secrets described "Sha1-Hulud: The Second Coming."
([Datadog](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)) or "Shai-Hulud: Here We Go Again"
([JFrog](https://research.jfrog.com/post/shai-hulud-is-back-august/)).

- **Prevents.** Nothing: wormsign does not filter egress.
- **Detects.** Exfiltration endpoints in code, and workflows that dump or send secrets (`scan`); repositories matching
  IOC patterns (`audit-org`, WS-AL-003).
- **Misses.** Run-time exfiltration. WS-GH-005 fires on none of the replayed worm workflows (WS-GH-002 does).
  Personal-account repositories; a new description string.

## Stage 4: persistence

**What the worm does.** Pushes workflows that send secrets out
([StepSecurity](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)), run on
discussions on self-hosted runners ([Wiz](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)), or sit
on a branch deleted after the run ([JFrog](https://research.jfrog.com/post/shai-hulud-is-back-august/)); registers the
machine as a runner named `SHA1HULUD` (Wiz); and in August 2026 commits a `.vscode/tasks.json` task that runs when the
folder opens and a `.claude/settings.json` session-start hook (JFrog;
[Picus](https://www.picussecurity.com/resource/blog/mini-shai-hulud-the-npm-supply-chain-worm-explained) for 2026-04).

**Prevents.** Nothing on its own. What stops a workflow change in a pull request is the code-owner review of
`.github/` that branch protection requires ([github-action.md](github-action.md#what-the-gate-does-not-stop)).

**Detects.** `diff`: every added or changed workflow or local action (WS-DF-003), at medium, below the default
`fail-on: high`, so for that review to read. `scan`: IOC workflow and runner names, secrets dumps, self-hosted
runners, discussion-triggered shell workflows, auto-run VS Code tasks (WS-PS-001) and Claude Code hooks and MCP
servers (WS-PS-002), the last two high whatever the command and checked by `diff` too. `audit-org`: worm workflows,
branches and runners. The detections: new runners, runs and jobs on a worm branch, quickly deleted first runs, and
node running a `.claude/setup.mjs` or `.vscode/setup.mjs` loader (WS-EP-002).

**Misses.**

- `diff` skips the payload-file and endpoint checks; the Action's default pull-request gate also runs `scan`.
- A runner registered on a host (listing runners needs admin rights), and branches deleted after the run (2025-11,
  2026-08), which `audit-org` finds only when a run was interrupted.
- A push with a stolen token skips `diff`; `scan` on push sees it only on a branch the wormsign workflow runs on.
- Renamed files defeat WS-GH-001 and WS-GH-006; `codeql_analysis.yml` is a medium IOC, so the August 2026 workflow
  fails the gate only through its `toJSON(secrets)` dump ([replay](../test/fixtures/replay/2026-08/README.md)).
- Persistence outside repositories, and changes to what a baselined task or hook runs through a script, a
  `${config:Name}` setting or settings outside the repository.

## Stage 5: propagation through republishing

**What the worm does.** Republishes each package the stolen npm token can write, "up to 100 of its packages" in
November 2025 ([Datadog](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)).

- **Prevents.** For consumers, the soak gate and OSV ([why 7 days](soak.md#why-7-days-and-when-72-hours-is-enough));
  for maintainers, H08 and [maintainer-hardening.md](maintainer-hardening.md).
- **Detects.** `soak`'s registry signals: an install script added or changed (WS-RG-001), provenance dropped
  (WS-RG-002), a token publish by an account new to the last five versions (WS-RG-003); IOC versions (WS-LK-001).
- **Misses.** A publish through your trusted release workflow; a first version; versions older than 14 days on a full
  run. The signals' false-positive rate is unmeasured. Nothing watches *your* packages.

## Stage 6: private repositories made public

**What the worm does.** Publishes the victim's private repositories
([Wiz](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack);
MITRE ATT&CK [S9008](https://attack.mitre.org/software/S9008/)).

- **Prevents.** Nothing; GitHub can restrict visibility changes to owners
  ([GitHub docs](https://docs.github.com/en/organizations/managing-organization-settings/restricting-repository-visibility-changes-in-your-organization)).
- **Detects.** `audit-org` reads `repo.access` events: each flip to public is WS-OR-002 (medium), 3 or more within 60
  minutes WS-OR-002 (high). WS-AL-001 counts repositories per actor in that window.
- **Misses.** Without GitHub Enterprise Cloud and an owner token, the audit log is unreadable and `audit-org`
  reports WS-OR-900 (info, below the default `--fail-on high`; [cli/audit-org.md](cli/audit-org.md)). Personal
  accounts. Detection comes after the code is public.

## Stage 7: destructive fallback

**What the worm does.** In November 2025, with no usable GitHub or npm credentials, it "attempts to destroy all files
in the user's home folder" ([Datadog](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)). Only
stopping stage 1 prevents it, and backups, the control, are out of scope. In May 2026 a watcher wipes the home
folder when its token is revoked: H14 finds that watcher before it fires, and the
[incident-response guide](incident-response.md) isolates the machine before any token is revoked. Nothing detects
the wipe itself.

## PyPI

Only `soak` reads what Python locks pin ([soak.md](soak.md#python-pypi-locks)), and the registry signals are npm-only.
The incidents: [evidence/pypi-incidents.md](evidence/pypi-incidents.md).

**What this means for the gate.**

- **The payload runs at import or at interpreter start (a `.pth` file), from a wheel.** Every 2024-2026 compromise
  did, none from `setup.py`. Refusing source builds does not stop it, and there is no install-scripts switch; not
  installing the version does: the soak gate and OSV.
- **Timing.** Every compromise with a known timeline was removed within about 12.5 hours of upload, and PyPI's 2025
  maximum, from the report, was 4 days. **The 7-day default is not derived from PyPI evidence**: it is npm's. The
  PyPI cases are consistent with it, but they are a handful of incidents, not a study.
- **OSV.** litellm, telnyx, num2words, mistralai, guardrails-ai and lightning have `MAL-` records, so WS-OS-001
  reports them once the records exist. The Ultralytics releases have only `PYSEC-2024-154`: after its soak, an
  Ultralytics-style compromise passes `soak` ([records](evidence/pypi-incidents.md#osv-records)).

| | Prevents | Detects | Misses |
|---|---|---|---|
| PyPI, through `soak` | a locked file younger than the soak (WS-SK-001); a locked file the index no longer has, never had, or of another project or version (WS-SK-002); git, URL and other-index sources (WS-SK-002) | OSV `MAL-` and CWE-506 records (WS-OS-001); builds whose requirements no lock pins (WS-SK-005) | a resolving install ([installing the project itself](soak.md#installing-the-project-itself)); an old compromise with no OSV record (Ultralytics); the rest of [Python limitations](soak.md#python-limitations) |

## Out of scope

- **Payloads that run on import**, and malware without install scripts; the soak gate and OSV still apply.
- **Stealthy single-package compromises.** A version with no IOC entry, OSV record or heuristic match, older than the
  soak, passes every check; the soak evidence comes from loud, self-propagating waves.
- **A compromised wormsign or CI around it.** Mitigations, not guarantees: release tags are rebuilt and compared byte
  for byte (`scripts/ci-verify-release.sh`), the Action is pinned by SHA, and the gate is built from the base commit
  ([SECURITY.md](../SECURITY.md)).
- **A compromised registry or OSV**, trusted as served.
- **Third-party Actions**, typosquats and dependency confusion: no pin, name-similarity or private-name check.
- **Installs that bypass the lock files** wormsign reads: tox, nox and hatch environments, pre-commit hooks and their
  `additional_dependencies`, conda's `environment.yml`, installs in a Dockerfile or Makefile, `requirements.in` and
  other files it does not read, and `npx` or `pip install` in `package.json` scripts
  ([partial list](soak.md#which-installs-the-gate-covers)).
- **Other ecosystems** (crates, container images, VS Code and browser extensions). PyPI is partial ([PyPI](#pypi)).
- **Bun lockfiles**: not parsed; `soak` fails closed (WS-SK-002), `diff` reports a change as unchecked (WS-DF-006).
- **Windows workstations**; **runtime monitoring** (no agent, egress filter or EDR).
- **Response**: [incident-response.md](incident-response.md); wormsign does not do it.
