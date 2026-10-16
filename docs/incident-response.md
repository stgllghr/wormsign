# Incident response

What to do when anything points to a Shai-Hulud-style compromise on a machine, in CI or in your GitHub organization.
Follow the numbered steps in order: above all, [isolate the machine](#1-isolate-the-machine-before-revoking-anything)
before revoking any token. If you have a security team or incident response provider, call them first and use this
page as a checklist.

wormsign cannot tell whether malicious code ran, what it took, or whether the attacker is still there.

## What counts as an indicator

These findings mean a compromise until shown otherwise:

| Source | Finding | Meaning |
|---|---|---|
| `scan`, `diff` | WS-LK-001 | A lockfile, or an installed package (`--node-modules`), pins a version a vendor lists as compromised. |
| `scan` | WS-FS-001 | A file's SHA-256 equals a published payload sample's. |
| `scan`, `diff` | WS-LC-003 | A lifecycle script runs a file with a published payload name (not `setup.mjs` or `math_init.js`, which are hash IOCs only: [iocs.md](iocs.md#what-is-not-covered)). |
| `scan`, `diff` | WS-GH-001, WS-GH-006 | A workflow file or runner name the worms use. |
| `scan` | WS-EX-002 | A published exfiltration endpoint in code. |
| `soak` | WS-OS-001 | OSV has a malicious-package record for a locked version. |
| `audit-org` | WS-OR-001, WS-OR-004, WS-OR-003 at critical | A repository, workflow, branch or runner matching an indicator. |
| `harden-dev.sh` | H11 FAIL on a hash | A payload file on disk. |

Others (WS-FS-002, H11 on a name, WS-LC-002, WS-PS-001, WS-PS-002, WS-EX-001, WS-OR-002, WS-OR-003 at low) are
prompts to look, not verdicts: read the file or event first ([rules.md](rules.md)).

## 0. Decide whether code ran

The payloads run at install time, from a `preinstall` or `postinstall` script
([StepSecurity, 2025-09](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised);
[JFrog, 2026-08](https://research.jfrog.com/post/shai-hulud-is-back-august/)), so a lockfile entry is not an
infection. Ask:

- Did any machine or CI job install from that lockfile without `--ignore-scripts`? Check CI logs and when the lockfile
  held the version (`git log -p -- package-lock.json`). For a git dependency, also count installs on npm 10 even with
  `--ignore-scripts`, on pnpm 10.0 to 10.25 under its default blocking, and on Yarn 4 once the repository is approved
  (verified on 4.18.1): they run its scripts ([threat model](threat-model.md#stage-1-install-time-execution)).
- Was it installed globally, or by a tool that installs on its own (`npx`, an editor extension)?
- Is it in any `node_modules`? `wormsign scan --node-modules` reports installed IOC versions and install scripts.

If no install ran, fix the lockfile and stop; if you cannot rule one out, assume it ran. The 2026-08 wave also
commits a `.vscode/tasks.json` task and a `.claude/settings.json` `SessionStart` hook that start the payload with no
install ([JFrog](https://research.jfrog.com/post/shai-hulud-is-back-august/)), so opening such a checkout in VS Code
or Claude Code may have run it (WS-PS-001, WS-PS-002; [architecture.md](architecture.md#diff-base-head)).

## 1. Isolate the machine before revoking anything

1. **Disconnect the machine or runner from the network** (unplug it, turn off Wi-Fi, or quarantine it with your EDR
   or network controls). Do not shut it down if you want memory evidence, and do not sign out of anything from it.
2. **Image it, or at least copy what [step 2](#2-preserve-evidence) lists**, before changing anything or revoking an
   npm token: the payload makes npm tokens whose description threatens a wipe on revocation
   ([StepSecurity, 2026-05-11](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem)).
3. **Look for the persistence the reports name.** The May 2026 Mini Shai-Hulud payload installs a `gh-token-monitor`
   daemon that polls GitHub every 60 seconds with the stolen token and runs `rm -rf ~/` when it is revoked; remove it
   "before revoking GitHub tokens, to avoid the wiper"
   ([Wiz, 2026-05-12](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)).
   Wiz and [JFrog](https://research.jfrog.com/post/shai-hulud-is-back-august/) report that it stops after 24 hours;
   do not count on that. JFrog assessed the 2026-08 payload's installer for it as a development or fallback
   capability. Wiz gives these paths for the token monitor:

   ```console
   $ ls -l ~/Library/LaunchAgents/com.user.gh-token-monitor.plist ~/.config/systemd/user/gh-token-monitor.service
   ls: ~/.config/systemd/user/gh-token-monitor.service: No such file or directory
   ls: ~/Library/LaunchAgents/com.user.gh-token-monitor.plist: No such file or directory
   ```

   (A clean macOS machine.) If either exists, stop the service before revoking any token: on macOS
   `launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.user.gh-token-monitor.plist`, on Linux
   `systemctl --user disable --now gh-token-monitor.service` (check both against your OS documentation).
   `harden-dev.sh` H14 checks these paths first, plus the `~/.local/bin/gh-token-monitor.sh` script and
   `~/.config/gh-token-monitor` directory StepSecurity names, and never removes them; `scan` does not.
4. **Self-hosted runners:** take the runner offline and out of its runner group, and rebuild "the host or CI runner
   from a clean image" ([JFrog](https://research.jfrog.com/post/shai-hulud-is-back-august/)).

GitHub-hosted runners are discarded after each job, but what the job could read is exposed: go to steps 2 and 3.

## 2. Preserve evidence

Save these before cleaning anything ([JFrog](https://research.jfrog.com/post/shai-hulud-is-back-august/)). Delete
nothing yet.

- **The project as it was:** the lockfile, `package.json`, the suspect packages in `node_modules`, and a wormsign
  report written outside the project:

  ```console
  $ mkdir -p ~/wormsign-evidence
  $ wormsign scan . --node-modules --no-baseline --format json --output ~/wormsign-evidence/wormsign-scan.json
  $ echo $?
  1
  ```

  Exit 1 means findings at or above `high`. Skip the baseline (it may be changed too), write outside the tree (a
  compromised tree decides what is at any path inside it), and copy the report off the machine.
- **Payload files** found by `scan` or `harden-dev.sh` (H11), with their hashes, quarantined and never run. `--path`
  adds directories to `harden-dev.sh`'s search:

  ```console
  $ ./harden-dev.sh --offline --path /path/to/suspect/dir
  ...
  [FAIL] H11  /path/to/suspect/dir/setup_bun.js has a worm payload file name (high; not a known sample's hash). Inspect it by hand; do not run it.
  ```

- **npm's logs** (`~/.npm/_logs/`), shell history, running processes and network connections.
- **CI logs and artifacts** of every run that installed the affected version: kept 90 days by default, and anyone
  with write access can delete them
  ([GitHub docs](https://docs.github.com/en/organizations/managing-organization-settings/configuring-the-retention-period-for-github-actions-artifacts-and-logs-in-your-organization)).
- **The organization audit log** (180 days): export it now
  ([GitHub docs](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization)).
- **Exfiltration repositories** ("Sha1-Hulud: The Second Coming."
  [Datadog](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)): record their names and contents,
  then make them private (step 6). Treat what was public as read.

## 3. Rotate credentials from a clean device

Use a machine that never installed the affected packages, and only after step 1. Assume everything the affected
machine or job could read is stolen ([Datadog](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)).
Rotate npm tokens first, "starting with tokens that have `bypass_2fa` and write permission", then GitHub tokens, then
"everything else present on the host or runner" ([JFrog](https://research.jfrog.com/post/shai-hulud-is-back-august/)).

- **npm:** revoke every token and session ([docs](https://docs.npmjs.com/revoking-access-tokens/), or
  `npm token list` and `npm token revoke <id>`), including tokens you did not create. Check the account's email, 2FA
  and recovery codes, and that no unknown maintainer was added
  ([npm owner](https://docs.npmjs.com/cli/v11/commands/npm-owner/)). Move CI publishing to trusted publishing
  ([maintainer-hardening.md](maintainer-hardening.md)).
- **GitHub:** revoke personal access tokens, `gh` CLI tokens, OAuth and App authorizations, and SSH keys the machine
  held ([tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens),
  [SSH keys](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/reviewing-your-ssh-keys),
  [apps](https://docs.github.com/en/apps/using-github-apps/reviewing-and-revoking-authorization-of-github-apps)). The
  [credential revocation API](https://docs.github.com/en/rest/credentials/revoke) revokes a publicly leaked token you
  do not own; it is a revocation too, so only after step 1 everywhere the token was. Review your
  [security log](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/reviewing-your-security-log),
  and rotate every Actions secret an affected workflow could read: a `toJSON(secrets)` dump exposes all of them.
- **Cloud:** AWS access keys and role sessions
  ([keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/id-credentials-access-keys-update.html),
  [sessions](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)); Google Cloud
  service account keys and `gcloud` credentials ([keys](https://docs.cloud.google.com/iam/docs/keys-create-delete),
  [`gcloud auth revoke`](https://docs.cloud.google.com/sdk/gcloud/reference/auth/revoke)); Azure sessions and service
  principal credentials ([revoke](https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access),
  [`az ad sp credential`](https://learn.microsoft.com/en-us/cli/azure/ad/sp/credential?view=azure-cli-latest)).
- **Everything else:** `.env` files, database passwords, API keys, `~/.netrc`, Docker logins, Kubernetes configs;
  `harden-dev.sh`'s H08 and H10 are a start, not an inventory.

## 4. Audit the organization

Stolen tokens create repositories, flip visibility, push workflows and branches and register runners (sources in
[`repos.json`](../data/iocs/repos.json) and [`workflows.json`](../data/iocs/workflows.json)). Look in every
organization and personal account they could reach.

**`wormsign audit-org <org>`** checks repositories, the audit log, runners, workflow names and worm branches
([cli/audit-org.md](cli/audit-org.md)). Create its token **after** step 3, on the clean device; without one it says
what the token needs:

```console
$ wormsign audit-org example-org
wormsign: set GITHUB_TOKEN or GH_TOKEN. Fine-grained token, read-only: repository Metadata, Contents and Administration; organization Self-hosted runners and Administration (audit log). Classic token: repo, admin:org (runners; a write-capable scope) and read:audit_log. Runner listings also need admin rights on the organization and the repositories.
$ echo $?
2
```


**By hand, in the GitHub UI or the exported audit log:**

- `repo.create` and `repo.access` events from the affected accounts; new runners, especially `SHA1HULUD`
  ([Unit 42](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)); workflow files added on any branch,
  after `git fetch --all`:

  ```console
  $ git log --all --diff-filter=A --format='%h %ad %an' --date=short --name-only -- .github/workflows/
  ```

  For the 2026-08 wave, also the commit message `chore: update config` and workflows that created and quickly deleted
  `codeql_analysis.yml` ([JFrog](https://research.jfrog.com/post/shai-hulud-is-back-august/)).
- Branches named in the IOC data (no output means none; the 2025-11 and 2026-08 payloads delete theirs, so that is
  not proof of absence):

  ```console
  $ git ls-remote --heads origin shai-hulud 'add-linter-workflow-*' dependabot/github_actions/format/setup-formatter
  ```

- `wormsign scan --no-baseline` on each default and recently pushed branch (a branch can carry a baseline that
  ignores `.github`); `wormsign diff <default branch> <branch>` shows what a branch adds. To keep watching, load the
  [detections](../detections/README.md) into your SIEM.

## 5. Check your published packages

If a token with publish rights was exposed, assume every package it could write was republished. The 2026-08 payload
adds a `preinstall` of `node setup.mjs` and bumps the patch version
([JFrog](https://research.jfrog.com/post/shai-hulud-is-back-august/)); `scan` reports that only as WS-LC-001 (medium)
unless the file's hash matches, so read the scripts yourself ([maintainer-hardening.md](maintainer-hardening.md)).

- Compare each package's publish times with your own releases:

  ```console
  $ npm view is-number time --json
  {
    ...
    "6.0.0": "2018-03-31T17:02:39.953Z",
    "7.0.0": "2018-07-04T15:08:58.238Z"
  }
  ```

- Read the scripts and publisher of any version you did not publish. One you did looks like this:

  ```console
  $ npm view is-number@7.0.0 scripts _npmUser.name
  scripts = { test: 'mocha' }
  _npmUser.name = 'jonschlinkert'
  ```

  An added `preinstall`, or a publisher that is not your release account, is the pattern (`soak` reports the same
  for packages you consume: WS-RG-001 to WS-RG-003).
- Report each malicious version with **Report malware** on its npmjs.com page
  ([npm docs](https://docs.npmjs.com/reporting-malware-in-an-npm-package/)). Unpublish within 72 hours if nothing
  public depends on it ([policy](https://docs.npmjs.com/policies/unpublish/)); a `name@version` is never reusable, so
  publish a clean, higher version and deprecate what you cannot unpublish
  ([npm deprecate](https://docs.npmjs.com/cli/v11/commands/npm-deprecate/)).

## 6. Clean up

Only after steps 1 to 3.

- **Machines and runners:** rebuild from a clean image; in place, at least remove the step 1 persistence, clear
  package-manager caches and reinstall with `npm ci --ignore-scripts` from a fixed lockfile.
- **Repositories:** delete injected workflows (`shai-hulud-workflow.yml`, `shai-hulud.yaml`, `discussion.yaml`,
  `formatter_123456789.yml`, `codeql_analysis.yml` if you did not add it), worm branches, and `.vscode/tasks.json`
  tasks and `.claude/` hooks you did not write. Review recent commits by the affected accounts.
- **Exfiltration repositories:** after step 2, make them private or delete them.
- **Visibility flips:** make the repositories private again
  ([visibility](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility))
  and rotate any secret that was in them.
- **Runners:** remove unknown ones
  ([docs](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/remove-runners)) and rebuild
  their hosts.
- **Next time:** [hardening.md](hardening.md), the [Action](github-action.md) on pull requests, and
  [maintainer-hardening.md](maintainer-hardening.md).

## 7. Involve others

- **npm:** **Report malware** (step 5), and npm support for the rest. **GitHub Support**, if you cannot regain an
  account or organization.
- **Your users:** which versions, the window and what to do; a repository security advisory reaches them.
- **Customers and regulators**, if stolen credentials reached customer data.

## Limits of this page

It draws on public vendor reports of the 2025-09, 2025-11, 2026-04/05 and 2026-08 waves. This project has not run the
malware, and a new variant can differ: read the current advisories. Commands that need an npm account, a GitHub
organization or a cloud account come from the linked vendor documentation and were not run by this project.