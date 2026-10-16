# Security policy

wormsign is a security tool, so a flaw in it can leave a project exposed while reporting that all is well.

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting:

1. Open the repository's **Security** tab: <https://github.com/stgllghr/wormsign/security>.
2. Click **Report a vulnerability**.
3. Describe the issue, the version or commit you tested, and the smallest input that shows it.

Please do not open a public issue, pull request or discussion for a vulnerability, and do not put exploit
details anywhere public until a fix is released. There is no security email address. If you cannot use
**Report a vulnerability**, open an issue with the "Request a private contact" template, put no details in it,
and the maintainer will reply with a private way to continue.

Use synthetic, inert test inputs, like those in `test/fixtures`; never attach live malware or real stolen
credentials.

## What counts as a vulnerability

- **A bypass of a detection or a gate.** Input that a rule is meant to catch but that wormsign does not report,
  or that a gate passes when it should fail. Examples: an IOC package version in a lockfile that is not reported;
  a pull request judged by its own changes to the baseline, package-manager config or the gate; a soak check that
  passes a package it could not verify; a baseline entry that suppresses more than the one finding it names.
- **IOC data integrity.** An entry in `data/iocs` whose source page does not support it, a way to make
  `wormsign update-iocs` load other data than it says, or IOC data that weakens a check (for example, an
  endpoint or pattern that suppresses unrelated findings).
- **Harmful behaviour on hostile input.** A repository, lockfile, workflow, `node_modules` tree, registry
  response or GitHub API response that makes wormsign run code from the scanned tree, use the network in
  `scan` or `diff`, write outside the file given to `--output`, expose a token, forge CI output (for
  example GitHub workflow commands in a report), hang, or exit 0 after failing to check something.
- The same classes of problem in `harden-dev.sh` (for example, a change it makes that is not backed up, or a
  setting it reports as PASS that the package manager does not enforce) or in the GitHub Action.

## What does not

- **Missing IOCs for a new worm wave.** Open a normal issue with the "New IOC" template and a public https
  source. Indicators are public by nature, so there is nothing to keep private.
- **False positives.** Use the "False positive" issue template.
- Known limitations in the documentation, such as heuristics a determined attacker can avoid, or an organization
  audit reduced by the GitHub plan or token scope (reported as WS-OR-900).
- Vulnerabilities in your own dependencies or workflows that wormsign reports correctly.

## Response

One maintainer, best effort: there is no response-time or fix-time commitment. You can expect an acknowledgement
when the report is read, a discussion of the fix in the private advisory, and credit in the advisory and
`CHANGELOG.md` unless you prefer not to be named.

## Supported versions

Only the latest release receives security fixes. Before the first release, that is the `main` branch.
