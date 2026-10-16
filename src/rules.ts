import type { RuleInfo } from "./types.js";

export const RULES: RuleInfo[] = [
  {
    id: "WS-LC-001",
    name: "install-lifecycle-script",
    description:
      "package.json defines a preinstall/install/postinstall script, which runs automatically when the package " +
      "is installed. Also reported for a .gyp file beside a package.json when a package manager runs node-gyp " +
      "rebuild on it at install, and gyp runs the shell commands in <!(...) expansions: npm for any .gyp file " +
      "with no install or preinstall script and gypfile not false, pnpm for binding.gyp with no install or " +
      "preinstall script, and Yarn 1 for binding.gyp with no install script. pnpm and Yarn 1 ignore gypfile, " +
      "and an empty script counts as none.",
    help:
      "Confirm the script is needed and review exactly what it runs. Installing with --ignore-scripts (or " +
      "ignore-scripts=true in .npmrc) stops lifecycle scripts from running.",
  },
  {
    id: "WS-LC-002",
    name: "suspicious-lifecycle-script",
    description:
      "A lifecycle script matches a download-and-execute, encoded-payload, or credential-harvesting pattern.",
    help:
      "Treat this as a likely compromise until reviewed: read the whole script, do not install this tree, and " +
      "compare the package with its last known-good version.",
  },
  {
    id: "WS-LC-003",
    name: "ioc-lifecycle-script",
    description: "A lifecycle script references a payload filename from the sourced IOC list.",
    help:
      "Treat this as a compromise: do not install, remove or replace the package, and rotate the credentials " +
      "(npm, GitHub, cloud) on every machine that ran the install.",
  },
  {
    id: "WS-LC-004",
    name: "package-manager-runs-repo-code",
    description:
      "The repository holds code a package manager runs without any lifecycle script: a .pnpmfile.cjs or " +
      ".pnpmfile.mjs (pnpm runs its hooks on install), .env.yarn (Yarn 4 loads it into every script), a file " +
      "under .yarn/releases or .yarn/plugins, a Plug'n'Play loader (.pnp.cjs, .pnp.loader.mjs), or a file that " +
      "config names as code to run. Also reported for that config: .yarnrc.yml yarnPath, plugins or " +
      "injectEnvironmentFiles; .yarnrc yarn-path; pnpm-workspace.yaml pnpmfile or globalPnpmfile; .npmrc " +
      "node-options (unless it only sets a memory or stack limit or what Node.js prints), script-shell, " +
      "pnpmfile or global-pnpmfile.",
    help:
      "Read the code, or what the setting runs, before running any package-manager command in this directory: a " +
      "yarnPath release runs on every yarn command, before any install. If it is the project's own reviewed " +
      "code (a committed Yarn release, a pnpmfile), baseline the finding: its fingerprint holds a hash of the " +
      "file's content or of the settings' values, so a later change is reported again. wormsign diff reports " +
      "any change to these files as WS-DF-005.",
  },
  {
    id: "WS-LK-001",
    name: "ioc-package-version",
    description: "A lockfile pins a package@version listed as compromised in the sourced IOC list.",
    help:
      "Move to a version that is not on the IOC list, regenerate the lockfile, and rotate the credentials on " +
      "every machine and CI runner that installed the compromised version.",
  },
  {
    id: "WS-LK-002",
    name: "non-registry-resolution",
    description: "A lockfile entry resolves from somewhere other than an allowed npm registry host.",
    help:
      "Check that this source is expected. If the package should come from the registry, reinstall it from " +
      "there; if the host is a trusted private registry, allow it with --registry-host.",
  },
  {
    id: "WS-LK-003",
    name: "missing-integrity",
    description:
      "A registry-resolved lockfile entry has no integrity hash, so tampering with the tarball would go " +
      "unnoticed.",
    help:
      "Regenerate the lockfile with a current package manager so that every registry entry records an integrity " +
      "hash.",
  },
  {
    id: "WS-GH-001",
    name: "ioc-workflow-file",
    description: "A workflow file has a name from the sourced IOC list.",
    help:
      "Delete the workflow, treat the repository as compromised, and rotate every secret the workflow could " +
      "read.",
  },
  {
    id: "WS-GH-002",
    name: "secrets-dump",
    description:
      "A workflow expression reads the whole secrets context: toJSON(secrets), the object filter secrets.* (as " +
      "in toJSON(secrets.*) or join(secrets.*, ' ')), secrets passed to any function such as format, or a " +
      "secrets[...] index computed at run time; in short, any use of secrets other than secrets.NAME or " +
      "secrets['NAME']. Context and function names match in any case, as GitHub reads them.",
    help:
      "Pass each step only the secrets it needs, as individual environment variables (secrets.NAME). " +
      "toJSON(secrets), secrets.* and a computed secrets[...] index hand every secret available to the workflow " +
      "to that step.",
  },
  {
    id: "WS-GH-003",
    name: "pull-request-target-head-checkout",
    description:
      "A pull_request_target or workflow_run workflow checks out code from the pull request: its head ref in a ref: " +
      "value or a git fetch or checkout, written out or through an env: variable bound to it, or a ref: computed " +
      "from the github context (toJSON, fromJSON or a computed index), which wormsign cannot resolve. Not followed, " +
      "so not reported: a head ref passed through a step output, a file or $GITHUB_ENV.",
    help:
      "Do not run pull request code in a pull_request_target or workflow_run workflow, which can read secrets " +
      "and get a write token. Use the pull_request trigger for untrusted code.",
  },
  {
    id: "WS-GH-004",
    name: "self-hosted-runner",
    description: "A workflow runs on a self-hosted runner.",
    help:
      "Use self-hosted runners only for trusted repositories, and prefer ephemeral runners so that a " +
      "compromised job cannot persist on the machine.",
  },
  {
    id: "WS-GH-005",
    name: "secret-to-file-or-network",
    description:
      "A workflow step passes a secret, directly or through an env: variable, to a command that writes a file " +
      "or uses the network. Not followed, so not reported: a secret the script assigns to a shell variable and " +
      "uses on a later line (T=\"${{ secrets.TOKEN }}\", then curl -d \"$T\"), or passes through a file, an " +
      "action input or a step output.",
    help:
      "Give the secret only to the tool that needs it, through an environment variable, and do not write it to " +
      "disk or send it to other hosts.",
  },
  {
    id: "WS-GH-006",
    name: "ioc-runner-name",
    description: "A workflow targets a runner name or label from the sourced IOC list.",
    help:
      "Take the runner and its host out of service, investigate the host as compromised, and rotate every " +
      "credential it could reach.",
  },
  {
    id: "WS-GH-007",
    name: "discussion-trigger-with-run",
    description:
      "A workflow is triggered by discussion events and runs shell commands (used as a remote-command backdoor " +
      "by a reported variant).",
    help:
      "Remove the discussion trigger or the run steps. Discussion events can come from users without write " +
      "access and should not drive shell commands.",
  },
  {
    id: "WS-FS-001",
    name: "ioc-payload-hash",
    description: "A file's SHA-256 matches a payload hash from the sourced IOC list.",
    help:
      "Treat this as a compromise: delete the file and rotate the credentials (npm, GitHub, cloud) on every " +
      "machine where it ran.",
  },
  {
    id: "WS-FS-002",
    name: "payload-filename",
    description: "A file has a name associated with worm payloads in the sourced IOC list.",
    help:
      "Inspect the file. A name match is weaker evidence than a hash match; if the file is not expected, treat " +
      "it as a compromise.",
  },
  {
    id: "WS-EX-001",
    name: "exfil-endpoint",
    description: "A file contains a hardcoded webhook, paste, or request-capture endpoint.",
    help:
      "Confirm that the endpoint is expected. Code that sends data to webhook, paste or request-capture " +
      "services is a common exfiltration channel.",
  },
  {
    id: "WS-EX-002",
    name: "ioc-exfil-endpoint",
    description: "A file contains an exfiltration endpoint from the sourced IOC list.",
    help: "Treat this as a compromise: remove the code and rotate every credential it could have read.",
  },
  {
    id: "WS-NM-001",
    name: "installed-package-install-script",
    description: "An installed package in node_modules declares an install-time script.",
    help:
      "Review the package's install script. Installing with --ignore-scripts stops install scripts from running.",
  },
  {
    id: "WS-DF-001",
    name: "new-dependency-install-script",
    description:
      "A pull request adds a dependency that runs install-time scripts, including a local package (a workspace " +
      "or file: directory) that an npm lockfile records with install scripts.",
    help:
      "Review the new dependency and its install script before merging. Install scripts run on every machine " +
      "and CI runner that installs the project. A reviewed one gets through today in one of two ways: the owner of " +
      "the required check overrides it for this pull request, or a pull request that baselines the finding lands " +
      "first, which itself fails WS-DF-005 and needs the same override. A narrower route, an opt-in code-owner approval of " +
      "the baseline change, is accepted but not yet built (docs/adr/0008-baseline-approval-route.md).",
  },
  {
    id: "WS-DF-002",
    name: "lifecycle-script-changed",
    description:
      "A pull request adds or changes a lifecycle script that an install runs, or a .gyp file beside a " +
      "package.json, for which npm, pnpm or Yarn 1 can run node-gyp rebuild. Also reported for an unchanged " +
      ".gyp file when the change adds the package.json beside it, or removes or empties its install script, " +
      "preinstall script or gypfile: false, so that npm, pnpm or Yarn 1 starts running node-gyp on it. pnpm and " +
      "Yarn 1 run binding.gyp even with gypfile: false, so a package.json added with gypfile: false is reported " +
      "too.",
    help: "Review the lifecycle script change before merging. It runs automatically on install.",
  },
  {
    id: "WS-DF-003",
    name: "workflow-changed",
    description: "A pull request adds or changes a GitHub Actions workflow.",
    help: "Review the workflow change before merging. Workflows on the default branch can read repository secrets.",
  },
  {
    id: "WS-DF-004",
    name: "dependency-install-script-added",
    description: "A pull request changes a dependency's version to one that now has install scripts.",
    help: "Review the new version's install script before merging and compare the version with the previous one.",
  },
  {
    id: "WS-DF-005",
    name: "install-policy-changed",
    description:
      "A pull request adds, changes or removes what controls installs or what wormsign reports: package-manager " +
      "config (.npmrc, .yarnrc, .yarnrc.yml, pnpm-workspace.yaml, .pnpmfile.cjs, bunfig.toml, pip.conf, pip.ini, " +
      "uv.toml, a pyproject.toml's [tool.uv] install settings), code that config runs, the build of a Python " +
      "project no uv.lock or pylock.toml lists (what decides its build requirements, which an install that builds " +
      "it resolves fresh: [build-system], setup.cfg, setup.py, hatch.toml, hook files), the packageManager field, the workspaces " +
      "field, a dependency spec that installs from a local path, or the wormsign baseline; or it removes a " +
      "lockfile (npm's, a Python lock, or a requirements file holding hashes), or strips a requirements file of " +
      "its hashes (one found by name, or by its --hash options as soak finds one: deps.txt, deps.lock.in).",
    help:
      "Review the change to the policy file itself. A change that weakens a release-age setting, re-enables " +
      "install scripts or adds a baseline entry can silence the other checks for this pull request.",
  },
  {
    id: "WS-DF-006",
    name: "changed-file-not-checked",
    description:
      "A pull request changes a manifest or lockfile that wormsign could not read or parse, or a bun lockfile, " +
      "which wormsign does not parse, so nothing in it was checked. Also reported on every run for a " +
      ".yarnrc.yml or pnpm-workspace.yaml with anything outside the YAML subset wormsign reads, since the code " +
      "it names could not be followed. A changed Python lockfile or requirements file, and any change to a " +
      "pyproject.toml, setup.py, setup.cfg or Pipfile, is reported at medium: diff does not check what they pin or " +
      "declare, and soak --base checks the locks.",
    help:
      "Fix the file so it parses, or review its changes by hand. The finding fails closed because the package " +
      "manager may still act on the file. For a Python lockfile, requirements file or manifest, run `wormsign soak " +
      "--base <base>` on the change, which checks what the locks pin.",
  },
  {
    id: "WS-SK-001",
    name: "package-too-new",
    description: "A locked package version was published less than the required soak time ago.",
    help:
      "Pin the previous version, or wait until this version has been published for the required soak time. In PR " +
      "mode (--base) an npm or Python entry the base's own soak read identically (the same lock file, name, " +
      "version and hashes) is not checked again, so a young version pushed directly to the base passes later pull " +
      "requests: the full soak on push and on a schedule catches it. A pin that lands first in a file the base's " +
      "soak never read as a lock is checked once a change makes it one.",
  },
  {
    id: "WS-SK-002",
    name: "soak-unverifiable",
    description:
      "The publish time or identity of a locked package version could not be verified; treated as failing (fail " +
      "closed). npm, pnpm, Yarn and bun: a missing, unreadable or unsupported lockfile, a git or off-registry " +
      "source, a private registry, a version not on the registry, an integrity that differs from the " +
      "registry's, or a registry error. PyPI: a lockfile soak does not read yet (poetry.lock, pdm.lock, " +
      "Pipfile.lock), a manifest or PEP 723 script that no lock covers, a requirements file that is not a " +
      "complete --require-hashes lock, a locked file without a sha256 or that is not a file of that project and " +
      "version on the index (deleted, quarantined or never published), a git, URL or other-index source, a " +
      "local source that is not in the reviewed tree, an install setting that may use another index or skip " +
      "hash checks, or an index error.",
    help:
      "Fix what the finding names (commit the lockfile, install from the registry, or make the registry " +
      "reachable with --registry or --pypi-index) and run the check again. For Python, lock with uv (uv lock), " +
      "or write a hash lock (uv pip compile --generate-hashes, with --require-hashes in the file), and install " +
      "with --locked, --frozen or --require-hashes. The gate fails closed when it cannot verify a package. Of the " +
      "requirements-file problems, a baseline can approve only a plain index requirement soak parsed to the end and " +
      "a local file it resolved to a regular file inside the repository; any other (an option, an include, a path " +
      "soak cannot pin, a line it could not read, a halt, the missing --require-hashes line) is never suppressed: " +
      "fix the line as its message says.",
  },
  {
    id: "WS-SK-003",
    name: "soak-config-missing",
    description:
      "No package-manager release-age setting enforcing the soak time was found in project configuration.",
    help:
      "Add the release-age setting the finding names for this package manager. Where none exists (Yarn " +
      "Classic), run `wormsign soak` in CI as the gate.",
  },
  {
    id: "WS-SK-004",
    name: "soak-config-too-short",
    description:
      "A package-manager release-age setting is shorter than required, cannot be interpreted, is ignored by the " +
      "package-manager version that will run (or that version is unknown), or is bypassed by an exclusion or " +
      "trust setting.",
    help:
      "Fix what the finding names: set the value to at least the required soak time, run a package-manager " +
      "version that enforces it, or remove the setting that bypasses it. For Yarn, write plain minutes: Yarn " +
      "4.10 reads a unit suffix as minutes (\"7d\" is 7 minutes), while 4.11 and later accept suffixes.",
  },
  {
    id: "WS-SK-005",
    name: "install-time-resolution",
    description:
      "A Python install builds a package from source, and the build's requirements are resolved when it runs, " +
      "outside every lockfile soak reads: a local project the install builds (a uv directory or editable " +
      "member, a pylock directory entry), a package locked only as an sdist, or uv configuration in the tree " +
      "that forces source builds (no-binary, no-build-isolation, extra-build-dependencies, config-settings). " +
      "soak never locks, binds or ages build requirements.",
    help:
      "Avoid the build where you can: `uv sync --locked --no-install-project` or `[tool.uv] package = false` " +
      "for a project that need not be installed, a version with wheels for the platforms you install on, no " +
      "build-forcing settings. Otherwise pin the build requirements with ==-pinned build constraints (uv " +
      "build-constraint-dependencies, pip --build-constraint) and keep the installer's release-age cutoff, " +
      "which is all that protects them. A reviewed local build can be baselined with a justification: its key " +
      "changes when its build requirements or build files do. In PR mode (--base) a build the change adds is " +
      "high, so the default --fail-on high stops it; one the base already had stays medium.",
  },
  {
    id: "WS-SK-006",
    name: "soak-outage-unverified",
    description:
      "Reported only with --on-outage warn: a locked package version was not checked because the npm registry or " +
      "the Python index was out for the whole run. Its request failed after soak's retry in transport before any " +
      "status line (a DNS or connection error, a TLS handshake that broke off, a timeout) or with HTTP 429 or a " +
      "5xx; the host gave no other answer in the run; and a HEAD probe of its root after the run got none either. " +
      "Its age, identity and OSV records are unverified. Without the option the same package is WS-SK-002, high, " +
      "and so it stays under the option when the host answered anything, including a host that went down mid-run, " +
      "and for every other problem: HTTP 404 or another 4xx, a redirect, a body that is slow, cut off or does not " +
      "parse, a certificate the client rejects, an integrity mismatch, a private registry or a name wormsign " +
      "cannot vouch for.",
    help:
      "The trade-off: under --on-outage warn an outage of the whole configured host no longer fails the gate at " +
      "the default --fail-on high, so whoever can make that host unreachable from the runner for the entire run " +
      "(an outage, a firewall rule, an attacker on the network path) can merge a change whose packages were never " +
      "checked, recorded only by this finding and the run's UNVERIFIED line. One name the registry will not serve " +
      "is not enough: it stays WS-SK-002. Choose the option only where a gate that teams switch off is the worse " +
      "risk, and run soak again once the host answers, before anything installs the change. A baseline never " +
      "suppresses this finding: an outage is transient, and an entry for it would waive the next one.",
  },
  {
    id: "WS-OR-001",
    name: "org-ioc-repo",
    description: "A repository name or description matches a worm indicator pattern.",
    help:
      "Inspect the repository. If it was created by the worm, preserve evidence, make it private or delete it, " +
      "and rotate the credentials it exposes.",
  },
  {
    id: "WS-OR-002",
    name: "org-visibility-flip",
    description: "Audit log shows a repository changed from private to public.",
    help:
      "Confirm that the change was intended. If not, make the repository private again and find out who made " +
      "the change.",
  },
  {
    id: "WS-OR-003",
    name: "org-runner",
    description: "A self-hosted runner registered on the organization or one of its repositories needs review.",
    help:
      "Confirm that the runner is expected and that only trusted repositories can use it. Remove a runner with " +
      "a worm IOC name and investigate its host.",
  },
  {
    id: "WS-OR-004",
    name: "org-ioc-workflow",
    description: "A repository contains a workflow file or branch whose name is in the sourced IOC list.",
    help:
      "Delete the workflow file or branch, treat the repository as compromised, and rotate every secret the " +
      "workflow could read.",
  },
  {
    id: "WS-OR-900",
    name: "org-audit-degraded",
    description:
      "Part of the organization audit could not run (GitHub plan or token scope, a rate limit, a GitHub or " +
      "network error, or an answer that is not the documented one); coverage is reduced.",
    help:
      "For a scope gap, run the audit again with a token that has the access named in the finding; for a rate " +
      "limit, a GitHub or network error or an unexpected answer, run it again later.",
  },
  {
    id: "WS-SC-900",
    name: "file-not-checked",
    description:
      "A file that decides what runs at install time or in CI (manifest, lockfile, workflow, or code or config " +
      "a package manager runs, see WS-LC-004) could not be checked: unreadable, too large, binary, invalid, a " +
      "symlink (to a file or package directory), or an unsupported format; a workflow in YAML the reader does " +
      "not model (flow or JSON form, flow jobs or steps, aliases, merge keys, the line breaks U+0085, U+2028 and " +
      "U+2029), or with a ${{ }} expression it cannot read (one outside a comment with no closing }} within 50 " +
      "lines, or one written in part with YAML escapes); two such " +
      "files whose paths differ only in case, Unicode form or trailing periods and spaces, of which a " +
      "case-insensitive disk or Windows holds only one; a code file that could not be searched for exfiltration " +
      "endpoints from the IOC list; or a workspaces pattern (package.json workspaces, pnpm-workspace.yaml " +
      "packages) that can match a package the scan does not read (under an ignored path, node_modules or .git, " +
      "or outside the repository).",
    help:
      "Make the file readable by wormsign or review it by hand. The finding is high by default because the " +
      "package manager or GitHub may still act on the file.",
  },
  {
    id: "WS-BL-001",
    name: "baseline-entry-expired",
    description: "A baseline entry's expiry date has passed, so the finding is no longer suppressed.",
    help: "Fix the finding, or review it again and renew the baseline entry with a new expiry date.",
  },
  // Registry signals.
  {
    id: "WS-RG-001",
    name: "registry-install-script-added",
    description:
      "A package version adds or changes a preinstall/install/postinstall script compared with the version it " +
      "replaces, according to the registry's copy of its manifest.",
    help:
      "Read the new script before installing this version, and keep the previous version until you have. A " +
      "reported worm adds a preinstall script to every package it republishes. False positives: a maintainer " +
      "adding a native addon or a binary download. Not seen: a node-gyp build from a binding.gyp in the " +
      "tarball, which the registry manifest does not show.",
  },
  {
    id: "WS-RG-002",
    name: "registry-provenance-dropped",
    description:
      "A package version was published without a provenance attestation, while the version it replaces had one.",
    help:
      "Find out how this version was published before installing it: npm creates provenance only in GitHub " +
      "Actions or GitLab CI, so a stolen token used anywhere else publishes without it. False positives: a " +
      "maintainer publishing by hand, or moving to a CI system that does not create provenance. Not seen: a " +
      "worm publishing from the package's own release workflow, which gets valid provenance, or from CI of its " +
      "own, whose provenance names another repository (check it with npm audit signatures and the attestation).",
  },
  {
    id: "WS-RG-003",
    name: "registry-new-publisher",
    description:
      "A package version was published, with a token or password, by an npm account that published none of the " +
      "five versions before it.",
    help:
      "Confirm with the project that this account is expected to publish. A worm publishes every package the " +
      "stolen token can write, including ones its owner rarely releases. False positives: a maintainer handover " +
      "or a new release manager. Publishes by a trusted publisher are not checked, since their provenance names " +
      "the workflow that made them.",
  },
  // OSV.
  {
    id: "WS-OS-001",
    name: "osv-malicious-package",
    description:
      "OSV has a malicious-package record for a locked package version: an OpenSSF malicious-packages record " +
      "(id MAL-...), into which GitHub advisories of type malware are merged, or a GitHub advisory (id " +
      "GHSA-...) whose CWE ids include CWE-506, embedded malicious code, which GitHub gives a hijacked release " +
      "such as ua-parser-js@0.7.29. Both kinds are reported in every ecosystem that soak checks, one finding " +
      "per record. Other records, such as ordinary vulnerabilities, are not reported.",
    help:
      "Treat this as a compromise: do not install this version, move the lockfile to a version without a " +
      "record, and rotate the credentials (package registry, GitHub, cloud) on every machine and CI runner that " +
      "installed it. The finding links to the record, which names the affected versions.",
  },
  {
    id: "WS-OS-900",
    name: "osv-not-checked",
    description:
      "Some locked package versions could not be checked against OSV (request failed, unexpected response, a " +
      "GitHub advisory whose record could not be read, more than 1000 versions with GitHub advisories to read " +
      "in one run, or not a registry name and version, such as a git dependency); treated as failing (fail " +
      "closed).",
    help:
      "Run the check again when api.osv.dev is reachable. When the message says more than 1000 versions had " +
      "GitHub advisories to read, the versions past that limit (in name and version order, compared as plain " +
      "strings, so 1.0.10 comes before 1.0.9) were not checked: run soak on fewer or smaller lockfiles, or run " +
      "it with --no-osv and check the lockfiles with another OSV client. A dependency that is not a registry " +
      "version cannot be looked up: review it by hand, and baseline the finding with a justification if it is " +
      "trusted.",
  },
  {
    id: "WS-OS-901",
    name: "osv-outage-unchecked",
    description:
      "Reported only with --on-outage warn: a locked package version was not checked against OSV for " +
      "malicious-package records because api.osv.dev was out for the whole run: its query batch failed after the " +
      "retry in transport before any status line or with HTTP 429 or a 5xx, OSV gave no other answer in the run, " +
      "and a HEAD probe of its root after the run got none either. One finding per version. Without the option " +
      "these versions are in WS-OS-900, high, and so they stay under the option when OSV answered anything, for a " +
      "record query that failed (it follows an answered batch), a redirect, HTTP 400 or another 4xx, an answer that " +
      "does not parse or has the wrong shape, and every other reason.",
    help:
      "The trade-off: under --on-outage warn an outage of api.osv.dev for the entire run no longer fails the gate " +
      "at the default --fail-on high, so a version with a malware record can merge while OSV is unreachable from the " +
      "runner, recorded only by this finding and the run's UNVERIFIED line. The soak time still applies. Run soak " +
      "again once api.osv.dev answers, before anything installs the change. A baseline never suppresses this " +
      "finding: an outage is transient, and an entry for it would waive the next one.",
  },
  // Editor and AI-agent persistence (the 2026-08 wave committed .vscode/tasks.json and .claude/settings.json; https://research.jfrog.com/post/shai-hulud-is-back-august/)
  {
    id: "WS-PS-001",
    name: "editor-auto-run-task",
    description:
      "A VS Code task runs automatically (runOptions.runOn folderOpen or worktreeCreated) from " +
      ".vscode/tasks.json, the tasks section of .vscode/settings.json, or a *.code-workspace file, so opening " +
      "the folder runs its command and those of the tasks it depends on; or a settings file sets what tasks run " +
      "with (a tasks section, or the terminal profile and environment settings tasks use). Always high, " +
      "whatever the command; the message adds reasons when the command matches the lifecycle-script heuristics " +
      "or an IOC file name.",
    help:
      "High whatever it runs: each automatic task in .vscode/tasks.json or a *.code-workspace file; each " +
      "top-level dotted key there (VS Code reads \"linux.tasks\" as nested task settings); and, in " +
      ".vscode/settings.json or a workspace's settings, one entry for any tasks section (nested or dotted " +
      "tasks.* keys) and one for the terminal settings tasks run with (terminal.integrated.automationProfile, " +
      "defaultProfile, profiles, env). Remove runOn unless needed, or review and baseline it. A task's " +
      "fingerprint covers it, the tasks its dependsOn reaches and its file's global settings (the whole file " +
      "for a dotted key or an unresolved or over-long dependsOn); a settings entry's covers all it lists. A " +
      "script a task runs (or an npm task's script), a setting it reads with ${config:...} and settings outside " +
      "the repository can change without a new finding. VS Code runs automatic tasks only in a trusted " +
      "workspace; while task.allowAutomaticTasks is unset it asks once per workspace, and Allow turns them on " +
      "for every trusted workspace.",
  },
  {
    id: "WS-PS-002",
    name: "agent-settings-command",
    description:
      "A Claude Code settings file, plugin file, skill/command/subagent frontmatter or project .mcp.json makes " +
      "Claude Code run something automatically: a hook of any event or type, a command setting such as " +
      "statusLine or apiKeyHelper, an env entry outside a few inert settings, or an MCP server that runs a " +
      "local command or a headersHelper. Always high, whatever the command; the message adds reasons when it " +
      "matches the lifecycle-script heuristics or an IOC file name.",
    help:
      "High whatever it runs: every settings-file hook, command setting such as statusLine, project MCP server " +
      "that runs a local command or a headersHelper, env entry other than a few inert model, limit and " +
      "telemetry settings, plugin or marketplace a settings file adds, plugin file under .claude/, and skill, " +
      "command or subagent file under .claude/ whose frontmatter mentions hooks or mcpServers or holds a " +
      "backslash (wormsign does not parse YAML, so a mere mention counts). A symlink under .claude/ is " +
      "WS-SC-900. Not reported: a skill's !`command` lines and allowed-tools, a plugin's other files, a plugin " +
      "outside .claude/. Review each entry and any script it runs, then baseline it: the fingerprint covers the " +
      "entry, so editing it reports it again, but the script can change unseen. claude -p and SDK sessions run " +
      "most of these at once, an interactive session once you trust the folder. To keep hooks from running in a " +
      "repository you have not reviewed, start Claude Code with --bare or --settings '{\"disableAllHooks\": " +
      "true}'.",
  },
];
