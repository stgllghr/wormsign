# `wormsign audit-org`

Audit a GitHub organization for traces a Shai-Hulud-style worm leaves outside any one repository: repositories it
created or made public, self-hosted runners it registered, and workflow files or branches it pushed. It sends only
`GET` requests to the GitHub REST API, with your token.

```text
wormsign audit-org <org> [--format human|json|sarif] [--output <file>] [--fail-on <severity|never>]
                         [--baseline <file>] [--iocs <dir>] [--since <YYYY-MM-DD>] [--max-repos <n>]
```

The token comes from `GITHUB_TOKEN`, else `GH_TOKEN`. `<org>` is an organization login (letters, digits and
hyphens), not a personal account.

## What it checks

| Step | API | Finding | When the API refuses |
|---|---|---|---|
| 1. Repositories (up to 5,000) | `GET /orgs/{org}/repos?type=all` | A name or description matching `data/iocs/repos.json`: [WS-OR-001](../rules.md#ws-or-001) | Exit 2, as for an empty list (what a token blind to private repositories can get). |
| 2. Audit log since `--since`, up to 2,000 events per query | `GET /orgs/{org}/audit-log` for `repo.access`, `repo.register_self_hosted_runner`, `org.register_self_hosted_runner` | Made public: medium [WS-OR-002](../rules.md#ws-or-002), plus one high for 3 or more within 60 minutes. Runner registrations: low [WS-OR-003](../rules.md#ws-or-003) | Info [WS-OR-900](../rules.md#ws-or-900). Enterprise Cloud only, for organization owners. |
| 3. Organization runners | `GET /orgs/{org}/actions/runners` | Every runner: low [WS-OR-003](../rules.md#ws-or-003), critical for an IOC name (`SHA1HULUD`) | Info WS-OR-900 |
| 4. Each non-archived repository, up to `--max-repos`, serially | `GET /repos/{owner}/{repo}/contents/.github/workflows` | An IOC workflow file name (`data/iocs/workflows.json`) on the default branch: [WS-OR-004](../rules.md#ws-or-004) | Info WS-OR-900 per check, with HTTP statuses and counts, for a scope refusal (401, 403, 404) |
| | `GET /repos/{owner}/{repo}/git/matching-refs/heads/<name>` per branch IOC (`shai-hulud`, `add-linter-workflow-*`, `dependabot/github_actions/format/setup-formatter`) | That branch name, or prefix for one ending in `*`: high [WS-OR-004](../rules.md#ws-or-004) | |
| | `GET /repos/{owner}/{repo}/actions/runners` | Every repository runner, as in step 3 | |


### An incomplete audit does not exit 0

The audit is *incomplete* when a rate limit stopped step 4, a step 4 check got an answer from no repository (no
Contents access anywhere, say), or a step 3 or 4 request failed for another reason than scope (a 5xx or no response
after one retry, or an unexpected answer: its own WS-OR-900, naming the repositories). Such a repository never counts
as checked, so one server error on the infected repository cannot pass as clean. The report ends with an
`audit incomplete: ...` note, and where it would have exited 0, `wormsign` exits 2:

```text
wormsign: audit incomplete: <reason>; see the WS-OR-900 findings
```

Scope refusals alone (no audit log, no organization-runner access, some repositories out of reach) are a reduced
audit: info WS-OR-900 findings, which pass `--fail-on high`, each naming the check that did not run and the access it
needs. A clean result for that check does not mean clean.

## Token

With no token set, `wormsign` prints the access it needs and exits 2.

| Check | Fine-grained token (read-only) | Classic token |
|---|---|---|
| Repository list | Metadata: read | `repo` (for private repositories) |
| Workflow listing, branch lookup | Contents: read | `repo` |
| Repository runners | Administration: read, and admin rights on the repository | `repo`, and admin rights |
| Organization runners | organization Self-hosted runners: read, and organization admin | `admin:org` (a write-capable scope) |
| Audit log | organization Administration: read, organization owner, Enterprise Cloud | `read:audit_log`, organization owner, Enterprise Cloud |

Prefer a fine-grained token: every permission above is read-only. Under SAML SSO, also authorize it for the
organization. Sources:
[repositories](https://docs.github.com/rest/repos/repos#list-organization-repositories),
[self-hosted runners](https://docs.github.com/rest/actions/self-hosted-runners),
[matching references](https://docs.github.com/rest/git/refs#list-matching-references),
[organization audit log](https://docs.github.com/enterprise-cloud@latest/rest/orgs/orgs#get-the-audit-log-for-an-organization).

## Options

`--format`, `--output`, `--fail-on`, `--baseline`, `--no-baseline` and `--iocs` work as for
[`scan`](scan.md#options), but a finding's `file` is `org/repo` or the organization, and the default baseline is the
current directory's, if any. Any other option is a usage error (exit 2), found before any request.

| Option | Meaning |
|---|---|
| `--since <YYYY-MM-DD>` | A real past date for the audit log, which keeps 180 days (default 30 days ago). |
| `--max-repos <n>` | Repositories given the step 4 checks (default 500); a whole number, at least 1. |

## Example output

The real command against the tests' simulated `api.github.com` (`fakeGitHub` in `test/validation-helpers.ts`), which
follows the documented REST shapes but was not recorded from the live API. One repository has the Shai-Hulud 2.0
description and a `SHA1HULUD` runner, another an `add-linter-workflow-*` branch; the audit log answers 404:

```console
$ wormsign audit-org example-org
CRITICAL WS-OR-001  example-org/a1b2c3d4e5f6g7h8i9
         Repository example-org/a1b2c3d4e5f6g7h8i9 (public) matches worm pattern sh2-description from the 2025-11 wave
         source: https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/
         fingerprint: e5654f9d9187652133b69273d8dffebd
...
INFO     WS-OR-900  -
         audit-log queries (repo.access, repo.register_self_hosted_runner, org.register_self_hosted_runner): skipped, HTTP 404. ...

wormsign audit-org: 5 finding(s) (2 critical, 1 high, 0 medium, 1 low, 1 info)
note: 3 repositories listed (2 private)
note: default-branch workflow file listing answered for 3 of 3 repositories (2 have a .github/workflows directory)
...
$ echo $?
1
```

With a token that has no Contents access, a clean organization's run ends with
`note: audit incomplete: no repository answered: default-branch workflow file listing, ...` and exits 2.

## Exit codes

`0`, `1` and `2` as in [output.md](../output.md#exit-codes): `2` includes no token, an unreadable or empty repository
list, and an incomplete audit.

## Network

`https://api.github.com` only, `GET` only, with the token as a bearer token, API version `2022-11-28` and a 30-second
timeout per request. A request is retried once after a 5xx, a 429 without the rate-limit headers, or a network error
or timeout; one that still fails is recorded and the run goes on. A path the URL parser would rewrite (a `..` segment
from a branch IOC, say) is refused, so the token never reaches another endpoint. Requests: a few listings, plus up to
(2 + number of branch IOCs) per repository in step 4, more across pages.

## Limitations

- **Without Enterprise Cloud there is no audit log**: no record of visibility flips or runner registrations.
- **Workflow files are checked on the default branch only**; other branches only for IOC branch names.
- **Name and description patterns match only the waves seen so far.**
- **Archived repositories, and those past `--max-repos`, get no per-repository checks.**
- **It audits one organization.** Shai-Hulud 2.0 created a repository and registered its runner in the victim's own
  account ([Socket](https://socket.dev/blog/shai-hulud-strikes-again-v2),
  [Datadog](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)); check a personal account by hand.
- **Runner listings need admin rights.** Without them, a worm runner registered on a repository goes unseen.
