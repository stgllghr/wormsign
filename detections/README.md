# Detections

**Status:** experimental ([maturity](../docs/stability.md#maturity)): no rule has run on real logs or in a SIEM
([what is not validated](#what-is-not-validated), [roadmap](../ROADMAP.md#next) item 4).

`wormsign scan` and `diff` stop a worm before it runs. These detections are for afterwards: if a Shai-Hulud-style
package did run, they spot it in GitHub's audit log, CI logs and endpoint process telemetry. They are data, not code:
load them into the SIEM or log pipeline you already use. When one fires, follow
[incident-response.md](../docs/incident-response.md); [threat-model.md](../docs/threat-model.md) maps them to the
worm's stages.

| ID | Data source | Fires on |
|----|-------------|----------|
| [WS-AL-001](github-audit-log/ws-al-001-mass-visibility-flip.yml) | GitHub audit log | 3+ repositories made public by one actor in 60 minutes (high); one made public with a token (medium) |
| [WS-AL-002](github-audit-log/ws-al-002-self-hosted-runner-registered.yml) | audit log | A runner named SHA1HULUD comes online or takes a job (critical); one registered by an identity off your allowlist (medium) |
| [WS-AL-003](github-audit-log/ws-al-003-ioc-repo-created.yml) | audit log + one REST call | A new public repository matching `data/iocs/repos.json` |
| [WS-AL-004](github-audit-log/ws-al-004-worm-workflow-run.yml) | audit log | A new workflow's first run deleted with a token within the hour; a workflow run or job on a worm branch (critical) |
| [WS-CI-001](ci/ws-ci-001-worm-loader-install-script.yml) | Install-step logs | A dependency's install script runs setup_bun.js, bun_environment.js or `node setup.mjs` |
| [WS-CI-002](ci/ws-ci-002-trufflehog-during-install.yml) | Install-step, process or egress logs | TruffleHog downloaded or run during an install |
| [WS-CI-003](ci/ws-ci-003-bun-bootstrap-during-install.yml) | Install-step, egress or DNS logs | Bun fetched from bun.sh or oven-sh/bun releases during an install |
| [WS-CI-004](ci/ws-ci-004-runner-registered-with-ioc-name.yml) | Process command lines, Actions jobs API | `config.sh --name SHA1HULUD` (quoted or not), or a job reporting `runner_name` SHA1HULUD |
| [WS-CI-005](ci/ws-ci-005-secrets-context-serialized.yml) | Actions job logs | A `"github_token": "***"` line: the whole secrets context serialized (high: an action taking it as an input prints it too) |
| [WS-EP-001](sigma/ws-ep-001-node-spawns-trufflehog-or-bun.yml) | Endpoint process creation | node starting TruffleHog or Bun, bun starting TruffleHog, Bun running a payload file or started by a shell, the shell-wrapped `trufflehog filesystem ... --json` scan; anything run from `~/.truffler-cache` |
| [WS-EP-002](sigma/ws-ep-002-node-runs-repository-hook-loader.yml) | Endpoint process creation | node running `.claude/setup.mjs` or `.vscode/setup.mjs` (the 2026-08 editor and agent hooks) |

These ids are separate from the scanner's rule ids, which describe findings in files.

## Formats

- **WS-AL-* and WS-EP-* are Sigma rules**, the audit-log ones with GitHub's own field names from its
  [organization](https://docs.github.com/en/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization)
  and [enterprise](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise)
  event references, except WS-AL-003's `enriched_description`, which your pipeline adds. WS-AL-001 and WS-AL-004
  hold [correlation rules](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md)
  (specification 2.1.0) and base rules that raise no alert of their own.
- **WS-CI-* use wormsign's own format**: `id`, `severity`, `attack`, `data_source`, a `pattern` (one regular
  expression per line, written to behave the same in JavaScript, Python `re` and `grep -E`), `iocs`,
  `false_positives`, `examples`, a `known_miss` block the pattern deliberately does not match, and a
  `known_false_positive` block of benign lines it does match.
- Each alerting rule has inert, synthetic `examples`, and each Sigma file has Splunk (`.spl`) and ES|QL (`.esql`)
  reference conversions from [tools/convert_rules.py](tools/convert_rules.py), post-processed as each file's header
  lists. Splunk correlations slide and keep one result per group. ES|QL cannot slide: it counts in 1-hour buckets and
  a set offset by 30 minutes, so it can miss a burst of 30 to 60 minutes and raises a row for each set that holds one.
- ATT&CK ids are ATT&CK v19.2, most from MITRE's [S9008 Shai-Hulud](https://attack.mitre.org/software/S9008/).
  T1102.002 for the self-hosted runner is our own mapping.

## What is validated

With sigma-cli 3.1.0, pySigma 1.5.1 and its Splunk 2.1.0, Elasticsearch 2.1.1 and SQLite 2.0.0 backends, installed
with the commands below:

- `sigma check --fail-on-issues` finds 0 errors and 0 issues, and fails on deliberately broken rules.
- Every file converts with the Splunk and ES|QL backends; the Kusto and Lucene backends cannot convert the
  correlations.
- `test/detections.test.ts` (in `npm test`) runs every alerting rule over its examples with an evaluator for the Sigma
  subset these rules use ([test/sigma-subset.ts](../test/sigma-subset.ts)), and checks their metadata, the IOC names
  they match, that the conversions are current, and that the hunt and schedules under Deploying fit the rules.
  [tools/check_sigma_examples.py](tools/check_sigma_examples.py) runs the same examples through the official SQLite
  backend. On 2026-10-15 all ten alerting rules passed both.
- `test/detections-queries.test.ts` runs the committed query bodies on small SPL and ES|QL models: each correlation's
  aggregation, field, group-by, threshold and window, every example, and a burst across an hour boundary. The SPL
  model fails on a query that tests a JSON array by its plain name.

```sh
VENV=$(mktemp -d)/venv; uv venv -q "$VENV"
uv pip install --python "$VENV/bin/python" --exclude-newer 2026-10-07T00:00:00Z \
  sigma-cli pysigma-backend-splunk pysigma-backend-elasticsearch pysigma-backend-sqlite
"$VENV/bin/sigma" check --fail-on-issues detections/github-audit-log/ detections/sigma/
"$VENV/bin/python" -I detections/tools/check_sigma_examples.py detections/github-audit-log/*.yml detections/sigma/*.yml
"$VENV/bin/python" -I detections/tools/convert_rules.py "$VENV/bin/sigma"   # after changing a rule
```

## What is not validated

- **No real data yet.** No rule has run against real events. The examples were written to fit the rules, not
  captured from an attack, and GitHub does not document the values of fields such as `@timestamp`,
  `programmatic_access_type`, `run_number`, `job_workflow_ref` or `secrets_passed`.
- **WS-AL-004's job rule has no positive control.** GitHub does not define `job_workflow_ref`'s value, so the rule
  matches the worm's branch after the `@` both as `refs/heads/<branch>` and bare. A value in another form never
  matches, silently: its recall is unverified until a sandbox replay's events are captured ([ROADMAP](../ROADMAP.md)).
  The run rule reads the documented `head_branch` of the same runs, and `workflow_run_id` joins a job to its run.
- **No SIEM.** The queries ran only on the test's models, not in Splunk or Elasticsearch; the ES|QL edits are untested.
- **Case is not cross-checked.** The SQLite checker's columns are case-insensitive (`NOCASE`) and so is the
  evaluator, so neither covers how a deployed query handles case.

## Deploying

Convert each rule with a pipeline for your field names and index
(`sigma convert -t splunk -p <your pipeline> detections/github-audit-log/`), on a backend with correlation support
such as Splunk or ES|QL, then make the edits the reference files list.

**Schedule the correlations (WS-AL-001, WS-AL-004) with overlapping runs.** A run that reads only its own interval
(`earliest=-1h@h latest=@h` every hour) counts in clock hours again and misses a burst across the boundary. Each run
must look back the rule's timespan plus the interval, plus the feed's delivery delay, so that every window lies whole
in one run. Overlapping runs see a burst more than once: throttle on the group-by fields (`actor`; `repo` and
`workflow_id`) for as long as the look-back. WS-AL-001 every 15 minutes, before any delivery delay:

- Splunk (`savedsearches.conf`): `cron_schedule = */15 * * * *`, `dispatch.earliest_time = -75m`,
  `dispatch.latest_time = now`, `alert.suppress = 1`, `alert.suppress.fields = actor`, `alert.suppress.period = 75m`.
- ES|QL (an Elastic Security rule): `"interval": "15m"`, `"from": "now-75m"` (60 minutes of additional look-back); it
  suppresses alerts by `actor` for 75 minutes.

**The audit-log rules (WS-AL-*)** need GitHub Enterprise Cloud, whose audit-log
[streaming](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise)
and [REST API](https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs#get-the-audit-log-for-an-organization)
are the only feeds. Stream the log, or poll `GET /orgs/{org}/audit-log` as an organization owner
([token](../docs/cli/audit-org.md#token)). The stream is delivered at least once: deduplicate on `_document_id`. GitHub
keeps web events for 180 days and Git events for seven, but the REST API returns only the past three months unless the
query names a time: a hunt without `created:` cannot clear an older compromise.

- **WS-AL-001**: deploy the correlation; the medium token rule is optional. Unlike `audit-org`'s burst check, it
  counts per actor, so three maintainers each opening one repository within the hour do not trip it.
- **WS-AL-002**: replace the example identity in `filter_allowlist` before deploying the medium rule. Enterprise
  runners are in the enterprise audit log.
- **WS-AL-003**: add `enriched_description` to every public `repo.create` from `GET /repos/{owner}/{repo}`, and
  alert when that call fails: without it only the name can match.
- **WS-AL-004**: for each alert, fetch the workflow file at `head_sha` and run `wormsign scan` on it. The job rule's
  `secrets_passed` lists what to rotate. It is a JSON array, which Splunk may extract as `secrets_passed{}`, so no
  rule tests it.

For a one-off hunt in an organization, `jq` reproduces WS-AL-002's critical rule (its `select` matched exactly the
rule's positive examples). Set `SINCE` at most 180 days back, and `ENT` to your enterprise's slug to read enterprise
runners, which only the enterprise audit log holds (an enterprise admin's token):

```sh
SINCE=YYYY-MM-DD
{
  for a in repo.self_hosted_runner_online org.self_hosted_runner_online workflows.prepared_workflow_job; do
    gh api --method GET --paginate "/orgs/$ORG/audit-log" -f phrase="action:$a created:>=$SINCE"
  done
  if [ -n "${ENT:-}" ]; then
    gh api --method GET --paginate "/enterprises/$ENT/audit-log" \
      -f phrase="action:enterprise.self_hosted_runner_online created:>=$SINCE"
  fi
} | jq -c '.[] | select((.action == "repo.self_hosted_runner_online" or .action == "org.self_hosted_runner_online"
                           or .action == "enterprise.self_hosted_runner_online" or .action == "workflows.prepared_workflow_job")
                          and ((.runner_name // "") | ascii_upcase) == "SHA1HULUD")'
```

**The endpoint rules (WS-EP-*)** need process-creation events with `Image`, `ParentImage`, `CommandLine`,
`ParentCommandLine` and `CurrentDirectory` (Sysmon, auditd with `CWD` records, or an EDR). WS-EP-001 filters Bun
asked only for its version (`oven-sh/setup-bun`, the `bun` package's postinstall), Bun run as `node` by package scripts
unless it runs a loader name, and pm2 (also as `pm2/lib/Daemon.js`) and nodemon by their command line.

**The CI detections (WS-CI-*)**:

- **Make install output visible**: run CI installs with `--loglevel=info`. At the default level npm 10.9.2 prints
  no dependency scripts and npm 12.2.0 only those it blocked. `--foreground-scripts` is no substitute: WS-CI-001 then
  cannot tell `node setup.mjs` from a project's own preinstall. pnpm and Yarn output was not checked.
- **Keep logs outside GitHub**: the 2026-08 wave deletes its workflow run (JFrog), and with it the log. Forward job
  logs as they are written and run the patterns there (`grep -E -e '<pattern>'`: WS-CI-004's starts with `-`).
- **Scope WS-CI-001 to WS-CI-003 to install steps**: TruffleHog and Bun are legitimate tools elsewhere.
- **Feed WS-CI-004 process command lines** and the jobs API's `runner_name`: the worm hides `config.sh`'s output.

## Known gaps

- The worm normally creates its exfiltration repository in the victim's personal account, which no organization
  audit log sees; WS-AL-003 fires only inside a monitored organization or Enterprise Managed Users enterprise.
  WS-AL-002 likely shares the gap: Datadog shows `config.sh` registering against `<owner>/<repo>` in the code that
  creates that repository. WS-CI-004 reads the infected host's command line instead.
- The audit log never names the files a push added, so WS-AL-004 relies on a new workflow's first run and on run
  deletion, and on the worm's branches. Run deletion is reported for the 2026-08 wave only (JFrog); Wiz says the
  2025-11 wave deletes "the workflow", which may mean the file, so the deletion rule may not fire for it.
- WS-CI-005 assumes GitHub prints a serialized secrets context one JSON line at a time; a log containing one was not
  observed. It cannot tell the worm's step from an action that takes `toJSON(secrets)` as an input.
- The endpoint rules miss the runner under `~/.dev-env`, its job process running discussion bodies, and the
  home-folder wipe.
