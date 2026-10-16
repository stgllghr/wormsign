# Output formats and exit codes

Every command that reports findings (`scan`, `diff`, `soak`, `audit-org`) produces the same report in one of three
formats, chosen with `--format`, and exits with the [codes below](#exit-codes).

| Format | For | Baselined findings |
|---|---|---|
| `human` (default) | a terminal or a CI log | counted in the summary line, not listed |
| `json` | scripts, dashboards, writing baseline entries | listed, with `suppressed.justification` |
| `sarif` | GitHub code scanning and other SARIF viewers | left out |

`--output <file>` writes the report to a regular file (new files mode 0644), with the same exit code; a symlink,
device or FIFO there is exit 2, so keep reports outside a checked tree. Errors go to stderr, prefixed `wormsign:`.

## Human

```text
CRITICAL WS-LK-001  package-lock.json
         wormsign-test-marker@1.0.0 is listed as compromised
         source: https://example.test/synthetic-ioc
         fingerprint: cd74b222b7484a0f8a27516f55225aac
...
wormsign scan: 22 finding(s) (7 critical, 9 high, 6 medium, 0 low, 0 info)
note: IOC data (unversioned) from --iocs test/fixtures/iocs
```

(The [cli/scan.md](cli/scan.md#examples) run of `test/fixtures/malicious`.) A finding is severity, [rule ID](rules.md)
and location (`file:line`, `file` or `-`); the message; `source:` for an IOC finding; and the [baseline](baseline.md)
`fingerprint:`. Findings sort by severity, then file, line, rule and key. The summary counts unsuppressed findings,
plus `, N baselined`. The notes say which IOC data was used and what was not checked: a report noting "no lockfile
found" is not a clean one.

## JSON

From the demo project in [baseline.md](baseline.md#entries):

```json
{
  "tool": "wormsign",
  "version": "0.1.0",
  "command": "scan",
  "findings": [
    {
      "file": "package.json",
      "key": "postinstall:2f0391b18bc0c6809c923f102fd8c313",
      "line": 5,
      "ruleId": "WS-LC-001",
      "severity": "medium",
      "message": "\"postinstall\" script runs on install for every consumer of this package: node setup.js",
      "fingerprint": "77e37b5c68b360e38667f4d11053b4bd"
    }
  ],
  "notes": [
    "IOC data 2026-10-02 from the bundled data /path/to/wormsign/data/iocs/",
    "..."
  ]
}
```

`findings` holds every finding, **baselined ones included**, sorted by file, line, rule ID and key; `notes` are the
human notes; `extra` is `soak`'s [evidence](#soak-evidence). Each finding has `ruleId`, `severity`, `message`, `key`
(what the rule matched) and `fingerprint` (32 hex characters, [computed](baseline.md#fingerprints)), and when
they apply, `file` (relative to the run's root; for `audit-org`, `org/repo` or the organization), a 1-based `line`,
the IOC `source` URL, `suppressed: { "justification": "..." }`, and `notBaselinable: true` for a finding no baseline
entry can approve (its message says why). Read fields by name: their order is not fixed. For
the gate's view, drop suppressed findings, as the exit code does:

```sh
wormsign scan --format json | jq '[.findings[] | select(.suppressed == null)]'
```

### Soak evidence

`soak --format json` adds what it learned about each locked version. From a real run on a lock of one benign
version, on 2026-10-15:

```json
  "extra": {
    "evidence": [
      {
        "name": "typescript",
        "version": "7.1.0-dev.20261015.1",
        "ecosystem": "npm",
        "publishedAt": "2026-10-15T08:02:47.486Z",
        "ageHours": 2.2,
        "status": "too-new",
        "registry": {
          "comparedWith": "7.1.0-dev.20261014.1",
          "signals": []
        },
        "osv": []
      }
    ],
    "minAgeMs": 604800000
  }
```

| Field | Meaning |
|---|---|
| `extra.minAgeMs` | The required age in milliseconds. |
| `extra.evidence[]` | One entry per checked registry version, npm and PyPI, sorted by name, version, ecosystem; not local packages, nor npm or Python entries `--base` skipped. |
| `.name`, `.version` | What gets installed: the tarball's, when `resolved` names another package's. |
| `.ecosystem` | `npm` (from `--registry`) or `PyPI` (from `--pypi-index`). |
| `.status` | `ok`, `too-new` (WS-SK-001) or `unverifiable` (WS-SK-002, with `.reason`). |
| `.publishedAt`, `.ageHours` | Publish time (PyPI: the youngest locked file's upload) and age, unless `unverifiable`. |
| `.registry` | `comparedWith` (the earlier version) and `signals` (WS-RG-* IDs), read for versions under 14 days old, or with `--base` for every changed one. |
| `.releaseFirstFileAt`, `.projectStatus` | PyPI: the release's first upload, and its PEP 792 status (`active`, `archived`, `deprecated`). |
| `.files[]`, `.filesTotal` | PyPI: up to 50 locked files (`filename`, `sha256`, `uploadTime`, `yanked`), and the total when cut. |
| `.osv` | `MAL-` IDs, and `GHSA-` IDs whose record lists CWE-506 ([soak.md](soak.md#layer-3-osv-malicious-package-records)); `[]` means none. |

An absent `osv` or `registry` means "not checked", never "clean". A full PyPI entry is in
[evidence/soak-py-live.md](evidence/soak-py-live.md).

## SARIF

`--format sarif` writes [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html), one run,
following GitHub's [SARIF support for code scanning](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).
It has no timestamps and is sorted, so the same input gives byte-identical SARIF; `test/golden/malicious.sarif.json`
is a full example the tests check.

### Rules

`runs[0].tool.driver` (`name` `wormsign`) lists every rule in `src/rules.ts`, fired or not, with descriptions, help,
a `helpUri` to [rules.md](rules.md), and a `security-severity` from the **worst severity the rule reported in this
run**, since GitHub reads it per rule:

| wormsign severity | `security-severity` | GitHub alert severity | Result `level` |
|---|---|---|---|
| critical | 9.5 | Critical | `error` |
| high | 8.0 | High | `error` |
| medium | 5.5 | Medium | `warning` |
| low | 3.0 | Low | `note` |
| info | none | (shown by `level`) | `note` |

A rule that reported nothing has no `security-severity`. If one rule reports a low and a critical finding in a run,
GitHub shows both alerts as Critical; each result keeps its own `level` and `properties.severity`, and a finding no
baseline entry can approve has `properties.notBaselinable: true`.

### Results

```json
{
  "ruleId": "WS-LK-001",
  "level": "error",
  "message": { "text": "wormsign-test-marker@1.0.0 is listed as compromised (source: https://example.test/synthetic-ioc)" },
  "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "package-lock.json" } } }],
  "partialFingerprints": { "wormsign/v1": "cd74b222b7484a0f8a27516f55225aac", "primaryLocationLineHash": "cd74b222b7484a0f8a27516f55225aac:1" },
  "properties": { "severity": "critical" }
}
```

`artifactLocation.uri` is the relative `file`, percent-encoded (`#`, `?` and `:` included), or `.` without one.
`partialFingerprints["wormsign/v1"]` is the baseline fingerprint; `primaryLocationLineHash` is set only for results
without a line, since GitHub's `upload-sarif` computes it for the rest.

### Baselined findings in SARIF

Baselined findings are left out: GitHub's SARIF reference does not list the `suppressions` property, so an included
one would be expected to open an alert. An existing alert disappears from the next upload with no recorded
dismissal; dismiss it in GitHub with the justification if the audit trail matters.

### What GitHub code scanning shows

Uploaded ([github-action.md](github-action.md#sarif-and-code-scanning)), each result becomes a Security-tab alert
titled by the message, with the rule's severity, help and [rules.md](rules.md) link, at the file and line. On a pull
request, new alerts on changed lines show as review annotations
([GitHub docs](https://docs.github.com/en/code-security/code-scanning/managing-code-scanning-alerts/triaging-code-scanning-alerts-in-pull-requests)).
`audit-org` repository names and a `soak` registry problem (uri `.`) are listed without a code view.

## Output is safe to print

In every format, and on stderr and in the Action's log, repository text is neutralised: control characters, every
Unicode format character (bidirectional controls, zero-width characters, U+FEFF, tag characters), line and paragraph
separators, blank Hangul fillers and variation selectors become `\uXXXX`. `##[` becomes `#\u0023[` and a leading
`::` is escaped, so text cannot issue
[workflow commands](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands). Each
replacement is a valid JSON escape, so JSON and SARIF parse to the original.

## Exit codes

| Code | `scan`, `diff`, `soak` | `audit-org` | `update-iocs` |
|---|---|---|---|
| 0 | No unsuppressed finding at or above `--fail-on` | Same, and the audit is complete | Cache written, or bundled data already current |
| 1 | At least one unsuppressed finding at or above `--fail-on` | Same | (never) |
| 2 | Usage error or internal error; no report | Usage error, internal error, repository list unreadable or empty, or an incomplete audit that would otherwise exit 0 | Usage error, download or validation error |

`--fail-on` takes `info`, `low`, `medium`, `high` (the default), `critical` or `never`; with `never`, errors still
exit 2. A crash, an exception or rejection nothing catches, is an internal error too: it prints
`wormsign: internal error: <message>` and exits 2, never Node's own 1. Usage errors are found before any scan, git or
network work.
