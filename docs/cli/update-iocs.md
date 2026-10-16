# `wormsign update-iocs`

Download IOC data newer than the copy bundled with this release, and cache it for `scan`, `diff` and `audit-org`, so
indicators published after a release apply without reinstalling. What the data holds is in [iocs.md](../iocs.md).

```text
wormsign update-iocs [--url <https-url>]
```

## What it does

1. Fetches the five files (`packages.json`, `files.json`, `workflows.json`, `repos.json`, `endpoints.json`) from
   `<url>`, by default `https://raw.githubusercontent.com/stgllghr/wormsign/main/data/iocs/`, each with a 60-second
   timeout. A redirect, or a file over 16 MiB whatever length the server declares, is refused.
2. Validates them as a scan would ([rules](../iocs.md#provenance-and-how-it-is-enforced)); the shared `version` must
   be a real date no later than tomorrow.
3. Compares them with the bundled data. A newer `version` is written to the cache. The same `version` and content,
   or an older `version`, writes nothing (exit 0). The same `version` with other content is refused (exit 2).
4. Writes to `$XDG_CACHE_HOME/wormsign/iocs`, or `~/.cache/wormsign/iocs`, each file through a temporary file and a
   rename, only after all five are fetched and validated.

### How scans use the cache

`scan`, `diff` and `audit-org` add the cache's entries to the bundled data when the cache's `version` is newer; the
cache can only add ([trust model](../iocs.md#trust-model)). A stale, partial or invalid cache is ignored, and the
report's first note says why. `--iocs <dir>` bypasses both. `soak` does not use IOC data.

## Options

| Option | Meaning |
|---|---|
| `--url <https-url>` | The directory holding the five files. Must be `https` and must not contain credentials (`user:token@`), which would be printed. A trailing `/` is added if missing. |

No other option is accepted.

## Examples

Against a local HTTPS server (its self-signed certificate passed with `NODE_EXTRA_CA_CERTS`) serving a changed
copy of the bundled data with the same `version`, and that copy dated the next day:

```console
$ wormsign update-iocs --url https://localhost:8443/conflict/
wormsign: refusing the IOC data at https://localhost:8443/conflict/: same version 2026-10-02 as the bundled data but different content; the source must bump "version"
$ echo $?
2
$ wormsign update-iocs --url https://localhost:8443/newer
IOC data 2026-10-03 from https://localhost:8443/newer/ written to /path/to/cache/wormsign/iocs
IOC cache updated: 4186 package versions, 20 hashes, 5 workflow names
$ wormsign scan | grep 'IOC data'
note: IOC data 2026-10-02 from the bundled data /path/to/wormsign/data/iocs/, plus additions from the update-iocs cache /path/to/cache/wormsign/iocs (2026-10-03)
```

A plain-HTTP or credentialed URL is refused before any request:

```console
$ wormsign update-iocs --url http://example.com/
wormsign: --url must be https: http://example.com/
$ echo $?
2
```

## Exit codes

0 when the cache was written or the bundled data is current; 2 for any error (usage, HTTP, network, redirect, size,
invalid data, a same-version conflict), with the cache unchanged. It reports no findings, so never exits 1
([output.md](../output.md#exit-codes)).

## Network

`GET` of the five files from the source URL (default `raw.githubusercontent.com`), no credentials, no redirects.

## Limitations

- **The data is not signed, and the cache can only add** ([trust model](../iocs.md#trust-model)).
- **Updating is manual.** Nothing runs `update-iocs` on a schedule; CI can run it as a step.
