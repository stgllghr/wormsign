Retrieved 2026-10-09T00:22:58.511Z; input data/iocs/packages.json

Latency (hours) = first public malware advisory listing the version minus its registry publish time.

|  | versions | measured | min | p25 | median | p75 | p90 | p95 | max | <=24h | <=48h | <=72h | <=7d |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| set openssf-shai-hulud-1-stepsecurity | 484 | 481 | 1.6 | 12.4 | 18.9 | 31.2 | 49.0 | 49.4 | 60.0 | 69.9% | 86.3% | 100.0% | 100.0% |
| set openssf-shai-hulud-1-socket | 523 | 520 | 1.6 | 13.5 | 18.8 | 30.1 | 48.6 | 49.3 | 60.0 | 71.2% | 87.5% | 100.0% | 100.0% |
| set datadog-shai-hulud-2.0 | 1091 | 1041 | 0.2 | 8.0 | 11.0 | 12.6 | 13.3 | 14.9 | 20.2 | 100.0% | 100.0% | 100.0% | 100.0% |
| set openssf-mini-shai-hulud-picus | 4 | 4 | 28.4 | 28.4 | 28.4 | 29.2 | 36.1 | 36.1 | 36.1 | 0.0% | 100.0% | 100.0% | 100.0% |
| set openssf-mini-shai-hulud-may-2026-stepsecurity | 344 | 332 | 0.2 | 3.7 | 4.7 | 6.5 | 7.5 | 7.8 | 433.8 | 99.1% | 99.1% | 99.1% | 99.1% |
| set openssf-shai-hulud-aug-2026-jfrog | 1738 | 1648 | 0.5 | 5.3 | 5.8 | 6.0 | 6.5 | 12.2 | 77.4 | 99.9% | 99.9% | 99.9% | 100.0% |
| wave 2025-09 | 525 | 522 | 1.6 | 13.5 | 18.9 | 30.1 | 48.6 | 49.3 | 60.0 | 71.1% | 87.4% | 100.0% | 100.0% |
| wave 2025-11 | 1091 | 1041 | 0.2 | 8.0 | 11.0 | 12.6 | 13.3 | 14.9 | 20.2 | 100.0% | 100.0% | 100.0% | 100.0% |
| wave 2026-04 | 4 | 4 | 28.4 | 28.4 | 28.4 | 29.2 | 36.1 | 36.1 | 36.1 | 0.0% | 100.0% | 100.0% | 100.0% |
| wave 2026-05 | 344 | 332 | 0.2 | 3.7 | 4.7 | 6.5 | 7.5 | 7.8 | 433.8 | 99.1% | 99.1% | 99.1% | 99.1% |
| wave 2026-08 | 1738 | 1648 | 0.5 | 5.3 | 5.8 | 6.0 | 6.5 | 12.2 | 77.4 | 99.9% | 99.9% | 99.9% | 100.0% |
| all in-wave versions (headline) | 3702 | 3547 | 0.2 | 5.5 | 6.3 | 12.1 | 18.3 | 22.5 | 433.8 | 95.5% | 98.0% | 99.9% | 99.9% |

In-wave versions by measure (record-level rows can predate the version's own listing):

|  | versions | measured | min | p25 | median | p75 | p90 | p95 | max | <=24h | <=48h | <=72h | <=7d |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| headline: first advisory listing the version | 3702 | 3547 | 0.2 | 5.5 | 6.3 | 12.1 | 18.3 | 22.5 | 433.8 | 95.5% | 98.0% | 99.9% | 99.9% |
| same, including pre-wave listings | 3704 | 3549 | 0.2 | 5.5 | 6.3 | 12.1 | 18.3 | 22.7 | 4680.5 | 95.4% | 97.9% | 99.8% | 99.9% |
| OSV per-version snapshots only | 3702 | 3530 | 0.2 | 5.5 | 6.2 | 12.1 | 18.3 | 22.5 | 433.8 | 95.5% | 98.0% | 99.9% | 99.9% |
| OSV record created (record-level) | 3702 | 3547 | -2.2 | 4.2 | 4.9 | 10.2 | 12.9 | 17.0 | 46.5 | 96.4% | 100.0% | 100.0% | 100.0% |
| GHSA published_at (record-level) | 3702 | 3253 | 0.1 | 4.1 | 4.8 | 10.7 | 18.8 | 37.8 | 6883.4 | 92.6% | 97.4% | 98.9% | 99.0% |
| package deleted (404): advisory minus wave start | 3702 | 154 | 5.8 | 6.8 | 7.2 | 20.5 | 21.1 | 21.1 | 51.8 | 97.4% | 98.1% | 100.0% | 100.0% |
| removal upper bound: packument time.modified | 3702 | 3547 | 0.1 | 11.3 | 122.2 | 2791.2 | 7478.1 | 9146.7 | 9299.0 | 46.2% | 48.7% | 49.2% | 51.3% |

- registry status: removed 3547, package-404 154, live 1
- headline source: osv:google-open-source-security 378, osv:ghsa-malware 3134, (none) 1, osv:amazon-inspector 156, osv:ossf-package-analysis 4, osv:record-date 29
- no advisory in either source: 1; no GHSA: 331; no OSV MAL-: 1
- over 72h: @beproduct/nestjs-auth@0.1.10 (2026-05-11, 433.79h); @tallyui/storage-sqlite@0.2.1 (2026-05-11, 432.39h); @tallyui/storage-sqlite@0.2.3 (2026-05-11, 431.16h); @ornikar/intl-config@10.0.10 (2026-08-04, 77.36h); @ornikar/react-native-svg-transformer@1.0.13 (2026-08-04, 77.39h)
- pre-wave listings (published before the wave's month), excluded above: @rxap/ngx-bootstrap@19.0.3 (2025-03-07, 4680.54h); @rxap/ngx-bootstrap@19.0.4 (2025-05-16, 2995.86h)
- advisory dated before the version: OSV snapshot 0, OSV record 8, GHSA record 0
- record existed >1h before it listed the version: 1913
- GHSA published more than 7 days after the version: 31
- wave start used for 404 bounds: {"2025-09":"2025-09-14T17:58:50.315Z","2025-11":"2025-11-24T03:10:05.406Z","2026-04":"2026-04-29T09:55:25.654Z","2026-05":"2026-05-11T19:20:39.110Z","2026-08":"2026-08-04T09:30:01.291Z"}
