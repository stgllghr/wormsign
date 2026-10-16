# PyPI incidents the design drew on

The PyPI incidents of 2024 to 2026, with how long each version stayed installable, as the sources give it. Every
source was retrieved on 2026-10-08. What they mean for the gate: [threat-model.md](../threat-model.md#pypi).

## Incidents

"Removed" is the time from upload until the version could no longer be installed from PyPI (deleted or quarantined),
as the source gives it.

| When | What happened | Upload to removal | Sources |
|---|---|---|---|
| 2024-12-04 to 2024-12-07 | Ultralytics: 8.3.41 and 8.3.42 were published by the project's own Trusted Publishing workflow after its GitHub Actions cache was poisoned, so they carried valid attestations; 8.3.45 and 8.3.46 were published with an API token left over from before Trusted Publishing. The payload was a crypto miner. | about 12 h (8.3.41), 1 h (8.3.42), 8 h and 7.5 h (8.3.45, 8.3.46), from the timeline's minute-level times | PyPI, [Supply-chain attack analysis: Ultralytics](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/) (2024-12-11); timeline in W. Woodruff, [zizmor would have caught the Ultralytics workflow vulnerability](https://blog.yossarian.net/2024/12/06/zizmor-ultralytics-injection) |
| July 2025 | num2words 0.5.15 and 0.5.16, uploaded by an attacker who had phished a maintainer's PyPI account; removed by the account's owner, PyPI's report says, within hours of the upload. | not given; StepSecurity saw 0.5.15 flagged about 2 hours after its publication | PyPI, [Incident Report: Phishing Attack](https://blog.pypi.org/posts/2025-07-31-incident-report-phishing-attack/) (2025-07-31); StepSecurity, [num2words PyPI Package Shows Signs of Compromise](https://www.stepsecurity.io/blog/supply-chain-security-alert-num2words-pypi-package-shows-signs-of-compromise) (2025-07-28) |
| September 2025 | GhostAction: workflows injected into GitHub repositories sent PyPI tokens, among other secrets, to the attackers. Nothing was published to PyPI; PyPI invalidated the affected tokens. | none published | PyPI, [Token Exfiltration Campaign via GitHub Actions Workflows](https://blog.pypi.org/posts/2025-09-16-github-actions-token-exfiltration/) (2025-09-16); GitGuardian, [The GhostAction Campaign](https://blog.gitguardian.com/ghostaction-campaign-3-325-secrets-stolen/) |
| September and November 2025 | The Shai-Hulud npm waves did not publish to PyPI. PyPI revoked PyPI tokens it found exposed in compromised repositories and saw no use of them. | none published | PyPI, [PyPI and Shai-Hulud](https://blog.pypi.org/posts/2025-11-26-pypi-and-shai-hulud/) (2025-11-26) |
| 2026-03-24 | litellm 1.82.7 and 1.82.8 (TeamPCP), published with a token stolen through a compromised Trivy dependency in the project's CI. 1.82.8 added `litellm_init.pth`, which Python runs at every interpreter start. | 2 h 32 min: 1 h 19 min to the first report, 1 h 12 min more to quarantine | PyPI, [Incident Report: LiteLLM/Telnyx supply-chain attacks](https://blog.pypi.org/posts/2026-04-02-incident-report-litellm-telnyx-supply-chain-attack/) (2026-04-02); LiteLLM, [Security Update](https://docs.litellm.ai/blog/security-update-march-2026) |
| 2026-03-27 | telnyx 4.87.1 (03:51 UTC) and 4.87.2 (04:07 UTC), TeamPCP again: the same embedded RSA key as litellm's payload. The code ran at import. | 3 h 42 min: 1 h 45 min to the first report, 1 h 57 min more to an automated quarantine | the same PyPI report; Endor Labs, [TeamPCP Strikes Again](https://www.endorlabs.com/learn/teampcp-strikes-again-telnyx-compromised-three-days-after-litellm) (2026-03-27) |
| 2026-04-30 | lightning 2.6.2 and 2.6.3 (Mini Shai-Hulud): ran on import. | not given; a bound only: Socket's scanner flagged both 18 minutes after publication | Socket, [PyTorch Lightning PyPI Package Compromised](https://socket.dev/blog/lightning-pypi-package-compromised) (2026-04-30) |
| May 2026 | mistralai and guardrails-ai (Mini Shai-Hulud): Mistral AI confirmed its SDK packages were contaminated. | not given | Tenable, [Mini Shai-Hulud FAQ](https://www.tenable.com/blog/mini-shai-hulud-frequently-asked-questions) (2026-05-21); GitHub advisories [GHSA-wx9m-wx4f-4cmg](https://osv.dev/vulnerability/GHSA-wx9m-wx4f-4cmg) (mistralai) and [GHSA-xmpw-2vmm-p4p6](https://osv.dev/vulnerability/GHSA-xmpw-2vmm-p4p6) (guardrails-ai), both CWE-506 |
| 2026-06-07 and 2026-06-08 | The "Hades"/Miasma wave: wheels that ship a `*-setup.pth`, which runs at interpreter start and starts a Bun-powered credential stealer. | a bound only: Endor Labs says its reports through PyPI's trusted-reporter API had six packages quarantined within 30 minutes | Socket, [Shai-Hulud Descends to Hades](https://socket.dev/blog/shai-hulud-descends-to-hades-miasma-pypi-wave) (2026-06-07: 37 wheels across 19 projects); Endor Labs, [Hades Wave Hits Six PyPI Bioinformatics Packages](https://www.endorlabs.com/learn/shai-hulud-hades-wave-hits-six-pypi-bioinformatics-packages) (2026-06-08) |

PyPI's own figure for 2025, across all malware reports: 66% handled within 4 hours of the report, 92% within 24
hours, at most 4 days ([PyPI 2025 in review](https://blog.pypi.org/posts/2025-12-31-pypi-2025-in-review/)). These are
measured from the report, not from the upload.

## Conflicts in the sources

Named rather than resolved:

- litellm's exposure: LiteLLM's post says the versions were live from 10:39 UTC "for about 40 minutes" before
  quarantine, and gives an affected window of 10:39 to 16:00 UTC; PyPI's report gives 2 h 32 min from upload to
  quarantine. This page uses PyPI's figure, as the registry's own record.
- The Hades wave's size: Socket counted 37 wheels across 19 projects on 2026-06-07, and Endor Labs six
  bioinformatics packages published on 2026-06-08. Whether the two counts overlap is not established here; if they
  do not, the total is 25 projects.
- Exact upload times were not published for num2words 0.5.15 and 0.5.16, mistralai, guardrails-ai or lightning,
  so for these, upload to removal and upload to advisory are bounds, not measurements.

## OSV records

Checked on OSV on 2026-10-09. litellm, telnyx, num2words, mistralai and guardrails-ai each have a GitHub advisory with
CWE-506 and a `MAL-` record ([MAL-2026-2144](https://osv.dev/vulnerability/MAL-2026-2144),
[MAL-2026-2254](https://osv.dev/vulnerability/MAL-2026-2254),
[MAL-2025-6794](https://osv.dev/vulnerability/MAL-2025-6794),
[MAL-2026-3608](https://osv.dev/vulnerability/MAL-2026-3608),
[MAL-2026-3607](https://osv.dev/vulnerability/MAL-2026-3607)). lightning 2.6.2 and 2.6.3 have
[MAL-2026-3201](https://osv.dev/vulnerability/MAL-2026-3201) (their GitHub advisory is CWE-470, not CWE-506). The
Ultralytics releases have neither, only `PYSEC-2024-154`.
