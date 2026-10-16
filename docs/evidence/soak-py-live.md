# Live soak controls against PyPI and OSV

`wormsign soak` run against the real PyPI index and OSV (`api.osv.dev`), with the two controls of
[soak-live.md](soak-live.md); unit tests use captured pypi.org pages and a fake OSV. It supports
[soak.md](../soak.md#python-pypi-locks). `soak` binds each locked file to an index file of that project and version
by sha256, and fails a version whose youngest locked file was uploaded less than `--min-age` ago.

- `--min-age 100000d` (about 274 years): **every** locked file must be young, and every version must fail with
  WS-SK-001.
- `--min-age 1m` (one minute): every version must pass, unless a locked file was uploaded in the last minute.

A gate stuck open passes the first; one stuck shut, or unable to bind a file or reach the index, fails the second
(WS-SK-002, high). A failed OSV request is WS-OS-900 (high), so a clean exit shows that OSV answered.

## The run

Run 2026-10-10 from 01:02:08 to 01:02:13 UTC on macOS 15.6.1 (arm64), Node 24.21.0 with npm 11.19.0 on the PATH,
wormsign built from the `src/` tree `c1193a069f361499a6cd381b1f88a59afb8cbb3f` (`git rev-parse <commit>:src`),
default index `https://pypi.org/simple/`. Later code changes decide nothing here: the requirements file is ASCII,
the uv project is `virtual`, so nothing is built, and each fixture ran outside any git work tree. The requirements
runs read pip's configuration with the machine's `python3 -m pip config list` (Homebrew Python 3.14.6, pip 26.1.2),
which listed nothing; no `PIP_*` or `UV_*` variable was set.

```sh
npm run build
for name in uv requirements; do
  dir=$(mktemp -d) && cp docs/evidence/data/soak-py-live/$name/* "$dir"
  node dist/src/cli.js soak "$dir" --min-age 100000d --format json > docs/evidence/data/soak-py-live/out/$name-100000d.json
  node dist/src/cli.js soak "$dir" --min-age 1m --format json      > docs/evidence/data/soak-py-live/out/$name-1m.json
  node dist/src/cli.js soak "$dir" --format json                   > docs/evidence/data/soak-py-live/out/$name-default.json
done
```

## The fixtures

Benign packages only, the same set in both: MarkupSafe 2.1.5 (for Python below 3.10), MarkupSafe 3.0.3 and six 1.17.0.

- `uv/uv.lock` and `uv/pyproject.toml`: `test/fixtures/python/locks/uv-0.12.21/fork`, written on 2026-10-08 by uv
  0.12.21 (7af826859, 2026-09-29) with `uv lock --exclude-newer 2026-10-01T00:00:00Z`
  (`test/fixtures/python/locks/TOOLS.txt`). The lock forks by Python version, so it holds two MarkupSafe versions: 142
  files, each with a sha256.
- `requirements/requirements.txt`: that lock exported on 2026-10-09 by uv 0.10.9 (Homebrew, 2026-03-06) with
  `uv export --frozen --offline --format requirements-txt -o requirements.txt`, with `HOME`, `XDG_CONFIG_HOME` and
  `UV_CACHE_DIR` in an empty directory and `UV_NO_CONFIG=1`, then a `--require-hashes` line added at the top, which
  makes it a hash lock. 142 hashes.

## Results

| fixture | run | exit | WS-SK-001 | per-version status | other findings |
| --- | --- | --- | --- | --- | --- |
| `uv.lock` | `--min-age 100000d` | 1 | 3 (51 + 89 + 2 = 142 young files) | 3 `too-new` | none |
| `uv.lock` | `--min-age 1m` | 0 | 0 | 3 `ok` | none |
| `uv.lock` | default (`7d`) | 0 | 0 | 3 `ok` | none |
| `requirements.txt` | `--min-age 100000d` | 1 | 3 (51 + 89 + 2 = 142 young files) | 3 `too-new` | none |
| `requirements.txt` | `--min-age 1m` | 0 | 0 | 3 `ok` | none |
| `requirements.txt` | default (`7d`) | 0 | 0 | 3 `ok` | none |

Every run bound all 142 locked files to PyPI files of the right project and version and read their upload times (no
WS-SK-002). OSV answered for all three versions and had no record for any (no WS-OS-001 or WS-OS-900). The files were
uploaded from 2024-02-02 (MarkupSafe 2.1.5) to 2025-09-27 (MarkupSafe 3.0.3), so the youngest was 377 days old and
the 7-day default passed them all. The `uv.lock` runs printed:

```text
note: 142 PyPI file(s) of 3 version(s) checked against https://pypi.org/simple/
note: registry signals (WS-RG-*) are not implemented for PyPI
note: release-age settings of Python tools are not checked by soak; see harden-dev.sh
note: 1 local Python package(s) not age-checked (their code is in this repository): demo-fork==0.1.0
note: the scanned root is not in a git work tree, so whether local Python sources are tracked by git was not checked
note: 3 package version(s) checked against OSV for malicious-package records (PyPI); 1 not sent to OSV (local code, git, VCS, a direct URL, another index, or a name not confirmed public: soak sends their names nowhere)
```

The local package is the fixture's own root project (`source = { virtual = "." }`), which has no upload time. The
requirements runs printed the first three notes and
`3 package version(s) checked against OSV for malicious-package records (PyPI)`. A WS-SK-001 message from the first
control:

```text
six==1.17.0 (PyPI) has 2 locked file(s) uploaded inside the required 100000.0d soak window: six-1.17.0-py2.py3-none-any.whl uploaded 674.3d ago (2024-12-04T17:35:26.475808Z); six-1.17.0.tar.gz uploaded 674.3d ago (2024-12-04T17:35:28.174320Z)
```

## The outputs

The six reports are in `docs/evidence/data/soak-py-live/out/`. Their evidence lists at most 50 files per version,
with `filesTotal` beyond that (MarkupSafe 2.1.5 has 51 locked files, 3.0.3 has 89). SHA-256 as committed:

| file | sha256 |
| --- | --- |
| `uv/uv.lock` | `efa0de110342a42e8ea9019312e300fb505532243c7f785714ffc468850f787f` |
| `uv/pyproject.toml` | `1f7a531f1203dee31e972f565004245cda7cd6fc85d6b5a79e4dc0236e0fbac7` |
| `requirements/requirements.txt` | `b0bfa89c68032d350a933386599004c899393edf1c4bd8ba06d921b38024a591` |
| `out/uv-100000d.json` | `b587ba0260e8f5292ad0217edfc6b0e0156a3537aa27a62d95066453e786aa15` |
| `out/uv-1m.json` | `02b45cb8dd581b3deca9fcbdc5a7630607c0d73443f0db27f266f04c7cb1a2c8` |
| `out/uv-default.json` | `954e311fbde8984a1602b3d5b9feb3305002af92a397bd4eaf03ee952bde081a` |
| `out/requirements-100000d.json` | `80830771b8516995d8a66e39c64820f7e37354eab9af10d65fef2330469eb379` |
| `out/requirements-1m.json` | `5f85d397fdeb41522c5a41a291c7224a8a7220016c1ba110c7cb281277d4f912` |
| `out/requirements-default.json` | `06a46a706fb0d8476c79c00e50969075ad197e400141b9c73f30f69cc698bb3c` |

## Limits

- The controls show that the gate binds real files by hash, reads their upload times, compares them with the
  threshold and reaches OSV, not what the right threshold is for PyPI: the 7-day default is not derived from PyPI
  evidence ([threat model](../threat-model.md#pypi)).
- There is no live positive control for OSV, quarantine or a deleted file: the three versions are benign. Asking
  about a removed malicious version would download nothing (the index answers 404, OSV with its record), but has
  not been run here. Unit tests
  against captured and forged index pages and OSV answers cover those paths (`test/python-soak.test.ts`,
  `test/python-soak-index.test.ts`), as do the `osv` module's mutants, through the same code for PyPI
  ([test-runs.md](test-runs.md#mutation-check)).
- Three versions and one index. A private index, a `pylock.toml`, a PEP 723 script lock, local sources and the
  install-settings check were not run live; their tests are in `test/python-*.test.ts` and
  `test/soak-python-cli.test.ts`.
- A re-run sees the same upload times unless PyPI removes a file; a new release changes nothing, because the locks
  pin exact files.
