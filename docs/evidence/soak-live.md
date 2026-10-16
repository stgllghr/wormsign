# Live soak controls against the npm registry and OSV

`wormsign soak` run against the real npm registry and OSV (`api.osv.dev`), with two controls whose right answer is
known; unit tests use fakes. It supports [soak.md](../soak.md) and [cli/soak.md](../cli/soak.md).

- `--min-age 100000d` (about 274 years): older than anything on npm, so **every** package must fail with WS-SK-001.
- `--min-age 1m` (one minute): every package must pass, unless one was published in the last minute.

A gate stuck open passes the first; one stuck shut, or unable to reach the registry, fails the second (an
unreadable publish time is WS-SK-002, high). OSV is checked on every run without `--no-osv`, and a failed OSV
request is WS-OS-900 (high), so a clean exit also shows that OSV answered.

Run 2026-10-10 from 01:01:06 to 01:01:21 UTC on macOS 15.6.1 (arm64), Node 24.21.0 with npm 11.19.0 on the PATH,
wormsign built from the `src/` tree `c1193a069f361499a6cd381b1f88a59afb8cbb3f` (`git rev-parse <commit>:src`), default
registry `https://registry.npmjs.org`. Code changed after it (the Python side, the walker's git settings, `skills`)
changes nothing for these npm-only directories. The JSON reports are in `docs/evidence/data/soak-live/out/`
([SHA-256](#the-outputs)).

## Lockfile: wormsign's own `package-lock.json`

A real, benign npm lockfile (lockfileVersion 3, SHA-256
`298a67f03b30c126d66a807fa64107f5fdc9104937e6a3b51aa2571c60b36c59`): 98 registry packages, the TypeScript and ESLint
toolchain, copied with `package.json` and `.npmrc` (`ignore-scripts=true`, `min-release-age=7`) into an empty
directory so that no test fixture was read with it.

```sh
npm run build
dir=$(mktemp -d) && cp package.json package-lock.json .npmrc "$dir"
node dist/src/cli.js soak "$dir" --min-age 100000d --format json > self-100000d.json   # control 1
node dist/src/cli.js soak "$dir" --min-age 1m --format json      > self-1m.json        # control 2
node dist/src/cli.js soak "$dir" --format json                   > self-default.json   # default (7d)
```

| run | exit | WS-SK-001 | per-package status | other findings |
| --- | --- | --- | --- | --- |
| `--min-age 100000d` | 1 | 98 | 98 `too-new` | WS-SK-004 (medium): `.npmrc: min-release-age = 7 days is 7.0d, shorter than the required 100000.0d` |
| `--min-age 1m` | 0 | 0 | 98 `ok` | none |
| default (`7d`) | 0 | 0 | 98 `ok` | none |

Every run printed the same three notes:

```text
note: registry signals read for 11 package version(s) published in the last 14 days; older versions not read
note: 98 package version(s) checked against OSV for malicious-package records
note: 98 package version(s) checked against https://registry.npmjs.org
```

All 98 versions were checked against the registry and OSV: no WS-SK-002 (every locked integrity hash matched the
registry's), no WS-OS-001 or WS-OS-900, and no registry signal (WS-RG-*) on the 11 recent versions. Publish times
ranged from 2013-08-24 to 2026-09-28; the youngest, `@typescript-eslint/*` 8.71.0, were 271.8 hours (11.3 days) old,
so the 7-day default passed them all. A WS-SK-001 message from control 1:

```text
@eslint-community/regexpp@4.12.2 was published 352.5d ago, inside the required 100000.0d soak window (published 2025-10-22T11:56:00.818Z)
```

WS-SK-004 is the offline half of the check, and it is right each time: 7 days is too short against 100000 days,
and long enough against one minute and 7 days, with an npm on the PATH (11.19.0; 11.10.0 or newer enforces it).
In the [first run](#the-first-run-2026-10-02), with npm 10.9.2, which reads the setting and ignores it
([package-managers.md](package-managers.md#npm)), all three runs reported WS-SK-004: the finding follows the npm that
will run, not only the file. It is medium, below the default `--fail-on high`.

## Lockfiles from the other package managers

`test/fixtures/lockfiles/{npm,pnpm,yarn1,berry}` are real lockfiles written by npm, pnpm, Yarn 1 and Yarn 4 for the
same benign dependency set (26 registry packages each). Same controls:

```sh
for pm in npm pnpm yarn1 berry; do
  node dist/src/cli.js soak test/fixtures/lockfiles/$pm --min-age 100000d --format json > $pm-100000d.json
  node dist/src/cli.js soak test/fixtures/lockfiles/$pm --min-age 1m --format json      > $pm-1m.json
done
```

| lockfile | `100000d`: exit, WS-SK-001 | `1m`: exit, WS-SK-001 |
| --- | --- | --- |
| npm `package-lock.json` | 1, 26 of 26 | 0, 0 of 26 |
| pnpm `pnpm-lock.yaml` | 1, 26 of 26 | 0, 0 of 26 |
| Yarn 1 `yarn.lock` | 1, 26 of 26 | 0, 0 of 26 |
| Yarn 4 `yarn.lock` | 1, 26 of 26 | 0, 0 of 26 |

Each run checked all 26 versions against the registry and OSV, and reported WS-SK-003, since the fixtures hold no
release-age setting: medium for npm, pnpm and Yarn 4, and low for Yarn 1 (`Yarn Classic has no release-age
setting`). No fixture version was published in the last 14 days, so no registry signals were read. One version's OSV
answer named a GitHub advisory; soak read its record for CWE-506 (embedded malicious code), found none, and every run
notes `OSV records requested for 1 version(s) (GHSA classification)`. The Yarn 4 runs also note
`1 local package(s) not age-checked (their code is in this repository): fixture` and
`1 not sent to OSV (local code, git, or another registry: soak sends their names nowhere)`: the workspace itself.

## The outputs

SHA-256 of each report in `docs/evidence/data/soak-live/out/` as committed:

| file | sha256 |
| --- | --- |
| `self-100000d.json` | `1796d84231cecfa37adb47afda659321a0384d25896df1292f69a2c0ecc0dd00` |
| `self-1m.json` | `6b191d13cffdaad666c9c1bdfc23541da82aea3886322bde92609f13eaee6569` |
| `self-default.json` | `2a7b323759689365dd568d9cd8603449bada38cf47a0a1f48283d9387505e825` |
| `npm-100000d.json` | `1542f529ad71056519851fc203bee85ae9149411e62cdbc5b135b3e3895c06e0` |
| `npm-1m.json` | `b1897a9f254f412e5ea304abf0a5715012ab17649ba099cea3978afd2670097b` |
| `pnpm-100000d.json` | `a4338729ea8801f277dfc8cf03e96eeef436858b1cb24001a0841180b4bc9ad0` |
| `pnpm-1m.json` | `1b1d8efa53000f77dd4a0cb70182e17c1f58e70e8ca78fe9061af705724523ca` |
| `yarn1-100000d.json` | `87ec7e33b9c590b51a7fcce099ab9a9f3539836617937962bcf9a475d1a87333` |
| `yarn1-1m.json` | `497d7aa77da2c3228038d193607750db9f154acc88d6ad4867a5068e8281a2e9` |
| `berry-100000d.json` | `e9d5cf449dc758d21ab44e389ef30b1d6d12d8561bc5fc85818a97b0702bef00` |
| `berry-1m.json` | `119b81d84398a29bb4971393e539edc03d551e1c16682ad6a764c99504d5a80e` |

## The first run (2026-10-02)

The first run, on 2026-10-02 at 19:14 UTC with npm 10.9.2 on the PATH, used code from before this repository and the
72-hour default of the time; its outputs were not committed. Its lockfile held 110 registry packages, and the
controls gave the same answers (110 `too-new` at 100000 days, 110 `ok` at one minute), with WS-SK-004 on all three
runs. Its default run caught two development dependencies younger than 72 hours:

```text
HIGH     WS-SK-001  package-lock.json
         @types/node@22.20.5 was published 20.6h ago, inside the required 3.0d soak window (published 2026-10-01T22:38:10.803Z)
HIGH     WS-SK-001  package-lock.json
         ignore@7.0.11 was published 2.2d ago, inside the required 3.0d soak window (published 2026-09-30T14:15:23.068Z)
```

That was the gate doing its job, not a false positive. The repository's pull-request gate runs `soak --base`, which
checks only the versions a change adds or updates, so these two did not fail unrelated pull requests; a full
`wormsign soak` failed until they aged out. The fixture runs gave the same counts, with WS-SK-003 at medium for all
four lockfiles.

## Limits

- The controls show that the gate reads real publish times, compares them with the threshold and reaches OSV, not
  what the right threshold is ([soak-latency.md](soak-latency.md)).
- There is no live positive control for OSV or the registry signals: every package here is benign. The
  [latency study](soak-latency.md#the-run)'s control asks OSV about `@ctrl/tinycolor@4.1.1`, which checks OSV's data,
  not `soak`'s path from an answer to a finding. That path is covered by a unit test that replays a real
  `api.osv.dev` response for that version (`test/osv.test.ts`), by the `osv` module's mutants
  ([test-runs.md](test-runs.md#mutation-check)), and, for registry signals, by fake registry documents.
- A registry or OSV outage, or a package missing from the registry, makes the gate fail closed by default (WS-SK-002,
  WS-OS-900); unit tests cover those paths.
- Results depend on the day: here nothing locked was younger than 7 days; the first run's default run caught two.
