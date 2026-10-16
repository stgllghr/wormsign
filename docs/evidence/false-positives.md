# False positives on 15 popular repositories

`wormsign scan` over 15 popular JavaScript/TypeScript repositories, every finding classified
([validation.md](../validation.md#evidence-from-real-data)). It measures noise, not detection: none of the 15 is known
to be compromised. One commit per repository was scanned, without `--node-modules`, and `diff` was not run.
The scanner was tuned on this corpus, so the rate is not held-out, and an AI agent (Claude Code) labelled every
finding with no person checking.

**Result.** With no baseline, 8 of the 15 fail `scan`'s default gate (`--fail-on high`): react, babel, prettier,
storybook, next.js, astro, npm/cli and eslint. All 299 high findings, the ones that fail it, are by design, so each of
the 8 needs a justified baseline or `ignorePaths` entry before the gate passes. `soak`'s Python side fails a ninth,
TypeScript ([below](#soaks-python-side-on-the-same-corpus)); `soak`'s npm side was not measured, nor `diff`. Of all
1,591 findings, 1 is a false positive, a medium one, below the default gate; the IOC-driven rules reported
nothing. Three fixes removed 5,675 of the first run's 5,676 false positives.

Run 2026-10-16 from 04:20 to 04:24 UTC on Node 23.11.0 (built with npm 10.9.2), macOS 15.6.1 arm64, git 2.50.1,
IOC data dated 2026-10-02, default options. The JSON's `scanner` field gives the tree IDs of `src/`
(`6e08aa14b48c6fb5aeed1065ed9634680794c1de`) and `data/iocs/` (`ce5f3ebb8e67bf7860f2bb0e9b72b7407ab5a8fe`), as
`git rev-parse 0ff5d3e:src 0ff5d3e:data/iocs` prints them. The JSON's one edit replaces each checkout's path with
`<repo>/` (15 times): `sed 's#<absolute path of the checkout>/#<repo>/#g'`.

| File | Size | SHA-256 |
| --- | --- | --- |
| [`data/fp-corpus.json`](data/fp-corpus.json): every finding, note and control result | 633,581 bytes | `6530dc4fa06a51d5b2fe899c5b1a1be350a3a671acebadd428165f2b6a740e47` |
| [`data/fp-corpus-soak.json`](data/fp-corpus-soak.json): `soak`'s [Python findings](#soaks-python-side-on-the-same-corpus) | 6,171 bytes | `32a3bc9006ef43f8f56c64e3a22bb3ad216cd5613b759ffff64dd43bf61c7a07` |

## Corpus

Default-branch commits resolved on 2026-10-02 (`gh api repos/<repo>/commits/<branch>`), pinned in
[`scripts/fp-corpus.mjs`](../../scripts/fp-corpus.mjs) and fetched with `git fetch --depth 1`, hooks, LFS and
submodules off; nothing is installed or run. 227 real workflows; lockfiles of npm, pnpm, Yarn 1 and Yarn 4.

| repository | commit | root lockfile | workflows | files scanned | findings |
| --- | --- | --- | --- | --- | --- |
| facebook/react | `7c6ac13e19fe` | yarn.lock (Yarn 1) | 26 | 7,252 | 682 |
| webpack/webpack | `d37872d245f4` | yarn.lock (Yarn 1) | 15 | 19,548 | 0 |
| babel/babel | `7c1dcfac0037` | yarn.lock (Yarn 4) | 13 | 27,674 | 7 |
| prettier/prettier | `8dafda772d09` | yarn.lock (Yarn 4) | 17 | 9,471 | 3 |
| storybookjs/storybook | `2a3bdfe58ea4` | yarn.lock (Yarn 4) | 20 | 8,478 | 15 |
| vercel/next.js | `8e0700c74474` | pnpm-lock.yaml | 29 | 32,954 | 11 |
| vitejs/vite | `10033218d239` | pnpm-lock.yaml | 13 | 2,823 | 2 |
| sveltejs/svelte | `020242d6bef0` | pnpm-lock.yaml | 4 | 9,178 | 0 |
| withastro/astro | `322cd139fadb` | pnpm-lock.yaml | 21 | 6,943 | 4 |
| microsoft/TypeScript | `09b1db061731` | package-lock.json | 13 | 66,945 | 0 |
| nodejs/undici | `f850c68967e3` | package-lock.json | 13 | 840 | 0 |
| nestjs/nest | `7fb52e7f4f73` | package-lock.json | 2 | 2,466 | 1 |
| npm/cli | `b317f16c80df` | package-lock.json | 26 | 4,864 | 863 |
| expressjs/express | `7ef98448f8b3` | none | 5 | 214 | 0 |
| eslint/eslint | `bc51eee6e3e8` | none | 10 | 2,303 | 3 |

**Positive control.** Each root lockfile, scanned against a synthetic IOC list naming one `name@version` in it, must
give exactly that WS-LK-001; it did for all 13. A canary not in babel's lockfile (`@actions/github@9.1.2`, not
`9.1.1`) gives none, so the control can fail.

## Classification

**TP:** a risky practice in a file the project uses to install or run code. **BD (by design):** accurate, but no
weakness here (an uninstalled or deliberately broken fixture, code run on purpose, or a practice the rule cannot tell
from a risky one). **FP:** wrong.

| rule | findings | TP | BD | FP | severity |
| --- | --- | --- | --- | --- | --- |
| WS-LK-003 missing-integrity | 1,251 | 561 | 690 | 0 | medium |
| WS-LK-002 non-registry-resolution | 250 | 1 | 249 | 0 | medium/high |
| WS-LC-001 install-lifecycle-script | 37 | 2 | 35 | 0 | low/medium |
| WS-SC-900 file-not-checked | 31 | 0 | 31 | 0 | high |
| WS-LC-004 package-manager-runs-repo-code | 17 | 0 | 17 | 0 | high |
| WS-GH-005 secret-to-file-or-network | 3 | 0 | 3 | 0 | high |
| WS-PS-002 agent-settings-command | 1 | 0 | 1 | 0 | high |
| WS-EX-001 exfil-endpoint | 1 | 0 | 0 | **1** | medium |
| **total** | **1,591** | **564** | **1,026** | **1** | |

No other rule fired; the 13 files named `bundle.js` are an IOC only with a payload hash, and none matched. 1,001 of
the 1,026 by-design findings are under test, fixture, example or template directories. Rule by repository:

| rule | react | webpack | babel | prettier | storybook | next.js | vite | svelte | astro | TypeScript | undici | nest | cli | express | eslint | total |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WS-EX-001 | . | . | . | . | . | . | . | . | 1 | . | . | . | . | . | . | 1 |
| WS-GH-005 | . | . | . | . | 1 | . | . | . | 1 | . | . | . | . | . | 1 | 3 |
| WS-LC-001 | 6 | . | 1 | . | 4 | 7 | 2 | . | . | . | . | 1 | 16 | . | . | 37 |
| WS-LC-004 | . | . | 4 | 3 | 10 | . | . | . | . | . | . | . | . | . | . | 17 |
| WS-LK-002 | . | . | . | . | . | 1 | . | . | 1 | . | . | . | 248 | . | . | 250 |
| WS-LK-003 | 675 | . | . | . | . | . | . | . | . | . | . | . | 576 | . | . | 1251 |
| WS-PS-002 | 1 | . | . | . | . | . | . | . | . | . | . | . | . | . | . | 1 |
| WS-SC-900 | . | . | 2 | . | . | 3 | . | . | 1 | . | . | . | 23 | . | 2 | 31 |
| lockfile control | passed | passed | passed | passed | passed | passed | passed | passed | passed | passed | passed | passed | passed | no lockfile | no lockfile | |

## Notes by rule

### WS-LK-003 missing-integrity (1,251)

- **TP, 561:** npm/cli's root lockfile pins no hash for them, so `npm ci` takes what the registry serves: 534 nearly
  all development dependencies, and 27 top-level `inBundle` entries (such as `chalk@5.6.2`, `ms@2.1.3`) npm fetches
  like any other (checked under npm 10.9.2 and 12.2.0).
- **BD, 690:** react's `fixtures/ssr2/package-lock.json` (675) and 15 in npm/cli's arborist fixtures.
- Fixed: the first run's 5,670 false positives in react's 19 Yarn 1 lockfiles, whose `resolved` URLs end in the
  tarball's SHA-1 (`#<40 hex>`), which Yarn 1.22.22 verifies (`ssri.fromHex(this.hash, 'sha1')`).

### WS-LK-002 non-registry-resolution (250)

- **TP, 1:** next.js's `ci-info@2.0.0`, from a GitHub codeload tarball.
- **BD, 249:** 248 in npm/cli's arborist fixtures (git sources, `file:` tarballs, `${REGISTRY}` placeholders, a
  240-entry `sax` fixture), and astro's `fake-data-pkg` test tarball.

### WS-LC-001 install-lifecycle-script (37)

- **TP, 2:** vite's `preinstall: npx only-allow pnpm` and next.js `examples/with-xata`'s
  `postinstall: npx @xata.io/cli@latest ...`, unpinned packages run at install.
- **BD, 35:** dev hooks in private root manifests (react, babel, storybook `husky`, next.js, vite
  `simple-git-hooks`; low), examples and templates (next.js, storybook `agent-eval`), 16 npm/cli lifecycle fixtures
  and 4 next.js `binding.gyp` fixtures. Three are medium, the manifest not being `private`, though never published
  from there: nest's `@nestjs/core` (the published 12.1.2 has no scripts), `react-forgive` and `snap`.

### WS-SC-900 file-not-checked (31)

- **BD, 31:** deliberately invalid manifests and lockfiles (babel, eslint, npm/cli), `file:` tarballs and
  dependencies wormsign does not unpack (next.js, astro, npm/cli), npm/cli's `yarn-stuff/yarn.lock` (with
  `meta: "this is not a priority entry"`, which Yarn 1 never writes), and next.js's `.claude/skills` symlink to
  `../.agents/skills`, which Claude Code follows ([rules.md](../rules.md), WS-PS-002).
- Fixed: the first run's false positive on babel's `yarn.lock` (line 8: `"$repo-utils"`, a Yarn 4 `link:` entry).

### WS-LC-004 package-manager-runs-repo-code (17)

- **BD, 17** (a rule new since the first run): committed Yarn releases and plugins, run on every `yarn` command, and
  the `.yarnrc.yml` files naming them. babel: `.yarn/releases/yarn-4.17.0.cjs`, two plugins,
  `.yarnrc.yml`; prettier: `.yarn/releases/yarn-4.18.1.cjs`, one plugin, `.yarnrc.yml`; storybook:
  `.yarn/releases/yarn-4.18.0.cjs`, the root `.yarnrc.yml` and 8 under `test-storybooks/`. Baselined once, a changed
  release is reported again. Any Yarn 4 project that commits its release fails this way: prettier passed the first
  run and fails this one for that alone.

### WS-GH-005 secret-to-file-or-network (3)

- **BD, 3:** storybook `handle-release-branches.yml:39`, astro `examples-deploy.yml:23` and eslint
  `rebuild-docs-sites.yml:20` `curl -X POST` a Netlify build hook whose URL or token is the secret.

### WS-PS-002 agent-settings-command (1)

- **BD, 1 (react `.claude/settings.json:8`):** a hook that only prints a file:

  ```text
  Claude Code SessionStart hook runs automatically in sessions in this repository: at once under claude -p or
  the SDK, after the trust prompt in an interactive session: if [[ "$PWD" != */compiler* ]]; then cat .claude/instructions.md 2>/dev/null || true; fi
  ```

  No `.vscode/tasks.json` (TypeScript, next.js, astro) runs on folder open; storybook's two `.mcp.json` files declare
  an HTTP server and none.

### WS-EX-001 exfil-endpoint (1)

- **FP, 1 (astro `packages/astro/test/units/dev/sec-fetch.test.ts:160`):** a made-up `ngrok.io` subdomain as an
  `Origin` header in a unit test. Medium, so it does not fail the default gate.

### WS-GH-003 pull-request-target-head-checkout (0)

Fixed: the first run's 4 false positives (react's `runtime_commit_artifacts.yml`, lines 287, 295, 461, 469), a
`git show ${{ ... github.event.workflow_run.head_sha ... }} --no-patch`. The rule now needs a git command that
fetches, checks out or applies code (`fetch`, `checkout`, `switch`, `worktree`, `reset`, `merge`). Spot checks of the
other `pull_request_target` and `workflow_run` workflows (babel, next.js, storybook, npm/cli, undici, prettier, react
sizebot) found no checkout of pull request code.

## Changes since the first run

Two earlier runs over the same checkouts were not published: the first (2026-10-02) found 7,250 findings and 5,676
false positives, and a second (2026-10-09, before the fixes) 7,249 and 5,676, with babel's control failing both times.

| Runs | Scanner change | Findings |
| --- | --- | --- |
| first to second | `binding.gyp` read as an install script | +4 WS-LC-001 in next.js test fixtures (BD) |
| first to second | a stricter Yarn 1 reader fails closed on npm/cli's `yarn-stuff/yarn.lock` | +1 WS-SC-900, −4 WS-LK-002 and −2 WS-LK-003 it gave before (all BD) |
| second to this page | Yarn 1 `#sha1` fragments read as integrity | −5,670 WS-LK-003 in react (FP) |
| second to this page | Yarn 4 `link:`, `portal:`, `workspace:` entries local by any name | −1 WS-SC-900 in babel (FP); babel's control passes |
| second to this page | the stricter [WS-GH-003](#ws-gh-003-pull-request-target-head-checkout-0) | −4 WS-GH-003 in react (FP) |
| second to this page | new rule WS-LC-004 | +17 WS-LC-004 in babel, prettier and storybook (BD) |

Every other finding is unchanged, at the same file and line. The fixes have tests and mutants (`core-lockfile`,
`core-workflows`).

This page's run is of 0ff5d3e's src tree. Against the published 2026-10-09 run (21:38 UTC) only the 18 WS-SC-900 keys
and fingerprints changed (the key now digests the reason). Runs at these earlier src trees gave the same findings and
notes, byte for byte but `scanner` and `retrieved`, so the review fixes to `scan` after d37a961 (property paths read
as GitHub reads them, a `${{` in a comment, the line breaks YAML reads) changed nothing here:

| src tree | Run (UTC) |
| --- | --- |
| `d89b7aadc0b88b9624b0a742948ed30d71140e19` (7bb2879, before the Python PR-mode change) | 2026-10-15 15:18 to 15:25 |
| `db08c840a6131252b6e384d677f35e811d4459f5` (d37a961) | 2026-10-14 21:34 to 21:45 |
| `c1193a069f361499a6cd381b1f88a59afb8cbb3f` | 2026-10-10 00:49 to 00:57 |
| `a5401f7eb596d6f8d75ad8e6dfa8151afb4f6b6d` | 2026-10-10 02:24 to 02:30 |
| `626e519dfa49624b0fbc4c75b5d61888a9e7d6c3` | 2026-10-10 03:51 to 03:57 |
| `35c6caa6607f134537d0f1a9f78842ee5a7d7a7a` | 2026-10-10 05:12 to 05:18 |
| `415fd1a4dc6d25a696fe65ca93b86343af288002` | 2026-10-10 05:58 to 06:04 |
| `927c90b8e183988b5eafb451232471683c140dee` | 2026-10-11 03:16 to 03:23 |
| `169249d4a5c159d4901aceafe61fb003b669b150` | 2026-10-12 06:49 to 06:57 |

None of the 227 workflows uses a YAML form the reader now reports as not checked (flow or JSON form, flow jobs or
steps, aliases, merge keys). A new note names Python inputs `scan` does not read: 1 in storybook
(`agent-eval/scripts/compare_stats.py.lock`), 42 in TypeScript.

## soak's Python side on the same corpus

[`scripts/fp-corpus-soak.mjs`](../../scripts/fp-corpus-soak.mjs) runs `wormsign soak --no-baseline --no-osv` over the
checkouts, with the npm registry on a closed local port (npm's half fails at once, sending nothing) and the default
Python index. Run 2026-10-16 at 04:25 UTC, same code and machine:

| rule | findings | TP | BD | FP | severity |
| --- | --- | --- | --- | --- | --- |
| WS-SK-002 | 42 | 0 | 42 | 0 | high |

- **BD, 42 (TypeScript):** compiler test baselines under `tsc/testdata/baselines/reference/` match the
  requirements-file name rule (`constraints`, `.txt`) but hold lines that are no requirement, so `soak` reports them
  rather than pass over them. One `ignorePaths` entry (`tsc/testdata/baselines`) clears all 42.
- **The other 14: 0.** storybook's PEP 723 script lock pins 16 versions, 443 files, all on pypi.org and older than 7
  days.

A deliberate trade: `soak` reports the 42 rather than note them, because a note can hide a file pip installs from
(a `file:pkgdir` line, a `# coding:` line, a U+001F). Earlier code noted them (the 2026-10-10 runs at 00:59 and
02:30 UTC) or read them as requirements files (2,459 WS-SK-002).

The runs at src trees `415fd1a4` (2026-10-10 06:04 UTC), `927c90b8` (2026-10-11 03:23 UTC), `169249d4` (2026-10-12 06:56
UTC), `db08c840` (d37a961, 2026-10-14 21:45 UTC) and `d89b7aad` (7bb2879, before the Python PR-mode change, 2026-10-15
15:27 UTC) gave the same PyPI results as this one. The corpus has no `pyproject.toml`, `setup.py`, `setup.cfg` or
`Pipfile`, so it says nothing about the manifest rules or `diff`'s build check
([WS-DF-005](../cli/diff.md#a-python-build-changed-expected-on-ordinary-pull-requests)).

## Reproduce

```sh
npm run build
node scripts/fp-corpus.mjs --work /tmp/fp-corpus --out /tmp/fp-corpus.json
jq -S '[.results[] | {repo, sha, lockfiles, workflows, lockfileControl, findings}]' /tmp/fp-corpus.json | shasum -a 256
jq -S '[.results[] | {repo, sha, lockfiles, workflows, lockfileControl, findings}]' docs/evidence/data/fp-corpus.json | shasum -a 256
```

It needs `git`, github.com and about 2 GB of disk, takes 6 to 11 minutes (about a minute and a half over the same
`--work`), and refuses uncommitted changes in `src/` or `data/iocs/`. From the same code the two `jq` digests match:
`402a592bdfa0c5e648c9b5c4d2d5d62b33b275a37a4c5412716ddd79b84c327f`. Then (about 35 seconds, 16 requests to pypi.org):

```sh
node scripts/fp-corpus-soak.mjs --work /tmp/fp-corpus --out /tmp/fp-corpus-soak.json
```
