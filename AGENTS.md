# AGENTS.md

## Layout
- `src/`: the TypeScript CLI (args in `src/main.ts`, entry `dist/src/cli.js`); `src/python/`: PyPI readers and soak.
- `test/`: `*.test.ts`, inert `fixtures/`, `golden/`; `scripts/`: test runner, CI and maintainer tools, mutants.
- `data/iocs/`: IOC data; `docs/`; `detections/`: SIEM rules; `harden-dev.sh`; `action.yml`: the GitHub Action.
- `plugins/wormsign/`: the agent skill and its plugin (skill files stay plain ASCII).

## Build and test
- Install with `npm ci --ignore-scripts` on Node 24.14.1 or later (npm 11.10 or later enforces `.npmrc`'s
  `min-release-age`); the CLI itself supports Node 22 or later.
- `npm run build` compiles to `dist/`; `npm test` builds, then runs every test.
- One file: `npm run build && node scripts/run-tests.mjs dist/test/<name>.test.js`.
- Never run bare `node --test`: it leaks temp dirs. `scripts/run-tests.mjs` owns and removes them.
- Opt-in tests:
  - Real pip and uv: `HARDEN_REAL=1` with `HARDEN_REAL_PYTHON=<python3 with pip 26.1.2 or 26.2.1>` and
    `HARDEN_REAL_UV=<uv 0.10.9 or 0.12.21>`; without them it may pick an unpinned `/usr/bin/python3` and fail.
    Full recipe: the header of `test/harden-real.test.ts`.
  - `WORMSIGN_PIP_REF=<venv with pip 26.1.2 or 26.2.1>`: live pip differential.
  - `WORMSIGN_REQUIRE_PYTHON=1` makes the Python differentials fail instead of skip without python3.

## Before you finish
- `npm test`, `npm run lint` and `npm run self-scan` (any unbaselined finding fails).
- `npm run mutation -- --check`: every mutant's text still occurs exactly once.
- `shellcheck harden-dev.sh scripts/*.sh` if shell changed; `actionlint` if workflows changed.
- Rules changed: update `RULE_META` in `scripts/gen-rules-doc.mjs`, run `npm run docs:rules`, commit `docs/rules.md`.

## Tests and mutants
- Every behaviour change needs a test that fails when the change is reverted. Revert it and watch it fail.
- Add a mutant for it to `scripts/mutants-<module>.mjs` (18 per module at most) and run
  `npm run mutation -- --only "<name>"` until it prints `killed`. `--list-modules` names the modules.
- Each mutant is a full suite run and the suite has timing assertions: run one at a time, on an idle machine.
- SARIF golden: `UPDATE_GOLDEN=1 npm test`, then review `git diff test/golden/` line by line.
- `test/golden/npm-soak-identical.json` changes only on purpose, with `UPDATE_NPM_SOAK_GOLDEN=1 npm test`.

## Rules
- Fail closed: what can't be verified is a finding (WS-SC-900, WS-SK-002, ...), never a pass.
- Bad input is a `UsageError`, never a finding: exit 2 with a message (caught in `run()`, `src/main.ts`). That covers
  a bad argument, baseline or IOC file and a git object `diff` cannot read. A checked file that cannot be read or
  parsed is a finding (WS-SC-900, WS-DF-006).
- A heuristic may shape a finding, never hide one. Never close a gap by imitating pip, uv or npm more closely.
- `scan` and `diff` never use the network.
- Never send private package names to a public registry or OSV. ADR 0007's public witness, not yet built, will send an
  unscoped name the adopter did not declare private.
- Never run `harden-dev.sh` with your real `HOME`; use `npm run test:harden`.
- Never install or fetch malicious packages: tests use inert fixtures and a fake network.
- No npm runtime dependencies. `src/vendor/smol-toml/` stays byte-identical (the build checks `VENDORED.json`).
- Keep heavy CI jobs (mutation, macOS) off pull requests: schedule or `workflow_dispatch` with `slow` only.
- Docs describe only what ships; their counts match the test and mutant output.

Procedures for IOCs, rules, baselines and releases: [CONTRIBUTING.md](CONTRIBUTING.md).
