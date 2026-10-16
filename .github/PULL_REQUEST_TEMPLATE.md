## What and why

<!-- What this changes, why, and the issue it closes ("Closes #123"). One change per pull request. -->

## How it was tested

<!-- The test that covers it, and how you saw that test fail with the change reverted. Paste command output where it helps. -->

## Checklist

See CONTRIBUTING.md for what each item means. Tick an item or say why it does not apply.

- [ ] No npm runtime dependency added (`dependencies` in `package.json` stays absent, and nothing new is vendored); `src/vendor/` changes only through `scripts/verify-vendor.mjs --write`; no new development dependency without a reason given above.
- [ ] Fails closed: anything the change cannot check is reported as a finding, not passed silently.
- [ ] Every behaviour change has a test, and I watched that test fail with the change reverted.
- [ ] A new or changed rule is in `src/rules.ts`, has a scenario in `test/validation-coverage.test.ts`, a mutant in `scripts/mutants-<module>.mjs` and an entry in `RULE_META` in `scripts/gen-rules-doc.mjs`; `docs/rules.md` was regenerated with `npm run docs:rules` and committed; the rule is in the rule-coverage table of `docs/validation.md`, and its rule counts (the at-a-glance row and section 1) are right.
- [ ] A new IOC has an https `source`, is copied exactly as that page prints it, and is listed above with the source URL, a quote of the surrounding text and (if you have it) the SHA-256 of your saved copy; `"version"` is updated in all five `data/iocs` files. (The maintainer runs `scripts/verify-ioc-sources.mjs` against the recorded snapshots.)
- [ ] No network use added to `scan` or `diff`; no telemetry.
- [ ] Changes to `test/golden/` were regenerated with `UPDATE_GOLDEN=1 npm test` (`UPDATE_NPM_SOAK_GOLDEN=1` for `npm-soak-identical.json`, which only a change meant to alter npm output may touch) and reviewed line by line.
- [ ] Any `.wormsign-baseline.json` entry has a fingerprint, a real justification and, where possible, an expiry date, explained above.
- [ ] Non-obvious platform facts (package-manager settings, GitHub behaviour, API fields) cite their documentation in a comment.
- [ ] `npm test`, `npm run lint`, `npm run self-scan` and `shellcheck harden-dev.sh scripts/*.sh` pass locally; `npm run mutation` too if a rule or a fail-closed path changed.
- [ ] Fixtures are synthetic and inert: no real malware, payloads or credentials.
