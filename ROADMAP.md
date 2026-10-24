# Roadmap

What comes after 0.1.0, in priority order. One maintainer works through it, best effort; nothing here has a date.

## Next

The immediate release adds a beta TypeScript/JavaScript scanning API, declarations and runnable examples, with
verification against the installed tarball ([release checklist](docs/release-readiness.md)).

A separate experimental milestone is automatic protection for a shared development sandbox used by multiple
coding agents. It needs a trusted execution boundary, verified package intake, recovery and whole-task evaluation;
the library reports observations and does not grant execution authority. That sandbox implementation is outside
this library release.

1. **A private-mirror mode for `soak`** ([#3](https://github.com/stgllghr/wormsign/issues/3)) (Artifactory and the like), as [ADR 0007](docs/adr/0007-private-registry-mirrors.md)
   decides: the public registries witness by default, with the mirror's URLs kept, private names declared and
   reported at medium, and an unclassified npm scope stopping the run; the mirror's own metadata, with a read-only
   token, by opt-in; a configurable OSV endpoint. *Why:* today every package from a private
   registry fails closed (WS-SK-002) unless the registry serves publish times without credentials (the Action's
   `registry` input), so those shops cannot use the gate.
2. **A CODEOWNERS approval route for baseline changes,** ([#4](https://github.com/stgllghr/wormsign/issues/4)) opt-in, as [ADR 0008](docs/adr/0008-baseline-approval-route.md)
   decides: two pull requests, every guard verified or WS-DF-005 stays high. *Why:* a baseline change always fails
   its own pull request (WS-DF-005) and merges only by overriding a required check; a code-owner approval is
   narrower and leaves a record.
3. **Monorepo performance:** ([#5](https://github.com/stgllghr/wormsign/issues/5)) one `git cat-file --batch` instead of one `git show` process per file. *Why:* `diff`
   and PR-mode `soak` start a process for every file they read from git.
4. **Real-log and SIEM validation of the detections** ([#6](https://github.com/stgllghr/wormsign/issues/6)), in this order:
   1. capture real audit-log, job-log and process events from a sandbox GitHub organization replaying each wave, to
      replace the examples written to fit the rules and check the field values they assume, first the
      `job_workflow_ref` that WS-AL-004's job rule depends on;
   2. run the committed Splunk and ES|QL queries in Splunk and Elasticsearch containers in CI, over the examples and
      the hour-boundary burst, instead of the test's models;
   3. measure each rule's alert volume on 30 to 90 days of a real organization's logs (first WS-AL-002's medium
      rule, WS-CI-005 and WS-EP-001's Bun branches), and set levels from it;
   4. publish a wave-by-rule table of whether each rule would have fired.

   *Why:* their tests use inert, synthetic events only, and the converted queries have never run in a SIEM.
5. **A human-labelled false-positive study on a held-out corpus.** ([#7](https://github.com/stgllghr/wormsign/issues/7)) *Why:* the published figure comes from the corpus
   the scanner was tuned on, labelled by an AI agent ([evidence](docs/evidence/false-positives.md)).
6. **A second maintainer.** ([#8](https://github.com/stgllghr/wormsign/issues/8)) *Why:* with one owner, code-owner review cannot bind the owner's own changes, and every
   response waits on one person.
7. **Measured overlap with zizmor:** ([#9](https://github.com/stgllghr/wormsign/issues/9)) run zizmor on the 15-repository corpus and compare its findings with WS-GH-001
   to WS-GH-007. *Why:* the [overlap table](docs/positioning.md#the-workflow-rules-against-zizmor-and-actionlint)
   comes from zizmor's docs, and [ADR 0009](docs/adr/0009-scope-of-0-1-0.md) keeps WS-GH-003 and WS-GH-004 until it is measured.
8. **A manifest/lock drift check:** ([#10](https://github.com/stgllghr/wormsign/issues/10)) compare the lock's root entries with the manifest, and report WS-SK-002 on a
   mismatch. *Why:* `soak` checks the lock, not the manifest, so a `package.json` dependency the lock lacks gives no
   finding, and `npm install` or Yarn 1 installs it fresh ([assumed setup](docs/threat-model.md#attacker)).
9. **`diff` flags installs outside the lock** ([#11](https://github.com/stgllghr/wormsign/issues/11)) it can see: an added pre-commit repository, and `npx` or `pip install`
   in a `package.json` script. *Why:* they install packages no lock pins, with no finding today
   ([out of scope](docs/threat-model.md#out-of-scope)).
10. **A differential test harness for requirements files:** ([#12](https://github.com/stgllghr/wormsign/issues/12)) generated requirements files read by pinned pip and uv
    offline, compared with soak's reading; every split is a test. *Why:* ten review rounds of the Python PR-mode
    change found pip/uv splits one at a time (comments and glued backslashes on continued lines, an option's value
    read to the line break, `..` through a symlink, lines pip refuses that uv installs), each from a hand-written
    repro; a generator that varies separators, continuations, options and paths would find the next ones before a
    reviewer does, and record both tools' readings as fixtures.
11. **Install-script severity from what the script runs:** ([#13](https://github.com/stgllghr/wormsign/issues/13)) high when it runs a file the same change adds, or a file
    with an IOC payload name. *Why:* a root `preinstall: node setup.mjs`, the 2026 wave's shape, is medium in `diff`
    (WS-DF-002) and low or medium in `scan` (WS-LC-001), while a `.vscode/tasks.json` that runs the same file is high.

## Deliberately out of scope

- **Per-tool-call agent hooks as the execution boundary.** A hook alone cannot contain nested commands or
  arbitrary downloaders. Runtime enforcement for shared sandboxes is a separate milestone above; the agent skill
  remains guidance ([ADR 0006](docs/adr/0006-skill-is-guidance.md)).
- **A hosted service.** wormsign runs from the repository and public APIs, with no account and no telemetry. A
  service would add both, and one more party to trust.
- **Imitating installer parsers.** A model of pip, uv or npm that is wrong passes what the installer installs
  ([ADR 0004](docs/adr/0004-no-installer-parser-imitation.md)).

## Known limits

Listed in [soak.md's limitations](docs/soak.md#limitations), its
[Python limitations](docs/soak.md#python-limitations) and the
[threat model's out-of-scope list](docs/threat-model.md#out-of-scope). Each item above has an issue; the
[`roadmap` label](https://github.com/stgllghr/wormsign/issues?q=label%3Aroadmap) also holds the `dir:`-mode
symlink limit ([#14](https://github.com/stgllghr/wormsign/issues/14)).
