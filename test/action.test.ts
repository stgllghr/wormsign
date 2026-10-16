// Tests for scripts/ci-action.mjs, the runner behind the composite GitHub Action (action.yml): how inputs become CLI
// arguments, and what the action reports for the inert fixtures in test/fixtures/action that action-selftest.yml
// also runs through `uses: ./`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const SCRIPT = join(ROOT, "scripts", "ci-action.mjs");
const CLI = join(ROOT, "dist", "src", "cli.js");

type Env = Record<string, string>;
type Plan = { command: string; args: string[]; warning?: string; baselineFrom?: string };
type Sarif = { runs: ({ automationDetails?: { id: string }; results: { ruleId: string; level: string; partialFingerprints: Record<string, string> }[] } & Record<string, unknown>)[] } & Record<string, unknown>;
type Mod = {
  GATE: string[];
  plan(env: Env): Plan;
  plans(env: Env): Plan[];
  gateSarif(docs: { command: string; sarif: Sarif }[]): Sarif;
  stepSummary(reports: { command: string; report: { notes?: unknown[] } }[]): string;
  sarifUpload(env: Env): { upload: boolean; notice?: string };
  activeFindings(r: { findings: { suppressed?: unknown }[] }): number;
  safeLine(text: string): string;
  workflowCommand(name: string, message: string): string;
  escapeData(s: string): string;
  escapeProperty(s: string): string;
};
const mod = (): Promise<Mod> => import(pathToFileURL(SCRIPT).href) as Promise<Mod>;

test("action: an empty command is the gate on pull_request (diff, scan, soak --base, each as its own call plans it) and scan on any other event", async () => {
  const { GATE, plan, plans } = await mod();
  const pr = { GITHUB_EVENT_NAME: "pull_request", WS_BASE: "b".repeat(40), WS_HEAD: "h".repeat(40) };
  assert.deepEqual(GATE, ["diff", "scan", "soak"]);
  assert.deepEqual(plans(pr), [
    { command: "diff", args: ["diff", "b".repeat(40), "h".repeat(40)] },
    { command: "scan", args: ["scan", "."], baselineFrom: "b".repeat(40) },
    { command: "soak", args: ["soak", ".", "--base", "b".repeat(40)] },
  ]);
  // Exactly what three Action calls with command diff, scan and soak plan, whatever the other inputs say.
  const inputs = { ...pr, WS_PATH: "app", WS_FAIL_ON: "medium", WS_MIN_AGE: "3d", WS_REQUIRE_CONFIG: "true", WS_ON_OUTAGE: "warn", WS_NO_BASELINE: "true" };
  assert.deepEqual(plans(inputs), GATE.map((command) => plan({ ...inputs, WS_COMMAND: command })));
  // An explicit command is that command alone, as before.
  for (const command of ["diff", "scan", "soak"]) assert.deepEqual(plans({ ...pr, WS_COMMAND: command }), [plan({ ...pr, WS_COMMAND: command })], command);
  for (const event of ["push", "schedule", "workflow_dispatch", "merge_group", ""]) {
    assert.deepEqual(plans({ GITHUB_EVENT_NAME: event, WS_HEAD: "h".repeat(40) }), [{ command: "scan", args: ["scan", "."] }], event);
  }
});

test("action: on-outage warn reaches soak as --on-outage warn, and only soak; fail is the default; anything else is an error", async () => {
  const { plan } = await mod();
  assert.deepEqual(plan({ WS_COMMAND: "soak", WS_ON_OUTAGE: "warn" }).args, ["soak", ".", "--on-outage", "warn"]);
  for (const v of ["fail", "", " "]) assert.deepEqual(plan({ WS_COMMAND: "soak", WS_ON_OUTAGE: v }).args, ["soak", "."], JSON.stringify(v));
  assert.deepEqual(plan({ WS_COMMAND: "scan", WS_ON_OUTAGE: "warn" }).args, ["scan", "."]);
  assert.deepEqual(plan({ WS_COMMAND: "diff", WS_BASE: "a", WS_HEAD: "b", WS_ON_OUTAGE: "warn" }).args, ["diff", "a", "b"]);
  // Checked for every command, so a typo is never a silent fail.
  for (const command of ["scan", "soak"]) assert.throws(() => plan({ WS_COMMAND: command, WS_ON_OUTAGE: "warning" }), /on-outage must be "fail" or "warn", got "warning"/, command);
  const yml = readFileSync(join(ROOT, "action.yml"), "utf8");
  assert.match(yml, /\n {2}on-outage:\n(?: {4}.*\n| {6}.*\n)*? {4}default: "fail"\n/, "an input, fail by default");
  assert.match(yml, /\n {8}WS_ON_OUTAGE: \$\{\{ inputs\.on-outage \}\}\n/, "passed to the wrapper");
});

test("action: the gate's SARIF is one run per command, each the command's own run plus its category", async () => {
  const { gateSarif } = await mod();
  const doc = (ruleId: string): Sarif => ({ $schema: "s", version: "2.1.0", runs: [{ tool: { driver: { name: "wormsign" } }, results: [{ ruleId, level: "error", partialFingerprints: { "wormsign/v1": ruleId } }] }] });
  const merged = gateSarif([{ command: "diff", sarif: doc("WS-DF-001") }, { command: "soak", sarif: doc("WS-SK-001") }]);
  assert.deepEqual(merged, {
    $schema: "s",
    version: "2.1.0",
    runs: [
      { ...doc("WS-DF-001").runs[0], automationDetails: { id: "wormsign-diff/" } },
      { ...doc("WS-SK-001").runs[0], automationDetails: { id: "wormsign-soak/" } },
    ],
  });
  assert.throws(() => gateSarif([]), /no SARIF to combine/);
});

test("action: the step summary shows each command's UNVERIFIED line, escaped, and nothing without one", async () => {
  const { stepSummary } = await mod();
  assert.equal(stepSummary([{ command: "soak", report: { notes: ["1 package version(s) checked", "warning: x"] } }]), "");
  const s = stepSummary([{ command: "diff", report: { notes: [] } }, { command: "soak", report: { notes: ["UNVERIFIED: 2 packages not checked (registry.npmjs.org unreachable: HTTP 503); --on-outage warn", "UNVERIFIED: <b>&\u202e"] } }]);
  assert.match(s, /^### wormsign: packages not verified\n\n- `soak`: UNVERIFIED: 2 packages not checked \(registry\.npmjs\.org unreachable: HTTP 503\); --on-outage warn\n- `soak`: UNVERIFIED: &lt;b&gt;&amp;\\u202e\n/);
});

test("action: on pull_request_target, workflow_run and issue_comment, which check out the base branch, the default command is an error", async () => {
  const { plan } = await mod();
  const sha = "s".repeat(40);
  for (const event of ["pull_request_target", "workflow_run", "issue_comment"]) {
    assert.throws(() => plan({ GITHUB_EVENT_NAME: event, GITHUB_SHA: sha, WS_HEAD: sha }), new RegExp(`on ${event} the default checkout and github\\.sha are the base branch, not the change, so the default command would check trusted code and pass`), event);
    // diff with head left at github.sha (the base branch tip there) never sees the change either.
    assert.throws(() => plan({ GITHUB_EVENT_NAME: event, GITHUB_SHA: sha, WS_COMMAND: "diff", WS_BASE: "b".repeat(40), WS_HEAD: sha }), /so diff with head s+ \(github\.sha, the default\) never sees the change/, event);
    assert.deepEqual(plan({ GITHUB_EVENT_NAME: event, GITHUB_SHA: sha, WS_COMMAND: "diff", WS_BASE: "b".repeat(40), WS_HEAD: "h".repeat(40) }), { command: "diff", args: ["diff", "b".repeat(40), "h".repeat(40)] });
    // An explicit scan runs, with a warning that it checks whatever was checked out.
    assert.match(plan({ GITHUB_EVENT_NAME: event, GITHUB_SHA: sha, WS_COMMAND: "scan" }).warning ?? "", /scan checks whatever the workflow checked out \(path "\."\)/, event);
  }
  const r = runAction({ GITHUB_EVENT_NAME: "pull_request_target", GITHUB_SHA: sha, WS_HEAD: sha });
  try {
    assert.equal(r.status, 2);
    assert.match(r.stdout, /^::error title=wormsign action::on pull_request_target the default checkout/m);
  } finally {
    rmSync(r.dir, { recursive: true, force: true });
  }
});

test("action: diff needs both revisions, and passes path as --dir only when it is not the default", async () => {
  const { plan } = await mod();
  assert.throws(() => plan({ WS_COMMAND: "diff", WS_HEAD: "abc" }), /diff needs base and head/);
  assert.throws(() => plan({ WS_COMMAND: "diff", WS_BASE: "abc" }), /diff needs base and head/);
  assert.deepEqual(plan({ WS_COMMAND: "diff", WS_BASE: "a", WS_HEAD: "b", WS_PATH: "pkg" }).args, ["diff", "a", "b", "--dir", "pkg"]);
  assert.deepEqual(plan({ WS_COMMAND: "diff", WS_BASE: "a", WS_HEAD: "b", WS_PATH: " . " }).args, ["diff", "a", "b"]);
});

test("action: soak options map to their flags; --config-only drops --base", async () => {
  const { plan } = await mod();
  assert.deepEqual(plan({ WS_COMMAND: "soak", WS_BASE: "a", WS_MIN_AGE: "3d", WS_OSV: "false", WS_REQUIRE_CONFIG: "true" }).args, [
    "soak", ".", "--base", "a", "--require-config", "--min-age", "3d", "--no-osv",
  ]);
  assert.deepEqual(plan({ WS_COMMAND: "soak", WS_BASE: "a", WS_CONFIG_ONLY: "true", WS_OSV: "true" }).args, ["soak", ".", "--config-only"]);
  // Defaults: OSV on, no base outside a pull request, CLI default min-age and PyPI index.
  assert.deepEqual(plan({ WS_COMMAND: "soak" }).args, ["soak", "."]);
  assert.deepEqual(plan({ WS_COMMAND: "soak", WS_PYPI_INDEX: " " }).args, ["soak", "."]);
});

test("action: pypi-index is passed to soak as --pypi-index, one argument, and only to soak", async () => {
  const { plan } = await mod();
  const index = "https://pypi.corp.example/simple/ --no-osv";
  assert.deepEqual(plan({ WS_COMMAND: "soak", WS_PYPI_INDEX: index }).args, ["soak", ".", "--pypi-index", index]);
  assert.deepEqual(plan({ WS_COMMAND: "soak", WS_PYPI_INDEX: "https://pypi.org/simple/", WS_CONFIG_ONLY: "true" }).args, ["soak", ".", "--config-only", "--pypi-index", "https://pypi.org/simple/"]);
  assert.ok(!plan({ WS_COMMAND: "scan", WS_PYPI_INDEX: "https://pypi.org/simple/" }).args.includes("--pypi-index"));
  const yml = readFileSync(join(ROOT, "action.yml"), "utf8");
  assert.match(yml, /\n {2}pypi-index:\n(?: {4}.*\n| {6}.*\n)*? {4}default: ""\n/, "an input, empty by default");
  assert.match(yml, /\n {8}WS_PYPI_INDEX: \$\{\{ inputs\.pypi-index \}\}\n/, "passed to the wrapper");
});

test("action: registry-host reaches scan and diff as one --registry-host per host, registry reaches soak as --registry, each one argument", async () => {
  const { plan, plans } = await mod();
  const hosts = { WS_REGISTRY_HOST: " acme.jfrog.io, npm.example.com:8443 " };
  assert.deepEqual(plan({ WS_COMMAND: "scan", ...hosts }).args, ["scan", ".", "--registry-host", "acme.jfrog.io", "--registry-host", "npm.example.com:8443"]);
  assert.deepEqual(plan({ WS_COMMAND: "diff", WS_BASE: "a", WS_HEAD: "b", WS_PATH: "pkg", ...hosts, WS_FAIL_ON: "medium" }).args, [
    "diff", "a", "b", "--dir", "pkg", "--registry-host", "acme.jfrog.io", "--registry-host", "npm.example.com:8443", "--fail-on", "medium",
  ]);
  // soak has no --registry-host (the CLI would refuse it); registry is its flag, and only its.
  const registry = "https://acme.jfrog.io/artifactory/api/npm/npm/ --no-osv";
  assert.deepEqual(plan({ WS_COMMAND: "soak", ...hosts, WS_REGISTRY: registry }).args, ["soak", ".", "--registry", registry]);
  for (const [command, extra] of [["scan", {}], ["diff", { WS_BASE: "a", WS_HEAD: "b" }]] as const) {
    assert.ok(!plan({ WS_COMMAND: command, WS_REGISTRY: registry, ...extra }).args.includes("--registry"), command);
  }
  // Empty, the default, or blank passes nothing.
  for (const v of ["", " "]) {
    assert.deepEqual(plan({ WS_COMMAND: "scan", WS_REGISTRY_HOST: v }).args, ["scan", "."], JSON.stringify(v));
    assert.deepEqual(plan({ WS_COMMAND: "soak", WS_REGISTRY: v }).args, ["soak", "."], JSON.stringify(v));
  }
  // The gate gives each command the flag it takes.
  const gate = plans({ GITHUB_EVENT_NAME: "pull_request", WS_BASE: "b".repeat(40), WS_HEAD: "h".repeat(40), WS_REGISTRY_HOST: "acme.jfrog.io", WS_REGISTRY: "https://acme.jfrog.io/npm/" });
  assert.deepEqual(gate.map((p) => p.args), [
    ["diff", "b".repeat(40), "h".repeat(40), "--registry-host", "acme.jfrog.io"],
    ["scan", ".", "--registry-host", "acme.jfrog.io"],
    ["soak", ".", "--base", "b".repeat(40), "--registry", "https://acme.jfrog.io/npm/"],
  ]);
  const yml = readFileSync(join(ROOT, "action.yml"), "utf8");
  for (const [input, envName] of [["registry-host", "WS_REGISTRY_HOST"], ["registry", "WS_REGISTRY"]]) {
    assert.match(yml, new RegExp(`\\n {2}${input}:\\n(?: {4}.*\\n| {6}.*\\n)*? {4}default: ""\\n`), `${input}: an input, empty by default`);
    assert.match(yml, new RegExp(`\\n {8}${envName}: \\$\\{\\{ inputs\\.${input} \\}\\}\\n`), `${input}: passed to the wrapper`);
  }
});

test("action: registry-host and registry must be one line, and registry-host has no empty entry; checked whatever the command", async () => {
  const { plan } = await mod();
  for (const command of ["scan", "soak"]) {
    assert.throws(() => plan({ WS_COMMAND: command, WS_REGISTRY_HOST: "acme.jfrog.io\nnpm.example.com" }), /registry-host must be one line, got "acme\.jfrog\.io\nnpm\.example\.com"/, command);
    assert.throws(() => plan({ WS_COMMAND: command, WS_REGISTRY: "https://acme.jfrog.io/\r\nnpm/" }), /registry must be one line/, command);
    for (const v of ["acme.jfrog.io,,npm.example.com", "acme.jfrog.io,", ",", "acme.jfrog.io npm.example.com"]) {
      assert.throws(() => plan({ WS_COMMAND: command, WS_REGISTRY_HOST: v }), /registry-host is a comma-separated list of hosts, with no empty entry and no space inside one, got/, `${command} ${JSON.stringify(v)}`);
    }
  }
  // Through the script: exit 2 with an error annotation, before any command runs.
  const r = runAction({ GITHUB_EVENT_NAME: "push", WS_COMMAND: "scan", WS_REGISTRY_HOST: "acme.jfrog.io," });
  try {
    assert.equal(r.status, 2);
    assert.match(r.stdout, /^::error title=wormsign action::registry-host is a comma-separated list/m);
    assert.doesNotMatch(r.stdout, /^wormsign scan /m, "the CLI never ran");
  } finally {
    rmSync(r.dir, { recursive: true, force: true });
  }
});

test("action: no-baseline passes --no-baseline to every command, and cannot be combined with baseline", async () => {
  const { plan } = await mod();
  for (const [cmd, extra] of [["scan", {}], ["diff", { WS_BASE: "a", WS_HEAD: "b" }], ["soak", {}]] as const) {
    assert.equal(plan({ WS_COMMAND: cmd, WS_NO_BASELINE: "true", ...extra }).args.at(-1), "--no-baseline", cmd);
    assert.ok(!plan({ WS_COMMAND: cmd, WS_NO_BASELINE: "false", ...extra }).args.includes("--no-baseline"), cmd);
    assert.ok(!plan({ WS_COMMAND: cmd, ...extra }).args.includes("--no-baseline"), `${cmd}: off by default`);
  }
  assert.deepEqual(plan({ GITHUB_EVENT_NAME: "push", WS_NO_BASELINE: "true" }).args, ["scan", ".", "--no-baseline"]);
  assert.throws(() => plan({ WS_COMMAND: "scan", WS_NO_BASELINE: "true", WS_BASELINE: "/trusted/b.json" }), /baseline and no-baseline cannot be used together/);
  assert.throws(() => plan({ WS_COMMAND: "scan", WS_NO_BASELINE: "yes" }), /no-baseline must be "true" or "false", got "yes"/);
  const yml = readFileSync(join(ROOT, "action.yml"), "utf8");
  assert.match(yml, /\n {2}no-baseline:\n(?: {4}.*\n| {6}.*\n)*? {4}default: "false"\n/, "an input, off by default");
  assert.match(yml, /\n {8}WS_NO_BASELINE: \$\{\{ inputs\.no-baseline \}\}\n/, "passed to the wrapper");
});

test("action: fail-on and baseline pass through; every command gets them", async () => {
  const { plan } = await mod();
  for (const [cmd, extra] of [["scan", {}], ["diff", { WS_BASE: "a", WS_HEAD: "b" }], ["soak", {}]] as const) {
    const { args } = plan({ WS_COMMAND: cmd, WS_FAIL_ON: "medium", WS_BASELINE: "/trusted/b.json", ...extra });
    assert.deepEqual(args.slice(-4), ["--fail-on", "medium", "--baseline", "/trusted/b.json"], cmd);
  }
});

test("action: an unknown command or a mistyped boolean is an error, never a silent default", async () => {
  const { plan } = await mod();
  assert.throws(() => plan({ WS_COMMAND: "audit-org" }), /command must be one of scan, diff, soak/);
  assert.throws(() => plan({ WS_COMMAND: "soak", WS_OSV: "flase" }), /osv must be "true" or "false"/);
  assert.throws(() => plan({ WS_COMMAND: "soak", WS_CONFIG_ONLY: "yes" }), /config-only must be/);
  assert.throws(() => plan({ WS_COMMAND: "soak", WS_REQUIRE_CONFIG: "1" }), /require-config must be/);
  assert.throws(() => plan({ WS_UPLOAD_SARIF: "ture" }), /upload-sarif must be "auto", "true" or "false", got "ture"/);
});

test("action: upload-sarif auto uploads only when the event says the repository is public; true and false are kept", async () => {
  const { sarifUpload } = await mod();
  const decide = (upload: string | undefined, isPrivate: string | undefined): string => {
    const r = sarifUpload({ ...(upload === undefined ? {} : { WS_UPLOAD_SARIF: upload }), ...(isPrivate === undefined ? {} : { WS_REPOSITORY_PRIVATE: isPrivate }) });
    return r.upload ? "upload" : `skip: ${r.notice ?? "(no notice)"}`;
  };
  // Empty is what action.yml passes for an input left at an empty value, and "auto" its default.
  for (const auto of [undefined, "", "auto"]) {
    assert.equal(decide(auto, "false"), "upload", `${auto}: public`);
    assert.match(decide(auto, "true"), /^skip: upload-sarif is auto and this repository is private, so the SARIF report was not uploaded/, `${auto}: private`);
    // An event whose payload has no repository (github.event.repository.private renders as "").
    assert.match(decide(auto, ""), /^skip: upload-sarif is auto and this event does not say whether the repository is public/, `${auto}: unknown`);
    assert.match(decide(auto, undefined), /^skip: .*Set upload-sarif: "true" to upload/, `${auto}: unset`);
  }
  for (const isPrivate of ["true", "false", ""]) {
    assert.equal(decide("true", isPrivate), "upload", `true, private=${isPrivate}: an explicit true always uploads`);
    assert.equal(decide("false", isPrivate), "skip: (no notice)", `false, private=${isPrivate}`);
  }
});

test("action: upload-sarif auto skips a pull_request from a fork, whose token is read-only; the same repository and other events upload", async () => {
  const { sarifUpload } = await mod();
  const pub = { WS_REPOSITORY_PRIVATE: "false", WS_REPO: "acme/app" };
  assert.deepEqual(sarifUpload({ ...pub, GITHUB_EVENT_NAME: "pull_request", WS_HEAD_REPO: "acme/app" }), { upload: true });
  const fork = sarifUpload({ ...pub, GITHUB_EVENT_NAME: "pull_request", WS_HEAD_REPO: "mallory/app" });
  assert.equal(fork.upload, false);
  assert.match(fork.notice ?? "", /^upload-sarif is auto and this pull request comes from a fork, whose token is read-only/);
  // Only auto: an explicit true is kept (and fails the job if the upload does).
  assert.deepEqual(sarifUpload({ ...pub, WS_UPLOAD_SARIF: "true", GITHUB_EVENT_NAME: "pull_request", WS_HEAD_REPO: "mallory/app" }), { upload: true });
  // A push has no head repository.
  assert.deepEqual(sarifUpload({ ...pub, GITHUB_EVENT_NAME: "push", WS_HEAD_REPO: "" }), { upload: true });
  // action.yml passes both.
  const yml = readFileSync(join(ROOT, "action.yml"), "utf8");
  assert.match(yml, /WS_HEAD_REPO: \$\{\{ github\.event\.pull_request\.head\.repo\.full_name \}\}/);
  assert.match(yml, /WS_REPO: \$\{\{ github\.repository \}\}/);
});

test("action: a baseline the checked tree brings that hides anything is a warning annotation, not only a log line", () => {
  const tree = mkdtempSync(join(tmpdir(), "wormsign-action-tree-"));
  execFileSync("mkdir", ["-p", join(tree, ".github", "workflows")]);
  writeFileSync(join(tree, ".github", "workflows", "shai-hulud-workflow.yml"), "on: push\njobs: {}\n");
  writeFileSync(join(tree, ".wormsign-baseline.json"), JSON.stringify({ version: 1, entries: [], ignorePaths: [{ path: ".github", justification: "written by whoever pushed this branch" }] }));
  const r = runAction({ GITHUB_EVENT_NAME: "push", WS_COMMAND: "scan", WS_PATH: tree });
  assert.equal(r.status, 0);
  assert.equal(r.out["exit-code"], "0", "the gate passes: the baseline is the tree's own");
  assert.match(r.stdout, /^::warning title=wormsign action::.*\.wormsign-baseline\.json comes from the directory being checked and kept 1 file\(s\) from being checked with ignorePaths \(\.github\)/m);
  // With no-baseline, nothing is hidden and nothing is warned about.
  const all = runAction({ GITHUB_EVENT_NAME: "push", WS_COMMAND: "scan", WS_PATH: tree, WS_NO_BASELINE: "true" });
  assert.equal(all.out["exit-code"], "1");
  assert.doesNotMatch(all.stdout, /^::warning/m);
});

test("action: scan on a pull request reads the base revision's baseline, so the change cannot hide its own findings", async () => {
  const { plan } = await mod();
  assert.equal(plan({ GITHUB_EVENT_NAME: "pull_request", WS_COMMAND: "scan", WS_BASE: "abc" }).baselineFrom, "abc");
  for (const env of [
    { GITHUB_EVENT_NAME: "push", WS_COMMAND: "scan", WS_BASE: "abc" },
    { GITHUB_EVENT_NAME: "pull_request", WS_COMMAND: "scan", WS_BASE: "" },
    { GITHUB_EVENT_NAME: "pull_request", WS_COMMAND: "scan", WS_BASE: "abc", WS_BASELINE: "b.json" },
    { GITHUB_EVENT_NAME: "pull_request", WS_COMMAND: "scan", WS_BASE: "abc", WS_NO_BASELINE: "true" },
    { GITHUB_EVENT_NAME: "pull_request", WS_COMMAND: "soak", WS_BASE: "abc" },
  ] as Env[]) {
    assert.equal(plan(env).baselineFrom, undefined, JSON.stringify(env));
  }
  // The change adds an IOC-named workflow and a baseline that ignores .github.
  const repo = mkdtempSync(join(tmpdir(), "wormsign-action-prscan-"));
  const git = (...a: string[]) => execFileSync("git", ["-c", "user.email=t@t.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...a], { cwd: repo, stdio: "pipe" });
  git("init", "-q", "-b", "main");
  writeFileSync(join(repo, "package.json"), '{"name":"x","version":"1.0.0"}');
  git("add", "-A");
  git("commit", "-qm", "base");
  execFileSync("mkdir", ["-p", join(repo, ".github", "workflows")]);
  writeFileSync(join(repo, ".github", "workflows", "shai-hulud-workflow.yml"), "on: push\njobs: {}\n");
  writeFileSync(join(repo, ".wormsign-baseline.json"), JSON.stringify({ version: 1, entries: [], ignorePaths: [{ path: ".github", justification: "written by the pull request itself" }] }));
  git("add", "-A");
  git("commit", "-qm", "change");
  const pr = runAction({ GITHUB_EVENT_NAME: "pull_request", WS_COMMAND: "scan", WS_PATH: repo, WS_BASE: "HEAD~1" });
  assert.equal(pr.out["exit-code"], "1", pr.stdout);
  assert.match(pr.stdout, /scan reads the baseline as committed in the base revision HEAD~1, not the change's own/);
  assert.match(pr.stdout, /WS-GH-001/);
  // Control: the change's own file, named explicitly, hides it.
  assert.equal(runAction({ GITHUB_EVENT_NAME: "pull_request", WS_COMMAND: "scan", WS_PATH: repo, WS_BASE: "HEAD~1", WS_BASELINE: join(repo, ".wormsign-baseline.json") }).out["exit-code"], "0");
  // Once the base holds that baseline (the change merged with an override), the next pull request is judged by it.
  const next = runAction({ GITHUB_EVENT_NAME: "pull_request", WS_COMMAND: "scan", WS_PATH: repo, WS_BASE: "HEAD" });
  assert.equal(next.out["exit-code"], "0", next.stdout);
  // A base the clone does not hold stops the step (exit 2), never falls back to the change's file.
  const missing = runAction({ GITHUB_EVENT_NAME: "pull_request", WS_COMMAND: "scan", WS_PATH: repo, WS_BASE: "0".repeat(40) });
  assert.equal(missing.status, 2, missing.stdout);
  assert.match(missing.stdout, /^::error title=wormsign action::cannot read the base revision's baseline: "0{40}" is not a commit/m);
});

/** True if the Actions runner would take this stdout line as a workflow command (actions/runner ActionCommand.cs). */
const runnerCommand = (line: string): boolean => (line.trimStart().startsWith("::") && line.trimStart().indexOf("::", 2) > 0) || /##\[[^\]]*\]/.test(line);

test("action: workflow command data and properties are escaped as the runner unescapes them (%, CR, LF; : and , in properties)", async () => {
  const { escapeData, escapeProperty, workflowCommand } = await mod();
  assert.equal(escapeData("50% a\r\nb %0A"), "50%25 a%0D%0Ab %250A");
  assert.equal(escapeProperty("a:b,c%\n"), "a%3Ab%2Cc%25%0A");
  // The runner turns "%0A" back into a line break: a literal one in a value must reach the annotation as typed.
  assert.equal(workflowCommand("error", "cannot use x%0A::stop-commands::t"), "::error title=wormsign action::cannot use x%250A::stop-commands::t");
  assert.equal(workflowCommand("warning", "100%"), "::warning title=wormsign action::100%25");
});

test("action: input values in the script's own log lines cannot start a workflow command", async () => {
  const { safeLine, workflowCommand } = await mod();
  const hostile = ".\n::stop-commands::tok\n##[error]forged\r::add-mask::secret\u2028x";
  assert.equal(safeLine(hostile).includes("\n"), false);
  assert.ok(!runnerCommand(safeLine(hostile)));
  assert.equal(safeLine("::x::y"), "\\u003a:x::y");
  const own = workflowCommand("error", `cannot use ${hostile}`);
  assert.ok(own.startsWith("::error title=wormsign action::cannot use "), own);
  assert.equal(own.split("\n").length, 1);
  assert.ok(!/##\[/.test(own));
  // Through the script: every line it prints that the runner would read as a command is one of its own, on one line.
  const envs: Env[] = [
    { GITHUB_EVENT_NAME: "push", WS_COMMAND: "scan", WS_PATH: hostile },
    { GITHUB_EVENT_NAME: "push", WS_COMMAND: "diff", WS_BASE: "a", WS_HEAD: "b\n::add-mask::secret" },
    { GITHUB_EVENT_NAME: "pull_request_target", WS_COMMAND: "soak", WS_PATH: hostile, WS_CONFIG_ONLY: "true" },
    { GITHUB_EVENT_NAME: "push", WS_COMMAND: "scan", WS_FAIL_ON: "high\n::stop-commands::tok" },
  ];
  for (const env of envs) {
    const r = runAction(env);
    for (const line of r.stdout.split("\n")) {
      if (!runnerCommand(line)) continue;
      assert.match(line, /^::(warning|notice|error) title=wormsign action::/, `${JSON.stringify(env)}: ${JSON.stringify(line)}`);
      assert.ok(!/##\[/.test(line), line);
    }
    assert.ok(!/^::(stop-commands|add-mask)/m.test(r.stdout), r.stdout);
  }
});

test("action.yml: upload-sarif defaults to auto; the upload step runs on the run step's decision and fails the job if it fails", () => {
  const yml = readFileSync(join(ROOT, "action.yml"), "utf8");
  assert.match(yml, /\n {2}upload-sarif:\n(?: {4}.*\n)*? {4}default: "auto"\n/);
  assert.match(yml, /\n {8}WS_REPOSITORY_PRIVATE: \$\{\{ github\.event\.repository\.private \}\}\n/, "the run step is told the repository's visibility");
  const upload = /\n {4}- name: Upload SARIF to code scanning\n((?: {6}.*\n)+)/.exec(yml)?.[1] ?? "";
  assert.match(upload, /^ {6}if: steps\.run\.outputs\.upload-sarif == 'true' && steps\.run\.outputs\.sarif != ''$/m);
  assert.match(upload, /^ {6}uses: github\/codeql-action\/upload-sarif@[0-9a-f]{40} /m);
  assert.doesNotMatch(upload, /continue-on-error/, "an upload that runs and fails fails the job");
});

test("action: the findings count leaves out baselined findings", async () => {
  const { activeFindings } = await mod();
  assert.equal(activeFindings({ findings: [{}, { suppressed: { justification: "x" } }, {}] }), 2);
});

/** Runs the script as action.yml does, from the repository root, and returns its outputs. */
function runAction(env: Env | ((dir: string) => Env), script = SCRIPT): { status: number | null; signal: NodeJS.Signals | null; out: Record<string, string>; stdout: string; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), "wormsign-action-test-"));
  const outputs = join(dir, "outputs");
  writeFileSync(outputs, "");
  const res = spawnSync(process.execPath, [script], {
    cwd: ROOT,
    encoding: "utf8",
    // A run that waits on something (a FIFO at the sarif path) is killed and shows as `signal`, not a hung suite.
    timeout: 60_000,
    env: { PATH: process.env["PATH"] ?? "", HOME: dir, RUNNER_TEMP: dir, GITHUB_OUTPUT: outputs, ...(typeof env === "function" ? env(dir) : env) },
  });
  const out = Object.fromEntries(readFileSync(outputs, "utf8").split("\n").filter(Boolean).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
  return { status: res.status, signal: res.signal, out, stdout: res.stdout, dir };
}

const fixtureDiff = (name: string): Env => ({ WS_COMMAND: "diff", WS_BASE: `dir:test/fixtures/action/${name}/base`, WS_HEAD: `dir:test/fixtures/action/${name}/head` });

test("action: the malicious-shaped fixture fails the gate; its SARIF is exactly the CLI's", () => {
  const r = runAction({ ...fixtureDiff("malicious"), WS_FAIL_ON: "high" });
  try {
    // The script itself succeeds: the action's last step turns exit-code into the failure, after the SARIF upload.
    assert.equal(r.status, 0);
    assert.equal(r.out["exit-code"], "1");
    assert.equal(r.out["findings"], "2");
    assert.equal(r.out["command"], "diff");
    assert.match(r.stdout, /CRITICAL WS-GH-001 {2}\.github\/workflows\/shai-hulud-workflow\.yml/);
    const sarifPath = r.out["sarif"] ?? "";
    assert.match(sarifPath, /\/wormsign-sarif-[^/]+\/diff\.sarif$/);
    assert.ok(sarifPath.startsWith(r.dir), "the default is under RUNNER_TEMP");
    const direct = spawnSync(process.execPath, [CLI, "diff", ...[fixtureDiff("malicious")["WS_BASE"], fixtureDiff("malicious")["WS_HEAD"]] as string[], "--format", "sarif"], {
      cwd: ROOT,
      encoding: "utf8",
    });
    assert.equal(readFileSync(sarifPath, "utf8"), direct.stdout);
  } finally {
    rmSync(r.dir, { recursive: true, force: true });
  }
});

test("action: the clean fixture passes with no findings; the SARIF directory is created", () => {
  const r = runAction((dir) => ({ ...fixtureDiff("clean"), WS_SARIF: join(dir, "sarif", "clean.sarif") }));
  try {
    assert.equal(r.status, 0);
    assert.equal(r.out["sarif"], join(r.dir, "sarif", "clean.sarif"));
    assert.equal(r.out["exit-code"], "0");
    assert.equal(r.out["findings"], "0");
    const sarif = JSON.parse(readFileSync(r.out["sarif"] ?? "", "utf8")) as { runs: { results: unknown[] }[] };
    assert.deepEqual(sarif.runs[0]?.results, []);
  } finally {
    rmSync(r.dir, { recursive: true, force: true });
  }
});

test("action: fail-on never reports findings without failing; a CLI error stops at once with exit 2", () => {
  const never = runAction({ ...fixtureDiff("malicious"), WS_FAIL_ON: "never" });
  const broken = runAction({ WS_COMMAND: "diff", WS_BASE: "no-such-revision-xyz", WS_HEAD: "HEAD" });
  const badInput = runAction({ WS_COMMAND: "nope" });
  try {
    assert.equal(never.out["exit-code"], "0");
    assert.equal(never.out["findings"], "2");
    assert.equal(broken.status, 2);
    assert.equal(broken.out["exit-code"], "2");
    assert.equal(broken.out["sarif"], "");
    assert.equal(badInput.status, 2);
    assert.match(badInput.stdout, /^::error title=wormsign action::command must be one of/m);
  } finally {
    for (const r of [never, broken, badInput]) rmSync(r.dir, { recursive: true, force: true });
  }
});

test("action: on a private repository the default skips the upload with a notice and still writes the SARIF file", () => {
  const skipped = runAction({ ...fixtureDiff("malicious"), WS_REPOSITORY_PRIVATE: "true" });
  const public_ = runAction({ ...fixtureDiff("malicious"), WS_REPOSITORY_PRIVATE: "false" });
  const forced = runAction({ ...fixtureDiff("clean"), WS_REPOSITORY_PRIVATE: "true", WS_UPLOAD_SARIF: "true" });
  const broken = runAction({ WS_COMMAND: "diff", WS_BASE: "no-such-revision-xyz", WS_HEAD: "HEAD", WS_REPOSITORY_PRIVATE: "false" });
  try {
    assert.equal(skipped.out["upload-sarif"], "false");
    assert.equal(skipped.out["exit-code"], "1", "the gate is unchanged");
    assert.match(readFileSync(skipped.out["sarif"] ?? "", "utf8"), /"ruleId": "WS-GH-001"/, "the SARIF file is written");
    const notice = skipped.stdout.split("\n").filter((l) => l.startsWith("::notice title=wormsign action::"));
    assert.equal(notice.length, 1, skipped.stdout);
    assert.ok(notice[0]?.includes("this repository is private") && notice[0].endsWith(`The report is at ${skipped.out["sarif"]} (the sarif output).`), notice[0]);
    assert.equal(public_.out["upload-sarif"], "true");
    assert.doesNotMatch(public_.stdout, /::notice/);
    assert.equal(forced.out["upload-sarif"], "true");
    assert.equal(broken.out["upload-sarif"], "false", "no report, no upload");
  } finally {
    for (const r of [skipped, public_, forced, broken]) rmSync(r.dir, { recursive: true, force: true });
  }
});

test("action: the sarif path is never written through a symlink, nor to anything but a regular file", () => {
  const victim = join(mkdtempSync(join(tmpdir(), "wormsign-action-victim-")), "rc");
  writeFileSync(victim, "# my shell rc\n");
  const linked = runAction((dir) => {
    symlinkSync(victim, join(dir, "wormsign.sarif"));
    return { ...fixtureDiff("malicious"), WS_SARIF: join(dir, "wormsign.sarif") };
  });
  const device = runAction({ ...fixtureDiff("clean"), WS_SARIF: "/dev/null" });
  try {
    assert.equal(linked.status, 2);
    assert.match(linked.stdout, /^::error title=wormsign action::sarif \S+wormsign\.sarif is a symbolic link; refusing to write through it$/m);
    assert.equal(readFileSync(victim, "utf8"), "# my shell rc\n");
    assert.equal(device.status, 2);
    assert.match(device.stdout, /^::error title=wormsign action::sarif \/dev\/null is not a regular file; refusing to write to it$/m);
  } finally {
    for (const r of [linked, device]) rmSync(r.dir, { recursive: true, force: true });
    rmSync(dirname(victim), { recursive: true, force: true });
  }
});

test("action: a FIFO at the sarif path is refused at once, not waited on", { skip: process.platform === "win32" }, () => {
  // With nobody reading the FIFO, a blocking open would wait for ever; runAction's timeout turns that into a signal.
  const r = runAction((dir) => {
    execFileSync("mkfifo", [join(dir, "wormsign.sarif")]);
    return { ...fixtureDiff("clean"), WS_SARIF: join(dir, "wormsign.sarif") };
  });
  try {
    assert.equal(r.signal, null, "the action hung on the FIFO");
    assert.equal(r.status, 2);
    assert.match(r.stdout, /^::error title=wormsign action::cannot write sarif \S+wormsign\.sarif: ENXIO$/m);
  } finally {
    rmSync(r.dir, { recursive: true, force: true });
  }
});

test("action: two runs in one job keep separate default SARIF files", () => {
  const shared = mkdtempSync(join(tmpdir(), "wormsign-action-shared-"));
  const a = runAction({ ...fixtureDiff("malicious"), RUNNER_TEMP: shared });
  const b = runAction({ ...fixtureDiff("clean"), RUNNER_TEMP: shared });
  try {
    assert.notEqual(a.out["sarif"], b.out["sarif"]);
    assert.match(readFileSync(a.out["sarif"] ?? "", "utf8"), /"ruleId": "WS-GH-001"/);
  } finally {
    for (const d of [shared, a.dir, b.dir]) rmSync(d, { recursive: true, force: true });
  }
});

test("action: the script runs when reached through a symlinked directory (as a checkout under a link would be)", () => {
  const links = mkdtempSync(join(tmpdir(), "wormsign-action-link-"));
  symlinkSync(ROOT, join(links, "gate"));
  const r = runAction(fixtureDiff("malicious"), join(links, "gate", "scripts", "ci-action.mjs"));
  try {
    assert.equal(r.out["exit-code"], "1", "main() ran and wrote its outputs");
  } finally {
    for (const d of [links, r.dir]) rmSync(d, { recursive: true, force: true });
  }
});

/* ---- The pull_request gate, end to end: the script runs the real CLI three times on a git repository. ---- */

/**
 * NODE_OPTIONS for the Action's script and the CLI it starts: an --import module that replaces fetch, so soak never
 * reaches the network. "old": the registry (the public one, or MIRROR) serves every name with one version published
 * 400 hours ago and OSV has no record; "refused": a connection to the registry is refused (an outage). Any other URL
 * throws.
 */
function noNetwork(dir: string, mode: "old" | "refused"): string {
  const file = join(dir, "fake-fetch.mjs");
  writeFileSync(
    file,
    [
      `const MODE = ${JSON.stringify(mode)};`,
      "globalThis.fetch = async (input, init) => {",
      "  const url = String(input);",
      '  if (url === "https://api.osv.dev/v1/querybatch") return new Response(JSON.stringify({ results: JSON.parse(String(init.body)).queries.map(() => ({})) }));',
      // The public registry, or the private one at ACME (MIRROR) that the registry tests point soak at.
      `  const m = /^(https:\\/\\/registry\\.npmjs\\.org|${MIRROR.replace(/[./]/g, "\\$&")})\\/(.*)$/.exec(url);`,
      '  if (m && MODE === "refused") throw new TypeError("fetch failed", { cause: Object.assign(new Error("connect ECONNREFUSED 127.0.0.9:443"), { code: "ECONNREFUSED" }) });',
      "  if (m) {",
      "    const name = decodeURIComponent(m[2]);",
      '    const tarball = m[1] + "/" + name + "/-/" + name + "-1.0.0.tgz";',
      '    return new Response(JSON.stringify({ name, time: { "1.0.0": new Date(Date.now() - 400 * 3600000).toISOString() }, versions: { "1.0.0": { dist: { integrity: "sha512-x", tarball } } } }));',
      "  }",
      '  throw new TypeError("the test allows no network: " + url);',
      "};",
      "",
    ].join("\n"),
  );
  return `--import ${pathToFileURL(file).href}`;
}

/** A PATH with git and stub package managers, so soak's `<pm> --version` answers the same on every machine. */
function stubPath(dir: string): string {
  const bin = join(dir, "bin");
  execFileSync("mkdir", ["-p", bin]);
  for (const [m, v] of Object.entries({ npm: "11.10.0", pnpm: "11.16.0", yarn: "4.10.3", bun: "1.3.0" })) writeFileSync(join(bin, m), `#!/bin/sh\necho ${v}\n`, { mode: 0o755 });
  return `${bin}:${dirname(execFileSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).trim())}`;
}

/** A private registry's npm repository, as Artifactory serves one: the URL its lockfile entries resolve from. */
const MIRROR = "https://acme.jfrog.io/artifactory/api/npm/npm";

const lock = (names: string[], registry = "https://registry.npmjs.org"): string =>
  JSON.stringify({
    name: "app",
    version: "1.0.0",
    lockfileVersion: 3,
    requires: true,
    packages: Object.fromEntries([["", { name: "app", version: "1.0.0" }], ...names.map((n) => [`node_modules/${n}`, { version: "1.0.0", resolved: `${registry}/${n}/-/${n}-1.0.0.tgz`, integrity: "sha512-x" }])]),
  });

/**
 * A git repository whose last commit is a pull request's change: it adds `fresh` to the lockfile, and with `workflow`
 * an IOC-named workflow. Both lockfiles resolve from `registry`.
 */
function pullRequest(change: (dir: string) => void = () => undefined, registry?: string): { repo: string; base: string; head: string } {
  const repo = mkdtempSync(join(tmpdir(), "wormsign-action-gate-"));
  const git = (...a: string[]) => execFileSync("git", ["-c", "user.email=t@t.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...a], { cwd: repo, encoding: "utf8", stdio: "pipe" }).trim();
  git("init", "-q", "-b", "main");
  writeFileSync(join(repo, "package.json"), '{"name":"app","version":"1.0.0"}');
  writeFileSync(join(repo, "package-lock.json"), lock(["old"], registry));
  git("add", "-A");
  git("commit", "-qm", "base");
  writeFileSync(join(repo, "package-lock.json"), lock(["old", "fresh"], registry));
  change(repo);
  git("add", "-A");
  git("commit", "-qm", "change");
  return { repo, base: git("rev-parse", "HEAD~1"), head: git("rev-parse", "HEAD") };
}

const withWorkflow = (repo: string): void => {
  execFileSync("mkdir", ["-p", join(repo, ".github", "workflows")]);
  writeFileSync(join(repo, ".github", "workflows", "shai-hulud-workflow.yml"), "on: push\njobs: {}\n");
};

const readSarif = (path: string | undefined): Sarif => JSON.parse(readFileSync(path ?? "", "utf8")) as Sarif;

test("action: on pull_request the default runs diff, scan and soak in order, as the three-call recipe does: worst exit, summed findings, one SARIF with each command's run", () => {
  const { repo, base, head } = pullRequest(withWorkflow);
  const env = (dir: string): Env => ({ GITHUB_EVENT_NAME: "pull_request", WS_BASE: base, WS_HEAD: head, WS_PATH: repo, WS_REPOSITORY_PRIVATE: "false", NODE_OPTIONS: noNetwork(dir, "old"), PATH: stubPath(dir) });
  const gate = runAction(env);
  const each = ["diff", "scan", "soak"].map((command) => runAction((dir) => ({ ...env(dir), WS_COMMAND: command })));
  try {
    assert.equal(gate.status, 0, gate.stdout);
    assert.equal(gate.out["command"], "gate");
    assert.deepEqual(each.map((r) => r.out["exit-code"]), ["1", "1", "0"], "diff and scan fail on the workflow, soak passes");
    assert.equal(gate.out["exit-code"], "1", "the worst of the three");
    assert.equal(gate.out["findings"], String(each.reduce((n, r) => n + Number(r.out["findings"]), 0)));
    assert.equal(gate.out["upload-sarif"], "true");
    // Each command's own lines, in order: its command line, then its report.
    const commandLines = (stdout: string) => stdout.split("\n").filter((l) => /^wormsign (diff|scan|soak) /.test(l)).map((l) => l.replace(/\/[^ ]*base-baseline\.json/, "<base-baseline>"));
    assert.deepEqual(commandLines(gate.stdout), each.flatMap((r) => commandLines(r.stdout)));
    const reports = gate.stdout.split("\n").filter((l) => /^wormsign (diff|scan|soak): /.test(l));
    assert.deepEqual(reports.map((l) => l.split(":")[0]), ["wormsign diff", "wormsign scan", "wormsign soak"]);
    assert.match(gate.stdout, /scan reads the baseline as committed in the base revision/);
    // One file, one run per command: the command's own run, rule ids and fingerprints unchanged, plus its category.
    const sarif = readSarif(gate.out["sarif"]);
    assert.match(gate.out["sarif"] ?? "", /\/gate\.sarif$/);
    assert.equal(sarif.runs.length, 3);
    sarif.runs.forEach((run, i) => {
      const own = readSarif(each[i]!.out["sarif"]);
      const { automationDetails, ...rest } = run;
      assert.deepEqual(automationDetails, { id: `wormsign-${GATE_ORDER[i]}/` });
      assert.deepEqual(rest, own.runs[0], `${GATE_ORDER[i]}'s run is its own SARIF's`);
      assert.deepEqual({ ...sarif, runs: [] }, { ...own, runs: [] });
    });
    // Code scanning takes several runs in one file only with distinct tool and category.
    assert.equal(new Set(sarif.runs.map((r) => `${JSON.stringify((r["tool"] as { driver: unknown }).driver)}|${r.automationDetails?.id}`)).size, 3);
    assert.ok(sarif.runs[0]!.results.some((r) => r.ruleId === "WS-GH-001") && sarif.runs[1]!.results.some((r) => r.ruleId === "WS-GH-001"));
  } finally {
    for (const r of [gate, ...each]) rmSync(r.dir, { recursive: true, force: true });
    rmSync(repo, { recursive: true, force: true });
  }
});

const GATE_ORDER = ["diff", "scan", "soak"];

test("action: the default on pull_request fails the Mini Shai-Hulud replay, which diff alone, the old default, passes", () => {
  const git = (cwd: string, ...a: string[]) => execFileSync("git", ["-c", "user.email=t@t.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...a], { cwd, encoding: "utf8", stdio: "pipe" }).trim();
  const repo = mkdtempSync(join(tmpdir(), "wormsign-action-replay-"));
  git(repo, "init", "-q", "-b", "main");
  git(repo, "commit", "-q", "--allow-empty", "-m", "base");
  cpSync(join(ROOT, "test", "fixtures", "replay", "2026-04"), repo, { recursive: true });
  git(repo, "add", "-A");
  git(repo, "commit", "-qm", "change");
  const env = (dir: string): Env => ({ GITHUB_EVENT_NAME: "pull_request", WS_BASE: git(repo, "rev-parse", "HEAD~1"), WS_HEAD: git(repo, "rev-parse", "HEAD"), WS_PATH: repo, NODE_OPTIONS: noNetwork(dir, "old"), PATH: stubPath(dir) });
  const gate = runAction(env);
  const diffAlone = runAction((dir) => ({ ...env(dir), WS_COMMAND: "diff" }));
  try {
    assert.equal(diffAlone.out["exit-code"], "0", "diff alone passes the wave");
    assert.equal(gate.out["exit-code"], "1", gate.stdout);
    const soak = readSarif(gate.out["sarif"]).runs.find((r) => r.automationDetails?.id === "wormsign-soak/");
    assert.ok(soak?.results.some((r) => r.ruleId === "WS-SK-002" && r.level === "error"), "soak's WS-SK-002 for the git dependency fails it");
  } finally {
    for (const r of [gate, diffAlone]) rmSync(r.dir, { recursive: true, force: true });
    rmSync(repo, { recursive: true, force: true });
  }
});

test("action: in the gate a command that errors is exit-code 2, and the others still run and reach the SARIF; alone it stops the step, as before", () => {
  const { repo, base, head } = pullRequest(withWorkflow);
  const env = (dir: string): Env => ({ GITHUB_EVENT_NAME: "pull_request", WS_BASE: base, WS_HEAD: head, WS_PATH: repo, WS_MIN_AGE: "soon", NODE_OPTIONS: noNetwork(dir, "old"), PATH: stubPath(dir) });
  const gate = runAction(env);
  const alone = runAction((dir) => ({ ...env(dir), WS_COMMAND: "soak" }));
  // A base the clone does not hold: diff and soak cannot read it, and scan cannot read the base's baseline.
  const none = runAction((dir) => ({ ...env(dir), WS_MIN_AGE: "", WS_BASE: "0".repeat(40) }));
  try {
    assert.equal(gate.status, 0, gate.stdout);
    assert.equal(gate.out["exit-code"], "2", "soak's usage error is the worst");
    assert.deepEqual(readSarif(gate.out["sarif"]).runs.map((r) => r.automationDetails?.id), ["wormsign-diff/", "wormsign-scan/"]);
    assert.equal(alone.status, 2);
    assert.equal(alone.out["exit-code"], "2");
    assert.equal(alone.out["sarif"], "");
    assert.equal(none.status, 2, none.stdout);
    assert.equal(none.out["exit-code"], "2");
    assert.equal(none.out["sarif"], "");
    assert.match(none.stdout, /^::error title=wormsign action::cannot read the base revision's baseline/m);
    assert.deepEqual(none.stdout.split("\n").filter((l) => /^wormsign (diff|soak) /.test(l)).map((l) => l.split(" ")[1]), ["diff", "soak"], "every command was tried");
  } finally {
    for (const r of [gate, alone, none]) rmSync(r.dir, { recursive: true, force: true });
    rmSync(repo, { recursive: true, force: true });
  }
});

test("action: on-outage warn turns a registry outage into WS-SK-006 at medium, an annotation and the step summary; the default fails", () => {
  const { repo, base, head } = pullRequest();
  const env = (dir: string): Env => ({ GITHUB_EVENT_NAME: "pull_request", WS_BASE: base, WS_HEAD: head, WS_PATH: repo, NODE_OPTIONS: noNetwork(dir, "refused"), PATH: stubPath(dir), GITHUB_STEP_SUMMARY: join(dir, "summary.md") });
  const warn = runAction((dir) => ({ ...env(dir), WS_ON_OUTAGE: "warn" }));
  const fail = runAction(env);
  try {
    const line = "UNVERIFIED: 1 package not checked (registry.npmjs.org unreachable: connection failed (ECONNREFUSED)); --on-outage warn";
    assert.equal(warn.out["exit-code"], "0", warn.stdout);
    assert.match(warn.stdout, /wormsign soak \S+ --base [0-9a-f]{40} --on-outage warn/);
    assert.ok(warn.stdout.split("\n").includes(`::warning title=wormsign action::${line}`), warn.stdout);
    assert.equal(readFileSync(join(warn.dir, "summary.md"), "utf8"), `### wormsign: packages not verified\n\n- \`soak\`: ${line}\n\nAn outage left these unchecked, and \`on-outage: warn\` reports them at medium. Re-run the gate before merging.\n`);
    const soak = readSarif(warn.out["sarif"]).runs.find((r) => r.automationDetails?.id === "wormsign-soak/");
    assert.deepEqual(soak?.results.filter((r) => r.ruleId.startsWith("WS-SK-00") && r.ruleId !== "WS-SK-003").map((r) => `${r.ruleId} ${r.level}`), ["WS-SK-006 warning"]);
    assert.equal(fail.out["exit-code"], "1");
    assert.doesNotMatch(fail.stdout, /UNVERIFIED/);
    assert.ok(!existsSync(join(fail.dir, "summary.md")), "nothing to summarise");
  } finally {
    for (const r of [warn, fail]) rmSync(r.dir, { recursive: true, force: true });
    rmSync(repo, { recursive: true, force: true });
  }
});

const ruleIds = (r: { out: Record<string, string> }): string[] => readSarif(r.out["sarif"]).runs.flatMap((run) => run.results.map((x) => x.ruleId));

test("action: a lock that resolves from a private registry fails scan and diff with WS-LK-002 high, and passes both with registry-host", () => {
  const { repo, base, head } = pullRequest(undefined, MIRROR);
  const scan: Env = { GITHUB_EVENT_NAME: "pull_request", WS_COMMAND: "scan", WS_PATH: repo, WS_BASE: base };
  const diff: Env = { GITHUB_EVENT_NAME: "pull_request", WS_COMMAND: "diff", WS_PATH: repo, WS_BASE: base, WS_HEAD: head };
  const runs = {
    scan: runAction(scan),
    diff: runAction(diff),
    scanHost: runAction({ ...scan, WS_REGISTRY_HOST: "acme.jfrog.io" }),
    diffHost: runAction({ ...diff, WS_REGISTRY_HOST: "npm.example.com, acme.jfrog.io" }),
    // Control: another host allows nothing here.
    scanOther: runAction({ ...scan, WS_REGISTRY_HOST: "npm.example.com" }),
  };
  try {
    for (const r of [runs.scan, runs.diff, runs.scanOther]) {
      assert.equal(r.out["exit-code"], "1", r.stdout);
      assert.ok(ruleIds(r).includes("WS-LK-002"), r.stdout);
      assert.match(r.stdout, /resolves from acme\.jfrog\.io, not an allowed registry host/);
    }
    assert.equal(ruleIds(runs.scan).filter((id) => id === "WS-LK-002").length, 2, "scan: every entry");
    assert.equal(ruleIds(runs.diff).filter((id) => id === "WS-LK-002").length, 1, "diff: the entry the change adds");
    for (const r of [runs.scanHost, runs.diffHost]) {
      assert.equal(r.out["exit-code"], "0", r.stdout);
      assert.deepEqual(ruleIds(r).filter((id) => id === "WS-LK-002"), [], r.stdout);
    }
    assert.match(runs.diffHost.stdout, /^wormsign diff [0-9a-f]{40} [0-9a-f]{40} --dir \S+ --registry-host npm\.example\.com --registry-host acme\.jfrog\.io$/m);
  } finally {
    for (const r of Object.values(runs)) rmSync(r.dir, { recursive: true, force: true });
    rmSync(repo, { recursive: true, force: true });
  }
});

test("action: the gate passes a private registry's lock with registry-host and registry (osv off); without registry soak fails it, and with OSV on it is WS-OS-900", () => {
  const { repo, base, head } = pullRequest(undefined, MIRROR);
  const env = (dir: string): Env => ({ GITHUB_EVENT_NAME: "pull_request", WS_BASE: base, WS_HEAD: head, WS_PATH: repo, WS_REGISTRY_HOST: "acme.jfrog.io", NODE_OPTIONS: noNetwork(dir, "old"), PATH: stubPath(dir) });
  const both = runAction((dir) => ({ ...env(dir), WS_REGISTRY: `${MIRROR}/`, WS_OSV: "false" }));
  const hostOnly = runAction((dir) => ({ ...env(dir), WS_OSV: "false" }));
  const osv = runAction((dir) => ({ ...env(dir), WS_REGISTRY: `${MIRROR}/` }));
  const soakRun = (r: { out: Record<string, string> }) => readSarif(r.out["sarif"]).runs.find((run) => run.automationDetails?.id === "wormsign-soak/");
  const high = (r: { out: Record<string, string> }) => soakRun(r)?.results.filter((x) => x.level === "error").map((x) => x.ruleId);
  try {
    assert.equal(both.out["exit-code"], "0", both.stdout);
    assert.match(both.stdout, new RegExp(`^wormsign soak \\S+ --base [0-9a-f]{40} --registry ${MIRROR.replace(/[./]/g, "\\$&")}/ --no-osv$`, "m"));
    assert.deepEqual(high(both), []);
    assert.equal(hostOnly.out["exit-code"], "1", hostOnly.stdout);
    assert.ok(high(hostOnly)?.includes("WS-SK-002"), "soak asks registry.npmjs.org, which the lock does not resolve from");
    assert.equal(osv.out["exit-code"], "1", osv.stdout);
    assert.deepEqual(high(osv), ["WS-OS-900"], "no private name is sent to OSV: ADR 0007");
  } finally {
    for (const r of [both, hostOnly, osv]) rmSync(r.dir, { recursive: true, force: true });
    rmSync(repo, { recursive: true, force: true });
  }
});

test("action: a registry-host or registry holding $() reaches the CLI as one literal argument, and one holding a line break is refused; no shell runs either", () => {
  const { repo, base } = pullRequest(undefined, MIRROR);
  const pwned = (dir: string) => join(dir, "pwned");
  const scan: Env = { GITHUB_EVENT_NAME: "pull_request", WS_COMMAND: "scan", WS_PATH: repo, WS_BASE: base };
  // No space in it (a space inside an entry is refused as a missing comma): ${IFS} is the shell's.
  const literal = runAction((dir) => ({ ...scan, WS_REGISTRY_HOST: `acme.jfrog.io$(touch\${IFS}${pwned(dir)})` }));
  const lines = runAction((dir) => ({ ...scan, WS_REGISTRY_HOST: `acme.jfrog.io$(touch ${pwned(dir)})\n::add-mask::secret` }));
  const url = runAction((dir) => ({ GITHUB_EVENT_NAME: "push", WS_COMMAND: "soak", WS_PATH: repo, WS_CONFIG_ONLY: "true", WS_REGISTRY: `https://acme.jfrog.io/npm/\n$(touch ${pwned(dir)})` }));
  try {
    // One argument, never matching the lock's host: the findings stay.
    assert.equal(literal.out["exit-code"], "1", literal.stdout);
    assert.ok(literal.stdout.split("\n").some((l) => l.startsWith(`wormsign scan ${repo} --registry-host acme.jfrog.io$(touch\${IFS}${pwned(literal.dir)}) --baseline `)), literal.stdout);
    assert.ok(ruleIds(literal).includes("WS-LK-002"));
    for (const [r, input] of [[lines, "registry-host"], [url, "registry"]] as const) {
      assert.equal(r.status, 2, r.stdout);
      const own = r.stdout.split("\n").filter((l) => l.startsWith("::"));
      assert.equal(own.length, 1, r.stdout);
      assert.ok(own[0]?.startsWith(`::error title=wormsign action::${input} must be one line, got "`), own[0]);
      assert.doesNotMatch(r.stdout, /^::add-mask::/m);
      assert.doesNotMatch(r.stdout, /^wormsign (scan|soak) /m, "the CLI never ran");
    }
    for (const r of [literal, lines, url]) assert.ok(!existsSync(pwned(r.dir)), "nothing ran the $() as a command");
    // action.yml hands every input to the script as an environment variable, never inside a run: line.
    const steps = readFileSync(join(ROOT, "action.yml"), "utf8").split("\nruns:\n")[1] ?? "";
    const uses = steps.split("\n").filter((l) => l.includes("${{ inputs."));
    assert.ok(uses.length >= 17, `${uses.length} input uses`);
    for (const l of uses) assert.match(l, /^ {8}WS_[A-Z_]+: \$\{\{ inputs\.[a-z-]+ \}\}$/, l);
  } finally {
    for (const r of [literal, lines, url]) rmSync(r.dir, { recursive: true, force: true });
    rmSync(repo, { recursive: true, force: true });
  }
});
