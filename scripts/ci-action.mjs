#!/usr/bin/env node
// Runs the wormsign CLI for the composite GitHub Action (action.yml) and reports the result as step outputs.
//
// The CLI runs once per command, writing a JSON report; this script then renders that report twice with the CLI's own
// renderer (dist/src/report.js, from the same commit): human-readable to the log and SARIF to a file. One run means
// one set of network requests for soak and one consistent result for both outputs. On pull_request an empty command
// is the gate, the three commands of the recommended recipe in order (GATE, see plans): diff, scan, soak. Each runs as
// its own Action call would, and the step reports the worst exit code, every command's output in turn and one SARIF
// file with a run per command (gateSarif).
//
// It always exits 0 once a command has produced a report, after writing the outputs exit-code, findings, sarif,
// command and upload-sarif (whether action.yml's upload step runs, see sarifUpload) to $GITHUB_OUTPUT. The action's
// last step fails the job on a nonzero exit-code, after the SARIF upload step, so results reach code scanning exactly
// when the gate fails. A CLI usage or internal error (exit 2) leaves no report: with one command this script exits 2
// at once; in the gate the other commands still run and report, and exit-code is 2.
//
// Inputs arrive as WS_* environment variables set by action.yml from the action inputs. They are never
// interpolated into a shell command: values are passed to the CLI as separate argv entries.
import { spawnSync } from "node:child_process";
import { appendFileSync, closeSync, constants, existsSync, fstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, parse, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const CLI = join(ROOT, "dist", "src", "cli.js");
const REPORT = join(ROOT, "dist", "src", "report.js");

const COMMANDS = ["scan", "diff", "soak"];
/**
 * What an empty command runs on pull_request, in this order: the recommended gate's three commands
 * (docs/github-action.md, "Recommended pull-request gate"), so the default is the safe recipe, not diff alone.
 */
export const GATE = ["diff", "scan", "soak"];
/** How the CLI's note starts when the checked tree's own baseline suppressed or ignored something. */
const TREE_BASELINE = "warning: ";
/** How soak's note starts under --on-outage warn when an outage left packages unchecked (src/net.ts UNVERIFIED). */
const UNVERIFIED = "UNVERIFIED: ";
const ON_OUTAGE = ["fail", "warn"];

/** "true" or "false" only: a typo such as "flase" must not silently pick a default. */
function bool(env, key, fallback) {
  const v = (env[key] ?? "").trim();
  if (v === "") return fallback;
  if (v === "true" || v === "false") return v === "true";
  throw new Error(`${key.replace(/^WS_/, "").toLowerCase().replaceAll("_", "-")} must be "true" or "false", got "${v}"`);
}

const str = (env, key) => (env[key] ?? "").trim();

const inputName = (key) => key.replace(/^WS_/, "").toLowerCase().replaceAll("_", "-");

/**
 * An input that must be one line. A line break is an error, not a separator: the CLI's URL parser drops one from
 * --registry without a word, and a list split on it would take an injected second line for a value.
 */
function oneLine(env, key) {
  const v = str(env, key);
  if (/[\r\n\u2028\u2029]/.test(v)) throw new Error(`${inputName(key)} must be one line, got "${v}"`);
  return v;
}

/**
 * A comma-separated list input (registry-host), one line, each entry trimmed. An empty entry ("a,,b", a trailing
 * comma) or one with a space inside (a missing comma) is an error, never dropped or passed on: a host the CLI never
 * matches would leave every finding for it in place without saying why.
 */
function list(env, key) {
  const v = oneLine(env, key);
  if (v === "") return [];
  return v.split(",").map((entry) => {
    const e = entry.trim();
    if (e === "" || /\s/.test(e)) throw new Error(`${inputName(key)} is a comma-separated list of hosts, with no empty entry and no space inside one, got "${v}"`);
    return e;
  });
}

// eslint-disable-next-line no-control-regex -- matching control characters is the point
const CONTROL = /[\u0000-\u001f\u007f-\u009f\p{Cf}\p{Zl}\p{Zp}]/gu;
const escaped = (c) => Array.from({ length: c.length }, (_, i) => `\\u${c.charCodeAt(i).toString(16).padStart(4, "0")}`).join("");

/**
 * A line this script prints itself, made safe as src/report.ts neutralise makes the CLI's: input values (path, base,
 * head, sarif) can come from data a pull request controls when a workflow builds them from it, and the runner reads
 * workflow commands from stdout ("::cmd::" at the start of a line, "##[cmd]" anywhere). Control and format characters
 * become \uXXXX, so a value cannot start a new line; "##[" and a leading "::" are broken up. This file cannot import
 * dist/src/report.js before it knows the CLI is there, so the rule is repeated here and tested on the same inputs.
 */
export function safeLine(text) {
  return String(text).replace(CONTROL, escaped).replace(/##\[/g, "#\\u0023[").replace(/^(\s*):(?=:)/, "$1\\u003a");
}

/**
 * A workflow command's data, escaped as the runner unescapes it (actions/toolkit command.ts escapeData): "%" first,
 * then CR and LF. Without it a literal "%0A" in a message would become a line break in the annotation.
 */
export const escapeData = (s) => String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
/** A workflow command property's value, escaped as escapeData and also ":" and "," (escapeProperty). */
export const escapeProperty = (s) => escapeData(s).replace(/:/g, "%3A").replace(/,/g, "%2C");

/** A workflow command of this script's own (::warning, ::notice, ::error) whose message may hold input values. */
export function workflowCommand(name, message) {
  return `::${name} title=${escapeProperty("wormsign action")}::${escapeData(safeLine(message))}`;
}

/**
 * Events whose default checkout and github.sha are the base branch, not the change that triggered them: the last
 * commit on the pull request's base branch (pull_request_target) or on the default branch (workflow_run, and
 * issue_comment, which is how a "/scan" comment on a pull request arrives).
 * https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request_target
 * https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run
 * https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#issue_comment
 */
const BASE_CHECKOUT_EVENTS = ["pull_request_target", "workflow_run", "issue_comment"];

/**
 * What the step runs, one plan (see plan) per command. An empty command on pull_request is the gate: GATE's commands,
 * each planned exactly as an Action call with that command would be, so soak gets --base and scan the base revision's
 * baseline as they do in the three-call recipe. Anything else is one command. Pure, so it is unit-tested.
 */
export function plans(env) {
  if (str(env, "WS_COMMAND") === "" && str(env, "GITHUB_EVENT_NAME") === "pull_request") return GATE.map((command) => plan({ ...env, WS_COMMAND: command }));
  return [plan(env)];
}

/**
 * The CLI command and its arguments for the given inputs, and a warning to print, if any. Pure, so it is unit-tested.
 * An empty command means scan (plans() makes it the gate on pull_request), except on the events above, where the
 * default would check trusted base code and pass without ever looking at the change, so it is an error.
 */
export function plan(env) {
  // Validated before the CLI runs, so "ture" fails instead of silently skipping the upload.
  sarifUpload(env);
  const onOutage = str(env, "WS_ON_OUTAGE") || "fail";
  if (!ON_OUTAGE.includes(onOutage)) throw new Error(`on-outage must be "fail" or "warn", got "${onOutage}"`);
  // Checked whatever the command, as on-outage is, so a bad value fails the step that holds it.
  const registryHosts = list(env, "WS_REGISTRY_HOST");
  const registry = oneLine(env, "WS_REGISTRY");
  const event = str(env, "GITHUB_EVENT_NAME");
  const baseCheckout = BASE_CHECKOUT_EVENTS.includes(event);
  const why = `on ${event} the default checkout and github.sha are the base branch, not the change`;
  if (baseCheckout && !str(env, "WS_COMMAND")) {
    throw new Error(`${why}, so the default command would check trusted code and pass. Use the pull_request trigger (docs/github-action.md), or set command, path, base and head explicitly`);
  }
  const command = str(env, "WS_COMMAND") || "scan";
  if (!COMMANDS.includes(command)) throw new Error(`command must be one of ${COMMANDS.join(", ")}, got "${command}"`);
  const path = str(env, "WS_PATH") || ".";
  const base = str(env, "WS_BASE");
  const head = str(env, "WS_HEAD");
  const args = [command];
  if (baseCheckout && command === "diff" && head !== "" && head === str(env, "GITHUB_SHA")) {
    throw new Error(`${why}, so diff with head ${head} (github.sha, the default) never sees the change. Set head to the change's commit`);
  }
  const warning = baseCheckout && command !== "diff" ? `${why}: ${command} checks whatever the workflow checked out (path "${path}"), so make sure that is the change you mean to gate` : undefined;

  if (command === "scan") args.push(path);
  if (command === "diff") {
    if (!base || !head) {
      throw new Error("diff needs base and head revisions. On pull_request they default to the pull request's base commit and merge commit; on other events set the base and head inputs");
    }
    args.push(base, head);
    if (path !== ".") args.push("--dir", path);
  }
  // A private registry's host, so its lockfile URLs are not WS-LK-002; soak has no such flag and takes registry.
  if (command === "scan" || command === "diff") for (const host of registryHosts) args.push("--registry-host", host);
  if (command === "soak") {
    args.push(path);
    const configOnly = bool(env, "WS_CONFIG_ONLY", false);
    if (configOnly) args.push("--config-only");
    // With a base (on pull_request it defaults to the PR's base commit) an npm or Python entry the base's own soak read
    // identically is skipped, and the baseline comes from the base.
    else if (base) args.push("--base", base);
    if (bool(env, "WS_REQUIRE_CONFIG", false)) args.push("--require-config");
    const minAge = str(env, "WS_MIN_AGE");
    if (minAge) args.push("--min-age", minAge);
    // The CLI validates it (https, no credentials) before any network access.
    const pypiIndex = str(env, "WS_PYPI_INDEX");
    if (pypiIndex) args.push("--pypi-index", pypiIndex);
    // The same: the CLI refuses http (but for localhost) and credentials, exit 2.
    if (registry) args.push("--registry", registry);
    if (!bool(env, "WS_OSV", true)) args.push("--no-osv");
    if (onOutage === "warn") args.push("--on-outage", "warn");
  }

  const failOn = str(env, "WS_FAIL_ON");
  if (failOn) args.push("--fail-on", failOn);
  const baseline = str(env, "WS_BASELINE");
  // no-baseline: read no baseline at all, not even the checked-out tree's own, which a pushed branch controls.
  const noBaseline = bool(env, "WS_NO_BASELINE", false);
  if (noBaseline && baseline) throw new Error("baseline and no-baseline cannot be used together");
  if (baseline) args.push("--baseline", baseline);
  if (noBaseline) args.push("--no-baseline");
  // scan on a pull request reads the checked-out change, whose own .wormsign-baseline.json the change can edit: with
  // neither input set, main() gives it the base revision's file instead, as diff and soak --base read theirs.
  const baselineFrom = command === "scan" && event === "pull_request" && base !== "" && !baseline && !noBaseline ? base : undefined;
  return { command, args, ...(warning ? { warning } : {}), ...(baselineFrom ? { baselineFrom } : {}) };
}

/** The baseline a file at the base revision holds, as main() passes it to scan: the file's text, or an empty baseline. */
const EMPTY_BASELINE = '{"version":1,"entries":[]}\n';

/**
 * The text of `<dir>/.wormsign-baseline.json` at revision `rev`, or an empty baseline when the revision has none. git
 * is found on PATH as the CLI finds it (never inside the checked-out tree), started from the filesystem root, with
 * lazy fetching and every transport off. Any other failure throws: the step stops rather than fall back to the
 * change's own file.
 */
export async function baselineAt(dir, rev, env = process.env) {
  const { findProgram } = await import(pathToFileURL(join(ROOT, "dist", "src", "exec.js")).href);
  const program = findProgram("git", env, [resolve(dir)]);
  if (!("path" in program)) throw new Error(`cannot read the base revision's baseline: ${program.refused ?? program.missing}`);
  const git = (args) =>
    spawnSync(program.path, ["-c", "protocol.allow=never", "-c", "core.fsmonitor=false", "-C", resolve(dir), ...args], {
      cwd: parse(process.cwd()).root,
      env: { ...env, GIT_NO_LAZY_FETCH: "1", GIT_TERMINAL_PROMPT: "0" },
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
    });
  const commit = git(["rev-parse", "--verify", "--quiet", "--end-of-options", `${rev}^{commit}`]);
  if (commit.status !== 0) throw new Error(`cannot read the base revision's baseline: "${rev}" is not a commit in ${dir} (check out with fetch-depth 0, or enough history to hold the base)`);
  const sha = commit.stdout.trim();
  const listed = git(["ls-tree", "--name-only", sha, "--", ".wormsign-baseline.json"]);
  if (listed.status !== 0) throw new Error(`cannot read the base revision's baseline: git ls-tree failed (${(listed.stderr ?? "").split("\n")[0]})`);
  if (listed.stdout.trim() === "") return EMPTY_BASELINE;
  const shown = git(["show", `${sha}:./.wormsign-baseline.json`]);
  if (shown.status !== 0) throw new Error(`cannot read the base revision's baseline: git show failed (${(shown.stderr ?? "").split("\n")[0]})`);
  return shown.stdout;
}

/**
 * Whether action.yml's upload step runs, and the notice to print when it does not. upload-sarif "true" always uploads,
 * and a failed upload fails the job; "false" never does. "auto", the default, uploads when the event says the
 * repository is public (github.event.repository.private, passed as WS_REPOSITORY_PRIVATE, is "false"): code
 * scanning on a private repository needs GitHub Code Security, and an upload without it fails the job even when the
 * gate passes. A private repository, an event without the field, or a pull_request from a fork (WS_HEAD_REPO, the
 * head repository's full name, is not WS_REPO, github.repository) skips the upload with a notice; the SARIF file is
 * written either way. Pure, so it is unit-tested.
 */
export function sarifUpload(env) {
  const v = str(env, "WS_UPLOAD_SARIF") || "auto";
  if (v === "true" || v === "false") return { upload: v === "true" };
  if (v !== "auto") throw new Error(`upload-sarif must be "auto", "true" or "false", got "${v}"`);
  // A pull_request from a fork runs with a read-only token. Whether code scanning takes its upload is untested here
  // (docs/github-action.md, Code scanning), so auto skips it, as this repository's own workflows do: the gate's result
  // must not depend on it.
  const headRepo = str(env, "WS_HEAD_REPO");
  if (str(env, "GITHUB_EVENT_NAME") === "pull_request" && headRepo !== "" && headRepo !== str(env, "WS_REPO")) {
    return {
      upload: false,
      notice: "upload-sarif is auto and this pull request comes from a fork, whose token is read-only, so the SARIF report was not uploaded to code scanning. Keep it as an artifact, or set upload-sarif: \"true\" to try the upload",
    };
  }
  const visibility = str(env, "WS_REPOSITORY_PRIVATE");
  if (visibility === "false") return { upload: true };
  const why = visibility === "true" ? "this repository is private" : "this event does not say whether the repository is public";
  return {
    upload: false,
    notice: `upload-sarif is auto and ${why}, so the SARIF report was not uploaded to code scanning (a private repository needs GitHub Code Security for it). Set upload-sarif: "true" to upload, with security-events: write`,
  };
}

/**
 * Writes the SARIF report as the CLI writes --output: never through a symlink in the last path component
 * (O_NOFOLLOW), without waiting on a FIFO (O_NONBLOCK: with no reader the open fails at once, with ENXIO), and only
 * to a regular file. A checked-out tree can commit a symlink under the name the sarif input gives, which would
 * otherwise point the write at any file the runner user can write.
 */
export function writeReport(path, text) {
  let fd;
  try {
    fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0), 0o644);
  } catch (e) {
    throw new Error(e.code === "ELOOP" ? `sarif ${path} is a symbolic link; refusing to write through it` : `cannot write sarif ${path}: ${e.code ?? e.message}`, { cause: e });
  }
  try {
    if (!fstatSync(fd).isFile()) throw new Error(`sarif ${path} is not a regular file; refusing to write to it`);
    writeFileSync(fd, text);
  } finally {
    closeSync(fd);
  }
}

/** Unsuppressed findings: what the human report lists and the SARIF file contains. */
export function activeFindings(report) {
  return report.findings.filter((f) => !f.suppressed).length;
}

/**
 * The gate's SARIF file: one run per command that produced a report, in the order they ran, each exactly the run of
 * that command's own SARIF (rule ids, fingerprints and all) plus automationDetails.id "wormsign-<command>/". Code
 * scanning rejects a file with two runs of one tool and category (GitHub changelog, 2025-07-21, "Code scanning will
 * stop combining multiple SARIF runs uploaded in the same SARIF file"); each run's category is the one the three-call
 * recipe's uploads used (category wormsign-<command>, to which upload-sarif adds the "/"), so alerts carry over, and
 * upload-sarif only fills in a category for a run that has none (populateRunAutomationDetails). One merged run
 * instead would have put a finding diff and scan both report in one category twice, and left the recipe's alerts in
 * categories no upload refreshes. `docs` holds each command and its parsed SARIF. Pure, so it is unit-tested.
 */
export function gateSarif(docs) {
  const [first] = docs;
  if (first === undefined) throw new Error("no SARIF to combine");
  return { ...first.sarif, runs: docs.map(({ command, sarif }) => ({ ...sarif.runs[0], automationDetails: { id: `wormsign-${command}/` } })) };
}

/** Markdown for $GITHUB_STEP_SUMMARY: each command's UNVERIFIED line, if any (empty otherwise). HTML is escaped. */
export function stepSummary(reports) {
  const lines = reports.flatMap(({ command, report }) => (report.notes ?? []).filter((n) => typeof n === "string" && n.startsWith(UNVERIFIED)).map((n) => `- \`${command}\`: ${safeLine(n).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")}`));
  return lines.length === 0 ? "" : `### wormsign: packages not verified\n\n${lines.join("\n")}\n\nAn outage left these unchecked, and \`on-outage: warn\` reports them at medium. Re-run the gate before merging.\n`;
}

/**
 * Runs one planned command: the CLI with a JSON report, then that report rendered to the log. Returns the exit code
 * and, when the CLI produced one, the report. In the gate (`keepGoing`), a base baseline that cannot be read is an
 * error annotation and exit 2 for that command, so the others still run; alone, it stops the step, as before.
 */
async function runCommand(env, step, work, keepGoing) {
  const { command, args, baselineFrom } = step;
  const json = join(work, `${command}.json`);
  if (baselineFrom) {
    const file = join(work, "base-baseline.json");
    let text;
    try {
      text = await baselineAt(str(env, "WS_PATH") || ".", baselineFrom, env);
    } catch (e) {
      if (!keepGoing) throw e;
      console.log(workflowCommand("error", e.message));
      return { command, code: 2 };
    }
    writeFileSync(file, text);
    args.push("--baseline", file);
    console.log(safeLine(`wormsign: scan reads the baseline as committed in the base revision ${baselineFrom}, not the change's own`));
  }
  console.log(safeLine(`wormsign ${args.join(" ")}`));
  // stdout is unused (the report goes to --output); stderr carries CLI errors to the log.
  const res = spawnSync(process.execPath, [CLI, ...args, "--format", "json", "--output", json], { stdio: ["ignore", "inherit", "inherit"] });
  const code = res.status ?? 2;
  if ((code !== 0 && code !== 1) || !existsSync(json)) return { command, code: code === 0 || code === 1 ? 2 : code };
  const parsed = JSON.parse(readFileSync(json, "utf8"));
  const report = { command: parsed.command, findings: parsed.findings, notes: parsed.notes, toolVersion: parsed.version };
  const { renderReport } = await import(pathToFileURL(REPORT).href);
  process.stdout.write(renderReport(report, "human"));
  for (const note of report.notes ?? []) {
    // The checked tree's own baseline hid something (src/main.ts warnTreeBaseline): an annotation, not only a log line.
    // A branch pushed with a stolen token can bring such a file; no-baseline reads none.
    if (typeof note === "string" && note.startsWith(TREE_BASELINE)) console.log(workflowCommand("warning", note.slice("warning: ".length)));
    // --on-outage warn left packages unchecked: an annotation too, and the step summary (main).
    if (typeof note === "string" && note.startsWith(UNVERIFIED)) console.log(workflowCommand("warning", note));
  }
  return { command, code, report };
}

function setOutputs(env, outputs) {
  const lines = Object.entries(outputs).map(([k, v]) => {
    if (/[\r\n]/.test(String(v))) throw new Error(`output ${k} contains a line break`);
    return `${k}=${v}\n`;
  });
  if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, lines.join(""));
  else process.stdout.write(lines.join(""));
}

export async function main(env = process.env) {
  const major = Number(process.versions.node.split(".")[0]);
  if (major < 22) throw new Error(`wormsign needs Node.js 22 or newer on the runner, found ${process.versions.node}`);
  if (!existsSync(CLI)) {
    throw new Error(
      `${CLI} is missing. Pin the action to a release tag commit (vX.Y.Z), which contains the compiled CLI, ` +
        "or build first when using the action from a checkout (npm ci --ignore-scripts && npm run build).",
    );
  }
  const steps = plans(env);
  const { upload, notice } = sarifUpload(env);
  // A workflow command, so it shows as an annotation; input values in it are escaped (safeLine).
  for (const { warning } of steps) if (warning) console.log(workflowCommand("warning", warning));
  const gate = steps.length > 1;
  // The command output names the upload's category; the gate's runs carry their own (gateSarif).
  const command = gate ? "gate" : steps[0].command;
  // A fresh directory per run by default, so two uses of the action in one job keep separate reports.
  const sarif = str(env, "WS_SARIF") || join(mkdtempSync(join(env.RUNNER_TEMP || tmpdir(), "wormsign-sarif-")), `${command}.sarif`);
  const work = mkdtempSync(join(env.RUNNER_TEMP || tmpdir(), "wormsign-action-"));
  try {
    const done = [];
    for (const step of steps) done.push(await runCommand(env, step, work, gate));
    const reports = done.filter((d) => d.report !== undefined);
    // The worst: 2 (an error) over 1 (findings) over 0.
    const code = Math.max(...done.map((d) => d.code));
    if (reports.length === 0) {
      setOutputs(env, { "exit-code": code, findings: "", sarif: "", command, "upload-sarif": "false" });
      return 2;
    }
    const { neutralise, renderReport } = await import(pathToFileURL(REPORT).href);
    mkdirSync(dirname(sarif), { recursive: true });
    // Rendered as the CLI renders SARIF (src/report.ts renderReport), so each run's text is what its command writes.
    const sarifOf = (r) => renderReport(r.report, "sarif");
    writeReport(sarif, gate ? `${JSON.stringify(gateSarif(reports.map((r) => ({ command: r.command, sarif: JSON.parse(sarifOf(r)) }))), null, 2).split("\n").map(neutralise).join("\n")}\n` : sarifOf(reports[0]));
    // The path is the sarif input or under RUNNER_TEMP, escaped like every line this script prints.
    if (notice) console.log(workflowCommand("notice", `${notice}. The report is at ${sarif} (the sarif output).`));
    const summary = stepSummary(reports);
    if (summary !== "" && env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, summary);
    const findings = reports.reduce((n, r) => n + activeFindings(r.report), 0);
    setOutputs(env, { "exit-code": code, findings, sarif, command, "upload-sarif": upload ? "true" : "false" });
    return 0;
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

// Compared as real paths: Node resolves symlinks for the entry module, so a script reached through a symlinked
// directory would otherwise never run main() and exit 0 without doing anything.
if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(
    (code) => process.exit(code),
    (e) => {
      // A workflow command, so the message shows as an annotation; input values it quotes are escaped (safeLine).
      console.log(workflowCommand("error", e.message));
      process.exit(2);
    },
  );
}
