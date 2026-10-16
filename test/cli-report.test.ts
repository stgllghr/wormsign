import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bundledIocDir } from "../src/iocs.js";
import { run } from "../src/main.js";
import { fakeIO, fx } from "./helpers.js";

const IOCS = ["--iocs", fx("iocs")];

function project(files: Record<string, string>): string {
  const d = mkdtempSync(join(tmpdir(), "ws-report-"));
  for (const [p, t] of Object.entries(files)) writeFileSync(join(d, p), t);
  return d;
}

async function json(argv: string[]): Promise<{ code: number; notes: string[] }> {
  const io = fakeIO();
  const code = await run([...argv, "--format", "json"], io);
  return { code, notes: (JSON.parse(io.out) as { notes: string[] }).notes };
}

test("cli: repository text in an error message cannot inject workflow commands through stderr", async () => {
  const baseline = { version: 1, entries: [], ignorePaths: [{ path: "a\n::error file=x,line=1::forged\n  ::stop-commands::dead", justification: "x" }] };
  const d = project({ ".wormsign-baseline.json": JSON.stringify(baseline) });
  const io = fakeIO();
  assert.equal(await run(["scan", d, ...IOCS], io), 2);
  assert.match(io.err, /needs a real justification/, "positive control: the message is printed");
  for (const line of io.err.split("\n")) assert.doesNotMatch(line, /^\s*::|##\[/, line);
});

test("cli: a baseline that is not JSON is named without quoting what it contains", async () => {
  const d = project({ "secret.txt": "TOKEN=abcdef123456", ".wormsign-baseline.json": "TOKEN=abcdef123456" });
  const io = fakeIO();
  assert.equal(await run(["scan", d, ...IOCS], io), 2);
  assert.match(io.err, /is not valid JSON/);
  assert.doesNotMatch(io.err, /TOKEN|abcdef/);
  // A symlink in its place is not even opened: refused for what it is, so nothing it points at is read or quoted.
  const l = project({ "secret.txt": "TOKEN=abcdef123456" });
  symlinkSync(join(l, "secret.txt"), join(l, ".wormsign-baseline.json"));
  const linked = fakeIO();
  assert.equal(await run(["scan", l, ...IOCS], linked), 2);
  assert.match(linked.err, /it is a symlink/);
  assert.doesNotMatch(linked.err, /TOKEN|abcdef/);
});

test("cli: --help documents only options that work", async () => {
  const io = fakeIO();
  await run(["--help"], io);
  assert.doesNotMatch(io.out, /--cache-file/);
  assert.match(io.out, /--base <rev> /);
});

test("cli: --help is a reference that fits a screen: usage and options, every line whole, design notes in the docs", async () => {
  const io = fakeIO();
  await run(["--help"], io);
  const lines = io.out.trimEnd().split("\n");
  assert.ok(lines.length <= 60, `${lines.length} lines`);
  for (const l of lines) assert.ok(l.length <= 120, `${l.length}: ${l}`);
  // A paragraph is wrapped evenly: a short line inside one ("exactly one; on a full", then the sentence going on below)
  // is a line break someone left in by hand.
  for (const [i, l] of lines.entries()) {
    const next = lines[i + 1] ?? "";
    if (l !== "" && !l.startsWith(" ") && next !== "" && !next.startsWith(" ") && !l.endsWith(":") && l.length < 60) assert.fail(`line ${i + 1} is cut short: ${l}`);
  }
  // Every option row starts with its flag, and a description that goes on is indented under the description.
  const options = lines.slice(lines.indexOf("Options:") + 1, lines.findIndex((l, i) => i > lines.indexOf("Options:") && l === ""));
  for (const l of options) assert.match(l, /^ {2}--\S|^ {36}\S/, l);
  assert.match(io.out, /docs\/cli\/<command>\.md/);
});

test("cli: scan and diff say which IOC data they used", async () => {
  const scan = await json(["scan", fx("clean"), ...IOCS]);
  assert.ok(scan.notes.some((n) => n.startsWith("IOC data ") && n.includes(`--iocs ${fx("iocs")}`)), scan.notes.join("|"));
  const bundled = await json(["scan", fx("clean")]);
  assert.ok(bundled.notes.some((n) => n.includes(`from the bundled data ${bundledIocDir}`)), bundled.notes.join("|"));
  const diff = await json(["diff", `dir:${fx("clean")}`, `dir:${fx("clean")}`, ...IOCS]);
  assert.ok(diff.notes.some((n) => n.startsWith("IOC data ")), diff.notes.join("|"));
});

test("cli: scan notes a baseline entry that matches no finding", async () => {
  const entry = { fingerprint: "0123456789abcdef0123456789abcdef", justification: "Accepted before the fingerprint changed" };
  const d = project({ ".wormsign-baseline.json": JSON.stringify({ version: 1, entries: [entry] }) });
  const r = await json(["scan", d, ...IOCS]);
  assert.ok(r.notes.includes("baseline entry 0123456789abcdef0123456789abcdef matches no finding"), r.notes.join("|"));
});

test("cli: diff names the baseline its ignored paths came from", async () => {
  const b = { version: 1, entries: [], ignorePaths: [{ path: "fixtures", justification: "Inert fixtures for the test suite" }] };
  const d = project({ "b.json": JSON.stringify(b) });
  const r = await json(["diff", `dir:${fx("clean")}`, `dir:${fx("clean")}`, "--baseline", join(d, "b.json"), ...IOCS]);
  const note = r.notes.find((n) => n.startsWith("ignored paths"));
  assert.ok(note?.includes(`baseline ${join(d, "b.json")};`), note);
});

test("cli update-iocs: data that is already current is said so, not reported as an update", async () => {
  const files = Object.fromEntries(
    ["packages", "files", "workflows", "repos", "endpoints"].map((n) => [`${n}.json`, JSON.stringify({ ...JSON.parse(readFileSync(join(bundledIocDir, `${n}.json`), "utf8")), version: "2000-01-01" })]),
  );
  const fetchImpl = (async (u: string | URL) => new Response(files[String(u).split("/").pop() as string])) as typeof fetch;
  const io = fakeIO({ fetchImpl });
  assert.equal(await run(["update-iocs", "--url", "https://example.test/i/"], io), 0);
  assert.match(io.out, /already current/);
  assert.doesNotMatch(io.out, /cache updated/);
});

test("cli soak: a symlink loop is a finding, not a crash", async () => {
  const d = project({ "package.json": '{"name":"p"}', "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: { "": {} } }) });
  symlinkSync("b", join(d, "a"));
  symlinkSync("a", join(d, "b"));
  const io = fakeIO({ env: { HOME: d } });
  assert.equal(await run(["soak", d, "--config-only", "--format", "json"], io), 1);
  assert.doesNotMatch(io.err, /internal error/);
  const findings = (JSON.parse(io.out) as { findings: { file: string; message: string }[] }).findings;
  assert.ok(findings.some((f) => f.file === "a" && /could not be resolved \(ELOOP\)/.test(f.message)));
});
