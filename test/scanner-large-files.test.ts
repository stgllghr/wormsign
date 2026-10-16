// Exfiltration endpoints from the IOC list (WS-EX-002) are plain substrings, so a code file over the 2 MiB text cap
// is still searched for them, in overlapping chunks, up to 64 MiB: the payloads they come from were 3.6 and 10 MB.
// A code file that cannot be searched is a low WS-SC-900 finding, not only a note.
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, truncateSync } from "node:fs";
import { join } from "node:path";
import { scanDirectory } from "../src/scan.js";
import { readChunks } from "../src/fsutil.js";
import { testCtx } from "./helpers.js";
import { tempTree } from "./validation-helpers.js";

const MIB = 1024 * 1024;
const ENDPOINT = "https://wormsign-marker.invalid/collect"; // the synthetic IOC in test/fixtures/iocs
const scan = (d: string, nodeModules = false) => scanDirectory(d, testCtx(), { nodeModules });
const ex2 = (r: ReturnType<typeof scan>) => r.findings.filter((f) => f.ruleId === "WS-EX-002").map((f) => `${f.severity} ${f.file}:${f.line}`).sort();

/** `lines` lines of "//", padded so that ENDPOINT starts `before` bytes ahead of the 2 MiB chunk boundary; then 1 MiB more. */
function straddling(before: number): { text: string; line: number } {
  const lines = Math.floor((2 * MIB - before) / 3);
  const head = "//\n".repeat(lines) + " ".repeat(2 * MIB - before - 3 * lines);
  return { text: `${head}${ENDPOINT}\n${"y".repeat(MIB)}`, line: lines + 1 };
}

test("scan: an IOC endpoint in a 3 MiB code file is found, across a chunk boundary, on its own line", () => {
  const { text, line } = straddling(10);
  const d = tempTree({ "dist/bundle.js": text, "node_modules/p/index.js": text });
  const r = scan(d, true);
  assert.deepEqual(ex2(r), [`critical dist/bundle.js:${line}`, `critical node_modules/p/index.js:${line}`]);
  // Generic hosts are matched only up to the text cap; that is said, outside node_modules, where they are checked at all.
  assert.deepEqual(r.notes.filter((n) => n.startsWith("searched")), ["searched dist/bundle.js for exfiltration endpoints from the IOC list only, not for webhook, paste or tunnel hosts (WS-EX-001): it is larger than 2 MiB"]);
  assert.deepEqual(r.findings.filter((f) => f.ruleId === "WS-SC-900"), []);
});

test("scan: a code file with a NUL byte is still searched for IOC endpoints", () => {
  assert.deepEqual(ex2(scan(tempTree({ "x.js": `a\0b\n${ENDPOINT}\n` }))), ["critical x.js:2"]);
});

test("scan: a code file over 64 MiB, or one that cannot be read, is a low WS-SC-900 finding", () => {
  const d = tempTree({ "huge.js": "x", "secret.js": "x", "huge.txt": "x" });
  truncateSync(join(d, "huge.js"), 64 * MIB + 1); // sparse: cheap to create
  truncateSync(join(d, "huge.txt"), 64 * MIB + 1); // not code: not searched, not reported
  const unreadable = process.getuid?.() !== 0 && process.platform !== "win32";
  if (unreadable) chmodSync(join(d, "secret.js"), 0o000);
  const r = scan(d);
  const sc = r.findings.filter((f) => f.ruleId === "WS-SC-900").map((f) => `${f.severity} ${f.file} ${f.message}`).sort();
  assert.deepEqual(sc, [
    "low huge.js huge.js was not checked: it is larger than 64 MiB, so it was not searched for exfiltration endpoints from the IOC list",
    ...(unreadable ? ["low secret.js secret.js was not checked: it could not be read (EACCES), so it was not searched for exfiltration endpoints from the IOC list"] : []),
  ]);
  if (unreadable) chmodSync(join(d, "secret.js"), 0o600);
});

test("readChunks: overlapping chunks see every byte, count lines from the start of the file, and stop at the cap", () => {
  const d = tempTree({ "f": "a\nbb\nccc\ndddd\n" });
  const seen: [string, number][] = [];
  assert.deepEqual(readChunks(join(d, "f"), { maxBytes: 100, chunkBytes: 4, overlap: 2 }, (c, line) => seen.push([c.toString(), line])), { size: 14 });
  assert.deepEqual(seen, [["a\nbb", 1], ["bb\nccc", 2], ["cc\nddd", 3], ["ddd\n", 4]]);
  assert.deepEqual(readChunks(join(d, "f"), { maxBytes: 13, chunkBytes: 4, overlap: 2 }, () => assert.fail("nothing is read past the cap")), { problem: `it is larger than ${13 / 1024 / 1024} MiB` });
});
