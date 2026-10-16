// `wormsign baseline add`: appends reviewed findings to a baseline file, each with a reason a person wrote. What it
// refuses (a bad fingerprint, one already there, a placeholder reason, a past or impossible expiry, a link, a missing
// directory, a file no command could read back), what it keeps (every field, as written, and the file's mode), how it
// writes (a temporary file renamed into place) and that a scan accepts what it writes and suppresses the finding.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, statSync, symlinkSync, unlinkSync, writeFileSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { addToBaseline } from "../src/baseline-add.js";
import { MAX_BASELINE_BYTES } from "../src/baseline.js";
import { run } from "../src/main.js";
import type { Finding } from "../src/types.js";
import { UsageError } from "../src/types.js";
import { NOW, escapeRegExp, fakeIO, fx } from "./helpers.js";

const CLI = fileURLToPath(new URL("../src/cli.js", import.meta.url));
const FP1 = "0123456789abcdef0123456789abcdef";
const FP2 = "fedcba9876543210fedcba9876543210";
const FP3 = "77e37b5c68b360e38667f4d11053b4bd";
const WHY = "setup.js only copies a config template; reviewed in PR 41";

const tmp = (): string => mkdtempSync(join(tmpdir(), "ws-bladd-"));

async function cli(argv: string[], over: Parameters<typeof fakeIO>[0] = {}): Promise<{ code: number; out: string; err: string }> {
  const io = fakeIO(over);
  const code = await run(argv, io);
  return { code, out: io.out, err: io.err };
}

/** `baseline add` with --baseline <file>, as run() runs it. */
const add = (file: string, ...rest: string[]) => cli(["baseline", "add", ...rest, "--baseline", file]);

const pretty = (o: unknown): string => `${JSON.stringify(o, null, 2)}\n`;

test("baseline add: one entry into a new file, written as 2-space JSON, and printed", async () => {
  const file = join(tmp(), "b.json");
  const r = await add(file, FP1, "--reason", WHY, "--expires", "2027-01-31");
  assert.equal(r.code, 0, r.err);
  // Without --from, one line says the fingerprint was not checked and how to have it checked.
  assert.equal(r.err, "wormsign: note: not checked against a report; pass --from <report.json> (a --format json report) to refuse a fingerprint that is no finding there or whose finding no entry can approve\n");
  assert.equal(readFileSync(file, "utf8"), pretty({ version: 1, entries: [{ fingerprint: FP1, justification: WHY, expires: "2027-01-31" }] }));
  assert.equal(r.out, `added ${FP1} (expires 2027-01-31): ${WHY}\n${file}: 1 entry added (new file)\n`);
});

test("baseline add: several fingerprints in one call are appended after the entries already there, in order", async () => {
  const file = join(tmp(), "b.json");
  assert.equal((await add(file, FP1, "--reason", WHY)).code, 0);
  const r = await add(file, FP2, FP3, "--reason", "  Both are the vendored test harness, reviewed in PR 7  ");
  assert.equal(r.code, 0, r.err);
  const second = "Both are the vendored test harness, reviewed in PR 7";
  assert.deepEqual(JSON.parse(readFileSync(file, "utf8")), {
    version: 1,
    entries: [
      { fingerprint: FP1, justification: WHY },
      { fingerprint: FP2, justification: second },
      { fingerprint: FP3, justification: second },
    ],
  });
  assert.equal(r.out, `added ${FP2}: ${second}\nadded ${FP3}: ${second}\n${file}: 2 entries added\n`);
});

test("baseline add: every field already in the file is kept as written, ignorePaths included, and so is its mode", async () => {
  const file = join(tmp(), "b.json");
  // An ignorePaths prefix the reader normalises ("./test/fixtures/") and a padded justification: kept as they are.
  const before = {
    version: 1,
    ignorePaths: [{ path: "./test/fixtures/", justification: "  Inert synthetic fixtures for the test suite  " }],
    entries: [{ justification: "Field order as the author wrote it, reviewed", fingerprint: FP1, expires: "2030-01-01" }],
  };
  writeFileSync(file, `\uFEFF${JSON.stringify(before)}`);
  chmodSync(file, 0o604);
  const r = await add(file, FP2, "--reason", WHY);
  assert.equal(r.code, 0, r.err);
  assert.equal(readFileSync(file, "utf8"), pretty({ ...before, entries: [...before.entries, { fingerprint: FP2, justification: WHY }] }));
  assert.equal(statSync(file).mode & 0o777, 0o604, "the file keeps its permissions");
});

test("baseline add: a fingerprint already in the file, or given twice, is refused and nothing is written", async () => {
  const file = join(tmp(), "b.json");
  writeFileSync(file, pretty({ version: 1, entries: [{ fingerprint: FP2, justification: "Expired, to be reviewed again", expires: "2020-01-01" }] }));
  const text = readFileSync(file, "utf8");
  const dup = await add(file, FP1, FP2, "--reason", WHY);
  assert.equal(dup.code, 2);
  assert.match(dup.err, new RegExp(`fingerprint ${FP2} is already in entries\\[0\\]; edit that entry`));
  const twice = await add(file, FP1, FP1, "--reason", WHY);
  assert.equal(twice.code, 2);
  assert.match(twice.err, new RegExp(`fingerprint ${FP1} is given twice`));
  assert.equal(readFileSync(file, "utf8"), text);
  assert.equal(dup.out + twice.out, "");
});

test("baseline add: a fingerprint that is not 32 lower-case hex characters is refused, and no file is created", async () => {
  const file = join(tmp(), "b.json");
  for (const bad of [FP1.toUpperCase(), FP1.slice(1), `${FP1}0`, `${FP1.slice(1)}g`, "77e37b5c"]) {
    const r = await add(file, bad, "--reason", WHY);
    assert.equal(r.code, 2, bad);
    assert.match(r.err, new RegExp(`"${bad}" is not a fingerprint: 32 lower-case hex characters`), bad);
  }
  // One bad fingerprint among good ones refuses them all.
  assert.equal((await add(file, FP1, "nothex", "--reason", WHY)).code, 2);
  assert.equal(existsSync(file), false);
  assert.equal((await add(file, FP1, "--reason", WHY)).code, 0, "control: a real fingerprint is added");
});

test("baseline add: a reason shorter than 15 characters, a placeholder or none at all is refused", async () => {
  const file = join(tmp(), "b.json");
  for (const reason of ["ok", "n/a", "reviewed", "   fourteen chars   ".padEnd(30), "TODO: review this one later", "fixme before the release"]) {
    const r = await add(file, FP1, "--reason", reason);
    assert.equal(r.code, 2, reason);
    assert.match(r.err, /--reason needs a real justification \(at least 15 characters, not a placeholder\)/, reason);
  }
  const none = await cli(["baseline", "add", FP1, "--baseline", file]);
  assert.equal(none.code, 2);
  assert.match(none.err, /baseline add needs --reason/);
  assert.equal(existsSync(file), false);
  assert.equal((await add(file, FP1, "--reason", "exactly 15 char")).code, 0, "control: 15 characters is enough");
});

test("baseline add: an expiry in the past is refused; today, the last day an entry suppresses, is accepted", async () => {
  // fakeIO's clock is 2026-10-01T12:00:00Z.
  assert.equal(NOW.toISOString(), "2026-10-01T12:00:00.000Z");
  const file = join(tmp(), "b.json");
  for (const day of ["2026-09-30", "2020-01-01"]) {
    const r = await add(file, FP1, "--reason", WHY, "--expires", day);
    assert.equal(r.code, 2, day);
    assert.match(r.err, new RegExp(`--expires ${day} is in the past`));
  }
  assert.equal(existsSync(file), false);
  const today = await add(file, FP1, "--reason", WHY, "--expires", "2026-10-01");
  assert.equal(today.code, 0, today.err);
  assert.equal((JSON.parse(readFileSync(file, "utf8")) as { entries: { expires: string }[] }).entries[0]?.expires, "2026-10-01");
});

test("baseline add: an expiry that is not a real YYYY-MM-DD date is refused", async () => {
  const file = join(tmp(), "b.json");
  for (const day of ["2027-02-30", "2027-13-01", "2027-1-5", "tomorrow", "2027-01-31T00:00:00Z", "31/01/2027"]) {
    const r = await add(file, FP1, "--reason", WHY, "--expires", day);
    assert.equal(r.code, 2, day);
    assert.match(r.err, new RegExp(`invalid --expires "${escapeRegExp(day)}" \\(a real date written YYYY-MM-DD\\)`), day);
  }
  const twice = await add(file, FP1, "--reason", WHY, "--expires", "2027-01-31", "--expires", "2028-01-31");
  assert.equal(twice.code, 2);
  assert.match(twice.err, /--expires is given more than once/);
  assert.equal(existsSync(file), false);
});

test("baseline add: a symlinked baseline is refused, dangling or not, and neither the link nor its target changes", async () => {
  const d = tmp();
  const target = join(d, "real.json");
  const text = pretty({ version: 1, entries: [] });
  writeFileSync(target, text);
  symlinkSync(target, join(d, "link.json"));
  symlinkSync(join(d, "missing.json"), join(d, "dangling.json"));
  for (const name of ["link.json", "dangling.json"]) {
    const r = await add(join(d, name), FP1, "--reason", WHY);
    assert.equal(r.code, 2, name);
    assert.match(r.err, /it is a symlink, which baseline add does not write through or replace/, name);
    assert.ok(lstatSync(join(d, name)).isSymbolicLink(), `${name} is still a link`);
  }
  assert.equal(readFileSync(target, "utf8"), text);
  assert.equal(existsSync(join(d, "missing.json")), false);
  assert.deepEqual(readdirSync(d).sort(), ["dangling.json", "link.json", "real.json"]);
});

test("baseline add: a directory or a FIFO at the baseline path is refused as not a regular file", async () => {
  const d = tmp();
  mkdirSync(join(d, "dir.json"));
  execFileSync("mkfifo", [join(d, "fifo.json")]);
  for (const name of ["dir.json", "fifo.json"]) {
    const r = await add(join(d, name), FP1, "--reason", WHY);
    assert.equal(r.code, 2, name);
    assert.match(r.err, /it is not a regular file/, name);
    assert.doesNotMatch(r.err, /internal error/, name);
  }
});

test("baseline add: a baseline in a directory that does not exist is refused, and no directory is made", async () => {
  const d = tmp();
  const r = await add(join(d, "no", "such", "b.json"), FP1, "--reason", WHY);
  assert.equal(r.code, 2);
  assert.match(r.err, new RegExp(`cannot create baseline .*: directory ${join(d, "no", "such")} does not exist`));
  assert.deepEqual(readdirSync(d), []);
});

test("baseline add: an existing baseline a scan would refuse is refused too, and left as it is", async () => {
  const file = join(tmp(), "b.json");
  for (const bad of ['{"version":1,"entries":[{"fingerprint":"0123456789abcdef0123456789abcdef","justification":"Reviewed in PR 9 by the owner","expiry":"2027-01-01"}]}', "{not json", '{"version":2,"entries":[]}']) {
    writeFileSync(file, bad);
    const r = await add(file, FP2, "--reason", WHY);
    assert.equal(r.code, 2, bad);
    assert.match(r.err, /unknown key "expiry"|is not valid JSON|expected \{"version":1/, bad);
    assert.equal(readFileSync(file, "utf8"), bad);
  }
});

test("baseline add: a file that would grow past the 2 MiB every command reads is refused, and left as it is", async () => {
  const file = join(tmp(), "b.json");
  const filler = (n: number) => pretty({ version: 1, ignorePaths: [{ path: "vendor", justification: "x".repeat(n) }], entries: [] });
  // Just under the cap: the file is readable, and one more entry pushes it over.
  const n = MAX_BASELINE_BYTES - filler(0).length - 40;
  const text = filler(n);
  assert.ok(Buffer.byteLength(text) <= MAX_BASELINE_BYTES);
  writeFileSync(file, text);
  const r = await add(file, FP1, "--reason", WHY);
  assert.equal(r.code, 2);
  assert.match(r.err, /would be larger than 2 MiB, which no command reads/);
  assert.equal(readFileSync(file, "utf8"), text);
  const small = join(tmp(), "b.json");
  writeFileSync(small, filler(n - 400));
  assert.equal((await add(small, FP1, "--reason", WHY)).code, 0, "control: with room for the entry it is added");
});

test("baseline add: the file is replaced by a rename; a failed write or rename leaves it whole and no temporary file behind", () => {
  const d = tmp();
  const file = join(d, "b.json");
  const text = pretty({ version: 1, entries: [{ fingerprint: FP1, justification: WHY }] });
  writeFileSync(file, text);
  const req = { fingerprints: [FP2], reason: WHY, now: NOW };
  const renamed: string[] = [];
  const failRename = { write: (fd: number, t: string) => void writeSync(fd, t), rename: (from: string) => {
    renamed.push(from);
    throw Object.assign(new Error("injected"), { code: "EIO" });
  } };
  assert.throws(() => addToBaseline(file, req, failRename), (e: unknown) => e instanceof UsageError && /cannot write baseline .*: EIO; the file is unchanged/.test(e.message));
  // The temporary file was written beside the baseline, so the rename never crosses a file system.
  assert.equal(renamed.length, 1);
  assert.equal(dirname(renamed[0] as string), d);
  assert.match(renamed[0] as string, /\/\.b\.json\.tmp-/);
  assert.deepEqual(readdirSync(d), ["b.json"]);
  assert.equal(readFileSync(file, "utf8"), text);
  // A write that fails half way.
  const failWrite = { write: (fd: number, t: string) => {
    writeSync(fd, t.slice(0, 10));
    throw Object.assign(new Error("injected"), { code: "ENOSPC" });
  }, rename: () => assert.fail("no rename after a failed write") };
  assert.throws(() => addToBaseline(file, req, failWrite), /ENOSPC; the file is unchanged/);
  assert.deepEqual(readdirSync(d), ["b.json"]);
  assert.equal(readFileSync(file, "utf8"), text);
  // Control: the default writes, and leaves only the baseline.
  assert.deepEqual(addToBaseline(file, req).added, [{ fingerprint: FP2, justification: WHY }]);
  assert.deepEqual(readdirSync(d), ["b.json"]);
  assert.equal((JSON.parse(readFileSync(file, "utf8")) as { entries: unknown[] }).entries.length, 2);
});

test("baseline add: eight run at once each add their entry, and no lock file is left behind", async () => {
  // A review's reproduction: 8 parallel adds left 2 entries in the file, and every one exited 0.
  const d = tmp();
  const fps = Array.from({ length: 8 }, (_, i) => (i + 1).toString(16).padStart(32, "0"));
  const runs = fps.map(
    (fp, i) =>
      new Promise<{ code: number | null; err: string }>((done) => {
        const child = spawn(process.execPath, [CLI, "baseline", "add", fp, "--reason", `Reviewed concurrently, number ${i + 1}`], { cwd: d, env: { ...process.env, XDG_CACHE_HOME: join(d, ".cache") } });
        let err = "";
        child.stderr.on("data", (c: Buffer) => (err += c.toString()));
        child.on("close", (code) => done({ code, err }));
      }),
  );
  const results = await Promise.all(runs);
  assert.deepEqual(results.map((r) => r.code), fps.map(() => 0), results.map((r) => r.err).join(""));
  const entries = (JSON.parse(readFileSync(join(d, ".wormsign-baseline.json"), "utf8")) as { entries: { fingerprint: string }[] }).entries;
  assert.deepEqual(entries.map((e) => e.fingerprint).sort(), [...fps].sort());
  assert.deepEqual(readdirSync(d).filter((f) => f !== ".cache"), [".wormsign-baseline.json"]);
});

test("baseline add: the file is locked from its read to its rename; a lock held elsewhere is waited for, then refused", () => {
  const d = tmp();
  const file = join(d, "b.json");
  writeFileSync(file, pretty({ version: 1, entries: [] }));
  const lockFile = join(d, ".b.json.lock");
  // Another add while this one writes (here, from inside its write) finds the lock, waits, and is refused.
  let inner: unknown;
  const ops = { write: (fd: number, t: string) => {
    assert.ok(existsSync(lockFile), "the lock is held while the file is written");
    try {
      addToBaseline(file, { fingerprints: [FP2], reason: WHY, now: NOW }, { write: () => assert.fail("no write"), rename: () => assert.fail("no rename"), lockWaitMs: 60 });
    } catch (e) {
      inner = e;
    }
    writeSync(fd, t);
  }, rename: renameSync };
  assert.deepEqual(addToBaseline(file, { fingerprints: [FP1], reason: WHY, now: NOW }, ops).added.map((e) => e.fingerprint), [FP1]);
  assert.ok(inner instanceof UsageError, String(inner));
  assert.equal(inner.message, `cannot add to baseline ${file}: its lock file ${lockFile} exists, so another baseline add (process ${process.pid}) is writing it; retry when that one is done, or remove ${lockFile} if none is running`);
  assert.deepEqual(readdirSync(d), ["b.json"], "the lock is removed when the add is done");
  assert.deepEqual((JSON.parse(readFileSync(file, "utf8")) as { entries: { fingerprint: string }[] }).entries.map((e) => e.fingerprint), [FP1]);
  // A lock whose process is running (here, this one), or holds no PID yet, is waited for, then refused and left where
  // it is; the file is not touched.
  const before = readFileSync(file, "utf8");
  const noWrite = { write: () => assert.fail("no write"), rename: () => assert.fail("no rename"), lockWaitMs: 100 };
  for (const [held, by] of [[`${process.pid}\n`, ` (process ${process.pid})`], ["", ""]] as const) {
    writeFileSync(lockFile, held);
    const t0 = Date.now();
    assert.throws(() => addToBaseline(file, { fingerprints: [FP2], reason: WHY, now: NOW }, noWrite), (e: unknown) => e instanceof UsageError && e.message === `cannot add to baseline ${file}: its lock file ${lockFile} exists, so another baseline add${by} is writing it; retry when that one is done, or remove ${lockFile} if none is running`);
    assert.ok(Date.now() - t0 >= 90, "it waited for the lock");
    assert.equal(readFileSync(lockFile, "utf8"), held);
    assert.equal(readFileSync(file, "utf8"), before);
  }
  // A failed add releases the lock too.
  rmSync(lockFile);
  assert.throws(() => addToBaseline(file, { fingerprints: [FP1], reason: WHY, now: NOW }), /already in entries\[0\]/);
  assert.deepEqual(readdirSync(d), ["b.json"]);
});

test("baseline add: a lock whose holder finishes while it is read is not called left over", () => {
  // The eight-at-once test failed once under load: one add read another's PID, that add removed its lock and exited,
  // and kill(pid, 0) then found no process. An add removes its lock before it exits, so the lock is gone on a second
  // look, and the open is tried again.
  const d = tmp();
  const file = join(d, "b.json");
  writeFileSync(file, pretty({ version: 1, entries: [] }));
  const lockFile = join(d, ".b.json.lock");
  const gone = spawnSync(process.execPath, ["-e", ""]).pid as number;
  writeFileSync(lockFile, `${gone}\n`);
  let reads = 0;
  const finishes = { write: (fd: number, t: string) => void writeSync(fd, t), rename: renameSync, lockWaitMs: 5000, lockRead: () => {
    reads++;
    rmSync(lockFile, { force: true });
  } };
  assert.deepEqual(addToBaseline(file, { fingerprints: [FP1], reason: WHY, now: NOW }, finishes).added, [{ fingerprint: FP1, justification: WHY }]);
  assert.equal(reads, 1);
  assert.deepEqual(readdirSync(d), ["b.json"], "the lock it then took is released");
  // Control: a lock still there on the second look is left over, and refused at once.
  writeFileSync(lockFile, `${gone}\n`);
  assert.throws(() => addToBaseline(file, { fingerprints: [FP2], reason: WHY, now: NOW }, { ...finishes, lockRead: () => void reads++ }), /is left over from process/);
  assert.equal(readFileSync(lockFile, "utf8"), `${gone}\n`);
});

test("baseline add: a lock left by a process that is no longer running, or a symlink or directory there, is named and never removed", () => {
  // A round-2 review: every lock was "another baseline add is writing it", even when its PID was dead or it was a link.
  const d = tmp();
  const file = join(d, "b.json");
  writeFileSync(file, pretty({ version: 1, entries: [] }));
  const lockFile = join(d, ".b.json.lock");
  const noWrite = { write: () => assert.fail("no write"), rename: () => assert.fail("no rename"), lockWaitMs: 5000 };
  const refused = (): string => {
    const t0 = Date.now();
    try {
      addToBaseline(file, { fingerprints: [FP1], reason: WHY, now: NOW }, noWrite);
    } catch (e) {
      assert.ok(e instanceof UsageError, String(e));
      assert.ok(Date.now() - t0 < 2000, "refused at once, without waiting for the lock");
      return e.message;
    }
    return assert.fail("refused");
  };
  const remove = `Remove it if no baseline add is running: rm -- '${lockFile}'`;
  // A process that has exited: kill(pid, 0) finds no such process.
  const gone = spawnSync(process.execPath, ["-e", ""]).pid as number;
  writeFileSync(lockFile, `${gone}\n`);
  assert.equal(refused(), `cannot add to baseline ${file}: its lock file ${lockFile} is left over from process ${gone}, which is no longer running; nothing was changed. ${remove}`);
  assert.equal(readFileSync(lockFile, "utf8"), `${gone}\n`, "the lock is left for the user");
  rmSync(lockFile);
  symlinkSync(join(d, "elsewhere"), lockFile);
  assert.equal(refused(), `cannot add to baseline ${file}: its lock file ${lockFile} is a symlink, which baseline add never makes; nothing was changed. ${remove}`);
  assert.ok(lstatSync(lockFile).isSymbolicLink());
  assert.equal(existsSync(join(d, "elsewhere")), false);
  unlinkSync(lockFile);
  mkdirSync(lockFile);
  assert.equal(refused(), `cannot add to baseline ${file}: its lock file ${lockFile} is not a regular file, which baseline add never makes; nothing was changed. ${remove}`);
  assert.ok(statSync(lockFile).isDirectory());
  assert.equal(readFileSync(file, "utf8"), pretty({ version: 1, entries: [] }));
  // The rm command quotes the path for a shell.
  const odd = join(tmp(), "it's");
  mkdirSync(odd);
  writeFileSync(join(odd, "b.json"), pretty({ version: 1, entries: [] }));
  writeFileSync(join(odd, ".b.json.lock"), `${gone}\n`);
  assert.throws(() => addToBaseline(join(odd, "b.json"), { fingerprints: [FP1], reason: WHY, now: NOW }, noWrite), (e: unknown) => e instanceof Error && e.message.endsWith(`rm -- '${odd.replace("it's", "it'\\''s")}/.b.json.lock'`));
});

test("baseline add: a file the user cannot write is refused, not replaced, and its mode is kept", { skip: process.getuid?.() === 0 && "root may write any file" }, async () => {
  // A review found a 0444 baseline replaced by the rename all the same.
  const d = tmp();
  const file = join(d, "b.json");
  const text = pretty({ version: 1, entries: [] });
  writeFileSync(file, text);
  chmodSync(file, 0o444);
  const r = await add(file, FP1, "--reason", WHY);
  assert.equal(r.code, 2);
  assert.equal(r.err, `wormsign: refusing baseline ${file}: you cannot write it (mode 0444), and baseline add would replace it; make it writable first if the change is meant\n`);
  assert.equal(readFileSync(file, "utf8"), text);
  assert.equal(statSync(file).mode & 0o777, 0o444);
  assert.deepEqual(readdirSync(d), ["b.json"]);
  chmodSync(file, 0o644);
  assert.equal((await add(file, FP1, "--reason", WHY)).code, 0, "control: once writable, it is added");
});

test("baseline add end to end: fingerprints from a fixture scan, added, are accepted by scan --baseline and suppress only those findings", async () => {
  const scan = async (...extra: string[]) => {
    const r = await cli(["scan", fx("malicious"), "--iocs", fx("iocs"), "--format", "json", ...extra]);
    return { code: r.code, err: r.err, findings: (JSON.parse(r.out) as { findings: Finding[] }).findings };
  };
  const before = await scan("--no-baseline");
  const picked = ["WS-GH-004", "WS-PS-002"].map((rule) => before.findings.find((f) => f.ruleId === rule)?.fingerprint as string);
  assert.ok(picked.every((fp) => typeof fp === "string" && fp.length === 32), picked.join(" "));
  const file = join(tmp(), "b.json");
  const r = await add(file, ...picked, "--reason", "Synthetic fixture findings, reviewed for this test");
  assert.equal(r.code, 0, r.err);
  const after = await scan("--baseline", file);
  assert.equal(after.err, "");
  const suppressed = after.findings.filter((f) => f.suppressed);
  assert.deepEqual(suppressed.map((f) => f.fingerprint).sort(), [...picked].sort());
  for (const f of suppressed) assert.equal(f.suppressed?.justification, "Synthetic fixture findings, reviewed for this test");
  assert.equal(after.findings.filter((f) => !f.suppressed).length, before.findings.length - 2);
});

test("baseline add end to end: the default file is ./.wormsign-baseline.json, which the next scan reads, and the gate passes", () => {
  const d = tmp();
  writeFileSync(join(d, "package.json"), JSON.stringify({ name: "demo", version: "1.0.0", scripts: { postinstall: "node setup.js" } }));
  const wormsign = (...argv: string[]) => spawnSync(process.execPath, [CLI, ...argv], { cwd: d, encoding: "utf8", env: { ...process.env, XDG_CACHE_HOME: join(d, ".cache") } });
  const first = wormsign("scan", "--iocs", fx("iocs"), "--fail-on", "medium", "--format", "json");
  assert.equal(first.status, 1, first.stderr);
  const finding = (JSON.parse(first.stdout) as { findings: Finding[] }).findings.find((f) => f.ruleId === "WS-LC-001");
  assert.ok(finding, first.stdout);
  const added = wormsign("baseline", "add", finding.fingerprint, "--reason", WHY);
  assert.equal(added.status, 0, added.stderr);
  assert.equal(added.stdout, `added ${finding.fingerprint}: ${WHY}\n.wormsign-baseline.json: 1 entry added (new file)\n`);
  assert.ok(lstatSync(join(d, ".wormsign-baseline.json")).isFile());
  const second = wormsign("scan", "--iocs", fx("iocs"), "--fail-on", "medium");
  assert.equal(second.status, 0, second.stdout + second.stderr);
  assert.match(second.stdout, /0 finding\(s\) .*, 1 baselined/);
});

test("baseline add --from: a fingerprint that is not a finding of the report, or whose finding no entry can approve, is refused with the reason, and nothing is written", async () => {
  const d = tmp();
  const file = join(d, "b.json");
  const finding = (fingerprint: string, ruleId: string, message: string, more: Record<string, unknown> = {}) => ({ ruleId, severity: "high", message, key: "k", fingerprint, ...more });
  const report = join(d, "report.json");
  writeFileSync(
    report,
    JSON.stringify({
      tool: "wormsign",
      version: "0.1.0",
      command: "soak",
      findings: [
        finding(FP1, "WS-SK-002", "Cannot verify soak time for PyPI package six==1.17.0: too young"),
        finding(FP2, "WS-SK-002", "Cannot verify soak time for the packages in requirements.txt: requirements.txt:2: option -e is not allowed in a hash lock; fix it. No baseline entry can approve this finding: soak cannot tell from this line what an install fetches", { notBaselinable: true }),
        finding(FP3, "WS-SK-006", "Unverified: the registry did not answer"),
      ],
      notes: [],
    }),
  );
  const refused: [string, RegExp][] = [
    [FP2, new RegExp(`fingerprint ${FP2} \\(WS-SK-002\\) is a finding no baseline entry can approve, so an entry would suppress nothing; nothing was added: soak cannot tell from this line what an install fetches$`, "m")],
    [FP3, /\(WS-SK-006\) is a finding no baseline entry can approve, .*: an outage under --on-outage warn is transient/],
    ["00000000000000000000000000000000", /fingerprint 0{32} is not a finding in --from .*report\.json; nothing was added/],
  ];
  for (const [fp, message] of refused) {
    // With an approvable fingerprint before it: nothing at all is added.
    const r = await add(file, FP1, fp, "--reason", WHY, "--from", report);
    assert.equal(r.code, 2, fp);
    assert.match(r.err, message, fp);
    assert.equal(r.out, "", fp);
    assert.equal(existsSync(file), false, fp);
  }
  // What is not a JSON report wormsign wrote is refused, and so is a report that is not a regular file.
  const bad: [string, string][] = [
    ["not JSON", "findings"],
    ["SARIF", JSON.stringify({ version: "2.1.0", runs: [] })],
    ["a finding without a fingerprint", JSON.stringify({ tool: "wormsign", findings: [{ ruleId: "WS-SK-002", message: "m" }] })],
    ["findings another tool wrote", JSON.stringify({ tool: "other", findings: [finding(FP1, "WS-SK-002", "too young")] })],
  ];
  for (const [what, text] of bad) {
    writeFileSync(report, text);
    const r = await add(file, FP1, "--reason", WHY, "--from", report);
    assert.equal(r.code, 2, what);
    assert.match(r.err, /--from .*report\.json is not a report written by wormsign --format json/, what);
  }
  const dirReport = await add(file, FP1, "--reason", WHY, "--from", d);
  assert.match(dirReport.err, /cannot read --from .*: it is not a regular file/);
  assert.equal((await add(file, FP1, "--reason", WHY, "--from", join(d, "none.json"))).code, 2);
  assert.match((await add(file, FP1, "--reason", WHY, "--from", report, "--from", report)).err, /--from is given more than once/);
  assert.equal(existsSync(file), false);
  // Control: an approvable finding of the report is added.
  writeFileSync(report, JSON.stringify({ tool: "wormsign", findings: [finding(FP1, "WS-SK-002", "too young")] }));
  const ok = await add(file, FP1, "--reason", WHY, "--from", report);
  assert.equal(ok.code, 0, ok.err);
  assert.equal(ok.err, "", "checked against the report: no note");
  assert.deepEqual((JSON.parse(readFileSync(file, "utf8")) as { entries: { fingerprint: string }[] }).entries.map((e) => e.fingerprint), [FP1]);
});

test("baseline add: usage errors exit 2 with a message, never an internal error, never a scan or a request, and write nothing", async () => {
  const d = tmp();
  const file = join(d, "b.json");
  let fetched = 0;
  const fetchImpl = (async () => {
    fetched++;
    throw new Error("no network");
  }) as typeof fetch;
  const cases: [string[], RegExp][] = [
    [["baseline"], /usage: wormsign baseline add <fingerprint>\.\.\. --reason <text> \(got: nothing\)/],
    [["baseline", "add"], /usage: wormsign baseline add <fingerprint>\.\.\. --reason <text> \(got: add\)/],
    [["baseline", "remove", FP1, "--reason", WHY], /unknown baseline action "remove" \(add\)/],
    [["baseline", FP1, FP2, "--reason", WHY], new RegExp(`unknown baseline action "${FP1}" \\(add\\)`)],
    [["baseline", "add", FP1, "--reason", WHY, "--reason", "A second reason, which would win"], /--reason is given more than once/],
    [["baseline", "add", FP1, "--reason"], /--reason needs a value/],
    [["baseline", "add", FP1, "--reason="], /--reason needs a value/],
    [["baseline", "add", FP1, "--reason", WHY, "--format", "json"], /--format is not an option of baseline/],
    [["baseline", "add", FP1, "--reason", WHY, "--iocs", fx("iocs")], /--iocs is not an option of baseline/],
    [["baseline", "add", FP1, "--reason", WHY, "--no-baseline"], /--no-baseline is not an option of baseline/],
    [["baseline", "add", FP1, "--reason", WHY, "--all"], /unknown option --all/],
    [["scan", d, "--reason", WHY], /--reason is not an option of scan/],
    [["soak", d, "--expires", "2027-01-01"], /--expires is not an option of soak/],
  ];
  for (const [argv, message] of cases) {
    // --baseline first, so that a flag missing its value cannot take it as one.
    const r = await cli(argv[0] === "baseline" ? ["--baseline", file, ...argv] : argv, { fetchImpl });
    assert.equal(r.code, 2, argv.join(" "));
    assert.match(r.err, message, argv.join(" "));
    assert.doesNotMatch(r.err, /internal error/, argv.join(" "));
    assert.equal(r.out, "", argv.join(" "));
  }
  assert.equal(fetched, 0);
  assert.deepEqual(readdirSync(d), []);
  const ok = await cli(["baseline", "add", FP1, "--reason", WHY, "--baseline", file], { fetchImpl });
  assert.equal(ok.code, 0, "control: the same command with its arguments right writes the file");
  assert.equal(fetched, 0);
});

test("baseline add: --help lists the command and its three options", async () => {
  const r = await cli(["--help"]);
  assert.match(r.out, /^ {2}wormsign baseline add <fp>\.\.\. {5}add reviewed findings to \.wormsign-baseline\.json in the current directory/m);
  assert.match(r.out, /^ {2}--reason <text> +baseline add: /m);
  assert.match(r.out, /^ {2}--expires <YYYY-MM-DD> +baseline add: /m);
  assert.match(r.out, /^ {2}--from <report\.json> +baseline add: /m);
});
