import { test } from "node:test";
import assert from "node:assert/strict";
import { checkLockfile } from "../src/checks/lockfile.js";
import { testCtx } from "./helpers.js";

const messageFor = (resolved: string): string => {
  const f = checkLockfile({ kind: "npm", file: "package-lock.json", packages: [{ name: "a", version: "1.0.0", resolved, integrity: "sha512-x" }] }, testCtx());
  assert.equal(f.length, 1, resolved);
  assert.equal(f[0]?.ruleId, "WS-LK-002");
  return f[0]?.message ?? "";
};

test("WS-LK-002 names a host-less source instead of printing an empty host", () => {
  for (const r of ["file:../bundler/bundler-1.0.0.tgz", "patch:a@npm%3A1.0.0#./x.patch", "exec:./gen.js"]) {
    const m = messageFor(r);
    assert.ok(m.includes(r), m);
    assert.doesNotMatch(m, /from ,/);
  }
});

test("WS-LK-002 says why it fired: plain HTTP to an allowed registry is not a disallowed host", () => {
  assert.equal(messageFor("http://registry.npmjs.org/a/-/a-1.0.0.tgz"), "a@1.0.0 resolves from registry.npmjs.org over plain HTTP");
  assert.equal(messageFor("https://evil.example.invalid/a.tgz"), "a@1.0.0 resolves from evil.example.invalid, not an allowed registry host");
  assert.equal(messageFor("http://evil.example.invalid/a.tgz"), "a@1.0.0 resolves from evil.example.invalid over plain HTTP, not an allowed registry host");
});

/* A baseline entry approves one artifact: repointing a baselined git dependency at another URL is a new finding. */
test("WS-LK-002: a baselined git source swapped to another URL is reported again, in scan and in diff", async () => {
  const { execFileSync } = await import("node:child_process");
  const { mkdtempSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { run } = await import("../src/main.js");
  const { fakeIO, fx } = await import("./helpers.js");
  const lock = (resolved: string) =>
    JSON.stringify({ lockfileVersion: 3, packages: { "": { dependencies: { foo: "^1.0.0" } }, "node_modules/foo": { version: "1.0.0", resolved, integrity: "sha512-x" } } });
  const GIT = "git+ssh://git@github.com/example/foo.git#0000000000000000000000000000000000000000";
  const EVIL = "https://evil.example/foo-1.0.0.tgz";
  const d = mkdtempSync(join(tmpdir(), "ws-lk-bl-"));
  const git = (...a: string[]) => execFileSync("git", ["-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...a], { cwd: d, stdio: "pipe" });
  const write = (resolved: string) => writeFileSync(join(d, "package-lock.json"), lock(resolved));
  const json = async (argv: string[]) => {
    const io = fakeIO();
    const code = await run([...argv, "--format", "json", "--iocs", fx("iocs")], io);
    return { code, findings: (JSON.parse(io.out) as { findings: { ruleId: string; fingerprint: string; suppressed?: unknown }[] }).findings.filter((f) => f.ruleId === "WS-LK-002") };
  };
  writeFileSync(join(d, "package.json"), JSON.stringify({ name: "app", private: true, dependencies: { foo: "^1.0.0" } }));
  write(GIT);
  const reviewed = (await json(["scan", d])).findings;
  assert.equal(reviewed.length, 1);
  const baseline = { version: 1, entries: [{ fingerprint: reviewed[0]?.fingerprint, justification: "Reviewed: foo is our fork, pinned to a commit" }] };
  writeFileSync(join(d, ".wormsign-baseline.json"), JSON.stringify(baseline));
  assert.ok((await json(["scan", d])).findings.every((f) => f.suppressed), "control: the reviewed git source is suppressed");
  git("init", "-q", "-b", "main");
  git("add", "-A");
  git("commit", "-q", "-m", "base");
  write(EVIL);
  git("commit", "-qam", "repoint foo");
  for (const argv of [["scan", d], ["diff", "HEAD~1", "HEAD", "--dir", d]]) {
    const r = await json(argv);
    assert.ok(r.findings.some((f) => !f.suppressed), argv[0]);
    assert.equal(r.code, 1, argv[0]);
  }
});
