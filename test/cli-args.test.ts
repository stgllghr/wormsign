import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../src/main.js";
import { fakeIO, fx } from "./helpers.js";

const IOCS = ["--iocs", fx("iocs")];

/** A fetch that records calls and fails, to prove a command made none. */
function countingFetch() {
  const calls: string[] = [];
  const f = (async (u: string | URL | Request) => {
    calls.push(String(u));
    throw new Error("no network in this test");
  }) as typeof fetch;
  return { f, calls };
}

/** A project locking one package from `registry`: soak only queries the registry an entry resolves from. */
function soakProject(registry = "https://registry.npmjs.org"): string {
  const d = mkdtempSync(join(tmpdir(), "ws-args-"));
  const entry = { version: "1.0.0", resolved: `${registry}/young/-/young-1.0.0.tgz`, integrity: "sha512-x" };
  writeFileSync(join(d, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/young": entry } }));
  return d;
}

async function usage(argv: string[], over = {}): Promise<string> {
  const io = fakeIO(over);
  assert.equal(await run(argv, io), 2, argv.join(" "));
  assert.doesNotMatch(io.err, /internal error/, argv.join(" "));
  return io.err;
}

test("cli: extra positionals are usage errors, never silently dropped", async () => {
  assert.match(await usage(["scan", fx("clean"), fx("malicious"), ...IOCS]), /usage: wormsign scan \[dir\]/);
  await usage(["diff", "a", "b", "c"]);
  await usage(["soak", fx("clean"), "extra"]);
  await usage(["audit-org", "o1", "o2"], { env: { GITHUB_TOKEN: "t" } });
  const net = countingFetch();
  await usage(["update-iocs", "extra"], { fetchImpl: net.f });
  assert.deepEqual(net.calls, []);
});

test("cli: options of other commands and unknown single-dash options are usage errors", async () => {
  assert.match(await usage(["scan", "--dir", fx("malicious"), ...IOCS]), /--dir is not an option of scan/);
  assert.match(await usage(["scan", fx("clean"), "-x"]), /unknown option -x/);
  await usage(["update-iocs", "--format", "json"]);
});

test("cli: boolean options take no value and value options need a non-empty one", async () => {
  assert.match(await usage(["scan", fx("clean"), "--node-modules=false"]), /does not take a value/);
  assert.match(await usage(["scan", fx("clean"), "--baseline="]), /needs a value/);
});

test("cli: --format, --output and --registry are checked before any network access", async () => {
  const d = soakProject();
  const net = countingFetch();
  await usage(["soak", d, "--format", "bogus"], { fetchImpl: net.f, env: { HOME: d } });
  await usage(["soak", d, "--output", join(d, "missing", "r.json")], { fetchImpl: net.f, env: { HOME: d } });
  assert.match(await usage(["soak", d, "--registry", "http://registry.example"], { fetchImpl: net.f, env: { HOME: d } }), /must be https/);
  await usage(["audit-org", "o", "--format", "bogus"], { fetchImpl: net.f, env: { GITHUB_TOKEN: "t" } });
  assert.deepEqual(net.calls, []);
  const local = countingFetch();
  const mirrored = soakProject("http://127.0.0.1:4873");
  await run(["soak", mirrored, "--registry", "http://127.0.0.1:4873"], fakeIO({ fetchImpl: local.f, env: { HOME: mirrored } }));
  assert.ok(local.calls[0]?.startsWith("http://127.0.0.1:4873/"), "plain http is allowed for a loopback mirror");
});

test("cli: --since and --max-repos are checked before any network access", async () => {
  const net = countingFetch();
  const org = { fetchImpl: net.f, env: { GITHUB_TOKEN: "t" } };
  for (const since of ["garbage", "2026-13-45", "2026-02-30"]) assert.match(await usage(["audit-org", "o", "--since", since], org), /invalid --since/);
  for (const n of ["abc", "0", "-5", "1.5"]) assert.match(await usage(["audit-org", "o", "--max-repos", n], org), /invalid --max-repos/);
  assert.deepEqual(net.calls, []);
});

test("cli: --baseline and --iocs files are checked before any git, scan or network work", async () => {
  const net = countingFetch();
  const org = { fetchImpl: net.f, env: { GITHUB_TOKEN: "t" } };
  const missing = join(tmpdir(), "ws-no-such-dir", "b.json");
  assert.match(await usage(["audit-org", "o", "--baseline", missing], org), /baseline file not found/);
  const bad = join(mkdtempSync(join(tmpdir(), "ws-badbl-")), "b.json");
  writeFileSync(bad, '{"version":1}');
  assert.match(await usage(["audit-org", "o", "--baseline", bad], org), /expected \{"version":1/);
  assert.match(await usage(["audit-org", "o", "--iocs", join(tmpdir(), "ws-no-iocs")], org), /cannot read IOC file/);
  assert.deepEqual(net.calls, []);
  // diff runs git first; a bad file must be reported before git can fail on a revision or a non-repository.
  assert.match(await usage(["diff", "no-such-rev", "HEAD", "--dir", tmpdir(), "--baseline", missing]), /baseline file not found/);
  assert.match(await usage(["diff", "no-such-rev", "HEAD", "--dir", tmpdir(), "--iocs", join(tmpdir(), "ws-no-iocs")]), /cannot read IOC file/);
});

test("cli: an --output that cannot be written is a usage error, not an internal error", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ws-outdir-"));
  assert.match(await usage(["scan", fx("clean"), "--output", dir, ...IOCS]), /cannot write --output/);
});

test("cli: help names every command that uses the network", async () => {
  const io = fakeIO();
  await run(["--help"], io);
  assert.match(io.out, /Network: soak \(unless --config-only\), audit-org and update-iocs\. scan and diff never use the network\./);
});

test("cli: a baseline ignorePaths entry that matches nothing is reported", async () => {
  const d = mkdtempSync(join(tmpdir(), "ws-ipnote-"));
  writeFileSync(join(d, "package.json"), '{"name":"p"}');
  writeFileSync(join(d, ".wormsign-baseline.json"), JSON.stringify({ version: 1, entries: [], ignorePaths: [{ path: "fixtures", justification: "Inert fixtures used by the test suite" }] }));
  const io = fakeIO();
  assert.equal(await run(["scan", d, ...IOCS], io), 0);
  assert.match(io.out, /ignorePaths entry "fixtures" matches nothing/);
});
