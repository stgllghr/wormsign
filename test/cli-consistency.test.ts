import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { checkExfil } from "../src/checks/exfil.js";
import { userIocDir } from "../src/iocs.js";
import { run } from "../src/main.js";
import { checkSoakConfig } from "../src/soak-config.js";
import { fakeIO, fx, testCtx } from "./helpers.js";

test("update-iocs cache: an empty or relative XDG_CACHE_HOME is ignored, as the XDG spec requires", () => {
  const home = join(homedir(), ".cache", "wormsign", "iocs");
  assert.equal(userIocDir({}), home);
  assert.equal(userIocDir({ XDG_CACHE_HOME: "" }), home);
  assert.equal(userIocDir({ XDG_CACHE_HOME: "x" }), home);
  assert.equal(userIocDir({ XDG_CACHE_HOME: "./cache" }), home);
  assert.equal(userIocDir({ XDG_CACHE_HOME: "/var/cache/me" }), "/var/cache/me/wormsign/iocs");
});

test("update-iocs cache: with XDG_CACHE_HOME empty, scan does not read a cache from the scanned directory", () => {
  // A pull request that ships wormsign/iocs/*.json must not supply its own IOC data.
  const d = mkdtempSync(join(tmpdir(), "ws-xdg-"));
  mkdirSync(join(d, "wormsign"));
  cpSync(fx("iocs"), join(d, "wormsign", "iocs"), { recursive: true });
  writeFileSync(join(d, "package.json"), '{"name":"x","private":true}');
  const cli = new URL("../src/cli.js", import.meta.url).pathname;
  const out = execFileSync(process.execPath, [cli, "scan", ".", "--format", "json"], { cwd: d, env: { ...process.env, XDG_CACHE_HOME: "", HOME: mkdtempSync(join(tmpdir(), "ws-home-")) } }).toString();
  const notes = (JSON.parse(out) as { notes: string[] }).notes.join("\n");
  assert.doesNotMatch(notes, /cache wormsign\/iocs/);
  assert.match(notes, /\.cache\/wormsign\/iocs|the bundled data/);
});

/* ---- one baseline parser for every command ---- */

function repoWithBaseline(text: string): string {
  const d = mkdtempSync(join(tmpdir(), "ws-bl-"));
  const git = (...a: string[]) => execFileSync("git", ["-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...a], { cwd: d, stdio: "pipe" });
  git("init", "-q", "-b", "main");
  writeFileSync(join(d, "package.json"), '{"name":"x","private":true}');
  writeFileSync(join(d, ".wormsign-baseline.json"), text);
  git("add", "-A");
  git("commit", "-q", "-m", "a");
  git("commit", "-q", "--allow-empty", "-m", "b");
  return d;
}

async function codes(d: string): Promise<{ scan: number; diff: number; soak: number; err: string }> {
  const go = async (argv: string[]) => {
    const io = fakeIO({ env: { HOME: mkdtempSync(join(tmpdir(), "ws-home-")) } });
    const code = await run([...argv, "--format", "json"], io);
    return { code, err: io.err };
  };
  const [scan, diff, soak] = [await go(["scan", d, "--iocs", fx("iocs")]), await go(["diff", "HEAD~1", "HEAD", "--dir", d, "--iocs", fx("iocs")]), await go(["soak", d, "--base", "HEAD~1", "--config-only"])];
  return { scan: scan.code, diff: diff.code, soak: soak.code, err: scan.err + diff.err + soak.err };
}

test("baseline: scan, diff and soak --base accept and reject the same file, and never print its contents", async () => {
  const good = JSON.stringify({ version: 1, entries: [] });
  const bom = await codes(repoWithBaseline(`\uFEFF${good}`));
  assert.deepEqual([bom.scan, bom.diff, bom.soak], [0, 0, 0], bom.err);
  const bad = await codes(repoWithBaseline('{"SECRET-TOKEN-abc123": oops'));
  assert.deepEqual([bad.scan, bad.diff, bad.soak], [2, 2, 2]);
  assert.doesNotMatch(bad.err, /SECRET/);
  assert.equal(bad.err.match(/is not valid JSON/g)?.length, 3, bad.err);
});

/* ---- environment values are not .npmrc text ---- */

test("soak config: an npm_config_min_release_age value is read as npm reads it, with no comment stripping", () => {
  const d = mkdtempSync(join(tmpdir(), "ws-env-"));
  const config = (env: Record<string, string>) =>
    checkSoakConfig(d, [{ kind: "npm", file: "package-lock.json", packages: [] }], { env, minAgeMs: 72 * 3_600_000, versionOf: () => ({ version: "99.0.0", source: "stub" }) });
  const msg = (env: Record<string, string>) => config(env).map((f) => `${f.ruleId} ${f.message}`).join("\n");
  assert.match(msg({ npm_config_min_release_age: "5 #x" }), /WS-SK-004 .*could not be interpreted/);
  assert.match(msg({ npm_config_min_release_age: "5;x" }), /WS-SK-004 .*could not be interpreted/);
  assert.equal(config({ npm_config_min_release_age: "5" }).length, 0, "control: 5 days passes");
  // A file's comment is still a comment.
  writeFileSync(join(d, ".npmrc"), "min-release-age=5 # five days\n");
  assert.equal(config({}).length, 0);
});

/* ---- a lower-severity IOC endpoint does not hide the generic finding ---- */

test("exfil: an IOC endpoint below medium does not replace the medium generic finding", async () => {
  const ctx = testCtx();
  ctx.iocs.endpoints.push({ substring: "webhook.site", severity: "info", wave: "test", source: "https://example.test/synthetic-ioc" });
  const f = checkExfil("a.js", 'fetch("https://webhook.site/abc-123")', ctx, { iocOnly: false }).map((x) => `${x.ruleId} ${x.severity}`).sort();
  assert.deepEqual(f, ["WS-EX-001 medium", "WS-EX-002 info"]);
  // Through the CLI, with the entry in an IOC directory, the default-medium gate still fails.
  const iocs = mkdtempSync(join(tmpdir(), "ws-iocs-"));
  cpSync(fx("iocs"), iocs, { recursive: true });
  const ep = JSON.parse(readFileSync(join(iocs, "endpoints.json"), "utf8")) as { endpoints: object[] };
  ep.endpoints.push({ substring: "webhook[.]site", severity: "info", wave: "test", source: "https://example.test/synthetic-ioc" });
  writeFileSync(join(iocs, "endpoints.json"), JSON.stringify(ep));
  const d = mkdtempSync(join(tmpdir(), "ws-exfil-"));
  cpSync(fx("malicious", "src", "exfil.js"), join(d, "exfil.js"));
  const io = fakeIO();
  assert.equal(await run(["scan", d, "--iocs", iocs, "--fail-on", "medium"], io), 1, io.out);
  // A severe-enough entry still replaces it, as before.
  const severe = testCtx();
  severe.iocs.endpoints.push({ substring: "webhook.site", severity: "high", wave: "test", source: "https://example.test/synthetic-ioc" });
  assert.deepEqual(checkExfil("a.js", 'fetch("https://webhook.site/abc-123")', severe, { iocOnly: false }).map((x) => x.ruleId), ["WS-EX-002"]);
});

/* ---- CLI arguments ---- */

test("audit-org: --since and --max-repos are checked once, before the token and with one message", async () => {
  const err = async (argv: string[], env: Record<string, string> = {}) => {
    const io = fakeIO({ env });
    const code = await run(argv, io);
    return { code, err: io.err };
  };
  // Before the token check: no token is set.
  for (const since of ["2030-01-01", "2026-13-01", "2026-02-30"]) {
    const r = await err(["audit-org", "acme", "--since", since]);
    assert.equal(r.code, 2);
    assert.match(r.err, new RegExp(`invalid --since "${since}" \\(a past date, YYYY-MM-DD\\)`));
  }
  const r = await err(["audit-org", "acme", "--max-repos", "0"]);
  assert.match(r.err, /invalid --max-repos "0" \(a whole number, at least 1\)/);
});

test("--help names every exit 2, including an incomplete audit-org", async () => {
  const io = fakeIO();
  await run(["--help"], io);
  assert.match(io.out, /2 usage or internal error\n\(audit-org: also when the repository list cannot be read, and when the audit is incomplete/);
});
