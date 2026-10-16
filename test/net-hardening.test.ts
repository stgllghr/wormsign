// What the network commands accept from their inputs and their servers: URLs with credentials (never accepted or
// printed), redirects (never followed off the URL the user gave), and the size of IOC data (bounded, so a feed or a
// planted cache cannot stall every later scan or audit).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MAX_IOC_FILE_BYTES, branchIocProblem, loadIocs, nameRegexProblem, parseIocs } from "../src/iocs.js";
import { parseLockfileText } from "../src/lockfile/index.js";
import type { ParsedLockfile } from "../src/lockfile/index.js";
import { run } from "../src/main.js";
import { checkSoakLockfiles } from "../src/soak.js";
import { updateIocs } from "../src/update-iocs.js";
import { redactUrl } from "../src/url.js";
import { NOW, fakeIO, fx } from "./helpers.js";

const IOC_FILES = ["packages", "files", "workflows", "repos", "endpoints"] as const;
const fixtureText = (n: string): string => readFileSync(join(fx("iocs"), `${n}.json`), "utf8");
const rawFiles = () => Object.fromEntries(IOC_FILES.map((n) => [n, JSON.parse(fixtureText(n))])) as Record<(typeof IOC_FILES)[number], Record<string, unknown[]> & Record<string, unknown>>;

/** A fetch that, like the real one, follows a redirect unless the request says redirect: "manual" (or "error"). */
function redirecting(routes: Record<string, () => Response>) {
  const calls: string[] = [];
  const f = (async (url: string | URL, init?: RequestInit): Promise<Response> => {
    let u = String(url);
    for (let hops = 0; hops < 5; hops++) {
      calls.push(u);
      const res = routes[u]?.() ?? new Response("", { status: 404 });
      const to = res.headers.get("location");
      if (res.status < 300 || res.status > 399 || to === null) return res;
      if (init?.redirect === "error") throw new TypeError("fetch failed (redirect)");
      if (init?.redirect === "manual") return res;
      u = new URL(to, u).href;
    }
    throw new TypeError("too many redirects");
  }) as typeof fetch;
  return { f, calls };
}

test("redactUrl drops userinfo, query and fragment and keeps everything else as written", () => {
  assert.equal(redactUrl("https://ci:S3CRET@npm.acme.example/"), "https://npm.acme.example/");
  assert.equal(redactUrl("https://a@b@npm.acme.example/path"), "https://npm.acme.example/path");
  assert.equal(redactUrl("https://npm.acme.example/x?token=S3CRET#f"), "https://npm.acme.example/x");
  assert.equal(redactUrl("https://registry.npmjs.org"), "https://registry.npmjs.org");
  assert.equal(redactUrl("https://u:p@[bad"), "https://[bad");
  assert.equal(redactUrl("https://host/a@b"), "https://host/a@b", "an @ in the path is not userinfo");
});

test("redactUrl drops userinfo from every form the URL parser reads credentials from", () => {
  // Each of these is the URL https://u:S3CRET@h/x to the WHATWG parser that fetch uses.
  for (const url of ["https:u:S3CRET@h/x", "https:\\\\u:S3CRET@h/x", "https:/u:S3CRET@h/x", " https://u:S3CRET@h/x", "\thttps://u:S3CRET@h/x", "HTTPS:u:S3CRET@h/x?token=S3CRET"]) {
    assert.equal(new URL(url).password, "S3CRET", JSON.stringify(url));
    assert.equal(redactUrl(url), "https://h/x", JSON.stringify(url));
  }
  // Only the parser sees these: a tab inside the scheme and a leading control character are dropped by it, and a
  // "\\" ends the authority only in a special scheme's URL.
  for (const [url, shown] of [["ht\ttps://u:S3CRET@h/x", "https://h/x"], ["\u0001https://u:S3CRET@h/x", "https://h/x"], ["foo://u\\:S3CRET@h/", "foo://h/"]]) {
    assert.equal(redactUrl(url as string), shown, JSON.stringify(url));
  }
  // Text the parser refuses still loses what looks like userinfo.
  assert.equal(redactUrl("https:u:S3CRET@[bad"), "https:[bad");
});

/* ---- NET-2: redirects ---- */

test("update-iocs: a redirect is refused, never followed to plain http", async () => {
  const routes: Record<string, () => Response> = {};
  for (const n of IOC_FILES) {
    routes[`https://iocs.example/iocs/${n}.json`] = () => new Response(null, { status: 302, headers: { location: `http://plain.example/iocs/${n}.json` } });
    routes[`http://plain.example/iocs/${n}.json`] = () => new Response(fixtureText(n));
  }
  const g = redirecting(routes);
  const dir = mkdtempSync(join(tmpdir(), "ws-redirect-"));
  await assert.rejects(
    updateIocs("https://iocs.example/iocs/", dir, g.f, NOW),
    /https:\/\/iocs\.example\/iocs\/packages\.json: HTTP 302, a redirect to http:\/\/plain\.example\/iocs\/packages\.json, which wormsign does not follow; pass the final https URL with --url$/,
  );
  assert.deepEqual(g.calls, ["https://iocs.example/iocs/packages.json"], "nothing was fetched over plain http");
});

const LOCK = JSON.stringify({
  name: "p",
  lockfileVersion: 3,
  requires: true,
  packages: {
    "": { name: "p", dependencies: { "is-number": "7.0.0" } },
    "node_modules/is-number": { version: "7.0.0", resolved: "https://reg.example/is-number/-/is-number-7.0.0.tgz", integrity: "sha512-abc" },
  },
});
const NPM_LOCK = LOCK.replaceAll("https://reg.example/", "https://registry.npmjs.org/");
const OLD_DOC = JSON.stringify({ name: "is-number", time: { "7.0.0": "2001-01-01T00:00:00.000Z" }, versions: { "7.0.0": { dist: { integrity: "sha512-abc", tarball: "https://reg.example/is-number/-/is-number-7.0.0.tgz" } } } });

test("soak: a registry redirect is refused (WS-SK-002), never followed to plain http where publish times can be forged", async () => {
  const g = redirecting({
    "https://reg.example/is-number": () => new Response(null, { status: 301, headers: { location: "http://reg.example/is-number" } }),
    "http://reg.example/is-number": () => new Response(OLD_DOC),
  });
  const lock = parseLockfileText("package-lock.json", LOCK) as ParsedLockfile;
  const res = await checkSoakLockfiles([lock], { minAgeMs: 7 * 86_400_000, registry: "https://reg.example/", now: NOW, fetchImpl: g.f });
  assert.deepEqual(res.findings.map((f) => f.ruleId), ["WS-SK-002"]);
  assert.match(res.findings[0]?.message ?? "", /registry returned HTTP 301, a redirect to http:\/\/reg\.example\/is-number, which wormsign does not follow; pass the registry's final https URL as --registry/);
  assert.ok(!g.calls.some((u) => u.startsWith("http:")), g.calls.join(" "));
});

test("update-iocs: a request that fails is a usage error naming the file, not an internal error", async () => {
  const f = (async () => {
    throw new TypeError("fetch failed");
  }) as unknown as typeof fetch;
  await assert.rejects(updateIocs("https://iocs.example/i/", mkdtempSync(join(tmpdir(), "ws-ioc-")), f, NOW), (e: Error) => e.constructor.name === "UsageError" && e.message === "cannot download https://iocs.example/i/packages.json: fetch failed");
});

/* ---- NET-3: credentials in URLs ---- */

function project(lock = LOCK): string {
  const d = mkdtempSync(join(tmpdir(), "ws-net-"));
  writeFileSync(join(d, "package-lock.json"), lock);
  writeFileSync(join(d, "package.json"), JSON.stringify({ name: "p", dependencies: { "is-number": "7.0.0" } }));
  return d;
}
const home = () => mkdtempSync(join(tmpdir(), "ws-home-"));

test("cli: --registry and --url with credentials are usage errors that never print them", async () => {
  const net = redirecting({});
  for (const argv of [
    ["soak", project(), "--registry", "https://wsuser:S3CRET_TOKEN@localhost:9/"],
    ["soak", project(), "--registry", "https://wsuser:S3CRET_TOKEN@[bad"],
    // Without "//", or with backslashes, the URL parser still reads user and token.
    ["soak", project(), "--registry", "https:wsuser:S3CRET_TOKEN@localhost:9/"],
    ["soak", project(), "--registry", "https:\\\\wsuser:S3CRET_TOKEN@localhost:9/"],
    ["update-iocs", "--url", "https:S3CRET_TOKEN@raw.example/x/"],
    ["update-iocs", "--url", "https://S3CRET_TOKEN@raw.example/x/"],
  ]) {
    const io = fakeIO({ fetchImpl: net.f, env: { HOME: home() } });
    assert.equal(await run(argv, io), 2, argv.join(" "));
    assert.match(io.err, /must not contain credentials|invalid --registry/, argv.join(" "));
    assert.ok(!`${io.out}${io.err}`.includes("S3CRET_TOKEN"), `${argv.join(" ")}: ${io.err}`);
  }
  assert.deepEqual(net.calls, [], "nothing was requested");
  const io = fakeIO({ fetchImpl: net.f, env: { HOME: home() } });
  assert.equal(await run(["update-iocs", "--url", "http://raw.example/x/"], io), 2);
  assert.match(io.err, /--url must be https: http:\/\/raw\.example\/x\//);
});

test("update-iocs refuses a URL with credentials before any request", async () => {
  const net = redirecting({});
  await assert.rejects(updateIocs("https://tok:S3CRET@iocs.example/x/", mkdtempSync(join(tmpdir(), "ws-ioc-")), net.f, NOW), (e: Error) => /must not contain credentials/.test(e.message) && !e.message.includes("S3CRET"));
  assert.deepEqual(net.calls, []);
});

test("soak: a registry URL from config or --registry is printed without credentials, query or fragment", async () => {
  const net = redirecting({});
  const io = fakeIO({ fetchImpl: net.f, env: { HOME: home(), npm_config_registry: "https://ci:S3CRET_TOKEN@npm.acme.example/" } });
  await run(["soak", project(NPM_LOCK), "--no-osv", "--format", "json"], io);
  assert.match(io.out, /environment variable npm_config_registry installs packages from https:\/\/npm\.acme\.example\/, not https:\/\/registry\.npmjs\.org/);
  assert.ok(!io.out.includes("S3CRET_TOKEN"), io.out);
  const q = fakeIO({ fetchImpl: net.f, env: { HOME: home() } });
  await run(["soak", project(), "--no-osv", "--registry", "https://reg.example/?token=S3CRET_TOKEN", "--format", "json"], q);
  const notes = (JSON.parse(q.out) as { notes: string[] }).notes;
  assert.ok(notes.includes("1 package version(s) checked against https://reg.example/"), notes.join("\n"));
  assert.ok(!q.out.includes("S3CRET_TOKEN"), q.out);
});

test("soak: a scope registry in .npmrc written without \"//\" is printed without its token, in SARIF too", async () => {
  const net = redirecting({});
  const lock = JSON.stringify({
    name: "p",
    lockfileVersion: 3,
    requires: true,
    packages: {
      "": { name: "p", dependencies: { "@acme/x": "1.0.0" } },
      "node_modules/@acme/x": { version: "1.0.0", resolved: "https://registry.npmjs.org/@acme/x/-/x-1.0.0.tgz", integrity: "sha512-abc" },
    },
  });
  const d = project(lock);
  writeFileSync(join(d, ".npmrc"), "@acme:registry=https:ci:S3CRET_TOKEN@npm.acme.example/\n");
  const io = fakeIO({ fetchImpl: net.f, env: { HOME: home() } });
  await run(["soak", d, "--no-osv", "--format", "sarif"], io);
  assert.match(io.out, /\.npmrc installs @acme from https:\/\/npm\.acme\.example\/, not https:\/\/registry\.npmjs\.org/);
  assert.ok(!`${io.out}${io.err}`.includes("S3CRET_TOKEN"), io.out);
});

test("soak: a git source's URL is printed without its credentials, in the human report and in SARIF", async () => {
  // npm writes a git dependency's URL as the package.json gave it, so a token there reaches the lockfile.
  const lock = JSON.stringify({
    name: "p",
    lockfileVersion: 3,
    requires: true,
    packages: {
      "": { name: "p", dependencies: { tokdep: "github:acme/tokdep" } },
      "node_modules/tokdep": { version: "1.0.0", resolved: "git+https://x-access-token:S3CRET_TOKEN@github.com/acme/tokdep.git#0123456789abcdef0123456789abcdef01234567" },
    },
  });
  for (const format of ["human", "sarif"]) {
    const io = fakeIO({ fetchImpl: redirecting({}).f, env: { HOME: home() } });
    assert.equal(await run(["soak", project(lock), "--no-osv", "--format", format], io), 1, format);
    assert.match(io.out, /Cannot verify soak time for tokdep@1\.0\.0: it resolves from a git source \(git\+https:\/\/github\.com\/acme\/tokdep\.git\)/, format);
    assert.ok(!`${io.out}${io.err}`.includes("S3CRET_TOKEN"), io.out);
  }
});

/* ---- NET-5: branch IOC names ---- */

test("IOC loader: a branch name git check-ref-format rejects is refused, '..' above all", () => {
  for (const bad of ["../../../../../../user/keys", "a/../b", "a..b", ".hidden", "a/.b", "a//b", "/a", "a/", "a.lock", "a.lock/b", "a.", "x/.*"]) {
    const r = rawFiles();
    (r.repos["branches"] as unknown[]).push({ name: bad, wave: "test", source: "https://example.test/b" });
    assert.throws(() => parseIocs(r), /not a branch name/, bad);
    assert.ok(branchIocProblem(bad), bad);
  }
  for (const ok of ["shai-hulud", "add-linter-workflow-*", "dependabot/github_actions/format/setup-formatter", "release/*", "v1.2", "a.locked", "x.lock*"]) {
    assert.equal(branchIocProblem(ok), undefined, ok);
  }
});

/* ---- NET-6: bounded IOC data ---- */

test("IOC loader: entry counts are capped", () => {
  const endpoints = rawFiles();
  endpoints.endpoints["endpoints"] = Array.from({ length: 1001 }, (_, i) => ({ substring: `e${i}[.]example[.]com`, severity: "high", wave: "test", source: "https://example.test/e" }));
  assert.throws(() => parseIocs(endpoints), /endpoints\.json endpoints: 1001 entries, more than the 1000 wormsign accepts/);
  const branches = rawFiles();
  branches.repos["branches"] = Array.from({ length: 101 }, (_, i) => ({ name: `b${i}`, wave: "test", source: "https://example.test/b" }));
  assert.throws(() => parseIocs(branches), /repos\.json branches: 101 entries, more than the 100/);
  const versions = rawFiles();
  const set = (versions.packages["sets"] as { packages: Record<string, string[]> }[])[0] as { packages: Record<string, string[]> };
  set.packages["many"] = Array.from({ length: 200_001 }, (_, i) => `0.0.${i}`);
  assert.throws(() => parseIocs(versions), /package versions: 200\d{3} entries, more than the 200000/);
});

test("IOC loader: a repository nameRegex that could backtrack without bound is refused", () => {
  for (const [bad, why] of [
    ["^([\\w.-]+)+!$", /repeats a group/],
    ["^(?:ab)*$", /repeats a group/],
    ["^(a|aa){2,}$", /repeats a group/],
    ["^(a)\\1$", /backreference/],
    ["^a?a?a?aaa$", /more than 2 variable-length quantifiers/],
    ["^\\w*\\w*\\w*!$", /more than 2 variable-length quantifiers/],
    ["^[a-z]{1,30}[0-9]{2,}x+$", /more than 2 variable-length quantifiers/],
    [`^${"a".repeat(100)}$`, /longer than 100 characters/],
    ["(", /Invalid regular expression/],
  ] as const) {
    assert.match(nameRegexProblem(bad) ?? "", why, bad);
    const r = rawFiles();
    ((r.repos["patterns"] as Record<string, unknown>[])[2] as Record<string, unknown>)["nameRegex"] = bad;
    assert.throws(() => parseIocs(r), /nameRegex refused/, bad);
  }
  for (const ok of ["^[0-9a-z]{18}$", "^[a-z]+-[0-9]*$", "^shai-hulud(-migration)?$", "[)]+x", "\\(+x", "^a{3}b{2}c+?$"]) assert.equal(nameRegexProblem(ok), undefined, ok);
});

test("update-iocs: a download larger than the cap is refused, whether or not it declares its length", async () => {
  const big = () => new Response("x".repeat(MAX_IOC_FILE_BYTES + 1));
  const declared = () => new Response("{}", { headers: { "content-length": String(MAX_IOC_FILE_BYTES + 1) } });
  for (const body of [big, declared]) {
    const g = redirecting({ "https://iocs.example/i/packages.json": body });
    await assert.rejects(updateIocs("https://iocs.example/i/", mkdtempSync(join(tmpdir(), "ws-ioc-")), g.f, NOW), new RegExp(`packages\\.json is larger than the ${MAX_IOC_FILE_BYTES} bytes wormsign accepts for an IOC file \\(${MAX_IOC_FILE_BYTES + 1} bytes\\)`), body.name);
  }
});

/** The bundled fixture IOC files as an update-iocs cache, with `packages.json` replaced by `make`. */
function cacheWith(make: (path: string) => void): string {
  const dir = mkdtempSync(join(tmpdir(), "ws-cache-"));
  for (const n of IOC_FILES) if (n !== "packages") writeFileSync(join(dir, `${n}.json`), fixtureText(n));
  make(join(dir, "packages.json"));
  return dir;
}

test("IOC cache: a file over the cap is ignored with a note, never read", () => {
  const dir = cacheWith((p) => {
    writeFileSync(p, "");
    truncateSync(p, MAX_IOC_FILE_BYTES + 1);
  });
  const set = loadIocs({ cacheDir: dir });
  assert.match(set.notes[0] ?? "", new RegExp(`^ignored the update-iocs cache .*packages\\.json: ${MAX_IOC_FILE_BYTES + 1} bytes, more than the ${MAX_IOC_FILE_BYTES} wormsign reads$`));
});

test("IOC cache: a FIFO in place of a file is refused at once, not waited on", () => {
  const dir = cacheWith((p) => {
    const r = spawnSync("mkfifo", [p]);
    assert.equal(r.status, 0, `mkfifo: ${String(r.stderr)}`);
  });
  // In a child process with a timeout: a blocking open would hang the whole test run.
  const loader = new URL("../src/iocs.js", import.meta.url).href;
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", `const { loadIocs } = await import(${JSON.stringify(loader)}); console.log(loadIocs({ cacheDir: process.argv[1] }).notes[0]);`, dir], { encoding: "utf8", timeout: 20_000 });
  assert.equal(r.signal, null, "the loader hung on the FIFO");
  assert.match(r.stdout, /^ignored the update-iocs cache .*packages\.json: not a regular file$/m);
});
