import { test } from "node:test";
import assert from "node:assert/strict";
import { auditOrg, matchRepoPattern } from "../src/audit-org.js";
import type { IocSet } from "../src/iocs.js";
import { run } from "../src/main.js";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fakeIO, fx, testIocs } from "./helpers.js";

/* A fake api.github.com. Route keys are paths; "*" matches one path segment; an exact key wins. */
interface Route { status?: number; body?: unknown; raw?: string; link?: string; headers?: Record<string, string> }
type Handler = Route | ((u: URL) => Route);
function github(routes: Record<string, Handler>) {
  const calls: { method: string; url: URL; auth: string | null }[] = [];
  const stats = { inFlight: 0, maxInFlight: 0 };
  const f = (async (url: string | URL, init?: RequestInit) => {
    const u = new URL(String(url));
    calls.push({ method: init?.method ?? "GET", url: u, auth: new Headers(init?.headers).get("authorization") });
    stats.maxInFlight = Math.max(stats.maxInFlight, ++stats.inFlight);
    await new Promise((r) => setImmediate(r));
    stats.inFlight--;
    const key = u.pathname in routes ? u.pathname : Object.keys(routes).find((k) => new RegExp(`^${k.replaceAll("*", "[^/]+")}$`).test(u.pathname));
    const h = u.origin === "https://api.github.com" && key !== undefined ? routes[key] : undefined;
    const r = (typeof h === "function" ? h(u) : h) ?? { status: 404, body: { message: "Not Found" } };
    return new Response(r.raw ?? JSON.stringify(r.body ?? {}), { status: r.status ?? 200, headers: { ...(r.link ? { link: r.link } : {}), ...r.headers } });
  }) as typeof fetch;
  return { f, calls, stats };
}
const quiet = {
  "/orgs/acme/audit-log": { body: [] },
  "/orgs/acme/actions/runners": { body: { total_count: 0, runners: [] } },
  "/repos/acme/*/actions/runners": { body: { total_count: 0, runners: [] } },
  "/repos/acme/*/git/matching-refs/heads/wormsign-test-branch": { body: [] },
};
const repo = (name: string, description: string | null = null, priv = true) => ({ name, full_name: `acme/${name}`, private: priv, description });
const oneRepo = { "/orgs/acme/repos": { body: [repo("a")] } };
const iocs = (): IocSet => ({ ...testIocs(), branches: [{ name: "wormsign-test-branch", wave: "test", source: "https://example.test/synthetic-ioc" }] });
const phrases = (calls: { url: URL }[]) => calls.filter((c) => c.url.pathname === "/orgs/acme/audit-log").map((c) => c.url.searchParams.get("phrase"));
const degradedKeys = (fs: { ruleId: string; key: string }[]) => fs.filter((f) => f.ruleId === "WS-OR-900").map((f) => f.key).sort();

test("audit-org: repo patterns, IOC runners at org and repo level, IOC workflow file and branch; serial GETs with the token", async () => {
  const g = github({
    ...quiet,
    "/orgs/acme/repos": { body: [repo("wormsign-marker-repo"), repo("abcdefghijklmnopqr", "WORMSIGN synthetic description"), repo("abcdefghijklmnopqr2", "something else"), repo("normal", "a normal repo")] },
    "/orgs/acme/actions/runners": { body: { total_count: 2, runners: [{ name: "WORMSIGNTEST", status: "online" }, { name: "build-01", status: "online" }] } },
    "/repos/acme/normal/actions/runners": { body: { total_count: 1, runners: [{ name: "wormsigntest", status: "offline" }] } },
    "/repos/acme/normal/contents/.github/workflows": { body: [{ name: "ci.yml" }, { name: "wormsign-marker-workflow.yml" }] },
    "/repos/acme/normal/git/matching-refs/heads/wormsign-test-branch": { body: [{ ref: "refs/heads/wormsign-test-branch" }] },
    // matching-refs is a prefix match; a longer branch name is not the IOC.
    "/repos/acme/abcdefghijklmnopqr2/git/matching-refs/heads/wormsign-test-branch": { body: [{ ref: "refs/heads/wormsign-test-branch-2" }] },
  });
  const res = await auditOrg({ org: "acme", token: "tkn", iocs: iocs(), fetchImpl: g.f });
  const by = (id: string) => res.findings.filter((f) => f.ruleId === id);
  assert.deepEqual(by("WS-OR-001").map((f) => f.key).sort(), ["acme/abcdefghijklmnopqr:t-desc", "acme/abcdefghijklmnopqr:t-regex", "acme/wormsign-marker-repo:t-name"]);
  assert.deepEqual(by("WS-OR-003").filter((f) => f.severity === "critical").map((f) => f.file).sort(), ["acme", "acme/normal"], "org runner and repo runner, matched case-insensitively");
  assert.equal(by("WS-OR-003").find((f) => f.key === "runner:build-01")?.severity, "low");
  assert.deepEqual(by("WS-OR-004").map((f) => f.key).sort(), ["acme/normal:branch:wormsign-test-branch", "acme/normal:wormsign-marker-workflow.yml"]);
  assert.deepEqual(degradedKeys(res.findings), []);
  assert.ok(res.notes.includes("4 repositories listed (4 private)"));
  assert.ok(res.notes.includes("default-branch workflow file listing answered for 4 of 4 repositories (1 have a .github/workflows directory)"));
  assert.ok(g.calls.every((c) => c.method === "GET" && c.auth === "Bearer tkn"), "read-only: GET only");
  assert.equal(g.stats.maxInFlight, 1, "requests are serial");
});

test("audit-org: one documented audit-log query per action; flips to public, a burst, runner registrations", async () => {
  const t0 = Date.parse("2026-09-20T10:00:00Z");
  const ev = (i: number, min: number) => ({ action: "repo.access", repo: `acme/r${i}`, actor: "mallory", visibility: "public", previous_visibility: "private", "@timestamp": t0 + min * 60_000 });
  const byAction = (log: Record<string, unknown[]>) => (u: URL): Route => ({ body: log[/action:(\S+)/.exec(u.searchParams.get("phrase") ?? "")?.[1] ?? ""] ?? [] });
  const g = github({
    ...quiet,
    ...oneRepo,
    "/orgs/acme/audit-log": byAction({
      "repo.access": [ev(1, 0), ev(2, 5), ev(3, 9), { ...ev(4, 600), visibility: "private", previous_visibility: "public" }],
      "repo.register_self_hosted_runner": [{ action: "repo.register_self_hosted_runner", actor: "mallory", repo: "acme/r1", "@timestamp": t0 }, { action: "repo.register_self_hosted_runner", actor: "mallory", repo: "acme/r1", "@timestamp": t0 + 1000 }],
      "org.register_self_hosted_runner": [{ action: "org.register_self_hosted_runner", actor: "ops-bot", "@timestamp": t0 }],
    }),
  });
  const res = await auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: g.f, since: new Date("2026-09-01T00:00:00Z") });
  assert.deepEqual(phrases(g.calls), ["action:repo.access created:>=2026-09-01", "action:repo.register_self_hosted_runner created:>=2026-09-01", "action:org.register_self_hosted_runner created:>=2026-09-01"]);
  const flips = res.findings.filter((f) => f.ruleId === "WS-OR-002");
  assert.equal(flips.filter((f) => f.severity === "medium").length, 3, "the flip to private is ignored");
  assert.equal(flips.filter((f) => f.severity === "high").length, 1, "burst of 3 within an hour");
  assert.ok(flips.some((f) => f.message.includes("at 2026-09-20T10:00:00.000Z")), "@timestamp is epoch milliseconds");
  const regs = res.findings.filter((f) => f.key.startsWith("runner-registration:")).map((f) => [f.file, f.message.split(" self-hosted")[0]]);
  assert.deepEqual(regs.sort(), [["acme", "ops-bot registered 1"], ["acme/r1", "mallory registered 2"]]);
  const slow = await auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: github({ ...quiet, ...oneRepo, "/orgs/acme/audit-log": byAction({ "repo.access": [ev(1, 0), ev(2, 120), ev(3, 240)] }) }).f });
  assert.equal(slow.findings.filter((f) => f.severity === "high").length, 0);
});

test("audit-org: audit log unavailable gives one degraded finding naming every skipped query; real status for runners", async () => {
  const g = github({ ...quiet, ...oneRepo, "/orgs/acme/audit-log": { status: 404 }, "/orgs/acme/actions/runners": { status: 403 } });
  const res = await auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: g.f });
  assert.deepEqual(degradedKeys(res.findings), ["audit-log queries (repo.access, repo.register_self_hosted_runner, org.register_self_hosted_runner)", "organization runner inventory"]);
  assert.equal(phrases(g.calls).length, 1, "no further audit-log queries after the API said no");
  const runner = res.findings.find((f) => f.key === "organization runner inventory");
  assert.match(runner?.message ?? "", /skipped, HTTP 403\. .*admin:org.*does not mean clean/);
});

test("audit-org: a failed repository listing is an error, never a clean audit", async () => {
  for (const [status, why] of [[401, /HTTP 401\): GitHub rejected the token/], [403, /HTTP 403\): the token may not list/], [404, /HTTP 404\): the organization does not exist/], [502, /HTTP 502\): GitHub did not return/]] as const) {
    const g = github({ ...quiet, "/orgs/acme/repos": { status } });
    await assert.rejects(auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: g.f }), why);
    // A 5xx is retried once; then, as after any other failure, nothing else is requested.
    assert.equal(g.calls.length, status >= 500 ? 2 : 1, `HTTP ${status}: nothing else is requested`);
  }
  await assert.rejects(auditOrg({ org: "../etc", token: "t", iocs: iocs(), fetchImpl: github({}).f }), /invalid organization/);
});

test("audit-org: a 200 listing that is empty or not a repository list is an error, never a clean audit", async () => {
  await assert.rejects(auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: github({ ...quiet, "/orgs/acme/repos": { body: [] } }).f }), /the token sees 0 repositories in acme, so nothing was audited\. .*classic token: needs repo/);
  for (const bad of [{ raw: "<html>proxy login</html>" }, { body: { message: "weird" } }, { body: { runners: [repo("a")] } }, { body: null }, { body: [null] }, { body: [{ full_name: "acme/a" }] }]) {
    const g = github({ ...quiet, "/orgs/acme/repos": bad });
    await assert.rejects(auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: g.f }), /cannot list repositories of acme \(HTTP 200 \(unexpected body\)\): the response is not a repository list; nothing was audited/, JSON.stringify(bad));
    assert.equal(g.calls.length, 1);
  }
  // A later page that is not a list is not silently dropped either.
  const g = github({ ...quiet, "/orgs/acme/repos": (u) => (u.searchParams.get("page") ? { raw: "oops" } : { body: [repo("a")], link: '<https://api.github.com/orgs/acme/repos?page=2>; rel="next"' }) });
  await assert.rejects(auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: g.f }), /unexpected body/);
});

test("audit-org: when every per-repository check fails, the audit is incomplete and the note does not claim coverage", async () => {
  const denied = { status: 403, body: { message: "Resource not accessible by personal access token" } };
  const g = github({ "/orgs/acme/repos": { body: [repo("a"), repo("b"), repo("c")] }, "/repos/acme/*/contents/.github/workflows": denied, "/repos/acme/*/git/matching-refs/heads/wormsign-test-branch": denied, "/repos/acme/*/actions/runners": denied, "/orgs/acme/actions/runners": denied, "/orgs/acme/audit-log": denied });
  const res = await auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: g.f });
  assert.equal(res.incomplete, "no repository answered: default-branch workflow file listing, IOC branch lookup (wormsign-test-branch), repository runner inventory");
  assert.ok(res.notes.includes("default-branch workflow file listing answered for 0 of 3 repositories (0 have a .github/workflows directory)"));
  // Every worm check answered by at least one repository is coverage; the other repositories' gaps are WS-OR-900 findings.
  const one = await auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: github({ "/orgs/acme/repos": { body: [repo("a"), repo("b")] }, "/repos/acme/a/contents/.github/workflows": { status: 404 }, "/repos/acme/a/git/matching-refs/heads/wormsign-test-branch": { body: [] }, "/repos/acme/a/actions/runners": quiet["/repos/acme/*/actions/runners"], "/repos/acme/*/contents/.github/workflows": denied, "/repos/acme/*/git/matching-refs/heads/wormsign-test-branch": denied, "/repos/acme/*/actions/runners": denied }).f });
  assert.equal(one.incomplete, undefined);
  assert.deepEqual(degradedKeys(one.findings), ["IOC branch lookup (wormsign-test-branch)", "audit-log queries (repo.access, repo.register_self_hosted_runner, org.register_self_hosted_runner)", "default-branch workflow file listing", "organization runner inventory", "repository runner inventory"]);
});

test("audit-org: a worm check that no repository answered makes the audit incomplete, even when another check answered", async () => {
  // A fine-grained token with Administration: read but no Contents: read: only the runner probe answers.
  const denied = { status: 403 };
  const routes = { ...quiet, "/orgs/acme/repos": { body: [repo("a"), repo("b")] }, "/repos/acme/*/contents/.github/workflows": denied, "/repos/acme/*/git/matching-refs/heads/wormsign-test-branch": denied };
  const res = await auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: github(routes).f });
  assert.equal(res.incomplete, "no repository answered: default-branch workflow file listing, IOC branch lookup (wormsign-test-branch)");
  assert.ok(res.notes.includes("default-branch workflow file listing answered for 0 of 2 repositories (0 have a .github/workflows directory)"));
  assert.ok(res.notes.includes("IOC branch lookup (wormsign-test-branch) answered for 0 of 2 repositories"));
  assert.ok(res.notes.includes("repository runner inventory answered for 2 of 2 repositories"));
  const io = fakeIO({ env: { GITHUB_TOKEN: "t" }, fetchImpl: github(routes).f });
  assert.equal(await run(["audit-org", "acme", ...IOCS], io), 2);
  assert.match(io.err, /audit incomplete: no repository answered: default-branch workflow file listing/);
  // The branch lookup alone failing everywhere is enough.
  const branchOnly = await auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: github({ ...routes, "/repos/acme/*/contents/.github/workflows": { body: [] } }).f });
  assert.equal(branchOnly.incomplete, "no repository answered: IOC branch lookup (wormsign-test-branch)");
  // Repository runners never appear in the organization listing: a working organization listing does not stand in
  // for the repository runner inventory.
  const noAdmin = { ...quiet, "/orgs/acme/repos": { body: [repo("a")] }, "/repos/acme/*/actions/runners": denied };
  const blind = await auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: github(noAdmin).f });
  assert.equal(blind.incomplete, "no repository answered: repository runner inventory");
  assert.deepEqual(degradedKeys(blind.findings), ["repository runner inventory"]);
  assert.equal(await run(["audit-org", "acme", ...IOCS], fakeIO({ env: { GITHUB_TOKEN: "t" }, fetchImpl: github(noAdmin).f })), 2);
});

test("audit-org: per-repository failures report their real statuses and counts; absent directories and empty repos are not failures", async () => {
  const g = github({
    ...quiet,
    "/orgs/acme/repos": { body: [repo("a"), repo("b"), repo("c"), repo("d"), repo("e")] },
    "/repos/acme/a/contents/.github/workflows": { status: 403 },
    "/repos/acme/e/contents/.github/workflows": { status: 404 },
    "/repos/acme/b/contents/.github/workflows": { status: 500 },
    // .github/workflows is a file: a 200 that is not a listing is a failure, not "no workflows".
    "/repos/acme/c/contents/.github/workflows": { body: { type: "file", name: "workflows" } },
    "/repos/acme/d/contents/.github/workflows": { body: [] },
    "/repos/acme/a/git/matching-refs/heads/wormsign-test-branch": { status: 409 },
  });
  const res = await auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: g.f });
  // A scope failure is counted under the token's needs; a server error and an unexpected answer each name their
  // repositories, say it is not the token, and make the audit incomplete.
  assert.deepEqual(degradedKeys(res.findings), ["default-branch workflow file listing", "default-branch workflow file listing (a GitHub or network error)", "default-branch workflow file listing (an unexpected answer)"]);
  const msg = (key: string) => res.findings.find((f) => f.key === key)?.message ?? "";
  assert.match(msg("default-branch workflow file listing"), /^default-branch workflow file listing: failed for 1 of 5 repositories \(HTTP 403 x1\)\. The token needs Contents: read/);
  assert.match(msg("default-branch workflow file listing (a GitHub or network error)"), /^default-branch workflow file listing: not checked for 1 of 5 repositories because of a GitHub or network error \(HTTP 500 x1\): acme\/b\. It was retried once and is not a token scope problem/);
  assert.match(msg("default-branch workflow file listing (an unexpected answer)"), /^default-branch workflow file listing: not checked for 1 of 5 repositories because of an unexpected answer \(HTTP 200 \(unexpected body\) x1\): acme\/c\. GitHub did not give the documented response/);
  assert.ok(res.notes.includes("default-branch workflow file listing answered for 2 of 5 repositories (1 have a .github/workflows directory)"));
  assert.equal(res.incomplete, "not checked because of a GitHub or network error or an unexpected answer: default-branch workflow file listing for acme/b (HTTP 500 x1); default-branch workflow file listing for acme/c (HTTP 200 (unexpected body) x1)");
  // Scope failures alone are a reduced audit, reported as findings, not an incomplete one (docs/cli/audit-org.md).
  const scopeOnly = await auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: github({ ...quiet, "/orgs/acme/repos": { body: [repo("a"), repo("d")] }, "/repos/acme/a/contents/.github/workflows": { status: 403 }, "/repos/acme/d/contents/.github/workflows": { body: [] } }).f });
  assert.equal(scopeOnly.incomplete, undefined);
});

test("audit-org: a 5xx, a 429 without rate-limit headers and a network error are retried once; a real rate limit is not", async () => {
  const flaky = (first: Route | Error, then: Route = { body: [] }) => {
    let n = 0;
    return (): Route => {
      if (n++ > 0) return then;
      if (first instanceof Error) throw first;
      return first;
    };
  };
  for (const first of [{ status: 502 }, { status: 429 }, new TypeError("fetch failed")] as const) {
    const g = github({ ...quiet, ...oneRepo, "/repos/acme/a/contents/.github/workflows": flaky(first) });
    const res = await auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: g.f });
    assert.equal(g.calls.filter((c) => c.url.pathname === "/repos/acme/a/contents/.github/workflows").length, 2, String(first));
    assert.deepEqual(degradedKeys(res.findings), [], String(first));
    assert.equal(res.incomplete, undefined, String(first));
  }
  const limited = github({ ...quiet, ...oneRepo, "/repos/acme/a/contents/.github/workflows": { status: 429, headers: { "retry-after": "60" } } });
  const res = await auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: limited.f });
  assert.equal(limited.calls.filter((c) => c.url.pathname === "/repos/acme/a/contents/.github/workflows").length, 1);
  assert.match(res.incomplete ?? "", /stopped by a rate limit/);
});

test("audit-org: one repository's persistent 502 or timeout is named, not blamed on the token, and the audit is incomplete (exit 2) with every other result kept", async () => {
  const timeout = (): Route => {
    throw new DOMException("The operation was aborted due to timeout", "TimeoutError");
  };
  for (const [fail, status] of [[{ status: 502 }, /HTTP 502 x1/], [timeout, /no response \(The operation was aborted due to timeout\) x1/]] as const) {
    const routes = {
      ...quiet,
      "/orgs/acme/repos": { body: [repo("web"), repo("victim")] },
      "/repos/acme/web/contents/.github/workflows": { body: [{ name: "wormsign-marker-workflow.yml" }] },
      "/repos/acme/victim/contents/.github/workflows": fail,
    };
    const res = await auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: github(routes).f });
    const gap = res.findings.find((f) => f.key === "default-branch workflow file listing (a GitHub or network error)");
    assert.match(gap?.message ?? "", new RegExp(`not checked for 1 of 2 repositories because of a GitHub or network error \\(${status.source}\\): acme/victim\\.`));
    assert.doesNotMatch(gap?.message ?? "", /token needs/);
    assert.match(res.incomplete ?? "", /default-branch workflow file listing for acme\/victim/);
    assert.ok(res.findings.some((f) => f.key === "acme/web:wormsign-marker-workflow.yml"), "what the other repository answered is kept");
    const io = fakeIO({ env: { GITHUB_TOKEN: "t" }, fetchImpl: github(routes).f });
    // --fail-on never: the findings alone would exit 0, so the 2 is the incomplete audit's.
    assert.equal(await run(["audit-org", "acme", ...IOCS, "--fail-on", "never"], io), 2);
    assert.match(io.err, /audit incomplete: not checked because of a GitHub or network error or an unexpected answer: default-branch workflow file listing for acme\/victim/);
    assert.match(io.out, /WS-OR-004/, "the report still prints what was found");
  }
});

test("audit-org: an organization runner listing that fails with a server error makes the audit incomplete; one the token may not read does not", async () => {
  const res = await auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: github({ ...quiet, ...oneRepo, "/orgs/acme/actions/runners": { status: 503 } }).f });
  assert.match(res.findings.find((f) => f.key === "organization runner inventory")?.message ?? "", /skipped, HTTP 503\. It was retried once and is not a token scope problem/);
  assert.equal(res.incomplete, "not checked because of a GitHub or network error or an unexpected answer: organization runner inventory (HTTP 503)");
  const denied = await auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: github({ ...quiet, ...oneRepo, "/orgs/acme/actions/runners": { status: 403 } }).f });
  assert.equal(denied.incomplete, undefined);
});

test("audit-org: rate limiting stops the per-repository checks and says so", async () => {
  const g = github({
    ...quiet,
    "/orgs/acme/repos": { body: [repo("r1"), repo("r2"), repo("r3"), repo("r4")] },
    "/orgs/acme/actions/runners": { status: 403, headers: { "x-ratelimit-remaining": "0" } },
    "/repos/acme/*/contents/.github/workflows": { body: [] },
    "/repos/acme/r2/contents/.github/workflows": { status: 429, headers: { "retry-after": "60" } },
  });
  const res = await auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: g.f });
  assert.match(res.findings.find((f) => f.key === "per-repository checks")?.message ?? "", /stopped after 1 of 4 repositories, HTTP 429 \(rate limited\)\. GitHub rate-limited the token/);
  assert.match(res.findings.find((f) => f.key === "organization runner inventory")?.message ?? "", /HTTP 403 \(rate limited\)\. GitHub rate-limited/);
  assert.ok(!g.calls.some((c) => /\/repos\/acme\/r[34]\//.test(c.url.pathname)), "no requests after the limit");
  assert.equal(res.incomplete, "per-repository checks stopped by a rate limit after 1 of 4 repositories");
});

test("audit-org: pagination caps are reported, not silent", async () => {
  const page = Array.from({ length: 100 }, (_, i) => ({ action: "repo.access", visibility: "private", "@timestamp": i }));
  const g = github({
    ...quiet,
    ...oneRepo,
    "/orgs/acme/audit-log": (u) => (u.searchParams.get("phrase")?.startsWith("action:repo.access") ? { body: page, link: `<https://api.github.com/orgs/acme/audit-log?${u.searchParams}>; rel="next"` } : { body: [] }),
  });
  const res = await auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: g.f });
  assert.ok(res.notes.includes("audit-log query action:repo.access stopped at the 2000-entry cap; later entries were not checked"));
});

test("audit-org: pagination follows same-origin links and refuses look-alike hosts", async () => {
  const g = github({ ...quiet, "/orgs/acme/repos": (u) => (u.searchParams.get("page") ? { body: [repo("b")] } : { body: [repo("a")], link: '<https://api.github.com/orgs/acme/repos?page=2>; rel="next"' }) });
  const ok = await auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: g.f });
  assert.ok(ok.notes.includes("2 repositories listed (2 private)"));
  for (const evil of ["https://evil.example/steal", "https://api.github.com.evil.example/steal", "https://api.github.com@evil.example/steal"]) {
    const e = github({ "/orgs/acme/repos": { body: [repo("a")], link: `<${evil}>; rel="next"` } });
    await assert.rejects(auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: e.f }), /refusing to follow/, evil);
    assert.ok(e.calls.every((c) => c.url.hostname === "api.github.com"), `token never sent to ${evil}`);
  }
});

test("audit-org: archived repositories are skipped and --max-repos caps per-repository checks, with a note", async () => {
  const g = github({ ...quiet, "/orgs/acme/repos": { body: [{ ...repo("a"), archived: true }, repo("b"), repo("c")] } });
  const res = await auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: g.f, maxRepos: 1 });
  const probed = new Set(g.calls.map((c) => /^\/repos\/acme\/([^/]+)\//.exec(c.url.pathname)?.[1]).filter(Boolean));
  assert.deepEqual([...probed], ["b"]);
  assert.ok(res.notes.includes("per-repository checks covered 1 of 3 repositories (archived repositories skipped, --max-repos 1)"));
  // Only archived repositories: no worm check ran, so the audit is not clean.
  const all = await auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: github({ ...quiet, "/orgs/acme/repos": { body: [{ ...repo("a"), archived: true }] } }).f });
  assert.equal(all.incomplete, "no repository answered: default-branch workflow file listing, IOC branch lookup (wormsign-test-branch), repository runner inventory");
});

test("audit-org: a branch IOC ending in * matches any branch with that prefix", async () => {
  const linter = { name: "add-linter-workflow-*", wave: "test", source: "https://example.test/synthetic-ioc" };
  const g = github({ ...quiet, ...oneRepo, "/repos/acme/a/git/matching-refs/heads/add-linter-workflow-": { body: [{ ref: "refs/heads/add-linter-workflow-1732000000000" }] } });
  const res = await auditOrg({ org: "acme", token: "t", iocs: { ...iocs(), branches: [...iocs().branches, linter] }, fetchImpl: g.f });
  assert.deepEqual(res.findings.filter((f) => f.ruleId === "WS-OR-004").map((f) => f.key), ["acme/a:branch:add-linter-workflow-1732000000000"]);
  assert.equal(res.incomplete, undefined);
});

test("audit-org: a branch IOC that is only \"*\" or has a \"*\" before its end, or that git would not accept as a branch name, is rejected before any request", async () => {
  for (const name of ["*", "**", "", "add-*-workflow", "add-linter-workflow-**", "../../../../../../user/keys", "a/../b", "a..b", ".hidden", "a/.b", "a//b", "/a", "a/", "a.lock", "a.lock/b", "a.", "x/.*"]) {
    const g = github({ ...quiet, ...oneRepo });
    const bad = { ...iocs(), branches: [{ name, wave: "test", source: "https://example.test/synthetic-ioc" }] };
    await assert.rejects(auditOrg({ org: "acme", token: "t", iocs: bad, fetchImpl: g.f }), new RegExp(`invalid branch IOC "${name.replaceAll("*", "\\*")}"`), name);
    assert.equal(g.calls.length, 0, `${name}: nothing is requested`);
  }
});

test("audit-org: a request path the URL parser would rewrite (a \"..\" segment) is refused, so the token never reaches another endpoint", async () => {
  const g = github({ ...quiet, "/orgs/acme/repos": { body: [{ name: "x", full_name: "acme/../../user", private: true, description: null }] } });
  await assert.rejects(auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: g.f }), /refusing a request path that the URL parser rewrites: \/repos\/acme\/\.\.\/\.\.\/user\//);
  assert.ok(g.calls.every((c) => c.url.pathname.startsWith("/orgs/acme/")), g.calls.map((c) => c.url.pathname).join(" "));
});

test("audit-org: a nameRegex sees at most the 100 characters GitHub allows in a repository name", () => {
  const p = { id: "x", match: "nameRegexAndDescriptionExact", nameRegex: "^x{100}$", description: "d", severity: "high", wave: "t", source: "https://example.test/s" } as const;
  assert.ok(matchRepoPattern(p, { name: "x".repeat(101), description: "d" }));
  assert.ok(!matchRepoPattern(p, { name: "x".repeat(100), description: "other" }));
});

test("audit-org: entries without the fields the checks read are an unexpected body, not a crash or a skip", async () => {
  const g = github({
    ...quiet,
    ...oneRepo,
    "/orgs/acme/actions/runners": { body: { total_count: 1, runners: [{ status: "online" }] } },
    "/repos/acme/a/contents/.github/workflows": { body: [null] },
    "/orgs/acme/audit-log": { body: [null] },
  });
  const res = await auditOrg({ org: "acme", token: "t", iocs: iocs(), fetchImpl: g.f });
  const msg = (key: string) => res.findings.find((f) => f.key.startsWith(key))?.message ?? "";
  assert.match(msg("organization runner inventory"), /skipped, HTTP 200 \(unexpected body\)/);
  assert.match(msg("default-branch workflow file listing"), /not checked for 1 of 1 repositories because of an unexpected answer \(HTTP 200 \(unexpected body\) x1\): acme\/a\./);
  assert.match(msg("audit-log queries"), /skipped, HTTP 200 \(unexpected body\)/);
});

test("repo pattern matching semantics", () => {
  const p = (m: object) => m as Parameters<typeof matchRepoPattern>[0];
  assert.ok(matchRepoPattern(p({ match: "nameExact", name: "Shai-Hulud" }), { name: "Shai-Hulud", description: null }));
  assert.ok(!matchRepoPattern(p({ match: "nameExact", name: "Shai-Hulud" }), { name: "shai-hulud-fan", description: null }));
  assert.ok(matchRepoPattern(p({ match: "nameContains", name: "shai-hulud migration" }), { name: "Shai-Hulud-Migration-1", description: null }) === false, "hyphenation differs");
  assert.ok(matchRepoPattern(p({ match: "descriptionContains", description: "mini shai-hulud" }), { name: "x", description: "A Mini Shai-Hulud has Appeared" }));
  assert.ok(!matchRepoPattern(p({ match: "descriptionExact", description: "x" }), { name: "x", description: null }));
});

/* ---- CLI wiring ---- */
const IOCS = ["--iocs", fx("iocs")];
test("cli audit-org: needs a token and says which scopes; errors never print the token", async () => {
  const none = fakeIO();
  assert.equal(await run(["audit-org", "acme"], none), 2);
  assert.match(none.err, /Fine-grained token, read-only: repository Metadata, Contents and Administration; organization Self-hosted runners and Administration \(audit log\)\. Classic token: repo, admin:org/);
  assert.doesNotMatch(none.err, /README/, "there is no README to point at");
  const io = fakeIO({ env: { GITHUB_TOKEN: "ghp_SECRETSECRET" }, fetchImpl: github({ "/orgs/acme/repos": { status: 401 } }).f });
  assert.equal(await run(["audit-org", "acme", ...IOCS], io), 2);
  assert.ok(!io.err.includes("ghp_SECRETSECRET") && !io.out.includes("ghp_SECRETSECRET"));
});
test("cli audit-org: a misspelled organization exits 2", async () => {
  const io = fakeIO({ env: { GITHUB_TOKEN: "t" }, fetchImpl: github({ ...quiet }).f });
  assert.equal(await run(["audit-org", "acmee", ...IOCS], io), 2);
  assert.match(io.err, /cannot list repositories of acmee \(HTTP 404\).*nothing was audited/);
});
test("cli audit-org: an empty repository listing exits 2", async () => {
  const io = fakeIO({ env: { GITHUB_TOKEN: "t" }, fetchImpl: github({ ...quiet, "/orgs/acme/repos": { body: [] } }).f });
  assert.equal(await run(["audit-org", "acme", ...IOCS], io), 2);
  assert.match(io.err, /sees 0 repositories in acme, so nothing was audited/);
});
test("cli audit-org: an incomplete audit prints its report and exits 2 unless findings already fail it", async () => {
  const denied = { status: 403 };
  const routes = { "/orgs/acme/repos": { body: [repo("a")] }, "/repos/acme/*/contents/.github/workflows": denied, "/repos/acme/*/git/matching-refs/heads/wormsign-test-branch": denied, "/repos/acme/*/actions/runners": denied, "/orgs/acme/actions/runners": denied, "/orgs/acme/audit-log": denied };
  const io = fakeIO({ env: { GITHUB_TOKEN: "t" }, fetchImpl: github(routes).f });
  assert.equal(await run(["audit-org", "acme", ...IOCS], io), 2);
  assert.match(io.out, /WS-OR-900/, "the degraded findings are still reported");
  assert.match(io.err, /audit incomplete: no repository answered: default-branch workflow file listing, repository runner inventory; see the WS-OR-900 findings/);
  // A JSON report says so too, and names the IOC data it used.
  const json = fakeIO({ env: { GITHUB_TOKEN: "t" }, fetchImpl: github(routes).f });
  assert.equal(await run(["audit-org", "acme", ...IOCS, "--format", "json"], json), 2);
  const notes = (JSON.parse(json.out) as { notes: string[] }).notes;
  assert.ok(notes.includes("audit incomplete: no repository answered: default-branch workflow file listing, repository runner inventory"), notes.join("\n"));
  assert.ok(notes.some((n) => n.includes(`--iocs ${fx("iocs")}`)), notes.join("\n"));
  const hit = fakeIO({ env: { GITHUB_TOKEN: "t" }, fetchImpl: github({ ...routes, "/orgs/acme/repos": { body: [repo("wormsign-marker-repo")] } }).f });
  assert.equal(await run(["audit-org", "acme", ...IOCS], hit), 1, "findings at the threshold keep exit 1");
});
test("cli audit-org: bad --max-repos and --since are usage errors before any request", async () => {
  for (const flags of [["--max-repos", "ten"], ["--max-repos", "0"], ["--max-repos", "-1"], ["--max-repos", "1.5"], ["--since", "2026-13-01"], ["--since", "2026-02-30"], ["--since", "2026-1-1"], ["--since", "2026-10-02"]]) {
    const g = github({ ...quiet, "/orgs/acme/repos": { body: [] } });
    const io = fakeIO({ env: { GITHUB_TOKEN: "t" }, fetchImpl: g.f });
    assert.equal(await run(["audit-org", "acme", ...IOCS, ...flags], io), 2, flags.join(" "));
    assert.match(io.err, new RegExp(`invalid ${flags[0]}`), flags.join(" "));
    assert.equal(g.calls.length, 0, flags.join(" "));
  }
  const g = github({ ...quiet, "/orgs/acme/repos": { body: [repo("a"), repo("b")] } });
  const io = fakeIO({ env: { GITHUB_TOKEN: "t" }, fetchImpl: g.f });
  assert.equal(await run(["audit-org", "acme", ...IOCS, "--max-repos", "1", "--since", "2026-09-01", "--format", "json"], io), 0);
  assert.equal(phrases(g.calls)[0], "action:repo.access created:>=2026-09-01");
  assert.match(io.out, /per-repository checks covered 1 of 2 repositories/);
});

test("cli audit-org: a baseline in the working directory says on stderr what it suppressed, and --no-baseline reads none", async (t) => {
  const routes = { ...quiet, "/orgs/acme/repos": { body: [repo("wormsign-marker-repo")] } };
  const first = fakeIO({ env: { GITHUB_TOKEN: "t" }, fetchImpl: github(routes).f });
  assert.equal(await run(["audit-org", "acme", ...IOCS, "--format", "json"], first), 1);
  const fps = (JSON.parse(first.out) as { findings: { fingerprint: string }[] }).findings.map((f) => f.fingerprint);
  assert.ok(fps.length > 0);
  // A clone someone else wrote, with a baseline that hides every finding, as the working directory.
  const clone = mkdtempSync(join(tmpdir(), "wormsign-ao-cwd-"));
  writeFileSync(join(clone, ".wormsign-baseline.json"), JSON.stringify({ version: 1, entries: fps.map((fingerprint) => ({ fingerprint, justification: "written by the clone's author" })) }));
  const cwd = process.cwd();
  process.chdir(clone);
  t.after(() => process.chdir(cwd));
  const hidden = fakeIO({ env: { GITHUB_TOKEN: "t" }, fetchImpl: github(routes).f });
  assert.equal(await run(["audit-org", "acme", ...IOCS, "--format", "json"], hidden), 0);
  assert.match(hidden.err, /^wormsign: warning: \.wormsign-baseline\.json comes from the directory being checked and suppressed \d+ finding\(s\) \(WS-OR-001: \d+/);
  // Human text on a terminal: the note is on the screen, so it is said there once, not on stderr as well.
  const human = fakeIO({ env: { GITHUB_TOKEN: "t" }, fetchImpl: github(routes).f, stdoutIsTTY: true });
  assert.equal(await run(["audit-org", "acme", ...IOCS], human), 0);
  assert.equal(human.out.split("comes from the directory being checked").length, 2, human.out);
  assert.match(human.out, /^note: warning: \.wormsign-baseline\.json comes from the directory being checked and suppressed/m);
  assert.equal(human.err, "");
  const all = fakeIO({ env: { GITHUB_TOKEN: "t" }, fetchImpl: github(routes).f });
  assert.equal(await run(["audit-org", "acme", ...IOCS, "--no-baseline"], all), 1);
  assert.equal(all.err, "");
});
