/**
 * The PyPI Simple API client (src/python/index.ts): the exact request, what a response must look like before it is
 * believed, redirects, status codes, project status in both shapes, upload times, and how a locked sha256 is bound to
 * an index file. Responses are captured Simple JSON from pypi.org (test/fixtures/python/simple, and forged/captured)
 * or edits of them; a fake fetch serves them, never the network.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  bindLockedFile,
  CONCURRENCY,
  createIndexClient,
  displayUrl,
  MAX_SIMPLE_BYTES,
  normalizeIndexUrl,
  parseSimpleProject,
  readUploadTime,
  releaseFiles,
  sameFileUrl,
  SIMPLE_JSON,
  userAgent,
  type IndexProject,
} from "../src/python/index.js";

const FIX = join(import.meta.dirname, "..", "..", "test", "fixtures", "python");
const VERSION = (JSON.parse(readFileSync(join(import.meta.dirname, "..", "..", "package.json"), "utf8")) as { version: string }).version;

type Page = Record<string, unknown> & { files: Record<string, unknown>[]; meta: Record<string, unknown> };
/** A captured Simple JSON page, as a fresh object each time. */
function page(name: string): Page {
  const file = name === "pyyaml" ? join(FIX, "forged", "captured", "pyyaml.json") : join(FIX, "simple", `${name}.json`);
  return JSON.parse(readFileSync(file, "utf8")) as Page;
}
const json = (body: unknown, status = 200, type = SIMPLE_JSON): Response => new Response(JSON.stringify(body), { status, headers: { "content-type": type } });

interface Call {
  url: string;
  init: RequestInit | undefined;
}
/** A fake fetch: `routes` maps a URL to a response (or a function of the call count); anything else throws. */
function fake(routes: Record<string, Response | ((n: number) => Response | Promise<Response>)>) {
  const calls: Call[] = [];
  const count = new Map<string, number>();
  const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    calls.push({ url: u, init });
    const r = routes[u];
    if (r === undefined) throw new Error(`no route for ${u}`);
    const n = (count.get(u) ?? 0) + 1;
    count.set(u, n);
    return typeof r === "function" ? r(n) : r.clone();
  }) as typeof fetch;
  return { fetchImpl, calls };
}

const SIX = "https://pypi.org/simple/six/";

test("index: one GET per project, the JSON Simple form, wormsign's User-Agent, redirects not followed by fetch", async () => {
  const f = fake({ [SIX]: json(page("six")) });
  const client = createIndexClient({ index: "https://pypi.org/simple/", fetchImpl: f.fetchImpl });
  const [a, b] = await Promise.all([client.project("six"), client.project("six")]);
  assert.ok("project" in a && a === b, "the second call is served from the first");
  assert.equal(f.calls.length, 1);
  assert.equal(client.requests, 1);
  const headers = f.calls[0]!.init?.headers as Record<string, string>;
  assert.equal(f.calls[0]!.url, SIX);
  assert.equal(headers["accept"], "application/vnd.pypi.simple.v1+json");
  assert.equal(headers["user-agent"], `wormsign/${VERSION} (+https://github.com/stgllghr/wormsign)`);
  assert.equal(userAgent("1.2.3"), "wormsign/1.2.3 (+https://github.com/stgllghr/wormsign)");
  assert.equal(f.calls[0]!.init?.redirect, "manual");
  assert.ok(f.calls[0]!.init?.signal instanceof AbortSignal, "every request has a timeout");
  const p = (a as { project: IndexProject }).project;
  assert.equal(p.files.length, 48);
  assert.deepEqual(p.status, { state: "active", given: true });
  const whl = p.files.find((x) => x.filename === "six-1.17.0-py2.py3-none-any.whl")!;
  assert.deepEqual(whl, {
    filename: "six-1.17.0-py2.py3-none-any.whl",
    yanked: false,
    url: "https://files.pythonhosted.org/packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl",
    sha256: "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274",
    uploadTime: "2024-12-04T17:35:26.475808Z",
    dist: { kind: "wheel", name: "six", version: "1.17.0" },
  });

  // Any index path, with or without a trailing slash; the name is always the normalised one.
  const g = fake({ "https://pypi.corp.example/a/simple/zope-interface/": json({ ...page("six"), name: "zope-interface" }) });
  const corp = createIndexClient({ index: "https://pypi.corp.example/a/simple", fetchImpl: g.fetchImpl });
  assert.ok("project" in (await corp.project("zope-interface")));
  for (const bad of ["Six", "zope.interface", "../six", "six/..", "a b", ""]) {
    const r = await corp.project(bad);
    assert.ok("error" in r && /not a normalised project name/.test(r.error), bad);
  }
  assert.equal(g.calls.length, 1, "a name not in normal form never reaches a URL");
});

test("index: at most two requests in flight", async () => {
  let inFlight = 0;
  let most = 0;
  const routes: Record<string, (n: number) => Promise<Response>> = {};
  for (const name of ["a", "b", "c", "d", "e", "f"]) {
    routes[`https://pypi.org/simple/${name}/`] = async () => {
      inFlight++;
      most = Math.max(most, inFlight);
      await new Promise((r) => setTimeout(r, 5));
      inFlight--;
      return json({ ...page("six"), name });
    };
  }
  const f = fake(routes);
  const client = createIndexClient({ index: "https://pypi.org/simple/", fetchImpl: f.fetchImpl });
  const all = await Promise.all(["a", "b", "c", "d", "e", "f"].map((n) => client.project(n)));
  assert.ok(all.every((r) => "project" in r));
  assert.equal(CONCURRENCY, 2);
  assert.equal(most, 2);
});

test("index: a redirect within the index's origin is followed (at most 3); to another origin it is refused and not fetched", async () => {
  const same = fake({
    [SIX]: new Response(null, { status: 301, headers: { location: "/simple/six/v2/" } }),
    "https://pypi.org/simple/six/v2/": json(page("six")),
  });
  const r = await createIndexClient({ index: "https://pypi.org/simple/", fetchImpl: same.fetchImpl }).project("six");
  assert.ok("project" in r);
  assert.equal(r.project.url, "https://pypi.org/simple/six/v2/");
  assert.deepEqual(same.calls.map((c) => c.url), [SIX, "https://pypi.org/simple/six/v2/"]);

  const cross = fake({ [SIX]: new Response(null, { status: 302, headers: { location: "https://evil.example/simple/six/" } }) });
  const x = await createIndexClient({ index: "https://pypi.org/simple/", fetchImpl: cross.fetchImpl }).project("six");
  assert.deepEqual(x, { error: "the index redirected to https://evil.example, another origin, which wormsign does not follow" });
  assert.deepEqual(cross.calls.map((c) => c.url), [SIX], "the other origin is never asked");
  const scheme = fake({ [SIX]: new Response(null, { status: 307, headers: { location: "http://pypi.org/simple/six/" } }) });
  assert.match((await createIndexClient({ index: "https://pypi.org/simple/", fetchImpl: scheme.fetchImpl }).project("six") as { error: string }).error, /another origin/, "https to http is another origin");

  const loop: Record<string, Response> = {};
  for (let i = 0; i < 5; i++) loop[i === 0 ? SIX : `${SIX}${i}`] = new Response(null, { status: 308, headers: { location: `${SIX}${i + 1}` } });
  const l = fake(loop);
  assert.deepEqual(await createIndexClient({ index: "https://pypi.org/simple/", fetchImpl: l.fetchImpl }).project("six"), { error: "the index redirected more than 3 times" });
  assert.equal(l.calls.length, 4);
  const noLocation = fake({ [SIX]: new Response(null, { status: 301 }) });
  assert.deepEqual(await createIndexClient({ index: "https://pypi.org/simple/", fetchImpl: noLocation.fetchImpl }).project("six"), { error: "the index answered HTTP 301 with no Location" });
});

test("index: 404 is 'not on the index'; 429/5xx and network errors are retried once; other statuses are errors", async () => {
  const run = async (routes: Parameters<typeof fake>[0]) => {
    const f = fake(routes);
    return { r: await createIndexClient({ index: "https://pypi.org/simple/", fetchImpl: f.fetchImpl }).project("six"), calls: f.calls.length };
  };
  assert.deepEqual(await run({ [SIX]: json({ message: "Not Found" }, 404, "application/json") }), { r: { notFound: "not on the index (deleted or quarantined), or never published" }, calls: 1 });
  assert.deepEqual(await run({ [SIX]: (n) => (n === 1 ? json({}, 503) : json(page("six"))) }).then((x) => ["project" in x.r, x.calls]), [true, 2]);
  assert.deepEqual(await run({ [SIX]: json({}, 502) }), { r: { error: "the index returned HTTP 502", outage: "HTTP 502" }, calls: 2 });
  assert.deepEqual(await run({ [SIX]: json({}, 429) }), { r: { error: "the index returned HTTP 429", outage: "HTTP 429" }, calls: 2 });
  assert.deepEqual(await run({ [SIX]: json({}, 403) }), { r: { error: "the index returned HTTP 403 (wormsign sends no credentials)" }, calls: 1 });
  assert.deepEqual(await run({ [SIX]: json({}, 202) }), { r: { error: "the index returned HTTP 202" }, calls: 1 });
  let n = 0;
  const flaky = (async () => {
    if (++n === 1) throw new Error("ECONNRESET");
    return json(page("six"));
  }) as unknown as typeof fetch;
  assert.ok("project" in (await createIndexClient({ index: "https://pypi.org/simple/", fetchImpl: flaky }).project("six")));
  const down = (async () => {
    throw new Error("getaddrinfo ENOTFOUND pypi.org");
  }) as unknown as typeof fetch;
  assert.deepEqual(await createIndexClient({ index: "https://pypi.org/simple/", fetchImpl: down }).project("six"), { error: "the request to the index failed: getaddrinfo ENOTFOUND pypi.org" });
});

test("index: a response that is not the JSON Simple API v1.1+ for the project asked about is an error, never an empty answer", async () => {
  const get = async (res: Response) => createIndexClient({ index: "https://pypi.org/simple/", fetchImpl: fake({ [SIX]: res }).fetchImpl }).project("six");
  const err = async (res: Response) => ((await get(res)) as { error: string }).error;
  assert.equal(await err(new Response("<html>", { headers: { "content-type": "text/html" } })), 'the index answered with content type "text/html", not application/vnd.pypi.simple.v1+json (PEP 691\'s JSON form)');
  assert.equal(await err(new Response("{}")), 'the index answered with content type "text/plain", not application/vnd.pypi.simple.v1+json (PEP 691\'s JSON form)');
  assert.ok("project" in (await get(new Response(JSON.stringify(page("six")), { headers: { "content-type": "Application/VND.pypi.simple.v1+json; charset=utf-8" } }))), "type parameters and case do not matter");
  assert.equal(await err(json({ ...page("six"), meta: { "api-version": "1.0" } })), 'the index\'s API version "1.0" is not 1.1 or a later 1.x, so it may not give upload times (PEP 700)');
  assert.equal(await err(json({ ...page("six"), meta: { "api-version": "2.0" } })), 'the index\'s API version "2.0" is not 1.1 or a later 1.x, so it may not give upload times (PEP 700)');
  assert.equal(await err(json({ ...page("six"), meta: { "api-version": 1.4 } })), "the index's API version 1.4 is not 1.1 or a later 1.x, so it may not give upload times (PEP 700)");
  assert.ok("project" in (await get(json({ ...page("six"), meta: { "api-version": "1.12" } }))), "1.12 is a later 1.x");
  assert.equal(await err(json({ ...page("six"), name: "Six" })), 'the index answered for project "Six", not "six"');
  assert.equal(await err(json({ ...page("six"), name: "idna" })), 'the index answered for project "idna", not "six"');
  assert.equal(await err(json({ ...page("six"), files: {} })), "the index's response has no files list");
  assert.equal(await err(json({ ...page("six"), files: [null] })), "file #1 in the index's response is not an object");
  assert.equal(await err(json({ ...page("six"), files: [{ filename: "a/b.whl", hashes: {} }] })), "file #1 in the index's response has no valid filename");
  assert.equal(await err(json({ ...page("six"), files: [{ filename: "six-1.0.tar.gz" }] })), "file #1 in the index's response (six-1.0.tar.gz) has no hashes object");
  assert.equal(await err(json({ ...page("six"), files: [{ filename: "six-1.0.tar.gz", hashes: {}, yanked: 1 }] })), "file #1 in the index's response (six-1.0.tar.gz) has a yanked value that is neither a boolean nor a reason");
  assert.equal(await err(json([])), "the index's response is not a JSON object");
  assert.equal(await err(json({ name: "six", files: [] })), "the index's response has no meta object");
  assert.equal(await err(new Response("{", { headers: { "content-type": SIMPLE_JSON } })), "the index's response is not valid JSON");
  assert.equal(await err(new Response(new Uint8Array([0x7b, 0xff, 0x7d]), { headers: { "content-type": SIMPLE_JSON } })), "the index's response is not valid UTF-8");
  assert.equal(await err(new Response("{}", { headers: { "content-type": SIMPLE_JSON, "content-length": String(MAX_SIMPLE_BYTES + 1) } })), "the index's response is larger than 64 MiB");
  // A body larger than the cap without a Content-Length is cut off while it streams.
  const chunk = new Uint8Array(8 * 1024 * 1024).fill(0x20);
  let sent = 0;
  const stream = new ReadableStream<Uint8Array>({
    pull(c) {
      sent += chunk.length;
      if (sent > MAX_SIMPLE_BYTES * 2) c.close();
      else c.enqueue(chunk);
    },
  });
  const streamed = await createIndexClient({ index: "https://pypi.org/simple/", fetchImpl: (async () => new Response(stream, { headers: { "content-type": SIMPLE_JSON } })) as unknown as typeof fetch }).project("six");
  assert.deepEqual(streamed, { error: "the index's response is larger than 64 MiB" });
  assert.ok(sent <= MAX_SIMPLE_BYTES + 2 * chunk.length, "reading stopped at the cap");
});

test("index: relative file URLs resolve against the response URL; credentials, queries and other schemes in the index URL are refused", async () => {
  const p = page("six");
  p.files = [{ ...p.files[0]!, url: "../../packages/six-0.9.0.tar.gz#sha256=abc" }];
  const r = parseSimpleProject(p, "six", "https://pypi.corp.example/simple/six/");
  assert.ok("project" in r);
  assert.equal(r.project.files[0]!.url, "https://pypi.corp.example/packages/six-0.9.0.tar.gz#sha256=abc");
  assert.ok(sameFileUrl("https://pypi.corp.example/packages/six-0.9.0.tar.gz", r.project.files[0]!.url), "the fragment is never sent, so it does not count");
  assert.ok(!sameFileUrl("https://pypi.corp.example/packages/six-0.9.0.tar.gz", "https://evil.example/packages/six-0.9.0.tar.gz"));
  assert.ok(!sameFileUrl("https://pypi.corp.example/packages/six-0.9.0.tar.gz", undefined));
  assert.ok(sameFileUrl("https://pypi.corp.example/packages/six-0.9.0.tar.gz#sha256=abc", r.project.files[0]!.url), "the index's own fragment");
  assert.ok(!sameFileUrl("https://pypi.corp.example/packages/six-0.9.0.tar.gz#sha512=abc", r.project.files[0]!.url), "another fragment");

  // Character for character: a lock url that only WHATWG parsing turns into the index's url is another url, because
  // pip 26.2.1 rebuilds it with Python's urlsplit (the first one reaches evil.example there).
  const real = "https://files.pythonhosted.org/packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl";
  assert.ok(sameFileUrl(real, real));
  for (const spelled of [
    "https://files.pythonhosted.org\\@evil.example/../packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl",
    "https://files.pythonhosted.org/packages/b7/ce/./149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl",
    "https://files.pythonhosted.org/x/../packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl",
    "https://FILES.pythonhosted.org/packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl",
    "https://files.pythonhosted.org:443/packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl",
    "https://files.pythonhosted.org\\packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl",
    " https://files.pythonhosted.org/packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl",
    `${real}#sha256=4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274`,
  ]) {
    assert.equal(new URL(spelled).href.replace(/#.*$/, ""), real, `positive control: WHATWG reads ${spelled} as the index's url`);
    assert.ok(!sameFileUrl(spelled, real), spelled);
  }

  const f = fake({});
  const creds = await createIndexClient({ index: "https://user:token@pypi.corp.example/simple/", fetchImpl: f.fetchImpl }).project("six");
  assert.deepEqual(creds, { error: "the index URL carries credentials, which wormsign never sends" });
  for (const bad of ["ftp://pypi.org/simple/", "https://pypi.org/simple/?x=1", "not a url"]) {
    const e = await createIndexClient({ index: bad, fetchImpl: f.fetchImpl }).project("six");
    assert.match((e as { error: string }).error, /is not an http\(s\) URL without query or fragment/, bad);
  }
  assert.equal(f.calls.length, 0);

  assert.equal(normalizeIndexUrl("https://PyPI.org/simple/"), "https://pypi.org/simple");
  assert.equal(normalizeIndexUrl("https://pypi.org/simple"), "https://pypi.org/simple");
  assert.equal(normalizeIndexUrl("https://pypi.org:443/simple//"), "https://pypi.org/simple");
  assert.equal(normalizeIndexUrl("https://u:p@pypi.org/simple/"), "https://pypi.org/simple");
  assert.equal(normalizeIndexUrl("https://pypi.org:8443/simple/"), "https://pypi.org:8443/simple");
  assert.equal(normalizeIndexUrl("/abs/path/fl"), undefined);
  assert.equal(normalizeIndexUrl("https://pypi.org/simple/?a"), undefined);
  assert.equal(displayUrl("https://user:secret@pypi.corp.example/simple/"), "https://pypi.corp.example/simple/");
  assert.equal(displayUrl("https://pypi.org/simple/"), "https://pypi.org/simple/");
  // Credentials the URL parser does not read as userinfo, or in a URL it refuses, are not printed either.
  assert.equal(displayUrl("https://user:secret@pypi.corp.example:99999/simple/"), "https://pypi.corp.example:99999/simple/");
  assert.equal(displayUrl("git+ssh:user:secret@git.corp.example/x.git"), "git+ssh:git.corp.example/x.git");
  assert.equal(displayUrl(" https://user:secret@[bad/simple/"), " https://[bad/simple/");
  // Anything else is shown as given, query and fragment included (a git source's commit is in its fragment).
  assert.equal(displayUrl("https://github.com/benjaminp/six?tag=1.17.0#2b9bd1ba"), "https://github.com/benjaminp/six?tag=1.17.0#2b9bd1ba");
  assert.equal(displayUrl("https://files.example/a@b/x.whl"), "https://files.example/a@b/x.whl");
});

test("index: project-status is read from the top-level object or from flat strings in meta; anything else is unknown", () => {
  const status = (edit: (p: Page) => void) => {
    const p = page("six");
    edit(p);
    const r = parseSimpleProject(p, "six", SIX);
    assert.ok("project" in r);
    return r.project.status;
  };
  assert.deepEqual(status((p) => delete p["project-status"]), { state: "active", given: false }, "absent counts as active");
  assert.deepEqual(status((p) => (p["project-status"] = { status: "quarantined", reason: "malware" })), { state: "quarantined", reason: "malware", given: true });
  assert.deepEqual(status((p) => (p["project-status"] = { status: "archived" })), { state: "archived", given: true });
  assert.deepEqual(
    status((p) => {
      delete p["project-status"];
      p.meta["project-status"] = "quarantined";
      p.meta["project-status-reason"] = "malware";
    }),
    { state: "quarantined", reason: "malware", given: true },
    "the Simple API specification's example shape",
  );
  assert.deepEqual(status((p) => (p.meta["project-status"] = "active")), { state: "active", given: true }, "both shapes, agreeing");
  assert.deepEqual(status((p) => (p.meta["project-status"] = "quarantined")), { state: "unknown", value: '"active" at the top level and "quarantined" in meta' });
  assert.deepEqual(status((p) => (p["project-status"] = { status: "frozen" })), { state: "unknown", value: '"frozen"' });
  assert.deepEqual(status((p) => (p["project-status"] = "quarantined")), { state: "unknown", value: 'project-status "quarantined"' });
  assert.deepEqual(status((p) => (p["project-status"] = { reason: "x" })), { state: "unknown", value: 'project-status {"reason":"x"}' });
  assert.deepEqual(status((p) => {
    delete p["project-status"];
    p.meta["project-status"] = { status: "active" };
  }), { state: "unknown", value: 'meta.project-status {"status":"active"}' });
});

test("index: upload-time must be PEP 700's format and a real instant", () => {
  for (const ok of ["2024-12-04T17:35:26.475808Z", "2024-12-04T17:35:26Z", "2024-12-04T17:35:26.4Z", "2024-02-29T00:00:00Z"]) assert.deepEqual(readUploadTime(ok), { time: ok }, ok);
  for (const bad of ["2024-12-04T17:35:26.4758081Z", "2024-12-04T17:35:26+00:00", "2024-12-04 17:35:26Z", "2024-12-04T17:35Z", "2024-12-04", " 2024-12-04T17:35:26Z", "20241-12-04T17:35:26Z"]) {
    assert.match((readUploadTime(bad) as { problem: string }).problem, /is not in PEP 700's format/, bad);
  }
  for (const impossible of ["2023-02-29T00:00:00Z", "2024-13-01T00:00:00Z", "2024-12-04T24:00:00Z", "2024-12-04T23:60:00Z"]) {
    assert.match((readUploadTime(impossible) as { problem: string }).problem, /is not a real date and time|is not in PEP 700's format/, impossible);
  }
  assert.deepEqual(readUploadTime(undefined), { problem: "the index gives no upload-time for it (PEP 700)" });
  assert.deepEqual(readUploadTime(1733333726), { problem: "the index's upload-time 1733333726 is not in PEP 700's format" });
  const p = page("six");
  p.files = [{ ...p.files[0]!, "upload-time": "yesterday" }, { ...p.files[1]! }];
  delete p.files[1]!["upload-time"];
  const r = parseSimpleProject(p, "six", SIX) as { project: IndexProject };
  assert.equal(r.project.files[0]!.uploadTime, undefined);
  assert.equal(r.project.files[0]!.uploadTimeProblem, 'the index\'s upload-time "yesterday" is not in PEP 700\'s format');
  assert.equal(r.project.files[1]!.uploadTimeProblem, "the index gives no upload-time for it (PEP 700)");
});

test("index: a locked sha256 binds only to a file of this project and this version (PEP 440 equality, from the file name)", () => {
  const six = (parseSimpleProject(page("six"), "six", SIX) as { project: IndexProject }).project;
  const WHL_117 = "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274";
  const WHL_116 = six.files.find((f) => f.filename === "six-1.16.0-py2.py3-none-any.whl")!.sha256!;
  assert.ok("file" in bindLockedFile(six, "six", "1.17.0", WHL_117));
  assert.ok("file" in bindLockedFile(six, "six", "1.17.0", WHL_117.toUpperCase()), "hex case does not matter");
  assert.ok("file" in bindLockedFile(six, "six", "1.17", WHL_117), "1.17 equals 1.17.0 (PEP 440)");
  assert.deepEqual(bindLockedFile(six, "six", "1.17.0", WHL_116), { problem: "locked hash belongs to six-1.16.0-py2.py3-none-any.whl, not to a file of six 1.17.0" });
  assert.deepEqual(bindLockedFile(six, "six", "1.17.0", "0".repeat(64)), { problem: "not on the index (deleted or quarantined), or never published" });

  // A file listed under this project whose name states another project binds to nothing.
  const p = page("six");
  p.files.push({ ...p.files.at(-1)!, filename: "evil-1.17.0-py3-none-any.whl", hashes: { sha256: "a".repeat(64) } });
  const forged = (parseSimpleProject(p, "six", SIX) as { project: IndexProject }).project;
  assert.equal(forged.files.at(-1)!.dist, undefined);
  assert.deepEqual(bindLockedFile(forged, "six", "1.17.0", "a".repeat(64)), { problem: "locked hash belongs to evil-1.17.0-py3-none-any.whl, not to a file of six 1.17.0" });

  // Two files with the same hash: the youngest is the one aged.
  const q = page("six");
  const sdist = q.files.find((f) => f["filename"] === "six-1.17.0.tar.gz")!;
  q.files.push({ ...sdist, filename: "six-1.17.0.zip", "upload-time": "2026-01-01T00:00:00Z" });
  const twice = (parseSimpleProject(q, "six", SIX) as { project: IndexProject }).project;
  assert.equal((bindLockedFile(twice, "six", "1.17.0", (sdist["hashes"] as { sha256: string }).sha256) as { file: { filename: string } }).file.filename, "six-1.17.0.zip");

  assert.deepEqual(releaseFiles(six, "six", "1.17.0").map((f) => f.filename).sort(), ["six-1.17.0-py2.py3-none-any.whl", "six-1.17.0.tar.gz"]);
  const yaml = (parseSimpleProject(page("pyyaml"), "pyyaml", "https://pypi.org/simple/pyyaml/") as { project: IndexProject }).project;
  const r601 = releaseFiles(yaml, "pyyaml", "6.0.1");
  assert.equal(r601.length, 51, "PyYAML 6.0.1's files (its rc1 is another version)");
  assert.equal(r601.map((f) => f.uploadTime!).sort()[0], "2023-07-17T23:57:04.325444Z");
});
