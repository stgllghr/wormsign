import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bundledIocDir, indexPackages, loadIocDir, loadIocs, parseIocs } from "../src/iocs.js";
import { DEFAULT_IOC_URL, updateIocs } from "../src/update-iocs.js";
import { fx } from "./helpers.js";

/* ---- bundled IOC data: provenance is enforced, not assumed ---- */
test("bundled IOC data loads and every entry has an https source", () => {
  const iocs = loadIocDir(bundledIocDir);
  for (const s of iocs.packageSets) assert.match(s.source, /^https:\/\//, s.id);
  for (const list of [iocs.hashes, iocs.names, iocs.workflowFiles, iocs.runnerNames, iocs.repoPatterns, iocs.branches, iocs.endpoints]) {
    for (const e of list) assert.match((e as { source: string }).source, /^https:\/\//);
  }
  assert.ok(iocs.hashes.length >= 20);
});
test("bundled IOC data: known entries are present and indexed", () => {
  const iocs = loadIocDir(bundledIocDir);
  const idx = indexPackages(iocs.packageSets);
  assert.match(idx.lookup("@ctrl/tinycolor", "4.1.1") ?? "", /stepsecurity/);
  assert.ok(idx.lookup("@ctrl/tinycolor", "4.1.2"));
  assert.equal(idx.lookup("@ctrl/tinycolor", "4.1.0"), undefined, "adjacent safe version must not match");
  assert.equal(idx.lookup("lodash", "4.17.21"), undefined);
  assert.ok(iocs.runnerNames.some((r) => r.name === "SHA1HULUD"));
  assert.ok(iocs.workflowFiles.some((w) => w.name === "shai-hulud-workflow.yml"));
});
test("every sha256 in the bundled data is unique and well-formed", () => {
  const hs = loadIocDir(bundledIocDir).hashes.map((h) => h.sha256);
  assert.equal(new Set(hs).size, hs.length);
  assert.ok(hs.every((h) => /^[0-9a-f]{64}$/.test(h)));
});

function rawFiles() {
  const read = (n: string) => JSON.parse(readFileSync(join(fx("iocs"), `${n}.json`), "utf8"));
  return { packages: read("packages"), files: read("files"), workflows: read("workflows"), repos: read("repos"), endpoints: read("endpoints") };
}
test("mutant: IOC entries without a source are rejected", () => {
  const mutate = (f: (r: ReturnType<typeof rawFiles>) => void) => { const r = rawFiles(); f(r); return () => parseIocs(r); };
  assert.throws(mutate((r) => delete r.packages.sets[0].source), /source/);
  assert.throws(mutate((r) => (r.files.hashes[0].source = "http://insecure.example")), /https source/);
  assert.throws(mutate((r) => delete r.files.names[0].source), /source/);
  assert.throws(mutate((r) => delete r.workflows.workflowFiles[0].source), /source/);
  assert.throws(mutate((r) => delete r.workflows.runnerNames[0].source), /source/);
  assert.throws(mutate((r) => delete r.repos.patterns[0].source), /source/);
  assert.throws(mutate((r) => delete r.endpoints.endpoints[0].source), /source/);
  assert.throws(mutate((r) => (r.files.hashes[0].sha256 = "abc")), /bad sha256/);
  assert.throws(mutate((r) => (r.repos.patterns[2].nameRegex = "(")));
  assert.throws(mutate((r) => (r.packages.schema = 2)), /schema 1/);
  assert.throws(mutate((r) => (r.files.names[0].nameOnlySeverity = "severe")), /bad severity/);
  assert.throws(mutate((r) => (r.workflows.workflowFiles[0].severity = "CRITICAL")), /bad severity/);
  assert.throws(mutate((r) => (r.packages.sets[0].packages["wormsign-test-marker"] = [])), /no versions/);
  assert.throws(mutate((r) => (r.workflows.runnerNames[0].name = "SHA1HULUD(")), /plain runner name/);
  assert.throws(mutate((r) => (r.repos.version = "2026-10-02")), /disagree on "version"/);
  assert.throws(mutate((r) => { for (const f of Object.values(r)) f.version = "Oct 2026"; }), /YYYY-MM-DD/);
  for (const broad of ["", "https://", "a[.]b", "https://www[.]", "https://[.]", "webhook[.]site[.]"]) assert.throws(mutate((r) => (r.endpoints.endpoints[0].substring = broad)), /not a host or URL/, broad);
  for (const host of ["0x0[.]st", "t[.]me", "https://bit[.]ly/x"]) assert.doesNotThrow(mutate((r) => (r.endpoints.endpoints[0].substring = host)), host);
  const branch = (name: string) => mutate((r) => r.repos.branches.push({ name, wave: "test", source: "https://example.test/b" }));
  for (const bad of ["*", "a*b", "a b"]) assert.throws(branch(bad), /not a branch name, or a prefix ending in "\*"/, bad);
  for (const ok of ["shai-hulud", "add-linter-workflow-*", "dependabot/github_actions/format/setup-formatter"]) assert.doesNotThrow(branch(ok), ok);
  assert.doesNotThrow(mutate(() => undefined));
});

/* ---- exclusions: a version a source lists in error is dropped by the loader, with evidence ---- */
const exclusion = { set: "synthetic", name: "wormsign-test-marker", version: "1.0.0", checked: "2026-10-02", reason: "listed in error", evidence: ["https://example.test/evidence"] };
test("exclusions drop the listed version without editing the set as read", () => {
  const r = rawFiles();
  r.packages.sets[0].packages["wormsign-test-marker"] = ["1.0.0", "1.0.1"];
  r.packages.sets[0].packages["other"] = ["2.0.0"];
  r.packages.exclusions = [exclusion, { ...exclusion, name: "other", version: "2.0.0" }];
  const before = structuredClone(r);
  const idx = indexPackages(parseIocs(r).packageSets);
  assert.equal(idx.lookup("wormsign-test-marker", "1.0.0"), undefined);
  assert.ok(idx.lookup("wormsign-test-marker", "1.0.1"), "only the excluded version goes");
  assert.equal(idx.lookup("other", "2.0.0"), undefined, "a name with no version left goes");
  assert.deepEqual(r, before, "update-iocs compares the parsed files with the bundled ones");
});
test("mutant: an exclusion without evidence, or one that drops nothing, is rejected", () => {
  const withExclusion = (x: Record<string, unknown>) => () => {
    const r = rawFiles();
    r.packages.exclusions = [x];
    return parseIocs(r);
  };
  assert.doesNotThrow(withExclusion(exclusion));
  for (const k of ["reason", "checked", "evidence"]) {
    const x: Record<string, unknown> = { ...exclusion };
    delete x[k];
    assert.throws(withExclusion(x), /needs a reason, a "checked" YYYY-MM-DD date and https evidence URLs/, k);
  }
  assert.throws(withExclusion({ ...exclusion, reason: "" }), /needs a reason/);
  assert.throws(withExclusion({ ...exclusion, evidence: [] }), /needs a reason/);
  assert.throws(withExclusion({ ...exclusion, evidence: ["http://example.test/e"] }), /needs a reason/);
  assert.throws(withExclusion({ ...exclusion, checked: "2026-02-30" }), /needs a reason/);
  assert.throws(withExclusion({ ...exclusion, version: "9.9.9" }), /exclusion wormsign-test-marker@9\.9\.9: set synthetic does not list it/);
  assert.throws(withExclusion({ ...exclusion, set: "elsewhere" }), /set elsewhere does not list it/);
});

/* ---- update-iocs and the cache ---- */
function serve(files: Record<string, string>): typeof fetch {
  return (async (u: string | URL) => {
    const name = String(u).split("/").pop() as string;
    return name in files ? new Response(files[name]) : new Response("", { status: 404 });
  }) as typeof fetch;
}
const IOC_FILES = ["packages", "files", "workflows", "repos", "endpoints"];
const fixtureFiles = () => Object.fromEntries(IOC_FILES.map((n) => [`${n}.json`, readFileSync(join(fx("iocs"), `${n}.json`), "utf8")]));
const bundledVersion = () => loadIocDir(bundledIocDir).version as string;
type Files = Record<string, Record<string, unknown>>;
/** The bundled data files re-dated to `version`, optionally edited, as an update source would serve them. */
function release(version: string, edit: (f: Files) => void = () => undefined): Record<string, string> {
  const f: Files = Object.fromEntries(IOC_FILES.map((n) => [n, { ...JSON.parse(readFileSync(join(bundledIocDir, `${n}.json`), "utf8")), version }]));
  edit(f);
  return Object.fromEntries(IOC_FILES.map((n) => [`${n}.json`, JSON.stringify(f[n])]));
}
function writeCache(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "ws-cache-"));
  for (const [n, t] of Object.entries(files)) writeFileSync(join(dir, n), t);
  return dir;
}
const NEWER = "9999-12-31";
/** The clock for update-iocs, which refuses data dated after tomorrow; NEWER is tomorrow here. */
const LATE = new Date("9999-12-30T12:00:00Z");

test("bundled IOC data is versioned", () => {
  assert.match(bundledVersion(), /^\d{4}-\d{2}-\d{2}$/);
});
test("update-iocs: a newer, complete download replaces the cache", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ws-ioc-"));
  const res = await updateIocs("https://example.test/iocs/", dir, serve(release(NEWER)), LATE);
  assert.equal(res.written, true);
  assert.equal(loadIocDir(dir).version, NEWER);
  assert.deepEqual(res.notes, [`IOC data ${NEWER} from https://example.test/iocs/ written to ${dir}`]);
});
test("update-iocs: data no newer than the bundled data is already current, not an error, and writes nothing", async () => {
  for (const version of [bundledVersion(), "2000-01-01"]) {
    const dir = mkdtempSync(join(tmpdir(), "ws-ioc-"));
    const res = await updateIocs("https://example.test/iocs/", dir, serve(release(version)), LATE);
    assert.equal(res.written, false, version);
    assert.deepEqual(readdirSync(dir), [], version);
    assert.deepEqual(res.notes, [`bundled IOC data ${bundledVersion()} is already current (https://example.test/iocs/ has ${version}); cache not written`]);
    assert.deepEqual(loadIocs({ cacheDir: dir }).notes, [`IOC data ${bundledVersion()} from the bundled data ${bundledIocDir}`]);
  }
});
test("update-iocs: invalid, partial, stale, mixed or unversioned downloads leave the cache untouched", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ws-ioc-"));
  await updateIocs("https://example.test/iocs/", dir, serve(release(NEWER)), LATE);
  const before = readFileSync(join(dir, "packages.json"), "utf8");
  const update = (files: Record<string, string>, url = "https://example.test/iocs/") => updateIocs(url, dir, serve(files), LATE);
  await assert.rejects(update(release(NEWER, (f) => delete (f.files?.hashes as { source?: string }[])[0]?.source)), /source/);
  const partial = release(NEWER);
  delete partial["repos.json"];
  await assert.rejects(update(partial), /HTTP 404$/);
  await assert.rejects(update(release(NEWER), "http://example.test/iocs/"), /https/);
  assert.equal((await update(release(bundledVersion()))).written, false);
  await assert.rejects(update(release(NEWER, (f) => (f.repos!.version = "2000-01-01"))), /disagree/);
  await assert.rejects(update(fixtureFiles()), /refusing the IOC data at https:\/\/example\.test\/iocs\/: it has no version/);
  assert.equal(readFileSync(join(dir, "packages.json"), "utf8"), before);
});
test("IOC version must be a real calendar date, because versions are compared as strings", () => {
  const parseRelease = (v: string) => () => parseIocs(Object.fromEntries(Object.entries(release(v)).map(([n, t]) => [n.replace(".json", ""), JSON.parse(t)])) as Parameters<typeof parseIocs>[0]);
  for (const bad of ["2026-99-99", "2026-02-30", "2026-13-01", "2026-1-1"]) assert.throws(parseRelease(bad), /real YYYY-MM-DD date/, bad);
  assert.equal(parseRelease("2028-02-29")().version, "2028-02-29");
});
test("update-iocs: data dated after tomorrow is refused, so no cache outlives later releases", async () => {
  const day = (n: number) => new Date(Date.parse(bundledVersion()) + n * 86_400_000).toISOString().slice(0, 10);
  const now = new Date(`${day(1)}T23:59:00Z`);
  const dir = mkdtempSync(join(tmpdir(), "ws-ioc-"));
  await assert.rejects(updateIocs("https://example.test/iocs/", dir, serve(release(day(3))), now), new RegExp(`version ${day(3)} is in the future`));
  assert.deepEqual(readdirSync(dir), []);
  // Tomorrow is allowed: a release dated in a timezone ahead of UTC.
  assert.equal((await updateIocs("https://example.test/iocs/", dir, serve(release(day(2))), now)).written, true);
});
test("update-iocs: same-dated data with other content is refused, not called already current", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ws-ioc-"));
  const files = release(bundledVersion(), (f) => (f.packages!.sets as unknown[]).push({ id: "same-day", wave: "test", source: "https://example.test/new", packages: { "brand-new-worm": ["1.0.0"] } }));
  await assert.rejects(updateIocs("https://example.test/iocs/", dir, serve(files), LATE), /same version .* but different content; the source must bump "version"/);
  // One edit in any of the five files counts.
  const edits: ((f: Files) => void)[] = [
    (f) => (f.packages!.description = "edited"),
    (f) => (f.files!.hashes as unknown[]).pop(),
    (f) => (f.workflows!.runnerNames as unknown[]).pop(),
    (f) => (f.repos!.branches as unknown[]).pop(),
    (f) => (f.endpoints!.description = "edited"),
  ];
  for (const edit of edits) await assert.rejects(updateIocs("https://example.test/iocs/", dir, serve(release(bundledVersion(), edit)), LATE), /different content/, String(edit));
  assert.deepEqual(readdirSync(dir), []);
});
test("update-iocs: same-dated data with its keys reordered is the same content, so already current", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ws-ioc-"));
  const reversed = (o: unknown): unknown => Array.isArray(o) ? o.map(reversed) : o && typeof o === "object" ? Object.fromEntries(Object.entries(o).reverse().map(([k, v]) => [k, reversed(v)])) : o;
  const files = Object.fromEntries(Object.entries(release(bundledVersion())).map(([n, t]) => [n, JSON.stringify(reversed(JSON.parse(t)))]));
  assert.notEqual(files["packages.json"], release(bundledVersion())["packages.json"], "positive control: the text differs");
  assert.equal((await updateIocs("https://example.test/iocs/", dir, serve(files), LATE)).written, false);
  assert.deepEqual(readdirSync(dir), []);
});
test("update-iocs writes exactly the data that loadIocs then adds", async () => {
  for (const version of ["2000-01-01", NEWER]) {
    const dir = mkdtempSync(join(tmpdir(), "ws-ioc-"));
    const files = release(version, (f) => ((f.packages!.sets as { id: string }[])[0]!.id = "from-update"));
    const { written } = await updateIocs("https://example.test/iocs/", dir, serve(files), LATE);
    // Judge the same data as a cache, whether or not update-iocs wrote it.
    const used = loadIocs({ cacheDir: written ? dir : writeCache(files) }).packageSets.some((s) => s.id === "from-update");
    assert.equal(written, used, version);
  }
});
test("update-iocs: a 404 from the default source says why and what to do", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ws-ioc-"));
  await assert.rejects(updateIocs(DEFAULT_IOC_URL, dir, serve({}), LATE), /HTTP 404 from the default source \(this repository's main branch\); pass --url <https directory holding the five IOC files>$/);
});
test("loadIocs: --iocs dir wins and the report names it", () => {
  const set = loadIocs({ dir: fx("iocs") });
  assert.equal(set.packageSets[0]?.id, "synthetic");
  assert.deepEqual(set.notes, [`IOC data (unversioned) from --iocs ${fx("iocs")}`]);
});
test("loadIocs: with no cache, the bundled data is used and named", () => {
  const set = loadIocs({ cacheDir: mkdtempSync(join(tmpdir(), "ws-empty-")) });
  assert.deepEqual(set.notes, [`IOC data ${bundledVersion()} from the bundled data ${bundledIocDir}`]);
});
test("loadIocs: a newer cache adds its IOCs to the bundled data, and the report says so", () => {
  const cache = writeCache(release(NEWER, (f) => {
    f.packages!.sets = [{ id: "from-cache", wave: "test", source: "https://example.test/new", packages: { "wormsign-new-ioc": ["9.9.9"] } }];
    f.packages!.exclusions = [];
    (f.workflows!.runnerNames as { name: string }[]).push({ ...(f.workflows!.runnerNames as { name: string }[])[0]!, name: "NewRunner" });
  }));
  const bundled = loadIocDir(bundledIocDir);
  const set = loadIocs({ cacheDir: cache });
  assert.deepEqual(set.packageSets.map((s) => s.id), [...bundled.packageSets.map((s) => s.id), "from-cache"]);
  assert.equal(indexPackages(set.packageSets).lookup("wormsign-new-ioc", "9.9.9"), "https://example.test/new");
  assert.deepEqual(set.runnerNames.map((r) => r.name), [...bundled.runnerNames.map((r) => r.name), "NewRunner"]);
  assert.equal(set.version, NEWER);
  assert.deepEqual(set.notes, [`IOC data ${bundledVersion()} from the bundled data ${bundledIocDir}, plus additions from the update-iocs cache ${cache} (${NEWER})`]);
});
test("loadIocs: a newer cache, however dated, shrunk or edited, cannot remove, soften or duplicate a bundled IOC", () => {
  const bundled = loadIocDir(bundledIocDir);
  const bundledIdx = indexPackages(bundled.packageSets);
  const [someName, someVersions] = Object.entries(bundled.packageSets[0]!.packages)[0]!;
  const cache = writeCache(release("2099-01-01", (f) => {
    f.packages!.sets = [{ id: "tiny", wave: "test", source: "https://example.test/tiny", packages: { [someName]: someVersions } }];
    f.packages!.exclusions = []; // the bundled ones name sets this cache no longer has
    // Every bundled key again, reordered and relabelled or softened, so the cache-first merge order shows too.
    f.files!.hashes = (f.files!.hashes as object[]).map((h) => ({ ...h, name: "renamed.js", wave: "cache" })).reverse();
    f.endpoints!.endpoints = (f.endpoints!.endpoints as object[]).map((e) => ({ ...e, severity: "info" })).reverse();
    f.files!.names = (f.files!.names as object[]).map((n) => ({ ...n, nameOnlySeverity: "info" })).reverse();
    f.repos!.patterns = (f.repos!.patterns as object[]).map((p) => ({ ...p, severity: "info" })).reverse();
    f.repos!.branches = [];
    for (const w of f.workflows!.workflowFiles as { severity: string }[]) w.severity = "info";
    for (const r of f.workflows!.runnerNames as { name: string }[]) r.name = r.name.toLowerCase();
  }));
  const set = loadIocs({ cacheDir: cache });
  assert.equal(set.version, "2099-01-01");
  assert.deepEqual(set.hashes, bundled.hashes);
  assert.deepEqual(set.endpoints, bundled.endpoints);
  assert.deepEqual(set.names, bundled.names);
  assert.deepEqual(set.repoPatterns, bundled.repoPatterns);
  assert.deepEqual(set.branches, bundled.branches);
  assert.deepEqual(set.workflowFiles, bundled.workflowFiles);
  assert.deepEqual(set.runnerNames, bundled.runnerNames);
  assert.equal(indexPackages(set.packageSets).lookup(someName, someVersions[0]!), bundledIdx.lookup(someName, someVersions[0]!));
  for (const s of bundled.packageSets) {
    for (const [n, vs] of Object.entries(s.packages)) for (const v of vs) assert.ok(indexPackages(set.packageSets).lookup(n, v), `${n}@${v}`);
  }
});
test("loadIocs: a stale, unversioned, corrupt or partial cache is ignored with a note", () => {
  const partial = release(NEWER);
  delete partial["repos.json"];
  const cases: [string, Record<string, string>, RegExp][] = [
    ["same version", release(bundledVersion(), (f) => ((f.packages!.sets as { id: string }[])[0]!.id = "from-cache")), /is not newer than the bundled data/],
    ["older", release("2000-01-01", (f) => ((f.packages!.sets as { id: string }[])[0]!.id = "from-cache")), /older than the bundled data/],
    ["unversioned, as written by an older wormsign", fixtureFiles(), /has no version/],
    ["impossible date", release("2026-99-99"), /real YYYY-MM-DD date/],
    ["corrupt", { ...release(NEWER), "packages.json": "{garbage" }, /cannot read IOC file/],
    ["partial", partial, /cannot read IOC file .*repos\.json/],
  ];
  for (const [what, files, why] of cases) {
    const cache = writeCache(files);
    const set = loadIocs({ cacheDir: cache });
    assert.equal(set.version, bundledVersion(), what);
    assert.ok(!set.packageSets.some((s) => s.id === "from-cache" || s.id === "synthetic"), what);
    assert.ok(set.hashes.length >= 20, what);
    assert.ok(set.notes[0]?.startsWith(`ignored the update-iocs cache ${cache}: `), what);
    assert.match(set.notes[0] ?? "", why, what);
    assert.match(set.notes[1] ?? "", /from the bundled data/, what);
  }
});
