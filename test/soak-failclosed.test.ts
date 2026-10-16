import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkSoakLockfiles } from "../src/soak.js";
import { checkSoakConfig, installRegistries, installedVersion } from "../src/soak-config.js";
import { parseLockfileText } from "../src/lockfile/index.js";
import type { ParsedLockfile } from "../src/lockfile/index.js";
import { run } from "../src/main.js";
import { FIXTURES, NOW, fakeIO } from "./helpers.js";

/* Round 2: settings files, manifests, directories and base revisions the gate used to read as "nothing here". */

const H = 3_600_000;

function proj(files: Record<string, string>): string {
  const d = mkdtempSync(join(tmpdir(), "ws-fc-"));
  for (const [k, v] of Object.entries(files)) {
    mkdirSync(join(d, k, ".."), { recursive: true });
    writeFileSync(join(d, k), v);
  }
  return d;
}

const pnpm: ParsedLockfile[] = [{ kind: "pnpm", file: "pnpm-lock.yaml", packages: [] }];
const berry: ParsedLockfile[] = [{ kind: "yarn-berry", file: "yarn.lock", packages: [] }];
const cfg = (files: Record<string, string>, locks: ParsedLockfile[]) =>
  checkSoakConfig(proj(files), locks, { minAgeMs: 72 * H, versionOf: () => ({ version: "99.0.0", source: "stub" }) });
const keys = (fs: { key: string }[]) => fs.map((f) => f.key.replace(/=.*$/s, ""));
const uninterpretable = (fs: { message: string }[]) => fs.some((f) => /could not be interpreted/.test(f.message));

/** A registry where every package is old; records the names asked for. OSV has no record for anything. */
function oldRegistry() {
  const calls: string[] = [];
  const f = (async (url: string | URL, init?: RequestInit) => {
    if (String(url) === "https://api.osv.dev/v1/querybatch") return new Response(JSON.stringify({ results: (JSON.parse(String(init?.body)) as { queries: unknown[] }).queries.map(() => ({})) }));
    const name = decodeURIComponent(String(url).replace("https://registry.npmjs.org/", ""));
    calls.push(name);
    const time = { "1.0.0": new Date(NOW.getTime() - 9000 * H).toISOString() };
    return new Response(JSON.stringify({ name, time, versions: { "1.0.0": { dist: { integrity: "sha512-x" } } } }), { status: 200 });
  }) as typeof fetch;
  return { f, calls };
}

type Out = { findings: { ruleId: string; message: string; severity: string; fingerprint: string; file?: string }[]; notes: string[] };
async function soak(args: string[], env: Record<string, string> = {}, f: typeof fetch = oldRegistry().f) {
  const io = fakeIO({ fetchImpl: f, env: { HOME: mkdtempSync(join(tmpdir(), "ws-home-")), ...env } });
  const code = await run(["soak", ...args, "--format", "json"], io);
  return { code, out: (io.out ? JSON.parse(io.out) : { findings: [], notes: [] }) as Out, err: io.err };
}
const high = (o: Out) => o.findings.filter((x) => x.severity === "high");

/* ---- YAML the reader does not model fails closed ---- */

test("config: pnpm-workspace.yaml spellings pnpm 11.16.0 honours are read or reported, never passed silently", () => {
  const ws = (text: string) => cfg({ "pnpm-workspace.yaml": text }, pnpm);
  // A blank before the colon is still the key (verified: `pnpm config get` reads each of these).
  assert.deepEqual(keys(ws("minimumReleaseAge: 4320\ntrustLockfile : true\n")), ["pnpm:trustLockfile"]);
  assert.deepEqual(keys(ws('minimumReleaseAge: 4320\n"trustLockfile" : true\n')), ["pnpm:trustLockfile"]);
  assert.deepEqual(keys(ws('minimumReleaseAge: 4320\nminimumReleaseAgeExclude : ["*"]\n')), ["pnpm:minimumReleaseAgeExclude"]);
  assert.deepEqual(keys(ws("minimumReleaseAge: 4320\nminimumReleaseAgeStrict\t: false\n")), ["pnpm:minimumReleaseAgeStrict"]);
  // Constructs outside the modelled subset make the whole file a finding.
  const outside: [string, string][] = [
    ["explicit key", "minimumReleaseAge: 4320\n? trustLockfile\n: true\n"],
    ["indented top-level map", "  minimumReleaseAge: 4320\n  trustLockfile: true\n"],
    ["flow top-level map", "{minimumReleaseAge: 4320, trustLockfile: true}\n"],
    ["escaped key", 'minimumReleaseAge: 4320\n"trust\\u004cockfile": true\n'],
    ["merge key (pnpm 11.16.0 reads trustLockfile from it)", "minimumReleaseAge: 4320\n<<: {trustLockfile: true}\n"],
    ["two documents", "minimumReleaseAge: 4320\n---\ntrustLockfile: true\n"],
    ["duplicate key (pnpm rejects the file)", "minimumReleaseAge: 4320\nminimumReleaseAge: 1\n"],
  ];
  for (const [label, text] of outside) assert.ok(uninterpretable(ws(text)), label);
  assert.deepEqual(ws("---\nminimumReleaseAge: 4320 # 3 days\ntrustLockfile: false\n"), [], "positive control: one leading document marker is plain YAML");
});

test("config: .yarnrc.yml: a blank before the colon is read; a duplicate key (Yarn 4.10.3 reads the last) and an escape fail closed, since the subset has neither", () => {
  const rc = (text: string) => cfg({ ".yarnrc.yml": text }, berry);
  assert.deepEqual(keys(rc('npmMinimalAgeGate: 4320\nnpmPreapprovedPackages : ["*"]\n')), ["yarn:npmPreapprovedPackages"]);
  assert.ok(uninterpretable(rc("npmMinimalAgeGate: 4320\nnpmMinimalAgeGate: 1\n")), "Yarn uses the last value, 1");
  assert.ok(uninterpretable(rc("npmMinimalAgeGate: 1\nnpmMinimalAgeGate: 4320\n")), "a duplicate fails closed whichever value is last");
  assert.ok(uninterpretable(rc('npmMinimalAgeGate: 4320\n"npmPreapproved\\u0050ackages": ["*"]\n')));
  assert.deepEqual(rc("npmMinimalAgeGate: 4320\n"), [], "positive control");
  assert.match(rc("")[0]?.message ?? "", /Without it Yarn 4\.10\.3 \(default 0\) installs/, "the default is stated for the version it was verified on");
});

test("config: a lone CR ends a YAML line (pnpm 11.16.0 and Yarn 4.10.3 read the key after it)", () => {
  const ws = (text: string) => keys(cfg({ "pnpm-workspace.yaml": text }, pnpm));
  assert.deepEqual(ws("minimumReleaseAge: 4320\nfoo:\n  bar\rtrustLockfile: true\n"), ["pnpm:trustLockfile"]);
  assert.deepEqual(ws('minimumReleaseAge: 4320\nfoo:\n  bar\rminimumReleaseAgeExclude: ["*"]\n'), ["pnpm:minimumReleaseAgeExclude"]);
  assert.deepEqual(keys(cfg({ ".yarnrc.yml": "logFilters:\n  - level: discard\rnpmMinimalAgeGate: 1\n" }, berry)), ["yarn:npmMinimalAgeGate"]);
});

test("config: a quoted scalar or flow collection left open on its line swallows the next lines, so the file is not interpreted", () => {
  const ws = (text: string) => cfg({ "pnpm-workspace.yaml": text }, pnpm);
  const rc = (text: string) => cfg({ ".yarnrc.yml": text }, berry);
  // Verified: Yarn 4.10.3 reads npmMinimalAgeGate as unset (0) and pnpm 11.16.0 reads minimumReleaseAge as undefined.
  assert.ok(uninterpretable(rc('npmAuthToken: "abc\nnpmMinimalAgeGate: 4320\n  # "\n')), "top-level double quote");
  assert.ok(uninterpretable(ws('catalog:\n  a: "1.0.0\nminimumReleaseAge: 4320\n  # "\n')), "nested double quote");
  assert.ok(uninterpretable(ws("registry: 'https://registry.npmjs.org/\nminimumReleaseAge: 4320\n  # '\n")), "single quote");
  assert.ok(uninterpretable(ws("catalog: {a: 1.0.0,\nminimumReleaseAge: 4320\n  }\n")), "flow map");
  assert.ok(uninterpretable(ws('minimumReleaseAge: 4320\nregistries:\n  "@c\\u006frp": https://npm.corp.example/\n')), "an escape can spell a key the check reads");
  // A quote opened inside brackets is not a closed flow collection, and '' inside an open single-quoted scalar does not close it.
  assert.ok(uninterpretable(ws('onlyBuiltDependencies: [x, "y]\nminimumReleaseAge: 4320\n  # "]\n')), "double quote opened in a flow sequence");
  assert.ok(uninterpretable(ws("onlyBuiltDependencies: [x, 'y]\nminimumReleaseAge: 4320\n  # ']\n")), "single quote opened in a flow sequence");
  // Verified: pnpm 11.16.0 reads minimumReleaseAge as undefined and Yarn 4.10.3 reads npmMinimalAgeGate as 0. The keys
  // holding the quote are ones no check reads, so only the open-quote scan can catch them.
  assert.ok(uninterpretable(ws("catalog:\n  a: 'a''b\nminimumReleaseAge: 4320\nzz: a'\n")), "doubled quote inside an open single-quoted scalar");
  assert.ok(uninterpretable(ws("catalog:\n  a: '''x\nminimumReleaseAge: 4320\nzz: a'\n")), "open single-quoted scalar starting with a doubled quote");
  assert.ok(uninterpretable(rc("logFilters:\n  - text: '''x\nnpmMinimalAgeGate: 4320\nzz: a'\n")), "the same in .yarnrc.yml");
  // Verified: pnpm 11.16.0 reads the key "a#b" and swallows minimumReleaseAge into its value. A '#' starts a comment only after a blank.
  assert.ok(uninterpretable(ws("catalog:\n  a#b: 'c\nminimumReleaseAge: 4320\n  # '\n")), "'#' inside a plain key");
  // YAML whitespace is space and tab only. Verified: pnpm 11.16.0 reads "<U+00A0>#" as a key whose open quote swallows
  // minimumReleaseAge (undefined), and rejects "-<U+00A0>a" (a plain scalar, not a list item) at the key's indentation.
  assert.ok(uninterpretable(ws("catalog:\n \u00a0#: 'x\nminimumReleaseAge: 4320\nzz: a'\n")), "a no-break space does not make a line a comment");
  assert.ok(uninterpretable(ws("catalog:\n-\u00a0a\nminimumReleaseAge: 4320\n")), "a no-break space after '-' does not make a list item");
  const control = 'minimumReleaseAge: 4320\ncatalog:\n  a: "1.0.0"\n  b: \'it\'\'s\'\n  c: [x, {y: "z"}] # "\n  "d\\u0062": "e\\"f"\n  g: it\'s\npackages:\n  - "pkgs/*"\n';
  assert.deepEqual(ws(control), [], "positive control: quotes and flow collections closed on their line, an escape in a key no check reads, a quote inside a word");
  // Verified: pnpm 11.16.0 reads minimumReleaseAge as 4320 after each of these; a bracket opens a collection only where a value starts.
  assert.deepEqual(ws("catalog:\n  a: x [y\nminimumReleaseAge: 4320\n"), [], "positive control: a bracket inside a plain scalar");
  assert.ok(uninterpretable(ws("catalog:\n  a: x, 'y\nminimumReleaseAge: 4320\n")), "a quote after a blank inside a plain scalar is not guessed at: a false positive that fails closed");
});

test("config: a quote inside a plain scalar of a flow collection does not pair with the quote that opens the next entry", () => {
  // Verified: pnpm 11.16.0 reads minimumReleaseAge as undefined, and Yarn 4.10.3 reads npmMinimalAgeGate as 0, for each of
  // these. "a 'b" is a plain scalar, and the quote after ", " opens a scalar that runs on to the next lines.
  for (const rest of ["'c]", "':x]", "']"]) {
    const label = `[a 'b, ${rest}`;
    assert.ok(uninterpretable(cfg({ "pnpm-workspace.yaml": `packages: [a 'b, ${rest}\nminimumReleaseAge: 4320\nzz: a']\n` }, pnpm)), label);
    assert.ok(uninterpretable(cfg({ ".yarnrc.yml": `unsafeHttpWhitelist: [a 'b, ${rest}\nnpmMinimalAgeGate: 4320\nzz: a']\n` }, berry)), label);
  }
  // Verified: pnpm 11.16.0 reads minimumReleaseAge as undefined after an anchor or a JSON-style ":" before an open quote.
  assert.ok(uninterpretable(cfg({ "pnpm-workspace.yaml": "catalog:\n  a: &q 'y\nminimumReleaseAge: 4320\nzz: a'\n" }, pnpm)), "after an anchor");
  assert.ok(uninterpretable(cfg({ "pnpm-workspace.yaml": "catalog: {\"a\":'y}\nminimumReleaseAge: 4320\nzz: a'}\n" }, pnpm)), "after a JSON-style ':'");
  // Verified the same way: whether "- " or "," starts a value depends on what came before it on the line, not on the characters alone.
  assert.ok(uninterpretable(cfg({ "pnpm-workspace.yaml": "packages: [a - 'b, 'c]\nminimumReleaseAge: 4320\nzz: a']\n" }, pnpm)), "' - ' inside a flow plain scalar");
  assert.ok(uninterpretable(cfg({ "pnpm-workspace.yaml": "catalog:\n  x,'y: 'z\nminimumReleaseAge: 4320\nzz: a'\n" }, pnpm)), "',' inside a block plain key");
  assert.ok(uninterpretable(cfg({ "pnpm-workspace.yaml": "packages: [a:'b, 'c]\nminimumReleaseAge: 4320\nzz: a']\n" }, pnpm)), "':' with no blank after it inside a flow plain scalar");
  assert.deepEqual(cfg({ "pnpm-workspace.yaml": "packages: [\"a\",'b', it's, c'd]\nminimumReleaseAge: 4320\n" }, pnpm), [], "positive control");
});

test("config: a key a check reads must be spelled in the subset (one-line scalar, block or one-level flow list, block map); anything else fails closed", () => {
  const ws = (text: string) => cfg({ "pnpm-workspace.yaml": `minimumReleaseAge: 4320\n${text}` }, pnpm);
  const outside: [string, string][] = [
    ["anchor on a scalar", "trustLockfile: &t false\n"],
    ["tag on a scalar", "trustLockfile: !!bool false\n"],
    ["alias as a list", "minimumReleaseAgeExclude: *x\n"],
    ["block scalar where a scalar is expected", "minimumReleaseAgeStrict: |\n  true\n"],
    ["scalar on the next line", "trustLockfile:\n  false\n"],
    ["flow collection nested two levels", "minimumReleaseAgeExclude: [[a]]\n"],
    ["flow collection as a list entry", "minimumReleaseAgeExclude:\n  - [a]\n"],
    ["anchored list entry", "minimumReleaseAgeExclude:\n  - &a lodash\n"],
    ["anchor on a block map", "registries: &r\n  default: https://registry.npmjs.org/\n"],
    ["tag on a block list", "minimumReleaseAgeExclude: !!seq\n  - lodash\n"],
    ["scalar and block list both", "minimumReleaseAgeExclude: x\n  - lodash\n"],
    ["flow list where a map is expected", "registries: ['@corp']\n"],
    ["flow map in registries", "registries: {'@corp': https://npm.corp.example/}\n"],
    ["duplicate key in registries", "registries:\n  default: https://registry.npmjs.org/\n  default: https://npm.corp.example/\n"],
    ["tab indentation in registries", "registries:\n\tdefault: https://npm.corp.example/\n"],
    ["a second document", "---\ntrustLockfile: true\n"],
    ["document end marker", "...\n"],
    ["directive", "%YAML 1.2\n"],
  ];
  for (const [label, text] of outside) assert.ok(uninterpretable(ws(text)), label);
  const bad = ws("trustLockfile: false\n&a x:\n  - y\n");
  assert.match(bad[0]?.message ?? "", /\(a line that is not a simple 'key: value' on line 3\)/, "the lines under a bad line are not credited to the key before it");
  // Keys no check reads are skipped, so YAML features there are not findings.
  const other = "catalog:\n  a: &v 1.0.0\n  b: *v\n  c: !!str x\n  <<: {d: 1}\noverrides: |\n  anything: here\npackages: [[a], {b: c}]\n";
  assert.deepEqual(ws(other), [], "positive control: anchors, aliases, tags, merge keys and block scalars under keys no check reads");
  // Block scalar bodies are not modelled: a quote left open in one is still read as continuing (a false positive that fails closed).
  assert.ok(uninterpretable(ws("overrides: |\n  'tis\n")));
  assert.deepEqual(ws("trustLockfile: false # safe\nminimumReleaseAgeExclude: [] # none\nregistries: {}\n"), [], "positive control: empty flow collections and comments");
});

test("config: ' #' inside a quoted scalar or a comment is not a problem, and a quoted value keeps its ' #'", () => {
  const ws = (text: string) => cfg({ "pnpm-workspace.yaml": `minimumReleaseAge: 4320\n${text}` }, pnpm);
  assert.deepEqual(ws('catalog:\n  a: 1.0.0 # see "issue #12"\n  b: "x #y"\n'), []);
  assert.deepEqual(keys(ws('trustLockfile: "a #b" # c\n')), ["pnpm:trustLockfile"]);
  assert.match(ws('trustLockfile: "a #b" # c\n')[0]?.key ?? "", /="a #b"$/);
  assert.deepEqual(ws("minimumReleaseAgeExclude:\n  - '*' # all\n  - lodash\n").map((f) => f.key), ["pnpm:minimumReleaseAgeExclude=- '*' - lodash"]);
  // pnpm 11.16.0 reads ["a #b"] (verified); a list's line is read as a comment from ' #', which fails closed (no package name has a blank).
  assert.ok(uninterpretable(ws('minimumReleaseAgeExclude: ["a #b"]\n')));
});

test("config: only space and tab are YAML blanks, so a no-break space keeps 'false' from reading as false", () => {
  const ws = (text: string) => cfg({ "pnpm-workspace.yaml": `minimumReleaseAge: 4320\n${text}` }, pnpm);
  // pnpm 11.16.0 reads these as the strings "false<NBSP>" and "<NBSP>false" (verified), and a non-empty string trusts the lockfile.
  assert.deepEqual(keys(ws("trustLockfile: false\u00a0\n")), ["pnpm:trustLockfile"]);
  assert.deepEqual(ws("trustLockfile: \u00a0false\n").map((f) => f.ruleId), ["WS-SK-004"], "a leading no-break space is not a plain scalar this reader models: fails closed");
  assert.ok(uninterpretable(ws("trustLockfile: \u00a0false\n")));
  assert.deepEqual(ws("trustLockfile: false \t\n"), [], "positive control: trailing spaces and tabs are blanks");
});

test("config: the YAML reader is linear on hostile lines (a flow collection 100k deep, quotes, blanks)", () => {
  const n = 500_000;
  const deep = 100_000;
  const hostile = [
    `x: ${"[".repeat(deep)}${"]".repeat(deep)}\n`,
    `x: ${"[".repeat(n)}\n`,
    `x: ${"'a' ".repeat(n / 2)}\n`,
    `x: a${" ".repeat(2 * n)}b\n`,
    `trustLockfile: a${" ".repeat(2 * n)}b\n`,
    `minimumReleaseAgeExclude: [${" ".repeat(2 * n)}x\n`,
    `registries:\n  default: 'a${"''".repeat(n)}\n`,
  ];
  for (const text of hostile) {
    const t = Date.now();
    ws(text);
    assert.ok(Date.now() - t < 1000, `${text.slice(0, 30)}: ${Date.now() - t} ms`);
  }
  function ws(text: string) {
    return cfg({ "pnpm-workspace.yaml": `minimumReleaseAge: 4320\n${text}` }, pnpm);
  }
});

test("cli soak: a baselined 'could not be interpreted' finding fails again when the file changes", async () => {
  const text = "minimumReleaseAge: 10080\ntrustLockfile: &t false\n";
  const d = proj({ "package.json": '{"name":"x","packageManager":"pnpm@11.16.0"}', "pnpm-lock.yaml": "lockfileVersion: '9.0'\n", "pnpm-workspace.yaml": text });
  const args = [d, "--config-only", "--require-config"];
  const first = await soak(args);
  assert.equal(first.code, 1);
  const fp = first.out.findings.find((f) => /could not be interpreted/.test(f.message))?.fingerprint as string;
  writeFileSync(join(d, ".wormsign-baseline.json"), JSON.stringify({ version: 1, entries: [{ fingerprint: fp, justification: "anchor reviewed" }] }));
  assert.equal((await soak(args)).code, 0, "positive control: the reviewed file is baselined");
  // pnpm 11.16.0 reads trustLockfile and minimumReleaseAgeExclude from this merge key (verified).
  writeFileSync(join(d, "pnpm-workspace.yaml"), `${text}<<: {trustLockfile: true, minimumReleaseAgeExclude: ['*']}\n`);
  const edited = await soak(args);
  assert.equal(edited.code, 1);
  assert.match(edited.out.findings.map((f) => f.message).join("\n"), /trustLockfile: a value that is not a one-line scalar on line 2; a line that is not a simple 'key: value' on line 3/, "every problem is listed, in line order");
});

test("installedVersion: the nearest pin in the project or a parent decides; a decoy or broken package.json does not", () => {
  const bin = mkdtempSync(join(tmpdir(), "ws-bin-"));
  writeFileSync(join(bin, "yarn"), "#!/bin/sh\necho 4.18.1\n");
  chmodSync(join(bin, "yarn"), 0o755);
  const root = proj({ ".yarnrc.yml": "yarnPath: .yarn/releases/yarn-4.5.0.cjs\n", "package.json": '{"packageManager":"pnpm@10.0.0"}', "svc/package.json": '{"name":"svc"}' });
  assert.equal(installedVersion("yarn", root, { PATH: bin }, "svc").version, "4.5.0", "Yarn 4.10.3 runs a parent's yarnPath (verified)");
  assert.match(installedVersion("yarn", root, { PATH: bin }, "svc").source, /file name of yarnPath/);
  assert.equal(installedVersion("pnpm", root, {}, "svc").version, "10.0.0", "corepack walks up to the nearest packageManager (verified)");
  const decoy = proj({ "package.json": '{"config":{"packageManager":"pnpm@99.0.0"},"packageManager":"pnpm@9.0.0"}' });
  assert.equal(installedVersion("pnpm", decoy, {}).version, "9.0.0");
  const broken = installedVersion("pnpm", proj({ "package.json": '{"packageManager":"pnpm@99.0.0",' }), {});
  assert.equal(broken.version, undefined);
  assert.match(broken.source, /not valid JSON/);
});

test("cli soak: a nested yarn.lock is checked against the Yarn its parent's yarnPath runs", async () => {
  const d = proj({ ".yarnrc.yml": "yarnPath: .yarn/releases/yarn-4.5.0.cjs\n", "svc/.yarnrc.yml": "npmMinimalAgeGate: 10080\n", "svc/yarn.lock": berryLock("x") });
  const { code, out } = await soak([d, "--config-only", "--require-config"]);
  assert.equal(code, 1);
  assert.match(out.findings.map((f) => f.message).join("\n"), /yarn 4\.5\.0 \(from the file name of yarnPath .*\) ignores it/);
});

test("soak: a pnpm devEngines.runtime binary is not looked up on the npm registry and fails closed on its download site", async () => {
  const text = readFileSync(join(FIXTURES, "lockfiles/protocols/pnpm11-runtime/pnpm-lock.yaml"), "utf8");
  const lock = parseLockfileText("pnpm-lock.yaml", text);
  assert.ok(lock);
  const r = oldRegistry();
  const old = (async (url: string | URL) => {
    const res = await r.f(url);
    const body = (await res.json()) as { time: Record<string, string>; versions: Record<string, unknown> };
    return new Response(JSON.stringify({ time: { "7.0.0": body.time["1.0.0"] }, versions: { "7.0.0": { dist: { integrity: lock.packages[0]?.integrity } } } }), { status: 200 });
  }) as typeof fetch;
  const res = await checkSoakLockfiles([lock], { minAgeMs: 72 * H, registry: "https://registry.npmjs.org", now: NOW, fetchImpl: old });
  assert.deepEqual(r.calls, ["is-number"]);
  assert.ok(res.findings.length > 0 && res.findings.every((f) => f.ruleId === "WS-SK-002" && /node@runtime:22\.11\.0.*nodejs\.org/.test(f.message)), JSON.stringify(res.findings));
  // soak has no list of official download sites (`wormsign scan` does, WS-LK-002), so a runtime named node on any other host must fail closed too.
  const evil = parseLockfileText("pnpm-lock.yaml", text.replace(/https:\/\/[^/\s]+\//g, "https://evil.example/"));
  assert.ok(evil);
  const bad = await checkSoakLockfiles([evil], { minAgeMs: 72 * H, registry: "https://registry.npmjs.org", now: NOW, fetchImpl: old });
  assert.ok(bad.findings.some((f) => f.ruleId === "WS-SK-002" && /node@runtime:22\.11\.0.*evil\.example/.test(f.message)), JSON.stringify(bad.findings));
});

test("cli soak: a symlinked settings file stops the run; a BOM does not hide a .npmrc registry (npm 10.9.2 strips it)", async () => {
  const lock = JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/@corp/secret": { version: "1.0.0", integrity: "sha512-x" } } });
  const outside = proj({ ".npmrc": "@corp:registry=https://npm.corp.example/\n" });
  const linked = proj({ "package-lock.json": lock });
  symlinkSync(join(outside, ".npmrc"), join(linked, ".npmrc"));
  const r = oldRegistry();
  const sym = await soak([linked], {}, r.f);
  assert.equal(sym.code, 2);
  assert.match(sym.err, /cannot read \.npmrc \(it is a symlink\)/);
  const bom = await soak([proj({ "package-lock.json": lock, ".npmrc": "\uFEFF@corp:registry=https://npm.corp.example/\n" })], {}, r.f);
  assert.equal(bom.code, 1);
  assert.deepEqual(r.calls, []);
});

test("config: pnpm 11 reads its global config.yaml last, after the environment and pnpm-workspace.yaml (verified 11.16.0); pnpm 10 is not credited with it", () => {
  const run = (ws: string | undefined, user: string, version = "11.16.0") =>
    checkSoakConfig(proj(ws === undefined ? {} : { "pnpm-workspace.yaml": ws }), pnpm, { minAgeMs: 72 * H, userPnpm: ["~/.config/pnpm/config.yaml", user], versionOf: () => ({ version, source: "stub" }) });
  assert.deepEqual(run(undefined, "minimumReleaseAge: 4320\n"), [], "the global setting counts");
  assert.deepEqual(keys(run("minimumReleaseAge: 10\n", "minimumReleaseAge: 4320\n")), ["pnpm:minimumReleaseAge"], "the workspace file wins");
  assert.deepEqual(run(undefined, "minimumReleaseAge: 4320\ntrustLockfile: true\n").map((f) => f.file), ["~/.config/pnpm/config.yaml"]);
  assert.ok(uninterpretable(run(undefined, "minimumReleaseAge: 4320\n? trustLockfile\n: true\n")));
  assert.deepEqual(keys(run(undefined, "minimumReleaseAge: 4320\n", "10.16.0")), ["pnpm:minimumReleaseAge"], "pnpm 10 does not read config.yaml");
});

test("cli soak: a registry in pnpm's global config.yaml sends no name to --registry", async () => {
  const files = { "pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages:\n  'secret@1.0.0':\n    resolution: {integrity: sha512-x}\n" };
  const xdg = proj({ "pnpm/config.yaml": "registry: https://npm.corp.example/\n" });
  const r = oldRegistry();
  const { code } = await soak([proj(files)], { XDG_CONFIG_HOME: xdg }, r.f);
  assert.equal(code, 1);
  assert.deepEqual(r.calls, []);
  const control = oldRegistry();
  await soak([proj(files)], { XDG_CONFIG_HOME: proj({}) }, control.f);
  assert.deepEqual(control.calls, ["secret"], "positive control");
});

test("installedVersion: yarnPath is read with the same YAML reader (a blank before the colon still pins Yarn)", () => {
  const bin = mkdtempSync(join(tmpdir(), "ws-bin-"));
  writeFileSync(join(bin, "yarn"), "#!/bin/sh\necho 4.18.1\n");
  chmodSync(join(bin, "yarn"), 0o755);
  const d = proj({ ".yarnrc.yml": "yarnPath : .yarn/releases/yarn-4.9.4.cjs\n" });
  assert.equal(installedVersion("yarn", d, { PATH: bin }).version, "4.9.4");
});

const pnpmLock = (name: string) => `lockfileVersion: '9.0'\npackages:\n  '${name}@1.0.0':\n    resolution: {integrity: sha512-x}\n`;
const berryLock = (name: string) => `__metadata:\n  version: 8\n\n"${name}@npm:^1.0.0":\n  version: 1.0.0\n  resolution: "${name}@npm:1.0.0"\n`;

test("cli soak: a registry set in a spelling the reader misses, or in a file it cannot interpret, sends no name to --registry", async () => {
  const cases: [string, Record<string, string>][] = [
    ["blank before the colon", { ".yarnrc.yml": 'npmRegistryServer : "https://npm.corp.example"\n', "yarn.lock": berryLock("secret") }],
    ["duplicate key (Yarn reads the last)", { ".yarnrc.yml": 'npmRegistryServer: "https://registry.npmjs.org"\nnpmRegistryServer: "https://npm.corp.example"\n', "yarn.lock": berryLock("secret") }],
    ["duplicate key, public last (the subset has no duplicates, so it fails closed either way)", { ".yarnrc.yml": 'npmRegistryServer: "https://npm.corp.example"\nnpmRegistryServer: "https://registry.npmjs.org"\n', "yarn.lock": berryLock("secret") }],
    ["scope through an alias", { ".yarnrc.yml": 'npmScopes:\n  corp: &s\n    npmRegistryServer: "https://npm.corp.example"\n  acme: *s\n', "yarn.lock": berryLock("@acme/secret") }],
    ["registry hidden after a lone CR (pnpm 11.16.0 reads it)", { "pnpm-workspace.yaml": "foo:\n  bar\rregistry: https://npm.corp.example/\n", "pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages:\n  'secret@1.0.0':\n    resolution: {integrity: sha512-x}\n" }],
    ["npmRegistryServer hidden after a lone CR (Yarn 4.10.3 reads it)", { ".yarnrc.yml": 'logFilters:\n  - level: discard\rnpmRegistryServer: "https://npm.corp.example"\n', "yarn.lock": berryLock("secret") }],
    ["second scope of a flow npmScopes", { ".yarnrc.yml": 'npmScopes: {a: {npmRegistryServer: "https://registry.npmjs.org"}, corp: {npmRegistryServer: "https://npm.corp.example"}}\n', "yarn.lock": berryLock("@corp/secret") }],
    ["scope server on the next line", { ".yarnrc.yml": 'npmScopes:\n  corp:\n    npmRegistryServer:\n      "https://npm.corp.example"\n', "yarn.lock": berryLock("@corp/secret") }],
    // Verified: Yarn 4.10.3 reads corp's server in each of these four.
    ["' #' in a quoted scalar of a scope's flow map", { ".yarnrc.yml": 'npmScopes:\n  corp: {npmAuthToken: "a #", npmRegistryServer: "https://npm.corp.example"} # c\n', "yarn.lock": berryLock("@corp/secret") }],
    ["' #' in a quoted scalar of a flow npmScopes", { ".yarnrc.yml": 'npmScopes: {corp: {npmAuthToken: "a #", npmRegistryServer: "https://npm.corp.example"}}\n', "yarn.lock": berryLock("@corp/secret") }],
    ["anchor on npmScopes", { ".yarnrc.yml": 'npmScopes: &a\n  corp:\n    npmRegistryServer: "https://npm.corp.example"\n', "yarn.lock": berryLock("@corp/secret") }],
    ["tag on npmScopes", { ".yarnrc.yml": 'npmScopes: !!map\n  corp:\n    npmRegistryServer: "https://npm.corp.example"\n', "yarn.lock": berryLock("@corp/secret") }],
    ["scope server behind an escaped key", { ".yarnrc.yml": 'npmScopes:\n  corp:\n    "npmRegistry\\u0053erver": "https://npm.corp.example"\n', "yarn.lock": berryLock("@corp/secret") }],
    // Verified: Yarn 4.10.3 and pnpm 11.16.0 read an explicit "? " scope key, and pnpm an anchored one.
    ["explicit npmScopes key", { ".yarnrc.yml": 'npmScopes:\n  a:\n    npmRegistryServer: "https://registry.npmjs.org"\n  ? corp\n  : npmRegistryServer: "https://npm.corp.example"\n', "yarn.lock": berryLock("@corp/secret") }],
    ["explicit registries key", { "pnpm-workspace.yaml": "registries:\n  default: https://registry.npmjs.org/\n  ? '@corp'\n  : https://npm.corp.example/\n", "pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages:\n  '@corp/secret@1.0.0':\n    resolution: {integrity: sha512-x}\n" }],
    ["anchored registries key", { "pnpm-workspace.yaml": "registries:\n  default: https://registry.npmjs.org/\n  &a '@corp': https://npm.corp.example/\n", "pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages:\n  '@corp/secret@1.0.0':\n    resolution: {integrity: sha512-x}\n" }],
    // Verified: as a later entry, Yarn 4.10.3 reads corp's server and pnpm 11.16.0 reads default from each of these.
    ["anchored npmScopes key, unquoted", { ".yarnrc.yml": 'npmScopes:\n  a:\n    npmAuthToken: x\n  &k corp:\n    npmRegistryServer: "https://npm.corp.example"\n', "yarn.lock": berryLock("@corp/secret") }],
    ["tagged npmScopes key", { ".yarnrc.yml": 'npmScopes:\n  a:\n    npmAuthToken: x\n  !!str corp:\n    npmRegistryServer: "https://npm.corp.example"\n', "yarn.lock": berryLock("@corp/secret") }],
    ["anchored registries default", { "pnpm-workspace.yaml": "registries:\n  '@x': https://registry.npmjs.org/\n  &a default: https://npm.corp.example/\n", "pnpm-lock.yaml": pnpmLock("secret") }],
    ["tagged registries default", { "pnpm-workspace.yaml": "registries:\n  '@x': https://registry.npmjs.org/\n  !!str default: https://npm.corp.example/\n", "pnpm-lock.yaml": pnpmLock("secret") }],
    // Verified: pnpm 11.16.0 reads a merge key inside registries.
    ["merge key in registries, scope", { "pnpm-workspace.yaml": "registries:\n  <<: {'@corp': https://npm.corp.example/}\n", "pnpm-lock.yaml": pnpmLock("@corp/secret") }],
    ["merge key in registries, default", { "pnpm-workspace.yaml": "registries:\n  <<: {default: https://npm.corp.example/}\n", "pnpm-lock.yaml": pnpmLock("secret") }],
    ["uninterpretable pnpm-workspace.yaml", { "pnpm-workspace.yaml": "? registry\n: https://npm.corp.example\n", "pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages:\n  'secret@1.0.0':\n    resolution: {integrity: sha512-x}\n" }],
  ];
  for (const [label, files] of cases) {
    const r = oldRegistry();
    const { code, out } = await soak([proj(files)], {}, r.f);
    assert.deepEqual(r.calls, [], label);
    assert.equal(code, 1, label);
    assert.ok(high(out).some((f) => f.ruleId === "WS-SK-002"), label);
  }
  const control = oldRegistry();
  await soak([proj({ ".yarnrc.yml": 'npmRegistryServer: "https://registry.npmjs.org" # public\n', "yarn.lock": berryLock("secret") })], {}, control.f);
  assert.deepEqual(control.calls, ["secret"], "positive control: a public registry is checked");
  const scoped = oldRegistry();
  await soak([proj({ ".yarnrc.yml": 'npmScopes:\n  corp:\n    npmRegistryServer: "https://registry.npmjs.org"\n', "yarn.lock": berryLock("@corp/secret") })], {}, scoped.f);
  assert.deepEqual(scoped.calls, ["@corp/secret"], "positive control: a scope on the public registry is checked");
});

test("installRegistries: pnpm registries keys are read as pnpm reads them ('' is a quote; a key that is neither default nor @scope is never used)", () => {
  const d = proj({ "pnpm-workspace.yaml": "registries:\n  default: 'https://npm.corp.example/a''b'\n  corp: https://other.example/\n" });
  const got = installRegistries(d, { kind: "pnpm", file: "pnpm-lock.yaml", packages: [] }, {});
  assert.deepEqual(got.map((r) => [r.scope, r.url]), [["", "https://npm.corp.example/a'b"]]);
});

/* ---- a baseline approves one value ---- */

test("cli soak: a baselined config finding fails again when the value changes (a reviewed exclusion does not approve '*')", async () => {
  const files = (exclude: string) => ({
    "package.json": '{"name":"x","packageManager":"pnpm@11.16.0"}',
    "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "pnpm-workspace.yaml": `minimumReleaseAge: 10080\nminimumReleaseAgeExclude:\n  - ${exclude}\n`,
  });
  const d = proj(files("internal-lib"));
  const args = [d, "--config-only", "--require-config"];
  const first = await soak(args);
  assert.equal(first.code, 1);
  const fp = first.out.findings.find((f) => /minimumReleaseAgeExclude/.test(f.message))?.fingerprint as string;
  writeFileSync(join(d, ".wormsign-baseline.json"), JSON.stringify({ version: 1, entries: [{ fingerprint: fp, justification: "internal-lib is ours" }] }));
  assert.equal((await soak(args)).code, 0, "positive control: the reviewed exclusion is baselined");
  writeFileSync(join(d, "pnpm-workspace.yaml"), files('"*"')["pnpm-workspace.yaml"]);
  assert.equal((await soak(args)).code, 1);
});

test("config: age and version findings are keyed on the value, so a baselined 1 day does not also approve 1 minute", () => {
  const age = (v: string) => cfg({ "pnpm-workspace.yaml": `minimumReleaseAge: ${v}\n` }, pnpm).map((f) => f.key);
  assert.deepEqual(age("1440"), ["pnpm:minimumReleaseAge=1440 minutes"]);
  assert.notDeepEqual(age("1440"), age("1"));
  const ver = (version: string) =>
    checkSoakConfig(proj({ ".npmrc": "min-release-age=3\n" }), [{ kind: "npm", file: "package-lock.json", packages: [] }], { minAgeMs: 72 * H, versionOf: () => ({ version, source: "stub" }) }).map((f) => f.key);
  assert.deepEqual(ver("10.9.2"), ["npm:version=10.9.2"]);
});

/* ---- lockfile discovery ---- */

test("cli soak: a missing root or a root that is a file is a usage error, not 'nothing to verify'", async () => {
  const d = proj({ "f.txt": "x" });
  assert.equal((await soak([join(d, "nope")])).code, 2);
  assert.equal((await soak([join(d, "f.txt")])).code, 2);
});

test("cli soak: a directory that cannot be listed is a finding", async (t) => {
  const d = proj({ "svc/package.json": '{"dependencies":{"young":"1.0.0"}}', "svc/package-lock.json": "{}" });
  chmodSync(join(d, "svc"), 0o000);
  t.after(() => chmodSync(join(d, "svc"), 0o755));
  const { code, out } = await soak([d]);
  assert.equal(code, 1);
  assert.match(high(out).find((f) => f.file === "svc")?.message ?? "", /could not be listed/);
});

test("cli soak: a symlinked directory is reported, not skipped", async () => {
  const elsewhere = proj({ "package.json": '{"dependencies":{"young":"1.0.0"}}' });
  const d = proj({});
  symlinkSync(elsewhere, join(d, "svc"));
  const { code, out } = await soak([d]);
  assert.equal(code, 1);
  assert.match(high(out).find((f) => f.file === "svc")?.message ?? "", /symlinked directory/);
});

test("cli soak: package.json declares dependencies through peerDependencies too (npm 7+ installs them)", async () => {
  const { code, out } = await soak([proj({ "package.json": '{"peerDependencies":{"is-number":"7.0.0"}}' })]);
  assert.equal(code, 1);
  assert.match(high(out)[0]?.message ?? "", /declares dependencies but there is no lockfile/);
});

test("cli soak: a large, invalid or unreadable package.json is a finding, not 'no dependencies'", async (t) => {
  const big = `{"dependencies":{"young":"1.0.0"},"description":"${"x".repeat(3_000_000)}"}`;
  const large = await soak([proj({ "package.json": big })]);
  assert.equal(large.code, 1, "over the scanner's 2 MB text cap");
  assert.match(high(large.out)[0]?.message ?? "", /declares dependencies but there is no lockfile/);
  for (const bad of ['{"dependencies":', '{"dependencies":{"young":"1.0.0"}}\u0000', "[]"]) {
    const { code, out } = await soak([proj({ "package.json": bad })]);
    assert.equal(code, 1, JSON.stringify(bad));
    assert.match(high(out)[0]?.message ?? "", /not a valid JSON object/);
  }
  const d = proj({ "package.json": '{"dependencies":{"young":"1.0.0"}}' });
  chmodSync(join(d, "package.json"), 0o000);
  t.after(() => chmodSync(join(d, "package.json"), 0o644));
  const unreadable = await soak([d]);
  assert.equal(unreadable.code, 1);
  assert.match(high(unreadable.out)[0]?.message ?? "", /could not be read/);
});

test("cli soak: an unreadable user .npmrc stops the run instead of reading as absent", async (t) => {
  const home = mkdtempSync(join(tmpdir(), "ws-home-"));
  writeFileSync(join(home, ".npmrc"), "@corp:registry=https://npm.corp.example/\n");
  chmodSync(join(home, ".npmrc"), 0o000);
  t.after(() => chmodSync(join(home, ".npmrc"), 0o644));
  const lock = JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/@corp/secret": { version: "1.0.0", integrity: "sha512-x" } } });
  const r = oldRegistry();
  const { code, err } = await soak([proj({ "package-lock.json": lock })], { HOME: home }, r.f);
  assert.equal(code, 2);
  assert.match(err, /cannot read .*\.npmrc/);
  assert.deepEqual(r.calls, []);
});

/* ---- versionless entries ---- */

test("soak: a lockfile entry with no version is unverifiable, not skipped (npm ci installs it for a '*' spec)", async () => {
  const lock: ParsedLockfile = {
    kind: "npm",
    file: "package-lock.json",
    packages: [
      { name: "old", version: "1.0.0", integrity: "sha512-x" },
      { name: "young", version: "", resolved: "https://registry.npmjs.org/young/-/young-1.0.0.tgz", integrity: "sha512-y" },
    ],
  };
  const r = oldRegistry();
  const res = await checkSoakLockfiles([lock], { minAgeMs: 72 * H, registry: "https://registry.npmjs.org", now: NOW, fetchImpl: r.f });
  assert.deepEqual(r.calls, ["old"]);
  assert.deepEqual(res.findings.map((f) => f.ruleId), ["WS-SK-002"]);
  assert.match(res.findings[0]?.message ?? "", /young@: the lockfile entry has no version/);
});

/* ---- --base is a git revision, never a directory the change could add ---- */

function git(cwd: string, ...args: string[]) {
  execFileSync("git", ["-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...args], { cwd, stdio: "ignore" });
}
const npmLock = (pkgs: string[]) =>
  JSON.stringify({ lockfileVersion: 3, packages: Object.fromEntries([["", {}], ...pkgs.map((n) => [`node_modules/${n}`, { version: "1.0.0", resolved: `https://registry.npmjs.org/${n}/-/${n}-1.0.0.tgz`, integrity: "sha512-x" }])]) });

test("cli soak: a directory named like the --base revision cannot stand in for the base lockfile or baseline", async (t) => {
  const repo = proj({ "package-lock.json": npmLock(["old"]) });
  git(repo, "init", "-q");
  git(repo, "add", ".");
  git(repo, "commit", "-qm", "base");
  git(repo, "branch", "base");
  // The PR: a young dependency, plus a directory "base/" holding a copy of its own lock and a baseline for it.
  writeFileSync(join(repo, "package-lock.json"), npmLock(["old", "young"]));
  mkdirSync(join(repo, "base"));
  writeFileSync(join(repo, "base", "package-lock.json"), npmLock(["old", "young"]));
  const r = oldRegistry();
  const young = (async (url: string | URL, init?: RequestInit) =>
    String(url).endsWith("/young")
      ? new Response(JSON.stringify({ time: { "1.0.0": new Date(NOW.getTime() - H).toISOString() }, versions: { "1.0.0": { dist: { integrity: "sha512-x" } } } }), { status: 200 })
      : r.f(url, init)) as typeof fetch;
  const first = await soak([repo], {}, young);
  const fp = first.out.findings.find((f) => f.ruleId === "WS-SK-001")?.fingerprint as string;
  writeFileSync(join(repo, "base", ".wormsign-baseline.json"), JSON.stringify({ version: 1, entries: [{ fingerprint: fp, justification: "forged by the PR" }] }));
  const cwd = process.cwd();
  process.chdir(repo);
  t.after(() => process.chdir(cwd));
  const { code, out } = await soak([".", "--base", "base"], {}, young);
  assert.equal(code, 1);
  assert.deepEqual(high(out).map((f) => f.ruleId), ["WS-SK-001"]);
  assert.match(out.notes.join("\n"), /baseline read from base/);
});

test("cli soak --base: a version the base locked (and baselined) in one lockfile is checked when a change adds it to another", async (t) => {
  const repo = proj({ "package-lock.json": npmLock(["old"]), "docs/package-lock.json": npmLock(["young"]) });
  const r = oldRegistry();
  const young = (async (url: string | URL, init?: RequestInit) =>
    String(url).endsWith("/young")
      ? new Response(JSON.stringify({ time: { "1.0.0": new Date(NOW.getTime() - H).toISOString() }, versions: { "1.0.0": { dist: { integrity: "sha512-x" } } } }), { status: 200 })
      : r.f(url, init)) as typeof fetch;
  const first = await soak([repo], {}, young);
  const docs = first.out.findings.filter((f) => f.ruleId === "WS-SK-001");
  assert.deepEqual(docs.map((f) => f.file), ["docs/package-lock.json"]);
  writeFileSync(join(repo, ".wormsign-baseline.json"), JSON.stringify({ version: 1, entries: [{ fingerprint: docs[0]!.fingerprint, justification: "docs site build only, reviewed" }] }));
  git(repo, "init", "-q");
  git(repo, "add", ".");
  git(repo, "commit", "-qm", "base");
  // The change: the same young version, now in the lockfile that is installed.
  writeFileSync(join(repo, "package-lock.json"), npmLock(["old", "young"]));
  const cwd = process.cwd();
  process.chdir(repo);
  t.after(() => process.chdir(cwd));
  const { code, out } = await soak([".", "--base", "HEAD", "--min-age", "72h"], {}, young);
  assert.equal(code, 1);
  assert.deepEqual(high(out).map((f) => `${f.ruleId} ${f.file}`), ["WS-SK-001 package-lock.json"], out.notes.join("\n"));
  // Control: the base's own copy of the docs lockfile still counts as unchanged.
  assert.ok(out.notes.includes("2 unchanged package(s) not checked (PR mode)"), out.notes.join("\n"));
});
