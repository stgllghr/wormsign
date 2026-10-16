import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, parse } from "node:path";
import { checkSoakConfig, installedVersion } from "../src/soak-config.js";
import type { ConfigOptions, TreeInputs } from "../src/soak-config.js";
import type { ParsedLockfile } from "../src/lockfile/index.js";
import { run } from "../src/main.js";
import { NOW, fakeIO } from "./helpers.js";

/* Where settings come from: environment variables, YAML spellings, parent and user files, registries, lockfile discovery. */

const H = 3_600_000;

function proj(files: Record<string, string>): string {
  const d = mkdtempSync(join(tmpdir(), "ws-src-"));
  for (const [k, v] of Object.entries(files)) {
    mkdirSync(join(d, k, ".."), { recursive: true });
    writeFileSync(join(d, k), v);
  }
  return d;
}

const pnpm: ParsedLockfile[] = [{ kind: "pnpm", file: "pnpm-lock.yaml", packages: [] }];
const berry = (file = "yarn.lock"): ParsedLockfile[] => [{ kind: "yarn-berry", file, packages: [] }];
const cfg = (root: string, locks: ParsedLockfile[], extra: Partial<Omit<ConfigOptions, keyof TreeInputs>> = {}) =>
  checkSoakConfig(root, locks, { minAgeMs: 72 * H, versionOf: () => ({ version: "99.0.0", source: "stub" }), ...extra });
/** Finding keys without the value part, which every config key carries after "=". */
const keys = (fs: { key: string }[]) => fs.map((f) => f.key.replace(/=.*$/s, ""));

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
async function soak(dir: string, env: Record<string, string> = {}, f: typeof fetch = oldRegistry().f) {
  const io = fakeIO({ fetchImpl: f, env: { HOME: mkdtempSync(join(tmpdir(), "ws-home-")), ...env } });
  const code = await run(["soak", dir, "--format", "json"], io);
  return { code, out: JSON.parse(io.out) as Out };
}
const high = (o: Out) => o.findings.filter((x) => x.severity === "high");

/* ---- installedVersion never runs in a writable shared directory ---- */

test("installedVersion: the binary runs from the filesystem root with yarnPath ignored, never from TMPDIR where anyone can plant .yarnrc.yml", () => {
  const shared = mkdtempSync(join(tmpdir(), "ws-shared-"));
  mkdirSync(join(shared, "sub"));
  writeFileSync(join(shared, ".yarnrc.yml"), "yarnPath: ./pwn.cjs\n");
  const bin = mkdtempSync(join(tmpdir(), "ws-bin-"));
  writeFileSync(join(bin, "yarn"), `#!/bin/sh\npwd > "${bin}/cwd"\necho "$YARN_IGNORE_PATH" > "${bin}/ignore"\necho 1.22.22\n`);
  chmodSync(join(bin, "yarn"), 0o755);
  const saved = process.env["TMPDIR"];
  process.env["TMPDIR"] = join(shared, "sub");
  try {
    assert.equal(installedVersion("yarn", proj({}), { PATH: bin }).version, "1.22.22");
  } finally {
    if (saved === undefined) delete process.env["TMPDIR"];
    else process.env["TMPDIR"] = saved;
  }
  assert.equal(readFileSync(join(bin, "cwd"), "utf8").trim(), parse(process.cwd()).root, "no parent directory anyone else can write to");
  assert.equal(readFileSync(join(bin, "ignore"), "utf8").trim(), "1");
});

/* ---- YAML spellings pnpm and Yarn honour ---- */

test("config: pnpm bypass settings are caught in plain, quoted and block-sequence spellings (verified with pnpm 11.16.0), and only the safe values pass", () => {
  const ws = (extra: string) => cfg(proj({ "pnpm-workspace.yaml": `minimumReleaseAge: 4320\n${extra}` }), pnpm);
  assert.deepEqual(keys(ws("trustLockfile: True\n")), ["pnpm:trustLockfile"]);
  assert.deepEqual(keys(ws("trustLockfile: \"false\"\n")), ["pnpm:trustLockfile"], "a quoted string is not the boolean false");
  assert.deepEqual(keys(ws("minimumReleaseAgeStrict: False\n")), ["pnpm:minimumReleaseAgeStrict"]);
  assert.deepEqual(keys(ws('"minimumReleaseAgeExclude": ["*"]\n')), ["pnpm:minimumReleaseAgeExclude"]);
  assert.deepEqual(keys(ws('minimumReleaseAgeExclude:\n- "*"\n')), ["pnpm:minimumReleaseAgeExclude"], "a sequence at the key's own indentation");
  assert.deepEqual(keys(ws('minimumReleaseAgeExclude:\n\n  # why\n  - "*"\n')), ["pnpm:minimumReleaseAgeExclude"], "blank and comment lines inside the block");
  assert.deepEqual(ws("trustLockfile: FALSE\nminimumReleaseAgeStrict: true\nminimumReleaseAgeExclude: null\n"), [], "safe values are not findings");
  const quoted = cfg(proj({ "pnpm-workspace.yaml": '"minimumReleaseAge": 1\n' }), pnpm);
  assert.match(quoted[0]?.message ?? "", /minimumReleaseAge = 1 minutes is .* shorter/, "a quoted key is read, not reported as missing");
});

test("config: Yarn's npmPreapprovedPackages is caught as a column-0 sequence (verified with Yarn 4.10.3)", () => {
  assert.deepEqual(keys(cfg(proj({ ".yarnrc.yml": 'npmMinimalAgeGate: 4320\nnpmPreapprovedPackages:\n- "*"\n' }), berry())), ["yarn:npmPreapprovedPackages"]);
});

/* ---- environment variables and other files override the project's ---- */

test("config: pnpm 11 reads pnpm_config_* over pnpm-workspace.yaml; pnpm 10 reads npm_config_* under it (verified 11.16.0, 10.16.0)", () => {
  const d = proj({ "pnpm-workspace.yaml": "minimumReleaseAge: 4320\n" });
  const lowered = cfg(d, pnpm, { env: { pnpm_config_minimum_release_age: "0" } });
  assert.equal(lowered[0]?.ruleId, "WS-SK-004");
  assert.match(lowered[0]?.message ?? "", /^environment variable pnpm_config_minimum_release_age: minimumReleaseAge = 0 minutes/);
  assert.deepEqual(keys(cfg(d, pnpm, { env: { PNPM_CONFIG_TRUST_LOCKFILE: "true" } })), ["pnpm:trustLockfile"]);
  assert.deepEqual(cfg(d, pnpm, { env: { npm_config_minimum_release_age: "0" } }), [], "pnpm 11 ignores npm_config_minimum_release_age");
  const v10 = { versionOf: () => ({ version: "10.16.0", source: "stub" }) };
  assert.deepEqual(cfg(d, pnpm, { ...v10, env: { npm_config_minimum_release_age: "0" } }), [], "pnpm 10: the file wins over the environment");
  assert.match(cfg(proj({}), pnpm, { ...v10, env: { npm_config_minimum_release_age: "0" } })[0]?.message ?? "", /environment variable npm_config_minimum_release_age/);
});

test("config: Yarn reads YARN_* variables over every file, parent .yarnrc.yml files, and the user's (verified, Yarn 4.10.3)", () => {
  const d = proj({ "app/.yarnrc.yml": "npmMinimalAgeGate: 4320\n" });
  const env = cfg(d, berry("app/yarn.lock"), { env: { YARN_NPM_MINIMAL_AGE_GATE: "0" } });
  assert.match(env[0]?.message ?? "", /^environment variable YARN_NPM_MINIMAL_AGE_GATE: npmMinimalAgeGate = 0 minutes/);
  assert.deepEqual(keys(cfg(d, berry("app/yarn.lock"), { env: { yarn_npm_preapproved_packages: "*" } })), ["yarn:npmPreapprovedPackages"]);
  const parent = proj({ "app/.yarnrc.yml": "npmMinimalAgeGate: 4320\n", ".yarnrc.yml": "npmPreapprovedPackages: ['*']\nnpmMinimalAgeGate: 1\n" });
  const p = cfg(parent, berry("app/yarn.lock"));
  assert.deepEqual(p.map((f) => `${f.key} ${f.file}`), ["yarn:npmPreapprovedPackages=['*'] .yarnrc.yml"], "the parent's list counts; the nearer gate wins over the parent's");
  const user = cfg(proj({}), berry(), { userYarnrc: "npmMinimalAgeGate: 4320\n" });
  assert.deepEqual(user, [], "a gate in ~/.yarnrc.yml applies");
});

/* ---- private registries: names never reach --registry ---- */

const noResolved = (name: string) => JSON.stringify({ lockfileVersion: 3, packages: { "": {}, [`node_modules/${name}`]: { version: "1.0.0", integrity: "sha512-x" } } });

test("cli soak: registry settings are read the way the package manager reads them, so private names never reach --registry", async () => {
  const cases: [string, Record<string, string>, Record<string, string>][] = [
    ["inline comment (npm prints the URL without it)", { ".npmrc": "@corp:registry=https://npm.corp.example/ ; private\n", "package-lock.json": noResolved("@corp/secret") }, {}],
    ["nested project's own .npmrc", { "svc/.npmrc": "@corp:registry=https://npm.corp.example/\n", "svc/package-lock.json": noResolved("@corp/secret") }, {}],
    ["npm_config_@scope:registry", { "package-lock.json": noResolved("@corp/secret") }, { "npm_config_@corp:registry": "https://npm.corp.example/" }],
    ["pnpm-workspace.yaml registries", { "pnpm-workspace.yaml": 'registries:\n  "@corp": https://npm.corp.example/\n', "pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages:\n  '@corp/secret@1.0.0':\n    resolution: {integrity: sha512-x}\n" }, {}],
    ["parent .yarnrc.yml npmRegistryServer", { ".yarnrc.yml": 'npmRegistryServer: "https://npm.corp.example"\n', "app/yarn.lock": '__metadata:\n  version: 8\n\n"secret@npm:^1.0.0":\n  version: 1.0.0\n  resolution: "secret@npm:1.0.0"\n' }, {}],
    ["Yarn npmScopes", { ".yarnrc.yml": "npmScopes:\n  corp:\n    npmRegistryServer: https://npm.corp.example\n", "yarn.lock": '__metadata:\n  version: 8\n\n"@corp/secret@npm:^1.0.0":\n  version: 1.0.0\n  resolution: "@corp/secret@npm:1.0.0"\n' }, {}],
    ["YARN_NPM_REGISTRY_SERVER", { "yarn.lock": '__metadata:\n  version: 8\n\n"secret@npm:^1.0.0":\n  version: 1.0.0\n  resolution: "secret@npm:1.0.0"\n' }, { YARN_NPM_REGISTRY_SERVER: "https://npm.corp.example" }],
  ];
  for (const [label, files, env] of cases) {
    const r = oldRegistry();
    const { code, out } = await soak(proj(files), env, r.f);
    assert.deepEqual(r.calls, [], `${label}: no name sent to the public registry`);
    assert.equal(code, 1, label);
    assert.match(high(out).find((f) => f.ruleId === "WS-SK-002")?.message ?? "", /installs .* from https:\/\/npm\.corp\.example/, label);
  }
  const control = oldRegistry();
  assert.equal((await soak(proj({ "package-lock.json": noResolved("@corp/secret") }), {}, control.f)).code, 0, "positive control: unconfigured scopes are checked");
  assert.deepEqual(control.calls, ["@corp/secret"]);
});

test("cli soak: an artifact locked in two projects is checked against each project's registry settings", async () => {
  const d = proj({ "package-lock.json": noResolved("plain"), "svc/package-lock.json": noResolved("plain"), "svc/.npmrc": "registry=https://npm.corp.example/\n" });
  const { code, out } = await soak(d);
  assert.equal(code, 1);
  assert.deepEqual(high(out).map((f) => f.file), ["svc/package-lock.json"]);
});

/* ---- a baseline approves one artifact, not a name ---- */

const gitLock = (repo: string) =>
  JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/gitdep": { version: "1.0.0", resolved: `git+ssh://git@github.com/${repo}` } } });

test("cli soak: a baselined git dependency fails again when its source changes", async () => {
  const d = proj({ "package-lock.json": gitLock(`a/b.git#${"1".repeat(40)}`) });
  const first = await soak(d);
  assert.equal(first.code, 1);
  const fp = first.out.findings.find((f) => f.ruleId === "WS-SK-002")?.fingerprint as string;
  writeFileSync(join(d, ".wormsign-baseline.json"), JSON.stringify({ version: 1, entries: [{ fingerprint: fp, justification: `reviewed commit ${"1".repeat(40)}` }] }));
  assert.equal((await soak(d)).code, 0, "positive control: the reviewed source is baselined");
  for (const swapped of [`a/b.git#${"2".repeat(40)}`, `attacker/evil.git#${"1".repeat(40)}`]) {
    writeFileSync(join(d, "package-lock.json"), gitLock(swapped));
    assert.equal((await soak(d)).code, 1, swapped);
  }
});

test("cli soak: a baselined lockfile problem does not hide a different problem with the same file", async () => {
  const real = proj({ "package-lock.json": noResolved("plain") });
  const d = proj({});
  symlinkSync(join(real, "package-lock.json"), join(d, "package-lock.json"));
  const first = await soak(d);
  const fp = first.out.findings.find((f) => /symlink/.test(f.message))?.fingerprint as string;
  writeFileSync(join(d, ".wormsign-baseline.json"), JSON.stringify({ version: 1, entries: [{ fingerprint: fp, justification: "vendored lockfile, reviewed" }] }));
  assert.equal((await soak(d)).code, 0, "positive control");
  rmSync(join(d, "package-lock.json"));
  writeFileSync(join(d, "package-lock.json"), "{ not json");
  assert.equal((await soak(d)).code, 1);
});

/* ---- lockfile discovery ---- */

test("cli soak: a package.json with dependencies needs a lockfile in its directory or a parent, whatever other lockfiles exist", async () => {
  const d = proj({ "package.json": '{"dependencies":{"left-pad":"^1"}}', "test/fixture/package-lock.json": noResolved("plain") });
  const { code, out } = await soak(d);
  assert.equal(code, 1);
  assert.match(high(out)[0]?.message ?? "", /packages in package.json: it declares dependencies but there is no lockfile/);
  assert.equal((await soak(proj({ "package.json": '{"dependencies":{"plain":"^1"}}', "package-lock.json": noResolved("plain"), "svc/package.json": '{"dependencies":{"plain":"^1"}}' }))).code, 0, "a workspace member uses the root lockfile");
});

test("cli soak: symlinked lockfiles and manifests are reported even in a directory with no regular files", async () => {
  const real = proj({ "lock.json": noResolved("plain"), "package.json": '{"dependencies":{"plain":"^1"}}' });
  const d = proj({ "package.json": '{"name":"root"}' });
  mkdirSync(join(d, "svc"));
  symlinkSync(join(real, "lock.json"), join(d, "svc", "package-lock.json"));
  symlinkSync(join(real, "package.json"), join(d, "svc", "package.json"));
  const { code, out } = await soak(d);
  assert.equal(code, 1);
  assert.deepEqual(high(out).map((f) => f.file).sort(), ["svc/package-lock.json", "svc/package.json"]);
  assert.ok(high(out).every((f) => /symlink/.test(f.message)));
});
