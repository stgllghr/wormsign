/**
 * The vendored TOML parser (src/vendor/smol-toml/): offline checks that the copy is the one VENDORED.json records,
 * that the build ships it unchanged, that the licence travels with it, and that the 1.9.0 behaviours the Python readers
 * rely on (docs/architecture.md) still hold. scripts/verify-vendor.mjs re-derives the copy from the npm tarball
 * (network; CI runs it on every change and monthly).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse, TomlDate, TomlError } from "../src/vendor/smol-toml/index.js";

const ROOT = join(import.meta.dirname, "..", "..");
const VENDOR = join(ROOT, "src", "vendor", "smol-toml");

interface Record_ {
  package: string;
  version: string;
  license: string;
  tarball: string;
  integrity: string;
  upstream: { repository: string; ref: string; commit: string; provenance: string };
  files: Record<string, string>;
}
const record = JSON.parse(readFileSync(join(VENDOR, "VENDORED.json"), "utf8")) as Record_;
const sha256 = (b: Buffer): string => createHash("sha256").update(b).digest("hex");

test("vendor: every vendored file has the sha256 VENDORED.json records, and nothing else is there", () => {
  assert.equal(record.package, "smol-toml");
  assert.equal(record.version, "1.9.0");
  assert.equal(record.license, "BSD-3-Clause");
  assert.equal(record.tarball, "https://registry.npmjs.org/smol-toml/-/smol-toml-1.9.0.tgz");
  assert.match(record.integrity, /^sha512-[A-Za-z0-9+/]{86}==$/);
  assert.equal(record.upstream.repository, "https://github.com/squirrelchat/smol-toml");
  assert.equal(record.upstream.ref, "refs/tags/v1.9.0");
  assert.match(record.upstream.commit, /^[0-9a-f]{40}$/);
  assert.deepEqual(readdirSync(join(VENDOR, "..")), ["smol-toml"], "src/vendor holds nothing but smol-toml");
  const present = readdirSync(VENDOR).filter((f) => f !== "VENDORED.json").sort();
  assert.deepEqual(present, Object.keys(record.files).sort());
  assert.ok(present.includes("LICENSE") && present.includes("index.js") && present.includes("parse.js"));
  for (const f of present) assert.equal(sha256(readFileSync(join(VENDOR, f))), record.files[f], f);
});

test("vendor: the build ships the vendored .js, LICENSE and VENDORED.json byte-identical", () => {
  const dist = join(ROOT, "dist", "src", "vendor", "smol-toml");
  const shipped = readdirSync(dist).sort();
  assert.deepEqual(shipped, [...Object.keys(record.files).filter((f) => f.endsWith(".js") || f === "LICENSE"), "VENDORED.json"].sort());
  for (const f of shipped) assert.ok(readFileSync(join(dist, f)).equals(readFileSync(join(VENDOR, f))), f);
});

test("vendor: copy-vendor refuses an edited, added or removed file, and copies an intact one", () => {
  const run = (dir: string): { status: number | null; err: string } => {
    const r = spawnSync(process.execPath, [join(dir, "scripts", "copy-vendor.mjs")], { encoding: "utf8" });
    return { status: r.status, err: r.stderr };
  };
  const fresh = (): string => {
    const d = mkdtempSync(join(tmpdir(), "ws-vendor-"));
    mkdirSync(join(d, "scripts"));
    cpSync(join(ROOT, "scripts", "copy-vendor.mjs"), join(d, "scripts", "copy-vendor.mjs"));
    cpSync(VENDOR, join(d, "src", "vendor", "smol-toml"), { recursive: true });
    return d;
  };
  const ok = fresh();
  assert.equal(run(ok).status, 0);
  assert.ok(existsSync(join(ok, "dist", "src", "vendor", "smol-toml", "parse.js")));
  assert.ok(!existsSync(join(ok, "dist", "src", "vendor", "smol-toml", "parse.d.ts")));

  const edited = fresh();
  writeFileSync(join(edited, "src", "vendor", "smol-toml", "parse.js"), readFileSync(join(VENDOR, "parse.js"), "utf8") + "\n// edited\n");
  const e = run(edited);
  assert.equal(e.status, 1);
  assert.match(e.err, /parse\.js has sha256 [0-9a-f]{64}, VENDORED\.json records/);
  assert.ok(!existsSync(join(edited, "dist")), "nothing is copied when a check fails");

  const added = fresh();
  writeFileSync(join(added, "src", "vendor", "smol-toml", "extra.js"), "export {};\n");
  assert.match(run(added).err, /holds \[.*extra\.js.*\] but VENDORED\.json lists/);

  // Beside smol-toml/: ESLint ignores only that directory, so anything else in src/vendor/ is refused.
  const beside = fresh();
  mkdirSync(join(beside, "src", "vendor", "other"));
  writeFileSync(join(beside, "src", "vendor", "other", "x.ts"), "export const x = 1;\n");
  const b = run(beside);
  assert.equal(b.status, 1);
  assert.match(b.err, /src\/vendor holds \[other, smol-toml\]; only smol-toml is vendored/);
  assert.ok(!existsSync(join(beside, "dist")), "nothing is copied when a check fails");
  const eslint = readFileSync(join(ROOT, "eslint.config.js"), "utf8");
  assert.ok(eslint.includes('"src/vendor/smol-toml/**"') && !eslint.includes('"src/vendor/**"'), "ESLint ignores smol-toml only");
});

test("vendor: the licence ships, THIRD_PARTY_NOTICES.md carries its full text, CODEOWNERS covers the copy", () => {
  const licence = readFileSync(join(VENDOR, "LICENSE"), "utf8");
  assert.match(licence, /^Copyright \(c\) Squirrel Chat et al\., All rights reserved\./);
  const notices = readFileSync(join(ROOT, "THIRD_PARTY_NOTICES.md"), "utf8");
  assert.ok(notices.includes(licence.trimEnd()), "THIRD_PARTY_NOTICES.md quotes src/vendor/smol-toml/LICENSE verbatim");
  for (const fact of [record.version, record.integrity, record.upstream.commit, "BSD-3-Clause"]) assert.ok(notices.includes(fact), fact);
  assert.match(readFileSync(join(ROOT, ".github", "CODEOWNERS"), "utf8"), /^\/src\/vendor\/\s+@stgllghr$/m);
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { dependencies?: unknown; description: string };
  assert.equal(pkg.dependencies, undefined, "the parser is vendored, not an npm dependency");
  // The description npm and GitHub show names the vendored code, and says what uses it.
  assert.match(pkg.description, /No npm runtime dependencies; one vendored, pinned, verified TOML parser, for the Python lockfiles soak reads and the pyproject\.toml files diff compares\./);
});

test("vendor: CI re-derives the copy from the registry on every run and monthly", () => {
  const ci = readFileSync(join(ROOT, ".github", "workflows", "ci.yml"), "utf8");
  const job = /^ {2}verify-vendor:\n((?: {4}.*\n|\n)*)/m.exec(ci)?.[1];
  assert.ok(job, "ci.yml has a verify-vendor job");
  assert.doesNotMatch(job, /^ {4}if:/m, "not limited to some events");
  assert.match(job, /^ {6}- run: node scripts\/verify-vendor\.mjs$/m);
  assert.match(job, /^ {6}- uses: actions\/checkout@[0-9a-f]{40} # v/m);
  assert.match(ci, /^ {2}schedule:\n(?: {4}#.*\n)* {4}- cron: "17 4 1 \* \*"$/m, "the workflow has its monthly schedule");
});

/* ---- smol-toml 1.9.0 facts the readers rely on (docs/architecture.md); an upgrade that changes one fails here ---- */

const throwsToml = (text: string, re: RegExp): void => {
  assert.throws(() => parse(text), (e: unknown) => e instanceof TomlError && re.test(e.message));
};

test("vendor facts: a BOM parses, duplicates throw, tables have a null prototype, unsafe keys stay own keys", () => {
  assert.deepEqual({ ...parse("\ufeffa = 1\n") }, { a: 1 }, "smol-toml accepts a leading BOM; src/python/toml.ts refuses it");
  throwsToml("a = 1\na = 2\n", /redefine an already defined table or value/);
  throwsToml("[x]\n[x]\n", /redefine an already defined table or value/);
  const doc = parse("i = { z = 3 }\n[t]\nx = 1\n[[a]]\ny = 2\n");
  for (const v of [doc, doc["t"], (doc["a"] as unknown[])[0], doc["i"]]) assert.equal(Object.getPrototypeOf(v), null);
  const unsafe = parse('__proto__ = 1\n[constructor]\nx = 1\n');
  assert.ok(Object.hasOwn(unsafe, "__proto__") && Object.hasOwn(unsafe, "constructor"));
  assert.equal(Object.getPrototypeOf(unsafe), null);
  parse("[__proto__]\npolluted = 1\n");
  assert.equal(({} as Record<string, unknown>)["polluted"], undefined);
});

test("vendor facts: integers beyond 2^53 throw by default and are bigints when asked; datetimes are TomlDate", () => {
  throwsToml("a = 9007199254740992\n", /cannot be represented losslessly/);
  assert.equal(parse("a = 9007199254740991\n")["a"], 9007199254740991);
  assert.equal(parse("a = 9223372036854775807\n", { integersAsBigInt: "asNeeded" })["a"], 9223372036854775807n);
  assert.equal(parse("a = 1\n", { integersAsBigInt: "asNeeded" })["a"], 1);
  const d = parse("d = 2024-12-04T17:35:26.475808Z\nl = 2024-12-04\n");
  assert.ok(d["d"] instanceof TomlDate && (d["d"] as TomlDate).isDateTime() && !(d["d"] as TomlDate).isLocal());
  assert.equal((d["d"] as TomlDate).toISOString(), "2024-12-04T17:35:26.475Z", "millisecond precision: microseconds are dropped");
  assert.ok((d["l"] as TomlDate).isDate() && (d["l"] as TomlDate).isLocal());
});

test("vendor facts: TOML 1.1 inline tables, rolled-over dates and CRLF kept in multi-line strings", () => {
  assert.deepEqual({ ...(parse("a = { b = 1, }\n")["a"] as object) }, { b: 1 }, "a trailing comma in an inline table (TOML 1.1)");
  assert.deepEqual({ ...(parse("a = {\n  b = 1\n}\n")["a"] as object) }, { b: 1 }, "a newline in an inline table (TOML 1.1)");
  assert.equal((parse("a = 2023-02-29\n")["a"] as TomlDate).toISOString(), "2023-03-01", "an impossible date rolls over");
  assert.equal((parse("a = 2024-02-30\n")["a"] as TomlDate).toISOString(), "2024-03-01");
  assert.equal((parse("a = 2024-02-30T00:00:00Z\n")["a"] as TomlDate).toISOString(), "2024-03-01T00:00:00.000Z");
  throwsToml("a = 2024-13-01\n", /invalid date/);
  assert.equal(parse('a = """x\r\ny"""\n')["a"], "x\r\ny", "CRLF stays in a multi-line basic string");
  assert.equal(parse("a = '''x\r\ny'''\n")["a"], "x\r\ny", "and in a multi-line literal string");
});

test("vendor facts: inline nesting is capped at 1000 levels; dotted keys and headers are not recursive", () => {
  parse(`a = ${"[".repeat(1000)}${"]".repeat(1000)}\n`);
  throwsToml(`a = ${"[".repeat(1001)}${"]".repeat(1001)}\n`, /excessively nested/);
  throwsToml(`a = ${"{b=".repeat(2000)}1${"}".repeat(2000)}\n`, /excessively nested/);
  parse(`${Array.from({ length: 100_000 }, (_, i) => `k${i}`).join(".")} = 1\n`);
  parse(`[${Array.from({ length: 100_000 }, (_, i) => `k${i}`).join(".")}]\n`);
});
