/**
 * The Python readers (src/python/): names, versions, file names, TOML, uv.lock, pylock.toml, PEP 723 blocks and local
 * paths. Fixtures under test/fixtures/python/locks were written by uv 0.10.9, uv 0.12.21 and pip 26.2.1
 * (scripts/gen-py-fixtures.sh); forged/ holds variants of them that each reader must refuse, with the reason.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { OSV_VALID } from "../src/osv.js";
import { basenameOf, parseDistFilename, parseSdistFilename, parseWheelFilename } from "../src/python/filenames.js";
import { isNormalizedName, isValidName, normalizeName, projectName } from "../src/python/names.js";
import { canonicalVersion, compareVersions, isCanonicalVersion, parseVersion, versionsEqual } from "../src/python/pep440.js";
import { parseScriptBlock } from "../src/python/pep723.js";
import { checkLocalPath } from "../src/python/paths.js";
import { isPylockName, parsePylock, readPylock } from "../src/python/pylock.js";
import { bytesDigest, contentDigest, get, isSafeCount, offsetDateTime, parseToml, readToml, type TomlTable } from "../src/python/toml.js";
import { parseUvLock, REVISIONS, readUvLock, type UvLock } from "../src/python/uvlock.js";

const FIX = join(import.meta.dirname, "..", "..", "test", "fixtures", "python", "locks");
const FORGED = join(FIX, "forged");
const UVS = ["uv-0.10.9", "uv-0.12.21"];
const SIX_WHL = "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274";
const SIX_SDIST = "ff70335d468e7eb6ec65b95b99d3a2836546063f63acc5171de367e834932a81";

/** A seeded generator, so a failing fuzz case is reproducible. */
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}
const randomStrings = (alphabet: string, count: number, maxLen: number, seed: number): string[] => {
  const r = rng(seed);
  return Array.from({ length: count }, () => Array.from({ length: Math.floor(r() * (maxLen + 1)) }, () => alphabet[Math.floor(r() * alphabet.length)]).join(""));
};

/* ---- names ---- */

test("names: PEP 503 normalisation and PEP 508 validity", () => {
  assert.equal(normalizeName("Zope.Interface"), "zope-interface");
  assert.equal(normalizeName("a__b--c..d_.-e"), "a-b-c-d-e");
  for (const n of ["six", "Six", "zope.interface", "a", "A1", "a-b_c.d"]) assert.ok(isValidName(n), n);
  for (const n of ["", "-six", "six-", "six_", ".six", "si x", "six!", "s\u00efx", "six\n"]) assert.ok(!isValidName(n), JSON.stringify(n));
  assert.equal(projectName("Zope.Interface"), "zope-interface");
  assert.equal(projectName("six "), undefined);
  assert.equal(projectName("a".repeat(200)), "a".repeat(200));
  assert.equal(projectName("a".repeat(201)), undefined);
  assert.ok(isNormalizedName("zope-interface") && !isNormalizedName("zope.interface") && !isNormalizedName("Six") && !isNormalizedName("a--b"));
});

test("names: isNormalizedName accepts exactly what src/osv.ts sends to OSV for PyPI", () => {
  const corpus = [
    ...["six", "zope-interface", "zope.interface", "zope_interface", "a--b", "a-", "-a", "A", "a", "0", "a-0", "a".repeat(200), "a".repeat(201), "", "a b", "\u00e9"],
    ...randomStrings("ab0-_.A ~", 4000, 8, 1),
  ];
  for (const n of corpus) assert.equal(isNormalizedName(n), OSV_VALID.PyPI.name(n), JSON.stringify(n));
  // Every normalised form of a valid name is one OSV accepts.
  for (const n of randomStrings("aB9-_.", 2000, 12, 2).filter(isValidName)) assert.equal(OSV_VALID.PyPI.name(normalizeName(n)), normalizeName(n).length <= 200, n);
});

/* ---- PEP 440 ---- */

test("pep440: canonical forms, as packaging 26.2 prints them", () => {
  const cases: [string, string][] = [
    ["1.0", "1.0"], ["v1.0", "1.0"], ["V1.0", "1.0"], ["1.0.0", "1.0.0"], ["01.002", "1.2"], ["0!1.0", "1.0"], ["1!2.0", "1!2.0"],
    ["1.0a1", "1.0a1"], ["1.0alpha1", "1.0a1"], ["1.0-beta.2", "1.0b2"], ["1.0c1", "1.0rc1"], ["1.0pre1", "1.0rc1"], ["1.0preview", "1.0rc0"],
    ["1.0RC1", "1.0rc1"], ["1.0-1", "1.0.post1"], ["1.0.post", "1.0.post0"], ["1.0rev2", "1.0.post2"], ["1.0r", "1.0.post0"], ["1.0_post_3", "1.0.post3"],
    ["1.0.dev", "1.0.dev0"], ["1.0-dev3", "1.0.dev3"], ["1.0a1.post2.dev3", "1.0a1.post2.dev3"], ["1.0+ABC.01", "1.0+abc.1"], ["1.0+a-b_c", "1.0+a.b.c"],
    ["1.0+0a", "1.0+0a"], ["2026.7.22", "2026.7.22"], ["1.0-beta-2", "1.0b2"], ["1.0.a.1", "1.0a1"],
  ];
  for (const [input, canonical] of cases) assert.equal(canonicalVersion(input), canonical, input);
  // packaging also accepts surrounding whitespace ("1.0 "); this parser takes a token, never a padded string.
  for (const bad of ["", "1.", ".1", "1..0", "1.0+", "1.0+_", "a1", "1.0 ", " 1.0", "1.0-", "1!", "1.0.*", "1.0+a..b", "\u0661.\u0660", "1.0x", "latest", "1.0-beta-2-", "1.0betaa"]) {
    assert.equal(parseVersion(bad), undefined, JSON.stringify(bad));
  }
});

test("pep440: ordering and equality follow PEP 440 (zero padding, epochs, pre/post/dev, local labels)", () => {
  // PEP 440's own example order, extended with a local label and an epoch.
  const ordered = ["1.0.dev456", "1.0a1", "1.0a2.dev456", "1.0a12.dev456", "1.0a12", "1.0b1.dev456", "1.0b2", "1.0b2.post345.dev456", "1.0b2.post345", "1.0rc1.dev456", "1.0rc1", "1.0", "1.0+abc.5", "1.0+abc.7", "1.0+5", "1.0.post456.dev34", "1.0.post456", "1.0.15", "1.1.dev1", "1!0.1"];
  const v = ordered.map((s) => parseVersion(s)!);
  for (let i = 0; i < v.length; i++) {
    for (let j = 0; j < v.length; j++) assert.equal(Math.sign(compareVersions(v[i]!, v[j]!)), Math.sign(i - j), `${ordered[i]} vs ${ordered[j]}`);
  }
  for (const [a, b] of [["1.0", "1.0.0"], ["1.0", "1.0.0.0"], ["1.0.post0", "1.0-0"], ["1.0.post0", "1.0.post"], ["1.0+1", "1.0+01"], ["1.0+abc", "1.0+ABC"], ["0!1", "1.0"], ["1.0a", "1.0a0"], ["1.0c1", "1.0rc1"]]) {
    assert.ok(versionsEqual(a!, b!), `${a} == ${b}`);
  }
  for (const [a, b] of [["1!1.0", "1.0"], ["1.0+abc", "1.0"], ["1.0.dev0", "1.0"], ["1.0a1", "1.0b1"], ["1.0.1", "1.0"], ["99999999999999999999", "99999999999999999998"], ["1.0", "x"]]) {
    assert.ok(!versionsEqual(a!, b!), `${a} != ${b}`);
  }
  assert.ok(compareVersions(parseVersion("1.99999999999999999999")!, parseVersion("1.99999999999999999998")!) > 0, "numbers beyond 2^53 compare exactly");
});

test("pep440: isCanonicalVersion accepts exactly what src/osv.ts sends to OSV for PyPI", () => {
  const corpus = [
    ...["1.0", "1.0.0", "0", "01", "1.0a1", "1.0a01", "1.0.post1", "1.0.dev1", "1!1.0", "0!1.0", "1.0+abc.1", "1.0+abc.01", "1.0+0a", "1.0+ABC", "v1.0", "1.0c1", "1.0-1"],
    `1.${"0".repeat(252)}`, `1.${"0".repeat(253)}`, `1.${"0".repeat(254)}`,
    ...randomStrings("0123456789.!+abcdeprostv-_", 6000, 12, 3),
  ];
  for (const s of corpus) assert.equal(isCanonicalVersion(s), OSV_VALID.PyPI.version(s), JSON.stringify(s));
});

/* ---- file names ---- */

test("filenames: wheel and sdist names give the project and version; anything ambiguous or malformed gives undefined", () => {
  assert.deepEqual(parseWheelFilename("six-1.17.0-py2.py3-none-any.whl"), { kind: "wheel", name: "six", version: "1.17.0" });
  assert.deepEqual(parseWheelFilename("MarkupSafe-2.1.5-cp38-cp38-win32.whl"), { kind: "wheel", name: "markupsafe", version: "2.1.5" });
  assert.deepEqual(parseWheelFilename("pkg-1.0-1abc-py3-none-any.whl"), { kind: "wheel", name: "pkg", version: "1.0" });
  assert.deepEqual(parseWheelFilename("zope.interface-6.0_post1-py3-none-any.whl"), { kind: "wheel", name: "zope-interface", version: "6.0.post1" });
  for (const bad of ["pkg-1.0-x1-py3-none-any.whl", "pkg-1.0-py3-none.whl", "pkg__x-1.0-py3-none-any.whl", "pkg-latest-py3-none-any.whl", "pkg-1.0-py3-none-any.zip", "a/pkg-1.0-py3-none-any.whl", "pkg-1.0--none-any.whl"]) {
    assert.equal(parseWheelFilename(bad), undefined, bad);
  }
  assert.equal(parseWheelFilename("six-1.17.0-py2.py3-none-any.whl", "idna"), undefined);

  assert.deepEqual(parseSdistFilename("six-1.17.0.tar.gz"), { kind: "sdist", name: "six", version: "1.17.0" });
  assert.deepEqual(parseSdistFilename("python-dateutil-2.8.2.tar.gz"), { kind: "sdist", name: "python-dateutil", version: "2.8.2" });
  assert.deepEqual(parseSdistFilename("zope.interface-6.0.zip"), { kind: "sdist", name: "zope-interface", version: "6.0" });
  // "foo-1.0-2" is foo 1.0.post2 or foo-1.0 2: ambiguous unless the project is known.
  assert.equal(parseSdistFilename("foo-1.0-2.tar.gz"), undefined);
  assert.deepEqual(parseSdistFilename("foo-1.0-2.tar.gz", "foo"), { kind: "sdist", name: "foo", version: "1.0.post2" });
  assert.deepEqual(parseSdistFilename("foo-1.0-2.tar.gz", "foo-1-0"), { kind: "sdist", name: "foo-1-0", version: "2" });
  for (const bad of ["six-1.17.0.tar.bz2", "six-1.17.0.TAR.GZ", "six.tar.gz", "six-latest.tar.gz", "-1.0.tar.gz", "six-1.17.0.egg"]) assert.equal(parseSdistFilename(bad), undefined, bad);
  assert.deepEqual(parseDistFilename("six-1.17.0.tar.gz", "six"), { kind: "sdist", name: "six", version: "1.17.0" });
  assert.equal(parseDistFilename("six-1.17.0-py2.py3-none-any.whl", "six")?.kind, "wheel");
  assert.equal(basenameOf("https://files.pythonhosted.org/packages/b7/ce/x/six-1.17.0-py2.py3-none-any.whl"), "six-1.17.0-py2.py3-none-any.whl");
  assert.equal(basenameOf("https://h/p/pkg-1.0%2Blocal.tar.gz"), "pkg-1.0+local.tar.gz");
  assert.equal(basenameOf("vendor/six.whl"), "six.whl");
  assert.equal(basenameOf("https://h/dir/"), undefined);
});

/* ---- TOML ---- */

test("toml: a BOM, invalid UTF-8, a parse error and an oversized file are problems, never exceptions", () => {
  const d = mkdtempSync(join(tmpdir(), "ws-toml-"));
  const write = (name: string, data: string | Buffer): string => {
    writeFileSync(join(d, name), data);
    return join(d, name);
  };
  assert.match((readToml(write("bom.toml", "\uFEFFa = 1\n")) as { problem: string }).problem, /starts with a BOM/);
  assert.match((readToml(write("latin1.toml", Buffer.from([0x61, 0x3d, 0x22, 0xe9, 0x22, 0x0a]))) as { problem: string }).problem, /not valid UTF-8/);
  assert.match((readToml(write("bad.toml", "a = 1\na = 2\n")) as { problem: string }).problem, /not valid TOML \(line 2, column \d+: trying to redefine/);
  assert.match((readToml(write("big.toml", "a = 1\n"), 3) as { problem: string }).problem, /larger than/);
  assert.match((readToml(join(d, "missing.toml")) as { problem: string }).problem, /could not be read \(ENOENT\)/);
  assert.match((parseToml(`a = ${"[".repeat(5000)}${"]".repeat(5000)}`) as { problem: string }).problem, /excessively nested/);
  const ok = parseToml('n = 9223372036854775807\nd = 2024-12-04T17:35:26+01:00\nl = 2024-12-04T17:35:26\n__proto__ = "x"\n') as { doc: Record<string, unknown> };
  assert.equal(get(ok.doc, "n"), 9223372036854775807n);
  assert.ok(!isSafeCount(get(ok.doc, "n")) && isSafeCount(3) && !isSafeCount(-1) && !isSafeCount(1.5));
  assert.equal(offsetDateTime(get(ok.doc, "d")), "2024-12-04T16:35:26.000Z");
  assert.equal(offsetDateTime(get(ok.doc, "l")), undefined, "a local date-time has no instant");
  assert.equal(get(ok.doc, "__proto__"), "x");
  assert.equal(get(ok.doc, "toString"), undefined, "get never reads the prototype chain");
});

test("toml: a 1 MB adversarial document of each shape parses in well under a second (linear, not quadratic)", () => {
  const shapes: Record<string, string> = {};
  let s = "";
  for (let i = 0; s.length < 1_000_000; i++) s += `[t${i}]\n`;
  shapes["table headers"] = s;
  s = "[a]\n";
  for (let i = 0; s.length < 1_000_000; i++) s += `k${i}.x.y = 1\n`;
  shapes["dotted keys"] = s;
  shapes["array-of-tables"] = "[[a.b]]\n".repeat(125_000);
  shapes["inline tables"] = `a = [${"{x=1},".repeat(166_000)}]\n`;
  shapes["[[package]]"] = '[[package]]\nname = "x"\n'.repeat(45_000);
  for (const [shape, text] of Object.entries(shapes)) {
    const t0 = performance.now();
    const r = parseToml(text);
    const ms = performance.now() - t0;
    assert.ok("doc" in r, shape);
    assert.ok(ms < 2000, `${shape}: ${Math.round(ms)} ms`);
  }
});

/* ---- uv.lock ---- */

const brief = (l: UvLock): string[] => l.packages.map((p) => `${p.name} ${p.version ?? "-"} ${p.source.kind}:${"url" in p.source ? p.source.url : "path" in p.source ? p.source.path : ""} sdist=${p.sdist?.sha256?.slice(0, 8) ?? "-"} wheels=${p.wheels.length}`);

test("uv.lock: every lock uv 0.10.9 and 0.12.21 wrote reads with no problems, revision 3, the same for both", () => {
  for (const name of ["simple/uv.lock", "fork/uv.lock", "editable/uv.lock", "path/uv.lock", "script/example.py.lock"]) {
    const [a, b] = UVS.map((uv) => readUvLock(join(FIX, uv, name)));
    for (const l of [a!, b!]) {
      assert.deepEqual(l.problems, [], name);
      assert.equal(l.version, 1);
      assert.equal(l.revision, 3, `${name}: the revision both uvs wrote`);
    }
    assert.deepEqual(a, b, `${name}: uv 0.10.9 and 0.12.21 wrote the same lock`);
  }
  assert.ok(REVISIONS.includes(3) && REVISIONS.includes(5) && !REVISIONS.includes(6));
});

test("uv.lock: registry packages carry every file with its sha256, url, size and upload time", () => {
  const l = readUvLock(join(FIX, "uv-0.12.21", "simple", "uv.lock"));
  assert.deepEqual(brief(l), ["demo-simple 0.1.0 virtual:. sdist=- wheels=0", "idna 3.20 registry:https://pypi.org/simple sdist=a7db8500 wheels=1", "six 1.17.0 registry:https://pypi.org/simple sdist=ff70335d wheels=1"]);
  const six = l.packages.find((p) => p.name === "six")!;
  assert.deepEqual(six.sdist, {
    kind: "sdist",
    url: "https://files.pythonhosted.org/packages/94/e7/b2c673351809dca68a0e064b6af791aa332cf192da575fd474ed7d6f16a2/six-1.17.0.tar.gz",
    filename: "six-1.17.0.tar.gz",
    size: 34031,
    uploadTime: "2024-12-04T17:35:28.174Z",
    hashes: { sha256: SIX_SDIST },
    sha256: SIX_SDIST,
  });
  assert.equal(six.wheels[0]!.sha256, SIX_WHL);
  assert.equal(six.wheels[0]!.filename, "six-1.17.0-py2.py3-none-any.whl");
  assert.deepEqual(l.options["exclude-newer"], "2026-10-01T00:00:00Z");
});

test("uv.lock: a forking resolution keeps every [[package]] entry of a name, in file order", () => {
  const l = readUvLock(join(FIX, "uv-0.12.21", "fork", "uv.lock"));
  const markupsafe = l.packages.filter((p) => p.name === "markupsafe");
  assert.deepEqual(markupsafe.map((p) => p.version), ["2.1.5", "3.0.3"]);
  assert.deepEqual(markupsafe.map((p) => p.index), [1, 2]);
  assert.ok(markupsafe.every((p) => p.resolutionMarkers.length > 0 && p.wheels.length > 40 && p.sdist !== undefined));
  assert.equal(new Set(markupsafe.flatMap((p) => p.wheels.map((w) => w.sha256))).size, markupsafe.reduce((n, p) => n + p.wheels.length, 0));
});

test("uv.lock: workspace members, editable and directory sources, and a path archive", () => {
  const e = readUvLock(join(FIX, "uv-0.12.21", "editable", "uv.lock"));
  assert.deepEqual(e.members, ["demo-editable", "member"]);
  assert.deepEqual(e.packages.filter((p) => p.source.kind === "editable").map((p) => [p.name, (p.source as { path: string }).path]), [["demo-editable", "."], ["member", "packages/member"]]);
  const p = readUvLock(join(FIX, "uv-0.12.21", "path", "uv.lock"));
  const six = p.packages.find((x) => x.name === "six")!;
  assert.deepEqual(six.source, { kind: "path", path: "vendor/six-1.17.0-py2.py3-none-any.whl" });
  assert.deepEqual(six.wheels, [{ kind: "wheel", filename: "six-1.17.0-py2.py3-none-any.whl", hashes: { sha256: SIX_WHL }, sha256: SIX_WHL }]);
  assert.deepEqual(p.packages.find((x) => x.name === "localdir")!.source, { kind: "directory", path: "libs/localdir" });
  const s = readUvLock(join(FIX, "uv-0.12.21", "script", "example.py.lock"));
  assert.deepEqual(s.packages.map((x) => x.name), ["certifi", "six"]);
});

test("uv.lock: forged locks are refused with the reason", () => {
  const expect: Record<string, RegExp | null> = {
    "uv-sha512-only-wheel.lock": /six 1\.17\.0\) wheel #1 \(six-1\.17\.0-py2\.py3-none-any\.whl\): no sha256 hash, so it cannot be bound to an index file/,
    "uv-unhashed-wheel.lock": /wheel #1 \(six-1\.17\.0-py2\.py3-none-any\.whl\): no sha256 hash, so it cannot be bound/,
    "uv-uppercase-hash.lock": /hash "sha256:4721F391.*" is not an algorithm:lowercase-hex digest/,
    "uv-unknown-file-key.lock": /wheel #1: unknown key\(s\) "signature": format not supported/,
    "uv-unknown-package-key.lock": /\(six 1\.17\.0\): unknown key\(s\) "install-hook"/,
    "uv-unknown-source.lock": /unknown source \{"svn":/,
    "uv-registry-and-path-source.lock": /unknown source \{"registry":"https:\/\/pypi\.org\/simple","path":"vendor\/six\.whl"\}/,
    "uv-unknown-top-key.lock": /unknown top-level key\(s\) "install-from"/,
    "uv-distribution-tables.lock": /unknown top-level key\(s\) "distribution"/,
    "uv-version-2.lock": /lockfile version 2 is not 1/,
    "uv-revision-99.lock": /lockfile revision 99 is not one this reader knows/,
    "uv-missing-version.lock": /\(six\): no version, so it cannot be bound or checked against OSV/,
    "uv-oversized-size.lock": /size is not a non-negative integer/,
    "uv-duplicate-key.lock": /not valid TOML \(line \d+, column \d+: trying to redefine/,
    "uv-bom.lock": /starts with a BOM/,
    "uv-no-files.lock": /\(six 1\.17\.0\): no sdist or wheels entries, so nothing can be bound/,
    "uv-wheel-url-and-filename.lock": /\(six 1\.17\.0\) wheel #1: url and filename together \(uv uses only the first of url, path and filename\): format not supported/,
    "uv-sdist-url-and-path.lock": /\(six 1\.17\.0\) sdist: url and path together \(uv uses only the first of url, path and filename\): format not supported/,
    "uv-revision-5.lock": null,
    "uv-no-revision.lock": null,
    "uv-git-source.lock": null,
  };
  const forged = readdirSync(FORGED).filter((f) => f.startsWith("uv-") && f.endsWith(".lock")).sort();
  assert.deepEqual(forged, Object.keys(expect).sort(), "every forged uv.lock has an expectation");
  for (const [file, re] of Object.entries(expect)) {
    const l = readUvLock(join(FORGED, file));
    if (re === null) assert.deepEqual(l.problems, [], file);
    else assert.ok(l.problems.some((p) => re.test(p)), `${file}: ${JSON.stringify(l.problems)}`);
  }
  assert.equal(readUvLock(join(FORGED, "uv-no-revision.lock")).revision, 0, "a missing revision is 0, as uv reads it");
  assert.equal(readUvLock(join(FORGED, "uv-git-source.lock")).packages.find((p) => p.name === "six")!.source.kind, "git");
  assert.ok(!readUvLock(join(FORGED, "uv-sha512-only-wheel.lock")).packages.find((p) => p.name === "six")!.wheels.some((w) => w.sha256 === undefined));
});

/* ---- pylock.toml ---- */

test("pylock: the locks uv export and pip lock wrote read with no problems", () => {
  for (const uv of UVS) {
    const l = readPylock(join(FIX, uv, "simple", "pylock.toml"));
    assert.deepEqual(l.problems, []);
    assert.equal(l.lockVersion, "1.0");
    assert.equal(l.createdBy, "uv");
    assert.deepEqual(l.packages.map((p) => [p.name, p.version, p.source]), [["idna", "3.20", { kind: "files", index: "https://pypi.org/simple" }], ["six", "1.17.0", { kind: "files", index: "https://pypi.org/simple" }]]);
    const six = l.packages[1]!;
    assert.deepEqual([six.sdist?.sha256, six.wheels.map((w) => w.sha256)], [SIX_SDIST, [SIX_WHL]]);
    assert.equal(six.wheels[0]!.uploadTime, "2024-12-04T17:35:26.000Z", "uv writes upload-time as a TOML date-time, to the second");
  }
  const pip = readPylock(join(FIX, "pip-26.2.1", "lock", "pylock.toml"));
  assert.deepEqual(pip.problems, []);
  assert.equal(pip.createdBy, "pip");
  assert.deepEqual(pip.packages.map((p) => [p.name, p.version, p.source, p.sdist, p.wheels.length]), [["certifi", "2026.7.22", { kind: "files" }, undefined, 1], ["idna", "3.10", { kind: "files" }, undefined, 1], ["six", "1.17.0", { kind: "files" }, undefined, 1]]);
  assert.equal(pip.packages[2]!.wheels[0]!.uploadTime, undefined, "pip lock writes no upload-time");
  assert.ok(isPylockName("pylock.toml") && isPylockName("pylock.dev.toml") && !isPylockName("pylock.a.b.toml") && !isPylockName("pylock..toml") && !isPylockName("Pylock.toml"));
});

test("pylock: forged locks are refused with the reason; local sources are typed", () => {
  const expect: Record<string, RegExp | null> = {
    "pylock-sha512-only.toml": /\(six 1\.17\.0\) wheel #1 \(six-1\.17\.0-py2\.py3-none-any\.whl\): no sha256 hash, so it cannot be bound to an index file/,
    "pylock-empty-hashes.toml": /wheel #1 \(six-1\.17\.0-py2\.py3-none-any\.whl\): no hashes table, so it cannot be bound/,
    "pylock-uppercase-algorithm.toml": /hash algorithm "SHA256" is not lowercase/,
    "pylock-no-version.toml": /\(six\): no version, so it cannot be bound or checked against OSV/,
    "pylock-unknown-package-key.toml": /unknown key\(s\) "build-script"/,
    "pylock-unknown-file-key.toml": /wheel #1: unknown key\(s\) "signature"/,
    "pylock-lock-version-2.toml": /lock-version "2\.0" is not 1\.x/,
    "pylock-sdist-and-archive.toml": /more than one source \(archive, sdist\/wheels\)/,
    "pylock-no-files.toml": /\(six 1\.17\.0\): no sdist, wheels, archive, directory or vcs entry/,
    "pylock-bom.toml": /starts with a BOM/,
    "pylock-url-and-path.toml": /\(six 1\.17\.0\) wheel #1: both url and path \(pip and uv install from the path\): format not supported/,
    "pylock-lock-version-1-1.toml": null,
    "pylock-local-sources.toml": null,
    "pylock-wheel-name-override.toml": null,
  };
  const forged = readdirSync(FORGED).filter((f) => f.startsWith("pylock-")).sort();
  assert.deepEqual(forged, Object.keys(expect).sort(), "every forged pylock has an expectation");
  for (const [file, re] of Object.entries(expect)) {
    const l = readPylock(join(FORGED, file));
    if (re === null) assert.deepEqual(l.problems, [], file);
    else assert.ok(l.problems.some((p) => re.test(p)), `${file}: ${JSON.stringify(l.problems)}`);
  }
  const local = readPylock(join(FORGED, "pylock-local-sources.toml"));
  assert.deepEqual(local.packages.slice(-3).map((p) => [p.name, p.version, p.source]), [
    ["six", "1.17.0", { kind: "archive" }],
    ["localdir", undefined, { kind: "directory", path: "libs/localdir", editable: false }],
    ["six-git", undefined, { kind: "vcs", type: "git", url: "https://github.com/benjaminp/six", commitId: "2b9bd1ba1ee9e3f1a6c7a1d1b6b6a7c3f7f2a1c0" }],
  ]);
  assert.deepEqual(local.packages.at(-3)!.archive, { kind: "archive", path: "vendor/six-1.17.0-py2.py3-none-any.whl", filename: "six-1.17.0-py2.py3-none-any.whl", hashes: { sha256: SIX_WHL }, sha256: SIX_WHL });
  const renamed = readPylock(join(FORGED, "pylock-wheel-name-override.toml")).packages.find((p) => p.name === "six")!;
  assert.equal(renamed.wheels[0]!.filename, "six-1.16.0-py2.py3-none-any.whl", "a file's name field takes precedence over its URL");
});

test("readers: a value of any TOML type anywhere in a lock gives problems or entries, never an exception", () => {
  const values = ["9223372036854775808", "18446744073709551616", "-1", "1.5", "nan", "true", "1979-05-27T07:32:00Z", "1979-05-27", "07:32:00", "{ a = 1 }", "{}", "[1, 2]", "[]", '""', '"x"', '"sha256:"'];
  const r = rng(11);
  const locks = [
    ...UVS.flatMap((uv) => ["simple/uv.lock", "fork/uv.lock", "editable/uv.lock", "path/uv.lock", "script/example.py.lock", "simple/pylock.toml"].map((f) => join(FIX, uv, f))),
    join(FIX, "pip-26.2.1", "lock", "pylock.toml"),
    ...readdirSync(FORGED).filter((f) => /\.(lock|toml)$/.test(f)).map((f) => join(FORGED, f)),
  ];
  let parsed = 0;
  for (const file of locks) {
    const text = readFileSync(file, "utf8");
    const spots = [...text.matchAll(/= ("[^"\n]*"|[0-9][0-9T:.Z-]*)/g)];
    const read = file.endsWith(".toml") ? parsePylock : parseUvLock;
    for (let i = 0; i < 60 && spots.length > 0; i++) {
      const m = spots[Math.floor(r() * spots.length)]!;
      const at = m.index! + 2;
      const doc = parseToml(text.slice(0, at) + values[Math.floor(r() * values.length)]! + text.slice(at + m[1]!.length));
      if ("problem" in doc) continue;
      parsed++;
      const out = read(doc.doc);
      assert.ok(Array.isArray(out.problems) && Array.isArray(out.packages), file);
    }
  }
  assert.ok(parsed > 1000, `${parsed} variants parsed`);
  // Values that once reached JSON.stringify in a message, which throws on a bigint.
  const big = "18446744073709551616";
  const uv = (text: string): string[] => parseUvLock((parseToml(text) as { doc: Record<string, unknown> }).doc).problems;
  assert.match(uv(`version = ${big}\n`).join(), /lockfile version 18446744073709551616 is not 1/);
  assert.match(uv(`version = 1\nrevision = ${big}\n`).join(), /lockfile revision 18446744073709551616 is not one/);
  const pkg = (fields: string): string[] => uv(`version = 1\nrevision = 3\n[[package]]\nname = "six"\n${fields}\n`);
  assert.match(pkg(`version = ${big}\nsource = { registry = "https://pypi.org/simple" }`).join(), /version 18446744073709551616 is not a PEP 440 version/);
  assert.match(pkg(`version = "1.0"\nsource = { svn = ${big} }`).join(), /unknown source \{"svn":"18446744073709551616"\}/);
  assert.match(pkg(`version = "1.0"\nsource = { registry = "https://pypi.org/simple" }\nwheels = [{ url = "https://x/six-1.0-py3-none-any.whl", hash = ${big} }]`).join(), /hash 18446744073709551616 is not an algorithm/);
  const pl = (text: string): string[] => parsePylock((parseToml(text) as { doc: Record<string, unknown> }).doc).problems;
  assert.match(pl(`lock-version = ${big}\n`).join(), /lock-version 18446744073709551616 is not 1\.x/);
  assert.match(pl(`lock-version = "1.0"\n[[packages]]\nname = "six"\nversion = ${big}\nwheels = [{ url = "https://x/six-1.0-py3-none-any.whl", hashes = { sha256 = "${SIX_WHL}" } }]\n`).join(), /version 18446744073709551616 is not a PEP 440 version/);
});

/* ---- PEP 723 ---- */

const block = (text: string | Buffer) => parseScriptBlock(typeof text === "string" ? Buffer.from(text) : text);

test("pep723: blocks uv reads, and the forms uv does not read as blocks", () => {
  const deps = '# /// script\n# dependencies = ["six==1.17.0"]\n# ///\n';
  const ok = block(`#!/usr/bin/env -S uv run --script\n${deps}print(1)\n`);
  assert.equal(ok.kind, "block");
  assert.deepEqual(ok.kind === "block" && [ok.line, get(ok.metadata, "dependencies")], [2, ["six==1.17.0"]]);
  assert.equal(block(deps.replaceAll("\n", "\r\n")).kind, "block", "CRLF");
  assert.equal(block("# /// script\n#\n# dependencies = []\n#\n# ///\n").kind, "block", "lines that are just #");
  assert.equal(block("print(1)\n").kind, "none");
  assert.equal(block(`\uFEFF${deps}`).kind, "none", "a BOM before the tag");
  assert.equal(block(`  ${deps}`).kind, "none", "an indented tag");
  assert.equal(block(deps.replace("# /// script\n", "# /// script \n")).kind, "none", "a tag with a trailing space");
  assert.equal(block(deps.replace("# /// script\n", "# /// scripts\n")).kind, "none");
});

test("pep723: what uv refuses, or what readers may read differently, is a problem", () => {
  const deps = '# /// script\n# dependencies = ["six==1.17.0"]\n# ///\n';
  const problem = (text: string | Buffer, re: RegExp): void => {
    const r = block(text);
    assert.equal(r.kind, "problem", JSON.stringify(text.toString().slice(0, 60)));
    assert.match((r as { problem: string }).problem, re);
  };
  problem('# /// script\n# dependencies = ["six"]\nprint(1)\n', /line 1: the `# \/\/\/ script` block has no closing `# \/\/\/` line/);
  problem('# /// script\n# dependencies = ["six"\n# ///\n', /line 1: the `# \/\/\/ script` block is not valid TOML/);
  problem(`${deps}print(1)\n${deps}`, /line 5 is "# \/\/\/ script" but uv does not read it/);
  problem(`x = '# /// script'\n${deps}`, /line 2 is "# \/\/\/ script" but uv does not read it/);
  problem(deps.replaceAll("\n", "\r"), /line 1 is "# \/\/\/ script" but uv does not read it/);
  problem(Buffer.concat([Buffer.from(deps), Buffer.from([0xff, 0x0a])]), /not valid UTF-8/);
  assert.equal(block(Buffer.from([0xff, 0x0a, 0x70])).kind, "none", "invalid UTF-8 without a tag is no block, as in uv");
});

/* ---- local paths ---- */

test("paths: relative, normalised, inside the root, present, no symlink on the way, tracked when git says so", () => {
  const root = mkdtempSync(join(tmpdir(), "ws-paths-"));
  const outside = mkdtempSync(join(tmpdir(), "ws-paths-out-"));
  mkdirSync(join(root, "app", "libs", "pkg", "src"), { recursive: true });
  writeFileSync(join(root, "app", "libs", "pkg", "pyproject.toml"), "");
  writeFileSync(join(root, "app", "libs", "pkg", "src", "m.py"), "");
  writeFileSync(join(root, "app", "w.whl"), "");
  const opts = { root, base: "app" };
  assert.deepEqual(checkLocalPath("libs/pkg", "directory", opts), { ok: true, rel: "app/libs/pkg", abs: join(root, "app", "libs", "pkg") });
  assert.deepEqual(checkLocalPath("w.whl", "file", opts), { ok: true, rel: "app/w.whl", abs: join(root, "app", "w.whl") });
  assert.equal(checkLocalPath(".", "directory", opts).ok, true);
  const no = (raw: string, expect: "file" | "directory", re: RegExp, o: Parameters<typeof checkLocalPath>[2] = opts): void => {
    const r = checkLocalPath(raw, expect, o);
    assert.ok(!r.ok && re.test(r.problem), `${raw}: ${JSON.stringify(r)}`);
  };
  no("/etc", "directory", /not a relative path/);
  no("C:/x", "directory", /not a relative path/);
  no("file:///x", "directory", /not a relative path/);
  no("libs\\pkg", "directory", /not a relative path in \/ form/);
  no("../app/libs/pkg", "directory", /not a normalised path/);
  no("libs/../libs/pkg", "directory", /not a normalised path/);
  no("./libs/pkg", "directory", /not a normalised path/);
  no("libs/pkg/", "directory", /not a normalised path/);
  no("libs//pkg", "directory", /not a normalised path/);
  no("libs/missing", "directory", /not present in the scanned tree \(ENOENT\)/);
  no("w.whl", "directory", /not a directory/);
  no("libs/pkg", "file", /not a regular file/);

  symlinkSync(join(root, "app", "libs"), join(root, "app", "linked"));
  no("linked/pkg", "directory", /a symlink \(app\/linked\) is on the path/);
  symlinkSync(outside, join(root, "app", "libs", "pkg", "src", "escape"));
  no("libs/pkg", "directory", /the symlink app\/libs\/pkg\/src\/escape resolves outside the scanned root/);
  symlinkSync(join(root, "nowhere"), join(root, "app", "libs", "pkg", "src", "escape2"));
  no("libs/pkg", "directory", /does not resolve|outside the scanned root/);

  const root2 = mkdtempSync(join(tmpdir(), "ws-paths2-"));
  mkdirSync(join(root2, "pkg", "sub"), { recursive: true });
  writeFileSync(join(root2, "pkg", "pyproject.toml"), "");
  writeFileSync(join(root2, "pkg", "sub", "a.py"), "");
  symlinkSync(join(root2, "pkg", "sub", "a.py"), join(root2, "pkg", "inside-link"));
  assert.equal(checkLocalPath("pkg", "directory", { root: root2, base: "" }).ok, true, "a symlink resolving inside the root is fine");
  const tracked = new Set(["pkg/pyproject.toml", "pkg/sub/a.py", "pkg/inside-link"]);
  assert.equal(checkLocalPath("pkg", "directory", { root: root2, base: "", tracked }).ok, true);
  writeFileSync(join(root2, "pkg", "sub", "untracked.py"), "");
  no("pkg", "directory", /holds 1 file\(s\) not tracked by git \(pkg\/sub\/untracked\.py\)/, { root: root2, base: "", tracked });
  no("pkg/sub/untracked.py", "file", /not tracked by git/, { root: root2, base: "", tracked });
  no("pkg", "directory", /holds more than 2 entries/, { root: root2, base: "", maxEntries: 2 });
  no("../x", "directory", /not a normalised path/, { root: root2, base: "sub" });
  const deep = checkLocalPath("..", "directory", { root: root2, base: "" });
  assert.ok(!deep.ok);
  no(".", "directory", /the scanned root could not be read \(ENOENT\)/, { root: join(root2, "gone"), base: "" });
});

test("readers: each problem covers the content it is about (a file entry, a package, the whole file), whatever its position", () => {
  const doc = (t: string): TomlTable => {
    const r = parseToml(t);
    assert.ok("doc" in r, t);
    return r.doc;
  };
  // The canonical form: key order, quoting and inline-or-not do not change the digest; any value does.
  assert.equal(contentDigest(doc('a = 1\nb = "x"\n')), contentDigest(doc("b = 'x'\na = 1\n")));
  assert.equal(contentDigest(doc("[t]\nk = [1, 2]\n")), contentDigest(doc("t = { k = [1, 2] }\n")));
  for (const other of ['a = 2\nb = "x"\n', 'a = 1\nb = "y"\n', 'a = "1"\nb = "x"\n', 'a = 1\nb = ["x"]\n']) assert.notEqual(contentDigest(doc(other)), contentDigest(doc('a = 1\nb = "x"\n')), other);
  let deep: unknown = 1;
  for (let i = 0; i < 100_000; i++) deep = [deep];
  assert.match(contentDigest(deep), /^[0-9a-f]{64}$/, "no recursion: a deep value cannot overflow the stack");

  const wheel = (url: string, extra = "") => `{ url = "${url}", hash = "sha256:${"a".repeat(64)}"${extra} }`;
  const lock = (wheels: string[], pre = "") => `version = 1\nrevision = 3\n${pre}\n[[package]]\nname = "six"\nversion = "1.17.0"\nsource = { registry = "https://pypi.org/simple" }\nwheels = [${wheels.join(", ")}]\n`;
  const read = (t: string) => {
    const u = parseUvLock(doc(t));
    assert.equal(u.covers.length, u.problems.length);
    return u;
  };
  const a = read(lock([wheel("https://x/six-1.17.0-py3-none-any.whl", ', zstd = "z"')]));
  assert.match(a.problems[0]!, /wheel #1: unknown key\(s\) "zstd"/);
  assert.equal(a.covers[0], contentDigest(doc(`w = ${wheel("https://x/six-1.17.0-py3-none-any.whl", ', zstd = "z"')}\n`)["w"]), "the wheel's table");
  assert.notEqual(read(lock([wheel("https://evil/six-1.17.0-py3-none-any.whl", ', zstd = "z"')])).covers[0], a.covers[0], "another url there");
  assert.equal(read(lock([wheel("https://y/ok.whl"), wheel("https://x/six-1.17.0-py3-none-any.whl", ', zstd = "z"')])).covers[0], a.covers[0], "moved to wheel #2: the same");
  // A whole-file problem covers the file's bytes when read from disk, the document otherwise.
  const dir = mkdtempSync(join(tmpdir(), "ws-pyread-"));
  const unknown = lock([wheel("https://x/a.whl")]).replace("revision = 3", "revision = 99");
  writeFileSync(join(dir, "uv.lock"), unknown);
  const fromDisk = readUvLock(join(dir, "uv.lock"));
  assert.deepEqual([fromDisk.problems.length, fromDisk.covers], [1, [bytesDigest(unknown)]]);
  writeFileSync(join(dir, "uv.lock"), "version = [\n");
  assert.deepEqual(readUvLock(join(dir, "uv.lock")).covers, [bytesDigest("version = [\n")], "a parse error covers the bytes");
  assert.equal(read(unknown).covers[0], contentDigest(doc(unknown)));

  const py = (pkg: string) => `lock-version = "1.0"\ncreated-by = "x"\n\n[[packages]]\n${pkg}\n`;
  const p = parsePylock(doc(py('name = "six"\nversion = "1.17.0"\nmystery = 1\n[[packages.wheels]]\nurl = "https://x/six-1.17.0-py3-none-any.whl"\nhashes = { sha256 = "' + "a".repeat(64) + '" }')));
  assert.equal(p.covers.length, p.problems.length);
  assert.match(p.problems[0]!, /unknown key\(s\) "mystery"/);
  const q = parsePylock(doc(py('name = "six"\nversion = "1.17.0"\nmystery = 1\n[[packages.wheels]]\nurl = "https://evil/six-1.17.0-py3-none-any.whl"\nhashes = { sha256 = "' + "a".repeat(64) + '" }')));
  assert.notEqual(q.covers[0], p.covers[0], "a package problem covers the whole package, its files included");
});
