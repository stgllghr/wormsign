/**
 * Differential tests: the Python readers against the tools they stand in for.
 *
 * - TOML: src/python/toml.ts (smol-toml 1.9.0) against Python's tomllib, over every TOML fixture, plus edge cases.
 *   Date-times are compared as RFC 3339 instants at millisecond precision (smol-toml keeps milliseconds). Runs when a
 *   python3 with tomllib is on PATH; otherwise it skips with a message naming the python checked, and fails instead
 *   when WORMSIGN_REQUIRE_PYTHON=1 (CI sets it).
 * - PEP 440: src/python/pep440.ts against the packaging library pip vendors, when that python3 has pip. That is
 *   whatever pip the python3 on PATH has (in CI, the one setup-python installs), not necessarily the packaging 26.2
 *   src/python/pep440.ts follows, so the test reports the pip and packaging versions it compared with.
 * - Requirements files: test/python-differential-requirements.test.ts.
 * - PEP 723: src/python/pep723.ts against how uv 0.10.9 and 0.12.21 read each script (recorded the same way).
 */
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { canonicalVersion, compareVersions, parseVersion } from "../src/python/pep440.js";
import { parseScriptBlock } from "../src/python/pep723.js";
import { get, parseToml, readToml, TomlDate } from "../src/python/toml.js";

const ROOT = join(import.meta.dirname, "..", "..");
const PY = join(ROOT, "test", "fixtures", "python");

/* ---- python3 ---- */

interface Python {
  path: string;
  version: string;
  pip: boolean;
}

/**
 * Every python3 run here is bounded: a run that does not finish fails its test, saying what it ran, instead of holding
 * the whole file until scripts/run-tests.mjs's ten-minute timeout. Each run takes well under a second.
 *
 * No run gets its input on stdin. spawnSync's `input` of more than the 8 KiB a macOS socket pair buffers sometimes
 * never finishes writing when many processes run at once: python3 waits in read() on stdin, and node holds the other
 * end in spawnSync's loop, never woken to write the rest (Node 23.11.0, macOS 15.6.1; 7 of 1,800 runs of the 73 KB
 * PEP 440 input under 12 concurrent loops, 0 of 1,800 with the same input in a file). So python() passes the input as
 * a file, and stdin is /dev/null.
 */
const PYTHON_LIMIT_MS = 60_000;

function runPython(cmd: string, args: string[]): SpawnSyncReturns<string> {
  return spawnSync(cmd, args, { stdio: ["ignore", "pipe", "pipe"], encoding: "utf8", maxBuffer: 256 * 1024 * 1024, timeout: PYTHON_LIMIT_MS, killSignal: "SIGKILL" });
}

/** Why a python3 run did not finish, or undefined when it did. */
function unfinished(r: SpawnSyncReturns<string>, what: string): string | undefined {
  if ((r.error as NodeJS.ErrnoException | undefined)?.code === "ETIMEDOUT") return `${what} did not finish within ${PYTHON_LIMIT_MS / 1000} s and was killed`;
  if (r.signal) return `${what} was killed by ${r.signal}`;
  return undefined;
}

/** python3 on PATH with tomllib, or the reason there is none, naming the python checked. */
function findPython(): Python | { missing: string } | { broken: string } {
  const probe = "import sys, tomllib; print(sys.executable); print(sys.version.split()[0])";
  const r = runPython("python3", ["-c", probe]);
  const stuck = unfinished(r, `python3 -c '${probe}'`);
  if (stuck) return { broken: stuck };
  if (r.error) return { missing: `no python3 on PATH (${process.env["PATH"] ?? ""}): ${(r.error as NodeJS.ErrnoException).code ?? r.error.message}` };
  if (r.status !== 0) {
    const v = runPython("python3", ["-c", "import sys; print(sys.executable, sys.version.split()[0])"]);
    return { missing: `python3 (${v.stdout.trim() || "unknown"}) has no tomllib (Python 3.11 or later): ${r.stderr.trim().split("\n").pop()}` };
  }
  const [path, version] = r.stdout.trim().split("\n");
  const p = runPython(path!, ["-c", "import pip._vendor.packaging.version"]);
  const pipStuck = unfinished(p, `${path} -c 'import pip._vendor.packaging.version'`);
  if (pipStuck) return { broken: pipStuck };
  return { path: path!, version: version!, pip: p.status === 0 };
}
const PYTHON = findPython();

/** Skips a test that needs python3, or fails it when WORMSIGN_REQUIRE_PYTHON=1. A python3 that hangs always fails. */
function needPython(t: TestContext, what: string): Python | undefined {
  if ("broken" in PYTHON) assert.fail(PYTHON.broken);
  if ("missing" in PYTHON) {
    if (process.env["WORMSIGN_REQUIRE_PYTHON"] === "1") assert.fail(`WORMSIGN_REQUIRE_PYTHON=1 but ${PYTHON.missing}`);
    t.skip(`${what} skipped: ${PYTHON.missing}`);
    return undefined;
  }
  return PYTHON;
}

/** Runs script with sys.stdin reading input from a file (see PYTHON_LIMIT_MS), and returns what it printed. */
function python(py: Python, script: string, input: string): string {
  const file = join(mkdtempSync(join(tmpdir(), "ws-pydiff-")), "input.json");
  writeFileSync(file, input);
  const r = runPython(py.path, ["-c", `import sys\nsys.stdin = open(sys.argv[1], encoding="utf-8")\n${script}`, file]);
  const stuck = unfinished(r, `${py.path} ${py.version} running ${JSON.stringify(script.trim().split("\n")[0])} (${input.length} characters of input)`);
  if (stuck) assert.fail(stuck);
  assert.equal(r.status, 0, `${py.path} ${py.version}: ${r.stderr}`);
  return r.stdout;
}

test("differential: CI runs these tests with python3 required, from a pinned setup-python", () => {
  const ci = readFileSync(join(ROOT, ".github", "workflows", "ci.yml"), "utf8");
  const job = /^ {2}test:\n((?: {4}.*\n|\n)*)/m.exec(ci)?.[1];
  assert.ok(job, "ci.yml has a test job");
  assert.match(job, /^ {4}env:\n(?: {6}#.*\n)* {6}WORMSIGN_REQUIRE_PYTHON: "1"$/m);
  assert.match(job, /^ {6}- uses: actions\/setup-python@[0-9a-f]{40} # v\d+\.\d+\.\d+\n {8}with:\n {10}python-version: "3\.\d+"$/m);
  assert.ok(job.indexOf("actions/setup-python@") < job.indexOf("- run: npm test"), "python is set up before the tests run");
});

/* ---- TOML vs tomllib ---- */

const TOMLLIB = `
import datetime, json, math, sys, tomllib
def norm(v):
    if isinstance(v, bool): return v
    if isinstance(v, int): return v if abs(v) <= 2**53 - 1 else {"$bigint": str(v)}
    if isinstance(v, float):
        if math.isnan(v): return {"$float": "nan"}
        if math.isinf(v): return {"$float": "inf" if v > 0 else "-inf"}
        return v
    if isinstance(v, str): return v
    if isinstance(v, datetime.datetime):
        if v.tzinfo is None: return {"$local-datetime": v.isoformat(timespec="milliseconds")}
        u = v.astimezone(datetime.timezone.utc)
        return {"$datetime": u.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (u.microsecond // 1000)}
    if isinstance(v, datetime.date): return {"$date": v.isoformat()}
    if isinstance(v, datetime.time): return {"$time": v.isoformat(timespec="milliseconds")}
    if isinstance(v, list): return [norm(x) for x in v]
    if isinstance(v, dict): return {k: norm(x) for k, x in v.items()}
    raise TypeError(type(v))
out = {}
for path in json.load(sys.stdin):
    try:
        with open(path, "rb") as f:
            out[path] = {"doc": norm(tomllib.load(f))}
    except Exception as e:
        out[path] = {"error": type(e).__name__ + ": " + str(e)}
json.dump(out, sys.stdout)
`;

/** The same normal form for smol-toml's values. */
function norm(v: unknown): unknown {
  if (typeof v === "bigint") return { $bigint: v.toString() };
  if (typeof v === "number") return Number.isNaN(v) ? { $float: "nan" } : v === Infinity ? { $float: "inf" } : v === -Infinity ? { $float: "-inf" } : v;
  if (v instanceof TomlDate) {
    if (v.isDateTime() && !v.isLocal()) return { $datetime: new Date(v.getTime()).toISOString() };
    if (v.isDateTime()) return { "$local-datetime": v.toISOString() };
    if (v.isDate()) return { $date: v.toISOString() };
    return { $time: v.toISOString() };
  }
  if (Array.isArray(v)) return v.map(norm);
  if (typeof v === "object" && v !== null) return Object.fromEntries(Object.keys(v).map((k) => [k, norm(get(v as Record<string, unknown>, k))]));
  return v;
}

function walkFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walkFiles(p) : [p];
  });
}

/**
 * Inputs whose reading may differ: smol-toml accepts TOML 1.1 and an impossible date that tomllib (TOML 1.0) refuses,
 * and keeps a CRLF inside a multi-line string where tomllib reads "\n" ("differs": both read it, to different values).
 */
const EDGE: { name: string; text: string; outcome: "agree" | "superset" | "agree-or-superset" | "differs" }[] = [
  { name: "64-bit integers", text: "a = 9223372036854775807\nb = -9223372036854775808\nc = 0x7fffffffffffffff\nd = 9007199254740991\n", outcome: "agree" },
  { name: "floats", text: "a = inf\nb = -inf\nc = nan\nd = 1e300\ne = -0.0\nf = 6.02e23\n", outcome: "agree" },
  { name: "date-times", text: "a = 1979-05-27T07:32:00Z\nb = 1979-05-27T00:32:00.999999-07:00\nc = 1979-05-27T07:32:00\nd = 1979-05-27\ne = 07:32:00.5\nf = 1979-05-27 07:32:00Z\n", outcome: "agree" },
  { name: "strings", text: 'a = "\\u00e9\\U0001F600\\t"\nb = """\nx \\\n  y"""\nc = \'\'\'raw \\n\'\'\'\n"quoted.key" = 1\n', outcome: "agree" },
  { name: "unsafe keys", text: '__proto__ = 1\nconstructor = 2\n[toString]\nx = 1\n', outcome: "agree" },
  { name: "CRLF", text: "a = 1\r\nb = [\r\n  1,\r\n]\r\n", outcome: "agree" },
  { name: "bare CR", text: "a = 1\rb = 2\n", outcome: "agree" },
  { name: "NUL in a string", text: 'a = "x\u0000y"\n', outcome: "agree" },
  { name: "control character in a comment", text: "a = 1 # \u0001\n", outcome: "agree" },
  { name: "duplicate key", text: "a = 1\na = 2\n", outcome: "agree" },
  { name: "BOM", text: "\ufeffa = 1\n", outcome: "agree" },
  { name: "TOML 1.1 newline in an inline table", text: "a = {\n  b = 1,\n}\n", outcome: "agree-or-superset" },
  { name: "TOML 1.1 \\e escape", text: 'a = "\\e"\n', outcome: "agree-or-superset" },
  { name: "TOML 1.1 \\x escape", text: 'a = "\\x41"\n', outcome: "agree-or-superset" },
  { name: "TOML 1.1 time without seconds", text: "a = 2024-01-01T10:20Z\n", outcome: "agree-or-superset" },
  { name: "TOML 1.1 trailing comma in an inline table", text: "a = { b = 1, }\n", outcome: "agree-or-superset" },
  { name: "an impossible date", text: "a = 2024-02-30\n", outcome: "superset" },
  { name: "February 29 of a common year", text: "a = 2023-02-29\n", outcome: "superset" },
  { name: "an impossible date in a date-time", text: "a = 2024-02-30T00:00:00Z\n", outcome: "superset" },
  { name: "CRLF in a multi-line basic string", text: 'a = """x\r\ny"""\n', outcome: "differs" },
  { name: "CRLF in a multi-line literal string", text: "a = '''x\r\ny'''\n", outcome: "differs" },
];

test("differential: TOML read by smol-toml equals tomllib's reading, for every TOML fixture", (t) => {
  const py = needPython(t, "the TOML differential");
  if (!py) return;
  const files = walkFiles(join(PY, "locks")).filter((f) => /\.(toml|lock)$/.test(f));
  assert.ok(files.length > 40, `${files.length} TOML fixtures`);
  const theirs = JSON.parse(python(py, TOMLLIB, JSON.stringify(files))) as Record<string, { doc?: unknown; error?: string }>;
  let agreed = 0;
  for (const f of files) {
    const ours = readToml(f);
    const name = relative(ROOT, f).split(sep).join("/");
    const them = theirs[f]!;
    if ("problem" in ours) {
      assert.ok(them.error !== undefined, `${name}: we refuse it (${ours.problem}) but tomllib reads it`);
    } else {
      assert.equal(them.error, undefined, `${name}: tomllib refuses it (${them.error}) but we read it`);
      assert.deepEqual(norm(ours.doc), them.doc, name);
      agreed++;
    }
  }
  assert.ok(agreed > 30, `${agreed} fixtures read alike (python3 ${py.path} ${py.version})`);
});

test("differential: TOML edge cases agree with tomllib, or are a documented superset or difference", (t) => {
  const py = needPython(t, "the TOML edge-case differential");
  if (!py) return;
  const dir = mkdtempSync(join(tmpdir(), "ws-tomldiff-"));
  const paths = EDGE.map((e, i) => {
    const p = join(dir, `${i}.toml`);
    writeFileSync(p, e.text);
    return p;
  });
  const theirs = JSON.parse(python(py, TOMLLIB, JSON.stringify(paths))) as Record<string, { doc?: unknown; error?: string }>;
  EDGE.forEach((e, i) => {
    const ours = parseToml(e.text);
    const them = theirs[paths[i]!]!;
    const agree = "problem" in ours ? them.error !== undefined : them.error === undefined && JSON.stringify(norm(ours.doc)) === JSON.stringify(them.doc);
    const superset = !("problem" in ours) && them.error !== undefined;
    if (e.outcome === "agree") assert.ok(agree, `${e.name}: ours ${JSON.stringify("problem" in ours ? ours.problem : norm(ours.doc))}, tomllib ${JSON.stringify(them)}`);
    else if (e.outcome === "superset") assert.ok(superset, `${e.name}: expected smol-toml to accept and tomllib to refuse`);
    else if (e.outcome === "differs") assert.ok(!("problem" in ours) && them.error === undefined && !agree, `${e.name}: expected both to read it, to different values: ours ${JSON.stringify("problem" in ours ? ours.problem : norm(ours.doc))}, tomllib ${JSON.stringify(them)}`);
    else assert.ok(agree || superset, `${e.name}: ours ${JSON.stringify("problem" in ours ? ours.problem : norm(ours.doc))}, tomllib ${JSON.stringify(them)}`);
  });
});

/* ---- PEP 440 vs packaging ---- */

test("differential: PEP 440 canonical forms and ordering equal pip's vendored packaging", (t) => {
  const py = needPython(t, "the PEP 440 differential");
  if (!py) return;
  if (!py.pip) {
    if (process.env["WORMSIGN_REQUIRE_PYTHON"] === "1") assert.fail(`WORMSIGN_REQUIRE_PYTHON=1 but ${py.path} ${py.version} has no pip`);
    t.skip(`the PEP 440 differential skipped: ${py.path} ${py.version} has no pip (pip._vendor.packaging)`);
    return;
  }
  const [pipVersion, packagingVersion] = python(py, "import pip, pip._vendor.packaging as p\nprint(pip.__version__, p.__version__)", "").trim().split(" ");
  t.diagnostic(`compared with pip ${pipVersion}'s vendored packaging ${packagingVersion} (${py.path} ${py.version}); src/python/pep440.ts follows packaging 26.2`);
  let seed = 7;
  const r = (): number => ((seed = (seed * 1664525 + 1013904223) >>> 0), seed / 2 ** 32);
  const alphabet = "0123456789.!+-_abcdeilnoprstvABC";
  const inputs = new Set(["1.0", "1.0.0", "1!0", "1.0-1", "1.0.post", "1.0+ABC.01", "v1.0", "1.0c1", "1.0preview2", "1.0_dev_3", "01.0", "1.0rev"]);
  while (inputs.size < 8000) inputs.add(Array.from({ length: 1 + Math.floor(r() * 10) }, () => alphabet[Math.floor(r() * alphabet.length)]).join(""));
  const list = [...inputs];
  const theirs = JSON.parse(
    python(py, "import json, sys\nfrom pip._vendor.packaging.version import Version, InvalidVersion\ndef c(s):\n    try: return str(Version(s))\n    except InvalidVersion: return None\njson.dump([c(s) for s in json.load(sys.stdin)], sys.stdout)", JSON.stringify(list)),
  ) as (string | null)[];
  list.forEach((s, i) => assert.equal(canonicalVersion(s) ?? null, theirs[i], JSON.stringify(s)));
  const valid = list.filter((s) => canonicalVersion(s) !== undefined);
  assert.ok(valid.length > 300, `${valid.length} valid versions`);
  const pairs = valid.slice(0, 400).flatMap((a, i) => valid.slice(i + 1, i + 20).map((b) => [a, b]));
  const order = JSON.parse(
    python(py, "import json, sys\nfrom pip._vendor.packaging.version import Version\njson.dump([(Version(a) > Version(b)) - (Version(a) < Version(b)) for a, b in json.load(sys.stdin)], sys.stdout)", JSON.stringify(pairs)),
  ) as number[];
  pairs.forEach(([a, b], i) => assert.equal(Math.sign(compareVersions(parseVersion(a!)!, parseVersion(b!)!)), order[i], `${a} vs ${b}`));
});

/* ---- PEP 723 vs recorded uv ---- */

test("differential: script blocks read as uv 0.10.9 and 0.12.21 read them, or refused where readers differ", () => {
  const reads = JSON.parse(readFileSync(join(PY, "locks", "forged", "uv-script-reads.json"), "utf8")) as Record<string, Record<string, { exit: number; requirements?: string[]; error?: string }>>;
  // A tag line uv does not use, which Python's own reading (universal newlines, the PEP's regex) sees as a block.
  const STRICTER = new Set(["script-bare-cr.py", "script-tag-in-string.py"]);
  const dir = join(PY, "locks", "forged", "scripts");
  assert.deepEqual(readdirSync(dir).sort(), Object.keys(reads).sort());
  for (const [file, byUv] of Object.entries(reads)) {
    const ours = parseScriptBlock(readFileSync(join(dir, file)));
    const uvs = Object.values(byUv);
    const agree = uvs.every((u) => JSON.stringify(u) === JSON.stringify(uvs[0]));
    if (!agree || uvs.some((u) => u.exit !== 0) || STRICTER.has(file)) {
      assert.equal(ours.kind, "problem", `${file}: uv ${JSON.stringify(byUv)}`);
      continue;
    }
    const deps = uvs[0]!.requirements!;
    if (deps.length === 0) assert.equal(ours.kind, "none", `${file}: uv reads no block`);
    else {
      assert.equal(ours.kind, "block", file);
      const listed = ours.kind === "block" ? (get(ours.metadata, "dependencies") as string[]) : [];
      assert.deepEqual(listed.map((d) => d.split(/[=<>!~ ;[]/)[0]!.toLowerCase()).sort(), deps, file);
    }
  }
});
