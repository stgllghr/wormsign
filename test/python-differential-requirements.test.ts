/**
 * Differential test of the requirements reader (src/python/requirements.ts) against what pip 26.2.1's own parser read
 * in each corpus file and what `uv pip sync --dry-run` of uv 0.10.9 and 0.12.21 would install from it, both recorded
 * by scripts/gen-py-fixtures.sh (test/fixtures/python/requirements) and compared offline, so no python3 is needed.
 * When WORMSIGN_PIP_REF names a virtual environment, its pip re-reads the corpus live with the same recorder.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { CONTINUED_COMMENT, CONTINUED_SHAPE, preprocessRequirements, readRequirements, type RequirementsUnit } from "../src/python/requirements.js";
import { refusedByPipAndUv } from "../src/python/scripts.js";

const ROOT = join(import.meta.dirname, "..", "..");
const PY = join(ROOT, "test", "fixtures", "python");
const CORPUS = join(PY, "requirements", "corpus");

function walkFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walkFiles(p) : [p];
  });
}

interface PipLine {
  file: string;
  line: number;
  args: string;
  requirement: string | null;
  constraint: boolean;
  opts: Record<string, unknown>;
}
type PipFile = { lines: PipLine[]; require_hashes: boolean } | { error: string };
interface UvRead {
  exit: number;
  install: string[];
  warnings: string[];
  error: string | null;
}
const PIP = JSON.parse(readFileSync(join(PY, "requirements", "pip-26.2.1.json"), "utf8")) as { pip: string; files: Record<string, PipFile> };
const UV = JSON.parse(readFileSync(join(PY, "requirements", "uv-pip-sync.json"), "utf8")) as { uv: string[]; files: Record<string, Record<string, UvRead>> };

/**
 * How the reader's verdict relates to pip's reading of each corpus file:
 * - agree: a hash lock, read line for line as pip reads it;
 * - rule: read line for line as pip reads it, and refused by the lock rule;
 * - stricter: pip reads it, the reader refuses it (the reason is the comment);
 * - pip-rejects: pip's parser refuses it, and so does the reader;
 * - empty: nothing but comments and blank lines.
 */
const RELATION: Record<string, "agree" | "rule" | "stricter" | "pip-rejects" | "empty"> = {
  "lock-uv-pip-compile.txt": "agree", "lock-uv-export.txt": "agree", "lock-one-line.txt": "agree", "lock-crlf.txt": "agree", "lock-utf8-bom.txt": "agree",
  "lock-coding-utf8.txt": "agree", "lock-continuation.txt": "agree", "lock-extras-marker.txt": "agree", "lock-spaces-around-eq.txt": "agree",
  "lock-hash-space-value.txt": "agree", "lock-include.txt": "agree", "lock-constraint.txt": "agree",
  "lock-require-hashes-in-include.txt": "agree", "lock-only-require-hashes.txt": "agree", "lock-comments.txt": "agree", "lock-trailing-backslash-eof.txt": "agree",
  "comment-ends-with-backslash.txt": "agree", "env-var-in-comment.txt": "agree",
  "included/with-require-hashes.txt": "agree", "included/require-hashes-only.txt": "agree",
  "empty-comments.txt": "empty", "empty-file.txt": "empty",
  "no-require-hashes.txt": "rule", "unhashed-line.txt": "rule", "unpinned.txt": "rule", "wildcard.txt": "rule", "triple-equals.txt": "rule",
  "local-version.txt": "rule", "sha512-only.txt": "rule", "uppercase-hash.txt": "rule", "url-line.txt": "rule", "vcs-line.txt": "rule", "path-line.txt": "rule",
  "hash-on-own-line.txt": "rule", "tab-before-hash.txt": "rule", "included/base.txt": "rule", "included/constraints.txt": "rule",
  "mixed-hashes.txt": "rule", "require-hashes-in-constraint.txt": "rule", "require-hashes-in-include-unhashed.txt": "rule", "included/=eq.txt": "rule", "included/eq.txt": "rule",
  "included/hash#x.txt": "rule", "included/hash": "rule", "included/constraint-with-r.txt": "rule", "included/reqs-in-constraint.txt": "rule",
  // "${" is refused before parsing: pip would substitute an environment variable there.
  "env-var.txt": "stricter",
  // A continued line outside the shape pip-compile writes (a requirement ending in " \\", then --hash=sha256: lines;
  // requirements.ts continuation): a doubled "\\", a comment line inside the continuation.
  "double-backslash.txt": "stricter", "continuation-broken-by-comment.txt": "stricter",
  // Options a lock may not use; pip reads them (and applies them to the index, build or install).
  "index-url.txt": "stricter", "extra-index-url.txt": "stricter", "find-links.txt": "stricter", "no-index.txt": "stricter", "trusted-host.txt": "stricter",
  "no-binary.txt": "stricter", "only-binary.txt": "stricter", "prefer-binary.txt": "stricter", "config-settings.txt": "stricter", "editable.txt": "stricter",
  // pip ignores these options where they are, or the text after them; the reader refuses instead of ignoring.
  "include-and-require-hashes.txt": "stricter", "include-twice-on-a-line.txt": "stricter", "require-hashes-on-requirement-line.txt": "stricter",
  "include-on-requirement-line.txt": "stricter", "hash-before-requirement.txt": "stricter", "leftover-text.txt": "stricter", "double-dash.txt": "stricter",
  // Shell quoting and abbreviated option names pip's optparse accepts.
  "quoted-hash.txt": "stricter", "abbreviated-hash.txt": "stricter", "abbreviated-require-hashes.txt": "stricter",
  // Text pip splits or decodes where uv does not (uv-pip-sync.json shows uv's reading), or that pip would decode with another encoding.
  "nbsp-before-comment.txt": "stricter", "sep-bare-cr.txt": "stricter", "sep-form-feed.txt": "stricter", "sep-vertical-tab.txt": "stricter", "sep-next-line.txt": "stricter",
  "sep-line-separator.txt": "stricter", "sep-file-separator.txt": "stricter", "sep-escape-control.txt": "stricter", "utf16.txt": "stricter", "nul-byte.txt": "stricter",
  "coding-latin1.txt": "stricter",
  // Whitespace Python and JavaScript disagree on (pip strips U+001F and U+00A0, not U+FEFF), and control characters.
  "ws-unit-separator.txt": "stricter", "ws-unit-separator-comment.txt": "stricter", "ws-bom-middle.txt": "stricter", "ws-bom-comment.txt": "stricter",
  "ws-nbsp-start.txt": "stricter", "ws-em-space-start.txt": "stricter", "ctl-start-of-heading.txt": "stricter", "ctl-delete.txt": "stricter",
  // Includes pip and uv read differently (uv-pip-sync.json shows uv reading another file, or refusing the line).
  "include-attached.txt": "stricter", "include-equals.txt": "stricter", "included/equals.txt": "stricter", "include-hash-in-path.txt": "stricter",
  "requirements-in-constraint.txt": "stricter",
  "include-cycle.txt": "pip-rejects", "included/cycle-a.txt": "pip-rejects", "included/cycle-b.txt": "pip-rejects", "include-missing.txt": "pip-rejects",
  "include-outside.txt": "pip-rejects", "include-url.txt": "pip-rejects", "md5-hash.txt": "pip-rejects", "invalid-utf8.txt": "pip-rejects",
};

/** The reader's lines in pip's shape: requirement text and the --hash / --require-hashes options. */
function ourLines(u: RequirementsUnit): { file: string; line: number; args: string; opts: Record<string, unknown> }[] {
  return u.lines.map((l) => {
    const opts: Record<string, unknown> = {};
    for (const o of l.options) {
      if (o.name === "hash") {
        const [alg, digest] = [o.value!.slice(0, o.value!.indexOf(":")), o.value!.slice(o.value!.indexOf(":") + 1)];
        const h = (opts["hashes"] ??= {}) as Record<string, string[]>;
        (h[alg] ??= []).push(digest);
      } else if (o.name === "require-hashes") opts["require_hashes"] = true;
    }
    return { file: l.file, line: l.line, args: l.args, opts };
  });
}
const pipLines = (f: { lines: PipLine[] }) => f.lines.map((l) => ({ file: l.file, line: l.line, args: l.args, opts: l.opts }));

test("differential: requirements files read as pip 26.2.1 reads them, or refused for a stated reason", () => {
  assert.equal(PIP.pip, "26.2.1");
  const corpus = walkFiles(CORPUS).map((f) => relative(CORPUS, f).split(sep).join("/")).sort();
  assert.deepEqual(Object.keys(PIP.files).sort(), corpus, "pip-26.2.1.json covers the corpus (scripts/gen-py-fixtures.sh)");
  assert.deepEqual(Object.keys(RELATION).sort(), corpus, "every corpus file has a stated relation");
  for (const [file, relation] of Object.entries(RELATION)) {
    const ours = readRequirements(CORPUS, file);
    const pip = PIP.files[file]!;
    if (relation === "pip-rejects") {
      assert.ok("error" in pip, `${file}: pip read it`);
      assert.ok(ours.problems.length > 0, `${file}: pip refuses it (${"error" in pip ? pip.error : ""}) but the reader does not`);
      continue;
    }
    assert.ok(!("error" in pip), `${file}: pip refused it: ${"error" in pip ? pip.error : ""}`);
    if (relation === "empty") {
      assert.ok(ours.empty && pip.lines.length === 0, file);
    } else if (relation === "stricter") {
      assert.ok(ours.problems.length > 0, `${file}: expected a problem`);
    } else {
      assert.deepEqual(ourLines(ours), pipLines(pip), `${file}: line for line as pip reads it`);
      if (relation === "rule") assert.ok(ours.problems.length > 0, `${file}: the lock rule refuses it`);
      else {
        assert.deepEqual(ours.problems, [], file);
        assert.equal(pip.require_hashes, true, `${file}: pip runs in --require-hashes mode`);
        const pipReqs = pip.lines.filter((l) => l.requirement !== null).map((l) => `${l.requirement!.replace(/\s+/g, "").replace(/;.*$/, "")}`);
        assert.deepEqual(ours.entries.map((e) => `${e.name}${e.extras.length ? `[${e.extras.join(",")}]` : ""}==${e.rawVersion}`), pipReqs.map((r) => r.toLowerCase()), file);
      }
    }
  }
});

test("differential: what uv 0.10.9 and 0.12.21 install from each lock is what the reader read, or nothing", () => {
  assert.deepEqual(UV.uv, ["0.10.9", "0.12.21"]);
  for (const [file, relation] of Object.entries(RELATION)) {
    if (relation !== "agree") continue;
    const ours = readRequirements(CORPUS, file);
    const want = ours.entries.filter((e) => !e.constraint).map((e) => `${e.name}==${e.version}`).sort();
    for (const v of UV.uv) {
      const got = UV.files[file]![`uv-${v}`]!;
      // uv may refuse a file pip reads (fail closed); it must never install something else.
      if (got.exit === 0) assert.deepEqual(got.install, want, `${file}: uv ${v} would install ${JSON.stringify(got.install)}`);
      else assert.deepEqual(got.install, [], file);
      if (v === "0.10.9" && ours.requireHashes && got.exit === 0) {
        assert.ok(got.warnings.some((w) => /Ignoring unsupported option .*--require-hashes/.test(w)), `${file}: uv 0.10.9 ignores --require-hashes in a file (Limitation 2)`);
      }
    }
  }
  // Files refused as text pip and uv read differently: the recordings show that they do.
  const whitespace = ["ws-unit-separator.txt", "ws-unit-separator-comment.txt", "ws-bom-middle.txt", "ws-bom-comment.txt", "ws-nbsp-start.txt", "ws-em-space-start.txt", "ctl-start-of-heading.txt", "ctl-delete.txt"];
  for (const file of ["sep-form-feed.txt", "sep-vertical-tab.txt", "sep-next-line.txt", "sep-line-separator.txt", "sep-file-separator.txt", "sep-escape-control.txt", "nbsp-before-comment.txt", "tab-before-hash.txt", ...whitespace]) {
    const pip = PIP.files[file] as { lines: PipLine[] };
    const pipReqs = pip.lines.filter((l) => l.requirement !== null).map((l) => l.requirement!).sort();
    const reads = UV.uv.map((v) => UV.files[file]![`uv-${v}`]!);
    const differs = reads.some((r) => r.exit !== 0 || JSON.stringify(r.install) !== JSON.stringify(pipReqs));
    assert.ok(differs, `${file}: pip and uv read it alike, so the reason given for refusing it is wrong`);
  }
});

/** Every corpus file pip's parser reads (no error): discovery must never take one as refused by pip and uv. */
function assertNotRefusedWherePipReads(files: Record<string, PipFile>, by: string): void {
  let read = 0;
  for (const [file, pip] of Object.entries(files)) {
    if ("error" in pip) continue;
    read++;
    assert.ok(!refusedByPipAndUv(readFileSync(join(CORPUS, file))), `${file}: ${by} reads it, but refusedByPipAndUv says pip refuses it`);
  }
  assert.ok(read > 90, `${read} files read`);
}

test("differential: refusedByPipAndUv is false for every corpus file pip 26.2.1's parser reads", () => {
  assertNotRefusedWherePipReads(PIP.files, "pip 26.2.1");
  // pip strips the U+001F: idna is read on line 3, as typed after the character.
  const unit = PIP.files["ws-unit-separator.txt"] as { lines: PipLine[] };
  assert.deepEqual(unit.lines.map((l) => l.requirement), [null, "six==1.17.0", "idna==3.10"]);
  // A comment line after a U+001F is not joined to the next: six is still read.
  assert.deepEqual((PIP.files["ws-unit-separator-comment.txt"] as { lines: PipLine[] }).lines.map((l) => l.requirement), [null, "six==1.17.0"]);
});

test("differential: the includes refused as read differently are read differently by pip and uv, as recorded", () => {
  const pipReqs = (file: string) => (PIP.files[file] as { lines: PipLine[] }).lines.filter((l) => l.requirement !== null).map((l) => [l.file, l.requirement, l.constraint]);
  const uv = (file: string, v: string) => UV.files[file]![`uv-${v}`]!;
  // "-r=eq.txt" and "-r hash#x.txt": pip reads one file, both uvs install from another.
  assert.deepEqual(pipReqs("include-equals.txt"), [["included/=eq.txt", "six==1.17.0", false]]);
  assert.deepEqual(pipReqs("include-hash-in-path.txt"), [["included/hash#x.txt", "six==1.17.0", false]]);
  for (const v of UV.uv) {
    for (const file of ["include-equals.txt", "include-hash-in-path.txt"]) assert.deepEqual([uv(file, v).exit, uv(file, v).install], [0, ["idna==3.10"]], `${file} with uv ${v}`);
    // "-rfile": pip reads it, uv refuses it.
    assert.match(uv("include-attached.txt", v).error!, /Expected '=' or whitespace/, `uv ${v}`);
    // -r in a file reached through -c: pip installs idna, uv only constrains it.
    assert.deepEqual(uv("requirements-in-constraint.txt", v).install, ["six==1.17.0"], `uv ${v}`);
  }
  assert.deepEqual(pipReqs("include-attached.txt"), [["included/base.txt", "six==1.17.0", false]]);
  assert.deepEqual(pipReqs("requirements-in-constraint.txt"), [["requirements-in-constraint.txt", "six==1.17.0", false], ["included/reqs-in-constraint.txt", "idna==3.10", false]]);
  // --require-hashes in a file reached with -r makes uv 0.12.21 refuse an unhashed requirement; with -c it does not.
  assert.match(uv("require-hashes-in-include-unhashed.txt", "0.12.21").error!, /In `--require-hashes` mode, all requirements must have a hash/);
  assert.deepEqual([uv("require-hashes-in-constraint.txt", "0.12.21").exit, uv("require-hashes-in-constraint.txt", "0.12.21").install], [0, ["six==1.17.0"]]);
  for (const file of ["require-hashes-in-include-unhashed.txt", "require-hashes-in-constraint.txt"]) assert.equal((PIP.files[file] as { require_hashes: boolean }).require_hashes, true, `pip honours it in ${file}`);
});

test('differential: a line continued with "\\" is read only in the shape pip-compile writes; the rest, which pip and uv can read apart, is refused', () => {
  // Recorded with the pip and uv on hand (readings.json says which), offline, against wheels of the same names: what
  // each reads or installs. pip joins every continued line to the next; uv reads some up to the line break.
  const dir = join(PY, "requirements", "continued");
  type Reading = { pip: { requirements: string[] } | { error: string }; uv: UvRead };
  const rec = JSON.parse(readFileSync(join(dir, "readings.json"), "utf8")) as { files: Record<string, Reading> };
  assert.deepEqual(Object.keys(rec.files).sort(), [...readdirSync(dir).filter((f) => f.endsWith(".txt")), "include/requirements.txt"].sort(), "readings.json covers the directory");
  const pipNames = (r: Reading): string[] | undefined => ("error" in r.pip ? undefined : r.pip.requirements.map((q) => q.split(/[ ;=@]/)[0]!).sort());
  const uvNames = (r: Reading): string[] => r.uv.install.map((q) => q.split(/[ =@]/)[0]!).sort();
  const COMMENT = /: a comment \("#" at the start or after a space\) on a line that ends in "\\": pip joins the next line into the comment, .* uv ends the comment at the line break and reads the next line on its own; put the comment on a line of its own/;
  const GLUED = /: a "\\" with no space before it at the end of a line: pip joins the next line to the text before it, .* uv does not join them and reads the next line on its own; write the requirement and its --hash options on one line/;
  const OPTION = /: an option on a line that ends in "\\": pip joins the next line to it, while uv reads the option's value to the line break, .*; write the option and its value on one line, with no "\\"/;
  const SHAPE = /: a line continued with "\\" outside the shape pip-compile and uv pip compile write \(a requirement ending in " \\", then --hash=sha256:<64 hex digits> lines\): pip joins every such line to the next, while uv reads some up to the line break/;
  const refused: [string, RegExp, number][] = [
    ["space-before-hash.txt", COMMENT, 2],
    ["tab-before-hash.txt", COMMENT, 2],
    ["middle-line.txt", SHAPE, 3],
    ["no-space-before-hash.txt", GLUED, 2],
    ["glued-hash.txt", GLUED, 2],
    // six's sdist hash split before its last four digits: pip reads the whole hash, uv installs "c926".
    ["split-hash.txt", GLUED, 2],
    // pip refuses "--require-hashesevil==0.0.1"; uv installs evil.
    ["glued-require-hashes.txt", OPTION, 1],
    // "-r a.txt \\": pip reads a.txt (six), uv the file "a.txt " (evil), made beside it when recorded.
    ["include/requirements.txt", OPTION, 2],
  ];
  for (const [file] of refused) {
    const r = rec.files[file]!;
    assert.equal(r.uv.exit, 0, file);
    assert.notDeepEqual(pipNames(r), uvNames(r), `${file}: pip and uv read it differently`);
  }
  // Read alike, and refused all the same: outside the allowed shape, whatever follows.
  const alike: [string, RegExp, number][] = [
    ["end-of-file.txt", COMMENT, 2],
    ["glued-version.txt", GLUED, 1],
    ["comment-line-ending-in-backslash.txt", SHAPE, 3],
  ];
  for (const [file] of alike) assert.deepEqual(pipNames(rec.files[file]!), uvNames(rec.files[file]!), file);
  for (const [file, message, line] of [...refused, ...alike]) {
    const ours = readRequirements(dir, file);
    assert.deepEqual(ours.entries, [], file);
    assert.equal(ours.problems.length, 1, `${file}: ${ours.problems.join("\n")}`);
    assert.match(ours.problems[0]!, message, file);
    assert.ok(ours.problems[0]!.startsWith(`${file}:${line}: `), ours.problems[0]);
  }
  // In the allowed shape, or not continued, and read as pip reads them: uv agrees. A "#" inside a value (a quoted
  // marker, a URL fragment) starts no comment for either.
  for (const file of ["quoted-marker.txt", "url-fragment.txt"]) {
    const r = rec.files[file]!;
    assert.deepEqual(pipNames(r), uvNames(r), `${file}: pip and uv read it alike`);
    const ours = readRequirements(dir, file);
    assert.ok(!ours.problems.some((p) => [COMMENT, GLUED, OPTION, SHAPE].some((re) => re.test(p))), `${file}: ${ours.problems.join("\n")}`);
    assert.deepEqual(ours.lines.filter((l) => l.args !== "").map((l) => l.line), file === "quoted-marker.txt" ? [2, 4] : [1, 3], file);
  }
  // pip strips a continued line's leading "\\", so "\\# c \\" starts a comment that takes in the next line (uv
  // refuses the "\\"); a "#" glued inside a value on a " \\" line starts none.
  assert.deepEqual(preprocessRequirements("six==1.16.0 \\\n\\# c \\\nevil==0.0.1\n"), { problem: CONTINUED_SHAPE, line: 2, fix: 'write the requirement and its --hash options on one line, or continue it as pip-compile does (" \\", then --hash=sha256: lines)' });
  assert.deepEqual(preprocessRequirements("\\# c \\\nevil==0.0.1\n"), { problem: CONTINUED_COMMENT, line: 1, fix: "put the comment on a line of its own" });
  const marker = readRequirements(dir, "quoted-marker.txt");
  assert.deepEqual([marker.problems, marker.entries.map((e) => `${e.name}==${e.version}${e.marker ? ` ; ${e.marker}` : ""}`)], [[], ["six==1.16.0 ; sys_platform != '#x'", "evil==0.0.1"]]);
});

test("differential: live pip re-reads the corpus as recorded (only when WORMSIGN_PIP_REF names a venv)", (t) => {
  const venv = process.env["WORMSIGN_PIP_REF"];
  if (!venv) {
    t.skip("WORMSIGN_PIP_REF is not set: compared with the recorded pip-26.2.1.json only");
    return;
  }
  const python = join(venv, process.platform === "win32" ? "Scripts" : "bin", process.platform === "win32" ? "python.exe" : "python");
  const version = spawnSync(python, ["-m", "pip", "--version"], { encoding: "utf8" });
  assert.equal(version.status, 0, `${python}: ${version.stderr}`);
  // The recorder is the one scripts/gen-py-fixtures.sh runs, taken from the script itself.
  const gen = readFileSync(join(ROOT, "scripts", "gen-py-fixtures.sh"), "utf8");
  const m = /pip-\$PIP_VERSION\.json" <<'PY'\n([\s\S]*?)\nPY\n/.exec(gen);
  assert.ok(m, "the pip recorder in scripts/gen-py-fixtures.sh");
  const r = spawnSync(python, ["-", CORPUS], { input: m[1], encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  assert.equal(r.status, 0, r.stderr);
  const live = JSON.parse(r.stdout) as { files: Record<string, PipFile> };
  assert.deepEqual(live.files, PIP.files, `${version.stdout.trim()} reads the corpus as recorded`);
  assertNotRefusedWherePipReads(live.files, version.stdout.trim());
});

