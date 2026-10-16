/**
 * The requirements reader (src/python/requirements.ts) over the corpus in test/fixtures/python/requirements/corpus:
 * which files are hash locks, what they lock, and the problem (with its line) for every file that is not one.
 * test/python-differential.test.ts compares the same corpus with what pip 26.2.1 and uv read.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { decodeRequirements, LOCK_REMEDIATION, MAX_REQUIREMENTS_BYTES, MAX_UNIT_LINES, MAX_UNIT_PROBLEMS, parseLine, preprocessRequirements, readRequirements } from "../src/python/requirements.js";

const CORPUS = join(import.meta.dirname, "..", "..", "test", "fixtures", "python", "requirements", "corpus");
const SIX = ["4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274", "ff70335d468e7eb6ec65b95b99d3a2836546063f63acc5171de367e834932a81"];

/** A lock: the name==version (c) of each entry in order. */
type Expect = { lock: string[] } | "empty" | RegExp;

const EXPECTED: Record<string, Expect> = {
  "lock-uv-pip-compile.txt": { lock: ["idna==3.10", "packaging==25.0", "six==1.17.0"] },
  "lock-uv-export.txt": { lock: ["idna==3.20", "six==1.17.0"] },
  "lock-one-line.txt": { lock: ["six==1.17.0", "idna==3.10", "packaging==25.0"] },
  "lock-crlf.txt": { lock: ["six==1.17.0", "idna==3.10"] },
  "lock-utf8-bom.txt": { lock: ["six==1.17.0"] },
  "lock-coding-utf8.txt": { lock: ["six==1.17.0"] },
  "lock-continuation.txt": { lock: ["six==1.17.0"] },
  "lock-extras-marker.txt": { lock: ["six==1.17.0"] },
  "lock-spaces-around-eq.txt": { lock: ["six==1.17.0"] },
  "lock-hash-space-value.txt": { lock: ["six==1.17.0"] },
  "lock-include.txt": { lock: ["six==1.17.0", "idna==3.10"] },
  "lock-constraint.txt": { lock: ["six==1.17.0", "packaging==25.0 (c)"] },
  "lock-require-hashes-in-include.txt": { lock: ["idna==3.10", "six==1.17.0"] },
  "lock-only-require-hashes.txt": { lock: [] },
  "lock-comments.txt": { lock: ["six==1.17.0"] },
  "lock-trailing-backslash-eof.txt": { lock: ["six==1.17.0"] },
  "comment-ends-with-backslash.txt": { lock: ["six==1.17.0"] },
  // Only " \\" continues a line (requirements.ts continuation): a doubled "\\" is outside the shape pip-compile writes.
  "double-backslash.txt": /^double-backslash\.txt:2: a line continued with "\\" outside the shape pip-compile and uv pip compile write/,
  "env-var-in-comment.txt": { lock: ["six==1.17.0"] },
  "empty-comments.txt": "empty",
  "empty-file.txt": "empty",
  "no-require-hashes.txt": /^no-require-hashes\.txt: no --require-hashes line in the file or the files it includes/,
  "unhashed-line.txt": /^unhashed-line\.txt:3: idna==3\.10 has no --hash=sha256/,
  "unpinned.txt": /^unpinned\.txt:2: "six>=1\.16" is not pinned with a single ==version/,
  "wildcard.txt": /^wildcard\.txt:2: "six==1\.17\.\*" uses a wildcard/,
  "triple-equals.txt": /^triple-equals\.txt:2: "six===1\.17\.0" uses ===/,
  "local-version.txt": /^local-version\.txt:2: .*a local version label/,
  "md5-hash.txt": /^md5-hash\.txt:2: --hash=md5:.*pip accepts only sha256, sha384 and sha512/,
  "sha512-only.txt": /^sha512-only\.txt:2: --hash=sha512:abababababab\.\.\.: pip installs a file that matches any one listed hash, and wormsign binds sha256 digests only/,
  "mixed-hashes.txt": /^mixed-hashes\.txt:2: --hash=sha512:abababababab\.\.\.: pip installs a file that matches any one listed hash, and wormsign binds sha256 digests only, so this one names a file that cannot be bound to an index file/,
  "uppercase-hash.txt": /^uppercase-hash\.txt:2: .*not a lowercase hex sha256 digest/,
  "index-url.txt": /^index-url\.txt:1: option -i is not allowed in a hash lock/,
  "extra-index-url.txt": /^extra-index-url\.txt:1: option --extra-index-url is not allowed/,
  "find-links.txt": /^find-links\.txt:1: option --find-links is not allowed/,
  "no-index.txt": /^no-index\.txt:1: option --no-index is not allowed/,
  "trusted-host.txt": /^trusted-host\.txt:1: option --trusted-host is not allowed/,
  "no-binary.txt": /^no-binary\.txt:1: option --no-binary is not allowed/,
  "only-binary.txt": /^only-binary\.txt:1: option --only-binary is not allowed/,
  "prefer-binary.txt": /^prefer-binary\.txt:1: option --prefer-binary is not allowed/,
  "config-settings.txt": /^config-settings\.txt:2: option --config-settings is not allowed/,
  "editable.txt": /^editable\.txt:2: option -e is not allowed/,
  "url-line.txt": /^url-line\.txt:2: "six @ https:.*" is a URL, VCS or path requirement/,
  "vcs-line.txt": /^vcs-line\.txt:2: "git\+https:.*" is a URL, VCS or path requirement/,
  "path-line.txt": /^path-line\.txt:2: "\.\/vendor\/.*" is a URL, VCS or path requirement/,
  "env-var.txt": /^env-var\.txt:2: "\$\{": pip expands environment variables/,
  "include-outside.txt": /^include-outside\.txt:2: -r \.\.\/outside\.txt is outside the scanned root/,
  "include-missing.txt": /^include-missing\.txt:2: -r included\/missing\.txt: .*not present in the scanned tree \(ENOENT\)/,
  "include-url.txt": /^include-url\.txt:2: -r file:\/\/\/nonexistent\/requirements\.txt includes a file by URL/,
  "include-attached.txt": /^include-attached\.txt:2: -rincluded\/base\.txt: a value attached to -r, which pip and uv read differently \("=" is part of the path to pip and a separator to uv\); write "-r <path>"$/,
  "include-equals.txt": /^included\/equals\.txt:1: -r=eq\.txt: a value attached to -r, which pip and uv read differently/,
  "include-hash-in-path.txt": /^include-hash-in-path\.txt:2: -r included\/hash#x\.txt: a "#" in the path, where uv ends the path and pip does not; rename the file/,
  "requirements-in-constraint.txt": /^included\/constraint-with-r\.txt:1: -r reqs-in-constraint\.txt in a file reached through -c: pip installs its lines as requirements, uv reads them as constraints; include the file with -r/,
  "require-hashes-in-constraint.txt": /^included\/require-hashes-only\.txt:1: --require-hashes only in a file reached through -c, where uv ignores it \(pip does not\); put the --require-hashes line in the requirements file itself$/,
  "require-hashes-in-include-unhashed.txt": /^require-hashes-in-include-unhashed\.txt:1: six==1\.17\.0 has no --hash=sha256/,
  "include-cycle.txt": /^included\/cycle-b\.txt:1: included\/cycle-a\.txt includes itself \(via include-cycle\.txt -> included\/cycle-a\.txt -> included\/cycle-b\.txt -> included\/cycle-a\.txt\)/,
  "include-and-require-hashes.txt": /^include-and-require-hashes\.txt:1: -r or -c shares its line with another option, which pip then ignores/,
  "include-twice-on-a-line.txt": /^include-twice-on-a-line\.txt:2: -r or -c shares its line with another option/,
  "require-hashes-on-requirement-line.txt": /^require-hashes-on-requirement-line\.txt:1: --require-hashes on a requirement line, where pip ignores it/,
  "include-on-requirement-line.txt": /^include-on-requirement-line\.txt:2: --requirement on a requirement line/,
  "hash-before-requirement.txt": /^hash-before-requirement\.txt:2: "six==1\.17\.0" after the options: pip ignores it/,
  "hash-on-own-line.txt": /^hash-on-own-line\.txt:2: six==1\.17\.0 has no --hash=sha256/,
  "continuation-broken-by-comment.txt": /^continuation-broken-by-comment\.txt:3: a line continued with "\\" outside the shape/,
  "quoted-hash.txt": /^quoted-hash\.txt:2: a quote or backslash in the options/,
  "abbreviated-hash.txt": /^abbreviated-hash\.txt:2: option --has is not allowed/,
  "abbreviated-require-hashes.txt": /^abbreviated-require-hashes\.txt:1: option --require-hash is not allowed/,
  "leftover-text.txt": /^leftover-text\.txt:2: "junk" after the options: pip ignores it/,
  "double-dash.txt": /^double-dash\.txt:2: "--": pip ignores everything after it/,
  "tab-before-hash.txt": /^tab-before-hash\.txt:2: .*a tab before an option, which pip reads as part of the requirement and uv as a separator/,
  "nbsp-before-comment.txt": /^nbsp-before-comment\.txt:2: a Unicode space character \(U\+00A0\) that pip reads as whitespace and uv rejects/,
  "sep-bare-cr.txt": /^sep-bare-cr\.txt:1: a carriage return not followed by a line feed: only \\n and \\r\\n line breaks are read/,
  "sep-form-feed.txt": /^sep-form-feed\.txt:2: a line separator pip and uv read differently \(U\+000C\)/,
  "sep-vertical-tab.txt": /^sep-vertical-tab\.txt:2: a line separator pip and uv read differently \(U\+000B\)/,
  "sep-next-line.txt": /^sep-next-line\.txt:2: a line separator pip and uv read differently \(U\+0085\)/,
  "sep-line-separator.txt": /^sep-line-separator\.txt:2: a line separator pip and uv read differently \(U\+2028\)/,
  "sep-file-separator.txt": /^sep-file-separator\.txt:2: a line separator pip and uv read differently \(U\+001C\)/,
  "sep-escape-control.txt": /^sep-escape-control\.txt:2: a control character pip and uv read differently \(U\+001B\)/,
  "ws-unit-separator.txt": /^ws-unit-separator\.txt:3: a control character pip and uv read differently \(U\+001F\)/,
  "ws-unit-separator-comment.txt": /^ws-unit-separator-comment\.txt:2: a control character pip and uv read differently \(U\+001F\)/,
  "ws-bom-middle.txt": /^ws-bom-middle\.txt:3: "\ufeffidna==3\.10" is not a name==version pin/,
  // U+FEFF is not whitespace to pip: line 3 is a requirement, continued onto a line that is not a --hash.
  "ws-bom-comment.txt": /^ws-bom-comment\.txt:4: a line continued with "\\" outside the shape/,
  "ws-nbsp-start.txt": /^ws-nbsp-start\.txt:2: a Unicode space character \(U\+00A0\) that pip reads as whitespace and uv rejects/,
  "ws-em-space-start.txt": /^ws-em-space-start\.txt:2: a Unicode space character \(U\+2003\) that pip reads as whitespace and uv rejects/,
  "ctl-start-of-heading.txt": /^ctl-start-of-heading\.txt:3: a control character pip and uv read differently \(U\+0001\)/,
  "ctl-delete.txt": /^ctl-delete\.txt:2: --hash=sha256:ff70335d468e7eb6ec65b95b99d3a2836546063f63acc5171de367e834932a81\x7f: not a lowercase hex sha256 digest/,
  "utf16.txt": /^utf16\.txt: encoding not supported: it starts with a UTF-16 or UTF-32 byte-order mark/,
  "nul-byte.txt": /^nul-byte\.txt:3: encoding not supported: it contains a NUL byte/,
  "coding-latin1.txt": /^coding-latin1\.txt: encoding not supported: a coding declaration names "latin-1", and pip would decode the file with it/,
  "invalid-utf8.txt": /^invalid-utf8\.txt: encoding not supported: it is not valid UTF-8/,
};

const summary = (rel: string): Expect => {
  const u = readRequirements(CORPUS, rel);
  if (u.empty) return "empty";
  if (u.problems.length > 0) return new RegExp(u.problems.join(" || ").replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  return { lock: u.entries.map((e) => `${e.name}==${e.version}${e.constraint ? " (c)" : ""}`) };
};

test("requirements: every corpus file reads as its expected lock, empty file or problem", () => {
  const files = readdirSync(CORPUS).filter((f) => f.endsWith(".txt")).sort();
  assert.deepEqual(files, Object.keys(EXPECTED).sort(), "every corpus file has an expectation");
  for (const [file, want] of Object.entries(EXPECTED)) {
    const u = readRequirements(CORPUS, file);
    if (want === "empty") {
      assert.ok(u.empty && u.problems.length === 0 && u.entries.length === 0, `${file}: ${JSON.stringify(summary(file))}`);
    } else if (want instanceof RegExp) {
      assert.ok(u.problems.some((p) => want.test(p)), `${file}: ${JSON.stringify(u.problems)}`);
    } else {
      assert.deepEqual(u.problems, [], file);
      assert.deepEqual(summary(file), want, file);
      assert.ok(u.requireHashes !== undefined, `${file}: a lock has --require-hashes`);
      assert.ok(u.entries.every((e) => e.sha256.length > 0 && e.sha256.every((h) => /^[0-9a-f]{64}$/.test(h))), file);
    }
  }
});

test("requirements: a lock records each requirement's file, line, hashes, extras and marker", () => {
  const u = readRequirements(CORPUS, "lock-include.txt");
  assert.deepEqual(u.files, ["lock-include.txt", "included/base.txt"]);
  assert.deepEqual(u.requireHashes, { file: "lock-include.txt", line: 1 });
  assert.deepEqual(u.entries.map((e) => [e.file, e.line, e.name, e.version, e.sha256.length]), [["included/base.txt", 1, "six", "1.17.0", 2], ["lock-include.txt", 3, "idna", "3.10", 2]]);
  assert.deepEqual(readRequirements(CORPUS, "included/base.txt").entries[0]!.sha256.sort(), [...SIX].sort());
  const em = readRequirements(CORPUS, "lock-extras-marker.txt").entries[0]!;
  assert.deepEqual([em.extras, em.marker, em.rawVersion], [["test"], 'python_version >= "3.8"', "1.17.0"]);
  const cont = readRequirements(CORPUS, "lock-continuation.txt").entries[0]!;
  assert.deepEqual([cont.line, cont.sha256.sort()], [2, [...SIX].sort()]);
  const req = readRequirements(CORPUS, "lock-require-hashes-in-include.txt");
  assert.deepEqual(req.requireHashes, { file: "included/with-require-hashes.txt", line: 1 }, "--require-hashes in an included file counts for the unit");
  const viaR = readRequirements(CORPUS, "require-hashes-in-include-unhashed.txt");
  assert.deepEqual(viaR.requireHashes, { file: "included/require-hashes-only.txt", line: 1 }, "reached with -r it counts");
  assert.equal(viaR.problems.length, 1, JSON.stringify(viaR.problems));
  const viaC = readRequirements(CORPUS, "require-hashes-in-constraint.txt");
  assert.equal(viaC.requireHashes, undefined, "reached with -c it does not count");
  assert.ok(!viaC.problems.some((p) => /no --require-hashes line/.test(p)), "the problem names the line that does not count");
  const c = readRequirements(CORPUS, "lock-constraint.txt");
  assert.deepEqual(c.entries.map((e) => [e.name, e.constraint, e.file]), [["six", false, "lock-constraint.txt"], ["packaging", true, "included/constraints.txt"]]);
});

test("requirements: every lock-rule problem says how to fix it", () => {
  for (const file of ["unhashed-line.txt", "index-url.txt", "url-line.txt", "unpinned.txt"]) {
    const u = readRequirements(CORPUS, file);
    assert.ok(u.problems.length > 0 && u.problems.every((p) => p.endsWith(`; ${LOCK_REMEDIATION}`)), `${file}: ${JSON.stringify(u.problems)}`);
  }
  // Every requirement already has its hashes: the missing line alone is the fix, so it comes first, regenerating second.
  const hashed = readRequirements(CORPUS, "no-require-hashes.txt");
  assert.deepEqual(hashed.problems, [`no-require-hashes.txt: no --require-hashes line in the file or the files it includes; add a \`--require-hashes\` line at the top of no-require-hashes.txt, or ${LOCK_REMEDIATION}`]);
  assert.deepEqual(hashed.lockRule, ["file"], "still the lock rule's file problem");
  // A requirement without a hash as well: the line alone is not enough, so the fix is the hash lock.
  const dir = mkdtempSync(join(tmpdir(), "wormsign-req-remedy-"));
  writeFileSync(join(dir, "requirements.txt"), "six==1.17.0 --hash=sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274\nidna==3.10\n");
  const partly = readRequirements(dir, "requirements.txt");
  assert.deepEqual(partly.lockRule, ["line", "file"]);
  assert.ok(partly.problems.every((p) => p.endsWith(`; ${LOCK_REMEDIATION}`) && !p.includes("at the top of")), JSON.stringify(partly.problems));
  assert.match(LOCK_REMEDIATION, /uv pip compile --generate-hashes.*pip-compile --generate-hashes.*--require-hashes/);
  assert.match(readRequirements(CORPUS, "sep-form-feed.txt").problems[0]!, /; save it as UTF-8 with \\n or \\r\\n line endings$/);
});

test("requirements: pip's text rules, step by step", () => {
  const lines = (text: string) => {
    const r = preprocessRequirements(text);
    assert.ok("lines" in r, JSON.stringify(r));
    return r.lines.map((l) => [l.line, l.text]);
  };
  const hash = "--hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  assert.deepEqual(lines(`a \\\n  ${hash} \\\n    ${hash}\nc\n`), [[1, `a   ${hash}     ${hash}`], [4, "c"]], "continuation keeps the first line's number");
  assert.deepEqual(lines(`a \\\r\n  ${hash}\r\n`), [[1, `a   ${hash}`]], "CRLF");
  assert.deepEqual(lines(`a \\`), [[1, "a"]], "a requirement continued at the end of the file");
  assert.deepEqual(lines("# c \\\nd\n"), [[2, "d"]], "a comment line ending in \"\\\" continues nothing");
  // Any other continued line is refused (an allowlist): pip joins it, uv may read it up to the line break.
  const refused = (text: string, line: number, re: RegExp) => {
    const r = preprocessRequirements(text);
    assert.ok("problem" in r && r.line === line && re.test(r.problem), `${JSON.stringify(text)}: ${JSON.stringify(r)}`);
  };
  for (const [text, line, re] of [
    ["a \\\n  b\n", 2, /outside the shape/],
    ["a \\\n# c\nd\n", 2, /outside the shape/],
    ["a \\\n\nd\n", 2, /outside the shape/],
    [`a \\\n  ${hash.toUpperCase().replace("--HASH=SHA256", "--hash=sha256")}\n`, 2, /outside the shape/],
    [`a \\\n  ${hash} # c\n`, 2, /outside the shape/],
    [`a \\\n  ${hash}\\\nb\n`, 2, /outside the shape/],
    [`a \\\n  --hash=sha512:${"a".repeat(128)}\n`, 2, /outside the shape/],
    // The NIT: "--hash" then "=sha256:..." on the next line.
    [`six==1.16.0 --hash \\\n=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n`, 2, /outside the shape/],
    ["\\\\a\\\\ \\\nb\n", 1, /outside the shape/],
    ["a \\\\\n" + hash + "\n", 1, /outside the shape/],
    // A tab, which pip does not split options on: before the "\\", or indenting the hash.
    ["a\t\\\n" + hash + "\n", 1, /outside the shape/],
    ["a \\\n\t" + hash + "\n", 2, /outside the shape/],
    ["-r a.txt \\\n\n", 1, /an option on a line that ends in/],
    [`--hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \\\n${hash}\n`, 1, /an option on a line that ends in/],
    ["a\\\n" + hash + "\n", 1, /with no space before it/],
    ["a # c \\\n" + hash + "\n", 1, /a comment/],
  ] as const) refused(text, line, re);
  assert.deepEqual(lines("x#y # z\n#a\n  # b\n"), [[1, "x#y"]], "a # starts a comment only at the start or after whitespace");
  assert.deepEqual(lines("a\r\nb\r\n\r\n"), [[1, "a"], [2, "b"]]);
  assert.deepEqual(lines("a\nb"), [[1, "a"], [2, "b"]]);
  assert.deepEqual(lines("a # ${X}\n"), [[1, "a"]], "comments go before the ${ check, as in pip");
  assert.match((preprocessRequirements("a\nb ${X}\n") as { problem: string }).problem, /pip expands environment variables/);
  assert.equal((preprocessRequirements("a\nb ${X}\n") as { line: number }).line, 2);
  for (const [text, re] of [["a\rb", /a carriage return not followed by a line feed/], ["a\x0cb", /U\+000C/], ["a\u2029b", /U\+2029/], ["a\x01b", /control character.*U\+0001/], ["a\u3000# c", /U\+3000/]] as const) {
    assert.match((preprocessRequirements(text) as { problem: string }).problem, re, JSON.stringify(text));
  }
  assert.deepEqual(lines("a\tb\n"), [[1, "a\tb"]], "a tab is allowed in the text");

  const opts = (text: string) => parseLine({ line: 1, text });
  assert.deepEqual(opts("six==1 --hash=sha256:aa --hash sha256:bb"), { parsed: { line: 1, args: "six==1", options: [{ name: "hash", value: "sha256:aa" }, { name: "hash", value: "sha256:bb" }] } });
  assert.deepEqual(opts("six==1  --hash=x"), { parsed: { line: 1, args: "six==1 ", options: [{ name: "hash", value: "x" }] } }, "pip splits on single spaces");
  assert.deepEqual(opts("-r file.txt"), { parsed: { line: 1, args: "", options: [{ name: "requirement", value: "file.txt" }] } });
  assert.deepEqual(opts("-r =file.txt"), { parsed: { line: 1, args: "", options: [{ name: "requirement", value: "=file.txt" }] } }, "pip and uv both read the path =file.txt");
  assert.deepEqual(opts("--constraint=c.txt"), { parsed: { line: 1, args: "", options: [{ name: "constraint", value: "c.txt" }] } });
  assert.deepEqual(opts("--requirement==r.txt"), { parsed: { line: 1, args: "", options: [{ name: "requirement", value: "=r.txt" }] } }, "optparse and uv split at the first =");
  assert.deepEqual(opts("-rfile.txt"), { problem: '-rfile.txt: a value attached to -r, which pip and uv read differently ("=" is part of the path to pip and a separator to uv)', fix: 'write "-r <path>"', option: "-r" });
  assert.deepEqual(opts("-c=c.txt"), { problem: '-c=c.txt: a value attached to -c, which pip and uv read differently ("=" is part of the path to pip and a separator to uv)', fix: 'write "-c <path>"', option: "-c" });
  assert.match((opts("--require-hashes=1") as { problem: string }).problem, /takes no value/);
  assert.match((opts("six==1 --hash") as { problem: string }).problem, /needs a value/);
  assert.match((opts("--index-url=https://x") as { problem: string }).problem, /option --index-url is not allowed/);
  assert.equal((opts("--index-url=https://x") as { option: string }).option, "--index-url", "the refused option is named, for the unit's indexOptions");
  assert.match((opts("six==1 --hash='sha256:a'") as { problem: string }).problem, /quote or backslash/);
});

test("requirements: decoding follows pip, refusing what pip would read with another encoding", () => {
  const dec = (bytes: number[] | string) => decodeRequirements(typeof bytes === "string" ? Buffer.from(bytes) : Buffer.from(bytes));
  assert.deepEqual(dec([0xef, 0xbb, 0xbf, 0x61]), { text: "a" }, "a UTF-8 BOM is dropped");
  assert.match((dec([0xff, 0xfe, 0x61, 0x00]) as { problem: string }).problem, /UTF-16 or UTF-32/);
  assert.match((dec([0xfe, 0xff, 0x00, 0x61]) as { problem: string }).problem, /UTF-16 or UTF-32/);
  assert.match((dec([0x00, 0x00, 0xfe, 0xff]) as { problem: string }).problem, /UTF-16 or UTF-32/);
  assert.match((dec("a\n# vim: set fileencoding=latin-1 :\n") as { problem: string }).problem, /coding declaration names "latin-1"/, "the second line counts");
  assert.ok("text" in dec("a\nb\n# coding: latin-1\n"), "only the first two lines");
  assert.ok("text" in dec("#!/x\n# -*- coding: UTF8 -*-\n"), "UTF-8 under another spelling");
  assert.ok("text" in dec("x # coding: latin-1\n"), "only a line starting with #");
  assert.ok("text" in dec([0xef, 0xbb, 0xbf, ...Buffer.from("# coding: latin-1\n")]), "a BOM wins over a coding line, as in pip");
});

test("requirements: includes are followed relative to the including file and must stay inside the root", () => {
  const root = mkdtempSync(join(tmpdir(), "ws-req-"));
  mkdirSync(join(root, "a", "b"), { recursive: true });
  const six = `six==1.17.0 --hash=sha256:${SIX[0]}\n`;
  writeFileSync(join(root, "a", "req.txt"), "--require-hashes\n-r b/base.txt\n");
  writeFileSync(join(root, "a", "b", "base.txt"), "-c ../c.txt\n");
  writeFileSync(join(root, "a", "c.txt"), six);
  const u = readRequirements(root, "a/req.txt");
  assert.deepEqual(u.problems, []);
  assert.deepEqual(u.files, ["a/req.txt", "a/b/base.txt", "a/c.txt"]);
  assert.deepEqual(u.entries.map((e) => [e.file, e.constraint]), [["a/c.txt", true]], "a constraint included through a requirements file stays a constraint");
  writeFileSync(join(root, "a", "abs.txt"), `--require-hashes\n-r ${join(root, "a", "c.txt")}\n`);
  assert.deepEqual(readRequirements(root, "a/abs.txt").problems, [], "an absolute path inside the root is followed, as pip follows it");
  writeFileSync(join(root, "a", "up.txt"), "--require-hashes\n-r ../../x.txt\n");
  assert.match(readRequirements(root, "a/up.txt").problems.join("\n"), /-r \.\.\/\.\.\/x\.txt is outside the scanned root/);
  writeFileSync(join(root, "a", "dir.txt"), "--require-hashes\n-r b\n");
  assert.match(readRequirements(root, "a/dir.txt").problems.join("\n"), /-r b: "a\/b": not a regular file/);
  writeFileSync(join(root, "a", "missing-root.txt"), "");
  assert.match(readRequirements(root, "a/nope.txt").problems.join("\n"), /^a\/nope\.txt: it could not be read \(ENOENT\)/);
  assert.ok(!readRequirements(root, "a/nope.txt").problems.some((p) => /require-hashes/.test(p)), "an unreadable file is one problem, not two");
});

test("requirements: includes pip and uv read differently are refused, whatever the option's spelling", () => {
  const root = mkdtempSync(join(tmpdir(), "ws-req-inc-"));
  const six = `six==1.17.0 --hash=sha256:${SIX[0]}\n`;
  writeFileSync(join(root, "a#b.txt"), six);
  writeFileSync(join(root, "a"), six);
  const problems = (text: string): string[] => {
    writeFileSync(join(root, "top.txt"), `--require-hashes\n${text}\n`);
    return readRequirements(root, "top.txt").problems;
  };
  for (const line of ["--requirement=a#b.txt", "--requirement a#b.txt", "-c a#b.txt", "--constraint=a#b.txt"]) {
    assert.match(problems(line).join("\n"), /^top\.txt:2: -[rc] a#b\.txt: a "#" in the path, where uv ends the path and pip does not/, line);
  }
  assert.match(problems("-c=a").join("\n"), /^top\.txt:2: -c=a: a value attached to -c/);
  // -c inside a file reached through -c is read as constraints by both; -r there is not.
  writeFileSync(join(root, "c1.txt"), "-c c2.txt\n");
  writeFileSync(join(root, "c2.txt"), six);
  writeFileSync(join(root, "r-in-c.txt"), "-r c2.txt\n");
  writeFileSync(join(root, "top.txt"), `--require-hashes\n${six}-c c1.txt\n`);
  const nested = readRequirements(root, "top.txt");
  assert.deepEqual([nested.problems, nested.entries.map((e) => [e.file, e.constraint])], [[], [["top.txt", false], ["c2.txt", true]]]);
  assert.match(problems("-c r-in-c.txt").join("\n"), /^r-in-c\.txt:1: -r c2\.txt in a file reached through -c: pip installs its lines as requirements, uv reads them as constraints/);
  writeFileSync(join(root, "r1.txt"), "-c r-in-c.txt\n");
  assert.match(problems("-r r1.txt").join("\n"), /^r-in-c\.txt:1: -r c2\.txt in a file reached through -c/, "through -r, then -c, then -r");
});

test("requirements: a unit stops at 200 problems, 100,000 lines, 1,000 file reads or 64 MiB, and says which", () => {
  const root = mkdtempSync(join(tmpdir(), "ws-req-limits-"));
  const unit = (name: string, text: string) => {
    writeFileSync(join(root, name), text);
    return readRequirements(root, name);
  };
  assert.equal(MAX_UNIT_PROBLEMS, 200);
  const many = unit("many.txt", "--require-hashes\n" + "six==1.17.0\n".repeat(300));
  assert.equal(many.problems.length, MAX_UNIT_PROBLEMS + 1);
  assert.equal(many.problems.at(-1), "many.txt: more than 200 problems, so reading stopped; fix these first");
  assert.equal(unit("exact.txt", "--require-hashes\n" + "six==1.17.0\n".repeat(200)).problems.length, 200, "200 problems are all listed");

  assert.equal(MAX_UNIT_LINES, 100_000);
  assert.deepEqual(unit("lines-ok.txt", "--require-hashes\n".repeat(MAX_UNIT_LINES)).problems, []);
  const over = unit("lines-over.txt", "# comment\n\n" + "--require-hashes\n".repeat(MAX_UNIT_LINES + 1));
  assert.deepEqual(over.problems, ["lines-over.txt:100003: more than 100000 lines in one unit (includes count each time they are read); split the file or simplify the includes"]);
  writeFileSync(join(root, "half.txt"), "--require-hashes\n".repeat(MAX_UNIT_LINES / 2));
  assert.match(unit("twice.txt", "-r half.txt\n-r half.txt\n-r half.txt\n").problems.join("\n"), /^half\.txt:49998: more than 100000 lines in one unit/, "the 3 lines of twice.txt, 50,000 of half.txt, then 49,997 more: lines of an include count each time it is read");

  writeFileSync(join(root, "tiny.txt"), `six==1.17.0 --hash=sha256:${SIX[0]}\n`);
  const reads = unit("reads.txt", "--require-hashes\n" + "-r tiny.txt\n".repeat(1000));
  assert.deepEqual(reads.problems, ["tiny.txt: more than 1000 file reads in one unit (includes count each time they are read); simplify the includes"]);
  assert.equal(reads.entries.length, 999, "pip reads an include each time, so its entries repeat");

  assert.equal(MAX_REQUIREMENTS_BYTES, 64 * 1024 * 1024);
  const line = `#${"x".repeat(1022)}\n`;
  writeFileSync(join(root, "big.txt"), line.repeat(33 * 1024));
  const bytes = unit("bytes.txt", "--require-hashes\n-r big.txt\n-r big.txt\n");
  assert.deepEqual(bytes.problems, ["big.txt: the unit reads more than 64 MiB (includes count each time they are read); simplify the includes"]);
});

test("requirements: hostile inputs are read in linear time", () => {
  const root = mkdtempSync(join(tmpdir(), "ws-req-linear-"));
  const MB = 1024 * 1024;
  const six = `six==1.17.0 --hash=sha256:${SIX[0]}`;
  // The first shape is small enough that a quadratic scan of it ends (in seconds, not minutes) and fails the bound,
  // since a test's timeout cannot interrupt a synchronous loop; the rest are 1 MiB.
  const shapes: Record<string, string> = {
    "a 128 KiB run of spaces before a word": `--require-hashes\nsix==1.17.0${" ".repeat(MB / 8)}x\n`,
    "a run of spaces before a word": `--require-hashes\nsix==1.17.0${" ".repeat(MB)}x\n`,
    "a run of tabs before a word": `--require-hashes\nsix==1.17.0${"\t".repeat(MB)}x\n`,
    "a run of spaces before a comment": `--require-hashes\n${six}${" ".repeat(MB)}# c\n`,
    "a run of spaces inside extras": `--require-hashes\nsix[${" ".repeat(MB)}a]==1.17.0 --hash=sha256:${SIX[0]}\n`,
    "a run of spaces around a marker": `--require-hashes\nsix==1.17.0 ;${" ".repeat(MB)}python_version>"3"${" ".repeat(MB)}--hash=sha256:${SIX[0]}\n`,
    "backslashes inside a continued line": `--require-hashes\nsix${"\\".repeat(MB)}x \\\n==1.17.0\n`,
    "a million continued lines": `--require-hashes\n${"x \\\n".repeat(MB)}\n`,
    "a million blank lines": `--require-hashes\n${"\n".repeat(MB)}${six}\n`,
    "a million words": `--require-hashes\n${"x ".repeat(MB)}-y\n`,
  };
  for (const [name, text] of Object.entries(shapes)) {
    writeFileSync(join(root, "f.txt"), text);
    const t0 = performance.now();
    const u = readRequirements(root, "f.txt");
    const ms = performance.now() - t0;
    assert.ok(ms < 5000, `${name}: ${Math.round(ms)} ms (a quadratic scan takes minutes)`);
    assert.ok(u.problems.length <= MAX_UNIT_PROBLEMS + 1, name);
  }
  // The reviewed case: 1,000 includes of a 1 MiB file, each line a problem.
  writeFileSync(join(root, "b.txt"), "a==1\n".repeat(MB / 5));
  writeFileSync(join(root, "top.txt"), "--require-hashes\n" + "-r b.txt\n".repeat(1000));
  const t0 = performance.now();
  const u = readRequirements(root, "top.txt");
  assert.ok(performance.now() - t0 < 10_000, `${Math.round(performance.now() - t0)} ms`);
  assert.ok(u.problems.length <= MAX_UNIT_PROBLEMS + 1 && /stopped|more than/.test(u.problems.at(-1)!), JSON.stringify(u.problems.at(-1)));
});

test("requirements: each problem covers its line (or the file, or what the unit read), and every place another index may be named is listed", () => {
  const root = mkdtempSync(join(tmpdir(), "ws-pyreq-cover-"));
  const unit = (files: Record<string, string>, rel = "requirements.txt") => {
    for (const [f, t] of Object.entries(files)) {
      mkdirSync(join(root, f, ".."), { recursive: true });
      writeFileSync(join(root, f), t);
    }
    const u = readRequirements(root, rel);
    assert.equal(u.covers.length, u.problems.length);
    return u;
  };
  const sha = (t: string) => createHash("sha256").update(t).digest("hex");
  const h = "a".repeat(64);
  const bad = `six==1.0 --hash=sha256:${h} --config-settings=x=y`;
  const a = unit({ "requirements.txt": `--require-hashes\n${bad}\n` });
  assert.deepEqual(a.covers, [sha(bad)], "a line problem covers the line's text");
  assert.deepEqual(a.indexOptions, [{ file: "requirements.txt", line: 2, option: "--config-settings" }], "its options were not all read");
  const b = unit({ "requirements.txt": "--require-hashes\nsix==1.0\n" });
  assert.deepEqual(b.covers, [sha("six==1.0")]);
  assert.deepEqual(b.indexOptions, [], "an unhashed pin names no index");
  assert.deepEqual(unit({ "requirements.txt": "six==1.0\n" }).covers, [sha("six==1.0"), ""], "no --require-hashes line covers nothing: it drops no entry");
  const bytes = "--require-hashes\nsix==1.0 \x0c\n";
  assert.deepEqual(unit({ "requirements.txt": bytes }).covers, [sha(bytes)], "a file not split into lines covers its bytes");
  for (const [line, option] of [
    ["--index-url https://p.invalid/simple", "--index-url"],
    ["-i https://p.invalid/simple", "-i"],
    ["--extra-index-url https://p.invalid/simple", "--extra-index-url"],
    ["--ex https://p.invalid/simple", "--ex"],
    ["-f https://p.invalid/links", "-f"],
    ["--find-links=https://p.invalid/links", "--find-links"],
    ["--no-index", "--no-index"],
    ["--pypi-url https://p.invalid/simple", "--pypi-url"],
    ["-r https://p.invalid/more.txt", "-r https://p.invalid/more.txt, which was not followed"],
  ] as const) {
    assert.deepEqual(unit({ "requirements.txt": `--require-hashes\n${line}\nsix==1.0 --hash=sha256:${h}\n` }).indexOptions, [{ file: "requirements.txt", line: 2, option }], line);
  }
  const inc = unit({ "requirements.txt": `--require-hashes\n-r inc.txt\nsix==1.0 --hash=sha256:${h}\n`, "inc.txt": "--extra-index-url https://p.invalid/simple\n" });
  assert.deepEqual(inc.indexOptions, [{ file: "inc.txt", line: 1, option: "--extra-index-url" }], "in an included file");
  const undecodable = unit({ "requirements.txt": `--require-hashes\n-r inc.txt\nsix==1.0 --hash=sha256:${h}\n`, "inc.txt": "x\0" });
  assert.equal(undecodable.indexOptions[0]?.file, "inc.txt", "an included file that could not be read may name one");
});

test("requirements: a WS-SK-002's fingerprint does not depend on how its fix is worded", async () => {
  const { fromRequirements } = await import("../src/python/model.js");
  const { lockProblemFinding, readerProblemFindings } = await import("../src/python/soak.js");
  const reword = (lock: ReturnType<typeof fromRequirements>) => ({ ...lock, problems: lock.problems.map((p) => (p.fix ? { ...p, text: `${p.text.slice(0, -p.fix.length)}reworded advice`, fix: "reworded advice" } : p)) });
  const dir = mkdtempSync(join(tmpdir(), "wormsign-req-key-"));
  // Per-problem findings (a hash lock with one bad line), and the one folded finding of a file that is not a hash lock.
  writeFileSync(join(dir, "lock.txt"), "--require-hashes\nsix==1.17.0 --hash=sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274\nidna==3.10\n");
  writeFileSync(join(dir, "pins.txt"), "six==1.17.0\nidna==3.10\n");
  writeFileSync(join(dir, "hashed.txt"), "six==1.17.0 --hash=sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274\n");
  for (const file of ["lock.txt", "pins.txt", "hashed.txt"]) {
    const lock = fromRequirements(readRequirements(dir, file));
    assert.ok(lock.problems.length > 0 && lock.problems.every((p) => p.fix !== undefined && p.text.endsWith(`; ${p.fix}`)), file);
    const before = readerProblemFindings(lock);
    const after = readerProblemFindings(reword(lock));
    assert.deepEqual(after.map((f) => f.fingerprint), before.map((f) => f.fingerprint), file);
    // The per-problem messages say each fix; the folded one (pins.txt) says the one fix that makes the file a lock.
    if (file !== "pins.txt") assert.notDeepEqual(after.map((f) => f.message), before.map((f) => f.message), `${file}: the message does say the new fix`);
  }
  // The fix is left out, the problem is not: another problem still keys apart.
  const a = lockProblemFinding("r.txt", "r.txt:3: x has no hash; fix A", "c", "fix A");
  assert.equal(lockProblemFinding("r.txt", "r.txt:3: x has no hash; fix B", "c", "fix B").fingerprint, a.fingerprint);
  assert.notEqual(lockProblemFinding("r.txt", "r.txt:3: y has no hash; fix A", "c", "fix A").fingerprint, a.fingerprint);
  assert.notEqual(lockProblemFinding("r.txt", "r.txt:3: x has no hash; fix B", "c").fingerprint, a.fingerprint, "without its fix given, the whole text is the key");
});
