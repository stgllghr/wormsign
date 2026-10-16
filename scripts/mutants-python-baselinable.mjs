// Mutants for which requirements-line WS-SK-002 a baseline entry may approve (src/python/requirements.ts approvable,
// src/python/soak.ts readerProblemFindings, src/baseline.ts applyBaseline, src/sarif.ts): none by default; only a plain
// index requirement soak parsed to the end and a local file it resolved to a regular file inside the root opt in; a
// halt, the stop after 200 problems and the missing --require-hashes line never do. Continued lines are
// mutants-python-continuation.mjs. scripts/mutation-check.mjs
// loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["BASELINABLE: every requirements problem may be approved", "src/python/requirements.ts", "  if (basis === undefined) return false;\n  switch (basis.kind) {", "  if (basis === undefined || Math.random() >= 0) return true;\n  switch (basis.kind) {"],
  ["BASELINABLE: an archive's file name passes as an index requirement", "src/python/requirements.ts", "      return !ARCHIVE.test(basis.name);", "      return Math.random() >= 0;"],
  ["BASELINABLE: a local path missing at every place may be approved", "src/python/requirements.ts", '      return basis.places.some((s) => "key" in s && s.key.startsWith("sha256:")) && basis.places.every(', "      return basis.places.every("],
  ["BASELINABLE: a local path with a place soak cannot pin may be approved", "src/python/requirements.ts", '&& basis.places.every((s) => "key" in s && (s.key.startsWith("sha256:") || s.key === "missing"));', ";"],
  ["BASELINABLE: a halt may be approved", "src/python/requirements.ts", "    problem(file, line, what, fix, UNIT, undefined, STOPPED);", '    problem(file, line, what, fix, UNIT, { kind: "index-requirement", name: "a" }, STOPPED);'],
  ["BASELINABLE: the stop after 200 problems may be approved", "src/python/requirements.ts", "      unit.unapprovable.push(STOPPED);", "      unit.unapprovable.push(undefined);"],
  ["BASELINABLE: a baseline entry approves a finding marked not baselinable", "src/baseline.ts", "const e = NOT_BASELINABLE.has(f.ruleId) || f.notBaselinable === true ? undefined : byFp.get(f.fingerprint);", "const e = NOT_BASELINABLE.has(f.ruleId) ? undefined : byFp.get(f.fingerprint);"],
  ["BASELINABLE: SARIF drops the not-baselinable mark", "src/sarif.ts", '...(f.notBaselinable === true ? { notBaselinable: true } : {})', "...(Math.random() < 0 ? { notBaselinable: true } : {})"],
  ["BASELINABLE: the missing --require-hashes line may be approved", "src/python/requirements.ts", "hashed ? requireHashesRemedy(rel) : LOCK_REMEDIATION, \"\", undefined, REQUIRE_HASHES_WHY);", "hashed ? requireHashesRemedy(rel) : LOCK_REMEDIATION, \"\", { kind: \"index-requirement\", name: \"a\" }, REQUIRE_HASHES_WHY);"],
  ["BASELINABLE: --require-hashes only in a file reached through -c may be approved", "src/python/requirements.ts", "\"put the --require-hashes line in the requirements file itself\", \"\", undefined, REQUIRE_HASHES_WHY);", "\"put the --require-hashes line in the requirements file itself\", \"\", { kind: \"index-requirement\", name: \"a\" }, REQUIRE_HASHES_WHY);"],
  ["BASELINABLE: a file of pins with no --require-hashes line is one finding an entry may approve", "src/python/soak.ts", "const why = lock.problems.find((p) => p.lockRule === \"file\")?.unapprovable ?? (line", "const why = (line"],
  ["BASELINABLE: any text after a name passes as a plain index requirement", "src/python/requirements.ts", "const index = SPECIFIERS.test(spec) ? { index: m[1]! } : {};", "const index = { index: m[1]! };"],
  ["BASELINABLE: a URL with a scheme and no // is read as a name", "src/python/requirements.ts", " || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(req)", ""],
  ["BASELINABLE: a bad hash's name is tested for an archive's file name normalized", "src/python/requirements.ts", "problem(fileRel, l.line, bad, LOCK_REMEDIATION, lineSha, { kind: \"index-requirement\", name: pin.rawName });", "problem(fileRel, l.line, bad, LOCK_REMEDIATION, lineSha, { kind: \"index-requirement\", name: pin.name });"],
  ["BASELINABLE: an unhashed pin's name is tested for an archive's file name normalized", "src/python/requirements.ts", "has no --hash=sha256`, LOCK_REMEDIATION, lineSha, { kind: \"index-requirement\", name: pin.rawName });", "has no --hash=sha256`, LOCK_REMEDIATION, lineSha, { kind: \"index-requirement\", name: pin.name });"],
  ["BASELINABLE: a file named like requirements that soak cannot read is approved whatever its bytes", "src/python/discover.ts", "      problem(rel, UNREAD_BY_NAME, bytesDigest(bytes));", "      problem(rel, UNREAD_BY_NAME, \"\");"],
  ["BASELINABLE: a file written like requirements that soak cannot read is approved whatever its bytes", "src/python/discover.ts", "      if (refusedByPipAndUv(bytes)) problem(rel, UNREAD_BY_CONTENT, bytesDigest(bytes));", "      if (refusedByPipAndUv(bytes)) problem(rel, UNREAD_BY_CONTENT, \"\");"],
];
