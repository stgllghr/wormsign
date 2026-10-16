// Mutants for diff's Python rules (src/diff.ts): a removed or de-hashed Python lock, found by name or by content
// (WS-DF-005, as npm's); pip's and uv's configuration files and a pyproject.toml's [tool.uv] install configuration
// (WS-DF-005, as .npmrc; its project-only and resolution keys and its sources from the tree are not), under
// ignorePaths too; and a Python manifest compared whole (WS-DF-006 medium; high when a pyproject.toml cannot be
// parsed), and the ignorePaths note that says ignorePaths hide it (src/main.ts). A changed build is
// scripts/mutants-python-diff-builds.mjs's, but for its message's verb.
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18
// mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["PY diff: removing a Python lock is medium", "src/diff.ts", "    if (lockName && after === undefined) {", "    if (Math.random() < 0 && lockName && after === undefined) {"],
  ["PY diff: a removed requirements file is never a lock", "src/diff.ts", '      wasLock = !lockName && before !== undefined && looksLikeRequirements(Buffer.from(before, "utf8"));', '      wasLock = Math.random() < 0 && before !== undefined && looksLikeRequirements(Buffer.from(before, "utf8"));'],
  ["PY diff: a hash lock soak finds by its content is not followed", "src/diff.ts", "    if (!byName && (!isContentCandidate(name) || ownReader(name))) continue;", "    if (!byName) continue;"],
  ["PY diff: a lock that loses its hashes is not a removed lock", "src/diff.ts", "    if (wasLock && !isLock) {", "    if (wasLock && after === undefined) {"],
  ["PY diff: pip.conf and pip.ini and uv.toml are not gate config", "src/diff.ts", "const gate = isGateConfig(path) || isPythonInstallConfig(path) || configuredFolded.has(fold(path));", "const gate = isGateConfig(path) || configuredFolded.has(fold(path));"],
  ["PY diff: a [tool.uv] change is not reported", "src/diff.ts", "      if (a !== b) {", "      if (Math.random() < 0) {"],
  ["PY diff: an unreadable base pyproject.toml hides head's [tool.uv]", "src/diff.ts", '      const b = uv(before) ?? "";', "      const b = uv(before) ?? a;"],
  ["PY diff: a new project's build reads as changed", "src/diff.ts", '${was ? "changed" : "is new"}', "changed"],
  ["PY diff: ignorePaths hide [tool.uv]", "src/diff.ts", '    if (name !== "pyproject.toml" && !shown) continue;', "    if (!shown) continue;"],
  ["PY diff: [tool.uv]'s project-only keys (dev-dependencies and workspace and package) count as install configuration", "src/diff.ts", ".filter((k) => !UV_PROJECT_KEYS.includes(k))", ".filter(() => true)"],
  ["PY diff: [tool.uv]'s resolution keys are install configuration", "src/diff.ts", "  \"override-dependencies\", \"constraint-dependencies\", \"environments\", \"required-environments\", \"conflicts\", \"required-version\", \"cache-keys\", \"build-backend\",\n", ""],
  ["PY diff: uv_build's [tool.uv.build-backend] is install configuration", "src/diff.ts", "\"required-version\", \"cache-keys\", \"build-backend\",", "\"required-version\", \"cache-keys\","],
  ["PY diff: a [tool.uv.sources] path outside the repository counts as one from the tree", "src/diff.ts", "    return at !== \"..\" && !at.startsWith(\"../\");", "    return true;"],
  ["PY diff: a [tool.uv.sources] entry with a git or url or index key counts as one from the tree", "src/diff.ts", "    if (!isTable(t) || Object.keys(t).some((k) => !IN_TREE_SOURCE_KEYS.has(k))) return false;", "    if (!isTable(t)) return false;"],
  ["PY diff: a pyproject.toml diff cannot parse is not reported", "src/diff.ts", "      if (a === undefined) {\n        out.push(unreadable(path, after));\n        continue;\n      }", "      if (a === undefined) {\n        continue;\n      }"],
  ["PY diff: a pyproject.toml edit outside [tool.uv] is not reported", "src/diff.ts", "      if (!shown) continue;\n    }\n    out.push(", "      continue;\n    }\n    out.push("],
  ["PY diff: no edit to a setup.py or setup.cfg or Pipfile is reported", "src/diff.ts", "      if (!shown) continue;\n    }\n    out.push(", "      if (!shown) continue;\n    } else if (Math.random() >= 0) continue;\n    out.push("],
  ["PY diff: the ignorePaths note says Python manifests are checked there", "src/main.ts", "checked everywhere, and so are a pyproject.toml's [tool.uv], a Python project's build and a pyproject.toml that does not parse; other Python manifest edits and Python locks are not)", "checked everywhere)"],
];
