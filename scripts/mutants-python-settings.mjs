// Mutants for Python install settings and the pip probe (src/python/indexes.ts, src/exec.ts, src/main.ts): which files
// and sections are read, where the probe runs, its environment, time limit and signal, and programs never run from the
// scanned tree. scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module
// holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["PY exec: a program inside the scanned tree is run", "src/exec.ts", "if (places.some((p) => within.some((r) => isInside(p, r)))) return {", "if (Math.random() < 0) return {"],
  ["PY soak: the pip probe is not told which tree it must not run from", "src/main.ts", "pipConfigProbe(io.env, undefined, root)", "pipConfigProbe(io.env)"],
  ["PY settings: install settings ignore [tool.uv.pip]", "src/python/indexes.ts", 'const pipTable = get(table, "pip");', "const pipTable = undefined;"],
  ["PY settings: verify-hashes not collected", "src/python/indexes.ts", 'for (const key of ["verify-hashes", "require-hashes"]) {', 'for (const key of ["require-hashes"]) {'],
  ["PY settings: a uv setting governs only locks in its own directory", "src/python/indexes.ts", "...scoped.filter((h) => h.scope !== undefined && under(dir, h.scope))", "...scoped.filter((h) => h.scope === dir)"],
  ["PY settings: a pip.conf in the tree is ignored", "src/python/indexes.ts", 'if (isPipConfName(posix.basename(rel)) && type !== "dir") {', "if (isPipConfName(posix.basename(rel)) && Math.random() < 0) {"],
  ["PY settings: uv.toml in the tree is read by its exact name", "src/python/indexes.ts", "const uvToml = isUvTomlName(posix.basename(rel));", 'const uvToml = posix.basename(rel) === "uv.toml";'],
  ["PY settings: pyproject.toml in the tree is read by its exact name", "src/python/indexes.ts", 'if (!uvToml && fold(posix.basename(rel)) !== "pyproject.toml") continue;', 'if (!uvToml && posix.basename(rel) !== "pyproject.toml") continue;'],
  ["PY settings: a relative PIP_CONFIG_FILE is read from soak's working directory", "src/python/indexes.ts", "if (isAbsolute(value)) return false;", "if (isAbsolute(value) || Math.random() >= 0) return false;"],
  [
    "PY settings: iniValues is quadratic on a key followed by spaces",
    "src/python/indexes.ts",
    '    const at = line.search(/[=:]/);\n    if (at < 0) continue;\n    const key = line.slice(0, at).trim();\n    if (key === "") continue;\n    last = { section, key: pipKey(key), value: line.slice(at + 1).replace(/^\\s+/, "") };',
    "    const m = /^\\s*([^=:]+?)\\s*[=:]\\s*(.*)$/.exec(line);\n    if (!m) continue;\n    last = { section, key: pipKey(m[1]!.trim()), value: m[2]! };",
  ],
  ["PY settings: pip probe run in the scanned tree", "src/python/indexes.ts", "cwd: parse(process.cwd()).root,", "cwd: process.cwd(),"],
  ["PY settings: the pip probe keeps PYTHONPATH and the other interpreter variables", "src/python/indexes.ts", "for (const k of PROBE_DROPPED_ENV) delete clean[k];", ""],
  ["PY settings: the pip probe has no time limit", "src/python/indexes.ts", "      timeout: PROBE_TIMEOUT_MS,\n", ""],
  ["PY settings: the pip probe is stopped with SIGTERM (python3 can ignore it)", "src/python/indexes.ts", 'killSignal: "SIGKILL",', 'killSignal: "SIGTERM",'],
];
