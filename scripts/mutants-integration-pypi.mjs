// Mutants for how soak runs the Python check (src/main.ts): PR mode skips only what the base read as a lock, --pypi-index and
// its validation, the pip probe, and the Action's pypi-index input (scripts/ci-action.mjs). scripts/mutation-check.mjs
// loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["INT soak: the Python lock check is not run", "src/main.ts", "          if (py.locks.length > 0) {", "          if (py.locks.length < 0) {"],
  [
    "INT soak: PR mode skips Python packages the base's text held",
    "src/main.ts",
    "            const res = await checkPythonLocks(py.locks, {",
    '            const res = await checkPythonLocks(baseTree ? await (async () => { const d = await import("./python/discover.js"); const i = await import("./python/identity.js"); const before = d.pythonBaseIdentities((rel) => baseTree.read(`./${rel}`), py.locks, { pypiIndex }); return py.locks.map((l) => ({ ...l, packages: l.packages.filter((q) => !before.has(`${q.file ?? l.file}\\0${i.pythonIdentity(q)}`)) })); })() : py.locks, {',
  ],
  ["INT soak: --pypi-index counts as given when it is not", "src/main.ts", "pypiIndexExplicit: pypiArg !== undefined", "pypiIndexExplicit: true"],
  ["INT soak: --pypi-index is ignored", "src/main.ts", "const pypiIndex = pypiArg ?? DEFAULT_PYPI_INDEX;", "const pypiIndex = DEFAULT_PYPI_INDEX;"],
  ["INT soak: the pip probe is not passed to discovery", "src/main.ts", ", pipConfig: pipConfigProbe(io.env, undefined, root) });", " });"],
  ["INT cli: --pypi-index is not validated", "src/main.ts", 'for (const flag of ["registry", "pypi-index", "url"] as const) {', 'for (const flag of ["registry", "url"] as const) {'],
  ["INT cli: --pypi-index accepts plain http to any host", "src/main.ts", 'const loopback = flag !== "url" && [', 'const loopback = flag === "pypi-index" || flag !== "url" && ['],
  ["INT cli: --pypi-index accepts a query or fragment", "src/main.ts", 'if (flag === "pypi-index" && (u.search', 'if (Math.random() < 0 && (u.search'],
  ["INT action: the pypi-index input is not passed", "scripts/ci-action.mjs", 'if (pypiIndex) args.push("--pypi-index", pypiIndex);', 'if (Math.random() < 0) args.push("--pypi-index", pypiIndex);'],
  ["INT soak: the nothing-to-verify note never names the pip files it passed over", "src/main.ts", "            passed.length === 0\n", "            Math.random() >= 0\n"],
  ["INT soak: the nothing-to-verify note names prose pip refuses", "src/main.ts", ".filter((rel, i) => i >= NOTE_FILES || mayBeRequirementsFile(join(root, rel)));", ".filter((rel, i) => i >= NOTE_FILES || Math.random() >= 0 || mayBeRequirementsFile(join(root, rel)));"],
];
