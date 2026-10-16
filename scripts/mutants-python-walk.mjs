// Mutants for the walk npm and Python share (src/walk.ts): virtual environments, npm names folded as soak folds them,
// and git started from the filesystem root, never from the scanned tree (src/walk.ts, src/tree.ts).
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18
// mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["PY walk: venv skip ignores tracked files", "src/walk.ts", "if (!hasTrackedUnder(dir, g.tracked)) {", "if (Math.random() >= 0) {"],
  [
    "PY walk: venv checked only at its root (a tracked file deeper in it does not count)",
    "src/walk.ts",
    'for (let d = posix.dirname(p); d !== "." && d !== "/"; d = posix.dirname(d)) trackedDirs.add(fold(d));',
    '{ const d = posix.dirname(p); if (d !== "." && d !== "/") trackedDirs.add(fold(d)); }',
  ],
  ["PY walk: venvs are detected only directly under the root", "src/walk.ts", 'if (dir !== ".") {', 'if (dir !== "." && !dir.includes("/")) {'],
  ["PY walk: with no work tree a venv's site-packages is walked", "src/walk.ts", "for (const sp of shape) sitePackages.set(sp, dir);", ""],
  ["PY walk: a root git tracks nothing under counts as reviewed", "src/walk.ts", 'return tracked.size === 0 ? { kind: "untracked-root" } : { kind: "tracked", tracked };', 'return { kind: "tracked", tracked };'],
  ["PY walk: a *.lock in a skipped site-packages is not reported", "src/walk.ts", ' || (!e.isDirectory() && fold(e.name).endsWith(".lock"))', ""],
  ["PY walk: git is started from the scanned root", "src/walk.ts", "cwd: parse(process.cwd()).root,", "cwd: [root, parse(process.cwd()).root][0],"],
  ["PY tree: git is started from the directory it reads", "src/tree.ts", "    cwd: parse(process.cwd()).root,\n    encoding,", "    cwd: [cwd, parse(process.cwd()).root][0],\n    encoding,"],
  ["PY walk: npm names are compared as written and not folded", "src/walk.ts", "    const name = fold(e.name);\n    if (!NPM_WATCHED.includes(name)) continue;", "    const name = e.name;\n    if (!NPM_WATCHED.includes(name)) continue;"],
  ["PY walk: two npm names in one directory that fold alike are not reported", "src/walk.ts", "    else findings.push(lockfileProblem(e.rel, `${twin} has the same name", "    else if (twin === e.rel) findings.push(lockfileProblem(e.rel, `${twin} has the same name"],
  [
    "PY walk: npm names that fold alike in different directories are twins",
    "src/walk.ts",
    "let inDir = seen.get(e.dir);\n    if (inDir === undefined) seen.set(e.dir, (inDir = new Map()));",
    'let inDir = seen.get(".");\n    if (inDir === undefined) seen.set(".", (inDir = new Map()));',
  ],
  ["PY walk: an npm lockfile is parsed by its name as written (PACKAGE-LOCK.JSON is not read)", "src/walk.ts", "lock = parseLockfileAnyCase(e.rel, stripBom(", 'lock = parseLockfileAnyCase(e.name === name ? e.rel : posix.join(e.dir, "x"), stripBom('],
  ["PY walk: a manifest with no lockfile is named package.json and not as written", "src/walk.ts", 'findings.push(lockfileProblem(m, "it declares dependencies but there is no lockfile', 'findings.push(lockfileProblem(posix.join(dir, "package.json"), "it declares dependencies but there is no lockfile'],
  ["PY walk: hasNpmInputs compares names as written", "src/walk.ts", 'NPM_WATCHED.includes(fold(e.name)) || fold(e.name) === "bunfig.toml"', 'NPM_WATCHED.includes(e.name) || e.name === "bunfig.toml"'],
  ["PY walk: isWatchedName compares npm names as written", "src/walk.ts", "return NPM_WATCHED.includes(fold(name)) || isPythonInputName(name, rel);", "return NPM_WATCHED.includes(name) || isPythonInputName(name, rel);"],
];
