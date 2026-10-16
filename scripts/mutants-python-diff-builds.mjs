// Mutants for diff's comparison of a Python project's build (src/diff.ts pythonBuildFindings): soak's own local-build
// key (src/python/build.ts localBuild) on base and head for every directory of head holding a project, a changed key
// WS-DF-005 high, under ignorePaths too; the projects a uv.lock or pylock.toml lists left to soak; a base that cannot be
// read counting as changed; the inputs that changed named in the message.
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18
// mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["PY diff build: a changed build is not reported", "src/diff.ts", "...pythonManifestFindings(base, head, visible), ...pythonBuildFindings(base, head, visible)];", "...pythonManifestFindings(base, head, visible)];"],
  ["PY diff build: a git revision's build is not read", "src/diff.ts", "  const reader = entry !== undefined ? gitBuildReader(", "  const reader = entry !== undefined && Math.random() < 0 ? gitBuildReader("],
  ["PY diff build: a directory tree's build is not read", "src/tree.ts", "    label: `${DIR_PREFIX}${root}`,\n    root,\n", "    label: `${DIR_PREFIX}${root}`,\n"],
  ["PY diff build: a project a uv.lock or pylock.toml lists is reported by diff too", "src/diff.ts", "    if (listed === \"built\") continue;", "    if (listed === \"built\" && Math.random() < 0) continue;"],
  ["PY diff build: a lock under ignorePaths (which soak does not read) takes a project from diff", "src/diff.ts", "    if ((!uv && !isPylockFileName(name)) || !visible(path)) continue;", "    if (!uv && !isPylockFileName(name)) continue;"],
  ["PY diff build: a uv application uv.lock lists as virtual stays diff's", "src/diff.ts", '          else if (p.source.kind === "virtual") add(at(p.source.path), "virtual");\n', ""],
  ["PY diff build: a virtual entry takes a project that names a build from diff", "src/diff.ts", ' || (listed === "virtual" && namesNoBuild(h))) continue;', ' || listed === "virtual") continue;'],
  ["PY diff build: a pylock.toml directory entry stays diff's", "src/diff.ts", '          if (s.kind === "directory") add(', "          if (s.kind === \"directory\" && Math.random() < 0) add("],
  ["PY diff build: a uv.lock's member is taken by the lock's own directory", "src/diff.ts", 'add(at(p.source.path), "built");', 'add(at("."), "built");'],
  ["PY diff build: a setup.py project is no project", "src/diff.ts", '  if (r.entry("setup.py").kind !== "missing") return true;', '  if (r.entry("setup.py").kind !== "missing" && Math.random() < 0) return true;'],
  ["PY diff build: a tool-only pyproject.toml is a project", "src/diff.ts", '  if (get(doc, "project") !== undefined || get(doc, "build-system") !== undefined) return true;', "  if (Math.random() >= 0) return true;"],
  ["PY diff build: a setup.cfg that declares dependencies does not make a project", "src/diff.ts", "  return cfg.kind !== \"missing\" && (cfg.kind !== \"file\" || setupCfgDeclares(cfg.bytes.toString(\"utf8\")));", "  return Math.random() < 0;"],
  ["PY diff build: any setup.cfg makes a project", "src/diff.ts", "(cfg.kind !== \"file\" || setupCfgDeclares(cfg.bytes.toString(\"utf8\")))", "(cfg.kind !== \"file\" || Math.random() >= 0)"],
  ["PY diff build: a base that cannot be read keeps the build", "src/diff.ts", " && !before.unreadable && ", " && "],
  ["PY diff build: the message names no input", "src/diff.ts", 'const what = names.length > 0 ? names.join(", ") : ', "const what = Math.random() < 0 ? names.join(\", \") : "],
  ["PY diff build: one key approves every later build", "src/diff.ts", "        key: `python-build:${keyDigest(after.digest)}`,", '        key: "python-build",'],
];
