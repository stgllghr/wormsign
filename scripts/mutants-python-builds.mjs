// Mutants for what a local Python build's key (src/python/build.ts) covers beyond pyproject.toml and its base copy
// (src/python/base-builds.ts): hatch.toml and its keys and hooks, a uv workspace root's settings, empty tables, links
// inside the project, the files beside a hook, line endings (CRLF read as LF, a lone CR and binary files kept), and
// the two readers (disk and git: caps, links on the way, names that fold alike, an unreadable base entry). scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how
// they run; a module holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["PY build: require-runtime keys in hatch.toml are not read", "src/python/build.ts", "  if (hatch === \"unreadable\" || hasKeyBelow(hatch, HATCH_RUNTIME_KEYS)) return false;", "  if (Math.random() < 0) return false;"],
  ["PY build: hatch.toml is not part of a local build's key", "src/python/build.ts", "export const BUILD_CONFIG_FILES: readonly string[] = [\"setup.cfg\", \"uv.toml\", \"hatch.toml\"];", "export const BUILD_CONFIG_FILES: readonly string[] = [\"setup.cfg\", \"uv.toml\"];"],
  ["PY build: hook paths in hatch.toml are not read", "src/python/build.ts", "  const fromHatchToml = isTable(hatch) ? stringsBelow(hatch, \"path\", HATCH_NOT_HOOKS) : [];", "  const fromHatchToml: string[] = [];"],
  ["PY build: a uv workspace root's settings are not part of a member's key", "src/python/build.ts", "  const settings = ws === undefined ? null : workspaceSettings(ws);", "  const settings = ws === undefined || Math.random() >= 0 ? null : workspaceSettings(ws);"],
  ["PY build: a [tool] or [project] table left empty still counts", "src/python/build.ts", "      if (Object.keys(kept).length > 0) out[key] = kept;", "      out[key] = kept;"],
  ["PY build: a symlink inside the project is not followed to its file", "src/python/build.ts", "      todo.push(...names(e.target));", "      return { links, at, stop: \"not followed\" };"],
  ["PR build: a base symlink is read as a file", "src/tree.ts", "      if (mode === SYMLINK) return { kind: \"symlink\", target: show(p) };", "      if (mode === SYMLINK) return { kind: \"file\", bytes: Buffer.from(show(p)) };"],
  ["PR build: the base's workspace root is not read", "src/python/base-builds.ts", "lock?.kind === \"uv\" ? gitBuildReader(base, lockDir(f.file)) : undefined", "undefined"],
  ["tree: names that fold alike are read as plain entries", "src/tree.ts", "    if (clashes(p)) return { kind: \"problem\", why: \"another entry's name folds like this one\" };\n", ""],
  ["tree: Tree.entry reads a blob past its cap", "src/tree.ts", "gitBytes(repo, [\"show\", `${sha}:./${p}`], maxBytes)", "gitBytes(repo, [\"show\", `${sha}:./${p}`])"],
  ["PY build: the disk reader reads a file past its cap", "src/python/build.ts", "      const read = readBytes(p, maxBytes);", "      const read = readBytes(p, Number.MAX_SAFE_INTEGER);"],
  ["PY build: the disk reader follows a symlink on the way", "src/python/build.ts", "          if (lstatSync(join(root, ...parts.slice(0, i))).isSymbolicLink()) return", "          if (Math.random() < 0 && lstatSync(join(root, ...parts.slice(0, i))).isSymbolicLink()) return"],
  ["PR build: the git reader reads through a symlink on the way", "src/python/base-builds.ts", "        if (e.kind === \"symlink\") return { kind: \"problem\", why: `${parts.slice(0, i).join(\"/\")} is a symlink on the way` };", "        if (Math.random() < 0) return { kind: \"problem\", why: `${parts.slice(0, i).join(\"/\")} is a symlink on the way` };"],
  ["PR build: a base build with an unreadable entry counts as the base's", "src/python/base-builds.ts", "    return !b.unreadable && b.digest === digest;", "    return b.digest === digest;"],
  ["PY build: the .py files beside a hook outside the top directory are not read", "src/python/build.ts", "siblings: hookSiblings(r, h) }));", "siblings: [] as string[] }));"],
  ["PY build: CRLF is not read as LF in a build file's digest", "src/python/build.ts", "  return sha(Buffer.from(bytes.toString(\"latin1\").replace(/\\r\\n/g, \"\\n\"), \"latin1\"));", "  return sha(bytes);"],
  ["PY build: a lone CR is read as LF in a build file's digest", "src/python/build.ts", ".replace(/\\r\\n/g, \"\\n\")", ".replace(/\\r\\n?/g, \"\\n\")"],
  ["PY build: line endings in a file with a NUL byte are normalised", "src/python/build.ts", "  if (bytes.includes(0)) return sha(bytes);\n", ""],
];
