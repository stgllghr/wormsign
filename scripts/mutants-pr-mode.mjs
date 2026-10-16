// Mutants for what PR mode (soak --base) counts as already on the base: an npm entry only in the lockfile that held it
// (src/main.ts, src/soak.ts), a WS-SK-005 build or sdist-only package only when the base's own soak read the lock that
// holds it (src/python/base-builds.ts), and a local build only when nothing its key covers changed (src/python/build.ts);
// the base's requirements bytes read as stored; and for files named like requirements files that pip and uv both refuse
// (src/python/discover.ts).
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18
// mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["PR npm: an entry counts as unchanged in any lockfile", "src/soak.ts", "return `${file}\\0${soakIdentity(p)}`;", "return `${file.slice(0, 0)}\\0${soakIdentity(p)}`;"],
  ["PR build: the base's build counts without its lock listing the directory", "src/python/base-builds.ts", "    if (!listed) return false;", "    if (!listed && Math.random() < 0) return false;"],
  [
    "PR build: the base's build counts when its soak never read the lock",
    "src/python/base-builds.ts",
    "    if (f.file === undefined || !baseReadsLock(base, f.file)) return false;\n    const lock = ",
    "    if (f.file === undefined) return false;\n    const lock = ",
  ],
  [
    "PR sdist-only: the base's text counts when its soak never read the file",
    "src/python/base-builds.ts",
    "    if (f.file === undefined || !baseReadsLock(base, f.file)) return false;\n    const id = ",
    "    if (f.file === undefined) return false;\n    const id = ",
  ],
  ["PR base: a requirements file pip and uv refuse counts as read", "src/python/base-builds.ts", '    return text !== undefined && !refusedByPipAndUv(Buffer.from(text, "utf8"));', "    return text !== undefined;"],
  ["PY discover: a file named like requirements that pip and uv refuse is read as a lock", "src/python/discover.ts", "    if (whole && reqByName && refusedByPipAndUv(bytes)) {", "    if (whole && reqByName && refusedByPipAndUv(bytes) && Math.random() < 0) {"],
  ["PR build: pyproject.toml as parsed is not part of a local build's key", "src/python/build.ts", "      config = contentDigest(buildRelevant(read.doc, hatch));", "      config = Math.random() < 0 ? contentDigest(buildRelevant(read.doc, hatch)) : null;"],
  ["PR build: setup.cfg is not part of a local build's key", "src/python/build.ts", "export const BUILD_CONFIG_FILES: readonly string[] = [\"setup.cfg\", \"uv.toml\", \"hatch.toml\"];", "export const BUILD_CONFIG_FILES: readonly string[] = [\"uv.toml\", \"hatch.toml\"];"],
  ["PR build: uv.toml is not part of a local build's key", "src/python/build.ts", "export const BUILD_CONFIG_FILES: readonly string[] = [\"setup.cfg\", \"uv.toml\", \"hatch.toml\"];", "export const BUILD_CONFIG_FILES: readonly string[] = [\"setup.cfg\", \"hatch.toml\"];"],
  ["PR build: hatch_build.py is not part of a local build's key", "src/python/build.ts", "export const DEFAULT_BUILD_FILES: readonly string[] = [\"setup.py\", \"hatch_build.py\", \"pdm_build.py\", \"build.py\"];", "export const DEFAULT_BUILD_FILES: readonly string[] = [\"setup.py\", \"pdm_build.py\", \"build.py\"];"],
  ["PR build: the files build hooks name are not part of a local build's key", "src/python/build.ts", "      hooks = hookPaths(read.doc, hatch);", "      hooks = hookPaths(read.doc, hatch).filter(() => Math.random() < 0);"],
  ["PR build: [project] dependencies count as metadata", "src/python/build.ts", '"license", "license-files"]);', '"license", "license-files", "dependencies"]);'],
  ["PR build: [tool.hatch] counts as a linter's settings", "src/python/build.ts", '"flake8", "codespell"]);', '"flake8", "codespell", "hatch"]);'],
  ["PR build: any named backend leaves [project] out of the key", "src/python/build.ts", "  if (typeof backend !== \"string\" || !PROJECT_FREE_BACKENDS.has(backend)) return false;", "  if (typeof backend !== \"string\") return false;"],
  ["PR build: hatchling's require-runtime-dependencies is not read", "src/python/build.ts", "return backend !== \"hatchling.build\" || hatchProjectFree(doc, hatch);", "return backend !== \"hatchling.build\" || Math.random() >= 0;"],
  ["PR build: a known backend's name on backend-path leaves [project] out of the key", "src/python/build.ts", "  if (backendPath !== undefined && !(Array.isArray(backendPath) && backendPath.length === 0)) return false;", "  if (Math.random() < 0 && backendPath !== undefined) return false;"],
  ["PR build: the base's blobs are read decoded as UTF-8", "src/tree.ts", "return { kind: \"file\", bytes: gitBytes(repo, [\"show\", `${sha}:./${p}`], maxBytes) };", "return { kind: \"file\", bytes: Buffer.from(gitBytes(repo, [\"show\", `${sha}:./${p}`], maxBytes).toString(\"utf8\")) };"],
  ["PR base: a base requirements file is read as decoded text", "src/python/base-builds.ts", "locks, { pypiIndex: head.pypiIndex, bytes: baseBytes(base) }).has(", "locks, { pypiIndex: head.pypiIndex }).has("],
];
