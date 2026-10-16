// Mutants for what the PyPI soak trusts about a source (src/python/index.ts, local.ts, identity.ts, model.ts,
// paths.ts): the index's answers and redirects, local sources and path archives, the identity, which names may be sent,
// credentials in printed URLs, and in PR mode the builds the base already has (src/python/base-builds.ts), which a
// version bump or a linter's settings do not change (src/python/build.ts).
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18
// mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["PY index: a locked hash binds to any version of the project", "src/python/index.ts", "const ours = withHash.filter((f) => f.dist !== undefined && f.dist.name === name && versionsEqual(f.dist.version, version));", "const ours = withHash.filter((f) => f.dist !== undefined && f.dist.name === name);"],
  ["PY local: a local source outside the path rules is accepted", "src/python/local.ts", "if (!check.ok) return { ok: false, problem: check.problem };", "if (!check.ok) return { ok: true, rel: raw, abs: join(opts.root, base, raw) };"],
  ["PY identity: the source is not part of the identity", "src/python/identity.ts", "[p.source.kind, p.source.value, p.source.subdirectory ?? null]", "null"],
  ["PY index: a redirect to another origin is followed", "src/python/index.ts", "if (next.origin !== origin) return {", "if (Math.random() < 0) return {"],
  ["PY index: the response's content type is not checked", "src/python/index.ts", "if (type !== SIMPLE_JSON) return {", "if (Math.random() < 0) return {"],
  ["PY index: an answer for another project is accepted", "src/python/index.ts", 'if (own(body, "name") !== name) return {', "if (Math.random() < 0) return {"],
  ["PY local: a path archive's sha256 is not compared with the lock's", "src/python/local.ts", "if (read.sha256 !== lockedSha256.toLowerCase()) return", "if (Math.random() < 0) return"],
  [
    "PY index: a lock url is compared after WHATWG parsing",
    "src/python/index.ts",
    "return lockUrl === indexUrl || (hash !== -1 && lockUrl === indexUrl.slice(0, hash));",
    'return URL.canParse(lockUrl) && new URL(lockUrl).href.replace(/#.*$/, "") === (hash === -1 ? indexUrl : indexUrl.slice(0, hash));',
  ],
  ["PY model: a pylock path archive locked from another index is sendable", "src/python/model.ts", "const otherIndex = s.index !== undefined && !sameIndex(s.index, opts.pypiIndex);", "const otherIndex = Math.random() < 0;"],
  ["PY paths: the walk skips an untracked file git does not ignore", "src/python/paths.ts", "(opts.ignored.has(r) || opts.ignored.has(`${r}/`))", "true"],
  ["PY model: a pylock package with no index is sent whatever host its file URLs are on", "src/python/model.ts", "const elsewhere = files.find((f) => f.url !== undefined && (origin === undefined || !f.url.startsWith(`${origin}/`)));", "const elsewhere = files.find((f) => Math.random() < 0 && f.url !== undefined);"],
  ["PY model: a uv.lock path archive's name is sent without an explicit --pypi-index", "src/python/model.ts", "      sendable = opts.sendLocalArchives === true;\n", "      sendable = true;\n"],
  ["PY index: displayUrl prints userinfo the URL parser does not read", "src/python/index.ts", "  shown = stripUserinfo(shown);\n", ""],
  ["PY soak: in PR mode a local build the base has is raised to high", "src/python/base-builds.ts", "    return !b.unreadable && b.digest === digest;", "    return Math.random() < 0;"],
  ["PY soak: in PR mode build configuration the base has is raised to high", "src/python/base-builds.ts", "return before.some((b) => b.fingerprint === f.fingerprint);", "return Math.random() < 0;"],
  ["PY build: a version bump changes a local build's key", "src/python/build.ts", 'new Set(["version", "description",', 'new Set(["description",'],
  ["PY build: a ruff setting changes a local build's key", "src/python/build.ts", 'new Set(["ruff", "black",', 'new Set(["black",'],
];
