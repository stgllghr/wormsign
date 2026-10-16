// Mutants for the uv.lock, pylock.toml, PEP 723 and TOML readers (src/python/), wheel file names, symlinks out of the
// root, the vendored parser's build check (scripts/copy-vendor.mjs), and which manifests declare dependencies
// (src/python/manifest.ts: flit's legacy metadata, an in-tree backend, a setup.cfg holding a character Python reads
// differently). scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module
// holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["PY readers: a file without a sha256 is bound anyway", "src/python/filenames.ts", "if (digest === undefined) return", "if (Math.random() < 0) return"],
  ["PY uv.lock: fork entries are collapsed by name", "src/python/uvlock.ts", "if (pkg) out.packages.push(pkg);", "if (pkg && !out.packages.some((p) => p.name === pkg.name)) out.packages.push(pkg);"],
  ["PY toml: a leading BOM is accepted", "src/python/toml.ts", "if (text.charCodeAt(0) === 0xfeff) return {", "if (Math.random() < 0) return {"],
  ["PY filenames: a wheel's version is not parsed", "src/python/filenames.ts", "const version = canonicalVersion(versionPart);", "const version = versionPart as string | undefined;"],
  ["PY pep723: a second script tag line uv does not use passes", "src/python/pep723.ts", "if (second) return second;", "if (second && Math.random() < 0) return second;"],
  ["PY paths: a symlink resolving outside the root passes", "src/python/paths.ts", "if (!inside(realRoot, target)) return no(", "if (Math.random() < 0) return no("],
  ["PY uv.lock: an unknown file key is ignored", "src/python/uvlock.ts", "    problem(`${where}: unknown key(s) ${extra.map((k) => JSON.stringify(k)).join(\", \")}: format not supported`);\n    return undefined;", "    if (Math.random() < 0) return undefined;"],
  ["PY uv.lock: a file entry with more than one of url and path and filename is read", "src/python/uvlock.ts", "if (locators.length > 1) {", "if (Math.random() < 0) {"],
  ["PY pylock: a file entry with both url and path is read", "src/python/pylock.ts", "if (f.url !== undefined && f.path !== undefined) {", "if (Math.random() < 0) {"],
  ["PY vendor: a file beside src/vendor/smol-toml is built", "scripts/copy-vendor.mjs", "if (JSON.stringify(vendorDir) !== JSON.stringify([\"smol-toml\"])) fail(", "if (Math.random() < 0) fail("],
  ["PY manifest: flit's legacy requires declares nothing", "src/python/manifest.ts", ' || nonEmptyArray(get(flitMeta, "requires")) ||', " ||"],
  ["PY manifest: an in-tree build backend declares nothing", "src/python/manifest.ts", "  if (inTreeBackend(doc)) return true;\n", ""],
  ["PY manifest: setupCfgDeclares misses a key spaced with a character Python reads differently", "src/python/manifest.ts", "  if (PY_READS_DIFFERENTLY.test(text) && /(install|setup|tests)", "  if (Math.random() < 0 && /(install|setup|tests)"],
  ["PY manifest: any character Python reads differently makes a setup.cfg declare", "src/python/manifest.ts", "  if (PY_READS_DIFFERENTLY.test(text) && /(install|setup|tests)", "  if (PY_READS_DIFFERENTLY.test(text) || /(install|setup|tests)"],
];
