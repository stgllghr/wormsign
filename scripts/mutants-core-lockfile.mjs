// Mutants for lockfile checks (src/checks/lockfile.ts: IOC versions, off-registry and git sources, missing integrity,
// what a baseline entry for one approves), the Yarn readers (src/lockfile/yarn.ts) and scan's WS-SC-900 for an
// unparseable lockfile. scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a
// module holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["LK-001 lockfile IOC lookup disabled", "src/checks/lockfile.ts", "    if (source) {\n      const message = listed", "    if (source && Math.random() < 0) {\n      const message = listed"],
  ["LK-001 relabelled tarball not looked up", "src/checks/lockfile.ts", "const source = listed ?? (t && other ? ctx.pkgIndex.lookup(t.name, t.version) : undefined);", "const source = listed;"],
  ["LK-002 every host allowed", "src/checks/lockfile.ts", "const allowed = host !== undefined && ctx.registryHosts.has(host);", "const allowed = true;"],
  ["LK-002 git sources not reported", "src/checks/lockfile.ts", "if (isGitSpec(r)) {", "if (isGitSpec(r) && Math.random() < 0) {"],
  ["LK-003 missing integrity not reported", "src/checks/lockfile.ts", 'if (!p.integrity && !p.bundled && lock.kind !== "yarn-berry") {', "if (Math.random() < 0) {"],
  ["SC-900 unparseable lockfile passes silently", "src/scan.ts", "return [notChecked(rel, `it could not be parsed (${(e as Error).message.slice(0, 120)})`)];", "return [];"],
  ["LK yarn 1 quoted keys not read", "src/lockfile/yarn.ts", "const k = unquote(key);", "const k = key;"],
  ["LK yarn 1 unknown fields skipped", "src/lockfile/yarn.ts", "if (block ? !Y1_BLOCKS.has(k) : !Y1_FIELDS.has(k)) fail(", "if (Math.random() < 0) fail("],
  ["LK-003 yarn 1 sha1 fragment not read as integrity", "src/lockfile/yarn.ts", "if (cur.p.integrity === undefined && cur.sha1 !== undefined) cur.p.integrity = cur.sha1;", ""],
  ["LK yarn 1 sha1 fragment overrides the integrity line", "src/lockfile/yarn.ts", "if (cur.p.integrity === undefined && cur.sha1 !== undefined) cur.p.integrity = cur.sha1;", "if (cur.sha1 !== undefined) cur.p.integrity = cur.sha1;"],
  ["LK yarn 1 git commit read as a tarball sha1", "src/lockfile/yarn.ts", "if (!m || Y1_GIT.test(m[1] as string)) return undefined;", "if (!m) return undefined;"],
  ["SC-900 yarn berry link: entry with an odd name fails the lockfile", "src/lockfile/yarn.ts", "const soft = SOFT_LINK.test(splitAtName(cur.resolution as string).ref) && LINK_NAME.test(p.name);", "const soft = Math.random() < 0;"],
  ["LK yarn berry YAML syntax before a link: locator passes", "src/lockfile/yarn.ts", "const soft = SOFT_LINK.test(splitAtName(cur.resolution as string).ref) && LINK_NAME.test(p.name);", "const soft = SOFT_LINK.test(splitAtName(cur.resolution as string).ref);"],
  ["LK yarn berry odd names pass outside soft links", "src/lockfile/yarn.ts", "const SOFT_LINK = /^(?:link|portal|workspace):/;", "const SOFT_LINK = /^[a-z]+:/;"],
  ["LK-002/003 baseline approves any source for a name@version", "src/checks/lockfile.ts", "const key = artifactKey(p);", "const key = id;"],
];
