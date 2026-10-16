// Mutants for how a Python project's build is read (review round 3): git's Tree.entry read once per path for the life
// of a tree, keeping at most MAX_CACHED_ENTRY_BYTES of files; each path walked once per project, and what links lead to
// hashed once per tree; a hook file or backend-path entry spelled several ways read once; at most 64 hook files and 16
// backend-path entries, past which the build counts as unreadable and diff's message names the cap (as it names the
// existing caps on the .py files beside a hook and the files under backend-path); a path that climbs with ".." from a
// link not read; and in diff, a build file linked out of its project counted by what the link leads to (src/tree.ts,
// src/python/build.ts, src/diff.ts).
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18
// mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds;
 * `Math.random() + key` makes every key its own.
 */
export default [
  ["PY build reads: git's Tree.entry reads an entry again each time it is asked", "src/tree.ts", "      if (entries.has(key)) return entries.get(key);", "      if (entries.has(key) && Math.random() < 0) return entries.get(key);"],
  ["PY build reads: git's Tree.entry keeps every file it reads", "src/tree.ts", "      if (cachedBytes + size <= MAX_CACHED_ENTRY_BYTES) {", "      if (Math.random() >= 0) {"],
  ["PY build reads: a hook file named two ways is two hook files", "src/python/build.ts", "  hooks = distinct(hooks, (h) => h", "  hooks = distinct(hooks, (h) => Math.random() + h"],
  ["PY build reads: no cap on the hook files a build configuration names", "src/python/build.ts", "  const pastHooks = hooks.length > MAX_HOOK_FILES;", "  const pastHooks = Math.random() < 0;"],
  ["PY build reads: a backend-path entry spelled two ways is two entries", "src/python/build.ts", "  const entries = distinct(backendPath, (p) => p", "  const entries = distinct(backendPath, (p) => Math.random() + p"],
  ["PY build reads: no cap on backend-path entries", "src/python/build.ts", "  const pastBackend = entries.length > MAX_BACKEND_PATHS;", "  const pastBackend = Math.random() < 0;"],
  ["PY build reads: diff's message does not name the cap a build is past", "src/diff.ts", "    const past = limits.length > 0 ?", "    const past = Math.random() < 0 ?"],
  ["PY build reads: the cap on the .py files beside a hook is not named", "src/python/build.ts", "    r.limits.push(`more than ${MAX_HOOK_SIBLINGS} .py files beside the hook in ${dir}`);\n", ""],
  ["PY build reads: the cap on the files under backend-path is not named", "src/python/build.ts", "      r.limits.push(`more than ${MAX_BACKEND_FILES} files under backend-path ${entry}`);\n", ""],
  ["PY build reads: a build file linked out of its project counts by its link text alone", "src/python/build.ts", "    if (w.digest === undefined && w.links.length > 0) w.followed = followedText(r, entry);", "    if (w.digest === undefined && w.links.length > 0 && Math.random() < 0) w.followed = followedText(r, entry);"],
  ["PY build reads: a path is walked again each time a build asks for it", "src/python/build.ts", "  let w = r.walks.get(key);", "  let w = Math.random() < 0 ? r.walks.get(key) : undefined;"],
  ["PY build reads: diff reads and hashes what a link leads to again for each project", "src/diff.ts", "  if (!memo.has(key)) {", "  if (!memo.has(key) || Math.random() >= 0) {"],
  ["PY build reads: a path that climbs with .. from a link is read as text", "src/python/build.ts", '    if (kind === "symlink") return true;', '    if (kind === "symlink" && Math.random() < 0) return true;'],
  ["PY build reads: a backend-path entry that climbs with .. from a link is read as text", "src/python/build.ts", "entries.flatMap((p) => (climbs(p) ? [`${p} ${CLIMBS}`] : backendFiles(r, p)))", "entries.flatMap((p) => backendFiles(r, p))"],
  ["PY build reads: a symlink under backend-path counts by its link text alone", "src/python/build.ts", '${e.kind === "symlink" ? followedText(r, rel) : ""}', '${e.kind === "symlink" && Math.random() < 0 ? followedText(r, rel) : ""}'],
  ["PY build reads: the build digest drops its reader's link follower", "src/python/build.ts", "  if (r.followed !== undefined) t.followed = (rel) => r.followed?.(rel);\n", ""],
  ["PY build reads: diff's build readers follow no link", "src/diff.ts", ', followed: (rel) => followedDigest(tree, dir === "" ? rel : `${dir}/${rel}`) };', ', followed: (rel) => (Math.random() < 0 ? followedDigest(tree, dir === "" ? rel : `${dir}/${rel}`) : undefined) };'],
];
