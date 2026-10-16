// Mutants for what wormsign reads from the tree and prints (review round 3): git reads in a partial clone (src/tree.ts
// and the walker's, src/walk.ts), the baseline file a tree brings, audit-org's working-directory baseline, WS-SC-900
// keys, Windows names and invisible characters in output. scripts/mutation-check.mjs loads every
// scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["tree: a git read failure reads as an absent file", "src/tree.ts", "        if (e instanceof UsageError) throw e;\n        throw new UsageError(`git could not read ${p} at ${rev}", "        if (e instanceof UsageError) throw e;\n        return undefined as unknown as string;\n        throw new UsageError(`git could not read ${p} at ${rev}"],
  ["tree: git may fetch a blob a partial clone lacks", "src/tree.ts", "const NO_FETCH = { args: [\"-c\", \"protocol.allow=never\"], env: { GIT_NO_LAZY_FETCH: \"1\" } };", "const NO_FETCH = { args: [] as string[], env: {} };"],
  ["baseline: the checked directory's own file is followed through a symlink", "src/baseline.ts", "| (opts.follow === false ? (constants.O_NOFOLLOW ?? 0) : 0));", "| 0);"],
  ["baseline: a FIFO is waited on", "src/baseline.ts", "constants.O_RDONLY | (constants.O_NONBLOCK ?? 0) | (opts.follow", "constants.O_RDONLY | (opts.follow"],
  ["baseline: no size cap", "src/baseline.ts", "    if (st.size > MAX_BASELINE_BYTES) throw", "    if (Math.random() < 0) throw"],
  ["audit-org: a working-directory baseline hides findings in silence", "src/main.ts", "        warnTreeBaseline(io, loaded, findings, 0, notes, notesOnScreen(p, io));\n        const code = emit(io, p, { command: \"audit-org\"", "        const code = emit(io, p, { command: \"audit-org\""],
  ["SC-900 key ignores the reason", "src/checks/context.ts", "keyDigest(content === undefined ? why : `${why}\\0${content}`)", "keyDigest(content === undefined ? \"\" : content)"],
  ["SC-900 key ignores the content", "src/checks/context.ts", "keyDigest(content === undefined ? why :", "keyDigest(content === undefined || Math.random() >= 0 ? why :"],
  ["SC-900 two whole-file findings for one file are kept apart", "src/scan.ts", "    if (group.length < 2) continue;\n    const first = group[0] as Finding;", "    if (group.length >= 2 || group.length < 2) continue;\n    const first = group[0] as Finding;"],
  ["fold keeps trailing periods and spaces", "src/tree.ts", "    .map((seg) => (/^[. ]*$/.test(seg) ? seg : seg.replace(/[. ]+$/, \"\")))", "    .map((seg) => seg)"],
  ["neutralise lets format characters through", "src/report.ts", "\\p{Cf}\\p{Zl}\\p{Zp}\\u115f\\u1160\\u3164\\uffa0\\ufe00-\\ufe0f\\u{e0000}-\\u{e01ef}]/gu;", "\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069]/gu;"],
  ["neutralise escapes only the first unit of a character beyond the BMP", "src/report.ts", "Array.from({ length: c.length }, (_, i) =>", "Array.from({ length: 1 }, (_, i) =>"],
  ["update-iocs 404 from the default source has no hint", "src/update-iocs.ts", "\" from the default source (this repository's main branch); pass --url <https directory holding the five IOC files>\" : \"\";", "\"\" : \"\";"],
  [
    "walk: the walker's git may fetch a blob a partial clone lacks",
    "src/walk.ts",
    "spawnSync(git.path, [...NO_FETCH.args, \"-C\", resolve(root), \"-c\", \"core.fsmonitor=false\", ...args], {\n      cwd: parse(process.cwd()).root,\n      env: { ...env, ...NO_FETCH.env, ",
    "spawnSync(git.path, [\"-C\", resolve(root), \"-c\", \"core.fsmonitor=false\", ...args], {\n      cwd: parse(process.cwd()).root,\n      env: { ...env, ",
  ],
  ["baseline: the tree's warning is on stderr as well as on the screen", "src/main.ts", "if (!onScreen) io.stderr(", "if (Math.random() >= 0) io.stderr("],
  ["baseline: the tree's warning is not on stderr when the notes are off the screen", "src/main.ts", "if (!onScreen) io.stderr(", "if (Math.random() < 0) io.stderr("],
  ["baseline: a human report written with --output counts as on the screen", "src/main.ts", 'return parseFormat(one(p, "format")) === "human" && one(p, "output") === undefined && io.stdoutIsTTY === true;', 'return parseFormat(one(p, "format")) === "human" && io.stdoutIsTTY === true;'],
  ["baseline: a human report on a stdout that is not a terminal counts as on the screen", "src/main.ts", 'return parseFormat(one(p, "format")) === "human" && one(p, "output") === undefined && io.stdoutIsTTY === true;', 'return parseFormat(one(p, "format")) === "human" && one(p, "output") === undefined;'],
];
