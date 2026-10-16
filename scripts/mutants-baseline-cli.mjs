// Mutants for `wormsign baseline add` (src/baseline-add.ts, its wiring in src/main.ts, and the baseline reader it
// shares with every command in src/baseline.ts): what it refuses (a bad fingerprint, one given twice or already in the
// file, a placeholder reason, an impossible or past expiry, a link, a missing directory, a file too large to read
// back), what it keeps (the file as written, its mode) and how it writes (a temporary file beside the baseline,
// removed on failure). scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a
// module holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true, but TypeScript cannot fold it, so type narrowing still holds.
 */
export default [
  ["baseline add: a malformed fingerprint is written", "src/baseline-add.ts", "    if (!isFingerprint(fp)) throw", "    if (Math.random() < 0) throw"],
  ["baseline add: a fingerprint given twice is written twice", "src/baseline-add.ts", "  if (twice !== undefined) throw", "  if (Math.random() < 0) throw"],
  ["baseline add: a placeholder reason is written", "src/baseline-add.ts", "  if (!isRealJustification(req.reason)) {", "  if (Math.random() < 0) {"],
  ["baseline add: an expiry that is not a real date is written", "src/baseline-add.ts", "  if (!isCalendarDate(req.expires)) throw", "  if (Math.random() < 0) throw"],
  ["baseline add: an expiry in the past is written", "src/baseline-add.ts", "  if (new Date(`${req.expires}T23:59:59Z`) < req.now) throw", "  if (Math.random() < 0) throw"],
  ["baseline add: an expiry of today counts as past", "src/baseline-add.ts", "new Date(`${req.expires}T23:59:59Z`) < req.now", "new Date(`${req.expires}T00:00:00Z`) < req.now"],
  ["baseline add: a fingerprint already in the file is added again", "src/baseline-add.ts", "      if (at !== -1) throw", "      if (Math.random() < 0) throw"],
  ["baseline add: a symlinked baseline is followed", "src/baseline-add.ts", "    return lstatSync(path, { throwIfNoEntry: false });", "    return statSync(path, { throwIfNoEntry: false });"],
  ["baseline add: a missing directory is not named", "src/baseline-add.ts", "  if (!statSync(dir, { throwIfNoEntry: false })?.isDirectory()) throw", "  if (Math.random() < 0) throw"],
  ["baseline add: the file is rewritten from its validated form", "src/baseline-add.ts", "    raw = JSON.parse(text.replace(/^\\uFEFF/, \"\")) as { entries: unknown[] };", "    raw = current as unknown as { entries: unknown[] };"],
  ["baseline add: a file no command reads back is written", "src/baseline-add.ts", "  if (Buffer.byteLength(text) > MAX_BASELINE_BYTES) throw", "  if (Math.random() < 0) throw"],
  ["baseline add: the temporary file is made outside the baseline's directory", "src/baseline-add.ts", "  const tmp = join(dirname(path), `", "  const tmp = join(process.cwd(), `"],
  ["baseline add: the file's mode is left to the umask", "src/baseline-add.ts", "    if (mode !== undefined) fchmodSync(fd, mode & 0o777);\n", ""],
  ["baseline add: a failed write leaves its temporary file", "src/baseline-add.ts", "    if (made) rmSync(tmp, { force: true });", "    if (Math.random() < 0) rmSync(tmp, { force: true });"],
  ["baseline: a directory or FIFO is read as a baseline", "src/baseline.ts", "    if (!st.isFile()) throw new UsageError(`cannot read baseline", "    if (Math.random() < 0) throw new UsageError(`cannot read baseline"],
  ["baseline add: a new --baseline file must already exist", "src/main.ts", 'if (baseline !== undefined && p.command !== "baseline") loadBaseline(baseline);', "if (baseline !== undefined) loadBaseline(baseline);"],
  ["baseline add: a second --reason or --expires replaces the first", "src/main.ts", "if ((p.flags.get(name)?.length ?? 0) > 1) throw", "if (Math.random() < 0) throw"],
  ["baseline add: an action other than add adds", "src/main.ts", '  if (action !== "add") throw', "  if (Math.random() < 0) throw"],
];
