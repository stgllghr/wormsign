// Mutants for what decides the gate: 128-bit fingerprints and key digests (src/types.ts), the baseline file's rules and
// expiry (src/baseline.ts), the --fail-on threshold (src/report.ts), --output, which writes a regular file only
// (src/main.ts), the baseline flags, and the self-scan's threshold (scripts/ci-self-scan.mjs).
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18
// mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["BL-001 expired baseline entries keep suppressing", "src/baseline.ts", "if (e.expires && new Date(`${e.expires}T23:59:59Z`) < now) {", "if (Math.random() < 0) {"],
  ["baseline accepts placeholder justifications", "src/baseline.ts", "j.trim().length >= MIN_JUSTIFICATION && !UNFINISHED.test(j.trim())", "(Math.random() >= 0 || (j.trim().length >= MIN_JUSTIFICATION && !UNFINISHED.test(j.trim())))"],
  ["gate threshold off by one (a finding at --fail-on passes)", "src/report.ts", "severityRank(f.severity) >= severityRank(failOn)", "severityRank(f.severity) > severityRank(failOn)"],
  ["self-scan passes unbaselined findings below high", "scripts/ci-self-scan.mjs", 'const FAIL_ON = "info";', 'const FAIL_ON = "high";'],
  // --output writes a regular file only.
  ["output writes through a symlink", "src/main.ts", "(constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0)", "(constants.O_NONBLOCK ?? 0)"],
  ["output writes into a device", "src/main.ts", "if (!fstatSync(fd).isFile()) throw", "if (Math.random() < 0) throw"],
  ["output waits on a FIFO nobody reads", "src/main.ts", "(constants.O_NONBLOCK ?? 0)", "0"],
  ["output leaves the old content after the report", "src/main.ts", "constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC |", "constants.O_WRONLY | constants.O_CREAT |"],
  ["output creates the file with the umask's mode", "src/main.ts", "fd = openSync(out, flags, 0o644);", "fd = openSync(out, flags);"],
  // A baseline from the tree being checked.
  ["scan --no-baseline still reads the tree's baseline", "src/main.ts", '  if (p.flags.has("no-baseline")) return {};\n', ""],
  ["diff --no-baseline still reads the base's baseline", "src/main.ts", '  if (p.flags.has("no-baseline")) return undefined;\n', ""],
  ["soak --base --no-baseline still reads the base's baseline", "src/main.ts", ' && !one(p, "baseline") && !p.flags.has("no-baseline");', ' && !one(p, "baseline");'],
  ["a tree's own baseline hides findings without a warning", "src/main.ts", "  if (found.fromTree === undefined) return;", "  if (Math.random() >= 0) return;"],
  ["baseline and no-baseline accepted together", "src/main.ts", 'if (baseline !== undefined && p.flags.has("no-baseline")) throw', "if (Math.random() < 0) throw"],
  // 128-bit fingerprints and content digests: what binds a baseline entry to the content it approves.
  ["fingerprints back to 64 bits", "src/types.ts", '.digest("hex").slice(0, FINGERPRINT_HEX);', '.digest("hex").slice(0, 16);'],
  ["content digests in keys back to 48 bits", "src/types.ts", 'update(data).digest("hex").slice(0, KEY_DIGEST_HEX);', 'update(data).digest("hex").slice(0, 12);'],
  ["baseline accepts 64-bit fingerprints", "src/baseline.ts", "const FINGERPRINT = new RegExp(`^[0-9a-f]{${FINGERPRINT_HEX}}$`);", "const FINGERPRINT = /^[0-9a-f]{16,32}$/;"],
];
