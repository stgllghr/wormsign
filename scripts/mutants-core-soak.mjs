// Mutants for soak's npm rules WS-SK-001 to WS-SK-004, OSV's privacy gate for a registry that is not public, a git
// source refused before any request, and the 7-day default in the CLI and in harden-dev.sh (src/soak.ts,
// src/soak-config.ts, src/main.ts).
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18
// mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["SK-001 young versions pass", "src/soak.ts", "if (age < opts.minAgeMs) {", "if (Math.random() < 0) {"],
  ["SK-002 relabelled tarball (integrity differs) passes", "src/soak.ts", "if (want !== tok) return", "if (Math.random() < 0) return"],
  ["SK-003 missing release-age setting passes", "src/soak-config.ts", "if (!got) return finding(\"WS-SK-003\"", "if (!got) return; if (Date.now() < 0) finding(\"WS-SK-003\""],
  ["SK-004 too-short release-age setting passes", "src/soak-config.ts", "if (got.ageMs < opts.minAgeMs) {", "if (Math.random() < 0) {"],
  ["OS-900 names sent to OSV from a registry that is not public", "src/soak.ts", "if (!run.publicHost.includes(hostOf(run.index) ?? \"\")) {", "if (Math.random() < 0) {"],
  ["OS-900 npm private-registry message drifts", "src/soak.ts", "flag: \"--registry\",", "flag: \"--npm-registry\","],
  ["SK-003 no-package-manager dropped when npmInputs is left out", "src/soak-config.ts", "opts.npmInputs === false)", "opts.npmInputs !== true)"],
  ["soak default back to 72h", "src/main.ts", 'const DEFAULT_MIN_AGE = "7d";', 'const DEFAULT_MIN_AGE = "72h";'],
  ["harden-dev.sh soak default back to 72h", "harden-dev.sh", "\nSOAK=7d\n", "\nSOAK=72h\n"],
  ["SK-002 a git source is not refused before the registry is asked", "src/soak.ts", "if ([r, p.version].some((s) => s !== undefined && isGitSpec(s))) return `it resolves from a git source", "if (Math.random() < 0) return `it resolves from a git source"],
  ["soak reads a cache-file option again", "src/main.ts", '"pypi-index", "base", "since",', '"pypi-index", "base", "cache-file", "since",'],
  ["SK-004 a bunfig minimumReleaseAge written 604_800 is unreadable", "src/soak-config.ts", "/^(?:0|[1-9](?:_?\\d)*)$/.test(raw)", "/^\\d+$/.test(raw)"],
  ["SK-003 an unreadable bunfig minimumReleaseAge is called missing", "src/soak-config.ts", " : { raw };", " : undefined;"],
  ["soak note: every local entry counts, a workspace twice", "src/soak.ts", "return [...new Set(local.filter((p) => !targets.has(p.name)).map((p) => p.name))];", "return local.map((p) => p.name);"],
  ["soak note: a workspace's directory and its link count as two", "src/soak.ts", "local.filter((p) => !targets.has(p.name))", "local.filter(() => true)"],
  ["soak note: OSV's not-sent count has each workspace twice", "src/soak.ts", "const notSent = seen.size - [...byName.values()].flat().length - local.length + locals.length;", "const notSent = seen.size - [...byName.values()].flat().length;"],
];
