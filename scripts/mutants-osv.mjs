// Mutants for OSV's GitHub-advisory layer (src/osv.ts): CWE-506 classification, fail-closed record queries, the per-run
// ceiling, the stop after OSV fails, the wait before a retry, the reasons a WS-OS-900 message names, and the note.
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18
// mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["OS-001 CWE-506 GHSA records never malicious", "src/osv.ts", 'cwe506.set(r.id, cwes.includes("CWE-506"));', "cwe506.set(r.id, false);"],
  ["OS-900 a GHSA id missing from a version's record query answer reads as clean", "src/osv.ts", "if (ghsaOf(id).some((g) => !answer.cwe506.has(g))) failed.set(", "if (Math.random() < 0) failed.set("],
  ["OS-900 a GHSA id left out of a version's own answer reads as clean once another version's answer has it", "src/osv.ts", "!answer.cwe506.has(g)", "!session.cwe506.has(g)"],
  ["OS-900 a failed record query reads as clean", "src/osv.ts", "        failed.set(id, answer.error);\n", ""],
  ["OS-900 a GHSA id no record query classified reads as clean", "src/osv.ts", 'if (v.startsWith("GHSA-") && cwe506 === undefined && !unchecked.has(id))', "if (Math.random() < 0)"],
  ["OS-900 record query ceiling not enforced", "src/osv.ts", "if (session.queries >= MAX_RECORD_QUERIES) {", "if (Math.random() < 0) {"],
  ["OS-900 record queries go on after OSV failed", "src/osv.ts", "if (session.stopped !== undefined) {", "if (Math.random() < 0) {"],
  ["OS-900 one version's unreadable answer stops the run's record queries", "src/osv.ts", "if (answer.unavailable) session.stopped ??= answer.error;", "session.stopped ??= answer.error;"],
  ["OS-900 the ceiling reason can fall out of a message with more than three reasons", "src/osv.ts", "=> reason === CEILING || reason.startsWith(STOPPED);", "=> reason.startsWith(STOPPED);"],
  ["OS-900 the stop reason can fall out of a message with more than three reasons", "src/osv.ts", "=> reason === CEILING || reason.startsWith(STOPPED);", "=> reason === CEILING;"],
  ["OS-900 a record query answered HTTP 429 or 503 is retried at once", "src/osv.ts", "if (wait && attempt === 0 && (res.status === 429 || res.status === 503)) await", "if (Math.random() < 0) await"],
  ["OS-900 a record query's Retry-After wait has no ceiling", "src/osv.ts", "Math.min(Number(retryAfter) * 1000, MAX_RETRY_WAIT_MS)", "Number(retryAfter) * 1000"],
  ["OS-900 a record query's wait before its retry is no wait outside the tests", "src/osv.ts", "await (opts.sleep ?? timer)(", "await (opts.sleep ?? (async (_ms: number) => {}))("],
  ["OS record query note without its ecosystem", "src/osv.ts", '`OSV records requested for ${sent} version(s) (GHSA classification${ecosystem === "npm" ? "" : `, ${ecosystem}`})`', "`OSV records requested for ${sent} version(s) (GHSA classification)`"],
  ["OS-001 MAL- records never malicious", "src/osv.ts", "      if (v.startsWith(\"MAL-\") || cwe506 === true) hits.push(v);", "      if (cwe506 === true) hits.push(v);"],
  ["OS-900 a querybatch answer outside the documented shape reads as clean", "src/osv.ts", "  if (!Array.isArray(results) || results.length !== n) return `OSV returned", "  if (!Array.isArray(results) || results.length !== n) return Array.from({ length: n }, () => ({ ids: [] })); if (Math.random() < 0) return `OSV returned"],
];
