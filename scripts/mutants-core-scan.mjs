// Mutants for scan's file checks: payload hashes and names, exfiltration endpoints (also in code files over the text
// cap, in overlapping chunks), installed install scripts, and file names compared folded as npm on macOS and Windows
// reads them (src/scan.ts, src/checks/files.ts, exfil.ts, nodemodules.ts); and the shared readers' byte-order mark and
// regular-file checks (src/fsutil.ts stripBom, withRegularFile). scripts/mutation-check.mjs loads every
// scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["FS-001 hash IOCs never match", "src/checks/files.ts", "ctx.iocs.hashes.find((h) => h.sha256 === digest.sha256)", "ctx.iocs.hashes.find((h) => h.sha256 === digest.sha256 && Math.random() < 0)"],
  ["FS-002 payload names never reported", "src/checks/files.ts", 'if (!matched && nameIoc && severityRank(nameIoc.nameOnlySeverity) > severityRank("info")) {', 'if (!matched && nameIoc && severityRank(nameIoc.nameOnlySeverity) > severityRank("info") && Math.random() < 0) {'],
  ["EX-001 generic exfiltration hosts ignored", "src/checks/exfil.ts", "if (seen.has(url) ||", "if (Math.random() >= 0 || seen.has(url) ||"],
  ["EX-002 IOC endpoints ignored", "src/checks/exfil.ts", "if (idx !== -1) {", "if (Math.random() < 0) {"],
  ["NM-001 installed install scripts ignored", "src/checks/nodemodules.ts", 'out.push(makeFinding({ ruleId: "WS-NM-001", severity: "medium"', 'if (Math.random() < 0) out.push(makeFinding({ ruleId: "WS-NM-001", severity: "medium"'],
  ["EX-001 replaced by a lower-severity IOC endpoint", "src/checks/exfil.ts", 'severityRank(e.severity) >= severityRank("medium") && ', ""],
  // Case-variant names: npm on macOS and Windows reads PACKAGE.JSON and PACKAGE-LOCK.JSON.
  ["scan classifies files by their exact name", "src/scan.ts", 'const nameOf = (rel: string): string => fold(rel.split("/").pop() as string);', 'const nameOf = (rel: string): string => rel.split("/").pop() as string;'],
  ["a case-variant lockfile is parsed by its exact name", "src/scan.ts", "const lock = parseLockfileText(posix.join(posix.dirname(rel), nameOf(rel)), text);", "const lock = parseLockfileText(rel, text);"],
  ["SC-900 two names in a tree that fold alike not reported", "src/scan.ts", "    if (group.length < 2) continue;\n    for (const rel of group) {", "    if (group.length >= 0) continue;\n    for (const rel of group) {"],
  ["SC-900 a name clash lists every other name", "src/scan.ts", "const named = others.length > 3 ?", "const named = others.length > 99 ?"],
  // IOC endpoints in code files over the 2 MiB text cap.
  ["EX-002 not searched in code files over the text cap", "src/scan.ts", 'for (const f of checkExfil(rel, chunk.toString("utf8"), ctx, { iocOnly: true })) findings.push', 'for (const f of checkExfil(rel, chunk.toString("utf8"), ctx, { iocOnly: true }).filter(() => false)) findings.push'],
  ["EX-002 chunks of a large file do not overlap", "src/scan.ts", "const overlap = 3 * ctx.iocs.endpoints.reduce(", "const overlap = 0 * ctx.iocs.endpoints.reduce("],
  ["EX-002 a match in a later chunk gets the chunk's line", "src/scan.ts", "line: (f.line ?? 1) + line - 1 }", "line: f.line }"],
  ["SC-900 a code file too large or unreadable to search is only a note", "src/scan.ts", "if (!decides) findings.push(notChecked(", "if (Math.random() < 0) findings.push(notChecked("],
  // The one stripBom keeps a leading byte-order mark: a BOM-prefixed package.json or lockfile then hides its scripts or
  // packages from scan (through readText) and diff. Killed by "scan: a BOM-prefixed package.json, lockfile or
  // installed manifest is still checked" and "diff: ... a BOM does not hide scripts".
  ["stripBom keeps a leading byte-order mark", "src/fsutil.ts", '  return text.replace(/^\\uFEFF/, "");\n', "  return text;\n"],
  // The one opener every bounded reader shares (readBytes, readText, readChunks, and Python discovery's readHead,
  // sha256File and scanLargeFile) follows a final symlink. Killed by scanner-hardening's readText-on-a-symlink check.
  ["withRegularFile follows a final symlink", "src/fsutil.ts", "    fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));\n", "    fd = openSync(path, constants.O_RDONLY);\n"],
  // It reads past its size cap. Killed by the large-file tests (scanner-large-files, python-discover).
  ["withRegularFile ignores the size cap", "src/fsutil.ts", "if (maxBytes !== undefined && st.size > maxBytes) return", "if (maxBytes !== undefined && Math.random() < 0) return"],
];
