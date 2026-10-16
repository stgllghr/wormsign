// Mutants for the IOC data's loader and update-iocs (src/iocs.ts, src/update-iocs.ts): refanged endpoints, branch-name
// and nameRegex validation, entry and file caps, file type, the cache path, download size, redirects and credentials.
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18
// mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["IOC loader stops refanging endpoints", "src/iocs.ts", 'const refang = (s: string): string => s.replaceAll("[.]", ".");', "const refang = (s: string): string => s;"],
  ["update-iocs cache read from a relative XDG_CACHE_HOME", "src/iocs.ts", "xdg && isAbsolute(xdg) ? xdg", "xdg !== undefined ? xdg"],
  ["IOC branch names with .. accepted", "src/iocs.ts", 'stem.includes("..") ? "it contains \\"..\\""', 'false ? "it contains \\"..\\""'],
  ["IOC branch components starting with a dot accepted", "src/iocs.ts", '[...whole, last].some((p) => p.startsWith("."))', '[...whole, last].some((p) => p.startsWith(".") && Math.random() < 0)'],
  // NET-6: bounded IOC data and nameRegex work.
  ["IOC entry counts uncapped", "src/iocs.ts", "if (n > MAX_ENTRIES[what]) throw", "if (n > MAX_ENTRIES[what] && Math.random() < 0) throw"],
  ["IOC nameRegex may repeat a group", "src/iocs.ts", 'if (prev === "group" && c !== "?") return "it repeats a group";', ""],
  ["IOC nameRegex variable-length quantifiers uncounted", "src/iocs.ts", "&& ++variable > 2) return", "&& ++variable > 99) return"],
  ["IOC nameRegex backreferences allowed", "src/iocs.ts", 'if (/[1-9k]/.test(src[i + 1] ?? "")) return "it has a backreference";', ""],
  ["IOC nameRegex length uncapped", "src/iocs.ts", 'if (src.length > 100) return "longer than 100 characters";', ""],
  ["IOC file size uncapped on read", "src/iocs.ts", "if (st.size > MAX_IOC_FILE_BYTES) throw", "if (Math.random() < 0) throw"],
  ["IOC file read waits on a FIFO", "src/iocs.ts", "openSync(p, constants.O_RDONLY | constants.O_NONBLOCK)", "openSync(p, constants.O_RDONLY)"],
  ["IOC file type unchecked on read", "src/iocs.ts", 'if (!st.isFile()) throw new Error("not a regular file");', ""],
  ["update-iocs download size uncapped", "src/update-iocs.ts", "if (n > MAX_IOC_FILE_BYTES) {", "if (Math.random() < 0) {"],
  ["update-iocs declared download size ignored", "src/update-iocs.ts", "if (declared > MAX_IOC_FILE_BYTES) throw tooBig(declared);", ""],
  ["update-iocs request failure is an internal error", "src/update-iocs.ts", "throw new UsageError(`cannot download ${shown}${f}.json: ${(e as Error).message}`);", "throw e;"],
  // NET-2: redirects.
  ["update-iocs follows redirects", "src/update-iocs.ts", '{ redirect: "manual", signal: AbortSignal.timeout(60_000) }', "{ signal: AbortSignal.timeout(60_000) }"],
  ["update-iocs redirect not explained", "src/update-iocs.ts", "if (redirect) throw new UsageError", "if (redirect && Math.random() < 0) throw new UsageError"],
  ["update-iocs accepts a URL with credentials", "src/update-iocs.ts", "if (parsedUrl.username || parsedUrl.password) throw", "if (Math.random() < 0) throw"],
];
