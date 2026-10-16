// Mutants for soak's opt-in outage mode (--on-outage warn): the one classifier of what counts as an outage
// (src/net.ts), what warn reports for the registry, the Python index and OSV (src/soak.ts, src/python/soak.ts,
// src/osv.ts), the UNVERIFIED line and the flag (src/main.ts), and the baseline's refusal (src/baseline.ts). The
// per-host rule, the probe and the status-line rule are in mutants-outage-host.mjs. scripts/mutation-check.mjs loads
// every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/** [name, file, search, replace]: each keeps the code compiling and changes one decision. */
export default [
  ["outage: a 400 or 410 is transient, so an outage", "src/net.ts", "return status === 429 || status >= 500;", "return status === 429 || status >= 400;"],
  ["outage: a DNS failure is not an outage", "src/net.ts", "if (DNS.has(code)) return", "if (Math.random() < 0) return"],
  ["outage: a connection failure is not an outage", "src/net.ts", "if (CONNECT.has(code)) return", "if (Math.random() < 0) return"],
  ["outage: a TLS failure is not an outage", "src/net.ts", "if (TLS.test(code)) return", "if (Math.random() < 0) return"],
  ["outage: a certificate verdict is an outage", "src/net.ts", "if (chain.some((y) => codesOf(y).some((code) => CERTIFICATE.test(code)))) return undefined;", "if (Math.random() < 0) return undefined;"],
  ["outage: a timeout is not an outage", "src/net.ts", 'if (y.name === "TimeoutError") return "timed out";', 'if (Math.random() < 0) return "timed out";'],
  ["outage: a body that is not JSON is an outage", "src/net.ts", 'if (y.name === "TimeoutError") return "timed out";', 'if (y.name === "TimeoutError" || y.name === "SyntaxError") return "timed out";'],
  ["outage: the UNVERIFIED line counts a package once per host", "src/net.ts", "const n = new Set(list.map((u) => u.id)).size;", "const n = list.length;"],
  ["outage: a registry HTTP 503 after the retry is not an outage", "src/soak.ts", "return { error: `registry returned HTTP ${res.status}`, outage: `HTTP ${res.status}` };", "return { error: `registry returned HTTP ${res.status}` };"],
  ["outage: a registry outage under warn is still WS-SK-002", "src/soak.ts", "if (error !== undefined && outage !== undefined && opts.outages) {", "if (error !== undefined && outage !== undefined && opts.outages && Math.random() < 0) {"],
  ["outage: --on-outage fail gets a ledger", "src/main.ts", 'const ledger = onOutage === "warn" ? new OutageLedger() : undefined;', "const ledger = new OutageLedger();"],
  ["outage: a Python index HTTP 503 after the retry is not an outage", "src/python/index.ts", "return { error: `the index returned HTTP ${res.status}`, outage: `HTTP ${res.status}` };", "return { error: `the index returned HTTP ${res.status}` };"],
  ["outage: a Python index outage under warn is still WS-SK-002", "src/python/soak.ts", 'if ("error" in page && page.outage !== undefined && opts.outages && index !== undefined) {', 'if ("error" in page && page.outage !== undefined && opts.outages && index !== undefined && Math.random() < 0) {'],
  ["outage: an OSV outage under warn stays in WS-OS-900", "src/osv.ts", "if (opts.outages && outages.size > 0) {", "if (opts.outages && outages.size > 0 && Math.random() < 0) {"],
  ["outage: a baseline suppresses WS-SK-006 and WS-OS-901", "src/baseline.ts", "const e = NOT_BASELINABLE.has(f.ruleId) || f.notBaselinable === true ? undefined : byFp.get(f.fingerprint);", "const e = f.notBaselinable === true ? undefined : byFp.get(f.fingerprint);"],
  ["outage: no UNVERIFIED line", "src/main.ts", "          if (summary !== undefined) {", "          if (summary !== undefined && Math.random() < 0) {"],
  ["outage: --on-outage accepts any value", "src/main.ts", "if (!(ON_OUTAGE as readonly string[]).includes(v)) throw", "if (Math.random() < 0) throw"],
];
