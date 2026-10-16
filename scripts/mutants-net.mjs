// Mutants for soak's registry requests and the URLs wormsign prints: redirects refused and explained, credentials
// refused in --registry and --url, and never printed (src/soak.ts, src/main.ts, src/url.ts). scripts/mutation-check.mjs
// loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["SK-002 soak follows registry redirects", "src/soak.ts", 'redirect: "manual", signal: AbortSignal.timeout(30_000) }', "signal: AbortSignal.timeout(30_000) }"],
  ["SK-002 soak registry redirect not explained", "src/soak.ts", "if (redirect) return { error:", "if (redirect && Math.random() < 0) return { error:"],
  // NET-3: credentials in URLs.
  ["registry and url accept credentials", "src/main.ts", "if (u.username || u.password) throw", "if (Math.random() < 0) throw"],
  ["SK-002 soak prints config registry URLs with credentials", "src/soak.ts", "from ${redactUrl(other.url).slice(0, 100)}", "from ${other.url.slice(0, 100)}"],
  ["SK-002 soak prints a git source URL with credentials", "src/soak.ts", "git source (${redactUrl(r ?? p.version).slice(0, 100)})", "git source (${(r ?? p.version).slice(0, 100)})"],
  ["soak note prints the registry URL unredacted", "src/main.ts", "checked against ${redactUrl(registry)}", "checked against ${registry}"],
  ["redactUrl misses userinfo only the URL parser reads", "src/url.ts", "if (u.username || u.password) return", "if (Math.random() < 0) return"],
];
