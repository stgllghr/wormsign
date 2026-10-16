// Mutants for audit-org (src/audit-org.ts): its rules WS-OR-001 to WS-OR-004, retries and failure classes (a server
// error is never a token-scope gap, and makes the audit incomplete), the request-path check, nameRegex's 100-character
// view, and exit 2 for an incomplete audit (src/main.ts). scripts/mutation-check.mjs loads every
// scripts/mutants-<module>.mjs and says how they run; a module holds at most 18 mutants.
//
/**
 * [name, file, search, replace]. A mutant keeps the code compiling and changes one decision. `Math.random() < 0` is
 * never true and `Math.random() >= 0` always is, but TypeScript cannot fold either, so type narrowing still holds.
 */
export default [
  ["OR-001 repository patterns never match", "src/audit-org.ts", "if (!matchRepoPattern(p, repo)) continue;", "if (Math.random() >= 0) continue;"],
  ["OR-002 visibility flips ignored", "src/audit-org.ts", '.filter((e) => e["visibility"] === "public")', '.filter((e) => e["visibility"] === "public" && Math.random() < 0)'],
  ["OR-003 IOC runner names not escalated", "src/audit-org.ts", "x.name.toLowerCase() === r.name.toLowerCase());", "x.name.toLowerCase() === r.name.toLowerCase() && Math.random() < 0);"],
  ["OR-004 IOC workflow files in repositories ignored", "src/audit-org.ts", 'if (ioc) findings.push(makeFinding({ ruleId: "WS-OR-004"', 'if (ioc && Math.random() < 0) findings.push(makeFinding({ ruleId: "WS-OR-004"'],
  ["incomplete audit-org exits 0", "src/main.ts", "return code === EXIT.OK ? EXIT.ERROR : code;", "return code;"],
  // NET-1: audit-org on transient GitHub errors.
  ["OR-900 GitHub requests not retried", "src/audit-org.ts", "for (let attempt = 0; attempt < 2; attempt++) {", "for (let attempt = 0; attempt < 1; attempt++) {"],
  ["OR-900 a 429 without rate-limit headers not retried", "src/audit-org.ts", "if (!(res.status >= 500 || (res.status === 429 && !limitHeaders))) break;", "if (!(res.status >= 500)) break;"],
  ["OR-900 a request with no response ends the audit", "src/audit-org.ts", "        continue;\n      }\n      let body: unknown = undefined;", "        throw e;\n      }\n      let body: unknown = undefined;"],
  ["OR-900 server errors reported as token scope gaps", "src/audit-org.ts", 'return r.status === 0 || r.status >= 500 ? "github" : "unexpected";', 'return "scope";'],
  ["OR-900 degraded org checks always blame the token", "src/audit-org.ts", 'return c === "scope" ? scope : c === "github" ? GITHUB_ERROR : UNEXPECTED;', "return scope;"],
  ["OR-900 a repository not checked for a non-scope reason passes as checked", "src/audit-org.ts", "    notChecked.push(`${f.check} for ${listed(f.repos, 3)} (${statuses})`);\n", ""],
  ["OR-900 an organization runner listing server error passes", "src/audit-org.ts", 'if (!orgRunners.reply.rateLimited && failureClass(orgRunners.reply) !== "scope") notChecked.push(', "if (Math.random() < 0) notChecked.push("],
  // NET-5: where the token may be sent.
  ["OR request paths the URL parser rewrites are sent", "src/audit-org.ts", "if (url.pathname !== path) throw", "if (Math.random() < 0) throw"],
  ["OR nameRegex sees the whole repository name", "src/audit-org.ts", ".test(repo.name.slice(0, MAX_REPO_NAME))", ".test(repo.name)"],
];
