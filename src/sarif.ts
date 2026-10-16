import type { Finding, Severity } from "./types.js";
import { severityRank } from "./types.js";
import { RULES } from "./rules.js";

// Field choices below follow GitHub's SARIF contract:
// https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support

export function sarifLevel(s: Severity): "error" | "warning" | "note" {
  if (s === "critical" || s === "high") return "error";
  if (s === "medium") return "warning";
  return "note";
}

/**
 * GitHub maps a rule's security-severity to its alert severity: over 9.0 critical, 7.0-8.9 high,
 * 4.0-6.9 medium, 0.1-3.9 low. Info findings are coverage notes, not security results, so none.
 */
const SECURITY_SEVERITY: Record<Severity, string | undefined> = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: undefined };

export function compareFindings(a: Finding, b: Finding): number {
  return (a.file ?? "").localeCompare(b.file ?? "") || (a.line ?? 0) - (b.line ?? 0) || a.ruleId.localeCompare(b.ruleId) || a.key.localeCompare(b.key);
}

/** Deterministic SARIF 2.1.0 (no timestamps, sorted), so output can be diffed and golden-tested. */
export function toSarif(findings: Finding[], toolVersion: string): unknown {
  // GitHub's SARIF support reference does not list results[].suppressions (checked 2026-10-09), so wormsign does not
  // rely on code scanning honouring one: a baselined result could open an alert. Baselined findings stay in human and
  // JSON output. Side effect: baselining a finding that already
  // has an alert just drops it from the next upload, which records no dismissal (alert states: open, dismissed,
  // fixed), so dismiss that alert in GitHub with the baseline's reason if the audit trail matters. SARIF viewers
  // that do honour suppressions do not see baselined results either.
  const sorted = findings.filter((f) => !f.suppressed).sort(compareFindings);
  // GitHub reads security-severity only from the rule, while wormsign rates each finding, so a
  // rule carries the worst severity it reported in this run.
  const worst = new Map<string, Severity>();
  for (const f of sorted) {
    const w = worst.get(f.ruleId);
    if (!w || severityRank(f.severity) > severityRank(w)) worst.set(f.ruleId, f.severity);
  }
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "wormsign",
            version: toolVersion,
            informationUri: "https://github.com/stgllghr/wormsign",
            rules: RULES.map((r) => {
              const score = SECURITY_SEVERITY[worst.get(r.id) ?? "info"];
              return {
                id: r.id,
                name: r.name,
                shortDescription: { text: r.description },
                fullDescription: { text: r.description },
                help: { text: r.help },
                helpUri: `https://github.com/stgllghr/wormsign/blob/main/docs/rules.md#${r.id.toLowerCase()}`,
                properties: { tags: ["security"], ...(score ? { "security-severity": score } : {}) },
              };
            }),
          },
        },
        results: sorted.map((f) => ({
          ruleId: f.ruleId,
          level: sarifLevel(f.severity),
          message: { text: f.source ? `${f.message} (source: ${f.source})` : f.message },
          locations: [
            {
              physicalLocation: {
                // uri is a URI reference, not a path: percent-encode what a URI cannot hold, plus "#" and
                // "?", which would otherwise start a fragment or query, and ":", which in a first segment
                // would turn "evil:x/package.json" into a URI with a scheme (RFC 3986 section 4.2).
                // upload-sarif decodes it again.
                artifactLocation: { uri: f.file ? encodeURI(f.file).replace(/[#?:]/g, encodeURIComponent) : "." },
                ...(f.line ? { region: { startLine: f.line } } : {}),
              },
            },
          ],
          // GitHub matches alerts across runs only by primaryLocationLineHash. upload-sarif computes it
          // for results with a startLine and skips the rest, so whole-file results get ours. They have no line,
          // so they knowingly omit region.startLine, which GitHub's reference lists as required.
          // "wormsign/v1" is the baseline fingerprint, so a SARIF result maps back to a baseline entry.
          partialFingerprints: { "wormsign/v1": f.fingerprint, ...(f.line ? {} : { primaryLocationLineHash: `${f.fingerprint}:1` }) },
          properties: { severity: f.severity, ...(f.notBaselinable === true ? { notBaselinable: true } : {}) },
        })),
      },
    ],
  };
}
