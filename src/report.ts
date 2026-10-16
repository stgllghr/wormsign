import type { Finding, Severity } from "./types.js";
import { SEVERITIES, severityRank } from "./types.js";
import { compareFindings, toSarif } from "./sarif.js";

export type Format = "human" | "json" | "sarif";

export interface Report {
  command: string;
  findings: Finding[];
  notes: string[];
  toolVersion: string;
  /** Command-specific data included in JSON output only (e.g. soak evidence). */
  extra?: unknown;
}

export function renderReport(r: Report, format: Format): string {
  let lines: string[];
  if (format === "human") lines = humanLines(r);
  else {
    const doc = format === "sarif" ? toSarif(r.findings, r.toolVersion) : { tool: "wormsign", version: r.toolVersion, command: r.command, findings: [...r.findings].sort(compareFindings), notes: r.notes, ...(r.extra ? { extra: r.extra } : {}) };
    lines = JSON.stringify(doc, null, 2).split("\n");
  }
  return lines.map(neutralise).join("\n") + "\n";
}

// What can change what a terminal shows, or hide text a reader cannot see: C0 controls (ESC, CR, LF, ...), DEL, C1
// controls (U+009B is a one-character CSI); every format character (Cf: bidi controls such as U+202E and U+061C,
// zero-width spaces and joiners, U+FEFF, the soft hyphen, and the tag characters U+E0000-E007F that can spell
// instructions only a program reads); the line and paragraph separators (Zl, Zp); the Hangul fillers, which render as
// blanks; and variation selectors.
// eslint-disable-next-line no-control-regex, no-misleading-character-class -- matching these characters one by one is the point
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\p{Cf}\p{Zl}\p{Zp}\u115f\u1160\u3164\uffa0\ufe00-\ufe0f\u{e0000}-\u{e01ef}]/gu;
/** Every UTF-16 unit as \uXXXX: a character beyond the BMP becomes its surrogate pair, which JSON reads back as it was. */
const escapeChar = (c: string): string => Array.from({ length: c.length }, (_, i) => `\\u${c.charCodeAt(i).toString(16).padStart(4, "0")}`).join("");

/**
 * Make one output line safe to print whatever repo-controlled text (paths, script excerpts, IOC
 * notes) it carries. Every replacement is a \uXXXX escape, which is also a valid JSON string
 * escape, so JSON and SARIF output still parse back to the original text.
 *
 * The GitHub Actions runner scans stdout for workflow commands in two forms: "::cmd::" at the start
 * of a line after leading whitespace, and the legacy "##[cmd]" anywhere in a line (TryParseV2 and
 * TryParse in actions/runner src/Runner.Common/ActionCommand.cs; see also
 * https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands).
 * Unescaped, a malicious postinstall could forge annotations or send "::stop-commands::".
 */
export function neutralise(line: string): string {
  return line
    .replace(UNSAFE, escapeChar)
    .replace(/##\[/g, "#\\u0023[")
    .replace(/^(\s*):(?=:)/, "$1\\u003a");
}

function humanLines(r: Report): string[] {
  const active = r.findings.filter((f) => !f.suppressed);
  const suppressed = r.findings.filter((f) => f.suppressed);
  const lines: string[] = [];
  const bySev = [...active].sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || compareFindings(a, b));
  for (const f of bySev) {
    const loc = f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : "-";
    lines.push(`${f.severity.toUpperCase().padEnd(8)} ${f.ruleId.padEnd(10)} ${loc}`);
    lines.push(`         ${f.message}`);
    if (f.source) lines.push(`         source: ${f.source}`);
    lines.push(`         fingerprint: ${f.fingerprint}`);
  }
  const counts = SEVERITIES.slice().reverse().map((s) => `${active.filter((f) => f.severity === s).length} ${s}`).join(", ");
  lines.push("", `wormsign ${r.command}: ${active.length} finding(s) (${counts})${suppressed.length ? `, ${suppressed.length} baselined` : ""}`);
  for (const n of r.notes) lines.push(`note: ${n}`);
  return lines;
}

/** Exit status 1 when any unsuppressed finding is at or above the threshold. */
export function gateExitCode(findings: Finding[], failOn: Severity | "never"): 0 | 1 {
  if (failOn === "never") return 0;
  return findings.some((f) => !f.suppressed && severityRank(f.severity) >= severityRank(failOn)) ? 1 : 0;
}
