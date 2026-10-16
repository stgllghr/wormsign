import type { Finding } from "../types.js";
import { makeFinding, severityRank } from "../types.js";
import { lineIndex } from "../fsutil.js";
import type { ScanContext } from "./context.js";

/**
 * Hosts commonly used to receive stolen data. They are heuristics, not IOCs:
 * all have legitimate uses (testing, chat alerts), so a hit is a prompt to look,
 * not a verdict. CISA's advisory recommends blocking webhook.site specifically.
 */
const GENERIC: { re: RegExp; label: string }[] = [
  { re: /https?:\/\/(?:[\w-]+\.)?webhook\.site\/[\w-]+/gi, label: "webhook.site" },
  { re: /https?:\/\/(?:[\w-]+\.)?(?:requestbin\.com|hookbin\.com|requestcatcher\.com|pipedream\.net)\/?[\w/-]*/gi, label: "request-capture service" },
  { re: /https?:\/\/(?:[\w-]+\.)?(?:oast\.(?:pro|live|site|online|fun|me)|interact\.sh|burpcollaborator\.net)\b/gi, label: "out-of-band interaction service" },
  { re: /https?:\/\/(?:discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot)[\w/:.-]*/gi, label: "chat webhook" },
  { re: /https?:\/\/(?:pastebin\.com\/raw|paste\.ee\/r|transfer\.sh|file\.io)\/?[\w/.-]*/gi, label: "paste/file drop" },
  { re: /https?:\/\/[\w-]+\.(?:ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com)\b/gi, label: "tunnel endpoint" },
];

const CODE_LIKE = /\.(?:[cm]?js|ts|sh|bash|zsh|ps1|ya?ml|json|py|rb)$/i;

export function isExfilScannable(rel: string): boolean {
  return CODE_LIKE.test(rel) && !/(^|\/)(package-lock\.json|npm-shrinkwrap\.json)$/.test(rel);
}

export interface ExfilOptions {
  /** In node_modules only IOC endpoints are checked; generic hosts are too common in dependencies. */
  iocOnly: boolean;
}

export function checkExfil(rel: string, text: string, ctx: ScanContext, opts: ExfilOptions): Finding[] {
  const out: Finding[] = [];
  const lineAt = lineIndex(text);
  for (const e of ctx.iocs.endpoints) {
    // Host names are case-insensitive, so a re-cased copy of the endpoint reaches the same sink.
    const idx = text.search(new RegExp(escapeRegExp(e.substring), "i"));
    if (idx !== -1) {
      out.push(
        makeFinding({
          ruleId: "WS-EX-002",
          severity: e.severity,
          message: `Contains exfiltration endpoint ${e.substring} reported for the ${e.wave} wave`,
          file: rel,
          line: lineAt(idx),
          key: e.substring,
          source: e.source,
        }),
      );
    }
  }
  if (opts.iocOnly) return out;
  const seen = new Set<string>();
  for (const g of GENERIC) {
    for (const m of text.matchAll(g.re)) {
      const url = m[0];
      // An IOC endpoint's WS-EX-002 replaces this finding only when it is at least as severe: a lower-severity entry
      // (an update-iocs cache can add one) must not turn a medium finding into one below the gate.
      const replaced = ctx.iocs.endpoints.some((e) => severityRank(e.severity) >= severityRank("medium") && url.toLowerCase().includes(e.substring.toLowerCase()));
      if (seen.has(url) || replaced) continue;
      seen.add(url);
      out.push(
        makeFinding({
          ruleId: "WS-EX-001",
          severity: "medium",
          message: `Hardcoded ${g.label} endpoint ${url.slice(0, 100)}; verify it is not a data sink`,
          file: rel,
          line: lineAt(m.index ?? 0),
          key: url,
        }),
      );
    }
  }
  return out;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
