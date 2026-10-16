#!/usr/bin/env node
// Maintainer tool (not shipped): writes docs/rules.md from the rule catalogue in src/rules.ts.
// Usage:
//   npm run docs:rules                        build, then write docs/rules.md
//   node scripts/gen-rules-doc.mjs --check    exit 1 when docs/rules.md differs from what this would write
// It reads the compiled catalogue (dist/src/rules.js), so run `npm run build` first when calling it directly.
// test/docs-rules.test.ts fails when docs/rules.md is out of date.
//
// src/rules.ts holds each rule's id, name, description and help. Which command reports a rule and at which
// severities are not in the catalogue, so they are listed below, read from the code that creates each finding
// (grep for the rule id under src/). test/docs-rules.test.ts fails when a rule has no entry here or an entry has
// no rule, and runs the commands over fixtures to check that what they report matches these entries.
import { readFileSync, writeFileSync } from "node:fs";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

/** Commands that read the baseline, and so can report an expired entry. */
const BASELINE_COMMANDS = ["scan", "diff", "soak", "audit-org"];

/**
 * Per rule: the commands that report it, the severities it can have ("ioc": the severity of the IOC data entry that
 * matched, which may be any severity), and when each severity applies (empty for a rule with one fixed severity).
 */
export const RULE_META = {
  "WS-LC-001": { commands: ["scan"], severities: ["low", "medium"], when: "low when package.json has \"private\": true (the script runs only for installs of this project); medium otherwise, because the script runs for everyone who installs the package." },
  "WS-LC-002": { commands: ["scan", "diff"], severities: ["high"], when: "scan checks the project's manifests and, with --node-modules, installed packages; diff checks install-time scripts the change adds or changes." },
  "WS-LC-003": { commands: ["scan", "diff"], severities: ["high", "critical"], when: "critical when the IOC list rates the payload file name high or critical on its own; high otherwise." },
  "WS-LC-004": { commands: ["scan"], severities: ["high"], when: "Not reported inside node_modules or under the baseline's ignorePaths, except for a file that config outside them names. A .yarnrc.yml or pnpm-workspace.yaml with YAML outside the subset wormsign reads is reported as WS-SC-900 instead, and so is such a file reached through a symlink." },
  "WS-LK-001": { commands: ["scan", "diff"], severities: ["critical"], when: "scan checks lockfiles and, with --node-modules, installed packages; diff checks the lockfile entries a change adds." },
  "WS-LK-002": { commands: ["scan", "diff"], severities: ["medium", "high"], when: "medium for a git source; high for another host, plain HTTP, a value that is not a registry URL, a registry URL that names another package, or a runtime binary downloaded from somewhere other than its official release site." },
  "WS-LK-003": { commands: ["scan", "diff"], severities: ["medium"], when: "Not reported for Yarn Berry lockfiles, which record a checksum of Yarn's own archive format rather than a registry integrity, or for bundled dependencies. A Yarn 1 entry with no integrity line is not reported when its resolved URL ends in # and a 40-hex SHA-1, which Yarn 1 verifies; that SHA-1 is its integrity." },
  "WS-GH-001": { commands: ["scan", "diff"], severities: ["ioc"], when: "the severity of the matching entry in data/iocs/workflows.json." },
  "WS-GH-002": { commands: ["scan", "diff"], severities: ["high"], when: "" },
  "WS-GH-003": { commands: ["scan", "diff"], severities: ["high"], when: "" },
  "WS-GH-004": { commands: ["scan", "diff"], severities: ["medium"], when: "" },
  "WS-GH-005": { commands: ["scan", "diff"], severities: ["high"], when: "" },
  "WS-GH-006": { commands: ["scan", "diff"], severities: ["critical"], when: "" },
  "WS-GH-007": { commands: ["scan", "diff"], severities: ["medium", "high"], when: "high when a job in the workflow runs on a self-hosted runner (the shape of the reported backdoor); medium otherwise." },
  "WS-FS-001": { commands: ["scan"], severities: ["critical"], when: "" },
  "WS-FS-002": { commands: ["scan"], severities: ["ioc"], when: "the nameOnlySeverity of the matching entry in data/iocs/files.json. Names rated info are not reported. A file whose hash matches is reported as WS-FS-001 instead." },
  "WS-EX-001": { commands: ["scan"], severities: ["medium"], when: "Not checked inside node_modules, where these hosts are common." },
  "WS-EX-002": { commands: ["scan"], severities: ["ioc"], when: "the severity of the matching entry in data/iocs/endpoints.json." },
  "WS-NM-001": { commands: ["scan"], severities: ["low", "medium"], when: "only with --node-modules. Medium for a preinstall, install or postinstall script; low for a binding.gyp without one, for which npm runs node-gyp rebuild." },
  "WS-DF-001": { commands: ["diff"], severities: ["high"], when: "" },
  "WS-DF-002": { commands: ["diff"], severities: ["medium"], when: "A suspicious or IOC script is also reported as WS-LC-002 or WS-LC-003." },
  "WS-DF-003": { commands: ["diff"], severities: ["medium"], when: "Covers workflows and local actions (action.yml, action.yaml); the workflow rules WS-GH-* also run on the new content." },
  "WS-DF-004": { commands: ["diff"], severities: ["high"], when: "" },
  "WS-DF-005": { commands: ["diff"], severities: ["high"], when: "" },
  "WS-DF-006": { commands: ["diff"], severities: ["medium", "high"], when: "Medium for a changed Python lockfile or requirements file, and for any change to a pyproject.toml, setup.py, setup.cfg or Pipfile (the file compared whole), which diff does not resolve and soak --base checks the locks of; not what a manifest names (a hook, a dependency file). High otherwise (a pyproject.toml that cannot be parsed included)." },
  "WS-SK-001": { commands: ["soak"], severities: ["high"], when: "" },
  "WS-SK-002": { commands: ["soak"], severities: ["medium", "high"], when: "Medium only for a local Python project whose one problem is files git does not track, on a run without --base (a developer's checkout); with --base that is high too." },
  "WS-SK-003": { commands: ["soak"], severities: ["low", "medium", "high"], when: "low for Yarn Classic, which has no release-age setting; medium otherwise; --require-config raises medium to high." },
  "WS-SK-004": { commands: ["soak"], severities: ["medium", "high"], when: "medium; --require-config raises it to high." },
  "WS-SK-005": { commands: ["soak"], severities: ["medium", "high"], when: "Python locks only. Medium on a full run, so the default --fail-on high reports it without failing: most Python projects build something. In PR mode (--base) a build the change adds is high; one the base has stays medium. --require-config does not raise it." },
  "WS-SK-006": { commands: ["soak"], severities: ["medium"], when: "Only with --on-outage warn, when the npm registry or the Python index gave no answer in the whole run nor to the probe after it; never suppressed by a baseline." },
  "WS-OR-001": { commands: ["audit-org"], severities: ["ioc"], when: "the severity of the matching pattern in data/iocs/repos.json." },
  "WS-OR-002": { commands: ["audit-org"], severities: ["medium", "high"], when: "medium for each repository made public; one extra high finding when 3 or more were made public within 60 minutes." },
  "WS-OR-003": { commands: ["audit-org"], severities: ["low", "critical"], when: "critical when a runner's name matches a runner name in the IOC list; low for any other registered runner or runner registration event." },
  "WS-OR-004": { commands: ["audit-org"], severities: ["ioc", "high"], when: "for a workflow file, the severity of the matching entry in data/iocs/workflows.json; high for a branch named in data/iocs/repos.json." },
  "WS-OR-900": { commands: ["audit-org"], severities: ["info"], when: "It does not fail the default gate; an audit that a rate limit stopped, whose per-repository checks no repository answered, or that left a repository or the organization runner inventory unchecked because of a GitHub or network error or an unexpected answer, exits 2 instead." },
  "WS-SC-900": { commands: ["scan"], severities: ["low", "high"], when: "high by default; low for a symlink to a directory that holds no package.json and that wormsign does not scan, and for a code file that could not be searched for exfiltration endpoints from the IOC list (unreadable, or larger than 64 MiB)." },
  "WS-BL-001": { commands: BASELINE_COMMANDS, severities: ["medium"], when: "Reported by any command that applied a baseline with an expired entry." },
  "WS-RG-001": { commands: ["soak"], severities: ["high"], when: "" },
  "WS-RG-002": { commands: ["soak"], severities: ["high"], when: "" },
  "WS-RG-003": { commands: ["soak"], severities: ["medium"], when: "" },
  "WS-OS-001": { commands: ["soak"], severities: ["critical"], when: "Not run with --no-osv." },
  "WS-OS-900": { commands: ["soak"], severities: ["high"], when: "Not run with --no-osv." },
  "WS-OS-901": { commands: ["soak"], severities: ["medium"], when: "Only with --on-outage warn, when api.osv.dev gave no answer in the whole run nor to the probe after it; never suppressed by a baseline. Not run with --no-osv." },
  "WS-PS-001": { commands: ["scan"], severities: ["high"], when: "whatever the command it runs." },
  "WS-PS-002": { commands: ["scan"], severities: ["high"], when: "whatever the command it runs." },
};

/** What each ID prefix covers, in the order the families are listed. */
const FAMILIES = [
  ["LC", "Lifecycle scripts in package.json"],
  ["LK", "Lockfile entries"],
  ["GH", "GitHub Actions workflows"],
  ["FS", "Payload files"],
  ["EX", "Exfiltration endpoints"],
  ["NM", "Installed packages (node_modules)"],
  ["PS", "Editor and AI-agent persistence"],
  ["SC", "Scan coverage"],
  ["DF", "Pull request diff"],
  ["SK", "Soak time"],
  ["RG", "Registry signals"],
  ["OS", "OSV malicious-package records"],
  ["OR", "GitHub organization audit"],
  ["BL", "Baseline"],
];

const COMMAND_PAGES = { scan: "cli/scan.md", diff: "cli/diff.md", soak: "cli/soak.md", "audit-org": "cli/audit-org.md" };

/** Catalogue text is plain (it is also the SARIF help text), so characters Markdown would act on are escaped. */
const md = (s) => s.replace(/[\\`*_[\]<>|~]/g, "\\$&");

const severityText = (sev) => sev.map((s) => (s === "ioc" ? "set by the IOC entry" : s)).join(", ");
const commandLinks = (cmds) => cmds.map((c) => `[\`${c}\`](${COMMAND_PAGES[c]})`).join(", ");

/** The whole of docs/rules.md for `rules` (RuleInfo[] from src/rules.ts). Throws when a rule and RULE_META disagree. */
export function renderRulesDoc(rules, meta = RULE_META) {
  const ids = rules.map((r) => r.id);
  const missing = ids.filter((id) => !meta[id]);
  const stale = Object.keys(meta).filter((id) => !ids.includes(id));
  if (missing.length || stale.length) {
    throw new Error(`scripts/gen-rules-doc.mjs RULE_META is out of step with src/rules.ts: no entry for ${missing.join(", ") || "-"}; entry without a rule: ${stale.join(", ") || "-"}`);
  }
  const family = (id) => id.split("-")[1];
  const unknown = ids.filter((id) => !FAMILIES.some(([p]) => p === family(id)));
  if (unknown.length) throw new Error(`scripts/gen-rules-doc.mjs FAMILIES has no entry for ${unknown.join(", ")}`);

  const out = [
    "<!-- Generated by scripts/gen-rules-doc.mjs from src/rules.ts. Do not edit by hand: run `npm run docs:rules`. -->",
    "",
    "# Rules",
    "",
    `wormsign has ${rules.length} rules. Each finding carries one rule ID. This page is generated from the rule catalogue`,
    "in `src/rules.ts`, which is also where the SARIF output takes each rule's description and help text, and every",
    "SARIF rule's `helpUri` points at the rule's section here. `test/docs-rules.test.ts` fails when this page is out of",
    "date.",
    "",
    "Severity is set per finding, not per rule: the same rule can report different severities in different",
    "situations, listed under each rule. \"Set by the IOC entry\" means the severity comes from the matching entry in the",
    "IOC data (`data/iocs/`, see [iocs.md](iocs.md)). How severities map to exit codes and to GitHub code scanning is in",
    "[output.md](output.md); how to suppress a reviewed finding is in [baseline.md](baseline.md).",
    "",
    "| Rule | Name | Reported by | Severity |",
    "|---|---|---|---|",
    ...FAMILIES.flatMap(([p]) => rules.filter((r) => family(r.id) === p)).map((r) => `| [${r.id}](#${r.id.toLowerCase()}) | ${md(r.name)} | ${meta[r.id].commands.join(", ")} | ${severityText(meta[r.id].severities)} |`),
    "",
  ];
  for (const [prefix, title] of FAMILIES) {
    const members = rules.filter((r) => family(r.id) === prefix);
    if (members.length === 0) continue;
    out.push(`## ${title} (WS-${prefix})`, "");
    for (const r of members) {
      const m = meta[r.id];
      out.push(
        `### ${r.id}`,
        "",
        `**${md(r.name)}**`,
        "",
        md(r.description),
        "",
        `- **Reported by:** ${commandLinks(m.commands)}`,
        `- **Severity:** ${severityText(m.severities)}${m.when ? `. ${md(m.when.charAt(0).toUpperCase() + m.when.slice(1))}` : ""}`,
        `- **What to do:** ${md(r.help)}`,
        "",
      );
    }
  }
  return out.join("\n");
}

export const DOC_PATH = fileURLToPath(new URL("../docs/rules.md", import.meta.url));

async function main() {
  const rulesUrl = new URL("../dist/src/rules.js", import.meta.url);
  let RULES;
  try {
    ({ RULES } = await import(rulesUrl.href));
  } catch (e) {
    console.error(`cannot load ${fileURLToPath(rulesUrl)} (${e.message}); run npm run build first`);
    process.exit(2);
  }
  const text = renderRulesDoc(RULES);
  if (process.argv.includes("--check")) {
    let current = "";
    try {
      current = readFileSync(DOC_PATH, "utf8");
    } catch {
      // missing counts as out of date
    }
    if (current !== text) {
      console.error("docs/rules.md is out of date: run npm run docs:rules");
      process.exit(1);
    }
    console.log("docs/rules.md is up to date");
    return;
  }
  writeFileSync(DOC_PATH, text);
  console.log(`wrote docs/rules.md (${RULES.length} rules)`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
