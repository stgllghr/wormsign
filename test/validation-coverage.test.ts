// Rule coverage: every rule in src/rules.ts must be produced by at least one scenario that drives a real entry point
// (scan, diff, soak, audit-org, the baseline). RULES is read at run time, so a rule added without a scenario fails here.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RULES } from "../src/rules.js";
import { NOW, fx } from "./helpers.js";
import { cli, fakeGitHub, fakeNet, ruleIds, tempTree } from "./validation-helpers.js";
import type { Outcome } from "./validation-helpers.js";

const TEST_IOCS = ["--iocs", fx("iocs")];
const H = 3_600_000;

/** An npm lockfile v3 (the format npm 7+ writes) locking each "name@version" from the registry. */
function npmLock(entries: { id: string; script?: boolean }[]): string {
  const packages: Record<string, unknown> = { "": { name: "app", version: "1.0.0" } };
  for (const { id, script } of entries) {
    const [name, version] = id.split("@") as [string, string];
    packages[`node_modules/${name}`] = { version, resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`, integrity: "sha512-x", ...(script ? { hasInstallScript: true } : {}) };
  }
  return JSON.stringify({ name: "app", version: "1.0.0", lockfileVersion: 3, requires: true, packages }, null, 2);
}

interface Scenario {
  name: string;
  /** Rules this scenario exists to produce; it fails if any is missing. */
  expect: string[];
  run: () => Promise<Outcome>;
}

const SCENARIOS: Scenario[] = [
  {
    name: "scan: synthetic malicious project (test/fixtures/malicious)",
    expect: ["WS-LC-001", "WS-LC-002", "WS-LC-003", "WS-LK-001", "WS-LK-002", "WS-LK-003", "WS-GH-001", "WS-GH-002", "WS-GH-003", "WS-GH-004", "WS-GH-005", "WS-GH-006", "WS-GH-007", "WS-FS-001", "WS-EX-001", "WS-EX-002"],
    run: () => cli(["scan", fx("malicious"), ...TEST_IOCS]),
  },
  {
    name: "scan: payload name with unknown content, manifest that is not JSON",
    expect: ["WS-FS-002", "WS-SC-900"],
    run: () => cli(["scan", tempTree({ "wormsign_marker_loader.js": "not the sample\n", "package.json": "{ not json" }), ...TEST_IOCS]),
  },
  {
    name: "scan: a pnpmfile and an .npmrc node-options, which run without any lifecycle script",
    expect: ["WS-LC-004"],
    run: () => cli(["scan", tempTree({ "package.json": '{"name":"app","version":"1.0.0"}', ".pnpmfile.cjs": "module.exports = {}\n", ".npmrc": "node-options=--require ./preload.js\n" }), ...TEST_IOCS]),
  },
  {
    name: "scan --node-modules: installed packages with install scripts (test/fixtures/nm)",
    expect: ["WS-NM-001"],
    run: () => cli(["scan", fx("nm"), "--node-modules", ...TEST_IOCS]),
  },
  {
    name: "diff: new install-script dependency, script bump, lifecycle script, workflow, .npmrc, bun.lock",
    expect: ["WS-DF-001", "WS-DF-002", "WS-DF-003", "WS-DF-004", "WS-DF-005", "WS-DF-006"],
    run: () => {
      const base = tempTree({ "package.json": '{"name":"app","version":"1.0.0"}', "package-lock.json": npmLock([{ id: "bumped@1.0.0" }]) });
      const head = tempTree({
        "package.json": '{"name":"app","version":"1.0.0","scripts":{"postinstall":"node build.js"}}',
        "package-lock.json": npmLock([{ id: "bumped@2.0.0", script: true }, { id: "fresh@1.0.0", script: true }]),
        ".github/workflows/ci.yml": "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n",
        ".npmrc": "ignore-scripts=false\n",
        "bun.lock": "{}\n",
      });
      return cli(["diff", `dir:${base}`, `dir:${head}`, ...TEST_IOCS]);
    },
  },
  {
    name: "soak (fake registry): a 5-hour-old version, an unpublished one, min-release-age=1",
    expect: ["WS-SK-001", "WS-SK-002", "WS-SK-004"],
    run: () => {
      const dir = tempTree({ "package.json": '{"name":"app","version":"1.0.0","dependencies":{"young":"1.0.0","ghost":"1.0.0"}}', "package-lock.json": npmLock([{ id: "young@1.0.0" }, { id: "ghost@1.0.0" }]), ".npmrc": "min-release-age=1\n" });
      const registry = (async (url: string | URL) => {
        if (!String(url).endsWith("/young")) return new Response("{}", { status: 404 });
        const time = { "1.0.0": new Date(NOW.getTime() - 5 * H).toISOString() };
        return new Response(JSON.stringify({ name: "young", time, versions: { "1.0.0": { dist: { integrity: "sha512-x", tarball: "https://registry.npmjs.org/young/-/young-1.0.0.tgz" } } } }));
      }) as typeof fetch;
      return cli(["soak", dir], { env: { HOME: mkdtempSync(join(tmpdir(), "wormsign-home-")) }, fetchImpl: registry });
    },
  },
  {
    name: "soak (fake registry and OSV): a 5-day-old version adds a preinstall script, drops provenance, has a new publisher and a MAL- record",
    expect: ["WS-RG-001", "WS-RG-002", "WS-RG-003", "WS-OS-001"],
    run: () => {
      const dir = tempTree({ "package-lock.json": npmLock([{ id: "lib@1.0.1" }]) });
      const ago = (days: number) => new Date(NOW.getTime() - days * 24 * H).toISOString();
      const dist = { integrity: "sha512-x", tarball: "https://registry.npmjs.org/lib/-/lib-1.0.1.tgz" };
      const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
        if (String(url) === "https://api.osv.dev/v1/querybatch") {
          const { queries } = JSON.parse(String(init?.body)) as { queries: unknown[] };
          return new Response(JSON.stringify({ results: queries.map(() => ({ vulns: [{ id: "MAL-0000-1", modified: NOW.toISOString() }] })) }));
        }
        const versions = {
          "1.0.0": { _npmUser: { name: "alice" }, dist: { ...dist, attestations: { provenance: { predicateType: "https://slsa.dev/provenance/v1" } } } },
          "1.0.1": { _npmUser: { name: "mallory" }, scripts: { preinstall: "node setup.js" }, dist },
        };
        return new Response(JSON.stringify({ name: "lib", time: { "1.0.0": ago(60), "1.0.1": ago(5) }, versions }));
      }) as typeof fetch;
      return cli(["soak", dir], { env: { HOME: mkdtempSync(join(tmpdir(), "wormsign-home-")) }, fetchImpl });
    },
  },
  {
    name: "soak (fake registry, OSV answering HTTP 503): the OSV check fails closed",
    expect: ["WS-OS-900"],
    run: () => {
      const dir = tempTree({ "package-lock.json": npmLock([{ id: "old@1.0.0" }]) });
      const fetchImpl = (async (url: string | URL) => {
        if (String(url) === "https://api.osv.dev/v1/querybatch") return new Response("", { status: 503 });
        const time = { "1.0.0": new Date(NOW.getTime() - 400 * H).toISOString() };
        return new Response(JSON.stringify({ name: "old", time, versions: { "1.0.0": { dist: { integrity: "sha512-x", tarball: "https://registry.npmjs.org/old/-/old-1.0.0.tgz" } } } }));
      }) as typeof fetch;
      return cli(["soak", dir], { env: { HOME: mkdtempSync(join(tmpdir(), "wormsign-home-")) }, fetchImpl });
    },
  },
  {
    name: "soak --on-outage warn (fake registry answering HTTP 503 to everything): each package the outage left unchecked",
    expect: ["WS-SK-006"],
    run: () => {
      const dir = tempTree({ "package-lock.json": npmLock([{ id: "down@1.0.0" }]) });
      const fetchImpl = (async () => new Response("", { status: 503 })) as typeof fetch;
      return cli(["soak", dir, "--on-outage", "warn"], { env: { HOME: mkdtempSync(join(tmpdir(), "wormsign-home-")) }, fetchImpl, sleep: async () => {} });
    },
  },
  {
    name: "soak --on-outage warn (fake registry, OSV answering HTTP 503 to everything): each version OSV's outage left unchecked",
    expect: ["WS-OS-901"],
    run: () => {
      const dir = tempTree({ "package-lock.json": npmLock([{ id: "old@1.0.0" }]) });
      const fetchImpl = (async (url: string | URL) => {
        if (String(url).startsWith("https://api.osv.dev/")) return new Response("", { status: 503 });
        const time = { "1.0.0": new Date(NOW.getTime() - 400 * H).toISOString() };
        return new Response(JSON.stringify({ name: "old", time, versions: { "1.0.0": { dist: { integrity: "sha512-x", tarball: "https://registry.npmjs.org/old/-/old-1.0.0.tgz" } } } }));
      }) as typeof fetch;
      return cli(["soak", dir, "--on-outage", "warn"], { env: { HOME: mkdtempSync(join(tmpdir(), "wormsign-home-")) }, fetchImpl, sleep: async () => {} });
    },
  },
  {
    name: "soak (fake PyPI index and OSV): a uv workspace whose two editable members the install builds (uv 0.12.21's lock)",
    expect: ["WS-SK-005"],
    run: () => {
      const fixture = fx("python", "locks", "uv-0.12.21", "editable");
      const dir = tempTree(Object.fromEntries(["pyproject.toml", "uv.lock", "packages/member/pyproject.toml"].map((rel) => [rel, readFileSync(join(fixture, rel), "utf8")])));
      return cli(["soak", dir], { env: { HOME: mkdtempSync(join(tmpdir(), "wormsign-home-")) }, fetchImpl: fakeNet().fetchImpl });
    },
  },
  {
    name: "soak --config-only: npm lockfile, no release-age setting anywhere",
    expect: ["WS-SK-003"],
    run: () => cli(["soak", tempTree({ "package-lock.json": npmLock([]) }), "--config-only"], { env: { HOME: mkdtempSync(join(tmpdir(), "wormsign-home-")) } }),
  },
  {
    name: "audit-org (fake GitHub, Enterprise Cloud): IOC repo, visibility flip, IOC runner, IOC workflow",
    expect: ["WS-OR-001", "WS-OR-002", "WS-OR-003", "WS-OR-004"],
    run: () =>
      cli(["audit-org", "acme", ...TEST_IOCS], {
        env: { GITHUB_TOKEN: "test-token" },
        fetchImpl: fakeGitHub("acme", {
          repos: [{ name: "wormsign-marker-repo" }, { name: "app" }],
          workflows: { app: ["ci.yml", "wormsign-marker-workflow.yml"] },
          orgRunners: ["WORMSIGNTEST"],
          auditLog: { "repo.access": [{ action: "repo.access", repo: "acme/app", actor: "mallory", visibility: "public", "@timestamp": NOW.getTime() - H }] },
        }),
      }),
  },
  {
    name: "audit-org (fake GitHub, no audit-log API): degraded coverage is reported",
    expect: ["WS-OR-900"],
    run: () => cli(["audit-org", "acme", ...TEST_IOCS], { env: { GITHUB_TOKEN: "test-token" }, fetchImpl: fakeGitHub("acme", { repos: [{ name: "app" }] }) }),
  },
  {
    name: "baseline: an entry whose expiry date has passed",
    expect: ["WS-BL-001"],
    run: async () => {
      const dir = tempTree({ "package.json": '{"name":"app","version":"1.0.0","scripts":{"postinstall":"node build.js"}}' });
      const first = await cli(["scan", dir, ...TEST_IOCS]);
      const fp = first.findings.find((f) => f.ruleId === "WS-LC-001")?.fingerprint;
      assert.ok(fp, "the baseline scenario needs a finding to suppress");
      const baseline = join(dir, "baseline.json");
      writeFileSync(baseline, JSON.stringify({ version: 1, entries: [{ fingerprint: fp, justification: "Reviewed: the build step compiles native code", expires: "2026-01-01" }] }));
      return cli(["scan", dir, "--baseline", baseline, ...TEST_IOCS]);
    },
  },
];

test("validation coverage: every rule in src/rules.ts is produced by a scenario that runs a real entry point", async () => {
  const producedBy = new Map<string, string[]>();
  for (const s of SCENARIOS) {
    const got = ruleIds((await s.run()).findings);
    const missing = s.expect.filter((r) => !got.includes(r));
    assert.deepEqual(missing, [], `scenario "${s.name}" did not produce ${missing.join(", ")} (it produced ${got.join(", ") || "nothing"})`);
    for (const r of got) producedBy.set(r, [...(producedBy.get(r) ?? []), s.name]);
  }
  const uncovered = RULES.map((r) => r.id).filter((id) => !producedBy.has(id));
  assert.deepEqual(uncovered, [], `rules no scenario produces (add a scenario to test/validation-coverage.test.ts): ${uncovered.join(", ")}`);
  const unknown = [...producedBy.keys()].filter((id) => !RULES.some((r) => r.id === id));
  assert.deepEqual(unknown, [], `scenarios produced rule IDs missing from src/rules.ts: ${unknown.join(", ")}`);
  console.log(["| Rule | Scenarios that produce it |", "|---|---|", ...RULES.map((r) => `| ${r.id} | ${(producedBy.get(r.id) ?? []).join("; ")} |`)].join("\n"));
});
