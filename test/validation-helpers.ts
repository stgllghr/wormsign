// Shared by the validation-*.test.ts files: they drive the real CLI entry point (run() in src/main.ts) with
// JSON output, so what they measure is what a user or CI job would see, flags and wiring included.
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { run } from "../src/main.js";
import type { IO } from "../src/main.js";
import type { Finding } from "../src/types.js";
import { fakeIO } from "./helpers.js";

/** The IOC data a release ships. Passed with --iocs so that a developer's update-iocs cache never changes a result. */
export const BUNDLED_IOCS = fileURLToPath(new URL("../../data/iocs/", import.meta.url));

export interface Outcome {
  code: number;
  findings: Finding[];
  notes: string[];
}

/** Runs `wormsign <argv> --format json` through the real entry point. A run that prints no report throws. */
export async function cli(argv: string[], over: Partial<IO> = {}): Promise<Outcome> {
  const io = fakeIO(over);
  const code = await run([...argv, "--format", "json"], io);
  if (io.out === "") throw new Error(`wormsign ${argv.join(" ")} printed no report (exit ${code}): ${io.err}`);
  const doc = JSON.parse(io.out) as { findings: Finding[]; notes: string[] };
  return { code, findings: doc.findings, notes: doc.notes };
}

export const ruleIds = (findings: Finding[]): string[] => [...new Set(findings.map((f) => f.ruleId))].sort();

/** A new temporary directory holding `files` (relative path -> content). */
export function tempTree(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "wormsign-validation-"));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  return dir;
}

/** A git repository with one commit per step; each step edits the working tree in the directory it is given. */
export function gitRepo(steps: ((dir: string) => void)[]): string {
  const dir = mkdtempSync(join(tmpdir(), "wormsign-validation-git-"));
  const git = (...a: string[]) => execFileSync("git", ["-c", "user.email=v@v.invalid", "-c", "user.name=v", "-c", "commit.gpgsign=false", ...a], { cwd: dir, stdio: "pipe" });
  git("init", "-q", "-b", "main");
  steps.forEach((step, i) => {
    step(dir);
    git("add", "-A");
    git("commit", "-q", "--allow-empty", "-m", `c${i}`);
  });
  return dir;
}

/** What a fake GitHub organization holds. Repositories without an entry have no workflows, branches or runners. */
export interface FakeOrg {
  repos: { name: string; description?: string; private?: boolean }[];
  /** Repository name -> file names in .github/workflows on the default branch. */
  workflows?: Record<string, string[]>;
  /** Repository name -> branch names. */
  branches?: Record<string, string[]>;
  /** Repository name -> self-hosted runner names. */
  repoRunners?: Record<string, string[]>;
  orgRunners?: string[];
  /** Audit-log action -> events; omitted means the organization has no audit-log API (not Enterprise Cloud: 404). */
  auditLog?: Record<string, Record<string, unknown>[]>;
}

/** A read-only api.github.com serving `state` for organization `org`, shaped as src/audit-org.ts documents each endpoint. */
export function fakeGitHub(org: string, state: FakeOrg): typeof fetch {
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
  const runners = (names: string[] = []) => json({ total_count: names.length, runners: names.map((name, id) => ({ id, name, status: "online" })) });
  return (async (input: string | URL) => {
    const u = new URL(String(input));
    const path = decodeURIComponent(u.pathname);
    if (u.origin !== "https://api.github.com") return json({ message: "Not Found" }, 404);
    if (path === `/orgs/${org}/repos`) return json(state.repos.map((r) => ({ name: r.name, full_name: `${org}/${r.name}`, private: r.private ?? true, description: r.description ?? null })));
    if (path === `/orgs/${org}/audit-log`) {
      if (!state.auditLog) return json({ message: "Not Found" }, 404);
      const action = /action:(\S+)/.exec(u.searchParams.get("phrase") ?? "")?.[1] ?? "";
      return json(state.auditLog[action] ?? []);
    }
    if (path === `/orgs/${org}/actions/runners`) return runners(state.orgRunners);
    const m = new RegExp(`^/repos/${org}/([^/]+)/(.*)$`).exec(path);
    if (!m) return json({ message: "Not Found" }, 404);
    const [, repo, rest] = m as unknown as [string, string, string];
    if (rest === "actions/runners") return runners(state.repoRunners?.[repo]);
    if (rest === "contents/.github/workflows") {
      const files = state.workflows?.[repo];
      return files ? json(files.map((name) => ({ name, path: `.github/workflows/${name}`, type: "file" }))) : json({ message: "Not Found" }, 404);
    }
    if (rest.startsWith("git/matching-refs/heads/")) {
      const prefix = rest.slice("git/matching-refs/heads/".length);
      return json((state.branches?.[repo] ?? []).filter((b) => b.startsWith(prefix)).map((b) => ({ ref: `refs/heads/${b}` })));
    }
    return json({ message: "Not Found" }, 404);
  }) as typeof fetch;
}

/** Simple JSON pages captured from pypi.org (test/fixtures/python/simple/index.json says when): the fake index serves these. */
const PYPI_PAGES = fileURLToPath(new URL("../../test/fixtures/python/simple/", import.meta.url));

export interface FakeNetOptions {
  /** The Python index the fake serves (default https://pypi.org/simple/): GET <index>/<name>/ answers a captured page or 404. */
  pypiIndex?: string;
  /** npm packuments by name, served at https://registry.npmjs.org/<name>; any other name is a 404. */
  npm?: Record<string, unknown>;
  /** OSV record ids by "<ecosystem>:<name>@<version>" ("npm:six@1.17.0", "PyPI:six@1.17.0"), as POST /v1/querybatch answers them. */
  osv?: Record<string, string[]>;
  /** For POST /v1/query: GHSA id -> its database_specific.cwe_ids. A version's answer holds every GHSA id `osv` gives it. */
  ghsa?: Record<string, string[]>;
}

export interface FakeNet {
  fetchImpl: typeof fetch;
  /** Every URL asked for, in order. */
  calls: string[];
  /** Every version sent to POST /v1/querybatch, as "<ecosystem>:<name>@<version>". */
  osvQueries: string[];
  /** Every version whose records were requested with POST /v1/query, as "<ecosystem>:<name>@<version>". */
  recordQueries: string[];
}

/**
 * A fake network for soak through the real CLI: the npm registry, a Python index serving the pages captured from
 * pypi.org, and OSV. Its answers depend only on what is asked; it records every request.
 */
export function fakeNet(opts: FakeNetOptions = {}): FakeNet {
  const calls: string[] = [];
  const osvQueries: string[] = [];
  const recordQueries: string[] = [];
  const index = (opts.pypiIndex ?? "https://pypi.org/simple/").replace(/\/+$/, "");
  const json = (body: unknown, status = 200, type = "application/json") => new Response(JSON.stringify(body), { status, headers: { "content-type": type } });
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    calls.push(url);
    if (url === "https://api.osv.dev/v1/querybatch") {
      const { queries } = JSON.parse(String(init?.body)) as { queries: { package: { name: string; ecosystem: string }; version: string }[] };
      const results = queries.map((q) => {
        const id = `${q.package.ecosystem}:${q.package.name}@${q.version}`;
        osvQueries.push(id);
        const ids = opts.osv?.[id] ?? [];
        return ids.length > 0 ? { vulns: ids.map((v) => ({ id: v, modified: "2026-01-01T00:00:00Z" })) } : {};
      });
      return json({ results });
    }
    if (url === "https://api.osv.dev/v1/query") {
      const q = JSON.parse(String(init?.body)) as { package: { name: string; ecosystem: string }; version: string };
      const id = `${q.package.ecosystem}:${q.package.name}@${q.version}`;
      recordQueries.push(id);
      const vulns = (opts.osv?.[id] ?? []).map((v) => (v.startsWith("GHSA-") ? { id: v, database_specific: { cwe_ids: opts.ghsa?.[v] ?? [] } } : { id: v }));
      return json(vulns.length > 0 ? { vulns } : {});
    }
    if (url.startsWith("https://registry.npmjs.org/")) {
      const name = decodeURIComponent(url.slice("https://registry.npmjs.org/".length));
      const doc = opts.npm?.[name];
      return doc === undefined ? json({ error: "Not found" }, 404) : json(doc);
    }
    if (url.startsWith(`${index}/`)) {
      const m = /^([a-z0-9-]+)\/$/.exec(url.slice(index.length + 1));
      let page: string | undefined;
      try {
        page = m ? readFileSync(join(PYPI_PAGES, `${m[1]}.json`), "utf8") : undefined;
      } catch {
        page = undefined;
      }
      return page === undefined ? json({ message: "Not Found" }, 404) : new Response(page, { headers: { "content-type": "application/vnd.pypi.simple.v1+json" } });
    }
    throw new Error(`the fake network has no answer for ${url}`);
  }) as typeof fetch;
  return { fetchImpl, calls, osvQueries, recordQueries };
}

/** stubBin's directories, one per pipConfig, made once per test process and removed when it exits. */
const STUB_BINS = new Map<string, string>();
process.on("exit", () => {
  for (const d of STUB_BINS.values()) rmSync(d, { recursive: true, force: true });
});

/**
 * A directory of stub binaries for PATH: npm, pnpm, Yarn and bun print fixed versions, and python3 answers
 * `python3 -m pip config list` with `pipConfig` (default: nothing, as pip does with no configuration), after appending
 * its working directory and PYTHONPATH to $WS_TEST_PROBE_LOG when that is set. Nothing on the machine is run. The same
 * directory comes back for the same pipConfig, and it is removed when the test process exits, so runs leave none
 * behind. Callers must not write into it.
 */
export function stubBin(pipConfig = ""): string {
  const made = STUB_BINS.get(pipConfig);
  if (made !== undefined) return made;
  const d = mkdtempSync(join(tmpdir(), "wormsign-validation-bin-"));
  STUB_BINS.set(pipConfig, d);
  for (const [m, v] of Object.entries({ npm: "11.10.0", pnpm: "11.16.0", yarn: "4.10.3", bun: "1.3.0" })) {
    writeFileSync(join(d, m), `#!/bin/sh\necho ${v}\n`, { mode: 0o755 });
  }
  const answer = pipConfig === "" ? "" : `cat <<'WS_PIP_CONFIG'\n${pipConfig}\nWS_PIP_CONFIG\n`;
  writeFileSync(join(d, "python3"), `#!/bin/sh\nif [ -n "$WS_TEST_PROBE_LOG" ]; then printf 'cwd=%s PYTHONPATH=%s args=%s\\n' "$(pwd)" "\${PYTHONPATH-unset}" "$*" >> "$WS_TEST_PROBE_LOG"; fi\n${answer}exit 0\n`, { mode: 0o755 });
  return d;
}
