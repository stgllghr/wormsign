import type { Finding } from "./types.js";
import { makeFinding, UsageError } from "./types.js";
import type { IocSet, RepoPattern } from "./iocs.js";
import { MAX_REPO_NAME, branchIocProblem } from "./iocs.js";

// GitHub facts this module relies on, checked against the REST API description
// (github.com/github/rest-api-description) and docs.github.com:
// - GET /orgs/{org}/repos: fine-grained Metadata: read.
// - GET /repos/{owner}/{repo}/contents/{path} and /git/matching-refs/{ref}: fine-grained Contents: read.
//   matching-refs returns every ref that starts with the given name (a prefix match), 200 [] when none does,
//   and 409 for an empty repository. https://docs.github.com/rest/git/refs#list-matching-references
// - GET /orgs/{org}/actions/runners: org admin; classic admin:org, fine-grained org "Self-hosted runners: read".
//   GET /repos/{owner}/{repo}/actions/runners: repo admin; classic repo, fine-grained "Administration: read".
//   Both return { total_count, runners: [{ name, status, ... }] }.
//   https://docs.github.com/rest/actions/self-hosted-runners
// - GET /orgs/{org}/audit-log: GitHub Enterprise Cloud only, organization owners only; classic read:audit_log,
//   fine-grained org "Administration: read". "@timestamp" is epoch milliseconds (see the response example).
//   https://docs.github.com/enterprise-cloud@latest/rest/orgs/orgs#get-the-audit-log-for-an-organization

export interface AuditOptions {
  org: string;
  token: string;
  iocs: IocSet;
  fetchImpl?: typeof fetch;
  apiBase?: string;
  /** Upper bound on repositories that get per-repository checks (workflows, branches, runners). */
  maxRepos?: number;
  /** Visibility flips within this window count as a burst. */
  burstWindowMs?: number;
  burstThreshold?: number;
  /** Only audit-log events on or after this day are considered. */
  since?: Date;
}

export interface AuditResult {
  findings: Finding[];
  notes: string[];
  /** Set when a worm check got no answer anywhere, or the checks stopped early; the CLI then fails even without findings. */
  incomplete?: string;
}

interface Repo {
  name: string;
  full_name: string;
  private: boolean;
  description: string | null;
  archived?: boolean;
}

interface Reply {
  /** The HTTP status, or 0 when no response arrived (a network error or the 30-second timeout); see `error`. */
  status: number;
  body: unknown;
  next?: string;
  rateLimited: boolean;
  /** Why no response arrived (status 0). */
  error?: string;
}

type AuditEvent = Record<string, unknown>;

export function matchRepoPattern(p: RepoPattern, repo: Pick<Repo, "name" | "description">): boolean {
  const desc = repo.description ?? "";
  switch (p.match) {
    case "nameExact":
      return repo.name === p.name;
    case "nameContains":
      return !!p.name && repo.name.toLowerCase().includes(p.name.toLowerCase());
    case "descriptionExact":
      return desc === p.description;
    case "descriptionContains":
      return !!p.description && desc.toLowerCase().includes(p.description.toLowerCase());
    case "nameRegexAndDescriptionExact":
      // The description first, as it is cheap, and the name only up to GitHub's maximum length: the IOC loader bounds
      // a nameRegex's work by the length of what it matches (nameRegexProblem).
      return desc === p.description && !!p.nameRegex && new RegExp(p.nameRegex).test(repo.name.slice(0, MAX_REPO_NAME));
  }
}

class GitHub {
  private readonly f: typeof fetch;
  private readonly origin: string;
  constructor(
    private readonly token: string,
    private readonly base: string,
    fetchImpl?: typeof fetch,
  ) {
    this.f = fetchImpl ?? fetch;
    this.origin = new URL(base).origin;
  }

  /**
   * The only HTTP method this tool ever uses against GitHub. Retried once after a 5xx, a 429 without the headers that
   * mark the rate limit, or a network error or timeout, as soak and OSV retry: one transient fault must not cost a
   * repository its checks. A request that still gets no response is a Reply with status 0, never an exception, so one
   * repository's timeout cannot end the run and lose what the others answered.
   */
  async get(pathOrUrl: string): Promise<Reply> {
    const full = pathOrUrl.startsWith("/") ? `${this.base}${pathOrUrl}` : pathOrUrl;
    const url = new URL(full);
    // Compare parsed origins: a string prefix check also accepts https://api.github.com.evil.example.
    if (url.origin !== this.origin) throw new Error(`refusing to follow link outside ${this.origin}`);
    // The URL parser resolves "." and ".." segments (also written %2e), so a path built from data must come out as it
    // went in, or the request, with the token, would go to another endpoint than the one the check means.
    const path = full.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i, "").replace(/[?#].*$/s, "");
    if (url.pathname !== path) throw new Error(`refusing a request path that the URL parser rewrites: ${path.slice(0, 200)}`);
    let reply: Reply = { status: 0, body: undefined, rateLimited: false, error: "not attempted" };
    for (let attempt = 0; attempt < 2; attempt++) {
      let res: Response;
      try {
        res = await this.f(url, {
          method: "GET",
          headers: { accept: "application/vnd.github+json", authorization: `Bearer ${this.token}`, "x-github-api-version": "2022-11-28", "user-agent": "wormsign" },
          signal: AbortSignal.timeout(30_000),
        });
      } catch (e) {
        const code = (e as { cause?: { code?: unknown } }).cause?.code;
        reply = { status: 0, body: undefined, rateLimited: false, error: `${(e as Error).message || String(e)}${typeof code === "string" ? ` (${code})` : ""}` };
        continue;
      }
      let body: unknown = undefined;
      try {
        body = await res.json();
      } catch {
        /* empty or non-JSON body */
      }
      const next = /<([^>]+)>;\s*rel="next"/.exec(res.headers.get("link") ?? "")?.[1];
      // https://docs.github.com/rest/using-the-rest-api/rate-limits-for-the-rest-api#exceeding-the-rate-limit
      const limitHeaders = res.headers.get("x-ratelimit-remaining") === "0" || res.headers.has("retry-after");
      const rateLimited = res.status === 429 || (res.status === 403 && limitHeaders);
      reply = { status: res.status, body, rateLimited, ...(next ? { next } : {}) };
      if (!(res.status >= 500 || (res.status === 429 && !limitHeaders))) break;
    }
    return reply;
  }

  /**
   * Follows rel="next" links up to `limit` items; `truncated` says that more pages remained.
   * Each page must be a JSON array (or hold one under `key`) of objects whose `fields` are strings;
   * anything else is not `ok`, never an empty list or a silently skipped entry.
   */
  async paginate(path: string, limit: number, fields: string[], key?: "runners"): Promise<{ reply: Reply; items: unknown[]; truncated: boolean; ok: boolean }> {
    const items: unknown[] = [];
    let url: string | undefined = path;
    let reply: Reply;
    do {
      reply = await this.get(url);
      const page = key ? (reply.body as Record<string, unknown> | null | undefined)?.[key] : reply.body;
      const valid = Array.isArray(page) && page.every((x) => fields.every((f) => typeof (x as Record<string, unknown> | null)?.[f] === "string"));
      if (reply.status !== 200 || !valid) return { reply, items, truncated: false, ok: false };
      items.push(...page);
      url = reply.next;
    } while (url && items.length < limit);
    return { reply, items, truncated: url !== undefined, ok: true };
  }
}

const RATE_LIMITED = "GitHub rate-limited the token; wait for the limit to reset, then rerun (or lower --max-repos).";
const AUDIT_LOG_NEED = "The organization audit-log API exists only on GitHub Enterprise Cloud and only for organization owners (classic token: read:audit_log; fine-grained: organization Administration: read).";

function describe(r: Reply): string {
  if (r.status === 0) return `no response (${(r.error ?? "request failed").slice(0, 120)})`;
  return r.rateLimited ? `HTTP ${r.status} (rate limited)` : r.status === 200 ? "HTTP 200 (unexpected body)" : `HTTP ${r.status}`;
}

/**
 * Why a request that is not rate-limited failed: "scope" for 401, 403 and 404, which GitHub returns for what the token
 * may not see (for a private resource it answers 404, not 403:
 * https://docs.github.com/rest/using-the-rest-api/troubleshooting-the-rest-api#404-not-found-for-an-existing-resource);
 * "github" for a 5xx or no response, both after one retry; "unexpected" for anything else, such as a 200 that is not
 * what the check reads. Only "scope" is a gap a token with more access would close.
 */
type FailureClass = "scope" | "github" | "unexpected";
function failureClass(r: Reply): FailureClass {
  if (r.status === 401 || r.status === 403 || r.status === 404) return "scope";
  return r.status === 0 || r.status >= 500 ? "github" : "unexpected";
}
const GITHUB_ERROR = "It was retried once and is not a token scope problem: run the audit again.";
const UNEXPECTED = "GitHub did not give the documented response the check reads; it is not a token scope problem.";
/** What a degraded finding tells the reader to do, by the failure's class: only a scope failure is about the token. */
function needFor(r: Reply, scope: string): string {
  if (r.rateLimited) return RATE_LIMITED;
  const c = failureClass(r);
  return c === "scope" ? scope : c === "github" ? GITHUB_ERROR : UNEXPECTED;
}
/** "a, b, c" for at most `max` names, then how many more. */
function listed(names: string[], max = 10): string {
  return names.length <= max ? names.join(", ") : `${names.slice(0, max).join(", ")} and ${names.length - max} more`;
}

function degraded(feature: string, why: string, need: string, key = feature): Finding {
  return makeFinding({
    ruleId: "WS-OR-900",
    severity: "info",
    message: `${feature}: ${why}. ${need} Coverage is reduced, and a clean result for this check does not mean clean.`,
    key,
  });
}

function when(ms: unknown): string {
  const d = new Date(Number(ms));
  return Number.isNaN(d.getTime()) ? "an unknown time" : d.toISOString();
}

export async function auditOrg(opts: AuditOptions): Promise<AuditResult> {
  if (!/^[A-Za-z0-9-]+$/.test(opts.org)) throw new UsageError(`invalid organization name "${opts.org}"`);
  // A branch IOC ending in "*" is a prefix, any other is exact. git forbids "*" in branch names, so the marker can
  // never be part of a real name. An empty prefix would flag every branch, and any other "*" would never match.
  const branchIocs = opts.iocs.branches.map((b) => {
    const why = branchIocProblem(b.name);
    if (why) throw new UsageError(`invalid branch IOC "${b.name}" (a branch name, optionally ending in one "*" for a prefix): ${why}`);
    const prefix = b.name.endsWith("*");
    return { ...b, prefix, stem: prefix ? b.name.slice(0, -1) : b.name };
  });
  const gh = new GitHub(opts.token, opts.apiBase ?? "https://api.github.com", opts.fetchImpl);
  const findings: Finding[] = [];
  const notes: string[] = [];
  const org = opts.org;
  const capped = (what: string, n: number): void => {
    notes.push(`${what} stopped at the ${n}-entry cap; later entries were not checked`);
  };

  // 1. Repository inventory. Every per-repository check depends on it, so without it nothing was audited.
  const repoRes = await gh.paginate(`/orgs/${org}/repos?type=all&per_page=100`, 5000, ["name", "full_name"]);
  if (!repoRes.ok) {
    const r = repoRes.reply;
    const why = r.rateLimited
      ? "GitHub rate-limited the token"
      : r.status === 401
        ? "GitHub rejected the token"
        : r.status === 404
          ? "the organization does not exist or this token cannot see it"
          : r.status === 403
            ? "the token may not list this organization's repositories (fine-grained: Metadata: read; an organization that enforces SSO must also have authorized the token)"
            : r.status === 200
              ? "the response is not a repository list"
              : "GitHub did not return the repository list";
    throw new UsageError(`cannot list repositories of ${org} (${describe(r)}): ${why}; nothing was audited`);
  }
  const repos = repoRes.items as Repo[];
  // The listing answers 200 with only the public repositories to a token that cannot read private ones,
  // so an empty list usually means a token problem, not an empty organization.
  // https://docs.github.com/rest/repos/repos#list-organization-repositories
  if (repos.length === 0) {
    throw new UsageError(`the token sees 0 repositories in ${org}, so nothing was audited. Either the organization has none, or the token cannot read its private repositories and it has no public ones (classic token: needs repo; fine-grained: resource owner ${org}, with repositories selected).`);
  }
  if (repoRes.truncated) capped("repository listing", repos.length);
  notes.push(`${repos.length} repositories listed (${repos.filter((r) => r.private).length} private)`);
  for (const repo of repos) {
    for (const p of opts.iocs.repoPatterns) {
      if (!matchRepoPattern(p, repo)) continue;
      findings.push(
        makeFinding({
          ruleId: "WS-OR-001",
          severity: p.severity,
          message: `Repository ${repo.full_name} (${repo.private ? "private" : "public"}) matches worm pattern ${p.id} from the ${p.wave} wave`,
          file: repo.full_name,
          key: `${repo.full_name}:${p.id}`,
          source: p.source,
        }),
      );
    }
  }

  // 2. Audit log: visibility flips, and runner registrations (which outlive a runner that was removed).
  // One query per action, because the documented phrase syntax has no OR operator.
  // https://docs.github.com/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization#searching-the-audit-log
  const since = (opts.since ?? new Date(Date.now() - 30 * 86_400_000)).toISOString().slice(0, 10);
  const actions = ["repo.access", "repo.register_self_hosted_runner", "org.register_self_hosted_runner"];
  const events = new Map<string, AuditEvent[]>();
  for (const [i, action] of actions.entries()) {
    const phrase = encodeURIComponent(`action:${action} created:>=${since}`);
    const r = await gh.paginate(`/orgs/${org}/audit-log?phrase=${phrase}&per_page=100`, 2000, ["action"]);
    if (!r.ok) {
      // Not an incomplete audit whatever the cause: most organizations cannot use this API (Enterprise Cloud only).
      findings.push(degraded(`audit-log queries (${actions.slice(i).join(", ")})`, `skipped, ${describe(r.reply)}`, needFor(r.reply, AUDIT_LOG_NEED)));
      break;
    }
    if (r.truncated) capped(`audit-log query action:${action}`, r.items.length);
    events.set(action, r.items as AuditEvent[]);
  }

  // repo.access is GitHub's event for any visibility change; "visibility" holds the new value.
  const publicFlips = (events.get("repo.access") ?? []).filter((e) => e["visibility"] === "public");
  for (const e of publicFlips) {
    findings.push(makeFinding({ ruleId: "WS-OR-002", severity: "medium", message: `${String(e["repo"] ?? "a repository")} was made public by ${String(e["actor"] ?? "unknown actor")} at ${when(e["@timestamp"])}`, file: String(e["repo"] ?? org), key: `${String(e["repo"])}:${String(e["@timestamp"])}` }));
  }
  const times = publicFlips.map((e) => Number(e["@timestamp"])).sort((a, b) => a - b);
  const win = opts.burstWindowMs ?? 3_600_000;
  const thr = opts.burstThreshold ?? 3;
  for (let i = 0; i + thr - 1 < times.length; i++) {
    if ((times[i + thr - 1] as number) - (times[i] as number) <= win) {
      findings.push(makeFinding({ ruleId: "WS-OR-002", severity: "high", message: `${thr}+ repositories were made public within ${Math.round(win / 60_000)} minutes (starting ${when(times[i])}); this is the pattern the worm produces`, file: org, key: `burst:${times[i]}` }));
      break;
    }
  }

  // Registration events carry no runner name, so they are grouped per scope and actor for review.
  const registrations = new Map<string, { where: string; actor: string; count: number; last: number }>();
  for (const e of [...(events.get("repo.register_self_hosted_runner") ?? []), ...(events.get("org.register_self_hosted_runner") ?? [])]) {
    const where = String(e["repo"] ?? org);
    const actor = String(e["actor"] ?? "unknown actor");
    const g = registrations.get(`${where}\0${actor}`) ?? { where, actor, count: 0, last: 0 };
    g.count++;
    g.last = Math.max(g.last, Number(e["@timestamp"]) || 0);
    registrations.set(`${where}\0${actor}`, g);
  }
  for (const g of registrations.values()) {
    findings.push(makeFinding({ ruleId: "WS-OR-003", severity: "low", message: `${g.actor} registered ${g.count} self-hosted runner(s) on ${g.where} since ${since} (latest at ${when(g.last)}); the runner may have been removed since, so confirm you recognise it`, file: g.where, key: `runner-registration:${g.actor}` }));
  }

  const runnerFindings = (where: string, items: unknown[]): void => {
    for (const r of items as { name: string; status?: string }[]) {
      const ioc = opts.iocs.runnerNames.find((x) => x.name.toLowerCase() === r.name.toLowerCase());
      findings.push(
        makeFinding({
          ruleId: "WS-OR-003",
          severity: ioc ? "critical" : "low",
          message: ioc ? `Runner "${r.name}" on ${where} matches the name the worm registers (${ioc.wave} wave)` : `Self-hosted runner "${r.name}" (${r.status ?? "unknown"}) is registered on ${where}; confirm you recognise it`,
          file: where,
          key: `runner:${r.name}`,
          ...(ioc ? { source: ioc.source } : {}),
        }),
      );
    }
  };

  // 3. Organization-level runners. Runners registered on a single repository are listed in step 4.
  // Checks that did not run for a reason other than the token's scope or the rate limit: the audit is incomplete.
  const notChecked: string[] = [];
  const orgRunners = await gh.paginate(`/orgs/${org}/actions/runners?per_page=100`, 1000, ["name"], "runners");
  if (!orgRunners.ok) {
    findings.push(degraded("organization runner inventory", `skipped, ${describe(orgRunners.reply)}`, needFor(orgRunners.reply, "It needs organization admin rights (classic token: admin:org; fine-grained: organization Self-hosted runners: read).")));
    if (!orgRunners.reply.rateLimited && failureClass(orgRunners.reply) !== "scope") notChecked.push(`organization runner inventory (${describe(orgRunners.reply)})`);
  } else {
    if (orgRunners.truncated) capped("organization runner listing", orgRunners.items.length);
    runnerFindings(org, orgRunners.items);
  }

  // 4. Per-repository checks. Requests stay serial because GitHub asks clients to avoid concurrent
  // requests to stay under its secondary rate limits.
  // https://docs.github.com/rest/using-the-rest-api/best-practices-for-using-the-rest-api#avoid-concurrent-requests
  const max = opts.maxRepos ?? 500;
  const targets = repos.filter((r) => !r.archived).slice(0, max);
  if (repos.length > targets.length) notes.push(`per-repository checks covered ${targets.length} of ${repos.length} repositories (archived repositories skipped, --max-repos ${max})`);
  let withWorkflows = 0;
  const contentsNeed = "The token needs Contents: read on them.";
  const WORKFLOW_LISTING = "default-branch workflow file listing";
  const probes: { check: string; need: string; path: (r: Repo) => string; fields: string[]; key?: "runners"; absent?: number; found: (r: Repo, items: unknown[]) => void }[] = [
    {
      check: WORKFLOW_LISTING,
      need: contentsNeed,
      path: (r) => `/repos/${r.full_name}/contents/.github/workflows`,
      fields: ["name"],
      // The repository has no workflow directory. Not verified: that a token without Contents: read gets 403 here,
      // never 404. If it got 404, the IOC branch lookup below, which accepts only 409, would still fail.
      absent: 404,
      found: (repo, items) => {
        withWorkflows++;
        for (const entry of items as { name: string }[]) {
          const ioc = opts.iocs.workflowFiles.find((w) => w.name === entry.name);
          if (ioc) findings.push(makeFinding({ ruleId: "WS-OR-004", severity: ioc.severity, message: `${repo.full_name} contains .github/workflows/${ioc.name}, an IOC from the ${ioc.wave} wave`, file: repo.full_name, key: `${repo.full_name}:${ioc.name}`, source: ioc.source }));
        }
      },
    },
    // The worm pushes its workflow to a branch it creates, which the default-branch listing above never sees.
    ...branchIocs.map((b) => ({
      check: `IOC branch lookup (${b.name})`,
      need: contentsNeed,
      path: (r: Repo) => `/repos/${r.full_name}/git/matching-refs/heads/${b.stem.split("/").map(encodeURIComponent).join("/")}`,
      fields: ["ref"],
      absent: 409, // empty repository
      found: (repo: Repo, items: unknown[]) => {
        // matching-refs is a prefix match, so an exact IOC must equal the whole ref.
        for (const { ref } of items as { ref: string }[]) {
          if (b.prefix ? !ref.startsWith(`refs/heads/${b.stem}`) : ref !== `refs/heads/${b.stem}`) continue;
          const branch = ref.slice("refs/heads/".length);
          findings.push(makeFinding({ ruleId: "WS-OR-004", severity: "high", message: `${repo.full_name} has a branch named "${branch}", which the ${b.wave} wave creates to run its workflow`, file: repo.full_name, key: `${repo.full_name}:branch:${branch}`, source: b.source }));
        }
      },
    })),
    {
      check: "repository runner inventory",
      need: "It needs admin rights on those repositories (classic token: repo; fine-grained: Administration: read).",
      path: (r) => `/repos/${r.full_name}/actions/runners?per_page=100`,
      fields: ["name"],
      key: "runners",
      // Failing everywhere makes the audit incomplete even when the organization listing answered: a runner
      // registered on a repository shows up only here, and any unrecognised runner is a persistence channel.
      // Shai-Hulud 2.0's own SHA1HULUD runner appears to sit on the 18-character repository it creates "in the
      // victim's account" (Socket); Datadog shows config.sh --url https://github.com/${owner}/${repoName} and hunts
      // DiscussionEvents on 18-character repository names. Whether that owner can be an organization is unverified,
      // and a personal account is outside an organization audit.
      // https://socket.dev/blog/shai-hulud-strikes-again-v2 https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/
      found: (repo, items) => runnerFindings(repo.full_name, items),
    },
  ];
  // Per check and failure class, so that a server error is never reported as a scope gap, nor hidden among them.
  const failures = new Map<string, { check: string; need: string; cls: FailureClass; statuses: Map<string, number>; repos: string[] }>();
  const answered = probes.map(() => 0); // per check, so one working check cannot hide another that never worked
  let stopped: Reply | undefined;
  let done = 0;
  repoLoop: for (const repo of targets) {
    for (const [i, p] of probes.entries()) {
      const r = await gh.paginate(p.path(repo), 1000, p.fields, p.key);
      if (r.ok) {
        if (r.truncated) capped(`${p.check} for ${repo.full_name}`, r.items.length);
        p.found(repo, r.items);
        answered[i]!++;
      } else if (r.reply.rateLimited) {
        stopped = r.reply;
        break repoLoop; // every further request fails until the limit resets
      } else if (r.reply.status === p.absent) {
        answered[i]!++;
      } else {
        const cls = failureClass(r.reply);
        const f = failures.get(`${p.check}\0${cls}`) ?? { check: p.check, need: p.need, cls, statuses: new Map<string, number>(), repos: [] };
        f.statuses.set(describe(r.reply), (f.statuses.get(describe(r.reply)) ?? 0) + 1);
        f.repos.push(repo.full_name);
        failures.set(`${p.check}\0${cls}`, f);
      }
    }
    done++;
  }
  for (const [i, p] of probes.entries()) {
    const dirs = p.check === WORKFLOW_LISTING ? ` (${withWorkflows} have a .github/workflows directory)` : "";
    notes.push(`${p.check} answered for ${answered[i]} of ${targets.length} repositories${dirs}`);
  }
  if (stopped) findings.push(degraded("per-repository checks", `stopped after ${done} of ${targets.length} repositories, ${describe(stopped)}`, RATE_LIMITED));
  for (const f of failures.values()) {
    const n = f.repos.length;
    const statuses = [...f.statuses].map(([s, c]) => `${s} x${c}`).join(", ");
    if (f.cls === "scope") {
      // Repositories outside the token's reach are a documented, reduced audit (docs/cli/audit-org.md); they are counted, not named.
      findings.push(degraded(f.check, `failed for ${n} of ${targets.length} repositories (${statuses})`, f.need));
      continue;
    }
    // Any other failure leaves named repositories unchecked for a reason no token change would fix, so it is
    // reported by name, under its own key, and makes the audit incomplete (exit 2), which unlike a finding cannot be
    // baselined: the next run may well get an answer.
    const what = f.cls === "github" ? "a GitHub or network error" : "an unexpected answer";
    findings.push(degraded(f.check, `not checked for ${n} of ${targets.length} repositories because of ${what} (${statuses}): ${listed(f.repos)}`, f.cls === "github" ? GITHUB_ERROR : UNEXPECTED, `${f.check} (${what})`));
    notChecked.push(`${f.check} for ${listed(f.repos, 3)} (${statuses})`);
  }

  // Repo-name patterns alone are not an audit: a worm check that no repository answered, or a run cut short, must not exit 0.
  // That includes an organization whose repositories are all archived: nothing was checked. Nor may a repository whose
  // check failed for a reason other than the token's scope pass as checked.
  const unanswered = probes.filter((_, i) => answered[i] === 0).map((p) => p.check);
  const reasons = [...(unanswered.length > 0 ? [`no repository answered: ${unanswered.join(", ")}`] : []), ...(notChecked.length > 0 ? [`not checked because of a GitHub or network error or an unexpected answer: ${notChecked.join("; ")}`] : [])];
  const incomplete = stopped ? `per-repository checks stopped by a rate limit after ${done} of ${targets.length} repositories` : reasons.length > 0 ? reasons.join("; ") : undefined;
  return { findings, notes, ...(incomplete ? { incomplete } : {}) };
}
