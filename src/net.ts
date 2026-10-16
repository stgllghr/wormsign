/**
 * One classifier for the network failures of soak's three services, the npm registry (src/soak.ts), the Python index
 * (src/python/index.ts) and OSV (src/osv.ts): which failure is an outage, and so may be reported at medium under
 * `--on-outage warn` (WS-SK-006, WS-OS-901), and which stays a fail-closed finding (WS-SK-002, WS-OS-900).
 *
 * Two tests, both needed:
 * - The request: after the client's retry it failed in transport before any status line came back (a DNS or
 *   connection error, a TLS handshake that broke off, a timeout), or the status was 429 or a 5xx. A failure after a
 *   status line (a body that is slow, cut off or unreadable), a 404 or another 4xx, a redirect, an answer that does not
 *   parse or has the wrong shape, a certificate the client rejects, an integrity mismatch, a young version, a registry
 *   or name wormsign cannot vouch for, and any thrown error this file does not recognise are not.
 * - The host (OutageLedger): it gave no other answer in the whole run, and a probe sent after the run gets none
 *   either. One name the registry will not serve, while it serves the rest or its root, is that name's problem, not
 *   an outage: it stays high. A host that answers at any point in the run, and so one that goes down mid-run, fails
 *   closed.
 */
import type { Finding } from "./types.js";

/** What `--on-outage` chooses. "fail", the default, keeps every network failure a fail-closed finding. */
export type OnOutage = "fail" | "warn";

export const ON_OUTAGE: readonly OnOutage[] = ["fail", "warn"];

/** HTTP 429 and every 5xx: each client retries them once, and when the retry fails too the service is out. */
export function isTransientStatus(status: number): boolean {
  return status === 429 || status >= 500;
}

/** getaddrinfo's codes for a name that did not resolve, now or for good (Node's dns module, errors). */
const DNS = new Set(["ENOTFOUND", "EAI_AGAIN", "EAI_FAIL"]);
/** A connection that could not be made or broke: libuv's codes, and undici's for a socket or connect timeout. */
const CONNECT = new Set([
  "ECONNREFUSED",
  "ECONNRESET",
  "ECONNABORTED",
  "ETIMEDOUT",
  "EHOSTUNREACH",
  "EHOSTDOWN",
  "ENETUNREACH",
  "ENETDOWN",
  "EPIPE",
  "UND_ERR_CONNECT_TIMEOUT",
  "UND_ERR_SOCKET",
  "UND_ERR_HEADERS_TIMEOUT",
  "UND_ERR_BODY_TIMEOUT",
  "UND_ERR_CLOSED",
]);
/** A TLS handshake that broke off or spoke another protocol: OpenSSL's ERR_SSL_ reasons, EPROTO, a handshake timeout. */
const TLS = /^(?:ERR_SSL_|EPROTO$|ERR_TLS_HANDSHAKE_TIMEOUT$)/;
/**
 * A certificate verdict: the client rejected what the server presented (CERT_HAS_EXPIRED, UNABLE_TO_VERIFY_LEAF_SIGNATURE,
 * DEPTH_ZERO_SELF_SIGNED_CERT, SELF_SIGNED_CERT_IN_CHAIN, ERR_TLS_CERT_ALTNAME_INVALID, HOSTNAME_MISMATCH), or an
 * ERR_SSL_ alert about a certificate. That says the server may not be the one asked for: a reason to fail, never an
 * outage, wherever it is in the error's chain.
 */
const CERTIFICATE = /CERT|UNABLE_TO_|HOSTNAME_MISMATCH|_CA$|VERIFY|SIGNATURE/;

/**
 * The transport failure a thrown fetch error is, worded for a message ("connection failed (ECONNREFUSED)"), or
 * undefined when it is anything else. Node's fetch throws TypeError("fetch failed") with the cause holding the code,
 * an AggregateError of them when it tried several addresses, a TypeError("terminated") when the body broke off, and the
 * AbortSignal.timeout() reason, a DOMException named TimeoutError, when a request ran out of time. A SyntaxError (a body
 * that is not JSON), an HTTP parser error (an answer that is not HTTP), a certificate verdict or an error without a
 * known code is not an outage. The clients ask only about a failure that came before any status line.
 */
export function transportFailure(e: unknown): string | undefined {
  const chain: { name?: unknown; code?: unknown; errors?: unknown; cause?: unknown }[] = [];
  let x = e as (typeof chain)[number] | null | undefined;
  for (let depth = 0; depth < 4 && typeof x === "object" && x !== null; depth++, x = x.cause as typeof x) chain.push(x);
  const codesOf = (y: (typeof chain)[number]): string[] => [y.code, ...(Array.isArray(y.errors) ? y.errors.map((z) => (z as { code?: unknown } | null)?.code) : [])].filter((c): c is string => typeof c === "string");
  if (chain.some((y) => codesOf(y).some((code) => CERTIFICATE.test(code)))) return undefined;
  for (const y of chain) {
    if (y.name === "TimeoutError") return "timed out";
    for (const code of codesOf(y)) {
      if (DNS.has(code)) return `DNS lookup failed (${code})`;
      if (CONNECT.has(code)) return `connection failed (${code})`;
      if (TLS.test(code)) return `TLS failed (${code})`;
    }
  }
  return undefined;
}

/** One package version an outage left unchecked under --on-outage warn: the host that was out, why, and the package. */
export interface Unverified {
  host: string;
  error: string;
  /** "<ecosystem>:<name>@<version>", so a package the registry and OSV both missed counts once. */
  id: string;
}

/**
 * What a check reports for the requests an outage may explain, decided once the run is over: `warn` (WS-SK-006,
 * WS-OS-901) when `host` never answered, else `failClosed`, exactly what the check reports without the option.
 */
export interface OutageClaim {
  /** The host whose outage the claim rests on, as `answered` records it (URL.host: name and any port). */
  host: string;
  /** The URL the ledger probes, with HEAD, when the run never heard from the host: its root. */
  probe: string;
  failClosed: Finding[];
  warn: Finding[];
  unverified: Unverified[];
}

/**
 * The probe's answers that say the host is not there to answer: rate limited, or a gateway that could not reach it
 * (502, 503, 504). Any other status, 500, 501 (no HEAD) and 505 included, comes from a host that is up.
 */
const PROBE_DOWN: ReadonlySet<number> = new Set([429, 502, 503, 504]);

/**
 * The run's outages under --on-outage warn. Each client records every host that answers (`answered`: any status but
 * 429 and the 5xx); each check files a claim instead of a finding for what an outage left unchecked. `resolve`, after
 * every request of the run, probes each claimed host that never answered once, with HEAD on its root (no package name
 * is sent): the host is out only when that probe fails in transport or is answered 429, 502, 503 or 504. A host that answered at any point in the run,
 * or answers the probe, gets every claim on it back as its fail-closed findings.
 */
export class OutageLedger {
  readonly #answered = new Set<string>();
  readonly #probed = new Set<string>();
  readonly #claims: OutageClaim[] = [];

  /** The host gave an HTTP answer that is not 429 or a 5xx: it is not out, whatever its other requests did. */
  answered(host: string): void {
    this.#answered.add(host);
  }

  claim(c: OutageClaim): void {
    this.#claims.push(c);
  }

  /** How many claims the checks have filed so far. */
  get filed(): number {
    return this.#claims.length;
  }

  /** The claims' findings, and the packages the UNVERIFIED line counts. Call once, after every check of the run. */
  async resolve(fetchImpl: typeof fetch = fetch, timeoutMs = 30_000): Promise<{ findings: Finding[]; unverified: Unverified[] }> {
    for (const c of this.#claims) {
      if (this.#answered.has(c.host) || this.#probed.has(c.host)) continue;
      this.#probed.add(c.host);
      try {
        const res = await fetchImpl(c.probe, { method: "HEAD", redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
        if (!PROBE_DOWN.has(res.status)) this.answered(c.host);
      } catch (e) {
        // Only a transport failure confirms the outage; a certificate verdict or anything unknown fails closed.
        if (transportFailure(e) === undefined) this.answered(c.host);
      }
    }
    const findings: Finding[] = [];
    const unverified: Unverified[] = [];
    for (const c of this.#claims) {
      if (this.#answered.has(c.host)) {
        findings.push(...c.failClosed);
      } else {
        findings.push(...c.warn);
        unverified.push(...c.unverified);
      }
    }
    return { findings, unverified };
  }
}

/** The note and stderr line every --on-outage warn run with an outage prints. */
export const UNVERIFIED = "UNVERIFIED: ";

/**
 * `UNVERIFIED: N packages not checked (<host> unreachable: <error>; ...); --on-outage warn`, or undefined when the run
 * had no outage. Each host is named once, with the error of its first package in host and id order.
 */
export function outageSummary(list: readonly Unverified[]): string | undefined {
  if (list.length === 0) return undefined;
  const n = new Set(list.map((u) => u.id)).size;
  const byHost = new Map<string, string>();
  for (const u of [...list].sort((a, b) => a.host.localeCompare(b.host) || a.id.localeCompare(b.id))) if (!byHost.has(u.host)) byHost.set(u.host, u.error);
  const hosts = [...byHost].map(([host, error]) => `${host} unreachable: ${error}`).join("; ");
  return `${UNVERIFIED}${n} package${n === 1 ? "" : "s"} not checked (${hosts}); --on-outage warn`;
}
