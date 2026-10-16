// URL handling shared by the commands that use the network (soak, update-iocs).

/**
 * `url` without its userinfo (`user:password@`), query and fragment, for printing. Registry URLs read from
 * config (.npmrc, npm_config_registry, .yarnrc.yml) may carry a token there, and every message and note can end up
 * in a CI log or a SARIF upload.
 *
 * The WHATWG URL parser, which npm's fetch and wormsign's use, decides what the userinfo is, so it is asked first:
 * it also reads credentials from forms a pattern misses, such as `https:user:token@host/`, `https:\\user:token@host/`,
 * a leading space or control character, or a tab inside the scheme. When it finds userinfo, the URL is printed as
 * it parsed, without userinfo, query and fragment. Otherwise a pattern drops anything that still looks like
 * userinfo (in text the parser refuses: after the scheme and any "/" or "\", the authority ends at the first "/",
 * "\", "?" or "#", and the last "@" before it ends the userinfo), and the query and fragment. The rest is kept
 * exactly as given, so a URL without those parts prints unchanged (`new URL(u).href` would add a trailing slash).
 */
export function redactUrl(url: string): string {
  try {
    const u = new URL(url);
    if (u.username || u.password) return `${u.protocol}//${u.host}${u.pathname}`;
  } catch {
    // Not a URL the parser accepts: the pattern below still applies.
  }
  return stripUserinfo(url).replace(/[?#].*$/s, "");
}

/**
 * redactUrl's pattern alone: `url` without anything that still looks like userinfo (after the scheme and any "/" or
 * "\", up to the last "@" before the first "/", "\", "?" or "#"), and otherwise exactly as given, query and fragment
 * included. For text the URL parser refuses, or reads without userinfo (`git+ssh:user:token@host/x`, a port out of
 * range), which a message must still not print with its credentials.
 */
export function stripUserinfo(url: string): string {
  return url.replace(/^(\s*[a-z][a-z0-9+.-]*:[/\\]*)[^/\\?#]*@/i, "$1");
}

/**
 * What to say about a redirect, or undefined when `res` is not one. Fetches whose URL the user supplies pass
 * `redirect: "manual"`, so a 3xx comes back as itself instead of being followed: an https URL that redirects to
 * plain http, or to another host, would otherwise be fetched there while every message names the original
 * (https://fetch.spec.whatwg.org/#concept-request-redirect-mode; Node's fetch, undici, returns the 3xx response
 * with its Location header).
 */
export function redirectProblem(res: Response): string | undefined {
  if (res.status < 300 || res.status > 399) return undefined;
  const to = res.headers.get("location");
  return `HTTP ${res.status}, a redirect${to ? ` to ${redactUrl(to).slice(0, 200)}` : ""}, which wormsign does not follow`;
}
