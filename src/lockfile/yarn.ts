import type { LockedPackage } from "./types.js";
import { checkIdentity } from "./identity.js";

function unquote(s: string): string {
  const t = s.trim();
  // Yarn never writes escapes, but yarn 1 decodes them: a header "is\x2Dnumber@7.0.0" installs is-number.
  if (t.startsWith('"') && t.includes("\\")) throw new Error(`escape sequences are not supported: ${t}`);
  return t.startsWith('"') && t.endsWith('"') ? t.slice(1, -1) : t;
}

/** Splits a descriptor or locator like `@scope/pkg@npm:^1.0.0` at the '@' that ends the name. */
function splitAtName(d: string): { name: string; ref: string } {
  const at = d.indexOf("@", 1);
  return at === -1 ? { name: d, ref: "" } : { name: d.slice(0, at), ref: d.slice(at + 1) };
}

function fail(file: string, i: number, why: string): never {
  throw new Error(`${file} line ${i + 1}: ${why}`);
}

export function isYarnBerry(text: string): boolean {
  return /^__metadata:/m.test(text);
}

/**
 * One yarn 1 token as yarn writes it: double-quoted (escapes are matched here and rejected by unquote), or bare,
 * starting with a letter and holding none of the characters that make yarn quote a value. Yarn's own tokenizer
 * accepts more (`"resolved" "url"` is the key resolved), and when its grammar fails it reads the whole file as YAML
 * instead, where `resolved: url` is the key resolved. So the reader below accepts a subset of yarn's grammar, reads
 * a key whether quoted or not, and throws on every other line: a line it skipped could be one yarn acts on.
 */
const Y1_TOKEN = String.raw`(?:"(?:[^"\\]|\\.)*"|(?!true|false)[a-zA-Z][^\s:,"\\[\]]*)`;
const Y1_HEADER = new RegExp(String.raw`^${Y1_TOKEN}(?:, *${Y1_TOKEN})*:$`);
const Y1_FIELD = new RegExp(String.raw`^ {2}(${Y1_TOKEN}) +(${Y1_TOKEN}) *$`);
const Y1_BLOCK = new RegExp(String.raw`^ {2}(${Y1_TOKEN}):$`);
const Y1_DEPENDENCY = new RegExp(String.raw`^ {4}${Y1_TOKEN} +${Y1_TOKEN} *$`);
/** The fields yarn 1.22 writes in an entry. `uid` is informational; any other field is not read, so it throws. */
const Y1_FIELDS = new Set(["version", "resolved", "integrity", "uid"]);
const Y1_BLOCKS = new Set(["dependencies", "optionalDependencies"]);
/** A git source, whose `#` fragment names a commit, not a tarball: yarn 1 fetches `git://`, `git+<x>://`, ssh and `.git` URLs with git. */
const Y1_GIT = /^(?:git(?:\+[a-z0-9]+)?:\/\/|git@|ssh:\/\/)|\.git$/;

/**
 * The hash yarn 1 checks a tarball against when its entry has no `integrity` line: the SHA-1 in the `resolved` URL's
 * fragment, which yarn writes as 40 lower-case hex digits. In yarn 1.22.22's lib/cli.js, PackageRequest.getLocked
 * passes the fragment on as the remote's `hash`, TarballFetcher._findIntegrity falls back to
 * `ssri.fromHex(this.hash, 'sha1')`, and createExtractor validates it even beside an `integrity` line. Run with yarn
 * 1.22.22 against a tarball served locally, `install --frozen-lockfile` fails with "Integrity check failed" when the
 * fragment is wrong (with or without an integrity line) and installs when it is right. Undefined for a git source,
 * whose fragment is a commit, and for any other fragment.
 */
function fragmentIntegrity(resolved: string): string | undefined {
  const m = /^(.*)#([0-9a-f]{40})$/.exec(resolved);
  if (!m || Y1_GIT.test(m[1] as string)) return undefined;
  return `sha1-${Buffer.from(m[2] as string, "hex").toString("base64")}`;
}

/**
 * yarn.lock v1 (classic): blocks of `"a@^1", "a@^1.2":` followed by indented
 * `version "x"`, `resolved "url#sha1"`, `integrity ...` and dependency lists.
 * Throws on a line or block it cannot read rather than dropping it.
 */
export function parseYarnClassic(text: string): LockedPackage[] {
  const out: LockedPackage[] = [];
  let cur: { p: LockedPackage; line: number; linked: boolean; seen: Set<string>; inBlock: boolean; sha1?: string } | undefined;
  const flush = (): void => {
    if (!cur) return;
    if (cur.p.version === "") fail("yarn.lock", cur.line, `${cur.p.name} has no version`);
    // Only once the entry is complete: its integrity line, if any, can come after resolved.
    if (cur.p.integrity === undefined && cur.sha1 !== undefined) cur.p.integrity = cur.sha1;
    // file:/link: directories have no `resolved`; a file: tarball does and is reported through it.
    out.push(checkIdentity(cur.linked && !cur.p.resolved ? { ...cur.p, local: true } : cur.p, `yarn.lock line ${cur.line + 1}`));
    cur = undefined;
  };
  // Yarn's tokenizer ends a line at \r\n, \n or a lone \r.
  for (const [i, line] of text.split(/\r\n|\r|\n/).entries()) {
    if (line.startsWith("#") || line.trim() === "") continue;
    if (!/^\s/.test(line)) {
      flush();
      if (!Y1_HEADER.test(line)) fail("yarn.lock", i, "not an entry header");
      // Classic quotes each descriptor separately: `"a@^1", a@^2:`; the first one names the package.
      const first = new RegExp(`^${Y1_TOKEN}`).exec(line)?.[0] as string;
      const { name, ref } = splitAtName(unquote(first));
      const real = ref.startsWith("npm:") ? splitAtName(ref.slice("npm:".length)).name : name; // alias@npm:real@range
      cur = { p: { name: real, version: "" }, line: i, linked: /^(file|link):/.test(ref), seen: new Set(), inBlock: false };
      continue;
    }
    if (!cur) fail("yarn.lock", i, "indented line outside an entry");
    if (Y1_DEPENDENCY.test(line)) {
      if (!cur.inBlock) fail("yarn.lock", i, "a dependency line outside a dependencies block");
      continue;
    }
    const block = Y1_BLOCK.exec(line);
    const field = block ? undefined : Y1_FIELD.exec(line);
    const key = block?.[1] ?? field?.[1];
    if (key === undefined) fail("yarn.lock", i, "not a `key value` line yarn writes (a key with a colon or other syntax makes yarn read the file differently)");
    const k = unquote(key);
    if (block ? !Y1_BLOCKS.has(k) : !Y1_FIELDS.has(k)) fail("yarn.lock", i, `unsupported field ${JSON.stringify(k.slice(0, 40))}`);
    if (cur.seen.has(k)) fail("yarn.lock", i, `duplicate field ${k}`);
    cur.seen.add(k);
    cur.inBlock = block !== null;
    if (!field) continue;
    const val = unquote(field[2] as string);
    if (k === "version") cur.p.version = val;
    else if (k === "resolved") {
      cur.p.resolved = val.replace(/#[0-9a-f]+$/, "");
      const sha1 = fragmentIntegrity(val);
      if (sha1 !== undefined) cur.sha1 = sha1;
    } else if (k === "integrity") cur.p.integrity = val;
  }
  flush();
  return out;
}

/**
 * yarn.lock (berry, v2+). The `resolution:` locator is what Yarn fetches, so
 * name, version and source come from it rather than from the header, which may
 * list several descriptors or an alias. Berry records a `checksum` of its own
 * archive format, not a registry integrity, so integrity is not checked for
 * berry lockfiles.
 */
export function parseYarnBerry(text: string): LockedPackage[] {
  const out: LockedPackage[] = [];
  let cur: { header: string; line: number; version?: string; resolution?: string } | undefined;
  let inMetadata = false;
  let explicitKey = false; // Yarn writes a very long header as a YAML explicit key: `? "<header>"`, then `:`
  const flush = (): void => {
    if (cur) {
      const p = berryPackage(cur);
      const soft = SOFT_LINK.test(splitAtName(cur.resolution as string).ref) && LINK_NAME.test(p.name);
      out.push(soft ? p : checkIdentity(p, `yarn.lock line ${cur.line + 1}`));
    }
    cur = undefined;
  };
  for (const [i, line] of text.split(/\r?\n/).entries()) {
    if (line.startsWith("#") || line.trim() === "") continue;
    if (explicitKey) {
      if (line !== ":") fail("yarn.lock", i, "expected `:` after an explicit `?` key");
      explicitKey = false;
      continue;
    }
    if (!/^\s/.test(line)) {
      flush();
      explicitKey = line.startsWith("? ");
      if (!explicitKey && !line.endsWith(":")) fail("yarn.lock", i, "not an entry header");
      inMetadata = line === "__metadata:";
      if (!inMetadata) cur = { header: unquote(explicitKey ? line.slice(2) : line.slice(0, -1)), line: i };
      continue;
    }
    if (inMetadata) continue;
    if (!cur) fail("yarn.lock", i, "indented line outside an entry");
    const m = /^ {2}(version|resolution):\s*(.*)$/.exec(line);
    if (m && cur) cur[m[1] as "version" | "resolution"] = unquote(m[2] as string);
  }
  flush();
  return out;
}

/**
 * link:, portal: and workspace: resolutions (linkType: soft): a directory in the repository that Yarn links in place
 * and never fetches. Yarn takes such an entry's name from the dependency's key and does not check it as an npm name:
 * babel's lockfile locks "$repo-utils@link:./scripts/repo-utils", and Yarn 4.18.1 locks "$x@link:./x",
 * "$x@portal:./x" and a workspace named "$x" alike. Such an entry is local whatever its name, so its name is not
 * checked as an npm name; a registry, URL, git or file: entry's still is, and fails the whole lockfile closed when it
 * is not one.
 */
const SOFT_LINK = /^(?:link|portal|workspace):/;
/**
 * A soft link's name as Yarn writes it: no whitespace or quote, and no YAML indicator first. This reader keeps node
 * properties as text, so `!t@link:x "evil@npm:1.0.0"` reads as a link named `!t` while YAML reads a tagged npm
 * locator; a property needs an indicator and a space before the value, so such a name is still checked as an npm
 * name and fails the lockfile closed.
 */
const LINK_NAME = /^(?![&!*|>%`{}[\],#?])[^\s"']+$/;

function berryPackage(e: { header: string; line: number; version?: string; resolution?: string }): LockedPackage {
  if (!e.resolution) fail("yarn.lock", e.line, `${e.header} has no resolution`);
  const { name, ref } = splitAtName(e.resolution as string);
  const src = berrySource(ref);
  if (src === "local") return { name, version: e.version ?? "", local: true };
  if (!e.version) fail("yarn.lock", e.line, `${e.header} has no version`);
  // For the registry the locator's version is the one fetched; the `version:` field is informational.
  const version = ref.startsWith("npm:") ? ref.slice("npm:".length).replace(/::.*$/, "") : (e.version as string);
  return { name, version, ...(src === "npm" ? {} : { resolved: src }) };
}

/** "npm" for the default registry, "local" for in-repo sources, otherwise the source to report. */
function berrySource(ref: string): string {
  const proto = /^([a-z]+):/.exec(ref)?.[1];
  // `npm:1.2.3::__archiveUrl=<url>` makes Yarn fetch the tarball from that URL instead of the registry.
  if (proto === "npm") return new URLSearchParams(ref.split("::")[1] ?? "").get("__archiveUrl") ?? "npm";
  if (proto === "patch") {
    // `patch:<url-encoded locator>#<patch file>`: Yarn fetches the inner locator, then patches it. Yarn adds such
    // entries itself (builtin<compat/typescript|resolve|fsevents>), so judge the inner locator's source.
    const hash = ref.indexOf("#");
    return berrySource(splitAtName(decodeURIComponent(ref.slice("patch:".length, hash === -1 ? undefined : hash))).ref);
  }
  const spec = ref.replace(/::.*$/, ""); // drop Yarn's `::locator=...&hash=...` bookkeeping
  if (proto === "workspace" || proto === "portal" || proto === "link") return "local";
  if (proto === "file" && !/\.(tgz|tar\.gz|tar)(#|$)/.test(spec)) return "local"; // a directory in the repo
  return spec;
}
