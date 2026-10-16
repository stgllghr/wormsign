import type { LockedPackage } from "./types.js";
import { checkIdentity, SEMVER } from "./identity.js";

function unquote(s: string): string {
  const t = s.trim();
  // pnpm never writes escapes, but its YAML parser decodes them: "is\x2Dnumber" installs is-number.
  if (t.startsWith('"') && t.includes("\\")) throw new Error(`escape sequences are not supported: ${t}`);
  return (t.startsWith("'") && t.endsWith("'")) || (t.startsWith('"') && t.endsWith('"')) ? t.slice(1, -1) : t;
}

/** "@scope/name@1.2.3(peer@1)" (v9), "/name@1.2.3(peer@1)" (v6), "/name/1.2.3_peer@1" (v5). */
export function splitPnpmKey(raw: string): { name: string; version: string } | undefined {
  let k = unquote(raw).replace(/\(.*$/, "");
  if (k.startsWith("/")) k = k.slice(1);
  const v5 = /^((?:@[^/]+\/)?[^/@]+)\/([^/_]+)(?:_.*)?$/.exec(k);
  if (v5) return { name: v5[1] as string, version: v5[2] as string };
  const at = k.indexOf("@", 1); // the name ends at the first '@' after a scope; versions may contain '@' (git+ssh://git@...)
  return at > 0 ? { name: k.slice(0, at), version: k.slice(at + 1) } : undefined;
}

type Fail = (i: number, why: string) => never;

/**
 * A resolution value as pnpm writes it: plain, or quoted without escapes. YAML
 * syntax that a parser would turn into something else (`&a`, `!!str`, `*a`, a
 * nested flow collection) throws rather than being read as text. Inner spaces
 * are kept (pnpm 11.16 writes `directory: dir with space/lib`), but not a
 * trailing one, ` #` (a comment) or `: ` (a nested key).
 */
function scalar(v: string, i: number, fail: Fail): string {
  if (/^'[^']*'$|^"[^"\\]*"$/.test(v)) return v.slice(1, -1);
  return /^[^\s'"&*!|>%@`{}[\],#?][^,{}[\]]*$/.test(v) && !/\s$|\s#|:\s/.test(v) ? v : fail(i, `unsupported YAML value: ${v}`);
}

interface Entry {
  key: string;
  line: number;
  resolution?: Map<string, string>;
  name?: string;
  version?: string;
  requiresBuild?: boolean;
  /** `url:` and `integrity:` values anywhere in a block-style resolution, in file order. */
  urls: string[];
  integrities: string[];
}

/** Importer sections whose entries point at `packages:`; links and workspace deps do not. */
const IMPORTER_SECTIONS = new Set(["importers", "dependencies", "devDependencies", "optionalDependencies"]);

/**
 * Reads the top-level `packages:` map of pnpm-lock.yaml (v5-v9). Hand-rolled
 * because ADR 0005 allows no YAML dependency, so it accepts only
 * the layout pnpm writes (plain top-level keys, two-space entries, four-space
 * fields, a resolution as a flow map or, for runtimes, a block of plain keys) and
 * throws on anything else: pnpm reads the file with a real YAML parser, so a
 * reformatted lockfile it still installs from must not parse to fewer packages
 * here.
 */
export function parsePnpmLock(text: string): LockedPackage[] {
  const out: LockedPackage[] = [];
  const lines = text.split(/\r?\n/);
  let section = "";
  let expectsPackages = false;
  let entry: Entry | undefined;
  let block = false; // inside a block-style `resolution:` map
  const fail: Fail = (i, why) => {
    throw new Error(`line ${i + 1}: ${why}`);
  };
  const flush = (): void => {
    if (entry) out.push(...toPackages(entry, fail));
    entry = undefined;
  };
  for (const [i, line] of lines.entries()) {
    if (line.trim() === "") continue;
    if (!line.startsWith(" ")) {
      flush();
      if (line === "---") continue; // pnpm 11 writes configDependencies/packageManager as a leading YAML document
      const top = /^([A-Za-z]\w*):(.*)$/.exec(line) ?? fail(i, "not a plain top-level key");
      section = top[1] as string;
      if (section === "packages" && !/^\s*(\{\})?$/.test(top[2] as string)) fail(i, "`packages:` must be followed by indented entries");
      continue;
    }
    if (IMPORTER_SECTIONS.has(section)) {
      const value = /^ +\S+: *(\S.*)$/.exec(line)?.[1];
      if (value && value !== "{}" && !/^['"]?(link|workspace):/.test(value)) expectsPackages = true;
    }
    if (section !== "packages") continue;
    const key = /^ {2}(\S.*?):$/.exec(line);
    if (key) {
      flush();
      entry = { key: key[1] as string, line: i, urls: [], integrities: [] };
      block = false;
      continue;
    }
    if (!entry || !line.startsWith("    ")) fail(i, "unexpected indentation in `packages:`");
    if (block && entry && line.startsWith("      ")) {
      // A runtime's download URLs sit in nested `variants:`, so every line must be a plain key whatever its depth.
      const [, indent, k, raw] = /^( +)(?:- )?([A-Za-z]\w*):(?: +(\S.*))?$/.exec(line) ?? fail(i, "unexpected line in a block `resolution:`");
      const v = raw === undefined ? "" : scalar(raw, i, fail);
      if (indent?.length === 6 && raw !== undefined) entry.resolution?.set(k as string, v);
      if (k === "url") entry.urls.push(v);
      if (k === "integrity") entry.integrities.push(v);
      continue;
    }
    block = false;
    const field = /^ {4}(resolution|name|version|requiresBuild):\s*(.*)$/.exec(line);
    if (!field || !entry) continue;
    const value = unquote(field[2] as string);
    block = field[1] === "resolution" && value === "";
    if (field[1] === "resolution") entry.resolution = block ? new Map() : flowMap(field[2] as string, i, fail);
    else if (field[1] === "name") entry.name = value;
    else if (field[1] === "version") entry.version = value;
    else entry.requiresBuild = value === "true";
  }
  flush();
  if (out.length === 0 && expectsPackages) throw new Error("importers list dependencies but no `packages:` entries were found");
  return out;
}

/** `{integrity: sha512-..., tarball: https://...}`: one level of plain keys, the only flow form pnpm writes here. */
function flowMap(text: string, i: number, fail: Fail): Map<string, string> {
  const body = /^\{(.+)\}$/.exec(text.trim())?.[1] ?? fail(i, "a resolution must be a flow map or an indented block");
  const map = new Map<string, string>();
  for (const part of body.split(/,\s*/)) {
    const [, k, v] = /^([A-Za-z]\w*): (.+)$/.exec(part) ?? fail(i, `unsupported resolution field: ${part}`);
    map.set(k as string, scalar(v as string, i, fail));
  }
  return map;
}

function toPackages(e: Entry, fail: Fail): LockedPackage[] {
  const res = e.resolution?.size ? e.resolution : fail(e.line, `${e.key} has no resolution`);
  const fromKey = splitPnpmKey(e.key);
  const where = `line ${e.line + 1}`;
  const type = res.get("type");
  // devEngines.runtime (pnpm 11): a binary per platform, downloaded from each `url:` and installed as the runtime.
  if (type === "variations" || type === "binary") {
    if (e.urls.length === 0 || e.urls.length !== e.integrities.length) fail(e.line, `${e.key}: expected one url and integrity per binary`);
    return e.urls.map((url, j) => checkIdentity({ name: fromKey?.name ?? "", version: fromKey?.version ?? "", resolved: url, integrity: e.integrities[j] as string, runtime: true }, where));
  }
  // pnpm picks a fetcher by `type` alone: no type is a tarball (from `tarball:`, else the registry), and a field
  // of another type is ignored: `directory:` or `repo:` without its type, `tarball:` with one (pnpm 9.0 and 11.16 pickFetcher).
  if (type !== undefined && type !== "directory" && type !== "git") fail(e.line, `${e.key} has an unsupported resolution type`);
  const integrity = res.get("integrity");
  const tarball = type === undefined ? res.get("tarball") : undefined;
  const repo = type === "git" ? (res.get("repo") ?? fail(e.line, `${e.key} has a git resolution without a repo`)) : undefined;
  const local = type === "directory";
  if (!integrity && !tarball && !repo && !local) fail(e.line, `${e.key} has an unrecognised resolution`);
  // A registry key names the package; anything else is named by the name/version pnpm read from its manifest.
  // pnpm 9 takes a registry entry's version from its key and pnpm 10 and 11 from a `version:` field, which they
  // write only for other sources, so a field that disagrees with a registry key cannot be read either way.
  const registry = !repo && !local && SEMVER.test(fromKey?.version ?? "");
  if (registry && ((e.name ?? fromKey?.name) !== fromKey?.name || (e.version ?? fromKey?.version) !== fromKey?.version)) {
    fail(e.line, `${e.key} has a name or version field that differs from its key`);
  }
  return [checkIdentity({
    name: (e.name ?? fromKey?.name) ?? "",
    version: (registry ? fromKey?.version : e.version) ?? "",
    ...(integrity ? { integrity } : {}),
    ...(tarball ? { resolved: tarball } : repo ? { resolved: `git+${repo}` } : {}),
    ...(local ? { local: true } : {}),
    ...(e.requiresBuild ? { hasInstallScript: true } : {}),
  }, where)];
}
