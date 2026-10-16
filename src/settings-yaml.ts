/**
 * YAML settings files (pnpm-workspace.yaml, pnpm 11's config.yaml, .yarnrc.yml): a strict subset, not a YAML parser.
 * soak reads release-age and registry settings with it (src/soak-config.ts), and scan and diff the paths a setting
 * names as code to run (src/diff.ts configuredCode). The keys a check reads must have the shape it expects, spelled
 * simply; anything else there (anchor, alias, tag, merge key, "? " key, block scalar, nested flow collection, escape,
 * duplicate key) is a problem, and the caller fails closed. Other keys are skipped, but no line may leave a quote or
 * bracket open, since YAML would carry it into the next lines.
 */
import { stripBom } from "./fsutil.js";
import { keyDigest } from "./types.js";

/** A scalar's string: quotes removed, and '' in a single-quoted one read as ' (as pnpm 11.16.0 does, verified). */
export const unquote = (v: string): string => (/^".*"$/.test(v) ? v.slice(1, -1) : /^'.*'$/.test(v) ? v.slice(1, -1).replaceAll("''", "'") : v);

/**
 * A read key's value: a scalar (quotes kept: a quoted "false" is a string, not the boolean), a list as one line, a
 * map, or (pathsValue) the paths a setting names, unquoted.
 */
export type YamlValue = string | string[] | Map<string, YamlValue>;
/** A settings file's values for the keys its checks read, what in it this reader does not model, and a digest of its text. */
export interface YamlDoc { values: Map<string, YamlValue>; problems: string[]; digest: string }
/** A line's text and 1-based number. */
interface Line { text: string; n: number }
type Fail = (why: string, n: number) => undefined;
/** Reads a key's value from the rest of its line and the lines under it, or reports why it cannot. */
export type Reader = (head: Line, under: Line[], fail: Fail) => YamlValue | undefined;

/** A YAML 1.2 null: a spelling of it, or nothing. */
export const NULL = /^(null|Null|NULL|~)?$/;
/**
 * A quoted scalar: single-quoted ('' is a quote, so a closing quote is never followed by another) or double-quoted
 * (backslash escapes). Sticky: it matches at lastIndex.
 */
const QUOTED = /'(?:[^']|'')*'(?!')|"(?:[^"\\]|\\.)*"/y;
/**
 * A plain, double-quoted (no escapes) or single-quoted (no '') key, optional blanks, ':', then the value.
 * An anchor, tag, merge key or "? " key does not match.
 */
const YAML_KEY = /^(?:"([^"\\]*)"|'([^']*)'|([\w$./@-]+))[ \t]*:(?:[ \t]+(.*))?$/;
/** A plain scalar, or nothing: no indicator (& * ! | > [ { " ' % @ # , and ? : - before a blank) first, and no ": " in it. */
const PLAIN = /^(([^\s"'&*!|>[\]{}%@`#,?:-]|[?:-]\S)([^:]|:\S)*)?$/;

/** The text without its comment ('#' at the start or after a blank) and outer blanks: spaces and tabs only, the only YAML blanks. */
function bare(text: string): string {
  const t = text.replace(/(^|[ \t])#.*$/, "");
  // Index loops, not a regex: /[ \t]+$/ is quadratic on a long run of blanks followed by something else.
  let [a, b] = [0, t.length];
  while (a < b && (t[a] === " " || t[a] === "\t")) a++;
  while (b > a && (t[b - 1] === " " || t[b - 1] === "\t")) b--;
  return t.slice(a, b);
}

/**
 * Does the line leave a quoted scalar or flow collection open? YAML continues it on the next lines, which can
 * swallow a top-level key (verified: pnpm 11.16.0 and Yarn 4.10.3 then read the key as unset). A quote opens a
 * scalar only where a value starts: after the indentation, "- " or ": ", and after "[", "{" or "," in a flow
 * collection. Elsewhere a quote after a blank or one of [{,: (as in "[a 'b, 'c]", or after an anchor) is not
 * guessed at and counts as open; one after any other character ("it's") is plain text. One pass: linear time.
 */
function leavesOpen(line: string): boolean {
  let depth = 0; // flow collections open
  let start = true; // a value can start here
  for (let i = 0; i < line.length; i++) {
    const c = line[i] as string;
    if (c === "'" || c === '"') {
      if (!start && !/[ \t[{,:]/.test(line[i - 1] as string)) continue;
      QUOTED.lastIndex = i;
      if (!start || !QUOTED.test(line)) return true;
      [i, start] = [QUOTED.lastIndex - 1, false];
    } else if (c === " " || c === "\t") {
      if (line[i + 1] === "#") break;
    } else if (depth > 0 && (c === "]" || c === "}")) [depth, start] = [depth - 1, false];
    else if ((start || depth > 0) && (c === "[" || c === "{")) [depth, start] = [depth + 1, true];
    else start = (depth > 0 && c === ",") || ((c === ":" || (start && c === "-")) && /^[ \t]?$/.test(line[i + 1] ?? ""));
  }
  return depth > 0;
}

/** The scalar on a key's line, quotes kept and comment dropped ("" for none); undefined for anything else. */
function scalar(text: string): string | undefined {
  const quoted = /^("[^"\\]*"|'(?:[^']|'')*')[ \t]*(#.*)?$/.exec(text)?.[1];
  return quoted ?? (PLAIN.test(bare(text)) ? bare(text) : undefined);
}

const indentOf = (l: Line): number => (/^ */.exec(l.text) as RegExpExecArray)[0].length;

/**
 * Splits the lines of a block map at `indent` into its keys, each with its value's text and the lines under it
 * (deeper, or a "- " item at the key's own indentation, which pnpm and Yarn accept). A line that is not a
 * simple key, and a duplicate key, is a problem (pnpm rejects a duplicate; Yarn reads the last, verified).
 */
function blockMap(lines: Line[], indent: number, fail: Fail): Map<string, [head: Line, under: Line[]]> {
  const out = new Map<string, [Line, Line[]]>();
  let under: Line[] | undefined;
  for (const l of lines) {
    const depth = indentOf(l);
    if (under && (depth > indent || (depth === indent && /^-([ \t]|$)/.test(l.text.slice(indent))))) {
      under.push(l);
      continue;
    }
    const m = depth === indent ? YAML_KEY.exec(l.text.slice(indent)) : null;
    const key = m && ((m[1] ?? m[2] ?? m[3]) as string);
    under = []; // the lines under a bad line belong to no key
    if (key === null) fail("a line that is not a simple 'key: value'", l.n);
    else if (out.has(key)) fail(`a duplicate key ${key}`, l.n);
    else out.set(key, [{ text: m?.[4] ?? "", n: l.n }, under]);
  }
  return out;
}

/** A one-line scalar, with nothing under its key. */
export const scalarValue: Reader = (head, under, fail) => {
  const v = scalar(head.text);
  return v !== undefined && under.length === 0 ? v : fail("a value that is not a one-line scalar", head.n);
};

/** A list of scalars, as one line: "- a - b" from a block list, a one-level flow list "[a, b]", or null. Any item makes it a finding. */
export const listValue: Reader = (head, under, fail) => {
  const v = bare(head.text);
  if (under.length === 0) return NULL.test(v) || /^\[[^[\]{}]*\]$/.test(v) ? v : fail("a value that is not a list of scalars", head.n);
  if (v !== "") return fail("a value both on the key's line and under it", head.n);
  const items: string[] = [];
  for (const l of under) {
    const item = indentOf(l) === indentOf(under[0] as Line) ? scalar(/^ *-[ \t]+(.*)$/.exec(l.text)?.[1] ?? "") : undefined;
    if (!item) return fail("a list entry that is not a one-line scalar", l.n);
    items.push(`- ${item}`);
  }
  return items.join(" ");
};

/** A block map whose values `read` reads, or null or "{}" for an empty one. */
export const mapOf = (read: Reader): Reader => (head, under, fail) => {
  const v = bare(head.text);
  if (under.length === 0) return NULL.test(v) || /^\{\s*\}$/.test(v) ? new Map() : fail("a value that is not a block map", head.n);
  if (v !== "") return fail("a value both on the key's line and under it", head.n);
  const out = new Map<string, YamlValue>();
  for (const [key, [h, u]] of blockMap(under, indentOf(under[0] as Line), fail)) {
    const value = read(h, u, fail);
    if (value === undefined) return undefined;
    out.set(key, value);
  }
  return out;
};

/** The items of a one-level flow list ("a, 'b', \"c\""), unquoted; undefined after a failure. Index loops: linear time. */
function flowItems(inner: string, n: number, fail: Fail): string[] | undefined {
  const out: string[] = [];
  if (bare(inner) === "") return out;
  const blanks = (i: number): number => {
    while (inner[i] === " " || inner[i] === "\t") i++;
    return i;
  };
  for (let i = 0; ; i++) {
    i = blanks(i);
    let raw: string;
    if (inner[i] === '"' || inner[i] === "'") {
      QUOTED.lastIndex = i;
      if (!QUOTED.test(inner)) return fail("a list entry with an unclosed quote", n);
      raw = inner.slice(i, QUOTED.lastIndex);
      i = blanks(QUOTED.lastIndex);
    } else {
      const end = inner.indexOf(",", i);
      raw = bare(inner.slice(i, end === -1 ? inner.length : end));
      i = end === -1 ? inner.length : end;
      if (raw === "" || !PLAIN.test(raw) || /["']/.test(raw)) return fail("a list entry that is not a plain or quoted scalar", n);
    }
    if (raw.startsWith('"') && raw.includes("\\")) return fail("a list entry with an escape", n);
    out.push(unquote(raw));
    if (i >= inner.length) return out;
    if (inner[i] !== ",") return fail("a list entry followed by more than a comma", n);
  }
}

/**
 * The paths a setting names, unquoted: a one-line scalar, a one-level flow list, or a block list whose entries are
 * one-line scalars or maps with a one-line `path` (Yarn's plugins: `- path: x` and `spec: y` under it). Any other
 * shape is a problem.
 */
const pathsValue: Reader = (head, under, fail) => {
  const v = bare(head.text);
  if (under.length === 0) {
    if (NULL.test(v)) return [];
    const flow = /^\[(.*)\]$/.exec(v);
    if (flow) return flowItems(flow[1] as string, head.n, fail);
    const one = scalar(head.text);
    return one === undefined || /^"[^"]*\\/.test(one) ? fail("a value that is not a path or a list of paths", head.n) : [unquote(one)];
  }
  if (v !== "") return fail("a value both on the key's line and under it", head.n);
  const dash = indentOf(under[0] as Line);
  const out: string[] = [];
  for (let i = 0; i < under.length; ) {
    const l = under[i++] as Line;
    const more: Line[] = [];
    while (i < under.length && indentOf(under[i] as Line) > dash) more.push(under[i++] as Line);
    const item = indentOf(l) === dash ? /^ *-[ \t]+(.*)$/.exec(l.text)?.[1] : undefined;
    if (item === undefined) return fail("a list entry that is not '- <path>'", l.n);
    let path: string | undefined;
    if (YAML_KEY.test(item)) {
      const at = l.text.length - item.length;
      const entry = blockMap([{ text: `${" ".repeat(at)}${item}`, n: l.n }, ...more], at, fail).get("path");
      path = entry && entry[1].length === 0 ? scalar(entry[0].text) : undefined;
    } else if (more.length === 0) {
      path = scalar(item);
    }
    if (path === undefined || path === "" || /^"[^"]*\\/.test(path)) return fail("a list entry that is not a one-line path", l.n);
    out.push(unquote(path));
  }
  return out;
};

/**
 * The paths that `keys` of a YAML settings file name, read with the strict subset above. `problems` lists what the
 * reader does not model anywhere in the file; a caller that follows these paths must fail closed on any.
 */
export function yamlPaths(text: string, keys: string[]): { values: Map<string, string[]>; problems: string[] } {
  const doc = readYaml(text, new Map(keys.map((k) => [k, pathsValue])));
  const values = new Map<string, string[]>();
  for (const [k, v] of doc.values) if (Array.isArray(v)) values.set(k, v);
  return { values, problems: doc.problems };
}

/** Reads the keys `readers` names from a YAML settings file. A lone CR ends a line, as in YAML (verified, pnpm 11.16.0). */
export function readYaml(text: string, readers: Map<string, Reader>): YamlDoc {
  const problems: [n: number, why: string][] = [];
  const fail: Fail = (why, n) => void problems.push([n, why]);
  const lines = stripBom(text).split(/\r\n|\r|\n/).map((t, i) => ({ text: t, n: i + 1 })).filter((l) => !/^[ \t]*(#.*)?$/.test(l.text));
  for (const l of lines) if (leavesOpen(l.text)) fail("a quoted scalar or flow collection that continues on the next line", l.n);
  if (/^---[ \t]*(#.*)?$/.test(lines[0]?.text ?? "")) lines.shift();
  const values = new Map<string, YamlValue>();
  for (const [key, [head, under]] of blockMap(lines, 0, fail)) {
    const v = readers.get(key)?.(head, under, (why, n) => fail(`${key}: ${why}`, n));
    if (v !== undefined) values.set(key, v);
  }
  const listed = problems.sort((a, b) => a[0] - b[0]).map(([n, why]) => `${why} on line ${n}`);
  return { values, problems: listed, digest: keyDigest(text) };
}

/** A scalar or list setting, as one line. */
export const yamlText = (v: YamlValue | undefined): string | undefined => (typeof v === "string" ? v : undefined);
/** A map setting (empty when unset). */
export const yamlMap = (v: YamlValue | undefined): Map<string, YamlValue> => (v instanceof Map ? v : new Map());
