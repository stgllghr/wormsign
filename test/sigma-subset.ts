/**
 * Just enough YAML and Sigma to run the rules in detections/ over their own example events, with no dependency.
 *
 * Both halves are subsets and fail closed: a YAML construct, Sigma modifier, condition or correlation type outside
 * what the rules use throws, so a rule that starts using one fails the test instead of being half-evaluated. The
 * semantics follow the Sigma specification (case-insensitive string matching, `*` and `?` wildcards, backslash
 * escapes, sliding correlation windows); detections/tools/check_sigma_examples.py runs the same examples through
 * the official pySigma SQLite backend as a cross-check.
 */

export type Yaml = string | number | boolean | null | Yaml[] | { [key: string]: Yaml };
export type YamlMap = { [key: string]: Yaml };
export type SigmaEvent = Record<string, unknown>;

export const isMap = (v: Yaml | undefined): v is YamlMap => typeof v === "object" && v !== null && !Array.isArray(v);

class SubsetError extends Error {}

/** Parses a multi-document YAML file made of block mappings, block sequences of scalars, scalars and `|`/`>` blocks. */
export function parseYamlDocuments(text: string): YamlMap[] {
  const docs: string[][] = [[]];
  for (const line of text.split("\n")) {
    if (line === "---") docs.push([]);
    else (docs.at(-1) as string[]).push(line);
  }
  return docs.map((lines, d) => {
    const p = new YamlParser(lines);
    const value = p.block(0);
    if (p.next() !== undefined) throw new SubsetError(`document ${d + 1}: unexpected indentation at "${p.next()}"`);
    if (!isMap(value)) throw new SubsetError(`document ${d + 1} is not a mapping`);
    return value;
  });
}

class YamlParser {
  private i = 0;
  constructor(private readonly lines: string[]) {}

  private significant(): number {
    while (this.i < this.lines.length) {
      const t = (this.lines[this.i] as string).trim();
      if (t !== "" && !t.startsWith("#")) break;
      this.i++;
    }
    return this.i;
  }

  next(): string | undefined {
    return this.lines[this.significant()];
  }

  private indentOf(line: string): number {
    const n = line.length - line.trimStart().length;
    if (line.slice(0, n).includes("\t")) throw new SubsetError(`tab indentation: "${line}"`);
    return n;
  }

  block(indent: number): Yaml {
    const line = this.next();
    if (line === undefined) return null;
    if (this.indentOf(line) !== indent) throw new SubsetError(`expected indentation ${indent}: "${line}"`);
    return /^\s*- /.test(line) ? this.sequence(indent) : this.mapping(indent);
  }

  private mapping(indent: number): YamlMap {
    const out: YamlMap = {};
    for (let line = this.next(); line !== undefined && this.indentOf(line) === indent; line = this.next()) {
      const m = /^([A-Za-z_@][\w@.|-]*):(?: +(.*))?$/.exec(line.trim());
      if (!m) throw new SubsetError(`not a "key: value" line: "${line}"`);
      const key = m[1] as string;
      if (Object.hasOwn(out, key)) throw new SubsetError(`duplicate key ${key}`);
      this.i++;
      const rest = stripComment(m[2] ?? "");
      if (/^[|>][-+]?$/.test(rest)) out[key] = this.blockScalar(indent, rest);
      else if (rest !== "") out[key] = scalar(rest);
      else {
        const after = this.next();
        out[key] = after !== undefined && this.indentOf(after) > indent ? this.block(this.indentOf(after)) : null;
      }
    }
    return out;
  }

  private sequence(indent: number): Yaml[] {
    const out: Yaml[] = [];
    for (let line = this.next(); line !== undefined && this.indentOf(line) === indent && /^\s*- /.test(line); line = this.next()) {
      const item = stripComment(line.trim().slice(2).trim());
      if (!/^['"]/.test(item) && (/: /.test(item) || item.endsWith(":"))) throw new SubsetError(`mappings in sequences are not supported: "${line}"`);
      out.push(scalar(item));
      this.i++;
    }
    return out;
  }

  /** The lines under a `|` or `>` indicator: all that are blank or indented deeper than the key. */
  private blockScalar(indent: number, indicator: string): string {
    if (indicator.endsWith("+")) throw new SubsetError(`block indicator ${indicator} is not supported`);
    const body: string[] = [];
    let inner: number | undefined;
    for (; this.i < this.lines.length; this.i++) {
      const line = this.lines[this.i] as string;
      if (line.trim() === "") {
        body.push("");
        continue;
      }
      const n = this.indentOf(line);
      if (n <= indent) break;
      inner ??= n;
      if (n < inner) throw new SubsetError(`block scalar line indented less than its first line: "${line}"`);
      body.push(line.slice(inner));
    }
    while (body.at(-1) === "") body.pop();
    const text = indicator.startsWith("|") ? body.join("\n") : body.reduce((acc, l) => (l === "" ? `${acc}\n` : acc === "" || acc.endsWith("\n") ? acc + l : `${acc} ${l}`), "");
    return indicator.endsWith("-") ? text : `${text}\n`;
  }
}

/** Drops a trailing ` # comment` outside quotes. */
function stripComment(s: string): string {
  let quote: string | undefined;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote) {
      if (c === quote) quote = undefined;
    } else if (c === "'" || c === '"') quote = c;
    else if (c === "#" && (i === 0 || s[i - 1] === " ")) return s.slice(0, i).trimEnd();
  }
  return s;
}

function scalar(s: string): Yaml {
  if (s.startsWith("'")) {
    if (!/^'(?:[^']|'')*'$/.test(s)) throw new SubsetError(`bad single-quoted scalar: ${s}`);
    return s.slice(1, -1).replaceAll("''", "'");
  }
  if (s.startsWith('"')) return JSON.parse(s) as string;
  if (/^[[\]{}&*!|>%@`]/.test(s) || / #|: /.test(s)) throw new SubsetError(`unsupported plain scalar: ${s}`);
  if (s === "true" || s === "false") return s === "true";
  if (s === "null" || s === "~") return null;
  if (/^-?\d+$/.test(s)) return Number(s);
  return s;
}

// --- Sigma -------------------------------------------------------------------------------------------------------

const MODIFIERS = new Set(["contains", "startswith", "endswith", "all", "exists"]);

/** A Sigma string value as a regular expression: `*` and `?` are wildcards, and `\` escapes `*`, `?` and `\`. */
type StringMatch = "eq" | "contains" | "startswith" | "endswith";

function valueRegex(value: string | number | boolean, how: StringMatch): RegExp {
  let body = "";
  if (typeof value === "string") {
    for (let i = 0; i < value.length; i++) {
      const c = value[i] as string;
      const n = value[i + 1];
      if (c === "\\" && (n === "*" || n === "?" || n === "\\")) {
        body += n.replace(/[\\*?]/, "\\$&");
        i++;
      } else if (c === "*") body += ".*";
      else if (c === "?") body += ".";
      else body += c.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
    }
  } else body = String(value).replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
  const start = how === "eq" || how === "startswith" ? "^" : "";
  const end = how === "eq" || how === "endswith" ? "$" : "";
  return new RegExp(`${start}${body}${end}`, "is");
}

function fieldMatches(event: SigmaEvent, key: string, expected: Yaml): boolean {
  const [field, ...mods] = key.split("|") as [string, ...string[]];
  for (const m of mods) if (!MODIFIERS.has(m)) throw new SubsetError(`unsupported modifier |${m}`);
  const actual = event[field];
  const present = actual !== undefined && actual !== null;
  if (mods.includes("exists")) {
    if (mods.length !== 1 || typeof expected !== "boolean") throw new SubsetError(`|exists takes true or false alone: ${key}`);
    return present === expected;
  }
  const how = mods.filter((m) => m !== "all");
  if (how.length > 1) throw new SubsetError(`more than one string modifier: ${key}`);
  const values = Array.isArray(expected) ? expected : [expected];
  if (values.length === 0) throw new SubsetError(`empty value list: ${key}`);
  // Sigma defines matching on one value. A list or map in the event would be matched element-wise by some backends and
  // as serialized text by others, so the evaluator refuses it rather than return a "no match" it cannot justify.
  if (present && typeof actual === "object") throw new SubsetError(`field ${field} holds ${Array.isArray(actual) ? "a list" : "a map"}; only |exists may test it`);
  const one = (v: Yaml): boolean => {
    if (v === null || typeof v === "object") throw new SubsetError(`unsupported value for ${key}: ${JSON.stringify(v)}`);
    if (!present) return false;
    // "All values are treated as case-insensitive strings" (Sigma rules specification 2.1.0, "General"), so the rule's
    // true matches the event's "TRUE" and its 1 matches "1".
    return valueRegex(v, (how[0] ?? "eq") as StringMatch).test(String(actual));
  };
  return mods.includes("all") ? values.every(one) : values.some(one);
}

function selectionMatches(name: string, selection: Yaml | undefined, event: SigmaEvent): boolean {
  if (!isMap(selection)) throw new SubsetError(`selection ${name} must be a mapping of fields (lists and keywords are not supported)`);
  return Object.entries(selection).every(([key, value]) => fieldMatches(event, key, value));
}

/** Evaluates a Sigma condition: identifiers, and, or, not, parentheses, and `1 of` / `all of` a name or `prefix*`. */
function conditionMatches(detection: YamlMap, event: SigmaEvent): boolean {
  const condition = detection["condition"];
  if (typeof condition !== "string") throw new SubsetError("detection.condition must be one string");
  const tokens = condition.match(/[()]|[^\s()]+/g) ?? [];
  let at = 0;
  const peek = (): string | undefined => tokens[at];
  const take = (): string => {
    const t = tokens[at++];
    if (t === undefined) throw new SubsetError(`condition ends early: ${condition}`);
    return t;
  };
  const selections = Object.keys(detection).filter((k) => k !== "condition");
  const named = (pattern: string): string[] => {
    const names = pattern.endsWith("*") ? selections.filter((s) => s.startsWith(pattern.slice(0, -1))) : selections.filter((s) => s === pattern);
    if (names.length === 0 || pattern === "them") throw new SubsetError(`condition names no selection: ${pattern}`);
    return names;
  };
  const or = (): boolean => {
    let v = and();
    while (peek() === "or") {
      take();
      v = and() || v;
    }
    return v;
  };
  const and = (): boolean => {
    let v = not();
    while (peek() === "and") {
      take();
      v = not() && v;
    }
    return v;
  };
  const not = (): boolean => {
    if (peek() === "not") {
      take();
      return !not();
    }
    return atom();
  };
  const atom = (): boolean => {
    const t = take();
    if (t === "(") {
      const v = or();
      if (take() !== ")") throw new SubsetError(`unbalanced parentheses: ${condition}`);
      return v;
    }
    if ((t === "1" || t === "all") && peek() === "of") {
      take();
      const results = named(take()).map((s) => selectionMatches(s, detection[s], event));
      return t === "1" ? results.includes(true) : results.every(Boolean);
    }
    if (["and", "or", "of", ")", "|"].includes(t) || t.includes("*")) throw new SubsetError(`unexpected "${t}" in condition: ${condition}`);
    return selectionMatches(t, detection[named(t)[0] as string], event);
  };
  const v = or();
  if (at !== tokens.length) throw new SubsetError(`unexpected "${peek()}" in condition: ${condition}`);
  return v;
}

/** Whether a single Sigma rule (not a correlation) matches one event. */
export function ruleMatches(rule: YamlMap, event: SigmaEvent): boolean {
  const detection = rule["detection"];
  if (!isMap(detection)) throw new SubsetError(`rule ${String(rule["name"])} has no detection mapping`);
  return conditionMatches(detection, event);
}

const SPAN_UNITS: Record<string, number> = { s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 };
const COMPARE: Record<string, (a: number, b: number) => boolean> = {
  gt: (a, b) => a > b,
  gte: (a, b) => a >= b,
  lt: (a, b) => a < b,
  lte: (a, b) => a <= b,
  eq: (a, b) => a === b,
  neq: (a, b) => a !== b,
};

/**
 * Runs a correlation rule over a stream of events (ordered by `@timestamp`, epoch milliseconds) and returns, for each
 * alert, the indexes of the events in its window. Windows slide: every matching event ends one window of `timespan`.
 * Supports event_count, value_count (one field) and temporal (no condition: every referenced rule must match).
 */
export function correlationAlerts(correlation: YamlMap, rulesByName: Map<string, YamlMap>, events: SigmaEvent[]): Set<number>[] {
  const c = correlation["correlation"];
  if (!isMap(c)) throw new SubsetError("correlation section missing");
  const type = c["type"];
  const names = c["rules"];
  const groupBy = c["group-by"];
  const span = /^(\d+)([smhd])$/.exec(String(c["timespan"]));
  if (!Array.isArray(names) || names.length === 0 || !Array.isArray(groupBy) || groupBy.length === 0 || !span) throw new SubsetError("correlation needs rules, group-by and a timespan like 1h");
  for (const k of Object.keys(c)) if (!["type", "rules", "group-by", "timespan", "condition"].includes(k)) throw new SubsetError(`unsupported correlation key ${k}`);
  const width = Number(span[1]) * (SPAN_UNITS[span[2] as string] as number);
  const rules = names.map((n) => {
    const r = rulesByName.get(String(n));
    if (!r || r["correlation"] !== undefined) throw new SubsetError(`correlation rule ${String(n)} is not a base rule in this file`);
    return r;
  });
  const time = (e: SigmaEvent): number => {
    const t = e["@timestamp"];
    if (typeof t !== "number" || !Number.isFinite(t)) throw new SubsetError(`event without a numeric @timestamp: ${JSON.stringify(e)}`);
    return t;
  };
  const matched = events.map((e, i) => ({ i, t: time(e), e, by: rules.map((r) => ruleMatches(r, e)) })).filter((m) => m.by.includes(true));
  // Group-by values compare as case-insensitive text, as in the SQLite cross-check (TEXT COLLATE NOCASE columns), so
  // 9001 and "9001" are one group: the specification treats every value as a case-insensitive string.
  const key = (e: SigmaEvent): string | undefined => {
    const values = groupBy.map((f) => e[String(f)]);
    if (values.some((v) => typeof v === "object" && v !== null)) throw new SubsetError(`a group-by field holds a list or map: ${JSON.stringify(e)}`);
    return values.some((v) => v === undefined || v === null) ? undefined : JSON.stringify(values.map((v) => String(v).toLowerCase()));
  };

  let measure: (window: typeof matched) => number;
  let condition: [string, number][];
  const cond = c["condition"];
  if (type === "temporal") {
    if (cond !== undefined) throw new SubsetError("a temporal condition is not supported");
    measure = (w) => rules.filter((_, r) => w.some((m) => m.by[r])).length;
    condition = [["gte", rules.length]];
  } else if (type === "event_count" || type === "value_count") {
    if (!isMap(cond)) throw new SubsetError(`${type} needs a condition`);
    const field = cond["field"];
    if (type === "value_count" ? typeof field !== "string" : field !== undefined) throw new SubsetError(`${type} takes ${type === "value_count" ? "one field" : "no field"}`);
    condition = Object.entries(cond)
      .filter(([k]) => k !== "field")
      .map(([k, v]) => {
        if (!(k in COMPARE) || typeof v !== "number") throw new SubsetError(`bad correlation condition ${k}: ${String(v)}`);
        return [k, v];
      });
    if (condition.length === 0) throw new SubsetError("correlation condition has no comparison");
    measure =
      type === "event_count"
        ? (w) => w.length
        : (w) => new Set(w.map((m) => m.e[field as string]).filter((v) => v !== undefined && v !== null).map((v) => String(v).toLowerCase())).size;
  } else throw new SubsetError(`unsupported correlation type ${String(type)}`);

  const alerts: Set<number>[] = [];
  for (const anchor of matched) {
    const group = key(anchor.e);
    if (group === undefined) continue;
    const window = matched.filter((m) => key(m.e) === group && m.t <= anchor.t && m.t >= anchor.t - width);
    const value = measure(window);
    if (condition.every(([op, n]) => (COMPARE[op] as (a: number, b: number) => boolean)(value, n))) alerts.push(new Set(window.map((m) => m.i)));
  }
  return alerts;
}
