/**
 * Reads the committed Splunk (.spl) and ES|QL (.esql) conversions of the Sigma rules in detections/ and checks what they
 * say, not only that they are current: each correlation's aggregation, field, group-by, threshold and window must be
 * the rule's, and each query must return the rule's positive examples and none of its negative ones.
 *
 * The queries run on small models of the two languages, written from their references, not in Splunk or
 * Elasticsearch. The SPL model compares values case-insensitively, lets NOT pass an event without the field and refuses
 * a query that tests a JSON array by its plain name; the ES|QL model compares case-sensitively, propagates null, reads
 * a backslash in like as an escape and sees an array as one multivalued field. Both fail closed: a construct outside
 * the subset the converter writes throws, so the test fails instead of skipping it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { correlationAlerts, isMap, parseYamlDocuments, type SigmaEvent, type Yaml, type YamlMap } from "./sigma-subset.js";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const RULE_DIRS = ["detections/github-audit-log", "detections/sigma"];
const RULES = RULE_DIRS.flatMap((d) =>
  readdirSync(join(ROOT, d))
    .filter((f) => f.endsWith(".yml"))
    .map((f) => join(ROOT, d, f)),
);

class ModelError extends Error {}

/** The queries of a reference file, by the name of the Sigma rule on the line above each. */
function queriesOf(text: string): Map<string, string> {
  const out = new Map<string, string>();
  let name: string | undefined;
  let lines: string[] = [];
  const flush = () => {
    if (name !== undefined) out.set(name, lines.join("\n").trim());
  };
  for (const line of text.split("\n")) {
    const m = /^# (ws_[a-z0-9_]+): .* \([a-z ]+\)$/.exec(line);
    if (m) {
      flush();
      name = m[1] as string;
      lines = [];
    } else if (name !== undefined) lines.push(line);
  }
  flush();
  return out;
}

type Value = string | number | boolean | null;
type Pred = (e: SigmaEvent) => boolean;
type Windowing = { kind: "sliding"; width: number } | { kind: "buckets"; width: number; offsets: number[] };
interface Correlation {
  aggregation: "distinct" | "count";
  field: string | undefined;
  by: string[];
  threshold: number;
  windowing: Windowing;
  /** For a temporal correlation: the event type each base query assigns. */
  typed: [string, Pred][] | undefined;
  /** How each backend groups: Splunk drops an event without a by field, ES|QL groups it under null. */
  nullGroups: boolean;
  /** Splunk's final `dedup` of the group-by fields: one result per group, the first event that completes its burst. */
  dedup: boolean;
}
interface Query {
  match: Pred;
  correlation: Correlation | undefined;
}

const fieldValue = (e: SigmaEvent, field: string): Value => {
  const v = e[field];
  if (v === undefined || v === null) return null;
  if (typeof v === "object") throw new ModelError(`field ${field} holds a list or map, which the models do not cover`);
  return v as Value;
};

/**
 * Splunk's `field=*`. A JSON array is not a field of that name in Splunk: its values sit at the spath location path
 * `field{}` (the spath reference), and whether automatic JSON extraction keeps the braces depends on how the event is
 * indexed, so a query that tests an array field by its plain name may never match. The model refuses it.
 */
const splPresent = (e: SigmaEvent, field: string): boolean => {
  const v = e[field];
  if (v === null) throw new ModelError(`${field} is a JSON null, whose extraction in Splunk the model does not cover`);
  if (typeof v === "object") throw new ModelError(`Splunk names the array or map ${field} as ${field}{} or ${field}.<key>, not ${field}: the query tests a field Splunk may not have`);
  return v !== undefined;
};

/**
 * ES|QL's `is not null`. A JSON array is one multivalued column of the field's own name (the ES|QL multivalued fields
 * reference), and null values in it are not stored, so an empty array, or one of nulls only, is null. A map is no
 * column at all: its keys are columns of their own.
 */
const esqlPresent = (e: SigmaEvent, field: string): boolean => {
  const v = e[field];
  if (Array.isArray(v)) return v.some((x) => x !== null);
  if (typeof v === "object" && v !== null) throw new ModelError(`${field} holds a map, which ES|QL reads as one column per key`);
  return v !== undefined && v !== null;
};

const wildcard = (pattern: string, flags: string, escapes: boolean): RegExp => {
  let body = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i] as string;
    if (escapes && c === "\\") {
      const n = pattern[++i];
      if (n === undefined) throw new ModelError(`like pattern ends in an escape: ${pattern}`);
      body += n.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
    } else if (c === "*") body += ".*";
    else if (c === "?" && escapes) body += ".";
    else body += c.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
  }
  return new RegExp(`^${body}$`, flags);
};

/** A double-quoted literal: \\ and \" are the only escapes the converters write. */
function unquote(literal: string): string {
  let out = "";
  for (let i = 1; i < literal.length - 1; i++) {
    const c = literal[i] as string;
    if (c === "\\") {
      const n = literal[++i];
      if (n !== "\\" && n !== '"') throw new ModelError(`unexpected escape \\${n} in ${literal}`);
      out += n;
    } else out += c;
  }
  return out;
}

const DURATION: Record<string, number> = { s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 };
const duration = (n: string, unit: string): number => {
  const ms = DURATION[unit === "minutes" || unit === "minute" ? "m" : unit === "hours" || unit === "hour" ? "h" : unit === "days" || unit === "day" ? "d" : unit === "seconds" || unit === "second" ? "s" : unit];
  if (ms === undefined) throw new ModelError(`unknown time unit ${unit}`);
  return Number(n) * ms;
};

// --- Splunk SPL -------------------------------------------------------------------------------------------------

/** A search-command expression: field=value, field IN (...), NOT, OR, AND and juxtaposition (AND), parentheses. */
function splSearch(text: string): Pred {
  const tokens = text.match(/\(|\)|\w+ IN \((?:"(?:[^"\\]|\\.)*"(?:, )?)+\)|\w+=(?:"(?:[^"\\]|\\.)*"|[^\s()]+)|\S+/g) ?? [];
  let at = 0;
  const peek = () => tokens[at];
  const take = () => {
    const t = tokens[at++];
    if (t === undefined) throw new ModelError(`search ends early: ${text}`);
    return t;
  };
  const term = (field: string, raw: string): Pred => {
    if (raw === "*") return (e) => splPresent(e, field);
    const value = raw.startsWith('"') ? unquote(raw) : raw;
    if (!raw.startsWith('"') && /["\\]/.test(raw)) throw new ModelError(`unquoted value with quotes or escapes: ${raw}`);
    const re = wildcard(value, "is", false);
    return (e) => {
      const v = fieldValue(e, field);
      return v !== null && re.test(String(v));
    };
  };
  // Splunk evaluates NOT first, then OR, then AND (the search command's documented order).
  const and = (): Pred => {
    const parts = [or()];
    while (peek() !== undefined && peek() !== ")") {
      if (peek() === "AND") take();
      parts.push(or());
    }
    return (e) => parts.every((p) => p(e));
  };
  const or = (): Pred => {
    const parts = [not()];
    while (peek() === "OR") {
      take();
      parts.push(not());
    }
    return (e) => parts.some((p) => p(e));
  };
  const not = (): Pred => {
    if (peek() === "NOT") {
      take();
      const p = not();
      return (e) => !p(e);
    }
    const t = take();
    if (t === "(") {
      const p = and();
      if (take() !== ")") throw new ModelError(`unbalanced parentheses: ${text}`);
      return p;
    }
    const inList = /^(\w+) IN \((.*)\)$/.exec(t);
    if (inList) {
      const values = (inList[2] as string).match(/"(?:[^"\\]|\\.)*"/g) ?? [];
      const preds = values.map((v) => term(inList[1] as string, v));
      return (e) => preds.some((p) => p(e));
    }
    const eq = /^(\w+)=(.+)$/.exec(t);
    if (eq) return term(eq[1] as string, eq[2] as string);
    throw new ModelError(`unsupported search term ${t}`);
  };
  const p = and();
  if (at !== tokens.length) throw new ModelError(`unread search after ${tokens[at]}: ${text}`);
  return p;
}

function splQuery(query: string): Query {
  const lines = query.split("\n").filter((l) => l.trim() !== "");
  let match: Pred;
  let typed: [string, Pred][] | undefined;
  let i: number;
  if (lines[0] === "| multisearch") {
    typed = [];
    for (i = 1; i < lines.length && (lines[i] as string).startsWith("[ search "); i++) {
      const m = /^\[ search (.+) \| eval event_type="(\w+)" \]$/.exec(lines[i] as string);
      if (!m) throw new ModelError(`unsupported multisearch arm: ${lines[i]}`);
      typed.push([m[2] as string, splSearch(m[1] as string)]);
    }
    const arms = typed;
    match = (e) => arms.some(([, p]) => p(e));
  } else {
    match = splSearch(lines[0] as string);
    i = 1;
  }
  const rest = lines.slice(i);
  if (rest.length === 0 && typed === undefined) return { match, correlation: undefined };
  const stage = rest.join("\n");
  const sliding = /^\| sort 0 _time\n\| streamstats time_window=(\d+)([smhd]) (dc|count)\((\w*)\) as (\w+) by ([\w ]+)\n\| search (\w+) >= (\d+)(?:\n\| dedup ([\w ]+))?$/.exec(stage);
  const fixed = /^\| bin _time span=(\d+)([smhd])\n\| stats (dc|count)\((\w*)\) as (\w+) by _time ([\w ]+)\n\| search (\w+) >= (\d+)$/.exec(stage);
  const m = sliding ?? fixed;
  if (!m || m[5] !== m[7]) throw new ModelError(`unsupported Splunk correlation stage:\n${stage}`);
  // dedup keeps the first result for each value of its fields; the model covers only a dedup of the group-by fields.
  if (m[9] !== undefined && m[9] !== m[6]) throw new ModelError(`dedup ${m[9]} is not the group-by ${m[6]}`);
  const width = duration(m[1] as string, m[2] as string);
  return {
    match,
    correlation: {
      aggregation: m[3] === "dc" ? "distinct" : "count",
      field: m[4] === "" ? undefined : m[4],
      by: (m[6] as string).split(" "),
      threshold: Number(m[8]),
      windowing: sliding ? { kind: "sliding", width } : { kind: "buckets", width, offsets: [0] },
      typed,
      nullGroups: false,
      dedup: m[9] !== undefined,
    },
  };
}

// --- ES|QL ------------------------------------------------------------------------------------------------------

type Expr = (e: SigmaEvent) => Value;

/** The where-clause subset convert_rules.py writes, evaluated with ES|QL's null propagation and case-sensitivity. */
function esqlExpr(text: string): Expr {
  const tokens = text.match(/"(?:[^"\\]|\\.)*"|==|[(),]|-?\d+\b|[A-Za-z_@][\w@.]*/g) ?? [];
  if (tokens.join("").replace(/\s/g, "") !== text.replace(/\s/g, "")) throw new ModelError(`unreadable ES|QL: ${text}`);
  let at = 0;
  const peek = () => tokens[at];
  const take = (want?: string) => {
    const t = tokens[at++];
    if (t === undefined || (want !== undefined && t !== want)) throw new ModelError(`expected ${want ?? "a token"}, found ${t}: ${text}`);
    return t;
  };
  const literal = (): Value => {
    const t = take();
    if (t.startsWith('"')) return unquote(t);
    if (/^-?\d+$/.test(t)) return Number(t);
    if (t === "true" || t === "false") return t === "true";
    throw new ModelError(`expected a literal, found ${t}`);
  };
  const value = (): Expr => {
    const t = take();
    if (t === "to_lower") {
      take("(");
      const inner = value();
      take(")");
      return (e) => {
        const v = inner(e);
        if (v === null) return null;
        if (typeof v !== "string") throw new ModelError(`to_lower of a non-string ${String(v)}`);
        return v.toLowerCase();
      };
    }
    if (!/^[A-Za-z_@][\w@.]*$/.test(t)) throw new ModelError(`expected a field, found ${t}`);
    return (e) => fieldValue(e, t);
  };
  const same = (a: Value, b: Value): boolean => {
    if (typeof a !== typeof b) throw new ModelError(`comparison of ${typeof a} with ${typeof b}`);
    return a === b;
  };
  const or = (): Expr => {
    const parts = [and()];
    while (peek() === "or") {
      take();
      parts.push(and());
    }
    return (e) => {
      const vs = parts.map((p) => p(e));
      return vs.includes(true) ? true : vs.includes(null) ? null : false;
    };
  };
  const and = (): Expr => {
    const parts = [not()];
    while (peek() === "and") {
      take();
      parts.push(not());
    }
    return (e) => {
      const vs = parts.map((p) => p(e));
      return vs.includes(false) ? false : vs.includes(null) ? null : true;
    };
  };
  const not = (): Expr => {
    if (peek() === "not") {
      take();
      const p = not();
      return (e) => {
        const v = p(e);
        return v === null ? null : !v;
      };
    }
    return primary();
  };
  const primary = (): Expr => {
    if (peek() === "(") {
      take();
      const p = or();
      take(")");
      return p;
    }
    if (peek() === "coalesce") {
      take();
      take("(");
      const p = or();
      take(",");
      const fallback = literal();
      take(")");
      return (e) => p(e) ?? fallback;
    }
    if (peek() === "starts_with" || peek() === "ends_with") {
      const fn = take();
      take("(");
      const v = value();
      take(",");
      const lit = literal();
      take(")");
      if (typeof lit !== "string") throw new ModelError(`${fn} with a non-string`);
      return (e) => {
        const s = v(e);
        if (s === null) return null;
        if (typeof s !== "string") throw new ModelError(`${fn} of a non-string`);
        return fn === "starts_with" ? s.startsWith(lit) : s.endsWith(lit);
      };
    }
    if (tokens[at + 1] === "is") {
      const field = take();
      take("is");
      const negated = peek() === "not";
      if (negated) take();
      take("null");
      return (e) => esqlPresent(e, field) === negated;
    }
    const lhs = value();
    const op = take();
    if (op === "==") {
      const lit = literal();
      return (e) => {
        const v = lhs(e);
        return v === null ? null : same(v, lit);
      };
    }
    if (op === "in") {
      take("(");
      const lits = [literal()];
      while (peek() === ",") {
        take();
        lits.push(literal());
      }
      take(")");
      return (e) => {
        const v = lhs(e);
        return v === null ? null : lits.some((l) => same(v, l));
      };
    }
    if (op === "like") {
      const lit = literal();
      if (typeof lit !== "string") throw new ModelError("like with a non-string");
      const re = wildcard(lit, "s", true);
      return (e) => {
        const v = lhs(e);
        if (v === null) return null;
        if (typeof v !== "string") throw new ModelError("like on a non-string");
        return re.test(v);
      };
    }
    throw new ModelError(`unsupported ES|QL operator ${op}: ${text}`);
  };
  const p = or();
  if (at !== tokens.length) throw new ModelError(`unread ES|QL after ${tokens[at]}: ${text}`);
  return p;
}

const truthy =
  (x: Expr): Pred =>
  (e) =>
    x(e) === true;

function esqlQuery(query: string): Query {
  const lines = query.split("\n");
  const head = /^from \* metadata _id, _index, _version \| where (.+)$/.exec(lines[0] as string);
  if (!head) throw new ModelError(`unsupported ES|QL source: ${lines[0]}`);
  const match = truthy(esqlExpr(head[1] as string));
  if (lines.length === 1) return { match, correlation: undefined };
  let i = 1;
  let typed: [string, Pred][] | undefined;
  const caseLine = /^\| eval event_type=case\((.+)\)$/.exec(lines[i] as string);
  if (caseLine) {
    // case(cond, "name", cond, "name"): split on the commas between arms, outside parentheses and quotes.
    const parts: string[] = [];
    let depth = 0;
    let cur = "";
    for (const tok of (caseLine[1] as string).match(/"(?:[^"\\]|\\.)*"|[(),]|[^"(),]+/g) ?? []) {
      if (tok === "(") depth++;
      if (tok === ")") depth--;
      if (tok === "," && depth === 0) {
        parts.push(cur.trim());
        cur = "";
      } else cur += tok;
    }
    parts.push(cur.trim());
    if (parts.length % 2 !== 0) throw new ModelError(`unsupported case(): ${caseLine[1]}`);
    typed = [];
    for (let k = 0; k < parts.length; k += 2) typed.push([unquote(parts[k + 1] as string), truthy(esqlExpr(parts[k] as string))]);
    i++;
  }
  const stage = lines.slice(i).join("\n");
  const grids = /^\| eval timebucket=mv_append\(date_trunc\((\d+) (\w+), @timestamp\), date_trunc\((\d+) (\w+), @timestamp \+ (\d+) (\w+)\) - (\d+) (\w+)\) \| stats (\w+)=(count_distinct|count)\((\w*)\) by timebucket, ([\w, ]+)\n\| where (\w+) >= (\d+)$/.exec(stage);
  const single = /^\| eval timebucket=date_trunc\((\d+) ?(\w+), @timestamp\) \| stats (\w+)=(count_distinct|count)\((\w*)\) by timebucket, ([\w, ]+)\n\| where (\w+) >= (\d+)$/.exec(stage);
  let windowing: Windowing;
  let agg: string[];
  if (grids) {
    const width = duration(grids[1] as string, grids[2] as string);
    const offset = duration(grids[5] as string, grids[6] as string);
    if (duration(grids[3] as string, grids[4] as string) !== width || duration(grids[7] as string, grids[8] as string) !== offset) throw new ModelError(`the two bucketings differ in width or offset: ${stage}`);
    windowing = { kind: "buckets", width, offsets: [0, offset] };
    agg = grids.slice(9);
  } else if (single) {
    windowing = { kind: "buckets", width: duration(single[1] as string, single[2] as string), offsets: [0] };
    agg = single.slice(3);
  } else throw new ModelError(`unsupported ES|QL correlation stage:\n${stage}`);
  const [name, fn, field, by, condName, threshold] = agg as [string, string, string, string, string, string];
  if (name !== condName) throw new ModelError(`the where tests ${condName}, not ${name}`);
  if (typed && field !== "event_type") throw new ModelError("a temporal correlation must count event_type");
  return {
    match,
    correlation: { aggregation: fn === "count_distinct" ? "distinct" : "count", field: field === "" ? undefined : field, by: by.split(", "), threshold: Number(threshold), windowing, typed, nullGroups: true, dedup: false },
  };
}

/** Runs a correlation query's model over a stream and returns, for each alert, the indexes of its events. */
function queryAlerts(q: Query, events: SigmaEvent[]): Set<number>[] {
  const c = q.correlation;
  if (!c) throw new ModelError("not a correlation");
  const time = (e: SigmaEvent): number => {
    const t = e["@timestamp"];
    if (typeof t !== "number") throw new ModelError(`event without a numeric @timestamp: ${JSON.stringify(e)}`);
    return t;
  };
  const rows = events
    .map((e, i) => ({ e, i, t: time(e), type: c.typed ? c.typed.find(([, p]) => p(e))?.[0] : undefined }))
    .filter((r) => q.match(r.e))
    .sort((a, b) => a.t - b.t);
  const group = (e: SigmaEvent): string | undefined => {
    const values = c.by.map((f) => fieldValue(e, f));
    return !c.nullGroups && values.includes(null) ? undefined : JSON.stringify(values);
  };
  const measure = (w: typeof rows): number => {
    if (c.aggregation === "count") return w.length;
    const values = w.map((r) => (c.typed ? (r.type ?? null) : fieldValue(r.e, c.field as string))).filter((v) => v !== null);
    return new Set(values.map((v) => JSON.stringify(v))).size;
  };
  const alerts: Set<number>[] = [];
  if (c.windowing.kind === "sliding") {
    const width = c.windowing.width;
    const reported = new Set<string>();
    for (const r of rows) {
      const g = group(r.e);
      if (g === undefined || (c.dedup && reported.has(g))) continue;
      const w = rows.filter((o) => group(o.e) === g && o.t <= r.t && o.t >= r.t - width);
      if (measure(w) < c.threshold) continue;
      reported.add(g);
      alerts.push(new Set(w.map((o) => o.i)));
    }
  } else {
    if (c.dedup) throw new ModelError("dedup is modelled only after streamstats");
    const { width, offsets } = c.windowing;
    const buckets = new Map<string, typeof rows>();
    for (const r of rows) {
      const g = group(r.e);
      if (g === undefined) continue;
      for (const off of offsets) {
        const key = `${off}|${Math.floor((r.t + off) / width)}|${g}`;
        buckets.set(key, [...(buckets.get(key) ?? []), r]);
      }
    }
    for (const w of buckets.values()) if (measure(w) >= c.threshold) alerts.push(new Set(w.map((o) => o.i)));
  }
  return alerts;
}

const BACKENDS = [
  ["spl", splQuery],
  ["esql", esqlQuery],
] as const;

interface Loaded {
  file: string;
  docs: YamlMap[];
  byName: Map<string, YamlMap>;
  alerting: YamlMap[];
  queries: Record<"spl" | "esql", Map<string, string>>;
}

const load = (file: string): Loaded => {
  const docs = parseYamlDocuments(readFileSync(file, "utf8"));
  const referenced = new Set(docs.flatMap((d) => (isMap(d["correlation"]) && Array.isArray(d["correlation"]["rules"]) ? d["correlation"]["rules"].map(String) : [])));
  return {
    file,
    docs,
    byName: new Map(docs.map((d) => [String(d["name"]), d])),
    alerting: docs.filter((d) => !referenced.has(String(d["name"]))),
    queries: { spl: queriesOf(readFileSync(file.replace(/\.yml$/, ".spl"), "utf8")), esql: queriesOf(readFileSync(file.replace(/\.yml$/, ".esql"), "utf8")) },
  };
};
const LOADED = RULES.map(load);
const eventsOf = (block: Yaml | undefined): SigmaEvent[] => (typeof block === "string" ? block.split("\n").filter((l) => l.trim() !== "").map((l) => JSON.parse(l) as SigmaEvent) : []);
const examples = (doc: YamlMap): { pos: SigmaEvent[]; neg: SigmaEvent[] } => {
  const ex = doc["examples"];
  return { pos: eventsOf(isMap(ex) ? ex["positive"] : undefined), neg: eventsOf(isMap(ex) ? ex["negative"] : undefined) };
};
const queryFor = (l: Loaded, name: string, backend: "spl" | "esql"): Query => {
  const text = l.queries[backend].get(name);
  if (text === undefined) throw new ModelError(`${backend} reference has no query for ${name}`);
  return backend === "spl" ? splQuery(text) : esqlQuery(text);
};

test("the SPL and ES|QL models read ==, like, not and NOT as their languages do", () => {
  const esql = (where: string, e: SigmaEvent) => esqlQuery(`from * metadata _id, _index, _version | where ${where}`).match(e);
  // ES|QL compares case-sensitively and drops an event whose condition is null.
  assert.ok(!esql('runner_name == "SHA1HULUD"', { runner_name: "sha1hulud" }));
  assert.ok(esql('to_lower(runner_name) == "sha1hulud"', { runner_name: "SHA1HULUD" }));
  assert.ok(!esql('not actor == "bot"', { action: "x" }));
  assert.ok(esql('not coalesce(actor == "bot", false)', { action: "x" }));
  // like reads a backslash as its escape character: a literal backslash needs two in the pattern.
  const dir = { d: "C:\\Users\\dev\\app\\node_modules\\pkg" };
  // pySigma writes "*\\node_modules\\*": like then reads \n and \* as escapes, a literal "n" and a literal "*".
  assert.ok(!esql(String.raw`d like "*\\node_modules\\*"`, dir));
  assert.ok(esql(String.raw`d like "*\\\\node_modules\\\\*"`, dir));
  // Splunk compares values case-insensitively, lets NOT pass an event without the field, and reads NOT, OR, AND in
  // that order.
  const spl = (search: string, e: SigmaEvent) => splQuery(search).match(e);
  assert.ok(spl('runner_name="SHA1HULUD"', { runner_name: "sha1hulud" }));
  assert.ok(spl('NOT actor="bot"', { action: "x" }));
  assert.ok(spl('a="1" b="1" OR c="1"', { a: 1, c: 1 }) && !spl('a="1" b="1" OR c="1"', { b: 1, c: 1 }));
  assert.ok(spl('p=*', { p: "token" }) && !spl("p=*", { q: "token" }));
  // A JSON array: Splunk puts its values at secrets_passed{}, so secrets_passed=* may find no field; ES|QL reads one
  // multivalued column, null when the array holds no value.
  assert.throws(() => spl("secrets_passed=*", { secrets_passed: ["NPM_TOKEN"] }), /secrets_passed\{\}/);
  assert.ok(esql("secrets_passed is not null", { secrets_passed: ["NPM_TOKEN"] }));
  assert.ok(!esql("secrets_passed is not null", { secrets_passed: [] }) && esql("secrets_passed is null", { secrets_passed: [null] }));
  assert.throws(() => spl('a="x" | where b=1', { a: "x" }), ModelError);
});

test("each committed correlation counts what its rule counts: aggregation, field, group-by, threshold and window", () => {
  let seen = 0;
  for (const l of LOADED) {
    for (const doc of l.alerting) {
      const c = doc["correlation"];
      if (!isMap(c)) continue;
      const span = /^(\d+)([smhd])$/.exec(String(c["timespan"]));
      assert.ok(span, `${String(doc["name"])}: timespan`);
      const width = duration(span[1] as string, span[2] as string);
      const cond = isMap(c["condition"]) ? c["condition"] : {};
      const expected = {
        aggregation: c["type"] === "event_count" ? "count" : "distinct",
        field: c["type"] === "value_count" ? String(cond["field"]) : c["type"] === "temporal" ? "event_type" : undefined,
        by: (c["group-by"] as Yaml[]).map(String),
        threshold: c["type"] === "temporal" ? (c["rules"] as Yaml[]).length : Number(cond["gte"]),
      };
      if (c["type"] !== "temporal") assert.deepEqual(Object.keys(cond).sort(), (c["type"] === "value_count" ? ["field", "gte"] : ["gte"]).sort(), "only gte conditions are modelled");
      for (const [backend] of BACKENDS) {
        const q = queryFor(l, String(doc["name"]), backend).correlation;
        assert.ok(q, `${backend} ${String(doc["name"])} has no correlation stage`);
        const got = { aggregation: q.aggregation, field: q.typed ? "event_type" : q.field, by: q.by, threshold: q.threshold, dedup: q.dedup };
        // Splunk keeps one result per group with a dedup of the group-by fields; ES|QL's stats already gives one row
        // per group and bucket.
        assert.deepEqual(got, { ...expected, dedup: backend === "spl" }, `${backend} ${String(doc["name"])}`);
        // Splunk can slide; ES|QL cannot, so it uses buckets of the timespan in two sets offset by half of it.
        const want: Windowing = backend === "spl" ? { kind: "sliding", width } : { kind: "buckets", width, offsets: [0, width / 2] };
        assert.deepEqual(q.windowing, want, `${backend} ${String(doc["name"])} window`);
        if (q.typed) assert.deepEqual(q.typed.map(([n]) => n).sort(), (c["rules"] as Yaml[]).map(String).sort(), `${backend} ${String(doc["name"])} event types`);
        seen++;
      }
    }
  }
  assert.equal(seen, 4, "WS-AL-001 and WS-AL-004 each hold one correlation, in two backends");
});

test("every committed query returns its rule's positive examples and none of its negative ones", () => {
  let checked = 0;
  for (const l of LOADED) {
    for (const doc of l.alerting) {
      const name = String(doc["name"]);
      const { pos, neg } = examples(doc);
      assert.ok(pos.length > 0 && neg.length > 0, name);
      for (const [backend] of BACKENDS) {
        const q = queryFor(l, name, backend);
        if (q.correlation) {
          const hit = new Set(queryAlerts(q, pos).flatMap((a) => [...a]));
          for (const [i, e] of pos.entries()) assert.ok(hit.has(i), `${backend} ${name} misses positive ${JSON.stringify(e)}`);
          assert.deepEqual(queryAlerts(q, neg), [], `${backend} ${name} alerts on its negative examples`);
        } else {
          for (const e of pos) assert.ok(q.match(e), `${backend} ${name} misses positive ${JSON.stringify(e)}`);
          for (const e of neg) assert.ok(!q.match(e), `${backend} ${name} matches negative ${JSON.stringify(e)}`);
        }
        checked++;
      }
    }
  }
  assert.ok(checked >= 18, `${checked} queries checked`);
});

test("a burst across an hour boundary alerts in the committed queries as in the Sigma rule", () => {
  const hour = Date.UTC(2026, 9, 14, 11);
  const al4 = LOADED.find((l) => l.byName.has("ws_al_004_new_workflow_run_deleted_by_token")) as Loaded;
  const al1 = LOADED.find((l) => l.byName.has("ws_al_001_mass_visibility_flip")) as Loaded;
  const deletion = al4.byName.get("ws_al_004_new_workflow_run_deleted_by_token") as YamlMap;
  const flip = al1.byName.get("ws_al_001_mass_visibility_flip") as YamlMap;
  const at = (e: SigmaEvent, t: number): SigmaEvent => ({ ...e, "@timestamp": t });
  const minutes = (n: number) => n * 60_000;

  // The worm's first run at 10:57:30 and its deletion five minutes later, at 11:02:30.
  const [run, del] = examples(deletion).pos as [SigmaEvent, SigmaEvent];
  const straddle = [at(run, hour - minutes(2.5)), at(del, hour + minutes(2.5))];
  // Three repositories made public at 10:58, 11:00 and 11:02.
  const flips = examples(flip).pos.map((e, k) => at(e, hour + minutes(2 * k - 2)));
  for (const [doc, l, events] of [
    [deletion, al4, straddle],
    [flip, al1, flips],
  ] as const) {
    const name = String(doc["name"]);
    assert.equal(correlationAlerts(doc, l.byName, events).length > 0, true, `the Sigma evaluator alerts for ${name}`);
    for (const [backend] of BACKENDS) assert.ok(queryAlerts(queryFor(l, name, backend), events).length > 0, `${backend} ${name} misses the burst across 11:00`);
  }

  // What ES|QL still misses, pinned so that the README's account of it stays true: a 40-minute burst that each set of
  // buckets splits (10:25, 10:45, 11:05 against boundaries at 10:30 and 11:00). Splunk and the evaluator alert.
  const split = examples(flip).pos.map((e, k) => at(e, hour - minutes(35) + minutes(20 * k)));
  assert.ok(correlationAlerts(flip, al1.byName, split).length > 0);
  assert.ok(queryAlerts(queryFor(al1, "ws_al_001_mass_visibility_flip", "spl"), split).length > 0);
  assert.equal(queryAlerts(queryFor(al1, "ws_al_001_mass_visibility_flip", "esql"), split).length, 0);

  // The fixed clock-hour form the backends write without post-processing misses the burst across 11:00.
  const fixed = splQuery('action="repo.access"\n| bin _time span=1h\n| stats dc(repo) as value_count by _time actor\n| search value_count >= 3');
  assert.equal(queryAlerts(fixed, flips).length, 0);
});

test("a Splunk correlation raises one result per group, not one per event that completes the burst", () => {
  const al1 = LOADED.find((l) => l.byName.has("ws_al_001_mass_visibility_flip")) as Loaded;
  const flip = al1.byName.get("ws_al_001_mass_visibility_flip") as YamlMap;
  const [first] = examples(flip).pos as [SigmaEvent];
  // Five repositories made public by one actor, two minutes apart, from 13:20 past the hour: the third, fourth and
  // fifth each complete a burst of three.
  const burst = [0, 1, 2, 3, 4].map((k) => ({ ...first, repo: `example-org/repo-${k}`, "@timestamp": (first["@timestamp"] as number) + k * 120_000 }));
  const spl = queryFor(al1, "ws_al_001_mass_visibility_flip", "spl");
  assert.equal(correlationAlerts(flip, al1.byName, burst).length, 3);
  assert.equal(queryAlerts(spl, burst).length, 1);
  // A second actor's burst in the same hour is a result of its own.
  assert.equal(queryAlerts(spl, [...burst, ...burst.map((e) => ({ ...e, actor: "second-victim" }))]).length, 2);
  // ES|QL raises one row for each set of buckets that holds the whole burst: both, here. The README's throttling on the
  // group-by fields is what makes that one alert.
  assert.equal(queryAlerts(queryFor(al1, "ws_al_001_mass_visibility_flip", "esql"), burst).length, 2);
});
