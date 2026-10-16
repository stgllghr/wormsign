import type { Finding, Severity } from "../types.js";
import { keyDigest, makeFinding } from "../types.js";
import { notChecked } from "./context.js";
import type { ScanContext } from "./context.js";

export const WORKFLOW_PATH = /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/;

/*
 * Line-based analysis of a workflow file. This is deliberately not a YAML
 * parser: it tracks only indentation, comments, quotes and block scalars, which
 * is enough to find keys, their children and the shell text of `run:` steps. It
 * cannot follow anchors, reusable workflows, composite actions or expression
 * logic. Inputs are attacker-controlled, so every regex here runs in linear time
 * (no two adjacent quantifiers can match the same characters) and the
 * "children of" walks skip blank, comment and script lines up front.
 *
 * Not modelled, so reported as not checked (WS-SC-900, high; unmodelled()): a workflow written in flow (JSON) form, a
 * flow value for `jobs:`, `steps:` or a job, a step written as a flow mapping (`- {run: ...}`), and YAML aliases and
 * merge keys (`*x`, `<<:`), which can bring in steps or a runner from elsewhere in the file. GitHub accepts all of
 * these, and the checks below would read them only in part.
 *
 * A `${{ }}` expression runs from its `${{` to the first `}}` outside a string literal, as GitHub reads it, on its own
 * line or a later one (expressionSpans()). The checks read each line as written and as YAML reads it (quotes removed,
 * `''` and escapes decoded). Where an expression ends on a later line, they read the line it starts on joined to the
 * lines up to that one, a line break read as a space, as written with comments (a wrong guess of where a comment
 * starts must not hide part of one) and as YAML reads them, and report at the line it starts on, once. Inside an
 * expression, property paths are matched as GitHub's lexer reads them, in any case and without the whitespace around
 * `.`, `[` and `]` (readPaths()). Not read, so reported as not checked (WS-SC-900, high; unreadExpressions()): a `${{`
 * with no `}}` within MAX_EXPRESSION_LINES (50) lines as YAML reads them (not one in a comment, which GitHub ignores),
 * and an expression a YAML escape wrote part of (`\x24{{`, `\x73ecrets.T`, an escaped line break inside one or after
 * `$` or `${`), since the checks read expressions as written. Also not checked (lineBreaks()): a file holding U+0085,
 * U+2028 or U+2029, which YamlDotNet (the YAML library actions/runner's workflow parser reads with) takes for a line
 * break, and this reader, like YAML 1.2, does not.
 *
 * Known misses: a runner chosen by an expression other than a matrix value, or
 * by `group:` alone (larger GitHub-hosted runners use groups too); a secret that
 * reaches a sink through a shell variable set on an earlier line (`T="${{ secrets.T }}"`, then `curl -d "$T"`), a
 * script file, an action input or an `env: {}` flow mapping; a checkout of a SHA fetched at run time, or passed through
 * a step output (`steps.x.outputs.sha`), a file or `$GITHUB_ENV`, or from an `issue_comment` workflow; a head ref bound
 * in env: on the line below its name or by a computed value (`fromJSON(...)`), or held in an env: variable that a git
 * command other than fetch, checkout, switch or reset uses (headEnvNames()); pull request code read with `git show <ref>:<file>` and run, or checked out
 * through a git alias set in a config file; a YAML escape in a trigger, a key or a runner label (`"self-\x68osted"`),
 * which only the per-line checks read decoded; an `if:` condition written without `${{ }}` and split across lines,
 * read a line at a time; a command split across lines (a folded `>` scalar, a
 * `\` continuation) or `gh --repo x pr checkout`; top-level keys not at column 0;
 * a flow collection whose continuation lines are not indented past its key
 * (`runs-on: [` with `self-hosted` below it at the same indent); an `env:` value
 * on the line below its name. Known false positive: every word in a wrapped or
 * one-line `on:` flow mapping counts as an event, filter values included
 * (`on: {push: {branches: [discussion]}}`).
 */

interface Line {
  n: number;
  indent: number;
  /** The line without indentation. A trailing YAML comment is removed, except inside a block scalar. */
  text: string;
  /** The line without indentation, its comment included. */
  raw: string;
  /** The line as YAML reads it (see Value), outside block scalar content, where it is the line as written. */
  value?: string;
  /** Positions in `value` that a YAML escape wrote (see Value). */
  escaped?: ReadonlySet<number>;
  /** Set when the line ends in an escaped line break (see Value). */
  joins?: true;
  /**
   * Key owning the scalar this line is content of ("run" for a script): a block scalar, where `#` is content and Actions
   * expands `${{ }}` even in shell comments, or the continuation of a multi-line plain scalar.
   */
  block?: string;
  /**
   * Set when the line may be YAML structure after all, so it is also read as YAML: a plain scalar's continuation (the
   * scanner's guess), or content of a block whose header may have been text inside a quoted scalar.
   */
  unsure?: true;
  /** Job id under top-level `jobs:`, or "" outside a job. */
  job: string;
  /** The `key: value` this line starts, if any (never inside a block scalar, unless unsure). */
  entry?: { key: string; value: string };
}

/** True for lines read as YAML structure: not scalar content, unless unsure. */
const isYaml = (l: Line) => l.block === undefined || l.unsure === true;

const ENTRY = /^(?:-[ \t]+)?(["']?)([\w.-]+)\1[ \t]*:(?![^ \t])/;
const BLOCK_INDICATOR = /(?:^|[ \t])[|>][-+1-9]{0,2}$/;
const DASH = /^-[ \t]+/;
/** A sequence item: `- x`, or a `-` alone with its node below it. */
const ITEM = /^-(?:[ \t]|$)/;
/** An anchor (`&a`) or tag (`!!str`): node properties, which may stand before a node or on a line of their own. */
const PROPERTY = /^[&!]/;

function entry(text: string): { key: string; value: string } | undefined {
  const m = ENTRY.exec(text);
  return m ? { key: m[2] as string, value: text.slice(m[0].length).trim() } : undefined;
}

/** True when the text is empty or holds only anchors and tags. */
const onlyProperties = (text: string) => text.split(/[ \t]+/).every((w) => w === "" || PROPERTY.test(w));

/** The key of a `key:` line whose value starts on a later line ("" for a `-` alone), else undefined. */
function openKey(text: string): string | undefined {
  const e = entry(text);
  if (e) return onlyProperties(e.value) ? e.key : undefined;
  return text === "-" ? "" : undefined;
}

/**
 * Where the scanner is on a line: where a node may start, inside a plain
 * (unquoted) scalar, or just after a quoted scalar or flow collection. Only a
 * node start lets a quote open a quoted scalar, as in YAML: `name: CI - '` is
 * the plain scalar "CI - '".
 */
type At = "node" | "plain" | "after";

/** What is still open at the end of a line: a quote, and the depth of `[`/`{` flow collections. */
interface Open {
  quote: string;
  depth: number;
  at: At;
}

const isSpace = (c: string | undefined) => c === " " || c === "\t";

/** A hex escape in a double-quoted scalar, after its backslash: `\x24`, `$`, `\U00000024`. */
const HEX_ESCAPE = /^(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})/;
/** What YAML's other escapes in a double-quoted scalar stand for (YAML 1.2, 5.7); any other character stands for itself. */
const NAMED_ESCAPES: Record<string, string> = { "0": "\0", a: "\x07", b: "\b", t: "\t", n: "\n", v: "\v", f: "\f", r: "\r", e: "\x1b", N: "\x85", _: "\xa0", L: "\u2028", P: "\u2029" };

/**
 * A line as YAML reads it, as far as a `${{ }}` expression is concerned (`value`): the line without its comment, the
 * quotes of a quoted scalar removed, `''` in a single-quoted scalar read as `'`, and a double-quoted scalar's escapes
 * decoded. `escaped` holds the positions in `value` an escape wrote, other than `\\`, `\"` and `\/` (characters an
 * expression gives no meaning). `joins` is set when the line ends in an escaped line break, which joins the next line
 * to this one with no space between them.
 */
interface Value {
  value: string;
  escaped?: Set<number>;
  joins: boolean;
}

/** Removes a trailing YAML comment, tracking the quotes and flow collections that make `#` content. */
function stripComment(s: string, open: Open): Open & Value & { text: string; mapping: boolean } {
  let { quote, depth, at } = open;
  let mapping = false;
  let escaped: Set<number> | undefined;
  let joins = false;
  // The value is copied in runs: `value`, then s.slice(from, i). Only a quote, an escape, an anchor or a tag ends a run.
  let value = "";
  let from = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i] as string;
    if (quote !== "") {
      if (c === "\\" && quote === '"') {
        value += s.slice(from, i);
        const next = s[i + 1];
        const hex = HEX_ESCAPE.exec(s.slice(i + 1, i + 10))?.[0];
        const code = hex === undefined ? NaN : parseInt(hex.slice(1), 16);
        // A code point past U+10FFFF is no character: such an escape stands for its letter, as an unknown one does.
        const decoded = code <= 0x10ffff ? String.fromCodePoint(code) : undefined;
        if (next === undefined) {
          joins = true;
        } else {
          if (decoded !== undefined || (next !== "\\" && next !== '"' && next !== "/")) (escaped ??= new Set()).add(value.length);
          value += decoded ?? NAMED_ESCAPES[next] ?? next;
          if (decoded !== undefined) i += (hex as string).length - 1;
        }
        i++;
        from = i + 1;
      } else if (c === quote && quote === "'" && s[i + 1] === "'") {
        // `''` is one quote.
        value += s.slice(from, i + 1);
        i++;
        from = i + 1;
      } else if (c === quote) {
        value += s.slice(from, i);
        from = i + 1;
        quote = "";
        at = "after";
      }
    } else if (c === "#" && (i === 0 || isSpace(s[i - 1]))) {
      return { text: s.slice(0, i), quote, depth, at, mapping, value: value + s.slice(from, i), joins, ...(escaped ? { escaped } : {}) };
    } else if (isSpace(c)) {
      // Separation: the state is unchanged.
    } else if (at === "node" && (c === '"' || c === "'")) {
      value += s.slice(from, i);
      from = i + 1;
      quote = c;
    } else if (at === "node" && (c === "&" || c === "!")) {
      // An anchor or tag; the node itself follows it.
      value += s.slice(from, i);
      while (i + 1 < s.length && !isSpace(s[i + 1])) i++;
      from = i + 1;
    } else if ((at === "node" || depth > 0) && (c === "[" || c === "{")) {
      depth++;
      at = "node";
    } else if (depth > 0 && (c === "]" || c === "}")) {
      depth--;
      at = "after";
    } else if (depth > 0 && c === ",") {
      at = "node";
    } else if (c === ":" && (isSpace(s[i + 1]) || i + 1 === s.length || at === "after")) {
      // `key: value`, or JSON-style `"key":value` right after a quoted key.
      mapping ||= depth === 0;
      at = "node";
    } else if (!(at === "node" && (c === "-" || c === "?") && (isSpace(s[i + 1]) || i + 1 === s.length))) {
      at = "plain";
    }
  }
  return { text: s, quote, depth, at, mapping, value: value + s.slice(from), joins, ...(escaped ? { escaped } : {}) };
}

/**
 * Where the `${{` expression at `i` ends: the index of its closing `}}`, or -1 when the text ends first. GitHub ends an
 * expression at the first `}}` outside a string literal (actions/runner TemplateReader), so a `}}` in one does not.
 */
function expressionEnd(text: string, i: number): number {
  let inString = false;
  for (let j = i + 3; j < text.length; j++) {
    if (text[j] === "'") inString = !inString;
    else if (!inString && text[j] === "}" && text[j + 1] === "}") return j;
  }
  return -1;
}

/**
 * The block scalar starting on this line (`run: |`, `run: &a !!str |`, `- >-`): the key owning it, the
 * column, relative to the line's indentation, that its content is indented past, and whether the
 * header is alone on its line.
 */
function blockStart(text: string): { key: string; col: number; alone: boolean } | undefined {
  const m = BLOCK_INDICATOR.exec(text);
  if (!m) return undefined;
  const words = text.slice(0, m.index).split(/[ \t]+/).filter((w) => w !== "");
  while (PROPERTY.test(words.at(-1) ?? "")) words.pop();
  const head = words.join(" ");
  if (head === "" || head === "-") return { key: "", col: 0, alone: head === "" };
  return head.endsWith(":") ? { key: entry(head)?.key ?? "", col: DASH.exec(text)?.[0].length ?? 0, alone: false } : undefined;
}

function parseLines(src: string): Line[] {
  const out: Line[] = [];
  /**
   * A block scalar's content is every line indented past its key (or past its `-`). A header seen while a quote
   * seems open, or inside such a block, may be text in a quoted scalar, so that block's lines are read both ways.
   */
  let block: { key: string; parent: number; unsure: boolean } | undefined;
  let open: Open = { quote: "", depth: 0, at: "node" };
  /** Lines indented at least this far continue a multi-line plain scalar, where a quote is content, owned by plainKey. */
  let plainFrom = Infinity;
  let plainKey = "";
  /** The key owning the quoted scalar still open at the end of the last line. */
  let quoteKey = "";
  let inJobs = false;
  let jobIndent = -1;
  let job = "";
  /** The last line that is neither blank, only a comment, nor block scalar content, without its comment, and its openKey. */
  let last: { indent: number; text: string; key: string | undefined } | undefined;
  // Node's UTF-8 decoding keeps a byte order mark, which YAML allows at the start of a stream.
  // YAML breaks lines at CR LF, LF or a lone CR.
  src.replace(/^\uFEFF/, "").split(/\r\n?|\n/).forEach((r, i) => {
    let indent = 0;
    while (r.charCodeAt(indent) === 32) indent++;
    const rest = r.slice(indent);
    let inBlock: string | undefined;
    if (block) {
      if (rest.trim() === "" || indent > block.parent) {
        if (!block.unsure) {
          // Block scalar content is read as written: no quotes, escapes or comments.
          out.push({ n: i + 1, indent, text: rest, raw: rest, block: block.key, job });
          return;
        }
        inBlock = block.key;
      } else {
        block = undefined;
      }
    }
    // Inside a flow collection a line break is only a space, so the state carries over as it is.
    const inQuote = open.quote !== "";
    const cont = !inQuote && open.depth === 0 && indent >= plainFrom;
    const s = stripComment(rest, open.quote !== "" || open.depth > 0 ? open : { quote: "", depth: 0, at: cont ? "plain" : "node" });
    const yamlText = s.text.trimEnd();
    const text = inBlock === undefined ? yamlText : rest.trimEnd();
    // Keys are read even where the scanner thinks a quote is still open, so a wrong guess cannot hide one. Text in a
    // real quote that looks like a key can then only add a trigger, never remove one: triggers() reads every `on:`.
    const e = entry(text);
    // A scalar alone on the line below `key:` (or a `-`) is that key's value: `run:` then `  gh pr checkout 5`.
    const alone = !inQuote && open.depth === 0 && !cont && text !== "" && !e && !ITEM.test(text);
    const ownerKey = alone && last && indent > last.indent ? last.key : undefined;
    if (text !== "") {
      if (indent === 0) {
        inJobs = e?.key === "jobs";
        jobIndent = -1;
        job = "";
      } else if (inJobs) {
        if (jobIndent < 0) jobIndent = indent;
        if (indent === jobIndent) job = e?.key ?? job;
      }
      const ended = s.at === "plain" && s.quote === "" && s.depth === 0;
      // A plain scalar continues on lines indented past its key, or past its `-`, even when it starts on the line below the key.
      if (!ended) plainFrom = Infinity;
      else if (!cont) {
        plainFrom =
          ownerKey !== undefined && last
            ? last.indent + (DASH.exec(last.text)?.[0].length ?? 0) + 1
            : indent + (s.mapping ? (DASH.exec(text)?.[0].length ?? 0) + 1 : DASH.test(text) ? 1 : 0);
        plainKey = e?.key ?? ownerKey ?? "";
      }
    }
    // `run: echo;` then `  gh pr checkout 5` on the next line is one script: Actions runs "echo; gh pr checkout 5".
    const scalarOf = inBlock ?? ((inQuote ? quoteKey : cont ? plainKey : ownerKey) || undefined);
    out.push({
      n: i + 1,
      indent,
      text,
      raw: rest,
      value: s.value,
      job,
      ...(s.escaped ? { escaped: s.escaped } : {}),
      ...(s.joins ? { joins: true as const } : {}),
      ...(e ? { entry: e } : {}),
      ...(scalarOf !== undefined ? { block: scalarOf, unsure: true as const } : {}),
    });
    // Also tried where a quote seems open, for the same reason keys are.
    const b = blockStart(yamlText);
    // A header alone on its line (`run:`, then `|` below it) belongs to the key or `-` on the line before, so its
    // content need only be indented past that key, not past the header.
    const prev = b?.alone ? last : undefined;
    const joined = prev && blockStart(`${prev.text} ${yamlText}`);
    const unsure = s.quote !== "" || inBlock !== undefined;
    if (prev && joined) block = { key: joined.key, parent: prev.indent + joined.col, unsure };
    else if (b !== undefined) block = { key: b.key, parent: indent + b.col, unsure };
    if (b !== undefined) plainFrom = Infinity;
    // The quote state carries across a block: if its header was really text inside a quote, the quote is still open after it.
    open = { quote: s.quote, depth: s.depth, at: s.at };
    if (!inQuote) quoteKey = e?.key ?? ownerKey ?? "";
    // A line holding only an anchor or tag (`&a`) leaves the key its node belongs to on the line before.
    if (!onlyProperties(yamlText)) last = { indent, text: yamlText, key: openKey(yamlText) };
  });
  return out;
}

/** Lines that are YAML structure: not blank, not only a comment, not block scalar content (unless unsure). */
const structural = (lines: Line[]) => lines.filter((l) => isYaml(l) && l.text !== "");

/**
 * The structural lines nested under yaml[i], up to the first dedent. Under a
 * `key:` with no value, `- ` items at the key's own indent count too, as YAML
 * allows (`on:` then `- push`). Callers of one kind (`on:`, `env:`, `matrix:`,
 * `runs-on:`) that enclose a line sit at different indents, at most two per
 * indent (with and without a `-`), so each kind visits each line at most twice
 * per indentation byte, plus twice. Callers test a visited line against a set
 * built in one pass, never by rescanning its text.
 */
function children(yaml: Line[], i: number): Line[] {
  const out: Line[] = [];
  const p = yaml[i] as Line;
  const items = p.entry !== undefined && onlyProperties(p.entry.value) && !DASH.test(p.text);
  for (let j = i + 1; j < yaml.length; j++) {
    const l = yaml[j] as Line;
    if (l.indent < p.indent || (l.indent === p.indent && !(items && ITEM.test(l.text)))) break;
    out.push(l);
  }
  return out;
}

/** A value without its leading anchors and tags (`&a !!seq [x]` is `[x]`). */
const bare = (value: string): string => value.replace(/^(?:[&!][^ \t]*[ \t]*)+/, "");

/**
 * Why the reader cannot vouch for this workflow, or undefined: the forms named in the comment at the top of this file.
 * Each is valid YAML that GitHub runs, and each can carry a step, a runner or a trigger the line-based checks would
 * not see where they look for it.
 */
function unmodelled(yaml: Line[]): string | undefined {
  // An empty collection (`jobs: {}`) holds nothing to miss.
  const flow = (v: string): boolean => /^[[{]/.test(v) && !/^(?:\{[ \t]*\}|\[[ \t]*\])$/.test(v);
  // The first line that is not a document marker or directive.
  const first = yaml.find((l) => l.text !== "---" && !l.text.startsWith("%"));
  if (first !== undefined && flow(bare(first.text))) return `it is written in flow (JSON) form (line ${first.n})`;
  for (const [i, l] of yaml.entries()) {
    const e = l.entry;
    if (/^(?:-[ \t]+)?<<[ \t]*:/.test(l.text)) return `it uses a YAML merge key (line ${l.n})`;
    const value = e !== undefined ? bare(e.value) : ITEM.test(l.text) ? bare(l.text.replace(DASH, "")) : "";
    if (value.startsWith("*")) return `it uses a YAML alias (line ${l.n})`;
    if (e === undefined) continue;
    // A job's own mapping, `jobs:` or `steps:` written as a flow collection.
    if ((e.key === "jobs" || e.key === "steps" || (l.job !== "" && e.key === l.job && l.indent > 0)) && flow(value)) return `\`${e.key}:\` has a flow value (line ${l.n})`;
    // A step written as a flow mapping: `- {run: ...}` under `steps:`.
    if (e.key === "steps") {
      const step = children(yaml, i).find((c) => ITEM.test(c.text) && flow(bare(c.text.replace(DASH, ""))));
      if (step !== undefined) return `a step is written as a flow mapping (line ${step.n})`;
    }
  }
  return undefined;
}

/** At most this many line numbers are named in the message. */
const MAX_UNREAD_LINES = 5;

/**
 * The most lines one `${{ }}` expression may take in. GitHub's expressions are conditions and values: of the 2,530 in
 * the workflows and actions of the false-positive corpus's 15 repositories, 13 span lines, the longest 9. A `${{` with
 * no `}}` within this many lines is reported as not checked, so a stray `${{` cannot join the rest of a file into one.
 */
export const MAX_EXPRESSION_LINES = 50;

/** Where the `${{ }}` expressions in a file end, from expressionSpans(). Line indexes count from 0. */
interface Spans {
  /** For each line on which an expression starts that a later line closes: the index of the last line it takes in. */
  through: Map<number, number>;
  /** Lines on which a `${{`, as YAML reads the line, has no closing `}}` within MAX_EXPRESSION_LINES lines. */
  unclosed: Set<number>;
  /** Lines on which an expression starts that a YAML escape wrote part of. */
  escaped: Set<number>;
}

/**
 * Where each `${{ }}` expression ends, as GitHub reads it: at the first `}}` outside a string literal (actions/runner
 * TemplateReader), on its own line or a later one. Each line is read two ways: as written, its comment included, and
 * as YAML reads it, with the positions a YAML escape wrote. Where the two disagree, the expression takes in the most
 * lines either gives, so a wrong guess about where a comment or a quote ends cannot cut one short; one that only the
 * reading as written opens and never closes takes in none. Only a `${{` YAML reads, comments gone, can be unclosed: a
 * `${{` in a comment is text GitHub ignores. Each character is read once per way.
 */
function expressionSpans(lines: Line[]): Spans {
  const spans: Spans = { through: new Map(), unclosed: new Set(), escaped: new Set() };
  const ways: [(l: Line) => string, boolean][] = [
    [(l) => l.raw, false],
    [(l) => l.value ?? l.text, true],
  ];
  for (const [read, decoded] of ways) {
    /** The index of the line the open expression starts on, or -1; whether it is in a string literal, and was escaped. */
    let open = -1;
    let inString = false;
    let esc = false;
    /**
     * The open expression ends on line k: closed there, or not closed (`closed` false) within MAX_EXPRESSION_LINES or
     * the file. One not closed as written, comments included, takes in no lines, and is not unclosed: GitHub ignores
     * a comment, and one as YAML reads it, where the comments are gone, is what is reported.
     */
    const end = (k: number, closed: boolean) => {
      if (!closed && decoded) spans.unclosed.add(open);
      if (k > open && (closed || decoded)) spans.through.set(open, Math.max(spans.through.get(open) ?? k, k));
      if (esc) spans.escaped.add(open);
      open = -1;
    };
    lines.forEach((l, k) => {
      const t = read(l);
      const at = decoded ? l.escaped : undefined;
      for (let i = 0; i < t.length; i++) {
        if (open < 0) {
          const j = t.indexOf("${{", i);
          if (j < 0) break;
          open = k;
          inString = false;
          esc = at !== undefined && (at.has(j) || at.has(j + 1) || at.has(j + 2));
          i = j + 2;
        } else {
          if (at?.has(i)) esc = true;
          if (t[i] === "'") inString = !inString;
          else if (!inString && t[i] === "}" && t[i + 1] === "}") {
            if (at?.has(i + 1)) esc = true;
            end(k, true);
            i++;
          }
        }
      }
      // An escaped line break inside an expression writes part of it, and so does one after `$` or `${`, which YAML
      // joins to the next line's `{{` or `{` with no space between.
      if (decoded && l.joins === true) {
        if (open >= 0) esc = true;
        else if (/\$\{?$/.test(t)) spans.escaped.add(k);
      }
      if (open >= 0 && k - open + 1 >= MAX_EXPRESSION_LINES) end(k, false);
    });
    if (open >= 0) end(lines.length - 1, false);
  }
  return spans;
}

/**
 * Why the checks cannot read some `${{ }}` expression in the file, or undefined: one with no `}}` within
 * MAX_EXPRESSION_LINES lines, or one a YAML escape wrote part of. Rather than guess, the reader reports the file as not
 * checked.
 */
function unreadExpressions(spans: Spans): string | undefined {
  const at = (indexes: Set<number>): string | undefined => {
    const ns = [...indexes].sort((x, y) => x - y).map((k) => k + 1);
    if (ns.length === 0) return undefined;
    const more = ns.length - MAX_UNREAD_LINES;
    return `line${ns.length > 1 ? "s" : ""} ${ns.slice(0, MAX_UNREAD_LINES).join(", ")}${more > 0 ? `, and ${more} more` : ""}`;
  };
  const unclosed = at(spans.unclosed);
  const escaped = at(spans.escaped);
  if (unclosed === undefined && escaped === undefined) return undefined;
  const what = [
    ...(unclosed !== undefined ? [`a \${{ }} expression has no closing }} within ${MAX_EXPRESSION_LINES} lines (it starts on ${unclosed})`] : []),
    ...(escaped !== undefined ? [`a \${{ }} expression is written with YAML escape sequences (${escaped})`] : []),
  ].join(", and ");
  return `${what}, so wormsign cannot read what GitHub evaluates there: a secret or pull request code it uses was not checked. Close each expression with }} within ${MAX_EXPRESSION_LINES} lines, and write it without escapes`;
}

/** The characters YamlDotNet also breaks lines at (CharacterAnalyzer.IsBreak), besides CR and LF. */
const OTHER_LINE_BREAKS: [string, string][] = [["\x85", "U+0085 (NEXT LINE)"], ["\u2028", "U+2028 (LINE SEPARATOR)"], ["\u2029", "U+2029 (PARAGRAPH SEPARATOR)"]];

/**
 * Why the reader cannot vouch for this workflow's lines, or undefined: it holds a character YamlDotNet reads as a line
 * break and this reader does not, so a comment or a scalar may end there for GitHub, and what follows be a step.
 */
function lineBreaks(lines: Line[]): string | undefined {
  const found = OTHER_LINE_BREAKS.flatMap(([c, name]) => {
    const at = lines.find((l) => l.raw.includes(c));
    return at === undefined ? [] : [`${name} on line ${at.n}`];
  });
  if (found.length === 0) return undefined;
  return `it holds ${found.join(", ")}, which YamlDotNet, the YAML library of GitHub's runner, reads as a line break and wormsign's workflow reader does not, so GitHub may end a comment or value there and read what follows as a step that was not checked. Remove the character, or in a double-quoted string write it as an escape (\\x85, \\u2028 or \\u2029)`;
}

/**
 * Event names under the top-level `on:` key, in its scalar, list or mapping form. Every `on:` counts, so text in a
 * multi-line quoted scalar that looks like an earlier `on:` cannot hide the real one.
 */
function triggers(yaml: Line[]): Set<string> {
  const events = new Set<string>();
  yaml.forEach((l, i) => {
    if (l.indent !== 0 || l.entry?.key !== "on") return;
    const kids = children(yaml, i);
    const top = kids[0]?.indent;
    // An anchor or tag (`on: &x [push]`, `on: !!seq` with a list below) is not an event name.
    const value = l.entry.value.replace(/^(?:[&!][^ \t]*[ \t]*)+/, "");
    // A flow collection (`[push, ...]`) may wrap onto the lines below; every word in it counts, as on one line.
    const texts = /^[[{]/.test(value || (kids[0]?.text ?? ""))
      ? [value, ...kids.map((k) => k.text)]
      : value !== ""
        ? [value]
        : kids.filter((k) => k.indent === top).map((k) => k.entry?.key ?? k.text.replace(/^-[ \t]*/, ""));
    for (const t of texts) for (const ev of t.match(/[\w-]+/g) ?? []) events.add(ev);
  });
  return events;
}

/**
 * Each `${{ }}` expression in the text, from its `${{` to its end (expressionEnd()), with its property paths as GitHub's
 * lexer reads them (actions/runner LexicalAnalyzer): whitespace between tokens is skipped, so a `.`, `[` or `]` with
 * whitespace around it is read as if it had none (`github.event.pull_request` then `.head.sha` on the next line, read
 * joined with a space, is `github.event.pull_request.head.sha`), and names match in any case (DictionaryContextData
 * looks keys up with OrdinalIgnoreCase), so the text is lower-cased. Whitespace is .NET's Char.IsWhiteSpace, which
 * also counts U+0085. String literals keep their whitespace. An expression still open at the end of the text runs to
 * it. `paths` holds the whole text with each expression so read, and `['x']` index syntax read as `.x`: what the
 * property-path checks match (HEAD_REF, `matrix.`); the text outside expressions is as written.
 */
function readPaths(text: string): { bodies: string[]; paths: string } {
  const bodies: string[] = [];
  let paths = "";
  let from = 0;
  for (let i = text.indexOf("${{"); i >= 0; ) {
    const end = expressionEnd(text, i);
    const j = end < 0 ? text.length : end;
    const body = pathsOf(text.slice(i + 3, j));
    bodies.push(body);
    paths += text.slice(from, i + 3) + body;
    from = j;
    i = end < 0 ? -1 : text.indexOf("${{", end + 2);
  }
  return { bodies, paths: (paths + text.slice(from)).replace(INDEX_SYNTAX, ".$2") };
}

const EXPRESSION_SPACE = /[\s\x85]/;
const PATH_PUNCTUATION = new Set([".", "[", "]"]);

/**
 * One expression's text as readPaths() describes it: each run of whitespace outside a string literal is dropped next to
 * `.`, `[` or `]` and is one space elsewhere. Linear: each character is read once, and the text is copied in runs.
 */
function pathsOf(expr: string): string {
  const e = expr.toLowerCase();
  let out = "";
  /** The last character written, and the start of the run not yet copied. */
  let last = "";
  let from = 0;
  let inString = false;
  for (let i = 0; i < e.length; i++) {
    const c = e[i] as string;
    if (inString || !EXPRESSION_SPACE.test(c)) {
      if (c === "'") inString = !inString;
      continue;
    }
    if (i > from) {
      out += e.slice(from, i);
      last = e[i - 1] as string;
    }
    let j = i + 1;
    while (j < e.length && EXPRESSION_SPACE.test(e[j] as string)) j++;
    const next = e[j];
    if (next !== undefined && !PATH_PUNCTUATION.has(next) && !PATH_PUNCTUATION.has(last)) {
      out += " ";
      last = " ";
    }
    from = j;
    i = j - 1;
  }
  return out + e.slice(from);
}

/** True when some `${{ }}` expression in the text reads the secrets context, its paths read as readPaths() reads them. */
function readsSecrets(text: string): boolean {
  return readPaths(text).bodies.some((e) => /\bsecrets[.[]/.test(e));
}

/**
 * The `${{ }}` expressions on a line, each with its string literals emptied (`'it''s'` becomes `''''`), so that a
 * word inside a literal is not read as a context. A `}}` inside a literal does not end the expression; an expression
 * still open at the end of the line runs to it.
 */
function expressions(text: string): string[] {
  const out: string[] = [];
  for (let i = text.indexOf("${{"); i >= 0; ) {
    const end = expressionEnd(text, i);
    const j = end < 0 ? text.length : end;
    out.push(text.slice(i + 3, j).replace(/'[^']*'/g, "''"));
    i = end < 0 ? -1 : text.indexOf("${{", end + 2);
  }
  return out;
}

/** `secrets` as a context, in any case (GitHub matches context and function names case-insensitively), not a property such as `inputs.secrets`. */
const SECRETS_CONTEXT = /(?<![\w.$-])secrets(?![\w-])/gi;
/** What may follow `secrets` to read one secret by name: `.NAME` or `['NAME']` (a literal, emptied by expressions()). */
const ONE_SECRET = /\s*(?:\.\s*[A-Za-z_][\w-]*|\[\s*''\s*\])/y;

/**
 * True when a `${{ }}` expression on the line uses the secrets context other than as `secrets.NAME` or
 * `secrets['NAME']`: `toJSON(secrets)`, the object filter `secrets.*` (GitHub's expression docs, "Object filters":
 * the `*` syntax also applies to an object, so `toJSON(secrets.*)` and `join(secrets.*, ' ')` hold every value),
 * `format('{0}', secrets)`, or a computed `secrets[...]` index, which can name any secret.
 */
function readsWholeSecrets(text: string): boolean {
  for (const expr of expressions(text)) {
    for (const m of expr.matchAll(SECRETS_CONTEXT)) {
      ONE_SECRET.lastIndex = m.index + m[0].length;
      if (!ONE_SECRET.test(expr)) return true;
    }
  }
  return false;
}

/**
 * git subcommands that put a ref's code in the working tree: the fetches and checkouts, and the commands that apply
 * or extract its commits or files. `git show`, `git log` or `git commit` with a head ref reads metadata only.
 */
const GIT_FETCHES = new Set(["fetch", "pull", "clone", "checkout", "switch", "worktree", "reset", "merge", "rebase", "cherry-pick", "restore", "read-tree", "checkout-index", "archive", "bisect", "apply"]);
/** git's global options that take the next word as their value (git(1)). */
const GIT_VALUE_OPTIONS = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--attr-source"]);
/** Words read after `git` for its subcommand; more than this many global options is not what a workflow writes. */
const GIT_MAX_OPTIONS = 16;

/** The git subcommands a head ref held in an env: variable is checked for (headEnvNames()): fetch and check out. */
const GIT_CHECKOUTS = new Set(["fetch", "checkout", "switch", "reset"]);

/**
 * True when a git command on the line may fetch or check out code: its subcommand is in `fetches` (GIT_FETCHES unless
 * given), or is not a plain word (`git $cmd`), or is hidden behind global options or a `-c alias.*` setting. Fails
 * closed: only a subcommand read as a plain word outside `fetches` clears a `git`. Linear: each `git` reads at most
 * GIT_MAX_OPTIONS words after it.
 */
function gitFetchesCode(t: string, fetches: ReadonlySet<string> = GIT_FETCHES): boolean {
  const words = t.split(/[ \t]+/);
  for (let i = 0; i < words.length; i++) {
    const g = words[i] as string;
    // `git`, `/usr/bin/git`, `$(git`: not `.git` or `my-git`.
    if (!g.endsWith("git") || (g.length > 3 && /[\w.-]/.test(g[g.length - 4] as string))) continue;
    for (let j = i + 1; ; j++) {
      if (j >= words.length) break; // `git` last on the line: no subcommand here
      if (j > i + GIT_MAX_OPTIONS) return true;
      const w = words[j] as string;
      if (w.startsWith("-")) {
        if (w === "-c" && /^["']?alias\./i.test(words[j + 1] ?? "")) return true;
        if (GIT_VALUE_OPTIONS.has(w)) j++;
        continue;
      }
      let end = w.length;
      while (end > 0 && ";&|)`'\"".includes(w[end - 1] as string)) end--; // `git fetch;`, `$(git show)`
      const sub = w.slice(0, end);
      if (sub === "") break; // `git;` or `which git &&`: git with no subcommand
      if (fetches.has(sub) || !/^[a-z][a-z0-9-]*$/.test(sub)) return true;
      break;
    }
  }
  return false;
}

/** Names bound to a secret in any `env:` mapping. Not scoped to a job or step: a false positive is cheaper than a miss. */
function secretEnvNames(yaml: Line[], texts: (l: Line) => string[]): Set<string> {
  const bindsSecret = new Set(yaml.filter((l) => l.entry && texts(l).some(readsSecrets)));
  const names = new Set<string>();
  yaml.forEach((l, i) => {
    if (l.entry?.key !== "env" || l.entry.value !== "") return;
    for (const c of children(yaml, i)) {
      if (c.entry && bindsSecret.has(c)) names.add(c.entry.key);
    }
  });
  return names;
}

/**
 * Names bound in any `env:` mapping (workflow, job or step) to a value that names pull request code: HEAD_REF, on
 * readPaths()'s paths. Not scoped to a job or step, as secretEnvNames is not. A ref:, or a git fetch or checkout, that
 * reads one checks out that code (`SHA: ${{ github.event.pull_request.head.sha }}`, then `ref: ${{ env.SHA }}`).
 */
function headEnvNames(yaml: Line[], texts: (l: Line) => string[]): Set<string> {
  const bindsHead = new Set(yaml.filter((l) => l.entry && texts(l).some((t) => HEAD_REF.test(readPaths(t).paths))));
  const names = new Set<string>();
  yaml.forEach((l, i) => {
    if (l.entry?.key !== "env" || l.entry.value !== "") return;
    for (const c of children(yaml, i)) {
      if (c.entry && bindsHead.has(c)) names.add(c.entry.key);
    }
  });
  return names;
}

/** Jobs whose `matrix:` mentions a self-hosted label, for `runs-on: ${{ matrix.x }}`. */
function selfHostedMatrixJobs(yaml: Line[], selfHosted: Set<Line>): Set<string> {
  const jobs = new Set<string>();
  yaml.forEach((l, i) => {
    if (l.entry?.key === "matrix" && (selfHosted.has(l) || children(yaml, i).some((c) => selfHosted.has(c)))) jobs.add(l.job);
  });
  return jobs;
}

const SELF_HOSTED = /self-hosted/i;
const TO_JSON_SECRETS = /toJSON\s*\(\s*secrets\s*\)/i;
/** Expressions and refspecs that name pull request code, matched on readPaths()'s `paths`. */
const HEAD_REF = /github\.event\.pull_request\.(?:head\b|merge_commit_sha)|github\.head_ref|github\.event\.workflow_run\.head_|(?<![\w/])(?:refs\/)?pull\/[^/\n]{1,100}\/(?:head|merge)\b/;
const INDEX_SYNTAX = /\[\s*(['"])([\w-]+)\1\s*\]/g;
/** `env.NAME` in readPaths()'s paths (lower case). */
const ENV_CONTEXT = /(?<![\w.$-])env\.([a-z_][\w-]*)/g;
/**
 * The github context reached through toJSON or fromJSON, or through a computed index (a `[ ]` that readPaths() did not
 * read as `.name`, so not one string literal): a ref built this way can name the pull request's head without spelling
 * it (`fromJSON(toJSON(github.event)).pull_request.head.sha`, `github.event[format('{0}', 'pull_request')]`). Matched on
 * one expression's paths.
 */
const COMPUTED_GITHUB = /(?:tojson|fromjson)\((?:[a-z]\w*\()*github(?![\w-])|(?<![\w.$-])github(?:\.[\w-]+)*\[/;
const REF_KEY = /(?:^|[\s{,])["']?(?:ref|repository)["']?[ \t]*:/;
const NET_OR_FILE = /\b(curl|wget|ncat?|Invoke-WebRequest|iwr|tee|base64)\b|\s>>?\s*\S/;
/** Appending to the runner's own env/output files is how values are meant to pass between steps. */
const ENV_FILE_WRITE = /(?:>>?|\btee(?:[ \t]+-a)?)[ \t]*"?\$(?:\{|env:)?GITHUB_(?:ENV|OUTPUT|STEP_SUMMARY|PATH)\b\}?"?/g;
const VAR_REF = /\$(?:env:)?\{?([A-Za-z_]\w*)/g;
/** Triggers that run with the base repository's secrets while able to reach pull request code (GitHub's "secure use" reference). */
const PRIVILEGED = ["pull_request_target", "workflow_run"];

/**
 * Baseline key: job id plus a hash of the matched line's text (with the lines an expression on it takes in), so moving
 * the line does not change it. `add` numbers copies.
 */
function contentKey(tag: string, l: Line, text: string): string {
  return `${tag}:${l.job}:${keyDigest(text.trim())}`;
}

/** Each distinct string once, in order. */
const distinct = (xs: string[]): string[] => [...new Set(xs)];

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function checkWorkflow(file: string, text: string, ctx: ScanContext): Finding[] {
  const out: Finding[] = [];
  const lines = parseLines(text);
  const base = file.split("/").pop() as string;
  const copies = new Map<string, number>();
  const spans = expressionSpans(lines);
  const opens = (l: Line) => l.raw.includes("${{") || (l.value ?? "").includes("${{");
  /**
   * For a line inside an expression that starts on an earlier line, when no expression starts on it: the lines those
   * expressions start on, which were read with all of it.
   */
  const within = new Map<number, number[]>();
  for (const [start, last] of spans.through) {
    for (let k = start + 1; k <= last; k++) if (!opens(lines[k] as Line)) within.set(k, [...(within.get(k) ?? []), start]);
  }
  /**
   * What the checks read for a line (`texts`) and what a finding's key digests (`key`). A line is read as written and
   * as YAML reads it, and keyed as written. Where an expression that starts on it ends on a later line, it is read
   * joined to the lines up to that one, a line break read as a space: as written, comments included (in an
   * expression the reader may have taken for a comment), and as YAML reads them; and keyed as written without them.
   */
  const joined = new Map<number, { texts: string[]; key: string }>();
  const readOf = (l: Line): { texts: string[]; key: string } => {
    const last = spans.through.get(l.n - 1);
    if (last === undefined) return { texts: distinct([l.text, l.value ?? l.text]), key: l.text };
    let r = joined.get(l.n - 1);
    if (r === undefined) {
      const span = lines.slice(l.n - 1, last + 1);
      const join = (part: (x: Line) => string) => span.map(part).join(" ");
      r = { texts: distinct([join((x) => x.raw), join((x) => x.value ?? x.text)]), key: join((x) => x.text) };
      joined.set(l.n - 1, r);
    }
    return r;
  };
  const textsOf = (l: Line): string[] => readOf(l).texts;
  /** What each line reported, so a line in `within` is not reported again for what a line it was read with was. */
  const reported = new Set<string>();
  const add = (ruleId: string, severity: Severity, message: string, l: Line, key: string, source?: string) => {
    const what = `${ruleId}\0${message}`;
    if (within.get(l.n - 1)?.some((start) => reported.has(`${start}\0${what}`))) return;
    reported.add(`${l.n - 1}\0${what}`);
    // A second identical line gets its own key, so neither dedupe nor a baseline of the first can hide it.
    const n = copies.get(`${ruleId}:${key}`) ?? 0;
    copies.set(`${ruleId}:${key}`, n + 1);
    out.push(makeFinding({ ruleId, severity, message, file, line: l.n, key: n === 0 ? key : `${key}#${n}`, ...(source ? { source } : {}) }));
  };

  for (const w of ctx.iocs.workflowFiles) {
    if (w.name === base) {
      out.push(
        makeFinding({
          ruleId: "WS-GH-001",
          severity: w.severity,
          message: `Workflow file name ${w.name} matches an IOC (${w.wave} wave)${w.note ? `. ${w.note}` : ""}`,
          file,
          key: w.name,
          source: w.source,
        }),
      );
    }
  }

  const yaml = structural(lines);
  const why = unmodelled(yaml);
  if (why !== undefined) out.push(notChecked(file, `${why}, which wormsign's workflow reader does not model, so its triggers, jobs, runners and steps were read only in part`));
  const breaks = lineBreaks(lines);
  if (breaks !== undefined) out.push(notChecked(file, breaks, "high", text));
  const unread = unreadExpressions(spans);
  // Keyed on the whole file too: where such an expression ends is what cannot be read, so any edit is new.
  if (unread !== undefined) out.push(notChecked(file, unread, "high", text));
  const pos = new Map(yaml.map((l, i) => [l, i]));
  const on = triggers(yaml);
  const privileged = PRIVILEGED.filter((t) => on.has(t));
  const secretEnv = secretEnvNames(yaml, textsOf);
  const headEnv = privileged.length > 0 ? headEnvNames(yaml, textsOf) : new Set<string>();
  /** In expressions env names match in any case, as context keys do (readPaths() lower-cases them). */
  const headEnvLower = new Set([...headEnv].map((n) => n.toLowerCase()));
  const readsHeadEnv = (paths: string) => [...paths.matchAll(ENV_CONTEXT)].some((m) => headEnvLower.has(m[1] as string));
  const selfHosted = new Set(yaml.filter((l) => SELF_HOSTED.test(l.text)));
  const matrixJobs = selfHostedMatrixJobs(yaml, selfHosted);
  const runnerLines = ctx.iocs.runnerNames.map((r) => ({ r, lines: new Set(yaml.filter((l) => l.text.includes(r.name))) }));
  const registrations = ctx.iocs.runnerNames.map((r) => ({ r, re: new RegExp(`--name[\\s=]+["']?${escapeRegExp(r.name)}(?![\\w-])`) }));
  let hasRun = false;
  let selfHostedJob = false;

  lines.forEach((l) => {
    const { texts, key: keyText } = readOf(l);
    if (texts.every((t) => t.trim() === "")) return;
    const e = l.entry;
    if ((e?.key === "run" && e.value !== "") || l.block === "run") hasRun = true;
    // The line is a script, or a `run:` key with its script on this line: the texts hold it.
    const script = l.block === "run" || (e?.key === "run" && blockStart(l.text) === undefined);

    // TO_JSON_SECRETS also reads text outside `${{ }}`: an `if:` condition is an expression written without one.
    const dump = texts.some((t) => TO_JSON_SECRETS.test(t));
    if (dump || texts.some(readsWholeSecrets)) {
      const what = dump ? "Serializes the entire secrets context with toJSON(secrets)" : "Reads the secrets context other than as secrets.NAME or secrets['NAME'] (secrets.*, a function of secrets, or a computed index), which can expose every secret";
      add("WS-GH-002", "high", what, l, contentKey("toJSON-secrets", l, keyText));
    }

    if (privileged.length > 0) {
      // The key on this line, or a value below its key: a block scalar (`ref: >-`) or a plain scalar alone on the next line.
      const refValue = (t: string) => (isYaml(l) && REF_KEY.test(t)) || l.block === "ref" || l.block === "repository";
      const checksOut = (text: string) => {
        const t = readPaths(text).paths;
        const viaKey = refValue(t) && (HEAD_REF.test(t) || readsHeadEnv(t));
        // A head ref held in an env: variable counts only for git fetch, checkout, switch and reset: `echo "$SHA"` is common.
        const headVar = readsHeadEnv(t) || [...t.matchAll(VAR_REF)].some((m) => headEnv.has(m[1] as string));
        const viaScript = script && (/\bgh\s+pr\s+checkout\b/.test(t) || (HEAD_REF.test(t) && gitFetchesCode(t)) || (headVar && gitFetchesCode(t, GIT_CHECKOUTS)));
        return viaKey || viaScript;
      };
      // Only in a ref: value, so fail closed there: toJSON(github.event) in a run line is a common debug dump.
      const computedRef = (text: string) => {
        const r = readPaths(text);
        return refValue(r.paths) && r.bodies.some((b) => COMPUTED_GITHUB.test(b.replace(INDEX_SYNTAX, ".$2")));
      };
      if (texts.some(checksOut)) {
        add("WS-GH-003", "high", `${privileged.join("/")} workflow checks out pull request code, running it with access to secrets`, l, contentKey("prt-checkout", l, keyText));
      } else if (texts.some(computedRef)) {
        add("WS-GH-003", "high", `${privileged.join("/")} workflow checks out a ref computed from the github context (through toJSON, fromJSON or a computed index), which wormsign cannot resolve: it may be pull request code, run with access to secrets`, l, contentKey("prt-checkout-computed", l, keyText));
      }
    }

    if (e?.key === "runs-on") {
      // The line itself, for the inline forms, then the nested group/labels or list forms, or a wrapped flow list.
      const region = [l, ...children(yaml, pos.get(l) as number)];
      if (region.some((c) => selfHosted.has(c)) || (texts.some((t) => readPaths(t).paths.includes("matrix.")) && matrixJobs.has(l.job))) {
        selfHostedJob = true;
        add("WS-GH-004", "medium", "Job runs on a self-hosted runner; a compromised job can persist on that machine", l, contentKey("self-hosted", l, keyText));
      }
      for (const { r, lines: named } of runnerLines) {
        if (region.some((c) => named.has(c))) {
          add("WS-GH-006", "critical", `Targets runner ${r.name}, the name the worm registers (${r.wave} wave)`, l, `runner:${l.job}:${r.name}`, r.source);
        }
      }
    }

    const sinksSecret = (t: string) => {
      if (!NET_OR_FILE.test(t.replace(ENV_FILE_WRITE, " "))) return false;
      const viaEnv = script && [...t.matchAll(VAR_REF)].some((m) => secretEnv.has(m[1] as string));
      return readsSecrets(t) || viaEnv;
    };
    if (texts.some(sinksSecret)) {
      add("WS-GH-005", "high", "A secret reaches a command that writes a file or uses the network", l, contentKey("secret-sink", l, keyText));
    }

    for (const { r, re } of registrations) {
      if (texts.some((t) => re.test(t))) {
        add("WS-GH-006", "critical", `Registers a runner named ${r.name} (${r.wave} wave)`, l, `runner-register:${r.name}`, r.source);
      }
    }
  });

  if ((on.has("discussion") || on.has("discussion_comment")) && hasRun) {
    // A self-hosted runner as well is the shape of the worm's discussion.yaml backdoor (Wiz).
    out.push(
      makeFinding({
        ruleId: "WS-GH-007",
        severity: selfHostedJob ? "high" : "medium",
        message: `Workflow is triggered by discussion events and runs shell commands${selfHostedJob ? ", with a self-hosted runner" : ""}; anyone who can open a discussion can influence it. A reported variant used this as a command backdoor`,
        file,
        key: selfHostedJob ? "discussion-run-self-hosted" : "discussion-run",
        source: "https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack",
      }),
    );
  }
  return out;
}
