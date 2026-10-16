/**
 * What discovery learns from a file's bytes, in its one content pass (src/python/discover.ts): is the file a PEP 723
 * script, and is it a requirements file whatever its name?
 *
 * Which files are read (isContentCandidate; docs/soak.md, "Discovery"): a .py or .pyw file; a file with no extension
 * or one of CONTENT_EXTENSIONS (.txt, .in, .lock, .pip, .req, .sh, ...), the names a requirements file or a uv script
 * run by path is given in practice; and any file with a regular `<name>.lock` beside it, whatever its name (uv runs a
 * script with that lock). No other file is opened, so source code, bundles, images and data cost nothing however many
 * there are: before, every regular file in the tree was opened, which took a 75,000-file tree from under a second to
 * about 25 seconds.
 *
 * Scripts (docs/soak.md, "Manifests, scripts and virtual environments"). A file is a script when any of these holds:
 * - its name ends in .py or .pyw (any size discovery reads, MAX_SCRIPT_BYTES);
 * - its first line is a shebang whose tokens include `uv` (a path ending in /uv counts, and env's `-Suv`) and `run`,
 *   which covers `#!/usr/bin/env -S uv run --script` and `uv -q run`;
 * - it has a line that is exactly `# /// script` (lines split on "\r\n", "\r" or "\n", as pep723.ts reads stray tags):
 *   searched in the first CONTENT_LIMIT bytes, in the whole file (up to MAX_SCRIPT_BYTES) when it is larger, and in
 *   the whole of a file with a `<name>.lock` beside it.
 * Its block is read by pep723.ts (uv's rules), and its lock is `<script path>.lock` whatever its name (verified: uv
 * 0.10.9 and 0.12.21 `uv lock --script deploy` writes deploy.lock, and crlf.txt gets crlf.txt.lock;
 * test/fixtures/python/repos/scripts/GENERATED.txt).
 *
 * Requirements files by content (docs/soak.md, "Requirements files"): a file read (above) that pip or uv would read as
 * having a `--require-hashes` line or a `--hash` option with a value, and that both could read as a requirements file
 * at all. Read as pip 26.2.1 reads a requirements file (req_file.py), over-inclusively, so that a spelling pip or uv
 * accepts cannot hide one:
 * - decoding: a UTF-8, UTF-16 or UTF-32 byte-order mark decodes the rest as pip does (_decode_req_file); a PEP 263
 *   coding line in the first two lines naming a Python codec whose ASCII bytes are not ASCII text (UTF-7, UTF-16 and
 *   UTF-32 without a mark, EBCDIC, unicode_escape, ...: OPAQUE_CODECS) makes the file a candidate outright, since its
 *   text cannot be searched as bytes; anything else is searched as bytes: ASCII-compatible encodings, the locale
 *   fallback pip uses for invalid UTF-8, and a name Python has no codec for (utf-8-unix, binary), with which pip fails
 *   (LookupError) and uv reads the bytes as UTF-8. NUL bytes do not exclude a file: pip reads one that holds one;
 * - lines are split as str.splitlines splits them, and a line ending in "\" is joined to the next unless it is a
 *   comment (join_lines). Comments are not removed: that only adds candidates;
 * - options are what follows the first token starting with "-" (break_args_options; pip splits tokens on " ", uv
 *   also on a tab, so any whitespace counts here). Text before it is the requirement, which pip never reads as an
 *   option: `const x = "--hash=..."` holds no option. In the options, quotes and backslashes are dropped (pip reads
 *   them with shlex: --h'a'sh= and --h\ash= are --hash=);
 * - a hash option is `--hash`, or an abbreviation optparse accepts (`--h`, `--ha`, `--has`; measured: pip 26.2.1
 *   reads each), after the start of the options or whitespace, followed by "=" or whitespace (`--hash sha256:...` is
 *   the same option), and then a value pip could check: `<algorithm>:` and at least 8 hex digits, or anything holding
 *   `${NAME}` (pip expands an environment variable before it parses, so `--hash=sha256:${DIGEST}` is a real hash).
 *   `webpack --hash`, `--hash=x` and an f-string's `--hash=sha256:{digest}` are not: pip refuses or never matches them;
 * - `--require-hashes`, or an abbreviation down to `--require-` (`--require` is ambiguous with `--requirement`), at
 *   the start of a line, quotes and backslashes dropped. Only at the very start: an indented one is the usual
 *   Dockerfile or shell continuation (`RUN pip install \` / `    --require-hashes \`). Any file holding hashed pins
 *   is found by its hash options anyway, so this rule only adds files that pin nothing themselves.
 * - a file larger than CONTENT_LIMIT (up to MAX_SCRIPT_BYTES) is searched in chunks (mayHoldRequirementsOption) for the
 *   bytes `--h` or `--require-` with quotes and backslashes dropped, and for a byte-order mark or opaque coding line;
 *   one that has them is a candidate.
 * A candidate that pip and uv look certain to refuse (refusedByPipAndUv: a line that is no requirement and no option
 * either reads, such as "FROM node:22", "on: push", prose or `RUN pip install --no-cache-dir ...`) is not read for
 * its packages: discovery reports it as one high WS-SK-002 for the whole file, keyed on its content, which a baseline
 * entry or an ignorePaths entry clears. It is never a note: that judgement has been wrong (a U+001F pip strips, a
 * `file:` URL, a coding line), and a note would hide a file pip installs from.
 * Every step is a linear scan: a hostile file of CONTENT_LIMIT bytes costs milliseconds.
 * Limitation (for the docs): a file with another extension (.md, .yml, .ts, ...) and no `<name>.lock` beside it is a
 * requirements file or script only by name, and a file that only includes others (-r/-c) and pins nothing with a hash
 * is found only by name or by a `--require-hashes` line.
 */
import { readSync } from "node:fs";
import { withRegularFile } from "../fsutil.js";
import { fold } from "../tree.js";
import { continuation } from "./requirements.js";

export const TAG = "# /// script";
/** The most bytes of a file read for the content rules. */
export const CONTENT_LIMIT = 1024 * 1024;
/** The most bytes of a script read for its block. */
export const MAX_SCRIPT_BYTES = 64 * 1024 * 1024;
/** Bytes read from a large file to see whether its first line is a uv shebang. */
export const SHEBANG_BYTES = 4096;

/**
 * Extensions (folded) of the files the content pass reads besides .py, .pyw and files with no extension: names given to
 * requirements files (requirements.in, deps.lock, ci.pip, base.req, packages.lst, tools.deps, pip.conf-style .conf,
 * .cfg and .ini) and to scripts run by path (.sh and the like).
 */
export const CONTENT_EXTENSIONS: ReadonlySet<string> = new Set(["txt", "text", "in", "lock", "pip", "req", "reqs", "requirements", "lst", "list", "deps", "conf", "cfg", "ini", "sh", "bash", "zsh", "command"]);

/** Does the content pass read this file (besides a file with a `<name>.lock` beside it)? See the module comment. */
export function isContentCandidate(name: string): boolean {
  const f = fold(name);
  const dot = f.lastIndexOf(".");
  // No extension: "deploy", "Dockerfile", or a dotfile such as ".requirements".
  if (dot <= 0) return true;
  const ext = f.slice(dot + 1);
  return ext === "py" || ext === "pyw" || CONTENT_EXTENSIONS.has(ext);
}

const TAG_BYTES = Buffer.from(TAG, "latin1");
const CR = 0x0d;
const LF = 0x0a;

/** A PEP 723 script's lock: `<script path>.lock`, for every script (uv 0.10.9 and 0.12.21). */
export const scriptLockPath = (script: string): string => `${script}.lock`;

/** Has a line that is exactly "# /// script", lines split on "\r\n", "\r" or "\n". */
export function hasScriptTagLine(buf: Buffer): boolean {
  for (let at = buf.indexOf(TAG_BYTES); at !== -1; at = buf.indexOf(TAG_BYTES, at + 1)) {
    const before = at === 0 ? LF : buf[at - 1];
    const end = at + TAG_BYTES.length;
    const after = end === buf.length ? LF : buf[end];
    if ((before === LF || before === CR) && (after === LF || after === CR)) return true;
  }
  return false;
}

/** The first line is a shebang whose tokens include uv and run. */
export function isUvShebang(buf: Buffer): boolean {
  if (buf[0] !== 0x23 || buf[1] !== 0x21) return false;
  let end = buf.indexOf(LF);
  if (end === -1) end = buf.length;
  const line = buf.subarray(2, end).toString("latin1").replace(/\r$/, "");
  const tokens = line
    .split(/[ \t\f\v]+/)
    .map((t) => t.replace(/["']/g, ""))
    .filter((t) => t !== "");
  const isUv = (t: string): boolean => {
    const bare = t.startsWith("-S") ? t.slice(2) : t;
    const base = bare.slice(bare.lastIndexOf("/") + 1);
    return base === "uv" || base === "uv.exe";
  };
  return tokens.some(isUv) && tokens.includes("run");
}

/**
 * Python codec names (normalised as Python's encodings.normalize_encoding does: lower case, runs of other characters
 * as "_") whose text is not the ASCII the bytes spell: every codec and alias in CPython 3.14.6's encodings package that
 * decodes the bytes 0x20-0x7e, "\t", "\n" and "\r" to anything else or not at all (listed with a script over
 * encodings.aliases and the codec modules), plus unicode_escape and raw_unicode_escape, which turn `\x2d` into "-".
 * Any other name is either ASCII-compatible or not a codec Python has (pip then fails), so its bytes are searched.
 */
export const OPAQUE_CODECS: ReadonlySet<string> = new Set([
  ...["037", "1026", "1140", "273", "424", "500", "864", "cp01140", "cp037", "cp1026", "cp1140", "cp273", "cp424", "cp500", "cp864", "cp875"],
  ...["csibm01140", "csibm037", "csibm1026", "csibm273", "csibm424", "csibm500", "csibm864"],
  ...["ebcdic_cp_be", "ebcdic_cp_ca", "ebcdic_cp_ch", "ebcdic_cp_he", "ebcdic_cp_nl", "ebcdic_cp_us", "ebcdic_cp_wt", "ebcdic_us_37_euro"],
  ...["hz", "hz_gb", "hz_gb_2312", "hzgb", "ibm01140", "ibm037", "ibm039", "ibm1026", "ibm1140", "ibm273", "ibm424", "ibm500", "ibm864", "punycode"],
  ...["s_jis_2004", "s_jisx0213", "shift_jis_2004", "shift_jisx0213", "shiftjis2004", "shiftjisx0213", "sjis_2004", "sjisx0213"],
  ...["u16", "u32", "u7", "undefined", "unicode_1_1_utf_7", "unicodebigunmarked", "unicodelittleunmarked"],
  ...["utf16", "utf32", "utf7", "utf_16", "utf_16_be", "utf_16_le", "utf_16be", "utf_16le", "utf_32", "utf_32_be", "utf_32_le", "utf_32be", "utf_32le", "utf_7"],
  ...["unicode_escape", "raw_unicode_escape"],
]);

const decodeUtf32 = (b: Buffer, littleEndian: boolean): string => {
  let out = "";
  for (let i = 0; i + 4 <= b.length; i += 4) {
    const cp = littleEndian ? b.readUInt32LE(i) : b.readUInt32BE(i);
    out += cp <= 0x10ffff ? String.fromCodePoint(cp) : "\ufffd";
  }
  return out;
};

/**
 * The text pip would read, for searching (see the module comment): `{ text }`, or `{ opaque, codec }` when pip would
 * decode it with an encoding whose text is not visible in its bytes (`codec` normalised as OPAQUE_CODECS lists it).
 */
export function pipView(buf: Buffer): { text: string } | { opaque: string; codec: string } {
  const starts = (...b: number[]): boolean => b.every((x, i) => buf[i] === x);
  if (starts(0xef, 0xbb, 0xbf)) return { text: buf.subarray(3).toString("latin1") };
  if (starts(0xff, 0xfe, 0x00, 0x00)) return { text: decodeUtf32(buf.subarray(4), true) };
  if (starts(0x00, 0x00, 0xfe, 0xff)) return { text: decodeUtf32(buf.subarray(4), false) };
  if (starts(0xff, 0xfe)) return { text: new TextDecoder("utf-16le").decode(buf.subarray(2)) };
  if (starts(0xfe, 0xff)) return { text: new TextDecoder("utf-16be").decode(buf.subarray(2)) };
  const named = codingLine(buf);
  if (named !== undefined) {
    const name = named.toLowerCase().replace(/[^a-z0-9.]+/g, "_").replace(/^_+|_+$/g, "");
    const codec = OPAQUE_CODECS.has(name) ? name : name.replace(/\./g, "_");
    if (OPAQUE_CODECS.has(codec)) return { opaque: `a coding line names ${JSON.stringify(named)}`, codec };
  }
  return { text: buf.toString("latin1") };
}

/**
 * The codec a PEP 263 coding line names, as written, or undefined: pip reads data.split(b"\n")[:2], a line starting
 * with "#", PEP263_ENCODING_RE = rb"coding[:=]\s*([-\w.]+)" (the first match). A byte-order mark is read before it, so
 * pipView checks for one first.
 */
function codingLine(buf: Buffer): string | undefined {
  const first = buf.indexOf(LF);
  const second = first === -1 ? -1 : buf.indexOf(LF, first + 1);
  const head = buf.subarray(0, second === -1 ? buf.length : second).toString("latin1").split("\n");
  for (const l of head) {
    if (!l.startsWith("#")) continue;
    const m = /coding[:=][ \t\n\r\f\v]*([-\w.]+)/.exec(l);
    if (m) return m[1]!;
  }
  return undefined;
}

/**
 * Python's names (normalised: lower case, runs of other characters as "_") for plain UTF-8 and ASCII, the only codecs
 * whose text of a plain-ASCII file is its bytes: encodings.aliases for utf_8 and ascii, and cp65001.
 */
const PLAIN_CODECS: ReadonlySet<string> = new Set([
  ...["utf_8", "utf8", "u8", "utf", "utf8_ucs2", "utf8_ucs4", "cp65001"],
  ...["ascii", "us_ascii", "646", "ansi_x3_4_1968", "ansi_x3_4_1986", "cp367", "csascii", "ibm367", "iso646_us", "iso_646_irv_1991", "iso_ir_6", "us"],
]);

/** Python's str.splitlines separators, which pip splits a requirements file on. */
const PY_LINE_BREAK_SOURCE = "\\r\\n|[\\n\\r\\v\\f\\x1c\\x1d\\x1e\\x85\\u2028\\u2029]";
const PY_LINE_BREAK = new RegExp(`(?:${PY_LINE_BREAK_SOURCE})`);
/** pip's COMMENT_RE.match(line): a comment line is never joined to the next. */
const COMMENT_LINE = /^\s*#/;
/** Where the options begin: the first token starting with "-" (see the module comment). */
const OPTION_START = /(?:^|\s)-/;
const QUOTES_AND_BACKSLASHES = /["'\\]/g;
const HASH_OPTION = /(?:^|\s)--h(?:a(?:s(?:h)?)?)?(?:=\s*|\s+)(?:[A-Za-z0-9_]+:[0-9A-Fa-f]{8}|\S*\$\{[A-Z0-9_]+\})/;

/** line.strip("\\"), without a regular expression (a run of backslashes is scanned once). */
function stripBackslashes(line: string): string {
  let a = 0;
  let b = line.length;
  while (a < b && line.charCodeAt(a) === 0x5c) a++;
  while (b > a && line.charCodeAt(b - 1) === 0x5c) b--;
  return line.slice(a, b);
}

/** The lines pip parses: split as str.splitlines splits, a line ending in "\\" joined to the next unless it is a comment. */
export function pipLogicalLines(text: string): string[] {
  const out: string[] = [];
  let pending: string[] = [];
  for (const line of text.split(PY_LINE_BREAK)) {
    const comment = COMMENT_LINE.test(line);
    if (!line.endsWith("\\") || comment) {
      if (pending.length > 0) {
        pending.push(comment ? ` ${line}` : line);
        out.push(pending.join(""));
        pending = [];
      } else out.push(line);
    } else pending.push(stripBackslashes(line));
  }
  if (pending.length > 0) out.push(pending.join(""));
  return out;
}

/** The requirements content rule: pip or uv would read a `--hash` option or a `--require-hashes` line in the file. */
export function looksLikeRequirements(buf: Buffer): boolean {
  const view = pipView(buf);
  if ("opaque" in view) return true;
  for (const line of pipLogicalLines(view.text)) {
    if (line.startsWith("-") && line.replace(QUOTES_AND_BACKSLASHES, "").startsWith("--require-")) return true;
    const at = line.search(OPTION_START);
    if (at !== -1 && HASH_OPTION.test(line.slice(at).replace(QUOTES_AND_BACKSLASHES, ""))) return true;
  }
  return false;
}

/**
 * The long options pip 26.2.1 reads in a requirements file (req_file.py build_parser: SUPPORTED_OPTIONS and
 * SUPPORTED_OPTIONS_REQ), with whether each takes a value; uv reads a subset of them. optparse also takes any
 * abbreviation of one, so a flag is known when it is the start of one of these.
 */
const PIP_LONG: readonly [string, boolean][] = [
  ["--index-url", true], ["--pypi-url", true], ["--extra-index-url", true], ["--no-index", false], ["--constraint", true],
  ["--requirement", true], ["--editable", true], ["--find-links", true], ["--no-binary", true], ["--only-binary", true],
  ["--prefer-binary", false], ["--require-hashes", false], ["--no-require-hashes", false], ["--pre", false],
  ["--all-releases", true], ["--only-final", true], ["--trusted-host", true], ["--use-feature", true], ["--hash", true],
  ["--config-settings", true],
];
/** pip's short options in a requirements file, each taking a value: -i, -c, -r, -e, -f, -C. */
const PIP_SHORT = new Set(["i", "c", "r", "e", "f", "C"]);

/** A URL scheme at the start (`file:pkgdir`, `git+https:`): pip reads such a line as a URL, not as a name. */
const URL_SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:/;
/** pip's ARCHIVE_EXTENSIONS (pip/_internal/utils/filetypes.py): a line ending in one is a path to an archive. */
const ARCHIVE = /\.(zip|whl|tar\.bz2|tbz|tar\.xz|txz|tlz|tar\.lz|tar\.lzma|tar\.gz|tgz|tar)$/i;

/**
 * Might pip or uv read this as a requirement? False only when it is certainly not one: not a path or URL (a "/", a
 * "\\", a leading ".", "://", "@" or an archive name, which pip reads as a path or URL), no "${" (pip expands it
 * first), and not `name [extras] [version specifiers] [; marker]` by PEP 508's grammar. A linear scan.
 */
export function mayBeRequirement(text: string): boolean {
  const a = text.trim();
  if (a === "" || a.includes("${") || /[/\\]|:\/\/|@/.test(a) || a.startsWith(".") || URL_SCHEME.test(a) || ARCHIVE.test(a)) return true;
  const n = a.length;
  let i = 0;
  const alnum = (c: string | undefined): boolean => c !== undefined && /[A-Za-z0-9]/.test(c);
  const ws = (): void => {
    while (i < n && /\s/.test(a[i]!)) i++;
  };
  const name = (): boolean => {
    if (!alnum(a[i])) return false;
    const start = i;
    while (i < n && /[A-Za-z0-9._-]/.test(a[i]!)) i++;
    return i > start && alnum(a[i - 1]);
  };
  if (!name()) return false;
  ws();
  if (a[i] === "[") {
    i++;
    ws();
    if (a[i] !== "]") {
      for (;;) {
        if (!name()) return false;
        ws();
        if (a[i] === ",") {
          i++;
          ws();
          continue;
        }
        break;
      }
    }
    if (a[i] !== "]") return false;
    i++;
    ws();
  }
  if (i === n || a[i] === ";") return true;
  const paren = a[i] === "(";
  if (paren) {
    i++;
    ws();
  }
  for (;;) {
    const op = ["===", "~=", "==", "!=", "<=", ">=", "<", ">"].find((o) => a.startsWith(o, i));
    if (op === undefined) return false;
    i += op.length;
    ws();
    const start = i;
    while (i < n && !/[\s,;()]/.test(a[i]!)) i++;
    if (i === start) return false;
    ws();
    if (a[i] !== ",") break;
    i++;
    ws();
  }
  if (paren) {
    if (a[i] !== ")") return false;
    i++;
    ws();
  }
  return i === n || a[i] === ";";
}

/** Might pip or uv accept these option tokens? False when one is an option neither has (pip: "no such option"). */
function mayBeOptions(tokens: string[]): boolean {
  for (let k = 0; k < tokens.length; k++) {
    const tok = tokens[k]!.replace(QUOTES_AND_BACKSLASHES, "");
    // pip ignores words that are not options (optparse leaves them as arguments), and "--" ends the options.
    if (!tok.startsWith("-") || tok === "-") continue;
    if (tok === "--") return true;
    if (tok.startsWith("--")) {
      const eq = tok.indexOf("=");
      const flag = eq === -1 ? tok : tok.slice(0, eq);
      const known = PIP_LONG.filter(([o]) => o.startsWith(flag));
      if (known.length === 0) return false;
      // The value is the next word when it is not attached: it is not an option, whatever it starts with.
      if (eq === -1 && known.some(([, v]) => v)) k++;
    } else {
      if (!PIP_SHORT.has(tok[1]!)) return false;
      if (tok.length === 2) k++;
    }
  }
  return true;
}

/**
 * A character other than a tab, a line feed, a carriage return followed by a line feed, and printable ASCII
 * (U+0020-U+007E). Python and JavaScript disagree on what whitespace is exactly there: str.strip(), str.isspace() and
 * `\s` in pip's patterns also take U+001C-U+001F, U+0085, U+00A0 and the other Unicode spaces, which a JavaScript
 * .trim() and `\s` take only in part (not U+001C-U+001F or U+0085), and JavaScript takes U+FEFF, which Python does not; and
 * str.splitlines also splits on "\r", "\x0b", "\x0c", "\x1c"-"\x1e", "\x85", U+2028 and U+2029. How pip splits a
 * line, strips it, finds a comment and decides whether a line ending in "\" is joined to the next all depend on
 * that, so outside this set refusedText cannot tell what pip reads, and it is not sure.
 */
const NOT_PLAIN = /[^\t\n\r\x20-\x7e]|\r(?!\n)/;

/**
 * True when some line of the text, comments dropped and continued lines joined, is certainly refused (see below).
 * False for the whole text when it holds any character NOT_PLAIN matches.
 */
function refusedText(text: string): boolean {
  if (NOT_PLAIN.test(text)) return false;
  // A continued line outside the one shape the reader joins (requirements.ts continuation): pip joins it to the next
  // line, uv may not (`--require-hashes\` then `evil==0.0.1`: pip refuses the joined option, uv installs evil). Not
  // sure, so the reader decides.
  let continuing = false;
  for (const line of text.split("\n")) {
    const next = continuation(line.endsWith("\r") ? line.slice(0, -1) : line, continuing);
    if ("problem" in next) return false;
    continuing = next.continuing;
  }
  for (const raw of pipLogicalLines(text)) {
    // pip's ignore_comments: a "#" at the start or after whitespace starts a comment.
    const line = raw.replace(/(^|\s)#.*$/s, "").trim();
    if (line === "" || line.includes("${")) continue;
    const readings = [/(?:^| )-/, /(?:^|\s)-/].map((re) => {
      const at = line.search(re);
      const start = at === -1 ? line.length : at === 0 && line.startsWith("-") ? 0 : at + 1;
      return { args: line.slice(0, start), options: line.slice(start) };
    });
    if (readings.every((r) => !mayBeRequirement(r.args) || !mayBeOptions(r.options.split(/\s+/).filter((t) => t !== "")))) return true;
  }
  return false;
}

/**
 * Would pip and uv both refuse this file as a requirements file? True when, read as pip decodes it, some line, comments
 * dropped and continued lines joined, is certainly neither a requirement nor options the reader accepts, taken both
 * ways a line splits into a requirement and options (pip splits on spaces only, uv on any whitespace). False whenever
 * it cannot be sure: a coding line naming any codec but plain UTF-8 or ASCII (PLAIN_CODECS: `# coding: idna` changes
 * the text pip reads) or an opaque one; a text holding a character other than a tab, a line feed, a carriage return
 * followed by a line feed and U+0020-U+007E, where Python's whitespace, line breaks and comments differ from
 * JavaScript's (NOT_PLAIN: one U+001F at the start of a line is whitespace pip strips, so "\x1fidna==3.10" is a
 * requirement pip installs); a line continued with "\" in any shape but the one pip-compile writes, which pip joins
 * to the next line and uv may not; "${" on the line. A linear scan.
 * It never hides a file: discovery (src/python/discover.ts) reports a file it calls refused as one high WS-SK-002 for
 * the whole file, keyed on its content, instead of reading the file's packages, so being wrong only changes which
 * high findings a file gives.
 */
export function refusedByPipAndUv(buf: Buffer): boolean {
  const view = pipView(buf);
  if ("opaque" in view) return false;
  // pip reads a coding line only when no byte-order mark decided the encoding first.
  const bom = (buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) || (buf[0] === 0xff && buf[1] === 0xfe) || (buf[0] === 0xfe && buf[1] === 0xff) || (buf[0] === 0 && buf[1] === 0 && buf[2] === 0xfe && buf[3] === 0xff);
  const named = bom ? undefined : codingLine(buf);
  if (named !== undefined && !PLAIN_CODECS.has(named.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, ""))) return false;
  return refusedText(view.text);
}

/** What a chunked read of a file larger than CONTENT_LIMIT found. */
export interface LargeScan {
  /** A line that is exactly `# /// script`. */
  tag: boolean;
  /** The bytes of a hash or require-hashes option (`--h` or `--r` after "--", quotes and backslashes dropped), a byte-order mark, or an opaque coding line. */
  requirements: boolean;
}

/**
 * Reads a regular file of at most `maxBytes` (without following a final symlink) one chunk at a time, so memory stays
 * at one chunk whatever its size, and reports whether it may be a PEP 723 script or a requirements file: what decides
 * whether discovery reads it in full. Over-inclusive: `--recursive` counts as a candidate, and the full read decides.
 */
export function scanLargeFile(path: string, maxBytes: number): LargeScan | { problem: string } {
  const CHUNK = 1024 * 1024;
  return withRegularFile(path, maxBytes, (fd) => {
    const out: LargeScan = { tag: false, requirements: false };
    const buf = Buffer.alloc(TAG_BYTES.length + 1 + CHUNK);
    /** Bytes kept from the end of the previous chunk, so a tag line split across two chunks is seen whole. */
    let kept = 0;
    let first = true;
    /** "-" seen in a row, quotes and backslashes skipped (0, 1 or 2). */
    let dashes = 0;
    for (;;) {
      const n = readSync(fd, buf, kept, CHUNK, null);
      if (n === 0) break;
      const chunk = buf.subarray(0, kept + n);
      if (first) {
        // A UTF-16 or UTF-32 byte-order mark, or a coding line naming an opaque codec: its text is not in its bytes.
        const bom = (chunk[0] === 0xff && chunk[1] === 0xfe) || (chunk[0] === 0xfe && chunk[1] === 0xff) || (chunk[0] === 0 && chunk[1] === 0 && chunk[2] === 0xfe && chunk[3] === 0xff);
        if (bom || "opaque" in pipView(chunk)) out.requirements = true;
      }
      // A tag at the very start of a later chunk began mid-line in the file: only the first chunk starts a line there.
      for (let at = chunk.indexOf(TAG_BYTES); at !== -1 && !out.tag; at = chunk.indexOf(TAG_BYTES, at + 1)) {
        const before = at === 0 ? (first ? LF : undefined) : chunk[at - 1];
        const end = at + TAG_BYTES.length;
        if (end === chunk.length && n === CHUNK) continue; // the line may go on in the next chunk; seen there whole
        const after = end === chunk.length ? LF : chunk[end];
        if ((before === LF || before === CR) && (after === LF || after === CR)) out.tag = true;
      }
      for (let i = kept; i < chunk.length && !out.requirements; i++) {
        const b = chunk[i]!;
        if (b === 0x22 || b === 0x27 || b === 0x5c) continue;
        if (dashes === 2 && (b === 0x68 || b === 0x72)) out.requirements = true;
        else if (b === 0x2d) dashes = Math.min(dashes + 1, 2);
        else dashes = 0;
      }
      if (out.tag && out.requirements) break;
      kept = Math.min(TAG_BYTES.length + 1, chunk.length);
      chunk.copy(buf, 0, chunk.length - kept);
      first = false;
    }
    return out;
  });
}
