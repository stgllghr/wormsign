/**
 * Requirements files read as hash locks: a file and the files it includes with -r/-c, judged as one unit.
 *
 * The text is read the way pip 26.2.1 reads it (pip/_internal/req/req_file.py: _decode_req_file, preprocess,
 * join_lines, ignore_comments, break_args_options, the optparse options), so what wormsign checks is what pip
 * installs. Wherever pip and uv read a file differently, or pip would expand or ignore something, the reader reports
 * a problem instead of choosing one reading:
 *
 * Text, before parsing (each a problem with its line number):
 * - a UTF-8 byte-order mark is dropped, as pip does. A UTF-16 or UTF-32 one, a NUL byte, bytes that are not UTF-8
 *   (pip would fall back to the locale's encoding) and a PEP 263 coding line naming anything but UTF-8 in the first
 *   two lines (pip would decode with it) are "encoding not supported";
 * - pip splits lines with Python's str.splitlines, uv does not: "\x0b", "\x0c", "\x1c"-"\x1e", "\x85", U+2028 and
 *   U+2029 are "a line separator pip and uv read differently", and every other C0 control character except "\t" is
 *   "a control character pip and uv read differently". A "\r" not followed by "\n" is refused too, as a line break
 *   other than "\n" and "\r\n" (pip 26.2.1 and both uvs were seen to split it alike). Other Unicode whitespace
 *   (U+00A0, U+1680, U+2000-U+200A, U+202F, U+205F, U+3000) is whitespace to pip (it starts a comment, it is
 *   stripped) and an error to uv: also a problem. So is a tab before an option, which pip reads as part of the
 *   requirement and uv as a separator. test/fixtures/python/requirements records each of these readings;
 * - then, as pip does: split on "\n" and "\r\n", join lines ending in "\", drop comments, and refuse "${" (pip would
 *   expand an environment variable there; wormsign never does). Every step is a linear scan.
 *
 * The lock rule. The unit is a lock only if:
 * - some option line in it, in a file not reached through -c, is `--require-hashes`. pip honours the line anywhere in
 *   the unit. uv 0.12.21 honours it in the file and in files reached with -r, and ignores it in a file reached with
 *   -c (its parser keeps only the requirements of a constraints file); uv 0.10.9 ignores it everywhere with a
 *   warning. test/fixtures/python/requirements/uv-pip-sync.json records all three;
 * - every requirement line, in every file of the unit (constraint files included), is `name[extras]==version` with an
 *   optional `; marker`, a PEP 440 version without a local label or wildcard, and at least one `--hash=sha256:<hex>`.
 *   Every hash on the line must be sha256: pip installs a file that matches any one listed hash, and wormsign binds
 *   sha256 digests only, so a sha384 or sha512 digest would name a file it cannot bind to an index file;
 * - the only options are --hash (on a requirement line), --require-hashes, and -r/--requirement or -c/--constraint
 *   naming a file inside the root, each on a line of its own. Includes are always followed, relative to the
 *   including file's directory, as pip does. Everything else (-i, --extra-index-url, -f, --trusted-host,
 *   --no-binary, --only-binary, --prefer-binary, --config-settings, -e, --no-index, ...) is a problem, and so is an
 *   option written in an abbreviated form, a quote or backslash in options, and text optparse would ignore.
 * Includes pip and uv read differently are problems too: a value attached to -r or -c (pip reads "-r=x" as the file
 * "=x", uv as "x", and uv refuses "-rx"), a "#" in an include's path (uv ends the path there, pip does not), and -r in
 * a file reached through -c (pip installs that file's lines as requirements, uv reads them as constraints).
 * Each violation is a problem naming the file and line, with how to fix it. A file holding nothing but blank lines and
 * comments is `empty`, with no problems.
 *
 * Limits, so a hostile file cannot exhaust memory or time: each file at most 64 MiB, and one unit at most 64 MiB read,
 * 1,000 file reads, 100,000 lines after joining and dropping comments, and 200 problems (includes count each time
 * they are read, as pip reads them each time). Reaching a limit is a problem, and reading stops there.
 *
 * Each problem has, in `covers` (the same index), the sha256 of the content it is about, so that a baseline entry for
 * it approves that content only: a problem with one line covers that line's text (after joining and dropping its
 * comment); a file that could not be decoded or split into lines covers the file's bytes; a limit that stopped the
 * reading covers every byte the unit read; a missing `--require-hashes` line covers nothing ("": it drops no entry,
 * and every line without a hash is a problem of its own); a file that could not be read covers nothing.
 *
 * Index options. pip applies -i, --extra-index-url, -f and --no-index (and their abbreviations) to the whole install,
 * from whichever file of the unit holds them. Every such option is refused above, and so is every line whose options
 * were not read to the end, every include not followed and every file not read in full: any of them may name another
 * index. Each is listed in `indexOptions`, and discovery (src/python/discover.ts) then sends none of the unit's names
 * anywhere.
 */
import { createHash } from "node:crypto";
import { lstatSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, join, posix, relative, resolve, sep } from "node:path";
import { readBytes } from "../fsutil.js";
import { isHexDigest } from "./filenames.js";
import { isValidName, normalizeName } from "./names.js";
import { formatVersion, parseVersion } from "./pep440.js";
import { MAX_ARCHIVE_BYTES, sha256File } from "./local.js";
import { checkLocalPath } from "./paths.js";

export interface RequirementEntry {
  /** "/"-separated path relative to the root. */
  file: string;
  /** Line of the requirement (the first line, when continued with "\"). */
  line: number;
  /** PEP 503-normalised. */
  name: string;
  extras: string[];
  /** Canonical PEP 440 version. */
  version: string;
  /** The version as written after "==". */
  rawVersion: string;
  marker?: string;
  /** Digests by algorithm (sha256, sha384, sha512), lowercase hex. */
  hashes: Record<string, string[]>;
  /** The sha256 digests, the ones wormsign binds. */
  sha256: string[];
  /** From a file included with -c. */
  constraint: boolean;
}

export interface RequirementsUnit {
  /** The file read, relative to the root. */
  file: string;
  /** Every file read for the unit, the root file first. */
  files: string[];
  /** Where --require-hashes is, in a file not reached through -c, if anywhere. */
  requireHashes?: { file: string; line: number };
  entries: RequirementEntry[];
  /** Each as "<file>:<line>: <what>; <how to fix it>". */
  problems: string[];
  /** For each problem, the sha256 of the content it is about (see the module comment); "" when it covers nothing. */
  covers: string[];
  /** For each problem, its "<how to fix it>" ("" for none): soak keys the finding without it, so a reworded fix keeps it. */
  fixes: string[];
  /**
   * For each problem, what the lock rule refused, where the fix is to make the file a hash lock (LOCK_REMEDIATION, or
   * for a file whose requirements all have their hashes requireHashesRemedy): "line" for a line (a requirement that is
   * not `name==version` with a sha256 --hash, or an option a lock does not allow), "file" for the missing
   * --require-hashes line, undefined for any other problem.
   */
  lockRule: ("line" | "file" | undefined)[];
  /**
   * For each problem, why no baseline entry may approve it, or undefined when one may: approvable decides, and only a
   * line soak positively understands opts in.
   */
  unapprovable: (string | undefined)[];
  /**
   * Where the unit's own text may name another index: an index option, a line whose options were not all read, an
   * include not followed, a file not read in full. `option` is what was found there.
   */
  indexOptions: { file: string; line?: number; option: string }[];
  /** The root file holds only blank lines and comments. */
  empty: boolean;
  /**
   * Every line read, as pip's line parser yields it: includes expanded in place and the -r/-c lines themselves left
   * out. A line whose options are refused is not here (it is a problem). For comparing with pip's own parser.
   */
  lines: (ParsedLine & { file: string })[];
}

/** One logical line as pip's line parser sees it: the requirement text and the options after it. */
export interface ParsedLine {
  line: number;
  args: string;
  options: { name: "hash" | "require-hashes" | "requirement" | "constraint"; value?: string }[];
}

export const LOCK_REMEDIATION = "make the file a hash lock: regenerate it with `uv pip compile --generate-hashes` or `pip-compile --generate-hashes`, then add a `--require-hashes` line";
/**
 * The fix for a file whose every requirement already has its hashes and that lacks only the --require-hashes line: that
 * line alone makes it a hash lock (pip applies it to the files the file includes too). Regenerating stays the second
 * option.
 */
export const requireHashesRemedy = (file: string): string => `add a \`--require-hashes\` line at the top of ${file}, or ${LOCK_REMEDIATION}`;
const TEXT_REMEDIATION = "save it as UTF-8 with \\n or \\r\\n line endings";

/** The largest requirements file read, and the most bytes one unit reads in all (includes counted each time). */
export const MAX_REQUIREMENTS_BYTES = 64 * 1024 * 1024;
/** Most files one unit may read, includes counted each time they are reached. */
const MAX_UNIT_FILES = 1000;
/** Most lines one unit may read, counted after continuation lines are joined and comments and blank lines dropped. */
export const MAX_UNIT_LINES = 100_000;
/** Most problems listed for one unit; reading stops at the next one. */
export const MAX_UNIT_PROBLEMS = 200;

/** Python's whitespace (str.isspace(), and `\s` in a str pattern). */
const isPyWs = (c: number): boolean =>
  (c >= 0x09 && c <= 0x0d) || (c >= 0x1c && c <= 0x20) || c === 0x85 || c === 0xa0 || c === 0x1680 || (c >= 0x2000 && c <= 0x200a) || c === 0x2028 || c === 0x2029 || c === 0x202f || c === 0x205f || c === 0x3000;
const isBlank = (c: number): boolean => c === 0x20 || c === 0x09;
const isBackslash = (c: number): boolean => c === 0x5c;

/** Strips the characters `drop` matches from both ends: one pass each way, so linear (a regex like /x+$/ is not). */
function strip(t: string, drop: (c: number) => boolean): string {
  let a = 0;
  let b = t.length;
  while (a < b && drop(t.charCodeAt(a))) a++;
  while (b > a && drop(t.charCodeAt(b - 1))) b--;
  return t.slice(a, b);
}

/** pip's COMMENT_RE.match: the line starts with optional whitespace and a "#". */
function isCommentLine(l: string): boolean {
  let i = 0;
  while (i < l.length && isPyWs(l.charCodeAt(i))) i++;
  return l.charCodeAt(i) === 0x23;
}

/** pip's ignore_comments for one line: cut at the first "#" at the start or after whitespace, then strip. */
function dropComment(t: string): string {
  let end = t.length;
  for (let i = t.indexOf("#"); i !== -1; i = t.indexOf("#", i + 1)) {
    if (i === 0 || isPyWs(t.charCodeAt(i - 1))) {
      end = i;
      break;
    }
  }
  return strip(t.slice(0, end), isPyWs);
}
/** Characters Python's str.splitlines splits on and uv does not (besides "\n" and "\r\n"). */
// eslint-disable-next-line no-control-regex -- matching control characters is the point
const SEPARATOR = /\r(?!\n)|[\x0b\x0c\x1c-\x1e\x85\u2028\u2029]/;
/** The other C0 control characters, "\t" aside. */
// eslint-disable-next-line no-control-regex -- matching control characters is the point
const CONTROL = /[\x00-\x08\x0e-\x1b\x1f]/;
const OTHER_SPACE = /[\xa0\u1680\u2000-\u200a\u202f\u205f\u3000]/;
const UTF8_NAMES = new Set(["utf_8", "utf8", "u8", "utf", "utf8_ucs2", "utf8_ucs4", "cp65001"]);

/** The first "#" that starts a comment for pip (COMMENT_RE: at the start or after whitespace), or -1. */
function commentStart(t: string): number {
  for (let i = t.indexOf("#"); i !== -1; i = t.indexOf("#", i + 1)) if (i === 0 || isPyWs(t.charCodeAt(i - 1))) return i;
  return -1;
}
/** A line ending in "\\" whose last character before its run of backslashes is not whitespace. */
function gluedBackslash(l: string): boolean {
  let i = l.length;
  while (i > 0 && isBackslash(l.charCodeAt(i - 1))) i--;
  return i > 0 && i < l.length && !isPyWs(l.charCodeAt(i - 1));
}
/** A comment on a line continued with "\\": the two readings (test/fixtures/python/requirements/continued). */
export const CONTINUED_COMMENT =
  'a comment ("#" at the start or after a space) on a line that ends in "\\": pip joins the next line into the comment, so never installs what it names, while uv ends the comment at the line break and reads the next line on its own';
/** An option continued with "\\": the two readings (the same fixture). */
export const CONTINUED_OPTION =
  'an option on a line that ends in "\\": pip joins the next line to it, while uv reads the option\'s value to the line break, the spaces and "\\" included (`-r a.txt \\` names the file "a.txt "), so the two can read different files or settings';
/** A "\\" glued to the text before it at the end of a requirement or hash line: the two readings (the same fixture). */
export const GLUED_BACKSLASH =
  'a "\\" with no space before it at the end of a line: pip joins the next line to the text before it, so the two read as one (a hash, a version), while uv does not join them and reads the next line on its own';
/** Any other continued line: outside the shape pip-compile and uv pip compile write. */
export const CONTINUED_SHAPE =
  'a line continued with "\\" outside the shape pip-compile and uv pip compile write (a requirement ending in " \\", then --hash=sha256:<64 hex digits> lines): pip joins every such line to the next, while uv reads some up to the line break, so the two can read different packages';
const OPTION_FIX = 'write the option and its value on one line, with no "\\"';
const SHAPE_FIX = 'write the requirement and its --hash options on one line, or continue it as pip-compile does (" \\", then --hash=sha256: lines)';
/** A --hash line under a continued requirement, as pip-compile and uv pip compile write it; itself continued or not. */
const HASH_CONTINUATION = /^ *--hash=sha256:[0-9a-f]{64}(?: +\\)?$/;

/**
 * What a physical line (its "\r" dropped) does to a continuation (pip joins a line ending in "\\" to the next):
 * whether the line after it continues this one, or why the file is refused. An allowlist, as approvable is: only the
 * shape pip-compile and uv pip compile write is read, a requirement (not an option) ending in a space and one "\\",
 * then --hash=sha256:<digest> lines indented with spaces, each but the last ending so. Anything else continued (an
 * option, whose value uv reads to the line break; a comment; a "\\" glued to the text; a doubled "\\"; a tab, which
 * pip does not split on; a line that is not such a hash) pip and uv may read apart. A comment line ending in "\\"
 * continues nothing, for either.
 */
export function continuation(l: string, continuing: boolean): { continuing: boolean } | { problem: string; fix: string } {
  if (continuing) return HASH_CONTINUATION.test(l) ? { continuing: l.endsWith("\\") } : { problem: CONTINUED_SHAPE, fix: SHAPE_FIX };
  if (!l.endsWith("\\") || isCommentLine(l)) return { continuing: false };
  // pip strips the leading backslashes of the piece it joins, so "\\#" counts.
  if (commentStart(strip(l, isBackslash)) !== -1) return { problem: CONTINUED_COMMENT, fix: "put the comment on a line of its own" };
  if (strip(l, isPyWs).startsWith("-")) return { problem: CONTINUED_OPTION, fix: OPTION_FIX };
  if (gluedBackslash(l)) return { problem: GLUED_BACKSLASH, fix: SHAPE_FIX };
  if (l.startsWith("\\") || !l.endsWith(" \\")) return { problem: CONTINUED_SHAPE, fix: SHAPE_FIX };
  return { continuing: true };
}
/** Lines, or a problem: `limit` when the problem is reaching maxLines. */
type TextResult = { lines: { line: number; text: string }[] } | { problem: string; line?: number; limit?: true; fix?: string };

/** Decodes a requirements file's bytes as pip does, refusing what pip and uv would read differently. */
export function decodeRequirements(bytes: Uint8Array): { text: string } | { problem: string; line?: number } {
  let data = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const startsWith = (...b: number[]): boolean => b.every((x, i) => data[i] === x);
  const bom = startsWith(0xef, 0xbb, 0xbf);
  if (!bom && (startsWith(0x00, 0x00, 0xfe, 0xff) || startsWith(0xff, 0xfe) || startsWith(0xfe, 0xff))) {
    return { problem: "encoding not supported: it starts with a UTF-16 or UTF-32 byte-order mark" };
  }
  if (bom) data = data.subarray(3);
  const nul = data.indexOf(0);
  if (nul !== -1) return { problem: "encoding not supported: it contains a NUL byte", line: data.subarray(0, nul).toString("latin1").split("\n").length };
  if (!bom) {
    // pip decodes with a PEP 263 coding declaration found on either of the first two lines that start with "#".
    const firstEnd = data.indexOf(0x0a);
    const secondEnd = firstEnd === -1 ? -1 : data.indexOf(0x0a, firstEnd + 1);
    const firstTwo = data.subarray(0, secondEnd === -1 ? data.length : secondEnd).toString("latin1").split("\n");
    for (const l of firstTwo) {
      if (!l.startsWith("#")) continue;
      const m = /coding[:=][ \t\n\r\f\v]*([-\w.]+)/.exec(l);
      if (m && !UTF8_NAMES.has(m[1]!.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, ""))) {
        return { problem: `encoding not supported: a coding declaration names ${JSON.stringify(m[1])}, and pip would decode the file with it` };
      }
    }
  }
  try {
    return { text: new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data) };
  } catch {
    return { problem: "encoding not supported: it is not valid UTF-8 (pip would fall back to the locale's encoding)" };
  }
}

/**
 * pip's preprocess (join continuation lines, drop comments, skip blank lines), after the separator checks. More than
 * `maxLines` lines left at the end is a problem.
 */
export function preprocessRequirements(text: string, maxLines = Infinity): TextResult {
  const lineAt = (i: number): number => text.slice(0, i).split("\n").length;
  const sepAt = text.search(SEPARATOR);
  if (sepAt !== -1) {
    // pip 26.2.1, uv 0.10.9 and uv 0.12.21 were seen to split a bare "\r" alike (test/fixtures/python/requirements),
    // so it is refused as a line break other than "\n" and "\r\n", not as one they are known to disagree on.
    const problem = text[sepAt] === "\r" ? "a carriage return not followed by a line feed: only \\n and \\r\\n line breaks are read" : `a line separator pip and uv read differently (${charName(text[sepAt]!)})`;
    return { problem, line: lineAt(sepAt) };
  }
  const controlAt = text.search(CONTROL);
  if (controlAt !== -1) return { problem: `a control character pip and uv read differently (${charName(text[controlAt]!)})`, line: lineAt(controlAt) };
  const spaceAt = text.search(OTHER_SPACE);
  if (spaceAt !== -1) return { problem: `a Unicode space character (${charName(text[spaceAt]!)}) that pip reads as whitespace and uv rejects`, line: lineAt(spaceAt) };

  // Physical lines, split on "\n" with one "\r" before it dropped, read one at a time (no array of every line).
  // join_lines: a line ending in "\" (and not a comment) is joined to the next, in the one shape continuation allows;
  // the joined line keeps the first line's number; pip removes every leading and trailing backslash of a continued
  // line. Then ignore_comments, then the "${" check pip's expand_env_variables makes necessary.
  const lines: { line: number; text: string }[] = [];
  let problem: { problem: string; line: number; limit?: true; fix?: string } | undefined;
  const logical = (line: number, joined: string): void => {
    const t = dropComment(joined);
    if (t === "") return;
    if (t.includes("${")) problem = { problem: "\"${\": pip expands environment variables written ${NAME}, and wormsign never does", line };
    else if (lines.length >= maxLines) problem = { problem: `more than ${maxLines} lines`, line, limit: true };
    else lines.push({ line, text: t });
  };
  // A continued line's pieces, joined 4,096 at a time so a million short lines are not a million strings.
  let pieces: string[] = [];
  let chunks: string[] = [];
  let continuing = false;
  let first = 0;
  const joined = (): string => {
    const all = chunks.join("") + pieces.join("");
    pieces = [];
    chunks = [];
    continuing = false;
    return all;
  };
  for (let pos = 0, n = 1; pos < text.length && problem === undefined; n++) {
    const nl = text.indexOf("\n", pos);
    let l = nl === -1 ? text.slice(pos) : text.slice(pos, nl);
    pos = nl === -1 ? text.length : nl + 1;
    if (l.endsWith("\r")) l = l.slice(0, -1);
    const next = continuation(l, continuing);
    if ("problem" in next) problem = { problem: next.problem, line: n, fix: next.fix };
    else if (!next.continuing) {
      if (continuing) logical(first, joined() + l);
      else logical(n, l);
    } else {
      if (!continuing) first = n;
      continuing = true;
      pieces.push(strip(l, isBackslash));
      if (pieces.length >= 4096) {
        chunks.push(pieces.join(""));
        pieces = [];
      }
    }
  }
  if (continuing && problem === undefined) logical(first, joined());
  return problem ?? { lines };
}

const charName = (c: string): string => `U+${c.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}`;

/**
 * pip's break_args_options: the line split on " " only, words up to the first that starts with "-" are the
 * requirement and the rest the options. A word starts at the line's start or after a " ", so this finds the first "-"
 * there instead of splitting (a line of a million spaces would be a million words).
 */
function breakArgsOptions(line: string): { args: string; options: string } {
  for (let j = line.indexOf("-"); j !== -1; j = line.indexOf("-", j + 1)) {
    if (j === 0) return { args: "", options: line };
    if (line.charCodeAt(j - 1) === 0x20) return { args: line.slice(0, j - 1), options: line.slice(j) };
  }
  return { args: line, options: "" };
}

const LONG: Record<string, ParsedLine["options"][number]["name"]> = { "--hash": "hash", "--require-hashes": "require-hashes", "--requirement": "requirement", "--constraint": "constraint" };
const SHORT: Record<string, ParsedLine["options"][number]["name"]> = { "-r": "requirement", "-c": "constraint" };
const TAKES_VALUE = new Set(["hash", "requirement", "constraint"]);

/**
 * Tokenises and reads the options of one line, accepting only the options a lock may use, written in full. A problem
 * may carry its own fix.
 */
export function parseLine(line: { line: number; text: string }): { parsed: ParsedLine } | { problem: string; fix?: string; option: string } {
  const { args, options } = breakArgsOptions(line.text);
  const parsed: ParsedLine = { line: line.line, args, options: [] };
  if (options === "") return { parsed };
  if (/["'\\]/.test(options)) return { problem: "a quote or backslash in the options, which pip reads with shell quoting rules; write the options plainly", option: "options written with quotes or backslashes" };
  const tokens = options.split(/[ \t\r\n]+/).filter((t) => t !== "");
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i]!;
    let name: ParsedLine["options"][number]["name"] | undefined;
    let value: string | undefined;
    if (tok.startsWith("--")) {
      const eq = tok.indexOf("=");
      const flag = eq === -1 ? tok : tok.slice(0, eq);
      name = Object.hasOwn(LONG, flag) ? LONG[flag] : undefined;
      if (name === undefined) return { problem: tok === "--" ? "\"--\": pip ignores everything after it" : `option ${flag} is not allowed in a hash lock`, option: flag };
      if (eq !== -1) value = tok.slice(eq + 1);
    } else if (tok.startsWith("-") && tok.length > 1) {
      const flag = tok.slice(0, 2);
      name = Object.hasOwn(SHORT, flag) ? SHORT[flag] : undefined;
      if (name === undefined) return { problem: `option ${flag} is not allowed in a hash lock`, option: flag };
      // pip reads "-r=x" as the file "=x", uv as "x" ("=" separates there), and uv refuses "-rx".
      if (tok.length > 2) return { problem: `${tok}: a value attached to ${flag}, which pip and uv read differently ("=" is part of the path to pip and a separator to uv)`, fix: `write "${flag} <path>"`, option: flag };
    } else {
      return { problem: `${JSON.stringify(tok)} after the options: pip ignores it`, option: tok };
    }
    if (TAKES_VALUE.has(name)) {
      if (value === undefined) {
        value = tokens[++i];
        if (value === undefined) return { problem: `option ${tok} needs a value`, option: tok };
      }
      parsed.options.push({ name, value });
    } else {
      if (value !== undefined) return { problem: `option --${name} takes no value`, option: tok };
      parsed.options.push({ name });
    }
  }
  return { parsed };
}

const STRONG = new Set(["sha256", "sha384", "sha512"]);
const ARCHIVE = /\.(zip|whl|tar\.bz2|tbz|tar\.xz|txz|tlz|tar\.lz|tar\.lzma|tar\.gz|tgz|tar)$/i;
const PIN = /^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)[ \t]*(?:\[([^\]]*)\])?[ \t]*(.*)$/s;
/** PEP 440 version specifiers, comma-separated, or none: what a plain index requirement may hold after its name. */
const SPECIFIERS = /^(?:(?:~=|===|==|!=|<=|>=|<|>)[ \t]*[A-Za-z0-9._+!*-]+[ \t]*(?:,[ \t]*(?:~=|===|==|!=|<=|>=|<|>)[ \t]*[A-Za-z0-9._+!*-]+[ \t]*)*)?$/;

/**
 * What soak understood a problem's line to be, for approvable: (a) a plain index requirement it parsed to the end (a
 * name, extras, a marker and specifiers, with nothing but the hash options it reads); or (b) a local file, with what
 * was found at each place pip may look.
 */
export type ApprovalBasis = { kind: "index-requirement"; name: string } | { kind: "local-file"; places: LocalFileState[] };

/**
 * May a baseline entry approve a requirements problem? No, by default (ADR 0001): a problem's key covers its line,
 * and only for a line soak positively understands does that line fix what an install fetches. So only:
 * - (a) a plain index requirement soak parsed to the end (ApprovalBasis "index-requirement"), whose name as written
 *   (not normalized, which turns its dots into dashes) is not an archive's file name (pip installs
 *   `foo-1.0-py3-none-any.whl[x]` from that file);
 * - (b) a local file every place of which soak resolved to a regular file inside the root, keyed by its sha256, or to
 *   nothing (missing), and at least one to a file: a path missing at every place, a directory, or one soak cannot pin
 *   (localFileState's unkeyable cases) does not qualify.
 * Anything else (an option, an include, `${`, a line soak could not split or parse, a halt, and the missing
 * --require-hashes line, which is keyed on no text of the file: REQUIRE_HASHES_WHY) is not approvable.
 */
export function approvable(basis: ApprovalBasis | undefined): boolean {
  if (basis === undefined) return false;
  switch (basis.kind) {
    case "index-requirement":
      return !ARCHIVE.test(basis.name);
    case "local-file":
      return basis.places.some((s) => "key" in s && s.key.startsWith("sha256:")) && basis.places.every((s) => "key" in s && (s.key.startsWith("sha256:") || s.key === "missing"));
  }
}

/**
 * A ".." segment after a named one (a/../b, either separator): pip resolves such a path as text (os.path.abspath), uv
 * joins it as written and the system follows a symlink at "a" first, so ".." climbs from where the link points. soak
 * follows neither reading.
 */
export function climbsAfterName(path: string): boolean {
  let named = false;
  for (const seg of path.split(/[\\/]/)) {
    if (seg === "..") {
      if (named) return true;
    } else if (seg !== "" && seg !== ".") named = true;
  }
  return false;
}
const CLIMB =
  'a ".." after a directory name in the path: pip resolves it as text (a/../b is b), while uv joins the path as written, so the system follows a symlink at a first and ".." climbs from where the link points';
const CLIMB_FIX = 'write the path without ".." after a directory name';

/** Why a halt, and the stop after MAX_UNIT_PROBLEMS, is not approvable: what follows was never read. */
const STOPPED = "the reading stopped here, so what follows was never read";
/** Why a problem no baseline entry may approve is so, for a problem with no reason of its own. */
const NOT_UNDERSTOOD = "soak cannot tell from this line what an install fetches, so an entry for it would approve whatever it comes to name";
/** Why the missing --require-hashes line is not approvable: its key covers no text, so nothing an edit does changes it. */
const REQUIRE_HASHES_WHY = "the missing line is keyed on no text of the file, so an entry would approve it whatever the file comes to hold; the remedy is to add a --require-hashes line to the requirements file itself";

/** Reads a requirement's text as a `name[extras]==version ; marker` pin, or says why it is not one. */
function readPin(args: string): { name: string; rawName: string; extras: string[]; version: string; rawVersion: string; marker?: string } | { problem: string; local?: string; index?: string } {
  const semi = args.indexOf(";");
  const req = strip(semi === -1 ? args : args.slice(0, semi), isPyWs);
  const marker = semi === -1 ? undefined : strip(args.slice(semi + 1), isPyWs);
  // A scheme with no "//" is a URL too: pip installs `file:foo` from the file foo, `git+file:repo` from a repository.
  if (/:\/\/|@|\/|\\/.test(req) || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(req) || req.startsWith(".") || ARCHIVE.test(req)) {
    const local = localTarget(req);
    return { problem: `${JSON.stringify(req)} is a URL, VCS or path requirement, not a name==version pin`, ...(local === undefined ? {} : { local }) };
  }
  if (/\t-/.test(req)) return { problem: `${JSON.stringify(req)}: a tab before an option, which pip reads as part of the requirement and uv as a separator` };
  const m = PIN.exec(req);
  if (!m || !isValidName(m[1]!)) return { problem: `${JSON.stringify(req)} is not a name==version pin` };
  const extras = (m[2] ?? "").split(",").map((e) => strip(e, isBlank)).filter((e) => e !== "");
  if (extras.some((e) => !isValidName(e))) return { problem: `${JSON.stringify(req)} has an invalid extra` };
  const spec = m[3]!;
  // A plain index requirement, read to the end: a name, extras and specifiers soak parsed, and nothing else (approvable).
  const index = SPECIFIERS.test(spec) ? { index: m[1]! } : {};
  const pin = /^==[ \t]*([^ \t,;=<>!~*]+)$/.exec(spec);
  if (!pin) {
    if (spec === "") return { problem: `${JSON.stringify(req)} is not pinned (no ==version)`, ...index };
    if (spec.startsWith("===")) return { problem: `${JSON.stringify(req)} uses ===, which is not a PEP 440 pin`, ...index };
    if (/\*/.test(spec)) return { problem: `${JSON.stringify(req)} uses a wildcard, which is not a pin`, ...index };
    return { problem: `${JSON.stringify(req)} is not pinned with a single ==version`, ...index };
  }
  const parsed = parseVersion(pin[1]!);
  if (!parsed) return { problem: `${JSON.stringify(req)}: ${JSON.stringify(pin[1])} is not a PEP 440 version` };
  if (parsed.local) return { problem: `${JSON.stringify(req)}: a local version label (+...) is never on a public index`, ...index };
  if (marker !== undefined && !/^[\x20-\x7e\t]*$/.test(marker)) return { problem: `${JSON.stringify(req)}: the marker has characters outside printable ASCII` };
  const out: { name: string; rawName: string; extras: string[]; version: string; rawVersion: string; marker?: string } = {
    name: normalizeName(m[1]!),
    rawName: m[1]!,
    extras: extras.map(normalizeName),
    version: formatVersion(parsed),
    rawVersion: pin[1]!,
  };
  if (marker !== undefined && marker !== "") out.marker = marker;
  return out;
}

const posixRel = (root: string, abs: string): string => relative(root, abs).split(sep).join("/");

/**
 * Where a unit's files come from: their bytes, and whether an include may name a path. The disk by default (readBytes,
 * and checkLocalPath: a regular file inside the root, no symlink on the way); PR mode reads the base revision's unit
 * in memory instead (src/python/discover.ts pythonBaseLocks), so nothing of the base is written to disk.
 */
export interface RequirementsSource {
  read(rel: string): { bytes: Uint8Array } | { problem: string };
  include(rel: string): { ok: true } | { ok: false; problem: string };
  /**
   * What a requirement line naming a local file finds at `rel` (inside the root; localFileState). Absent: "not read".
   */
  state?(rel: string): LocalFileState;
}

/** The disk under `root`. */
const diskSource = (root: string): RequirementsSource => ({
  read: (rel) => readBytes(join(root, rel), MAX_REQUIREMENTS_BYTES),
  include: (rel) => {
    const local = checkLocalPath(rel, "file", { root, base: "" });
    return local.ok ? { ok: true } : { ok: false, problem: local.problem };
  },
  state: (rel) => localFileState(root, rel),
});

/**
 * What a requirement line naming a local file finds at `rel`: a `key` when soak can pin it by what it holds, or why
 * not (`unkeyable`), which makes the line's problem one no baseline entry approves: a fixed word for, say, a file
 * outside the root would approve any bytes later put there.
 * - keyed: `sha256:<hex>` of a regular file, with ` via <path>` when symlinks lead there (the target's path inside the
 *   root: pip follows them, so the link and its target are both in the key); `missing` (a file that appears later
 *   changes the key); `directory` (its contents are not in the key: docs/soak.md says so);
 * - unkeyable: a path with a backslash or none a file system opens; a symlink that does not resolve (dangling, a loop)
 *   or leads outside the root; something other than a regular file or directory; a file larger than `maxBytes`
 *   (MAX_ARCHIVE_BYTES, 4 GiB); a file that cannot be read. Never throws.
 */
export type LocalFileState = { key: string } | { unkeyable: string };
export function localFileState(root: string, rel: string, maxBytes: number = MAX_ARCHIVE_BYTES): LocalFileState {
  if (rel === "" || rel === ".") return { key: "directory" };
  if (rel.includes("\\")) return { unkeyable: "its path holds a backslash (a Windows path, which wormsign does not read)" };
  if (rel.length > 4096 || rel.includes("\0")) return { unkeyable: "its path is not one a file system opens" };
  try {
    const abs = join(root, rel);
    if (lstatSync(abs, { throwIfNoEntry: false }) === undefined) {
      // Absent, or under a symlinked directory that leads nowhere: only the first is a state that keys.
      const parts = rel.split("/");
      for (let i = 1; i < parts.length; i++) {
        if (lstatSync(join(root, ...parts.slice(0, i)), { throwIfNoEntry: false })?.isSymbolicLink()) return { unkeyable: "it is reached through a symlink that does not resolve" };
      }
      return { key: "missing" };
    }
    let real: string;
    try {
      real = realpathSync(abs);
    } catch {
      return { unkeyable: "it is a symlink that does not resolve (dangling, or a loop)" };
    }
    const inRoot = relative(realpathSync(root), real);
    if (inRoot === ".." || inRoot.startsWith(`..${sep}`) || isAbsolute(inRoot)) return { unkeyable: "a symlink leads it outside the scanned root" };
    const target = inRoot.split(sep).join("/");
    const via = target === rel ? "" : ` via ${target}`;
    const st = statSync(real);
    if (st.isDirectory()) return { key: `directory${via}` };
    if (!st.isFile()) return { unkeyable: "it is not a regular file" };
    if (st.size > maxBytes) return { unkeyable: `it is larger than ${maxBytes % (1024 * 1024 * 1024) === 0 ? `${maxBytes / (1024 * 1024 * 1024)} GiB` : `${maxBytes} bytes`}` };
    const r = sha256File(real, maxBytes);
    return "sha256" in r ? { key: `sha256:${r.sha256}${via}` } : { unkeyable: "it could not be read" };
  } catch {
    return { unkeyable: "it could not be read" };
  }
}

/**
 * The local file a requirement names, as written: a path (`./wheels/x.whl`, `dist/x.tar.gz`, `x.whl`), or the path of a
 * `file:` URL (`name @ file:wheels/x.whl`, `file:///abs/x.whl`); undefined for a remote URL or a VCS source.
 */
function localTarget(req: string): string | undefined {
  const at = /^[A-Za-z0-9][A-Za-z0-9._-]*[ \t]*(?:\[[^\]]*\])?[ \t]*@[ \t]*(.+)$/s.exec(req);
  const ref = (at ? at[1]! : req).trim();
  if (/^file:/i.test(ref)) {
    // pip reads a file: URL with urlsplit: a #fragment and a ?query are not part of the path.
    let p = ref.slice("file:".length).split("#")[0]!.split("?")[0]!;
    if (p.startsWith("//")) {
      const slash = p.indexOf("/", 2);
      p = slash === -1 ? "" : p.slice(slash);
    }
    try {
      return decodeURIComponent(p);
    } catch {
      return p;
    }
  }
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(ref) && !/^[A-Za-z]:[\\/]/.test(ref)) return undefined;
  return ref.split("#")[0]!;
}

/**
 * Reads the requirements file at `rel` (relative to `root`) and every file it includes, as one unit, from `source`
 * (the disk under `root` by default; `root` also bounds where an include may point). Never throws.
 */
export function readRequirements(root: string, rel: string, source: RequirementsSource = diskSource(root)): RequirementsUnit {
  const unit: RequirementsUnit = { file: rel, files: [], entries: [], problems: [], covers: [], fixes: [], lockRule: [], unapprovable: [], empty: false, lines: [], indexOptions: [] };
  let stopped = false;
  /** Every byte the unit reads, file by file: what a limit that stops the reading covers. */
  const unitHash = createHash("sha256");
  const UNIT = "\0unit";
  const sha = (s: string | Uint8Array): string => createHash("sha256").update(s).digest("hex");
  /**
   * What a problem with a line naming a local file covers: the line and, for each place the file may be (beside the
   * file that names it; from the root; and from the directory of the top-level file and of each file that includes
   * this one, where pip resolves a relative path when run there; an absolute path as it is), what is there
   * (source.state). Tagged, so it never spells the key of a line alone. `unkeyable` says why one of
   * those places cannot be pinned by its content (outside the root, a backslash, localFileState's cases): then no
   * baseline entry may approve the line.
   */
  const localKey = (text: string, fileRel: string, target: string, chain: string[]): { covers: string; places: LocalFileState[]; unkeyable?: string } => {
    const inside = (r: string): string | undefined => (r === ".." || r.startsWith("../") || posix.isAbsolute(r) ? undefined : r);
    const places: [string, string | undefined][] = target.includes("\\")
      ? [["as written", target]]
      : posix.isAbsolute(target)
        ? [["absolute", inside(posixRel(root, target))]]
        : [
            ["beside", inside(posix.normalize(posix.join(posix.dirname(fileRel), target)))],
            ["root", inside(posix.normalize(target))],
            // The directories of the top-level file and of each include on the way (backend/ for backend/requirements.txt).
            ...[...new Set(chain.map((c) => posix.dirname(c)))]
              .filter((d) => d !== "." && d !== posix.dirname(fileRel))
              .map((d): [string, string | undefined] => [`from ${d}`, inside(posix.normalize(posix.join(d, target)))]),
          ];
    let unkeyable: string | undefined;
    const found: LocalFileState[] = [];
    const states = places.map(([where, rel]) => {
      const st: LocalFileState = rel === undefined ? { unkeyable: "it is outside the scanned root" } : (source.state?.(rel) ?? { key: "not read" });
      found.push(st);
      if ("unkeyable" in st) unkeyable ??= `${rel ?? target}: ${st.unkeyable}`;
      return `${where}=${rel ?? ""}:${"key" in st ? st.key : `!${st.unkeyable}`}`;
    });
    return { covers: sha(`local-target-2\0${text}\0${states.join("\0")}`), places: found, ...(unkeyable === undefined ? {} : { unkeyable }) };
  };
  /**
   * A problem; `basis` is what soak understood its line to be (approvable decides from it whether an entry may approve
   * it), `why` the reason when it may not (NOT_UNDERSTOOD by default).
   */
  const problem = (file: string, line: number | undefined, what: string, fix: string, covers: string, basis?: ApprovalBasis, why = NOT_UNDERSTOOD): void => {
    if (stopped) return;
    if (unit.problems.length >= MAX_UNIT_PROBLEMS) {
      unit.problems.push(`${rel}: more than ${MAX_UNIT_PROBLEMS} problems, so reading stopped; fix these first`);
      unit.covers.push(UNIT);
      unit.fixes.push("");
      unit.lockRule.push(undefined);
      unit.unapprovable.push(STOPPED);
      unit.indexOptions.push({ file: rel, option: "the lines after the first problems, which were not read" });
      stopped = true;
      return;
    }
    unit.problems.push(`${file}${line === undefined ? "" : `:${line}`}: ${what}; ${fix}`);
    unit.covers.push(covers);
    unit.fixes.push(fix);
    unit.lockRule.push(fix !== LOCK_REMEDIATION && fix !== requireHashesRemedy(rel) ? undefined : line === undefined ? "file" : "line");
    unit.unapprovable.push(approvable(basis) ? undefined : why);
  };
  /** A limit reached: one problem, and nothing more is read. */
  const halt = (file: string, line: number | undefined, what: string, fix: string): void => {
    problem(file, line, what, fix, UNIT, undefined, STOPPED);
    if (!stopped) unit.indexOptions.push({ file, ...(line !== undefined ? { line } : {}), option: "text not read (a limit stopped the reading)" });
    stopped = true;
  };
  /** Text of the unit that was not read: it may hold an index option. */
  const unread = (file: string, line: number | undefined, option: string): void => {
    unit.indexOptions.push({ file, ...(line !== undefined ? { line } : {}), option });
  };
  let visits = 0;
  let bytes = 0;
  let linesRead = 0;
  let rootParsed = false;
  /** The first --require-hashes in a file reached through -c, which uv 0.12.21 ignores. */
  let constraintRequireHashes: { file: string; line: number } | undefined;

  const visit = (fileRel: string, constraint: boolean, chain: string[]): void => {
    if (stopped) return;
    if (++visits > MAX_UNIT_FILES) {
      halt(fileRel, undefined, `more than ${MAX_UNIT_FILES} file reads in one unit (includes count each time they are read)`, "simplify the includes");
      return;
    }
    if (!unit.files.includes(fileRel)) unit.files.push(fileRel);
    const read = source.read(fileRel);
    if ("problem" in read) {
      problem(fileRel, undefined, read.problem, "make it a readable regular file", "");
      unread(fileRel, undefined, "a file that could not be read");
      return;
    }
    bytes += read.bytes.length;
    const fileSha = sha(read.bytes);
    unitHash.update(`${fileRel}\0${fileSha}\n`);
    if (bytes > MAX_REQUIREMENTS_BYTES) {
      halt(fileRel, undefined, `the unit reads more than ${MAX_REQUIREMENTS_BYTES / 1024 / 1024} MiB (includes count each time they are read)`, "simplify the includes");
      return;
    }
    const decoded = decodeRequirements(read.bytes);
    if ("problem" in decoded) {
      problem(fileRel, decoded.line, decoded.problem, TEXT_REMEDIATION, fileSha);
      unread(fileRel, decoded.line, "a file that could not be decoded");
      return;
    }
    const pre = preprocessRequirements(decoded.text, MAX_UNIT_LINES - linesRead);
    if ("problem" in pre) {
      if (pre.limit) halt(fileRel, pre.line, `more than ${MAX_UNIT_LINES} lines in one unit (includes count each time they are read)`, "split the file or simplify the includes");
      else {
        problem(fileRel, pre.line, pre.problem, pre.fix ?? (pre.problem.startsWith('"${"') ? "write the value out" : TEXT_REMEDIATION), fileSha);
        unread(fileRel, pre.line, "a file that could not be split into lines");
      }
      return;
    }
    linesRead += pre.lines.length;
    if (chain.length === 1) {
      rootParsed = true;
      if (pre.lines.length === 0) {
        unit.empty = true;
        return;
      }
    }
    for (const l of pre.lines) {
      if (stopped) return;
      // A problem with this line covers its text: another name, hash or option there is another problem.
      const lineSha = sha(l.text);
      const res = parseLine(l);
      if ("problem" in res) {
        problem(fileRel, l.line, res.problem, res.fix ?? LOCK_REMEDIATION, lineSha);
        unread(fileRel, l.line, res.option);
        continue;
      }
      const { parsed } = res;
      if (!parsed.options.some((o) => o.name === "requirement" || o.name === "constraint") || parsed.args !== "") unit.lines.push({ file: fileRel, ...parsed });
      if (parsed.args !== "") {
        // A requirement line: only --hash may follow it.
        const other = parsed.options.find((o) => o.name !== "hash");
        if (other) {
          problem(fileRel, l.line, `--${other.name} on a requirement line, where pip ignores it`, LOCK_REMEDIATION, lineSha);
          continue;
        }
        const pin = readPin(parsed.args);
        if ("problem" in pin) {
          // A line naming a local file covers that file's bytes too, so a baseline entry for it approves that file only;
          // one whose file soak cannot pin by its content no entry approves at all.
          if ("local" in pin && pin.local !== undefined && climbsAfterName(pin.local)) {
            problem(fileRel, l.line, `${pin.problem}; ${CLIMB}`, CLIMB_FIX, lineSha, undefined, "pip and uv can install different files from this line");
            continue;
          }
          const local = "local" in pin && pin.local !== undefined ? localKey(l.text, fileRel, pin.local, chain) : undefined;
          if (local !== undefined) {
            const why = `${local.unkeyable ?? "it names no regular file inside the repository (a directory, or nothing at any place pip may look)"}; make it a regular file inside the repository, or check from the repository root`;
            problem(fileRel, l.line, pin.problem, LOCK_REMEDIATION, local.covers, { kind: "local-file", places: local.places }, why);
          } else problem(fileRel, l.line, pin.problem, LOCK_REMEDIATION, lineSha, "index" in pin && pin.index !== undefined ? { kind: "index-requirement", name: pin.index } : undefined);
          continue;
        }
        const hashes: Record<string, string[]> = {};
        let bad: string | undefined;
        for (const o of parsed.options) {
          const colon = o.value!.indexOf(":");
          const algorithm = colon === -1 ? "" : o.value!.slice(0, colon);
          const digest = o.value!.slice(colon + 1);
          if (!STRONG.has(algorithm)) bad = `--hash=${o.value}: pip accepts only sha256, sha384 and sha512, written algorithm:digest`;
          else if (!isHexDigest(algorithm, digest)) bad = `--hash=${o.value}: not a lowercase hex ${algorithm} digest`;
          else if (algorithm !== "sha256") bad = `--hash=${algorithm}:${digest.slice(0, 12)}...: pip installs a file that matches any one listed hash, and wormsign binds sha256 digests only, so this one names a file that cannot be bound to an index file`;
          else (hashes[algorithm] ??= []).push(digest);
        }
        if (bad !== undefined) {
          problem(fileRel, l.line, bad, LOCK_REMEDIATION, lineSha, { kind: "index-requirement", name: pin.rawName });
          continue;
        }
        const sha256 = hashes["sha256"] ?? [];
        if (sha256.length === 0) {
          problem(fileRel, l.line, `${pin.name}==${pin.rawVersion} has no --hash=sha256`, LOCK_REMEDIATION, lineSha, { kind: "index-requirement", name: pin.rawName });
          continue;
        }
        const entry: RequirementEntry = { file: fileRel, line: l.line, name: pin.name, extras: pin.extras, version: pin.version, rawVersion: pin.rawVersion, hashes, sha256, constraint };
        if (pin.marker !== undefined) entry.marker = pin.marker;
        unit.entries.push(entry);
        continue;
      }
      // An option line.
      const includes = parsed.options.filter((o) => o.name === "requirement" || o.name === "constraint");
      if (includes.length > 0) {
        if (parsed.options.length > 1) {
          problem(fileRel, l.line, "-r or -c shares its line with another option, which pip then ignores", "put each option on a line of its own", lineSha);
          unread(fileRel, l.line, "an include that was not followed");
          continue;
        }
        const inc = includes[0]!;
        const flag = inc.name === "requirement" ? "-r" : "-c";
        const target = inc.value!;
        const skipped = (what: string, fix: string): void => {
          problem(fileRel, l.line, what, fix, lineSha);
          unread(fileRel, l.line, `${flag} ${target}, which was not followed`);
        };
        if (/^(http|https|file):/i.test(target)) {
          skipped(`${flag} ${target} includes a file by URL, which is not part of the reviewed tree`, "include a file inside the repository");
          continue;
        }
        if (target.includes("#")) {
          skipped(`${flag} ${target}: a "#" in the path, where uv ends the path and pip does not`, 'rename the file so that its path has no "#"');
          continue;
        }
        if (constraint && inc.name === "requirement") {
          skipped(`-r ${target} in a file reached through -c: pip installs its lines as requirements, uv reads them as constraints`, "include the file with -r from a requirements file instead");
          continue;
        }
        if (climbsAfterName(target)) {
          skipped(`${flag} ${target}: ${CLIMB}`, CLIMB_FIX);
          continue;
        }
        const abs = resolve(root, fileRel, "..", target);
        const incRel = posixRel(root, abs);
        if (incRel === "" || incRel === ".." || incRel.startsWith("../") || resolve(root, incRel) !== abs) {
          skipped(`${flag} ${target} is outside the scanned root`, "include a file inside the repository");
          continue;
        }
        const local = source.include(incRel);
        if (!local.ok) {
          skipped(`${flag} ${target}: ${local.problem}`, "include a regular file inside the repository");
          continue;
        }
        if (chain.includes(incRel)) {
          problem(fileRel, l.line, `${incRel} includes itself (via ${[...chain, incRel].join(" -> ")}), which pip refuses`, "remove the loop", lineSha);
          continue;
        }
        visit(incRel, constraint || inc.name === "constraint", [...chain, incRel]);
        continue;
      }
      for (const o of parsed.options) {
        if (o.name === "hash") problem(fileRel, l.line, "--hash with no requirement on its line, which pip ignores", LOCK_REMEDIATION, lineSha);
        else if (constraint) constraintRequireHashes ??= { file: fileRel, line: l.line };
        else unit.requireHashes ??= { file: fileRel, line: l.line };
      }
    }
  };

  visit(rel, false, [rel]);
  if (rootParsed && !unit.empty && unit.requireHashes === undefined) {
    // No entry is dropped for these: every line without a hash is a problem of its own.
    if (constraintRequireHashes !== undefined) {
      const c = constraintRequireHashes;
      problem(c.file, c.line, "--require-hashes only in a file reached through -c, where uv ignores it (pip does not)", "put the --require-hashes line in the requirements file itself", "", undefined, REQUIRE_HASHES_WHY);
    } else {
      // No line the lock rule refused: every requirement has its hashes, so the line alone is enough.
      const hashed = !unit.lockRule.includes("line");
      problem(rel, undefined, "no --require-hashes line in the file or the files it includes", hashed ? requireHashesRemedy(rel) : LOCK_REMEDIATION, "", undefined, REQUIRE_HASHES_WHY);
    }
  }
  const whole = unitHash.digest("hex");
  unit.covers = unit.covers.map((c) => (c === UNIT ? whole : c));
  return unit;
}
