/**
 * TOML for the Python readers: one place that reads a file, decodes it and parses it with the vendored smol-toml
 * 1.9.0 (src/vendor/smol-toml, byte-identical to its npm tarball; see VENDORED.json and docs/architecture.md).
 *
 * The reader API never throws: an unreadable file, bytes that are not UTF-8, a leading byte-order mark and a parse
 * error all come back as a `problem` the caller reports.
 *
 * Facts this relies on (smol-toml 1.9.0, measured 2026-10-08; docs/architecture.md has the list):
 * - every table, inline table and array-of-tables element is an object with a null prototype, so a key such as
 *   "__proto__" or "constructor" is an own property like any other. Read keys with `get` (Object.hasOwn) only;
 * - a duplicate key or table is an error, as TOML 1.0 requires;
 * - with `integersAsBigInt: "asNeeded"`, an integer beyond 2^53 is a bigint rather than an error (Python's tomllib
 *   reads it as an int; TOML allows 64-bit integers);
 * - date-times are TomlDate objects (a Date subclass) with millisecond precision: sub-millisecond digits are dropped;
 * - inline nesting deeper than 1000 levels is an error.
 */
import { createHash } from "node:crypto";
import { parse, TomlDate, TomlError } from "../vendor/smol-toml/index.js";
import { readBytes } from "../fsutil.js";

/** A parsed TOML table. Values are TomlValue; every object has a null prototype. */
export type TomlTable = Record<string, unknown>;

/**
 * A parsed document, or why not. `sha256` is the digest of the file's bytes when they could be read (readToml), so a
 * problem with the whole file can be keyed on exactly what was read.
 */
export type TomlRead = ({ doc: TomlTable } | { problem: string }) & { sha256?: string };

/** The sha256 of some bytes, hex. */
export const bytesDigest = (b: Uint8Array | string): string => createHash("sha256").update(b).digest("hex");

/**
 * The sha256 of a TOML value in a canonical form: tables with their keys sorted, arrays in order, strings as JSON,
 * numbers, booleans and dates each tagged with their type, nothing truncated. Two values with the same content give
 * the same digest however the file wrote them (key order, quoting, inline or not, comments); any change to the content
 * as parsed changes it (smol-toml reads the float 1.0 as the number 1, so those two are one value here). Built with an explicit stack, so a deeply nested value cannot overflow the call stack.
 * A reader problem is keyed on this digest of the table it is about (src/python/soak.ts lockProblemFinding).
 */
export function contentDigest(v: unknown): string {
  const hash = createHash("sha256");
  type Item = { emit: string } | { value: unknown };
  const stack: Item[] = [{ value: v }];
  while (stack.length > 0) {
    const item = stack.pop()!;
    if ("emit" in item) {
      hash.update(item.emit);
      continue;
    }
    const x = item.value;
    if (Array.isArray(x)) {
      stack.push({ emit: "]" });
      for (let i = x.length - 1; i >= 0; i--) stack.push({ value: x[i] }, { emit: i === 0 ? "" : "," });
      hash.update("[");
    } else if (x instanceof Date) {
      let iso: string;
      try {
        iso = x.toISOString();
      } catch {
        iso = String(x);
      }
      hash.update(`d${JSON.stringify(iso)}`);
    } else if (typeof x === "object" && x !== null) {
      const keys = Object.keys(x).sort();
      stack.push({ emit: "}" });
      for (let i = keys.length - 1; i >= 0; i--) stack.push({ value: (x as TomlTable)[keys[i]!] }, { emit: `${i === 0 ? "" : ","}${JSON.stringify(keys[i])}:` });
      hash.update("{");
    } else if (typeof x === "string") {
      hash.update(JSON.stringify(x));
    } else if (typeof x === "bigint") {
      hash.update(`i${x.toString()}`);
    } else if (typeof x === "number") {
      hash.update(Number.isInteger(x) ? `i${x}` : `f${Object.is(x, -0) ? "-0" : String(x)}`);
    } else {
      hash.update(`${typeof x}:${String(x)}`);
    }
  }
  return hash.digest("hex");
}

/** The largest TOML file read: lockfiles of very large workspaces stay far below this (a 100k-package lock is ~40 MB). */
export const MAX_TOML_BYTES = 64 * 1024 * 1024;

const DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * Decodes UTF-8 without dropping a byte-order mark, so the caller can see one. Measured 2026-10-08: Python 3.14's
 * tomllib and pip 26.2.1 (loading pyproject.toml) reject a TOML file that starts with U+FEFF; uv 0.10.9 and 0.12.21
 * accept it in both uv.lock and pyproject.toml, and so does smol-toml. Tools disagree, so a BOM is a problem rather
 * than something to strip.
 */
export function decodeUtf8(bytes: Uint8Array): { text: string } | { problem: string } {
  let text: string;
  try {
    text = DECODER.decode(bytes);
  } catch {
    return { problem: "it is not valid UTF-8" };
  }
  return { text };
}

/** Parses TOML text. A leading U+FEFF and any parse error are problems; nothing is thrown. */
export function parseToml(text: string): TomlRead {
  if (text.charCodeAt(0) === 0xfeff) return { problem: "it starts with a BOM (byte-order mark), which pip and Python's tomllib reject and uv accepts" };
  try {
    return { doc: parse(text, { integersAsBigInt: "asNeeded", useLegacyDate: true, unsafeKeyBehaviour: "keep" }) as TomlTable };
  } catch (e) {
    if (e instanceof TomlError) return { problem: `it is not valid TOML (line ${e.line}, column ${e.column}: ${firstLine(e.message)})` };
    // RangeError (stack) or anything else smol-toml did not anticipate: still a problem, never a crash.
    return { problem: `it could not be parsed as TOML (${firstLine(String((e as Error)?.message ?? e))})` };
  }
}

/** Reads and parses a TOML file of at most MAX_TOML_BYTES. */
export function readToml(path: string, maxBytes: number = MAX_TOML_BYTES): TomlRead {
  const read = readBytes(path, maxBytes);
  if ("problem" in read) return read;
  return tomlOfBytes(read.bytes);
}

/**
 * A TOML file's bytes as readToml reads them once it has them: their sha256, then UTF-8, then TOML. PR mode reads the
 * base revision's blobs with it (src/python/base-entries.ts), so the base's lock is read exactly as the head's is.
 */
export function tomlOfBytes(bytes: Uint8Array): TomlRead {
  const sha256 = bytesDigest(bytes);
  const decoded = decodeUtf8(bytes);
  if ("problem" in decoded) return { ...decoded, sha256 };
  return { ...parseToml(decoded.text), sha256 };
}

const firstLine = (s: string): string => s.split("\n", 1)[0]!.replace(/^Invalid TOML document: /, "").slice(0, 160);

/* ---- reading values: Object.hasOwn only ---- */

/** A TOML value shown in a message: JSON with bigints as digits, cut at 200 characters. Never throws. */
export function show(v: unknown): string {
  if (typeof v === "bigint") return v.toString();
  let s: string;
  try {
    s = JSON.stringify(v, (_key, x: unknown) => (typeof x === "bigint" ? x.toString() : x)) ?? String(v);
  } catch {
    s = Object.prototype.toString.call(v);
  }
  return s.length > 200 ? `${s.slice(0, 200)}...` : s;
}

/** A table's own value for key, or undefined. Never reads the prototype chain. */
export function get(table: TomlTable, key: string): unknown {
  return Object.hasOwn(table, key) ? table[key] : undefined;
}

/** A TOML table (not an array, not a date). */
export function isTable(v: unknown): v is TomlTable {
  return typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof Date);
}

/** The table's own keys that are not in `known`. */
export function unknownKeys(table: TomlTable, known: readonly string[]): string[] {
  return Object.keys(table).filter((k) => !known.includes(k));
}

/** A non-negative integer that fits a JS number exactly (sizes); a bigint or a float is not one. */
export function isSafeCount(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}

/**
 * An offset date-time as an RFC 3339 UTC string with milliseconds ("2024-12-04T17:35:26.000Z"), or undefined for any
 * other value (a local date-time, date or time, which carries no instant).
 */
export function offsetDateTime(v: unknown): string | undefined {
  if (!(v instanceof TomlDate) || !v.isDateTime() || v.isLocal() || !v.isValid()) return undefined;
  return new Date(v.getTime()).toISOString();
}

export { TomlDate };
