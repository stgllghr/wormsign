/**
 * PEP 723 inline script metadata: the `# /// script` block, read the way uv reads it.
 *
 * uv's parser (crates/uv-scripts/src/lib.rs, ScriptTag::parse, read at uv 0.10.9 and 0.12.21) is the reference:
 * 1. Find the FIRST occurrence of the bytes "# /// script". None: no block.
 * 2. It must start the file or follow "\r" or "\n"; otherwise: no block (uv does not look further).
 * 3. The text before it and from it on must be UTF-8 (an error in uv).
 * 4. From there, lines are split as Rust's str::lines does (on "\n" and "\r\n"; a bare "\r" stays in the line), and
 *    the first line must be exactly "# /// script" (so a trailing space, or a bare "\r" after the tag, is no block).
 * 5. Following lines that are "#" or start with "# " are the block body ("#" or "# " removed); the first other line
 *    ends it. The closing line is the LAST body line that is exactly "///"; none is an error ("unclosed").
 * 6. The body before the closing line, joined with "\n", is TOML.
 * uv 0.12.21 also refuses a second complete `script` block after the first; 0.10.9 does not.
 *
 * So a BOM before the tag, an indented tag and a tag with trailing spaces are not blocks (uv runs such a script
 * without installing anything). What uv would refuse, or what another reader may see differently, is a problem:
 * - a tag line uv does not use: any line that is exactly "# /// script" when lines are split as Python's universal
 *   newlines split them ("\r\n", "\r" or "\n"), other than the one uv opens the block at. That covers a second block
 *   (0.10.9 and 0.12.21 disagree), a tag after a first "# /// script" that is not at a line start, and a tag ended by a
 *   bare "\r" (Python tools read a block there, uv does not);
 * - an unclosed block, bytes that are not UTF-8, and a body that is not valid TOML.
 */
import { decodeUtf8, parseToml, type TomlTable } from "./toml.js";

export type ScriptBlock =
  | { kind: "none" }
  | { kind: "block"; metadata: TomlTable; /** 1-based line of the opening tag */ line: number }
  | { kind: "problem"; problem: string };

const TAG = "# /// script";
const TAG_BYTES = Buffer.from(TAG, "utf8");
const CR = 0x0d;
const LF = 0x0a;

/** Rust's str::lines: split on "\n", drop one "\r" before each "\n", keep a bare "\r", no empty last line. */
function rustLines(text: string): string[] {
  const parts = text.split("\n");
  const lines = parts.map((p, i) => (i < parts.length - 1 && p.endsWith("\r") ? p.slice(0, -1) : p));
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  return lines;
}

/** Byte offsets of every line that is exactly the tag, lines split on "\r\n", "\r" or "\n". */
function tagOffsets(buf: Buffer): number[] {
  const out: number[] = [];
  for (let at = buf.indexOf(TAG_BYTES); at !== -1; at = buf.indexOf(TAG_BYTES, at + 1)) {
    const before = at === 0 ? LF : buf[at - 1];
    const after = at + TAG_BYTES.length === buf.length ? LF : buf[at + TAG_BYTES.length];
    if ((before === LF || before === CR) && (after === LF || after === CR)) out.push(at);
  }
  return out;
}

/** The 1-based line of a byte offset, lines split on "\r\n", "\r" or "\n". */
function lineOf(buf: Buffer, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset; i++) {
    if (buf[i] === LF || (buf[i] === CR && buf[i + 1] !== LF)) line++;
  }
  return line;
}

/** Reads the script block of a file's bytes. Never throws. */
export function parseScriptBlock(bytes: Uint8Array): ScriptBlock {
  const buf = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const tags = tagOffsets(buf);
  const stray = (opened: number | undefined): ScriptBlock | undefined => {
    const other = tags.find((t) => t !== opened);
    if (other === undefined) return undefined;
    return { kind: "problem", problem: `line ${lineOf(buf, other)} is "# /// script" but uv does not read it as the script's metadata block, so tools may disagree about the script's dependencies` };
  };

  const at = buf.indexOf(TAG_BYTES);
  if (at === -1) return { kind: "none" };
  if (at > 0 && buf[at - 1] !== LF && buf[at - 1] !== CR) return stray(undefined) ?? { kind: "none" };
  const prelude = decodeUtf8(buf.subarray(0, at));
  const rest = decodeUtf8(buf.subarray(at));
  if ("problem" in prelude || "problem" in rest) return { kind: "problem", problem: "a `# /// script` block is present but the file is not valid UTF-8" };
  const lines = rustLines(rest.text);
  if (lines[0] !== TAG) return stray(undefined) ?? { kind: "none" };
  const line = lineOf(buf, at);

  const body: string[] = [];
  for (const l of lines.slice(1)) {
    if (!l.startsWith("#")) break;
    const after = l.slice(1);
    if (after === "") body.push("");
    else if (after.startsWith(" ")) body.push(after.slice(1));
    else break;
  }
  let close = -1;
  for (let i = body.length - 1; i >= 0; i--) {
    if (body[i] === "///") {
      close = i;
      break;
    }
  }
  if (close === -1) return { kind: "problem", problem: `line ${line}: the \`# /// script\` block has no closing \`# ///\` line` };
  const second = stray(at);
  if (second) return second;

  const parsed = parseToml(body.slice(0, close).join("\n") + "\n");
  if ("problem" in parsed) return { kind: "problem", problem: `line ${line}: the \`# /// script\` block ${parsed.problem.replace(/^it /, "")}` };
  return { kind: "block", metadata: parsed.doc, line };
}
