import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readFileSync, readSync } from "node:fs";
import { join, relative, sep } from "node:path";

export const MAX_TEXT_BYTES = 2 * 1024 * 1024;

export function toPosix(p: string): string {
  return sep === "/" ? p : p.split(sep).join("/");
}

export interface WalkOptions {
  includeNodeModules: boolean;
  /** Called with each symlink that is skipped, so a caller can report one it cannot afford to ignore. */
  onSymlink?: (rel: string) => void;
  /** Called with a directory or entry that could not be read, and the error code, so a skip is never silent. */
  onUnreadable?: (rel: string, code: string) => void;
}

/**
 * Yields regular files under root (relative posix paths). Never follows
 * symlinks, so walking a hostile repo never leaves the scan root.
 */
export function* walk(root: string, opts: WalkOptions): Generator<string> {
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop() as string;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch (e) {
      opts.onUnreadable?.(toPosix(relative(root, dir)), (e as NodeJS.ErrnoException).code ?? "error");
      continue;
    }
    entries.sort();
    for (const name of entries) {
      if (name === ".git") continue;
      if (name === "node_modules" && !opts.includeNodeModules) continue;
      const full = join(dir, name);
      let st;
      try {
        st = lstatSync(full);
      } catch (e) {
        opts.onUnreadable?.(toPosix(relative(root, full)), (e as NodeJS.ErrnoException).code ?? "error");
        continue;
      }
      if (st.isSymbolicLink()) opts.onSymlink?.(toPosix(relative(root, full)));
      else if (st.isDirectory()) stack.push(full);
      else if (st.isFile()) yield toPosix(relative(root, full));
    }
  }
}

/** A file's bytes or text, or why it could not be read. Callers must report `problem`, never treat it as empty. */
export type BytesRead = { bytes: Buffer } | { problem: string };
export type TextRead = { text: string } | { problem: string };

/**
 * Opens a regular file, refuses one larger than maxBytes (when given), and calls `use` with its descriptor and size,
 * closing it afterwards. O_NOFOLLOW refuses a symlink as the final path component (even one swapped in after walk()
 * listed the path); it does not cover a parent directory swapped for a symlink during the scan. Where the platform
 * does not define the flag (Windows), it is not applied. Every failure, including an error `use` throws, is a problem:
 * the readers of every command build on this, so they open files the same way and say the same things.
 */
export function withRegularFile<T>(path: string, maxBytes: number | undefined, use: (fd: number, size: number) => T | { problem: string }): T | { problem: string } {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    return { problem: code === "ELOOP" ? "it is a symlink" : `it could not be read (${code ?? "error"})` };
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return { problem: "it is not a regular file" };
    if (maxBytes !== undefined && st.size > maxBytes) return { problem: `it is larger than ${maxBytes / 1024 / 1024} MiB` };
    return use(fd, st.size);
  } catch (e) {
    return { problem: `it could not be read (${(e as NodeJS.ErrnoException).code ?? "error"})` };
  } finally {
    closeSync(fd);
  }
}

/** Reads a regular file of at most maxBytes, opened by withRegularFile. */
export function readBytes(path: string, maxBytes: number): BytesRead {
  return withRegularFile(path, maxBytes, (fd) => ({ bytes: readFileSync(fd) }));
}

/** How far readChunks got: the size of the file, every byte of which was visited, or why it could not be read. */
export type ChunksRead = { size: number } | { problem: string };

/**
 * Reads a regular file of at most maxBytes, opened by withRegularFile, and calls visit with each chunk of at most
 * overlap + chunkBytes bytes. Each chunk after the first starts with the last `overlap` bytes of the one before, so
 * any run of at most overlap + 1 bytes lies whole in at least one chunk. `line` is the 1-based line the chunk starts
 * on. Memory stays at one chunk whatever the size of the file.
 */
export function readChunks(path: string, opts: { maxBytes: number; chunkBytes: number; overlap: number }, visit: (chunk: Buffer, line: number) => void): ChunksRead {
  const tooLarge = { problem: `it is larger than ${opts.maxBytes / 1024 / 1024} MiB` };
  return withRegularFile(path, opts.maxBytes, (fd) => {
    const buf = Buffer.alloc(opts.overlap + opts.chunkBytes);
    let kept = 0;
    let line = 1;
    let size = 0;
    for (;;) {
      const n = readSync(fd, buf, kept, opts.chunkBytes, null);
      if (n === 0) return { size };
      size += n;
      // The file may grow after fstat; the cap holds for what is read.
      if (size > opts.maxBytes) return tooLarge;
      const end = kept + n;
      visit(buf.subarray(0, end), line);
      kept = Math.min(opts.overlap, end);
      const leaving = buf.subarray(0, end - kept);
      for (let i = leaving.indexOf(0x0a); i !== -1; i = leaving.indexOf(0x0a, i + 1)) line++;
      buf.copyWithin(0, end - kept, end);
    }
  });
}

/**
 * The text without a leading UTF-8 byte-order mark. npm and pnpm strip one before parsing (verified with npm 10.9.2,
 * pnpm 11.16), and npm installs from a package-lock.json that starts with one, so the gate must read it too.
 */
export function stripBom(text: string): string {
  return text.replace(/^\uFEFF/, "");
}

/** readBytes for a text file: NUL bytes are a problem, and a leading byte-order mark is dropped. */
export function readText(path: string, maxBytes: number = MAX_TEXT_BYTES): TextRead {
  const read = readBytes(path, maxBytes);
  if ("problem" in read) return read;
  if (read.bytes.includes(0)) return { problem: "it contains NUL bytes" };
  return { text: stripBom(read.bytes.toString("utf8")) };
}

/**
 * Returns a lookup from string index to 1-based line number. Newline offsets
 * are collected once, so k lookups cost O(n + k log n) rather than O(k * n).
 */
export function lineIndex(text: string): (index: number) => number {
  const starts = [0];
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) starts.push(i + 1);
  return (index) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if ((starts[mid] as number) <= index) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
}
