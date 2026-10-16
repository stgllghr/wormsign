/**
 * Finding the programs wormsign runs (git; `python3 -m pip config list`; `npm`, `pnpm`, `yarn` and `bun --version`) on
 * PATH here, in node, rather than leaving it to the OS, so that no program from the tree being checked runs:
 * - an empty or relative PATH entry is skipped: it names the working directory, which a spawn would resolve;
 * - the first match is refused, and nothing is run, when its PATH directory or the file itself (symlinks followed) is
 *   inside the scanned tree. CI may have put a directory of the repository on PATH before wormsign runs
 *   ($GITHUB_WORKSPACE/bin, an activated in-tree .venv/bin whose site-packages holds a .pth file), and a `python3` or
 *   `git` committed there would run inside the gate's step, with its secrets. Searching on past it would run another
 *   program than the one the install uses (an in-tree venv's python3 reads the venv's pip.conf), so the caller treats a
 *   refusal as "could not be run" and fails closed;
 * - otherwise the program is spawned by the absolute path found.
 * On Windows a name is also tried with .com and .exe, as libuv tries them; on POSIX the file must be executable.
 */
import { accessSync, constants, realpathSync, statSync } from "node:fs";
import { delimiter, isAbsolute, join, relative, sep } from "node:path";

export type Program = { path: string } | { refused: string } | { missing: string };

const real = (p: string): string => {
  try {
    return realpathSync(p);
  } catch {
    return p;
  }
};

/** Is `p` at or under `root`? Both absolute. */
export function isInside(p: string, root: string): boolean {
  const r = relative(root, p);
  return r === "" || (r !== ".." && !r.startsWith(`..${sep}`) && !isAbsolute(r));
}

/** The program `name` on env's PATH, unless it is inside one of `roots` (see the module comment). Never throws. */
export function findProgram(name: string, env: Record<string, string | undefined>, roots: string[]): Program {
  const path = env["PATH"] ?? env["Path"] ?? "";
  const names = process.platform === "win32" && !/\.[a-z0-9]+$/i.test(name) ? [name, `${name}.com`, `${name}.exe`] : [name];
  const within = roots.flatMap((r) => [r, real(r)]);
  for (const dir of path.split(delimiter)) {
    if (dir === "" || !isAbsolute(dir)) continue;
    for (const n of names) {
      const file = join(dir, n);
      try {
        if (!statSync(file).isFile()) continue;
        if (process.platform !== "win32") accessSync(file, constants.X_OK);
      } catch {
        continue;
      }
      const places = [dir, real(dir), file, real(file)];
      if (places.some((p) => within.some((r) => isInside(p, r)))) return { refused: `${name} on PATH is ${file}, inside the scanned tree, so it was not run` };
      return { path: file };
    }
  }
  return { missing: `${name} was not found on PATH` };
}
