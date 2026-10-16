// Where the harden-dev.sh tests put their sandbox. The script makes its probe directory only under a directory that,
// like every directory above it, is owned by root or the user and writable by neither group nor others (private_dir
// in harden-dev.sh), so each run's TMPDIR must be such a directory for the tests to see where the probes run. On Linux
// os.tmpdir() is /tmp, which every user can write, so the sandbox goes in the first private one of os.tmpdir(),
// XDG_RUNTIME_DIR and the home directory (only the sandbox goes there, never a run's HOME: each run has its own).
import { existsSync, realpathSync, statSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, isAbsolute } from "node:path";

/** What harden-dev.sh's private_dir accepts. */
export function privateDir(dir: string | undefined): boolean {
  if (!dir || !isAbsolute(dir) || !existsSync(dir)) return false;
  for (let d = realpathSync(dir); ; d = dirname(d)) {
    const st = statSync(d);
    if ((st.uid !== 0 && st.uid !== process.getuid?.()) || (st.mode & 0o022) !== 0) return false;
    if (dirname(d) === d) return true;
  }
}

export function privateBase(): string {
  const base = [tmpdir(), process.env["XDG_RUNTIME_DIR"], homedir()].find(privateDir);
  if (base === undefined) {
    throw new Error("no private directory for the harden-dev.sh sandbox: os.tmpdir(), XDG_RUNTIME_DIR and the home directory are each writable by another user, or under a directory that is");
  }
  return base;
}
