/**
 * `wormsign skills`: install, check and remove the agent skill this package ships (plugins/wormsign/skills/wormsign/)
 * for Claude Code, Codex and Cursor. Nothing is fetched: the files come from the installed package. Only the `wormsign`
 * folder under each agent's skills folder is ever written or removed; a folder wormsign did not write, or one edited
 * since, is left alone without --force. Manifest paths are compared, never opened: a forged one cannot reach outside.
 */
import { createHash, randomBytes } from "node:crypto";
import { accessSync, constants, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { UsageError } from "./types.js";

export const SKILL_NAME = "wormsign";
export const MANIFEST = ".wormsign-skill.json";
export const bundledSkillDir = fileURLToPath(new URL("../../plugins/wormsign/skills/wormsign/", import.meta.url));
const PACKAGE_VERSION = (JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { version: string }).version;

export const AGENTS = ["claude", "codex", "cursor"] as const;
export type Agent = (typeof AGENTS)[number];
export const ACTIONS = ["install", "check", "uninstall"] as const;
export type Action = (typeof ACTIONS)[number];

/** Printable ASCII and newline: what every shipped skill file holds, so nothing in it is invisible. */
const PLAIN = /^[\n\x20-\x7e]*$/;
/** A skill folder holds a few small files; a bigger one is not wormsign's, and is not read whole. */
const MAX_FILES = 64;
const MAX_FILE_BYTES = 256 * 1024;

export function parseAction(s: string | undefined): Action {
  if ((ACTIONS as readonly string[]).includes(s ?? "")) return s as Action;
  throw new UsageError(`usage: wormsign skills ${ACTIONS.join("|")}${s === undefined ? "" : ` (got: ${s})`}`);
}

/** --agent values: comma-separated and repeatable; undefined when none was given. */
export function parseAgents(values: string[] | undefined): Agent[] | undefined {
  if (values === undefined) return undefined;
  const out: Agent[] = [];
  for (const raw of values.flatMap((v) => v.split(","))) {
    const a = raw.trim();
    if (!(AGENTS as readonly string[]).includes(a)) throw new UsageError(`invalid --agent "${a}" (${AGENTS.join(", ")})`);
    if (!out.includes(a as Agent)) out.push(a as Agent);
  }
  return out;
}

/**
 * The home folder the user-level targets are under: $HOME when it is an absolute path, else the system's home folder
 * if that is one. An empty or relative HOME would otherwise put the skill under the working directory.
 */
export function userHome(env: Record<string, string | undefined>, fallback: () => string = homedir): string {
  const h = env["HOME"];
  if (h && isAbsolute(h)) return h;
  const f = fallback();
  if (f && isAbsolute(f)) return f;
  throw new UsageError(`HOME is ${h === undefined ? "not set" : `"${h}"`}, not an absolute path, and no home folder was found; set HOME to your home folder`);
}

export interface Where {
  home: string;
  env: Record<string, string | undefined>;
  /** --project: the git root; unset for the user folders. */
  projectRoot?: string;
}

/** Claude Code's folder: $CLAUDE_CONFIG_DIR when it is absolute, else ~/.claude. */
export function claudeDir(w: Where): string {
  const c = w.env["CLAUDE_CONFIG_DIR"];
  return c && isAbsolute(c) ? c : join(w.home, ".claude");
}

/** The agents whose user folders exist. */
export function detectAgents(w: Where): Agent[] {
  const found: Agent[] = [];
  if (existsSync(claudeDir(w))) found.push("claude");
  if (existsSync(join(w.home, ".codex"))) found.push("codex");
  if (existsSync(join(w.home, ".cursor"))) found.push("cursor");
  return found;
}

export interface Target {
  agents: Agent[];
  skillsDir: string;
  dir: string;
  /** No path component below this one may be a symbolic link: the project root, or the skills folder itself. */
  guardFrom: string;
}

/**
 * Whether Cursor reads the folder Claude Code's copy goes in: always with --project (.claude/skills); at user level
 * only ~/.claude/skills, the folder Cursor's documentation names, not a $CLAUDE_CONFIG_DIR elsewhere (docs/skills.md).
 */
function cursorReadsClaudeCopy(w: Where): boolean {
  return w.projectRoot !== undefined || resolve(claudeDir(w)) === resolve(w.home, ".claude");
}

/**
 * One target per folder. Codex reads .agents/skills; Cursor reads that folder and Claude Code's, so Cursor shares
 * Claude Code's copy when both are selected (and Cursor reads that folder), and Codex's otherwise: the .agents copy is
 * written only for Codex, or for Cursor without Claude Code.
 */
export function targetsFor(agents: Agent[], w: Where): Target[] {
  const byDir = new Map<string, Target>();
  const cursorWithClaude = agents.includes("cursor") && agents.includes("claude") && cursorReadsClaudeCopy(w);
  for (const a of agents) {
    const claudeFolder = a === "claude" || (a === "cursor" && cursorWithClaude);
    const skillsDir = w.projectRoot !== undefined ? join(w.projectRoot, claudeFolder ? ".claude" : ".agents", "skills") : claudeFolder ? join(claudeDir(w), "skills") : join(w.home, ".agents", "skills");
    const t = byDir.get(skillsDir) ?? { agents: [], skillsDir, dir: join(skillsDir, SKILL_NAME), guardFrom: w.projectRoot ?? skillsDir };
    t.agents.push(a);
    byDir.set(skillsDir, t);
  }
  return [...byDir.values()];
}

interface Tree {
  files: Map<string, Buffer>;
  /** Links, other entries, and files past the caps: never read. */
  odd: string[];
}

function readTree(dir: string): Tree {
  const files = new Map<string, Buffer>();
  const odd: string[] = [];
  const walk = (rel: string): void => {
    for (const name of readdirSync(join(dir, rel)).sort()) {
      const r = rel === "" ? name : `${rel}/${name}`;
      const st = lstatSync(join(dir, r));
      if (st.isDirectory()) walk(r);
      else if (st.isFile() && st.size <= MAX_FILE_BYTES && files.size < MAX_FILES) files.set(r, readFileSync(join(dir, r)));
      else odd.push(r);
    }
  };
  walk("");
  return { files, odd };
}

export interface Bundle {
  version: string;
  files: Map<string, Buffer>;
}

export function loadBundle(dir = bundledSkillDir, version = PACKAGE_VERSION): Bundle {
  let t: Tree;
  try {
    t = readTree(dir);
  } catch (e) {
    throw new UsageError(`the bundled skill at ${dir} cannot be read (${(e as NodeJS.ErrnoException).code ?? (e as Error).message}); reinstall wormsign`);
  }
  const problem = t.odd.length > 0 ? `it holds ${t.odd.join(", ")}` : !t.files.has("SKILL.md") ? "it has no SKILL.md" : t.files.has(MANIFEST) ? `it holds ${MANIFEST}` : undefined;
  if (problem) throw new UsageError(`the bundled skill at ${dir} is damaged: ${problem}; reinstall wormsign`);
  return { version, files: t.files };
}

/** The files are a Map: a path such as `constructor` or `__proto__` is only ever a key, never an Object.prototype name. */
interface Manifest {
  version: string;
  files: Map<string, string>;
}

const sha256 = (b: Buffer): string => createHash("sha256").update(b).digest("hex");

export function manifestText(b: Bundle): string {
  const files = Object.fromEntries([...b.files].map(([rel, bytes]) => [rel, sha256(bytes)]));
  return `${JSON.stringify({ tool: "wormsign", version: b.version, files }, null, 2)}\n`;
}

function parseManifest(buf: Buffer | undefined): Manifest | undefined {
  if (buf === undefined) return undefined;
  try {
    const m = JSON.parse(buf.toString("utf8")) as { tool?: unknown; version?: unknown; files?: unknown };
    if (m.tool !== "wormsign" || typeof m.version !== "string" || typeof m.files !== "object" || m.files === null || Array.isArray(m.files)) return undefined;
    const files = new Map<string, string>();
    for (const [rel, h] of Object.entries(m.files)) {
      if (typeof h !== "string" || !/^[0-9a-f]{64}$/.test(h)) return undefined;
      files.set(rel, h);
    }
    return { version: m.version, files };
  } catch {
    return undefined;
  }
}

export interface Inspection {
  /** absent: nothing at that path; ours: a folder with a wormsign manifest; foreign: anything else. */
  state: "absent" | "ours" | "foreign";
  why?: string;
  version?: string;
  /** In the manifest, not on disk. */
  lost: string[];
  /** On disk, differing from the manifest. */
  edited: string[];
  /** On disk, not in the manifest. */
  extra: string[];
  odd: string[];
  /** Files holding anything but printable ASCII and newline. */
  notPlain: string[];
  /** In this release's skill, not in the manifest. */
  missing: string[];
  /** In the manifest with a hash other than this release's, or in the manifest and not in this release's skill. */
  differs: string[];
  /** The manifest's version or files differ from this release's skill. */
  outdated: boolean;
}

export function inspect(dir: string, bundle: Bundle): Inspection {
  const none = { lost: [], edited: [], extra: [], odd: [], notPlain: [], missing: [], differs: [], outdated: false };
  let st;
  try {
    st = lstatSync(dir);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return { state: "absent", ...none };
    throw new UsageError(`cannot read ${dir}: ${(e as NodeJS.ErrnoException).code ?? (e as Error).message}`);
  }
  if (st.isSymbolicLink()) return { state: "foreign", why: "it is a symbolic link", ...none };
  if (!st.isDirectory()) return { state: "foreign", why: "it is not a folder", ...none };
  let tree: Tree;
  try {
    tree = readTree(dir);
  } catch (e) {
    throw new UsageError(`cannot read ${dir}: ${(e as NodeJS.ErrnoException).code ?? (e as Error).message}`);
  }
  const manifest = parseManifest(tree.files.get(MANIFEST));
  if (!manifest) return { state: "foreign", why: tree.files.has(MANIFEST) ? `its ${MANIFEST} is not one wormsign wrote` : `it has no ${MANIFEST}, so wormsign did not install it`, ...none, odd: tree.odd };
  tree.files.delete(MANIFEST);
  const r: Inspection = { state: "ours", version: manifest.version, ...none, lost: [], edited: [], extra: [], notPlain: [], missing: [], differs: [], odd: tree.odd };
  for (const [rel, hash] of manifest.files) {
    const bytes = tree.files.get(rel);
    if (bytes === undefined) r.lost.push(rel);
    else if (sha256(bytes) !== hash) r.edited.push(rel);
  }
  for (const [rel, bytes] of tree.files) {
    if (!manifest.files.has(rel)) r.extra.push(rel);
    if (!PLAIN.test(bytes.toString("latin1"))) r.notPlain.push(rel);
  }
  for (const rel of bundle.files.keys()) if (!manifest.files.has(rel)) r.missing.push(rel);
  for (const [rel, b] of bundle.files) if (manifest.files.has(rel) && manifest.files.get(rel) !== sha256(b)) r.differs.push(rel);
  for (const rel of manifest.files.keys()) if (!bundle.files.has(rel)) r.differs.push(rel);
  r.outdated = manifest.version !== bundle.version || r.missing.length + r.differs.length > 0;
  return r;
}

/** Nothing on disk differs from what wormsign wrote there. */
export const unedited = (i: Inspection): boolean => i.state === "ours" && i.lost.length + i.edited.length + i.extra.length + i.odd.length === 0;
/** Exactly this release's skill. */
export const current = (i: Inspection): boolean => unedited(i) && !i.outdated && i.missing.length === 0 && i.notPlain.length === 0;

export interface Outcome {
  lines: string[];
  code: 0 | 1;
}
export interface Options {
  agents?: Agent[];
  dryRun: boolean;
  force: boolean;
}

/** A path component from target.guardFrom down to the skill folder that is a symbolic link, if any. */
function linkOnPath(t: Target): string | undefined {
  const parts = relative(t.guardFrom, t.dir).split(sep).filter(Boolean);
  let p = t.guardFrom;
  for (const part of ["", ...parts]) {
    p = part === "" ? p : join(p, part);
    try {
      if (lstatSync(p).isSymbolicLink()) return p;
    } catch {
      return undefined; // the rest does not exist yet
    }
  }
  return undefined;
}

const label = (t: Target): string => `${t.dir} (${t.agents.join(", ")})`;
const list = (what: string, xs: string[]): string[] => (xs.length ? [`${what}: ${xs.join(", ")}`] : []);
const errCode = (e: unknown): string => (e as NodeJS.ErrnoException).code ?? (e as Error).message;
/** A path quoted for a POSIX shell, so a removal command can be pasted as printed. */
const shellQuote = (p: string): string => `'${p.replace(/'/g, "'\\''")}'`;
const removeCommand = (paths: string[]): string => `rm -r -- ${paths.map(shellQuote).join(" ")}`;

/** The renames and removals that put a new copy in place of an old one, or take a copy out. Tests pass their own. */
export interface FsOps {
  rename(from: string, to: string): void;
  remove(path: string): void;
}
const FS: FsOps = { rename: renameSync, remove: (p) => rmSync(p, { recursive: true, force: true }) };

/**
 * Why a target's skills folder cannot be written, if it cannot: the nearest part of its path that exists must be a
 * folder wormsign may write to. Checked for every target before anything is written or removed.
 */
function unwritable(t: Target): string | undefined {
  let p = t.skillsDir;
  while (!existsSync(p) && dirname(p) !== p) p = dirname(p);
  try {
    if (!statSync(p).isDirectory()) return "ENOTDIR";
    accessSync(p, constants.W_OK);
    return undefined;
  } catch (e) {
    return errCode(e);
  }
}

/**
 * Writes the skill to a temporary folder beside t.dir, then renames it into place. An existing copy is renamed aside
 * first and put back if the second rename fails; if putting it back fails too, the error names the folder it is left
 * in. Once the new copy is in place the old one is removed, best effort: if that fails, the install stands and the
 * returned warning says where what is left of the old copy is, and that the user should delete it.
 */
function writeSkill(t: Target, b: Bundle, ops: FsOps): string | undefined {
  const tag = `${process.pid}-${randomBytes(4).toString("hex")}`;
  const tmp = join(t.skillsDir, `.${SKILL_NAME}.tmp-${tag}`);
  const old = join(t.skillsDir, `.${SKILL_NAME}.old-${tag}`);
  let replaced = false;
  let stranded = "";
  try {
    mkdirSync(t.skillsDir, { recursive: true });
    mkdirSync(tmp);
    for (const [rel, bytes] of b.files) {
      mkdirSync(dirname(join(tmp, rel)), { recursive: true });
      writeFileSync(join(tmp, rel), bytes, { flag: "wx", mode: 0o644 });
    }
    writeFileSync(join(tmp, MANIFEST), manifestText(b), { flag: "wx", mode: 0o644 });
    if (existsSync(t.dir)) {
      ops.rename(t.dir, old);
      try {
        ops.rename(tmp, t.dir);
      } catch (e) {
        try {
          ops.rename(old, t.dir);
        } catch (back) {
          stranded = `; the copy that was there could not be put back (${errCode(back)}) and is in ${old}`;
        }
        throw e;
      }
      replaced = true;
    } else {
      ops.rename(tmp, t.dir);
    }
  } catch (e) {
    // The temporary folder goes too. If even that fails, the error says where it is and how to remove it, after
    // what failed and where an old copy is left; the removal's own failure never replaces that error.
    let unfinished = "";
    try {
      ops.remove(tmp);
    } catch (r) {
      unfinished = `; the unfinished new copy could not be removed (${errCode(r)}): ${removeCommand([tmp])}`;
    }
    throw new UsageError(`cannot write ${t.dir}: ${(e as NodeJS.ErrnoException).code ?? (e as Error).message}${stranded}${unfinished}`);
  }
  if (!replaced) return undefined;
  try {
    ops.remove(old);
  } catch (e) {
    return `the old copy could not be removed (${errCode(e)}); remove what is left of it with: ${removeCommand([old])}`;
  }
  return undefined;
}

/**
 * Takes the skill folder out of its skills folder: renamed to a dot-folder beside it first, so a skills folder wormsign
 * cannot write to fails before anything is deleted, then deleted. If only the delete fails, the skill is already out of
 * the skills folder, and the error says where the rest is.
 */
function removeSkill(t: Target, ops: FsOps): void {
  const gone = join(t.skillsDir, `.${SKILL_NAME}.old-${process.pid}-${randomBytes(4).toString("hex")}`);
  let moved = false;
  try {
    ops.rename(t.dir, gone);
    moved = true;
    ops.remove(gone);
  } catch (e) {
    const why = (e as NodeJS.ErrnoException).code ?? (e as Error).message;
    throw new UsageError(`cannot remove ${t.dir}: ${why}${moved ? `; the skill is out of ${t.skillsDir}, but what is left of it is in ${gone}: ${removeCommand([gone])}` : ""}`);
  }
}

/**
 * What install does to one target: leave it alone, saying why, or write it, saying what that replaces; and the folders
 * an interrupted run left beside it, which install names but never removes.
 */
type InstallStep = ({ refused: string; what?: undefined } | { what: string; refused?: undefined }) & { t: Target; stray: string[] };

/** How a copy wormsign wrote differs from its own manifest: files edited, added or lost since, or not regular files. */
const modifications = (i: Inspection): string[] => [...list("edited", i.edited), ...list("extra", i.extra), ...list("lost", i.lost), ...list("not a regular file", i.odd)];

/**
 * How a copy that matches its own manifest differs from this build at the same version: edited along with its manifest,
 * or written by another build of that version (a clone's earlier commit). Another version's differences are an upgrade.
 */
const differences = (i: Inspection, b: Bundle): string[] => (i.version === b.version ? [...list("differs from this wormsign's skill", i.differs), ...list("missing", i.missing)] : []);

/** Inspects each target in turn and decides; one that cannot be read, or written when it would be, is a usage error. */
function* installSteps(targets: Target[], b: Bundle, o: Options): Generator<InstallStep> {
  for (const t of targets) {
    const i = inspect(t.dir, b);
    const found = leftovers(t);
    if (i.state === "foreign" && !o.force) {
      yield { t, stray: found, refused: `left alone, ${i.why}; --force replaces it` };
      continue;
    }
    if (i.state === "ours" && !unedited(i) && !o.force) {
      yield { t, stray: found, refused: `left alone, edited since wormsign installed it: ${[...i.edited, ...i.extra, ...i.lost, ...i.odd].join(", ")}; --force replaces it` };
      continue;
    }
    const why = unwritable(t);
    if (why) throw new UsageError(`cannot write ${t.dir}: ${why}`);
    const modified = i.state === "ours" ? modifications(i) : [];
    const different = i.state === "ours" ? differences(i, b) : [];
    const what =
      i.state === "absent"
        ? `installed ${b.version}`
        : i.state === "foreign"
          ? `replaced a folder wormsign did not write with ${b.version}`
          : modified.length > 0
            ? `replaced a modified copy with ${b.version} (${modified.join("; ")})`
            : i.version !== b.version
              ? `replaced ${i.version} with ${b.version}`
              : different.length > 0
                ? `replaced a different ${b.version} copy (edited, or another build; ${different.join("; ")})`
                : `reinstalled ${b.version}`;
    yield { t, stray: found, what };
  }
}

function install(targets: Target[], b: Bundle, o: Options, ops: FsOps): Outcome {
  const lines: string[] = [];
  let code: 0 | 1 = 0;
  // Every target is inspected and checked before the first write, so a target that cannot be read or written stops
  // the run before anything is written: the output never leaves out a copy that was written.
  const steps: Iterable<InstallStep> = [...installSteps(targets, b, o)];
  const written: string[] = [];
  for (const s of steps) {
    const strayLines = s.stray.length > 0 ? [`${label(s.t)}: warning: ${leftoverText(s.stray)}`] : [];
    if (s.refused !== undefined) {
      lines.push(`${label(s.t)}: ${s.refused}`, ...strayLines);
      code = 1;
      continue;
    }
    if (o.dryRun) {
      lines.push(`would write ${label(s.t)}: ${s.what}, ${b.files.size} files`, ...strayLines);
      continue;
    }
    let left: string | undefined;
    try {
      left = writeSkill(s.t, b, ops);
    } catch (e) {
      // An error no check before the first write can foresee (EIO, ENOSPC): the copies already written stay in place,
      // and the error says which, since the output that would have listed them is not printed.
      throw written.length > 0 ? new UsageError(`${(e as Error).message}; already written: ${written.join("; ")}`) : e;
    }
    lines.push(`${label(s.t)}: ${s.what}, ${b.files.size} files`, ...strayLines);
    written.push(`${label(s.t)}: ${s.what}`);
    if (left) lines.push(`${label(s.t)}: warning: ${left}`);
  }
  return { lines, code };
}

/**
 * Folders an interrupted install or uninstall left in a target's skills folder: `.wormsign.old-*` (a copy moved aside)
 * and `.wormsign.tmp-*` (a copy being written). A skills folder that does not exist leaves none.
 */
function leftovers(t: Target): string[] {
  let names: string[];
  try {
    names = readdirSync(t.skillsDir);
  } catch (e) {
    if (["ENOENT", "ENOTDIR"].includes(errCode(e))) return [];
    throw new UsageError(`cannot read ${t.skillsDir}: ${errCode(e)}`);
  }
  return names.filter((n) => n.startsWith(`.${SKILL_NAME}.old-`) || n.startsWith(`.${SKILL_NAME}.tmp-`)).sort().map((n) => join(t.skillsDir, n));
}

/** What `check` and `install` say about leftover folders: where they are, and the command that removes them. */
const leftoverText = (stray: string[]): string => `left over from an interrupted install or uninstall: ${stray.join(", ")}; remove with: ${removeCommand(stray)}`;

function check(targets: Target[], b: Bundle): Outcome {
  const lines: string[] = [];
  let code: 0 | 1 = 0;
  for (const t of targets) {
    const i = inspect(t.dir, b);
    const stray = leftovers(t);
    if (stray.length > 0) code = 1;
    const strayLine = stray.length > 0 ? [`${label(t)}: ${leftoverText(stray)}`] : [];
    if (current(i)) {
      lines.push(`${label(t)}: ok, ${b.version}`, ...strayLine);
      continue;
    }
    code = 1;
    if (i.state === "absent") lines.push(`${label(t)}: not installed`);
    else if (i.state === "foreign") lines.push(`${label(t)}: not wormsign's skill, ${i.why}`);
    else {
      // Another version is outdated; the same version with other files is a copy whose manifest was rewritten.
      const release = i.outdated && i.version !== b.version ? [`outdated: ${i.version}, this wormsign ships ${b.version}`] : list("differs from this wormsign's skill", i.differs);
      const problems = [...list("edited", i.edited), ...list("extra", i.extra), ...list("lost", i.lost), ...list("missing", i.missing), ...list("not a regular file", i.odd), ...list("not plain ASCII", i.notPlain), ...release];
      lines.push(`${label(t)}: ${problems.join("; ")}`);
    }
    lines.push(...strayLine);
  }
  return { lines, code };
}

/** Inspects each target in turn; one that cannot be read, or removed when it would be, is a usage error. */
function* uninstallSteps(targets: Target[], b: Bundle, o: Options): Generator<{ t: Target; i: Inspection }> {
  for (const t of targets) {
    const i = inspect(t.dir, b);
    if (i.state !== "absent" && (unedited(i) || o.force)) {
      const why = unwritable(t);
      if (why) throw new UsageError(`cannot remove ${t.dir}: ${why}`);
    }
    yield { t, i };
  }
}

function uninstall(targets: Target[], b: Bundle, o: Options, ops: FsOps): Outcome {
  const lines: string[] = [];
  let code: 0 | 1 = 0;
  // As for install: every target is inspected and checked before the first removal.
  const steps: Iterable<{ t: Target; i: Inspection }> = [...uninstallSteps(targets, b, o)];
  const removed: string[] = [];
  for (const { t, i } of steps) {
    if (i.state === "absent") {
      lines.push(`${label(t)}: not installed`);
    } else if (unedited(i) || o.force) {
      if (!o.dryRun) {
        try {
          removeSkill(t, ops);
        } catch (e) {
          // As for install: the copies already removed are named, since the output that would have listed them is not.
          throw removed.length > 0 ? new UsageError(`${(e as Error).message}; already removed: ${removed.join(", ")}`) : e;
        }
        removed.push(label(t));
      }
      lines.push(`${label(t)}: ${o.dryRun ? "would remove" : "removed"}`);
    } else {
      lines.push(`${label(t)}: left alone, ${i.state === "foreign" ? i.why : "edited since wormsign installed it"}; --force removes it`);
      code = 1;
    }
  }
  return { lines, code };
}

/**
 * The note shown when Cursor is selected and both folders it reads hold the skill: Claude Code's copy and the .agents
 * copy, which Codex, or Cursor without Claude Code, has. Cursor's docs do not say how it handles one skill name in two
 * folders (docs/skills.md), so the note says it may list the skill twice, not that it does, and names the check command
 * that inspects both copies (Cursor with Claude Code is one copy, so that command names Codex).
 */
function cursorNote(agents: Agent[], where: Where): string | undefined {
  if (!agents.includes("cursor") || !cursorReadsClaudeCopy(where)) return undefined;
  const [claude] = targetsFor(["claude"], where);
  const [shared] = targetsFor(["codex"], where);
  if (!claude || !shared || !existsSync(claude.dir) || !existsSync(shared.dir)) return undefined;
  const command = `wormsign skills check${where.projectRoot === undefined ? "" : " --project"} --agent claude,codex`;
  return `note: Cursor reads both ${claude.skillsDir} and ${shared.skillsDir}, so it may list this skill twice; \`${command}\` shows whether both copies match`;
}

/**
 * What a refused link leaves the user, and only what this command can do: the other scope's folders (--project, or
 * without it), never the folder behind the link; uninstall points at `check`, which reads through links. The command
 * repeats the --agent list given, so it names the same agents.
 */
function linkAlternative(action: Action, where: Where, agents: Agent[] | undefined): string {
  const agentFlag = agents ? ` --agent ${agents.join(",")}` : "";
  if (action === "uninstall") return `\`wormsign skills ${where.projectRoot === undefined ? "check" : "check --project"}${agentFlag}\` reads through it and shows what is there, for you to remove yourself`;
  return where.projectRoot === undefined
    ? `to install the skill anyway, run \`wormsign skills install --project${agentFlag}\` in a git repository: it writes into that repository's folders instead`
    : `to install the skill anyway, run \`wormsign skills install${agentFlag}\` without --project: it writes into your user folders instead`;
}

export function runSkills(action: Action, o: Options, where: Where, bundleOrDir?: Bundle | string, ops: FsOps = FS): Outcome {
  const agents = o.agents ?? detectAgents(where);
  if (agents.length === 0) {
    throw new UsageError(`no supported agent found (looked for ${claudeDir(where)}, ${join(where.home, ".codex")} and ${join(where.home, ".cursor")}); pass --agent with any of ${AGENTS.join(", ")}`);
  }
  const b = typeof bundleOrDir === "object" ? bundleOrDir : loadBundle(bundleOrDir);
  const targets = targetsFor(agents, where);
  if (action !== "check") {
    for (const t of targets) {
      const link = linkOnPath(t);
      if (link) throw new UsageError(`${link} is a symbolic link, which wormsign does not write through, even with --force; ${linkAlternative(action, where, o.agents)}`);
    }
  }
  const head = o.agents ? [] : [`agents found: ${agents.join(", ")}`];
  const out = action === "install" ? install(targets, b, o, ops) : action === "check" ? check(targets, b) : uninstall(targets, b, o, ops);
  const note = action === "uninstall" ? undefined : cursorNote(agents, where);
  return { lines: [...head, ...out.lines, ...(note ? [note] : [])], code: out.code };
}
