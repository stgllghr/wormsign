import { dirname, isAbsolute, join, posix, relative, sep } from "node:path";
import { lstatSync, realpathSync, statSync } from "node:fs";
import type { Finding, Severity } from "./types.js";
import { UsageError, keyDigest, makeFinding, severityRank } from "./types.js";
import { MAX_TEXT_BYTES, readBytes, readChunks, readText, toPosix, walk } from "./fsutil.js";
import type { ScanContext } from "./checks/context.js";
import { dedupe, notChecked } from "./checks/context.js";
import { checkLifecycle, checkPnpmWorkspace } from "./checks/lifecycle.js";
import { checkLockfile } from "./checks/lockfile.js";
import { WORKFLOW_PATH, checkWorkflow } from "./checks/workflows.js";
import { candidateNames, checkFile, hashesOnlyCheckedWithHashAll } from "./checks/files.js";
import { checkExfil, isExfilScannable } from "./checks/exfil.js";
import { NM_PACKAGE_JSON, checkInstalledPackage } from "./checks/nodemodules.js";
import { PERSISTENCE_PATH, checkPersistence } from "./checks/persistence.js";
import { BASELINE_FILE } from "./baseline.js";
import { configuredCode, isGateConfig } from "./diff.js";
import { isPythonInputName } from "./python/manifest.js";
import { LOCKFILE_NAMES, parseLockfileText } from "./lockfile/index.js";
import type { ParsedLockfile } from "./lockfile/index.js";
import { yamlPaths } from "./settings-yaml.js";
import { fold } from "./tree.js";
import type { Tree } from "./tree.js";

export interface ScanOptions {
  nodeModules: boolean;
  /** Path prefixes (posix, relative to root) excluded from scanning. Set from the baseline file. */
  ignorePrefixes?: string[];
}

export interface ScanResult {
  findings: Finding[];
  filesScanned: number;
  /** Files under ignorePrefixes, which were not read. */
  filesIgnored: number;
  /** Things the scan could not do, shown to the user so that silence is never mistaken for clean. */
  notes: string[];
}

/** Lockfiles can exceed the 2 MiB text limit in large monorepos, so they get their own, still bounded, limit. */
const MAX_LOCKFILE_BYTES = 64 * 1024 * 1024;
/**
 * The largest code file searched for exfiltration endpoints from the IOC list, or hashed as code a package manager
 * runs: the hash cap of checks/files.ts. The endpoint IOCs come from payloads larger than the 2 MiB text cap (the
 * 2025-09 bundle.js was about 3.6 MB, the 2025-11 bun_environment.js about 10 MB), and they are plain substrings, so a
 * chunked search costs time linear in the file, unlike the generic patterns.
 */
const MAX_CODE_BYTES = 64 * 1024 * 1024;

/** Files a package manager acts on that wormsign cannot parse, by folded name. A Map, so names like `constructor` are not members. */
const UNSUPPORTED = new Map([
  ["package.yaml", "if this is a pnpm manifest, pnpm runs its scripts, but wormsign cannot parse YAML manifests"],
  ["package.json5", "if this is a pnpm manifest, pnpm runs its scripts, but wormsign cannot parse JSON5 manifests"],
  ["bun.lock", "wormsign cannot parse Bun lockfiles, so its packages were not checked against the IOC list"],
  ["bun.lockb", "wormsign cannot parse Bun lockfiles, so its packages were not checked against the IOC list"],
]);
const PNPM_ONLY_MANIFESTS = new Set(["package.yaml", "package.json5"]);

/**
 * A file's name as a package manager on macOS or Windows opens it: npm 10.9.2 there reads PACKAGE.JSON and
 * PACKAGE-LOCK.JSON as package.json and package-lock.json, so every file is classified by its folded name (tree.ts).
 */
const nameOf = (rel: string): string => fold(rel.split("/").pop() as string);

/** `name` is a folded file name. */
const isLockfile = (name: string): boolean => (LOCKFILE_NAMES as readonly string[]).includes(name);

/**
 * A lockfile parsed by its folded name, so that PACKAGE-LOCK.JSON is read as the package-lock.json a case-insensitive
 * disk makes it. The result keeps the path as written.
 */
export function parseLockfileAnyCase(rel: string, text: string): ParsedLockfile | undefined {
  const lock = parseLockfileText(posix.join(posix.dirname(rel), nameOf(rel)), text);
  return lock && { ...lock, file: rel };
}

/** Package-manager files that run code (WS-LC-004), as diff gates them; the baseline file is wormsign's own. */
const runsCode = (rel: string): boolean => isGateConfig(rel) && nameOf(rel) !== BASELINE_FILE;

/**
 * A path whose content decides what runs at install, in CI or in an editor, so
 * a symlink there must not hide it. That includes anything under .claude/:
 * Claude Code reads a skill from a symlinked folder's target
 * (code.claude.com/docs/en/skills), and a skill folder can be a plugin.
 */
function decidesExecution(rel: string): boolean {
  const name = nameOf(rel);
  return name === "package.json" || name === "pnpm-workspace.yaml" || UNSUPPORTED.has(name) || isLockfile(name) || runsCode(rel) || WORKFLOW_PATH.test(rel) || PERSISTENCE_PATH.test(fold(rel)) || /(^|\/)\.github(\/workflows)?$/.test(rel) || /(^|\/)\.(vscode$|claude($|\/))/i.test(fold(rel));
}

/** Whether rel is one of the prefixes or under one; a prefix covers its directory, not a sibling sharing its name. */
const under = (rel: string, prefixes: string[]): boolean => prefixes.some((p) => rel === p || rel.startsWith(p.endsWith("/") ? p : `${p}/`));

/**
 * One whole-file WS-SC-900 per file: two checks that cannot read the same file (pnpm-workspace.yaml's overrides and its code
 * settings) report it once, with every reason, at the highest severity, keyed on all of the reasons' keys, so a
 * baseline entry covers exactly that set and a new reason fails again.
 */
function oneNotCheckedPerFile(findings: Finding[]): Finding[] {
  const byFile = new Map<string, Finding[]>();
  // Only notChecked()'s whole-file findings: a WS-SC-900 for one entry of a file (a dependency path) stays its own.
  for (const f of findings) if (f.ruleId === "WS-SC-900" && f.key.startsWith("not-checked ")) byFile.set(f.file ?? "", [...(byFile.get(f.file ?? "") ?? []), f]);
  const merged = new Map<Finding, Finding | undefined>();
  for (const group of byFile.values()) {
    if (group.length < 2) continue;
    const first = group[0] as Finding;
    const severity = group.reduce<Severity>((s, f) => (severityRank(f.severity) > severityRank(s) ? f.severity : s), first.severity);
    const prefix = `${first.file ?? ""} was not checked: `;
    const why = group.map((f) => (f.message.startsWith(prefix) ? f.message.slice(prefix.length) : f.message)).join("; and ");
    const key = `not-checked ${keyDigest(group.map((f) => f.key).sort().join("\0"))}`;
    merged.set(first, makeFinding({ ruleId: "WS-SC-900", severity, message: `${prefix}${why}`, ...(first.file !== undefined ? { file: first.file } : {}), key }));
    for (const f of group.slice(1)) merged.set(f, undefined);
  }
  const out: Finding[] = [];
  for (const f of findings) {
    if (!merged.has(f)) out.push(f);
    else if (merged.get(f) !== undefined) out.push(merged.get(f) as Finding);
  }
  return out;
}

/** Appends one by one: spreading a 100,000-element array into push() overflows the stack and loses the scan. */
function append(to: Finding[], from: Finding[]): void {
  for (const f of from) to.push(f);
}

export function scanDirectory(root: string, ctx: ScanContext, opts: ScanOptions): ScanResult {
  try {
    if (!statSync(root).isDirectory()) throw new Error();
  } catch {
    throw new UsageError(`not a directory: ${root}`);
  }
  const findings: Finding[] = [];
  const notes: string[] = [];
  const names = candidateNames(ctx);
  const ignore = opts.ignorePrefixes ?? [];
  const ignored = (rel: string): boolean => under(rel, ignore);
  // A dependency path is read by the package manager, which on macOS folds case, so `file:./TEST/x` reaches an ignored test/x.
  const foldedIgnore = ignore.map(fold);
  const ignoredAnyCase = (rel: string): boolean => under(fold(rel), foldedIgnore);
  const unhashed = (rel: string) => (why: string) => notes.push(`not hashed ${rel}: ${why}`);
  let filesScanned = 0;
  let filesIgnored = 0;
  let manifests = 0;
  let lockfiles = 0;
  let installed = 0;
  const realRoot = realpathSync(root);
  // Paths that decide what runs, by folded path: two in one group are one file on a case-insensitive disk.
  const byFold = new Map<string, string[]>();
  const track = (rel: string): void => {
    if (rel.split("/").includes("node_modules") || !decidesExecution(rel)) return;
    const key = fold(rel);
    const group = byFold.get(key);
    if (group) group.push(rel);
    else byFold.set(key, [rel]);
  };
  const pmFiles: string[] = [];
  /** Python lockfiles, requirements files and manifests: scan does not read them (soak does), and says so. */
  const pythonInputs: string[] = [];
  /**
   * A symlinked directory whose target walk() never visits under its real path:
   * outside the root, or in node_modules, .git or an ignored prefix, so its
   * content goes unchecked. npm 10.9.2 and pnpm 11.16 followed such a link only
   * when a workspace pattern or a file: dependency named it or a path through it,
   * and a package.json at its top is what makes it a package there. That case is
   * high; any other directory link (bazel-bin, a Nix `result`) is low. Only the
   * target's metadata is read, never its content.
   */
  const hiddenDirectory = (rel: string): Severity | undefined => {
    let target: string;
    try {
      target = realpathSync(join(root, rel));
      if (!statSync(target).isDirectory()) return undefined;
    } catch {
      return undefined; // dangling: there is nothing for a package manager to follow either
    }
    const inside = relative(realRoot, target);
    const r = toPosix(inside);
    const unscanned = inside.split(sep)[0] === ".." || isAbsolute(inside) || r.split("/").some((s) => s === "node_modules" || s === ".git") || ignored(r);
    if (!unscanned) return undefined;
    try {
      return statSync(join(target, "package.json"), { throwIfNoEntry: false })?.isFile() ? "high" : "low";
    } catch {
      return "high"; // ELOOP, EACCES: a package.json may be there, so fail closed
    }
  };
  const onSymlink = (rel: string): void => {
    // Package managers follow a symlinked package.json, lockfile or workflow; wormsign never reads through one.
    if (ignored(rel)) return;
    track(rel);
    // A link named like a payload is never read, so only its name is checked; the skipped hash is a note.
    if (names.has(rel.split("/").pop() as string)) append(findings, checkFile(rel, undefined, names, ctx, unhashed(rel)));
    if (decidesExecution(rel)) {
      findings.push(notChecked(rel, "it is a symlink, which package managers follow but wormsign does not"));
      return;
    }
    const severity = rel.split("/").includes("node_modules") ? undefined : hiddenDirectory(rel);
    if (severity === "high") {
      findings.push(notChecked(rel, "it is a symlink to a package directory wormsign does not scan (or to one whose package.json it could not inspect); npm and pnpm can run its scripts when a workspace pattern or a file: dependency names it"));
    } else if (severity) {
      findings.push(notChecked(rel, "it is a symlink to a directory wormsign does not scan; npm and pnpm follow it when a workspace pattern or a file: dependency names a package inside it", severity));
    }
  };
  const onUnreadable = (rel: string, code: string): void => {
    if (!ignored(rel)) findings.push(notChecked(rel || ".", `it could not be read (${code}), so nothing in it was checked`));
  };

  for (const rel of walk(root, { includeNodeModules: opts.nodeModules, onSymlink, onUnreadable })) {
    if (ignored(rel)) {
      filesIgnored++;
      continue;
    }
    filesScanned++;
    const abs = join(root, rel);
    const name = nameOf(rel);
    const inNodeModules = rel.split("/").includes("node_modules");
    track(rel);
    if (!inNodeModules && runsCode(rel)) pmFiles.push(rel);
    if (!inNodeModules && isPythonInputName(name, rel)) pythonInputs.push(rel);

    append(findings, checkFile(rel, abs, names, ctx, unhashed(rel)));

    if (!inNodeModules && isLockfile(name)) {
      lockfiles++;
      append(findings, scanLockfile(rel, abs, ctx));
      continue;
    }
    const unsupported = inNodeModules ? undefined : UNSUPPORTED.get(name);
    if (unsupported !== undefined) {
      const skip = PNPM_ONLY_MANIFESTS.has(name) ? notPnpmScripts(abs) : undefined;
      if (skip) notes.push(`skipped ${rel}: ${skip}`);
      else findings.push(notChecked(rel, unsupported));
      continue;
    }

    const isManifest = name === "package.json" && (!inNodeModules || NM_PACKAGE_JSON.test(fold(rel)));
    const isWorkflow = WORKFLOW_PATH.test(rel);
    const isPersistence = !inNodeModules && PERSISTENCE_PATH.test(fold(rel));
    const isPnpmWorkspace = !inNodeModules && name === "pnpm-workspace.yaml";
    const wantsExfil = isExfilScannable(rel);
    if (isManifest) {
      if (inNodeModules) installed++;
      else manifests++;
    }
    if (!isManifest && !isWorkflow && !isPersistence && !isPnpmWorkspace && !wantsExfil) continue;
    const read = readText(abs);
    if ("problem" in read) {
      const decides = isManifest || isWorkflow || isPersistence || isPnpmWorkspace;
      if (decides) findings.push(notChecked(rel, read.problem));
      // Workflow file-name IOCs need no content.
      if (isWorkflow) append(findings, checkWorkflow(rel, "", ctx));
      if (wantsExfil) {
        const searched = searchIocEndpoints(rel, abs, ctx);
        if ("problem" in searched) {
          // Low: an attacker who can change a payload can change its endpoint too, which defeats this IOC at any size,
          // and large generated code and JSON is common. Still a finding, not a note, so a baseline must accept it.
          if (!decides) findings.push(notChecked(rel, `${searched.problem}, so it was not searched for exfiltration endpoints from the IOC list`, "low"));
        } else {
          append(findings, searched.findings);
          // In node_modules only IOC endpoints are ever checked, so nothing was left out there.
          if (!inNodeModules) notes.push(`searched ${rel} for exfiltration endpoints from the IOC list only, not for webhook, paste or tunnel hosts (WS-EX-001): ${read.problem}`);
        }
      }
      continue;
    }
    const text = read.text;
    if (isManifest) append(findings, inNodeModules ? checkInstalledPackage(rel, abs, text, ctx) : checkLifecycle(rel, text, ctx, { root: realRoot, isIgnored: ignoredAnyCase, ignored: ignore }));
    if (isWorkflow) append(findings, checkWorkflow(rel, text, ctx));
    if (isPersistence) append(findings, checkPersistence(rel, text, ctx));
    if (isPnpmWorkspace) append(findings, checkPnpmWorkspace(rel, text, { root: realRoot, isIgnored: ignoredAnyCase, ignored: ignore }));
    if (wantsExfil) append(findings, checkExfil(rel, text, ctx, { iocOnly: inNodeModules }));
  }
  append(findings, packageManagerCode(root, pmFiles));
  for (const group of byFold.values()) {
    if (group.length < 2) continue;
    for (const rel of group) {
      const others = group.filter((r) => r !== rel);
      // A few names, not all: n such names in one tree would otherwise make a report of n * n names.
      const named = others.length > 3 ? `${others.slice(0, 3).join(", ")} and ${others.length - 3} more` : others.join(", ");
      findings.push(notChecked(rel, `${named} ${others.length > 1 ? "have" : "has"} the same name in another case or Unicode form, or but for trailing periods or spaces (which Windows drops), and a case-insensitive disk (macOS, Windows) holds only one of them, so which one a package manager or CI reads is not known`));
    }
  }
  if (!opts.nodeModules) notes.push("node_modules was not scanned (use --node-modules for a deep scan)");
  else if (installed === 0) notes.push("--node-modules found no installed packages (not installed yet, or Yarn Plug'n'Play), so the deep scan checked nothing");
  if (manifests > 0 && lockfiles === 0) notes.push("no npm, pnpm or yarn lockfile found, so dependency versions were not checked against the IOC list");
  if (pythonInputs.length > 0) {
    notes.push(
      `${pythonInputs.length} Python lockfile(s), requirements file(s) or manifest(s) found, which scan does not read: \`wormsign soak\` checks the versions they pin: ${pythonInputs.slice(0, 10).join(", ")}${pythonInputs.length > 10 ? ", ..." : ""}`,
    );
  }
  const unnamed = hashesOnlyCheckedWithHashAll(ctx);
  if (unnamed.length > 0) notes.push(`${unnamed.length} hash IOC(s) have no published file name and are checked only with --hash-all: ${unnamed.join(", ")}`);
  return { findings: oneNotCheckedPerFile(dedupe(findings)), filesScanned, filesIgnored, notes };
}

/**
 * The exfiltration endpoints from the IOC list in a code file too large to read as text (or holding NUL bytes), up to
 * MAX_CODE_BYTES, by the same check as smaller files run on 2 MiB chunks. Chunks overlap by the longest endpoint (3
 * UTF-8 bytes per UTF-16 unit, as the check reads them), so a match across a chunk boundary is whole in one chunk.
 */
function searchIocEndpoints(rel: string, abs: string, ctx: ScanContext): { findings: Finding[] } | { problem: string } {
  const overlap = 3 * ctx.iocs.endpoints.reduce((n, e) => Math.max(n, e.substring.length), 0);
  const findings: Finding[] = [];
  const read = readChunks(abs, { maxBytes: MAX_CODE_BYTES, chunkBytes: MAX_TEXT_BYTES, overlap }, (chunk, line) => {
    // Lines are counted from the chunk's start; the fingerprint does not hold the line, so a match seen in two chunks is one finding.
    for (const f of checkExfil(rel, chunk.toString("utf8"), ctx, { iocOnly: true })) findings.push({ ...f, line: (f.line ?? 1) + line - 1 });
  });
  return "problem" in read ? read : { findings };
}

/**
 * Config that names code for a package manager to run, by folded file name: the settings diff follows
 * (configuredCode), and in .npmrc also node-options, which npm passes to the Node.js of every script it runs, and
 * pnpm's global-pnpmfile. .npmrc keys are matched in any case and with _ for -, as pnpm 10.34.6 reads them (tree.ts).
 */
const CODE_SETTINGS = new Map<string, { yaml: string[]; runs: string } | { ini: RegExp; runs: string }>([
  [".yarnrc.yml", { yaml: ["yarnPath", "plugins", "injectEnvironmentFiles"], runs: "Yarn 2+ runs the yarnPath release and the plugins on every yarn command and loads injectEnvironmentFiles into every script" }],
  ["pnpm-workspace.yaml", { yaml: ["pnpmfile", "globalPnpmfile"], runs: "pnpm 11 runs a pnpmfile's hooks on install" }],
  // [ \t], not \s: under the m flag \s also matches newlines, which makes a file of blank lines quadratic.
  [".npmrc", { ini: /^[ \t]*["']?(node[-_]options|script[-_]shell|(?:global[-_])?pnpmfile)["']?[ \t]*=(.*)$/gim, runs: "npm passes node-options to the Node.js of every script it runs and runs every script with script-shell, and pnpm 9 runs the pnpmfile it names on install" }],
  [".yarnrc", { ini: /^[ \t]*"?(yarn-path)"?[ \t]+(.*)$/gm, runs: "Yarn 1 runs the yarn-path file in its place on every yarn command" }],
]);

/**
 * node-options flags that load no code and change no module resolution, only a memory or stack limit or what is
 * printed: an .npmrc that sets only these (often --max-old-space-size, for large builds) runs nothing new. Node.js
 * also accepts _ for - in V8 options.
 */
const INERT_NODE_OPTION = /^--(?:max[-_]old[-_]space[-_]size|max[-_]semi[-_]space[-_]size|stack[-_]size|max-http-header-size)=\d+$|^--(?:enable-source-maps|no-warnings|no-deprecation|trace-warnings|trace-deprecation)$|^--unhandled-rejections=[a-z-]+$|^--dns-result-order=[a-z0-9]+$/;
const inertNodeOptions = (value: string): boolean =>
  value
    .replace(/^(["'])(.*)\1$/, "$2")
    .split(/[ \t]+/)
    .filter((t) => t !== "")
    .every((t) => INERT_NODE_OPTION.test(t));

/** Why a file is code a package manager runs from where it lies, as diff's isGateConfig and YARN_CODE list them. */
function codeRole(rel: string): string | undefined {
  const name = nameOf(rel);
  const path = fold(rel);
  if (name === ".pnpmfile.cjs" || name === ".pnpmfile.mjs") return "pnpm runs a pnpmfile's hooks on install";
  if (name === ".env.yarn") return "Yarn 4 loads .env.yarn into every script it runs, and NODE_OPTIONS there can load any file";
  if (/(^|\/)\.yarn\/releases\//.test(path)) return "a yarnPath that names a release here makes every yarn command run it";
  if (/(^|\/)\.yarn\/plugins\//.test(path)) return "yarn runs the plugins .yarnrc.yml lists from here on every command";
  if (/(^|\/)\.pnp\.(cjs|loader\.mjs)$/.test(path)) return "yarn loads its Plug'n'Play loader on every yarn run";
  return undefined;
}

/**
 * The file at `p` (relative, normalized, no ".."), or why it cannot be read without following a symlink, or undefined
 * when it does not exist: then the setting that names it runs nothing.
 */
function regularFileAt(root: string, p: string): { rel: string } | { problem: string } | undefined {
  const parts = p.split("/");
  for (let i = 1; i <= parts.length; i++) {
    let st;
    try {
      st = lstatSync(join(root, ...parts.slice(0, i)));
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      return code === "ENOENT" || code === "ENOTDIR" ? undefined : { problem: `it could not be read (${code ?? "error"})` };
    }
    if (st.isSymbolicLink()) return { problem: "it is reached through a symlink, which wormsign does not follow" };
    if (i === parts.length && !st.isFile()) return { problem: "it is not a regular file" };
  }
  return { rel: p };
}

/**
 * WS-LC-004: code a package manager runs without any lifecycle script, from `files` (outside node_modules and the
 * ignored paths): settings that name such code, keyed on their values, and the code itself, keyed on its content,
 * so that a baseline entry accepts one reviewed version. A file such a setting names is reported wherever it is.
 */
function packageManagerCode(root: string, files: string[]): Finding[] {
  const out: Finding[] = [];
  const code = new Map<string, string>();
  const configs: string[] = [];
  for (const rel of files) {
    if (CODE_SETTINGS.has(nameOf(rel))) configs.push(rel);
    else {
      const role = codeRole(rel);
      if (role !== undefined) code.set(rel, role);
    }
  }
  const texts = new Map<string, string>();
  for (const rel of configs) {
    const read = readText(join(root, rel));
    if ("problem" in read) {
      out.push(notChecked(rel, `${read.problem}, so the code it may make a package manager run is not known`));
      continue;
    }
    texts.set(rel, read.text);
    const spec = CODE_SETTINGS.get(nameOf(rel)) as { yaml: string[]; runs: string } | { ini: RegExp; runs: string };
    let settings: string[];
    if ("yaml" in spec) {
      const doc = yamlPaths(read.text, spec.yaml);
      // As notPnpmScripts: no YAML spells one of these keys without its letters or a backslash escape, so YAML the
      // reader does not model elsewhere in the file (a flow list over several lines) cannot hide one.
      const mayName = new RegExp(`${spec.yaml.join("|")}|\\\\`, "i").test(read.text);
      if (doc.problems.length > 0 && mayName) out.push(notChecked(rel, `it has YAML outside the subset wormsign reads (${doc.problems.slice(0, 3).join("; ").slice(0, 200)}), so the code it may make a package manager run is not known`));
      settings = [...doc.values].filter(([, v]) => v.length > 0).map(([k, v]) => `${k}: ${v.join(", ")}`);
    } else {
      settings = [...read.text.matchAll(spec.ini)].filter((m) => !(/^node[-_]options$/i.test(m[1] as string) && inertNodeOptions((m[2] ?? "").trim()))).map((m) => `${m[1]}=${(m[2] ?? "").trim()}`);
    }
    if (settings.length === 0) continue;
    out.push(
      makeFinding({
        ruleId: "WS-LC-004",
        severity: "high",
        message: `${rel.split("/").pop()} sets ${settings.join("; ").slice(0, 200)}: ${spec.runs}`,
        file: rel,
        key: `settings:${keyDigest(settings.join("\n"))}`,
      }),
    );
  }
  // The files those settings name, resolved as diff resolves them.
  const tree: Tree = { label: root, list: () => [...texts.keys()], read: (p) => texts.get(p) };
  for (const p of configuredCode(tree).paths) {
    const at = regularFileAt(root, p);
    if (at === undefined) continue;
    if ("problem" in at) out.push(notChecked(p, `${at.problem}, and package-manager config in this tree names it as code to run`));
    else code.set(at.rel, "package-manager config in this tree names it as code to run");
  }
  for (const [rel, role] of code) {
    const read = readBytes(join(root, rel), MAX_CODE_BYTES);
    if ("problem" in read) {
      out.push(notChecked(rel, `${read.problem}, and it is code a package manager runs`));
      continue;
    }
    out.push(makeFinding({ ruleId: "WS-LC-004", severity: "high", message: `${rel} is code a package manager runs without any lifecycle script: ${role}`, file: rel, key: `code:${keyDigest(read.bytes)}` }));
  }
  return out;
}

/**
 * Why a package.yaml or package.json5 cannot give pnpm install scripts, or
 * undefined when it might. pnpm 11.16 reads package.json in its place when both
 * exist, so a Haskell (hpack) package.yaml beside one is inert. Without the word
 * `scripts` there are none, unless a YAML or JSON5 escape spells it (pnpm
 * accepted "scr\x69pts"), hence any backslash also counts.
 */
function notPnpmScripts(abs: string): string | undefined {
  try {
    lstatSync(join(dirname(abs), "package.json"));
    return "pnpm reads the package.json next to it instead";
  } catch {
    // no package.json: pnpm would read this file
  }
  const read = readText(abs);
  if ("problem" in read || /scripts|\\/.test(read.text)) return undefined;
  return "it declares no scripts";
}

function scanLockfile(rel: string, abs: string, ctx: ScanContext): Finding[] {
  const read = readText(abs, MAX_LOCKFILE_BYTES);
  if ("problem" in read) return [notChecked(rel, read.problem)];
  try {
    const lock = parseLockfileAnyCase(rel, read.text);
    return lock ? checkLockfile(lock, ctx) : [];
  } catch (e) {
    return [notChecked(rel, `it could not be parsed (${(e as Error).message.slice(0, 120)})`)];
  }
}
