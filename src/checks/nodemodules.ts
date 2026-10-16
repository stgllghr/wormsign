import { lstatSync } from "node:fs";
import { dirname, join } from "node:path";
import type { Finding } from "../types.js";
import { makeFinding } from "../types.js";
import type { ScanContext } from "./context.js";
import { notChecked } from "./context.js";
import { INSTALL_HOOKS, contentFindings, parseManifest } from "./lifecycle.js";

export const NM_PACKAGE_JSON = /(^|\/)node_modules\/(@[^/]+\/)?[^/@][^/]*\/package\.json$/;

/**
 * Checks one installed package: IOC name@version, and any install-time script.
 * Every package with an install script is reported (WS-NM-001) because the point
 * of the deep scan is an inventory of what ran code at install time.
 */
export function checkInstalledPackage(rel: string, abs: string, text: string, ctx: ScanContext): Finding[] {
  const pkg = parseManifest(text);
  if (!pkg) return [notChecked(rel, "it is not a valid JSON object, so the installed package could not be checked", "high", text)];
  if (typeof pkg.name !== "string" || typeof pkg.version !== "string") return [];
  const out: Finding[] = [];
  const id = `${pkg.name}@${pkg.version}`;
  const src = ctx.pkgIndex.lookup(pkg.name, pkg.version);
  if (src) {
    out.push(makeFinding({ ruleId: "WS-LK-001", severity: "critical", message: `Installed package ${id} is listed as compromised`, file: rel, key: id, source: src }));
  }
  const scripts = pkg.scripts && typeof pkg.scripts === "object" ? pkg.scripts : {};
  for (const hook of INSTALL_HOOKS) {
    const cmd = scripts[hook];
    if (typeof cmd !== "string") continue;
    out.push(makeFinding({ ruleId: "WS-NM-001", severity: "medium", message: `${id} runs a ${hook} script: ${cmd.slice(0, 120)}`, file: rel, key: `${id}:${hook}` }));
    out.push(...contentFindings(rel, hook, cmd, undefined, ctx));
  }
  // npm runs `node-gyp rebuild` at install when binding.gyp exists and no install script is declared.
  const hasHook = INSTALL_HOOKS.some((h) => typeof scripts[h] === "string");
  // lstat: an entry of that name is enough, and a symlink is never followed out of the scan root.
  if (!hasHook && lstatSync(join(dirname(abs), "binding.gyp"), { throwIfNoEntry: false })) {
    out.push(makeFinding({ ruleId: "WS-NM-001", severity: "low", message: `${id} has binding.gyp, so npm runs node-gyp rebuild at install`, file: rel, key: `${id}:gyp` }));
  }
  return out;
}
