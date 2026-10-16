import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { registrySignals } from "../src/registry-signals.js";
import type { Packument, PackumentVersion } from "../src/registry-signals.js";
import { fx } from "./helpers.js";

/** Trimmed real packuments from registry.npmjs.org, fetched 2026-10-02 (see each file's _fixture). */
const real = (name: string): Packument => JSON.parse(readFileSync(fx("registry", `${name}.json`), "utf8")) as Packument;
const ids = (r: { signals: { ruleId: string }[] }) => r.signals.map((s) => s.ruleId);

/**
 * SYNTHETIC: `doc` plus one version published an hour after its newest one. The real keyv@6.0.0 worm version was
 * removed from the registry, so its manifest cannot be fetched; this follows the reported worm path instead
 * (https://research.jfrog.com/post/shai-hulud-is-back-august/): token publish, new preinstall, no provenance.
 */
function publish(doc: Packument, version: string, v: PackumentVersion): Packument {
  const last = Math.max(...Object.values(doc.time ?? {}).map((t) => Date.parse(t)));
  return { ...doc, time: { ...doc.time, [version]: new Date(last + 3_600_000).toISOString() }, versions: { ...doc.versions, [version]: v } };
}
const wormed = (publisher: string) => publish(real("keyv"), "6.0.1", { _npmUser: { name: publisher }, scripts: { preinstall: "node setup.mjs" } });

test("registry fixtures: real field shapes the signals read (trusted publisher, provenance, install script)", () => {
  const rc = real("keyv").versions!["6.0.0-rc.1"]!;
  assert.equal(rc._npmUser?.trustedPublisher?.id, "github");
  assert.ok(rc.dist?.attestations?.provenance);
  assert.equal(real("microtime").versions!["3.0.0-0"]!.scripts?.install, "node-gyp-build");
  assert.ok(real("keyv").time?.["6.0.0"] && !real("keyv").versions?.["6.0.0"], "the worm version is in time but gone from versions");
});

test("registry signals: a worm-style token publish after trusted releases adds a preinstall and drops provenance", () => {
  const r = registrySignals(wormed("jaredwray"), "6.0.1");
  assert.equal(r.previous, "6.0.0-rc.1", "newest earlier version still on the registry");
  assert.deepEqual(ids(r), ["WS-RG-001", "WS-RG-002"], "the token owner published 6.0.0-beta.1, so the publisher is not new");
  assert.equal(r.signals[0]!.severity, "high");
  assert.match(r.signals[0]!.message, /^keyv@6\.0\.1 adds a preinstall script that 6\.0\.0-rc\.1 did not have: node setup\.mjs$/);
  assert.match(r.signals[1]!.message, /keyv@6\.0\.1 .*without provenance.*6\.0\.0-rc\.1/);
});

test("registry signals: the same publish by an account outside the last five releases is a new publisher", () => {
  const r = registrySignals(wormed("co-maintainer"), "6.0.1");
  assert.deepEqual(ids(r), ["WS-RG-001", "WS-RG-002", "WS-RG-003"]);
  const s = r.signals[2]!;
  assert.equal(s.severity, "medium");
  assert.match(s.message, /keyv@6\.0\.1 was published by npm user co-maintainer, who published none of the 5 versions before it \(6\.0\.0-alpha\.3 to 6\.0\.0-rc\.1\)/);
  assert.match(s.message, /trusted publisher github/);
});

test("registry signals: an explicit previous version (the base lockfile's) is what the target is compared with", () => {
  const r = registrySignals(wormed("jaredwray"), "6.0.1", "6.0.0-beta.1");
  assert.equal(r.previous, "6.0.0-beta.1");
  assert.deepEqual(ids(r), ["WS-RG-001"], "6.0.0-beta.1 had no provenance, so none was dropped");
  assert.match(r.signals[0]!.message, /that 6\.0\.0-beta\.1 did not have/);
});

test("registry signals: the key is name@version whichever version it was compared with, so baselines stay stable", () => {
  const keys = (r: { signals: { key: string }[] }) => r.signals.map((s) => s.key);
  assert.deepEqual(keys(registrySignals(wormed("x"), "6.0.1")), ["keyv@6.0.1", "keyv@6.0.1", "keyv@6.0.1"]);
  assert.deepEqual(keys(registrySignals(wormed("x"), "6.0.1", "6.0.0-beta.1")), ["keyv@6.0.1", "keyv@6.0.1"]);
});

test("registry signals: a removed version is never the comparison, and a removed target is not compared", () => {
  // @ctrl/tinycolor 4.1.1 and 4.1.2 (Shai-Hulud, Sept 2025) are in time but not versions.
  const r = registrySignals(real("tinycolor"), "4.2.0");
  assert.equal(r.previous, "4.1.0");
  assert.deepEqual(ids(r), [], "4.2.0 gained provenance; nothing was dropped");
  assert.deepEqual(registrySignals(real("tinycolor"), "4.1.1"), { signals: [] });
  assert.deepEqual(registrySignals(real("tinycolor"), "4.2.0", "4.1.2"), { previous: undefined, signals: [] });
});

test("registry signals: a move to trusted publishing is not a new publisher", () => {
  const r = registrySignals(real("tinycolor"), "4.2.1");
  assert.equal(r.previous, "4.2.0");
  assert.deepEqual(ids(r), [], "scttcper published 4.2.0; 4.2.1 is a trusted publish");
});

test("registry signals: a backport is compared with its own line, not a newer major published just before it", () => {
  // Real: vite 4.5.6 was published 38 minutes after 5.4.12; the 5.x line has provenance, the 4.x line never had.
  const r = registrySignals(real("vite"), "4.5.6");
  assert.equal(r.previous, "4.5.5");
  assert.deepEqual(ids(r), []);
});

test("registry signals: a release on the current line is compared with that line, not an older-line backport published just before it", () => {
  // Real: vite 4.5.8 (no provenance) was published 15 hours before 5.4.14 and 6 minutes after 5.4.13.
  const r = registrySignals(real("vite"), "5.4.14");
  assert.equal(r.previous, "5.4.13");
  assert.deepEqual(ids(r), []);
  assert.equal(registrySignals(real("vite"), "5.4.13").previous, "5.4.12", "not 4.5.7, published between them");
  // SYNTHETIC: 5.4.14 republished without provenance, as a token publish would be.
  const doc = real("vite");
  doc.versions!["5.4.14"] = { _npmUser: { name: "vitebot" } };
  const s = registrySignals(doc, "5.4.14");
  assert.deepEqual(ids(s), ["WS-RG-002"]);
  assert.equal(s.signals[0]!.message, "vite@5.4.14 was published without provenance; 5.4.13 had a provenance attestation");
});

test("registry signals: the first version of a new major is compared with the newest earlier lower major", () => {
  const r = registrySignals(real("microtime"), "3.0.0-0");
  assert.equal(r.previous, "2.1.9");
  assert.deepEqual(ids(r), ["WS-RG-001"], "a real, benign install-script change: the documented false positive");
  assert.equal(r.signals[0]!.message, `microtime@3.0.0-0 changes its install script from 2.1.9's "prebuild-install || node-gyp rebuild" to: node-gyp-build`);
  assert.deepEqual(ids(registrySignals(real("microtime"), "2.1.9")), [], "unchanged install script");
});

test("registry signals: real publisher change (webpack 5.98.0) and the return to the usual publisher", () => {
  const r = registrySignals(real("webpack"), "5.98.0");
  assert.deepEqual(ids(r), ["WS-RG-003"]);
  assert.match(r.signals[0]!.message, /^webpack@5\.98\.0 was published by npm user thelarkinn, who published none of the 5 versions before it \(5\.95\.0 to 5\.97\.1\), published by npm user evilebottnawi$/);
  assert.deepEqual(ids(registrySignals(real("webpack"), "5.99.0")), [], "evilebottnawi published 4 of the 5 before");
});

test("registry signals: missing or malformed registry data yields no comparison rather than a crash", () => {
  assert.deepEqual(registrySignals({ name: "p", versions: { "1.0.0": {} } }, "1.0.0"), { previous: undefined, signals: [] });
  const doc: Packument = {
    name: "p",
    time: { "1.0.0": "2026-01-01T00:00:00Z", "1.0.1": "not a date" },
    versions: { "1.0.0": { scripts: { install: ["x"] } }, "1.0.1": { scripts: { install: 1, postinstall: null } } },
  };
  assert.deepEqual(registrySignals(doc, "1.0.1"), { previous: undefined, signals: [] }, "no valid publish time, no history");
  assert.deepEqual(ids(registrySignals(doc, "1.0.1", "1.0.0")), [], "non-string scripts are not scripts");
});
