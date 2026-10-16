#!/usr/bin/env node
// Build step, run after tsc: copies the vendored TOML parser (src/vendor/smol-toml/) into dist/src/vendor/smol-toml/,
// so the compiled readers can import it. tsc does not copy .js files.
//
// Before copying, every vendored file is hashed and compared with src/vendor/smol-toml/VENDORED.json, and the
// directory must hold exactly the files listed there. src/vendor/ itself must hold nothing but smol-toml/: ESLint
// skips that directory only (eslint.config.js), and tsc would compile a .ts file anywhere under src/. A mismatch stops
// the build: an edited, added or removed file is never shipped. Copied: the .js files, LICENSE (the BSD-3-Clause notice must travel with the code) and
// VENDORED.json. The .d.ts files are for tsc only and are not copied.
//
// scripts/verify-vendor.mjs (network) re-derives the same files from the pinned npm tarball; this script and
// test/vendor-integrity.test.ts are the offline checks.
//
// Usage: node scripts/copy-vendor.mjs   (run from anywhere; paths are relative to this file)
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const SRC = join(ROOT, "src", "vendor", "smol-toml");
const OUT = join(ROOT, "dist", "src", "vendor", "smol-toml");

const fail = (message) => {
  console.error(`copy-vendor: ${message}`);
  process.exit(1);
};

const vendorDir = readdirSync(join(ROOT, "src", "vendor")).sort();
if (JSON.stringify(vendorDir) !== JSON.stringify(["smol-toml"])) fail(`src/vendor holds [${vendorDir.join(", ")}]; only smol-toml is vendored`);

let record;
try {
  record = JSON.parse(readFileSync(join(SRC, "VENDORED.json"), "utf8"));
} catch (e) {
  fail(`cannot read src/vendor/smol-toml/VENDORED.json: ${e.message}`);
}
const listed = Object.keys(record.files ?? {}).sort();
const present = readdirSync(SRC).filter((f) => f !== "VENDORED.json").sort();
if (listed.length === 0) fail("VENDORED.json lists no files");
if (JSON.stringify(listed) !== JSON.stringify(present)) {
  fail(`src/vendor/smol-toml holds [${present.join(", ")}] but VENDORED.json lists [${listed.join(", ")}]`);
}
for (const name of listed) {
  const got = createHash("sha256").update(readFileSync(join(SRC, name))).digest("hex");
  if (got !== record.files[name]) fail(`${name} has sha256 ${got}, VENDORED.json records ${record.files[name]}`);
}

mkdirSync(OUT, { recursive: true });
const shipped = [...listed.filter((f) => f.endsWith(".js") || f === "LICENSE"), "VENDORED.json"];
for (const name of shipped) copyFileSync(join(SRC, name), join(OUT, name));
