#!/usr/bin/env node
// Re-derives the vendored TOML parser from the pinned npm tarball and checks the copy in src/vendor/smol-toml/
// (network; CI runs it on every change and monthly). The pin is src/vendor/smol-toml/VENDORED.json: package, version
// and the tarball's sha512 integrity.
//
// Checks, in order:
// 1. The registry's metadata for that version names the same tarball integrity as VENDORED.json.
// 2. The downloaded tarball's sha512 equals that integrity.
// 3. Every vendored file is byte-identical to the tarball's package/dist/<file> (package/LICENSE for LICENSE), the
//    vendored set is exactly the tarball's dist/*.js (minus the CommonJS build, index.cjs), dist/*.d.ts and LICENSE,
//    and VENDORED.json's sha256 for each file is right.
// 4. The registry's SLSA provenance statement for the version names the tarball's sha512 as its subject and the
//    repository, ref and commit VENDORED.json records. This decodes the statement; it does not verify its Sigstore
//    signature. `npm audit signatures` in a project that installs the same version does that (see VENDORED.json).
//
// Usage: node scripts/verify-vendor.mjs [--write]
//   --write  (maintainer, to upgrade) after checks 1, 2 and 4, replace src/vendor/smol-toml/ with the tarball's
//            files and rewrite VENDORED.json's file hashes and upstream commit. Edit "version", "tarball" and
//            "integrity" in VENDORED.json first; review the diff before committing.
// Exit 0 when every check holds, 1 otherwise.
/* global fetch, AbortSignal, Buffer */
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const DIR = join(ROOT, "src", "vendor", "smol-toml");
const RECORD = join(DIR, "VENDORED.json");
const REGISTRY = "https://registry.npmjs.org";
const SLSA = "https://slsa.dev/provenance/v1";

const args = process.argv.slice(2);
const write = args.includes("--write");
for (const a of args) {
  if (a !== "--write") {
    console.error(`unknown argument: ${a}\nusage: node scripts/verify-vendor.mjs [--write]`);
    process.exit(1);
  }
}

const problems = [];
const check = (ok, message) => {
  if (!ok) problems.push(message);
  return ok;
};

async function get(url) {
  const res = await fetch(url, { signal: AbortSignal.timeout(60_000), redirect: "error" });
  if (!res.ok) throw new Error(`GET ${url}: HTTP ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

/** The regular files of a (ustar or pax) tar archive, by path. */
function untar(buf) {
  const files = new Map();
  let paxPath;
  for (let off = 0; off + 512 <= buf.length; ) {
    const header = buf.subarray(off, off + 512);
    if (header.every((b) => b === 0)) break;
    const field = (start, len) => header.subarray(start, start + len).toString("utf8").replace(/\0.*$/s, "");
    const size = parseInt(field(124, 12).trim() || "0", 8);
    const type = String.fromCharCode(header[156] || 48);
    const prefix = field(345, 155);
    const name = paxPath ?? (prefix ? `${prefix}/${field(0, 100)}` : field(0, 100));
    const body = buf.subarray(off + 512, off + 512 + size);
    paxPath = undefined;
    if (type === "x") {
      const m = /(?:^|\n)\d+ path=([^\n]*)\n/.exec(body.toString("utf8"));
      if (m) paxPath = m[1];
    } else if (type === "0" || type === "\0") {
      files.set(name, Buffer.from(body));
    }
    off += 512 + Math.ceil(size / 512) * 512;
  }
  return files;
}

const sha = (alg, buf, enc) => createHash(alg).update(buf).digest(enc);

const record = JSON.parse(readFileSync(RECORD, "utf8"));
const { package: name, version, integrity } = record;
console.log(`verify-vendor: ${name}@${version}, pinned integrity ${integrity}`);

// 1. Registry metadata.
const meta = JSON.parse((await get(`${REGISTRY}/${encodeURIComponent(name)}/${encodeURIComponent(version)}`)).toString("utf8"));
check(meta.dist?.integrity === integrity, `the registry's integrity for ${name}@${version} is ${meta.dist?.integrity}, VENDORED.json pins ${integrity}`);
check(meta.dist?.tarball === record.tarball, `the registry's tarball URL is ${meta.dist?.tarball}, VENDORED.json records ${record.tarball}`);
check(meta.license === record.license, `the registry's licence is ${meta.license}, VENDORED.json records ${record.license}`);

// 2. The tarball.
const tgz = await get(record.tarball);
const got = `sha512-${sha("sha512", tgz, "base64")}`;
if (!check(got === integrity, `the downloaded tarball's integrity is ${got}, VENDORED.json pins ${integrity}`)) {
  for (const p of problems) console.error(`FAIL: ${p}`);
  process.exit(1);
}
const entries = untar(gunzipSync(tgz));
const expected = new Map();
for (const [path, bytes] of entries) {
  const m = /^package\/dist\/([^/]+\.(?:js|d\.ts))$/.exec(path);
  if (m && m[1] !== "index.cjs") expected.set(m[1], bytes);
}
const licence = entries.get("package/LICENSE");
if (check(licence !== undefined, "the tarball has no package/LICENSE")) expected.set("LICENSE", licence);

// 4. Provenance (checked before --write, so an upgrade records only an attested commit).
const attestations = JSON.parse((await get(`${REGISTRY}/-/npm/v1/attestations/${encodeURIComponent(name)}@${encodeURIComponent(version)}`)).toString("utf8"));
const slsa = (attestations.attestations ?? []).find((a) => a.predicateType === SLSA);
let commit;
if (check(slsa !== undefined, `the registry serves no ${SLSA} attestation for ${name}@${version}`)) {
  const statement = JSON.parse(Buffer.from(slsa.bundle.dsseEnvelope.payload, "base64").toString("utf8"));
  const subject = statement.subject?.find((s) => s.name === `pkg:npm/${name}@${version}`);
  check(subject?.digest?.sha512 === sha("sha512", tgz, "hex"), "the provenance subject's sha512 is not the tarball's");
  const workflow = statement.predicate?.buildDefinition?.externalParameters?.workflow ?? {};
  const dep = statement.predicate?.buildDefinition?.resolvedDependencies?.[0] ?? {};
  commit = dep.digest?.gitCommit;
  if (!write) {
    check(workflow.repository === record.upstream?.repository, `provenance repository ${workflow.repository}, VENDORED.json records ${record.upstream?.repository}`);
    check(workflow.ref === record.upstream?.ref, `provenance ref ${workflow.ref}, VENDORED.json records ${record.upstream?.ref}`);
    check(commit === record.upstream?.commit, `provenance commit ${commit}, VENDORED.json records ${record.upstream?.commit}`);
  } else {
    record.upstream = { ...record.upstream, repository: workflow.repository, ref: workflow.ref, commit };
  }
}

if (write) {
  if (problems.length > 0) {
    for (const p of problems) console.error(`FAIL: ${p}`);
    process.exit(1);
  }
  for (const f of readdirSync(DIR)) if (f !== "VENDORED.json") rmSync(join(DIR, f));
  record.files = {};
  for (const [file, bytes] of [...expected].sort(([a], [b]) => (a < b ? -1 : 1))) {
    writeFileSync(join(DIR, file), bytes);
    record.files[file] = sha("sha256", bytes, "hex");
  }
  writeFileSync(RECORD, `${JSON.stringify(record, null, 2)}\n`);
  console.log(`verify-vendor: wrote ${expected.size} files and VENDORED.json from ${record.tarball} (commit ${commit})`);
  process.exit(0);
}

// 3. The vendored copy.
const vendored = readdirSync(DIR).filter((f) => f !== "VENDORED.json").sort();
check(JSON.stringify(vendored) === JSON.stringify([...expected.keys()].sort()), `src/vendor/smol-toml holds [${vendored.join(", ")}], the tarball's set is [${[...expected.keys()].sort().join(", ")}]`);
check(JSON.stringify(Object.keys(record.files).sort()) === JSON.stringify([...expected.keys()].sort()), "VENDORED.json's file list is not the tarball's set");
for (const [file, bytes] of expected) {
  let mine;
  try {
    mine = readFileSync(join(DIR, file));
  } catch {
    continue; // reported by the set comparison above
  }
  check(mine.equals(bytes), `src/vendor/smol-toml/${file} differs from the tarball's copy`);
  check(record.files[file] === sha("sha256", bytes, "hex"), `VENDORED.json's sha256 for ${file} is not the tarball file's`);
}

if (problems.length > 0) {
  for (const p of problems) console.error(`FAIL: ${p}`);
  process.exit(1);
}
console.log(`verify-vendor: ok: ${expected.size} files are byte-identical to ${record.tarball} (integrity and provenance commit ${commit} match)`);
