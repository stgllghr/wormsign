// Check the API and examples from an external consumer. ci-pack-smoke.sh uses an offline tarball install;
// library-consumer.test.ts also runs this against the built checkout. Neither path contacts a registry.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [consumer, repo] = process.argv.slice(2);
assert.ok(consumer && repo, "usage: ci-library-smoke.mjs <consumer-directory> <repository>");
const pkg = join(consumer, "node_modules/wormsign");
const run = args => spawnSync(process.execPath, args, { cwd: consumer, encoding: "utf8", timeout: 60_000 });
const imported = run(["--input-type=module", "-e", 'import { scan, gateExitCode } from "wormsign"; if (typeof scan !== "function" || gateExitCode([]) !== 0) throw new Error("bad library entry"); console.log("import-ok");']);
assert.equal(imported.status, 0, imported.stderr);
assert.equal(imported.stdout, "import-ok\n", "import must not invoke the CLI");

const example = join(pkg, "examples/scan.mjs");
const clean = run([example, join(repo, "test/fixtures/clean")]);
assert.equal(clean.status, 0, clean.stderr);
assert.ok(Array.isArray(JSON.parse(clean.stdout).findings));
const positive = run([example, join(repo, "test/fixtures/malicious")]);
assert.equal(positive.status, 1, positive.stderr);
assert.ok(JSON.parse(positive.stdout).findings.some(f => f.ruleId === "WS-GH-002"));
const missing = run([example, join(consumer, "missing-project")]);
assert.equal(missing.status, 2, missing.stderr);
assert.equal(missing.stdout, "");
assert.ok(JSON.parse(missing.stderr).extra.error);

// The example uses the same output encoder as the CLI, including GitHub's legacy workflow-command syntax.
const hostile = join(consumer, "library-output-control");
mkdirSync(hostile);
const marker = "##[error]inert-library-output\u202e";
writeFileSync(join(hostile, "package.json"), JSON.stringify({ scripts: { postinstall: "echo " + marker } }));
const encoded = run([example, hostile]);
assert.equal(encoded.status, 0, encoded.stderr); // A plain lifecycle-presence finding is below high.
assert.doesNotMatch(encoded.stdout, /##\[|\u202e/u);
assert.ok(JSON.parse(encoded.stdout).findings.some(f => f.ruleId === "WS-LC-001" && f.message.includes(marker)));
const unsafePath = run([example, join(consumer, "missing-" + marker)]);
assert.equal(unsafePath.status, 2);
assert.doesNotMatch(unsafePath.stderr, /##\[|\u202e/u);
assert.ok(JSON.parse(unsafePath.stderr).extra.error.includes(marker));
assert.equal(JSON.parse(clean.stdout).version, JSON.parse(readFileSync(join(pkg, "package.json"), "utf8")).version);

copyFileSync(join(pkg, "examples/scan.mts"), join(consumer, "library-example.mts"));
const typed = run([join(repo, "node_modules/typescript/bin/tsc"), "--noEmit", "--strict", "--module", "NodeNext", "--target", "ES2023", "--types", "node", "--typeRoots", join(repo, "node_modules/@types"), "library-example.mts"]);
assert.equal(typed.status, 0, typed.stdout + typed.stderr);
console.log("ci-library-smoke: public import, example exits 0/1/2 and external TypeScript consumer passed");
