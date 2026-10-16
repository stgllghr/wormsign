// gitTree reads every .npmrc, .yarnrc and pnpm-workspace.yaml of a commit to learn which directories installs link
// into (owned()), on every diff. A pull request controls those files, so reading them must be linear and bounded.
import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { gitTree } from "../src/tree.js";
import { gitRepo } from "./validation-helpers.js";

/** A commit with a package.json and an .npmrc of `lines` lines that each set modules-dir plainly. */
const repoWith = (lines: number): string =>
  gitRepo([
    (dir) => {
      writeFileSync(join(dir, "package.json"), "{}");
      writeFileSync(join(dir, ".npmrc"), "modules-dir=a\n".repeat(lines));
    },
  ]);

test("gitTree: an .npmrc of 140,000 modules-dir lines is read in linear time", () => {
  // 1.96 MB, under the 2 MiB cap. Copying the rest of the file for each line took about 9 s for 160,000 lines.
  const tree = gitTree(repoWith(140_000), "HEAD");
  const t0 = performance.now();
  assert.equal(tree.unfollowed?.("package.json"), undefined, "every line is a plain setting, so the manifest is followed");
  const ms = performance.now() - t0;
  assert.ok(ms < 3000, `took ${Math.round(ms)} ms`); // about 0.5 s with git; the quadratic loop alone took 7 s
});

test("gitTree: install-directory config over the 2 MiB cap is not parsed, so every path is unfollowed (fail closed)", () => {
  const tree = gitTree(repoWith(170_000), "HEAD"); // 2.38 MB of valid lines
  assert.notEqual(tree.unfollowed?.("package.json"), undefined);
  assert.equal(gitTree(repoWith(10), "HEAD").unfollowed?.("package.json"), undefined, "a small one is read");
});
