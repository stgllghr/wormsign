import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  // src/vendor/smol-toml/ is a third-party package copied byte-identical from its npm tarball (VENDORED.json); it is
  // checked by hash, not linted, since any edit to it would fail the integrity checks. Only that directory is
  // ignored, and scripts/copy-vendor.mjs refuses anything else in src/vendor/, so no other file there escapes both.
  { ignores: ["dist/**", "test/fixtures/**", "node_modules/**", "src/vendor/smol-toml/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  { rules: { "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }] } },
  // Plain-JS Node scripts are not type-checked, so ESLint needs their globals. Listed by hand
  // rather than adding the `globals` package for three names.
  { files: ["**/*.mjs"], languageOptions: { globals: { process: "readonly", console: "readonly", URL: "readonly" } } },
);
