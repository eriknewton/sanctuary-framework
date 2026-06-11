import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    cli: "src/cli.ts",
    "verify-transparency": "src/transparency/offline-cli.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  target: "node22",
  splitting: false,
  treeshake: true,
  noExternal: ["@noble/curves", "@noble/hashes"],
});
