import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    "castle-wall-boot-daemon": "src/cli/castle-wall-boot-daemon.ts",
  },
  outDir: "dist/boot-runtime",
  format: ["esm"],
  dts: false,
  sourcemap: true,
  clean: false,
  target: "node22",
  splitting: false,
  treeshake: true,
  noExternal: [/.*/],
});
