import { defineConfig } from "tsup";
import { execFileSync } from "node:child_process";

const UNKNOWN_SOURCE_SHA = "unknown";

function resolveSourceSha(): string {
  const override = process.env.SANCTUARY_SOURCE_SHA?.trim();
  if (override) {
    return override;
  }
  try {
    return execFileSync(
      "/usr/bin/git",
      ["rev-parse", "HEAD"],
      { encoding: "utf8" },
    ).trim();
  } catch {
    console.warn(
      `Warning: SANCTUARY_SOURCE_SHA is not set and git metadata is unavailable; using ${UNKNOWN_SOURCE_SHA}.`,
    );
    return UNKNOWN_SOURCE_SHA;
  }
}

const sourceSha = resolveSourceSha();
if (sourceSha !== UNKNOWN_SOURCE_SHA && !/^[a-f0-9]{40}$/.test(sourceSha)) {
  throw new Error("SANCTUARY_SOURCE_SHA must be the exact 40-hex source commit");
}

export default defineConfig({
  entry: {
    // Must match the file entries in scripts/sealed-cli-runtime-entries.mjs.
    index: "src/index.ts",
    "intelligence/index": "src/intelligence/index.ts",
    cli: "src/cli.ts",
    "linux-policy-sign": "src/cli/linux-policy-sign.ts",
    "verify-transparency": "src/transparency/offline-cli.ts",
    "response-worker": "src/proxy/response-worker.ts",
    "directory-capability-worker": "src/storage/directory-capability-worker.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  target: "node22",
  splitting: false,
  treeshake: true,
  define: {
    __SANCTUARY_SOURCE_SHA__: JSON.stringify(sourceSha),
  },
  noExternal: ["@noble/curves", "@noble/hashes"],
});
