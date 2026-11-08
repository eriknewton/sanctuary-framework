import { defineConfig } from "tsup";
import { build as buildNativeWorker } from "esbuild";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";

// Must match SANCTUARY_SOURCE_SHA_ENV in server/test/scripts/tsup-config-source-sha.test.ts.
const SANCTUARY_SOURCE_SHA_ENV = "SANCTUARY_SOURCE_SHA";
const SOURCE_SHA_BYTES = 20; // SHA-1 commit ids are 20 raw bytes.
const HEX_CHARS_PER_BYTE = 2;
const SOURCE_SHA_HEX_CHARS = SOURCE_SHA_BYTES * HEX_CHARS_PER_BYTE;
// Must match SOURCE_SHA_HEX_PATTERN in server/src/cli/install.ts, server/src/cli/castle-wall.ts,
// and server/scripts/build-castle-wall-runtime-manifest.mjs.
const SOURCE_SHA_HEX_PATTERN = new RegExp(`^[0-9a-f]{${SOURCE_SHA_HEX_CHARS}}$`);
const GIT_REV_PARSE_TIMEOUT_MS = 5_000; // 5_000 ms = 5 seconds for one local metadata read.

function requireSourceSha(value: string, source: string): string {
  // INVARIANT: sealed-app verification compares against this value, so a placeholder would make every field check refuse.
  if (!SOURCE_SHA_HEX_PATTERN.test(value)) {
    throw new Error(
      `${SANCTUARY_SOURCE_SHA_ENV} must be the exact ${SOURCE_SHA_HEX_CHARS}-hex source commit; ` +
        `${source} was missing or malformed.`,
    );
  }
  return value;
}

function resolveSourceSha(): string {
  const override = process.env[SANCTUARY_SOURCE_SHA_ENV];
  if (override !== undefined) {
    return requireSourceSha(override.trim(), SANCTUARY_SOURCE_SHA_ENV);
  }
  let gitSha: string;
  try {
    gitSha = execFileSync(
      "/usr/bin/git",
      ["rev-parse", "HEAD"],
      { encoding: "utf8", timeout: GIT_REV_PARSE_TIMEOUT_MS },
    ).trim();
  } catch {
    throw new Error(
      `${SANCTUARY_SOURCE_SHA_ENV} must be set to the exact ${SOURCE_SHA_HEX_CHARS}-hex source commit ` +
        "when git metadata is unavailable.",
    );
  }
  return requireSourceSha(gitSha, "git rev-parse HEAD");
}

const sourceSha = resolveSourceSha();

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
    // Must match the injected global declared in server/src/cli/install.ts.
    __SANCTUARY_SOURCE_SHA__: JSON.stringify(sourceSha),
  },
  noExternal: ["@noble/curves", "@noble/hashes"],
  async onSuccess() {
    // The native worker has its own closed bundle because it is not an entrypoint of the frozen CLI runtime.
    // Must match custody.rs WORKER_BINARY and k1-release-closure.test.ts; the installed basename is signing-worker.cjs.
    await buildNativeWorker({
      entryPoints: ["src/signing/worker.ts"], outfile: "dist/k1/signing-worker.cjs",
      bundle: true, platform: "node", format: "cjs", target: "node22", packages: "bundle",
      plugins: [{
        name: "release-custody-observer-removal",
        setup(build) {
          // Release artifacts remove callback calls before bundling so no secret observer survives tree shaking.
          build.onLoad({filter: /[/\\]core[/\\]master-custody\.ts$/}, async args => {
            const source = await readFile(args.path, "utf8");
            const contents = source.replace(/^\s*opts\.__testObserveSecretBuffer\?\.\([^;]+;$/gm, "");
            return {contents, loader: "ts"};
          });
        },
      }],
    });
  },
});
