import { defineConfig } from "tsup";
import { readFileSync } from "node:fs";
// Must match the validated build inputs and package contract in scripts/build-evidence-pack.mjs.
const revision = process.env.SANCTUARY_SOURCE_SHA;
if (!revision || !/^[0-9a-f]{40}$/.test(revision)) throw new Error("Full source revision required");
const artifactMode = process.env.SANCTUARY_ARTIFACT_MODE;
if (artifactMode !== "release" && artifactMode !== "fixture") throw new Error("Explicit artifact mode required");
const pkg = JSON.parse(readFileSync(new URL("../packages/evidence-pack-verifier/package.json", import.meta.url), "utf8"));
const common = { format: ["esm" as const], target: "node22", splitting: false, clean: false, dts: false, sourcemap: false, treeshake: true, define: { __SANCTUARY_SOURCE_SHA__: JSON.stringify(revision), __EVIDENCE_PACK_VERSION__: JSON.stringify(pkg.version) } };
const command = (name: string) => ({ js: `process.stdout.on("error", () => { process.exitCode = 1; });\nprocess.exitCode = await ${name}(process.argv.slice(2));` });
// Both installed bins retain stream failure even when the command later returns success.
const installedCommand = (call: string) => ({ js: `let outputFailed = false;
const failOutput = () => { outputFailed = true; process.exitCode = 1; };
process.stdout.on("error", failOutput);
process.stderr.on("error", failOutput);
const commandExit = await ${call};
process.exitCode = outputFailed ? 1 : commandExit;` });
export default defineConfig([
  { ...common, entry: { "verify-evidence-pack": "src/evidence-pack/snapshot-installed-cli.ts" }, outDir: "../packages/evidence-pack-verifier/dist", noExternal: [/.*/], banner: { js: "#!/usr/bin/env node" }, footer: installedCommand("runInstalledOfflineCommand(process.argv.slice(2), import.meta.url, offlineIO)") },
  // Must match BIN in artifact-policy.mjs and the package bin map. The installed entries require the loader URL; no caller-controlled location is accepted.
  { ...common, entry: { "check-evidence-pack-artifact": "src/evidence-pack/snapshot-artifact-cli.ts" }, outDir: "../packages/evidence-pack-verifier/dist", noExternal: [/.*/], banner: { js: "#!/usr/bin/env node" }, footer: installedCommand(`runInstalledArtifactCommand(process.argv.slice(2), ${JSON.stringify(artifactMode)}, import.meta.url)`) },
  // Each operator entry is self-contained so its keychain chokepoint has exactly one module instance.
  { ...common, entry: { "export-evidence-pack": "src/evidence-pack/snapshot-export-cli.ts" }, outDir: "evidence-pack-dist", footer: command("runSnapshotExportCommand") },
  { ...common, entry: { "export-evidence-trust": "src/evidence-pack/snapshot-trust-cli.ts" }, outDir: "evidence-pack-dist", footer: command("runSnapshotTrustCommand") },
  { ...common, entry: { "evidence-pack-drill-fixture": "scripts/evidence-pack-drill-fixture.ts" }, outDir: "evidence-pack-dist", footer: command("runDrillFixture") },
  { ...common, entry: { "evidence-pack-drill-isolation": "scripts/evidence-pack-drill-isolation.ts" }, outDir: "evidence-pack-dist" },
]);
