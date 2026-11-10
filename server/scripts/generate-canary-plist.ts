/**
 * Regenerate the canary golden fixture and its SHA-256 from the generator.
 * Must match server/test/castle-wall/liveness/fixtures/canary.golden.plist and
 * canary.golden.sha256; the launchd-plists test regenerates both in memory and
 * byte-compares them. Usage: npx tsx scripts/generate-canary-plist.ts [--check]
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { canaryPlistSha256, generateCanaryPlist } from "../src/castle-wall/liveness/launchd-plists.js";

/** Fixture account name only; a real host's name comes from `id -un <agent_uid>` at install time. */
export const CANARY_FIXTURE_ACCOUNT = "sanctuary-agent-fixture";
const FIXTURES = join(import.meta.dirname ?? __dirname, "..", "test", "castle-wall", "liveness", "fixtures");
export const CANARY_GOLDEN_PLIST = join(FIXTURES, "canary.golden.plist");
export const CANARY_GOLDEN_SHA256 = join(FIXTURES, "canary.golden.sha256");

export function renderCanaryGolden(): { plist: string; sha256: string } {
  return { plist: generateCanaryPlist(CANARY_FIXTURE_ACCOUNT), sha256: `${canaryPlistSha256(CANARY_FIXTURE_ACCOUNT)}\n` };
}

function main(): void {
  const { plist, sha256 } = renderCanaryGolden();
  if (process.argv.includes("--check")) {
    const same = readFileSync(CANARY_GOLDEN_PLIST, "utf8") === plist && readFileSync(CANARY_GOLDEN_SHA256, "utf8") === sha256;
    process.exitCode = same ? 0 : 1;
    return;
  }
  writeFileSync(CANARY_GOLDEN_PLIST, plist);
  writeFileSync(CANARY_GOLDEN_SHA256, sha256);
}

if (process.argv[1] !== undefined && /generate-canary-plist\.ts$/.test(process.argv[1])) main();
