/**
 * Structural guard for resolver-publication maintenance seams that are not
 * observable through the daemon's runtime contract.
 *
 * The concurrent-reload behavior is characterized in the daemon integration
 * suite. These checks keep the adjacent authoring hazards from returning: a
 * closure-captured default that can silently supply stale composition inputs,
 * and a non-null assertion at the manifest publication boundary.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const DAEMON_SOURCE = join(
  HERE,
  "..",
  "..",
  "src",
  "castle-wall",
  "runtime",
  "macos-daemon.ts",
);

describe("Castle Wall resolver publication source invariants", () => {
  it("requires explicit composition inputs and a guarded publication listener", () => {
    const source = readFileSync(DAEMON_SOURCE, "utf8");

    expect(source).toContain(
      "let manifestState = await composeManifestForResolvers(startupResolvers, {",
    );
    expect(source).not.toMatch(
      /exclusiveEgressGate:\s*ExclusiveEgressGatePolicy \| undefined;\s*}\s*=\s*{\s*agentOrigin,\s*operatorBaseline,\s*exclusiveEgressGate\s*}/s,
    );
    expect(source).toContain(
      "const requireListener = (): MacOSCastleWallListenerHandle => {",
    );
    expect(source).toContain("requireListener().broadcastManifestUpdate()");
    expect(source).not.toContain("listener!.broadcastManifestUpdate()");
  });
});
