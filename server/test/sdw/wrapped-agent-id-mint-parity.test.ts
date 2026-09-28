/**
 * SDW owner pin shape rule vs the wrap-time minter: the two can never drift.
 *
 * Capability: every id `sanctuary wrap` writes into a harness's `sanctuary`
 * MCP entry as `SANCTUARY_AGENT_ID` is accepted by the SDW owner-pin shape
 * rule, for every wrap platform and for arbitrary storage paths. The accept
 * case in `memory-isolation-agent-id-shape.test.ts` builds its ids by hand;
 * this file builds them through the real minter (`wrappedAgentId` in
 * `src/wrap/cli.ts`), so a change to either side (a new platform, a new
 * harness kind, a different fortress-id hash length) turns this red instead
 * of silently refusing every freshly wrapped harness.
 * Register row `SDW-OWNER-PIN-AGENT-ID-SHAPE-01`.
 */
import { describe, expect, it } from "vitest";

import { MemoryStorage } from "../../src/storage/memory.js";
import { checkOrEstablishSdwOwnerPin, isWrappedAgentId } from "../../src/sdw/memory-isolation.js";
import { wrappedAgentId } from "../../src/wrap/cli.js";
import type { AgentPlatform } from "../../src/wrap/config-reader.js";

// A Record keyed by the union makes this list exhaustive at the type level:
// adding an AgentPlatform without adding it here fails `npm run typecheck`.
const EVERY_PLATFORM: Record<AgentPlatform, true> = {
  openclaw: true,
  "claude-code": true,
  cursor: true,
  hermes: true,
  mastra: true,
  cline: true,
  generic: true,
};

const STORAGE_PATHS: readonly string[] = [
  "/Users/operator/.sanctuary",
  "/srv/fortress-a",
  "",
  "/home/ünïcødé/.sanctuary state",
  "C:\\Users\\op\\.sanctuary",
];

describe("wrappedAgentId (wrap minter) and isWrappedAgentId (SDW owner-pin rule) agree", () => {
  it("every id the minter produces is accepted by the shared shape rule and can establish a pin", async () => {
    for (const platform of Object.keys(EVERY_PLATFORM) as AgentPlatform[]) {
      for (const storagePath of STORAGE_PATHS) {
        const minted = wrappedAgentId(platform, storagePath);
        expect(isWrappedAgentId(minted), `${platform} @ ${JSON.stringify(storagePath)} -> ${minted}`).toBe(true);
        expect(
          await checkOrEstablishSdwOwnerPin({
            storage: new MemoryStorage(),
            masterKey: new Uint8Array(32).fill(7),
            fortressId: "fortress:parity",
            ownerRef: "fleet-self",
            agentId: minted,
          }),
          minted,
        ).toEqual({ allowed: true });
      }
    }
  });
});
