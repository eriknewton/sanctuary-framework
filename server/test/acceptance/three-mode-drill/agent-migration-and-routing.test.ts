/**
 * §12.6 — Agent migration + chat-routing follows the new locator.
 *
 * Spec: Review/Sanctuary/Federation_Protocol_V0.1_Spec_2026-04-21.md §12.6,
 *       §6.2 (locator_update), §3.2 (agent-state-transfer per Q6).
 *
 *   "An agent canonically hosted on node B migrates to node C. The
 *    agent-locator update is a signed event that propagates to all three.
 *    A chat-routing query addressed to the agent routes to node C via the
 *    updated locator."
 *
 * The test exercises:
 *   1. Initial locator set (version 1): agent X on node B.
 *   2. Migration: B wraps the agent snapshot via `wrapAgentSnapshot` — real
 *      HKDF-derived AEAD with the (src=B, dst=C, agent, locator_version=2)
 *      AAD tuple — and unicasts to C.
 *   3. C unwraps with the same tuple; asserts plaintext byte-equals.
 *   4. Locator update (version 2): agent X on node C.
 *   5. All three nodes' locator tables agree on "agent X → C".
 *   6. "Chat-routing" = locator resolution. Each node's locator lookup
 *      returns C as the canonical host.
 */

import { afterEach, describe, expect, it } from "vitest";

import { stringToBytes } from "../../../src/core/encoding.js";
import type { LocatorUpdatePayload } from "../../../src/mesh/types.js";
import {
  unwrapAgentSnapshot,
  wrapAgentSnapshot,
} from "../../../src/mesh/lifecycle/index.js";

import { bootThreeModeDrill, type ThreeModeDrillHandle, waitFor } from "./harness.js";

let active: ThreeModeDrillHandle | null = null;

afterEach(async () => {
  if (active) {
    await active.teardown();
    active = null;
  }
});

describe("three-mode-drill §12.6 — agent migration + routing via updated locator", () => {
  it(
    "agent X migrates B → C via Q6 agent-state-transfer + locator update; all three nodes route to C",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;

      const agentId = "drill-agent-§12.6-migrant";

      // ── Step 1: initial locator — agent X hosted on B (version 1) ─────
      const v1Payload: LocatorUpdatePayload = {
        agent_id: agentId,
        canonical_node: drill.nodeIdB,
        locator_version: 1,
        last_migration_at: new Date().toISOString(),
        hosting_principal: drill.root_principal_cert.principal_id,
      };
      await drill.nodeB.publishLocatorUpdate({
        payload: v1Payload,
        principal_private_key: drill.root_principal_keypair.privateKey,
        emitter_principal: drill.root_principal_cert.principal_id,
      });
      await waitFor(
        () => {
          return (
            drill.nodeA.getLocatorTable().get(agentId)?.payload
              .canonical_node === drill.nodeIdB &&
            drill.nodeC.getLocatorTable().get(agentId)?.payload
              .canonical_node === drill.nodeIdB
          );
        },
        5_000,
        25,
        "initial locator (B) converges across A and C"
      );

      // ── Step 2: Q6 agent-state-transfer — B wraps snapshot for C ──────
      const agentSnapshot = stringToBytes(
        JSON.stringify({
          agent_id: agentId,
          scratch: "vault-contents-for-drill",
          memory: ["msg-1", "msg-2"],
          launched_at: Date.now(),
        })
      );
      const nextLocatorVersion = 2;
      const wrapped = wrapAgentSnapshot({
        snapshot_bytes: agentSnapshot,
        fortress_master_secret: drill.master_private_key,
        source_node_id: drill.nodeIdB,
        destination_node_id: drill.nodeIdC,
        agent_id: agentId,
        authorizing_locator_version: nextLocatorVersion,
      });

      // B unicasts the wrapped snapshot to C over the real libp2p stream.
      const received: string[] = [];
      drill.transportC.subscribeUnicast((to, message) => {
        if (to === drill.nodeIdC) received.push(message);
      });
      const wireMsg = JSON.stringify({
        kind: "agent_state_transfer",
        wrapped,
      });
      await drill.transportB.unicast(drill.nodeIdC, wireMsg);
      await waitFor(
        () => received.length >= 1,
        5_000,
        25,
        "C receives wrapped snapshot over unicast"
      );

      // C unwraps with the identical tuple — byte-for-byte match.
      const parsed = JSON.parse(received[0]) as {
        kind: string;
        wrapped: ReturnType<typeof wrapAgentSnapshot>;
      };
      expect(parsed.kind).toBe("agent_state_transfer");
      const recovered = unwrapAgentSnapshot({
        wrapped: parsed.wrapped,
        fortress_master_secret: drill.master_private_key,
        source_node_id: drill.nodeIdB,
        destination_node_id: drill.nodeIdC,
        agent_id: agentId,
        authorizing_locator_version: nextLocatorVersion,
      });
      expect(recovered).toEqual(agentSnapshot);

      // ── Step 3: publish locator v2 — agent X now hosted on C ──────────
      const v2Payload: LocatorUpdatePayload = {
        agent_id: agentId,
        canonical_node: drill.nodeIdC,
        locator_version: nextLocatorVersion,
        last_migration_at: new Date().toISOString(),
        hosting_principal: drill.root_principal_cert.principal_id,
      };
      await drill.nodeC.publishLocatorUpdate({
        payload: v2Payload,
        principal_private_key: drill.root_principal_keypair.privateKey,
        emitter_principal: drill.root_principal_cert.principal_id,
      });

      await waitFor(
        () => {
          const a = drill.nodeA.getLocatorTable().get(agentId)?.payload;
          const b = drill.nodeB.getLocatorTable().get(agentId)?.payload;
          const c = drill.nodeC.getLocatorTable().get(agentId)?.payload;
          return (
            a?.canonical_node === drill.nodeIdC &&
            a?.locator_version === 2 &&
            b?.canonical_node === drill.nodeIdC &&
            b?.locator_version === 2 &&
            c?.canonical_node === drill.nodeIdC &&
            c?.locator_version === 2
          );
        },
        5_000,
        25,
        "locator v2 (C) converges across all three nodes"
      );

      // ── Step 4: "chat routing" — every node resolves agent X → C ──────
      // v0.1 ships locator resolution as the route lookup; a chat-router
      // (Q2 surface, v1.0 scope in WP-MVP-7) consumes this lookup to
      // address messages to the canonical host.
      const routeFrom = (node: typeof drill.nodeA) =>
        node.getLocatorTable().get(agentId)?.payload.canonical_node;
      expect(routeFrom(drill.nodeA)).toBe(drill.nodeIdC);
      expect(routeFrom(drill.nodeB)).toBe(drill.nodeIdC);
      expect(routeFrom(drill.nodeC)).toBe(drill.nodeIdC);
    },
    90_000
  );
});
