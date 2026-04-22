/**
 * §12.1 — Single-console consistency across three node modes.
 *
 * Spec: Review/Sanctuary/Federation_Protocol_V0.1_Spec_2026-04-21.md §12.1
 *
 *   "A single console — the pilot operator's dashboard — reaches all three
 *    nodes at once. After steady state, the three nodes agree on:
 *      - roster membership
 *      - policy set
 *      - locator table
 *      - canonical audit node designation"
 *
 * The "single console" here is the vitest test driver. It reads the same
 * four shapes off each of the three real libp2p-backed MeshNodes and asserts
 * equality.
 */

import { afterEach, describe, expect, it } from "vitest";

import { bootThreeModeDrill, type ThreeModeDrillHandle } from "./harness.js";

let active: ThreeModeDrillHandle | null = null;

afterEach(async () => {
  if (active) {
    await active.teardown();
    active = null;
  }
});

describe("three-mode-drill §12.1 — roster/policy/locator/canonical-audit consistency", () => {
  it(
    "three nodes agree on roster, policy version vector, locator table, and canonical-audit designation",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;

      // ── Roster — all three nodes see all three peers ──────────────────
      expect(drill.nodeA.getRoster().size()).toBe(3);
      expect(drill.nodeB.getRoster().size()).toBe(3);
      expect(drill.nodeC.getRoster().size()).toBe(3);

      const rosterIds = (node: typeof drill.nodeA) =>
        node
          .getRoster()
          .listAll()
          .map((e) => e.certificate.node_id)
          .sort();
      expect(rosterIds(drill.nodeA)).toEqual(rosterIds(drill.nodeB));
      expect(rosterIds(drill.nodeA)).toEqual(rosterIds(drill.nodeC));
      expect(rosterIds(drill.nodeA)).toEqual(
        [drill.nodeIdA, drill.nodeIdB, drill.nodeIdC].sort()
      );

      // ── Node-mode mapping — each cert declares the right mode ─────────
      const modeOf = (node: typeof drill.nodeA, id: string) =>
        node.getRoster().lookupNodeCert(id)?.node_mode;
      expect(modeOf(drill.nodeA, drill.nodeIdA)).toBe("local");
      expect(modeOf(drill.nodeA, drill.nodeIdB)).toBe("operator_cloud");
      expect(modeOf(drill.nodeA, drill.nodeIdC)).toBe("sovereign_tee");
      expect(modeOf(drill.nodeB, drill.nodeIdA)).toBe("local");
      expect(modeOf(drill.nodeC, drill.nodeIdA)).toBe("local");

      // ── Policy set — initially empty on all three nodes ───────────────
      expect(drill.nodeA.getPolicyBundle().versionVector()).toEqual({});
      expect(drill.nodeB.getPolicyBundle().versionVector()).toEqual({});
      expect(drill.nodeC.getPolicyBundle().versionVector()).toEqual({});

      // ── Locator table — initially empty on all three nodes ────────────
      expect(drill.nodeA.getLocatorTable().size()).toBe(0);
      expect(drill.nodeB.getLocatorTable().size()).toBe(0);
      expect(drill.nodeC.getLocatorTable().size()).toBe(0);
      expect(drill.nodeA.getLocatorTable().highest()).toBe(
        drill.nodeB.getLocatorTable().highest()
      );
      expect(drill.nodeA.getLocatorTable().highest()).toBe(
        drill.nodeC.getLocatorTable().highest()
      );

      // ── Canonical audit — exactly node A holds the log ────────────────
      expect(drill.nodeA.getCanonicalAuditLog()).toBeDefined();
      expect(drill.nodeB.getCanonicalAuditLog()).toBeUndefined();
      expect(drill.nodeC.getCanonicalAuditLog()).toBeUndefined();
    },
    90_000
  );
});
