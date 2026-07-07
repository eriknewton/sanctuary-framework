/**
 * Tests for pre-arm and post-arm connectivity verification (fix B2): both
 * are fail-closed per-endpoint probes, never "assume reachable" on a
 * throwing probe.
 */

import { describe, it, expect } from "vitest";

import {
  verifyReachabilityBeforeArm,
  verifyReachabilityAfterArm,
  type EndpointProbeTarget,
} from "../../../src/castle-wall/provision/verify.js";

describe("castle-wall/provision/verify", () => {
  describe("verifyReachabilityBeforeArm", () => {
    it("reports allReachable true when every endpoint probe resolves true", async () => {
      const targets: EndpointProbeTarget[] = [
        { name: "LLM", probe: async () => true },
        { name: "Telegram", probe: async () => true },
      ];
      const result = await verifyReachabilityBeforeArm(targets);
      expect(result.allReachable).toBe(true);
      expect(result.results).toEqual([
        { name: "LLM", reachable: true },
        { name: "Telegram", reachable: true },
      ]);
    });

    it("reports allReachable false when any endpoint probe resolves false", async () => {
      const targets: EndpointProbeTarget[] = [
        { name: "LLM", probe: async () => true },
        { name: "Gmail", probe: async () => false },
      ];
      const result = await verifyReachabilityBeforeArm(targets);
      expect(result.allReachable).toBe(false);
      expect(result.results.find((r) => r.name === "Gmail")?.reachable).toBe(false);
    });

    it("fail-closed: a throwing probe counts as unreachable, not as unknown/assume-fine", async () => {
      const targets: EndpointProbeTarget[] = [
        { name: "LLM", probe: async () => true },
        {
          name: "Telegram",
          probe: async () => {
            throw new Error("DNS resolution failed");
          },
        },
      ];
      const result = await verifyReachabilityBeforeArm(targets);
      expect(result.allReachable).toBe(false);
      expect(result.results.find((r) => r.name === "Telegram")?.reachable).toBe(false);
    });

    it("fix F1 (BLOCKER): an empty target list fails CLOSED, not vacuously true -- an empty probe list must never let the flow arm unverified", async () => {
      const result = await verifyReachabilityBeforeArm([]);
      expect(result.allReachable).toBe(false);
      expect(result.results).toEqual([{ name: "(no endpoints configured)", reachable: false }]);
    });
  });

  describe("verifyReachabilityAfterArm", () => {
    it("uses the same fail-closed per-endpoint semantics as the pre-arm check", async () => {
      const targets: EndpointProbeTarget[] = [{ name: "Gmail", probe: async () => false }];
      const result = await verifyReachabilityAfterArm(targets);
      expect(result.allReachable).toBe(false);
    });
  });
});
