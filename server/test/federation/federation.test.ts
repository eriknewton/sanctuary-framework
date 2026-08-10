/**
 * Federation Registry & Trust Evaluation — Tests
 *
 * Tests for peer registration, trust evaluation, handshake expiry handling,
 * and federation status reporting.
 *
 * `registerFromHandshake` is async (fix-round-2, MUST-FIX 6 — BoundedMap's
 * global-capacity eviction awaits a durable audit write before deleting)
 * and its 4th `origin` parameter is REQUIRED (fix-round-2, MUST-FIX 1/2 —
 * a per-origin quota that can silently skip accounting when omitted is
 * itself the defect this fix-round closes). This file is not exercising
 * per-origin fairness (see test/security/attacker-writable-collections-bounds.test.ts
 * for that), so every call here uses one constant `TEST_ORIGIN`.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { FederationRegistry } from "../../src/federation/registry.js";
import type { HandshakeResult } from "../../src/handshake/types.js";
import type { SignedSHR } from "../../src/shr/types.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";

const TEST_ORIGIN = "agent:test-origin";

// ── Helpers ─────────────────────────────────────────────────────────────

const mockSHR: SignedSHR = {
  body: {
    shr_version: "1.0",
    implementation: {
      sanctuary_version: "0.4.0",
      node_version: "20.0.0",
      generated_by: "sanctuary-mcp-server",
    },
    instance_id: "peer-1",
    generated_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 3600000).toISOString(),
    layers: {
      l1: { status: "active", encryption: "aes-256-gcm", key_custody: "self", integrity: "merkle-sha256", identity_type: "ed25519", state_portable: true },
      l2: { status: "degraded", isolation_type: "local-process", attestation_available: true },
      l3: { status: "active", proof_system: "schnorr-pedersen", selective_disclosure: true },
      l4: { status: "active", reputation_mode: "self-custodied", attestation_format: "eas-compatible", reputation_portable: true },
    },
    capabilities: { handshake: true, shr_exchange: true, reputation_verify: true, encrypted_channel: false },
    degradations: [],
  },
  signed_by: "mock-key",
  signature_scheme: "ed25519-v1",
  signature: "mock-sig",
};

function makeHandshakeResult(overrides: Partial<HandshakeResult> = {}): HandshakeResult {
  return {
    counterparty_id: "peer-1",
    counterparty_shr: mockSHR,
    verified: true,
    sovereignty_level: "degraded",
    trust_tier: "verified-degraded",
    completed_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 3600000).toISOString(),
    errors: [],
    liveness_proven: true,
    ...overrides,
  };
}

// ── Tests ───────────────────────────────────────────────────────────────

describe("Federation Registry", () => {
  let registry: FederationRegistry;

  beforeEach(() => {
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    registry = new FederationRegistry(auditLog);
  });

  describe("Peer Registration", () => {
    it("registers a peer from a completed handshake", async () => {
      const hsResult = makeHandshakeResult();
      // Non-null: the registry is fresh (well under MAX_FEDERATION_PEERS),
      // so registration cannot be refused for capacity here.
      const peer = (await registry.registerFromHandshake(hsResult, "did:sanctuary:peer-1", undefined, TEST_ORIGIN))!;

      expect(peer.peer_id).toBe("peer-1");
      expect(peer.peer_did).toBe("did:sanctuary:peer-1");
      expect(peer.trust_tier).toBe("verified-degraded");
      expect(peer.active).toBe(true);
    });

    it("assigns verified-sovereign tier for fully sovereign peers", async () => {
      const hsResult = makeHandshakeResult({
        counterparty_id: "sovereign-peer",
        trust_tier: "verified-sovereign",
      });
      const peer = (await registry.registerFromHandshake(hsResult, "did:sanctuary:sovereign", undefined, TEST_ORIGIN))!;

      expect(peer.trust_tier).toBe("verified-sovereign");
    });

    it("updates existing peer on re-registration", async () => {
      const hsResult1 = makeHandshakeResult({ trust_tier: "verified-degraded" });
      await registry.registerFromHandshake(hsResult1, "did:sanctuary:peer-1", undefined, TEST_ORIGIN);

      const hsResult2 = makeHandshakeResult({ trust_tier: "verified-sovereign" });
      const peer = (await registry.registerFromHandshake(hsResult2, "did:sanctuary:peer-1", undefined, TEST_ORIGIN))!;

      expect(peer.trust_tier).toBe("verified-sovereign");
      // First seen should be preserved
      expect(registry.listPeers()).toHaveLength(1);
    });

    it("preserves first_seen on re-registration", async () => {
      const hsResult1 = makeHandshakeResult();
      const peer1 = (await registry.registerFromHandshake(hsResult1, "did:sanctuary:peer-1", undefined, TEST_ORIGIN))!;
      const firstSeen = peer1.first_seen;

      // Wait a tiny bit and re-register
      const hsResult2 = makeHandshakeResult();
      const peer2 = (await registry.registerFromHandshake(hsResult2, "did:sanctuary:peer-1", undefined, TEST_ORIGIN))!;

      expect(peer2.first_seen).toBe(firstSeen);
    });
  });

  describe("Peer Lookup", () => {
    it("returns null for unknown peers", () => {
      expect(registry.getPeer("nonexistent")).toBeNull();
    });

    it("returns the peer for known IDs", async () => {
      await registry.registerFromHandshake(makeHandshakeResult(), "did:sanctuary:peer-1", undefined, TEST_ORIGIN);
      const peer = registry.getPeer("peer-1");

      expect(peer).not.toBeNull();
      expect(peer!.peer_did).toBe("did:sanctuary:peer-1");
    });

    it("auto-deactivates peers with expired handshakes", async () => {
      const expired = makeHandshakeResult({
        counterparty_id: "expired-peer",
        expires_at: new Date(Date.now() - 1000).toISOString(),
      });
      await registry.registerFromHandshake(expired, "did:sanctuary:expired-peer", undefined, TEST_ORIGIN);

      const peer = registry.getPeer("expired-peer");
      expect(peer).not.toBeNull();
      expect(peer!.active).toBe(false);
      expect(peer!.trust_tier).toBe("self-attested");
    });
  });

  describe("Listing", () => {
    it("lists all peers", async () => {
      await registry.registerFromHandshake(
        makeHandshakeResult({ counterparty_id: "p1" }),
        "did:p1",
        undefined,
        TEST_ORIGIN
      );
      await registry.registerFromHandshake(
        makeHandshakeResult({ counterparty_id: "p2" }),
        "did:p2",
        undefined,
        TEST_ORIGIN
      );

      expect(registry.listPeers()).toHaveLength(2);
    });

    it("filters to active-only peers", async () => {
      await registry.registerFromHandshake(
        makeHandshakeResult({ counterparty_id: "active-peer" }),
        "did:active",
        undefined,
        TEST_ORIGIN
      );
      await registry.registerFromHandshake(
        makeHandshakeResult({
          counterparty_id: "expired-peer",
          expires_at: new Date(Date.now() - 1000).toISOString(),
        }),
        "did:expired",
        undefined,
        TEST_ORIGIN
      );

      const active = registry.listPeers({ active_only: true });
      expect(active).toHaveLength(1);
      expect(active[0]!.peer_id).toBe("active-peer");
    });
  });

  describe("Peer Removal", () => {
    it("removes a peer", async () => {
      await registry.registerFromHandshake(makeHandshakeResult(), "did:peer-1", undefined, TEST_ORIGIN);
      expect(registry.removePeer("peer-1")).toBe(true);
      expect(registry.getPeer("peer-1")).toBeNull();
    });

    it("returns false for non-existent peer removal", () => {
      expect(registry.removePeer("ghost")).toBe(false);
    });
  });

  describe("Trust Evaluation", () => {
    it("returns none trust for unknown peers", () => {
      const eval_ = registry.evaluateTrust("unknown-peer");
      expect(eval_.trust_level).toBe("none");
      expect(eval_.sovereignty_tier).toBe("unverified");
    });

    it("returns medium trust for verified-degraded peer with active handshake", async () => {
      await registry.registerFromHandshake(
        makeHandshakeResult({ trust_tier: "verified-degraded" }),
        "did:peer",
        undefined,
        TEST_ORIGIN
      );

      const eval_ = registry.evaluateTrust("peer-1");
      expect(eval_.trust_level).toBe("medium");
      expect(eval_.handshake_current).toBe(true);
      expect(eval_.sovereignty_tier).toBe("verified-degraded");
    });

    it("returns high trust for verified-sovereign with attestation history", async () => {
      await registry.registerFromHandshake(
        makeHandshakeResult({ trust_tier: "verified-sovereign" }),
        "did:peer",
        undefined,
        TEST_ORIGIN
      );

      const eval_ = registry.evaluateTrust("peer-1", 15, 90);
      expect(eval_.trust_level).toBe("high");
    });

    it("degrades trust when handshake expires", async () => {
      await registry.registerFromHandshake(
        makeHandshakeResult({
          trust_tier: "verified-sovereign",
          expires_at: new Date(Date.now() - 1000).toISOString(),
        }),
        "did:peer",
        undefined,
        TEST_ORIGIN
      );

      const eval_ = registry.evaluateTrust("peer-1");
      expect(eval_.handshake_current).toBe(false);
      expect(eval_.sovereignty_tier).toBe("self-attested"); // Degraded from sovereign
    });

    it("factors in reputation score", async () => {
      await registry.registerFromHandshake(
        makeHandshakeResult({ trust_tier: "verified-degraded" }),
        "did:peer",
        undefined,
        TEST_ORIGIN
      );

      const lowRep = registry.evaluateTrust("peer-1", 0, 20);
      const highRep = registry.evaluateTrust("peer-1", 0, 90);

      // High reputation should contribute to higher trust
      expect(highRep.factors.some((f) => f.includes("High reputation"))).toBe(true);
      expect(lowRep.factors.some((f) => f.includes("Low reputation"))).toBe(true);
    });

    it("includes all evaluation factors in output", async () => {
      await registry.registerFromHandshake(
        makeHandshakeResult(),
        "did:peer",
        undefined,
        TEST_ORIGIN
      );

      const eval_ = registry.evaluateTrust("peer-1", 5, 75);
      expect(eval_.factors.length).toBeGreaterThanOrEqual(3);
      expect(eval_.evaluated_at).toBeTruthy();
      expect(eval_.mutual_attestation_count).toBe(5);
      expect(eval_.reputation_score).toBe(75);
    });
  });

  describe("Handshake Results Integration", () => {
    it("exposes active handshake results for tier resolution", async () => {
      await registry.registerFromHandshake(
        makeHandshakeResult({ counterparty_id: "active" }),
        "did:active",
        undefined,
        TEST_ORIGIN
      );
      await registry.registerFromHandshake(
        makeHandshakeResult({
          counterparty_id: "expired",
          expires_at: new Date(Date.now() - 1000).toISOString(),
        }),
        "did:expired",
        undefined,
        TEST_ORIGIN
      );

      const results = registry.getHandshakeResults();
      expect(results.size).toBe(1);
      expect(results.has("active")).toBe(true);
      expect(results.has("expired")).toBe(false);
    });
  });
});
