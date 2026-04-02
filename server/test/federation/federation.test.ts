/**
 * Federation Registry & Trust Evaluation — Tests
 *
 * Tests for peer registration, trust evaluation, handshake expiry handling,
 * and federation status reporting.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { FederationRegistry } from "../../src/federation/registry.js";
import type { HandshakeResult } from "../../src/handshake/types.js";
import type { SignedSHR } from "../../src/shr/types.js";

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
    ...overrides,
  };
}

// ── Tests ───────────────────────────────────────────────────────────────

describe("Federation Registry", () => {
  let registry: FederationRegistry;

  beforeEach(() => {
    registry = new FederationRegistry();
  });

  describe("Peer Registration", () => {
    it("registers a peer from a completed handshake", () => {
      const hsResult = makeHandshakeResult();
      const peer = registry.registerFromHandshake(hsResult, "did:sanctuary:peer-1");

      expect(peer.peer_id).toBe("peer-1");
      expect(peer.peer_did).toBe("did:sanctuary:peer-1");
      expect(peer.trust_tier).toBe("verified-degraded");
      expect(peer.active).toBe(true);
    });

    it("assigns verified-sovereign tier for fully sovereign peers", () => {
      const hsResult = makeHandshakeResult({
        counterparty_id: "sovereign-peer",
        trust_tier: "verified-sovereign",
      });
      const peer = registry.registerFromHandshake(hsResult, "did:sanctuary:sovereign");

      expect(peer.trust_tier).toBe("verified-sovereign");
    });

    it("updates existing peer on re-registration", () => {
      const hsResult1 = makeHandshakeResult({ trust_tier: "verified-degraded" });
      registry.registerFromHandshake(hsResult1, "did:sanctuary:peer-1");

      const hsResult2 = makeHandshakeResult({ trust_tier: "verified-sovereign" });
      const peer = registry.registerFromHandshake(hsResult2, "did:sanctuary:peer-1");

      expect(peer.trust_tier).toBe("verified-sovereign");
      // First seen should be preserved
      expect(registry.listPeers()).toHaveLength(1);
    });

    it("preserves first_seen on re-registration", () => {
      const hsResult1 = makeHandshakeResult();
      const peer1 = registry.registerFromHandshake(hsResult1, "did:sanctuary:peer-1");
      const firstSeen = peer1.first_seen;

      // Wait a tiny bit and re-register
      const hsResult2 = makeHandshakeResult();
      const peer2 = registry.registerFromHandshake(hsResult2, "did:sanctuary:peer-1");

      expect(peer2.first_seen).toBe(firstSeen);
    });
  });

  describe("Peer Lookup", () => {
    it("returns null for unknown peers", () => {
      expect(registry.getPeer("nonexistent")).toBeNull();
    });

    it("returns the peer for known IDs", () => {
      registry.registerFromHandshake(makeHandshakeResult(), "did:sanctuary:peer-1");
      const peer = registry.getPeer("peer-1");

      expect(peer).not.toBeNull();
      expect(peer!.peer_did).toBe("did:sanctuary:peer-1");
    });

    it("auto-deactivates peers with expired handshakes", () => {
      const expired = makeHandshakeResult({
        counterparty_id: "expired-peer",
        expires_at: new Date(Date.now() - 1000).toISOString(),
      });
      registry.registerFromHandshake(expired, "did:sanctuary:expired-peer");

      const peer = registry.getPeer("expired-peer");
      expect(peer).not.toBeNull();
      expect(peer!.active).toBe(false);
      expect(peer!.trust_tier).toBe("self-attested");
    });
  });

  describe("Listing", () => {
    it("lists all peers", () => {
      registry.registerFromHandshake(
        makeHandshakeResult({ counterparty_id: "p1" }),
        "did:p1"
      );
      registry.registerFromHandshake(
        makeHandshakeResult({ counterparty_id: "p2" }),
        "did:p2"
      );

      expect(registry.listPeers()).toHaveLength(2);
    });

    it("filters to active-only peers", () => {
      registry.registerFromHandshake(
        makeHandshakeResult({ counterparty_id: "active-peer" }),
        "did:active"
      );
      registry.registerFromHandshake(
        makeHandshakeResult({
          counterparty_id: "expired-peer",
          expires_at: new Date(Date.now() - 1000).toISOString(),
        }),
        "did:expired"
      );

      const active = registry.listPeers({ active_only: true });
      expect(active).toHaveLength(1);
      expect(active[0]!.peer_id).toBe("active-peer");
    });
  });

  describe("Peer Removal", () => {
    it("removes a peer", () => {
      registry.registerFromHandshake(makeHandshakeResult(), "did:peer-1");
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

    it("returns medium trust for verified-degraded peer with active handshake", () => {
      registry.registerFromHandshake(
        makeHandshakeResult({ trust_tier: "verified-degraded" }),
        "did:peer"
      );

      const eval_ = registry.evaluateTrust("peer-1");
      expect(eval_.trust_level).toBe("medium");
      expect(eval_.handshake_current).toBe(true);
      expect(eval_.sovereignty_tier).toBe("verified-degraded");
    });

    it("returns high trust for verified-sovereign with attestation history", () => {
      registry.registerFromHandshake(
        makeHandshakeResult({ trust_tier: "verified-sovereign" }),
        "did:peer"
      );

      const eval_ = registry.evaluateTrust("peer-1", 15, 90);
      expect(eval_.trust_level).toBe("high");
    });

    it("degrades trust when handshake expires", () => {
      registry.registerFromHandshake(
        makeHandshakeResult({
          trust_tier: "verified-sovereign",
          expires_at: new Date(Date.now() - 1000).toISOString(),
        }),
        "did:peer"
      );

      const eval_ = registry.evaluateTrust("peer-1");
      expect(eval_.handshake_current).toBe(false);
      expect(eval_.sovereignty_tier).toBe("self-attested"); // Degraded from sovereign
    });

    it("factors in reputation score", () => {
      registry.registerFromHandshake(
        makeHandshakeResult({ trust_tier: "verified-degraded" }),
        "did:peer"
      );

      const lowRep = registry.evaluateTrust("peer-1", 0, 20);
      const highRep = registry.evaluateTrust("peer-1", 0, 90);

      // High reputation should contribute to higher trust
      expect(highRep.factors.some((f) => f.includes("High reputation"))).toBe(true);
      expect(lowRep.factors.some((f) => f.includes("Low reputation"))).toBe(true);
    });

    it("includes all evaluation factors in output", () => {
      registry.registerFromHandshake(
        makeHandshakeResult(),
        "did:peer"
      );

      const eval_ = registry.evaluateTrust("peer-1", 5, 75);
      expect(eval_.factors.length).toBeGreaterThanOrEqual(3);
      expect(eval_.evaluated_at).toBeTruthy();
      expect(eval_.mutual_attestation_count).toBe(5);
      expect(eval_.reputation_score).toBe(75);
    });
  });

  describe("Handshake Results Integration", () => {
    it("exposes active handshake results for tier resolution", () => {
      registry.registerFromHandshake(
        makeHandshakeResult({ counterparty_id: "active" }),
        "did:active"
      );
      registry.registerFromHandshake(
        makeHandshakeResult({
          counterparty_id: "expired",
          expires_at: new Date(Date.now() - 1000).toISOString(),
        }),
        "did:expired"
      );

      const results = registry.getHandshakeResults();
      expect(results.size).toBe(1);
      expect(results.has("active")).toBe(true);
      expect(results.has("expired")).toBe(false);
    });
  });
});
