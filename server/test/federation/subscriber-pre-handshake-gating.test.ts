/**
 * Subscriber pre-handshake registration gating -- Tests
 *
 * Verifies that cross-identity subscriber registrations are refused when
 * the requesting peer has not completed the sovereignty handshake.
 *
 * Covers:
 *   1. Subscriber with not_started handshake: refused + critical audit entry.
 *   2. Subscriber with in_progress handshake: refused (maps to not_started
 *      in handshakeResults since only completed results are stored).
 *   3. Subscriber with failed handshake: refused.
 *   4. Subscriber with verified_sovereign handshake: permitted; tagged.
 *   5. Subscriber with verified_degraded handshake: permitted; tagged.
 *   6. Self-subscription: always permitted.
 *   7. Denial messages: generic; do not leak which state caused refusal.
 *
 * Closes housekeeping queue item #27.
 */

import { describe, it, expect } from "vitest";
import {
  checkSubscriberHandshakeState,
  buildDeniedAuditDetails,
  SUBSCRIBER_DENIED_MESSAGE,
  type HandshakeStateLookup,
} from "../../src/handshake/subscriber-gate.js";
import type { HandshakeResult } from "../../src/handshake/types.js";
import type { SignedSHR } from "../../src/shr/types.js";
import { evaluateSlotGate } from "../../src/policy-engine/gates/evaluator.js";
import type { SlotGateExtendedContext } from "../../src/policy-engine/gates/evaluator.js";
import type { GateRequest } from "../../src/policy-engine/types.js";
import { GATE_REASON_CODES } from "../../src/policy-engine/constants.js";

// ── Helpers ─────────────────────────────────────────────────────────────

const SELF_ID = "local-sanctuary-instance";
const PEER_ID = "remote-peer-abc";

const mockSHR: SignedSHR = {
  body: {
    shr_version: "1.0",
    implementation: {
      sanctuary_version: "1.3.0",
      node_version: "22.0.0",
      generated_by: "sanctuary-mcp-server",
    },
    instance_id: PEER_ID,
    generated_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 3600000).toISOString(),
    layers: {
      l1: { status: "active", encryption: "aes-256-gcm", key_custody: "self", integrity: "merkle-sha256", identity_type: "ed25519", state_portable: true },
      l2: { status: "active", isolation_type: "local-process", attestation_available: true },
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
    counterparty_id: PEER_ID,
    counterparty_shr: mockSHR,
    verified: true,
    sovereignty_level: "full",
    trust_tier: "verified-sovereign",
    completed_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 3600000).toISOString(),
    errors: [],
    ...overrides,
  };
}

function makeLookup(map: Map<string, HandshakeResult>): HandshakeStateLookup {
  return (id: string) => map.get(id);
}

/** Deterministic Ed25519 key seed for test receipt signing. */
const TEST_KEY = new Uint8Array(32).fill(0x42);

function makeGateContext(
  subscriberHandshakeGate?: SlotGateExtendedContext["subscriberHandshakeGate"]
): SlotGateExtendedContext {
  return {
    policy: {
      policy_version: "test-v1",
      agent_id: "test-agent",
      fortress_id: "test-fortress",
      source_english: "test",
      slots: {
        memory: { slot: "memory", mode: "deny", grants: [] },
        credentials: { slot: "credentials", mode: "deny", grants: [] },
        plans: { slot: "plans", mode: "deny", grants: [] },
        outputs: {
          slot: "outputs",
          mode: "grant",
          grants: [
            { counterparty: PEER_ID, action: "subscribe" },
            { counterparty: SELF_ID, action: "subscribe" },
          ],
        },
      },
      capabilities: {
        concordia_commitment_classes: [],
        honeypot_skill_ids: [],
        is_sentinel: false,
      },
      egress: { default_action: "allow", rules: [] },
      budget: null,
      retention: null,
    },
    nodeSigningKey: TEST_KEY,
    nodeId: "test-node",
    fortressId: "test-fortress",
    subscriberHandshakeGate,
    now: () => new Date("2026-05-16T12:00:00Z"),
  };
}

function makeSubscribeRequest(counterparty: string): GateRequest {
  return {
    agent_id: "test-agent",
    counterparty,
    action: "subscribe",
  };
}

// ── Subscriber gate utility tests ───────────────────────────────────────

describe("Subscriber pre-handshake gating", () => {
  describe("checkSubscriberHandshakeState", () => {
    it("refuses subscriber with not_started handshake (no entry in results)", () => {
      const lookup = makeLookup(new Map());
      const result = checkSubscriberHandshakeState(PEER_ID, SELF_ID, lookup);
      expect(result.permitted).toBe(false);
      expect(result.state).toBe("not_started");
      expect(result.is_self).toBe(false);
    });

    it("refuses subscriber with failed handshake (verified=false)", () => {
      const map = new Map<string, HandshakeResult>();
      map.set(PEER_ID, makeHandshakeResult({
        verified: false,
        trust_tier: "unverified",
      }));
      const lookup = makeLookup(map);
      const result = checkSubscriberHandshakeState(PEER_ID, SELF_ID, lookup);
      expect(result.permitted).toBe(false);
      expect(result.state).toBe("failed");
      expect(result.is_self).toBe(false);
    });

    it("refuses subscriber with expired handshake", () => {
      const map = new Map<string, HandshakeResult>();
      map.set(PEER_ID, makeHandshakeResult({
        expires_at: new Date(Date.now() - 1000).toISOString(),
      }));
      const lookup = makeLookup(map);
      const result = checkSubscriberHandshakeState(PEER_ID, SELF_ID, lookup);
      expect(result.permitted).toBe(false);
      expect(result.state).toBe("expired");
      expect(result.is_self).toBe(false);
    });

    it("permits subscriber with verified_sovereign handshake", () => {
      const map = new Map<string, HandshakeResult>();
      map.set(PEER_ID, makeHandshakeResult({
        trust_tier: "verified-sovereign",
      }));
      const lookup = makeLookup(map);
      const result = checkSubscriberHandshakeState(PEER_ID, SELF_ID, lookup);
      expect(result.permitted).toBe(true);
      expect(result.state).toBe("verified_sovereign");
      expect(result.trust_tier).toBe("verified-sovereign");
      expect(result.is_self).toBe(false);
    });

    it("permits subscriber with verified_degraded handshake", () => {
      const map = new Map<string, HandshakeResult>();
      map.set(PEER_ID, makeHandshakeResult({
        trust_tier: "verified-degraded",
        sovereignty_level: "degraded",
      }));
      const lookup = makeLookup(map);
      const result = checkSubscriberHandshakeState(PEER_ID, SELF_ID, lookup);
      expect(result.permitted).toBe(true);
      expect(result.state).toBe("verified_degraded");
      expect(result.trust_tier).toBe("verified-degraded");
      expect(result.is_self).toBe(false);
    });

    it("always permits self-subscription regardless of handshake state", () => {
      const lookup = makeLookup(new Map()); // no entries at all
      const result = checkSubscriberHandshakeState(SELF_ID, SELF_ID, lookup);
      expect(result.permitted).toBe(true);
      expect(result.is_self).toBe(true);
    });

    it("refuses subscriber with unverified trust tier", () => {
      const map = new Map<string, HandshakeResult>();
      map.set(PEER_ID, makeHandshakeResult({
        verified: true,
        trust_tier: "unverified",
      }));
      const lookup = makeLookup(map);
      const result = checkSubscriberHandshakeState(PEER_ID, SELF_ID, lookup);
      expect(result.permitted).toBe(false);
      expect(result.state).toBe("failed");
    });
  });

  describe("denial message non-leakage", () => {
    it("generic denial message does not reveal handshake state", () => {
      expect(SUBSCRIBER_DENIED_MESSAGE).not.toContain("not_started");
      expect(SUBSCRIBER_DENIED_MESSAGE).not.toContain("in_progress");
      expect(SUBSCRIBER_DENIED_MESSAGE).not.toContain("failed");
      expect(SUBSCRIBER_DENIED_MESSAGE).not.toContain("expired");
      expect(SUBSCRIBER_DENIED_MESSAGE).not.toContain("verified");
    });
  });

  describe("buildDeniedAuditDetails", () => {
    it("includes attempting peer identity and subscriber surface", () => {
      const gateResult = {
        permitted: false,
        state: "not_started" as const,
        is_self: false,
      };
      const details = buildDeniedAuditDetails(
        PEER_ID,
        "outputs_slot_subscribe",
        gateResult
      );
      expect(details.attempting_peer_identity).toBe(PEER_ID);
      expect(details.subscriber_surface).toBe("outputs_slot_subscribe");
      expect(details.handshake_state_observed).toBe("not_started");
      expect(details.timestamp).toBeTruthy();
    });
  });

  // ── Slot gate evaluator integration tests ─────────────────────────────

  describe("slot gate evaluator integration", () => {
    it("denies subscribe action when handshake gate reports not permitted", () => {
      const ctx = makeGateContext((counterpartyId) => ({
        permitted: false,
        state: "not_started",
        is_self: counterpartyId === SELF_ID,
      }));
      const req = makeSubscribeRequest(PEER_ID);
      const result = evaluateSlotGate("outputs", ctx, req);
      expect(result.decision).toBe("deny");
      expect(result.reason_code).toBe(
        GATE_REASON_CODES.SUBSCRIBER_HANDSHAKE_NOT_VERIFIED
      );
      // Generic explanation -- does not leak state
      expect(result.explanation).toBe("operation not permitted");
    });

    it("allows subscribe action when handshake gate reports verified", () => {
      const ctx = makeGateContext((counterpartyId) => ({
        permitted: true,
        state: "verified_sovereign",
        is_self: counterpartyId === SELF_ID,
      }));
      const req = makeSubscribeRequest(PEER_ID);
      const result = evaluateSlotGate("outputs", ctx, req);
      expect(result.decision).toBe("allow");
      expect(result.reason_code).toBe(GATE_REASON_CODES.RULE_ALLOW);
    });

    it("allows self-subscription even when handshake gate is present", () => {
      const ctx = makeGateContext((counterpartyId) => ({
        permitted: counterpartyId === SELF_ID,
        state: counterpartyId === SELF_ID ? "verified_sovereign" : "not_started",
        is_self: counterpartyId === SELF_ID,
      }));
      const req = makeSubscribeRequest(SELF_ID);
      const result = evaluateSlotGate("outputs", ctx, req);
      expect(result.decision).toBe("allow");
      expect(result.reason_code).toBe(GATE_REASON_CODES.RULE_ALLOW);
    });

    it("does not apply handshake gate for non-subscribe actions", () => {
      const ctx = makeGateContext((_counterpartyId) => ({
        // Would deny if checked
        permitted: false,
        state: "not_started",
        is_self: false,
      }));
      // Add a read grant for the peer
      ctx.policy!.slots.outputs.grants.push({
        counterparty: PEER_ID,
        action: "read",
      });
      const req: GateRequest = {
        agent_id: "test-agent",
        counterparty: PEER_ID,
        action: "read",
      };
      const result = evaluateSlotGate("outputs", ctx, req);
      expect(result.decision).toBe("allow");
      expect(result.reason_code).toBe(GATE_REASON_CODES.RULE_ALLOW);
    });

    it("does not check handshake gate when callback is absent (backward compat)", () => {
      const ctx = makeGateContext(undefined);
      const req = makeSubscribeRequest(PEER_ID);
      const result = evaluateSlotGate("outputs", ctx, req);
      // Without handshake gate, falls through to grant evaluation
      expect(result.decision).toBe("allow");
      expect(result.reason_code).toBe(GATE_REASON_CODES.RULE_ALLOW);
    });

    it("denies subscribe for expired handshake counterparty", () => {
      const ctx = makeGateContext((counterpartyId) => ({
        permitted: false,
        state: "expired",
        is_self: counterpartyId === SELF_ID,
      }));
      const req = makeSubscribeRequest(PEER_ID);
      const result = evaluateSlotGate("outputs", ctx, req);
      expect(result.decision).toBe("deny");
      expect(result.reason_code).toBe(
        GATE_REASON_CODES.SUBSCRIBER_HANDSHAKE_NOT_VERIFIED
      );
    });

    it("denies subscribe for failed handshake counterparty", () => {
      const ctx = makeGateContext((counterpartyId) => ({
        permitted: false,
        state: "failed",
        is_self: counterpartyId === SELF_ID,
      }));
      const req = makeSubscribeRequest(PEER_ID);
      const result = evaluateSlotGate("outputs", ctx, req);
      expect(result.decision).toBe("deny");
      expect(result.reason_code).toBe(
        GATE_REASON_CODES.SUBSCRIBER_HANDSHAKE_NOT_VERIFIED
      );
    });

    it("receipt includes subscriber_handshake_not_verified reason code", () => {
      const ctx = makeGateContext((_counterpartyId) => ({
        permitted: false,
        state: "not_started",
        is_self: false,
      }));
      const req = makeSubscribeRequest(PEER_ID);
      const result = evaluateSlotGate("outputs", ctx, req);
      expect(result.receipt.reason_code).toBe(
        "subscriber_handshake_not_verified"
      );
      expect(result.receipt.decision).toBe("deny");
    });
  });
});
