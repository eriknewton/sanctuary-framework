/**
 * Ping Identity Gateway Adapter — Tests
 *
 * Tests for SHR → authorization context transformation, scoring, and constraint generation.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import { generateSHR } from "../../src/shr/generator.js";
import {
  transformSHRForGateway,
  transformSHRGeneric,
  type PingAuthorizationContext,
  type GenericAuthorizationContext,
} from "../../src/shr/gateway-adapter.js";
import type { SignedSHR } from "../../src/shr/types.js";
import type { SanctuaryConfig } from "../../src/config.js";
import { defaultConfig } from "../../src/config.js";

// Minimal IdentityManager mock
class TestIdentityManager {
  private identities = new Map<string, any>();
  private defaultId: string | null = null;

  constructor(storage: MemoryStorage, masterKey: Uint8Array) {
    const encKey = derivePurposeKey(masterKey, "identity-encryption");
    const { publicIdentity, storedIdentity } = createIdentity(
      "test",
      encKey,
      "recovery-key"
    );
    this.identities.set(publicIdentity.identity_id, storedIdentity);
    this.defaultId = publicIdentity.identity_id;
  }

  get(id: string) {
    return this.identities.get(id);
  }
  getDefault() {
    return this.defaultId ? this.identities.get(this.defaultId) : undefined;
  }
  list() {
    return Array.from(this.identities.values());
  }
}

describe("Ping Identity Gateway Adapter", () => {
  let storage: MemoryStorage;
  let masterKey: Uint8Array;
  let identityManager: TestIdentityManager;
  let config: SanctuaryConfig;

  beforeEach(() => {
    storage = new MemoryStorage();
    masterKey = generateRandomKey();
    identityManager = new TestIdentityManager(storage, masterKey);
    config = defaultConfig();
  });

  describe("transformSHRForGateway", () => {
    it("transforms a full-sovereignty SHR correctly", () => {
      // Generate an SHR with all layers active
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const context = transformSHRForGateway(shr);

      expect(context).toBeDefined();
      expect(context.shr_version).toBe("1.0");
      expect(context.agent_identity).toBe(shr.signed_by);
      expect(context.overall_score).toBeGreaterThanOrEqual(0);
      expect(context.overall_score).toBeLessThanOrEqual(100);
      expect(["full", "elevated", "standard", "restricted"]).toContain(
        context.recommended_trust_level
      );
    });

    it("includes all layer scores", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const context = transformSHRForGateway(shr);

      expect(context.layer_scores.l1_cognitive).toBeDefined();
      expect(context.layer_scores.l2_operational).toBeDefined();
      expect(context.layer_scores.l3_disclosure).toBeDefined();
      expect(context.layer_scores.l4_reputation).toBeDefined();

      expect(context.layer_scores.l1_cognitive).toBeGreaterThanOrEqual(0);
      expect(context.layer_scores.l2_operational).toBeGreaterThanOrEqual(0);
      expect(context.layer_scores.l3_disclosure).toBeGreaterThanOrEqual(0);
      expect(context.layer_scores.l4_reputation).toBeGreaterThanOrEqual(0);
    });

    it("includes all layer statuses", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const context = transformSHRForGateway(shr);

      expect(context.layer_status.l1_cognitive).toBeDefined();
      expect(context.layer_status.l2_operational).toBeDefined();
      expect(context.layer_status.l3_disclosure).toBeDefined();
      expect(context.layer_status.l4_reputation).toBeDefined();
    });

    it("includes authorization signals", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const context = transformSHRForGateway(shr);

      expect(context.authorization_signals).toBeDefined();
      expect(context.authorization_signals.approval_gate_active).toBeDefined();
      expect(context.authorization_signals.context_gating_active).toBeDefined();
      expect(context.authorization_signals.encryption_at_rest).toBeDefined();
      expect(context.authorization_signals.behavioral_baseline_active).toBeDefined();
      expect(context.authorization_signals.identity_verified).toBeDefined();
      expect(context.authorization_signals.zero_knowledge_capable).toBeDefined();
      expect(context.authorization_signals.selective_disclosure_active).toBeDefined();
      expect(context.authorization_signals.reputation_portable).toBeDefined();
      expect(context.authorization_signals.handshake_capable).toBeDefined();
    });

    it("includes degradations with authorization impacts", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const context = transformSHRForGateway(shr);

      expect(Array.isArray(context.degradations)).toBe(true);

      // Each degradation should have authorization impact
      for (const deg of context.degradations) {
        expect(deg.layer).toBeDefined();
        expect(deg.code).toBeDefined();
        expect(deg.severity).toBeDefined();
        expect(deg.authorization_impact).toBeDefined();
      }
    });

    it("includes recommended constraints", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const context = transformSHRForGateway(shr);

      expect(Array.isArray(context.recommended_constraints)).toBe(true);

      // Each constraint should have type and rationale
      for (const constraint of context.recommended_constraints) {
        expect(constraint.type).toBeDefined();
        expect(constraint.description).toBeDefined();
        expect(constraint.rationale).toBeDefined();
        expect(["high", "medium", "low"]).toContain(constraint.priority);
      }
    });

    it("preserves signature information", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const context = transformSHRForGateway(shr);

      expect(context.shr_signature).toBe(shr.signature);
      expect(context.shr_signed_by).toBe(shr.signed_by);
    });

    it("calculates trust levels correctly", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const context = transformSHRForGateway(shr);

      if (context.overall_score >= 80) {
        expect(context.recommended_trust_level).toBe("full");
      } else if (context.overall_score >= 60) {
        expect(context.recommended_trust_level).toBe("elevated");
      } else if (context.overall_score >= 40) {
        expect(context.recommended_trust_level).toBe("standard");
      } else {
        expect(context.recommended_trust_level).toBe("restricted");
      }
    });

    it("sets context expiry to SHR expiry", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const context = transformSHRForGateway(shr);

      expect(context.context_expires_at).toBe(shr.body.expires_at);
    });

    it("with local-process environment, applies L2 degradations", () => {
      const localConfig = {
        ...config,
        execution: {
          ...config.execution,
          environment: "local-process",
        },
      };

      const shr = generateSHR(undefined, {
        config: localConfig,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const context = transformSHRForGateway(shr);

      // L2 should be degraded
      expect(context.layer_status.l2_operational).toBe("degraded");
      expect(context.layer_scores.l2_operational).toBeLessThan(100);

      // Should have constraints related to L2 degradation
      const hasL2Constraint = context.recommended_constraints.some((c) =>
        c.description.toLowerCase().includes("isolation") ||
        c.description.toLowerCase().includes("read-only")
      );
      expect(hasL2Constraint).toBe(true);
    });

    it("with schnorr-pedersen proof system, L3 is active (genuine ZK)", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const context = transformSHRForGateway(shr);

      // L3 should be active — Schnorr + Pedersen + range proofs are genuine ZK
      expect(context.layer_status.l3_disclosure).toBe("active");
      expect(context.layer_scores.l3_disclosure).toBe(100);

      // Should NOT have constraints related to L3 degradation
      const hasL3Constraint = context.recommended_constraints.some((c) =>
        c.description.toLowerCase().includes("no zero-knowledge")
      );
      expect(hasL3Constraint).toBe(false);
    });
  });

  describe("transformSHRGeneric", () => {
    it("produces a generic authorization context", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const context = transformSHRGeneric(shr);

      expect(context).toBeDefined();
      expect(context.agent_id).toBe(shr.signed_by);
      expect(context.sovereignty_score).toBeGreaterThanOrEqual(0);
      expect(context.sovereignty_score).toBeLessThanOrEqual(100);
      expect(["full", "elevated", "standard", "restricted"]).toContain(
        context.trust_level
      );
    });

    it("includes generic layer scores", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const context = transformSHRGeneric(shr);

      expect(context.layer_scores).toBeDefined();
      expect(context.layer_scores.l1).toBeDefined();
      expect(context.layer_scores.l2).toBeDefined();
      expect(context.layer_scores.l3).toBeDefined();
      expect(context.layer_scores.l4).toBeDefined();
    });

    it("includes simplified constraints", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const context = transformSHRGeneric(shr);

      expect(Array.isArray(context.constraints)).toBe(true);
      for (const constraint of context.constraints) {
        expect(constraint.type).toBeDefined();
        expect(constraint.description).toBeDefined();
      }
    });

    it("preserves capabilities from authorization signals", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const context = transformSHRGeneric(shr);

      expect(context.capabilities).toBeDefined();
      expect(Object.keys(context.capabilities).length).toBeGreaterThan(0);
    });
  });

  describe("authorization constraint generation", () => {
    it("generates high-priority constraints for critical degradations", () => {
      const localConfig = {
        ...config,
        execution: {
          ...config.execution,
          environment: "local-process",
        },
      };

      const shr = generateSHR(undefined, {
        config: localConfig,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const context = transformSHRForGateway(shr);

      const highPriorityConstraints = context.recommended_constraints.filter(
        (c) => c.priority === "high"
      );

      expect(highPriorityConstraints.length).toBeGreaterThan(0);
    });

    it("adjusts constraints based on overall sovereignty score", () => {
      // Create a very degraded config
      const veryDegradedConfig = {
        ...config,
        execution: {
          ...config.execution,
          environment: "local-process",
        },
        disclosure: {
          ...config.disclosure,
          proof_system: "commitment-only",
        },
      };

      const shr = generateSHR(undefined, {
        config: veryDegradedConfig,
        identityManager: identityManager as any,
        masterKey,
      }) as SignedSHR;

      const context = transformSHRForGateway(shr);

      // With multiple degradations, overall score should be lower
      // and constraints should reflect that
      if (context.overall_score < 40) {
        const hasRestrictedScope = context.recommended_constraints.some((c) =>
          c.type === "restricted_scope" &&
          c.rationale.includes("overall")
        );
        expect(hasRestrictedScope).toBe(true);
      }
    });
  });

  // ─── v0.9.1: new L4 degradation codes surface correctly ──────────
  describe("L4 degradation codes (v0.9.1)", () => {
    function zeroTiers() {
      return {
        "verified-sovereign": 0,
        "verified-degraded": 0,
        "self-attested": 0,
        "unverified": 0,
      } as const;
    }

    it("transforms NO_REPUTATION_HISTORY into a gateway authorization impact", () => {
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
        l4Evidence: {
          attestation_count: 0,
          tier_distribution: { ...zeroTiers() },
          most_recent_attestation_at: null,
          dispute_count: 0,
          context_breakdown: {},
          verascore_linked: true,
        },
      }) as SignedSHR;

      const context = transformSHRForGateway(shr);
      const entry = context.degradations.find(
        (d) => d.code === "NO_REPUTATION_HISTORY"
      );
      expect(entry).toBeDefined();
      expect(entry?.authorization_impact).toMatch(/new counterparty|escrow/i);
      expect(entry?.authorization_impact).not.toBe("Unknown authorization impact");
    });

    it("transforms each new L4 code without falling through to 'Unknown'", () => {
      const now = new Date("2026-05-01T00:00:00Z");
      const stale = new Date(
        now.getTime() - 60 * 24 * 60 * 60 * 1000
      ).toISOString();
      const shr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
        now,
        l4Evidence: {
          attestation_count: 5,
          tier_distribution: {
            "verified-sovereign": 0,
            "verified-degraded": 0,
            "self-attested": 4,
            "unverified": 1,
          },
          most_recent_attestation_at: stale,
          dispute_count: 2,
          context_breakdown: { commerce: 5 },
          verascore_linked: false,
        },
      }) as SignedSHR;

      const context = transformSHRForGateway(shr);
      const l4Entries = context.degradations.filter((d) => d.layer === "l4");

      const codes = l4Entries.map((e) => e.code).sort();
      expect(codes).toEqual(
        [
          "LOW_TIER_DOMINANCE",
          "STALE_REPUTATION",
          "DISPUTE_ON_RECORD",
          "NO_VERASCORE_LINK",
        ].sort()
      );
      for (const entry of l4Entries) {
        expect(entry.authorization_impact).toBeTruthy();
        expect(entry.authorization_impact).not.toBe(
          "Unknown authorization impact"
        );
      }
    });

    it("subtracts DEGRADATION_IMPACT from the L4 layer score when L4 degradations fire", () => {
      const healthyShr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
        l4Evidence: {
          attestation_count: 10,
          tier_distribution: {
            "verified-sovereign": 10,
            "verified-degraded": 0,
            "self-attested": 0,
            "unverified": 0,
          },
          most_recent_attestation_at: new Date().toISOString(),
          dispute_count: 0,
          context_breakdown: { commerce: 10 },
          verascore_linked: true,
        },
      }) as SignedSHR;

      const degradedShr = generateSHR(undefined, {
        config,
        identityManager: identityManager as any,
        masterKey,
        l4Evidence: {
          attestation_count: 0,
          tier_distribution: { ...zeroTiers() },
          most_recent_attestation_at: null,
          dispute_count: 0,
          context_breakdown: {},
          verascore_linked: false,
        },
      }) as SignedSHR;

      const healthy = transformSHRForGateway(healthyShr);
      const degraded = transformSHRForGateway(degradedShr);
      expect(degraded.layer_scores.l4_reputation).toBeLessThan(
        healthy.layer_scores.l4_reputation
      );
    });
  });
});
