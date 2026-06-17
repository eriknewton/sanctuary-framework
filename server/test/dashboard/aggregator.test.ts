/**
 * Dashboard aggregator tests — verify getProtectionSnapshot() returns
 * the correct shape and traffic-light status across healthy, degraded,
 * and compromised states.
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { getProtectionSnapshot } from "../../src/dashboard/aggregator.js";
import type { AggregatorSources } from "../../src/dashboard/aggregator.js";
import type { AuditEntry } from "../../src/operational/audit-log.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { producerSigningBytes } from "../../src/castle-wall/runtime/producer-signature.js";
import {
  CASTLE_WALL_AUDIT_PROVENANCE_KEY,
  CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
} from "../../src/castle-wall/constants.js";
import type { IdentityManager } from "../../src/cognitive/tools.js";
import type { PublicIdentity, StoredIdentity } from "../../src/core/identity.js";

function stubIdentity(overrides: Partial<PublicIdentity> = {}): StoredIdentity {
  return {
    identity_id: overrides.identity_id ?? "id-1",
    label: overrides.label ?? "Agent-1",
    public_key: overrides.public_key ?? "pk",
    did: overrides.did ?? "did:key:z6Mkabcdef1234567890abcdef1234567890abcdef1234567890",
    created_at: overrides.created_at ?? new Date().toISOString(),
    key_type: "ed25519",
    key_protection: overrides.key_protection ?? "passphrase",
    encrypted_private_key: {} as StoredIdentity["encrypted_private_key"],
    rotation_history: [],
  };
}

function stubIdentityManager(identity?: StoredIdentity): IdentityManager {
  const store: PublicIdentity[] = identity
    ? [
        {
          identity_id: identity.identity_id,
          label: identity.label,
          public_key: identity.public_key,
          did: identity.did,
          created_at: identity.created_at,
          key_type: identity.key_type,
          key_protection: identity.key_protection,
        },
      ]
    : [];
  return {
    getDefault: () => identity,
    list: () => store,
    getPrimaryIdentityId: () => identity?.identity_id ?? null,
    get: (id: string) => (identity && identity.identity_id === id ? identity : undefined),
  } as unknown as IdentityManager;
}

function stubAuditLog(
  entries: AuditEntry[],
  integrity_findings: unknown[] = [],
): AuditLog {
  return {
    query: async () => ({ entries, total: entries.length, integrity_findings }),
    append: () => undefined,
    size: entries.length,
  } as unknown as AuditLog;
}

// A fresh Castle Wall enforcement-evidence audit entry (carries the provenance
// marker the posture reader requires); arms the wall so the overall light can
// legitimately go green.
function cwArmEntry(ageMs = 60_000): AuditEntry {
  return {
    timestamp: new Date(Date.now() - ageMs).toISOString(),
    layer: "l1",
    operation: "egress_allowed",
    identity_id: "id-1",
    result: "success",
    details: { cw_source: "castle_wall_audit_consumer" },
  } as unknown as AuditEntry;
}

function baseSources(overrides: Partial<AggregatorSources> = {}): AggregatorSources {
  const sources: AggregatorSources = {
    mode: "co-located",
    server_version: "0.9.0-test",
    ...overrides,
  };
  return sources;
}

describe("getProtectionSnapshot", () => {
  it("returns all four layers and top-level structure", async () => {
    const snap = await getProtectionSnapshot(baseSources());
    expect(snap.layers.l1).toBeDefined();
    expect(snap.layers.l2).toBeDefined();
    expect(snap.layers.l3).toBeDefined();
    expect(snap.layers.l4).toBeDefined();
    expect(snap.overall.light).toMatch(/^(green|yellow|red)$/);
    expect(typeof snap.generated_at).toBe("string");
    expect(snap.mode).toBe("co-located");
    expect(snap.server_version).toBe("0.9.0-test");
  });

  it("configured layers full but NO Castle Wall evidence renders honest amber, not green", async () => {
    // The honesty fix: identity + DID + Verascore configured proves "configured",
    // not "enforced". With no fresh Castle Wall enforcement evidence the overall
    // light must be amber, never the green it used to show.
    const identity = stubIdentity();
    const sources = baseSources({
      identityManager: stubIdentityManager(identity),
      auditLog: stubAuditLog([]),
      teeAvailable: false,
      reputation: { score: 82, profile_url: "https://verascore.ai/p/abc" },
    });
    const snap = await getProtectionSnapshot(sources);
    expect(snap.layers.l1.state).toBe("full");
    expect(snap.layers.l3.state).toBe("full");
    expect(snap.layers.l4.state).toBe("full");
    expect(snap.overall.light).toBe("yellow");
    expect(snap.overall.status).toBe("degraded");
    expect(snap.overall.headline).toMatch(/Castle Wall enforcement not confirmed/);
  });

  it("flags green only when all layers full AND Castle Wall is armed (fresh enforcement evidence)", async () => {
    const sources = baseSources({
      identityManager: stubIdentityManager(stubIdentity()),
      auditLog: stubAuditLog([cwArmEntry()]),
      teeAvailable: true,
      reputation: { score: 95, profile_url: "https://verascore.ai/p/xyz" },
    });
    const snap = await getProtectionSnapshot(sources);
    expect(snap.layers.l2.state).toBe("full");
    expect(snap.overall.light).toBe("green");
    expect(snap.overall.status).toBe("healthy");
    expect(snap.overall.headline).toBe("All layers full, Castle Wall enforcing");
  });

  it("does NOT go green when all layers full and wall armed but the audit chain is tamper-flagged", async () => {
    // Integrity findings mean the evidence behind the light is untrustworthy:
    // fail closed to red, never green, even with a fresh wall-arm entry present.
    const sources = baseSources({
      identityManager: stubIdentityManager(stubIdentity()),
      auditLog: stubAuditLog([cwArmEntry()], [
        { kind: "entry_hash_mismatch", message: "tampered" },
      ]),
      teeAvailable: true,
      reputation: { score: 95, profile_url: "https://verascore.ai/p/xyz" },
    });
    const snap = await getProtectionSnapshot(sources);
    expect(snap.overall.light).toBe("red");
    expect(snap.overall.status).toBe("compromised");
    expect(snap.overall.headline).toBe("Audit chain integrity check failed");
  });

  it("flags yellow (degraded) when L1/L3/L4 are not full", async () => {
    const sources = baseSources({
      identityManager: stubIdentityManager(),
      auditLog: stubAuditLog([]),
    });
    const snap = await getProtectionSnapshot(sources);
    expect(snap.layers.l1.state).toBe("degraded");
    expect(snap.layers.l4.state).toBe("degraded");
    expect(snap.overall.light).toBe("yellow");
    expect(snap.overall.status).toBe("degraded");
  });

  it("produces an 'Unclaimed agent' when no identity is present", async () => {
    const snap = await getProtectionSnapshot(baseSources());
    expect(snap.agent.display_name).toBe("Unclaimed agent");
    expect(snap.agent.did).toBeNull();
    expect(snap.agent.did_fingerprint).toBeNull();
    expect(snap.layers.l4.claim_cta).toMatch(/verascore/);
  });

  it("fingerprints the DID to a short display form", async () => {
    const identity = stubIdentity({
      did: "did:key:z6MkABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijkl",
    });
    const snap = await getProtectionSnapshot(
      baseSources({ identityManager: stubIdentityManager(identity) })
    );
    expect(snap.agent.did_fingerprint).toMatch(/^.{6}….{6}$/);
  });

  it("counts proof-creation ops and injection blocks from today only", async () => {
    const today = new Date();
    today.setHours(12, 0, 0, 0);
    const yesterday = new Date(today.getTime() - 24 * 60 * 60 * 1000);

    const audit: AuditEntry[] = [
      {
        timestamp: today.toISOString(),
        layer: "l3",
        operation: "zk_prove",
        identity_id: "id-1",
        result: "success",
      },
      {
        timestamp: today.toISOString(),
        layer: "l2",
        operation: "injection_blocked",
        identity_id: "id-1",
        result: "failure",
      },
      {
        timestamp: yesterday.toISOString(),
        layer: "l3",
        operation: "zk_prove",
        identity_id: "id-1",
        result: "success",
      },
    ];

    const sources = baseSources({
      identityManager: stubIdentityManager(stubIdentity()),
      auditLog: stubAuditLog(audit),
    });
    const snap = await getProtectionSnapshot(sources);
    expect(snap.layers.l3.proofs_today).toBe(1);
    expect(snap.layers.l1.injection_blocked_today).toBeGreaterThanOrEqual(1);
  });

  it("summarizes privacy filtering from audit metadata", async () => {
    const now = new Date().toISOString();
    const audit: AuditEntry[] = [
      {
        timestamp: now,
        layer: "l2",
        operation: "context_gate_filter",
        identity_id: "id-1",
        result: "success",
        details: {
          privacy_findings: 2,
          privacy_classes: ["email", "phone"],
        },
      },
      {
        timestamp: now,
        layer: "l2",
        operation: "context_gate_enforcer_builtin_privacy_filter",
        identity_id: "id-1",
        result: "success",
        details: {
          privacy_findings: 1,
          privacy_classes: ["email"],
        },
      },
    ];

    const snap = await getProtectionSnapshot(
      baseSources({ auditLog: stubAuditLog(audit) })
    );
    expect(snap.privacy.filtered_events).toBe(2);
    expect(snap.privacy.filtered_spans).toBe(3);
    expect(snap.privacy.classes).toEqual({ email: 2, phone: 1 });
    expect(snap.privacy.last_filtered_at).toBe(now);
  });

  it("attaches a Verascore score when reputation is provided", async () => {
    const sources = baseSources({
      identityManager: stubIdentityManager(stubIdentity()),
      auditLog: stubAuditLog([]),
      reputation: { score: 72, profile_url: "https://verascore.ai/p/12" },
    });
    const snap = await getProtectionSnapshot(sources);
    expect(snap.layers.l4.state).toBe("full");
    expect(snap.layers.l4.score).toBe(72);
    expect(snap.layers.l4.profile_url).toBe("https://verascore.ai/p/12");
    expect(snap.layers.l4.claim_cta).toBeNull();
  });

  it("shows claim CTA when identity exists but no reputation yet", async () => {
    const sources = baseSources({
      identityManager: stubIdentityManager(stubIdentity()),
      auditLog: stubAuditLog([]),
    });
    const snap = await getProtectionSnapshot(sources);
    expect(snap.layers.l4.state).toBe("degraded");
    expect(snap.layers.l4.claim_cta).toContain("verascore.ai");
  });

  it("degrades gracefully without auditLog or identityManager (standalone)", async () => {
    const snap = await getProtectionSnapshot(baseSources({ mode: "standalone" }));
    expect(snap.mode).toBe("standalone");
    expect(snap.audit).toEqual([]);
    expect(snap.activity).toEqual([]);
    expect(snap.pending_approvals).toEqual([]);
    expect(snap.agent.display_name).toBe("Unclaimed agent");
  });

  it("echoes the 4-card layer labels so the HTML can match on them", async () => {
    const snap = await getProtectionSnapshot(baseSources());
    expect(snap.layers.l1.label).toBe("L1 Cognitive");
    expect(snap.layers.l2.label).toBe("L2 Operational");
    expect(snap.layers.l3.label).toBe("L3 Disclosure");
    expect(snap.layers.l4.label).toBe("L4 Reputation");
  });

  it("flips to red when aggregator sources indicate a compromised L1 via null identity + failure-heavy audit", async () => {
    // There is no code path that directly returns 'compromised' today, but the
    // helper must not crash and must fall back to yellow/red sensibly when
    // fed adversarial state.
    const snap = await getProtectionSnapshot(
      baseSources({
        auditLog: stubAuditLog(
          Array.from({ length: 25 }).map((_, i) => ({
            timestamp: new Date().toISOString(),
            layer: "l2" as const,
            operation: `injection_blocked_${i}`,
            identity_id: "id-1",
            result: "failure" as const,
          }))
        ),
      })
    );
    expect(snap.overall.light === "yellow" || snap.overall.light === "red").toBe(true);
    expect(snap.layers.l1.injection_blocked_today).toBeGreaterThanOrEqual(25);
  });

  // ── Counter filter tests (rc.4) ───────────────────────────────────

  describe("vc_count filter", () => {
    const today = new Date();
    today.setHours(10, 0, 0, 0);

    it("counts reputation_record as a VC-issuing op", async () => {
      const snap = await getProtectionSnapshot(baseSources({
        identityManager: stubIdentityManager(stubIdentity()),
        auditLog: stubAuditLog([
          { timestamp: today.toISOString(), layer: "l4", operation: "reputation_record", identity_id: "id-1", result: "success" },
        ]),
      }));
      expect(snap.layers.l3.vc_count).toBe(1);
    });

    it("counts bootstrap_provide_guarantee as a VC-issuing op", async () => {
      const snap = await getProtectionSnapshot(baseSources({
        identityManager: stubIdentityManager(stubIdentity()),
        auditLog: stubAuditLog([
          { timestamp: today.toISOString(), layer: "l4", operation: "bootstrap_provide_guarantee", identity_id: "id-1", result: "success" },
        ]),
      }));
      expect(snap.layers.l3.vc_count).toBe(1);
    });

    it("counts reputation_publish as a VC-issuing op", async () => {
      const snap = await getProtectionSnapshot(baseSources({
        identityManager: stubIdentityManager(stubIdentity()),
        auditLog: stubAuditLog([
          { timestamp: today.toISOString(), layer: "l4", operation: "reputation_publish", identity_id: "id-1", result: "success" },
        ]),
      }));
      expect(snap.layers.l3.vc_count).toBe(1);
    });

    it("does NOT count reputation_query", async () => {
      const snap = await getProtectionSnapshot(baseSources({
        identityManager: stubIdentityManager(stubIdentity()),
        auditLog: stubAuditLog([
          { timestamp: today.toISOString(), layer: "l4", operation: "reputation_query", identity_id: "id-1", result: "success" },
        ]),
      }));
      expect(snap.layers.l3.vc_count).toBe(0);
    });

    it("does NOT count reputation_export", async () => {
      const snap = await getProtectionSnapshot(baseSources({
        identityManager: stubIdentityManager(stubIdentity()),
        auditLog: stubAuditLog([
          { timestamp: today.toISOString(), layer: "l4", operation: "reputation_export", identity_id: "id-1", result: "success" },
        ]),
      }));
      expect(snap.layers.l3.vc_count).toBe(0);
    });
  });

  describe("countProofsToday filter", () => {
    const today = new Date();
    today.setHours(10, 0, 0, 0);

    it("counts zk_prove", async () => {
      const snap = await getProtectionSnapshot(baseSources({
        identityManager: stubIdentityManager(stubIdentity()),
        auditLog: stubAuditLog([
          { timestamp: today.toISOString(), layer: "l3", operation: "zk_prove", identity_id: "id-1", result: "success" },
        ]),
      }));
      expect(snap.layers.l3.proofs_today).toBe(1);
    });

    it("counts zk_range_prove", async () => {
      const snap = await getProtectionSnapshot(baseSources({
        identityManager: stubIdentityManager(stubIdentity()),
        auditLog: stubAuditLog([
          { timestamp: today.toISOString(), layer: "l3", operation: "zk_range_prove", identity_id: "id-1", result: "success" },
        ]),
      }));
      expect(snap.layers.l3.proofs_today).toBe(1);
    });

    it("counts proof_commitment", async () => {
      const snap = await getProtectionSnapshot(baseSources({
        identityManager: stubIdentityManager(stubIdentity()),
        auditLog: stubAuditLog([
          { timestamp: today.toISOString(), layer: "l3", operation: "proof_commitment", identity_id: "id-1", result: "success" },
        ]),
      }));
      expect(snap.layers.l3.proofs_today).toBe(1);
    });

    it("does NOT count zk_verify", async () => {
      const snap = await getProtectionSnapshot(baseSources({
        identityManager: stubIdentityManager(stubIdentity()),
        auditLog: stubAuditLog([
          { timestamp: today.toISOString(), layer: "l3", operation: "zk_verify", identity_id: "id-1", result: "success" },
        ]),
      }));
      expect(snap.layers.l3.proofs_today).toBe(0);
    });

    it("does NOT count disclosure_evaluate", async () => {
      const snap = await getProtectionSnapshot(baseSources({
        identityManager: stubIdentityManager(stubIdentity()),
        auditLog: stubAuditLog([
          { timestamp: today.toISOString(), layer: "l3", operation: "disclosure_evaluate", identity_id: "id-1", result: "success" },
        ]),
      }));
      expect(snap.layers.l3.proofs_today).toBe(0);
    });
  });

  describe("countInjectionsToday filter", () => {
    const today = new Date();
    today.setHours(10, 0, 0, 0);

    it("counts injection_detected:X ops", async () => {
      const snap = await getProtectionSnapshot(baseSources({
        auditLog: stubAuditLog([
          { timestamp: today.toISOString(), layer: "l2", operation: "injection_detected:state_read", identity_id: "id-1", result: "failure" },
        ]),
      }));
      expect(snap.layers.l1.injection_blocked_today).toBe(1);
    });

    it("counts proxy_injection_blocked:X ops", async () => {
      const snap = await getProtectionSnapshot(baseSources({
        auditLog: stubAuditLog([
          { timestamp: today.toISOString(), layer: "l2", operation: "proxy_injection_blocked:test", identity_id: "id-1", result: "failure" },
        ]),
      }));
      expect(snap.layers.l1.injection_blocked_today).toBe(1);
    });

    it("does NOT count a non-injection failure", async () => {
      const snap = await getProtectionSnapshot(baseSources({
        auditLog: stubAuditLog([
          { timestamp: today.toISOString(), layer: "l1", operation: "state_read", identity_id: "id-1", result: "failure" },
        ]),
      }));
      expect(snap.layers.l1.injection_blocked_today).toBe(0);
    });

    it("does NOT count a successful L2 op that does not contain injection/blocked", async () => {
      const snap = await getProtectionSnapshot(baseSources({
        auditLog: stubAuditLog([
          { timestamp: today.toISOString(), layer: "l2", operation: "context_gate_filter", identity_id: "id-1", result: "success" },
        ]),
      }));
      expect(snap.layers.l1.injection_blocked_today).toBe(0);
    });
  });

  // ─── v0.9.1: L4 evidence widget ──────────────────────────────────
  describe("L4 evidence widget", () => {
    function zeroTiers() {
      return {
        "verified-sovereign": 0,
        "verified-degraded": 0,
        "self-attested": 0,
        "unverified": 0,
      };
    }

    it("omits evidence when no l4Evidence is supplied (backward-compat)", async () => {
      const snap = await getProtectionSnapshot(
        baseSources({ identityManager: stubIdentityManager(stubIdentity()) })
      );
      expect(snap.layers.l4.evidence).toBeUndefined();
      expect(snap.layers.l4.active_degradations).toBeUndefined();
      expect(snap.layers.l4.layer_score).toBeUndefined();
    });

    it("populates evidence + degradations when l4Evidence is supplied", async () => {
      const snap = await getProtectionSnapshot(
        baseSources({
          identityManager: stubIdentityManager(stubIdentity()),
          l4Evidence: {
            attestation_count: 0,
            tier_distribution: zeroTiers(),
            most_recent_attestation_at: null,
            dispute_count: 0,
            context_breakdown: {},
            verascore_linked: false,
          },
        })
      );
      expect(snap.layers.l4.evidence).toBeDefined();
      expect(snap.layers.l4.evidence?.attestation_count).toBe(0);
      const codes = (snap.layers.l4.active_degradations ?? []).map((d) => d.code);
      expect(codes).toContain("NO_REPUTATION_HISTORY");
      expect(codes).toContain("NO_VERASCORE_LINK");
      expect(typeof snap.layers.l4.layer_score).toBe("number");
      expect(snap.layers.l4.layer_score!).toBeLessThan(100);
    });

    it("downgrades L4 state to 'degraded' when evidence fires degradations even if Verascore is attached", async () => {
      const snap = await getProtectionSnapshot(
        baseSources({
          identityManager: stubIdentityManager(stubIdentity()),
          reputation: { score: 85, profile_url: "https://verascore.ai/p/x" },
          l4Evidence: {
            attestation_count: 0,
            tier_distribution: zeroTiers(),
            most_recent_attestation_at: null,
            dispute_count: 0,
            context_breakdown: {},
            verascore_linked: false,
          },
        })
      );
      expect(snap.layers.l4.state).toBe("degraded");
    });

    it("keeps L4 state 'full' when evidence is healthy AND Verascore is attached", async () => {
      const snap = await getProtectionSnapshot(
        baseSources({
          identityManager: stubIdentityManager(stubIdentity()),
          reputation: { score: 85, profile_url: "https://verascore.ai/p/x" },
          l4Evidence: {
            attestation_count: 10,
            tier_distribution: {
              "verified-sovereign": 8,
              "verified-degraded": 2,
              "self-attested": 0,
              "unverified": 0,
            },
            most_recent_attestation_at: new Date().toISOString(),
            dispute_count: 0,
            context_breakdown: { commerce: 10 },
            verascore_linked: true,
          },
        })
      );
      expect(snap.layers.l4.state).toBe("full");
      expect(snap.layers.l4.layer_score).toBeGreaterThanOrEqual(100);
      expect(snap.layers.l4.active_degradations).toEqual([]);
    });

    it("surfaces mitigation text in active_degradations", async () => {
      const snap = await getProtectionSnapshot(
        baseSources({
          identityManager: stubIdentityManager(stubIdentity()),
          l4Evidence: {
            attestation_count: 0,
            tier_distribution: zeroTiers(),
            most_recent_attestation_at: null,
            dispute_count: 0,
            context_breakdown: {},
            verascore_linked: false,
          },
        })
      );
      const noHistory = (snap.layers.l4.active_degradations ?? []).find(
        (d) => d.code === "NO_REPUTATION_HISTORY"
      );
      expect(noHistory?.mitigation).toBeTruthy();
    });
  });

  // ─── Castle Wall arm-state → overall light (seam #2 honesty) ─────────
  describe("Castle Wall enforcement gates the overall light", () => {
    function fullConfigSources(
      auditLog: AggregatorSources["auditLog"],
      overrides: Partial<AggregatorSources> = {}
    ): AggregatorSources {
      return baseSources({
        identityManager: stubIdentityManager(stubIdentity()),
        auditLog,
        teeAvailable: true,
        reputation: { score: 90, profile_url: "https://verascore.ai/p/x" },
        ...overrides,
      });
    }

    it("stale enforcement evidence (outside the freshness window) renders amber, not green", async () => {
      // A 20-minute-old arm entry is past the 10-minute freshness window: the
      // wall may have been disarmed since, so it must read unknown → amber.
      const snap = await getProtectionSnapshot(
        fullConfigSources(stubAuditLog([cwArmEntry(20 * 60_000)]))
      );
      expect(snap.overall.light).toBe("yellow");
      expect(snap.overall.status).toBe("degraded");
      expect(snap.overall.headline).toMatch(/Castle Wall enforcement not confirmed/);
    });

    it("a fresh 'not enforcing' fault (filter_crashed) renders the degraded headline", async () => {
      const faultEntry: AuditEntry = {
        timestamp: new Date(Date.now() - 60_000).toISOString(),
        layer: "l1",
        operation: "filter_crashed",
        identity_id: "id-1",
        result: "failure",
        details: { cw_source: CASTLE_WALL_AUDIT_PROVENANCE_VALUE },
      } as unknown as AuditEntry;
      const snap = await getProtectionSnapshot(
        fullConfigSources(stubAuditLog([faultEntry]))
      );
      expect(snap.overall.light).toBe("yellow");
      expect(snap.overall.headline).toMatch(
        /Castle Wall degraded \(not enforcing\)/
      );
    });
  });

  // ─── L1 "encrypted at rest" requires live integrity evidence ─────────
  describe("L1 cognitive headline (seam #2 encryption-claim honesty)", () => {
    it("downgrades to 'Encryption configured' when no audit log is wired (no live integrity check)", async () => {
      const snap = await getProtectionSnapshot(
        baseSources({ identityManager: stubIdentityManager(stubIdentity()) })
      );
      expect(snap.layers.l1.state).toBe("full");
      expect(snap.layers.l1.headline).toBe(
        "Encryption configured (no live integrity check)"
      );
    });

    it("asserts 'State encrypted at rest' only when a clean live audit chain confirms integrity", async () => {
      const snap = await getProtectionSnapshot(
        baseSources({
          identityManager: stubIdentityManager(stubIdentity()),
          auditLog: stubAuditLog([], []),
        })
      );
      expect(snap.layers.l1.headline).toBe("State encrypted at rest");
    });
  });

  // ─── Producer-key fix (HIGH): a forged marker-only entry must not arm
  //     green on a key-bearing host ─────────────────────────────────────
  describe("producer-key threading closes the forged-marker arm hole", () => {
    const FRESH_TS = Date.now() - 1000;
    const daemonPriv = ed25519.utils.randomPrivateKey();
    const daemonPubB64 = toBase64url(ed25519.getPublicKey(daemonPriv));

    function toBase64url(bytes: Uint8Array): string {
      let bin = "";
      for (const b of bytes) bin += String.fromCharCode(b);
      return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    function realLog(): AuditLog {
      return new AuditLog(new MemoryStorage(), generateRandomKey());
    }

    /** A forged in-process enforcement entry: marker + claimed producer_signed
     * basis but a garbage signature. Hash-chains cleanly; any co-located module
     * can write it. */
    async function appendForged(log: AuditLog): Promise<void> {
      const seq = 0;
      const canonical = JSON.stringify({
        timestamp: new Date(FRESH_TS).toISOString(),
        layer: "l1",
        operation: "egress_allowed",
        identity_id: "id-1",
        result: "success",
        details: { agent_id: "id-1", dest_host: "ok.example" },
      });
      await log.appendCritical({
        layer: "l1",
        operation: "egress_allowed",
        identity_id: "id-1",
        result: "success",
        timestamp: new Date(FRESH_TS).toISOString(),
        details: {
          seq,
          [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: "AAAA" + "A".repeat(82),
          [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
          [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: canonical,
          [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: FRESH_TS,
          [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]:
            CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
          [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
        },
      });
    }

    /** A genuine daemon-signed enforcement entry. */
    async function appendGenuine(log: AuditLog): Promise<void> {
      const seq = 1;
      const canonical = JSON.stringify({
        timestamp: new Date(FRESH_TS).toISOString(),
        layer: "l1",
        operation: "egress_allowed",
        identity_id: "id-1",
        result: "success",
        details: { agent_id: "id-1", dest_host: "ok.example" },
      });
      const sig = ed25519.sign(
        producerSigningBytes(canonical, FRESH_TS, seq),
        daemonPriv
      );
      await log.appendCritical({
        layer: "l1",
        operation: "egress_allowed",
        identity_id: "id-1",
        result: "success",
        timestamp: new Date(FRESH_TS).toISOString(),
        details: {
          seq,
          [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
          [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
          [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: canonical,
          [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: FRESH_TS,
          [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]:
            CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
          [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
        },
      });
    }

    function keyBearingSources(
      log: AuditLog,
      overrides: Partial<AggregatorSources> = {}
    ): AggregatorSources {
      return baseSources({
        identityManager: stubIdentityManager(stubIdentity()),
        auditLog: log,
        teeAvailable: true,
        reputation: { score: 90, profile_url: "https://verascore.ai/p/x" },
        resolvePinnedProducerKey: () => daemonPubB64,
        ...overrides,
      });
    }

    it("a forged marker-only entry does NOT arm the shield green on a key-bearing host", async () => {
      const log = realLog();
      await appendForged(log);
      const snap = await getProtectionSnapshot(keyBearingSources(log));
      // The forged signature fails re-verification against the pinned key, so the
      // wall is not armed → the hero shield stays amber rather than over-claiming.
      expect(snap.overall.light).toBe("yellow");
      expect(snap.overall.status).toBe("degraded");
    });

    it("a genuine daemon-signed entry DOES arm the shield green on a key-bearing host", async () => {
      const log = realLog();
      await appendGenuine(log);
      const snap = await getProtectionSnapshot(keyBearingSources(log));
      expect(snap.overall.light).toBe("green");
      expect(snap.overall.status).toBe("healthy");
    });

    it("producerKeyExpectedButUnavailable forces amber even with a genuine entry present", async () => {
      // The key is expected (daemon published one) but the reader could not load
      // it. The reader must NOT fall back to the channel basis and render green;
      // it surfaces degraded (amber).
      const log = realLog();
      await appendGenuine(log);
      const snap = await getProtectionSnapshot(
        keyBearingSources(log, {
          resolvePinnedProducerKey: () => null,
          producerKeyExpectedButUnavailable: true,
        })
      );
      expect(snap.overall.light).toBe("yellow");
      expect(snap.overall.status).toBe("degraded");
    });
  });
});
