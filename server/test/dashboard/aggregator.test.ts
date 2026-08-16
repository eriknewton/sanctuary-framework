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
  CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SUBJECT_BINDING_MACOS_AUDIT_TOKEN,
} from "../../src/castle-wall/constants.js";
import { protectionSubjectForUid } from "../../src/castle-wall/subject-binding.js";
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
    // The aggregator runs the Castle Wall badge read inside `runEagerReads` (the
    // #717 eager scope). On the real AuditLog this opens an AsyncLocalStorage
    // scope and runs `fn`; for this in-memory stub (whose `query` is already a
    // constant return) it is a transparent pass-through that simply invokes `fn`.
    runEagerReads: <T>(fn: () => Promise<T>): Promise<T> => fn(),
    // F2 BLOCKER-1 (round 3): the aggregator now routes its integrity gate
    // through the shared audit-chain verdict. This stub fortress is not migrated
    // (sealed region `not_present`), so the verdict is `findings` iff routine
    // findings exist, else `verified`.
    getAuditChainVerdict: async () => ({
      status: integrity_findings.length > 0 ? "findings" : "verified",
      routine_finding_count: integrity_findings.length,
      sealed_region: { status: "not_present" },
    }),
    append: () => undefined,
    size: entries.length,
  } as unknown as AuditLog;
}

// A fresh Castle Wall enforcement-evidence audit entry (carries the provenance
// marker the posture reader requires); arms the wall so the overall light can
// legitimately go green.
const FORTRESS = "fortress:test";

function subjectForUid(uid: number): string {
  const subject = protectionSubjectForUid(FORTRESS, uid);
  if (subject === null) throw new Error("test subject could not be derived");
  return subject;
}

function auditTokenForRuid(uid: number): string {
  const vals = [
    0xffffffff,
    uid,
    uid,
    uid,
    uid,
    0x00000269,
    0x000186ae,
    0x00000566,
  ];
  return vals
    .map((value) => {
      const bytes = new Uint8Array(4);
      new DataView(bytes.buffer).setUint32(0, value >>> 0, true);
      return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
    })
    .join("");
}

const CLAIM_UID = 601;
const CLAIM_TOKEN = auditTokenForRuid(CLAIM_UID);
const CLAIM_SUBJECT = subjectForUid(CLAIM_UID);
const UNDETERMINED_AVAILABILITY = {
  status: "undetermined" as const,
  reason: "availability_not_queried",
  observed_at: null,
  freshness_window_ms: 30_000,
  active_connection_count: 0,
};

function cwArmEntry(ageMs = 60_000, identityId = CLAIM_SUBJECT): AuditEntry {
  return {
    timestamp: new Date(Date.now() - ageMs).toISOString(),
    layer: "l1",
    operation: "egress_allowed",
    identity_id: identityId,
    result: "success",
    details: {
      agent_id: CLAIM_TOKEN,
      cw_source: "castle_wall_audit_consumer",
    },
  } as unknown as AuditEntry;
}

function baseSources(overrides: Partial<AggregatorSources> = {}): AggregatorSources {
  const sources: AggregatorSources = {
    mode: "co-located",
    server_version: "0.9.0-test",
    platform: "linux",
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
      resolveProtectionClaimSubject: () => CLAIM_SUBJECT,
    });
    const snap = await getProtectionSnapshot(sources);
    expect(snap.layers.l2.state).toBe("full");
    expect(snap.overall.light).toBe("green");
    expect(snap.overall.status).toBe("healthy");
    expect(snap.overall.headline).toBe("All layers full, Castle Wall enforcing");
  });

  it("injected undetermined v3 availability prevents linux-shaped legacy evidence from going green", async () => {
    const sources = baseSources({
      identityManager: stubIdentityManager(stubIdentity()),
      auditLog: stubAuditLog([cwArmEntry()]),
      teeAvailable: true,
      reputation: { score: 95, profile_url: "https://verascore.ai/p/xyz" },
      resolveProtectionClaimSubject: () => CLAIM_SUBJECT,
      resolveEnforcementAvailability: () => UNDETERMINED_AVAILABILITY,
    });
    const snap = await getProtectionSnapshot(sources);
    expect(snap.overall.light).toBe("yellow");
    expect(snap.overall.status).toBe("degraded");
    expect(snap.overall.headline).toMatch(/Castle Wall enforcement not confirmed/);
  });

  it("legacy dashboard hero stays non-green when Castle Wall evidence is fresh but subject-bound elsewhere", async () => {
    const sources = baseSources({
      identityManager: stubIdentityManager(stubIdentity()),
      auditLog: stubAuditLog([cwArmEntry(60_000, subjectForUid(602))]),
      teeAvailable: true,
      reputation: { score: 95, profile_url: "https://verascore.ai/p/xyz" },
      resolveProtectionClaimSubject: () => subjectForUid(601),
    });
    const snap = await getProtectionSnapshot(sources);
    expect(snap.overall.light).toBe("yellow");
    expect(snap.overall.status).toBe("degraded");
    expect(snap.overall.headline).toMatch(/Castle Wall enforcement not confirmed/);
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

    it("does NOT count reconcile-tagged reputation_record re-emissions (LD6 fix-round-2 F4 / R2-1): one credential retried N times stays vc_count 1", async () => {
      // The tagged entry is the in-lock guard-hit re-audit an identical-args
      // retry appends (see the `reconcile` field docs in bridge/tools.ts /
      // reputation-store.ts) -- one durable record, many tagged entries.
      // Without the filter this counted 3.
      const snap = await getProtectionSnapshot(baseSources({
        identityManager: stubIdentityManager(stubIdentity()),
        auditLog: stubAuditLog([
          { timestamp: today.toISOString(), layer: "l4", operation: "reputation_record", identity_id: "id-1", result: "success", details: { attestation_id: "att-1" } },
          { timestamp: today.toISOString(), layer: "l4", operation: "reputation_record", identity_id: "id-1", result: "success", details: { attestation_id: "att-1", reconcile: true } },
          { timestamp: today.toISOString(), layer: "l4", operation: "reputation_record", identity_id: "id-1", result: "success", details: { attestation_id: "att-1", reconcile: true } },
        ]),
      }));
      expect(snap.layers.l3.vc_count).toBe(1);
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
        resolveProtectionClaimSubject: () => CLAIM_SUBJECT,
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
      expect(snap.layers.l1.memory_attest_ready).toBe(true);
    });

    it("F2 HIGH-1: verified_suffix_only earns amber, NEVER the green 'State encrypted at rest' / memory_attest_ready", async () => {
      // An armed box: the operator uid cannot read the root-owned sealed region,
      // so the shared verdict is `verified_suffix_only` (untampered but NOT
      // fully verified). This is the false-green the round-4 gate caught: the
      // dashboard used to render "State encrypted at rest" + memory_attest_ready
      // over it. It must now render an honest amber caveat instead.
      const suffixOnlyLog = {
        query: async () => ({ entries: [], total: 0, integrity_findings: [] }),
        runEagerReads: <T>(fn: () => Promise<T>): Promise<T> => fn(),
        getAuditChainVerdict: async () => ({
          status: "verified_suffix_only",
          routine_finding_count: 0,
          sealed_region: { status: "unreadable", note: "operator-uid EACCES" },
        }),
        append: () => undefined,
        size: 0,
      } as unknown as AuditLog;

      const snap = await getProtectionSnapshot(
        baseSources({
          identityManager: stubIdentityManager(stubIdentity()),
          auditLog: suffixOnlyLog,
        })
      );
      expect(snap.layers.l1.headline).toBe(
        "State encrypted; sealed history not re-verifiable at this privilege (run as root for a full verify)"
      );
      expect(snap.layers.l1.headline).not.toBe("State encrypted at rest");
      expect(snap.layers.l1.memory_attest_ready).toBe(false);
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
        identity_id: CLAIM_TOKEN,
        result: "success",
        details: { agent_id: CLAIM_TOKEN, dest_host: "ok.example" },
      });
      await log.appendCritical({
        layer: "l1",
        operation: "egress_allowed",
        identity_id: CLAIM_SUBJECT,
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
          [CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY]:
            CASTLE_WALL_PRODUCER_SUBJECT_BINDING_MACOS_AUDIT_TOKEN,
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
        identity_id: CLAIM_TOKEN,
        result: "success",
        details: { agent_id: CLAIM_TOKEN, dest_host: "ok.example" },
      });
      const sig = ed25519.sign(
        producerSigningBytes(canonical, FRESH_TS, seq),
        daemonPriv
      );
      await log.appendCritical({
        layer: "l1",
        operation: "egress_allowed",
        identity_id: CLAIM_SUBJECT,
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
          [CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY]:
            CASTLE_WALL_PRODUCER_SUBJECT_BINDING_MACOS_AUDIT_TOKEN,
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
        resolveProtectionClaimSubject: () => CLAIM_SUBJECT,
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

  // Seam #8: L2 sandbox_status and L1 memory_attest_ready must reflect
  // evidence, not presence.
  describe("L2 sandbox_status honesty (seam #8)", () => {
    const loadedPolicy = {
      version: 1,
      tier1_always_approve: [],
      tier3_always_allow: [],
      tier2_anomaly: {},
      approval_channel: { type: "stderr", timeout_seconds: 30 },
    } as unknown as AggregatorSources["policy"];

    // A genuine gate adjudication: only `gate_*` operations count as
    // enforcement evidence.
    function l2AuditEntry(
      ageMs = 60_000,
      operation = "gate_allow:state_read"
    ): AuditEntry {
      return {
        timestamp: new Date(Date.now() - ageMs).toISOString(),
        layer: "l2",
        operation,
        identity_id: "id-1",
        result: "success",
      } as unknown as AuditEntry;
    }

    it("reads 'No Principal Policy loaded' when no policy is configured", async () => {
      const snap = await getProtectionSnapshot(baseSources());
      expect(snap.layers.l2.sandbox_status).toBe("No Principal Policy loaded");
    });

    it("reads 'configured' when a policy is loaded but no recent adjudication", async () => {
      const snap = await getProtectionSnapshot(
        baseSources({ policy: loadedPolicy, auditLog: stubAuditLog([]) })
      );
      expect(snap.layers.l2.sandbox_status).toBe(
        "Principal Policy gate configured (no recent adjudication)"
      );
    });

    it("reads 'active' only with recent L2 gate adjudication evidence", async () => {
      const snap = await getProtectionSnapshot(
        baseSources({
          policy: loadedPolicy,
          auditLog: stubAuditLog([l2AuditEntry()]),
        })
      );
      expect(snap.layers.l2.sandbox_status).toBe("Principal Policy gate active");
    });

    it("does NOT read 'active' from a recent principal_policy_view (a policy read, not an adjudication)", async () => {
      const snap = await getProtectionSnapshot(
        baseSources({
          policy: loadedPolicy,
          auditLog: stubAuditLog([
            l2AuditEntry(60_000, "principal_policy_view"),
          ]),
        })
      );
      expect(snap.layers.l2.sandbox_status).toBe(
        "Principal Policy gate configured (no recent adjudication)"
      );
    });

    it("does NOT read 'active' from a recent custody/rollback L2 envelope write", async () => {
      const snap = await getProtectionSnapshot(
        baseSources({
          policy: loadedPolicy,
          auditLog: stubAuditLog([
            l2AuditEntry(60_000, "custody_rollback_suspected"),
          ]),
        })
      );
      expect(snap.layers.l2.sandbox_status).toBe(
        "Principal Policy gate configured (no recent adjudication)"
      );
    });

    it("does NOT read 'active' from a long-stale L2 entry", async () => {
      const snap = await getProtectionSnapshot(
        baseSources({
          policy: loadedPolicy,
          auditLog: stubAuditLog([l2AuditEntry(60 * 60 * 1000)]),
        })
      );
      expect(snap.layers.l2.sandbox_status).toBe(
        "Principal Policy gate configured (no recent adjudication)"
      );
    });

    it("memory_attest_ready requires live integrity evidence, not bare identity", async () => {
      // Identity present but no audit log: cannot anchor an attestation.
      const noChain = await getProtectionSnapshot(
        baseSources({ identityManager: stubIdentityManager(stubIdentity()) })
      );
      expect(noChain.layers.l1.memory_attest_ready).toBe(false);

      // Identity + clean live chain: ready.
      const withChain = await getProtectionSnapshot(
        baseSources({
          identityManager: stubIdentityManager(stubIdentity()),
          auditLog: stubAuditLog([]),
        })
      );
      expect(withChain.layers.l1.memory_attest_ready).toBe(true);
    });
  });
});
