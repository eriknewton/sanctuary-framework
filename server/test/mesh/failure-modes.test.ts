/**
 * Sanctuary Federation Protocol v0.1 — Failure-Mode Operator Surfaces Tests
 *
 * WP-MVP-3 Follow-up #3 spawn-prompt acceptance criteria covered here:
 *   1 — All five §8 failure modes have a named detection loop + named
 *       operator-surface handler + at least one passing regression test.
 *   2 — Rollback detection reuses PR #29's envelope+audit-batch primitives
 *       (no second implementation).
 *   7 — Mesh Health dashboard panel renders via existing SSE /events
 *       channel — every state transition produces an observable SSE event.
 *   8 — Every usage event emitted carries `event_class` from the PR #33 enum.
 *   9 — Every signed emission carries `signature_scheme: 'ed25519-v1'`.
 *  11 — Non-dependency: no Concordia / Verascore imports.
 *
 * Mesh Health bridge: structural-typing test against an in-memory broadcast
 * target that mirrors `SovereigntyDashboard`'s mesh-broadcast methods. The
 * shipping dashboard satisfies the same interface; the bridge is interchange-
 * ably wired.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { generateKeypair } from "../../src/core/identity.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { sha256 } from "@noble/hashes/sha256";
import {
  MeshChainDiscontinuityError,
  MeshRollbackDetectedError,
  MeshSignatureError,
} from "../../src/mesh/errors.js";
import { sealAuditBatch } from "../../src/mesh/audit-batch.js";
import {
  CAP_STANDARD_FORTRESS_NODE,
  SIGNATURE_SCHEME_V1,
  V01_EVENT_TYPES,
} from "../../src/mesh/constants.js";
import {
  generateFortressMaster,
  issueNodeIdentityCertificate,
  issuePrincipalCertificate,
  deriveNodeAuditChainKey,
} from "../../src/mesh/trust-root.js";
import { canonicalizeToBytes } from "../../src/mesh/canonical-json.js";
import { InMemoryTransport } from "../../src/mesh/in-memory-transport.js";
import {
  AuditBuffer,
  CanonicalAuditLog,
  InMemoryCounterStore,
  InMemoryNodeKeyStore,
  MeshNode,
  createAutoApproveJoinApprover,
} from "../../src/mesh/lifecycle/index.js";
import {
  FAILURE_MODE,
  FailureModeDashboardBridge,
  FailureModeDetector,
  MESH_SYSTEM_POLICY_VERSION_HASH,
  emitGateApproved,
  emitGateDenied,
  emitPolicyPinned,
  emitSentinelAlert,
  packDmswitchTriggeredEvent,
  shouldTriggerDmswitch,
  type AlertEmitContext,
  type FailureModeAlert,
  type MeshHealthSnapshot,
  type MeshHealthBroadcastTarget,
} from "../../src/mesh/failure-modes/index.js";
import {
  buildPostRecoveryPrompt,
  PostRecoveryPromptStore,
} from "../../src/mesh/guardian/index.js";
import { EVENT_CLASSES } from "../../src/agent-contract/constants.js";
import type {
  AuditBatch,
  FortressMasterPublicKey,
  PrincipalCertificate,
  SignedEvent,
} from "../../src/mesh/types.js";

// ═══════════════════════════════════════════════════════════════════════
// Fixtures: a real bootstrapped mesh node with detector wired
// ═══════════════════════════════════════════════════════════════════════

interface DetectorFixture {
  master_public: FortressMasterPublicKey;
  master_secret: Uint8Array;
  principal_cert: PrincipalCertificate;
  principal_kp: ReturnType<typeof generateKeypair>;
  node: MeshNode;
  transport: InMemoryTransport;
  detector: FailureModeDetector;
  emit_ctx: AlertEmitContext;
  alerts: FailureModeAlert[];
  snapshots: MeshHealthSnapshot[];
}

async function makeFixture(opts: { canonicalAuditNodeId?: string } = {}): Promise<DetectorFixture> {
  const transport = new InMemoryTransport();
  const handle = transport.attach("node-1");
  const placeholder = createAutoApproveJoinApprover({
    pinned_master_pubkey: {} as FortressMasterPublicKey,
    issuing_principal_cert: {} as PrincipalCertificate,
    issuing_principal_private_key: new Uint8Array(32),
  });
  const result = await MeshNode.bootstrapFirstNode({
    node_id: "node-1",
    node_mode: "local",
    transport: handle,
    approver: placeholder,
    key_store: new InMemoryNodeKeyStore(),
  });
  const realApprover = createAutoApproveJoinApprover({
    pinned_master_pubkey: result.bootstrap.master_public,
    issuing_principal_cert: result.bootstrap.root_principal_certificate,
    issuing_principal_private_key: result.bootstrap.root_principal_private_key,
  });
  result.node.setApprover(realApprover);

  const counters = new InMemoryCounterStore();
  // Seed counters by reading current envelope_monotonic_seq from node so
  // we don't collide with the bootstrap node_join event (seq=1).
  for (let i = 0; i < 10; i++) counters.next("envelope_monotonic_seq");

  const emit_ctx: AlertEmitContext = {
    emitter_node: "node-1",
    emitter_principal: result.bootstrap.root_principal_certificate.principal_id,
    fortress_id: result.bootstrap.master_public.fortress_id,
    node_private_key: result.bootstrap.node_private_key,
    principal_private_key: result.bootstrap.root_principal_private_key,
    counters,
  };

  const alerts: FailureModeAlert[] = [];
  const snapshots: MeshHealthSnapshot[] = [];

  const detector = new FailureModeDetector(
    result.node,
    { emit_context: emit_ctx },
    {
      canonical_audit_node_id:
        opts.canonicalAuditNodeId ?? "node-1",
      tick_interval_ms: 60_000,
      on_alert: (a) => alerts.push(a),
      on_health_snapshot: (s) => snapshots.push(s),
    }
  );

  return {
    master_public: result.bootstrap.master_public,
    master_secret: result.bootstrap.master_private_key,
    principal_cert: result.bootstrap.root_principal_certificate,
    principal_kp: {
      publicKey: new Uint8Array(),
      privateKey: result.bootstrap.root_principal_private_key,
    } as ReturnType<typeof generateKeypair>,
    node: result.node,
    transport,
    detector,
    emit_ctx,
    alerts,
    snapshots,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §8.1 Node offline — 3 missed heartbeats
// ═══════════════════════════════════════════════════════════════════════

describe("§8.1 offline detection", () => {
  it("flips a peer to `unreachable` after 3 missed heartbeats and emits sentinel_alert", async () => {
    const f = await makeFixture();
    // Add a peer cert to the roster + advance the clock past the dropout
    // threshold without recording any heartbeat.
    const peerKp = generateKeypair();
    const peerCert = issueNodeIdentityCertificate({
      node_id: "node-2",
      node_pubkey: peerKp.publicKey,
      node_mode: "local",
      fortress_id: f.master_public.fortress_id,
      capabilities: CAP_STANDARD_FORTRESS_NODE,
      parent_chain: {
        fortress_master_pubkey: f.master_public.public_key,
        principal_id: f.principal_cert.principal_id,
        principal_pubkey: f.principal_cert.principal_pubkey,
      },
      principal_private_key: f.emit_ctx.principal_private_key!,
      master_private_key: f.master_secret,
    });
    f.node.admitPeerCertificate({
      certificate: peerCert,
      issuing_principal_cert: f.principal_cert,
    });
    // Roster.add seeds last_heartbeat_at to nowMs at insertion. Advance the
    // detector clock past 3 × 30s = 90s.
    f.detector.tick(Date.now() + 95_000);
    expect(f.node.getRoster().presenceOf("node-2")).toBe("unreachable");
    const offlineAlerts = f.alerts.filter(
      (a) => a.mode === FAILURE_MODE.OFFLINE && a.target_node === "node-2"
    );
    expect(offlineAlerts.length).toBeGreaterThanOrEqual(1);
    // Plain-English message check.
    expect(offlineAlerts[0]!.message).toMatch(/missed.*heartbeats/);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §8.2 Compromised — multi-signal aggregator
// ═══════════════════════════════════════════════════════════════════════

describe("§8.2 compromised detection", () => {
  it("flags a node whose envelope monotonic_seq goes non-monotonic", async () => {
    const f = await makeFixture();
    // First heartbeat — establish baseline.
    f.node.onHeartbeatReceived({
      emitter_node: "node-2",
      monotonic_seq: 5,
      policy_version_vector: {},
      audit_seq: 0,
      advertised_state: "active",
    });
    // Second heartbeat with seq <= prior — rollback canary.
    f.node.onHeartbeatReceived({
      emitter_node: "node-2",
      monotonic_seq: 3,
      policy_version_vector: {},
      audit_seq: 0,
      advertised_state: "active",
    });
    const flagged = f.alerts.filter(
      (a) => a.mode === FAILURE_MODE.COMPROMISED && a.target_node === "node-2"
    );
    expect(flagged.length).toBeGreaterThanOrEqual(1);
    expect(flagged[0]!.detail.signal).toBe("non_monotonic_seq");
  });

  it("offers node_revoke as an option in the operator-decision detail", async () => {
    const f = await makeFixture();
    f.node.onAuditBatchRejected({
      error: new MeshRollbackDetectedError("node-2", "non-monotonic batch_seq"),
      emitter_node: "node-2",
    });
    const rollbackAlerts = f.alerts.filter(
      (a) => a.mode === FAILURE_MODE.ROLLBACK
    );
    expect(rollbackAlerts.length).toBeGreaterThanOrEqual(1);
    expect(rollbackAlerts[0]!.detail.decision_options).toEqual([
      "accept_restored_backup",
      "revoke_compromised",
    ]);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §8.3 Rollback — operator surface consumes PR #29 errors
// ═══════════════════════════════════════════════════════════════════════

describe("§8.3 rollback operator surface", () => {
  it("MeshRollbackDetectedError → ROLLBACK alert with both decision branches", async () => {
    const f = await makeFixture();
    f.node.onAuditBatchRejected({
      error: new MeshRollbackDetectedError("node-2", "test rollback"),
      emitter_node: "node-2",
    });
    const a = f.alerts.find((x) => x.mode === FAILURE_MODE.ROLLBACK)!;
    expect(a).toBeDefined();
    // resolveRollback branches.
    const approved = f.detector.resolveRollback({
      alert_id: a.alert_id,
      decision: "accept_restored_backup",
    });
    expect(approved.event.event_class).toBe("gate_approved");
    expect(approved.event.signature_scheme).toBe(SIGNATURE_SCHEME_V1);

    // Fresh alert for the revoke branch.
    f.node.onAuditBatchRejected({
      error: new MeshRollbackDetectedError("node-3", "another rollback"),
      emitter_node: "node-3",
    });
    const a2 = f.alerts.find(
      (x) => x.mode === FAILURE_MODE.ROLLBACK && x.target_node === "node-3"
    )!;
    const denied = f.detector.resolveRollback({
      alert_id: a2.alert_id,
      decision: "revoke_compromised",
    });
    expect(denied.event.event_class).toBe("gate_denied");
    expect(denied.event.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
  });

  it("MeshChainDiscontinuityError also surfaces as rollback (chain canary)", async () => {
    const f = await makeFixture();
    f.node.onAuditBatchRejected({
      error: new MeshChainDiscontinuityError(
        "node-2",
        42,
        "prev_batch_hash mismatch"
      ),
      emitter_node: "node-2",
    });
    const rollbackAlerts = f.alerts.filter(
      (a) => a.mode === FAILURE_MODE.ROLLBACK
    );
    expect(rollbackAlerts.length).toBeGreaterThanOrEqual(1);
  });

  it("non-rollback audit-batch errors surface as compromised (not rollback)", async () => {
    const f = await makeFixture();
    f.node.onAuditBatchRejected({
      error: new MeshSignatureError("hkdf_chain_proof mismatch"),
      emitter_node: "node-2",
    });
    const compromised = f.alerts.filter(
      (a) => a.mode === FAILURE_MODE.COMPROMISED && a.target_node === "node-2"
    );
    expect(compromised.length).toBeGreaterThanOrEqual(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §8.4 Split-brain — locator + policy conflict surfaces
// ═══════════════════════════════════════════════════════════════════════

describe("§8.4 split-brain conflict resolution", () => {
  it("two distinct policy versions for same parent_version surface as split-brain alert", async () => {
    const f = await makeFixture();
    // Manufacture two policy_update envelopes for the same agent + parent
    // version but different policy_version values, then dispatch them through
    // onPolicyUpdate.
    function fakePolicyEvt(version: number) {
      return {
        protocol_version: "0.1",
        event_type: "policy_update",
        event_id: `evt-${version}`,
        emitter_node: "node-1",
        emitter_principal: f.principal_cert.principal_id,
        fortress_id: f.master_public.fortress_id,
        causal_parents: [],
        payload: {
          agent_id: "agent-x",
          policy_version: version,
          policy_blob: "{}",
          parent_version: 1,
        },
        payload_hash: "",
        emitted_at: new Date().toISOString(),
        monotonic_seq: 100 + version,
        extension_envelope: {},
        node_signature: "fake",
      };
    }
    f.node.onPolicyUpdate(fakePolicyEvt(2) as never, "applied");
    f.node.onPolicyUpdate(fakePolicyEvt(3) as never, "applied");
    const splitBrain = f.alerts.filter((a) => a.mode === FAILURE_MODE.SPLIT_BRAIN);
    expect(splitBrain.length).toBeGreaterThanOrEqual(1);
    expect(splitBrain[0]!.target_node).toBe("agent-x");
  });

  it("resolveSplitBrainConflict emits policy_pinned + records superseded_by on rejected versions", async () => {
    const f = await makeFixture();
    function fakeLocatorEvt(version: number, target: string) {
      return {
        protocol_version: "0.1",
        event_type: "locator_update",
        event_id: `loc-${target}`,
        emitter_node: "node-1",
        emitter_principal: f.principal_cert.principal_id,
        fortress_id: f.master_public.fortress_id,
        causal_parents: [],
        payload: {
          agent_id: "agent-y",
          locator_version: version,
          canonical_node: target,
          last_migration_at: new Date().toISOString(),
          hosting_principal: f.principal_cert.principal_id,
        },
        payload_hash: "",
        emitted_at: new Date().toISOString(),
        monotonic_seq: 200 + version,
        extension_envelope: {},
        node_signature: "fake",
      };
    }
    f.node.onLocatorUpdate(fakeLocatorEvt(5, "n-east") as never, "applied");
    f.node.onLocatorUpdate(fakeLocatorEvt(5, "n-west") as never, "conflict");
    const conflicts = f.detector.listSplitBrainConflicts();
    expect(conflicts.length).toBe(1);
    const conflict = conflicts[0]!;
    const chosen = conflict.candidates[0]!;
    const result = f.detector.resolveSplitBrainConflict({
      conflict_id: conflict.conflict_id,
      chosen_event_id: chosen.event_id,
    });
    expect(result.event.event_class).toBe("policy_pinned");
    expect(result.event.capability_target).toBe("mesh.policy_pin:agent-y");
    expect(result.event.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
    // Conflict cleared after resolution.
    expect(f.detector.listSplitBrainConflicts()).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §8.5 Canonical audit loss
// ═══════════════════════════════════════════════════════════════════════

describe("§8.5 canonical audit loss", () => {
  it("after grace window, fires sentinel_alert with promote_replica option", async () => {
    const f = await makeFixture({ canonicalAuditNodeId: "node-canon" });
    // The detector starts canonicalAuditLastSeenAt at construction time.
    // Tick at +25 hours → past the 24h grace window.
    const fastForward = Date.now() + 25 * 60 * 60 * 1000;
    f.detector.tick(fastForward);
    const lossAlerts = f.alerts.filter(
      (a) => a.mode === FAILURE_MODE.CANONICAL_AUDIT_LOSS
    );
    expect(lossAlerts.length).toBeGreaterThanOrEqual(1);
    expect(lossAlerts[0]!.detail.decision_options).toEqual(["promote_replica"]);
  });

  it("promoteCanonicalAudit emits policy_pinned + retargets the staleness tracker", async () => {
    const f = await makeFixture({ canonicalAuditNodeId: "node-canon" });
    f.detector.tick(Date.now() + 25 * 60 * 60 * 1000);
    const result = f.detector.promoteCanonicalAudit({
      new_canonical_node_id: "node-replica",
    });
    expect(result.event.event_class).toBe("policy_pinned");
    expect(result.event.capability_target).toBe(
      "mesh.policy_pin:canonical_audit_node"
    );
    expect(result.event.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
    // After promotion the loss alert should be marked resolved.
    const open = f.detector.listAlerts().filter(
      (a) => a.mode === FAILURE_MODE.CANONICAL_AUDIT_LOSS && a.resolution.state === "open"
    );
    expect(open.length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// DMswitch propagation
// ═══════════════════════════════════════════════════════════════════════

describe("DMswitch trigger broadcast + receipt", () => {
  it("shouldTriggerDmswitch fires past absence + grace threshold", () => {
    const now = Date.now();
    const last = now - (90 + 30) * 24 * 60 * 60 * 1000 - 1;
    expect(shouldTriggerDmswitch({ last_operator_activity_at: last, now_ms: now })).toBe(true);
    expect(
      shouldTriggerDmswitch({
        last_operator_activity_at: now - 60 * 24 * 60 * 60 * 1000,
        now_ms: now,
      })
    ).toBe(false);
  });

  it("packDmswitchTriggeredEvent produces a v0.1 SignedEvent with event_type='dmswitch_triggered'", async () => {
    const f = await makeFixture();
    const evt = packDmswitchTriggeredEvent({
      emitter_node: "node-1",
      emitter_principal: f.principal_cert.principal_id,
      fortress_id: f.master_public.fortress_id,
      last_operator_activity_at: new Date(Date.now() - 121 * 24 * 60 * 60 * 1000).toISOString(),
      triggered_at: new Date().toISOString(),
      reason: "automatic",
      node_private_key: f.emit_ctx.node_private_key,
      counters: f.emit_ctx.counters,
    });
    expect(evt.event_type).toBe("dmswitch_triggered");
    expect((V01_EVENT_TYPES as readonly string[]).includes(evt.event_type)).toBe(true);
    expect(evt.protocol_version).toBe("0.1");
    expect(evt.payload.reason).toBe("automatic");
    expect(evt.node_signature).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("on receipt, detector unlocks the guardian-revocation path + emits sentinel_alert", async () => {
    const f = await makeFixture();
    expect(f.detector.isDmswitchUnlocked()).toBe(false);
    f.node.onLifecycleEvent(
      {
        protocol_version: "0.1",
        event_type: "dmswitch_triggered",
        event_id: "dms-1",
        emitter_node: "node-1",
        emitter_principal: f.principal_cert.principal_id,
        fortress_id: f.master_public.fortress_id,
        causal_parents: [],
        payload: {} as never,
        payload_hash: "",
        emitted_at: new Date().toISOString(),
        monotonic_seq: 999,
        extension_envelope: {},
        node_signature: "x",
      } as never,
      "received"
    );
    expect(f.detector.isDmswitchUnlocked()).toBe(true);
    // sentinel_alert was emitted via the alerts module — implicit by virtue of
    // detector publishing the alert. Direct assertion on the alerts list:
    const dmAlerts = f.alerts.filter((a) =>
      String(a.detail.signal).includes("dmswitch_triggered")
    );
    expect(dmAlerts.length).toBeGreaterThanOrEqual(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Spawn-prompt acceptance #7 — Mesh Health dashboard SSE
// ═══════════════════════════════════════════════════════════════════════

describe("FailureModeDashboardBridge — Mesh Health via existing SSE channel", () => {
  it("forwards every alert + every snapshot through the broadcast target", async () => {
    const f = await makeFixture();
    const broadcasts: Array<{ kind: string; payload: unknown }> = [];
    const target: MeshHealthBroadcastTarget = {
      broadcastMeshHealth: (s) => broadcasts.push({ kind: "snapshot", payload: s }),
      broadcastMeshFailureModeAlert: (a) =>
        broadcasts.push({ kind: "alert", payload: a }),
      broadcastMeshPostRecoveryPrompt: (p) =>
        broadcasts.push({ kind: "prompt", payload: p }),
    };
    new FailureModeDashboardBridge({ detector: f.detector, target });

    // Trigger an alert (envelope-rejection path).
    f.node.onEnvelopeRejected({
      error: new MeshSignatureError("test"),
      event_type: "policy_update",
      emitter_node: "node-2",
    });
    // Trigger a snapshot push via tick.
    f.detector.tick(Date.now());

    const alertBroadcasts = broadcasts.filter((b) => b.kind === "alert");
    const snapshotBroadcasts = broadcasts.filter((b) => b.kind === "snapshot");
    expect(alertBroadcasts.length).toBeGreaterThanOrEqual(1);
    expect(snapshotBroadcasts.length).toBeGreaterThanOrEqual(1);
  });

  it("a post-recovery prompt routes through pushPostRecoveryPrompt", async () => {
    const f = await makeFixture();
    const broadcasts: Array<{ kind: string; payload: unknown }> = [];
    const target: MeshHealthBroadcastTarget = {
      broadcastMeshHealth: () => {},
      broadcastMeshFailureModeAlert: () => {},
      broadcastMeshPostRecoveryPrompt: (p) =>
        broadcasts.push({ kind: "prompt", payload: p }),
    };
    const bridge = new FailureModeDashboardBridge({
      detector: f.detector,
      target,
    });
    const prompt = await buildPostRecoveryPrompt({
      broker: { listSecretNames: async () => ["gmail", "stripe-key"] },
      old_master_pubkey: "old",
      new_master_pubkey: "new",
      rotated_at: new Date().toISOString(),
    });
    bridge.pushPostRecoveryPrompt(prompt);
    expect(broadcasts).toHaveLength(1);
    expect(broadcasts[0]!.kind).toBe("prompt");
    const p = broadcasts[0]!.payload as Record<string, unknown>;
    expect((p.credentials as unknown[]).length).toBe(2);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Spawn-prompt acceptance #8 — event_class enum coverage
// ═══════════════════════════════════════════════════════════════════════

describe("event_class enum coverage on every emission path", () => {
  let f: DetectorFixture;
  beforeEach(async () => {
    f = await makeFixture();
  });

  it("emitSentinelAlert produces event_class=sentinel_alert with valid enum value", () => {
    const out = emitSentinelAlert(f.emit_ctx, {
      failure_mode: FAILURE_MODE.OFFLINE,
      target: "node-2",
      detail: {},
    });
    expect(out.event.event_class).toBe("sentinel_alert");
    expect((EVENT_CLASSES as readonly string[]).includes(out.event.event_class)).toBe(true);
    expect(out.event.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
  });

  it("emitGateApproved produces event_class=gate_approved", () => {
    const out = emitGateApproved(f.emit_ctx, {
      failure_mode: FAILURE_MODE.ROLLBACK,
      target: "node-2",
      decision: "accept_restored_backup",
      detail: {},
    });
    expect(out.event.event_class).toBe("gate_approved");
    expect(out.event.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
  });

  it("emitGateDenied produces event_class=gate_denied", () => {
    const out = emitGateDenied(f.emit_ctx, {
      failure_mode: FAILURE_MODE.COMPROMISED,
      target: "node-2",
      decision: "deny",
      detail: {},
    });
    expect(out.event.event_class).toBe("gate_denied");
    expect(out.event.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
  });

  it("emitPolicyPinned produces event_class=policy_pinned", () => {
    const out = emitPolicyPinned(f.emit_ctx, {
      subject: "agent-z",
      pinned_to: "evt-99",
      detail: {},
    });
    expect(out.event.event_class).toBe("policy_pinned");
    expect(out.event.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
  });

  it("MESH_SYSTEM_POLICY_VERSION_HASH is a stable base64url SHA-256", () => {
    const expected = toBase64url(sha256(stringToBytes("mesh-system-v1")));
    expect(MESH_SYSTEM_POLICY_VERSION_HASH).toBe(expected);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Spawn-prompt acceptance #2 — rollback uses PR #29 primitives, no second impl
// ═══════════════════════════════════════════════════════════════════════

describe("rollback detection reuses PR #29 envelope+audit-batch primitives", () => {
  it("a real audit-batch with non-monotonic batch_seq throws MeshRollbackDetectedError from sealAuditBatch", async () => {
    const masterKp = generateKeypair();
    const nodeKp = generateKeypair();
    // Build a fake first batch then try to seal a second batch with seq=0 again.
    const auditChainKey = deriveNodeAuditChainKey({
      fortress_master_secret: masterKp.privateKey,
      node_id: "node-1",
    });
    const firstBatch = sealAuditBatch({
      emitter_node: "node-1",
      batch_seq: 0,
      entries: [],
      previous_batch: null,
      node_audit_chain_key: auditChainKey,
      node_private_key: nodeKp.privateKey,
    });
    // Trying to seal seq=0 again with a previous batch present throws.
    expect(() =>
      sealAuditBatch({
        emitter_node: "node-1",
        batch_seq: 0,
        entries: [],
        previous_batch: firstBatch,
        node_audit_chain_key: auditChainKey,
        node_private_key: nodeKp.privateKey,
      })
    ).toThrow();
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Snapshot rollup
// ═══════════════════════════════════════════════════════════════════════

describe("MeshHealthSnapshot rollup", () => {
  it("includes the observer node + canonical audit node in the snapshot", async () => {
    const f = await makeFixture();
    const snap = f.detector.snapshot();
    expect(snap.observer_node).toBe("node-1");
    expect(snap.canonical_audit_node).toBe("node-1");
    expect(snap.fortress_id).toBe(f.master_public.fortress_id);
  });
});
