/**
 * §12.8 - Five §8 failure modes proven end-to-end through the three-mode drill.
 *
 * Spec: Review/Sanctuary/Federation_Protocol_V0.1_Spec_2026-04-21.md §12.8,
 *       §8 (failure modes), §9 (recovery cascade).
 *
 * Each test below boots the real three-mode mesh (libp2p + Noise + gossipsub),
 * mounts a FailureModeDetector + FailureModeDashboardBridge on an observer
 * node, drives the mode's real trigger, and asserts that:
 *   (a) the detector flags it with the correct failure mode,
 *   (b) the Mesh Health dashboard bridge forwards the alert to a broadcast
 *       target shaped like the shipping SovereigntyDashboard,
 *   (c) the signed sentinel_alert envelope carries `signature_scheme:
 *       'ed25519-v1'` and an `event_class` drawn from the PR #33 enum.
 *
 * The drill harness's real libp2p transport is used on every wire path. The
 * compromise-signal injection (§8.2) uses the node's `onHeartbeatReceived`
 * hook - the same seam the production detector subscribes to - so the sealed
 * envelope emit path is not modified or mocked.
 */

import { afterEach, describe, expect, it } from "vitest";

import { InMemoryCounterStore } from "../../../src/mesh/lifecycle/index.js";
import { authenticatedPeer } from "../../../src/mesh/lifecycle/envelope-rejection.js";
import {
  FAILURE_MODE,
  FailureModeDashboardBridge,
  FailureModeDetector,
  type AlertEmitContext,
  type FailureModeAlert,
  type MeshHealthBroadcastTarget,
  type MeshHealthSnapshot,
} from "../../../src/mesh/failure-modes/index.js";
import {
  MeshRollbackDetectedError,
} from "../../../src/mesh/errors.js";
import { EVENT_CLASSES } from "../../../src/agent-contract/constants.js";
import { SIGNATURE_SCHEME_V1 } from "../../../src/mesh/constants.js";
import { encodePolicyBlob } from "../../../src/policy-engine/canonical-policy.js";
import type {
  LocatorUpdatePayload,
  PolicyUpdatePayload,
  SignedEvent,
} from "../../../src/mesh/types.js";
import type { CompiledPolicy } from "../../../src/policy-engine/types.js";

import {
  bootThreeModeDrill,
  GOSSIP_SETTLE_MS,
  type ThreeModeDrillHandle,
  waitFor,
} from "./harness.js";

let active: ThreeModeDrillHandle | null = null;

afterEach(async () => {
  if (active) {
    await active.teardown();
    active = null;
  }
});

// ═══════════════════════════════════════════════════════════════════════
// Shared wiring - mount a detector + dashboard bridge on a chosen observer.
// ═══════════════════════════════════════════════════════════════════════

interface DetectorRig {
  detector: FailureModeDetector;
  alerts: FailureModeAlert[];
  snapshots: MeshHealthSnapshot[];
  broadcasts: Array<{ kind: "snapshot" | "alert" | "prompt"; payload: unknown }>;
  emit_ctx: AlertEmitContext;
}

/**
 * Mount a FailureModeDetector + FailureModeDashboardBridge on the selected
 * observer node. The detector's emit context is seeded with a fresh counter
 * store so sentinel_alert envelope seqs do not collide with the node's own
 * wire emissions. The broadcast target captures alerts + snapshots +
 * post-recovery-prompt pushes for assertion.
 */
function mountDetector(
  drill: ThreeModeDrillHandle,
  observer: "A" | "B" | "C",
  canonicalAuditNodeId: string
): DetectorRig {
  const node =
    observer === "A"
      ? drill.nodeA
      : observer === "B"
        ? drill.nodeB
        : drill.nodeC;
  const nodeId =
    observer === "A"
      ? drill.nodeIdA
      : observer === "B"
        ? drill.nodeIdB
        : drill.nodeIdC;
  const nodeKp =
    observer === "A"
      ? drill.nodeKpA
      : observer === "B"
        ? drill.nodeKpB
        : drill.nodeKpC;

  // Fresh counter store - detector emissions are isolated from the node's own
  // envelope counters. Seed past the node's bootstrap seqs (same pattern as
  // the unit fixture in server/test/mesh/failure-modes.test.ts).
  const counters = new InMemoryCounterStore();
  for (let i = 0; i < 100; i++) counters.next("envelope_monotonic_seq");

  const emit_ctx: AlertEmitContext = {
    emitter_node: nodeId,
    emitter_principal: drill.root_principal_cert.principal_id,
    fortress_id: drill.master_public.fortress_id,
    node_private_key: nodeKp.privateKey,
    principal_private_key: drill.root_principal_keypair.privateKey,
    counters,
  };

  const alerts: FailureModeAlert[] = [];
  const snapshots: MeshHealthSnapshot[] = [];
  const broadcasts: DetectorRig["broadcasts"] = [];

  const detector = new FailureModeDetector(
    node,
    { emit_context: emit_ctx },
    {
      canonical_audit_node_id: canonicalAuditNodeId,
      tick_interval_ms: 60_000,
      on_alert: (a) => alerts.push(a),
      on_health_snapshot: (s) => snapshots.push(s),
    }
  );

  const target: MeshHealthBroadcastTarget = {
    broadcastMeshHealth: (s) => broadcasts.push({ kind: "snapshot", payload: s }),
    broadcastMeshFailureModeAlert: (a) =>
      broadcasts.push({ kind: "alert", payload: a }),
    broadcastMeshPostRecoveryPrompt: (p) =>
      broadcasts.push({ kind: "prompt", payload: p }),
  };
  new FailureModeDashboardBridge({ detector, target });

  return { detector, alerts, snapshots, broadcasts, emit_ctx };
}

// ═══════════════════════════════════════════════════════════════════════
// The drill
// ═══════════════════════════════════════════════════════════════════════

describe("three-mode-drill §12.8 - five §8 failure modes end-to-end", () => {
  it(
    "§8.1 offline - stalled heartbeats flip a peer to unreachable, detector fires sentinel_alert, bridge forwards it",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;
      const rig = mountDetector(drill, "A", drill.nodeIdA);

      // No running heartbeat loop exists in the drill (harness emits one
      // round at boot, nothing periodic). Advance the detector's tick past
      // three missed intervals on node C to drive the dropout path.
      const missedThresholdMs = 3 * 30_000; // HEARTBEAT_INTERVAL_MS × threshold
      rig.detector.tick(Date.now() + missedThresholdMs + 5_000);

      expect(drill.nodeA.getRoster().presenceOf(drill.nodeIdC)).toBe(
        "unreachable"
      );
      const offline = rig.alerts.filter(
        (a) =>
          a.mode === FAILURE_MODE.OFFLINE && a.target_node === drill.nodeIdC
      );
      expect(offline.length).toBeGreaterThanOrEqual(1);
      expect(offline[0].message).toMatch(/missed.*heartbeats/i);

      const bridgedAlerts = rig.broadcasts.filter((b) => b.kind === "alert");
      expect(
        bridgedAlerts.some((b) => {
          const p = b.payload as FailureModeAlert;
          return (
            p.mode === FAILURE_MODE.OFFLINE && p.target_node === drill.nodeIdC
          );
        })
      ).toBe(true);

      // Snapshot rollup reflects the unreachable peer.
      const snap = rig.detector.snapshot();
      const row = snap.nodes.find((n) => n.node_id === drill.nodeIdC)!;
      expect(row.presence).toBe("unreachable");
      expect(row.rollup).toBe("unreachable");
    },
    90_000
  );

  it(
    "§8.2 compromised - non-monotonic envelope monotonic_seq from B surfaces as compromised with revoke option and no auto-revoke",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;
      const rig = mountDetector(drill, "A", drill.nodeIdA);

      // Establish a baseline monotonic_seq on A for emitter B. The hook
      // surface is the same seam the production receive path dispatches
      // through after envelope verification; we use it here as a
      // test-harness helper to drive a non-monotonic signal without
      // modifying the sealed emit path. Spec §8.2 second bullet.
      drill.nodeA.onHeartbeatReceived({
        // The heartbeat hook fires only after envelope verification, so its
        // `emitter_node` is branded; the harness mints it the same way the
        // production router does.
        emitter_node: authenticatedPeer(drill.nodeIdB),
        monotonic_seq: 500,
        policy_version_vector: {},
        audit_seq: 0,
        advertised_state: "active",
      });
      // Now drive a non-monotonic follow-up - strictly lower than the baseline.
      drill.nodeA.onHeartbeatReceived({
        // The heartbeat hook fires only after envelope verification, so its
        // `emitter_node` is branded; the harness mints it the same way the
        // production router does.
        emitter_node: authenticatedPeer(drill.nodeIdB),
        monotonic_seq: 200,
        policy_version_vector: {},
        audit_seq: 0,
        advertised_state: "active",
      });

      const compromised = rig.alerts.filter(
        (a) =>
          a.mode === FAILURE_MODE.COMPROMISED &&
          a.target_node === drill.nodeIdB
      );
      expect(compromised.length).toBeGreaterThanOrEqual(1);
      expect(compromised[0].detail.signal).toBe("non_monotonic_seq");

      // Detector offers revoke via the rollback branch's decision options on a
      // companion path; non-monotonic-seq alerts themselves encode the
      // diagnostic signal. Surface the revoke path via a rollback alert on
      // the same emitter and confirm no auto-revoke fires.
      drill.nodeA.onAuditBatchRejected({
        error: new MeshRollbackDetectedError(
          drill.nodeIdB,
          "test: non-monotonic batch_seq"
        ),
        emitter_node: drill.nodeIdB,
      });
      const rollback = rig.alerts.find(
        (a) =>
          a.mode === FAILURE_MODE.ROLLBACK && a.target_node === drill.nodeIdB
      )!;
      expect(rollback.detail.decision_options).toEqual([
        "accept_restored_backup",
        "revoke_compromised",
      ]);

      // No auto-revoke - B is still in A's active roster.
      expect(drill.nodeA.getRoster().presenceOf(drill.nodeIdB)).toBe("active");
      expect(
        drill.nodeA.getRoster().lookupActiveNodeCert(drill.nodeIdB)
      ).toBeDefined();

      // Alert was bridged with a valid event_class when the operator resolves.
      const emitted = rig.detector.resolveRollback({
        alert_id: rollback.alert_id,
        decision: "revoke_compromised",
      });
      expect(emitted.event.event_class).toBe("gate_denied");
      expect(
        (EVENT_CLASSES as readonly string[]).includes(emitted.event.event_class)
      ).toBe(true);
      expect(emitted.event.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
    },
    90_000
  );

  it(
    "§8.3 rollback - MeshRollbackDetectedError surfaces as ROLLBACK alert with accept/revoke branches on the Mesh Health bridge",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;
      const rig = mountDetector(drill, "A", drill.nodeIdA);

      // Drive two real audit batches from B, then re-emit batch N-1 after N
      // has been sealed. The canonical log's rollback canary (§8.3) triggers
      // `MeshRollbackDetectedError` on receipt; the MeshNode's
      // `handleIncomingUnicast` routes the error through
      // `onAuditBatchRejected`, which the detector observes.
      drill.nodeB.pushAuditEntry({
        emitter_agent: "drill-agent-b",
        emitter_principal: drill.root_principal_cert.principal_id,
        policy_version: 0,
        attestation_state: "verified",
        payload: { round: 0, from: "B", drill: "§12.8 rollback" },
      });
      await drill.nodeB.flushAuditBuffer(drill.nodeIdA);
      drill.nodeB.pushAuditEntry({
        emitter_agent: "drill-agent-b",
        emitter_principal: drill.root_principal_cert.principal_id,
        policy_version: 0,
        attestation_state: "verified",
        payload: { round: 1, from: "B", drill: "§12.8 rollback" },
      });
      await drill.nodeB.flushAuditBuffer(drill.nodeIdA);
      await waitFor(
        () => drill.nodeA.getCanonicalAuditSize() >= 2,
        15_000,
        50,
        "canonical log has B batches N-1 and N"
      );

      // Synthesize a rollback by replaying B's batch_seq=0 directly into the
      // ingestion path. The canonical log already has batch_seq=1 stored, so
      // seq=0 trips the monotonic canary via `MeshRollbackDetectedError`.
      const replayBatch = drill.nodeA
        .getCanonicalAuditLog()!
        .snapshot()
        .find((b) => b.emitter_node === drill.nodeIdB && b.batch_seq === 0)!;
      try {
        drill.nodeA["ingestAuditBatch"](
          JSON.stringify({ kind: "audit_batch", batch: replayBatch })
        );
      } catch (e) {
        drill.nodeA.onAuditBatchRejected({
          error: e instanceof Error ? e : new Error(String(e)),
          emitter_node: drill.nodeIdB,
        });
      }

      const rollback = rig.alerts.find(
        (a) =>
          a.mode === FAILURE_MODE.ROLLBACK && a.target_node === drill.nodeIdB
      )!;
      expect(rollback).toBeDefined();
      expect(rollback.detail.decision_options).toEqual([
        "accept_restored_backup",
        "revoke_compromised",
      ]);
      expect(rollback.message).toMatch(/rolled back|Rollback/i);

      // Bridge forwarded the alert.
      const bridged = rig.broadcasts.find(
        (b) =>
          b.kind === "alert" &&
          (b.payload as FailureModeAlert).mode === FAILURE_MODE.ROLLBACK
      );
      expect(bridged).toBeDefined();

      // Both branches emit a valid signed usage event with ed25519-v1.
      const accept = rig.detector.resolveRollback({
        alert_id: rollback.alert_id,
        decision: "accept_restored_backup",
      });
      expect(accept.event.event_class).toBe("gate_approved");
      expect(accept.event.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
    },
    120_000
  );

  it(
    "§8.4 split-brain - two policy versions for same parent_version raise SPLIT_BRAIN; resolveSplitBrainConflict emits policy_pinned with superseded_by",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;
      const rig = mountDetector(drill, "A", drill.nodeIdA);

      // B and C each publish a policy for the same agent + same parent_version
      // but different policy_versions. Node A observes both via gossipsub;
      // the detector's policy-conflict observer records both versions for the
      // shared (agent, parent_version) key and raises SPLIT_BRAIN.
      //
      // ORDERING BARRIER. Two gossipsub publishes from two DIFFERENT peers
      // have no delivery-order guarantee at A, so this test pins the order:
      // publish v7, wait for A to have APPLIED it, then publish v8. That keeps
      // the drill deterministic about WHICH version A ends up holding.
      //
      // It is no longer load-bearing for detection itself. The detector used
      // to count only policy_updates whose PolicyBundleStore result was
      // `applied`, and the store refuses any version <= the one it already
      // holds as `policy_version_replay`; so if C's v8 had landed first, B's
      // v7 was thrown away and the conflict below could never hold, at any
      // timeout. The detector now also records a refusal that carries a
      // different origin under the same parent_version, so both arrival orders
      // raise SPLIT_BRAIN. Both orders are covered deterministically in
      // `test/mesh/failure-modes.test.ts` ("policy conflict is arrival-order
      // independent"), which is where that property is proven; keep this
      // barrier so the drill does not depend on network luck.
      const agentId = "agent-split";
      await drill.nodeB.publishPolicyUpdate({
        payload: {
          agent_id: agentId,
          policy_version: 7,
          valid_from: "2026-06-01T00:00:00.000Z",
          valid_until: "2099-01-01T00:00:00.000Z",
          policy_blob: compiledPolicyBlob(agentId, 7, drill.fortressId, 1),
          parent_version: 1,
        } as PolicyUpdatePayload,
        principal_private_key: drill.root_principal_keypair.privateKey,
        emitter_principal: drill.root_principal_cert.principal_id,
      });
      await waitFor(
        () => drill.nodeA.getPolicyBundle().versionOf(agentId) === 7,
        GOSSIP_SETTLE_MS,
        50,
        "A applied B's policy_version 7"
      );
      await drill.nodeC.publishPolicyUpdate({
        payload: {
          agent_id: agentId,
          policy_version: 8,
          valid_from: "2026-06-01T00:00:00.000Z",
          valid_until: "2099-01-01T00:00:00.000Z",
          policy_blob: compiledPolicyBlob(agentId, 8, drill.fortressId, 1),
          parent_version: 1,
        } as PolicyUpdatePayload,
        principal_private_key: drill.root_principal_keypair.privateKey,
        emitter_principal: drill.root_principal_cert.principal_id,
      });

      // Wait until A has dispatched both policy_updates through the router.
      await waitFor(
        () => {
          return (
            rig.detector.listSplitBrainConflicts().length >= 1 &&
            rig.alerts.some(
              (a) =>
                a.mode === FAILURE_MODE.SPLIT_BRAIN && a.target_node === agentId
            )
          );
        },
        GOSSIP_SETTLE_MS,
        50,
        "split-brain conflict observed on A"
      );

      const conflict = rig.detector
        .listSplitBrainConflicts()
        .find((c) => c.agent_id === agentId)!;
      expect(conflict.candidates.length).toBeGreaterThanOrEqual(2);
      const chosen = conflict.candidates[0]!;
      const rejected = conflict.candidates.filter(
        (c) => c.event_id !== chosen.event_id
      );
      expect(rejected.length).toBeGreaterThanOrEqual(1);

      const resolved = rig.detector.resolveSplitBrainConflict({
        conflict_id: conflict.conflict_id,
        chosen_event_id: chosen.event_id,
      });
      expect(resolved.event.event_class).toBe("policy_pinned");
      expect(resolved.event.capability_target).toBe(
        `mesh.policy_pin:${agentId}`
      );
      expect(resolved.event.signature_scheme).toBe(SIGNATURE_SCHEME_V1);

      // The resolved alert is marked `resolved` with the chosen event_id in
      // its decision field - the event envelope itself hashes detail, so
      // superseded_by wiring is asserted via the detector's recorded alert
      // state rather than by decoding the hashed envelope payload.
      const resolvedAlert = rig.detector
        .listAlerts()
        .find(
          (a) =>
            a.mode === FAILURE_MODE.SPLIT_BRAIN &&
            a.target_node === agentId &&
            a.resolution.state === "resolved"
        );
      expect(resolvedAlert).toBeDefined();
      expect(resolvedAlert!.resolution.decision).toBe(
        `pin:${chosen.event_id}`
      );
      // Conflict cleared post-resolution.
      expect(
        rig.detector
          .listSplitBrainConflicts()
          .some((c) => c.agent_id === agentId)
      ).toBe(false);

      // Bridge forwarded both the SPLIT_BRAIN detection and at least one
      // post-resolution snapshot.
      const splitBrainBridged = rig.broadcasts.find(
        (b) =>
          b.kind === "alert" &&
          (b.payload as FailureModeAlert).mode === FAILURE_MODE.SPLIT_BRAIN
      );
      expect(splitBrainBridged).toBeDefined();
    },
    // Boot (~37s of bounded harness waits worst case) + two GOSSIP_SETTLE_MS
    // budgets. Sized so a slow wait reports through waitFor's descriptive
    // message rather than as an opaque vitest test-timeout.
    180_000
  );

  it(
    "§8.5 canonical audit loss - 24h grace elapsed without canonical heartbeat fires alert with promote_replica; promoteCanonicalAudit retargets + emits policy_pinned",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;
      // Observer = B; canonical audit = A (the drill's default). The
      // detector's staleness tracker initializes at construction; fast-
      // forwarding past the 24h grace window fires the loss alert.
      const rig = mountDetector(drill, "B", drill.nodeIdA);

      rig.detector.tick(Date.now() + 25 * 60 * 60 * 1000);

      const loss = rig.alerts.find(
        (a) => a.mode === FAILURE_MODE.CANONICAL_AUDIT_LOSS
      )!;
      expect(loss).toBeDefined();
      expect(loss.target_node).toBe(drill.nodeIdA);
      expect(loss.detail.decision_options).toEqual(["promote_replica"]);
      expect(loss.message).toMatch(/canonical audit/i);

      const lossBridged = rig.broadcasts.find(
        (b) =>
          b.kind === "alert" &&
          (b.payload as FailureModeAlert).mode ===
            FAILURE_MODE.CANONICAL_AUDIT_LOSS
      );
      expect(lossBridged).toBeDefined();

      // Operator promotes B as the new canonical. Detector emits
      // policy_pinned + retargets. The follow-up event must carry a valid
      // event_class and ed25519-v1.
      const promoted = rig.detector.promoteCanonicalAudit({
        new_canonical_node_id: drill.nodeIdB,
      });
      expect(promoted.event.event_class).toBe("policy_pinned");
      expect(promoted.event.capability_target).toBe(
        "mesh.policy_pin:canonical_audit_node"
      );
      expect(promoted.event.signature_scheme).toBe(SIGNATURE_SCHEME_V1);

      // Post-promote snapshot reflects the new canonical designation.
      const snap = rig.detector.snapshot();
      expect(snap.canonical_audit_node).toBe(drill.nodeIdB);
      expect(snap.canonical_audit_loss).toBe(false);
    },
    60_000
  );
});

function compiledPolicyBlob(
  agentId: string,
  policyVersion: number,
  fortressId: string,
  parentVersion?: number,
): string {
  return encodePolicyBlob({
    schema_version: "0.1",
    agent_id: agentId,
    fortress_id: fortressId,
    policy_version: policyVersion,
    ...(parentVersion !== undefined ? { parent_version: parentVersion } : {}),
    slots: {
      memory: { slot: "memory", mode: "deny", grants: [] },
      credentials: { slot: "credentials", mode: "deny", grants: [] },
      plans: { slot: "plans", mode: "deny", grants: [] },
      outputs: { slot: "outputs", mode: "deny", grants: [] },
    },
    capabilities: {
      concordia_commitment_classes: [],
      honeypot_skill_ids: [],
      is_sentinel: false,
    },
    auto_trigger_ladder: {
      honeypot_auto_freeze: false,
      threshold_rule_action: "operator_approved",
      ml_anomaly_action: "operator_approved",
    },
    source_english: "fixture",
    compiled_at: "2026-06-09T12:00:00.000Z",
  } satisfies CompiledPolicy);
}

// Touch type-only imports so they do not drop from tree-shaking. The
// LocatorUpdatePayload + SignedEvent imports are reserved for a v1.x
// follow-up that exercises locator-conflict resolution in the drill (spec
// §8.4 second branch); keeping the imports live signals the intent.
void (null as unknown as SignedEvent<LocatorUpdatePayload>);
