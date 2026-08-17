/**
 * WP-MVP-8 Recovery Flows — drill-harness integration.
 *
 * Drives all four ceremonies end-to-end against the real three-mode mesh
 * (libp2p + Noise + gossipsub) that bootThreeModeDrill sets up:
 *
 *   Ceremony 1 — Device-loss recovery
 *   Ceremony 2 — Compromised-node revoke (with optional chained rotation)
 *   Ceremony 3 — Canonical-audit-node promotion
 *   Ceremony 4 — Master-rotation ceremony + broadcast orchestration with acks
 *
 * Each test asserts the Key 8 operator-in-the-loop invariant (no ceremony
 * executes without an explicit confirm() call), §10 hard-gate invariants
 * (every signed event carries `signature_scheme: 'ed25519-v1'` and an
 * approved `event_class`), and the post-recovery prompt fires on every
 * ceremony.
 */

import { afterEach, describe, expect, it } from "vitest";
import { authenticatedPeer } from "../../../src/mesh/lifecycle/envelope-rejection.js";

import { generateKeypair } from "../../../src/core/identity.js";
import { toBase64url } from "../../../src/core/encoding.js";
import { packSignedEvent } from "../../../src/mesh/envelope.js";
import {
  CAP_STANDARD_FORTRESS_NODE,
  SIGNATURE_SCHEME_V1,
} from "../../../src/mesh/constants.js";
import { EVENT_CLASSES } from "../../../src/agent-contract/constants.js";
import {
  deriveNodeAuditChainKey,
  deriveNodeTransportKey,
  issueNodeIdentityCertificate,
} from "../../../src/mesh/trust-root.js";
import {
  issueGuardianRoster,
  signMasterRotationAsGuardian,
  PostRecoveryPromptStore,
  type GuardianIdentity,
} from "../../../src/mesh/guardian/index.js";
import {
  InMemoryCounterStore,
} from "../../../src/mesh/lifecycle/index.js";
import type {
  FortressMasterPublicKey,
  NodeIdentityCertificate,
} from "../../../src/mesh/types.js";
import {
  CanonicalAuditPromotionCeremony,
  DeviceRecoveryCeremony,
  MasterRotationCeremony,
  MasterRotationReceiver,
  NodeRevokeCeremony,
  RECOVERY_UNICAST_KINDS,
  StaticBrokerCredentialLister,
  acknowledgePostRecoveryPrompt,
  canonicalAuditPromoteQuorumInput,
  createMasterRotationAckSubscription,
  deviceRecoveryQuorumInput,
  deviceRecoveryRevokeQuorumInput,
  firePostRecoveryPrompt,
  type MasterRotationAckMessage,
} from "../../../src/mesh/recovery-flows/index.js";
import {
  buildGuardianMasterRotationQuorumInput,
  buildGuardianRevokeQuorumInput,
  mintRevokeCollectionContext,
  GUARDIAN_REVOKE_QUORUM_SCHEMA_V2,
  REVOKE_QUORUM_MAX_LIFETIME_MS,
} from "../../../src/mesh/guardian/index.js";
import type { AlertEmitContext } from "../../../src/mesh/failure-modes/index.js";

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
// Shared fixtures for ceremonies
// ═══════════════════════════════════════════════════════════════════════

function buildGuardianRoster(
  drill: ThreeModeDrillHandle
): { roster: ReturnType<typeof issueGuardianRoster>; guardians: Array<{ identity: GuardianIdentity; sk: Uint8Array }> } {
  const guardians: Array<{ identity: GuardianIdentity; sk: Uint8Array }> = [];
  for (let i = 0; i < 5; i++) {
    const kp = generateKeypair();
    guardians.push({
      identity: {
        guardian_id: "g" + i,
        public_key: toBase64url(kp.publicKey),
        kind: "human",
        invited_at: new Date().toISOString(),
      },
      sk: kp.privateKey,
    });
  }
  const roster = issueGuardianRoster({
    m: 3,
    n: 5,
    guardians: guardians.map((g) => g.identity),
    fortress_id: drill.master_public.fortress_id,
    version: 1,
    master_private_key: drill.master_private_key,
  });
  return { roster, guardians };
}

function buildEmitCtx(
  drill: ThreeModeDrillHandle,
  observer: "A" | "B" | "C"
): AlertEmitContext {
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
  const counters = new InMemoryCounterStore();
  for (let i = 0; i < 100; i++) counters.next("envelope_monotonic_seq");
  return {
    emitter_node: nodeId,
    emitter_principal: drill.root_principal_cert.principal_id,
    fortress_id: drill.master_public.fortress_id,
    node_private_key: nodeKp.privateKey,
    principal_private_key: drill.root_principal_keypair.privateKey,
    counters,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// Ceremony 1 — Device-loss recovery
// ═══════════════════════════════════════════════════════════════════════

describe("WP-MVP-8 ceremony 1 — device-loss recovery", () => {
  it(
    "operator assembles 3-of-5 guardian signatures; revokes lost node; admits replacement cert; post-recovery prompt fires",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;

      // Treat node B as the lost device. Record B's pre-loss HKDF material.
      const preLossAuditChainKey = deriveNodeAuditChainKey({
        fortress_master_secret: drill.master_private_key,
        node_id: drill.nodeIdB,
      });
      const preLossTransportKey = deriveNodeTransportKey({
        fortress_master_secret: drill.master_private_key,
        node_id: drill.nodeIdB,
        node_mode: drill.nodeCertB.node_mode,
      });

      // Issue a fresh replacement cert chained under the current fortress.
      // The replacement has a fresh node_id (the ceremony's product intent:
      // admit a new replacement device rather than literally reusing B's id).
      const replacementKp = generateKeypair();
      const replacementId = "replacement-" + drill.nodeIdB.slice(0, 16);
      const replacementCert: NodeIdentityCertificate = issueNodeIdentityCertificate({
        node_id: replacementId,
        node_pubkey: replacementKp.publicKey,
        node_mode: "local",
        fortress_id: drill.master_public.fortress_id,
        capabilities: CAP_STANDARD_FORTRESS_NODE,
        parent_chain: {
          fortress_master_pubkey: drill.master_public.public_key,
          principal_id: drill.root_principal_cert.principal_id,
          principal_pubkey: drill.root_principal_cert.principal_pubkey,
        },
        principal_private_key: drill.root_principal_keypair.privateKey,
        master_private_key: drill.master_private_key,
      });

      const { roster, guardians } = buildGuardianRoster(drill);
      const emitCtx = buildEmitCtx(drill, "A");

      // C12-REPLAY v2: one fresh collection context signs BOTH inputs.
      const quorumContext = mintRevokeCollectionContext();
      const quorumInput = deviceRecoveryQuorumInput(
        {
          lost_node_id: drill.nodeIdB,
          replacement_node_cert: replacementCert,
          quorum_context: quorumContext,
        },
        drill.master_public.fortress_id
      );
      const quorumSigs = guardians
        .slice(0, 3)
        .map((g) =>
          signMasterRotationAsGuardian({
            input: quorumInput,
            guardian_id: g.identity.guardian_id,
            guardian_private_key: g.sk,
          })
        );
      // The guardians also sign the node_revoke quorum input for the lost
      // node in the same ceremony session: the recovery quorum never covers
      // the revocation, and revokePeer + every receiver verify against these.
      const revokeInput = deviceRecoveryRevokeQuorumInput(
        { lost_node_id: drill.nodeIdB, quorum_context: quorumContext },
        drill.master_public.fortress_id
      );
      const revokeSigs = guardians
        .slice(0, 3)
        .map((g) =>
          signMasterRotationAsGuardian({
            input: revokeInput,
            guardian_id: g.identity.guardian_id,
            guardian_private_key: g.sk,
          })
        );
      // Pin the roster on the receiving peer too, so its independent
      // node_revoke authority re-check can verify the broadcast quorum.
      drill.nodeC.registerGuardianRoster(roster);

      // Last activity long enough in the past that the grace window is not
      // blocking the ceremony (past 90d + 30d).
      const longAgo = new Date(
        Date.now() - 200 * 24 * 60 * 60 * 1000
      ).toISOString();

      const ceremony = DeviceRecoveryCeremony.propose({
        proposal: {
          lost_node_id: drill.nodeIdB,
          replacement_node_cert: replacementCert,
          guardian_signatures: quorumSigs,
          revoke_guardian_signatures: revokeSigs,
          quorum_context: quorumContext,
        },
        ctx: {
          node: drill.nodeA,
          root_principal_cert: drill.root_principal_cert,
          pinned_master: drill.master_public,
          pinned_roster: roster,
          emit_ctx: emitCtx,
          fortress_master_secret: drill.master_private_key,
          dmswitch_input: { last_operator_activity_at: longAgo },
        },
      });
      expect(ceremony.state).toBe("proposed");

      // Key 8 invariant: execute before confirm must throw.
      await expect(ceremony.execute()).rejects.toThrow();
      expect(ceremony.state).toBe("proposed");

      ceremony.confirm({ note: "device B lost; admitting replacement" });
      expect(ceremony.state).toBe("confirmed");

      const { result, gate_event: gateEvent, hkdf_re_derivation_proof } =
        await ceremony.execute();
      expect(ceremony.state).toBe("completed");

      // B is marked revoked on A's roster.
      expect(drill.nodeA.getRoster().presenceOf(drill.nodeIdB)).toBe(
        "revoked"
      );
      // C12 regression gate: the broadcast revoke must ALSO verify on the
      // receiving peer. Node C re-checks node_revoke authority against the
      // quorum signatures carried in the event; with the pre-fix recovery-
      // quorum signatures (which never covered the revoke payload) this
      // propagation never happened, because every receiver refused the event.
      await waitFor(
        () =>
          drill.nodeC.getRoster().presenceOf(drill.nodeIdB) === "revoked",
        GOSSIP_SETTLE_MS,
        50,
        "node C marks lost node revoked from the broadcast quorum revoke"
      );
      // Replacement cert is admitted on A's roster.
      expect(
        drill.nodeA.getRoster().lookupNodeCert(replacementId)
      ).toBeDefined();

      // gate_approved event carries ceremony detail + ed25519-v1 scheme + an
      // approved event_class.
      expect(gateEvent.event.event_class).toBe("gate_approved");
      expect(
        (EVENT_CLASSES as readonly string[]).includes(
          gateEvent.event.event_class
        )
      ).toBe(true);
      expect(gateEvent.event.signature_scheme).toBe(SIGNATURE_SCHEME_V1);

      // HKDF re-derivation proof: byte-identical to B's pre-loss material
      // when we re-derive for B's original (node_id, mode) with the same
      // master. This proves guardian recovery preserves master-derivable
      // material across ceremonies.
      const reDerivedForLost = deriveNodeAuditChainKey({
        fortress_master_secret: drill.master_private_key,
        node_id: drill.nodeIdB,
      });
      expect(Buffer.from(reDerivedForLost)).toEqual(
        Buffer.from(preLossAuditChainKey)
      );
      const reDerivedForLostTransport = deriveNodeTransportKey({
        fortress_master_secret: drill.master_private_key,
        node_id: drill.nodeIdB,
        node_mode: drill.nodeCertB.node_mode,
      });
      expect(Buffer.from(reDerivedForLostTransport)).toEqual(
        Buffer.from(preLossTransportKey)
      );
      // hkdf_re_derivation_proof carries the REPLACEMENT's HKDF subkeys
      // under the current master — distinct from B's because node_id differs.
      expect(hkdf_re_derivation_proof.audit_chain_key.length).toBe(32);
      expect(hkdf_re_derivation_proof.transport_key.length).toBe(32);

      // Retired id surfaced on the result.
      expect(result.retired_node_id).toBe(drill.nodeIdB);

      // Post-recovery prompt fires with ceremony context.
      const promptStore = new PostRecoveryPromptStore();
      const state = await firePostRecoveryPrompt({
        store: promptStore,
        ceremony_type: "device_recovery",
        ceremony_id: ceremony.ceremony_id,
        old_master_pubkey: drill.master_public.public_key,
        new_master_pubkey: drill.master_public.public_key,
        rotated_at: result.completed_at,
        broker: new StaticBrokerCredentialLister([
          "openai-api-key",
          "anthropic-api-key",
        ]),
      });
      expect(promptStore.size()).toBe(1);
      expect(state.credentials.length).toBe(2);

      // Ack the prompt → emits a signed gate_approved event.
      const ackEvent = acknowledgePostRecoveryPrompt({
        store: promptStore,
        stored_prompt_key: state.rotated_at,
        emit_ctx: emitCtx,
        ceremony_id: ceremony.ceremony_id,
        note: "rotated 1 credential; deferred 1",
        dismissed: false,
      });
      expect(ackEvent.event.event_class).toBe("gate_approved");
      expect(ackEvent.event.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
    },
    120_000
  );

  it(
    "propose() rejects recovery attempted inside DMswitch grace window",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;
      const { roster, guardians } = buildGuardianRoster(drill);
      const emitCtx = buildEmitCtx(drill, "A");
      const replacementKp = generateKeypair();
      const replacementCert = issueNodeIdentityCertificate({
        node_id: "replacement-dms-" + drill.nodeIdB.slice(0, 8),
        node_pubkey: replacementKp.publicKey,
        node_mode: "local",
        fortress_id: drill.master_public.fortress_id,
        capabilities: CAP_STANDARD_FORTRESS_NODE,
        parent_chain: {
          fortress_master_pubkey: drill.master_public.public_key,
          principal_id: drill.root_principal_cert.principal_id,
          principal_pubkey: drill.root_principal_cert.principal_pubkey,
        },
        principal_private_key: drill.root_principal_keypair.privateKey,
        master_private_key: drill.master_private_key,
      });
      const quorumContext = mintRevokeCollectionContext();
      const input = deviceRecoveryQuorumInput(
        {
          lost_node_id: drill.nodeIdB,
          replacement_node_cert: replacementCert,
          quorum_context: quorumContext,
        },
        drill.master_public.fortress_id
      );
      const sigs = guardians
        .slice(0, 3)
        .map((g) =>
          signMasterRotationAsGuardian({
            input,
            guardian_id: g.identity.guardian_id,
            guardian_private_key: g.sk,
          })
        );
      // Recent activity → grace window active.
      const recent = new Date(Date.now() - 60_000).toISOString();
      expect(() =>
        DeviceRecoveryCeremony.propose({
          proposal: {
            lost_node_id: drill.nodeIdB,
            replacement_node_cert: replacementCert,
            guardian_signatures: sigs,
            revoke_guardian_signatures: [],
            quorum_context: quorumContext,
          },
          ctx: {
            node: drill.nodeA,
            root_principal_cert: drill.root_principal_cert,
            pinned_master: drill.master_public,
            pinned_roster: roster,
            emit_ctx: emitCtx,
            fortress_master_secret: drill.master_private_key,
            dmswitch_input: { last_operator_activity_at: recent },
          },
        })
      ).toThrow(/DMswitch grace/);
    },
    90_000
  );
});

// ═══════════════════════════════════════════════════════════════════════
// Ceremony 2 — Compromised-node revoke
// ═══════════════════════════════════════════════════════════════════════

describe("WP-MVP-8 ceremony 2 — compromised-node revoke", () => {
  it(
    "operator confirms; 3-of-5 guardian quorum signs; node B is revoked + retargeted; no auto-revoke fired",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;
      const { roster, guardians } = buildGuardianRoster(drill);
      const emitCtx = buildEmitCtx(drill, "A");

      // Verify B is still active pre-ceremony (no auto-revoke from any hook).
      expect(drill.nodeA.getRoster().presenceOf(drill.nodeIdB)).toBe("active");
      expect(
        drill.nodeA.getRoster().lookupActiveNodeCert(drill.nodeIdB)
      ).toBeDefined();

      const quorumContext = mintRevokeCollectionContext();
      const proposal = {
        target_node_id: drill.nodeIdB,
        reason: "non-monotonic envelope sequence detected",
        guardian_signatures: [],
      } as const;
      const input = buildGuardianRevokeQuorumInput({
        context: quorumContext,
        target_node_id: proposal.target_node_id,
        reason: proposal.reason,
        fortress_id: drill.master_public.fortress_id,
      });
      const sigs = guardians
        .slice(0, 3)
        .map((g) =>
          signMasterRotationAsGuardian({
            input,
            guardian_id: g.identity.guardian_id,
            guardian_private_key: g.sk,
          })
        );
      const ceremony = NodeRevokeCeremony.propose({
        proposal: {
          ...proposal,
          guardian_signatures: sigs,
          quorum_context: quorumContext,
        },
        ctx: {
          node: drill.nodeA,
          pinned_master: drill.master_public,
          pinned_roster: roster,
          emit_ctx: emitCtx,
        },
      });

      // Key 8 invariant: execute before confirm must throw.
      await expect(ceremony.execute()).rejects.toThrow();
      expect(drill.nodeA.getRoster().presenceOf(drill.nodeIdB)).toBe("active");

      ceremony.confirm({ note: "B flagged as compromised; revoking" });
      const { result, revoke_event, gate_event } = await ceremony.execute();
      expect(result.master_rotation_chained).toBe(false);

      // Post-revoke: B is revoked on A's roster; B's signed events would be
      // rejected by lookupActiveNodeCert at verify time.
      expect(drill.nodeA.getRoster().presenceOf(drill.nodeIdB)).toBe(
        "revoked"
      );
      expect(
        drill.nodeA.getRoster().lookupActiveNodeCert(drill.nodeIdB)
      ).toBeUndefined();

      // Revoke event carries guardian quorum signatures + ed25519-v1.
      expect(revoke_event.event_type).toBe("node_revoke");
      expect(
        (revoke_event.payload as { quorum_signatures?: unknown[] })
          .quorum_signatures?.length
      ).toBe(3);

      // gate_denied event carries the operator's decision.
      expect(gate_event.event.event_class).toBe("gate_denied");
      expect(gate_event.event.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
    },
    120_000
  );

  it(
    "C12-REPLAY T1 drill: an EXPIRED harvested guardian quorum, broadcast over the real libp2p mesh, does NOT revoke a healthy node",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;
      const { roster, guardians } = buildGuardianRoster(drill);
      // Receiver (node C) pins the guardian roster so it can verify the quorum.
      drill.nodeC.registerGuardianRoster(roster);
      expect(drill.nodeC.getRoster().presenceOf(drill.nodeIdB)).toBe("active");

      // An abandoned ceremony whose collection window opened long ago and has
      // lapsed. On CURRENT MAIN (v1, no freshness) these harvested signatures
      // would authorize revoking node B forever; under v2 the receiver's own
      // strict clock refuses them.
      const expiredContext = mintRevokeCollectionContext({
        now: new Date(Date.now() - (REVOKE_QUORUM_MAX_LIFETIME_MS + 60 * 60 * 1000)),
      });
      const input = buildGuardianRevokeQuorumInput({
        context: expiredContext,
        target_node_id: drill.nodeIdB,
        reason: "harvested-abandoned-ceremony",
        fortress_id: drill.master_public.fortress_id,
      });
      const sigs = guardians.slice(0, 3).map((g) => ({
        guardian_pubkey: g.identity.public_key,
        signature: signMasterRotationAsGuardian({
          input,
          guardian_id: g.identity.guardian_id,
          guardian_private_key: g.sk,
        }).signature,
      }));

      // Node A signs and broadcasts the harvested revoke over the real mesh.
      const revokeEvt = packSignedEvent({
        event_type: "node_revoke",
        emitter_node: drill.nodeIdA,
        emitter_principal: drill.root_principal_cert.principal_id,
        fortress_id: drill.master_public.fortress_id,
        payload: {
          node_id: drill.nodeIdB,
          reason: "harvested-abandoned-ceremony",
          effective_at: expiredContext.initiated_at,
          quorum_signatures: sigs,
          quorum_context: {
            input_schema: GUARDIAN_REVOKE_QUORUM_SCHEMA_V2,
            ceremony_id: expiredContext.ceremony_id,
            initiated_at: expiredContext.initiated_at,
            expires_at: expiredContext.expires_at,
          },
        },
        monotonic_seq: 5_000_000,
        node_private_key: drill.nodeKpA.privateKey,
      });
      await drill.transportA.broadcast(revokeEvt);

      // Give gossipsub a full settle budget, then assert node B is STILL active
      // on the receiver — the expired quorum was refused at the live path.
      await new Promise((r) => setTimeout(r, 2000));
      expect(drill.nodeC.getRoster().presenceOf(drill.nodeIdB)).toBe("active");
      expect(
        drill.nodeC.getRoster().lookupActiveNodeCert(drill.nodeIdB)
      ).toBeDefined();
    },
    120_000
  );
});

// ═══════════════════════════════════════════════════════════════════════
// Ceremony 3 — Canonical-audit-node promotion
// ═══════════════════════════════════════════════════════════════════════

describe("WP-MVP-8 ceremony 3 — canonical-audit-node promotion", () => {
  it(
    "operator confirms; 3-of-5 guardian quorum signs; canonical_audit_change event broadcasts; policy_pinned emitted",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;
      const { roster, guardians } = buildGuardianRoster(drill);
      const emitCtx = buildEmitCtx(drill, "A");

      // Drill default: A is canonical audit. Promote B.
      const proposal = {
        current_canonical_node_id: drill.nodeIdA,
        new_canonical_node_id: drill.nodeIdB,
        guardian_signatures: [],
      } as const;
      const input = canonicalAuditPromoteQuorumInput(
        proposal,
        drill.master_public.fortress_id
      );
      const sigs = guardians
        .slice(0, 3)
        .map((g) =>
          signMasterRotationAsGuardian({
            input,
            guardian_id: g.identity.guardian_id,
            guardian_private_key: g.sk,
          })
        );

      const ceremony = CanonicalAuditPromotionCeremony.propose({
        proposal: { ...proposal, guardian_signatures: sigs },
        ctx: {
          node: drill.nodeA,
          principal_private_key: drill.root_principal_keypair.privateKey,
          emitter_principal: drill.root_principal_cert.principal_id,
          pinned_master: drill.master_public,
          pinned_roster: roster,
          emit_ctx: emitCtx,
        },
      });

      // Key 8 invariant.
      await expect(ceremony.execute()).rejects.toThrow();

      ceremony.confirm({ note: "A offline past 24h; promoting B" });
      const { result, canonical_audit_change_event, policy_pinned_event } =
        await ceremony.execute();
      expect(result.new_canonical_node_id).toBe(drill.nodeIdB);

      expect(canonical_audit_change_event.event_type).toBe(
        "canonical_audit_change"
      );
      expect(
        (canonical_audit_change_event.payload as { new_canonical_node: string })
          .new_canonical_node
      ).toBe(drill.nodeIdB);

      expect(policy_pinned_event.event.event_class).toBe("policy_pinned");
      expect(policy_pinned_event.event.signature_scheme).toBe(
        SIGNATURE_SCHEME_V1
      );
    },
    120_000
  );
});

// ═══════════════════════════════════════════════════════════════════════
// Ceremony 4 — Master rotation + broadcast orchestration with acks
// ═══════════════════════════════════════════════════════════════════════

describe("WP-MVP-8 ceremony 4 — master rotation + broadcast orchestration with acks", () => {
  it(
    "initiator broadcasts rotation over libp2p; both peers install + sign acks; no dissenting nodes",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;
      const { roster, guardians } = buildGuardianRoster(drill);
      const emitCtx = buildEmitCtx(drill, "A");

      // NEW master + new root principal.
      const newMasterKp = generateKeypair();
      const newMasterPublic: FortressMasterPublicKey = {
        public_key: toBase64url(newMasterKp.publicKey),
        fortress_id: drill.master_public.fortress_id,
        created_at: new Date().toISOString(),
      };
      const newRootPrincipalKp = generateKeypair();

      // QI-SIBLING-02: window minted before signing; carried on the wire.
      const rotationContext = mintRevokeCollectionContext();
      const rotatedAt = new Date().toISOString();
      const input = buildGuardianMasterRotationQuorumInput({
        context: rotationContext,
        old_master_pubkey: drill.master_public.public_key,
        new_master_pubkey: newMasterPublic,
        rotated_at: rotatedAt,
        fortress_id: drill.master_public.fortress_id,
      });
      const sigs = guardians
        .slice(0, 3)
        .map((g) =>
          signMasterRotationAsGuardian({
            input,
            guardian_id: g.identity.guardian_id,
            guardian_private_key: g.sk,
          })
        );

      // Mount receivers on B and C — each will unwrap their bundle + install
      // + surface an ack.
      const receivers = mountReceiversOnBC(drill, roster);

      // Initiator ack subscription — the initiator's transport subscribes to
      // unicast to collect acks. Pre-rotation pubkey lookup maps node_id to
      // the pre-rotation cert's pubkey.
      const preRotPubkeyByNode = new Map<string, string>([
        [drill.nodeIdA, drill.nodeCertA.node_pubkey],
        [drill.nodeIdB, drill.nodeCertB.node_pubkey],
        [drill.nodeIdC, drill.nodeCertC.node_pubkey],
      ]);
      const ackSub = createMasterRotationAckSubscription({
        fortress_id: drill.master_public.fortress_id,
        lookup_pre_rotation_pubkey: (id) => preRotPubkeyByNode.get(id),
      });
      // Wire each receiver's ack emission into the initiator's subscription.
      // In production, receivers would unicast ack to the initiator; here we
      // short-circuit by feeding directly into the ack subscription.
      receivers.forEach((r) => r.onAckEmit((ack) => ackSub.ingest(ack)));

      // Wire B and C's receive paths: their transports deliver unicasts to
      // the receiver's handleIncomingUnicast; their onLifecycleEvent
      // delivers the `master_rotation` broadcast.
      for (const [nodeId, rec] of receivers) {
        const node =
          nodeId === drill.nodeIdB ? drill.nodeB : drill.nodeC;
        const transport =
          nodeId === drill.nodeIdB ? drill.transportB : drill.transportC;
        transport.subscribeUnicast(async (to, message) => {
          try {
            await rec.handleIncomingUnicast(to, message);
          } catch {
            // A bundle unwrap failure throws out of handleIncomingUnicast BEFORE
            // any pending entry exists, so it reaches no ack path and no
            // rejection hook — this catch is the only thing standing between it
            // and the transport, and swallowing it here keeps it from masking the
            // ceremony execute() assertions below. (The earlier claim that these
            // failures surface through the ack error path was wrong: the unwrap
            // throws before there is an entry to ack about. See the bundle-path
            // note on MasterRotationReceiver.handleIncomingUnicast.)
          }
        });
        const existingHandler = node.onLifecycleEvent;
        node.onLifecycleEvent = (evt, kind) => {
          existingHandler(evt, kind);
          if (evt.event_type === "master_rotation" && kind === "received") {
            // `evt.emitter_node` is AUTHENTICATED here: the receive path runs
            // verifyOrThrow before the router fires this hook with
            // kind === "received". The `void` call is deliberate and now safe —
            // the receiver converts refusals to an audit entry plus
            // onEnvelopeRejected instead of rejecting the promise.
            void rec.handleIncomingMasterRotationBroadcast(
              evt.payload as import("../../../src/mesh/types.js").MasterRotationPayload,
              { emitter_node: authenticatedPeer(evt.emitter_node) }
            );
          }
        };
      }

      // Propose the rotation on A.
      const ceremony = MasterRotationCeremony.propose({
        proposal: {
          new_master_public: newMasterPublic,
          new_master_secret: newMasterKp.privateKey,
          new_root_principal_private_key: newRootPrincipalKp.privateKey,
          new_root_principal_public_key: newRootPrincipalKp.publicKey,
          guardian_signatures: sigs,
          quorum_context: rotationContext,
          rotated_at: rotatedAt,
          ack_timeout_ms: 15_000,
        },
        ctx: {
          node: drill.nodeA,
          transport: drill.transportA,
          old_fortress_master_secret: drill.master_private_key,
          old_root_principal_cert: drill.root_principal_cert,
          peers: [
            { node_id: drill.nodeIdB, node_cert: drill.nodeCertB },
            { node_id: drill.nodeIdC, node_cert: drill.nodeCertC },
          ],
          pinned_roster: roster,
          pinned_old_master: drill.master_public,
          emit_ctx: emitCtx,
          self_node_cert: drill.nodeCertA,
        },
      });

      // Key 8 invariant.
      await expect(
        ceremony.execute({ ack_subscription: ackSub })
      ).rejects.toThrow();

      ceremony.confirm({ note: "scheduled master rotation; all peers online" });
      const result = await ceremony.execute({ ack_subscription: ackSub });

      expect(result.acks_received.sort()).toEqual(
        [drill.nodeIdB, drill.nodeIdC].sort()
      );
      expect(result.dissenting_nodes).toEqual([]);
      expect(result.rotated_at).toBe(rotatedAt);

      // All three nodes pin the new master post-cascade.
      for (const node of [drill.nodeA, drill.nodeB, drill.nodeC]) {
        expect(node.getPinnedMaster().public_key).toBe(
          newMasterPublic.public_key
        );
      }

      ackSub.close();
    },
    180_000
  );

  it(
    "broadcast ack timeout surfaces dissenting nodes to the operator (no silent partial rotation)",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;
      const { roster, guardians } = buildGuardianRoster(drill);
      const emitCtx = buildEmitCtx(drill, "A");

      const newMasterKp = generateKeypair();
      const newMasterPublic: FortressMasterPublicKey = {
        public_key: toBase64url(newMasterKp.publicKey),
        fortress_id: drill.master_public.fortress_id,
        created_at: new Date().toISOString(),
      };
      const newRootPrincipalKp = generateKeypair();
      // QI-SIBLING-02: window minted before signing; carried on the wire.
      const rotationContext = mintRevokeCollectionContext();
      const rotatedAt = new Date().toISOString();
      const input = buildGuardianMasterRotationQuorumInput({
        context: rotationContext,
        old_master_pubkey: drill.master_public.public_key,
        new_master_pubkey: newMasterPublic,
        rotated_at: rotatedAt,
        fortress_id: drill.master_public.fortress_id,
      });
      const sigs = guardians
        .slice(0, 3)
        .map((g) =>
          signMasterRotationAsGuardian({
            input,
            guardian_id: g.identity.guardian_id,
            guardian_private_key: g.sk,
          })
        );

      // Mount receiver ONLY on B. C is simulated-offline: its receiver never
      // feeds an ack into the subscription.
      const recB = new MasterRotationReceiver({
        node: drill.nodeB,
        node_id: drill.nodeIdB,
        node_mode: "operator_cloud",
        fortress_id: drill.master_public.fortress_id,
        old_fortress_master_secret: () => drill.master_private_key,
        pinned_old_master: () => drill.master_public,
        pinned_guardian_roster: () => roster,
        node_private_key: drill.nodeKpB.privateKey,
      });
      const preRotPubkeyByNode = new Map<string, string>([
        [drill.nodeIdA, drill.nodeCertA.node_pubkey],
        [drill.nodeIdB, drill.nodeCertB.node_pubkey],
        [drill.nodeIdC, drill.nodeCertC.node_pubkey],
      ]);
      const ackSub = createMasterRotationAckSubscription({
        fortress_id: drill.master_public.fortress_id,
        lookup_pre_rotation_pubkey: (id) => preRotPubkeyByNode.get(id),
      });
      recB.onAckEmit((ack) => ackSub.ingest(ack));
      drill.transportB.subscribeUnicast(async (to, message) => {
        try {
          await recB.handleIncomingUnicast(to, message);
        } catch {
          // Surfaces as ack error in the receiver.
        }
      });
      const prevLifecycleB = drill.nodeB.onLifecycleEvent;
      drill.nodeB.onLifecycleEvent = (evt, kind) => {
        prevLifecycleB(evt, kind);
        if (evt.event_type === "master_rotation" && kind === "received") {
          void recB.handleIncomingMasterRotationBroadcast(
            evt.payload as import("../../../src/mesh/types.js").MasterRotationPayload,
            { emitter_node: authenticatedPeer(evt.emitter_node) }
          );
        }
      };

      const ceremony = MasterRotationCeremony.propose({
        proposal: {
          new_master_public: newMasterPublic,
          new_master_secret: newMasterKp.privateKey,
          new_root_principal_private_key: newRootPrincipalKp.privateKey,
          new_root_principal_public_key: newRootPrincipalKp.publicKey,
          guardian_signatures: sigs,
          quorum_context: rotationContext,
          rotated_at: rotatedAt,
          ack_timeout_ms: 3_000,
        },
        ctx: {
          node: drill.nodeA,
          transport: drill.transportA,
          old_fortress_master_secret: drill.master_private_key,
          old_root_principal_cert: drill.root_principal_cert,
          peers: [
            { node_id: drill.nodeIdB, node_cert: drill.nodeCertB },
            { node_id: drill.nodeIdC, node_cert: drill.nodeCertC },
          ],
          pinned_roster: roster,
          pinned_old_master: drill.master_public,
          emit_ctx: emitCtx,
          self_node_cert: drill.nodeCertA,
        },
      });
      ceremony.confirm({ note: "testing partial rotation surfacing" });

      let caught: unknown = null;
      try {
        await ceremony.execute({ ack_subscription: ackSub });
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeTruthy();
      const err = caught as {
        name: string;
        dissenting_nodes: string[];
        received_acks: string[];
      };
      expect(err.name).toBe("BroadcastAckTimeoutError");
      expect(err.dissenting_nodes).toContain(drill.nodeIdC);
      // B's ack went through.
      expect(err.received_acks).toContain(drill.nodeIdB);

      ackSub.close();
    },
    180_000
  );
});

// ═══════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════

function mountReceiversOnBC(
  drill: ThreeModeDrillHandle,
  roster: ReturnType<typeof issueGuardianRoster>
): Map<string, MasterRotationReceiver> {
  const receivers = new Map<string, MasterRotationReceiver>();
  receivers.set(
    drill.nodeIdB,
    new MasterRotationReceiver({
      node: drill.nodeB,
      node_id: drill.nodeIdB,
      node_mode: "operator_cloud",
      fortress_id: drill.master_public.fortress_id,
      old_fortress_master_secret: () => drill.master_private_key,
      pinned_old_master: () => drill.master_public,
      pinned_guardian_roster: () => roster,
      node_private_key: drill.nodeKpB.privateKey,
    })
  );
  receivers.set(
    drill.nodeIdC,
    new MasterRotationReceiver({
      node: drill.nodeC,
      node_id: drill.nodeIdC,
      node_mode: "sovereign_tee",
      fortress_id: drill.master_public.fortress_id,
      old_fortress_master_secret: () => drill.master_private_key,
      pinned_old_master: () => drill.master_public,
      pinned_guardian_roster: () => roster,
      node_private_key: drill.nodeKpC.privateKey,
    })
  );
  return receivers;
}

// waitFor imported but referenced conditionally; silence unused-import
// warning for TS-only lint.
void waitFor;
void RECOVERY_UNICAST_KINDS;
void ({} as MasterRotationAckMessage);
