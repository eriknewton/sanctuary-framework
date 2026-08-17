/**
 * Master-rotation ceremony + wire-level broadcast orchestration.
 *
 * Spec §9.3 (guardian-quorum reconstitution), §9.4 (cascade implications),
 * §9.5 (audit continuity), Architecture Walk Key 8 (operator-in-the-loop),
 * Key 13 (recovery cascade).
 *
 * Flow (initiator side):
 *   0. The ceremony device mints a collection context (`mintRevokeCollection
 *      Context`) and the guardians sign the rotation input built from it. This
 *      happens BEFORE `propose` — the window and its ceremony_id exist before
 *      any signature does (QI-SIBLING-02).
 *   1. `propose` — caller supplies the NEW master public + private key, the
 *      NEW root-principal keypair, that collection context, and M-of-N guardian
 *      signatures. Ceremony enforces the window with its own clock, builds the
 *      `MasterRotationPayload` and runs the cascade (re-issues every peer cert +
 *      re-derives every peer's HKDF subkeys under the new master). No state is
 *      mutated yet.
 *   2. `confirm` — operator explicit confirmation step. Required by Key 8.
 *   3. `execute` — per-peer unicast of the encrypted secret bundle, broadcast
 *      of the signed `master_rotation` envelope, local install, ack
 *      collection, emit `gate_approved` audit event.
 *
 * Receiver side (`MasterRotationReceiver`):
 *   1. Unwrap the bundle using the OLD per-node transport key; cache the
 *      decrypted plaintext keyed by rotated_at.
 *   2. On `master_rotation` broadcast, look up the cached bundle, verify the
 *      quorum, call `installMasterRotation` locally, surface a signed ack
 *      via `onAckEmit` so the wiring layer can unicast it back to the
 *      initiator.
 *
 * Non-dependency invariant: no Concordia, no Verascore imports.
 * §10 hard gate: the `master_rotation` wire event is an existing V01 event
 * type; the `master_rotation_bundle` + `master_rotation_ack` unicast kinds
 * are orchestration-layer (not federation protocol events) — a v0.1 MeshNode
 * that does not run this orchestrator silently drops them in its unknown-kind
 * branch of `handleIncomingUnicast`.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { fromBase64url, toBase64url } from "../../core/encoding.js";
import type { MeshTransport } from "../in-memory-transport.js";
import { MeshNode } from "../lifecycle/mesh-node.js";
import {
  acceptMasterRotation,
  assertQuorumContextFresh,
  buildMasterRotationPayload,
  parseMasterRotationQuorumContext,
  rekeyOnMasterRotation,
  buildMasterRotationAuditPayload,
  toWireMasterRotationQuorumContext,
  type GuardianRoster,
} from "../guardian/index.js";
import { SIGNATURE_SCHEME_V1 } from "../constants.js";
import type {
  FortressMasterPublicKey,
  MasterRotationPayload,
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "../types.js";
import {
  emitGateApproved,
  type AlertEmitContext,
  type EmittedAlert,
} from "../failure-modes/alerts.js";
import {
  DEFAULT_BROADCAST_ACK_TIMEOUT_MS,
  RECOVERY_UNICAST_KINDS,
} from "./constants.js";
import {
  BroadcastAckTimeoutError,
  CeremonyError,
  CeremonyNotConfirmedError,
} from "./errors.js";
import {
  unwrapMasterRotationBundle,
  wrapMasterRotationBundle,
  type MasterRotationBundleEnvelope,
  type MasterRotationBundlePlaintext,
} from "./secret-bundle.js";
import type {
  MasterRotationProposal,
  MasterRotationResult,
  OperatorConfirmation,
} from "./types.js";

// ═══════════════════════════════════════════════════════════════════════
// Ack message shape
// ═══════════════════════════════════════════════════════════════════════

export interface MasterRotationAckMessage {
  kind: typeof RECOVERY_UNICAST_KINDS.MASTER_ROTATION_ACK;
  fortress_id: string;
  node_id: string;
  rotated_at: string;
  new_master_pubkey: string;
  status: "installed" | "error";
  error_message?: string;
  /** Base64url Ed25519 signature by the peer's pre-rotation node key. */
  ack_signature: string;
  /** MANDATORY crypto-agility hinge. v0.1 accepts only "ed25519-v1". */
  signature_scheme: typeof SIGNATURE_SCHEME_V1;
}

function ackSigningBytes(params: {
  node_id: string;
  rotated_at: string;
  new_master_pubkey: string;
  fortress_id: string;
  status: "installed" | "error";
}): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
      kind: RECOVERY_UNICAST_KINDS.MASTER_ROTATION_ACK,
      fortress_id: params.fortress_id,
      node_id: params.node_id,
      rotated_at: params.rotated_at,
      new_master_pubkey: params.new_master_pubkey,
      status: params.status,
    })
  );
}

// ═══════════════════════════════════════════════════════════════════════
// Initiator-side ceremony
// ═══════════════════════════════════════════════════════════════════════

export interface MasterRotationInitiatorContext {
  /** Initiator's MeshNode handle — used for local install + broadcast. */
  node: MeshNode;
  /** Initiator's transport — used for per-peer unicast bundle delivery. */
  transport: MeshTransport;
  /** OLD fortress-master secret for wrapping peer bundles. */
  old_fortress_master_secret: Uint8Array;
  /** OLD root-principal certificate (the cascade re-issues against its principal_id). */
  old_root_principal_cert: PrincipalCertificate;
  /** Peers the initiator needs to distribute to. Self is excluded. */
  peers: Array<{
    node_id: string;
    node_cert: NodeIdentityCertificate;
  }>;
  /** Pinned guardian roster. */
  pinned_roster: GuardianRoster;
  /** Pinned OLD fortress-master public. */
  pinned_old_master: FortressMasterPublicKey;
  /** Alert emit context for gate_approved on ceremony completion. */
  emit_ctx: AlertEmitContext;
  /** Initiator's own pre-rotation node certificate. */
  self_node_cert: NodeIdentityCertificate;
}

interface PreparedRotation {
  rotated_at: string;
  new_master_public: FortressMasterPublicKey;
  payload: MasterRotationPayload;
  re_issued_self_cert: NodeIdentityCertificate;
  new_root_principal_cert: PrincipalCertificate;
  re_issued_by_node_id: Map<string, NodeIdentityCertificate>;
  peer_bundles: Map<string, MasterRotationBundleEnvelope>;
  new_master_secret: Uint8Array;
  proposal: MasterRotationProposal;
}

export class MasterRotationCeremony {
  readonly ceremony_id: string;
  readonly ceremony_type = "master_rotation" as const;
  state: "proposed" | "confirmed" | "executing" | "completed" | "failed" =
    "proposed";
  proposed_at: string;
  confirmed_at?: string;
  completed_at?: string;
  failure_reason?: string;

  private readonly prepared: PreparedRotation;
  private readonly ctx: MasterRotationInitiatorContext;

  private constructor(params: {
    ceremony_id: string;
    prepared: PreparedRotation;
    ctx: MasterRotationInitiatorContext;
  }) {
    this.ceremony_id = params.ceremony_id;
    this.proposed_at = new Date().toISOString();
    this.prepared = params.prepared;
    this.ctx = params.ctx;
  }

  /**
   * Build the rotation artifact + cascade + per-peer wrapped bundles.
   * No wire traffic, no state mutation.
   */
  static propose(params: {
    proposal: MasterRotationProposal;
    ctx: MasterRotationInitiatorContext;
  }): MasterRotationCeremony {
    const rotatedAt = params.proposal.rotated_at ?? new Date().toISOString();

    // QI-SIBLING-02: the collection context was minted BEFORE the guardians
    // signed, so the signatures bind its ceremony_id. Re-validate the
    // operator-supplied context element-by-element and refuse a lapsed window
    // HERE, so the operator gets the feedback at propose time rather than one
    // step later when the acceptance gate below would refuse anyway.
    const parsedContext = parseMasterRotationQuorumContext(
      toWireMasterRotationQuorumContext(params.proposal.quorum_context)
    );
    if (!parsedContext.ok) {
      throw new CeremonyError(
        `master_rotation proposal has a malformed quorum context: ${parsedContext.reason}`
      );
    }
    assertQuorumContextFresh(parsedContext.context, {
      mode: "strict",
      now: new Date(),
    });

    const payload = buildMasterRotationPayload({
      quorum_context: params.proposal.quorum_context,
      old_master_pubkey: params.ctx.pinned_old_master.public_key,
      new_master_pubkey: params.proposal.new_master_public,
      rotated_at: rotatedAt,
      fortress_id: params.ctx.pinned_old_master.fortress_id,
      guardian_signatures: params.proposal.guardian_signatures,
      pinned_roster: params.ctx.pinned_roster,
    });
    // Catch a mis-assembled quorum BEFORE unlocking confirm(). Same relying-side
    // gate a receiver runs, same clock discipline (each site uses its own).
    acceptMasterRotation({
      payload,
      pinned_master: params.ctx.pinned_old_master,
      pinned_roster: params.ctx.pinned_roster,
      now: new Date(),
    });

    // Cascade: re-issue self + every peer cert under the new master.
    const allOldCerts: NodeIdentityCertificate[] = [
      params.ctx.self_node_cert,
      ...params.ctx.peers.map((p) => p.node_cert),
    ];
    const cascade = rekeyOnMasterRotation({
      new_master_secret: params.proposal.new_master_secret,
      new_master_public: params.proposal.new_master_public,
      old_node_certificates: allOldCerts,
      old_root_principal: params.ctx.old_root_principal_cert,
      new_root_principal_private_key:
        params.proposal.new_root_principal_private_key,
      new_root_principal_public_key:
        params.proposal.new_root_principal_public_key,
    });
    const newRootPrincipalCert = cascade.new_root_principal_certificate;

    const reIssuedById = new Map<string, NodeIdentityCertificate>();
    for (const c of cascade.re_issued_node_certificates) {
      reIssuedById.set(c.node_id, c);
    }
    const reIssuedSelf = reIssuedById.get(params.ctx.self_node_cert.node_id);
    if (!reIssuedSelf) {
      throw new CeremonyError(
        `cascade did not produce a re-issued cert for self node ${params.ctx.self_node_cert.node_id}`
      );
    }

    // Build the per-peer encrypted bundle.
    const peerBundles = new Map<string, MasterRotationBundleEnvelope>();
    const newMasterSecretB64 = toBase64url(params.proposal.new_master_secret);
    for (const peer of params.ctx.peers) {
      const peerReIssued = reIssuedById.get(peer.node_id);
      if (!peerReIssued) {
        throw new CeremonyError(
          `cascade did not produce a re-issued cert for peer ${peer.node_id}`
        );
      }
      const plaintext: MasterRotationBundlePlaintext = {
        new_master_secret: newMasterSecretB64,
        re_issued_self_cert: peerReIssued,
        new_root_principal_cert: newRootPrincipalCert,
        rotated_at: rotatedAt,
        new_master_pubkey: params.proposal.new_master_public.public_key,
      };
      peerBundles.set(
        peer.node_id,
        wrapMasterRotationBundle({
          plaintext,
          old_fortress_master_secret: params.ctx.old_fortress_master_secret,
          target_node_id: peer.node_id,
          target_node_mode: peer.node_cert.node_mode,
          fortress_id: params.ctx.pinned_old_master.fortress_id,
        })
      );
    }

    return new MasterRotationCeremony({
      // One identifier end to end (QI-SIBLING-02): adopt the context's
      // CSPRNG-minted ceremony_id — the one the guardians actually signed —
      // instead of minting a fresh id after the signatures already exist. This
      // also retires the local `generateCeremonyId` copy, which silently
      // degraded to a non-CSPRNG source when getRandomValues was absent.
      ceremony_id: params.proposal.quorum_context.ceremony_id,
      prepared: {
        rotated_at: rotatedAt,
        new_master_public: params.proposal.new_master_public,
        payload,
        re_issued_self_cert: reIssuedSelf,
        new_root_principal_cert: newRootPrincipalCert,
        re_issued_by_node_id: reIssuedById,
        peer_bundles: peerBundles,
        new_master_secret: params.proposal.new_master_secret,
        proposal: params.proposal,
      },
      ctx: params.ctx,
    });
  }

  /**
   * Operator-explicit confirmation. Key 8 invariant: without this, execute()
   * throws `CeremonyNotConfirmedError`.
   */
  confirm(confirmation: OperatorConfirmation): void {
    if (this.state !== "proposed") {
      throw new CeremonyError(
        `cannot confirm master-rotation ceremony from state=${this.state}`
      );
    }
    if (!confirmation.note || confirmation.note.trim().length === 0) {
      throw new CeremonyError(
        "operator confirmation requires a non-empty note"
      );
    }
    // QI-SIBLING-02 (C12 §8 Q4 precedent): an operator confirmation is not a
    // freshness extension. A ceremony whose collection window lapsed between
    // propose and confirm refuses here, so the operator learns at the click
    // rather than mid-execute with bundles already unicast. Same shared
    // assertion, this device's own clock.
    const parsed = parseMasterRotationQuorumContext(
      toWireMasterRotationQuorumContext(this.prepared.proposal.quorum_context)
    );
    if (!parsed.ok) {
      throw new CeremonyError(
        `master_rotation confirm: malformed quorum context (${parsed.reason})`
      );
    }
    assertQuorumContextFresh(parsed.context, { mode: "strict", now: new Date() });
    this.state = "confirmed";
    this.confirmed_at = confirmation.at ?? new Date().toISOString();
  }

  /**
   * Execute the confirmed ceremony.
   */
  async execute(params: {
    ack_subscription: MasterRotationAckSubscription;
  }): Promise<MasterRotationResult> {
    if (this.state !== "confirmed") {
      throw new CeremonyNotConfirmedError("master_rotation");
    }
    this.state = "executing";

    const timeoutMs =
      this.prepared.proposal.ack_timeout_ms ??
      DEFAULT_BROADCAST_ACK_TIMEOUT_MS;
    const expectedAckers = [...this.prepared.peer_bundles.keys()];

    try {
      // 1. Per-peer unicast bundle delivery.
      for (const [peerId, envelope] of this.prepared.peer_bundles) {
        await this.ctx.transport.unicast(peerId, JSON.stringify(envelope));
      }

      // 2. Broadcast the `master_rotation` SignedEvent via the MeshNode's
      //    lifecycle-emit path. This emits the exact §4.2 envelope shape that
      //    every receiver's dispatcher already handles.
      await emitMasterRotationBroadcast(
        this.ctx.node,
        this.prepared.payload
      );

      // 3. Install locally.
      this.ctx.node.installMasterRotation({
        payload: this.prepared.payload,
        new_master_secret: this.prepared.new_master_secret,
        re_issued_self_cert: this.prepared.re_issued_self_cert,
        new_root_principal_cert: this.prepared.new_root_principal_cert,
      });

      // 4. Admit each peer's re-issued cert into the post-rotation roster so
      //    post-rotation envelope verification resolves to the new-chain
      //    certs.
      for (const peer of this.ctx.peers) {
        const reIssued = this.prepared.re_issued_by_node_id.get(peer.node_id);
        if (!reIssued) continue;
        this.ctx.node.admitPeerCertificate({
          certificate: reIssued,
          issuing_principal_cert: this.prepared.new_root_principal_cert,
        });
      }

      // 5. Await acks.
      const acksReceived = await params.ack_subscription.waitFor({
        rotated_at: this.prepared.rotated_at,
        expected: expectedAckers,
        timeout_ms: timeoutMs,
      });
      const dissenting = expectedAckers.filter((id) => !acksReceived.has(id));
      const ackedIds = [...acksReceived];

      // 6. Emit the operator-visible gate_approved audit-trail event.
      emitGateApproved(this.ctx.emit_ctx, {
        failure_mode: "master_rotation",
        target: this.prepared.new_master_public.public_key,
        decision: "execute_master_rotation",
        detail: {
          ceremony_id: this.ceremony_id,
          rotated_at: this.prepared.rotated_at,
          acked_nodes: ackedIds,
          dissenting_nodes: dissenting,
        },
      });

      this.state = "completed";
      this.completed_at = new Date().toISOString();

      if (dissenting.length > 0) {
        // Rotation landed; operator must decide whether to retry or revoke
        // dissenting peers. Surface the partial outcome as an error and leave
        // state=completed so the record reflects "installed + partial acks".
        throw new BroadcastAckTimeoutError({
          dissenting_nodes: dissenting,
          received_acks: ackedIds,
          ceremony: "master_rotation",
        });
      }

      return {
        rotated_at: this.prepared.rotated_at,
        new_master_pubkey: this.prepared.new_master_public.public_key,
        acks_received: ackedIds,
        dissenting_nodes: dissenting,
        new_root_principal_cert: this.prepared.new_root_principal_cert,
      };
    } catch (e) {
      if (e instanceof BroadcastAckTimeoutError) throw e;
      this.state = "failed";
      this.failure_reason = e instanceof Error ? e.message : String(e);
      throw e;
    }
  }

  // Read-only accessors used by downstream ceremonies (device-recovery
  // chains a rotation, etc.) and by tests.
  rotatedAt(): string {
    return this.prepared.rotated_at;
  }
  rotationPayload(): MasterRotationPayload {
    return this.prepared.payload;
  }
  newRootPrincipalCert(): PrincipalCertificate {
    return this.prepared.new_root_principal_cert;
  }
  reIssuedCertFor(nodeId: string): NodeIdentityCertificate {
    if (nodeId === this.ctx.self_node_cert.node_id) {
      return this.prepared.re_issued_self_cert;
    }
    const c = this.prepared.re_issued_by_node_id.get(nodeId);
    if (!c) {
      throw new CeremonyError(`no re-issued cert for ${nodeId}`);
    }
    return c;
  }
  peerBundles(): ReadonlyMap<string, MasterRotationBundleEnvelope> {
    return this.prepared.peer_bundles;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Receiver-side
// ═══════════════════════════════════════════════════════════════════════

/**
 * Per-rotation receiver state. Because the bundle unicast and rotation
 * broadcast arrive independently (possibly out-of-order), the receiver
 * caches both keyed by rotated_at and fires the install once both are
 * present.
 */
interface PendingRotationOnReceiver {
  bundle?: MasterRotationBundlePlaintext;
  broadcast?: MasterRotationPayload;
}

export interface MasterRotationReceiverOptions {
  node: MeshNode;
  node_id: string;
  node_mode: "local" | "operator_cloud" | "sovereign_tee";
  fortress_id: string;
  /** OLD master secret (accessor — may change if multiple rotations chain). */
  old_fortress_master_secret: () => Uint8Array;
  pinned_old_master: () => FortressMasterPublicKey;
  pinned_guardian_roster: () => GuardianRoster;
  /** Receiver's ed25519 private key for signing the outgoing ack. */
  node_private_key: Uint8Array;
}

export class MasterRotationReceiver {
  private readonly pending = new Map<string, PendingRotationOnReceiver>();
  private readonly installed = new Set<string>();
  private readonly opts: MasterRotationReceiverOptions;
  private readonly ackEmitListeners = new Set<
    (ack: MasterRotationAckMessage) => void
  >();

  constructor(opts: MasterRotationReceiverOptions) {
    this.opts = opts;
  }

  /**
   * Consume a unicast from `transport.subscribeUnicast`. Returns true if the
   * message was a `master_rotation_bundle` (so the caller knows not to pass
   * it to MeshNode's regular dispatcher).
   */
  async handleIncomingUnicast(
    to: string,
    message: string
  ): Promise<boolean> {
    if (to !== this.opts.node_id) return false;
    let parsed: { kind?: string };
    try {
      parsed = JSON.parse(message);
    } catch {
      return false;
    }
    if (parsed.kind !== RECOVERY_UNICAST_KINDS.MASTER_ROTATION_BUNDLE) {
      return false;
    }
    const envelope = parsed as unknown as MasterRotationBundleEnvelope;
    const plaintext = unwrapMasterRotationBundle({
      envelope,
      old_fortress_master_secret: this.opts.old_fortress_master_secret(),
      this_node_id: this.opts.node_id,
      this_node_mode: this.opts.node_mode,
      this_fortress_id: this.opts.fortress_id,
    });
    const entry = this.pending.get(envelope.rotated_at) ?? {};
    entry.bundle = plaintext;
    this.pending.set(envelope.rotated_at, entry);
    await this.maybeInstall(envelope.rotated_at);
    return true;
  }

  /**
   * Call from a `MeshNode.onLifecycleEvent` hook when a received
   * `master_rotation` event arrives.
   */
  async handleIncomingMasterRotationBroadcast(
    payload: MasterRotationPayload
  ): Promise<void> {
    const entry = this.pending.get(payload.rotated_at) ?? {};
    entry.broadcast = payload;
    this.pending.set(payload.rotated_at, entry);
    await this.maybeInstall(payload.rotated_at);
  }

  private async maybeInstall(rotatedAt: string): Promise<void> {
    if (this.installed.has(rotatedAt)) return;
    const entry = this.pending.get(rotatedAt);
    if (!entry?.bundle || !entry.broadcast) return;

    // Verify the guardian quorum against pinned state, and the collection
    // window against THIS receiver's clock (QI-SIBLING-02). Strict mode, not
    // the sync-anchored variant: a rotation only installs when the live unicast
    // bundle and the broadcast are both in hand, and that pairing is collected
    // inside DEFAULT_BROADCAST_ACK_TIMEOUT_MS, so there is no legitimate
    // late-joiner case that needs to outlive the collection window. A node that
    // was offline for the ceremony recovers through device recovery, not
    // through a replayed rotation.
    try {
      acceptMasterRotation({
        payload: entry.broadcast,
        pinned_master: this.opts.pinned_old_master(),
        pinned_roster: this.opts.pinned_guardian_roster(),
        now: new Date(),
      });
    } catch (e) {
      // A refused broadcast must not stay retained (rule 8). Freshness
      // enforcement makes refusal the guaranteed outcome for every replay, so
      // the refusal path is now the cheap one; holding the rejected payload
      // would let an authentic-but-replaying peer grow this map for free. The
      // BUNDLE half is kept: unwrapping it required the old per-node transport
      // key, so it is not attacker-mintable, and dropping it would turn a
      // refused broadcast into a permanent inability to install a later valid
      // one at the same rotated_at.
      entry.broadcast = undefined;
      throw e;
    }

    if (
      entry.bundle.re_issued_self_cert.parent_chain.fortress_master_pubkey !==
      entry.broadcast.new_master_pubkey.public_key
    ) {
      this.surfaceAckError(rotatedAt, entry.broadcast, "cert_chain_mismatch");
      return;
    }

    let newMasterSecret: Uint8Array;
    try {
      newMasterSecret = fromBase64url(entry.bundle.new_master_secret);
    } catch (e) {
      this.surfaceAckError(
        rotatedAt,
        entry.broadcast,
        `malformed new_master_secret: ${e instanceof Error ? e.message : String(e)}`
      );
      return;
    }

    try {
      this.opts.node.installMasterRotation({
        payload: entry.broadcast,
        new_master_secret: newMasterSecret,
        re_issued_self_cert: entry.bundle.re_issued_self_cert,
        new_root_principal_cert: entry.bundle.new_root_principal_cert,
      });
    } catch (e) {
      this.surfaceAckError(
        rotatedAt,
        entry.broadcast,
        e instanceof Error ? e.message : String(e)
      );
      return;
    }

    this.installed.add(rotatedAt);

    const ack: MasterRotationAckMessage = {
      kind: RECOVERY_UNICAST_KINDS.MASTER_ROTATION_ACK,
      fortress_id: this.opts.fortress_id,
      node_id: this.opts.node_id,
      rotated_at: rotatedAt,
      new_master_pubkey: entry.broadcast.new_master_pubkey.public_key,
      status: "installed",
      ack_signature: toBase64url(
        ed25519.sign(
          ackSigningBytes({
            node_id: this.opts.node_id,
            rotated_at: rotatedAt,
            new_master_pubkey: entry.broadcast.new_master_pubkey.public_key,
            fortress_id: this.opts.fortress_id,
            status: "installed",
          }),
          this.opts.node_private_key
        )
      ),
      signature_scheme: SIGNATURE_SCHEME_V1,
    };
    for (const l of this.ackEmitListeners) l(ack);
  }

  private surfaceAckError(
    rotatedAt: string,
    broadcast: MasterRotationPayload,
    errorMessage: string
  ): void {
    const ack: MasterRotationAckMessage = {
      kind: RECOVERY_UNICAST_KINDS.MASTER_ROTATION_ACK,
      fortress_id: this.opts.fortress_id,
      node_id: this.opts.node_id,
      rotated_at: rotatedAt,
      new_master_pubkey: broadcast.new_master_pubkey.public_key,
      status: "error",
      error_message: errorMessage,
      ack_signature: toBase64url(
        ed25519.sign(
          ackSigningBytes({
            node_id: this.opts.node_id,
            rotated_at: rotatedAt,
            new_master_pubkey: broadcast.new_master_pubkey.public_key,
            fortress_id: this.opts.fortress_id,
            status: "error",
          }),
          this.opts.node_private_key
        )
      ),
      signature_scheme: SIGNATURE_SCHEME_V1,
    };
    for (const l of this.ackEmitListeners) l(ack);
  }

  /**
   * Subscribe to ack emissions. The wiring layer connects this to the
   * transport's unicast path targeted at the rotation initiator.
   */
  onAckEmit(listener: (ack: MasterRotationAckMessage) => void): () => void {
    this.ackEmitListeners.add(listener);
    return () => this.ackEmitListeners.delete(listener);
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Ack subscription
// ═══════════════════════════════════════════════════════════════════════

export interface MasterRotationAckSubscription {
  acksFor(rotatedAt: string): ReadonlyMap<string, MasterRotationAckMessage>;
  ingest(ack: MasterRotationAckMessage): void;
  waitFor(params: {
    rotated_at: string;
    expected: string[];
    timeout_ms: number;
  }): Promise<Set<string>>;
  close(): void;
}

export function createMasterRotationAckSubscription(params: {
  fortress_id: string;
  /**
   * Returns the pre-rotation node pubkey (base64url) for an incoming ack's
   * `node_id`. The ack is signed with the peer's OLD per-node key (the key
   * it had when it unwrapped the bundle). The initiator verifies against
   * that old key because post-install the peer's OLD private key is zeroed.
   */
  lookup_pre_rotation_pubkey: (nodeId: string) => string | undefined;
}): MasterRotationAckSubscription {
  const byRotation = new Map<string, Map<string, MasterRotationAckMessage>>();
  const waiters = new Set<() => void>();
  let closed = false;

  const sub: MasterRotationAckSubscription = {
    acksFor(rotatedAt) {
      return byRotation.get(rotatedAt) ?? new Map();
    },
    ingest(ack: MasterRotationAckMessage): void {
      if (closed) return;
      if (ack.kind !== RECOVERY_UNICAST_KINDS.MASTER_ROTATION_ACK) return;
      if (ack.fortress_id !== params.fortress_id) return;
      if (ack.signature_scheme !== SIGNATURE_SCHEME_V1) return;
      const pubkey = params.lookup_pre_rotation_pubkey(ack.node_id);
      if (!pubkey) return;
      const ok = ed25519.verify(
        fromBase64url(ack.ack_signature),
        ackSigningBytes({
          node_id: ack.node_id,
          rotated_at: ack.rotated_at,
          new_master_pubkey: ack.new_master_pubkey,
          fortress_id: ack.fortress_id,
          status: ack.status,
        }),
        fromBase64url(pubkey)
      );
      if (!ok) return;
      const map = byRotation.get(ack.rotated_at) ?? new Map();
      map.set(ack.node_id, ack);
      byRotation.set(ack.rotated_at, map);
      for (const w of waiters) w();
    },
    async waitFor({ rotated_at, expected, timeout_ms }) {
      const deadline = Date.now() + timeout_ms;
      while (true) {
        const acks = byRotation.get(rotated_at) ?? new Map();
        const received = new Set<string>();
        for (const id of expected) {
          const a = acks.get(id);
          if (a && a.status === "installed") received.add(id);
        }
        if (received.size === expected.length) return received;
        const remaining = deadline - Date.now();
        if (remaining <= 0) return received;
        await new Promise<void>((resolve) => {
          let done = false;
          const notify = () => {
            if (done) return;
            done = true;
            clearTimeout(t);
            waiters.delete(notify);
            resolve();
          };
          const t = setTimeout(notify, Math.min(50, remaining));
          waiters.add(notify);
        });
      }
    },
    close(): void {
      closed = true;
      for (const w of waiters) w();
      waiters.clear();
    },
  };

  return sub;
}

// ═══════════════════════════════════════════════════════════════════════
// Broadcast emit helper
// ═══════════════════════════════════════════════════════════════════════

/**
 * MeshNode exposes a private `emitLifecycleEvent` that already handles
 * `master_rotation`. The orchestrator invokes it via a typed accessor so the
 * wire shape matches exactly what receivers' dispatchers already expect.
 * This keeps the `master_rotation` envelope signature, seq, and causal-
 * parent conventions consistent with every other v0.1 lifecycle event.
 */
async function emitMasterRotationBroadcast(
  node: MeshNode,
  payload: MasterRotationPayload
): Promise<void> {
  const nodeWithInternal = node as unknown as {
    emitLifecycleEvent: (
      eventType: "master_rotation",
      payload: MasterRotationPayload
    ) => Promise<unknown>;
  };
  if (typeof nodeWithInternal.emitLifecycleEvent !== "function") {
    throw new CeremonyError(
      "orchestrator: MeshNode.emitLifecycleEvent is not accessible"
    );
  }
  await nodeWithInternal.emitLifecycleEvent("master_rotation", payload);
}

// ═══════════════════════════════════════════════════════════════════════
// Misc
// ═══════════════════════════════════════════════════════════════════════

// QI-SIBLING-02: the local `generateCeremonyId` copy was DELETED here. It
// silently degraded to a non-CSPRNG source when `crypto.getRandomValues` was
// absent (a MUST-NEVER #5 degradation) and it minted an id AFTER
// the guardian signatures existed, so nothing could bind it. The ceremony now
// adopts the CSPRNG-fail-closed ceremony_id from the collection context minted
// by `mintRevokeCollectionContext` in `mesh/guardian/revoke-quorum-input.ts`.

export { emitGateApproved, type EmittedAlert };

/**
 * Build a `master_rotation_boundary` audit-entry payload. MeshNode.install-
 * MasterRotation already pushes a boundary entry internally, so callers
 * typically do not invoke this directly; kept for test-harness introspection
 * and for out-of-band cascades.
 */
export function buildRotationBoundaryFor(payload: MasterRotationPayload) {
  return buildMasterRotationAuditPayload({
    old_master_pubkey: payload.old_master_pubkey,
    new_master_pubkey: payload.new_master_pubkey.public_key,
    guardian_quorum_signatures: payload.quorum_signatures,
    rotated_at: payload.rotated_at,
  });
}
