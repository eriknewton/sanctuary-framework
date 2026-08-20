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
 *   3. `execute` — re-assert the collection window with this device's own clock
 *      BEFORE any wire traffic (the confirm-to-execute gap is operator-paced and
 *      unbounded), then per-peer unicast of the encrypted secret bundle,
 *      broadcast of the signed `master_rotation` envelope, local install, ack
 *      collection, emit `gate_approved` audit event.
 *
 * Receiver side (`MasterRotationReceiver`):
 *   1. Unwrap the bundle using the OLD per-node transport key; cache the
 *      decrypted plaintext in the pending map keyed by rotated_at.
 *   2. On `master_rotation` broadcast, look up the cached bundle, verify the
 *      quorum and the window with this node's own clock, call
 *      `installMasterRotation` locally, surface a signed ack via `onAckEmit`
 *      so the wiring layer can unicast it back to the initiator.
 *   3. A refused broadcast never rejects and never acks: it drops the broadcast
 *      half, writes a GOVERNED denial audit entry keyed on the authenticated
 *      emitter, and fires `onEnvelopeRejected`. The pending map itself is
 *      UNBOUNDED — a stated rule-8 gap on a parked layer, see the declaration.
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
  classifyAdmissionRefusal,
  type AuthenticatedPeer,
} from "../lifecycle/envelope-rejection.js";
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
  parseMasterRotationBundleEnvelope,
  unwrapMasterRotationBundle,
  wrapMasterRotationBundle,
  type MasterRotationBundleEnvelope,
  type MasterRotationBundlePlaintext,
} from "./secret-bundle.js";
import { SecretBundleError } from "./errors.js";
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
      // 0. PRE-BROADCAST FRESHNESS GATE (QI-SIBLING-02 fix round, state
      //    `confirmed` -> `executing`). The confirm-to-execute gap is
      //    operator-paced and unbounded: an operator can confirm at T+1min and
      //    click execute hours later. Without this line the initiator unicasts
      //    bundles, broadcasts, and installs the new master under a window that
      //    has already lapsed, every peer refuses with QuorumFreshnessError, and
      //    the fortress splits across two masters — a state that needs a fresh
      //    guardian quorum to leave. `REVOKE_QUORUM_MAX_LIFETIME_MS`'s own
      //    derivation says the window must cover "execute's local accept", so
      //    this is the line that makes that comment true rather than aspirational.
      //
      //    Mirrors the C12 revoke path's emit-site gate (`mesh-node.ts`
      //    `revokePeer`, "pre-broadcast guardian invariant"): master rotation
      //    adopted C12's confirm gate but not its emit gate. Single-shot is
      //    sufficient because the state machine forbids re-entering `execute`,
      //    and this device's OWN clock is read here, never a timestamp lifted
      //    from the payload.
      //
      //    Parses `payload.quorum_context` — the field that actually rides the
      //    wire and that every receiver re-checks — rather than the in-memory
      //    `proposal.quorum_context` it was projected from. The two agree today
      //    because `propose` builds one from the other, so gating on the
      //    proposal would be a check on a value the peers never see; an
      //    emit-site gate must assert over exactly the bytes it is about to
      //    emit, or a later divergence between the two representations passes
      //    here and fails at every receiver.
      const executeContext = parseMasterRotationQuorumContext(
        this.prepared.payload.quorum_context
      );
      if (!executeContext.ok) {
        throw new CeremonyError(
          `master_rotation execute: malformed quorum context (${executeContext.reason})`
        );
      }
      assertQuorumContextFresh(executeContext.context, {
        mode: "strict",
        now: new Date(),
      });

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
  /**
   * The broadcast half AND the AUTHENTICATED emitter that delivered it, held as
   * ONE field so the two cannot come apart. `emitter_node` is the emitter of a
   * SignedEvent that already passed the receive path's `verifyOrThrow`, never a
   * string lifted from the payload: every refusal is attributed with it, and an
   * attribution keyed on a spoofable field would let one peer pin its refusals
   * on another. Pairing them structurally is what lets `surfaceBroadcastRefusal`
   * require a non-optional emitter, so no refusal can be recorded against an
   * unknown origin by omission.
   *
   * UEK-02: the field is now typed `AuthenticatedPeer`, so the paragraph above
   * is enforced rather than requested. A caller holding only an unverified
   * `string` cannot construct this object at all, and the one place that
   * asserts "this was verified" is `authenticatedPeer()` at the receive path's
   * mint site.
   */
  broadcast?: {
    payload: MasterRotationPayload;
    emitter_node: AuthenticatedPeer;
  };
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
  /**
   * In-flight rotations, keyed on the SENDER-CHOSEN `rotated_at` string, read
   * before any validation runs.
   *
   * THIS MAP IS UNBOUNDED. That is a known AGENTS.md rule-8 gap on a parked
   * layer, tracked as QI-02-F11 in the private defect register; the register row
   * is the only place its details resolve. Nothing in the surrounding freshness
   * work bounds it, and no comment, doc or claim here may say otherwise.
   *
   * Two admission bounds have been attempted at this line and both failed a
   * gate, which is why there is no third one here rather than a smaller one.
   * DESIGN CONSTRAINT for whoever bounds it next: a bound must govern entry
   * LIFETIME, not only admission — delete on successful install, sweep entries
   * that reached a terminal state, and decide explicitly what happens to a
   * broadcast that never pairs. An admission-only cap over a map nothing ever
   * removes from turns a full map into a permanent refusal to install any later
   * rotation, which is the two-master split this file's execute-time gate exists
   * to prevent, and its operator symptom is silence. QI-02-F11 also records the
   * availability tradeoff any eviction policy inherits.
   */
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
   *
   * STATED CONSEQUENCE of the round-2 subtraction, written down rather than left
   * to be discovered: removing the capacity-refusal branch removed the ONLY
   * `onEnvelopeRejected` call on this bundle path, so a failure here — a bundle
   * that will not unwrap under the old per-node transport key — now has NO
   * operator surface at all. It throws to the caller, and the reference wiring
   * discards it. That is defensible: unwrapping requires a key an attacker does
   * not hold, so this is a local or misdelivered-bundle fault rather than an
   * attacker-driven one, and the broadcast half still refuses loudly. It is also
   * a real gap in what an operator can see, so whoever gives this path a signal
   * is ADDING one, not restoring one.
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
    // Element-level parse, not a cast: `parsed` is arbitrary attacker-chosen
    // JSON, and its fields are consumed in comparisons and AAD construction
    // before anything is authenticated. Both sides of that boundary consume
    // THIS one schema, so the typed result is the agreement (AGENTS.md rule 11)
    // rather than two validators that can drift. This bounds THIS envelope's
    // fields only; it is not a claim that the recovery path's untrusted input
    // is generally safe to dereference.
    const envelopeParse = parseMasterRotationBundleEnvelope(parsed);
    if (!envelopeParse.ok) {
      throw new SecretBundleError(
        `master_rotation_bundle envelope is malformed (${envelopeParse.reason})`
      );
    }
    const envelope = envelopeParse.envelope;
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
   *
   * `emitter_node` MUST be the verified envelope's `emitter_node`. The receive
   * path runs `verifyOrThrow` before dispatching to the router that fires
   * `onLifecycleEvent(evt, "received")`, so at that hook the value is
   * authenticated; passing anything read out of the payload instead would key
   * this receiver's refusal audit — and the per-emitter budget the denial-audit
   * governor applies to it — on an attacker-chosen string, letting one peer
   * spend another peer's bucket and pin its own refusals on that peer.
   *
   * NEVER REJECTS ON A REFUSAL, and that is the precise guarantee — not a
   * blanket "never throws". QI-SIBLING-02 made refusal the GUARANTEED outcome
   * for every stale or replayed broadcast, and the reference wiring invokes this
   * as `void rec.handleIncomingMasterRotationBroadcast(...)`, so under Node's
   * default unhandled-rejection behavior a propagating refusal would let an
   * authenticated peer crash the receiving node by replaying a stale rotation.
   * Every attacker-reachable failure — a refused window, a refused quorum, and
   * the operator-surfacing callbacks those fire — is contained: refusals become
   * a governed audit entry plus `onEnvelopeRejected`, exactly as the
   * `node_revoke` router handler already does for the identical class, and both
   * that hook and the ack listeners are caller-supplied, so both are wrapped.
   *
   * The residual, stated rather than hidden: a fault on the INSTALL path (an
   * ed25519 signing failure from a corrupt local node key) still rejects. That
   * path is only reachable with a bundle already unwrapped under the old
   * per-node transport key, so it is a local fault and not attacker-drivable,
   * and silently swallowing a local key fault would be the worse trade.
   */
  async handleIncomingMasterRotationBroadcast(
    payload: MasterRotationPayload,
    params: { emitter_node: AuthenticatedPeer }
  ): Promise<void> {
    const entry = this.pending.get(payload.rotated_at) ?? {};
    entry.broadcast = { payload, emitter_node: params.emitter_node };
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
    const broadcast = entry.broadcast.payload;
    try {
      acceptMasterRotation({
        payload: broadcast,
        pinned_master: this.opts.pinned_old_master(),
        pinned_roster: this.opts.pinned_guardian_roster(),
        now: new Date(),
      });
    } catch (e) {
      // A refused broadcast is not retained: freshness enforcement makes refusal
      // the guaranteed outcome for every replay, so holding the rejected payload
      // would let an authentic-but-replaying peer grow this map for free. This
      // is a hygiene measure on the PAIRED path and is explicitly NOT a bound on
      // the map — see the `pending` declaration, whose comment names the gap and
      // the register row rather than letting this line read as coverage.
      //
      // The BUNDLE half is kept: unwrapping it required the old per-node
      // transport key, so it is not attacker-mintable, and dropping it would
      // turn a refused broadcast into a permanent inability to install a later
      // valid one at the same rotated_at.
      const refusedEmitter = entry.broadcast.emitter_node;
      entry.broadcast = undefined;
      this.surfaceBroadcastRefusal(
        refusedEmitter,
        rotatedAt,
        e instanceof Error ? e : new Error(String(e))
      );
      return;
    }

    if (
      entry.bundle.re_issued_self_cert.parent_chain.fortress_master_pubkey !==
      broadcast.new_master_pubkey.public_key
    ) {
      this.surfaceAckError(rotatedAt, broadcast, "cert_chain_mismatch");
      return;
    }

    let newMasterSecret: Uint8Array;
    try {
      newMasterSecret = fromBase64url(entry.bundle.new_master_secret);
    } catch (e) {
      this.surfaceAckError(
        rotatedAt,
        broadcast,
        `malformed new_master_secret: ${e instanceof Error ? e.message : String(e)}`
      );
      return;
    }

    try {
      this.opts.node.installMasterRotation({
        payload: broadcast,
        new_master_secret: newMasterSecret,
        re_issued_self_cert: entry.bundle.re_issued_self_cert,
        new_root_principal_cert: entry.bundle.new_root_principal_cert,
      });
    } catch (e) {
      this.surfaceAckError(
        rotatedAt,
        broadcast,
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
      new_master_pubkey: broadcast.new_master_pubkey.public_key,
      status: "installed",
      ack_signature: toBase64url(
        ed25519.sign(
          ackSigningBytes({
            node_id: this.opts.node_id,
            rotated_at: rotatedAt,
            new_master_pubkey: broadcast.new_master_pubkey.public_key,
            fortress_id: this.opts.fortress_id,
            status: "installed",
          }),
          this.opts.node_private_key
        )
      ),
      signature_scheme: SIGNATURE_SCHEME_V1,
    };
    this.emitAck(ack);
  }

  /**
   * The ONE receiver-side refusal surface (QI-SIBLING-02 fix round, fixes the
   * "a refusing node looks identical to one that never received the broadcast"
   * gap). Two effects, both operator-facing and neither decisional:
   *
   *   1. A GOVERNED audit entry via `MeshNode.auditMasterRotationDenied`, keyed
   *      on the AUTHENTICATED emitter. Governed because refusal is the
   *      guaranteed outcome for every replay, so an ungoverned entry per
   *      refusal would be a zero-cost audit-write amplifier for any in-roster
   *      peer (rule 8) — the same reason the revoke-denial and
   *      uncorrelated-sync paths are governed.
   *   2. `onEnvelopeRejected`, the hook the `node_revoke` router handler
   *      already uses for this class, which the failure-mode detector consumes.
   *
   * Deliberately NO error ack. An ack is a freshly SIGNED message unicast to
   * the initiator, so emitting one per refused replay would hand an
   * authenticated peer a signing-and-reflection amplifier aimed at the
   * initiator — trading a fixed local defect for an attacker-driven remote one.
   * The audit entry is the durable operator record and it reaches the canonical
   * audit node on the normal batch flush, which is where a fleet operator reads
   * "this node refused" from.
   *
   * `emitterNode` is REQUIRED, not optional-with-an-unknown-peer-fallback. It is
   * carried inside `PendingRotationOnReceiver.broadcast` alongside the payload
   * it authenticated, so the only way to reach a refusal is to be holding the
   * emitter that caused it. A refusal attributed to "unknown" is a forensic dead
   * end and an unkeyed governor bucket every peer would share, so the type
   * forecloses it instead of a runtime fallback papering over it.
   *
   * UEK-02: `emitterNode` is now `AuthenticatedPeer` rather than `string`, so
   * "required" is joined by "provably verified upstream" — a required
   * parameter still accepts an unverified value, a branded one does not.
   */
  private surfaceBroadcastRefusal(
    emitterNode: AuthenticatedPeer,
    rotatedAt: string,
    error: Error
  ): void {
    // Audit-write availability must never change the refusal or the operator
    // signal (the governor's forensic-only invariant), so a failed audit write
    // is contained here and `onEnvelopeRejected` still fires below.
    try {
      this.opts.node.auditMasterRotationDenied({
        emitter_node: emitterNode,
        rotated_at: rotatedAt,
        error,
      });
    } catch {
      // An unkeyed or mid-rotation node cannot seal an entry; the rejection
      // hook below is still the operator's signal.
    }
    // The hook is CALLER-SUPPLIED and in production reaches signing and counter
    // I/O, so it can throw. Refusal is the guaranteed outcome for every replay
    // and the reference wiring calls this receiver as `void ...`, so an
    // unwrapped hook would hand an authenticated peer the exact
    // unhandled-rejection crash this refusal path exists to close. Containment
    // is not silent degradation (MUST-NEVER #5): the refusal has already
    // happened and is unaffected, and the governed audit entry above is sealed
    // BEFORE this line, so a broken operator hook loses its own delivery and
    // never the evidence.
    //
    // STATED BOUND (rule 8), PARTIALLY closed and still live. Bare ids UEK-02
    // and QI-02-F12; they resolve only in the private register.
    //
    // WHAT CLOSED: the identity this refusal is attributed to. The consumer of
    // `onEnvelopeRejected` now keys per-origin state on an AUTHENTICATED
    // origin, so a refusal can no longer open a bucket under a name the sender
    // chose. That closed at the shared boundary, which is where every caller
    // gets it at once.
    //
    // WHAT DID NOT: the per-refusal WORK, which is what the bound stated here
    // was always about, and it is unchanged. The audit write above is GOVERNED
    // per authenticated emitter; this hook is not. It fires once per refusal,
    // costing a signature each time, and freshness enforcement makes refusal
    // the guaranteed outcome for every replay — so the work an in-roster peer
    // can drive downstream of this line still scales with the NUMBER of
    // refusals it chooses to cause. Bounding retained state is not bounding
    // invocations. Nothing on this path bounds that today.
    //
    // QI-02-F12: `acceptMasterRotation` refuses for two very different
    // reasons, and the class decides which one an operator is told. A lapsed
    // collection window or a skewed receiver clock (`QuorumFreshnessError`) is
    // a timing relationship between two nodes and must NOT be rendered as a
    // compromise accusation against the rotation initiator; a bad or missing
    // guardian quorum is an authority violation and must.
    try {
      this.opts.node.onEnvelopeRejected({
        error,
        event_type: "master_rotation",
        rejection_origin: emitterNode,
        reason_class: classifyAdmissionRefusal(error),
      });
    } catch {
      // Nothing further to escalate to: the audit entry is already sealed.
    }
  }

  /**
   * Fan an ack out to every subscriber, isolating each one.
   *
   * Listeners are caller-supplied and the reference wiring's listener unicasts
   * over the transport, so one throwing listener must not (a) reject the
   * receiver's promise, which the `void`-calling wiring turns into an unhandled
   * rejection, or (b) starve the listeners registered after it. Both sites that
   * emit an ack funnel here, so the isolation cannot be present on one and
   * absent on the other (rule 5: one implementation, never two that drift).
   *
   * What the containment COSTS differs by call site, and both are stated below
   * rather than described from the success path alone.
   */
  private emitAck(ack: MasterRotationAckMessage): void {
    for (const l of this.ackEmitListeners) {
      try {
        l(ack);
      } catch {
        // Containment, priced per CALL SITE.
        //
        // SUCCESS ack: the install decision is already made and recorded, so a
        // lost delivery costs this subscriber's copy and nothing else.
        //
        // ERROR ack: the install FAILED. Nothing is audited on that path, the
        // rejection hook does not fire, and this ack is the ONLY signal that
        // exists — so a swallowed throw makes a failed install locally silent
        // and, at the initiator, indistinguishable from a node that was simply
        // offline for the ceremony. That is the deliberate round-2 trade and not
        // an oversight: a rejected promise under the `void`-calling wiring is an
        // attacker-reachable crash, a lost operator signal is not, and a crash
        // loses the signal too. The remaining subscribers still get the ack in
        // both cases.
      }
    }
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
    this.emitAck(ack);
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
