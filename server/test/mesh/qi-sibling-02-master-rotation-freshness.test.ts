/**
 * QI-SIBLING-02 — master-rotation quorum-input freshness (register row
 * QI-SIBLING-02; details resolve only in the private defect register).
 *
 * CAPABILITY UNDER TEST: the relying side of a master rotation enforces the
 * collection window the guardians signed, with its OWN clock, at every site that
 * consumes the quorum. A guardian quorum is a bearer capability, and a signature
 * over a signer-chosen timestamp proves who signed it, not that the posture it
 * asserts is still current (AGENTS.md rule 10). Without a relying-side window an
 * abandoned ceremony's quorum stays a master-swap capability for as long as a
 * node remains pinned to the old master, which is the same class as C12-REPLAY
 * with a heavier consequence, since the accepted artifact replaces the fortress
 * master.
 *
 * The capability adopts the C12 collection context + `assertQuorumContextFresh`
 * unchanged (the struct is input-agnostic by design) under its own domain
 * separator, and every guard below plants its divergence and asserts the
 * refusal rather than asserting the happy path alone.
 */

import { describe, it, expect, vi } from "vitest";
import {
  REJECTION_REASON_CLASS,
  authenticatedPeer,
  type RejectionOrigin,
  type RejectionReasonClass,
} from "../../src/mesh/lifecycle/envelope-rejection.js";
import { toBase64url } from "../../src/core/encoding.js";
import { generateKeypair } from "../../src/core/identity.js";
import {
  acceptMasterRotation,
  buildGuardianMasterRotationQuorumInput,
  buildGuardianRevokeQuorumInput,
  buildMasterRotationPayload,
  DEFAULT_GUARDIAN_M,
  DEFAULT_GUARDIAN_N,
  GUARDIAN_MASTER_ROTATION_QUORUM_SCHEMA_V2,
  GUARDIAN_REVOKE_QUORUM_SCHEMA_V2,
  issueGuardianRoster,
  MasterRotationError,
  mintRevokeCollectionContext,
  QuorumFreshnessError,
  rekeyOnMasterRotation,
  REVOKE_QUORUM_CLOCK_SKEW_MS,
  REVOKE_QUORUM_MAX_LIFETIME_MS,
  signMasterRotationAsGuardian,
  type GuardianIdentity,
  type GuardianRevokeQuorumContext,
} from "../../src/mesh/guardian/index.js";
import {
  generateFortressMaster,
} from "../../src/mesh/trust-root.js";
import {
  InMemoryCounterStore,
  InMemoryNodeKeyStore,
  MeshNode,
  createAutoApproveJoinApprover,
} from "../../src/mesh/lifecycle/index.js";
import { InMemoryTransport } from "../../src/mesh/in-memory-transport.js";
import {
  MasterRotationCeremony,
  MasterRotationReceiver,
  createMasterRotationAckSubscription,
  wrapMasterRotationBundle,
} from "../../src/mesh/recovery-flows/index.js";
import type { MeshTransport } from "../../src/mesh/in-memory-transport.js";
import type {
  FortressMasterPublicKey,
  MasterRotationPayload,
  PrincipalCertificate,
  SignedEvent,
} from "../../src/mesh/types.js";

const HOUR_MS = 60 * 60 * 1000;

/**
 * The AUTHENTICATED emitter every receiver-side test attributes its broadcast
 * to. In production this is `evt.emitter_node` off an envelope that already
 * passed `verifyOrThrow`; a per-peer quota keyed on anything the payload
 * carries would be attacker-selectable and therefore no quota at all.
 */
// UEK-02: the reference wiring mints the brand from the receive path's
// already-verified `evt.emitter_node`; the fixture does the same so it
// exercises the production shape rather than a widened one.
const PEER = authenticatedPeer("peer-initiator");

interface GuardianKp {
  identity: GuardianIdentity;
  private_key: Uint8Array;
}

function makeGuardian(id: string): GuardianKp {
  const kp = generateKeypair();
  return {
    identity: {
      guardian_id: id,
      public_key: toBase64url(kp.publicKey),
      kind: "human",
      invited_at: new Date().toISOString(),
    },
    private_key: kp.privateKey,
  };
}

function makeFixture() {
  const oldFortress = generateFortressMaster();
  const guardians = ["g1", "g2", "g3", "g4", "g5"].map(makeGuardian);
  const roster = issueGuardianRoster({
    m: DEFAULT_GUARDIAN_M,
    n: DEFAULT_GUARDIAN_N,
    guardians: guardians.map((g) => g.identity),
    fortress_id: oldFortress.public.fortress_id,
    version: 1,
    master_private_key: oldFortress.private_key,
  });
  // The "attacker" master is a perfectly well-formed master the guardians once
  // signed for in a ceremony that was later abandoned.
  const attackerMaster = generateFortressMaster();
  return { oldFortress, guardians, roster, attackerMaster };
}

type Fixture = ReturnType<typeof makeFixture>;

/**
 * Produce a real 3-of-5-signed rotation payload for an arbitrary collection
 * context and rotated_at. Every signature is genuine; only the WINDOW varies,
 * which is the whole point — the defect was never a signature problem.
 */
function signRotation(params: {
  fx?: Fixture;
  context: GuardianRevokeQuorumContext;
  rotated_at: string;
}): {
  payload: MasterRotationPayload;
  pinned_master: Fixture["oldFortress"]["public"];
  pinned_roster: Fixture["roster"];
  fx: Fixture;
} {
  const fx = params.fx ?? makeFixture();
  const { oldFortress, guardians, roster, attackerMaster } = fx;
  const newMaster = {
    ...attackerMaster.public,
    fortress_id: oldFortress.public.fortress_id,
  };
  const input = buildGuardianMasterRotationQuorumInput({
    context: params.context,
    old_master_pubkey: oldFortress.public.public_key,
    new_master_pubkey: newMaster,
    rotated_at: params.rotated_at,
    fortress_id: oldFortress.public.fortress_id,
  });
  const guardian_signatures = guardians
    .slice(0, 3)
    .map((g) =>
      signMasterRotationAsGuardian({
        input,
        guardian_id: g.identity.guardian_id,
        guardian_private_key: g.private_key,
      })
    );
  const payload = buildMasterRotationPayload({
    quorum_context: params.context,
    old_master_pubkey: oldFortress.public.public_key,
    new_master_pubkey: newMaster,
    rotated_at: params.rotated_at,
    fortress_id: oldFortress.public.fortress_id,
    guardian_signatures,
    pinned_roster: roster,
  });
  return {
    payload,
    pinned_master: oldFortress.public,
    pinned_roster: roster,
    fx,
  };
}

/** A context opened `agoMs` in the past with the default 4h lifetime. */
function contextOpenedAgo(agoMs: number): GuardianRevokeQuorumContext {
  return mintRevokeCollectionContext({ now: new Date(Date.now() - agoMs) });
}

// ═══════════════════════════════════════════════════════════════════════
// The core requirement — the relying side refuses a lapsed or signer-selected
// window, on artifacts whose signatures are all genuine
// ═══════════════════════════════════════════════════════════════════════

describe("QI-SIBLING-02 — relying side refuses a stale rotation quorum", () => {
  it("REFUSES a rotation quorum whose collection window closed five years ago", () => {
    const fiveYears = 5 * 365 * 24 * HOUR_MS;
    const { payload, pinned_master, pinned_roster } = signRotation({
      context: contextOpenedAgo(fiveYears),
      rotated_at: new Date(Date.now() - fiveYears).toISOString(),
    });

    expect(() =>
      acceptMasterRotation({
        payload,
        pinned_master,
        pinned_roster,
        now: new Date(),
      })
    ).toThrow(QuorumFreshnessError);
  });

  it("REFUSES a rotation quorum dated far in the future (signer picking its own validity)", () => {
    // A context minted a year from now, with a rotated_at to match: the whole
    // artifact is internally consistent and correctly signed, and is refused
    // purely on the relying party's clock.
    const oneYearAhead = new Date(Date.now() + 365 * 24 * HOUR_MS);
    const { payload, pinned_master, pinned_roster } = signRotation({
      context: mintRevokeCollectionContext({ now: oneYearAhead }),
      rotated_at: oneYearAhead.toISOString(),
    });

    expect(() =>
      acceptMasterRotation({
        payload,
        pinned_master,
        pinned_roster,
        now: new Date(),
      })
    ).toThrow(QuorumFreshnessError);
  });

  it("REFUSES a rotation quorum whose timestamp is not a timestamp at all", () => {
    const { payload, pinned_master, pinned_roster } = signRotation({
      context: mintRevokeCollectionContext(),
      rotated_at: "whenever-the-attacker-likes",
    });

    expect(() =>
      acceptMasterRotation({
        payload,
        pinned_master,
        pinned_roster,
        now: new Date(),
      })
    ).toThrow(QuorumFreshnessError);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// The guard's positive half — an unproven guard is not evidence
// ═══════════════════════════════════════════════════════════════════════

describe("QI-SIBLING-02 — a legitimate rotation still accepts", () => {
  it("accepts a rotation inside its collection window", () => {
    const context = mintRevokeCollectionContext();
    const { payload, pinned_master, pinned_roster, fx } = signRotation({
      context,
      rotated_at: new Date().toISOString(),
    });

    const result = acceptMasterRotation({
      payload,
      pinned_master,
      pinned_roster,
      now: new Date(),
    });
    expect(result.accepted_new_master.public_key).toBe(
      fx.attackerMaster.public.public_key
    );
  });

  it("accepts a SLOW ceremony: guardians signing 20h apart, executed at the 23rd hour", () => {
    // The compatibility question the window has to answer. The operator widens
    // the collection lifetime to the cap; the guardians sign hours apart; the
    // operator executes near the end of day one. The relying side accepts.
    const openedAgo = 23 * HOUR_MS;
    const context = mintRevokeCollectionContext({
      now: new Date(Date.now() - openedAgo),
      requested_lifetime_ms: REVOKE_QUORUM_MAX_LIFETIME_MS,
    });
    const { payload, pinned_master, pinned_roster } = signRotation({
      context,
      // rotated_at is stamped at execute time, 23h after collection opened.
      rotated_at: new Date().toISOString(),
    });

    expect(() =>
      acceptMasterRotation({
        payload,
        pinned_master,
        pinned_roster,
        now: new Date(),
      })
    ).not.toThrow();
  });

  it("REFUSES the same ceremony one hour past the cap", () => {
    const context = mintRevokeCollectionContext({
      now: new Date(Date.now() - 25 * HOUR_MS),
      requested_lifetime_ms: REVOKE_QUORUM_MAX_LIFETIME_MS,
    });
    const { payload, pinned_master, pinned_roster } = signRotation({
      context,
      rotated_at: new Date(Date.now() - 25 * HOUR_MS).toISOString(),
    });

    expect(() =>
      acceptMasterRotation({
        payload,
        pinned_master,
        pinned_roster,
        now: new Date(),
      })
    ).toThrow(QuorumFreshnessError);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Fail-before probes — plant a divergence, prove the guard catches it
// ═══════════════════════════════════════════════════════════════════════

describe("QI-SIBLING-02 — planted divergences are refused", () => {
  it("REFUSES the v1 shape (quorum signatures with no window) under the clean break", () => {
    const { payload, pinned_master, pinned_roster } = signRotation({
      context: mintRevokeCollectionContext(),
      rotated_at: new Date().toISOString(),
    });
    // Strip the window: exactly the retired v1 payload, still perfectly signed.
    const v1Payload: MasterRotationPayload = { ...payload };
    delete v1Payload.quorum_context;

    expect(() =>
      acceptMasterRotation({
        payload: v1Payload,
        pinned_master,
        pinned_roster,
        now: new Date(),
      })
    ).toThrow(/v1-shape rotation quorum/);
  });

  it("REFUSES a signer-selected lifetime longer than the cap", () => {
    // The generator clamps, so this window can only exist if the payload was
    // hand-crafted — which is precisely the rule-10 case: the attacker IS the
    // generator, so the relying side re-enforces the cap itself.
    const initiated = new Date();
    const context: GuardianRevokeQuorumContext = {
      ceremony_id: mintRevokeCollectionContext().ceremony_id,
      initiated_at: initiated.toISOString(),
      expires_at: new Date(
        initiated.getTime() + REVOKE_QUORUM_MAX_LIFETIME_MS + HOUR_MS
      ).toISOString(),
    };
    const { payload, pinned_master, pinned_roster } = signRotation({
      context,
      rotated_at: initiated.toISOString(),
    });

    expect(() =>
      acceptMasterRotation({
        payload,
        pinned_master,
        pinned_roster,
        now: new Date(),
      })
    ).toThrow(/exceeds max/);
  });

  it("REFUSES a rotated_at forward-dated outside its own window", () => {
    // Everything is signed and the window is live; only the operator-visible
    // stamp lies. Left unchecked it would land verbatim in the audit boundary
    // entry, so the audit trail would faithfully record a rotation that never
    // happened at that moment.
    const context = mintRevokeCollectionContext();
    const { payload, pinned_master, pinned_roster } = signRotation({
      context,
      rotated_at: new Date(
        Date.parse(context.expires_at) + HOUR_MS
      ).toISOString(),
    });

    expect(() =>
      acceptMasterRotation({
        payload,
        pinned_master,
        pinned_roster,
        now: new Date(),
      })
    ).toThrow(/rotated_at is past expires_at/);
  });

  it("REFUSES a rotated_at back-dated before its own window", () => {
    const context = mintRevokeCollectionContext();
    const { payload, pinned_master, pinned_roster } = signRotation({
      context,
      rotated_at: new Date(
        Date.parse(context.initiated_at) - REVOKE_QUORUM_CLOCK_SKEW_MS - HOUR_MS
      ).toISOString(),
    });

    expect(() =>
      acceptMasterRotation({
        payload,
        pinned_master,
        pinned_roster,
        now: new Date(),
      })
    ).toThrow(/precedes initiated_at/);
  });

  it("REFUSES a revoke-schema context presented as a rotation context (cross-ceremony splice)", () => {
    const context = mintRevokeCollectionContext();
    const { payload, pinned_master, pinned_roster } = signRotation({
      context,
      rotated_at: new Date().toISOString(),
    });
    const spliced: MasterRotationPayload = {
      ...payload,
      quorum_context: {
        ...payload.quorum_context!,
        // The revoke separator, on an otherwise valid live rotation.
        input_schema:
          GUARDIAN_REVOKE_QUORUM_SCHEMA_V2 as unknown as typeof GUARDIAN_MASTER_ROTATION_QUORUM_SCHEMA_V2,
      },
    };

    expect(() =>
      acceptMasterRotation({
        payload: spliced,
        pinned_master,
        pinned_roster,
        now: new Date(),
      })
    ).toThrow(/schema_missing_or_wrong/);
  });

  it("REFUSES guardian signatures collected for a REVOKE presented as a rotation quorum", () => {
    // Byte-level proof that the domain separator does its job: real guardian
    // signatures over a live revoke input cannot authorize a master swap.
    const fx = makeFixture();
    const context = mintRevokeCollectionContext();
    const revokeInput = buildGuardianRevokeQuorumInput({
      context,
      target_node_id: "node-b",
      reason: "compromised",
      fortress_id: fx.oldFortress.public.fortress_id,
    });
    const revokeSigs = fx.guardians.slice(0, 3).map((g) => ({
      guardian_pubkey: g.identity.public_key,
      signature: signMasterRotationAsGuardian({
        input: revokeInput,
        guardian_id: g.identity.guardian_id,
        guardian_private_key: g.private_key,
      }).signature,
    }));
    const forged: MasterRotationPayload = {
      old_master_pubkey: fx.oldFortress.public.public_key,
      new_master_pubkey: {
        ...fx.attackerMaster.public,
        fortress_id: fx.oldFortress.public.fortress_id,
      },
      quorum_signatures: revokeSigs,
      rotated_at: new Date().toISOString(),
      quorum_context: {
        input_schema: GUARDIAN_MASTER_ROTATION_QUORUM_SCHEMA_V2,
        ceremony_id: context.ceremony_id,
        initiated_at: context.initiated_at,
        expires_at: context.expires_at,
      },
    };

    expect(() =>
      acceptMasterRotation({
        payload: forged,
        pinned_master: fx.oldFortress.public,
        pinned_roster: fx.roster,
        now: new Date(),
      })
    ).toThrow(/does not verify/);
  });

  it("REFUSES a ceremony_id swapped after signing (the nonce rides inside the signed bytes)", () => {
    const context = mintRevokeCollectionContext();
    const { payload, pinned_master, pinned_roster } = signRotation({
      context,
      rotated_at: new Date().toISOString(),
    });
    const tampered: MasterRotationPayload = {
      ...payload,
      quorum_context: {
        ...payload.quorum_context!,
        ceremony_id: mintRevokeCollectionContext().ceremony_id,
      },
    };

    expect(() =>
      acceptMasterRotation({
        payload: tampered,
        pinned_master,
        pinned_roster,
        now: new Date(),
      })
    ).toThrow(/does not verify/);
  });

  it("REFUSES a new-master object whose created_at was edited after signing", () => {
    // The quorum signs the WHOLE new-master object, not just its public_key.
    // `created_at` rides the wire and lands in the receiver's pinned master
    // record, so narrowing the signed bytes to the bare key would drop a
    // consumed field out of quorum coverage.
    const { payload, pinned_master, pinned_roster } = signRotation({
      context: mintRevokeCollectionContext(),
      rotated_at: new Date().toISOString(),
    });
    const tampered: MasterRotationPayload = {
      ...payload,
      new_master_pubkey: {
        ...payload.new_master_pubkey,
        created_at: "2000-01-01T00:00:00.000Z",
      },
    };

    expect(() =>
      acceptMasterRotation({
        payload: tampered,
        pinned_master,
        pinned_roster,
        now: new Date(),
      })
    ).toThrow(/does not verify/);
  });

  it("REFUSES a malformed context element rather than dereferencing it (rule 11)", () => {
    const { payload, pinned_master, pinned_roster } = signRotation({
      context: mintRevokeCollectionContext(),
      rotated_at: new Date().toISOString(),
    });
    const malformed = {
      ...payload,
      quorum_context: {
        input_schema: GUARDIAN_MASTER_ROTATION_QUORUM_SCHEMA_V2,
        ceremony_id: "not-32-hex",
        initiated_at: payload.quorum_context!.initiated_at,
        expires_at: payload.quorum_context!.expires_at,
      },
    } as MasterRotationPayload;

    expect(() =>
      acceptMasterRotation({
        payload: malformed,
        pinned_master,
        pinned_roster,
        now: new Date(),
      })
    ).toThrow(MasterRotationError);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Wired-consumer proof (AGENTS.md rule 4) — the SHIPPED receiver, not the
// verifier in isolation. A capability with no production consumer is not
// shipped, whatever its own tests say.
// ═══════════════════════════════════════════════════════════════════════

// The receiver's `pending` map is deliberately UNBOUNDED on this branch (see the
// declaration's own comment and the register row it cites), so this suite has no
// capacity or flood test. That is a stated gap, not an untested claim: two
// admission bounds were attempted and both failed a gate, and a test asserting a
// bound that does not exist would be the same decorative-coverage shape the
// subtraction exists to end. The regression test below guards the opposite
// direction — that no future admission-only cap can silence this receiver.
describe("QI-SIBLING-02 wired consumer — MasterRotationReceiver enforces the window", () => {
  async function bootReceiverScenario(
    rotationContext: GuardianRevokeQuorumContext,
    options: {
      /**
       * Deliver this many DECOY bundle unicasts at distinct `rotated_at` keys
       * BEFORE the real one. Each decoy is a genuine bundle (wrapped under the
       * old per-node transport key), so each parks a bundle-bearing entry in the
       * receiver's `pending` map and none of them can ever be evicted by a policy
       * that preserves the bundle half.
       */
      prefill_bundles?: number;
      /** Replace the ack listener with one that throws. */
      throwing_ack_listener?: boolean;
      /** Replace `onEnvelopeRejected` with one that throws. */
      throwing_rejection_hook?: boolean;
    } = {}
  ) {
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
    const oldMaster = result.bootstrap.master_public;
    const guardians = ["g1", "g2", "g3", "g4", "g5"].map(makeGuardian);
    const roster = issueGuardianRoster({
      m: DEFAULT_GUARDIAN_M,
      n: DEFAULT_GUARDIAN_N,
      guardians: guardians.map((g) => g.identity),
      fortress_id: oldMaster.fortress_id,
      version: 1,
      master_private_key: result.bootstrap.master_private_key,
    });

    const newMasterKp = generateKeypair();
    const newMasterPublic: FortressMasterPublicKey = {
      public_key: toBase64url(newMasterKp.publicKey),
      fortress_id: oldMaster.fortress_id,
      created_at: new Date().toISOString(),
    };
    // rotated_at is stamped inside the ceremony's own window so the ONLY thing
    // separating the two scenarios below is whether that window is still open.
    const rotatedAt = new Date(
      Date.parse(rotationContext.initiated_at) + 60_000
    ).toISOString();

    const input = buildGuardianMasterRotationQuorumInput({
      context: rotationContext,
      old_master_pubkey: oldMaster.public_key,
      new_master_pubkey: newMasterPublic,
      rotated_at: rotatedAt,
      fortress_id: oldMaster.fortress_id,
    });
    const payload = buildMasterRotationPayload({
      quorum_context: rotationContext,
      old_master_pubkey: oldMaster.public_key,
      new_master_pubkey: newMasterPublic,
      rotated_at: rotatedAt,
      fortress_id: oldMaster.fortress_id,
      guardian_signatures: guardians.slice(0, 3).map((g) =>
        signMasterRotationAsGuardian({
          input,
          guardian_id: g.identity.guardian_id,
          guardian_private_key: g.private_key,
        })
      ),
      pinned_roster: roster,
    });

    const newPrincipalKp = generateKeypair();
    const cascade = rekeyOnMasterRotation({
      new_master_secret: newMasterKp.privateKey,
      new_master_public: newMasterPublic,
      old_node_certificates: [result.bootstrap.node_certificate],
      old_root_principal: result.bootstrap.root_principal_certificate,
      new_root_principal_private_key: newPrincipalKp.privateKey,
      new_root_principal_public_key: newPrincipalKp.publicKey,
    });
    const wrapBundleAt = (at: string) =>
      wrapMasterRotationBundle({
        plaintext: {
          new_master_secret: toBase64url(newMasterKp.privateKey),
          re_issued_self_cert: cascade.re_issued_node_certificates[0]!,
          new_root_principal_cert: cascade.new_root_principal_certificate,
          rotated_at: at,
          new_master_pubkey: newMasterPublic.public_key,
        },
        old_fortress_master_secret: result.bootstrap.master_private_key,
        target_node_id: "node-1",
        target_node_mode: "local",
        fortress_id: oldMaster.fortress_id,
      });
    const envelope = wrapBundleAt(rotatedAt);

    const acks: unknown[] = [];
    const receiver = new MasterRotationReceiver({
      node: result.node,
      node_id: "node-1",
      node_mode: "local",
      fortress_id: oldMaster.fortress_id,
      old_fortress_master_secret: () => result.bootstrap.master_private_key,
      pinned_old_master: () => oldMaster,
      pinned_guardian_roster: () => roster,
      node_private_key: result.bootstrap.node_private_key,
    });
    if (options.throwing_ack_listener) {
      // Registered FIRST so the assertion is that a throwing subscriber does not
      // starve the one after it, not merely that the loop survives its last
      // iteration.
      receiver.onAckEmit(() => {
        throw new Error("ack listener exploded");
      });
    }
    receiver.onAckEmit((ack) => acks.push(ack));
    // The refusal surface the wiring layer consumes. Captured here because the
    // whole point of the fix is that a refusing node is DISTINGUISHABLE from one
    // that never received the broadcast.
    const rejections: Array<{
      error: Error;
      event_type: string;
      rejection_origin: RejectionOrigin;
      reason_class: RejectionReasonClass;
    }> = [];
    result.node.onEnvelopeRejected = (info) => {
      rejections.push(info);
      // In production this hook reaches signing and counter I/O, so it CAN
      // throw; the receiver must contain that rather than converting it into an
      // unhandled rejection under the `void`-calling reference wiring.
      if (options.throwing_rejection_hook) {
        throw new Error("rejection hook exploded");
      }
    };
    for (let i = 0; i < (options.prefill_bundles ?? 0); i++) {
      await receiver.handleIncomingUnicast(
        "node-1",
        JSON.stringify(
          wrapBundleAt(`2026-04-01T00:00:00.${String(i).padStart(3, "0")}Z`)
        )
      );
    }
    await receiver.handleIncomingUnicast("node-1", JSON.stringify(envelope));

    return {
      node: result.node,
      receiver,
      payload,
      acks,
      rejections,
      oldMaster,
      newMasterPublic,
    };
  }

  /** Denial entries this node has sealed but not yet flushed. */
  function denialEntries(node: MeshNode): unknown[] {
    return node
      .peekPendingAuditEntries()
      .filter(
        (e) =>
          (e.payload as { operation?: string } | undefined)?.operation ===
          "master_rotation_denied"
      );
  }

  it("installs a rotation whose window is open", async () => {
    const s = await bootReceiverScenario(mintRevokeCollectionContext());
    await s.receiver.handleIncomingMasterRotationBroadcast(s.payload, {
      emitter_node: PEER,
    });
    expect(s.node.getPinnedMaster().public_key).toBe(
      s.newMasterPublic.public_key
    );
    expect(s.acks).toHaveLength(1);
    expect(s.rejections).toHaveLength(0);
  });

  it("REFUSES a rotation whose window closed, leaves the pinned master untouched, and SURFACES the refusal", async () => {
    // Failure-mode note: a receiver that merely logged and continued here would
    // look identical in the ack stream to one that never got the broadcast. The
    // assertion that matters is the pinned master, plus a refusal an operator
    // can actually see.
    const s = await bootReceiverScenario(
      contextOpenedAgo(REVOKE_QUORUM_MAX_LIFETIME_MS + HOUR_MS)
    );
    // Never throws: the reference wiring calls this as `void ...`, so a
    // propagating refusal would be an unhandled rejection an authenticated peer
    // can trigger at will.
    await expect(
      s.receiver.handleIncomingMasterRotationBroadcast(s.payload, {
        emitter_node: PEER,
      })
    ).resolves.toBeUndefined();
    expect(s.node.getPinnedMaster().public_key).toBe(s.oldMaster.public_key);
    expect(s.acks).toHaveLength(0);
    expect(s.rejections).toHaveLength(1);
    expect(s.rejections[0]!.event_type).toBe("master_rotation");
    expect(s.rejections[0]!.rejection_origin).toBe(PEER);
    expect(s.rejections[0]!.error).toBeInstanceOf(QuorumFreshnessError);
    // QI-02-F12: a lapsed collection window is a TIMING fact about two clocks,
    // so the boundary must classify it as a freshness refusal. The detector
    // renders that as PEER_REFUSED/degraded rather than accusing this
    // authentic initiator of compromise.
    expect(s.rejections[0]!.reason_class).toBe(
      REJECTION_REASON_CLASS.FRESHNESS_REFUSED
    );
    // The message names the ceremony it is actually refusing — it used to say
    // "revoke quorum context" for a master rotation, which told the operator
    // the wrong ceremony had failed.
    expect(s.rejections[0]!.error.message).toContain(
      GUARDIAN_MASTER_ROTATION_QUORUM_SCHEMA_V2
    );
    expect(s.rejections[0]!.error.message).not.toContain(
      GUARDIAN_REVOKE_QUORUM_SCHEMA_V2
    );
    // And it is durably recorded, keyed on the authenticated emitter.
    expect(denialEntries(s.node)).toHaveLength(1);
  });

  it("still installs after MANY prior bundle-bearing entries — an admission-only cap must never become a permanent refusal", async () => {
    // REGRESSION GUARD for the subtracted bound (register row QI-02-F11). The
    // removed admission cap refused an insert once every retained entry held a
    // bundle, and NOTHING in this receiver ever removes a bundle-bearing entry:
    // no sweep, no TTL, no delete after a successful install. The result was a
    // node that silently stopped installing rotations for the life of the
    // instance, which is the two-master split the execute-time gate exists to
    // prevent. This test drives well past the cap that was in place and asserts
    // the legitimate rotation still lands.
    //
    // FAILURE-MODE NOTE for whoever bounds this map next: the symptom of getting
    // it wrong is nothing at all on the receiving node. The rotation just never
    // arrives, and the operator sees a healthy node pinned to the old master.
    const s = await bootReceiverScenario(mintRevokeCollectionContext(), {
      prefill_bundles: 32,
    });
    await s.receiver.handleIncomingMasterRotationBroadcast(s.payload, {
      emitter_node: PEER,
    });
    expect(s.node.getPinnedMaster().public_key).toBe(
      s.newMasterPublic.public_key
    );
    expect(s.acks).toHaveLength(1);
    expect(s.rejections).toHaveLength(0);
  });

  it("a THROWING onEnvelopeRejected hook cannot turn a refusal into an unhandled rejection", async () => {
    // MUTATION-PROOF TARGET: fails if the try/catch around `onEnvelopeRejected`
    // in `surfaceBroadcastRefusal` is deleted. The hook is caller-supplied and in
    // production reaches signing and counter I/O, and the reference wiring calls
    // the receiver as `void ...`, so an unwrapped hook hands an authenticated
    // peer the exact crash the refusal path was built to close: replay a stale
    // rotation, the hook throws, the promise rejects, nobody is awaiting it.
    const s = await bootReceiverScenario(
      contextOpenedAgo(REVOKE_QUORUM_MAX_LIFETIME_MS + HOUR_MS),
      { throwing_rejection_hook: true }
    );
    await expect(
      s.receiver.handleIncomingMasterRotationBroadcast(s.payload, {
        emitter_node: PEER,
      })
    ).resolves.toBeUndefined();
    // The refusal still happened, was still attributed to the authenticated
    // emitter, and the durable record was still sealed BEFORE the hook ran, so
    // a broken hook loses its own delivery and nothing else.
    expect(s.node.getPinnedMaster().public_key).toBe(s.oldMaster.public_key);
    expect(s.rejections).toHaveLength(1);
    expect(s.rejections[0]!.rejection_origin).toBe(PEER);
    expect(denialEntries(s.node)).toHaveLength(1);
  });

  it("a THROWING ack listener neither rejects the install path nor starves the next listener", async () => {
    // MUTATION-PROOF TARGET: fails if the per-listener try/catch in `emitAck` is
    // deleted. Same `void`-wiring hazard as above on the success half, plus the
    // subscriber-starvation half: the throwing listener is registered FIRST, so
    // an unisolated loop never reaches the one that records the ack.
    const s = await bootReceiverScenario(mintRevokeCollectionContext(), {
      throwing_ack_listener: true,
    });
    await expect(
      s.receiver.handleIncomingMasterRotationBroadcast(s.payload, {
        emitter_node: PEER,
      })
    ).resolves.toBeUndefined();
    expect(s.node.getPinnedMaster().public_key).toBe(
      s.newMasterPublic.public_key
    );
    expect(s.acks).toHaveLength(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Initiator-side pre-broadcast gate — the confirm-to-execute gap is
// operator-paced and unbounded, so confirm() alone enforces nothing about
// the moment the fortress actually swaps masters.
// ═══════════════════════════════════════════════════════════════════════

describe("QI-SIBLING-02 — execute() re-asserts the window before any wire traffic", () => {
  /**
   * Boot one node, a guardian roster, and a fully signed rotation whose
   * collection window is open NOW. The caller then moves the clock and calls
   * execute.
   */
  async function bootCeremonyScenario() {
    const transport = new InMemoryTransport();
    const handle = transport.attach("node-1");
    // A second attached peer is the broadcast OBSERVER: InMemoryTransport never
    // delivers a broadcast back to its emitter, so counting here is the only way
    // to see whether the rotation actually left the node.
    const observer = transport.attach("observer");
    const broadcasts: SignedEvent[] = [];
    observer.subscribe((evt) => {
      if (evt.event_type === "master_rotation") broadcasts.push(evt);
    });

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
    const oldMaster = result.bootstrap.master_public;
    const guardians = ["g1", "g2", "g3", "g4", "g5"].map(makeGuardian);
    const roster = issueGuardianRoster({
      m: DEFAULT_GUARDIAN_M,
      n: DEFAULT_GUARDIAN_N,
      guardians: guardians.map((g) => g.identity),
      fortress_id: oldMaster.fortress_id,
      version: 1,
      master_private_key: result.bootstrap.master_private_key,
    });

    const newMasterKp = generateKeypair();
    const newMasterPublic: FortressMasterPublicKey = {
      public_key: toBase64url(newMasterKp.publicKey),
      fortress_id: oldMaster.fortress_id,
      created_at: new Date().toISOString(),
    };
    const newRootPrincipalKp = generateKeypair();
    const quorumContext = mintRevokeCollectionContext();
    const rotatedAt = new Date().toISOString();
    const input = buildGuardianMasterRotationQuorumInput({
      context: quorumContext,
      old_master_pubkey: oldMaster.public_key,
      new_master_pubkey: newMasterPublic,
      rotated_at: rotatedAt,
      fortress_id: oldMaster.fortress_id,
    });
    const sigs = guardians.slice(0, 3).map((g) =>
      signMasterRotationAsGuardian({
        input,
        guardian_id: g.identity.guardian_id,
        guardian_private_key: g.private_key,
      })
    );

    // Counting transport wrapper: a unicast that escapes the gate is a peer
    // holding the new master secret while the initiator is refusing to install.
    let unicasts = 0;
    const countingTransport: MeshTransport = {
      broadcast: (evt) => handle.broadcast(evt),
      unicast: (to, message) => {
        unicasts += 1;
        return handle.unicast(to, message);
      },
      subscribe: (h) => handle.subscribe(h),
      subscribeUnicast: (h) => handle.subscribeUnicast(h),
    };

    const ceremony = MasterRotationCeremony.propose({
      proposal: {
        new_master_public: newMasterPublic,
        new_master_secret: newMasterKp.privateKey,
        new_root_principal_private_key: newRootPrincipalKp.privateKey,
        new_root_principal_public_key: newRootPrincipalKp.publicKey,
        guardian_signatures: sigs,
        quorum_context: quorumContext,
        rotated_at: rotatedAt,
        ack_timeout_ms: 50,
      },
      ctx: {
        node: result.node,
        transport: countingTransport,
        old_fortress_master_secret: result.bootstrap.master_private_key,
        old_root_principal_cert: result.bootstrap.root_principal_certificate,
        peers: [],
        pinned_roster: roster,
        pinned_old_master: oldMaster,
        emit_ctx: {
          emitter_node: "node-1",
          emitter_principal:
            result.bootstrap.root_principal_certificate.principal_id,
          fortress_id: oldMaster.fortress_id,
          node_private_key: result.bootstrap.node_private_key,
          counters: new InMemoryCounterStore(),
        },
        self_node_cert: result.bootstrap.node_certificate,
      },
    });

    const ackSub = createMasterRotationAckSubscription({
      fortress_id: oldMaster.fortress_id,
      lookup_pre_rotation_pubkey: () => undefined,
    });

    return {
      node: result.node,
      ceremony,
      ackSub,
      oldMaster,
      newMasterPublic,
      quorumContext,
      broadcasts,
      unicastCount: () => unicasts,
    };
  }

  it("confirms inside the window, then REFUSES to execute outside it — nothing broadcast, nothing installed", async () => {
    // MUTATION-PROOF TARGET: delete the step-0 gate in
    // MasterRotationCeremony.execute and this test fails on all four
    // assertions — the rotation broadcasts, the initiator installs the new
    // master, and the raised error becomes an ack-timeout instead of a
    // freshness refusal.
    const s = await bootCeremonyScenario();
    s.ceremony.confirm({ note: "operator confirms while the window is open" });
    expect(s.ceremony.state).toBe("confirmed");

    // The operator walks away and clicks execute after the collection window
    // has closed. Fake timers move only the clock; execute throws before any
    // timer is ever scheduled.
    vi.useFakeTimers();
    try {
      vi.setSystemTime(
        new Date(Date.parse(s.quorumContext.expires_at) + HOUR_MS)
      );
      await expect(
        s.ceremony.execute({ ack_subscription: s.ackSub })
      ).rejects.toThrow(QuorumFreshnessError);
    } finally {
      vi.useRealTimers();
    }

    // The whole point: a fortress that installs a new master while every peer
    // refuses the same rotation is split across two masters, and leaving that
    // state needs a fresh guardian quorum.
    expect(s.node.getPinnedMaster().public_key).toBe(s.oldMaster.public_key);
    expect(s.broadcasts).toHaveLength(0);
    expect(s.unicastCount()).toBe(0);
    expect(s.ceremony.state).toBe("failed");

    s.ackSub.close();
  });

  it("gates on the bytes it is ABOUT TO EMIT: a diverged payload context refuses even while the proposal is fresh", async () => {
    // MUTATION-PROOF TARGET for the round-2 emit-site correction, which had a
    // 12-line rationale and no test: repoint execute's step-0 parse from
    // `prepared.payload.quorum_context` back to `prepared.proposal.quorum_context`
    // and this test fails while the whole rest of the suite stays green. That is
    // the same shape as the round-0 bound whose test stayed green when its
    // mitigation was deleted, and it is what this test exists to end.
    //
    // The two representations agree today, because `propose` projects one from
    // the other, so the ONLY way to observe which one the gate reads is to make
    // them disagree. That divergence is planted here rather than discovered,
    // which is exactly what the invariant protects against: an emit-site gate
    // must assert over the bytes it is about to put on the wire, or a later
    // divergence between the two representations passes the initiator and fails
    // at every receiver — the split-master state, arrived at through a gate that
    // reported success.
    const s = await bootCeremonyScenario();
    s.ceremony.confirm({ note: "operator confirms while the window is open" });

    // Reach past the private field deliberately: no public surface can diverge
    // them, which is the point. `prepared.proposal` is left untouched.
    const internals = s.ceremony as unknown as {
      prepared: {
        payload: MasterRotationPayload;
        proposal: { quorum_context: GuardianRevokeQuorumContext };
      };
    };
    const wire = internals.prepared.payload.quorum_context;
    expect(wire).toBeDefined();
    const lapsedInitiated = new Date(Date.now() - 2 * HOUR_MS).toISOString();
    const lapsedExpires = new Date(Date.now() - HOUR_MS).toISOString();
    wire!.initiated_at = lapsedInitiated;
    wire!.expires_at = lapsedExpires;

    // The in-memory proposal context is STILL FRESH. A gate reading it sees an
    // open window and proceeds; only a gate reading the emitted payload refuses.
    expect(
      Date.parse(internals.prepared.proposal.quorum_context.expires_at)
    ).toBeGreaterThan(Date.now());

    await expect(
      s.ceremony.execute({ ack_subscription: s.ackSub })
    ).rejects.toThrow(QuorumFreshnessError);

    // Same four consequences as the clock-drift case: nothing left the node and
    // the node did not swap its own master.
    expect(s.node.getPinnedMaster().public_key).toBe(s.oldMaster.public_key);
    expect(s.broadcasts).toHaveLength(0);
    expect(s.unicastCount()).toBe(0);
    expect(s.ceremony.state).toBe("failed");

    s.ackSub.close();
  });

  it("executes normally when the window is still open (the gate is not a blanket refusal)", async () => {
    const s = await bootCeremonyScenario();
    s.ceremony.confirm({ note: "operator confirms and executes promptly" });
    const result = await s.ceremony.execute({ ack_subscription: s.ackSub });
    expect(result.new_master_pubkey).toBe(s.newMasterPublic.public_key);
    expect(s.node.getPinnedMaster().public_key).toBe(
      s.newMasterPublic.public_key
    );
    expect(s.broadcasts).toHaveLength(1);
    s.ackSub.close();
  });
});
