/**
 * QI-SIBLING-02 — master-rotation quorum-input freshness.
 *
 * REPRODUCTION (this file's first describe block was written and run FIRST,
 * against unmodified main at 0004bd98, where all three cases FAILED): the
 * master-rotation quorum input carried a signer-chosen `rotated_at` consumed as
 * data with no relying-side window, so a harvested/abandoned rotation quorum
 * authorized a master swap forever against any node still pinned to the old
 * master. Same rule-10 class as C12-REPLAY, worse consequence: the accepted
 * artifact replaces the fortress master, which is a master ROLLBACK primitive.
 *
 * The fix adopts the C12 collection context + `assertQuorumContextFresh`
 * unchanged (the struct is input-agnostic by design) under its own domain
 * separator.
 */

import { describe, it, expect } from "vitest";
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
  InMemoryNodeKeyStore,
  MeshNode,
  createAutoApproveJoinApprover,
} from "../../src/mesh/lifecycle/index.js";
import { InMemoryTransport } from "../../src/mesh/in-memory-transport.js";
import {
  MasterRotationReceiver,
  wrapMasterRotationBundle,
} from "../../src/mesh/recovery-flows/index.js";
import type {
  FortressMasterPublicKey,
  MasterRotationPayload,
  PrincipalCertificate,
} from "../../src/mesh/types.js";

const HOUR_MS = 60 * 60 * 1000;

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
// Reproduction — these three FAILED against unmodified main (0004bd98)
// ═══════════════════════════════════════════════════════════════════════

describe("QI-SIBLING-02 reproduction — relying side refuses a stale rotation quorum", () => {
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

describe("QI-SIBLING-02 wired consumer — MasterRotationReceiver enforces the window", () => {
  async function bootReceiverScenario(rotationContext: GuardianRevokeQuorumContext) {
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
    const envelope = wrapMasterRotationBundle({
      plaintext: {
        new_master_secret: toBase64url(newMasterKp.privateKey),
        re_issued_self_cert: cascade.re_issued_node_certificates[0]!,
        new_root_principal_cert: cascade.new_root_principal_certificate,
        rotated_at: rotatedAt,
        new_master_pubkey: newMasterPublic.public_key,
      },
      old_fortress_master_secret: result.bootstrap.master_private_key,
      target_node_id: "node-1",
      target_node_mode: "local",
      fortress_id: oldMaster.fortress_id,
    });

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
    receiver.onAckEmit((ack) => acks.push(ack));
    await receiver.handleIncomingUnicast("node-1", JSON.stringify(envelope));

    return { node: result.node, receiver, payload, acks, oldMaster, newMasterPublic };
  }

  it("installs a rotation whose window is open", async () => {
    const s = await bootReceiverScenario(mintRevokeCollectionContext());
    await s.receiver.handleIncomingMasterRotationBroadcast(s.payload);
    expect(s.node.getPinnedMaster().public_key).toBe(
      s.newMasterPublic.public_key
    );
    expect(s.acks).toHaveLength(1);
  });

  it("REFUSES a rotation whose window closed, and leaves the pinned master untouched", async () => {
    // Failure-mode note: a receiver that merely logged and continued here would
    // look identical in the ack stream to one that never got the broadcast. The
    // assertion that matters is the pinned master, not the absence of an ack.
    const s = await bootReceiverScenario(
      contextOpenedAgo(REVOKE_QUORUM_MAX_LIFETIME_MS + HOUR_MS)
    );
    await expect(
      s.receiver.handleIncomingMasterRotationBroadcast(s.payload)
    ).rejects.toThrow(QuorumFreshnessError);
    expect(s.node.getPinnedMaster().public_key).toBe(s.oldMaster.public_key);
    expect(s.acks).toHaveLength(0);
  });

  it("drops a REFUSED broadcast so repeated replays cannot grow receiver state", async () => {
    // Rule 8: freshness enforcement makes refusal the guaranteed outcome for a
    // replay, so the refusal path became the cheap one in this very change.
    const s = await bootReceiverScenario(
      contextOpenedAgo(REVOKE_QUORUM_MAX_LIFETIME_MS + HOUR_MS)
    );
    // Every replay must refuse identically; a retained rejected payload would
    // short-circuit the second call on the cached entry instead.
    for (let i = 0; i < 5; i++) {
      await expect(
        s.receiver.handleIncomingMasterRotationBroadcast(s.payload)
      ).rejects.toThrow(QuorumFreshnessError);
    }
    expect(s.node.getPinnedMaster().public_key).toBe(s.oldMaster.public_key);
    expect(s.acks).toHaveLength(0);
  });
});
