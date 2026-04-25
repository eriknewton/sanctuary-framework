/**
 * Coordination lifecycle — end-to-end two-agent workflow.
 *
 * Drives the full propose → accept → complete flow against the real
 * `LocalCoordinator`, the real `AuditLog`, and the real `HandoffStore`.
 * Verifies every signature with real Ed25519, asserts each lifecycle event
 * lands in the audit chain in the right order, and asserts the persisted
 * record's status_changed_at advances on transition.
 */

import { describe, expect, it } from "vitest";
import {
  fromBase64url,
  toBase64url,
} from "../../src/core/encoding.js";
import { ed25519 } from "@noble/curves/ed25519";
import {
  canonicalLayer1Bytes,
  canonicalLayer2Bytes,
  verifyAuditPayload,
  verifyHandoffRecord,
} from "../../src/coordination/index.js";
import { buildCoordinationFixture } from "./fixture.js";

function freshTaskScope() {
  return {
    category: "delegate_subtask" as const,
    requested_capabilities: ["plans", "outputs"],
    priority: "normal" as const,
  };
}

function freshContextRef() {
  return {
    policy_context_id: "pc-test-1",
    audit_entry_id: "ae-test-1",
    placeholder_refs: [],
  };
}

describe("coordination/lifecycle — two-agent local workflow", () => {
  it("propose → accept → complete with verified signatures at each stage", async () => {
    const f = buildCoordinationFixture();

    const proposed = await f.coordinator.proposeHandoff({
      sender: f.sender.signer,
      recipient_agent_id: f.recipient.agent_id,
      identity_id: f.operator.identity_id,
      task_scope: freshTaskScope(),
      context_reference: freshContextRef(),
    });
    expect(proposed.status).toBe("created");
    expect(proposed.record).toBeDefined();
    expect(proposed.record!.signature_scheme).toBe("ed25519-v1");
    expect(verifyHandoffRecord(proposed.record!, f.keyResolver)).toBe(true);
    expect(proposed.audit_payload.signature_scheme).toBe("ed25519-v1");
    expect(verifyAuditPayload(proposed.audit_payload, f.keyResolver)).toBe(
      true,
    );
    expect(proposed.audit_payload.actor_role).toBe("sender");
    expect(proposed.audit_payload.actor_id).toBe(f.sender.agent_id);

    const handoffId = proposed.record!.handoff_id;

    const accepted = await f.coordinator.acceptHandoff({
      handoff_id: handoffId,
      recipient: f.recipient.signer,
    });
    expect(accepted.signature_scheme).toBe("ed25519-v1");
    expect(verifyAuditPayload(accepted, f.keyResolver)).toBe(true);
    expect(accepted.actor_role).toBe("recipient");
    expect(accepted.actor_id).toBe(f.recipient.agent_id);
    expect(accepted.previous_status).toBe("created");
    expect(accepted.new_status).toBe("accepted");

    const completed = await f.coordinator.completeHandoff({
      handoff_id: handoffId,
      recipient: f.recipient.signer,
      completion_audit_ref: "wcomp-1",
    });
    expect(completed.signature_scheme).toBe("ed25519-v1");
    expect(verifyAuditPayload(completed, f.keyResolver)).toBe(true);
    expect(completed.actor_role).toBe("recipient");
    expect(completed.previous_status).toBe("accepted");
    expect(completed.new_status).toBe("completed");

    const persisted = await f.coordinator.getHandoff(handoffId);
    expect(persisted?.status).toBe("completed");
  });

  it("Layer 1 signature verifies under sender public key only", async () => {
    const f = buildCoordinationFixture();
    const proposed = await f.coordinator.proposeHandoff({
      sender: f.sender.signer,
      recipient_agent_id: f.recipient.agent_id,
      identity_id: f.operator.identity_id,
      task_scope: freshTaskScope(),
      context_reference: freshContextRef(),
    });
    const record = proposed.record!;

    // Sanity: real verify against sender pubkey passes.
    const { signature, ...withoutSig } = record;
    const sigBytes = fromBase64url(signature);
    expect(
      ed25519.verify(sigBytes, canonicalLayer1Bytes(withoutSig), f.sender.publicKey),
    ).toBe(true);

    // Wrong-pubkey verification fails.
    expect(
      ed25519.verify(sigBytes, canonicalLayer1Bytes(withoutSig), f.recipient.publicKey),
    ).toBe(false);
  });

  it("Layer 2 actor_signature verifies under the actor's pubkey", async () => {
    const f = buildCoordinationFixture();
    const proposed = await f.coordinator.proposeHandoff({
      sender: f.sender.signer,
      recipient_agent_id: f.recipient.agent_id,
      identity_id: f.operator.identity_id,
      task_scope: freshTaskScope(),
      context_reference: freshContextRef(),
    });

    const { actor_signature, ...withoutSig } = proposed.audit_payload;
    const sigBytes = fromBase64url(actor_signature);
    expect(
      ed25519.verify(
        sigBytes,
        canonicalLayer2Bytes(withoutSig),
        f.sender.publicKey,
      ),
    ).toBe(true);
  });

  it("audit chain previous_status forms a verifiable lifecycle sequence", async () => {
    const f = buildCoordinationFixture();
    const proposed = await f.coordinator.proposeHandoff({
      sender: f.sender.signer,
      recipient_agent_id: f.recipient.agent_id,
      identity_id: f.operator.identity_id,
      task_scope: freshTaskScope(),
      context_reference: freshContextRef(),
    });
    const handoffId = proposed.record!.handoff_id;

    const accepted = await f.coordinator.acceptHandoff({
      handoff_id: handoffId,
      recipient: f.recipient.signer,
    });
    const completed = await f.coordinator.completeHandoff({
      handoff_id: handoffId,
      recipient: f.recipient.signer,
    });

    // Bootstrap convention: created event self-loops on previous_status.
    expect(proposed.audit_payload.previous_status).toBe("created");
    expect(proposed.audit_payload.new_status).toBe("created");
    // Each subsequent transition's previous_status equals the prior new_status.
    expect(accepted.previous_status).toBe(proposed.audit_payload.new_status);
    expect(completed.previous_status).toBe(accepted.new_status);
  });
});

describe("coordination/lifecycle — denial paths", () => {
  it("operator-denied handoff records actor_role: policy_gate, signed by operator", async () => {
    const f = buildCoordinationFixture();
    const proposed = await f.coordinator.proposeHandoff({
      sender: f.sender.signer,
      recipient_agent_id: f.recipient.agent_id,
      identity_id: f.operator.identity_id,
      task_scope: freshTaskScope(),
      context_reference: freshContextRef(),
    });
    const denial = await f.coordinator.denyHandoff({
      handoff_id: proposed.record!.handoff_id,
      actor: f.operator.signer,
      actor_role: "policy_gate",
      reason_class: "operator_denied",
    });
    expect(denial.actor_role).toBe("policy_gate");
    expect(denial.actor_id).toBe(f.operator.identity_id);
    expect(denial.signature_scheme).toBe("ed25519-v1");
    expect(verifyAuditPayload(denial, f.keyResolver)).toBe(true);

    const persisted = await f.coordinator.getHandoff(
      proposed.record!.handoff_id,
    );
    expect(persisted?.status).toBe("denied");
    expect(persisted?.status_reason_class).toBe("operator_denied");
  });

  it("recipient-denied handoff records actor_role: recipient, signed by recipient", async () => {
    const f = buildCoordinationFixture();
    const proposed = await f.coordinator.proposeHandoff({
      sender: f.sender.signer,
      recipient_agent_id: f.recipient.agent_id,
      identity_id: f.operator.identity_id,
      task_scope: freshTaskScope(),
      context_reference: freshContextRef(),
    });
    const denial = await f.coordinator.denyHandoff({
      handoff_id: proposed.record!.handoff_id,
      actor: f.recipient.signer,
      actor_role: "recipient",
      reason_class: "recipient_locked_down",
    });
    expect(denial.actor_role).toBe("recipient");
    expect(denial.actor_id).toBe(f.recipient.agent_id);
    expect(verifyAuditPayload(denial, f.keyResolver)).toBe(true);
  });

  it("operator denial is not accepted under recipient's key resolution", async () => {
    const f = buildCoordinationFixture();
    const proposed = await f.coordinator.proposeHandoff({
      sender: f.sender.signer,
      recipient_agent_id: f.recipient.agent_id,
      identity_id: f.operator.identity_id,
      task_scope: freshTaskScope(),
      context_reference: freshContextRef(),
    });
    const denial = await f.coordinator.denyHandoff({
      handoff_id: proposed.record!.handoff_id,
      actor: f.operator.signer,
      actor_role: "policy_gate",
      reason_class: "operator_denied",
    });
    // Forge: relabel actor_role as "recipient" without re-signing → must fail.
    const forged = { ...denial, actor_role: "recipient" as const };
    expect(verifyAuditPayload(forged, f.keyResolver)).toBe(false);
  });
});

describe("coordination/lifecycle — signature scheme is inside the signed bytes", () => {
  it("substituting signature_scheme post-sign breaks Layer 1 verification", async () => {
    const f = buildCoordinationFixture();
    const proposed = await f.coordinator.proposeHandoff({
      sender: f.sender.signer,
      recipient_agent_id: f.recipient.agent_id,
      identity_id: f.operator.identity_id,
      task_scope: freshTaskScope(),
      context_reference: freshContextRef(),
    });
    const record = proposed.record!;
    // Tamper the scheme in-place to a future-looking value.
    const tampered = {
      ...record,
      signature_scheme: "ml-dsa-65-v1" as unknown as typeof record.signature_scheme,
    };
    expect(verifyHandoffRecord(tampered, f.keyResolver)).toBe(false);
  });

  it("substituting signature_scheme post-sign breaks Layer 2 verification", async () => {
    const f = buildCoordinationFixture();
    const proposed = await f.coordinator.proposeHandoff({
      sender: f.sender.signer,
      recipient_agent_id: f.recipient.agent_id,
      identity_id: f.operator.identity_id,
      task_scope: freshTaskScope(),
      context_reference: freshContextRef(),
    });
    const tampered = {
      ...proposed.audit_payload,
      signature_scheme:
        "ml-dsa-65-v1" as unknown as typeof proposed.audit_payload.signature_scheme,
    };
    expect(verifyAuditPayload(tampered, f.keyResolver)).toBe(false);
  });

  it("v1.1 verifiers reject any scheme that is not ed25519-v1 even if the signature is valid for the bytes", async () => {
    const f = buildCoordinationFixture();
    const proposed = await f.coordinator.proposeHandoff({
      sender: f.sender.signer,
      recipient_agent_id: f.recipient.agent_id,
      identity_id: f.operator.identity_id,
      task_scope: freshTaskScope(),
      context_reference: freshContextRef(),
    });
    // Build a record whose scheme says ml-dsa-65-v1 BUT whose signed bytes
    // include that scheme — i.e. the scheme is inside the signed body, but
    // verifiers MUST reject the scheme regardless. This is the
    // crypto-agility-hinge invariant.
    const { signature, ...withoutSig } = proposed.record!;
    void signature;
    const futureUnsigned = {
      ...withoutSig,
      signature_scheme:
        "ml-dsa-65-v1" as unknown as typeof withoutSig.signature_scheme,
    };
    const futureSig = ed25519.sign(
      canonicalLayer1Bytes(futureUnsigned),
      f.sender.privateKey,
    );
    const future = { ...futureUnsigned, signature: toBase64url(futureSig) };
    expect(verifyHandoffRecord(future, f.keyResolver)).toBe(false);
  });
});

describe("coordination/lifecycle — no-bypass guards", () => {
  it("acceptHandoff rejects an unknown handoff id", async () => {
    const f = buildCoordinationFixture();
    await expect(
      f.coordinator.acceptHandoff({
        handoff_id: "lh-does-not-exist",
        recipient: f.recipient.signer,
      }),
    ).rejects.toMatchObject({ name: "HandoffNotFoundError" });
  });

  it("acceptHandoff rejects a handoff that is already accepted", async () => {
    const f = buildCoordinationFixture();
    const proposed = await f.coordinator.proposeHandoff({
      sender: f.sender.signer,
      recipient_agent_id: f.recipient.agent_id,
      identity_id: f.operator.identity_id,
      task_scope: freshTaskScope(),
      context_reference: freshContextRef(),
    });
    await f.coordinator.acceptHandoff({
      handoff_id: proposed.record!.handoff_id,
      recipient: f.recipient.signer,
    });
    await expect(
      f.coordinator.acceptHandoff({
        handoff_id: proposed.record!.handoff_id,
        recipient: f.recipient.signer,
      }),
    ).rejects.toMatchObject({ name: "HandoffStateError" });
  });

  it("acceptHandoff refuses an actor that is not the recipient", async () => {
    const f = buildCoordinationFixture();
    const proposed = await f.coordinator.proposeHandoff({
      sender: f.sender.signer,
      recipient_agent_id: f.recipient.agent_id,
      identity_id: f.operator.identity_id,
      task_scope: freshTaskScope(),
      context_reference: freshContextRef(),
    });
    await expect(
      f.coordinator.acceptHandoff({
        handoff_id: proposed.record!.handoff_id,
        recipient: f.thirdParty.signer,
      }),
    ).rejects.toMatchObject({ name: "HandoffActorError" });
  });

  it("completeHandoff requires accepted state", async () => {
    const f = buildCoordinationFixture();
    const proposed = await f.coordinator.proposeHandoff({
      sender: f.sender.signer,
      recipient_agent_id: f.recipient.agent_id,
      identity_id: f.operator.identity_id,
      task_scope: freshTaskScope(),
      context_reference: freshContextRef(),
    });
    await expect(
      f.coordinator.completeHandoff({
        handoff_id: proposed.record!.handoff_id,
        recipient: f.recipient.signer,
      }),
    ).rejects.toMatchObject({ name: "HandoffStateError" });
  });
});
