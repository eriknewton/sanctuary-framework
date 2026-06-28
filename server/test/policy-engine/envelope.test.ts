/**
 * Envelope round-trip - compile → pack → verify → decode.
 *
 * Uses real trust-root + real keys from the WP-MVP-3 mesh fixture. No crypto
 * mocked. The SignedEvent<PolicyUpdatePayload> is built with packSignedEvent
 * (from server/src/mesh/envelope.ts) via packPolicyUpdate.
 */

import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { toBase64url } from "../../src/core/encoding.js";
import { canonicalizeToBytes } from "../../src/mesh/canonical-json.js";
import {
  encodePolicyBlob,
} from "../../src/policy-engine/canonical-policy.js";
import {
  packPolicyUpdate,
  unpackPolicyUpdate,
} from "../../src/policy-engine/envelope.js";
import { compileFixturePolicy } from "../../src/policy-engine/compiler-fixture.js";
import {
  PolicyVersionForkError,
  PolicyVersionRollbackError,
  CompiledPolicyShapeError,
} from "../../src/policy-engine/errors.js";
import { buildFortress, verifyCtxFor } from "./fixture.js";

function compiledFor(fortress_id: string, policy_version = 1) {
  return compileFixturePolicy({
    agent_id: "researcher",
    fortress_id,
    policy_version,
    source_english: "Agent researcher may read outputs from agent analyst.",
  });
}

describe("policy-engine/envelope - pack + unpack round-trip", () => {
  it("packs a policy_update event and verifies end-to-end", () => {
    const f = buildFortress();
    const compiled = compiledFor(f.master.public.fortress_id);
    const evt = packPolicyUpdate({
      policy: compiled,
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      monotonic_seq: 1,
      node_private_key: f.nodeKeypair.privateKey,
      principal_private_key: f.principalKeypair.privateKey,
    });
    expect(evt.event_type).toBe("policy_update");
    expect(evt.payload.agent_id).toBe("researcher");
    expect(evt.payload.policy_version).toBe(1);
    expect(evt.payload.valid_from).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(Date.parse(evt.payload.valid_until)).toBeGreaterThan(
      Date.parse(evt.payload.valid_from),
    );

    const result = unpackPolicyUpdate({
      event: evt,
      meshVerifyContext: verifyCtxFor(f),
    });
    expect(result.compiled.slots.outputs.grants).toEqual([
      { counterparty: "analyst", action: "read" },
    ]);
    expect(result.meshVerify.ok).toBe(true);
  });

  it("rejects a tampered payload header (mesh signature catches it)", () => {
    const f = buildFortress();
    const compiled = compiledFor(f.master.public.fortress_id, 1);
    const evt = packPolicyUpdate({
      policy: compiled,
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      monotonic_seq: 1,
      node_private_key: f.nodeKeypair.privateKey,
      principal_private_key: f.principalKeypair.privateKey,
    });
    const tampered = {
      ...evt,
      payload: { ...evt.payload, policy_version: 2 },
    };
    expect(() =>
      unpackPolicyUpdate({
        event: tampered,
        meshVerifyContext: verifyCtxFor(f),
      })
    ).toThrow();
  });

  it("rejects a rollback (received version <= pinned head)", () => {
    const f = buildFortress();
    const compiled = compiledFor(f.master.public.fortress_id, 3);
    const evt = packPolicyUpdate({
      policy: compiled,
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      monotonic_seq: 1,
      node_private_key: f.nodeKeypair.privateKey,
      principal_private_key: f.principalKeypair.privateKey,
    });
    expect(() =>
      unpackPolicyUpdate({
        event: evt,
        meshVerifyContext: verifyCtxFor(f),
        pinnedVersionHead: 5,
      })
    ).toThrow(PolicyVersionRollbackError);
  });

  it("rejects a fork (parent_version does not match pinned head)", () => {
    const f = buildFortress();
    const compiled = compiledFor(f.master.public.fortress_id, 5);
    compiled.parent_version = 2;
    const evt = packPolicyUpdate({
      policy: compiled,
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      monotonic_seq: 1,
      node_private_key: f.nodeKeypair.privateKey,
      principal_private_key: f.principalKeypair.privateKey,
    });
    expect(() =>
      unpackPolicyUpdate({
        event: evt,
        meshVerifyContext: verifyCtxFor(f),
        pinnedVersionHead: 4,
      })
    ).toThrow(PolicyVersionForkError);
  });

  it("rejects a forged blob whose inner fortress_id does not match the envelope", () => {
    const f = buildFortress();
    // Compile two policies: one for the real fortress (used as envelope
    // cover), one for a different fortress (swapped in as forged blob).
    const cover = compiledFor(f.master.public.fortress_id, 1);
    const forged = compileFixturePolicy({
      agent_id: "researcher",
      fortress_id: "other-fortress",
      policy_version: 1,
      source_english: "Agent researcher may read outputs from agent analyst.",
    });
    const evt = packPolicyUpdate({
      policy: cover,
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      monotonic_seq: 1,
      node_private_key: f.nodeKeypair.privateKey,
      principal_private_key: f.principalKeypair.privateKey,
    });
    const forgedPayload = {
      ...evt.payload,
      policy_blob: encodePolicyBlob(forged),
    };
    const payloadHash = toBase64url(sha256(canonicalizeToBytes(forgedPayload)));
    const bodyToSign = {
      protocol_version: evt.protocol_version,
      event_type: evt.event_type,
      event_id: evt.event_id,
      emitter_node: evt.emitter_node,
      emitter_principal: evt.emitter_principal,
      fortress_id: evt.fortress_id,
      causal_parents: evt.causal_parents,
      payload: forgedPayload,
      payload_hash: payloadHash,
      emitted_at: evt.emitted_at,
      monotonic_seq: evt.monotonic_seq,
      extension_envelope: evt.extension_envelope,
    };
    const bytesToSign = canonicalizeToBytes(bodyToSign);
    const forgedEvt = {
      ...bodyToSign,
      node_signature: toBase64url(
        ed25519.sign(bytesToSign, f.nodeKeypair.privateKey)
      ),
      principal_signature: toBase64url(
        ed25519.sign(bytesToSign, f.principalKeypair.privateKey)
      ),
    };
    expect(() =>
      unpackPolicyUpdate({
        event: forgedEvt as typeof evt,
        meshVerifyContext: verifyCtxFor(f),
      })
    ).toThrow(CompiledPolicyShapeError);
  });
});
