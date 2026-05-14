/**
 * Sanctuary Federation Protocol v0.1 — Envelope Tests
 *
 * Exercises packSignedEvent + verifySignedEvent end-to-end. Hard-gate reservations
 * (reserved extension keys, reserved event-type namespaces, forward-compat) are
 * the load-bearing tests for acceptance criterion 10.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url, fromBase64url } from "../../src/core/encoding.js";
import { randomBytes } from "../../src/core/random.js";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { canonicalizeToBytes } from "../../src/mesh/canonical-json.js";
import { CAP_STANDARD_FORTRESS_NODE } from "../../src/mesh/constants.js";
import {
  MeshReservedCapabilityBitError,
  MeshReservedEventTypeError,
  MeshReservedExtensionKeyError,
  MeshSignatureError,
} from "../../src/mesh/errors.js";
import {
  packSignedEvent,
  verifySignedEvent,
  type VerifyContext,
} from "../../src/mesh/envelope.js";
import {
  generateFortressMaster,
  issueNodeIdentityCertificate,
  issuePrincipalCertificate,
} from "../../src/mesh/trust-root.js";
import type {
  NodeIdentityCertificate,
  PolicyUpdatePayload,
  PrincipalCertificate,
  SignedEvent,
} from "../../src/mesh/types.js";

interface TestFortress {
  master: ReturnType<typeof generateFortressMaster>;
  principalKeypair: ReturnType<typeof generateKeypair>;
  principalCert: PrincipalCertificate;
  nodeKeypair: ReturnType<typeof generateKeypair>;
  nodeCert: NodeIdentityCertificate;
}

function buildFortress(principalId = "root"): TestFortress {
  const master = generateFortressMaster();
  const principalKeypair = generateKeypair();
  const principalCert = issuePrincipalCertificate({
    principal_id: principalId,
    principal_pubkey: principalKeypair.publicKey,
    role: "root",
    fortress_id: master.public.fortress_id,
    master_private_key: master.private_key,
  });
  const nodeKeypair = generateKeypair();
  const nodeCert = issueNodeIdentityCertificate({
    node_id: "node-" + toBase64url(randomBytes(4)),
    node_pubkey: nodeKeypair.publicKey,
    node_mode: "local",
    fortress_id: master.public.fortress_id,
    capabilities: CAP_STANDARD_FORTRESS_NODE,
    parent_chain: {
      fortress_master_pubkey: master.public.public_key,
      principal_id: principalId,
      principal_pubkey: principalCert.principal_pubkey,
    },
    principal_private_key: principalKeypair.privateKey,
  });
  return { master, principalKeypair, principalCert, nodeKeypair, nodeCert };
}

function contextFor(f: TestFortress): VerifyContext {
  return {
    pinnedMasterPubkey: f.master.public,
    lookupNodeCert: (id) => (id === f.nodeCert.node_id ? f.nodeCert : undefined),
    lookupPrincipalCert: (id) =>
      id === f.principalCert.principal_id ? f.principalCert : undefined,
  };
}

function signEventBody(
  body: Omit<SignedEvent, "node_signature" | "principal_signature">,
  privateKey: Uint8Array
): SignedEvent {
  return {
    ...body,
    node_signature: toBase64url(
      ed25519.sign(canonicalizeToBytes(body), privateKey)
    ),
  };
}

function signNodeCertWithCapabilities(
  cert: NodeIdentityCertificate,
  capabilities: number,
  principalPrivateKey: Uint8Array
): NodeIdentityCertificate {
  const body = {
    node_id: cert.node_id,
    node_pubkey: cert.node_pubkey,
    node_mode: cert.node_mode,
    fortress_id: cert.fortress_id,
    joined_at: cert.joined_at,
    capabilities,
    parent_chain: cert.parent_chain,
    tee_attestation_hash: cert.tee_attestation_hash,
    delegated_grants: cert.delegated_grants ?? [],
    attestation_lineage_chain: cert.attestation_lineage_chain ?? [],
  };
  return {
    ...body,
    principal_signature: toBase64url(
      ed25519.sign(canonicalizeToBytes(body), principalPrivateKey)
    ),
  };
}

describe("mesh/envelope — basic pack + verify round-trip", () => {
  let f: TestFortress;
  beforeAll(() => {
    f = buildFortress();
  });

  it("packs a valid policy_update envelope and verifies end-to-end", () => {
    const payload: PolicyUpdatePayload = {
      agent_id: "agent-x",
      policy_version: 1,
      policy_blob: "base64url-of-compiled-policy",
    };
    const evt = packSignedEvent<PolicyUpdatePayload>({
      event_type: "policy_update",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      fortress_id: f.master.public.fortress_id,
      payload,
      monotonic_seq: 1,
      node_private_key: f.nodeKeypair.privateKey,
      principal_private_key: f.principalKeypair.privateKey,
    });
    expect(evt.protocol_version).toBe("0.1");
    expect(evt.node_signature).toBeTruthy();
    expect(evt.principal_signature).toBeTruthy();

    const res = verifySignedEvent(evt, contextFor(f));
    expect(res.ok).toBe(true);
    expect(res.recognized_reserved_extension_keys).toEqual([]);
  });

  it("emits monotonic ULID event IDs per emitter", () => {
    const payload: PolicyUpdatePayload = {
      agent_id: "agent-x",
      policy_version: 1,
      policy_blob: "base64url-of-compiled-policy",
    };
    const events = [1, 2, 3].map((seq) =>
      packSignedEvent<PolicyUpdatePayload>({
        event_type: "policy_update",
        emitter_node: f.nodeCert.node_id,
        emitter_principal: f.principalCert.principal_id,
        fortress_id: f.master.public.fortress_id,
        payload: { ...payload, policy_version: seq },
        monotonic_seq: seq,
        node_private_key: f.nodeKeypair.privateKey,
        principal_private_key: f.principalKeypair.privateKey,
      })
    );
    expect(events[0].event_id).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(events[1].event_id > events[0].event_id).toBe(true);
    expect(events[2].event_id > events[1].event_id).toBe(true);
  });

  it("still verifies legacy stored events with non-ULID event IDs", () => {
    const payload: PolicyUpdatePayload = {
      agent_id: "agent-x",
      policy_version: 4,
      policy_blob: "base64url-of-compiled-policy",
    };
    const body = {
      protocol_version: "0.1",
      event_type: "policy_update",
      event_id: "0123456789abcdef0123456789abcdef",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      fortress_id: f.master.public.fortress_id,
      causal_parents: [] as string[],
      payload,
      payload_hash: toBase64url(sha256(canonicalizeToBytes(payload))),
      emitted_at: "2026-05-14T00:00:00.000Z",
      monotonic_seq: 4,
      extension_envelope: {},
    };
    const legacy = signEventBody(body, f.nodeKeypair.privateKey);
    expect(verifySignedEvent(legacy, contextFor(f)).ok).toBe(true);
  });

  it("rejects envelope whose payload has been tampered after signing", () => {
    const evt = packSignedEvent({
      event_type: "heartbeat",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: "system",
      fortress_id: f.master.public.fortress_id,
      payload: { node_state: "active" },
      monotonic_seq: 1,
      node_private_key: f.nodeKeypair.privateKey,
    });
    const tampered = {
      ...evt,
      payload: { node_state: "gated_closed" },
    };
    expect(() => verifySignedEvent(tampered, contextFor(f))).toThrow(
      MeshSignatureError
    );
  });

  it("rejects envelope whose node_signature was produced by a different key", () => {
    const evt = packSignedEvent({
      event_type: "heartbeat",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: "system",
      fortress_id: f.master.public.fortress_id,
      payload: { node_state: "active" },
      monotonic_seq: 1,
      node_private_key: generateKeypair().privateKey,
    });
    expect(() => verifySignedEvent(evt, contextFor(f))).toThrow(
      MeshSignatureError
    );
  });

  it("rejects envelope with unknown protocol_version", () => {
    const evt = packSignedEvent({
      event_type: "heartbeat",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: "system",
      fortress_id: f.master.public.fortress_id,
      payload: { node_state: "active" },
      monotonic_seq: 1,
      node_private_key: f.nodeKeypair.privateKey,
    });
    const fromFuture = { ...evt, protocol_version: "0.2" };
    expect(() => verifySignedEvent(fromFuture, contextFor(f))).toThrow(
      MeshSignatureError
    );
  });
});

describe("mesh/envelope — hard-gate reservations (§10.1, §10.3)", () => {
  let f: TestFortress;
  beforeAll(() => {
    f = buildFortress();
  });

  it("emitter refuses to populate reserved extension keys", () => {
    expect(() =>
      packSignedEvent({
        event_type: "heartbeat",
        emitter_node: f.nodeCert.node_id,
        emitter_principal: "system",
        fortress_id: f.master.public.fortress_id,
        payload: { node_state: "active" },
        monotonic_seq: 1,
        extension_envelope: {
          cross_fortress_read_grant: { anything: "at all" },
        },
        node_private_key: f.nodeKeypair.privateKey,
      })
    ).toThrow(MeshReservedExtensionKeyError);
  });

  it("emitter refuses to emit reserved-namespace event_types", () => {
    for (const et of [
      "EXTENSION_foo",
      "cross_fortress_read_query",
      "multi_master_policy_merge",
    ]) {
      expect(() =>
        packSignedEvent({
          event_type: et,
          emitter_node: f.nodeCert.node_id,
          emitter_principal: f.principalCert.principal_id,
          fortress_id: f.master.public.fortress_id,
          payload: {},
          monotonic_seq: 1,
          node_private_key: f.nodeKeypair.privateKey,
          principal_private_key: f.principalKeypair.privateKey,
        })
      ).toThrow(MeshReservedEventTypeError);
    }
  });

  it("receiver rejects reserved extension keys even with a valid signature", () => {
    // Simulate a v1.x emitter: hand-craft an envelope with a reserved extension
    // key and a valid signature. v0.1 receivers must reject before undefined
    // future semantics enter verified state.
    const v1xPayload = { node_state: "active" };
    const v1xBody = {
      protocol_version: "0.1",
      event_type: "heartbeat",
      event_id: toBase64url(randomBytes(16)),
      emitter_node: f.nodeCert.node_id,
      emitter_principal: "system",
      fortress_id: f.master.public.fortress_id,
      causal_parents: [] as string[],
      payload: v1xPayload,
      payload_hash: toBase64url(sha256(canonicalizeToBytes(v1xPayload))),
      emitted_at: new Date().toISOString(),
      monotonic_seq: 42,
      extension_envelope: {
        cross_fortress_read_query: {
          grant_event_id: "some-grant-id",
          scope: "audit_summary last 24h",
        },
      },
    };
    const v1xEvt = signEventBody(v1xBody, f.nodeKeypair.privateKey);
    expect(() => verifySignedEvent(v1xEvt, contextFor(f))).toThrow(
      MeshReservedExtensionKeyError
    );
  });

  it("signature validates across non-reserved extension-envelope forward-compat boundary", () => {
    // The signature was generated over canonicalize(body including extension_envelope).
    // If canonicalization is deterministic, a v0.1 verifier re-canonicalizes the same
    // bytes and signature verification succeeds for extension keys outside the
    // reserved namespace.
    const v1xPayload = { node_state: "active" };
    const body = {
      protocol_version: "0.1",
      event_type: "heartbeat",
      event_id: "fixed-event-id",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: "system",
      fortress_id: f.master.public.fortress_id,
      causal_parents: [] as string[],
      payload: v1xPayload,
      payload_hash: toBase64url(sha256(canonicalizeToBytes(v1xPayload))),
      emitted_at: "2026-04-21T12:00:00.000Z",
      monotonic_seq: 42,
      extension_envelope: {
        partner_observer_note: {
          arbitrary: "v1.x content",
          nested: { a: 1, b: [2, 3] },
        },
      },
    };
    const bytes = canonicalizeToBytes(body);
    // Re-canonicalize and compare bytes — determinism check.
    const bytes2 = canonicalizeToBytes(body);
    expect(Buffer.from(bytes).equals(Buffer.from(bytes2))).toBe(true);
    const sig = ed25519.sign(bytes, f.nodeKeypair.privateKey);
    const evt: SignedEvent = { ...body, node_signature: toBase64url(sig) };
    const res = verifySignedEvent(evt, contextFor(f));
    expect(res.ok).toBe(true);
  });

  it("receiver rejects reserved-namespace event types even with a valid signature", () => {
    const payload = { node_state: "active" };
    const body = {
      protocol_version: "0.1",
      event_type: "cross_fortress_read_query",
      event_id: "reserved-event-id",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: "system",
      fortress_id: f.master.public.fortress_id,
      causal_parents: [] as string[],
      payload,
      payload_hash: toBase64url(sha256(canonicalizeToBytes(payload))),
      emitted_at: "2026-05-14T00:00:00.000Z",
      monotonic_seq: 43,
      extension_envelope: {},
    };
    const evt = signEventBody(body, f.nodeKeypair.privateKey);
    expect(() => verifySignedEvent(evt, contextFor(f))).toThrow(
      MeshReservedEventTypeError
    );
  });

  it("receiver rejects node certificates with reserved capability bits", () => {
    const payload = { node_state: "active" };
    const body = {
      protocol_version: "0.1",
      event_type: "heartbeat",
      event_id: "reserved-capability-id",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: "system",
      fortress_id: f.master.public.fortress_id,
      causal_parents: [] as string[],
      payload,
      payload_hash: toBase64url(sha256(canonicalizeToBytes(payload))),
      emitted_at: "2026-05-14T00:00:00.000Z",
      monotonic_seq: 44,
      extension_envelope: {},
    };
    const evt = signEventBody(body, f.nodeKeypair.privateKey);
    const certWithReservedCapability = signNodeCertWithCapabilities(
      f.nodeCert,
      CAP_STANDARD_FORTRESS_NODE | 0x08,
      f.principalKeypair.privateKey
    );
    expect(() =>
      verifySignedEvent(evt, {
        ...contextFor(f),
        lookupNodeCert: (id) =>
          id === f.nodeCert.node_id ? certWithReservedCapability : undefined,
      })
    ).toThrow(MeshReservedCapabilityBitError);
  });

  it("receiver rejects envelope whose fortress_id does not match pinned fortress (§10.5)", () => {
    const other = buildFortress("root");
    // Pack under other's keys but claim our fortress_id — this should fail
    // at lookupNodeCert (our roster doesn't know other.nodeCert). And if we
    // claim other.fortress_id, the isolation-guard should fire.
    const evt = packSignedEvent({
      event_type: "heartbeat",
      emitter_node: other.nodeCert.node_id,
      emitter_principal: "system",
      fortress_id: other.master.public.fortress_id,
      payload: { node_state: "active" },
      monotonic_seq: 1,
      node_private_key: other.nodeKeypair.privateKey,
    });
    expect(() => verifySignedEvent(evt, contextFor(f))).toThrow(
      MeshSignatureError
    );
  });

  it("receiver rejects envelope whose principal chain terminates at foreign master", () => {
    // Another fortress issues a cert; envelope claims our fortress_id and our
    // cert IDs but carries signatures from the foreign key set. The lookup
    // returns our cert (by ID match), verification fails at Ed25519.
    const other = buildFortress("root");
    const evt: SignedEvent = {
      protocol_version: "0.1",
      event_type: "heartbeat",
      event_id: "bogus",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      fortress_id: f.master.public.fortress_id,
      causal_parents: [],
      payload: { node_state: "active" },
      payload_hash: "x",
      emitted_at: new Date().toISOString(),
      monotonic_seq: 1,
      extension_envelope: {},
      node_signature: toBase64url(
        ed25519.sign(new Uint8Array([0]), other.nodeKeypair.privateKey)
      ),
    };
    expect(() => verifySignedEvent(evt, contextFor(f))).toThrow(
      MeshSignatureError
    );
  });
});
