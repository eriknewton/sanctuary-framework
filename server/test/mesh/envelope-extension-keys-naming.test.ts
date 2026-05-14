/**
 * Sanctuary Federation Protocol v0.1 — Envelope extension-keys naming guard
 *
 * Regression guard for full-sweep finding #66. The VerifyResult field that
 * lists forward-compat extension keys was renamed from `unknown_extension_keys`
 * to `recognized_reserved_extension_keys` because the original name inverted
 * the meaning: the field contains keys that ARE in the reserved set (so a
 * v1.x consumer can detect them), not keys that are unknown.
 *
 * If a future refactor reverts the name or repurposes the field to "keys not
 * in the reserved set," this test fails loudly.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url } from "../../src/core/encoding.js";
import { randomBytes } from "../../src/core/random.js";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { canonicalizeToBytes } from "../../src/mesh/canonical-json.js";
import { CAP_STANDARD_FORTRESS_NODE } from "../../src/mesh/constants.js";
import {
  MeshReservedExtensionKeyError,
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

describe("mesh/envelope extension-keys field naming (full-sweep #66)", () => {
  let f: TestFortress;
  beforeAll(() => {
    f = buildFortress();
  });

  it("VerifyResult exposes recognized_reserved_extension_keys (renamed from unknown_extension_keys)", () => {
    const evt = packSignedEvent({
      event_type: "heartbeat",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      fortress_id: f.master.public.fortress_id,
      payload: { node_state: "active" },
      monotonic_seq: 1,
      node_private_key: f.nodeKeypair.privateKey,
      principal_private_key: f.principalKeypair.privateKey,
    });
    const res = verifySignedEvent(evt, contextFor(f));
    expect(res.ok).toBe(true);
    expect(Object.prototype.hasOwnProperty.call(res, "recognized_reserved_extension_keys")).toBe(true);
    expect(Object.prototype.hasOwnProperty.call(res, "unknown_extension_keys")).toBe(false);
    expect(res.recognized_reserved_extension_keys).toEqual([]);
  });

  it("rejects RESERVED extension keys instead of treating them as non-reserved unknown keys", () => {
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
      monotonic_seq: 7,
      extension_envelope: {
        cross_fortress_read_query: { grant_event_id: "g1", scope: "audit" },
      },
    };
    const v1xBytes = canonicalizeToBytes(v1xBody);
    const sig = ed25519.sign(v1xBytes, f.nodeKeypair.privateKey);
    const v1xEvt: SignedEvent = {
      ...v1xBody,
      node_signature: toBase64url(sig),
    };
    expect(() => verifySignedEvent(v1xEvt, contextFor(f))).toThrow(
      MeshReservedExtensionKeyError
    );
  });
});
