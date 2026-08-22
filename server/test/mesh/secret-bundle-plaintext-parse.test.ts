/**
 * WIRE-PARSE-PLAINTEXT-02: malformed decrypted plaintext must produce a typed
 * SecretBundleError, never a raw TypeError from field dereference.
 *
 * Each case creates genuinely AES-GCM-authenticated ciphertext (correct key,
 * correct AAD) whose plaintext is valid JSON but not a valid
 * MasterRotationBundlePlaintext shape. The unwrap path must refuse with a
 * typed SecretBundleError before any field is dereferenced.
 */

import { describe, it, expect } from "vitest";

import { encrypt } from "../../src/core/encryption.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { generateKeypair } from "../../src/core/identity.js";
import {
  CAP_STANDARD_FORTRESS_NODE,
} from "../../src/mesh/constants.js";
import {
  generateFortressMaster,
  issueNodeIdentityCertificate,
  issuePrincipalCertificate,
  deriveNodeTransportKey,
} from "../../src/mesh/trust-root.js";
import {
  unwrapMasterRotationBundle,
  wrapMasterRotationBundle,
  SecretBundleError,
  type MasterRotationBundleEnvelope,
} from "../../src/mesh/recovery-flows/index.js";

// ═══════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════

/**
 * Build the same AAD that unwrapMasterRotationBundle computes internally.
 * The prefix string and field concatenation order must exactly match the
 * private `secret-bundle.ts::bundleAad`; the parser-reason assertions and
 * round-trip test make any divergence fail at test time.
 */
function bundleAad(params: {
  target_node_id: string;
  fortress_id: string;
  rotated_at: string;
  new_master_pubkey: string;
}): Uint8Array {
  return stringToBytes(
    "sanctuary-recovery-flows-v0.1-master-rotation-bundle|" +
      params.fortress_id +
      "|" +
      params.target_node_id +
      "|" +
      params.rotated_at +
      "|" +
      params.new_master_pubkey
  );
}

interface TestFixture {
  nodeId: string;
  fortressId: string;
  masterSecret: Uint8Array;
  rotatedAt: string;
  newMasterPubkey: string;
  wrappingKey: Uint8Array;
  aad: Uint8Array;
}

function buildTestFixture(): TestFixture {
  const masterBundle = generateFortressMaster();
  const nodeId = "peer-plaintext-test";
  const fortressId = masterBundle.public.fortress_id;
  const rotatedAt = new Date().toISOString();
  const newMasterKp = generateKeypair();
  const newMasterPubkey = toBase64url(newMasterKp.publicKey);
  const wrappingKey = deriveNodeTransportKey({
    fortress_master_secret: masterBundle.private_key,
    node_id: nodeId,
    node_mode: "local",
  });
  const aad = bundleAad({
    target_node_id: nodeId,
    fortress_id: fortressId,
    rotated_at: rotatedAt,
    new_master_pubkey: newMasterPubkey,
  });
  return {
    nodeId,
    fortressId,
    masterSecret: masterBundle.private_key,
    rotatedAt,
    newMasterPubkey,
    wrappingKey,
    aad,
  };
}

/**
 * Wrap arbitrary JSON as genuinely authenticated ciphertext and build a
 * well-formed envelope around it. The ciphertext is authentic (correct key +
 * AAD), so AES-GCM decryption succeeds; the defect is in the plaintext shape.
 */
function envelopeWithPlaintext(
  fx: TestFixture,
  jsonValue: string
): MasterRotationBundleEnvelope {
  const ciphertext = encrypt(stringToBytes(jsonValue), fx.wrappingKey, fx.aad);
  return {
    kind: "master_rotation_bundle",
    target_node_id: fx.nodeId,
    fortress_id: fx.fortressId,
    ciphertext,
    rotated_at: fx.rotatedAt,
    new_master_pubkey: fx.newMasterPubkey,
  };
}

function unwrapWith(
  fx: TestFixture,
  envelope: MasterRotationBundleEnvelope
): void {
  unwrapMasterRotationBundle({
    envelope,
    old_fortress_master_secret: fx.masterSecret,
    this_node_id: fx.nodeId,
    this_node_mode: "local",
    this_fortress_id: fx.fortressId,
  });
}

/**
 * Assert that unwrapping the envelope throws SecretBundleError with the given
 * reason token in the message. Calls unwrapWith exactly once.
 */
function expectMalformed(
  fx: TestFixture,
  envelope: MasterRotationBundleEnvelope,
  reason: string
): void {
  let caught: unknown;
  try {
    unwrapWith(fx, envelope);
  } catch (e) {
    caught = e;
  }
  expect(caught).toBeInstanceOf(SecretBundleError);
  expect((caught as Error).message).toContain(reason);
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

describe("secret-bundle plaintext parse (WIRE-PARSE-PLAINTEXT-02)", () => {
  it("rejects JSON null plaintext with SecretBundleError, not TypeError", () => {
    const fx = buildTestFixture();
    const envelope = envelopeWithPlaintext(fx, "null");
    expectMalformed(fx, envelope, "plaintext_not_object");
  });

  it("rejects JSON number plaintext with SecretBundleError", () => {
    const fx = buildTestFixture();
    const envelope = envelopeWithPlaintext(fx, "42");
    expectMalformed(fx, envelope, "plaintext_not_object");
  });

  it("rejects JSON string plaintext with SecretBundleError", () => {
    const fx = buildTestFixture();
    const envelope = envelopeWithPlaintext(fx, '"hello"');
    expectMalformed(fx, envelope, "plaintext_not_object");
  });

  it("rejects JSON array plaintext with SecretBundleError", () => {
    const fx = buildTestFixture();
    const envelope = envelopeWithPlaintext(fx, "[1, 2, 3]");
    expectMalformed(fx, envelope, "plaintext_not_object");
  });

  it("rejects JSON true plaintext with SecretBundleError", () => {
    const fx = buildTestFixture();
    const envelope = envelopeWithPlaintext(fx, "true");
    expectMalformed(fx, envelope, "plaintext_not_object");
  });

  it("rejects object with missing required fields with SecretBundleError", () => {
    const fx = buildTestFixture();
    const envelope = envelopeWithPlaintext(fx, "{}");
    expectMalformed(fx, envelope, "new_master_secret_not_string");
  });

  it("rejects object with non-string new_master_secret with SecretBundleError", () => {
    const fx = buildTestFixture();
    const payload = JSON.stringify({
      new_master_secret: 123,
      re_issued_self_cert: { node_id: fx.nodeId },
      new_root_principal_cert: {},
      rotated_at: fx.rotatedAt,
      new_master_pubkey: fx.newMasterPubkey,
    });
    const envelope = envelopeWithPlaintext(fx, payload);
    expectMalformed(fx, envelope, "new_master_secret_not_string");
  });

  it("rejects object with null re_issued_self_cert with SecretBundleError", () => {
    const fx = buildTestFixture();
    const payload = JSON.stringify({
      new_master_secret: "AAAA",
      re_issued_self_cert: null,
      new_root_principal_cert: {},
      rotated_at: fx.rotatedAt,
      new_master_pubkey: fx.newMasterPubkey,
    });
    const envelope = envelopeWithPlaintext(fx, payload);
    expectMalformed(fx, envelope, "re_issued_self_cert_invalid");
  });

  it("rejects object with null new_root_principal_cert with SecretBundleError", () => {
    const fx = buildTestFixture();
    // Use a fully-valid re_issued_self_cert so the first cert parse succeeds;
    // the defect under test is new_root_principal_cert: null.
    const obj = validPlaintextObj(fx);
    obj.new_root_principal_cert = null;
    const envelope = envelopeWithPlaintext(fx, JSON.stringify(obj));
    expectMalformed(fx, envelope, "new_root_principal_cert_invalid");
  });

  // ─── element-level cert regressions (P1 fix) ─────────────────────────
  // These prove that authenticated ciphertext with a structurally invalid
  // embedded certificate is refused by the parser, not passed through to
  // installMasterRotation where a raw TypeError would occur.

  /** Build a minimally valid plaintext object for selective field breakage. */
  function validPlaintextObj(fx: TestFixture): Record<string, unknown> {
    return {
      new_master_secret: "AAAA",
      rotated_at: fx.rotatedAt,
      new_master_pubkey: fx.newMasterPubkey,
      re_issued_self_cert: {
        node_id: fx.nodeId,
        node_pubkey: "BBBB",
        node_mode: "local",
        fortress_id: fx.fortressId,
        joined_at: new Date().toISOString(),
        capabilities: 1,
        parent_chain: {
          fortress_master_pubkey: "CCCC",
          principal_id: "root",
          principal_pubkey: "DDDD",
        },
        principal_signature: "EEEE",
      },
      new_root_principal_cert: {
        principal_id: "root",
        principal_pubkey: "FFFF",
        role: "root",
        fortress_id: fx.fortressId,
        issued_at: new Date().toISOString(),
        master_signature: "GGGG",
      },
    };
  }

  it("rejects node cert with missing parent_chain (would TypeError in installMasterRotation)", () => {
    const fx = buildTestFixture();
    const obj = validPlaintextObj(fx);
    const cert = obj.re_issued_self_cert as Record<string, unknown>;
    delete cert.parent_chain;
    const envelope = envelopeWithPlaintext(fx, JSON.stringify(obj));
    expectMalformed(fx, envelope, "re_issued_self_cert_invalid");
  });

  it("rejects node cert with non-object parent_chain", () => {
    const fx = buildTestFixture();
    const obj = validPlaintextObj(fx);
    (obj.re_issued_self_cert as Record<string, unknown>).parent_chain = "not-an-object";
    const envelope = envelopeWithPlaintext(fx, JSON.stringify(obj));
    expectMalformed(fx, envelope, "re_issued_self_cert_invalid");
  });

  it("rejects node cert with non-string fortress_master_pubkey in parent_chain", () => {
    const fx = buildTestFixture();
    const obj = validPlaintextObj(fx);
    const cert = obj.re_issued_self_cert as Record<string, unknown>;
    (cert.parent_chain as Record<string, unknown>).fortress_master_pubkey = 42;
    const envelope = envelopeWithPlaintext(fx, JSON.stringify(obj));
    expectMalformed(fx, envelope, "re_issued_self_cert_invalid");
  });

  it("rejects root cert with missing principal_id (would install under undefined map key)", () => {
    const fx = buildTestFixture();
    const obj = validPlaintextObj(fx);
    const cert = obj.new_root_principal_cert as Record<string, unknown>;
    delete cert.principal_id;
    const envelope = envelopeWithPlaintext(fx, JSON.stringify(obj));
    expectMalformed(fx, envelope, "new_root_principal_cert_invalid");
  });

  it("rejects node cert with invalid node_mode", () => {
    const fx = buildTestFixture();
    const obj = validPlaintextObj(fx);
    (obj.re_issued_self_cert as Record<string, unknown>).node_mode = "invalid_mode";
    const envelope = envelopeWithPlaintext(fx, JSON.stringify(obj));
    expectMalformed(fx, envelope, "re_issued_self_cert_invalid");
  });

  it("rejects root cert with invalid principal role", () => {
    const fx = buildTestFixture();
    const obj = validPlaintextObj(fx);
    (obj.new_root_principal_cert as Record<string, unknown>).role = "admin";
    const envelope = envelopeWithPlaintext(fx, JSON.stringify(obj));
    expectMalformed(fx, envelope, "new_root_principal_cert_invalid");
  });

  it("rejects node cert with non-number capabilities", () => {
    const fx = buildTestFixture();
    const obj = validPlaintextObj(fx);
    (obj.re_issued_self_cert as Record<string, unknown>).capabilities = "high";
    const envelope = envelopeWithPlaintext(fx, JSON.stringify(obj));
    expectMalformed(fx, envelope, "re_issued_self_cert_invalid");
  });

  it("rejects node cert with wrong optional field type (expires_at = number)", () => {
    const fx = buildTestFixture();
    const obj = validPlaintextObj(fx);
    (obj.re_issued_self_cert as Record<string, unknown>).expires_at = 12345;
    const envelope = envelopeWithPlaintext(fx, JSON.stringify(obj));
    expectMalformed(fx, envelope, "re_issued_self_cert_invalid");
  });

  it("rejects root cert with wrong optional field type (expires_at = true)", () => {
    const fx = buildTestFixture();
    const obj = validPlaintextObj(fx);
    (obj.new_root_principal_cert as Record<string, unknown>).expires_at = true;
    const envelope = envelopeWithPlaintext(fx, JSON.stringify(obj));
    expectMalformed(fx, envelope, "new_root_principal_cert_invalid");
  });

  it("valid round-trip still succeeds (regression guard)", () => {
    const masterBundle = generateFortressMaster();
    const nodeId = "peer-roundtrip";
    const newMaster = generateFortressMaster();
    const newRootKp = generateKeypair();
    // A master rotation preserves the fortress identity: new certs carry the
    // original fortress_id, signed under the new master key pair.
    const newRootCert = issuePrincipalCertificate({
      principal_id: "root",
      principal_pubkey: newRootKp.publicKey,
      role: "root",
      fortress_id: masterBundle.public.fortress_id,
      master_private_key: newMaster.private_key,
    });
    const reIssuedKp = generateKeypair();
    const reIssued = issueNodeIdentityCertificate({
      node_id: nodeId,
      node_pubkey: reIssuedKp.publicKey,
      node_mode: "local",
      fortress_id: masterBundle.public.fortress_id,
      capabilities: CAP_STANDARD_FORTRESS_NODE,
      parent_chain: {
        fortress_master_pubkey: newMaster.public.public_key,
        principal_id: newRootCert.principal_id,
        principal_pubkey: newRootCert.principal_pubkey,
      },
      principal_private_key: newRootKp.privateKey,
      master_private_key: newMaster.private_key,
    });
    const rotatedAt = new Date().toISOString();
    const envelope = wrapMasterRotationBundle({
      plaintext: {
        new_master_secret: toBase64url(newMaster.private_key),
        re_issued_self_cert: reIssued,
        new_root_principal_cert: newRootCert,
        rotated_at: rotatedAt,
        new_master_pubkey: newMaster.public.public_key,
      },
      old_fortress_master_secret: masterBundle.private_key,
      target_node_id: nodeId,
      target_node_mode: "local",
      fortress_id: masterBundle.public.fortress_id,
    });
    const pt = unwrapMasterRotationBundle({
      envelope,
      old_fortress_master_secret: masterBundle.private_key,
      this_node_id: nodeId,
      this_node_mode: "local",
      this_fortress_id: masterBundle.public.fortress_id,
    });
    expect(pt.new_master_pubkey).toBe(newMaster.public.public_key);
    expect(pt.rotated_at).toBe(rotatedAt);
    expect(pt.re_issued_self_cert.node_id).toBe(nodeId);
  });
});
