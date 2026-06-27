/**
 * Sanctuary Federation Protocol v0.1 — Trust Root Tests
 *
 * Real-shape tests: generates actual fortress-master keypair, issues real
 * principal + node certs, walks the chain against real signatures. No mocks.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { fromBase64url, toBase64url } from "../../src/core/encoding.js";
import {
  ED25519_SIGNATURE_SUITE_ID,
  HYBRID_SIGNATURE_SUITE_ID,
  ML_DSA_65_PUBLIC_KEY_BYTES,
} from "../../src/core/crypto-suite-registry.js";
import { generateKeypair } from "../../src/core/identity.js";
import { canonicalizeToBytes } from "../../src/mesh/canonical-json.js";
import {
  CAP_AUDIT_REPLICA_ELIGIBLE,
  CAP_COLD_STORAGE_RECEIPT_REPLICA,
  CAP_STANDARD_FORTRESS_NODE,
} from "../../src/mesh/constants.js";
import {
  MeshChainError,
  MeshReservedCapabilityBitError,
} from "../../src/mesh/errors.js";
import {
  deriveNodeAuditChainKey,
  deriveNodeTransportKey,
  generateFortressMaster,
  issueNodeIdentityCertificate,
  issuePrincipalCertificate,
  NODE_IDENTITY_CERTIFICATE_VERSION_EXPIRING,
  v01VisibleCapabilities,
  verifyCertChain,
  verifyPrincipalCertificate,
} from "../../src/mesh/trust-root.js";
import {
  generateFortressMasterV2Hybrid,
  generateHybridCertificateKeypair,
  issueNodeIdentityCertificateV2Hybrid,
  issuePrincipalCertificateV2Hybrid,
  MAX_HYBRID_NODE_CERT_JSON_BYTES,
  verifyCertChainV2Hybrid,
  verifyCertChainWithPolicy,
  verifyPrincipalCertificateV2Hybrid,
} from "../../src/mesh/trust-root-hybrid.js";
import { randomBytes } from "../../src/core/random.js";

describe("mesh/trust-root — fortress-master bootstrap", () => {
  it("generates a fortress-master keypair with stable fortress-id", () => {
    const master = generateFortressMaster();
    expect(master.public.fortress_id).toHaveLength(32);
    expect(master.public.public_key).toBeTruthy();
    expect(master.private_key).toHaveLength(32);
    // Public key reconstructs from the private key.
    expect(toBase64url(ed25519.getPublicKey(master.private_key))).toBe(
      master.public.public_key
    );
  });

  it("never returns the same fortress-id twice", () => {
    const a = generateFortressMaster();
    const b = generateFortressMaster();
    expect(a.public.fortress_id).not.toBe(b.public.fortress_id);
  });
});

describe("mesh/trust-root — principal cert chain", () => {
  let master: ReturnType<typeof generateFortressMaster>;
  let rootPrincipalKeypair: ReturnType<typeof generateKeypair>;
  let rootPrincipalCert: ReturnType<typeof issuePrincipalCertificate>;

  beforeAll(() => {
    master = generateFortressMaster();
    rootPrincipalKeypair = generateKeypair();
    rootPrincipalCert = issuePrincipalCertificate({
      principal_id: "root",
      principal_pubkey: rootPrincipalKeypair.publicKey,
      role: "root",
      fortress_id: master.public.fortress_id,
      master_private_key: master.private_key,
    });
  });

  it("issues and verifies a root principal cert", () => {
    expect(() =>
      verifyPrincipalCertificate(rootPrincipalCert, master.public)
    ).not.toThrow();
  });

  it("rejects a principal cert from a foreign fortress (cross-operator isolation)", () => {
    const foreignMaster = generateFortressMaster();
    expect(() =>
      verifyPrincipalCertificate(rootPrincipalCert, foreignMaster.public)
    ).toThrow(MeshChainError);
  });

  it("rejects a principal cert with tampered pubkey", () => {
    const tampered = {
      ...rootPrincipalCert,
      principal_pubkey: toBase64url(generateKeypair().publicKey),
    };
    expect(() => verifyPrincipalCertificate(tampered, master.public)).toThrow(
      MeshChainError
    );
  });

  it("rejects an expired principal cert", () => {
    const pastExpiry = new Date(Date.now() - 60_000).toISOString();
    const expiredCert = issuePrincipalCertificate({
      principal_id: "partner-alice",
      principal_pubkey: generateKeypair().publicKey,
      role: "partner",
      fortress_id: master.public.fortress_id,
      master_private_key: master.private_key,
      expires_at: pastExpiry,
    });
    expect(() => verifyPrincipalCertificate(expiredCert, master.public)).toThrow(
      MeshChainError
    );
  });
});

describe("mesh/trust-root — per-node cert chain + hard-gate capability reservations", () => {
  let master: ReturnType<typeof generateFortressMaster>;
  let principalKeypair: ReturnType<typeof generateKeypair>;
  let principalCert: ReturnType<typeof issuePrincipalCertificate>;
  let nodeKeypair: ReturnType<typeof generateKeypair>;

  beforeAll(() => {
    master = generateFortressMaster();
    principalKeypair = generateKeypair();
    principalCert = issuePrincipalCertificate({
      principal_id: "root",
      principal_pubkey: principalKeypair.publicKey,
      role: "root",
      fortress_id: master.public.fortress_id,
      master_private_key: master.private_key,
    });
    nodeKeypair = generateKeypair();
  });

  function issueNode(caps: number, withMasterSig = false, expires_at?: string) {
    return issueNodeIdentityCertificate({
      node_id: "node-" + toBase64url(randomBytes(4)),
      node_pubkey: nodeKeypair.publicKey,
      node_mode: "local",
      fortress_id: master.public.fortress_id,
      capabilities: caps,
      parent_chain: {
        fortress_master_pubkey: master.public.public_key,
        principal_id: principalCert.principal_id,
        principal_pubkey: principalCert.principal_pubkey,
      },
      principal_private_key: principalKeypair.privateKey,
      master_private_key: withMasterSig ? master.private_key : undefined,
      expires_at,
    });
  }

  it("issues and verifies a standard v0.1 node cert", () => {
    const cert = issueNode(CAP_STANDARD_FORTRESS_NODE);
    expect(() => verifyCertChain(cert, principalCert, master.public)).not.toThrow();
  });

  it("accepts a legacy node cert with no expires_at (migration compatibility)", () => {
    const cert = issueNode(CAP_STANDARD_FORTRESS_NODE);
    expect(cert.expires_at).toBeUndefined();
    expect(() => verifyCertChain(cert, principalCert, master.public)).not.toThrow();
  });

  it("signs and enforces node cert expires_at when present", () => {
    const now = Date.parse("2026-06-20T12:00:00.000Z");
    const expiresAt = new Date(now + 60_000).toISOString();
    const cert = issueNode(CAP_STANDARD_FORTRESS_NODE, true, expiresAt);
    expect(cert.certificate_version).toBe(NODE_IDENTITY_CERTIFICATE_VERSION_EXPIRING);
    expect(cert.expires_at).toBe(expiresAt);
    expect(() =>
      verifyCertChain(cert, principalCert, master.public, now),
    ).not.toThrow();
    expect(() =>
      verifyCertChain(cert, principalCert, master.public, now + 60_001),
    ).toThrow(MeshChainError);
  });

  it("rejects an expiring node cert without the signed certificate_version marker", () => {
    const now = Date.parse("2026-06-20T12:00:00.000Z");
    const cert = issueNode(
      CAP_STANDARD_FORTRESS_NODE,
      true,
      new Date(now + 60_000).toISOString(),
    );
    const unversioned = { ...cert, certificate_version: undefined };
    expect(() =>
      verifyCertChain(unversioned, principalCert, master.public, now),
    ).toThrow(MeshChainError);
  });

  it("rejects a node cert whose signed expires_at was tampered", () => {
    const now = Date.parse("2026-06-20T12:00:00.000Z");
    const cert = issueNode(
      CAP_STANDARD_FORTRESS_NODE,
      true,
      new Date(now + 60_000).toISOString(),
    );
    const tampered = {
      ...cert,
      expires_at: new Date(now + 3_600_000).toISOString(),
    };
    expect(() =>
      verifyCertChain(tampered, principalCert, master.public, now),
    ).toThrow(MeshChainError);
  });

  it("cert issuance rejects reserved capability bits (hard gate §10.2)", () => {
    // Bit 3 is the first reserved bit (v1.x cross-fortress read endpoint).
    expect(() => issueNode(CAP_STANDARD_FORTRESS_NODE | (1 << 3))).toThrow(
      MeshReservedCapabilityBitError
    );
    // Bit 4 (v1.x guardian-delegated principal endpoint).
    expect(() => issueNode(CAP_STANDARD_FORTRESS_NODE | (1 << 4))).toThrow(
      MeshReservedCapabilityBitError
    );
    // Bit 31 (future allocation).
    expect(() =>
      issueNode(CAP_STANDARD_FORTRESS_NODE | (1 << 31))
    ).toThrow(MeshReservedCapabilityBitError);
  });

  it("cert issuance refuses capabilities=0 (bit 0 is mandatory)", () => {
    expect(() => issueNode(0)).toThrow(MeshChainError);
  });

  it("rejects TEE attestation hashes on non-sovereign-TEE node certs", () => {
    expect(() =>
      issueNodeIdentityCertificate({
        node_id: "cloud-with-self-report",
        node_pubkey: nodeKeypair.publicKey,
        node_mode: "operator_cloud",
        fortress_id: master.public.fortress_id,
        capabilities: CAP_STANDARD_FORTRESS_NODE,
        parent_chain: {
          fortress_master_pubkey: master.public.public_key,
          principal_id: principalCert.principal_id,
          principal_pubkey: principalCert.principal_pubkey,
        },
        principal_private_key: principalKeypair.privateKey,
        tee_attestation_hash: "self-reported",
      }),
    ).toThrow(MeshChainError);
  });

  it("v0.1 verifier tolerates unknown capability bits on v1.x cert (forward-compat §10.2)", () => {
    // Simulate a v1.x-issued cert carrying bit 3 by hand-crafting the body and
    // signing with the principal key. v0.1 verifier MUST accept (but v01VisibleCapabilities
    // masks bit 3 off).
    const v1xCert = issueNode(CAP_STANDARD_FORTRESS_NODE);
    // Monkey-patch bit 3 onto the capabilities field. Because signatures cover
    // the field, we must re-sign — simulating what a v1.x issuer would do.
    const body = {
      node_id: v1xCert.node_id,
      node_pubkey: v1xCert.node_pubkey,
      node_mode: v1xCert.node_mode,
      fortress_id: v1xCert.fortress_id,
      joined_at: v1xCert.joined_at,
      capabilities: CAP_STANDARD_FORTRESS_NODE | (1 << 3),
      parent_chain: v1xCert.parent_chain,
      tee_attestation_hash: v1xCert.tee_attestation_hash,
      delegated_grants: [],
      attestation_lineage_chain: [],
    };
    const newSig = ed25519.sign(
      canonicalizeToBytes(body),
      principalKeypair.privateKey
    );
    const futureCert = {
      ...body,
      principal_signature: toBase64url(newSig),
    };
    // Forward-compat: verifier accepts.
    expect(() =>
      verifyCertChain(futureCert as typeof v1xCert, principalCert, master.public)
    ).not.toThrow();
    // v01VisibleCapabilities masks the reserved bit off.
    expect(v01VisibleCapabilities(futureCert as typeof v1xCert)).toBe(
      CAP_STANDARD_FORTRESS_NODE
    );
    expect(futureCert.capabilities & (1 << 3)).not.toBe(0); // raw cert still carries it
  });

  it("v0.1 verifier accepts cert with and without master_signature (§10.4)", () => {
    const certWithout = issueNode(CAP_STANDARD_FORTRESS_NODE, false);
    const certWith = issueNode(CAP_STANDARD_FORTRESS_NODE, true);
    expect(certWithout.master_signature).toBeUndefined();
    expect(certWith.master_signature).toBeTruthy();
    expect(() => verifyCertChain(certWithout, principalCert, master.public)).not.toThrow();
    expect(() => verifyCertChain(certWith, principalCert, master.public)).not.toThrow();
  });

  it("tampered master_signature on an otherwise-valid cert is rejected (defense-in-depth)", () => {
    const cert = issueNode(CAP_STANDARD_FORTRESS_NODE, true);
    const fake = ed25519.sign(
      new Uint8Array([1, 2, 3]),
      generateKeypair().privateKey
    );
    const bad = { ...cert, master_signature: toBase64url(fake) };
    expect(() => verifyCertChain(bad, principalCert, master.public)).toThrow(
      MeshChainError
    );
  });

  it("cert chain validation rejects foreign fortress-master (cross-operator isolation §10.5)", () => {
    const foreign = generateFortressMaster();
    const cert = issueNode(CAP_STANDARD_FORTRESS_NODE);
    expect(() => verifyCertChain(cert, principalCert, foreign.public)).toThrow(
      MeshChainError
    );
  });

  it("rejects node cert whose parent_chain.principal_pubkey does not match principal cert", () => {
    const cert = issueNode(CAP_STANDARD_FORTRESS_NODE);
    const imposterPrincipalCert = {
      ...principalCert,
      principal_pubkey: toBase64url(generateKeypair().publicKey),
    };
    expect(() =>
      verifyCertChain(cert, imposterPrincipalCert, master.public)
    ).toThrow(MeshChainError);
  });

  it("accepts v0.1 opt-in audit-replica and cold-storage capability bits", () => {
    const cert = issueNode(
      CAP_STANDARD_FORTRESS_NODE |
        CAP_AUDIT_REPLICA_ELIGIBLE |
        CAP_COLD_STORAGE_RECEIPT_REPLICA
    );
    expect(() => verifyCertChain(cert, principalCert, master.public)).not.toThrow();
  });
});

describe("mesh/trust-root — frozen v1 canonical bodies", () => {
  it("keeps v1 principal and node signed bodies byte-stable", () => {
    const principalBody = {
      principal_id: "root",
      principal_pubkey: "principal-ed25519",
      role: "root",
      fortress_id: "fortress-1",
      issued_at: "2026-06-23T00:00:00.000Z",
      expires_at: undefined,
    };
    expect(Buffer.from(canonicalizeToBytes(principalBody)).toString("utf8")).toBe(
      '{"fortress_id":"fortress-1","issued_at":"2026-06-23T00:00:00.000Z","principal_id":"root","principal_pubkey":"principal-ed25519","role":"root"}'
    );

    const nodeBody = {
      certificate_version: NODE_IDENTITY_CERTIFICATE_VERSION_EXPIRING,
      node_id: "node-1",
      node_pubkey: "node-ed25519",
      node_mode: "local",
      fortress_id: "fortress-1",
      joined_at: "2026-06-23T00:01:00.000Z",
      expires_at: "2026-07-23T00:01:00.000Z",
      capabilities: CAP_STANDARD_FORTRESS_NODE,
      parent_chain: {
        fortress_master_pubkey: "master-ed25519",
        principal_id: "root",
        principal_pubkey: "principal-ed25519",
      },
      tee_attestation_hash: undefined,
      delegated_grants: [],
      attestation_lineage_chain: [],
    };
    expect(Buffer.from(canonicalizeToBytes(nodeBody)).toString("utf8")).toBe(
      '{"attestation_lineage_chain":[],"capabilities":1,"certificate_version":"sanctuary.v1.expiring-node-cert","delegated_grants":[],"expires_at":"2026-07-23T00:01:00.000Z","fortress_id":"fortress-1","joined_at":"2026-06-23T00:01:00.000Z","node_id":"node-1","node_mode":"local","node_pubkey":"node-ed25519","parent_chain":{"fortress_master_pubkey":"master-ed25519","principal_id":"root","principal_pubkey":"principal-ed25519"}}'
    );
  });
});

describe("mesh/trust-root — v2 hybrid certificate chain", () => {
  async function makeHybridChain() {
    const master = generateFortressMasterV2Hybrid();
    const principalKeys = generateHybridCertificateKeypair({
      owner_kind: "principal",
      owner_id: "root",
    });
    const principalCert = await issuePrincipalCertificateV2Hybrid({
      principal_id: "root",
      principal_public_keys: principalKeys.public_keys,
      role: "root",
      master_public_keys: master.public,
      master_private_keys: master.private_keys,
      issued_at: "2026-06-23T00:00:00.000Z",
      expires_at: "2026-07-23T00:00:00.000Z",
    });
    const nodeKeys = generateHybridCertificateKeypair({
      owner_kind: "node",
      owner_id: "node-1",
    });
    const nodeCert = await issueNodeIdentityCertificateV2Hybrid({
      node_id: "node-1",
      node_public_keys: nodeKeys.public_keys,
      node_mode: "local",
      capabilities: CAP_STANDARD_FORTRESS_NODE,
      principal_certificate: principalCert,
      principal_private_keys: principalKeys.private_keys,
      master_public_keys: master.public,
      master_private_keys: master.private_keys,
      joined_at: "2026-06-23T00:01:00.000Z",
      expires_at: "2026-07-23T00:01:00.000Z",
    });
    return { master, principalKeys, principalCert, nodeKeys, nodeCert };
  }

  it("generates public descriptors without returning private bytes from verifier surfaces", async () => {
    const { master, principalCert, nodeCert } = await makeHybridChain();

    expect(master.public.public_keys.ml_dsa_65.public_key).toBeTruthy();
    expect(JSON.stringify(master.public)).not.toContain("private");
    expect(JSON.stringify(principalCert)).not.toContain("secret_key");
    expect(JSON.stringify(nodeCert)).not.toContain("secret_key");
  });

  it("issues and verifies a v2 hybrid principal and node chain", async () => {
    const { master, principalCert, nodeCert } = await makeHybridChain();
    const now = Date.parse("2026-06-23T12:00:00.000Z");

    await expect(
      verifyPrincipalCertificateV2Hybrid(principalCert, master.public, now)
    ).resolves.toBeUndefined();
    await expect(
      verifyCertChainV2Hybrid(nodeCert, principalCert, master.public, now)
    ).resolves.toBeUndefined();
    await expect(
      verifyCertChainWithPolicy(nodeCert, principalCert, master.public, {
        minimum_suite: HYBRID_SIGNATURE_SUITE_ID,
        nowMs: now,
      })
    ).resolves.toBeUndefined();
  });

  it("rejects a v2 node cert missing the required master signature bundle", async () => {
    const { master, principalCert, nodeCert } = await makeHybridChain();
    const downgraded = {
      ...nodeCert,
      master_signature_bundle: undefined,
    };

    await expect(
      verifyCertChainV2Hybrid(
        downgraded as typeof nodeCert,
        principalCert,
        master.public
      )
    ).rejects.toThrow(MeshChainError);
  });

  it("rejects parent-chain key-ref substitution", async () => {
    const { master, principalCert, nodeCert } = await makeHybridChain();
    const tampered = {
      ...nodeCert,
      parent_chain: {
        ...nodeCert.parent_chain,
        principal_key_refs: {
          ...nodeCert.parent_chain.principal_key_refs,
          ml_dsa_65: "attacker.ml-dsa-65-v1",
        },
      },
    };

    await expect(
      verifyCertChainV2Hybrid(tampered, principalCert, master.public)
    ).rejects.toThrow(MeshChainError);
  });

  it("rejects oversized hybrid cert fields before signature verification", async () => {
    const { master, principalCert, nodeCert } = await makeHybridChain();
    const oversizedPublicKey = toBase64url(
      new Uint8Array(ML_DSA_65_PUBLIC_KEY_BYTES + 1)
    );
    const oversizedKey = {
      ...nodeCert,
      node_public_keys: {
        ...nodeCert.node_public_keys,
        ml_dsa_65: {
          ...nodeCert.node_public_keys.ml_dsa_65,
          public_key: oversizedPublicKey,
        },
      },
    };
    const oversizedJson = {
      ...nodeCert,
      delegated_grants: ["x".repeat(MAX_HYBRID_NODE_CERT_JSON_BYTES)],
    };

    await expect(
      verifyCertChainV2Hybrid(oversizedKey, principalCert, master.public)
    ).rejects.toThrow(MeshChainError);
    await expect(
      verifyCertChainV2Hybrid(oversizedJson, principalCert, master.public)
    ).rejects.toThrow(/parse cap/);
  });

  it("rejects v1 chains under hybrid-required policy while preserving v1 acceptance under legacy policy", async () => {
    const master = generateFortressMaster();
    const principalKeypair = generateKeypair();
    const principalCert = issuePrincipalCertificate({
      principal_id: "root",
      principal_pubkey: principalKeypair.publicKey,
      role: "root",
      fortress_id: master.public.fortress_id,
      master_private_key: master.private_key,
    });
    const nodeKeypair = generateKeypair();
    const nodeCert = issueNodeIdentityCertificate({
      node_id: "legacy-node",
      node_pubkey: nodeKeypair.publicKey,
      node_mode: "local",
      fortress_id: master.public.fortress_id,
      capabilities: CAP_STANDARD_FORTRESS_NODE,
      parent_chain: {
        fortress_master_pubkey: master.public.public_key,
        principal_id: principalCert.principal_id,
        principal_pubkey: principalCert.principal_pubkey,
      },
      principal_private_key: principalKeypair.privateKey,
      master_private_key: master.private_key,
    });

    await expect(
      verifyCertChainWithPolicy(nodeCert, principalCert, master.public, {
        minimum_suite: ED25519_SIGNATURE_SUITE_ID,
      })
    ).resolves.toBeUndefined();
    await expect(
      verifyCertChainWithPolicy(nodeCert, principalCert, master.public, {
        minimum_suite: HYBRID_SIGNATURE_SUITE_ID,
      })
    ).rejects.toThrow(/hybrid-required chain policy/);
  });
});

describe("mesh/trust-root — HKDF per-node key derivation", () => {
  it("derives deterministic node_transport_key from master + node_id + mode", () => {
    const master = generateFortressMaster();
    const k1 = deriveNodeTransportKey({
      fortress_master_secret: master.private_key,
      node_id: "node-abc",
      node_mode: "local",
    });
    const k2 = deriveNodeTransportKey({
      fortress_master_secret: master.private_key,
      node_id: "node-abc",
      node_mode: "local",
    });
    expect(k1).toHaveLength(32);
    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(true);
  });

  it("derives different node_transport_key for different modes", () => {
    const master = generateFortressMaster();
    const k1 = deriveNodeTransportKey({
      fortress_master_secret: master.private_key,
      node_id: "node-abc",
      node_mode: "local",
    });
    const k2 = deriveNodeTransportKey({
      fortress_master_secret: master.private_key,
      node_id: "node-abc",
      node_mode: "sovereign_tee",
    });
    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(false);
  });

  it("derives different node_transport_key for different node_ids", () => {
    const master = generateFortressMaster();
    const k1 = deriveNodeTransportKey({
      fortress_master_secret: master.private_key,
      node_id: "node-abc",
      node_mode: "local",
    });
    const k2 = deriveNodeTransportKey({
      fortress_master_secret: master.private_key,
      node_id: "node-xyz",
      node_mode: "local",
    });
    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(false);
  });

  it("derives different keys for transport vs audit-chain purpose (domain separation)", () => {
    const master = generateFortressMaster();
    const transport = deriveNodeTransportKey({
      fortress_master_secret: master.private_key,
      node_id: "node-abc",
      node_mode: "local",
    });
    const audit = deriveNodeAuditChainKey({
      fortress_master_secret: master.private_key,
      node_id: "node-abc",
    });
    expect(Buffer.from(transport).equals(Buffer.from(audit))).toBe(false);
  });

  it("guardian-recovery invariant: re-deriving from the same master reproduces the keys", () => {
    const master = generateFortressMaster();
    const original = deriveNodeAuditChainKey({
      fortress_master_secret: master.private_key,
      node_id: "node-abc",
    });
    // Simulate guardian recovery producing the same master bytes.
    const recoveredMasterSecret = new Uint8Array(master.private_key);
    const recovered = deriveNodeAuditChainKey({
      fortress_master_secret: recoveredMasterSecret,
      node_id: "node-abc",
    });
    expect(Buffer.from(original).equals(Buffer.from(recovered))).toBe(true);
  });
});
