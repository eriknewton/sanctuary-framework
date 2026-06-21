/**
 * Sanctuary Federation Protocol v0.1 — Trust Root
 *
 * Fortress-master → principal-cert → per-node-cert chain.
 *
 * Key responsibilities:
 * - Generate fortress-master keypair at bootstrap (private key lives only in the encrypted state store,
 *   never returned from this module's public surface).
 * - Issue principal certificates signed by fortress-master.
 * - Issue per-node certificates signed by the operator's principal (optionally also
 *   signed by fortress-master for v1.x-ready operators — §10.4).
 * - Verify certificate chains against the pinned fortress-master public key.
 * - Derive per-node per-purpose symmetric keys via HKDF (transport, audit-chain).
 *
 * Security invariants:
 * - Private keys never appear in any return value from verifier / chain-validator paths.
 * - v0.1 cert issuance rejects reserved capability bits (§10.2, hard gate).
 * - Chain validation refuses any cert whose chain does not terminate at the pinned
 *   fortress-master public key (cross-operator isolation — §10.5).
 * - Canonical JSON signing ensures signatures verify deterministically across platforms.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import {
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../core/encoding.js";
import { generateKeypair } from "../core/identity.js";
import { randomBytes } from "../core/random.js";
import { canonicalizeToBytes } from "./canonical-json.js";
import {
  HKDF_NODE_AUDIT_CHAIN_INFO_PREFIX,
  HKDF_NODE_TRANSPORT_INFO_PREFIX,
  hasReservedCapabilityBits,
  type NodeMode,
  V01_ALLOWED_CAPABILITY_MASK,
} from "./constants.js";
import {
  MeshChainError,
  MeshReservedCapabilityBitError,
} from "./errors.js";
import type {
  FortressMasterPublicKey,
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "./types.js";

export const NODE_IDENTITY_CERTIFICATE_VERSION_EXPIRING =
  "sanctuary.v1.expiring-node-cert" as const;

// ═══════════════════════════════════════════════════════════════════════
// Bootstrap
// ═══════════════════════════════════════════════════════════════════════

/**
 * Generate a new fortress-master keypair at first-fortress bootstrap.
 *
 * The returned private key is the ONLY time this module yields the master's
 * secret material. Callers MUST immediately store it in the operator's encrypted state store
 * (encrypted under the unified passphrase) and discard the plaintext.
 *
 * Spec: §2.1, §3.7.
 */
export function generateFortressMaster(): {
  public: FortressMasterPublicKey;
  private_key: Uint8Array;
} {
  const { publicKey, privateKey } = generateKeypair();
  const fortressId = generateFortressId();
  return {
    public: {
      public_key: toBase64url(publicKey),
      fortress_id: fortressId,
      created_at: new Date().toISOString(),
    },
    private_key: privateKey,
  };
}

/**
 * Generate a 128-bit fortress-id. Stable for the fortress's lifetime; never re-used.
 *
 * Build-thread pick for §11 Q7 — we use 128 bits of randomness rendered as
 * hex (32 chars). This matches the spec's 128-bit recommendation and is stable,
 * opaque, and URL-safe. Not strictly a ULID (no embedded timestamp) because
 * the created_at field on FortressMasterPublicKey carries the timestamp
 * separately and we don't want to leak bootstrap time via the id itself.
 */
export function generateFortressId(): string {
  const bytes = randomBytes(16);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

// ═══════════════════════════════════════════════════════════════════════
// Certificate issuance
// ═══════════════════════════════════════════════════════════════════════

/**
 * Issue a principal certificate signed by the fortress-master.
 *
 * Called at fortress bootstrap (to issue the Root principal cert) and again
 * whenever the operator delegates to a subordinate principal (Partner / Associate
 * per Key 14). The master private key is required in plaintext only for the
 * signature operation and MUST be zeroed by the caller after return.
 */
export function issuePrincipalCertificate(params: {
  principal_id: string;
  principal_pubkey: Uint8Array;
  role: PrincipalCertificate["role"];
  fortress_id: string;
  master_private_key: Uint8Array;
  expires_at?: string;
}): PrincipalCertificate {
  const body = {
    principal_id: params.principal_id,
    principal_pubkey: toBase64url(params.principal_pubkey),
    role: params.role,
    fortress_id: params.fortress_id,
    issued_at: new Date().toISOString(),
    expires_at: params.expires_at,
  };
  const sig = ed25519.sign(canonicalizeToBytes(body), params.master_private_key);
  return {
    ...body,
    master_signature: toBase64url(sig),
  };
}

/**
 * Issue a per-node certificate at join (§3.1).
 *
 * Signed by the operator's principal. Optionally also signed by the fortress-master
 * (recommended; REQUIRED at v1.x per §10.4).
 *
 * v0.1 issuance rejects reserved capability bits (§10.2 hard gate). Throws
 * MeshReservedCapabilityBitError.
 */
export function issueNodeIdentityCertificate(params: {
  node_id: string;
  node_pubkey: Uint8Array;
  node_mode: NodeMode;
  fortress_id: string;
  capabilities: number;
  parent_chain: NodeIdentityCertificate["parent_chain"];
  principal_private_key: Uint8Array;
  expires_at?: string;
  tee_attestation_hash?: string;
  /** Optional — set to attach master_signature (recommended; REQUIRED at v1.x). */
  master_private_key?: Uint8Array;
}): NodeIdentityCertificate {
  if (hasReservedCapabilityBits(params.capabilities)) {
    throw new MeshReservedCapabilityBitError(params.capabilities);
  }
  if (params.capabilities === 0) {
    throw new MeshChainError(
      "v0.1 node cert MUST set at least CAP_STANDARD_FORTRESS_NODE (bit 0)"
    );
  }

  const body = {
    certificate_version: params.expires_at
      ? NODE_IDENTITY_CERTIFICATE_VERSION_EXPIRING
      : undefined,
    node_id: params.node_id,
    node_pubkey: toBase64url(params.node_pubkey),
    node_mode: params.node_mode,
    fortress_id: params.fortress_id,
    joined_at: new Date().toISOString(),
    expires_at: params.expires_at,
    capabilities: params.capabilities,
    parent_chain: params.parent_chain,
    tee_attestation_hash: params.tee_attestation_hash,
    // These are optional v1.x reservation slots. Always empty at v0.1 issuance;
    // v1.x issuers will populate delegated_grants. Present in canonicalization
    // so v1.x signatures over a cert with non-empty slots remain deterministic.
    delegated_grants: [] as unknown[],
    attestation_lineage_chain: [] as unknown[],
  };
  const bytesToSign = canonicalizeToBytes(body);
  const principalSig = ed25519.sign(bytesToSign, params.principal_private_key);
  const cert: NodeIdentityCertificate = {
    ...body,
    principal_signature: toBase64url(principalSig),
  };
  if (params.master_private_key) {
    const masterSig = ed25519.sign(bytesToSign, params.master_private_key);
    cert.master_signature = toBase64url(masterSig);
  }
  return cert;
}

// ═══════════════════════════════════════════════════════════════════════
// Chain verification
// ═══════════════════════════════════════════════════════════════════════

/**
 * Verify a principal certificate against a pinned fortress-master public key.
 *
 * Returns on success; throws MeshChainError on any failure.
 */
export function verifyPrincipalCertificate(
  cert: PrincipalCertificate,
  pinnedMasterPubkey: FortressMasterPublicKey,
  nowMs = Date.now()
): void {
  if (cert.fortress_id !== pinnedMasterPubkey.fortress_id) {
    throw new MeshChainError(
      `principal cert fortress_id=${cert.fortress_id} does not match pinned master fortress_id=${pinnedMasterPubkey.fortress_id} — cross-operator isolation invariant`
    );
  }
  if (cert.expires_at && Date.parse(cert.expires_at) < nowMs) {
    throw new MeshChainError(
      `principal cert ${cert.principal_id} expired at ${cert.expires_at}`
    );
  }
  const body = {
    principal_id: cert.principal_id,
    principal_pubkey: cert.principal_pubkey,
    role: cert.role,
    fortress_id: cert.fortress_id,
    issued_at: cert.issued_at,
    expires_at: cert.expires_at,
  };
  const ok = ed25519.verify(
    fromBase64url(cert.master_signature),
    canonicalizeToBytes(body),
    fromBase64url(pinnedMasterPubkey.public_key)
  );
  if (!ok) {
    throw new MeshChainError(
      `principal cert ${cert.principal_id} signature does not verify against pinned fortress-master`
    );
  }
}

/**
 * Verify a node identity certificate's chain:
 *   node_cert → principal_cert → fortress-master
 *
 * Walks both hops. Refuses any cert whose chain does not terminate at the pinned
 * fortress-master — cross-operator isolation invariant (§10.5, hard-gate walkthrough
 * §2.5).
 *
 * If `cert.master_signature` is present, it is ALSO verified against the pinned
 * fortress-master public key — the v1.x-ready hook at v0.1.
 *
 * v0.1 verifier tolerates unknown (reserved) capability bits on otherwise-valid
 * certs (forward-compat for v1.x issuers). Reserved capability bits 3-31 are
 * accepted on verify (spec S10.2 of Federation Protocol v0.1).
 * `v01VisibleCapabilities()` masks them off for v0.1-bounded display. Issuance
 * correctly rejects bits 3-31; only verify is forward-compat.
 */
export function verifyCertChain(
  cert: NodeIdentityCertificate,
  principalCert: PrincipalCertificate,
  pinnedMasterPubkey: FortressMasterPublicKey,
  nowMs = Date.now()
): void {
  // Fortress-id coherence across the whole chain.
  if (cert.fortress_id !== pinnedMasterPubkey.fortress_id) {
    throw new MeshChainError(
      `node cert fortress_id=${cert.fortress_id} does not match pinned master fortress_id=${pinnedMasterPubkey.fortress_id} — cross-operator isolation invariant`
    );
  }
  if (principalCert.fortress_id !== pinnedMasterPubkey.fortress_id) {
    throw new MeshChainError(
      `principal cert fortress_id mismatch during node-chain validation`
    );
  }
  if (
    cert.parent_chain.fortress_master_pubkey !== pinnedMasterPubkey.public_key
  ) {
    throw new MeshChainError(
      `node cert parent_chain.fortress_master_pubkey does not match pinned master`
    );
  }
  if (cert.parent_chain.principal_id !== principalCert.principal_id) {
    throw new MeshChainError(
      `node cert parent_chain.principal_id=${cert.parent_chain.principal_id} does not match given principal cert ${principalCert.principal_id}`
    );
  }
  if (cert.parent_chain.principal_pubkey !== principalCert.principal_pubkey) {
    throw new MeshChainError(
      `node cert parent_chain.principal_pubkey does not match given principal cert`
    );
  }

  // Walk the upper hop: principal → master.
  verifyPrincipalCertificate(principalCert, pinnedMasterPubkey, nowMs);

  // Migration-safe node expiry: legacy node certs with no expires_at remain
  // non-expiring, but any present expiry is signed below and enforced here.
  if (cert.certificate_version !== undefined) {
    if (cert.certificate_version !== NODE_IDENTITY_CERTIFICATE_VERSION_EXPIRING) {
      throw new MeshChainError(
        `node cert ${cert.node_id} has unsupported certificate_version ${cert.certificate_version}`
      );
    }
    if (!cert.expires_at) {
      throw new MeshChainError(
        `node cert ${cert.node_id} has certificate_version without expires_at`
      );
    }
  }
  if (cert.expires_at) {
    if (cert.certificate_version !== NODE_IDENTITY_CERTIFICATE_VERSION_EXPIRING) {
      throw new MeshChainError(
        `node cert ${cert.node_id} missing certificate_version ${NODE_IDENTITY_CERTIFICATE_VERSION_EXPIRING}`
      );
    }
    const expiresMs = Date.parse(cert.expires_at);
    if (Number.isNaN(expiresMs) || expiresMs < nowMs) {
      throw new MeshChainError(
        `node cert ${cert.node_id} expired at ${cert.expires_at}`
      );
    }
  }

  // Walk the lower hop: node → principal.
  const body = {
    certificate_version: cert.certificate_version,
    node_id: cert.node_id,
    node_pubkey: cert.node_pubkey,
    node_mode: cert.node_mode,
    fortress_id: cert.fortress_id,
    joined_at: cert.joined_at,
    expires_at: cert.expires_at,
    capabilities: cert.capabilities,
    parent_chain: cert.parent_chain,
    tee_attestation_hash: cert.tee_attestation_hash,
    delegated_grants: cert.delegated_grants ?? [],
    attestation_lineage_chain: cert.attestation_lineage_chain ?? [],
  };
  const bytesToVerify = canonicalizeToBytes(body);
  const principalOk = ed25519.verify(
    fromBase64url(cert.principal_signature),
    bytesToVerify,
    fromBase64url(principalCert.principal_pubkey)
  );
  if (!principalOk) {
    throw new MeshChainError(
      `node cert ${cert.node_id} principal_signature does not verify against principal ${principalCert.principal_id}`
    );
  }

  // Optional master-signature hop (v1.x-ready hook at v0.1).
  if (cert.master_signature) {
    const masterOk = ed25519.verify(
      fromBase64url(cert.master_signature),
      bytesToVerify,
      fromBase64url(pinnedMasterPubkey.public_key)
    );
    if (!masterOk) {
      throw new MeshChainError(
        `node cert ${cert.node_id} master_signature present but does not verify against pinned fortress-master`
      );
    }
  }
}

/**
 * Return the v0.1-recognized subset of capability bits on a cert. Reserved bits
 * are silently masked off — this is the "v0.1 verifier tolerates unknown bits"
 * behavior required by §10.2.
 */
export function v01VisibleCapabilities(cert: NodeIdentityCertificate): number {
  return cert.capabilities & V01_ALLOWED_CAPABILITY_MASK;
}

// ═══════════════════════════════════════════════════════════════════════
// HKDF-derived per-node symmetric keys (§2.2)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Derive the per-node transport-encryption symmetric key.
 *
 * Spec §2.2:
 *   node_transport_key = HKDF(
 *     ikm    = fortress_master_secret,
 *     salt   = node_id,
 *     info   = "sanctuary-fed-v0.1-transport" || node_id || node_mode,
 *     length = 32
 *   )
 *
 * Deterministic — same master + same node_id + same mode → same key. Recoverable
 * from the master under guardian quorum without re-distributing per-node secrets.
 */
export function deriveNodeTransportKey(params: {
  fortress_master_secret: Uint8Array;
  node_id: string;
  node_mode: NodeMode;
}): Uint8Array {
  const salt = stringToBytes(params.node_id);
  const info = stringToBytes(
    HKDF_NODE_TRANSPORT_INFO_PREFIX + params.node_id + params.node_mode
  );
  return hkdf(sha256, params.fortress_master_secret, salt, info, 32);
}

/**
 * Derive the per-node audit-chain HMAC key.
 *
 * Spec §2.2:
 *   node_audit_chain_key = HKDF(
 *     ikm    = fortress_master_secret,
 *     salt   = node_id,
 *     info   = "sanctuary-fed-v0.1-audit-chain" || node_id,
 *     length = 32
 *   )
 *
 * Used as the HMAC key for AuditBatch.hkdf_chain_proof (§5.2). A stolen per-node
 * signing key alone cannot forge this proof — the attacker also needs the master
 * secret (or the HKDF-derived key itself, which is not persisted separately).
 */
export function deriveNodeAuditChainKey(params: {
  fortress_master_secret: Uint8Array;
  node_id: string;
}): Uint8Array {
  const salt = stringToBytes(params.node_id);
  const info = stringToBytes(
    HKDF_NODE_AUDIT_CHAIN_INFO_PREFIX + params.node_id
  );
  return hkdf(sha256, params.fortress_master_secret, salt, info, 32);
}
