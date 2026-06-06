/**
 * Sanctuary MCP Server — L1 Cognitive Sovereignty: StateStore
 *
 * The encrypted state store is the foundation of Sanctuary.
 * Every read and write goes through here. All data is encrypted
 * with namespace-specific keys. All writes are signed by an identity.
 * All reads verify integrity via Merkle proofs.
 *
 * Security invariants:
 * - Plaintext never touches the filesystem
 * - Every write gets a unique IV
 * - Every write is signed (non-repudiation)
 * - Monotonic version numbers prevent rollback
 * - Merkle tree verifies namespace integrity
 * - Secure deletion overwrites before unlinking
 */

import type { StorageBackend } from "../storage/interface.js";
import { ed25519 } from "@noble/curves/ed25519";
import {
  encrypt,
  decrypt,
  type EncryptedPayload,
} from "../core/encryption.js";
import {
  hashToString,
  computeMerkleRoot,
  generateMerkleProof,
  verifyMerkleProof,
} from "../core/hashing.js";
import { sign, verify } from "../core/identity.js";
import { deriveNamespaceKey } from "../core/key-derivation.js";
import {
  toBase64url,
  fromBase64url,
  stringToBytes,
  bytesToString,
} from "../core/encoding.js";
import type { EncryptedPayload as EncPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import type { StoredIdentity } from "../core/identity.js";

const STATE_ENVELOPE_SCHEMA_VERSION = 2;
const STATE_ENVELOPE_SIGNING_DOMAIN = "sanctuary.state-envelope.v1\n";
const STATE_ENVELOPE_PUBLIC_KEYS_KEY = "state-envelope-public-keys-v1";
const STATE_ENVELOPE_VERSION_ANCHORS_KEY = "state-envelope-version-anchors-v1";

export type StateVerificationClassification =
  | "signature_mismatch"
  | "kid_unknown"
  | "integrity_hash_mismatch"
  | "schema_mismatch"
  | "rollback_detected";

export class StateVerificationError extends Error {
  readonly classification: StateVerificationClassification;

  constructor(classification: StateVerificationClassification, message: string) {
    super(message);
    this.name = "StateVerificationError";
    this.classification = classification;
  }
}

export class LegacyEnvelopeWarning extends Error {
  readonly classification = "legacy_schema_1";

  constructor(message: string) {
    super(message);
    this.name = "LegacyEnvelopeWarning";
  }
}

export interface LegacyEnvelopeWarningInfo {
  name: "LegacyEnvelopeWarning";
  classification: "legacy_schema_1";
  message: string;
}

export interface SignedStateEnvelope {
  namespace: string;
  key: string;
  version: number;
  kid: string;
  metadata: {
    timestamp: string;
    schema_version: number;
    content_type?: string;
    ttl_seconds?: number;
    tags?: string[];
  };
  integrity_hash: string;
  payload: {
    schema_version: number;
    algo: string;
    nonce: string;
    tag: string;
    ciphertext: string;
    encrypted_at: string;
  };
}

/**
 * Reserved namespace prefixes — used by internal subsystems.
 * Imported bundles MUST NOT write to these namespaces.
 */
const RESERVED_NAMESPACE_PREFIXES = [
  "_identities",
  "_policies",
  "_audit",
  "_meta",
  "_principal",
  "_commitments",
  "_reputation",
  "_escrow",
  "_guarantees",
  "_bridge",
  "_federation",
  "_handshake",
  "_shr",
  "_sovereignty_profile",
  "_context_gate_policies",
  "_fortress_mode",
] as const;

/**
 * Check whether a namespace is reserved (internal subsystem use only).
 * External callers MUST NOT read, write, list, or import these namespaces.
 */
export function isReservedNamespace(namespace: string): boolean {
  return RESERVED_NAMESPACE_PREFIXES.some(
    (prefix) => namespace === prefix || namespace.startsWith(prefix + "/")
  );
}

/** On-disk format for an encrypted state entry */
export interface StateEntry {
  /** Format version. v1 is legacy signed-ciphertext-only. v2 signs the full envelope. */
  v: number;
  /** Canonical schema-2 state envelope signed by sig. */
  envelope?: SignedStateEnvelope;
  /** Encrypted payload */
  payload: EncryptedPayload;
  /** Version number (monotonically increasing) */
  ver: number;
  /** Legacy-compatible signature over ciphertext by the writing identity (base64url) */
  sig: string;
  /** Schema-2 signature over the canonical envelope by the writing identity (base64url) */
  envelope_sig?: string;
  /** Identity that wrote this entry */
  kid: string;
  /** SHA-256 of the plaintext value (base64url, for client-side verification) */
  integrity_hash: string;
  /** Metadata */
  metadata: {
    content_type?: string;
    ttl_seconds?: number;
    tags?: string[];
    schema_version?: number;
    written_at: string;
  };
}

/** Result of a state write operation */
export interface WriteResult {
  key: string;
  namespace: string;
  version: number;
  merkle_root: string;
  written_at: string;
  size_bytes: number;
  integrity_hash: string;
}

/** Result of a state read operation */
export interface ReadResult {
  key: string;
  namespace: string;
  value: string;
  version: number;
  integrity_verified: boolean;
  signature_verified: boolean;
  merkle_proof: string[];
  written_at: string;
  written_by: string;
  warnings?: LegacyEnvelopeWarningInfo[];
}

/** Options for state write */
export interface WriteOptions {
  content_type?: string;
  ttl_seconds?: number;
  tags?: string[];
}

/** Cached namespace key with TTL */
interface CachedKey {
  key: Uint8Array;
  expiresAt: number;
}

function canonicalize(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item));
  }

  const record = value as Record<string, unknown>;
  const canonical: Record<string, unknown> = {};
  for (const key of Object.keys(record).sort()) {
    const item = record[key];
    if (item !== undefined) {
      canonical[key] = canonicalize(item);
    }
  }
  return canonical;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function stateEnvelopeSigningBytes(envelope: SignedStateEnvelope): Uint8Array {
  return stringToBytes(STATE_ENVELOPE_SIGNING_DOMAIN + canonicalJson(envelope));
}

function legacyWarning(): LegacyEnvelopeWarningInfo {
  return {
    name: "LegacyEnvelopeWarning",
    classification: "legacy_schema_1",
    message:
      "Legacy state envelope v1 loaded with ciphertext-only signature verification",
  };
}

function payloadAuthTag(payload: EncryptedPayload): string {
  const ciphertextAndTag = fromBase64url(payload.ct);
  if (ciphertextAndTag.length < 16) {
    throw new StateVerificationError(
      "schema_mismatch",
      "Encrypted payload is too short to contain an authentication tag"
    );
  }
  return toBase64url(ciphertextAndTag.slice(ciphertextAndTag.length - 16));
}

function buildSignedEnvelope(args: {
  namespace: string;
  key: string;
  version: number;
  kid: string;
  metadata: StateEntry["metadata"];
  integrityHash: string;
  payload: EncryptedPayload;
}): SignedStateEnvelope {
  return {
    namespace: args.namespace,
    key: args.key,
    version: args.version,
    kid: args.kid,
    metadata: {
      timestamp: args.metadata.written_at,
      schema_version: STATE_ENVELOPE_SCHEMA_VERSION,
      content_type: args.metadata.content_type,
      ttl_seconds: args.metadata.ttl_seconds,
      tags: args.metadata.tags,
    },
    integrity_hash: args.integrityHash,
    payload: {
      schema_version: args.payload.v,
      algo: args.payload.alg,
      nonce: args.payload.iv,
      tag: payloadAuthTag(args.payload),
      ciphertext: args.payload.ct,
      encrypted_at: args.payload.ts,
    },
  };
}

export class StateStore {
  private storage: StorageBackend;
  private masterKey: Uint8Array;

  // Cache of version numbers per namespace/key for anti-rollback
  private versionCache = new Map<string, number>();

  // Cache of content hashes per namespace for Merkle tree computation
  private contentHashes = new Map<string, Map<string, string>>();

  // LRU-with-TTL cache for derived namespace keys (avoids repeated HKDF)
  private namespaceKeyCache = new Map<string, CachedKey>();
  private static readonly KEY_CACHE_TTL_MS = 15 * 60 * 1000; // 15 minutes
  private static readonly KEY_CACHE_MAX_ENTRIES = 128;

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.masterKey = masterKey;
  }

  /**
   * Get or derive a namespace encryption key, with caching.
   * Cache entries expire after 15 minutes and are evicted LRU when
   * the cache exceeds 128 entries.
   */
  private getNamespaceKey(namespace: string): Uint8Array {
    const now = Date.now();
    const cached = this.namespaceKeyCache.get(namespace);
    if (cached && cached.expiresAt > now) {
      return cached.key;
    }

    // Evict expired or LRU entries if at capacity
    if (this.namespaceKeyCache.size >= StateStore.KEY_CACHE_MAX_ENTRIES) {
      // Remove oldest entry (Map iteration order = insertion order)
      const firstKey = this.namespaceKeyCache.keys().next().value;
      if (firstKey !== undefined) this.namespaceKeyCache.delete(firstKey);
    }

    const derived = deriveNamespaceKey(this.masterKey, namespace);
    this.namespaceKeyCache.set(namespace, {
      key: derived,
      expiresAt: now + StateStore.KEY_CACHE_TTL_MS,
    });
    return derived;
  }

  /** Invalidate all cached namespace keys (call on master key rotation). */
  invalidateKeyCache(): void {
    this.namespaceKeyCache.clear();
  }

  private versionKey(namespace: string, key: string): string {
    return `${namespace}/${key}`;
  }

  private get identityEncryptionKey(): Uint8Array {
    return derivePurposeKey(this.masterKey, "identity-encryption");
  }

  private publicKeyFromEncryptedPrivateKey(
    encryptedPrivateKey: EncPayload,
    identityEncryptionKey: Uint8Array
  ): Uint8Array {
    const privateKey = decrypt(encryptedPrivateKey, identityEncryptionKey);
    try {
      return ed25519.getPublicKey(privateKey);
    } finally {
      privateKey.fill(0);
    }
  }

  private async loadJsonRecord(
    key: string
  ): Promise<Record<string, unknown>> {
    const raw = await this.storage.read("_meta", key);
    if (!raw) return {};

    try {
      const parsed = JSON.parse(bytesToString(raw));
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      // Fall through to a typed verification failure.
    }

    throw new StateVerificationError(
      "schema_mismatch",
      `State metadata record is corrupted: _meta/${key}`
    );
  }

  private async saveJsonRecord(
    key: string,
    record: Record<string, unknown>
  ): Promise<void> {
    await this.storage.write("_meta", key, stringToBytes(JSON.stringify(record)));
  }

  private async rememberWriterPublicKey(
    kid: string,
    publicKey: Uint8Array
  ): Promise<void> {
    const registry = await this.loadJsonRecord(STATE_ENVELOPE_PUBLIC_KEYS_KEY);
    const publicKeyString = toBase64url(publicKey);
    if (registry[kid] === publicKeyString) return;

    registry[kid] = publicKeyString;
    await this.saveJsonRecord(STATE_ENVELOPE_PUBLIC_KEYS_KEY, registry);
  }

  private async resolveStoredIdentity(kid: string): Promise<StoredIdentity | null> {
    try {
      const raw = await this.storage.read("_identities", kid);
      if (raw) {
        const encrypted = JSON.parse(bytesToString(raw)) as EncryptedPayload;
        const decrypted = decrypt(encrypted, this.identityEncryptionKey);
        return JSON.parse(bytesToString(decrypted)) as StoredIdentity;
      }
    } catch {
      return null;
    }

    return null;
  }

  private async resolveWriterPublicKey(kid: string): Promise<Uint8Array | null> {
    const identity = await this.resolveStoredIdentity(kid);
    if (identity) {
      return fromBase64url(identity.public_key);
    }

    const registry = await this.loadJsonRecord(STATE_ENVELOPE_PUBLIC_KEYS_KEY);
    const publicKey = registry[kid];
    if (typeof publicKey !== "string") return null;

    try {
      return fromBase64url(publicKey);
    } catch {
      return null;
    }
  }

  private async getAnchoredVersion(
    namespace: string,
    key: string
  ): Promise<number> {
    const anchors = await this.loadJsonRecord(STATE_ENVELOPE_VERSION_ANCHORS_KEY);
    const anchored = anchors[this.versionKey(namespace, key)];
    return typeof anchored === "number" && Number.isSafeInteger(anchored)
      ? anchored
      : 0;
  }

  private async observeVersion(
    namespace: string,
    key: string,
    version: number
  ): Promise<void> {
    const anchors = await this.loadJsonRecord(STATE_ENVELOPE_VERSION_ANCHORS_KEY);
    const vk = this.versionKey(namespace, key);
    const anchored = anchors[vk];
    const lastSeen =
      typeof anchored === "number" && Number.isSafeInteger(anchored)
        ? anchored
        : 0;

    if (version < lastSeen) {
      throw new StateVerificationError(
        "rollback_detected",
        `Rollback detected for ${namespace}/${key}: found version ${version}, expected at least ${lastSeen}`
      );
    }

    if (version > lastSeen) {
      anchors[vk] = version;
      await this.saveJsonRecord(STATE_ENVELOPE_VERSION_ANCHORS_KEY, anchors);
    }
  }

  /**
   * Get or initialize the content hash map for a namespace.
   */
  private async getNamespaceHashes(
    namespace: string
  ): Promise<Map<string, string>> {
    if (this.contentHashes.has(namespace)) {
      return this.contentHashes.get(namespace)!;
    }

    // Load existing entries to build the hash map
    const entries = await this.storage.list(namespace);
    const hashMap = new Map<string, string>();

    for (const entry of entries) {
      const raw = await this.storage.read(namespace, entry.key);
      if (raw) {
        try {
          const stateEntry: StateEntry = JSON.parse(bytesToString(raw));
          hashMap.set(entry.key, stateEntry.integrity_hash);
          this.versionCache.set(
            this.versionKey(namespace, entry.key),
            stateEntry.ver
          );
        } catch {
          // Corrupted entry — skip it
        }
      }
    }

    this.contentHashes.set(namespace, hashMap);
    return hashMap;
  }

  /**
   * Write encrypted state.
   *
   * @param namespace - Logical grouping
   * @param key - State key
   * @param value - Plaintext value (will be encrypted)
   * @param identityId - Identity performing the write
   * @param encryptedPrivateKey - Identity's encrypted private key (for signing)
   * @param identityEncryptionKey - Key to decrypt the identity's private key
   * @param options - Optional metadata
   */
  async write(
    namespace: string,
    key: string,
    value: string,
    identityId: string,
    encryptedPrivateKey: EncPayload,
    identityEncryptionKey: Uint8Array,
    options: WriteOptions = {}
  ): Promise<WriteResult> {
    const namespaceKey = this.getNamespaceKey(namespace);
    const plaintext = stringToBytes(value);

    // Compute integrity hash of plaintext
    const integrityHash = hashToString(plaintext);

    // Encrypt the value
    const payload = encrypt(plaintext, namespaceKey);

    // Determine version number (monotonically increasing)
    const vk = this.versionKey(namespace, key);
    const currentVersion = this.versionCache.get(vk) ?? 0;
    const anchoredVersion = await this.getAnchoredVersion(namespace, key);
    const newVersion = Math.max(currentVersion, anchoredVersion) + 1;

    const now = new Date().toISOString();
    const metadata: StateEntry["metadata"] = {
      content_type: options.content_type,
      ttl_seconds: options.ttl_seconds,
      tags: options.tags,
      schema_version: STATE_ENVELOPE_SCHEMA_VERSION,
      written_at: now,
    };
    const envelope = buildSignedEnvelope({
      namespace,
      key,
      version: newVersion,
      kid: identityId,
      metadata,
      integrityHash,
      payload,
    });

    // Sign the canonical envelope, binding path, version, writer, metadata,
    // plaintext hash, and ciphertext metadata to the writer identity.
    const envelopeSignature = sign(
      stateEnvelopeSigningBytes(envelope),
      encryptedPrivateKey,
      identityEncryptionKey
    );
    const legacyCiphertextSignature = sign(
      fromBase64url(payload.ct),
      encryptedPrivateKey,
      identityEncryptionKey
    );

    const writerPublicKey = this.publicKeyFromEncryptedPrivateKey(
      encryptedPrivateKey,
      identityEncryptionKey
    );

    // Construct the state entry
    const stateEntry: StateEntry = {
      v: STATE_ENVELOPE_SCHEMA_VERSION,
      envelope,
      payload,
      ver: newVersion,
      sig: toBase64url(legacyCiphertextSignature),
      envelope_sig: toBase64url(envelopeSignature),
      kid: identityId,
      integrity_hash: integrityHash,
      metadata,
    };

    // Serialize and write to storage
    const serialized = stringToBytes(JSON.stringify(stateEntry));
    await this.storage.write(namespace, key, serialized);
    await this.rememberWriterPublicKey(identityId, writerPublicKey);
    await this.observeVersion(namespace, key, newVersion);

    // Update caches
    this.versionCache.set(vk, newVersion);
    const nsHashes = await this.getNamespaceHashes(namespace);
    nsHashes.set(key, integrityHash);

    // Compute new Merkle root
    const merkleRoot = computeMerkleRoot(nsHashes);

    return {
      key,
      namespace,
      version: newVersion,
      merkle_root: merkleRoot,
      written_at: now,
      size_bytes: serialized.length,
      integrity_hash: integrityHash,
    };
  }

  /**
   * Read and decrypt state with default-on envelope verification.
   *
   * @param namespace - Logical grouping
   * @param key - State key
   * @param signerPublicKeyOrVerifyIntegrity - Optional expected public key for legacy callers, or verifyIntegrity boolean
   * @param verifyIntegrity - Whether to verify Merkle proof (default: true)
   */
  async read(
    namespace: string,
    key: string,
    signerPublicKeyOrVerifyIntegrity?: Uint8Array | boolean,
    verifyIntegrity = true
  ): Promise<ReadResult | null> {
    const signerPublicKey =
      signerPublicKeyOrVerifyIntegrity instanceof Uint8Array
        ? signerPublicKeyOrVerifyIntegrity
        : undefined;
    const shouldVerifyIntegrity =
      typeof signerPublicKeyOrVerifyIntegrity === "boolean"
        ? signerPublicKeyOrVerifyIntegrity
        : verifyIntegrity;

    return this.readInternal(namespace, key, {
      verifyIntegrity: shouldVerifyIntegrity,
      verifySignature: true,
      enforceRollback: true,
      signerPublicKey,
    });
  }

  /**
   * Explicit migration escape hatch for legacy state flows.
   * This skips signature and rollback verification and is intentionally not
   * exposed through MCP tools. Integrity hash and decryption authentication
   * are still checked before plaintext is returned.
   */
  async readUnverified(
    namespace: string,
    key: string,
    verifyIntegrity = true
  ): Promise<ReadResult | null> {
    return this.readInternal(namespace, key, {
      verifyIntegrity,
      verifySignature: false,
      enforceRollback: false,
    });
  }

  private validateSchema2Envelope(
    entry: StateEntry,
    namespace: string,
    key: string
  ): SignedStateEnvelope {
    if (!entry.envelope) {
      throw new StateVerificationError(
        "schema_mismatch",
        `State envelope schema 2 is missing for ${namespace}/${key}`
      );
    }

    const expected = buildSignedEnvelope({
      namespace,
      key,
      version: entry.ver,
      kid: entry.kid,
      metadata: entry.metadata,
      integrityHash: entry.integrity_hash,
      payload: entry.payload,
    });

    if (canonicalJson(entry.envelope) !== canonicalJson(expected)) {
      throw new StateVerificationError(
        "schema_mismatch",
        `State envelope metadata mismatch for ${namespace}/${key}`
      );
    }

    return entry.envelope;
  }

  private async verifyEntrySignature(
    entry: StateEntry,
    namespace: string,
    key: string,
    signerPublicKey?: Uint8Array
  ): Promise<{ verified: boolean; warnings?: LegacyEnvelopeWarningInfo[] }> {
    const publicKey = signerPublicKey ?? (await this.resolveWriterPublicKey(entry.kid));

    if (entry.v === 1) {
      const warnings = [legacyWarning()];
      if (!publicKey) {
        return { verified: false, warnings };
      }

      const sigValid = verify(
        fromBase64url(entry.payload.ct),
        fromBase64url(entry.sig),
        publicKey
      );
      if (!sigValid) {
        throw new StateVerificationError(
          "signature_mismatch",
          `Legacy state signature verification failed for ${namespace}/${key}`
        );
      }
      return { verified: true, warnings };
    }

    if (entry.v !== STATE_ENVELOPE_SCHEMA_VERSION) {
      throw new StateVerificationError(
        "schema_mismatch",
        `Unsupported state envelope schema: ${entry.v}`
      );
    }

    if (!publicKey) {
      throw new StateVerificationError(
        "kid_unknown",
        `Writer key not found for ${entry.kid}`
      );
    }

    const envelope = this.validateSchema2Envelope(entry, namespace, key);
    if (!entry.envelope_sig) {
      throw new StateVerificationError(
        "schema_mismatch",
        `State envelope signature is missing for ${namespace}/${key}`
      );
    }
    const sigValid = verify(
      stateEnvelopeSigningBytes(envelope),
      fromBase64url(entry.envelope_sig),
      publicKey
    );
    if (!sigValid) {
      throw new StateVerificationError(
        "signature_mismatch",
        `Signature verification failed for state envelope ${namespace}/${key}`
      );
    }

    const legacySigValid = verify(
      fromBase64url(entry.payload.ct),
      fromBase64url(entry.sig),
      publicKey
    );
    if (!legacySigValid) {
      throw new StateVerificationError(
        "signature_mismatch",
        `Signature verification failed for legacy ciphertext ${namespace}/${key}`
      );
    }

    return { verified: true };
  }

  private async migrateLegacyEntryToSchema2(
    entry: StateEntry,
    namespace: string,
    key: string
  ): Promise<StateEntry> {
    if (entry.v !== 1) return entry;

    const identity = await this.resolveStoredIdentity(entry.kid);
    if (!identity) return entry;

    const metadata: StateEntry["metadata"] = {
      ...entry.metadata,
      schema_version: STATE_ENVELOPE_SCHEMA_VERSION,
    };
    const envelope = buildSignedEnvelope({
      namespace,
      key,
      version: entry.ver,
      kid: entry.kid,
      metadata,
      integrityHash: entry.integrity_hash,
      payload: entry.payload,
    });
    const envelopeSignature = sign(
      stateEnvelopeSigningBytes(envelope),
      identity.encrypted_private_key,
      this.identityEncryptionKey
    );
    const migrated: StateEntry = {
      ...entry,
      v: STATE_ENVELOPE_SCHEMA_VERSION,
      envelope,
      envelope_sig: toBase64url(envelopeSignature),
      metadata,
    };

    await this.storage.write(namespace, key, stringToBytes(JSON.stringify(migrated)));
    await this.rememberWriterPublicKey(entry.kid, fromBase64url(identity.public_key));
    return migrated;
  }

  private async readInternal(
    namespace: string,
    key: string,
    options: {
      verifyIntegrity: boolean;
      verifySignature: boolean;
      enforceRollback: boolean;
      signerPublicKey?: Uint8Array;
    }
  ): Promise<ReadResult | null> {
    const raw = await this.storage.read(namespace, key);
    if (!raw) return null;

    let stateEntry: StateEntry;
    try {
      stateEntry = JSON.parse(bytesToString(raw));
    } catch {
      throw new StateVerificationError(
        "schema_mismatch",
        `Corrupted state entry: ${namespace}/${key}`
      );
    }

    // Anti-rollback check
    const vk = this.versionKey(namespace, key);
    const cachedVersion = this.versionCache.get(vk);
    if (
      options.enforceRollback &&
      cachedVersion !== undefined &&
      stateEntry.ver < cachedVersion
    ) {
      throw new StateVerificationError(
        "rollback_detected",
        `Rollback detected for ${namespace}/${key}: found version ${stateEntry.ver}, expected at least ${cachedVersion}`
      );
    }

    // F1: a legacy (v1) entry must never ADVANCE the version past an established
    // anchor. The current write schema is v2, so every legitimate version bump is
    // written as v2 — a v1 entry claiming a version above the persisted anchor can
    // only be a downgrade/replay forgery. The v1 signature binds the ciphertext
    // ONLY (not the version/namespace/key), so the signature check below cannot
    // catch this; the persisted anchor is the discriminator. (A genuine
    // pre-migration v1 entry sits at or below the anchor it established, or lives
    // on a never-anchored fortress where the anchor is 0.) NOTE: this depends on
    // the version-anchor file surviving; authenticating that file against
    // deletion/rollback (it is currently unsigned) is a separate hardening.
    if (options.enforceRollback && stateEntry.v === 1) {
      const anchoredVersion = await this.getAnchoredVersion(namespace, key);
      if (anchoredVersion > 0 && stateEntry.ver > anchoredVersion) {
        throw new StateVerificationError(
          "rollback_detected",
          `Rollback detected for ${namespace}/${key}: a legacy (v1) entry at version ${stateEntry.ver} cannot exceed the established anchor ${anchoredVersion} (legitimate advances are written as schema v2)`
        );
      }
    }

    let signatureVerified = false;
    let warnings: LegacyEnvelopeWarningInfo[] | undefined;
    if (options.verifySignature) {
      const verification = await this.verifyEntrySignature(
        stateEntry,
        namespace,
        key,
        options.signerPublicKey
      );
      signatureVerified = verification.verified;
      warnings = verification.warnings;
    }

    // Decrypt
    const namespaceKey = this.getNamespaceKey(namespace);
    const plaintext = decrypt(stateEntry.payload, namespaceKey);
    const value = bytesToString(plaintext);

    // Verify integrity hash
    const computedHash = hashToString(plaintext);
    if (computedHash !== stateEntry.integrity_hash) {
      throw new StateVerificationError(
        "integrity_hash_mismatch",
        `Integrity hash mismatch for ${namespace}/${key}: computed ${computedHash}, stored ${stateEntry.integrity_hash}`
      );
    }

    if (options.verifySignature && stateEntry.v === 1) {
      stateEntry = await this.migrateLegacyEntryToSchema2(stateEntry, namespace, key);
    }

    // Merkle proof verification
    let merkleProofPath: string[] = [];
    let integrityVerified = true;

    if (options.verifyIntegrity) {
      const nsHashes = await this.getNamespaceHashes(namespace);
      const proof = generateMerkleProof(nsHashes, key);
      if (proof) {
        integrityVerified = verifyMerkleProof(proof);
        merkleProofPath = proof.path.map(
          (step) => `${step.position}:${step.hash}`
        );
      }
    }

    if (options.enforceRollback) {
      await this.observeVersion(namespace, key, stateEntry.ver);
    }

    // Update version cache
    this.versionCache.set(vk, stateEntry.ver);

    return {
      key,
      namespace,
      value,
      version: stateEntry.ver,
      integrity_verified: integrityVerified,
      signature_verified: signatureVerified,
      merkle_proof: merkleProofPath,
      written_at: stateEntry.metadata.written_at,
      written_by: stateEntry.kid,
      warnings,
    };
  }

  /**
   * List keys in a namespace (metadata only — no decryption).
   */
  async list(
    namespace: string,
    prefix?: string,
    tags?: string[],
    limit = 100,
    offset = 0
  ): Promise<{
    keys: Array<{
      key: string;
      version: number;
      size_bytes: number;
      written_at: string;
      tags: string[];
    }>;
    total: number;
    merkle_root: string;
  }> {
    const storageEntries = await this.storage.list(namespace, prefix);
    const result: Array<{
      key: string;
      version: number;
      size_bytes: number;
      written_at: string;
      tags: string[];
    }> = [];

    for (const entry of storageEntries) {
      const raw = await this.storage.read(namespace, entry.key);
      if (!raw) continue;

      try {
        const stateEntry: StateEntry = JSON.parse(bytesToString(raw));

        // Filter by tags if specified
        if (tags && tags.length > 0) {
          const entryTags = stateEntry.metadata.tags ?? [];
          const hasMatchingTag = tags.some((t) => entryTags.includes(t));
          if (!hasMatchingTag) continue;
        }

        result.push({
          key: entry.key,
          version: stateEntry.ver,
          size_bytes: entry.size_bytes,
          written_at: stateEntry.metadata.written_at,
          tags: stateEntry.metadata.tags ?? [],
        });
      } catch {
        // Skip corrupted entries
      }
    }

    const nsHashes = await this.getNamespaceHashes(namespace);
    const merkleRoot = computeMerkleRoot(nsHashes);

    return {
      keys: result.slice(offset, offset + limit),
      total: result.length,
      merkle_root: merkleRoot,
    };
  }

  /**
   * Securely delete state (overwrite with random bytes before removal).
   */
  async delete(
    namespace: string,
    key: string
  ): Promise<{
    deleted: boolean;
    key: string;
    namespace: string;
    new_merkle_root: string;
    deleted_at: string;
  }> {
    const deleted = await this.storage.delete(namespace, key, true);

    // Update caches
    const vk = this.versionKey(namespace, key);
    this.versionCache.delete(vk);
    const nsHashes = await this.getNamespaceHashes(namespace);
    nsHashes.delete(key);
    const merkleRoot = computeMerkleRoot(nsHashes);

    return {
      deleted,
      key,
      namespace,
      new_merkle_root: merkleRoot,
      deleted_at: new Date().toISOString(),
    };
  }

  /**
   * Export all state for a namespace as an encrypted bundle.
   */
  async export(
    namespace?: string
  ): Promise<{
    bundle: string;
    namespaces: string[];
    total_keys: number;
    bundle_hash: string;
    exported_at: string;
  }> {
    const namespacesToExport: string[] = [];

    if (namespace) {
      namespacesToExport.push(namespace);
    } else {
      // Discover all namespaces from the content hash cache
      for (const ns of this.contentHashes.keys()) {
        namespacesToExport.push(ns);
      }
    }

    const exportData: Record<
      string,
      Array<{ key: string; entry: StateEntry }>
    > = {};
    let totalKeys = 0;

    for (const ns of namespacesToExport) {
      const entries = await this.storage.list(ns);
      exportData[ns] = [];

      for (const entry of entries) {
        const raw = await this.storage.read(ns, entry.key);
        if (!raw) continue;

        try {
          const stateEntry: StateEntry = JSON.parse(bytesToString(raw));
          exportData[ns]!.push({ key: entry.key, entry: stateEntry });
          totalKeys++;
        } catch {
          // Skip corrupted entries
        }
      }
    }

    const bundleJson = JSON.stringify({
      sanctuary_export_version: 1,
      exported_at: new Date().toISOString(),
      namespaces: namespacesToExport,
      data: exportData,
    });

    const bundleBytes = stringToBytes(bundleJson);
    const bundleHash = hashToString(bundleBytes);

    return {
      bundle: toBase64url(bundleBytes),
      namespaces: namespacesToExport,
      total_keys: totalKeys,
      bundle_hash: bundleHash,
      exported_at: new Date().toISOString(),
    };
  }

  /**
   * Import a previously exported state bundle.
   */
  async import(
    bundleBase64: string,
    conflictResolution: "skip" | "overwrite" | "version" = "skip",
    publicKeyResolver: (kid: string) => Uint8Array | null
  ): Promise<{
    imported_keys: number;
    skipped_keys: number;
    skipped_invalid_sig: number;
    skipped_unknown_kid: number;
    conflicts: number;
    namespaces: string[];
    imported_at: string;
  }> {
    const bundleBytes = fromBase64url(bundleBase64);
    const bundleJson = bytesToString(bundleBytes);
    const bundle = JSON.parse(bundleJson);

    let importedKeys = 0;
    let skippedKeys = 0;
    let skippedInvalidSig = 0;
    let skippedUnknownKid = 0;
    let conflicts = 0;
    const namespaces: string[] = [];

    for (const [ns, entries] of Object.entries(
      bundle.data as Record<string, Array<{ key: string; entry: StateEntry }>>
    )) {
      // Namespace firewall: skip reserved namespaces during import
      if (RESERVED_NAMESPACE_PREFIXES.some(
        (prefix) => ns === prefix || ns.startsWith(prefix + "/")
      )) {
        skippedKeys += (entries as Array<{ key: string; entry: StateEntry }>).length;
        continue;
      }
      namespaces.push(ns);

      for (const { key, entry } of entries) {
        // Signature verification: mandatory for all imported entries
        // Resolve the signing identity
        const signerPublicKey = publicKeyResolver(entry.kid);
        if (!signerPublicKey) {
          skippedUnknownKid++;
          skippedKeys++;
          continue;
        }

        // Verify the signature against the schema-2 envelope or legacy ciphertext.
        try {
          if (entry.v !== 1 && entry.v !== STATE_ENVELOPE_SCHEMA_VERSION) {
            skippedInvalidSig++;
            skippedKeys++;
            continue;
          }
          const signaturePayload =
            entry.v === STATE_ENVELOPE_SCHEMA_VERSION
              ? stateEnvelopeSigningBytes(
                  this.validateSchema2Envelope(entry, ns, key)
                )
              : fromBase64url(entry.payload.ct);
          const signature =
            entry.v === STATE_ENVELOPE_SCHEMA_VERSION
              ? entry.envelope_sig
              : entry.sig;
          if (!signature) {
            skippedInvalidSig++;
            skippedKeys++;
            continue;
          }
          const sigValid = verify(
            signaturePayload,
            fromBase64url(signature),
            signerPublicKey
          );
          if (!sigValid) {
            skippedInvalidSig++;
            skippedKeys++;
            continue;
          }
          if (entry.v === STATE_ENVELOPE_SCHEMA_VERSION) {
            const legacySigValid = verify(
              fromBase64url(entry.payload.ct),
              fromBase64url(entry.sig),
              signerPublicKey
            );
            if (!legacySigValid) {
              skippedInvalidSig++;
              skippedKeys++;
              continue;
            }
          }
        } catch {
          // Malformed signature or ciphertext — reject
          skippedInvalidSig++;
          skippedKeys++;
          continue;
        }

        const exists = await this.storage.exists(ns, key);

        if (exists) {
          conflicts++;
          if (conflictResolution === "skip") {
            skippedKeys++;
            continue;
          }
          if (conflictResolution === "version") {
            // Only overwrite if imported version is higher
            const raw = await this.storage.read(ns, key);
            if (raw) {
              try {
                const existingEntry: StateEntry = JSON.parse(
                  bytesToString(raw)
                );
                if (entry.ver <= existingEntry.ver) {
                  skippedKeys++;
                  continue;
                }
              } catch {
                // Corrupted existing entry — overwrite
              }
            }
          }
          // conflictResolution === "overwrite" falls through
        }

        // Write the entry
        const serialized = stringToBytes(JSON.stringify(entry));
        await this.storage.write(ns, key, serialized);
        importedKeys++;

        // Update caches
        const vk = this.versionKey(ns, key);
        this.versionCache.set(vk, entry.ver);
        const nsHashes = await this.getNamespaceHashes(ns);
        nsHashes.set(key, entry.integrity_hash);
      }
    }

    return {
      imported_keys: importedKeys,
      skipped_keys: skippedKeys,
      skipped_invalid_sig: skippedInvalidSig,
      skipped_unknown_kid: skippedUnknownKid,
      conflicts,
      namespaces,
      imported_at: new Date().toISOString(),
    };
  }
}
