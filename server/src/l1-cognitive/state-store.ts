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

/** On-disk format for an encrypted state entry */
export interface StateEntry {
  /** Format version */
  v: number;
  /** Encrypted payload */
  payload: EncryptedPayload;
  /** Version number (monotonically increasing) */
  ver: number;
  /** Signature over ciphertext by the writing identity (base64url) */
  sig: string;
  /** Identity that wrote this entry */
  kid: string;
  /** SHA-256 of the plaintext value (base64url, for client-side verification) */
  integrity_hash: string;
  /** Metadata */
  metadata: {
    content_type?: string;
    ttl_seconds?: number;
    tags?: string[];
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
  merkle_proof: string[];
  written_at: string;
  written_by: string;
}

/** Options for state write */
export interface WriteOptions {
  content_type?: string;
  ttl_seconds?: number;
  tags?: string[];
}

export class StateStore {
  private storage: StorageBackend;
  private masterKey: Uint8Array;

  // Cache of version numbers per namespace/key for anti-rollback
  private versionCache = new Map<string, number>();

  // Cache of content hashes per namespace for Merkle tree computation
  private contentHashes = new Map<string, Map<string, string>>();

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.masterKey = masterKey;
  }

  private versionKey(namespace: string, key: string): string {
    return `${namespace}/${key}`;
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
    const namespaceKey = deriveNamespaceKey(this.masterKey, namespace);
    const plaintext = stringToBytes(value);

    // Compute integrity hash of plaintext
    const integrityHash = hashToString(plaintext);

    // Encrypt the value
    const payload = encrypt(plaintext, namespaceKey);

    // Determine version number (monotonically increasing)
    const vk = this.versionKey(namespace, key);
    const currentVersion = this.versionCache.get(vk) ?? 0;
    const newVersion = currentVersion + 1;

    // Sign the ciphertext (non-repudiation)
    const ciphertextBytes = fromBase64url(payload.ct);
    const signature = sign(
      ciphertextBytes,
      encryptedPrivateKey,
      identityEncryptionKey
    );

    const now = new Date().toISOString();

    // Construct the state entry
    const stateEntry: StateEntry = {
      v: 1,
      payload,
      ver: newVersion,
      sig: toBase64url(signature),
      kid: identityId,
      integrity_hash: integrityHash,
      metadata: {
        content_type: options.content_type,
        ttl_seconds: options.ttl_seconds,
        tags: options.tags,
        written_at: now,
      },
    };

    // Serialize and write to storage
    const serialized = stringToBytes(JSON.stringify(stateEntry));
    await this.storage.write(namespace, key, serialized);

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
   * Read and decrypt state.
   *
   * @param namespace - Logical grouping
   * @param key - State key
   * @param signerPublicKey - Expected signer's public key (for signature verification)
   * @param verifyIntegrity - Whether to verify Merkle proof (default: true)
   */
  async read(
    namespace: string,
    key: string,
    signerPublicKey?: Uint8Array,
    verifyIntegrity = true
  ): Promise<ReadResult | null> {
    const raw = await this.storage.read(namespace, key);
    if (!raw) return null;

    let stateEntry: StateEntry;
    try {
      stateEntry = JSON.parse(bytesToString(raw));
    } catch {
      throw new Error(`Corrupted state entry: ${namespace}/${key}`);
    }

    if (stateEntry.v !== 1) {
      throw new Error(`Unsupported state entry version: ${stateEntry.v}`);
    }

    // Anti-rollback check
    const vk = this.versionKey(namespace, key);
    const cachedVersion = this.versionCache.get(vk);
    if (cachedVersion !== undefined && stateEntry.ver < cachedVersion) {
      throw new Error(
        `Rollback detected for ${namespace}/${key}: ` +
          `found version ${stateEntry.ver}, expected >= ${cachedVersion}`
      );
    }

    // Verify signature if public key provided
    if (signerPublicKey) {
      const ciphertextBytes = fromBase64url(stateEntry.payload.ct);
      const signatureBytes = fromBase64url(stateEntry.sig);
      const sigValid = verify(ciphertextBytes, signatureBytes, signerPublicKey);
      if (!sigValid) {
        throw new Error(
          `Signature verification failed for ${namespace}/${key}`
        );
      }
    }

    // Decrypt
    const namespaceKey = deriveNamespaceKey(this.masterKey, namespace);
    const plaintext = decrypt(stateEntry.payload, namespaceKey);
    const value = bytesToString(plaintext);

    // Verify integrity hash
    const computedHash = hashToString(plaintext);
    if (computedHash !== stateEntry.integrity_hash) {
      throw new Error(
        `Integrity hash mismatch for ${namespace}/${key}: ` +
          `computed ${computedHash}, stored ${stateEntry.integrity_hash}`
      );
    }

    // Merkle proof verification
    let merkleProofPath: string[] = [];
    let integrityVerified = true;

    if (verifyIntegrity) {
      const nsHashes = await this.getNamespaceHashes(namespace);
      const proof = generateMerkleProof(nsHashes, key);
      if (proof) {
        integrityVerified = verifyMerkleProof(proof);
        merkleProofPath = proof.path.map(
          (step) => `${step.position}:${step.hash}`
        );
      }
    }

    // Update version cache
    this.versionCache.set(vk, stateEntry.ver);

    return {
      key,
      namespace,
      value,
      version: stateEntry.ver,
      integrity_verified: integrityVerified,
      merkle_proof: merkleProofPath,
      written_at: stateEntry.metadata.written_at,
      written_by: stateEntry.kid,
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
    conflictResolution: "skip" | "overwrite" | "version" = "skip"
  ): Promise<{
    imported_keys: number;
    skipped_keys: number;
    conflicts: number;
    namespaces: string[];
    imported_at: string;
  }> {
    const bundleBytes = fromBase64url(bundleBase64);
    const bundleJson = bytesToString(bundleBytes);
    const bundle = JSON.parse(bundleJson);

    let importedKeys = 0;
    let skippedKeys = 0;
    let conflicts = 0;
    const namespaces: string[] = [];

    for (const [ns, entries] of Object.entries(
      bundle.data as Record<string, Array<{ key: string; entry: StateEntry }>>
    )) {
      namespaces.push(ns);

      for (const { key, entry } of entries) {
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
      conflicts,
      namespaces,
      imported_at: new Date().toISOString(),
    };
  }
}
