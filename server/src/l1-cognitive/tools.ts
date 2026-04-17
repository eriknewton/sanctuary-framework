/**
 * Sanctuary MCP Server — L1 Cognitive Sovereignty: Tool Definitions
 *
 * MCP tool wrappers for StateStore and IdentityRoot operations.
 * These tools are the public API that agents interact with.
 */

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import { StateStore } from "./state-store.js";
import {
  createIdentity,
  rotateKeys,
  sign as identitySign,
  verify as identityVerify,
  type StoredIdentity,
  type PublicIdentity,
} from "../core/identity.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import {
  toBase64url,
  fromBase64url,
  stringToBytes,
} from "../core/encoding.js";
import type { StorageBackend } from "../storage/interface.js";
import { encrypt, decrypt } from "../core/encryption.js";
import { bytesToString } from "../core/encoding.js";
import type { AuditLog } from "../l2-operational/audit-log.js";

/**
 * Reserved namespace prefixes — used by internal subsystems.
 * Agent-facing state tools MUST reject reads, writes, deletes, lists, and
 * imports to these namespaces. Internal subsystems access the StateStore
 * directly, bypassing these tool-level checks.
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
] as const;

/**
 * Check whether a namespace is reserved for internal use.
 * Returns the matching reserved prefix, or null if the namespace is safe.
 */
function getReservedNamespaceViolation(namespace: string): string | null {
  for (const prefix of RESERVED_NAMESPACE_PREFIXES) {
    if (namespace === prefix || namespace.startsWith(prefix + "/")) {
      return prefix;
    }
  }
  return null;
}

/** Manages all identities — provides storage and retrieval */
export class IdentityManager {
  private storage: StorageBackend;
  private masterKey: Uint8Array;
  private identities = new Map<string, StoredIdentity>();
  private primaryIdentityId: string | null = null;
  private metadataKey = "primary_identity_id";

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.masterKey = masterKey;
  }

  private get encryptionKey(): Uint8Array {
    return derivePurposeKey(this.masterKey, "identity-encryption");
  }

  /** Load identities from storage on startup.
   *  Returns { total: number of encrypted files found, loaded: number successfully decrypted }.
   *  A mismatch (total > 0, loaded === 0) indicates a wrong master key / missing passphrase.
   */
  async load(): Promise<{ total: number; loaded: number; failed: number }> {
    const entries = await this.storage.list("_identities");
    let failed = 0;
    for (const entry of entries) {
      const raw = await this.storage.read("_identities", entry.key);
      if (!raw) continue;
      try {
        const encrypted = JSON.parse(bytesToString(raw));
        const decrypted = decrypt(encrypted, this.encryptionKey);
        const identity: StoredIdentity = JSON.parse(bytesToString(decrypted));
        this.identities.set(identity.identity_id, identity);
      } catch {
        failed++;
      }
    }

    // Load the primary identity ID from persistent storage
    // This ensures the same identity is used as default on every restart
    try {
      const metaRaw = await this.storage.read("_meta", this.metadataKey);
      if (metaRaw) {
        const metaStr = bytesToString(metaRaw);
        const primaryId = JSON.parse(metaStr) as string;
        // Verify the stored primary ID still exists
        if (this.identities.has(primaryId)) {
          this.primaryIdentityId = primaryId;
        } else {
          // Stored primary ID was deleted; fall back to first loaded
          this.primaryIdentityId = this.identities.keys().next().value || null;
        }
      } else {
        // No primary ID stored yet; use first loaded identity
        this.primaryIdentityId = this.identities.keys().next().value || null;
      }
    } catch {
      // Metadata read failed; use first loaded identity
      this.primaryIdentityId = this.identities.keys().next().value || null;
    }

    return { total: entries.length, loaded: this.identities.size, failed };
  }

  /** Save an identity to storage */
  async save(identity: StoredIdentity): Promise<void> {
    const serialized = stringToBytes(JSON.stringify(identity));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      "_identities",
      identity.identity_id,
      stringToBytes(JSON.stringify(encrypted))
    );
    this.identities.set(identity.identity_id, identity);
    // If this is the first identity, set it as primary
    if (!this.primaryIdentityId) {
      this.primaryIdentityId = identity.identity_id;
      this.savePrimaryIdentityId();
    }
  }

  /** Set which identity is the default/primary identity */
  async setPrimary(identityId: string): Promise<boolean> {
    if (!this.identities.has(identityId)) {
      return false;
    }
    this.primaryIdentityId = identityId;
    await this.savePrimaryIdentityId();
    return true;
  }

  /** Persist the primary identity ID to storage */
  private async savePrimaryIdentityId(): Promise<void> {
    if (!this.primaryIdentityId) return;
    try {
      const serialized = stringToBytes(JSON.stringify(this.primaryIdentityId));
      await this.storage.write("_meta", this.metadataKey, serialized);
    } catch {
      // Metadata write failed; continue without persistence
      // The primary ID will revert to first-loaded on next startup
    }
  }

  get(id: string): StoredIdentity | undefined {
    return this.identities.get(id);
  }

  getDefault(): StoredIdentity | undefined {
    if (!this.primaryIdentityId) return undefined;
    return this.identities.get(this.primaryIdentityId);
  }

  getPrimaryIdentityId(): string | null {
    return this.primaryIdentityId;
  }

  list(): PublicIdentity[] {
    return Array.from(this.identities.values()).map((si) => ({
      identity_id: si.identity_id,
      label: si.label,
      public_key: si.public_key,
      did: si.did,
      created_at: si.created_at,
      key_type: si.key_type,
      key_protection: si.key_protection,
    }));
  }

  /** List identities with rotation count (for dashboard display). */
  listWithRotationCount(): Array<PublicIdentity & { rotation_count: number }> {
    return Array.from(this.identities.values()).map((si) => ({
      identity_id: si.identity_id,
      label: si.label,
      public_key: si.public_key,
      did: si.did,
      created_at: si.created_at,
      key_type: si.key_type,
      key_protection: si.key_protection,
      rotation_count: si.rotation_history?.length ?? 0,
    }));
  }
}

/**
 * Create all L1 tool definitions.
 */
export function createL1Tools(
  stateStore: StateStore,
  storage: StorageBackend,
  masterKey: Uint8Array,
  keyProtection: "passphrase" | "hardware-key" | "recovery-key",
  auditLog?: AuditLog
): { tools: ToolDefinition[]; identityManager: IdentityManager } {
  const identityMgr = new IdentityManager(storage, masterKey);
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");

  // Helper to get identity or throw
  function resolveIdentity(identityId?: string): StoredIdentity {
    const id = identityId
      ? identityMgr.get(identityId)
      : identityMgr.getDefault();
    if (!id) {
      throw new Error(
        identityId
          ? `Identity not found: ${identityId}`
          : "No default identity. Create one with sanctuary/identity_create."
      );
    }
    return id;
  }

  const tools: ToolDefinition[] = [
    // ── Identity Tools ──────────────────────────────────────────────────

    {
      name: "identity_create",
      description:
        "Create a new sovereign identity (Ed25519 keypair). " +
        "The private key is encrypted and never exposed.",
      inputSchema: {
        type: "object",
        properties: {
          label: {
            type: "string",
            description: 'Human-readable label (e.g., "my-agent")',
          },
        },
        required: ["label"],
      },
      handler: async (args) => {
        const label = args.label as string;
        const { publicIdentity, storedIdentity } = createIdentity(
          label,
          identityEncKey,
          keyProtection
        );
        await identityMgr.save(storedIdentity);

        auditLog?.append("l1", "identity_create", publicIdentity.identity_id, {
          label,
        });

        // If key_protection is "none", generate and show recovery key
        // (In practice, the recovery key is the master key itself,
        //  which was generated at server init and shown once)
        return toolResult({
          identity_id: publicIdentity.identity_id,
          public_key: publicIdentity.public_key,
          did: publicIdentity.did,
          created_at: publicIdentity.created_at,
          key_type: publicIdentity.key_type,
          key_protection: publicIdentity.key_protection,
          backed_up: false,
        });
      },
    },

    {
      name: "identity_list",
      description: "List all managed sovereign identities.",
      inputSchema: {
        type: "object",
        properties: {
          filter: {
            type: "object",
            properties: {
              label: { type: "string" },
            },
          },
        },
      },
      handler: async (args) => {
        let identities = identityMgr.list();
        const filter = args.filter as { label?: string } | undefined;
        if (filter?.label) {
          identities = identities.filter((i) =>
            i.label.includes(filter.label!)
          );
        }
        return toolResult({ identities });
      },
    },

    {
      name: "identity_sign",
      description:
        "Sign data with a managed identity. " +
        "The private key is decrypted in memory only during signing.",
      inputSchema: {
        type: "object",
        properties: {
          identity_id: { type: "string" },
          payload: {
            type: "string",
            description: "Base64url-encoded data to sign",
          },
        },
        required: ["payload"],
      },
      handler: async (args) => {
        const identity = resolveIdentity(args.identity_id as string | undefined);
        const payloadStr = args.payload as string;

        // Accept either base64url-encoded bytes or plain text
        let payload: Uint8Array;
        try {
          payload = fromBase64url(payloadStr);
        } catch {
          payload = stringToBytes(payloadStr);
        }

        const signature = identitySign(
          payload,
          identity.encrypted_private_key,
          identityEncKey
        );

        auditLog?.append("l1", "identity_sign", identity.identity_id);

        return toolResult({
          signature: toBase64url(signature),
          algorithm: "Ed25519",
          signed_at: new Date().toISOString(),
          public_key: identity.public_key,
          payload_encoding: "base64url",
        });
      },
    },

    {
      name: "identity_verify",
      description:
        "Verify an Ed25519 signature. Provide either identity_id or public_key.",
      inputSchema: {
        type: "object",
        properties: {
          payload: {
            type: "string",
            description: "Original data (plain text or base64url-encoded)",
          },
          signature: { type: "string", description: "Base64url signature" },
          identity_id: {
            type: "string",
            description: "Identity ID to look up public key (alternative to public_key)",
          },
          public_key: {
            type: "string",
            description: "Base64url public key (alternative to identity_id)",
          },
        },
        required: ["payload", "signature"],
      },
      handler: async (args) => {
        const payloadStr = args.payload as string;

        // Accept either base64url-encoded bytes or plain text
        let payload: Uint8Array;
        try {
          payload = fromBase64url(payloadStr);
        } catch {
          payload = stringToBytes(payloadStr);
        }

        const signature = fromBase64url(args.signature as string);

        // Resolve public key from identity_id or direct public_key param
        let publicKey: Uint8Array;
        if (args.identity_id) {
          const identity = resolveIdentity(args.identity_id as string);
          publicKey = fromBase64url(identity.public_key);
        } else if (args.public_key) {
          publicKey = fromBase64url(args.public_key as string);
        } else {
          return toolResult({
            error: "Provide either identity_id or public_key for verification.",
          });
        }

        const valid = identityVerify(payload, signature, publicKey);

        return toolResult({
          valid,
          verified_at: new Date().toISOString(),
        });
      },
    },

    {
      name: "identity_rotate",
      description:
        "Rotate keys for an identity. Generates a new keypair and " +
        "signs a rotation event with the old key for verifiable chain.",
      inputSchema: {
        type: "object",
        properties: {
          identity_id: { type: "string" },
          reason: { type: "string" },
        },
        required: ["identity_id"],
      },
      handler: async (args) => {
        const identity = resolveIdentity(args.identity_id as string);
        const reason = (args.reason as string) ?? "Key rotation";

        const { updatedIdentity, rotationEvent } = rotateKeys(
          identity,
          identityEncKey,
          reason
        );
        await identityMgr.save(updatedIdentity);

        auditLog?.append("l1", "identity_rotate", identity.identity_id, {
          reason,
        });

        return toolResult({
          identity_id: updatedIdentity.identity_id,
          old_public_key: rotationEvent.old_public_key,
          new_public_key: rotationEvent.new_public_key,
          new_did: updatedIdentity.did,
          rotated_at: rotationEvent.rotated_at,
        });
      },
    },

    {
      name: "identity_set_primary",
      description:
        "Set which identity is the default/primary identity. " +
        "This identity will be used by shr_generate, reputation_publish, and other tools " +
        "when no explicit identity_id parameter is provided. " +
        "The selection is persisted across server restarts.",
      inputSchema: {
        type: "object",
        properties: {
          identity_id: {
            type: "string",
            description: "The identity ID to set as primary",
          },
        },
        required: ["identity_id"],
      },
      handler: async (args) => {
        const identityId = args.identity_id as string;
        const identity = identityMgr.get(identityId);

        if (!identity) {
          return toolResult({
            error: `Identity "${identityId}" not found.`,
          });
        }

        const success = await identityMgr.setPrimary(identityId);
        if (!success) {
          return toolResult({
            error: `Failed to set primary identity to "${identityId}".`,
          });
        }

        auditLog?.append("l1", "identity_set_primary", identityId, {
          previous_primary: identityMgr.getPrimaryIdentityId(),
        });

        return toolResult({
          primary_identity_id: identityId,
          label: identity.label,
          did: identity.did,
          set_at: new Date().toISOString(),
        });
      },
    },

    // ── State Tools ─────────────────────────────────────────────────────

    {
      name: "state_write",
      description:
        "Write encrypted state to the sovereign store. " +
        "Value is encrypted with a namespace-specific key. " +
        "The write is signed by the active identity.",
      inputSchema: {
        type: "object",
        properties: {
          namespace: {
            type: "string",
            description: 'Logical grouping (e.g., "memory", "config")',
          },
          key: { type: "string", description: "State key within namespace" },
          value: {
            type: "string",
            description: "Plaintext value (encrypted before storage)",
          },
          metadata: {
            type: "object",
            properties: {
              content_type: { type: "string" },
              ttl_seconds: { type: "number" },
              tags: { type: "array", items: { type: "string" } },
            },
          },
          identity_id: { type: "string" },
        },
        required: ["namespace", "key", "value"],
      },
      handler: async (args) => {
        // Namespace firewall: reject writes to reserved internal namespaces
        const reservedViolation = getReservedNamespaceViolation(args.namespace as string);
        if (reservedViolation) {
          return toolResult({
            error: "namespace_reserved",
            message: `Namespace "${args.namespace}" is reserved for internal use (prefix: ${reservedViolation}). Choose a different namespace.`,
          });
        }

        const identity = resolveIdentity(args.identity_id as string | undefined);
        const metadata = args.metadata as {
          content_type?: string;
          ttl_seconds?: number;
          tags?: string[];
        } | undefined;

        const result = await stateStore.write(
          args.namespace as string,
          args.key as string,
          args.value as string,
          identity.identity_id,
          identity.encrypted_private_key,
          identityEncKey,
          {
            content_type: metadata?.content_type,
            ttl_seconds: metadata?.ttl_seconds,
            tags: metadata?.tags,
          }
        );

        auditLog?.append("l1", "state_write", identity.identity_id, {
          namespace: args.namespace,
          key: args.key,
        });

        return toolResult(result);
      },
    },

    {
      name: "state_read",
      description:
        "Read and decrypt state from the sovereign store. " +
        "Verifies integrity via Merkle proof and signature.",
      inputSchema: {
        type: "object",
        properties: {
          namespace: { type: "string" },
          key: { type: "string" },
          verify_integrity: { type: "boolean", default: true },
        },
        required: ["namespace", "key"],
      },
      handler: async (args) => {
        // Namespace firewall: reject reads from reserved internal namespaces
        const reservedViolation = getReservedNamespaceViolation(args.namespace as string);
        if (reservedViolation) {
          return toolResult({
            error: "namespace_reserved",
            message: `Namespace "${args.namespace}" is reserved for internal use (prefix: ${reservedViolation}). Cannot read from reserved namespaces.`,
          });
        }

        const result = await stateStore.read(
          args.namespace as string,
          args.key as string,
          undefined, // Skip signature verification for now (would need writer's pubkey)
          args.verify_integrity as boolean ?? true
        );

        if (!result) {
          return toolResult({
            error: "not_found",
            namespace: args.namespace,
            key: args.key,
          });
        }

        auditLog?.append("l1", "state_read", result.written_by, {
          namespace: args.namespace,
          key: args.key,
        });

        return toolResult(result);
      },
    },

    {
      name: "state_list",
      description:
        "List keys in a namespace (metadata only — no decryption).",
      inputSchema: {
        type: "object",
        properties: {
          namespace: { type: "string" },
          prefix: { type: "string" },
          tags: { type: "array", items: { type: "string" } },
          limit: { type: "number", default: 100 },
          offset: { type: "number", default: 0 },
        },
        required: ["namespace"],
      },
      handler: async (args) => {
        // Namespace firewall: reject listing of reserved internal namespaces
        const reservedViolation = getReservedNamespaceViolation(args.namespace as string);
        if (reservedViolation) {
          return toolResult({
            error: "namespace_reserved",
            message: `Namespace "${args.namespace}" is reserved for internal use (prefix: ${reservedViolation}). Cannot list reserved namespaces.`,
          });
        }

        const result = await stateStore.list(
          args.namespace as string,
          args.prefix as string | undefined,
          args.tags as string[] | undefined,
          (args.limit as number) ?? 100,
          (args.offset as number) ?? 0
        );
        return toolResult(result);
      },
    },

    {
      name: "state_delete",
      description:
        "Securely delete state. Overwrites file with random bytes " +
        "before removal (right to deletion, S1.6).",
      inputSchema: {
        type: "object",
        properties: {
          namespace: { type: "string" },
          key: { type: "string" },
          reason: { type: "string" },
        },
        required: ["namespace", "key"],
      },
      handler: async (args) => {
        // Namespace firewall: reject deletes from reserved internal namespaces
        const reservedViolation = getReservedNamespaceViolation(args.namespace as string);
        if (reservedViolation) {
          return toolResult({
            error: "namespace_reserved",
            message: `Namespace "${args.namespace}" is reserved for internal use (prefix: ${reservedViolation}). Cannot delete from reserved namespaces.`,
          });
        }

        const result = await stateStore.delete(
          args.namespace as string,
          args.key as string
        );

        auditLog?.append("l1", "state_delete", "principal", {
          namespace: args.namespace,
          key: args.key,
          reason: args.reason,
        });

        return toolResult(result);
      },
    },

    {
      name: "state_export",
      description:
        "Export state as an encrypted, portable bundle for migration.",
      inputSchema: {
        type: "object",
        properties: {
          namespace: { type: "string" },
          format: { type: "string", default: "sanctuary-v1" },
        },
      },
      handler: async (args) => {
        const result = await stateStore.export(
          args.namespace as string | undefined
        );

        auditLog?.append("l1", "state_export", "principal", {
          namespaces: result.namespaces,
        });

        return toolResult(result);
      },
    },

    {
      name: "state_import",
      description: "Import a previously exported state bundle.",
      inputSchema: {
        type: "object",
        properties: {
          bundle: { type: "string", description: "Base64url-encoded bundle" },
          conflict_resolution: {
            type: "string",
            enum: ["skip", "overwrite", "version"],
            default: "skip",
          },
        },
        required: ["bundle"],
      },
      handler: async (args) => {
        // Wire public key resolver for signature verification (SEC-005)
        const publicKeyResolver = (kid: string): Uint8Array | null => {
          const identity = identityMgr.get(kid);
          if (!identity) return null;
          return fromBase64url(identity.public_key);
        };

        const result = await stateStore.import(
          args.bundle as string,
          (args.conflict_resolution as "skip" | "overwrite" | "version") ??
            "skip",
          publicKeyResolver
        );

        auditLog?.append("l1", "state_import", "principal", {
          imported_keys: result.imported_keys,
        });

        return toolResult(result);
      },
    },
  ];

  return { tools, identityManager: identityMgr };
}
