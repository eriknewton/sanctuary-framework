/**
 * Sanctuary MCP Server - L1 Cognitive Sovereignty: Tool Definitions
 *
 * MCP tool wrappers for StateStore and IdentityRoot operations.
 * These tools are the public API that agents interact with.
 */

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import {
  decodeExportBundleNamespaces,
  StateStore,
  StateVerificationError,
} from "./state-store.js";
import type { OriginActor } from "../exit/memory-class.js";
import {
  createIdentity,
  rotateKeys,
  sign as identitySign,
  verify as identityVerify,
  type StoredIdentity,
  type PublicIdentity,
  type RotationEvent,
} from "../core/identity.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import {
  toBase64url,
  fromBase64url,
  stringToBytes,
} from "../core/encoding.js";
import type { StorageBackend } from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { bytesToString } from "../core/encoding.js";
import type { AuditEntry, AuditLog } from "../operational/audit-log.js";
import {
  fixedDenial,
  OpaqueNamespaceRegistry,
  resolveActiveSessionIdentity,
  type SessionBinding,
} from "../agent-native/safety-base.js";

export const AUDIT_EVENT_SIGNING_DOMAIN = "sanctuary.audit.v1";
export const INTERNAL_RECEIPT_SIGNING_DOMAIN = "sanctuary.receipt.v1";

export type InternalSigningDomain =
  | typeof AUDIT_EVENT_SIGNING_DOMAIN
  | typeof INTERNAL_RECEIPT_SIGNING_DOMAIN;

export interface AuditEventSigningPayload {
  event_id: string;
  layer: string;
  operation: string;
  actor: string;
  timestamp: string;
  event_hash: string;
  previous_event_hash?: string;
}

export interface InternalReceiptSigningPayload {
  receipt_id: string;
  receipt_type: "approval" | "tool_call" | "state_write" | "handoff" | "internal";
  subject: string;
  issued_at: string;
  status: "issued" | "approved" | "denied" | "completed" | "failed";
  body_hash: string;
  expires_at?: string;
}

export interface InternalSigningOptions {
  identity_id?: string;
}

export interface InternalSigningResult {
  identity_id: string;
  public_key: string;
  signature: string;
  algorithm: "Ed25519";
  domain: InternalSigningDomain;
  signed_payload: string;
  payload_encoding: "domain-separated-canonical-json-v1";
  signed_at: string;
}

export interface InternalIdentitySigningHelpers {
  audit_event_sign: (
    payload: AuditEventSigningPayload,
    options?: InternalSigningOptions
  ) => Promise<InternalSigningResult>;
  internal_receipt_sign: (
    payload: InternalReceiptSigningPayload,
    options?: InternalSigningOptions
  ) => Promise<InternalSigningResult>;
}

export const IDENTITY_OVERWRITE_DENIAL =
  "Identity operation refused: routine identity creation and import cannot replace an existing identity.";

export class IdentityOverwriteRefusedError extends Error {
  constructor() {
    super(IDENTITY_OVERWRITE_DENIAL);
    this.name = "IdentityOverwriteRefusedError";
  }
}

/**
 * Reserved namespace prefixes - used by internal subsystems.
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
  "_fortress_mode",
  "_facade",
  "_file_grants",
  "_castle_wall_observe",
] as const;

/**
 * Check whether a namespace is reserved for internal use.
 * Returns the matching reserved prefix, or null if the namespace is safe.
 */
function getReservedNamespaceViolation(namespace: string): string | null {
  // F6: ALL underscore-prefixed namespaces are reserved for internal subsystems;
  // external callers must not write/read/list/delete them. The curated list below
  // enumerates the known internal namespaces (used for a precise violation label),
  // but the `_` prefix is the contract - a non-curated `_foo` is still reserved.
  if (namespace.startsWith("_")) {
    for (const prefix of RESERVED_NAMESPACE_PREFIXES) {
      if (namespace === prefix || namespace.startsWith(prefix + "/")) {
        return prefix;
      }
    }
    return namespace;
  }
  return null;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }

  const record = value as Record<string, unknown>;
  const entries = Object.keys(record)
    .sort()
    .filter((key) => record[key] !== undefined)
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`);
  return `{${entries.join(",")}}`;
}

export function domainSeparatedSigningBytes(
  domain: InternalSigningDomain,
  payload: Record<string, unknown>
): Uint8Array {
  return stringToBytes(`${domain}\n${canonicalJson(payload)}`);
}

function assertPlainRecord(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object.`);
  }
  return value as Record<string, unknown>;
}

function assertKnownKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  name: string
): void {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(value)) {
    if (!allowedSet.has(key)) {
      throw new Error(`${name} contains unsupported field: ${key}`);
    }
  }
}

function requireNonEmptyString(
  value: Record<string, unknown>,
  key: string,
  name: string
): string {
  const field = value[key];
  if (typeof field !== "string" || field.trim() === "") {
    throw new Error(`${name}.${key} must be a non-empty string.`);
  }
  return field;
}

function optionalNonEmptyString(
  value: Record<string, unknown>,
  key: string,
  name: string
): string | undefined {
  if (value[key] === undefined) return undefined;
  return requireNonEmptyString(value, key, name);
}

function requireSha256Digest(
  value: Record<string, unknown>,
  key: string,
  name: string
): string {
  const digest = requireNonEmptyString(value, key, name);
  if (!/^sha256:[a-f0-9]{64}$/.test(digest)) {
    throw new Error(`${name}.${key} must be a sha256:<64 hex> digest.`);
  }
  return digest;
}

function optionalSha256Digest(
  value: Record<string, unknown>,
  key: string,
  name: string
): string | undefined {
  if (value[key] === undefined) return undefined;
  return requireSha256Digest(value, key, name);
}

function requireOneOf<T extends string>(
  value: Record<string, unknown>,
  key: string,
  allowed: readonly T[],
  name: string
): T {
  const field = requireNonEmptyString(value, key, name);
  if (!(allowed as readonly string[]).includes(field)) {
    throw new Error(`${name}.${key} must be one of: ${allowed.join(", ")}.`);
  }
  return field as T;
}

function requireEncryptedPayload(
  value: Record<string, unknown>,
  key: string,
  name: string
): EncryptedPayload {
  const payload = assertPlainRecord(value[key], `${name}.${key}`);
  assertKnownKeys(payload, ["v", "alg", "iv", "ct", "ts"], `${name}.${key}`);
  if (payload.v !== 1) {
    throw new Error(`${name}.${key}.v must be 1.`);
  }
  if (payload.alg !== "aes-256-gcm") {
    throw new Error(`${name}.${key}.alg must be aes-256-gcm.`);
  }
  return {
    v: 1,
    alg: "aes-256-gcm",
    iv: requireNonEmptyString(payload, "iv", `${name}.${key}`),
    ct: requireNonEmptyString(payload, "ct", `${name}.${key}`),
    ts: requireNonEmptyString(payload, "ts", `${name}.${key}`),
  };
}

function requireRotationHistory(value: Record<string, unknown>, name: string) {
  const history = value.rotation_history;
  if (!Array.isArray(history)) {
    throw new Error(`${name}.rotation_history must be an array.`);
  }
  return history.map((item, index) => {
    const record = assertPlainRecord(item, `${name}.rotation_history[${index}]`);
    assertKnownKeys(
      record,
      ["old_public_key", "new_public_key", "rotation_event", "rotated_at"],
      `${name}.rotation_history[${index}]`
    );
    return {
      old_public_key: requireNonEmptyString(
        record,
        "old_public_key",
        `${name}.rotation_history[${index}]`
      ),
      new_public_key: requireNonEmptyString(
        record,
        "new_public_key",
        `${name}.rotation_history[${index}]`
      ),
      rotation_event: requireNonEmptyString(
        record,
        "rotation_event",
        `${name}.rotation_history[${index}]`
      ),
      rotated_at: requireNonEmptyString(
        record,
        "rotated_at",
        `${name}.rotation_history[${index}]`
      ),
    };
  });
}

function normalizeImportedIdentity(payload: unknown): StoredIdentity {
  const record = assertPlainRecord(payload, "identity_import.identity");
  assertKnownKeys(
    record,
    [
      "identity_id",
      "label",
      "public_key",
      "did",
      "created_at",
      "key_type",
      "key_protection",
      "encrypted_private_key",
      "rotation_history",
    ],
    "identity_import.identity"
  );

  return {
    identity_id: requireNonEmptyString(record, "identity_id", "identity_import.identity"),
    label: requireNonEmptyString(record, "label", "identity_import.identity"),
    public_key: requireNonEmptyString(record, "public_key", "identity_import.identity"),
    did: requireNonEmptyString(record, "did", "identity_import.identity"),
    created_at: requireNonEmptyString(record, "created_at", "identity_import.identity"),
    key_type: requireOneOf(
      record,
      "key_type",
      ["ed25519"],
      "identity_import.identity"
    ),
    key_protection: requireOneOf(
      record,
      "key_protection",
      ["passphrase", "hardware-key", "recovery-key"],
      "identity_import.identity"
    ),
    encrypted_private_key: requireEncryptedPayload(
      record,
      "encrypted_private_key",
      "identity_import.identity"
    ),
    rotation_history: requireRotationHistory(record, "identity_import.identity"),
  };
}

function normalizeAuditEventSigningPayload(
  payload: AuditEventSigningPayload
): AuditEventSigningPayload {
  const record = assertPlainRecord(payload, "audit_event_sign payload");
  assertKnownKeys(
    record,
    [
      "event_id",
      "layer",
      "operation",
      "actor",
      "timestamp",
      "event_hash",
      "previous_event_hash",
    ],
    "audit_event_sign payload"
  );
  return {
    event_id: requireNonEmptyString(record, "event_id", "audit_event_sign payload"),
    layer: requireNonEmptyString(record, "layer", "audit_event_sign payload"),
    operation: requireNonEmptyString(record, "operation", "audit_event_sign payload"),
    actor: requireNonEmptyString(record, "actor", "audit_event_sign payload"),
    timestamp: requireNonEmptyString(record, "timestamp", "audit_event_sign payload"),
    event_hash: requireSha256Digest(record, "event_hash", "audit_event_sign payload"),
    ...(optionalSha256Digest(record, "previous_event_hash", "audit_event_sign payload")
      ? {
          previous_event_hash: optionalSha256Digest(
            record,
            "previous_event_hash",
            "audit_event_sign payload"
          ),
        }
      : {}),
  };
}

function normalizeInternalReceiptSigningPayload(
  payload: InternalReceiptSigningPayload
): InternalReceiptSigningPayload {
  const record = assertPlainRecord(payload, "internal_receipt_sign payload");
  assertKnownKeys(
    record,
    [
      "receipt_id",
      "receipt_type",
      "subject",
      "issued_at",
      "status",
      "body_hash",
      "expires_at",
    ],
    "internal_receipt_sign payload"
  );
  return {
    receipt_id: requireNonEmptyString(record, "receipt_id", "internal_receipt_sign payload"),
    receipt_type: requireOneOf(
      record,
      "receipt_type",
      ["approval", "tool_call", "state_write", "handoff", "internal"],
      "internal_receipt_sign payload"
    ),
    subject: requireNonEmptyString(record, "subject", "internal_receipt_sign payload"),
    issued_at: requireNonEmptyString(record, "issued_at", "internal_receipt_sign payload"),
    status: requireOneOf(
      record,
      "status",
      ["issued", "approved", "denied", "completed", "failed"],
      "internal_receipt_sign payload"
    ),
    body_hash: requireSha256Digest(record, "body_hash", "internal_receipt_sign payload"),
    ...(optionalNonEmptyString(record, "expires_at", "internal_receipt_sign payload")
      ? {
          expires_at: optionalNonEmptyString(
            record,
            "expires_at",
            "internal_receipt_sign payload"
          ),
        }
      : {}),
  };
}

/** Manages all identities - provides storage and retrieval */
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
    // Two-factor custody floor (I4/F6) for NEW identities, enforced here
    // (not only in saveNew) because several callers - sanctuary_bootstrap,
    // wrap-auto identity creation - persist through save() directly
    // (codex round-2 HIGH). Updates/rotations of an already-loaded
    // identity are not creation and stay un-gated.
    if (!this.identities.has(identity.identity_id)) {
      const { enforceCustodyFloor } = await import(
        "../core/master-custody.js"
      );
      await enforceCustodyFloor(this.storage, "identity_create", this.masterKey);
    }
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
      // Fire and forget by design: savePrimaryIdentityId swallows its own
      // storage errors (the primary pointer reverts to first-loaded on next
      // startup), so this promise never rejects.
      void this.savePrimaryIdentityId();
    }
  }

  hasIdentityConflict(identity: StoredIdentity): boolean {
    return Array.from(this.identities.values()).some(
      (existing) =>
        existing.identity_id === identity.identity_id ||
        existing.did === identity.did ||
        existing.public_key === identity.public_key
    );
  }

  /** Save a newly-created/imported identity without allowing overwrite. */
  async saveNew(identity: StoredIdentity): Promise<void> {
    if (this.hasIdentityConflict(identity)) {
      throw new IdentityOverwriteRefusedError();
    }
    // The two-factor custody floor (I4/F6) is enforced inside save() for
    // every new identity, covering this path and the direct-save callers.
    await this.save(identity);
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

  async rotate(
    identityId: string,
    reason: string,
  ): Promise<{ updatedIdentity: StoredIdentity; rotationEvent: RotationEvent } | null> {
    const identity = this.identities.get(identityId);
    if (!identity) return null;
    const result = rotateKeys(identity, this.encryptionKey, reason);
    await this.save(result.updatedIdentity);
    return result;
  }
}

function resolveInternalSigningIdentity(
  identityMgr: IdentityManager,
  identityId?: string
): StoredIdentity {
  const identity = identityId
    ? identityMgr.get(identityId)
    : identityMgr.getDefault();
  if (!identity) {
    throw new Error(
      identityId
        ? `Identity not found: ${identityId}`
        : "No default identity available for internal signing."
    );
  }
  return identity;
}

export function createInternalIdentitySigningHelpers(
  identityMgr: IdentityManager,
  masterKey: Uint8Array,
  auditLog?: AuditLog
): InternalIdentitySigningHelpers {
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");

  async function signTypedPayload(
    operation: "audit_event_sign" | "internal_receipt_sign",
    domain: InternalSigningDomain,
    payload: Record<string, unknown>,
    identityId?: string
  ): Promise<InternalSigningResult> {
    const identity = resolveInternalSigningIdentity(identityMgr, identityId);
    const signedPayload = domainSeparatedSigningBytes(domain, payload);
    const signature = identitySign(
      signedPayload,
      identity.encrypted_private_key,
      identityEncKey
    );

    await recordCriticalAudit(auditLog, "l1", operation, identity.identity_id, {
      domain,
    });

    return {
      identity_id: identity.identity_id,
      public_key: identity.public_key,
      signature: toBase64url(signature),
      algorithm: "Ed25519",
      domain,
      signed_payload: toBase64url(signedPayload),
      payload_encoding: "domain-separated-canonical-json-v1",
      signed_at: new Date().toISOString(),
    };
  }

  return {
    audit_event_sign: (payload, options = {}) =>
      signTypedPayload(
        "audit_event_sign",
        AUDIT_EVENT_SIGNING_DOMAIN,
        normalizeAuditEventSigningPayload(payload) as unknown as Record<string, unknown>,
        options.identity_id
      ),
    internal_receipt_sign: (payload, options = {}) =>
      signTypedPayload(
        "internal_receipt_sign",
        INTERNAL_RECEIPT_SIGNING_DOMAIN,
        normalizeInternalReceiptSigningPayload(payload) as unknown as Record<string, unknown>,
        options.identity_id
      ),
  };
}

async function recordCriticalAudit(
  auditLog: AuditLog | undefined,
  layer: AuditEntry["layer"],
  operation: string,
  identityId: string,
  details?: Record<string, unknown>,
  result: AuditEntry["result"] = "success"
): Promise<void> {
  if (!auditLog) return;
  await auditLog.appendCritical({
    layer,
    operation,
    identity_id: identityId,
    result,
    details,
  });
}

async function refuseIdentityOverwrite(
  auditLog: AuditLog | undefined,
  operation: "identity_create" | "identity_import",
  attemptedIdentityId: string
): Promise<never> {
  await recordCriticalAudit(
    auditLog,
    "l1",
    `${operation}_overwrite_refused`,
    attemptedIdentityId,
    { attempted_operation: operation },
    "failure"
  );
  throw new IdentityOverwriteRefusedError();
}

/**
 * Create all Cognitive-layer tool definitions.
 */
export function createCognitiveTools(
  stateStore: StateStore,
  storage: StorageBackend,
  masterKey: Uint8Array,
  keyProtection: "passphrase" | "hardware-key" | "recovery-key",
  auditLog?: AuditLog,
  options?: {
    namespaceRegistry?: OpaqueNamespaceRegistry;
    currentSessionBinding?: () => SessionBinding | undefined;
  }
): {
  tools: ToolDefinition[];
  identityManager: IdentityManager;
  internalSigning: InternalIdentitySigningHelpers;
  namespaceRegistry: OpaqueNamespaceRegistry;
} {
  const identityMgr = new IdentityManager(storage, masterKey);
  const namespaceRegistry = options?.namespaceRegistry ?? new OpaqueNamespaceRegistry();
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const internalSigning = createInternalIdentitySigningHelpers(
    identityMgr,
    masterKey,
    auditLog
  );

  // Helper to get identity or throw
  function resolveIdentity(identityId?: string): StoredIdentity {
    const binding = options?.currentSessionBinding?.();
    const idToResolve = identityId ?? (binding
      ? resolveActiveSessionIdentity(binding).identity_id
      : undefined);
    const id = idToResolve
      ? identityMgr.get(idToResolve)
      : identityMgr.getDefault();
    if (!id) {
      throw new Error(
        idToResolve
          ? `Identity not found: ${idToResolve}`
          : "No default identity. Create one with sanctuary/identity_create."
      );
    }
    return id;
  }

  async function denyNamespaceAccess(operation: string, namespace: string) {
    await recordCriticalAudit(auditLog, "l1", operation, "system", {
      namespace,
      denial_class: "namespace_unavailable",
    }, "failure");
    return toolResult(fixedDenial(`audit:${operation}`));
  }

  function assertOpaqueNamespaceOwned(namespace: string): void {
    namespaceRegistry.assertOwned(namespace, options?.currentSessionBinding?.());
  }

  function assertOpaqueNamespacesOwned(namespaces: string[]): void {
    for (const namespace of namespaces) {
      namespaceRegistry.assertOwned(namespace, options?.currentSessionBinding?.());
    }
  }

  function sessionOwnedExportNamespaces(): string[] {
    const binding = options?.currentSessionBinding?.();
    if (!binding) return stateStore.listCachedExportableNamespaces();
    const active = resolveActiveSessionIdentity(binding);
    const namespaces = stateStore.listCachedExportableNamespaces();
    const exportable: string[] = [];
    for (const namespace of namespaces) {
      if (!namespaceRegistry.isOpaqueMemoryHandle(namespace)) {
        exportable.push(namespace);
        continue;
      }
      const owner = namespaceRegistry.getOwner(namespace);
      if (!owner) {
        throw new Error("namespace_ownership_ambiguous");
      }
      if (owner === active.identity_id) {
        exportable.push(namespace);
      }
    }
    return exportable.sort();
  }

  function assertIdentityMatchesSession(identityId: string | undefined, operation: string): void {
    const binding = options?.currentSessionBinding?.();
    if (!binding) return;
    const active = resolveActiveSessionIdentity(binding);
    if (identityId && identityId !== active.identity_id) {
      throw new Error(`${operation}: identity binding unavailable`);
    }
  }

  function stateWriteOriginActor(identityId: string): OriginActor {
    try {
      const active = resolveActiveSessionIdentity(options?.currentSessionBinding?.());
      return active.identity_id === identityId ? "agent" : "operator";
    } catch {
      return "operator";
    }
  }

  const tools: ToolDefinition[] = [
    // Identity Tools

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
        if (identityMgr.hasIdentityConflict(storedIdentity)) {
          await refuseIdentityOverwrite(
            auditLog,
            "identity_create",
            publicIdentity.identity_id
          );
        }
        await recordCriticalAudit(auditLog, "l1", "identity_create", publicIdentity.identity_id, {
          label,
        });
        await identityMgr.saveNew(storedIdentity);

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
      name: "identity_import",
      description:
        "Import a sovereign identity record without exposing private key material. " +
        "Routine imports refuse to replace any existing identity.",
      inputSchema: {
        type: "object",
        properties: {
          identity: {
            type: "object",
            description: "Stored identity record with encrypted private key payload.",
          },
        },
        required: ["identity"],
      },
      handler: async (args) => {
        const storedIdentity = normalizeImportedIdentity(args.identity);
        if (identityMgr.hasIdentityConflict(storedIdentity)) {
          await refuseIdentityOverwrite(
            auditLog,
            "identity_import",
            storedIdentity.identity_id
          );
        }
        await recordCriticalAudit(
          auditLog,
          "l1",
          "identity_import",
          storedIdentity.identity_id,
          { imported: true }
        );
        await identityMgr.saveNew(storedIdentity);

        return toolResult({
          identity_id: storedIdentity.identity_id,
          public_key: storedIdentity.public_key,
          did: storedIdentity.did,
          created_at: storedIdentity.created_at,
          key_type: storedIdentity.key_type,
          key_protection: storedIdentity.key_protection,
          imported: true,
        });
      },
    },

    {
      name: "identity_list",
      description: "List all managed sovereign identities with labels, DIDs, public keys, and which is primary. Read-only; no private key material returned.",
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
        "Sign data with a managed identity after operator approval. " +
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
        try {
          assertIdentityMatchesSession(args.identity_id as string | undefined, "identity_sign");
        } catch {
          return toolResult(fixedDenial("audit:identity_sign"));
        }
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

        await recordCriticalAudit(auditLog, "l1", "identity_sign", identity.identity_id);

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
        await recordCriticalAudit(auditLog, "l1", "identity_rotate", identity.identity_id, {
          reason,
        });
        await identityMgr.save(updatedIdentity);

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

        const previousPrimary = identityMgr.getPrimaryIdentityId();

        await recordCriticalAudit(auditLog, "l1", "identity_set_primary", identityId, {
          previous_primary: previousPrimary,
        });

        const success = await identityMgr.setPrimary(identityId);
        if (!success) {
          return toolResult({
            error: `Failed to set primary identity to "${identityId}".`,
          });
        }

        return toolResult({
          primary_identity_id: identityId,
          label: identity.label,
          did: identity.did,
          set_at: new Date().toISOString(),
        });
      },
    },

    // State Tools

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

        try {
          assertOpaqueNamespaceOwned(args.namespace as string);
          assertIdentityMatchesSession(args.identity_id as string | undefined, "state_write");
        } catch {
          return denyNamespaceAccess("state_write", args.namespace as string);
        }

        const identity = resolveIdentity(args.identity_id as string | undefined);
        const metadata = args.metadata as {
          content_type?: string;
          ttl_seconds?: number;
          tags?: string[];
        } | undefined;

        await recordCriticalAudit(auditLog, "l1", "state_write", identity.identity_id, {
          namespace: args.namespace,
          key: args.key,
        });

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
            provenance: {
              origin_actor: stateWriteOriginActor(identity.identity_id),
            },
          }
        );

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

        try {
          assertOpaqueNamespaceOwned(args.namespace as string);
        } catch {
          return denyNamespaceAccess("state_read", args.namespace as string);
        }

        let result;
        try {
          result = await stateStore.read(
            args.namespace as string,
            args.key as string,
            (args.verify_integrity as boolean | undefined) ?? true
          );
        } catch (error) {
          if (error instanceof StateVerificationError) {
            await recordCriticalAudit(
              auditLog,
              "l1",
              "state_read_verification_failed",
              "state-store",
              {
                namespace: args.namespace,
                key: args.key,
                classification: error.classification,
              },
              "failure"
            );
            return toolResult({
              error: "state_verification_failed",
              classification: error.classification,
              signature_verified: false,
              message: "State verification failed.",
              namespace: args.namespace,
              key: args.key,
            });
          }
          throw error;
        }

        if (!result) {
          return toolResult(fixedDenial("audit:state_read"));
        }

        void auditLog?.append("l1", "state_read", result.written_by, {
          namespace: args.namespace,
          key: args.key,
        });

        return toolResult(result);
      },
    },

    {
      name: "state_list",
      description:
        "List the keys in a namespace with metadata (version, size, timestamps) only: values are not decrypted or returned. Use to enumerate stored state before a targeted state_read. Read-only.",
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

        try {
          assertOpaqueNamespaceOwned(args.namespace as string);
        } catch {
          return denyNamespaceAccess("state_list", args.namespace as string);
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
        "Permanently delete state: removes the entry with a best-effort " +
        "random-byte overwrite before unlinking. On copy-on-write/SSD media " +
        "the original bytes may survive, so at-rest confidentiality rests on " +
        "encryption (data is stored as ciphertext), not on the overwrite. " +
        "Satisfies right-to-deletion (S1.6) by removing the entry.",
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

        try {
          assertOpaqueNamespaceOwned(args.namespace as string);
        } catch {
          return denyNamespaceAccess("state_delete", args.namespace as string);
        }

        await recordCriticalAudit(auditLog, "l1", "state_delete", "principal", {
          namespace: args.namespace,
          key: args.key,
          reason: args.reason,
        });

        const result = await stateStore.delete(
          args.namespace as string,
          args.key as string
        );

        return toolResult(result);
      },
    },

    {
      name: "state_export",
      description:
        "Export state as an encrypted sanctuary-v1 bundle for migration to another instance of the same fortress, meaning the same master key, for example after restoring via the recovery key. Tier 1: requires operator approval because data leaves the local store. New exports include an authenticated completeness manifest with the namespace set, per-namespace item counts, and per-namespace content checksums. On state_import, the manifest verifies that the bundle body still matches the approved export scope and rejects dropped or added namespaces and entries within that scope. It does not prove that data outside the approved export scope should have been included, and it does not make the bundle importable by a different fortress master key.",
      inputSchema: {
        type: "object",
        properties: {
          namespace: { type: "string" },
          format: { type: "string", default: "sanctuary-v1" },
        },
      },
      approvalTargetArgs: (args) =>
        typeof args.namespace === "string"
          ? args
          : { ...args, namespaces: sessionOwnedExportNamespaces() },
      handler: async (args) => {
        let namespaces: string[] | undefined;
        if (typeof args.namespace === "string") {
          try {
            assertOpaqueNamespaceOwned(args.namespace);
          } catch {
            return denyNamespaceAccess("state_export", args.namespace);
          }
        } else if (options?.currentSessionBinding?.()) {
          try {
            namespaces = sessionOwnedExportNamespaces();
          } catch {
            return denyNamespaceAccess("state_export", "state_export");
          }
        } else {
          namespaces = sessionOwnedExportNamespaces();
        }

        const result =
          typeof args.namespace === "string"
            ? await stateStore.export(args.namespace)
            : await stateStore.exportNamespaces(namespaces);

        await recordCriticalAudit(auditLog, "l1", "state_export", "principal", {
          namespaces: result.namespaces,
        });

        return toolResult(result);
      },
    },

    {
      name: "state_import",
      description: "Import a previously exported encrypted sanctuary-v1 state bundle into another instance of the same fortress, meaning the same master key, for example after restoring via the recovery key. Tier 1: requires operator approval. By default, import requires authenticated bundle integrity and a completeness manifest, then recomputes the manifest before any write. Manifest, count, checksum, timestamp, MAC, or newer-schema mismatches are rejected. The verification proves the bundle body still matches the approved export scope; it does not prove data outside that scope should have been included. Manifestless legacy bundles are rejected unless allow_unverified_legacy is true, and that import result is flagged unverified-completeness-legacy-bundle.",
      inputSchema: {
        type: "object",
        properties: {
          bundle: { type: "string", description: "Base64url-encoded bundle" },
          conflict_resolution: {
            type: "string",
            enum: ["skip", "overwrite", "version"],
            default: "skip",
          },
          allow_unverified_legacy: {
            type: "boolean",
            default: false,
            description:
              "Explicitly import a manifestless legacy bundle without completeness guarantees. Default false rejects bundles that predate authenticated completeness verification.",
          },
        },
        required: ["bundle"],
      },
      approvalTargetArgs: (args) => ({
        ...args,
        namespaces: decodeExportBundleNamespaces(args.bundle as string),
      }),
      handler: async (args) => {
        let targetNamespaces: string[];
        try {
          targetNamespaces = decodeExportBundleNamespaces(args.bundle as string);
          assertOpaqueNamespacesOwned(targetNamespaces);
        } catch {
          return denyNamespaceAccess("state_import", "state_import");
        }

        // Wire public key resolver for signature verification (SEC-005)
        const publicKeyResolver = (kid: string): Uint8Array | null => {
          const identity = identityMgr.get(kid);
          if (!identity) return null;
          return fromBase64url(identity.public_key);
        };

        await recordCriticalAudit(auditLog, "l1", "state_import", "principal", {
          conflict_resolution:
            (args.conflict_resolution as "skip" | "overwrite" | "version") ??
            "skip",
          namespaces: targetNamespaces,
        });

        const result = await stateStore.import(
          args.bundle as string,
          (args.conflict_resolution as "skip" | "overwrite" | "version") ??
            "skip",
          publicKeyResolver,
          { allowUnverifiedLegacy: args.allow_unverified_legacy === true }
        );

        return toolResult(result);
      },
    },
  ];

  return { tools, identityManager: identityMgr, internalSigning, namespaceRegistry };
}

// Back-compat alias (L1-L4 rename PR-3)
// The layer-numbered name stays exported so downstream imports keep working.
// The functional name above is canonical.
export const createL1Tools = createCognitiveTools;
