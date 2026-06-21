/**
 * Sanctuary MCP Server - L1 Cognitive Sovereignty: StateStore
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
  hmacSha256,
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
import {
  mintProvenanceStamp,
  serializeStamp,
  type DerivedFromEdge,
  type OriginActor,
  type ProvenanceStamp,
  type SealedProvenanceStamp,
} from "../exit/memory-class.js";

const LEGACY_STATE_ENVELOPE_SCHEMA_VERSION = 2;
const STATE_ENVELOPE_SCHEMA_VERSION = 3;
const LEGACY_STATE_ENVELOPE_SIGNING_DOMAIN = "sanctuary.state-envelope.v1\n";
const STATE_ENVELOPE_SIGNING_DOMAIN_PREFIX = "sanctuary.state-envelope.v";
const STATE_ENVELOPE_PUBLIC_KEYS_KEY = "state-envelope-public-keys-v1";
const STATE_ENVELOPE_VERSION_ANCHORS_KEY = "state-envelope-version-anchors-v1";
// F1: domain-separated MAC over the version-anchor record (the rollback floor),
// which is stored plaintext. Without authentication a filesystem adversary could
// silently EDIT/LOWER a key's floor to defeat the #391 leapfrog gate; the MAC
// makes such an edit detectable (verification fails -> the read is rejected). The
// MAC binds the `_meta` key so the record cannot be replayed under another key.
// Scope note: this authenticates the version anchor only. The writer-public-key
// registry (`state-envelope-public-keys-v1`) is a separate plaintext `_meta`
// record; authenticating it (to close kid->key injection when an identity is
// resolved from the registry rather than `_identities`) is a related but
// distinct hardening, tracked separately - it is NOT covered here.
const STATE_META_MAC_DOMAIN = "sanctuary.meta-record-mac.v1\n";
// Distinctive envelope marker so a MAC'd record is unambiguously distinguished
// from a legacy bare record (legacy keys are versionKeys, never this).
const STATE_META_MAC_MARKER = "__sanctuary_meta_mac_v1";
const FACADE_HIDDEN_MARKER_NAMESPACE = "_facade/hidden";

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

export function decodeExportBundleNamespaces(bundleBase64: string): string[] {
  const bundleBytes = fromBase64url(bundleBase64);
  const bundleJson = bytesToString(bundleBytes);
  const bundle = JSON.parse(bundleJson) as {
    namespaces?: unknown;
    data?: unknown;
  };
  const actualNamespaces =
    bundle.data && typeof bundle.data === "object" && !Array.isArray(bundle.data)
      ? Object.keys(bundle.data).sort()
      : [];
  if (Array.isArray(bundle.namespaces)) {
    if (!bundle.namespaces.every((namespace) => typeof namespace === "string")) {
      throw new Error("export bundle namespace metadata is invalid");
    }
    const declaredNamespaces = [...bundle.namespaces].sort();
    if (declaredNamespaces.join("\0") !== actualNamespaces.join("\0")) {
      throw new Error("export bundle namespace metadata does not match data");
    }
  }
  return actualNamespaces;
}

function parseFacadeHiddenMarker(raw: Uint8Array): { namespace: string; key: string } | null {
  try {
    const marker = JSON.parse(bytesToString(raw)) as Record<string, unknown>;
    if (typeof marker.namespace !== "string" || typeof marker.key !== "string") return null;
    return { namespace: marker.namespace, key: marker.key };
  } catch {
    return null;
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
  provenance_stamp?: ProvenanceStamp;
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
 * Reserved namespace prefixes - used by internal subsystems.
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
  /** Format version. v1 is legacy signed-ciphertext-only; v2+ signs the full envelope. */
  v: number;
  /** Canonical state envelope signed by envelope_sig. */
  envelope?: SignedStateEnvelope;
  /** Encrypted payload */
  payload: EncryptedPayload;
  /** Version number (monotonically increasing) */
  ver: number;
  /** Legacy-compatible signature over ciphertext by the writing identity (base64url) */
  sig: string;
  /** Signature over the canonical envelope by the writing identity (base64url) */
  envelope_sig?: string;
  /**
   * Schema-3 user-state provenance stamp. Present only on new writes after
   * Exit Slice 2. Legacy schema-2 entries intentionally remain unstamped.
   */
  provenance_stamp?: ProvenanceStamp;
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
  provenance?: {
    /**
     * Internal, derived actor signal. `agent` is passed only from the existing
     * session-identity path; absent/unknown fails closed to operator.
     */
    origin_actor?: OriginActor;
    origin_ref?: string;
    lineage_id?: string;
    derived_from?: readonly DerivedFromEdge[];
  };
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

/** Constant-time byte comparison for MAC verification (avoids timing leaks). */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

function stateEnvelopeSigningDomain(envelope: SignedStateEnvelope): string {
  const schemaVersion = envelope.metadata.schema_version;
  if (schemaVersion <= LEGACY_STATE_ENVELOPE_SCHEMA_VERSION) {
    return LEGACY_STATE_ENVELOPE_SIGNING_DOMAIN;
  }
  return `${STATE_ENVELOPE_SIGNING_DOMAIN_PREFIX}${schemaVersion}\n`;
}

function stateEnvelopeSigningBytes(envelope: SignedStateEnvelope): Uint8Array {
  return stringToBytes(stateEnvelopeSigningDomain(envelope) + canonicalJson(envelope));
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
  schemaVersion: number;
  metadata: StateEntry["metadata"];
  provenanceStamp?: ProvenanceStamp;
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
      schema_version: args.schemaVersion,
      content_type: args.metadata.content_type,
      ttl_seconds: args.metadata.ttl_seconds,
      tags: args.metadata.tags,
    },
    ...(args.provenanceStamp !== undefined
      ? { provenance_stamp: args.provenanceStamp }
      : {}),
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

function entryBinding(namespace: string, key: string): string {
  return `${namespace}/${key}`;
}

function resolveWriteOriginActor(actor: OriginActor | undefined): OriginActor {
  return actor === "agent" || actor === "system" ? actor : "operator";
}

function mintSerializedWriteStamp(args: {
  namespace: string;
  key: string;
  identityId: string;
  writtenAt: string;
  version: number;
  provenance?: WriteOptions["provenance"];
}): ProvenanceStamp {
  const stamp = mintProvenanceStamp({
    origin_actor: resolveWriteOriginActor(args.provenance?.origin_actor),
    origin_ref: args.provenance?.origin_ref ?? args.identityId,
    lineage_id:
      args.provenance?.lineage_id ??
      `state:${entryBinding(args.namespace, args.key)}:v${args.version}`,
    written_at: args.writtenAt,
    entry_binding: entryBinding(args.namespace, args.key),
    ...(args.provenance?.derived_from !== undefined
      ? { derived_from: args.provenance.derived_from }
      : {}),
  });
  return serializeStamp(stamp);
}

function isMemoryClass(value: unknown): value is ProvenanceStamp["memory_class"] {
  return (
    value === "operator_owned" ||
    value === "agent_owned" ||
    value === "shared_entangled"
  );
}

function isOriginActor(value: unknown): value is OriginActor {
  return value === "operator" || value === "agent" || value === "system";
}

function isStringArray(value: unknown): value is readonly string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function normalizeDerivedEdgesForRemint(
  stamp: ProvenanceStamp
): readonly DerivedFromEdge[] | null {
  if (stamp.derived_from_edges !== undefined) {
    if (!Array.isArray(stamp.derived_from_edges)) return null;
    const edges: DerivedFromEdge[] = [];
    for (const edge of stamp.derived_from_edges) {
      if (
        edge === null ||
        typeof edge !== "object" ||
        typeof (edge as { lineage_id?: unknown }).lineage_id !== "string" ||
        !isMemoryClass((edge as { memory_class?: unknown }).memory_class)
      ) {
        return null;
      }
      edges.push({
        lineage_id: (edge as { lineage_id: string }).lineage_id,
        memory_class: (edge as { memory_class: ProvenanceStamp["memory_class"] }).memory_class,
      });
    }
    return edges;
  }

  // Old serialized stamps that carried only lineage ids cannot safely
  // reconstruct a shared_entangled class. New schema-3 writes persist full
  // edges, so this path is only for defensive compatibility.
  return stamp.memory_class === "shared_entangled" ? null : [];
}

function normalizePersistedProvenanceStamp(value: unknown): ProvenanceStamp | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (
    !isMemoryClass(record.memory_class) ||
    !isOriginActor(record.origin_actor) ||
    typeof record.origin_ref !== "string" ||
    record.origin_ref.length === 0 ||
    typeof record.lineage_id !== "string" ||
    record.lineage_id.length === 0 ||
    typeof record.written_at !== "string" ||
    !isStringArray(record.derived_from)
  ) {
    return null;
  }
  if (
    record.entry_binding !== undefined &&
    (typeof record.entry_binding !== "string" || record.entry_binding.length === 0)
  ) {
    return null;
  }
  const stamp: ProvenanceStamp = {
    memory_class: record.memory_class,
    origin_actor: record.origin_actor,
    origin_ref: record.origin_ref,
    lineage_id: record.lineage_id,
    written_at: record.written_at,
    derived_from: [...record.derived_from],
    ...(record.entry_binding !== undefined
      ? { entry_binding: record.entry_binding }
      : {}),
  };
  const edges = normalizeDerivedEdgesForRemint({
    ...stamp,
    ...(record.derived_from_edges !== undefined
      ? { derived_from_edges: record.derived_from_edges as DerivedFromEdge[] }
      : {}),
  });
  if (edges === null) return null;
  return {
    ...stamp,
    ...(edges.length > 0 ? { derived_from_edges: edges } : {}),
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
    if (cached) {
      // Best-effort: the entry is expired and is about to be replaced by a
      // freshly derived key below; zero the stale bytes so they are not left
      // on the V8 heap until GC (prior callers consumed the key synchronously).
      cached.key.fill(0);
    }

    // Evict expired or LRU entries if at capacity
    if (this.namespaceKeyCache.size >= StateStore.KEY_CACHE_MAX_ENTRIES) {
      // Remove oldest entry (Map iteration order = insertion order)
      const firstKey = this.namespaceKeyCache.keys().next().value;
      if (firstKey !== undefined) {
        // Best-effort: zero the derived key bytes before dropping the entry so
        // the material is not left on the V8 heap until GC (consistent with
        // identity.ts / master-custody.ts / master-rotation.ts).
        this.namespaceKeyCache.get(firstKey)?.key.fill(0);
        this.namespaceKeyCache.delete(firstKey);
      }
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
    // Best-effort: zero each derived key's bytes before clearing so the
    // material is not left on the V8 heap until GC.
    for (const cached of this.namespaceKeyCache.values()) {
      cached.key.fill(0);
    }
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

  /**
   * MAC over the version-anchor record, keyed from the master key and bound to
   * the record key (so it cannot be replayed under another `_meta` key).
   */
  private metaRecordMacBytes(
    key: string,
    record: Record<string, unknown>
  ): Uint8Array {
    const macKey = derivePurposeKey(this.masterKey, "state-meta-mac");
    return hmacSha256(
      macKey,
      stringToBytes(STATE_META_MAC_DOMAIN + key + "\n" + canonicalJson(record))
    );
  }

  /**
   * Load the MAC-authenticated version-anchor record (the persistent rollback
   * floor - F1). Stored as a `{ marker, data, mac }` envelope:
   *   - MAC present + valid    -> return the authenticated floor.
   *   - MAC present + invalid  -> edited in place; reject (the attacker cannot
   *     silently LOWER a key's floor).
   *   - no marker (bare / marker-stripped) OR absent -> NO trusted floor
   *     (return {}). We deliberately do NOT trust or re-MAC a bare record:
   *     re-MACing it would let a filesystem adversary bypass authentication by
   *     stripping the marker and rewriting the values. Instead the floor
   *     re-establishes from the *authenticated* v2 entries via observeVersion,
   *     so a stripped/legacy anchor self-heals on the next read/write without
   *     ever trusting attacker-supplied values.
   *
   * Residual (documented, not closed here): deleting the anchor AND replacing a
   * key's entry with an older validly-signed v2 entry resets that key's floor
   * (a replay). Closing it needs a floor that does not live in a single
   * deletable file (boot-anchored / externally-attested) - out of scope for F1.
   */
  private async loadVersionAnchors(): Promise<Record<string, unknown>> {
    const raw = await this.storage.read(
      "_meta",
      STATE_ENVELOPE_VERSION_ANCHORS_KEY
    );
    if (!raw) return {};

    let parsed: unknown;
    try {
      parsed = JSON.parse(bytesToString(raw));
    } catch {
      throw new StateVerificationError(
        "schema_mismatch",
        `State metadata record is corrupted: _meta/${STATE_ENVELOPE_VERSION_ANCHORS_KEY}`
      );
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new StateVerificationError(
        "schema_mismatch",
        `State metadata record is corrupted: _meta/${STATE_ENVELOPE_VERSION_ANCHORS_KEY}`
      );
    }
    const obj = parsed as Record<string, unknown>;

    if (obj[STATE_META_MAC_MARKER] !== true) {
      // Bare / marker-stripped / legacy: untrusted. Ignore (no floor); it
      // re-derives from authenticated entries via observeVersion.
      return {};
    }

    const data = obj.data;
    const mac = obj.mac;
    if (
      !data ||
      typeof data !== "object" ||
      Array.isArray(data) ||
      typeof mac !== "string"
    ) {
      throw new StateVerificationError(
        "schema_mismatch",
        `Version-anchor record is malformed: _meta/${STATE_ENVELOPE_VERSION_ANCHORS_KEY}`
      );
    }
    const record = data as Record<string, unknown>;
    let providedMac: Uint8Array;
    try {
      providedMac = fromBase64url(mac);
    } catch {
      throw new StateVerificationError(
        "integrity_hash_mismatch",
        `Version-anchor MAC is malformed: _meta/${STATE_ENVELOPE_VERSION_ANCHORS_KEY}`
      );
    }
    if (
      !constantTimeEqual(
        providedMac,
        this.metaRecordMacBytes(STATE_ENVELOPE_VERSION_ANCHORS_KEY, record)
      )
    ) {
      throw new StateVerificationError(
        "integrity_hash_mismatch",
        `Version-anchor record failed authentication (tampered or wrong key): _meta/${STATE_ENVELOPE_VERSION_ANCHORS_KEY}`
      );
    }
    return record;
  }

  /** Persist the version-anchor record in a MAC-authenticated envelope (F1). */
  private async saveVersionAnchors(
    record: Record<string, unknown>
  ): Promise<void> {
    const envelope = {
      [STATE_META_MAC_MARKER]: true,
      data: record,
      mac: toBase64url(
        this.metaRecordMacBytes(STATE_ENVELOPE_VERSION_ANCHORS_KEY, record)
      ),
    };
    await this.storage.write(
      "_meta",
      STATE_ENVELOPE_VERSION_ANCHORS_KEY,
      stringToBytes(JSON.stringify(envelope))
    );
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
    const anchors = await this.loadVersionAnchors();
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
    const anchors = await this.loadVersionAnchors();
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
      await this.saveVersionAnchors(anchors);
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
          // Corrupted entry - skip it
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

    // F1: the version-anchor record is untrusted unless MAC-valid (a bare /
    // marker-stripped anchor is ignored - see loadVersionAnchors), so it cannot
    // be the sole monotonic floor: otherwise the first post-upgrade write to an
    // existing key on a cold process (empty cache + ignored bare anchor) would
    // reset its version to 1, clobbering a higher on-disk version. Populate
    // versionCache from the persisted entries first so the floor reflects the
    // real on-disk version. (getNamespaceHashes is memoized per namespace, so
    // the later call at the end of write() reuses this.)
    await this.getNamespaceHashes(namespace);

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
    const provenanceStamp = mintSerializedWriteStamp({
      namespace,
      key,
      identityId,
      writtenAt: now,
      version: newVersion,
      provenance: options.provenance,
    });
    const envelope = buildSignedEnvelope({
      namespace,
      key,
      version: newVersion,
      kid: identityId,
      schemaVersion: STATE_ENVELOPE_SCHEMA_VERSION,
      metadata,
      provenanceStamp,
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
      provenance_stamp: provenanceStamp,
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

  private validateSignedEnvelope(
    entry: StateEntry,
    namespace: string,
    key: string
  ): SignedStateEnvelope {
    if (!entry.envelope) {
      throw new StateVerificationError(
        "schema_mismatch",
        `State envelope is missing for ${namespace}/${key}`
      );
    }

    if (
      entry.v !== LEGACY_STATE_ENVELOPE_SCHEMA_VERSION &&
      entry.v !== STATE_ENVELOPE_SCHEMA_VERSION
    ) {
      throw new StateVerificationError(
        "schema_mismatch",
        `Unsupported state envelope schema: ${entry.v}`
      );
    }

    if (entry.v === LEGACY_STATE_ENVELOPE_SCHEMA_VERSION && entry.provenance_stamp !== undefined) {
      throw new StateVerificationError(
        "schema_mismatch",
        `Legacy state envelope schema ${LEGACY_STATE_ENVELOPE_SCHEMA_VERSION} cannot carry provenance for ${namespace}/${key}`
      );
    }

    if (entry.v === STATE_ENVELOPE_SCHEMA_VERSION && entry.provenance_stamp === undefined) {
      throw new StateVerificationError(
        "schema_mismatch",
        `State envelope schema ${STATE_ENVELOPE_SCHEMA_VERSION} is missing provenance for ${namespace}/${key}`
      );
    }

    const expected = buildSignedEnvelope({
      namespace,
      key,
      version: entry.ver,
      kid: entry.kid,
      schemaVersion: entry.v,
      metadata: entry.metadata,
      ...(entry.provenance_stamp !== undefined
        ? { provenanceStamp: entry.provenance_stamp }
        : {}),
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

    if (
      entry.v !== LEGACY_STATE_ENVELOPE_SCHEMA_VERSION &&
      entry.v !== STATE_ENVELOPE_SCHEMA_VERSION
    ) {
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

    const envelope = this.validateSignedEnvelope(entry, namespace, key);
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

  /**
   * Verify a persisted state entry's signed envelope before re-minting its
   * provenance stamp into a live in-process seal for the exit partition. The
   * on-disk stamp is never trusted directly: schema/signature verification is
   * the durable trust anchor, then this method recomputes the class through the
   * sealed minter.
   */
  async remintVerifiedProvenanceStampForExport(
    entry: StateEntry,
    namespace: string,
    key: string
  ): Promise<
    | {
        status: "sealed";
        declaredStamp: ProvenanceStamp;
        sealedStamp: SealedProvenanceStamp;
      }
    | { status: "unstamped" }
    | { status: "unsealed"; declaredStamp?: ProvenanceStamp }
    | { status: "verification_failed"; error: StateVerificationError }
  > {
    // Legacy schema v1 signs only ciphertext, and schema v2 intentionally
    // carries no signed provenance. Any top-level provenance on either schema
    // is unsigned attacker-controlled metadata, so partitioned export must
    // treat the entry as unstamped without inspecting that field.
    if (entry.v <= LEGACY_STATE_ENVELOPE_SCHEMA_VERSION) {
      return { status: "unstamped" };
    }

    try {
      const verification = await this.verifyEntrySignature(entry, namespace, key);
      if (!verification.verified) {
        return {
          status: "verification_failed",
          error: new StateVerificationError(
            "kid_unknown",
            `Writer key not found for ${entry.kid}`
          ),
        };
      }
    } catch (err) {
      if (err instanceof StateVerificationError) {
        return { status: "verification_failed", error: err };
      }
      throw err;
    }

    if (entry.provenance_stamp === undefined) {
      return { status: "unstamped" };
    }

    const declaredStamp = normalizePersistedProvenanceStamp(entry.provenance_stamp);
    if (declaredStamp === null) {
      return { status: "unsealed" };
    }

    const derivedEdges = normalizeDerivedEdgesForRemint(declaredStamp);
    if (derivedEdges === null) {
      return { status: "unsealed", declaredStamp };
    }

    const sealedStamp = mintProvenanceStamp({
      origin_actor: declaredStamp.origin_actor,
      origin_ref: declaredStamp.origin_ref,
      lineage_id: declaredStamp.lineage_id,
      written_at: declaredStamp.written_at,
      ...(declaredStamp.entry_binding !== undefined
        ? { entry_binding: declaredStamp.entry_binding }
        : {}),
      ...(derivedEdges.length > 0 ? { derived_from: derivedEdges } : {}),
    });

    if (sealedStamp.memory_class !== declaredStamp.memory_class) {
      return { status: "unsealed", declaredStamp };
    }

    return { status: "sealed", declaredStamp, sealedStamp };
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
      schema_version: LEGACY_STATE_ENVELOPE_SCHEMA_VERSION,
    };
    const envelope = buildSignedEnvelope({
      namespace,
      key,
      version: entry.ver,
      kid: entry.kid,
      schemaVersion: LEGACY_STATE_ENVELOPE_SCHEMA_VERSION,
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
      v: LEGACY_STATE_ENVELOPE_SCHEMA_VERSION,
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
    // anchor. Legitimate version bumps are written as signed-envelope schemas
    // (v2+), so a v1 entry claiming a version above the persisted anchor can
    // only be a downgrade/replay forgery. The v1 signature binds the ciphertext
    // ONLY (not version/namespace/key), so the signature check below cannot catch
    // this; the persisted anchor is the discriminator. The anchor record is now
    // MAC-authenticated (loadVersionAnchors), so it can no longer be silently
    // EDITED/LOWERED to defeat this gate (an edit fails the MAC and the read is
    // rejected).
    //
    // RESIDUAL (documented, not closed here): a bare/absent anchor is treated as
    // "no trusted floor" (anchored 0), so this gate does not fire. A filesystem
    // adversary can therefore RESET the floor by deleting/stripping the anchors
    // record and then replay a forged high-version v1 entry. Closing the
    // deletion variant requires distrusting v1 on the enforced read path entirely
    // (verified:false unless re-migrated), which breaks reads of legitimate
    // un-migrated pre-v2 fortresses - a backward-compat migration decision left
    // as a follow-up. (A genuine pre-migration v1 entry sits at/below its anchor;
    // on a bare-anchor fortress it reads normally because the gate is skipped.)
    if (options.enforceRollback && stateEntry.v === 1) {
      const anchoredVersion = await this.getAnchoredVersion(namespace, key);
      if (anchoredVersion > 0 && stateEntry.ver > anchoredVersion) {
        throw new StateVerificationError(
          "rollback_detected",
          `Rollback detected for ${namespace}/${key}: a legacy (v1) entry at version ${stateEntry.ver} cannot exceed the established anchor ${anchoredVersion} (legitimate advances are written as signed-envelope schemas)`
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
   * List keys in a namespace (metadata only - no decryption).
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
    return this.exportNamespaces(
      namespace === undefined ? undefined : [namespace]
    );
  }

  listCachedExportableNamespaces(): string[] {
    return [...this.contentHashes.keys()]
      .filter((namespace) => !namespace.startsWith("_"))
      .sort();
  }

  async exportNamespaces(
    requestedNamespaces?: string[]
  ): Promise<{
    bundle: string;
    namespaces: string[];
    total_keys: number;
    bundle_hash: string;
    exported_at: string;
  }> {
    const namespacesToExport: string[] = [];

    // F6: never export internal `_`-prefixed namespaces - import() rejects them
    // (so they cannot round-trip) and they are internal-subsystem state external
    // export must not expose. Filter HERE (not mid-loop) so the serialized
    // `namespaces` metadata and `data` stay consistent: the bundle never lists a
    // namespace it does not actually contain.
    if (requestedNamespaces) {
      for (const namespace of requestedNamespaces) {
        if (!namespace.startsWith("_") && !namespacesToExport.includes(namespace)) {
          namespacesToExport.push(namespace);
        }
      }
    } else {
      // Discover all namespaces from the content hash cache
      namespacesToExport.push(...this.listCachedExportableNamespaces());
    }

    const exportData: Record<
      string,
      Array<{ key: string; entry: StateEntry }>
    > = {};
    const facadeHiddenMarkers: Array<{ key: string; marker: unknown }> = [];
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

    const markerEntries = await this.storage.list(FACADE_HIDDEN_MARKER_NAMESPACE);
    for (const entry of markerEntries) {
      const raw = await this.storage.read(FACADE_HIDDEN_MARKER_NAMESPACE, entry.key);
      if (!raw) continue;
      const marker = parseFacadeHiddenMarker(raw);
      if (!marker || !namespacesToExport.includes(marker.namespace)) continue;
      facadeHiddenMarkers.push({
        key: entry.key,
        marker: JSON.parse(bytesToString(raw)) as unknown,
      });
    }

    const bundleJson = JSON.stringify({
      sanctuary_export_version: 1,
      exported_at: new Date().toISOString(),
      namespaces: namespacesToExport,
      data: exportData,
      ...(facadeHiddenMarkers.length > 0
        ? { facade_hidden_markers: facadeHiddenMarkers }
        : {}),
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
    decodeExportBundleNamespaces(bundleBase64);

    let importedKeys = 0;
    let skippedKeys = 0;
    let skippedInvalidSig = 0;
    let skippedUnknownKid = 0;
    let conflicts = 0;
    const namespaces: string[] = [];

    for (const [ns, entries] of Object.entries(
      bundle.data as Record<string, Array<{ key: string; entry: StateEntry }>>
    )) {
      // Namespace firewall: skip reserved namespaces during import.
      // F6: reject ALL underscore-prefixed (internal) namespaces, not just the
      // curated RESERVED_NAMESPACE_PREFIXES list. Export never emits a
      // `_`-prefixed namespace, so any in a bundle is crafted; the curated list
      // could miss a newer internal `_`-namespace and let a bundle write into it.
      if (ns.startsWith("_") || RESERVED_NAMESPACE_PREFIXES.some(
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

        // Verify the signature against the signed envelope or legacy ciphertext.
        try {
          if (
            entry.v !== 1 &&
            entry.v !== LEGACY_STATE_ENVELOPE_SCHEMA_VERSION &&
            entry.v !== STATE_ENVELOPE_SCHEMA_VERSION
          ) {
            skippedInvalidSig++;
            skippedKeys++;
            continue;
          }
          const signaturePayload =
            entry.v === LEGACY_STATE_ENVELOPE_SCHEMA_VERSION ||
            entry.v === STATE_ENVELOPE_SCHEMA_VERSION
              ? stateEnvelopeSigningBytes(
                  this.validateSignedEnvelope(entry, ns, key)
                )
              : fromBase64url(entry.payload.ct);
          const signature =
            entry.v === LEGACY_STATE_ENVELOPE_SCHEMA_VERSION ||
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
          if (
            entry.v === LEGACY_STATE_ENVELOPE_SCHEMA_VERSION ||
            entry.v === STATE_ENVELOPE_SCHEMA_VERSION
          ) {
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
          // Malformed signature or ciphertext - reject
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
                // Corrupted existing entry - overwrite
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

    if (Array.isArray(bundle.facade_hidden_markers)) {
      const importedNamespaceSet = new Set(namespaces);
      for (const item of bundle.facade_hidden_markers) {
        if (!item || typeof item !== "object" || Array.isArray(item)) continue;
        const record = item as Record<string, unknown>;
        if (typeof record.key !== "string" || record.key.includes("/") || record.key.length > 256) continue;
        const marker = record.marker;
        if (!marker || typeof marker !== "object" || Array.isArray(marker)) continue;
        const markerRecord = marker as Record<string, unknown>;
        if (
          typeof markerRecord.namespace !== "string" ||
          typeof markerRecord.key !== "string" ||
          !importedNamespaceSet.has(markerRecord.namespace)
        ) {
          continue;
        }
        await this.storage.write(
          FACADE_HIDDEN_MARKER_NAMESPACE,
          record.key,
          stringToBytes(JSON.stringify(markerRecord))
        );
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

// ── Master-rotation helpers (core/master-rotation.ts) ────────────────
//
// State entries cryptographically bind their CIPHERTEXT to the writer
// identity (the v2 envelope signs nonce/tag/ciphertext; the legacy v1 `sig`
// signs the raw ciphertext), so a master rotation cannot simply re-encrypt a
// state entry - it must re-sign with the original writer's resident private
// key. These helpers keep the canonical envelope/signature construction in
// this module (single source of truth) while the rotation engine drives the
// walk. They never relax verification: the OLD entry's signatures are
// verified BEFORE re-signing (a rotation must not launder a tampered entry
// into a freshly-signed one), and a missing writer identity fails closed.

/** Writer material the rotation engine resolved for a state entry's kid. */
export interface RotationWriterMaterial {
  /** The writer's encrypted private key (under `identityEncryptionKey`). */
  encryptedPrivateKey: EncPayload;
  /** The identity-encryption purpose key that decrypts it. */
  identityEncryptionKey: Uint8Array;
  /** The writer's Ed25519 public key (for verifying the OLD signatures). */
  publicKey: Uint8Array;
}

export class RotationStateEntryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RotationStateEntryError";
  }
}

export type RotateStateEntryResult =
  | { status: "already-new" }
  | { status: "verified-old" }
  | { status: "converted"; bytes: Uint8Array };

/**
 * Verify (and, unless `verifyOnly`, re-encrypt + re-sign) one persisted
 * state entry for a master rotation.
 *
 *  - Decrypts under the NEW namespace key first → "already-new" (idempotent
 *    resume; GCM authentication decides).
 *  - Otherwise decrypts under the OLD namespace key (failure throws - the
 *    rotation preflight aborts; nothing is mutated on an undecryptable
 *    fortress).
 *  - Verifies the OLD entry's signature(s) against the writer's public key
 *    before producing anything (no laundering).
 *  - Re-encrypts the plaintext under the new key and re-signs with the
 *    writer's resident private key. Version, integrity_hash (plaintext
 *    hash), metadata, and kid are all preserved - only the ciphertext block
 *    and the signatures over it change.
 */
export async function rotateStateEntryBytes(args: {
  raw: Uint8Array;
  namespace: string;
  key: string;
  oldNamespaceKey: Uint8Array;
  newNamespaceKey: Uint8Array;
  resolveWriter: (kid: string) => Promise<RotationWriterMaterial | null>;
  verifyOnly?: boolean;
}): Promise<RotateStateEntryResult> {
  const { namespace, key } = args;
  let entry: StateEntry;
  try {
    entry = JSON.parse(bytesToString(args.raw)) as StateEntry;
  } catch {
    throw new RotationStateEntryError(
      `state entry ${namespace}/${key} is not valid JSON`
    );
  }
  if (!entry || typeof entry !== "object" || !entry.payload) {
    throw new RotationStateEntryError(
      `state entry ${namespace}/${key} has no encrypted payload`
    );
  }

  // Idempotent resume: an entry that already authenticates under the new
  // namespace key was converted before the crash.
  try {
    decrypt(entry.payload, args.newNamespaceKey).fill(0);
    return { status: "already-new" };
  } catch {
    // Not yet converted - proceed with the old key.
  }

  let plaintext: Uint8Array;
  try {
    plaintext = decrypt(entry.payload, args.oldNamespaceKey);
  } catch {
    throw new RotationStateEntryError(
      `state entry ${namespace}/${key} does not decrypt under either the old or the new master`
    );
  }

  try {
    const writer = await args.resolveWriter(entry.kid);
    if (!writer) {
      throw new RotationStateEntryError(
        `state entry ${namespace}/${key} was written by identity "${entry.kid}", ` +
          `which is not resident in this fortress. Rotation re-signs every state ` +
          `entry with its writer's key and cannot proceed without it. ` +
          `Re-import the identity, or delete the orphaned entry, then retry.`
      );
    }

    // Verify the OLD signatures before re-signing anything.
    if (entry.v === 1) {
      if (
        typeof entry.sig !== "string" ||
        !verify(fromBase64url(entry.payload.ct), fromBase64url(entry.sig), writer.publicKey)
      ) {
        throw new RotationStateEntryError(
          `state entry ${namespace}/${key} failed legacy signature verification; refusing to re-sign it`
        );
      }
    } else {
      if (!entry.envelope || typeof entry.envelope_sig !== "string") {
        throw new RotationStateEntryError(
          `state entry ${namespace}/${key} is schema ${entry.v} but is missing its signed envelope`
        );
      }
      const expected = buildSignedEnvelope({
        namespace,
        key,
        version: entry.ver,
        kid: entry.kid,
        schemaVersion: entry.v,
        metadata: entry.metadata,
        ...(entry.provenance_stamp !== undefined
          ? { provenanceStamp: entry.provenance_stamp }
          : {}),
        integrityHash: entry.integrity_hash,
        payload: entry.payload,
      });
      if (canonicalJson(entry.envelope) !== canonicalJson(expected)) {
        throw new RotationStateEntryError(
          `state entry ${namespace}/${key} envelope metadata mismatch; refusing to re-sign it`
        );
      }
      if (
        !verify(
          stateEnvelopeSigningBytes(entry.envelope),
          fromBase64url(entry.envelope_sig),
          writer.publicKey
        ) ||
        typeof entry.sig !== "string" ||
        !verify(fromBase64url(entry.payload.ct), fromBase64url(entry.sig), writer.publicKey)
      ) {
        throw new RotationStateEntryError(
          `state entry ${namespace}/${key} failed signature verification; refusing to re-sign it`
        );
      }
    }

    if (args.verifyOnly) {
      return { status: "verified-old" };
    }

    const newPayload = encrypt(plaintext, args.newNamespaceKey);
    const legacySig = sign(
      fromBase64url(newPayload.ct),
      writer.encryptedPrivateKey,
      writer.identityEncryptionKey
    );

    let rotated: StateEntry;
    if (entry.v === 1) {
      rotated = { ...entry, payload: newPayload, sig: toBase64url(legacySig) };
    } else {
      const envelope = buildSignedEnvelope({
        namespace,
        key,
        version: entry.ver,
        kid: entry.kid,
        schemaVersion: entry.v,
        metadata: entry.metadata,
        ...(entry.provenance_stamp !== undefined
          ? { provenanceStamp: entry.provenance_stamp }
          : {}),
        integrityHash: entry.integrity_hash,
        payload: newPayload,
      });
      const envelopeSig = sign(
        stateEnvelopeSigningBytes(envelope),
        writer.encryptedPrivateKey,
        writer.identityEncryptionKey
      );
      rotated = {
        ...entry,
        envelope,
        payload: newPayload,
        sig: toBase64url(legacySig),
        envelope_sig: toBase64url(envelopeSig),
      };
    }
    return {
      status: "converted",
      bytes: stringToBytes(JSON.stringify(rotated)),
    };
  } finally {
    plaintext.fill(0);
  }
}

/** `_meta` keys owned by the state store (for the rotation walker). */
export const STATE_META_PUBLIC_KEYS_KEY = STATE_ENVELOPE_PUBLIC_KEYS_KEY;
export const STATE_META_VERSION_ANCHORS_KEY = STATE_ENVELOPE_VERSION_ANCHORS_KEY;

/**
 * Re-MAC the version-anchor `_meta` record for a master rotation.
 *
 * Returns:
 *  - null            - record is bare/legacy (no MAC marker): untrusted today
 *    and left untouched; the floor re-derives from authenticated entries.
 *  - "already-new"   - MAC already verifies under the new master (resume).
 *  - bytes           - restamped record, after the OLD MAC verified.
 *
 * Throws when the record carries the marker but its MAC verifies under
 * NEITHER master - that is tampering, and a rotation must not launder it
 * into a freshly-authenticated record.
 */
export function rotateStateMetaRecordBytes(args: {
  raw: Uint8Array;
  metaKey: string;
  oldMasterKey: Uint8Array;
  newMasterKey: Uint8Array;
}): Uint8Array | "already-new" | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToString(args.raw));
  } catch {
    throw new RotationStateEntryError(
      `state meta record _meta/${args.metaKey} is not valid JSON`
    );
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new RotationStateEntryError(
      `state meta record _meta/${args.metaKey} is malformed`
    );
  }
  const obj = parsed as Record<string, unknown>;
  if (obj[STATE_META_MAC_MARKER] !== true) {
    return null; // Bare/legacy record: untrusted, leave as-is.
  }
  const data = obj.data;
  const mac = obj.mac;
  if (!data || typeof data !== "object" || Array.isArray(data) || typeof mac !== "string") {
    throw new RotationStateEntryError(
      `state meta record _meta/${args.metaKey} is malformed`
    );
  }
  const record = data as Record<string, unknown>;
  const macFor = (master: Uint8Array): Uint8Array => {
    const macKey = derivePurposeKey(master, "state-meta-mac");
    const out = hmacSha256(
      macKey,
      stringToBytes(STATE_META_MAC_DOMAIN + args.metaKey + "\n" + canonicalJson(record))
    );
    macKey.fill(0);
    return out;
  };
  let provided: Uint8Array;
  try {
    provided = fromBase64url(mac);
  } catch {
    throw new RotationStateEntryError(
      `state meta record _meta/${args.metaKey} MAC is malformed`
    );
  }
  if (constantTimeEqual(provided, macFor(args.newMasterKey))) {
    return "already-new";
  }
  if (!constantTimeEqual(provided, macFor(args.oldMasterKey))) {
    throw new RotationStateEntryError(
      `state meta record _meta/${args.metaKey} failed authentication under both masters (tampered); refusing to restamp it`
    );
  }
  const restamped = {
    [STATE_META_MAC_MARKER]: true,
    data: record,
    mac: toBase64url(macFor(args.newMasterKey)),
  };
  return stringToBytes(JSON.stringify(restamped));
}
