/**
 * The state-entry envelope and its open path: parse, signature verification,
 * decryption and the integrity-hash check. The state store's enforcing read
 * and the local job worker both open records only through these functions,
 * so there is one envelope format and one verifier (rollback floors,
 * migration writes and version anchors stay in the state store).
 *
 * This file must not import cognitive/state-store.ts: the job worker's import
 * graph excludes it.
 */
import { decrypt, type EncryptedPayload } from "../core/encryption.js";
import { fromBase64url, toBase64url, stringToBytes, bytesToString } from "../core/encoding.js";
import { hashToString } from "../core/hashing.js";
import { verify } from "../core/identity.js";
import { STATE_ENVELOPE_SIGNING_DOMAIN_PREFIX } from "../core/signing-domains.js";
import { describeUntrusted } from "../errors/untrusted-diagnostic.js";
import type { ProvenanceStamp } from "../exit/memory-class.js";

export const LEGACY_STATE_ENVELOPE_SCHEMA_VERSION = 2;
export const STATE_ENVELOPE_SCHEMA_VERSION = 3;
export const LEGACY_STATE_ENVELOPE_SIGNING_DOMAIN = "sanctuary.state-envelope.v1\n";

export type StateVerificationClassification =
  | "signature_mismatch"
  | "kid_unknown"
  | "integrity_hash_mismatch"
  | "schema_mismatch"
  | "rollback_detected"
  // "the writer could not be established", which is a DISTINCT answer from all
  // four above and must never be collapsed into one of them: the bytes are
  // intact (not `integrity_hash_mismatch`), no signature was examined and found
  // wrong (not `signature_mismatch`), the shape parsed (not `schema_mismatch`),
  // and the version is at or above its floor (not `rollback_detected`). It is
  // also distinct from `kid_unknown`, which a signed-envelope (v2+) read raises
  // when key resolution fails outright; this one is raised by the enforcing read
  // path when verification was REQUESTED and finished without establishing a
  // writer. A caller that treats them as the same value loses the one
  // distinction that tells it a migration, not a repair, is the remedy.
  | "writer_unverified"
  // "the writer COULD be established, so this caller asked the wrong path".
  // Raised only by the operator disclosure surface, which serves exactly the
  // entries the enforcing read refuses and refuses everything else, so it can
  // never become a way to skip verification on an entry that does not need it.
  // Distinct from every value above because nothing failed: this is a refusal
  // to bypass a control that would have succeeded.
  | "writer_is_establishable";

export type StateVerificationReason =
  | "legacy_version_ceiling"
  | "version_below_floor";

export class StateVerificationError extends Error {
  readonly classification: StateVerificationClassification;
  readonly reason?: StateVerificationReason;

  constructor(
    classification: StateVerificationClassification,
    message: string,
    reason?: StateVerificationReason
  ) {
    super(message);
    this.name = "StateVerificationError";
    this.classification = classification;
    this.reason = reason;
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

export function verifyStateEntrySignaturesWithAuthenticatedKey(args: {
  publicKeys: readonly Uint8Array[];
  legacyCiphertext: Uint8Array;
  legacySignature: Uint8Array;
  envelopeBytes?: Uint8Array;
  envelopeSignature?: Uint8Array;
}): boolean {
  // INVARIANT: schema-2+ entries bind the envelope and legacy ciphertext to
  // the same authenticated writer key; separate matching keys would install
  // bytes the enforcing reader refuses.
  if (
    (args.envelopeBytes === undefined) !==
    (args.envelopeSignature === undefined)
  ) {
    return false;
  }
  return args.publicKeys.some((publicKey) => {
    if (
      args.envelopeBytes !== undefined &&
      args.envelopeSignature !== undefined &&
      !verify(args.envelopeBytes, args.envelopeSignature, publicKey)
    ) {
      return false;
    }
    return verify(args.legacyCiphertext, args.legacySignature, publicKey);
  });
}

export function canonicalize(value: unknown): unknown {
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

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

export function stateEnvelopeSigningDomain(envelope: SignedStateEnvelope): string {
  const schemaVersion = envelope.metadata.schema_version;
  if (schemaVersion <= LEGACY_STATE_ENVELOPE_SCHEMA_VERSION) {
    return LEGACY_STATE_ENVELOPE_SIGNING_DOMAIN;
  }
  return `${STATE_ENVELOPE_SIGNING_DOMAIN_PREFIX}${schemaVersion}\n`;
}

export function stateEnvelopeSigningBytes(envelope: SignedStateEnvelope): Uint8Array {
  return stringToBytes(stateEnvelopeSigningDomain(envelope) + canonicalJson(envelope));
}

export function legacyWarning(): LegacyEnvelopeWarningInfo {
  return {
    name: "LegacyEnvelopeWarning",
    classification: "legacy_schema_1",
    message:
      "Legacy state envelope v1 loaded with ciphertext-only signature verification",
  };
}

export function payloadAuthTag(payload: EncryptedPayload): string {
  const ciphertextAndTag = fromBase64url(payload.ct);
  if (ciphertextAndTag.length < 16) {
    throw new StateVerificationError(
      "schema_mismatch",
      "Encrypted payload is too short to contain an authentication tag"
    );
  }
  return toBase64url(ciphertextAndTag.slice(ciphertextAndTag.length - 16));
}

export function buildSignedEnvelope(args: {
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

export function validateSignedStateEnvelope(
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
      `Unsupported state envelope schema: ${describeUntrusted(entry.v)}`
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

export function verifyStateEntrySignatureWithKeys(
  entry: StateEntry,
  namespace: string,
  key: string,
  publicKeys: readonly Uint8Array[]
): { verified: boolean; warnings?: LegacyEnvelopeWarningInfo[] } {
  if (entry.v === 1) {
    const warnings = [legacyWarning()];
    if (publicKeys.length === 0) {
      return { verified: false, warnings };
    }

    const sigValid = verifyStateEntrySignaturesWithAuthenticatedKey({
      publicKeys,
      legacyCiphertext: fromBase64url(entry.payload.ct),
      legacySignature: fromBase64url(entry.sig),
    });
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
      `Unsupported state envelope schema: ${describeUntrusted(entry.v)}`
    );
  }

  if (publicKeys.length === 0) {
    throw new StateVerificationError(
      "kid_unknown",
      `Writer key not found for ${describeUntrusted(entry.kid)}`
    );
  }

  const envelope = validateSignedStateEnvelope(entry, namespace, key);
  if (!entry.envelope_sig) {
    throw new StateVerificationError(
      "schema_mismatch",
      `State envelope signature is missing for ${namespace}/${key}`
    );
  }
  if (typeof entry.sig !== "string") {
    throw new StateVerificationError(
      "schema_mismatch",
      `State envelope legacy ciphertext signature is missing for ${namespace}/${key}`
    );
  }
  const envelopeSig = fromBase64url(entry.envelope_sig);
  const legacySig = fromBase64url(entry.sig);
  const signedEnvelope = stateEnvelopeSigningBytes(envelope);
  const legacyCiphertext = fromBase64url(entry.payload.ct);
  const sigValid = verifyStateEntrySignaturesWithAuthenticatedKey({
    publicKeys,
    envelopeBytes: signedEnvelope,
    envelopeSignature: envelopeSig,
    legacyCiphertext,
    legacySignature: legacySig,
  });
  if (!sigValid) {
    throw new StateVerificationError(
      "signature_mismatch",
      `Signature verification failed for state envelope ${namespace}/${key}`
    );
  }

  return { verified: true };
}

/** Parse step of the enforcing read; must match readInternal in cognitive/state-store.ts. */
export function parseStateEntry(raw: Uint8Array, namespace: string, key: string): StateEntry {
  try {
    return JSON.parse(bytesToString(raw));
  } catch {
    throw new StateVerificationError(
      "schema_mismatch",
      `Corrupted state entry: ${namespace}/${key}`
    );
  }
}

/** Decrypt and integrity steps of the enforcing read; must match readInternal in cognitive/state-store.ts. */
export function decryptStateEntryPayload(
  entry: StateEntry,
  namespaceKey: Uint8Array,
  namespace: string,
  key: string
): { plaintext: Uint8Array; value: string } {
  const plaintext = decrypt(entry.payload, namespaceKey);
  const value = bytesToString(plaintext);

  // The hash is recomputed from the decrypted bytes; the stored hash is only compared, never trusted.
  const computedHash = hashToString(plaintext);
  if (computedHash !== entry.integrity_hash) {
    throw new StateVerificationError(
      "integrity_hash_mismatch",
      `Integrity hash mismatch for ${namespace}/${key}: computed ${computedHash}, stored ${describeUntrusted(entry.integrity_hash)}`
    );
  }
  return { plaintext, value };
}

export interface OpenedStateEntry {
  entry: StateEntry;
  value: string;
  warnings?: LegacyEnvelopeWarningInfo[];
}

/**
 * Open one stored state entry: parse, verify its signatures against the
 * writer keys `resolveWriterKeys` vouches for, decrypt, and check the
 * integrity hash. A signature that cannot be attributed to an authenticated
 * writer key refuses, exactly as the state store's enforcing read refuses.
 */
export async function openStateEntry(
  raw: Uint8Array,
  options: {
    namespace: string;
    key: string;
    namespaceKey: Uint8Array;
    /** Authenticated writer public keys for a kid; must match resolveWriterPublicKeys in cognitive/state-store.ts. */
    resolveWriterKeys: (kid: string) => Promise<readonly Uint8Array[]>;
  }
): Promise<OpenedStateEntry> {
  const entry = parseStateEntry(raw, options.namespace, options.key);
  const publicKeys = await options.resolveWriterKeys(entry.kid);
  const verification = verifyStateEntrySignatureWithKeys(entry, options.namespace, options.key, publicKeys);
  // Must match the writer_unverified refusal in readInternal in cognitive/state-store.ts:
  // a value is returned only when signature verification succeeded.
  if (!verification.verified) {
    throw new StateVerificationError(
      "writer_unverified",
      `Writer could not be established for ${options.namespace}/${options.key}: the enforcing read path returns a value only when signature verification succeeds`
    );
  }
  const { plaintext, value } = decryptStateEntryPayload(entry, options.namespaceKey, options.namespace, options.key);
  plaintext.fill(0);
  return { entry, value, ...(verification.warnings ? { warnings: verification.warnings } : {}) };
}
