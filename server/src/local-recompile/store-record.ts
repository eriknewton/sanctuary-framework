/**
 * Shared record format, lock entry and refusals for the two local stores.
 *
 * Every stored record is `JSON.stringify(EncryptedPayload)` (AES-256-GCM) under
 * the store's purpose key, with the record key as additional authenticated
 * data. GCM authentication is the record MAC: a head, anchor or index record
 * is authenticated exactly like a row, and master rotation re-encrypts all of
 * them with the same recipe.
 */
import { decrypt, encrypt, type EncryptedPayload } from "../core/encryption.js";
import {
  CrossProcessLockError,
  kernelBackedCrossProcessLockPlatformSupported,
  type CrossProcessLockLease,
} from "../storage/cross-process-lock.js";
import { AGENT_DISCOVERY_SKIPPED_NAMESPACES } from "../storage/agent-discovery.js";
import type { StorageBackend, StrictDurabilityStorageCapabilities } from "../storage/interface.js";
import { canonicalLocalJson, parseLocalJson } from "./canonical.js";

// Must match AGENT_DISCOVERY_SKIPPED_NAMESPACES in storage/agent-discovery.ts:
// the stores live only under names agent discovery skips and the tool ban covers.
export const [LOCAL_RESULTS_NAMESPACE, LOCAL_DISCLOSURE_NAMESPACE, LOCAL_OPLOG_NAMESPACE] =
  AGENT_DISCOVERY_SKIPPED_NAMESPACES;

export const KIB = 1024; // 2^10 bytes
export const MIB = KIB * KIB;
export const SECOND_MS = 1_000;
export const MINUTE_MS = 60 * SECOND_MS;
export const HOUR_MS = 60 * MINUTE_MS;
export const DAY_MS = 24 * HOUR_MS;

// AES-256 takes a 256-bit key: 256 / 8 bytes.
export const LOCAL_STORE_KEY_BYTES = 256 / 8;
// The GCM tag @noble/ciphers appends to every ciphertext: 128 bits.
const GCM_TAG_BYTES = 128 / 8;
// The fixed envelope around `ct` is about 90 bytes (five keys, `"v":1`, the
// algorithm name, a 16-character IV and a 24-character ISO timestamp); 128
// covers it with room for a six-digit year.
const SEALED_ENVELOPE_ALLOWANCE_BYTES = 128;

/** Upper bound of a sealed record whose canonical plaintext is at most `plaintextBytes`. */
export function sealedRecordMaxBytes(plaintextBytes: number): number {
  // Unpadded base64url carries 3 bytes in 4 characters.
  return SEALED_ENVELOPE_ALLOWANCE_BYTES + Math.ceil(((plaintextBytes + GCM_TAG_BYTES) * 4) / 3);
}

export const LOCAL_STORE_FAILURES = [
  "capability",
  "lock",
  "invalid_record",
  "authentication",
  "capacity",
  "exists",
  "not_found",
  "conflict",
  "closed",
  "io",
] as const;
export type LocalStoreFailure = (typeof LOCAL_STORE_FAILURES)[number];

/** A refusal that carries only a closed kind: never a path, key byte or record text. */
export class LocalStoreError extends Error {
  readonly kind: LocalStoreFailure;
  constructor(kind: LocalStoreFailure) {
    super(`local store refused: ${kind}`);
    this.name = "LocalStoreError";
    this.kind = kind;
  }
}

/** The storage capabilities both stores require; anything less refuses. */
export type LocalStoreBackend = StorageBackend &
  Required<Pick<StorageBackend, "readBounded">> &
  Pick<StrictDurabilityStorageCapabilities, "withStrictNamespaceLock" | "writeStrict" | "writeIfAbsentStrict">;

export function assertLocalStoreBackend(storage: LocalStoreBackend): void {
  const candidate = storage as Partial<LocalStoreBackend> | null | undefined;
  // A backend without exclusive strict writes or the kernel-backed lock cannot
  // keep the chain linear, so it refuses rather than writing without them.
  if (
    typeof candidate?.withStrictNamespaceLock !== "function" ||
    typeof candidate.writeStrict !== "function" ||
    typeof candidate.writeIfAbsentStrict !== "function" ||
    typeof candidate.readBounded !== "function" ||
    typeof candidate.delete !== "function"
  ) {
    throw new LocalStoreError("capability");
  }
}

export interface LocalStoreLockOptions {
  /** Bounded acquire wait; defaults to CROSS_PROCESS_LOCK_TIMEOUT_MS in storage/cross-process-lock.ts. */
  timeoutMs?: number;
  /** Lock rendezvous directory; defaults to the storage backend's runtime root. */
  runtimeRoot?: string;
}

/**
 * Run `operation` under the store's kernel-backed strict namespace lock. This
 * is the required cross-process lock with `kernelBacked: true`, entered
 * through the strict door because only that binding admits the exclusive
 * strict writes the stores publish rows with.
 */
export async function withLocalStoreLock<T>(
  storage: LocalStoreBackend,
  namespace: string,
  lockFileName: string,
  operation: (lease: CrossProcessLockLease) => Promise<T>,
  options: LocalStoreLockOptions = {},
): Promise<T> {
  assertLocalStoreBackend(storage);
  // Without the kernel lock a crashed holder could not be told from a live
  // one, so unsupported platforms refuse before any store mutation.
  if (!kernelBackedCrossProcessLockPlatformSupported(process.platform)) {
    throw new LocalStoreError("capability");
  }
  try {
    return await storage.withStrictNamespaceLock(namespace, lockFileName, operation, {
      kernelBacked: true,
      ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
      ...(options.runtimeRoot === undefined ? {} : { runtimeRoot: options.runtimeRoot }),
    });
  } catch (error) {
    throw toLocalStoreError(error);
  }
}

/** Storage diagnostics can carry paths, so only a closed kind crosses this boundary. */
export function toLocalStoreError(error: unknown): LocalStoreError {
  if (error instanceof LocalStoreError) return error;
  if (error instanceof CrossProcessLockError) return new LocalStoreError("lock");
  return new LocalStoreError("io");
}

/** Copy a required 32-byte store key so a caller zeroing its buffer cannot change a live store. */
export function copyStoreKey(key: Uint8Array): Uint8Array {
  if (!(key instanceof Uint8Array) || key.length !== LOCAL_STORE_KEY_BYTES) {
    throw new LocalStoreError("capability");
  }
  return Uint8Array.from(key);
}

const encoder = new TextEncoder();
const strictDecoder = new TextDecoder("utf-8", { fatal: true });

/** Canonical UTF-8 bytes of `value`, refused when longer than `maxBytes`. */
export function canonicalBytes(value: unknown, maxBytes: number): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = encoder.encode(canonicalLocalJson(value));
  } catch {
    throw new LocalStoreError("invalid_record");
  }
  if (bytes.length > maxBytes) throw new LocalStoreError("capacity");
  return bytes;
}

export interface RecordBounds {
  /** Largest canonical plaintext accepted for this record. */
  plaintextMaxBytes: number;
  /** Largest sealed record accepted on write and read. */
  sealedMaxBytes: number;
}

/** Seal one record; the record key is the AAD, so a record moved to another key fails authentication. */
export function sealRecord(value: unknown, storeKey: Uint8Array, recordKey: string, bounds: RecordBounds): Uint8Array {
  const plaintext = canonicalBytes(value, bounds.plaintextMaxBytes);
  try {
    const sealed = encoder.encode(JSON.stringify(encrypt(plaintext, storeKey, encoder.encode(recordKey))));
    if (sealed.length > bounds.sealedMaxBytes) throw new LocalStoreError("capacity");
    return sealed;
  } finally {
    plaintext.fill(0);
  }
}

/** Open one sealed record; any parse, shape or tag failure is an authentication refusal. */
export function openRecord(sealed: Uint8Array, storeKey: Uint8Array, recordKey: string, bounds: RecordBounds): unknown {
  if (sealed.length > bounds.sealedMaxBytes) throw new LocalStoreError("capacity");
  let plaintext: Uint8Array | undefined;
  try {
    const envelope = parseLocalJson(strictDecoder.decode(sealed));
    if (!isEnvelope(envelope)) throw new LocalStoreError("authentication");
    plaintext = decrypt(envelope, storeKey, encoder.encode(recordKey));
  } catch {
    throw new LocalStoreError("authentication");
  }
  try {
    if (plaintext.length > bounds.plaintextMaxBytes) throw new LocalStoreError("capacity");
    return parseLocalJson(strictDecoder.decode(plaintext));
  } catch (error) {
    if (error instanceof LocalStoreError) throw error;
    throw new LocalStoreError("invalid_record");
  } finally {
    plaintext.fill(0);
  }
}

function isEnvelope(value: unknown): value is EncryptedPayload {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record.v === "number" &&
    typeof record.alg === "string" &&
    typeof record.iv === "string" &&
    typeof record.ct === "string" &&
    typeof record.ts === "string"
  );
}

export interface StoredRecord {
  value: unknown;
  sealed: Uint8Array;
}

/** Bounded read and open of one record; null when absent. */
export async function readRecord(
  storage: LocalStoreBackend,
  namespace: string,
  recordKey: string,
  storeKey: Uint8Array,
  bounds: RecordBounds,
): Promise<StoredRecord | null> {
  let sealed: Uint8Array | null;
  try {
    sealed = await storage.readBounded(namespace, recordKey, bounds.sealedMaxBytes);
  } catch (error) {
    throw toLocalStoreError(error);
  }
  if (sealed === null) return null;
  return { value: openRecord(sealed, storeKey, recordKey, bounds), sealed };
}

// ── Closed-schema helpers ───────────────────────────────────────────

export function asPlainRecord(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new LocalStoreError("invalid_record");
  }
  return value as Record<string, unknown>;
}

/** Refuse any record whose key set is not exactly `fields`. */
export function requireExactFields(value: Record<string, unknown>, fields: readonly string[]): void {
  const keys = Object.keys(value);
  if (keys.length !== fields.length || keys.some((key) => !fields.includes(key))) {
    throw new LocalStoreError("invalid_record");
  }
}

export function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

export function isLowerHex(value: unknown, length: number): value is string {
  return typeof value === "string" && value.length === length && /^[0-9a-f]+$/.test(value);
}

// A request id carries 128 random bits as 32 lowercase hex digits.
export const REQUEST_ID_HEX_LENGTH = 128 / 4;
// A seat is named by its identity id: the first 128 bits of SHA-256(public key)
// as hex; must match generateIdentityId in core/identity.ts.
export const SEAT_ID_HEX_LENGTH = 128 / 4;

export function isRequestId(value: unknown): value is string {
  return isLowerHex(value, REQUEST_ID_HEX_LENGTH);
}
