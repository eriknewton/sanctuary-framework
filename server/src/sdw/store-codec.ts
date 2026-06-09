import { decrypt, type EncryptedPayload } from "../core/encryption.js";
import { bytesToString } from "../core/encoding.js";
import { sdwAad } from "./grammar.js";
import type { SdwNamespace, SdwRecord } from "./records.js";
import { SdwValidationError, UnsupportedRecordVersion } from "./errors.js";

export function decodeSdwRecord<T extends SdwRecord>(
  raw: Uint8Array,
  options: {
    readonly namespace: SdwNamespace;
    readonly storageKey: string;
    readonly fortressId: string;
    readonly encryptionKey: Uint8Array;
    readonly expectedKind: T["kind"];
    readonly verifyIdentity: (record: T) => boolean;
  },
): T {
  try {
    const aad = sdwAad(options.fortressId, options.namespace, options.storageKey);
    const envelope = JSON.parse(bytesToString(raw)) as EncryptedPayload;
    const plaintext = decrypt(envelope, options.encryptionKey, aad);
    const record = JSON.parse(bytesToString(plaintext)) as T & { readonly version: number };
    if (record.version !== 1) {
      throw new UnsupportedRecordVersion(options.namespace, options.storageKey, record.version);
    }
    if (record.kind !== options.expectedKind || !options.verifyIdentity(record)) {
      throw new SdwValidationError("identity_mismatch", "SDW record identity mismatch");
    }
    return record;
  } catch (error) {
    if (error instanceof UnsupportedRecordVersion || error instanceof SdwValidationError) {
      throw error;
    }
    throw new SdwValidationError("auth_failed", "SDW record authentication failed");
  }
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((item) => canonicalize(item));
  const object = value as { readonly [key: string]: unknown };
  const out: { [key: string]: unknown } = {};
  for (const key of Object.keys(object).sort()) {
    const item = object[key];
    if (item !== undefined) out[key] = canonicalize(item);
  }
  return out;
}
