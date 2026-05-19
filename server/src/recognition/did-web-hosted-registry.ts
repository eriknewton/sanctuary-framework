/**
 * Sanctuary WP-V1.x-RECOGNITION-LAYER Path C hosted-alternative registry.
 *
 * Encrypted-at-rest store mapping operator handles to their DID Documents.
 * Operators without their own domain register here so Sanctuary can serve
 * their did:web document from `identity.sanctuaryprotocol.ai/<handle>`.
 *
 * Storage layout:
 *   namespace: `_recognition_hosted_did_web`
 *   key:       the operator handle (lowercase, validated)
 *   payload:   AES-256-GCM ciphertext of the JSON-serialized entry.
 *   HKDF info: `l2-recognition-hosted-did-web-v1`
 *   AAD:       UTF-8 bytes of the fortress id.
 *
 * Mirrors the PiiConfigStore + ThresholdConfigStore encryption pattern.
 */

import type { StorageBackend } from "../storage/interface.js";
import {
  encrypt,
  decrypt,
  type EncryptedPayload,
} from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";
import type { DidDocument } from "./did-web.js";

export const HOSTED_DID_WEB_NAMESPACE = "_recognition_hosted_did_web";
const HKDF_INFO = "l2-recognition-hosted-did-web-v1";
const MAX_PAYLOAD_BYTES = 64 * 1024;

/** Operator handle: lowercase alphanumeric + hyphens, 1-64 chars. */
const HANDLE_RE = /^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$/;

export interface HostedDidWebEntry {
  operator_handle: string;
  did_document: DidDocument;
  published_at: string;
}

interface PersistedEntry {
  version: 1;
  fortress_id: string;
  saved_at: string;
  entry: HostedDidWebEntry;
}

export interface DidWebHostedRegistryOptions {
  storage: StorageBackend;
  masterKey: Uint8Array;
  fortressId: string;
  now?: () => Date;
}

export function validateHandle(handle: string): string | null {
  if (!handle || !HANDLE_RE.test(handle)) {
    return "handle must be 1-64 lowercase alphanumeric characters or hyphens, must start and end with alphanumeric";
  }
  return null;
}

export class DidWebHostedRegistry {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Uint8Array;
  private readonly fortressId: string;
  private readonly now: () => Date;

  constructor(opts: DidWebHostedRegistryOptions) {
    this.storage = opts.storage;
    this.encryptionKey = derivePurposeKey(opts.masterKey, HKDF_INFO);
    this.fortressId = opts.fortressId;
    this.now = opts.now ?? (() => new Date());
  }

  async get(handle: string): Promise<HostedDidWebEntry | null> {
    const err = validateHandle(handle);
    if (err) return null;
    let raw: Uint8Array | null;
    try {
      raw = await this.storage.read(HOSTED_DID_WEB_NAMESPACE, handle);
    } catch {
      return null;
    }
    if (!raw) return null;
    if (raw.length > MAX_PAYLOAD_BYTES) return null;
    try {
      const aad = stringToBytes(this.fortressId);
      const envelope: EncryptedPayload = JSON.parse(bytesToString(raw));
      const plaintext = decrypt(envelope, this.encryptionKey, aad);
      const persisted = JSON.parse(bytesToString(plaintext)) as PersistedEntry;
      if (persisted.version !== 1) return null;
      if (persisted.fortress_id !== this.fortressId) return null;
      return persisted.entry;
    } catch {
      return null;
    }
  }

  async set(handle: string, didDocument: DidDocument): Promise<HostedDidWebEntry> {
    const err = validateHandle(handle);
    if (err) throw new Error(`did-web-hosted: ${err}`);
    const entry: HostedDidWebEntry = {
      operator_handle: handle,
      did_document: didDocument,
      published_at: this.now().toISOString(),
    };
    const persisted: PersistedEntry = {
      version: 1,
      fortress_id: this.fortressId,
      saved_at: this.now().toISOString(),
      entry,
    };
    const aad = stringToBytes(this.fortressId);
    const plaintext = stringToBytes(JSON.stringify(persisted));
    const envelope = encrypt(plaintext, this.encryptionKey, aad);
    await this.storage.write(
      HOSTED_DID_WEB_NAMESPACE,
      handle,
      stringToBytes(JSON.stringify(envelope)),
    );
    return entry;
  }
}
