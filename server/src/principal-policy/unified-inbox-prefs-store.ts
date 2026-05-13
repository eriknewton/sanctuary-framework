import { createHash } from "node:crypto";

import { bytesToString, stringToBytes } from "../core/encoding.js";
import {
  decrypt,
  encrypt,
  type EncryptedPayload,
} from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import type { StorageBackend } from "../storage/interface.js";

export const UNIFIED_INBOX_PREFS_NAMESPACE = "_unified_inbox";
export const UNIFIED_INBOX_PREFS_KEY_PREFIX = "operator-prefs.v1.";

const HKDF_INFO = "principal-policy-unified-inbox-operator-prefs-v1";
const MAX_PREFS_BYTES = 64 * 1024;
const DEFAULT_INBOX_FILTER_PREFS: InboxFilterPrefs = {
  search: "",
  source: "",
  severity: "",
  agent: "",
  from: "",
  to: "",
};

export interface InboxFilterPrefs {
  search: string;
  source: string;
  severity: string;
  agent: string;
  from: string;
  to: string;
}

interface PersistedPrefsEnvelope {
  version: 1;
  fortress_id: string;
  operator_id: string;
  surface_id: "dashboard:v1_1:unified-inbox";
  filters: InboxFilterPrefs;
}

export class UnifiedInboxPrefsStore {
  private readonly encryptionKey: Uint8Array;

  constructor(
    private readonly opts: {
      storage: StorageBackend;
      masterKey: Uint8Array;
      fortressId: string;
      operatorId: string;
    },
  ) {
    this.encryptionKey = derivePurposeKey(opts.masterKey, HKDF_INFO);
  }

  async load(): Promise<InboxFilterPrefs> {
    const raw = await this.opts.storage.read(
      UNIFIED_INBOX_PREFS_NAMESPACE,
      this.storageKey(),
    );
    if (!raw || raw.length > MAX_PREFS_BYTES) return defaultPrefs();
    try {
      const encrypted = JSON.parse(bytesToString(raw)) as EncryptedPayload;
      const plaintext = decrypt(encrypted, this.encryptionKey, this.aad());
      const persisted = JSON.parse(
        bytesToString(plaintext),
      ) as PersistedPrefsEnvelope;
      if (persisted.version !== 1) return defaultPrefs();
      if (persisted.fortress_id !== this.opts.fortressId) return defaultPrefs();
      if (persisted.operator_id !== this.opts.operatorId) return defaultPrefs();
      if (persisted.surface_id !== "dashboard:v1_1:unified-inbox") {
        return defaultPrefs();
      }
      return normalizePrefs(persisted.filters);
    } catch {
      return defaultPrefs();
    }
  }

  async save(filters: Partial<InboxFilterPrefs>): Promise<InboxFilterPrefs> {
    const normalized = normalizePrefs(filters);
    const persisted: PersistedPrefsEnvelope = {
      version: 1,
      fortress_id: this.opts.fortressId,
      operator_id: this.opts.operatorId,
      surface_id: "dashboard:v1_1:unified-inbox",
      filters: normalized,
    };
    const encrypted = encrypt(
      stringToBytes(JSON.stringify(persisted)),
      this.encryptionKey,
      this.aad(),
    );
    await this.opts.storage.write(
      UNIFIED_INBOX_PREFS_NAMESPACE,
      this.storageKey(),
      stringToBytes(JSON.stringify(encrypted)),
    );
    return normalized;
  }

  private aad(): Uint8Array {
    return stringToBytes(
      `${this.opts.fortressId}|${this.opts.operatorId}|dashboard:v1_1:unified-inbox`,
    );
  }

  private storageKey(): string {
    const operatorHash = createHash("sha256")
      .update(this.opts.operatorId)
      .digest("hex")
      .slice(0, 32);
    return `${UNIFIED_INBOX_PREFS_KEY_PREFIX}${operatorHash}`;
  }
}

export function normalizePrefs(filters: Partial<InboxFilterPrefs>): InboxFilterPrefs {
  return {
    search: stringValue(filters.search),
    source: stringValue(filters.source),
    severity: stringValue(filters.severity),
    agent: stringValue(filters.agent),
    from: stringValue(filters.from),
    to: stringValue(filters.to),
  };
}

function defaultPrefs(): InboxFilterPrefs {
  return { ...DEFAULT_INBOX_FILTER_PREFS };
}

function stringValue(value: unknown): string {
  return typeof value === "string" ? value.slice(0, 256) : "";
}
