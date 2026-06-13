/**
 * HABEAS PORT — operator-readable distress inbox.
 *
 * Persistent, encrypted-at-rest store of distress envelopes the local
 * listener received on 127.0.0.1:8741. Follows the existing encrypted-state
 * pattern (BaselineTracker): a purpose-derived key off the fortress master,
 * stored under a reserved `_distress` namespace the agent cannot address
 * through any MCP surface.
 *
 * Bounded by design: a rolling ring capped at DISTRESS_INBOX_MAX entries.
 * Oldest entries drop first so a flood of (already rate-limited, already
 * audited) distress signals cannot grow the inbox without bound. The audit
 * log remains the complete, append-only record; the inbox is the
 * operator-facing convenience surface, not the system of record.
 *
 * Read-only to the dashboard: the dashboard route lists entries through
 * `list()`; nothing in the HTTP surface writes or deletes. Writes happen only
 * from the listener's verified-delivery path.
 */

import type { StorageBackend } from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";
import type { DistressEnvelope } from "./tools.js";

/** Reserved namespace; not addressable through the agent's MCP state surface. */
export const DISTRESS_INBOX_NAMESPACE = "_distress";
export const DISTRESS_INBOX_KEY = "inbox";

/** Hard cap on retained inbox entries (rolling ring). */
export const DISTRESS_INBOX_MAX = 200;

/** One received-and-stored distress record. */
export interface DistressInboxEntry {
  /** The bounded envelope exactly as received (closed shape). */
  envelope: DistressEnvelope;
  /** SHA-256 of the canonical envelope (as the emitter computed it). */
  envelope_hash: string;
  /** When the LISTENER accepted it (distinct from envelope.emitted_at). */
  received_at: string;
  /** Whether the emitter's HMAC over the frame verified (always true once
   * stored — unverified frames are rejected before they reach the inbox; kept
   * explicit for the operator surface). */
  authenticated: true;
}

interface PersistedInbox {
  entries: DistressInboxEntry[];
}

export class DistressInbox {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;
  private entries: DistressInboxEntry[] = [];
  private loaded = false;

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "distress-inbox");
  }

  /** Load persisted entries. A missing/corrupt store is treated as empty —
   * the inbox is a convenience surface, never the audit system of record, so
   * a read failure must not crash the dashboard boot. */
  async load(): Promise<void> {
    if (this.loaded) return;
    try {
      const raw = await this.storage.read(
        DISTRESS_INBOX_NAMESPACE,
        DISTRESS_INBOX_KEY,
      );
      if (raw) {
        const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
        const decrypted = decrypt(encrypted, this.encryptionKey);
        const parsed = JSON.parse(bytesToString(decrypted)) as PersistedInbox;
        if (Array.isArray(parsed.entries)) {
          this.entries = parsed.entries.slice(-DISTRESS_INBOX_MAX);
        }
      }
    } catch {
      this.entries = [];
    }
    this.loaded = true;
  }

  /** Append a received envelope and persist. The ring is trimmed to the cap. */
  async append(entry: DistressInboxEntry): Promise<void> {
    await this.load();
    this.entries.push(entry);
    if (this.entries.length > DISTRESS_INBOX_MAX) {
      this.entries = this.entries.slice(-DISTRESS_INBOX_MAX);
    }
    const serialized = stringToBytes(
      JSON.stringify({ entries: this.entries } satisfies PersistedInbox),
    );
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      DISTRESS_INBOX_NAMESPACE,
      DISTRESS_INBOX_KEY,
      stringToBytes(JSON.stringify(encrypted)),
    );
  }

  /**
   * Newest-first list of entries, capped by `limit`. Returns a structural
   * copy so callers cannot mutate the in-memory ring.
   */
  async list(limit = DISTRESS_INBOX_MAX): Promise<DistressInboxEntry[]> {
    await this.load();
    const bounded = Math.max(0, Math.min(limit, DISTRESS_INBOX_MAX));
    return this.entries
      .slice(-bounded)
      .reverse()
      .map((e) => ({ ...e, envelope: { ...e.envelope } }));
  }

  /** Count of retained entries. */
  async count(): Promise<number> {
    await this.load();
    return this.entries.length;
  }
}
