/**
 * Sanctuary MCP Server — L2 Operational Isolation: Audit Log
 *
 * Append-only log of all sovereignty-relevant operations.
 * Stored encrypted under L1 sovereignty.
 *
 * Every tool invocation that modifies state, generates proofs,
 * or records reputation produces an audit entry. The human principal
 * can inspect what their agent has done.
 */

import type { StorageBackend } from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";

export interface AuditEntry {
  timestamp: string;
  layer: "l1" | "l2" | "l3" | "l4";
  operation: string;
  identity_id: string;
  result: "success" | "failure";
  details?: Record<string, unknown>;
}

export class AuditLog {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;
  private entries: AuditEntry[] = [];
  private counter = 0;

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "audit-log");
  }

  /**
   * Append an audit entry.
   */
  append(
    layer: AuditEntry["layer"],
    operation: string,
    identityId: string,
    details?: Record<string, unknown>,
    result: "success" | "failure" = "success"
  ): void {
    const entry: AuditEntry = {
      timestamp: new Date().toISOString(),
      layer,
      operation,
      identity_id: identityId,
      result,
      details,
    };

    this.entries.push(entry);

    // Async persist (fire-and-forget for performance; entries are also in memory)
    this.persistEntry(entry).catch(() => {
      // Persistence failure is logged but doesn't block the operation
    });
  }

  private async persistEntry(entry: AuditEntry): Promise<void> {
    const key = `${Date.now()}-${this.counter++}`;
    const serialized = stringToBytes(JSON.stringify(entry));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      "_audit",
      key,
      stringToBytes(JSON.stringify(encrypted))
    );
  }

  /**
   * Query the audit log with filtering.
   */
  async query(options: {
    since?: string;
    layer?: AuditEntry["layer"];
    operation_type?: string;
    limit?: number;
  }): Promise<{ entries: AuditEntry[]; total: number }> {
    // First, try to load persisted entries we don't have in memory
    await this.loadPersistedEntries();

    let filtered = this.entries;

    if (options.since) {
      const sinceDate = new Date(options.since);
      filtered = filtered.filter(
        (e) => new Date(e.timestamp) >= sinceDate
      );
    }
    if (options.layer) {
      filtered = filtered.filter((e) => e.layer === options.layer);
    }
    if (options.operation_type) {
      filtered = filtered.filter(
        (e) => e.operation === options.operation_type
      );
    }

    const total = filtered.length;
    const limit = options.limit ?? 50;
    const entries = filtered.slice(-limit); // Most recent entries

    return { entries, total };
  }

  private async loadPersistedEntries(): Promise<void> {
    try {
      const storedEntries = await this.storage.list("_audit");
      for (const meta of storedEntries) {
        const raw = await this.storage.read("_audit", meta.key);
        if (!raw) continue;
        try {
          const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
          const decrypted = decrypt(encrypted, this.encryptionKey);
          const entry: AuditEntry = JSON.parse(bytesToString(decrypted));

          // Deduplicate (check if we already have this timestamp+operation)
          const isDuplicate = this.entries.some(
            (e) =>
              e.timestamp === entry.timestamp &&
              e.operation === entry.operation &&
              e.identity_id === entry.identity_id
          );
          if (!isDuplicate) {
            this.entries.push(entry);
          }
        } catch {
          // Skip corrupted entries
        }
      }

      // Sort by timestamp
      this.entries.sort(
        (a, b) =>
          new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
      );
    } catch {
      // Storage not available yet — that's fine
    }
  }

  /**
   * Get total number of entries.
   */
  get size(): number {
    return this.entries.length;
  }
}
