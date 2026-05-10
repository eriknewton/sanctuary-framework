/**
 * Sanctuary v1.3 WP-V1.3-1 Sentinel Finding Store.
 *
 * Encrypted at-rest persistence for sentinel findings. Sibling to the
 * Upsilon-3 aggregator-store: same fortress-master-key-derived HKDF
 * subkey shape, AAD-bound to the finding_id, retention-aware.
 *
 * Storage layout:
 *   namespace: `_sentinel_findings`
 *   key:       `finding.{finding_id}` (one record per finding)
 *   payload:   AES-256-GCM ciphertext of the JSON-serialized record.
 *   key:       `l2-sentinel-finding-v1` HKDF subkey of fortress master.
 *   AAD:       UTF-8 bytes of `finding_id`.
 *
 * Multi-fortress isolation: HKDF subkey derives from the fortress
 * master key. Two fortresses never produce identical encryption keys
 * for identical finding_ids.
 *
 * Retention: 30 days default, mirroring the audit-log envelope and the
 * aggregator payload store.
 */

import type { StorageBackend } from "../storage/interface.js";
import {
  encrypt,
  decrypt,
  type EncryptedPayload,
} from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";
import {
  SENTINEL_SUMMARY_MAX_CHARS,
  type SentinelFinding,
  type SentinelSeverity,
} from "./types.js";

export const SENTINEL_FINDING_NAMESPACE = "_sentinel_findings";
export const SENTINEL_FINDING_KEY_PREFIX = "finding.";
const HKDF_INFO = "l2-sentinel-finding-v1";

export const DEFAULT_SENTINEL_FINDING_RETENTION_DAYS = 30;

/** Hard upper bound on per-finding decode size. */
const MAX_FINDING_BYTES = 256 * 1024;

interface PersistedFinding {
  /** Bump on schema change. */
  version: 1;
  finding: SentinelFinding;
  retention_until: string;
}

export interface SentinelFindingStoreOptions {
  storage: StorageBackend;
  masterKey: Uint8Array;
  fortressId: string;
  /** Operator-tunable retention window. Default 30 days. */
  retentionDays?: number;
  /** Wall-clock provider for deterministic tests. */
  now?: () => Date;
}

export class SentinelFindingStore {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Uint8Array;
  private readonly fortressId: string;
  private readonly retentionDays: number;
  private readonly now: () => Date;

  constructor(opts: SentinelFindingStoreOptions) {
    this.storage = opts.storage;
    this.encryptionKey = derivePurposeKey(opts.masterKey, HKDF_INFO);
    this.fortressId = opts.fortressId;
    this.retentionDays =
      opts.retentionDays !== undefined && opts.retentionDays > 0
        ? opts.retentionDays
        : DEFAULT_SENTINEL_FINDING_RETENTION_DAYS;
    this.now = opts.now ?? (() => new Date());
  }

  /**
   * Persist a finding. Truncates the operator-visible summary to
   * SENTINEL_SUMMARY_MAX_CHARS so the dashboard render stays bounded.
   * Returns the retention deadline so callers can audit it.
   */
  async saveFinding(finding: SentinelFinding): Promise<string> {
    const truncated: SentinelFinding = {
      ...finding,
      fortress_id: this.fortressId,
      summary: truncateSummary(finding.summary),
    };
    const retentionMs = this.retentionDays * 24 * 60 * 60 * 1000;
    const retentionUntil = new Date(this.now().getTime() + retentionMs);
    const persisted: PersistedFinding = {
      version: 1,
      finding: truncated,
      retention_until: retentionUntil.toISOString(),
    };
    const aad = stringToBytes(finding.finding_id);
    const plaintext = stringToBytes(JSON.stringify(persisted));
    const envelope = encrypt(plaintext, this.encryptionKey, aad);
    await this.storage.write(
      SENTINEL_FINDING_NAMESPACE,
      findingKey(finding.finding_id),
      stringToBytes(JSON.stringify(envelope)),
    );
    return persisted.retention_until;
  }

  /** Load a single finding by id, or null when absent / corrupted. */
  async loadFinding(findingId: string): Promise<SentinelFinding | null> {
    let raw: Uint8Array | null;
    try {
      raw = await this.storage.read(
        SENTINEL_FINDING_NAMESPACE,
        findingKey(findingId),
      );
    } catch {
      return null;
    }
    if (!raw) return null;
    if (raw.length > MAX_FINDING_BYTES) return null;
    return this.decode(findingId, raw);
  }

  /**
   * List findings, newest first. Optional filters: since (ISO 8601),
   * severity, sentinel_id, agent_id, limit. Default limit 100.
   */
  async listFindings(opts?: {
    since?: string;
    severity?: SentinelSeverity;
    sentinelId?: string;
    agentId?: string;
    limit?: number;
  }): Promise<SentinelFinding[]> {
    const metas = await this.storage.list(
      SENTINEL_FINDING_NAMESPACE,
      SENTINEL_FINDING_KEY_PREFIX,
    );
    const findings: SentinelFinding[] = [];
    for (const meta of metas) {
      const id = stripKeyPrefix(meta.key);
      if (id === null) continue;
      const raw = await this.storage.read(
        SENTINEL_FINDING_NAMESPACE,
        meta.key,
      );
      if (!raw) continue;
      if (raw.length > MAX_FINDING_BYTES) continue;
      const finding = await this.decode(id, raw);
      if (!finding) continue;
      if (opts?.since && finding.observed_at < opts.since) continue;
      if (opts?.severity && finding.severity !== opts.severity) continue;
      if (opts?.sentinelId && finding.sentinel_id !== opts.sentinelId) continue;
      if (opts?.agentId && finding.agent_id !== opts.agentId) continue;
      findings.push(finding);
    }
    findings.sort((a, b) => (a.observed_at < b.observed_at ? 1 : -1));
    const limit = opts?.limit ?? 100;
    return findings.slice(0, limit);
  }

  /**
   * Drop expired findings. Returns the count removed.
   */
  async pruneExpired(now?: Date): Promise<{ pruned: number }> {
    const cutoff = (now ?? this.now()).toISOString();
    const metas = await this.storage.list(
      SENTINEL_FINDING_NAMESPACE,
      SENTINEL_FINDING_KEY_PREFIX,
    );
    let pruned = 0;
    for (const meta of metas) {
      const id = stripKeyPrefix(meta.key);
      if (id === null) continue;
      const raw = await this.storage.read(
        SENTINEL_FINDING_NAMESPACE,
        meta.key,
      );
      if (!raw) continue;
      try {
        const aad = stringToBytes(id);
        const envelope: EncryptedPayload = JSON.parse(bytesToString(raw));
        const plaintext = decrypt(envelope, this.encryptionKey, aad);
        const persisted = JSON.parse(
          bytesToString(plaintext),
        ) as PersistedFinding;
        if (persisted.retention_until <= cutoff) {
          await this.storage.delete(SENTINEL_FINDING_NAMESPACE, meta.key);
          pruned += 1;
        }
      } catch {
        // Corrupted record: leave in place; rotation handled by audit log.
      }
    }
    return { pruned };
  }

  private async decode(
    findingId: string,
    raw: Uint8Array,
  ): Promise<SentinelFinding | null> {
    try {
      const aad = stringToBytes(findingId);
      const envelope: EncryptedPayload = JSON.parse(bytesToString(raw));
      const plaintext = decrypt(envelope, this.encryptionKey, aad);
      const persisted = JSON.parse(
        bytesToString(plaintext),
      ) as PersistedFinding;
      if (persisted.version !== 1) return null;
      if (persisted.finding.finding_id !== findingId) return null;
      if (persisted.finding.fortress_id !== this.fortressId) return null;
      return persisted.finding;
    } catch {
      return null;
    }
  }
}

function findingKey(findingId: string): string {
  return `${SENTINEL_FINDING_KEY_PREFIX}${findingId}`;
}

function stripKeyPrefix(key: string): string | null {
  if (!key.startsWith(SENTINEL_FINDING_KEY_PREFIX)) return null;
  return key.slice(SENTINEL_FINDING_KEY_PREFIX.length);
}

function truncateSummary(summary: string): string {
  if (summary.length <= SENTINEL_SUMMARY_MAX_CHARS) return summary;
  return `${summary.slice(0, SENTINEL_SUMMARY_MAX_CHARS - 3)}...`;
}
