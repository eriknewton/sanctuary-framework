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

import type { StorageBackend, StorageEntryMeta } from "../storage/interface.js";
import {
  encrypt,
  decrypt,
  type EncryptedPayload,
} from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";
import type { AuditLog } from "../operational/audit-log.js";
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

/**
 * CLASS-LEVEL bounded-listing guard (register Z-HNY-02): `listFindings` used
 * to decrypt EVERY record in the namespace before applying any filter or the
 * `limit`, so an attacker who drives finding COUNT up (honeypot invocations,
 * pre-coalescing) turned every read into an O(all-records)-decrypt scan.
 * Storage metadata already carries `modified_at`, which for this store is
 * always the write-time of the record it describes (writes are append-once
 * per finding_id in the normal case; a re-saved finding_id only happens via
 * the honeypot coalescing update path, which still bumps modified_at to the
 * latest observation — so "newest write" tracks "most recently relevant"
 * closely enough to order the scan by). Sorting metas by `modified_at`
 * descending and decrypting only the newest MAX_SCANNED_RECORDS bounds
 * decrypt work to a constant regardless of how large the store has grown,
 * without touching the `finding.{finding_id}` at-rest key format (checked
 * against reorg-surface-manifest.md: that format is not listed as frozen,
 * but reusing storage metadata the backend already maintains is simpler and
 * lower-risk than minting a parallel index record).
 *
 * 500 = 5x the default result `limit` (100): generous slack so a caller
 * asking for the newest 100 findings still gets them even when up to 80% of
 * the freshest 500 records are filtered out by severity/sentinel/agent,
 * without decrypting the whole store to find out.
 */
const MAX_SCANNED_RECORDS = 500;

/**
 * CLASS-LEVEL guard: `pruneExpired()` fires once per fortress-unlock (see
 * dashboard/v1_1/wiring.ts, index.ts) and previously decrypted every record
 * in the namespace to check `retention_until`. Bounding a single call's scan
 * keeps one unlock cycle from blocking on an unboundedly large store; sorted
 * oldest-modified-first so a capped pass still reclaims the records most
 * likely to be past retention. A store larger than this cap simply keeps
 * shrinking across successive unlocks rather than all at once.
 *
 * 2000 = large enough that a normally-sized fortress prunes its whole
 * expired set in one pass, small enough to bound one unlock cycle's decrypt
 * work to a constant under an active flood.
 */
const PRUNE_SCAN_CAP = 2000;

/**
 * CLASS-LEVEL hard ceiling (register Z-HNY-02, AGENTS.md rule 8 step 4):
 * once the tracked record count reaches this, `saveFinding` will not persist
 * past it by blindly evicting the oldest record — see `evictOldestExpired`.
 * 5000 = comfortably above what the honeypot write-site coalescing (see
 * tool-call-trap-runtime.ts) and normal sentinel activity produce for a real
 * fortress, while still reachable in an adversarial test.
 */
const MAX_TRACKED_FINDINGS = 5000;

/**
 * Bounds the decrypt work `evictOldestExpired` spends per saturated write:
 * only the oldest SATURATION_EVICT_SCAN_CAP records (by modified_at) are
 * inspected for an already-expired one to reclaim. 50 = enough to find a
 * genuinely expired record in a store where expiry is roughly FIFO by
 * write time, without turning every write near the ceiling into another
 * O(all-records) scan.
 */
const SATURATION_EVICT_SCAN_CAP = 50;

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
  /**
   * Optional: when supplied, a write that hits MAX_TRACKED_FINDINGS with no
   * reclaimable (expired) record audits `finding_store_saturated` at l2.
   * Not required — the protective behavior itself (never blind-evicting a
   * live record to make room) is unconditional and does not depend on this
   * being wired; omitting it only loses the observability signal, never the
   * guard (AGENTS.md rule 3 distinguishes a dependency that GATES a security
   * property, which must be required, from one that only reports on it).
   */
  auditLog?: AuditLog;
  /**
   * Test-only overrides for the bounded-work constants (MAX_TRACKED_FINDINGS,
   * MAX_SCANNED_RECORDS, PRUNE_SCAN_CAP). Production call sites never set
   * these; they exist so the class-level bounded-collection inventory test
   * (test/security/attacker-writable-collections-bounds.test.ts) can drive
   * the REAL production write/list/prune path to its cap in a handful of
   * iterations instead of thousands, without weakening the shipped defaults.
   */
  maxTrackedFindings?: number;
  maxScannedRecords?: number;
  pruneScanCap?: number;
}

export class SentinelFindingStore {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Uint8Array;
  private readonly fortressId: string;
  private readonly retentionDays: number;
  private readonly now: () => Date;
  private readonly auditLog: AuditLog | undefined;
  private readonly maxTrackedFindings: number;
  private readonly maxScannedRecords: number;
  private readonly pruneScanCap: number;

  constructor(opts: SentinelFindingStoreOptions) {
    this.storage = opts.storage;
    this.encryptionKey = derivePurposeKey(opts.masterKey, HKDF_INFO);
    this.fortressId = opts.fortressId;
    this.retentionDays =
      opts.retentionDays !== undefined && opts.retentionDays > 0
        ? opts.retentionDays
        : DEFAULT_SENTINEL_FINDING_RETENTION_DAYS;
    this.now = opts.now ?? (() => new Date());
    this.auditLog = opts.auditLog;
    this.maxTrackedFindings = opts.maxTrackedFindings ?? MAX_TRACKED_FINDINGS;
    this.maxScannedRecords = opts.maxScannedRecords ?? MAX_SCANNED_RECORDS;
    this.pruneScanCap = opts.pruneScanCap ?? PRUNE_SCAN_CAP;
  }

  /**
   * Persist a finding. Truncates the operator-visible summary to
   * SENTINEL_SUMMARY_MAX_CHARS so the dashboard render stays bounded.
   * Returns the retention deadline so callers can audit it.
   *
   * `opts.knownExisting`: set ONLY when the caller can prove this
   * `finding_id` already has a persisted record from a PRIOR successful
   * `saveFinding` call in this process (never merely assumed) — e.g. the
   * honeypot coalescing tracker (tool-call-trap-runtime.ts) caches a
   * finding_id in `activeFindingWindows` only after `saveFinding` for it
   * has already succeeded once. When set, this call skips the
   * ceiling/`isNewRecord` metadata listing below, because an update to an
   * existing key can never grow the tracked count — this keeps the
   * coalesced repeat-invocation write path O(1) instead of paying an
   * O(records) metadata listing on every follow-up within the same window.
   * A caller that sets this for a genuinely new key bypasses the ceiling
   * check for that one write; do not set it speculatively.
   */
  async saveFinding(
    finding: SentinelFinding,
    opts?: { knownExisting?: boolean },
  ): Promise<string> {
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
    const key = findingKey(finding.finding_id);
    if (!opts?.knownExisting) {
      await this.enforceTrackedFindingsCeiling(key);
    }
    await this.writeFinding(key, finding.finding_id, persisted);
    return persisted.retention_until;
  }

  /**
   * The bounded-ceiling check factored out of `saveFinding` so the
   * `knownExisting` fast path can skip it entirely. See MAX_TRACKED_FINDINGS.
   */
  private async enforceTrackedFindingsCeiling(key: string): Promise<void> {
    const metas = await this.storage.list(
      SENTINEL_FINDING_NAMESPACE,
      SENTINEL_FINDING_KEY_PREFIX,
    );
    // Only a NEW finding_id grows the tracked count; an update to an
    // existing key (same key, overwritten in place) must never be blocked
    // by the ceiling below.
    const isNewRecord = !metas.some((meta) => meta.key === key);
    if (isNewRecord && metas.length >= this.maxTrackedFindings) {
      const evicted = await this.evictOldestExpired(metas);
      if (!evicted) {
        // Never evict a live (non-expired) record to make room, regardless
        // of severity — this is the AGENTS.md rule 8 invariant ("a
        // pre-existing critical finding MUST survive a flood") satisfied at
        // its strongest: no live record of ANY severity is blind-FIFO'd.
        // The write below still proceeds (a temporary ceiling overshoot),
        // because refusing to record a NEW finding is itself a silent loss
        // of security signal — the honest failure mode here is "grew past
        // the ceiling, loudly," not "dropped an observation."
        void this.auditLog?.append(
          "l2",
          "finding_store_saturated",
          this.fortressId,
          {
            tracked_count: metas.length,
            max_tracked_findings: this.maxTrackedFindings,
          },
          "failure",
        );
      }
    }
  }

  /** Encrypt and write the persisted envelope. Shared tail of saveFinding. */
  private async writeFinding(
    key: string,
    findingId: string,
    persisted: PersistedFinding,
  ): Promise<void> {
    const aad = stringToBytes(findingId);
    const plaintext = stringToBytes(JSON.stringify(persisted));
    const envelope = encrypt(plaintext, this.encryptionKey, aad);
    await this.storage.write(
      SENTINEL_FINDING_NAMESPACE,
      key,
      stringToBytes(JSON.stringify(envelope)),
    );
  }

  /**
   * Scan the oldest SATURATION_EVICT_SCAN_CAP records (by modified_at) for
   * one already past its own retention_until, and delete the first one
   * found. Returns whether a record was reclaimed. Bounded decrypt work —
   * see SATURATION_EVICT_SCAN_CAP's derivation.
   */
  private async evictOldestExpired(metas: StorageEntryMeta[]): Promise<boolean> {
    const cutoff = this.now().toISOString();
    const oldest = [...metas]
      .sort((a, b) => (a.modified_at < b.modified_at ? -1 : 1))
      .slice(0, SATURATION_EVICT_SCAN_CAP);
    for (const meta of oldest) {
      const id = stripKeyPrefix(meta.key);
      if (id === null) continue;
      const raw = await this.storage.read(SENTINEL_FINDING_NAMESPACE, meta.key);
      if (!raw) continue;
      try {
        const aad = stringToBytes(id);
        const envelope: EncryptedPayload = JSON.parse(bytesToString(raw));
        const plaintext = decrypt(envelope, this.encryptionKey, aad);
        const persisted = JSON.parse(bytesToString(plaintext)) as PersistedFinding;
        if (persisted.retention_until <= cutoff) {
          await this.storage.delete(SENTINEL_FINDING_NAMESPACE, meta.key);
          return true;
        }
      } catch {
        // Corrupted record: leave in place; rotation handled by audit log.
      }
    }
    return false;
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
   *
   * BOUNDED (register Z-HNY-02): decrypts at most MAX_SCANNED_RECORDS,
   * newest-by-modified_at first — see that constant's derivation. The final
   * sort/slice still runs over the (bounded) decoded set, so ordering
   * within the scanned window is exactly `observed_at` descending, same as
   * before this fix.
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
    const scanWindow = [...metas]
      .sort((a, b) => (a.modified_at < b.modified_at ? 1 : -1))
      .slice(0, this.maxScannedRecords);
    const findings: SentinelFinding[] = [];
    for (const meta of scanWindow) {
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
   *
   * BOUNDED (register Z-HNY-02): inspects at most PRUNE_SCAN_CAP records per
   * call, oldest-by-modified_at first, so one fortress-unlock cycle's worth
   * of work stays constant regardless of store size — see that constant's
   * derivation.
   */
  async pruneExpired(now?: Date): Promise<{ pruned: number }> {
    const cutoff = (now ?? this.now()).toISOString();
    const metas = await this.storage.list(
      SENTINEL_FINDING_NAMESPACE,
      SENTINEL_FINDING_KEY_PREFIX,
    );
    const scanWindow = [...metas]
      .sort((a, b) => (a.modified_at < b.modified_at ? -1 : 1))
      .slice(0, this.pruneScanCap);
    let pruned = 0;
    for (const meta of scanWindow) {
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
