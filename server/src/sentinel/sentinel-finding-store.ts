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
 * CLASS-LEVEL bounded-listing guard (register Z-HNY-02 RECHECK):
 * `listFindings` used to sort metas by `modified_at`, SLICE to the newest
 * MAX_SCANNED_RECORDS, and only THEN apply the caller's since/severity/
 * sentinel/agent filters — so a flood of RECENT low-value findings could
 * push an older matching finding out of the scan window before the filter
 * ever ran, hiding it from a `severity: "alert"` or `since: <8 days ago>`
 * query even though it still exists and is still in-window. That second
 * consumer is not hypothetical: sentinels/anomaly-trigger.ts asks for
 * `since: <8 days ago>, limit: 5000` to compute its rolling baseline, and a
 * flood of same-day low-severity findings silently starved it down to
 * whatever fit in the newest 500 — a real, broken security consumer, not
 * just a display truncation.
 *
 * The fix is the in-memory INDEX below (`this.index`): every write updates
 * a small, PLAINTEXT-metadata-only record (severity/sentinel_id/agent_id/
 * observed_at — never the finding's `summary`/`details`, so the index
 * itself never becomes a plaintext oracle over encrypted content) keyed by
 * finding_id, and `listFindings` filters against the index FIRST — an
 * in-memory field compare, no decrypt — before touching storage at all.
 * Only the (already-filtered, already-sorted) top of the match set is
 * decrypted, bounded to the CALLER's own `limit` (capped at
 * MAX_SCANNED_RECORDS so a caller cannot force unbounded decrypt work by
 * passing an enormous limit — see that constant's derivation, pinned to
 * anomaly-trigger's own QUERY_LIMIT so its 8-day baseline is never
 * truncated). A record written by a PRIOR process (before this store
 * instance existed) is covered too: `ensureIndex()` lazily backfills the
 * index from storage on first use — see that method.
 */
const MAX_SCANNED_RECORDS = 5000;
// CROSS-FILE PIN: must be >= sentinel/sentinels/anomaly-trigger.ts's
// QUERY_LIMIT (currently 5000) — anomaly-trigger asks for `limit: 5000` to
// cover its full 8-day baseline window, and MAX_SCANNED_RECORDS is the
// absolute ceiling `listFindings` will ever decrypt for ANY caller's
// `limit`, including that one. If either constant changes, check the other.

/**
 * One entry of the in-memory finding index (see MAX_SCANNED_RECORDS above).
 * Deliberately narrow: only the fields `listFindings`'s filters need,
 * never the finding's `summary`/`details` — the index exists to avoid
 * decrypting records that WON'T match, not to cache plaintext content.
 */
interface FindingIndexEntry {
  severity: SentinelSeverity;
  sentinel_id: string;
  agent_id?: string;
  observed_at: string;
}

/**
 * Bound on the ONE-TIME lazy index backfill (`ensureIndex`, see
 * MAX_SCANNED_RECORDS above) — a cost paid at most once per store instance
 * lifetime (amortized across every subsequent `listFindings`/`saveFinding`
 * call, never repeated per-request), not a per-call bound. 20000 = 4x
 * MAX_TRACKED_FINDINGS's default (5000): generous headroom for that
 * constant's documented soft-ceiling overshoot (a live record is never
 * blind-evicted, so the store can temporarily exceed its own ceiling — see
 * MAX_TRACKED_FINDINGS below) while still bounding the backfill to a
 * constant instead of truly unbounded storage-namespace size.
 */
const MAX_INDEX_BACKFILL_RECORDS = 20_000;

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
  // Filter-before-decrypt index (see MAX_SCANNED_RECORDS's doc). Populated
  // incrementally on every saveFinding, and lazily backfilled ONCE from
  // storage (`ensureIndex`) so records written by a PRIOR process instance
  // are covered too.
  private readonly index = new Map<string, FindingIndexEntry>();
  private indexReady = false;
  private indexBuildPromise: Promise<void> | null = null;

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
   * Lazily build the filter index from storage, exactly ONCE per store
   * instance lifetime (see MAX_SCANNED_RECORDS's doc +
   * MAX_INDEX_BACKFILL_RECORDS's derivation). Concurrent callers share the
   * same in-flight build via `indexBuildPromise` rather than each kicking
   * off a redundant full scan.
   */
  private async ensureIndex(): Promise<void> {
    if (this.indexReady) return;
    if (!this.indexBuildPromise) {
      this.indexBuildPromise = this.buildIndex();
    }
    await this.indexBuildPromise;
  }

  private async buildIndex(): Promise<void> {
    const metas = await this.storage.list(
      SENTINEL_FINDING_NAMESPACE,
      SENTINEL_FINDING_KEY_PREFIX,
    );
    const bounded = metas.slice(0, MAX_INDEX_BACKFILL_RECORDS);
    for (const meta of bounded) {
      const id = stripKeyPrefix(meta.key);
      if (id === null) continue;
      const raw = await this.storage.read(SENTINEL_FINDING_NAMESPACE, meta.key);
      if (!raw || raw.length > MAX_FINDING_BYTES) continue;
      const finding = await this.decode(id, raw);
      if (!finding) continue;
      this.index.set(id, {
        severity: finding.severity,
        sentinel_id: finding.sentinel_id,
        agent_id: finding.agent_id,
        observed_at: finding.observed_at,
      });
    }
    this.indexReady = true;
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
    // Keep the filter index current (see MAX_SCANNED_RECORDS's doc). Set
    // unconditionally, INCLUDING before `ensureIndex()` has ever run for
    // this instance — when the lazy backfill does run later it will read
    // this same record from storage and overwrite with an identical entry,
    // so ordering between "index updated here" and "index backfilled from
    // storage" never matters.
    this.index.set(truncated.finding_id, {
      severity: truncated.severity,
      sentinel_id: truncated.sentinel_id,
      agent_id: truncated.agent_id,
      observed_at: truncated.observed_at,
    });
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
          this.index.delete(id);
          // NEVER-SILENT-EVICTION (AGENTS.md rule 6/"never silently
          // degrade"): the saturation branch above already audits the
          // FAILURE case (no reclaimable record found); this is the
          // SUCCESS case, which previously left no trace at all — an
          // operator reading the audit log could not tell "the store
          // reclaimed a genuinely expired record to make room" apart from
          // "a write just silently happened to fit." Audit the reclamation
          // too, so eviction of a store record is never silent either way.
          void this.auditLog?.append(
            "l2",
            "finding_store_expired_record_reclaimed",
            this.fortressId,
            { finding_id: id, retention_until: persisted.retention_until },
            "success",
          );
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
   * FILTER-BEFORE-TRUNCATE (register Z-HNY-02 RECHECK — the class
   * re-introduced by the first cut of this bound; see MAX_SCANNED_RECORDS's
   * doc above for the full story). since/severity/sentinel_id/agent_id are
   * matched against the in-memory INDEX first — a cheap field compare, no
   * decrypt, no storage read — so a flood of recent NON-matching findings
   * can never push an older MATCHING one out of view: the match set is
   * computed over the WHOLE index, not a truncated recency window. Only
   * the matched, newest-first set is then decrypted, and that decrypt work
   * is bounded to `min(limit, MAX_SCANNED_RECORDS)` — the caller's own
   * requested limit, capped so a caller cannot force unbounded decrypt work
   * by requesting an enormous one (AGENTS.md rule 8(d), bounded work per
   * request).
   */
  async listFindings(opts?: {
    since?: string;
    severity?: SentinelSeverity;
    sentinelId?: string;
    agentId?: string;
    limit?: number;
  }): Promise<SentinelFinding[]> {
    await this.ensureIndex();

    const matches: Array<[string, FindingIndexEntry]> = [];
    for (const entry of this.index) {
      const [, meta] = entry;
      if (opts?.since && meta.observed_at < opts.since) continue;
      if (opts?.severity && meta.severity !== opts.severity) continue;
      if (opts?.sentinelId && meta.sentinel_id !== opts.sentinelId) continue;
      if (opts?.agentId && meta.agent_id !== opts.agentId) continue;
      matches.push(entry);
    }
    matches.sort((a, b) => (a[1].observed_at < b[1].observed_at ? 1 : -1));

    const limit = opts?.limit ?? 100;
    const decryptBound = Math.max(0, Math.min(limit, this.maxScannedRecords));
    const findings: SentinelFinding[] = [];
    for (const [id] of matches.slice(0, decryptBound)) {
      const raw = await this.storage.read(SENTINEL_FINDING_NAMESPACE, findingKey(id));
      if (!raw) continue;
      if (raw.length > MAX_FINDING_BYTES) continue;
      const finding = await this.decode(id, raw);
      if (!finding) continue;
      findings.push(finding);
    }
    findings.sort((a, b) => (a.observed_at < b.observed_at ? 1 : -1));
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
          this.index.delete(id);
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
