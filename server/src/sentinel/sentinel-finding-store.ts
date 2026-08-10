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
// CROSS-FILE PIN (revised, fix-round-2 / MUST-FIX 5 RECHECK): this used to
// be pinned to sentinel/sentinels/anomaly-trigger.ts's QUERY_LIMIT because
// that 8-day rolling-baseline consumer asked `listFindings` for
// `limit: 5000` — but a decrypt-bounded, sorted-then-sliced `limit` is
// exactly the shape that let a flood in a RECENT window truncate an OLDER
// baseline window out of the result before anomaly-trigger ever saw it (the
// register Z-HNY-02 class this file's index exists to close, recurring one
// layer up). anomaly-trigger.ts now calls `listFindingMetadata` instead
// (see that method's doc) — an index-only scan with NO limit and NO
// decrypt, so it cannot be truncated by a flood at all. MAX_SCANNED_RECORDS
// remains the decrypt-work ceiling for `listFindings`'s CONTENT-bearing
// callers (dashboard/CLI "show recent findings" style queries), where a
// bounded top-N-newest truncation is the correct, disclosed behavior for a
// display page, not a security-relevant baseline.

/**
 * One entry of the in-memory finding index (see MAX_SCANNED_RECORDS above).
 * Deliberately narrow: only the fields `listFindings`'s filters need,
 * never the finding's `summary`/`details` — the index exists to avoid
 * decrypting records that WON'T match, not to cache plaintext content.
 * `origin` (MUST-FIX 4, fix-round-2) is the ONE exception carrying derived
 * (not raw) data: the resolved per-origin-quota key (see
 * `resolveFindingOrigin`), computed once at write/backfill time so
 * `originCount` never has to re-derive it on every quota check.
 */
interface FindingIndexEntry {
  severity: SentinelSeverity;
  sentinel_id: string;
  agent_id?: string;
  observed_at: string;
  origin: string;
}

/**
 * Public shape of `listFindingMetadata`'s results — the index entry plus
 * the finding_id (the index's own map key, not stored redundantly inside
 * `FindingIndexEntry` itself). Exported so consumers like
 * sentinel/sentinels/anomaly-trigger.ts can type their windowed-bucket
 * helpers against it without importing the internal `FindingIndexEntry`.
 */
export type SentinelFindingMetadata = FindingIndexEntry & { finding_id: string };

/**
 * Shared bucket for a finding this store cannot attribute to any caller
 * (MUST-FIX 4, fix-round-2 — mirrors handshake/tools.ts's
 * `AGENT_UNKNOWN_ORIGIN` decision: a shared bucket, not an unbounded escape
 * hatch, because every finding in it still counts against the SAME quota).
 * Fortress-wide findings (e.g. a cross-agent-chatter spike with no single
 * responsible agent) legitimately have no attributable origin; they are not
 * an attacker signal by themselves, so refusing them entirely would be the
 * wrong failure mode.
 */
export const UNATTRIBUTED_FINDING_ORIGIN = "unattributed";

/**
 * Resolve the per-origin-quota key for a finding (MUST-FIX 4). Prefers the
 * finding's own `agent_id` (set directly by most sentinels — e.g.
 * credential-usage-watcher.ts, anomaly detectors). Falls back to
 * `details.caller_identity` — several honeypot producers
 * (tool-call-trap-runtime.ts, filesystem-trap-monitor.ts,
 * runtime-trap-handler.ts) record the triggering caller ONLY inside
 * `details`, never as a top-level `agent_id`, because that field's product
 * meaning is "which agent this finding is ABOUT" and a fortress-wide
 * honeypot trigger is arguably about the trap, not a single agent — but the
 * per-origin WRITE quota needs the ACTUAL caller regardless of that
 * distinction, since the honeypot's tool-call trap is the highest-volume
 * attacker-reachable producer this store has. A finding with neither field
 * falls into the shared `UNATTRIBUTED_FINDING_ORIGIN` bucket.
 */
function resolveFindingOrigin(finding: SentinelFinding): string {
  if (finding.agent_id) return finding.agent_id;
  const callerIdentity = finding.details["caller_identity"];
  if (typeof callerIdentity === "string" && callerIdentity.length > 0) {
    return callerIdentity;
  }
  return UNATTRIBUTED_FINDING_ORIGIN;
}

/**
 * Thrown by `saveFinding` when a write is refused rather than persisted
 * (MUST-FIX 4, fix-round-2 — replaces the prior "always overshoot, never
 * refuse" behavior). `reason` distinguishes "THIS finding's own origin is
 * over its per-write quota" from "the whole store is genuinely saturated
 * and nothing is reclaimable" — the same origin_quota/capacity split
 * `BoundedMapRefuseReason` uses (core/bounded-map.ts), for the same reason:
 * an operator needs to tell "one caller is flooding" apart from "the store
 * is full of legitimately-live findings." Every current caller of
 * `saveFinding` already wraps the call in a try/catch or lets an outer
 * per-sentinel/per-detector catch handle a thrown error as a loud,
 * audited-but-non-fatal failure (see sentinel-dispatcher.ts's `tick()` /
 * anomaly-pipeline.ts's `tick()`, and the honeypot producers' existing
 * `.catch(() => undefined)` best-effort-persist convention) — this is
 * deliberately NOT a silent drop: the store itself audits the refusal
 * (`finding_store_origin_quota_exceeded` / `finding_store_saturated`)
 * before throwing, so the operator-visible trail exists even when a caller
 * only catches-and-discards.
 */
export class SentinelFindingStoreRefusedError extends Error {
  readonly reason: "origin_quota" | "capacity";
  constructor(reason: "origin_quota" | "capacity") {
    super(
      reason === "origin_quota"
        ? "Sentinel finding store: origin per-write quota exceeded"
        : "Sentinel finding store: at capacity, nothing reclaimable"
    );
    this.name = "SentinelFindingStoreRefusedError";
    this.reason = reason;
  }
}

/**
 * REMOVED (MUST-FIX 5, fix-round-3): a `MAX_INDEX_BACKFILL_RECORDS` constant
 * used to slice the ONE-TIME lazy index backfill (`ensureIndex`) to the
 * first N lexicographically-listed records, sized as a multiple of
 * MAX_TRACKED_FINDINGS's DEFAULT (5000). Two problems, both closed by
 * making `buildIndex` read every listed record instead of a slice:
 *
 * 1. `maxTrackedFindings` is a per-INSTANCE override
 *    (`SentinelFindingStoreOptions.maxTrackedFindings`, used by tests to
 *    drive the real ceiling in a handful of iterations instead of
 *    thousands) — a FIXED module-level slice could not track an
 *    instance's real ceiling. An instance constructed with a LARGER
 *    override than the constant the old slice was derived from would
 *    silently cold-start with an INCOMPLETE index: a retained record past
 *    the slice, but still within THAT instance's own
 *    `maxTrackedFindings`, was invisible to `listFindings`/
 *    `listFindingMetadata`/`originCount` until the next write happened to
 *    touch it — a filtered post-restart query could miss a record that
 *    genuinely still exists and is still within the store's own bound,
 *    which is exactly the "flood in a recent window hides an older
 *    matching record" class this file's index exists to close one layer
 *    up (see MAX_SCANNED_RECORDS's doc).
 * 2. Even pinning the slice to `this.maxTrackedFindings` at call time
 *    (rather than a module constant) would still be provably incomplete
 *    for the ONE disclosed residual case: pre-fix overshoot records
 *    written before MUST-FIX 4 made the ceiling a hard refuse. A slice
 *    sized off the CURRENT ceiling cannot bound a count that predates the
 *    ceiling existing.
 *
 * `buildIndex` below reads every record `storage.list()` returns for the
 * namespace — this store's own MAX_TRACKED_FINDINGS + per-origin quota
 * (MUST-FIX 4) already bound how large that listing can grow GOING
 * FORWARD; the only residual cost is retained pre-fix overshoot still
 * inside the retention window, which ages out on its own (30 days
 * default) rather than needing a truncation that could hide a live
 * record.
 */

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
 *
 * REAL CEILING, NOT SOFT (MUST-FIX 4, fix-round-2 RECHECK): the prior cut of
 * this store still WROTE a new record past this ceiling whenever nothing
 * was reclaimable (an audited but unbounded overshoot — the class this rule
 * exists to close, one layer up from where it was first closed). A write
 * that hits the ceiling with nothing reclaimable is now REFUSED
 * (`SentinelFindingStoreRefusedError`, reason `"capacity"`), loudly audited
 * exactly as before. This is safe for the rule-8(c) invariant ("a
 * pre-existing critical finding must survive a flood") because eviction
 * only ever reclaims an already-EXPIRED record regardless of severity —
 * refusing a NEW write never touches an existing one, critical or not.
 */
const MAX_TRACKED_FINDINGS = 5000;

/**
 * Per-origin quota for durable finding writes (AGENTS.md rule 8, MUST-FIX 4
 * RECHECK — this store's own bound had no per-writer accounting at all: any
 * single caller could grow it toward MAX_TRACKED_FINDINGS on its own,
 * exhausting the shared ceiling for every other producer). Mirrors the
 * MUST-FIX 1 spine's per-origin-quota shape (handshake sessions/results,
 * federation peers): the origin is resolved via `resolveFindingOrigin`
 * (agent_id, or the honeypot's `details.caller_identity` fallback), so a
 * single flooding agent session exhausts only its own share and is REFUSED
 * (`SentinelFindingStoreRefusedError`, reason `"origin_quota"`) before it
 * can starve the ceiling for a different agent or a different sentinel's
 * fortress-wide findings. 500 = 1/10th of MAX_TRACKED_FINDINGS, matching
 * the same ratio MAX_HANDSHAKE_SESSIONS_PER_ORIGIN /
 * MAX_HANDSHAKE_RESULTS_PER_ORIGIN / MAX_FEDERATION_PEERS_PER_ORIGIN use:
 * generous per-origin headroom while guaranteeing at least 10 distinct
 * origins' worth of findings fit before any one origin threatens the
 * shared ceiling.
 */
export const MAX_FINDINGS_PER_ORIGIN = 500;

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
   * MAX_SCANNED_RECORDS, PRUNE_SCAN_CAP, MAX_FINDINGS_PER_ORIGIN). Production
   * call sites never set these; they exist so the class-level
   * bounded-collection inventory test
   * (test/security/attacker-writable-collections-bounds.test.ts) can drive
   * the REAL production write/list/prune path to its cap in a handful of
   * iterations instead of thousands, without weakening the shipped defaults.
   */
  maxTrackedFindings?: number;
  maxScannedRecords?: number;
  pruneScanCap?: number;
  maxFindingsPerOrigin?: number;
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
  private readonly maxFindingsPerOrigin: number;
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
    this.maxFindingsPerOrigin =
      opts.maxFindingsPerOrigin ?? MAX_FINDINGS_PER_ORIGIN;
  }

  /**
   * Lazily build the filter index from storage, exactly ONCE per store
   * instance lifetime (see MAX_SCANNED_RECORDS's doc and `buildIndex`'s
   * COMPLETE-REBUILD note below). Concurrent callers share the same
   * in-flight build via `indexBuildPromise` rather than each kicking off a
   * redundant full scan.
   */
  private async ensureIndex(): Promise<void> {
    if (this.indexReady) return;
    if (!this.indexBuildPromise) {
      this.indexBuildPromise = this.buildIndex();
    }
    await this.indexBuildPromise;
  }

  /**
   * COMPLETE-REBUILD NOTE (MUST-FIX 5, fix-round-3): reads EVERY key the
   * storage backend's `list()` returns for the namespace — no slice, no
   * truncation. Completeness is by construction, not by a bound argued to
   * be generous enough (see the REMOVED-constant doc above for why a
   * fixed or even per-instance-derived slice could still be wrong): every
   * record `list()` reports gets decoded and indexed, so a cold-started
   * store's filter index always matches its actual retained record set,
   * regardless of how a given instance configures `maxTrackedFindings` or
   * how much pre-fix overshoot residue a long-lived store still carries.
   * The one-time cost this pays is proportional to the namespace's actual
   * size, not a constant — acceptable because it is paid ONCE per store
   * instance lifetime (see `ensureIndex` above), not per request, and
   * because MUST-FIX 4's hard ceiling + per-origin quota already bound how
   * large that size can grow going forward.
   */
  private async buildIndex(): Promise<void> {
    const metas = await this.storage.list(
      SENTINEL_FINDING_NAMESPACE,
      SENTINEL_FINDING_KEY_PREFIX,
    );
    for (const meta of metas) {
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
        origin: resolveFindingOrigin(finding),
      });
    }
    this.indexReady = true;
  }

  /**
   * How many findings `origin` currently holds, per the in-memory index
   * (MUST-FIX 4). Callers MUST `await ensureIndex()` first (both call
   * sites — `enforceTrackedFindingsCeiling` and `listFindingMetadata` —
   * already do), or a cold-start count reads as artificially low. O(index
   * size), itself bounded by MAX_TRACKED_FINDINGS going forward (see that
   * constant's doc) — cheap in-memory field compares, no decrypt, no I/O.
   */
  private originCount(origin: string): number {
    let count = 0;
    for (const entry of this.index.values()) {
      if (entry.origin === origin) count += 1;
    }
    return count;
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
   *
   * THROWS `SentinelFindingStoreRefusedError` (MUST-FIX 4, fix-round-2
   * RECHECK — was previously unconditional-success with a silent overshoot)
   * when the write is refused: either the finding's own resolved origin
   * (`resolveFindingOrigin`) is already at `MAX_FINDINGS_PER_ORIGIN`, or the
   * store is at `MAX_TRACKED_FINDINGS` with nothing reclaimable. Both cases
   * are audited (non-critical, matches this store's existing
   * `finding_store_saturated` telemetry convention) BEFORE throwing, so the
   * refusal is never silent even for a caller that only catches-and-drops
   * the exception (the honeypot producers' existing best-effort-persist
   * convention).
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
    const origin = resolveFindingOrigin(truncated);
    if (!opts?.knownExisting) {
      await this.enforceTrackedFindingsCeiling(key, origin);
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
      origin,
    });
    return persisted.retention_until;
  }

  /**
   * The bounded-ceiling check factored out of `saveFinding` so the
   * `knownExisting` fast path can skip it entirely. See MAX_TRACKED_FINDINGS
   * and MAX_FINDINGS_PER_ORIGIN. Throws `SentinelFindingStoreRefusedError`
   * on refusal (MUST-FIX 4) instead of returning and letting the caller
   * silently overshoot.
   */
  private async enforceTrackedFindingsCeiling(
    key: string,
    origin: string,
  ): Promise<void> {
    // Per-origin quota FIRST (mirrors BoundedMap.set()'s ordering, MUST-FIX
    // 1's spine shape): a flooding origin hits its own wall before it can
    // ever consume shared global headroom. Needs the index ready — a
    // cold-start count before backfill would under-count and let an origin
    // exceed its quota on the very first write after a restart.
    await this.ensureIndex();
    if (this.originCount(origin) >= this.maxFindingsPerOrigin) {
      void this.auditLog?.append(
        "l2",
        "finding_store_origin_quota_exceeded",
        this.fortressId,
        { origin, max_findings_per_origin: this.maxFindingsPerOrigin },
        "failure",
      );
      throw new SentinelFindingStoreRefusedError("origin_quota");
    }

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
        // REFUSE the write instead of the prior overshoot (MUST-FIX 4): a
        // pre-existing finding is never touched either way (refusing a NEW
        // write cannot drop an EXISTING one), and the refusal is loudly
        // audited, so this is "refused a new write, loudly," never "dropped
        // an observation silently."
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
        throw new SentinelFindingStoreRefusedError("capacity");
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
   *
   * AWAITED CRITICAL AUDIT BEFORE DELETE (MUST-FIX 6, fix-round-2 RECHECK):
   * when `auditLog` is configured, the reclamation INTENT is audited via
   * `appendCritical` (durable, round-trip-verified) and AWAITED before the
   * delete, not `void auditLog.append(...)` fire-and-forget after. If the
   * awaited write REJECTS, this ABORTS the whole reclamation scan and
   * returns `false` — the caller (`enforceTrackedFindingsCeiling`) then
   * refuses the triggering write (capacity), rather than deleting a record
   * with no durable trail of why. This mirrors bounded-map.ts's
   * onEvict/set() contract for the same reason: a crash or a rejected audit
   * write between "decided to delete" and "deleted" must never leave
   * "vanished, no record" as the observable outcome. `auditLog` itself
   * stays OPTIONAL (see `SentinelFindingStoreOptions.auditLog`'s doc — it
   * only gates observability, not the eviction guarantee); when absent,
   * reclamation proceeds exactly as before (no audit to await or fail).
   *
   * INTENT / COMPLETION SPLIT + RE-VERIFY-BEFORE-DELETE (MUST-FIX 4,
   * fix-round-3): the pre-delete audit above records INTENT
   * (`finding_store_expired_record_reclaim_started`), never
   * `finding_store_expired_record_reclaimed` — that operation name is now
   * reserved for the COMPLETION audit written AFTER `storage.delete()`
   * resolves, tagged `success`/`failure` to match what actually happened.
   * A delete failure after a successful intent write now produces an
   * explicit `finding_store_expired_record_reclaim_failed` entry instead
   * of a false success. Immediately before the delete, the record is
   * RE-READ and re-checked against `cutoff`; if a concurrent `saveFinding`
   * renewed it in the interim, the delete is skipped
   * (`finding_store_expired_record_reclaim_abandoned`) and the scan moves
   * to the next candidate, rather than deleting state a concurrent writer
   * just legitimately extended. See the inline comment at the call site
   * for the full reasoning on both defects this closes.
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
          // INTENT -> RE-VERIFY -> DELETE -> COMPLETION (MUST-FIX 4,
          // fix-round-3 — replaces a single pre-delete audit that recorded
          // `result: "success"` for the RECLAMATION before the delete had
          // even been attempted). Two distinct bugs that ordering hid:
          //
          // 1. FALSE SUCCESS ON DELETE FAILURE: the old audit entry
          //    claimed `finding_store_expired_record_reclaimed` / success
          //    BEFORE calling `storage.delete()`, which is itself
          //    fallible and was never wrapped — a delete failure after
          //    that point left a durable "success" record for a
          //    reclamation that never actually happened, with no
          //    corrective entry. Splitting into an INTENT audit (this
          //    call, still `appendCritical`, still awaited and aborting
          //    on rejection — the crash-safety property MUST-FIX 6
          //    established is unchanged) and a separate COMPLETION audit
          //    AFTER the delete resolves means a delete failure now
          //    produces an intent record plus an explicit FAILURE record,
          //    never an uncorrected false success.
          // 2. CONCURRENT-REFRESH DELETION ON STALE STATE: `persisted` was
          //    decoded from a `storage.read()` at the top of this loop
          //    iteration; the awaited audit write below is a real async
          //    gap during which a CONCURRENT `saveFinding` for this SAME
          //    finding_id could legitimately renew it (extend
          //    `retention_until`). Without a re-check, this call would
          //    still delete the renewed record based on the STALE
          //    "expired" decision made before the renewal. The storage
          //    interface (storage/interface.ts) has no compare-and-delete
          //    primitive, so the closest available atomicity is
          //    re-reading immediately before the delete and refusing to
          //    proceed if the record no longer qualifies — narrows the
          //    race to the smallest window this interface allows, rather
          //    than leaving the original (much wider) one open.
          if (this.auditLog) {
            try {
              await this.auditLog.appendCritical({
                layer: "l2",
                operation: "finding_store_expired_record_reclaim_started",
                identity_id: this.fortressId,
                result: "success",
                details: { finding_id: id, retention_until: persisted.retention_until },
              });
            } catch {
              // ABORT the reclamation: never delete a record with no
              // durable audit trail even for the INTENT to do so. The
              // caller treats "not reclaimed" the same as "genuinely
              // nothing reclaimable" and refuses the triggering write
              // (capacity) — fail closed, not a silent delete.
              return false;
            }
          }

          // Re-verify immediately before the destructive delete (concurrent-
          // refresh guard, see point 2 above).
          const freshRaw = await this.storage.read(SENTINEL_FINDING_NAMESPACE, meta.key);
          if (!freshRaw) {
            // Already gone — a concurrent reclamation or an operator
            // delete beat this one to it. Nothing to reclaim here; keep
            // scanning rather than treating this as a hard failure.
            continue;
          }
          let stillExpired: boolean;
          try {
            const freshEnvelope: EncryptedPayload = JSON.parse(bytesToString(freshRaw));
            const freshPlaintext = decrypt(freshEnvelope, this.encryptionKey, aad);
            const freshPersisted = JSON.parse(bytesToString(freshPlaintext)) as PersistedFinding;
            stillExpired = freshPersisted.retention_until <= cutoff;
          } catch {
            // Corrupted on re-read: treat the ORIGINAL decision (made from
            // a successfully-decoded read moments ago) as still valid —
            // matches this file's existing "leave corrupted records for
            // rotation" convention rather than blocking reclamation on a
            // decode failure of a record already decided reclaimable.
            stillExpired = true;
          }
          if (!stillExpired) {
            // A concurrent write renewed this record between the initial
            // read and this re-check — leave it in place. Audit the
            // abandoned intent explicitly so the `_started` entry above
            // never reads as an unresolved, ambiguous record.
            if (this.auditLog) {
              void this.auditLog.append(
                "l2",
                "finding_store_expired_record_reclaim_abandoned",
                this.fortressId,
                { finding_id: id, reason: "renewed_concurrently" },
                "success",
              );
            }
            continue;
          }

          let deleted: boolean;
          try {
            deleted = await this.storage.delete(SENTINEL_FINDING_NAMESPACE, meta.key);
          } catch (err) {
            // The delete itself failed AFTER intent was durably recorded
            // (point 1 above) — audit the mismatch explicitly rather than
            // leaving the `_started` entry as the only, ambiguous trace.
            if (this.auditLog) {
              void this.auditLog.append(
                "l2",
                "finding_store_expired_record_reclaim_failed",
                this.fortressId,
                { finding_id: id, error: err instanceof Error ? err.message : String(err) },
                "failure",
              );
            }
            return false;
          }
          if (this.auditLog) {
            void this.auditLog.append(
              "l2",
              "finding_store_expired_record_reclaimed",
              this.fortressId,
              { finding_id: id, retention_until: persisted.retention_until },
              deleted ? "success" : "failure",
            );
          }
          this.index.delete(id);
          return deleted;
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
   * List finding METADATA ONLY — no decrypt, no storage read — matching the
   * same since/severity/sentinel_id/agent_id filters as `listFindings`, but
   * returning EVERY index match rather than a decrypt-bounded top-N slice.
   *
   * MUST-FIX 5 (fix-round-2 RECHECK — anomaly baseline flood-truncation).
   * Built for sentinel/sentinels/anomaly-trigger.ts's 8-day rolling
   * baseline, which needs an ACCURATE per-window finding count and
   * sentinel/agent attribution and must NEVER have a flood in one window
   * silently push an OLDER window's findings out of the result — exactly
   * what `listFindings`'s `min(limit, MAX_SCANNED_RECORDS)` decrypt bound
   * did when a caller like that one asked for the whole span in one call
   * (see MAX_SCANNED_RECORDS's cross-file-pin comment above for the full
   * story). Every field Trigger A/B/C need (finding_id, severity,
   * sentinel_id, agent_id, observed_at) already lives in the index; none of
   * them need `summary`/`details`, so skipping decrypt entirely is not a
   * shortcut, it is the CORRECT bound for this consumer.
   *
   * NOT capped by MAX_SCANNED_RECORDS (AGENTS.md rule 8(d) note): unlike
   * `listFindings`, this method's cost is cheap in-memory field compares
   * only — the true bound is the store's OWN size, which MUST-FIX 4
   * (MAX_TRACKED_FINDINGS as a hard refuse + MAX_FINDINGS_PER_ORIGIN) now
   * makes a real ceiling rather than the prior soft/overshootable one. A
   * decrypt-bounded slice would reintroduce the exact truncation bug this
   * method exists to close; an unbounded-by-decrypt scan over a
   * store that is itself bounded is the fix, not a gap.
   */
  async listFindingMetadata(opts?: {
    since?: string;
    severity?: SentinelSeverity;
    sentinelId?: string;
    agentId?: string;
  }): Promise<SentinelFindingMetadata[]> {
    await this.ensureIndex();

    const matches: SentinelFindingMetadata[] = [];
    for (const [id, meta] of this.index) {
      if (opts?.since && meta.observed_at < opts.since) continue;
      if (opts?.severity && meta.severity !== opts.severity) continue;
      if (opts?.sentinelId && meta.sentinel_id !== opts.sentinelId) continue;
      if (opts?.agentId && meta.agent_id !== opts.agentId) continue;
      matches.push({ finding_id: id, ...meta });
    }
    matches.sort((a, b) => (a.observed_at < b.observed_at ? 1 : -1));
    return matches;
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
