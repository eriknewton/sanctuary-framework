/**
 * Sanctuary MCP Server — Concordia Bridge: Tool Definitions
 *
 * MCP tool wrappers for the Concordia-Sanctuary bridge.
 * Three tools:
 *   sanctuary/bridge_commit  — Bind a negotiation outcome to a Sanctuary commitment
 *   sanctuary/bridge_verify  — Verify a commitment against a revealed outcome
 *   sanctuary/bridge_attest  — Record a negotiation as a reputation attestation
 */

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import type { IdentityManager } from "../cognitive/tools.js";
import type { StorageBackend } from "../storage/interface.js";
import type { AuditLog } from "../operational/audit-log.js";
import type { HandshakeResult } from "../handshake/types.js";
import { AGENT_UNKNOWN_ORIGIN } from "../handshake/tools.js";
import {
  ReputationStore,
  ReputationStoreQuotaError,
  type StoredAttestation,
} from "../reputation/reputation-store.js";
import {
  MAX_PENDING_ADMISSION_WAITERS,
  ON_EVICT_AUDIT_TIMEOUT_MS,
} from "../core/bounded-map.js";
import { resolveTierByDid, TIER_WEIGHTS, type TierMetadata } from "../reputation/tiers.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { fromBase64url, stringToBytes } from "../core/encoding.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { bytesToString } from "../core/encoding.js";
import { publicKeyToDid, requireLocalDidEncodings, type StoredIdentity } from "../core/identity.js";
import {
  BRIDGE_METRIC_POLICY,
  BridgeAttestationMetricValidationError,
  CONCORDIA_BRIDGE_REPUTATION_CONTEXT,
  buildBridgeAttestationMetrics,
} from "../reputation/bridge-metrics.js";

import {
  createBridgeCommitment,
  verifyBridgeCommitment,
} from "./bridge.js";
import type {
  ConcordiaOutcome,
  BridgeCommitment,
} from "./types.js";

export {
  BRIDGE_ATTESTATION_BEHAVIORAL_METRIC_ALLOWLIST,
  BRIDGE_POLICY_METRIC_ALLOWLIST,
} from "../reputation/bridge-metrics.js";

// ─── Bridge Store: growth bounds (LD3 BRIDGE-BP-01) ───────────────────────
//
// bridge_commit is a Tier-3 (auto-allowed) tool: BridgeStore.save() wrote
// one permanent encrypted record per call, keyed by a fresh
// commitment.bridge_commitment_id, with NO cap, NO dedup, and NO eviction —
// an agent could grow `_bridge` without bound. Every later bridge_attest and
// ReputationStore.hasLocalBridgeCommitmentForAttestation decrypt-scans the
// WHOLE `_bridge` namespace, so unbounded growth also amplifies every later
// call's cost. This is the same "attacker-writable collection with no cap"
// class #1190/#1199 already closed for in-memory maps (core/bounded-map.ts),
// here applied to PERSISTED storage instead.

/**
 * Bound on total persisted bridge commitments. 5000 mirrors the
 * global/per-origin ratio sentinel-finding-store.ts uses
 * (MAX_TRACKED_FINDINGS=5000 / MAX_FINDINGS_PER_ORIGIN=500 = 10): generous
 * headroom for a real fortress's negotiation history while guaranteeing at
 * least 10 distinct origins can each use their full per-origin share before
 * the global ceiling bites.
 */
export const MAX_BRIDGE_COMMITMENTS = 5000;

/**
 * Per-origin quota for `_bridge` writes. Bound to the SERVER-SET
 * agent-session principal (`callerIdentity`, threaded from router.ts —
 * see `resolveBridgeOrigin` below), NEVER a caller-supplied field:
 * `identity_id` is Tier-3 `identity_create`-mintable and `session_id` is
 * free-form caller input, so keying this quota on either would be
 * defeated by minting a fresh value per call — the exact mistake
 * MAX_HANDSHAKE_SESSIONS_PER_ORIGIN's doc (handshake/tools.ts) records and
 * this mirrors. 500 = 1/10th of MAX_BRIDGE_COMMITMENTS, the same ratio
 * used above.
 */
export const MAX_BRIDGE_COMMITMENTS_PER_ORIGIN = 500;

/**
 * Per-origin quota for CONCORDIA_BRIDGE_REPUTATION_CONTEXT attestations
 * written via bridge_attest into the sibling `_reputation` store (same
 * shape/finding as MAX_BRIDGE_COMMITMENTS_PER_ORIGIN — see
 * ReputationStore.countAttestationsByOriginForContext). Kept as its own,
 * smaller constant rather than reusing MAX_BRIDGE_COMMITMENTS_PER_ORIGIN:
 * one commitment can legitimately be attested by only its two parties
 * (proposer/acceptor), so a real fortress needs far fewer distinct
 * bridge attestations per origin than commitments. 200 stays a generous
 * multiple of any realistic single-session attestation volume while
 * keeping the ceiling meaningfully tighter than the commitment quota.
 */
export const MAX_BRIDGE_ATTESTATIONS_PER_ORIGIN = 200;

/** Reason a bridge-store write was refused (LD3 BRIDGE-BP-01). */
export type BridgeStoreRefuseReason =
  | "origin_quota"
  | "capacity"
  | "scan_unavailable"
  | "admission_busy";

/**
 * Typed refusal thrown by BridgeStore.assertOriginWithinQuota. `capacity`
 * and `origin_quota` are ordinary fail-closed refusals; `scan_unavailable`
 * means the pre-write quota scan itself could not complete (a
 * storage.list error, or an entry that failed to read/decrypt) — treated
 * as a refusal rather than "assume headroom," mirroring
 * ReputationStore.findExistingAttestationForDedup's fail-closed contract
 * on this same `_bridge` namespace. `admission_busy` (LD3 gate fix-round-2,
 * MUST-FIX 3) means this call never even reached the quota scan, because
 * MAX_PENDING_ADMISSION_WAITERS other callers were already queued for this
 * store's admission lock — see BridgeStore.runAdmissionExclusiveBounded's
 * doc.
 */
export class BridgeStoreQuotaError extends Error {
  readonly reason: BridgeStoreRefuseReason;
  constructor(reason: BridgeStoreRefuseReason) {
    super(
      reason === "origin_quota"
        ? "Bridge commitment store: origin per-write quota exceeded"
        : reason === "capacity"
          ? "Bridge commitment store: capacity exceeded"
          : reason === "admission_busy"
            ? "Bridge commitment store: admission queue is saturated; " +
              "refusing to write (retry shortly)"
            : "Bridge commitment store: could not confirm quota headroom " +
              "(storage scan failed); refusing to write"
    );
    this.name = "BridgeStoreQuotaError";
    this.reason = reason;
  }
}

/** Reason a bridge_attest reputation-context write was refused (LD3 gate fix-round DEFECT 2). */
export type BridgeAttestOriginQuotaRefuseReason =
  | "origin_quota"
  | "scan_unavailable"
  | "dedup_scan_unavailable";

/**
 * Typed refusal thrown by bridge_attest's `additionalQuotaCheck` callback
 * (see the tool handler below and ReputationStore.record()'s doc). Distinct
 * from `BridgeStoreQuotaError` (that one guards `_bridge`; this one guards
 * bridge_attest's own narrower, context-scoped share of the SIBLING
 * `_reputation` store — see MAX_BRIDGE_ATTESTATIONS_PER_ORIGIN's doc) and
 * from `ReputationStoreQuotaError` (that one is `_reputation`'s OWN global
 * chokepoint bound, checked in the same admission-locked section — see
 * reputation-store.ts). No `capacity` reason here: this check only ever
 * enforces the per-origin share of ONE context, not a global ceiling on
 * that context. `dedup_scan_unavailable` (LD3 gate fix-round-2, MUST-FIX 4)
 * is distinct from `scan_unavailable`: the former is the ATOMIC in-lock
 * dedup re-scan (checkAttestAdmission's first step) failing to enumerate
 * `_reputation`, the latter is the origin-quota scan (its second step)
 * failing — kept as separate reasons, not coalesced, so the audit trail and
 * the error text tell an operator WHICH scan could not confirm its result,
 * rather than a generic "quota headroom" message that would be wrong for a
 * dedup-scan failure (that scan is about uniqueness, not headroom).
 */
export class BridgeAttestOriginQuotaError extends Error {
  readonly reason: BridgeAttestOriginQuotaRefuseReason;
  constructor(reason: BridgeAttestOriginQuotaRefuseReason) {
    super(
      reason === "origin_quota"
        ? "Bridge attestation store: origin per-write quota exceeded"
        : reason === "dedup_scan_unavailable"
          ? "Bridge attestation store: could not confirm this negotiation " +
            "was not already attested (storage scan failed); refusing to write"
          : "Bridge attestation store: could not confirm quota headroom " +
            "(storage scan failed); refusing to write"
    );
    this.name = "BridgeAttestOriginQuotaError";
    this.reason = reason;
  }
}

/**
 * Thrown from `bridge_attest`'s `additionalQuotaCheck` closure (LD3 gate
 * fix-round-2, MUST-FIX 4) when the ATOMIC, in-lock dedup re-scan finds an
 * existing attestation for this same negotiation. Carries `existing` so the
 * catch site can return the SAME idempotent "already_attested" response the
 * pre-fix outer pre-check returned, without a second storage scan.
 *
 * WHY THIS EXISTS (the race this closes): the pre-fix version ran
 * `findExistingAttestationForDedup` ONCE, before calling
 * `reputationStore.record()`, with an await gap between that scan and the
 * eventual write — record()'s own admission lock did not exist yet at that
 * point in the call. Two concurrent `bridge_attest` calls for the SAME
 * commitment could both run the scan, both see no match (neither has
 * written yet), and both then persist a fresh attestation, double-counting
 * one negotiation. Re-running the SAME scan as part of record()'s
 * `additionalQuotaCheck` — which executes INSIDE record()'s
 * per-instance admission lock, immediately before the write, with no await
 * gap between the recheck and the write — makes the second of two
 * concurrent calls observe the FIRST call's already-completed write (the
 * admission lock serializes them), so the second throws this error instead
 * of persisting a duplicate. Single-process only: two SEPARATE server
 * processes racing the same commitment are not covered (no shared
 * admission lock across processes) — a documented, accepted DEBT, same
 * class as the bridge self-inflation DEBT above and cross-process
 * uniqueness generally (Erik: cross-process is the deferred follow-up).
 */
export class BridgeAttestDuplicateError extends Error {
  readonly existing: StoredAttestation;
  constructor(existing: StoredAttestation) {
    super("Bridge attestation store: duplicate attestation for this negotiation");
    this.name = "BridgeAttestDuplicateError";
    this.existing = existing;
  }
}

/**
 * Resolve the per-origin quota key for a bridge-store write (LD3
 * BRIDGE-BP-01). Mirrors `resolveSessionOrigin` in handshake/tools.ts —
 * see that function's doc for why the SERVER-SET `callerIdentity` (never
 * a caller-supplied field) is the only safe quota key. Reimplemented as a
 * one-line function here, rather than imported, because
 * `resolveSessionOrigin` itself is not exported (only its
 * `AGENT_UNKNOWN_ORIGIN` shared-bucket constant is, so there remains
 * exactly one definition of THAT decision).
 */
function resolveBridgeOrigin(callerIdentity: string | undefined): string {
  return callerIdentity && callerIdentity.length > 0
    ? callerIdentity
    : AGENT_UNKNOWN_ORIGIN;
}

/**
 * Bounds BridgeStore's whole admission critical section (LD3 gate
 * fix-round-2, MUST-FIX 3 — same class and derivation as
 * REPUTATION_STORE_ADMISSION_DEADLINE_MS in reputation-store.ts and
 * STORE_ADMISSION_DEADLINE_MS in sentinel-finding-store.ts; see either
 * doc for the full derivation). CROSS-FILE PIN: must stay numerically
 * identical to reputation-store.ts's REPUTATION_STORE_ADMISSION_DEADLINE_MS
 * and sentinel-finding-store.ts's STORE_ADMISSION_DEADLINE_MS — all three
 * are ON_EVICT_AUDIT_TIMEOUT_MS + the same 10s storage-op margin, kept as
 * separate local constants per module (not a shared import) for the same
 * module-boundary reason `resolveBridgeOrigin` above is reimplemented
 * rather than imported.
 */
const BRIDGE_STORAGE_OP_MARGIN_MS = 10_000;
const BRIDGE_STORE_ADMISSION_DEADLINE_MS =
  ON_EVICT_AUDIT_TIMEOUT_MS + BRIDGE_STORAGE_OP_MARGIN_MS;

/**
 * Race `promise` against a timer that rejects after `ms`. Mirrors
 * reputation-store.ts's `withReputationAdmissionDeadline` / core/
 * bounded-map.ts's (unexported) `withTimeout` — reproduced here rather than
 * reaching across a module boundary for a five-line helper.
 */
function withBridgeAdmissionDeadline<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`bridge-store: admission did not settle within ${ms}ms`));
    }, ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err) => {
        clearTimeout(timer);
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    );
  });
}

// ─── Bridge Store ────────────────────────────────────────────────────────
// Persists bridge commitments encrypted at rest for later verification
// and attestation linking.

class BridgeStore {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;
  private maxCommitments: number;
  private maxCommitmentsPerOrigin: number;
  private readonly maxPendingAdmissionWaiters: number;
  /**
   * Live count of callers currently occupying this store's admission-waiter
   * cap (LD3 gate fix-round-2, MUST-FIX 3 — mirrors ReputationStore's field
   * of the same name, reputation-store.ts, and BoundedMap's
   * `pendingAdmissionWaiters`, core/bounded-map.ts). Incremented
   * SYNCHRONOUSLY in `runAdmissionExclusiveBounded` before its first
   * `await`, decremented in a `finally` once the admission settles either
   * way.
   */
  private pendingAdmissionWaiters = 0;
  /**
   * Serializes the check-then-write critical section in save() (LD3 gate
   * fix-round DEFECT 2): a single promise chain per BridgeStore INSTANCE,
   * not per origin, because assertOriginWithinQuota reads both the
   * per-origin count AND the global `_bridge` size — a lock scoped to one
   * origin could not stop two DIFFERENT origins from racing past the
   * global MAX_BRIDGE_COMMITMENTS ceiling together. Mirrors BoundedMap's
   * `admissionQueue` (core/bounded-map.ts) and ReputationStore's identical
   * field (reputation-store.ts): chain the next call onto the settled tail
   * of the previous one, so the whole quota-check-then-persist section
   * runs start to finish with no other save() interleaved. ONLY reached via
   * `runAdmissionExclusiveBounded` below (LD3 gate fix-round-2, MUST-FIX 3),
   * which adds the waiter cap and settlement deadline this raw chain does
   * not enforce on its own.
   */
  private admissionQueue: Promise<void> = Promise.resolve();

  /**
   * `maxCommitments`/`maxCommitmentsPerOrigin` (LD3 BRIDGE-BP-01) default
   * to the production constants but are overridable for tests only — the
   * real caps require thousands of writes to reach, which a capacity/
   * quota-refusal test would otherwise have to perform for real
   * (mirrors sentinel-finding-store.ts's `maxTrackedFindings`/
   * `maxFindingsPerOrigin` test-only override options; production call
   * sites never set these). `maxPendingAdmissionWaiters` (LD3 gate
   * fix-round-2) defaults to MAX_PENDING_ADMISSION_WAITERS
   * (core/bounded-map.ts — shared, not re-derived); same test-only-override
   * shape.
   */
  constructor(
    storage: StorageBackend,
    masterKey: Uint8Array,
    maxCommitments: number = MAX_BRIDGE_COMMITMENTS,
    maxCommitmentsPerOrigin: number = MAX_BRIDGE_COMMITMENTS_PER_ORIGIN,
    maxPendingAdmissionWaiters: number = MAX_PENDING_ADMISSION_WAITERS
  ) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "bridge-commitments");
    this.maxCommitments = maxCommitments;
    this.maxCommitmentsPerOrigin = maxCommitmentsPerOrigin;
    this.maxPendingAdmissionWaiters = maxPendingAdmissionWaiters;
  }

  /**
   * Scan `_bridge` and enforce both the global MAX_BRIDGE_COMMITMENTS
   * ceiling and `origin`'s MAX_BRIDGE_COMMITMENTS_PER_ORIGIN share (LD3
   * BRIDGE-BP-01). Fails CLOSED: a storage.list error, or any entry that
   * cannot be read/decrypted, throws `scan_unavailable` rather than
   * silently treating an unscannable entry as "not this origin" — the
   * same fail-closed posture ReputationStore.findExistingAttestationForDedup
   * already uses scanning this exact namespace.
   *
   * DEBT (LD3 BRIDGE-BP-01, scope): this is an O(N) decrypt-scan on every
   * write, same shape as the pre-existing bridge_attest/
   * hasLocalBridgeCommitmentForAttestation scans. Indexing `_bridge` by
   * origin (an in-memory count cache built once and maintained
   * incrementally) would remove the rescan; that is a larger structural
   * change left as follow-up. This fix bounds the STORE'S SIZE — which
   * bounds every scan's own worst case, including this one — rather than
   * changing the scan's algorithmic shape.
   */
  private async assertOriginWithinQuota(origin: string): Promise<void> {
    let entries: Array<{ key: string }>;
    try {
      entries = await this.storage.list("_bridge");
    } catch {
      throw new BridgeStoreQuotaError("scan_unavailable");
    }

    if (entries.length >= this.maxCommitments) {
      throw new BridgeStoreQuotaError("capacity");
    }

    let originCount = 0;
    for (const meta of entries) {
      let raw: Uint8Array | null;
      try {
        raw = await this.storage.read("_bridge", meta.key);
      } catch {
        throw new BridgeStoreQuotaError("scan_unavailable");
      }
      if (!raw) continue;
      try {
        const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
        const decrypted = decrypt(encrypted, this.encryptionKey);
        const record = JSON.parse(bytesToString(decrypted)) as { origin?: string };
        if (record.origin === origin) originCount++;
      } catch {
        throw new BridgeStoreQuotaError("scan_unavailable");
      }
    }

    if (originCount >= this.maxCommitmentsPerOrigin) {
      throw new BridgeStoreQuotaError("origin_quota");
    }
  }

  /**
   * `origin` (LD3 BRIDGE-BP-01) is the resolved quota key — see
   * `resolveBridgeOrigin`. Required, not optional: this is the ONLY
   * production call site (bridge_commit's handler), so there is no
   * back-compat surface an optional parameter would need to protect, and
   * an optional origin here would silently disable the quota exactly the
   * way AGENTS.md rule 3 warns against.
   *
   * CLOSED (LD3 gate fix-round DEFECT 2): the pre-fix version of this
   * method had an accepted "narrow TOCTOU residual" here — the quota check
   * and the persist were separated by awaits with no lock, so N concurrent
   * callers under the SAME origin could all pass the check before any of
   * them wrote, overshooting the cap by up to N-1. That was a real,
   * unbounded-under-genuine-concurrency race (not the small-constant
   * residual the old comment described: nothing capped how many callers
   * could race the same window), reproduced by the gate at 499/500 and
   * 199/200. The check and the write now both run inside
   * `runAdmissionExclusive`, a single per-instance admission lock (mirrors
   * BoundedMap's `admissionQueue`), so no other save() can observe state
   * between this call's check and its write.
   */
  async save(
    commitment: BridgeCommitment,
    outcome: ConcordiaOutcome,
    origin: string
  ): Promise<void> {
    await this.runAdmissionExclusiveBounded(async () => {
      await this.assertOriginWithinQuota(origin);

      const record = { commitment, outcome, origin };
      const serialized = stringToBytes(JSON.stringify(record));
      const encrypted = encrypt(serialized, this.encryptionKey);
      await this.storage.write(
        "_bridge",
        commitment.bridge_commitment_id,
        stringToBytes(JSON.stringify(encrypted))
      );
    });
  }

  /** Raw promise-chain primitive. Never call directly — see
   * `runAdmissionExclusiveBounded`, the ONLY caller, for the waiter-cap +
   * settlement-deadline wrapper every production admission goes through. */
  private async runAdmissionExclusive<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.admissionQueue.then(fn, fn);
    this.admissionQueue = run.then(
      () => undefined,
      () => undefined
    );
    return run;
  }

  /**
   * The ONLY entry point into `admissionQueue` (LD3 gate fix-round-2,
   * MUST-FIX 3 — mirrors ReputationStore.runAdmissionExclusiveBounded,
   * reputation-store.ts, exactly; see that method's doc for the full
   * rationale). Adds a bounded admission-WAITER cap (checked+incremented
   * synchronously before joining `admissionQueue`, fail-closed
   * `admission_busy` refusal at the cap) and a settlement deadline
   * (BRIDGE_STORE_ADMISSION_DEADLINE_MS) that bounds ONLY how long the
   * CALLER waits, never how long this store's lock is held.
   *
   * LD5 BP-DEADLINE-01 (closed): the pre-fix version wrapped `fn` in
   * `withBridgeAdmissionDeadline` BEFORE handing it to
   * `runAdmissionExclusive`, so the raw promise chained onto
   * `admissionQueue` WAS the deadline race — the lock released to the next
   * admission the instant the timer fired, even though the underlying
   * `fn()` (the quota check plus `storage.write`) kept running detached. A
   * scheduled fault ("scan passes, write hangs past the deadline, a new
   * admission is enqueued, the write is released later, repeat") could
   * therefore land arbitrarily many writes against quota headroom that had
   * already gone stale by the time each write actually landed, defeating
   * `MAX_BRIDGE_COMMITMENTS_PER_ORIGIN` outright — NOT the "exactly one
   * extra write, never unbounded growth" bound this comment used to claim.
   * The fix: `fn` (raw, undecorated) is what gets chained onto
   * `admissionQueue` via `runAdmissionExclusive` below, so the lock is held
   * until `fn()` truly settles; the deadline is applied ONLY to the promise
   * this method awaits and returns, bounding what the CALLER is told
   * without ever releasing the lock early. A `fn()` that never settles at
   * all (genuinely hung, not merely slow) therefore blocks this store's
   * queue for every later admission until it does — that trade is
   * deliberate: the alternative (releasing the lock early) is the exact
   * quota bypass this fix closes. Each individual caller still fails closed
   * on its own deadline and this store's `pendingAdmissionWaiters` cap, so
   * a hung storage backend degrades to "no new admissions succeed," never
   * to a quota overshoot.
   */
  private async runAdmissionExclusiveBounded<T>(fn: () => Promise<T>): Promise<T> {
    if (this.pendingAdmissionWaiters >= this.maxPendingAdmissionWaiters) {
      throw new BridgeStoreQuotaError("admission_busy");
    }
    this.pendingAdmissionWaiters += 1;
    try {
      // Chain the RAW fn onto admissionQueue (never the deadline-wrapped
      // closure) so runAdmissionExclusive only advances the queue once
      // fn() itself settles. The deadline races the ALREADY-CHAINED
      // promise below, so a timeout changes only what THIS call reports —
      // never when the lock frees for the next admission (LD5
      // BP-DEADLINE-01).
      const chained = this.runAdmissionExclusive(fn);
      return await withBridgeAdmissionDeadline(
        chained,
        BRIDGE_STORE_ADMISSION_DEADLINE_MS
      );
    } finally {
      this.pendingAdmissionWaiters -= 1;
    }
  }

  async get(
    commitmentId: string
  ): Promise<{ commitment: BridgeCommitment; outcome: ConcordiaOutcome } | null> {
    const raw = await this.storage.read("_bridge", commitmentId);
    if (!raw) return null;

    try {
      const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      return JSON.parse(bytesToString(decrypted));
    } catch {
      return null;
    }
  }
}

/**
 * Test-only override for the LD3 BRIDGE-BP-01 growth bounds. Production
 * call sites never set this (mirrors sentinel-finding-store.ts's
 * `maxTrackedFindings`/`maxFindingsPerOrigin` options) — it exists solely
 * so a capacity/quota-refusal test can drive a small cap instead of
 * performing thousands of real writes to reach the production ceiling.
 */
export interface BridgeToolsTestOverrides {
  maxBridgeCommitments?: number;
  maxBridgeCommitmentsPerOrigin?: number;
  maxBridgeAttestationsPerOrigin?: number;
  /**
   * Cap on BridgeStore's admission-WAITER queue (LD3 gate fix-round-2,
   * MUST-FIX 3). Defaults to MAX_PENDING_ADMISSION_WAITERS (core/
   * bounded-map.ts — shared, not re-derived). Test-only override, same
   * shape as the three above.
   */
  maxPendingAdmissionWaiters?: number;
}

// ─── Tool Factory ────────────────────────────────────────────────────────

/**
 * `reputationStore` (LD3 gate fix-round-2, MUST-FIX 2 — REQUIRED, not
 * optional/constructed-internally): production runs exactly ONE
 * ReputationStore instance over the `_reputation` backend, shared between
 * this factory and createReputationTools (reputation/tools.ts) — see
 * index.ts's composition-root comment at this factory's call site. Before
 * this fix, this factory constructed its OWN ReputationStore, so a live
 * server had TWO independent in-memory admission locks and quota views over
 * the SAME persisted backend: a concurrent reputation_record (through
 * createReputationTools' store) and bridge_attest (through THIS factory's
 * OWN store) could each observe pre-write headroom on their own store's
 * view and both write, overshooting MAX_REPUTATION_RECORDS(_PER_ORIGIN)
 * together — the quota check is only as good as the ONE store instance that
 * enforces it. Making this a REQUIRED parameter (rather than optional with
 * an internal-construction fallback) is deliberate: AGENTS.md rule 3 — an
 * optional dependency that GATES a security property must be required, or
 * the composition root must fail closed when it is missing, because an
 * optional shape here would silently reintroduce the exact two-instance
 * defect this fix closes the moment a future call site forgot to pass it.
 */
export function createBridgeTools(
  storage: StorageBackend,
  masterKey: Uint8Array,
  identityManager: IdentityManager,
  auditLog: AuditLog,
  reputationStore: ReputationStore,
  handshakeResults?: ReadonlyMap<string, HandshakeResult>,
  testOverrides?: BridgeToolsTestOverrides
): { tools: ToolDefinition[] } {
  const bridgeStore = new BridgeStore(
    storage,
    masterKey,
    testOverrides?.maxBridgeCommitments,
    testOverrides?.maxBridgeCommitmentsPerOrigin,
    testOverrides?.maxPendingAdmissionWaiters
  );
  const identityEncryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const hsResults = handshakeResults ?? new Map<string, HandshakeResult>();
  const maxBridgeAttestationsPerOrigin =
    testOverrides?.maxBridgeAttestationsPerOrigin ?? MAX_BRIDGE_ATTESTATIONS_PER_ORIGIN;

  // Helper to resolve identity
  function resolveIdentity(identityId?: string): StoredIdentity {
    const id = identityId
      ? identityManager.get(identityId)
      : identityManager.getDefault();
    if (!id) {
      throw new Error(
        identityId
          ? `Identity "${identityId}" not found`
          : "No identity available. Create one with identity_create first."
      );
    }
    return id;
  }

  function localPublicKeyForDid(did: string): Uint8Array | null {
    const match = identityManager.list().find((i) => i.did === did);
    return match ? fromBase64url(match.public_key) : null;
  }

  function outcomeFromArgs(value: unknown): ConcordiaOutcome | null {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return null;
    }
    const input = value as Record<string, unknown>;
    return {
      session_id: input.session_id as string,
      protocol_version: input.protocol_version as string,
      proposer_did: input.proposer_did as string,
      acceptor_did: input.acceptor_did as string,
      terms: input.terms as Record<string, unknown>,
      terms_hash: input.terms_hash as string,
      rounds: input.rounds as number,
      accepted_at: input.accepted_at as string,
      ...(input.session_receipt !== undefined
        ? { session_receipt: input.session_receipt as string }
        : {}),
    };
  }

  const tools: ToolDefinition[] = [
    // ─── bridge_commit ─────────────────────────────────────────────────

    {
      name: "bridge_commit",
      description:
        "Create a cryptographic commitment binding a Concordia negotiation outcome " +
        "to Sanctuary's L3 proof layer. The commitment includes a SHA-256 hash of " +
        "the canonical outcome (hiding + binding), an Ed25519 signature by the " +
        "committer's identity, and an optional Pedersen commitment on the round " +
        "count for zero-knowledge range proofs. This is the Sanctuary side of the " +
        "Concordia bridge — call this when a Concordia `accept` fires.",
      inputSchema: {
        type: "object",
        properties: {
          session_id: {
            type: "string",
            description: "Concordia session identifier",
          },
          protocol_version: {
            type: "string",
            description: 'Concordia protocol version (e.g., "concordia-v1")',
          },
          proposer_did: {
            type: "string",
            description: "DID of the party who proposed the accepted terms",
          },
          acceptor_did: {
            type: "string",
            description: "DID of the party who accepted",
          },
          terms: {
            type: "object",
            description: "The accepted terms (opaque to Sanctuary, meaningful to Concordia)",
          },
          terms_hash: {
            type: "string",
            description: "SHA-256 hash of the canonical terms serialization (computed by Concordia)",
          },
          rounds: {
            type: "number",
            description: "Number of negotiation rounds (propose/counter cycles)",
          },
          accepted_at: {
            type: "string",
            description: "ISO 8601 timestamp when accept was issued",
          },
          session_receipt: {
            type: "string",
            description: "Optional: signed Concordia session receipt",
          },
          identity_id: {
            type: "string",
            description: "Sanctuary identity to sign the commitment (uses default if omitted)",
          },
          include_pedersen: {
            type: "boolean",
            description: "Include a Pedersen commitment on round count for ZK range proofs",
          },
        },
        required: [
          "session_id",
          "protocol_version",
          "proposer_did",
          "acceptor_did",
          "terms",
          "terms_hash",
          "rounds",
          "accepted_at",
        ],
      },
      handler: async (args, callerIdentity) => {
        const outcome: ConcordiaOutcome = {
          session_id: args.session_id as string,
          protocol_version: args.protocol_version as string,
          proposer_did: args.proposer_did as string,
          acceptor_did: args.acceptor_did as string,
          terms: args.terms as Record<string, unknown>,
          terms_hash: args.terms_hash as string,
          rounds: args.rounds as number,
          accepted_at: args.accepted_at as string,
          session_receipt: args.session_receipt as string | undefined,
        };

        const identity = resolveIdentity(args.identity_id as string | undefined);
        const includePedersen = (args.include_pedersen as boolean) ?? false;

        const bridgeCommitment = createBridgeCommitment(
          outcome,
          identity,
          identityEncryptionKey,
          includePedersen
        );

        // Persist the commitment and outcome for later verification/attestation.
        // LD3 BRIDGE-BP-01: bound to the SERVER-SET session origin, never a
        // caller-supplied identity_id (see resolveBridgeOrigin's doc).
        const origin = resolveBridgeOrigin(callerIdentity);
        try {
          await bridgeStore.save(bridgeCommitment, outcome, origin);
        } catch (err) {
          if (err instanceof BridgeStoreQuotaError) {
            void auditLog.append(
              "l3",
              err.reason === "origin_quota"
                ? "bridge_commit_origin_quota_exceeded"
                : err.reason === "capacity"
                  ? "bridge_commit_store_saturated"
                  : "bridge_commit_quota_scan_unavailable",
              identity.identity_id,
              {
                session_id: outcome.session_id,
                caller_identity: origin,
              },
              "failure"
            );
            return toolResult({ error: err.message });
          }
          throw err;
        }

        await auditLog.appendCritical({
          layer: "l3",
          operation: "bridge_commit",
          identity_id: identity.identity_id,
          result: "success",
          details: {
            bridge_commitment_id: bridgeCommitment.bridge_commitment_id,
            session_id: outcome.session_id,
            counterparty: outcome.proposer_did === identity.did
              ? outcome.acceptor_did
              : outcome.proposer_did,
          },
        });

        return toolResult({
          bridge_commitment_id: bridgeCommitment.bridge_commitment_id,
          session_id: bridgeCommitment.session_id,
          sha256_commitment: bridgeCommitment.sha256_commitment,
          committer_did: bridgeCommitment.committer_did,
          signature: bridgeCommitment.signature,
          pedersen_commitment: bridgeCommitment.pedersen_commitment
            ? { commitment: bridgeCommitment.pedersen_commitment.commitment }
            : undefined,
          committed_at: bridgeCommitment.committed_at,
          bridge_version: bridgeCommitment.bridge_version,
          note: "Bridge commitment created. The blinding factor is stored encrypted. " +
            "Use bridge_verify to verify the commitment against the revealed outcome. " +
            "Use bridge_attest to link this negotiation to your reputation.",
        });
      },
    },

    // ─── bridge_verify ───────────────────────────────────────────────────

    {
      name: "bridge_verify",
      description:
        "Verify a bridge commitment against a revealed Concordia negotiation outcome. " +
        "Checks SHA-256 commitment validity, Ed25519 signature, session ID match, " +
        "terms hash integrity, and Pedersen commitment (if present). Use this to " +
        "confirm that a counterparty's claimed negotiation outcome matches what was " +
        "cryptographically committed.",
      inputSchema: {
        type: "object",
        properties: {
          bridge_commitment_id: {
            type: "string",
            description: "The bridge commitment ID to verify",
          },
          committer_public_key: {
            type: "string",
            description:
              "The committer's Ed25519 public key (base64url). " +
              "Required if verifying a counterparty's commitment. " +
              "Omit to auto-resolve from local identities.",
          },
          outcome: {
            type: "object",
            description:
              "Revealed ConcordiaOutcome to verify against the commitment. " +
              "If omitted, the stored outcome is used for backward-compatible local checks.",
          },
        },
        required: ["bridge_commitment_id"],
      },
      handler: async (args) => {
        const commitmentId = args.bridge_commitment_id as string;
        const externalPublicKey = args.committer_public_key as string | undefined;
        const revealedOutcome = outcomeFromArgs(args.outcome);

        // Load the stored commitment and outcome
        const record = await bridgeStore.get(commitmentId);
        if (!record) {
          return toolResult({
            error: `Bridge commitment "${commitmentId}" not found`,
          });
        }

        const { commitment: storedCommitment, outcome: storedOutcome } = record;
        const outcome = revealedOutcome ?? storedOutcome;

        // Resolve the committer's public key. An operator-supplied key is still
        // counterparty-controlled input, so it must derive back to the DID stored
        // in the commitment before verifyBridgeCommitment can make an identity
        // claim from its signature result.
        let publicKey: Uint8Array;
        if (externalPublicKey) {
          publicKey = fromBase64url(externalPublicKey);
          const derivedDid = publicKeyToDid(publicKey);
          if (derivedDid !== storedCommitment.committer_did) {
            return toolResult({
              error:
                `committer_public_key resolves to "${derivedDid}", ` +
                `but commitment names "${storedCommitment.committer_did}"`,
              bridge_commitment_id: commitmentId,
              signature_valid: false,
              _content_trust: "external",
            });
          }
        } else {
          // Try to find the committer in local identities
          const localPublicKey = localPublicKeyForDid(storedCommitment.committer_did);
          if (!localPublicKey) {
            return toolResult({
              error: `Cannot resolve public key for committer "${storedCommitment.committer_did}". ` +
                "Provide committer_public_key for external verification.",
            });
          }
          publicKey = localPublicKey;
        }

        const result = verifyBridgeCommitment(storedCommitment, outcome, publicKey);

        void auditLog.append("l3", "bridge_verify", "system", {
          bridge_commitment_id: commitmentId,
          session_id: storedCommitment.session_id,
          valid: result.valid,
        });

        return toolResult({
          ...result,
          session_id: storedCommitment.session_id,
          committer_did: storedCommitment.committer_did,
          // SEC-ADD-03: Tag response as containing counterparty-controlled data
          _content_trust: "external",
        });
      },
    },

    // ─── bridge_attest ───────────────────────────────────────────────────

    {
      name: "bridge_attest",
      description:
        "Record a Concordia negotiation as a Sanctuary L4 reputation attestation, " +
        "linked to a bridge commitment. The commitment (L3) proves the revealed " +
        "outcome matches the committer's signed commitment and terms hash; it does " +
        "not independently prove Concordia agreement or counterparty assent. The " +
        "attestation (L4) feeds the sovereignty-weighted reputation score. Its " +
        "weight reflects the SIGNER's sovereignty tier (who makes the claim), not " +
        "the counterparty's; a locally-signed attestation is self-attested.",
      inputSchema: {
        type: "object",
        properties: {
          bridge_commitment_id: {
            type: "string",
            description: "The bridge commitment ID to link",
          },
          outcome_result: {
            type: "string",
            enum: ["completed", "partial", "failed", "disputed"],
            description: "Negotiation outcome for reputation scoring",
          },
          metrics: {
            type: "object",
            additionalProperties: false,
            description:
              "Optional self-declared bridge behavioral inputs. Sanctuary " +
              "does not independently verify these declarations; it bounds " +
              "and buckets them before storage under metric_policy " +
              `"${BRIDGE_METRIC_POLICY}". Raw deal terms, raw magnitudes, ` +
              "legacy exact metric names, and unknown keys are rejected.",
            properties: {
              declared_offers_made: {
                type: "integer",
                minimum: 1,
                maximum: 64,
                description:
                  "Self-declared offer count, integer 1..64. Stored only as " +
                  "declared_offers_made_bucket, not the exact count.",
              },
              declared_concession: {
                type: "number",
                minimum: 0,
                maximum: 1,
                description:
                  "Self-declared concession ratio from 0 to 1. Stored only " +
                  "as declared_concession_bucket (0..10), not the exact ratio.",
              },
              declared_reasoning_provided: {
                type: "boolean",
                description:
                  "Self-declared whether reasoning was provided. Stored as " +
                  "declared_reasoning_provided 0 or 1.",
              },
              declared_response_time_ms: {
                type: "integer",
                minimum: 0,
                maximum: 3600000,
                description:
                  "Self-declared response latency in milliseconds, integer " +
                  "0..3600000. Stored only as declared_response_time_bucket, " +
                  "not exact milliseconds.",
              },
            },
          },
          identity_id: {
            type: "string",
            description: "Identity to sign the attestation (uses default if omitted)",
          },
        },
        required: ["bridge_commitment_id", "outcome_result"],
      },
      handler: async (args, callerIdentity) => {
        const commitmentId = args.bridge_commitment_id as string;
        const outcomeResult = args.outcome_result as
          | "completed"
          | "partial"
          | "failed"
          | "disputed";
        const identityId = args.identity_id as string | undefined;

        // Load the stored commitment and outcome
        const record = await bridgeStore.get(commitmentId);
        if (!record) {
          return toolResult({
            error: `Bridge commitment "${commitmentId}" not found`,
          });
        }

        const { commitment, outcome } = record;
        const identity = resolveIdentity(identityId);

        if (identity.did !== outcome.proposer_did && identity.did !== outcome.acceptor_did) {
          return toolResult({
            error:
              `Identity "${identity.did}" cannot attest bridge commitment "${commitmentId}" ` +
              "because it is neither the proposer nor the acceptor.",
          });
        }

        // bridge_attest writes L4 reputation, so it refuses the external-key
        // escape hatch used by read-only bridge_verify. The committer key must be
        // one Sanctuary already resolves for commitment.committer_did before an
        // attestation can amplify the bridge result.
        const committerPublicKey = localPublicKeyForDid(commitment.committer_did);
        if (!committerPublicKey) {
          return toolResult({
            error:
              `Cannot verify bridge commitment "${commitmentId}" before attestation: ` +
              `no local public key for committer "${commitment.committer_did}".`,
          });
        }

        const verification = verifyBridgeCommitment(commitment, outcome, committerPublicKey);
        if (!verification.valid) {
          return toolResult({
            error:
              `Bridge commitment "${commitmentId}" failed verification and cannot be attested.`,
            verification,
          });
        }

        let builtMetrics;
        try {
          builtMetrics = buildBridgeAttestationMetrics(outcome, args.metrics);
        } catch (err) {
          if (err instanceof BridgeAttestationMetricValidationError) {
            return toolResult({ error: err.message });
          }
          throw err;
        }

        // Determine counterparty DID
        const counterpartyDid =
          outcome.proposer_did === identity.did
            ? outcome.acceptor_did
            : outcome.proposer_did;

        // Idempotency for the SAME-NEGOTIATION replay: a party can call
        // bridge_attest repeatedly on the same valid commitment. Each call would
        // otherwise mint a fresh attestation reusing interaction_id =
        // session_id, and the reputation aggregator counts attestations with no
        // de-dup, so re-attesting one session would inflate the tallies N-fold.
        // Detect an attestation this same party has ALREADY recorded for this
        // session in the bridge context and return it idempotently rather than
        // recording a second. The counterparty attesting the same session, a
        // different context, or a different session still records normally.
        //
        // SCOPE (do not overclaim): this closes RE-ATTESTATION of the SAME
        // negotiation (same session_id tuple) only. It does NOT prevent a party
        // from minting MULTIPLE DISTINCT commitments for one real negotiation:
        // the session_id is caller-supplied and the session_receipt is not
        // verified here, so a fresh session_id per call still self-inflates the
        // tally. That broader self-inflation is NOT closed by this fix and is a
        // known scoring-engine / collusion concern (the bridge cannot verify a
        // Concordia session is unique or real without a verified session_receipt
        // anchor).
        //
        // DEBT (bridge self-inflation): verify the Concordia session_receipt (or
        // another negotiation-unique anchor) so one real negotiation cannot be
        // re-committed under many session_ids. That is a trust-boundary decision
        // for Erik (draft-then-approve), not resolved by this dedup.
        //
        // FAST-PATH ONLY, NOT THE SECURITY BOUNDARY (LD3 gate fix-round-2,
        // MUST-FIX 4 — narrowed from fix-round-1): this scan runs BEFORE
        // record()'s admission lock, with an await gap before the eventual
        // write, so it is a genuine check-then-write TOCTOU under real
        // concurrency — two concurrent bridge_attest calls for the SAME
        // commitment could both pass this scan (neither has written yet) and
        // both persist. It exists only to skip the cost of metrics-building,
        // tier resolution, and signing for the COMMON (non-concurrent) case
        // of an obvious repeat call. The AUTHORITATIVE recheck is
        // `checkAttestAdmission` below, composed into record()'s
        // `additionalQuotaCheck` so it runs INSIDE record()'s admission lock,
        // immediately before the write — see that closure's doc for how it
        // closes the race this fast path cannot. Fail CLOSED on the dedup
        // scan here too: if uniqueness cannot be confirmed (a storage.list
        // error, or any entry that failed to load/decrypt during the scan),
        // deny the attest rather than risk recording a duplicate under a
        // transient error. The aggregate read paths intentionally skip
        // corrupted entries; this dedup path does not.
        const dedupFastPath = await reputationStore.findExistingAttestationForDedup({
          interaction_id: outcome.session_id,
          participant_did: identity.did,
          counterparty_did: counterpartyDid,
          context: CONCORDIA_BRIDGE_REPUTATION_CONTEXT,
        });
        if (!dedupFastPath.scanComplete) {
          return toolResult({
            error:
              "Cannot confirm this negotiation was not already attested " +
              "(reputation store could not be fully read); the attestation was " +
              "not recorded. Retry once the store is readable.",
          });
        }
        if (dedupFastPath.match) {
          const existingAttestation = dedupFastPath.match;
          return toolResult({
            attestation_id: existingAttestation.attestation.attestation_id,
            bridge_commitment_id: commitmentId,
            session_id: outcome.session_id,
            counterparty_did: counterpartyDid,
            outcome_result: existingAttestation.attestation.data.outcome_result,
            sovereignty_tier: existingAttestation.attestation.data.sovereignty_tier,
            metric_policy: existingAttestation.attestation.data.metric_policy,
            attested_at: existingAttestation.recorded_at,
            already_attested: true,
            note:
              "This negotiation was already attested by this identity; returning " +
              "the existing attestation. Reputation was not recorded a second time.",
          });
        }

        // The weight reflects who makes the claim, not who it is about, so an
        // untrusted caller cannot borrow a verified counterparty's credibility.
        // REP-01: the signer (identity.did) is a LOCAL identity; cap it at
        // self-attested (a handshake-map match for a local signer is a
        // self-vouch). Passing exactly the signer DID is race-free. The storage
        // chokepoint (trustedSovereigntyTier, A11 — now an UNCONDITIONAL
        // clamp) enforces the same cap at scoring for every record, including
        // a pre-fix laundered record or a direct ReputationStore.record()
        // caller that bypasses this tool. requireLocalDidEncodings (not bare
        // identity.did) so BOTH DID encodings this identity's key could be
        // persisted under are capped — see resolveTierByDid's doc. The
        // "require" (hard-fail) form, not the soft localDidEncodings, because
        // `identity` is a HELD identity: a decode failure on our own key
        // material is an integrity error and must refuse the record, never
        // silently produce an empty cap set (register §Z RECHECK MUST-FIX-1).
        const tierMeta: TierMetadata = resolveTierByDid(
          identity.did,
          hsResults,
          true,
          new Set(requireLocalDidEncodings(identity.public_key))
        );
        const tier = tierMeta.sovereignty_tier;

        // LD3 BRIDGE-BP-01 (bound updated LD3 gate fix-round DEFECT 2): bound
        // per-origin growth of Concordia-bridge attestations in the sibling
        // `_reputation` store, the same class as BridgeStore's `_bridge`
        // quota above. `origin` is the SERVER-SET session principal
        // (resolveBridgeOrigin), never `identity.did` — that DID is Tier-3
        // `identity_create`-mintable, so a per-origin cap keyed on it would
        // be defeated by minting a fresh identity per call, the same defeat
        // MAX_BRIDGE_COMMITMENTS_PER_ORIGIN's doc records.
        //
        // `checkAttestAdmission` (LD3 gate fix-round-2, MUST-FIX 4 — renamed
        // and widened from the fix-round-1 `checkAttestOriginQuota`) is
        // passed to record() as `additionalQuotaCheck`, so it executes
        // INSIDE record()'s own admission lock, immediately before the
        // write, with no await gap between this check and the persist. It
        // now does TWO things atomically, in order:
        //
        // 1. RE-RUN the dedup scan (the same criteria the fast-path check
        //    above already ran) and throw BridgeAttestDuplicateError on a
        //    match. This is the AUTHORITATIVE dedup check: the fast-path
        //    scan above ran before this lock, with an await gap before the
        //    eventual write, so two concurrent bridge_attest calls for the
        //    SAME commitment could both pass IT and both reach here — but
        //    record()'s admission lock serializes their entries into THIS
        //    closure, so the second call's re-scan observes the first
        //    call's already-completed write and throws, instead of both
        //    persisting a duplicate. See BridgeAttestDuplicateError's doc
        //    for the full race this closes and its single-process scope.
        // 2. The origin-quota scan (unchanged from fix-round-1): the
        //    pre-fix ordering let N concurrent bridge_attest calls all
        //    observe headroom (e.g. all at count 199) before any of them
        //    wrote, overshooting maxBridgeAttestationsPerOrigin by up to
        //    N-1; composing the check into record()'s single-flight section
        //    closes that race the same way BridgeStore.save() was closed
        //    above. Fails CLOSED (denies) if either scan cannot confirm its
        //    result.
        const origin = resolveBridgeOrigin(callerIdentity);
        const checkAttestAdmission = async (): Promise<void> => {
          const dedupRecheck = await reputationStore.findExistingAttestationForDedup({
            interaction_id: outcome.session_id,
            participant_did: identity.did,
            counterparty_did: counterpartyDid,
            context: CONCORDIA_BRIDGE_REPUTATION_CONTEXT,
          });
          if (!dedupRecheck.scanComplete) {
            throw new BridgeAttestOriginQuotaError("dedup_scan_unavailable");
          }
          if (dedupRecheck.match) {
            throw new BridgeAttestDuplicateError(dedupRecheck.match);
          }

          const originQuota = await reputationStore.countAttestationsByOriginForContext(
            origin,
            CONCORDIA_BRIDGE_REPUTATION_CONTEXT
          );
          if (!originQuota.scanComplete) {
            throw new BridgeAttestOriginQuotaError("scan_unavailable");
          }
          if (originQuota.count >= maxBridgeAttestationsPerOrigin) {
            throw new BridgeAttestOriginQuotaError("origin_quota");
          }
        };

        // Record the reputation attestation
        let attestation;
        try {
          attestation = await reputationStore.record(
            outcome.session_id, // interaction_id = concordia session
            counterpartyDid,
            {
              type: "negotiation",
              result: outcomeResult,
              metrics: builtMetrics.metrics,
              metric_policy: builtMetrics.policy,
            },
            CONCORDIA_BRIDGE_REPUTATION_CONTEXT,
            identity,
            identityEncryptionKey,
            undefined, // counterparty_attestation
            tier,
            origin,
            checkAttestAdmission
          );
        } catch (err) {
          if (err instanceof BridgeAttestationMetricValidationError) {
            return toolResult({ error: err.message });
          }
          if (err instanceof BridgeAttestDuplicateError) {
            // The atomic in-lock recheck found a match a concurrent call
            // already persisted between the fast-path scan and this write —
            // return the SAME idempotent shape the fast-path branch above
            // returns, never a second attestation. Not itself a quota
            // refusal, so no quota audit entry; the request succeeded
            // idempotently.
            const existingAttestation = err.existing;
            return toolResult({
              attestation_id: existingAttestation.attestation.attestation_id,
              bridge_commitment_id: commitmentId,
              session_id: outcome.session_id,
              counterparty_did: counterpartyDid,
              outcome_result: existingAttestation.attestation.data.outcome_result,
              sovereignty_tier: existingAttestation.attestation.data.sovereignty_tier,
              metric_policy: existingAttestation.attestation.data.metric_policy,
              attested_at: existingAttestation.recorded_at,
              already_attested: true,
              note:
                "This negotiation was already attested by this identity; returning " +
                "the existing attestation. Reputation was not recorded a second time.",
            });
          }
          if (err instanceof BridgeAttestOriginQuotaError) {
            void auditLog.append(
              "l4",
              err.reason === "origin_quota"
                ? "bridge_attest_origin_quota_exceeded"
                : err.reason === "dedup_scan_unavailable"
                  ? "bridge_attest_dedup_scan_unavailable"
                  : "bridge_attest_quota_scan_unavailable",
              identity.identity_id,
              { bridge_commitment_id: commitmentId, caller_identity: origin },
              "failure"
            );
            return toolResult({
              error:
                err.reason === "origin_quota"
                  ? `This origin has reached its bridge-attestation quota ` +
                    `(${maxBridgeAttestationsPerOrigin}); the attestation was ` +
                    "not recorded."
                  : err.reason === "dedup_scan_unavailable"
                    ? "Cannot confirm this negotiation was not already attested " +
                      "(reputation store could not be fully read); the attestation " +
                      "was not recorded. Retry once the store is readable."
                    : "Cannot confirm this origin's attestation quota headroom " +
                      "(reputation store could not be fully read); the attestation " +
                      "was not recorded. Retry once the store is readable.",
            });
          }
          if (err instanceof ReputationStoreQuotaError) {
            // `_reputation`'s OWN global/per-origin chokepoint bound (LD3
            // gate fix-round DEFECT 1, reputation-store.ts) — distinct from
            // the context-scoped check above, checked in the same
            // admission-locked section inside record(). `admission_busy`
            // (fix-round-2, MUST-FIX 3) is included here: it is refused
            // before record() ever reaches assertRecordQuota, but is still
            // surfaced through this same catch since record() throws it the
            // same way.
            void auditLog.append(
              "l4",
              err.reason === "origin_quota"
                ? "bridge_attest_reputation_origin_quota_exceeded"
                : err.reason === "capacity"
                  ? "bridge_attest_reputation_store_saturated"
                  : err.reason === "admission_busy"
                    ? "bridge_attest_reputation_admission_busy"
                    : "bridge_attest_reputation_quota_scan_unavailable",
              identity.identity_id,
              { bridge_commitment_id: commitmentId, caller_identity: origin },
              "failure"
            );
            return toolResult({ error: err.message });
          }
          throw err;
        }

        await auditLog.appendCritical({
          layer: "l4",
          operation: "bridge_attest",
          identity_id: identity.identity_id,
          result: "success",
          details: {
            bridge_commitment_id: commitmentId,
            session_id: outcome.session_id,
            attestation_id: attestation.attestation.attestation_id,
            counterparty_did: counterpartyDid,
            sovereignty_tier: tier,
          },
        });

        const weight = TIER_WEIGHTS[tier];

        return toolResult({
          attestation_id: attestation.attestation.attestation_id,
          bridge_commitment_id: commitmentId,
          session_id: outcome.session_id,
          counterparty_did: counterpartyDid,
          outcome_result: outcomeResult,
          sovereignty_tier: tier,
          metric_policy: attestation.attestation.data.metric_policy,
          attested_at: attestation.recorded_at,
          already_attested: false,
          note: `Negotiation recorded as reputation attestation. ` +
            `Signer sovereignty tier: ${tier} (weight: ${weight}).`,
        });
      },
    },
  ];

  return { tools };
}
