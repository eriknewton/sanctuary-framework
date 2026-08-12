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
  ReputationAlreadyRecordedError,
  ReputationIdOccupiedUnverifiedError,
  type ReputationRecordAuditProjection,
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
  deriveBridgeCommitmentId,
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

// ─── Content-derived commitment ids + existence guard (LD6 BP-DEADLINE-03) ─
//
// Admission_Completion_Design_Brief_2026-08-11.md V2-3/V2-4: bridge_commit
// used to mint `bridge-${Date.now()}-${rand}`, so a caller that timed out
// waiting for admission had no safe key to retry -- re-issuing the SAME
// negotiation minted a SECOND commitment and doubled quota. `bridge.ts` now
// derives the id from `(session_id, terms_hash, committer_did)` (see
// `deriveBridgeCommitmentId`); `BridgeStore.save` below adds the in-lock
// existence guard that makes a retry resolve to the SAME record.

/**
 * Thrown by `BridgeStore.save`'s existence guard when the content-derived
 * key is OCCUPIED by a record that FAILS intent verification (recompute-
 * from-stored-fields, signature, or tuple equality -- see
 * `verifyStoredCommitmentIntent`'s doc). Never overwritten, never silently
 * treated as success. Distinct from `BridgeStoreQuotaError`
 * ("scan_unavailable"): that reason means the guard's own scan could not
 * complete; this one means the scan completed and found something that does
 * not check out.
 */
export class BridgeIdOccupiedUnverifiedError extends Error {
  constructor() {
    super(
      "Bridge commitment store: the derived commitment id is occupied by a " +
      "record that failed intent verification; refusing to write."
    );
    this.name = "BridgeIdOccupiedUnverifiedError";
  }
}

/**
 * The plain projection an in-lock audit callback needs -- nothing more.
 * Carries only already-computed primitive fields, never a store handle.
 */
export interface BridgeCommitmentAuditProjection {
  bridge_commitment_id: string;
  session_id: string;
  counterparty_did: string;
  /**
   * True ONLY on the existence-guard reconcile branch (an already-committed
   * retry), false on a fresh write (LD6 gate fix-round F4, reworked
   * fix-round-2 -- must match the same field on
   * `ReputationRecordAuditProjection` in reputation-store.ts). The
   * reconcile branch ALWAYS re-emits its success audit -- O(1): one
   * bounded appendCritical, never an in-lock audit-log READ, which on the
   * non-eager path costs a full-chain decrypt + re-verify and would
   * serialize every admission behind it -- but the callback TAGS the
   * emitted entry (`reconcile: true` in `details`) so consumers that COUNT
   * success entries (posture.ts's receipt tally) exclude re-emissions: an
   * identical-args retry loop appends only tagged entries the tally
   * ignores, so it cannot inflate the posture-visible count N-fold. The
   * self-heal semantic survives: a crash-window-orphaned record still gets
   * a durable, full-fidelity (tagged) success entry from any retry.
   */
  reconcile: boolean;
}

/**
 * Callback invoked INSIDE `BridgeStore.save`'s admission lock (V2-2/V2-5),
 * either immediately after a NEW commitment is durably written, or as the
 * reconcile step when the existence guard finds an already-committed match
 * whose audit may have been lost to a prior crash. The parameter type
 * exposes ONLY the plain projection above -- no `BridgeStore` reference, no
 * storage handle, no admission-queue accessor -- so the callback has
 * nothing PASSED IN that it could re-enter a store's admission lock with.
 *
 * HONEST BOUND (fix-round correction): this restricts only the PARAMETER a
 * caller receives, not what a closure built against this type can
 * LEXICALLY CAPTURE from its own creation scope -- a TS function type
 * constrains arguments, not closures, so it cannot stop a call site from
 * writing `async (projection) => { await bridgeStore.save(...); ... }` and
 * capturing `bridgeStore` from the outer scope regardless of `projection`'s
 * shape. Re-entry avoidance here is a CONVENTION every current call site
 * follows (the closure captures only `auditLog` + primitive locals, never
 * `bridgeStore` / `storage`), not a structural guarantee this type enforces
 * (V2-5 gap-5). A real structural guard (e.g. a re-entrancy flag on the
 * admission lock itself) would close this properly; it is not built here.
 * Construct the closure passed here by capturing `auditLog` + plain data
 * ONLY, never `bridgeStore` / `storage`.
 */
export type BridgeInLockAuditEmit = (
  projection: BridgeCommitmentAuditProjection
) => Promise<void>;

/** `BridgeStore.save`'s result: which commitment/outcome the CALLER should
 * use downstream. On a reconciled retry (`alreadyCommitted: true`) this is
 * the STORED record, never the freshly re-signed one the caller built for
 * this call (bridge signs `committed_at = now`, so a naive overwrite would
 * leave two byte-distinct-but-valid records racing for one key -- the
 * existence guard is what closes that, by never writing the new one). */
export interface BridgeSaveResult {
  commitment: BridgeCommitment;
  outcome: ConcordiaOutcome;
  alreadyCommitted: boolean;
}

/** Reason a bridge_attest reputation-context write was refused (LD3 gate fix-round DEFECT 2). */
export type BridgeAttestOriginQuotaRefuseReason = "origin_quota" | "scan_unavailable";

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
 * that context.
 *
 * LD6 BP-DEADLINE-03: this error's reason set used to include
 * `dedup_scan_unavailable` for a same-negotiation dedup re-scan this
 * closure ran itself. That dedup is now STRUCTURAL -- `record()`'s own
 * existence guard (reputation-store.ts, `findVerifiedExistingRecord`)
 * performs it INSIDE the same lock, before this closure even runs, and
 * signals a scan failure via `ReputationStoreQuotaError("scan_unavailable")`
 * instead (see the tool handler's catch block). This closure now enforces
 * ONLY the origin-quota share described above.
 */
export class BridgeAttestOriginQuotaError extends Error {
  readonly reason: BridgeAttestOriginQuotaRefuseReason;
  constructor(reason: BridgeAttestOriginQuotaRefuseReason) {
    super(
      reason === "origin_quota"
        ? "Bridge attestation store: origin per-write quota exceeded"
        : "Bridge attestation store: could not confirm quota headroom " +
          "(storage scan failed); refusing to write"
    );
    this.name = "BridgeAttestOriginQuotaError";
    this.reason = reason;
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
 * The counterparty relative to `commitment.committer_did`: whichever of
 * `proposer_did`/`acceptor_did` is NOT the committer. Used to build the
 * `BridgeCommitmentAuditProjection` for both a fresh write and a
 * reconciled existence-guard hit, so the audit detail is identical either
 * way.
 */
function counterpartyDidOf(commitment: BridgeCommitment, outcome: ConcordiaOutcome): string {
  return outcome.proposer_did === commitment.committer_did
    ? outcome.acceptor_did
    : outcome.proposer_did;
}

/**
 * Bounds how long a CALLER waits on BridgeStore's whole admission critical
 * section (LD3 gate fix-round-2, MUST-FIX 3). Caller-facing ONLY: the lock
 * itself is held until `fn()` settles (LD5 BP-DEADLINE-01, see
 * `runAdmissionExclusiveBounded`'s doc), so this constant bounds what the
 * caller is told, never how long the section runs.
 *
 * DERIVATION against the section's true worst case (LD6 gate fix-round F2
 * — the prior comment predated V2-2 and omitted the in-lock audit append
 * this PR added). The locked section in `save()` is: existence-guard read
 * + (on a content-id miss) one full O(N) legacy decrypt-scan +
 * `assertOriginWithinQuota`'s second full O(N) decrypt-scan + the record
 * write + one AWAITED `appendCritical`. The audit append's own worst case
 * is AUDIT_WRITE_LOCK_TIMEOUT_MS (5s lock acquisition) +
 * DEFAULT_AUDIT_WRITE_LOCK_HOLD_DEADLINE_MS (30s write-hold), both
 * operational/audit-log.ts — 35s. ON_EVICT_AUDIT_TIMEOUT_MS
 * (core/bounded-map.ts) is that same 35s plus a 5s scheduling margin, i.e.
 * 40s: it is the established named bound for "one awaited audit append
 * performed inside a lock," which is exactly this section's shape, so it is
 * reused rather than re-derived. BRIDGE_STORAGE_OP_MARGIN_MS (10s) is the
 * defensive backstop for the section's OWN storage ops (the guard read, the
 * two O(N) decrypt-scans — N bounded by MAX_BRIDGE_COMMITMENTS — and the
 * write), which the storage interface gives no settle-time contract for at
 * all; it is a backstop, not a precise bound. The reconcile (guard-hit)
 * branch's in-lock work is ONE bounded appendCritical (the F4 fix-round-2
 * tag-based re-emission -- same 35s worst case as the write path's append,
 * with NO in-lock audit-log read), so the fresh-write path, which adds the
 * scans and the record write on top of that same append, stays the
 * section's worst case. Total: the deadline exceeds the audit append's 35s
 * hard worst case by 15s of margin for everything else in the section.
 *
 * ACCEPTED CONSEQUENCE (deliberate, fail-closed): because the audit append
 * is INSIDE the lock, a slow or contended audit backend serializes
 * admissions behind it, and callers whose wait crosses this deadline are
 * REFUSED — an availability cost, never fail-open. The alternatives are
 * both worse: auditing outside the lock reopens the V2-2
 * caller-told-success-without-durable-audit divergence, and releasing the
 * lock on timeout is the exact quota bypass LD5 BP-DEADLINE-01 closed.
 *
 * WHY bridge/reputation accept this in-lock audit coupling and the
 * sentinel path does NOT (the asymmetry sentinel-dispatcher.ts's comment
 * refuses to fold audit into saveFinding's lock over): a saturated
 * `SentinelFindingStore.saveFinding` can ALREADY spend up to
 * ON_EVICT_AUDIT_TIMEOUT_MS (40s, the withTimeout-bounded evict-intent
 * append) inside its lock; folding a second, bare (unbounded-by-timeout)
 * audit append in would worst-case 40s + 35s = 75s against the same 50s
 * deadline, timing out every capped-out caller. The 75s figure must match
 * the routeFinding comment in sentinel-dispatcher.ts and the derivation
 * note on REPUTATION_STORE_ADMISSION_DEADLINE_MS (reputation-store.ts).
 * BridgeStore and ReputationStore perform NO in-lock evict audit — their
 * section contains exactly ONE awaited append — so the single 35s worst
 * case fits this budget with margin.
 *
 * CROSS-FILE PIN: must stay numerically identical to reputation-store.ts's
 * REPUTATION_STORE_ADMISSION_DEADLINE_MS and sentinel-finding-store.ts's
 * STORE_ADMISSION_DEADLINE_MS — all three are ON_EVICT_AUDIT_TIMEOUT_MS +
 * the same 10s storage-op margin, kept as separate local constants per
 * module (not a shared import) for the same module-boundary reason
 * `resolveBridgeOrigin` above is reimplemented rather than imported.
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
   * `await`, decremented when `fn()` itself SETTLES (via a `.then` attached
   * to the chained promise), never on the caller's deadline-bounded await
   * settling first — see LD5 BP-DEADLINE-02 on `runAdmissionExclusiveBounded`
   * for why a caller-timeout-triggered release let chained closures pile up
   * unbounded behind a permanently-hung `fn`.
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
  /**
   * V2-4 sunset flag: gates the legacy tuple-scan fallback (see
   * `findExistingCommitmentForTuple`) that lets a caller retry with an OLD
   * random-format id still resolve to its existing record. Defaults to
   * `true` (production always scans) -- an operator would flip this off
   * only after running an out-of-band migration that re-keys every legacy
   * record to its content id, at which point the guard collapses to a
   * single content-id read. DEBT (owed, not built here -- out of scope per
   * the design brief V2-4 "optional operator-run maintenance verb"): no
   * `migrate-bridge-ids` CLI verb exists yet, so this flag has no way to
   * be safely turned off today; it stays `true` in practice until that
   * verb ships.
   */
  private readonly legacyIdScanEnabled: boolean;

  constructor(
    storage: StorageBackend,
    masterKey: Uint8Array,
    maxCommitments: number = MAX_BRIDGE_COMMITMENTS,
    maxCommitmentsPerOrigin: number = MAX_BRIDGE_COMMITMENTS_PER_ORIGIN,
    maxPendingAdmissionWaiters: number = MAX_PENDING_ADMISSION_WAITERS,
    legacyIdScanEnabled: boolean = true
  ) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "bridge-commitments");
    this.maxCommitments = maxCommitments;
    this.maxCommitmentsPerOrigin = maxCommitmentsPerOrigin;
    this.maxPendingAdmissionWaiters = maxPendingAdmissionWaiters;
    this.legacyIdScanEnabled = legacyIdScanEnabled;
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
  /**
   * `committerPublicKey` (LD6 BP-DEADLINE-03): the CURRENT identity's own
   * public key, used by the existence guard to verify a matched record's
   * signature -- see `verifyStoredCommitmentIntent`'s doc for why the
   * current caller's key (not a general DID resolver) is sound here.
   * `emitAudit` (V2-2/V2-5): runs INSIDE this method's admission lock,
   * either right after a NEW commitment durably writes, or as the
   * reconcile step when the existence guard finds an already-committed
   * match -- see `BridgeInLockAuditEmit`'s doc.
   */
  async save(
    commitment: BridgeCommitment,
    outcome: ConcordiaOutcome,
    origin: string,
    committerPublicKey: Uint8Array,
    emitAudit: BridgeInLockAuditEmit
  ): Promise<BridgeSaveResult> {
    return this.runAdmissionExclusiveBounded(async () => {
      // LD6 BP-DEADLINE-03 (V2-2/V2-3/V2-4): the existence guard runs
      // FIRST, inside the lock, before quota or write -- a retry of this
      // exact (session_id, terms_hash, committer_did) tuple (content-id
      // hit) or a pre-upgrade retry carrying an old random id (legacy-scan
      // hit) always observes a prior admission's completed write instead
      // of racing it. An id match ALONE never authorizes
      // `already_committed`; see findVerifiedExistingCommitment's doc.
      const tuple = {
        session_id: commitment.session_id,
        terms_hash: outcome.terms_hash,
        committer_did: commitment.committer_did,
      };
      const existing = await this.findVerifiedExistingCommitment(
        commitment.bridge_commitment_id,
        tuple,
        committerPublicKey
      );
      if (existing === "scan_unavailable") {
        throw new BridgeStoreQuotaError("scan_unavailable");
      }
      if (existing === "occupied_unverified") {
        throw new BridgeIdOccupiedUnverifiedError();
      }
      if (existing !== null) {
        // Reconcile: a record that committed but lost its audit to a prior
        // crash (the V2-2 named residual) gets its audit re-emitted here.
        // ALWAYS emitted on a guard hit -- never conditioned on an in-lock
        // audit-log read (that read is the HIGH fix-round-2 removed: a
        // non-eager query re-verifies the whole chain inside the lock) --
        // and `reconcile: true` (LD6 gate fix-round-2 F4) makes the
        // callback TAG the entry so counting consumers skip it; see
        // BridgeCommitmentAuditProjection's `reconcile` doc.
        await emitAudit({
          bridge_commitment_id: existing.commitment.bridge_commitment_id,
          session_id: existing.commitment.session_id,
          counterparty_did: counterpartyDidOf(existing.commitment, existing.outcome),
          reconcile: true,
        });
        return { commitment: existing.commitment, outcome: existing.outcome, alreadyCommitted: true };
      }

      await this.assertOriginWithinQuota(origin);

      const record = { commitment, outcome, origin };
      const serialized = stringToBytes(JSON.stringify(record));
      const encrypted = encrypt(serialized, this.encryptionKey);
      await this.storage.write(
        "_bridge",
        commitment.bridge_commitment_id,
        stringToBytes(JSON.stringify(encrypted))
      );

      // V2-2: the success audit is emitted INSIDE this same locked
      // section, immediately after the durable write settles -- write-first,
      // then an AWAITED appendCritical, never the reverse. This gives
      // "eventual, self-healing commit<->audit agreement", NOT atomicity: a
      // crash between the write above becoming durable and this append
      // becoming durable leaves a committed-but-unaudited record, which is
      // transient and self-healing (the reconcile branch above re-emits it
      // on the next retry or guard-read) but not reducible to zero within
      // one process (no cross-log transaction primitive exists on
      // StorageBackend -- see the design brief V2-2). If `emitAudit` THROWS
      // here (audit backend down -- a failure, not a crash), this call
      // REJECTS: the write already landed, but the caller is NEVER told
      // success without a durable audit. The record stays in place for an
      // idempotent retry, which re-enters the guard above and re-emits the
      // audit.
      await emitAudit({
        bridge_commitment_id: commitment.bridge_commitment_id,
        session_id: commitment.session_id,
        counterparty_did: counterpartyDidOf(commitment, outcome),
        // Fresh write: this entry cannot already exist, so the callback
        // appends without the reconcile-branch absence query (F4).
        reconcile: false,
      });

      return { commitment, outcome, alreadyCommitted: false };
    });
  }

  /**
   * V2-3/V2-4 existence guard used by `save()`. Looks for a commitment
   * already committed for `tuple`, either at the content-derived
   * `contentId` (primary) or via the legacy tuple-scan
   * (`findExistingCommitmentForTuple` -- a pre-upgrade random-id record).
   * Returns:
   *   - the STORED `{commitment, outcome}`, when a match passes intent
   *     verification;
   *   - `"occupied_unverified"`, when the content-id key is occupied by a
   *     record that FAILS intent verification (a pre-seed or corrupted
   *     entry) -- the caller must fail closed, NEVER overwrite;
   *   - `"scan_unavailable"`, when the guard's own read/scan could not
   *     complete (a storage error) -- distinct from occupied-unverified:
   *     nothing was found to be wrong, the guard simply could not confirm
   *     either way;
   *   - `null`, when neither the primary key nor the legacy scan has a
   *     match -- the caller should proceed to quota-check-then-write.
   *
   * `committerPublicKey` is the CURRENT identity's own public key, not a
   * general DID resolver. This is sound, not a shortcut: any match this
   * guard can honor requires the stored record's `committer_did` to equal
   * the identity making THIS call -- either by construction (the content-id
   * hit's hash preimage includes `committer_did`) or by the explicit
   * tuple-equality filter (`findExistingCommitmentForTuple` matches on
   * `committer_did` exactly). If the key is occupied by a record genuinely
   * signed by someone else, that signature will not verify against
   * `committerPublicKey` -- the correct fail-closed outcome, not a false
   * negative.
   */
  private async findVerifiedExistingCommitment(
    contentId: string,
    tuple: { session_id: string; terms_hash: string; committer_did: string },
    committerPublicKey: Uint8Array
  ): Promise<
    | { commitment: BridgeCommitment; outcome: ConcordiaOutcome }
    | "occupied_unverified"
    | "scan_unavailable"
    | null
  > {
    let raw: Uint8Array | null;
    try {
      raw = await this.storage.read("_bridge", contentId);
    } catch {
      return "scan_unavailable";
    }

    if (raw !== null) {
      let candidate: { commitment: BridgeCommitment; outcome: ConcordiaOutcome; origin?: string };
      try {
        const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
        const decrypted = decrypt(encrypted, this.encryptionKey);
        candidate = JSON.parse(bytesToString(decrypted));
      } catch {
        // Undecryptable/corrupted content at the derived key: cannot be a
        // legitimate prior commit under this scheme (a genuine write always
        // round-trips), so this is occupied-but-unverified, not absence.
        return "occupied_unverified";
      }
      return this.verifyStoredCommitmentIntent(candidate, tuple, committerPublicKey, contentId)
        ? { commitment: candidate.commitment, outcome: candidate.outcome }
        : "occupied_unverified";
    }

    if (!this.legacyIdScanEnabled) {
      return null;
    }

    const legacy = await this.findExistingCommitmentForTuple(tuple);
    if (legacy === "scan_unavailable") return "scan_unavailable";
    if (legacy === null) return null;
    // No `expectedContentId` here: a legacy match was found by an EXACT
    // field-by-field scan, so tuple equality already holds by
    // construction -- recomputing a content id and comparing it to the
    // record's OLD random id would always fail and is not the check this
    // path needs. The signature check below is still required
    // (defense-in-depth: a legacy match is genuine only if it was actually
    // signed by this caller's key).
    return this.verifyStoredCommitmentIntent(legacy, tuple, committerPublicKey)
      ? { commitment: legacy.commitment, outcome: legacy.outcome }
      : "occupied_unverified";
  }

  /**
   * V2-4 legacy dual-read: scan `_bridge` for a pre-upgrade record (still
   * keyed by its old random id) matching `tuple` exactly. Bounded by this
   * store's own size cap (MAX_BRIDGE_COMMITMENTS), the SAME O(N)
   * decrypt-scan shape `assertOriginWithinQuota` already pays on every
   * write -- not a new unbounded surface. Runs at most once per admission,
   * only on a content-id miss, inside the lock. Fails CLOSED (mirrors
   * `assertOriginWithinQuota`'s contract on this exact namespace): a
   * storage.list error, or any entry that cannot be read/decrypted, is
   * treated as "cannot confirm," never as "not a match."
   */
  private async findExistingCommitmentForTuple(
    tuple: { session_id: string; terms_hash: string; committer_did: string }
  ): Promise<
    { commitment: BridgeCommitment; outcome: ConcordiaOutcome } | "scan_unavailable" | null
  > {
    let entries: Array<{ key: string }>;
    try {
      entries = await this.storage.list("_bridge");
    } catch {
      return "scan_unavailable";
    }

    for (const meta of entries) {
      let raw: Uint8Array | null;
      try {
        raw = await this.storage.read("_bridge", meta.key);
      } catch {
        return "scan_unavailable";
      }
      if (!raw) continue;
      try {
        const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
        const decrypted = decrypt(encrypted, this.encryptionKey);
        const record = JSON.parse(bytesToString(decrypted)) as {
          commitment: BridgeCommitment;
          outcome: ConcordiaOutcome;
        };
        if (
          record.commitment.session_id === tuple.session_id &&
          record.outcome.terms_hash === tuple.terms_hash &&
          record.commitment.committer_did === tuple.committer_did
        ) {
          return record;
        }
      } catch {
        return "scan_unavailable";
      }
    }

    return null;
  }

  /**
   * V2-3 intent verification: an id (or tuple) match ALONE must never
   * authorize `already_committed`. Recomputes the content id from the
   * STORED record's own fields and asserts it equals `expectedContentId`
   * (skipped for a legacy-scan match -- see the call site's doc), verifies
   * the stored record's OWN signature via `verifyBridgeCommitment` against
   * `committerPublicKey`, and asserts EXACT field equality between the
   * stored tuple and the incoming operation's tuple -- not just id
   * equality, the "verify exact canonical intent" the design brief
   * requires. All checks must pass.
   */
  private verifyStoredCommitmentIntent(
    candidate: { commitment: BridgeCommitment; outcome: ConcordiaOutcome },
    tuple: { session_id: string; terms_hash: string; committer_did: string },
    committerPublicKey: Uint8Array,
    expectedContentId?: string
  ): boolean {
    // Fail-closed verification body (LD6 gate fix-round F6; scope widened
    // fix-round-2 M-3 -- must match the try/catch in
    // verifyStoredAttestationIntent, reputation-store.ts): the try encloses
    // the ENTIRE body from the candidate destructure onward, because a
    // decryptable-but-wrong-shape candidate (null, or missing
    // commitment/outcome) throws a raw TypeError at the first property
    // access -- before any signature work -- and is exactly as unverified
    // as a bad signature (so are a malformed base64url signature,
    // wrong-length key material, or an uncanonicalizable outcome inside
    // verifyBridgeCommitment). ANY throw classifies as the fail-closed
    // `occupied_unverified` (return false), never an unclassified
    // rejection escaping save()'s locked section.
    try {
      const { commitment, outcome } = candidate;
      if (expectedContentId !== undefined) {
        const recomputed = deriveBridgeCommitmentId(
          commitment.session_id,
          outcome.terms_hash,
          commitment.committer_did
        );
        if (recomputed !== expectedContentId) return false;
      }
      if (
        commitment.session_id !== tuple.session_id ||
        outcome.terms_hash !== tuple.terms_hash ||
        commitment.committer_did !== tuple.committer_did
      ) {
        return false;
      }
      const verification = verifyBridgeCommitment(commitment, outcome, committerPublicKey);
      return verification.valid;
    } catch {
      return false;
    }
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
   * on its own deadline; a hung storage backend degrades to "no new
   * admissions succeed," never to a quota overshoot. That is NOT, by
   * itself, clean degradation with no other cost — see LD5 BP-DEADLINE-02
   * immediately below for the companion memory risk this fix also closes.
   *
   * LD5 BP-DEADLINE-02 (closed): `pendingAdmissionWaiters` used to be
   * released in a `finally` on THIS method's own await — i.e. on the
   * CALLER's timeout, not on `fn()` settlement. Under a permanently-hung
   * `fn()`, a timed-out caller freed its waiter slot while `fn` stayed
   * chained on `admissionQueue`, so later admissions kept passing the
   * waiter cap and piling up unbounded chained closures behind the hung
   * head (all reachable from `this.admissionQueue`, never GC-eligible) —
   * the cap bounded only CONCURRENT waiters, not CUMULATIVE chained
   * closures. The fix: the slot is released when `chained` (i.e. `fn()`)
   * itself settles, not when this call's deadline-bounded await returns —
   * see the settlement `.then` below.
   */
  private async runAdmissionExclusiveBounded<T>(fn: () => Promise<T>): Promise<T> {
    if (this.pendingAdmissionWaiters >= this.maxPendingAdmissionWaiters) {
      throw new BridgeStoreQuotaError("admission_busy");
    }
    this.pendingAdmissionWaiters += 1;
    // Chain the RAW fn onto admissionQueue (never the deadline-wrapped
    // closure) so runAdmissionExclusive only advances the queue once
    // fn() itself settles. The deadline races the ALREADY-CHAINED
    // promise below, so a timeout changes only what THIS call reports —
    // never when the lock frees for the next admission (LD5
    // BP-DEADLINE-01).
    const chained = this.runAdmissionExclusive(fn);
    // Release the waiter slot when fn() SETTLES, never when THIS caller's
    // await resolves: on a caller timeout the deadline rejects this call
    // while fn() stays chained on admissionQueue, and freeing the slot then
    // would let later admissions pile unbounded chained closures behind a
    // permanently-hung fn (LD5 BP-DEADLINE-02, rule-8). Holding the slot for
    // fn's lifetime caps accumulation at maxPendingAdmissionWaiters. chained
    // is also awaited below, so its rejection is handled and cannot surface
    // as unhandledRejection.
    const releaseSlot = (): void => {
      this.pendingAdmissionWaiters -= 1;
    };
    chained.then(releaseSlot, releaseSlot);
    return await withBridgeAdmissionDeadline(
      chained,
      BRIDGE_STORE_ADMISSION_DEADLINE_MS
    );
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
  /**
   * V2-4 sunset flag override (LD6 BP-DEADLINE-03). Production defaults to
   * `true`; a legacy-dual-read test can set this `false` to isolate the
   * content-id-only path, or leave it `true` (the default) to exercise the
   * legacy tuple-scan fallback.
   */
  legacyIdScanEnabled?: boolean;
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
    testOverrides?.maxPendingAdmissionWaiters,
    testOverrides?.legacyIdScanEnabled
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
        // LD6 BP-DEADLINE-03 (V2-2/V2-5): the success audit is threaded in as
        // an `InLockAuditEmit` closure and runs INSIDE BridgeStore.save's
        // admission lock (either right after the write, or as the reconcile
        // step on an already-committed retry). The closure captures ONLY
        // `auditLog` + the primitive `identity.identity_id` -- never
        // `bridgeStore` / `storage` -- so re-entry into any store's
        // admission lock from inside it does not happen HERE, by
        // CONVENTION, not by a type-system guarantee -- see
        // `BridgeInLockAuditEmit`'s doc for why the callback type cannot
        // enforce this on its own (V2-5 gap-5).
        const emitAudit: BridgeInLockAuditEmit = async (projection) => {
          // F4 (fix-round-2, tag-based dedupe): a reconcile re-emission is
          // TAGGED rather than deduped by an in-lock audit-log read -- see
          // the projection's `reconcile` doc. posture.ts's receipt tally
          // skips tagged entries.
          await auditLog.appendCritical({
            layer: "l3",
            operation: "bridge_commit",
            identity_id: identity.identity_id,
            result: "success",
            details: {
              bridge_commitment_id: projection.bridge_commitment_id,
              session_id: projection.session_id,
              counterparty: projection.counterparty_did,
              ...(projection.reconcile ? { reconcile: true } : {}),
            },
          });
        };

        let saveResult;
        try {
          saveResult = await bridgeStore.save(
            bridgeCommitment,
            outcome,
            origin,
            fromBase64url(identity.public_key),
            emitAudit
          );
        } catch (err) {
          if (err instanceof BridgeIdOccupiedUnverifiedError) {
            void auditLog.append(
              "l3",
              "bridge_commit_id_occupied_unverified",
              identity.identity_id,
              { session_id: outcome.session_id, caller_identity: origin },
              "failure"
            );
            return toolResult({ error: err.message });
          }
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

        const committed = saveResult.commitment;
        return toolResult({
          bridge_commitment_id: committed.bridge_commitment_id,
          session_id: committed.session_id,
          sha256_commitment: committed.sha256_commitment,
          committer_did: committed.committer_did,
          signature: committed.signature,
          pedersen_commitment: committed.pedersen_commitment
            ? { commitment: committed.pedersen_commitment.commitment }
            : undefined,
          committed_at: committed.committed_at,
          bridge_version: committed.bridge_version,
          // LD6 BP-DEADLINE-03 (Erik decision 3): a caller that retries the
          // identical negotiation (same session_id/terms_hash/committer_did)
          // is told this was already committed, rather than getting a
          // second, byte-different commitment -- this is the retry-safe
          // result shape a timed-out caller relies on.
          already_committed: saveResult.alreadyCommitted,
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

        // Idempotency for the SAME-NEGOTIATION replay (LD6 BP-DEADLINE-03):
        // a party can call bridge_attest repeatedly on the same valid
        // commitment. This used to be a two-layer dedup (a fast-path scan
        // here, plus an authoritative in-lock recheck) because the
        // attestation id was random, so only an explicit scan could tell a
        // repeat apart from a new attestation. The id is now content-derived
        // from (interaction_id = session_id, participant_did = identity.did,
        // counterparty_did, context) -- see reputation-store.ts's
        // `deriveReputationAttestationId` -- so `record()`'s OWN in-lock
        // existence guard (`findVerifiedExistingRecord`) IS the authoritative
        // dedup, structurally, with no separate scan needed here: a repeat
        // call resolves to the SAME key and record() rejects with
        // `ReputationAlreadyRecordedError`, caught below.
        //
        // SCOPE (do not overclaim, unchanged by this fix): this closes
        // RE-ATTESTATION of the SAME negotiation (same session_id tuple)
        // only. It does NOT prevent a party from minting MULTIPLE DISTINCT
        // commitments for one real negotiation: the session_id is
        // caller-supplied and the session_receipt is not verified here, so a
        // fresh session_id per call still self-inflates the tally.
        //
        // DEBT (bridge self-inflation, unchanged by this fix): verify the
        // Concordia session_receipt (or another negotiation-unique anchor)
        // so one real negotiation cannot be re-committed under many
        // session_ids. That is a trust-boundary decision for Erik
        // (draft-then-approve), not resolved by this dedup.

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
        // `checkAttestAdmission` is passed to record() as
        // `additionalQuotaCheck`, so it executes INSIDE record()'s own
        // admission lock, immediately before the write, with no await gap
        // between this check and the persist. LD6 BP-DEADLINE-03: this
        // closure used to ALSO re-run the dedup scan and throw
        // `BridgeAttestDuplicateError` on a match -- that dedup is now
        // STRUCTURAL, performed by record()'s OWN existence guard before
        // `additionalQuotaCheck` ever runs (see the comment above), so this
        // closure enforces ONLY the origin-quota share described above: the
        // pre-fix ordering let N concurrent bridge_attest calls all observe
        // headroom (e.g. all at count 199) before any of them wrote,
        // overshooting maxBridgeAttestationsPerOrigin by up to N-1;
        // composing the check into record()'s single-flight section closes
        // that race the same way BridgeStore.save() was closed above. Fails
        // CLOSED (denies) if the scan cannot confirm its result.
        const origin = resolveBridgeOrigin(callerIdentity);
        const checkAttestAdmission = async (): Promise<void> => {
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

        // LD6 BP-DEADLINE-03 (V2-2/V2-5): the success audit is threaded in
        // as an `InLockAuditEmit` closure and runs INSIDE record()'s
        // admission lock (either right after the write, or as the
        // reconcile step on an already-committed retry). Captures ONLY
        // `auditLog` + primitive locals (`commitmentId`) -- never
        // `reputationStore` -- so re-entry into any store's admission lock
        // from inside it does not happen HERE, by CONVENTION, not by a
        // type-system guarantee -- see `ReputationInLockAuditEmit`'s doc
        // (reputation-store.ts) for why the callback type cannot enforce
        // this on its own (V2-5 gap-5).
        const emitReputationAudit = async (
          projection: ReputationRecordAuditProjection
        ): Promise<void> => {
          // F4 (fix-round-2, tag-based dedupe): a reconcile re-emission is
          // TAGGED rather than deduped by an in-lock audit-log read -- see
          // ReputationRecordAuditProjection's `reconcile` doc. ACCEPTED
          // (vs origin/main): the removed `already_attested` fast path
          // appended ZERO entries per identical Tier-3 retry; this appends
          // one TAGGED entry per guard hit -- per-call audit appends are
          // the ambient norm on every other tool path, and the tally
          // excludes tags.
          await auditLog.appendCritical({
            layer: "l4",
            operation: "bridge_attest",
            identity_id: identity.identity_id,
            result: "success",
            details: {
              bridge_commitment_id: commitmentId,
              session_id: projection.interaction_id,
              attestation_id: projection.attestation_id,
              counterparty_did: projection.counterparty_did,
              // Reconcile-audit fidelity: on an idempotent retry this is
              // the STORED record's tier, not the current call's freshly
              // resolved `tier`. A legacy/pre-existing record can carry a
              // different tier; its audit must describe what is durable.
              sovereignty_tier: projection.sovereignty_tier,
              ...(projection.reconcile ? { reconcile: true } : {}),
            },
          });
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
            checkAttestAdmission,
            emitReputationAudit
          );
        } catch (err) {
          if (err instanceof BridgeAttestationMetricValidationError) {
            return toolResult({ error: err.message });
          }
          if (err instanceof ReputationIdOccupiedUnverifiedError) {
            void auditLog.append(
              "l4",
              "bridge_attest_id_occupied_unverified",
              identity.identity_id,
              { bridge_commitment_id: commitmentId, caller_identity: origin },
              "failure"
            );
            return toolResult({ error: err.message });
          }
          if (err instanceof ReputationAlreadyRecordedError) {
            // The structural existence guard found a match -- either THIS
            // caller's own prior attest (same idempotent shape the old
            // fast-path branch used to return), or a concurrent call that
            // already persisted between admission and this recheck. Not a
            // hard failure, so no failure-audit entry; the request
            // succeeded idempotently.
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

        // LD6 BP-DEADLINE-03: the success audit for a NEW attestation is
        // already emitted INSIDE record()'s admission lock via
        // `emitReputationAudit` above (V2-2) -- no second, out-of-lock
        // append here.
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
