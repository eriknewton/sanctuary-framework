/**
 * Sanctuary MCP Server — L4 Verifiable Reputation: Reputation Store
 *
 * Records interaction outcomes as signed attestations, queries aggregated
 * reputation data, and supports export/import for cross-platform portability.
 *
 * Attestation format is EAS-compatible (Ethereum Attestation Service) to
 * enable future on-chain anchoring without requiring blockchain for MVS.
 *
 * Security invariants:
 * - All attestations are signed by the recording identity
 * - Attestations are stored encrypted under L1 sovereignty
 * - Reputation queries return aggregates, never raw interaction data
 * - Export bundles include all signatures for independent verification
 * - Import verifies every signature before accepting attestations
 */

import type { StorageBackend } from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import {
  stringToBytes,
  bytesToString,
  toBase64url,
  fromBase64url,
  fromBase64urlStrict,
} from "../core/encoding.js";
import { randomBytes } from "../core/random.js";
import { sign, verify } from "../core/identity.js";
import type { StoredIdentity } from "../core/identity.js";
import type { SovereigntyTier } from "./tiers.js";
import { clampImportedSovereigntyTier } from "./tiers.js";
import { hashToString } from "../core/hashing.js";
import { verifyBridgeCommitment } from "../bridge/bridge.js";
import type { BridgeCommitment, ConcordiaOutcome } from "../bridge/types.js";
import {
  BRIDGE_METRIC_POLICY,
  BridgeAttestationMetricValidationError,
  assertImportableBridgeAttestationMetrics,
  assertRecordableBridgeAttestationMetrics,
  bridgeCountBucket,
  isConcordiaBridgeReputationContext,
} from "./bridge-metrics.js";
import {
  MAX_PENDING_ADMISSION_WAITERS,
  ON_EVICT_AUDIT_TIMEOUT_MS,
} from "../core/bounded-map.js";

// ─── Types ────────────────────────────────────────────────────────────────

/** Interaction outcome for recording */
export interface InteractionOutcome {
  type: "transaction" | "negotiation" | "service" | "dispute" | "custom";
  result: "completed" | "partial" | "failed" | "disputed";
  metrics?: Record<string, number>;
  metric_policy?: string;
}

/** A signed attestation of an interaction */
export interface Attestation {
  attestation_id: string;
  schema: "sanctuary-interaction-v1";
  data: {
    interaction_id: string;
    participant_did: string;
    counterparty_did: string;
    outcome_type: string;
    outcome_result: string;
    metrics: Record<string, number>;
    metric_policy?: string;
    context: string;
    timestamp: string;
    /** Sovereignty tier of the signer at time of recording */
    sovereignty_tier?: SovereigntyTier;
  };
  signature: string;
  signer: string;
}

/** Stored attestation (encrypted at rest) */
export interface StoredAttestation {
  attestation: Attestation;
  counterparty_attestation?: string;
  recorded_at: string;
  /**
   * Provenance marker distinguishing a record this instance witnessed
   * directly (false) from one accepted via importBundle (true) or of unknown
   * origin (absent).
   *
   * A11 (ratified; register §Z RECHECK residual, now closed): this marker no
   * longer controls whether trustedSovereigntyTier clamps the declared tier.
   * Clamping is UNCONDITIONAL regardless of `imported` — see
   * trustedSovereigntyTier — because a local record's declared tier can never
   * legitimately exceed self-attested either: every record() write is signed
   * with a LOCALLY-HELD key by construction, so "trust cannot originate from a
   * locally-held key" is the SAME self-vouch class as the handshake chokepoint
   * (recordHandshakeResult in handshake/tools.ts), expressed here at the
   * storage/scoring boundary instead of the handshake boundary.
   *
   *   - false  => recorded locally via ReputationStore.record().
   *   - true   => accepted via importBundle; a foreign signer's
   *               uncorroborated claim.
   *   - absent => unknown provenance (a legacy record written before this
   *               marker existed).
   *
   * The marker is retained for its genuine remaining purpose: distinguishing
   * directly-witnessed history from imported history for audit, export, and
   * dedup logic elsewhere in this file. The signed attestation.data is left
   * byte-intact regardless, so re-export signatures still verify; the clamp
   * is applied at the consumption boundary, never by mutating the signed
   * payload.
   */
  imported?: boolean;

  /**
   * SERVER-SET agent-session principal (`callerIdentity`, LD3 BRIDGE-BP-01)
   * that WROTE this record, when the caller supplied one. Distinct from
   * `attestation.data.participant_did`: the participant DID is a Sanctuary
   * identity, which `identity_create` lets an agent mint freely (Tier 3),
   * so it cannot serve as a per-origin write-growth quota key — this field
   * can, because only the router sets it, never a tool argument. Optional
   * and NOT part of the signed `attestation.data`: it is bookkeeping for
   * `countAttestationsByOriginForContext`'s quota scan, not a claim the
   * signature covers, and its absence on a record just means that record's
   * writer predates this field or bypassed the quota-checked call site
   * (record() accepts it as an optional trailing parameter precisely so
   * the many pre-existing direct-record() callers are unaffected — see
   * `record()`'s doc for which call sites are expected to supply it).
   */
  origin?: string;
}

/** Aggregated metric statistics */
export interface MetricAggregate {
  mean: number;
  median: number;
  min: number;
  max: number;
  count: number;
}

/** Reputation query result */
export interface ReputationSummary {
  total_interactions: number;
  completed: number;
  partial: number;
  failed: number;
  disputed: number;
  contexts: string[];
  time_range: { start: string; end: string };
  aggregate_metrics: Record<string, MetricAggregate>;
}

/**
 * Reputation-layer attestation evidence summary for the SHR degradation
 * emitter and the dashboard evidence widget. Derived from the stored
 * attestations; does not include Verascore-link state (tracked separately
 * via audit log).
 */
export interface ReputationAttestationSummary {
  /** Total number of attestations covered by the summary */
  attestation_count: number;
  /** Count of attestations at each sovereignty tier */
  tier_distribution: Record<SovereigntyTier, number>;
  /** ISO timestamp of the most recent attestation, or null if none */
  most_recent_attestation_at: string | null;
  /** Count of attestations with outcome_result === "disputed" */
  dispute_count: number;
  /** Count of attestations per context label */
  context_breakdown: Record<string, number>;
}

export type BridgeMetricEvidenceStatus =
  | "none"
  | "policy_rated"
  | "legacy_unbounded_metrics"
  | "unverified_policy_claim";

// ── Back-compat alias (L1-L4 rename PR-3) ───────────────────────────────
// The layer-numbered name stays exported so downstream imports keep working.
// The functional name above is canonical.
export type L4AttestationSummary = ReputationAttestationSummary;

export const REPUTATION_COMPLETENESS_MANIFEST_SCHEMA_VERSION = 1;
export const REPUTATION_LEGACY_REJECT_MESSAGE =
  "reputation export predates completeness verification; re-export, or re-run with allow_unverified_legacy to import without completeness guarantees";

export type ReputationBundleCompletenessVerification =
  | "verified"
  | "unverified-completeness-legacy-bundle";

export interface ReputationContextCompleteness {
  attestation_count: number;
  content_checksum_sha256: string;
}

export interface ReputationCompletenessManifest {
  schema_version: typeof REPUTATION_COMPLETENESS_MANIFEST_SCHEMA_VERSION;
  format: "SANCTUARY_REP_V1";
  exported_at: string;
  total_attestation_count: number;
  context_count: number;
  contexts: string[];
  context_attestations: Record<string, ReputationContextCompleteness>;
}

export class ReputationBundleVerificationError extends Error {
  readonly invalidAttestations: number;
  readonly unverifiableAttestations: number;

  constructor(
    message: string,
    invalidAttestations = 0,
    unverifiableAttestations = 0
  ) {
    super(message);
    this.name = "ReputationBundleVerificationError";
    this.invalidAttestations = invalidAttestations;
    this.unverifiableAttestations = unverifiableAttestations;
  }
}

/** Portable reputation bundle */
export interface ReputationBundle {
  version: "SANCTUARY_REP_V1";
  attestations: Attestation[];
  exported_at: string;
  exporter_did: string;
  completeness_manifest?: ReputationCompletenessManifest;
  bundle_signature: string;
}

// ─── Escrow and Bootstrap ─────────────────────────────────────────────────

/** Escrow for trust bootstrapping */
export interface Escrow {
  escrow_id: string;
  transaction_terms: string;
  terms_hash: string;
  collateral_amount?: number;
  counterparty_did: string;
  creator_did: string;
  created_at: string;
  expires_at: string;
  status: "pending" | "active" | "released" | "disputed" | "expired";
}

/** Principal guarantee for a new agent */
export interface Guarantee {
  guarantee_id: string;
  principal_did: string;
  agent_did: string;
  scope: string;
  max_liability?: number;
  valid_until: string;
  certificate: string; // Signed certificate
  created_at: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────

/**
 * The sovereignty tier that may be TRUSTED for weighting from a stored
 * attestation, as opposed to the raw self-asserted tier in the signed data.
 *
 * A11 (ratified; closes the REP-01 RESIDUAL / register §Z RECHECK): the clamp
 * to MAX_IMPORTED_SOVEREIGNTY_TIER is now UNCONDITIONAL, regardless of the
 * `imported` provenance marker. Every record() write is signed with a
 * LOCALLY-HELD key by construction (see ReputationStore.record), so a local
 * record's declared tier can never legitimately exceed self-attested either —
 * "trust cannot originate from a locally-held key" is the SAME self-vouch
 * class the handshake producer chokepoint closes (recordHandshakeResult in
 * handshake/tools.ts), expressed here at the storage/scoring boundary instead
 * of the handshake boundary. This closes the residual the REP-01 RECHECK
 * deliberately left open: a pre-fix laundered local record, or a hypothetical
 * direct ReputationStore.record() caller that stores a privileged local tier,
 * can no longer keep privileged weight.
 *
 * DESIGN CONSEQUENCE (inside the A11 ratification): verified-sovereign /
 * verified-degraded are now unreachable in reputation scoring product-wide —
 * an imported record was already clamped by provenance, and a local record's
 * declared tier is already forced to self-attested at every standard
 * record-time caller (reputation_record / bridge_attest, via
 * resolveTierByDid capping the signer's own DID). This clamp makes that
 * structural rather than convention-dependent.
 *
 * This is the single chokepoint every tier-weighted read must go through so a
 * forged, provenance-unknown, OR provably-local attestation cannot inflate
 * its scoring weight. It never RAISES a tier.
 */
export function trustedSovereigntyTier(
  stored: StoredAttestation
): SovereigntyTier | undefined {
  const declared = stored.attestation.data.sovereignty_tier;
  return clampImportedSovereigntyTier(declared);
}

function computeMedian(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 !== 0
    ? sorted[mid]!
    : (sorted[mid - 1]! + sorted[mid]!) / 2;
}

function aggregateMetrics(
  attestations: StoredAttestation[],
  metricNames?: string[]
): Record<string, MetricAggregate> {
  const result: Record<string, MetricAggregate> = {};

  // Collect all metric names if not specified
  const names =
    metricNames ??
    Array.from(
      new Set(
        attestations.flatMap((a) =>
          Object.keys(a.attestation.data.metrics)
        )
      )
    );

  for (const name of names) {
    const values = attestations
      .map((a) => a.attestation.data.metrics[name])
      // Fail closed: a non-finite metric (Infinity/-Infinity/NaN, e.g. an
      // imported attestation carrying 1e309) must not poison the aggregate.
      .filter((v): v is number => typeof v === "number" && Number.isFinite(v));

    if (values.length === 0) {
      result[name] = { mean: 0, median: 0, min: 0, max: 0, count: 0 };
      continue;
    }

    result[name] = {
      mean: values.reduce((s, v) => s + v, 0) / values.length,
      median: computeMedian(values),
      min: Math.min(...values),
      max: Math.max(...values),
      count: values.length,
    };
  }

  return result;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }

  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .filter((key) => record[key] !== undefined)
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

function compareStrings(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

function sortedAttestations(attestations: Attestation[]): Attestation[] {
  return [...attestations].sort((a, b) =>
    compareStrings(canonicalJson(a), canonicalJson(b))
  );
}

export function buildReputationCompletenessManifest(
  exportedAt: string,
  attestations: Attestation[]
): ReputationCompletenessManifest {
  const contexts = Array.from(
    new Set(attestations.map((a) => a.data.context))
  ).sort(compareStrings);
  const contextAttestations: Record<string, ReputationContextCompleteness> = {};

  for (const context of contexts) {
    const inContext = sortedAttestations(
      attestations.filter((a) => a.data.context === context)
    );
    contextAttestations[context] = {
      attestation_count: inContext.length,
      content_checksum_sha256: hashToString(
        stringToBytes(canonicalJson(inContext))
      ),
    };
  }

  return {
    schema_version: REPUTATION_COMPLETENESS_MANIFEST_SCHEMA_VERSION,
    format: "SANCTUARY_REP_V1",
    exported_at: exportedAt,
    total_attestation_count: attestations.length,
    context_count: contexts.length,
    contexts,
    context_attestations: contextAttestations,
  };
}

export function reputationBundleSigningBytes(bundle: {
  version: "SANCTUARY_REP_V1";
  attestations: Attestation[];
  exported_at: string;
  exporter_did: string;
  completeness_manifest?: ReputationCompletenessManifest;
}): Uint8Array {
  return stringToBytes(
    canonicalJson({
      version: bundle.version,
      attestations: bundle.attestations,
      exported_at: bundle.exported_at,
      exporter_did: bundle.exporter_did,
      completeness_manifest: bundle.completeness_manifest,
    })
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isBridgeCommitmentRecord(value: unknown): value is BridgeCommitment {
  return (
    isRecord(value) &&
    typeof value.bridge_commitment_id === "string" &&
    typeof value.session_id === "string" &&
    typeof value.sha256_commitment === "string" &&
    typeof value.blinding_factor === "string" &&
    typeof value.committer_did === "string" &&
    typeof value.signature === "string" &&
    typeof value.committed_at === "string" &&
    value.bridge_version === "sanctuary-concordia-bridge-v1"
  );
}

function isConcordiaOutcomeRecord(value: unknown): value is ConcordiaOutcome {
  return (
    isRecord(value) &&
    typeof value.session_id === "string" &&
    value.protocol_version === "concordia-v1" &&
    typeof value.proposer_did === "string" &&
    typeof value.acceptor_did === "string" &&
    isRecord(value.terms) &&
    typeof value.terms_hash === "string" &&
    typeof value.rounds === "number" &&
    Number.isInteger(value.rounds) &&
    value.rounds >= 1 &&
    value.rounds <= 64 &&
    typeof value.accepted_at === "string"
  );
}

function withAttestationMetrics(
  stored: StoredAttestation,
  metrics: Record<string, number>
): StoredAttestation {
  return {
    ...stored,
    attestation: {
      ...stored.attestation,
      data: {
        ...stored.attestation.data,
        metrics,
      },
    },
  };
}

function assertSupportedReputationBundleShape(
  bundle: unknown
): asserts bundle is ReputationBundle {
  if (!isRecord(bundle)) {
    throw new ReputationBundleVerificationError(
      "Reputation bundle must be a JSON object"
    );
  }
  if (
    bundle.version !== "SANCTUARY_REP_V1" ||
    !Array.isArray(bundle.attestations) ||
    typeof bundle.exported_at !== "string" ||
    typeof bundle.exporter_did !== "string" ||
    typeof bundle.bundle_signature !== "string"
  ) {
    throw new ReputationBundleVerificationError(
      "Reputation bundle schema is unsupported"
    );
  }
}

/**
 * Recompute and verify the public completeness manifest for a reputation
 * bundle. This does not verify bundle or attestation signatures; callers that
 * need provenance verification must run signature checks separately.
 */
export function verifyReputationBundleCompleteness(
  bundle: unknown,
  options: { allowUnverifiedLegacy?: boolean } = {}
): ReputationBundleCompletenessVerification {
  assertSupportedReputationBundleShape(bundle);

  const manifest = bundle.completeness_manifest;
  if (manifest === undefined) {
    if (options.allowUnverifiedLegacy !== true) {
      throw new ReputationBundleVerificationError(
        REPUTATION_LEGACY_REJECT_MESSAGE
      );
    }
    return "unverified-completeness-legacy-bundle";
  }

  if (!isRecord(manifest)) {
    throw new ReputationBundleVerificationError(
      "Reputation bundle completeness manifest is malformed"
    );
  }

  const schemaVersion = manifest.schema_version;
  if (typeof schemaVersion !== "number") {
    throw new ReputationBundleVerificationError(
      "Reputation bundle completeness schema metadata is malformed"
    );
  }
  if (schemaVersion > REPUTATION_COMPLETENESS_MANIFEST_SCHEMA_VERSION) {
    throw new ReputationBundleVerificationError(
      "Reputation bundle completeness schema version is newer than this build supports"
    );
  }
  if (schemaVersion !== REPUTATION_COMPLETENESS_MANIFEST_SCHEMA_VERSION) {
    throw new ReputationBundleVerificationError(
      "Reputation bundle completeness schema version is unsupported"
    );
  }

  const expectedManifest = buildReputationCompletenessManifest(
    bundle.exported_at,
    bundle.attestations
  );
  if (
    manifest.format !== "SANCTUARY_REP_V1" ||
    manifest.exported_at !== bundle.exported_at ||
    manifest.total_attestation_count !== bundle.attestations.length ||
    canonicalJson(manifest) !== canonicalJson(expectedManifest)
  ) {
    throw new ReputationBundleVerificationError(
      "Reputation bundle completeness manifest does not match contents"
    );
  }

  return "verified";
}

// ─── Reputation Store: growth bounds (LD3 gate fix-round, DEFECT 1) ───────
//
// record() and importBundle() are the TWO writers of `_reputation`, and (LD3
// gate fix-round-2, MUST-FIX 1) both now route their writes through the SAME
// low-level admission+quota primitive: assertRecordQuotaForCount() run inside
// runAdmissionExclusiveBounded()'s single per-instance lock. The pre-fix
// BRIDGE-BP-01 pass bounded only bridge_attest's OWN per-origin-per-context
// share of `_reputation` (see countAttestationsByOriginForContext); the
// generic, Tier-2 (anomaly-gated-auto-allow) `reputation_record` MCP tool
// called record() directly with no origin and no cap, so an attacker could
// grow `_reputation` without bound through THAT tool alone. The fix-round-1
// pass closed that for record() but left importBundle() writing directly
// (bypassing both the quota check and the admission lock) — a Tier-1
// (human-approved) `reputation_import` call could still grow `_reputation`
// past the cap indefinitely across repeated approved imports, and every O(N)
// decrypt-scan over `_reputation` (this file has several) had no real
// worst-case bound as long as EITHER writer could bypass it. Bounding the
// SHARED PRIMITIVE both writers call — rather than one more consumer —
// closes the class for every present and future writer, mirroring the
// "bound at the shared substrate, not one consumer" lesson BridgeStore/
// MAX_HANDSHAKE_* already apply to their own namespaces. A SECOND, INSTANCE-
// level defect (LD3 gate fix-round-2, MUST-FIX 2) compounded this: production
// constructed TWO ReputationStore instances over the SAME `_reputation`
// backend (createReputationTools and createBridgeTools each built their own),
// so even a correctly-bounded chokepoint had two independent in-memory
// admission locks and quota views that could both observe headroom and both
// write, overshooting the cap together. index.ts now constructs exactly ONE
// ReputationStore and injects it into both tool factories — see index.ts's
// composition-root comment at the `createBridgeTools` call site.

/**
 * Global ceiling on total persisted `_reputation` records, checked by
 * record() before every write. 20000 mirrors the 10x global/per-origin
 * ratio MAX_BRIDGE_COMMITMENTS/MAX_BRIDGE_COMMITMENTS_PER_ORIGIN and
 * MAX_HANDSHAKE_SESSIONS/MAX_HANDSHAKE_SESSIONS_PER_ORIGIN already use
 * (bridge/tools.ts, handshake/tools.ts), sized up from those because
 * `_reputation` is the single aggregation point for EVERY context
 * (general reputation_record traffic plus every bridge_attest write),
 * not one bridge-specific namespace — generous headroom for a real
 * fortress's full interaction history while still bounding every scan's
 * worst case.
 */
export const MAX_REPUTATION_RECORDS = 20000;

/**
 * Per-origin quota for `_reputation` writes, checked by record() before
 * every write. Bound to the SERVER-SET agent-session principal
 * (`callerIdentity`), NEVER a caller-supplied field: `identity_id` is
 * Tier-3 `identity_create`-mintable (see resolveTierByDid's and
 * resolveBridgeOrigin's docs for the same defeat), so keying this quota on
 * it would be defeated by minting a fresh identity per call. 2000 = 1/10th
 * of MAX_REPUTATION_RECORDS, the same ratio used above.
 */
export const MAX_REPUTATION_RECORDS_PER_ORIGIN = 2000;

/**
 * Shared bucket a record() call with no resolvable session origin pools
 * into, so an unattributed write is still quota-accounted rather than
 * exempted from the cap entirely. Mirrors AGENT_UNKNOWN_ORIGIN
 * (handshake/tools.ts) / resolveBridgeOrigin's fallback (bridge/tools.ts)
 * — kept as this module's OWN constant (same string value, not a shared
 * import) so reputation-store.ts, a low-level storage module, does not need
 * to import the much larger handshake/tools.ts just for one literal.
 */
export const REPUTATION_UNKNOWN_ORIGIN = "agent:unknown";

/** Reason a `_reputation` write was refused (LD3 gate fix-round DEFECT 1). */
export type ReputationStoreRefuseReason =
  | "origin_quota"
  | "capacity"
  | "scan_unavailable"
  | "admission_busy";

/**
 * Typed refusal thrown by ReputationStore's record()/importBundle()
 * chokepoint quota check. `capacity` and `origin_quota` are ordinary
 * fail-closed refusals; `scan_unavailable` means the pre-write quota scan
 * itself could not complete (a storage.list error, or an entry that failed
 * to read/decrypt) — treated as a refusal rather than "assume headroom,"
 * mirroring BridgeStoreQuotaError's identical contract on the sibling
 * `_bridge` namespace (bridge/tools.ts). `admission_busy` (LD3 gate
 * fix-round-2, MUST-FIX 3) is a FOURTH, distinct reason: this call never
 * even reached the quota scan, because MAX_PENDING_ADMISSION_WAITERS other
 * callers were already queued for this store's admission lock — see
 * `runAdmissionExclusiveBounded`'s doc.
 */
export class ReputationStoreQuotaError extends Error {
  readonly reason: ReputationStoreRefuseReason;
  constructor(reason: ReputationStoreRefuseReason) {
    super(
      reason === "origin_quota"
        ? "Reputation store: origin per-write quota exceeded"
        : reason === "capacity"
          ? "Reputation store: capacity exceeded"
          : reason === "admission_busy"
            ? "Reputation store: admission queue is saturated; refusing to " +
              "write (retry shortly)"
            : "Reputation store: could not confirm quota headroom " +
              "(storage scan failed); refusing to write"
    );
    this.name = "ReputationStoreQuotaError";
    this.reason = reason;
  }
}

/**
 * Test-only override for the record()/importBundle()-chokepoint growth
 * bounds (LD3 gate fix-round DEFECT 1 / fix-round-2). Production call sites
 * never set this — it exists solely so a capacity/quota-refusal test can
 * drive a small cap instead of performing thousands of real writes to reach
 * the production ceiling (mirrors BridgeToolsTestOverrides in
 * bridge/tools.ts).
 */
export interface ReputationStoreTestOverrides {
  maxReputationRecords?: number;
  maxReputationRecordsPerOrigin?: number;
  /**
   * Cap on this store's admission-WAITER queue (LD3 gate fix-round-2,
   * MUST-FIX 3). Defaults to MAX_PENDING_ADMISSION_WAITERS (core/
   * bounded-map.ts — shared, not re-derived). Test-only override, same
   * shape as the two above.
   */
  maxPendingAdmissionWaiters?: number;
}

/**
 * Bounds the whole admission critical section `runAdmissionExclusiveBounded`
 * guards (LD3 gate fix-round-2, MUST-FIX 3 — same class as
 * core/bounded-map.ts's `onEvict` timeout and
 * sentinel-finding-store.ts's `STORE_ADMISSION_DEADLINE_MS`, applied here to
 * `_reputation`'s own admission lock): a hung `storage.list`/`read`/`write`
 * call inside the locked section would otherwise retain the lock
 * indefinitely and wedge every later record()/importBundle() admission
 * behind it. ON_EVICT_AUDIT_TIMEOUT_MS is reused rather than re-derived (it
 * is itself derived from audit-log.ts's two-phase lock-acquisition + write-
 * hold deadline contract — see that constant's doc, core/bounded-map.ts);
 * STORAGE_OP_MARGIN_MS is a defensive backstop for this store's OWN
 * storage.list/read/write calls, which carry no settle-time contract at all
 * (storage/interface.ts). Kept as a LOCAL constant, not imported from
 * sentinel-finding-store.ts, for the same module-boundary reason
 * REPUTATION_UNKNOWN_ORIGIN is this file's own constant rather than an
 * import — the two derivations must stay numerically identical, which is
 * why both are pinned to ON_EVICT_AUDIT_TIMEOUT_MS + the same margin
 * (cross-file pin: must match STORAGE_OP_MARGIN_MS /
 * STORE_ADMISSION_DEADLINE_MS in sentinel-finding-store.ts and
 * bridge/tools.ts).
 *
 * ACCEPTED RESIDUAL (mirrors sentinel-finding-store.ts's paragraph,
 * recorded honestly, not "fixed"): a storage call that hangs PAST this
 * deadline and later completes can still land detached write(s) after the
 * triggering admission was already refused — the deadline stops this call
 * from WAITING, it cannot CANCEL the underlying storage operation (no
 * cancellation or compare-and-swap primitive exists). For a single-record
 * `record()` the overshoot is bounded to exactly one extra write. For a
 * BATCH `importBundle()` the timed-out closure can continue its write loop,
 * so the overshoot is bounded by that ONE bundle's size — and that size is
 * itself bounded because `assertRecordQuotaForCount` refuses the whole
 * bundle up front if it would exceed the cap, so a single import never
 * writes more than the headroom the batch check permitted; a second
 * admission may then also write once the deadline releases the queue. The
 * overshoot is therefore bounded (never unbounded growth) and requires
 * storage to pathologically hang past a multi-second deadline and still
 * succeed. Reachability is further limited: both importBundle paths are
 * OPERATOR-gated (`reputation_import` is tier1_always_approve; the exit CLI
 * is a separate operator process), so this is not an in-server Tier-3
 * agent-reachable cap bypass. Cross-process concurrency is the separate
 * accepted DEBT (bridge/tools.ts). The per-refusal `admission_busy` audit
 * append is 1:1 with a real MCP round-trip (not N×M); the uncapped audit
 * queue it feeds is the separately-tracked systemic item (register AUD-BP-01).
 */
const REPUTATION_STORAGE_OP_MARGIN_MS = 10_000;
const REPUTATION_STORE_ADMISSION_DEADLINE_MS =
  ON_EVICT_AUDIT_TIMEOUT_MS + REPUTATION_STORAGE_OP_MARGIN_MS;

/**
 * Race `promise` against a timer that rejects after `ms`. Mirrors
 * core/bounded-map.ts's (unexported) `withTimeout` / sentinel-finding-
 * store.ts's `withDeadline` — reproduced here rather than reaching across a
 * module boundary for a five-line helper (same reasoning as
 * REPUTATION_UNKNOWN_ORIGIN's doc). Used only to bound
 * runAdmissionExclusiveBounded's critical section; a timeout here rejects
 * the whole admission call, the same fail-closed outcome as any other
 * admission failure.
 */
function withReputationAdmissionDeadline<T>(
  promise: Promise<T>,
  ms: number
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(
        new Error(
          `reputation-store: admission did not settle within ${ms}ms`
        )
      );
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

// ─── Reputation Store ─────────────────────────────────────────────────────

export class ReputationStore {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;
  /** Held for custody-floor envelope authentication (never logged). */
  private masterKey: Uint8Array;
  private readonly maxRecords: number;
  private readonly maxRecordsPerOrigin: number;
  private readonly maxPendingAdmissionWaiters: number;
  /**
   * Live count of callers currently occupying this store's admission-waiter
   * cap (LD3 gate fix-round-2, MUST-FIX 3 — mirrors BoundedMap's
   * `pendingAdmissionWaiters`, core/bounded-map.ts, and
   * sentinel-finding-store.ts's field of the same name). Incremented
   * SYNCHRONOUSLY in `runAdmissionExclusiveBounded` before its first
   * `await`, decremented in a `finally` once the admission settles either
   * way — the synchronous check-then-increment needs no separate lock
   * because both happen in the same tick, with no `await` between them.
   */
  private pendingAdmissionWaiters = 0;
  /**
   * Serializes the check-then-write critical section in record() and
   * importBundle() (LD3 gate fix-round DEFECT 2 / fix-round-2 MUST-FIX 1): a
   * single promise chain per ReputationStore INSTANCE, not per origin,
   * because assertRecordQuotaForCount reads both the per-origin count AND
   * the global `_reputation` size — a lock scoped to one origin could not
   * stop two DIFFERENT origins from racing past the global
   * MAX_REPUTATION_RECORDS ceiling together. Mirrors BoundedMap's
   * `admissionQueue` (core/bounded-map.ts): chain the next call onto the
   * settled tail of the previous one, so the WHOLE quota-check-then-persist
   * section (including any caller-supplied `additionalQuotaCheck`, and
   * importBundle()'s whole write loop) runs start to finish with no other
   * record()/importBundle() interleaved — this is what closes the TOCTOU
   * the pre-fix version left open (many concurrent callers all observing
   * capacity BEFORE any of them wrote, then all writing and overshooting
   * the cap). ONLY reached via `runAdmissionExclusiveBounded` below, which
   * adds the waiter cap and settlement deadline this raw chain does not
   * enforce on its own.
   */
  private admissionQueue: Promise<void> = Promise.resolve();

  constructor(
    storage: StorageBackend,
    masterKey: Uint8Array,
    testOverrides?: ReputationStoreTestOverrides
  ) {
    this.storage = storage;
    this.masterKey = masterKey;
    this.encryptionKey = derivePurposeKey(masterKey, "l4-reputation");
    this.maxRecords = testOverrides?.maxReputationRecords ?? MAX_REPUTATION_RECORDS;
    this.maxRecordsPerOrigin =
      testOverrides?.maxReputationRecordsPerOrigin ?? MAX_REPUTATION_RECORDS_PER_ORIGIN;
    this.maxPendingAdmissionWaiters =
      testOverrides?.maxPendingAdmissionWaiters ?? MAX_PENDING_ADMISSION_WAITERS;
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
   * MUST-FIX 3 — mirrors `SentinelFindingStore.runAdmissionExclusive` /
   * `BoundedMap`'s waiter-cap pattern exactly, core/bounded-map.ts and
   * sentinel/sentinel-finding-store.ts). Two properties `runAdmissionExclusive`
   * alone does not provide:
   *
   * 1. WAITER CAP: the queue of callers WAITING to chain onto
   *    `admissionQueue` is itself attacker-influenceable state (every
   *    `record()`/`importBundle()` call from a Tier-2/Tier-1 tool can queue
   *    one), so it needs its own bound (AGENTS.md rule 8, applied to the
   *    serialization primitive's OWN state, not just the collection it
   *    protects). Checked and incremented SYNCHRONOUSLY, before this
   *    method's first `await` — TOCTOU-safe with no extra lock because both
   *    happen in the same tick. A refusal here never calls
   *    `runAdmissionExclusive`: the closure is never constructed, never
   *    chained onto `admissionQueue`, so a refused call leaves the queue
   *    exactly as it was and cannot itself contribute to a wedge.
   * 2. SETTLEMENT DEADLINE: `fn` races against
   *    REPUTATION_STORE_ADMISSION_DEADLINE_MS via
   *    withReputationAdmissionDeadline — a hung `storage.list`/`read`/
   *    `write` call inside `fn` cannot retain this lock past that deadline;
   *    the queue still advances for the NEXT admission even though the hung
   *    operation itself keeps running detached (see that constant's doc for
   *    the accepted, bounded residual this trade-off leaves).
   */
  private async runAdmissionExclusiveBounded<T>(fn: () => Promise<T>): Promise<T> {
    if (this.pendingAdmissionWaiters >= this.maxPendingAdmissionWaiters) {
      throw new ReputationStoreQuotaError("admission_busy");
    }
    this.pendingAdmissionWaiters += 1;
    try {
      return await this.runAdmissionExclusive(() =>
        withReputationAdmissionDeadline(fn(), REPUTATION_STORE_ADMISSION_DEADLINE_MS)
      );
    } finally {
      this.pendingAdmissionWaiters -= 1;
    }
  }

  /**
   * Scan `_reputation` and enforce both the global MAX_REPUTATION_RECORDS
   * ceiling and `origin`'s MAX_REPUTATION_RECORDS_PER_ORIGIN share against
   * an incoming batch of `additionalCount` new records (LD3 gate fix-round
   * DEFECT 1 / fix-round-2 MUST-FIX 1 — generalized from a single-record
   * check to a batch check so importBundle() can enforce the cap for its
   * WHOLE bundle atomically, all-or-nothing, rather than admitting records
   * up to the cap and silently dropping the rest). `additionalCount <= 0`
   * is a no-op (an empty bundle needs no headroom and must not be refused
   * merely because the store happens to be full). Fails CLOSED: a
   * storage.list error, or any entry that cannot be read/decrypted, throws
   * `scan_unavailable` rather than silently treating an unscannable entry as
   * "not this origin" — the same fail-closed posture
   * findExistingAttestationForDedup and countAttestationsByOriginForContext
   * already use scanning this exact namespace. MUST be called only from
   * inside runAdmissionExclusiveBounded (see record()/importBundle()) so
   * this check and the write(s) it gates can never be split by a concurrent
   * write.
   */
  private async assertRecordQuotaForCount(
    origin: string,
    additionalCount: number
  ): Promise<void> {
    if (additionalCount <= 0) return;

    let entries: Array<{ key: string }>;
    try {
      entries = await this.storage.list("_reputation");
    } catch {
      throw new ReputationStoreQuotaError("scan_unavailable");
    }

    if (entries.length + additionalCount > this.maxRecords) {
      throw new ReputationStoreQuotaError("capacity");
    }

    let originCount = 0;
    for (const meta of entries) {
      let raw: Uint8Array | null;
      try {
        raw = await this.storage.read("_reputation", meta.key);
      } catch {
        throw new ReputationStoreQuotaError("scan_unavailable");
      }
      if (!raw) continue;
      try {
        const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
        const decrypted = decrypt(encrypted, this.encryptionKey);
        const record = JSON.parse(bytesToString(decrypted)) as { origin?: string };
        if (record.origin === origin) originCount++;
      } catch {
        throw new ReputationStoreQuotaError("scan_unavailable");
      }
    }

    if (originCount + additionalCount > this.maxRecordsPerOrigin) {
      throw new ReputationStoreQuotaError("origin_quota");
    }
  }

  /**
   * Single-record convenience wrapper around assertRecordQuotaForCount, used
   * by record(). See that method's doc for the batch shape importBundle()
   * uses instead.
   */
  private async assertRecordQuota(origin: string): Promise<void> {
    return this.assertRecordQuotaForCount(origin, 1);
  }

  /**
   * Resolve the record()/importBundle() quota-key origin (LD3 gate
   * fix-round DEFECT 1 / fix-round-2 MUST-FIX 1): an absent or empty origin
   * pools into REPUTATION_UNKNOWN_ORIGIN rather than exempting the write
   * from quota entirely — see REPUTATION_UNKNOWN_ORIGIN's doc. ONE
   * definition shared by both writers so their fallback behavior can never
   * drift apart.
   */
  private static resolveOrigin(origin: string | undefined): string {
    return origin !== undefined && origin.length > 0 ? origin : REPUTATION_UNKNOWN_ORIGIN;
  }

  /**
   * Record an interaction outcome as a signed attestation.
   *
   * `origin` (LD3 gate fix-round DEFECT 1, optional, trailing): the
   * SERVER-SET agent-session principal that quota-gates this write via the
   * record()-chokepoint bound (MAX_REPUTATION_RECORDS /
   * MAX_REPUTATION_RECORDS_PER_ORIGIN, enforced by assertRecordQuota
   * above), and is stamped onto the stored record's `origin` provenance
   * field (see StoredAttestation's doc) for both that bound's own future
   * scans and countAttestationsByOriginForContext's narrower context-scoped
   * scan to count on a later write. UNLIKE the pre-fix version of this
   * parameter, an absent/empty `origin` no longer means "this call site's
   * growth is unbounded": every call resolves to a real origin or the
   * shared REPUTATION_UNKNOWN_ORIGIN bucket below, so EVERY writer — the
   * general-purpose `reputation_record` tool, bridge_attest, and any direct
   * caller (tests, internal tooling) — is quota-bound by this single
   * chokepoint, not just the call site that happens to resolve and pass a
   * real session origin. See the DEFECT-1 header comment above this class
   * for why bounding the chokepoint replaced the old bridge_attest-only
   * quota as the source of truth for this bound.
   *
   * `additionalQuotaCheck` (LD3 gate fix-round DEFECT 2, optional): an
   * extra async check the caller needs evaluated ATOMICALLY with this
   * write — e.g. bridge_attest's own narrower, context-scoped
   * MAX_BRIDGE_ATTESTATIONS_PER_ORIGIN quota (bridge/tools.ts). It runs
   * INSIDE the same admission-locked section as assertRecordQuota, right
   * before the write it gates, with no await between the check and the
   * write — composing a caller's own pre-write check into record()'s
   * single-flight section is what closes a TOCTOU a caller-side check (run
   * BEFORE calling record(), separated from the eventual write by this
   * method's own awaits) could not: N concurrent callers all observing
   * headroom via their own separate scan, then all calling record() and
   * overshooting their own quota. A throw here aborts the write; nothing
   * is persisted.
   */
  async record(
    interactionId: string,
    counterpartyDid: string,
    outcome: InteractionOutcome,
    context: string,
    identity: StoredIdentity,
    identityEncryptionKey: Uint8Array,
    counterpartyAttestation?: string,
    sovereigntyTier?: SovereigntyTier,
    origin?: string,
    additionalQuotaCheck?: () => Promise<void>
  ): Promise<StoredAttestation> {
    const resolvedOrigin = ReputationStore.resolveOrigin(origin);
    const attestationId = `att-${Date.now()}-${toBase64url(randomBytes(8))}`;
    const now = new Date().toISOString();
    const metrics = isConcordiaBridgeReputationContext(context)
      ? assertRecordableBridgeAttestationMetrics(
          outcome.metrics,
          outcome.metric_policy
        )
      : outcome.metrics ?? {};

    // Build the attestation data
    const attestationData: Attestation["data"] = {
      interaction_id: interactionId,
      participant_did: identity.did,
      counterparty_did: counterpartyDid,
      outcome_type: outcome.type,
      outcome_result: outcome.result,
      metrics,
      ...(outcome.metric_policy !== undefined
        ? { metric_policy: outcome.metric_policy }
        : {}),
      context,
      timestamp: now,
      sovereignty_tier: sovereigntyTier,
    };
    await this.assertPolicyRatedBridgeAttestationHasLocalCommitment(
      attestationData
    );

    // Sign the attestation data
    const dataBytes = stringToBytes(JSON.stringify(attestationData));
    const signature = sign(
      dataBytes,
      identity.encrypted_private_key,
      identityEncryptionKey
    );

    const attestation: Attestation = {
      attestation_id: attestationId,
      schema: "sanctuary-interaction-v1",
      data: attestationData,
      signature: toBase64url(signature),
      signer: identity.did,
    };

    const stored: StoredAttestation = {
      attestation,
      // A raw counterparty attachment is retained but never treated as a
      // verified countersignature: there is no counterparty-signature verifier,
      // so no confirmation flag is emitted (the presence-only flag was removed).
      counterparty_attestation: counterpartyAttestation,
      recorded_at: now,
      // Provably local provenance (this tier came from a handshake this
      // instance witnessed, or from the self-attested cap resolveTierByDid
      // applies to a local signer). Stamped explicitly, not left absent,
      // because absent fails closed. Retained for audit/export/dedup
      // provenance; it no longer exempts this record from the
      // trustedSovereigntyTier clamp (A11 — the clamp is unconditional).
      imported: false,
      // Always stamped now (LD3 gate fix-round DEFECT 1) — `resolvedOrigin`
      // is never undefined, so every record is quota-attributed to a real
      // origin or the shared REPUTATION_UNKNOWN_ORIGIN bucket, never left
      // unattributed the way a pre-fix caller with no origin was.
      origin: resolvedOrigin,
    };

    // DEFECT 1 (chokepoint bound) + DEFECT 2 (TOCTOU close), LD3 gate
    // fix-round: the quota check and the persist run inside ONE
    // admission-locked section so no concurrent record() call — for this
    // origin, another origin, or the global cap — can observe stale
    // headroom between the check and this write. `additionalQuotaCheck`
    // (if supplied) runs in the SAME section, immediately before the
    // write, for the same reason — see record()'s doc. Routed through
    // runAdmissionExclusiveBounded (fix-round-2, MUST-FIX 3), not the raw
    // runAdmissionExclusive, so a flood of concurrent record() calls
    // refuses fail-closed at the waiter cap instead of growing the
    // in-memory queue without bound.
    return this.runAdmissionExclusiveBounded(async () => {
      await this.assertRecordQuota(resolvedOrigin);
      if (additionalQuotaCheck) {
        await additionalQuotaCheck();
      }

      const serialized = stringToBytes(JSON.stringify(stored));
      const encrypted = encrypt(serialized, this.encryptionKey);
      await this.storage.write(
        "_reputation",
        attestationId,
        stringToBytes(JSON.stringify(encrypted))
      );

      return stored;
    });
  }

  /**
   * Find a single existing attestation matching an interaction identity tuple.
   * Used for idempotency / replay-resistance at the recording boundary (e.g.
   * the bridge's attest path) so a party cannot RE-ATTEST the SAME negotiation:
   * matching on the full identifying tuple (interaction id == Concordia
   * session_id, participant/signer DID, counterparty DID, and context) collapses
   * repeated bridge_attest calls on one session into a single recorded
   * attestation. Distinct parties, or the same party in a different context or
   * interaction, are NOT deduped. Returns the FIRST match by stable
   * attestation_id ordering for determinism.
   *
   * SCOPE (do not overclaim): this closes the same-negotiation / same-session
   * replay only. It does NOT prevent a party from minting MULTIPLE distinct
   * commitments for one real negotiation, because the interaction_id is the
   * caller-supplied Concordia session_id and the bridge does not verify a
   * session_receipt anchor here. So choosing a fresh session_id per call still
   * lets one real negotiation self-inflate the tallies N-fold. That broader
   * self-inflation is NOT closed by this dedup and is a known scoring-engine /
   * collusion concern (the bridge cannot prove a Concordia session is unique or
   * real without a verified session_receipt). See findExistingAttestationForDedup
   * for the fail-closed variant the bridge actually calls.
   */
  async findExistingAttestation(criteria: {
    interaction_id: string;
    participant_did: string;
    counterparty_did: string;
    context: string;
  }): Promise<StoredAttestation | null> {
    const result = await this.findExistingAttestationForDedup(criteria);
    return result.match;
  }

  /**
   * Fail-closed dedup scan for the attest boundary.
   *
   * Unlike loadAllPaginated / query / loadAll (which deliberately SKIP a
   * storage.list error or a corrupted entry so aggregate reads degrade
   * gracefully), the dedup path must fail CLOSED: if a pre-existing matching
   * attestation happens to be the entry that cannot be listed/read/decrypted,
   * a silent skip would let the caller record a SECOND attestation under a
   * transient error (a double-count). So this scan reports `scanComplete:false`
   * whenever the namespace listing throws OR any per-entry load/decrypt fails,
   * and the caller (bridge_attest) must DENY the attest rather than risk a
   * duplicate.
   *
   * Returns `{ match, scanComplete }`:
   * - `match`: the first matching attestation by stable id ordering, or null.
   * - `scanComplete`: false if the scan could not reliably confirm uniqueness
   *   (a list error, or any entry that failed to load/decrypt during the scan).
   *
   * Scoped to dedup ONLY; other callers keep skip-corrupted aggregate reads.
   */
  async findExistingAttestationForDedup(criteria: {
    interaction_id: string;
    participant_did: string;
    counterparty_did: string;
    context: string;
  }): Promise<{ match: StoredAttestation | null; scanComplete: boolean }> {
    let entries: Array<{ key: string }>;
    try {
      entries = await this.storage.list("_reputation");
    } catch {
      // Cannot enumerate the namespace, so cannot confirm uniqueness: fail closed.
      return { match: null, scanComplete: false };
    }

    let match: StoredAttestation | null = null;
    let scanComplete = true;

    for (const meta of entries) {
      let raw: Uint8Array | null;
      try {
        raw = await this.storage.read("_reputation", meta.key);
      } catch {
        // A read error on an entry we needed to inspect: cannot confirm the
        // pre-existing attestation is not THIS entry. Fail closed.
        scanComplete = false;
        continue;
      }
      if (!raw) continue;

      let stored: StoredAttestation;
      try {
        const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
        const decrypted = decrypt(encrypted, this.encryptionKey);
        stored = JSON.parse(bytesToString(decrypted));
      } catch {
        // A corrupted / undecryptable entry might BE the pre-existing match;
        // we cannot rule it out, so the scan is incomplete. Fail closed.
        scanComplete = false;
        continue;
      }

      const d = stored.attestation.data;
      if (
        d.interaction_id === criteria.interaction_id &&
        d.participant_did === criteria.participant_did &&
        d.counterparty_did === criteria.counterparty_did &&
        d.context === criteria.context
      ) {
        if (
          match === null ||
          stored.attestation.attestation_id < match.attestation.attestation_id
        ) {
          match = stored;
        }
      }
    }

    return { match, scanComplete };
  }

  /**
   * Count existing `_reputation` records in `context` whose stored
   * `origin` provenance marker (LD3 BRIDGE-BP-01, see StoredAttestation's
   * doc) matches `origin`. Used by bridge_attest (bridge/tools.ts) to
   * bound its own narrower, context-scoped MAX_BRIDGE_ATTESTATIONS_PER_ORIGIN
   * share of Concordia-bridge attestations specifically — as of the LD3
   * gate fix-round DEFECT 2 close, that call now runs INSIDE record()'s own
   * `additionalQuotaCheck` (see record()'s doc), not before calling
   * record(), so this scan's result and the write it gates can never be
   * split by a concurrent write. `origin` must be the SERVER-SET
   * agent-session principal, never a caller-supplied field.
   *
   * Fails CLOSED on the same terms as findExistingAttestationForDedup:
   * `scanComplete: false` on a storage.list error, or any entry that
   * cannot be read/decrypted, because a skipped entry might be the one
   * that would put `origin` over quota, and undercounting would let the
   * caller record past its cap.
   *
   * DEBT (LD3 BRIDGE-BP-01, scope; corrected LD3 gate fix-round DEFECT 3 —
   * see the register): a second full-namespace decrypt scan of
   * `_reputation`, alongside the dedup scan bridge_attest already runs via
   * findExistingAttestationForDedup. Both exist because `_reputation` has
   * no origin index; adding one (an in-memory count cache, built once and
   * maintained incrementally) would remove this, but is a larger
   * structural change than this narrow scan-shape goal —
   * BridgeStore.assertOriginWithinQuota in bridge/tools.ts records the
   * matching DEBT note for `_bridge`. CORRECTED CLAIM (fix-round-2
   * RECHECK): the fix-round-1 text here asserted this scan's worst case was
   * bounded by "this fix" while `_reputation`'s total SIZE was in fact
   * still unbounded through TWO other paths — the `reputation_record` tool
   * wrote to the same namespace with no cap at all (DEFECT 1), and
   * importBundle() wrote directly, bypassing the chokepoint entirely (LD3
   * gate fix-round-2 MUST-FIX 1) — so the claim was false both times it was
   * written. It is true now: record() AND importBundle() both route through
   * the SAME MAX_REPUTATION_RECORDS chokepoint (assertRecordQuotaForCount,
   * this file, above), and that chokepoint is enforced from a SINGLE
   * ReputationStore instance in production (index.ts constructs one and
   * injects it into both createReputationTools and createBridgeTools — LD3
   * gate fix-round-2 MUST-FIX 2), so `_reputation`'s total size is bounded
   * for every writer, which is what actually bounds this scan's worst case.
   * The scan's algorithmic shape (a full O(N) decrypt pass) is unchanged and
   * remains DEBT, now honestly bounded rather than falsely claimed bounded.
   */
  async countAttestationsByOriginForContext(
    origin: string,
    context: string
  ): Promise<{ count: number; scanComplete: boolean }> {
    let entries: Array<{ key: string }>;
    try {
      entries = await this.storage.list("_reputation");
    } catch {
      return { count: 0, scanComplete: false };
    }

    let count = 0;
    let scanComplete = true;

    for (const meta of entries) {
      let raw: Uint8Array | null;
      try {
        raw = await this.storage.read("_reputation", meta.key);
      } catch {
        scanComplete = false;
        continue;
      }
      if (!raw) continue;

      try {
        const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
        const decrypted = decrypt(encrypted, this.encryptionKey);
        const stored: StoredAttestation = JSON.parse(bytesToString(decrypted));
        if (stored.origin === origin && stored.attestation.data.context === context) {
          count++;
        }
      } catch {
        scanComplete = false;
        continue;
      }
    }

    return { count, scanComplete };
  }

  async classifyBridgeMetricEvidence(
    stored: StoredAttestation
  ): Promise<BridgeMetricEvidenceStatus> {
    const data = stored.attestation.data;
    if (!isConcordiaBridgeReputationContext(data.context)) {
      return "none";
    }
    if (Object.keys(data.metrics).length === 0) {
      return "none";
    }
    if (data.metric_policy === BRIDGE_METRIC_POLICY) {
      return (await this.hasLocalBridgeCommitmentForAttestation(data))
        ? "policy_rated"
        : "unverified_policy_claim";
    }
    return data.metric_policy === undefined
      ? "legacy_unbounded_metrics"
      : "unverified_policy_claim";
  }

  async redactUnsafeBridgeMetrics(
    attestations: StoredAttestation[]
  ): Promise<StoredAttestation[]> {
    const redacted: StoredAttestation[] = [];
    for (const stored of attestations) {
      const status = await this.classifyBridgeMetricEvidence(stored);
      redacted.push(
        status === "legacy_unbounded_metrics" ||
          status === "unverified_policy_claim"
          ? withAttestationMetrics(stored, {})
          : stored
      );
    }
    return redacted;
  }

  private async filterExportableBridgeAttestations(
    attestations: StoredAttestation[]
  ): Promise<StoredAttestation[]> {
    const exportable: StoredAttestation[] = [];
    for (const stored of attestations) {
      const status = await this.classifyBridgeMetricEvidence(stored);
      if (
        status === "legacy_unbounded_metrics" ||
        status === "unverified_policy_claim"
      ) {
        continue;
      }
      exportable.push(stored);
    }
    return exportable;
  }

  /**
   * Query reputation data with filtering.
   * Returns aggregates only — not raw interaction data.
   */
  async query(options: {
    context?: string;
    time_range?: { start: string; end: string };
    metrics?: string[];
    counterparty_did?: string;
  }): Promise<ReputationSummary> {
    const all = await this.loadAll();
    let filtered = all;

    if (options.context) {
      filtered = filtered.filter(
        (a) => a.attestation.data.context === options.context
      );
    }

    if (options.time_range) {
      const start = new Date(options.time_range.start).getTime();
      const end = new Date(options.time_range.end).getTime();
      filtered = filtered.filter((a) => {
        const t = new Date(a.attestation.data.timestamp).getTime();
        return t >= start && t <= end;
      });
    }

    if (options.counterparty_did) {
      filtered = filtered.filter(
        (a) => a.attestation.data.counterparty_did === options.counterparty_did
      );
    }

    const contexts = Array.from(
      new Set(filtered.map((a) => a.attestation.data.context))
    );

    const timestamps = filtered.map((a) =>
      new Date(a.attestation.data.timestamp).getTime()
    );
    const start = timestamps.length > 0
      ? new Date(Math.min(...timestamps)).toISOString()
      : new Date().toISOString();
    const end = timestamps.length > 0
      ? new Date(Math.max(...timestamps)).toISOString()
      : new Date().toISOString();
    const aggregateInput = await this.redactUnsafeBridgeMetrics(filtered);

    return {
      total_interactions: filtered.length,
      completed: filtered.filter(
        (a) => a.attestation.data.outcome_result === "completed"
      ).length,
      partial: filtered.filter(
        (a) => a.attestation.data.outcome_result === "partial"
      ).length,
      failed: filtered.filter(
        (a) => a.attestation.data.outcome_result === "failed"
      ).length,
      disputed: filtered.filter(
        (a) => a.attestation.data.outcome_result === "disputed"
      ).length,
      contexts,
      time_range: { start, end },
      aggregate_metrics: aggregateMetrics(aggregateInput, options.metrics),
    };
  }

  /**
   * Export attestations as a portable reputation bundle.
   */
  async exportBundle(
    identity: StoredIdentity,
    identityEncryptionKey: Uint8Array,
    context?: string
  ): Promise<ReputationBundle> {
    let all = await this.loadAll();

    if (context) {
      all = all.filter((a) => a.attestation.data.context === context);
    }

    const exportable = await this.filterExportableBridgeAttestations(all);
    const attestations = exportable.map((a) => a.attestation);
    const exportedAt = new Date().toISOString();
    const completenessManifest = buildReputationCompletenessManifest(
      exportedAt,
      attestations
    );
    const bundleData = {
      version: "SANCTUARY_REP_V1" as const,
      attestations,
      exported_at: exportedAt,
      exporter_did: identity.did,
      completeness_manifest: completenessManifest,
    };

    // Sign the bundle
    const bundleSignature = sign(
      reputationBundleSigningBytes(bundleData),
      identity.encrypted_private_key,
      identityEncryptionKey
    );

    return {
      ...bundleData,
      bundle_signature: toBase64url(bundleSignature),
    };
  }

  /**
   * Import attestations from a reputation bundle.
   * Always verifies bundle and attestation signatures before crediting.
   * The verifySignatures parameter is retained for older internal callers but
   * no longer disables per-attestation verification.
   *
   * Signature verification is NOT bypassable on this path: there is no
   * "accept unverifiable" option. A missing signer key, an absent, a malformed,
   * or a tampered per-attestation signature makes the whole bundle invalid and
   * NOTHING is written. An operator who wants a relaxed, write-free verdict must
   * use the read-only exit-bundle previewer (exit/verifier.ts), which never
   * admits an attestation into the store.
   *
   * GROWTH BOUND (LD3 gate fix-round-2, MUST-FIX 1): before this fix,
   * importBundle wrote every attestation directly to `_reputation`,
   * bypassing BOTH record()'s MAX_REPUTATION_RECORDS(_PER_ORIGIN) quota and
   * its admission lock — `reputation_import` is Tier-1 (human-approved), but
   * an approved import still grows `_reputation` on every call, so repeated
   * approved imports could grow the store past the cap indefinitely, and two
   * concurrent imports (or an import racing a record()/bridge_attest write)
   * could each observe pre-write headroom and both persist, overshooting the
   * cap together. This bundle's writes now run inside the SAME
   * runAdmissionExclusiveBounded section record() uses, checked against
   * assertRecordQuotaForCount for the WHOLE bundle's size up front — so the
   * cap decision is ALL-OR-NOTHING: a bundle that would push `_reputation`
   * past MAX_REPUTATION_RECORDS or `origin`'s MAX_REPUTATION_RECORDS_PER_ORIGIN
   * share is refused in full, with NOTHING written, rather than admitting
   * attestations up to the cap and silently dropping the rest (that
   * up-to-cap-then-drop shape would make a caller's own `imported` count the
   * only signal of a partial, cap-truncated import, easy to miss — refusing
   * whole is the same fail-closed shape signature verification above already
   * uses for this same method: "the whole bundle invalid, NOTHING is
   * written"). `origin` (new, optional, trailing — mirrors record()'s
   * parameter) is the SERVER-SET agent-session principal that performed the
   * `reputation_import` call, resolved via the SAME ReputationStore.resolveOrigin
   * fallback record() uses, so quota is never bypassed by omitting it.
   *
   * @param publicKeys - Map of DID → public key bytes for signature verification
   */
  async importBundle(
    bundle: ReputationBundle,
    _verifySignatures: boolean,
    publicKeys: Map<string, Uint8Array>,
    options: {
      allowUnverifiedLegacy?: boolean;
    } = {},
    origin?: string
  ): Promise<{
    imported: number;
    invalid: number;
    unverifiable: number;
    contexts: string[];
    completeness_verification: ReputationBundleCompletenessVerification;
  }> {
    // Two-factor custody floor (I4/F6): reputation is trust-bearing state.
    // Enforced in the core so no CLI/SDK path can bypass it.
    const { enforceCustodyFloor } = await import("../core/master-custody.js");
    await enforceCustodyFloor(this.storage, "reputation_import", this.masterKey);

    const verification = await this.verifyBundleForImport(
      bundle,
      publicKeys,
      options
    );

    const resolvedOrigin = ReputationStore.resolveOrigin(origin);
    const contexts = new Set<string>();

    // MUST-FIX 1: quota check + every write for this bundle run inside ONE
    // admission-locked, deadline-bounded section (runAdmissionExclusiveBounded
    // — the same primitive record() uses), so a concurrent record(),
    // bridge_attest, or another importBundle() call can never observe stale
    // headroom between this check and these writes. All-or-nothing: if the
    // batch quota check throws, the loop below never runs and NOTHING is
    // written — see this method's doc for why up-to-cap-then-drop was
    // rejected in favor of refuse-whole.
    const imported = await this.runAdmissionExclusiveBounded(async () => {
      await this.assertRecordQuotaForCount(
        resolvedOrigin,
        bundle.attestations.length
      );

      let count = 0;
      for (const attestation of bundle.attestations) {
        // Store the imported attestation only after all bundle-level and
        // per-attestation validation succeeds, AND the batch quota check
        // above passed for the whole bundle. Mark it imported so
        // tier-weighted reads clamp its self-asserted sovereignty_tier to
        // the non-privileged import ceiling: a foreign signer's
        // "verified-sovereign" claim is not trustworthy on this instance,
        // which never witnessed that handshake. `origin` is stamped
        // (mirrors record()'s `stored.origin`) so THIS import's records are
        // quota-attributed on every later scan the same way a record()
        // write already is.
        const stored: StoredAttestation = {
          attestation,
          recorded_at: new Date().toISOString(),
          imported: true,
          origin: resolvedOrigin,
        };

        const serialized = stringToBytes(JSON.stringify(stored));
        const encrypted = encrypt(serialized, this.encryptionKey);
        await this.storage.write(
          "_reputation",
          attestation.attestation_id,
          stringToBytes(JSON.stringify(encrypted))
        );

        count++;
        contexts.add(attestation.data.context);
      }
      return count;
    });

    return {
      imported,
      invalid: verification.invalid,
      unverifiable: verification.unverifiable,
      contexts: Array.from(contexts),
      completeness_verification: verification.completeness_verification,
    };
  }

  /**
   * Verify a reputation bundle without writing imported attestations.
   * This portable check covers bundle completeness, signatures, and metric
   * shape. Local storage-dependent gates, such as policy-rated bridge
   * commitment provenance, are covered by verifyBundleForImport.
   */
  verifyBundle(
    bundle: ReputationBundle,
    publicKeys: Map<string, Uint8Array>,
    options: {
      allowUnverifiedLegacy?: boolean;
    } = {}
  ): {
    invalid: number;
    unverifiable: number;
    contexts: string[];
    completeness_verification: ReputationBundleCompletenessVerification;
  } {
    const completenessVerification = this.verifyBundleCompleteness(
      bundle,
      publicKeys,
      options.allowUnverifiedLegacy === true
    );

    // Per-attestation signature verification is NOT bypassable on any path that
    // reaches a store write. A missing signer key, an absent, a malformed, or a
    // tampered signature is invalid, and any invalid attestation fails the whole
    // bundle below. The relaxed "accept unverifiable" verdict is confined to the
    // read-only exit-bundle previewer (exit/verifier.ts), which never writes.
    const attestationVerification = this.inspectAttestationSignatures(
      bundle,
      publicKeys
    );
    const { invalid, unverifiable } = attestationVerification;
    if (invalid > 0) {
      throw new ReputationBundleVerificationError(
        "Reputation bundle contains attestations with invalid or unverifiable signatures",
        invalid,
        unverifiable
      );
    }

    const metricVerification = this.inspectBridgeAttestationMetrics(bundle);
    if (metricVerification.invalid > 0) {
      throw new ReputationBundleVerificationError(
        "Reputation bundle contains concordia-bridge attestations with " +
          "invalid behavioral metrics: " +
          metricVerification.errors.join(" "),
        metricVerification.invalid,
        0
      );
    }

    return {
      invalid,
      unverifiable,
      contexts: Array.from(
        new Set(bundle.attestations.map((attestation) => attestation.data.context))
      ),
      completeness_verification: completenessVerification,
    };
  }

  /**
   * Verify a reputation bundle using the same storage-dependent semantic gates
   * that importBundle applies before the first _reputation write.
   */
  async verifyBundleForImport(
    bundle: ReputationBundle,
    publicKeys: Map<string, Uint8Array>,
    options: {
      allowUnverifiedLegacy?: boolean;
    } = {}
  ): Promise<{
    invalid: number;
    unverifiable: number;
    contexts: string[];
    completeness_verification: ReputationBundleCompletenessVerification;
  }> {
    const verification = this.verifyBundle(bundle, publicKeys, options);
    await this.assertImportablePolicyRatedBridgeAttestationsHaveLocalCommitments(
      bundle.attestations
    );
    return verification;
  }

  private inspectBridgeAttestationMetrics(
    bundle: ReputationBundle
  ): { invalid: number; errors: string[] } {
    let invalid = 0;
    const errors: string[] = [];

    for (const attestation of bundle.attestations) {
      if (!isConcordiaBridgeReputationContext(attestation.data.context)) {
        continue;
      }

      try {
        assertImportableBridgeAttestationMetrics(
          attestation.data.metrics,
          attestation.data.metric_policy
        );
      } catch (err) {
        invalid++;
        const message =
          err instanceof Error
            ? err.message
            : "Bridge attestation metrics rejected.";
        errors.push(
          `attestation ${attestation.attestation_id}: ${message}`
        );
      }
    }

    return { invalid, errors };
  }

  private async assertImportablePolicyRatedBridgeAttestationsHaveLocalCommitments(
    attestations: Attestation[]
  ): Promise<void> {
    const missingProvenance: string[] = [];
    for (const attestation of attestations) {
      const data = attestation.data;
      if (
        !isConcordiaBridgeReputationContext(data.context) ||
        data.metric_policy !== BRIDGE_METRIC_POLICY
      ) {
        continue;
      }

      const hasCommitment =
        await this.hasLocalBridgeCommitmentForAttestation(data);
      if (!hasCommitment) {
        missingProvenance.push(attestation.attestation_id);
      }
    }

    if (missingProvenance.length > 0) {
      throw new ReputationBundleVerificationError(
        "Reputation bundle contains policy-rated concordia-bridge attestations " +
          "without matching local bridge commitments: " +
          missingProvenance.join(", "),
        missingProvenance.length,
        0
      );
    }
  }

  private async assertPolicyRatedBridgeAttestationHasLocalCommitment(
    data: Attestation["data"]
  ): Promise<void> {
    if (
      !isConcordiaBridgeReputationContext(data.context) ||
      data.metric_policy !== BRIDGE_METRIC_POLICY
    ) {
      return;
    }

    const hasCommitment = await this.hasLocalBridgeCommitmentForAttestation(data);
    if (!hasCommitment) {
      throw new BridgeAttestationMetricValidationError(
        "Policy-rated concordia-bridge attestations require a matching local " +
          "bridge commitment; use bridge_commit followed by bridge_attest."
      );
    }
  }

  private async hasLocalBridgeCommitmentForAttestation(
    data: Attestation["data"]
  ): Promise<boolean> {
    let entries: Array<{ key: string }>;
    try {
      entries = await this.storage.list("_bridge");
    } catch {
      return false;
    }

    const bridgeEncryptionKey = derivePurposeKey(
      this.masterKey,
      "bridge-commitments"
    );

    for (const meta of entries) {
      let raw: Uint8Array | null;
      try {
        raw = await this.storage.read("_bridge", meta.key);
      } catch {
        return false;
      }
      if (!raw) continue;

      try {
        const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
        const decrypted = decrypt(encrypted, bridgeEncryptionKey);
        const bridgeRecord = JSON.parse(bytesToString(decrypted)) as unknown;
        if (!isRecord(bridgeRecord)) {
          continue;
        }
        if (await this.bridgeRecordMatchesPolicyAttestation(bridgeRecord, data)) {
          return true;
        }
      } catch {
        return false;
      }
    }

    return false;
  }

  private async bridgeRecordMatchesPolicyAttestation(
    bridgeRecord: Record<string, unknown>,
    data: Attestation["data"]
  ): Promise<boolean> {
    const commitment = bridgeRecord.commitment;
    const outcome = bridgeRecord.outcome;
    if (
      !isBridgeCommitmentRecord(commitment) ||
      !isConcordiaOutcomeRecord(outcome)
    ) {
      return false;
    }

    if (
      data.metrics.negotiation_round_bucket !==
        bridgeCountBucket(outcome.rounds)
    ) {
      return false;
    }

    const participants = new Set([outcome.proposer_did, outcome.acceptor_did]);
    if (
      commitment.session_id !== data.interaction_id ||
      outcome.session_id !== data.interaction_id ||
      !participants.has(commitment.committer_did) ||
      !participants.has(data.participant_did) ||
      !participants.has(data.counterparty_did) ||
      data.participant_did === data.counterparty_did
    ) {
      return false;
    }

    const committerPublicKey = await this.findIdentityPublicKeyByDid(
      commitment.committer_did
    );
    if (!committerPublicKey) {
      return false;
    }

    try {
      return verifyBridgeCommitment(
        commitment,
        outcome,
        committerPublicKey
      ).valid;
    } catch {
      return false;
    }
  }

  private async findIdentityPublicKeyByDid(
    did: string
  ): Promise<Uint8Array | null> {
    let entries: Array<{ key: string }>;
    try {
      entries = await this.storage.list("_identities");
    } catch {
      return null;
    }

    const identityEncryptionKey = derivePurposeKey(
      this.masterKey,
      "identity-encryption"
    );
    for (const meta of entries) {
      let raw: Uint8Array | null;
      try {
        raw = await this.storage.read("_identities", meta.key);
      } catch {
        return null;
      }
      if (!raw) continue;

      try {
        const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
        const decrypted = decrypt(encrypted, identityEncryptionKey);
        const identity = JSON.parse(bytesToString(decrypted)) as StoredIdentity;
        if (identity.did === did) {
          return fromBase64url(identity.public_key);
        }
      } catch {
        continue;
      }
    }

    return null;
  }

  private verifyBundleCompleteness(
    bundle: ReputationBundle,
    publicKeys: Map<string, Uint8Array>,
    allowUnverifiedLegacy: boolean
  ): ReputationBundleCompletenessVerification {
    assertSupportedReputationBundleShape(bundle);

    if (bundle.completeness_manifest === undefined) {
      this.verifyBundleSignature(bundle, publicKeys);
      return verifyReputationBundleCompleteness(bundle, {
        allowUnverifiedLegacy,
      });
    }

    const completenessVerification = verifyReputationBundleCompleteness(bundle, {
      allowUnverifiedLegacy,
    });
    this.verifyBundleSignature(bundle, publicKeys);

    return completenessVerification;
  }

  private verifyBundleSignature(
    bundle: ReputationBundle,
    publicKeys: Map<string, Uint8Array>
  ): void {
    const exporterKey = publicKeys.get(bundle.exporter_did);
    if (!exporterKey) {
      throw new ReputationBundleVerificationError(
        "Reputation bundle signer is unknown"
      );
    }

    let signatureBytes: Uint8Array;
    try {
      signatureBytes = fromBase64url(bundle.bundle_signature);
    } catch {
      throw new ReputationBundleVerificationError(
        "Reputation bundle signature is malformed"
      );
    }

    const manifestInclusiveValid = verify(
      reputationBundleSigningBytes(bundle),
      signatureBytes,
      exporterKey
    );
    // Legacy (pre-completeness-manifest) reputation exports and older exit
    // artifacts were signed over the four-field body via plain JSON.stringify,
    // with no completeness_manifest key. Accept that signing payload ONLY when
    // the manifest is genuinely absent (mirrors exit/verifier). This does NOT
    // reopen the strip-downgrade: a current bundle with its manifest removed was
    // signed over the manifest-inclusive canonical bytes, so neither the current
    // nor the legacy payload matches its signature, and it is rejected.
    const legacyValid =
      bundle.completeness_manifest === undefined &&
      verify(
        stringToBytes(
          JSON.stringify({
            version: bundle.version,
            attestations: bundle.attestations,
            exported_at: bundle.exported_at,
            exporter_did: bundle.exporter_did,
          })
        ),
        signatureBytes,
        exporterKey
      );
    if (!manifestInclusiveValid && !legacyValid) {
      throw new ReputationBundleVerificationError(
        "Reputation bundle signature verification failed"
      );
    }
  }

  /**
   * Verify every per-attestation Ed25519 signature in a bundle. This runs on
   * the IMPORT path (verifyBundle / verifyBundleForImport / importBundle), where
   * signature verification is NOT bypassable: a missing signer key, an absent,
   * a malformed, or a tampered signature all count as `invalid`, and the caller
   * refuses the whole bundle (zero writes) when `invalid > 0`.
   *
   * `unverifiable` is retained as a reported COUNT (how many attestations had an
   * unknown signer key) for diagnostics, but an unverifiable attestation is
   * ALSO counted as invalid here, so it can never be admitted into the store.
   * The only relaxed, write-free "accept unverifiable" verdict lives in the
   * standalone read-only exit-bundle previewer (exit/verifier.ts), which does
   * not route through this method and never writes to the store.
   */
  private inspectAttestationSignatures(
    bundle: ReputationBundle,
    publicKeys: Map<string, Uint8Array>
  ): { invalid: number; unverifiable: number } {
    let invalid = 0;
    let unverifiable = 0;
    for (const attestation of bundle.attestations) {
      if (attestation.signer !== attestation.data.participant_did) {
        invalid++;
        continue;
      }

      const signerKey = publicKeys.get(attestation.signer);
      if (!signerKey) {
        // Unknown signer: the signature cannot be verified, so it cannot be
        // trusted. Fail closed on the import path regardless of any caller
        // preference. Counted as unverifiable (for the diagnostic total) AND
        // invalid (so the bundle is rejected before any write).
        unverifiable++;
        invalid++;
        continue;
      }

      // Strict decode: an absent, non-string, or non-canonical base64url
      // signature is rejected here rather than silently coerced. fromBase64url
      // is lenient (it skips junk and tolerates trailing padding), which is a
      // signature-malleability fail-open on the import path; fromBase64urlStrict
      // throws on any deviation, so a tampered or malformed signature counts as
      // invalid and the bundle is refused before any write.
      let sigBytes: Uint8Array;
      try {
        sigBytes = fromBase64urlStrict(attestation.signature);
      } catch {
        invalid++;
        continue;
      }

      const dataBytes = stringToBytes(JSON.stringify(attestation.data));
      if (!verify(dataBytes, sigBytes, signerKey)) {
        invalid++;
      }
    }
    return { invalid, unverifiable };
  }

  // ─── Escrow ───────────────────────────────────────────────────────────

  /**
   * Create an escrow for trust bootstrapping.
   */
  async createEscrow(
    transactionTerms: string,
    counterpartyDid: string,
    timeoutSeconds: number,
    creatorDid: string,
    collateralAmount?: number
  ): Promise<Escrow> {
    const escrowId = `esc-${Date.now()}-${toBase64url(randomBytes(8))}`;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + timeoutSeconds * 1000);

    // Hash the terms for tamper detection
    const { hashToString } = await import("../core/hashing.js");
    const termsHash = hashToString(stringToBytes(transactionTerms));

    const escrow: Escrow = {
      escrow_id: escrowId,
      transaction_terms: transactionTerms,
      terms_hash: termsHash,
      collateral_amount: collateralAmount,
      counterparty_did: counterpartyDid,
      creator_did: creatorDid,
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
      status: "pending",
    };

    const serialized = stringToBytes(JSON.stringify(escrow));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      "_escrows",
      escrowId,
      stringToBytes(JSON.stringify(encrypted))
    );

    return escrow;
  }

  /**
   * Get an escrow by ID.
   */
  async getEscrow(escrowId: string): Promise<Escrow | null> {
    const raw = await this.storage.read("_escrows", escrowId);
    if (!raw) return null;

    try {
      const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      return JSON.parse(bytesToString(decrypted));
    } catch {
      return null;
    }
  }

  // ─── Guarantees ─────────────────────────────────────────────────────

  /**
   * Create a principal's guarantee for a new agent.
   */
  async createGuarantee(
    principalIdentity: StoredIdentity,
    agentDid: string,
    scope: string,
    durationSeconds: number,
    identityEncryptionKey: Uint8Array,
    maxLiability?: number
  ): Promise<Guarantee> {
    const guaranteeId = `guar-${Date.now()}-${toBase64url(randomBytes(8))}`;
    const now = new Date();
    const validUntil = new Date(now.getTime() + durationSeconds * 1000);

    const certificateData = {
      guarantee_id: guaranteeId,
      principal_did: principalIdentity.did,
      agent_did: agentDid,
      scope,
      max_liability: maxLiability,
      valid_until: validUntil.toISOString(),
      issued_at: now.toISOString(),
    };

    // Sign the certificate with the principal's key
    const certBytes = stringToBytes(JSON.stringify(certificateData));
    const signature = sign(
      certBytes,
      principalIdentity.encrypted_private_key,
      identityEncryptionKey
    );

    const certificate = toBase64url(
      stringToBytes(
        JSON.stringify({
          ...certificateData,
          signature: toBase64url(signature),
        })
      )
    );

    const guarantee: Guarantee = {
      guarantee_id: guaranteeId,
      principal_did: principalIdentity.did,
      agent_did: agentDid,
      scope,
      max_liability: maxLiability,
      valid_until: validUntil.toISOString(),
      certificate,
      created_at: now.toISOString(),
    };

    const serialized = stringToBytes(JSON.stringify(guarantee));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      "_guarantees",
      guaranteeId,
      stringToBytes(JSON.stringify(encrypted))
    );

    return guarantee;
  }

  // ─── L4 Evidence Summary ─────────────────────────────────────────────

  /**
   * Summarize attestations for the L4 degradation emitter and dashboard widget.
   *
   * Returns aggregate evidence about the identity's reputation state —
   * counts, tier distribution, recency, dispute counts, context coverage —
   * without exposing raw attestations. The caller combines this with an
   * audit-log check for Verascore link state to produce the final
   * `ReputationEvidence` struct consumed by the SHR generator.
   *
   * @param participantDid - If provided, only count attestations where the
   *   `participant_did` matches. If omitted, covers all attestations in the
   *   store.
   */
  async summarizeForSHR(
    participantDid?: string
  ): Promise<ReputationAttestationSummary> {
    const all = await this.loadAll();
    const filtered = participantDid
      ? all.filter((a) => a.attestation.data.participant_did === participantDid)
      : all;

    const tierDist: Record<SovereigntyTier, number> = {
      "verified-sovereign": 0,
      "verified-degraded": 0,
      "self-attested": 0,
      "unverified": 0,
    };
    const contextBreakdown: Record<string, number> = {};
    let mostRecentMs: number | null = null;
    let disputeCount = 0;

    for (const a of filtered) {
      // Trust-clamped tier (unconditional — see trustedSovereigntyTier): no
      // stored attestation, imported or local, may claim a privileged tier
      // above self-attested.
      const tier = trustedSovereigntyTier(a);
      if (tier) tierDist[tier]++;

      const ctx = a.attestation.data.context;
      if (ctx) contextBreakdown[ctx] = (contextBreakdown[ctx] ?? 0) + 1;

      const ts = new Date(a.attestation.data.timestamp).getTime();
      if (!isNaN(ts) && (mostRecentMs === null || ts > mostRecentMs)) {
        mostRecentMs = ts;
      }

      if (a.attestation.data.outcome_result === "disputed") disputeCount++;
    }

    return {
      attestation_count: filtered.length,
      tier_distribution: tierDist,
      most_recent_attestation_at:
        mostRecentMs !== null ? new Date(mostRecentMs).toISOString() : null,
      dispute_count: disputeCount,
      context_breakdown: contextBreakdown,
    };
  }

  // ─── Tier-Aware Access ───────────────────────────────────────────────

  /**
   * Load attestations for tier-weighted scoring.
   *
   * Applies basic context/counterparty filtering AND normalizes each record's
   * scoring-visible `attestation.data.sovereignty_tier` through
   * trustedSovereigntyTier, so this is the single trust chokepoint for scoring:
   * a caller cannot feed a raw privileged tier into computeWeightedScore or a
   * tier distribution by forgetting to clamp. ANY attestation that self-
   * asserts a privileged ("verified-*") tier is returned clamped to the
   * non-privileged ceiling (self-attested) — imported, unknown-provenance, and
   * provably-local (imported === false) records alike (A11: the clamp is
   * unconditional; see trustedSovereigntyTier).
   *
   * The clamp is applied to a SCORING VIEW built on a fresh object spine, not to
   * the persisted record: the signed `attestation.data` on disk is left
   * byte-intact so re-export signatures still verify. The returned objects are a
   * read-only scoring projection and are never re-persisted or re-exported. The
   * per-record `imported` provenance marker is preserved so callers that still
   * call trustedSovereigntyTier directly get the same (idempotent) verdict.
   */
  async loadAllForTierScoring(options?: {
    context?: string;
    counterparty_did?: string;
  }): Promise<StoredAttestation[]> {
    let all = await this.loadAll();

    if (options?.context) {
      all = all.filter((a) => a.attestation.data.context === options.context);
    }
    if (options?.counterparty_did) {
      all = all.filter(
        (a) => a.attestation.data.counterparty_did === options.counterparty_did
      );
    }

    return all.map((stored) => {
      const trusted = trustedSovereigntyTier(stored);
      if (trusted === stored.attestation.data.sovereignty_tier) {
        // No clamp needed (already trusted-local, already at/below ceiling, or
        // both undefined): return the record unchanged to avoid an allocation.
        return stored;
      }
      // Scoring view: override only the tier, on a fresh spine, leaving the
      // persisted record and its signed data byte-image untouched.
      return {
        ...stored,
        attestation: {
          ...stored.attestation,
          data: {
            ...stored.attestation.data,
            sovereignty_tier: trusted,
          },
        },
      };
    });
  }

  // ─── Internal ─────────────────────────────────────────────────────────

  private async loadAll(): Promise<StoredAttestation[]> {
    const results: StoredAttestation[] = [];
    for await (const page of this.loadAllPaginated(100)) {
      results.push(...page);
    }
    return results;
  }

  /**
   * Cursor-based async iterator that loads attestations in pages.
   * Prevents OOM at 100K+ records by reading and decrypting in batches.
   */
  async *loadAllPaginated(
    pageSize = 100
  ): AsyncGenerator<StoredAttestation[]> {
    let entries: Array<{ key: string }>;
    try {
      entries = await this.storage.list("_reputation");
    } catch {
      return; // Storage not available
    }

    for (let i = 0; i < entries.length; i += pageSize) {
      const page: StoredAttestation[] = [];
      const slice = entries.slice(i, i + pageSize);
      for (const meta of slice) {
        const raw = await this.storage.read("_reputation", meta.key);
        if (!raw) continue;
        try {
          const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
          const decrypted = decrypt(encrypted, this.encryptionKey);
          page.push(JSON.parse(bytesToString(decrypted)));
        } catch {
          // Skip corrupted entries
        }
      }
      if (page.length > 0) yield page;
    }
  }
}
