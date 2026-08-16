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
import { deriveContentId } from "../core/content-id.js";
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

// ─── Content-derived attestation ids (LD6 BP-DEADLINE-03) ─────────────────
//
// Admission_Completion_Design_Brief_2026-08-11.md V2-3: `record()` used to
// mint `att-${Date.now()}-${rand}`, so a caller that timed out waiting for
// admission had no safe key to retry -- re-issuing the SAME logical
// operation minted a SECOND attestation and doubled quota (the BP-DEADLINE
// class this fix closes). The id is now a deterministic hash of the
// operation's own identifying tuple, so a retry of the SAME tuple always
// resolves to the SAME key.

/**
 * CROSS-FILE PIN: `record()`'s existence guard (`findVerifiedExistingRecord`
 * below) recomputes this SAME id from a STORED record's own fields to
 * verify intent before honoring `already_committed` -- the tag, prefix, and
 * tuple order here must stay in lockstep with that recomputation. `.v1` is
 * this derivation's version; bump the suffix (never reuse `v1`) if the
 * tuple or framing ever changes, so old and new ids can never collide.
 */
export const REPUTATION_ATTESTATION_ID_DOMAIN_TAG = "sanctuary.reputation.attestation.v1";
export const REPUTATION_ATTESTATION_ID_PREFIX = "att";

/**
 * The ONE place the attestation id tuple/order is assembled, so `record()`
 * (minting) and its existence guard (recomputing from a STORED record's own
 * fields) can never drift apart on field order. `participantDid` is always
 * the SIGNER (the identity making the call), never the counterparty -- see
 * `record()`'s doc.
 */
export function deriveReputationAttestationId(
  interactionId: string,
  participantDid: string,
  counterpartyDid: string,
  context: string
): string {
  return deriveContentId(REPUTATION_ATTESTATION_ID_PREFIX, REPUTATION_ATTESTATION_ID_DOMAIN_TAG, [
    interactionId,
    participantDid,
    counterpartyDid,
    context,
  ]);
}

/**
 * Thrown by `record()`'s existence guard when the incoming
 * (interaction_id, participant_did, counterparty_did, context) tuple
 * matches a record ALREADY durably committed (at the content-derived key,
 * or via the legacy tuple-scan -- V2-4) and that record passes intent
 * verification. Callers (bridge_attest, reputation_record) catch this and
 * return the SAME idempotent "already recorded" shape they already return
 * for other idempotency paths, never a second attestation. `existing`
 * carries the stored record so the caller does not need a second read.
 */
export class ReputationAlreadyRecordedError extends Error {
  readonly existing: StoredAttestation;
  constructor(existing: StoredAttestation) {
    super(
      "Reputation store: this interaction was already recorded; " +
      "returning the existing attestation."
    );
    this.name = "ReputationAlreadyRecordedError";
    this.existing = existing;
  }
}

/**
 * Thrown by `record()`'s existence guard when the content-derived key (or a
 * legacy-scan match) is OCCUPIED by a record that FAILS intent verification
 * (recompute-from-stored-fields, signature, or tuple equality -- see
 * `findVerifiedExistingRecord`'s doc). This is the fail-closed refusal V2-3
 * requires: an id match alone never authorizes `already_committed`, and an
 * occupied-but-unverified key is NEVER overwritten and NEVER silently
 * treated as success. Distinct from `ReputationStoreQuotaError`
 * ("scan_unavailable"): that reason means the guard's OWN scan could not
 * complete; this one means the scan completed and found something that does
 * not check out.
 */
export class ReputationIdOccupiedUnverifiedError extends Error {
  constructor() {
    super(
      "Reputation store: the derived record id is occupied by a record " +
      "that failed intent verification; refusing to write."
    );
    this.name = "ReputationIdOccupiedUnverifiedError";
  }
}

/**
 * The plain projection an in-lock audit callback needs -- nothing more.
 * Carries only already-computed primitive fields, never a store handle.
 */
export interface ReputationRecordAuditProjection {
  attestation_id: string;
  interaction_id: string;
  counterparty_did: string;
  context: string;
  // LD6 BP-DEADLINE-03 fix-round (three-way divergence close): outcome_type
  // / outcome_result / sovereignty_tier are carried in the projection so the
  // in-lock audit callback can log the STORED record's own values, never a
  // caller-closure-captured incoming value. On the reconcile branch below,
  // `record()` passes `existing.attestation.data.*` here (the tuple already
  // committed) rather than the retry call's own `outcome`/`sovereigntyTier`
  // arguments -- a same-tuple retry with a DIFFERENT outcome must not make
  // the audit disagree with the durable record and the caller-visible
  // result, which both reflect the stored attestation, not the retry input.
  outcome_type: string;
  outcome_result: string;
  sovereignty_tier?: SovereigntyTier;
  /**
   * True ONLY on the existence-guard reconcile branch (an already-committed
   * retry), false on a fresh write (LD6 gate fix-round F4, reworked
   * fix-round-2 -- must match the same field on
   * `BridgeCommitmentAuditProjection` in bridge/tools.ts). The reconcile
   * branch ALWAYS re-emits its success audit -- O(1): one bounded
   * appendCritical, never an in-lock audit-log READ, which on the
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
 * Callback invoked INSIDE `record()`'s admission lock (V2-2/V2-5), either
 * immediately after a NEW record is durably written, or as the reconcile
 * step when the existence guard finds an already-committed match whose
 * audit may have been lost to a prior crash. The parameter type exposes
 * ONLY the plain projection above -- no `ReputationStore` reference, no
 * storage handle, no admission-queue accessor -- so the callback has
 * nothing PASSED IN that it could re-enter a store's admission lock with.
 *
 * HONEST BOUND (fix-round correction, mirrors bridge/tools.ts's
 * `BridgeInLockAuditEmit`): this restricts only the PARAMETER a caller
 * receives, not what a closure built against this type can LEXICALLY
 * CAPTURE from its own creation scope -- a TS function type constrains
 * arguments, not closures, so it cannot stop a call site from writing
 * `async (projection) => { await reputationStore.record(...); ... }` and
 * capturing `reputationStore` from the outer scope regardless of
 * `projection`'s shape. Re-entry avoidance here is a CONVENTION every
 * current call site follows (the closure captures only `auditLog` +
 * primitive locals, never `reputationStore` / `storage`), not a structural
 * guarantee this type enforces (V2-5 gap-5). A real structural guard (e.g.
 * a re-entrancy flag on the admission lock itself) would close this
 * properly; it is not built here. Construct the closure passed here by
 * capturing `auditLog` + plain data ONLY, never `reputationStore` /
 * `storage`.
 */
export type ReputationInLockAuditEmit = (
  projection: ReputationRecordAuditProjection
) => Promise<void>;

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
 * Bounds how long a `runAdmissionExclusiveBounded` CALLER waits for its own
 * admission to settle (LD3 gate fix-round-2, MUST-FIX 3 — same class as
 * core/bounded-map.ts's `onEvict` timeout and
 * sentinel-finding-store.ts's `STORE_ADMISSION_DEADLINE_MS`, applied here to
 * `_reputation`'s own admission lock). NOT a bound on how long the
 * underlying lock is held (LD5 BP-DEADLINE-01 — see
 * `runAdmissionExclusiveBounded`'s doc): a hung `storage.list`/`read`/
 * `write` call inside the locked section keeps the lock, by design, until
 * it settles — a timeout only stops THIS caller from waiting on it, WITHOUT
 * releasing `admissionQueue` to a later admission that could otherwise
 * observe stale (pre-write) headroom, and (LD5 BP-DEADLINE-02, closed)
 * WITHOUT freeing `pendingAdmissionWaiters`' slot either — that slot is
 * held until `fn()` itself settles, so a caller timeout alone cannot let
 * later admissions pile chained closures behind a permanently-hung `fn`.
 * DERIVATION against the section's true worst case (LD6 gate fix-round F2
 * — the prior comment predated V2-2 and omitted the in-lock audit append
 * this PR added). record()'s locked section is: existence-guard read + (on
 * a content-id miss) one full O(N) legacy decrypt-scan +
 * `assertRecordQuota`'s scan + any caller-supplied `additionalQuotaCheck`
 * (bridge_attest's origin-context scan) + the record write + one AWAITED
 * `appendCritical` via `emitAudit`; importBundle()'s locked section is the
 * batch quota check + its whole write loop, with NO in-lock audit append.
 * The audit append's own worst case is AUDIT_WRITE_LOCK_TIMEOUT_MS (5s
 * lock acquisition) + DEFAULT_AUDIT_WRITE_LOCK_HOLD_DEADLINE_MS (30s
 * write-hold), both operational/audit-log.ts — 35s.
 * ON_EVICT_AUDIT_TIMEOUT_MS (core/bounded-map.ts) is that same 35s plus a
 * 5s scheduling margin, i.e. 40s: the established named bound for "one
 * awaited audit append performed inside a lock," which is exactly
 * record()'s shape, so it is reused rather than re-derived.
 * STORAGE_OP_MARGIN_MS (10s) is the defensive backstop for this store's
 * OWN storage.list/read/write calls (N bounded by MAX_REPUTATION_RECORDS),
 * which carry no settle-time contract at all (storage/interface.ts); a
 * backstop, not a precise bound. The reconcile (guard-hit) branch's
 * in-lock work is ONE bounded appendCritical (the F4 fix-round-2 tag-based
 * re-emission -- same 35s worst case as the write path's append, with NO
 * in-lock audit-log read), so the fresh-write path, which adds the scans
 * and the record write on top of that same append, stays the section's
 * worst case. Total: the deadline exceeds the audit append's 35s hard
 * worst case by 15s of margin for everything else.
 *
 * ACCEPTED CONSEQUENCE (deliberate, fail-closed): because the audit append
 * is INSIDE the lock, a slow or contended audit backend serializes
 * admissions behind it, and callers whose wait crosses this deadline are
 * REFUSED — an availability cost, never fail-open (auditing outside the
 * lock reopens the V2-2 told-success-without-durable-audit divergence).
 * WHY this store and BridgeStore accept the coupling and the sentinel path
 * does not: `SentinelFindingStore.saveFinding` can ALREADY spend up to
 * ON_EVICT_AUDIT_TIMEOUT_MS (40s) in-lock on an evict-INTENT append, so a
 * second in-lock append would worst-case 40s + 35s = 75s against the same
 * 50s budget (the 75s figure must match BRIDGE_STORE_ADMISSION_DEADLINE_MS's
 * note in bridge/tools.ts and sentinel-dispatcher.ts's routeFinding
 * comment) — see the fuller asymmetry note at either of those sites.
 *
 * Kept as a LOCAL constant, not imported from
 * sentinel-finding-store.ts, for the same module-boundary reason
 * REPUTATION_UNKNOWN_ORIGIN is this file's own constant rather than an
 * import — the derivations must stay numerically identical, which is
 * why all are pinned to ON_EVICT_AUDIT_TIMEOUT_MS + the same margin
 * (cross-file pin: must match STORAGE_OP_MARGIN_MS /
 * STORE_ADMISSION_DEADLINE_MS in sentinel-finding-store.ts and
 * BRIDGE_STORAGE_OP_MARGIN_MS / BRIDGE_STORE_ADMISSION_DEADLINE_MS in
 * bridge/tools.ts).
 *
 * LD5 BP-DEADLINE-01 (closed — this paragraph previously read "ACCEPTED
 * RESIDUAL" and claimed a bounded, "exactly one extra write" overshoot; that
 * claim was WRONG under repeated scheduling, not merely narrow): the pre-fix
 * `runAdmissionExclusiveBounded` wrapped `fn` in
 * `withReputationAdmissionDeadline` BEFORE handing it to
 * `runAdmissionExclusive`, so the raw promise chained onto `admissionQueue`
 * WAS the deadline race — the lock released to the next admission the
 * instant the timer fired, even though the underlying `fn()` (quota check
 * plus `storage.write`, or importBundle's whole write loop) kept running
 * detached. A caller that repeatedly scheduled "scan passes, write hangs
 * past the deadline, enqueue another admission, release the delayed write
 * later" could keep every successive admission's quota scan observing
 * STALE (pre-write) headroom indefinitely — there was no cap on how many
 * waves of this could run, so the overshoot was unbounded, not "exactly
 * one." The fix: `fn` (raw, undecorated) is what gets chained onto
 * `admissionQueue` via `runAdmissionExclusive`, so the lock is held until
 * `fn()` truly settles; the deadline is applied ONLY to the promise
 * `runAdmissionExclusiveBounded` awaits and returns, bounding what the
 * CALLER is told without ever releasing the lock early. A `fn()` that never
 * settles at all (genuinely hung, not merely slow) now blocks this store's
 * queue for every later admission until it does — deliberate, since the
 * alternative (releasing the lock early) is the exact bypass this fix
 * closes; each caller still fails closed on its own deadline and
 * `pendingAdmissionWaiters` cap, so a hung storage backend degrades to "no
 * new admissions succeed," never to a quota overshoot. That is NOT, by
 * itself, clean degradation with no other cost: LD5 BP-DEADLINE-02 (closed,
 * see `runAdmissionExclusiveBounded`'s doc below) closes the companion
 * memory risk — chained closures behind a permanently-hung admission are
 * bounded at `maxPendingAdmissionWaiters` because the waiter slot is now
 * held for `fn`'s full lifetime, not released on the caller's deadline
 * timeout. Reachability remains as before: both importBundle paths are
 * OPERATOR-gated
 * (`reputation_import` is tier1_always_approve; the exit CLI is a separate
 * operator process). Cross-process concurrency is the separate accepted
 * DEBT (bridge/tools.ts). The per-refusal `admission_busy` audit append is
 * 1:1 with a real MCP round-trip (not N×M); the uncapped audit queue it
 * feeds is the separately-tracked systemic item (register AUD-BP-01).
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
   * `await`, decremented when `fn()` itself SETTLES (via a `.then` attached
   * to the chained promise), never on the caller's deadline-bounded await
   * settling first — see LD5 BP-DEADLINE-02 on `runAdmissionExclusiveBounded`
   * for why a caller-timeout-triggered release let chained closures pile up
   * unbounded behind a permanently-hung `fn`. The synchronous
   * check-then-increment needs no separate lock because both happen in the
   * same tick, with no `await` between them.
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
   * 2. SETTLEMENT DEADLINE: the promise this method returns to ITS OWN
   *    caller races against REPUTATION_STORE_ADMISSION_DEADLINE_MS via
   *    withReputationAdmissionDeadline — bounding how long that CALLER
   *    waits, never how long this store's lock is held (LD5 BP-DEADLINE-01
   *    — see REPUTATION_STORE_ADMISSION_DEADLINE_MS's doc for the closed
   *    defect this replaces). `fn` itself is chained onto `admissionQueue`
   *    RAW, undecorated, so the lock only frees once `fn()` truly settles;
   *    a hung `storage.list`/`read`/`write` call inside `fn` therefore
   *    keeps holding this lock past the deadline, on purpose — releasing it
   *    early is exactly what let a detached write land against
   *    already-stale quota headroom.
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
      throw new ReputationStoreQuotaError("admission_busy");
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
    return await withReputationAdmissionDeadline(
      chained,
      REPUTATION_STORE_ADMISSION_DEADLINE_MS
    );
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
   *
   * `emitAudit` (LD6 BP-DEADLINE-03, optional trailing): an `InLockAuditEmit`
   * callback run INSIDE this same admission-locked section -- either right
   * after a NEW record durably writes, or as the reconcile step when the
   * existence guard finds an already-committed match (V2-2). Optional so
   * the many direct-`record()` callers (tests, internal tooling with no
   * audit log) are unaffected; both MCP tool call sites (bridge_attest,
   * reputation_record) always supply it.
   *
   * REJECTS with `ReputationAlreadyRecordedError` (carrying the existing
   * record) when the existence guard finds this exact
   * (interaction_id, participant_did, counterparty_did, context) tuple
   * already committed -- callers must catch this and return the SAME
   * idempotent shape they already return for other idempotency paths,
   * never treat it as a hard failure. REJECTS with
   * `ReputationIdOccupiedUnverifiedError` when the derived key is occupied
   * by a record that fails intent verification (never overwritten, never
   * silently accepted).
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
    additionalQuotaCheck?: () => Promise<void>,
    emitAudit?: ReputationInLockAuditEmit
  ): Promise<StoredAttestation> {
    const resolvedOrigin = ReputationStore.resolveOrigin(origin);
    // LD6 BP-DEADLINE-03: content-derived id from the tuple identifying THIS
    // logical operation (`participant_did` = the SIGNER, `identity.did` --
    // never the counterparty), so a retry of the identical tuple resolves
    // to the SAME key instead of minting a fresh random one.
    const attestationId = deriveReputationAttestationId(
      interactionId,
      identity.did,
      counterpartyDid,
      context
    );
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
    const tuple = {
      interaction_id: interactionId,
      participant_did: identity.did,
      counterparty_did: counterpartyDid,
      context,
    };
    return this.runAdmissionExclusiveBounded(async () => {
      // LD6 BP-DEADLINE-03 (V2-2/V2-3/V2-4): the existence guard runs FIRST,
      // inside the lock, before quota or write -- a retry of this exact
      // tuple (content-id hit) or a pre-upgrade retry carrying an old
      // random id (legacy-scan hit) always observes a prior admission's
      // completed write instead of racing it. An id match ALONE never
      // authorizes `already_committed`; see findVerifiedExistingRecord's
      // doc for the intent-verification steps that gate this.
      const existing = await this.findVerifiedExistingRecord(
        attestationId,
        tuple,
        fromBase64url(identity.public_key)
      );
      if (existing === "scan_unavailable") {
        throw new ReputationStoreQuotaError("scan_unavailable");
      }
      if (existing === "occupied_unverified") {
        throw new ReputationIdOccupiedUnverifiedError();
      }
      if (existing !== null) {
        // Reconcile: a record that committed but lost its audit to a prior
        // crash (the V2-2 named residual) gets its audit re-emitted here,
        // on the first retry or existence-guard read that finds it.
        // ALWAYS emitted on a guard hit -- never conditioned on an in-lock
        // audit-log read (that read is the HIGH fix-round-2 removed: a
        // non-eager query re-verifies the whole chain inside the lock) --
        // and `reconcile: true` (LD6 gate fix-round-2 F4) makes the
        // callback TAG the entry so counting consumers skip it; see
        // ReputationRecordAuditProjection's `reconcile` doc.
        if (emitAudit) {
          await emitAudit({
            attestation_id: existing.attestation.attestation_id,
            interaction_id: existing.attestation.data.interaction_id,
            counterparty_did: existing.attestation.data.counterparty_did,
            context: existing.attestation.data.context,
            // Reconcile-audit fidelity (fix-round): STORED values, never
            // this call's own `outcome`/`sovereigntyTier` arguments -- see
            // ReputationRecordAuditProjection's doc.
            outcome_type: existing.attestation.data.outcome_type,
            outcome_result: existing.attestation.data.outcome_result,
            sovereignty_tier: existing.attestation.data.sovereignty_tier,
            reconcile: true,
          });
        }
        throw new ReputationAlreadyRecordedError(existing);
      }

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

      // V2-2: the success audit is emitted INSIDE this same locked section,
      // immediately after the durable write settles -- write-first, then an
      // AWAITED appendCritical, never the reverse (see the design brief's
      // "why not audit-intent-before-write"). This gives "eventual,
      // self-healing commit<->audit agreement", NOT atomicity: a crash
      // between the write above becoming durable and this append becoming
      // durable leaves a committed-but-unaudited record, which is
      // transient and self-healing (the reconcile branch above re-emits it
      // on the next retry or guard-read) but not reducible to zero within
      // one process -- see the design brief V2-2 for why (no cross-log
      // transaction primitive exists on StorageBackend). If `emitAudit`
      // THROWS here (audit backend down -- a failure, not a crash), this
      // call REJECTS: the write already landed, but the caller is NEVER
      // told success without a durable audit (fail closed, never silently
      // degrade). The record stays in place for an idempotent retry, which
      // re-enters the guard above and re-emits the audit.
      if (emitAudit) {
        await emitAudit({
          attestation_id: stored.attestation.attestation_id,
          interaction_id: stored.attestation.data.interaction_id,
          counterparty_did: stored.attestation.data.counterparty_did,
          context: stored.attestation.data.context,
          // Same STORED-value sourcing as the reconcile branch above; on
          // this fresh-write path `stored` is what just landed, so this is
          // identical to the incoming outcome/tier today, but reading it
          // from `stored` (not the outer closure) keeps one source of truth
          // and matches the reconcile branch's shape exactly.
          outcome_type: stored.attestation.data.outcome_type,
          outcome_result: stored.attestation.data.outcome_result,
          sovereignty_tier: stored.attestation.data.sovereignty_tier,
          // Fresh write: this entry cannot already exist, so the callback
          // appends without the reconcile-branch absence query (F4).
          reconcile: false,
        });
      }

      return stored;
    });
  }

  /**
   * V2-3/V2-4 existence guard used by `record()`. Looks for a record
   * already committed for `tuple`, either at the content-derived
   * `contentId` (primary) or via the legacy tuple-scan
   * (`findExistingAttestationForDedup` -- a pre-upgrade random-id record).
   * Returns:
   *   - the STORED record, when a match passes intent verification;
   *   - `"occupied_unverified"`, when the content-id key is occupied by a
   *     record that FAILS intent verification (a pre-seed or corrupted
   *     entry) -- the caller must fail closed, NEVER overwrite;
   *   - `"scan_unavailable"`, when the guard's own read/scan could not
   *     complete (a storage error) -- distinct from occupied-unverified:
   *     nothing was found to be wrong, the guard simply could not confirm
   *     either way, so it fails closed the same way
   *     `findExistingAttestationForDedup`'s own callers already do;
   *   - `null`, when neither the primary key nor the legacy scan has a
   *     match -- the caller should proceed to quota-check-then-write.
   *
   * `callerPublicKey` is the CURRENT identity's own public key, not a
   * general DID resolver. This is sound, not a shortcut: any match this
   * guard can honor requires the stored record's `participant_did` to
   * equal `identity.did` -- either by construction (the content-id hit's
   * hash preimage includes `identity.did`) or by the explicit
   * tuple-equality filter (`findExistingAttestationForDedup` matches on
   * `participant_did` exactly). If the key is occupied by a record
   * genuinely signed by someone else, that signature will not verify
   * against `callerPublicKey` -- the correct fail-closed outcome, not a
   * false negative.
   */
  private async findVerifiedExistingRecord(
    contentId: string,
    tuple: {
      interaction_id: string;
      participant_did: string;
      counterparty_did: string;
      context: string;
    },
    callerPublicKey: Uint8Array
  ): Promise<StoredAttestation | "occupied_unverified" | "scan_unavailable" | null> {
    let raw: Uint8Array | null;
    try {
      raw = await this.storage.read("_reputation", contentId);
    } catch {
      return "scan_unavailable";
    }

    if (raw !== null) {
      let candidate: StoredAttestation;
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
      // DEBT (LD6 gate fix-round F1, import pre-seed vector): importBundle()
      // deliberately writes at the CALLER-SUPPLIED `attestation.attestation_id`
      // (the id is not part of the signed attestation bytes, and
      // `deriveReputationAttestationId` is exported and publicly computable),
      // so an imported bundle entry can land at exactly the content-derived
      // key a victim tuple's future record() call will compute. That entry
      // fails intent verification here (wrong tuple/signature), so this
      // branch refuses it fail-closed -- correctly -- but the refusal is
      // PERMANENT: `_reputation` is a reserved namespace with no operator
      // recovery verb, so the victim tuple can never be recorded until the
      // squatting entry is removed out-of-band. Bounded by the operator gate
      // on `reputation_import` (Tier-1, tier1_always_approve: every import is
      // human-approved), so this is not an unauthenticated-attacker path; the
      // recovery path (and/or import-id hardening that re-keys or refuses
      // derived-format ids on import) is OWED as the deferred
      // import-id-hardening design item -- do not silently re-add id
      // rewriting to importBundle, which intentionally preserves foreign ids.
      return this.verifyStoredAttestationIntent(candidate, tuple, callerPublicKey, contentId)
        ? candidate
        : "occupied_unverified";
    }

    // Primary miss: fall back to the legacy tuple-scan (V2-4) for a
    // pre-upgrade record still keyed by its old random id. Bounded by this
    // store's own size cap (MAX_REPUTATION_RECORDS), the SAME O(N)
    // decrypt-scan shape bridge_attest's fast path already pays via this
    // exact method -- not a new unbounded surface, and it runs at most once
    // per admission, only on a content-id miss.
    const legacy = await this.findExistingAttestationForDedup(tuple);
    if (!legacy.scanComplete) {
      return "scan_unavailable";
    }
    if (legacy.match === null) {
      return null;
    }
    // No `expectedContentId` here: a legacy match was found by an EXACT
    // field-by-field scan (findExistingAttestationForDedup), so tuple
    // equality already holds by construction -- recomputing a content id
    // and comparing it to the record's OLD random id would always fail
    // and is not the check this path needs. The signature check below is
    // still required (defense-in-depth: a legacy match is genuine only if
    // it was actually signed by this caller's key).
    return this.verifyStoredAttestationIntent(legacy.match, tuple, callerPublicKey)
      ? legacy.match
      : "occupied_unverified";
  }

  /**
   * V2-3 intent verification: an id (or tuple) match ALONE must never
   * authorize `already_committed`. Recomputes the content id from the
   * STORED record's own fields and asserts it equals `expectedContentId`
   * (skipped for a legacy-scan match -- see the call site's doc), verifies
   * the stored record's OWN signature against `callerPublicKey` (byte-exact
   * re-serialization mirrors the check `importBundle` already performs on
   * import -- `JSON.stringify(data)` then `verify`), and asserts EXACT field
   * equality between the stored tuple and the incoming operation's tuple --
   * not just id equality, the "verify exact canonical intent" the design
   * brief requires. All three must pass.
   */
  private verifyStoredAttestationIntent(
    stored: StoredAttestation,
    tuple: {
      interaction_id: string;
      participant_did: string;
      counterparty_did: string;
      context: string;
    },
    callerPublicKey: Uint8Array,
    expectedContentId?: string
  ): boolean {
    // Fail-closed verification body (LD6 gate fix-round F6; scope widened
    // fix-round-2 M-3 -- must match the try/catch in
    // verifyStoredCommitmentIntent, bridge/tools.ts): the try encloses the
    // ENTIRE body from the stored-data access onward, because a
    // decryptable-but-wrong-shape record (null, or missing
    // attestation/data) throws a raw TypeError at the first property
    // access -- before any signature work -- and is exactly as unverified
    // as a bad signature (so is a malformed base64url signature or
    // wrong-length key material). ANY throw classifies as the fail-closed
    // `occupied_unverified` (return false), never an unclassified
    // rejection escaping record()'s locked section.
    try {
      const d = stored.attestation.data;
      if (expectedContentId !== undefined) {
        const recomputed = deriveReputationAttestationId(
          d.interaction_id,
          d.participant_did,
          d.counterparty_did,
          d.context
        );
        if (recomputed !== expectedContentId) return false;
      }
      if (
        d.interaction_id !== tuple.interaction_id ||
        d.participant_did !== tuple.participant_did ||
        d.counterparty_did !== tuple.counterparty_did ||
        d.context !== tuple.context
      ) {
        return false;
      }
      const sigBytes = fromBase64urlStrict(stored.attestation.signature);
      const dataBytes = stringToBytes(JSON.stringify(d));
      return verify(dataBytes, sigBytes, callerPublicKey);
    } catch {
      return false;
    }
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
