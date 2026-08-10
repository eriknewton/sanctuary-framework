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
   * Provenance marker used by tier-weighted reads to decide whether a stored
   * attestation's self-asserted sovereignty_tier may be trusted.
   *
   *   - false  => recorded locally from a handshake THIS instance witnessed;
   *               the tier is trustworthy and is NOT clamped.
   *   - true   => accepted via importBundle; the tier is a foreign signer's
   *               uncorroborated claim and is clamped to
   *               MAX_IMPORTED_SOVEREIGNTY_TIER at every weighted read.
   *   - absent => unknown provenance. FAIL CLOSED: a record whose imported
   *               field is undefined is treated as untrusted and clamped like
   *               an import. Legacy attestations written before this marker
   *               existed land here, so a pre-patch imported "verified-sovereign"
   *               claim cannot keep a privileged weight just because it predates
   *               the marker. Only an explicit imported:false escapes the clamp.
   *
   * The signed attestation.data is left byte-intact so re-export signatures still
   * verify; this marker drives the trust clamp at the consumption boundary
   * instead of mutating the signed payload.
   */
  imported?: boolean;
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
 * The recorded tier passes through verbatim ONLY when provenance is provably
 * local (imported === false): it was set from a handshake this instance
 * witnessed. In EVERY other case the tier is clamped to
 * MAX_IMPORTED_SOVEREIGNTY_TIER:
 *
 *   - imported === true  => a foreign signer's uncorroborated tier claim.
 *   - imported undefined => unknown provenance. Fail CLOSED. Legacy records
 *                           written before the marker existed have no imported
 *                           field; a pre-patch imported "verified-sovereign"
 *                           claim must NOT keep a privileged weight merely
 *                           because it predates the marker.
 *
 * This is the single chokepoint every tier-weighted read must go through so a
 * forged or provenance-unknown attestation cannot inflate its scoring weight.
 * It never RAISES a tier.
 */
export function trustedSovereigntyTier(
  stored: StoredAttestation
): SovereigntyTier | undefined {
  const declared = stored.attestation.data.sovereignty_tier;
  return stored.imported === false
    ? declared
    : clampImportedSovereigntyTier(declared);
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

// ─── Reputation Store ─────────────────────────────────────────────────────

export class ReputationStore {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;
  /** Held for custody-floor envelope authentication (never logged). */
  private masterKey: Uint8Array;

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.masterKey = masterKey;
    this.encryptionKey = derivePurposeKey(masterKey, "l4-reputation");
  }

  /**
   * Record an interaction outcome as a signed attestation.
   */
  async record(
    interactionId: string,
    counterpartyDid: string,
    outcome: InteractionOutcome,
    context: string,
    identity: StoredIdentity,
    identityEncryptionKey: Uint8Array,
    counterpartyAttestation?: string,
    sovereigntyTier?: SovereigntyTier
  ): Promise<StoredAttestation> {
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
      // Provably local provenance: this tier came from a handshake this
      // instance witnessed, so trustedSovereigntyTier leaves it unclamped.
      // Stamped explicitly (not left absent) because absent now fails closed.
      imported: false,
    };

    // Persist encrypted
    const serialized = stringToBytes(JSON.stringify(stored));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      "_reputation",
      attestationId,
      stringToBytes(JSON.stringify(encrypted))
    );

    return stored;
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
   * @param publicKeys - Map of DID → public key bytes for signature verification
   */
  async importBundle(
    bundle: ReputationBundle,
    _verifySignatures: boolean,
    publicKeys: Map<string, Uint8Array>,
    options: {
      allowUnverifiedLegacy?: boolean;
    } = {}
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

    let imported = 0;
    const contexts = new Set<string>();

    for (const attestation of bundle.attestations) {
      // Store the imported attestation only after all bundle-level and
      // per-attestation validation succeeds. Mark it imported so tier-weighted
      // reads clamp its self-asserted sovereignty_tier to the non-privileged
      // import ceiling: a foreign signer's "verified-sovereign" claim is not
      // trustworthy on this instance, which never witnessed that handshake.
      const stored: StoredAttestation = {
        attestation,
        recorded_at: new Date().toISOString(),
        imported: true,
      };

      const serialized = stringToBytes(JSON.stringify(stored));
      const encrypted = encrypt(serialized, this.encryptionKey);
      await this.storage.write(
        "_reputation",
        attestation.attestation_id,
        stringToBytes(JSON.stringify(encrypted))
      );

      imported++;
      contexts.add(attestation.data.context);
    }

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
      // Trust-clamped tier: an imported attestation cannot claim a privileged
      // tier this instance never witnessed (see trustedSovereigntyTier).
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
   * tier distribution by forgetting to clamp. An imported or unknown-provenance
   * attestation that self-asserts a privileged ("verified-*") tier is returned
   * clamped to the non-privileged import ceiling (self-attested); a provably
   * local record (imported === false) is returned unchanged.
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
