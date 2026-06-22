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
} from "../core/encoding.js";
import { randomBytes } from "../core/random.js";
import { sign, verify } from "../core/identity.js";
import type { StoredIdentity } from "../core/identity.js";
import type { SovereigntyTier } from "./tiers.js";
import { hashToString } from "../core/hashing.js";

// ─── Types ────────────────────────────────────────────────────────────────

/** Interaction outcome for recording */
export interface InteractionOutcome {
  type: "transaction" | "negotiation" | "service" | "dispute" | "custom";
  result: "completed" | "partial" | "failed" | "disputed";
  metrics?: Record<string, number>;
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
  counterparty_confirmed: boolean;
  recorded_at: string;
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

    // Build the attestation data
    const attestationData: Attestation["data"] = {
      interaction_id: interactionId,
      participant_did: identity.did,
      counterparty_did: counterpartyDid,
      outcome_type: outcome.type,
      outcome_result: outcome.result,
      metrics: outcome.metrics ?? {},
      context,
      timestamp: now,
      sovereignty_tier: sovereigntyTier,
    };

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
      counterparty_attestation: counterpartyAttestation,
      counterparty_confirmed: !!counterpartyAttestation,
      recorded_at: now,
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
      aggregate_metrics: aggregateMetrics(filtered, options.metrics),
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

    const attestations = all.map((a) => a.attestation);
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
   * @param publicKeys - Map of DID → public key bytes for signature verification
   */
  async importBundle(
    bundle: ReputationBundle,
    _verifySignatures: boolean,
    publicKeys: Map<string, Uint8Array>,
    options: {
      allowUnverifiedLegacy?: boolean;
      allowUnverifiableAttestations?: boolean;
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

    const completenessVerification = this.verifyBundleCompleteness(
      bundle,
      publicKeys,
      options.allowUnverifiedLegacy === true
    );

    const attestationVerification = this.inspectAttestationSignatures(
      bundle,
      publicKeys,
      options.allowUnverifiableAttestations === true
    );
    const { invalid, unverifiable } = attestationVerification;
    if (invalid > 0) {
      throw new ReputationBundleVerificationError(
        "Reputation bundle contains attestations with invalid or unverifiable signatures",
        invalid,
        unverifiable
      );
    }

    let imported = 0;
    const contexts = new Set<string>();

    for (const attestation of bundle.attestations) {
      // Store the imported attestation only after all bundle-level and
      // per-attestation validation succeeds.
      const stored: StoredAttestation = {
        attestation,
        counterparty_confirmed: false,
        recorded_at: new Date().toISOString(),
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
      invalid,
      unverifiable,
      contexts: Array.from(contexts),
      completeness_verification: completenessVerification,
    };
  }

  private verifyBundleCompleteness(
    bundle: ReputationBundle,
    publicKeys: Map<string, Uint8Array>,
    allowUnverifiedLegacy: boolean
  ): ReputationBundleCompletenessVerification {
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

    const manifest = bundle.completeness_manifest;
    if (manifest === undefined) {
      this.verifyBundleSignature(bundle, publicKeys);
      if (!allowUnverifiedLegacy) {
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

    this.verifyBundleSignature(bundle, publicKeys);

    return "verified";
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

  private inspectAttestationSignatures(
    bundle: ReputationBundle,
    publicKeys: Map<string, Uint8Array>,
    allowUnverifiableAttestations: boolean
  ): { invalid: number; unverifiable: number } {
    let invalid = 0;
    let unverifiable = 0;
    for (const attestation of bundle.attestations) {
      const signerKey = publicKeys.get(attestation.signer);
      if (!signerKey) {
        unverifiable++;
        if (allowUnverifiableAttestations) {
          continue;
        }
        invalid++;
        continue;
      }

      let sigBytes: Uint8Array;
      try {
        sigBytes = fromBase64url(attestation.signature);
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
      const tier = a.attestation.data.sovereignty_tier;
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
   * Applies basic context/counterparty filtering, returns full StoredAttestations
   * so callers can access sovereignty_tier from attestation data.
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

    return all;
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
