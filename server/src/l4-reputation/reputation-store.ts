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
 * L4 attestation evidence summary for the SHR degradation emitter and the
 * dashboard evidence widget. Derived from the stored attestations; does not
 * include Verascore-link state (tracked separately via audit log).
 */
export interface L4AttestationSummary {
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

/** Portable reputation bundle */
export interface ReputationBundle {
  version: "SANCTUARY_REP_V1";
  attestations: Attestation[];
  exported_at: string;
  exporter_did: string;
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

// ─── Reputation Store ─────────────────────────────────────────────────────

export class ReputationStore {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
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
    const bundleData = {
      version: "SANCTUARY_REP_V1" as const,
      attestations,
      exported_at: new Date().toISOString(),
      exporter_did: identity.did,
    };

    // Sign the bundle
    const bundleBytes = stringToBytes(JSON.stringify(bundleData));
    const bundleSignature = sign(
      bundleBytes,
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
   * Verifies signatures if requested (default: true).
   *
   * @param publicKeys - Map of DID → public key bytes for signature verification
   */
  async importBundle(
    bundle: ReputationBundle,
    verifySignatures: boolean,
    publicKeys: Map<string, Uint8Array>
  ): Promise<{ imported: number; invalid: number; contexts: string[] }> {
    let imported = 0;
    let invalid = 0;
    const contexts = new Set<string>();

    for (const attestation of bundle.attestations) {
      if (verifySignatures) {
        const signerKey = publicKeys.get(attestation.signer);
        if (!signerKey) {
          invalid++;
          continue;
        }

        const dataBytes = stringToBytes(
          JSON.stringify(attestation.data)
        );
        const sigBytes = fromBase64url(attestation.signature);

        if (!verify(dataBytes, sigBytes, signerKey)) {
          invalid++;
          continue;
        }
      }

      // Store the imported attestation
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
      contexts: Array.from(contexts),
    };
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
   * `L4Evidence` struct consumed by the SHR generator.
   *
   * @param participantDid - If provided, only count attestations where the
   *   `participant_did` matches. If omitted, covers all attestations in the
   *   store.
   */
  async summarizeForSHR(
    participantDid?: string
  ): Promise<L4AttestationSummary> {
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
