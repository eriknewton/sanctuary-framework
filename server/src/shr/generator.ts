/**
 * Sanctuary MCP Server — SHR Generator
 *
 * Generates a Sovereignty Health Report from current server state,
 * signs it with a specified identity, and returns the complete signed SHR.
 */

import type { SanctuaryConfig } from "../config.js";
import type { IdentityManager } from "../l1-cognitive/tools.js";
import type {
  SHRBody,
  SignedSHR,
  SHRDegradation,
  DegradationCode,
  LayerStatus,
} from "./types.js";
import { canonicalizeForSigning } from "./types.js";
import { sign } from "../core/identity.js";
import { toBase64url, stringToBytes } from "../core/encoding.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import type { SovereigntyTier } from "../l4-reputation/tiers.js";

/** Default SHR validity window: 1 hour */
const DEFAULT_VALIDITY_MS = 60 * 60 * 1000;

/**
 * Default freshness window for the STALE_REPUTATION degradation.
 * If the most recent attestation is older than this, L4 is flagged stale.
 */
export const DEFAULT_FRESHNESS_WINDOW_DAYS = 30;

/**
 * Default dominance threshold for LOW_TIER_DOMINANCE. When the combined
 * share of self-attested and unverified attestations exceeds this fraction,
 * L4 is flagged as low-tier-dominated.
 */
export const DEFAULT_LOW_TIER_DOMINANCE_THRESHOLD = 0.6;

/**
 * Observed L4 reputation state used by the emitter. Callers gather these
 * facts from the reputation store + audit log; the emitter derives
 * degradations from them. Keeping evidence as plain data keeps the
 * generator synchronous and easy to test.
 */
export interface L4Evidence {
  /** Total attestations attributed to the signing identity */
  attestation_count: number;
  /** Count of attestations at each sovereignty tier */
  tier_distribution: Record<SovereigntyTier, number>;
  /** ISO timestamp of most recent attestation, or null when none exist */
  most_recent_attestation_at: string | null;
  /** Count of attestations with outcome_result === "disputed" */
  dispute_count: number;
  /** Attestation count per context label (optional; used by dashboard) */
  context_breakdown?: Record<string, number>;
  /**
   * True iff the `reputation_publish` tool has been successfully invoked
   * for this identity (i.e., there is at least one success audit entry).
   */
  verascore_linked: boolean;
  /**
   * Optional overrides for the emitter thresholds. Defaults apply when
   * omitted or when a field is missing.
   */
  thresholds?: {
    freshness_window_days?: number;
    low_tier_dominance_threshold?: number;
  };
}

export interface SHRGeneratorOptions {
  config: SanctuaryConfig;
  identityManager: IdentityManager;
  masterKey: Uint8Array;
  /** Override validity window (milliseconds). Default: 1 hour. */
  validityMs?: number;
  /**
   * Optional L4 reputation evidence. When provided, the generator emits
   * L4 degradations (NO_REPUTATION_HISTORY, LOW_TIER_DOMINANCE,
   * STALE_REPUTATION, DISPUTE_ON_RECORD, NO_VERASCORE_LINK) accordingly
   * and downgrades `layers.l4.status` to `degraded` when any fire.
   * When omitted, L4 is left at "active" (backward-compatible).
   */
  l4Evidence?: L4Evidence;
  /**
   * Clock override for deterministic testing of staleness behavior.
   * Defaults to the current wall clock.
   */
  now?: Date;
}

/**
 * Derive L4 degradations from observed evidence. Exported for unit tests.
 *
 * Emitter rules:
 *   - Empty store → NO_REPUTATION_HISTORY (warning). Other per-attestation
 *     signals (staleness, disputes, tier dominance) are skipped — they have
 *     no meaning when count == 0.
 *   - NO_VERASCORE_LINK fires independently of history: an agent with
 *     rich internal reputation but no external publish is still worth
 *     flagging.
 */
export function deriveL4Degradations(
  evidence: L4Evidence,
  now: Date = new Date()
): SHRDegradation[] {
  const out: SHRDegradation[] = [];

  const freshnessDays =
    evidence.thresholds?.freshness_window_days ?? DEFAULT_FRESHNESS_WINDOW_DAYS;
  const dominanceThreshold =
    evidence.thresholds?.low_tier_dominance_threshold ??
    DEFAULT_LOW_TIER_DOMINANCE_THRESHOLD;

  if (evidence.attestation_count === 0) {
    out.push({
      layer: "l4",
      code: "NO_REPUTATION_HISTORY",
      severity: "warning",
      description:
        "Signing identity has no recorded reputation attestations",
      mitigation:
        "Complete interactions that produce reputation_record calls, or import a portable reputation bundle",
    });
  } else {
    // LOW_TIER_DOMINANCE — most evidence comes from weakly-verified signers
    const lowTierCount =
      (evidence.tier_distribution["self-attested"] ?? 0) +
      (evidence.tier_distribution["unverified"] ?? 0);
    const lowTierShare = lowTierCount / evidence.attestation_count;
    if (lowTierShare > dominanceThreshold) {
      const pct = Math.round(lowTierShare * 100);
      out.push({
        layer: "l4",
        code: "LOW_TIER_DOMINANCE",
        severity: "info",
        description: `${pct}% of attestations are self-attested or unverified`,
        mitigation:
          "Complete sovereignty handshakes with counterparties to upgrade future attestations to verified tiers",
      });
    }

    // STALE_REPUTATION — no new attestation inside the freshness window
    if (evidence.most_recent_attestation_at) {
      const mostRecentMs = new Date(evidence.most_recent_attestation_at).getTime();
      if (!isNaN(mostRecentMs)) {
        const ageMs = now.getTime() - mostRecentMs;
        const windowMs = freshnessDays * 24 * 60 * 60 * 1000;
        if (ageMs > windowMs) {
          const ageDays = Math.round(ageMs / (24 * 60 * 60 * 1000));
          out.push({
            layer: "l4",
            code: "STALE_REPUTATION",
            severity: "info",
            description: `Most recent attestation is ${ageDays} days old (freshness window: ${freshnessDays} days)`,
            mitigation:
              "Record a fresh interaction outcome or refresh reputation from active counterparties",
          });
        }
      }
    }

    // DISPUTE_ON_RECORD — at least one attestation flagged as disputed
    if (evidence.dispute_count > 0) {
      out.push({
        layer: "l4",
        code: "DISPUTE_ON_RECORD",
        severity: "warning",
        description: `${evidence.dispute_count} attestation${evidence.dispute_count === 1 ? "" : "s"} marked as disputed`,
        mitigation:
          "Review disputed interactions; counterparties may weigh this signal when evaluating trust",
      });
    }
  }

  // NO_VERASCORE_LINK — independent of attestation history
  if (!evidence.verascore_linked) {
    out.push({
      layer: "l4",
      code: "NO_VERASCORE_LINK",
      severity: "info",
      description:
        "No successful reputation_publish call for this identity — reputation is not externally discoverable",
      mitigation:
        "Run reputation_publish to link this identity to a Verascore profile",
    });
  }

  return out;
}

/**
 * Generate and sign a Sovereignty Health Report.
 *
 * @param identityId - Which identity to sign with (defaults to primary)
 * @param opts - Generator dependencies
 * @returns The signed SHR, or an error string
 */
export function generateSHR(
  identityId: string | undefined,
  opts: SHRGeneratorOptions
): SignedSHR | string {
  const { config, identityManager, masterKey, validityMs, l4Evidence, now: nowOverride } = opts;

  // Resolve signing identity
  const identity = identityId
    ? identityManager.get(identityId)
    : identityManager.getDefault();

  if (!identity) {
    return "No identity available for signing. Create an identity first.";
  }

  const now = nowOverride ?? new Date();
  const expiresAt = new Date(now.getTime() + (validityMs ?? DEFAULT_VALIDITY_MS));

  // Assess degradations
  const degradations: SHRDegradation[] = [];

  if (config.execution.environment === "local-process") {
    degradations.push({
      layer: "l2",
      code: "PROCESS_ISOLATION_ONLY" as DegradationCode,
      severity: "warning",
      description: "Process-level isolation only (no TEE)",
      mitigation: "TEE support planned for a future release",
    });
    degradations.push({
      layer: "l2",
      code: "SELF_REPORTED_ATTESTATION" as DegradationCode,
      severity: "warning",
      description: "Attestation is self-reported (no hardware root of trust)",
      mitigation: "TEE attestation planned for a future release",
    });
  }

  // Note: L3 is NOT degraded. Sanctuary's Schnorr proofs + Pedersen commitments +
  // range proofs are genuine zero-knowledge proofs. The "commitment-only" label was
  // a categorization error — these ARE ZK proofs with selective disclosure capability.

  // L4 degradations — emitted when reputation evidence is supplied.
  // Without evidence the generator leaves L4 at "active" (backward-compatible
  // with older call sites; fresh code paths always provide evidence).
  const l4Degradations = l4Evidence
    ? deriveL4Degradations(l4Evidence, now)
    : [];
  degradations.push(...l4Degradations);

  const l4Status: LayerStatus =
    l4Degradations.length > 0 ? "degraded" : "active";

  // Build the SHR body
  const body: SHRBody = {
    shr_version: "1.0",
    implementation: {
      sanctuary_version: config.version,
      node_version: process.versions.node,
      generated_by: "sanctuary-mcp-server",
    },
    instance_id: identity.identity_id,
    generated_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    layers: {
      l1: {
        status: "active",
        encryption: config.state.encryption,
        key_custody: "self",
        integrity: config.state.integrity,
        identity_type: config.state.identity_provider,
        state_portable: true,
      },
      l2: {
        status: config.execution.environment === "local-process"
          ? "degraded"
          : "active",
        isolation_type: config.execution.environment,
        attestation_available: config.execution.attestation,
      },
      l3: {
        status: "active",
        proof_system: config.disclosure.proof_system,
        selective_disclosure: true,
      },
      l4: {
        status: l4Status,
        reputation_mode: config.reputation.mode,
        attestation_format: config.reputation.attestation_format,
        reputation_portable: true,
      },
    },
    capabilities: {
      handshake: true,
      shr_exchange: true,
      reputation_verify: true,
      encrypted_channel: false, // Not yet implemented
    },
    degradations,
  };

  // Canonical serialization for signing
  const canonical = canonicalizeForSigning(body);
  const payload = stringToBytes(canonical);

  // Sign with the identity's private key
  const encryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const signatureBytes = sign(
    payload,
    identity.encrypted_private_key,
    encryptionKey
  );

  return {
    body,
    signed_by: identity.public_key,
    signature: toBase64url(signatureBytes),
  };
}
