/**
 * Sanctuary MCP Server — Ping Identity Gateway Adapter
 *
 * Transforms Sovereignty Health Reports (SHRs) into authorization contexts
 * compatible with Ping Identity's Agent Gateway for runtime access decisions.
 *
 * The adapter generates:
 * 1. Overall sovereignty score (0-100)
 * 2. Per-layer capability assessments
 * 3. Authorization-relevant feature flags
 * 4. Recommended trust levels and constraints
 * 5. Authorization policy recommendations for the gateway
 */

import type { SignedSHR, SHRBody, SHRDegradation } from "./types.js";
import { verifySHR } from "./verifier.js";

// ── Gateway Authorization Context ───────────────────────────────────────

/**
 * A Ping Identity-compatible authorization context derived from an SHR.
 * This structure is designed to be passed to the Agent Gateway for
 * runtime access decisions.
 */
export interface PingAuthorizationContext {
  /** SHR version — for compatibility tracking */
  shr_version: string;

  /** Agent's Ed25519 public key (base64url) — for identity verification */
  agent_identity: string;

  /** When the context was generated (ISO 8601) */
  generated_at: string;

  /** When the underlying SHR expires (ISO 8601) */
  context_expires_at: string;

  /** Overall sovereignty score (0-100) */
  overall_score: number;

  /** Recommended trust level based on sovereignty posture */
  recommended_trust_level: "full" | "elevated" | "standard" | "restricted";

  /** Per-layer sovereignty scores */
  layer_scores: {
    l1_cognitive: number;
    l2_operational: number;
    l3_disclosure: number;
    l4_reputation: number;
  };

  /** Per-layer status: active, degraded, inactive */
  layer_status: {
    l1_cognitive: string;
    l2_operational: string;
    l3_disclosure: string;
    l4_reputation: string;
  };

  /** Authorization-relevant capability flags */
  authorization_signals: {
    /** Is human approval required for sensitive operations? */
    approval_gate_active: boolean;

    /** Is outbound data filtered by context gating? */
    context_gating_active: boolean;

    /** Is agent state encrypted at rest? */
    encryption_at_rest: boolean;

    /** Is anomaly detection / behavioral baseline active? */
    behavioral_baseline_active: boolean;

    /** Does the agent have cryptographic identity (Ed25519)? */
    identity_verified: boolean;

    /** Can the agent conduct zero-knowledge proofs? */
    zero_knowledge_capable: boolean;

    /** Is selective disclosure enabled? */
    selective_disclosure_active: boolean;

    /** Can the agent perform portable reputation verification? */
    reputation_portable: boolean;

    /** Can the agent conduct handshakes? */
    handshake_capable: boolean;
  };

  /** Degradations that affect authorization */
  degradations: GatewayDegradation[];

  /** Recommended authorization constraints */
  recommended_constraints: AuthorizationConstraint[];

  /** The underlying SHR signature for verification */
  shr_signature: string;

  /** Base64url-encoded public key that signed the SHR */
  shr_signed_by: string;
}

/**
 * A degradation reframed for authorization context.
 */
export interface GatewayDegradation {
  layer: string;
  code: string;
  severity: string;
  description: string;
  authorization_impact: string;
}

/**
 * An authorization constraint recommended based on the agent's sovereignty posture.
 */
export interface AuthorizationConstraint {
  /** Constraint type: read_only, requires_approval, restricted_scope, identity_verification_required, etc. */
  type: string;

  /** Human-readable description */
  description: string;

  /** Reason this constraint is recommended (which sovereignty gap drives it) */
  rationale: string;

  /** Priority: high, medium, low */
  priority: "high" | "medium" | "low";
}

// ── Layer Scoring Model ──────────────────────────────────────────────────

/**
 * Layer-specific scoring weights and degradation impacts.
 *
 * Each layer starts at 100 points. Degradations subtract points based on severity.
 * "critical" = -40, "warning" = -25, "info" = -10.
 */
const LAYER_WEIGHTS = {
  l1: 100,
  l2: 100,
  l3: 100,
  l4: 100,
};

const DEGRADATION_IMPACT = {
  critical: 40,
  warning: 25,
  info: 10,
};

// ── Public API ───────────────────────────────────────────────────────────

/**
 * Transform an SHR into a Ping Identity Gateway authorization context.
 *
 * Verifies the SHR (signature, expiry, identity binding) before trusting any
 * of its self-reported fields — see the invariant comment at the top of the
 * function body.
 *
 * @param shr - The signed SHR to transform (a counterparty's SHR, or a
 *   freshly self-signed one — both paths verify identically)
 * @returns A PingAuthorizationContext ready for the Agent Gateway
 * @throws {Error} if `shr` fails verification (invalid signature, expired,
 *   unbound instance_id, malformed schema/layers) — no trust decision is
 *   minted from an unverified SHR
 */
export function transformSHRForGateway(shr: SignedSHR): PingAuthorizationContext {
  // PUBLIC trust-minting entry point: ALWAYS the real clock. `now` is
  // deliberately NOT a parameter here. A trust decision must not let its
  // caller choose the temporal reference — a request-wired `now` in the past
  // would make a genuinely-signed-but-EXPIRED SHR verify, re-opening exactly
  // the expiry bypass verifySHR closes. Clock injection for deterministic
  // tests lives in transformSHRForGatewayAt below, which no production/MCP
  // path reaches.
  return transformSHRForGatewayAt(shr, new Date());
}

/**
 * TEST-ONLY clock seam for transformSHRForGateway. NOT part of the public SHR
 * surface and NOT re-exported from any barrel; the only callers are
 * transformSHRForGateway (real clock) and the gateway-adapter tests (fixed-time
 * fixtures). Never wire `now` to a request-supplied value — see
 * transformSHRForGateway's doc for why that would re-open the expiry bypass.
 */
export function transformSHRForGatewayAt(
  shr: SignedSHR,
  now: Date,
): PingAuthorizationContext {
  // SHR-GW-01 (rule-7, semantic provenance): every field read below —
  // layers, capabilities, degradations, instance_id — is SELF-REPORTED by
  // whoever holds `shr.signed_by`'s private key. It carries no credibility
  // until `verifySHR` (server/src/shr/verifier.ts) has confirmed the Ed25519
  // signature over the canonical body, checked temporal validity, and bound
  // `instance_id` to `signed_by` (directly or via a verified rotation
  // chain). This function mints a trust decision (score up to 100, up to
  // "full" trust) FROM those fields, so an unverified SHR must never reach
  // the scoring logic below: a counterparty could otherwise self-report
  // "all layers active" and be handed the Gateway's highest trust tier with
  // no cryptographic backing. Fail closed — do not fall through to scoring
  // on a verification failure.
  const verification = verifySHR(shr, now);
  if (!verification.valid) {
    throw new Error(
      `Cannot mint a gateway trust decision from an unverified SHR: ${verification.errors.join("; ")}`
    );
  }

  const { body, signed_by, signature } = shr;

  // Calculate per-layer scores
  const layerScores = calculateLayerScores(body);

  // Calculate overall score (weighted average)
  const overallScore = calculateOverallScore(layerScores);

  // Determine recommended trust level
  const trustLevel = determineTrustLevel(overallScore);

  // Extract authorization signals from SHR
  const signals = extractAuthorizationSignals(body);

  // Transform degradations for authorization context
  const degradations = transformDegradations(body.degradations);

  // Generate recommended constraints
  const constraints = generateAuthorizationConstraints(body, degradations);

  return {
    shr_version: body.shr_version,
    agent_identity: signed_by,
    generated_at: new Date().toISOString(),
    context_expires_at: body.expires_at,
    overall_score: overallScore,
    recommended_trust_level: trustLevel,
    layer_scores: {
      l1_cognitive: layerScores.l1,
      l2_operational: layerScores.l2,
      l3_disclosure: layerScores.l3,
      l4_reputation: layerScores.l4,
    },
    layer_status: {
      l1_cognitive: body.layers.l1.status,
      l2_operational: body.layers.l2.status,
      l3_disclosure: body.layers.l3.status,
      l4_reputation: body.layers.l4.status,
    },
    authorization_signals: signals,
    degradations,
    recommended_constraints: constraints,
    shr_signature: signature,
    shr_signed_by: signed_by,
  };
}

/**
 * Calculate sovereignty scores for each layer based on the SHR.
 */
function calculateLayerScores(
  body: SHRBody
): {
  l1: number;
  l2: number;
  l3: number;
  l4: number;
} {
  const layers = body.layers;
  const degradations = body.degradations;

  let l1Score = LAYER_WEIGHTS.l1;
  let l2Score = LAYER_WEIGHTS.l2;
  let l3Score = LAYER_WEIGHTS.l3;
  let l4Score = LAYER_WEIGHTS.l4;

  // Apply degradation penalties
  for (const deg of degradations) {
    const impact =
      DEGRADATION_IMPACT[deg.severity as keyof typeof DEGRADATION_IMPACT] || 10;

    if (deg.layer === "l1") {
      l1Score = Math.max(0, l1Score - impact);
    } else if (deg.layer === "l2") {
      l2Score = Math.max(0, l2Score - impact);
    } else if (deg.layer === "l3") {
      l3Score = Math.max(0, l3Score - impact);
    } else if (deg.layer === "l4") {
      l4Score = Math.max(0, l4Score - impact);
    }
  }

  // Bonus points for active status (if no degradations bring it below a threshold)
  if (layers.l1.status === "active" && l1Score > 50) l1Score = Math.min(100, l1Score + 5);
  if (layers.l2.status === "active" && l2Score > 50) l2Score = Math.min(100, l2Score + 5);
  if (layers.l3.status === "active" && l3Score > 50) l3Score = Math.min(100, l3Score + 5);
  if (layers.l4.status === "active" && l4Score > 50) l4Score = Math.min(100, l4Score + 5);

  // Inactive layers score 0
  if (layers.l1.status === "inactive") l1Score = 0;
  if (layers.l2.status === "inactive") l2Score = 0;
  if (layers.l3.status === "inactive") l3Score = 0;
  if (layers.l4.status === "inactive") l4Score = 0;

  return {
    l1: Math.round(l1Score),
    l2: Math.round(l2Score),
    l3: Math.round(l3Score),
    l4: Math.round(l4Score),
  };
}

/**
 * Calculate overall sovereignty score (0-100) as weighted average of layer scores.
 */
function calculateOverallScore(layerScores: {
  l1: number;
  l2: number;
  l3: number;
  l4: number;
}): number {
  const average = (layerScores.l1 + layerScores.l2 + layerScores.l3 + layerScores.l4) / 4;
  return Math.round(average);
}

/**
 * Determine recommended trust level based on overall score.
 */
function determineTrustLevel(
  score: number
): "full" | "elevated" | "standard" | "restricted" {
  if (score >= 80) return "full";
  if (score >= 60) return "elevated";
  if (score >= 40) return "standard";
  return "restricted";
}

/**
 * Extract authorization-relevant signals from the SHR.
 */
function extractAuthorizationSignals(body: SHRBody): PingAuthorizationContext["authorization_signals"] {
  const l1 = body.layers.l1;
  const l3 = body.layers.l3;
  const l4 = body.layers.l4;

  // Infer signals from layer configuration
  return {
    approval_gate_active: body.capabilities.handshake, // Handshake implies human loop capability
    context_gating_active: body.capabilities.encrypted_channel, // Proxy for gating capability
    encryption_at_rest: l1.encryption !== "none" && l1.encryption !== "unencrypted",
    behavioral_baseline_active: false, // Would need explicit field in SHR v1.1
    identity_verified: l1.identity_type === "ed25519" || l1.identity_type !== "none",
    zero_knowledge_capable: l3.status === "active",
    selective_disclosure_active: l3.selective_disclosure,
    reputation_portable: l4.reputation_portable,
    handshake_capable: body.capabilities.handshake,
  };
}

/**
 * Transform degradations into authorization-aware format.
 */
function transformDegradations(degradations: SHRDegradation[]): GatewayDegradation[] {
  return degradations.map((deg) => {
    let authzImpact: string;

    if (deg.code === "NO_TEE") {
      authzImpact = "Restricted to read-only operations until TEE available";
    } else if (deg.code === "PROCESS_ISOLATION_ONLY") {
      authzImpact = "Requires additional identity verification";
    } else if (deg.code === "COMMITMENT_ONLY") {
      authzImpact = "Limited data sharing scope — no zero-knowledge proofs";
    } else if (deg.code === "NO_ZK_PROOFS") {
      authzImpact = "Cannot perform confidential disclosures";
    } else if (deg.code === "SELF_REPORTED_ATTESTATION") {
      authzImpact = "Attestation trust degraded — human verification recommended";
    } else if (deg.code === "NO_SELECTIVE_DISCLOSURE") {
      authzImpact = "Must share entire data context, cannot redact";
    } else if (deg.code === "BASIC_SYBIL_ONLY") {
      authzImpact = "Restrict to interactions with known agents only";
    } else if (deg.code === "NO_REPUTATION_HISTORY") {
      authzImpact =
        "No prior reputation — treat as a new counterparty; require escrow or human approval for value transfer";
    } else if (deg.code === "LOW_TIER_DOMINANCE") {
      authzImpact =
        "Reputation dominated by self-attested / unverified signers — weight accordingly, require additional confirmation on high-value actions";
    } else if (deg.code === "STALE_REPUTATION") {
      authzImpact =
        "Reputation is stale — may not reflect current behavior; refresh before relying on it";
    } else if (deg.code === "DISPUTE_ON_RECORD") {
      authzImpact =
        "Disputes on record — review dispute context before extending trust beyond low-value interactions";
    } else if (deg.code === "NO_VERASCORE_LINK") {
      authzImpact =
        "No external reputation profile — counterparty cannot independently discover reputation bundle";
    } else {
      authzImpact = "Unknown authorization impact";
    }

    return {
      layer: deg.layer,
      code: deg.code,
      severity: deg.severity,
      description: deg.description,
      authorization_impact: authzImpact,
    };
  });
}

/**
 * Generate recommended authorization constraints based on sovereignty posture.
 */
function generateAuthorizationConstraints(
  body: SHRBody,
  _degradations: GatewayDegradation[]
): AuthorizationConstraint[] {
  const constraints: AuthorizationConstraint[] = [];
  const layers = body.layers;

  // L1 (Cognitive Sovereignty) constraints
  if (layers.l1.status === "degraded" || layers.l1.key_custody !== "self") {
    constraints.push({
      type: "identity_verification_required",
      description: "Additional identity verification required for sensitive operations",
      rationale: "L1 is degraded or key custody is not self-managed",
      priority: "high",
    });
  }

  if (!layers.l1.state_portable) {
    constraints.push({
      type: "location_bound",
      description: "Agent state is not portable — restrict to home environment",
      rationale: "State cannot be safely migrated across boundaries",
      priority: "medium",
    });
  }

  // L2 (Operational Isolation) constraints
  if (layers.l2.status === "degraded" || layers.l2.isolation_type === "local-process") {
    constraints.push({
      type: "read_only",
      description: "Restrict to read-only operations until operational isolation improves",
      rationale: "L2 isolation is process-level only (no TEE)",
      priority: "high",
    });
  }

  if (!layers.l2.attestation_available) {
    constraints.push({
      type: "requires_approval",
      description: "Human approval required for writes and sensitive reads",
      rationale: "No attestation available — self-reported integrity only",
      priority: "high",
    });
  }

  // L3 (Selective Disclosure) constraints
  if (layers.l3.status === "degraded" || !layers.l3.selective_disclosure) {
    constraints.push({
      type: "restricted_scope",
      description: "Limit data sharing to minimal required scope — no selective disclosure",
      rationale: "Agent cannot redact data or prove predicates without revealing all context",
      priority: "high",
    });
  }

  // Note: "schnorr-pedersen" (and legacy "commitment-only") both provide genuine ZK proofs.
  // No additional constraint needed for the proof system.

  // L4 (Reputation) constraints
  if (layers.l4.status === "degraded") {
    constraints.push({
      type: "known_agents_only",
      description: "Restrict interactions to known, pre-approved agents",
      rationale: "Reputation layer is degraded",
      priority: "medium",
    });
  }

  if (!layers.l4.reputation_portable) {
    constraints.push({
      type: "location_bound",
      description: "Reputation is not portable — restrict to home environment",
      rationale: "Cannot present reputation to external parties",
      priority: "low",
    });
  }

  // Overall score-based constraints
  const layerScores = calculateLayerScores(body);
  const overallScore = calculateOverallScore(layerScores);

  if (overallScore < 40) {
    constraints.push({
      type: "restricted_scope",
      description: "Overall sovereignty score below threshold — restrict to non-sensitive operations",
      rationale: `Overall sovereignty score is ${overallScore}/100`,
      priority: "high",
    });
  }

  return constraints;
}

// ── Generic Gateway Export ───────────────────────────────────────────────

/**
 * Generic authorization context (format-agnostic).
 * Used when format is "generic" instead of "ping".
 */
export interface GenericAuthorizationContext {
  agent_id: string;
  sovereignty_score: number;
  trust_level: string;
  layer_scores: Record<string, number>;
  capabilities: Record<string, boolean>;
  constraints: Array<{
    type: string;
    description: string;
  }>;
  expires_at: string;
  signature: string;
}

/**
 * Transform an SHR into a generic authorization context.
 */
export function transformSHRGeneric(shr: SignedSHR): GenericAuthorizationContext {
  // Real clock only — see transformSHRForGateway's doc for why a trust-minting
  // entry point does not accept a caller-chosen clock.
  const context = transformSHRForGateway(shr);

  return {
    agent_id: context.agent_identity,
    sovereignty_score: context.overall_score,
    trust_level: context.recommended_trust_level,
    layer_scores: {
      l1: context.layer_scores.l1_cognitive,
      l2: context.layer_scores.l2_operational,
      l3: context.layer_scores.l3_disclosure,
      l4: context.layer_scores.l4_reputation,
    },
    capabilities: context.authorization_signals,
    constraints: context.recommended_constraints.map((c) => ({
      type: c.type,
      description: c.description,
    })),
    expires_at: context.context_expires_at,
    signature: context.shr_signature,
  };
}
