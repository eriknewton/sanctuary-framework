/**
 * Sanctuary MCP Server - Local provisioning audit payload builders.
 *
 * These helpers bridge the source-only P1 provisioning planner/action stack to
 * the v1.2 intelligence audit contracts. They construct data payloads only:
 * no AuditLog append, installer, Ollama pull/probe, selector mutation,
 * persistence, state write, or host mutation happens here.
 */

import type {
  IntelligenceAuditPayloadHeader,
  IntelligenceLocalModelRuntime,
  IntelligenceModelProvisionRefusalReason,
  IntelligenceModelProvisionRefusedPayload,
  IntelligenceModelPullPayload,
} from "../contracts/v1.2/intelligence-events.js";
import { INTEL_OPS } from "./audit-events.js";
import type { ModelManifestTier } from "./model-manifest.js";
import { SURFACES, type Surface } from "./types.js";

export type LocalProvisioningAuditPayloadBuildError =
  | "empty_surface_set"
  | "unknown_surface"
  | "missing_model_id"
  | "missing_runtime_tag"
  | "missing_manifest_version"
  | "invalid_expected_digest"
  | "invalid_observed_digest"
  | "digest_mismatch"
  | "missing_operator_consent"
  | "invalid_latency_ms"
  | "invalid_refusal_reason";

export type LocalProvisioningAuditOperation =
  | typeof INTEL_OPS.MODEL_PULL
  | typeof INTEL_OPS.MODEL_PROVISION_REFUSED;

export type LocalProvisioningAuditPayloadBuildResult<
  Payload extends IntelligenceModelPullPayload | IntelligenceModelProvisionRefusedPayload,
  Operation extends LocalProvisioningAuditOperation,
> =
  | { ok: true; operation: Operation; payload: Payload }
  | {
      ok: false;
      operation: Operation;
      reason: LocalProvisioningAuditPayloadBuildError;
      message: string;
    };

export interface BuildLocalProvisioningModelPullAuditPayloadParams {
  header: IntelligenceAuditPayloadHeader;
  surfaces: readonly Surface[];
  tier: ModelManifestTier;
  modelId: string;
  runtimeTag: string;
  manifestVersion: string;
  expectedWeightsSha256: string;
  observedManifestDigestSha256: string;
  operatorConsentEventId: string;
  latencyMs: number;
}

export interface BuildLocalProvisioningRefusalAuditPayloadParams {
  header: IntelligenceAuditPayloadHeader;
  surfaces: readonly Surface[];
  tier: ModelManifestTier | null;
  modelId?: string | null;
  runtime?: IntelligenceLocalModelRuntime | null;
  runtimeTag?: string | null;
  manifestVersion?: string | null;
  expectedWeightsSha256?: string | null;
  observedManifestDigestSha256?: string | null;
  reason: IntelligenceModelProvisionRefusalReason;
  operatorConsentEventId?: string | null;
  requiresOperatorConsent?: boolean;
  requiresNetworkEgress?: boolean;
}

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

const MODEL_PROVISION_REFUSAL_REASONS = [
  "ollama_unreachable",
  "operator_declined",
  "hardware_below_baseline",
  "tier_exceeds_hardware",
  "manifest_untrusted",
  "model_missing",
  "pull_failed",
  "digest_unavailable",
  "digest_mismatch",
] as const satisfies readonly IntelligenceModelProvisionRefusalReason[];

export function buildLocalProvisioningModelPullAuditPayload(
  params: BuildLocalProvisioningModelPullAuditPayloadParams,
): LocalProvisioningAuditPayloadBuildResult<
  IntelligenceModelPullPayload,
  typeof INTEL_OPS.MODEL_PULL
> {
  const surfaces = normalizeSurfaces(params.surfaces, INTEL_OPS.MODEL_PULL);
  if (!surfaces.ok) return surfaces;
  const modelId = requireNonEmpty(params.modelId, "missing_model_id", INTEL_OPS.MODEL_PULL);
  if (!modelId.ok) return modelId;
  const runtimeTag = requireNonEmpty(
    params.runtimeTag,
    "missing_runtime_tag",
    INTEL_OPS.MODEL_PULL,
  );
  if (!runtimeTag.ok) return runtimeTag;
  const manifestVersion = requireNonEmpty(
    params.manifestVersion,
    "missing_manifest_version",
    INTEL_OPS.MODEL_PULL,
  );
  if (!manifestVersion.ok) return manifestVersion;
  const expectedDigest = validateDigest(
    params.expectedWeightsSha256,
    "invalid_expected_digest",
    INTEL_OPS.MODEL_PULL,
  );
  if (!expectedDigest.ok) return expectedDigest;
  const observedDigest = validateDigest(
    params.observedManifestDigestSha256,
    "invalid_observed_digest",
    INTEL_OPS.MODEL_PULL,
  );
  if (!observedDigest.ok) return observedDigest;
  if (expectedDigest.value !== observedDigest.value) {
    return failure(
      INTEL_OPS.MODEL_PULL,
      "digest_mismatch",
      "observed model manifest digest must match the signed manifest digest before a model_pull payload can be built",
    );
  }
  const consent = requireNonEmpty(
    params.operatorConsentEventId,
    "missing_operator_consent",
    INTEL_OPS.MODEL_PULL,
  );
  if (!consent.ok) return consent;
  if (!Number.isFinite(params.latencyMs) || params.latencyMs < 0) {
    return failure(
      INTEL_OPS.MODEL_PULL,
      "invalid_latency_ms",
      "model_pull latency_ms must be a finite non-negative number",
    );
  }

  return {
    ok: true,
    operation: INTEL_OPS.MODEL_PULL,
    payload: {
      ...params.header,
      kind: "model_pull",
      surfaces: surfaces.value,
      tier: params.tier,
      model_id: modelId.value,
      runtime: "ollama",
      runtime_tag: runtimeTag.value,
      manifest_version: manifestVersion.value,
      expected_weights_sha256: expectedDigest.value,
      observed_manifest_digest_sha256: observedDigest.value,
      operator_consent_event_id: consent.value,
      latency_ms: params.latencyMs,
      requires_operator_consent: true,
      requires_network_egress: true,
      mutates_host: true,
      writes_fortress_state: false,
    },
  };
}

export function buildLocalProvisioningRefusalAuditPayload(
  params: BuildLocalProvisioningRefusalAuditPayloadParams,
): LocalProvisioningAuditPayloadBuildResult<
  IntelligenceModelProvisionRefusedPayload,
  typeof INTEL_OPS.MODEL_PROVISION_REFUSED
> {
  const surfaces = normalizeSurfaces(
    params.surfaces,
    INTEL_OPS.MODEL_PROVISION_REFUSED,
  );
  if (!surfaces.ok) return surfaces;
  if (!isProvisioningRefusalReason(params.reason)) {
    return failure(
      INTEL_OPS.MODEL_PROVISION_REFUSED,
      "invalid_refusal_reason",
      "model_provision_refused reason must be one of the stable refusal enums",
    );
  }
  const expectedDigest = validateOptionalDigest(
    params.expectedWeightsSha256 ?? null,
    "invalid_expected_digest",
    INTEL_OPS.MODEL_PROVISION_REFUSED,
  );
  if (!expectedDigest.ok) return expectedDigest;
  const observedDigest = validateOptionalDigest(
    params.observedManifestDigestSha256 ?? null,
    "invalid_observed_digest",
    INTEL_OPS.MODEL_PROVISION_REFUSED,
  );
  if (!observedDigest.ok) return observedDigest;

  return {
    ok: true,
    operation: INTEL_OPS.MODEL_PROVISION_REFUSED,
    payload: {
      ...params.header,
      kind: "model_provision_refused",
      surfaces: surfaces.value,
      tier: params.tier,
      model_id: optionalNonEmpty(params.modelId ?? null),
      runtime: params.runtime ?? null,
      runtime_tag: optionalNonEmpty(params.runtimeTag ?? null),
      manifest_version: optionalNonEmpty(params.manifestVersion ?? null),
      expected_weights_sha256: expectedDigest.value,
      observed_manifest_digest_sha256: observedDigest.value,
      reason: params.reason,
      operator_consent_event_id: optionalNonEmpty(params.operatorConsentEventId ?? null),
      requires_operator_consent: params.requiresOperatorConsent ?? false,
      requires_network_egress: params.requiresNetworkEgress ?? false,
      mutates_host: false,
      writes_fortress_state: false,
    },
  };
}

function normalizeSurfaces<Operation extends LocalProvisioningAuditOperation>(
  surfaces: readonly Surface[],
  operation: Operation,
):
  | { ok: true; value: Surface[] }
  | {
      ok: false;
      operation: Operation;
      reason: LocalProvisioningAuditPayloadBuildError;
      message: string;
    } {
  if (surfaces.length === 0) {
    return failure(operation, "empty_surface_set", "audit payload requires at least one surface");
  }
  const requested = new Set<Surface>();
  for (const surface of surfaces) {
    if (!SURFACES.includes(surface)) {
      return failure(operation, "unknown_surface", `unknown intelligence surface: ${String(surface)}`);
    }
    requested.add(surface);
  }
  return {
    ok: true,
    value: SURFACES.filter((surface) => requested.has(surface)),
  };
}

function requireNonEmpty<Operation extends LocalProvisioningAuditOperation>(
  value: string,
  reason: LocalProvisioningAuditPayloadBuildError,
  operation: Operation,
):
  | { ok: true; value: string }
  | {
      ok: false;
      operation: Operation;
      reason: LocalProvisioningAuditPayloadBuildError;
      message: string;
    } {
  const normalized = optionalNonEmpty(value);
  if (normalized === null) {
    return failure(operation, reason, `${reason} while building local provisioning audit payload`);
  }
  return { ok: true, value: normalized };
}

function validateDigest<Operation extends LocalProvisioningAuditOperation>(
  value: string,
  reason: LocalProvisioningAuditPayloadBuildError,
  operation: Operation,
):
  | { ok: true; value: string }
  | {
      ok: false;
      operation: Operation;
      reason: LocalProvisioningAuditPayloadBuildError;
      message: string;
    } {
  const normalized = optionalNonEmpty(value);
  if (normalized === null || !SHA256_HEX_RE.test(normalized)) {
    return failure(operation, reason, `${reason}: expected a lowercase sha256 hex digest`);
  }
  return { ok: true, value: normalized };
}

function validateOptionalDigest<Operation extends LocalProvisioningAuditOperation>(
  value: string | null,
  reason: LocalProvisioningAuditPayloadBuildError,
  operation: Operation,
):
  | { ok: true; value: string | null }
  | {
      ok: false;
      operation: Operation;
      reason: LocalProvisioningAuditPayloadBuildError;
      message: string;
    } {
  if (value === null) return { ok: true, value: null };
  return validateDigest(value, reason, operation);
}

function optionalNonEmpty(value: string | null): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function isProvisioningRefusalReason(
  reason: string,
): reason is IntelligenceModelProvisionRefusalReason {
  return MODEL_PROVISION_REFUSAL_REASONS.includes(
    reason as IntelligenceModelProvisionRefusalReason,
  );
}

function failure<Operation extends LocalProvisioningAuditOperation>(
  operation: Operation,
  reason: LocalProvisioningAuditPayloadBuildError,
  message: string,
): {
  ok: false;
  operation: Operation;
  reason: LocalProvisioningAuditPayloadBuildError;
  message: string;
} {
  return { ok: false, operation, reason, message };
}
