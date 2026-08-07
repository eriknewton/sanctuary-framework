/**
 * Sanctuary MCP Server - Local intelligence provisioning plan.
 *
 * P1 provisioning needs a source-only decision layer before any installer or
 * download path mutates an operator host. This module turns a verified signed
 * model manifest plus the hardware/Ollama probe results into a deterministic
 * plan. It never shells out, installs Ollama, pulls models, or writes state.
 */

import type {
  ModelManifestBody,
  ModelManifestModel,
  ModelManifestTier,
} from "./model-manifest.js";
import { MODEL_MANIFEST_TIERS, resolveModelForSurface } from "./model-manifest.js";
import type { OllamaModelDigestReport } from "./substrates/local.js";
import { SURFACES, type HardwareCapabilityReport, type Surface } from "./types.js";

export type LocalProvisioningPlanStatus =
  | "satisfied"
  | "needs_ollama"
  | "needs_pull"
  | "needs_digest_probe"
  | "blocked";

export type LocalProvisioningModelStatus =
  | "already_provisioned"
  | "install_ollama_required"
  | "pull_required"
  | "digest_probe_required"
  | "blocked";

export type LocalProvisioningBlockReason =
  | "hardware_below_baseline"
  | "tier_exceeds_hardware"
  | "digest_unavailable"
  | "digest_mismatch";

export interface LocalProvisioningModelPlan {
  modelId: string;
  runtimeTag: string;
  expectedWeightsSha256: string;
  paramsB: number;
  surfaces: Surface[];
  status: LocalProvisioningModelStatus;
  blockReason: LocalProvisioningBlockReason | null;
  observedManifestDigestSha256: string | null;
  observedBlobSha256: string[];
  requiresOperatorConsent: boolean;
  requiresNetworkEgress: boolean;
}

export interface LocalProvisioningSurfaceBinding {
  surface: Surface;
  modelId: string | null;
  runtimeTag: string | null;
  status: "disabled" | "model_required";
}

export interface BuildLocalProvisioningPlanParams {
  manifest: ModelManifestBody;
  hardware: HardwareCapabilityReport;
  /**
   * Optional operator-selected tier. When omitted, the detected hardware tier
   * picks the manifest bundle. The planner refuses elevation above hardware.
   */
  requestedTier?: ModelManifestTier;
  /** Optional subset of surfaces to plan; omitted means all closed surfaces. */
  surfaces?: readonly Surface[];
  /**
   * Digest reports from `OllamaClient.showModel()`, keyed by the report model
   * tag. Absence means the next safe action is a digest probe, not success.
   */
  digestReports?: readonly OllamaModelDigestReport[];
}

export interface LocalProvisioningPlan {
  status: LocalProvisioningPlanStatus;
  tier: ModelManifestTier | null;
  hardwareTier: HardwareCapabilityReport["tier"];
  blockReason: LocalProvisioningBlockReason | null;
  surfaceBindings: LocalProvisioningSurfaceBinding[];
  modelPlans: LocalProvisioningModelPlan[];
}

const TIER_RANK: Record<ModelManifestTier, number> = {
  baseline: 1,
  mid: 2,
  pro: 3,
};

export function buildLocalProvisioningPlan(
  params: BuildLocalProvisioningPlanParams,
): LocalProvisioningPlan {
  const tier = resolvePlanningTier(params.hardware, params.requestedTier);
  const surfaces = normalizeSurfaces(params.surfaces);
  if (tier.ok === false) {
    return {
      status: "blocked",
      tier: null,
      hardwareTier: params.hardware.tier,
      blockReason: tier.reason,
      surfaceBindings: surfaces.map((surface) => ({
        surface,
        modelId: null,
        runtimeTag: null,
        status: "disabled",
      })),
      modelPlans: [],
    };
  }

  const needed = new Map<string, { model: ModelManifestModel; surfaces: Surface[] }>();
  const surfaceBindings: LocalProvisioningSurfaceBinding[] = [];
  for (const surface of surfaces) {
    const model = resolveModelForSurface(params.manifest, tier.tier, surface);
    if (model === null) {
      surfaceBindings.push({
        surface,
        modelId: null,
        runtimeTag: null,
        status: "disabled",
      });
      continue;
    }

    surfaceBindings.push({
      surface,
      modelId: model.model_id,
      runtimeTag: model.runtime_tag,
      status: "model_required",
    });
    const existing = needed.get(model.model_id);
    if (existing) {
      existing.surfaces.push(surface);
    } else {
      needed.set(model.model_id, { model, surfaces: [surface] });
    }
  }

  const digestReports = new Map(
    (params.digestReports ?? []).map((report) => [report.model, report]),
  );
  const installedTags = new Set(params.hardware.ollamaModels);
  const modelPlans = [...needed.values()].map(({ model, surfaces: modelSurfaces }) =>
    planModel({
      model,
      surfaces: modelSurfaces,
      ollamaReachable: params.hardware.ollamaReachable,
      installedTags,
      digestReport: digestReports.get(model.runtime_tag) ?? null,
    }),
  );

  return {
    status: summarizeStatus(modelPlans),
    tier: tier.tier,
    hardwareTier: params.hardware.tier,
    blockReason: null,
    surfaceBindings,
    modelPlans,
  };
}

function resolvePlanningTier(
  hardware: HardwareCapabilityReport,
  requestedTier: ModelManifestTier | undefined,
): { ok: true; tier: ModelManifestTier } | { ok: false; reason: LocalProvisioningBlockReason } {
  if (hardware.tier === "below-baseline") {
    return { ok: false, reason: "hardware_below_baseline" };
  }
  const detectedTier = hardware.tier;
  const tier = requestedTier ?? detectedTier;
  if (!MODEL_MANIFEST_TIERS.includes(tier)) {
    return { ok: false, reason: "tier_exceeds_hardware" };
  }
  if (TIER_RANK[tier] > TIER_RANK[detectedTier]) {
    return { ok: false, reason: "tier_exceeds_hardware" };
  }
  return { ok: true, tier };
}

function normalizeSurfaces(surfaces: readonly Surface[] | undefined): Surface[] {
  if (surfaces === undefined) return [...SURFACES];
  const requested = new Set(surfaces);
  return SURFACES.filter((surface) => requested.has(surface));
}

function planModel(args: {
  model: ModelManifestModel;
  surfaces: Surface[];
  ollamaReachable: boolean;
  installedTags: ReadonlySet<string>;
  digestReport: OllamaModelDigestReport | null;
}): LocalProvisioningModelPlan {
  const base = {
    modelId: args.model.model_id,
    runtimeTag: args.model.runtime_tag,
    expectedWeightsSha256: args.model.weights_sha256,
    paramsB: args.model.params_b,
    surfaces: [...args.surfaces],
    observedManifestDigestSha256:
      args.digestReport?.manifestDigestSha256 ?? null,
    observedBlobSha256: args.digestReport?.blobSha256 ?? [],
  };

  if (!args.ollamaReachable) {
    return {
      ...base,
      status: "install_ollama_required",
      blockReason: null,
      requiresOperatorConsent: true,
      requiresNetworkEgress: false,
    };
  }

  if (!args.installedTags.has(args.model.runtime_tag)) {
    return {
      ...base,
      status: "pull_required",
      blockReason: null,
      requiresOperatorConsent: true,
      requiresNetworkEgress: true,
    };
  }

  if (args.digestReport === null) {
    return {
      ...base,
      status: "digest_probe_required",
      blockReason: null,
      requiresOperatorConsent: false,
      requiresNetworkEgress: false,
    };
  }

  if (args.digestReport.manifestDigestSha256 === null) {
    return {
      ...base,
      status: "blocked",
      blockReason: "digest_unavailable",
      requiresOperatorConsent: false,
      requiresNetworkEgress: false,
    };
  }

  if (args.digestReport.manifestDigestSha256 !== args.model.weights_sha256) {
    return {
      ...base,
      status: "blocked",
      blockReason: "digest_mismatch",
      requiresOperatorConsent: false,
      requiresNetworkEgress: false,
    };
  }

  return {
    ...base,
    status: "already_provisioned",
    blockReason: null,
    requiresOperatorConsent: false,
    requiresNetworkEgress: false,
  };
}

function summarizeStatus(
  plans: readonly LocalProvisioningModelPlan[],
): LocalProvisioningPlanStatus {
  if (plans.some((plan) => plan.status === "blocked")) return "blocked";
  if (plans.some((plan) => plan.status === "install_ollama_required")) {
    return "needs_ollama";
  }
  if (plans.some((plan) => plan.status === "pull_required")) {
    return "needs_pull";
  }
  if (plans.some((plan) => plan.status === "digest_probe_required")) {
    return "needs_digest_probe";
  }
  return "satisfied";
}
