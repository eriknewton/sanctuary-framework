/**
 * Sanctuary MCP Server - Local provisioning action preview.
 *
 * The P1 consent ceremony needs a truthful plan-print layer before any host
 * mutation. This module turns the source-only provisioning plan into data-only
 * operator actions; it never shells out, builds command strings, pulls models,
 * probes Ollama, writes selector config, or persists provenance itself.
 */

import type {
  LocalProvisioningBlockReason,
  LocalProvisioningModelPlan,
  LocalProvisioningPlan,
  LocalProvisioningPlanStatus,
} from "./local-provisioning-plan.js";
import { SURFACES, type HardwareCapabilityReport, type Surface } from "./types.js";
import type { ModelManifestTier } from "./model-manifest.js";

export type LocalProvisioningActionPreviewStatus =
  | "satisfied"
  | "action_required"
  | "refused";

export type LocalProvisioningActionKind =
  | "install_ollama"
  | "pull_model"
  | "probe_digest"
  | "declare_model_provenance"
  | "refuse_provisioning";

export type LocalProvisioningActionReason =
  | "ollama_unreachable"
  | "model_missing"
  | "digest_probe_required"
  | "already_verified"
  | "plan_blocked"
  | LocalProvisioningBlockReason;

export interface LocalProvisioningAction {
  kind: LocalProvisioningActionKind;
  modelId: string | null;
  runtimeTag: string | null;
  surfaces: Surface[];
  expectedWeightsSha256: string | null;
  observedManifestDigestSha256: string | null;
  paramsB: number | null;
  reason: LocalProvisioningActionReason;
  requiresOperatorConsent: boolean;
  requiresNetworkEgress: boolean;
  mutatesHost: boolean;
  writesFortressState: boolean;
}

export interface LocalProvisioningActionPreview {
  status: LocalProvisioningActionPreviewStatus;
  planStatus: LocalProvisioningPlanStatus;
  tier: ModelManifestTier | null;
  hardwareTier: HardwareCapabilityReport["tier"];
  planBlockReason: LocalProvisioningBlockReason | null;
  disabledSurfaces: Surface[];
  actions: LocalProvisioningAction[];
  requiresOperatorConsent: boolean;
  requiresNetworkEgress: boolean;
  mutatesHost: boolean;
  writesFortressState: boolean;
}

export function buildLocalProvisioningActionPreview(
  plan: LocalProvisioningPlan,
): LocalProvisioningActionPreview {
  const actions: LocalProvisioningAction[] = [];
  const installRequired = plan.modelPlans.some(
    (modelPlan) => modelPlan.status === "install_ollama_required",
  );

  if (plan.blockReason !== null && plan.modelPlans.length === 0) {
    actions.push({
      kind: "refuse_provisioning",
      modelId: null,
      runtimeTag: null,
      surfaces: disabledSurfaces(plan),
      expectedWeightsSha256: null,
      observedManifestDigestSha256: null,
      paramsB: null,
      reason: plan.blockReason,
      requiresOperatorConsent: false,
      requiresNetworkEgress: false,
      mutatesHost: false,
      writesFortressState: false,
    });
  }

  if (installRequired) {
    actions.push({
      kind: "install_ollama",
      modelId: null,
      runtimeTag: null,
      surfaces: surfacesForPlans(
        plan.modelPlans.filter(
          (modelPlan) => modelPlan.status === "install_ollama_required",
        ),
      ),
      expectedWeightsSha256: null,
      observedManifestDigestSha256: null,
      paramsB: null,
      reason: "ollama_unreachable",
      requiresOperatorConsent: true,
      requiresNetworkEgress: true,
      mutatesHost: true,
      writesFortressState: false,
    });
  }

  for (const modelPlan of plan.modelPlans) {
    const action = actionForModelPlan(modelPlan);
    if (action !== null) actions.push(action);
  }

  return {
    status: summarizePreviewStatus(actions),
    planStatus: plan.status,
    tier: plan.tier,
    hardwareTier: plan.hardwareTier,
    planBlockReason: plan.blockReason,
    disabledSurfaces: disabledSurfaces(plan),
    actions,
    requiresOperatorConsent: actions.some((action) => action.requiresOperatorConsent),
    requiresNetworkEgress: actions.some((action) => action.requiresNetworkEgress),
    mutatesHost: actions.some((action) => action.mutatesHost),
    writesFortressState: actions.some((action) => action.writesFortressState),
  };
}

function actionForModelPlan(
  modelPlan: LocalProvisioningModelPlan,
): LocalProvisioningAction | null {
  switch (modelPlan.status) {
    case "install_ollama_required":
    case "pull_required":
      return modelAction(modelPlan, {
        kind: "pull_model",
        reason: "model_missing",
        requiresOperatorConsent: true,
        requiresNetworkEgress: true,
        mutatesHost: true,
        writesFortressState: false,
      });
    case "digest_probe_required":
      return modelAction(modelPlan, {
        kind: "probe_digest",
        reason: "digest_probe_required",
        requiresOperatorConsent: false,
        requiresNetworkEgress: false,
        mutatesHost: false,
        writesFortressState: false,
      });
    case "blocked":
      return modelAction(modelPlan, {
        kind: "refuse_provisioning",
        reason: modelPlan.blockReason ?? "plan_blocked",
        requiresOperatorConsent: false,
        requiresNetworkEgress: false,
        mutatesHost: false,
        writesFortressState: false,
      });
    case "already_provisioned":
      return modelAction(modelPlan, {
        kind: "declare_model_provenance",
        reason: "already_verified",
        requiresOperatorConsent: false,
        requiresNetworkEgress: false,
        mutatesHost: false,
        writesFortressState: true,
      });
    default:
      return null;
  }
}

function modelAction(
  modelPlan: LocalProvisioningModelPlan,
  effect: Pick<
    LocalProvisioningAction,
    | "kind"
    | "reason"
    | "requiresOperatorConsent"
    | "requiresNetworkEgress"
    | "mutatesHost"
    | "writesFortressState"
  >,
): LocalProvisioningAction {
  return {
    ...effect,
    modelId: modelPlan.modelId,
    runtimeTag: modelPlan.runtimeTag,
    surfaces: orderedSurfaces(modelPlan.surfaces),
    expectedWeightsSha256: modelPlan.expectedWeightsSha256,
    observedManifestDigestSha256: modelPlan.observedManifestDigestSha256,
    paramsB: modelPlan.paramsB,
  };
}

function disabledSurfaces(plan: LocalProvisioningPlan): Surface[] {
  return orderedSurfaces(
    plan.surfaceBindings
      .filter((binding) => binding.status === "disabled")
      .map((binding) => binding.surface),
  );
}

function surfacesForPlans(plans: readonly LocalProvisioningModelPlan[]): Surface[] {
  return orderedSurfaces(plans.flatMap((plan) => plan.surfaces));
}

function orderedSurfaces(surfaces: readonly Surface[]): Surface[] {
  const requested = new Set(surfaces);
  return SURFACES.filter((surface) => requested.has(surface));
}

function summarizePreviewStatus(
  actions: readonly LocalProvisioningAction[],
): LocalProvisioningActionPreviewStatus {
  if (actions.some((action) => action.kind === "refuse_provisioning")) {
    return "refused";
  }
  if (
    actions.some(
      (action) =>
        action.kind === "install_ollama" ||
        action.kind === "pull_model" ||
        action.kind === "probe_digest",
    )
  ) {
    return "action_required";
  }
  return "satisfied";
}
