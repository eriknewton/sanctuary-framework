/**
 * Sanctuary MCP Server - Local provisioning consent packet.
 *
 * Turns a source-only action preview into the deterministic data a future CLI
 * prompt can render. This module does not render UI, build shell commands,
 * install Ollama, pull/probe models, append audit entries, write selector
 * config, persist provenance, or mutate host/fortress state.
 */

import type {
  LocalProvisioningAction,
  LocalProvisioningActionKind,
  LocalProvisioningActionPreview,
  LocalProvisioningActionReason,
} from "./local-provisioning-actions.js";
import type { LocalProvisioningBlockReason } from "./local-provisioning-plan.js";
import type { ModelManifestTier } from "./model-manifest.js";
import type { HardwareCapabilityReport, Surface } from "./types.js";

export type LocalProvisioningConsentPacketStatus =
  | "not_required"
  | "requires_operator_consent"
  | "refused";

export type LocalProvisioningConsentScope =
  | "ollama_install"
  | "model_pull"
  | "manual_review"
  | "not_required"
  | "refused";

export interface LocalProvisioningConsentAction {
  kind: LocalProvisioningActionKind;
  consentScope: LocalProvisioningConsentScope;
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

export interface LocalProvisioningConsentPacket {
  status: LocalProvisioningConsentPacketStatus;
  planStatus: LocalProvisioningActionPreview["planStatus"];
  tier: ModelManifestTier | null;
  hardwareTier: HardwareCapabilityReport["tier"];
  planBlockReason: LocalProvisioningBlockReason | null;
  disabledSurfaces: Surface[];
  consentActions: LocalProvisioningConsentAction[];
  refusalActions: LocalProvisioningConsentAction[];
  nonConsentActions: LocalProvisioningConsentAction[];
  requiresOperatorConsent: boolean;
  requiresNetworkEgress: boolean;
  mutatesHost: boolean;
  writesFortressState: boolean;
}

export function buildLocalProvisioningConsentPacket(
  preview: LocalProvisioningActionPreview,
): LocalProvisioningConsentPacket {
  const actions = preview.actions.map(copyAction);
  const refusalActions = actions.filter(
    (action) => action.kind === "refuse_provisioning",
  );
  const consentActions = actions.filter(
    (action) =>
      action.requiresOperatorConsent && action.kind !== "refuse_provisioning",
  );
  const nonConsentActions = actions.filter(
    (action) =>
      !action.requiresOperatorConsent && action.kind !== "refuse_provisioning",
  );

  return {
    status: summarizeConsentStatus(refusalActions, consentActions),
    planStatus: preview.planStatus,
    tier: preview.tier,
    hardwareTier: preview.hardwareTier,
    planBlockReason: preview.planBlockReason,
    disabledSurfaces: [...preview.disabledSurfaces],
    consentActions,
    refusalActions,
    nonConsentActions,
    requiresOperatorConsent: consentActions.length > 0,
    requiresNetworkEgress: consentActions.some(
      (action) => action.requiresNetworkEgress,
    ),
    mutatesHost: consentActions.some((action) => action.mutatesHost),
    writesFortressState: actions.some((action) => action.writesFortressState),
  };
}

function summarizeConsentStatus(
  refusalActions: readonly LocalProvisioningConsentAction[],
  consentActions: readonly LocalProvisioningConsentAction[],
): LocalProvisioningConsentPacketStatus {
  if (refusalActions.length > 0) return "refused";
  if (consentActions.length > 0) return "requires_operator_consent";
  return "not_required";
}

function copyAction(action: LocalProvisioningAction): LocalProvisioningConsentAction {
  return {
    kind: action.kind,
    consentScope: consentScopeForAction(action),
    modelId: action.modelId,
    runtimeTag: action.runtimeTag,
    surfaces: [...action.surfaces],
    expectedWeightsSha256: action.expectedWeightsSha256,
    observedManifestDigestSha256: action.observedManifestDigestSha256,
    paramsB: action.paramsB,
    reason: action.reason,
    requiresOperatorConsent: action.requiresOperatorConsent,
    requiresNetworkEgress: action.requiresNetworkEgress,
    mutatesHost: action.mutatesHost,
    writesFortressState: action.writesFortressState,
  };
}

function consentScopeForAction(
  action: LocalProvisioningAction,
): LocalProvisioningConsentScope {
  if (action.kind === "refuse_provisioning") return "refused";
  if (!action.requiresOperatorConsent) return "not_required";
  if (action.kind === "install_ollama") return "ollama_install";
  if (action.kind === "pull_model") return "model_pull";
  return "manual_review";
}
