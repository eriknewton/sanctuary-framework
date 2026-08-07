/**
 * Sanctuary MCP Server - Local provisioning provenance receipts.
 *
 * The planner decides what is installed, missing, or unsafe. This receipt
 * layer is the next false-green boundary: it mints model provenance only for
 * entries that are already provisioned and whose observed manifest digest still
 * matches the verified Sanctuary model manifest.
 */

import type { ModelProvenance } from "../operational/model-provenance.js";
import type { ModelManifestBody, ModelManifestTier } from "./model-manifest.js";
import { provenanceFromModelManifestModel } from "./model-manifest.js";
import type {
  LocalProvisioningBlockReason,
  LocalProvisioningModelPlan,
  LocalProvisioningModelStatus,
  LocalProvisioningPlan,
  LocalProvisioningPlanStatus,
} from "./local-provisioning-plan.js";
import type { Surface } from "./types.js";

export type LocalProvisioningReceiptStatus =
  | "complete"
  | "partial"
  | "refused";

export type LocalProvisioningReceiptRefusalReason =
  | "plan_blocked"
  | "model_not_in_manifest"
  | "plan_manifest_mismatch"
  | "model_not_provisioned"
  | "digest_unavailable"
  | "digest_mismatch";

export interface LocalProvisioningDeclaredModel {
  modelId: string;
  runtimeTag: string;
  surfaces: Surface[];
  manifestVersion: number;
  weightsSha256: string;
  observedManifestDigestSha256: string;
  provenance: ModelProvenance;
}

export interface LocalProvisioningRefusedModel {
  modelId: string;
  runtimeTag: string;
  surfaces: Surface[];
  status: LocalProvisioningModelStatus;
  reason: LocalProvisioningReceiptRefusalReason;
  blockReason: LocalProvisioningBlockReason | null;
  expectedWeightsSha256: string;
  observedManifestDigestSha256: string | null;
}

export interface BuildLocalProvisioningReceiptParams {
  manifest: ModelManifestBody;
  plan: LocalProvisioningPlan;
  declaredAt?: string;
}

export interface LocalProvisioningReceipt {
  status: LocalProvisioningReceiptStatus;
  manifestVersion: number;
  tier: ModelManifestTier | null;
  planStatus: LocalProvisioningPlanStatus;
  planBlockReason: LocalProvisioningBlockReason | null;
  declaredAt: string;
  declaredModels: LocalProvisioningDeclaredModel[];
  refusedModels: LocalProvisioningRefusedModel[];
}

export function buildLocalProvisioningReceipt(
  params: BuildLocalProvisioningReceiptParams,
): LocalProvisioningReceipt {
  const declaredAt = params.declaredAt ?? new Date().toISOString();
  const declaredModels: LocalProvisioningDeclaredModel[] = [];
  const refusedModels: LocalProvisioningRefusedModel[] = [];

  for (const modelPlan of params.plan.modelPlans) {
    const declaration = tryDeclareModel({
      manifest: params.manifest,
      modelPlan,
      declaredAt,
    });
    if (declaration.kind === "declared") {
      declaredModels.push(declaration.model);
    } else {
      refusedModels.push(declaration.model);
    }
  }

  return {
    status: summarizeReceiptStatus(declaredModels, refusedModels, params.plan),
    manifestVersion: params.manifest.manifest_version,
    tier: params.plan.tier,
    planStatus: params.plan.status,
    planBlockReason: params.plan.blockReason,
    declaredAt,
    declaredModels,
    refusedModels,
  };
}

function tryDeclareModel(args: {
  manifest: ModelManifestBody;
  modelPlan: LocalProvisioningModelPlan;
  declaredAt: string;
}):
  | { kind: "declared"; model: LocalProvisioningDeclaredModel }
  | { kind: "refused"; model: LocalProvisioningRefusedModel } {
  const manifestModel = args.manifest.models[args.modelPlan.modelId];
  if (manifestModel === undefined) {
    return refuse(args.modelPlan, "model_not_in_manifest");
  }

  if (
    manifestModel.runtime_tag !== args.modelPlan.runtimeTag ||
    manifestModel.weights_sha256 !== args.modelPlan.expectedWeightsSha256
  ) {
    return refuse(args.modelPlan, "plan_manifest_mismatch");
  }

  if (args.modelPlan.status !== "already_provisioned") {
    return refuse(args.modelPlan, refusalForUnprovisionedPlan(args.modelPlan));
  }

  if (args.modelPlan.observedManifestDigestSha256 === null) {
    return refuse(args.modelPlan, "digest_unavailable");
  }

  if (args.modelPlan.observedManifestDigestSha256 !== manifestModel.weights_sha256) {
    return refuse(args.modelPlan, "digest_mismatch");
  }

  return {
    kind: "declared",
    model: {
      modelId: manifestModel.model_id,
      runtimeTag: manifestModel.runtime_tag,
      surfaces: [...args.modelPlan.surfaces],
      manifestVersion: args.manifest.manifest_version,
      weightsSha256: manifestModel.weights_sha256,
      observedManifestDigestSha256: args.modelPlan.observedManifestDigestSha256,
      provenance: provenanceFromModelManifestModel(
        manifestModel,
        args.declaredAt,
      ),
    },
  };
}

function refuse(
  modelPlan: LocalProvisioningModelPlan,
  reason: LocalProvisioningReceiptRefusalReason,
): { kind: "refused"; model: LocalProvisioningRefusedModel } {
  return {
    kind: "refused",
    model: {
      modelId: modelPlan.modelId,
      runtimeTag: modelPlan.runtimeTag,
      surfaces: [...modelPlan.surfaces],
      status: modelPlan.status,
      reason,
      blockReason: modelPlan.blockReason,
      expectedWeightsSha256: modelPlan.expectedWeightsSha256,
      observedManifestDigestSha256: modelPlan.observedManifestDigestSha256,
    },
  };
}

function refusalForUnprovisionedPlan(
  modelPlan: LocalProvisioningModelPlan,
): LocalProvisioningReceiptRefusalReason {
  if (modelPlan.blockReason === "digest_unavailable") return "digest_unavailable";
  if (modelPlan.blockReason === "digest_mismatch") return "digest_mismatch";
  return "model_not_provisioned";
}

function summarizeReceiptStatus(
  declaredModels: readonly LocalProvisioningDeclaredModel[],
  refusedModels: readonly LocalProvisioningRefusedModel[],
  plan: LocalProvisioningPlan,
): LocalProvisioningReceiptStatus {
  if (plan.blockReason !== null && plan.modelPlans.length === 0) return "refused";
  if (refusedModels.length === 0) return "complete";
  if (declaredModels.length === 0) return "refused";
  return "partial";
}
