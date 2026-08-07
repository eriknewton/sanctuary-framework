/**
 * Sanctuary MCP Server - Local provisioning receipt application.
 *
 * This is the narrow consume boundary for local provisioning receipts. It
 * writes only to an injected ModelProvenanceStore, refuses incomplete receipts
 * by default, and does not install, pull, select, persist, or probe anything on
 * the host.
 */

import type { ModelProvenanceStore } from "../operational/model-provenance.js";
import type {
  LocalProvisioningReceipt,
  LocalProvisioningReceiptStatus,
} from "./local-provisioning-receipt.js";

export type LocalProvisioningStoreApplyStatus =
  | "applied_complete"
  | "applied_partial"
  | "refused";

export type LocalProvisioningStoreApplyRefusalReason =
  | "receipt_refused"
  | "receipt_partial"
  | "no_declared_models"
  | "primary_model_not_declared";

export interface ApplyLocalProvisioningReceiptToStoreParams {
  receipt: LocalProvisioningReceipt;
  store: ModelProvenanceStore;
  /**
   * Partial receipts are visibility artifacts by default. Operators may choose
   * to apply the verified subset, but the caller must opt in so missing local
   * models cannot be silently hidden.
   */
  allowPartial?: boolean;
  /**
   * Optional explicit primary model for the provenance store. This does not
   * change selector config or route any inference; it only updates the
   * injected provenance store when `setPrimary` is also true.
   */
  primaryModelId?: string;
  /** Default false: declaring provenance does not implicitly select a model. */
  setPrimary?: boolean;
}

export type ApplyLocalProvisioningReceiptToStoreResult =
  | {
      status: Exclude<LocalProvisioningStoreApplyStatus, "refused">;
      manifestVersion: number;
      receiptStatus: LocalProvisioningReceiptStatus;
      declaredModelIds: string[];
      skippedRefusedModelIds: string[];
      primaryModelId: string | null;
      refusalReason: null;
    }
  | {
      status: "refused";
      manifestVersion: number;
      receiptStatus: LocalProvisioningReceiptStatus;
      declaredModelIds: string[];
      skippedRefusedModelIds: string[];
      primaryModelId: null;
      refusalReason: LocalProvisioningStoreApplyRefusalReason;
    };

export function applyLocalProvisioningReceiptToStore(
  params: ApplyLocalProvisioningReceiptToStoreParams,
): ApplyLocalProvisioningReceiptToStoreResult {
  const { receipt } = params;
  const allowPartial = params.allowPartial ?? false;
  const setPrimary = params.setPrimary ?? false;
  const declaredModelIds = receipt.declaredModels.map((model) => model.modelId);
  const skippedRefusedModelIds = receipt.refusedModels.map((model) => model.modelId);

  if (receipt.status === "refused") {
    return refuse(params, "receipt_refused");
  }

  if (receipt.status === "partial" && !allowPartial) {
    return refuse(params, "receipt_partial");
  }

  if (receipt.declaredModels.length === 0) {
    return refuse(params, "no_declared_models");
  }

  const primaryModelId = params.primaryModelId ?? receipt.declaredModels[0]!.modelId;
  if (setPrimary && !declaredModelIds.includes(primaryModelId)) {
    return refuse(params, "primary_model_not_declared");
  }

  for (const model of receipt.declaredModels) {
    params.store.declare(model.provenance);
  }

  if (setPrimary) {
    params.store.setPrimary(primaryModelId);
  }

  return {
    status: receipt.status === "partial" ? "applied_partial" : "applied_complete",
    manifestVersion: receipt.manifestVersion,
    receiptStatus: receipt.status,
    declaredModelIds,
    skippedRefusedModelIds,
    primaryModelId: setPrimary ? primaryModelId : null,
    refusalReason: null,
  };
}

function refuse(
  params: ApplyLocalProvisioningReceiptToStoreParams,
  reason: LocalProvisioningStoreApplyRefusalReason,
): ApplyLocalProvisioningReceiptToStoreResult {
  return {
    status: "refused",
    manifestVersion: params.receipt.manifestVersion,
    receiptStatus: params.receipt.status,
    declaredModelIds: params.receipt.declaredModels.map((model) => model.modelId),
    skippedRefusedModelIds: params.receipt.refusedModels.map((model) => model.modelId),
    primaryModelId: null,
    refusalReason: reason,
  };
}
