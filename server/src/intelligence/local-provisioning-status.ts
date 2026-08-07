/**
 * Sanctuary MCP Server - Local provisioning degraded status builder.
 *
 * Converts source-only provisioning consent/refusal data into the existing
 * operator-visible `SurfaceStatus` shape. This module does not probe Ollama,
 * install or pull models, append audit entries, mutate selector config, write
 * provenance, persist state, or flip any surface to a remote substrate.
 */

import {
  BADGE_LABEL_KEYS,
  BADGE_TRADEOFF_KEYS,
} from "./templates.js";
import type {
  LocalProvisioningConsentAction,
  LocalProvisioningConsentPacket,
} from "./local-provisioning-consent.js";
import type { LocalProvisioningActionReason } from "./local-provisioning-actions.js";
import {
  SURFACES,
  type RecentFailureEntry,
  type SubstrateBadge,
  type SubstrateFailureClass,
  type Surface,
  type SurfaceStatus,
} from "./types.js";

export interface BuildLocalProvisioningDegradedSurfaceStatusesOptions {
  now?: Date;
}

interface DegradedSurfaceSource {
  reason: LocalProvisioningActionReason;
  failureClass: SubstrateFailureClass;
  snippet: string;
}

export function buildLocalProvisioningDegradedSurfaceStatuses(
  packet: LocalProvisioningConsentPacket,
  options: BuildLocalProvisioningDegradedSurfaceStatusesOptions = {},
): SurfaceStatus[] {
  const ts = (options.now ?? new Date()).toISOString();
  const bySurface = new Map<Surface, DegradedSurfaceSource>();

  collectActions(bySurface, packet.refusalActions);
  collectActions(bySurface, packet.consentActions);
  collectActions(
    bySurface,
    packet.nonConsentActions.filter((action) => action.kind === "probe_digest"),
  );

  return SURFACES.filter((surface) => bySurface.has(surface)).map((surface) => {
    const source = bySurface.get(surface)!;
    const recentFailure: RecentFailureEntry = {
      ts,
      failureClass: source.failureClass,
      snippet: source.snippet,
    };
    return {
      surface,
      chosen: "local",
      badge: localDegradedBadge(surface),
      health: "degraded",
      failureClass: source.failureClass,
      recentFailures: [recentFailure],
    };
  });
}

function collectActions(
  bySurface: Map<Surface, DegradedSurfaceSource>,
  actions: readonly LocalProvisioningConsentAction[],
): void {
  for (const action of actions) {
    if (action.kind === "declare_model_provenance") continue;
    const source = degradedSourceForReason(action.reason);
    for (const surface of orderedSurfaces(action.surfaces)) {
      if (!bySurface.has(surface)) bySurface.set(surface, source);
    }
  }
}

function orderedSurfaces(surfaces: readonly Surface[]): Surface[] {
  const requested = new Set(surfaces);
  return SURFACES.filter((surface) => requested.has(surface));
}

function localDegradedBadge(surface: Surface): SubstrateBadge {
  return {
    surface,
    substrate: "local",
    labelKey: BADGE_LABEL_KEYS.local,
    tradeoffKey: BADGE_TRADEOFF_KEYS.local,
    status: "yellow",
  };
}

function degradedSourceForReason(
  reason: LocalProvisioningActionReason,
): DegradedSurfaceSource {
  switch (reason) {
    case "ollama_unreachable":
      return source(
        reason,
        "substrate_unavailable",
        "Local intelligence is degraded: Ollama is not reachable; setup needs operator consent before install or pull.",
      );
    case "model_missing":
      return source(
        reason,
        "substrate_misconfigured",
        "Local intelligence is degraded: the signed manifest model is not installed; no model was marked provisioned.",
      );
    case "digest_probe_required":
      return source(
        reason,
        "substrate_misconfigured",
        "Local intelligence is degraded: model digest evidence is required before the surface can be marked provisioned.",
      );
    case "hardware_below_baseline":
      return source(
        reason,
        "substrate_unavailable",
        "Local intelligence is degraded: detected hardware is below the signed manifest baseline.",
      );
    case "tier_exceeds_hardware":
      return source(
        reason,
        "substrate_misconfigured",
        "Local intelligence is degraded: requested model tier exceeds detected hardware capability.",
      );
    case "digest_unavailable":
      return source(
        reason,
        "substrate_misconfigured",
        "Local intelligence is degraded: Ollama did not report digest evidence for the installed model.",
      );
    case "digest_mismatch":
      return source(
        reason,
        "substrate_misconfigured",
        "Local intelligence is degraded: observed model digest does not match the signed manifest.",
      );
    case "plan_blocked":
      return source(
        reason,
        "internal_error",
        "Local intelligence is degraded: provisioning plan was blocked before any model was marked provisioned.",
      );
    case "already_verified":
      return source(
        reason,
        "substrate_misconfigured",
        "Local intelligence is degraded: verified provenance was unexpectedly reported as degraded.",
      );
  }
}

function source(
  reason: LocalProvisioningActionReason,
  failureClass: SubstrateFailureClass,
  snippet: string,
): DegradedSurfaceSource {
  return { reason, failureClass, snippet };
}
