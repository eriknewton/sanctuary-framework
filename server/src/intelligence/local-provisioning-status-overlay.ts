/**
 * Sanctuary MCP Server - Local provisioning status overlay.
 *
 * Safely overlays source-only local provisioning degraded rows onto an
 * existing operator-visible status report. This module is data-only: it does
 * not probe Ollama, install or pull models, append audit entries, mutate
 * selector config, write provenance, persist state, or switch any surface to a
 * remote substrate.
 */

import {
  SURFACES,
  type SubstrateBadge,
  type SubstrateStatusReport,
  type Surface,
  type SurfaceStatus,
} from "./types.js";

export type LocalProvisioningStatusOverlayErrorCode =
  | "badge_surface_mismatch"
  | "duplicate_surface"
  | "missing_failure_context"
  | "missing_report_surface"
  | "non_degraded_overlay"
  | "non_local_overlay";

export class LocalProvisioningStatusOverlayError extends Error {
  readonly code: LocalProvisioningStatusOverlayErrorCode;
  readonly surface: Surface | null;

  constructor(
    code: LocalProvisioningStatusOverlayErrorCode,
    message: string,
    surface: Surface | null = null,
  ) {
    super(message);
    this.name = "LocalProvisioningStatusOverlayError";
    this.code = code;
    this.surface = surface;
  }
}

export interface ApplyLocalProvisioningStatusOverlayResult {
  report: SubstrateStatusReport;
  overlaidSurfaces: Surface[];
}

export function applyLocalProvisioningStatusOverlay(
  report: SubstrateStatusReport,
  overlays: readonly SurfaceStatus[],
): ApplyLocalProvisioningStatusOverlayResult {
  const bySurface = new Map<Surface, SurfaceStatus>();

  for (const overlay of overlays) {
    assertLocalDegradedOverlay(overlay);
    if (bySurface.has(overlay.surface)) {
      throw new LocalProvisioningStatusOverlayError(
        "duplicate_surface",
        `Duplicate local provisioning status overlay for ${overlay.surface}.`,
        overlay.surface,
      );
    }
    bySurface.set(overlay.surface, overlay);
  }

  const reportSurfaces = new Set(report.surfaces.map((status) => status.surface));
  for (const surface of bySurface.keys()) {
    if (!reportSurfaces.has(surface)) {
      throw new LocalProvisioningStatusOverlayError(
        "missing_report_surface",
        `Local provisioning status overlay references ${surface}, but the base status report does not contain that surface.`,
        surface,
      );
    }
  }

  return {
    report: {
      version: report.version,
      generatedAt: report.generatedAt,
      hardware: { ...report.hardware, ollamaModels: [...report.hardware.ollamaModels] },
      surfaces: report.surfaces.map((status) =>
        cloneSurfaceStatus(bySurface.get(status.surface) ?? status),
      ),
    },
    overlaidSurfaces: SURFACES.filter((surface) => bySurface.has(surface)),
  };
}

function assertLocalDegradedOverlay(status: SurfaceStatus): void {
  if (status.badge.surface !== status.surface) {
    throw new LocalProvisioningStatusOverlayError(
      "badge_surface_mismatch",
      `Local provisioning status overlay for ${status.surface} carries a badge for ${status.badge.surface}.`,
      status.surface,
    );
  }
  if (status.chosen !== "local" || status.badge.substrate !== "local") {
    throw new LocalProvisioningStatusOverlayError(
      "non_local_overlay",
      `Local provisioning status overlay for ${status.surface} must stay on the local substrate.`,
      status.surface,
    );
  }
  if (status.health !== "degraded" || status.badge.status !== "yellow") {
    throw new LocalProvisioningStatusOverlayError(
      "non_degraded_overlay",
      `Local provisioning status overlay for ${status.surface} must be a yellow degraded status.`,
      status.surface,
    );
  }
  if (status.failureClass === null || status.recentFailures.length === 0) {
    throw new LocalProvisioningStatusOverlayError(
      "missing_failure_context",
      `Local provisioning status overlay for ${status.surface} must carry failure context.`,
      status.surface,
    );
  }
}

function cloneSurfaceStatus(status: SurfaceStatus): SurfaceStatus {
  return {
    surface: status.surface,
    chosen: status.chosen,
    badge: cloneBadge(status.badge),
    health: status.health,
    failureClass: status.failureClass,
    recentFailures: status.recentFailures.map((failure) => ({
      ts: failure.ts,
      failureClass: failure.failureClass,
      snippet: failure.snippet,
    })),
  };
}

function cloneBadge(badge: SubstrateBadge): SubstrateBadge {
  return {
    surface: badge.surface,
    substrate: badge.substrate,
    labelKey: badge.labelKey,
    tradeoffKey: badge.tradeoffKey,
    status: badge.status,
  };
}
