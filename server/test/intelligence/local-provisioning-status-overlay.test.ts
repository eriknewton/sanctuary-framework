import { describe, expect, it } from "vitest";

import {
  BADGE_LABEL_KEYS,
  BADGE_TRADEOFF_KEYS,
  LocalProvisioningStatusOverlayError,
  SURFACES,
  applyLocalProvisioningStatusOverlay,
  buildLocalProvisioningConsentPacket,
  buildLocalProvisioningDegradedSurfaceStatuses,
  type LocalProvisioningAction,
  type LocalProvisioningActionPreview,
  type SubstrateChoice,
  type SubstrateStatusReport,
  type Surface,
  type SurfaceStatus,
} from "../../src/intelligence/index.js";

const sha256Hex = "a".repeat(64);
const generatedAt = "2026-08-07T15:45:00.000Z";
const overlayTime = new Date("2026-08-07T15:46:00.000Z");

describe("local provisioning status overlay", () => {
  it("overlays local degraded provisioning rows without changing report metadata or untouched surfaces", () => {
    const report = baseReport();
    const overlays = degradedStatuses([
      action({
        kind: "install_ollama",
        modelId: null,
        runtimeTag: null,
        surfaces: ["concierge", "privacy-filter-tier-2"],
        reason: "ollama_unreachable",
        requiresOperatorConsent: true,
        requiresNetworkEgress: true,
        mutatesHost: true,
      }),
    ]);

    const result = applyLocalProvisioningStatusOverlay(report, overlays);

    expect(result.overlaidSurfaces).toEqual([
      "concierge",
      "privacy-filter-tier-2",
    ]);
    expect(result.report.version).toBe("1.2");
    expect(result.report.generatedAt).toBe(report.generatedAt);
    expect(result.report.hardware).toEqual(report.hardware);
    expect(result.report.surfaces.map((status) => status.surface)).toEqual(
      report.surfaces.map((status) => status.surface),
    );

    const concierge = bySurface(result.report, "concierge");
    expect(concierge).toMatchObject({
      chosen: "local",
      health: "degraded",
      failureClass: "substrate_unavailable",
    });
    expect(concierge.badge.status).toBe("yellow");
    expect(concierge.recentFailures[0]!.snippet).toContain(
      "Ollama is not reachable",
    );
    expect(bySurface(result.report, "gate-explanation").health).toBe("ok");
    expect(bySurface(report, "concierge").health).toBe("ok");
  });

  it("sanitizes stray executable fields while cloning overlay data", () => {
    const [overlay] = degradedStatuses([
      action({
        kind: "probe_digest",
        reason: "digest_probe_required",
        surfaces: ["concierge"],
      }),
    ]);
    const hostileOverlay = {
      ...overlay!,
      command: "ollama pull qwen2.5:1.5b-instruct",
      argv: ["ollama", "pull"],
      shell: "/bin/zsh",
      badge: {
        ...overlay!.badge,
        command: "bad badge key",
      },
      recentFailures: [
        {
          ...overlay!.recentFailures[0]!,
          argv: ["hidden"],
        },
      ],
    } as unknown as SurfaceStatus;

    const result = applyLocalProvisioningStatusOverlay(baseReport(), [
      hostileOverlay,
    ]);
    hostileOverlay.recentFailures[0]!.snippet = "mutated after overlay";

    const concierge = bySurface(result.report, "concierge");
    expect(concierge.recentFailures[0]!.snippet).toContain(
      "model digest evidence is required",
    );
    expect(serializedKeys(result.report)).not.toContain("command");
    expect(serializedKeys(result.report)).not.toContain("argv");
    expect(serializedKeys(result.report)).not.toContain("shell");
  });

  it("rejects overlays that would switch a surface to a remote substrate", () => {
    const [overlay] = degradedStatuses([
      action({
        kind: "pull_model",
        reason: "model_missing",
        surfaces: ["concierge"],
        requiresOperatorConsent: true,
        requiresNetworkEgress: true,
        mutatesHost: true,
      }),
    ]);
    const remoteOverlay: SurfaceStatus = {
      ...overlay!,
      chosen: "venice",
      badge: {
        ...overlay!.badge,
        substrate: "venice",
      },
    };

    expectOverlayError(
      () => applyLocalProvisioningStatusOverlay(baseReport(), [remoteOverlay]),
      "non_local_overlay",
      "concierge",
    );
  });

  it("rejects overlays that are not degraded with visible failure context", () => {
    const okOverlay: SurfaceStatus = {
      ...status("concierge"),
      health: "ok",
      failureClass: null,
      recentFailures: [],
    };

    expectOverlayError(
      () => applyLocalProvisioningStatusOverlay(baseReport(), [okOverlay]),
      "non_degraded_overlay",
      "concierge",
    );
  });

  it("rejects duplicate overlays for the same surface", () => {
    const [overlay] = degradedStatuses([
      action({
        kind: "pull_model",
        reason: "model_missing",
        surfaces: ["concierge"],
        requiresOperatorConsent: true,
        requiresNetworkEgress: true,
        mutatesHost: true,
      }),
    ]);

    expectOverlayError(
      () =>
        applyLocalProvisioningStatusOverlay(baseReport(), [overlay!, overlay!]),
      "duplicate_surface",
      "concierge",
    );
  });

  it("rejects overlays for surfaces missing from the base report", () => {
    const [overlay] = degradedStatuses([
      action({
        kind: "pull_model",
        reason: "model_missing",
        surfaces: ["concierge"],
        requiresOperatorConsent: true,
        requiresNetworkEgress: true,
        mutatesHost: true,
      }),
    ]);
    const report = baseReport({
      surfaces: baseReport().surfaces.filter(
        (item) => item.surface !== "concierge",
      ),
    });

    expectOverlayError(
      () => applyLocalProvisioningStatusOverlay(report, [overlay!]),
      "missing_report_surface",
      "concierge",
    );
  });
});

function baseReport(
  overrides: Partial<SubstrateStatusReport> = {},
): SubstrateStatusReport {
  return {
    version: "1.2",
    generatedAt,
    hardware: {
      totalRamGb: 16,
      cpuArch: "apple-silicon-other",
      tier: "mid",
      recommendedLocalModel: "phi-4-mini",
      ollamaReachable: true,
      ollamaModels: ["qwen2.5:1.5b-instruct"],
    },
    surfaces: SURFACES.map((surface) => status(surface)),
    ...overrides,
  };
}

function status(
  surface: Surface,
  choice: SubstrateChoice = "local",
): SurfaceStatus {
  return {
    surface,
    chosen: choice,
    badge: {
      surface,
      substrate: choice,
      labelKey: BADGE_LABEL_KEYS[choice],
      tradeoffKey: BADGE_TRADEOFF_KEYS[choice],
      status: "green",
    },
    health: "ok",
    failureClass: null,
    recentFailures: [],
  };
}

function degradedStatuses(
  actions: LocalProvisioningAction[],
): SurfaceStatus[] {
  return buildLocalProvisioningDegradedSurfaceStatuses(
    buildLocalProvisioningConsentPacket(preview(actions)),
    { now: overlayTime },
  );
}

function preview(
  actions: LocalProvisioningAction[],
): LocalProvisioningActionPreview {
  return {
    status: "action_required",
    planStatus: "needs_pull",
    tier: "baseline",
    hardwareTier: "baseline",
    planBlockReason: null,
    disabledSurfaces: [],
    actions,
    requiresOperatorConsent: actions.some(
      (item) => item.requiresOperatorConsent,
    ),
    requiresNetworkEgress: actions.some((item) => item.requiresNetworkEgress),
    mutatesHost: actions.some((item) => item.mutatesHost),
    writesFortressState: actions.some((item) => item.writesFortressState),
  };
}

function action(
  overrides: Partial<LocalProvisioningAction> = {},
): LocalProvisioningAction {
  return {
    kind: "pull_model",
    modelId: "qwen2.5-1.5b",
    runtimeTag: "qwen2.5:1.5b-instruct",
    surfaces: ["concierge"],
    expectedWeightsSha256: sha256Hex,
    observedManifestDigestSha256: null,
    paramsB: 1.5,
    reason: "model_missing",
    requiresOperatorConsent: false,
    requiresNetworkEgress: false,
    mutatesHost: false,
    writesFortressState: false,
    ...overrides,
  };
}

function bySurface(
  report: SubstrateStatusReport,
  surface: Surface,
): SurfaceStatus {
  const found = report.surfaces.find((item) => item.surface === surface);
  if (!found) throw new Error(`missing ${surface}`);
  return found;
}

function expectOverlayError(
  fn: () => unknown,
  code: LocalProvisioningStatusOverlayError["code"],
  surface: Surface,
): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(LocalProvisioningStatusOverlayError);
    const overlayError = error as LocalProvisioningStatusOverlayError;
    expect(overlayError.code).toBe(code);
    expect(overlayError.surface).toBe(surface);
    return;
  }
  throw new Error(`expected LocalProvisioningStatusOverlayError ${code}`);
}

function serializedKeys(value: unknown): string[] {
  const keys = new Set<string>();
  visit(value, keys);
  return [...keys].sort();
}

function visit(value: unknown, keys: Set<string>): void {
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) visit(item, keys);
    return;
  }
  for (const [key, item] of Object.entries(value)) {
    keys.add(key);
    visit(item, keys);
  }
}
