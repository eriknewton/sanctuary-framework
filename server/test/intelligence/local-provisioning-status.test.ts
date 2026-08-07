import { describe, expect, it } from "vitest";

import {
  buildLocalProvisioningConsentPacket,
  buildLocalProvisioningDegradedSurfaceStatuses,
  type LocalProvisioningAction,
  type LocalProvisioningActionPreview,
} from "../../src/intelligence/index.js";

const sha256Hex = "e".repeat(64);
const now = new Date("2026-08-07T14:20:00.000Z");

describe("local provisioning degraded surface status", () => {
  it("reports below-baseline refusals as local degraded statuses without cloud fallback", () => {
    const statuses = buildLocalProvisioningDegradedSurfaceStatuses(
      buildLocalProvisioningConsentPacket(
        preview([
          action({
            kind: "refuse_provisioning",
            modelId: null,
            runtimeTag: null,
            surfaces: [
              "concierge",
              "direct-agent-gate-advisor",
              "sentinel-scoring",
              "gate-explanation",
              "privacy-filter-tier-2",
              "template-suggestion",
            ],
            reason: "hardware_below_baseline",
          }),
        ], { status: "refused", planStatus: "blocked" }),
      ),
      { now },
    );

    expect(statuses.map((status) => status.surface)).toEqual([
      "concierge",
      "direct-agent-gate-advisor",
      "sentinel-scoring",
      "gate-explanation",
      "privacy-filter-tier-2",
      "template-suggestion",
    ]);
    expect(statuses.every((status) => status.chosen === "local")).toBe(true);
    expect(statuses.every((status) => status.badge.substrate === "local")).toBe(
      true,
    );
    expect(statuses.every((status) => status.badge.status === "yellow")).toBe(
      true,
    );
    expect(statuses.every((status) => status.health === "degraded")).toBe(true);
    expect(statuses[0]!.failureClass).toBe("substrate_unavailable");
    expect(statuses[0]!.recentFailures).toEqual([
      {
        ts: now.toISOString(),
        failureClass: "substrate_unavailable",
        snippet:
          "Local intelligence is degraded: detected hardware is below the signed manifest baseline.",
      },
    ]);
  });

  it("reports digest mismatches as degraded without marking a surface provisioned", () => {
    const statuses = buildLocalProvisioningDegradedSurfaceStatuses(
      buildLocalProvisioningConsentPacket(
        preview([
          action({
            kind: "refuse_provisioning",
            surfaces: ["privacy-filter-tier-2"],
            reason: "digest_mismatch",
            observedManifestDigestSha256: "f".repeat(64),
          }),
        ], { status: "refused", planStatus: "blocked" }),
      ),
      { now },
    );

    expect(statuses).toMatchObject([
      {
        surface: "privacy-filter-tier-2",
        chosen: "local",
        health: "degraded",
        failureClass: "substrate_misconfigured",
        recentFailures: [
          {
            failureClass: "substrate_misconfigured",
            snippet:
              "Local intelligence is degraded: observed model digest does not match the signed manifest.",
          },
        ],
      },
    ]);
    expect(serializedKeys(statuses)).not.toContain("provisioned");
  });

  it("dedupes consent-required install and pull actions into stable surface rows", () => {
    const statuses = buildLocalProvisioningDegradedSurfaceStatuses(
      buildLocalProvisioningConsentPacket(
        preview([
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
          action({
            kind: "pull_model",
            surfaces: ["concierge"],
            reason: "model_missing",
            requiresOperatorConsent: true,
            requiresNetworkEgress: true,
            mutatesHost: true,
          }),
        ]),
      ),
      { now },
    );

    expect(statuses.map((status) => status.surface)).toEqual([
      "concierge",
      "privacy-filter-tier-2",
    ]);
    expect(statuses[0]!.failureClass).toBe("substrate_unavailable");
    expect(statuses[0]!.recentFailures[0]!.snippet).toContain(
      "Ollama is not reachable",
    );
    expect(statuses[1]!.failureClass).toBe("substrate_unavailable");
  });

  it("does not degrade already verified provenance declarations", () => {
    const statuses = buildLocalProvisioningDegradedSurfaceStatuses(
      buildLocalProvisioningConsentPacket(
        preview([
          action({
            kind: "declare_model_provenance",
            reason: "already_verified",
            writesFortressState: true,
          }),
        ], { status: "satisfied", planStatus: "satisfied" }),
      ),
      { now },
    );

    expect(statuses).toEqual([]);
  });

  it("keeps the status payload data-only with no executable command fields", () => {
    const statuses = buildLocalProvisioningDegradedSurfaceStatuses(
      buildLocalProvisioningConsentPacket(
        preview([
          action({
            kind: "probe_digest",
            reason: "digest_probe_required",
            surfaces: ["concierge"],
          }),
        ]),
      ),
      { now },
    );

    expect(statuses).toHaveLength(1);
    expect(serializedKeys(statuses)).not.toContain("command");
    expect(serializedKeys(statuses)).not.toContain("argv");
    expect(serializedKeys(statuses)).not.toContain("shell");
  });
});

function preview(
  actions: LocalProvisioningAction[],
  overrides: Partial<LocalProvisioningActionPreview> = {},
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
    ...overrides,
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
