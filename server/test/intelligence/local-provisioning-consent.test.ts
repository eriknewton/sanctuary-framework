import { describe, expect, it } from "vitest";

import {
  buildLocalProvisioningConsentPacket,
  type LocalProvisioningAction,
  type LocalProvisioningActionPreview,
} from "../../src/intelligence/index.js";

const sha256Hex = "d".repeat(64);

describe("local provisioning consent packet", () => {
  it("separates consent-required host mutations from non-consent actions", () => {
    const packet = buildLocalProvisioningConsentPacket(
      preview([
        action({
          kind: "install_ollama",
          modelId: null,
          runtimeTag: null,
          reason: "ollama_unreachable",
          requiresOperatorConsent: true,
          requiresNetworkEgress: true,
          mutatesHost: true,
        }),
        action({
          kind: "pull_model",
          reason: "model_missing",
          requiresOperatorConsent: true,
          requiresNetworkEgress: true,
          mutatesHost: true,
        }),
        action({
          kind: "probe_digest",
          reason: "digest_probe_required",
        }),
      ]),
    );

    expect(packet.status).toBe("requires_operator_consent");
    expect(packet.consentActions.map((item) => item.consentScope)).toEqual([
      "ollama_install",
      "model_pull",
    ]);
    expect(packet.nonConsentActions.map((item) => item.kind)).toEqual([
      "probe_digest",
    ]);
    expect(packet.requiresNetworkEgress).toBe(true);
    expect(packet.mutatesHost).toBe(true);
    expect(serializedKeys(packet)).not.toContain("command");
    expect(serializedKeys(packet)).not.toContain("argv");
  });

  it("keeps fail-closed refusals out of consent actions", () => {
    const packet = buildLocalProvisioningConsentPacket(
      preview([
        action({
          kind: "refuse_provisioning",
          modelId: null,
          runtimeTag: null,
          surfaces: ["privacy-filter-tier-2"],
          reason: "hardware_below_baseline",
        }),
      ], { status: "refused", planStatus: "blocked" }),
    );

    expect(packet.status).toBe("refused");
    expect(packet.consentActions).toEqual([]);
    expect(packet.refusalActions).toMatchObject([
      {
        kind: "refuse_provisioning",
        consentScope: "refused",
        reason: "hardware_below_baseline",
        mutatesHost: false,
        writesFortressState: false,
      },
    ]);
  });

  it("treats verified provenance declarations as non-host consent work", () => {
    const packet = buildLocalProvisioningConsentPacket(
      preview([
        action({
          kind: "declare_model_provenance",
          reason: "already_verified",
          writesFortressState: true,
        }),
      ], { status: "satisfied", planStatus: "satisfied" }),
    );

    expect(packet.status).toBe("not_required");
    expect(packet.consentActions).toEqual([]);
    expect(packet.nonConsentActions).toMatchObject([
      {
        kind: "declare_model_provenance",
        consentScope: "not_required",
        mutatesHost: false,
        writesFortressState: true,
      },
    ]);
    expect(packet.writesFortressState).toBe(true);
    expect(packet.mutatesHost).toBe(false);
  });

  it("copies arrays so callers cannot mutate the original action preview", () => {
    const original = preview([
      action({
        kind: "pull_model",
        reason: "model_missing",
        requiresOperatorConsent: true,
        requiresNetworkEgress: true,
        mutatesHost: true,
      }),
    ]);
    const packet = buildLocalProvisioningConsentPacket(original);

    packet.consentActions[0]!.surfaces.push("sentinel-scoring");
    packet.disabledSurfaces.push("gate-explanation");

    expect(original.actions[0]!.surfaces).toEqual(["concierge"]);
    expect(original.disabledSurfaces).toEqual([]);
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
