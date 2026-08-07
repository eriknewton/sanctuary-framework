import { describe, expect, it } from "vitest";
import {
  buildLocalProvisioningActionPreview,
  buildLocalProvisioningPlan,
  type HardwareCapabilityReport,
  type ModelManifestBody,
} from "../../src/intelligence/index.js";

const QWEN_HASH =
  "1111111111111111111111111111111111111111111111111111111111111111";
const PHI_HASH =
  "2222222222222222222222222222222222222222222222222222222222222222";
const OTHER_HASH =
  "3333333333333333333333333333333333333333333333333333333333333333";

const BODY: ModelManifestBody = {
  manifest_version: 12,
  models: {
    qwen: {
      model_id: "qwen",
      model_name: "Qwen2.5 1.5B Instruct",
      model_version: "2.5",
      provider: "Alibaba Cloud",
      runtime: "ollama",
      runtime_tag: "qwen2.5:1.5b",
      registry_source: "ollama://qwen2.5:1.5b",
      weights_sha256: QWEN_HASH,
      params_b: 1.5,
      license: "Apache-2.0",
      license_url: "https://example.test/qwen",
      open_weights: true,
      open_source: false,
      local_inference: true,
    },
    phi: {
      model_id: "phi",
      model_name: "Phi-4 Mini Instruct",
      model_version: "4",
      provider: "Microsoft",
      runtime: "ollama",
      runtime_tag: "phi4-mini",
      registry_source: "ollama://phi4-mini",
      weights_sha256: PHI_HASH,
      params_b: 3.8,
      license: "MIT",
      license_url: "https://example.test/phi",
      open_weights: true,
      open_source: false,
      local_inference: true,
    },
  },
  tiers: {
    baseline: ["qwen"],
    mid: ["qwen", "phi"],
    pro: ["qwen", "phi"],
  },
  surface_defaults: {
    baseline: {
      concierge: "qwen",
      "direct-agent-gate-advisor": "qwen",
      "sentinel-scoring": "qwen",
      "gate-explanation": null,
      "privacy-filter-tier-2": "qwen",
      "template-suggestion": "qwen",
    },
    mid: {
      concierge: "qwen",
      "direct-agent-gate-advisor": "qwen",
      "sentinel-scoring": "phi",
      "gate-explanation": null,
      "privacy-filter-tier-2": "phi",
      "template-suggestion": "qwen",
    },
    pro: {
      concierge: "qwen",
      "direct-agent-gate-advisor": "qwen",
      "sentinel-scoring": "phi",
      "gate-explanation": null,
      "privacy-filter-tier-2": "phi",
      "template-suggestion": "qwen",
    },
  },
};

function hardware(
  overrides: Partial<HardwareCapabilityReport> = {},
): HardwareCapabilityReport {
  return {
    totalRamGb: 16,
    cpuArch: "apple-silicon-m2",
    tier: "mid",
    recommendedLocalModel: "phi-4-mini",
    ollamaReachable: true,
    ollamaModels: [],
    ...overrides,
  };
}

describe("local provisioning action preview", () => {
  it("refuses below-baseline hardware without proposing host mutation", () => {
    const plan = buildLocalProvisioningPlan({
      manifest: BODY,
      hardware: hardware({
        tier: "below-baseline",
        recommendedLocalModel: null,
        ollamaReachable: false,
      }),
    });

    const preview = buildLocalProvisioningActionPreview(plan);

    expect(preview).toMatchObject({
      status: "refused",
      planStatus: "blocked",
      planBlockReason: "hardware_below_baseline",
      requiresOperatorConsent: false,
      requiresNetworkEgress: false,
      mutatesHost: false,
      writesFortressState: false,
    });
    expect(preview.actions).toEqual([
      {
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
        expectedWeightsSha256: null,
        observedManifestDigestSha256: null,
        paramsB: null,
        reason: "hardware_below_baseline",
        requiresOperatorConsent: false,
        requiresNetworkEgress: false,
        mutatesHost: false,
        writesFortressState: false,
      },
    ]);
  });

  it("dedupes the Ollama install action while still naming every model pull", () => {
    const plan = buildLocalProvisioningPlan({
      manifest: BODY,
      hardware: hardware({ ollamaReachable: false, ollamaModels: [] }),
    });

    const preview = buildLocalProvisioningActionPreview(plan);

    expect(preview.status).toBe("action_required");
    expect(preview.requiresOperatorConsent).toBe(true);
    expect(preview.requiresNetworkEgress).toBe(true);
    expect(preview.mutatesHost).toBe(true);
    expect(preview.actions.map((action) => action.kind)).toEqual([
      "install_ollama",
      "pull_model",
      "pull_model",
    ]);
    expect(preview.actions[0]).toMatchObject({
      modelId: null,
      reason: "ollama_unreachable",
      surfaces: [
        "concierge",
        "direct-agent-gate-advisor",
        "sentinel-scoring",
        "privacy-filter-tier-2",
        "template-suggestion",
      ],
    });
    expect(preview.actions.slice(1).map((action) => action.runtimeTag)).toEqual([
      "qwen2.5:1.5b",
      "phi4-mini",
    ]);
  });

  it("renders missing installed models as consented pull actions", () => {
    const plan = buildLocalProvisioningPlan({
      manifest: BODY,
      hardware: hardware({ ollamaModels: [] }),
      surfaces: ["privacy-filter-tier-2"],
    });

    const preview = buildLocalProvisioningActionPreview(plan);

    expect(preview).toMatchObject({
      status: "action_required",
      requiresOperatorConsent: true,
      requiresNetworkEgress: true,
      mutatesHost: true,
      writesFortressState: false,
    });
    expect(preview.actions).toMatchObject([
      {
        kind: "pull_model",
        modelId: "phi",
        runtimeTag: "phi4-mini",
        surfaces: ["privacy-filter-tier-2"],
        expectedWeightsSha256: PHI_HASH,
        paramsB: 3.8,
        reason: "model_missing",
      },
    ]);
  });

  it("renders installed models without digest evidence as non-mutating probes", () => {
    const plan = buildLocalProvisioningPlan({
      manifest: BODY,
      hardware: hardware({ ollamaModels: ["qwen2.5:1.5b"] }),
      surfaces: ["concierge"],
    });

    const preview = buildLocalProvisioningActionPreview(plan);

    expect(preview).toMatchObject({
      status: "action_required",
      requiresOperatorConsent: false,
      requiresNetworkEgress: false,
      mutatesHost: false,
      writesFortressState: false,
    });
    expect(preview.actions[0]).toMatchObject({
      kind: "probe_digest",
      modelId: "qwen",
      runtimeTag: "qwen2.5:1.5b",
      reason: "digest_probe_required",
    });
  });

  it("turns digest mismatches into refusal actions, not warnings", () => {
    const plan = buildLocalProvisioningPlan({
      manifest: BODY,
      hardware: hardware({ ollamaModels: ["phi4-mini"] }),
      surfaces: ["privacy-filter-tier-2"],
      digestReports: [
        {
          model: "phi4-mini",
          manifestDigestSha256: OTHER_HASH,
          blobSha256: [PHI_HASH],
        },
      ],
    });

    const preview = buildLocalProvisioningActionPreview(plan);

    expect(preview.status).toBe("refused");
    expect(preview.actions).toMatchObject([
      {
        kind: "refuse_provisioning",
        modelId: "phi",
        runtimeTag: "phi4-mini",
        observedManifestDigestSha256: OTHER_HASH,
        reason: "digest_mismatch",
        requiresOperatorConsent: false,
        requiresNetworkEgress: false,
        mutatesHost: false,
        writesFortressState: false,
      },
    ]);
  });

  it("renders verified installed models as provenance declaration only", () => {
    const plan = buildLocalProvisioningPlan({
      manifest: BODY,
      hardware: hardware({ ollamaModels: ["qwen2.5:1.5b"] }),
      surfaces: ["concierge"],
      digestReports: [
        {
          model: "qwen2.5:1.5b",
          manifestDigestSha256: QWEN_HASH,
          blobSha256: [],
        },
      ],
    });

    const preview = buildLocalProvisioningActionPreview(plan);

    expect(preview).toMatchObject({
      status: "satisfied",
      requiresOperatorConsent: false,
      requiresNetworkEgress: false,
      mutatesHost: false,
      writesFortressState: true,
    });
    expect(preview.actions).toMatchObject([
      {
        kind: "declare_model_provenance",
        modelId: "qwen",
        runtimeTag: "qwen2.5:1.5b",
        observedManifestDigestSha256: QWEN_HASH,
        reason: "already_verified",
      },
    ]);
  });

  it("preserves manifest-disabled surfaces outside the action list", () => {
    const plan = buildLocalProvisioningPlan({
      manifest: BODY,
      hardware: hardware({ ollamaModels: ["qwen2.5:1.5b", "phi4-mini"] }),
      digestReports: [
        {
          model: "qwen2.5:1.5b",
          manifestDigestSha256: QWEN_HASH,
          blobSha256: [],
        },
        {
          model: "phi4-mini",
          manifestDigestSha256: PHI_HASH,
          blobSha256: [],
        },
      ],
    });

    const preview = buildLocalProvisioningActionPreview(plan);

    expect(preview.disabledSurfaces).toEqual(["gate-explanation"]);
    expect(
      preview.actions.some((action) => action.surfaces.includes("gate-explanation")),
    ).toBe(false);
  });
});
