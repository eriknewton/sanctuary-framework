import { describe, expect, it } from "vitest";
import {
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
  manifest_version: 9,
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

describe("local provisioning plan", () => {
  it("blocks below-baseline hardware before planning model pulls", () => {
    const plan = buildLocalProvisioningPlan({
      manifest: BODY,
      hardware: hardware({
        tier: "below-baseline",
        recommendedLocalModel: null,
        ollamaReachable: false,
      }),
    });

    expect(plan.status).toBe("blocked");
    expect(plan.blockReason).toBe("hardware_below_baseline");
    expect(plan.tier).toBeNull();
    expect(plan.modelPlans).toEqual([]);
    expect(plan.surfaceBindings.every((binding) => binding.status === "disabled")).toBe(
      true,
    );
  });

  it("dedupes model pulls while preserving the surfaces each model serves", () => {
    const plan = buildLocalProvisioningPlan({
      manifest: BODY,
      hardware: hardware({ ollamaModels: [] }),
    });

    expect(plan.status).toBe("needs_pull");
    expect(plan.tier).toBe("mid");
    expect(plan.surfaceBindings).toContainEqual({
      surface: "gate-explanation",
      modelId: null,
      runtimeTag: null,
      status: "disabled",
    });
    expect(plan.modelPlans).toHaveLength(2);

    const qwen = plan.modelPlans.find((entry) => entry.modelId === "qwen");
    expect(qwen).toMatchObject({
      runtimeTag: "qwen2.5:1.5b",
      status: "pull_required",
      requiresOperatorConsent: true,
      requiresNetworkEgress: true,
    });
    expect(qwen?.surfaces).toEqual([
      "concierge",
      "direct-agent-gate-advisor",
      "template-suggestion",
    ]);

    const phi = plan.modelPlans.find((entry) => entry.modelId === "phi");
    expect(phi?.surfaces).toEqual(["sentinel-scoring", "privacy-filter-tier-2"]);
  });

  it("marks an installed model provisioned only when its manifest digest matches", () => {
    const plan = buildLocalProvisioningPlan({
      manifest: BODY,
      hardware: hardware({ ollamaModels: ["phi4-mini"] }),
      surfaces: ["privacy-filter-tier-2"],
      digestReports: [
        {
          model: "phi4-mini",
          manifestDigestSha256: PHI_HASH,
          blobSha256: [QWEN_HASH],
        },
      ],
    });

    expect(plan.status).toBe("satisfied");
    expect(plan.modelPlans).toHaveLength(1);
    expect(plan.modelPlans[0]).toMatchObject({
      modelId: "phi",
      status: "already_provisioned",
      blockReason: null,
      observedManifestDigestSha256: PHI_HASH,
      observedBlobSha256: [QWEN_HASH],
    });
  });

  it("requires an explicit digest probe for installed tags before claiming success", () => {
    const plan = buildLocalProvisioningPlan({
      manifest: BODY,
      hardware: hardware({ ollamaModels: ["qwen2.5:1.5b"] }),
      surfaces: ["concierge"],
    });

    expect(plan.status).toBe("needs_digest_probe");
    expect(plan.modelPlans[0]).toMatchObject({
      modelId: "qwen",
      status: "digest_probe_required",
      blockReason: null,
    });
  });

  it("does not treat blob-only or wrong manifest digests as proof", () => {
    const blobOnly = buildLocalProvisioningPlan({
      manifest: BODY,
      hardware: hardware({ ollamaModels: ["phi4-mini"] }),
      surfaces: ["privacy-filter-tier-2"],
      digestReports: [
        {
          model: "phi4-mini",
          manifestDigestSha256: null,
          blobSha256: [PHI_HASH],
        },
      ],
    });

    expect(blobOnly.status).toBe("blocked");
    expect(blobOnly.modelPlans[0]).toMatchObject({
      status: "blocked",
      blockReason: "digest_unavailable",
      observedBlobSha256: [PHI_HASH],
    });

    const wrongManifest = buildLocalProvisioningPlan({
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

    expect(wrongManifest.status).toBe("blocked");
    expect(wrongManifest.modelPlans[0]).toMatchObject({
      status: "blocked",
      blockReason: "digest_mismatch",
      observedManifestDigestSha256: OTHER_HASH,
    });
  });

  it("refuses requested tier elevation while allowing a lower requested tier", () => {
    const elevated = buildLocalProvisioningPlan({
      manifest: BODY,
      hardware: hardware({ tier: "mid" }),
      requestedTier: "pro",
    });
    expect(elevated.status).toBe("blocked");
    expect(elevated.blockReason).toBe("tier_exceeds_hardware");

    const lowered = buildLocalProvisioningPlan({
      manifest: BODY,
      hardware: hardware({ tier: "mid", ollamaModels: [] }),
      requestedTier: "baseline",
    });
    expect(lowered.status).toBe("needs_pull");
    expect(lowered.tier).toBe("baseline");
    expect(lowered.modelPlans.map((entry) => entry.modelId)).toEqual(["qwen"]);
  });
});
