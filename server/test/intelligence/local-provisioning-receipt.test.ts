import { describe, expect, it } from "vitest";
import {
  buildLocalProvisioningPlan,
  buildLocalProvisioningReceipt,
  type HardwareCapabilityReport,
  type LocalProvisioningPlan,
  type ModelManifestBody,
} from "../../src/intelligence/index.js";

const QWEN_HASH =
  "1111111111111111111111111111111111111111111111111111111111111111";
const PHI_HASH =
  "2222222222222222222222222222222222222222222222222222222222222222";
const OTHER_HASH =
  "3333333333333333333333333333333333333333333333333333333333333333";
const DECLARED_AT = "2026-08-07T05:30:00.000Z";

const BODY: ModelManifestBody = {
  manifest_version: 10,
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

function receiptFrom(plan: LocalProvisioningPlan) {
  return buildLocalProvisioningReceipt({
    manifest: BODY,
    plan,
    declaredAt: DECLARED_AT,
  });
}

describe("local provisioning receipt", () => {
  it("declares provenance only for exact manifest-digest matches", () => {
    const plan = buildLocalProvisioningPlan({
      manifest: BODY,
      hardware: hardware({ ollamaModels: ["qwen2.5:1.5b"] }),
      surfaces: ["concierge"],
      digestReports: [
        {
          model: "qwen2.5:1.5b",
          manifestDigestSha256: QWEN_HASH,
          blobSha256: [OTHER_HASH],
        },
      ],
    });

    const receipt = receiptFrom(plan);

    expect(receipt.status).toBe("complete");
    expect(receipt.refusedModels).toEqual([]);
    expect(receipt.declaredModels).toHaveLength(1);
    expect(receipt.declaredModels[0]).toMatchObject({
      modelId: "qwen",
      runtimeTag: "qwen2.5:1.5b",
      surfaces: ["concierge"],
      manifestVersion: 10,
      weightsSha256: QWEN_HASH,
      observedManifestDigestSha256: QWEN_HASH,
      provenance: {
        model_id: "qwen",
        weights_hash: `sha256:${QWEN_HASH}`,
        declared_at: DECLARED_AT,
        local_inference: true,
      },
    });
  });

  it("refuses to mint provenance for pull-required models", () => {
    const plan = buildLocalProvisioningPlan({
      manifest: BODY,
      hardware: hardware({ ollamaModels: [] }),
      surfaces: ["concierge"],
    });

    const receipt = receiptFrom(plan);

    expect(receipt.status).toBe("refused");
    expect(receipt.declaredModels).toEqual([]);
    expect(receipt.refusedModels).toEqual([
      expect.objectContaining({
        modelId: "qwen",
        status: "pull_required",
        reason: "model_not_provisioned",
      }),
    ]);
  });

  it("reports partial receipts without hiding unprovisioned surfaces", () => {
    const plan = buildLocalProvisioningPlan({
      manifest: BODY,
      hardware: hardware({ ollamaModels: ["qwen2.5:1.5b"] }),
      surfaces: ["concierge", "privacy-filter-tier-2"],
      digestReports: [
        {
          model: "qwen2.5:1.5b",
          manifestDigestSha256: QWEN_HASH,
          blobSha256: [],
        },
      ],
    });

    const receipt = receiptFrom(plan);

    expect(receipt.status).toBe("partial");
    expect(receipt.declaredModels.map((entry) => entry.modelId)).toEqual(["qwen"]);
    expect(receipt.refusedModels).toEqual([
      expect.objectContaining({
        modelId: "phi",
        status: "pull_required",
        surfaces: ["privacy-filter-tier-2"],
        reason: "model_not_provisioned",
      }),
    ]);
  });

  it("rechecks fabricated provisioned plans against the signed manifest", () => {
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
    const forged: LocalProvisioningPlan = {
      ...plan,
      modelPlans: [
        {
          ...plan.modelPlans[0]!,
          expectedWeightsSha256: OTHER_HASH,
          status: "already_provisioned",
        },
      ],
    };

    const receipt = receiptFrom(forged);

    expect(receipt.status).toBe("refused");
    expect(receipt.declaredModels).toEqual([]);
    expect(receipt.refusedModels[0]).toMatchObject({
      modelId: "qwen",
      reason: "plan_manifest_mismatch",
      expectedWeightsSha256: OTHER_HASH,
    });
  });

  it("refuses digest-unavailable and digest-mismatch plans", () => {
    const blobOnlyPlan = buildLocalProvisioningPlan({
      manifest: BODY,
      hardware: hardware({ ollamaModels: ["qwen2.5:1.5b"] }),
      surfaces: ["concierge"],
      digestReports: [
        {
          model: "qwen2.5:1.5b",
          manifestDigestSha256: null,
          blobSha256: [QWEN_HASH],
        },
      ],
    });
    expect(receiptFrom(blobOnlyPlan).refusedModels[0]).toMatchObject({
      reason: "digest_unavailable",
      blockReason: "digest_unavailable",
    });

    const mismatchPlan = buildLocalProvisioningPlan({
      manifest: BODY,
      hardware: hardware({ ollamaModels: ["qwen2.5:1.5b"] }),
      surfaces: ["concierge"],
      digestReports: [
        {
          model: "qwen2.5:1.5b",
          manifestDigestSha256: OTHER_HASH,
          blobSha256: [],
        },
      ],
    });
    expect(receiptFrom(mismatchPlan).refusedModels[0]).toMatchObject({
      reason: "digest_mismatch",
      blockReason: "digest_mismatch",
      observedManifestDigestSha256: OTHER_HASH,
    });
  });

  it("keeps plan-level hardware refusals visible", () => {
    const plan = buildLocalProvisioningPlan({
      manifest: BODY,
      hardware: hardware({
        tier: "below-baseline",
        recommendedLocalModel: null,
      }),
    });

    const receipt = receiptFrom(plan);

    expect(receipt.status).toBe("refused");
    expect(receipt.planBlockReason).toBe("hardware_below_baseline");
    expect(receipt.declaredModels).toEqual([]);
    expect(receipt.refusedModels).toEqual([]);
  });
});
