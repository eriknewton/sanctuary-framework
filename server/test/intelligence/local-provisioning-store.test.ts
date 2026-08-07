import { describe, expect, it } from "vitest";
import {
  applyLocalProvisioningReceiptToStore,
  buildLocalProvisioningPlan,
  buildLocalProvisioningReceipt,
  type HardwareCapabilityReport,
  type LocalProvisioningPlan,
  type ModelManifestBody,
} from "../../src/intelligence/index.js";
import {
  InMemoryModelProvenanceStore,
  MODEL_PRESETS,
} from "../../src/operational/model-provenance.js";

const QWEN_HASH =
  "1111111111111111111111111111111111111111111111111111111111111111";
const PHI_HASH =
  "2222222222222222222222222222222222222222222222222222222222222222";
const DECLARED_AT = "2026-08-07T05:45:00.000Z";

const BODY: ModelManifestBody = {
  manifest_version: 11,
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

describe("local provisioning receipt store application", () => {
  it("applies a complete receipt to the injected provenance store", () => {
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
    const store = new InMemoryModelProvenanceStore();

    const result = applyLocalProvisioningReceiptToStore({
      receipt: receiptFrom(plan),
      store,
    });

    expect(result).toEqual({
      status: "applied_complete",
      manifestVersion: 11,
      receiptStatus: "complete",
      declaredModelIds: ["qwen"],
      skippedRefusedModelIds: [],
      primaryModelId: null,
      refusalReason: null,
    });
    expect(store.get("qwen")).toMatchObject({
      model_id: "qwen",
      weights_hash: `sha256:${QWEN_HASH}`,
      declared_at: DECLARED_AT,
      local_inference: true,
    });
    expect(store.get("phi")).toBeUndefined();
  });

  it("refuses partial receipts by default without mutating the store", () => {
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
    const store = new InMemoryModelProvenanceStore();
    const existing = MODEL_PRESETS.claudeOpus4();
    store.declare(existing);

    const result = applyLocalProvisioningReceiptToStore({
      receipt: receiptFrom(plan),
      store,
    });

    expect(result).toMatchObject({
      status: "refused",
      receiptStatus: "partial",
      declaredModelIds: ["qwen"],
      skippedRefusedModelIds: ["phi"],
      refusalReason: "receipt_partial",
    });
    expect(store.list()).toEqual([existing]);
    expect(store.get("qwen")).toBeUndefined();
  });

  it("applies only the verified subset when partial application is explicit", () => {
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
    const store = new InMemoryModelProvenanceStore();

    const result = applyLocalProvisioningReceiptToStore({
      receipt: receiptFrom(plan),
      store,
      allowPartial: true,
    });

    expect(result).toMatchObject({
      status: "applied_partial",
      receiptStatus: "partial",
      declaredModelIds: ["qwen"],
      skippedRefusedModelIds: ["phi"],
      refusalReason: null,
    });
    expect(store.get("qwen")).toMatchObject({ model_id: "qwen" });
    expect(store.get("phi")).toBeUndefined();
  });

  it("validates explicit primary selection before mutating the store", () => {
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
    const store = new InMemoryModelProvenanceStore();

    const result = applyLocalProvisioningReceiptToStore({
      receipt: receiptFrom(plan),
      store,
      setPrimary: true,
      primaryModelId: "phi",
    });

    expect(result).toMatchObject({
      status: "refused",
      refusalReason: "primary_model_not_declared",
    });
    expect(store.list()).toEqual([]);
  });

  it("sets an explicit primary only after declaring matching models", () => {
    const plan = buildLocalProvisioningPlan({
      manifest: BODY,
      hardware: hardware({ ollamaModels: ["qwen2.5:1.5b", "phi4-mini"] }),
      surfaces: ["concierge", "privacy-filter-tier-2"],
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
    const store = new InMemoryModelProvenanceStore();

    const result = applyLocalProvisioningReceiptToStore({
      receipt: receiptFrom(plan),
      store,
      setPrimary: true,
      primaryModelId: "phi",
    });

    expect(result).toMatchObject({
      status: "applied_complete",
      declaredModelIds: ["qwen", "phi"],
      primaryModelId: "phi",
      refusalReason: null,
    });
    expect(store.primary()?.model_id).toBe("phi");
  });

  it("refuses fully refused receipts without store writes", () => {
    const plan = buildLocalProvisioningPlan({
      manifest: BODY,
      hardware: hardware({
        tier: "below-baseline",
        recommendedLocalModel: null,
      }),
    });
    const store = new InMemoryModelProvenanceStore();

    const result = applyLocalProvisioningReceiptToStore({
      receipt: receiptFrom(plan),
      store,
      allowPartial: true,
    });

    expect(result).toMatchObject({
      status: "refused",
      receiptStatus: "refused",
      declaredModelIds: [],
      skippedRefusedModelIds: [],
      refusalReason: "receipt_refused",
    });
    expect(store.list()).toEqual([]);
  });
});
