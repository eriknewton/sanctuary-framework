import { describe, expect, it } from "vitest";

import {
  buildLocalProvisioningModelPullAuditPayload,
  buildLocalProvisioningRefusalAuditPayload,
  INTEL_OPS,
} from "../../src/intelligence/index.js";

const header = {
  version: "1.2",
  event_id: "int-local-provisioning-1",
  emitted_at: "2026-08-07T13:30:00.000Z",
  identity_id: "operator-1",
} as const;

const sha256Hex = "b".repeat(64);

describe("local provisioning audit payload builders", () => {
  it("builds a model_pull payload only for a consented verified pull", () => {
    const result = buildLocalProvisioningModelPullAuditPayload({
      header,
      surfaces: ["template-suggestion", "concierge", "concierge"],
      tier: "baseline",
      modelId: "qwen2.5-1.5b",
      runtimeTag: "qwen2.5:1.5b-instruct",
      manifestVersion: "2026-08-07",
      expectedWeightsSha256: sha256Hex,
      observedManifestDigestSha256: sha256Hex,
      operatorConsentEventId: "audit-consent-1",
      latencyMs: 420,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.message);
    expect(result.operation).toBe(INTEL_OPS.MODEL_PULL);
    expect(result.payload).toMatchObject({
      kind: "model_pull",
      surfaces: ["concierge", "template-suggestion"],
      runtime: "ollama",
      requires_operator_consent: true,
      requires_network_egress: true,
      mutates_host: true,
      writes_fortress_state: false,
    });
    expect(result.payload).not.toHaveProperty("request_body");
    expect(result.payload).not.toHaveProperty("response_body");
  });

  it("refuses model_pull payloads when digest evidence is not exact", () => {
    const result = buildLocalProvisioningModelPullAuditPayload({
      header,
      surfaces: ["concierge"],
      tier: "baseline",
      modelId: "qwen2.5-1.5b",
      runtimeTag: "qwen2.5:1.5b-instruct",
      manifestVersion: "2026-08-07",
      expectedWeightsSha256: sha256Hex,
      observedManifestDigestSha256: "c".repeat(64),
      operatorConsentEventId: "audit-consent-1",
      latencyMs: 420,
    });

    expect(result).toMatchObject({
      ok: false,
      operation: INTEL_OPS.MODEL_PULL,
      reason: "digest_mismatch",
    });
  });

  it("requires operator consent before a model_pull payload can exist", () => {
    const result = buildLocalProvisioningModelPullAuditPayload({
      header,
      surfaces: ["concierge"],
      tier: "baseline",
      modelId: "qwen2.5-1.5b",
      runtimeTag: "qwen2.5:1.5b-instruct",
      manifestVersion: "2026-08-07",
      expectedWeightsSha256: sha256Hex,
      observedManifestDigestSha256: sha256Hex,
      operatorConsentEventId: "   ",
      latencyMs: 420,
    });

    expect(result).toMatchObject({
      ok: false,
      operation: INTEL_OPS.MODEL_PULL,
      reason: "missing_operator_consent",
    });
  });

  it("builds a fail-closed model_provision_refused payload without mutation flags", () => {
    const result = buildLocalProvisioningRefusalAuditPayload({
      header,
      surfaces: ["privacy-filter-tier-2"],
      tier: null,
      reason: "hardware_below_baseline",
      requiresOperatorConsent: false,
      requiresNetworkEgress: false,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.message);
    expect(result.operation).toBe(INTEL_OPS.MODEL_PROVISION_REFUSED);
    expect(result.payload).toMatchObject({
      kind: "model_provision_refused",
      surfaces: ["privacy-filter-tier-2"],
      tier: null,
      model_id: null,
      runtime: null,
      runtime_tag: null,
      reason: "hardware_below_baseline",
      mutates_host: false,
      writes_fortress_state: false,
    });
    expect(result.payload).not.toHaveProperty("request_body");
    expect(result.payload).not.toHaveProperty("response_body");
  });

  it("rejects unknown refusal reasons before an audit payload is built", () => {
    const result = buildLocalProvisioningRefusalAuditPayload({
      header,
      surfaces: ["concierge"],
      tier: "baseline",
      reason: "free-form reason" as never,
    });

    expect(result).toMatchObject({
      ok: false,
      operation: INTEL_OPS.MODEL_PROVISION_REFUSED,
      reason: "invalid_refusal_reason",
    });
  });
});
