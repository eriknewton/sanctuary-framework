import { describe, expect, it } from "vitest";

import { INTEL_OPS } from "../../src/intelligence/audit-events.js";
import type {
  IntelligenceAuditPayload,
  IntelligenceModelProvisionRefusedPayload,
  IntelligenceModelPullPayload,
} from "../../src/intelligence/index.js";

const header = {
  version: "1.2",
  event_id: "audit-event-1",
  emitted_at: "2026-08-07T13:00:00.000Z",
  identity_id: "operator-1",
} as const;

const sha256Hex = "a".repeat(64);

describe("local provisioning audit payload contracts", () => {
  it("ties the model-pull payload kind to the reserved audit operation name", () => {
    const payload: IntelligenceModelPullPayload = {
      ...header,
      kind: "model_pull",
      surfaces: ["concierge", "template-suggestion"],
      tier: "baseline",
      model_id: "qwen2.5-1.5b",
      runtime: "ollama",
      runtime_tag: "qwen2.5:1.5b-instruct",
      manifest_version: "2026-08-07",
      expected_weights_sha256: sha256Hex,
      observed_manifest_digest_sha256: sha256Hex,
      operator_consent_event_id: "audit-consent-1",
      latency_ms: 1234,
      requires_operator_consent: true,
      requires_network_egress: true,
      mutates_host: true,
      writes_fortress_state: false,
    };
    const auditPayload: IntelligenceAuditPayload = payload;

    expect(`intelligence_${auditPayload.kind}`).toBe(INTEL_OPS.MODEL_PULL);
    expect(payload).not.toHaveProperty("request_body");
    expect(payload).not.toHaveProperty("response_body");
    expect(payload).not.toHaveProperty("operator_credential");
  });

  it("keeps provisioning refusals metadata-only and fail-closed", () => {
    const payload: IntelligenceModelProvisionRefusedPayload = {
      ...header,
      event_id: "audit-event-2",
      kind: "model_provision_refused",
      surfaces: ["privacy-filter-tier-2"],
      tier: null,
      model_id: null,
      runtime: null,
      runtime_tag: null,
      manifest_version: null,
      expected_weights_sha256: null,
      observed_manifest_digest_sha256: null,
      reason: "hardware_below_baseline",
      operator_consent_event_id: null,
      requires_operator_consent: false,
      requires_network_egress: false,
      mutates_host: false,
      writes_fortress_state: false,
    };
    const auditPayload: IntelligenceAuditPayload = payload;

    expect(`intelligence_${auditPayload.kind}`).toBe(
      INTEL_OPS.MODEL_PROVISION_REFUSED,
    );
    expect(payload.mutates_host).toBe(false);
    expect(payload.writes_fortress_state).toBe(false);
    expect(payload).not.toHaveProperty("request_body");
    expect(payload).not.toHaveProperty("response_body");
    expect(payload).not.toHaveProperty("operator_credential");
  });
});
