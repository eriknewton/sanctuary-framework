/**
 * Agent Contract v0.1 — Usage event emission + verification tests (§6).
 */

import { describe, it, expect } from "vitest";
import { toBase64url } from "../../src/core/encoding.js";
import {
  emitUsageEvent,
  verifyUsageEvent,
} from "../../src/agent-contract/usage-event.js";
import { UsageEventSchemaError } from "../../src/agent-contract/errors.js";
import { MeshSignatureError } from "../../src/mesh/errors.js";
import { SIGNATURE_SCHEME_V1 } from "../../src/mesh/constants.js";
import { buildTestFortress } from "./fixture.js";
import type { SignedEvent } from "../../src/mesh/types.js";
import type { UsageEvent } from "../../src/agent-contract/types.js";

describe("Usage event emission + verification (§6)", () => {
  it("emits a well-formed usage event that round-trips verification", () => {
    const f = buildTestFortress();
    const { signed_event, event } = emitUsageEvent({
      agent_id: "agent-alpha",
      fortress_id: f.master.public.fortress_id,
      event_class: "tool_call",
      capability_kind: "tool-call",
      capability_target: "filesystem/read",
      input: { path: "/tmp/a.txt" },
      output: { bytes: "hello" },
      policy_version: 1,
      policy_version_hash: toBase64url(new Uint8Array([1, 2, 3])),
      attestation_state: "present",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      principal_private_key: f.principalKeypair.privateKey,
      monotonic_seq: 0,
    });
    expect(event.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
    expect(event.capability_kind).toBe("tool-call");
    const r = verifyUsageEvent(signed_event, f.verifyContext);
    expect(r.event.agent_id).toBe("agent-alpha");
  });

  it("rejects wrong event_type", () => {
    const f = buildTestFortress();
    const { signed_event } = emitUsageEvent({
      agent_id: "agent-alpha",
      fortress_id: f.master.public.fortress_id,
      event_class: "tool_call",
      capability_kind: "tool-call",
      capability_target: "x",
      input: null,
      output: null,
      policy_version: 1,
      policy_version_hash: "aGFzaA",
      attestation_state: "present",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      monotonic_seq: 0,
    });
    const wrong = { ...signed_event, event_type: "heartbeat" };
    expect(() =>
      verifyUsageEvent(wrong as SignedEvent, f.verifyContext)
    ).toThrow(UsageEventSchemaError);
  });

  it("rejects tamper on the output_hash (payload_hash coherence)", () => {
    const f = buildTestFortress();
    const { signed_event } = emitUsageEvent({
      agent_id: "agent-alpha",
      fortress_id: f.master.public.fortress_id,
      event_class: "tool_call",
      capability_kind: "tool-call",
      capability_target: "x",
      input: { a: 1 },
      output: { b: 2 },
      policy_version: 1,
      policy_version_hash: "aGFzaA",
      attestation_state: "present",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      monotonic_seq: 0,
    });
    const tampered: SignedEvent<UsageEvent> = {
      ...signed_event,
      payload: { ...signed_event.payload, output_hash: "ZEVHONiZRxYX" },
    };
    expect(() => verifyUsageEvent(tampered, f.verifyContext)).toThrow(
      MeshSignatureError
    );
  });

  it("produces identical input_hash for equal inputs (canonical canonicalization)", () => {
    const f = buildTestFortress();
    const a = emitUsageEvent({
      agent_id: "agent-alpha",
      fortress_id: f.master.public.fortress_id,
      event_class: "tool_call",
      capability_kind: "tool-call",
      capability_target: "x",
      input: { a: 1, b: 2 },
      output: null,
      policy_version: 1,
      policy_version_hash: "aGFzaA",
      attestation_state: "present",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      monotonic_seq: 0,
    });
    const b = emitUsageEvent({
      agent_id: "agent-alpha",
      fortress_id: f.master.public.fortress_id,
      event_class: "tool_call",
      capability_kind: "tool-call",
      capability_target: "x",
      input: { b: 2, a: 1 }, // reversed key order
      output: null,
      policy_version: 1,
      policy_version_hash: "aGFzaA",
      attestation_state: "present",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      monotonic_seq: 1,
    });
    expect(a.event.input_hash).toBe(b.event.input_hash);
  });
});
