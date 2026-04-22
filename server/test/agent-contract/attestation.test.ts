/**
 * Agent Contract v0.1 — Attestation tests (§2.9).
 */

import { describe, it, expect } from "vitest";
import {
  buildAttestation,
  emitAttestation,
  fetchAttestation,
  InMemoryAttestationStore,
  markAttestationDegraded,
} from "../../src/agent-contract/attestation.js";
import { AttestationUnavailableError } from "../../src/agent-contract/errors.js";
import { buildTestFortress } from "./fixture.js";

describe("Attestation emission + fetch (§2.9)", () => {
  it("builds a signed attestation and round-trips through the store", async () => {
    const f = buildTestFortress();
    const store = new InMemoryAttestationStore();
    const reg = await emitAttestation(store, {
      agent_id: "agent-a",
      fortress_id: f.master.public.fortress_id,
      usage_event_id: "u-1",
      source: "proxy_canonical",
      attested_payload: { tool: "fs", result_bytes: 42 },
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      monotonic_seq: 0,
    });
    expect(reg.attestation.usage_event_id).toBe("u-1");
    const fetched = await fetchAttestation(store, "u-1", f.verifyContext);
    expect(fetched.attested_hash).toBe(reg.attestation.attested_hash);
  });

  it("reports missing attestation (degrade-not-destroy)", async () => {
    const f = buildTestFortress();
    const store = new InMemoryAttestationStore();
    await markAttestationDegraded(store, "u-2", "signer offline");
    await expect(
      fetchAttestation(store, "u-2", f.verifyContext)
    ).rejects.toThrow(AttestationUnavailableError);
    expect(await store.degradationReason("u-2")).toBe("signer offline");
  });

  it("emits without attested_payload (degraded synthesis still produces a hash)", () => {
    const f = buildTestFortress();
    const { attestation } = buildAttestation({
      agent_id: "a",
      fortress_id: f.master.public.fortress_id,
      usage_event_id: "u-3",
      source: "harness_self_report",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      monotonic_seq: 0,
    });
    expect(attestation.attested_hash.length).toBeGreaterThan(0);
    expect(attestation.attested_payload).toBeUndefined();
  });
});
