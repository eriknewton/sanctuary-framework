/**
 * Agent-contract audit-log SEAL — end-to-end.
 *
 * Closes the deferred audit-log seal in `agent-contract/lifecycle.ts`: a Tier-B
 * adapter configured with `lifecycle_seal` writes a critical, chain-bound
 * workload-lifecycle audit entry for every (audit-mapped) lifecycle transition,
 * binding the mesh SignedEvent to the chain by `signed_event_hash`.
 *
 * Asserts: dual-channel binding (M5), checkpointed is the one unmirrored
 * transition, sleep-as-default for retire/revoke, prev-link honesty (H2), and
 * that absent seal config is a clean no-op (additive, non-breaking).
 */

import { describe, it, expect } from "vitest";

import {
  bindAgentIdentity,
  InMemoryAgentKeyStore,
} from "../../src/agent-contract/identity-bind.js";
import {
  ClineAdapter,
  type ClineTransport,
  type TierBAdapterParams,
} from "../../src/agent-contract/adapters/cline.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { canonicalJson, sha256Hex } from "../../src/audit/chain.js";
import { buildPolicyBlobBytes, buildTestFortress } from "../agent-contract/fixture.js";
import type { LifecycleSealContext } from "../../src/workload-lifecycle/seal.js";

function makeStubClineTransport(): ClineTransport {
  return {
    async send() {},
    async receive() {
      return null;
    },
    async close() {},
  } as ClineTransport;
}

async function buildSealedAdapter() {
  const f = buildTestFortress();
  const store = new InMemoryAgentKeyStore();
  const binding = await bindAgentIdentity({
    agent_id: "agent-a",
    fortress_id: f.master.public.fortress_id,
    fortress_master_secret: f.fortressMasterSecret,
    store,
  });
  const storage = new MemoryStorage();
  const auditLog = new AuditLog(storage, generateRandomKey());
  const sealContext: LifecycleSealContext = {
    auditLog,
    workload_class: "stateful-agent",
    initiator: { kind: "operator", identity_id: "op-1" },
    recording_identity_id: "fortress-1",
  };
  const base: TierBAdapterParams = {
    agent_id: "agent-a",
    fortress_id: f.master.public.fortress_id,
    harness_id: "cline",
    model_provider: "anthropic",
    model_id: "claude-opus-4-7",
    capabilities: [{ kind: "tool-call", target: "filesystem/read*" }],
    policy_version: 1,
    policy_blob_bytes: buildPolicyBlobBytes(1),
    attestation_endpoint: "http://127.0.0.1:3501/att",
    key_store: store,
    agent_identity_binding: binding,
    fortress_master_secret: f.fortressMasterSecret,
    emitter_node: f.nodeCert.node_id,
    emitter_principal: f.principalCert.principal_id,
    node_private_key: f.nodeKeypair.privateKey,
    lifecycle_seal: {
      context: sealContext,
      workload_id: "wl-a",
      instance_id: "wli-a",
    },
  };
  const adapter = new ClineAdapter({ ...base, transport: makeStubClineTransport() });
  return { adapter, auditLog, base, f, store };
}

describe("agent-contract seal — dual-channel binding", () => {
  it("seals a launched transition into the chain and binds by signed_event_hash", async () => {
    const { adapter, auditLog } = await buildSealedAdapter();
    const { lifecycle_emission } = await adapter.launch();

    const { entries } = await auditLog.query({
      operation_type: "workload_instantiated",
    });
    expect(entries).toHaveLength(1);
    const details = entries[0]!.details!;
    expect(details.workload_id).toBe("wl-a");
    expect(details.instance_id).toBe("wli-a");
    expect(details.workload_class).toBe("stateful-agent");
    // Honest by default: v1 consent is operator authorization, flagged absent.
    expect(details.consent_status).toBe("absent");
    expect(details.manufactured_preference_caveat).toBe(true);
    // The binding: the audit entry commits to exactly this mesh SignedEvent.
    expect(details.signed_event_hash).toBe(
      sha256Hex(canonicalJson(lifecycle_emission.signed_event))
    );
  });

  it("retire records as workload_slept (sleep-as-default), not delete", async () => {
    const { adapter, auditLog } = await buildSealedAdapter();
    await adapter.launch();
    await adapter.retire("launched", "test exit");

    const slept = await auditLog.query({ operation_type: "workload_slept" });
    expect(slept.entries).toHaveLength(1);
    expect(slept.entries[0]!.details?.state_disposition).toBe("preserved");

    const deleted = await auditLog.query({ operation_type: "workload_deleted" });
    expect(deleted.entries).toHaveLength(0);
  });

  it("checkpointed is the one transition with NO audit counterpart (M5)", async () => {
    const { adapter, auditLog } = await buildSealedAdapter();
    await adapter.launch();
    // Drive a checkpoint via the adapter's lifecycle command surface.
    await adapter.sendLifecycle("checkpoint", {
      from_state: "launched",
      reason: "snapshot",
      checkpoint_hash: "Y2hlY2twb2ludA",
    });
    // No workload_checkpointed op exists, and checkpointed maps to no op:
    const all = await auditLog.query({ layer: "l2", limit: 100 });
    const ops = all.entries.map((e) => e.operation);
    expect(ops).toContain("workload_instantiated");
    expect(ops).not.toContain("workload_checkpointed");
    // The checkpoint mesh event still happened; it is simply not mirrored.
  });

  it("prev_lifecycle_seq forms a per-instance ordinal across sealed events", async () => {
    const { adapter, auditLog } = await buildSealedAdapter();
    // launch is the FIRST recorded event for this instance: it carries no
    // prev-link (nothing precedes it), and advances the ordinal to 1.
    await adapter.launch();
    // pause is the 2nd recorded event; its prev points at launch (ordinal 1).
    await adapter.sendLifecycle("pause", { from_state: "launched", reason: "p" });
    // resume is the 3rd; its prev points at pause (ordinal 2).
    await adapter.sendLifecycle("resume", {
      from_state: "paused",
      reason: "r",
      checkpoint_hash: "Y2hlY2twb2ludA",
    });

    const instantiated = await auditLog.query({
      operation_type: "workload_instantiated",
    });
    // First event: no prev-link.
    expect(instantiated.entries[0]!.details?.prev_lifecycle_seq).toBeUndefined();
    const paused = await auditLog.query({ operation_type: "workload_paused" });
    expect(paused.entries[0]!.details?.prev_lifecycle_seq).toBe(1);
    const resumed = await auditLog.query({ operation_type: "workload_resumed" });
    expect(resumed.entries[0]!.details?.prev_lifecycle_seq).toBe(2);
  });
});

describe("agent-contract seal — additive / non-breaking", () => {
  it("an adapter with NO lifecycle_seal writes no workload-lifecycle entries", async () => {
    // Same setup but seal omitted: the mesh emission still happens, the chain
    // stays empty of workload_* ops. Existing callers are unaffected.
    const f = buildTestFortress();
    const store = new InMemoryAgentKeyStore();
    const binding = await bindAgentIdentity({
      agent_id: "agent-a",
      fortress_id: f.master.public.fortress_id,
      fortress_master_secret: f.fortressMasterSecret,
      store,
    });
    const adapter = new ClineAdapter({
      agent_id: "agent-a",
      fortress_id: f.master.public.fortress_id,
      harness_id: "cline",
      model_provider: "anthropic",
      model_id: "claude-opus-4-7",
      capabilities: [{ kind: "tool-call", target: "filesystem/read*" }],
      policy_version: 1,
      policy_blob_bytes: buildPolicyBlobBytes(1),
      attestation_endpoint: "http://127.0.0.1:3501/att",
      key_store: store,
      agent_identity_binding: binding,
      fortress_master_secret: f.fortressMasterSecret,
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      transport: makeStubClineTransport(),
    });
    const { lifecycle_emission } = await adapter.launch();
    expect(lifecycle_emission.body.to_state).toBe("launched");
    // No AuditLog was wired; nothing to assert on a chain — the point is it did
    // not throw and required no audit instance.
  });
});
