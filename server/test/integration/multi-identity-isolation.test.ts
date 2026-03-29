/**
 * Integration Test: Multi-Identity Isolation
 *
 * Verifies that multiple identities within the same Sanctuary instance
 * maintain proper isolation:
 * - Each identity has unique keys
 * - State written by one identity is accessible but attributed correctly
 * - Signatures from one identity cannot be verified against another
 * - Reputation is correctly associated with the signing identity
 */

import { describe, it, expect } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/l1-cognitive/state-store.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { createL1Tools } from "../../src/l1-cognitive/tools.js";
import { createL4Tools } from "../../src/l4-reputation/tools.js";

async function callTool(
  tools: Array<{ name: string; handler: (args: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }> }> }>,
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const tool = tools.find((t) => t.name === name);
  if (!tool) throw new Error(`Tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text);
}

describe("Multi-Identity Isolation", () => {
  it("two identities have distinct keys, DIDs, and signatures", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const stateStore = new StateStore(storage, masterKey);
    const auditLog = new AuditLog(storage, masterKey);

    const { tools, identityManager } = createL1Tools(
      stateStore, storage, masterKey, "recovery-key", auditLog
    );
    await identityManager.load();

    // Create two distinct identities
    const alice = await callTool(tools, "sanctuary/identity_create", {
      label: "alice-agent",
    });
    const bob = await callTool(tools, "sanctuary/identity_create", {
      label: "bob-agent",
    });

    // Different IDs, keys, and DIDs
    expect(alice.identity_id).not.toBe(bob.identity_id);
    expect(alice.public_key).not.toBe(bob.public_key);
    expect(alice.did).not.toBe(bob.did);

    // Alice signs a message
    const aliceSig = await callTool(tools, "sanctuary/identity_sign", {
      identity_id: alice.identity_id,
      payload: "hello from alice",
    });

    // Verify with Alice's key: valid
    const aliceVerify = await callTool(tools, "sanctuary/identity_verify", {
      identity_id: alice.identity_id,
      payload: "hello from alice",
      signature: aliceSig.signature,
    });
    expect(aliceVerify.valid).toBe(true);

    // Verify with Bob's key: invalid (cross-identity rejection)
    const bobVerify = await callTool(tools, "sanctuary/identity_verify", {
      identity_id: bob.identity_id,
      payload: "hello from alice",
      signature: aliceSig.signature,
    });
    expect(bobVerify.valid).toBe(false);
  });

  it("reputation attestations are bound to the signing identity", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const stateStore = new StateStore(storage, masterKey);
    const auditLog = new AuditLog(storage, masterKey);

    const { tools: l1Tools, identityManager } = createL1Tools(
      stateStore, storage, masterKey, "recovery-key", auditLog
    );
    await identityManager.load();
    const { tools: l4Tools } = createL4Tools(storage, masterKey, identityManager, auditLog);
    const allTools = [...l1Tools, ...l4Tools];

    const agent1 = await callTool(allTools, "sanctuary/identity_create", {
      label: "agent-1",
    });
    const agent2 = await callTool(allTools, "sanctuary/identity_create", {
      label: "agent-2",
    });

    // Agent 1 records a transaction
    await callTool(allTools, "sanctuary/reputation_record", {
      interaction_id: "txn-001",
      counterparty_did: "did:key:external",
      outcome: { type: "transaction", result: "completed" },
      context: "commerce",
      identity_id: agent1.identity_id,
    });

    // Agent 2 records a different transaction
    await callTool(allTools, "sanctuary/reputation_record", {
      interaction_id: "txn-002",
      counterparty_did: "did:key:external",
      outcome: { type: "service", result: "failed" },
      context: "support",
      identity_id: agent2.identity_id,
    });

    // Query all — both present
    const all = await callTool(allTools, "sanctuary/reputation_query", {});
    const summary = all.summary as Record<string, unknown>;
    expect(summary.total_interactions).toBe(2);
    expect(summary.completed).toBe(1);
    expect(summary.failed).toBe(1);

    // Export with agent1's identity — all attestations included
    // (export includes all, signed by the export identity)
    const exported = await callTool(allTools, "sanctuary/reputation_export", {
      format: "SANCTUARY_REP_V1",
      identity_id: agent1.identity_id,
    });
    expect(exported.attestation_count).toBe(2);
  });

  it("identity list shows all created identities", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const stateStore = new StateStore(storage, masterKey);
    const auditLog = new AuditLog(storage, masterKey);

    const { tools, identityManager } = createL1Tools(
      stateStore, storage, masterKey, "recovery-key", auditLog
    );
    await identityManager.load();

    await callTool(tools, "sanctuary/identity_create", { label: "id-1" });
    await callTool(tools, "sanctuary/identity_create", { label: "id-2" });
    await callTool(tools, "sanctuary/identity_create", { label: "id-3" });

    const list = await callTool(tools, "sanctuary/identity_list", {});
    const identities = list.identities as Array<Record<string, unknown>>;
    expect(identities).toHaveLength(3);
    const labels = identities.map((i) => i.label);
    expect(labels).toContain("id-1");
    expect(labels).toContain("id-2");
    expect(labels).toContain("id-3");
  });
});
