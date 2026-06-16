/**
 * Integration Test: Reputation Portability Round-Trip
 *
 * Verifies the core value proposition: an agent can carry its reputation
 * from one Sanctuary instance to another with full signature verification.
 *
 * Tests:
 * - Export with known identity → import with signature verification → success
 * - Export → tamper → import with verification → rejection
 * - Export → import without verification → accepts (trust-on-first-import)
 * - Context-filtered export only includes matching attestations
 */

import { describe, it, expect } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { createL4Tools } from "../../src/reputation/tools.js";
import { fromBase64url, toBase64url } from "../../src/core/encoding.js";

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

async function createInstance() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);

  const { tools: l1Tools, identityManager } = createL1Tools(
    stateStore, storage, masterKey, "recovery-key", auditLog
  );
  await identityManager.load();
  const { tools: l4Tools } = createL4Tools(storage, masterKey, identityManager, auditLog);

  return {
    tools: [...l1Tools, ...l4Tools],
    storage,
    masterKey,
    identityManager,
  };
}

describe("Reputation Portability", () => {
  it("verified import succeeds when destination knows the source identity", async () => {
    // Instance A: create identity and record reputation
    const instA = await createInstance();

    const identity = await callTool(instA.tools, "identity_create", {
      label: "portable-agent",
    });

    await callTool(instA.tools, "reputation_record", {
      interaction_id: "txn-port-001",
      counterparty_did: "did:key:cp1",
      outcome: { type: "transaction", result: "completed", metrics: { score: 95 } },
      context: "commerce",
      identity_id: identity.identity_id,
    });

    const exported = await callTool(instA.tools, "reputation_export", {
      identity_id: identity.identity_id,
    });

    // Instance B: import with the source's public key registered
    const instB = await createInstance();

    // Register source identity in Instance B (key exchange happened out of band)
    const sourceIdentity = instA.identityManager.get(identity.identity_id as string)!;
    await instB.identityManager.save(sourceIdentity);

    const imported = await callTool(instB.tools, "reputation_import", {
      bundle: exported.bundle,
      verify_signatures: true,
    });

    expect(imported.imported_attestations).toBe(1);
    expect(imported.invalid_attestations).toBe(0);

    // Verify imported data
    const query = await callTool(instB.tools, "reputation_query", {});
    const summary = query.summary as Record<string, unknown>;
    expect(summary.total_interactions).toBe(1);
    expect(summary.completed).toBe(1);
  });

  it("verified import rejects tampered attestations", async () => {
    const instA = await createInstance();

    const identity = await callTool(instA.tools, "identity_create", {
      label: "tamper-test",
    });

    await callTool(instA.tools, "reputation_record", {
      interaction_id: "txn-tamper-001",
      counterparty_did: "did:key:cp1",
      outcome: { type: "transaction", result: "completed" },
      context: "test",
      identity_id: identity.identity_id,
    });

    const exported = await callTool(instA.tools, "reputation_export", {
      identity_id: identity.identity_id,
    });

    // Tamper with the bundle: decode, modify, re-encode
    const bundleBytes = fromBase64url(exported.bundle as string);
    const bundleJson = JSON.parse(new TextDecoder().decode(bundleBytes));
    bundleJson.attestations[0].data.outcome_result = "failed"; // tamper!
    const tamperedBundle = toBase64url(
      new TextEncoder().encode(JSON.stringify(bundleJson))
    );

    // Instance B with source identity registered
    const instB = await createInstance();
    const sourceIdentity = instA.identityManager.get(identity.identity_id as string)!;
    await instB.identityManager.save(sourceIdentity);

    const imported = await callTool(instB.tools, "reputation_import", {
      bundle: tamperedBundle,
      verify_signatures: true,
    });

    // Tampered attestation should be rejected
    expect(imported.imported_attestations).toBe(0);
    expect(imported.invalid_attestations).toBe(1);
  });

  it("context-filtered export only includes matching attestations", async () => {
    const inst = await createInstance();

    const identity = await callTool(inst.tools, "identity_create", {
      label: "filter-test",
    });

    // Record in two different contexts
    await callTool(inst.tools, "reputation_record", {
      interaction_id: "txn-c1",
      counterparty_did: "did:key:cp",
      outcome: { type: "transaction", result: "completed" },
      context: "commerce",
      identity_id: identity.identity_id,
    });
    await callTool(inst.tools, "reputation_record", {
      interaction_id: "txn-c2",
      counterparty_did: "did:key:cp",
      outcome: { type: "service", result: "completed" },
      context: "support",
      identity_id: identity.identity_id,
    });

    // Export only commerce
    const commerceExport = await callTool(inst.tools, "reputation_export", {
      context: "commerce",
      identity_id: identity.identity_id,
    });
    expect(commerceExport.attestation_count).toBe(1);
    expect((commerceExport.contexts as string[])).toContain("commerce");
    expect((commerceExport.contexts as string[])).not.toContain("support");

    // Export all
    const allExport = await callTool(inst.tools, "reputation_export", {
      identity_id: identity.identity_id,
    });
    expect(allExport.attestation_count).toBe(2);
  });
});
