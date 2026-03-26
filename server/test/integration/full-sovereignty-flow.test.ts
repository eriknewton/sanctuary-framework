/**
 * Integration Test: Full Sovereignty Flow
 *
 * Validates the RFC Section 10.1 acceptance criteria:
 * "An agent running in Claude Code can connect to the Sanctuary MCP Server,
 *  create an identity, write encrypted state, record interactions, export
 *  its reputation, and import it into a different harness — with zero
 *  plaintext leakage at any point."
 *
 * This test exercises all four sovereignty layers in sequence,
 * simulating a realistic agent lifecycle.
 */

import { describe, it, expect } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/l1-cognitive/state-store.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { createL1Tools } from "../../src/l1-cognitive/tools.js";
import { createL3Tools } from "../../src/l3-disclosure/tools.js";
import { createL4Tools } from "../../src/l4-reputation/tools.js";

/**
 * Helper: invoke an MCP tool handler by name and return parsed JSON result.
 */
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

describe("Full Sovereignty Flow", () => {
  it("identity → state → attest → commit → reputation → export → import", async () => {
    // ── Setup: Instance A (the "source" harness) ───────────────────────
    const storageA = new MemoryStorage();
    const masterKeyA = generateRandomKey();
    const stateStoreA = new StateStore(storageA, masterKeyA);
    const auditLogA = new AuditLog(storageA, masterKeyA);

    const { tools: l1Tools, identityManager: idMgrA } = createL1Tools(
      stateStoreA, storageA, masterKeyA, "recovery-key", auditLogA
    );
    await idMgrA.load();

    const { tools: l3Tools } = createL3Tools(storageA, masterKeyA, auditLogA);
    const { tools: l4Tools } = createL4Tools(storageA, masterKeyA, idMgrA, auditLogA);
    const allToolsA = [...l1Tools, ...l3Tools, ...l4Tools];

    // ── Step 1: L1 — Create Identity ───────────────────────────────────
    const identity = await callTool(allToolsA, "sanctuary/identity_create", {
      label: "test-agent-alpha",
    });
    expect(identity.identity_id).toBeTruthy();
    expect(identity.did).toBeTruthy();
    expect((identity.did as string)).toMatch(/^did:key:/);
    const identityId = identity.identity_id as string;

    // ── Step 2: L1 — Write Encrypted State ─────────────────────────────
    const writeResult = await callTool(allToolsA, "sanctuary/state_write", {
      namespace: "agent-memory",
      key: "preferences",
      value: JSON.stringify({
        risk_tolerance: "moderate",
        max_transaction: 5000,
        preferred_counterparties: ["did:key:trusted1", "did:key:trusted2"],
      }),
      identity_id: identityId,
    });
    expect(writeResult.version).toBe(1);
    expect(writeResult.merkle_root).toBeTruthy();

    // ── Step 3: L1 — Read Back State (verify round-trip) ───────────────
    const readResult = await callTool(allToolsA, "sanctuary/state_read", {
      namespace: "agent-memory",
      key: "preferences",
    });
    expect(readResult.integrity_verified).toBe(true);
    const parsedValue = JSON.parse(readResult.value as string);
    expect(parsedValue.risk_tolerance).toBe("moderate");
    expect(parsedValue.max_transaction).toBe(5000);

    // ── Step 4: L1 — Sign Data ─────────────────────────────────────────
    const signResult = await callTool(allToolsA, "sanctuary/identity_sign", {
      identity_id: identityId,
      payload: "I authorize transaction XYZ-789",
    });
    expect(signResult.signature).toBeTruthy();

    // ── Step 5: L1 — Verify Signature ──────────────────────────────────
    const verifyResult = await callTool(allToolsA, "sanctuary/identity_verify", {
      identity_id: identityId,
      payload: "I authorize transaction XYZ-789",
      signature: signResult.signature,
    });
    expect(verifyResult.valid).toBe(true);

    // ── Step 6: L3 — Create Commitment ─────────────────────────────────
    const commitment = await callTool(allToolsA, "sanctuary/proof_commitment", {
      value: "I am authorized for transactions up to $5,000",
    });
    expect(commitment.commitment).toBeTruthy();
    expect(commitment.blinding_factor).toBeTruthy();

    // ── Step 7: L3 — Reveal and Verify Commitment ──────────────────────
    const reveal = await callTool(allToolsA, "sanctuary/proof_reveal", {
      commitment: commitment.commitment,
      value: "I am authorized for transactions up to $5,000",
      blinding_factor: commitment.blinding_factor,
    });
    expect(reveal.valid).toBe(true);

    // ── Step 8: L3 — Set Disclosure Policy ─────────────────────────────
    const policy = await callTool(allToolsA, "sanctuary/disclosure_set_policy", {
      policy_name: "Commerce Negotiation Policy",
      rules: [
        {
          context: "commerce",
          disclose: ["agent_name", "capability_level"],
          withhold: ["spending_limit", "strategy"],
          proof_required: ["authorization_level"],
        },
        {
          context: "*",
          disclose: ["agent_name"],
          withhold: ["private_key", "master_key", "strategy"],
          proof_required: [],
        },
      ],
      default_action: "withhold",
    });
    expect(policy.policy_id).toBeTruthy();

    // ── Step 9: L3 — Evaluate Disclosure Request ───────────────────────
    const disclosure = await callTool(allToolsA, "sanctuary/disclosure_evaluate", {
      context: "commerce",
      requested_fields: [
        "agent_name",
        "spending_limit",
        "authorization_level",
        "strategy",
        "unknown_field",
      ],
      policy_id: policy.policy_id,
    });
    const decisions = disclosure.decisions as Array<{ field: string; action: string }>;
    expect(decisions.find((d) => d.field === "agent_name")!.action).toBe("disclose");
    expect(decisions.find((d) => d.field === "spending_limit")!.action).toBe("withhold");
    expect(decisions.find((d) => d.field === "authorization_level")!.action).toBe("proof");
    expect(decisions.find((d) => d.field === "strategy")!.action).toBe("withhold");
    expect(decisions.find((d) => d.field === "unknown_field")!.action).toBe("withhold");

    // ── Step 10: L4 — Record Reputation ────────────────────────────────
    const rep1 = await callTool(allToolsA, "sanctuary/reputation_record", {
      interaction_id: "txn-alpha-001",
      counterparty_did: "did:key:counterparty-beta",
      outcome: {
        type: "transaction",
        result: "completed",
        metrics: { fulfillment_rate: 1.0, response_time_ms: 450 },
      },
      context: "commerce",
      identity_id: identityId,
    });
    expect(rep1.attestation_id).toBeTruthy();
    expect(rep1.self_attestation).toBeTruthy();

    const rep2 = await callTool(allToolsA, "sanctuary/reputation_record", {
      interaction_id: "txn-alpha-002",
      counterparty_did: "did:key:counterparty-gamma",
      outcome: {
        type: "negotiation",
        result: "completed",
        metrics: { fulfillment_rate: 0.85, response_time_ms: 1200 },
      },
      context: "commerce",
      identity_id: identityId,
    });
    expect(rep2.attestation_id).toBeTruthy();

    // ── Step 11: L4 — Query Reputation ─────────────────────────────────
    const repQuery = await callTool(allToolsA, "sanctuary/reputation_query", {
      context: "commerce",
    });
    const summary = repQuery.summary as Record<string, unknown>;
    expect(summary.total_interactions).toBe(2);
    expect(summary.completed).toBe(2);
    const metrics = summary.aggregate_metrics as Record<string, Record<string, number>>;
    expect(metrics.fulfillment_rate.mean).toBeCloseTo(0.925);
    expect(metrics.response_time_ms.mean).toBeCloseTo(825);

    // ── Step 12: L4 — Export Reputation ────────────────────────────────
    const exportResult = await callTool(allToolsA, "sanctuary/reputation_export", {
      format: "SANCTUARY_REP_V1",
      identity_id: identityId,
    });
    expect(exportResult.attestation_count).toBe(2);
    expect(exportResult.bundle).toBeTruthy();
    expect(exportResult.bundle_hash).toBeTruthy();

    // ── Step 13: Import into Instance B (different harness) ────────────
    const storageB = new MemoryStorage();
    const masterKeyB = generateRandomKey();
    const stateStoreB = new StateStore(storageB, masterKeyB);
    const auditLogB = new AuditLog(storageB, masterKeyB);

    const { tools: l1ToolsB, identityManager: idMgrB } = createL1Tools(
      stateStoreB, storageB, masterKeyB, "recovery-key", auditLogB
    );
    await idMgrB.load();
    const { tools: l4ToolsB } = createL4Tools(storageB, masterKeyB, idMgrB, auditLogB);
    const allToolsB = [...l1ToolsB, ...l4ToolsB];

    // Create an identity in Instance B so we can work with it
    await callTool(allToolsB, "sanctuary/identity_create", {
      label: "instance-b-identity",
    });

    // For cross-instance import with signature verification, Instance B
    // must know Instance A's public key. In production this happens via
    // federation or explicit key exchange. Here we simulate it by
    // registering A's public identity in B's identity manager.
    for (const aPub of idMgrA.list()) {
      await idMgrB.save({
        identity_id: aPub.identity_id,
        label: aPub.label + "-imported",
        public_key: aPub.public_key,
        did: aPub.did,
        created_at: aPub.created_at,
        key_type: aPub.key_type,
        key_protection: "recovery-key",
        encrypted_private_key: { ct: "", iv: "", tag: "" },
      } as any);
    }

    // Import the bundle — signature verification is always enforced.
    // Instance B can verify because we registered A's public key above.
    const importResult = await callTool(allToolsB, "sanctuary/reputation_import", {
      bundle: exportResult.bundle,
    });
    expect(importResult.imported_attestations).toBe(2);
    expect(importResult.invalid_attestations).toBe(0);

    // Verify imported reputation is queryable in Instance B
    const repQueryB = await callTool(allToolsB, "sanctuary/reputation_query", {});
    const summaryB = repQueryB.summary as Record<string, unknown>;
    expect(summaryB.total_interactions).toBe(2);
    expect(summaryB.completed).toBe(2);

    // ── Step 14: Verify Zero Plaintext Leakage ─────────────────────────
    const sensitiveStrings = [
      "moderate",
      "risk_tolerance",
      "max_transaction",
      "preferred_counterparties",
      "did:key:trusted1",
      "I authorize transaction XYZ-789",
      "I am authorized for transactions up to $5,000",
      "Commerce Negotiation Policy",
      "spending_limit",
    ];

    // Scan Instance A storage
    for (const ns of ["agent-memory", "_identities", "_commitments", "_policies", "_reputation", "_audit"]) {
      const entries = await storageA.list(ns);
      for (const entry of entries) {
        const raw = await storageA.read(ns, entry.key);
        if (!raw) continue;
        const rawStr = new TextDecoder().decode(raw);
        for (const secret of sensitiveStrings) {
          expect(rawStr).not.toContain(secret);
        }
      }
    }

    // Scan Instance B storage
    for (const ns of ["_identities", "_reputation", "_audit"]) {
      const entries = await storageB.list(ns);
      for (const entry of entries) {
        const raw = await storageB.read(ns, entry.key);
        if (!raw) continue;
        const rawStr = new TextDecoder().decode(raw);
        for (const secret of sensitiveStrings) {
          expect(rawStr).not.toContain(secret);
        }
      }
    }
  }, 30_000);
});
