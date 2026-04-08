/**
 * Gate Integration Test — Prompt Injection Defense
 *
 * End-to-end test simulating a prompt injection scenario where a compromised
 * agent attempts operations that SHOULD be blocked by the Principal Policy gate.
 *
 * Scenario:
 *   1. Agent tries state_export → blocked (Tier 1 always-approve, auto-deny)
 *   2. Agent tries reading an unfamiliar namespace → blocked (Tier 2 anomaly)
 *   3. Agent does normal state_read on a known namespace → allowed (Tier 3)
 *   4. Agent floods identity_sign → blocked after exceeding frequency limit
 *   5. Agent tries reputation_import → blocked (Tier 1)
 *   6. Agent tries new counterparty interaction → blocked (Tier 2)
 *
 * Uses CallbackApprovalChannel to simulate auto-deny behavior without
 * involving stderr prompts.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { CallbackApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import { DEFAULT_POLICY, extractOperationName } from "../../src/principal-policy/loader.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import type { PrincipalPolicy, ApprovalRequest, ApprovalResponse } from "../../src/principal-policy/types.js";

describe("Gate Integration — Prompt Injection Defense", () => {
  let gate: ApprovalGate;
  let baseline: BaselineTracker;
  let auditLog: AuditLog;
  let approvalDecisions: Array<{ request: ApprovalRequest; response: ApprovalResponse }>;

  beforeEach(async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    auditLog = new AuditLog(storage, masterKey);
    baseline = new BaselineTracker(storage, masterKey);

    // Track all approval requests for assertions
    approvalDecisions = [];

    // Auto-deny channel (simulates real behavior: no human present)
    const channel = new CallbackApprovalChannel(async (request) => {
      const response: ApprovalResponse = {
        decision: "deny",
        decided_at: new Date().toISOString(),
        decided_by: "auto-deny",
      };
      approvalDecisions.push({ request, response });
      return response;
    });

    gate = new ApprovalGate(DEFAULT_POLICY, baseline, channel, auditLog);
  });

  // ── Tier 1: High-risk operations always blocked ──────────────────────

  it("blocks state_export (Tier 1) even with valid args", async () => {
    const result = await gate.evaluate("state_export", {
      format: "full",
    });

    expect(result.allowed).toBe(false);
    expect(result.tier).toBe(1);
    expect(result.approval_required).toBe(true);
    expect(approvalDecisions).toHaveLength(1);
    expect(approvalDecisions[0]!.request.operation).toBe("state_export");
  });

  it("blocks reputation_import (Tier 1)", async () => {
    const result = await gate.evaluate("reputation_import", {
      bundle: "fake-bundle-data",
    });

    expect(result.allowed).toBe(false);
    expect(result.tier).toBe(1);
  });

  it("blocks identity_rotate (Tier 1)", async () => {
    const result = await gate.evaluate("identity_rotate", {
      identity_id: "id-1",
    });

    expect(result.allowed).toBe(false);
    expect(result.tier).toBe(1);
  });

  it("blocks bootstrap_provide_guarantee (Tier 1)", async () => {
    const result = await gate.evaluate("bootstrap_provide_guarantee", {
      principal_identity_id: "id-1",
      agent_identity_id: "id-2",
      scope: "all",
      duration_seconds: 3600,
    });

    expect(result.allowed).toBe(false);
    expect(result.tier).toBe(1);
  });

  // ── Tier 2: Behavioral anomaly detection ──────────────────────────────

  it("blocks access to unfamiliar namespace (Tier 2 new_namespace_access)", async () => {
    // First establish a baseline by doing some known-namespace reads
    await gate.evaluate("state_read", {
      namespace: "known-ns",
      key: "data-1",
    });
    await gate.evaluate("state_read", {
      namespace: "known-ns",
      key: "data-2",
    });

    // Now the agent tries a namespace it has never accessed
    const result = await gate.evaluate("state_read", {
      namespace: "secret-credentials",
      key: "api-keys",
    });

    expect(result.allowed).toBe(false);
    expect(result.tier).toBe(2);
    // The approval request should mention the new namespace
    const lastApproval = approvalDecisions[approvalDecisions.length - 1]!;
    expect(lastApproval.request.reason).toContain("secret-credentials");
  });

  it("blocks interaction with new counterparty (Tier 2 new_counterparty)", async () => {
    // Establish a known counterparty
    await gate.evaluate("reputation_record", {
      interaction_id: "i-1",
      counterparty_did: "did:known:alice",
      outcome: { type: "service", result: "completed" },
    });

    // Now the injected prompt tries a new counterparty
    const result = await gate.evaluate("reputation_record", {
      interaction_id: "i-2",
      counterparty_did: "did:attacker:eve",
      outcome: { type: "service", result: "completed" },
    });

    expect(result.allowed).toBe(false);
    expect(result.tier).toBe(2);
    const lastApproval = approvalDecisions[approvalDecisions.length - 1]!;
    expect(lastApproval.request.reason).toContain("did:attacker:eve");
  });

  it("blocks signing frequency spike (Tier 2 max_signs_per_minute)", async () => {
    // Flood identity_sign to exceed the default limit (10/min)
    const results = [];
    for (let i = 0; i < 12; i++) {
      results.push(
        await gate.evaluate("identity_sign", {
          payload: `message-${i}`,
        })
      );
    }

    // The first calls should be allowed, but once the limit is exceeded...
    const blocked = results.filter((r) => !r.allowed);
    expect(blocked.length).toBeGreaterThan(0);

    const blockedResult = blocked[0]!;
    expect(blockedResult.tier).toBe(2);
  });

  // ── Tier 3: Normal operations allowed ──────────────────────────────────

  it("allows normal state_read on known namespace (Tier 3)", async () => {
    // Establish the namespace first
    await gate.evaluate("state_read", {
      namespace: "my-data",
      key: "key-1",
    });

    // Subsequent reads on the same namespace should be allowed
    const result = await gate.evaluate("state_read", {
      namespace: "my-data",
      key: "key-2",
    });

    expect(result.allowed).toBe(true);
    expect(result.tier).toBe(3);
    expect(result.approval_required).toBe(false);
  });

  it("allows reputation_query (Tier 3, read-only)", async () => {
    const result = await gate.evaluate("reputation_query", {
      context: "general",
    });

    expect(result.allowed).toBe(true);
    expect(result.tier).toBe(3);
  });

  it("allows monitor_health (Tier 3)", async () => {
    const result = await gate.evaluate("monitor_health", {});

    expect(result.allowed).toBe(true);
    expect(result.tier).toBe(3);
  });

  it("allows Phase 3A tools as Tier 3 (shr_generate, handshake_initiate)", async () => {
    const shrResult = await gate.evaluate("shr_generate", {});
    expect(shrResult.allowed).toBe(true);
    expect(shrResult.tier).toBe(3);

    const hsResult = await gate.evaluate("handshake_initiate", {});
    expect(hsResult.allowed).toBe(true);
    expect(hsResult.tier).toBe(3);
  });

  it("allows reputation_query_weighted as Tier 3", async () => {
    const result = await gate.evaluate("reputation_query_weighted", {
      metric: "fulfillment_rate",
    });

    expect(result.allowed).toBe(true);
    expect(result.tier).toBe(3);
  });

  // ── Combined attack scenario ──────────────────────────────────────────

  it("simulates a full prompt injection attack sequence", async () => {
    // Step 1: Attacker's first goal — exfiltrate all state
    const exportResult = await gate.evaluate("state_export", {
      format: "full",
    });
    expect(exportResult.allowed).toBe(false);
    // Denial message is generic — doesn't reveal policy
    expect(exportResult.reason).toBeDefined();

    // Step 2: Attacker pivots — tries to read a namespace they haven't accessed before
    const credResult = await gate.evaluate("state_read", {
      namespace: "stolen-credentials",
      key: "api-tokens",
    });
    expect(credResult.allowed).toBe(false);

    // Step 3: Attacker tries to import fake reputation
    const importResult = await gate.evaluate("reputation_import", {
      bundle: "ZmFrZS1idW5kbGU",
    });
    expect(importResult.allowed).toBe(false);

    // Step 4: Attacker tries normal operation to avoid detection
    // (this is allowed — the gate doesn't block legitimate operations)
    const normalResult = await gate.evaluate("identity_list", {});
    expect(normalResult.allowed).toBe(true);

    // Verify all blocked operations were audit-logged
    const log = await auditLog.query({ limit: 50 });
    const gateEntries = log.entries.filter((e) =>
      e.operation.startsWith("gate_")
    );
    expect(gateEntries.length).toBeGreaterThanOrEqual(4);

    // Verify denial entries exist for the blocked operations
    const denyEntries = gateEntries.filter((e) =>
      e.operation.startsWith("gate_deny")
    );
    expect(denyEntries.length).toBeGreaterThanOrEqual(3);
  });

  // ── Approval flow (when human is present) ──────────────────────────────

  it("allows Tier 1 operation when human explicitly approves", async () => {
    // Replace channel with one that approves
    const approveChannel = new CallbackApprovalChannel(async () => ({
      decision: "approve",
      decided_at: new Date().toISOString(),
      decided_by: "human",
    }));

    const approveGate = new ApprovalGate(
      DEFAULT_POLICY,
      baseline,
      approveChannel,
      auditLog
    );

    const result = await approveGate.evaluate("state_export", {
      format: "full",
    });

    expect(result.allowed).toBe(true);
    expect(result.tier).toBe(1);
    expect(result.approval_required).toBe(true);
  });
});
