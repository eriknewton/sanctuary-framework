import { registerFixture } from "../../registry.js";
import { ApprovalGate } from "../../../../server/src/principal-policy/gate.js";
import { BaselineTracker } from "../../../../server/src/principal-policy/baseline.js";
import { AutoApproveChannel, CallbackApprovalChannel } from "../../../../server/src/principal-policy/approval-channel.js";
import { DEFAULT_POLICY } from "../../../../server/src/principal-policy/loader.js";
import { AuditLog } from "../../../../server/src/l2-operational/audit-log.js";
import { generateRandomKey } from "../../../../server/src/core/random.js";
import { MemoryStorage } from "../../../../server/src/storage/memory.js";

// Recon: canonical custody gate is ApprovalGate.evaluate() with identity_sign
// under DEFAULT_POLICY, mirrored by approval-gate.test.ts. Maps to row 2.
const CLAIM_ID = "2";
const CLAIM_LABEL = "Approval gating (Tier 1 / Tier 2 / Tier 3 policy)";

function makeGate(decision: "approve" | "deny"): ApprovalGate {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const baseline = new BaselineTracker(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const channel =
    decision === "approve"
      ? new AutoApproveChannel()
      : new CallbackApprovalChannel(async () => ({
          decision: "deny",
          decided_at: new Date().toISOString(),
          decided_by: "human",
        }));
  return new ApprovalGate(DEFAULT_POLICY, baseline, channel, auditLog);
}

async function evaluateCustodyGate(decision: "approve" | "deny") {
  const gate = makeGate(decision);
  return gate.evaluate("identity_sign", { payload: "synthetic-custody-key" });
}

registerFixture(CLAIM_ID, CLAIM_LABEL, "custody-key-gate: gate-open allows", async () => {
  const start = performance.now();
  const result = await evaluateCustodyGate("approve");
  return {
    passed: result.allowed === true && result.tier === 1 && result.approval_required === true,
    durationMs: performance.now() - start,
  };
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "custody-key-gate: gate-closed denies", async () => {
  const start = performance.now();
  const result = await evaluateCustodyGate("deny");
  return {
    passed:
      result.allowed === false &&
      result.tier === 1 &&
      result.approval_response?.decision === "deny",
    durationMs: performance.now() - start,
  };
});

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "custody-key-gate: gate-toggle race produces deterministic outcome",
  async () => {
    const start = performance.now();
    let permit = false;
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const gate = new ApprovalGate(
      DEFAULT_POLICY,
      new BaselineTracker(storage, masterKey),
      new CallbackApprovalChannel(async () => ({
        decision: permit ? "approve" : "deny",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      })),
      new AuditLog(storage, masterKey),
    );
    const pending = gate.evaluate("identity_sign", { payload: "race-fixture" });
    permit = true;
    const result = await pending;
    return {
      passed: result.allowed === false && result.approval_response?.decision === "deny",
      message: "gate decision used the pre-toggle closed state",
      durationMs: performance.now() - start,
    };
  },
);
