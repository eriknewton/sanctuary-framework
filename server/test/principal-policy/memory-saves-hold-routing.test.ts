/** Quota holds preserve proof authority, argument binding and approval-only anomaly commits. */
import { afterEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ApprovalGate, OWN_SCOPE_SAVE_MAX_PER_WINDOW, OWN_SCOPE_SAVE_WINDOW_MS } from "../../src/principal-policy/gate.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { ApprovalProofStore, deriveTargetResource, fingerprintIdentityId, normalizedArgsHash } from "../../src/agent-native/safety-base.js";
import type { ApprovalRequest } from "../../src/principal-policy/types.js";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(directories.splice(0).map(directory => rm(directory, { recursive: true, force: true })));
});

async function rig(kind: "reached" | "unavailable", decision: "approve" | "deny" = "deny") {
  const storage = new MemoryStorage();
  const key = generateRandomKey();
  const baseline = new BaselineTracker(storage, key);
  const audit = new AuditLog(storage, key);
  const proofs = new ApprovalProofStore();
  const session = { identity_id: "hold-session", requester_identity_fingerprint: fingerprintIdentityId("hold-session") };
  const seen: ApprovalRequest[] = [];
  let directory: string | undefined;
  const start = Date.now();
  if (kind === "reached") {
    directory = await mkdtemp(join(tmpdir(), "save-hold-routing-"));
    directories.push(directory);
    await writeFile(join(directory, "own-scope-save-quota.json"), JSON.stringify([
      [createHash("sha256").update("agent:unknown").digest("hex"), start, OWN_SCOPE_SAVE_MAX_PER_WINDOW, OWN_SCOPE_SAVE_MAX_PER_WINDOW],
    ]));
  }
  const gate = new ApprovalGate(
    { ...DEFAULT_POLICY, tier2_anomaly: { ...DEFAULT_POLICY.tier2_anomaly, first_session_policy: "log" } },
    baseline,
    { requestApproval: async request => {
      seen.push(request);
      return { decision, decided_by: "human", decided_at: new Date().toISOString() };
    } },
    audit, undefined, undefined, undefined,
    { ownScopeSaveStateDirectory: directory, approvalProofStore: proofs, currentSessionBinding: () => session },
  );
  return { gate, baseline, audit, proofs, session, seen, start };
}

const args = { namespace: "own-hold", key: "key", value: "body" };
const bytes = Buffer.byteLength(args.value);

describe.each(["reached", "unavailable"] as const)("memory save %s hold routing", kind => {
  it.each(["approve", "deny"] as const)("binds arguments and commits the observed namespace only on %s", async decision => {
    const r = await rig(kind, decision);
    expect(r.baseline.isNewNamespace(args.namespace)).toBe(true);
    const result = await r.gate.evaluate("state_write", args, undefined, undefined, "sanctuary_remember");
    expect(result).toMatchObject({ allowed: decision === "approve", tier: 2, approval_required: true });
    expect(r.seen).toHaveLength(1);
    expect(r.seen[0]).toMatchObject({
      reason: `memory save quota ${kind}`,
      args_binding: normalizedArgsHash(args),
      context: kind === "reached"
        ? { count: OWN_SCOPE_SAVE_MAX_PER_WINDOW, bytes: OWN_SCOPE_SAVE_MAX_PER_WINDOW, window_ms: OWN_SCOPE_SAVE_WINDOW_MS }
        : { cause_class: "storage_unconfigured" },
    });
    expect(r.seen[0].context).toEqual(kind === "reached"
      ? { count: OWN_SCOPE_SAVE_MAX_PER_WINDOW, bytes: OWN_SCOPE_SAVE_MAX_PER_WINDOW, window_ms: OWN_SCOPE_SAVE_WINDOW_MS }
      : { cause_class: "storage_unconfigured" });
    expect(r.baseline.isNewNamespace(args.namespace)).toBe(decision !== "approve");
    const { entries } = await r.audit.query({});
    expect(entries.filter(row => row.operation.startsWith("memory_save_anomaly_observed:"))).toEqual([]);
    expect(entries.filter(row => row.operation === `memory_save_quota_${kind}`)).toMatchObject([{
      identity_id: "agent:unknown", result: "success",
      details: kind === "reached"
        ? { count: OWN_SCOPE_SAVE_MAX_PER_WINDOW, bytes: OWN_SCOPE_SAVE_MAX_PER_WINDOW, requested_bytes: bytes, window_start: r.start, window_ms: OWN_SCOPE_SAVE_WINDOW_MS }
        : { cause_class: "storage_unconfigured" },
    }]);
  });

  it("verifies a Tier 2 proof once without a second hold or an observation commit", async () => {
    const r = await rig(kind);
    const record = r.proofs.createApproved({
      tool_name: "state_write", normalized_args_hash: normalizedArgsHash(args),
      requester_identity_fingerprint: r.session.requester_identity_fingerprint,
      target_resource: deriveTargetResource("state_write", args), risk_tier: 2,
      expires_at: new Date(Date.now() + OWN_SCOPE_SAVE_WINDOW_MS).toISOString(),
      nonce: "hold-retry", audit_id: "hold-audit",
    });
    const retry = () => r.gate.evaluate("state_write", args, { approval_ref: record.approval_ref }, undefined, "sanctuary_remember");
    expect(await retry()).toMatchObject({ allowed: true, tier: 2, approval_required: true });
    expect(record.consumed).toBe(true);
    expect(await retry()).toMatchObject({ allowed: false, tier: 2 });
    expect(r.seen).toEqual([]);
    expect(r.baseline.isNewNamespace(args.namespace)).toBe(true);
    const { entries } = await r.audit.query({});
    expect(entries.filter(row => row.operation.startsWith("memory_save_anomaly_observed:"))).toEqual([]);
    expect(entries.filter(row => row.operation === `memory_save_quota_${kind}`)).toHaveLength(2);
  });
});
