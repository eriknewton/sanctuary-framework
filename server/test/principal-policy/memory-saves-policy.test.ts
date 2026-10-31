/** Own-memory classification honors explicit policy, exact tool pairs and bounded admission. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync } from "node:fs";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ApprovalGate, OWN_SCOPE_MEMORY_SAVES, OWN_SCOPE_SAVE_WINDOW_MS, OWN_SCOPE_SAVE_MAX_PER_WINDOW, OWN_SCOPE_SAVE_MAX_BYTES_PER_WINDOW, OWN_SCOPE_SAVE_MAX_TRACKED_CALLERS } from "../../src/principal-policy/gate.js";
import { DEFAULT_POLICY, parsePolicy, generateDefaultPolicyYaml, detectPrincipalPolicyDowngrades, loadPrincipalPolicy, MalformedPrincipalPolicyError } from "../../src/principal-policy/loader.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { CallbackApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { InjectionDetector } from "../../src/security/injection-detector.js";

function policy(extra: Record<string, unknown> = {}) {
  return parsePolicy(JSON.stringify({ ...DEFAULT_POLICY, ...extra }));
}
const quotaDirectories: string[] = [];
function rig(p = policy(), spike = false, detector?: InjectionDetector) {
  let caller = "hermes:fortress-0123456789abcdef";
  let requests = 0;
  const logs: Array<Record<string, any>> = [];
  const known = new Set<string>();
  const baseline = {
    recordToolCall() {}, isFirstSession: false,
    isNewNamespace: (ns: string) => !known.has(ns),
    recordNamespaceAccess: (ns: string) => { known.add(ns); },
    getProfile: () => ({ known_namespaces: [] }),
    getCallRate: () => spike ? DEFAULT_POLICY.tier2_anomaly.frequency_spike_multiplier + 1 : 0,
    getAverageCallRate: () => spike ? 1 : 0,
  } as unknown as BaselineTracker;
  let retainLogs = true;
  const audit = { appendCritical: async (entry: Record<string, any>) => { if (retainLogs) logs.push(entry); }, append: async () => {} } as unknown as AuditLog;
  const channel = new CallbackApprovalChannel(async () => {
    requests++;
    return { decision: "deny", decided_by: "human", decided_at: new Date().toISOString() };
  });
  const quotaDirectory = mkdtempSync(join(tmpdir(), "save-quota-"));
  quotaDirectories.push(quotaDirectory);
  const gate = new ApprovalGate(p, baseline, channel, audit, detector, undefined, undefined, { currentAgentId: () => caller, ownScopeSaveStateDirectory: quotaDirectory });
  return { gate, logs, known, requests: () => requests, setCaller: (next: string) => { caller = next; }, stopRetainingLogs: () => { retainLogs = false; } };
}
afterEach(async () => {
  vi.useRealTimers();
  for (const dir of quotaDirectories.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe("memory save policy", () => {
  it("normalizes legacy Tier 1 inserts to never and explicit always to Tier 1", () => {
    const legacy = policy({ memory_save_approval: undefined, tier1_always_approve: ["memory_insert"] });
    expect(legacy.memory_save_approval).toBe("never");
    expect(legacy.tier1_always_approve).not.toContain("memory_insert");
    expect(legacy.tier3_always_allow).toContain("memory_insert");
    const always = policy({ memory_save_approval: "always", tier1_always_approve: [], tier3_always_allow: ["memory_insert"] });
    expect(always.tier1_always_approve).toContain("memory_insert");
    expect(always.tier3_always_allow).not.toContain("memory_insert");
  });
  it.each(["sometimes", "", "true", "null", "[]", "{}"])("refuses malformed memory_save_approval %s at load", async (value) => {
    const dir = await mkdtemp(join(tmpdir(), "save-policy-"));
    try {
      await writeFile(join(dir, "principal-policy.yaml"), generateDefaultPolicyYaml().replace(/^memory_save_approval:.*$/m, `memory_save_approval: ${value}`), { mode: 0o600 }); // Owner-only policy fixture.
      await expect(loadPrincipalPolicy(dir)).rejects.toBeInstanceOf(MalformedPrincipalPolicyError);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
  it.each(["never", undefined])("reports explicit approval relaxation to %s", (value) => {
    expect(detectPrincipalPolicyDowngrades(policy({ memory_save_approval: "always" }), policy({ memory_save_approval: value })))
      .toContainEqual(expect.objectContaining({ field: "memory_save_approval", reason: "memory_save_approval_relaxed" }));
  });
  it("matches only the full closed set of invoked and classified pairs", async () => {
    expect(Object.isFrozen(OWN_SCOPE_MEMORY_SAVES)).toBe(true);
    expect(OWN_SCOPE_MEMORY_SAVES).toEqual({ memory_insert: "memory_insert", sanctuary_remember: "state_write" });
    const { gate, requests } = rig();
    expect((await gate.evaluate("state_write", { namespace: "raw", value: "x" }, undefined, undefined, "state_write")).tier).toBe(2);
    expect((await gate.evaluate("state_read", { namespace: "wrong", value: "x" }, undefined, undefined, "sanctuary_remember")).tier).toBe(2);
    expect((await gate.evaluate("state_write", { namespace: "own", value: "x" }, undefined, undefined, "sanctuary_remember")).allowed).toBe(true);
    expect(requests()).toBe(2);
  });
  it("observes spikes without a hold and commits new own namespaces", async () => {
    const { gate, logs, known, requests } = rig(policy(), true);
    await gate.evaluate("state_write", { namespace: "own", value: "private body" }, undefined, undefined, "sanctuary_remember");
    await gate.evaluate("state_write", { namespace: "own", value: "private body" }, undefined, undefined, "sanctuary_remember");
    expect(known.has("own")).toBe(true);
    expect(requests()).toBe(0);
    expect(logs.filter(e => e.operation === "memory_save_anomaly_observed:state_write")).toEqual([
      expect.objectContaining({ layer: "l2", identity_id: "system", details: { reason_class: "new_namespace_access", tier: 3 } }),
      expect.objectContaining({ layer: "l2", identity_id: "system", details: { reason_class: "frequency_spike", tier: 3 } }),
    ]);
    expect(JSON.stringify(logs)).not.toContain("private body");
  });
  // fail-before-exempt: W4 exact-pair broadening and W6 table expansion pin the unchanged holds.
  it("honors state_write Tier 1 and always remember baseline gating", async () => {
    for (const [p, tier] of [[policy({ tier1_always_approve: ["state_write"] }), 1], [policy({ memory_save_approval: "always" }), 2]] as const) {
      const { gate, requests } = rig(p);
      expect((await gate.evaluate("state_write", { namespace: "own", value: "x" }, undefined, undefined, "sanctuary_remember")).tier).toBe(tier);
      expect(requests()).toBe(1);
    }
  });
  // fail-before-exempt: moving the own-save branch above injection escalation turns this red.
  it("still holds an injection escalation before own-memory admission", async () => {
    const detector = new InjectionDetector();
    vi.spyOn(detector, "scan").mockReturnValue({ flagged: true, confidence: 1, recommendation: "escalate", signals: [] });
    const { gate, requests } = rig(policy(), false, detector);
    expect((await gate.evaluate("state_write", { value: "injection" }, undefined, undefined, "sanctuary_remember")).tier).toBe(1);
    expect(requests()).toBe(1);
    expect(gate.getOwnScopeSaveQuotaDiagnostics().trackedCallers).toBe(0);
  });
});

describe("own-memory admission bounds", () => {
  it("holds the 121st save and keeps constant work through adversarial caller waves", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-30T00:00:00Z"));
    const r = rig();
    r.stopRetainingLogs();
    // Ten thousand attempts from one caller, then ten attempts per thousand callers.
    const attempts = 10_000;
    const callers = 1_000;
    const maxMapOperations = 5; // Admission map operations; bounded file validation/pruning is measured separately.
    for (let n = 0; n < attempts; n++) {
      const result = await r.gate.evaluate("memory_insert", { text_bytes: 1 }, undefined, undefined, "memory_insert");
      expect(result.tier).toBe(n < OWN_SCOPE_SAVE_MAX_PER_WINDOW ? 3 : 2);
      expect(r.gate.getOwnScopeSaveQuotaDiagnostics().lastWork).toBeLessThanOrEqual(maxMapOperations);
    }
    expect(r.requests()).toBe(attempts - OWN_SCOPE_SAVE_MAX_PER_WINDOW);
    for (let n = 0; n < attempts; n++) {
      r.setCaller(`caller-${Math.floor(n / (attempts / callers))}`);
      await r.gate.evaluate("memory_insert", { text_bytes: 1 }, undefined, undefined, "memory_insert");
      expect(r.gate.getOwnScopeSaveQuotaDiagnostics().trackedCallers).toBeLessThanOrEqual(OWN_SCOPE_SAVE_MAX_TRACKED_CALLERS);
      expect(r.gate.getOwnScopeSaveQuotaDiagnostics().lastWork).toBeLessThanOrEqual(maxMapOperations);
    }
    expect(r.gate.getOwnScopeSaveQuotaDiagnostics().trackedCallers).toBe(OWN_SCOPE_SAVE_MAX_TRACKED_CALLERS);
  }, 180_000); // Twenty thousand durable file reservations, including fsync.
  it("counts UTF-8 bytes and resets the window without retaining passage bodies", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-30T00:00:00Z"));
    const { gate, logs, requests } = rig();
    const value = "é".repeat(OWN_SCOPE_SAVE_MAX_BYTES_PER_WINDOW / Buffer.byteLength("é"));
    expect((await gate.evaluate("state_write", { value }, undefined, undefined, "sanctuary_remember")).tier).toBe(3);
    expect((await gate.evaluate("state_write", { value: "x" }, undefined, undefined, "sanctuary_remember")).tier).toBe(2);
    expect(requests()).toBe(1);
    expect(logs.filter(e => e.operation === "memory_save_quota_reached")).toEqual([
      expect.objectContaining({ identity_id: "agent:hermes:fortress-0123456789abcdef", details: { count: 1, bytes: OWN_SCOPE_SAVE_MAX_BYTES_PER_WINDOW, requested_bytes: 1, window_start: Date.now(), window_ms: OWN_SCOPE_SAVE_WINDOW_MS } }),
    ]);
    expect(JSON.stringify(logs)).not.toContain("é");
    vi.setSystemTime(Date.now() + OWN_SCOPE_SAVE_WINDOW_MS);
    expect((await gate.evaluate("state_write", { value: "x" }, undefined, undefined, "sanctuary_remember")).tier).toBe(3);
  });
});

// fail-before-exempt: W6 pins the full save table while these existing protected verbs stay Tier 1.
it("keeps every plaintext-crossing memory verb and vault export at Tier 1", async () => {
  const { gate, requests } = rig();
  const verbs = ["sdw_export", "memory_ingest", "memory_emit", "memory_transcode", "memory_transcode_restore"];
  for (const verb of verbs) {
    expect((await gate.evaluate(verb, {}, undefined, undefined, verb)).tier, verb).toBe(1);
  }
  expect(requests()).toBe(verbs.length);
});
