/**
 * Z-HNY-01 bounded tool-call trap correlation buffer regression suite.
 */

import { describe, expect, it } from "vitest";

import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { ToolCallTrapRuntime } from "../../src/honeypot/tool-call-trap-runtime.js";
import {
  FOLLOW_UP_WINDOW_MS,
  MAX_ACTIVATIONS_PER_CALLER_PER_TRAP,
  MAX_FOLLOW_UP_TOOL_CALLS_PER_ACTIVATION,
  MAX_RETAINED_ACTIVATIONS_PER_TRAP,
} from "../../src/honeypot/tool-call-trap-runtime.js";
import { TrapRegistry } from "../../src/honeypot/trap-registry.js";
import { HONEYPOT_AUDIT_OPS, type TrapSpec } from "../../src/honeypot/types.js";
import { SentinelFindingStore } from "../../src/sentinel/sentinel-finding-store.js";
import { MemoryStorage } from "../../src/storage/memory.js";

const FORTRESS = "fortress_hny01";
const OPERATOR = "operator_hny01";
const TRAP_ID = "tool-trap-hny01";
const FAKE_TOOL = "admin_password_reader";
const START_MS = Date.parse("2026-08-09T10:00:00.000Z");
const EXTRA_INVOCATIONS = 7;
const ONE_MS_AFTER_WINDOW = FOLLOW_UP_WINDOW_MS + 1;
const QUERY_LIMIT = 10_000;

interface Rig {
  auditLog: AuditLog;
  findingStore: SentinelFindingStore;
  registry: TrapRegistry;
  runtime: ToolCallTrapRuntime;
}

async function makeRig(opts: { now: () => Date }): Promise<Rig> {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const findingStore = new SentinelFindingStore({
    storage,
    masterKey,
    fortressId: FORTRESS,
  });
  const registry = new TrapRegistry();
  const runtime = new ToolCallTrapRuntime({
    registry,
    findingStore,
    auditLog,
    operatorId: OPERATOR,
    fortressId: FORTRESS,
    now: opts.now,
  });
  registry.deploy(mkToolSpec());
  return { auditLog, findingStore, registry, runtime };
}

function mkToolSpec(overrides: Partial<TrapSpec> = {}): TrapSpec {
  return {
    trap_id: overrides.trap_id ?? TRAP_ID,
    trap_class: "tool_call",
    trigger: overrides.trigger ?? {
      kind: "tool_call",
      fake_tool_name: FAKE_TOOL,
      fake_tool_description: "Read the administrative password.",
      fake_tool_schema: {
        type: "object",
        properties: { reason: { type: "string" } },
      },
      catalog_visibility: "all_wrapped_agents",
      fake_response: "TRAP_ONLY_FAKE_PASSWORD_DO_NOT_USE",
    },
    finding_severity: overrides.finding_severity ?? "alert",
    english_text:
      overrides.english_text ??
      "Deploy a fake admin_password_reader tool visible to all agents.",
    explanation_paragraph: overrides.explanation_paragraph ?? "test fixture",
    compiled_at: overrides.compiled_at ?? new Date(START_MS).toISOString(),
  };
}

function countFollowUpAuditEmissions(auditLog: AuditLog): () => number {
  let count = 0;
  const originalAppend = auditLog.append.bind(auditLog);
  auditLog.append = ((...args: Parameters<AuditLog["append"]>) => {
    if (args[1] === HONEYPOT_AUDIT_OPS.FOLLOW_UP_CORRELATED) count += 1;
    return originalAppend(...args);
  }) as AuditLog["append"];
  return () => count;
}

describe("Z-HNY-01 tool-call trap correlation bounds", () => {
  it("bounds retained activations and follow-up audit work under adversarial growth", async () => {
    let nowMs = START_MS;
    const rig = await makeRig({ now: () => new Date(nowMs) });
    const followUpAuditCount = countFollowUpAuditEmissions(rig.auditLog);

    const perCallerInvocations =
      MAX_ACTIVATIONS_PER_CALLER_PER_TRAP + EXTRA_INVOCATIONS;
    for (let i = 0; i < perCallerInvocations; i += 1) {
      await rig.runtime.invokeIfTrap(FAKE_TOOL, { probe: i }, "agent:steady");
    }

    let stats = rig.runtime.stats()[0]!;
    expect(stats.activations.length).toBeLessThanOrEqual(
      MAX_RETAINED_ACTIVATIONS_PER_TRAP,
    );
    expect(
      stats.activations.filter((a) => a.caller_identity === "agent:steady").length,
    ).toBeLessThanOrEqual(MAX_ACTIVATIONS_PER_CALLER_PER_TRAP);

    const trapCapInvocations =
      MAX_RETAINED_ACTIVATIONS_PER_TRAP + EXTRA_INVOCATIONS;
    for (let i = 0; i < trapCapInvocations; i += 1) {
      await rig.runtime.invokeIfTrap(FAKE_TOOL, { probe: i }, `agent:burst-${i}`);
    }

    stats = rig.runtime.stats()[0]!;
    expect(stats.activations.length).toBeLessThanOrEqual(
      MAX_RETAINED_ACTIVATIONS_PER_TRAP,
    );

    const followUpRig = await makeRig({ now: () => new Date(nowMs) });
    const followUpAuditCountForRig = countFollowUpAuditEmissions(
      followUpRig.auditLog,
    );
    for (let i = 0; i < perCallerInvocations; i += 1) {
      await followUpRig.runtime.invokeIfTrap(
        FAKE_TOOL,
        { probe: i },
        "agent:steady",
      );
    }

    const retainedActivationCount = followUpRig.runtime.stats()[0]!.activations.length;
    const followUpCalls = MAX_FOLLOW_UP_TOOL_CALLS_PER_ACTIVATION + EXTRA_INVOCATIONS;
    for (let i = 0; i < followUpCalls; i += 1) {
      followUpRig.runtime.recordToolCall(
        "file_read",
        { path: `/tmp/${i}` },
        "agent:steady",
      );
    }

    const followUpStats = followUpRig.runtime.stats()[0]!;
    for (const activation of followUpStats.activations) {
      expect(activation.follow_up_tool_calls.length).toBeLessThanOrEqual(
        MAX_FOLLOW_UP_TOOL_CALLS_PER_ACTIVATION,
      );
    }
    expect(followUpAuditCountForRig()).toBeLessThanOrEqual(
      retainedActivationCount * MAX_FOLLOW_UP_TOOL_CALLS_PER_ACTIVATION,
    );
    expect(followUpAuditCountForRig()).toBeLessThan(
      perCallerInvocations * followUpCalls,
    );
    expect(followUpAuditCount()).toBe(0);
  });

  it("keeps durable findings and trigger audits after retained activations are evicted", async () => {
    let nowMs = START_MS;
    const rig = await makeRig({ now: () => new Date(nowMs) });
    let triggerAuditCount = 0;
    const originalAppend = rig.auditLog.append.bind(rig.auditLog);
    rig.auditLog.append = ((...args: Parameters<AuditLog["append"]>) => {
      if (args[1] === HONEYPOT_AUDIT_OPS.TRIGGERED) triggerAuditCount += 1;
      return originalAppend(...args);
    }) as AuditLog["append"];

    const invocationCount = MAX_ACTIVATIONS_PER_CALLER_PER_TRAP + EXTRA_INVOCATIONS;
    for (let i = 0; i < invocationCount; i += 1) {
      await rig.runtime.invokeIfTrap(FAKE_TOOL, { probe: i }, "agent:steady");
    }
    expect(rig.runtime.stats()[0]!.activations.length).toBeLessThan(
      invocationCount,
    );

    nowMs += ONE_MS_AFTER_WINDOW;
    expect(rig.runtime.stats()[0]!.activations).toEqual([]);

    const findings = await rig.findingStore.listFindings({ limit: QUERY_LIMIT });
    expect(findings.length).toBe(invocationCount);
    expect(triggerAuditCount).toBe(invocationCount);
  });

  it("removes expired activations before later real tool calls", async () => {
    let nowMs = START_MS;
    const rig = await makeRig({ now: () => new Date(nowMs) });
    const followUpAuditCount = countFollowUpAuditEmissions(rig.auditLog);

    await rig.runtime.invokeIfTrap(FAKE_TOOL, { probe: "a" }, "agent:steady");
    await rig.runtime.invokeIfTrap(FAKE_TOOL, { probe: "b" }, "agent:steady");
    expect(rig.runtime.stats()[0]!.activations.length).toBe(2);

    nowMs += ONE_MS_AFTER_WINDOW;
    rig.runtime.recordToolCall("file_read", { path: "/etc/passwd" }, "agent:steady");

    expect(rig.runtime.stats()[0]!.activations).toEqual([]);
    expect(followUpAuditCount()).toBe(0);
  });

  it("does not throw or retain when the finding store fails (pre-gate fail-safe)", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const failingFindingStore = {
      saveFinding: async (): Promise<string> => {
        throw new Error("finding store unavailable");
      },
    } as unknown as SentinelFindingStore;
    const registry = new TrapRegistry();
    const runtime = new ToolCallTrapRuntime({
      registry,
      findingStore: failingFindingStore,
      auditLog,
      operatorId: OPERATOR,
      fortressId: FORTRESS,
      now: () => new Date(START_MS),
    });
    registry.deploy(mkToolSpec());

    // invokeIfTrap runs pre-gate and uncaught in the router; a persistence failure
    // must not throw (no internal error leaks to the agent) and must still return
    // the operator-configured fake response so the honeypot stays stealthy.
    const result = await runtime.invokeIfTrap(FAKE_TOOL, { probe: "x" }, "agent:evil");
    expect(result).toEqual({
      handled: true,
      response: "TRAP_ONLY_FAKE_PASSWORD_DO_NOT_USE",
    });
    // The unpersisted activation must NOT be retained (retained implies persisted).
    expect(runtime.stats()[0]!.activations).toEqual([]);
  });
});
