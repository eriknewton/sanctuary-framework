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
  MAX_RETAINED_ARG_BYTES,
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
    const nowMs = START_MS;
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

  it("bounds retained BYTES and stats serialization at the FULL per-trap cap under attacker-sized args (RECHECK-HNY-01)", async () => {
    // The count caps alone do not stop a visible agent from making each retained
    // entry attacker-sized. Fill the whole per-trap retention cap (128), which
    // takes FOUR callers each at the per-caller cap (32) — a single caller only
    // reaches 32 and would hide the true ceiling. A ~2 MB blob retained across
    // 128 activations x (1 + 16 follow-ups) would serialize to ~4.5 GB pre-fix;
    // the byte bound keeps it to ~128 x 17 x ~1 KB.
    const rig = await makeRig({ now: () => new Date(START_MS) });
    // ADVERSARIAL content: a backslash-heavy blob. JSON.stringify escapes each
    // backslash, and the retained preview is a STRING that stats() re-serializes,
    // so those escapes DOUBLE again — the amplifier a naive byte-count ceiling
    // misses. Identical args every call make the true size deterministic so we
    // can assert arg_bytes EXACTLY (not just "large").
    const bigBlob = "\\".repeat(1_000_000);
    const invocationArgs = { blob: bigBlob };
    const followUpArgs = { blob: bigBlob };
    const expectedArgBytes = Buffer.byteLength(
      JSON.stringify(invocationArgs),
      "utf8",
    );
    const expectedFollowUpBytes = Buffer.byteLength(
      JSON.stringify(followUpArgs),
      "utf8",
    );
    const callerCount = 4; // 4 x 32 = 128 = MAX_RETAINED_ACTIVATIONS_PER_TRAP
    expect(callerCount * MAX_ACTIVATIONS_PER_CALLER_PER_TRAP).toBe(
      MAX_RETAINED_ACTIVATIONS_PER_TRAP,
    );
    for (let c = 0; c < callerCount; c += 1) {
      const caller = `agent:flood-${c}`;
      for (let i = 0; i < MAX_ACTIVATIONS_PER_CALLER_PER_TRAP + EXTRA_INVOCATIONS; i += 1) {
        await rig.runtime.invokeIfTrap(FAKE_TOOL, invocationArgs, caller);
      }
      // Follow-ups with attacker-sized args, correlated to this caller's
      // activations, must be bounded too.
      for (let i = 0; i < MAX_FOLLOW_UP_TOOL_CALLS_PER_ACTIVATION + EXTRA_INVOCATIONS; i += 1) {
        rig.runtime.recordToolCall("file_read", followUpArgs, caller);
      }
    }

    const stats = rig.runtime.stats();
    const activations = stats[0]!.activations;
    // The whole retained buffer is at the per-trap ceiling.
    expect(activations.length).toBe(MAX_RETAINED_ACTIVATIONS_PER_TRAP);

    // Whole serialized payload bounded by the honest formula (128 x 17 x ~1 KB
    // re-escaped preview ~= ~2.2 MB of previews + per-activation metadata ~=
    // ~2.9 MB total) even with adversarial escaping content, not by the
    // ~gigabytes of raw input. Assert < 4 MB: above the real ceiling, far below
    // anything the raw retention would produce (fails on pre-fix code).
    const serializedBytes = Buffer.byteLength(JSON.stringify(stats), "utf8");
    expect(serializedBytes).toBeLessThan(4_000_000);

    for (const activation of activations) {
      // Preview serialized size bounded even under re-escaping: <= ~2x the raw
      // cap (escaping) + U+FFFD + JSON field overhead.
      expect(
        Buffer.byteLength(JSON.stringify(activation.invocation_args), "utf8"),
      ).toBeLessThan(MAX_RETAINED_ARG_BYTES * 2 + 256);
      expect(activation.arg_truncated).toBe(true);
      // True size reported EXACTLY, not just "large".
      expect(activation.arg_bytes).toBe(expectedArgBytes);
      expect(activation.follow_up_tool_calls.length).toBe(
        MAX_FOLLOW_UP_TOOL_CALLS_PER_ACTIVATION,
      );
      for (const followUp of activation.follow_up_tool_calls) {
        expect(
          Buffer.byteLength(JSON.stringify(followUp.args), "utf8"),
        ).toBeLessThan(MAX_RETAINED_ARG_BYTES * 2 + 256);
        expect(followUp.args_truncated).toBe(true);
        expect(followUp.args_bytes).toBe(expectedFollowUpBytes);
      }
    }
  });

  it("caps the retained preview at MAX_RETAINED_ARG_BYTES on a BYTE boundary for multibyte args", async () => {
    // A char-boundary slice would let a multibyte-heavy arg retain up to ~4x the
    // byte cap. Drive an all-multibyte (4-byte UTF-8) blob and assert the
    // retained preview's true byte length never exceeds the constant.
    const rig = await makeRig({ now: () => new Date(START_MS) });
    const emoji = "\u{1F600}".repeat(600_000); // each code point = 4 UTF-8 bytes
    await rig.runtime.invokeIfTrap(FAKE_TOOL, { blob: emoji }, "agent:multibyte");
    const activation = rig.runtime.stats()[0]!.activations[0]!;
    expect(activation.arg_truncated).toBe(true);
    const preview = (activation.invocation_args as { _sanctuary_arg_preview: string })
      ._sanctuary_arg_preview;
    // Byte-boundary truncation caps the RAW slice at MAX; if it splits a 4-byte
    // sequence, decoding appends one U+FFFD (3 bytes), so the decoded preview is
    // at most MAX + 3 — never the ~4x a char-boundary slice would retain.
    expect(Buffer.byteLength(preview, "utf8")).toBeLessThanOrEqual(
      MAX_RETAINED_ARG_BYTES + 3,
    );
  });

  it("retains small args verbatim (byte bound does not damage normal fidelity)", async () => {
    const rig = await makeRig({ now: () => new Date(START_MS) });
    const smallArgs = { reason: "why do you want the admin password?" };
    await rig.runtime.invokeIfTrap(FAKE_TOOL, smallArgs, "agent:curious");
    const activation = rig.runtime.stats()[0]!.activations[0]!;
    expect(activation.invocation_args).toEqual(smallArgs);
    expect(activation.arg_truncated).toBe(false);
    expect(activation.arg_bytes).toBe(
      Buffer.byteLength(JSON.stringify(smallArgs), "utf8"),
    );
  });

  // This asserts a CORRECTNESS property: evicting an entry from the bounded
  // in-memory correlation buffer must not lose its durable finding/audit record
  // (retained-implies-persisted, and durability survives eviction). It is NOT an
  // endorsement of unbounded durable growth: the durable sentinel-finding store
  // has no per-caller/size quota, a separate PRE-EXISTING concern on a shared
  // subsystem (all sentinels) that this PR does not change — a naive quota there
  // could silently drop real security findings, so it is tracked as its own
  // register item (Z-HNY-02) for a dedicated fix. This PR closes Z-HNY-01: the
  // in-memory buffer bytes + the N-way audit amplification.
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
