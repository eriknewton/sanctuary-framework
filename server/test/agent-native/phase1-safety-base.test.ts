import { describe, expect, it } from "vitest";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { CallbackApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/l1-cognitive/state-store.js";
import { createL1Tools } from "../../src/l1-cognitive/tools.js";
import {
  classifyApprovalRequest,
  fixedDenial,
  fingerprintIdentityId,
  OpaqueNamespaceRegistry,
  type SessionBinding,
} from "../../src/agent-native/safety-base.js";
import type { ToolDefinition } from "../../src/router.js";

async function callTool(
  tools: ToolDefinition[],
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const tool = tools.find((t) => t.name === name);
  if (!tool) throw new Error(`missing tool: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text);
}

function session(identityId: string): SessionBinding {
  return {
    identity_id: identityId,
    requester_identity_fingerprint: fingerprintIdentityId(identityId),
  };
}

describe("agent-native Phase 1 safety base", () => {
  it("verifies approval proofs against the actual primitive args and denies atomic reuse", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const baseline = new BaselineTracker(storage, masterKey);
    const active = session("agent-a");
    let prompts = 0;
    const gate = new ApprovalGate(
      DEFAULT_POLICY,
      baseline,
      new CallbackApprovalChannel(async () => {
        prompts++;
        return {
          decision: "deny",
          decided_at: new Date().toISOString(),
          decided_by: "human",
        };
      }),
      auditLog,
      undefined,
      undefined,
      undefined,
      { currentSessionBinding: () => active }
    );

    const primitiveArgs = { namespace: "memory", key: "delete-me" };
    const approved = gate.createApprovedProof({
      toolName: "state_delete",
      args: primitiveArgs,
      session: active,
    });

    const mismatch = await gate.evaluate(
      "state_delete",
      { namespace: "memory", key: "other-key" },
      { approval_ref: approved.approval_ref }
    );
    expect(mismatch.allowed).toBe(false);
    expect(prompts).toBe(0);

    const firstUse = await gate.evaluate("state_delete", primitiveArgs, {
      approval_ref: approved.approval_ref,
    });
    expect(firstUse.allowed).toBe(true);

    const replay = await gate.evaluate("state_delete", primitiveArgs, {
      approval_ref: approved.approval_ref,
    });
    expect(replay.allowed).toBe(false);
    expect(prompts).toBe(0);
  });

  it("classifies approval requests without executing the operation or prompting", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const baseline = new BaselineTracker(storage, masterKey);
    const active = session("agent-a");
    const gate = new ApprovalGate(
      DEFAULT_POLICY,
      baseline,
      new CallbackApprovalChannel(async () => {
        throw new Error("preflight must not call the approval channel");
      }),
      auditLog,
      undefined,
      undefined,
      undefined,
      { currentSessionBinding: () => active }
    );
    let executed = false;
    const tools: ToolDefinition[] = [
      {
        name: "state_delete",
        description: "delete",
        inputSchema: { type: "object", properties: {} },
        handler: async () => {
          executed = true;
          return { content: [{ type: "text", text: "{}" }] };
        },
      },
    ];

    const preflight = await classifyApprovalRequest({
      operation: "state_delete",
      args: { namespace: "memory", key: "target" },
      session: active,
      tools,
      classifyTier: (toolName, args) => gate.classifyRiskTier(toolName, args),
      auditLog,
    });

    expect(preflight.tool_name).toBe("state_delete");
    expect(preflight.risk_tier).toBe(1);
    expect(preflight.normalized_args_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(executed).toBe(false);
  });

  it("enforces opaque memory handles at the primitive state layer", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const stateStore = new StateStore(storage, masterKey);
    const namespaceRegistry = new OpaqueNamespaceRegistry();
    let active: SessionBinding | undefined;
    const { tools, identityManager } = createL1Tools(
      stateStore,
      storage,
      masterKey,
      "recovery-key",
      auditLog,
      {
        namespaceRegistry,
        currentSessionBinding: () => active,
      }
    );
    await identityManager.load();
    const alice = await callTool(tools, "identity_create", { label: "alice" });
    const bob = await callTool(tools, "identity_create", { label: "bob" });
    const aliceId = alice.identity_id as string;
    const bobId = bob.identity_id as string;
    const aliceHandle = namespaceRegistry.issueMemoryHandle(aliceId);

    active = session(aliceId);
    const write = await callTool(tools, "state_write", {
      namespace: aliceHandle,
      key: "user_tz",
      value: "America/Los_Angeles",
      identity_id: aliceId,
    });
    expect(write.key).toBe("user_tz");

    active = session(bobId);
    const replayedHandle = await callTool(tools, "state_read", {
      namespace: aliceHandle,
      key: "user_tz",
    });
    const absent = await callTool(tools, "state_read", {
      namespace: namespaceRegistry.issueMemoryHandle(bobId),
      key: "missing",
    });
    expect(replayedHandle).toEqual(absent);
    expect(replayedHandle.denied).toBe(true);
    expect(replayedHandle.message).toBe("This action is not available in the current context.");

    active = undefined;
    const unbound = await callTool(tools, "state_list", {
      namespace: aliceHandle,
    });
    expect({
      message: unbound.message,
      remediation_class: unbound.remediation_class,
      retry_after: unbound.retry_after,
    }).toEqual({
      message: replayedHandle.message,
      remediation_class: replayedHandle.remediation_class,
      retry_after: replayedHandle.retry_after,
    });
  });

  it("uses only coarse retry_after values in fixed denials", () => {
    expect(fixedDenial("audit:ref", "wait", "minutes")).toEqual({
      denied: true,
      message: "This action is not available in the current context.",
      remediation_class: "wait",
      retry_after: "minutes",
      audit_ref: "audit:ref",
    });
    expect(fixedDenial("audit:ref").retry_after).toBeNull();
  });
});
