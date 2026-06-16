import { describe, expect, it } from "vitest";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { CallbackApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
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
        inputSchema: {
          type: "object",
          properties: {
            namespace: { type: "string" },
            key: { type: "string" },
          },
          required: ["namespace", "key"],
        },
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

  it("excludes another session's cached opaque memory from omitted-namespace export", async () => {
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
    await callTool(tools, "state_write", {
      namespace: aliceHandle,
      key: "private",
      value: "alice-only",
      identity_id: aliceId,
    });

    active = session(bobId);
    const result = await callTool(tools, "state_export", {});
    expect(result.namespaces).not.toContain(aliceHandle);
    expect(result.namespaces).toEqual([]);
  });

  it("refuses import into another session's opaque memory handle before writing", async () => {
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
    await callTool(tools, "state_write", {
      namespace: aliceHandle,
      key: "private",
      value: "alice-only",
      identity_id: aliceId,
    });
    const exported = await callTool(tools, "state_export", {
      namespace: aliceHandle,
    });

    await callTool(tools, "state_delete", {
      namespace: aliceHandle,
      key: "private",
    });

    active = session(bobId);
    const imported = await callTool(tools, "state_import", {
      bundle: exported.bundle,
      conflict_resolution: "overwrite",
    });
    expect(imported.denied).toBe(true);

    active = session(aliceId);
    const missing = await callTool(tools, "state_read", {
      namespace: aliceHandle,
      key: "private",
    });
    expect(missing.denied).toBe(true);
  });

  it("rejects import bundles whose declared namespaces differ from data namespaces", async () => {
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
    const aliceId = alice.identity_id as string;
    const aliceHandle = namespaceRegistry.issueMemoryHandle(aliceId);

    active = session(aliceId);
    await callTool(tools, "state_write", {
      namespace: aliceHandle,
      key: "private",
      value: "alice-only",
      identity_id: aliceId,
    });
    const exported = await callTool(tools, "state_export", {
      namespace: aliceHandle,
    });
    const decoded = JSON.parse(
      Buffer.from(exported.bundle as string, "base64url").toString("utf8")
    ) as Record<string, unknown>;
    decoded.namespaces = ["shared"];
    const mismatchedBundle = Buffer.from(
      JSON.stringify(decoded),
      "utf8"
    ).toString("base64url");

    await callTool(tools, "state_delete", {
      namespace: aliceHandle,
      key: "private",
    });
    const imported = await callTool(tools, "state_import", {
      bundle: mismatchedBundle,
      conflict_resolution: "overwrite",
    });
    expect(imported.denied).toBe(true);

    const missing = await callTool(tools, "state_read", {
      namespace: aliceHandle,
      key: "private",
    });
    expect(missing.denied).toBe(true);
  });

  it("exports all active-session owned namespaces while excluding other opaque handles", async () => {
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
    const bobHandle = namespaceRegistry.issueMemoryHandle(bobId);

    active = session(aliceId);
    await callTool(tools, "state_write", {
      namespace: aliceHandle,
      key: "private",
      value: "alice-only",
      identity_id: aliceId,
    });
    await callTool(tools, "state_write", {
      namespace: "shared",
      key: "public",
      value: "alice-shared",
      identity_id: aliceId,
    });

    active = session(bobId);
    await callTool(tools, "state_write", {
      namespace: bobHandle,
      key: "private",
      value: "bob-only",
      identity_id: bobId,
    });

    active = session(aliceId);
    const exported = await callTool(tools, "state_export", {});
    expect(exported.namespaces).toContain(aliceHandle);
    expect(exported.namespaces).toContain("shared");
    expect(exported.namespaces).not.toContain(bobHandle);
  });

  it("resolves omitted identity write and sign to the active session identity", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const stateStore = new StateStore(storage, masterKey);
    let active: SessionBinding | undefined;
    const { tools, identityManager } = createL1Tools(
      stateStore,
      storage,
      masterKey,
      "recovery-key",
      auditLog,
      { currentSessionBinding: () => active }
    );
    await identityManager.load();
    const alice = await callTool(tools, "identity_create", { label: "alice-default" });
    const bob = await callTool(tools, "identity_create", { label: "bob-session" });
    const aliceId = alice.identity_id as string;
    const bobId = bob.identity_id as string;

    active = session(bobId);
    await callTool(tools, "state_write", {
      namespace: "shared",
      key: "owner",
      value: "bob",
    });
    const read = await callTool(tools, "state_read", {
      namespace: "shared",
      key: "owner",
    });
    expect(read.written_by).toBe(bobId);
    expect(read.written_by).not.toBe(aliceId);

    const signed = await callTool(tools, "identity_sign", {
      payload: "hello",
    });
    expect(signed.public_key).toBe(bob.public_key);
    expect(signed.public_key).not.toBe(alice.public_key);
  });

  it("fails closed on omitted identity write and sign when active binding is ambiguous", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const stateStore = new StateStore(storage, masterKey);
    let active: SessionBinding | undefined;
    const { tools, identityManager } = createL1Tools(
      stateStore,
      storage,
      masterKey,
      "recovery-key",
      auditLog,
      { currentSessionBinding: () => active }
    );
    await identityManager.load();
    const alice = await callTool(tools, "identity_create", { label: "alice" });
    active = { identity_id: alice.identity_id as string };

    const write = await callTool(tools, "state_write", {
      namespace: "shared",
      key: "owner",
      value: "alice",
    });
    const signed = await callTool(tools, "identity_sign", {
      payload: "hello",
    });
    expect(write.denied).toBe(true);
    expect(signed.denied).toBe(true);
  });

  it("validates and canonicalizes approval preflight args through the execution schema path", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const active = session("agent-a");
    const tools: ToolDefinition[] = [
      {
        name: "state_write",
        description: "write",
        tool_class: "write",
        inputSchema: {
          type: "object",
          properties: {
            namespace: { type: "string" },
            key: { type: "string" },
            value: { type: "string" },
          },
          required: ["namespace", "key", "value"],
        },
        handler: async () => ({ content: [{ type: "text", text: "{}" }] }),
      },
    ];
    const classify = (toolName: string, args: Record<string, unknown>) => {
      expect(toolName).toBe("state_write");
      expect(args).toEqual({ namespace: "memory", key: "k", value: "v" });
      return 3 as const;
    };

    const ok = await classifyApprovalRequest({
      operation: "state_write",
      args: {
        namespace: "memory",
        key: "k",
        value: "v",
        approval_ref: "approval:test",
      },
      session: active,
      tools,
      classifyTier: classify,
      auditLog,
    });
    expect(ok.target_resource).toBe("state_write:memory/k");

    await expect(classifyApprovalRequest({
      operation: "state_write",
      args: { namespace: "memory", key: "k", value: "v", extra: true },
      session: active,
      tools,
      classifyTier: classify,
      auditLog,
    })).rejects.toThrow("This action is not available in the current context.");

    await expect(classifyApprovalRequest({
      operation: "state_write",
      args: { namespace: "memory", key: "k" },
      session: active,
      tools,
      classifyTier: classify,
      auditLog,
    })).rejects.toThrow("This action is not available in the current context.");

    await expect(classifyApprovalRequest({
      operation: "state_write",
      args: { namespace: "memory", key: "k", value: "x".repeat(1_048_577) },
      session: active,
      tools,
      classifyTier: classify,
      auditLog,
    })).rejects.toThrow("This action is not available in the current context.");

    const importTools: ToolDefinition[] = [
      {
        name: "state_import",
        description: "import",
        tool_class: "write",
        inputSchema: {
          type: "object",
          properties: {
            bundle: { type: "string" },
            conflict_resolution: {
              type: "string",
              enum: ["skip", "overwrite", "version"],
            },
          },
          required: ["bundle"],
        },
        handler: async () => ({ content: [{ type: "text", text: "{}" }] }),
      },
    ];
    const bundle = Buffer.from(JSON.stringify({
      namespaces: ["mem_target"],
      data: { mem_target: [] },
    }), "utf8").toString("base64url");
    const importPreflight = await classifyApprovalRequest({
      operation: "state_import",
      args: { bundle, conflict_resolution: "skip" },
      session: active,
      tools: importTools,
      classifyTier: () => 1,
      auditLog,
    });
    expect(importPreflight.target_resource).toBe("state_import:mem_target");

    await expect(classifyApprovalRequest({
      operation: "state_import",
      args: { bundle: "not-json" },
      session: active,
      tools: importTools,
      classifyTier: () => 1,
      auditLog,
    })).rejects.toThrow("This action is not available in the current context.");
  });

  it("binds omitted state_export approval targets to the actual exported namespaces", async () => {
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
    const aliceId = alice.identity_id as string;
    const aliceHandle = namespaceRegistry.issueMemoryHandle(aliceId);

    active = session(aliceId);
    await callTool(tools, "state_write", {
      namespace: aliceHandle,
      key: "private",
      value: "alice-only",
      identity_id: aliceId,
    });
    await callTool(tools, "state_write", {
      namespace: "shared",
      key: "public",
      value: "alice-shared",
      identity_id: aliceId,
    });

    const preflight = await classifyApprovalRequest({
      operation: "state_export",
      args: {},
      session: active,
      tools,
      classifyTier: () => 1,
      auditLog,
    });
    expect(preflight.target_resource).toBe(
      `state_export:${[aliceHandle, "shared"].sort().join(",")}`
    );
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
