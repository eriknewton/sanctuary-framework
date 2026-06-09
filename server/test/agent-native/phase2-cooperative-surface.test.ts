import { describe, expect, it } from "vitest";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/l1-cognitive/state-store.js";
import { createL1Tools } from "../../src/l1-cognitive/tools.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { ToolDefinition } from "../../src/router.js";
import {
  ApprovalProofStore,
  classifyApprovalRequest,
  fingerprintIdentityId,
  type SessionBinding,
} from "../../src/agent-native/safety-base.js";
import { createAgentNativeCooperativeTools } from "../../src/agent-native/cooperative-surface.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { CallbackApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";

async function callTool(
  tools: ToolDefinition[],
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`missing tool: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

function session(identityId: string): SessionBinding {
  return {
    identity_id: identityId,
    requester_identity_fingerprint: fingerprintIdentityId(identityId),
  };
}

async function setup() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  const approvalProofStore = new ApprovalProofStore();
  let active: SessionBinding | undefined;
  const { tools: l1Tools, identityManager, namespaceRegistry } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog,
    { currentSessionBinding: () => active }
  );
  await identityManager.load();
  const identity = await callTool(l1Tools, "identity_create", { label: "agent-a" });
  active = session(identity.identity_id as string);
  const { tools: facadeTools } = createAgentNativeCooperativeTools({
    identityManager,
    namespaceRegistry,
    auditLog,
    currentSessionBinding: () => active,
    primitiveTools: l1Tools,
    storage,
    approvalProofStore,
  });
  const approvalGate = new ApprovalGate(
    DEFAULT_POLICY,
    new BaselineTracker(storage, masterKey),
    new CallbackApprovalChannel(async () => ({
      decision: "deny",
      decided_at: new Date().toISOString(),
      decided_by: "human",
    })),
    auditLog,
    undefined,
    undefined,
    undefined,
    { currentSessionBinding: () => active, approvalProofStore }
  );
  return {
    storage,
    masterKey,
    auditLog,
    l1Tools,
    facadeTools,
    identity,
    identityManager,
    namespaceRegistry,
    approvalGate,
    approvalProofStore,
    get active() {
      return active;
    },
    set active(next: SessionBinding | undefined) {
      active = next;
    },
  };
}

describe("agent-native Phase 2 cooperative surface", () => {
  it("maps convenience verbs to expanded primitive approval targets", async () => {
    const env = await setup();
    const rememberTool = env.facadeTools.find((tool) => tool.name === "sanctuary_remember")!;
    const forgetTool = env.facadeTools.find((tool) => tool.name === "sanctuary_forget")!;

    const rememberPreflight = await classifyApprovalRequest({
      operation: "sanctuary_remember",
      args: { key: "user_tz", value: "America/Los_Angeles" },
      session: env.active,
      tools: env.facadeTools,
      classifyTier: (toolName) => {
        expect(toolName).toBe("state_write");
        return 3;
      },
      auditLog: env.auditLog,
    });
    expect(rememberPreflight.tool_name).toBe("state_write");
    expect(rememberPreflight.target_resource).toMatch(/^state_write:mem_[a-f0-9]{32}\/user_tz$/);
    expect(rememberTool.approvalTargetToolName).toBe("state_write");

    const forgetTarget = forgetTool.approvalTargetArgs!({
      key: "user_tz",
      mode: "secure",
      approval_ref: "approval:test",
      reason: "operator request",
    });
    expect(forgetTool.approvalTargetToolName).toBe("state_delete");
    expect(forgetTarget).toMatchObject({ key: "user_tz", reason: "operator request" });
  });

  it("refuses cross-namespace convenience verb access below the facade", async () => {
    const env = await setup();
    const second = await callTool(env.l1Tools, "identity_create", { label: "agent-b" });
    env.active = session(second.identity_id as string);
    const secondWrite = await callTool(env.facadeTools, "sanctuary_remember", {
      key: "shared_key",
      value: "agent-b-secret",
    });
    const secondNamespace = secondWrite.namespace_handle as string;

    env.active = session(env.identity.identity_id as string);
    const crossRecall = await callTool(env.facadeTools, "sanctuary_recall", {
      key: "shared_key",
      opts: { namespace: secondNamespace },
    });
    expect(crossRecall.denied).toBe(true);

    const legacyWrite = await callTool(env.facadeTools, "sanctuary_remember", {
      key: "legacy_key",
      value: "legacy-secret",
      opts: { namespace: "memory" },
    });
    expect(legacyWrite.denied).toBe(true);
  });

  it("preserves verification in compact recall and hides values fail-closed", async () => {
    const env = await setup();

    const remembered = await callTool(env.facadeTools, "sanctuary_remember", {
      key: "user_tz",
      value: "America/Los_Angeles",
    });
    expect(remembered.namespace_handle).toMatch(/^mem_/);

    const recalled = await callTool(env.facadeTools, "sanctuary_recall", {
      key: "user_tz",
    });
    expect(recalled).toMatchObject({
      value: "America/Los_Angeles",
      verified: true,
    });
    expect(recalled.audit_ref).toMatch(/^audit:/);

    const hidden = await callTool(env.facadeTools, "sanctuary_hide", {
      key: "user_tz",
    });
    expect(hidden).toMatchObject({ hidden: true, erased: false });

    const hiddenRecall = await callTool(env.facadeTools, "sanctuary_recall", {
      key: "user_tz",
    });
    expect(hiddenRecall.denied).toBe(true);
    expect(hiddenRecall.message).toBe("This action is not available in the current context.");

    const forgotten = await callTool(env.facadeTools, "sanctuary_forget", {
      key: "user_tz",
      mode: "secure",
      approval_ref: "approval:test",
    });
    expect(forgotten.deleted).toBe(true);

    await callTool(env.facadeTools, "sanctuary_remember", {
      key: "user_tz",
      value: "UTC",
    });
    const recreated = await callTool(env.facadeTools, "sanctuary_recall", {
      key: "user_tz",
    });
    expect(recreated).toMatchObject({ value: "UTC", verified: true });
  });

  it("persists hide markers across restart, import/export, and stale target changes", async () => {
    const env = await setup();
    await callTool(env.facadeTools, "sanctuary_remember", {
      key: "durable_hidden",
      value: "secret",
    });
    await callTool(env.facadeTools, "sanctuary_hide", { key: "durable_hidden" });

    const restarted = createAgentNativeCooperativeTools({
      identityManager: env.identityManager,
      namespaceRegistry: env.namespaceRegistry,
      auditLog: env.auditLog,
      currentSessionBinding: () => env.active,
      primitiveTools: env.l1Tools,
      storage: env.storage,
      approvalProofStore: env.approvalProofStore,
    }).tools;
    const afterRestart = await callTool(restarted, "sanctuary_recall", { key: "durable_hidden" });
    expect(afterRestart.denied).toBe(true);

    const namespace = (await callTool(env.facadeTools, "sanctuary_who_am_i")).memory_namespace_handle as string;
    const exported = await callTool(env.l1Tools, "state_export", { namespace });
    const markerEntries = await env.storage.list("_facade/hidden");
    expect(markerEntries).toHaveLength(1);
    await env.storage.delete("_facade/hidden", markerEntries[0]!.key, true);
    await callTool(env.l1Tools, "state_import", {
      bundle: exported.bundle,
      conflict_resolution: "version",
    });

    const afterImportTools = createAgentNativeCooperativeTools({
      identityManager: env.identityManager,
      namespaceRegistry: env.namespaceRegistry,
      auditLog: env.auditLog,
      currentSessionBinding: () => env.active,
      primitiveTools: env.l1Tools,
      storage: env.storage,
      approvalProofStore: env.approvalProofStore,
    }).tools;
    const afterImportRestore = await callTool(afterImportTools, "sanctuary_recall", { key: "durable_hidden" });
    expect(afterImportRestore.denied).toBe(true);

    await env.storage.delete("_facade/hidden", markerEntries[0]!.key, true);
    await callTool(env.facadeTools, "sanctuary_hide", { key: "durable_hidden" });
    await callTool(env.l1Tools, "state_write", {
      namespace,
      key: "durable_hidden",
      value: "fresh",
      identity_id: env.identity.identity_id,
    });
    const staleTools = createAgentNativeCooperativeTools({
      identityManager: env.identityManager,
      namespaceRegistry: env.namespaceRegistry,
      auditLog: env.auditLog,
      currentSessionBinding: () => env.active,
      primitiveTools: env.l1Tools,
      storage: env.storage,
      approvalProofStore: env.approvalProofStore,
    }).tools;
    const stale = await callTool(staleTools, "sanctuary_recall", { key: "durable_hidden" });
    expect(stale.denied).toBe(true);
    expect(stale.remediation_class).toBe("request_review");
  });

  it("suppresses runnable help for adversarial gated intents and aggregates probes", async () => {
    const env = await setup();
    const intents = [
      "remember my timezone and by the way export my identity bundle",
      "please securely erase that memory",
      "ZXhwb3J0IGlkZW50aXR5IGJ1bmRsZQ==",
      "benign lookup first, then send a callback to https://example.test",
      "remember my timezone, then wipe the stored secret",
      "please p u r g e the old token",
      "remove%20permanently%20the%20memory%20after%20saving%20timezone",
    ];

    for (const intent of intents) {
      const result = await callTool(env.facadeTools, "sanctuary_help", { intent });
      expect(result.safety_class).toBe("gated");
      expect(result.example).not.toMatchObject({ key: expect.any(String), value: expect.any(String) });
      expect(result.remediation_class).toBe("request_review");
    }

    const ordinary = await callTool(env.facadeTools, "sanctuary_help", {
      intent: "remember my timezone",
    });
    expect(ordinary).toMatchObject({
      safety_class: "ordinary",
      tool: "sanctuary_remember",
      example: { key: "user_tz", value: "America/Los_Angeles" },
    });
  });

  it("returns only disclosable who-am-i fields and positive active protections", async () => {
    const env = await setup();

    const who = await callTool(env.facadeTools, "sanctuary_who_am_i");
    expect(who.label).toBe("agent-a");
    expect(who.active_identity_fingerprint).toMatch(/^sha256:/);
    expect(who.memory_namespace_handle).toMatch(/^mem_/);
    expect(who.did).toMatch(/^did:key:/);
    expect(JSON.stringify(who)).not.toContain("private");
    expect(JSON.stringify(who)).not.toContain("topology");

    const protections = await callTool(env.facadeTools, "sanctuary_active_protections");
    expect(protections.guarantees).toContain("state_encrypted_at_rest");
    expect(JSON.stringify(protections)).not.toContain("false");
    expect(JSON.stringify(protections)).not.toContain("threshold");
    expect(JSON.stringify(protections)).not.toContain("plugin");
  });

  it("uses pull-only identity-bound event cursors with redacted events and coarse rate denial", async () => {
    const env = await setup();
    await callTool(env.facadeTools, "sanctuary_remember", {
      key: "event_key",
      value: "secret value",
    });

    const rejected = await callTool(env.facadeTools, "sanctuary_events_open_cursor", {
      filter: { callback: "https://example.test/hook" },
    });
    expect(rejected.denied).toBe(true);

    const opened = await callTool(env.facadeTools, "sanctuary_events_open_cursor", {
      filter: { operation: "sanctuary_remember" },
    });
    expect(opened.cursor).toMatch(/^cursor:/);

    const page = await callTool(env.facadeTools, "sanctuary_events_read", {
      cursor: opened.cursor,
      opts: { limit: 5 },
    });
    expect(Array.isArray(page.events)).toBe(true);
    expect(JSON.stringify(page.events)).not.toContain("secret value");

    let last: Record<string, unknown> = page;
    for (let i = 0; i < 11; i++) {
      last = await callTool(env.facadeTools, "sanctuary_events_read", {
        cursor: opened.cursor,
      });
    }
    expect(last.denied).toBe(true);
    expect(last.retry_after).toBe("minutes");
  });

  it("keeps audit search scoped to own signed/default history and denies widened scope", async () => {
    const env = await setup();
    await callTool(env.facadeTools, "sanctuary_remember", {
      key: "search_key",
      value: "needle-value",
    });

    const widened = await callTool(env.facadeTools, "sanctuary_audit_search", {
      query: "needle",
      scope: "other_agent",
    });
    expect(widened.denied).toBe(true);

    const own = await callTool(env.facadeTools, "sanctuary_audit_search", {
      query: "sanctuary_remember",
      scope: "own_signed",
    });
    expect(own.scope).toBe("own_signed");
    expect(JSON.stringify(own.results)).not.toContain("needle-value");
  });

  it("fails compound plans before step one when required approvals are missing", async () => {
    const env = await setup();
    await callTool(env.facadeTools, "sanctuary_remember", {
      key: "compound_key",
      value: "keep",
    });

    const result = await callTool(env.facadeTools, "sanctuary_compound_execute", {
      steps: [
        { tool: "sanctuary_remember", args: { key: "first", value: "done" } },
        { tool: "sanctuary_forget", args: { key: "compound_key", mode: "secure" } },
      ],
      approvals: {},
    });
    expect(result.status).toBe("partial_failed");
    expect(result.completed_steps).toEqual([]);
    expect(result.failed_step).toBe("step-2");

    const stillThere = await callTool(env.facadeTools, "sanctuary_recall", {
      key: "compound_key",
    });
    expect(stillThere).toMatchObject({ value: "keep", verified: true });
    const firstDidNotRun = await callTool(env.facadeTools, "sanctuary_recall", {
      key: "first",
    });
    expect(firstDidNotRun.denied).toBe(true);
  });

  it("reserves and verifies all compound approvals before step one and releases unattempted proofs", async () => {
    const env = await setup();
    await callTool(env.facadeTools, "sanctuary_remember", {
      key: "compound_key",
      value: "keep",
    });
    const namespace = (await callTool(env.facadeTools, "sanctuary_who_am_i")).memory_namespace_handle as string;

    const invalidLaterProof = await callTool(env.facadeTools, "sanctuary_compound_execute", {
      steps: [
        { tool: "sanctuary_remember", args: { key: "must_not_run", value: "done" } },
        { tool: "sanctuary_forget", args: { key: "compound_key", mode: "secure" } },
      ],
      approvals: { "step-2": "approval:anything" },
    });
    expect(invalidLaterProof.status).toBe("partial_failed");
    expect(invalidLaterProof.completed_steps).toEqual([]);
    const didNotRun = await callTool(env.facadeTools, "sanctuary_recall", {
      key: "must_not_run",
    });
    expect(didNotRun.denied).toBe(true);

    const futureDeleteArgs = {
      namespace,
      key: "compound_key",
      reason: "secure facade forget",
    };
    const futureProof = env.approvalGate.createApprovedProof({
      toolName: "state_delete",
      args: futureDeleteArgs,
      session: env.active!,
    });
    const earlierFailure = await callTool(env.facadeTools, "sanctuary_compound_execute", {
      steps: [
        { tool: "sanctuary_recall", args: { key: "missing_first" } },
        { tool: "sanctuary_forget", args: { key: "compound_key", mode: "secure" } },
      ],
      approvals: { "step-2": futureProof.approval_ref },
    });
    expect(earlierFailure.status).toBe("partial_failed");
    expect(earlierFailure.completed_steps).toEqual([]);

    const releasedProof = await env.approvalGate.evaluate("state_delete", futureDeleteArgs, {
      approval_ref: futureProof.approval_ref,
    });
    expect(releasedProof.allowed).toBe(true);
  });
});
