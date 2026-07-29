import { describe, expect, it } from "vitest";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { AGENT_AUDIT_VIEW_FIELDS } from "../../src/operational/agent-audit-redaction.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { toolResult, type ToolDefinition } from "../../src/router.js";
import {
  ApprovalProofStore,
  classifyApprovalRequest,
  canonicalJson,
  fingerprintIdentityId,
  normalizedArgsHash,
  sha256,
  type SessionBinding,
} from "../../src/agent-native/safety-base.js";
import { createAgentNativeCooperativeTools } from "../../src/agent-native/cooperative-surface.js";
import { attributeFlows } from "../../src/castle-wall/audit/per-rule-report.js";
import { CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY } from "../../src/castle-wall/constants.js";
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

function compoundPlanHash(
  steps: Array<{
    step_id: string;
    primitive_tool: string;
    primitive: Record<string, unknown>;
    risk_tier: 1 | 3;
  }>
): `sha256:${string}` {
  return sha256(canonicalJson(steps.map((step) => ({
    step_id: step.step_id,
    primitive_tool: step.primitive_tool,
    normalized_args_hash: normalizedArgsHash(step.primitive),
    risk_tier: step.risk_tier,
  }))));
}

const EVENT_ALLOWED_KEYS = [
  "cursor_event_id",
  ...AGENT_AUDIT_VIEW_FIELDS,
].sort();

function toolsWithOverride(
  tools: ToolDefinition[],
  name: string,
  handler: ToolDefinition["handler"]
): ToolDefinition[] {
  return tools.map((tool) => tool.name === name ? { ...tool, handler } : tool);
}

function facadeWithPrimitives(
  env: Awaited<ReturnType<typeof setup>>,
  primitiveTools: ToolDefinition[]
): ToolDefinition[] {
  return createAgentNativeCooperativeTools({
    identityManager: env.identityManager,
    namespaceRegistry: env.namespaceRegistry,
    auditLog: env.auditLog,
    currentSessionBinding: () => env.active,
    primitiveTools,
    storage: env.storage,
    approvalProofStore: env.approvalProofStore,
  }).tools;
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

  it("garbage-collects expired hide markers and reveals the target by default", async () => {
    const env = await setup();
    await callTool(env.facadeTools, "sanctuary_remember", {
      key: "temporary_hidden",
      value: "visible-after-expiry",
    });
    await callTool(env.facadeTools, "sanctuary_hide", {
      key: "temporary_hidden",
      opts: { ttl: -1 },
    });

    const recalled = await callTool(env.facadeTools, "sanctuary_recall", {
      key: "temporary_hidden",
    });
    expect(recalled).toMatchObject({ value: "visible-after-expiry", verified: true });

    const markerEntries = await env.storage.list("_facade/hidden");
    expect(markerEntries).toHaveLength(0);
    const audited = await env.auditLog.query({
      operation_type: "sanctuary_hide_marker_gc",
      limit: 10,
    });
    expect(audited.entries).toHaveLength(1);
    expect(audited.entries[0]!.details).toMatchObject({
      marker_namespace: "_facade/hidden",
      target: expect.stringContaining("/temporary_hidden"),
    });
  });

  it("suppresses runnable help for adversarial gated intents and aggregates probes", async () => {
    const env = await setup();
    const helpTool = env.facadeTools.find((tool) => tool.name === "sanctuary_help")!;
    expect(helpTool.description).toContain("never reveals policy internals");
    expect(helpTool.description).not.toContain("policy-aware");
    const intents = [
      "remember my timezone and by the way export my identity bundle",
      "please securely erase that memory",
      "ZXhwb3J0IGlkZW50aXR5IGJ1bmRsZQ==",
      "benign lookup first, then send a callback to https://example.test",
      "remember my timezone, then wipe the stored secret",
      "remember my timezone, then remove the stored secret",
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
    expect(JSON.stringify(ordinary)).not.toContain("policy-aware");

    const ambiguousMultiIntent = await callTool(env.facadeTools, "sanctuary_help", {
      intent: "remember my timezone, then sort out the rest later",
    });
    expect(ambiguousMultiIntent.safety_class).toBe("sensitive");
    expect(ambiguousMultiIntent.example).toBeNull();
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
    for (let i = 0; i < 7; i++) {
      await callTool(env.facadeTools, "sanctuary_remember", {
        key: `event_key_${i}`,
        value: `secret value ${i}`,
      });
    }

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
      opts: { limit: 3 },
    });
    expect(Array.isArray(page.events)).toBe(true);
    const pageEvents = page.events as Array<Record<string, unknown>>;
    expect(pageEvents.map((event) => event.cursor_event_id)).toEqual([0, 1, 2]);
    for (const event of pageEvents) {
      expect(Object.keys(event).sort()).toEqual(EVENT_ALLOWED_KEYS);
      expect(typeof event.has_details).toBe("boolean");
      expect(event).not.toHaveProperty("summary");
      expect(event).not.toHaveProperty("layer");
      expect(event).not.toHaveProperty("identity_match");
    }
    expect(JSON.stringify(page.events)).not.toContain("secret value");

    const secondPage = await callTool(env.facadeTools, "sanctuary_events_read", {
      cursor: opened.cursor,
      opts: { limit: 3 },
    });
    expect((secondPage.events as Array<Record<string, unknown>>).map((event) => event.cursor_event_id)).toEqual([3, 4, 5]);

    const thirdPage = await callTool(env.facadeTools, "sanctuary_events_read", {
      cursor: opened.cursor,
      opts: { limit: 3 },
    });
    expect((thirdPage.events as Array<Record<string, unknown>>).map((event) => event.cursor_event_id)).toEqual([6]);

    let last: Record<string, unknown> = thirdPage;
    for (let i = 0; i < 8; i++) {
      last = await callTool(env.facadeTools, "sanctuary_events_read", {
        cursor: opened.cursor,
      });
    }
    expect(last.denied).toBe(true);
    expect(last.retry_after).toBe("minutes");
  });

  it("applies compound hide and forget marker side effects", async () => {
    const env = await setup();
    await callTool(env.facadeTools, "sanctuary_remember", {
      key: "compound_hidden",
      value: "old secret",
    });

    const hidden = await callTool(env.facadeTools, "sanctuary_compound_execute", {
      steps: [
        { tool: "sanctuary_hide", args: { key: "compound_hidden" } },
      ],
    });
    expect(hidden.status).toBe("completed");
    const hiddenMarkers = await env.storage.list("_facade/hidden");
    expect(hiddenMarkers).toHaveLength(1);

    const hiddenRecall = await callTool(env.facadeTools, "sanctuary_recall", {
      key: "compound_hidden",
    });
    expect(hiddenRecall.denied).toBe(true);

    const namespace = (await callTool(env.facadeTools, "sanctuary_who_am_i")).memory_namespace_handle as string;
    const deleteArgs = {
      namespace,
      key: "compound_hidden",
      reason: "secure facade forget",
    };
    const planHash = compoundPlanHash([
      {
        step_id: "step-1",
        primitive_tool: "state_delete",
        primitive: deleteArgs,
        risk_tier: 1,
      },
    ]);
    const proof = env.approvalGate.createApprovedProof({
      toolName: "state_delete",
      args: deleteArgs,
      session: env.active!,
      planHash,
      stepId: "step-1",
    });

    const forgotten = await callTool(env.facadeTools, "sanctuary_compound_execute", {
      steps: [
        { tool: "sanctuary_forget", args: { key: "compound_hidden", mode: "secure" } },
      ],
      approvals: { "step-1": proof.approval_ref },
    });
    expect(forgotten.status).toBe("completed");
    const markersAfterForget = await env.storage.list("_facade/hidden");
    expect(markersAfterForget).toHaveLength(0);

    await callTool(env.facadeTools, "sanctuary_remember", {
      key: "compound_hidden",
      value: "new secret",
    });
    const recreated = await callTool(env.facadeTools, "sanctuary_recall", {
      key: "compound_hidden",
    });
    expect(recreated).toMatchObject({ value: "new secret", verified: true });
  });

  it("denies compound forget without secure mode before state_delete and keeps the marker", async () => {
    const env = await setup();
    await callTool(env.facadeTools, "sanctuary_remember", {
      key: "compound_mode_guard",
      value: "do not delete",
    });
    await callTool(env.facadeTools, "sanctuary_hide", { key: "compound_mode_guard" });
    const beforeMarkers = await env.storage.list("_facade/hidden");
    expect(beforeMarkers).toHaveLength(1);

    const namespace = (await callTool(env.facadeTools, "sanctuary_who_am_i")).memory_namespace_handle as string;
    const deleteArgs = {
      namespace,
      key: "compound_mode_guard",
      reason: "secure facade forget",
    };
    const planHash = compoundPlanHash([
      {
        step_id: "step-1",
        primitive_tool: "state_delete",
        primitive: deleteArgs,
        risk_tier: 1,
      },
    ]);
    const proof = env.approvalGate.createApprovedProof({
      toolName: "state_delete",
      args: deleteArgs,
      session: env.active!,
      planHash,
      stepId: "step-1",
    });
    const originalDelete = env.l1Tools.find((tool) => tool.name === "state_delete")!;
    let stateDeleteCalls = 0;
    const guardedTools = facadeWithPrimitives(
      env,
      toolsWithOverride(env.l1Tools, "state_delete", async (args) => {
        stateDeleteCalls += 1;
        return originalDelete.handler(args);
      })
    );

    const result = await callTool(guardedTools, "sanctuary_compound_execute", {
      steps: [
        { tool: "sanctuary_forget", args: { key: "compound_mode_guard", mode: "unsafe" } },
      ],
      approvals: { "step-1": proof.approval_ref },
    });
    expect(result.denied).toBe(true);
    expect(result.message).toBe("This action is not available in the current context.");
    expect(result.status).not.toBe("completed");
    expect(stateDeleteCalls).toBe(0);

    const afterMarkers = await env.storage.list("_facade/hidden");
    expect(afterMarkers.map((entry) => entry.key)).toEqual(beforeMarkers.map((entry) => entry.key));
    const stillHidden = await callTool(env.facadeTools, "sanctuary_recall", {
      key: "compound_mode_guard",
    });
    expect(stillHidden.denied).toBe(true);
    const raw = await callTool(env.l1Tools, "state_read", {
      namespace,
      key: "compound_mode_guard",
      verify_integrity: true,
    });
    expect(raw).toMatchObject({ value: "do not delete" });
  });

  it("keeps the marker and emits no success audit when standalone forget state_delete is denied", async () => {
    const env = await setup();
    await callTool(env.facadeTools, "sanctuary_remember", {
      key: "standalone_denied_forget",
      value: "still present",
    });
    await callTool(env.facadeTools, "sanctuary_hide", { key: "standalone_denied_forget" });
    const beforeMarkers = await env.storage.list("_facade/hidden");
    expect(beforeMarkers).toHaveLength(1);

    const deniedTools = facadeWithPrimitives(
      env,
      toolsWithOverride(env.l1Tools, "state_delete", async () => toolResult({ denied: true }))
    );
    const result = await callTool(deniedTools, "sanctuary_forget", {
      key: "standalone_denied_forget",
      mode: "secure",
      approval_ref: "approval:test",
    });
    expect(result.denied).toBe(true);
    expect(result.deleted).not.toBe(true);

    const afterMarkers = await env.storage.list("_facade/hidden");
    expect(afterMarkers.map((entry) => entry.key)).toEqual(beforeMarkers.map((entry) => entry.key));
    const stillHidden = await callTool(env.facadeTools, "sanctuary_recall", {
      key: "standalone_denied_forget",
    });
    expect(stillHidden.denied).toBe(true);
    const forgetAudits = await env.auditLog.query({
      operation_type: "sanctuary_forget",
      limit: 10,
    });
    expect(forgetAudits.entries).toHaveLength(0);
  });

  it("keeps the marker and reports partial failure when compound forget state_delete is denied", async () => {
    const env = await setup();
    await callTool(env.facadeTools, "sanctuary_remember", {
      key: "compound_denied_forget",
      value: "still present",
    });
    await callTool(env.facadeTools, "sanctuary_hide", { key: "compound_denied_forget" });
    const beforeMarkers = await env.storage.list("_facade/hidden");
    expect(beforeMarkers).toHaveLength(1);

    const namespace = (await callTool(env.facadeTools, "sanctuary_who_am_i")).memory_namespace_handle as string;
    const deleteArgs = {
      namespace,
      key: "compound_denied_forget",
      reason: "secure facade forget",
    };
    const planHash = compoundPlanHash([
      {
        step_id: "step-1",
        primitive_tool: "state_delete",
        primitive: deleteArgs,
        risk_tier: 1,
      },
    ]);
    const proof = env.approvalGate.createApprovedProof({
      toolName: "state_delete",
      args: deleteArgs,
      session: env.active!,
      planHash,
      stepId: "step-1",
    });
    const deniedTools = facadeWithPrimitives(
      env,
      toolsWithOverride(env.l1Tools, "state_delete", async () => toolResult({ denied: true }))
    );

    const result = await callTool(deniedTools, "sanctuary_compound_execute", {
      steps: [
        { tool: "sanctuary_forget", args: { key: "compound_denied_forget", mode: "secure" } },
      ],
      approvals: { "step-1": proof.approval_ref },
    });
    expect(result.status).toBe("partial_failed");
    expect(result.status).not.toBe("completed");
    expect(result.completed_steps).toEqual([]);
    expect(result.failed_step).toBe("step-1");

    const afterMarkers = await env.storage.list("_facade/hidden");
    expect(afterMarkers.map((entry) => entry.key)).toEqual(beforeMarkers.map((entry) => entry.key));
    const stillHidden = await callTool(env.facadeTools, "sanctuary_recall", {
      key: "compound_denied_forget",
    });
    expect(stillHidden.denied).toBe(true);
    const forgetAudits = await env.auditLog.query({
      operation_type: "sanctuary_forget",
      limit: 10,
    });
    expect(forgetAudits.entries).toHaveLength(0);
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

  // Property #11 (no-policy-inference): the agent-facing audit search must NOT be
  // a probing oracle. The returned rows already omit details, but searching over
  // the RAW details would still let an agent guess a policy-inference-sensitive
  // value (rule_id / rule_id_matched / decision_provenance / the signed-canonical
  // blob) and learn a differential match off result_count. The search corpus is
  // the agent-REDACTED projection, so a probe for any sensitive value can never
  // hit, while the entry stays findable by its (non-sensitive) operation.
  it("audit search does not leak policy-inference-sensitive details via probing (oracle closed, property #11)", async () => {
    const env = await setup();
    const ownIdentity = env.identity.identity_id as string;

    // Seed a Castle Wall enforcement audit entry carrying every sensitive detail
    // key on the cooperative surface's shared audit log, owned by the active agent
    // so it falls within the search's own_signed identity scope.
    await env.auditLog.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: ownIdentity,
      result: "failure",
      details: {
        decision: "deny_once",
        rule_id: "deny-secret-mac-rule",
        rule_id_matched: "deny-secret-linux-rule",
        decision_provenance: "policy_path_secret_provenance",
        [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]:
          '{"rule_id_matched":"deny-embedded-in-signed-blob","agent_id":"a"}',
        dest_host: "non-sensitive-host.example",
      },
    });

    // Baseline: the entry IS discoverable by its non-sensitive operation name.
    const byOperation = await callTool(env.facadeTools, "sanctuary_audit_search", {
      query: "egress_blocked",
      scope: "own_signed",
    });
    expect((byOperation.results as unknown[]).length).toBe(1);

    // Each sensitive value must yield ZERO matches — the probe cannot
    // differentially confirm the value's presence (result_count unaffected).
    for (const probe of [
      "deny-secret-mac-rule", // rule_id
      "deny-secret-linux-rule", // rule_id_matched
      "policy_path_secret_provenance", // decision_provenance
      "deny-embedded-in-signed-blob", // value inside the signed-canonical blob string
    ]) {
      const probed = await callTool(env.facadeTools, "sanctuary_audit_search", {
        query: probe,
        scope: "own_signed",
      });
      expect(
        (probed.results as unknown[]).length,
        `probe "${probe}" must not differentially match`
      ).toBe(0);
      // And the sensitive value never appears in the returned payload.
      expect(JSON.stringify(probed.results)).not.toContain(probe);
    }
  });

  // Residual presence-oracle (codex MEDIUM): an in-place redaction projection
  // leaves the sensitive KEY NAMES and the `[redacted]` sentinel in the search
  // corpus, so probing a key name or the sentinel would differentially match
  // entries that carry a policy-sensitive field. The search corpus OMITS those
  // keys entirely, so a probe for a key name OR the sentinel yields the SAME
  // result_count whether or not the entry has the sensitive field (no presence
  // oracle). Verified differentially against a control entry that has none of
  // the sensitive keys.
  it("audit search does not leak sensitive key NAMES or the [redacted] sentinel via probing (presence oracle closed, property #11)", async () => {
    const env = await setup();
    const ownIdentity = env.identity.identity_id as string;

    // Entry A: carries every sensitive detail key.
    await env.auditLog.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: ownIdentity,
      result: "failure",
      details: {
        decision: "deny_once",
        rule_id: "deny-mac-rule",
        rule_id_matched: "deny-linux-rule",
        decision_provenance: "policy_path_provenance",
        [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]:
          '{"rule_id_matched":"deny-in-blob","agent_id":"a"}',
        dest_host: "host-a.example",
      },
    });
    // Entry B (control): same shape, NONE of the sensitive keys present.
    await env.auditLog.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: ownIdentity,
      result: "success",
      details: { decision: "allow", dest_host: "host-b.example" },
    });

    // Sanity: both entries are discoverable by the (non-sensitive) operation.
    const byOperation = await callTool(env.facadeTools, "sanctuary_audit_search", {
      query: "egress_blocked",
      scope: "own_signed",
    });
    expect((byOperation.results as unknown[]).length).toBe(2);

    // Probing a sensitive KEY NAME must NOT differentially reveal that entry A
    // carries it: the key name is absent from the corpus, so zero matches —
    // identical to the control entry that never had the key.
    for (const keyName of [
      "rule_id",
      "rule_id_matched",
      "decision_provenance",
      CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
    ]) {
      const probed = await callTool(env.facadeTools, "sanctuary_audit_search", {
        query: keyName,
        scope: "own_signed",
      });
      expect(
        (probed.results as unknown[]).length,
        `key-name probe "${keyName}" must not differentially match`
      ).toBe(0);
      expect(JSON.stringify(probed.results)).not.toContain(keyName);
    }

    // Probing the redaction SENTINEL must also not differentially match: an
    // in-place projection would have written "[redacted]" into entry A's corpus
    // for each stripped key, turning the sentinel itself into a presence oracle.
    const sentinelProbe = await callTool(env.facadeTools, "sanctuary_audit_search", {
      query: "[redacted]",
      scope: "own_signed",
    });
    expect(
      (sentinelProbe.results as unknown[]).length,
      "sentinel probe must not differentially match"
    ).toBe(0);
    expect(JSON.stringify(sentinelProbe.results)).not.toContain("[redacted]");
  });

  // The OPERATOR audit path stays full-fidelity over the SAME seeded entry: it
  // must still see the unredacted matched rule. The agent redaction is scoped to
  // the agent-facing search/read boundary only and must not bleed into operator
  // attribution (per-rule-per-flow read-out).
  it("operator audit path still sees full (unredacted) details after the agent search fix", async () => {
    const env = await setup();
    const ownIdentity = env.identity.identity_id as string;
    await env.auditLog.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: ownIdentity,
      result: "failure",
      details: {
        decision: "deny_once",
        rule_id: "deny-operator-visible-rule",
        dest_host: "h.example",
      },
    });

    // Operator reads the raw audit log directly: details are full-fidelity.
    const raw = await env.auditLog.query({ layer: "l1", limit: 50 });
    const rawEntry = raw.entries.find((e) => e.operation === "egress_blocked");
    expect(rawEntry?.details?.rule_id).toBe("deny-operator-visible-rule");

    // The operator per-rule-per-flow read-out attributes the flow to that rule.
    const attributed = attributeFlows(raw.entries);
    const flow = attributed.find((f) => f.operation === "egress_blocked");
    expect(flow?.ruleId).toBe("deny-operator-visible-rule");
  });

  // Legitimate agent search over NON-sensitive fields keeps working: the redacted
  // projection preserves operation names and non-sensitive detail values.
  it("agent search still matches non-sensitive detail fields after the fix", async () => {
    const env = await setup();
    const ownIdentity = env.identity.identity_id as string;
    await env.auditLog.appendCritical({
      layer: "l1",
      operation: "egress_allowed",
      identity_id: ownIdentity,
      result: "success",
      details: {
        decision: "allow",
        rule_id: "allow-secret-rule",
        dest_host: "searchable-allowed-host.example",
      },
    });

    // A non-sensitive detail value is still searchable.
    const byHost = await callTool(env.facadeTools, "sanctuary_audit_search", {
      query: "searchable-allowed-host",
      scope: "own_signed",
    });
    expect((byHost.results as unknown[]).length).toBe(1);
    expect((byHost.results as Array<Record<string, unknown>>)[0]!.operation).toBe(
      "egress_allowed"
    );

    // ...but the sensitive rule_id on the SAME entry is still not searchable.
    const byRule = await callTool(env.facadeTools, "sanctuary_audit_search", {
      query: "allow-secret-rule",
      scope: "own_signed",
    });
    expect((byRule.results as unknown[]).length).toBe(0);
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
    const planHash = compoundPlanHash([
      {
        step_id: "step-1",
        primitive_tool: "state_read",
        primitive: { namespace, key: "missing_first", verify_integrity: true },
        risk_tier: 3,
      },
      {
        step_id: "step-2",
        primitive_tool: "state_delete",
        primitive: futureDeleteArgs,
        risk_tier: 1,
      },
    ]);
    const futureProof = env.approvalGate.createApprovedProof({
      toolName: "state_delete",
      args: futureDeleteArgs,
      session: env.active!,
      planHash,
      stepId: "step-2",
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

    const releasedProof = await callTool(env.facadeTools, "sanctuary_compound_execute", {
      steps: [
        { tool: "sanctuary_recall", args: { key: "missing_first" } },
        { tool: "sanctuary_forget", args: { key: "compound_key", mode: "secure" } },
      ],
      approvals: { "step-2": futureProof.approval_ref },
    });
    expect(releasedProof.status).toBe("partial_failed");
    expect(releasedProof.completed_steps).toEqual([]);

    const directUseDenied = await env.approvalGate.evaluate("state_delete", futureDeleteArgs, {
      approval_ref: futureProof.approval_ref,
    });
    expect(directUseDenied.allowed).toBe(false);
  });

  it("binds compound approval proofs to plan hash and step id", async () => {
    const env = await setup();
    await callTool(env.facadeTools, "sanctuary_remember", {
      key: "compound_key",
      value: "delete-me",
    });
    await callTool(env.facadeTools, "sanctuary_remember", {
      key: "other_key",
      value: "delete-me-too",
    });
    const namespace = (await callTool(env.facadeTools, "sanctuary_who_am_i")).memory_namespace_handle as string;
    const deleteArgs = {
      namespace,
      key: "compound_key",
      reason: "secure facade forget",
    };
    const validPlanHash = compoundPlanHash([
      {
        step_id: "step-1",
        primitive_tool: "state_write",
        primitive: {
          namespace,
          key: "first",
          value: "done",
          identity_id: env.identity.identity_id,
        },
        risk_tier: 3,
      },
      {
        step_id: "step-2",
        primitive_tool: "state_delete",
        primitive: deleteArgs,
        risk_tier: 1,
      },
    ]);
    const validProof = env.approvalGate.createApprovedProof({
      toolName: "state_delete",
      args: deleteArgs,
      session: env.active!,
      planHash: validPlanHash,
      stepId: "step-2",
    });

    const completed = await callTool(env.facadeTools, "sanctuary_compound_execute", {
      steps: [
        { tool: "sanctuary_remember", args: { key: "first", value: "done" } },
        { tool: "sanctuary_forget", args: { key: "compound_key", mode: "secure" } },
      ],
      approvals: { "step-2": validProof.approval_ref },
    });
    expect(completed.status).toBe("completed");

    const crossPlanProof = env.approvalGate.createApprovedProof({
      toolName: "state_delete",
      args: deleteArgs,
      session: env.active!,
      planHash: validPlanHash,
      stepId: "step-2",
    });
    const crossPlanReplay = await callTool(env.facadeTools, "sanctuary_compound_execute", {
      steps: [
        { tool: "sanctuary_remember", args: { key: "different_first", value: "done" } },
        { tool: "sanctuary_forget", args: { key: "compound_key", mode: "secure" } },
      ],
      approvals: { "step-2": crossPlanProof.approval_ref },
    });
    expect(crossPlanReplay.status).toBe("partial_failed");
    expect(crossPlanReplay.completed_steps).toEqual([]);

    const otherDeleteArgs = {
      namespace,
      key: "other_key",
      reason: "secure facade forget",
    };
    const stepReplayPlanHash = compoundPlanHash([
      {
        step_id: "step-1",
        primitive_tool: "state_delete",
        primitive: otherDeleteArgs,
        risk_tier: 1,
      },
    ]);
    const wrongStepProof = env.approvalGate.createApprovedProof({
      toolName: "state_delete",
      args: otherDeleteArgs,
      session: env.active!,
      planHash: stepReplayPlanHash,
      stepId: "step-2",
    });
    const crossStepReplay = await callTool(env.facadeTools, "sanctuary_compound_execute", {
      steps: [
        { tool: "sanctuary_forget", args: { key: "other_key", mode: "secure" } },
      ],
      approvals: { "step-1": wrongStepProof.approval_ref },
    });
    expect(crossStepReplay.status).toBe("partial_failed");
    expect(crossStepReplay.completed_steps).toEqual([]);
  });
});
