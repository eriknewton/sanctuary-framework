// fail-before-exempt: the cooperative factory now requires a namespace insert store, so this file passes a recording no-op; its assertions are unchanged.
// fail-before-exempt: the synthetic help owner now reads as a loaded identity, because a cooperative session is confirmed against the identity manager; the help assertions are unchanged.
// fail-before-exempt: cognitive tools now take a session binding together with its boot decision; this file supplies a named boot decision beside its existing binding and asserts no new behavior.
// fail-before-exempt: this file's callTool helper now runs a tool's approvalTargetArgs before its handler, matching router.ts's gate-time projection order, so a gated tool (e.g. state_export) is exercised the way the shipped composition root wires it instead of denying on a missing binding; no new product behavior is asserted by this edit.
import { afterEach, describe, expect, it, vi } from "vitest";
import { recordingNamespaceInserts } from "../helpers/cooperative-test-options.js";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { AGENT_AUDIT_VIEW_FIELDS } from "../../src/operational/agent-audit-redaction.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import { createServer, toolResult, type ToolDefinition } from "../../src/router.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { readCallScopeNote, runInCallScope } from "../../src/operational/audit-log.js";
import { noteRefusalCause, type DenialCause, type DenialRecorder, type DenialRecordInput } from "../../src/agent-native/denial-ledger.js";
import { createReputationTools } from "../../src/reputation/tools.js";
import { StateVerificationError } from "../../src/cognitive/state-entry-open.js";
import { INTERNAL_SIGNING_DOMAIN_PREFIXES } from "../../src/core/signing-domains.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { createSanctuaryServer, type SanctuaryServer } from "../../src/index.js";
import {
  ApprovalProofStore,
  classifyApprovalRequest,
  canonicalJson,
  fingerprintIdentityId,
  fixedDenial,
  MemoryHandleOwnershipConflictError,
  MEMORY_HANDLE_RECORD_VERSION,
  MEMORY_HANDLE_REGISTRY_NAMESPACE,
  normalizedArgsHash,
  sha256,
  type SessionBinding,
} from "../../src/agent-native/safety-base.js";
import { createAgentNativeCooperativeTools, readPrimitiveResult } from "../../src/agent-native/cooperative-surface.js";
import { attributeFlows } from "../../src/castle-wall/audit/per-rule-report.js";
import { CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY } from "../../src/castle-wall/constants.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { CallbackApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import {
  DEFAULT_POLICY,
  writeDefaultPrincipalPolicyFile,
} from "../../src/principal-policy/loader.js";
import type { ApprovalResponse } from "../../src/principal-policy/types.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";
import { expectedRefusal, expectedRefusalBody } from "../helpers/expected-refusal.js";

const cleanup: Array<() => Promise<unknown>> = [];

afterEach(async () => {
  for (const close of cleanup.splice(0).reverse()) await close();
});

async function callTool(
  tools: ToolDefinition[],
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`missing tool: ${name}`);
  // Mirror router.ts:229 (the gate-time projection runs on the SAME args
  // object the handler receives, before the handler runs) and router.ts's
  // catch around it (a throwing approvalTargetArgs denies rather than
  // propagating). For state_export this is also what attaches the
  // approval binding the handler now requires (SDW-pattern exact-consent
  // binding, cognitive/tools.ts); tools without approvalTargetArgs are
  // unaffected.
  try {
    await tool.approvalTargetArgs?.(args);
  } catch {
    return fixedDenial(`audit:gate:${name}`) as unknown as Record<string, unknown>;
  }
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

async function callServerTool(
  app: SanctuaryServer,
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const handler = (
    app.server as unknown as { _requestHandlers: Map<string, Function> }
  )._requestHandlers.get("tools/call");
  if (!handler) throw new Error("tools/call handler not registered");
  const result = await handler(
    {
      method: "tools/call" as const,
      params: { name, arguments: args },
    },
    {}
  );
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
    { sessionBindingBootState: () => "state_BOUND_NAMED", currentSessionBinding: () => active }
  );
  await identityManager.load();
  const identity = await callTool(l1Tools, "identity_create", { label: "agent-a" });
  active = session(identity.identity_id as string);
  const { tools: facadeTools } = createAgentNativeCooperativeTools({ baselineNamespaceInserts: recordingNamespaceInserts(),
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

/** The details of the newest compound failure row, read raw from the operator audit log. */
async function lastCompoundFailure(env: { auditLog: AuditLog }): Promise<Record<string, unknown>> {
  const rows = (await env.auditLog.query({ operation_type: "sanctuary_compound_execute", limit: 50 })).entries
    .filter((entry) => entry.result === "failure");
  const last = rows.at(-1);
  if (!last) throw new Error("no compound failure row");
  return last.details ?? {};
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
  return createAgentNativeCooperativeTools({ baselineNamespaceInserts: recordingNamespaceInserts(),
    identityManager: env.identityManager,
    namespaceRegistry: env.namespaceRegistry,
    auditLog: env.auditLog,
    currentSessionBinding: () => env.active,
    primitiveTools,
    storage: env.storage,
    approvalProofStore: env.approvalProofStore,
  }).tools;
}

async function writeMemoryHandleRecord(
  stateStore: StateStore,
  masterKey: Uint8Array,
  identity: {
    identity_id: string;
    encrypted_private_key: Parameters<StateStore["write"]>[4];
  },
  handle: string
): Promise<void> {
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  await stateStore.write(
    MEMORY_HANDLE_REGISTRY_NAMESPACE,
    identity.identity_id,
    JSON.stringify({
      v: MEMORY_HANDLE_RECORD_VERSION,
      identity_id: identity.identity_id,
      handle,
    }),
    identity.identity_id,
    identity.encrypted_private_key,
    identityEncKey,
    {
      provenance: {
        origin_actor: "system",
        origin_ref: identity.identity_id,
      },
    }
  );
}

async function setupFilesystemSurface() {
  const path = await mkdtemp(join(tmpdir(), "memory-handle-"));
  cleanup.push(() => rm(path, { recursive: true, force: true }));
  const masterKey = generateRandomKey();
  const storage = new FilesystemStorage(path);
  let active: SessionBinding | undefined;
  const build = async (backend: StorageBackend = storage) => {
    const stateStore = new StateStore(backend, masterKey);
    const auditLog = new AuditLog(backend, masterKey);
    const { tools: l1Tools, identityManager, namespaceRegistry } = createL1Tools(
      stateStore,
      backend,
      masterKey,
      "recovery-key",
      auditLog,
      { sessionBindingBootState: () => "state_BOUND_NAMED", currentSessionBinding: () => active }
    );
    await identityManager.load();
    const approvalProofStore = new ApprovalProofStore();
    const { tools: facadeTools } = createAgentNativeCooperativeTools({ baselineNamespaceInserts: recordingNamespaceInserts(),
      identityManager,
      namespaceRegistry,
      auditLog,
      currentSessionBinding: () => active,
      primitiveTools: l1Tools,
      storage: backend,
      approvalProofStore,
    });
    return { l1Tools, identityManager, namespaceRegistry, facadeTools, auditLog };
  };
  const first = await build();
  const identity = await callTool(first.l1Tools, "identity_create", { label: "agent-a" });
  active = session(identity.identity_id as string);
  return {
    storage,
    masterKey,
    identity,
    get active() {
      return active;
    },
    set active(next: SessionBinding | undefined) {
      active = next;
    },
    first,
    build,
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

    const forgetTarget = await forgetTool.approvalTargetArgs!({
      key: "user_tz",
      mode: "secure",
      approval_ref: "approval:test",
      reason: "operator request",
    });
    expect(forgetTool.approvalTargetToolName).toBe("state_delete");
    expect(forgetTarget).toMatchObject({ key: "user_tz", reason: "operator request" });
  });

  it("keeps cooperative memory reachable after a fresh server surface opens the same fortress", async () => {
    const env = await setupFilesystemSurface();
    const remembered = await callTool(env.first.facadeTools, "sanctuary_remember", {
      key: "timezone",
      value: "America/Los_Angeles",
    });
    const handle = remembered.namespace_handle as string;
    expect(handle).toMatch(/^mem_[a-f0-9]{32}$/);

    const fresh = await env.build();
    expect(await fresh.namespaceRegistry.getOwner(handle)).toBe(env.identity.identity_id);
    const recalled = await callTool(fresh.facadeTools, "sanctuary_recall", {
      key: "timezone",
    });
    expect(recalled).toMatchObject({
      value: "America/Los_Angeles",
      verified: true,
    });
  });

  it("keeps another identity out of a restarted handle owner map", async () => {
    const env = await setupFilesystemSurface();
    const bob = await callTool(env.first.l1Tools, "identity_create", { label: "agent-b" });
    const remembered = await callTool(env.first.facadeTools, "sanctuary_remember", {
      key: "timezone",
      value: "America/Los_Angeles",
    });
    const handle = remembered.namespace_handle as string;

    const fresh = await env.build();
    env.active = session(bob.identity_id as string);
    const crossRecall = await callTool(fresh.facadeTools, "sanctuary_recall", {
      key: "timezone",
      opts: { namespace: handle },
    });
    expect(crossRecall.denied).toBe(true);
    expect(crossRecall).not.toHaveProperty("value");
  });

  it("refuses a cooperative memory call when the handle record cannot be stored", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const stateStore = new StateStore(storage, masterKey);
    let active: SessionBinding | undefined;
    const { tools: l1Tools, identityManager, namespaceRegistry } = createL1Tools(
      stateStore,
      storage,
      masterKey,
      "recovery-key",
      auditLog,
      { sessionBindingBootState: () => "state_BOUND_NAMED", currentSessionBinding: () => active }
    );
    await identityManager.load();
    const identity = await callTool(l1Tools, "identity_create", { label: "agent-a" });
    active = session(identity.identity_id as string);
    const originalWrite = storage.write.bind(storage);
    storage.write = async (namespace, key, data) => {
      if (namespace === MEMORY_HANDLE_REGISTRY_NAMESPACE) {
        throw new Error("forced handle persistence failure");
      }
      return originalWrite(namespace, key, data);
    };
    const { tools: facadeTools } = createAgentNativeCooperativeTools({ baselineNamespaceInserts: recordingNamespaceInserts(),
      identityManager,
      namespaceRegistry,
      auditLog,
      currentSessionBinding: () => active,
      primitiveTools: l1Tools,
      storage,
      approvalProofStore: new ApprovalProofStore(),
    });

    const result = await callTool(facadeTools, "sanctuary_remember", {
      key: "timezone",
      value: "America/Los_Angeles",
    });
    expect(result.denied).toBe(true);
    expect(result).not.toHaveProperty("namespace_handle");

    storage.write = originalWrite;
    const retry = await callTool(facadeTools, "sanctuary_remember", {
      key: "timezone",
      value: "America/Los_Angeles",
    });
    expect(retry.namespace_handle).toMatch(/^mem_[a-f0-9]{32}$/);
  });

  it("refuses duplicate verified memory handle records before trusting scan order", async () => {
    const exerciseOrder = async (labels: readonly [string, string]) => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const auditLog = new AuditLog(storage, masterKey);
      const stateStore = new StateStore(storage, masterKey);
      let active: SessionBinding | undefined;
      const { tools: l1Tools, identityManager, namespaceRegistry } = createL1Tools(
        stateStore,
        storage,
        masterKey,
        "recovery-key",
        auditLog,
        { sessionBindingBootState: () => "state_BOUND_NAMED", currentSessionBinding: () => active }
      );
      await identityManager.load();
      const firstCreated = await callTool(l1Tools, "identity_create", { label: labels[0] });
      const secondCreated = await callTool(l1Tools, "identity_create", { label: labels[1] });
      const byLabel = new Map([
        [labels[0], identityManager.get(firstCreated.identity_id as string)!],
        [labels[1], identityManager.get(secondCreated.identity_id as string)!],
      ]);
      const handle = "mem_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

      for (const label of labels) {
        await writeMemoryHandleRecord(stateStore, masterKey, byLabel.get(label)!, handle);
      }

      active = session(byLabel.get("agent-a")!.identity_id);
      await expect(namespaceRegistry.getOwner(handle)).rejects.toBeInstanceOf(
        MemoryHandleOwnershipConflictError
      );

      const { tools: facadeTools } = createAgentNativeCooperativeTools({ baselineNamespaceInserts: recordingNamespaceInserts(),
        identityManager,
        namespaceRegistry,
        auditLog,
        currentSessionBinding: () => active,
        primitiveTools: l1Tools,
        storage,
        approvalProofStore: new ApprovalProofStore(),
      });
      const denied = await callTool(facadeTools, "sanctuary_recall", {
        key: "timezone",
        opts: { namespace: handle },
      });
      expect(denied.denied).toBe(true);
      expect(denied).not.toHaveProperty("value");
    };

    await exerciseOrder(["agent-a", "agent-b"]);
    await exerciseOrder(["agent-b", "agent-a"]);
  });

  it("converges first-use handle claims across fresh registries on one fortress", async () => {
    const env = await setupFilesystemSurface();
    const left = await env.build();
    const right = await env.build();
    const [a, b] = await Promise.all([
      callTool(left.facadeTools, "sanctuary_remember", {
        key: "left",
        value: "one",
      }),
      callTool(right.facadeTools, "sanctuary_remember", {
        key: "right",
        value: "two",
      }),
    ]);

    expect(a.namespace_handle).toMatch(/^mem_[a-f0-9]{32}$/);
    expect(b.namespace_handle).toBe(a.namespace_handle);
    const recalledLeft = await callTool((await env.build()).facadeTools, "sanctuary_recall", {
      key: "left",
    });
    const recalledRight = await callTool((await env.build()).facadeTools, "sanctuary_recall", {
      key: "right",
    });
    expect(recalledLeft.value).toBe("one");
    expect(recalledRight.value).toBe("two");
  });

  it("keeps cooperative memory reachable after the real server composition restarts", async () => {
    const home = await createTempHome("memory-handle-composition");
    cleanup.push(home.cleanup);
    await mkdir(home.defaultFortressPath, { recursive: true, mode: 0o700 });
    const { policyPath } = await writeDefaultPrincipalPolicyFile(home.defaultFortressPath);
    const policy = await readFile(policyPath, "utf8");
    await writeFile(policyPath, policy.replace("type: stderr", "type: callback"), {
      mode: 0o600,
    });
    const originalSessionIdentity = process.env.SANCTUARY_SESSION_IDENTITY_ID;
    const approve = async (): Promise<ApprovalResponse> => ({
      decision: "approve" as const,
      decided_at: new Date().toISOString(),
      decided_by: "human" as const,
    });
    let first: SanctuaryServer | undefined;
    let second: SanctuaryServer | undefined;
    try {
      first = await createSanctuaryServer({
        passphrase: TEST_PASSPHRASE,
        approvalCallback: approve,
      });
      const identity = await callServerTool(first, "identity_create", {
        label: "agent-a",
      });
      process.env.SANCTUARY_SESSION_IDENTITY_ID = identity.identity_id as string;
      const remembered = await callServerTool(first, "sanctuary_remember", {
        key: "timezone",
        value: "America/Los_Angeles",
      });
      const handle = remembered.namespace_handle as string;
      expect(handle).toMatch(/^mem_[a-f0-9]{32}$/);
      await first.cleanup();
      first = undefined;

      second = await createSanctuaryServer({
        passphrase: TEST_PASSPHRASE,
        approvalCallback: approve,
      });
      const recalled = await callServerTool(second, "sanctuary_recall", {
        key: "timezone",
      });
      expect(recalled).toMatchObject({
        value: "America/Los_Angeles",
        verified: true,
      });
      const who = await callServerTool(second, "sanctuary_who_am_i");
      expect(who.memory_namespace_handle).toBe(handle);
    } finally {
      if (first) await first.cleanup();
      if (second) await second.cleanup();
      if (originalSessionIdentity === undefined) {
        delete process.env.SANCTUARY_SESSION_IDENTITY_ID;
      } else {
        process.env.SANCTUARY_SESSION_IDENTITY_ID = originalSessionIdentity;
      }
    }
  }, 60_000);

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

    const restarted = createAgentNativeCooperativeTools({ baselineNamespaceInserts: recordingNamespaceInserts(),
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

    const afterImportTools = createAgentNativeCooperativeTools({ baselineNamespaceInserts: recordingNamespaceInserts(),
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
    const staleTools = createAgentNativeCooperativeTools({ baselineNamespaceInserts: recordingNamespaceInserts(),
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

  it("routes the seven evaluate phrasings to a read-only tool or CLI guidance and leaves remember/recall byte-identical", async () => {
    const env = await setup();
    // Each phrasing an installing agent asks before it trusts the socket, with
    // the state it must land in and the read-only tool (or null for a
    // CLI-only answer) that state routes to.
    const phrasings: Array<[string, string, string | null]> = [
      ["should I install this", "install_decision", "sovereignty_audit"],
      ["what does this protect", "protections", "sanctuary_active_protections"],
      ["what are the bounds", "bounds", "monitor_health"],
      ["which platforms", "bounds", "monitor_health"],
      ["what do you not do", "bounds", "monitor_health"],
      ["how do I verify", "verify", "monitor_health"],
      ["how do I uninstall", "uninstall", null],
    ];
    for (const [intent, question, tool] of phrasings) {
      const result = await callTool(env.facadeTools, "sanctuary_help", { intent });
      expect(result.intent_class, intent).toBe("evaluate");
      expect(result.evaluate_question, intent).toBe(question);
      expect(result.safety_class, intent).toBe("ordinary");
      expect(result.tool, intent).toBe(tool);
      expect(typeof result.guidance, intent).toBe("string");
      // A non-null route: a runnable read-only tool, or the CLI command.
      expect(result.tool !== null || (result.guidance as string).length > 0, intent).toBe(true);
      expect(result.remediation_class, intent).toBeUndefined();
      const related = result.related_tools as Array<{ tool: string; tier: string }>;
      expect(related.map((entry) => entry.tool).sort()).toEqual([
        "monitor_health",
        "sanctuary_active_protections",
        "sanctuary_policy_status",
        "sovereignty_audit",
      ]);
      expect(related.find((entry) => entry.tool === "sanctuary_policy_status")!.tier).toContain("Tier 1");
      expect(JSON.stringify(result)).not.toContain("\u2014");
    }
    const verify = await callTool(env.facadeTools, "sanctuary_help", { intent: "how do I verify" });
    expect(verify.guidance).toContain("sanctuary doctor --json");
    const uninstall = await callTool(env.facadeTools, "sanctuary_help", { intent: "how do I uninstall" });
    expect(uninstall.guidance).toContain("sanctuary uninstall");
    // The route also matches "unwrap"; the guidance must name the harness-config
    // restore too (README "Uninstall": footprint vs harness config are different verbs).
    expect(uninstall.guidance).toContain("sanctuary protect --unwrap");
    expect(uninstall.example).toBeNull();
    const bounds = await callTool(env.facadeTools, "sanctuary_help", { intent: "what are the bounds" });
    expect(bounds.guidance).toContain("ASSURANCE_MATRIX.md");
    expect(bounds.guidance).toContain("macOS: proven.");
    expect(bounds.guidance).toContain("Linux enforcement is proven on Ubuntu 24.04 (x86-64) only;");
    expect(bounds.guidance).toContain("Windows");
    expect(bounds.guidance).toContain("Tier 1");

    // The pre-existing routes are byte-identical: same fields, same values,
    // and none of the evaluate-only fields appear on them.
    const remember = await callTool(env.facadeTools, "sanctuary_help", { intent: "remember my timezone" });
    expect(remember).toEqual({
      safety_class: "ordinary",
      tool: "sanctuary_remember",
      example: { key: "user_tz", value: "America/Los_Angeles" },
      why_sanctuary: "State is encrypted, identity-bound, and audited.",
      audit_ref: remember.audit_ref,
    });
    const recall = await callTool(env.facadeTools, "sanctuary_help", { intent: "recall my timezone" });
    expect(recall).toEqual({
      safety_class: "ordinary",
      tool: "sanctuary_recall",
      example: { key: "user_tz" },
      why_sanctuary: "Recall preserves verification status in the response.",
      audit_ref: recall.audit_ref,
    });
    // A gated needle still wins over an evaluate needle.
    const gatedEvaluate = await callTool(env.facadeTools, "sanctuary_help", {
      intent: "what are the bounds on exporting my identity bundle",
    });
    expect(gatedEvaluate.safety_class).toBe("gated");
    expect(gatedEvaluate.intent_class).toBeUndefined();
  });

  it("routes an evaluate noun before the memory verbs, keeps nounless memory reads on recall, and offers no runnable example on the Tier 1 policy read", async () => {
    const env = await setup();
    // state_EVALUATE_NOUN: a bare read verb beside an evaluate noun is a
    // question about the socket, never a memory read.
    const readBounds = await callTool(env.facadeTools, "sanctuary_help", { intent: "read the bounds" });
    expect(readBounds.intent_class).toBe("evaluate");
    expect(readBounds.evaluate_question).toBe("bounds");
    expect(readBounds.tool).toBe("monitor_health");
    const getPlatforms = await callTool(env.facadeTools, "sanctuary_help", { intent: "get the list of platforms" });
    expect(getPlatforms.intent_class).toBe("evaluate");
    expect(getPlatforms.evaluate_question).toBe("bounds");
    expect(getPlatforms.tool).toBe("monitor_health");
    // state_RECALL: the same verbs without an evaluate noun still reach
    // recall, with the byte-identical pre-existing response shape.
    for (const intent of ["read my timezone", "get user_tz"]) {
      const recall = await callTool(env.facadeTools, "sanctuary_help", { intent });
      expect(recall, intent).toEqual({
        safety_class: "ordinary",
        tool: "sanctuary_recall",
        example: { key: "user_tz" },
        why_sanctuary: "Recall preserves verification status in the response.",
        audit_ref: recall.audit_ref,
      });
    }
    // Gated still outranks the noun: "policy" is a gated needle, so a tier
    // question that names the policy is sent for review (safety_class gated,
    // tool null, remediation request_review, the generic placeholder example)
    // rather than given runnable guidance; the needle that fired stays
    // server-side as the probe key and is never echoed, so the response does
    // not reveal which word tripped it. That is the safe order: the gated list
    // is the operator's veto and nothing downstream may re-route around it.
    const policyTier = await callTool(env.facadeTools, "sanctuary_help", {
      intent: "which policy tier waits on a human",
    });
    expect(policyTier.safety_class).toBe("gated");
    expect(policyTier.tool).toBeNull();
    expect(policyTier.example).toEqual({ args: "<operator-approved placeholders only>" });
    expect(policyTier.probe_key).toBeUndefined();
    expect(policyTier.remediation_class).toBe("request_review");
    expect(policyTier.intent_class).toBeUndefined();
    // The Tier 1 route names the tool but never hands out an example to run:
    // following one would trigger an operator prompt and audit it as runnable.
    const tier = await callTool(env.facadeTools, "sanctuary_help", { intent: "which tier needs a human" });
    expect(tier.intent_class).toBe("evaluate");
    expect(tier.evaluate_question).toBe("tiers");
    expect(tier.tool).toBeNull();
    expect(tier.example).toBeNull();
    expect(tier.guidance).toContain("sanctuary_policy_status");
    expect(tier.guidance).toContain("Tier 1");
    const related = tier.related_tools as Array<{ tool: string; tier: string }>;
    expect(related.find((entry) => entry.tool === "sanctuary_policy_status")!.tier).toContain("Tier 1");
    // The help call above is the latest sanctuary_help audit row.
    const helpAudits = await env.auditLog.query({ operation_type: "sanctuary_help", limit: 50 });
    const tierRow = helpAudits.entries.at(-1);
    expect(tierRow).toBeDefined();
    expect(tierRow!.details).toMatchObject({ safety_class: "ordinary", runnable_example: false });
  });

  it("a memory verb outranks an evaluate noun: ordinary intents receive their memory argument template", async () => {
    const env = await setup();
    // state_REMEMBER wins over any evaluate noun in the same intent.
    for (const intent of [
      "remember platform=linux",
      "save the evidence",
      "store my install notes",
      "remember that the verification passed",
      "store the tier I am in",
    ]) {
      const result = await callTool(env.facadeTools, "sanctuary_help", { intent });
      expect(result, intent).toEqual({
        safety_class: "ordinary",
        tool: "sanctuary_remember",
        example: { key: "<key>", value: "<value>" },
        why_sanctuary: "State is encrypted, identity-bound, and audited.",
        audit_ref: result.audit_ref,
      });
    }
    // state_RECALL wins when the verb is recall or lookup, and a bare read of
    // the agent's own data ("protected" is not an evaluate noun) stays a read.
    for (const intent of ["recall my bounds note", "read my protected key", "lookup the platform I saved"]) {
      const result = await callTool(env.facadeTools, "sanctuary_help", { intent });
      expect(result, intent).toEqual({
        safety_class: "ordinary",
        tool: "sanctuary_recall",
        example: { key: "<key>" },
        why_sanctuary: "Recall preserves verification status in the response.",
        audit_ref: result.audit_ref,
      });
    }
    // The seven evaluate phrasings, which carry no memory verb, still evaluate.
    for (const intent of [
      "should I install this",
      "what does this protect",
      "what are the bounds",
      "which platforms",
      "what do you not do",
      "how do I verify",
      "how do I uninstall",
    ]) {
      const result = await callTool(env.facadeTools, "sanctuary_help", { intent });
      expect(result.intent_class, intent).toBe("evaluate");
    }
  });
  it("reports binding availability only for bound-only help guidance in an unbound session", async () => {
    const storage = new MemoryStorage();
    const key = generateRandomKey();
    const auditLog = new AuditLog(storage, key);
    const { tools, identityManager, namespaceRegistry } = createL1Tools(new StateStore(storage, key), storage, key, "recovery-key", auditLog);
    let binding: SessionBinding | undefined = session("help-owner");
    // Test-only manager: the synthetic owner is a loaded identity, so its binding is a confirmed session.
    vi.spyOn(identityManager, "get").mockImplementation((id: string) => ({ identity_id: id }) as ReturnType<typeof identityManager.get>);
    const facade = createAgentNativeCooperativeTools({ baselineNamespaceInserts: recordingNamespaceInserts(), identityManager, namespaceRegistry, auditLog,
      primitiveTools: tools, currentSessionBinding: () => binding,
    }).tools;
    const bound = await callTool(facade, "sanctuary_help", { intent: "save the note" });
    expect(bound).toMatchObject({ tool: "sanctuary_remember" });
    expect(bound).not.toHaveProperty("session_bound");
    binding = undefined;
    const unbound = await callTool(facade, "sanctuary_help", { intent: "save the note" });
    expect(unbound).toMatchObject({ tool: "sanctuary_remember", session_bound: false });
    const posture = await callTool(facade, "sanctuary_help", { intent: "what does this protect" });
    expect(posture).toHaveProperty("tool", "sanctuary_active_protections");
    expect(posture).not.toHaveProperty("session_bound");
  });

  it("returns only disclosable who-am-i fields and positive active protections", async () => {
    const env = await setup();

    const who = await callTool(env.facadeTools, "sanctuary_who_am_i");
    expect(who.label).toBe("agent-a");
    expect(who.active_identity_fingerprint).toMatch(/^sha256:/);
    expect(who.memory_namespace_handle).toBeNull();
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
    // A rate denial is the one boundary refusal: no retry bucket tells the agent which limit it met.
    expect(last).toEqual(expectedRefusalBody());
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
    // The agent sees the one refusal; the step detail is in the operator failure row.
    expect(result).toEqual(expectedRefusalBody());
    const resultRow = await lastCompoundFailure(env);
    expect(result.status).not.toBe("completed");
    expect(resultRow.completed_steps ?? []).toEqual([]);
    expect(resultRow.failed_step).toBe("step-1");

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
    // The agent sees the one refusal; the step detail is in the operator failure row.
    expect(result).toEqual(expectedRefusalBody());
    const resultRow = await lastCompoundFailure(env);
    expect(resultRow.completed_steps ?? []).toEqual([]);
    expect(resultRow.failed_step).toBe("step-2");

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
    // The agent sees the one refusal; the step detail is in the operator failure row.
    expect(invalidLaterProof).toEqual(expectedRefusalBody());
    const invalidLaterProofRow = await lastCompoundFailure(env);
    expect(invalidLaterProofRow.completed_steps ?? []).toEqual([]);
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
    // The agent sees the one refusal; the step detail is in the operator failure row.
    expect(earlierFailure).toEqual(expectedRefusalBody());
    const earlierFailureRow = await lastCompoundFailure(env);
    expect(earlierFailureRow.completed_steps ?? []).toEqual([]);

    const releasedProof = await callTool(env.facadeTools, "sanctuary_compound_execute", {
      steps: [
        { tool: "sanctuary_recall", args: { key: "missing_first" } },
        { tool: "sanctuary_forget", args: { key: "compound_key", mode: "secure" } },
      ],
      approvals: { "step-2": futureProof.approval_ref },
    });
    // The agent sees the one refusal; the step detail is in the operator failure row.
    expect(releasedProof).toEqual(expectedRefusalBody());
    const releasedProofRow = await lastCompoundFailure(env);
    expect(releasedProofRow.completed_steps ?? []).toEqual([]);

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
    // The agent sees the one refusal; the step detail is in the operator failure row.
    expect(crossPlanReplay).toEqual(expectedRefusalBody());
    const crossPlanReplayRow = await lastCompoundFailure(env);
    expect(crossPlanReplayRow.completed_steps ?? []).toEqual([]);

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
    // The agent sees the one refusal; the step detail is in the operator failure row.
    expect(crossStepReplay).toEqual(expectedRefusalBody());
    const crossStepReplayRow = await lastCompoundFailure(env);
    expect(crossStepReplayRow.completed_steps ?? []).toEqual([]);
  });
});

// ── Operator causes through the router ────────────────────────────────────

interface RecordedDenial { cause: DenialCause; input: DenialRecordInput }

/**
 * The cooperative surface behind the real router, with a ledger that records each refusal's cause. With `primitives`
 * set, the primitive and reputation tools are served beside it.
 */
async function routerRig(overrides: Record<string, ToolDefinition["handler"]> = {}, primitivesServed = false) {
  const env = await setup();
  let primitives = env.l1Tools;
  for (const [name, handler] of Object.entries(overrides)) primitives = toolsWithOverride(primitives, name, handler);
  const tools = [
    ...facadeWithPrimitives(env, primitives),
    // The composition root assigns primitives their class; with no integrity findings here, the class changes nothing.
    ...(primitivesServed
      ? [...env.l1Tools, ...createReputationTools(env.storage, env.masterKey, env.identityManager, env.auditLog).tools]
        .map((tool): ToolDefinition => ({ ...tool, tool_class: tool.tool_class ?? "write" }))
      : []),
  ];
  const recorded: RecordedDenial[] = [];
  const denialLedger: DenialRecorder = { record: (cause, input) => { recorded.push({ cause, input }); } };
  const server = createServer(tools, { auditLog: env.auditLog, denialLedger, currentSessionBinding: () => env.active });
  const client = new Client({ name: "cooperative-causes", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  cleanup.push(() => server.close());
  cleanup.push(() => client.close());
  const call = (name: string, args: Record<string, unknown> = {}) => client.callTool({ name, arguments: args });
  const body = (result: Awaited<ReturnType<typeof call>>) =>
    JSON.parse((result.content as Array<{ text: string }>)[0]!.text) as Record<string, unknown>;
  return { env, tools, recorded, call, body };
}

type RouterRig = Awaited<ReturnType<typeof routerRig>>;

const refusingRead: ToolDefinition["handler"] = async () => toolResult({ error: "fixture refusal" });
const throwingRead: ToolDefinition["handler"] = async () => { throw new Error("fixture primitive fault"); };

const COOPERATIVE_CAUSE_CASES: Array<{
  cause: DenialCause;
  overrides?: Record<string, ToolDefinition["handler"]>;
  prepare?: (r: RouterRig) => Promise<void>;
  act: (r: RouterRig) => ReturnType<RouterRig["call"]>;
}> = [
  {
    cause: "primitive_refused",
    overrides: { state_read: refusingRead },
    act: (r) => r.call("sanctuary_recall", { key: "k" }),
  },
  {
    cause: "hidden_key",
    prepare: async (r) => {
      await r.call("sanctuary_remember", { key: "k", value: "v" });
      await r.call("sanctuary_hide", { key: "k" });
    },
    act: (r) => r.call("sanctuary_recall", { key: "k" }),
  },
  {
    cause: "cooperative_filter_refused",
    act: (r) => r.call("sanctuary_events_open_cursor", { filter: { url: "https://example.invalid" } }),
  },
  {
    cause: "audit_integrity_findings",
    prepare: async (r) => {
      vi.spyOn(r.env.auditLog, "getAuditChainVerdict").mockResolvedValue({ status: "findings" } as never);
    },
    act: (r) => r.call("sanctuary_audit_search", { query: "x" }),
  },
  {
    cause: "compound_step_refused",
    overrides: { state_read: refusingRead },
    act: (r) => r.call("sanctuary_compound_execute", { steps: [{ tool: "sanctuary_recall", args: { key: "k" } }] }),
  },
  {
    cause: "compound_approval_missing",
    act: (r) => r.call("sanctuary_compound_execute", { steps: [{ tool: "sanctuary_forget", args: { key: "k", mode: "secure" } }] }),
  },
  {
    cause: "compound_fault",
    act: (r) => r.call("sanctuary_compound_execute", { steps: [{ tool: "not_a_cooperative_tool", args: {} }] }),
  },
  {
    cause: "cooperative_fault",
    overrides: { state_read: throwingRead },
    act: (r) => r.call("sanctuary_recall", { key: "k" }),
  },
  {
    cause: "cursor_unknown",
    act: (r) => r.call("sanctuary_events_read", { cursor: "cursor:never-opened" }),
  },
  {
    cause: "cursor_spent",
    prepare: async (r) => {
      const opened = r.body(await r.call("sanctuary_events_open_cursor", {}));
      (r as RouterRig & { cursor?: string }).cursor = opened.cursor as string;
      for (let i = 0; i < 10; i++) await r.call("sanctuary_events_read", { cursor: opened.cursor });
    },
    act: (r) => r.call("sanctuary_events_read", { cursor: (r as RouterRig & { cursor?: string }).cursor }),
  },
  {
    cause: "cursor_table_full",
    prepare: async (r) => {
      for (let i = 0; i < 64; i++) await r.call("sanctuary_events_open_cursor", {});
    },
    act: (r) => r.call("sanctuary_events_open_cursor", {}),
  },
  {
    cause: "cursor_open_failed",
    prepare: async (r) => {
      vi.spyOn(r.env.auditLog, "query").mockRejectedValue(new Error("fixture query fault"));
    },
    act: (r) => r.call("sanctuary_events_open_cursor", {}),
  },
];

describe("every cooperative refusal names its operator cause", () => {
  it.each(COOPERATIVE_CAUSE_CASES.map((c) => [c.cause, c] as const))("%s: the agent gets the one refusal and the ledger records that cause", async (_cause, c) => {
    const r = await routerRig(c.overrides);
    await c.prepare?.(r);
    r.recorded.length = 0;
    expect(await c.act(r)).toEqual(expectedRefusal());
    expect(r.recorded.map((entry) => entry.cause)).toEqual([c.cause]);
  });

  it("a widened audit-search scope and a non-secure forget mode, which schema validation stops before the router's boundary, note their causes at the handler", async () => {
    const env = await setup();
    const tool = (name: string) => env.facadeTools.find((candidate) => candidate.name === name)!;
    const noted = async (name: string, args: Record<string, unknown>) =>
      runInCallScope(async (scope) => {
        expect(await tool(name).handler(args)).toEqual(toolResult(fixedDenial()));
        return readCallScopeNote(scope)?.cause;
      });
    expect(await noted("sanctuary_audit_search", { query: "x", scope: "everyone" })).toBe("audit_scope_refused");
    expect(await noted("sanctuary_forget", { key: "k", mode: "fast", approval_ref: "a" })).toBe("cooperative_filter_refused");
  });

  it("a refused remember's ledger record links its intent row", async () => {
    const r = await routerRig();
    const appendCritical = r.env.auditLog.appendCritical.bind(r.env.auditLog);
    vi.spyOn(r.env.auditLog, "appendCritical").mockImplementation(async (entry) => {
      if (entry.operation === "sanctuary_remember") throw new Error("fixture completion audit failure");
      return appendCritical(entry);
    });
    expect(await r.call("sanctuary_remember", { key: "k", value: "v" })).toEqual(expectedRefusal());
    expect(r.recorded).toHaveLength(1);
    expect(r.recorded[0]!.cause).toBe("cooperative_fault");
    const intents = (await r.env.auditLog.query({ operation_type: "sanctuary_remember_intent", limit: 10 })).entries;
    expect(intents).toHaveLength(1);
    expect(r.recorded[0]!.input.linked_ref).toBe(intents[0]!.details?.audit_ref);
  });

  it("a compound failure returns the one refusal and its step detail is in the operator failure row", async () => {
    const r = await routerRig({ state_read: refusingRead });
    expect(await r.call("sanctuary_compound_execute", {
      steps: [{ tool: "sanctuary_recall", args: { key: "a" } }, { tool: "sanctuary_recall", args: { key: "b" } }],
    })).toEqual(expectedRefusal());
    expect(r.recorded.map((entry) => entry.cause)).toEqual(["compound_step_refused"]);
    const rows = (await r.env.auditLog.query({ operation_type: "sanctuary_compound_execute", limit: 10 })).entries;
    expect(rows).toHaveLength(1);
    expect(rows[0]!.result).toBe("failure");
    expect(rows[0]!.details).toMatchObject({ failed_step: "step-1", completed_steps: [], release_not_consume: true });
  });

  it("a classified success whose text does not parse is a cooperative fault (defensive, not a shipped path)", async () => {
    // A two-item success shape whose first item is plain text: the classifier accepts it, the body read does not.
    const raw = { content: [{ type: "text", text: "plain report" }, { type: "text", text: "{}" }] };
    const read = await runInCallScope(async (scope) => ({
      result: readPrimitiveResult("sovereignty_audit", raw),
      cause: readCallScopeNote(scope)?.cause,
    }));
    expect(read).toEqual({ result: { outcome: "refused" }, cause: "cooperative_fault" });
  });
});

describe("a primitive's result is classified before it is read", () => {
  it("a non-JSON refusal is recorded primitive_refused", async () => {
    const r = await routerRig({ state_read: async () => ({ content: [{ type: "text", text: "not json" }] }) });
    expect(await r.call("sanctuary_recall", { key: "k" })).toEqual(expectedRefusal());
    expect(r.recorded.map((entry) => entry.cause)).toEqual(["primitive_refused"]);
  });

  it("a two-item refusal is recorded primitive_refused", async () => {
    const verified = JSON.stringify({ value: "v", version: 1, integrity_verified: true, signature_verified: true });
    const r = await routerRig({
      state_read: async () => ({ content: [{ type: "text", text: verified }, { type: "text", text: "trailing" }] }),
    });
    expect(await r.call("sanctuary_recall", { key: "k" })).toEqual(expectedRefusal());
    expect(r.recorded.map((entry) => entry.cause)).toEqual(["primitive_refused"]);
  });

  it("an ordinary success is parsed and succeeds", async () => {
    const r = await routerRig();
    expect(r.body(await r.call("sanctuary_remember", { key: "k", value: "stored" }))).toMatchObject({ key: "k" });
    expect(r.body(await r.call("sanctuary_recall", { key: "k" }))).toMatchObject({ value: "stored", verified: true });
    expect(r.recorded).toEqual([]);
  });
});

describe("each primitive's success inside the cooperative layer stays a success and writes no ledger row", () => {
  it("a state_write success stays a success and writes no ledger row", async () => {
    const r = await routerRig();
    expect((await r.call("sanctuary_remember", { key: "k", value: "v" })).isError).not.toBe(true);
    expect(r.recorded).toEqual([]);
  });

  it("a state_read success, through recall and through hide, stays a success and writes no ledger row", async () => {
    const r = await routerRig();
    await r.call("sanctuary_remember", { key: "k", value: "v" });
    await r.call("sanctuary_remember", { key: "h", value: "w" });
    expect(r.body(await r.call("sanctuary_recall", { key: "k" }))).toMatchObject({ value: "v", verified: true });
    expect(r.body(await r.call("sanctuary_hide", { key: "h" }))).toMatchObject({ hidden: true });
    expect(r.recorded).toEqual([]);
  });

  it("a state_read success whose body carries a nested error key stays a success and writes no ledger row", async () => {
    // The classifier reads only top-level verdict keys, so a nested `error` is data; a top-level `error: null` is a refusal.
    const body = { value: "v", version: 1, integrity_verified: true, signature_verified: true, metadata: { error: "nested" } };
    const r = await routerRig({ state_read: async () => toolResult(body) });
    expect(r.body(await r.call("sanctuary_recall", { key: "k" }))).toMatchObject({ value: "v", verified: true });
    expect(r.recorded).toEqual([]);
  });

  it("a state_delete success stays a success and writes no ledger row", async () => {
    const r = await routerRig();
    await r.call("sanctuary_remember", { key: "k", value: "v" });
    expect(r.body(await r.call("sanctuary_forget", { key: "k", mode: "secure", approval_ref: "approval:fixture" })))
      .toMatchObject({ mode: "secure" });
    expect(r.recorded).toEqual([]);
  });

  it("compound remember, recall and hide step successes stay a success and write no ledger row", async () => {
    const r = await routerRig();
    expect(r.body(await r.call("sanctuary_compound_execute", {
      steps: [
        { tool: "sanctuary_remember", args: { key: "c", value: "v" } },
        { tool: "sanctuary_recall", args: { key: "c" } },
        { tool: "sanctuary_hide", args: { key: "c" } },
      ],
    }))).toMatchObject({ status: "completed", completed_steps: ["step-1", "step-2", "step-3"] });
    expect(r.recorded).toEqual([]);
  });
});

describe("who-am-I and capabilities read the session once", () => {
  it("who-am-I and capabilities read the identity manager once per call, and the row's identity is that one read's value", async () => {
    const r = await routerRig();
    const identityId = r.env.identity.identity_id as string;
    const get = vi.spyOn(r.env.identityManager, "get");
    for (const name of ["sanctuary_who_am_i", "sanctuary_capabilities"]) {
      get.mockClear();
      expect((await r.call(name)).isError).not.toBe(true);
      expect(get, name).toHaveBeenCalledTimes(1);
      const rows = (await r.env.auditLog.query({ operation_type: name, limit: 10 })).entries;
      expect(rows.at(-1)?.identity_id, name).toBe(identityId);
    }
  });
});

// ── Primitive and reputation causes through the router ────────────────────

const PRIMITIVE_CAUSE_CASES: Array<{
  cause: DenialCause;
  act: (r: RouterRig) => Promise<Awaited<ReturnType<RouterRig["call"]>>>;
}> = [
  { cause: "namespace_refused", act: (r) => r.call("state_write", { namespace: "_reputation", key: "k", value: "v" }) },
  { cause: "storage_name_unusable", act: (r) => r.call("state_write", { namespace: "plain", key: "key-\u4E2D", value: "v" }) },
  { cause: "target_absent", act: (r) => r.call("state_read", { namespace: "plain", key: "never-written" }) },
  {
    cause: "sign_identity_mismatch",
    act: async (r) => {
      const other = await callTool(r.env.l1Tools, "identity_create", { label: "agent-b" });
      return r.call("identity_sign", { identity_id: other.identity_id, payload: toBase64url(stringToBytes("hello")) });
    },
  },
  {
    cause: "sign_reserved_domain",
    act: (r) => r.call("identity_sign", {
      identity_id: r.env.identity.identity_id,
      payload: toBase64url(stringToBytes(`${INTERNAL_SIGNING_DOMAIN_PREFIXES[0]}forged`)),
    }),
  },
  {
    cause: "import_unverified",
    act: async (r) => {
      expect((await r.call("state_write", { namespace: "plain", key: "k", value: "v" })).isError).not.toBe(true);
      const exported = await callTool(r.env.l1Tools, "state_export", { namespace: "plain" });
      expect(typeof exported.bundle).toBe("string");
      vi.spyOn(StateStore.prototype, "assertImportVersionFloors")
        .mockRejectedValue(new StateVerificationError("signature_mismatch", "fixture verification failure"));
      return r.call("state_import", { bundle: exported.bundle });
    },
  },
  {
    cause: "reputation_import_unverified",
    act: (r) => r.call("reputation_import", { bundle: toBase64url(stringToBytes("{}")) }),
  },
];

describe("every primitive and reputation refusal names its operator cause", () => {
  it.each(PRIMITIVE_CAUSE_CASES.map((c) => [c.cause, c] as const))("%s: the agent gets the one refusal and the ledger records that cause", async (_cause, c) => {
    const r = await routerRig({}, true);
    const result = await c.act(r);
    expect(result).toEqual(expectedRefusal());
    expect(r.recorded.map((entry) => entry.cause).at(-1)).toBe(c.cause);
  });

  it("an unusable stored name and an absent key give the same envelope and different ledger causes", async () => {
    const r = await routerRig();
    const unusable = await r.call("sanctuary_remember", { key: "key-\u4E2D", value: "v" });
    const absent = await r.call("sanctuary_recall", { key: "never-written" });
    expect(unusable).toEqual(expectedRefusal());
    expect(absent).toEqual(unusable);
    expect(r.recorded.map((entry) => entry.cause)).toEqual(["storage_name_unusable", "target_absent"]);
  });

  it("a cause noted by a primitive inside a cooperative call reaches the ledger as that cause", async () => {
    const r = await routerRig();
    expect(await r.call("sanctuary_recall", { key: "never-written" })).toEqual(expectedRefusal());
    expect(r.recorded.map((entry) => entry.cause)).toEqual(["target_absent"]);
  });

  it("a primitive's note inside remember wins, and the intent row shares the call's call_ref", async () => {
    const r = await routerRig();
    expect(await r.call("sanctuary_remember", { key: "key-\u4E2D", value: "v" })).toEqual(expectedRefusal());
    expect(r.recorded).toHaveLength(1);
    expect(r.recorded[0]!.cause).toBe("storage_name_unusable");
    // The first note carries no intent link; the call's rows share one call_ref instead.
    expect(r.recorded[0]!.input.linked_ref).toBeUndefined();
    const rows = async (operation: string) => (await r.env.auditLog.query({ operation_type: operation, limit: 10 })).entries;
    const [intent] = await rows("sanctuary_remember_intent");
    const [outcome] = await rows("sanctuary_remember");
    const [primitive] = await rows("state_write");
    expect(intent?.call_ref).toMatch(/^[0-9a-f]{16}$/);
    expect(outcome?.result).toBe("failure");
    expect(outcome?.call_ref).toBe(intent?.call_ref);
    expect(primitive?.call_ref).toBe(intent?.call_ref);
  });

  it("a stage fault after a primitive noted a cause keeps the stage's cause", async () => {
    // An invalid namespace is noted as refused at the source, then thrown out of the handler.
    const r = await routerRig({}, true);
    expect(await r.call("state_write", { namespace: "..", key: "k", value: "v" })).toEqual(expectedRefusal());
    expect(r.recorded.map((entry) => entry.cause)).toEqual(["handler_error"]);
    // The source's own refusal row shows it noted before the throw.
    const sourceRows = (await r.env.auditLog.query({ operation_type: "state_write", limit: 10 })).entries;
    expect(sourceRows.map((row) => row.details?.denial_class)).toEqual(["namespace_unavailable"]);
  });

  it("a cause a primitive notes on a call that then succeeds is discarded", async () => {
    const verified = { value: "v", version: 1, integrity_verified: true, signature_verified: true };
    const r = await routerRig({
      state_read: async () => {
        noteRefusalCause("target_absent");
        return toolResult(verified);
      },
    });
    expect(r.body(await r.call("sanctuary_recall", { key: "k" }))).toMatchObject({ value: "v", verified: true });
    expect(r.recorded).toEqual([]);
  });
});
