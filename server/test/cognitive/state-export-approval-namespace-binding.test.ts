/**
 * `state_export`'s Tier-1 approval gate freezes the exported namespace set
 * at gate time and binds it to the call the human approved: the handler
 * consumes that frozen set instead of re-deriving it from live state, so
 * the executed export's namespace list always matches what the approval
 * prompt was built from. Register: defect.tier1-approval-binding-state-
 * export-namespace-toctou-01.
 */
import { describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { createServer, type ToolDefinition } from "../../src/router.js";
import { createCognitiveTools } from "../../src/cognitive/tools.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import {
  normalizedArgsHash,
  fingerprintIdentityId,
  type SessionBinding,
} from "../../src/agent-native/safety-base.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { CallbackApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import type {
  ApprovalRequest,
  ApprovalResponse,
} from "../../src/principal-policy/types.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  bytesToString,
  fromBase64url,
} from "../../src/core/encoding.js";

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

function parseTextPayload(
  result: Awaited<ReturnType<Client["callTool"]>>
): Record<string, unknown> {
  const content = result.content as Array<{ type: string; text?: string }>;
  const first = content[0];
  if (!first || first.type !== "text" || typeof first.text !== "string") {
    throw new Error("missing text payload");
  }
  return JSON.parse(first.text) as Record<string, unknown>;
}

/**
 * Same JSON-text-payload shape as `parseTextPayload`, for a `ToolHandler`
 * result read directly (denial-path tests below call `tool.handler`/
 * `tool.approvalTargetArgs` as functions, not through the MCP client, the
 * same direct-call style `server/test/sdw/sdw-d2-export-import.test.ts`'s
 * `callThroughGate` helper uses to exercise router.ts's documented order
 * without a full transport round trip).
 */
function parseHandlerPayload(result: {
  content: Array<{ type: string; text?: string }>;
}): Record<string, unknown> {
  const first = result.content[0];
  if (!first || first.type !== "text" || typeof first.text !== "string") {
    throw new Error("missing text payload");
  }
  return JSON.parse(first.text) as Record<string, unknown>;
}

// Mirrors server/test/agent-native/phase1-safety-base.test.ts's `session`
// helper: a minimal SessionBinding for tests that need
// `createCognitiveTools`'s `currentSessionBinding` option populated (the
// session-bound branch of `approvalTargetArgs`, distinct from the
// no-session branch every other test in this file exercises).
function session(identityId: string): SessionBinding {
  return {
    identity_id: identityId,
    requester_identity_fingerprint: fingerprintIdentityId(identityId),
  };
}

describe("state_export approval namespace binding", () => {
  it("executes on exactly the namespace set the Tier-1 approval prompt was built from", async () => {
    const masterKey = generateRandomKey();
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, masterKey);

    // Seed real encrypted records in three namespaces via one StateStore
    // instance, then hand the SAME underlying storage to a fresh instance
    // below. `contentHashes` is an in-memory, per-instance cache (never
    // persisted), so the fresh instance starts knowing about none of them —
    // this is what lets the test warm A and B before C without special
    // fixture machinery.
    const seedingStore = new StateStore(storage, masterKey);
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const identity = createIdentity(
      "binding-test",
      identityEncKey,
      "recovery-key"
    );
    for (const [namespace, key, value] of [
      ["A", "k", "alpha"],
      ["B", "k", "bravo"],
      ["C", "k", "charlie"],
    ] as const) {
      await seedingStore.write(
        namespace,
        key,
        value,
        identity.storedIdentity.identity_id,
        identity.storedIdentity.encrypted_private_key,
        identityEncKey
      );
    }

    // The baseline already knows all three namespaces, so the routed
    // `state_list` warm-up call below is an ordinary Tier-3 operation and
    // does not itself trigger a second, unrelated approval prompt.
    const seedingBaseline = new BaselineTracker(storage, masterKey);
    await seedingBaseline.load();
    seedingBaseline.recordNamespaceAccess("A");
    seedingBaseline.recordNamespaceAccess("B");
    seedingBaseline.recordNamespaceAccess("C");
    await seedingBaseline.save();

    const stateStore = new StateStore(storage, masterKey);
    const baseline = new BaselineTracker(storage, masterKey);
    await baseline.load();

    const approvalRequested = deferred<ApprovalRequest>();
    const approvalDecision = deferred<ApprovalResponse>();
    let capturedRequest: ApprovalRequest | undefined;
    const channel = new CallbackApprovalChannel(async (request) => {
      capturedRequest = request;
      approvalRequested.resolve(request);
      return approvalDecision.promise;
    });
    const gate = new ApprovalGate(DEFAULT_POLICY, baseline, channel, auditLog);

    const { tools } = createCognitiveTools(
      stateStore,
      storage,
      masterKey,
      "passphrase",
      auditLog
    );
    const rawStateExportTool = tools.find((t) => t.name === "state_export");
    const rawStateListTool = tools.find((t) => t.name === "state_list");
    if (!rawStateExportTool || !rawStateListTool) {
      throw new Error("harness setup: state_export / state_list tool not found");
    }

    // Spy: delegate to the real gate-time computation and record exactly
    // what it returned, independently of anything a display channel might
    // summarize. This is the ground truth the approved bundle is checked
    // against below.
    let capturedGateArgs: Record<string, unknown> | undefined;
    const originalApprovalTargetArgs = rawStateExportTool.approvalTargetArgs!;
    const stateExportTool: ToolDefinition = {
      ...rawStateExportTool,
      tool_class: "write",
      approvalTargetArgs: async (args) => {
        const gateArgs = await originalApprovalTargetArgs(args);
        capturedGateArgs = gateArgs;
        return gateArgs;
      },
    };
    const stateListTool: ToolDefinition = {
      ...rawStateListTool,
      tool_class: "read",
    };

    const server = createServer([stateExportTool, stateListTool], {
      gate,
      auditLog,
    });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({
      name: "state-export-binding-test",
      version: "1.0.0",
    });
    await client.connect(clientTransport);

    try {
      await client.callTool({ name: "state_list", arguments: { namespace: "A" } });
      await client.callTool({ name: "state_list", arguments: { namespace: "B" } });
      expect(stateStore.listCachedExportableNamespaces()).toEqual(["A", "B"]);

      const exportPromise = client.callTool({
        name: "state_export",
        arguments: {},
      });

      await approvalRequested.promise;
      expect(capturedGateArgs?.namespaces).toEqual(["A", "B"]);
      expect(capturedRequest?.args_binding).toBe(
        normalizedArgsHash(capturedGateArgs as Record<string, unknown>)
      );

      // While the approval is still pending, a second routed call widens
      // the live export cache to a set the approval prompt never saw.
      await client.callTool({
        name: "state_list",
        arguments: { namespace: "C" },
      });
      expect(stateStore.listCachedExportableNamespaces()).toEqual([
        "A",
        "B",
        "C",
      ]);

      approvalDecision.resolve({
        decision: "approve",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      });

      const payload = parseTextPayload(await exportPromise);
      expect(payload.namespaces).toEqual(capturedGateArgs?.namespaces);
      expect(payload.namespaces).toEqual(["A", "B"]);

      const bundle = JSON.parse(
        bytesToString(fromBase64url(payload.bundle as string))
      ) as { data: Record<string, unknown> };
      expect(Object.keys(bundle.data).sort()).toEqual(["A", "B"]);
      expect(bundle.data.C).toBeUndefined();
    } finally {
      await client.close().catch(() => {});
      await server.close().catch(() => {});
    }
  });

  it("two concurrent bulk exports in one session each execute exactly their own gate-time bound set (kills a shared 'last projected scope' slot, and a snapshot only taken once per module)", async () => {
    const masterKey = generateRandomKey();
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, masterKey);

    const seedingStore = new StateStore(storage, masterKey);
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const identity = createIdentity(
      "binding-test-concurrent",
      identityEncKey,
      "recovery-key"
    );
    for (const [namespace, key, value] of [
      ["A", "k", "alpha"],
      ["B", "k", "bravo"],
      ["C", "k", "charlie"],
    ] as const) {
      await seedingStore.write(
        namespace,
        key,
        value,
        identity.storedIdentity.identity_id,
        identity.storedIdentity.encrypted_private_key,
        identityEncKey
      );
    }

    // The baseline already knows all three namespaces (as the first test
    // above does), so the routed `state_list` warm-up calls below are
    // ordinary Tier-3 operations and do not themselves trigger an anomaly-
    // escalation approval that this test's fixed two-slot `arrivals` queue
    // does not account for.
    const seedingBaseline = new BaselineTracker(storage, masterKey);
    await seedingBaseline.load();
    seedingBaseline.recordNamespaceAccess("A");
    seedingBaseline.recordNamespaceAccess("B");
    seedingBaseline.recordNamespaceAccess("C");
    await seedingBaseline.save();

    const stateStore = new StateStore(storage, masterKey);
    const baseline = new BaselineTracker(storage, masterKey);
    await baseline.load();

    // A queue-based channel: each request gets its OWN deferred decision,
    // resolved out of arrival order below, and an arrival deferred the test
    // awaits by index — deterministic, no sleeps, and no shared "current
    // request" slot in the TEST HARNESS either (which would defeat the
    // point of the test).
    const arrivals = [deferred<void>(), deferred<void>()];
    const pending: Array<{
      request: ApprovalRequest;
      decide: (response: ApprovalResponse) => void;
    }> = [];
    const channel = new CallbackApprovalChannel(async (request) => {
      const decision = deferred<ApprovalResponse>();
      const index = pending.length;
      pending.push({ request, decide: decision.resolve });
      arrivals[index]!.resolve();
      return decision.promise;
    });
    const gate = new ApprovalGate(DEFAULT_POLICY, baseline, channel, auditLog);

    const { tools } = createCognitiveTools(
      stateStore,
      storage,
      masterKey,
      "passphrase",
      auditLog
    );
    const rawStateExportTool = tools.find((t) => t.name === "state_export");
    const rawStateListTool = tools.find((t) => t.name === "state_list");
    if (!rawStateExportTool || !rawStateListTool) {
      throw new Error("harness setup: state_export / state_list tool not found");
    }
    const stateExportTool: ToolDefinition = {
      ...rawStateExportTool,
      tool_class: "write",
    };
    const stateListTool: ToolDefinition = {
      ...rawStateListTool,
      tool_class: "read",
    };

    const server = createServer([stateExportTool, stateListTool], {
      gate,
      auditLog,
    });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({
      name: "state-export-binding-concurrent-test",
      version: "1.0.0",
    });
    await client.connect(clientTransport);

    try {
      await client.callTool({ name: "state_list", arguments: { namespace: "A" } });
      await client.callTool({ name: "state_list", arguments: { namespace: "B" } });
      expect(stateStore.listCachedExportableNamespaces()).toEqual(["A", "B"]);

      // Export 1's gate-time projection runs now and snapshots {A, B}.
      const exportPromise1 = client.callTool({
        name: "state_export",
        arguments: {},
      });
      await arrivals[0]!.promise;

      // Widen the live cache WHILE export 1's approval is still pending.
      await client.callTool({
        name: "state_list",
        arguments: { namespace: "C" },
      });
      expect(stateStore.listCachedExportableNamespaces()).toEqual([
        "A",
        "B",
        "C",
      ]);

      // Export 2's gate-time projection runs with the now-widened cache and
      // snapshots {A, B, C} — a DIFFERENT call, a DIFFERENT args object, a
      // DIFFERENT binding than export 1's.
      const exportPromise2 = client.callTool({
        name: "state_export",
        arguments: {},
      });
      await arrivals[1]!.promise;

      // Decide export 2 FIRST. A single module-level "last projected
      // scope" slot (one of the narrower patches both reviewers named)
      // would now hold {A, B, C} for BOTH calls.
      pending[1]!.decide({
        decision: "approve",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      });
      const payload2 = parseTextPayload(await exportPromise2);
      expect(payload2.namespaces).toEqual(["A", "B", "C"]);

      // Decide export 1 SECOND. A shared slot, a snapshot taken only once
      // per module, or a snapshot skipped whenever a session binding is
      // absent would make export 1 export export 2's {A, B, C} set here
      // instead of its own {A, B}.
      pending[0]!.decide({
        decision: "approve",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      });
      const payload1 = parseTextPayload(await exportPromise1);
      expect(payload1.namespaces).toEqual(["A", "B"]);

      const bundle1 = JSON.parse(
        bytesToString(fromBase64url(payload1.bundle as string))
      ) as { data: Record<string, unknown> };
      expect(Object.keys(bundle1.data).sort()).toEqual(["A", "B"]);
      expect(bundle1.data.C).toBeUndefined();
    } finally {
      await client.close().catch(() => {});
      await server.close().catch(() => {});
    }
  });

  it("two concurrent bulk exports with a SESSION BINDING present each execute exactly their own gate-time bound set (kills a snapshot recomputed from live state only on the session-bound branch of approvalTargetArgs)", async () => {
    // Every other test in this file constructs `createCognitiveTools` with
    // no `currentSessionBinding`, so a mutation narrowing the fix to "take
    // the snapshot only when `options?.currentSessionBinding?.()` is
    // undefined" would still pass every one of them: the shipped boot path
    // (server/src/index.ts) DOES pass a session getter, so that mutation
    // would leave the TOCTOU open on exactly the path production uses. This
    // test is the concurrent test above, with a real SessionBinding
    // supplied, to close that gap.
    const masterKey = generateRandomKey();
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, masterKey);

    const seedingStore = new StateStore(storage, masterKey);
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const identity = createIdentity(
      "binding-test-session-concurrent",
      identityEncKey,
      "recovery-key"
    );
    for (const [namespace, key, value] of [
      ["D", "k", "delta"],
      ["E", "k", "echo"],
      ["F", "k", "foxtrot"],
    ] as const) {
      await seedingStore.write(
        namespace,
        key,
        value,
        identity.storedIdentity.identity_id,
        identity.storedIdentity.encrypted_private_key,
        identityEncKey
      );
    }

    const seedingBaseline = new BaselineTracker(storage, masterKey);
    await seedingBaseline.load();
    seedingBaseline.recordNamespaceAccess("D");
    seedingBaseline.recordNamespaceAccess("E");
    seedingBaseline.recordNamespaceAccess("F");
    await seedingBaseline.save();

    const stateStore = new StateStore(storage, masterKey);
    const baseline = new BaselineTracker(storage, masterKey);
    await baseline.load();
    const activeSession = session("session-concurrent-agent");

    const arrivals = [deferred<void>(), deferred<void>()];
    const pending: Array<{
      request: ApprovalRequest;
      decide: (response: ApprovalResponse) => void;
    }> = [];
    const channel = new CallbackApprovalChannel(async (request) => {
      const decision = deferred<ApprovalResponse>();
      const index = pending.length;
      pending.push({ request, decide: decision.resolve });
      arrivals[index]!.resolve();
      return decision.promise;
    });
    const gate = new ApprovalGate(DEFAULT_POLICY, baseline, channel, auditLog);

    const { tools } = createCognitiveTools(
      stateStore,
      storage,
      masterKey,
      "passphrase",
      auditLog,
      { currentSessionBinding: () => activeSession }
    );
    const rawStateExportTool = tools.find((t) => t.name === "state_export");
    const rawStateListTool = tools.find((t) => t.name === "state_list");
    if (!rawStateExportTool || !rawStateListTool) {
      throw new Error("harness setup: state_export / state_list tool not found");
    }
    const stateExportTool: ToolDefinition = {
      ...rawStateExportTool,
      tool_class: "write",
    };
    const stateListTool: ToolDefinition = {
      ...rawStateListTool,
      tool_class: "read",
    };

    const server = createServer([stateExportTool, stateListTool], {
      gate,
      auditLog,
    });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({
      name: "state-export-binding-session-concurrent-test",
      version: "1.0.0",
    });
    await client.connect(clientTransport);

    try {
      await client.callTool({ name: "state_list", arguments: { namespace: "D" } });
      await client.callTool({ name: "state_list", arguments: { namespace: "E" } });
      expect(stateStore.listCachedExportableNamespaces()).toEqual(["D", "E"]);

      const exportPromise1 = client.callTool({
        name: "state_export",
        arguments: {},
      });
      await arrivals[0]!.promise;

      // Widen the live cache WHILE export 1's approval is still pending —
      // the session-bound branch reads this same cache.
      await client.callTool({
        name: "state_list",
        arguments: { namespace: "F" },
      });
      expect(stateStore.listCachedExportableNamespaces()).toEqual([
        "D",
        "E",
        "F",
      ]);

      const exportPromise2 = client.callTool({
        name: "state_export",
        arguments: {},
      });
      await arrivals[1]!.promise;

      pending[1]!.decide({
        decision: "approve",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      });
      const payload2 = parseTextPayload(await exportPromise2);
      expect(payload2.namespaces).toEqual(["D", "E", "F"]);

      pending[0]!.decide({
        decision: "approve",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      });
      const payload1 = parseTextPayload(await exportPromise1);
      expect(payload1.namespaces).toEqual(["D", "E"]);

      const bundle1 = JSON.parse(
        bytesToString(fromBase64url(payload1.bundle as string))
      ) as { data: Record<string, unknown> };
      expect(Object.keys(bundle1.data).sort()).toEqual(["D", "E"]);
      expect(bundle1.data.F).toBeUndefined();
    } finally {
      await client.close().catch(() => {});
      await server.close().catch(() => {});
    }
  });

  it("the explicit single-namespace form is bound at gate time and executes on exactly that namespace (kills a snapshot taken for the bulk form and not the explicit form)", async () => {
    const masterKey = generateRandomKey();
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, masterKey);

    const seedingStore = new StateStore(storage, masterKey);
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const identity = createIdentity(
      "binding-test-explicit",
      identityEncKey,
      "recovery-key"
    );
    await seedingStore.write(
      "A",
      "k",
      "alpha",
      identity.storedIdentity.identity_id,
      identity.storedIdentity.encrypted_private_key,
      identityEncKey
    );
    await seedingStore.write(
      "B",
      "k",
      "bravo",
      identity.storedIdentity.identity_id,
      identity.storedIdentity.encrypted_private_key,
      identityEncKey
    );

    const stateStore = new StateStore(storage, masterKey);
    const baseline = new BaselineTracker(storage, masterKey);
    await baseline.load();

    const approvalRequested = deferred<ApprovalRequest>();
    const approvalDecision = deferred<ApprovalResponse>();
    const channel = new CallbackApprovalChannel(async (request) => {
      approvalRequested.resolve(request);
      return approvalDecision.promise;
    });
    const gate = new ApprovalGate(DEFAULT_POLICY, baseline, channel, auditLog);

    const { tools } = createCognitiveTools(
      stateStore,
      storage,
      masterKey,
      "passphrase",
      auditLog
    );
    const rawStateExportTool = tools.find((t) => t.name === "state_export");
    if (!rawStateExportTool) {
      throw new Error("harness setup: state_export tool not found");
    }
    const stateExportTool: ToolDefinition = {
      ...rawStateExportTool,
      tool_class: "write",
    };

    const server = createServer([stateExportTool], { gate, auditLog });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({
      name: "state-export-binding-explicit-test",
      version: "1.0.0",
    });
    await client.connect(clientTransport);

    try {
      const exportPromise = client.callTool({
        name: "state_export",
        arguments: { namespace: "A" },
      });
      const request = await approvalRequested.promise;
      expect(request.context.args_summary).toMatchObject({ namespace: "A" });

      approvalDecision.resolve({
        decision: "approve",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      });
      const payload = parseTextPayload(await exportPromise);
      expect(payload.namespaces).toEqual(["A"]);

      const bundle = JSON.parse(
        bytesToString(fromBase64url(payload.bundle as string))
      ) as { data: Record<string, unknown> };
      expect(Object.keys(bundle.data)).toEqual(["A"]);
      expect(bundle.data.B).toBeUndefined();
    } finally {
      await client.close().catch(() => {});
      await server.close().catch(() => {});
    }
  });

  it("an explicit reserved namespace is refused before the human is ever asked to approve it", async () => {
    const masterKey = generateRandomKey();
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, masterKey);
    const stateStore = new StateStore(storage, masterKey);
    const baseline = new BaselineTracker(storage, masterKey);
    await baseline.load();

    let approvalRequestedCount = 0;
    const channel = new CallbackApprovalChannel(async () => {
      approvalRequestedCount++;
      return {
        decision: "approve",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      } as ApprovalResponse;
    });
    const gate = new ApprovalGate(DEFAULT_POLICY, baseline, channel, auditLog);

    const { tools } = createCognitiveTools(
      stateStore,
      storage,
      masterKey,
      "passphrase",
      auditLog
    );
    const rawStateExportTool = tools.find((t) => t.name === "state_export");
    if (!rawStateExportTool) {
      throw new Error("harness setup: state_export tool not found");
    }
    const stateExportTool: ToolDefinition = {
      ...rawStateExportTool,
      tool_class: "write",
    };

    const server = createServer([stateExportTool], { gate, auditLog });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({
      name: "state-export-binding-reserved-explicit-test",
      version: "1.0.0",
    });
    await client.connect(clientTransport);

    try {
      const result = await client.callTool({
        name: "state_export",
        arguments: { namespace: "_audit" },
      });
      expect(result.isError).toBe(true);
      // Refused before the gate ever asked: the reserved-namespace check
      // in `approvalTargetArgs` throws, and router.ts's catch around it
      // denies without ever calling `gate.evaluate`.
      expect(approvalRequestedCount).toBe(0);
    } finally {
      await client.close().catch(() => {});
      await server.close().catch(() => {});
    }
  });

  it("the bulk form's reserved-namespace filtering happens before the set is bound, so the bound set and the executed set are equal", async () => {
    const masterKey = generateRandomKey();
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, masterKey);

    const seedingStore = new StateStore(storage, masterKey);
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const identity = createIdentity(
      "binding-test-reserved-bulk",
      identityEncKey,
      "recovery-key"
    );
    await seedingStore.write(
      "A",
      "k",
      "alpha",
      identity.storedIdentity.identity_id,
      identity.storedIdentity.encrypted_private_key,
      identityEncKey
    );

    const stateStore = new StateStore(storage, masterKey);
    // Warm the normal namespace and a reserved one into the fresh
    // instance's in-memory content-hash cache directly (`StateStore.list`
    // carries no reserved-namespace firewall of its own — that firewall
    // lives in the TOOL layer, e.g. state_list's handler), so this is how a
    // reserved namespace can be present in the underlying cache
    // `sessionOwnedExportNamespaces` reads from even though no MCP caller
    // can read or write it through the tool surface.
    await stateStore.list("A");
    await stateStore.list("_audit");

    const baseline = new BaselineTracker(storage, masterKey);
    await baseline.load();
    baseline.recordNamespaceAccess("A");
    await baseline.save();

    const approvalRequested = deferred<ApprovalRequest>();
    const approvalDecision = deferred<ApprovalResponse>();
    const channel = new CallbackApprovalChannel(async (request) => {
      approvalRequested.resolve(request);
      return approvalDecision.promise;
    });
    const gate = new ApprovalGate(DEFAULT_POLICY, baseline, channel, auditLog);

    const { tools } = createCognitiveTools(
      stateStore,
      storage,
      masterKey,
      "passphrase",
      auditLog
    );
    const rawStateExportTool = tools.find((t) => t.name === "state_export");
    if (!rawStateExportTool) {
      throw new Error("harness setup: state_export tool not found");
    }
    const stateExportTool: ToolDefinition = {
      ...rawStateExportTool,
      tool_class: "write",
    };

    const server = createServer([stateExportTool], { gate, auditLog });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({
      name: "state-export-binding-reserved-bulk-test",
      version: "1.0.0",
    });
    await client.connect(clientTransport);

    try {
      expect(stateStore.listCachedExportableNamespaces()).toEqual(["A"]);

      const exportPromise = client.callTool({
        name: "state_export",
        arguments: {},
      });
      await approvalRequested.promise;

      approvalDecision.resolve({
        decision: "approve",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      });
      const payload = parseTextPayload(await exportPromise);
      expect(payload.namespaces).toEqual(["A"]);
    } finally {
      await client.close().catch(() => {});
      await server.close().catch(() => {});
    }
  });
});

describe("state_export approval binding: denial paths", () => {
  // Direct function-level calls (`tool.approvalTargetArgs!` / `tool.handler`),
  // not a full MCP client/server round trip: the same established pattern
  // `server/test/sdw/sdw-d2-export-import.test.ts`'s `callThroughGate`
  // helper uses for binding-expiry/replay/mismatch checks, mirroring
  // router.ts's documented order (approvalTargetArgs runs, THEN the
  // handler) without needing transport machinery for a synchronous denial
  // check. No sleeps; the one timing-dependent case mocks `Date.now`
  // directly and restores it in a `finally`.
  async function makeStateExportTool(): Promise<ToolDefinition> {
    const masterKey = generateRandomKey();
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, masterKey);
    const stateStore = new StateStore(storage, masterKey);
    const { tools } = createCognitiveTools(
      stateStore,
      storage,
      masterKey,
      "passphrase",
      auditLog
    );
    const tool = tools.find((t) => t.name === "state_export");
    if (!tool) throw new Error("harness setup: state_export tool not found");
    return tool;
  }

  it("denies when no binding was ever attached (approvalTargetArgs never ran for this call)", async () => {
    const tool = await makeStateExportTool();
    const result = await tool.handler({});
    const payload = parseHandlerPayload(result);
    expect(payload.denied).toBe(true);
  });

  it("denies when the binding has aged past the fixed freshness ceiling, independent of any configured approval timeout", async () => {
    const tool = await makeStateExportTool();
    const args: Record<string, unknown> = {};
    const nowSpy = vi.spyOn(Date, "now");
    try {
      nowSpy.mockReturnValue(1_000_000);
      await tool.approvalTargetArgs!(args);
      // One millisecond past the 15-minute ceiling.
      nowSpy.mockReturnValue(1_000_000 + 15 * 60_000 + 1);
      const result = await tool.handler(args);
      const payload = parseHandlerPayload(result);
      expect(payload.denied).toBe(true);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("denies when the args object changed after gate time (hash mismatch)", async () => {
    const tool = await makeStateExportTool();
    const args: Record<string, unknown> = {};
    await tool.approvalTargetArgs!(args);
    // Mutate an enumerable field after the human's approval prompt was
    // built from the unmutated object — the non-enumerable binding survives
    // the mutation, but its recorded argsHash no longer matches.
    args.format = "tampered";
    const result = await tool.handler(args);
    const payload = parseHandlerPayload(result);
    expect(payload.denied).toBe(true);
  });

  it("denies a reused (already-consumed) binding on a second handler call with the same args object", async () => {
    const tool = await makeStateExportTool();
    const args: Record<string, unknown> = {};
    await tool.approvalTargetArgs!(args);
    const first = await tool.handler(args);
    expect(parseHandlerPayload(first).denied).toBeUndefined();
    // Single-use consumption (`takeStateExportApprovalBinding` deletes the
    // property on read): a second call against the SAME args object must
    // deny, not silently re-export the same set again.
    const second = await tool.handler(args);
    expect(parseHandlerPayload(second).denied).toBe(true);
  });

  it("explicit single-namespace form: denies when no binding was ever attached", async () => {
    const tool = await makeStateExportTool();
    const result = await tool.handler({ namespace: "A" });
    const payload = parseHandlerPayload(result);
    expect(payload.denied).toBe(true);
  });

  it("explicit single-namespace form: denies when the args object changed after gate time (hash mismatch)", async () => {
    const tool = await makeStateExportTool();
    const args: Record<string, unknown> = { namespace: "A" };
    await tool.approvalTargetArgs!(args);
    args.format = "tampered";
    const result = await tool.handler(args);
    const payload = parseHandlerPayload(result);
    expect(payload.denied).toBe(true);
  });

  // The freshness ceiling is enforced in the shared consume helper, so this
  // case and its bulk-form sibling above cover the SAME line. It is here
  // anyway: a form-conditional skip of that check passes a suite that only
  // drives one form, and this change exists because a guard with no failing
  // case was deleted on reasoning nobody had tested.
  it("explicit single-namespace form: denies when the binding has aged past the fixed freshness ceiling", async () => {
    const tool = await makeStateExportTool();
    const args: Record<string, unknown> = { namespace: "A" };
    const nowSpy = vi.spyOn(Date, "now");
    try {
      nowSpy.mockReturnValue(1_000_000);
      await tool.approvalTargetArgs!(args);
      // One millisecond past the 15-minute ceiling.
      nowSpy.mockReturnValue(1_000_000 + 15 * 60_000 + 1);
      const result = await tool.handler(args);
      const payload = parseHandlerPayload(result);
      expect(payload.denied).toBe(true);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("explicit single-namespace form: denies a reused (already-consumed) binding on a second handler call", async () => {
    const tool = await makeStateExportTool();
    const args: Record<string, unknown> = { namespace: "A" };
    await tool.approvalTargetArgs!(args);
    const first = await tool.handler(args);
    expect(parseHandlerPayload(first).denied).toBeUndefined();
    const second = await tool.handler(args);
    expect(parseHandlerPayload(second).denied).toBe(true);
  });
});

