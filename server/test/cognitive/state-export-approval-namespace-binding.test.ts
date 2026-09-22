/**
 * `state_export`'s Tier-1 approval gate freezes the exported namespace set
 * at gate time and binds it to the call the human approved: the handler
 * consumes that frozen set instead of re-deriving it from live state, so
 * the executed export's namespace list always matches what the approval
 * prompt was built from. Register: defect.tier1-approval-binding-state-
 * export-namespace-toctou-01.
 */
import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { createServer, type ToolDefinition } from "../../src/router.js";
import { createCognitiveTools } from "../../src/cognitive/tools.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { normalizedArgsHash } from "../../src/agent-native/safety-base.js";
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
});
