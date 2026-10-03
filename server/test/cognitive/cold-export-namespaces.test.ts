/**
 * Full exports discover durable state and bind its scope before approval.
 * LEGACY-BUG-001
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "../../src/router.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createCognitiveTools } from "../../src/cognitive/tools.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { bytesToString, fromBase64url } from "../../src/core/encoding.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { CallbackApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { normalizedArgsHash, OpaqueNamespaceRegistry, fingerprintIdentityId } from "../../src/agent-native/safety-base.js";
import { MAX_DISCOVERED_NAMESPACES } from "../../src/storage/interface.js";

const cleanup: Array<() => Promise<unknown>> = [];
afterEach(async () => {
  vi.restoreAllMocks();
  for (const close of cleanup.splice(0).reverse()) await close();
});

async function fixture(sessionScoped = false, ambiguousOwner = false) {
  const path = await mkdtemp(join(tmpdir(), "cold-export-"));
  cleanup.push(() => rm(path, { recursive: true, force: true }));
  const masterKey = generateRandomKey();
  const storage = new FilesystemStorage(path);
  const seed = new StateStore(storage, masterKey);
  const encKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity: identity } = createIdentity("cold-export", encKey, "recovery-key");
  const registry = new OpaqueNamespaceRegistry();
  const owned = registry.issueMemoryHandle(identity.identity_id);
  const foreign = registry.issueMemoryHandle("other-identity");
  const namespaces = ["alpha", "beta", "_internal"];
  if (sessionScoped) namespaces.push(owned, foreign);
  if (ambiguousOwner) namespaces.push("mem_unknown");
  for (const ns of namespaces) {
    await seed.write(ns, "note", ns, identity.identity_id, identity.encrypted_private_key, encKey);
  }
  const reopened = new FilesystemStorage(path);
  const cold = new StateStore(reopened, masterKey);
  const audit = new AuditLog(reopened, masterKey);
  const baseline = new BaselineTracker(reopened, masterKey);
  await baseline.load();
  const { tools } = createCognitiveTools(cold, reopened, masterKey, "recovery-key", audit, {
    namespaceRegistry: registry,
    currentSessionBinding: () => sessionScoped ? {
      identity_id: identity.identity_id,
      requester_identity_fingerprint: fingerprintIdentityId(identity.identity_id),
    } : undefined,
  });
  const tool = tools.find((item) => item.name === "state_export")!;
  let projection: Record<string, unknown> | undefined;
  let approvedHash: string | undefined;
  const channel = new CallbackApprovalChannel(async (request) => {
    approvedHash = request.args_binding;
    return { decision: "approve", decided_at: new Date().toISOString(), decided_by: "human" };
  });
  const server = createServer([{
    ...tool,
    tool_class: "write",
    approvalTargetArgs: async (args) => {
      projection = await tool.approvalTargetArgs!(args);
      return projection;
    },
  }], { gate: new ApprovalGate(DEFAULT_POLICY, baseline, channel, audit), auditLog: audit });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  cleanup.push(() => server.close());
  const client = new Client({ name: "cold-export-test", version: "1.0.0" });
  await client.connect(clientTransport);
  cleanup.push(() => client.close());
  return { cold, reopened, client, owned, foreign, projection: () => projection, approvedHash: () => approvedHash };
}

describe("durable namespace export", () => {
  it("exports cold namespaces through the Tier-1 MCP path with the approved scope", async () => {
    const f = await fixture();
    expect(f.cold.listCachedExportableNamespaces()).toEqual([]);
    const result = await f.client.callTool({ name: "state_export", arguments: {} });
    const payload = JSON.parse((result.content as Array<{ text: string }>)[0]!.text);
    expect(payload.namespaces).toEqual(["alpha", "beta"]);
    expect(payload.total_keys).toBe(2);
    expect(f.projection()?.namespaces).toEqual(payload.namespaces);
    expect(f.approvedHash()).toBe(normalizedArgsHash(f.projection()!));
    const bundle = JSON.parse(bytesToString(fromBase64url(payload.bundle)));
    expect(Object.keys(bundle.data).sort()).toEqual(payload.namespaces);
  });

  it("refuses before approval when enumeration fails", async () => {
    const f = await fixture();
    vi.spyOn(f.reopened, "listNamespaces").mockRejectedValue(new Error("enumeration unavailable"));
    const result = await f.client.callTool({ name: "state_export", arguments: {} });
    expect(result.isError).toBe(true);
    expect(f.approvedHash()).toBeUndefined();
    await expect(f.cold.export()).rejects.toThrow("enumeration unavailable");
  });

  it("fails closed when the backend cannot enumerate", async () => {
    const f = await fixture();
    Object.defineProperty(f.reopened, "listNamespaces", { value: undefined });
    await expect(f.cold.export()).rejects.toThrow("cannot enumerate");
  });

  it("rejects an oversized backend result before reading state or requesting approval", async () => {
    const f = await fixture();
    vi.spyOn(f.reopened, "listNamespaces").mockResolvedValue(
      Array.from({ length: MAX_DISCOVERED_NAMESPACES + 1 }, (_, i) => `ns-${i}`),
    );
    const exportState = vi.spyOn(f.cold, "exportNamespaces");
    await f.client.callTool({ name: "state_export", arguments: {} });
    expect(f.approvedHash()).toBeUndefined();
    expect(exportState).not.toHaveBeenCalled();
    await expect(f.cold.export()).rejects.toThrow("limit exceeded");
  });

  it("retains explicit namespace and empty-scope semantics without re-enumerating", async () => {
    const f = await fixture();
    const discovery = vi.spyOn(f.reopened, "listNamespaces").mockRejectedValue(new Error("must not discover"));
    expect((await f.cold.export("alpha")).namespaces).toEqual(["alpha"]);
    expect((await f.cold.exportNamespaces([])).namespaces).toEqual([]);
    expect(discovery).not.toHaveBeenCalled();
  });

  it("filters cold opaque namespaces to the active owner before approval", async () => {
    const f = await fixture(true);
    const result = await f.client.callTool({ name: "state_export", arguments: {} });
    const payload = JSON.parse((result.content as Array<{ text: string }>)[0]!.text);
    expect(payload.namespaces).toEqual(["alpha", "beta", f.owned].sort());
    expect(payload.namespaces).not.toContain(f.foreign);
    expect(f.projection()?.namespaces).toEqual(payload.namespaces);
  });

  it("refuses cold opaque state with ambiguous ownership before approval", async () => {
    const f = await fixture(true, true);
    const result = await f.client.callTool({ name: "state_export", arguments: {} });
    expect(result.isError).toBe(true);
    expect(f.approvedHash()).toBeUndefined();
  });
});
