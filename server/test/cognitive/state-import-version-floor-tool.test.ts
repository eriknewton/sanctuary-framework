/**
 * state_import enforces durable version floors through the MCP tool path.
 *
 * STATE-IMPORT-VERSION-FLOOR-01
 */

import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { createCognitiveTools } from "../../src/cognitive/tools.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import type { StoredIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { CallbackApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { createServer, type ToolDefinition } from "../../src/router.js";
import { MemoryStorage } from "../../src/storage/memory.js";

type ToolPayload = Record<string, unknown>;

const READ_TOOLS = new Set(["state_read"]);

function selectedTools(
  tools: ToolDefinition[],
  names: string[]
): ToolDefinition[] {
  const wanted = new Set(names);
  return tools
    .filter((tool) => wanted.has(tool.name))
    .map((tool) => ({
      ...tool,
      tool_class: READ_TOOLS.has(tool.name) ? "read" as const : "write" as const,
    }));
}

function parseToolPayload(
  result: Awaited<ReturnType<Client["callTool"]>>
): ToolPayload {
  const content = result.content;
  if (!Array.isArray(content) || content[0]?.type !== "text") {
    throw new Error("tool returned no text payload");
  }
  return JSON.parse(content[0].text) as ToolPayload;
}

async function callTool(
  client: Client,
  name: string,
  args: Record<string, unknown>
): Promise<ToolPayload> {
  return parseToolPayload(await client.callTool({ name, arguments: args }));
}

interface ToolRig {
  client: Client;
  close: () => Promise<void>;
  identityManager: ReturnType<typeof createCognitiveTools>["identityManager"];
  masterKey: Uint8Array;
  identityEncKey: Uint8Array;
}

async function makeToolRig(): Promise<ToolRig> {
  const masterKey = generateRandomKey();
  const storage = new MemoryStorage();
  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const { tools, identityManager } = createCognitiveTools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog
  );
  await identityManager.load();

  const baseline = new BaselineTracker(storage, masterKey);
  await baseline.load();
  const gate = new ApprovalGate(
    DEFAULT_POLICY,
    baseline,
    new CallbackApprovalChannel(async () => ({
      decision: "approve",
      decided_at: new Date().toISOString(),
      decided_by: "human",
    })),
    auditLog
  );

  const server = createServer(
    selectedTools(tools, [
      "identity_create",
      "state_write",
      "state_export",
      "state_import",
      "state_read",
    ]),
    { gate, auditLog }
  );
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({
    name: "state-import-version-floor-tool-test",
    version: "1.0.0",
  });
  await server.connect(serverTransport);
  await client.connect(clientTransport);

  return {
    client,
    identityManager,
    masterKey,
    identityEncKey,
    close: async () => {
      await client.close().catch(() => {});
      await server.close().catch(() => {});
    },
  };
}

async function createIdentity(client: Client): Promise<string> {
  const identity = await callTool(client, "identity_create", {
    label: "version-floor-writer",
  });
  return identity.identity_id as string;
}

async function writeValue(
  client: Client,
  identityId: string,
  key: string,
  value: string
): Promise<void> {
  await callTool(client, "state_write", {
    namespace: "notes",
    key,
    value,
    identity_id: identityId,
  });
}

async function readValue(
  client: Client,
  key: string
): Promise<ToolPayload> {
  return callTool(client, "state_read", {
    namespace: "notes",
    key,
  });
}

async function sourceBundle(args: {
  masterKey: Uint8Array;
  identityEncKey: Uint8Array;
  identity: StoredIdentity;
  values: Array<{ key: string; value: string }>;
}): Promise<string> {
  const sourceStore = new StateStore(new MemoryStorage(), args.masterKey);
  for (const item of args.values) {
    await sourceStore.write(
      "notes",
      item.key,
      item.value,
      args.identity.identity_id,
      args.identity.encrypted_private_key,
      args.identityEncKey
    );
  }
  return (await sourceStore.exportNamespaces(["notes"])).bundle;
}

describe("state_import version floor tool path", () => {
  it("continues when the imported key has no established floor", async () => {
    const rig = await makeToolRig();
    try {
      const identityId = await createIdentity(rig.client);
      const identity = rig.identityManager.get(identityId);
      if (!identity) throw new Error("missing identity");
      const bundle = await sourceBundle({
        masterKey: rig.masterKey,
        identityEncKey: rig.identityEncKey,
        identity,
        values: [{ key: "absent", value: "first" }],
      });

      const imported = await callTool(rig.client, "state_import", {
        bundle,
        conflict_resolution: "overwrite",
      });
      expect(imported.imported_keys).toBe(1);

      const current = await readValue(rig.client, "absent");
      expect(current.value).toBe("first");
      expect(current.version).toBe(1);
    } finally {
      await rig.close();
    }
  });

  it("continues when the imported key is at the established floor", async () => {
    const rig = await makeToolRig();
    try {
      const identityId = await createIdentity(rig.client);
      await writeValue(rig.client, identityId, "equal", "first");
      const exported = await callTool(rig.client, "state_export", {
        namespace: "notes",
      });

      const imported = await callTool(rig.client, "state_import", {
        bundle: exported.bundle,
        conflict_resolution: "overwrite",
      });
      expect(imported.imported_keys).toBe(1);

      const current = await readValue(rig.client, "equal");
      expect(current.value).toBe("first");
      expect(current.version).toBe(1);
    } finally {
      await rig.close();
    }
  });

  it("continues when the imported key advances the established floor", async () => {
    const rig = await makeToolRig();
    try {
      const identityId = await createIdentity(rig.client);
      const identity = rig.identityManager.get(identityId);
      if (!identity) throw new Error("missing identity");
      await writeValue(rig.client, identityId, "above", "first");
      const bundle = await sourceBundle({
        masterKey: rig.masterKey,
        identityEncKey: rig.identityEncKey,
        identity,
        values: [
          { key: "above", value: "first" },
          { key: "above", value: "second" },
        ],
      });

      const imported = await callTool(rig.client, "state_import", {
        bundle,
        conflict_resolution: "overwrite",
      });
      expect(imported.imported_keys).toBe(1);

      const current = await readValue(rig.client, "above");
      expect(current.value).toBe("second");
      expect(current.version).toBe(2);
    } finally {
      await rig.close();
    }
  });

  it("refuses a bundle below an established floor before changing state", async () => {
    const rig = await makeToolRig();
    try {
      const identityId = await createIdentity(rig.client);
      await writeValue(rig.client, identityId, "below", "first");
      const oldExport = await callTool(rig.client, "state_export", {
        namespace: "notes",
      });

      await writeValue(rig.client, identityId, "below", "second");

      const refusedImport = await callTool(rig.client, "state_import", {
        bundle: oldExport.bundle,
        conflict_resolution: "overwrite",
      });
      expect(refusedImport.denied).toBe(true);

      const currentRead = await readValue(rig.client, "below");
      expect(currentRead.value).toBe("second");
      expect(currentRead.version).toBe(2);
    } finally {
      await rig.close();
    }
  });

  it("refuses a mixed bundle before changing any entry", async () => {
    const rig = await makeToolRig();
    try {
      const identityId = await createIdentity(rig.client);
      const identity = rig.identityManager.get(identityId);
      if (!identity) throw new Error("missing identity");
      await writeValue(rig.client, identityId, "mixed-a", "first");
      await writeValue(rig.client, identityId, "mixed-a", "second");

      const mixedBundle = await sourceBundle({
        masterKey: rig.masterKey,
        identityEncKey: rig.identityEncKey,
        identity,
        values: [
          { key: "mixed-a", value: "first" },
          { key: "mixed-b", value: "first" },
          { key: "mixed-b", value: "second" },
        ],
      });

      const refusedImport = await callTool(rig.client, "state_import", {
        bundle: mixedBundle,
        conflict_resolution: "overwrite",
      });
      expect(refusedImport.denied).toBe(true);

      const currentA = await readValue(rig.client, "mixed-a");
      expect(currentA.value).toBe("second");
      expect(currentA.version).toBe(2);
      const missingB = await readValue(rig.client, "mixed-b");
      expect(missingB.denied).toBe(true);
      expect(missingB.value).toBeUndefined();
    } finally {
      await rig.close();
    }
  });
});
