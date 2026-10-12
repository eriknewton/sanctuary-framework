import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createCognitiveTools } from "../../src/cognitive/tools.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { CallbackApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { createServer } from "../../src/router.js";
import type { ToolDefinition } from "../../src/router.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";

const INVALID_NAMESPACES = ["", ".", ".."];
const READ_TOOLS = new Set(["state_read", "state_list"]);
const UNIX_EPOCH_MS = 0; // JavaScript Date millisecond zero is 1970-01-01T00:00:00.000Z.

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

function legacyBundleForNamespace(namespace: string): string {
  return toBase64url(
    stringToBytes(
      JSON.stringify({
        sanctuary_export_version: 1,
        format: "sanctuary-v1",
        exported_at: new Date(UNIX_EPOCH_MS).toISOString(),
        namespaces: [namespace],
        data: { [namespace]: [] },
      })
    )
  );
}

async function snapshotNames(path: string): Promise<string[]> {
  try {
    const entries = await readdir(path, { withFileTypes: true });
    return entries
      .map((entry) => `${entry.isDirectory() ? "d" : "f"}:${entry.name}`)
      .sort();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
}

async function snapshotSentinel(path: string): Promise<{ names: string[]; bytes: Buffer }> {
  return {
    names: await snapshotNames(path),
    bytes: await readFile(join(path, "k.enc")),
  };
}

function parseToolPayload(result: Awaited<ReturnType<Client["callTool"]>>): Record<string, unknown> {
  const content = result.content;
  if (!Array.isArray(content) || content[0]?.type !== "text") {
    throw new Error("tool returned no text payload");
  }
  return JSON.parse(content[0].text) as Record<string, unknown>;
}

describe("state tool namespace names", () => {
  it("refuses namespace names that are not a single path component before approval is requested", async () => {
    const fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-state-tools-"));
    const statePath = join(fortressPath, "state");
    try {
      const masterKey = generateRandomKey();
      const storage = new FilesystemStorage(statePath);
      const auditLog = new AuditLog(storage, masterKey);
      const stateStore = new StateStore(storage, masterKey);
      const { tools, identityManager } = createCognitiveTools(
        stateStore,
        storage,
        masterKey,
        "passphrase",
        auditLog
      );
      await identityManager.load();

      let approvalRequests = 0;
      const baseline = new BaselineTracker(storage, masterKey);
      await baseline.load();
      const gate = new ApprovalGate(
        DEFAULT_POLICY,
        baseline,
        new CallbackApprovalChannel(async () => {
          approvalRequests++;
          return {
            decision: "approve",
            decided_at: new Date().toISOString(),
            decided_by: "human",
          };
        }),
        auditLog
      );
      await mkdir(fortressPath, { recursive: true, mode: 0o700 });
      await writeFile(join(fortressPath, "k.enc"), Buffer.from("operator-sentinel"));

      const server = createServer(
        selectedTools(tools, [
          "identity_create",
          "state_write",
          "state_delete",
          "state_disclose_unattributed",
        ]),
        { gate, auditLog }
      );
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      const client = new Client({ name: "state-namespace-component-test", version: "1.0.0" });
      await server.connect(serverTransport);
      await client.connect(clientTransport);

      try {
        const identity = parseToolPayload(
          await client.callTool({
            name: "identity_create",
            arguments: { label: "namespace-component" },
          })
        );
        const identityId = identity.identity_id as string;
        approvalRequests = 0;

        for (const namespace of INVALID_NAMESPACES) {
          const beforeParent = await snapshotSentinel(fortressPath);
          const write = parseToolPayload(
            await client.callTool({
              name: "state_write",
              arguments: {
                namespace,
                key: "k",
                value: "v",
                identity_id: identityId,
              },
            })
          );
          expect(write.denied).toBe(true);

          const deleteResult = parseToolPayload(
            await client.callTool({
              name: "state_delete",
              arguments: { namespace, key: "k", reason: "test" },
            })
          );
          expect(deleteResult.denied).toBe(true);

          const disclosure = parseToolPayload(
            await client.callTool({
              name: "state_disclose_unattributed",
              arguments: { namespace, key: "k" },
            })
          );
          expect(disclosure.denied).toBe(true);
          expect(approvalRequests).toBe(0);
          expect(await snapshotSentinel(fortressPath)).toEqual(beforeParent);
        }
      } finally {
        await client.close().catch(() => {});
        await server.close().catch(() => {});
      }
    } finally {
      await rm(fortressPath, { recursive: true, force: true });
    }
  });

  it("refuses import bundles naming a namespace that is not a single path component before writing", async () => {
    const masterKey = generateRandomKey();
    const storage = new MemoryStorage();
    const stateStore = new StateStore(storage, masterKey);
    const bundle = legacyBundleForNamespace(".");
    await storage.write("safe", "keep", new Uint8Array([8, 9]));

    await expect(
      stateStore.import(bundle, "overwrite", () => null, {
        allowUnverifiedLegacy: true,
      })
    ).rejects.toThrow(/namespace/);
    expect(await storage.read("safe", "keep")).toEqual(new Uint8Array([8, 9]));
    expect((await storage.listNamespaces()).filter((name) => !name.startsWith("_"))).toEqual([
      "safe",
    ]);
  });

  it("refuses state_import bundles naming a namespace that is not a single path component before approval is requested", async () => {
    const masterKey = generateRandomKey();
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, masterKey);
    const stateStore = new StateStore(storage, masterKey);
    await storage.write("safe", "keep", new Uint8Array([1, 3]));
    const { tools, identityManager } = createCognitiveTools(
      stateStore,
      storage,
      masterKey,
      "passphrase",
      auditLog
    );
    await identityManager.load();

    let approvalRequests = 0;
    const baseline = new BaselineTracker(storage, masterKey);
    await baseline.load();
    const gate = new ApprovalGate(
      DEFAULT_POLICY,
      baseline,
      new CallbackApprovalChannel(async () => {
        approvalRequests++;
        return {
          decision: "approve",
          decided_at: new Date().toISOString(),
          decided_by: "human",
        };
      }),
      auditLog
    );
    const server = createServer(selectedTools(tools, ["state_import"]), {
      gate,
      auditLog,
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "state-import-namespace-component-test", version: "1.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    try {
      const payload = parseToolPayload(
        await client.callTool({
          name: "state_import",
          arguments: {
            bundle: legacyBundleForNamespace("."),
            conflict_resolution: "overwrite",
            allow_unverified_legacy: true,
          },
        })
      );
      expect(payload.denied).toBe(true);
      expect(approvalRequests).toBe(0);
      expect(await storage.read("safe", "keep")).toEqual(new Uint8Array([1, 3]));
      expect((await storage.listNamespaces()).filter((name) => !name.startsWith("_"))).toEqual([
        "safe",
      ]);
    } finally {
      await client.close().catch(() => {});
      await server.close().catch(() => {});
    }
  });

  it("keeps ordinary state tool namespace names working", async () => {
    const masterKey = generateRandomKey();
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, masterKey);
    const stateStore = new StateStore(storage, masterKey);
    const { tools, identityManager } = createCognitiveTools(
      stateStore,
      storage,
      masterKey,
      "passphrase",
      auditLog
    );
    await identityManager.load();
    const identityTool = tools.find((tool) => tool.name === "identity_create");
    const writeTool = tools.find((tool) => tool.name === "state_write");
    const readTool = tools.find((tool) => tool.name === "state_read");
    if (!identityTool || !writeTool || !readTool) {
      throw new Error("test harness missing state tools");
    }
    const identityResult = await identityTool.handler({ label: "ordinary-names" });
    const identity = JSON.parse(identityResult.content[0]!.text) as { identity_id: string };

    for (const namespace of ["notes", "a.b", ".visible", "..notes", "..visible"]) {
      const write = JSON.parse(
        (await writeTool.handler({
          namespace,
          key: "k",
          value: `value-${namespace}`,
          identity_id: identity.identity_id,
        })).content[0]!.text
      ) as Record<string, unknown>;
      expect(write.error).toBeUndefined();
      const read = JSON.parse(
        (await readTool.handler({
          namespace,
          key: "k",
          verify_integrity: true,
        })).content[0]!.text
      ) as Record<string, unknown>;
      expect(read.value).toBe(`value-${namespace}`);
    }
  });
});
