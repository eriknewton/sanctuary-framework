import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { bytesToString, stringToBytes } from "../../src/core/encoding.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog, type PersistedAuditEnvelopeV2 } from "../../src/l2-operational/audit-log.js";
import { createServer, toolResult, type ToolDefinition } from "../../src/router.js";
import { MemoryStorage } from "../../src/storage/memory.js";

async function connectTools(tools: ToolDefinition[], auditLog: AuditLog): Promise<Client> {
  const server = createServer(tools, { auditLog });
  const client = new Client({ name: "audit-gate-test", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return client;
}

async function makeBrokenAuditLog(): Promise<{
  auditLog: AuditLog;
  storage: MemoryStorage;
  masterKey: Uint8Array;
}> {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const writer = new AuditLog(storage, masterKey);
  await writer.appendCritical({
    layer: "l1",
    operation: "seed",
    identity_id: "test",
    result: "success",
  });

  const key = (await storage.list("_audit"))[0]!.key;
  const raw = await storage.read("_audit", key);
  const envelope = JSON.parse(bytesToString(raw!)) as PersistedAuditEnvelopeV2;
  envelope.entry_hash = "0".repeat(64);
  await storage.write("_audit", key, stringToBytes(JSON.stringify(envelope)));

  return { auditLog: new AuditLog(storage, masterKey), storage, masterKey };
}

function textPayload(result: Awaited<ReturnType<Client["callTool"]>>): Record<string, unknown> {
  const first = result.content[0];
  if (!first || first.type !== "text") throw new Error("missing text result");
  return JSON.parse(first.text) as Record<string, unknown>;
}

describe("MCP audit-integrity gate classification", () => {
  it("allows read tools, blocks write tools, and permits explicit write override", async () => {
    const { auditLog } = await makeBrokenAuditLog();
    let writeCount = 0;
    const tools: ToolDefinition[] = [
      {
        name: "test_read",
        description: "read",
        tool_class: "read",
        inputSchema: { type: "object", properties: {} },
        handler: async () => {
          const result = await auditLog.query({ limit: 10 });
          return toolResult({ ok: true, findings: result.integrity_findings.length });
        },
      },
      {
        name: "test_write",
        description: "write",
        tool_class: "write",
        inputSchema: { type: "object", properties: {} },
        handler: async () => {
          writeCount += 1;
          await auditLog.appendCritical({
            layer: "l1",
            operation: "test_write",
            identity_id: "test",
            result: "success",
          });
          return toolResult({ ok: true });
        },
      },
    ];
    const client = await connectTools(tools, auditLog);

    const readResult = await client.callTool({ name: "test_read", arguments: {} });
    expect(readResult.isError).not.toBe(true);
    expect(textPayload(readResult)).toMatchObject({ ok: true, findings: 1 });

    const blockedWrite = await client.callTool({ name: "test_write", arguments: {} });
    expect(blockedWrite.isError).toBe(true);
    expect(textPayload(blockedWrite)).toMatchObject({
      accept_broken_chain_required: true,
    });
    expect(writeCount).toBe(0);

    const overrideWrite = await client.callTool({
      name: "test_write",
      arguments: { accept_broken_chain: true },
    });
    expect(overrideWrite.isError).not.toBe(true);
    expect(textPayload(overrideWrite)).toMatchObject({ ok: true });
    expect(writeCount).toBe(1);

    const entries = await auditLog.runAllowingIntegrityFindings(() =>
      auditLog.query({ limit: 20 })
    );
    expect(entries.entries.some((entry) => entry.operation === "mcp_accept_broken_chain_override"))
      .toBe(true);

    await client.close();
  });

  it("fails registration when a tool lacks tool_class", () => {
    expect(() =>
      createServer([
        {
          name: "missing_class",
          description: "missing",
          inputSchema: { type: "object", properties: {} },
          handler: async () => toolResult({ ok: true }),
        },
      ])
    ).toThrow(/missing tool_class/);
  });
});
