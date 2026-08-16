import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { bytesToString, stringToBytes } from "../../src/core/encoding.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog, type PersistedAuditEnvelopeV2 } from "../../src/operational/audit-log.js";
import { createServer, toolResult, type ToolDefinition } from "../../src/router.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { extraAllowedFieldsForTool } from "../../src/tool-args.js";

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
  it("allows read tools and unconditionally blocks write tools on a broken chain", async () => {
    // CALLER-CONTROLLED-AUDIT-OVERRIDE (register row, HIGH; MUST-NEVER #5):
    // this test is the fail-before/after proof for the removal of the
    // agent-facing accept_broken_chain override. Pre-fix, this same setup
    // (with `arguments: { accept_broken_chain: true }` added to the write
    // call) let the write through and recorded an
    // `mcp_accept_broken_chain_override` audit entry keyed on the CALLING
    // AGENT's identity — an agent-reachable bypass of the audit-integrity
    // gate. Post-fix there is no argument that lifts the block. (The
    // operator CLI's `--accept-broken-chain` is a separate mechanism that
    // does not clear findings or reach this gate; see castle-wall.ts.)
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
    const readPayload = textPayload(readResult);
    expect(readPayload).toMatchObject({ ok: true });
    expect(readPayload.findings).toEqual(expect.any(Number));
    expect(readPayload.findings as number).toBeGreaterThanOrEqual(1);

    const blockedWrite = await client.callTool({ name: "test_write", arguments: {} });
    expect(blockedWrite.isError).toBe(true);
    expect(textPayload(blockedWrite)).toMatchObject({
      remediation: "none_available",
    });
    expect(writeCount).toBe(0);

    // An agent-supplied accept_broken_chain no longer exists as an accepted
    // argument at all — it is refused at schema validation, BEFORE the
    // audit-integrity gate even runs, with a diagnosable violation naming
    // the unknown field (never silently ignored/dropped).
    const attemptedOverride = await client.callTool({
      name: "test_write",
      arguments: { accept_broken_chain: true },
    });
    expect(attemptedOverride.isError).toBe(true);
    const overridePayload = textPayload(attemptedOverride);
    expect(overridePayload.error).toBe("validation_failed");
    expect(overridePayload.violations).toMatchObject([
      { field: "accept_broken_chain", message: expect.stringContaining("Unknown field") },
    ]);
    expect(writeCount).toBe(0);

    // No override audit entry is ever written — the operation name is gone
    // from the MCP path entirely (it survives only on the operator CLI side
    // as castle_wall_accept_broken_chain_override, a distinct operation).
    const entries = await auditLog.runAllowingIntegrityFindings(() =>
      auditLog.query({ limit: 20 })
    );
    expect(entries.entries.some((entry) => entry.operation === "mcp_accept_broken_chain_override"))
      .toBe(false);

    await client.close();
  });

  it("extraAllowedFieldsForTool returns exactly the current allowlist (full-set assertion)", () => {
    // AGENTS.md rule 5: a check that asserts only "accept_broken_chain is
    // gone" cannot detect a differently-named field re-adding an equivalent
    // escape hatch — every accept_broken_chain-specific assertion above
    // would stay green. Asserting the WHOLE shape closes that class: any
    // future addition to this allowlist, under any name, fails this test
    // until it is a deliberate, reviewed change.
    expect(extraAllowedFieldsForTool()).toEqual({
      approval_ref: { type: "string" },
    });
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
