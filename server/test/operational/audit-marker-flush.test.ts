/**
 * A successful call's success marker is not awaited at the request boundary,
 * so flush() is where a failed marker is reported: it rejects once, as for a
 * failed append, and the tool's successful result is unchanged.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  AUDIT_NAMESPACE,
  AuditLog,
  AuditLogPersistenceError,
  CALL_OUTCOME_SUCCESS_OPERATION,
} from "../../src/operational/audit-log.js";
import { createServer, toolResult, type ToolDefinition } from "../../src/router.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

type CallHandler = (request: unknown, extra: { signal: AbortSignal }) => Promise<unknown>;
type PrivateWrites = {
  writeAuditEntryBytes: (key: string, bytes: Uint8Array) => Promise<void>;
  writeHeadAnchor: (...args: unknown[]) => Promise<void>;
};

const OK_BODY = { ok: true };

afterEach(() => {
  vi.restoreAllMocks();
});

/** A router over one tool that writes one own row, then arms `armFault` so the next store write is the marker's. */
function rig(armFault: () => void) {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const tool: ToolDefinition = {
    name: "t",
    description: "t",
    tool_class: "write",
    inputSchema: { type: "object", properties: {} },
    handler: async () => {
      await auditLog.append("l2", "own_row", "agent:unknown");
      armFault();
      return toolResult(OK_BODY);
    },
  };
  const server = createServer([tool], { auditLog });
  const handler = (server as unknown as { _requestHandlers: Map<string, CallHandler> })._requestHandlers.get("tools/call")!;
  const call = () => handler({ method: "tools/call", params: { name: "t", arguments: {} } }, { signal: new AbortController().signal });
  return { storage, masterKey, auditLog, call };
}

describe("flush reports a failed success marker", () => {
  it("a marker the store refuses before its bytes are written makes flush reject once, and the tool result is unchanged", async () => {
    let failNext = false;
    const r = rig(() => { failNext = true; });
    const writes = r.auditLog as unknown as PrivateWrites;
    const original = writes.writeAuditEntryBytes.bind(r.auditLog);
    vi.spyOn(writes, "writeAuditEntryBytes").mockImplementation(async (key, bytes) => {
      if (failNext) {
        failNext = false;
        throw new Error("injected store refusal");
      }
      return original(key, bytes);
    });
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    expect(await r.call()).toEqual(toolResult(OK_BODY));
    // The marker settles before flush is called; the failure is still reported.
    for (let i = 0; i < 50; i++) await new Promise((resolve) => setImmediate(resolve));
    await expect(r.auditLog.flush()).rejects.toBeInstanceOf(AuditLogPersistenceError);
    await expect(r.auditLog.flush()).resolves.toBeUndefined();
    const rows = (await r.auditLog.query({ limit: 100, include_outcome_markers: true })).entries;
    expect(rows.map((row) => row.operation)).toEqual(["own_row"]);
  });

  it("a marker whose append rejects after its bytes are durable makes flush reject, and the marker is valid after reopen", async () => {
    let failNext = false;
    const r = rig(() => { failNext = true; });
    const writes = r.auditLog as unknown as PrivateWrites;
    const original = writes.writeHeadAnchor.bind(r.auditLog);
    vi.spyOn(writes, "writeHeadAnchor").mockImplementation(async (...args: unknown[]) => {
      if (failNext) {
        failNext = false;
        throw new Error("injected anchor failure");
      }
      return original(...args);
    });
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    expect(await r.call()).toEqual(toolResult(OK_BODY));
    // Flush is called while the marker may still be in flight.
    await expect(r.auditLog.flush()).rejects.toBeInstanceOf(AuditLogPersistenceError);
    await expect(r.auditLog.flush()).resolves.toBeUndefined();
    const reopened = new AuditLog(r.storage, r.masterKey);
    const rows = (await reopened.query({ limit: 100, include_outcome_markers: true })).entries;
    expect(rows.map((row) => row.operation)).toEqual(["own_row", CALL_OUTCOME_SUCCESS_OPERATION]);
  });

  it("a successful call whose marker lands leaves flush resolving", async () => {
    const r = rig(() => undefined);
    expect(await r.call()).toEqual(toolResult(OK_BODY));
    await expect(r.auditLog.flush()).resolves.toBeUndefined();
  });

  it("a read call on a chain with integrity findings marks the rows it was allowed to write, and flush resolves", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const writer = new AuditLog(storage, masterKey);
    await writer.appendCritical({ layer: "l2", operation: "one", identity_id: "system", result: "success" });
    await writer.appendCritical({ layer: "l2", operation: "two", identity_id: "system", result: "success" });
    await writer.appendCritical({ layer: "l2", operation: "three", identity_id: "system", result: "success" });
    // The oldest stored entry deleted: a hard finding on every later load, below the head the anchor names.
    const keys = (await storage.list(AUDIT_NAMESPACE, "entry-")).map((m) => m.key).sort();
    await storage.delete(AUDIT_NAMESPACE, keys[0]!);
    const auditLog = new AuditLog(storage, masterKey);
    const tool: ToolDefinition = {
      name: "r",
      description: "r",
      tool_class: "read",
      inputSchema: { type: "object", properties: {} },
      handler: async () => {
        await auditLog.append("l2", "read_row", "agent:unknown");
        return toolResult(OK_BODY);
      },
    };
    const handler = (createServer([tool], { auditLog }) as unknown as { _requestHandlers: Map<string, CallHandler> })._requestHandlers.get("tools/call")!;
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    expect(await handler({ method: "tools/call", params: { name: "r", arguments: {} } }, { signal: new AbortController().signal })).toEqual(toolResult(OK_BODY));
    await expect(auditLog.flush()).resolves.toBeUndefined();
    const visible = await auditLog.runAllowingIntegrityFindings(() => auditLog.query({ agent_visible: true, limit: 100 }));
    expect(visible.integrity_findings.length).toBeGreaterThan(0);
    expect(visible.entries.map((row) => row.operation)).toContain("read_row");
  });
});
