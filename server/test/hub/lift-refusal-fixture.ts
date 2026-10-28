/** Authenticated production bindings for approval feedback. IC-11. */
import { EventEmitter } from "node:events";
import type { IncomingMessage, ServerResponse } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { MemoryStorage } from "../../src/storage/memory.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { buildV11Bindings, fortressIdFromStoragePath } from "../../src/dashboard/v1_1/wiring.js";
import { dispatchV11Request } from "../../src/dashboard/v1_1/dispatch.js";
import { writePersistedLocalAgents } from "../../src/hub/agent-registry-persistence.js";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import type { HubInboxStore } from "../../src/hub/inbox-store.js";
import type { HubServiceDeps } from "../../src/hub/types.js";

export const REFUSAL_STATUS = 422; // HTTP Unprocessable Content.
export const LIFT_REASONS = ["agent_control_lockdown_lift_unsupported_not_locked_down", "lockdown_lift_no_snapshot"] as const;
export const refusalDetail = (reason: string) => `capability not supported: ${reason}`;
export class ApprovalReply extends EventEmitter {
  statusCode = 0;
  headersSent = false;
  destroyed = false;
  headers: Record<string, string> = {};
  chunks: string[] = [];
  writeHead(code: number, headers: Record<string, string>) { this.statusCode = code; this.headers = headers; this.headersSent = true; return this; }
  end(chunk = "") { this.chunks.push(chunk); return this; }
  destroy() { this.destroyed = true; this.emit("close"); return this; }
  json() { return JSON.parse(this.chunks.join("")); }
}
export async function liftFixture(lift?: Parameters<typeof buildV11Bindings>[0]["liftAgentEgressStop"]) {
  const storagePath = await mkdtemp(join(tmpdir(), "lift-feedback-"));
  const auditLog = new AuditLog(new MemoryStorage(), randomBytes(32)); // AES-256 fixture key.
  const record: LocalAgentRecord = {
    version: "1.1", agent_id: "fixture-agent", identity_id: "operator-fixture", harness: "claude_code",
    model_provider: {} as LocalAgentRecord["model_provider"], policy_id: "fixture-policy", status: "locked_down",
    budget_summary: {} as LocalAgentRecord["budget_summary"],
    last_activity_at: new Date().toISOString(), wrapped_at: new Date().toISOString(),
    capabilities: { can_pause: false, can_resume: false, can_restart: false, can_unwrap: false, can_lockdown: true, can_chat: false, can_change_template: false },
  };
  writePersistedLocalAgents(storagePath, [record]);
  const bindings = buildV11Bindings({ identityId: record.identity_id, fortressId: fortressIdFromStoragePath(storagePath), storagePath, auditLog, liftAgentEgressStop: lift });
  const service = bindings.hubService;
  const internals = service as unknown as { inboxStore: HubInboxStore; deps: HubServiceDeps };
  const call = async (path: string, method = "POST", reply = new ApprovalReply()) => {
    const req = Object.assign(new EventEmitter(), { url: path, method, headers: { host: "localhost", authorization: "Bearer fixture-operator" }, socket: { remoteAddress: "127.0.0.1" } }) as IncomingMessage;
    await dispatchV11Request({ bindings, authToken: "fixture-operator", loopbackAutoAuth: false }, req, reply as unknown as ServerResponse, new URL(path, "http://localhost"), method);
    return reply;
  };
  const enqueue = async () => {
    const result = await service.controlAgent(record.agent_id, "lockdown_lift");
    if (!("inbox_item_id" in result)) throw new Error("Expected queued approval");
    return result.inbox_item_id;
  };
  return { storagePath, auditLog, record, bindings, service, ...internals, call, enqueue,
    setStatus(status: LocalAgentRecord["status"]) { record.status = status; writePersistedLocalAgents(storagePath, [record]); internals.deps.agentRegistry.updateStatus(record.agent_id, status); },
    async close() { await auditLog.flush(); await rm(storagePath, { recursive: true, force: true }); },
  };
}
