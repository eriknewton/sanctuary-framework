import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { buildV11Bindings, fortressIdFromStoragePath } from "../../../src/dashboard/v1_1/wiring.js";
import { upsertPersistedLocalAgent } from "../../../src/hub/agent-registry-persistence.js";
import { InMemoryLocalAgentRegistry } from "../../../src/hub/index.js";
import type { LocalAgentRecord } from "../../../src/contracts/v1.1/local-agent-records.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { MemoryStorage } from "../../../src/storage/memory.js";

const NOW = "2026-10-27T12:00:00.000Z";
const IDENTITY = "operator-persisted-inbox";

function agent(agentId: string): LocalAgentRecord {
  return {
    version: "1.1", agent_id: agentId, identity_id: IDENTITY, harness: "other",
    model_provider: { vendor: "local", model_id: "test", runs_locally: true },
    policy_id: "test", status: "error", status_reason_class: "harness_error",
    budget_summary: { last_refreshed_at: NOW, daily: { unit: "tokens", cap: 1, used: 1 } },
    wrapped_at: NOW, last_activity_at: NOW,
    capabilities: { can_pause: false, can_resume: false, can_restart: false, can_unwrap: false,
      can_lockdown: false, can_chat: false, can_change_template: false },
  };
}

describe("persisted agents on production inbox reads", () => {
  let storagePath: string;
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW);
    storagePath = mkdtempSync(join(tmpdir(), "sanctuary-inbox-refresh-"));
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
    rmSync(storagePath, { recursive: true, force: true });
  });

  it("reads a post-boot append on listInbox and keeps unchanged refreshes silent", async () => {
    const known = agent("known-before-boot");
    upsertPersistedLocalAgent(storagePath, known);
    // Audit storage is in memory; 32 bytes is the required 256-bit test key.
    const auditLog = new AuditLog(new MemoryStorage(), Buffer.alloc(32));
    const publisher = { publishInbox: vi.fn(), publishAgentStatus: vi.fn() };
    const { hubService } = buildV11Bindings({ identityId: IDENTITY,
      fortressId: fortressIdFromStoragePath(storagePath), storagePath, auditLog, streamPublisher: publisher });
    const listAgents = vi.spyOn(hubService, "listAgents");
    const put = vi.spyOn(InMemoryLocalAgentRegistry.prototype, "put");
    try {
      const initial = hubService.listInbox();
      expect(initial.map((item) => item.kind).sort()).toEqual(["agent_error", "budget_warning"]);
      expect(publisher.publishAgentStatus).not.toHaveBeenCalled();

      const appended = agent("wrapped-after-boot");
      upsertPersistedLocalAgent(storagePath, appended);
      const items = hubService.listInbox();
      expect(items.filter((item) => item.agent_id === appended.agent_id).map((item) => item.kind).sort())
        .toEqual(["agent_error", "budget_warning"]);
      expect(publisher.publishAgentStatus).toHaveBeenCalledTimes(1); // Only the newly appended record changed.
      expect(publisher.publishInbox).toHaveBeenCalledTimes(items.length);

      const inboxCalls = publisher.publishInbox.mock.calls.length;
      const statusCalls = publisher.publishAgentStatus.mock.calls.length;
      put.mockClear();
      expect(hubService.listInbox()).toEqual(items);
      // Prove the refresh reached put for both records; silence alone could also mean no refresh happened.
      expect(put.mock.calls).toEqual([[known], [appended]]);
      expect(publisher.publishInbox).toHaveBeenCalledTimes(inboxCalls);
      expect(publisher.publishAgentStatus).toHaveBeenCalledTimes(statusCalls);
      expect(listAgents).not.toHaveBeenCalled();
    } finally {
      await auditLog.flush();
    }
  });
});
