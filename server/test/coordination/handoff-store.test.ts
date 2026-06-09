import { describe, expect, it } from "vitest";

import type { LocalHandoffRecord } from "../../src/contracts/v1.1/handoff-records.js";
import { HandoffStore, HANDOFF_NAMESPACE } from "../../src/coordination/handoff-store.js";
import { stringToBytes } from "../../src/core/encoding.js";
import { MemoryStorage } from "../../src/storage/memory.js";

const MASTER_KEY = new Uint8Array(32).fill(17);

describe("HandoffStore", () => {
  it("persists encrypted records, reloads from storage, and filters in created_at order", async () => {
    const storage = new MemoryStorage();
    const store = new HandoffStore(storage, MASTER_KEY);
    const laterAccepted = handoffRecord({
      handoff_id: "handoff-later",
      created_at: "2026-06-09T12:00:01.000Z",
      identity_id: "operator-a",
      sender_agent_id: "agent-a",
      recipient_agent_id: "agent-b",
      status: "accepted",
    });
    const earlierCreated = handoffRecord({
      handoff_id: "handoff-earlier",
      created_at: "2026-06-09T12:00:00.000Z",
      identity_id: "operator-a",
      sender_agent_id: "agent-a",
      recipient_agent_id: "agent-c",
      status: "created",
    });
    const otherIdentity = handoffRecord({
      handoff_id: "handoff-other-identity",
      created_at: "2026-06-09T12:00:02.000Z",
      identity_id: "operator-b",
      sender_agent_id: "agent-z",
      recipient_agent_id: "agent-b",
      status: "accepted",
    });

    await store.put(laterAccepted);
    await store.put(earlierCreated);
    await store.put(otherIdentity);

    const raw = await storage.read(HANDOFF_NAMESPACE, laterAccepted.handoff_id);
    expect(raw).not.toBeNull();
    expect(new TextDecoder().decode(raw!)).not.toContain("agent-a");
    expect(new TextDecoder().decode(raw!)).not.toContain("handoff-later");

    const reloaded = new HandoffStore(storage, MASTER_KEY);
    await expect(reloaded.get(laterAccepted.handoff_id)).resolves.toMatchObject({
      handoff_id: laterAccepted.handoff_id,
      recipient_agent_id: "agent-b",
      status: "accepted",
    });

    await expect(
      reloaded.list({ identity_id: "operator-a", sender_agent_id: "agent-a" }),
    ).resolves.toMatchObject([
      { handoff_id: "handoff-earlier" },
      { handoff_id: "handoff-later" },
    ]);
    await expect(reloaded.list({ status: "accepted" })).resolves.toMatchObject([
      { handoff_id: "handoff-later" },
      { handoff_id: "handoff-other-identity" },
    ]);
    await expect(
      reloaded.list({ recipient_agent_id: "agent-c", status: "accepted" }),
    ).resolves.toEqual([]);
  });

  it("returns undefined for malformed ciphertext and skips corrupted entries during list", async () => {
    const storage = new MemoryStorage();
    const store = new HandoffStore(storage, MASTER_KEY);
    const good = handoffRecord({
      handoff_id: "handoff-good",
      created_at: "2026-06-09T12:00:00.000Z",
      identity_id: "operator-a",
      sender_agent_id: "agent-a",
      recipient_agent_id: "agent-b",
      status: "created",
    });
    await store.put(good);
    await storage.write(HANDOFF_NAMESPACE, "handoff-corrupt", stringToBytes("not-json"));

    const reloaded = new HandoffStore(storage, MASTER_KEY);

    await expect(reloaded.get("handoff-corrupt")).resolves.toBeUndefined();
    await expect(reloaded.list()).resolves.toMatchObject([
      { handoff_id: "handoff-good" },
    ]);
  });
});

function handoffRecord(
  overrides: Pick<
    LocalHandoffRecord,
    | "handoff_id"
    | "created_at"
    | "identity_id"
    | "sender_agent_id"
    | "recipient_agent_id"
    | "status"
  >,
): LocalHandoffRecord {
  return {
    version: "1.1",
    handoff_id: overrides.handoff_id,
    created_at: overrides.created_at,
    sender_agent_id: overrides.sender_agent_id,
    recipient_agent_id: overrides.recipient_agent_id,
    identity_id: overrides.identity_id,
    task_scope: {
      category: "delegate_subtask",
      task_id: `task-${overrides.handoff_id}`,
      requested_capabilities: ["plans"],
      priority: "normal",
    },
    context_reference: {
      policy_context_id: "policy-context-1",
      audit_entry_id: `audit-${overrides.handoff_id}`,
      placeholder_refs: [`placeholder-${overrides.handoff_id}`],
    },
    status: overrides.status,
    status_changed_at: overrides.created_at,
    signature_scheme: "ed25519-v1",
    signature: `signature-${overrides.handoff_id}`,
  };
}
