// fail-before-exempt: new HubInboxStore tests cover retry and failed-resolution payload plumbing, not stop-button enforcement; real coverage is in agent-stop, egress, and controller tests.
import { describe, expect, it } from "vitest";

import { HubInboxStore } from "../../src/hub/inbox-store.js";
import type { HubApprovalPendingItem } from "../../src/contracts/v1.1/hub-events.js";

function item(id: string): HubApprovalPendingItem {
  return {
    version: "1.1",
    item_id: id,
    kind: "approval_pending",
    created_at: "2026-08-08T00:00:00.000Z",
    identity_id: "operator",
    display_template_id: "approval_pending.tier1.lockdown",
    display_template_args: [
      { kind: "identity_id", value: "operator" },
      { kind: "tier", value: "tier1" },
    ],
    resolved: false,
    tier: "tier1",
    operation_category: "lockdown",
  };
}

describe("HubInboxStore Tier 1 resolution outcomes", () => {
  it("keeps a throwing handler unresolved so approval can be retried", async () => {
    const store = new HubInboxStore();
    store.enqueueTier1(item("tier1.throwing"), async () => {
      throw new Error("handler failed");
    });

    await expect(
      store.resolve("tier1.throwing", "approve", "2026-08-08T00:00:01.000Z"),
    ).rejects.toThrow("handler failed");

    expect(store.get("tier1.throwing")).toMatchObject({ resolved: false });
    await expect(
      store.resolve("tier1.throwing", "approve", "2026-08-08T00:00:02.000Z"),
    ).rejects.toThrow("handler failed");
  });

  it("attaches returned failure payloads to resolved items", async () => {
    const store = new HubInboxStore();
    store.enqueueTier1(item("tier1.failed-payload"), async () => ({
      resolution_payload: {
        outcome: "failed",
        locked_count: 0,
        failed_count: 1,
      },
    }));

    const resolved = await store.resolve(
      "tier1.failed-payload",
      "approve",
      "2026-08-08T00:00:01.000Z",
    );

    expect(resolved).toMatchObject({
      resolved: true,
      resolution_payload: {
        outcome: "failed",
        locked_count: 0,
        failed_count: 1,
      },
    });
  });
});
