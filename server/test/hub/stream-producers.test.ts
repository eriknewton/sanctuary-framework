/** Inbox and registry mutations publish bounded dashboard invalidations. IC-12. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { HubService, HubInboxStore, InMemoryLocalAgentRegistry, createHubInboxSources,
  type HubStreamPublisher } from "../../src/hub/index.js";
import type { HubApprovalPendingItem, HubInboxItem } from "../../src/contracts/v1.1/hub-events.js";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import type { AuditLog } from "../../src/operational/audit-log.js";

const NOW = "2026-10-26T12:00:00.000Z";
const IDENTITY = "operator-stream";
const FORTRESS = "fortress-stream";
const HEADER_KEYS = ["item_id", "kind", "identity_id", "fortress_id", "emitted_at", "resolved"].sort();
const REFRESH_WAVES = 20; // Twenty refetch waves exercise the repeated-admission schedule.
const NEXT_TICK_MS = 1; // One clock tick distinguishes activity timestamps without sleeps.
function agent(): LocalAgentRecord {
  return { version: "1.1", agent_id: "agent-stream", identity_id: IDENTITY, harness: "other",
    model_provider: { vendor: "local", model_id: "test", runs_locally: true }, policy_id: "policy",
    status: "error", status_reason_class: "harness_error", last_activity_at: NOW, wrapped_at: NOW,
    budget_summary: { last_refreshed_at: NOW, daily: { unit: "tokens", cap: 1, used: 1 } },
    capabilities: { can_pause: true, can_resume: true, can_restart: true, can_unwrap: true,
      can_lockdown: true, can_chat: false, can_change_template: true } };
}
function approval(item_id: string): HubApprovalPendingItem {
  return { version: "1.1", item_id, kind: "approval_pending", identity_id: IDENTITY,
    agent_id: agent().agent_id, created_at: NOW, resolved: false, tier: "tier1",
    operation_category: "lockdown", display_template_id: "approval_pending.tier1.lockdown",
    display_template_args: [{ kind: "agent_id", value: agent().agent_id }] };
}
function setup(publisher?: HubStreamPublisher) {
  const registry = new InMemoryLocalAgentRegistry([agent()]);
  const sources = createHubInboxSources({ identityId: IDENTITY, agentRegistry: registry });
  const service = new HubService({ identityId: IDENTITY, fortressId: FORTRESS, agentRegistry: registry,
    streamPublisher: publisher, inboxSources: sources, now: () => new Date(),
    activitySources: { identityId: IDENTITY, auditLog: { append: vi.fn(async () => {}) } as unknown as AuditLog },
    policyBudgetSources: { listPolicySummaries: () => [], listBudgetSummaries: () => [] },
    agentController: { supports: () => true, pause: async () => "paused", resume: async () => "active",
      restart: async () => "active", unwrap: async () => "unwrapping", lockdown: async () => "locked_down",
      liftLockdown: async () => ({ outcome: "restored", restored_rule_ids: [], removed_rule_ids: [], reload_confirmed: true }),
      bindPolicy: async () => {}, bindChannelTemplate: async () => {} },
  });
  return { registry, sources, service };
}
function recorder() { return { publishInbox: vi.fn(), publishAgentStatus: vi.fn() }; }
function expectHeader(frame: unknown, item: HubInboxItem) {
  expect(Object.keys(frame as object).sort()).toEqual(HEADER_KEYS);
  expect(frame).toEqual({ item_id: item.item_id, kind: item.kind, identity_id: item.identity_id,
    fortress_id: FORTRESS, emitted_at: new Date().toISOString(), resolved: item.resolved });
}

beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(NOW); });
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

describe("hub stream producers", () => {
  it("publishes only headers for new source cards, Tier 1 enqueue and resolution", async () => {
    const publisher = recorder();
    const { service } = setup(publisher);
    const items = service.listInbox();
    expect(publisher.publishInbox).toHaveBeenCalledTimes(items.length);
    for (const [frame] of publisher.publishInbox.mock.calls) expectHeader(frame, items.find((i) => i.item_id === frame.item_id)!);
    publisher.publishInbox.mockClear();
    const queued = service.enqueueFortressLockdown();
    const pending = service.listInbox().find((i) => i.item_id === queued.inbox_item_id)!;
    expect(publisher.publishInbox).toHaveBeenCalledTimes(1);
    expectHeader(publisher.publishInbox.mock.calls[0][0], pending);
    publisher.publishInbox.mockClear();
    const resolved = await service.resolveInboxItem(queued.inbox_item_id, "approve");
    expect(publisher.publishInbox).toHaveBeenCalledTimes(1);
    expectHeader(publisher.publishInbox.mock.calls[0][0], resolved);
    expect((resolved as HubApprovalPendingItem).resolution_payload).toBeDefined();
  });

  it("bounds repeated and changed-field refreshes, clearing, and re-emission", async () => {
    const publisher = recorder();
    const { service, sources } = setup(publisher);
    const items = service.listInbox();
    expect(publisher.publishInbox).toHaveBeenCalledTimes(2); // Budget warning and agent error.
    publisher.publishInbox.mockClear();
    for (let wave = 0; wave < REFRESH_WAVES; wave++) service.listInbox();
    const errors = sources.listRecentAgentErrors();
    sources.listRecentAgentErrors = () => errors.map((item) => ({ ...item, agent_still_active: true }));
    service.listInbox();
    expect(publisher.publishInbox).not.toHaveBeenCalled();
    const budget = items.find((i) => i.kind === "budget_warning")!;
    await service.resolveInboxItem(budget.item_id, "dismiss");
    expect(publisher.publishInbox).toHaveBeenCalledTimes(1);
    publisher.publishInbox.mockClear();
    sources.listRecentAgentErrors = () => [];
    sources.listPresentSourceIds = undefined;
    service.listInbox();
    expect(publisher.publishInbox).toHaveBeenCalledTimes(1);
    expectHeader(publisher.publishInbox.mock.calls[0][0], { ...errors[0], resolved: true });
    publisher.publishInbox.mockClear();
    for (let wave = 0; wave < REFRESH_WAVES; wave++) service.listInbox();
    expect(publisher.publishInbox).not.toHaveBeenCalled();
    sources.listRecentAgentErrors = () => errors;
    service.listInbox();
    expect(publisher.publishInbox).toHaveBeenCalledTimes(1);
    expectHeader(publisher.publishInbox.mock.calls[0][0], errors[0]);
  });

  it("publishes post-change status and open ids once for updates, insertions and removals", () => {
    const publisher = recorder();
    const { registry, service } = setup(publisher);
    const openIds = service.listInbox().map((i) => i.item_id).sort();
    registry.updateStatus(agent().agent_id, "locked_down", "operator_lockdown");
    expect(publisher.publishAgentStatus).toHaveBeenCalledTimes(1);
    expect(publisher.publishAgentStatus.mock.calls[0][0]).toEqual({ version: "1.1", agent_id: agent().agent_id,
      status: "locked_down", status_reason_class: "operator_lockdown", last_activity_at: NOW,
      open_inbox_item_ids: expect.arrayContaining(openIds) });
    expect(publisher.publishAgentStatus.mock.calls[0][0].open_inbox_item_ids).toHaveLength(openIds.length);
    publisher.publishAgentStatus.mockClear();
    registry.put({ ...agent(), agent_id: "new-agent" });
    expect(publisher.publishAgentStatus).toHaveBeenCalledTimes(1);
    publisher.publishAgentStatus.mockClear();
    registry.remove("new-agent");
    expect(publisher.publishAgentStatus.mock.calls[0][0]).toEqual({ version: "1.1", agent_id: "new-agent",
      status: "unknown", last_activity_at: NOW, open_inbox_item_ids: [] });
    registry.remove("new-agent");
    expect(publisher.publishAgentStatus).toHaveBeenCalledTimes(1);
  });

  it("suppresses persisted refreshes and emits binding changes only for a changed snapshot timestamp", () => {
    const publisher = recorder();
    const { registry } = setup(publisher);
    for (let wave = 0; wave < REFRESH_WAVES; wave++) registry.put({ ...agent() });
    registry.updatePolicyBinding(agent().agent_id, "next-policy");
    registry.updateChannelTemplateBinding(agent().agent_id, "request-approve-act");
    expect(publisher.publishAgentStatus).not.toHaveBeenCalled();
    for (const update of [() => registry.updatePolicyBinding(agent().agent_id, "another-policy"),
      () => registry.updateChannelTemplateBinding(agent().agent_id, "request-approve-act")]) {
      vi.advanceTimersByTime(NEXT_TICK_MS);
      publisher.publishAgentStatus.mockClear();
      update();
      expect(publisher.publishAgentStatus).toHaveBeenCalledTimes(1);
      expect(publisher.publishAgentStatus.mock.calls[0][0].last_activity_at).toBe(new Date().toISOString());
    }
  });

  it("counts each throwing publisher once while resolve and status updates still commit", async () => {
    const publish = vi.fn(() => { throw new Error("sink unavailable"); });
    const { registry, service } = setup({ publishInbox: publish, publishAgentStatus: publish });
    const [item] = service.listInbox();
    expect(service.streamPublishErrorCount).toBe(publish.mock.calls.length);
    const before = service.streamPublishErrorCount;
    await expect(service.resolveInboxItem(item.item_id, "dismiss")).resolves.toMatchObject({ resolved: true });
    expect(service.streamPublishErrorCount).toBe(before + 1);
    registry.updateStatus(agent().agent_id, "paused");
    expect(registry.get(agent().agent_id)?.status).toBe("paused");
    expect(service.streamPublishErrorCount).toBe(before + 2); // One resolution plus one status attempt.
    vi.runAllTimers();
    expect(service.streamPublishErrorCount).toBe(publish.mock.calls.length);
    expect(publish).toHaveBeenCalledTimes(before + 2);
  });

  it("bounds listeners to one owner, counts throws, and detaches without retaining callbacks", async () => {
    const store = new HubInboxStore();
    const registry = new InMemoryLocalAgentRegistry();
    const fail = () => { throw new Error("observer failed"); };
    const detachInbox = store.subscribe(fail);
    const detachRegistry = registry.subscribe(fail);
    expect(() => store.subscribe(fail)).toThrow("already attached");
    expect(() => registry.subscribe(fail)).toThrow("already attached");
    store.upsertFromSource(approval("source"));
    store.enqueueTier1(approval("tier1"), async () => {});
    await store.resolve("tier1", "deny", NOW);
    registry.put(agent());
    registry.updateStatus(agent().agent_id, "paused");
    registry.remove(agent().agent_id);
    expect(store.listenerErrorCount).toBe(3); // Insert, enqueue, resolve.
    expect(registry.listenerErrorCount).toBe(3); // Insert, update, remove.
    detachInbox(); detachRegistry();
    store.upsertFromSource(approval("detached")); registry.put(agent());
    expect(store.listenerErrorCount).toBe(3);
    expect(registry.listenerErrorCount).toBe(3);
  });

  it("publishes one resolution across overlapping late completions and repeated waves", async () => {
    const store = new HubInboxStore();
    const listener = vi.fn();
    store.subscribe(listener);
    for (let wave = 0; wave < REFRESH_WAVES; wave++) {
      const item = approval(`deferred-${wave}`);
      const releases: Array<() => void> = [];
      store.enqueueTier1(item, () => new Promise<void>((resolve) => releases.push(resolve)));
      listener.mockClear();
      const first = store.resolve(item.item_id, "approve", NOW);
      const second = store.resolve(item.item_id, "approve", NOW);
      expect(listener).not.toHaveBeenCalled();
      releases[1](); await second;
      releases[0](); await first;
      expect(listener).toHaveBeenCalledTimes(1);
      expect(listener.mock.calls[0][0].resolved).toBe(true);
      vi.runAllTimers();
      expect(listener).toHaveBeenCalledTimes(1);
    }
  });

  it("installs no listeners without a publisher and does install them when supplied", () => {
    const inbox = vi.spyOn(HubInboxStore.prototype, "subscribe");
    const registry = vi.spyOn(InMemoryLocalAgentRegistry.prototype, "subscribe");
    setup();
    expect(inbox).not.toHaveBeenCalled(); expect(registry).not.toHaveBeenCalled();
    setup(recorder());
    expect(inbox).toHaveBeenCalledTimes(1); expect(registry).toHaveBeenCalledTimes(1);
  });
  it("a publisher that re-enters the service during a publish neither recurses nor adds frames", async () => {
    // Rule 12: a sink that reads the inbox from inside a publish meets the refresh-is-silent rule, so the publish
    // depth stays one and no extra frame is produced; the shipped sink (broadcastSSE) never re-enters at all.
    let service!: HubService; let registry!: InMemoryLocalAgentRegistry;
    let depth = 0; let maxDepth = 0; const inboxFrames: unknown[] = []; let statusFrames = 0;
    const reenter = () => { depth++; maxDepth = Math.max(maxDepth, depth); try { service.listInbox(); } finally { depth--; } };
    const publisher: HubStreamPublisher = {
      publishInbox: (frame) => { inboxFrames.push(frame); reenter(); },
      publishAgentStatus: () => { statusFrames++; reenter(); },
    };
    ({ service, registry } = setup(publisher));
    const items = service.listInbox();
    expect(inboxFrames).toHaveLength(items.length);
    // The first aggregation stores each new card before notifying, so a re-entrant read nests at most once per card
    // still to be stored and never republishes one: depth is bounded by the card count, not by the sink.
    expect(maxDepth).toBeLessThanOrEqual(items.length);
    expect(new Set(inboxFrames.map((f) => JSON.stringify(f))).size).toBe(items.length);
    maxDepth = 0;
    const enqueued = service.enqueueFortressLockdown();
    await service.resolveInboxItem(enqueued.inbox_item_id, "deny");
    expect(inboxFrames).toHaveLength(items.length + 2); // Enqueue plus resolution, nothing from the re-entrant reads.
    // A healthy insertion raises no source card, so the re-entrant read inside the status publish finds nothing new.
    const statusBefore = statusFrames;
    registry.put({ ...agent(), agent_id: "quiet-agent", status: "active", status_reason_class: undefined,
      budget_summary: { last_refreshed_at: NOW, daily: { unit: "tokens", cap: 100, used: 1 } } });
    expect(statusFrames).toBe(statusBefore + 1);
    expect(inboxFrames).toHaveLength(items.length + 2);
    expect(maxDepth).toBe(1);
    expect(service.streamPublishErrorCount).toBe(0);
  });
});
