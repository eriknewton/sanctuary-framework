/** Local producer observations reach the operator inbox with stable resolutions. IC-12. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as Hub from "../../src/hub/index.js";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import type { AuditLog } from "../../src/operational/audit-log.js";

const NOW = Date.parse("2026-10-26T12:00:00.000Z");
const IDENTITY = "operator-inbox";
const FORTRESS = "fortress-inbox";
const now = () => new Date();
// A timestamp thirty operator days old proves that presence does not expire.
const STALE_AGE_MS = 30 * 24 * 60 * 60 * 1000;
const iso = (offset = 0) => new Date(NOW + offset).toISOString();
const auditLog = { append: vi.fn(async () => undefined) } as unknown as AuditLog;

function agent(overrides: Partial<LocalAgentRecord> = {}): LocalAgentRecord {
  return {
    version: "1.1", agent_id: "agent-a", identity_id: IDENTITY,
    harness: "other", model_provider: { vendor: "local", model_id: "test", runs_locally: true },
    policy_id: "test", status: "active",
    budget_summary: { last_refreshed_at: iso() },
    last_activity_at: iso(), wrapped_at: iso(),
    capabilities: { can_pause: false, can_resume: false, can_restart: false,
      can_unwrap: false, can_lockdown: false, can_chat: false, can_change_template: false },
    ...overrides,
  };
}

describe("local inbox sources", () => {
  let registry: Hub.InMemoryLocalAgentRegistry;
  let sources: Hub.HubInboxSources;
  let service: Hub.HubService;

  afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    registry = new Hub.InMemoryLocalAgentRegistry();
    // Import the existing barrel so base-source runs reach the missing factory,
    // rather than failing test collection on a newly introduced module path.
    sources = Hub.createHubInboxSources({ identityId: IDENTITY, agentRegistry: registry });
    const unsupported = async (): Promise<never> => { throw new Error("unused controller"); };
    service = new Hub.HubService({ identityId: IDENTITY, fortressId: FORTRESS,
      agentRegistry: registry, inboxSources: sources, now,
      activitySources: { auditLog, identityId: IDENTITY },
      policyBudgetSources: { listPolicySummaries: () => [], listBudgetSummaries: () => [] },
      agentController: { supports: () => false, pause: unsupported, resume: unsupported, restart: unsupported,
        unwrap: unsupported, lockdown: unsupported, bindPolicy: unsupported,
        bindChannelTemplate: unsupported },
    });
  });

  it.each(["budget_warning", "agent_error"] as const)(
    "%s reaches the service and keeps its resolution on reaggregation", async (kind) => {
      registry.put(agent({ status: "error", status_reason_class: "harness_error",
        budget_summary: { last_refreshed_at: iso(), daily: { unit: "tokens", cap: 1, used: 1 } } }));
      const item = service.listInbox().find((entry) => entry.kind === kind)!;
      expect(item).toMatchObject({ version: "1.1", kind, identity_id: IDENTITY,
        created_at: iso(), resolved: false });
      if (kind === "budget_warning") {
        expect(item).toMatchObject({ agent_id: "agent-a", bucket: "daily", severity: "hard_cap", used_fraction: 1 });
      } else {
        expect(item).toMatchObject({ agent_id: "agent-a", error_class: "harness_error", agent_still_active: false,
          display_template_id: "agent_error.harness_error" });
      }
      await service.resolveInboxItem(item.item_id, "dismiss");
      expect(service.listInbox().filter((entry) => entry.item_id === item.item_id)).toEqual([
        { ...item, resolved: true, resolved_at: iso() },
      ]);
    });

  it("keeps blocked egress, privacy, recovery and approval callbacks empty", () => {
    expect(sources.listRecentBlockedEgress()).toEqual([]);
    expect(sources.listRecentPrivacyEvents()).toEqual([]);
    expect(sources.listActiveRecoveryPrompts()).toEqual([]);
    expect(sources.listPendingApprovals()).toEqual([]);
  });

  it.each(["budget_warning", "agent_error"] as const)(
    "%s is capped and newest first", (kind) => {
      const cap = { budget_warning: Hub.HUB_BUDGET_WARNING_SOURCE_CAP, agent_error: Hub.HUB_AGENT_ERROR_SOURCE_CAP }[kind];
      // One more than the page forces truncation; increasing time opposes insertion order.
      for (let i = 0; i <= cap; i++) {
        const timestamp = iso(i - cap);
        registry.put(agent({ agent_id: `agent-${i}`, status: "error", last_activity_at: timestamp,
          budget_summary: { last_refreshed_at: timestamp, daily: { unit: "tokens", cap: 1, used: 1 } } }));
      }
      const items = kind === "budget_warning"
        ? sources.listActiveBudgetWarnings() : sources.listRecentAgentErrors();
      expect(items).toHaveLength(cap);
      expect(items.map((item) => item.created_at)).toEqual(
        Array.from({ length: cap }, (_, i) => iso(-i)));
    });

  it("keeps stale hard caps and agent errors open across repeated service reads", () => {
    registry.put(agent({ status: "error", last_activity_at: iso(-STALE_AGE_MS),
      budget_summary: { last_refreshed_at: iso(-STALE_AGE_MS), daily: { unit: "tokens", cap: 1, used: 1 } } }));
    const items = service.listInbox();
    expect(items.map((item) => item.kind)).toEqual(["budget_warning", "agent_error"]);
    expect(items.every((item) => !item.resolved && item.created_at === iso(-STALE_AGE_MS))).toBe(true);
    vi.setSystemTime(NOW + STALE_AGE_MS);
    expect(service.listInbox()).toEqual(items);
    expect(service.listInbox({ openOnly: true })).toEqual(items);
  });

  it("preserves ids across source reconstruction", () => {
    registry.put(agent({ status: "error", last_activity_at: iso(-STALE_AGE_MS) }));
    const item = service.listInbox()[0]!;
    expect(item).toBeDefined();
    const rebuilt = Hub.createHubInboxSources({ identityId: IDENTITY, agentRegistry: registry });
    expect(rebuilt.listRecentAgentErrors()[0]!.item_id).toBe(item.item_id);
  });

  it("uses timestamps only for ordering, with unparseable timestamps last", () => {
    const timestamps = [undefined, "2026-10-26T12:00:00", "invalid", "1960-01-01T00:00:00Z",
      "2026-10-26T14:00:00+02:00", iso(1)];
    for (const [index, timestamp] of timestamps.entries()) {
      registry.put(agent({ agent_id: `time-${index}`, status: "error", last_activity_at: timestamp as string,
        budget_summary: { last_refreshed_at: timestamp as string, daily: { unit: "tokens", cap: 1, used: 1 } } }));
    }
    const items = service.listInbox();
    for (const kind of ["budget_warning", "agent_error"] as const) {
      const ordered = items.filter((item) => item.kind === kind);
      expect(ordered).toHaveLength(timestamps.length);
      // The three valid instants precede all missing, offset-less and malformed stamps, even before 1970.
      expect(ordered.slice(0, 3).map((item) => item.created_at)).toEqual(timestamps.slice(3).reverse());
      expect(new Set(ordered.slice(3).map((item) => item.created_at))).toEqual(new Set(timestamps.slice(0, 3)));
    }
    registry.put(agent({ agent_id: "", status: "error" }));
    expect(service.listInbox()).toEqual(items);
  });

  it("excludes foreign identity records", () => {
    registry.put(agent({ agent_id: "foreign", identity_id: "other", status: "error",
      budget_summary: { last_refreshed_at: iso(), daily: { unit: "tokens", cap: 1, used: 1 } } }));
    expect(service.listInbox()).toEqual([]);
  });

  it.each([
    { cap: 1, used: 1, expected: "hard_cap", fraction: 1 },
    { cap: 1, used: 2, expected: "hard_cap", fraction: 1 },
    { cap: 1, used: 0.5, soft_warn: 0.5, expected: "soft_warn", fraction: 0.5 },
    { cap: 1, used: 0.25, soft_warn: 0.5, expected: null },
    { cap: 0, used: 1, expected: null },
    { cap: -1, used: 1, expected: null },
    { cap: NaN, used: 1, expected: null },
    { cap: 1, used: NaN, expected: null },
    { cap: Infinity, used: 1, expected: null },
    { cap: 1, used: Infinity, expected: null },
    { cap: 1, used: 1, soft_warn: NaN, expected: "hard_cap", fraction: 1 },
    { cap: 1, used: 0.5, soft_warn: NaN, expected: null },
    { cap: 1, used: 1, soft_warn: Infinity, expected: "hard_cap", fraction: 1 },
    { cap: 1, used: 0.5, soft_warn: Infinity, expected: null },
    { cap: 1, used: 0, soft_warn: 0, expected: null },
    { cap: 1, used: 0.5, soft_warn: 0, expected: null },
    { cap: 1, used: 1, soft_warn: 0, expected: "hard_cap", fraction: 1 },
    { cap: 1, used: 0, soft_warn: -1, expected: null },
    { cap: 1, used: 0.5, soft_warn: -1, expected: null },
    { cap: 1, used: 1, soft_warn: -1, expected: "hard_cap", fraction: 1 },
    { cap: 1, used: 0.5, soft_warn: 1, expected: null },
    { cap: 1, used: 1, soft_warn: 1, expected: "hard_cap", fraction: 1 },
    { cap: 1, used: 2, soft_warn: 1, expected: "hard_cap", fraction: 1 },
    { cap: 1, used: 0.5, soft_warn: 2, expected: null },
    { cap: 1, used: 1, soft_warn: 2, expected: "hard_cap", fraction: 1 },
    { cap: 1, used: -1, expected: null },
    { cap: 1, used: -1, soft_warn: 0, expected: null },
    { cap: 1, used: -1, soft_warn: -1, expected: null },
  ])("handles budget arithmetic $cap/$used/$soft_warn", ({ expected, fraction, ...budget }) => {
    registry.put(agent({ budget_summary: { last_refreshed_at: iso(), daily: { unit: "tokens", ...budget } } }));
    const items = service.listInbox();
    if (expected) expect(items).toEqual([expect.objectContaining({ kind: "budget_warning",
      severity: expected, used_fraction: fraction })]);
    else expect(items).toEqual([]);
  });

  it("resolves cleared budget conditions while preserving separate bucket ids", () => {
    registry.put(agent({ budget_summary: { last_refreshed_at: iso(),
      daily: { unit: "tokens", cap: 1, used: 1 },
      monthly: { unit: "tokens", cap: 1, used: 1 } } }));
    const initial = service.listInbox({ openOnly: true });
    expect(initial).toHaveLength(2); // One card per budget bucket.
    expect(new Set(initial.map((item) => item.item_id)).size).toBe(initial.length);
    registry.put(agent());
    expect(service.listInbox({ openOnly: true })).toEqual([]);
    expect(service.listInbox()).toEqual(initial.map((item) => ({ ...item,
      resolved: true, resolved_at: iso() })));
    expect(service.listInbox().every((item) => !("cleared" in item))).toBe(true);
  });

  it("leaves only the hard cap open when a soft warning escalates", () => {
    registry.put(agent({ budget_summary: { last_refreshed_at: iso(),
      daily: { unit: "tokens", cap: 1, used: 0.5, soft_warn: 0.5 } } }));
    expect(service.listInbox({ openOnly: true })).toEqual([
      expect.objectContaining({ severity: "soft_warn", resolved: false }),
    ]);
    registry.put(agent({ budget_summary: { last_refreshed_at: iso(),
      daily: { unit: "tokens", cap: 1, used: 1, soft_warn: 0.5 } } }));
    expect(service.listInbox({ openOnly: true })).toEqual([
      expect.objectContaining({ severity: "hard_cap", resolved: false }),
    ]);
    expect(service.listInbox()).toEqual(expect.arrayContaining([
      expect.objectContaining({ severity: "soft_warn", resolved: true, resolved_at: iso() }),
    ]));
  });

  it("keeps a live hard cap dismissed but opens its next incident with the same id", async () => {
    const record = agent({ budget_summary: { last_refreshed_at: iso(),
      daily: { unit: "tokens", cap: 1, used: 1 } } });
    registry.put(record);
    const item = service.listInbox({ openOnly: true })[0]!;
    await service.resolveInboxItem(item.item_id, "dismiss");
    expect(service.listInbox({ openOnly: true })).toEqual([]);
    registry.put(agent());
    expect(service.listInbox({ openOnly: true })).toEqual([]);
    registry.put(record);
    expect(service.listInbox({ openOnly: true })).toEqual([item]);
    expect(service.listInbox()[0]).not.toHaveProperty("resolved_at");
  });

  it("uses the error fallback and clears the open card after registry recovery", () => {
    registry.put(agent({ status: "error" }));
    expect(service.listInbox({ openOnly: true })).toEqual([expect.objectContaining({ error_class: "other",
      agent_still_active: false, display_template_id: "agent_error.other" })]);
    registry.put(agent());
    expect(service.listInbox({ openOnly: true })).toEqual([]);
    expect(service.listInbox()).toEqual([expect.objectContaining({ resolved: true, resolved_at: iso() })]);
  });

  it("maps unknown persisted reason classes to the closed other class and template", () => {
    registry.put(agent({ status: "error", status_reason_class: "lockdown_failed" as never }));
    expect(service.listInbox()).toEqual([expect.objectContaining({ error_class: "other",
      display_template_id: "agent_error.other" })]);
  });

  it.each(["budget_hard_cap", "passphrase_required"] as const)(
    "leaves %s to its owning source", (status_reason_class) => {
      registry.put(agent({ status: "error", status_reason_class }));
      expect(sources.listRecentAgentErrors()).toEqual([]);
      expect(service.listInbox()).toEqual([]);
    });

  it("does not project operator lockdown as an agent error", () => {
    registry.put(agent({ status: "locked_down", status_reason_class: "operator_lockdown" }));
    expect(service.listInbox()).toEqual([]);
  });

  it("prunes old cleared cards through listInbox once per read and retains younger history", () => {
    const prune = vi.spyOn(Hub.HubInboxStore.prototype, "pruneResolvedOlderThan");
    const retentionMs = Hub.HUB_INBOX_RESOLVED_RETENTION_MS;
    registry.put(agent({ agent_id: "old", status: "error" }));
    const old = service.listInbox()[0]!;
    registry.put(agent({ agent_id: "old" }));
    expect(service.listInbox()).toEqual([{ ...old, resolved: true, resolved_at: iso() }]);
    // Half an operator day separates the two clearances.
    vi.setSystemTime(NOW + retentionMs / 2);
    registry.put(agent({ agent_id: "young", status: "error" }));
    const young = service.listInbox().find((item) => item.agent_id === "young")!;
    registry.put(agent({ agent_id: "young" }));
    service.listInbox();
    vi.setSystemTime(NOW + retentionMs);
    expect(service.listInbox()).toHaveLength(2); // Exactly at the retention boundary is retained.
    prune.mockClear();
    vi.setSystemTime(NOW + retentionMs + 1);
    expect(service.listInbox()).toEqual([{ ...young, resolved: true, resolved_at: iso(retentionMs / 2) }]);
    expect(prune).toHaveBeenCalledExactlyOnceWith(NOW + retentionMs + 1, retentionMs);
    expect(service.listInbox()).toEqual([{ ...young, resolved: true, resolved_at: iso(retentionMs / 2) }]);
  });

  it.each(["budget_warning", "agent_error"] as const)(
    "%s stays dismissed while present beyond the retention age", async (kind) => {
      registry.put(agent({ status: "error",
        budget_summary: { last_refreshed_at: iso(), daily: { unit: "tokens", cap: 1, used: 1 } } }));
      const item = service.listInbox().find((entry) => entry.kind === kind)!;
      await service.resolveInboxItem(item.item_id, "dismiss");
      vi.setSystemTime(NOW + STALE_AGE_MS);
      const dismissed = { ...item, resolved: true, resolved_at: iso() };
      expect(service.listInbox().find((entry) => entry.item_id === item.item_id)).toEqual(dismissed);
      expect(service.listInbox().find((entry) => entry.item_id === item.item_id)).toEqual(dismissed);
      expect(service.listInbox({ openOnly: true }).some((entry) => entry.item_id === item.item_id)).toBe(false);
    });

  it.each(["budget_warning", "agent_error"] as const)(
    "%s keeps both open and dismissed incidents present while omitted by the cap", async (kind) => {
      const cap = kind === "budget_warning" ? Hub.HUB_BUDGET_WARNING_SOURCE_CAP : Hub.HUB_AGENT_ERROR_SOURCE_CAP;
      const put = (index: number, timestamp = iso(index)) => registry.put(agent({
        agent_id: `cap-${index}`, status: "error", last_activity_at: timestamp,
        budget_summary: { last_refreshed_at: timestamp, daily: { unit: "tokens", cap: 1, used: 1 } },
      }));
      for (let i = 0; i < cap; i++) put(i);
      const initial = service.listInbox().filter((item) => item.kind === kind);
      const open = initial.find((item) => item.agent_id === "cap-0")!;
      const dismissed = initial.find((item) => item.agent_id === "cap-1")!;
      await service.resolveInboxItem(dismissed.item_id, "dismiss");
      put(cap); // One over the emission cap pushes the oldest still-live condition out.
      for (const items of [service.listInbox(), service.listInbox()]) {
        expect(items.find((item) => item.item_id === open.item_id)).toEqual(open);
        expect(items.find((item) => item.item_id === dismissed.item_id)).toMatchObject({ resolved: true, resolved_at: iso() });
      }
      expect(sources.listPresentSourceIds!(kind).size).toBe(cap + 1);
      put(0, iso(cap + 1)); // Returning the open card to emission now excludes the dismissed card.
      service.listInbox();
      service.listInbox();
      vi.setSystemTime(NOW + STALE_AGE_MS);
      expect(service.listInbox().find((item) => item.item_id === dismissed.item_id)).toMatchObject({ resolved: true, resolved_at: iso() });
      put(1, iso(cap + 2)); // The continuously present dismissal survives return to emission too.
      const returned = service.listInbox();
      expect(returned.find((item) => item.item_id === open.item_id)).toMatchObject({ resolved: false });
      expect(returned.find((item) => item.item_id === dismissed.item_id)).toMatchObject({ resolved: true, resolved_at: iso() });
      expect(service.listInbox()).toEqual(returned);
    });

  it("never reconciles the permanent empty stub kinds", () => {
    const reconcile = vi.spyOn(Hub.HubInboxStore.prototype, "reconcileSourceItems");
    service.listInbox();
    expect(reconcile.mock.calls.map(([prefix]) => prefix)).toEqual([
      "source.budget_warning.", "source.agent_error.",
    ]);
    for (const kind of ["blocked_egress", "privacy_event", "recovery_prompt", "approval_pending"] as const) {
      expect(sources.listPresentSourceIds!(kind)).toEqual(new Set());
    }
  });

  it.each([false, true])("reconciles emission loss with present-set support %s", (hasPresentSet) => {
    registry.put(agent({ status: "error" }));
    const [item] = sources.listRecentAgentErrors();
    expect(item).toBeDefined();
    sources.listRecentAgentErrors = () => [item!];
    if (!hasPresentSet) delete sources.listPresentSourceIds;
    expect(service.listInbox()).toEqual([item]);
    sources.listRecentAgentErrors = () => [];
    expect(service.listInbox()).toEqual(hasPresentSet ? [item] : [{ ...item, resolved: true, resolved_at: iso() }]);
  });

  it("requests bounded memory reads and bounds processing if a source ignores its limit", () => {
    const list = vi.spyOn(registry, "list");
    service.listInbox();
    expect(list).toHaveBeenCalledWith({ identity_id: IDENTITY, limit: Hub.HUB_INBOX_REGISTRY_SCAN_CAP });
    const excess = Array.from({ length: Hub.HUB_INBOX_REGISTRY_SCAN_CAP }, (_, i) => agent({ agent_id: `agent-${i}` }));
    // An untouched sentinel after the scan cap proves work stops at the bound.
    excess.push({ get identity_id(): never { throw new Error("beyond scan cap"); } } as unknown as LocalAgentRecord);
    list.mockReturnValue(excess);
    list.mockClear();
    expect(sources.listActiveBudgetWarnings()).toEqual([]);
    expect(list).toHaveBeenCalledTimes(1);
    list.mockClear();
    expect(sources.listPresentSourceIds!("budget_warning")).toEqual(new Set());
    expect(list).toHaveBeenCalledTimes(1);
    list.mockClear();
    expect(sources.listRecentAgentErrors()).toEqual([]);
    expect(list).toHaveBeenCalledTimes(1);
    list.mockClear();
    expect(sources.listPresentSourceIds!("agent_error")).toEqual(new Set());
    expect(list).toHaveBeenCalledTimes(1);
  });
});
