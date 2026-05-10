/**
 * Sanctuary v1.3 WP-V1.3-10 Cross-Harness Approval Inbox Upsilon-2
 *
 * Regression suite for AggregatorBackedChannel — the channel wrapper that
 * routes Tier 1/2 approval resolutions through the aggregator when the
 * operator has enabled approval-redirect mode.
 *
 * Acceptance map:
 *   1. Disabled → underlying channel handles request unchanged.
 *   2. Replace mode → operator inbox approve resolves the gate.
 *   3. Replace mode → operator inbox deny resolves the gate.
 *   4. Replace mode → aggregator timeout / expired → channel returns deny.
 *   5. Replace mode → hard timeout when aggregator never resolves.
 *   6. Replace mode → already-resolved entry surfaces via list().
 *   7. Notify mode → both paths fire, first decision wins.
 *   8. Notify mode → underlying channel error falls through to aggregator.
 *   9. Resolver dynamism: flipping enabled across calls is honored.
 */

import { describe, it, expect } from "vitest";

import {
  AggregatorBackedChannel,
} from "../../src/principal-policy/channels/aggregator-backed-channel.js";
import {
  ApprovalAggregator,
  type ApprovalGateEvent,
} from "../../src/principal-policy/approval-aggregator.js";
import {
  AutoApproveChannel,
  CallbackApprovalChannel,
} from "../../src/principal-policy/approval-channel.js";
import type { ApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import type {
  ApprovalRequest,
  ApprovalResponse,
} from "../../src/principal-policy/types.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

const FORTRESS = "fortress_test_upsilon2";
const IDENTITY = "identity_test_upsilon2";
const OPERATOR = "operator_test";

function gateRequestForOperation(
  operation: string,
  tier: 1 | 2 = 1,
): { request: ApprovalRequest; gateEvent: ApprovalGateEvent } {
  const ts = new Date().toISOString();
  const correlationId = `${ts}:${operation}:abcd`;
  const context = { operation, args_summary: { foo: "bar" } };
  const request: ApprovalRequest = {
    operation,
    tier,
    reason: `${operation} requires approval`,
    context,
    timestamp: ts,
  };
  const gateEvent: ApprovalGateEvent = {
    phase: "requested",
    operation,
    tier,
    reason: request.reason,
    context,
    request_timestamp: ts,
    correlation_id: correlationId,
  };
  return { request, gateEvent };
}

async function buildAggregator(): Promise<{
  aggregator: ApprovalAggregator;
  storage: MemoryStorage;
  auditLog: AuditLog;
}> {
  const masterKey = generateRandomKey();
  const storage = new MemoryStorage(masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const aggregator = new ApprovalAggregator({
    storage,
    masterKey,
    auditLog,
    identityId: IDENTITY,
    fortressId: FORTRESS,
  });
  return { aggregator, storage, auditLog };
}

class RecordingCallbackChannel implements ApprovalChannel {
  public readonly invocations: ApprovalRequest[] = [];
  constructor(
    private readonly responder: (
      r: ApprovalRequest,
    ) => Promise<ApprovalResponse>,
  ) {}
  async requestApproval(request: ApprovalRequest): Promise<ApprovalResponse> {
    this.invocations.push(request);
    return this.responder(request);
  }
}

describe("AggregatorBackedChannel — Upsilon-2", () => {
  it("delegates verbatim to the underlying channel when redirect is disabled", async () => {
    const { aggregator } = await buildAggregator();
    let count = 0;
    const underlying = new RecordingCallbackChannel(async () => {
      count++;
      return {
        decision: "approve",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      };
    });
    const channel = new AggregatorBackedChannel({
      underlying,
      aggregator,
      resolveRedirect: () => ({ enabled: false, mode: "replace" }),
    });
    const { request } = gateRequestForOperation("state_export");
    const response = await channel.requestApproval(request);
    expect(response.decision).toBe("approve");
    expect(count).toBe(1);
    expect(underlying.invocations.length).toBe(1);
  });

  it("replace mode: operator inbox approve resolves the gate (underlying never called)", async () => {
    const { aggregator } = await buildAggregator();
    const underlying = new RecordingCallbackChannel(async () => {
      throw new Error("underlying must NOT be invoked in replace mode");
    });
    const channel = new AggregatorBackedChannel({
      underlying,
      aggregator,
      resolveRedirect: () => ({ enabled: true, mode: "replace" }),
    });
    const { request, gateEvent } = gateRequestForOperation("state_delete");
    // Aggregator must record the requested entry before the channel can
    // match against it. The gate normally calls ingest before
    // requestApproval; mirror that ordering.
    const entry = await aggregator.ingest(gateEvent);
    expect(entry).not.toBeNull();
    const responsePromise = channel.requestApproval(request);
    // Operator approves through the inbox.
    await aggregator.resolve(entry!.aggregator_id, "approved", OPERATOR);
    const response = await responsePromise;
    expect(response.decision).toBe("approve");
    expect(response.decided_by).toBe("human");
    expect(underlying.invocations.length).toBe(0);
  });

  it("replace mode: operator inbox deny resolves the gate", async () => {
    const { aggregator } = await buildAggregator();
    const underlying = new AutoApproveChannel();
    const channel = new AggregatorBackedChannel({
      underlying,
      aggregator,
      resolveRedirect: () => ({ enabled: true, mode: "replace" }),
    });
    const { request, gateEvent } = gateRequestForOperation("identity_rotate");
    const entry = await aggregator.ingest(gateEvent);
    const responsePromise = channel.requestApproval(request);
    await aggregator.resolve(entry!.aggregator_id, "denied", OPERATOR);
    const response = await responsePromise;
    expect(response.decision).toBe("deny");
    expect(response.decided_by).toBe("human");
  });

  it("replace mode: hard timeout when aggregator never resolves returns deny", async () => {
    const { aggregator } = await buildAggregator();
    const underlying = new AutoApproveChannel();
    const channel = new AggregatorBackedChannel({
      underlying,
      aggregator,
      resolveRedirect: () => ({ enabled: true, mode: "replace" }),
      replaceModeTimeoutMs: 50,
    });
    const { request, gateEvent } = gateRequestForOperation("state_export");
    await aggregator.ingest(gateEvent);
    const start = Date.now();
    const response = await channel.requestApproval(request);
    const elapsed = Date.now() - start;
    expect(response.decision).toBe("deny");
    expect(response.decided_by).toBe("timeout");
    expect(elapsed).toBeGreaterThanOrEqual(40);
    expect(elapsed).toBeLessThan(2000);
  });

  it("replace mode: already-resolved aggregator entry returns its decision via list()", async () => {
    const { aggregator } = await buildAggregator();
    const underlying = new RecordingCallbackChannel(async () => {
      throw new Error("must not be invoked");
    });
    const channel = new AggregatorBackedChannel({
      underlying,
      aggregator,
      resolveRedirect: () => ({ enabled: true, mode: "replace" }),
    });
    const { request, gateEvent } = gateRequestForOperation("state_delete");
    const entry = await aggregator.ingest(gateEvent);
    // Resolve BEFORE requestApproval is called. The channel should pick
    // up the resolved entry from list() rather than waiting for an event.
    await aggregator.resolve(entry!.aggregator_id, "approved", OPERATOR);
    const response = await channel.requestApproval(request);
    expect(response.decision).toBe("approve");
  });

  it("replace mode: aggregator denial via system_ttl maps to channel deny", async () => {
    const { aggregator } = await buildAggregator();
    const underlying = new AutoApproveChannel();
    const channel = new AggregatorBackedChannel({
      underlying,
      aggregator,
      resolveRedirect: () => ({ enabled: true, mode: "replace" }),
    });
    const { request, gateEvent } = gateRequestForOperation("state_import");
    const entry = await aggregator.ingest(gateEvent);
    // Force a timeout/expired status by emitting a resolution event with
    // channel_failure decided_by — the aggregator maps that to status
    // `timeout`, which the channel maps to deny/timeout.
    const resolvedEvent: ApprovalGateEvent = {
      phase: "resolved",
      operation: gateEvent.operation,
      tier: gateEvent.tier,
      reason: gateEvent.reason,
      context: gateEvent.context,
      request_timestamp: gateEvent.request_timestamp,
      correlation_id: gateEvent.correlation_id,
      resolution: {
        decision: "deny",
        decided_at: new Date().toISOString(),
        decided_by: "channel_failure",
      },
    };
    const responsePromise = channel.requestApproval(request);
    await aggregator.ingest(resolvedEvent);
    const response = await responsePromise;
    expect(response.decision).toBe("deny");
    expect(response.decided_by).toBe("timeout");
    // Aggregator entry status is `timeout` not `denied`.
    const after = await aggregator.list();
    const target = after.find((e) => e.aggregator_id === entry!.aggregator_id);
    expect(target?.status).toBe("timeout");
  });

  it("notify mode: underlying channel approve resolves first, aggregator entry stays pending", async () => {
    const { aggregator } = await buildAggregator();
    const underlying = new AutoApproveChannel();
    const channel = new AggregatorBackedChannel({
      underlying,
      aggregator,
      resolveRedirect: () => ({ enabled: true, mode: "notify" }),
    });
    const { request, gateEvent } = gateRequestForOperation("state_export");
    await aggregator.ingest(gateEvent);
    const response = await channel.requestApproval(request);
    expect(response.decision).toBe("approve");
    // Aggregator entry is still pending — Upsilon-2 does not write a
    // synthetic resolution from the underlying channel result. The next
    // ApprovalGate `resolved` event (gate's own audit-log path) sets the
    // entry status; in this isolated test we have no gate, so it remains
    // pending which is the expected isolated-channel behavior.
    const after = await aggregator.list();
    expect(after.find((e) => e.audit_log_entry_id === `${request.timestamp}:${request.operation}`)?.status).toBe(
      "pending",
    );
  });

  it("notify mode: aggregator decision wins over slow underlying channel", async () => {
    const { aggregator } = await buildAggregator();
    const underlying = new RecordingCallbackChannel(
      async () =>
        new Promise<ApprovalResponse>((res) =>
          setTimeout(
            () =>
              res({
                decision: "approve",
                decided_at: new Date().toISOString(),
                decided_by: "human",
              }),
            500,
          ),
        ),
    );
    const channel = new AggregatorBackedChannel({
      underlying,
      aggregator,
      resolveRedirect: () => ({ enabled: true, mode: "notify" }),
    });
    const { request, gateEvent } = gateRequestForOperation("state_delete");
    const entry = await aggregator.ingest(gateEvent);
    const responsePromise = channel.requestApproval(request);
    // Aggregator resolves quickly through the inbox.
    setTimeout(
      () => void aggregator.resolve(entry!.aggregator_id, "denied", OPERATOR),
      30,
    );
    const response = await responsePromise;
    expect(response.decision).toBe("deny");
    expect(response.decided_by).toBe("human");
  });

  it("notify mode: underlying channel synchronous throw still produces a response from the aggregator", async () => {
    const { aggregator } = await buildAggregator();
    class ThrowingChannel implements ApprovalChannel {
      async requestApproval(): Promise<ApprovalResponse> {
        throw new Error("underlying boom");
      }
    }
    const channel = new AggregatorBackedChannel({
      underlying: new ThrowingChannel(),
      aggregator,
      resolveRedirect: () => ({ enabled: true, mode: "notify" }),
    });
    const { request, gateEvent } = gateRequestForOperation("state_export");
    const entry = await aggregator.ingest(gateEvent);
    const responsePromise = channel.requestApproval(request);
    setTimeout(
      () => void aggregator.resolve(entry!.aggregator_id, "approved", OPERATOR),
      20,
    );
    const response = await responsePromise;
    expect(response.decision).toBe("approve");
  });

  it("resolver dynamism: a resolver flip between calls toggles redirect for the next request only", async () => {
    const { aggregator } = await buildAggregator();
    let enabled = false;
    let underlyingCalls = 0;
    const underlying = new RecordingCallbackChannel(async () => {
      underlyingCalls++;
      return {
        decision: "approve",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      };
    });
    const channel = new AggregatorBackedChannel({
      underlying,
      aggregator,
      resolveRedirect: () => ({ enabled, mode: "replace" }),
    });

    // First call: redirect disabled → underlying answers.
    const { request: r1 } = gateRequestForOperation("state_export");
    const resp1 = await channel.requestApproval(r1);
    expect(resp1.decision).toBe("approve");
    expect(underlyingCalls).toBe(1);

    // Operator flips toggle on (mid-life policy edit).
    enabled = true;

    // Second call: redirect enabled → must come from aggregator.
    const { request: r2, gateEvent: e2 } = gateRequestForOperation(
      "identity_rotate",
    );
    const entry = await aggregator.ingest(e2);
    const resp2Promise = channel.requestApproval(r2);
    await aggregator.resolve(entry!.aggregator_id, "denied", OPERATOR);
    const resp2 = await resp2Promise;
    expect(resp2.decision).toBe("deny");
    expect(underlyingCalls).toBe(1); // not invoked the second time
  });
});
