/**
 * Dashboard-fold PR-1 — injected dependency overrides on the main dashboard.
 *
 * `setDependencies` now accepts the three read-only resolvers the wrap
 * ("Protect") boot path builds from the at-rest fortress records (because it
 * runs no live federation daemon): a fleet-roster provider, the pinned
 * producer-key resolver (+ fail-honest flag), and the enforcement-availability
 * resolver. These tests prove:
 *
 *  1. Injected resolvers are threaded BY IDENTITY into the snapshot
 *     aggregator sources (`buildAggregatorSources`) and the posture-route
 *     deps (`dispatchPosture`'s fleetRoster override), so the wrap-reuse
 *     path (PR-4) arms the surviving server with the wrap's own basis.
 *  2. NOT injecting anything leaves the pre-fold behavior in place (the
 *     server resolves each dependency itself) — the no-injection path is
 *     the byte-identical default every current production boot uses.
 */

import { describe, it, expect, afterEach } from "vitest";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import type { AggregatorSources } from "../../src/dashboard/aggregator.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { absentFleetRoster } from "../../src/principal-policy/fleet-roster.js";
import type { FleetRoster } from "../../src/principal-policy/fleet-roster.js";

const STUB_POLICY = {
  version: 1,
  tier1_always_approve: [],
  tier3_auto_allow: [],
  anomaly_thresholds: {
    new_namespace: true,
    unfamiliar_counterparty_window_days: 7,
    frequency_spike_multiplier: 5,
  },
  approval_channel: { type: "stderr", timeout_seconds: 30 },
} as never;

const STUB_BASELINE = { load: async () => {}, save: async () => {} } as never;

function makeChannel(): DashboardApprovalChannel {
  // Never started: these tests exercise dependency threading, not HTTP.
  return new DashboardApprovalChannel({
    port: 0,
    host: "127.0.0.1",
    timeout_seconds: 30,
    auto_deny: true,
  });
}

function makeAuditLog(): AuditLog {
  return new AuditLog(new MemoryStorage(), generateRandomKey());
}

type PrivateChannel = {
  buildAggregatorSources: () => Promise<AggregatorSources>;
};

describe("dashboard-fold PR-1: setDependencies injected overrides", () => {
  const channels: DashboardApprovalChannel[] = [];
  afterEach(async () => {
    for (const c of channels.splice(0)) await c.stop();
  });

  it("threads the injected enforcement-availability + producer-key resolvers into the snapshot sources BY IDENTITY", async () => {
    const channel = makeChannel();
    channels.push(channel);

    const injectedEnforcement = (() => {
      throw new Error("identity assertion only — never invoked");
    }) as never;
    const injectedProducerKey = (): string | null => "injected-key-b64url";

    channel.setDependencies({
      policy: STUB_POLICY,
      baseline: STUB_BASELINE,
      auditLog: makeAuditLog(),
      resolvePinnedProducerKey: injectedProducerKey,
      producerKeyExpectedButUnavailable: false,
      resolveEnforcementAvailability: injectedEnforcement,
    });

    const sources = await (
      channel as unknown as PrivateChannel
    ).buildAggregatorSources();

    expect(sources.resolveEnforcementAvailability).toBe(injectedEnforcement);
    expect(sources.resolvePinnedProducerKey).toBe(injectedProducerKey);
    // Fail-honest flag: explicitly false when the injected key resolved.
    expect("producerKeyExpectedButUnavailable" in sources).toBe(false);
  });

  it("injected producer-key fail-honest flag survives threading (unreadable ⇒ amber, never green)", async () => {
    const channel = makeChannel();
    channels.push(channel);

    channel.setDependencies({
      policy: STUB_POLICY,
      baseline: STUB_BASELINE,
      auditLog: makeAuditLog(),
      resolvePinnedProducerKey: () => null,
      producerKeyExpectedButUnavailable: true,
    });

    const sources = await (
      channel as unknown as PrivateChannel
    ).buildAggregatorSources();
    expect(sources.producerKeyExpectedButUnavailable).toBe(true);
  });

  it("without injection the snapshot sources keep the server's OWN resolvers (pre-fold default)", async () => {
    const channel = makeChannel();
    channels.push(channel);

    channel.setDependencies({
      policy: STUB_POLICY,
      baseline: STUB_BASELINE,
      auditLog: makeAuditLog(),
    });

    const sources = await (
      channel as unknown as PrivateChannel
    ).buildAggregatorSources();

    // The self-resolved closures exist and are NOT some injected function.
    expect(typeof sources.resolveEnforcementAvailability).toBe("function");
    expect(typeof sources.resolvePinnedProducerKey).toBe("function");
    // No producer key on a fresh in-memory fortress: honest null (channel
    // basis), and no fail-honest flag.
    expect(sources.resolvePinnedProducerKey?.()).toBeNull();
    expect("producerKeyExpectedButUnavailable" in sources).toBe(false);
  });

  it("serves the INJECTED fleet roster on GET /api/posture/fleet (wrap-reuse read path)", async () => {
    const { bindWithRetry, randomTestPort } = await import(
      "../util/port-collision-retry.js"
    );

    const injectedRoster: FleetRoster = {
      ...absentFleetRoster(),
      available: true,
      fortress_id: "injected-fortress",
    };

    let channel: DashboardApprovalChannel | undefined;
    let port = 0;
    await bindWithRetry(async () => {
      port = randomTestPort();
      channel = new DashboardApprovalChannel({
        port,
        host: "127.0.0.1",
        timeout_seconds: 30,
        auto_deny: true,
      });
      channel.setDependencies({
        policy: STUB_POLICY,
        baseline: STUB_BASELINE,
        auditLog: makeAuditLog(),
        fleetRoster: () => injectedRoster,
      });
      await channel.start();
    });
    channels.push(channel!);

    const res = await fetch(`http://127.0.0.1:${port}/api/posture/fleet`);
    expect(res.status).toBe(200);
    const roster = (await res.json()) as FleetRoster;
    expect(roster.fortress_id).toBe("injected-fortress");
    expect(roster.available).toBe(true);
  });
});
