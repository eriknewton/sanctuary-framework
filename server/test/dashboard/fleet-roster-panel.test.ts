/**
 * Wrap dashboard fleet-roster panel - HTTP-boundary guarantees.
 *
 * The wrap ("Protect") dashboard exposes the fleet-roster panel at the read-only
 * route `GET /api/fleet/roster`. These pin the four hard guarantees of that
 * surface at the transport boundary (not just the pure presenter, which
 * test/principal-policy/fleet-roster.test.ts covers):
 *
 *   1. AUTH-FIRST. When an auth token is configured, an unauthenticated request
 *      is rejected 401 BEFORE any roster is computed or served. The shared auth
 *      gate runs ahead of the route.
 *   2. HONEST ABSENCE. With no federation read-seam wired (the common
 *      single-machine wrap install), the route serves the absent roster
 *      (`available:false`, empty nodes, all-zero summaries), never a fabricated
 *      roster and never a greyed-green "all admitted" shell.
 *   3. PRESENTER WIRING. When a federation seam IS wired, the route serves the
 *      presenter's roster verbatim (the same shape the unit tests pin).
 *   4. READ-ONLY / SEE-NOT-MANAGE. The route answers GET only; a mutating verb
 *      (POST) does NOT match it and is not served by this router (no admit /
 *      revoke / rotate seam exists here).
 */

import { describe, it, expect, afterEach } from "vitest";
import { startDashboardServer } from "../../src/dashboard/server.js";
import type { DashboardHandle } from "../../src/dashboard/server.js";
import type { AggregatorSources } from "../../src/dashboard/aggregator.js";
import {
  absentFleetRoster,
  type FleetRoster,
} from "../../src/principal-policy/fleet-roster.js";

async function startForTest(overrides: {
  authToken?: string;
  fleetRoster?: () => FleetRoster;
} = {}): Promise<DashboardHandle> {
  const sources: AggregatorSources = {
    mode: "co-located",
    server_version: "0.9.0-test",
    activity: [],
    pendingApprovals: [],
  };
  return startDashboardServer({
    mode: "co-located",
    port: 0,
    sources,
    ...(overrides.authToken ? { authToken: overrides.authToken } : {}),
    ...(overrides.fleetRoster ? { fleetRoster: overrides.fleetRoster } : {}),
  });
}

/** A present, provisioned 2-node roster the panel should surface verbatim. */
function presentRoster(): FleetRoster {
  return {
    available: true,
    enabled: true,
    fortress_id: "fortress:test",
    node_id: "home-mac",
    eviction_serial: 2,
    nodes: [
      {
        node_id: "node-1",
        label: "home-mac",
        trust_state: "admitted",
        trust_evaluable: true,
        reach: "recent",
        node_mode: "local",
        provider_in_trust_boundary: false,
        last_sync_received_at: "2026-06-24T11:59:00.000Z",
        policy: {
          version: null,
          hash: null,
          hash_algorithm: null,
          applied_at: null,
          source_event_id: null,
          drift_state: "unknown",
        },
        first_seen: "2026-06-24T11:00:00.000Z",
        last_seen: "2026-06-24T11:59:00.000Z",
      },
      {
        node_id: "node-2",
        label: "linux-box",
        trust_state: "revoked",
        trust_evaluable: true,
        reach: "stale",
        node_mode: "local",
        provider_in_trust_boundary: false,
        last_sync_received_at: "2026-06-24T10:00:00.000Z",
        policy: {
          version: null,
          hash: null,
          hash_algorithm: null,
          applied_at: null,
          source_event_id: null,
          drift_state: "unknown",
        },
        first_seen: "2026-06-24T09:00:00.000Z",
        last_seen: "2026-06-24T11:00:00.000Z",
      },
    ],
    summary: { total: 2, admitted: 1, revoked: 1, untrusted: 0 },
    sync_health: {
      reachable: 1,
      stale: 1,
      never: 0,
      oldest_last_sync: "2026-06-24T10:00:00.000Z",
      freshness_window_ms: 600000,
    },
    policy_distribution: {
      available: true,
      operator_policy: null,
      summary: { in_sync: 0, drifted: 0, unknown: 2 },
    },
  };
}

describe("wrap dashboard fleet-roster panel (GET /api/fleet/roster)", () => {
  let handle: DashboardHandle | null = null;

  afterEach(async () => {
    if (handle) {
      await handle.stop();
      handle = null;
    }
  });

  it("GUARANTEE 1 (auth-first): rejects 401 when token required and missing, before serving any roster", async () => {
    // A provider that MUST NOT be reached: if the route computed a roster before
    // the auth gate, this throw would surface as a 500, not the required 401.
    handle = await startForTest({
      authToken: "secret-xyz",
      fleetRoster: () => {
        throw new Error("fleetRoster reached before auth gate");
      },
    });
    const res = await fetch(`${handle.url}/api/fleet/roster`);
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body).toEqual({ error: "unauthorized" });
  });

  it("GUARANTEE 1 (auth-first): a query-string token is NOT accepted (header-only)", async () => {
    handle = await startForTest({
      authToken: "secret-xyz",
      fleetRoster: () => presentRoster(),
    });
    const res = await fetch(`${handle.url}/api/fleet/roster?token=secret-xyz`);
    expect(res.status).toBe(401);
  });

  it("GUARANTEE 2 (honest absence): serves the absent roster when no federation seam is wired", async () => {
    // No fleetRoster provider => no federation on this process.
    handle = await startForTest();
    const res = await fetch(`${handle.url}/api/fleet/roster`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as FleetRoster;

    // Byte-identical to the single honest-absence source of truth: never a
    // fabricated roster, never a greyed-green "all admitted" shell.
    expect(body).toEqual(absentFleetRoster());
    expect(body.available).toBe(false);
    expect(body.enabled).toBe(false);
    expect(body.nodes).toEqual([]);
    expect(body.summary).toEqual({
      total: 0,
      admitted: 0,
      revoked: 0,
      untrusted: 0,
    });
  });

  it("GUARANTEE 3 (presenter wiring): serves the provided roster verbatim when a seam is wired", async () => {
    const roster = presentRoster();
    handle = await startForTest({
      authToken: "secret-xyz",
      fleetRoster: () => roster,
    });
    const res = await fetch(`${handle.url}/api/fleet/roster`, {
      headers: { Authorization: "Bearer secret-xyz" },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as FleetRoster;
    // Verbatim: the route adds no trust logic of its own, it presents what the
    // presenter computed. A revoked node stays revoked; nothing is laundered.
    expect(body).toEqual(roster);
    expect(body.nodes.map((n) => [n.node_id, n.trust_state])).toEqual([
      ["node-1", "admitted"],
      ["node-2", "revoked"],
    ]);
  });

  it("GUARANTEE 4 (read-only / SEE-not-manage): POST to the roster route is not served (no mutation seam)", async () => {
    handle = await startForTest({
      authToken: "secret-xyz",
      fleetRoster: () => presentRoster(),
    });
    const res = await fetch(`${handle.url}/api/fleet/roster`, {
      method: "POST",
      headers: { Authorization: "Bearer secret-xyz" },
    });
    // GET-only route: a mutating verb falls through to the router's 404. There
    // is no admit/revoke/rotate action here - the panel only SEES the fleet.
    expect(res.status).toBe(404);
  });

  it("carries no key material on the wire", async () => {
    handle = await startForTest({
      authToken: "secret-xyz",
      fleetRoster: () => presentRoster(),
    });
    const res = await fetch(`${handle.url}/api/fleet/roster`, {
      headers: { Authorization: "Bearer secret-xyz" },
    });
    const text = (await res.text()).toLowerCase();
    for (const forbidden of [
      "private",
      "secret", // note: matches nothing in the roster shape
      "privatekey",
      "private_key",
      "seed",
    ]) {
      expect(text).not.toContain(forbidden);
    }
  });
});
