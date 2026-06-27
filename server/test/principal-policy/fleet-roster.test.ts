/**
 * Fleet Console Slice 1 — fleet-roster presenter unit tests.
 *
 * These pin the trust model the console renders, against the SAME contract the
 * federation control-plane enforces (AGENTS.md constraints 4/5/6):
 *
 *   - Trust is the federation layer's verdict (`isNodeRevoked`), never
 *     re-derived from a `/v1/nodes` response field.
 *   - An UNEVALUABLE node (revocation state throws) renders `untrusted`,
 *     fail-closed — never amber, never silently admitted.
 *   - A revoked node renders `revoked`.
 *   - No key material appears on the roster shape.
 *   - An unprovisioned fortress has an honest absent roster, never a fabricated
 *     green "all admitted" shell.
 *
 * The presenter is pure over `V1FederationDeps`, so these build a faithful deps
 * fixture (the same method set the real dashboard supplies) and assert the
 * presented verdict. The end-to-end drill (real join ceremony -> real roster ->
 * real revoke over HTTP) lives in test/v1/fleet-console-drill.test.ts.
 */

import { describe, expect, it } from "vitest";

import {
  buildFleetRoster,
  FLEET_REACH_FRESHNESS_WINDOW_MS,
} from "../../src/principal-policy/fleet-roster.js";
import type {
  FederationContext,
  FederationNodeView,
  V1FederationDeps,
} from "../../src/v1/federation.js";

const NOW = Date.parse("2026-06-24T12:00:00.000Z");

/** A minimal non-issuer federation context (only the fields the presenter reads). */
const CTX: FederationContext = {
  fortressId: "fortress:test",
  nodeId: "home-mac",
  nodeMode: "local",
  pinnedMasterPubkey: {
    fortress_id: "fortress:test",
    public_key: "AAAA",
  } as FederationContext["pinnedMasterPubkey"],
  issuingPrincipalCert: {} as FederationContext["issuingPrincipalCert"],
  isNodeRevoked: () => false,
} as FederationContext;

function nodeView(
  nodeId: string,
  overrides?: Partial<FederationNodeView>,
): FederationNodeView {
  return {
    node_id: nodeId,
    label: overrides?.label ?? null,
    attestation_status: overrides?.attestation_status ?? "verified",
    node_mode: overrides?.node_mode ?? "local",
    host_provider: overrides?.host_provider ?? null,
    trust_boundary: overrides?.trust_boundary ?? {
      version: "operator-cloud-trust-boundary-v1",
      posture: "local_operator_host",
      label: "local operator host",
      provider_in_trust_boundary: false,
      tee_attested: false,
      disclosure: null,
    },
    tee_attested: overrides?.tee_attested ?? false,
    disclosure_acknowledged_at: overrides?.disclosure_acknowledged_at ?? null,
    drill_status: overrides?.drill_status ?? "not_applicable",
    first_seen: overrides?.first_seen ?? "2026-06-24T11:00:00.000Z",
    last_seen: overrides?.last_seen ?? "2026-06-24T11:59:00.000Z",
    last_sync: overrides?.last_sync ?? {
      received_at: "2026-06-24T11:59:00.000Z",
      sent_at: "2026-06-24T11:59:00.000Z",
      last_sequence: 3,
    },
  };
}

/**
 * Build a faithful `V1FederationDeps` fixture exposing only the read methods the
 * presenter touches; the mutation/sync methods throw if the presenter ever calls
 * them (it must not).
 */
function deps(opts: {
  context?: FederationContext | null;
  enabled?: boolean;
  nodes: FederationNodeView[];
  isNodeRevoked: (nodeId: string) => boolean;
}): V1FederationDeps {
  const mustNotCall = (name: string) => () => {
    throw new Error(`presenter must not call ${name}`);
  };
  return {
    getContext: () => (opts.context === undefined ? CTX : opts.context),
    isEnabled: () => opts.enabled ?? true,
    listNodes: () => opts.nodes,
    isNodeRevoked: opts.isNodeRevoked,
    // Everything below is a write/sync/key-bearing path the presenter must never
    // touch. Wire them to throw so a regression that reaches for them fails loud.
    setEnabled: mustNotCall("setEnabled") as never,
    resolveOperatorPublicKey: mustNotCall("resolveOperatorPublicKey") as never,
    audit: mustNotCall("audit") as never,
    rosterNodeIds: mustNotCall("rosterNodeIds") as never,
    recordJoin: mustNotCall("recordJoin") as never,
    listFederationEvents: mustNotCall("listFederationEvents") as never,
    appendFederationEvents: mustNotCall("appendFederationEvents") as never,
    acceptedHighWaterFor: mustNotCall("acceptedHighWaterFor") as never,
    recordAcceptedHighWater: mustNotCall("recordAcceptedHighWater") as never,
    nextOutboundHighWater: mustNotCall("nextOutboundHighWater") as never,
    renewLocalNodeCertificate: mustNotCall("renewLocalNodeCertificate") as never,
    federationPosture: mustNotCall("federationPosture") as never,
  };
}

describe("buildFleetRoster — trust verdict is the federation layer's, fail-closed", () => {
  it("presents a 2-node fleet as all admitted when none are revoked", () => {
    const roster = buildFleetRoster(
      deps({
        nodes: [nodeView("node-1"), nodeView("node-2", { label: "linux-box" })],
        isNodeRevoked: () => false,
      }),
      { now: () => NOW, evictionSerial: 0 },
    );

    expect(roster.available).toBe(true);
    expect(roster.enabled).toBe(true);
    expect(roster.fortress_id).toBe("fortress:test");
    expect(roster.node_id).toBe("home-mac");
    expect(roster.nodes.map((n) => [n.node_id, n.trust_state])).toEqual([
      ["node-1", "admitted"],
      ["node-2", "admitted"],
    ]);
    expect(roster.nodes.every((n) => n.trust_evaluable)).toBe(true);
    expect(roster.summary).toEqual({
      total: 2,
      admitted: 2,
      revoked: 0,
      untrusted: 0,
    });
  });

  it("flips a node to revoked when the federation projection reports it revoked", () => {
    const roster = buildFleetRoster(
      deps({
        nodes: [nodeView("node-1"), nodeView("node-2")],
        // The federation layer's verdict: node-2 is in the grow-only revoked set.
        isNodeRevoked: (id) => id === "node-2",
      }),
      { now: () => NOW },
    );

    const byId = Object.fromEntries(roster.nodes.map((n) => [n.node_id, n]));
    expect(byId["node-1"]!.trust_state).toBe("admitted");
    expect(byId["node-2"]!.trust_state).toBe("revoked");
    expect(byId["node-2"]!.trust_evaluable).toBe(true);
    expect(roster.summary).toEqual({
      total: 2,
      admitted: 1,
      revoked: 1,
      untrusted: 0,
    });
  });

  it("renders an UNEVALUABLE node as untrusted (fail-closed), never amber/admitted", () => {
    const roster = buildFleetRoster(
      deps({
        nodes: [nodeView("node-1"), nodeView("node-2")],
        // Revocation state cannot be evaluated for node-2 (the throw/false
        // distinction is security-significant on V1FederationDeps): fail closed.
        isNodeRevoked: (id) => {
          if (id === "node-2") throw new Error("revocation projection unavailable");
          return false;
        },
      }),
      { now: () => NOW },
    );

    const byId = Object.fromEntries(roster.nodes.map((n) => [n.node_id, n]));
    expect(byId["node-1"]!.trust_state).toBe("admitted");
    // The unevaluable node is UNTRUSTED, and trust_evaluable is false so the UI
    // can distinguish "proven revoked" from "could not prove".
    expect(byId["node-2"]!.trust_state).toBe("untrusted");
    expect(byId["node-2"]!.trust_evaluable).toBe(false);
    // It is NOT counted as admitted (no silent trust on an unprovable node).
    expect(roster.summary.admitted).toBe(1);
    expect(roster.summary.untrusted).toBe(1);
  });

  it("never re-derives trust from the response shape (attestation_status is ignored)", () => {
    // A node reporting attestation_status:'verified' must still render untrusted
    // if the federation projection cannot evaluate it. Trust is the verdict, not
    // the shape.
    const roster = buildFleetRoster(
      deps({
        nodes: [nodeView("liar", { attestation_status: "verified" })],
        isNodeRevoked: () => {
          throw new Error("unavailable");
        },
      }),
      { now: () => NOW },
    );
    expect(roster.nodes[0]!.trust_state).toBe("untrusted");
  });

  it("returns an honest ABSENT roster when federation is not provisioned", () => {
    const roster = buildFleetRoster(
      deps({
        context: null,
        nodes: [],
        isNodeRevoked: () => false,
      }),
      { now: () => NOW },
    );
    expect(roster.available).toBe(false);
    expect(roster.enabled).toBe(false);
    expect(roster.fortress_id).toBeNull();
    expect(roster.node_id).toBeNull();
    expect(roster.nodes).toEqual([]);
    expect(roster.summary).toEqual({
      total: 0,
      admitted: 0,
      revoked: 0,
      untrusted: 0,
    });
  });

  it("surfaces the fleet-wide eviction serial as supplied (context, not per-node)", () => {
    const roster = buildFleetRoster(
      deps({ nodes: [nodeView("node-1")], isNodeRevoked: () => false }),
      { now: () => NOW, evictionSerial: 7 },
    );
    expect(roster.eviction_serial).toBe(7);
  });

  it("degrades a missing/malformed eviction serial to an honest 0", () => {
    const roster = buildFleetRoster(
      deps({ nodes: [nodeView("node-1")], isNodeRevoked: () => false }),
      { now: () => NOW, evictionSerial: -5 },
    );
    expect(roster.eviction_serial).toBe(0);
  });
});

describe("buildFleetRoster — reach is liveness telemetry, separate from trust", () => {
  it("classifies a recent sync as reachable, never a trust signal", () => {
    const recent = new Date(NOW - 60_000).toISOString();
    const roster = buildFleetRoster(
      deps({
        nodes: [nodeView("node-1", { last_sync: { received_at: recent, sent_at: recent, last_sequence: 1 } })],
        isNodeRevoked: () => false,
      }),
      { now: () => NOW },
    );
    expect(roster.nodes[0]!.reach).toBe("recent");
  });

  it("classifies an old sync as stale", () => {
    const old = new Date(NOW - FLEET_REACH_FRESHNESS_WINDOW_MS - 60_000).toISOString();
    const roster = buildFleetRoster(
      deps({
        nodes: [nodeView("node-1", { last_sync: { received_at: old, sent_at: old, last_sequence: 1 } })],
        isNodeRevoked: () => false,
      }),
      { now: () => NOW },
    );
    expect(roster.nodes[0]!.reach).toBe("stale");
  });

  it("classifies a never-synced node as never (and a revoked node can still have recent reach)", () => {
    const recent = new Date(NOW - 60_000).toISOString();
    const roster = buildFleetRoster(
      deps({
        nodes: [
          nodeView("never", { last_sync: { received_at: null, sent_at: null, last_sequence: 0 } }),
          nodeView("revoked-but-recent", {
            last_sync: { received_at: recent, sent_at: recent, last_sequence: 9 },
          }),
        ],
        isNodeRevoked: (id) => id === "revoked-but-recent",
      }),
      { now: () => NOW },
    );
    const byId = Object.fromEntries(roster.nodes.map((n) => [n.node_id, n]));
    expect(byId["never"]!.reach).toBe("never");
    // Reach must NOT launder a revoked node into looking trusted: it is recent
    // AND revoked at the same time.
    expect(byId["revoked-but-recent"]!.reach).toBe("recent");
    expect(byId["revoked-but-recent"]!.trust_state).toBe("revoked");
  });
});

describe("buildFleetRoster — no key material on the roster shape", () => {
  it("emits only public identifiers and posture metadata", () => {
    const roster = buildFleetRoster(
      deps({ nodes: [nodeView("node-1")], isNodeRevoked: () => false }),
      { now: () => NOW },
    );
    const serialized = JSON.stringify(roster).toLowerCase();
    for (const forbidden of ["private", "secret", "privatekey", "private_key", "seed"]) {
      expect(serialized).not.toContain(forbidden);
    }
    // The roster node carries exactly the presentation fields, no extras.
    expect(Object.keys(roster.nodes[0]!).sort()).toEqual(
      [
        "first_seen",
        "label",
        "last_seen",
        "last_sync_received_at",
        "node_id",
        "node_mode",
        "provider_in_trust_boundary",
        "reach",
        "trust_evaluable",
        "trust_state",
      ].sort(),
    );
  });
});
