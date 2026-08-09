/**
 * Fleet Console Slice 1 - end-to-end in-process drill (LOOPBACK ONLY).
 *
 * The DONE-WHEN for Slice 1, run through the REAL DashboardApprovalChannel and
 * the REAL federation join + revocation paths (no signed host, no Erik-present
 * drill):
 *
 *   1. A synthetic/loopback 2-node federation shows a correct live roster on the
 *      board (`GET /api/posture/fleet` over the dashboard's authenticated
 *      surface): both admitted machines render `admitted`.
 *   2. Revoking node 2 (a REAL operator-signed `node_eviction` event flowed
 *      through `/v1/federation/sync` -> the fail-closed revocation chokepoint ->
 *      the dashboard's grow-only revoked projection) flips node 2 to `revoked`
 *      on the roster, while node 1 stays admitted.
 *   3. An UNEVALUABLE node (the dashboard's revocation projection throws)
 *      renders `untrusted` (fail-closed), NOT amber and NOT silently admitted.
 *
 * The roster is read through the SAME `V1FederationDeps` + `isNodeRevoked`
 * projection the `/v1` endpoints use: the console presents the federation
 * layer's verdict, it never re-derives trust from a response shape.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  federationEventHash,
  type FederationEvent,
} from "../../src/v1/federation.js";
import {
  addOperatorAuthorizationFields,
  signOperatorPayload,
} from "../../src/v1/operator-signed.js";
import { toBase64url } from "../../src/core/encoding.js";
import {
  FEDERATION_NODE_EVICTION_EVENT_KIND,
  FEDERATION_SYNC_WIRE_VERSION,
  federationOperatorAuthorityOrigin,
  signFederationNodeEvictionPayload,
} from "../../src/v1/federation-revocation.js";
import type { FleetRoster } from "../../src/principal-policy/fleet-roster.js";
import { OPERATOR, openDurableSession, startRig, type TestRig } from "./rig.js";
import {
  makeFederationMaterials,
  assembleJoinRequest,
  type FedMaterials,
} from "./fed-materials.js";
import type { BootstrapToken } from "../../src/mesh/types.js";

let rig: TestRig;
let materials: FedMaterials;

beforeEach(async () => {
  rig = await startRig({ withOperatorIdentity: true });
  materials = makeFederationMaterials();
  rig.dashboard.setFederationContext(materials.context);
});

afterEach(async () => {
  await rig.stop();
});

function operatorSigned(action: string, payload: Record<string, unknown>) {
  const signedPayload = addOperatorAuthorizationFields(payload);
  return {
    ...signedPayload,
    operator_signature: toBase64url(
      signOperatorPayload(action, signedPayload, OPERATOR.privateKey),
    ),
  };
}

async function enableFederation(token: string) {
  const res = await fetch(`${rig.baseUrl}/v1/federation/enable`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(
      operatorSigned("/v1/federation/enable", { idempotency_key: "enable" }),
    ),
  });
  expect(res.status).toBe(200);
}

/** Admit one node through the REAL operator-authorized join ceremony. */
async function admitNode(token: string, nodeId: string): Promise<void> {
  const initRes = await fetch(`${rig.baseUrl}/v1/federation/authorize/init`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(
      operatorSigned("/v1/federation/authorize/init", {
        intended_node_id: nodeId,
        intended_node_mode: "local",
      }),
    ),
  });
  expect(initRes.status, `authorize/init ${nodeId}`).toBe(200);
  const { bootstrap_token } = (await initRes.json()) as {
    bootstrap_token: BootstrapToken;
  };
  const assembled = assembleJoinRequest({
    bootstrapToken: bootstrap_token,
    fortressMasterSecret: materials.masterSecret,
  });
  const completeRes = await fetch(
    `${rig.baseUrl}/v1/federation/authorize/complete`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(assembled.joinRequest),
    },
  );
  expect(completeRes.status, `authorize/complete ${nodeId}`).toBe(200);
}

/** Read the fleet roster the board renders, through the authenticated surface. */
async function fetchFleet(): Promise<FleetRoster> {
  const res = await fetch(`${rig.baseUrl}/api/posture/fleet`, {
    headers: { Authorization: `Bearer ${rig.authToken}` },
  });
  expect(res.status).toBe(200);
  return (await res.json()) as FleetRoster;
}

/**
 * Build a REAL operator-signed eviction event and flow it through the
 * `/v1/federation/sync` path, the same way an evicting peer/operator would. This
 * exercises the fail-closed revocation chokepoint and lands the node id in the
 * dashboard's grow-only revoked projection, which the roster then reads.
 */
async function revokeNode(token: string, nodeId: string): Promise<void> {
  const origin = federationOperatorAuthorityOrigin(materials.fortressId);
  const payload = signFederationNodeEvictionPayload({
    fortressId: materials.fortressId,
    nodeId,
    reason: "operator drill eviction",
    effectiveAt: "2026-06-24T12:30:00.000Z",
    evictionSerial: 1,
    operatorPrincipalId: materials.context.issuingPrincipalCert.principal_id,
    operatorPrincipalPrivateKey: materials.context.getIssuingPrincipalPrivateKey(),
  });
  const withoutHash = {
    event_id: `${origin}:1`,
    origin_node_id: origin,
    sequence: 1,
    occurred_at: "2026-06-24T12:30:00.000Z",
    kind: FEDERATION_NODE_EVICTION_EVENT_KIND,
    payload: payload as unknown as Record<string, unknown>,
    previous_hash: null,
  };
  const event: FederationEvent = {
    ...withoutHash,
    event_hash: federationEventHash(withoutHash),
  };
  // The server reconstructs the operator-signed payload without a cursor when
  // the request omits it or sends cursor:null. This drill does not need a
  // cursor, so sign and send the cursorless shape.
  const syncPayload = {
    wire_version: FEDERATION_SYNC_WIRE_VERSION,
    node_id: origin,
    events: [event],
  };
  const res = await fetch(`${rig.baseUrl}/v1/federation/sync`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(operatorSigned("/v1/federation/sync", syncPayload)),
  });
  expect(res.status).toBe(200);
  const body = (await res.json()) as { accepted: string[]; rejected: unknown[] };
  expect(body.accepted).toContain(event.event_id);
  expect(body.rejected).toEqual([]);
}

// retry:2 - loopback /v1 federation rig races port/session setup under full-
// suite parallel load (recurring non-hermetic CI flake class).
describe("Fleet Console Slice 1 - federation-backed roster drill", { retry: 2 }, () => {
  it("shows a correct live 2-node roster; revoking node 2 flips it to revoked", async () => {
    const token = await openDurableSession(rig);
    await enableFederation(token);

    // ── 1. Synthetic/loopback 2-node federation ──────────────────────────
    await admitNode(token, "node-1");
    await admitNode(token, "node-2");

    const before = await fetchFleet();
    expect(before.available).toBe(true);
    expect(before.enabled).toBe(true);
    expect(before.fortress_id).toBe(materials.fortressId);
    const byIdBefore = Object.fromEntries(
      before.nodes.map((n) => [n.node_id, n]),
    );
    expect(byIdBefore["node-1"]?.trust_state).toBe("admitted");
    expect(byIdBefore["node-2"]?.trust_state).toBe("admitted");
    expect(before.summary).toEqual(
      expect.objectContaining({ admitted: 2, revoked: 0, untrusted: 0 }),
    );

    // ── 2. Revoke node 2 (real operator-signed eviction) -> flips revoked ─
    await revokeNode(token, "node-2");

    const after = await fetchFleet();
    const byIdAfter = Object.fromEntries(after.nodes.map((n) => [n.node_id, n]));
    expect(byIdAfter["node-1"]?.trust_state).toBe("admitted");
    expect(byIdAfter["node-2"]?.trust_state).toBe("revoked");
    expect(byIdAfter["node-2"]?.trust_evaluable).toBe(true);
    expect(after.summary).toEqual(
      expect.objectContaining({ admitted: 1, revoked: 1, untrusted: 0 }),
    );
    // The fleet eviction serial advanced with the real eviction.
    expect(after.eviction_serial).toBe(1);
  });

  it("renders an unevaluable node as untrusted (fail-closed), never amber/admitted", async () => {
    const token = await openDurableSession(rig);
    await enableFederation(token);
    await admitNode(token, "node-1");
    await admitNode(token, "node-2");

    // Simulate the dashboard's revocation projection becoming momentarily
    // unevaluable (e.g. a transient read failure). The presenter calls
    // `isNodeRevoked` per node; when it THROWS, the node must render UNTRUSTED.
    // We make the live revoked-set membership check throw to model that exactly.
    const dash = rig.dashboard as unknown as {
      _federationState: { revoked: Set<string> };
    };
    const realRevoked = dash._federationState.revoked;
    const throwingRevoked = {
      has(id: string): boolean {
        if (id === "node-2") throw new Error("revocation projection unavailable");
        return realRevoked.has(id);
      },
    } as unknown as Set<string>;
    dash._federationState = {
      ...dash._federationState,
      revoked: throwingRevoked,
    };

    const roster = await fetchFleet();
    const byId = Object.fromEntries(roster.nodes.map((n) => [n.node_id, n]));
    expect(byId["node-1"]?.trust_state).toBe("admitted");
    // Fail-closed: an unevaluable node is untrusted, not amber, not admitted.
    expect(byId["node-2"]?.trust_state).toBe("untrusted");
    expect(byId["node-2"]?.trust_evaluable).toBe(false);
    expect(roster.summary).toEqual(
      expect.objectContaining({ admitted: 1, untrusted: 1 }),
    );
  });

  it("presents an honest absent roster when federation is not provisioned", async () => {
    // Detach the federation context: the fortress now has no fleet at all.
    rig.dashboard.setFederationContext(null);
    const roster = await fetchFleet();
    expect(roster.available).toBe(false);
    expect(roster.nodes).toEqual([]);
    expect(roster.summary).toEqual({
      total: 0,
      admitted: 0,
      revoked: 0,
      untrusted: 0,
    });
  });
});
