import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  V1_FEDERATION_SYNC_PEER_MAX_BODY_BYTES,
  federationEventHash,
  type FederationEvent,
} from "../../src/v1/federation.js";
import { MAX_BODY_BYTES } from "../../src/v1/http.js";
import { signOperatorPayload } from "../../src/v1/operator-signed.js";
import { toBase64url } from "../../src/core/encoding.js";
import {
  OPERATOR,
  openDurableSession,
  openLoopbackSession,
  startRig,
  type TestRig,
} from "./rig.js";
import { makeFederationMaterials, type FedMaterials } from "./fed-materials.js";
import {
  FEDERATION_NODE_EVICTION_EVENT_KIND,
  FEDERATION_SYNC_WIRE_VERSION,
  federationOperatorAuthorityOrigin,
  signFederationNodeEvictionPayload,
} from "../../src/v1/federation-revocation.js";

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

function makeEvent(params: {
  nodeId: string;
  sequence: number;
  previousHash: string | null;
  kind?: string;
}): FederationEvent {
  const withoutHash = {
    event_id: `${params.nodeId}:${params.sequence}`,
    origin_node_id: params.nodeId,
    sequence: params.sequence,
    occurred_at: `2026-06-10T00:00:0${params.sequence}.000Z`,
    kind: params.kind ?? "agent.seen",
    payload: { agent_id: `agent-${params.sequence}` },
    previous_hash: params.previousHash,
  };
  return {
    ...withoutHash,
    event_hash: federationEventHash(withoutHash),
  };
}

function makeEvictionEvent(
  nodeId: string,
  sequence: number,
  previousHash: string | null,
): FederationEvent {
  const origin = federationOperatorAuthorityOrigin(materials.fortressId);
  const payload = signFederationNodeEvictionPayload({
    fortressId: materials.fortressId,
    nodeId,
    reason: "operator test eviction",
    effectiveAt: `2026-06-20T12:00:0${sequence}.000Z`,
    evictionSerial: sequence,
    operatorPrincipalId: materials.context.issuingPrincipalCert.principal_id,
    operatorPrincipalPrivateKey:
      materials.context.getIssuingPrincipalPrivateKey(),
  });
  const withoutHash = {
    event_id: `${origin}:${sequence}`,
    origin_node_id: origin,
    sequence,
    occurred_at: `2026-06-20T12:00:0${sequence}.000Z`,
    kind: FEDERATION_NODE_EVICTION_EVENT_KIND,
    payload: payload as unknown as Record<string, unknown>,
    previous_hash: previousHash,
  };
  return {
    ...withoutHash,
    event_hash: federationEventHash(withoutHash),
  };
}

function operatorSigned(action: string, payload: Record<string, unknown>) {
  return {
    ...payload,
    operator_signature: toBase64url(signOperatorPayload(action, payload, OPERATOR.privateKey)),
  };
}

function currentSyncPayload(payload: Record<string, unknown>): Record<string, unknown> {
  return { wire_version: FEDERATION_SYNC_WIRE_VERSION, ...payload };
}

async function enable(token: string) {
  const res = await fetch(`${rig.baseUrl}/v1/federation/enable`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(operatorSigned("/v1/federation/enable", { idempotency_key: "enable" })),
  });
  expect(res.status).toBe(200);
}

async function sync(token: string, payload: Record<string, unknown>) {
  return fetch(`${rig.baseUrl}/v1/federation/sync`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function peerSyncRaw(token: string, body: string) {
  return fetch(`${rig.baseUrl}/v1/federation/sync/peer`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body,
  });
}

async function latestSyncAudit(identityId: string) {
  const { entries } = await rig.auditLog.query({
    layer: "l2",
    operation_type: "v1_federation_sync",
    identity_id: identityId,
    limit: 20,
  });
  expect(entries.length).toBeGreaterThan(0);
  return entries[entries.length - 1]!;
}

describe("/v1/nodes + /v1/federation/sync", () => {
  it("lists joined nodes with attestation and sync metadata", async () => {
    const token = await openDurableSession(rig);
    await enable(token);
    const event = makeEvent({ nodeId: "linux-1", sequence: 1, previousHash: null });
    const payload = {
      node_id: "linux-1",
      events: [event],
      cursor: { after_sequence: 0 },
      idempotency_key: "sync-1",
    };
    const res = await sync(
      token,
      operatorSigned("/v1/federation/sync", currentSyncPayload(payload)),
    );
    expect(res.status).toBe(200);
    const audit = await latestSyncAudit("linux-1");
    expect(audit.result).toBe("success");
    expect(audit.details).toEqual(
      expect.objectContaining({
        accepted: 1,
        rejected: 0,
        sender_revoked: false,
      }),
    );

    const nodesRes = await fetch(`${rig.baseUrl}/v1/nodes`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(nodesRes.status).toBe(200);
    const body = (await nodesRes.json()) as { nodes: Array<Record<string, any>> };
    expect(body.nodes).toHaveLength(1);
    expect(body.nodes[0].node_id).toBe("linux-1");
    expect(body.nodes[0].attestation_status).toBe("verified");
    expect(body.nodes[0].last_sync.last_sequence).toBe(1);
  });

  it("requires OPERATOR_SIGNED for sync; a loopback session alone is not enough", async () => {
    const token = await openLoopbackSession(rig);
    const res = await sync(
      token,
      currentSyncPayload({
        node_id: "linux-1",
        events: [],
        idempotency_key: "unsigned",
      }),
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden" });
  });

  it("verifies operator-signed sync payloads with and without a cursor", async () => {
    const token = await openDurableSession(rig);
    await enable(token);

    const cursorless = makeEvent({
      nodeId: "linux-1",
      sequence: 1,
      previousHash: null,
    });
    const cursorlessPayload = currentSyncPayload({
      node_id: "linux-1",
      events: [cursorless],
      idempotency_key: "cursorless-sync",
    });
    expect("cursor" in cursorlessPayload).toBe(false);

    const cursorlessRes = await sync(
      token,
      operatorSigned("/v1/federation/sync", cursorlessPayload),
    );
    expect(cursorlessRes.status).toBe(200);
    expect(((await cursorlessRes.json()) as { accepted: string[] }).accepted).toEqual([
      cursorless.event_id,
    ]);
    expect((await latestSyncAudit("linux-1")).result).toBe("success");

    const withCursor = makeEvent({
      nodeId: "linux-2",
      sequence: 1,
      previousHash: null,
    });
    const withCursorPayload = currentSyncPayload({
      node_id: "linux-2",
      events: [withCursor],
      cursor: { node_id: "linux-2", after_sequence: 0 },
      idempotency_key: "with-cursor-sync",
    });
    expect(withCursorPayload.cursor).toEqual({
      node_id: "linux-2",
      after_sequence: 0,
    });

    const withCursorRes = await sync(
      token,
      operatorSigned("/v1/federation/sync", withCursorPayload),
    );
    expect(withCursorRes.status).toBe(200);
    expect(((await withCursorRes.json()) as { accepted: string[] }).accepted).toEqual([
      withCursor.event_id,
    ]);
    expect((await latestSyncAudit("linux-2")).result).toBe("success");
  });

  it("uses a peer-sync-specific JSON body cap for certificate-bearing envelopes, with no body-size oracle", async () => {
    // Federation P1: /sync/peer is pre-session and node-cert-authenticated. The
    // peer-specific body cap still rejects oversized envelopes (so cert-bearing
    // hybrid envelopes up to V1_FEDERATION_SYNC_PEER_MAX_BODY_BYTES are accepted
    // for parsing, but bigger is rejected cheaply before JSON.parse). NO-ORACLE
    // (§2): the over-default-under-peer-cap case and the over-peer-cap case now
    // BOTH collapse to the SAME generic 403 a verify failure returns, so a probe
    // cannot tell "too big" from "bad envelope" from the wire.
    const token = await openDurableSession(rig);
    await enable(token);

    const overDefaultUnderPeerCap = JSON.stringify({
      sender_node_id: "oversized-peer",
      pad: "x".repeat(MAX_BODY_BYTES + 1024),
    });
    expect(Buffer.byteLength(overDefaultUnderPeerCap, "utf8")).toBeGreaterThan(
      MAX_BODY_BYTES
    );
    expect(Buffer.byteLength(overDefaultUnderPeerCap, "utf8")).toBeLessThan(
      V1_FEDERATION_SYNC_PEER_MAX_BODY_BYTES
    );

    // Parsed (under the peer cap) but not a valid envelope -> generic 403.
    const parsedThenRejected = await peerSyncRaw(
      token,
      overDefaultUnderPeerCap
    );
    expect(parsedThenRejected.status).toBe(403);
    expect(await parsedThenRejected.json()).toEqual({ error: "forbidden" });

    const overPeerCap = JSON.stringify({
      sender_node_id: "too-large-peer",
      pad: "x".repeat(V1_FEDERATION_SYNC_PEER_MAX_BODY_BYTES),
    });
    expect(Buffer.byteLength(overPeerCap, "utf8")).toBeGreaterThan(
      V1_FEDERATION_SYNC_PEER_MAX_BODY_BYTES
    );

    // Rejected before parse (over the peer cap) -> the SAME generic 403, NOT a
    // distinguishable 400 (no body-size oracle).
    const rejectedBeforeParse = await peerSyncRaw(token, overPeerCap);
    expect(rejectedBeforeParse.status).toBe(403);
    expect(await rejectedBeforeParse.json()).toEqual({ error: "forbidden" });
  });

  it("rejects legacy unversioned sync requests before appending events", async () => {
    const token = await openDurableSession(rig);
    await enable(token);
    const event = makeEvent({ nodeId: "linux-1", sequence: 1, previousHash: null });
    const legacyPayload = {
      node_id: "linux-1",
      events: [event],
      cursor: { after_sequence: 0 },
      idempotency_key: "legacy-unversioned",
    };

    const res = await sync(
      token,
      operatorSigned("/v1/federation/sync", legacyPayload),
    );

    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden" });
    const nodesRes = await fetch(`${rig.baseUrl}/v1/nodes`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(((await nodesRes.json()) as { nodes: unknown[] }).nodes).toHaveLength(0);
  });

  it("rejects ordinary operator-signed sync events from an already-revoked node", async () => {
    const token = await openDurableSession(rig);
    await enable(token);

    const eviction = makeEvictionEvent("linux-1", 1, null);
    const evictionPayload = {
      node_id: federationOperatorAuthorityOrigin(materials.fortressId),
      events: [eviction],
      cursor: {},
      idempotency_key: "evict-linux-1",
    };
    const evictionRes = await sync(
      token,
      operatorSigned("/v1/federation/sync", currentSyncPayload(evictionPayload)),
    );
    expect(evictionRes.status).toBe(200);
    expect(((await evictionRes.json()) as { accepted: string[] }).accepted).toEqual([
      eviction.event_id,
    ]);

    const linuxEvent = makeEvent({
      nodeId: "linux-1",
      sequence: 1,
      previousHash: null,
    });
    const res = await sync(
      token,
      operatorSigned(
        "/v1/federation/sync",
        currentSyncPayload({
          node_id: "linux-1",
          events: [linuxEvent],
          cursor: { node_id: "linux-1", after_sequence: 0 },
          idempotency_key: "revoked-linux-ordinary",
        }),
      ),
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      accepted: string[];
      rejected: Array<{ event_id: string; reason: string }>;
      events?: FederationEvent[];
    };
    expect(body.accepted).toEqual([]);
    expect(body.rejected).toEqual([
      { event_id: linuxEvent.event_id, reason: "node_revoked" },
    ]);
    expect(body.events).toBeUndefined();
    const audit = await latestSyncAudit("linux-1");
    expect(audit.result).toBe("failure");
    expect(audit.details).toEqual(
      expect.objectContaining({
        accepted: 0,
        rejected: 1,
        sender_revoked: true,
      }),
    );

    const nodesRes = await fetch(`${rig.baseUrl}/v1/nodes`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(((await nodesRes.json()) as { nodes: unknown[] }).nodes).toHaveLength(0);
    const events = (rig.dashboard as unknown as {
      listFederationEvents(): FederationEvent[];
    }).listFederationEvents();
    expect(events.map((event) => event.event_id)).not.toContain(linuxEvent.event_id);
  });

  it("rejects a tampered operator signature before appending events", async () => {
    const token = await openDurableSession(rig);
    await enable(token);
    const event = makeEvent({ nodeId: "linux-1", sequence: 1, previousHash: null });
    const payload = {
      node_id: "linux-1",
      events: [event],
      idempotency_key: "tampered",
    };
    const signed = operatorSigned("/v1/federation/sync", currentSyncPayload(payload));
    const res = await sync(token, { ...signed, node_id: "cloud-1" });
    expect(res.status).toBe(403);

    const nodesRes = await fetch(`${rig.baseUrl}/v1/nodes`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(((await nodesRes.json()) as { nodes: unknown[] }).nodes).toHaveLength(0);
  });

  it("accepts a two-node exchange and rejects hash tampering, replay, and stale events", async () => {
    const token = await openDurableSession(rig);
    await enable(token);
    const linux1 = makeEvent({ nodeId: "linux-1", sequence: 1, previousHash: null });
    const linux2 = makeEvent({ nodeId: "linux-1", sequence: 2, previousHash: linux1.event_hash });
    const cloud1 = makeEvent({ nodeId: "cloud-1", sequence: 1, previousHash: null });
    const tampered = { ...makeEvent({ nodeId: "cloud-1", sequence: 2, previousHash: cloud1.event_hash }) };
    tampered.payload = { agent_id: "changed-after-hash" };
    const staleWithoutHash = {
      event_id: "linux-1:stale",
      origin_node_id: "linux-1",
      sequence: 1,
      occurred_at: "2026-06-10T00:00:09.000Z",
      kind: "stale",
      payload: { agent_id: "old" },
      previous_hash: null,
    };
    const stale = {
      ...staleWithoutHash,
      event_hash: federationEventHash(staleWithoutHash),
    };
    const payload = {
      node_id: "linux-1",
      events: [linux1, linux2, cloud1, tampered, linux1, stale],
      cursor: { node_id: "linux-1", after_sequence: 0 },
      idempotency_key: "exchange",
    };
    const res = await sync(
      token,
      operatorSigned("/v1/federation/sync", currentSyncPayload(payload)),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      accepted: string[];
      rejected: Array<{ event_id: string; reason: string }>;
      events: FederationEvent[];
    };
    expect(body.accepted).toEqual(["linux-1:1", "linux-1:2", "cloud-1:1"]);
    expect(body.rejected).toEqual(
      expect.arrayContaining([
        { event_id: "cloud-1:2", reason: "hash_mismatch" },
        { event_id: "linux-1:1", reason: "replay" },
        { event_id: "linux-1:stale", reason: "stale_sequence" },
      ]),
    );
    expect(body.events.map((event) => event.event_id)).toEqual(["linux-1:1", "linux-1:2"]);
  });
});
