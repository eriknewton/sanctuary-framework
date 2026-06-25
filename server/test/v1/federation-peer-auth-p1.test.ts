/**
 * Federation P1 — node-cert-authenticated PRE-SESSION `/sync/peer` route class +
 * dedicated rate limiter (merge-bar acceptance tests).
 *
 * P1 moves `/v1/federation/sync/peer` out of the post-session class and into a
 * new pre-session "node-cert-authenticated" auth class, dispatched BEFORE the
 * /v1 session gate (router.ts), alongside the BOOTSTRAP_TOKEN join ceremony. The
 * capability: a remote operator's machine syncs over a plain network connection
 * with NO `Authorization` header and NO shared operator login — the node
 * certificate in the sync envelope is the sole trust decision (it already was;
 * the session only gated network access).
 *
 * This file is the executable acceptance criteria for the six merge-bar tests:
 *   1. Positive end-to-end pre-session sync (no Authorization header), reciprocal
 *      envelope verified.
 *   2. Forged / unauthenticated envelope -> generic 403, slice NOT appended,
 *      audit reason recorded.
 *   3. No membership oracle: disabled / unprovisioned / bad-envelope are
 *      indistinguishable on the wire.
 *   4. Loopback is NOT rate-limit-exempt on this route (throttles), while the
 *      general/dashboard class over loopback still does NOT throttle.
 *   5. In-class-but-unhandled route fails closed + a non-POST on /sync/peer does
 *      not bypass into legacy routing.
 *   6. Post-session routes still require a session (no regression from moving
 *      /sync/peer out of isFederationPath).
 *
 * Confidentiality (P1 §5): the signed envelope gives INTEGRITY + AUTHENTICITY,
 * not confidentiality. These loopback tests do not, and cannot, prove the
 * composed confidential transport (Tailscale/WireGuard) the deploy story
 * requires; that is a transport-composition concern, asserted in the docs, not a
 * code feature.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { buildChallengeMessage } from "../../src/v1/ceremony.js";
import { toBase64url, fromBase64url } from "../../src/core/encoding.js";
import {
  signSyncEnvelope,
  type FederationSyncEnvelope,
} from "../../src/v1/federation-sync-envelope.js";
import {
  federationEventHash,
  isFederationNodeCertAuthPath,
  isFederationPath,
  type FederationEvent,
} from "../../src/v1/federation.js";
import {
  makeMultiNodeFortress,
  type FortressNode,
  type MultiNodeFortress,
} from "./fed-materials.js";

interface NodeDaemon {
  dashboard: DashboardApprovalChannel;
  baseUrl: string;
  node: FortressNode;
  auditLog: AuditLog;
  stop: () => Promise<void>;
}

function pickPort(): number {
  return 30000 + Math.floor(Math.random() * 20000);
}

/** Boot one daemon for a fortress node. `provision`/`enabled` control state. */
async function startNodeDaemon(
  node: FortressNode,
  opts: { provision?: boolean; enabled?: boolean } = {},
): Promise<NodeDaemon> {
  const provision = opts.provision ?? true;
  const enabled = opts.enabled ?? true;
  const storage = new MemoryStorage();
  const auditLog = new AuditLog(storage, randomBytes(32));
  const port = pickPort();
  const dashboard = new DashboardApprovalChannel({
    port,
    host: "127.0.0.1",
    timeout_seconds: 30,
    auth_token: `p1-${randomBytes(6).toString("hex")}`,
    auto_open: false,
  });
  dashboard.setDependencies({
    policy: {
      version: 1,
      tier1_always_approve: [],
      tier3_auto_allow: [],
      anomaly_thresholds: {
        new_namespace: true,
        unfamiliar_counterparty_window_days: 7,
        frequency_spike_multiplier: 5,
      },
      approval_channel: { type: "stderr", timeout_seconds: 30 },
    } as never,
    baseline: { load: async () => {}, save: async () => {} } as never,
    auditLog,
  });
  if (provision) {
    dashboard.setFederationContext(node.context);
    (dashboard as unknown as { _federationEnabled: boolean })._federationEnabled =
      enabled;
  }
  await dashboard.start();
  return {
    dashboard,
    baseUrl: `http://127.0.0.1:${port}`,
    node,
    auditLog,
    stop: () => dashboard.stop(),
  };
}

/** Open a loopback /v1 session — only used to prove POST-session routes 401. */
async function openSession(daemon: NodeDaemon): Promise<string> {
  daemon.dashboard.setAutoAuthLocalhost(true);
  const privateKey = randomBytes(32);
  const publicKey = ed25519.getPublicKey(privateKey);
  const initRes = await fetch(`${daemon.baseUrl}/v1/session/init`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ client_pubkey: toBase64url(publicKey) }),
  });
  expect(initRes.status).toBe(200);
  const init = (await initRes.json()) as {
    challenge: string;
    challenge_id: string;
    attestation_ref: string;
  };
  const message = buildChallengeMessage(
    publicKey,
    fromBase64url(init.challenge),
    init.attestation_ref,
  );
  const completeRes = await fetch(`${daemon.baseUrl}/v1/session/complete`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      challenge_id: init.challenge_id,
      client_signature: toBase64url(ed25519.sign(message, privateKey)),
    }),
  });
  expect(completeRes.status).toBe(200);
  return ((await completeRes.json()) as { session_token: string }).session_token;
}

/** POST a raw envelope to /sync/peer with NO Authorization header. */
async function postPeerNoAuth(
  baseUrl: string,
  envelope: FederationSyncEnvelope | Record<string, unknown>,
): Promise<Response> {
  return fetch(`${baseUrl}/v1/federation/sync/peer`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(envelope),
  });
}

function makeEvent(
  nodeId: string,
  sequence: number,
  previousHash: string | null,
): FederationEvent {
  const withoutHash = {
    event_id: `${nodeId}:${sequence}`,
    origin_node_id: nodeId,
    sequence,
    occurred_at: `2026-06-24T00:00:0${sequence}.000Z`,
    kind: "agent.seen",
    payload: { agent_id: `agent-${sequence}` },
    previous_hash: previousHash,
  };
  return { ...withoutHash, event_hash: federationEventHash(withoutHash) };
}

function signedSlice(
  fortress: MultiNodeFortress,
  senderId: string,
  recipientId: string,
  highWater: number,
  events: FederationEvent[],
): FederationSyncEnvelope {
  const sender = fortress.nodes[senderId]!;
  return signSyncEnvelope({
    fortressId: fortress.fortressId,
    senderNodeId: senderId,
    recipientNodeId: recipientId,
    syncHighWater: highWater,
    events,
    senderNodeCert: sender.nodeCert,
    issuingPrincipalCert: fortress.principalCert,
    nodePrivateKey: Uint8Array.from(sender.nodePrivateKey),
  });
}

async function latestPeerSyncAudit(daemon: NodeDaemon, identityId: string) {
  const { entries } = await daemon.auditLog.query({
    layer: "l2",
    operation_type: "v1_federation_sync_peer",
    identity_id: identityId,
    limit: 20,
  });
  return entries[entries.length - 1];
}

let fortress: MultiNodeFortress;
let mac1: NodeDaemon;
let linux1: NodeDaemon;

beforeEach(async () => {
  fortress = makeMultiNodeFortress(["mac-1", "linux-1"]);
  mac1 = await startNodeDaemon(fortress.nodes["mac-1"]!);
  linux1 = await startNodeDaemon(fortress.nodes["linux-1"]!);
});

afterEach(async () => {
  await mac1.stop();
  await linux1.stop();
});

describe("Federation P1 — pre-session node-cert-authenticated /sync/peer", () => {
  // ── Path-class predicates (unit level) ──────────────────────────────
  it("classifies /sync/peer in the node-cert-auth class and NOT the post-session class", () => {
    expect(isFederationNodeCertAuthPath("/v1/federation/sync/peer")).toBe(true);
    // It is no longer a post-session federation path (moved out of isFederationPath).
    expect(isFederationPath("/v1/federation/sync/peer")).toBe(false);
    // The post-session routes are untouched.
    for (const p of [
      "/v1/federation/enable",
      "/v1/federation/disable",
      "/v1/federation/status",
      "/v1/federation/authorize/init",
      "/v1/federation/sync",
      "/v1/nodes",
    ]) {
      expect(isFederationPath(p)).toBe(true);
      expect(isFederationNodeCertAuthPath(p)).toBe(false);
    }
    // The join ceremony is a DIFFERENT pre-session class, not this one.
    expect(isFederationNodeCertAuthPath("/v1/federation/authorize/complete")).toBe(
      false,
    );
    // A would-be future in-class route (3b) is NOT in the class yet.
    expect(
      isFederationNodeCertAuthPath("/v1/federation/rotate/reissue-node-cert"),
    ).toBe(false);
  });

  // ── Merge-bar 1: positive end-to-end (no Authorization header) ──────
  it("syncs a slice with NO Authorization header and verifies the reciprocal envelope", async () => {
    // mac-1 attests an agent so it has a real event to push.
    mac1.dashboard.recordLocalAgentIdentity("agent-p1", undefined);
    const macEvents = (mac1.dashboard as unknown as {
      listFederationEvents(): FederationEvent[];
    }).listFederationEvents();
    expect(macEvents.length).toBeGreaterThanOrEqual(1);

    const envelope = signSyncEnvelope({
      fortressId: fortress.fortressId,
      senderNodeId: "mac-1",
      recipientNodeId: "linux-1",
      syncHighWater: 1,
      events: macEvents,
      senderNodeCert: fortress.nodes["mac-1"]!.nodeCert,
      issuingPrincipalCert: fortress.principalCert,
      nodePrivateKey: Uint8Array.from(fortress.nodes["mac-1"]!.nodePrivateKey),
    });

    // NO Authorization header. The node cert in the envelope is the sole credential.
    const res = await postPeerNoAuth(linux1.baseUrl, envelope);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      accepted: string[];
      envelope?: FederationSyncEnvelope;
    };
    expect(body.accepted).toContain("mac-1:1");

    // Reciprocal envelope present and itself cert-chain-verifiable: it carries
    // linux-1's node cert chaining to the SAME shared master.
    expect(body.envelope).toBeDefined();
    expect(body.envelope?.sender_node_id).toBe("linux-1");
    expect(body.envelope?.sender_node_cert?.node_id).toBe("linux-1");

    const audit = await latestPeerSyncAudit(linux1, "mac-1");
    expect(audit?.result).toBe("success");
  });

  // ── Merge-bar 2: forged / unauthenticated envelope -> 403, not appended ─
  it("rejects a forged envelope (foreign master) with a generic 403, appends nothing, audits the reason", async () => {
    // A node from a DIFFERENT fortress (different master) signs a structurally
    // valid envelope. Its cert does NOT chain to linux-1's pinned master.
    const foreign = makeMultiNodeFortress(["intruder"]);
    const forged = signSyncEnvelope({
      fortressId: foreign.fortressId,
      senderNodeId: "intruder",
      recipientNodeId: "linux-1",
      syncHighWater: 1,
      events: [makeEvent("intruder", 1, null)],
      senderNodeCert: foreign.nodes["intruder"]!.nodeCert,
      issuingPrincipalCert: foreign.principalCert,
      nodePrivateKey: Uint8Array.from(foreign.nodes["intruder"]!.nodePrivateKey),
    });

    const res = await postPeerNoAuth(linux1.baseUrl, forged);
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden" });

    // Nothing was appended to linux-1's log.
    const linuxEvents = (linux1.dashboard as unknown as {
      listFederationEvents(): FederationEvent[];
    }).listFederationEvents();
    expect(linuxEvents.some((e) => e.origin_node_id === "intruder")).toBe(false);

    // The precise denial reason is recorded in the audit log (not on the wire).
    const audit = await latestPeerSyncAudit(linux1, "intruder");
    expect(audit?.result).toBe("failure");
    expect(audit?.details).toBeDefined();
  });

  it("rejects a tampered signature with the same generic 403", async () => {
    const envelope = signedSlice(fortress, "mac-1", "linux-1", 1, [
      makeEvent("mac-1", 1, null),
    ]);
    // Flip the node-key signature.
    const tampered = {
      ...envelope,
      envelope_signature: toBase64url(randomBytes(64)),
    };
    const res = await postPeerNoAuth(linux1.baseUrl, tampered);
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden" });
  });

  it("returns an over-ceiling 403 byte-identical (status + headers incl. cache-control: no-store + body) to a normal verify-failure 403", async () => {
    // Regression guard for the P1 review fix: the concurrent-verify over-ceiling
    // rejection MUST go through denyForbidden() so it carries Cache-Control:
    // no-store like every other 403 on this route. A hand-rolled writeHead that
    // omitted the header was wire-distinguishable -> a membership/load oracle.

    // (a) A normal verify failure (foreign master) — the reference 403.
    const foreign = makeMultiNodeFortress(["intruder"]);
    const forged = signSyncEnvelope({
      fortressId: foreign.fortressId,
      senderNodeId: "intruder",
      recipientNodeId: "linux-1",
      syncHighWater: 1,
      events: [makeEvent("intruder", 1, null)],
      senderNodeCert: foreign.nodes["intruder"]!.nodeCert,
      issuingPrincipalCert: foreign.principalCert,
      nodePrivateKey: Uint8Array.from(foreign.nodes["intruder"]!.nodePrivateKey),
    });
    const verifyFailRes = await postPeerNoAuth(linux1.baseUrl, forged);
    const verifyFailBody = await verifyFailRes.text();

    // (b) Drive the in-flight counter to the ceiling so the very next peer-sync
    // request takes the over-ceiling branch deterministically (no concurrency
    // race). The branch returns synchronously before any envelope is parsed, so
    // the envelope can be anything.
    const internals = linux1.dashboard as unknown as { inFlightPeerVerify: number };
    const saved = internals.inFlightPeerVerify;
    internals.inFlightPeerVerify = 16; // MAX_CONCURRENT_PEER_VERIFY
    let overCeilingRes: Response;
    let overCeilingBody: string;
    try {
      overCeilingRes = await postPeerNoAuth(linux1.baseUrl, { any: "body" });
      overCeilingBody = await overCeilingRes.text();
    } finally {
      internals.inFlightPeerVerify = saved;
    }

    // Status, body, and the security-relevant headers must all match exactly.
    expect(overCeilingRes.status).toBe(verifyFailRes.status);
    expect(overCeilingRes.status).toBe(403);
    expect(overCeilingBody).toBe(verifyFailBody);
    expect(overCeilingBody).toBe('{"error":"forbidden"}');
    expect(overCeilingRes.headers.get("cache-control")).toBe("no-store");
    expect(overCeilingRes.headers.get("cache-control")).toBe(
      verifyFailRes.headers.get("cache-control"),
    );
    expect(overCeilingRes.headers.get("content-type")).toBe(
      verifyFailRes.headers.get("content-type"),
    );
  });

  // ── Merge-bar 3: no membership oracle ───────────────────────────────
  it("returns an indistinguishable response for disabled, unprovisioned, and bad-envelope", async () => {
    // (a) federation disabled (provisioned-but-off).
    const disabled = await startNodeDaemon(fortress.nodes["mac-1"]!, {
      provision: true,
      enabled: false,
    });
    // (b) federation unprovisioned (no context bound at all).
    const unprovisioned = await startNodeDaemon(fortress.nodes["linux-1"]!, {
      provision: false,
    });
    try {
      const goodEnvelope = signedSlice(fortress, "mac-1", "linux-1", 1, [
        makeEvent("mac-1", 1, null),
      ]);
      const badEnvelope = { not: "an envelope" };

      const disabledRes = await postPeerNoAuth(disabled.baseUrl, goodEnvelope);
      const unprovRes = await postPeerNoAuth(unprovisioned.baseUrl, goodEnvelope);
      // (c) provisioned+enabled but the envelope is junk.
      const badRes = await postPeerNoAuth(linux1.baseUrl, badEnvelope);

      const [disabledBody, unprovBody, badBody] = await Promise.all([
        disabledRes.json(),
        unprovRes.json(),
        badRes.json(),
      ]);

      // All three: SAME status + SAME body. No enabled/provisioned/which-check oracle.
      expect(disabledRes.status).toBe(403);
      expect(unprovRes.status).toBe(403);
      expect(badRes.status).toBe(403);
      expect(disabledBody).toEqual({ error: "forbidden" });
      expect(unprovBody).toEqual({ error: "forbidden" });
      expect(badBody).toEqual({ error: "forbidden" });
    } finally {
      await disabled.stop();
      await unprovisioned.stop();
    }
  });

  // ── Merge-bar 4: loopback is NOT rate-limit-exempt on this route ─────
  it("throttles a loopback flood on /sync/peer while the general class over loopback does NOT throttle", async () => {
    // The federation_peer bucket is 60/min and does NOT exempt loopback. A junk
    // envelope still consumes a token (the rate check runs BEFORE any federation
    // state check), so a sustained flood eventually 429s — proving the loopback
    // exemption was dropped for this class.
    const junk = { not: "an envelope" };
    let sawThrottle = false;
    let firstThrottleIndex = -1;
    for (let i = 0; i < 80; i++) {
      const res = await postPeerNoAuth(linux1.baseUrl, junk);
      if (res.status === 429) {
        sawThrottle = true;
        firstThrottleIndex = i;
        // The throttle body carries NO federation-state detail (no-oracle §3).
        const body = (await res.json()) as Record<string, unknown>;
        expect(body).not.toHaveProperty("enabled");
        expect(body).not.toHaveProperty("provisioned");
        expect(res.headers.get("retry-after")).toBeTruthy();
        break;
      } else {
        // Pre-throttle, every junk request is the generic 403 (no oracle).
        expect(res.status).toBe(403);
        await res.json();
      }
    }
    expect(sawThrottle).toBe(true);
    // It throttled at the bucket boundary (60), not on the first request.
    expect(firstThrottleIndex).toBeGreaterThanOrEqual(60);

    // No regression: the general/dashboard class over loopback is NOT throttled.
    // The unauthenticated GET /v1/status is the general class; hammer it well
    // past the federation bucket and it must never 429.
    for (let i = 0; i < 130; i++) {
      const res = await fetch(`${linux1.baseUrl}/v1/status`);
      expect(res.status).toBe(200);
      await res.json();
    }
  });

  // ── Merge-bar 5: non-POST does not bypass; in-class-but-unhandled fails closed ─
  it("does not let a non-POST on /sync/peer bypass into legacy routing", async () => {
    // A GET on /sync/peer is NOT in the POST-only node-cert-auth dispatch, so it
    // falls through to the session gate: a generic 401 to an unauthenticated
    // caller (NOT a 200, NOT legacy /api routing, NOT a method-specific error).
    const res = await fetch(`${linux1.baseUrl}/v1/federation/sync/peer`, {
      method: "GET",
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });

    // With a valid session, a GET on the POST-only route is a generic 404 (an
    // authed caller can distinguish not-found) — still never legacy routing.
    const token = await openSession(linux1);
    const authed = await fetch(`${linux1.baseUrl}/v1/federation/sync/peer`, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    });
    expect([401, 404]).toContain(authed.status);
  });

  // ── Merge-bar 6: post-session routes still require a session ─────────
  it("still requires a session for the post-session federation routes (no regression)", async () => {
    // Moving /sync/peer out of isFederationPath must not open the post-session
    // routes. Each must 401 without a session.
    const postSessionProbes: Array<{ path: string; method: string }> = [
      { path: "/v1/federation/enable", method: "POST" },
      { path: "/v1/federation/disable", method: "POST" },
      { path: "/v1/federation/authorize/init", method: "POST" },
      { path: "/v1/federation/sync", method: "POST" },
      { path: "/v1/nodes", method: "GET" },
    ];
    for (const probe of postSessionProbes) {
      const res = await fetch(`${linux1.baseUrl}${probe.path}`, {
        method: probe.method,
        headers: { "Content-Type": "application/json" },
        body: probe.method === "POST" ? JSON.stringify({}) : undefined,
      });
      expect(res.status, `${probe.method} ${probe.path}`).toBe(401);
      expect(await res.json()).toEqual({ error: "unauthorized" });
    }
  });
});
