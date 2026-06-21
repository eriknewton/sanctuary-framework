/**
 * PR-A5 cross-machine FEDERATION MARQUEE integration test.
 *
 * The marquee scenario (API_Parity_Federation_Ready_Design §3.5): one operator,
 * many machines, one unified cross-machine view. This test stands up TWO
 * in-process daemons on different loopback ports — `mac-1` and `linux-1` — that
 * belong to the SAME fortress (one shared pinned fortress-master). It drives the
 * REAL cross-node sync over HTTP (`pushSyncToPeer` → POST /v1/federation/sync/peer),
 * not the A4 loopback-position-only self-sync, and asserts end to end:
 *
 *   1. Real cross-node exchange: mac-1's hash-chained event log is pushed to
 *      linux-1 over HTTP; linux-1 reconciles it into a consistent cross-machine
 *      view, verifying mac-1's node attestation CRYPTOGRAPHICALLY (cert chain to
 *      the shared pinned master) — no implicit trust across the boundary.
 *   2. Identity survives a substrate move: an agent attested on mac-1 is
 *      RECOGNIZED on linux-1 via the operator-signed portable identity event,
 *      NOT re-minted.
 *   3. Reciprocal verification: linux-1's reply envelope is verified by mac-1
 *      against the same shared master before mac-1 trusts any reciprocal event.
 *
 * Security (the things codex will attack), all asserted here:
 *   - A node from a DIFFERENT fortress (different master) is rejected (403):
 *     no trust elevation across the operator boundary.
 *   - A tampered envelope signature is rejected.
 *   - Replay / rollback of a whole (validly-signed) envelope is rejected via the
 *     per-sender high-water guard.
 *   - No private key material crosses the wire (only public certs + signatures).
 *
 * HARDWARE-DRILL ACCEPTANCE GATE (deferred, Erik-present on Mini1): this test
 * proves the protocol on LOOPBACK with two in-process daemons. The marquee
 * CAPTURE on REAL hardware — two physically separate machines (e.g. the Mac +
 * a Linux box) each running a signed daemon, an agent physically moved between
 * them, and the unified view rendered in the Mac app — is the deferred Mini1
 * drill and is NOT performed here. What loopback CANNOT prove: real NIC/TLS
 * transport, cross-OS clock skew, the host-app rendering the unified view, and
 * arming the Castle Wall around the federation listener. Those are the
 * acceptance criteria the hardware drill must capture.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { buildChallengeMessage } from "../../src/v1/ceremony.js";
import { toBase64url, fromBase64url } from "../../src/core/encoding.js";
import {
  pushSyncToPeer,
  recognizedPortableAgents,
  type PeerSyncIdentity,
} from "../../src/v1/federation-client.js";
import {
  signSyncEnvelope,
  type FederationSyncEnvelope,
} from "../../src/v1/federation-sync-envelope.js";
import { federationEventHash, type FederationEvent } from "../../src/v1/federation.js";
import {
  makeMultiNodeFortress,
  type FortressNode,
  type MultiNodeFortress,
} from "./fed-materials.js";

interface NodeDaemon {
  dashboard: DashboardApprovalChannel;
  baseUrl: string;
  node: FortressNode;
  stop: () => Promise<void>;
}

function pickPort(): number {
  return 30000 + Math.floor(Math.random() * 20000);
}

/** Boot one daemon for a fortress node, federation enabled + provisioned. */
async function startNodeDaemon(node: FortressNode): Promise<NodeDaemon> {
  const storage = new MemoryStorage();
  const auditLog = new AuditLog(storage, randomBytes(32));
  const port = pickPort();
  const dashboard = new DashboardApprovalChannel({
    port,
    host: "127.0.0.1",
    timeout_seconds: 30,
    auth_token: `marquee-${randomBytes(6).toString("hex")}`,
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
  dashboard.setFederationContext(node.context);
  // Federation enable is normally an operator-signed call; the marquee tests the
  // cross-node DATA path, so we flip it on directly via the same seam the
  // operator action ultimately drives.
  (dashboard as unknown as { _federationEnabled: boolean })._federationEnabled = true;
  await dashboard.start();
  return {
    dashboard,
    baseUrl: `http://127.0.0.1:${port}`,
    node,
    stop: () => dashboard.stop(),
  };
}

/** Open a loopback /v1 session on a daemon (network-access gate for /sync/peer). */
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

function peerIdentity(node: FortressNode): PeerSyncIdentity {
  // Fresh private-key copy per push so the driver's zeroing doesn't burn it.
  return { ...node.peerIdentity, nodePrivateKey: Uint8Array.from(node.peerIdentity.nodePrivateKey) };
}

let fortress: MultiNodeFortress;
let mac1: NodeDaemon;
let linux1: NodeDaemon;

beforeEach(async () => {
  fortress = makeMultiNodeFortress(["mac-1", "linux-1"]);
  mac1 = await startNodeDaemon(fortress.nodes["mac-1"]);
  linux1 = await startNodeDaemon(fortress.nodes["linux-1"]);
});

afterEach(async () => {
  await mac1.stop();
  await linux1.stop();
});

// retry:2 - cross-machine marquee assertions are timing/async-sensitive under
// full-suite parallel load (pass sharded + in isolation); retry re-runs, so a
// genuine regression still fails all attempts (not a regression-masking skip).
describe("PR-A5 cross-machine federation marquee", { retry: 2 }, () => {
  it("syncs an agent identity from mac-1 to linux-1 over real HTTP and recognizes it cross-machine", async () => {
    // mac-1 attests an agent locally → a portable agent.identity event.
    const agentPubkey = toBase64url(ed25519.getPublicKey(randomBytes(32)));
    mac1.dashboard.recordLocalAgentIdentity("agent-portable-1", agentPubkey);

    // linux-1 opens a /v1 session (network-access gate). mac-1 drives the REAL
    // cross-node sync to linux-1 over HTTP.
    const linuxSession = await openSession(linux1);
    const macEvents = (mac1.dashboard as unknown as {
      listFederationEvents(): FederationEvent[];
    }).listFederationEvents();
    expect(macEvents.length).toBeGreaterThanOrEqual(1);

    const result = await pushSyncToPeer(peerIdentity(fortress.nodes["mac-1"]), {
      peerUrl: linux1.baseUrl,
      recipientNodeId: "linux-1",
      sessionToken: linuxSession,
      events: macEvents,
      syncHighWater: 1,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // linux-1 accepted mac-1's agent.identity event after cert-chain verifying it.
    expect(result.acceptedByPeer).toContain("mac-1:1");

    // Cross-machine unified view: linux-1's /v1/nodes now lists mac-1 as a
    // VERIFIED node, and linux-1's log recognizes the portable agent without
    // re-minting it.
    const nodesRes = await fetch(`${linux1.baseUrl}/v1/nodes`, {
      headers: { Authorization: `Bearer ${linuxSession}` },
    });
    const nodesBody = (await nodesRes.json()) as { nodes: Array<Record<string, unknown>> };
    const macNode = nodesBody.nodes.find((n) => n.node_id === "mac-1");
    expect(macNode?.attestation_status).toBe("verified");

    const linuxEvents = (linux1.dashboard as unknown as {
      listFederationEvents(): FederationEvent[];
    }).listFederationEvents();
    const recognized = recognizedPortableAgents(linuxEvents);
    expect(recognized.has("agent-portable-1")).toBe(true);
    expect([...(recognized.get("agent-portable-1") ?? [])]).toContain("mac-1");
  });

  it("verifies the reciprocal reply: a round-trip sync exchanges both logs verifiably", async () => {
    mac1.dashboard.recordLocalAgentIdentity("agent-on-mac", undefined);
    linux1.dashboard.recordLocalAgentIdentity("agent-on-linux", undefined);

    const linuxSession = await openSession(linux1);
    const macEvents = (mac1.dashboard as unknown as {
      listFederationEvents(): FederationEvent[];
    }).listFederationEvents();

    const result = await pushSyncToPeer(peerIdentity(fortress.nodes["mac-1"]), {
      peerUrl: linux1.baseUrl,
      recipientNodeId: "linux-1",
      sessionToken: linuxSession,
      events: macEvents,
      syncHighWater: 1,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // The reciprocal envelope verified (peerNodeId set ⇒ cert-chain checked).
    expect(result.peerNodeId).toBe("linux-1");
    expect(result.reciprocalHighWater).toBeGreaterThan(0);
    const reciprocalAgents = recognizedPortableAgents(result.reciprocalEvents);
    expect(reciprocalAgents.has("agent-on-linux")).toBe(true);
  });

  it("rejects a peer event stamped with a FOREIGN origin_node_id (no node impersonation)", async () => {
    // A legitimately-attested mac-1 cert signs an envelope, but the event inside
    // claims to originate from a node mac-1 has no right to speak for. The
    // origin-binding gate must reject it before any phantom node is minted.
    const linuxSession = await openSession(linux1);
    const mac = fortress.nodes["mac-1"];
    const foreign = makeEvent("victim-node", 1, null);
    const envelope = signSyncEnvelope({
      fortressId: fortress.fortressId,
      senderNodeId: "mac-1",
      recipientNodeId: "linux-1",
      syncHighWater: 1,
      events: [foreign],
      senderNodeCert: mac.nodeCert,
      issuingPrincipalCert: fortress.principalCert,
      nodePrivateKey: Uint8Array.from(mac.nodePrivateKey),
    });
    const res = await postPeer(linux1.baseUrl, linuxSession, envelope);
    expect(res.status).toBe(403);

    // No phantom "victim-node" was minted as a verified node.
    const nodesRes = await fetch(`${linux1.baseUrl}/v1/nodes`, {
      headers: { Authorization: `Bearer ${linuxSession}` },
    });
    const nodes = ((await nodesRes.json()) as { nodes: Array<Record<string, unknown>> }).nodes;
    expect(nodes.find((n) => n.node_id === "victim-node")).toBeUndefined();
  });

  it("does NOT advance the high-water when the appended slice is partially rejected", async () => {
    // A signed envelope at high-water 5 whose events have a sequence gap: the
    // append rejects (previous_hash mismatch), so the high-water must NOT burn —
    // a later correct resend at a lower water must still be accepted.
    const linuxSession = await openSession(linux1);
    const mac = fortress.nodes["mac-1"];
    const e1 = makeEvent("mac-1", 1, null);
    // e2b has a WRONG previous_hash (does not chain to e1) → append rejects it
    // with previous_hash_mismatch, leaving the slice partially rejected.
    const e2b = makeEvent("mac-1", 2, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    const gapped = signSyncEnvelope({
      fortressId: fortress.fortressId,
      senderNodeId: "mac-1",
      recipientNodeId: "linux-1",
      syncHighWater: 5,
      events: [e1, e2b],
      senderNodeCert: mac.nodeCert,
      issuingPrincipalCert: fortress.principalCert,
      nodePrivateKey: Uint8Array.from(mac.nodePrivateKey),
    });
    const gapRes = await postPeer(linux1.baseUrl, linuxSession, gapped);
    expect(gapRes.status).toBe(200);
    const gapBody = (await gapRes.json()) as {
      accepted: string[];
      rejected: Array<{ event_id: string }>;
    };
    expect(gapBody.accepted).toContain("mac-1:1");
    expect(gapBody.rejected.length).toBeGreaterThan(0);

    // Now resend the missing e2 at a LOWER high-water (2). Because the gapped
    // envelope's water-5 was NOT recorded (it had rejections), this is accepted.
    const e2 = makeEvent("mac-1", 2, e1.event_hash);
    const fill = signSyncEnvelope({
      fortressId: fortress.fortressId,
      senderNodeId: "mac-1",
      recipientNodeId: "linux-1",
      syncHighWater: 2,
      events: [e2],
      senderNodeCert: mac.nodeCert,
      issuingPrincipalCert: fortress.principalCert,
      nodePrivateKey: Uint8Array.from(mac.nodePrivateKey),
    });
    const fillRes = await postPeer(linux1.baseUrl, linuxSession, fill);
    expect(fillRes.status).toBe(200);
    const fillBody = (await fillRes.json()) as { accepted: string[] };
    expect(fillBody.accepted).toContain("mac-1:2");
  });

  it("rejects a node from a DIFFERENT fortress (no trust elevation across the operator boundary)", async () => {
    // A whole separate fortress: different master, different operator.
    const stranger = makeMultiNodeFortress(["evil-1"]);
    const linuxSession = await openSession(linux1);

    const strangerEvent = makeEvent("evil-1", 1, null);
    const result = await pushSyncToPeer(peerIdentity(stranger.nodes["evil-1"]), {
      peerUrl: linux1.baseUrl,
      recipientNodeId: "linux-1",
      sessionToken: linuxSession,
      events: [strangerEvent],
      syncHighWater: 1,
    });
    // The cert chains to the stranger's master, not linux-1's pinned master.
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("rejected");

    // Nothing from the stranger landed.
    const nodesRes = await fetch(`${linux1.baseUrl}/v1/nodes`, {
      headers: { Authorization: `Bearer ${linuxSession}` },
    });
    const nodes = ((await nodesRes.json()) as { nodes: Array<Record<string, unknown>> }).nodes;
    expect(nodes.find((n) => n.node_id === "evil-1")).toBeUndefined();
  });

  it("rejects a tampered envelope signature (403, raw HTTP)", async () => {
    const linuxSession = await openSession(linux1);
    const mac = fortress.nodes["mac-1"];
    const event = makeEvent("mac-1", 1, null);
    const envelope = signSyncEnvelope({
      fortressId: fortress.fortressId,
      senderNodeId: "mac-1",
      recipientNodeId: "linux-1",
      syncHighWater: 1,
      events: [event],
      senderNodeCert: mac.nodeCert,
      issuingPrincipalCert: fortress.principalCert,
      nodePrivateKey: Uint8Array.from(mac.nodePrivateKey),
    });
    // Flip a byte in the signature.
    const sigBytes = fromBase64url(envelope.envelope_signature);
    sigBytes[0] ^= 0xff;
    const tampered: FederationSyncEnvelope = {
      ...envelope,
      envelope_signature: toBase64url(sigBytes),
    };
    const res = await postPeer(linux1.baseUrl, linuxSession, tampered);
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden" });
  });

  it("rejects replay/rollback of a whole validly-signed envelope (high-water guard)", async () => {
    const linuxSession = await openSession(linux1);
    const mac = fortress.nodes["mac-1"];
    const e1 = makeEvent("mac-1", 1, null);
    const e2 = makeEvent("mac-1", 2, e1.event_hash);

    // First push at high-water 2 (carries e1, e2).
    const first = signSyncEnvelope({
      fortressId: fortress.fortressId,
      senderNodeId: "mac-1",
      recipientNodeId: "linux-1",
      syncHighWater: 2,
      events: [e1, e2],
      senderNodeCert: mac.nodeCert,
      issuingPrincipalCert: fortress.principalCert,
      nodePrivateKey: Uint8Array.from(mac.nodePrivateKey),
    });
    const firstRes = await postPeer(linux1.baseUrl, linuxSession, first);
    expect(firstRes.status).toBe(200);

    // Replay a STALE but validly-signed envelope at high-water 1 → rollback.
    const stale = signSyncEnvelope({
      fortressId: fortress.fortressId,
      senderNodeId: "mac-1",
      recipientNodeId: "linux-1",
      syncHighWater: 1,
      events: [e1],
      senderNodeCert: mac.nodeCert,
      issuingPrincipalCert: fortress.principalCert,
      nodePrivateKey: Uint8Array.from(mac.nodePrivateKey),
    });
    const staleRes = await postPeer(linux1.baseUrl, linuxSession, stale);
    expect(staleRes.status).toBe(403);

    // Re-presenting the SAME first envelope (same high-water 2) is also rejected.
    const replayRes = await postPeer(linux1.baseUrl, linuxSession, first);
    expect(replayRes.status).toBe(403);
  });

  it("rejects an envelope addressed to the wrong recipient node (no cross-node replay)", async () => {
    const linuxSession = await openSession(linux1);
    const mac = fortress.nodes["mac-1"];
    const event = makeEvent("mac-1", 1, null);
    // Envelope says recipient is mac-1, but we POST it to linux-1.
    const misaddressed = signSyncEnvelope({
      fortressId: fortress.fortressId,
      senderNodeId: "mac-1",
      recipientNodeId: "mac-1",
      syncHighWater: 1,
      events: [event],
      senderNodeCert: mac.nodeCert,
      issuingPrincipalCert: fortress.principalCert,
      nodePrivateKey: Uint8Array.from(mac.nodePrivateKey),
    });
    const res = await postPeer(linux1.baseUrl, linuxSession, misaddressed);
    expect(res.status).toBe(403);
  });

  it("an empty / no-op envelope does NOT burn the per-sender high-water", async () => {
    // codex r2 MEDIUM: a verified peer must not be able to stall future syncs by
    // advancing its high-water with a content-free envelope at a huge value.
    const linuxSession = await openSession(linux1);
    const mac = fortress.nodes["mac-1"];
    const empty = signSyncEnvelope({
      fortressId: fortress.fortressId,
      senderNodeId: "mac-1",
      recipientNodeId: "linux-1",
      syncHighWater: 9999,
      events: [],
      senderNodeCert: mac.nodeCert,
      issuingPrincipalCert: fortress.principalCert,
      nodePrivateKey: Uint8Array.from(mac.nodePrivateKey),
    });
    const emptyRes = await postPeer(linux1.baseUrl, linuxSession, empty);
    expect(emptyRes.status).toBe(200);

    // A subsequent REAL sync at an ordinary low high-water must still be accepted
    // (the high-water was NOT burned to 9999).
    const e1 = makeEvent("mac-1", 1, null);
    const real = signSyncEnvelope({
      fortressId: fortress.fortressId,
      senderNodeId: "mac-1",
      recipientNodeId: "linux-1",
      syncHighWater: 1,
      events: [e1],
      senderNodeCert: mac.nodeCert,
      issuingPrincipalCert: fortress.principalCert,
      nodePrivateKey: Uint8Array.from(mac.nodePrivateKey),
    });
    const realRes = await postPeer(linux1.baseUrl, linuxSession, real);
    expect(realRes.status).toBe(200);
    expect(((await realRes.json()) as { accepted: string[] }).accepted).toContain("mac-1:1");
  });

  it("recognizes only agent.identity (not agent.seen) as a portable identity", async () => {
    // agent.seen is activity telemetry, not an admission of identity. A synced
    // sighting must NOT confer cross-machine recognition.
    const events: FederationEvent[] = [
      makeEvent("mac-1", 1, null), // kind: agent.seen, agent-1
    ];
    const recognized = recognizedPortableAgents(events);
    expect(recognized.size).toBe(0);

    // The same agent, attested via agent.identity, IS recognized.
    mac1.dashboard.recordLocalAgentIdentity("agent-1", undefined);
    const macEvents = (mac1.dashboard as unknown as {
      listFederationEvents(): FederationEvent[];
    }).listFederationEvents();
    const recognized2 = recognizedPortableAgents(macEvents);
    expect(recognized2.has("agent-1")).toBe(true);
  });

  it("requires a /v1 session for /sync/peer (no anonymous network access)", async () => {
    const mac = fortress.nodes["mac-1"];
    const envelope = signSyncEnvelope({
      fortressId: fortress.fortressId,
      senderNodeId: "mac-1",
      recipientNodeId: "linux-1",
      syncHighWater: 1,
      events: [makeEvent("mac-1", 1, null)],
      senderNodeCert: mac.nodeCert,
      issuingPrincipalCert: fortress.principalCert,
      nodePrivateKey: Uint8Array.from(mac.nodePrivateKey),
    });
    const res = await fetch(`${linux1.baseUrl}/v1/federation/sync/peer`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(envelope),
    });
    expect(res.status).toBe(401);
  });
});

// ── helpers ────────────────────────────────────────────────────────────────

async function postPeer(
  baseUrl: string,
  token: string,
  envelope: FederationSyncEnvelope,
): Promise<Response> {
  return fetch(`${baseUrl}/v1/federation/sync/peer`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
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
    occurred_at: `2026-06-13T00:00:0${sequence}.000Z`,
    kind: "agent.seen",
    payload: { agent_id: `agent-${sequence}` },
    previous_hash: previousHash,
  };
  return { ...withoutHash, event_hash: federationEventHash(withoutHash) };
}
