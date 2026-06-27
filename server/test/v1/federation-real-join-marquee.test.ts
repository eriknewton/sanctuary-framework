/**
 * Federation Slice 3c -- REAL-JOIN MARQUEE (in-process).
 *
 * The existing PR-A5 marquee (`federation-marquee.test.ts`) proves the
 * cross-node sync DATA path between two nodes that were handed pre-fabricated
 * ISSUER materials. This test proves the piece that was still build-gated: a
 * REAL end-to-end JOIN, where the second machine holds ONLY a NON-ISSUER joiner
 * trust root it earned from the ceremony.
 *
 * End to end, all keychain-free, all composing production functions:
 *   1. Issuer A is drill-seeded (custody + DEFAULT operator identity + issuer
 *      trust root) and boots federation-enabled.
 *   2. A authorizes a join (operator-signed authorize/init); B assembles +
 *      submits a real JoinRequest; A's ceremony issues B's node certificate.
 *   3. B persists its NON-ISSUER joiner trust root via the joiner store, against
 *      the OUT-OF-BAND pinned master (constraint 4), then BOOTS from that record
 *      into a NON-ISSUER context.
 *   4. B is provisioned NON-ISSUER: no issuer accessors, and authorize/init on B
 *      fails closed (issuer authority unavailable).
 *   5. A and B exchange a `/v1/federation/sync/peer` slice over real HTTP; B's
 *      cert chains to the shared pinned master (cert-chain-verified, no implicit
 *      trust), and an agent attested on A is recognized on B (portable identity).
 *   6. Cross-operator isolation: a DIFFERENT operator's node is rejected (403).
 *
 * HARDWARE-DRILL ACCEPTANCE GATE (deferred, Erik-present): this test proves the
 * real-join protocol on LOOPBACK with two in-process daemons. The capture on
 * physically separate machines remains the deferred drill.
 *
 * The approval gate is supplied by the TEST (`issuerContextWithApprover`), never
 * by the drill seed: the seed composes production functions and injects no
 * approver. Production wires the real principal-policy gate.
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
  pushSyncToPeer,
  recognizedPortableAgents,
  type PeerSyncIdentity,
} from "../../src/v1/federation-client.js";
import {
  type FederationContext,
  type FederationEvent,
  type FederationIssuerContext,
} from "../../src/v1/federation.js";
import {
  loadFederationJoinerTrustRoot,
  persistFederationJoinerTrustRoot,
} from "../../src/mesh/federation-joiner-trust-root-store.js";
import {
  seedFederationIssuerFortress,
  type SeededIssuerFortress,
} from "../util/federation-drill-seed.js";
import {
  buildJoinerCeremonyResult,
  issuerContextWithApprover,
  makeMultiNodeStranger,
} from "./federation-real-join.js";

interface Daemon {
  dashboard: DashboardApprovalChannel;
  baseUrl: string;
  stop(): Promise<void>;
}

const running: Daemon[] = [];

function pickPort(): number {
  return 31000 + Math.floor(Math.random() * 20000);
}

async function startDaemon(
  context: FederationContext,
  opts?: { enable?: boolean },
): Promise<Daemon> {
  const storage = new MemoryStorage();
  const auditLog = new AuditLog(storage, randomBytes(32));
  const port = pickPort();
  const dashboard = new DashboardApprovalChannel({
    port,
    host: "127.0.0.1",
    timeout_seconds: 30,
    auth_token: `realjoin-${randomBytes(6).toString("hex")}`,
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
  dashboard.setFederationContext(context);
  if (opts?.enable) {
    // Flip federation on via the same seam the operator-signed enable verb
    // ultimately drives; the verb's signing is covered by the admin CLI tests.
    (dashboard as unknown as { _federationEnabled: boolean })._federationEnabled = true;
  }
  await dashboard.start();
  const daemon = { dashboard, baseUrl: `http://127.0.0.1:${port}`, stop: () => dashboard.stop() };
  running.push(daemon);
  return daemon;
}

/** Open a loopback /v1 session (network-access gate for /sync/peer + status). */
async function openSession(daemon: Daemon): Promise<string> {
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

let issuerA: SeededIssuerFortress;
let issuerCtx: FederationIssuerContext;
let joinerStorage: MemoryStorage;
let joinerMasterKey: Uint8Array;

beforeEach(async () => {
  joinerStorage = new MemoryStorage();
  issuerA = await seedFederationIssuerFortress({
    storage: new MemoryStorage(),
    passphrase: "marquee-issuer-pw",
    nodeId: "mac-issuer",
  });
  issuerCtx = issuerContextWithApprover(issuerA);
  // The joiner's OWN custody (a SEPARATE operator fortress).
  const { seedCustodyAndOperator } = await import("../util/federation-drill-seed.js");
  const seeded = await seedCustodyAndOperator({
    storage: joinerStorage,
    passphrase: "marquee-joiner-pw",
    operatorLabel: "joiner-operator",
  });
  joinerMasterKey = seeded.masterKey;
});

afterEach(async () => {
  while (running.length > 0) {
    await running.pop()!.stop();
  }
  issuerA.masterKey.fill(0);
  joinerMasterKey.fill(0);
});

describe("Federation Slice 3c real-join marquee (in-process)", () => {
  it("A authorizes -> B joins -> B persists + boots NON-ISSUER -> A and B sync portable identity", async () => {
    // ── 1. Issuer A boots federation-enabled, A authorizes B's join. ──────────
    const issuerDaemon = await startDaemon(issuerCtx, { enable: true });

    // ── 2. Real join ceremony: B submits a JoinRequest, A issues B's cert. ────
    const ceremony = await buildJoinerCeremonyResult(issuerA, "linux-joiner");

    // ── 3. B persists its NON-ISSUER joiner trust root against the OUT-OF-BAND
    //       pinned master, then boots from it. ───────────────────────────────
    await persistFederationJoinerTrustRoot({
      storage: joinerStorage,
      masterKey: joinerMasterKey,
      pinnedMasterPubkey: issuerA.pinnedMaster, // out-of-band trust anchor
      issuingPrincipalCert: ceremony.issuingPrincipalCert,
      localNodeCert: ceremony.certificate,
      localNodePrivateKey: ceremony.localNodePrivateKey,
    });
    ceremony.localNodePrivateKey.fill(0);

    const loaded = await loadFederationJoinerTrustRoot({
      storage: joinerStorage,
      masterKey: joinerMasterKey,
    });
    expect(loaded).not.toBeNull();
    const joinerContext = loaded!.context;

    // ── 4. B is provisioned NON-ISSUER. ───────────────────────────────────────
    const ctxFields = joinerContext as unknown as Record<string, unknown>;
    expect("getIssuingPrincipalPrivateKey" in ctxFields).toBe(false);
    expect("getFortressMasterSecret" in ctxFields).toBe(false);
    expect("getMasterPrivateKey" in ctxFields).toBe(false);
    expect("approver" in ctxFields).toBe(false);

    const joinerDaemon = await startDaemon(joinerContext as FederationContext, { enable: true });
    const joinerSession = await openSession(joinerDaemon);

    // status: provisioned non-issuer.
    const statusRes = await fetch(`${joinerDaemon.baseUrl}/v1/federation/status`, {
      headers: { Authorization: `Bearer ${joinerSession}` },
    });
    expect(statusRes.status).toBe(200);
    const status = (await statusRes.json()) as Record<string, unknown>;
    expect(status).toEqual(
      expect.objectContaining({
        provisioned: true,
        fortress_id: issuerA.fortressId,
        node_id: "linux-joiner",
      }),
    );

    // authorize/init on B fails closed: a non-issuer has no issuer authority.
    // (Even with a forged operator signature, the ceremony structurally cannot
    // mint a token on a non-issuer context: issuerContextOrNull() returns null.)
    const authzRes = await fetch(`${joinerDaemon.baseUrl}/v1/federation/authorize/init`, {
      method: "POST",
      headers: { Authorization: `Bearer ${joinerSession}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        intended_node_id: "x",
        intended_node_mode: "local",
        operator_signature: "AA",
      }),
    });
    expect([403, 503]).toContain(authzRes.status);

    // ── 5. A and B exchange a /sync/peer slice; B recognizes A's portable agent. ─
    // A attests an agent locally -> a portable agent.identity event.
    const agentPubkey = toBase64url(ed25519.getPublicKey(randomBytes(32)));
    issuerDaemon.dashboard.recordLocalAgentIdentity("agent-portable-A", agentPubkey);

    const issuerEvents = (issuerDaemon.dashboard as unknown as {
      listFederationEvents(): FederationEvent[];
    }).listFederationEvents();
    expect(issuerEvents.length).toBeGreaterThanOrEqual(1);

    // Build A's PeerSyncIdentity from its issuer context (it holds its own node
    // cert + key + the shared pinned master).
    const issuerPeer: PeerSyncIdentity = {
      fortressId: issuerA.fortressId,
      nodeId: issuerCtx.nodeId,
      nodeCert: issuerCtx.localNodeCert!,
      issuingPrincipalCert: issuerCtx.issuingPrincipalCert,
      nodePrivateKey: issuerCtx.getLocalNodePrivateKey!()!,
      pinnedMaster: issuerA.pinnedMaster,
    };

    const result = await pushSyncToPeer(issuerPeer, {
      peerUrl: joinerDaemon.baseUrl,
      recipientNodeId: "linux-joiner",
      sessionToken: joinerSession,
      events: issuerEvents,
      syncHighWater: 1,
      isNodeRevoked: () => false,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.acceptedByPeer).toContain("mac-issuer:1");

    // B's unified view: A is now a VERIFIED node, and B recognizes the portable
    // agent without re-minting it.
    const nodesRes = await fetch(`${joinerDaemon.baseUrl}/v1/nodes`, {
      headers: { Authorization: `Bearer ${joinerSession}` },
    });
    const nodesBody = (await nodesRes.json()) as { nodes: Array<Record<string, unknown>> };
    expect(nodesBody.nodes.find((n) => n.node_id === "mac-issuer")?.attestation_status).toBe(
      "verified",
    );

    const joinerEvents = (joinerDaemon.dashboard as unknown as {
      listFederationEvents(): FederationEvent[];
    }).listFederationEvents();
    const recognized = recognizedPortableAgents(joinerEvents);
    expect(recognized.has("agent-portable-A")).toBe(true);
    expect([...(recognized.get("agent-portable-A") ?? [])]).toContain("mac-issuer");
  });

  it("cross-operator isolation: a DIFFERENT operator's node is rejected (403)", async () => {
    // Boot B from a real persisted joiner record.
    const ceremony = await buildJoinerCeremonyResult(issuerA, "linux-joiner");
    await persistFederationJoinerTrustRoot({
      storage: joinerStorage,
      masterKey: joinerMasterKey,
      pinnedMasterPubkey: issuerA.pinnedMaster,
      issuingPrincipalCert: ceremony.issuingPrincipalCert,
      localNodeCert: ceremony.certificate,
      localNodePrivateKey: ceremony.localNodePrivateKey,
    });
    ceremony.localNodePrivateKey.fill(0);
    const loaded = await loadFederationJoinerTrustRoot({
      storage: joinerStorage,
      masterKey: joinerMasterKey,
    });
    const joinerDaemon = await startDaemon(loaded!.context as FederationContext, { enable: true });
    const joinerSession = await openSession(joinerDaemon);

    // A whole separate fortress: different master, different operator.
    const stranger = makeMultiNodeStranger("evil-node");
    const strangerEvent = {
      event_id: "evil-node:1",
      origin_node_id: "evil-node",
      sequence: 1,
      occurred_at: "2026-06-24T00:00:01.000Z",
      kind: "agent.seen",
      payload: { agent_id: "agent-1" },
      previous_hash: null,
    };

    const result = await pushSyncToPeer(stranger.peerIdentity, {
      peerUrl: joinerDaemon.baseUrl,
      recipientNodeId: "linux-joiner",
      sessionToken: joinerSession,
      events: [
        {
          ...strangerEvent,
          event_hash: (
            await import("../../src/v1/federation.js")
          ).federationEventHash(strangerEvent),
        },
      ],
      syncHighWater: 1,
      isNodeRevoked: () => false,
    });
    // The stranger's cert chains to its own master, not B's pinned master.
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("rejected");

    const nodesRes = await fetch(`${joinerDaemon.baseUrl}/v1/nodes`, {
      headers: { Authorization: `Bearer ${joinerSession}` },
    });
    const nodes = ((await nodesRes.json()) as { nodes: Array<Record<string, unknown>> }).nodes;
    expect(nodes.find((n) => n.node_id === "evil-node")).toBeUndefined();
  });
});
