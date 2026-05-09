/**
 * Sanctuary Federation Protocol v0.1 — Policy Update Flow (real-shape integration)
 *
 * End-to-end test of one v0.1 message class (policy_update) over the in-memory
 * transport. Exercises: emitter pack → canonical bytes on wire → receiver
 * verify → router dispatch → handler called with correct payload.
 *
 * This is the contract the libp2p transport adapter (deferred to a follow-up
 * thread) will also need to satisfy. If this test passes here, the crypto path
 * is correct; the libp2p adapter only needs to swap bytes-on-the-wire for
 * bytes-over-the-network.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url } from "../../src/core/encoding.js";
import { randomBytes } from "../../src/core/random.js";
import { CAP_STANDARD_FORTRESS_NODE } from "../../src/mesh/constants.js";
import {
  packSignedEvent,
  verifySignedEvent,
  type VerifyContext,
} from "../../src/mesh/envelope.js";
import {
  generateFortressMaster,
  issueNodeIdentityCertificate,
  issuePrincipalCertificate,
} from "../../src/mesh/trust-root.js";
import { MeshRouter } from "../../src/mesh/router.js";
import { InMemoryTransport } from "../../src/mesh/in-memory-transport.js";
import type {
  NodeIdentityCertificate,
  PolicyUpdatePayload,
  PrincipalCertificate,
  SignedEvent,
} from "../../src/mesh/types.js";

interface Fortress {
  master: ReturnType<typeof generateFortressMaster>;
  principalKeypair: ReturnType<typeof generateKeypair>;
  principalCert: PrincipalCertificate;
}

interface Node {
  id: string;
  keypair: ReturnType<typeof generateKeypair>;
  cert: NodeIdentityCertificate;
}

function buildFortress(): Fortress {
  const master = generateFortressMaster();
  const principalKeypair = generateKeypair();
  const principalCert = issuePrincipalCertificate({
    principal_id: "root",
    principal_pubkey: principalKeypair.publicKey,
    role: "root",
    fortress_id: master.public.fortress_id,
    master_private_key: master.private_key,
  });
  return { master, principalKeypair, principalCert };
}

function addNode(f: Fortress, label: string, mode: "local" | "operator_cloud" | "sovereign_tee"): Node {
  const keypair = generateKeypair();
  const id = `node-${label}-` + toBase64url(randomBytes(3));
  const cert = issueNodeIdentityCertificate({
    node_id: id,
    node_pubkey: keypair.publicKey,
    node_mode: mode,
    fortress_id: f.master.public.fortress_id,
    capabilities: CAP_STANDARD_FORTRESS_NODE,
    parent_chain: {
      fortress_master_pubkey: f.master.public.public_key,
      principal_id: "root",
      principal_pubkey: f.principalCert.principal_pubkey,
    },
    principal_private_key: f.principalKeypair.privateKey,
    master_private_key: f.master.private_key, // v1.x-ready operator: master_signature present
  });
  return { id, keypair, cert };
}

describe("mesh — policy_update distributed across three-mode mesh (§12 criterion 3 shape)", () => {
  it("policy_update signed on console node is verified + dispatched on two peer nodes", async () => {
    const fortress = buildFortress();
    // Console / canonical-audit node runs in local mode.
    const local = addNode(fortress, "local-1", "local");
    const cloud = addNode(fortress, "cloud-1", "operator_cloud");
    const tee = addNode(fortress, "tee-1", "sovereign_tee");

    // Build the roster shared by every node in the mesh.
    const roster = new Map<string, NodeIdentityCertificate>();
    for (const n of [local, cloud, tee]) roster.set(n.id, n.cert);

    const verifyCtx: VerifyContext = {
      pinnedMasterPubkey: fortress.master.public,
      lookupNodeCert: (id) => roster.get(id),
      lookupPrincipalCert: (id) =>
        id === "root" ? fortress.principalCert : undefined,
    };

    // Transport + each node's router.
    const wire = new InMemoryTransport();
    const localT = wire.attach(local.id);
    const cloudT = wire.attach(cloud.id);
    const teeT = wire.attach(tee.id);

    // Each receiving node keeps a per-agent policy version pin.
    const cloudPolicies = new Map<string, PolicyUpdatePayload>();
    const teePolicies = new Map<string, PolicyUpdatePayload>();
    const cloudRouter = new MeshRouter();
    const teeRouter = new MeshRouter();
    cloudRouter.register<PolicyUpdatePayload>("policy_update", (evt) => {
      const p = evt.payload;
      const pinned = cloudPolicies.get(p.agent_id);
      if (!pinned || p.policy_version > pinned.policy_version) {
        cloudPolicies.set(p.agent_id, p);
      }
    });
    teeRouter.register<PolicyUpdatePayload>("policy_update", (evt) => {
      const p = evt.payload;
      const pinned = teePolicies.get(p.agent_id);
      if (!pinned || p.policy_version > pinned.policy_version) {
        teePolicies.set(p.agent_id, p);
      }
    });

    cloudT.subscribe((evt) => {
      const res = verifySignedEvent(evt, verifyCtx);
      expect(res.ok).toBe(true);
      cloudRouter.dispatch(res.event);
    });
    teeT.subscribe((evt) => {
      const res = verifySignedEvent(evt, verifyCtx);
      expect(res.ok).toBe(true);
      teeRouter.dispatch(res.event);
    });

    // Console (local node) authors and broadcasts a policy_update.
    const payload: PolicyUpdatePayload = {
      agent_id: "governed-harness-a",
      policy_version: 1,
      policy_blob: "compiled-policy-bytes-v1",
    };
    const evt = packSignedEvent<PolicyUpdatePayload>({
      event_type: "policy_update",
      emitter_node: local.id,
      emitter_principal: "root",
      fortress_id: fortress.master.public.fortress_id,
      payload,
      monotonic_seq: 1,
      node_private_key: local.keypair.privateKey,
      principal_private_key: fortress.principalKeypair.privateKey,
    });
    await localT.broadcast(evt);

    // Both receiving nodes pinned version 1 for governed-harness-a.
    expect(cloudPolicies.get("governed-harness-a")?.policy_version).toBe(1);
    expect(teePolicies.get("governed-harness-a")?.policy_version).toBe(1);
    expect(cloudRouter.stats().dispatched).toBe(1);
    expect(teeRouter.stats().dispatched).toBe(1);

    // Second policy update: higher version, pins on both.
    const payload2: PolicyUpdatePayload = {
      agent_id: "governed-harness-a",
      policy_version: 2,
      policy_blob: "compiled-policy-bytes-v2",
      parent_version: 1,
    };
    const evt2 = packSignedEvent<PolicyUpdatePayload>({
      event_type: "policy_update",
      emitter_node: local.id,
      emitter_principal: "root",
      fortress_id: fortress.master.public.fortress_id,
      payload: payload2,
      monotonic_seq: 2,
      node_private_key: local.keypair.privateKey,
      principal_private_key: fortress.principalKeypair.privateKey,
    });
    await localT.broadcast(evt2);

    expect(cloudPolicies.get("governed-harness-a")?.policy_version).toBe(2);
    expect(teePolicies.get("governed-harness-a")?.policy_version).toBe(2);
  });

  it("router silently drops reserved-namespace event_type after signature passes (forward-compat §10.3)", async () => {
    const fortress = buildFortress();
    const local = addNode(fortress, "local-1", "local");
    const cloud = addNode(fortress, "cloud-1", "operator_cloud");
    const roster = new Map<string, NodeIdentityCertificate>();
    roster.set(local.id, local.cert);
    roster.set(cloud.id, cloud.cert);

    const verifyCtx: VerifyContext = {
      pinnedMasterPubkey: fortress.master.public,
      lookupNodeCert: (id) => roster.get(id),
      lookupPrincipalCert: (id) =>
        id === "root" ? fortress.principalCert : undefined,
    };

    // Hand-forge a v1.x-era event in the reserved namespace. (packSignedEvent
    // refuses to emit it per hard gate, so we build it manually — simulating
    // a v1.x emitter sending into a v0.1 mesh.)
    const { canonicalizeToBytes } = await import(
      "../../src/mesh/canonical-json.js"
    );
    const { sha256 } = await import("@noble/hashes/sha256");
    const { ed25519 } = await import("@noble/curves/ed25519");

    const v1xPayload = {
      grant_event_id: "grant-123",
      scope: "audit_summary last 24h",
    };
    const v1xPayloadHash = toBase64url(
      sha256(canonicalizeToBytes(v1xPayload))
    );
    const v1xBody = {
      protocol_version: "0.1",
      event_type: "cross_fortress_read_query",
      event_id: toBase64url(randomBytes(16)),
      emitter_node: local.id,
      emitter_principal: "root",
      fortress_id: fortress.master.public.fortress_id,
      causal_parents: [] as string[],
      payload: v1xPayload,
      payload_hash: v1xPayloadHash,
      emitted_at: new Date().toISOString(),
      monotonic_seq: 99,
      extension_envelope: {
        cross_fortress_read_query: { grant_event_id: "grant-123" },
      },
    };
    const bytesToSign = canonicalizeToBytes(v1xBody);
    const nodeSig = ed25519.sign(bytesToSign, local.keypair.privateKey);
    const principalSig = ed25519.sign(
      bytesToSign,
      fortress.principalKeypair.privateKey
    );
    const v1xEvt: SignedEvent = {
      ...v1xBody,
      node_signature: toBase64url(nodeSig),
      principal_signature: toBase64url(principalSig),
    };

    // v0.1 receiver verifies (passes — signature correct, chain valid),
    // but router drops at dispatch because event_type is in reserved namespace.
    const res = verifySignedEvent(v1xEvt, verifyCtx);
    expect(res.ok).toBe(true);
    expect(res.recognized_reserved_extension_keys).toContain("cross_fortress_read_query");

    const router = new MeshRouter();
    let handlerCalled = false;
    // No handler registered for cross_fortress_read_query (it's not even a
    // legal v0.1 event type; register() would throw if we tried).
    const dispatched = router.dispatch(res.event);
    expect(dispatched).toBe(false);
    expect(router.stats().dropped_reserved).toBe(1);
    expect(router.stats().dispatched).toBe(0);
    expect(handlerCalled).toBe(false);
  });
});
