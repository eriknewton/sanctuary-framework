import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";

import { fromBase64url, toBase64url } from "../../src/core/encoding.js";
import {
  ML_DSA_65_COMPONENT_ALG,
  ML_DSA_65_SIGNATURE_BYTES,
} from "../../src/core/crypto-suite-registry.js";
import { CAP_STANDARD_FORTRESS_NODE } from "../../src/mesh/constants.js";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { generateNodeKeypair } from "../../src/mesh/lifecycle/join-approver.js";
import {
  mintHybridFederationMaterial,
  zeroHybridMaterialSecrets,
} from "../../src/mesh/federation-trust-root-store.js";
import {
  issuePrincipalCertificate,
  issueNodeIdentityCertificate,
  verifyCertChain,
} from "../../src/mesh/trust-root.js";
import type { NodeIdentityCertificate } from "../../src/mesh/types.js";
import {
  federationEventHash,
  type FederationEvent,
  JoinCeremony,
} from "../../src/v1/federation.js";
import {
  FEDERATION_SYNC_ENVELOPE_WIRE_VERSION,
  signSyncEnvelope,
  verifySyncEnvelope,
} from "../../src/v1/federation-sync-envelope.js";
import {
  acceptFederationEventsFailClosed,
  FEDERATION_NODE_EVICTION_EVENT_KIND,
  FEDERATION_NODE_EVICTION_EVENT_VERSION,
  FEDERATION_ROOT_REVOCATION_EVENT_KIND,
  FEDERATION_SYNC_WIRE_VERSION,
  federationOperatorAuthorityOrigin,
  foldFederationNodeEvictionEvent,
  normalizeFederationNodeCertificateRenewalConfig,
  renewNodeIdentityCertificateIfDue,
  shouldRenewNodeCertificate,
  signFederationRootRevocationPayloadHybrid,
  signFederationNodeEvictionPayload,
  startFederationNodeCertificateAutoRenewal,
  verifyFederationRootRevocationEvent,
  type FederationNodeEvictionPayload,
  type FederationRevocationLogEvent,
} from "../../src/v1/federation-revocation.js";
import {
  assembleJoinRequest,
  makeFederationMaterials,
  type FedMaterials,
} from "./fed-materials.js";

function issueNode(
  materials: FedMaterials,
  nodeId: string,
  expiresAt?: string,
): { cert: NodeIdentityCertificate; privateKey: Uint8Array } {
  const keypair = generateNodeKeypair();
  const cert = issueNodeIdentityCertificate({
    node_id: nodeId,
    node_pubkey: keypair.publicKey,
    node_mode: "local",
    fortress_id: materials.fortressId,
    capabilities: CAP_STANDARD_FORTRESS_NODE,
    parent_chain: {
      fortress_master_pubkey: materials.context.pinnedMasterPubkey.public_key,
      principal_id: materials.context.issuingPrincipalCert.principal_id,
      principal_pubkey: materials.context.issuingPrincipalCert.principal_pubkey,
    },
    principal_private_key: materials.context.getIssuingPrincipalPrivateKey(),
    master_private_key: materials.context.getMasterPrivateKey?.(),
    expires_at: expiresAt,
  });
  return { cert, privateKey: keypair.privateKey };
}

function makeEvictionEvent(
  materials: FedMaterials,
  payload: FederationNodeEvictionPayload,
  sequence = 1,
  previousHash: string | null = null,
): FederationEvent {
  const origin = federationOperatorAuthorityOrigin(materials.fortressId);
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

function makePeerEvent(
  nodeId: string,
  sequence = 1,
  previousHash: string | null = null,
): FederationEvent {
  const withoutHash = {
    event_id: `${nodeId}:${sequence}`,
    origin_node_id: nodeId,
    sequence,
    occurred_at: `2026-06-20T12:00:0${sequence}.000Z`,
    kind: "agent.seen",
    payload: { agent_id: `agent-${sequence}` },
    previous_hash: previousHash,
  };
  return {
    ...withoutHash,
    event_hash: federationEventHash(withoutHash),
  };
}

function signEviction(
  materials: FedMaterials,
  nodeId: string,
  serial: number,
): FederationNodeEvictionPayload {
  return signFederationNodeEvictionPayload({
    fortressId: materials.fortressId,
    nodeId,
    reason: "operator test eviction",
    effectiveAt: "2026-06-20T12:00:00.000Z",
    evictionSerial: serial,
    operatorPrincipalId: materials.context.issuingPrincipalCert.principal_id,
    operatorPrincipalPrivateKey: materials.context.getIssuingPrincipalPrivateKey(),
  });
}

describe("/v1 federation revocation projection", () => {
  it("grows only from operator-signed eviction events and rejects forged/replayed serials", () => {
    const materials = makeFederationMaterials();
    const projection = { revokedNodeIds: new Set<string>(), highestEvictionSerial: 0 };

    const validPayload = signEviction(materials, "mac-1", 1);
    expect(validPayload.event_version).toBe(FEDERATION_NODE_EVICTION_EVENT_VERSION);
    const first = makeEvictionEvent(materials, validPayload);
    const folded = foldFederationNodeEvictionEvent({
      event: first,
      projection,
      fortressId: materials.fortressId,
      pinnedMaster: materials.context.pinnedMasterPubkey,
      operatorPrincipalCert: materials.context.issuingPrincipalCert,
    });
    expect(folded.ok).toBe(true);
    expect(projection.revokedNodeIds.has("mac-1")).toBe(true);
    expect(projection.highestEvictionSerial).toBe(1);

    const forgedPayload = {
      ...validPayload,
      node_id: "linux-1",
      eviction_serial: 2,
    };
    const forged = makeEvictionEvent(materials, forgedPayload, 2, first.event_hash);
    const forgedFold = foldFederationNodeEvictionEvent({
      event: forged,
      projection,
      fortressId: materials.fortressId,
      pinnedMaster: materials.context.pinnedMasterPubkey,
      operatorPrincipalCert: materials.context.issuingPrincipalCert,
    });
    expect(forgedFold.ok).toBe(false);
    expect(projection.revokedNodeIds.has("linux-1")).toBe(false);

    const replay = makeEvictionEvent(materials, validPayload, 3, first.event_hash);
    const replayFold = foldFederationNodeEvictionEvent({
      event: replay,
      projection,
      fortressId: materials.fortressId,
      pinnedMaster: materials.context.pinnedMasterPubkey,
      operatorPrincipalCert: materials.context.issuingPrincipalCert,
    });
    expect(replayFold.ok).toBe(false);
    if (!replayFold.ok) expect(replayFold.reason).toBe("eviction_serial_replay");
    expect([...projection.revokedNodeIds]).toEqual(["mac-1"]);
  });

  it("rejects unversioned eviction events with a versioned denial", () => {
    const materials = makeFederationMaterials();
    const projection = { revokedNodeIds: new Set<string>(), highestEvictionSerial: 0 };
    const payload = signEviction(materials, "mac-1", 1) as unknown as Record<string, unknown>;
    delete payload.event_version;
    const event = makeEvictionEvent(
      materials,
      payload as unknown as FederationNodeEvictionPayload,
    );

    const folded = foldFederationNodeEvictionEvent({
      event,
      projection,
      fortressId: materials.fortressId,
      pinnedMaster: materials.context.pinnedMasterPubkey,
      operatorPrincipalCert: materials.context.issuingPrincipalCert,
    });

    expect(folded).toEqual({ ok: false, reason: "unsupported_event_version" });
    expect(projection.revokedNodeIds.size).toBe(0);
  });

  it("rejects mismatched eviction event versions with a lockstep denial", () => {
    const materials = makeFederationMaterials();
    const projection = { revokedNodeIds: new Set<string>(), highestEvictionSerial: 0 };
    const payload = {
      ...signEviction(materials, "mac-1", 1),
      event_version: "sanctuary.v0.node-eviction",
    } as unknown as FederationNodeEvictionPayload;
    const event = makeEvictionEvent(materials, payload);

    const folded = foldFederationNodeEvictionEvent({
      event,
      projection,
      fortressId: materials.fortressId,
      pinnedMaster: materials.context.pinnedMasterPubkey,
      operatorPrincipalCert: materials.context.issuingPrincipalCert,
    });

    expect(folded).toEqual({ ok: false, reason: "unsupported_event_version" });
    expect(projection.revokedNodeIds.size).toBe(0);
  });

  it("rejects the whole batch when one eviction has an unsupported event version", () => {
    const materials = makeFederationMaterials();
    const unsupportedPayload = {
      ...signEviction(materials, "mac-1", 1),
      event_version: "sanctuary.v0.node-eviction",
    } as unknown as FederationNodeEvictionPayload;
    const badEviction = makeEvictionEvent(materials, unsupportedPayload);
    const ordinary = makePeerEvent("linux-1");
    const appended: FederationEvent[] = [];

    const accepted = acceptFederationEventsFailClosed({
      events: [badEviction, ordinary],
      fortressId: materials.fortressId,
      wireVersion: FEDERATION_SYNC_WIRE_VERSION,
      senderNodeId: "linux-1",
      isNodeRevoked: () => false,
      appendEvents: (batch) => {
        appended.push(...batch);
        return { accepted: batch, rejected: [] };
      },
    });

    expect(accepted.accepted).toEqual([]);
    expect(accepted.batchRejected).toBe(true);
    expect(accepted.rejected).toEqual([
      { event_id: badEviction.event_id, reason: "unsupported_event_version" },
      { event_id: ordinary.event_id, reason: "unsupported_event_version" },
    ]);
    expect(appended).toEqual([]);
  });

  it("does not leave partial durable state when a combined append fails", () => {
    const materials = makeFederationMaterials();
    const eviction = makeEvictionEvent(materials, signEviction(materials, "mac-1", 1));
    const ordinary = makePeerEvent("linux-1");
    const durable: FederationEvent[] = [];
    let appendCalls = 0;

    const result = acceptFederationEventsFailClosed({
      events: [eviction, ordinary],
      fortressId: materials.fortressId,
      wireVersion: FEDERATION_SYNC_WIRE_VERSION,
      senderNodeId: "linux-1",
      isNodeRevoked: () => false,
      validateEvents: (batch) => ({ accepted: batch, rejected: [] }),
      appendEvents: (batch) => {
        appendCalls += 1;
        const staged = [...durable];
        for (const event of batch) {
          if (event.event_id === ordinary.event_id) {
            throw new Error("simulated durable append failure");
          }
          staged.push(event);
        }
        durable.splice(0, durable.length, ...staged);
        return { accepted: batch, rejected: [] };
      },
    });

    expect(appendCalls).toBe(1);
    expect(result).toEqual({
      accepted: [],
      rejected: [
        { event_id: eviction.event_id, reason: "append_failed" },
        { event_id: ordinary.event_id, reason: "append_failed" },
      ],
      senderRevoked: false,
      revocationStateAvailable: true,
      batchRejected: true,
    });
    expect(durable).toEqual([]);
  });

  it("rejects the whole dashboard batch and preserves state when the state swap fails", async () => {
    const materials = makeFederationMaterials();
    const eviction = makeEvictionEvent(materials, signEviction(materials, "mac-1", 1));
    const ordinary = makePeerEvent("linux-1");
    const dashboard = new DashboardApprovalChannel({
      port: 0,
      host: "127.0.0.1",
      timeout_seconds: 30,
      auto_open: false,
    });
    const dashboardAccess = dashboard as unknown as {
      _federationState: {
        eventLog: FederationEvent[];
        revoked: Set<string>;
        nodes: Map<string, unknown>;
      };
      appendFederationEvents(
        events: FederationEvent[],
        options?: { wireVersion?: unknown; senderNodeId?: string },
      ): {
        accepted: FederationEvent[];
        rejected: Array<{ event_id: string; reason: string }>;
        batchRejected?: boolean;
      };
      listFederationEvents(): FederationEvent[];
    };
    let stateDescriptor: PropertyDescriptor | undefined;

    try {
      dashboard.setFederationContext(materials.context);
      stateDescriptor = Object.getOwnPropertyDescriptor(
        dashboard,
        "_federationState",
      );
      if (stateDescriptor === undefined) {
        throw new Error("missing federation state descriptor");
      }
      const initialState = dashboardAccess._federationState;
      Object.defineProperty(dashboard, "_federationState", {
        configurable: true,
        get: () => initialState,
        set: () => {
          throw new Error("simulated federation state swap failure");
        },
      });

      const result = dashboardAccess.appendFederationEvents([eviction, ordinary], {
        wireVersion: FEDERATION_SYNC_WIRE_VERSION,
        senderNodeId: "linux-1",
      });

      expect(result.accepted).toEqual([]);
      expect(result.batchRejected).toBe(true);
      expect(result.rejected).toEqual([
        { event_id: eviction.event_id, reason: "append_failed" },
        { event_id: ordinary.event_id, reason: "append_failed" },
      ]);
      expect(dashboardAccess.listFederationEvents()).toEqual([]);
      expect(materials.context.isNodeRevoked("mac-1")).toBe(false);
      expect(dashboardAccess._federationState.eventLog).toEqual([]);
      expect(dashboardAccess._federationState.revoked.has("mac-1")).toBe(false);
      expect(dashboardAccess._federationState.nodes.has("linux-1")).toBe(false);
    } finally {
      if (stateDescriptor !== undefined) {
        Object.defineProperty(dashboard, "_federationState", stateDescriptor);
      }
      dashboard.setFederationContext(null);
      await dashboard.stop();
    }
  });

  it("rejects same-batch events from a projected pending eviction before commit", () => {
    const materials = makeFederationMaterials();
    const eviction = makeEvictionEvent(materials, signEviction(materials, "mac-1", 1));
    const ordinary = makePeerEvent("mac-1");
    const durable: FederationEvent[] = [];
    const appendBatches: FederationEvent[][] = [];

    const result = acceptFederationEventsFailClosed({
      events: [eviction, ordinary],
      fortressId: materials.fortressId,
      wireVersion: FEDERATION_SYNC_WIRE_VERSION,
      senderNodeId: "linux-1",
      isNodeRevoked: () => false,
      validateEvents: (batch) => ({ accepted: batch, rejected: [] }),
      appendEvents: (batch) => {
        appendBatches.push(batch);
        durable.push(...batch);
        return { accepted: batch, rejected: [] };
      },
    });

    expect(result).toEqual({
      accepted: [eviction],
      rejected: [{ event_id: ordinary.event_id, reason: "node_revoked" }],
      senderRevoked: false,
      revocationStateAvailable: true,
      batchRejected: false,
    });
    expect(appendBatches).toEqual([[eviction]]);
    expect(durable).toEqual([eviction]);
  });

  it("does not project evictions when dry validation verifier is unavailable", () => {
    const materials = makeFederationMaterials();
    const eviction = makeEvictionEvent(materials, signEviction(materials, "mac-1", 1));
    const ordinary = makePeerEvent("mac-1");
    const durable: FederationEvent[] = [];

    const result = acceptFederationEventsFailClosed({
      events: [eviction, ordinary],
      fortressId: materials.fortressId,
      wireVersion: FEDERATION_SYNC_WIRE_VERSION,
      senderNodeId: "linux-1",
      isNodeRevoked: () => false,
      appendEvents: (batch) => {
        durable.push(...batch);
        return { accepted: batch, rejected: [] };
      },
    });

    expect(result).toEqual({
      accepted: [ordinary],
      rejected: [
        {
          event_id: eviction.event_id,
          reason: "revocation_validation_unavailable",
        },
      ],
      senderRevoked: false,
      revocationStateAvailable: true,
      batchRejected: false,
    });
    expect(result.rejected).not.toContainEqual({
      event_id: ordinary.event_id,
      reason: "node_revoked",
    });
    expect(durable).toEqual([ordinary]);
  });

  it("does not project evictions rejected by dry append validation", () => {
    const materials = makeFederationMaterials();
    const eviction = makeEvictionEvent(materials, signEviction(materials, "mac-1", 1));
    const ordinary = makePeerEvent("mac-1");
    const durable: FederationEvent[] = [];

    const result = acceptFederationEventsFailClosed({
      events: [eviction, ordinary],
      fortressId: materials.fortressId,
      wireVersion: FEDERATION_SYNC_WIRE_VERSION,
      senderNodeId: "linux-1",
      isNodeRevoked: () => false,
      validateEvents: () => ({
        accepted: [],
        rejected: [{ event_id: eviction.event_id, reason: "operator_signature_invalid" }],
      }),
      appendEvents: (batch) => {
        durable.push(...batch);
        return { accepted: batch, rejected: [] };
      },
    });

    expect(result).toEqual({
      accepted: [ordinary],
      rejected: [{ event_id: eviction.event_id, reason: "operator_signature_invalid" }],
      senderRevoked: false,
      revocationStateAvailable: true,
      batchRejected: false,
    });
    expect(durable).toEqual([ordinary]);
  });

  it("accepts current lockstep sync wire version and its peer event", () => {
    const materials = makeFederationMaterials();
    const sender = issueNode(materials, "sender-node");
    const event = makePeerEvent("sender-node");
    const envelope = signSyncEnvelope({
      fortressId: materials.fortressId,
      senderNodeId: "sender-node",
      recipientNodeId: "receiver-node",
      syncHighWater: 1,
      events: [event],
      senderNodeCert: sender.cert,
      issuingPrincipalCert: materials.context.issuingPrincipalCert,
      nodePrivateKey: sender.privateKey,
    });

    expect(envelope.wire_version).toBe(FEDERATION_SYNC_ENVELOPE_WIRE_VERSION);
    const result = verifySyncEnvelope({
      envelope,
      pinnedMaster: materials.context.pinnedMasterPubkey,
      recipientNodeId: "receiver-node",
      acceptedHighWaterFor: () => null,
      isNodeRevoked: () => false,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected current-version envelope to verify");
    expect(result.events.map((accepted) => accepted.event_id)).toEqual([event.event_id]);
  });

  it("rejects peer sync envelopes on a mismatched lockstep wire version", () => {
    const materials = makeFederationMaterials();
    const sender = issueNode(materials, "sender-node");
    const event = makePeerEvent("sender-node");
    const envelope = signSyncEnvelope({
      fortressId: materials.fortressId,
      senderNodeId: "sender-node",
      recipientNodeId: "receiver-node",
      syncHighWater: 1,
      events: [event],
      senderNodeCert: sender.cert,
      issuingPrincipalCert: materials.context.issuingPrincipalCert,
      nodePrivateKey: sender.privateKey,
    });
    const mismatched = {
      ...envelope,
      wire_version: "sanctuary.v0.federation-sync-envelope",
    };

    const result = verifySyncEnvelope({
      envelope: mismatched,
      pinnedMaster: materials.context.pinnedMasterPubkey,
      recipientNodeId: "receiver-node",
      acceptedHighWaterFor: () => null,
      isNodeRevoked: () => false,
    });

    expect(result).toEqual({ ok: false, reason: "unsupported_wire_version" });
  });

  it("denies an operator-revoked node on sync and join", async () => {
    const materials = makeFederationMaterials();
    const projection = { revokedNodeIds: new Set<string>(), highestEvictionSerial: 0 };
    const eviction = makeEvictionEvent(materials, signEviction(materials, "mac-1", 1));
    const folded = foldFederationNodeEvictionEvent({
      event: eviction,
      projection,
      fortressId: materials.fortressId,
      pinnedMaster: materials.context.pinnedMasterPubkey,
      operatorPrincipalCert: materials.context.issuingPrincipalCert,
    });
    expect(folded.ok).toBe(true);

    const mac = issueNode(materials, "mac-1");
    const envelope = signSyncEnvelope({
      fortressId: materials.fortressId,
      senderNodeId: "mac-1",
      recipientNodeId: "linux-1",
      syncHighWater: 1,
      events: [],
      senderNodeCert: mac.cert,
      issuingPrincipalCert: materials.context.issuingPrincipalCert,
      nodePrivateKey: mac.privateKey,
    });
    const sync = verifySyncEnvelope({
      envelope,
      pinnedMaster: materials.context.pinnedMasterPubkey,
      recipientNodeId: "linux-1",
      acceptedHighWaterFor: () => null,
      isNodeRevoked: (nodeId) => projection.revokedNodeIds.has(nodeId),
    });
    expect(sync).toEqual({ ok: false, reason: "node_revoked" });

    materials.context.isNodeRevoked = (nodeId) => projection.revokedNodeIds.has(nodeId);
    const ceremony = new JoinCeremony(materials.context);
    const token = ceremony.authorizeInit({
      intendedNodeId: "mac-1",
      intendedNodeMode: "local",
    });
    const assembled = assembleJoinRequest({
      bootstrapToken: token,
      fortressMasterSecret: materials.masterSecret,
    });
    const join = await ceremony.authorizeComplete(assembled.joinRequest);
    expect(join.approved).toBe(false);
    if (!join.approved) expect(join.denialReason).toMatch(/revoked/);
  });

  it("reprojects revocation from the event log after federation context rebind", async () => {
    const materials = makeFederationMaterials();
    const dashboard = new DashboardApprovalChannel({
      port: 0,
      host: "127.0.0.1",
      timeout_seconds: 30,
      auto_open: false,
    });
    try {
      dashboard.setFederationContext(materials.context);
      const eviction = makeEvictionEvent(materials, signEviction(materials, "mac-1", 1));
      const append = (dashboard as unknown as {
        appendFederationEvents(
          events: FederationEvent[],
          options?: { wireVersion?: unknown },
        ): {
          accepted: FederationEvent[];
          rejected: Array<{ event_id: string; reason: string }>;
        };
      }).appendFederationEvents([eviction], {
        wireVersion: FEDERATION_SYNC_WIRE_VERSION,
      });
      expect(append.accepted.map((event) => event.event_id)).toEqual([eviction.event_id]);
      expect(materials.context.isNodeRevoked?.("mac-1")).toBe(true);

      dashboard.setFederationContext(null);
      expect(materials.context.isNodeRevoked?.("mac-1")).toBe(false);
      dashboard.setFederationContext(materials.context);
      expect(materials.context.isNodeRevoked?.("mac-1")).toBe(true);

      const mac = issueNode(materials, "mac-1");
      const envelope = signSyncEnvelope({
        fortressId: materials.fortressId,
        senderNodeId: "mac-1",
        recipientNodeId: "linux-1",
        syncHighWater: 1,
        events: [],
        senderNodeCert: mac.cert,
        issuingPrincipalCert: materials.context.issuingPrincipalCert,
        nodePrivateKey: mac.privateKey,
      });
      const sync = verifySyncEnvelope({
        envelope,
        pinnedMaster: materials.context.pinnedMasterPubkey,
        recipientNodeId: "linux-1",
        acceptedHighWaterFor: () => null,
        isNodeRevoked: (nodeId) => materials.context.isNodeRevoked?.(nodeId) ?? false,
      });
      expect(sync).toEqual({ ok: false, reason: "node_revoked" });

      const ceremony = new JoinCeremony(materials.context);
      const token = ceremony.authorizeInit({
        intendedNodeId: "mac-1",
        intendedNodeMode: "local",
      });
      const assembled = assembleJoinRequest({
        bootstrapToken: token,
        fortressMasterSecret: materials.masterSecret,
      });
      const join = await ceremony.authorizeComplete(assembled.joinRequest);
      expect(join.approved).toBe(false);
      if (!join.approved) expect(join.denialReason).toMatch(/revoked/);
    } finally {
      dashboard.setFederationContext(null);
      await dashboard.stop();
    }
  });

  it("keeps accepted evictions revoked after principal-certificate rotation and rebind", async () => {
    const materials = makeFederationMaterials();
    const dashboard = new DashboardApprovalChannel({
      port: 0,
      host: "127.0.0.1",
      timeout_seconds: 30,
      auto_open: false,
    });
    try {
      dashboard.setFederationContext(materials.context);
      const eviction = makeEvictionEvent(materials, signEviction(materials, "mac-1", 1));
      const append = (dashboard as unknown as {
        appendFederationEvents(
          events: FederationEvent[],
          options?: { wireVersion?: unknown },
        ): {
          accepted: FederationEvent[];
          rejected: Array<{ event_id: string; reason: string }>;
        };
      }).appendFederationEvents([eviction], {
        wireVersion: FEDERATION_SYNC_WIRE_VERSION,
      });
      expect(append.accepted.map((event) => event.event_id)).toEqual([eviction.event_id]);
      expect(materials.context.isNodeRevoked("mac-1")).toBe(true);

      const rotatedPrincipalPrivateKey = randomBytes(32);
      const rotatedPrincipalPubkey = ed25519.getPublicKey(rotatedPrincipalPrivateKey);
      const masterPrivateKey = materials.context.getMasterPrivateKey?.();
      if (!masterPrivateKey) throw new Error("test materials missing master private key");
      const rotatedContext = {
        ...materials.context,
        issuingPrincipalCert: issuePrincipalCertificate({
          principal_id: "principal-rotated",
          principal_pubkey: rotatedPrincipalPubkey,
          role: "Root",
          fortress_id: materials.fortressId,
          master_private_key: masterPrivateKey,
        }),
        getIssuingPrincipalPrivateKey: () => rotatedPrincipalPrivateKey,
        isNodeRevoked: () => false,
      };

      dashboard.setFederationContext(rotatedContext);

      expect(rotatedContext.isNodeRevoked("mac-1")).toBe(true);
    } finally {
      dashboard.setFederationContext(null);
      await dashboard.stop();
    }
  });
});

describe("/v1 federation expiry and renewal", () => {
  it("rejects renewal config whose check interval can skip the lead window", () => {
    expect(() =>
      normalizeFederationNodeCertificateRenewalConfig({
        certLifetimeMs: 10_000,
        renewalLeadMs: 1_000,
        renewalGraceMs: 1_000,
        renewalCheckIntervalMs: 1_001,
      }),
    ).toThrow(/renewalCheckIntervalMs/);
  });

  it("renews an accepted-config local cert on the lead-boundary tick before lapse", () => {
    const startsAt = Date.parse("2026-06-20T12:00:00.000Z");
    let now = startsAt + 500;
    const materials = makeFederationMaterials();
    const expiring = issueNode(
      materials,
      "lead-boundary-node",
      new Date(startsAt + 1_000).toISOString(),
    );
    const config = normalizeFederationNodeCertificateRenewalConfig({
      now: () => now,
      certLifetimeMs: 10_000,
      renewalLeadMs: 500,
      renewalGraceMs: 100,
      renewalCheckIntervalMs: 500,
    });

    const renewal = renewNodeIdentityCertificateIfDue({
      certificate: expiring.cert,
      localNodeId: "lead-boundary-node",
      pinnedMaster: materials.context.pinnedMasterPubkey,
      operatorPrincipalCert: materials.context.issuingPrincipalCert,
      operatorPrincipalPrivateKey: materials.context.getIssuingPrincipalPrivateKey(),
      masterPrivateKey: materials.context.getMasterPrivateKey?.(),
      isNodeRevoked: () => false,
      config,
    });

    expect(renewal.renewed).toBe(true);
    if (!renewal.renewed) throw new Error("expected renewal");
    now = startsAt + 1_001;
    expect(() =>
      verifyCertChain(
        expiring.cert,
        materials.context.issuingPrincipalCert,
        materials.context.pinnedMasterPubkey,
        now,
      ),
    ).toThrow();
    expect(() =>
      verifyCertChain(
        renewal.certificate,
        materials.context.issuingPrincipalCert,
        materials.context.pinnedMasterPubkey,
        now,
      ),
    ).not.toThrow();
  });

  it("never evicts a live node when manual renewal was forgotten but automatic renewal ran", () => {
    const now = Date.parse("2026-06-20T12:00:00.000Z");
    const materials = makeFederationMaterials();
    const expiring = issueNode(
      materials,
      "live-node",
      new Date(now + 1_000).toISOString(),
    );
    const renewal = renewNodeIdentityCertificateIfDue({
      certificate: expiring.cert,
      localNodeId: "live-node",
      pinnedMaster: materials.context.pinnedMasterPubkey,
      operatorPrincipalCert: materials.context.issuingPrincipalCert,
      operatorPrincipalPrivateKey: materials.context.getIssuingPrincipalPrivateKey(),
      masterPrivateKey: materials.context.getMasterPrivateKey?.(),
      isNodeRevoked: () => false,
      config: {
        now: () => now,
        certLifetimeMs: 10_000,
        renewalLeadMs: 2_000,
        renewalGraceMs: 1_000,
        renewalCheckIntervalMs: 100,
      },
    });
    expect(renewal.renewed).toBe(true);
    if (!renewal.renewed) throw new Error("expected renewal");

    const afterOriginalExpiry = now + 1_500;
    expect(() =>
      verifyCertChain(
        expiring.cert,
        materials.context.issuingPrincipalCert,
        materials.context.pinnedMasterPubkey,
        afterOriginalExpiry,
      ),
    ).toThrow();
    expect(() =>
      verifyCertChain(
        renewal.certificate,
        materials.context.issuingPrincipalCert,
        materials.context.pinnedMasterPubkey,
        afterOriginalExpiry,
      ),
    ).not.toThrow();
  });

  it("does not renew an expired-beyond-grace remote node and expiry denies sync", () => {
    const now = Date.now();
    const materials = makeFederationMaterials();
    const expiredRemote = issueNode(
      materials,
      "remote-gone",
      new Date(now - 60_000).toISOString(),
    );

    const renewal = renewNodeIdentityCertificateIfDue({
      certificate: expiredRemote.cert,
      localNodeId: "local-present-node",
      pinnedMaster: materials.context.pinnedMasterPubkey,
      operatorPrincipalCert: materials.context.issuingPrincipalCert,
      operatorPrincipalPrivateKey: materials.context.getIssuingPrincipalPrivateKey(),
      masterPrivateKey: materials.context.getMasterPrivateKey?.(),
      isNodeRevoked: () => false,
      config: {
        now: () => now,
        certLifetimeMs: 10_000,
        renewalLeadMs: 2_000,
        renewalGraceMs: 1_000,
        renewalCheckIntervalMs: 100,
      },
    });
    expect(renewal).toEqual({
      renewed: false,
      certificate: expiredRemote.cert,
      reason: "not_local_node",
    });

    const envelope = signSyncEnvelope({
      fortressId: materials.fortressId,
      senderNodeId: "remote-gone",
      recipientNodeId: "receiver-node",
      syncHighWater: 1,
      events: [],
      senderNodeCert: expiredRemote.cert,
      issuingPrincipalCert: materials.context.issuingPrincipalCert,
      nodePrivateKey: expiredRemote.privateKey,
    });
    const result = verifySyncEnvelope({
      envelope,
      pinnedMaster: materials.context.pinnedMasterPubkey,
      recipientNodeId: "receiver-node",
      acceptedHighWaterFor: () => null,
      isNodeRevoked: () => false,
    });
    expect(result).toEqual({ ok: false, reason: "cert_chain_invalid" });
  });

  it("does not renew a far-future local cert on every tick", () => {
    const now = Date.parse("2026-06-20T12:00:00.000Z");
    const materials = makeFederationMaterials();
    const farFuture = issueNode(
      materials,
      "future-node",
      new Date(now + 60_000).toISOString(),
    );
    const config = {
      now: () => now,
      certLifetimeMs: 120_000,
      renewalLeadMs: 2_000,
      renewalGraceMs: 1_000,
      renewalCheckIntervalMs: 100,
    };

    expect(shouldRenewNodeCertificate(farFuture.cert, config)).toBe(false);
    const renewal = renewNodeIdentityCertificateIfDue({
      certificate: farFuture.cert,
      localNodeId: "future-node",
      pinnedMaster: materials.context.pinnedMasterPubkey,
      operatorPrincipalCert: materials.context.issuingPrincipalCert,
      operatorPrincipalPrivateKey: materials.context.getIssuingPrincipalPrivateKey(),
      masterPrivateKey: materials.context.getMasterPrivateKey?.(),
      isNodeRevoked: () => false,
      config,
    });
    expect(renewal).toEqual({
      renewed: false,
      certificate: farFuture.cert,
      reason: "not_due",
    });
  });

  it("denies an expired node when automatic renewal is disabled or failed", () => {
    const materials = makeFederationMaterials();
    const expired = issueNode(
      materials,
      "expired-node",
      new Date(Date.now() - 60_000).toISOString(),
    );
    const envelope = signSyncEnvelope({
      fortressId: materials.fortressId,
      senderNodeId: "expired-node",
      recipientNodeId: "receiver-node",
      syncHighWater: 1,
      events: [],
      senderNodeCert: expired.cert,
      issuingPrincipalCert: materials.context.issuingPrincipalCert,
      nodePrivateKey: expired.privateKey,
    });
    const result = verifySyncEnvelope({
      envelope,
      pinnedMaster: materials.context.pinnedMasterPubkey,
      recipientNodeId: "receiver-node",
      acceptedHighWaterFor: () => null,
      isNodeRevoked: () => false,
    });
    expect(result).toEqual({ ok: false, reason: "cert_chain_invalid" });
  });

  it("legacy node certs without expires_at still verify and federate", () => {
    const materials = makeFederationMaterials();
    const legacy = issueNode(materials, "legacy-node");
    expect(legacy.cert.expires_at).toBeUndefined();
    const envelope = signSyncEnvelope({
      fortressId: materials.fortressId,
      senderNodeId: "legacy-node",
      recipientNodeId: "receiver-node",
      syncHighWater: 1,
      events: [],
      senderNodeCert: legacy.cert,
      issuingPrincipalCert: materials.context.issuingPrincipalCert,
      nodePrivateKey: legacy.privateKey,
    });
    const result = verifySyncEnvelope({
      envelope,
      pinnedMaster: materials.context.pinnedMasterPubkey,
      recipientNodeId: "receiver-node",
      acceptedHighWaterFor: () => null,
      isNodeRevoked: () => false,
    });
    expect(result.ok).toBe(true);
  });

  it("exposes an injectable scheduled renewal seam", async () => {
    let ticks = 0;
    let captured: (() => void) | null = null;
    const handle = startFederationNodeCertificateAutoRenewal({
      renewNow: () => {
        ticks += 1;
      },
      config: {
        certLifetimeMs: 10_000,
        renewalLeadMs: 1_000,
        renewalGraceMs: 1_000,
        renewalCheckIntervalMs: 50,
      },
      setIntervalFn: ((fn: () => void) => {
        captured = fn;
        return { unref() {} } as NodeJS.Timeout;
      }) as typeof setInterval,
      clearIntervalFn: (() => {}) as typeof clearInterval,
    });
    await handle.tick();
    captured?.();
    expect(ticks).toBeGreaterThanOrEqual(2);
    handle.stop();
  });
});

describe("/v1 federation root revocation hybrid verification", () => {
  it("rejects a structurally valid hybrid bundle with a corrupted ML-DSA signature", async () => {
    const materials = makeFederationMaterials();
    const principalPrivateKey = materials.context.getIssuingPrincipalPrivateKey();
    const hybrid = await mintHybridFederationMaterial({
      fortressId: materials.fortressId,
      nodeId: materials.context.nodeId,
      principalId: materials.context.issuingPrincipalCert.principal_id,
    });
    try {
      const revokedHybrid = {
        ed25519: {
          key_ref: hybrid.pinned_master.public_keys.ed25519.key_ref,
          public_key: hybrid.pinned_master.public_keys.ed25519.public_key,
        },
        ml_dsa_65: {
          key_ref: hybrid.pinned_master.public_keys.ml_dsa_65.key_ref,
          public_key: hybrid.pinned_master.public_keys.ml_dsa_65.public_key,
        },
      };
      const payload = await signFederationRootRevocationPayloadHybrid({
        fortressId: materials.fortressId,
        revokedMasterPubkey: "old-root-k1",
        revokedHybrid,
        effectiveAt: "2026-06-20T12:00:00.000Z",
        revocationSerial: 1,
        operatorPrincipalId: materials.context.issuingPrincipalCert.principal_id,
        newClassicalPrincipalPrivateKey: principalPrivateKey,
        newHybridPrincipalPrivateKeys: hybrid.issuing_principal_private_keys,
      });
      const eventForPayload = (
        eventPayload: Record<string, unknown>,
      ): FederationRevocationLogEvent => {
        const origin = federationOperatorAuthorityOrigin(materials.fortressId);
        const withoutHash = {
          event_id: `${origin}:1`,
          origin_node_id: origin,
          sequence: 1,
          occurred_at: "2026-06-20T12:00:00.000Z",
          kind: FEDERATION_ROOT_REVOCATION_EVENT_KIND,
          payload: eventPayload,
          previous_hash: null,
        };
        return {
          ...withoutHash,
          event_hash: federationEventHash(withoutHash),
        };
      };

      const valid = await verifyFederationRootRevocationEvent({
        event: eventForPayload({ ...payload }),
        fortressId: materials.fortressId,
        pinnedMaster: materials.context.pinnedMasterPubkey,
        operatorPrincipalCert: materials.context.issuingPrincipalCert,
        operatorHybridPrincipalPublicKeys:
          hybrid.issuing_principal_cert.principal_public_keys,
        highestRevocationSerial: 0,
      });
      expect(valid.ok).toBe(true);

      const bundle = payload.operator_signature_bundle;
      expect(bundle).toBeDefined();
      if (bundle === undefined) throw new Error("expected hybrid bundle");
      const components = bundle.components.map((component) => ({ ...component }));
      const mlDsaIndex = components.findIndex(
        (component) => component.alg === ML_DSA_65_COMPONENT_ALG,
      );
      expect(mlDsaIndex).toBe(1);
      const mlDsaSignature = fromBase64url(components[mlDsaIndex]!.sig);
      expect(mlDsaSignature.length).toBe(ML_DSA_65_SIGNATURE_BYTES);
      mlDsaSignature[0] ^= 0x01;
      components[mlDsaIndex] = {
        ...components[mlDsaIndex]!,
        sig: toBase64url(mlDsaSignature),
      };

      const rejected = await verifyFederationRootRevocationEvent({
        event: eventForPayload({
          ...payload,
          operator_signature_bundle: {
            ...bundle,
            components,
          },
        }),
        fortressId: materials.fortressId,
        pinnedMaster: materials.context.pinnedMasterPubkey,
        operatorPrincipalCert: materials.context.issuingPrincipalCert,
        operatorHybridPrincipalPublicKeys:
          hybrid.issuing_principal_cert.principal_public_keys,
        highestRevocationSerial: 0,
      });
      expect(rejected.ok).toBe(false);
      if (!rejected.ok) {
        expect(rejected.reason).toBe("operator_signature_bundle_invalid");
      }
    } finally {
      principalPrivateKey.fill(0);
      zeroHybridMaterialSecrets(hybrid);
    }
  });
});

describe("/v1 federation fail-closed revocation state", () => {
  it("denies sync when the revocation evaluator is absent", () => {
    const materials = makeFederationMaterials();
    const sender = issueNode(materials, "sender-node");
    const envelope = signSyncEnvelope({
      fortressId: materials.fortressId,
      senderNodeId: "sender-node",
      recipientNodeId: "receiver-node",
      syncHighWater: 1,
      events: [],
      senderNodeCert: sender.cert,
      issuingPrincipalCert: materials.context.issuingPrincipalCert,
      nodePrivateKey: sender.privateKey,
    });
    const result = verifySyncEnvelope({
      envelope,
      pinnedMaster: materials.context.pinnedMasterPubkey,
      recipientNodeId: "receiver-node",
      acceptedHighWaterFor: () => null,
    } as Parameters<typeof verifySyncEnvelope>[0]);
    expect(result).toEqual({
      ok: false,
      reason: "revocation_state_unavailable",
    });
  });

  it("denies sync when revocation state cannot be evaluated", () => {
    const materials = makeFederationMaterials();
    const sender = issueNode(materials, "sender-node");
    const envelope = signSyncEnvelope({
      fortressId: materials.fortressId,
      senderNodeId: "sender-node",
      recipientNodeId: "receiver-node",
      syncHighWater: 1,
      events: [],
      senderNodeCert: sender.cert,
      issuingPrincipalCert: materials.context.issuingPrincipalCert,
      nodePrivateKey: sender.privateKey,
    });
    const result = verifySyncEnvelope({
      envelope,
      pinnedMaster: materials.context.pinnedMasterPubkey,
      recipientNodeId: "receiver-node",
      acceptedHighWaterFor: () => null,
      isNodeRevoked: () => {
        throw new Error("revocation store unavailable");
      },
    });
    expect(result).toEqual({
      ok: false,
      reason: "revocation_state_unavailable",
    });
  });

  it("denies join when the revocation evaluator is absent", async () => {
    const materials = makeFederationMaterials();
    const unsafeContext = { ...materials.context } as Partial<typeof materials.context>;
    delete unsafeContext.isNodeRevoked;
    const ceremony = new JoinCeremony(unsafeContext as typeof materials.context);
    const token = ceremony.authorizeInit({
      intendedNodeId: "joining-node",
      intendedNodeMode: "local",
    });
    const assembled = assembleJoinRequest({
      bootstrapToken: token,
      fortressMasterSecret: materials.masterSecret,
    });

    const result = await ceremony.authorizeComplete(assembled.joinRequest);

    expect(result.approved).toBe(false);
    if (!result.approved) {
      expect(result.denialReason).toBe("revocation state unavailable");
    }
  });

  it("denies join when revocation state cannot be evaluated", async () => {
    const materials = makeFederationMaterials();
    materials.context.isNodeRevoked = () => {
      throw new Error("revocation store unavailable");
    };
    const ceremony = new JoinCeremony(materials.context);
    const token = ceremony.authorizeInit({
      intendedNodeId: "joining-node",
      intendedNodeMode: "local",
    });
    const assembled = assembleJoinRequest({
      bootstrapToken: token,
      fortressMasterSecret: materials.masterSecret,
    });
    const result = await ceremony.authorizeComplete(assembled.joinRequest);
    expect(result.approved).toBe(false);
    if (!result.approved) {
      expect(result.denialReason).toBe("revocation state unavailable");
    }
  });
});
