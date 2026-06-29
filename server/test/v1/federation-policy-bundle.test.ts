import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";

import { fromBase64url, toBase64url } from "../../src/core/encoding.js";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import {
  FederationSyncStateStore,
} from "../../src/v1/federation-sync-state-store.js";
import {
  federationEventHash,
  type FederationEvent,
  type V1FederationDeps,
} from "../../src/v1/federation.js";
import {
  FEDERATION_SYNC_WIRE_VERSION,
  federationOperatorAuthorityOrigin,
} from "../../src/v1/federation-revocation.js";
import {
  FEDERATION_POLICY_BUNDLE_EVENT_KIND,
  foldFederationPolicyBundleEvent,
  signFederationPolicyBundlePayload,
  verifyFederationPolicyBundleEvent,
  type FederationPolicyProjection,
  type FederationPolicyBundleRejectionReason,
} from "../../src/v1/federation-policy-bundle.js";
import { makeFederationMaterials, type FedMaterials } from "./fed-materials.js";

type DepsAccess = DashboardApprovalChannel & {
  buildV1FederationDeps(): V1FederationDeps;
  _federationEnabled: boolean;
};

const POLICY_HASH_V7 = "a".repeat(43);
const POLICY_HASH_V8 = "b".repeat(43);

function makePolicyEvent(
  materials: FedMaterials,
  params: {
    version: number;
    hash: string;
    sequence?: number;
    previousHash?: string | null;
  },
): FederationEvent {
  const sequence = params.sequence ?? 1;
  const origin = federationOperatorAuthorityOrigin(materials.fortressId);
  const occurredAt = `2026-06-27T12:00:0${sequence}.000Z`;
  const payload = signFederationPolicyBundlePayload({
    fortressId: materials.fortressId,
    policyVersion: params.version,
    policyHash: params.hash,
    signedAt: occurredAt,
    operatorPrincipalId: materials.context.issuingPrincipalCert.principal_id,
    operatorPrincipalPrivateKey: materials.context.getIssuingPrincipalPrivateKey(),
  });
  const body = {
    event_id: `${origin}:${sequence}`,
    origin_node_id: origin,
    sequence,
    occurred_at: occurredAt,
    kind: FEDERATION_POLICY_BUNDLE_EVENT_KIND,
    payload: payload as unknown as Record<string, unknown>,
    previous_hash: params.previousHash ?? null,
  };
  return { ...body, event_hash: federationEventHash(body) };
}

function withTamperedPayload(
  event: FederationEvent,
  patch: Record<string, unknown>,
): FederationEvent {
  const body = {
    event_id: event.event_id,
    origin_node_id: event.origin_node_id,
    sequence: event.sequence,
    occurred_at: event.occurred_at,
    kind: event.kind,
    payload: { ...event.payload, ...patch },
    previous_hash: event.previous_hash,
  };
  return { ...body, event_hash: federationEventHash(body) };
}

function withInvalidPrincipalChain(materials: FedMaterials): FedMaterials {
  const signature = fromBase64url(
    materials.context.issuingPrincipalCert.master_signature,
  );
  const invalidSignature = new Uint8Array(signature);
  invalidSignature[0] ^= 1;
  return {
    ...materials,
    context: {
      ...materials.context,
      issuingPrincipalCert: {
        ...materials.context.issuingPrincipalCert,
        master_signature: toBase64url(invalidSignature),
      },
    },
  };
}

async function buildDashboard(
  materials: FedMaterials,
  storage: MemoryStorage,
  masterKey: Uint8Array,
): Promise<{ dashboard: DepsAccess; deps: V1FederationDeps }> {
  const auditLog = new AuditLog(storage, randomBytes(32));
  const dashboard = new DashboardApprovalChannel({
    port: 0,
    host: "127.0.0.1",
    timeout_seconds: 30,
    auth_token: "test",
    auto_open: false,
  }) as DepsAccess;
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
  dashboard.setFederationContext(materials.context);
  dashboard._federationEnabled = true;
  await dashboard.setFederationSyncStateStore(
    new FederationSyncStateStore({ storage, masterKey }),
  );
  return { dashboard, deps: dashboard.buildV1FederationDeps() };
}

function appliedPolicySnapshot(deps: V1FederationDeps, nodeId: string) {
  return deps.listNodes().find((node) => node.node_id === nodeId)
    ?.applied_policy ?? null;
}

async function storedPolicySnapshot(
  storage: MemoryStorage,
  masterKey: Uint8Array,
  nodeId: string,
) {
  const snapshot = await new FederationSyncStateStore({
    storage,
    masterKey,
  }).load();
  return {
    operatorPolicy: snapshot.operatorPolicy
      ? {
          version: snapshot.operatorPolicy.version,
          hash: snapshot.operatorPolicy.hash,
          source_event_id: snapshot.operatorPolicy.source_event_id,
        }
      : null,
    nodePolicy: snapshot.appliedPolicyVersions.get(nodeId)
      ? {
          version: snapshot.appliedPolicyVersions.get(nodeId)?.version,
          hash: snapshot.appliedPolicyVersions.get(nodeId)?.hash,
          source_event_id: snapshot.appliedPolicyVersions.get(nodeId)
            ?.source_event_id,
        }
      : null,
  };
}

async function expectRejectedPolicyBundleDoesNotAdvance(params: {
  materials: FedMaterials;
  event: FederationEvent;
  reason: FederationPolicyBundleRejectionReason;
  currentPolicyVersion?: number | null;
  priorEvent?: FederationEvent;
}) {
  const verification = verifyFederationPolicyBundleEvent({
    event: params.event,
    fortressId: params.materials.fortressId,
    pinnedMaster: params.materials.context.pinnedMasterPubkey,
    operatorPrincipalCert: params.materials.context.issuingPrincipalCert,
    currentPolicyVersion: params.currentPolicyVersion ?? null,
  });

  expect(verification).toEqual({
    ok: false,
    reason: params.reason,
  });

  const storage = new MemoryStorage();
  const masterKey = new Uint8Array(32).fill(9);
  const { deps } = await buildDashboard(params.materials, storage, masterKey);

  if (params.priorEvent) {
    const accepted = await deps.appendFederationEvents([params.priorEvent], {
      senderNodeId: params.priorEvent.origin_node_id,
      wireVersion: FEDERATION_SYNC_WIRE_VERSION,
    });
    expect(accepted.rejected).toEqual([]);
    expect(accepted.accepted.map((event) => event.event_id)).toEqual([
      params.priorEvent.event_id,
    ]);
  }

  const beforeEventIds = deps
    .listFederationEvents()
    .map((event) => event.event_id);
  const beforeAppliedPolicy = appliedPolicySnapshot(
    deps,
    params.materials.context.nodeId,
  );
  const beforeStoredPolicy = await storedPolicySnapshot(
    storage,
    masterKey,
    params.materials.context.nodeId,
  );

  const rejected = await deps.appendFederationEvents([params.event], {
    senderNodeId: params.event.origin_node_id,
    wireVersion: FEDERATION_SYNC_WIRE_VERSION,
  });

  expect(rejected.accepted).toEqual([]);
  expect(rejected.rejected).toEqual([
    { event_id: params.event.event_id, reason: params.reason },
  ]);
  expect(deps.listFederationEvents().map((event) => event.event_id)).toEqual(
    beforeEventIds,
  );
  expect(appliedPolicySnapshot(deps, params.materials.context.nodeId)).toEqual(
    beforeAppliedPolicy,
  );
  await expect(
    storedPolicySnapshot(storage, masterKey, params.materials.context.nodeId),
  ).resolves.toEqual(beforeStoredPolicy);
}

describe("operator policy-bundle federation event", () => {
  it("verifies an issuing-principal signature and folds only the signed hash/version", () => {
    const materials = makeFederationMaterials();
    const event = makePolicyEvent(materials, { version: 7, hash: POLICY_HASH_V7 });
    const projection: FederationPolicyProjection = {
      current: null,
      appliedByNode: new Map(),
    };

    const folded = foldFederationPolicyBundleEvent({
      event,
      projection,
      fortressId: materials.fortressId,
      pinnedMaster: materials.context.pinnedMasterPubkey,
      operatorPrincipalCert: materials.context.issuingPrincipalCert,
      applyingNodeId: materials.context.nodeId,
    });

    expect(folded.ok).toBe(true);
    expect(projection.current).toEqual({
      version: 7,
      hash: POLICY_HASH_V7,
      hash_algorithm: "sha256-base64url",
      applied_at: event.occurred_at,
      source_event_id: event.event_id,
    });
    expect(projection.appliedByNode.get(materials.context.nodeId)?.version).toBe(7);
    expect(JSON.stringify(event.payload)).not.toContain("tier1_always_approve");
  });

  it("rejects a wrong-key forged operator signature and leaves policy state unchanged", async () => {
    const materials = makeFederationMaterials();
    const event = makePolicyEvent(materials, { version: 7, hash: POLICY_HASH_V7 });
    const signedAt = event.occurred_at;
    const forgedPayload = signFederationPolicyBundlePayload({
      fortressId: materials.fortressId,
      policyVersion: 7,
      policyHash: POLICY_HASH_V7,
      signedAt,
      operatorPrincipalId: materials.context.issuingPrincipalCert.principal_id,
      operatorPrincipalPrivateKey: randomBytes(32),
    });
    const forged = withTamperedPayload(
      event,
      forgedPayload as unknown as Record<string, unknown>,
    );

    await expectRejectedPolicyBundleDoesNotAdvance({
      materials,
      event: forged,
      reason: "operator_signature_invalid",
    });
  });

  it("rejects a fortress mismatch and leaves policy state unchanged", async () => {
    const materials = makeFederationMaterials();
    const event = makePolicyEvent(materials, { version: 7, hash: POLICY_HASH_V7 });
    const mismatched = withTamperedPayload(event, {
      fortress_id: "different-fortress",
    });

    await expectRejectedPolicyBundleDoesNotAdvance({
      materials,
      event: mismatched,
      reason: "fortress_mismatch",
    });
  });

  it("rejects a principal mismatch and leaves policy state unchanged", async () => {
    const materials = makeFederationMaterials();
    const event = makePolicyEvent(materials, { version: 7, hash: POLICY_HASH_V7 });
    const mismatched = withTamperedPayload(event, {
      operator_principal_id: "principal-forged",
    });

    await expectRejectedPolicyBundleDoesNotAdvance({
      materials,
      event: mismatched,
      reason: "principal_mismatch",
    });
  });

  it("rejects an invalid principal certificate chain and leaves policy state unchanged", async () => {
    const materials = withInvalidPrincipalChain(makeFederationMaterials());
    const event = makePolicyEvent(materials, { version: 7, hash: POLICY_HASH_V7 });

    await expectRejectedPolicyBundleDoesNotAdvance({
      materials,
      event,
      reason: "principal_chain_invalid",
    });
  });

  it("rejects an equal-version replay and retains the prior applied policy", async () => {
    const materials = makeFederationMaterials();
    const prior = makePolicyEvent(materials, {
      version: 7,
      hash: POLICY_HASH_V7,
    });
    const replay = makePolicyEvent(materials, {
      version: 7,
      hash: POLICY_HASH_V8,
      sequence: 2,
      previousHash: prior.event_hash,
    });

    await expectRejectedPolicyBundleDoesNotAdvance({
      materials,
      event: replay,
      reason: "policy_version_replay",
      currentPolicyVersion: 7,
      priorEvent: prior,
    });
  });

  it("rejects a tampered hash and leaves the applied projection unchanged", () => {
    const materials = makeFederationMaterials();
    const event = makePolicyEvent(materials, { version: 7, hash: POLICY_HASH_V7 });
    const tampered = withTamperedPayload(event, { policy_hash: POLICY_HASH_V8 });

    const verification = verifyFederationPolicyBundleEvent({
      event: tampered,
      fortressId: materials.fortressId,
      pinnedMaster: materials.context.pinnedMasterPubkey,
      operatorPrincipalCert: materials.context.issuingPrincipalCert,
      currentPolicyVersion: null,
    });

    expect(verification).toEqual({
      ok: false,
      reason: "operator_signature_invalid",
    });
  });

  it("rejects extra payload fields so raw policy cannot ride beside the marker", () => {
    const materials = makeFederationMaterials();
    const event = makePolicyEvent(materials, { version: 7, hash: POLICY_HASH_V7 });
    const withRawPolicy = withTamperedPayload(event, {
      raw_policy: "tier1_always_approve:\n  - state_export\n",
    });

    const verification = verifyFederationPolicyBundleEvent({
      event: withRawPolicy,
      fortressId: materials.fortressId,
      pinnedMaster: materials.context.pinnedMasterPubkey,
      operatorPrincipalCert: materials.context.issuingPrincipalCert,
      currentPolicyVersion: null,
    });

    expect(verification).toEqual({
      ok: false,
      reason: "malformed_payload",
    });
  });

  it("rejects invalid bundles at the dashboard append seam and persists valid markers", async () => {
    const materials = makeFederationMaterials();
    const storage = new MemoryStorage();
    const masterKey = new Uint8Array(32).fill(9);
    const { deps } = await buildDashboard(materials, storage, masterKey);
    const event = makePolicyEvent(materials, { version: 7, hash: POLICY_HASH_V7 });
    const tampered = withTamperedPayload(event, { policy_hash: POLICY_HASH_V8 });

    const rejected = await deps.appendFederationEvents([tampered], {
      senderNodeId: tampered.origin_node_id,
      wireVersion: FEDERATION_SYNC_WIRE_VERSION,
    });

    expect(rejected.accepted).toEqual([]);
    expect(rejected.rejected).toEqual([
      { event_id: tampered.event_id, reason: "operator_signature_invalid" },
    ]);
    expect(deps.listNodes()[0]?.applied_policy.version ?? null).toBeNull();

    const accepted = await deps.appendFederationEvents([event], {
      senderNodeId: event.origin_node_id,
      wireVersion: FEDERATION_SYNC_WIRE_VERSION,
    });

    expect(accepted.rejected).toEqual([]);
    expect(accepted.accepted.map((e) => e.event_id)).toEqual([event.event_id]);
    const node = deps.listNodes().find((n) => n.node_id === materials.context.nodeId);
    expect(node?.applied_policy).toMatchObject({
      version: 7,
      hash: POLICY_HASH_V7,
      hash_algorithm: "sha256-base64url",
      source_event_id: event.event_id,
    });

    const snapshot = await new FederationSyncStateStore({
      storage,
      masterKey,
    }).load();
    expect(snapshot.operatorPolicy?.version).toBe(7);
    expect(snapshot.operatorPolicy?.hash).toBe(POLICY_HASH_V7);
    expect(
      snapshot.appliedPolicyVersions.get(materials.context.nodeId)?.version,
    ).toBe(7);
  });
});
