import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";

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
