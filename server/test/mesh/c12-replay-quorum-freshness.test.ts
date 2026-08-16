/**
 * C12-REPLAY — v2 quorum-input freshness + sync hardening.
 *
 * Design of record: Review/Sanctuary/C12_REPLAY_Quorum_Freshness_Design_2026-08-16.md.
 * Maps to design §6 test plan T1..T10 plus the SYNC-APPEND-01 / NH / RG3 cases.
 *
 * Every adversarial case is falsifiable against current main (the v1 shape had
 * NO freshness, so an expired harvested quorum authorized revocation forever);
 * the mutation-probe notes on each case name the line whose deletion re-opens it.
 */

import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";

import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url, fromBase64url } from "../../src/core/encoding.js";
import { CAP_STANDARD_FORTRESS_NODE } from "../../src/mesh/constants.js";
import { packSignedEvent } from "../../src/mesh/envelope.js";
import { issueNodeIdentityCertificate } from "../../src/mesh/trust-root.js";
import {
  MeshNode,
  NodeLifecycleEventLog,
  InMemoryCounterStore,
  InMemoryNodeKeyStore,
  createAutoApproveJoinApprover,
} from "../../src/mesh/lifecycle/index.js";
import { InMemoryTransport } from "../../src/mesh/in-memory-transport.js";
import { DenialAuditGovernor } from "../../src/mesh/lifecycle/denial-audit-governor.js";
import { FailureModeDetector } from "../../src/mesh/failure-modes/index.js";
import { NodeRevokeCeremony } from "../../src/mesh/recovery-flows/index.js";
import {
  MAX_RETAINED_NON_REVOKE_EVENTS_PER_EMITTER,
  NODE_LIFECYCLE_LOG_MAX_EVENTS,
  REVOKE_DENIAL_AUDIT_GLOBAL_MAX,
  REVOKE_DENIAL_AUDIT_PER_EMITTER_MAX,
  REVOKE_DENIAL_AUDIT_WINDOW_MS,
} from "../../src/mesh/lifecycle/constants.js";
import type { SyncResponsePayload } from "../../src/mesh/lifecycle/types.js";
import {
  issueGuardianRoster,
  signMasterRotationAsGuardian,
  buildGuardianRevokeQuorumInput,
  mintRevokeCollectionContext,
  parseGuardianRevokeQuorumContext,
  assertQuorumContextFresh,
  computeRevokeAuthorizationKey,
  REVOKE_QUORUM_MAX_LIFETIME_MS,
  REVOKE_QUORUM_CLOCK_SKEW_MS,
  QuorumFreshnessError,
  GUARDIAN_REVOKE_QUORUM_SCHEMA_V2,
  type GuardianRevokeQuorumContext,
  type GuardianRoster,
} from "../../src/mesh/guardian/index.js";
import type {
  FortressMasterPublicKey,
  NodeRevokePayload,
  PrincipalCertificate,
  SignedEvent,
  NodeLifecyclePayload,
} from "../../src/mesh/types.js";

// ═══════════════════════════════════════════════════════════════════════
// Harness
// ═══════════════════════════════════════════════════════════════════════

interface Fortress {
  hub: InMemoryTransport;
  node: MeshNode;
  master: FortressMasterPublicKey;
  masterSecret: Uint8Array;
  rootCert: PrincipalCertificate;
  rootKey: Uint8Array;
  nodeKey: Uint8Array;
  fortressId: string;
  guardians: Array<{ id: string; pub: string; sk: Uint8Array }>;
  guardianRoster: GuardianRoster;
  m: number;
}

let seqCounter = 100;
function nextSeq(): number {
  return seqCounter++;
}

async function bootFortress(m = 2, n = 3): Promise<Fortress> {
  const hub = new InMemoryTransport();
  const placeholder = createAutoApproveJoinApprover({
    pinned_master_pubkey: {} as FortressMasterPublicKey,
    issuing_principal_cert: {} as PrincipalCertificate,
    issuing_principal_private_key: new Uint8Array(32),
  });
  const { node, bootstrap } = await MeshNode.bootstrapFirstNode({
    node_id: "canon-1",
    node_mode: "local",
    transport: hub.attach("canon-1"),
    approver: placeholder,
    key_store: new InMemoryNodeKeyStore(),
  });
  node.setApprover(
    createAutoApproveJoinApprover({
      pinned_master_pubkey: bootstrap.master_public,
      issuing_principal_cert: bootstrap.root_principal_certificate,
      issuing_principal_private_key: bootstrap.root_principal_private_key,
      master_private_key: bootstrap.master_private_key,
    })
  );

  const guardianKeys = Array.from({ length: n }, () => generateKeypair());
  const guardianIdentities = guardianKeys.map((kp, i) => ({
    guardian_id: `g${i}`,
    public_key: toBase64url(kp.publicKey),
    kind: "human",
    invited_at: "2026-05-14T00:00:00.000Z",
  }));
  const roster = issueGuardianRoster({
    m,
    n,
    guardians: guardianIdentities,
    fortress_id: bootstrap.master_public.fortress_id,
    version: 1,
    master_private_key: bootstrap.master_private_key,
  });
  node.registerGuardianRoster(roster);

  return {
    hub,
    node,
    master: bootstrap.master_public,
    masterSecret: bootstrap.master_private_key,
    rootCert: bootstrap.root_principal_certificate,
    rootKey: bootstrap.root_principal_private_key,
    nodeKey: bootstrap.node_private_key,
    fortressId: bootstrap.master_public.fortress_id,
    guardians: guardianIdentities.map((g, i) => ({
      id: g.guardian_id,
      pub: g.public_key,
      sk: guardianKeys[i].privateKey,
    })),
    guardianRoster: roster,
    m,
  };
}

/** Operations of the node's pending (unflushed) sealed audit entries. */
function pendingAuditOps(node: MeshNode): string[] {
  return node
    .peekPendingAuditEntries()
    .map((e) => (e.payload as { operation?: string }).operation ?? "");
}

/** Issue a node cert under the fortress root and add it to the node roster (active). */
function addRosterNode(
  f: Fortress,
  nodeId: string
): { cert: ReturnType<typeof issueNodeIdentityCertificate>; kp: ReturnType<typeof generateKeypair> } {
  const kp = generateKeypair();
  const cert = issueNodeIdentityCertificate({
    node_id: nodeId,
    node_pubkey: kp.publicKey,
    node_mode: "local",
    fortress_id: f.fortressId,
    capabilities: CAP_STANDARD_FORTRESS_NODE,
    parent_chain: {
      fortress_master_pubkey: f.master.public_key,
      principal_id: f.rootCert.principal_id,
      principal_pubkey: f.rootCert.principal_pubkey,
    },
    principal_private_key: f.rootKey,
    master_private_key: f.masterSecret,
  });
  f.node.getRoster().add(cert);
  f.node.getRoster().markActive(nodeId);
  return { cert, kp };
}

/** Build a fully-signed v2 node_revoke SignedEvent from an in-roster emitter. */
function buildV2Revoke(params: {
  f: Fortress;
  target: string;
  reason: string;
  context: GuardianRevokeQuorumContext;
  emitterNode: string;
  emitterKey: Uint8Array;
  effectiveAt?: string;
  seq?: number;
  omitContext?: boolean;
}): SignedEvent<NodeRevokePayload> {
  const input = buildGuardianRevokeQuorumInput({
    context: params.context,
    target_node_id: params.target,
    reason: params.reason,
    fortress_id: params.f.fortressId,
  });
  const sigs = params.f.guardians.slice(0, params.f.m).map((g) => ({
    guardian_pubkey: g.pub,
    signature: signMasterRotationAsGuardian({
      input,
      guardian_id: g.id,
      guardian_private_key: g.sk,
    }).signature,
  }));
  const payload: NodeRevokePayload = {
    node_id: params.target,
    reason: params.reason,
    effective_at: params.effectiveAt ?? new Date().toISOString(),
    quorum_signatures: sigs,
    quorum_context: params.omitContext
      ? undefined
      : {
          input_schema: GUARDIAN_REVOKE_QUORUM_SCHEMA_V2,
          ceremony_id: params.context.ceremony_id,
          initiated_at: params.context.initiated_at,
          expires_at: params.context.expires_at,
        },
  };
  return packSignedEvent<NodeRevokePayload>({
    event_type: "node_revoke",
    emitter_node: params.emitterNode,
    emitter_principal: params.f.rootCert.principal_id,
    fortress_id: params.f.fortressId,
    payload,
    monotonic_seq: params.seq ?? nextSeq(),
    node_private_key: params.emitterKey,
  }) as SignedEvent<NodeRevokePayload>;
}

const HOUR = 60 * 60 * 1000;

// ═══════════════════════════════════════════════════════════════════════
// Shared-module unit tests (T2/T3/T4/T9 parser + freshness)
// ═══════════════════════════════════════════════════════════════════════

describe("C12-REPLAY shared module — freshness + parser", () => {
  it("T3 relying-side lifetime cap: a signer-chosen decades window is refused", () => {
    const now = new Date("2026-08-16T00:00:00.000Z");
    // A context whose OWN window exceeds the cap (the generator cannot select
    // its own trust duration; the relying side hard-fails regardless).
    const parsed = parseGuardianRevokeQuorumContext({
      input_schema: GUARDIAN_REVOKE_QUORUM_SCHEMA_V2,
      ceremony_id: "a".repeat(32),
      initiated_at: now.toISOString(),
      expires_at: new Date(now.getTime() + 1000 * HOUR).toISOString(),
    });
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(() =>
      assertQuorumContextFresh(parsed.context, { mode: "strict", now })
    ).toThrow(QuorumFreshnessError);
    // Mutation probe: delete the lifetime-cap check -> this stops throwing.
  });

  it("T4 skew hard-fail: a future-dated initiated_at throws past the skew, passes within", () => {
    const now = new Date("2026-08-16T00:00:00.000Z");
    const mk = (offsetMs: number) =>
      parseGuardianRevokeQuorumContext({
        input_schema: GUARDIAN_REVOKE_QUORUM_SCHEMA_V2,
        ceremony_id: "b".repeat(32),
        initiated_at: new Date(now.getTime() + offsetMs).toISOString(),
        expires_at: new Date(now.getTime() + offsetMs + HOUR).toISOString(),
      });
    const beyond = mk(REVOKE_QUORUM_CLOCK_SKEW_MS + 1000);
    const within = mk(REVOKE_QUORUM_CLOCK_SKEW_MS - 1000);
    expect(beyond.ok && within.ok).toBe(true);
    if (!beyond.ok || !within.ok) return;
    expect(() =>
      assertQuorumContextFresh(beyond.context, { mode: "strict", now })
    ).toThrow(/future-dated/);
    expect(() =>
      assertQuorumContextFresh(within.context, { mode: "strict", now })
    ).not.toThrow();
  });

  it("strict expiry has NO skew grace (expired context refused at now)", () => {
    const initiated = new Date("2026-08-16T00:00:00.000Z");
    const parsed = parseGuardianRevokeQuorumContext({
      input_schema: GUARDIAN_REVOKE_QUORUM_SCHEMA_V2,
      ceremony_id: "c".repeat(32),
      initiated_at: initiated.toISOString(),
      expires_at: new Date(initiated.getTime() + HOUR).toISOString(),
    });
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    // now just past expiry: refused even within the skew constant.
    const now = new Date(initiated.getTime() + HOUR + 1000);
    expect(() =>
      assertQuorumContextFresh(parsed.context, { mode: "strict", now })
    ).toThrow(/expired/);
  });

  it("T6(v) sync_anchored bounds: effective_at below initiated by <skew accepted, more refused", () => {
    const initiated = new Date("2026-08-16T00:00:00.000Z");
    const parsed = parseGuardianRevokeQuorumContext({
      input_schema: GUARDIAN_REVOKE_QUORUM_SCHEMA_V2,
      ceremony_id: "d".repeat(32),
      initiated_at: initiated.toISOString(),
      expires_at: new Date(initiated.getTime() + HOUR).toISOString(),
    });
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const now = new Date(initiated.getTime() + 10 * HOUR); // long after the window
    // Emitter clock lagged the ceremony device by < skew: legitimate, accepted.
    const laggingOk = new Date(
      initiated.getTime() - (REVOKE_QUORUM_CLOCK_SKEW_MS - 1000)
    ).toISOString();
    expect(() =>
      assertQuorumContextFresh(parsed.context, {
        mode: "sync_anchored",
        now,
        effective_at: laggingOk,
      })
    ).not.toThrow();
    // Lagged by more than skew: refused (would otherwise be fail-open forever).
    const laggingBad = new Date(
      initiated.getTime() - (REVOKE_QUORUM_CLOCK_SKEW_MS + 1000)
    ).toISOString();
    expect(() =>
      assertQuorumContextFresh(parsed.context, {
        mode: "sync_anchored",
        now,
        effective_at: laggingBad,
      })
    ).toThrow();
    // Upper bound strict, no grace: effective_at past expires_at refused.
    const afterExpiry = new Date(initiated.getTime() + HOUR + 1000).toISOString();
    expect(() =>
      assertQuorumContextFresh(parsed.context, {
        mode: "sync_anchored",
        now,
        effective_at: afterExpiry,
      })
    ).toThrow();
  });

  it("T9 parser is element-level: each malformed field fails closed with a typed reason", () => {
    const good = {
      input_schema: GUARDIAN_REVOKE_QUORUM_SCHEMA_V2,
      ceremony_id: "e".repeat(32),
      initiated_at: "2026-08-16T00:00:00.000Z",
      expires_at: "2026-08-16T04:00:00.000Z",
    };
    expect(parseGuardianRevokeQuorumContext(good).ok).toBe(true);
    const cases: Array<[unknown, string]> = [
      [undefined, "context_absent"],
      [null, "context_absent"],
      [42, "context_not_object"],
      [{ ...good, input_schema: "sanctuary.guardian-revoke-quorum.v1" }, "schema_missing_or_wrong"],
      // Prefix must NOT match — exact literal only.
      [{ ...good, input_schema: GUARDIAN_REVOKE_QUORUM_SCHEMA_V2 + "x" }, "schema_missing_or_wrong"],
      [{ ...good, ceremony_id: "SHORT" }, "ceremony_id_malformed"],
      [{ ...good, ceremony_id: "E".repeat(32) }, "ceremony_id_malformed"], // uppercase rejected
      [{ ...good, initiated_at: "not-a-date" }, "initiated_at_not_iso"],
      [{ ...good, expires_at: 5 }, "expires_at_not_iso"],
      [{ ...good, expires_at: good.initiated_at }, "expires_not_after_initiated"],
    ];
    for (const [value, reason] of cases) {
      const r = parseGuardianRevokeQuorumContext(value);
      expect(r.ok, `expected fail for ${JSON.stringify(value)}`).toBe(false);
      if (!r.ok) expect(r.reason).toBe(reason);
    }
  });

  it("authorization key is stable per (target, ceremony_id) and per decoded principal sig", () => {
    const kA = computeRevokeAuthorizationKey({ target_node_id: "t", ceremony_id: "abc" });
    const kA2 = computeRevokeAuthorizationKey({ target_node_id: "t", ceremony_id: "abc" });
    const kB = computeRevokeAuthorizationKey({ target_node_id: "t", ceremony_id: "def" });
    expect(kA).toBe(kA2);
    expect(kA).not.toBe(kB);
    const sig = new Uint8Array([1, 2, 3, 4]);
    const kP = computeRevokeAuthorizationKey({ target_node_id: "t", principal_signature_bytes: sig });
    expect(kP.startsWith("p:t:")).toBe(true);
    expect(kP).not.toBe(kA);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Receive + sync path behavior (T1/T2/T6/T7/T8)
// ═══════════════════════════════════════════════════════════════════════

describe("C12-REPLAY receive + sync paths", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("T1(a) revokePeer pre-broadcast gate refuses an expired collection context", async () => {
    const f = await bootFortress();
    addRosterNode(f, "victim-a");
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-16T00:00:00.000Z"));
    const ctx = mintRevokeCollectionContext();
    // Advance the local clock past expiry, then a compromised local caller
    // tries to emit the harvested-but-expired quorum.
    vi.setSystemTime(new Date(Date.now() + REVOKE_QUORUM_MAX_LIFETIME_MS + HOUR));
    const input = buildGuardianRevokeQuorumInput({
      context: ctx,
      target_node_id: "victim-a",
      reason: "harvested",
      fortress_id: f.fortressId,
    });
    const sigs = f.guardians.slice(0, f.m).map((g) => ({
      guardian_pubkey: g.pub,
      signature: signMasterRotationAsGuardian({
        input,
        guardian_id: g.id,
        guardian_private_key: g.sk,
      }).signature,
    }));
    await expect(
      f.node.revokePeer({
        target_node_id: "victim-a",
        reason: "harvested",
        quorum_context: ctx,
        quorum_signatures: sigs,
      })
    ).rejects.toThrow(/expired|freshness|lifetime/i);
    expect(f.node.getRoster().presenceOf("victim-a")).not.toBe("revoked");
    // Mutation probe: delete assertQuorumContextFresh in the pre-broadcast gate
    // -> this emits a revocation of a healthy node.
  });

  it("T1(c) sync: in-window replay marks revoked; out-of-window replay refused, not persisted", async () => {
    const f = await bootFortress();
    addRosterNode(f, "victim-c");
    const emitter = addRosterNode(f, "emitter-c");
    const base = new Date("2026-08-16T00:00:00.000Z");
    const ctx = mintRevokeCollectionContext({ now: base });

    // In-window sync application (effective_at inside the window; now well after).
    const evtInWindow = buildV2Revoke({
      f,
      target: "victim-c",
      reason: "r",
      context: ctx,
      emitterNode: "emitter-c",
      emitterKey: emitter.kp.privateKey,
      effectiveAt: new Date(base.getTime() + HOUR).toISOString(),
    });
    const rejected: string[] = [];
    f.node.onEnvelopeRejected = ({ error }) => rejected.push(error.message);
    await f.node.applySync(
      { kind: "initial_sync", node_lifecycle_events: [evtInWindow] },
      new Date(base.getTime() + 100 * HOUR)
    );
    expect(f.node.getRoster().presenceOf("victim-c")).toBe("revoked");
    const logSizeAfterAccept = f.node.getLifecycleLog().size();

    // Out-of-window forged effective_at (past expires_at) — refused, NOT appended.
    const forged = buildV2Revoke({
      f,
      target: "victim-d",
      reason: "r",
      context: ctx,
      emitterNode: "emitter-c",
      emitterKey: emitter.kp.privateKey,
      effectiveAt: new Date(base.getTime() + 1000 * HOUR).toISOString(),
    });
    addRosterNode(f, "victim-d");
    const beforeSize = f.node.getLifecycleLog().size();
    await f.node.applySync(
      { kind: "initial_sync", node_lifecycle_events: [forged] },
      new Date(base.getTime() + 100 * HOUR)
    );
    expect(f.node.getRoster().presenceOf("victim-d")).not.toBe("revoked");
    // Non-persistence: a refused sync event is never appended (SYNC-APPEND-01).
    expect(f.node.getLifecycleLog().size()).toBe(beforeSize);
    expect(rejected.length).toBeGreaterThanOrEqual(1);
    void logSizeAfterAccept;
  });

  it("T1(b) live broadcast: a past-dated harvested quorum is refused at the receiver (not marked, audited)", async () => {
    const f = await bootFortress();
    addRosterNode(f, "victim-b");
    const emitter = addRosterNode(f, "emitter-b");
    // A context minted well in the past, already expired against the real clock.
    const past = new Date(Date.now() - (REVOKE_QUORUM_MAX_LIFETIME_MS + HOUR));
    const ctx = mintRevokeCollectionContext({ now: past });
    const evt = buildV2Revoke({
      f,
      target: "victim-b",
      reason: "harvested",
      context: ctx,
      emitterNode: "emitter-b",
      emitterKey: emitter.kp.privateKey,
      effectiveAt: past.toISOString(),
    });
    const rejected: string[] = [];
    f.node.onEnvelopeRejected = ({ error }) => rejected.push(error.message);
    const auditsBefore = f.node.snapshot().pending_audit_entries;
    // Deliver as a live broadcast from the emitter endpoint.
    const emitterTransport = f.hub.attach("emitter-b");
    await emitterTransport.broadcast(evt);
    await new Promise((r) => setTimeout(r, 0));
    expect(f.node.getRoster().presenceOf("victim-b")).not.toBe("revoked");
    expect(rejected.length).toBeGreaterThanOrEqual(1);
    expect(f.node.snapshot().pending_audit_entries).toBeGreaterThan(auditsBefore);
    // Mutation probe: delete the strict freshness check in admitRevoke's live
    // path -> victim-b is revoked by an expired harvested quorum.
  });

  it("T2 cross-context splice: signatures over context A presented under context B fail verification", async () => {
    const f = await bootFortress();
    addRosterNode(f, "victim-splice");
    const emitter = addRosterNode(f, "emitter-splice");
    const ctxA = mintRevokeCollectionContext();
    const ctxB = mintRevokeCollectionContext(); // distinct ceremony_id
    // Sign the quorum over context A.
    const inputA = buildGuardianRevokeQuorumInput({
      context: ctxA,
      target_node_id: "victim-splice",
      reason: "r",
      fortress_id: f.fortressId,
    });
    const sigs = f.guardians.slice(0, f.m).map((g) => ({
      guardian_pubkey: g.pub,
      signature: signMasterRotationAsGuardian({
        input: inputA,
        guardian_id: g.id,
        guardian_private_key: g.sk,
      }).signature,
    }));
    // But present the payload carrying context B's fields.
    const payload: NodeRevokePayload = {
      node_id: "victim-splice",
      reason: "r",
      effective_at: new Date().toISOString(),
      quorum_signatures: sigs,
      quorum_context: {
        input_schema: GUARDIAN_REVOKE_QUORUM_SCHEMA_V2,
        ceremony_id: ctxB.ceremony_id,
        initiated_at: ctxB.initiated_at,
        expires_at: ctxB.expires_at,
      },
    };
    const evt = packSignedEvent<NodeRevokePayload>({
      event_type: "node_revoke",
      emitter_node: "emitter-splice",
      emitter_principal: f.rootCert.principal_id,
      fortress_id: f.fortressId,
      payload,
      monotonic_seq: nextSeq(),
      node_private_key: emitter.kp.privateKey,
    }) as SignedEvent<NodeRevokePayload>;
    const rejected: string[] = [];
    f.node.onEnvelopeRejected = ({ error }) => rejected.push(error.message);
    await f.node.applySync({ kind: "initial_sync", node_lifecycle_events: [evt] });
    expect(f.node.getRoster().presenceOf("victim-splice")).not.toBe("revoked");
    expect(rejected.some((m) => /does not verify/.test(m))).toBe(true);
  });

  it("T6(iv) single append + non-persistence: accepted revoke appears exactly once", async () => {
    const f = await bootFortress();
    addRosterNode(f, "victim-e");
    const emitter = addRosterNode(f, "emitter-e");
    const ctx = mintRevokeCollectionContext();
    const evt = buildV2Revoke({
      f,
      target: "victim-e",
      reason: "r",
      context: ctx,
      emitterNode: "emitter-e",
      emitterKey: emitter.kp.privateKey,
    });
    const before = f.node.getLifecycleLog().size();
    await f.node.applySync({ kind: "initial_sync", node_lifecycle_events: [evt] });
    const log = f.node.getLifecycleLog().snapshot();
    const count = log.filter(
      (e) => e.event_type === "node_revoke" && (e.payload as NodeRevokePayload).node_id === "victim-e"
    ).length;
    expect(count).toBe(1); // NOT 2 (double-append resolved)
    expect(f.node.getLifecycleLog().size()).toBe(before + 1);
  });

  it("T6(iii) per-event isolation: a poison event is dropped, the legitimate revoke behind it still applies", async () => {
    const f = await bootFortress();
    addRosterNode(f, "victim-f");
    const emitter = addRosterNode(f, "emitter-f");
    const ctx = mintRevokeCollectionContext();
    // Poison: a node_revoke whose quorum_context is malformed (missing schema).
    const good = buildV2Revoke({
      f,
      target: "victim-f",
      reason: "r",
      context: ctx,
      emitterNode: "emitter-f",
      emitterKey: emitter.kp.privateKey,
    });
    const poison = buildV2Revoke({
      f,
      target: "victim-g",
      reason: "r",
      context: ctx,
      emitterNode: "emitter-f",
      emitterKey: emitter.kp.privateKey,
      omitContext: true, // v1-shape -> refused
    });
    addRosterNode(f, "victim-g");
    const rejected: string[] = [];
    f.node.onEnvelopeRejected = ({ error }) => rejected.push(error.message);
    // Poison FIRST, legitimate SECOND — the continue-on-poison ordering.
    await f.node.applySync({
      kind: "initial_sync",
      node_lifecycle_events: [poison, good],
    });
    expect(f.node.getRoster().presenceOf("victim-g")).not.toBe("revoked");
    expect(f.node.getRoster().presenceOf("victim-f")).toBe("revoked"); // survived the poison
    expect(rejected.length).toBeGreaterThanOrEqual(1);
    // Mutation probe: revert to a batch-abort loop -> victim-f stays active.
  });

  it("T7(d) authorization collapse: one harvested quorum + N distinct event_ids -> one retained revoke, no cross-target eviction", async () => {
    const f = await bootFortress();
    addRosterNode(f, "victim-h");
    addRosterNode(f, "other-victim");
    const emitter = addRosterNode(f, "emitter-h");
    const ctx = mintRevokeCollectionContext();

    // First, a legitimate revoke of a DIFFERENT target (its own authorization).
    const otherCtx = mintRevokeCollectionContext();
    const otherRevoke = buildV2Revoke({
      f,
      target: "other-victim",
      reason: "r",
      context: otherCtx,
      emitterNode: "emitter-h",
      emitterKey: emitter.kp.privateKey,
    });
    await f.node.applySync({ kind: "initial_sync", node_lifecycle_events: [otherRevoke] });
    expect(f.node.getRoster().presenceOf("other-victim")).toBe("revoked");

    // Now flood N distinct-event_id envelopes carrying the SAME (victim-h, ctx)
    // authorization (each is an ACCEPTED event on the first hit, a same-auth
    // replay after).
    const flood: SignedEvent<NodeLifecyclePayload>[] = [];
    for (let i = 0; i < 50; i++) {
      flood.push(
        buildV2Revoke({
          f,
          target: "victim-h",
          reason: "r",
          context: ctx,
          emitterNode: "emitter-h",
          emitterKey: emitter.kp.privateKey,
        }) as SignedEvent<NodeLifecyclePayload>
      );
    }
    await f.node.applySync({ kind: "initial_sync", node_lifecycle_events: flood });

    const log = f.node.getLifecycleLog().snapshot();
    const victimHRevokes = log.filter(
      (e) => e.event_type === "node_revoke" && (e.payload as NodeRevokePayload).node_id === "victim-h"
    );
    expect(victimHRevokes.length).toBe(1); // exactly one retained, not 50
    // other-victim's legitimate revoke is NOT evicted by the flood.
    const otherRevokes = log.filter(
      (e) => e.event_type === "node_revoke" && (e.payload as NodeRevokePayload).node_id === "other-victim"
    );
    expect(otherRevokes.length).toBe(1);
  });

  it("T8 re-admission guard: a same-authorization replay after rejoin is REFUSED (both channels), roster + log unchanged", async () => {
    const f = await bootFortress();
    const victim = addRosterNode(f, "victim-i");
    const emitter = addRosterNode(f, "emitter-i");
    const ctx = mintRevokeCollectionContext();

    // 1. Legitimate revoke of victim-i (in-window), applied via sync.
    const revoke = buildV2Revoke({
      f,
      target: "victim-i",
      reason: "r",
      context: ctx,
      emitterNode: "emitter-i",
      emitterKey: emitter.kp.privateKey,
    });
    await f.node.applySync({ kind: "initial_sync", node_lifecycle_events: [revoke] });
    expect(f.node.getRoster().presenceOf("victim-i")).toBe("revoked");
    const logAfterRevoke = f.node.getLifecycleLog().size();

    // 2. Operator re-admits victim-i via a fresh cert (rejoin-after-revoke path).
    const rejoinCert = issueNodeIdentityCertificate({
      node_id: "victim-i",
      node_pubkey: victim.kp.publicKey,
      node_mode: "local",
      fortress_id: f.fortressId,
      capabilities: CAP_STANDARD_FORTRESS_NODE,
      parent_chain: {
        fortress_master_pubkey: f.master.public_key,
        principal_id: f.rootCert.principal_id,
        principal_pubkey: f.rootCert.principal_pubkey,
      },
      principal_private_key: f.rootKey,
      master_private_key: f.masterSecret,
    });
    f.node.getRoster().add(rejoinCert);
    f.node.getRoster().markActive("victim-i");
    expect(f.node.getRoster().presenceOf("victim-i")).toBe("active");

    // 3. Same-authorization replay while target is LIVE — REFUSED, not applied,
    //    not dropped-silently. Roster stays active, log unchanged.
    const rejected: string[] = [];
    f.node.onEnvelopeRejected = ({ error }) => rejected.push(error.message);
    const replay = buildV2Revoke({
      f,
      target: "victim-i",
      reason: "r",
      context: ctx,
      emitterNode: "emitter-i",
      emitterKey: emitter.kp.privateKey,
    });
    await f.node.applySync({ kind: "initial_sync", node_lifecycle_events: [replay] });
    expect(f.node.getRoster().presenceOf("victim-i")).toBe("active"); // NOT re-revoked
    expect(f.node.getLifecycleLog().size()).toBe(logAfterRevoke); // no append
    expect(rejected.some((m) => /re-admission/.test(m))).toBe(true);
  });

  it("T6-idempotent: a same-authorization replay while target is STILL revoked is dropped (no second log entry, no re-mutation)", async () => {
    const f = await bootFortress();
    addRosterNode(f, "victim-j");
    const emitter = addRosterNode(f, "emitter-j");
    const ctx = mintRevokeCollectionContext();
    const evt = buildV2Revoke({
      f,
      target: "victim-j",
      reason: "r",
      context: ctx,
      emitterNode: "emitter-j",
      emitterKey: emitter.kp.privateKey,
    });
    await f.node.applySync({ kind: "initial_sync", node_lifecycle_events: [evt] });
    const size1 = f.node.getLifecycleLog().size();
    // Replay while still revoked: idempotent drop.
    await f.node.applySync({ kind: "initial_sync", node_lifecycle_events: [evt] });
    expect(f.node.getLifecycleLog().size()).toBe(size1);
    expect(f.node.getRoster().presenceOf("victim-j")).toBe("revoked");
  });

  it("M1 clean break: a v1-shape quorum revoke (no context) is refused with a version-distinguishing reason", async () => {
    const f = await bootFortress();
    addRosterNode(f, "victim-k");
    const emitter = addRosterNode(f, "emitter-k");
    const ctx = mintRevokeCollectionContext();
    const v1shape = buildV2Revoke({
      f,
      target: "victim-k",
      reason: "r",
      context: ctx,
      emitterNode: "emitter-k",
      emitterKey: emitter.kp.privateKey,
      omitContext: true,
    });
    const rejected: string[] = [];
    f.node.onEnvelopeRejected = ({ error }) => rejected.push(error.message);
    await f.node.applySync({ kind: "initial_sync", node_lifecycle_events: [v1shape] });
    expect(f.node.getRoster().presenceOf("victim-k")).not.toBe("revoked");
    expect(rejected.some((m) => /v1-shape/.test(m))).toBe(true);
  });

  it("F-10 orphan context: a payload with quorum_context but no signatures is rejected, never ignored", async () => {
    const f = await bootFortress();
    addRosterNode(f, "victim-l");
    const emitter = addRosterNode(f, "emitter-l");
    const ctx = mintRevokeCollectionContext();
    const payload: NodeRevokePayload = {
      node_id: "victim-l",
      reason: "r",
      effective_at: new Date().toISOString(),
      quorum_context: {
        input_schema: GUARDIAN_REVOKE_QUORUM_SCHEMA_V2,
        ceremony_id: ctx.ceremony_id,
        initiated_at: ctx.initiated_at,
        expires_at: ctx.expires_at,
      },
      // NO quorum_signatures — orphan context.
    };
    const evt = packSignedEvent<NodeRevokePayload>({
      event_type: "node_revoke",
      emitter_node: "emitter-l",
      emitter_principal: f.rootCert.principal_id,
      fortress_id: f.fortressId,
      payload,
      monotonic_seq: nextSeq(),
      node_private_key: emitter.kp.privateKey,
    }) as SignedEvent<NodeRevokePayload>;
    const rejected: string[] = [];
    f.node.onEnvelopeRejected = ({ error }) => rejected.push(error.message);
    await f.node.applySync({ kind: "initial_sync", node_lifecycle_events: [evt] });
    expect(rejected.some((m) => /orphan context/.test(m))).toBe(true);
    expect(f.node.getRoster().presenceOf("victim-l")).not.toBe("revoked");
  });

  it("T6(i)/(ii) S2 detectability: an out-of-window sync admission seals the distinct audit entry AND fires the distinct lifecycle marker", async () => {
    const f = await bootFortress();
    addRosterNode(f, "victim-s2");
    const emitter = addRosterNode(f, "emitter-s2");
    const base = new Date("2026-08-16T00:00:00.000Z");
    const ctx = mintRevokeCollectionContext({ now: base });
    // T6(i): a legitimate committed revoke whose window long lapsed reaches a
    // late joiner via sync. T6(ii) is the SAME admission shape driven by a
    // forged in-window effective_at — the laundering channel S2 concedes —
    // which is exactly why the admission must never be silent.
    const evt = buildV2Revoke({
      f,
      target: "victim-s2",
      reason: "r",
      context: ctx,
      emitterNode: "emitter-s2",
      emitterKey: emitter.kp.privateKey,
      effectiveAt: new Date(base.getTime() + HOUR).toISOString(),
    });
    const markers: string[] = [];
    f.node.onLifecycleEvent = (_evt, kind) => markers.push(kind);
    await f.node.applySync(
      { kind: "initial_sync", node_lifecycle_events: [evt] },
      new Date(base.getTime() + 100 * HOUR) // strict clock would refuse here
    );
    expect(f.node.getRoster().presenceOf("victim-s2")).toBe("revoked"); // admitted
    expect(pendingAuditOps(f.node)).toContain(
      "node_revoke_admitted_via_sync_out_of_window"
    );
    expect(markers).toContain("sync_admitted_out_of_window");
    // An idempotent same-authorization replay of the admitted event must NOT
    // add a second detectability entry (no ungoverned write amplifier).
    await f.node.applySync(
      { kind: "initial_sync", node_lifecycle_events: [evt] },
      new Date(base.getTime() + 100 * HOUR)
    );
    expect(
      pendingAuditOps(f.node).filter(
        (o) => o === "node_revoke_admitted_via_sync_out_of_window"
      ).length
    ).toBe(1);
    // Mutation probe: delete the recordSyncOutOfWindowAdmission call in
    // applySync -> the entry and marker assertions fail.
  });

  it("T6(i)/(ii) S2 detectability: the out-of-window entry is ABSENT on a live-path admission and on an in-window sync admission", async () => {
    const f = await bootFortress();
    addRosterNode(f, "victim-s3");
    const emitter = addRosterNode(f, "emitter-s3");
    const markers: string[] = [];
    f.node.onLifecycleEvent = (_evt, kind) => markers.push(kind);

    // Live-path admission: fresh in-window quorum broadcast to the receiver.
    const liveCtx = mintRevokeCollectionContext();
    const live = buildV2Revoke({
      f,
      target: "victim-s3",
      reason: "r",
      context: liveCtx,
      emitterNode: "emitter-s3",
      emitterKey: emitter.kp.privateKey,
    });
    const emitterTransport = f.hub.attach("emitter-s3");
    await emitterTransport.broadcast(live);
    await new Promise((r) => setTimeout(r, 0));
    expect(f.node.getRoster().presenceOf("victim-s3")).toBe("revoked");

    // In-window sync admission: now is still inside the collection window.
    addRosterNode(f, "victim-s4");
    const syncCtx = mintRevokeCollectionContext();
    const syncEvt = buildV2Revoke({
      f,
      target: "victim-s4",
      reason: "r",
      context: syncCtx,
      emitterNode: "emitter-s3",
      emitterKey: emitter.kp.privateKey,
    });
    await f.node.applySync(
      { kind: "initial_sync", node_lifecycle_events: [syncEvt] },
      new Date()
    );
    expect(f.node.getRoster().presenceOf("victim-s4")).toBe("revoked");

    expect(pendingAuditOps(f.node)).not.toContain(
      "node_revoke_admitted_via_sync_out_of_window"
    );
    expect(markers).not.toContain("sync_admitted_out_of_window");
  });

  it("T7(c) adversarial log cap: flood waves across the receive AND sync sites hold the NODE_LIFECYCLE_LOG_MAX_EVENTS bound and revoke entries survive", async () => {
    const f = await bootFortress();
    addRosterNode(f, "victim-t7c");
    const emitter = addRosterNode(f, "emitter-t7c");

    // 1. A real admitted revoke — the retention that must survive eviction.
    const ctx = mintRevokeCollectionContext();
    const revoke = buildV2Revoke({
      f,
      target: "victim-t7c",
      reason: "r",
      context: ctx,
      emitterNode: "emitter-t7c",
      emitterKey: emitter.kp.privateKey,
    });
    await f.node.applySync({
      kind: "initial_sync",
      node_lifecycle_events: [revoke],
    });
    expect(f.node.getRoster().presenceOf("victim-t7c")).toBe("revoked");

    // 2. Drive the log to its global cap (fast, no crypto). The per-emitter
    //    quota means one emitter tops out at its bucket, so 17 filler emitters
    //    are needed to cross the 10k global cap and engage enforceCap.
    const log = f.node.getLifecycleLog();
    const filler = (em: string, id: string) =>
      ({
        protocol_version: "0.1",
        event_type: "node_leave",
        event_id: id,
        emitter_node: em,
        emitter_principal: "p",
        fortress_id: f.fortressId,
        causal_parents: [],
        payload: { node_id: "x", reason: "graceful" },
        payload_hash: "h",
        emitted_at: "2026-08-16T00:00:00.000Z",
        monotonic_seq: 1,
        extension_envelope: {},
        node_signature: "s",
      }) as SignedEvent<NodeLifecyclePayload>;
    for (let e = 0; e < 17; e++) {
      for (let i = 0; i < MAX_RETAINED_NON_REVOKE_EVENTS_PER_EMITTER; i++) {
        log.append(filler(`filler-${e}`, `evt-${e}-${i}`));
      }
    }
    expect(log.size()).toBeLessThanOrEqual(NODE_LIFECYCLE_LOG_MAX_EVENTS);

    // 3. Replay/flood wave through the REAL receive site (live broadcasts).
    const emitterTransport = f.hub.attach("emitter-t7c");
    for (let i = 0; i < 10; i++) {
      const evt = packSignedEvent({
        event_type: "node_attestation_refresh",
        emitter_node: "emitter-t7c",
        emitter_principal: f.rootCert.principal_id,
        fortress_id: f.fortressId,
        payload: { node_id: "emitter-t7c", attestation_state: "present" },
        monotonic_seq: nextSeq(),
        node_private_key: emitter.kp.privateKey,
      });
      await emitterTransport.broadcast(evt);
    }
    await new Promise((r) => setTimeout(r, 0));
    expect(log.size()).toBeLessThanOrEqual(NODE_LIFECYCLE_LOG_MAX_EVENTS);

    // 4. Flood wave through the REAL sync site (same machinery, second site —
    //    rule 12: every site that shares the machinery).
    const syncWave: SignedEvent<NodeLifecyclePayload>[] = [];
    for (let i = 0; i < 10; i++) {
      syncWave.push(
        packSignedEvent({
          event_type: "node_attestation_refresh",
          emitter_node: "emitter-t7c",
          emitter_principal: f.rootCert.principal_id,
          fortress_id: f.fortressId,
          payload: { node_id: "emitter-t7c", attestation_state: "present" },
          monotonic_seq: nextSeq(),
          node_private_key: emitter.kp.privateKey,
        }) as unknown as SignedEvent<NodeLifecyclePayload>
      );
    }
    await f.node.applySync({
      kind: "initial_sync",
      node_lifecycle_events: syncWave,
    });

    // The bound holds product-wide, and the revoke entry survived the flood's
    // eviction pressure (revoke-preserving eviction).
    expect(log.size()).toBeLessThanOrEqual(NODE_LIFECYCLE_LOG_MAX_EVENTS);
    const revokes = log
      .snapshot()
      .filter(
        (e) =>
          e.event_type === "node_revoke" &&
          (e.payload as NodeRevokePayload).node_id === "victim-t7c"
      );
    expect(revokes.length).toBe(1);
    expect(f.node.getRoster().presenceOf("victim-t7c")).toBe("revoked");
    // Mutation probe (run + reverted): disable enforceCap's eviction loop ->
    // the size bound assertions fail (log grows past the cap).
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Sync-response request correlation (T6(vi), NH-3) + denial cap (T7(b), NH-4)
// ═══════════════════════════════════════════════════════════════════════

describe("C12-REPLAY sync-response correlation + denial cap", () => {
  it("T6(vi) an uncorrelated sync_response is refused before applySync (no roster/log mutation)", async () => {
    const f = await bootFortress();
    addRosterNode(f, "victim-m");
    const emitter = addRosterNode(f, "emitter-m");
    const ctx = mintRevokeCollectionContext();
    const revoke = buildV2Revoke({
      f,
      target: "victim-m",
      reason: "r",
      context: ctx,
      emitterNode: "emitter-m",
      emitterKey: emitter.kp.privateKey,
    });
    // Build a serving-peer-signed sync_response with a request_id that was
    // never issued by this node.
    const respPayload: SyncResponsePayload = {
      kind: "initial_sync",
      request_id: "deadbeefdeadbeefdeadbeefdeadbeef",
      node_lifecycle_events: [revoke],
    };
    const respEvt = packSignedEvent<SyncResponsePayload>({
      event_type: "sync_response",
      emitter_node: "emitter-m",
      emitter_principal: f.rootCert.principal_id,
      fortress_id: f.fortressId,
      payload: respPayload,
      monotonic_seq: nextSeq(),
      node_private_key: emitter.kp.privateKey,
    });

    const rejected: string[] = [];
    f.node.onEnvelopeRejected = ({ error, event_type }) =>
      rejected.push(`${event_type}:${error.message}`);
    const logBefore = f.node.getLifecycleLog().size();
    // Deliver the unsolicited sync_response to the node via unicast.
    const peer = f.hub.attach("peer-pusher");
    await peer.unicast(
      "canon-1",
      JSON.stringify({ kind: "sync_response", evt: respEvt })
    );
    await new Promise((r) => setTimeout(r, 0));

    expect(f.node.getRoster().presenceOf("victim-m")).not.toBe("revoked");
    expect(f.node.getLifecycleLog().size()).toBe(logBefore);
    expect(rejected.some((m) => m.startsWith("sync_response:"))).toBe(true);
  });

  it("T7(b) DenialAuditGovernor: per-emitter + global caps hold; saturation summary carries the accumulated counts", () => {
    const gov = new DenialAuditGovernor(
      REVOKE_DENIAL_AUDIT_PER_EMITTER_MAX,
      REVOKE_DENIAL_AUDIT_GLOBAL_MAX,
      REVOKE_DENIAL_AUDIT_WINDOW_MS
    );
    const now = 1_000;
    // One emitter beyond its per-emitter budget: extra denials are suppressed.
    let written = 0;
    let suppressed = 0;
    for (let i = 0; i < REVOKE_DENIAL_AUDIT_PER_EMITTER_MAX + 20; i++) {
      const d = gov.consider("emitter-A", now);
      if (d.writeIndividual) written++;
      else suppressed++;
    }
    expect(written).toBe(REVOKE_DENIAL_AUDIT_PER_EMITTER_MAX);
    expect(suppressed).toBe(20);
    // Distinct emitters were seen while suppressed; the summary records them.
    gov.consider("emitter-B", now); // within its own budget -> written
    for (let i = 0; i < 5; i++) gov.consider("emitter-A", now); // more suppressed
    const summary = gov.flushSaturationSummary();
    expect(summary).toBeDefined();
    if (!summary) return;
    expect(summary.suppressed_count).toBe(25);
    expect(summary.distinct_emitter_count).toBe(1); // only emitter-A was suppressed
  });

  it("denial-write flood stays bounded: pending audit entries do not track the flood size", async () => {
    const f = await bootFortress();
    const emitter = addRosterNode(f, "emitter-n");
    // Build many refused (out-of-window) revokes against distinct targets.
    const base = new Date("2026-08-16T00:00:00.000Z");
    const ctx = mintRevokeCollectionContext({ now: base });
    const events: SignedEvent<NodeLifecyclePayload>[] = [];
    for (let i = 0; i < 400; i++) {
      addRosterNode(f, `t-${i}`);
      events.push(
        buildV2Revoke({
          f,
          target: `t-${i}`,
          reason: "r",
          context: ctx,
          emitterNode: "emitter-n",
          emitterKey: emitter.kp.privateKey,
          effectiveAt: new Date(base.getTime() + 10_000 * HOUR).toISOString(),
        }) as SignedEvent<NodeLifecyclePayload>
      );
    }
    await f.node.applySync(
      { kind: "initial_sync", node_lifecycle_events: events },
      new Date(base.getTime() + 100 * HOUR)
    );
    // Every one is refused (out-of-window), but the individual audit writes are
    // capped by the global ceiling — far below the 400 denials.
    expect(f.node.snapshot().pending_audit_entries).toBeLessThan(400);
    // No target was actually revoked.
    for (let i = 0; i < 5; i++) {
      expect(f.node.getRoster().presenceOf(`t-${i}`)).not.toBe("revoked");
    }
  });

  it("uncorrelated sync_response refusals are write-governed: individual entries capped, saturation summary sealed on flush", async () => {
    const f = await bootFortress();
    const emitter = addRosterNode(f, "emitter-o");
    const peer = f.hub.attach("emitter-o");
    const SUPPRESSED = 20;
    const N = REVOKE_DENIAL_AUDIT_PER_EMITTER_MAX + SUPPRESSED;
    // The refusal is GUARANTEED for an unsolicited response, so an ungoverned
    // entry per refusal would be a zero-cost audit-write amplifier for any
    // in-roster peer — the same rule-8 incentive shape as the denial path.
    for (let i = 0; i < N; i++) {
      const respEvt = packSignedEvent<SyncResponsePayload>({
        event_type: "sync_response",
        emitter_node: "emitter-o",
        emitter_principal: f.rootCert.principal_id,
        fortress_id: f.fortressId,
        payload: {
          kind: "initial_sync",
          request_id: `never-issued-${i}`,
          node_lifecycle_events: [],
        },
        monotonic_seq: nextSeq(),
        node_private_key: emitter.kp.privateKey,
      });
      await peer.unicast(
        "canon-1",
        JSON.stringify({ kind: "sync_response", evt: respEvt })
      );
    }
    await new Promise((r) => setTimeout(r, 0));
    const ops = pendingAuditOps(f.node);
    expect(
      ops.filter((o) => o === "sync_response_uncorrelated").length
    ).toBe(REVOKE_DENIAL_AUDIT_PER_EMITTER_MAX); // NOT N
    expect(ops).not.toContain("sync_response_uncorrelated_saturation_summary");
    // The flush (production: the detector tick) seals the summary — counts are
    // degraded in granularity under flood, never lost.
    f.node.flushRevokeDenialSaturation();
    const summary = f.node
      .peekPendingAuditEntries()
      .map((e) => e.payload as {
        operation?: string;
        suppressed_count?: number;
        distinct_emitter_count?: number;
      })
      .find(
        (p) => p.operation === "sync_response_uncorrelated_saturation_summary"
      );
    expect(summary).toBeDefined();
    expect(summary?.suppressed_count).toBe(SUPPRESSED);
    expect(summary?.distinct_emitter_count).toBe(1);
  });

  it("wired consumer (rule 4): FailureModeDetector.tick — the production periodic tick — flushes a saturated-then-quiet denial schedule into the sealed summary", async () => {
    const f = await bootFortress();
    const emitter = addRosterNode(f, "emitter-p");
    // The production object graph: the real detector wired to the real node,
    // exactly as the composition root builds it. tick() is the function the
    // production setInterval invokes; calling it directly is the same code
    // path minus the wall-clock wait.
    const detector = new FailureModeDetector(
      f.node,
      {
        emit_context: {
          emitter_node: "canon-1",
          emitter_principal: f.rootCert.principal_id,
          fortress_id: f.fortressId,
          node_private_key: f.nodeKey,
          principal_private_key: f.rootKey,
          counters: new InMemoryCounterStore(),
        },
      },
      { canonical_audit_node_id: "canon-1", tick_interval_ms: 60_000 }
    );
    try {
      // Saturated wave: ONE emitter's out-of-window replays exceed its
      // per-emitter audit budget, so some denials are suppressed.
      const SUPPRESSED = 18;
      const base = new Date("2026-08-16T00:00:00.000Z");
      const ctx = mintRevokeCollectionContext({ now: base });
      const events: SignedEvent<NodeLifecyclePayload>[] = [];
      for (let i = 0; i < REVOKE_DENIAL_AUDIT_PER_EMITTER_MAX + SUPPRESSED; i++) {
        addRosterNode(f, `p-${i}`);
        events.push(
          buildV2Revoke({
            f,
            target: `p-${i}`,
            reason: "r",
            context: ctx,
            emitterNode: "emitter-p",
            emitterKey: emitter.kp.privateKey,
            effectiveAt: new Date(base.getTime() + 10_000 * HOUR).toISOString(),
          }) as SignedEvent<NodeLifecyclePayload>
        );
      }
      await f.node.applySync(
        { kind: "initial_sync", node_lifecycle_events: events },
        new Date(base.getTime() + 100 * HOUR)
      );
      // Quiet: no further denials arrive, so nothing rolls the window — the
      // summary is pending but unwritten.
      expect(pendingAuditOps(f.node)).not.toContain(
        "node_revoke_denied_saturation_summary"
      );
      detector.tick(Date.now());
      const summary = f.node
        .peekPendingAuditEntries()
        .map((e) => e.payload as {
          operation?: string;
          suppressed_count?: number;
          distinct_emitter_count?: number;
        })
        .find((p) => p.operation === "node_revoke_denied_saturation_summary");
      expect(summary).toBeDefined();
      expect(summary?.suppressed_count).toBe(SUPPRESSED);
      expect(summary?.distinct_emitter_count).toBe(1);
      // Mutation probe: remove the flushRevokeDenialSaturation call from
      // FailureModeDetector.tick -> the summary never appears.
    } finally {
      detector.stop();
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════
// NodeLifecycleEventLog dedupe + cap (SYNC-APPEND-01 unit)
// ═══════════════════════════════════════════════════════════════════════

describe("C12-REPLAY NodeLifecycleEventLog", () => {
  function fakeNonRevoke(emitter: string, eventId: string): SignedEvent<NodeLifecyclePayload> {
    return {
      protocol_version: "0.1",
      event_type: "node_leave",
      event_id: eventId,
      emitter_node: emitter,
      emitter_principal: "p",
      fortress_id: "f",
      causal_parents: [],
      payload: { node_id: "x", reason: "graceful" },
      payload_hash: "h",
      emitted_at: "2026-08-16T00:00:00.000Z",
      monotonic_seq: 1,
      extension_envelope: {},
      node_signature: "s",
    } as SignedEvent<NodeLifecyclePayload>;
  }

  it("non-revoke dedupe is emitter-scoped on (emitter, event_id)", () => {
    const log = new NodeLifecycleEventLog();
    log.append(fakeNonRevoke("n1", "e1"));
    log.append(fakeNonRevoke("n1", "e1")); // duplicate -> no-op
    expect(log.size()).toBe(1);
    log.append(fakeNonRevoke("n2", "e1")); // same event_id, different emitter -> kept
    expect(log.size()).toBe(2);
  });

  it("append rejects node_revoke events (they must use appendRevoke)", () => {
    const log = new NodeLifecycleEventLog();
    const rev = { ...fakeNonRevoke("n1", "r1"), event_type: "node_revoke" } as SignedEvent<NodeLifecyclePayload>;
    expect(() => log.append(rev)).toThrow(/appendRevoke/);
  });

  it("appendRevoke retains one entry per authorization and enforces the per-target quota (evict-oldest)", () => {
    const log = new NodeLifecycleEventLog();
    const mkRevoke = (auth: string) =>
      ({
        ...fakeNonRevoke("n1", "evt-" + auth),
        event_type: "node_revoke",
        payload: { node_id: "target", reason: "r" },
      }) as SignedEvent<NodeLifecyclePayload>;
    // 20 distinct authorizations for one target -> capped at the quota.
    for (let i = 0; i < 20; i++) {
      const authKey = `q:target:${i}`;
      if (!log.hasRetainedRevokeAuthorization(authKey)) {
        log.appendRevoke(mkRevoke(String(i)), {
          target_node_id: "target",
          authorization_key: authKey,
        });
      }
    }
    const revokes = log.snapshot().filter((e) => e.event_type === "node_revoke");
    expect(revokes.length).toBeLessThanOrEqual(8); // MAX_RETAINED_..._PER_TARGET
    // The NEWEST authorization survives (evict-oldest, never block-newest).
    expect(log.hasRetainedRevokeAuthorization("q:target:19")).toBe(true);
    expect(log.hasRetainedRevokeAuthorization("q:target:0")).toBe(false);
  });

  it("per-emitter quota (rule 8 per-origin): a flooding emitter evicts within its OWN bucket; other emitters' join events survive", () => {
    const log = new NodeLifecycleEventLog();
    const mkJoin = (emitter: string, id: string) =>
      ({
        ...fakeNonRevoke(emitter, id),
        event_type: "node_join",
      }) as SignedEvent<NodeLifecyclePayload>;
    // Three neighbors' join events, retained BEFORE the flood begins — under
    // global-only oldest-first eviction these would be the first casualties.
    log.append(mkJoin("n1", "j1"));
    log.append(mkJoin("n2", "j2"));
    log.append(mkJoin("n3", "j3"));
    const QUOTA = MAX_RETAINED_NON_REVOKE_EVENTS_PER_EMITTER;
    for (let i = 0; i < QUOTA + 50; i++) {
      log.append(fakeNonRevoke("flood", `f-${i}`));
    }
    const ids = log.snapshot().map((e) => e.event_id);
    // The neighbors' events survive the flood untouched.
    expect(ids).toContain("j1");
    expect(ids).toContain("j2");
    expect(ids).toContain("j3");
    // The flooder is capped at its quota, evicting its OWN oldest first.
    const floodRetained = log
      .snapshot()
      .filter((e) => e.emitter_node === "flood");
    expect(floodRetained.length).toBe(QUOTA);
    expect(ids).not.toContain("f-0");
    expect(ids).toContain(`f-${QUOTA + 49}`);
    expect(log.size()).toBe(3 + QUOTA);
    // Mutation probe: key the bucket eviction off the GLOBAL oldest instead of
    // the flooder's own bucket -> j1..j3 disappear and this test fails.
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Ceremony expiry boundaries (T5, design §8 Q4 adopted: confirm refuses too)
// ═══════════════════════════════════════════════════════════════════════

describe("C12-REPLAY ceremony expiry boundaries (T5)", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  async function proposeAtExpiryMinusDelta(target: string): Promise<{
    f: Fortress;
    ceremony: NodeRevokeCeremony;
    expiresMs: number;
  }> {
    const f = await bootFortress();
    addRosterNode(f, target);
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-16T00:00:00.000Z"));
    const ctx = mintRevokeCollectionContext();
    const input = buildGuardianRevokeQuorumInput({
      context: ctx,
      target_node_id: target,
      reason: "boundary",
      fortress_id: f.fortressId,
    });
    const sigs = f.guardians.slice(0, f.m).map((g) =>
      signMasterRotationAsGuardian({
        input,
        guardian_id: g.id,
        guardian_private_key: g.sk,
      })
    );
    const expiresMs = Date.parse(ctx.expires_at);
    // Propose at expiry - δ: still in-window, succeeds.
    vi.setSystemTime(new Date(expiresMs - 60_000));
    const ceremony = NodeRevokeCeremony.propose({
      proposal: {
        target_node_id: target,
        reason: "boundary",
        guardian_signatures: sigs,
        quorum_context: ctx,
      },
      ctx: {
        node: f.node,
        pinned_master: f.master,
        pinned_roster: f.guardianRoster,
        // Never reached in these schedules: confirm/execute refuse before any
        // alert emission.
        emit_ctx: null as unknown as never,
      },
    });
    return { f, ceremony, expiresMs };
  }

  it("T5(a) confirm at expiry+δ is refused (an operator confirmation is not a freshness extension); state stays proposed", async () => {
    const { ceremony, expiresMs } = await proposeAtExpiryMinusDelta("victim-t5a");
    vi.setSystemTime(new Date(expiresMs + 60_000));
    expect(() => ceremony.confirm({ note: "late confirm" })).toThrow(
      QuorumFreshnessError
    );
    expect(ceremony.state).toBe("proposed");
  });

  it("T5(b) confirm at expiry-δ then execute at expiry+δ: refused at the pre-broadcast gate, state failed, ZERO wire traffic", async () => {
    const { f, ceremony, expiresMs } =
      await proposeAtExpiryMinusDelta("victim-t5b");
    // Confirm just inside the window: allowed.
    ceremony.confirm({ note: "confirmed in-window" });
    expect(ceremony.state).toBe("confirmed");
    // Execute past expiry: revokePeer's strict pre-broadcast gate refuses
    // BEFORE anything is emitted or broadcast.
    vi.setSystemTime(new Date(expiresMs + 60_000));
    const emitted: string[] = [];
    f.node.onLifecycleEvent = (evt, kind) => {
      if (kind === "emitted") emitted.push(evt.event_type);
    };
    await expect(ceremony.execute()).rejects.toThrow(/expired/i);
    expect(ceremony.state).toBe("failed");
    expect(emitted).not.toContain("node_revoke"); // zero wire traffic
    expect(f.node.getRoster().presenceOf("victim-t5b")).toBe("active");
  });
});
