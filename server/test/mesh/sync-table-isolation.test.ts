/**
 * Sanctuary Federation Protocol v0.1 - applySync per-table isolation tests
 * (C12-SYNC-ORDER-01)
 *
 * Split out of lifecycle.test.ts so these two tests are NOT covered by that
 * file's file-level `fail-before-exempt` marker: the marker exempts the
 * whole file from the verify-fail-before CI gate, and these two tests are
 * new coverage for the applySync per-table isolation fix, so they must be
 * gated for real (checked to fail against pre-fix source). See
 * server/src/mesh/lifecycle/mesh-node.ts and constants.ts for the fix.
 *
 * No route table is mocked; no crypto path is bypassed. Helpers are
 * duplicated from lifecycle.test.ts rather than imported, matching this
 * test directory's existing convention (each mesh test file keeps its own
 * local bootstrap/fixture helpers; see c12-replay-quorum-freshness.test.ts,
 * failure-modes.test.ts, master-rotation-cascade.test.ts).
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { generateKeypair } from "../../src/core/identity.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { packSignedEvent } from "../../src/mesh/envelope.js";
import { encodePolicyBlob } from "../../src/policy-engine/canonical-policy.js";
import {
  generateFortressMaster,
  issuePrincipalCertificate,
} from "../../src/mesh/trust-root.js";
import { InMemoryTransport } from "../../src/mesh/in-memory-transport.js";
import {
  InMemoryNodeKeyStore,
  LocatorTableStore,
  MeshNode,
  NodeLifecycleEventLog,
  PolicyBundleStore,
  REVOKE_DENIAL_AUDIT_PER_EMITTER_MAX,
  buildSyncResponse,
  createAutoApproveJoinApprover,
} from "../../src/mesh/lifecycle/index.js";
import type {
  SyncRequestPayload,
  SyncResponsePayload,
} from "../../src/mesh/lifecycle/types.js";
import type {
  FortressMasterPublicKey,
  LocatorUpdatePayload,
  NodeLeavePayload,
  PrincipalCertificate,
  SignedEvent,
} from "../../src/mesh/types.js";
import type { CompiledPolicy } from "../../src/policy-engine/types.js";

// ═══════════════════════════════════════════════════════════════════════
// Helpers (duplicated from lifecycle.test.ts; see file header)
// ═══════════════════════════════════════════════════════════════════════

interface FortressFixture {
  master_public: FortressMasterPublicKey;
  master_private_key: Uint8Array;
  root_principal_keypair: ReturnType<typeof generateKeypair>;
  root_principal_cert: PrincipalCertificate;
}

function compiledPolicyBlob(
  agentId: string,
  policyVersion: number,
  opts: { fortressId?: string; parentVersion?: number } = {},
): string {
  return encodePolicyBlob({
    schema_version: "0.1",
    agent_id: agentId,
    fortress_id: opts.fortressId ?? "f",
    policy_version: policyVersion,
    ...(opts.parentVersion !== undefined
      ? { parent_version: opts.parentVersion }
      : {}),
    slots: {
      memory: { slot: "memory", mode: "deny", grants: [] },
      credentials: { slot: "credentials", mode: "deny", grants: [] },
      plans: { slot: "plans", mode: "deny", grants: [] },
      outputs: { slot: "outputs", mode: "deny", grants: [] },
    },
    capabilities: {
      concordia_commitment_classes: [],
      honeypot_skill_ids: [],
      is_sentinel: false,
    },
    auto_trigger_ladder: {
      honeypot_auto_freeze: false,
      threshold_rule_action: "operator_approved",
      ml_anomaly_action: "operator_approved",
    },
    source_english: "fixture",
    compiled_at: "2026-06-09T12:00:00.000Z",
  } satisfies CompiledPolicy);
}

function bootFortress(): FortressFixture {
  const m = generateFortressMaster();
  const rp = generateKeypair();
  const cert = issuePrincipalCertificate({
    principal_id: "root",
    principal_pubkey: rp.publicKey,
    role: "root",
    fortress_id: m.public.fortress_id,
    master_private_key: m.private_key,
  });
  return {
    master_public: m.public,
    master_private_key: m.private_key,
    root_principal_keypair: rp,
    root_principal_cert: cert,
  };
}

async function bootstrapFirstNode(opts: {
  fortress?: FortressFixture;
  transport: InMemoryTransport;
  node_id?: string;
  fortress_id_override?: string;
}) {
  // Bootstrap a node from scratch using MeshNode.bootstrapFirstNode so
  // the test exercises the same code path as production. The approver
  // passed in is a placeholder - the materials it would need (principal
  // cert + keys) only exist post-bootstrap, so we install the real
  // approver immediately after.
  const transportHandle = opts.transport.attach(opts.node_id ?? "node-1");
  const placeholder = createAutoApproveJoinApprover({
    pinned_master_pubkey: {} as FortressMasterPublicKey,
    issuing_principal_cert: {} as PrincipalCertificate,
    issuing_principal_private_key: new Uint8Array(32),
  });
  const result = await MeshNode.bootstrapFirstNode({
    fortress_id: opts.fortress_id_override,
    node_id: opts.node_id ?? "node-1",
    node_mode: "local",
    transport: transportHandle,
    approver: placeholder,
    key_store: new InMemoryNodeKeyStore(),
  });
  // Install the real approver now that the principal materials exist.
  result.node.setApprover(
    createAutoApproveJoinApprover({
      pinned_master_pubkey: result.bootstrap.master_public,
      issuing_principal_cert: result.bootstrap.root_principal_certificate,
      issuing_principal_private_key:
        result.bootstrap.root_principal_private_key,
      master_private_key: result.bootstrap.master_private_key,
    })
  );
  return result;
}

/**
 * `handleIncomingUnicast` is dispatched with `void` from the transport
 * subscription (fire-and-forget), so a test driving the real receive path has
 * to wait for the handler to settle rather than for `unicast()` to resolve.
 * Bounded poll — never an unconditional sleep, so a genuine failure surfaces
 * as the caller's own assertion rather than as a timeout.
 */
async function settleUnicastHandlers(
  until: () => boolean,
  maxTicks = 50
): Promise<void> {
  for (let i = 0; i < maxTicks; i++) {
    if (until()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

// ═══════════════════════════════════════════════════════════════════════
// C12-SYNC-ORDER-01 - applySync per-table isolation for policy/locator events
// ═══════════════════════════════════════════════════════════════════════

describe("lifecycle/sync - applySync per-table isolation (C12-SYNC-ORDER-01)", () => {
  it("C12-SYNC-ORDER-01: a poison policy_update is dropped-and-audited without costing the lifecycle events in the same response", async () => {
    const hub = new InMemoryTransport();
    const first = await bootstrapFirstNode({ transport: hub });
    const nodeId = first.bootstrap.node_certificate.node_id;
    const fortressId = first.bootstrap.master_public.fortress_id;
    const rootPrincipalId =
      first.bootstrap.root_principal_certificate.principal_id;

    // A policy_update signed by the bootstrapped node (in its own roster),
    // then its node_signature is overwritten with a signature over
    // DIFFERENT bytes — a malformed/unverifiable envelope, matching the
    // register row's description, rejected cleanly by verifyOrThrow rather
    // than by a parse crash.
    const poisonPolicy = packSignedEvent({
      event_type: "policy_update",
      emitter_node: nodeId,
      emitter_principal: rootPrincipalId,
      fortress_id: fortressId,
      payload: {
        agent_id: "agent-poison",
        policy_version: 1,
        valid_from: "2026-06-01T00:00:00.000Z",
        valid_until: "2099-01-01T00:00:00.000Z",
        policy_blob: compiledPolicyBlob("agent-poison", 1, { fortressId }),
      },
      monotonic_seq: 1,
      node_private_key: first.bootstrap.node_private_key,
    });
    poisonPolicy.node_signature = toBase64url(
      ed25519.sign(stringToBytes("poison"), first.bootstrap.node_private_key)
    );

    // A LEGITIMATE lifecycle event riding in the SAME sync response — a
    // node_leave that mutates roster presence. Fail-before: pre-fix, the
    // up-front policy/locator verify loop threw on the poison event above
    // and aborted applySync entirely, so this event's loop never ran and
    // the roster mutation below never happened — silently, because
    // handleIncomingUnicast's sync_response catch swallows the throw.
    const legitLeave = packSignedEvent<NodeLeavePayload>({
      event_type: "node_leave",
      emitter_node: nodeId,
      emitter_principal: rootPrincipalId,
      fortress_id: fortressId,
      payload: { node_id: nodeId, reason: "graceful" },
      monotonic_seq: 2,
      node_private_key: first.bootstrap.node_private_key,
    });

    const rejected: Array<{ error: Error; event_type: string }> = [];
    first.node.onEnvelopeRejected = ({ error, event_type }) =>
      rejected.push({ error, event_type });
    const beforeAuditEntries = first.node.snapshot().pending_audit_entries;

    await first.node.applySync({
      kind: "initial_sync",
      policy_updates: [poisonPolicy],
      node_lifecycle_events: [legitLeave],
    });

    // Per-table isolation: the poison policy_update never reached the
    // policy bundle...
    expect(first.node.getPolicyBundle().get("agent-poison")).toBeUndefined();
    // ...and the legit node_leave in the SAME response is still applied —
    // never lost to a poison event in a DIFFERENT table.
    expect(first.node.getRoster().presenceOf(nodeId)).toBe("left");

    // Never silent (MUST-NEVER #5): the operator-visible hook fires for the
    // drop...
    expect(rejected.some((r) => r.event_type === "policy_update")).toBe(
      true
    );
    // ...and a sealed, forensic audit entry recording the denial is queued
    // (governed by its own syncTableEventAuditGovernor budget — see
    // AUD-BP-01 at the enforcement site).
    expect(first.node.snapshot().pending_audit_entries).toBeGreaterThan(
      beforeAuditEntries
    );
    const deniedEntry = first.node
      .peekPendingAuditEntries()
      .find(
        (e) =>
          (e.payload as { operation?: string }).operation ===
          "sync_table_event_denied"
      );
    expect(deniedEntry).toBeDefined();
    expect((deniedEntry!.payload as { table?: string }).table).toBe(
      "policy_update"
    );
  });

  it("C12-SYNC-ORDER-01: the drop-audit governor is keyed on the authenticated relaying peer, not the poison event's own unverified claimed emitter_node", async () => {
    const hub = new InMemoryTransport();
    const first = await bootstrapFirstNode({ transport: hub });
    const fortressId = first.bootstrap.master_public.fortress_id;
    const rootPrincipalId =
      first.bootstrap.root_principal_certificate.principal_id;

    // N poison policy_update events, each claiming a DIFFERENT emitter_node
    // that is not even in the roster — a cheap, guaranteed verification
    // failure (rejected at the roster lookup, before signature checking, so
    // no valid key is needed to fabricate a claimed identity). N exceeds the
    // per-KEY cap so the test can distinguish "bounded by one authenticated
    // key" from "bounded by nothing" / "one bucket per claimed identity".
    const n = REVOKE_DENIAL_AUDIT_PER_EMITTER_MAX + 8;
    const poisonEvents = Array.from({ length: n }, (_, i) =>
      packSignedEvent({
        event_type: "policy_update",
        emitter_node: `spoofed-node-${i}`,
        emitter_principal: rootPrincipalId,
        fortress_id: fortressId,
        payload: {
          agent_id: `agent-spoof-${i}`,
          policy_version: 1,
          valid_from: "2026-06-01T00:00:00.000Z",
          valid_until: "2099-01-01T00:00:00.000Z",
          policy_blob: compiledPolicyBlob(`agent-spoof-${i}`, 1, {
            fortressId,
          }),
        },
        monotonic_seq: i + 1,
        // The signing key is irrelevant — verification rejects on
        // "emitter_node not in local roster" before it ever reaches the
        // signature check, so no valid identity is needed to spoof one.
        node_private_key: first.bootstrap.node_private_key,
      })
    );

    // A direct/initial-sync call (no relayingPeer argument) — the governor
    // falls back to the fixed unknown-peer sentinel, so every one of these
    // N distinct claimed identities collapses into ONE governor key.
    await first.node.applySync({
      kind: "initial_sync",
      policy_updates: poisonEvents,
    });
    // Force the pending suppression count into a sealed summary without
    // waiting for the governor's window to roll.
    first.node.flushRevokeDenialSaturation();

    const entries = first.node.peekPendingAuditEntries();
    const individualDenials = entries.filter(
      (e) =>
        (e.payload as { operation?: string }).operation ===
        "sync_table_event_denied"
    );
    const summary = entries.find(
      (e) =>
        (e.payload as { operation?: string }).operation ===
        "sync_table_event_denied_saturation_summary"
    );

    // Bounded by the PER-KEY cap, never by N: proves the governor is keyed
    // on one authenticated identity (the sentinel here), not on the N
    // distinct UNVERIFIED emitter_node strings the poison events claimed —
    // a per-claimed-identity key would have let every one of the N events
    // through as its own bucket.
    expect(individualDenials.length).toBeLessThanOrEqual(
      REVOKE_DENIAL_AUDIT_PER_EMITTER_MAX
    );
    expect(individualDenials.length).toBeGreaterThan(0);
    expect(summary).toBeDefined();
    // The saturation summary's distinct_emitter_count reflects the
    // GOVERNOR's key space (one shared bucket here), never the N-sized
    // attacker-chosen claimed-emitter space a defective keying would report.
    expect(
      (summary!.payload as { distinct_emitter_count?: number })
        .distinct_emitter_count
    ).toBe(1);
    // Each individual entry still retains the event's own claim, forensic-
    // only and clearly labeled unverified — never used as the governor key.
    for (const entry of individualDenials) {
      const payload = entry.payload as {
        relaying_peer?: string;
        claimed_emitter_node?: string;
      };
      expect(payload.relaying_peer).toBeDefined();
      expect(payload.claimed_emitter_node).toMatch(/^spoofed-node-\d+$/);
    }
  });

  it("C12-SYNC-ORDER-01: a locator_update dropped beneath a higher-versioned sibling is still re-served on the next sync round", async () => {
    const hub = new InMemoryTransport();
    const first = await bootstrapFirstNode({ transport: hub });
    const nodeId = first.bootstrap.node_certificate.node_id;
    const fortressId = first.bootstrap.master_public.fortress_id;
    const rootPrincipalId =
      first.bootstrap.root_principal_certificate.principal_id;

    const locatorEvent = (agentId: string, version: number, seq: number) =>
      packSignedEvent<LocatorUpdatePayload>({
        event_type: "locator_update",
        emitter_node: nodeId,
        emitter_principal: rootPrincipalId,
        fortress_id: fortressId,
        payload: {
          agent_id: agentId,
          canonical_node: nodeId,
          locator_version: version,
          last_migration_at: "2026-06-01T00:00:00.000Z",
          hosting_principal: rootPrincipalId,
        },
        monotonic_seq: seq,
        node_private_key: first.bootstrap.node_private_key,
      });

    const goodA5 = locatorEvent("agent-a", 5, 1);
    const goodB9 = locatorEvent("agent-b", 9, 2);

    // The peer that will serve the NEXT round holds both entries intact.
    const responderLocator = new LocatorTableStore();
    responderLocator.upsert(goodA5);
    responderLocator.upsert(goodB9);
    const respond = (request: SyncRequestPayload): SyncResponsePayload =>
      buildSyncResponse(request, {
        policy_bundle: new PolicyBundleStore(),
        locator_table: responderLocator,
        lifecycle_log: new NodeLifecycleEventLog(),
      });

    // The copy of A@v5 that reaches THIS node has a corrupted envelope
    // signature — the ordinary benign relay/rotation cause, not an exploit:
    // the relaying peer serves what verifies for IT, and this node refuses it.
    const poisonA5 = JSON.parse(JSON.stringify(goodA5)) as typeof goodA5;
    poisonA5.node_signature = toBase64url(
      ed25519.sign(stringToBytes("poison"), first.bootstrap.node_private_key)
    );

    await first.node.applySync({
      kind: "delta_sync",
      locator_updates: [poisonA5, goodB9],
    });

    // Per-table isolation did its job: A dropped, its higher-versioned
    // sibling B applied. This is the state the re-request must repair.
    expect(first.node.getLocatorTable().get("agent-a")).toBeUndefined();
    expect(
      first.node.getLocatorTable().get("agent-b")?.payload.locator_version
    ).toBe(9);
    // And the SCALAR watermark now reads 9 — i.e. it claims this node holds
    // everything at or below 9, which is exactly the false claim that made a
    // scalar baseline unable to recover the dropped entry.
    expect(first.node.getLocatorTable().highest()).toBe(9);

    // Drive the REAL request path so the baseline under test is the one
    // production sends, not one the test composes.
    const responderTransport = hub.attach("peer-responder");
    const captured: string[] = [];
    responderTransport.subscribeUnicast((_to, message) =>
      captured.push(message)
    );
    const capturedRequest = (): SyncRequestPayload => {
      expect(captured).toHaveLength(1);
      const wire = JSON.parse(captured[0]) as {
        evt: SignedEvent<SyncRequestPayload>;
      };
      return wire.evt.payload;
    };

    await first.node.requestSyncFromPeer({
      peer_node_id: "peer-responder",
      kind: "delta_sync",
    });
    const response = respond(capturedRequest());

    // THE GAP ASSERTION. Under a single scalar baseline of 9 the responder's
    // strictly-greater-than delta excludes A@v5 forever and this node ends
    // with no locator entry for agent-a while reporting fully-synced. The
    // per-agent baseline carries no claim about agent-a, so A@v5 comes back.
    const reserved = response.locator_updates?.find(
      (e) => e.payload.agent_id === "agent-a"
    );
    expect(reserved).toBeDefined();
    expect(reserved!.payload.locator_version).toBe(5);

    // The gap actually closes when the re-served entry is applied...
    await first.node.applySync(response);
    expect(
      first.node.getLocatorTable().get("agent-a")?.payload.locator_version
    ).toBe(5);

    // ...and the repair HEALS rather than becoming a permanent re-serve tax:
    // once agent-a is applied its baseline advances and the responder stops
    // re-sending it. A never-cleared scalar clamp would keep re-serving here.
    captured.length = 0;
    await first.node.requestSyncFromPeer({
      peer_node_id: "peer-responder",
      kind: "delta_sync",
    });
    expect(respond(capturedRequest()).locator_updates).toHaveLength(0);
  });

  it("C12-SYNC-ORDER-01: a poison table event no longer loses the whole response SILENTLY through the swallowing sync_response receive path", async () => {
    const hub = new InMemoryTransport();
    const first = await bootstrapFirstNode({ transport: hub });
    const nodeId = first.bootstrap.node_certificate.node_id;
    const fortressId = first.bootstrap.master_public.fortress_id;
    const rootPrincipalId =
      first.bootstrap.root_principal_certificate.principal_id;

    // This test deliberately goes through `handleIncomingUnicast`, NOT a
    // direct `applySync` call, because that handler's bare `catch {}` is
    // where the SILENCE comes from: pre-fix, one poison table event threw out
    // of applySync, the catch swallowed it, and the round's remaining events
    // were lost with no throw, no audit entry, and no operator hook — after
    // the correlation id had already been consumed. A direct applySync test
    // can observe the loss but never the silence.
    const relay = hub.attach("relay-peer");

    // Capture the outstanding request_id from a real sync_request, so the
    // response below correlates the way a genuine peer's would.
    const captured: string[] = [];
    relay.subscribeUnicast((_to, message) => captured.push(message));
    await first.node.requestSyncFromPeer({
      peer_node_id: "relay-peer",
      kind: "delta_sync",
    });
    const requestId = (
      JSON.parse(captured[0]) as { evt: SignedEvent<SyncRequestPayload> }
    ).evt.payload.request_id;
    expect(requestId).toBeDefined();

    const poisonLocator = packSignedEvent<LocatorUpdatePayload>({
      event_type: "locator_update",
      emitter_node: nodeId,
      emitter_principal: rootPrincipalId,
      fortress_id: fortressId,
      payload: {
        agent_id: "agent-poison",
        canonical_node: nodeId,
        locator_version: 3,
        last_migration_at: "2026-06-01T00:00:00.000Z",
        hosting_principal: rootPrincipalId,
      },
      monotonic_seq: 10,
      node_private_key: first.bootstrap.node_private_key,
    });
    poisonLocator.node_signature = toBase64url(
      ed25519.sign(stringToBytes("poison"), first.bootstrap.node_private_key)
    );

    // A legitimate lifecycle event riding the SAME response, in a DIFFERENT
    // table. Pre-fix this is what was silently lost.
    const legitLeave = packSignedEvent<NodeLeavePayload>({
      event_type: "node_leave",
      emitter_node: nodeId,
      emitter_principal: rootPrincipalId,
      fortress_id: fortressId,
      payload: { node_id: nodeId, reason: "graceful" },
      monotonic_seq: 11,
      node_private_key: first.bootstrap.node_private_key,
    });

    const responseEvt = packSignedEvent<SyncResponsePayload>({
      event_type: "sync_response",
      emitter_node: nodeId,
      emitter_principal: rootPrincipalId,
      fortress_id: fortressId,
      payload: {
        kind: "delta_sync",
        request_id: requestId,
        locator_updates: [poisonLocator],
        node_lifecycle_events: [legitLeave],
      },
      monotonic_seq: 12,
      node_private_key: first.bootstrap.node_private_key,
    });

    const rejected: string[] = [];
    first.node.onEnvelopeRejected = ({ event_type }) =>
      rejected.push(event_type ?? "unknown");

    const auditedDrop = () =>
      first.node
        .peekPendingAuditEntries()
        .some(
          (e) =>
            (e.payload as { operation?: string }).operation ===
            "sync_table_event_denied"
        );

    // Delivered through the transport, so the production subscription and the
    // swallowing catch are both in the path.
    await relay.unicast(
      nodeId,
      JSON.stringify({ kind: "sync_response", evt: responseEvt })
    );
    await settleUnicastHandlers(auditedDrop);

    // NOT SILENT (MUST-NEVER #5): the refusal produced a sealed audit entry
    // and fired the operator-visible hook, rather than vanishing into the
    // handler's catch.
    expect(auditedDrop()).toBe(true);
    expect(rejected).toContain("locator_update");
    // And the legitimate event in the other table survived the round, so the
    // consumed correlation id was not spent for nothing.
    expect(first.node.getRoster().presenceOf(nodeId)).toBe("left");
    // The poison entry itself never reached the table.
    expect(first.node.getLocatorTable().get("agent-poison")).toBeUndefined();
  });
});
