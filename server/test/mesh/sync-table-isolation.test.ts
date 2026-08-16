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
  MeshNode,
  REVOKE_DENIAL_AUDIT_PER_EMITTER_MAX,
  createAutoApproveJoinApprover,
} from "../../src/mesh/lifecycle/index.js";
import type {
  FortressMasterPublicKey,
  NodeLeavePayload,
  PrincipalCertificate,
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
});
