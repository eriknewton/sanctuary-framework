/**
 * Sanctuary v1.2.x Activity feed per-action attestation projection.
 *
 * Asserts that `aggregateActivity` populates the optional `attestation`
 * field on every projected `HubActivityFeedEntry`:
 *   1. Unsigned audit entries render `state: "degraded"` even on success.
 *   2. Producer-signed audit entries render `state: "verified"`.
 *   3. Distinct entry ids derive distinct fragments.
 *   4. Fragment shape is `<4hex>..<2hex>` (matches Sprint Piece 2 gallery).
 *
 * Real AuditLog over MemoryStorage; no mocks at the projection layer.
 *
 * Note on integrity claims: the fragment is a deterministic projection of
 * the audit-chain entry id, NOT a per-event Ed25519 signature. The audit
 * chain itself is the integrity claim.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";

import { MemoryStorage } from "../../src/storage/memory.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { aggregateActivity } from "../../src/hub/activity-feed.js";
import type { AuditEntry } from "../../src/operational/audit-log.js";
import { auditEntryAgentId } from "../../src/castle-wall/audit-attribution.js";
import { producerSigningBytes } from "../../src/castle-wall/runtime/producer-signature.js";
import {
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
} from "../../src/castle-wall/constants.js";

const IDENTITY_ID = "operator-attestation-projection-001";
const TEST_FORTRESS_ID = "fortress:test";
const VICTIM_AGENT_ID = "victim-agent-b";
const VICTIM_SUBJECT = `${TEST_FORTRESS_ID}/uid-503`;

interface Rig {
  auditLog: AuditLog;
}

function toBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const producerPriv = ed25519.utils.randomPrivateKey();
const producerPubB64 = toBase64url(ed25519.getPublicKey(producerPriv));
const SIGNED_AT_MS = 1_777_777_777_777;

function withProducerSignature(
  entry: AuditEntry,
  identityId: string,
): AuditEntry {
  const seq = typeof entry.details?.seq === "number" ? entry.details.seq : 77;
  const body = JSON.stringify({
    timestamp: entry.timestamp,
    layer: entry.layer,
    operation: entry.operation,
    identity_id: identityId,
    result: entry.result,
    details: entry.details ?? {},
  });
  const sig = ed25519.sign(
    producerSigningBytes(body, SIGNED_AT_MS, seq),
    producerPriv,
  );
  return {
    ...entry,
    identity_id: identityId,
    details: {
      ...(entry.details ?? {}),
      seq,
      [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
      [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]:
        CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: body,
      [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: SIGNED_AT_MS,
      [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]:
        CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
    },
  };
}

function signedVictimEgressEntry(): AuditEntry {
  return withProducerSignature(
    {
      timestamp: "2026-07-20T10:00:00.000Z",
      layer: "l1",
      operation: "egress_blocked",
      identity_id: VICTIM_SUBJECT,
      result: "success",
      details: {
        agent_id: VICTIM_AGENT_ID,
        agent_template: "claude-code",
        dest_host: "legitimate.example.com",
        dest_ip: "198.51.100.10",
        dest_port: 443,
        dest_protocol: "tcp",
      },
    },
    VICTIM_SUBJECT,
  );
}

async function startRig(): Promise<Rig> {
  const storage = new MemoryStorage();
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);
  return { auditLog };
}

describe("Activity feed: per-action attestation projection", () => {
  let rig: Rig;
  beforeEach(async () => (rig = await startRig()));
  afterEach(() => undefined);

  it("successful unsigned entries render attestation.state = 'degraded'", async () => {
    await rig.auditLog.append("l2", "policy_decision", IDENTITY_ID, {}, "success");
    await rig.auditLog.flush();
    const entries = await aggregateActivity(
      { auditLog: rig.auditLog, identityId: IDENTITY_ID },
      { limit: 10 },
    );
    expect(entries).toHaveLength(1);
    expect(entries[0]!.attestation).toBeDefined();
    expect(entries[0]!.attestation!.state).toBe("degraded");
  });

  it("producer-signed entries render attestation.state = 'verified'", async () => {
    const signed = signedVictimEgressEntry();
    await rig.auditLog.appendCritical({
      layer: signed.layer,
      operation: signed.operation,
      identity_id: signed.identity_id,
      timestamp: signed.timestamp,
      result: signed.result,
      details: signed.details,
    });
    await rig.auditLog.flush();
    const entries = await aggregateActivity(
      {
        auditLog: rig.auditLog,
        identityId: signed.identity_id,
        pinnedProducerKeyB64url: producerPubB64,
        subjectFortressId: TEST_FORTRESS_ID,
        listLocalAgents: () => [
          { agent_id: VICTIM_AGENT_ID, protection_subject: VICTIM_SUBJECT },
        ],
      },
      { limit: 10 },
    );
    expect(entries).toHaveLength(1);
    expect(entries[0]!.agent_id).toBe(VICTIM_AGENT_ID);
    expect(entries[0]!.attestation!.state).toBe("verified");
  });

  it("failed entries render attestation.state = 'degraded'", async () => {
    await rig.auditLog.append("l2", "policy_deny", IDENTITY_ID, {}, "failure");
    await rig.auditLog.flush();
    const entries = await aggregateActivity(
      { auditLog: rig.auditLog, identityId: IDENTITY_ID },
      { limit: 10 },
    );
    expect(entries).toHaveLength(1);
    expect(entries[0]!.attestation).toBeDefined();
    expect(entries[0]!.attestation!.state).toBe("degraded");
  });

  it("distinct entry ids derive distinct fragments", async () => {
    await rig.auditLog.append("l2", "policy_decision", IDENTITY_ID, {}, "success");
    // Force a different timestamp so the synthesized entry_id differs.
    await new Promise((resolve) => setTimeout(resolve, 5));
    await rig.auditLog.append("l2", "approval_granted", IDENTITY_ID, {}, "success");
    await rig.auditLog.flush();
    const entries = await aggregateActivity(
      { auditLog: rig.auditLog, identityId: IDENTITY_ID },
      { limit: 10 },
    );
    expect(entries).toHaveLength(2);
    const fragments = entries.map((e) => e.attestation!.fragment);
    expect(fragments[0]).not.toBe(fragments[1]);
  });

  it("fragment shape is '<4hex>..<2hex>' (6 hex chars + dots)", async () => {
    await rig.auditLog.append("l2", "policy_decision", IDENTITY_ID, {}, "success");
    await rig.auditLog.flush();
    const entries = await aggregateActivity(
      { auditLog: rig.auditLog, identityId: IDENTITY_ID },
      { limit: 10 },
    );
    expect(entries).toHaveLength(1);
    const fragment = entries[0]!.attestation!.fragment;
    expect(fragment).toMatch(/^[0-9a-f]{4}\.\.[0-9a-f]{2}$/);
  });

  it("forged unsigned Castle Wall entries do not attribute to a victim or render verified", async () => {
    await rig.auditLog.append(
      "l1",
      "egress_blocked",
      IDENTITY_ID,
      {
        agent_id: "victim-agent-b",
        dest_host: "evil.example",
        dest_ip: "203.0.113.99",
        dest_port: 443,
        dest_protocol: "tcp",
      },
      "success",
    );
    await rig.auditLog.flush();

    const entries = await aggregateActivity(
      { auditLog: rig.auditLog, identityId: IDENTITY_ID },
      { limit: 10 },
    );
    expect(entries).toHaveLength(1);
    expect(entries[0]!.agent_id).toBeUndefined();
    expect(entries[0]!.display_template_args).not.toContainEqual({
      kind: "agent_id",
      value: "victim-agent-b",
    });
    expect(entries[0]!.attestation!.state).toBe("degraded");

    const filtered = await aggregateActivity(
      { auditLog: rig.auditLog, identityId: IDENTITY_ID },
      { agent_id: "victim-agent-b", limit: 10 },
    );
    expect(filtered).toHaveLength(0);
  });

  it("fails closed for off-list Castle Wall operations and wrong-layer Castle Wall operation tags", async () => {
    const cases: Array<{ layer: AuditEntry["layer"]; operation: string }> = [
      { layer: "l1", operation: "agent_upstream_call" },
      { layer: "l2", operation: "egress_blocked" },
      { layer: "l3", operation: "egress_blocked" },
      { layer: "l4", operation: "egress_blocked" },
    ];
    for (const item of cases) {
      await rig.auditLog.append(
        item.layer,
        item.operation,
        IDENTITY_ID,
        {
          agent_id: "victim-agent-b",
          agent_template: "claude-code",
          dest_host: "evil.example",
          dest_ip: "203.0.113.99",
          dest_port: 443,
          dest_protocol: "tcp",
        },
        "success",
      );
    }
    await rig.auditLog.flush();

    const entries = await aggregateActivity(
      {
        auditLog: rig.auditLog,
        identityId: IDENTITY_ID,
        pinnedProducerKeyB64url: producerPubB64,
        subjectFortressId: TEST_FORTRESS_ID,
      },
      { limit: 10 },
    );

    expect(entries).toHaveLength(cases.length);
    for (const entry of entries) {
      expect(entry.agent_id).toBeUndefined();
      expect(entry.display_template_args).not.toContainEqual({
        kind: "agent_id",
        value: "victim-agent-b",
      });
      expect(entry.attestation!.state).toBe("degraded");
    }

    const filtered = await aggregateActivity(
      {
        auditLog: rig.auditLog,
        identityId: IDENTITY_ID,
        pinnedProducerKeyB64url: producerPubB64,
        subjectFortressId: TEST_FORTRESS_ID,
      },
      { agent_id: "victim-agent-b", limit: 10 },
    );
    expect(filtered).toHaveLength(0);
  });

  it("rejects a valid victim signature stapled onto a forged activity row", async () => {
    const signed = signedVictimEgressEntry();
    await rig.auditLog.appendCritical({
      layer: signed.layer,
      operation: signed.operation,
      identity_id: signed.identity_id,
      timestamp: signed.timestamp,
      result: signed.result,
      details: {
        ...signed.details,
        dest_host: "evil.example.com",
        dest_ip: "203.0.113.200",
      },
    });
    await rig.auditLog.flush();

    const entries = await aggregateActivity(
      {
        auditLog: rig.auditLog,
        identityId: signed.identity_id,
        pinnedProducerKeyB64url: producerPubB64,
        subjectFortressId: TEST_FORTRESS_ID,
      },
      { limit: 10 },
    );

    expect(entries).toHaveLength(1);
    expect(entries[0]!.agent_id).toBeUndefined();
    expect(entries[0]!.attestation!.state).toBe("degraded");

    const filtered = await aggregateActivity(
      {
        auditLog: rig.auditLog,
        identityId: signed.identity_id,
        pinnedProducerKeyB64url: producerPubB64,
        subjectFortressId: TEST_FORTRESS_ID,
      },
      { agent_id: "victim-agent-b", limit: 10 },
    );
    expect(filtered).toHaveLength(0);
  });

  it("rejects a valid signature when the persisted top-level result is changed", async () => {
    const signed = signedVictimEgressEntry();
    await rig.auditLog.appendCritical({
      layer: signed.layer,
      operation: signed.operation,
      identity_id: signed.identity_id,
      timestamp: signed.timestamp,
      result: "failure",
      details: signed.details,
    });
    await rig.auditLog.flush();

    const entries = await aggregateActivity(
      {
        auditLog: rig.auditLog,
        identityId: signed.identity_id,
        pinnedProducerKeyB64url: producerPubB64,
        subjectFortressId: TEST_FORTRESS_ID,
      },
      { limit: 10 },
    );

    expect(entries).toHaveLength(1);
    expect(entries[0]!.agent_id).toBeUndefined();
    expect(entries[0]!.attestation!.state).toBe("degraded");
  });

  it("rejects a valid signature when a new top-level persisted field is unbound", async () => {
    const signed = signedVictimEgressEntry();
    const persisted = {
      ...signed,
      unbound_top_level_field: "must-not-be-ignored",
    } as AuditEntry & { unbound_top_level_field: string };

    expect(
      auditEntryAgentId(persisted, {
        pinnedProducerKeyB64url: producerPubB64,
        subjectFortressId: TEST_FORTRESS_ID,
      }),
    ).toBeNull();
  });
});
