/**
 * The canary monitoring-origin exclusion, driven through the real consumer
 * functions: the observe adapter and refresh, the evidence-pack inventory, the
 * posture verdict counts and audit digest, and the per-rule report. Drops to
 * the canary tuple leave counts and candidates; near misses, hostful rows and
 * allows stay counted, and a canary drop stays enforcement evidence.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";
import * as C from "../../../src/castle-wall/constants.js";
import { attributeFlows } from "../../../src/castle-wall/audit/per-rule-report.js";
import { isMonitoringOriginDestination, isMonitoringOriginDrop } from "../../../src/castle-wall/liveness/monitoring-origin.js";
import { flowEventFromAuditEntry } from "../../../src/castle-wall/observe/adapter.js";
import { inProcessRefreshLock, refreshCandidatesFromAudit } from "../../../src/castle-wall/observe/refresh.js";
import { ObserveStore } from "../../../src/castle-wall/observe/store.js";
import type { CandidateObservation } from "../../../src/castle-wall/observe/types.js";
import { producerSigningBytes } from "../../../src/castle-wall/runtime/producer-signature.js";
import { StateStore } from "../../../src/cognitive/state-store.js";
import { createIdentity } from "../../../src/core/identity.js";
import { derivePurposeKey } from "../../../src/core/key-derivation.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { buildInventorySnapshot } from "../../../src/evidence-pack/inventory.js";
import { AuditLog, type AuditEntry } from "../../../src/operational/audit-log.js";
import { buildAuditDigest, buildCastleWallPosture } from "../../../src/principal-policy/posture.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { persistStoredIdentity } from "../../util/persist-stored-identity.js";

interface Case { name: string; operation: string; shape: "nested" | "flat"; details: Record<string, unknown>; excluded: boolean }
const CASES = (JSON.parse(readFileSync(join(__dirname, "fixtures", "audit-canary-entries.json"), "utf8")) as { cases: Case[] }).cases;
const drops = CASES.filter(c => c.operation === "egress_blocked");
const canaryDrops = drops.filter(c => c.excluded);
const nearMisses = drops.filter(c => !c.excluded);
const allow = CASES.find(c => c.operation === "egress_allowed")!;

const priv = ed25519.utils.randomPrivateKey();
const pub = Buffer.from(ed25519.getPublicKey(priv)).toString("base64url");
const FORTRESS = "fortress:test";
const SUBJECT = `${FORTRESS}/uid-502`;
const NOW = Date.parse("2026-11-09T12:00:00Z");
const SIGNED_AT = NOW - 1000;
let seq = 1;

function signed(operation: string, details: Record<string, unknown>, timestamp = new Date(SIGNED_AT).toISOString()): AuditEntry {
  const s = seq++;
  const body = JSON.stringify({ timestamp, layer: "l1", operation, identity_id: SUBJECT, result: "failure", details });
  const sig = ed25519.sign(producerSigningBytes(body, SIGNED_AT, s), priv);
  return {
    timestamp, layer: "l1", operation, identity_id: SUBJECT, result: "failure",
    details: {
      ...details, seq: s,
      [C.CASTLE_WALL_AUDIT_PROVENANCE_KEY]: C.CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      [C.CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: Buffer.from(sig).toString("base64url"),
      [C.CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: C.CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      [C.CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: body,
      [C.CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: SIGNED_AT,
      [C.CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: C.CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
    },
  } as AuditEntry;
}
const channel = (operation: string, details: Record<string, unknown>): AuditEntry => ({
  timestamp: new Date(SIGNED_AT).toISOString(), layer: "l1", operation, identity_id: SUBJECT, result: "failure",
  details: { ...details, [C.CASTLE_WALL_AUDIT_PROVENANCE_KEY]: C.CASTLE_WALL_AUDIT_PROVENANCE_VALUE },
} as AuditEntry);
const ATTRIBUTION = { pinnedProducerKeyB64url: pub, subjectFortressId: FORTRESS };

async function logWith(entries: AuditEntry[]): Promise<AuditLog> {
  const audit = new AuditLog(new MemoryStorage(), generateRandomKey());
  for (const e of entries) await audit.appendCritical({ layer: e.layer, operation: e.operation, identity_id: e.identity_id, result: e.result, timestamp: e.timestamp, details: e.details });
  return audit;
}

describe("monitoring-origin predicate", () => {
  it("matches the hostless canary tuple only", () => {
    expect(isMonitoringOriginDestination({ ip: "192.0.2.254", port: 9, protocol: "tcp", host: null })).toBe(true);
    expect(isMonitoringOriginDestination({ ip: "192.0.2.254", port: 9, protocol: "tcp" })).toBe(true);
    for (const t of [{ ip: "192.0.2.253", port: 9, protocol: "tcp" }, { ip: "192.0.2.254", port: 10, protocol: "tcp" }, { ip: "192.0.2.254", port: 9, protocol: "udp" },
      { ip: "192.0.2.254", port: 9, protocol: "tcp", host: "canary.example" }, { ip: "192.0.2.254", port: 9, protocol: "tcp", host: "" }]) {
      expect(isMonitoringOriginDestination(t), JSON.stringify(t)).toBe(false);
    }
    for (const c of CASES) expect(isMonitoringOriginDrop(c.operation, c.details), c.name).toBe(c.excluded);
  });
});

describe("observe adapter and refresh", () => {
  it("returns no flow event for a canary drop in either shape and keeps every near miss", () => {
    for (const c of canaryDrops) expect(flowEventFromAuditEntry(signed(c.operation, c.details), ATTRIBUTION), c.name).toBeNull();
    for (const c of nearMisses) expect(flowEventFromAuditEntry(signed(c.operation, c.details), ATTRIBUTION), c.name).not.toBeNull();
  });

  it("mints no candidate from a refresh over a chain holding canary drops", async () => {
    const masterKey = generateRandomKey();
    const stateStorage = new MemoryStorage();
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const { storedIdentity } = createIdentity("operator", identityEncKey, "passphrase");
    await persistStoredIdentity(stateStorage, masterKey, storedIdentity);
    const store = new ObserveStore(new StateStore(stateStorage, masterKey), {
      identityId: storedIdentity.identity_id, encryptedPrivateKey: storedIdentity.encrypted_private_key, identityEncryptionKey: identityEncKey,
    });
    const auditLog = new AuditLog(new MemoryStorage(), masterKey);
    const nearMiss = nearMisses.find(c => c.name === "near miss address")!;
    for (const e of [...canaryDrops, nearMiss].map(c => signed(c.operation, c.details))) {
      await auditLog.appendCritical({ layer: e.layer, operation: e.operation, identity_id: e.identity_id, result: e.result, timestamp: e.timestamp, details: e.details });
    }
    const outcome = await refreshCandidatesFromAudit({
      auditLog, store, readAllowlist: async () => ({ status: "ok", rules: [] }), lock: inProcessRefreshLock(),
      now: new Date(NOW), pinnedProducerKeyB64url: pub, subjectFortressId: FORTRESS,
    });
    expect(outcome.status).toBe("refreshed");
    const rows = [...(await store.listCandidates()).values()];
    expect(rows.map(r => r.ip)).toEqual(["192.0.2.253"]);
  });
});

describe("evidence-pack inventory", () => {
  const candidate = (ip: string, port: number, protocol: "tcp" | "udp", host: string | null, disposition: "denied" | "allowed" = "denied"): CandidateObservation => ({
    agent_id: "agent-1", agent_template: "claude-code", host, ip, port, protocol, hostname_source: null,
    first_seen: "2026-11-09T11:00:00.000Z", last_seen: "2026-11-09T11:59:00.000Z", times_seen: 3,
    would_be_disposition: disposition, exfil_risk: false,
  } as unknown as CandidateObservation);

  it("shows no row for a stored legacy canary candidate and keeps every near miss", () => {
    const records = [
      candidate("192.0.2.254", 9, "tcp", null),
      candidate("192.0.2.253", 9, "tcp", null),
      candidate("192.0.2.254", 10, "tcp", null),
      candidate("192.0.2.254", 9, "udp", null),
      candidate("192.0.2.254", 9, "tcp", "canary.example"),
    ];
    const snapshot = buildInventorySnapshot({ observedDestinations: { ok: true, records } });
    const outcome = snapshot.observed_destinations as unknown as { status: string; value: Array<{ host: string; port: number | null }> };
    expect(outcome.status).toBe("populated");
    const rows = outcome.value;
    const labels = JSON.stringify(rows);
    expect(rows).toHaveLength(4);
    expect(labels).toContain("192.0.2.253");
    expect(labels).toContain("canary.example");
    expect(rows.filter(r => r.host === "192.0.2.254" && r.port === 9)).toHaveLength(1);
  });
});

describe("posture", () => {
  it("removes canary drops from the blocked count while they stay enforcement evidence", async () => {
    const onlyCanary = await logWith(canaryDrops.map(c => channel(c.operation, c.details)));
    const posture = await buildCastleWallPosture({ auditLog: onlyCanary, originMachine: "test", platform: "linux", now: NOW, protectionClaimSubject: SUBJECT });
    expect(posture.verdict_counts.blocked).toBe(0);
    expect(posture.last_enforcement_evidence_at).not.toBeNull();
    const mixed = await logWith([...drops, allow].map(c => channel(c.operation, c.details)));
    const counted = await buildCastleWallPosture({ auditLog: mixed, originMachine: "test", platform: "linux", now: NOW, protectionClaimSubject: SUBJECT });
    expect(counted.verdict_counts.blocked).toBe(nearMisses.length);
    expect(counted.verdict_counts.allowed).toBe(1);
  });

  it("removes canary drops from the digest kernel blocks and blocked destinations, keeps allows and near misses", async () => {
    const audit = await logWith([...drops, allow].map(c => channel(c.operation, c.details)));
    const digest = await buildAuditDigest({ auditLog: audit, originMachine: "test", protectionClaimSubject: null, now: NOW });
    expect(digest.kernel_blocks).toBe(nearMisses.length);
    expect(digest.kernel_allows).toBe(1);
    expect(digest.blocked_destinations.reduce((n, row) => n + row.blocks, 0)).toBe(nearMisses.length);
    // The one 192.0.2.254:9 row is the udp near miss; the two canary drops add nothing to it.
    expect(digest.blocked_destinations.find(row => row.destination === "192.0.2.254:9")?.blocks).toBe(1);
  });

  it("reads the signed body, not the stored metadata, for a producer-verified digest entry", async () => {
    const canary = canaryDrops.find(c => c.shape === "flat")!;
    const audit = await logWith([signed(canary.operation, canary.details), signed("egress_blocked", nearMisses.find(c => c.shape === "flat")!.details)]);
    const digest = await buildAuditDigest({ auditLog: audit, originMachine: FORTRESS, protectionClaimSubject: SUBJECT, now: NOW, pinnedProducerKeyB64url: pub });
    expect(digest.kernel_blocks).toBe(1);
  });
});

describe("per-rule report", () => {
  it("attributes no flow for a canary drop and keeps near misses and the allow", () => {
    const flows = attributeFlows([...drops, allow].map(c => channel(c.operation, c.details)));
    expect(flows.filter(f => f.decision === "deny")).toHaveLength(nearMisses.length);
    expect(flows.filter(f => f.decision === "allow")).toHaveLength(1);
  });
});
