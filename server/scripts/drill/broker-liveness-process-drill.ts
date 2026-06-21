#!/usr/bin/env tsx
/**
 * Broker liveness signed-heartbeat drill.
 *
 * This is intentionally in-memory: it exercises the real AuditLog and
 * feature-health reader without starting a broker subprocess. The assertions
 * pin the security property the process drill cares about: marker-only and
 * replayed broker beats must never read alive.
 */

import { strict as assert } from "node:assert";

import { ed25519 } from "@noble/curves/ed25519";

import { buildFeatureHealthPanel } from "../../src/principal-policy/feature-health.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { toBase64url } from "../../src/core/encoding.js";
import {
  BROKER_DAEMON_AUDIT_PROVENANCE_KEY,
  BROKER_DAEMON_AUDIT_PROVENANCE_VALUE,
  BROKER_DAEMON_HEARTBEAT_OPERATION,
} from "../../src/broker-mcp/liveness-constants.js";
import {
  buildBrokerProducerSignedDetails,
  brokerProducerMarkerDetails,
} from "../../src/broker-mcp/producer-signature.js";

const FORTRESS = "fortress:broker-liveness-drill";
const NOW = 1_750_000_000_000;
const FRESH_TS = NOW - 60_000;
const STALE_TS = NOW - 30 * 60_000;

const privateKey = ed25519.utils.randomPrivateKey();
const publicKeyB64 = toBase64url(ed25519.getPublicKey(privateKey));

function newLog(): AuditLog {
  return new AuditLog(new MemoryStorage(), generateRandomKey());
}

function signedDetails(tsMs: number, seq: number): Record<string, unknown> {
  return brokerProducerMarkerDetails(
    buildBrokerProducerSignedDetails({
      operation: BROKER_DAEMON_HEARTBEAT_OPERATION,
      capturedAtUnixMs: tsMs,
      seq,
      privateKey,
    }),
  );
}

async function appendHeartbeat(
  log: AuditLog,
  topLevelTsMs: number,
  details: Record<string, unknown>,
): Promise<void> {
  await log.appendCritical({
    layer: "l3",
    operation: BROKER_DAEMON_HEARTBEAT_OPERATION,
    identity_id: FORTRESS,
    result: "success",
    timestamp: new Date(topLevelTsMs).toISOString(),
    details,
  });
}

async function brokerRow(log: AuditLog) {
  const panel = await buildFeatureHealthPanel({
    auditLog: log,
    originMachine: FORTRESS,
    now: NOW,
    brokerPinnedProducerKeyB64url: publicKeyB64,
  });
  const row = panel.rows.find((r) => r.feature_id === "secret_broker_daemon");
  assert(row, "secret_broker_daemon row exists");
  return row;
}

const valid = newLog();
await appendHeartbeat(valid, FRESH_TS, signedDetails(FRESH_TS, 1));
const validRow = await brokerRow(valid);
assert.equal(validRow.status, "unknown");
assert.equal(validRow.basis, "alive_no_recent_enforcement");

const forged = newLog();
await appendHeartbeat(forged, FRESH_TS, {
  source: "broker-server",
  [BROKER_DAEMON_AUDIT_PROVENANCE_KEY]: BROKER_DAEMON_AUDIT_PROVENANCE_VALUE,
});
const forgedRow = await brokerRow(forged);
assert.notEqual(forgedRow.basis, "alive_no_recent_enforcement");
assert.equal(forgedRow.basis, "dead_no_heartbeat");

const replayed = newLog();
const oldSignedBody = signedDetails(STALE_TS, 10);
await appendHeartbeat(replayed, STALE_TS, oldSignedBody);
await appendHeartbeat(replayed, STALE_TS + 1000, signedDetails(STALE_TS + 1000, 11));
await appendHeartbeat(replayed, FRESH_TS, oldSignedBody);
const replayedRow = await brokerRow(replayed);
assert.notEqual(replayedRow.basis, "alive_no_recent_enforcement");
assert.equal(replayedRow.basis, "dead_no_heartbeat");

const noBeats = newLog();
const noBeatRow = await brokerRow(noBeats);
assert.equal(noBeatRow.basis, "dead_no_heartbeat");

console.log("broker liveness drill passed");
