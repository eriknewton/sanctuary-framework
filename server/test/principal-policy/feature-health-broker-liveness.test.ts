/**
 * Broker daemon process-liveness heartbeat — reader honesty invariants
 * (Option C, Erik-ratified). The `secret_broker_daemon` row.
 *
 * This is a process-liveness surface for the long-running `sanctuary
 * broker-server` MCP daemon. It is ADDITIVE on the now-generalized per-feature
 * provenance gate (#658) and replicates the CORRECTED Castle Wall Slice-2
 * pattern (#656/#657): a periodic signed heartbeat + a clean-stop stand-down
 * signal, so a deliberate stop is NOT a false-RED while a genuine silent death
 * still fires the alarm.
 *
 * HONEST SCOPE (every assertion below defends this): a heartbeat proves ONLY
 * that the daemon PROCESS is alive. It is NOT token-mint/deny correctness, NOT
 * keychain-reachability, and says nothing about the per-invocation `sanctuary
 * secrets` path. The row carries an EMPTY `invocationOps` set, so green
 * (`active`) is STRUCTURALLY impossible.
 *
 * BASIS: producer-signed by a dedicated broker liveness key. Entries are
 * written through a REAL AuditLog over MemoryStorage, and the reader must reject
 * marker-only, wrong-key, and replayed beats.
 */

import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { AuditLog, type AuditEntry, type SealedRegionVerdict } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { toBase64url } from "../../src/core/encoding.js";
import {
  BROKER_DAEMON_PRODUCER_SIGNATURE_SCHEME,
  buildFeatureHealthPanel,
  evaluateFeatureHealth,
  SLICE1_FEATURE_REGISTRY,
  type FeatureRegistryEntry,
  type FeatureHealthRow,
  type FeatureHealthPanel,
} from "../../src/principal-policy/feature-health.js";
import {
  BROKER_DAEMON_HEARTBEAT_OPERATION,
  BROKER_DAEMON_STAND_DOWN_OPERATION,
  BROKER_DAEMON_AUDIT_PROVENANCE_KEY,
  BROKER_DAEMON_AUDIT_PROVENANCE_VALUE,
} from "../../src/broker-mcp/liveness-constants.js";
import {
  buildBrokerProducerSignedDetails,
  brokerProducerMarkerDetails,
} from "../../src/broker-mcp/producer-signature.js";

const FORTRESS = "fortress:broker-test";
const NOW = 1_750_000_000_000;
// Inside the 10-minute freshness window.
const FRESH_TS = NOW - 60_000;
// Outside the 10-minute freshness window, inside the 24h digest window.
const STALE_TS = NOW - 30 * 60_000;
// Older still (used to order two lifecycle signals).
const OLDER_TS = NOW - 60 * 60_000;
// Beyond the future-skew tolerance.
const FUTURE_TS = NOW + 10 * 60_000;

const BROKER_ROW_ID = "secret_broker_daemon";
const FRESH_SELF_REPORTING_ROW_ID = "fresh_self_reporting_probe";
const FRESH_SELF_REPORTING_INVOCATION_OPERATION =
  "fresh_self_reporting_probe_invoked";
const BROKER_PRIV = ed25519.utils.randomPrivateKey();
const BROKER_PUB_B64 = toBase64url(ed25519.getPublicKey(BROKER_PRIV));
const WRONG_PRIV = ed25519.utils.randomPrivateKey();
const WRONG_PUB_B64 = toBase64url(ed25519.getPublicKey(WRONG_PRIV));

function newLog(): AuditLog {
  return new AuditLog(new MemoryStorage(), generateRandomKey());
}

let nextBrokerSeq = 1;

function signedBrokerDetails(
  operation:
    | typeof BROKER_DAEMON_HEARTBEAT_OPERATION
    | typeof BROKER_DAEMON_STAND_DOWN_OPERATION,
  tsMs: number,
  seq = nextBrokerSeq++,
  privateKey = BROKER_PRIV,
): Record<string, unknown> {
  return brokerProducerMarkerDetails(
    buildBrokerProducerSignedDetails({
      operation,
      capturedAtUnixMs: tsMs,
      seq,
      privateKey,
    }),
  );
}

function brokerRow(panel: { rows: FeatureHealthRow[] }): FeatureHealthRow {
  const r = panel.rows.find((x) => x.feature_id === BROKER_ROW_ID);
  if (!r) throw new Error(`no ${BROKER_ROW_ID} row`);
  return r;
}

function truncatedAuditLog(
  allEntries: AuditEntry[],
  effectivePageLimit: number,
): AuditLog {
  const fake = {
    query: async (
      options: Parameters<AuditLog["query"]>[0],
    ): ReturnType<AuditLog["query"]> => {
      let filtered = allEntries;
      if (options.since) {
        const since = new Date(options.since);
        filtered = filtered.filter((e) => new Date(e.timestamp) >= since);
      }
      if (options.layer) {
        filtered = filtered.filter((e) => e.layer === options.layer);
      }
      if (options.operation_type) {
        filtered = filtered.filter((e) => e.operation === options.operation_type);
      }
      if (options.identity_id !== undefined) {
        filtered = filtered.filter((e) => e.identity_id === options.identity_id);
      }
      const requestedLimit = options.limit ?? 50;
      const limit = Math.min(requestedLimit, effectivePageLimit);
      return {
        entries: filtered.slice(-limit),
        total: filtered.length,
        integrity_findings: [],
      };
    },
    // F2 BLOCKER-1 (round 3): feature-health folds the sealed-region verdict
    // into its cleanliness claim. This stub is a non-migrated fortress, so the
    // sealed region is not present (never a tamper signal).
    verifySealedRegion: async (): Promise<SealedRegionVerdict> => ({ status: "not_present" }),
  };
  return fake as unknown as AuditLog;
}

async function buildPanel(
  log: AuditLog,
  brokerPinnedProducerKeyB64url: string | null = BROKER_PUB_B64,
): Promise<FeatureHealthPanel> {
  return buildFeatureHealthPanel({
    protectionClaimSubject: FORTRESS,
    auditLog: log,
    originMachine: FORTRESS,
    now: NOW,
    brokerPinnedProducerKeyB64url,
  });
}

function freshSelfReportingFeature(): FeatureRegistryEntry {
  return {
    id: FRESH_SELF_REPORTING_ROW_ID,
    label: "Fresh self-reporting probe",
    layer: "l3",
    liveness: "self_reporting",
    invocationOps: Object.freeze(
      new Set<string>([FRESH_SELF_REPORTING_INVOCATION_OPERATION]),
    ),
    brokenZeroDetectable: true,
  };
}

function brokerHeartbeatEntry(tsMs: number): AuditEntry {
  return {
    layer: "l3",
    operation: BROKER_DAEMON_HEARTBEAT_OPERATION,
    identity_id: FORTRESS,
    result: "success",
    timestamp: new Date(tsMs).toISOString(),
    details: signedBrokerDetails(BROKER_DAEMON_HEARTBEAT_OPERATION, tsMs),
  };
}

function freshSelfReportingInvocationEntry(tsMs: number): AuditEntry {
  return {
    layer: "l3",
    operation: FRESH_SELF_REPORTING_INVOCATION_OPERATION,
    identity_id: FORTRESS,
    result: "success",
    timestamp: new Date(tsMs).toISOString(),
    details: {},
  };
}

/**
 * A genuine broker daemon liveness heartbeat: a broker-producer-signed l3 entry
 * carrying the broker provenance marker.
 */
async function appendBrokerHeartbeat(log: AuditLog, tsMs: number): Promise<void> {
  await log.appendCritical({
    layer: "l3",
    operation: BROKER_DAEMON_HEARTBEAT_OPERATION,
    identity_id: FORTRESS,
    result: "success",
    timestamp: new Date(tsMs).toISOString(),
    details: signedBrokerDetails(BROKER_DAEMON_HEARTBEAT_OPERATION, tsMs),
  });
}

/** A genuine intentional stand-down (clean broker-server shutdown). */
async function appendBrokerStandDown(log: AuditLog, tsMs: number): Promise<void> {
  await log.appendCritical({
    layer: "l3",
    operation: BROKER_DAEMON_STAND_DOWN_OPERATION,
    identity_id: FORTRESS,
    result: "success",
    timestamp: new Date(tsMs).toISOString(),
    details: signedBrokerDetails(BROKER_DAEMON_STAND_DOWN_OPERATION, tsMs),
  });
}

/** A heartbeat that OMITS the broker provenance marker — must not be counted. */
async function appendUnmarkedHeartbeat(log: AuditLog, tsMs: number): Promise<void> {
  await log.appendCritical({
    layer: "l3",
    operation: BROKER_DAEMON_HEARTBEAT_OPERATION,
    identity_id: FORTRESS,
    result: "success",
    timestamp: new Date(tsMs).toISOString(),
    details: { source: "broker-server" },
  });
}

async function appendBrokerHeartbeatDetails(
  log: AuditLog,
  tsMs: number,
  details: Record<string, unknown>,
): Promise<void> {
  await log.appendCritical({
    layer: "l3",
    operation: BROKER_DAEMON_HEARTBEAT_OPERATION,
    identity_id: FORTRESS,
    result: "success",
    timestamp: new Date(tsMs).toISOString(),
    details,
  });
}

describe("broker daemon liveness — registry row is honest by construction", () => {
  it("the secret_broker_daemon row exists, is self_reporting, and has EMPTY invocationOps (green is structurally impossible)", () => {
    const row = SLICE1_FEATURE_REGISTRY.find((f) => f.id === BROKER_ROW_ID);
    expect(row).toBeDefined();
    if (!row) return;
    expect(row.layer).toBe("l3");
    expect(row.liveness).toBe("self_reporting");
    // EMPTY invocation set: the `active` branch requires a fresh invocation, so
    // an empty set makes green unreachable.
    expect(row.invocationOps.size).toBe(0);
    expect(row.provenanceMarker).toEqual({
      key: BROKER_DAEMON_AUDIT_PROVENANCE_KEY,
      value: BROKER_DAEMON_AUDIT_PROVENANCE_VALUE,
    });
    expect(row.producerSignatureScheme).toBe(
      BROKER_DAEMON_PRODUCER_SIGNATURE_SCHEME,
    );
    expect(row.rejectNonMonotonicSignedLiveness).toBe(true);
    expect(row.noHeartbeatFaultWhenProducerKeyPresent).toBe(true);
    expect(row.brokenZeroDetectable).toBe(true);
  });

  it("the broker daemon liveness / stand-down ops are DISJOINT from the event-driven secret_broker token ops", () => {
    const daemon = SLICE1_FEATURE_REGISTRY.find((f) => f.id === BROKER_ROW_ID);
    const eventRow = SLICE1_FEATURE_REGISTRY.find((f) => f.id === "secret_broker");
    expect(daemon).toBeDefined();
    expect(eventRow).toBeDefined();
    if (!daemon || !eventRow) return;
    for (const op of daemon.livenessOps ?? new Set<string>()) {
      expect(eventRow.invocationOps.has(op)).toBe(false);
    }
    for (const op of daemon.standDownOps ?? new Set<string>()) {
      expect(eventRow.invocationOps.has(op)).toBe(false);
    }
    // And the heartbeat / stand-down ops are distinct from each other.
    expect(BROKER_DAEMON_HEARTBEAT_OPERATION).not.toBe(
      BROKER_DAEMON_STAND_DOWN_OPERATION,
    );
  });

  it("the existing event-driven secret_broker row is UNCHANGED next to the new daemon row", () => {
    const eventRow = SLICE1_FEATURE_REGISTRY.find((f) => f.id === "secret_broker");
    expect(eventRow).toBeDefined();
    if (!eventRow) return;
    expect(eventRow.label).toBe("Secret broker (selective disclosure)");
    expect(eventRow.liveness).toBe("event_driven");
    expect([...eventRow.invocationOps].sort()).toEqual(
      ["broker_token_denied", "broker_token_issued"].sort(),
    );
    expect(eventRow.brokenZeroDetectable).toBe(false);
    // No liveness/stand-down/marker leaked onto the event-driven row.
    expect(eventRow.livenessOps).toBeUndefined();
    expect(eventRow.standDownOps).toBeUndefined();
    expect(eventRow.provenanceMarker).toBeUndefined();
  });
});

describe("broker daemon liveness — the 9 honesty invariants", () => {
  // (1) The row can NEVER read active/green. Even a fresh heartbeat is liveness,
  // not request-correctness. With empty invocationOps the active branch is
  // unreachable; a fresh beat reads daemon-alive-but-idle `unknown`.
  it("can NEVER read active: a fresh heartbeat with no requests → unknown / alive_no_recent_enforcement", async () => {
    const log = newLog();
    await appendBrokerHeartbeat(log, FRESH_TS);
    const row = brokerRow(await buildPanel(log));
    expect(row.status).toBe("unknown");
    expect(row.status).not.toBe("active");
    expect(row.basis).toBe("alive_no_recent_enforcement");
  });

  // (2) Heartbeat-then-silent (no stand-down) → fault / dead_no_heartbeat.
  it("heartbeat then silence (no stand-down) → fault / dead_no_heartbeat", async () => {
    const log = newLog();
    // The daemon beat (stale), then went silent with NO stand-down: killed.
    await appendBrokerHeartbeat(log, STALE_TS);
    const row = brokerRow(await buildPanel(log));
    expect(row.status).toBe("fault");
    expect(row.basis).toBe("dead_no_heartbeat");
  });

  it("stale heartbeat is still found when unrelated audit volume truncates the global digest page", async () => {
    const pageLimit = 2;
    const heartbeat: AuditEntry = {
      layer: "l3",
      operation: BROKER_DAEMON_HEARTBEAT_OPERATION,
      identity_id: FORTRESS,
      result: "success",
      timestamp: new Date(STALE_TS).toISOString(),
      details: {
        source: "broker-server",
        [BROKER_DAEMON_AUDIT_PROVENANCE_KEY]:
          BROKER_DAEMON_AUDIT_PROVENANCE_VALUE,
      },
    };
    const unrelated: AuditEntry[] = [0, 1, 2].map((i) => ({
      layer: "l3",
      operation: "unrelated_l3_noise",
      identity_id: FORTRESS,
      result: "success",
      timestamp: new Date(FRESH_TS + i * 1000).toISOString(),
      details: { source: "noise" },
    }));

    const panel = await buildPanel(
      truncatedAuditLog([heartbeat, ...unrelated], pageLimit),
    );
    const row = brokerRow(panel);

    expect(row.status).toBe("fault");
    expect(row.basis).toBe("dead_no_heartbeat");
    expect(panel.disclosure.broker_daemon_silent_death_detectable).toBe(true);
  });

  it("targeted lifecycle self-truncation degrades detectability without corrupting fresh self-reporting rows", async () => {
    const pageLimit = 2;
    const brokerFeature = SLICE1_FEATURE_REGISTRY.find(
      (f) => f.id === BROKER_ROW_ID,
    );
    expect(brokerFeature).toBeDefined();
    if (!brokerFeature) return;
    const freshFeature = freshSelfReportingFeature();
    const heartbeats: AuditEntry[] = [0, 1, 2].map((i) =>
      brokerHeartbeatEntry(STALE_TS + i * 1000),
    );

    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: truncatedAuditLog(
        [...heartbeats, freshSelfReportingInvocationEntry(FRESH_TS)],
        pageLimit,
      ),
      registry: Object.freeze([brokerFeature, freshFeature]),
      originMachine: FORTRESS,
      now: NOW,
      brokerPinnedProducerKeyB64url: BROKER_PUB_B64,
    });
    const freshRow = panel.rows.find(
      (r) => r.feature_id === FRESH_SELF_REPORTING_ROW_ID,
    );

    expect(panel.audit_integrity_ok).toBe(true);
    expect(panel.disclosure.broker_daemon_silent_death_detectable).toBe(false);
    expect(panel.disclosure.silent_death_distinguished_from_intentional_stop).toBe(
      false,
    );
    expect(panel.disclosure.castle_wall_silent_death_is_unknown_not_green).toBe(
      true,
    );
    expect(freshRow).toBeDefined();
    expect(freshRow?.status).toBe("active");
    expect(freshRow?.basis).toBe("fresh_enforcement_evidence");
    expect(freshRow?.basis).not.toBe("freshness_scan_incomplete");
  });

  it("freshness-window truncation still degrades self-reporting rows to freshness_scan_incomplete", async () => {
    const pageLimit = 10_000;
    const freshEntries: AuditEntry[] = Array.from(
      { length: pageLimit + 1 },
      (_, i) => freshSelfReportingInvocationEntry(FRESH_TS + i),
    );

    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: truncatedAuditLog(freshEntries, pageLimit),
      registry: Object.freeze([freshSelfReportingFeature()]),
      originMachine: FORTRESS,
      now: NOW,
    });
    const row = panel.rows.find(
      (r) => r.feature_id === FRESH_SELF_REPORTING_ROW_ID,
    );

    expect(panel.audit_integrity_ok).toBe(true);
    expect(row).toBeDefined();
    expect(row?.status).toBe("unknown");
    expect(row?.basis).toBe("freshness_scan_incomplete");
  });

  // (3) Most-recent signal is a stand-down → unknown / intentionally_stopped.
  it("stale heartbeat THEN a more-recent stand-down → unknown / intentionally_stopped, not red", async () => {
    const log = newLog();
    await appendBrokerHeartbeat(log, OLDER_TS);
    await appendBrokerStandDown(log, STALE_TS);
    const row = brokerRow(await buildPanel(log));
    expect(row.status).toBe("unknown");
    expect(row.basis).toBe("intentionally_stopped");
    expect(row.status).not.toBe("fault");
    expect(row.status).not.toBe("active");
  });

  // (4) Came-back-then-died: a later heartbeat after a stand-down, then silence
  // → fault again. A stand-down does NOT permanently mute the alarm.
  it("stand-down THEN a later heartbeat THEN silence → fault again (stand-down does not permanently mute)", async () => {
    const log = newLog();
    await appendBrokerStandDown(log, OLDER_TS);
    // Daemon came back and beat AFTER the stand-down, then went silent.
    await appendBrokerHeartbeat(log, STALE_TS);
    const row = brokerRow(await buildPanel(log));
    expect(row.status).toBe("fault");
    expect(row.basis).toBe("dead_no_heartbeat");
  });

  // (5) No heartbeat ever with a broker producer key → fault /
  // dead_no_heartbeat. The key proves this producer is provisioned to beat.
  it("no heartbeat ever with a broker producer key → fault / dead_no_heartbeat", async () => {
    const log = newLog();
    const row = brokerRow(await buildPanel(log));
    expect(row.status).toBe("fault");
    expect(row.basis).toBe("dead_no_heartbeat");
    expect(row.status).not.toBe("active");
  });

  // (6) A beat missing the broker marker is NOT counted (foreign L3 producer
  // reusing the op name cannot fake liveness).
  it("a heartbeat missing the broker provenance marker is NOT counted → dead_no_heartbeat", async () => {
    const log = newLog();
    await appendUnmarkedHeartbeat(log, FRESH_TS);
    const row = brokerRow(await buildPanel(log));
    // The unmarked beat is invisible to the reader; with the broker key present,
    // no verified beat means the daemon is not alive.
    expect(row.status).toBe("fault");
    expect(row.basis).toBe("dead_no_heartbeat");
  });

  it("an unsigned marker-only heartbeat is NOT counted as alive", async () => {
    const log = newLog();
    await appendBrokerHeartbeatDetails(log, FRESH_TS, {
      source: "broker-server",
      [BROKER_DAEMON_AUDIT_PROVENANCE_KEY]:
        BROKER_DAEMON_AUDIT_PROVENANCE_VALUE,
    });
    const row = brokerRow(await buildPanel(log));
    expect(row.status).toBe("fault");
    expect(row.basis).toBe("dead_no_heartbeat");
    expect(row.basis).not.toBe("alive_no_recent_enforcement");
  });

  it("a wrong-key signed heartbeat is NOT counted as alive", async () => {
    const log = newLog();
    await appendBrokerHeartbeatDetails(
      log,
      FRESH_TS,
      signedBrokerDetails(
        BROKER_DAEMON_HEARTBEAT_OPERATION,
        FRESH_TS,
        50,
        WRONG_PRIV,
      ),
    );
    const row = brokerRow(await buildPanel(log));
    expect(row.status).toBe("fault");
    expect(row.basis).toBe("dead_no_heartbeat");
    expect(WRONG_PUB_B64).not.toBe(BROKER_PUB_B64);
  });

  it("a non-monotonic signed heartbeat is rejected as replayed evidence", async () => {
    const log = newLog();
    await appendBrokerHeartbeatDetails(
      log,
      STALE_TS,
      signedBrokerDetails(BROKER_DAEMON_HEARTBEAT_OPERATION, STALE_TS, 80),
    );
    await appendBrokerHeartbeatDetails(
      log,
      FRESH_TS,
      signedBrokerDetails(BROKER_DAEMON_HEARTBEAT_OPERATION, FRESH_TS, 79),
    );
    const row = brokerRow(await buildPanel(log));
    expect(row.status).toBe("fault");
    expect(row.basis).toBe("dead_no_heartbeat");
    expect(row.basis).not.toBe("alive_no_recent_enforcement");
  });

  // (7) Tainted read → unknown (never green, never a trusted red).
  it("an integrity-tainted read forces unknown / integrity_tainted even with a fresh heartbeat", async () => {
    const log = newLog();
    await appendBrokerHeartbeat(log, FRESH_TS);
    // Inject an integrity finding via evaluateFeatureHealth with integrityOk=false.
    const feature = SLICE1_FEATURE_REGISTRY.find((f) => f.id === BROKER_ROW_ID);
    expect(feature).toBeDefined();
    if (!feature) return;
    const { entries } = await log.query({ limit: 10_000 });
    const row = evaluateFeatureHealth({
      feature,
      entries,
      freshnessEntries: entries,
      originMachine: FORTRESS,
      now: NOW,
      freshnessWindowMs: 10 * 60_000,
      integrityOk: false,
    });
    expect(row.status).toBe("unknown");
    expect(row.basis).toBe("integrity_tainted");
  });

  // (8) Future-skew rejection: a future-dated heartbeat does not register fresh,
  // and (since no other liveness exists) reads dead, not alive.
  it("a future-dated heartbeat beyond skew is rejected → dead_no_heartbeat (not alive)", async () => {
    const log = newLog();
    await appendBrokerHeartbeat(log, FUTURE_TS);
    const row = brokerRow(await buildPanel(log));
    expect(row.status).toBe("fault");
    expect(row.basis).toBe("dead_no_heartbeat");
    expect(row.status).not.toBe("active");
  });

  // (9) Fault precedence over a co-occurring stand-down: a heartbeat AFTER the
  // last stand-down means the daemon came back and beat, then died → the alarm
  // fires; the stale stand-down does not suppress a fresher silent death.
  it("a heartbeat strictly more recent than the last stand-down → fault (fault/death precedence over stale stand-down)", async () => {
    const log = newLog();
    await appendBrokerStandDown(log, STALE_TS);
    // A heartbeat AFTER the stand-down (still stale, so not fresh), then silence.
    await appendBrokerHeartbeat(log, STALE_TS + 60_000);
    const row = brokerRow(await buildPanel(log));
    expect(row.status).toBe("fault");
    expect(row.basis).toBe("dead_no_heartbeat");
  });
});

describe("broker daemon liveness — green stays structurally impossible", () => {
  it("token activity (broker_token_issued) on l3 does NOT make the DAEMON row green; it lands on the event-driven row instead", async () => {
    const log = newLog();
    // A real token decision AND a fresh daemon heartbeat in the same window.
    await log.appendCritical({
      layer: "l3",
      operation: "broker_token_issued",
      identity_id: FORTRESS,
      result: "success",
      timestamp: new Date(FRESH_TS).toISOString(),
      details: {},
    });
    await appendBrokerHeartbeat(log, FRESH_TS);
    const panel = await buildPanel(log);
    // The DAEMON (process-liveness) row never reads active: a token decision is
    // NOT one of its invocation ops (its invocationOps is empty), and a heartbeat
    // is not request-correctness. It reads daemon-alive-but-idle unknown.
    const daemon = brokerRow(panel);
    expect(daemon.status).not.toBe("active");
    expect(daemon.status).toBe("unknown");
    expect(daemon.invocation_count).toBe(0);
    // The token decision correctly lands on the EVENT-DRIVEN secret_broker row.
    const eventRow = panel.rows.find((x) => x.feature_id === "secret_broker");
    expect(eventRow?.status).toBe("active");
    expect(eventRow?.invocation_count).toBe(1);
  });
});

describe("broker daemon liveness — disclosure coexists honestly", () => {
  it("daemon silent-death is detectable AND event-driven broken-zero stays undetectable", async () => {
    const log = newLog();
    const panel = await buildPanel(log);
    expect(panel.disclosure.broker_daemon_silent_death_detectable).toBe(true);
    // Both facts coexist: the event-driven broken-zero caveat is unchanged.
    expect(panel.disclosure.broken_zero_undetectable_for_event_driven).toBe(true);
  });
});
