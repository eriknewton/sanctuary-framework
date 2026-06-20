/**
 * Broker daemon process-liveness heartbeat — reader honesty invariants
 * (Option C, Erik-ratified). The `secret_broker_daemon` row.
 *
 * This is a process-liveness surface for the long-running `sanctuary
 * broker-server` MCP daemon. It is ADDITIVE on the now-generalized per-feature
 * provenance gate (#658) and replicates the CORRECTED Castle Wall Slice-2
 * pattern (#656/#657): a periodic channel-marker heartbeat + a clean-stop
 * stand-down signal, so a deliberate stop is NOT a false-RED while a genuine
 * silent death still fires the alarm.
 *
 * HONEST SCOPE (every assertion below defends this): a heartbeat proves ONLY
 * that the daemon PROCESS is alive. It is NOT token-mint/deny correctness, NOT
 * keychain-reachability, and says nothing about the per-invocation `sanctuary
 * secrets` path. The row carries an EMPTY `invocationOps` set, so green
 * (`active`) is STRUCTURALLY impossible.
 *
 * BASIS: channel/marker only (no producer signature) - exactly the basis a
 * genuine Castle Wall heartbeat uses on a non-key-bearing host. Entries are
 * written through a REAL AuditLog over MemoryStorage (exactly what an in-process
 * writer can do), and the reader's verdict is asserted.
 */

import { describe, expect, it } from "vitest";

import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  buildFeatureHealthPanel,
  evaluateFeatureHealth,
  SLICE1_FEATURE_REGISTRY,
  type FeatureHealthRow,
  type FeatureHealthPanel,
} from "../../src/principal-policy/feature-health.js";
import {
  BROKER_DAEMON_HEARTBEAT_OPERATION,
  BROKER_DAEMON_STAND_DOWN_OPERATION,
  BROKER_DAEMON_AUDIT_PROVENANCE_KEY,
  BROKER_DAEMON_AUDIT_PROVENANCE_VALUE,
} from "../../src/broker-mcp/liveness-constants.js";

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

function newLog(): AuditLog {
  return new AuditLog(new MemoryStorage(), generateRandomKey());
}

function brokerRow(panel: { rows: FeatureHealthRow[] }): FeatureHealthRow {
  const r = panel.rows.find((x) => x.feature_id === BROKER_ROW_ID);
  if (!r) throw new Error(`no ${BROKER_ROW_ID} row`);
  return r;
}

async function buildPanel(log: AuditLog): Promise<FeatureHealthPanel> {
  return buildFeatureHealthPanel({
    auditLog: log,
    originMachine: FORTRESS,
    now: NOW,
  });
}

/**
 * A genuine broker daemon liveness heartbeat — the SHAPE THE REAL PRODUCER
 * EMITS (`broker-mcp/liveness-heartbeat.ts`): a direct channel-basis append on
 * l3 carrying the broker provenance marker and NO producer signature.
 */
async function appendBrokerHeartbeat(log: AuditLog, tsMs: number): Promise<void> {
  await log.appendCritical({
    layer: "l3",
    operation: BROKER_DAEMON_HEARTBEAT_OPERATION,
    identity_id: FORTRESS,
    result: "success",
    timestamp: new Date(tsMs).toISOString(),
    details: {
      source: "broker-server",
      [BROKER_DAEMON_AUDIT_PROVENANCE_KEY]: BROKER_DAEMON_AUDIT_PROVENANCE_VALUE,
    },
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
    details: {
      source: "broker-server",
      [BROKER_DAEMON_AUDIT_PROVENANCE_KEY]: BROKER_DAEMON_AUDIT_PROVENANCE_VALUE,
    },
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
    // Channel/marker basis only: a provenance marker, NO producer-signature
    // scheme (the broker has no per-event signing infra).
    expect(row.provenanceMarker).toEqual({
      key: BROKER_DAEMON_AUDIT_PROVENANCE_KEY,
      value: BROKER_DAEMON_AUDIT_PROVENANCE_VALUE,
    });
    expect(row.producerSignatureScheme).toBeUndefined();
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

  // (5) No heartbeat ever → unknown / no_evidence_self_reporting (no fabricated
  // death alarm for a daemon that was never observed running).
  it("no heartbeat ever → unknown / no_evidence_self_reporting (never a fabricated death alarm)", async () => {
    const log = newLog();
    const row = brokerRow(await buildPanel(log));
    expect(row.status).toBe("unknown");
    expect(row.basis).toBe("no_evidence_self_reporting");
    expect(row.status).not.toBe("fault");
  });

  // (6) A beat missing the broker marker is NOT counted (foreign L3 producer
  // reusing the op name cannot fake liveness).
  it("a heartbeat missing the broker provenance marker is NOT counted → no_evidence_self_reporting", async () => {
    const log = newLog();
    await appendUnmarkedHeartbeat(log, FRESH_TS);
    const row = brokerRow(await buildPanel(log));
    // The unmarked beat is invisible to the reader, so it reads as if no beat
    // ever happened — never alive, never a death alarm.
    expect(row.status).toBe("unknown");
    expect(row.basis).toBe("no_evidence_self_reporting");
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
  // and (since no other liveness exists) reads as no-evidence, not alive.
  it("a future-dated heartbeat beyond skew is rejected → no_evidence_self_reporting (not alive)", async () => {
    const log = newLog();
    await appendBrokerHeartbeat(log, FUTURE_TS);
    const row = brokerRow(await buildPanel(log));
    expect(row.status).toBe("unknown");
    expect(row.basis).toBe("no_evidence_self_reporting");
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
