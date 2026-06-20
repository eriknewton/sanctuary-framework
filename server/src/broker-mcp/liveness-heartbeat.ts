/**
 * Secret-broker daemon liveness heartbeat PRODUCER (Option C, Erik-ratified).
 *
 * Factored out of the `broker-server` CLI wiring so it can be unit-tested with
 * an injected `AuditLog` + fake timers (mirroring the Castle Wall heartbeat
 * producer in `castle-wall/runtime/macos-daemon.ts`) without spinning up the MCP
 * server. The wiring in `cli.ts` just calls `startBrokerLivenessHeartbeat(...)`
 * after `server.connect(transport)` and arranges for `standDown()` on SIGTERM /
 * SIGINT / transport close.
 *
 * HONESTY (do NOT overclaim): a beat proves ONLY that this long-running daemon
 * PROCESS is alive. It is NOT a token-mint/deny correctness signal, NOT a
 * keychain-reachable signal, and says nothing about the per-invocation
 * `sanctuary secrets` path. The reader keeps the matching feature-health row's
 * `invocationOps` EMPTY so a beat can NEVER earn green - see
 * `principal-policy/feature-health.ts`.
 *
 * BASIS: a DIRECT channel-basis `auditLog.append` (provenance marker only, no
 * producer signature). The broker has no per-event producer-signing infra; this
 * is the SAME basis the Castle Wall heartbeat uses on a non-key-bearing host. A
 * forged in-process beat can only relabel a real silent-death `fault` to a
 * non-green `unknown`, never manufacture green.
 */

import type { AuditLog } from "../operational/audit-log.js";
import {
  BROKER_DAEMON_AUDIT_LAYER,
  BROKER_DAEMON_HEARTBEAT_OPERATION,
  BROKER_DAEMON_STAND_DOWN_OPERATION,
  BROKER_DAEMON_AUDIT_PROVENANCE_KEY,
  BROKER_DAEMON_AUDIT_PROVENANCE_VALUE,
  BROKER_DAEMON_HEARTBEAT_INTERVAL_SECONDS,
} from "./liveness-constants.js";

export interface BrokerLivenessHeartbeatOptions {
  /** Audit log the broker daemon shares with the rest of the fortress. */
  auditLog: AuditLog;
  /** Identity id stamped on the audit entries (the daemon's fortress id). */
  fortressId: string;
  /** Override the cadence (seconds) for tests. Defaults to ~45s. */
  intervalSeconds?: number;
}

export interface BrokerLivenessHeartbeatHandle {
  /**
   * Stand the daemon down on a clean stop: clear the interval, append the
   * stand-down marker, flush. Idempotent - a second call is a no-op so a
   * SIGTERM-then-SIGINT (or a transport-close racing a signal) cannot double
   * emit. Resolves even if the append/flush fails (fail toward the alarm).
   */
  standDown: () => Promise<void>;
  /** Clear the interval WITHOUT emitting a stand-down. For test teardown only. */
  stop: () => void;
}

/**
 * Build the marker fields for a heartbeat / stand-down entry from FIXED fields
 * only (no untrusted spread), provenance marker stamped LAST - mirroring the
 * Castle Wall producer so a forger cannot pre-seed a field that out-ranks the
 * marker.
 */
function brokerMarkerDetails(): Record<string, unknown> {
  return {
    source: "broker-server",
    // Provenance marker LAST, constructed fields only (no untrusted spread).
    [BROKER_DAEMON_AUDIT_PROVENANCE_KEY]: BROKER_DAEMON_AUDIT_PROVENANCE_VALUE,
  };
}

/**
 * Start the periodic liveness heartbeat. Emits one beat IMMEDIATELY, then on a
 * ~45s interval. The interval is `.unref()`ed so it never keeps the event loop
 * alive on its own. A write failure is swallowed (the reader fails toward the
 * alarm: a MISSING beat reads as silent death, so a dropped beat is surfaced
 * honestly rather than masked, and a heartbeat write must never crash the
 * daemon).
 */
export function startBrokerLivenessHeartbeat(
  opts: BrokerLivenessHeartbeatOptions,
): BrokerLivenessHeartbeatHandle {
  const { auditLog, fortressId } = opts;
  const intervalMs =
    (opts.intervalSeconds ?? BROKER_DAEMON_HEARTBEAT_INTERVAL_SECONDS) * 1000;

  const emitBeat = async (): Promise<void> => {
    try {
      await auditLog.append(
        BROKER_DAEMON_AUDIT_LAYER,
        BROKER_DAEMON_HEARTBEAT_OPERATION,
        fortressId,
        brokerMarkerDetails(),
        "success",
      );
      await auditLog.flush();
    } catch {
      // A heartbeat write failure must never crash the daemon. The reader's
      // silent-death detection fails toward an alarm (a MISSING heartbeat reads
      // as fault), so a dropped beat is surfaced honestly rather than masked.
    }
  };

  // Emit one beat immediately so a daemon that dies seconds after boot still has
  // a prior-liveness signal on the chain (the reader only raises the silent-death
  // alarm once it has proof the producer was running).
  void emitBeat();

  let interval: NodeJS.Timeout | undefined = setInterval(() => {
    void emitBeat();
  }, intervalMs);
  interval.unref();

  let stoodDown = false;

  const stop = (): void => {
    if (interval === undefined) return;
    clearInterval(interval);
    interval = undefined;
  };

  const standDown = async (): Promise<void> => {
    if (stoodDown) return;
    stoodDown = true;
    stop();
    try {
      await auditLog.append(
        BROKER_DAEMON_AUDIT_LAYER,
        BROKER_DAEMON_STAND_DOWN_OPERATION,
        fortressId,
        brokerMarkerDetails(),
        "success",
      );
      await auditLog.flush();
    } catch {
      // A stand-down write failure must never crash the shutdown path. Without a
      // recorded stand-down the reader reads this quiet window as a silent death
      // (fails toward the alarm), which is the honest fallback.
    }
  };

  return { standDown, stop };
}
