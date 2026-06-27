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
 * BASIS: a producer-signed heartbeat. The reader re-verifies the signature
 * against the broker liveness producer public key and rejects unsigned,
 * wrong-key, and replayed beats.
 */

import type { AuditLog } from "../operational/audit-log.js";
import {
  BROKER_DAEMON_AUDIT_LAYER,
  BROKER_DAEMON_HEARTBEAT_OPERATION,
  BROKER_DAEMON_STAND_DOWN_OPERATION,
  BROKER_DAEMON_HEARTBEAT_INTERVAL_SECONDS,
} from "./liveness-constants.js";
import {
  brokerProducerMarkerDetails,
  type BrokerProducerSigner,
} from "./producer-signature.js";

export interface BrokerLivenessHeartbeatOptions {
  /** Audit log the broker daemon shares with the rest of the fortress. */
  auditLog: AuditLog;
  /** Identity id stamped on the audit entries (the daemon's fortress id). */
  fortressId: string;
  /** Dedicated broker daemon liveness producer signer. */
  producerSigner: BrokerProducerSigner;
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
  const { auditLog, fortressId, producerSigner } = opts;
  const intervalMs =
    (opts.intervalSeconds ?? BROKER_DAEMON_HEARTBEAT_INTERVAL_SECONDS) * 1000;

  let writeQueue = Promise.resolve();

  const emitOperation = async (
    operation:
      | typeof BROKER_DAEMON_HEARTBEAT_OPERATION
      | typeof BROKER_DAEMON_STAND_DOWN_OPERATION,
  ): Promise<void> => {
    try {
      const capturedAtUnixMs = Date.now();
      const signedDetails = await producerSigner.signDetails(operation, capturedAtUnixMs);
      await auditLog.appendCritical({
        layer: BROKER_DAEMON_AUDIT_LAYER,
        operation,
        identity_id: fortressId,
        timestamp: new Date(capturedAtUnixMs).toISOString(),
        details: brokerProducerMarkerDetails(signedDetails),
        result: "success",
      });
      await auditLog.flush();
    } catch {
      // A lifecycle write failure must never crash the daemon. The reader's
      // silent-death detection fails toward an alarm when signed lifecycle
      // evidence is missing, so a dropped beat is surfaced honestly.
    }
  };

  const queueOperation = (
    operation:
      | typeof BROKER_DAEMON_HEARTBEAT_OPERATION
      | typeof BROKER_DAEMON_STAND_DOWN_OPERATION,
  ): Promise<void> => {
    writeQueue = writeQueue.then(
      () => emitOperation(operation),
      () => emitOperation(operation),
    );
    return writeQueue;
  };

  // Emit one beat immediately so a daemon that dies seconds after boot still has
  // a prior-liveness signal on the chain (the reader only raises the silent-death
  // alarm once it has proof the producer was running).
  void queueOperation(BROKER_DAEMON_HEARTBEAT_OPERATION);

  let interval: NodeJS.Timeout | undefined = setInterval(() => {
    void queueOperation(BROKER_DAEMON_HEARTBEAT_OPERATION);
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
    await queueOperation(BROKER_DAEMON_STAND_DOWN_OPERATION);
  };

  return { standDown, stop };
}
