/**
 * Castle Wall runtime errors.
 *
 * The runtime module talks to the filter daemon over IPC and to the host
 * filesystem; structured errors here let the caller decide between recover
 * paths (retry, surface to menubar, fail-closed) without re-classifying
 * underlying causes.
 */

import { CastleWallError } from "../errors.js";

export class RuntimeIpcError extends CastleWallError {
  constructor(message: string) {
    super(message);
    this.name = "RuntimeIpcError";
  }
}

/**
 * A drain or drain-ACK failure, carrying the retry classification the caller
 * must act on.
 *
 * Distinct from a bare {@link RuntimeIpcError} because the caller's response is
 * completely different per class, and the previous code could not tell them
 * apart: EVERY drain/ACK error became an unsettled fault, which the activation
 * gate latched into a permanent not-armed wall with a durable
 * `castle_wall_drain_failed` record. That fired on an ordinary `systemctl stop`
 * with an ACK in flight, and on any 2-second control-lock contention window,
 * blaming a transport/persistence fault for a link that was fine.
 *
 * The three values are deliberate, and `unclassified` is not a fudge: a pre-v2
 * daemon does not send a class, and neither `retryable` nor `terminal` may be
 * invented for it. The caller retries an `unclassified` failure under a bounded
 * budget and fails closed when the budget is exhausted, which is the only
 * disposition that is honest about not knowing.
 */
export class RuntimeDrainError extends CastleWallError {
  readonly errorClass: "retryable" | "terminal" | "unclassified";
  /**
   * Which side of the channel failed. `ack` failures never risk evidence (the
   * consumer holds the events durably before it acks); `drain` failures mean no
   * evidence arrived this cycle.
   */
  readonly phase: "drain" | "ack";
  constructor(
    message: string,
    phase: RuntimeDrainError["phase"],
    errorClass: RuntimeDrainError["errorClass"]
  ) {
    super(message);
    this.name = "RuntimeDrainError";
    this.phase = phase;
    this.errorClass = errorClass;
  }

  /**
   * True when this failure, on its own, proves the evidence channel is broken.
   * The one place the question is answered, so the drain loop and the activation
   * gate cannot answer it differently.
   */
  get isTerminal(): boolean {
    return this.errorClass === "terminal";
  }
}

export class RuntimeHandshakeError extends CastleWallError {
  readonly reason:
    | "timeout"
    | "bad_challenge"
    | "signature_failed"
    | "transport_dropped";
  constructor(message: string, reason: RuntimeHandshakeError["reason"]) {
    super(message);
    this.name = "RuntimeHandshakeError";
    this.reason = reason;
  }
}

export class RuntimeManifestPublishError extends CastleWallError {
  constructor(message: string) {
    super(message);
    this.name = "RuntimeManifestPublishError";
  }
}

export class RuntimeFirewallDetectError extends CastleWallError {
  constructor(message: string) {
    super(message);
    this.name = "RuntimeFirewallDetectError";
  }
}

export class RuntimeApprovalTimeoutError extends CastleWallError {
  constructor(requestId: string) {
    super(`approval prompt ${requestId} expired without operator response`);
    this.name = "RuntimeApprovalTimeoutError";
  }
}

/**
 * The Linux producer-signed activation could not bring the enforcing daemon to
 * an armed, key-loaded, draining state. Thrown FAIL-CLOSED whenever a REQUESTED
 * (opted-in) Linux activation cannot prove it is enforcing:
 *
 *   - `daemon_start_failed` / `daemon_not_active` - the systemd unit would not
 *     start or did not report active.
 *   - `producer_key_unreadable` - the published key file exists but is malformed
 *     / unreadable (a key is expected).
 *   - `producer_key_absent` - opted in on Linux, the daemon launched, but no
 *     producer key was published. On the OPT-IN path a key is REQUIRED, so an
 *     absent key after launch is a fail-closed not-armed condition (NOT the
 *     channel-basis floor - that floor only applies WITHOUT opt-in). (codex
 *     CRITICAL: fail-open on absent key in the opt-in path.)
 *   - `handshake_failed` - the IPC handshake to the daemon failed.
 *   - `drain_failed` - the audit drain transport failed, so the wall would be
 *     armed-but-not-draining (its signed enforcement evidence never reaches the
 *     consumer). Load-bearing in opt-in mode. (codex HIGH: swallowed drain
 *     failure.)
 *   - `policy_incompatible` - a requested publication uses semantics the Linux
 *     packet path cannot authenticate (hostname/template/time) or has no
 *     explicit IP/CIDR destination; refusal happens before signing or storage.
 *
 * The caller surfaces NOT-ARMED - never fake-green, never a silent channel-basis
 * fallback when a key is expected.
 */
export class RuntimeLinuxActivationError extends CastleWallError {
  readonly reason:
    | "daemon_start_failed"
    | "daemon_not_active"
    | "producer_key_unreadable"
    | "producer_key_absent"
    | "handshake_failed"
    | "drain_failed"
    | "policy_incompatible"
    /**
     * The daemon answered a status query and reported a PROVEN-lost kernel
     * runtime. Distinct from `drain_failed` (the evidence channel) and from an
     * INDETERMINATE reading, which is never this reason: an unproven runtime is
     * recorded and surfaced, not treated as a failure.
     */
    | "runtime_degraded";
  constructor(message: string, reason: RuntimeLinuxActivationError["reason"]) {
    super(message);
    this.name = "RuntimeLinuxActivationError";
    this.reason = reason;
  }
}
