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
 *   - `daemon_start_failed` / `daemon_not_active` — the systemd unit would not
 *     start or did not report active.
 *   - `producer_key_unreadable` — the published key file exists but is malformed
 *     / unreadable (a key is expected).
 *   - `producer_key_absent` — opted in on Linux, the daemon launched, but no
 *     producer key was published. On the OPT-IN path a key is REQUIRED, so an
 *     absent key after launch is a fail-closed not-armed condition (NOT the
 *     channel-basis floor — that floor only applies WITHOUT opt-in). (codex
 *     CRITICAL: fail-open on absent key in the opt-in path.)
 *   - `handshake_failed` — the IPC handshake to the daemon failed.
 *   - `drain_failed` — the audit drain transport failed, so the wall would be
 *     armed-but-not-draining (its signed enforcement evidence never reaches the
 *     consumer). Load-bearing in opt-in mode. (codex HIGH: swallowed drain
 *     failure.)
 *
 * The caller surfaces NOT-ARMED — never fake-green, never a silent channel-basis
 * fallback when a key is expected.
 */
export class RuntimeLinuxActivationError extends CastleWallError {
  readonly reason:
    | "daemon_start_failed"
    | "daemon_not_active"
    | "producer_key_unreadable"
    | "producer_key_absent"
    | "handshake_failed"
    | "drain_failed";
  constructor(message: string, reason: RuntimeLinuxActivationError["reason"]) {
    super(message);
    this.name = "RuntimeLinuxActivationError";
    this.reason = reason;
  }
}
