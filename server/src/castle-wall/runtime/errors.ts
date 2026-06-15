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
 * an armed, key-loaded state. Thrown FAIL-CLOSED: the daemon would not start,
 * the unit is not active, or the pinned producer key is expected-but-unreadable.
 * The caller surfaces NOT-ARMED — never fake-green, never a silent channel-basis
 * fallback when a key is expected.
 */
export class RuntimeLinuxActivationError extends CastleWallError {
  readonly reason:
    | "daemon_start_failed"
    | "daemon_not_active"
    | "producer_key_unreadable"
    | "handshake_failed";
  constructor(message: string, reason: RuntimeLinuxActivationError["reason"]) {
    super(message);
    this.name = "RuntimeLinuxActivationError";
    this.reason = reason;
  }
}
