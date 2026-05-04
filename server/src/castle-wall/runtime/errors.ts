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
