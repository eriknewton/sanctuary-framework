/**
 * Recovery Cascade -- structured error classes.
 *
 * Seven error classes covering the four failure modes from acceptance
 * criterion 10: (a) threshold-not-met, (b) window-not-expired,
 * (c) signature-invalid, (d) roster-stale. Plus three structural errors.
 *
 * Each error is operator-visible. No em-dashes in messages.
 * No competitor names.
 */

/**
 * Base error for all recovery cascade failures.
 */
export class RecoveryError extends Error {
  readonly name: string = "RecoveryError";
  readonly code: string;
  constructor(message: string, code: string) {
    super(message);
    this.code = code;
  }
}

/**
 * Failure mode (a): M-of-N threshold not met.
 * Thrown when fewer than M valid guardian approvals are present.
 */
export class ThresholdNotMetError extends RecoveryError {
  readonly name = "ThresholdNotMetError";
  readonly valid_count: number;
  readonly threshold_m: number;
  constructor(params: { valid_count: number; threshold_m: number }) {
    super(
      `guardian threshold not met: ${params.valid_count} valid approvals, ${params.threshold_m} required`,
      "threshold_not_met"
    );
    this.valid_count = params.valid_count;
    this.threshold_m = params.threshold_m;
  }
}

/**
 * Failure mode (b): DMswitch window has not expired.
 * Thrown when the operator's inactivity window has not elapsed.
 */
export class WindowNotExpiredError extends RecoveryError {
  readonly name = "WindowNotExpiredError";
  readonly remaining_ms: number;
  readonly expires_at: string;
  constructor(params: { remaining_ms: number; expires_at: string }) {
    super(
      `DMswitch window has not expired; ${params.remaining_ms}ms remaining (expires at ${params.expires_at})`,
      "window_not_expired"
    );
    this.remaining_ms = params.remaining_ms;
    this.expires_at = params.expires_at;
  }
}

/**
 * Failure mode (c): Guardian signature verification failed.
 * Thrown when a guardian's approval signature does not verify
 * against their public key in the pinned roster.
 */
export class SignatureInvalidError extends RecoveryError {
  readonly name = "SignatureInvalidError";
  readonly guardian_id: string;
  constructor(params: { guardian_id: string; detail?: string }) {
    super(
      `guardian ${params.guardian_id} signature invalid${params.detail ? `: ${params.detail}` : ""}`,
      "signature_invalid"
    );
    this.guardian_id = params.guardian_id;
  }
}

/**
 * Failure mode (d): Guardian roster version is stale.
 * Thrown when approvals reference a roster version that does not match
 * the currently pinned roster.
 */
export class RosterStaleError extends RecoveryError {
  readonly name = "RosterStaleError";
  readonly expected_version: number;
  readonly actual_version: number;
  constructor(params: { expected_version: number; actual_version: number }) {
    super(
      `guardian roster version mismatch: cascade references v${params.actual_version}, pinned roster is v${params.expected_version}`,
      "roster_stale"
    );
    this.expected_version = params.expected_version;
    this.actual_version = params.actual_version;
  }
}

/**
 * Structural error: cascade is in an invalid state for the requested operation.
 */
export class CascadeStateError extends RecoveryError {
  readonly name = "CascadeStateError";
  constructor(message: string) {
    super(message, "cascade_state_error");
  }
}

/**
 * Structural error: guardian not found in the pinned roster.
 */
export class GuardianNotFoundError extends RecoveryError {
  readonly name = "GuardianNotFoundError";
  readonly guardian_id: string;
  constructor(guardian_id: string) {
    super(
      `guardian ${guardian_id} not found in the pinned roster`,
      "guardian_not_found"
    );
    this.guardian_id = guardian_id;
  }
}

/**
 * Structural error: recovery configuration is invalid.
 */
export class RecoveryConfigError extends RecoveryError {
  readonly name = "RecoveryConfigError";
  constructor(message: string) {
    super(message, "recovery_config_error");
  }
}
