/**
 * Sanctuary Composition v1.0 -- Errors
 *
 * 7 structured error classes for the composition subsystem.
 * All errors are recoverable; none should halt the fortress.
 * Sidecar crash is NEVER a fortress-halt condition.
 *
 * No em-dashes in any error message.
 */

/**
 * Base composition error. All composition errors extend this.
 */
export class CompositionError extends Error {
  constructor(
    message: string,
    public readonly code: string
  ) {
    super(message);
    this.name = "CompositionError";
  }
}

/**
 * Thrown when a composition operation is attempted but composition
 * is disabled in the fortress config.
 */
export class CompositionDisabledError extends CompositionError {
  constructor() {
    super(
      "Composition is disabled in fortress config. Enable with composition_enabled: true.",
      "COMPOSITION_DISABLED"
    );
    this.name = "CompositionDisabledError";
  }
}

/**
 * Thrown when the Concordia Python sidecar fails to spawn.
 */
export class SidecarSpawnError extends CompositionError {
  constructor(
    public readonly reason: string,
    public readonly exitCode?: number
  ) {
    super(
      `Sidecar failed to spawn: ${reason}`,
      "SIDECAR_SPAWN_FAILED"
    );
    this.name = "SidecarSpawnError";
  }
}

/**
 * Thrown when a JSON-RPC call to the sidecar times out.
 */
export class SidecarTimeoutError extends CompositionError {
  constructor(
    public readonly method: string,
    public readonly timeoutMs: number
  ) {
    super(
      `Sidecar RPC call "${method}" timed out after ${timeoutMs}ms`,
      "SIDECAR_TIMEOUT"
    );
    this.name = "SidecarTimeoutError";
  }
}

/**
 * Thrown when mandate verification fails.
 */
export class MandateVerificationError extends CompositionError {
  constructor(
    public readonly mandateId: string,
    public readonly reason: string
  ) {
    super(
      `Mandate verification failed for ${mandateId}: ${reason}`,
      "MANDATE_VERIFICATION_FAILED"
    );
    this.name = "MandateVerificationError";
  }
}

/**
 * Thrown when Verascore publish fails.
 */
export class VerascorePublishError extends CompositionError {
  constructor(
    public readonly reason: string,
    public readonly signalId?: string
  ) {
    super(
      `Verascore publish failed: ${reason}`,
      "VERASCORE_PUBLISH_FAILED"
    );
    this.name = "VerascorePublishError";
  }
}

/**
 * Thrown when a Verascore scope violation is detected (e.g., attempting
 * public publish without explicit opt-in).
 */
export class ScopeViolationError extends CompositionError {
  constructor(
    public readonly attemptedScope: string,
    public readonly allowedScope: string
  ) {
    super(
      `Scope violation: attempted "${attemptedScope}" but only "${allowedScope}" is allowed without explicit opt-in`,
      "SCOPE_VIOLATION"
    );
    this.name = "ScopeViolationError";
  }
}

/**
 * Thrown when a JSON-RPC frame received from the sidecar exceeds the
 * per-message size cap (MAX_SIDECAR_MESSAGE_BYTES).
 *
 * Surfaces through the sidecar event listener so the SidecarManager can
 * terminate the sidecar process and emit an audit event. The fortress
 * continues operating (composition degrades, fortress does not halt).
 */
export class SidecarMessageSizeCapExceededError extends CompositionError {
  constructor(
    public readonly bufferedBytes: number,
    public readonly capBytes: number
  ) {
    super(
      `Sidecar JSON-RPC frame exceeded ${capBytes} byte cap without newline boundary (buffered: ${bufferedBytes})`,
      "SIDECAR_MESSAGE_SIZE_CAP_EXCEEDED"
    );
    this.name = "SidecarMessageSizeCapExceededError";
  }
}

/**
 * Thrown when a composition-layer signing entry point is invoked without
 * a usable Ed25519 signing key. Two production shapes trigger this:
 *
 *   1. CompositionService.publishVerascoreSignal() was called with no
 *      signingKey argument AND the service was constructed without
 *      FortressContextInput, so getSidecarSigningKey() returned null.
 *   2. CompositionService.emitForCommitment() was called on a service
 *      constructed without FortressContextInput.
 *
 * The distinguishing callSite field lets reviewers and operator-surface
 * logs attribute the failure to the correct entry point without parsing
 * the message.
 */
export class MissingSidecarSigningKeyError extends CompositionError {
  constructor(
    message: string,
    public readonly callSite: "publishVerascoreSignal" | "emitForCommitment"
  ) {
    super(message, "MISSING_SIDECAR_SIGNING_KEY");
    this.name = "MissingSidecarSigningKeyError";
  }
}

/**
 * Thrown when a composition operation is attempted while the subsystem
 * is in degraded mode (sidecar crashed, restarting, etc.).
 *
 * This error is informational; the fortress continues operating.
 * The caller should check getDegradeState() for details.
 */
export class DegradeStateError extends CompositionError {
  constructor(
    public readonly reason: string,
    public readonly consecutiveCrashes: number,
    public readonly replayQueueDepth: number
  ) {
    super(
      `Composition degraded: ${reason} (crashes: ${consecutiveCrashes}, queued: ${replayQueueDepth})`,
      "COMPOSITION_DEGRADED"
    );
    this.name = "DegradeStateError";
  }
}
