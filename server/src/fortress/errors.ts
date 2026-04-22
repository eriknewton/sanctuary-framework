/**
 * Sanctuary Fortress Modes -- Errors
 *
 * Structured error classes with machine-readable codes.
 * Follows the MeshError / PolicyEngineError pattern.
 */

/**
 * Base error for all fortress mode operations.
 */
export class FortressError extends Error {
  readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = "FortressError";
    this.code = code;
  }
}

/**
 * Thrown when a requested mode transition is not in the legal-path matrix.
 * Example: Tier 1 directly to Tier 3 (must pass through Tier 2).
 */
export class IllegalTransitionError extends FortressError {
  constructor(from: string, to: string) {
    super(
      `Transition from ${from} to ${to} is not legal. ` +
        `Tier 1 to Tier 3 must pass through Tier 2.`,
      "ILLEGAL_TRANSITION"
    );
    this.name = "IllegalTransitionError";
  }
}

/**
 * Thrown when one or more preconditions for a mode transition are not met.
 */
export class ModePreconditionsNotMetError extends FortressError {
  readonly failures: Array<{ id: string; reason: string }>;

  constructor(failures: Array<{ id: string; reason: string }>) {
    const summary = failures
      .map((f) => `${f.id}: ${f.reason}`)
      .join("; ");
    super(
      `Mode transition preconditions not met: ${summary}`,
      "PRECONDITIONS_NOT_MET"
    );
    this.name = "ModePreconditionsNotMetError";
    this.failures = failures;
  }
}

/**
 * Thrown when a transition targets the tier the fortress is already in.
 */
export class AlreadyInTierError extends FortressError {
  constructor(tier: string) {
    super(
      `Fortress is already in ${tier}. No transition needed.`,
      "ALREADY_IN_TIER"
    );
    this.name = "AlreadyInTierError";
  }
}

/**
 * Thrown when an invalid tier string is provided.
 */
export class InvalidTierError extends FortressError {
  constructor(tier: string) {
    super(
      `"${tier}" is not a valid fortress tier. ` +
        `Valid tiers: tier_1_private, tier_2_federated, tier_3_interop.`,
      "INVALID_TIER"
    );
    this.name = "InvalidTierError";
  }
}

/**
 * Thrown when fortress mode config is corrupted or missing required fields.
 */
export class FortressConfigError extends FortressError {
  constructor(message: string) {
    super(message, "CONFIG_ERROR");
    this.name = "FortressConfigError";
  }
}

/**
 * Thrown when an external adapter registration is invalid
 * (e.g., capability bit outside the 3-7 range reserved for Tier 3).
 */
export class InvalidAdapterError extends FortressError {
  constructor(message: string) {
    super(message, "INVALID_ADAPTER");
    this.name = "InvalidAdapterError";
  }
}
