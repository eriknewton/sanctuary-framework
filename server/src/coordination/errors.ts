/**
 * Sanctuary v1.1 Coordination — Error Hierarchy
 *
 * One root error class for the coordination workstream so callers can catch
 * with a single `instanceof` check. Subclasses keep failure modes
 * distinguishable for tests and audit logging.
 *
 * Coordination errors deliberately do NOT carry policy-rule details. Denied
 * handoffs surface a coarse `reason_class` per the v1.1 contract; the
 * machine-readable `reason_code` from a wrapped policy receipt is preserved
 * on the error for audit consumers but generic for operator messages.
 */

import type { HandoffStatus } from "../contracts/v1.1/constants.js";

export class CoordinationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CoordinationError";
  }
}

export class HandoffNotFoundError extends CoordinationError {
  constructor(handoffId: string) {
    super(`handoff ${handoffId} not found`);
    this.name = "HandoffNotFoundError";
  }
}

export class HandoffStateError extends CoordinationError {
  readonly current: HandoffStatus;
  readonly expected: readonly HandoffStatus[];
  constructor(current: HandoffStatus, expected: readonly HandoffStatus[]) {
    super(
      `handoff state ${current} is not one of expected [${expected.join(", ")}]`,
    );
    this.name = "HandoffStateError";
    this.current = current;
    this.expected = expected;
  }
}

export class HandoffPolicyDenialError extends CoordinationError {
  readonly reason_code: string;
  constructor(reason_code: string) {
    super(`handoff denied by policy gate (${reason_code})`);
    this.name = "HandoffPolicyDenialError";
    this.reason_code = reason_code;
  }
}

export class HandoffSignatureError extends CoordinationError {
  constructor(message: string) {
    super(message);
    this.name = "HandoffSignatureError";
  }
}

export class HandoffActorError extends CoordinationError {
  constructor(message: string) {
    super(message);
    this.name = "HandoffActorError";
  }
}
