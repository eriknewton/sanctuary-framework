/**
 * Sanctuary Policy Engine — Error classes.
 *
 * Every error is typed so callers can discriminate without string-matching.
 */

export class PolicyEngineError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyEngineError";
  }
}

/** Compiled policy failed schema validation. */
export class CompiledPolicyShapeError extends PolicyEngineError {
  constructor(message: string) {
    super(message);
    this.name = "CompiledPolicyShapeError";
  }
}

/** Policy blob is not well-formed base64url or canonical JSON. */
export class PolicyBlobDecodeError extends PolicyEngineError {
  constructor(message: string) {
    super(message);
    this.name = "PolicyBlobDecodeError";
  }
}

/** New policy_version is less than or equal to the pinned version (rollback). */
export class PolicyVersionRollbackError extends PolicyEngineError {
  constructor(message: string) {
    super(message);
    this.name = "PolicyVersionRollbackError";
  }
}

/** parent_version does not match the pinned head. */
export class PolicyVersionForkError extends PolicyEngineError {
  constructor(message: string) {
    super(message);
    this.name = "PolicyVersionForkError";
  }
}

/** Compiler produced a non-deterministic artifact (digest mismatch). */
export class CompilerDeterminismError extends PolicyEngineError {
  constructor(message: string) {
    super(message);
    this.name = "CompilerDeterminismError";
  }
}

/** A module under gates/** tried to import a disallowed module. */
export class GateImportHygieneError extends PolicyEngineError {
  constructor(message: string) {
    super(message);
    this.name = "GateImportHygieneError";
  }
}
