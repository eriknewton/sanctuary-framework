/**
 * Sanctuary Attestation UX v1.0 -- Errors
 *
 * 5 structured error classes. All errors degrade; none halt.
 * Per design brief section 2, rule 4: "degrade, never destroy."
 */

/**
 * Base class for attestation errors. All attestation errors carry a
 * failure_mode_code so the failure-catalog can map them to badge states.
 */
export class AttestationError extends Error {
  readonly failure_mode_code: string;

  constructor(message: string, failure_mode_code: string) {
    super(message);
    this.name = "AttestationError";
    this.failure_mode_code = failure_mode_code;
  }
}

/**
 * Thrown when badge state derivation encounters an unknown scope ID
 * (agent_id or action_id not found in the store).
 */
export class BadgeScopeNotFoundError extends AttestationError {
  readonly scope_id: string;

  constructor(scope_id: string, layer: string) {
    super(
      `Badge scope not found: ${scope_id} in ${layer} layer`,
      "badge_scope_not_found"
    );
    this.name = "BadgeScopeNotFoundError";
    this.scope_id = scope_id;
  }
}

/**
 * Thrown when an attestation event references an unknown failure-mode code.
 * The system degrades to yellow and logs the unrecognized code.
 */
export class UnknownFailureModeError extends AttestationError {
  readonly unknown_code: string;

  constructor(unknown_code: string) {
    super(
      `Unknown failure-mode code: ${unknown_code}`,
      "unknown_failure_mode"
    );
    this.name = "UnknownFailureModeError";
    this.unknown_code = unknown_code;
  }
}

/**
 * Thrown when an attestation event's signature_scheme is not recognized.
 * The system degrades the badge to yellow (not red, per degrade-not-destroy).
 */
export class UnsupportedSignatureSchemeError extends AttestationError {
  readonly scheme: string;

  constructor(scheme: string) {
    super(
      `Unsupported signature scheme: ${scheme}`,
      "unsupported_signature_scheme"
    );
    this.name = "UnsupportedSignatureSchemeError";
    this.scheme = scheme;
  }
}

/**
 * Thrown when a custody provenance lookup is attempted for a transaction
 * that has no stub (transaction ID not found).
 */
export class CustodyProvenanceNotFoundError extends AttestationError {
  readonly tx_id: string;

  constructor(tx_id: string) {
    super(
      `Custody provenance not found for transaction: ${tx_id}`,
      "custody_provenance_not_found"
    );
    this.name = "CustodyProvenanceNotFoundError";
    this.tx_id = tx_id;
  }
}
