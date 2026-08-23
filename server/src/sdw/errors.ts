export type SdwReadFailureKind =
  | "auth_failed"
  | "identity_mismatch"
  | "malformed"
  | "replay_anchor_invalid"
  | "unsupported_record_version";

/**
 * The ten independent checks `classifyText` (server/src/sdw/write-gate.ts)
 * runs before a `classifier_reject`. One entry per check, in the order
 * `classifyText` evaluates them, so an operator refusal can name which one
 * fired instead of a single constant message (Rung-1 F2).
 */
export type SdwClassifierDetector =
  | "private_key_marker"
  | "private_key_marker_split"
  | "encoded_private_key"
  | "labeled_private_key"
  | "labeled_recovery_key"
  | "known_secret_token"
  | "jwt"
  | "url_credential"
  | "keyword_gated_high_entropy"
  | "bare_high_entropy_credential";

/**
 * Plain-English, operator-facing reason for each classifier detector. Class
 * and location only: every string here must be safe to print without
 * revealing what was matched (MUST-NEVER #9 in AGENTS.md). Consumed by
 * cli/memory-file.ts's refusal report and the memory_ingest MCP tool result
 * (memory_emit does not classify: it only emits already-accepted passages)
 * — cross-file pin: keep both in sync with this table ("must match
 * SDW_CLASSIFIER_DETECTOR_REASONS in sdw/errors.ts").
 */
export const SDW_CLASSIFIER_DETECTOR_REASONS: Readonly<Record<SdwClassifierDetector, string>> = {
  private_key_marker: "looks like a PEM-style private key block",
  private_key_marker_split: "looks like a private key block split across the record's fields",
  encoded_private_key: "looks like an encoded Ed25519 private key",
  labeled_private_key: "looks like a labeled Ed25519 private key value",
  labeled_recovery_key: "looks like a labeled Sanctuary recovery key value",
  known_secret_token: "looks like a known vendor secret token (API key, access token, or similar)",
  jwt: "looks like a JSON Web Token",
  url_credential: "looks like a credential embedded in a URL",
  keyword_gated_high_entropy:
    "a security-sensitive keyword appears near a high-entropy value that looks like a secret",
  bare_high_entropy_credential:
    "a high-entropy value elsewhere in the file looks like a raw credential",
};

/**
 * The plain-English reason for a classifier_reject, resolved from the
 * shared table when `detector` names a known detector, falling back to the
 * raw category string otherwise (an older/foreign SdwValidationError, or a
 * non-classifier category passed in by a caller that reuses this helper).
 * `detector` is `string | undefined` rather than SdwClassifierDetector
 * because it crosses the CLI/MCP adapter boundary (server/src/sdw/adapters/
 * memory-backend.ts's MemoryPassageScreen) as a loosely-typed field, so the
 * membership check is a runtime one. Single source for cli/memory-file.ts
 * and sdw/memory-file-tools.ts so the two cannot drift on what a detector id
 * means in English.
 */
export function sdwClassifierReasonText(reason: string, detector: string | undefined): string {
  if (
    detector !== undefined &&
    Object.prototype.hasOwnProperty.call(SDW_CLASSIFIER_DETECTOR_REASONS, detector)
  ) {
    return SDW_CLASSIFIER_DETECTOR_REASONS[detector as SdwClassifierDetector];
  }
  return reason;
}

export interface SdwValidationErrorOptions {
  readonly cause?: unknown;
  /** Populated only for category "classifier_reject"; see SdwClassifierDetector. */
  readonly detector?: SdwClassifierDetector;
  /**
   * 1-based line number of the match within the text the classifier scanned.
   * Present only when the detector's match location maps cleanly onto that
   * text (most do); absent when a hit was found only in a normalized or
   * field-reassembled view with no reliable line mapping. Never the matched
   * content itself.
   */
  readonly line?: number;
}

export class SdwValidationError extends Error {
  readonly category: string;
  readonly detector?: SdwClassifierDetector;
  readonly line?: number;

  constructor(category: string, message: string, options?: SdwValidationErrorOptions) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = "SdwValidationError";
    this.category = category;
    this.detector = options?.detector;
    this.line = options?.line;
  }
}

export class UnsupportedRecordVersion extends Error {
  readonly namespace: string;
  readonly storageKey: string;
  readonly version: number;

  constructor(namespace: string, storageKey: string, version: number) {
    super(`Unsupported SDW record version ${version} at ${namespace}/${storageKey}`);
    this.name = "UnsupportedRecordVersion";
    this.namespace = namespace;
    this.storageKey = storageKey;
    this.version = version;
  }
}

export class SdwCatalogError extends Error {
  readonly category: string;

  constructor(category: string, message: string) {
    super(message);
    this.name = "SdwCatalogError";
    this.category = category;
  }
}

export class SdwReplayAnchorError extends Error {
  readonly category: "invalid_mac" | "malformed" | "replay_anchor_invalid" | "replay_detected";

  constructor(
    category: "invalid_mac" | "malformed" | "replay_anchor_invalid" | "replay_detected",
    message: string,
  ) {
    super(message);
    this.name = "SdwReplayAnchorError";
    this.category = category;
  }
}
