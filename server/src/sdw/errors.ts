export type SdwReadFailureKind =
  | "auth_failed"
  | "identity_mismatch"
  | "malformed"
  | "replay_anchor_invalid"
  | "unsupported_record_version";

/**
 * The nine independent checks `classifyText` (server/src/sdw/write-gate.ts)
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
  | "keyword_gated_high_entropy";

/**
 * Plain-English, operator-facing reason for each classifier detector. Class
 * and location only: every string here must be safe to print without
 * revealing what was matched (MUST-NEVER #9 in AGENTS.md). Consumed by
 * cli/memory-file.ts's refusal report and the memory_ingest/memory_emit MCP
 * tool results — cross-file pin: keep both in sync with this table ("must
 * match SDW_CLASSIFIER_DETECTOR_REASONS in sdw/errors.ts").
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
};

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
  /** 1-based column of the match start, when line is present and cheap to compute. */
  readonly column?: number;
}

export class SdwValidationError extends Error {
  readonly category: string;
  readonly detector?: SdwClassifierDetector;
  readonly line?: number;
  readonly column?: number;

  constructor(category: string, message: string, options?: SdwValidationErrorOptions) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = "SdwValidationError";
    this.category = category;
    this.detector = options?.detector;
    this.line = options?.line;
    this.column = options?.column;
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
