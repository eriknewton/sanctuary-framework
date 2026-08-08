export type SdwReadFailureKind =
  | "auth_failed"
  | "identity_mismatch"
  | "malformed"
  | "replay_anchor_invalid"
  | "unsupported_record_version";

export class SdwValidationError extends Error {
  readonly category: string;

  constructor(category: string, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "SdwValidationError";
    this.category = category;
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
