export type ProfileFailureClassification =
  | "wrong-key"
  | "corrupted"
  | "schema-mismatch"
  | "unreadable";

export interface ProfileLoadErrorOptions {
  path: string;
  classification: ProfileFailureClassification;
  detail: string;
  recovery: string;
  quarantinedPath?: string;
  cause?: unknown;
}

export class ProfileLoadError extends Error {
  readonly path: string;
  readonly classification: ProfileFailureClassification;
  readonly recovery: string;
  readonly quarantinedPath?: string;
  override readonly cause?: unknown;

  constructor(options: ProfileLoadErrorOptions) {
    const quarantine =
      options.quarantinedPath
        ? ` Quarantined copy: ${options.quarantinedPath}.`
        : "";
    super(
      `Sanctuary sovereignty profile load failed. Classification: ${options.classification}. ` +
      `Path: ${options.path}. ${options.detail} Recovery: ${options.recovery}${quarantine}`,
      { cause: options.cause }
    );
    this.name = "ProfileLoadError";
    this.path = options.path;
    this.classification = options.classification;
    this.recovery = options.recovery;
    this.quarantinedPath = options.quarantinedPath;
    this.cause = options.cause;
  }
}
