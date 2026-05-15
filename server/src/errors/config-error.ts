export type ConfigFailureClassification =
  | "corrupted"
  | "schema-mismatch"
  | "unreadable";

export interface ConfigLoadErrorOptions {
  path: string;
  classification: ConfigFailureClassification;
  detail: string;
  recovery: string;
  quarantinedPath?: string;
  cause?: unknown;
}

export class ConfigLoadError extends Error {
  readonly path: string;
  readonly classification: ConfigFailureClassification;
  readonly recovery: string;
  readonly quarantinedPath?: string;
  override readonly cause?: unknown;

  constructor(options: ConfigLoadErrorOptions) {
    const quarantine =
      options.quarantinedPath
        ? ` Quarantined copy: ${options.quarantinedPath}.`
        : "";
    super(
      `Sanctuary config load failed. Classification: ${options.classification}. ` +
      `Path: ${options.path}. ${options.detail} Recovery: ${options.recovery}${quarantine}`,
      { cause: options.cause }
    );
    this.name = "ConfigLoadError";
    this.path = options.path;
    this.classification = options.classification;
    this.recovery = options.recovery;
    this.quarantinedPath = options.quarantinedPath;
    this.cause = options.cause;
  }
}
