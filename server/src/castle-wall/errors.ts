/**
 * Castle Wall structured errors.
 *
 * Each module returns these from parse, validation, and decision paths so
 * that subsequent PRs can format operator-facing messages and audit details
 * without re-classifying error shapes.
 */

export class CastleWallError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CastleWallError";
  }
}

export class AllowlistValidationError extends CastleWallError {
  readonly issues: ReadonlyArray<string>;
  constructor(message: string, issues: ReadonlyArray<string>) {
    super(message);
    this.name = "AllowlistValidationError";
    this.issues = issues;
  }
}

export class AllowlistSignatureError extends CastleWallError {
  constructor(message: string) {
    super(message);
    this.name = "AllowlistSignatureError";
  }
}

export class IpcFramingError extends CastleWallError {
  constructor(message: string) {
    super(message);
    this.name = "IpcFramingError";
  }
}
