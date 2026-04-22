/**
 * Sanctuary Operator Console v1.0 — Error classes.
 *
 * All errors the console throws inherit from `MeshConsoleError` so the HTTP
 * surface can catch + map to deterministic 4xx responses.
 */

export class MeshConsoleError extends Error {
  constructor(message: string) {
    super(message);
    Object.defineProperty(this, "name", {
      value: "MeshConsoleError",
      enumerable: false,
      configurable: true,
    });
  }
}

export class MeshConsoleReservedSurfaceError extends MeshConsoleError {
  constructor(
    reason: string,
    public readonly candidate: unknown
  ) {
    super(`reserved-surface rejected: ${reason}`);
    Object.defineProperty(this, "name", {
      value: "MeshConsoleReservedSurfaceError",
      enumerable: false,
      configurable: true,
    });
  }
}

export class MeshConsoleUnknownEventTypeError extends MeshConsoleError {
  constructor(public readonly eventType: string) {
    super(`unknown or reserved event_type: ${eventType}`);
    Object.defineProperty(this, "name", {
      value: "MeshConsoleUnknownEventTypeError",
      enumerable: false,
      configurable: true,
    });
  }
}

export class MeshConsoleJoinDecisionError extends MeshConsoleError {
  constructor(public readonly requestId: string, reason: string) {
    super(`join decision ${requestId}: ${reason}`);
    Object.defineProperty(this, "name", {
      value: "MeshConsoleJoinDecisionError",
      enumerable: false,
      configurable: true,
    });
  }
}
