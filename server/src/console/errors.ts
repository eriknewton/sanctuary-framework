/**
 * Sanctuary Operator Console v1.0 -- Error classes
 *
 * Six structured error classes per spawn prompt. All inherit from
 * ConsoleError so the API router can catch and map to HTTP responses.
 */

export class ConsoleError extends Error {
  readonly statusCode: number;
  constructor(message: string, statusCode = 400) {
    super(message);
    this.statusCode = statusCode;
    Object.defineProperty(this, "name", {
      value: "ConsoleError",
      enumerable: false,
      configurable: true,
    });
  }
}

export class ViewRenderError extends ConsoleError {
  constructor(view: string, reason: string) {
    super(`view render failed for "${view}": ${reason}`, 500);
    Object.defineProperty(this, "name", {
      value: "ViewRenderError",
      enumerable: false,
      configurable: true,
    });
  }
}

export class ApiRouteError extends ConsoleError {
  constructor(path: string, reason: string) {
    super(`route ${path}: ${reason}`, 400);
    Object.defineProperty(this, "name", {
      value: "ApiRouteError",
      enumerable: false,
      configurable: true,
    });
  }
}

export class AuthGateError extends ConsoleError {
  constructor(reason = "unauthorized") {
    super(reason, 401);
    Object.defineProperty(this, "name", {
      value: "AuthGateError",
      enumerable: false,
      configurable: true,
    });
  }
}

export class StaleStateError extends ConsoleError {
  constructor(resource: string) {
    super(`stale state: ${resource} has changed since last read`, 409);
    Object.defineProperty(this, "name", {
      value: "StaleStateError",
      enumerable: false,
      configurable: true,
    });
  }
}

export class ReservedRouteError extends ConsoleError {
  constructor(path: string) {
    super(`reserved route: ${path} is reserved for v1.x`, 403);
    Object.defineProperty(this, "name", {
      value: "ReservedRouteError",
      enumerable: false,
      configurable: true,
    });
  }
}

export class IntegrityCheckError extends ConsoleError {
  constructor(reason: string) {
    super(`integrity check failed: ${reason}`, 500);
    Object.defineProperty(this, "name", {
      value: "IntegrityCheckError",
      enumerable: false,
      configurable: true,
    });
  }
}
