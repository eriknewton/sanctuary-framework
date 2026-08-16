/**
 * Sanctuary v1.1. Operator Hub API Errors
 *
 * Structured error classes the API router catches and maps to HTTP responses.
 * Mirrors the console module's error-class pattern so dashboard glue code
 * works the same way against either surface.
 */

export class HubError extends Error {
  readonly statusCode: number;
  readonly publicDetail: string;
  constructor(message: string, statusCode = 400, publicDetail = message) {
    super(message);
    this.statusCode = statusCode;
    this.publicDetail = publicDetail;
    Object.defineProperty(this, "name", {
      value: "HubError",
      enumerable: false,
      configurable: true,
    });
  }
}

/**
 * Auth gate rejected the request. 401.
 */
export class HubAuthError extends HubError {
  constructor(reason = "unauthorized") {
    super(reason, 401);
    Object.defineProperty(this, "name", {
      value: "HubAuthError",
      enumerable: false,
      configurable: true,
    });
  }
}

/**
 * Caller asked for a resource that does not exist. 404.
 */
export class HubNotFoundError extends HubError {
  constructor(resource: string) {
    super(`${resource} not found`, 404);
    Object.defineProperty(this, "name", {
      value: "HubNotFoundError",
      enumerable: false,
      configurable: true,
    });
  }
}

/**
 * Request body or query parameter was malformed or missing. 400.
 */
export class HubValidationError extends HubError {
  constructor(reason: string) {
    super(reason, 400);
    Object.defineProperty(this, "name", {
      value: "HubValidationError",
      enumerable: false,
      configurable: true,
    });
  }
}

/**
 * Caller asked for a cross-fortress, fleet, or public-federation surface.
 * v1.1 is local-single-operator. 422.
 *
 * The hub deliberately rejects these at the API layer so a dashboard or
 * mobile companion (v1.2) cannot accidentally reach across fortress
 * boundaries through a v1.1 endpoint. Cross-fortress surfaces ship in v1.3.
 */
export class HubLocalOnlyError extends HubError {
  constructor(reason: string) {
    super(`local-only scope: ${reason}`, 422);
    Object.defineProperty(this, "name", {
      value: "HubLocalOnlyError",
      enumerable: false,
      configurable: true,
    });
  }
}

/**
 * Operation conflicts with the current state (e.g., resume on an already
 * active agent, approve on a resolved inbox item). 409.
 */
export class HubConflictError extends HubError {
  constructor(reason: string) {
    super(reason, 409);
    Object.defineProperty(this, "name", {
      value: "HubConflictError",
      enumerable: false,
      configurable: true,
    });
  }
}

/**
 * Hub service was asked to invoke a capability this Sanctuary build cannot
 * execute for the agent (for example, process control without a process
 * handle, or unwrap while the dashboard implementation is still bounded).
 * 422.
 */
export class HubCapabilityError extends HubError {
  readonly reasonCode: string;

  constructor(action: string) {
    super(`capability not supported: ${action}`, 422);
    this.reasonCode = action;
    Object.defineProperty(this, "name", {
      value: "HubCapabilityError",
      enumerable: false,
      configurable: true,
    });
  }
}
