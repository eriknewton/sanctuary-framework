const DEFAULT_DASHBOARD_URL = "http://127.0.0.1:3502";

export interface DashboardRequestContext {
  dashboardUrl?: string;
  /**
   * Federation PR-A1: explicit Authorization bearer override. When set,
   * it wins over SANCTUARY_DASHBOARD_AUTH_TOKEN; the empty string sends
   * NO Authorization header. The /v1 surface uses this to send short-lived
   * session tokens (and to keep the long-lived operator token off the
   * wire during the session ceremony itself).
   */
  authToken?: string;
}

/**
 * Federation PR-A1: classified dashboard-request failure. `kind` lets
 * API-client CLI verbs map failures onto the catalog exit codes
 * (2 = daemon unreachable / server error, 3 = auth failure, ...) without
 * string-matching the human-facing message.
 */
export class DashboardRequestError extends Error {
  readonly kind: "network" | "auth" | "not-implemented" | "server" | "http";
  readonly status: number | undefined;
  /**
   * Server-minted correlation id from the failure body's `request_id`, when the
   * endpoint emits one (today: the federation node-cert reissue route). The
   * server deliberately does not tell the caller WHICH check failed; this id is
   * how an operator who can read that fortress looks the reason up in its audit
   * log. Undefined for every endpoint that does not mint one.
   */
  readonly requestId: string | undefined;

  constructor(
    message: string,
    kind: DashboardRequestError["kind"],
    status?: number,
    requestId?: string,
  ) {
    super(message);
    this.name = "DashboardRequestError";
    this.kind = kind;
    this.status = status;
    this.requestId = requestId;
  }
}

interface DashboardErrorBody {
  ok?: boolean;
  error?: unknown;
  detail?: unknown;
  request_id?: unknown;
}

/**
 * Accept a server-supplied correlation id ONLY in the exact shape a Sanctuary
 * fortress mints (`randomUUID`), and drop anything else.
 *
 * This value comes off the wire from a host the client has NOT authenticated
 * (the reissue route is pre-session), and it is displayed to the operator inside
 * a command they are invited to run. A hostile or MITM'd endpoint that could put
 * arbitrary text in this field would be writing into the operator's terminal and
 * clipboard: `"x\nrm -rf ~/.sanctuary #"` renders as a second line that looks
 * like part of the suggested command. Constraining it to 36 hex-and-dash
 * characters removes the whole class -- newlines, shell metacharacters, ANSI
 * escapes, and unbounded length -- rather than trying to escape it at each
 * display site. A non-conforming id is DROPPED, not sanitized: the correct
 * outcome is "this endpoint gave us nothing to look up", which the callers
 * already handle by printing no lookup line at all.
 */
const CORRELATION_ID_SHAPE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function parseServerRequestId(value: unknown): string | undefined {
  return typeof value === "string" && CORRELATION_ID_SHAPE.test(value)
    ? value
    : undefined;
}

/**
 * Issue a request to the local Sanctuary dashboard and return the parsed JSON
 * body. The return is deliberately `any`: the body is untrusted, schema-loose
 * remote JSON whose shape varies per endpoint, and the CLI command consumers
 * (inbox.ts, task.ts, status.ts, v1-session.ts) read it loosely (`body.data?.X`
 * envelopes, then `?? body` fallbacks). Typing it `unknown` would force a cast
 * at every one of those ~14 field accesses across unrelated CLI files for no
 * safety gain (they already treat the value as untyped). JUDGMENT (DoE H-1): a
 * scoped, justified `any` on this one return is preferred over a sprawling,
 * regression-prone cast refactor; callers that DO want a shape narrow with `as`.
 */
export async function dashboardRequest(
  path: string,
  init?: RequestInit,
  ctx?: DashboardRequestContext,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- intentional: untrusted, schema-loose remote JSON; see JSDoc above
): Promise<any> {
  const base = (
    ctx?.dashboardUrl ?? process.env.SANCTUARY_DASHBOARD_URL ?? DEFAULT_DASHBOARD_URL
  ).replace(/\/$/, "");
  const token =
    ctx?.authToken !== undefined
      ? ctx.authToken
      : process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN ?? "";
  const headers = new Headers(init?.headers);
  headers.set("Accept", "application/json");
  if (init?.body) headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);

  let res: Response;
  try {
    res = await fetch(`${base}${path}`, { ...init, headers });
  } catch (cause) {
    throw new DashboardRequestError(
      `network/connection failure: ${errorDetail(cause)}. Hint: start the Sanctuary dashboard, verify --fortress runtime, or set SANCTUARY_DASHBOARD_URL to a reachable endpoint.`,
      "network",
    );
  }

  const body = (await res.json().catch(() => ({}))) as DashboardErrorBody;
  if (!res.ok || body.ok === false) {
    throw new DashboardRequestError(
      classifyHttpFailure(res.status, path, body),
      failureKind(res.status),
      res.status,
      parseServerRequestId(body.request_id),
    );
  }
  return body;
}

function failureKind(status: number): DashboardRequestError["kind"] {
  if (status === 401 || status === 403) return "auth";
  if (status === 404) return "not-implemented";
  if (status >= 500) return "server";
  return "http";
}

function classifyHttpFailure(
  status: number,
  path: string,
  body: DashboardErrorBody,
): string {
  const detail = bodyDetail(body) ?? `HTTP ${status}`;
  if (status === 404) {
    return `endpoint not implemented in this build (HTTP 404): ${detail}. Hint: verify the dashboard exposes ${path}, or upgrade/restart Sanctuary dashboard.`;
  }
  if (status === 401 || status === 403) {
    return `auth/policy denied (HTTP ${status}): ${detail}. Hint: check SANCTUARY_DASHBOARD_AUTH_TOKEN, fortress policy, and operator authorization.`;
  }
  if (status >= 500) {
    return `server error (HTTP ${status}): ${detail}. Hint: inspect the dashboard logs and retry after the service is healthy.`;
  }
  return `http error (HTTP ${status}): ${detail}`;
}

function bodyDetail(body: DashboardErrorBody): string | null {
  if (body.detail !== undefined) return String(body.detail);
  if (body.error !== undefined) return String(body.error);
  return null;
}

function errorDetail(cause: unknown): string {
  if (!(cause instanceof Error)) return String(cause);
  const nested = cause.cause instanceof Error ? `; cause: ${cause.cause.message}` : "";
  return `${cause.message}${nested}`;
}
