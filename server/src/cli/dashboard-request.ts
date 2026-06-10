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

  constructor(
    message: string,
    kind: DashboardRequestError["kind"],
    status?: number,
  ) {
    super(message);
    this.name = "DashboardRequestError";
    this.kind = kind;
    this.status = status;
  }
}

interface DashboardErrorBody {
  ok?: boolean;
  error?: unknown;
  detail?: unknown;
}

export async function dashboardRequest(
  path: string,
  init?: RequestInit,
  ctx?: DashboardRequestContext,
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
