const DEFAULT_DASHBOARD_URL = "http://127.0.0.1:3502";

export interface DashboardRequestContext {
  dashboardUrl?: string;
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
  const token = process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN ?? "";
  const headers = new Headers(init?.headers);
  headers.set("Accept", "application/json");
  if (init?.body) headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);

  let res: Response;
  try {
    res = await fetch(`${base}${path}`, { ...init, headers });
  } catch (cause) {
    throw new Error(
      `network/connection failure: ${errorDetail(cause)}. Hint: start the Sanctuary dashboard, verify --fortress runtime, or set SANCTUARY_DASHBOARD_URL to a reachable endpoint.`,
    );
  }

  const body = (await res.json().catch(() => ({}))) as DashboardErrorBody;
  if (!res.ok || body.ok === false) {
    throw new Error(classifyHttpFailure(res.status, path, body));
  }
  return body;
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
