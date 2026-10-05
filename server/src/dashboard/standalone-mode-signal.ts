import type { ServerResponse } from "node:http";

export const DASHBOARD_MODE_NOT_SERVED_STATUS = 503;
export const DASHBOARD_MODE_NOT_SERVED_ERROR = "dashboard_mode_not_served";
export const DASHBOARD_MODE_NOT_SERVED_MESSAGE =
  "Not available in this dashboard mode.";

export type DashboardModeNotServedMode = "standalone";

export interface DashboardModeNotServedResponse {
  ok: false;
  error: typeof DASHBOARD_MODE_NOT_SERVED_ERROR;
  mode: DashboardModeNotServedMode;
  unavailable: true;
  message: typeof DASHBOARD_MODE_NOT_SERVED_MESSAGE;
}

// These are the v1.1 optional panel reads that the standalone dashboard
// positively marks as unavailable when the real backing route binding is not
// mounted. Must match `DASHBOARD_MODE_NOT_SERVED_ERROR` handling in
// server/src/dashboard/v1_1/client.ts.
export const STANDALONE_OPTIONAL_PANEL_PATHS = [
  "/api/inbox/unified/prefs",
  "/api/auto-trigger/rules",
  "/api/auto-trigger/recommendations",
  "/api/honeypot/tool-traps",
  "/api/honeypot/credential-traps",
] as const;

export function isStandaloneOptionalPanelPath(path: string): boolean {
  return (STANDALONE_OPTIONAL_PANEL_PATHS as readonly string[]).includes(path);
}

export function dashboardModeNotServedBody(
  mode: DashboardModeNotServedMode,
): DashboardModeNotServedResponse {
  return {
    ok: false,
    error: DASHBOARD_MODE_NOT_SERVED_ERROR,
    mode,
    unavailable: true,
    message: DASHBOARD_MODE_NOT_SERVED_MESSAGE,
  };
}

export function writeDashboardModeNotServed(
  res: ServerResponse,
  mode: DashboardModeNotServedMode,
): void {
  res.writeHead(DASHBOARD_MODE_NOT_SERVED_STATUS, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(dashboardModeNotServedBody(mode)));
}
