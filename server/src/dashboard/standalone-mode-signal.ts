import type { ServerResponse } from "node:http";

import { AUTO_TRIGGER_API_PREFIX } from "../auto-trigger/auto-trigger-routes.js";
import { HONEYPOT_API_PREFIX } from "../honeypot/runtime-trap-handler.js";
import { UNIFIED_INBOX_PREFS_API_PATH } from "../principal-policy/unified-inbox-routes.js";

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
// mounted. Each path is derived from the owning route module's exported
// contract so a route rename cannot strand this signal on a dead literal.
export const STANDALONE_OPTIONAL_PANEL_PATHS = [
  UNIFIED_INBOX_PREFS_API_PATH,
  `${AUTO_TRIGGER_API_PREFIX}/rules`,
  `${AUTO_TRIGGER_API_PREFIX}/recommendations`,
  `${HONEYPOT_API_PREFIX}/tool-traps`,
  `${HONEYPOT_API_PREFIX}/credential-traps`,
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
