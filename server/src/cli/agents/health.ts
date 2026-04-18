/**
 * Sanctuary MCP Server — tenant dashboard health probe
 *
 * Checks whether a tenant's dashboard is actually listening by hitting
 * `/api/health` on the host+port the tenant's runtime.json advertises. The
 * endpoint is authenticated with a bearer token when `SANCTUARY_DASHBOARD_AUTH_TOKEN`
 * is set, but health returns 401 (not 404) in that case — which still tells
 * us the server is up. Both outcomes are treated as "running".
 */

import { get, type IncomingMessage } from "node:http";
import type { TenantDescriptor } from "./discovery.js";

export interface HealthProbeOptions {
  /** Millisecond timeout. Default 500ms. */
  timeoutMs?: number;
}

export interface HealthProbeResult {
  running: boolean;
  /** HTTP status, if any response reached us. */
  status: number | null;
  /** Why we marked the tenant not-running; null when running=true. */
  reason: string | null;
}

const DEFAULT_TIMEOUT_MS = 500;

/**
 * Probe a single tenant's dashboard. Never throws.
 * Running when the health endpoint responds with *any* HTTP status < 500
 * (200 = ok public, 401 = ok but token-gated, 404 = server up without health
 * route in an older build). Marks not-running on 5xx, connection refused,
 * timeout, or network error.
 */
export async function probeTenantDashboard(
  tenant: TenantDescriptor,
  options: HealthProbeOptions = {}
): Promise<HealthProbeResult> {
  const rt = tenant.runtime;
  if (!rt) {
    return { running: false, status: null, reason: "no runtime.json" };
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  return await new Promise<HealthProbeResult>((resolve) => {
    const req = get(
      {
        host: rt.dashboard_host,
        port: rt.dashboard_port,
        path: "/api/health",
        timeout: timeoutMs,
      },
      (res: IncomingMessage) => {
        res.resume();
        const status = res.statusCode ?? 0;
        if (status > 0 && status < 500) {
          resolve({ running: true, status, reason: null });
        } else {
          resolve({
            running: false,
            status,
            reason: `dashboard returned ${status}`,
          });
        }
      }
    );
    req.on("timeout", () => {
      req.destroy();
      resolve({ running: false, status: null, reason: "timeout" });
    });
    req.on("error", (err) => {
      resolve({
        running: false,
        status: null,
        reason: (err as NodeJS.ErrnoException).code ?? err.message,
      });
    });
  });
}
