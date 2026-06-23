/**
 * Sanctuary MCP Server — tenant dashboard health probe
 *
 * Checks whether a tenant's dashboard is actually a live Sanctuary build by
 * hitting `/api/health` on the host+port the tenant's runtime.json advertises.
 *
 * Honesty discipline (never-overclaim): a port that merely answers HTTP is NOT
 * proof a Sanctuary tenant is running there. A crashed tenant's port can be
 * reused by an unrelated process, and an older/foreign server can return any
 * status. We therefore confirm "running" only when the response identifies the
 * responder as a current Sanctuary build:
 *
 *   - status 200 AND a body shaped `{ ok: true, mode }` (the contract this
 *     endpoint serves) → confirmed Sanctuary tenant.
 *   - status 401 → SOMETHING auth-gated is listening, but a bare 401 proves only
 *     that, not that the responder is Sanctuary. This probe sends no
 *     Authorization header, so any auth-gated foreign server (nginx basic-auth,
 *     an unrelated token-gated API) returns 401 identically. We therefore treat
 *     401 as "port answered, not confirmed Sanctuary", symmetric with how a
 *     foreign 200/404 is handled — never as confirmed.
 *   - any other answer (200 with a foreign/missing body, a bare 404 that proves
 *     the responder is not a current build, a 3xx, etc.) → "port answered, not
 *     confirmed Sanctuary": something is listening, but it is not provably this
 *     agent. This is a distinct state from "running" and from "not running".
 *   - 5xx, connection refused, timeout, network error → not running.
 */

import { get, type IncomingMessage } from "node:http";
import type { TenantDescriptor } from "./discovery.js";

export interface HealthProbeOptions {
  /** Millisecond timeout. Default 500ms. */
  timeoutMs?: number;
}

/**
 * Probe outcome state space.
 *   - `confirmed`: a current Sanctuary build answered and identified itself.
 *   - `answered_unconfirmed`: a port answered HTTP but did not prove it is a
 *     current Sanctuary tenant (foreign server, bare 404, unexpected body).
 *   - `not_running`: nothing usable answered (5xx, refused, timeout, error).
 */
export type HealthProbeState =
  | "confirmed"
  | "answered_unconfirmed"
  | "not_running";

export interface HealthProbeResult {
  /**
   * True ONLY when the responder is a confirmed current Sanctuary build. A bare
   * port answer is NOT running. Kept for back-compat with existing callers.
   */
  running: boolean;
  /** Full probe state. Prefer this over `running` for new code. */
  state: HealthProbeState;
  /** HTTP status, if any response reached us. */
  status: number | null;
  /** Why we marked the tenant not-running / not-confirmed; null when confirmed. */
  reason: string | null;
}

const DEFAULT_TIMEOUT_MS = 500;
/** Cap on the health body we will read before deciding (defense vs. a chatty foreign server). */
const MAX_BODY_BYTES = 4096;

/**
 * Validate the `/api/health` body shape: `{ ok: true, mode: <string> }`.
 * A foreign 200 (e.g. an unrelated web server on a reused port) will not match.
 *
 * The probe keys ONLY on `ok` + `mode`, the frozen liveness contract. Newer
 * builds also emit additive opaque fields on `/api/health` (`instance`, a
 * per-boot id, and `since`, the process start time, per the Dashboard Server
 * Lifecycle Hardening brief D3); those are tolerated and ignored here, so an
 * older probe accepts a newer server and a newer probe accepts an older one.
 * Readiness/posture (`ready`/`supervisor`) never appear on `/api/health` (they
 * are auth-gated on `/api/readiness`), so this unauthenticated probe must not
 * key on them.
 */
function isSanctuaryHealthBody(raw: string): boolean {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return false;
  }
  if (typeof parsed !== "object" || parsed === null) return false;
  const body = parsed as Record<string, unknown>;
  return body.ok === true && typeof body.mode === "string";
}

/**
 * Probe a single tenant's dashboard. Never throws.
 */
export async function probeTenantDashboard(
  tenant: TenantDescriptor,
  options: HealthProbeOptions = {}
): Promise<HealthProbeResult> {
  const rt = tenant.runtime;
  if (!rt) {
    return {
      running: false,
      state: "not_running",
      status: null,
      reason: "no runtime.json",
    };
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
        const status = res.statusCode ?? 0;

        // 401: an auth-gated responder is listening, but we sent no Authorization
        // header — any token-gated foreign server (nginx basic-auth, an unrelated
        // API) returns 401 identically, so a bare 401 does NOT prove Sanctuary.
        // Downgrade to answered_unconfirmed, symmetric with foreign 200/404.
        if (status === 401) {
          res.resume();
          resolve({
            running: false,
            state: "answered_unconfirmed",
            status,
            reason: "port answered 401 (auth-gated), not confirmed Sanctuary",
          });
          return;
        }

        // 200: must carry the Sanctuary health body to be confirmed. A foreign
        // server squatting on a reused port can also return 200, so we validate.
        if (status === 200) {
          let body = "";
          let bytes = 0;
          let aborted = false;
          res.setEncoding("utf8");
          res.on("data", (chunk: string) => {
            if (aborted) return;
            bytes += Buffer.byteLength(chunk, "utf8");
            if (bytes > MAX_BODY_BYTES) {
              aborted = true;
              res.destroy();
              return;
            }
            body += chunk;
          });
          res.on("end", () => {
            if (isSanctuaryHealthBody(body)) {
              resolve({
                running: true,
                state: "confirmed",
                status,
                reason: null,
              });
            } else {
              resolve({
                running: false,
                state: "answered_unconfirmed",
                status,
                reason: "200 without a Sanctuary health body",
              });
            }
          });
          res.on("error", () => {
            resolve({
              running: false,
              state: "answered_unconfirmed",
              status,
              reason: "200 body read failed",
            });
          });
          return;
        }

        // Anything else that answered HTTP (bare 404 from a non-current build,
        // 3xx, other 4xx) is a port that answered but is not a confirmed
        // Sanctuary tenant. A 5xx, by contrast, is a server in trouble: not
        // running.
        res.resume();
        if (status >= 500) {
          resolve({
            running: false,
            state: "not_running",
            status,
            reason: `dashboard returned ${status}`,
          });
        } else {
          resolve({
            running: false,
            state: "answered_unconfirmed",
            status,
            reason: `port answered ${status}, not a confirmed Sanctuary build`,
          });
        }
      }
    );
    req.on("timeout", () => {
      req.destroy();
      resolve({
        running: false,
        state: "not_running",
        status: null,
        reason: "timeout",
      });
    });
    req.on("error", (err) => {
      resolve({
        running: false,
        state: "not_running",
        status: null,
        reason: (err as NodeJS.ErrnoException).code ?? err.message,
      });
    });
  });
}
