/**
 * Sanctuary v1.3 WP-V1.3-7 Nu-1 Auto-Trigger HTTP routes.
 *
 * Mounted under `/api/auto-trigger/*`. Mirrors the Chi-3 anomaly-
 * routes shape: every route runs through `authMiddleware` so loopback
 * auto-auth + bearer-token gating come from the shared implementation.
 *
 * Routes shipped in Nu-1:
 *
 *   GET    /api/auto-trigger/rules
 *       List all rules + their current configs (rung, overrides,
 *       cancel-window, last_promoted_at, last_demoted_at). Does NOT
 *       include full history (use the detail route).
 *
 *   GET    /api/auto-trigger/rules/:rule_id
 *       Full detail INCLUDING history (bounded to last 200 entries).
 *
 *   PATCH  /api/auto-trigger/rules/:rule_id
 *       Update threshold_overrides + cancel_window_seconds. Body JSON:
 *       { rule_type: 'sentinel'|'anomaly'|'honeypot',
 *         threshold_overrides?: { warn_sigma?, alert_sigma? },
 *         cancel_window_seconds?: number }
 *
 *   POST   /api/auto-trigger/rules/:rule_id/promote
 *       Rung N -> N+1. Body must include { rule_type }.
 *
 *   POST   /api/auto-trigger/rules/:rule_id/demote
 *       Rung N -> N-1. Body must include { rule_type }.
 *
 *   POST   /api/auto-trigger/cancel/:finding_id
 *       Operator cancels a pending rung-2 auto-action within its
 *       cancel-window. Returns 200 on cancel, 404 when the finding
 *       is not pending (window already expired or never queued).
 *
 * Castle-walking: no new outbound surface; read/write against the
 * encrypted ThresholdConfigStore + dispatcher in-memory state.
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import {
  authMiddleware,
  type AuthConfig,
} from "../console/auth-middleware.js";

import {
  ActionDispatcher,
} from "./action-dispatcher.js";
import type { CalibrationSuggester } from "./calibration-suggester.js";
import type { ThresholdConfigStore } from "./threshold-config-store.js";
import {
  AutoTriggerError,
  type AutoTriggerRuleType,
  type RuleThresholdConfig,
  type ThresholdOverrides,
} from "./types.js";

export const AUTO_TRIGGER_API_PREFIX = "/api/auto-trigger";

const MAX_BODY_BYTES = 16 * 1024;

export interface AutoTriggerRouterDeps {
  authConfig: AuthConfig;
  store: ThresholdConfigStore;
  dispatcher: ActionDispatcher;
  suggester?: CalibrationSuggester;
}

function writeJSON(
  res: ServerResponse,
  status: number,
  payload: unknown,
): void {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(payload));
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (chunks.length === 0) {
        resolve(null);
        return;
      }
      try {
        const text = Buffer.concat(chunks).toString("utf8");
        resolve(JSON.parse(text));
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

function isRuleType(value: unknown): value is AutoTriggerRuleType {
  return value === "sentinel" || value === "anomaly" || value === "honeypot";
}

/** Strip the history field for the list endpoint. */
function summarizeConfig(config: RuleThresholdConfig): Omit<
  RuleThresholdConfig,
  "history"
> & { history_count: number } {
  const { history, ...rest } = config;
  return { ...rest, history_count: history.length };
}

function matchRuleDetailRoute(path: string): { ruleId: string } | null {
  const prefix = `${AUTO_TRIGGER_API_PREFIX}/rules/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (rest.length === 0) return null;
  if (rest.includes("/")) return null;
  return { ruleId: decodeURIComponent(rest) };
}

function matchRulePromoteRoute(
  path: string,
): { ruleId: string } | null {
  const prefix = `${AUTO_TRIGGER_API_PREFIX}/rules/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (!rest.endsWith("/promote")) return null;
  const ruleId = rest.slice(0, rest.length - "/promote".length);
  if (ruleId.length === 0 || ruleId.includes("/")) return null;
  return { ruleId: decodeURIComponent(ruleId) };
}

function matchRuleDemoteRoute(path: string): { ruleId: string } | null {
  const prefix = `${AUTO_TRIGGER_API_PREFIX}/rules/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (!rest.endsWith("/demote")) return null;
  const ruleId = rest.slice(0, rest.length - "/demote".length);
  if (ruleId.length === 0 || ruleId.includes("/")) return null;
  return { ruleId: decodeURIComponent(ruleId) };
}

function matchRuleRecommendationRoute(
  path: string,
): { ruleId: string } | null {
  const prefix = `${AUTO_TRIGGER_API_PREFIX}/rules/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (!rest.endsWith("/recommendation")) return null;
  const ruleId = rest.slice(0, rest.length - "/recommendation".length);
  if (ruleId.length === 0 || ruleId.includes("/")) return null;
  return { ruleId: decodeURIComponent(ruleId) };
}

function matchAcceptRecommendationRoute(
  path: string,
): { ruleId: string } | null {
  const prefix = `${AUTO_TRIGGER_API_PREFIX}/rules/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (!rest.endsWith("/accept-recommendation")) return null;
  const ruleId = rest.slice(0, rest.length - "/accept-recommendation".length);
  if (ruleId.length === 0 || ruleId.includes("/")) return null;
  return { ruleId: decodeURIComponent(ruleId) };
}

function matchRejectRecommendationRoute(
  path: string,
): { ruleId: string } | null {
  const prefix = `${AUTO_TRIGGER_API_PREFIX}/rules/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (!rest.endsWith("/reject-recommendation")) return null;
  const ruleId = rest.slice(0, rest.length - "/reject-recommendation".length);
  if (ruleId.length === 0 || ruleId.includes("/")) return null;
  return { ruleId: decodeURIComponent(ruleId) };
}

function matchCancelRoute(path: string): { findingId: string } | null {
  const prefix = `${AUTO_TRIGGER_API_PREFIX}/cancel/`;
  if (!path.startsWith(prefix)) return null;
  const findingId = path.slice(prefix.length);
  if (findingId.length === 0 || findingId.includes("/")) return null;
  return { findingId: decodeURIComponent(findingId) };
}

/**
 * Handle a request against the auto-trigger surface. Returns true
 * when served (including 4xx/5xx); returns false so the caller can
 * continue routing.
 */
export async function handleAutoTriggerRoute(
  deps: AutoTriggerRouterDeps,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const host = req.headers.host || "localhost";
  const url = new URL(req.url ?? "/", `http://${host}`);
  const method = (req.method ?? "GET").toUpperCase();
  const path = url.pathname;

  if (
    path !== AUTO_TRIGGER_API_PREFIX &&
    !path.startsWith(`${AUTO_TRIGGER_API_PREFIX}/`)
  ) {
    return false;
  }

  const checkAuth = authMiddleware(deps.authConfig);
  if (!checkAuth(req, res, url)) return true;

  try {
    // GET /api/auto-trigger/rules
    if (method === "GET" && path === `${AUTO_TRIGGER_API_PREFIX}/rules`) {
      const ids = await deps.store.listRuleIds();
      const rules: Array<ReturnType<typeof summarizeConfig>> = [];
      for (const id of ids) {
        const config = await deps.store.get(id);
        if (config) rules.push(summarizeConfig(config));
      }
      writeJSON(res, 200, { ok: true, data: { rules } });
      return true;
    }

    // GET /api/auto-trigger/recommendations
    if (
      method === "GET" &&
      path === `${AUTO_TRIGGER_API_PREFIX}/recommendations`
    ) {
      if (!deps.suggester) {
        writeJSON(res, 503, { ok: false, error: "suggester_not_configured" });
        return true;
      }
      const recommendations = await deps.suggester.listRecommendations({
        includeSuppressed: true,
        includeNoChange: false,
      });
      writeJSON(res, 200, { ok: true, data: { recommendations } });
      return true;
    }

    // GET /api/auto-trigger/rules/:rule_id/recommendation
    if (method === "GET") {
      const match = matchRuleRecommendationRoute(path);
      if (match) {
        if (!deps.suggester) {
          writeJSON(res, 503, { ok: false, error: "suggester_not_configured" });
          return true;
        }
        const recommendation = await deps.suggester.getRecommendation(
          match.ruleId,
          { includeSuppressed: true, includeNoChange: true },
        );
        if (!recommendation) {
          writeJSON(res, 404, { ok: false, error: "rule_not_found" });
          return true;
        }
        writeJSON(res, 200, { ok: true, data: { recommendation } });
        return true;
      }
    }

    // GET /api/auto-trigger/rules/:rule_id
    if (method === "GET") {
      const match = matchRuleDetailRoute(path);
      if (match) {
        const config = await deps.store.get(match.ruleId);
        if (!config) {
          writeJSON(res, 404, { ok: false, error: "rule_not_found" });
          return true;
        }
        writeJSON(res, 200, { ok: true, data: { rule: config } });
        return true;
      }
    }

    // PATCH /api/auto-trigger/rules/:rule_id
    if (method === "PATCH") {
      const match = matchRuleDetailRoute(path);
      if (match) {
        const body = (await readBody(req)) as
          | {
              rule_type?: unknown;
              threshold_overrides?: unknown;
              cancel_window_seconds?: unknown;
            }
          | null;
        if (!body || !isRuleType(body.rule_type)) {
          writeJSON(res, 400, {
            ok: false,
            error: "rule_type required (sentinel|anomaly|honeypot)",
          });
          return true;
        }
        const overrides = sanitizeOverrides(body.threshold_overrides);
        const cancelWindow = sanitizeCancelWindow(body.cancel_window_seconds);
        const patch: Parameters<ActionDispatcher["updateThresholds"]>[2] = {};
        if (overrides) patch.threshold_overrides = overrides;
        if (cancelWindow !== undefined)
          patch.cancel_window_seconds = cancelWindow;
        const updated = await deps.dispatcher.updateThresholds(
          match.ruleId,
          body.rule_type,
          patch,
        );
        writeJSON(res, 200, { ok: true, data: { rule: updated } });
        return true;
      }
    }

    // POST /api/auto-trigger/rules/:rule_id/promote
    if (method === "POST") {
      const promote = matchRulePromoteRoute(path);
      if (promote) {
        const body = (await readBody(req)) as { rule_type?: unknown } | null;
        if (!body || !isRuleType(body.rule_type)) {
          writeJSON(res, 400, {
            ok: false,
            error: "rule_type required (sentinel|anomaly|honeypot)",
          });
          return true;
        }
        try {
          const after = await deps.dispatcher.promoteRule(
            promote.ruleId,
            body.rule_type,
          );
          writeJSON(res, 200, { ok: true, data: { rule: after } });
        } catch (err) {
          if (err instanceof AutoTriggerError && err.code === "rung_ceiling") {
            writeJSON(res, 409, { ok: false, error: err.code });
          } else {
            throw err;
          }
        }
        return true;
      }

      // POST /api/auto-trigger/rules/:rule_id/demote
      const demote = matchRuleDemoteRoute(path);
      if (demote) {
        const body = (await readBody(req)) as { rule_type?: unknown } | null;
        if (!body || !isRuleType(body.rule_type)) {
          writeJSON(res, 400, {
            ok: false,
            error: "rule_type required (sentinel|anomaly|honeypot)",
          });
          return true;
        }
        try {
          const after = await deps.dispatcher.demoteRule(
            demote.ruleId,
            body.rule_type,
          );
          writeJSON(res, 200, { ok: true, data: { rule: after } });
        } catch (err) {
          if (err instanceof AutoTriggerError && err.code === "rung_floor") {
            writeJSON(res, 409, { ok: false, error: err.code });
          } else {
            throw err;
          }
        }
        return true;
      }

      const acceptRecommendation = matchAcceptRecommendationRoute(path);
      if (acceptRecommendation) {
        if (!deps.suggester) {
          writeJSON(res, 503, { ok: false, error: "suggester_not_configured" });
          return true;
        }
        try {
          const accepted = await deps.suggester.acceptRecommendation(
            acceptRecommendation.ruleId,
          );
          writeJSON(res, 200, { ok: true, data: accepted });
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          writeJSON(res, 404, { ok: false, error: "recommendation_not_found", message: msg });
        }
        return true;
      }

      const rejectRecommendation = matchRejectRecommendationRoute(path);
      if (rejectRecommendation) {
        if (!deps.suggester) {
          writeJSON(res, 503, { ok: false, error: "suggester_not_configured" });
          return true;
        }
        const body = (await readBody(req)) as
          | { cooldown_hours?: unknown }
          | null;
        const cooldownHours =
          typeof body?.cooldown_hours === "number" &&
          Number.isFinite(body.cooldown_hours)
            ? body.cooldown_hours
            : undefined;
        try {
          const rejected = await deps.suggester.rejectRecommendation(
            rejectRecommendation.ruleId,
            cooldownHours,
          );
          writeJSON(res, 200, { ok: true, data: rejected });
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          writeJSON(res, 404, { ok: false, error: "rule_not_found", message: msg });
        }
        return true;
      }

      // POST /api/auto-trigger/cancel/:finding_id
      const cancel = matchCancelRoute(path);
      if (cancel) {
        const canceled = await deps.dispatcher.cancelPending(cancel.findingId);
        if (!canceled) {
          writeJSON(res, 404, { ok: false, error: "pending_not_found" });
          return true;
        }
        writeJSON(res, 200, { ok: true, data: { canceled: true } });
        return true;
      }
    }

    // Method or path under prefix but unmatched.
    writeJSON(res, 404, { ok: false, error: "not_found" });
    return true;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    writeJSON(res, 500, { ok: false, error: "internal", message });
    return true;
  }
}

function sanitizeOverrides(raw: unknown): ThresholdOverrides | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const obj = raw as Record<string, unknown>;
  const out: ThresholdOverrides = {};
  if (typeof obj["warn_sigma"] === "number" && Number.isFinite(obj["warn_sigma"])) {
    out.warn_sigma = obj["warn_sigma"];
  }
  if (
    typeof obj["alert_sigma"] === "number" &&
    Number.isFinite(obj["alert_sigma"])
  ) {
    out.alert_sigma = obj["alert_sigma"];
  }
  if (
    typeof obj["promotion_fire_count"] === "number" &&
    Number.isFinite(obj["promotion_fire_count"]) &&
    obj["promotion_fire_count"] >= 1
  ) {
    out.promotion_fire_count = Math.floor(obj["promotion_fire_count"]);
  }
  if (
    typeof obj["promotion_window_days"] === "number" &&
    Number.isFinite(obj["promotion_window_days"]) &&
    obj["promotion_window_days"] >= 1
  ) {
    out.promotion_window_days = Math.floor(obj["promotion_window_days"]);
  }
  if (
    typeof obj["demotion_cancel_count"] === "number" &&
    Number.isFinite(obj["demotion_cancel_count"]) &&
    obj["demotion_cancel_count"] >= 1
  ) {
    out.demotion_cancel_count = Math.floor(obj["demotion_cancel_count"]);
  }
  return out;
}

function sanitizeCancelWindow(raw: unknown): number | undefined {
  if (typeof raw !== "number") return undefined;
  if (!Number.isFinite(raw)) return undefined;
  if (raw < 1) return undefined;
  if (raw > 3600) return undefined;
  return Math.floor(raw);
}
