/**
 * Sanctuary WP-V1.x-QUERY-LAYER-ANONYMITY Rho-2 Tier B HTTP routes.
 *
 * Operator-facing surface for the Tier B PII rewrite toggle + the
 * trade-off explainer + a stateless "rewrite this text" debug
 * endpoint. Mirrors the Chi-3 anomaly-routes + Nu-1 auto-trigger
 * routes pattern: every route runs through `authMiddleware` so
 * loopback auto-auth + bearer-token gating come from the shared
 * implementation.
 *
 * Routes:
 *
 *   GET /api/query-anonymity/pii/config
 *       Read the current per-fortress config (enabled,
 *       consented_to_trade_off, consented_at, last_toggled_at).
 *
 *   PATCH /api/query-anonymity/pii/config
 *       Update config. Body JSON:
 *         { enabled?: boolean, smart_mode_enabled?: boolean,
 *           consented_to_trade_off?: boolean }
 *       Refuses (409 consent_required) if asking for enabled=true
 *       without consent_to_trade_off=true in the merged result.
 *
 *   GET /api/query-anonymity/pii/trade-off
 *       Returns the plain-English trade-off explainer. The dashboard
 *       renders this before the operator's first toggle to default-on.
 *
 *   POST /api/query-anonymity/pii/rewrite
 *       Body JSON: { text: string, use_llm?: boolean }
 *       Returns the regex-pass rewrite (no LLM call) for the
 *       dashboard's preview surface. The LLM-assisted variant is
 *       invoked from the live selector path; the route here is a
 *       deterministic preview only.
 *
 * Castle-walking: read-write against the encrypted PiiConfigStore +
 * stateless regex rewrite. No outbound surface added.
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import {
  authMiddleware,
  type AuthConfig,
} from "../console/auth-middleware.js";
import { sendCaughtError } from "../http/error-envelope.js";
import type { AuditLog } from "../operational/audit-log.js";

import {
  PiiConfigStore,
  PiiConsentRequired,
  defaultPiiRewriteConfig,
  type PiiRewriteConfig,
} from "./pii-config-store.js";
import {
  PII_REWRITE_AUDIT_OPS,
  PII_TRADE_OFF_EXPLAINER,
  rewritePiiRegexOnly,
} from "./pii-rewrite.js";

export const PII_REWRITE_API_PREFIX = "/api/query-anonymity/pii";

const MAX_BODY_BYTES = 64 * 1024;
const MAX_PREVIEW_TEXT_BYTES = 16 * 1024;

export interface PiiRewriteRouterDeps {
  authConfig: AuthConfig;
  store: PiiConfigStore;
  auditLog: AuditLog;
  identityId: string;
  fortressId: string;
  now?: () => Date;
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

/**
 * Handle a request against the Tier B surface. Returns true when
 * served (including 4xx/5xx); returns false so the caller can
 * continue routing past this prefix.
 */
export async function handlePiiRewriteRoute(
  deps: PiiRewriteRouterDeps,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const host = req.headers.host || "localhost";
  const url = new URL(req.url ?? "/", `http://${host}`);
  const method = (req.method ?? "GET").toUpperCase();
  const path = url.pathname;

  if (
    path !== PII_REWRITE_API_PREFIX &&
    !path.startsWith(`${PII_REWRITE_API_PREFIX}/`)
  ) {
    return false;
  }

  const checkAuth = authMiddleware(deps.authConfig);
  if (!checkAuth(req, res, url)) return true;

  try {
    if (
      method === "GET" &&
      path === `${PII_REWRITE_API_PREFIX}/config`
    ) {
      const now = (deps.now ?? (() => new Date()))();
      const config =
        (await deps.store.get()) ?? defaultPiiRewriteConfig(() => now);
      writeJSON(res, 200, { ok: true, data: { config } });
      return true;
    }

    if (
      method === "PATCH" &&
      path === `${PII_REWRITE_API_PREFIX}/config`
    ) {
      const body = (await readBody(req)) as
        | {
            enabled?: unknown;
            smart_mode_enabled?: unknown;
            consented_to_trade_off?: unknown;
          }
        | null;
      const patch: Partial<PiiRewriteConfig> = {};
      if (body && typeof body.enabled === "boolean") {
        patch.enabled = body.enabled;
      }
      if (body && typeof body.smart_mode_enabled === "boolean") {
        patch.smart_mode_enabled = body.smart_mode_enabled;
      }
      if (body && typeof body.consented_to_trade_off === "boolean") {
        patch.consented_to_trade_off = body.consented_to_trade_off;
      }
      if (Object.keys(patch).length === 0) {
        writeJSON(res, 400, {
          ok: false,
          error:
            "patch must include enabled, smart_mode_enabled, and/or consented_to_trade_off",
        });
        return true;
      }
      try {
        const { config: updated, consentJustRecorded } =
          await deps.store.patch(patch);
        // Audit emission: consent first, then config-updated. The
        // consent op fires only on the false -> true consent
        // transition, signalled EXPLICITLY by the store (derived from
        // state, not from comparing two independently-sampled
        // timestamps). This is deterministic regardless of how the
        // wall clock samples, closing the audit-completeness race.
        if (consentJustRecorded) {
          void deps.auditLog.append(
            "l2",
            PII_REWRITE_AUDIT_OPS.CONSENT_RECORDED,
            deps.identityId,
            {
              fortress_id: deps.fortressId,
              consented_at: updated.consented_at,
            },
          );
        }
        void deps.auditLog.append(
          "l2",
          PII_REWRITE_AUDIT_OPS.CONFIG_UPDATED,
          deps.identityId,
          {
            fortress_id: deps.fortressId,
            enabled: updated.enabled,
            smart_mode_enabled: updated.smart_mode_enabled,
            effective_tier_b_enabled:
              updated.enabled || updated.smart_mode_enabled,
            consented_to_trade_off: updated.consented_to_trade_off,
            updated_at: updated.updated_at,
          },
        );
        writeJSON(res, 200, { ok: true, data: { config: updated } });
      } catch (err) {
        if (err instanceof PiiConsentRequired) {
          writeJSON(res, 409, { ok: false, error: err.code });
        } else {
          throw err;
        }
      }
      return true;
    }

    if (
      method === "GET" &&
      path === `${PII_REWRITE_API_PREFIX}/trade-off`
    ) {
      writeJSON(res, 200, {
        ok: true,
        data: { explainer: PII_TRADE_OFF_EXPLAINER },
      });
      return true;
    }

    if (
      method === "POST" &&
      path === `${PII_REWRITE_API_PREFIX}/rewrite`
    ) {
      const body = (await readBody(req)) as { text?: unknown } | null;
      if (!body || typeof body.text !== "string") {
        writeJSON(res, 400, { ok: false, error: "text required" });
        return true;
      }
      if (body.text.length > MAX_PREVIEW_TEXT_BYTES) {
        writeJSON(res, 413, { ok: false, error: "text too large" });
        return true;
      }
      const result = rewritePiiRegexOnly(body.text);
      writeJSON(res, 200, { ok: true, data: { result } });
      return true;
    }

    writeJSON(res, 404, { ok: false, error: "not_found" });
    return true;
  } catch (err) {
    sendCaughtError(res, 500, "internal_error", err, {
      route: "query-anonymity",
      operation: `${method} ${path}`,
    });
    return true;
  }
}

/**
 * Helper for the live selector wiring (Rho-2.5 follow-up): emits the
 * `query_anonymity_pii_rewritten` audit event with per-category
 * counts. Exposed here so the eventual selector-wrapper module can
 * call it without re-implementing the audit shape.
 */
export function emitPiiRewriteAudit(opts: {
  auditLog: AuditLog;
  identityId: string;
  fortressId: string;
  redactionCounts: Record<string, number>;
  llmAssistRan: boolean;
  llmResidualCount: number;
  consentedToTradeOff: boolean;
}): void {
  void opts.auditLog.append(
    "l2",
    PII_REWRITE_AUDIT_OPS.PII_REWRITTEN,
    opts.identityId,
    {
      fortress_id: opts.fortressId,
      redaction_counts: opts.redactionCounts,
      llm_assist_ran: opts.llmAssistRan,
      llm_residual_count: opts.llmResidualCount,
      consented_to_trade_off: opts.consentedToTradeOff,
    },
  );
}
