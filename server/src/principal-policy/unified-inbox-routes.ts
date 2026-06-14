/**
 * Sanctuary WP-V1.3-4 Psi-1 Unified Inbox HTTP routes.
 *
 * Mounted under `/api/inbox/unified/*`. Mirrors the established
 * Phi-1 sentinel-routes / Chi-3 anomaly-routes pattern: every route
 * runs through the existing `authMiddleware` so loopback auto-auth +
 * bearer-token gating come from one shared implementation.
 *
 *   GET    /api/inbox/unified                      list (with filters)
 *   GET    /api/inbox/unified/stream               SSE: new entries + resolutions
 *   GET    /api/inbox/unified/:inbox_id            full detail
 *   POST   /api/inbox/unified/:inbox_id/resolve    operator-marks-resolved
 *
 * Castle-walking: no new outbound surface. Read-only against the
 * bridge; resolve is operator-auth-gated and only mutates in-memory
 * state.
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import {
  authMiddleware,
  type AuthConfig,
} from "../console/auth-middleware.js";
import {
  UnifiedInboxBridge,
  type InboxQuery,
  type UnifiedInboxBridgeEvent,
  type UnifiedInboxEntryState,
  type UnifiedInboxSeverity,
  type UnifiedInboxSourceClass,
} from "./unified-inbox-bridge.js";
import {
  INBOX_RETENTION_AUDIT_OPS,
  type RetentionPolicy,
  UnifiedInboxRetentionPolicy,
  type UnifiedInboxRetentionPolicyStore,
} from "./unified-inbox-retention-policy.js";
import {
  normalizePrefs,
  type UnifiedInboxPrefsStore,
} from "./unified-inbox-prefs-store.js";

export const UNIFIED_INBOX_API_PREFIX = "/api/inbox/unified";
export const UNIFIED_INBOX_RETENTION_API_PREFIX = "/api/inbox/retention";
export const UNIFIED_INBOX_PREFS_API_PATH = `${UNIFIED_INBOX_API_PREFIX}/prefs`;

export interface UnifiedInboxRouterDeps {
  authConfig: AuthConfig;
  bridge: UnifiedInboxBridge;
  retentionPolicy?: UnifiedInboxRetentionPolicy;
  retentionPolicyStore?: UnifiedInboxRetentionPolicyStore;
  prefsStore?: UnifiedInboxPrefsStore;
  auditLog?: import("../l2-operational/audit-log.js").AuditLog;
  identityId?: string;
  fortressId?: string;
}

const LIST_DEFAULT_LIMIT = 100;
const LIST_MAX_LIMIT = 500;

const VALID_SOURCE_CLASSES = new Set<UnifiedInboxSourceClass>([
  "approval",
  "sentinel_finding",
  "blocked_egress",
  "privacy_event",
  "budget_warning",
  "recovery_prompt",
  "agent_error",
]);

const VALID_SEVERITIES = new Set<UnifiedInboxSeverity>([
  "info",
  "warn",
  "alert",
  "critical",
]);

const VALID_STATES = new Set<UnifiedInboxEntryState>([
  "active",
  "archived",
  "snoozed",
  "dismissed",
]);

function writeJSON(
  res: ServerResponse,
  status: number,
  payload: unknown,
): void {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    Connection: "close",
  });
  res.end(JSON.stringify(payload));
}

function parseLimit(
  raw: string | null,
  defaultValue: number,
  max: number,
): number {
  if (raw === null || raw === "") return defaultValue;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed) || parsed < 0) return defaultValue;
  return Math.min(parsed, max);
}

function hasHardDeleteConfirmation(body: Record<string, unknown>): boolean {
  return body.confirm_delete === true;
}

function matchEntryPath(path: string): {
  inboxId: string;
  action: "get" | "resolve" | "archive" | "dismiss" | "snooze" | "unsnooze" | "delete";
} | null {
  const prefix = `${UNIFIED_INBOX_API_PREFIX}/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (rest === "stream") return null;
  if (rest.endsWith("/resolve")) {
    const inboxId = rest.slice(0, rest.length - "/resolve".length);
    if (inboxId.length === 0 || inboxId.includes("/")) return null;
    return { inboxId: decodeURIComponent(inboxId), action: "resolve" };
  }
  for (const action of ["archive", "dismiss", "snooze", "unsnooze", "delete"] as const) {
    const suffix = `/${action}`;
    if (rest.endsWith(suffix)) {
      const inboxId = rest.slice(0, rest.length - suffix.length);
      if (inboxId.length === 0 || inboxId.includes("/")) return null;
      return { inboxId: decodeURIComponent(inboxId), action };
    }
  }
  if (rest.includes("/")) return null;
  return { inboxId: decodeURIComponent(rest), action: "get" };
}

/**
 * True when `path` targets `POST :id/resolve` - the operator's
 * resolution of an approval entry (a Tier-1 approval decision). Reuses
 * `matchEntryPath` so it stays in lockstep with the dispatcher's route
 * parsing.
 */
function isApprovalResolvePath(path: string): boolean {
  const match = matchEntryPath(path);
  return match !== null && match.action === "resolve";
}

/**
 * Route handler. Returns true when served (including 4xx/5xx);
 * returns false to let the caller continue routing.
 */
export async function handleUnifiedInboxRoute(
  deps: UnifiedInboxRouterDeps,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const host = req.headers.host || "localhost";
  const url = new URL(req.url ?? "/", `http://${host}`);
  const method = (req.method ?? "GET").toUpperCase();
  const path = url.pathname;

  if (
    path !== UNIFIED_INBOX_API_PREFIX &&
    !path.startsWith(`${UNIFIED_INBOX_API_PREFIX}/`) &&
    path !== UNIFIED_INBOX_RETENTION_API_PREFIX &&
    !path.startsWith(`${UNIFIED_INBOX_RETENTION_API_PREFIX}/`)
  ) {
    return false;
  }

  // SECURITY (loopback-no-autoauth-for-approvals): `POST :id/resolve`
  // records the operator's resolution of an approval entry - a Tier-1
  // approval decision. It must ALWAYS require the operator bearer token,
  // even on loopback with `--auto-auth-localhost` on, so a co-resident
  // agent sharing loopback cannot self-resolve its own approval. Other
  // routes (list, get, archive/dismiss/snooze/delete inbox housekeeping,
  // retention, prefs) keep loopback auto-auth for local-dashboard
  // convenience. `requireToken` suppresses only the loopback shortcut;
  // token validation is unchanged.
  const isApprovalDecision =
    method === "POST" && isApprovalResolvePath(path);
  const checkAuth = authMiddleware(
    deps.authConfig,
    isApprovalDecision ? { requireToken: true } : undefined,
  );
  if (!checkAuth(req, res, url)) return true;

  try {
    if (path === UNIFIED_INBOX_PREFS_API_PATH) {
      if (!deps.prefsStore) {
        writeJSON(res, 503, {
          ok: false,
          error: "prefs_store_not_configured",
        });
        return true;
      }
      if (method === "GET") {
        writeJSON(res, 200, {
          ok: true,
          data: { filters: await deps.prefsStore.load() },
        });
        return true;
      }
      if (method === "PUT") {
        const body = await readJsonBody(req);
        const filters = normalizePrefs(
          typeof body.filters === "object" && body.filters !== null
            ? body.filters
            : body,
        );
        writeJSON(res, 200, {
          ok: true,
          data: { filters: await deps.prefsStore.save(filters) },
        });
        return true;
      }
      writeJSON(res, 405, { ok: false, error: "method_not_allowed" });
      return true;
    }

    if (method === "GET" && path === UNIFIED_INBOX_API_PREFIX) {
      const sourceClassRaw =
        url.searchParams.get("source_class") ?? undefined;
      const severityRaw = url.searchParams.get("severity") ?? undefined;
      const stateRaw = url.searchParams.get("state") ?? undefined;
      const since = url.searchParams.get("since") ?? undefined;
      const fullText = url.searchParams.get("full_text") ?? undefined;
      const agentId = url.searchParams.get("agent_id") ?? undefined;
      const includeResolved =
        url.searchParams.get("include_resolved") === "true";
      const limit = parseLimit(
        url.searchParams.get("limit"),
        LIST_DEFAULT_LIMIT,
        LIST_MAX_LIMIT,
      );
      const sourceClass =
        sourceClassRaw &&
        VALID_SOURCE_CLASSES.has(sourceClassRaw as UnifiedInboxSourceClass)
          ? (sourceClassRaw as UnifiedInboxSourceClass)
          : undefined;
      const severity =
        severityRaw &&
        VALID_SEVERITIES.has(severityRaw as UnifiedInboxSeverity)
          ? (severityRaw as UnifiedInboxSeverity)
          : undefined;
      const state =
        stateRaw && VALID_STATES.has(stateRaw as UnifiedInboxEntryState)
          ? (stateRaw as UnifiedInboxEntryState)
          : undefined;
      const query: InboxQuery = {
        limit,
        ...(sourceClass !== undefined ? { source_class: sourceClass } : {}),
        ...(severity !== undefined ? { severity: [severity] } : {}),
        ...(agentId !== undefined ? { agent_id: agentId } : {}),
        ...(fullText !== undefined ? { full_text: fullText } : {}),
        ...(since !== undefined
          ? {
              time_range: {
                from: since,
                to: new Date(8_640_000_000_000_000).toISOString(),
              },
            }
          : {}),
        state: state !== undefined
          ? [state]
          : includeResolved
            ? ["active", "archived", "snoozed", "dismissed"]
            : ["active"],
      };
      const entries = deps.bridge.queryInbox(query);
      writeJSON(res, 200, {
        ok: true,
        data: { entries, count: deps.bridge.countInbox(query) },
      });
      return true;
    }

    if (
      method === "GET" &&
      path === `${UNIFIED_INBOX_API_PREFIX}/stream`
    ) {
      return await handleSse(deps.bridge, req, res);
    }

    const entryMatch = matchEntryPath(path);
    if (entryMatch) {
      if (method === "GET" && entryMatch.action === "get") {
        const entry = deps.bridge.get(entryMatch.inboxId);
        if (!entry) {
          writeJSON(res, 404, { ok: false, error: "not_found" });
          return true;
        }
        writeJSON(res, 200, { ok: true, data: { entry } });
        return true;
      }
      if (method === "POST" && entryMatch.action === "resolve") {
        const resolvedBy = (req.headers["x-resolver-identity"] as
          | string
          | undefined) ??
          "operator";
        const entry = deps.bridge.resolve(entryMatch.inboxId, resolvedBy);
        if (!entry) {
          writeJSON(res, 404, { ok: false, error: "not_found" });
          return true;
        }
        writeJSON(res, 200, { ok: true, data: { entry } });
        return true;
      }
      if (method === "POST" && entryMatch.action !== "get") {
        const body = await readJsonBody(req);
        if (
          entryMatch.action === "delete" &&
          !hasHardDeleteConfirmation(body)
        ) {
          writeJSON(res, 400, {
            ok: false,
            error: "delete_confirmation_required",
          });
          return true;
        }
        const until = typeof body.until === "string" ? body.until : undefined;
        const id = entryMatch.inboxId;
        const result =
          entryMatch.action === "archive"
            ? deps.bridge.archiveBatch([id])
            : entryMatch.action === "dismiss"
              ? deps.bridge.dismissBatch([id])
              : entryMatch.action === "snooze"
                ? deps.bridge.snoozeBatch([id], until ?? "")
                : entryMatch.action === "unsnooze"
                  ? deps.bridge.unsnooze(id)
                  : deps.bridge.deleteBatch([id]);
        writeJSON(res, 200, { ok: true, data: { result } });
        return true;
      }
    }

    if (path === UNIFIED_INBOX_RETENTION_API_PREFIX && method === "GET") {
      const policy = deps.retentionPolicy ?? new UnifiedInboxRetentionPolicy();
      writeJSON(res, 200, {
        ok: true,
        data: {
          defaults: {
            archived: 90,
            dismissed: 30,
          },
          policies: policy.list(),
        },
      });
      return true;
    }

    if (
      method === "PATCH" &&
      path.startsWith(`${UNIFIED_INBOX_RETENTION_API_PREFIX}/`)
    ) {
      const match = matchRetentionPath(path);
      if (!match) {
        writeJSON(res, 404, { ok: false, error: "not_found", path });
        return true;
      }
      const body = await readJsonBody(req);
      const retainForDays = Number(body.retain_for_days);
      if (!Number.isFinite(retainForDays) || retainForDays < 0) {
        writeJSON(res, 400, {
          ok: false,
          error: "retain_for_days must be a non-negative number",
        });
        return true;
      }
      const policy = deps.retentionPolicy ?? new UnifiedInboxRetentionPolicy();
      const updated: RetentionPolicy = {
        source_class: match.sourceClass,
        state: match.state,
        retain_for_days: Math.floor(retainForDays),
      };
      policy.set(updated);
      await deps.retentionPolicyStore?.save(policy);
      void deps.auditLog?.append(
        "l2",
        INBOX_RETENTION_AUDIT_OPS.POLICY_UPDATED,
        deps.identityId ?? "operator",
        {
          fortress_id: deps.fortressId,
          source_class: updated.source_class,
          state: updated.state,
          retain_for_days: updated.retain_for_days,
          changed_at: new Date().toISOString(),
        },
      );
      writeJSON(res, 200, { ok: true, data: { policy: updated } });
      return true;
    }

    if (method === "POST" && path === `${UNIFIED_INBOX_API_PREFIX}/batch`) {
      const body = await readJsonBody(req);
      const ids = Array.isArray(body.entry_ids)
        ? body.entry_ids.filter((v: unknown): v is string => typeof v === "string")
        : [];
      const action = body.action;
      if (action === "delete" && !hasHardDeleteConfirmation(body)) {
        writeJSON(res, 400, {
          ok: false,
          error: "delete_confirmation_required",
        });
        return true;
      }
      const result =
        action === "archive"
          ? deps.bridge.archiveBatch(ids)
          : action === "dismiss"
            ? deps.bridge.dismissBatch(ids)
            : action === "snooze"
              ? deps.bridge.snoozeBatch(ids, String(body.until ?? ""))
              : action === "delete"
                ? deps.bridge.deleteBatch(ids)
                : null;
      if (!result) {
        writeJSON(res, 400, { ok: false, error: "bad_action" });
        return true;
      }
      writeJSON(res, 200, { ok: true, data: { result } });
      return true;
    }

    writeJSON(res, 404, { ok: false, error: "not_found", path });
    return true;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    writeJSON(res, 500, { ok: false, error: "internal", detail: msg });
    return true;
  }
}

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  if (chunks.length === 0) return {};
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function matchRetentionPath(path: string): {
  sourceClass: UnifiedInboxSourceClass;
  state: RetentionPolicy["state"];
} | null {
  const prefix = `${UNIFIED_INBOX_RETENTION_API_PREFIX}/`;
  if (!path.startsWith(prefix)) return null;
  const parts = path.slice(prefix.length).split("/");
  if (parts.length !== 2) return null;
  const sourceClass = decodeURIComponent(parts[0] ?? "");
  const state = decodeURIComponent(parts[1] ?? "");
  if (!VALID_SOURCE_CLASSES.has(sourceClass as UnifiedInboxSourceClass)) {
    return null;
  }
  if (state !== "archived" && state !== "dismissed") {
    return null;
  }
  return {
    sourceClass: sourceClass as UnifiedInboxSourceClass,
    state,
  };
}

async function handleSse(
  bridge: UnifiedInboxBridge,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-store",
    Connection: "keep-alive",
  });
  // Initial event: a sentinel ready-message so clients can detect
  // connection establishment.
  res.write(`event: ready\n`);
  res.write(`data: ${JSON.stringify({ ok: true })}\n\n`);
  const unsubscribe = bridge.onEvent((event: UnifiedInboxBridgeEvent) => {
    try {
      const eventName =
        event.type === "ingested" ? "entry_ingested" : "entry_resolved";
      res.write(`event: ${eventName}\n`);
      res.write(`data: ${JSON.stringify(event.entry)}\n\n`);
    } catch {
      // Client closed; cleanup happens on req close.
    }
  });
  req.on("close", () => {
    unsubscribe();
    try {
      res.end();
    } catch {
      // already closed
    }
  });
  // The promise never resolves while the SSE connection is open; the
  // caller's handler returns true to signal the route was served.
  return true;
}
