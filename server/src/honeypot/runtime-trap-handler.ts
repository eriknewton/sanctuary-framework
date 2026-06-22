/**
 * Sanctuary v1.3 WP-V1.3-5 Pi-1 Runtime Trap Handler + Management Routes.
 *
 * Two responsibilities, deliberately co-located so the wiring layer
 * has one place to mount everything:
 *
 *   1. handleHoneypotTriggerIfMatch:
 *      Front-of-dashboard hook called by the dashboard router BEFORE
 *      any legacy / v1.1 / sentinel / coordination dispatch. If the
 *      registry has a trap whose pattern matches the request, the
 *      handler emits the audit event + sentinel finding and returns
 *      a plausible 404 to the caller. Castle-walking core: the trap
 *      RESPONSE is server-internal; nothing leaves the fortress.
 *
 *   2. handleHoneypotRoute:
 *      Management API at /api/honeypot/* surface:
 *        POST   /api/honeypot/compile         compile English -> spec
 *        POST   /api/honeypot/deploy          deploy a spec
 *        GET    /api/honeypot/traps           list deployed traps
 *        DELETE /api/honeypot/traps/:trap_id  undeploy
 *        GET    /api/honeypot/findings        list trap findings
 *
 *      Auth-gated via the existing operator middleware. Multi-fortress
 *      isolation rides on the per-fortress registry + finding store.
 *
 * Castle-walking discipline:
 *   - Trap response is plausible 404 server-local; no outbound surface.
 *   - Trap-triggered findings route through Phi-1's finding store
 *     (the canonical Castle Layer 2 observability pipeline).
 *   - Audit emission on every operator action + every trap trigger.
 *   - The compile route delegates to honeypot-compiler.ts which routes
 *     through the substrate selector on the `template-suggestion`
 *     surface; that path is the canonical outbound LLM channel and
 *     respects the no-outbound-by-default rule (operator must wire
 *     a selector for the LLM path to fire; otherwise the compiler
 *     falls back to its heuristic path).
 */

import { createHash, randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

import {
  authMiddleware,
  type AuthConfig,
} from "../console/auth-middleware.js";
import {
  logCaughtError,
  sendCaughtError,
  type PublicErrorCode,
} from "../http/error-envelope.js";
import type { AuditLog } from "../operational/audit-log.js";
import type { SentinelFindingStore } from "../sentinel/sentinel-finding-store.js";
import type {
  SentinelFinding,
  SentinelSeverity,
} from "../sentinel/types.js";
import type { SubstrateSelector } from "../intelligence/selector.js";

import {
  HONEYPOT_AUDIT_OPS,
  HONEYPOT_SENTINEL_ID_PREFIX,
  honeypotSentinelId,
  type HoneypotDraft,
  type TrapSpec,
} from "./types.js";
import {
  compileHoneypot,
  hashOfEnglishDraft,
  type CompileResult,
} from "./honeypot-compiler.js";
import { validateTrapSpec } from "./trap-spec-validation.js";
import { TrapRegistry } from "./trap-registry.js";
import type { TrapStore } from "./trap-store.js";
import type { ToolCallTrapRuntime } from "./tool-call-trap-runtime.js";
import type { CredentialTrapRuntime } from "./credential-trap-runtime.js";

export const HONEYPOT_API_PREFIX = "/api/honeypot";

/**
 * Trap-trigger dependencies. The dashboard wires these once and reuses
 * them across every request the front-of-dispatch hook examines.
 */
export interface HoneypotTriggerDeps {
  registry: TrapRegistry;
  findingStore: SentinelFindingStore;
  auditLog: AuditLog;
  /** Operator identity attribution for audit + finding emissions. */
  operatorId: string;
  /** Stable fortress id stamped on every finding. */
  fortressId: string;
  /** Wall-clock provider for tests. */
  now?: () => Date;
  /** Pi-4 credential trap runtime for credential-use front-of-dispatch checks. */
  credentialRuntime?: CredentialTrapRuntime;
}

/** Management-route dependencies (superset of trigger deps). */
export interface HoneypotRouterDeps extends HoneypotTriggerDeps {
  authConfig: AuthConfig;
  /**
   * Optional substrate selector. When present, the compile route's
   * Path A (LLM) fires; absent, the compiler falls back to its
   * heuristic Path B (still produces a usable spec + warnings).
   */
  selector?: SubstrateSelector;
  /**
   * Pi-2: optional encrypted-at-rest trap store. When present, the
   * deploy and undeploy handlers write through to the store so the
   * fortress retains its deployed traps across restart. Absent store
   * keeps Pi-1's in-memory-only behavior (tests rely on this absence
   * to exercise the registry without a storage backend).
   */
  store?: TrapStore;
  /** Pi-3 tool-call trap runtime for stats + invocation drilldown. */
  toolCallRuntime?: ToolCallTrapRuntime;
  /** Pi-4 credential trap runtime for stats + read/use drilldown. */
  credentialRuntime?: CredentialTrapRuntime;
}

// ── Front-of-dispatch trap-trigger hook ──────────────────────────────────

/**
 * Check whether the incoming request matches any deployed trap. When
 * it does:
 *   - Emit the audit event with caller-identity + path + payload-hash.
 *   - Write a sentinel finding to the per-fortress finding store under
 *     `honeypot:<trap_id>` with the trap's configured severity.
 *   - Return a plausible 404 response to the caller. The caller cannot
 *     tell whether a trap fired or whether the path is genuinely
 *     unknown.
 *
 * Returns true when the request was handled (caller MUST NOT continue
 * dispatching), false when no trap matched (caller continues to its
 * existing route table).
 *
 * The body is consumed for hashing only when the request has a body
 * AND the dashboard's request-body-handling layer has not already
 * consumed it. The hashing is best-effort: a body-already-read
 * request still emits the trigger; payload_hash captures whatever
 * fragment is observable.
 */
export async function handleHoneypotTriggerIfMatch(
  deps: HoneypotTriggerDeps,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const url = req.url ?? "/";
  const path = url.split("?")[0] ?? "/";
  const method = (req.method ?? "GET").toUpperCase();
  // Front-of-dispatch must NOT shadow the management API. Operators
  // calling /api/honeypot/* go through the management routes, not the
  // trap-trigger path. Likewise the existing sentinel + coordination
  // surfaces are never trap candidates.
  if (path.startsWith(HONEYPOT_API_PREFIX)) return false;
  if (path.startsWith("/api/sentinels")) return false;
  if (path.startsWith("/api/coordination")) return false;

  const credentialUse = await deps.credentialRuntime?.detectHttpUseAttempt(req);
  if (credentialUse?.handled) {
    res.writeHead(credentialUse.statusCode, {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    });
    res.end(credentialUse.responseBody);
    return true;
  }

  const match = deps.registry.findMatching({ path, method });
  if (!match) return false;

  const now = (deps.now ?? (() => new Date()))();
  const callerIdentity = extractCallerIdentity(req);
  const payloadHash = await safeReadAndHashBody(req);

  const findingId = randomUUID();
  const finding: SentinelFinding = {
    finding_id: findingId,
    sentinel_id: honeypotSentinelId(match.trap_id),
    severity: match.finding_severity,
    summary: buildSummary(match, callerIdentity, path, method),
    details: {
      trap_id: match.trap_id,
      trap_class: match.trap_class,
      path_matched: path,
      method,
      caller_identity: callerIdentity,
      payload_hash: payloadHash,
    },
    observed_at: now.toISOString(),
    evidence_audit_ids: [],
    fortress_id: deps.fortressId,
  };
  // Best-effort persist; a finding-store write failure must NOT break
  // the trap RESPONSE (the caller still gets the 404).
  await deps.findingStore.saveFinding(finding).catch(() => undefined);

  void deps.auditLog.append(
    "l2",
    HONEYPOT_AUDIT_OPS.TRIGGERED,
    deps.operatorId,
    {
      trap_id: match.trap_id,
      trap_class: match.trap_class,
      path_matched: path,
      method,
      caller_identity: callerIdentity,
      payload_hash: payloadHash,
      finding_id: findingId,
      severity: match.finding_severity,
    },
  );

  // Plausible 404. The body intentionally looks like a routine
  // not-found response; the trap value depends on the caller not
  // realizing they triggered a honeypot.
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "not_found", path }));
  return true;
}

function buildSummary(
  spec: TrapSpec,
  callerIdentity: string,
  path: string,
  method: string,
): string {
  const pattern =
    spec.trigger.kind === "http_endpoint"
      ? spec.trigger.path_pattern
      : "(non-http)";
  return `honeypot ${spec.trap_id} triggered: ${method} ${path} from ${callerIdentity} (severity ${spec.finding_severity}, pattern ${pattern})`;
}

/**
 * Extract a stable identity hint from request headers. v1.0 surfaces:
 *   - X-Sanctuary-Agent header (set by the wrap-side proxy when an
 *     agent is the caller).
 *   - X-Forwarded-For (when behind a proxy).
 *   - The remote address (fallback).
 */
function extractCallerIdentity(req: IncomingMessage): string {
  const headers = req.headers;
  const agent = headers["x-sanctuary-agent"];
  if (typeof agent === "string" && agent.length > 0) return `agent:${agent}`;
  const xff = headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.length > 0) {
    const first = xff.split(",")[0]?.trim();
    if (first) return `ip:${first}`;
  }
  const ip = req.socket.remoteAddress;
  return ip ? `ip:${ip}` : "ip:unknown";
}

/**
 * Read the request body (best-effort) and return its SHA-256 hash,
 * truncated to 32 hex chars. On read failure (already-consumed
 * stream, timeout, oversize body) returns the literal string
 * `"unhashed"` so the finding still surfaces. Never throws.
 */
async function safeReadAndHashBody(req: IncomingMessage): Promise<string> {
  const MAX_BYTES = 64 * 1024;
  try {
    const chunks: Buffer[] = [];
    let total = 0;
    for await (const chunk of req) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += buf.length;
      if (total > MAX_BYTES) {
        return "unhashed";
      }
      chunks.push(buf);
    }
    if (chunks.length === 0) return "empty";
    const body = Buffer.concat(chunks);
    return createHash("sha256").update(body).digest("hex").slice(0, 32);
  } catch {
    return "unhashed";
  }
}

// ── Management API ───────────────────────────────────────────────────────

function writeJSON(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(payload));
}

async function readJSONBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  if (chunks.length === 0) return undefined;
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function matchTrapIdRoute(path: string): { trapId: string } | null {
  const prefix = `${HONEYPOT_API_PREFIX}/traps/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (rest.length === 0 || rest.includes("/")) return null;
  return { trapId: decodeURIComponent(rest) };
}

/**
 * Handle a management-API request. Returns true when served (any
 * status), false to let the caller continue routing (path didn't
 * match the honeypot surface).
 */
export async function handleHoneypotRoute(
  deps: HoneypotRouterDeps,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const host = req.headers.host || "localhost";
  const url = new URL(req.url ?? "/", `http://${host}`);
  const method = (req.method ?? "GET").toUpperCase();
  const path = url.pathname;
  if (
    path !== HONEYPOT_API_PREFIX &&
    !path.startsWith(`${HONEYPOT_API_PREFIX}/`)
  ) {
    return false;
  }
  const checkAuth = authMiddleware(deps.authConfig);
  if (!checkAuth(req, res, url)) return true;

  try {
    if (method === "POST" && path === `${HONEYPOT_API_PREFIX}/compile`) {
      const body = await readJSONBody(req);
      const englishText =
        body && typeof body === "object" && typeof (body as Record<string, unknown>)["english_text"] === "string"
          ? ((body as Record<string, unknown>)["english_text"] as string)
          : "";
      if (englishText.length === 0) {
        writeJSON(res, 400, {
          ok: false,
          error: "english_text required",
        });
        return true;
      }
      const draft: HoneypotDraft = {
        english_text: englishText,
        operator_id: deps.operatorId,
        observed_at: (deps.now ?? (() => new Date()))().toISOString(),
      };
      void deps.auditLog.append("l2", HONEYPOT_AUDIT_OPS.DRAFTED, deps.operatorId, {
        fortress_id: deps.fortressId,
        english_hash: hashOfEnglishDraft(englishText),
      });
      const result = await compileHoneypot(draft, {
        ...(deps.selector !== undefined ? { selector: deps.selector } : {}),
        ...(deps.now !== undefined ? { now: deps.now } : {}),
      });
      void deps.auditLog.append("l2", HONEYPOT_AUDIT_OPS.COMPILED, deps.operatorId, {
        fortress_id: deps.fortressId,
        trap_id: result.spec.trap_id,
        source: result.source,
        warning_count: result.warnings.length,
      });
      writeJSON(res, 200, {
        ok: true,
        data: { spec: result.spec, source: result.source, warnings: result.warnings },
      });
      return true;
    }

    if (method === "POST" && path === `${HONEYPOT_API_PREFIX}/deploy`) {
      const body = await readJSONBody(req);
      const spec =
        body && typeof body === "object" && (body as Record<string, unknown>)["spec"]
          ? ((body as Record<string, unknown>)["spec"] as TrapSpec)
          : null;
      if (!spec || typeof spec.trap_id !== "string" || spec.trap_id.length === 0) {
        writeJSON(res, 400, { ok: false, error: "spec.trap_id required" });
        return true;
      }
      const validation = validateTrapSpec(spec);
      if (!validation.ok) {
        writeJSON(res, 400, {
          ok: false,
          error: "invalid_trap_spec",
          details: validation.errors,
        });
        return true;
      }
      const isNew = deps.registry.deploy(spec);
      // Pi-2: persist the deployed spec to encrypted at-rest storage
      // when a store is wired. Best-effort: a store-write failure must
      // NOT block the operator's deploy (the in-memory registry has
      // already accepted the spec and the trap fires immediately on
      // matching traffic). Failures surface in the audit emission.
      let persistError: PublicErrorCode | null = null;
      if (deps.store) {
        try {
          await deps.store.save(spec);
        } catch (err) {
          persistError = "internal_error";
          logCaughtError(err, {
            route: "honeypot",
            operation: "deploy.persist",
          });
        }
      }
      void deps.auditLog.append("l2", HONEYPOT_AUDIT_OPS.DEPLOYED, deps.operatorId, {
        fortress_id: deps.fortressId,
        trap_id: spec.trap_id,
        trap_class: spec.trap_class,
        ...deployAuditTriggerDetails(spec),
        was_new: isNew,
        ...(persistError !== null
          ? { persist_error: persistError, persisted: false }
          : deps.store
            ? { persisted: true }
            : {}),
      });
      writeJSON(res, 200, {
        ok: true,
        data: {
          trap_id: spec.trap_id,
          was_new: isNew,
          ...(deps.store ? { persisted: persistError === null } : {}),
          ...(persistError !== null ? { persist_error: persistError } : {}),
        },
      });
      return true;
    }

    if (method === "GET" && path === `${HONEYPOT_API_PREFIX}/traps`) {
      const traps = deps.registry.list();
      writeJSON(res, 200, { ok: true, data: { traps } });
      return true;
    }

    if (method === "GET" && path === `${HONEYPOT_API_PREFIX}/tool-traps`) {
      const stats = deps.toolCallRuntime?.stats() ?? [];
      writeJSON(res, 200, { ok: true, data: { traps: stats } });
      return true;
    }

    if (method === "GET" && path === `${HONEYPOT_API_PREFIX}/credential-traps`) {
      const stats = deps.credentialRuntime?.stats() ?? [];
      writeJSON(res, 200, { ok: true, data: { traps: stats } });
      return true;
    }

    const trapMatch = matchTrapIdRoute(path);
    if (method === "DELETE" && trapMatch) {
      const removed = deps.registry.undeploy(trapMatch.trapId);
      // Pi-2: best-effort remove from encrypted at-rest storage. We
      // delete unconditionally rather than gating on `removed` because
      // the persisted layer and in-memory layer can drift (e.g., after
      // a partial boot reload). Deleting on undeploy is idempotent and
      // converges the two layers.
      let persistError: PublicErrorCode | null = null;
      if (deps.store) {
        try {
          await deps.store.delete(trapMatch.trapId);
        } catch (err) {
          persistError = "internal_error";
          logCaughtError(err, {
            route: "honeypot",
            operation: "undeploy.persist",
          });
        }
      }
      if (removed) {
        void deps.auditLog.append(
          "l2",
          HONEYPOT_AUDIT_OPS.UNDEPLOYED,
          deps.operatorId,
          {
            fortress_id: deps.fortressId,
            trap_id: trapMatch.trapId,
            ...(persistError !== null
              ? { persist_error: persistError, persisted: false }
              : deps.store
                ? { persisted: true }
                : {}),
          },
        );
      }
      writeJSON(res, removed ? 200 : 404, {
        ok: removed,
        data: {
          trap_id: trapMatch.trapId,
          removed,
          ...(deps.store ? { persisted: persistError === null } : {}),
          ...(persistError !== null ? { persist_error: persistError } : {}),
        },
      });
      return true;
    }

    if (method === "GET" && path === `${HONEYPOT_API_PREFIX}/findings`) {
      const since = url.searchParams.get("since") ?? undefined;
      const severityRaw = url.searchParams.get("severity") ?? undefined;
      const severity = isValidSeverity(severityRaw) ? severityRaw : undefined;
      const limit = parseLimit(url.searchParams.get("limit"), 50, 500);
      const all = await deps.findingStore.listFindings({
        ...(since !== undefined ? { since } : {}),
        ...(severity !== undefined ? { severity } : {}),
        limit: 500,
      });
      const honeypotFindings = all.filter((f) =>
        f.sentinel_id.startsWith(HONEYPOT_SENTINEL_ID_PREFIX),
      );
      writeJSON(res, 200, {
        ok: true,
        data: { findings: honeypotFindings.slice(0, limit) },
      });
      return true;
    }

    writeJSON(res, 404, { ok: false, error: "not_found", path });
    return true;
  } catch (err) {
    sendCaughtError(res, 500, "internal_error", err, {
      route: "honeypot",
      operation: `${method} ${path}`,
    });
    return true;
  }
}

function isValidSeverity(value: string | undefined): value is SentinelSeverity {
  return value === "info" || value === "warn" || value === "alert";
}

function deployAuditTriggerDetails(spec: TrapSpec): Record<string, unknown> {
  if (spec.trigger.kind === "tool_call") {
    return {
      fake_tool_name: spec.trigger.fake_tool_name,
      catalog_visibility: spec.trigger.catalog_visibility,
      visible_to_agents: spec.trigger.visible_to_agents ?? [],
    };
  }
  if (spec.trigger.kind === "credential") {
    return {
      fake_credential_name: spec.trigger.fake_credential_name,
      fake_credential_type: spec.trigger.fake_credential_type,
      visibility: spec.trigger.visibility,
      visible_to_agents: spec.trigger.visible_to_agents ?? [],
      emission_paths: spec.trigger.emission_paths,
      monitored_target_hosts: spec.trigger.monitored_target_hosts ?? [],
    };
  }
  return { path_pattern: spec.trigger.path_pattern };
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

// Re-export the CompileResult shape so callers building tooling on
// top of the management API can type-check responses.
export type { CompileResult };
