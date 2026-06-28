/**
 * Sanctuary WP-V1.3-6 Xi-1 English-Authored Policy HTTP routes.
 *
 * Mounted under `/api/policy/*`. Mirrors the established Phi-1 /
 * Chi-3 / Psi-1 sibling-view pattern via existing `authMiddleware`.
 *
 *   POST /api/policy/compile          submit English; returns CompiledPolicy
 *   GET  /api/policy/drafts           list compiled drafts (review surface)
 *   GET  /api/policy/drafts/:id       full detail
 *
 * Activation routes (POST `/drafts/:id/activate`, DELETE `/drafts/:id`)
 * are deferred to Xi-2; this PR ships review-only.
 *
 * Castle-walking: no NEW outbound surface. Substrate selector
 * (Castle Layer 3 cooperative MCP) is the canonical outbound channel
 * used by `EnglishPolicyCompiler` for the LLM-assist path. Rho-1's
 * Tier A header strip applies (it wraps the substrate-client fetch
 * once in the selector constructor; every outbound call goes
 * through it). Draft store is in-memory + per-fortress.
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import {
  authMiddleware,
  type AuthConfig,
} from "../console/auth-middleware.js";
import { sendCaughtError } from "../http/error-envelope.js";
import {
  constantTimeEquals,
} from "../dashboard/api.js";
import {
  EnglishPolicyCompiler,
  type CompiledPolicy,
  type EnglishPolicyDraft,
} from "./english-policy-compiler.js";
import type { EnglishPolicyActivator } from "./english-policy-activator.js";
import type { PolicyConflict } from "./conflict-detector.js";
import { ENGLISH_POLICY_ACTIVATION_AUDIT_OPS } from "./english-policy-activator.js";

export const ENGLISH_POLICY_API_PREFIX = "/api/policy";

export interface EnglishPolicyRouterDeps {
  authConfig: AuthConfig;
  compiler: EnglishPolicyCompiler;
  store: EnglishPolicyDraftStore;
  /**
   * Xi-2 activation lifecycle. Optional; when omitted, the
   * activation / revocation routes return 503. Routes that operate
   * only on the Xi-1 compile-only surface (compile, drafts list,
   * drafts detail) work unchanged regardless of whether the
   * activator is plumbed in.
   */
  activator?: EnglishPolicyActivator;
  /** Default operator id when the request did not carry an
   *  X-Operator-Identity header. Falls back to "operator". */
  defaultOperatorId?: string;
}

/**
 * In-memory per-fortress draft store. Persistence is deferred to
 * Xi-2+ when the activation lifecycle wires this into encrypted
 * fortress state. Xi-1's review-only surface keeps drafts in
 * memory; restart drops them (operator re-submits).
 */
export class EnglishPolicyDraftStore {
  private readonly entries = new Map<string, CompiledPolicy>();
  private readonly maxEntries: number;

  constructor(opts?: { maxEntries?: number }) {
    this.maxEntries = opts?.maxEntries ?? 1000;
  }

  put(draft: CompiledPolicy): void {
    if (this.entries.size >= this.maxEntries) {
      const oldest = this.entries.keys().next().value as string | undefined;
      if (oldest !== undefined) this.entries.delete(oldest);
    }
    this.entries.set(draft.draft_id, draft);
  }

  get(draftId: string): CompiledPolicy | null {
    return this.entries.get(draftId) ?? null;
  }

  list(opts?: { since?: string; limit?: number }): CompiledPolicy[] {
    const since = opts?.since !== undefined ? Date.parse(opts.since) : null;
    const out: CompiledPolicy[] = [];
    for (const entry of this.entries.values()) {
      if (since !== null) {
        const compiledMs = Date.parse(entry.compiled_at);
        if (!Number.isFinite(compiledMs) || compiledMs < since) continue;
      }
      out.push(entry);
    }
    return opts?.limit !== undefined ? out.slice(0, opts.limit) : out;
  }

  size(): number {
    return this.entries.size;
  }
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

async function readBody(req: IncomingMessage, maxBytes = 32 * 1024): Promise<string> {
  return await new Promise<string>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new Error("request body exceeds 32KB"));
        req.destroy();
        return;
      }
      chunks.push(Buffer.from(chunk));
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}

function matchDetailRoute(path: string): { draftId: string } | null {
  const prefix = `${ENGLISH_POLICY_API_PREFIX}/drafts/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (rest.length === 0 || rest.includes("/")) return null;
  return { draftId: decodeURIComponent(rest) };
}

function matchActivateRoute(path: string): { draftId: string } | null {
  const prefix = `${ENGLISH_POLICY_API_PREFIX}/drafts/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (!rest.endsWith("/activate")) return null;
  const draftId = rest.slice(0, rest.length - "/activate".length);
  if (draftId.length === 0 || draftId.includes("/")) return null;
  return { draftId: decodeURIComponent(draftId) };
}

function matchCheckConflictsRoute(path: string): { draftId: string } | null {
  const prefix = `${ENGLISH_POLICY_API_PREFIX}/drafts/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (!rest.endsWith("/check-conflicts")) return null;
  const draftId = rest.slice(0, rest.length - "/check-conflicts".length);
  if (draftId.length === 0 || draftId.includes("/")) return null;
  return { draftId: decodeURIComponent(draftId) };
}

function matchStatusRoute(path: string): { draftId: string } | null {
  const prefix = `${ENGLISH_POLICY_API_PREFIX}/drafts/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (!rest.endsWith("/status")) return null;
  const draftId = rest.slice(0, rest.length - "/status".length);
  if (draftId.length === 0 || draftId.includes("/")) return null;
  return { draftId: decodeURIComponent(draftId) };
}

async function readOptionalJSONBody<T = Record<string, unknown>>(
  req: IncomingMessage,
): Promise<T> {
  const body = await readBody(req);
  if (body.trim().length === 0) return {} as T;
  return JSON.parse(body) as T;
}

function auditRef(operation: string, draftId: string): {
  operation: string;
  draft_id: string;
} {
  return { operation, draft_id: draftId };
}

function writeGenericActivationFailure(
  res: ServerResponse,
  status: number,
  draftId: string,
  auditOperation: string = ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.ACTIVATION_REFUSED,
): void {
  writeJSON(res, status, {
    ok: false,
    error: "activation_refused",
    data: {
      audit_ref: auditRef(
        auditOperation,
        draftId,
      ),
    },
  });
}

function writeGenericRevocationFailure(
  res: ServerResponse,
  status: number,
  draftId: string,
  auditOperation: string = ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.REVOKED,
): void {
  writeJSON(res, status, {
    ok: false,
    error: "revocation_refused",
    data: {
      audit_ref: auditRef(
        auditOperation,
        draftId,
      ),
    },
  });
}

function requireOperatorCredential(
  authConfig: AuthConfig,
  req: IncomingMessage,
  res: ServerResponse,
): boolean {
  const header = req.headers.authorization;
  const token = header?.startsWith("Bearer ")
    ? header.slice(7).trim()
    : null;
  if (
    authConfig.authToken === undefined ||
    token === null ||
    !constantTimeEquals(token, authConfig.authToken)
  ) {
    writeJSON(res, 403, { ok: false, error: "operator_auth_required" });
    return false;
  }
  return true;
}

export async function handleEnglishPolicyRoute(
  deps: EnglishPolicyRouterDeps,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const host = req.headers.host || "localhost";
  const url = new URL(req.url ?? "/", `http://${host}`);
  const method = (req.method ?? "GET").toUpperCase();
  const path = url.pathname;

  if (
    path !== ENGLISH_POLICY_API_PREFIX &&
    !path.startsWith(`${ENGLISH_POLICY_API_PREFIX}/`)
  ) {
    return false;
  }

  const checkAuth = authMiddleware(deps.authConfig);
  if (!checkAuth(req, res, url)) return true;

  try {
    if (method === "POST" && path === `${ENGLISH_POLICY_API_PREFIX}/compile`) {
      let body: string;
      try {
        body = await readBody(req);
      } catch (err) {
        sendCaughtError(res, 413, "payload_too_large", err, {
          route: "policy-engine",
          operation: "compile.read_body",
        });
        return true;
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(body);
      } catch (err) {
        sendCaughtError(res, 400, "invalid_json", err, {
          route: "policy-engine",
          operation: "compile.parse_json",
        });
        return true;
      }
      if (!parsed || typeof parsed !== "object") {
        writeJSON(res, 400, {
          ok: false,
          error: "body_not_object",
        });
        return true;
      }
      const obj = parsed as Record<string, unknown>;
      const englishText = typeof obj["english_text"] === "string"
        ? (obj["english_text"] as string)
        : null;
      if (englishText === null) {
        writeJSON(res, 400, {
          ok: false,
          error: "missing_english_text",
        });
        return true;
      }
      const operatorId =
        (req.headers["x-operator-identity"] as string | undefined) ??
        (typeof obj["operator_id"] === "string"
          ? (obj["operator_id"] as string)
          : (deps.defaultOperatorId ?? "operator"));
      const draft: EnglishPolicyDraft = {
        english_text: englishText,
        observed_at: new Date().toISOString(),
        operator_id: operatorId,
      };
      const compiled = await deps.compiler.compile(draft);
      deps.store.put(compiled);
      writeJSON(res, 200, { ok: true, data: { draft: compiled } });
      return true;
    }

    if (method === "GET" && path === `${ENGLISH_POLICY_API_PREFIX}/drafts`) {
      const since = url.searchParams.get("since") ?? undefined;
      const limitRaw = url.searchParams.get("limit") ?? undefined;
      const limit =
        limitRaw !== undefined && !Number.isNaN(Number.parseInt(limitRaw, 10))
          ? Math.min(Math.max(Number.parseInt(limitRaw, 10), 0), 500)
          : undefined;
      const drafts = deps.store.list({
        ...(since !== undefined ? { since } : {}),
        ...(limit !== undefined ? { limit } : {}),
      });
      writeJSON(res, 200, { ok: true, data: { drafts } });
      return true;
    }

    const statusMatch = matchStatusRoute(path);
    if (statusMatch && method === "GET") {
      if (!requireOperatorCredential(deps.authConfig, req, res)) {
        return true;
      }
      if (!deps.activator) {
        writeJSON(res, 503, {
          ok: false,
          error: "activator_not_configured",
        });
        return true;
      }
      const record = await deps.activator.getRecord(statusMatch.draftId);
      if (!record) {
        writeJSON(res, 404, { ok: false, error: "not_found" });
        return true;
      }
      writeJSON(res, 200, {
        ok: true,
        data: {
          status: record.status,
          audit_ref: auditRef(
            record.status === "revoked"
              ? ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.REVOKED
              : ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.ACTIVATED,
            statusMatch.draftId,
          ),
        },
      });
      return true;
    }

    const activateMatch = matchActivateRoute(path);
    if (activateMatch && method === "POST") {
      if (!requireOperatorCredential(deps.authConfig, req, res)) {
        return true;
      }
      if (!deps.activator) {
        writeJSON(res, 503, {
          ok: false,
          error: "activator_not_configured",
        });
        return true;
      }
      const draft =
        deps.store.get(activateMatch.draftId) ??
        (await deps.activator.getRecord(activateMatch.draftId))?.draft ??
        null;
      if (!draft) {
        writeJSON(res, 404, { ok: false, error: "not_found" });
        return true;
      }
      const operatorId =
        (req.headers["x-operator-identity"] as string | undefined) ??
        (deps.defaultOperatorId ?? "operator");
      const overrideRaw = url.searchParams.get("override");
      const overrideLowConfidence =
        overrideRaw === "true" || overrideRaw === "1";
      let parsedBody: {
        conflicts_acknowledged?: PolicyConflict[];
        acknowledge_conflicts?: boolean;
        force_conflict_ids?: string[];
        force_conflict?: string;
      };
      try {
        parsedBody = await readOptionalJSONBody(req);
      } catch {
        writeJSON(res, 400, { ok: false, error: "invalid_json" });
        return true;
      }
      const forceQuery = url.searchParams.getAll("force_conflict");
      const forceConflictIds = [
        ...(Array.isArray(parsedBody.force_conflict_ids)
          ? parsedBody.force_conflict_ids.filter((id) => typeof id === "string")
          : []),
        ...(typeof parsedBody.force_conflict === "string"
          ? [parsedBody.force_conflict]
          : []),
        ...forceQuery,
      ];
      const conflictsForAcknowledgment =
        parsedBody.acknowledge_conflicts === true
          ? await deps.activator.checkConflicts(draft, operatorId)
          : undefined;
      const outcome = await deps.activator.activate(draft, operatorId, {
        override_low_confidence: overrideLowConfidence,
        conflicts_acknowledged:
          conflictsForAcknowledgment ??
          (Array.isArray(parsedBody.conflicts_acknowledged)
            ? parsedBody.conflicts_acknowledged
            : undefined),
        force_conflict_ids: forceConflictIds,
      });
      if (!outcome.ok) {
        const status =
          outcome.reason === "low_confidence_refused"
            ? 409
            : outcome.reason === "policy_conflicts_unacknowledged"
              ? 409
              : outcome.reason === "policy_conflict_force_required"
                ? 409
            : outcome.reason === "draft_not_found"
              ? 404
              : outcome.reason === "already_activated"
                ? 409
                : outcome.reason === "invalid_rule"
                  ? 400
                  : 500;
        writeGenericActivationFailure(
          res,
          status,
          activateMatch.draftId,
          outcome.reason === "policy_posture_downgrade_refused"
            ? ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.POLICY_WRITE_REFUSED
            : ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.ACTIVATION_REFUSED,
        );
        return true;
      }
      writeJSON(res, 200, {
        ok: true,
        data: {
          status: outcome.record.status,
          audit_ref: auditRef(
            ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.ACTIVATED,
            activateMatch.draftId,
          ),
        },
      });
      return true;
    }

    const checkConflictsMatch = matchCheckConflictsRoute(path);
    if (checkConflictsMatch && method === "POST") {
      if (!requireOperatorCredential(deps.authConfig, req, res)) {
        return true;
      }
      if (!deps.activator) {
        writeJSON(res, 503, {
          ok: false,
          error: "activator_not_configured",
        });
        return true;
      }
      const draft =
        deps.store.get(checkConflictsMatch.draftId) ??
        (await deps.activator.getRecord(checkConflictsMatch.draftId))?.draft ??
        null;
      if (!draft) {
        writeJSON(res, 404, { ok: false, error: "not_found" });
        return true;
      }
      const operatorId =
        (req.headers["x-operator-identity"] as string | undefined) ??
        (deps.defaultOperatorId ?? "operator");
      await deps.activator.checkConflicts(draft, operatorId);
      writeJSON(res, 200, {
        ok: true,
        data: {
          status: "review_recorded",
          audit_ref: auditRef(
            ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.CONFLICT_DETECTED,
            checkConflictsMatch.draftId,
          ),
        },
      });
      return true;
    }

    const detailMatch = matchDetailRoute(path);
    if (detailMatch) {
      if (method === "GET") {
        const draft = deps.store.get(detailMatch.draftId);
        if (!draft) {
          writeJSON(res, 404, { ok: false, error: "not_found" });
          return true;
        }
        writeJSON(res, 200, { ok: true, data: { draft } });
        return true;
      }
      if (method === "DELETE") {
        if (!requireOperatorCredential(deps.authConfig, req, res)) {
          return true;
        }
        if (!deps.activator) {
          writeJSON(res, 503, {
            ok: false,
            error: "activator_not_configured",
          });
          return true;
        }
        const operatorId =
          (req.headers["x-operator-identity"] as string | undefined) ??
          (deps.defaultOperatorId ?? "operator");
        const outcome = await deps.activator.revoke(
          detailMatch.draftId,
          operatorId,
        );
        if (!outcome.ok) {
          const status =
            outcome.reason === "draft_not_found"
              ? 404
              : outcome.reason === "not_activated"
                ? 409
                : outcome.reason === "policy_posture_downgrade_refused"
                  ? 409
                : 500;
          writeGenericRevocationFailure(
            res,
            status,
            detailMatch.draftId,
            outcome.reason === "policy_posture_downgrade_refused"
              ? ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.POLICY_WRITE_REFUSED
              : ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.REVOKED,
          );
          return true;
        }
        writeJSON(res, 200, {
          ok: true,
          data: {
            status: outcome.record.status,
            audit_ref: auditRef(
              ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.REVOKED,
              detailMatch.draftId,
            ),
          },
        });
        return true;
      }
    }

    writeJSON(res, 404, { ok: false, error: "not_found", path });
    return true;
  } catch (err) {
    sendCaughtError(res, 500, "internal_error", err, {
      route: "policy-engine",
      operation: `${method} ${path}`,
    });
    return true;
  }
}
