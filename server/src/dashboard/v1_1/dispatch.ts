/**
 * v1.1 Shared Dispatch Helper (v1.1.2 hotfix)
 *
 * v1.1.1 (PR #82) wired v1.1 routes only into the principal-policy
 * `DashboardApprovalChannel` server. The wrap-auto operator dashboard
 * (`dashboard/server.ts` + `dashboard/api.ts`) is a separate HTTP server
 * shipped without any v1.1 routing, so operators following the wrap-emitted
 * URL hit 404 on `/v1.1`, `/api/hub/*`, and the `/api/identities` alias.
 *
 * This module is a single source of truth for the v1.1 dispatch logic so
 * the two dashboard servers stay in lock-step. Both call `dispatchV11Request`
 * before their legacy route tables; the request-handler signatures of the
 * two servers diverge but the dispatch contract does not.
 *
 * Auth contract (mirrors PR #82's principal-policy implementation):
 *   - `/v1.1` HTML is served unauthenticated; the inline client negotiates
 *     bearer-token / loopback auto-auth on its own.
 *   - `/api/hub/*` and `/api/identities` route through the same `AuthConfig`
 *     contract as the legacy `/api/*` routes.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { basename } from "node:path";

import { handleHubRoute } from "../../hub/api-router.js";
import { handleDashboardV11Route } from "./index.js";
import {
  handleIntelligenceRoute,
  INTELLIGENCE_API_PREFIX,
} from "./intelligence-api-router.js";
import type { V11Bindings } from "./wiring.js";
import { enforceAuth, type AuthConfig } from "../../console/auth-middleware.js";
import { FilesystemStorage } from "../../storage/filesystem.js";
import { IdentityManager } from "../../cognitive/tools.js";
import { AuditLog } from "../../operational/audit-log.js";
import { fromBase64url } from "../../core/encoding.js";
import {
  applyDidWebRotationToRecord,
  buildDidWebHealthSnapshot,
  DID_WEB_AUDIT_OPS,
  identifierFromFortressDidWebRecord,
  loadFortressDidWebRecord,
  publishDidWebDocument,
  rotateDidWebKey,
  type DidWebIdentifier,
} from "../../recognition/did-web.js";

export interface DispatchV11RequestInputs {
  bindings: V11Bindings;
  /**
   * Bearer token for non-loopback callers. When undefined, the dashboard
   * runs without bearer-token gating (matches v1.0 unauthenticated mode).
   */
  authToken?: string;
  /** When true, loopback (127.0.0.1 / ::1) requests bypass token check. */
  loopbackAutoAuth: boolean;
}

function writeJSON(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(payload));
}

async function handleRecognitionDidWebRoute(
  inputs: DispatchV11RequestInputs,
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  method: string,
): Promise<boolean> {
  if (
    url.pathname !== "/api/hub/recognition/did-web" &&
    url.pathname !== "/api/hub/recognition/did-web/rotate-compromised"
  ) {
    return false;
  }
  const authConfig: AuthConfig = {
    loopbackAutoAuth: inputs.loopbackAutoAuth,
    ...(inputs.authToken !== undefined ? { authToken: inputs.authToken } : {}),
  };
  const requiresOperatorBearer =
    method === "POST" &&
    url.pathname === "/api/hub/recognition/did-web/rotate-compromised";
  try {
    enforceAuth(
      authConfig,
      req,
      url,
      requiresOperatorBearer ? { requireToken: true } : undefined,
    );
  } catch {
    writeJSON(res, 401, { ok: false, error: "unauthorized" });
    return true;
  }

  const storagePath = inputs.bindings.storagePath;
  if (!storagePath) {
    writeJSON(res, 200, {
      ok: true,
      data: buildDidWebHealthSnapshot(null),
    });
    return true;
  }

  if (method === "GET" && url.pathname === "/api/hub/recognition/did-web") {
    const record = await loadFortressDidWebRecord(storagePath);
    writeJSON(res, 200, {
      ok: true,
      data: buildDidWebHealthSnapshot(record),
    });
    return true;
  }

  if (
    method === "POST" &&
    url.pathname === "/api/hub/recognition/did-web/rotate-compromised"
  ) {
    if (!inputs.bindings.masterKey) {
      writeJSON(res, 503, {
        ok: false,
        error: "identity_rotation_not_wired",
        detail: "Dashboard binding does not include the unlocked fortress master key.",
      });
      return true;
    }
    const record = await loadFortressDidWebRecord(storagePath);
    if (!record) {
      writeJSON(res, 404, { ok: false, error: "did_web_not_configured" });
      return true;
    }
    const storage = new FilesystemStorage(`${storagePath}/state`);
    const identityManager = new IdentityManager(storage, inputs.bindings.masterKey);
    await identityManager.load();
    const rotationIdentity = await identityManager.rotate(
      inputs.bindings.identityId,
      "did-web:compromised",
    );
    if (!rotationIdentity) {
      writeJSON(res, 404, { ok: false, error: "identity_not_found" });
      return true;
    }
    const identifier = identifierFromFortressDidWebRecord(record);
    const rotation = await rotateDidWebKey(identifier, {
      reason: "compromised",
      preserve_old_key_for: 90,
      now: () => new Date(rotationIdentity.rotationEvent.rotated_at),
      new_public_key: fromBase64url(rotationIdentity.updatedIdentity.public_key),
    });
    const rotatedIdentifier: DidWebIdentifier = {
      ...identifier,
      did_document: rotation.new_did_document,
      public_key: fromBase64url(rotation.new_public_key_b64u),
    };
    const artifact = publishDidWebDocument(rotatedIdentifier);
    const updated = applyDidWebRotationToRecord(record, rotation, artifact);
    const { mkdir, writeFile } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const persistDir = join(storagePath, "recognition");
    await mkdir(persistDir, { recursive: true, mode: 0o700 });
    await writeFile(join(persistDir, "did-web.json"), JSON.stringify(updated, null, 2), { mode: 0o600 });
    await writeFile(join(persistDir, "did.json"), artifact.artifact, { mode: 0o644 });
    const auditLog = new AuditLog(storage, inputs.bindings.masterKey);
    void auditLog.append("l1", DID_WEB_AUDIT_OPS.KEY_ROTATED, inputs.bindings.identityId, {
      did: rotation.did,
      reason: rotation.rotation_reason,
      old_verification_method_id: rotation.old_verification_method_id,
      new_verification_method_id: rotation.new_verification_method_id,
      old_public_key_b64u: rotation.old_public_key_b64u,
      new_public_key_b64u: rotation.new_public_key_b64u,
      preserve_old_key_for: 90,
    });
    await auditLog.flush();
    writeJSON(res, 200, {
      ok: true,
      data: {
        rotation,
        artifact,
        health: buildDidWebHealthSnapshot(updated),
      },
    });
    return true;
  }

  writeJSON(res, 405, { ok: false, error: "method_not_allowed" });
  return true;
}

/**
 * Try to handle the request as a v1.1 route. Returns true when the route
 * matched and was served; false to fall through to the legacy route table.
 *
 * The v1.1 HTML at `/v1.1` is intentionally served before the legacy auth
 * gate so the operator can land on the page; the inline client handles its
 * own auth dance via fetch + sessionStorage.
 */
export async function dispatchV11Request(
  inputs: DispatchV11RequestInputs,
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  method: string,
): Promise<boolean> {
  const { bindings, authToken, loopbackAutoAuth } = inputs;

  // v1.1 dashboard HTML at /dashboard and /v1.1 (and trailing slash). The
  // bare root match remains for direct/back-compat helper callers, but both
  // production dashboard routers now serve the posture shell at `/` before
  // dispatch reaches this helper. Legacy v1.0 dashboard is preserved at
  // /v1.0 by the legacy route tables in principal-policy/dashboard.ts and
  // dashboard/api.ts; /v1.1 continues to serve operator bookmarks.
  if (
    method === "GET" &&
    (url.pathname === "/" ||
      url.pathname === "/dashboard" ||
      url.pathname === "/v1.1" ||
      url.pathname === "/v1.1/")
  ) {
    return handleDashboardV11Route(
      {
        identityId: bindings.identityId,
        fortressId: bindings.fortressId,
        ...(bindings.storagePath ? { tenantName: tenantNameFromStoragePath(bindings.storagePath) } : {}),
      },
      req,
      res,
    );
  }

  // Intelligence API at /api/hub/intelligence/*. Mounted BEFORE the
  // generic /api/hub/* dispatch so the more specific prefix wins. Same
  // auth contract as the rest of /api/hub/*; selector-bearing bindings
  // serve operator config, selector-less bindings respond 503 with a
  // documented "selector not configured" body.
  if (
    url.pathname === INTELLIGENCE_API_PREFIX ||
    url.pathname.startsWith(`${INTELLIGENCE_API_PREFIX}/`)
  ) {
    const authConfig: AuthConfig = {
      loopbackAutoAuth,
      ...(authToken !== undefined ? { authToken } : {}),
    };
    if (!bindings.intelligenceSelector) {
      res.writeHead(503, {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
      });
      res.end(
        JSON.stringify({
          ok: false,
          error: "selector_not_configured",
          detail: "Intelligence substrate selector is not wired into this dashboard binding.",
        }),
      );
      return true;
    }
    return handleIntelligenceRoute(
      { authConfig, selector: bindings.intelligenceSelector },
      req,
      res,
    );
  }

  if (await handleRecognitionDidWebRoute(inputs, req, res, url, method)) {
    return true;
  }

  // Hub API at /api/hub/*. Same auth contract as legacy /api/*.
  if (url.pathname.startsWith("/api/hub/")) {
    const authConfig: AuthConfig = {
      loopbackAutoAuth,
      ...(authToken !== undefined ? { authToken } : {}),
    };
    return handleHubRoute(
      { authConfig, service: bindings.hubService },
      req,
      res,
    );
  }

  // Finding E alias: /api/identities → /api/hub/agents (back-compat for
  // pre-v1.1 operator scripts). Same auth, same response shape.
  if (method === "GET" && url.pathname === "/api/identities") {
    const authConfig: AuthConfig = {
      loopbackAutoAuth,
      ...(authToken !== undefined ? { authToken } : {}),
    };
    const aliasReq = Object.create(req) as IncomingMessage;
    aliasReq.url = "/api/hub/agents" + url.search;
    return handleHubRoute(
      { authConfig, service: bindings.hubService },
      aliasReq,
      res,
    );
  }

  return false;
}

/**
 * Derive a human-friendly tenant name from the storage path. Uses the
 * directory basename (e.g. ".sanctuary" -> "default", "my-fortress" ->
 * "my-fortress"). Matches the naming convention from `discoverTenants()`
 * in `cli/agents/discover.ts`.
 */
function tenantNameFromStoragePath(storagePath: string): string {
  const name = basename(storagePath);
  return name === ".sanctuary" ? "default" : name;
}
