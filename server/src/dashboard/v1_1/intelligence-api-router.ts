/**
 * Sanctuary v1.1 Dashboard — Intelligence API Router
 *
 * HTTP route surface for the Intelligence Substrate Selector. Mirrors the
 * `hub/api-router.ts` shape so the dispatch layer can mount both with the
 * same machinery.
 *
 * Auth invariant: every route runs through the same `authMiddleware` as the
 * hub API routes. Loopback auto-auth + bearer-token gating come from the
 * same implementation.
 *
 * Local-only invariant: the substrate selector binds to the local fortress.
 * Routes reject `fortress_id` / `peer_id` style query parameters that would
 * extend the surface across fortresses (federation lands in v1.3+).
 *
 * Sensitive-field invariant: the GET /config response NEVER returns API
 * keys. Presence flags only. Operator-entered keys live encrypted under the
 * fortress master key in the SubstrateConfig record; the selector layer is
 * the only consumer that sees the raw bytes.
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import {
  authMiddleware,
  type AuthConfig,
} from "../../console/auth-middleware.js";
import { sendCaughtError } from "../../http/error-envelope.js";
import type { SubstrateSelector } from "../../intelligence/selector.js";
import {
  SUBSTRATE_CHOICES,
  SURFACES,
  FRONTIER_PROVIDERS,
  type FallbackBehavior,
  type FrontierProvider,
  type HybridRoutingRules,
  type LocalModelPick,
  type SubstrateChoice,
  type Surface,
} from "../../intelligence/types.js";

/** URL prefix the dispatch layer mounts under. */
export const INTELLIGENCE_API_PREFIX = "/api/hub/intelligence";

/** Cap on raw request-body bytes the router accepts. */
const MAX_REQUEST_BODY_BYTES = 64 * 1024;

const VALID_LOCAL_MODEL_PICKS: readonly LocalModelPick[] = [
  "gemma-2-2b",
  "phi-4-mini",
  "llama-3.1-8b",
];

const VALID_FALLBACKS: readonly FallbackBehavior[] = [
  "conservative-deny",
  "degrade-silent",
  "disable-surface",
];

export interface IntelligenceRouterDeps {
  authConfig: AuthConfig;
  selector: SubstrateSelector;
}

class IntelligenceRouterError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.publicDetail = message;
    this.name = "IntelligenceRouterError";
  }

  public readonly publicDetail: string;
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

async function readJSONBody<T = Record<string, unknown>>(
  req: IncomingMessage,
): Promise<T> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > MAX_REQUEST_BODY_BYTES) {
      throw new IntelligenceRouterError(
        413,
        "payload_too_large",
        "request body too large",
      );
    }
    chunks.push(buf);
  }
  const body = Buffer.concat(chunks).toString("utf-8");
  if (!body) return {} as T;
  try {
    return JSON.parse(body) as T;
  } catch {
    throw new IntelligenceRouterError(
      400,
      "invalid_json",
      "request body is not valid JSON",
    );
  }
}

function rejectCrossFortressParams(url: URL): void {
  for (const reserved of ["fortress_id", "peer_id", "remote_fortress_id"]) {
    if (url.searchParams.has(reserved)) {
      throw new IntelligenceRouterError(
        400,
        "local_only",
        `query parameter '${reserved}' is not supported (cross-fortress reach)`,
      );
    }
  }
}

function isSurface(value: unknown): value is Surface {
  return typeof value === "string" && (SURFACES as readonly string[]).includes(value);
}

function isSubstrateChoice(value: unknown): value is SubstrateChoice {
  return (
    typeof value === "string" &&
    (SUBSTRATE_CHOICES as readonly string[]).includes(value)
  );
}

function isLocalModelPick(value: unknown): value is LocalModelPick {
  return (
    typeof value === "string" &&
    (VALID_LOCAL_MODEL_PICKS as readonly string[]).includes(value)
  );
}

function isFallbackBehavior(value: unknown): value is FallbackBehavior {
  return (
    typeof value === "string" &&
    (VALID_FALLBACKS as readonly string[]).includes(value)
  );
}

function isFrontierProvider(value: unknown): value is FrontierProvider {
  return (
    typeof value === "string" &&
    (FRONTIER_PROVIDERS as readonly string[]).includes(value)
  );
}

function handleError(res: ServerResponse, err: unknown): void {
  if (err instanceof IntelligenceRouterError) {
    writeJSON(res, err.statusCode, {
      ok: false,
      error: err.code,
      detail: err.publicDetail,
    });
    return;
  }
  sendCaughtError(res, 500, "internal_error", err, {
    route: "intelligence",
  });
}

/**
 * Match `/api/hub/intelligence/surfaces/:surface[/<remainder>]`.
 * Returns null when the path does not match.
 */
function matchSurfaceRoute(path: string): {
  surface: string;
  remainder: string | null;
} | null {
  const prefix = `${INTELLIGENCE_API_PREFIX}/surfaces/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (rest.length === 0) return null;
  const slash = rest.indexOf("/");
  if (slash === -1) {
    return { surface: decodeURIComponent(rest), remainder: null };
  }
  return {
    surface: decodeURIComponent(rest.slice(0, slash)),
    remainder: rest.slice(slash + 1),
  };
}

/**
 * Match `/api/hub/intelligence/credentials/frontier/:provider`.
 */
function matchFrontierProviderRoute(path: string): {
  provider: string;
} | null {
  const prefix = `${INTELLIGENCE_API_PREFIX}/credentials/frontier/`;
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (!rest || rest.includes("/")) return null;
  return { provider: decodeURIComponent(rest) };
}

/**
 * Build the operator-safe view of the persisted SubstrateConfig. API keys
 * are NEVER serialized; only presence flags + non-secret fields surface.
 *
 * Consumers: the picker modal needs to know "does the operator have a
 * Venice key set" so it can show "Replace" instead of "Add" without ever
 * receiving the raw key bytes back over the wire.
 */
function sanitizeConfig(selector: SubstrateSelector): {
  version: number;
  per_surface: Record<Surface, SubstrateChoice>;
  local_model_picks: Partial<Record<Surface, LocalModelPick>>;
  custom_local_model_tags: Partial<Record<Surface, string>>;
  ollama_endpoint: string | null;
  venice_api_key_present: boolean;
  venice_model: string | null;
  frontier_keys_present: Record<FrontierProvider, boolean>;
  hybrid_rules: HybridRoutingRules | null;
  fallback: Record<Surface, FallbackBehavior>;
  apply_to_all_surfaces: boolean;
  updated_at: string;
} {
  const cfg = selector.getConfig();
  return {
    version: cfg.version,
    per_surface: cfg.perSurface,
    local_model_picks: cfg.localModelPicks,
    custom_local_model_tags: cfg.customLocalModelTags ?? {},
    ollama_endpoint: cfg.ollamaEndpoint ?? null,
    venice_api_key_present: typeof cfg.veniceApiKey === "string" && cfg.veniceApiKey.length > 0,
    venice_model: cfg.veniceModel ?? null,
    frontier_keys_present: {
      anthropic: typeof cfg.frontierConfig.anthropic === "string" && cfg.frontierConfig.anthropic.length > 0,
      openai: typeof cfg.frontierConfig.openai === "string" && cfg.frontierConfig.openai.length > 0,
      google: typeof cfg.frontierConfig.google === "string" && cfg.frontierConfig.google.length > 0,
    },
    hybrid_rules: cfg.hybridRules ?? null,
    fallback: cfg.fallback,
    apply_to_all_surfaces: cfg.applyToAllSurfaces !== false,
    updated_at: cfg.updatedAt,
  };
}

/**
 * Validate a hybrid-rules POST body and return a strongly-typed
 * HybridRoutingRules. Throws an IntelligenceRouterError 400 if the shape
 * is wrong; the selector's internal validateHybridRules catches the
 * deeper invariants (every surface bound, no recursion).
 */
function parseHybridRules(body: unknown): HybridRoutingRules {
  if (!body || typeof body !== "object") {
    throw new IntelligenceRouterError(400, "invalid_body", "rules object required");
  }
  const rules = (body as { rules?: unknown }).rules;
  if (!rules || typeof rules !== "object") {
    throw new IntelligenceRouterError(400, "invalid_body", "rules.rules object required");
  }
  const perSurfaceRaw = (rules as { perSurface?: unknown; per_surface?: unknown }).perSurface
    ?? (rules as { per_surface?: unknown }).per_surface;
  if (!perSurfaceRaw || typeof perSurfaceRaw !== "object") {
    throw new IntelligenceRouterError(
      400,
      "invalid_body",
      "rules.perSurface object required",
    );
  }
  const out: Record<Surface, Exclude<SubstrateChoice, "hybrid">> = {} as Record<Surface, Exclude<SubstrateChoice, "hybrid">>;
  for (const surface of SURFACES) {
    const value = (perSurfaceRaw as Record<string, unknown>)[surface];
    if (!isSubstrateChoice(value) || value === "hybrid") {
      throw new IntelligenceRouterError(
        400,
        "invalid_body",
        `rules.perSurface.${surface} must be one of local / venice / frontier-with-filter / disabled`,
      );
    }
    out[surface] = value as Exclude<SubstrateChoice, "hybrid">;
  }
  return { perSurface: out };
}

/**
 * Handle an intelligence API request. Returns true if the route matched
 * and was served (or refused with an error response). Returns false to
 * allow the caller to fall through to the next handler.
 */
export async function handleIntelligenceRoute(
  deps: IntelligenceRouterDeps,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const host = req.headers.host || "localhost";
  const url = new URL(req.url ?? "/", `http://${host}`);
  const method = (req.method ?? "GET").toUpperCase();
  const path = url.pathname;

  if (
    path !== INTELLIGENCE_API_PREFIX &&
    !path.startsWith(`${INTELLIGENCE_API_PREFIX}/`)
  ) {
    return false;
  }

  // Auth gate fires before any selector method runs.
  //
  // SECURITY (#800 follow-on, operational mutations): the intelligence
  // mutations (POST /reset, POST surface/all choice, POST preferences,
  // POST per-surface choice/fallback, POST/DELETE credentials, POST
  // hybrid-rules) change the model-routing substrate and write provider
  // API keys. They must require the operator bearer even on loopback with
  // `--auto-auth-localhost`, so a co-resident agent sharing the loopback
  // interface cannot retarget its own model routing or plant/clear
  // credentials tokenless. The GET reads (status / config) keep loopback
  // auto-auth. `requireToken` only suppresses the loopback shortcut; token
  // validation is unchanged. Fail-closed: with no token configured, a
  // mutating request is rejected, never allowed.
  const requiresOperatorBearer = method !== "GET";
  const checkAuth = authMiddleware(
    deps.authConfig,
    requiresOperatorBearer ? { requireToken: true } : undefined,
  );
  if (!checkAuth(req, res, url)) return true;

  try {
    rejectCrossFortressParams(url);

    // ── GET /api/hub/intelligence/status ────────────────────────────────
    if (method === "GET" && path === `${INTELLIGENCE_API_PREFIX}/status`) {
      const status = await deps.selector.getOperatorVisibleStatus();
      writeJSON(res, 200, { ok: true, data: status });
      return true;
    }

    // ── GET /api/hub/intelligence/config (sanitized) ────────────────────
    if (method === "GET" && path === `${INTELLIGENCE_API_PREFIX}/config`) {
      // Ensure the in-memory config matches the persisted record. The
      // sanitizer reads `selector.getConfig()` synchronously after.
      await deps.selector.getOperatorVisibleStatus();
      const sanitized = sanitizeConfig(deps.selector);
      writeJSON(res, 200, { ok: true, data: sanitized });
      return true;
    }

    // ── POST /api/hub/intelligence/reset ────────────────────────────────
    if (method === "POST" && path === `${INTELLIGENCE_API_PREFIX}/reset`) {
      await deps.selector.resetToDefaults();
      writeJSON(res, 200, { ok: true, data: sanitizeConfig(deps.selector) });
      return true;
    }

    // ── POST /api/hub/intelligence/surfaces/all/choice ──────────────────
    // Bulk-apply path for the picker modal's "Apply to all surfaces"
    // toggle (Finding SS, v1.2.0-rc.1). Body shape mirrors the
    // per-surface choice route minus the surface segment; substrate is
    // applied to every surface in one selector save with a single bulk
    // audit event.
    if (
      method === "POST" &&
      path === `${INTELLIGENCE_API_PREFIX}/surfaces/all/choice`
    ) {
      const body = await readJSONBody<{
        substrate?: unknown;
        local_model_pick?: unknown;
      }>(req);
      if (!isSubstrateChoice(body.substrate)) {
        throw new IntelligenceRouterError(
          400,
          "invalid_body",
          "substrate must be one of local / venice / frontier-with-filter / hybrid / disabled",
        );
      }
      let localModelPick: LocalModelPick | null | undefined;
      if (body.local_model_pick !== undefined) {
        if (body.local_model_pick === null) {
          localModelPick = null;
        } else if (isLocalModelPick(body.local_model_pick)) {
          localModelPick = body.local_model_pick;
        } else {
          throw new IntelligenceRouterError(
            400,
            "invalid_body",
            "local_model_pick must be one of gemma-2-2b / phi-4-mini / llama-3.1-8b or null",
          );
        }
      }
      await deps.selector.applyChoiceToAllSurfaces(body.substrate, { localModelPick });
      writeJSON(res, 200, { ok: true, data: sanitizeConfig(deps.selector) });
      return true;
    }

    // ── POST /api/hub/intelligence/preferences/apply-to-all ─────────────
    // Persist the operator's "Apply to all surfaces" toggle preference
    // so the picker modal's default checkbox state survives a dashboard
    // reload. Body: { value: boolean }. No audit event emitted; the
    // next bulk-or-single choice carries the operator-visible signal.
    if (
      method === "POST" &&
      path === `${INTELLIGENCE_API_PREFIX}/preferences/apply-to-all`
    ) {
      const body = await readJSONBody<{ value?: unknown }>(req);
      if (typeof body.value !== "boolean") {
        throw new IntelligenceRouterError(
          400,
          "invalid_body",
          "value must be boolean",
        );
      }
      await deps.selector.setApplyToAllPreference(body.value);
      writeJSON(res, 200, { ok: true, data: sanitizeConfig(deps.selector) });
      return true;
    }

    // ── /api/hub/intelligence/surfaces/:surface[/...] ───────────────────
    const surfaceMatch = matchSurfaceRoute(path);
    if (surfaceMatch) {
      if (!isSurface(surfaceMatch.surface)) {
        throw new IntelligenceRouterError(
          400,
          "invalid_surface",
          `unknown surface: ${surfaceMatch.surface}`,
        );
      }
      const surface = surfaceMatch.surface;

      // POST /api/hub/intelligence/surfaces/:surface/choice
      if (method === "POST" && surfaceMatch.remainder === "choice") {
        const body = await readJSONBody<{
          substrate?: unknown;
          local_model_pick?: unknown;
        }>(req);
        if (!isSubstrateChoice(body.substrate)) {
          throw new IntelligenceRouterError(
            400,
            "invalid_body",
            "substrate must be one of local / venice / frontier-with-filter / hybrid / disabled",
          );
        }
        // Atomic order: persist the local model pick FIRST so a refresh of
        // /status after the substrate flip immediately reflects the
        // operator's pick. Hybrid + venice + frontier cases ignore the
        // local pick gracefully.
        if (body.local_model_pick !== undefined) {
          if (body.local_model_pick === null) {
            await deps.selector.setLocalModelPick(surface, null);
          } else if (isLocalModelPick(body.local_model_pick)) {
            await deps.selector.setLocalModelPick(surface, body.local_model_pick);
          } else {
            throw new IntelligenceRouterError(
              400,
              "invalid_body",
              "local_model_pick must be one of gemma-2-2b / phi-4-mini / llama-3.1-8b or null",
            );
          }
        }
        await deps.selector.setPerSurfaceChoice(surface, body.substrate);
        writeJSON(res, 200, { ok: true, data: sanitizeConfig(deps.selector) });
        return true;
      }

      // POST /api/hub/intelligence/surfaces/:surface/fallback
      if (method === "POST" && surfaceMatch.remainder === "fallback") {
        const body = await readJSONBody<{ fallback?: unknown }>(req);
        if (!isFallbackBehavior(body.fallback)) {
          throw new IntelligenceRouterError(
            400,
            "invalid_body",
            "fallback must be one of conservative-deny / degrade-silent / disable-surface",
          );
        }
        await deps.selector.setFallbackBehavior(surface, body.fallback);
        writeJSON(res, 200, { ok: true, data: sanitizeConfig(deps.selector) });
        return true;
      }
    }

    // ── POST /api/hub/intelligence/credentials/venice ───────────────────
    if (
      method === "POST" &&
      path === `${INTELLIGENCE_API_PREFIX}/credentials/venice`
    ) {
      const body = await readJSONBody<{
        api_key?: unknown;
        model?: unknown;
      }>(req);
      if (typeof body.api_key !== "string" || body.api_key.length === 0) {
        throw new IntelligenceRouterError(
          400,
          "invalid_body",
          "api_key required (non-empty string)",
        );
      }
      await deps.selector.setVeniceApiKey(body.api_key);
      // venice_model is part of the SubstrateConfig but the selector has no
      // public setter for it at v1.0 of this PR; future operator-pick UI
      // can extend the selector. The current Venice model defaults at
      // VENICE_DEFAULT_MODEL until that work lands.
      writeJSON(res, 200, { ok: true, data: sanitizeConfig(deps.selector) });
      return true;
    }

    // ── DELETE /api/hub/intelligence/credentials/venice ─────────────────
    if (
      method === "DELETE" &&
      path === `${INTELLIGENCE_API_PREFIX}/credentials/venice`
    ) {
      await deps.selector.setVeniceApiKey(null);
      writeJSON(res, 200, { ok: true, data: sanitizeConfig(deps.selector) });
      return true;
    }

    // ── POST /api/hub/intelligence/credentials/frontier ─────────────────
    if (
      method === "POST" &&
      path === `${INTELLIGENCE_API_PREFIX}/credentials/frontier`
    ) {
      const body = await readJSONBody<{
        provider?: unknown;
        api_key?: unknown;
      }>(req);
      if (!isFrontierProvider(body.provider)) {
        throw new IntelligenceRouterError(
          400,
          "invalid_body",
          "provider must be one of anthropic / openai / google",
        );
      }
      if (typeof body.api_key !== "string" || body.api_key.length === 0) {
        throw new IntelligenceRouterError(
          400,
          "invalid_body",
          "api_key required (non-empty string)",
        );
      }
      await deps.selector.setFrontierApiKey(body.provider, body.api_key);
      writeJSON(res, 200, { ok: true, data: sanitizeConfig(deps.selector) });
      return true;
    }

    // ── DELETE /api/hub/intelligence/credentials/frontier/:provider ─────
    const frontierMatch = matchFrontierProviderRoute(path);
    if (method === "DELETE" && frontierMatch) {
      if (!isFrontierProvider(frontierMatch.provider)) {
        throw new IntelligenceRouterError(
          400,
          "invalid_provider",
          `unknown frontier provider: ${frontierMatch.provider}`,
        );
      }
      await deps.selector.setFrontierApiKey(frontierMatch.provider, null);
      writeJSON(res, 200, { ok: true, data: sanitizeConfig(deps.selector) });
      return true;
    }

    // ── POST /api/hub/intelligence/hybrid-rules ─────────────────────────
    if (
      method === "POST" &&
      path === `${INTELLIGENCE_API_PREFIX}/hybrid-rules`
    ) {
      const body = await readJSONBody(req);
      const rules = parseHybridRules(body);
      try {
        await deps.selector.setHybridRules(rules);
      } catch (err) {
        sendCaughtError(res, 400, "bad_request", err, {
          route: "intelligence",
          operation: "set_hybrid_rules",
        });
        return true;
      }
      writeJSON(res, 200, { ok: true, data: sanitizeConfig(deps.selector) });
      return true;
    }

    // No intelligence route matched.
    writeJSON(res, 404, {
      ok: false,
      error: "not_found",
      path,
    });
    return true;
  } catch (err) {
    handleError(res, err);
    return true;
  }
}
