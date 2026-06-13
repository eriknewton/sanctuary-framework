/**
 * /v1 agent endpoints (PR-A2).
 *
 *   GET  /v1/agents             SESSION_TOKEN, Tier 2 — unified roster read
 *   POST /v1/agents/protect     SESSION_TOKEN + OPERATOR_SIGNED, Tier 1
 *   POST /v1/agents/unprotect   SESSION_TOKEN + OPERATOR_SIGNED, Tier 1
 *
 * These are the read + write halves that close the "Mac app shells out to
 * `sanctuary wrap`" parity break for the unprotect direction and give every
 * renderer one API-backed agent list.
 *
 * Security model (fail closed — CLAUDE.md constraints 4, 5, 7):
 * - The router has already validated the SESSION_TOKEN before delegating
 *   here; a missing/invalid session never reaches this module.
 * - Writes additionally require a valid inline OPERATOR_SIGNED Ed25519
 *   signature over the canonical request payload (PR-A1's
 *   `verifyOperatorSignature`), verified against the daemon's operator
 *   identity public key. If no operator identity can be resolved, OR the
 *   signature does not verify, the write is DENIED with the generic 403 —
 *   never executed, never fails open. The two outcomes are indistinguishable
 *   in the response (no oracle for "is an operator key configured").
 * - Unprotect routes through the existing HubService Tier 1 approval queue
 *   (`controlAgent(..., "unwrap")`); it enqueues an approval-pending item
 *   and returns its id, it does NOT tear down synchronously.
 * - Protect (launching a NOT-yet-running harness) is NOT a HubService Tier 1
 *   control action. Phase S1 (split-process supervised-daemon, Erik-confirmed
 *   2026-06-13) wires execution through a SEPARATE supervisor process: the
 *   dashboard hands the supervisor a launch request over an authenticated
 *   local socket (`deps.launchProtect`); the supervisor owns spawning the
 *   wrapped agent and holds only a transient key. Protect is idempotent at
 *   both the request level (replay the 202) and the resource level (an
 *   already-up agent is a 200 no-op) so a double-click never double-launches.
 *   When no supervisor is wired, protect fails closed with 503 `unavailable`
 *   (never a silent success; never an auth oracle once a signature verified).
 *   Tier A+ (keychain-at-login) and Tier B (headless/unattended) are deferred
 *   behind their own Erik sign-off.
 *
 * Capability note (catalog Q2, OPEN): the canonical Wave 1 capability
 * vocabulary is unratified. Reads here are gated by the SESSION_TOKEN alone
 * (the catalog's Tier 2 requirement); writes are gated by the strictly
 * stronger OPERATOR_SIGNED cryptographic check. No new capability strings
 * are minted in PR-A2, so PR-A1's token contract is untouched; Q2 will add
 * read-capability granularity (`agents_read`) on top.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { createHash } from "node:crypto";
import type { LocalAgentRecord } from "../contracts/v1.1/local-agent-records.js";
import type { HubTier1ApprovalEnqueuedResult } from "../hub/types.js";
import type { V1SessionClaims } from "./session-service.js";
import { verifyOperatorSignature, canonicalJson } from "./operator-signed.js";
import { fromBase64url, toBase64url } from "../core/encoding.js";
import {
  writeJson,
  readJsonBody,
  denyForbidden,
  denyNotFound,
} from "./http.js";

/** Server-side cap on a single GET /v1/agents page, regardless of caller. */
export const V1_AGENTS_MAX_LIMIT = 100;
/** Default page size when the caller omits `limit`. */
export const V1_AGENTS_DEFAULT_LIMIT = 50;

/** Canonical AgentSummary (API Parity Catalog §2 "Shared Type Sketches"). */
export interface AgentSummary {
  agent_id: string;
  node_id: string;
  label: string;
  harness: string;
  protected: boolean;
  policy_id: string | null;
  last_activity_at: string | null;
}

/**
 * Outcome of a Tier 1 unprotect enqueue. The dashboard adapter maps
 * HubService's typed errors onto these reasons so this module never
 * depends on the hub error classes directly (and the handler maps each
 * reason to a fixed HTTP status).
 */
export type UnprotectOutcome =
  | { ok: true; result: HubTier1ApprovalEnqueuedResult }
  | { ok: false; reason: "not_found" | "unsupported" | "unavailable" };

/**
 * Outcome of asking the split-process supervisor to protect (launch +
 * supervise) an agent. The dashboard adapter (Phase S1) translates the
 * supervisor's socket response into one of these reasons so this module never
 * depends on the supervisor protocol types directly. Security-sensitive
 * reasons collapse into the generic 403 at the HTTP layer (no oracle).
 */
export type ProtectLaunchOutcome =
  | { ok: true; status: "protecting"; agent_id: string; launch_id: string }
  | { ok: true; status: "protected"; agent_id: string } // already up (no-op)
  | {
      ok: false;
      reason: "rotation_in_progress" | "bad_request" | "unavailable" | "forbidden";
    };

export interface V1AgentsDeps {
  /** This daemon's node id, echoed into every AgentSummary. */
  nodeId: string;
  /**
   * Local agent roster from the hub registry. Returns [] when no hub is
   * bound (the daemon simply manages no agents yet) — never throws.
   */
  listAgents(): LocalAgentRecord[];
  /**
   * The daemon operator identity's Ed25519 public key (32 bytes), or null
   * when no operator identity is configured. Null forces every write to
   * the generic 403 — fail closed, no operator-key oracle.
   */
  resolveOperatorPublicKey(): Uint8Array | null;
  /**
   * Enqueue a Tier 1 unwrap through HubService. Implementations translate
   * hub errors into {@link UnprotectOutcome} reasons; they never throw.
   */
  enqueueUnprotect(agentId: string): Promise<UnprotectOutcome>;
  /**
   * Ask the split-process supervisor (Phase S1) to launch + supervise an
   * agent. Implementations marshal a `protect` request over the authenticated
   * local socket and translate the supervisor's response/socket failures into
   * {@link ProtectLaunchOutcome} reasons; they never throw and never log the
   * transient key. Optional: when the supervisor subsystem is not wired, omit
   * this dep and protect fails closed with 503 `unavailable` (never a silent
   * success, never the old 501 oracle once a signature verified).
   */
  launchProtect?(spec: {
    agentId: string;
    harness: string;
    configPath: string;
  }): Promise<ProtectLaunchOutcome>;
  /** Injectable clock (idempotency expiry); defaults to Date.now. */
  now?: () => number;
  /** Injectable idempotency store; defaults to a fresh bounded LRU. */
  idempotency?: V1IdempotencyStore;
}

/** A path this module owns. */
export function isAgentsPath(pathname: string): boolean {
  return (
    pathname === "/v1/agents" ||
    pathname === "/v1/agents/protect" ||
    pathname === "/v1/agents/unprotect"
  );
}

// ── Idempotency (catalog Q7: client UUID key, 24h retention, bounded LRU) ──

/** Recommendation per catalog Q7 (pending Erik ratify): 24-hour retention. */
export const V1_IDEMPOTENCY_TTL_MS = 24 * 60 * 60_000;
/** Bound on retained idempotency records across all clients. */
export const V1_IDEMPOTENCY_MAX_ENTRIES = 1024;

interface IdempotencyRecord {
  status: number;
  body: unknown;
  storedAtMs: number;
}

/**
 * Replay cache so a retried Tier 1 write returns its first result instead
 * of enqueuing a second approval. Bounded LRU with a TTL; insertion-order
 * Map eviction.
 *
 * The composite key is built by the caller and MUST be stable across
 * sessions: a retry that opens a FRESH /v1 session (after a token timeout,
 * expiry, or process restart) gets a brand-new ephemeral session client
 * key, so keying on the session would silently miss and double-enqueue
 * (codex PR-A2 finding). The handler keys on the operator identity + action
 * + client-supplied idempotency key + a hash of the signed payload — none
 * of which change across a retry of the same logical operation.
 */
/** What a write producer yields: the response plus whether to durably cache it. */
export interface IdempotentResult {
  status: number;
  body: unknown;
  /** Cache for later (non-concurrent) retries. Failures set false. */
  cache: boolean;
}

export class V1IdempotencyStore {
  private readonly entries = new Map<string, IdempotencyRecord>();
  /**
   * In-flight reservations: a request that has passed the durable-cache
   * miss but not yet resolved holds its promise here so a CONCURRENT
   * duplicate awaits the same result instead of enqueuing a second Tier 1
   * item (codex PR-A2 finding). Cleared when the producer settles.
   */
  private readonly inflight = new Map<string, Promise<IdempotentResult>>();
  private readonly ttlMs: number;
  private readonly maxEntries: number;

  constructor(opts?: { ttlMs?: number; maxEntries?: number }) {
    this.ttlMs = opts?.ttlMs ?? V1_IDEMPOTENCY_TTL_MS;
    this.maxEntries = opts?.maxEntries ?? V1_IDEMPOTENCY_MAX_ENTRIES;
  }

  get(compositeKey: string, nowMs: number): IdempotencyRecord | undefined {
    const record = this.entries.get(compositeKey);
    if (!record) return undefined;
    if (nowMs - record.storedAtMs > this.ttlMs) {
      this.entries.delete(compositeKey);
      return undefined;
    }
    // Refresh recency (LRU): re-insert at the tail.
    this.entries.delete(compositeKey);
    this.entries.set(compositeKey, record);
    return record;
  }

  set(
    compositeKey: string,
    nowMs: number,
    value: { status: number; body: unknown },
  ): void {
    this.entries.delete(compositeKey);
    this.entries.set(compositeKey, {
      status: value.status,
      body: value.body,
      storedAtMs: nowMs,
    });
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
  }

  /**
   * Resolve a write exactly once per key: replay a durable cache hit,
   * coalesce onto an in-flight duplicate, or reserve the key and run
   * `producer`. The producer runs at most once across concurrent and
   * sequential duplicates while its result is cacheable; only one Tier 1
   * approval is ever enqueued for a given idempotency key.
   */
  async resolve(
    compositeKey: string,
    nowMs: number,
    producer: () => Promise<IdempotentResult>,
  ): Promise<{ status: number; body: unknown }> {
    const cached = this.get(compositeKey, nowMs);
    if (cached) return { status: cached.status, body: cached.body };

    const existing = this.inflight.get(compositeKey);
    if (existing) {
      const r = await existing;
      return { status: r.status, body: r.body };
    }

    const promise = producer();
    this.inflight.set(compositeKey, promise);
    try {
      const result = await promise;
      if (result.cache) {
        this.set(compositeKey, nowMs, { status: result.status, body: result.body });
      }
      return { status: result.status, body: result.body };
    } finally {
      this.inflight.delete(compositeKey);
    }
  }
}

/**
 * Build the session-independent idempotency key for a Tier 1 write. Stable
 * across retries of the same logical operation: operator namespace + action
 * + client idempotency UUID + a hash binding the exact signed payload (so a
 * client that reuses a UUID for a DIFFERENT payload gets a fresh enqueue
 * rather than a wrong replay).
 */
export function idempotencyKeyFor(
  operatorPublicKey: Uint8Array,
  action: string,
  idempotencyKey: string,
  signedPayload: Record<string, unknown>,
): string {
  const payloadHash = createHash("sha256")
    .update(canonicalJson(signedPayload), "utf-8")
    .digest("hex");
  return `${toBase64url(operatorPublicKey)}:${action}:${idempotencyKey}:${payloadHash}`;
}

// ── Mapping + pagination ────────────────────────────────────────────────

/** Map a hub registry record to the catalog AgentSummary shape. */
export function toAgentSummary(
  record: LocalAgentRecord,
  nodeId: string,
): AgentSummary {
  return {
    agent_id: record.agent_id,
    node_id: nodeId,
    // LocalAgentRecord carries no display label; the agent id is the
    // stable human-facing handle until a label field exists.
    label: record.agent_id,
    harness: record.harness,
    // Present in the hub roster ⇒ wrapped, unless mid-teardown.
    protected: record.status !== "unwrapping",
    policy_id: record.policy_id ?? null,
    last_activity_at: record.last_activity_at ?? null,
  };
}

interface AgentsQuery {
  nodeId?: string;
  harness?: string;
  limit: number;
  cursor?: string;
}

function parseAgentsQuery(url: URL): AgentsQuery {
  const rawLimit = url.searchParams.get("limit");
  let limit = V1_AGENTS_DEFAULT_LIMIT;
  if (rawLimit !== null) {
    const parsed = Number.parseInt(rawLimit, 10);
    if (Number.isFinite(parsed) && parsed > 0) {
      limit = Math.min(parsed, V1_AGENTS_MAX_LIMIT);
    }
  }
  return {
    nodeId: url.searchParams.get("node_id") ?? undefined,
    harness: url.searchParams.get("harness") ?? undefined,
    cursor: url.searchParams.get("cursor") ?? undefined,
    limit,
  };
}

/** Opaque offset cursor: base64url of the next start index. */
function decodeCursor(cursor: string | undefined): number {
  if (!cursor) return 0;
  try {
    const text = new TextDecoder().decode(fromBase64url(cursor));
    const n = Number.parseInt(text, 10);
    return Number.isFinite(n) && n >= 0 ? n : 0;
  } catch {
    return 0;
  }
}

function encodeCursor(offset: number): string {
  return toBase64url(new TextEncoder().encode(String(offset)));
}

// ── Handlers ────────────────────────────────────────────────────────────

/**
 * Dispatch an agents path. The session is already validated by the router;
 * `claims` carries the authenticated client identity used for idempotency
 * scoping and operator-signature binding context.
 */
export async function handleAgentsRequest(
  deps: V1AgentsDeps,
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  method: string,
  claims: V1SessionClaims,
): Promise<boolean> {
  if (method === "GET" && url.pathname === "/v1/agents") {
    handleListAgents(deps, res, url);
    return true;
  }
  if (method === "POST" && url.pathname === "/v1/agents/unprotect") {
    await handleUnprotect(deps, req, res, claims);
    return true;
  }
  if (method === "POST" && url.pathname === "/v1/agents/protect") {
    await handleProtect(deps, req, res, claims);
    return true;
  }
  // Wrong method on an owned path (e.g. GET /v1/agents/protect): not found,
  // same as any other unknown route to an authenticated caller.
  denyNotFound(res);
  return true;
}

function handleListAgents(
  deps: V1AgentsDeps,
  res: ServerResponse,
  url: URL,
): void {
  const query = parseAgentsQuery(url);

  // PR-A2 is single-node: only the local daemon's roster is knowable. A
  // request scoped to a different node returns an empty page rather than
  // an error — cross-node aggregation arrives with the federation read
  // endpoints (PR-A4). The local node still matches when node_id is omitted
  // or equals this node.
  if (query.nodeId !== undefined && query.nodeId !== deps.nodeId) {
    writeJson(res, 200, { agents: [] });
    return;
  }

  let summaries = deps
    .listAgents()
    .map((record) => toAgentSummary(record, deps.nodeId));
  if (query.harness !== undefined) {
    summaries = summaries.filter((a) => a.harness === query.harness);
  }
  // Stable order so the offset cursor is meaningful across pages.
  summaries.sort((a, b) => (a.agent_id < b.agent_id ? -1 : a.agent_id > b.agent_id ? 1 : 0));

  const start = decodeCursor(query.cursor);
  const page = summaries.slice(start, start + query.limit);
  const nextOffset = start + page.length;
  const body: { agents: AgentSummary[]; next_cursor?: string } = { agents: page };
  if (nextOffset < summaries.length) {
    body.next_cursor = encodeCursor(nextOffset);
  }
  writeJson(res, 200, body);
}

/**
 * Verify the inline OPERATOR_SIGNED signature over the request payload.
 * `payload` MUST be the request body with `operator_signature` removed.
 * Returns the verified operator public key when an operator identity is
 * configured AND the signature verifies; otherwise null. The caller maps
 * null to the generic 403 (no distinguishable failure reason) and reuses
 * the returned key to namespace idempotency to a stable operator identity.
 */
function resolveAndVerifyOperator(
  deps: V1AgentsDeps,
  action: string,
  payloadWithoutSignature: Record<string, unknown>,
  signature: unknown,
): Uint8Array | null {
  if (typeof signature !== "string" || signature.length === 0) return null;
  const operatorPublicKey = deps.resolveOperatorPublicKey();
  if (!operatorPublicKey) return null; // fail closed: no operator identity
  const ok = verifyOperatorSignature({
    action,
    payload: payloadWithoutSignature,
    signature,
    operatorPublicKey,
  });
  return ok ? operatorPublicKey : null;
}

async function handleUnprotect(
  deps: V1AgentsDeps,
  req: IncomingMessage,
  res: ServerResponse,
  _claims: V1SessionClaims,
): Promise<void> {
  const body = await readJsonBody(req);
  if (typeof body !== "object" || body === null) {
    // Authenticated caller: a shape error is an honest 400, not an auth
    // oracle (the session already proved access to the /v1 surface).
    writeJson(res, 400, { error: "bad request" });
    return;
  }
  const { agent_id, idempotency_key, node_id, operator_signature } = body as {
    agent_id?: unknown;
    idempotency_key?: unknown;
    node_id?: unknown;
    operator_signature?: unknown;
  };

  if (typeof agent_id !== "string" || agent_id.length === 0) {
    writeJson(res, 400, { error: "bad request" });
    return;
  }
  if (typeof idempotency_key !== "string" || idempotency_key.length === 0) {
    writeJson(res, 400, { error: "bad request" });
    return;
  }
  if (node_id !== undefined && typeof node_id !== "string") {
    writeJson(res, 400, { error: "bad request" });
    return;
  }

  // Operator signature is the real Tier 1 gate. Verify BEFORE touching the
  // hub so an unsigned request never enqueues an approval. The returned key
  // is the stable operator identity used to namespace idempotency.
  const action = "/v1/agents/unprotect";
  const signedPayload: Record<string, unknown> = { agent_id, idempotency_key };
  if (node_id !== undefined) signedPayload.node_id = node_id;
  const operatorPublicKey = resolveAndVerifyOperator(
    deps,
    action,
    signedPayload,
    operator_signature,
  );
  if (!operatorPublicKey) {
    denyForbidden(res);
    return;
  }

  // Single-node: a write addressed to a different node is rejected (no
  // federation transport in PR-A2). Reached only after a valid signature.
  if (node_id !== undefined && node_id !== deps.nodeId) {
    writeJson(res, 400, { error: "unknown node" });
    return;
  }

  // Enqueue the Tier 1 unwrap, deduplicated by idempotency key. The key is
  // the STABLE operator identity + action + idempotency key + payload hash,
  // NOT the ephemeral session client key — so a retry that opens a fresh
  // session still replays (codex finding 1). The store also coalesces
  // CONCURRENT duplicates onto one enqueue (codex finding 2).
  const nowMs = (deps.now ?? Date.now)();
  const store = deps.idempotency;
  const cacheKey = idempotencyKeyFor(operatorPublicKey, action, idempotency_key, signedPayload);

  // Enqueue is Tier 1: it queues an approval-pending item and returns —
  // the unwrap has NOT executed yet, so the success status is 202 Accepted
  // (matching the legacy hub control route), never 200. Failures are not
  // cached (a transient `unavailable` must be retryable).
  const produce = async (): Promise<IdempotentResult> => {
    const outcome = await deps.enqueueUnprotect(agent_id);
    if (!outcome.ok) {
      switch (outcome.reason) {
        case "not_found":
          return { status: 404, body: { error: "not found" }, cache: false };
        case "unsupported":
          return { status: 403, body: { error: "forbidden" }, cache: false };
        case "unavailable":
          return { status: 503, body: { error: "unavailable" }, cache: false };
      }
    }
    return {
      status: 202,
      body: {
        status: outcome.result.status,
        agent_id: outcome.result.agent_id,
        audit_event_id: outcome.result.inbox_item_id,
      },
      cache: true,
    };
  };

  const result = store
    ? await store.resolve(cacheKey, nowMs, produce)
    : await produce();
  writeJson(res, result.status, result.body);
}

async function handleProtect(
  deps: V1AgentsDeps,
  req: IncomingMessage,
  res: ServerResponse,
  _claims: V1SessionClaims,
): Promise<void> {
  const body = await readJsonBody(req);
  if (typeof body !== "object" || body === null) {
    writeJson(res, 400, { error: "bad request" });
    return;
  }
  const { harness, agent_id, config_path, node_id, idempotency_key, operator_signature } =
    body as {
      harness?: unknown;
      agent_id?: unknown;
      config_path?: unknown;
      node_id?: unknown;
      idempotency_key?: unknown;
      operator_signature?: unknown;
    };

  if (typeof harness !== "string" || harness.length === 0) {
    writeJson(res, 400, { error: "bad request" });
    return;
  }
  if (typeof idempotency_key !== "string" || idempotency_key.length === 0) {
    writeJson(res, 400, { error: "bad request" });
    return;
  }
  for (const value of [agent_id, config_path, node_id]) {
    if (value !== undefined && typeof value !== "string") {
      writeJson(res, 400, { error: "bad request" });
      return;
    }
  }

  // Lock the OPERATOR_SIGNED contract now, even though execution is stubbed:
  // an unsigned caller must NOT be able to tell that execution is
  // unimplemented (no 501 oracle without a valid signature).
  const signedPayload: Record<string, unknown> = { harness, idempotency_key };
  if (agent_id !== undefined) signedPayload.agent_id = agent_id;
  if (config_path !== undefined) signedPayload.config_path = config_path;
  if (node_id !== undefined) signedPayload.node_id = node_id;
  const operatorPublicKey = resolveAndVerifyOperator(
    deps,
    "/v1/agents/protect",
    signedPayload,
    operator_signature,
  );
  if (!operatorPublicKey) {
    denyForbidden(res);
    return;
  }

  if (node_id !== undefined && node_id !== deps.nodeId) {
    writeJson(res, 400, { error: "unknown node" });
    return;
  }

  // Protect launches a process via the split-process supervisor (Phase S1).
  // It requires a config_path (the harness config to supervise) and a stable
  // agent_id to key supervision + idempotency. A request without them is a
  // shape error, not an auth oracle (the signature already verified).
  if (typeof config_path !== "string" || config_path.length === 0) {
    writeJson(res, 400, { error: "bad request" });
    return;
  }
  const resolvedAgentId =
    typeof agent_id === "string" && agent_id.length > 0 ? agent_id : undefined;
  if (resolvedAgentId === undefined) {
    writeJson(res, 400, { error: "bad request" });
    return;
  }

  // Supervisor not wired ⇒ fail closed with a retryable 503 (NOT the old 501
  // oracle, and NOT a silent success). The signature already verified above,
  // so this is an honest "subsystem unavailable", not an auth signal.
  if (!deps.launchProtect) {
    writeJson(res, 503, { error: "unavailable" });
    return;
  }
  const launchProtect = deps.launchProtect;

  // Idempotency (review M2): protect is the path that LAUNCHES a process, so a
  // retried/raced double-click must launch exactly once. Key on the stable
  // operator identity + action + client idempotency key + payload hash — the
  // same session-independent composite the unprotect path uses — so a retry
  // that opens a fresh /v1 session still replays instead of double-launching.
  // The store also coalesces CONCURRENT duplicates onto one launch.
  const nowMs = (deps.now ?? Date.now)();
  const store = deps.idempotency;
  const cacheKey = idempotencyKeyFor(
    operatorPublicKey,
    "/v1/agents/protect",
    idempotency_key,
    signedPayload,
  );

  // Launch is asynchronous (Argon2id unlock, daemon arm, harness boot can take
  // seconds): success returns 202 Accepted with a distinct `launch_id` (L1:
  // protect's id is a launch handle, NOT an approval-queue inbox id like
  // unprotect's). "Already healthy" is a resource-level idempotent 200 no-op.
  // Security-sensitive denials (rotation/forbidden) collapse into the generic
  // 403 — no oracle, same fail-closed posture as the signature check. A
  // transient `unavailable` is a retryable 503 and is NOT cached.
  const produce = async (): Promise<IdempotentResult> => {
    const outcome = await launchProtect({
      agentId: resolvedAgentId,
      harness,
      configPath: config_path,
    });
    if (!outcome.ok) {
      switch (outcome.reason) {
        case "rotation_in_progress":
        case "forbidden":
          // Collapse into the generic 403 (no oracle for WHY it was denied;
          // the operator learns the reason from the audit log / dashboard).
          return { status: 403, body: { error: "forbidden" }, cache: false };
        case "bad_request":
          return { status: 400, body: { error: "bad request" }, cache: false };
        case "unavailable":
          return { status: 503, body: { error: "unavailable" }, cache: false };
      }
    }
    if (outcome.status === "protected") {
      // Resource-level idempotent no-op: the agent is already up (M2/L?).
      return {
        status: 200,
        body: { status: "protected", agent_id: outcome.agent_id },
        cache: true,
      };
    }
    return {
      status: 202,
      body: {
        status: "protecting",
        agent_id: outcome.agent_id,
        launch_id: outcome.launch_id,
      },
      cache: true,
    };
  };

  const result = store
    ? await store.resolve(cacheKey, nowMs, produce)
    : await produce();
  writeJson(res, result.status, result.body);
}
