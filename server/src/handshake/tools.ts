/**
 * Sanctuary MCP Server — Handshake MCP Tools
 *
 * MCP tool definitions for the sovereignty handshake protocol.
 * Four tools map to the four protocol steps:
 *   1. handshake_initiate — Start a handshake
 *   2. handshake_respond — Respond to an incoming challenge
 *   3. handshake_complete — Complete a handshake (initiator side)
 *   4. handshake_status — Check status of handshake sessions
 */

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import type { SanctuaryConfig } from "../config.js";
import type { IdentityManager } from "../cognitive/tools.js";
import type { AuditLog } from "../operational/audit-log.js";
import { BoundedMap } from "../core/bounded-map.js";
import { generateSHR, type SHRGeneratorOptions } from "../shr/generator.js";
import {
  sign as identitySign,
  publicKeyToDid,
  isLocallyHeldPublicKey,
} from "../core/identity.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { toBase64url, fromBase64url } from "../core/encoding.js";
import {
  initiateHandshake,
  respondToHandshake,
  completeHandshake,
  verifyCompletion,
  isSessionExpired,
  TERMINAL_SESSION_STATES,
} from "./protocol.js";
import {
  generateAttestation,
  verifyAttestation,
  type SignedAttestation,
} from "./attestation.js";
import {
  auditHandshakeAborted,
  auditHandshakeCompleted,
  auditHandshakeFailed,
  auditHandshakeInitiated,
  HANDSHAKE_LIFECYCLE_OPS,
  type HandshakeAbortReason,
  type HandshakeFailureReason,
} from "./audit.js";
import { verifySHR } from "../shr/verifier.js";
import type { SignedSHR } from "../shr/types.js";
import type {
  HandshakeChallenge,
  HandshakeResponse,
  HandshakeCompletion,
  HandshakeResult,
  HandshakeSession,
} from "./types.js";

/**
 * In-memory session store cap. BOUNDED (register LD2-03): `handshake_initiate`
 * mints a session per call with zero counterparty input, and a session is
 * otherwise deleted only by `handshake_abort` — an agent that never aborts
 * grows the store without limit. Every 4-step handler sweeps expired/terminal
 * sessions off the top (mirrors #1190's pruneExpiredActivations placement,
 * see the sweep calls in createHandshakeTools) so the map is bounded to LIVE
 * sessions on the request path; this cap is the backstop for a burst that
 * outpaces the 120s TTL between sweeps.
 *
 * 500 = generous headroom over any realistic single-fortress concurrent
 * in-flight handshake count (a human-triggered, interactive protocol, not a
 * hot loop) while still bounding worst-case memory to ~500 session records.
 * Exported so the class-level bounded-collection inventory test can drive
 * the real production path to this exact cap without hardcoding it twice.
 */
export const MAX_HANDSHAKE_SESSIONS = 500;

/**
 * Per-origin quota for `sessions` (AGENTS.md rule 8, MUST-FIX 1 RECHECK —
 * SPINE FIX, fix-round-2). The ORIGIN of a session is the SERVER-SET
 * AGENT-SESSION PRINCIPAL (`callerIdentity`, threaded down from
 * router.ts — `agent:<currentAgentId>` or the shared `agent:unknown`
 * bucket, see `AGENT_UNKNOWN_ORIGIN`'s doc), NEVER the caller-supplied
 * `identity_id` / `our_shr.body.instance_id` the fix-round-1 cut used.
 *
 * WHY THE CHANGE (verified at source): `identity_create` and
 * `identity_list` are both in `principal-policy/loader.ts`'s
 * `tier3_always_allow` — an untrusted agent mints local Sanctuary
 * identities freely, at will, with no approval gate. A per-origin quota
 * keyed on `identity_id` is therefore trivially defeated: mint ~10
 * identities, drive `MAX_HANDSHAKE_SESSIONS_PER_ORIGIN` sessions through
 * EACH one, and the flood again fills the whole global cap across 10
 * "distinct" origins that are really one attacker — reproducing the exact
 * cross-origin eviction/lockout this quota exists to prevent (the
 * fix-round-1 branch's own multi-identity test proved this at
 * attacker-writable-collections-bounds.test.ts). `callerIdentity` is not
 * mintable this way: it is set by the MCP router from
 * `options.currentAgentId()`, never from tool arguments, so an agent
 * cannot manufacture additional origins by minting identities — every
 * identity IT mints still calls through the SAME session and therefore
 * the SAME origin. 50 = 1/10th of MAX_HANDSHAKE_SESSIONS: generous for
 * legitimate concurrent in-flight handshakes from one agent session,
 * while guaranteeing at least 10 distinct agent sessions can be
 * mid-handshake at once before any single one could even begin to
 * threaten the global ceiling.
 *
 * HONEST POSTURE (rule 8, fix-round-2): this quota isolates DISTINCT agent
 * sessions from one another — the fleet / multi-agent-per-fortress
 * deployment shape this bound is really for. In a single-agent deployment
 * there is only ONE session, so this quota degenerates to a SELF-limit
 * (that one agent can fill its own 50-session share and get refused, same
 * as before) rather than a fairness guarantee between principals — there is
 * no second principal to be fair to. What does NOT degenerate: the
 * refuse-only eviction policy (never "evict this origin's own oldest to
 * make room") still holds in that single-session case, so even a
 * self-flooding single agent can never evict its OWN earlier session, let
 * alone another origin's — it just gets refused once its own quota fills.
 */
export const MAX_HANDSHAKE_SESSIONS_PER_ORIGIN = 50;

/**
 * Shared bucket for the `agent:unknown` fallback (MUST-FIX 1, deliberate
 * decision, fix-round-2). `router.ts` sets `callerIdentity` to
 * `agent:unknown` whenever `options.currentAgentId()` returns undefined —
 * e.g. a call that did not arrive through a wrapped-agent session (a
 * loopback/dashboard-triggered call, or a harness that never configured
 * `currentAgentId`). Every such call shares this ONE origin string and is
 * therefore subject to the SAME per-origin quota as any single named agent
 * session — deliberately NOT an unbounded escape hatch: an attacker cannot
 * multiply their headroom by arranging to look "unknown," because looking
 * unknown just means sharing one already-bounded bucket with every other
 * unknown caller. This is a shared-bucket choice, not fail-closed, because
 * unknown-identity calls are a legitimate operational path (embedded
 * dashboard / loopback tooling), not exclusively an attacker signal; a
 * fortress that runs entirely without a wrapped agent would otherwise have
 * every one of its own legitimate calls refused once the shared bucket's
 * modest quota is reached, which is the wrong failure mode for a
 * non-adversarial deployment shape.
 */
export const AGENT_UNKNOWN_ORIGIN = "agent:unknown";

/**
 * Resolve the per-origin quota key for a handler call (MUST-FIX 1). Shared
 * by `insertSession` (sessions) and `recordHandshakeResult`
 * (handshakeResults) so the AGENT_UNKNOWN_ORIGIN fallback decision lives in
 * exactly one place. `callerIdentity` is `router.ts`'s server-set session
 * principal; it is `undefined` only when a caller bypasses the router
 * entirely (a direct unit-test handler call, or a future non-MCP caller),
 * which this treats identically to the router's own `agent:unknown` case —
 * see AGENT_UNKNOWN_ORIGIN's doc for why a shared bucket, not fail-closed,
 * is the right response.
 */
function resolveSessionOrigin(callerIdentity: string | undefined): string {
  return callerIdentity && callerIdentity.length > 0
    ? callerIdentity
    : AGENT_UNKNOWN_ORIGIN;
}

/**
 * `handshakeResults` cap — shared with L4 tier resolution, federation
 * registration, and the dashboard. BOUNDED (register LD2-03): every
 * `handshake_exchange` call from an externally minted keypair adds a
 * permanent preview entry (verified:false), and src never deletes an entry,
 * so an unbounded stream of minted keys grows this map without limit.
 *
 * 1000 = headroom for a real fortress's peer + preview count (an order of
 * magnitude above a realistic federation peer list) while keeping the
 * capacity-refusal path reachable in an adversarial test without an
 * impractically long loop. Exported for the same reason as
 * MAX_HANDSHAKE_SESSIONS above.
 */
export const MAX_HANDSHAKE_RESULTS = 1000;

/**
 * Per-origin quota for `handshakeResults` (AGENTS.md rule 8, MUST-FIX 1
 * RECHECK — same spine fix as MAX_HANDSHAKE_SESSIONS_PER_ORIGIN above; see
 * that constant's doc for the full mint-many-identities defeat this closes).
 * The ORIGIN of a result is the SERVER-SET AGENT-SESSION PRINCIPAL
 * (`callerIdentity`, threaded from router.ts into `recordHandshakeResult`
 * below), NEVER the local identity that happened to sign the SHR
 * (`session.our_shr.body.instance_id` / `ourSHR.body.instance_id`) — a
 * value the calling agent can multiply at will via `identity_create`
 * (Tier 3 always-allow). Without this, feeding one agent session a stream
 * of attacker-controlled counterparty SHRs across many MINTED local
 * identities could still fill the entire global cap and — once every slot
 * holds a verified entry — permanently refuse recording for every OTHER
 * agent session too. With this, that flood exhausts only the flooding
 * SESSION's own quota and is REFUSED there, regardless of how many local
 * identities it minted to spread the flood across; a different agent
 * session's headroom is untouched. 100 = 1/10th of MAX_HANDSHAKE_RESULTS,
 * matching MAX_HANDSHAKE_SESSIONS_PER_ORIGIN's ratio: generous per-session
 * headroom, guarantees at least 10 distinct agent sessions' worth of
 * results fit before any one session could threaten the shared ceiling.
 */
export const MAX_HANDSHAKE_RESULTS_PER_ORIGIN = 100;

export interface HandshakeToolsOptions {
  /** If true, auto-publishes handshake attestations to Verascore after handshake_respond. */
  autoPublishHandshakes?: boolean;
  /** Verascore base URL to publish to. */
  verascoreUrl?: string;
  /**
   * Test-only override: SHR validity duration in ms, threaded into every
   * `generateSHR` call this closure makes (mirrors the
   * `maxTrackedFindings`-style test override pattern in
   * sentinel-finding-store.ts). Production call sites never set this
   * (defaults to shr/generator.ts's `DEFAULT_VALIDITY_MS`, one hour); it
   * exists so a test can produce a quickly-EXPIRING verified handshake
   * result without waiting a real hour, to exercise the expires_at-aware
   * `handshakeResults` eviction path end-to-end through the real tool
   * handlers rather than only at the BoundedMap unit level.
   */
  shrValidityMs?: number;
}

export function createHandshakeTools(
  config: SanctuaryConfig,
  identityManager: IdentityManager,
  masterKey: Uint8Array,
  auditLog: AuditLog,
  options?: HandshakeToolsOptions
): {
  tools: ToolDefinition[];
  // Exposed to every consumer (federation, dashboard, reputation, bridge) as
  // a ReadonlyMap: recordHandshakeResult below is the ONLY writer, and MUST
  // stay the only writer, since it is the producer chokepoint the whole
  // self-vouch class is closed at (register §Z RECHECK). The type system
  // enforces this at every consumer call site; a consumer that needs to
  // mutate the map is a design error, not a cast to work around.
  handshakeResults: ReadonlyMap<string, HandshakeResult>;
  // Per-origin accounting (AGENTS.md rule 8, MUST-FIX 1 RECHECK):
  // counterparty_id -> the AGENT-SESSION PRINCIPAL (`callerIdentity`,
  // resolved through `resolveSessionOrigin`) that FIRST created that
  // entry. This is `handshakeResults`'s own BoundedMap `origins` (see
  // `originsView()`, core/bounded-map.ts) — the IMMUTABLE ALLOCATION
  // origin, fixed forever at first insert and deliberately NEVER
  // reattributed on update (MUST-FIX 3, fix-round-2), so it feeds only
  // `handshakeResults`'s OWN per-origin quota
  // (`MAX_HANDSHAKE_RESULTS_PER_ORIGIN`, checked inside
  // `recordHandshakeResult` below). NOT what federation reads for its
  // registration charge — see `handshakeResultWriterOrigins` below for
  // that, and for why the two questions need different answers.
  handshakeResultOrigins: ReadonlyMap<string, string>;
  // FEDERATION-FACING WRITER accounting (MUST-FIX 2, fix-round-3). A
  // SEPARATE map from `handshakeResultOrigins` above: updated on EVERY
  // successful `recordHandshakeResult` write, insert OR update — "which
  // session's WRITE produced the result CURRENTLY stored for this
  // counterparty_id," not "which session's write claimed the slot
  // first." federation/tools.ts's register handler reads THIS map (never
  // `handshakeResultOrigins`) to decide whose per-origin registration
  // quota (`MAX_FEDERATION_PEERS_PER_ORIGIN`, federation/registry.ts) a
  // new peer counts against. The split exists because "first writer" and
  // "verified writer" are the same session in the common case but can
  // diverge under attack: `handshakeResultOrigins` staying fixed at first
  // insert (by design, to stop the framing/evasion attack MUST-FIX 3
  // closed) means an attacker who PREVIEWS a victim's counterparty FIRST
  // (a cheap, unverified `handshake_exchange` write — no real handshake
  // required) would otherwise permanently pin that counterparty_id's
  // charged origin to themselves; when the VICTIM later completes a REAL
  // 4-step verified handshake for that SAME counterparty (an UPDATE, per
  // BoundedMap's update path), federation would charge the victim's
  // genuine registration to the ATTACKER's quota — letting an attacker
  // who has exhausted their own quota with unrelated pre-previews deny a
  // victim's unrelated, legitimate registration. `handshakeResultWriterOrigins`
  // tracks the CURRENT writer instead, so that charge always lands on
  // whoever actually produced the verified result being registered.
  // REQUIRED at federation/tools.ts (not optional — MUST-FIX 2, both
  // rounds): an omitted map there must never mean "skip the quota."
  handshakeResultWriterOrigins: ReadonlyMap<string, string>;
} {
  const autoPublishHandshakes = options?.autoPublishHandshakes ?? false;
  const verascoreUrl = options?.verascoreUrl ?? "https://verascore.ai";
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");

  // In-memory session store (per server instance lifetime). Eviction policy
  // (reached only when the GLOBAL cap is hit and the incoming session's own
  // identity is still within MAX_HANDSHAKE_SESSIONS_PER_ORIGIN — see the
  // per-origin refusal path in BoundedMap.set(), which runs first): drop the
  // OLDEST session (first in Map insertion order — sessions are only ever
  // newly inserted, never re-inserted under the same key, so insertion
  // order tracks creation order) to admit a new one. This is safe to do
  // unconditionally: an evicted in-flight session simply fails its next
  // step with "No handshake session found," identical to what already
  // happens once its TTL expires — no trust state is lost, because a
  // session carries no trust until `recordHandshakeResult` writes it into
  // `handshakeResults`. This residual global-cap eviction can still cross
  // identities when pressure is spread thin across MANY distinct
  // identities each within their own quota — disclosed and accepted
  // (SOUND-WITH-FIXES gate review, target 1): the property this guards is
  // "one identity's OWN flood cannot evict another identity," not "the
  // global cap can never be reached by legitimate multi-identity load."
  // See MAX_HANDSHAKE_SESSIONS / MAX_HANDSHAKE_SESSIONS_PER_ORIGIN above.
  const sessions = new BoundedMap<string, HandshakeSession>({
    maxSize: MAX_HANDSHAKE_SESSIONS,
    maxPerOrigin: MAX_HANDSHAKE_SESSIONS_PER_ORIGIN,
    selectEviction: (entries) => {
      const oldest = entries.keys().next();
      // entries is non-empty whenever selectEviction runs (set() only
      // calls it when size >= maxSize > 0), so oldest.done is unreachable;
      // refuse defensively rather than evict a key that doesn't exist.
      if (oldest.done) return { refuse: true };
      return { evict: oldest.value };
    },
    onEvict: async (evictedSessionId) => {
      // AWAITED + CRITICAL (MUST-FIX 6, fix-round-2 RECHECK): eviction here
      // drops a live in-flight handshake session; BoundedMap.set() awaits
      // this and ABORTS the eviction (refuses the new insert) if the
      // durable write fails, rather than deleting a session with no audit
      // record of why. See bounded-map.ts's onEvict doc.
      //
      // INTENT ONLY, NOT COMPLETION (MUST-FIX 2, fix-round-5 — see
      // bounded-map.ts's onEvict doc "INTENT, NEVER COMPLETION" note): this
      // write can durably land AFTER set() has already timed out and
      // refused the eviction (appendCritical serializes behind
      // audit-log.ts's own append queue, so this write's total settle time
      // is unbounded under audit-queue contention even though set()'s own
      // wait is bounded). Naming it `_eviction_intent` rather than
      // `_evicted` means it can never be read as claiming the session was
      // actually removed — see `onEvicted` below for the completion record.
      await auditLog.appendCritical({
        layer: "l4",
        operation: "handshake_session_eviction_intent",
        identity_id: "system",
        result: "success",
        details: { session_id: evictedSessionId, reason: "capacity" },
      });
    },
    onEvicted: (evictedSessionId) => {
      // COMPLETION audit (MUST-FIX 2, fix-round-5 — see bounded-map.ts's
      // onEvicted doc). Fires synchronously, immediately after
      // bounded-map.ts's OWN delete, so by construction the session is
      // already gone by the time this runs — fire-and-forget is safe here
      // because this write can only ever describe a TRUE fact, never a
      // refused/timed-out eviction.
      void auditLog.append(
        "l4",
        "handshake_session_evicted",
        "system",
        { session_id: evictedSessionId, reason: "capacity" },
        "success"
      );
    },
    // No onRefuse here: `handshake_initiate` / `handshake_respond` below
    // already inspect `sessions.set()`'s return value and audit the
    // domain-specific reason (origin-quota vs global-capacity) themselves
    // with the identity that was refused — a second, BoundedMap-generic
    // audit entry here would just duplicate that with less context.
  });

  const SESSION_ORIGIN_QUOTA_ERROR =
    "This identity has too many in-flight handshake sessions " +
    `(limit ${MAX_HANDSHAKE_SESSIONS_PER_ORIGIN}). Complete or abort an ` +
    "existing session before starting a new one.";
  const SESSIONS_SATURATED_ERROR =
    "Handshake session store is at capacity; cannot start a new session " +
    "until an existing one completes, expires, or is aborted.";
  // CORRECTED (MUST-FIX 2, fix-round-6): the prior wording ("the store is
  // not full, its audit trail is unavailable") described the WRONG
  // condition. `audit_unavailable` is reachable ONLY from inside
  // bounded-map.ts's `map.size >= this.opts.maxSize` branch (see
  // `admitNewKey`) — the store WAS at capacity and an eviction WAS decided
  // to make room; what failed is that eviction's durable audit write, not
  // some separate "not full" state. Mirrors the wording
  // federation/tools.ts already uses correctly for its own
  // `audit_unavailable` branch.
  const SESSIONS_AUDIT_UNAVAILABLE_ERROR =
    "Handshake session store is at capacity and needed to evict an " +
    "existing session to admit this one, but the durable audit write for " +
    "that eviction did not complete in time; this is an audit-log " +
    "availability issue, not genuine session-store saturation. Retry " +
    "once the audit log recovers.";
  // ADMISSION-WAITER CAP (AGENTS.md rule 8, fix-round-6): distinct from all
  // three reasons above — this call never reached the origin-quota/
  // capacity/audit checks at all, because `sessions`'s own admission-lock
  // WAITER queue was already at its cap (core/bounded-map.ts's
  // `MAX_PENDING_ADMISSION_WAITERS`). A momentary serialization-primitive
  // saturation, not a statement about how many sessions are tracked.
  const SESSIONS_ADMISSION_BUSY_ERROR =
    "Handshake session store's admission queue is momentarily saturated " +
    "with other concurrent session insertions; retry shortly.";

  /**
   * Shared insert path for BOTH `handshake_initiate` and `handshake_respond`
   * (register LD2-03 / rule 8 RECHECK — every `sessions.set(...)` in this
   * file funnels through here, mirroring recordHandshakeResult's role for
   * `handshakeResults`, so the origin-quota-vs-capacity distinction and its
   * audit trail are written once, not duplicated per call site).
   *
   * `localIdentityId` is the LOCAL identity's own instance_id
   * (`shr.body.instance_id`) — kept ONLY as the audit log's `identity_id`
   * field (forensic attribution: which Sanctuary identity this session
   * belongs to) and as a component of `HandshakeFailureReason` context; it
   * is NEVER the quota origin (see MAX_HANDSHAKE_SESSIONS_PER_ORIGIN's doc
   * — a caller-mintable identity cannot be the quota key). `callerIdentity`
   * is the SERVER-SET agent-session principal (router.ts, MUST-FIX 1
   * spine) and IS the quota origin, resolved through
   * `resolveSessionOrigin` so an absent value (a call that bypassed the
   * router, or a legitimately unwrapped caller) lands in the shared
   * `AGENT_UNKNOWN_ORIGIN` bucket rather than skipping accounting.
   */
  function insertSession(
    session: HandshakeSession,
    localIdentityId: string,
    callerIdentity: string | undefined
  ): Promise<{ ok: true } | { ok: false; error: string; reason: HandshakeFailureReason }> {
    return (async () => {
      const origin = resolveSessionOrigin(callerIdentity);
      // MUST-FIX 3 (fix-round-3): read the REAL refusal reason off THIS
      // call's own result rather than reconstructing it from a pre-check
      // (the fix-round-2 shape) — `set()` can now refuse for a FOURTH
      // reason (`admission_busy`, fix-round-6, alongside `audit_unavailable`)
      // that a boolean-only pre-check (origin-quota-or-else-capacity)
      // cannot distinguish from genuine saturation.
      const result = await sessions.set(session.session_id, session, origin);
      if (!result.ok) {
        const reason: HandshakeFailureReason =
          result.reason === "origin_quota"
            ? "handshake_session_origin_quota_exceeded"
            : result.reason === "audit_unavailable"
              ? "handshake_session_audit_unavailable"
              : result.reason === "admission_busy"
                ? "handshake_session_admission_busy"
                : "handshake_session_store_saturated";
        const error =
          result.reason === "origin_quota"
            ? SESSION_ORIGIN_QUOTA_ERROR
            : result.reason === "audit_unavailable"
              ? SESSIONS_AUDIT_UNAVAILABLE_ERROR
              : result.reason === "admission_busy"
                ? SESSIONS_ADMISSION_BUSY_ERROR
                : SESSIONS_SATURATED_ERROR;
        void auditLog.append(
          "l4",
          reason,
          localIdentityId,
          { session_id: session.session_id, caller_identity: origin },
          "failure"
        );
        return { ok: false, error, reason };
      }
      return { ok: true };
    })();
  }

  // Completed handshake results indexed by counterparty ID — shared with L4
  // tier resolution, federation registration, and the dashboard. Kept as a
  // mutable BoundedMap INTERNALLY (recordHandshakeResult is the only
  // function in this closure that calls .set on it); the return type above
  // widens it to ReadonlyMap for every external consumer. See
  // MAX_HANDSHAKE_RESULTS above for the cap.
  //
  // Eviction policy: evict the oldest entry that is NOT a currently-live
  // verified peer to admit a new one — "currently-live verified" means
  // verified && liveness_proven && NOT PAST ITS OWN expires_at. A genuinely
  // live verified entry is NEVER evicted — see recordHandshakeResult, which
  // refuses the insert instead when no evictable entry exists to make room.
  // A full 4-step handshake IS attacker-reachable too (the counterparty
  // side is whatever process holds the minted key, which the attacker
  // controls end-to-end), so "prefer evicting previews/expired entries" is
  // not a loophole an attacker can route around by completing the liveness
  // proof; it just costs them a real round trip, and once the map is
  // saturated with entries that are ALL still live-verified, the fortress
  // fails closed (refuses new entries) rather than flushing an established
  // peer's trust state — the same fail-closed trade-off federation/registry.ts
  // makes for active peers.
  //
  // The `expires_at` check is load-bearing, not cosmetic (post-gate fix,
  // MEDIUM #1): without it, a verified+live entry that has since EXPIRED
  // was still treated as permanently unevictable, and nothing else ever
  // prunes `handshakeResults` (unlike `sessions`, which is TTL-swept every
  // handler call). An attacker who completes MAX_HANDSHAKE_RESULTS real
  // handshakes therefore permanently wedged the map — refusing every future
  // insert for the server's LIFETIME, long after every one of those entries
  // had expired. This selector is symmetric with
  // federation/registry.ts's `isPeerCurrentlyActive`-gated eviction now:
  // both roll off an expired verified entry to admit a new one, and both
  // refuse ONLY when every slot holds an entry that is verified, live, AND
  // still unexpired.
  const isHandshakeResultCurrentlyLive = (
    value: HandshakeResult,
    now: Date
  ): boolean =>
    value.verified && value.liveness_proven && new Date(value.expires_at) > now;

  const HANDSHAKE_RESULTS_SATURATED_ERROR =
    "Handshake result store is at capacity and every entry is a verified, " +
    "live, unexpired peer; cannot record a new handshake result until one " +
    "expires or is superseded.";
  const HANDSHAKE_RESULTS_ORIGIN_QUOTA_ERROR =
    "This identity has recorded too many handshake results " +
    `(limit ${MAX_HANDSHAKE_RESULTS_PER_ORIGIN}). This bounds one identity's ` +
    "share of the shared handshake-results store so it cannot exhaust the " +
    "space every identity draws from.";
  // CORRECTED (MUST-FIX 2, fix-round-6): the prior wording ("the store is
  // not full, its audit trail is unavailable") described the WRONG
  // condition — see SESSIONS_AUDIT_UNAVAILABLE_ERROR's doc above for the
  // identical correction and why `audit_unavailable` is only ever reached
  // from inside bounded-map.ts's AT-CAPACITY branch.
  const HANDSHAKE_RESULTS_AUDIT_UNAVAILABLE_ERROR =
    "Handshake result store is at capacity and needed to evict an " +
    "existing result to record this one, but the durable audit write for " +
    "that eviction did not complete in time; this is an audit-log " +
    "availability issue, not genuine handshake-result-store saturation. " +
    "Retry once the audit log recovers.";
  // ADMISSION-WAITER CAP (AGENTS.md rule 8, fix-round-6): see
  // SESSIONS_ADMISSION_BUSY_ERROR's doc above — same distinction, for
  // `handshakeResults`'s own admission-lock waiter queue.
  const HANDSHAKE_RESULTS_ADMISSION_BUSY_ERROR =
    "Handshake result store's admission queue is momentarily saturated " +
    "with other concurrent handshake completions; retry shortly.";
  const handshakeResults = new BoundedMap<string, HandshakeResult>({
    maxSize: MAX_HANDSHAKE_RESULTS,
    maxPerOrigin: MAX_HANDSHAKE_RESULTS_PER_ORIGIN,
    selectEviction: (entries) => {
      const now = new Date();
      for (const [key, value] of entries) {
        if (!isHandshakeResultCurrentlyLive(value, now)) {
          return { evict: key };
        }
      }
      return { refuse: true };
    },
    onEvict: async (evictedCounterpartyId, evictedResult) => {
      // AWAITED + CRITICAL (MUST-FIX 6, fix-round-2 RECHECK): see
      // `sessions`'s onEvict above — a verified peer's trust state
      // disappearing must have a durable audit record BEFORE the delete,
      // and the eviction ABORTS if the write fails.
      //
      // AUDIT ONLY (fix-round-4, MUST-FIX 1 / F1): this callback used to
      // ALSO clean up `handshakeResultWriterOrigins` here, guarded by a
      // conditional re-check (`handshakeResults.get(id) === evictedResult`)
      // that assumed "this promise resolved" and "bounded-map.ts decided to
      // delete" were the same event. They are NOT under
      // `ON_EVICT_AUDIT_TIMEOUT_MS`: bounded-map.ts can give up waiting on
      // this call (timeout) and refuse the eviction while this async
      // function keeps running DETACHED — no caller is listening to it
      // anymore — and when the write above eventually resolves, the OLD
      // conditional read as "still matches" (nothing else had touched the
      // entry) even though bounded-map.ts never deleted it, so the cleanup
      // ran for an eviction that, authoritatively, never happened. See the
      // real repro in the F1 gate finding this fix closes. The writer-origin
      // cleanup now lives in `onEvicted` below, which bounded-map.ts calls
      // ONLY immediately after its OWN synchronous delete — see that hook's
      // doc (core/bounded-map.ts) for why that makes it safe to do
      // unconditionally, with no reference re-check needed here at all.
      //
      // INTENT ONLY, NOT COMPLETION (MUST-FIX 2, fix-round-5 — a SECOND,
      // distinct symptom of the SAME F1 defect this file's `onEvicted`
      // split already closed for the sibling-state half: see
      // bounded-map.ts's onEvict doc "INTENT, NEVER COMPLETION" note).
      // `appendCritical` serializes behind audit-log.ts's own append
      // queue, so this write's total settle time is unbounded under
      // audit-queue contention even though `ON_EVICT_AUDIT_TIMEOUT_MS`
      // bounds how long `set()` itself waits — a write that resolves AFTER
      // `set()` already timed out and refused would, under the old
      // `_evicted`/"success" name, durably describe an eviction that never
      // happened (the entry is still in the map). Naming this the INTENT
      // record and moving the `_evicted` COMPLETION record into `onEvicted`
      // below (which only ever fires from this map's own authoritative
      // post-delete path) closes it structurally.
      await auditLog.appendCritical({
        layer: "l4",
        operation: "handshake_result_eviction_intent",
        identity_id: "system",
        result: "success",
        details: {
          counterparty_id: evictedCounterpartyId,
          verified: evictedResult.verified,
          liveness_proven: evictedResult.liveness_proven,
          expired: new Date(evictedResult.expires_at) <= new Date(),
          reason: "capacity",
        },
      });
    },
    onEvicted: (evictedCounterpartyId, evictedResult) => {
      // AUTHORITATIVE (fix-round-4, MUST-FIX 1 / F1 — see
      // core/bounded-map.ts's `BoundedMapOptions.onEvicted` doc). Keeps
      // `handshakeResultWriterOrigins`'s key set a subset of
      // `handshakeResults`'s own (MUST-FIX 2, fix-round-3): without this,
      // the writer-origin map would grow forever independent of
      // `handshakeResults`'s own bound — an entry counted here and never
      // removed, even after the underlying handshake result it describes
      // is gone, is exactly the unbounded-attacker-writable-collection
      // class this whole file exists to close (AGENTS.md rule 8).
      // UNCONDITIONAL, not a re-check against the evicted value: bounded-map
      // calls this synchronously, with no `await` between its own
      // `this.map.delete(evictedCounterpartyId)` and this call, so by
      // construction `handshakeResults` no longer holds ANY value for this
      // id at this exact point — there is nothing left to compare against,
      // and no concurrent write can have interleaved in the gap (there is
      // no gap).
      handshakeResultWriterOrigins.delete(evictedCounterpartyId);
      // COMPLETION audit (MUST-FIX 2, fix-round-5 — see `onEvict`'s
      // "INTENT ONLY" note above and bounded-map.ts's onEvicted doc).
      // Fire-and-forget is safe here for the same reason it is safe in
      // `sessions`'s onEvicted: this call only ever runs once the eviction
      // is ALREADY an authoritative fact, so the write can never be wrong,
      // only possibly delayed or lost.
      void auditLog.append(
        "l4",
        "handshake_result_evicted",
        "system",
        {
          counterparty_id: evictedCounterpartyId,
          verified: evictedResult.verified,
          liveness_proven: evictedResult.liveness_proven,
          expired: new Date(evictedResult.expires_at) <= new Date(),
          reason: "capacity",
        },
        "success"
      );
    },
    // No onRefuse here: recordHandshakeResult below reads the reason
    // directly off `handshakeResults.set()`'s own return value (MUST-FIX
    // 3, fix-round-3 — no longer a pre-check reconstruction) and audits
    // with the richer domain context (counterparty_id, the identity
    // refused) — see that function.
  });

  // FEDERATION-FACING WRITER accounting (MUST-FIX 2, fix-round-3) — see
  // this doc repeated in full on `createHandshakeTools`'s return type
  // above. Written by TWO sites, never a third: `recordHandshakeResult`
  // below sets an entry on every successful write (insert or update),
  // which is what makes it answer "who wrote the CURRENTLY stored value"
  // rather than `handshakeResults`'s own `origins` map's "who wrote it
  // FIRST"; `handshakeResults`'s `onEvicted` hook above (fix-round-4,
  // MUST-FIX 1) deletes an entry, authoritatively, exactly when
  // `handshakeResults` itself deletes the corresponding key. Both keep this
  // map's key set a subset of `handshakeResults`'s own — never a caller
  // outside this closure.
  const handshakeResultWriterOrigins = new Map<string, string>();

  const shrOpts: SHRGeneratorOptions = {
    config,
    identityManager,
    masterKey,
    validityMs: options?.shrValidityMs,
  };

  const SELF_VOUCH_ERROR =
    "Self-handshake rejected: an identity cannot verify another identity held by the same fortress";

  /**
   * Decode a base64url-encoded Ed25519 public key to raw bytes, or undefined
   * if it cannot be decoded. Every caller below uses the result ONLY to
   * REFUSE (never to grant trust), so a decode failure just skips the
   * refusal; a genuinely malformed key is already rejected elsewhere by SHR/
   * signature verification.
   */
  function tryDecodeSignerKey(signedByBase64url: string | undefined): Uint8Array | undefined {
    if (!signedByBase64url) return undefined;
    try {
      return fromBase64url(signedByBase64url);
    } catch {
      return undefined;
    }
  }

  /**
   * Derive the DID for a base64url-encoded Ed25519 public key, or undefined
   * if it cannot be decoded. INFORMATIONAL ONLY (audit-log readability) —
   * never use this for the local-identity TRUST decision; see
   * isLocallyHeldSignerKey / isLocallyHeldPublicKey below for why a DID
   * string is not safe to compare against a persisted identity's `.did`.
   */
  function tryDeriveDid(signedByBase64url: string | undefined): string | undefined {
    if (!signedByBase64url) return undefined;
    try {
      return publicKeyToDid(fromBase64url(signedByBase64url));
    } catch {
      return undefined;
    }
  }

  /**
   * Is `signerPublicKey` the raw signing key of an identity THIS fortress
   * currently holds? Computed FRESH via identityManager.list() on every call
   * (never cached at module-load or server-boot time), so an identity
   * created after startup is covered. Delegates to the shared
   * isLocallyHeldPublicKey predicate (core/identity.ts) — comparing DECODED
   * KEY BYTES, never a DID string, because a persisted identity's `.did` can
   * be in the legacy base64url encoding (see legacyPublicKeyToDid) while a
   * freshly-derived DID uses the canonical base58btc encoding; DID-string
   * equality silently fails to recognize a legacy-encoded local identity as
   * local (the #1194-class defect this guard exists to close).
   */
  function isLocallyHeldSignerKey(signerPublicKey: Uint8Array | undefined): boolean {
    return isLocallyHeldPublicKey(signerPublicKey, identityManager.list());
  }

  /**
   * CLASS-LEVEL SELF-VOUCH CHOKEPOINT (register §Z RECHECK / LD2-02, LD2-02b).
   *
   * `handshakeResults` is a SHARED SUBSTRATE: federation (peer registration),
   * the operator dashboard (handshake panel), and reputation/bridge tier
   * resolution all read from this ONE map. A poisoned entry that slips in
   * here is inherited as "verified" by every one of those consumers,
   * regardless of whether that consumer holds its own local-custody check
   * (neither federation nor the dashboard did — that was LD2-02 / LD2-02b).
   * Refusing the WRITE at the producer, rather than gating each consumer
   * separately, closes the whole class at once: no future consumer of this
   * map can be tricked by an entry that never exists.
   *
   * Every `handshakeResults.set(...)` in this file funnels through this one
   * function. A counterparty is "locally held" when its signing KEY BYTES
   * equal the key bytes of an identity THIS fortress currently holds
   * (isLocallyHeldSignerKey — compares decoded key material, never a DID
   * string; see that function's doc for the legacy-DID-encoding defect this
   * closes). The protocol-level `sameSigningKey()` guard (protocol.ts) only
   * rejects the degenerate case of an IDENTICAL key signing both sides of a
   * handshake; two DISTINCT locally-held keys (identity A handshaking
   * identity B, both created by the same operator) pass every
   * sameSigningKey check and are exactly the case this chokepoint closes.
   *
   * Also the SOLE writer for the bounded-collection guard (register
   * LD2-03): a refused insert (map at capacity, every existing entry
   * verified && liveness_proven) fails closed the same way a self-vouch
   * does — the caller gets an explicit refusal, never a silently-dropped
   * "success". `reason` on the failure branch lets callers audit the two
   * cases distinctly instead of collapsing them to one hardcoded label.
   *
   * `localIdentityId` is kept ONLY for audit attribution (which Sanctuary
   * identity signed our side); `callerIdentity` (MUST-FIX 1 spine) is the
   * quota origin, resolved via `resolveSessionOrigin` — see that function
   * and MAX_HANDSHAKE_RESULTS_PER_ORIGIN's doc for why a caller-mintable
   * identity must never be the accounting key.
   */
  function recordHandshakeResult(
    result: HandshakeResult,
    localIdentityId: string,
    callerIdentity: string | undefined
  ): Promise<{ ok: true } | { ok: false; error: string; reason: HandshakeFailureReason }> {
    return (async () => {
      const counterpartyKey = tryDecodeSignerKey(result.counterparty_shr.signed_by);
      if (isLocallyHeldSignerKey(counterpartyKey)) {
        // counterparty_did here is derived ONLY for the audit trail's
        // readability; the trust decision above already ran on decoded key
        // bytes, never this string.
        const counterpartyDid = tryDeriveDid(result.counterparty_shr.signed_by);
        void auditLog.append(
          "l4",
          "handshake_self_vouch_blocked",
          localIdentityId,
          {
            counterparty_id: result.counterparty_id,
            ...(counterpartyDid ? { counterparty_did: counterpartyDid } : {}),
          },
          "failure"
        );
        return { ok: false, error: SELF_VOUCH_ERROR, reason: "self_vouch_local_did" };
      }
      const origin = resolveSessionOrigin(callerIdentity);
      // MUST-FIX 3 (fix-round-3): read the REAL refusal reason off THIS
      // call's own `set()` result rather than reconstructing it from a
      // pre-check (the fix-round-2 shape) — `set()` can now refuse for a
      // FOURTH reason (`admission_busy`, fix-round-6, alongside
      // `audit_unavailable`) a boolean-only pre-check cannot distinguish
      // from genuine saturation.
      const setResult = await handshakeResults.set(
        result.counterparty_id,
        result,
        origin
      );
      if (!setResult.ok) {
        const reason: HandshakeFailureReason =
          setResult.reason === "origin_quota"
            ? "handshake_results_origin_quota_exceeded"
            : setResult.reason === "audit_unavailable"
              ? "handshake_results_audit_unavailable"
              : setResult.reason === "admission_busy"
                ? "handshake_results_admission_busy"
                : "handshake_results_saturated";
        const error =
          setResult.reason === "origin_quota"
            ? HANDSHAKE_RESULTS_ORIGIN_QUOTA_ERROR
            : setResult.reason === "audit_unavailable"
              ? HANDSHAKE_RESULTS_AUDIT_UNAVAILABLE_ERROR
              : setResult.reason === "admission_busy"
                ? HANDSHAKE_RESULTS_ADMISSION_BUSY_ERROR
                : HANDSHAKE_RESULTS_SATURATED_ERROR;
        void auditLog.append(
          "l4",
          reason,
          localIdentityId,
          { counterparty_id: result.counterparty_id, caller_identity: origin },
          "failure"
        );
        return { ok: false, error, reason };
      }
      // FEDERATION-FACING WRITER accounting (MUST-FIX 2, fix-round-3): set
      // on EVERY successful write, insert or update — see
      // `handshakeResultWriterOrigins`'s doc for why this must track the
      // CURRENT writer rather than staying fixed at first insert the way
      // `handshakeResults`'s own (BoundedMap-internal) origin does.
      handshakeResultWriterOrigins.set(result.counterparty_id, origin);
      return { ok: true };
    })();
  }

  /**
   * CLASS-LEVEL bounded-collection sweep (register LD2-03): run at the top
   * of every handler that touches `sessions`, mirroring #1190's
   * pruneExpiredActivations placement, so the map is bounded to LIVE
   * sessions on the request path, not only by the capacity cap.
   * `excludeSessionId` protects THIS call's own target session from being
   * swept before its expired/terminal state is classified and audited
   * below — sweeping it away here first would collapse a precise
   * "Handshake session expired" error into a generic "No handshake session
   * found," losing forensic signal for no bounding benefit (the session is
   * about to be read, and likely deleted, by this call either way).
   */
  function sweepExpiredSessions(excludeSessionId?: string): void {
    sessions.sweep(
      (session, sessionId) =>
        sessionId !== excludeSessionId &&
        (TERMINAL_SESSION_STATES.has(session.state) || isSessionExpired(session))
    );
  }

  const tools: ToolDefinition[] = [
    {
      name: "handshake_initiate",
      description:
        "Initiate a sovereignty handshake with a counterparty. " +
        "Generates a challenge containing this instance's signed SHR and a cryptographic nonce. " +
        "Send the returned challenge to the counterparty.",
      inputSchema: {
        type: "object",
        properties: {
          identity_id: {
            type: "string",
            description:
              "Identity to use for the handshake. Defaults to primary identity.",
          },
        },
      },
      handler: async (args, callerIdentity) => {
        sweepExpiredSessions();

        // Generate our SHR
        const shr = generateSHR(args.identity_id as string | undefined, shrOpts);
        if (typeof shr === "string") {
          return toolResult({ error: shr });
        }

        const { challenge, session } = initiateHandshake(shr);
        const insertResult = await insertSession(session, shr.body.instance_id, callerIdentity);
        if (!insertResult.ok) {
          auditHandshakeFailed(auditLog, {
            session_id: session.session_id,
            role: "initiator",
            identity_id: shr.body.instance_id,
            reason: insertResult.reason,
            error: insertResult.error,
          });
          return toolResult({ error: insertResult.error });
        }

        void auditLog.append("l4", "handshake_initiate", shr.body.instance_id);
        auditHandshakeInitiated(auditLog, {
          session_id: session.session_id,
          role: "initiator",
          identity_id: shr.body.instance_id,
        });

        return toolResult({
          session_id: session.session_id,
          challenge,
          instructions:
            "Send the 'challenge' object to the counterparty's sanctuary/handshake_respond tool. " +
            "When you receive their response, pass it to sanctuary/handshake_complete with this session_id.",
        });
      },
    },

    {
      name: "handshake_respond",
      description:
        "Respond to an incoming sovereignty handshake challenge. " +
        "Verifies the initiator's SHR, signs their nonce, and returns our SHR with a counter-nonce.",
      inputSchema: {
        type: "object",
        properties: {
          challenge: {
            type: "object",
            description: "The HandshakeChallenge received from the initiator.",
          },
          identity_id: {
            type: "string",
            description:
              "Identity to use for the response. Defaults to primary identity.",
          },
        },
        required: ["challenge"],
      },
      handler: async (args, callerIdentity) => {
        sweepExpiredSessions();

        const challenge = args.challenge as unknown as HandshakeChallenge;

        // Generate our SHR
        const shr = generateSHR(args.identity_id as string | undefined, shrOpts);
        if (typeof shr === "string") {
          return toolResult({ error: shr });
        }

        // Class-level self-vouch chokepoint (see recordHandshakeResult):
        // refuse a challenge from a counterparty this fortress already holds
        // keys for, before ever generating a response or advancing any
        // session state. sameSigningKey() inside respondToHandshake only
        // rejects an IDENTICAL key on both sides; this is the earliest point
        // that can catch the case it cannot — two DISTINCT locally-held keys.
        // Compares decoded key bytes (isLocallyHeldSignerKey), never a DID
        // string — see that function's doc.
        if (isLocallyHeldSignerKey(tryDecodeSignerKey(challenge.shr?.signed_by))) {
          void auditLog.append("l4", "handshake_respond", shr.body.instance_id, undefined, "failure");
          auditHandshakeFailed(auditLog, {
            session_id: "unknown",
            role: "responder",
            identity_id: shr.body.instance_id,
            reason: "self_vouch_local_did",
            error: SELF_VOUCH_ERROR,
          });
          return toolResult({ error: SELF_VOUCH_ERROR });
        }

        const result = respondToHandshake(
          challenge,
          shr,
          identityManager,
          masterKey,
          args.identity_id as string | undefined
        );

        if ("error" in result) {
          void auditLog.append("l4", "handshake_respond", shr.body.instance_id, undefined, "failure");
          auditHandshakeFailed(auditLog, {
            session_id: "unknown",
            role: "responder",
            identity_id: shr.body.instance_id,
            reason: classifyRespondFailure(result.error),
            error: result.error,
          });
          return toolResult({ error: result.error });
        }

        const insertResult = await insertSession(result.session, shr.body.instance_id, callerIdentity);
        if (!insertResult.ok) {
          void auditLog.append("l4", "handshake_respond", shr.body.instance_id, undefined, "failure");
          auditHandshakeFailed(auditLog, {
            session_id: result.session.session_id,
            role: "responder",
            identity_id: shr.body.instance_id,
            counterparty_id: challenge.shr.body.instance_id,
            reason: insertResult.reason,
            error: insertResult.error,
          });
          return toolResult({ error: insertResult.error });
        }

        void auditLog.append("l4", "handshake_respond", shr.body.instance_id);
        auditHandshakeInitiated(auditLog, {
          session_id: result.session.session_id,
          role: "responder",
          identity_id: shr.body.instance_id,
          counterparty_id: challenge.shr.body.instance_id,
        });

        // Auto-publish handshake attestation to Verascore (configurable).
        // This is a best-effort, non-blocking surface: failures are audit-logged
        // but do not break the handshake response.
        let autoPublishResult:
          | { attempted: boolean; ok?: boolean; status?: number; error?: string }
          | undefined;
        if (autoPublishHandshakes) {
          autoPublishResult = { attempted: true };
          try {
            // Only publish against https verascore hosts.
            const parsed = new URL(verascoreUrl);
            if (parsed.protocol !== "https:") {
              autoPublishResult.error = `verascore URL must use HTTPS (got ${parsed.protocol})`;
            } else {
              // DELTA-04: privacy. Without mutual explicit consent, strip
              // initiator-identifying fields from the published envelope.
              // We publish only the responder's own identity + opaque session id.
              const attestationPayload = {
                type: "handshake" as const,
                our_shr_signed_by: shr.signed_by,
                counterparty_signed_by: "redacted" as const,
                session_id: result.session.session_id,
                responded_at: new Date().toISOString(),
              };

              // DELTA-05: sign the publish payload with the responder's Ed25519
              // identity key so Verascore can verify it end-to-end.
              const responderIdentity = identityManager.get(shr.body.instance_id);
              if (!responderIdentity) {
                autoPublishResult.error =
                  `responder identity ${shr.body.instance_id} not found; skipping auto-publish`;
                void auditLog.append(
                  "l4",
                  "handshake_auto_publish",
                  shr.body.instance_id,
                  { error: autoPublishResult.error },
                  "failure"
                );
              } else {
                const payloadBytes = new TextEncoder().encode(
                  JSON.stringify(attestationPayload)
                );
                const sigBytes = identitySign(
                  payloadBytes,
                  responderIdentity.encrypted_private_key,
                  identityEncKey
                );
                const signatureB64 = toBase64url(sigBytes);

                const resp = await fetch(
                  `${verascoreUrl.replace(/\/$/, "")}/api/publish`,
                  {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                      agentId: shr.body.instance_id,
                      publicKey: shr.signed_by,
                      signature: signatureB64,
                      type: "handshake",
                      data: attestationPayload,
                    }),
                  }
                );
                autoPublishResult.ok = resp.ok;
                autoPublishResult.status = resp.status;
                void auditLog.append(
                  "l4",
                  "handshake_auto_publish",
                  shr.body.instance_id,
                  {
                    verascore_url: verascoreUrl,
                    status: resp.status,
                    ok: resp.ok,
                  },
                  resp.ok ? "success" : "failure"
                );
              }
            }
          } catch (err) {
            autoPublishResult.error =
              err instanceof Error ? err.message : String(err);
            void auditLog.append(
              "l4",
              "handshake_auto_publish",
              shr.body.instance_id,
              { verascore_url: verascoreUrl, error: autoPublishResult.error },
              "failure"
            );
          }
        }

        return toolResult({
          session_id: result.session.session_id,
          response: result.response,
          instructions:
            "Send the 'response' object back to the initiator. " +
            "When you receive their completion, pass it to sanctuary/handshake_status with this session_id.",
          auto_publish: autoPublishResult,
          // SEC-ADD-03: Tag response — contains SHR data that will be sent to counterparty
          _content_trust: "external",
        });
      },
    },

    {
      name: "handshake_complete",
      description:
        "Complete a sovereignty handshake (initiator side). " +
        "Verifies the responder's SHR and nonce signature, signs their nonce, and produces the final result.",
      inputSchema: {
        type: "object",
        properties: {
          session_id: {
            type: "string",
            description: "Session ID from handshake_initiate.",
          },
          response: {
            type: "object",
            description: "The HandshakeResponse received from the responder.",
          },
        },
        required: ["session_id", "response"],
      },
      handler: async (args, callerIdentity) => {
        const sessionId = args.session_id as string;
        sweepExpiredSessions(sessionId);
        const response = args.response as unknown as HandshakeResponse;

        const session = sessions.get(sessionId);
        if (!session) {
          auditHandshakeFailed(auditLog, {
            session_id: sessionId,
            role: "initiator",
            identity_id: "unknown",
            reason: "session_unknown",
            error: `No handshake session found: ${sessionId}`,
          });
          return toolResult({ error: `No handshake session found: ${sessionId}` });
        }
        // HS-2: reject a session past its server-anchored TTL. Mark it
        // `expired` (single-use terminal) so the nonce can never be reused.
        if (isSessionExpired(session)) {
          session.state = "expired";
          auditHandshakeFailed(auditLog, {
            session_id: sessionId,
            role: "initiator",
            identity_id: session.our_shr.body.instance_id,
            reason: "session_expired",
            error: "Handshake session expired",
          });
          return toolResult({ error: "Handshake session expired" });
        }
        // HS-2: single-use. Only a fresh `initiated` session can be completed;
        // any terminal/advanced state is spent and must not be reusable.
        if (session.state !== "initiated") {
          auditHandshakeFailed(auditLog, {
            session_id: sessionId,
            role: "initiator",
            identity_id: session.our_shr.body.instance_id,
            reason: "session_state_mismatch",
            error: `Session is in state '${session.state}', expected 'initiated'`,
          });
          return toolResult({
            error: `Session is in state '${session.state}', expected 'initiated'`,
          });
        }

        const result = completeHandshake(
          response,
          session,
          identityManager,
          masterKey
        );

        if ("error" in result) {
          session.state = "failed";
          void auditLog.append("l4", "handshake_complete", session.our_shr.body.instance_id, undefined, "failure");
          auditHandshakeFailed(auditLog, {
            session_id: sessionId,
            role: "initiator",
            identity_id: session.our_shr.body.instance_id,
            reason: classifyCompleteFailure(result.error),
            error: result.error,
          });
          return toolResult({ error: result.error });
        }

        // Class-level self-vouch chokepoint: refuse to RECORD (and therefore
        // to complete) when the responder's signing key belongs to an
        // identity this fortress already holds — the case sameSigningKey()
        // above cannot catch (two distinct locally-held keys). Reject before
        // the session is marked completed so the caller gets an explicit
        // refusal instead of a silently-unrecorded "success".
        const recorded = await recordHandshakeResult(
          result.result,
          session.our_shr.body.instance_id,
          callerIdentity
        );
        if (!recorded.ok) {
          session.state = "failed";
          void auditLog.append(
            "l4",
            "handshake_complete",
            session.our_shr.body.instance_id,
            undefined,
            "failure"
          );
          auditHandshakeFailed(auditLog, {
            session_id: sessionId,
            role: "initiator",
            identity_id: session.our_shr.body.instance_id,
            counterparty_id: result.result.counterparty_id,
            reason: recorded.reason,
            error: recorded.error,
          });
          return toolResult({ error: recorded.error });
        }

        session.state = "completed";
        session.their_shr = response.shr;
        session.their_nonce = response.responder_nonce;
        session.result = result.result;

        void auditLog.append("l4", "handshake_complete", session.our_shr.body.instance_id);
        auditHandshakeCompleted(auditLog, {
          session_id: sessionId,
          role: "initiator",
          identity_id: session.our_shr.body.instance_id,
          counterparty_id: result.result.counterparty_id,
          trust_tier: result.result.trust_tier,
        });

        return toolResult({
          completion: result.completion,
          result: result.result,
          instructions:
            "Send the 'completion' object to the responder so they can verify the handshake. " +
            "The 'result' object contains the verified counterparty status and trust tier.",
          // SEC-ADD-03: Tag response as containing counterparty-controlled SHR data
          _content_trust: "external",
        });
      },
    },

    {
      name: "handshake_status",
      description:
        "Check the state of an in-flight handshake session by id, or (responder side) verify an initiator's completion message. Read-only; returns session phase and, for verification, the validated counterparty SHR result.",
      inputSchema: {
        type: "object",
        properties: {
          session_id: {
            type: "string",
            description: "Session ID to check.",
          },
          completion: {
            type: "object",
            description:
              "Optional: HandshakeCompletion from the initiator (responder-side verification).",
          },
        },
        required: ["session_id"],
      },
      handler: async (args, callerIdentity) => {
        const sessionId = args.session_id as string;
        sweepExpiredSessions(sessionId);
        const completion = args.completion as unknown as HandshakeCompletion | undefined;

        const session = sessions.get(sessionId);
        if (!session) {
          return toolResult({ error: `No handshake session found: ${sessionId}` });
        }

        // HS-2: a completion against an expired session is rejected. Mark the
        // session `expired` (single-use terminal) before any verification so a
        // stale nonce cannot be reused. Only applies when actually verifying a
        // completion; bare status reads on an expired session still surface the
        // expired state below.
        if (
          completion &&
          session.role === "responder" &&
          !TERMINAL_SESSION_STATES.has(session.state) &&
          isSessionExpired(session)
        ) {
          session.state = "expired";
          auditHandshakeFailed(auditLog, {
            session_id: session.session_id,
            role: "responder",
            identity_id: session.our_shr.body.instance_id,
            reason: "session_expired",
            error: "Handshake session expired",
          });
          return toolResult({ error: "Handshake session expired" });
        }

        // If completion is provided, verify it (responder side).
        // The `state === "responded"` guard enforces single-use: once the
        // completion is verified the session advances to completed/failed and
        // can never be re-verified (replay of the completion message).
        if (completion && session.role === "responder" && session.state === "responded") {
          let result = verifyCompletion(completion, session);
          let recordFailure: { error: string; reason: HandshakeFailureReason } | undefined;

          // Class-level self-vouch / bounded-collection chokepoint: a
          // verified completion still must not be RECORDED when the
          // initiator's signing key belongs to an identity this fortress
          // already holds (reached only when sameSigningKey() in
          // protocol.ts already passed — the two distinct-local-keys case),
          // or when the shared results map is at capacity and every slot
          // already holds a verified peer (register LD2-03). Either way,
          // downgrade the returned result to unverified exactly as an
          // invalid nonce signature would, rather than silently reporting
          // verified:true for an entry that was never written.
          if (result.verified) {
            const recorded = await recordHandshakeResult(
              result,
              session.our_shr.body.instance_id,
              callerIdentity
            );
            if (!recorded.ok) {
              recordFailure = { error: recorded.error, reason: recorded.reason };
              result = {
                ...result,
                verified: false,
                trust_tier: "unverified",
                liveness_proven: false,
                errors: [...result.errors, recorded.error],
              };
            }
          }

          session.state = result.verified ? "completed" : "failed";
          session.result = result;

          void auditLog.append(
            "l4",
            "handshake_verify_completion",
            session.our_shr.body.instance_id,
            undefined,
            result.verified ? "success" : "failure"
          );
          if (result.verified) {
            auditHandshakeCompleted(auditLog, {
              session_id: session.session_id,
              role: "responder",
              identity_id: session.our_shr.body.instance_id,
              counterparty_id: result.counterparty_id,
              trust_tier: result.trust_tier,
            });
          } else {
            auditHandshakeFailed(auditLog, {
              session_id: session.session_id,
              role: "responder",
              identity_id: session.our_shr.body.instance_id,
              counterparty_id: result.counterparty_id,
              reason:
                recordFailure?.reason ??
                classifyCompleteFailure(result.errors.join("; ")),
              error: recordFailure?.error ?? result.errors.join("; "),
            });
          }

          return toolResult({ result });
        }

        // Otherwise just return session status
        return toolResult({
          session_id: session.session_id,
          role: session.role,
          state: session.state,
          initiated_at: session.initiated_at,
          result: session.result ?? null,
        });
      },
    },

    // ─── Streamlined Exchange ─────────────────────────────────────────

    {
      name: "handshake_exchange",
      description:
        "One-shot sovereignty exchange. Accepts a counterparty's signed SHR, verifies it, " +
        "generates our SHR, and produces a signed attestation artifact — all in a single call. " +
        "Returns a shareable attestation with human-readable summary. " +
        "Use this instead of the 4-step handshake protocol when you want a quick, " +
        "portable sovereignty verification (e.g., for social posting or async exchanges).",
      inputSchema: {
        type: "object",
        properties: {
          counterparty_shr: {
            type: "object",
            description:
              "The counterparty's signed SHR (SignedSHR object with body, signed_by, signature).",
          },
          identity_id: {
            type: "string",
            description:
              "Identity to use for the exchange. Defaults to primary identity.",
          },
        },
        required: ["counterparty_shr"],
      },
      handler: async (args, callerIdentity) => {
        const counterpartySHR = args.counterparty_shr as unknown as SignedSHR;

        // 1. Generate our SHR
        const ourSHR = generateSHR(args.identity_id as string | undefined, shrOpts);
        if (typeof ourSHR === "string") {
          return toolResult({ error: ourSHR });
        }

        // 2. Verify counterparty's SHR
        const verificationResult = verifySHR(counterpartySHR);

        // 3. Generate signed attestation artifact
        const attestation = generateAttestation({
          attesterSHR: ourSHR,
          subjectSHR: counterpartySHR,
          verificationResult,
          mutual: false,
          identityManager,
          masterKey,
          identityId: args.identity_id as string | undefined,
        });

        if ("error" in attestation) {
          void auditLog.append("l4", "handshake_exchange", ourSHR.body.instance_id, undefined, "failure");
          return toolResult({ error: attestation.error });
        }

        // 4. Store as a handshake result for tier resolution. Captures the
        // FAIL-LOUD recording outcome (register §Z RECHECK) for the
        // `verification.recorded` / `record_error` response fields below —
        // see recordHandshakeResult's doc for why a refusal here must be
        // surfaced, never silently dropped.
        let recordResult:
          | { ok: true }
          | { ok: false; error: string; reason: HandshakeFailureReason }
          | undefined;
        // MUST-FIX 7 (P2, fix-round-2 RECHECK): true only when THIS call's
        // preview already had live coverage from a prior 4-step handshake
        // (the MEDIUM#3 downgrade-DoS guard below, which deliberately skips
        // writing in that case) — the counterparty IS represented in
        // handshakeResults either way, just not because of this write. Used
        // below so `verification.recorded` never defaults to `true` when no
        // record exists and none was ever attempted (e.g. an invalid SHR).
        let alreadyLivePeer = false;
        //
        // HS-1 / HS-2 fix: handshake_exchange is a STRUCTURAL PREVIEW ONLY.
        // It performs no nonce challenge-response, so it proves neither
        // counterparty key-control nor liveness — a captured SHR replays
        // directly. Therefore it must NEVER write a `verified:true` result or
        // a verified-sovereign / verified-degraded trust tier. It is barred
        // from producing any trust label above `unverified`. Trust-establishing
        // handshakes MUST go through the nonce-bearing 4-step protocol
        // (handshake_initiate → respond → complete), which is the only path
        // that can set liveness_proven:true.
        if (verificationResult.valid) {
          const sovereigntyLevel = verificationResult.sovereignty_level as
            | "full"
            | "degraded"
            | "minimal"
            | "unverified";

          // MEDIUM#3: a structural preview must never DOWNGRADE an already
          // established peer. If a verified / liveness-proven result already
          // exists for this counterparty (from the 4-step protocol), leave it
          // intact — otherwise a captured SHR replayed through the preview path
          // would silently demote a live peer (downgrade DoS).
          const existing = handshakeResults.get(
            verificationResult.counterparty_id
          );
          if (!existing || (!existing.verified && !existing.liveness_proven)) {
            // Class-level self-vouch chokepoint: even an unverified preview
            // entry is refused when it describes a counterparty this fortress
            // already holds keys for — funneled through the SAME shared
            // recordHandshakeResult() every other write site uses, so a
            // future consumer of this map never has to special-case
            // "preview" entries differently from "completed" ones.
            //
            // FAIL-LOUD (register §Z RECHECK): earlier code discarded this
            // call's return value, so a self-vouch or bounded-collection
            // refusal here was invisible to the caller — the tool still
            // reported an apparently-successful preview even though nothing
            // was recorded. Capture it and surface it on the response below;
            // the attestation itself is still valid and still returned
            // (recording is a caching side effect for future tier
            // resolution, not the attestation's own correctness), so this is
            // additive honesty, not a new failure mode for the tool call.
            recordResult = await recordHandshakeResult(
              {
                counterparty_id: verificationResult.counterparty_id,
                counterparty_shr: counterpartySHR,
                verified: false,
                sovereignty_level: sovereigntyLevel,
                trust_tier: "unverified",
                completed_at: new Date().toISOString(),
                expires_at: verificationResult.expires_at,
                errors: [],
                liveness_proven: false,
              },
              ourSHR.body.instance_id,
              callerIdentity
            );
          } else {
            // Existing entry is already verified/live: the write was
            // deliberately skipped (MEDIUM#3), not refused — the
            // counterparty IS covered in handshakeResults, just from a
            // prior call. See `alreadyLivePeer`'s doc above.
            alreadyLivePeer = true;
          }
        }

        void auditLog.append("l4", "handshake_exchange", ourSHR.body.instance_id);

        return toolResult({
          attestation,
          our_shr: ourSHR,
          verification: {
            counterparty_valid: verificationResult.valid,
            counterparty_sovereignty: verificationResult.sovereignty_level,
            counterparty_id: verificationResult.counterparty_id,
            liveness_proven: false,
            trust_tier: "unverified",
            errors: verificationResult.errors,
            warnings: verificationResult.warnings,
            // FAIL-LOUD (register §Z RECHECK) + TRUTHFUL (MUST-FIX 7, P2,
            // fix-round-2 RECHECK): whether this counterparty is actually
            // represented in handshakeResults for future tier resolution.
            // Previously defaulted to `true` whenever no write was
            // ATTEMPTED — including when `verificationResult.valid` was
            // false, so an invalid SHR reported `recorded: true` despite
            // recording nothing. Now `true` only when this call actually
            // wrote a record (`recordResult.ok`) or the counterparty was
            // already covered by a prior live record (`alreadyLivePeer`);
            // `false` whenever verification failed, self-vouch fired, or
            // the bounded-collection quota refused the write.
            recorded: recordResult?.ok ?? alreadyLivePeer,
            ...(recordResult && !recordResult.ok
              ? { record_error: recordResult.error }
              : {}),
          },
          instructions:
            "STRUCTURAL CHECK ONLY — counterparty liveness is NOT proven, so this " +
            "is not a verified peer and cannot be used for federation. " +
            "The 'attestation' object is a signed, portable sovereignty verification artifact. " +
            "Share it with the counterparty or post attestation.summary publicly. " +
            "The counterparty can verify the attestation signature using your public key. " +
            "Our SHR is included so the counterparty can perform their own verification of us. " +
            "To establish a trusted peer, use the 4-step handshake_initiate / handshake_respond / " +
            "handshake_complete protocol, which proves liveness via a nonce challenge.",
          _content_trust: "external",
        });
      },
    },

    {
      name: "handshake_verify_attestation",
      description:
        "Verify a signed attestation artifact from another agent. " +
        "Checks the Ed25519 signature, temporal validity, and structural integrity.",
      inputSchema: {
        type: "object",
        properties: {
          attestation: {
            type: "object",
            description:
              "The SignedAttestation object to verify (body, signed_by, signature, summary).",
          },
        },
        required: ["attestation"],
      },
      handler: async (args) => {
        const attestation = args.attestation as unknown as SignedAttestation;

        const result = verifyAttestation(attestation);

        void auditLog.append(
          "l4",
          "handshake_verify_attestation",
          result.attester_id,
          undefined,
          result.valid ? "success" : "failure"
        );

        return toolResult({
          ...result,
          _content_trust: "external",
        });
      },
    },

    {
      name: "handshake_abort",
      description:
        "Abort an in-flight handshake session. Drops the session record and " +
        "appends a session-lifecycle audit entry (handshake_aborted) so the " +
        "operator can distinguish operator-cancelled, timed-out, and dropped " +
        "sessions from sessions that simply fell off the protocol path.",
      inputSchema: {
        type: "object",
        properties: {
          session_id: {
            type: "string",
            description: "Session ID returned from handshake_initiate / handshake_respond.",
          },
          reason: {
            type: "string",
            enum: [
              "operator_cancelled",
              "session_timeout",
              "transport_dropped",
              "shutdown",
              "other",
            ],
            description:
              "Why the session is being aborted. Defaults to 'operator_cancelled'.",
          },
        },
        required: ["session_id"],
      },
      handler: async (args) => {
        const sessionId = args.session_id as string;
        sweepExpiredSessions(sessionId);
        const reason = (args.reason as HandshakeAbortReason | undefined) ??
          "operator_cancelled";
        const session = sessions.get(sessionId);
        if (!session) {
          return toolResult({ error: `No handshake session found: ${sessionId}` });
        }
        if (session.state === "completed") {
          return toolResult({
            error: `Session ${sessionId} already completed; abort is only valid for in-flight sessions`,
          });
        }
        sessions.delete(sessionId);
        auditHandshakeAborted(auditLog, {
          session_id: sessionId,
          role: session.role,
          identity_id: session.our_shr.body.instance_id,
          ...(session.their_shr
            ? { counterparty_id: session.their_shr.body.instance_id }
            : {}),
          reason,
        });
        return toolResult({
          aborted: true,
          session_id: sessionId,
          reason,
        });
      },
    },
  ];

  return {
    tools,
    handshakeResults: handshakeResults.asReadonlyMap(),
    handshakeResultOrigins: handshakeResults.originsView(),
    handshakeResultWriterOrigins,
  };
}

/**
 * Map a respondToHandshake error string onto the lifecycle-audit reason
 * enum. Errors are short, well-known strings produced by protocol.ts.
 */
function classifyRespondFailure(error: string): HandshakeFailureReason {
  if (error.includes("Unsupported protocol version")) return "protocol_version_unsupported";
  if (error.includes("SHR verification failed")) return "shr_invalid";
  if (error.includes("No identity available")) return "no_signing_identity";
  return "other";
}

/** Same shape as classifyRespondFailure for completeHandshake / verifyCompletion errors. */
function classifyCompleteFailure(error: string): HandshakeFailureReason {
  if (error.includes("Unsupported protocol version")) return "protocol_version_unsupported";
  if (error.includes("SHR verification failed") || error.includes("SHR")) return "shr_invalid";
  if (error.includes("nonce signature is invalid")) return "nonce_signature_invalid";
  if (error.includes("No identity available")) return "no_signing_identity";
  return "other";
}

// Re-export the lifecycle ops for downstream consumers (audit-query callers).
export { HANDSHAKE_LIFECYCLE_OPS };
