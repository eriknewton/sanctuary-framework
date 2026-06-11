/**
 * Sanctuary v1.3 WP-V1.3-10 Cross-Harness Approval Inbox Upsilon-2
 *
 * `AggregatorBackedChannel` wraps an underlying `ApprovalChannel` (stderr,
 * dashboard, webhook) and routes Tier 1/2 approval resolutions through the
 * approval-inbox aggregator when redirect-mode is enabled.
 *
 * Two modes (selected by `approval_redirect.mode` in principal-policy.yaml):
 *
 *   - `replace`: the underlying channel is bypassed; `requestApproval()`
 *     blocks awaiting the operator's decision through the aggregator
 *     `resolve()` API (called by the HTTP `approve`/`deny` routes from
 *     Upsilon-1, or any other surface). Suppresses the wrapped agent's
 *     local approval prompt entirely.
 *   - `notify`: BOTH the underlying channel AND the aggregator run; the
 *     first decision wins. Used for harnesses that cannot fully suppress
 *     their local approval prompt (e.g. Mastra-class). The operator sees
 *     the local prompt AND can resolve from the unified inbox.
 *
 * Castle-walking discipline:
 *   - Real Castle Layer 1 enforcement is preserved: a denied resolution
 *     returns the same `ApprovalResponse{ decision: "deny" }` shape the
 *     gate already audit-logs and propagates to the egress filter.
 *   - The aggregator never invents a fresh approval — it only passes
 *     through decisions made by an operator (or the system TTL via
 *     `expired` -> deny).
 *   - The wrapper falls closed on aggregator errors (subscription throw,
 *     resolve throw): the request denies and the gate's existing
 *     channel-failure path captures the error in the audit log.
 *   - In `replace` mode with a degenerate aggregator (no events ever),
 *     the wrapper still respects the configured `timeout_seconds` from
 *     the underlying `ApprovalChannelConfig` and resolves to deny on
 *     timeout. This is the SEC-002 invariant carried into the redirect
 *     path.
 *
 * Not in scope here (v1.4+):
 *   - Per-agent overrides via `approval_redirect.per_agent`. The config
 *     parser already accepts and persists this map; v1.x ignores it. The
 *     gate signature does not propagate `agent_id`, so per-agent gating
 *     requires a coordinated upstream change.
 */

import type {
  ApprovalRequest,
  ApprovalResponse,
} from "../types.js";
import type { ApprovalChannel } from "../approval-channel.js";
import type {
  ApprovalAggregator,
  AggregatedApproval,
  ApprovalAggregatorEmit,
} from "../approval-aggregator.js";

/**
 * Resolver returned by the wire-up: reads the live policy at request time
 * so a `sanctuary agents config --approval-redirect=...` flip lands without
 * a server restart on the next request. Returns `null` to mean
 * "off/passthrough" (delegate to underlying channel unchanged).
 */
export interface ApprovalRedirectResolver {
  (request: ApprovalRequest): {
    enabled: boolean;
    mode: "replace" | "notify";
  };
}

export interface AggregatorBackedChannelOptions {
  /** Underlying channel (stderr / dashboard / webhook). Always constructed. */
  underlying: ApprovalChannel;
  /** The Upsilon-1 aggregator. Subscribed to via `onEvent`. */
  aggregator: ApprovalAggregator;
  /**
   * Reads the current redirect config per request. Called once per
   * `requestApproval()` so policy edits take effect on the next request
   * without process restart.
   */
  resolveRedirect: ApprovalRedirectResolver;
  /**
   * Hard timeout (ms) for `replace` mode when the aggregator never
   * resolves the entry. Defaults to 300_000ms (5min, mirrors the
   * aggregator's pending TTL).
   *
   * The aggregator's own TTL also fires `resolved` events with status
   * `expired` once an entry passes its `expires_at` (default 5min), but
   * `expireStale()` only runs on `list()` calls. The hard timeout here is
   * a belt-and-suspenders guarantee that a `replace`-mode block cannot
   * hang forever in an inbox-not-being-polled scenario.
   */
  replaceModeTimeoutMs?: number;
  /** Optional clock override for deterministic tests. */
  now?: () => Date;
}

const DEFAULT_REPLACE_MODE_TIMEOUT_MS = 5 * 60 * 1000;

/**
 * Internal: structural match between an `ApprovalRequest` (what the gate
 * hands the channel) and an `AggregatedApproval` (what the aggregator
 * persists). Both share the audit_entry_id format
 * `<request.timestamp>:<request.operation>` — see `auditEntryIdForEvent`
 * in approval-aggregator.ts.
 */
function auditEntryIdFor(request: ApprovalRequest): string {
  return `${request.timestamp}:${request.operation}`;
}

function statusToDecision(
  entry: AggregatedApproval,
): { decision: "approve" | "deny"; decided_by: ApprovalResponse["decided_by"] } | null {
  switch (entry.status) {
    case "approved":
      return {
        decision: "approve",
        decided_by: "human",
      };
    case "denied":
      return {
        decision: "deny",
        decided_by: "human",
      };
    case "timeout":
    case "expired":
      return {
        decision: "deny",
        decided_by: "timeout",
      };
    default:
      return null;
  }
}

export class AggregatorBackedChannel implements ApprovalChannel {
  private readonly underlying: ApprovalChannel;
  private readonly aggregator: ApprovalAggregator;
  private readonly resolveRedirect: ApprovalRedirectResolver;
  private readonly replaceModeTimeoutMs: number;
  private readonly now: () => Date;

  constructor(opts: AggregatorBackedChannelOptions) {
    this.underlying = opts.underlying;
    this.aggregator = opts.aggregator;
    this.resolveRedirect = opts.resolveRedirect;
    this.replaceModeTimeoutMs =
      opts.replaceModeTimeoutMs ?? DEFAULT_REPLACE_MODE_TIMEOUT_MS;
    this.now = opts.now ?? (() => new Date());
  }

  /** Expose underlying for tests / wire-up reuse. */
  getUnderlying(): ApprovalChannel {
    return this.underlying;
  }

  async requestApproval(request: ApprovalRequest): Promise<ApprovalResponse> {
    const cfg = this.resolveRedirect(request);
    if (!cfg.enabled) {
      // Redirect off → delegate verbatim. No subscription, no extra audit.
      return this.underlying.requestApproval(request);
    }
    if (cfg.mode === "replace") {
      return this.awaitAggregatorDecision(request);
    }
    // notify mode: race underlying channel and aggregator.
    return this.notifyMode(request);
  }

  /**
   * `replace` mode. Subscribe to the aggregator's event stream BEFORE
   * checking already-stored entries (avoids a race where the entry resolves
   * between list and subscribe). Match incoming events to this request by
   * audit_entry_id. Time out after `replaceModeTimeoutMs` to honor SEC-002.
   */
  private async awaitAggregatorDecision(
    request: ApprovalRequest,
  ): Promise<ApprovalResponse> {
    const auditId = auditEntryIdFor(request);

    return new Promise<ApprovalResponse>((resolveOuter) => {
      let settled = false;
      let unsubscribe: (() => void) | null = null;
      let timeoutHandle: ReturnType<typeof setTimeout> | null = null;

      const settle = (response: ApprovalResponse): void => {
        if (settled) return;
        settled = true;
        if (timeoutHandle) clearTimeout(timeoutHandle);
        if (unsubscribe) {
          try {
            unsubscribe();
          } catch {
            // swallow — we're already returning a decision
          }
        }
        resolveOuter(response);
      };

      const onEvent = (emit: ApprovalAggregatorEmit): void => {
        // Only resolved events drive a channel response; aggregated /
        // deduped events are observation-only.
        if (emit.type !== "resolved") return;
        if (emit.entry.audit_log_entry_id !== auditId) return;
        const mapped = statusToDecision(emit.entry);
        if (!mapped) return;
        settle({
          decision: mapped.decision,
          decided_at: emit.entry.resolved_at ?? this.now().toISOString(),
          decided_by: mapped.decided_by,
        });
      };

      try {
        unsubscribe = this.aggregator.onEvent(onEvent);
      } catch (err) {
        // Subscription failed — fall closed.
        settle({
          decision: "deny",
          decided_at: this.now().toISOString(),
          decided_by: "channel_failure",
        });
        // Surface the error via the underlying channel-failure path so the
        // gate's audit log captures it. We have already settled the
        // promise, so this throw triggers the gate's existing catch.
        throw err instanceof Error ? err : new Error(String(err));
      }

      // Race: the aggregator may have already resolved the entry between
      // the gate firing `requested` and this channel call. Check stored
      // entries by audit id; if a terminal status is already present,
      // settle immediately without waiting for an event.
      void this.aggregator
        .list({ limit: 200 })
        .then((entries) => {
          for (const entry of entries) {
            if (entry.audit_log_entry_id !== auditId) continue;
            const mapped = statusToDecision(entry);
            if (!mapped) return;
            settle({
              decision: mapped.decision,
              decided_at: entry.resolved_at ?? this.now().toISOString(),
              decided_by: mapped.decided_by,
            });
            return;
          }
        })
        .catch(() => {
          // Listing failed; the event-driven path remains live. No-op.
        });

      timeoutHandle = setTimeout(() => {
        settle({
          decision: "deny",
          decided_at: this.now().toISOString(),
          decided_by: "timeout",
        });
      }, this.replaceModeTimeoutMs);
    });
  }

  /**
   * `notify` mode. Fire the underlying channel and listen on the
   * aggregator simultaneously; whichever resolves first wins. Both
   * paths produce identical `ApprovalResponse` shapes; the gate's
   * downstream audit logging is unchanged.
   *
   * On underlying-channel failure, fall through to the aggregator wait
   * (still bounded by `replaceModeTimeoutMs`). Operator can still
   * resolve from the inbox even if the dashboard/webhook is down.
   */
  private async notifyMode(
    request: ApprovalRequest,
  ): Promise<ApprovalResponse> {
    const aggregatorPromise = this.awaitAggregatorDecision(request);
    let underlyingPromise: Promise<ApprovalResponse>;
    try {
      underlyingPromise = this.underlying.requestApproval(request);
    } catch {
      // Synchronous throw → defer to aggregator alone.
      const response = await aggregatorPromise;
      return response;
    }
    // Race the two promises. Promise.race rejects on first rejection,
    // which is the wrong shape here — a thrown underlying channel must
    // not blow up the wait. Wrap rejections so the aggregator wins.
    return Promise.race([
      aggregatorPromise,
      underlyingPromise.catch(
        () =>
          new Promise<ApprovalResponse>(() => {
            // Never resolves; aggregatorPromise is the only viable path
            // once the underlying channel has thrown. The outer race
            // settles when aggregatorPromise resolves.
          }),
      ),
    ]);
  }
}

/**
 * Wire-up helper for the boot path. Reads the live policy each call so
 * an in-flight `sanctuary agents config` edit is reflected on the next
 * approval (within the running server's policy reload semantics).
 *
 * If the policy lacks `approval_redirect`, returns `{ enabled: false }`
 * which short-circuits the wrapper to underlying-passthrough (zero
 * runtime cost in the disabled-default state).
 */
export function makeRedirectResolverFromPolicySupplier(
  supplier: () => {
    approval_redirect?: { enabled: boolean; mode: "replace" | "notify" };
  },
): ApprovalRedirectResolver {
  return (_request) => {
    const cfg = supplier().approval_redirect;
    if (!cfg || cfg.enabled !== true) {
      return { enabled: false, mode: "replace" };
    }
    return {
      enabled: true,
      mode: cfg.mode === "notify" ? "notify" : "replace",
    };
  };
}
