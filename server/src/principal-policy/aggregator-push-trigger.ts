/**
 * Sanctuary v1.3 WP-V1.3-10 Cross-Harness Approval Inbox Upsilon-4
 *
 * Push-notification trigger surface for the cross-harness approval
 * inbox. When a new aggregator entry is ingested, this module fires a
 * lightweight `PushEvent` to registered subscribers.
 *
 * Two subscription paths:
 *  - In-process: a callback handler receives the event directly. The
 *    v1.3 dashboard SSE pipeline subscribes through this path so
 *    desktop integrations get the same signal without paying for an
 *    outbound HTTP fan-out.
 *  - Webhook: an operator-configured URL receives a signed POST. v1.4
 *    mobile companions wire a hosted relay through this path. Webhooks
 *    are opt-in; the default zero-webhooks configuration is the
 *    no-outbound-by-default contract from CLAUDE.md.
 *
 * Castle-walking discipline:
 *  - Castle Layer 1 (Castle Wall): outbound webhook fires are subject
 *    to the kernel-level egress filter. The push trigger does not
 *    bypass any allow-list.
 *  - Castle Layer 3 (Cooperative MCP): the trigger is additive surface
 *    for compliant agents. A non-compliant or prompt-injected agent
 *    cannot register a webhook because no MCP tool exposes the
 *    registration; webhooks are operator-configured at process boot
 *    via the deps shape this module exports. The aggregator never
 *    fails on push fan-out failure (network drops are silent).
 *
 * No new outbound channel is introduced when zero webhooks are
 * registered. The signing path reuses HMAC-SHA256 from
 * `principal-policy/webhook.ts`'s `signPayload` shape.
 */

import { createHmac } from "node:crypto";

import type { ApprovalAggregator } from "./approval-aggregator.js";
import type { AggregatedApproval } from "./approval-aggregator.js";

/**
 * Maximum length of `action_summary` in the push event. Mirrors the
 * notification-body sizing typical of mobile push surfaces (APNs,
 * FCM): truncating to ~80 chars keeps the payload below platform
 * limits while preserving a recognizable summary.
 */
export const PUSH_EVENT_ACTION_SUMMARY_MAX_CHARS = 80;

/**
 * Lightweight event payload shipped to push subscribers. Carries the
 * minimum the v1.4 mobile companion needs to render a notification:
 * who triggered it, what action, how urgent. Full payload + audit
 * trail remain behind operator-authenticated routes.
 */
export interface PushEvent {
  aggregator_id: string;
  source_harness: string;
  source_agent_id: string;
  /** Operator-friendly one-line summary, truncated to PUSH_EVENT_ACTION_SUMMARY_MAX_CHARS. */
  action_summary: string;
  /**
   * Mapped from the entry's policy_rule_id. `tier1` for blocking
   * approval requests, `tier2` for behavioral-anomaly checks.
   * Undefined when the policy_rule_id does not name a tier.
   */
  urgency: "tier1" | "tier2" | "unknown";
  fortress_id: string;
  /** ISO 8601 timestamp at which this push event was produced. */
  emitted_at: string;
}

/** Outbound webhook subscription. */
export interface PushWebhookSubscription {
  url: string;
  /** Per-fortress shared secret used for HMAC-SHA256 signing. */
  secret: string;
}

/** Public view of a webhook subscription (no secret material). */
export interface PushWebhookSubscriptionPublic {
  url: string;
}

/**
 * Fetch implementation. Defaults to the global `fetch` available in
 * Node.js >= 18. Tests inject a stub.
 */
export type PushFetch = (
  url: string,
  init: { method: "POST"; headers: Record<string, string>; body: string },
) => Promise<unknown>;

export interface PushTriggerRegistryDeps {
  fortressId: string;
  /** Optional clock override for deterministic tests. */
  now?: () => Date;
  /**
   * Optional fetch override. Defaults to the global `fetch`. Tests
   * pass a stub that records calls without making real network
   * requests.
   */
  fetchImpl?: PushFetch;
}

/**
 * Subscriber registry + fan-out engine. Wired into an `ApprovalAggregator`
 * via `subscribeToAggregator()`; the aggregator's existing onEvent
 * hook drives `fire()` calls without the aggregator having to know
 * push exists.
 */
export class PushTriggerRegistry {
  private readonly fortressId: string;
  private readonly now: () => Date;
  private readonly fetchImpl: PushFetch;
  private readonly inProcess = new Set<(event: PushEvent) => void>();
  private readonly webhooks: PushWebhookSubscription[] = [];
  /** Track unsubscribe fns so the registry's own subscription is reversible. */
  private readonly aggregatorUnsubs = new Set<() => void>();

  constructor(deps: PushTriggerRegistryDeps) {
    this.fortressId = deps.fortressId;
    this.now = deps.now ?? (() => new Date());
    this.fetchImpl =
      deps.fetchImpl ??
      ((url, init) =>
        fetch(url, {
          method: init.method,
          headers: init.headers,
          body: init.body,
        }) as unknown as Promise<unknown>);
  }

  /**
   * Register an in-process event handler. Returns an unsubscribe fn.
   * The dashboard SSE pipeline subscribes through this path.
   */
  registerInProcess(handler: (event: PushEvent) => void): () => void {
    this.inProcess.add(handler);
    return () => this.inProcess.delete(handler);
  }

  /**
   * Register an outbound webhook. Operator-configured at server boot.
   * No MCP tool exposes this; the agent cannot self-register a
   * webhook. The default zero-webhooks state holds the
   * no-outbound-by-default contract.
   */
  registerWebhook(subscription: PushWebhookSubscription): void {
    if (subscription.url.length === 0 || subscription.secret.length === 0) {
      throw new Error(
        "push-trigger: webhook url and secret must be non-empty",
      );
    }
    this.webhooks.push({ url: subscription.url, secret: subscription.secret });
  }

  /**
   * Drop all registered webhooks. Used by `sanctuary lockdown` and
   * test setup.
   */
  unregisterAllWebhooks(): void {
    this.webhooks.length = 0;
  }

  /** Public view of registered webhooks (URLs only; no secrets). */
  listWebhooks(): PushWebhookSubscriptionPublic[] {
    return this.webhooks.map((wh) => ({ url: wh.url }));
  }

  /**
   * Wire the registry to an aggregator. Each `aggregated` event from
   * the aggregator fires a push trigger (deduplicated entries do not
   * fire; resolved/removed events do not fire either, since mobile
   * notifications are about new pending approvals).
   *
   * Returns an unsubscribe fn that severs the wiring without affecting
   * other subscribers.
   */
  subscribeToAggregator(aggregator: ApprovalAggregator): () => void {
    const unsubscribe = aggregator.onEvent((event) => {
      if (event.type !== "aggregated") return;
      void this.fire(this.eventFromEntry(event.entry));
    });
    this.aggregatorUnsubs.add(unsubscribe);
    return () => {
      unsubscribe();
      this.aggregatorUnsubs.delete(unsubscribe);
    };
  }

  /**
   * Fire a push event to all subscribers. In-process handlers run
   * synchronously inside try/catch (a broken handler never fails the
   * fan-out). Webhooks fan out concurrently; per-webhook failures are
   * caught and dropped (network drops never block the aggregator).
   */
  async fire(event: PushEvent): Promise<void> {
    for (const handler of this.inProcess) {
      try {
        handler(event);
      } catch {
        // In-process handler exceptions never fail the trigger.
      }
    }
    if (this.webhooks.length === 0) return;
    const body = JSON.stringify(event);
    await Promise.all(
      this.webhooks.map(async (wh) => {
        const signature = signHmacSha256Hex(body, wh.secret);
        try {
          await this.fetchImpl(wh.url, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-Sanctuary-Signature": signature,
              "X-Sanctuary-Event": "cross_harness_approval_aggregated",
            },
            body,
          });
        } catch {
          // Network failure is non-fatal: the inbox UI remains the
          // source of truth; mobile re-syncs via /sync on next poll.
        }
      }),
    );
  }

  /**
   * Pure helper exposed for tests + for callers that want to derive a
   * PushEvent from an aggregator entry without firing.
   */
  eventFromEntry(entry: AggregatedApproval): PushEvent {
    return {
      aggregator_id: entry.aggregator_id,
      source_harness: entry.source_harness,
      source_agent_id: entry.source_agent_id,
      action_summary: truncateSummary(entry.action_summary),
      urgency: urgencyFromPolicyRuleId(entry.policy_rule_id),
      fortress_id: this.fortressId,
      emitted_at: this.now().toISOString(),
    };
  }
}

function truncateSummary(summary: string): string {
  if (summary.length <= PUSH_EVENT_ACTION_SUMMARY_MAX_CHARS) return summary;
  return `${summary.slice(0, PUSH_EVENT_ACTION_SUMMARY_MAX_CHARS - 3)}...`;
}

function urgencyFromPolicyRuleId(
  policyRuleId: string,
): "tier1" | "tier2" | "unknown" {
  if (policyRuleId.startsWith("tier1")) return "tier1";
  if (policyRuleId.startsWith("tier2")) return "tier2";
  return "unknown";
}

/**
 * HMAC-SHA256 hex signature. Mirrors `signPayload` in
 * `principal-policy/webhook.ts` so operator tooling that already
 * handles approval-channel webhook signatures can verify push
 * notifications with the same code.
 */
export function signHmacSha256Hex(body: string, secret: string): string {
  return createHmac("sha256", secret).update(body).digest("hex");
}
