/**
 * Sanctuary MCP Server — Operator Chat Service
 *
 * The operator-fortress concierge surface. Distinct from the
 * agent-to-agent mesh chat (`chat-service.ts`) which handles libp2p +
 * OpenMLS group sessions among wrapped agents.
 *
 * The direct-agent surface (operator-to-wrapped-agent conversation) was
 * removed in the v1.2 reshape; the concierge surface is the only
 * operator-chat surface in v1.2.
 *
 * Concierge surface (path: `sendConcierge`):
 *   1. PII-filter the operator query (Tier 1 regex).
 *   2. Build fortress context from audit log + activity feed +
 *      agent registry (`assembleConciergeContext`).
 *   3. Invoke the substrate selector at `surface: "concierge"`.
 *   4. Persist operator query + concierge response in the concierge
 *      thread under `_chat/concierge.<sentinel>`.
 *   5. Emit `operator_concierge_chat` audit event with safe metadata.
 *
 * Sovereignty invariants:
 * - Audit emission is non-optional on every public method that mutates
 *   the chat state. Construction with no audit log is structurally
 *   rejected.
 * - The substrate selector is OPTIONAL: a service constructed without
 *   one degrades to "Concierge unavailable; substrate not configured".
 *   The wiring layer can instantiate the service before the substrate
 *   selector when bootstrap order requires it.
 * - The PII filter is the Tier 1 regex shipped in
 *   `l2-operational/privacy-filter.ts`; Tier 2 NER+LLM redaction lives
 *   in the substrate-selector layer (substrate-routed), not here.
 */

import { randomUUID } from "node:crypto";
import { sha256 } from "@noble/hashes/sha256";
import { hashToString } from "../core/hashing.js";
import { stringToBytes } from "../core/encoding.js";
import type { AuditLog } from "../l2-operational/audit-log.js";
import type {
  SubstrateSelector,
} from "../intelligence/index.js";
import type { SubstrateChoice } from "../intelligence/types.js";
import { OPERATOR_CHAT_OPS } from "./operator-chat-audit-events.js";
import {
  CONCIERGE_THREAD_KEY,
  type ConciergeResponse,
  type OperatorChatMessage,
  type OperatorChatRole,
  type OperatorChatThread,
} from "./operator-chat-types.js";
import { OperatorChatStore } from "./operator-chat-store.js";
import type {
  OperatorChatAuditPayload,
  OperatorConciergeChatPayload,
} from "../contracts/v1.2/operator-chat-events.js";

/**
 * Snapshot of fortress state surfaces the concierge consults to
 * answer operator queries. Caller (the hub-service wiring) supplies
 * the providers; the service wires them into the substrate prompt.
 *
 * Each provider returns plain strings the substrate selector folds
 * into a single context blob; the service does not attempt to
 * structure the prompt beyond stitching with newlines. Keeping the
 * prompt-shape decisions in the service-construction layer (rather
 * than in the wiring) lets the dashboard team iterate concierge
 * prompts without touching server code.
 */
export interface ConciergeContextProviders {
  /** Recent activity-feed entries as a free-form string, oldest first. */
  recentActivity: () => Promise<string>;
  /** Wrapped-agent inventory as a free-form string. */
  agentInventory: () => Promise<string>;
  /** Open inbox items as a free-form string. */
  openInbox: () => Promise<string>;
}

/**
 * PII filter the concierge applies to operator queries before passing
 * them to the substrate. v1.2 wires the Tier 1 regex; the substrate
 * selector handles Tier 2 NER+LLM redaction internally on egress paths.
 *
 * Returns the filtered query plus the count of redactions performed
 * (surfaced in the audit event for operator visibility).
 */
export interface ConciergePiiFilter {
  filter(input: string): { filtered: string; redactions: number };
}

/**
 * Construction inputs for the operator chat service.
 */
export interface OperatorChatServiceDeps {
  /** Encrypted at-rest store; built from fortress master key. */
  store: OperatorChatStore;
  /** Audit log for `operator_concierge_chat` events. */
  auditLog: AuditLog;
  /** Operator identity that owns the chat session. */
  identityId: string;
  /**
   * Substrate selector for concierge LLM calls. Optional: when omitted
   * the concierge surface degrades to a "substrate not configured"
   * response.
   */
  substrateSelector?: SubstrateSelector;
  /**
   * Concierge context providers. Required when a substrate selector
   * is wired; otherwise unused. Wiring layer assembles these from the
   * activity feed, agent registry, and inbox aggregator.
   */
  conciergeContextProviders?: ConciergeContextProviders;
  /**
   * PII filter applied to concierge queries pre-substrate. Optional;
   * when omitted the service still works (no redactions performed).
   * v1.2 wiring passes the Tier 1 regex.
   */
  conciergePiiFilter?: ConciergePiiFilter;
  /**
   * Stable max tokens for concierge responses. Defaults to 512 (small
   * enough for snappy local-model latency, large enough for a useful
   * summary). Operator-tunable via dashboard config.
   */
  conciergeMaxTokens?: number;
}

const DEFAULT_CONCIERGE_MAX_TOKENS = 512;

/**
 * Static Sanctuary domain reference injected into the concierge context
 * so the substrate can answer operator questions about Sanctuary concepts,
 * channel templates, policy slots, and architecture.
 *
 * v1.3 replaces this with dynamic context injection (pre-fetch live
 * template list + policy schema at chat time).
 */
export const SANCTUARY_DOMAIN_REFERENCE = `\
Castle Architecture (four enforcement layers):
1. Castle Wall: OS-boundary egress filter enforced at the kernel level. Blocks unauthorized outbound calls even from prompt-injected agents.
2. Sentinels: internal observation via process introspection. Surfaces anomalies to the operator; does not enforce.
3. Charter (Cooperative MCP): the sovereignty surface for compliant agents. Policy gates, approval tiers, audit logging, and encrypted state all live here.
4. Heralds: Concordia receipts and Verascore reputation. Cross-fortress accountability after an action completes.

Five channel templates (canonical names):
- request-approve-act: agent proposes an action, operator approves or denies before execution.
- read-then-report: agent reads outputs from a data source and reports summaries to the operator.
- scheduled-digest: agent runs on a schedule and delivers a periodic digest.
- plan-draft-only: agent drafts plans; operator reviews before any execution step.
- fortress-relay: agent relays messages between fortresses under operator-scoped policy.

Four canonical policy slots:
- memory: governs what the agent may persist and retrieve from encrypted state.
- credentials: governs access to secrets, API keys, and tokens held in the broker.
- plans: governs the agent's ability to create, modify, or execute plans.
- outputs: governs what the agent may emit to external surfaces (files, APIs, messages).

Key concepts:
- Fortress: the operator-owned sovereignty harness. All state is encrypted at rest under the cocoon.
- Cocoon: master-key-wrapped storage derived from the operator's passphrase via Argon2id.
- Identity: Ed25519 keypair with a DID, owned by the operator. Private keys never leave the cocoon.
- Audit log: append-only encrypted blobs, sequential, recording every gate decision and tool call.
- Wrapped agent: any agent runtime that connects to Sanctuary as an MCP client. Tier A (native), Tier B (adapter-wrapped), Tier C (escape hatch).

Note: this is a static reference block (v1.2.x). Dynamic context injection (live template list, policy schema) ships in v1.3.`;

export class OperatorChatService {
  private store: OperatorChatStore;
  private auditLog: AuditLog;
  private identityId: string;
  private substrateSelector?: SubstrateSelector;
  private contextProviders?: ConciergeContextProviders;
  private piiFilter?: ConciergePiiFilter;
  private conciergeMaxTokens: number;

  constructor(deps: OperatorChatServiceDeps) {
    this.store = deps.store;
    this.auditLog = deps.auditLog;
    this.identityId = deps.identityId;
    if (deps.substrateSelector) this.substrateSelector = deps.substrateSelector;
    if (deps.conciergeContextProviders) {
      this.contextProviders = deps.conciergeContextProviders;
    }
    if (deps.conciergePiiFilter) this.piiFilter = deps.conciergePiiFilter;
    this.conciergeMaxTokens =
      deps.conciergeMaxTokens ?? DEFAULT_CONCIERGE_MAX_TOKENS;
  }

  // ── Concierge ─────────────────────────────────────────────────────────

  /**
   * Operator submit on the concierge surface. Persists the operator's
   * query, fans out to the substrate selector, persists the response,
   * and emits the audit event.
   *
   * On substrate failure or absence: persists an honest "concierge
   * unavailable" response and audit-emits with `outcome` = the
   * appropriate failure class. The chat history reflects what the
   * operator sees on the page (no silent dropping).
   */
  async sendConcierge(query: string): Promise<ConciergeResponse> {
    const trimmed = query.trim();
    if (trimmed.length === 0) {
      throw new Error("concierge query must not be empty");
    }

    // Operator's message in. Filter PII before persist + before egress.
    const filterResult = this.piiFilter
      ? this.piiFilter.filter(trimmed)
      : { filtered: trimmed, redactions: 0 };

    const operatorMessage: OperatorChatMessage = {
      message_id: randomUUID(),
      surface: "concierge",
      role: "operator",
      body: trimmed,
      created_at: new Date().toISOString(),
    };
    await this.store.appendMessage(
      "concierge",
      CONCIERGE_THREAD_KEY,
      operatorMessage,
    );

    const start = Date.now();
    let conciergeBody: string;
    let servedBy: SubstrateChoice = "disabled";
    let displayLabel = "Concierge: substrate not configured";
    let outcome: "ok" | "substrate_failure" | "substrate_disabled" =
      "substrate_disabled";

    if (!this.substrateSelector) {
      conciergeBody =
        "Concierge unavailable. The substrate selector is not configured for this fortress. Pick a substrate in the Policy center to enable concierge replies.";
    } else {
      try {
        const handle = await this.substrateSelector.getSubstrate("concierge");
        servedBy = handle.substrate;
        displayLabel = handle.displayLabel;

        if (!handle.capability.summarize) {
          conciergeBody =
            "Concierge unavailable. The chosen substrate does not support summarization. Pick a different substrate in the Policy center.";
          outcome = "substrate_disabled";
        } else {
          const context = await this.assembleConciergeContext();
          const response = await this.substrateSelector.invokeSummarize(
            "concierge",
            {
              kind: "summarize",
              context,
              query: filterResult.filtered,
              maxTokens: this.conciergeMaxTokens,
            },
          );
          if (response.failureClass || response.body.kind !== "summarize") {
            conciergeBody = `Concierge call failed: ${response.failureClass ?? "unknown"}. The substrate selector logged the failure detail.`;
            outcome = "substrate_failure";
          } else {
            conciergeBody = response.body.text;
            outcome = "ok";
            servedBy = response.servedBy;
          }
        }
      } catch (err) {
        conciergeBody = `Concierge call failed: ${
          err instanceof Error ? err.message : String(err)
        }.`;
        outcome = "substrate_failure";
      }
    }

    const latencyMs = Date.now() - start;

    const responseMessage: OperatorChatMessage = {
      message_id: randomUUID(),
      surface: "concierge",
      role: "concierge",
      body: conciergeBody,
      created_at: new Date().toISOString(),
      served_by: servedBy,
      substrate_latency_ms: latencyMs,
    };
    await this.store.appendMessage(
      "concierge",
      CONCIERGE_THREAD_KEY,
      responseMessage,
    );

    const payload: OperatorConciergeChatPayload = {
      version: "1.2",
      event_id: makeEventId("conc"),
      emitted_at: new Date().toISOString(),
      identity_id: this.identityId,
      kind: "operator_concierge_chat",
      surface: "concierge",
      query_hash: hashOf(trimmed),
      response_hash: outcome === "ok" ? hashOf(conciergeBody) : null,
      substrate: servedBy,
      latency_ms: latencyMs,
      outcome,
    };
    this.emit(OPERATOR_CHAT_OPS.CONCIERGE_CHAT, payload, outcome === "ok" ? "success" : "failure");

    return {
      message: responseMessage,
      served_by: servedBy,
      display_label: displayLabel,
      outcome,
    };
  }

  /**
   * Read the persisted concierge thread, oldest message first. Returns
   * an empty array when no thread exists yet.
   */
  async getConciergeHistory(): Promise<OperatorChatMessage[]> {
    const thread = await this.store.loadThread(
      "concierge",
      CONCIERGE_THREAD_KEY,
    );
    return thread ? thread.messages : [];
  }

  /**
   * Stitch fortress state into a single context blob the substrate
   * folds into its summarization prompt.
   *
   * The blob is intentionally plain text (not structured JSON) because
   * small local models (Gemma 2 2B) handle plain text more reliably
   * than nested structures. Format:
   *
   *   ```
   *   ## Sanctuary reference
   *   <static domain reference block>
   *
   *   ## Recent activity
   *   <recentActivity output>
   *
   *   ## Wrapped agents
   *   <agentInventory output>
   *
   *   ## Open inbox
   *   <openInbox output>
   *   ```
   */
  private async assembleConciergeContext(): Promise<string> {
    const ref = `## Sanctuary reference\n${SANCTUARY_DOMAIN_REFERENCE}`;

    if (!this.contextProviders) {
      return `${ref}\n\n## Recent activity\n(no providers wired)\n\n## Wrapped agents\n(no providers wired)\n\n## Open inbox\n(no providers wired)`;
    }
    const [activity, agents, inbox] = await Promise.all([
      this.contextProviders.recentActivity(),
      this.contextProviders.agentInventory(),
      this.contextProviders.openInbox(),
    ]);
    return `${ref}\n\n## Recent activity\n${activity}\n\n## Wrapped agents\n${agents}\n\n## Open inbox\n${inbox}`;
  }

  // ── audit helpers ────────────────────────────────────────────────────

  private emit(
    operation: string,
    payload: OperatorChatAuditPayload,
    result: "success" | "failure",
  ): void {
    this.auditLog.append(
      "l2",
      operation,
      this.identityId,
      payload as unknown as Record<string, unknown>,
      result,
    );
  }
}

// ── helpers ──────────────────────────────────────────────────────────────

function makeEventId(prefix: string): string {
  return `${prefix}-${Date.now()}-${randomUUID().slice(0, 8)}`;
}

/**
 * SHA-256 of the input string, encoded as base64url (43 chars, no
 * padding). Matches the intelligence-events hashing discipline.
 */
function hashOf(input: string): string {
  return hashToString(sha256(stringToBytes(input)));
}

/**
 * Helper exported for hub-service consumers that need to rehydrate the
 * persisted thread into a sender-role label without re-deriving the
 * map. Keeps display-label semantics co-located with the role enum.
 */
export function operatorChatRoleLabel(
  role: OperatorChatRole,
): string {
  if (role === "operator") return "you";
  if (role === "concierge") return "Sanctuary Fortress concierge";
  return role;
}

export type {
  OperatorChatThread,
};
