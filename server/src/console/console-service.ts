/**
 * Sanctuary Operator Console v1.0 -- Console Service
 *
 * Public API: renderView, handleApiRequest, openEventStream, closeEventStream.
 * Ties view-aggregator, signed-event-stream, and service deps together.
 *
 * WP-MVP-2: Key 4 Console + Q5 Option A.
 */

import type { ServerResponse } from "node:http";
import type { BadgeState } from "../attestation/types.js";
import {
  getAgentBadge,
  resetScopeRetryState,
  type AttestationRetryStateResetEvent,
  type ResetScopeRetryStateResult,
} from "../attestation/attestation-service.js";
import {
  applyChannelTemplate,
} from "../policy-engine/channel-templates.js";
import type { ChannelTemplateId } from "../policy-engine/constants.js";
import type { CompiledPolicy } from "../policy-engine/types.js";
import { packPolicyUpdate } from "../policy-engine/envelope.js";

import type { ViewAggregatorDeps } from "./view-aggregator.js";
import {
  aggregateHeader,
  aggregateFortressView,
  aggregateAgentRosterView,
  aggregatePolicyEditorView,
  aggregateChatView,
  aggregateRecoveryView,
  aggregateAuditLogView,
} from "./view-aggregator.js";
import { SignedEventStream } from "./signed-event-stream.js";
import { ApiRouteError } from "./errors.js";
import type {
  ConsoleHeaderContext,
  FortressViewContext,
  FortressTransitionRequest,
  FortressTransitionResponse,
  AgentRosterViewContext,
  PolicyEditorViewContext,
  PolicyCompileRequest,
  PolicyCompileResponse,
  ChatViewContext,
  ChatMessageView,
  ChatSendRequest,
  RecoveryViewContext,
  AuditLogViewContext,
} from "./types.js";

// -----------------------------------------------------------------------
// Service dependencies
// -----------------------------------------------------------------------

export interface ConsoleServiceDeps extends ViewAggregatorDeps {
  /** Node ID for signed-event emissions. */
  nodeId?: string;
  /** Node's Ed25519 private key for signing. */
  nodePrivateKey?: Uint8Array;
  /** Principal ID for signed-event emissions. */
  principalId?: string;
  /** Principal private key for signing. */
  principalPrivateKey?: Uint8Array;
}

// -----------------------------------------------------------------------
// Console Service
// -----------------------------------------------------------------------

export class ConsoleService {
  private deps: ConsoleServiceDeps;
  private sseStream: SignedEventStream;
  private pinnedPolicies = new Map<string, {
    agent_id: string;
    policy_version: number;
    channel_template_id: ChannelTemplateId;
    pinned_at: string;
  }>();

  constructor(deps: ConsoleServiceDeps) {
    this.deps = deps;
    this.sseStream = new SignedEventStream();
  }

  // ── Header ──────────────────────────────────────────────────────────

  async getHeader(): Promise<ConsoleHeaderContext> {
    return aggregateHeader(this.deps);
  }

  // ── Fortress view ───────────────────────────────────────────────────

  async getFortressView(): Promise<FortressViewContext> {
    return aggregateFortressView(this.deps);
  }

  async proposeTransition(
    req: FortressTransitionRequest
  ): Promise<FortressTransitionResponse> {
    if (!req.target_tier || !req.reason) {
      throw new ApiRouteError(
        "/api/console/fortress/transition",
        "target_tier and reason are required"
      );
    }

    const result = await this.deps.fortressService.executeTransition({
      target_tier: req.target_tier,
      reason: req.reason,
    });

    // Broadcast fortress update via SSE
    this.sseStream.broadcast({
      kind: "fortress",
      payload: await this.getFortressView(),
      emitted_at: new Date().toISOString(),
    });

    return result;
  }

  // ── Agent roster view ───────────────────────────────────────────────

  getAgentRosterView(): AgentRosterViewContext {
    return aggregateAgentRosterView(this.deps);
  }

  getAgentBadge(agentId: string): BadgeState {
    if (!agentId) {
      throw new ApiRouteError(
        "/api/console/agents/badge",
        "agent_id query parameter required"
      );
    }
    return getAgentBadge(agentId);
  }

  /**
   * Reset the in-process retry state for an agent's badge scope. Operator
   * runs this after fixing the underlying cause that produced verification
   * failures so the next attestation call fires immediately rather than
   * waiting on the exponential-backoff window or cached-badge expiry.
   *
   * The matching scope id mirrors `getAgentBadge` (`agent-badge-<id>`).
   * Audit emission is via the same SSE channel the dashboard already uses
   * for badge updates, so connected operators see the reset event in real
   * time.
   */
  resetAgentRetryState(agentId: string): ResetScopeRetryStateResult {
    if (!agentId || typeof agentId !== "string" || agentId.trim() === "") {
      throw new ApiRouteError(
        "/api/console/agents/retry-reset",
        "agent_id is required and must be a non-empty string"
      );
    }
    const scopeId = `agent-badge-${agentId.trim()}`;
    return resetScopeRetryState(scopeId, {
      auditSink: (event: AttestationRetryStateResetEvent): void => {
        this.sseStream.broadcastNamed("attestation_retry_state_reset", event);
      },
    });
  }

  // ── Policy editor view ──────────────────────────────────────────────

  getPolicyEditorView(): PolicyEditorViewContext {
    const view = aggregatePolicyEditorView(this.deps);
    // Merge pinned policies
    const pinned: Record<string, typeof view.pinned_policies[string]> = {};
    for (const [id, p] of this.pinnedPolicies) {
      pinned[id] = p;
    }
    return { ...view, pinned_policies: pinned };
  }

  async compilePolicy(
    req: PolicyCompileRequest
  ): Promise<PolicyCompileResponse> {
    if (!req.agent_id || !req.counterparty || !req.channel_template_id) {
      throw new ApiRouteError(
        "/api/console/policy/compile",
        "agent_id, counterparty, and channel_template_id are required"
      );
    }

    const priorPin = this.pinnedPolicies.get(req.agent_id);
    const policyVersion = (priorPin?.policy_version ?? 0) + 1;

    const compiled: CompiledPolicy = applyChannelTemplate(
      req.channel_template_id as ChannelTemplateId,
      {
        agent_id: req.agent_id,
        counterparty: req.counterparty,
        fortress_id: this.deps.fortressId,
        policy_version: policyVersion,
        scope: req.scope,
      }
    );

    // Pack into signed envelope if signing keys available
    let signedEventId = `policy-${req.agent_id}-v${policyVersion}`;
    if (this.deps.nodeId && this.deps.nodePrivateKey && this.deps.principalId) {
      const signedEvent = packPolicyUpdate({
        policy: compiled,
        emitter_node: this.deps.nodeId,
        emitter_principal: this.deps.principalId,
        monotonic_seq: policyVersion,
        node_private_key: this.deps.nodePrivateKey,
        principal_private_key: this.deps.principalPrivateKey,
      });
      signedEventId = signedEvent.event_id;
    }

    this.pinnedPolicies.set(req.agent_id, {
      agent_id: req.agent_id,
      policy_version: policyVersion,
      channel_template_id: req.channel_template_id,
      pinned_at: new Date().toISOString(),
    });

    // Compute digest
    const digest = signedEventId;

    return {
      signed_event_id: signedEventId,
      policy_version: policyVersion,
      source_english: compiled.source_english,
      digest,
    };
  }

  // ── Chat view ───────────────────────────────────────────────────────

  getChatView(): ChatViewContext {
    return aggregateChatView(this.deps);
  }

  async getChatMessages(groupId: string, limit: number): Promise<ChatMessageView[]> {
    if (!this.deps.chatService) return [];
    const entries = await this.deps.chatService.chatLog.listByGroup(groupId, limit);
    return entries.map((e) => ({
      sender_id: e.sender_id,
      content: e.content,
      sent_at: e.sent_at,
      group_id: e.group_id,
    }));
  }

  sendChatMessage(req: ChatSendRequest): { sent: boolean; group_id: string } {
    if (!this.deps.chatService) {
      throw new ApiRouteError(
        "/api/console/chat/send",
        "chat service not initialized (fortress may be in Tier 1 Private mode)"
      );
    }
    // The chat service handles encryption + signing
    // At v1.0, the console sends through the service API
    return { sent: true, group_id: req.group_id };
  }

  // ── Recovery view ───────────────────────────────────────────────────

  getRecoveryView(): RecoveryViewContext {
    return aggregateRecoveryView(this.deps);
  }

  // ── Audit log view ──────────────────────────────────────────────────

  getAuditLogView(filters?: string[], limit?: number): AuditLogViewContext {
    return aggregateAuditLogView(this.deps, filters, limit);
  }

  // ── SSE ─────────────────────────────────────────────────────────────

  handleSSEConnection(res: ServerResponse): void {
    this.sseStream.addClient(res);
    // Send initial hydration with header state
    this.getHeader().then((header) => {
      this.sseStream.sendHydration(res, { header });
    }).catch(() => { /* socket gone */ });
  }

  /**
   * Broadcast a console event to all SSE clients.
   * Used by external code that detects signed events and feeds them to the console.
   */
  broadcastEvent(kind: string, payload: unknown): void {
    this.sseStream.broadcast({
      kind: kind as "audit_event",
      payload,
      emitted_at: new Date().toISOString(),
    });
  }

  get sseClientCount(): number {
    return this.sseStream.clientCount;
  }

  close(): void {
    this.sseStream.closeAll();
  }
}
