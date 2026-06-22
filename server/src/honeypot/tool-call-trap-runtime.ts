/**
 * Sanctuary v1.3 WP-V1.3-5 Pi-3 Tool-call trap runtime.
 *
 * Server-local MCP catalog injection for fake honeypot tools. The
 * runtime reads deployed TrapSpecs from the per-fortress TrapRegistry,
 * injects visible tool_call traps into list_tools, and intercepts
 * calls to those fake tool names before regular tool dispatch.
 */

import { createHash, randomUUID } from "node:crypto";

import type { AuditLog } from "../operational/audit-log.js";
import type { SentinelFindingStore } from "../sentinel/sentinel-finding-store.js";
import type { SentinelFinding } from "../sentinel/types.js";
import type { ToolDefinition } from "../router.js";

import { TrapRegistry } from "./trap-registry.js";
import {
  HONEYPOT_AUDIT_OPS,
  honeypotSentinelId,
  type ToolCallTrigger,
  type TrapSpec,
} from "./types.js";

export interface ToolCallTrapRuntimeDeps {
  registry: TrapRegistry;
  findingStore: SentinelFindingStore;
  auditLog: AuditLog;
  operatorId: string;
  fortressId: string;
  now?: () => Date;
}

export interface ToolCallInvocation {
  trap_id: string;
  fake_tool_name: string;
  caller_identity: string;
  invocation_args: Record<string, unknown>;
  arg_hash: string;
  invoked_at: string;
  finding_id: string;
  fake_response: string | Record<string, unknown>;
  response_plausibility: "operator_configured_fake_response";
  follow_up_tool_calls: ToolCallFollowUp[];
}

export interface ToolCallFollowUp {
  tool_name: string;
  caller_identity: string;
  args: Record<string, unknown>;
  args_hash: string;
  called_at: string;
}

export interface ToolCallTrapStats {
  trap_id: string;
  fake_tool_name: string;
  catalog_visibility: ToolCallTrigger["catalog_visibility"];
  visible_to_agents?: string[];
  invocation_count: number;
  last_invocation_at: string | null;
  caller_diversity: number;
  activations: ToolCallInvocation[];
}

const FOLLOW_UP_WINDOW_MS = 5 * 60 * 1000;

export class ToolCallTrapRuntime {
  private readonly registry: TrapRegistry;
  private readonly findingStore: SentinelFindingStore;
  private readonly auditLog: AuditLog;
  private readonly operatorId: string;
  private readonly fortressId: string;
  private readonly now: () => Date;
  private readonly activations = new Map<string, ToolCallInvocation[]>();

  constructor(deps: ToolCallTrapRuntimeDeps) {
    this.registry = deps.registry;
    this.findingStore = deps.findingStore;
    this.auditLog = deps.auditLog;
    this.operatorId = deps.operatorId;
    this.fortressId = deps.fortressId;
    this.now = deps.now ?? (() => new Date());
  }

  listCatalogTools(agentId?: string): ToolDefinition[] {
    const tools: ToolDefinition[] = [];
    for (const spec of this.toolCallSpecs()) {
      const trigger = spec.trigger;
      if (!isVisibleToAgent(trigger, agentId)) continue;
      tools.push({
        name: trigger.fake_tool_name,
        description: trigger.fake_tool_description,
        inputSchema: trigger.fake_tool_schema,
        handler: async () => ({ content: [] }),
      });
    }
    return tools;
  }

  async invokeIfTrap(
    toolName: string,
    args: Record<string, unknown>,
    callerIdentity: string,
  ): Promise<{ handled: false } | { handled: true; response: unknown }> {
    const spec = this.toolCallSpecs().find(
      (candidate) => candidate.trigger.fake_tool_name === toolName,
    );
    if (!spec) return { handled: false };

    const trigger = spec.trigger;
    if (!isVisibleToAgent(trigger, callerAgentId(callerIdentity))) {
      return { handled: false };
    }

    const now = this.now();
    const argHash = hashJson(args);
    const findingId = randomUUID();
    const invocation: ToolCallInvocation = {
      trap_id: spec.trap_id,
      fake_tool_name: trigger.fake_tool_name,
      caller_identity: callerIdentity,
      invocation_args: args,
      arg_hash: argHash,
      invoked_at: now.toISOString(),
      finding_id: findingId,
      fake_response: trigger.fake_response,
      response_plausibility: "operator_configured_fake_response",
      follow_up_tool_calls: [],
    };
    const list = this.activations.get(spec.trap_id) ?? [];
    list.push(invocation);
    this.activations.set(spec.trap_id, list);

    const finding: SentinelFinding = {
      finding_id: findingId,
      sentinel_id: honeypotSentinelId(spec.trap_id),
      severity: spec.finding_severity,
      summary:
        `honeypot ${spec.trap_id} triggered: tool ${trigger.fake_tool_name} invoked by ${callerIdentity}`,
      details: {
        trap_id: spec.trap_id,
        trap_class: spec.trap_class,
        fake_tool_name: trigger.fake_tool_name,
        caller_identity: callerIdentity,
        invocation_args: args,
        arg_hash: argHash,
        response_plausibility: invocation.response_plausibility,
        follow_up_window_ms: FOLLOW_UP_WINDOW_MS,
        follow_up_tool_calls: invocation.follow_up_tool_calls,
      },
      observed_at: now.toISOString(),
      evidence_audit_ids: [],
      fortress_id: this.fortressId,
    };
    await this.findingStore.saveFinding(finding).catch(() => undefined);
    void this.auditLog.append("l2", HONEYPOT_AUDIT_OPS.TRIGGERED, this.operatorId, {
      fortress_id: this.fortressId,
      trap_id: spec.trap_id,
      trap_class: spec.trap_class,
      fake_tool_name: trigger.fake_tool_name,
      caller_identity: callerIdentity,
      invocation_args: args,
      arg_hash: argHash,
      finding_id: findingId,
      severity: spec.finding_severity,
      response_plausibility: invocation.response_plausibility,
      fake_response_hash: hashJson(trigger.fake_response),
      follow_up_window_ms: FOLLOW_UP_WINDOW_MS,
      follow_up_tool_calls: [],
    });

    return { handled: true, response: trigger.fake_response };
  }

  recordToolCall(
    toolName: string,
    args: Record<string, unknown>,
    callerIdentity: string,
  ): void {
    const now = this.now();
    for (const [trapId, invocations] of this.activations.entries()) {
      for (const activation of invocations) {
        if (activation.caller_identity !== callerIdentity) continue;
        const delta = now.getTime() - Date.parse(activation.invoked_at);
        if (delta < 0 || delta > FOLLOW_UP_WINDOW_MS) continue;
        const followUp: ToolCallFollowUp = {
          tool_name: toolName,
          caller_identity: callerIdentity,
          args,
          args_hash: hashJson(args),
          called_at: now.toISOString(),
        };
        activation.follow_up_tool_calls.push(followUp);
        void this.auditLog.append(
          "l2",
          HONEYPOT_AUDIT_OPS.FOLLOW_UP_CORRELATED,
          this.operatorId,
          {
            fortress_id: this.fortressId,
            trap_id: trapId,
            fake_tool_name: activation.fake_tool_name,
            caller_identity: callerIdentity,
            follow_up_tool_name: toolName,
            args_hash: followUp.args_hash,
            activation_at: activation.invoked_at,
            called_at: followUp.called_at,
          },
        );
      }
    }
  }

  stats(): ToolCallTrapStats[] {
    return this.toolCallSpecs().map((spec) => {
      const trigger = spec.trigger;
      const activations = [...(this.activations.get(spec.trap_id) ?? [])];
      const callers = new Set(activations.map((a) => a.caller_identity));
      const last = activations
        .map((a) => a.invoked_at)
        .sort()
        .at(-1) ?? null;
      return {
        trap_id: spec.trap_id,
        fake_tool_name: trigger.fake_tool_name,
        catalog_visibility: trigger.catalog_visibility,
        ...(trigger.visible_to_agents
          ? { visible_to_agents: [...trigger.visible_to_agents] }
          : {}),
        invocation_count: activations.length,
        last_invocation_at: last,
        caller_diversity: callers.size,
        activations,
      };
    });
  }

  private toolCallSpecs(): Array<TrapSpec & { trigger: ToolCallTrigger }> {
    return this.registry
      .list()
      .filter(
        (spec): spec is TrapSpec & { trigger: ToolCallTrigger } =>
          spec.trigger.kind === "tool_call",
      );
  }
}

function isVisibleToAgent(
  trigger: ToolCallTrigger,
  agentId: string | undefined,
): boolean {
  if (trigger.catalog_visibility === "all_wrapped_agents") return true;
  if (!agentId) return false;
  return (trigger.visible_to_agents ?? []).includes(agentId);
}

function callerAgentId(callerIdentity: string): string {
  return callerIdentity.startsWith("agent:")
    ? callerIdentity.slice("agent:".length)
    : callerIdentity;
}

function hashJson(value: unknown): string {
  return createHash("sha256")
    .update(JSON.stringify(value) ?? "null", "utf8")
    .digest("hex")
    .slice(0, 32);
}
