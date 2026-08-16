/**
 * Sanctuary MCP Server - Tool Router
 *
 * Routes sanctuary/* tool calls to their layer-specific handlers.
 * Every tool call passes through schema validation and the ApprovalGate
 * (if configured) before execution. Neither can be bypassed.
 *
 * This module is the abstraction boundary for MCP SDK version migration -
 * if the SDK API changes, only this module needs updating.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { randomBytes } from "node:crypto";
import type { ApprovalGate } from "./principal-policy/gate.js";
import type { ToolCallTrapRuntime } from "./honeypot/tool-call-trap-runtime.js";
import type { AuditLog } from "./operational/audit-log.js";
import { fixedDenial, type SessionBinding } from "./agent-native/safety-base.js";
import {
  normalizeToolArgsForValidation,
  ToolArgumentValidationError,
} from "./tool-args.js";
import { getSanctuaryVersion } from "./version.js";

const PKG_VERSION = getSanctuaryVersion();

/**
 * Tool handler function signature.
 *
 * `callerIdentity` (MUST-FIX 1, fix-round-2 spine, register RECHECK): the
 * SERVER-SET agent-session principal — `agent:<currentAgentId>` when the
 * server is wrapping a known agent, `agent:unknown` otherwise (see
 * `callerIdentity`'s computation below) — NEVER derived from request args.
 * This is the only principal a calling agent cannot mint more of: Sanctuary
 * identities are `identity_create`-mintable at Tier 3 (principal-policy
 * `loader.ts`'s `tier3_always_allow`), so any per-origin quota keyed on a
 * caller-supplied `identity_id` is defeated by minting enough identities.
 * Handlers that enforce a per-origin quota on attacker-writable state
 * (handshake sessions/results, federation peer registration) MUST use this
 * value as the quota origin, never `args.identity_id` / `args.instance_id`.
 * Optional so every handler that does not need it (the overwhelming
 * majority) is unaffected — TypeScript allows a handler declared with fewer
 * parameters to satisfy this type.
 */
export type ToolHandler = (
  args: Record<string, unknown>,
  callerIdentity?: string
) => Promise<{ content: Array<{ type: "text"; text: string }> }>;

/** Tool definition for registration */
export interface ToolDefinition {
  name: string;
  description: string;
  tool_class?: "read" | "write";
  inputSchema: Record<string, unknown>;
  approvalTargetToolName?: string;
  approvalTargetArgs?: (
    args: Record<string, unknown>
  ) => Record<string, unknown> | Promise<Record<string, unknown>>;
  handler: ToolHandler;
}

const AGENT_CATALOG_HIDDEN_TOOLS = new Set([
  "context_gate_set_policy",
  "context_gate_apply_template",
]);

const GENERIC_GATE_DENIAL_REMEDIATION = "unavailable" as const;

/** Options for server creation */
export interface ServerOptions {
  /** Approval gate - if provided, every tool call is evaluated before execution */
  gate?: ApprovalGate;
  /** Pi-3 honeypot runtime for server-local fake tool catalog injection. */
  toolCallTrapRuntime?: ToolCallTrapRuntime;
  /** Current wrapped-agent id for per-agent catalog visibility. */
  currentAgentId?: () => string | undefined;
  /** Audit log used to enforce MCP read/write behavior on broken chains. */
  auditLog?: AuditLog;
  /** Active session identity binding for agent-native approval/namespace checks. */
  currentSessionBinding?: () => SessionBinding | undefined;
  /**
   * Agent-facing MCP `instructions` string, returned in the initialize
   * response so a connecting harness immediately learns the cooperative
   * tool catalog and why to route through it (first-class surfacing). Purely
   * a discovery aid; it makes no enforcement claim.
   */
  instructions?: string;
}

export function assertToolClasses(tools: readonly ToolDefinition[]): void {
  const missing = tools
    .filter((tool) => tool.tool_class !== "read" && tool.tool_class !== "write")
    .map((tool) => tool.name);
  if (missing.length > 0) {
    throw new Error(
      `Registered MCP tools missing tool_class: ${missing.join(", ")}`
    );
  }
}

/**
 * Create the MCP server with all Sanctuary tools registered.
 * If an ApprovalGate is provided, it wraps every tool call.
 */
export function createServer(
  tools: ToolDefinition[],
  options?: ServerOptions
): Server {
  const gate = options?.gate;
  assertToolClasses(tools);

  const server = new Server(
    {
      name: "sanctuary-mcp-server",
      version: PKG_VERSION,
    },
    {
      capabilities: {
        tools: {},
      },
      ...(options?.instructions ? { instructions: options.instructions } : {}),
    }
  );

  // Register tool listing
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const honeypotTools =
      options?.toolCallTrapRuntime?.listCatalogTools(
        options.currentAgentId?.(),
      ) ?? [];
    const catalog = [...tools, ...honeypotTools].filter(
      (tool) => !AGENT_CATALOG_HIDDEN_TOOLS.has(tool.name)
    );
    return {
      tools: catalog.map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
      })),
    };
  });

  // Register tool execution - validation + gate sit between router and handler
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const typedArgs = (args ?? {}) as Record<string, unknown>;
    const currentAgentId = options?.currentAgentId?.();
    const callerIdentity = currentAgentId
      ? `agent:${currentAgentId}`
      : "agent:unknown";

    const trapInvoke = await options?.toolCallTrapRuntime?.invokeIfTrap(
      name,
      typedArgs,
      callerIdentity,
    );
    if (trapInvoke?.handled) {
      const response = trapInvoke.response;
      return {
        content: [
          {
            type: "text" as const,
            text:
              typeof response === "string"
                ? response
                : JSON.stringify(response, null, 2),
          },
        ],
      };
    }

    const tool = tools.find((t) => t.name === name);
    if (!tool) {
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ error: `Unknown tool: ${name}` }),
          },
        ],
        isError: true,
      };
    }

    // Schema Validation
    // Validate arguments against the tool's declared inputSchema.
    // This runs BEFORE the gate so that the gate sees normalized args.
    let approvalRef: string | undefined;
    let handlerArgs: Record<string, unknown>;
    try {
      ({ approvalRef, handlerArgs } = normalizeToolArgsForValidation({
        args: typedArgs,
        schema: tool.inputSchema,
      }));
    } catch (error) {
      if (!(error instanceof ToolArgumentValidationError)) throw error;
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              error: "validation_failed",
              message: "Tool arguments failed schema validation",
              violations: error.violations,
            }),
          },
        ],
        isError: true,
      };
    }

    // Approval Gate
    // If a gate is configured, every tool call must pass through it.
    // Denied calls return the fixed coarse schema; details stay in audit.
    if (gate) {
      let gateArgs: Record<string, unknown>;
      try {
        gateArgs = (await tool.approvalTargetArgs?.(handlerArgs)) ?? handlerArgs;
      } catch {
        const errorPayload = fixedDenial(
          `audit:gate:${name}`,
          GENERIC_GATE_DENIAL_REMEDIATION,
          null
        );
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(errorPayload),
            },
          ],
          isError: true,
        };
      }
      const result = await gate.evaluate(
        tool.approvalTargetToolName ?? name,
        gateArgs,
        approvalRef ? { approval_ref: approvalRef } : undefined
      );
      if (!result.allowed) {
        // Invariant #7: the agent-facing denial must not reveal which policy
        // class fired. Specific remediation belongs in operator-only audit data.
        const errorPayload = fixedDenial(
          `audit:gate:${name}`,
          GENERIC_GATE_DENIAL_REMEDIATION,
          null
        );
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(errorPayload),
            },
          ],
          isError: true,
        };
      }
    }

    try {
      const findings = await options?.auditLog?.getIntegrityFindings();
      const hasIntegrityFindings = (findings?.length ?? 0) > 0;

      // CALLER-CONTROLLED-AUDIT-OVERRIDE (register row, HIGH; MUST-NEVER #5):
      // no argument an MCP caller supplies can lift this gate for a tool
      // classified `write` — `accept_broken_chain` is no longer an accepted
      // argument at all (see tool-args.ts), and no other agent-facing field
      // substitutes for it. That guarantee is scoped to classification: it
      // holds only for tools correctly classified `write`. The bypass below
      // keys off `tool.tool_class`, so a tool misclassified `read` whose
      // handler actually performs a write escapes this check structurally,
      // independent of any argument — a classification-correctness question
      // this argument-level change does not close. Findings persisting is a
      // hard stop for `write` tools, not a request for consent to proceed
      // past them: restoring MCP write capability once the audit chain has
      // integrity findings is not currently implemented anywhere in this
      // tree (the operator CLI's `--accept-broken-chain` does not clear
      // findings or reach this gate; see castle-wall.ts).
      if (tool.tool_class === "write" && hasIntegrityFindings) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                error: `${findings!.length} audit integrity findings detected`,
                audit_integrity_findings: findings,
                // Honest value, not a hint: no remediation exists. There is
                // no agent-usable path past this gate BY DESIGN, and no
                // operator path that restores MCP write capability once
                // findings are present is implemented in this tree either
                // (see the block comment above). An earlier draft said
                // `operator_recovery_required`, which named a recovery that
                // does not exist — on a surface an agent reads to decide what
                // to do next, that is a false promise, not a courtesy. Must
                // stay consistent with the assertion in
                // test/broker-mcp/audit-integrity-gate-classification.test.ts.
                remediation: "none_available",
              }),
            },
          ],
          isError: true,
        };
      }

      const runHandler = async () => {
        // Thread the server-set session principal to every handler (see
        // ToolHandler's doc) — this is what lets handshake/federation
        // per-origin quotas bind to a value the calling agent cannot mint
        // more of, instead of a caller-supplied identity_id.
        return tool.handler(handlerArgs, callerIdentity);
      };

      // Read tools bypass the audit-integrity gate unconditionally (an
      // operator must always be able to introspect); write tools never do,
      // since the override branch above is gone.
      const shouldBypassAuditIntegrity = tool.tool_class === "read";
      const result =
        shouldBypassAuditIntegrity && options?.auditLog
          ? await options.auditLog.runAllowingIntegrityFindings(runHandler)
          : await runHandler();
      options?.toolCallTrapRuntime?.recordToolCall(
        name,
        handlerArgs,
        callerIdentity,
      );
      return result;
    } catch (err) {
      // FAIL-CLOSED ERROR HANDLING (CISO MED-2, Invariant #7 no-policy-inference):
      // an uncaught handler error must NOT return its raw message to the agent -
      // `err.message` can carry a path, a policy detail, a stack-derived
      // internal, or a thrown invariant string (info disclosure / fail-open).
      // Instead, LOG the full error operator-side (audit log) under a synthetic
      // audit_ref, and return only a GENERIC payload to the agent carrying that
      // ref so an operator can correlate. Mirrors the cooperative tools'
      // fixedDenial discipline (generic agent-facing, full detail in audit).
      const auditRef = `audit:tool_error:${randomBytes(8).toString("hex")}`;
      const message = err instanceof Error ? err.message : "Unknown error";
      const stack = err instanceof Error ? err.stack : undefined;
      // Operator-visible record (full fidelity). Defensive: a logging failure
      // must never re-surface the raw error to the agent, so swallow it - the
      // generic response below is always returned.
      try {
        await options?.auditLog?.append(
          "l2",
          `tool_error:${name}`,
          callerIdentity,
          { audit_ref: auditRef, error: message, stack },
          "failure"
        );
      } catch {
        // Audit-write failed (e.g. integrity-locked chain). Do not leak; the
        // agent still receives only the generic payload.
      }
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ error: "tool execution failed", audit_ref: auditRef }),
          },
        ],
        isError: true,
      };
    }
  });

  return server;
}

/**
 * Helper to create a successful tool response.
 */
export function toolResult(
  data: object
): { content: Array<{ type: "text"; text: string }> } {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
  };
}
