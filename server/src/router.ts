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

import { OWN_SCOPE_MEMORY_SAVES } from "./principal-policy/gate.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { randomBytes } from "node:crypto";
import type { ApprovalGate } from "./principal-policy/gate.js";
import type { ToolCallTrapRuntime } from "./honeypot/tool-call-trap-runtime.js";
import type { AuditLog } from "./operational/audit-log.js";
import { refusalResult, type SessionBinding } from "./agent-native/safety-base.js";
import {
  CountingDenialRecorder,
  type DenialCause,
  type DenialRecorder,
  type DenialRecordInput,
} from "./agent-native/denial-ledger.js";
import {
  argumentStageCause,
  classifyToolOutcome,
  proxiedOutcomeFact,
  refusedResultFacts,
} from "./tool-outcome.js";
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
  callerIdentity?: string,
  context?: ToolExecutionContext,
) => Promise<{ content: Array<{ type: "text"; text: string }> }>;

export interface ToolExecutionContext {
  /** SDK-owned cancellation, consumed by proxy/response-runtime.ts. */
  readonly signal?: AbortSignal;
  /** Gate-minted durable id for the exact approved, normalized arguments. */
  readonly approvalAuditId?: string;
}

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
   * Operator-side record of every refusal's cause. Production passes the one
   * ledger the composition root builds; without one, the router counts
   * refusals in a ledger with no sink.
   */
  denialLedger?: DenialRecorder;
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

/** Named stages of runBoundedCall; the catch reads the current one to pick a cause. */
type BoundaryStage =
  | "state_ARGS"
  | "state_PRE_GATE_RECORD"
  | "state_GATE"
  | "state_INTEGRITY"
  | "state_HANDLER"
  | "state_OUTCOME"
  | "state_FINISH";

interface BoundedCall {
  readonly name: string;
  readonly tool: ToolDefinition;
  readonly handlerArgs: Record<string, unknown>;
  readonly approvalRef: string | undefined;
  readonly callerIdentity: string;
  readonly signal: AbortSignal | undefined;
}

// 8 random bytes = 16 hex characters: the existing tool_error audit_ref width.
const TOOL_ERROR_REF_BYTES = 8;

/** Prepare the gate's approval-target arguments; a throw becomes a refusal, not an escape. */
async function prepareGateArgs(
  tool: ToolDefinition,
  handlerArgs: Record<string, unknown>,
): Promise<{ ok: true; args: Record<string, unknown> } | { ok: false; error: unknown }> {
  try {
    return { ok: true, args: (await tool.approvalTargetArgs?.(handlerArgs)) ?? handlerArgs };
  } catch (error) {
    return { ok: false, error };
  }
}

function denialInput(
  call: BoundedCall,
  detail: {
    error?: unknown;
    linkedRef?: string;
    errorName?: string;
    errorMessage?: string;
    facts?: Readonly<Record<string, boolean>>;
  },
): DenialRecordInput {
  const thrown = detail.error;
  const errorName = detail.errorName
    ?? (thrown === undefined ? undefined : thrown instanceof Error ? thrown.name : typeof thrown);
  const errorMessage = detail.errorMessage
    ?? (thrown instanceof Error ? thrown.message : undefined);
  return {
    tool: call.name,
    origin: call.callerIdentity,
    ...(detail.linkedRef !== undefined ? { linked_ref: detail.linkedRef } : {}),
    ...(errorName !== undefined ? { error_name: errorName } : {}),
    ...(errorMessage !== undefined ? { error_message: errorMessage } : {}),
    ...(detail.facts !== undefined ? { facts: detail.facts } : {}),
  };
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
  // Every refusal reaches a ledger: production passes the shared one; a router
  // built without one counts refusals in a ledger with no sink and starts no I/O.
  const denialLedger: DenialRecorder = options?.denialLedger ?? new CountingDenialRecorder();

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
  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    const { name, arguments: args } = request.params;
    const typedArgs = (args ?? {}) as Record<string, unknown>;
    const currentAgentId = options?.currentAgentId?.();
    // The `agent:` form must match audit writers in sdw/memory-tools.ts and agent-native/cooperative-surface.ts.
    // The `agent:` form must match requestingAgentId in
    // server/src/principal-policy/gate.ts, which attributes held calls.
    // Must match the agent: audit identity in hermes-memory-bridge/bridge-core.ts.
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

    return await runBoundedCall({ name, tool, handlerArgs, approvalRef, callerIdentity, signal: extra.signal });
  });

  /**
   * Everything after the agent-input checks runs here, in one boundary: every
   * outcome other than the tool's own success shape leaves as refusalResult(),
   * so no stage, cause or tool can be told apart from the response. The stages
   * run in order; `stage` names the one in progress, and the catch reads it to
   * pick the operator-side cause of a throw.
   *
   *   state_ARGS -> (refused) state_PRE_GATE_RECORD -> refusal
   *   state_ARGS -> state_GATE -> (denied) refusal
   *   state_GATE -> state_INTEGRITY -> (write stop) refusal
   *   state_INTEGRITY -> state_HANDLER -> state_OUTCOME -> state_FINISH
   */
  async function runBoundedCall(call: BoundedCall): Promise<Awaited<ReturnType<ToolHandler>> | ReturnType<typeof refusalResult>> {
    const { name, tool, handlerArgs, approvalRef, callerIdentity } = call;
    // The operation name the gate evaluates; a pre-gate refusal records under the same name.
    const gateOperation = tool.approvalTargetToolName ?? name;
    let stage: BoundaryStage = "state_ARGS";
    try {
      let approvalAuditId: string | undefined;
      if (gate) {
        stage = "state_ARGS";
        const prepared = await prepareGateArgs(tool, handlerArgs);
        if (!prepared.ok) {
          stage = "state_PRE_GATE_RECORD";
          // A refusal decided before the gate leaves the same one gate_deny row an automatic denial does.
          await gate.recordPreGateRefusal(gateOperation);
          // Must match argumentStageCause in tool-outcome.ts, which picks the cause by error type.
          recordDenial(argumentStageCause(prepared.error), denialInput(call, { error: prepared.error }));
          return refuse();
        }

        stage = "state_GATE";
        const verdict = await gate.evaluate(
          gateOperation,
          prepared.args,
          approvalRef ? { approval_ref: approvalRef } : undefined,
          // Must match operatorPreviewSource in principal-policy/gate.ts. Registered identity and validated args are display-only;
          // keep enforcement target, gateArgs, proof binding, context and agent responses independent of this handoff.
          { operation: name, args: handlerArgs },
          // Registered names and target operations must match OWN_SCOPE_MEMORY_SAVES in principal-policy/gate.ts.
          Object.hasOwn(OWN_SCOPE_MEMORY_SAVES, name) ? name : undefined
        );
        if (!verdict.allowed) {
          // Invariant #7: which policy class fired stays in the gate's audit row and the ledger.
          recordDenial("gate_denied", denialInput(call, { linkedRef: verdict.approval_audit_id }));
          return refuse();
        }
        approvalAuditId = verdict.approval_audit_id;
      }

      stage = "state_INTEGRITY";
      const findings = await options?.auditLog?.getIntegrityFindings();
      const findingCount = findings?.length ?? 0;

      // CALLER-CONTROLLED-AUDIT-OVERRIDE (register row, HIGH; MUST-NEVER #5):
      // no argument an MCP caller supplies can lift this gate for a tool
      // classified `write` — `accept_broken_chain` is no longer an accepted
      // argument at all (see tool-args.ts), and no other agent-facing field
      // substitutes for it. That guarantee is scoped to classification: it
      // holds only for tools correctly classified `write`, because this branch
      // and the bypass below both key off `tool.tool_class` and neither looks
      // at what a handler does. Classification correctness is therefore a
      // separate property, and it has no gate: the read set in `index.ts`
      // (`READ_MCP_TOOLS`, plus every tool literal carrying an inline
      // `tool_class: "read"`) is maintained by review, so what this branch can
      // promise is bounded by that set being right (ABC-READCLASS-01, open).
      // Findings persisting is a
      // hard stop for `write` tools, not a request for consent to proceed
      // past them: restoring MCP write capability once the audit chain has
      // integrity findings is not currently implemented anywhere in this
      // tree (the operator CLI's `--accept-broken-chain` does not clear
      // findings or reach this gate; see castle-wall.ts). The findings and
      // their count go to the ledger only; the agent receives the one refusal.
      if (tool.tool_class === "write" && findingCount > 0) {
        recordDenial("write_integrity_stop", denialInput(call, {
          errorName: "audit_integrity_findings",
          errorMessage: `${findingCount} audit integrity findings detected`,
        }));
        return refuse();
      }

      stage = "state_HANDLER";
      const runHandler = async () => {
        // Thread the server-set session principal to every handler (see
        // ToolHandler's doc) — this is what lets handshake/federation
        // per-origin quotas bind to a value the calling agent cannot mint
        // more of, instead of a caller-supplied identity_id.
        return tool.handler(handlerArgs, callerIdentity, { approvalAuditId, signal: call.signal });
      };

      // Read tools bypass the audit-integrity gate unconditionally (an
      // operator must always be able to introspect); write tools never do,
      // since the override branch above is gone. This line is why the read set
      // is a security-relevant list and not a taxonomy: a handler reached from
      // here also gets its audit appends admitted onto a chain that already has
      // findings. Six commitment and verifier verbs have their membership
      // frozen by `test/structure/mcp-commitment-verb-classification.test.ts`;
      // the rest of the set is kept honest by review, not by a test.
      // Note WHICH set, because `tool_class` is assigned two different ways:
      // the `READ_MCP_TOOLS` table in index.ts (see the contract note on it)
      // UNIONED with every tool literal carrying an inline
      // `tool_class: "read"`. The inline half is the one an editor is likely to
      // assume the table covers, and it does not. Reconciling both halves
      // against what each handler's call graph can reach is ABC-READCLASS-01,
      // open and deferred to its own change.
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

      stage = "state_OUTCOME";
      // Must match TOOL_OUTCOME_SHAPES in tool-outcome.ts: only the tool's own
      // success shape passes; every other body, whatever it says, is a refusal.
      const outcome = classifyToolOutcome(name, result, tool);

      stage = "state_FINISH";
      if (outcome === "success") return result;
      if (proxiedOutcomeFact(result)?.upstream_failed === true) {
        recordDenial("proxy_upstream_error", denialInput(call, {}));
      } else {
        const facts = refusedResultFacts(result);
        recordDenial("post_allow_refusal", denialInput(call, {
          errorName: facts.error_name,
          errorMessage: facts.error_message,
          facts: facts.facts,
        }));
      }
      return refuse();
    } catch (err) {
      // FAIL-CLOSED ERROR HANDLING (CISO MED-2, Invariant #7 no-policy-inference):
      // a throw from any stage must NOT return its raw message to the agent -
      // `err.message` can carry a path, a policy detail, a stack-derived
      // internal, or a thrown invariant string (info disclosure / fail-open).
      // The agent receives the one refusal; the operator gets the stage's cause
      // in the ledger and, for the stages a handler runs in, the full error in
      // the audit log under a synthetic audit_ref the ledger row links to.
      switch (stage) {
        case "state_ARGS":
          recordDenial(argumentStageCause(err), denialInput(call, { error: err }));
          break;
        case "state_PRE_GATE_RECORD":
          recordDenial("pre_gate_record_fault", denialInput(call, { error: err }));
          break;
        case "state_GATE":
          recordDenial("gate_fault", denialInput(call, { error: err }));
          break;
        case "state_INTEGRITY":
          recordDenial("integrity_read_fault", denialInput(call, {
            error: err,
            linkedRef: await recordToolError(call, err),
          }));
          break;
        case "state_HANDLER":
          recordDenial("handler_error", denialInput(call, {
            error: err,
            linkedRef: await recordToolError(call, err),
          }));
          break;
        default:
          recordDenial("other", denialInput(call, { error: err }));
      }
      return refuse();
    }
  }

  /** The one place the boundary returns a refusal; must match refusalResult() in agent-native/safety-base.ts. */
  function refuse(): ReturnType<typeof refusalResult> {
    return refusalResult();
  }

  /**
   * Hand a cause to the ledger without ever affecting the response: a ledger
   * that throws still leaves the same refusal, and no append is awaited here.
   * Must match DENIAL_CAUSES in agent-native/denial-ledger.ts: every call site
   * passes a literal from that list (or argumentStageCause), checked
   * structurally by test/agent-native/denial-ledger.test.ts.
   */
  function recordDenial(cause: DenialCause, input: DenialRecordInput): void {
    try {
      denialLedger.record(cause, input);
    } catch {
      // The ledger is operator evidence; its failure never changes what the agent receives.
    }
  }

  /**
   * Record a throw from a stage a handler runs in, operator-side, under a
   * synthetic audit_ref (the existing tool_error row). A logging failure must
   * never re-surface the raw error, so it is swallowed.
   */
  async function recordToolError(call: BoundedCall, err: unknown): Promise<string> {
    const auditRef = `audit:tool_error:${randomBytes(TOOL_ERROR_REF_BYTES).toString("hex")}`;
    const message = err instanceof Error ? err.message : "Unknown error";
    const stack = err instanceof Error ? err.stack : undefined;
    try {
      await options?.auditLog?.append(
        "l2",
        `tool_error:${call.name}`,
        call.callerIdentity,
        { audit_ref: auditRef, error: message, stack },
        "failure"
      );
    } catch {
      // Audit-write failed (e.g. integrity-locked chain). Do not leak; the
      // agent still receives only the refusal.
    }
    return auditRef;
  }

  return server;
}

/**
 * Helper to create a successful tool response.
 * Pretty JSON serialization must match normalizeScreenedResponse in proxy/response-bounds.ts.
 */
export function toolResult(
  data: object
): { content: Array<{ type: "text"; text: string }> } {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
  };
}
