/**
 * Sanctuary MCP Server — Tool Router
 *
 * Routes sanctuary/* tool calls to their layer-specific handlers.
 * Every tool call passes through schema validation and the ApprovalGate
 * (if configured) before execution. Neither can be bypassed.
 *
 * This module is the abstraction boundary for MCP SDK version migration —
 * if the SDK API changes, only this module needs updating.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { createRequire } from "node:module";
import type { ApprovalGate } from "./principal-policy/gate.js";
import type { ToolCallTrapRuntime } from "./honeypot/tool-call-trap-runtime.js";
import type { AuditLog } from "./l2-operational/audit-log.js";
import { fixedDenial, type SessionBinding } from "./agent-native/safety-base.js";

const require = createRequire(import.meta.url);
const { version: PKG_VERSION } = require("../package.json");

/** Tool handler function signature */
export type ToolHandler = (
  args: Record<string, unknown>
) => Promise<{ content: Array<{ type: "text"; text: string }> }>;

/** Tool definition for registration */
export interface ToolDefinition {
  name: string;
  description: string;
  tool_class?: "read" | "write";
  inputSchema: Record<string, unknown>;
  handler: ToolHandler;
}

/** Options for server creation */
export interface ServerOptions {
  /** Approval gate — if provided, every tool call is evaluated before execution */
  gate?: ApprovalGate;
  /** Pi-3 honeypot runtime for server-local fake tool catalog injection. */
  toolCallTrapRuntime?: ToolCallTrapRuntime;
  /** Current wrapped-agent id for per-agent catalog visibility. */
  currentAgentId?: () => string | undefined;
  /** Audit log used to enforce MCP read/write behavior on broken chains. */
  auditLog?: AuditLog;
  /** Active session identity binding for agent-native approval/namespace checks. */
  currentSessionBinding?: () => SessionBinding | undefined;
}

// ── Schema Validation ──────────────────────────────────────────────────
// Lightweight JSON Schema validation for tool arguments.
// Enforces: required fields, type checks, unknown field rejection,
// and size caps on string arguments (defense against DoS via oversized payloads).

/** Maximum byte length for any single string argument (1 MB) */
const MAX_STRING_BYTES = 1_048_576;

/** Maximum byte length for base64 bundle arguments (5 MB) */
const MAX_BUNDLE_BYTES = 5_242_880;

/** Fields known to carry base64 bundles — get the larger size cap */
const BUNDLE_FIELDS = new Set(["bundle"]);

interface SchemaProperty {
  type?: string;
  properties?: Record<string, SchemaProperty>;
  required?: string[];
  items?: SchemaProperty;
  enum?: unknown[];
  default?: unknown;
}

interface ValidationError {
  field: string;
  message: string;
}

/**
 * Validate tool arguments against the tool's declared inputSchema.
 * Returns an array of validation errors (empty = valid).
 */
function validateArgs(
  args: Record<string, unknown>,
  schema: Record<string, unknown>,
  extraAllowedFields: Record<string, SchemaProperty> = {}
): ValidationError[] {
  const errors: ValidationError[] = [];
  const properties = (schema.properties ?? {}) as Record<string, SchemaProperty>;
  const required = (schema.required ?? []) as string[];

  // Check required fields
  for (const field of required) {
    if (args[field] === undefined || args[field] === null) {
      errors.push({ field, message: `Required field "${field}" is missing` });
    }
  }

  // Check for unknown fields (reject extra fields not in schema)
  const knownFields = new Set([
    ...Object.keys(properties),
    ...Object.keys(extraAllowedFields),
  ]);
  for (const field of Object.keys(args)) {
    if (!knownFields.has(field)) {
      errors.push({ field, message: `Unknown field "${field}"` });
    }
  }

  // Type-check and size-check each provided field
  for (const [field, value] of Object.entries(args)) {
    if (value === undefined || value === null) continue;
    const propSchema = properties[field] ?? extraAllowedFields[field];
    if (!propSchema) continue; // Already flagged as unknown above

    const typeError = checkType(field, value, propSchema);
    if (typeError) {
      errors.push(typeError);
      continue;
    }

    // String size caps
    if (typeof value === "string") {
      const maxBytes = BUNDLE_FIELDS.has(field) ? MAX_BUNDLE_BYTES : MAX_STRING_BYTES;
      // Use byte length, not string length, for accurate size checking
      const byteLength = new TextEncoder().encode(value).length;
      if (byteLength > maxBytes) {
        errors.push({
          field,
          message: `Field "${field}" exceeds maximum size (${byteLength} bytes > ${maxBytes} bytes)`,
        });
      }
    }

    // Enum validation
    if (propSchema.enum && !propSchema.enum.includes(value)) {
      errors.push({
        field,
        message: `Field "${field}" must be one of: ${propSchema.enum.join(", ")}`,
      });
    }
  }

  return errors;
}

/**
 * Check whether a value matches the declared JSON Schema type.
 */
function checkType(
  field: string,
  value: unknown,
  schema: SchemaProperty
): ValidationError | null {
  if (!schema.type) return null;

  switch (schema.type) {
    case "string":
      if (typeof value !== "string") {
        return { field, message: `Expected string for "${field}", got ${typeof value}` };
      }
      break;
    case "number":
      if (typeof value !== "number") {
        return { field, message: `Expected number for "${field}", got ${typeof value}` };
      }
      break;
    case "boolean":
      if (typeof value !== "boolean") {
        return { field, message: `Expected boolean for "${field}", got ${typeof value}` };
      }
      break;
    case "object":
      if (typeof value !== "object" || Array.isArray(value)) {
        return { field, message: `Expected object for "${field}", got ${typeof value}` };
      }
      break;
    case "array":
      if (!Array.isArray(value)) {
        return { field, message: `Expected array for "${field}", got ${typeof value}` };
      }
      break;
  }
  return null;
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
    }
  );

  // Register tool listing
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const honeypotTools =
      options?.toolCallTrapRuntime?.listCatalogTools(
        options.currentAgentId?.(),
      ) ?? [];
    const catalog = [...tools, ...honeypotTools];
    return {
      tools: catalog.map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
      })),
    };
  });

  // Register tool execution — validation + gate sit between router and handler
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

    // ── Schema Validation ────────────────────────────────────────────
    // Validate arguments against the tool's declared inputSchema.
    // This runs BEFORE the gate so that the gate sees normalized args.
    const approvalRef =
      typeof typedArgs.approval_ref === "string"
        ? typedArgs.approval_ref
        : undefined;
    const handlerArgs = { ...typedArgs };
    delete handlerArgs.approval_ref;

    const validationErrors = validateArgs(
      typedArgs,
      tool.inputSchema,
      {
        ...(tool.tool_class === "write"
          ? { accept_broken_chain: { type: "boolean", default: false } }
          : {}),
        approval_ref: { type: "string" },
      }
    );
    if (validationErrors.length > 0) {
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              error: "validation_failed",
              message: "Tool arguments failed schema validation",
              violations: validationErrors,
            }),
          },
        ],
        isError: true,
      };
    }

    // ── Approval Gate ──────────────────────────────────────────────
    // If a gate is configured, every tool call must pass through it.
    // Denied calls return the fixed coarse schema; details stay in audit.
    if (gate) {
      const result = await gate.evaluate(
        name,
        handlerArgs,
        approvalRef ? { approval_ref: approvalRef } : undefined
      );
      if (!result.allowed) {
        const errorPayload = fixedDenial(
          `audit:gate:${name}`,
          result.approval_required ? "request_review" : "try_lower_scope",
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
      const acceptBrokenChain = handlerArgs.accept_broken_chain === true;

      if (tool.tool_class === "write" && hasIntegrityFindings && !acceptBrokenChain) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                error: `${findings!.length} audit integrity findings detected`,
                audit_integrity_findings: findings,
                accept_broken_chain_required: true,
              }),
            },
          ],
          isError: true,
        };
      }

      const runHandler = async () => {
        if (tool.tool_class === "write" && hasIntegrityFindings && acceptBrokenChain) {
          await options?.auditLog?.appendCritical({
            layer: "l2",
            operation: "mcp_accept_broken_chain_override",
            identity_id: callerIdentity,
            result: "success",
            details: {
              tool: name,
              finding_count: findings!.length,
              findings,
            },
          });
        }
        return tool.handler(handlerArgs);
      };

      const shouldBypassAuditIntegrity =
        tool.tool_class === "read" ||
        (tool.tool_class === "write" && hasIntegrityFindings && acceptBrokenChain);
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
      const message =
        err instanceof Error ? err.message : "Unknown error";
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ error: message }),
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
