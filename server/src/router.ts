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
import type { ApprovalGate } from "./principal-policy/gate.js";

/** Tool handler function signature */
export type ToolHandler = (
  args: Record<string, unknown>
) => Promise<{ content: Array<{ type: "text"; text: string }> }>;

/** Tool definition for registration */
export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: ToolHandler;
}

/** Options for server creation */
export interface ServerOptions {
  /** Approval gate — if provided, every tool call is evaluated before execution */
  gate?: ApprovalGate;
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
  schema: Record<string, unknown>
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
  const knownFields = new Set(Object.keys(properties));
  for (const field of Object.keys(args)) {
    if (!knownFields.has(field)) {
      errors.push({ field, message: `Unknown field "${field}"` });
    }
  }

  // Type-check and size-check each provided field
  for (const [field, value] of Object.entries(args)) {
    if (value === undefined || value === null) continue;
    const propSchema = properties[field];
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

/**
 * Create the MCP server with all Sanctuary tools registered.
 * If an ApprovalGate is provided, it wraps every tool call.
 */
export function createServer(
  tools: ToolDefinition[],
  options?: ServerOptions
): Server {
  const gate = options?.gate;

  const server = new Server(
    {
      name: "sanctuary-mcp-server",
      version: "0.2.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // Register tool listing
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: tools.map((t) => ({
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
    const validationErrors = validateArgs(typedArgs, tool.inputSchema);
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
    // Denied calls return a generic error that does not reveal policy.
    if (gate) {
      const result = await gate.evaluate(name, typedArgs);
      if (!result.allowed) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                error: "Operation not permitted",
                approval_required: result.approval_required,
              }),
            },
          ],
          isError: true,
        };
      }
    }

    try {
      return await tool.handler(typedArgs);
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
