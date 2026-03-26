/**
 * Sanctuary MCP Server — Tool Router
 *
 * Routes sanctuary/* tool calls to their layer-specific handlers.
 * Every tool call passes through the ApprovalGate (if configured)
 * before execution. The gate cannot be bypassed.
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

  // Register tool execution — gate sits between router and handler
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
