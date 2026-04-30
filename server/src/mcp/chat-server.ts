/**
 * Sanctuary MCP Server — Standalone Operator Chat MCP Interface (v1.2.x F9)
 *
 * Exposes the wrapped-agent reply hook as an MCP server so ANY harness
 * speaking MCP — Claude Code, OpenClaw, Cline, Cursor, LangGraph,
 * Mastra, CrewAI, etc. — can deliver responses to the operator's
 * direct-agent chat surface. This is the harness-side ship that closes
 * the v1.2 direct-agent chat loop opened by PR #96 (which shipped the
 * operator-side primitives).
 *
 * Two tools are exposed:
 *   chat/poll_inbox   — wrapped agent polls for pending operator messages.
 *   chat/send_reply   — wrapped agent delivers a response to the operator.
 *
 * Each chat-server instance is bound to a single (agent_id, identity_id)
 * pair at construction; cross-agent isolation is the load-bearing
 * security invariant. A wrapped agent's MCP runtime invoking tools on
 * this server can only ever read or write its own active session.
 *
 * Denials return generic error messages; the reason is in the audit log,
 * never in the response. This matches the Sanctuary denial-opacity rule
 * shared with broker-server.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { SANCTUARY_VERSION } from "../config.js";
import type { OperatorChatService } from "../chat/operator-chat-service.js";

const PKG_VERSION = SANCTUARY_VERSION;

export interface ChatServerOptions {
  /** The wrapped agent this chat-server is bound to. */
  agentId: string;
  /** The Sanctuary identity_id of the operator who owns the fortress. */
  identityId: string;
}

function ok(payload: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(payload) }],
  };
}

function genericError(message = "Chat tool denied") {
  return {
    content: [
      { type: "text" as const, text: JSON.stringify({ error: message }) },
    ],
    isError: true,
  };
}

export function createChatMcpServer(
  service: OperatorChatService,
  opts: ChatServerOptions,
): Server {
  const server = new Server(
    {
      name: "sanctuary-chat",
      version: PKG_VERSION,
    },
    {
      capabilities: { tools: {} },
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: "chat/poll_inbox",
        description:
          "Poll for pending operator messages on this agent's active direct-chat session. Returns {messages, cursor, session_state}. Empty messages array when nothing new on an active session. Generic error when no active session exists for this agent.",
        inputSchema: {
          type: "object",
          properties: {},
          required: [],
        },
      },
      {
        name: "chat/send_reply",
        description:
          "Deliver a response to the operator on this agent's active direct-chat session. Body must be non-empty after trim. Returns the persisted message record. Generic error when no active session, session closed, or body empty.",
        inputSchema: {
          type: "object",
          properties: {
            session_id: {
              type: "string",
              description:
                "The session id surfaced by chat/poll_inbox. Must match the active session bound to this agent; cross-agent session ids are rejected.",
            },
            body: {
              type: "string",
              description:
                "The agent's reply text. Trimmed at the chat-server boundary; must be non-empty after trim.",
            },
          },
          required: ["session_id", "body"],
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: rawArgs } = request.params;
    const args = (rawArgs ?? {}) as Record<string, unknown>;

    try {
      switch (name) {
        case "chat/poll_inbox": {
          const session = await service.findActiveSessionForAgent(
            opts.agentId,
          );
          if (!session) {
            return genericError("No active chat session");
          }
          // Determine session-state at poll time. The chat surface in the
          // dashboard renders the same enum, so the harness can mirror
          // operator-visible state without re-deriving it.
          const sessionState = session.closed_at
            ? "closed"
            : Date.parse(session.expires_at) <= Date.now()
              ? "expired"
              : "active";
          if (sessionState !== "active") {
            return genericError("No active chat session");
          }

          const history = await service.getDirectAgentHistory(opts.agentId);
          // Scope to messages bound to THIS session_id, role=operator,
          // chronologically newer than the persisted cursor. Filtering
          // by session_id (not just role) is the cross-session leakage
          // guard: history retains messages from prior sessions on the
          // same agent thread; the agent sees only its current session.
          const cursor = session.last_polled_message_id ?? null;
          let cursorIdx = -1;
          if (cursor) {
            cursorIdx = history.findIndex((m) => m.message_id === cursor);
          }
          const newer = history
            .filter(
              (m) =>
                m.role === "operator" &&
                m.session_id === session.session_id,
            )
            .filter((m) => {
              if (cursorIdx < 0) return true;
              const idx = history.findIndex(
                (h) => h.message_id === m.message_id,
              );
              return idx > cursorIdx;
            });

          // Advance the cursor to the newest returned message id when we
          // returned at least one. Atomic from the chat-server's perspective:
          // a concurrent advance from another invocation would race here,
          // but the chat-server is the only writer of this field and runs
          // single-threaded in its own process, so concurrent advances do
          // not arise in v1.2.x.
          let newCursor = session.last_polled_message_id ?? null;
          if (newer.length > 0) {
            const lastId = newer[newer.length - 1]!.message_id;
            await service.advancePollCursor(session.session_id, lastId);
            newCursor = lastId;
          }

          return ok({
            session_id: session.session_id,
            messages: newer,
            cursor: newCursor,
            session_state: sessionState,
          });
        }

        case "chat/send_reply": {
          const sessionId = requireString(args, "session_id");
          const body = requireString(args, "body");

          // Cross-agent isolation guard. The session must exist AND
          // belong to this chat-server's bound agent_id. Without this
          // check, a compromised harness could pass another agent's
          // session_id and leak a reply into a foreign chat thread.
          const session = await service.resolveSession(sessionId);
          if (!session) {
            return genericError("Unknown chat session");
          }
          if (session.agent_id !== opts.agentId) {
            return genericError("Unknown chat session");
          }
          if (session.closed_at) {
            return genericError("Chat session already closed");
          }

          const message = await service.recordAgentReply({
            sessionId,
            body,
          });
          return ok({ message });
        }

        default:
          return genericError(`Unknown tool: ${name}`);
      }
    } catch (e) {
      // Generic denial; specific reason is in the audit log + stderr.
      const errMsg = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
      return genericError(`Chat error: ${errMsg}`);
    }
  });

  return server;
}

function requireString(args: Record<string, unknown>, key: string): string {
  const v = args[key];
  if (typeof v !== "string" || v.length === 0) {
    throw new Error(`Missing or empty: ${key}`);
  }
  return v;
}
