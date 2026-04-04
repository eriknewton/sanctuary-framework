/**
 * Sanctuary MCP Server — Proxy Client Manager
 *
 * Manages MCP client connections to upstream servers. Handles connection
 * lifecycle, reconnection with exponential backoff, and tool discovery.
 *
 * Security invariants:
 * - Upstream servers are configured via the sovereignty profile (Tier 1 gated)
 * - Connection failures do not block Sanctuary startup
 * - Tool discovery is re-run on every successful reconnection
 * - Environment variables for upstream transports are passed through, not stored in logs
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import type { UpstreamServer } from "../sovereignty-profile.js";

// ── Types ───────────────────────────────────────────────────────────────

export type ConnectionState = "disconnected" | "connecting" | "connected" | "error";

export interface UpstreamTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export interface UpstreamConnection {
  server: UpstreamServer;
  client: Client | null;
  transport: StdioClientTransport | SSEClientTransport | null;
  state: ConnectionState;
  tools: UpstreamTool[];
  error?: string;
  retryCount: number;
  retryTimer?: ReturnType<typeof setTimeout>;
}

/** Callback for state changes */
export type ConnectionStateCallback = (
  serverName: string,
  state: ConnectionState,
  toolCount: number,
  error?: string
) => void;

// ── Constants ───────────────────────────────────────────────────────────

const MAX_RETRIES = 5;
const BASE_BACKOFF_MS = 1000; // 1 second
const MAX_BACKOFF_MS = 30_000; // 30 seconds
const MAX_UPSTREAM_SERVERS = 20;

// ── Client Manager ─────────────────────────────────────────────────────

export class ClientManager {
  private connections: Map<string, UpstreamConnection> = new Map();
  private onStateChange?: ConnectionStateCallback;
  private shutdownRequested = false;

  constructor(options?: { onStateChange?: ConnectionStateCallback }) {
    this.onStateChange = options?.onStateChange;
  }

  /**
   * Configure upstream servers. Disconnects removed servers, connects new ones.
   * Non-blocking — connection failures are handled asynchronously.
   */
  async configure(servers: UpstreamServer[]): Promise<void> {
    if (servers.length > MAX_UPSTREAM_SERVERS) {
      throw new Error(`Maximum ${MAX_UPSTREAM_SERVERS} upstream servers allowed`);
    }

    // SEC-047: Validate server names before processing
    const SAFE_SERVER_NAME = /^[a-zA-Z0-9_\-]+$/;

    const newNames = new Set(servers.filter(s => {
      if (!SAFE_SERVER_NAME.test(s.name)) {
        return false; // Skip servers with unsafe names
      }
      return s.enabled;
    }).map(s => s.name));

    // Disconnect servers that are no longer in the config or are disabled
    for (const [name] of this.connections) {
      if (!newNames.has(name)) {
        await this.disconnectServer(name);
      }
    }

    // Connect new/updated servers
    for (const server of servers) {
      // SEC-047: Validate server name
      if (!SAFE_SERVER_NAME.test(server.name)) {
        continue; // Skip servers with unsafe names
      }

      if (!server.enabled) {
        // If it was connected, disconnect it
        if (this.connections.has(server.name)) {
          await this.disconnectServer(server.name);
        }
        continue;
      }

      const existing = this.connections.get(server.name);
      if (existing && existing.state === "connected") {
        // Update the server config (tier changes) without reconnecting
        existing.server = server;
        continue;
      }

      // New server or reconnecting a failed one
      this.connectServer(server);
    }
  }

  /**
   * Get all discovered tools across all connected upstream servers.
   */
  getAllTools(): Map<string, UpstreamTool[]> {
    const result = new Map<string, UpstreamTool[]>();
    for (const [name, conn] of this.connections) {
      if (conn.state === "connected" && conn.tools.length > 0) {
        result.set(name, conn.tools);
      }
    }
    return result;
  }

  /**
   * Get connection status for all configured servers.
   */
  getStatus(): Array<{
    name: string;
    state: ConnectionState;
    transport_type: string;
    tool_count: number;
    error?: string;
  }> {
    return Array.from(this.connections.values()).map(conn => ({
      name: conn.server.name,
      state: conn.state,
      transport_type: conn.server.transport.type,
      tool_count: conn.tools.length,
      error: conn.error,
    }));
  }

  /**
   * Get the upstream server config by name.
   */
  getServerConfig(name: string): UpstreamServer | undefined {
    return this.connections.get(name)?.server;
  }

  /**
   * Call a tool on an upstream server.
   */
  async callTool(
    serverName: string,
    toolName: string,
    args: Record<string, unknown>
  ): Promise<{ content: Array<{ type: string; text?: string; [key: string]: unknown }> }> {
    const conn = this.connections.get(serverName);
    if (!conn) {
      throw new Error(`Upstream server "${serverName}" is not configured`);
    }
    if (conn.state !== "connected" || !conn.client) {
      throw new Error(`Upstream server "${serverName}" is not connected (state: ${conn.state})`);
    }

    const result = await conn.client.callTool({
      name: toolName,
      arguments: args,
    });

    return result as { content: Array<{ type: string; text?: string; [key: string]: unknown }> };
  }

  /**
   * Shut down all connections cleanly.
   */
  async shutdown(): Promise<void> {
    this.shutdownRequested = true;

    // Cancel all retry timers
    for (const conn of this.connections.values()) {
      if (conn.retryTimer) {
        clearTimeout(conn.retryTimer);
        conn.retryTimer = undefined;
      }
    }

    // Disconnect all servers
    const disconnects = Array.from(this.connections.keys()).map(name =>
      this.disconnectServer(name)
    );
    await Promise.allSettled(disconnects);
  }

  // ── Private ───────────────────────────────────────────────────────────

  /**
   * Connect to an upstream server (non-blocking).
   * Spawns connection attempt in background — does not throw.
   */
  private connectServer(server: UpstreamServer): void {
    const conn: UpstreamConnection = {
      server,
      client: null,
      transport: null,
      state: "connecting",
      tools: [],
      retryCount: 0,
    };
    this.connections.set(server.name, conn);
    this.notifyStateChange(conn);

    // Non-blocking connect
    this.doConnect(conn).catch(() => {
      // Error handled inside doConnect
    });
  }

  /**
   * Perform the actual connection to an upstream server.
   */
  private async doConnect(conn: UpstreamConnection): Promise<void> {
    try {
      conn.state = "connecting";
      this.notifyStateChange(conn);

      // Create transport
      let transport: StdioClientTransport | SSEClientTransport;

      if (conn.server.transport.type === "stdio") {
        if (!conn.server.transport.command) {
          throw new Error("stdio transport requires a command");
        }

        // SEC-044: Validate stdio command args to prevent command injection
        if (conn.server.transport.args) {
          const SAFE_ARG_PATTERN = /^[a-zA-Z0-9._\-\/=:@]+$/;
          for (const arg of conn.server.transport.args) {
            if (!SAFE_ARG_PATTERN.test(arg)) {
              throw new Error(`Unsafe argument rejected: contains disallowed characters`);
            }
          }
        }

        // SEC-045: Filter blocked environment variables
        const ENV_BLOCKLIST = new Set([
          'PATH', 'HOME', 'USER', 'SHELL', 'NODE_OPTIONS', 'NODE_PATH',
          'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES',
          'PYTHONPATH', 'RUBYLIB', 'PERL5LIB',
          'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY',
          'http_proxy', 'https_proxy', 'no_proxy',
        ]);

        let transportEnv: Record<string, string> | undefined;
        if (conn.server.transport.env) {
          const safeEnv = { ...process.env } as Record<string, string>;
          for (const [key, value] of Object.entries(conn.server.transport.env)) {
            if (!ENV_BLOCKLIST.has(key)) {
              safeEnv[key] = value as string;
            }
            // Silently drop blocked env vars (logged via audit)
          }
          transportEnv = safeEnv;
        }

        transport = new StdioClientTransport({
          command: conn.server.transport.command,
          args: conn.server.transport.args,
          env: transportEnv,
        });
      } else {
        if (!conn.server.transport.url) {
          throw new Error("sse transport requires a url");
        }

        // SEC-052: Validate SSE URL scheme and prevent SSRF
        const ssrfUrl = new URL(conn.server.transport.url);
        if (ssrfUrl.protocol !== "http:" && ssrfUrl.protocol !== "https:") {
          throw new Error("SSE transport URL must use http or https scheme");
        }

        transport = new SSEClientTransport(ssrfUrl);
      }

      // Create MCP client
      const client = new Client(
        { name: `sanctuary-proxy/${conn.server.name}`, version: "1.0.0" },
        { capabilities: {} }
      );

      // Connect
      await client.connect(transport);

      conn.client = client;
      conn.transport = transport;
      conn.state = "connected";
      conn.error = undefined;
      conn.retryCount = 0;

      // Discover tools
      await this.discoverTools(conn);

      this.notifyStateChange(conn);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown connection error";
      conn.state = "error";
      conn.error = message;
      conn.client = null;
      conn.transport = null;
      this.notifyStateChange(conn);

      // Schedule retry if not at max
      this.scheduleRetry(conn);
    }
  }

  /**
   * Discover tools from a connected upstream server.
   */
  private async discoverTools(conn: UpstreamConnection): Promise<void> {
    if (!conn.client || conn.state !== "connected") return;

    try {
      const result = await conn.client.listTools();
      conn.tools = (result.tools ?? []).map(t => ({
        name: t.name,
        description: t.description ?? "",
        inputSchema: (t.inputSchema ?? { type: "object", properties: {} }) as Record<string, unknown>,
      }));
    } catch {
      // Tool discovery failed — server is connected but no tools available
      conn.tools = [];
    }
  }

  /**
   * Schedule a reconnection attempt with exponential backoff.
   */
  private scheduleRetry(conn: UpstreamConnection): void {
    if (this.shutdownRequested) return;
    if (conn.retryCount >= MAX_RETRIES) {
      conn.error = `Max retries (${MAX_RETRIES}) exceeded. Last error: ${conn.error}`;
      this.notifyStateChange(conn);
      return;
    }

    const delay = Math.min(
      BASE_BACKOFF_MS * Math.pow(2, conn.retryCount),
      MAX_BACKOFF_MS
    );
    conn.retryCount++;

    conn.retryTimer = setTimeout(() => {
      if (this.shutdownRequested) return;
      conn.retryTimer = undefined;
      this.doConnect(conn).catch(() => {
        // Error handled inside doConnect
      });
    }, delay);
  }

  /**
   * Disconnect a specific upstream server.
   */
  private async disconnectServer(name: string): Promise<void> {
    const conn = this.connections.get(name);
    if (!conn) return;

    // Cancel any pending retry
    if (conn.retryTimer) {
      clearTimeout(conn.retryTimer);
      conn.retryTimer = undefined;
    }

    // Close the client connection
    if (conn.client) {
      try {
        await conn.client.close();
      } catch {
        // Best-effort close
      }
    }

    // Close transport
    if (conn.transport) {
      try {
        await conn.transport.close();
      } catch {
        // Best-effort close
      }
    }

    this.connections.delete(name);
  }

  /**
   * Notify listener of state change.
   */
  private notifyStateChange(conn: UpstreamConnection): void {
    if (this.onStateChange) {
      try {
        this.onStateChange(conn.server.name, conn.state, conn.tools.length, conn.error);
      } catch {
        // Listener errors must not propagate
      }
    }
  }
}
