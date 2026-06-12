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
import type { AuditEntryInput } from "../l2-operational/audit-log.js";
import type { UpstreamServer } from "../sovereignty-profile.js";
import { validateUpstreamSseUrl } from "./ssrf-validator.js";

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
  manualClose?: boolean;
}

/** Callback for state changes */
export type ConnectionStateCallback = (
  serverName: string,
  state: ConnectionState,
  toolCount: number,
  error?: string
) => void;

export type ToolListChangedCallback = (
  serverName: string,
  tools: UpstreamTool[],
  state: ConnectionState
) => void;

export class UpstreamUnavailableError extends Error {
  readonly code = "upstream_unavailable";
  readonly serverName: string;
  readonly toolName?: string;
  readonly state?: ConnectionState;

  constructor(serverName: string, message: string, options?: { toolName?: string; state?: ConnectionState }) {
    super(message);
    this.name = "UpstreamUnavailableError";
    this.serverName = serverName;
    this.toolName = options?.toolName;
    this.state = options?.state;
  }
}

export interface ProxyAuditLog {
  appendCritical(entry: AuditEntryInput): Promise<void>;
}

// ── Constants ───────────────────────────────────────────────────────────

const MAX_RETRIES = 5;
const BASE_BACKOFF_MS = 1000; // 1 second
const MAX_BACKOFF_MS = 30_000; // 30 seconds
const MAX_UPSTREAM_SERVERS = 20;
const DEFAULT_STDIO_ENV_ALLOWLIST = [
  "PATH",
  "HOME",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "TZ",
  "TMPDIR",
] as const;

function isDeniedUpstreamEnvName(name: string): boolean {
  const normalized = name.toUpperCase();
  return (
    normalized.startsWith("SANCTUARY_") ||
    normalized.endsWith("_API_KEY") ||
    normalized.endsWith("_TOKEN") ||
    normalized.endsWith("_SECRET") ||
    normalized.endsWith("_PASSWORD") ||
    normalized.endsWith("_PASSPHRASE") ||
    normalized.startsWith("AWS_") ||
    normalized.startsWith("GCP_") ||
    normalized.startsWith("AZURE_") ||
    normalized.startsWith("OPENAI_") ||
    normalized.startsWith("ANTHROPIC_") ||
    normalized.startsWith("GOOGLE_")
  );
}

function isValidEnvName(name: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name);
}

export function buildUpstreamStdioEnv(
  configuredEnv: Record<string, string> | undefined,
  parentEnv: NodeJS.ProcessEnv = process.env
): Record<string, string> {
  const safeEnv: Record<string, string> = {};

  for (const key of DEFAULT_STDIO_ENV_ALLOWLIST) {
    const value = parentEnv[key];
    if (value !== undefined && !isDeniedUpstreamEnvName(key)) {
      safeEnv[key] = value;
    }
  }

  for (const [key, value] of Object.entries(configuredEnv ?? {})) {
    if (!isValidEnvName(key) || isDeniedUpstreamEnvName(key)) {
      continue;
    }
    safeEnv[key] = value;
  }

  return safeEnv;
}

// ── Client Manager ─────────────────────────────────────────────────────

export class ClientManager {
  private connections: Map<string, UpstreamConnection> = new Map();
  private onStateChange?: ConnectionStateCallback;
  private onToolListChanged?: ToolListChangedCallback;
  private auditLog?: ProxyAuditLog;
  private shutdownRequested = false;

  constructor(options?: {
    onStateChange?: ConnectionStateCallback;
    onToolListChanged?: ToolListChangedCallback;
    auditLog?: ProxyAuditLog;
  }) {
    this.onStateChange = options?.onStateChange;
    this.onToolListChanged = options?.onToolListChanged;
    this.auditLog = options?.auditLog;
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
    const SAFE_SERVER_NAME = /^[a-zA-Z0-9_-]+$/;

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
      tool_count: conn.state === "connected" ? conn.tools.length : 0,
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
      throw new UpstreamUnavailableError(
        serverName,
        `Upstream server "${serverName}" is not configured`,
        { toolName }
      );
    }
    if (conn.state !== "connected" || !conn.client) {
      throw new UpstreamUnavailableError(
        serverName,
        `Upstream server "${serverName}" is not connected (state: ${conn.state})`,
        { toolName, state: conn.state }
      );
    }
    if (!conn.tools.some((tool) => tool.name === toolName)) {
      throw new UpstreamUnavailableError(
        serverName,
        `Upstream tool "${toolName}" is not currently available on "${serverName}"`,
        { toolName, state: conn.state }
      );
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
          const SAFE_ARG_PATTERN = /^[a-zA-Z0-9._\-/=:@]+$/;
          for (const arg of conn.server.transport.args) {
            if (!SAFE_ARG_PATTERN.test(arg)) {
              throw new Error(`Unsafe argument rejected: contains disallowed characters`);
            }
          }
        }

        // SEC-045: Upstream MCP servers get a minimal, deny-filtered env.
        const transportEnv = buildUpstreamStdioEnv(conn.server.transport.env);

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
        const validation = await validateUpstreamSseUrl(conn.server.transport.url, {
          allowPrivateNetworks: conn.server.transport.allow_private_networks === true,
        });
        if (!validation.ok) {
          throw new Error(`SSE transport URL rejected by SSRF validator: ${validation.reason}`);
        }
        if (conn.server.transport.allow_private_networks === true) {
          await this.auditLog?.appendCritical({
            layer: "l2",
            operation: "proxy_ssrf_escape_hatch_used",
            identity_id: "system",
            result: "success",
            details: {
              event_type: "proxy.ssrf.escape_hatch_used",
              server: conn.server.name,
            },
          });
        }

        transport = new SSEClientTransport(new URL(conn.server.transport.url));
      }

      // Create MCP client
      const client = new Client(
        { name: `sanctuary-proxy/${conn.server.name}`, version: "1.0.0" },
        { capabilities: {} }
      );

      // Connect
      await client.connect(transport);
      client.onclose = () => {
        this.handleConnectionClosed(conn);
      };
      client.onerror = (error) => {
        conn.error = error.message;
      };

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
      const hadTools = conn.tools.length > 0;
      conn.tools = [];
      this.notifyStateChange(conn);
      if (hadTools) {
        this.notifyToolListChanged(conn);
      }

      // Schedule retry if not at max
      this.scheduleRetry(conn);
    }
  }

  /**
   * Discover tools from a connected upstream server.
   */
  private async discoverTools(conn: UpstreamConnection): Promise<void> {
    if (!conn.client || conn.state !== "connected") return;
    const previous = toolsFingerprint(conn.tools);

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
    if (toolsFingerprint(conn.tools) !== previous) {
      this.notifyToolListChanged(conn);
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
    conn.manualClose = true;

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
    this.notifyToolListChanged(conn);
  }

  /**
   * Notify listener of state change.
   */
  private notifyStateChange(conn: UpstreamConnection): void {
    if (this.onStateChange) {
      try {
        const toolCount = conn.state === "connected" ? conn.tools.length : 0;
        this.onStateChange(conn.server.name, conn.state, toolCount, conn.error);
      } catch {
        // Listener errors must not propagate
      }
    }
  }

  private notifyToolListChanged(conn: UpstreamConnection): void {
    if (this.onToolListChanged) {
      try {
        this.onToolListChanged(
          conn.server.name,
          conn.state === "connected" ? conn.tools : [],
          conn.state
        );
      } catch {
        // Listener errors must not propagate
      }
    }
  }

  private handleConnectionClosed(conn: UpstreamConnection): void {
    if (this.shutdownRequested || conn.manualClose) return;
    if (this.connections.get(conn.server.name) !== conn) return;

    conn.state = "disconnected";
    conn.client = null;
    conn.transport = null;
    conn.error = "Upstream connection closed";
    const hadTools = conn.tools.length > 0;
    conn.tools = [];
    this.notifyStateChange(conn);
    if (hadTools) {
      this.notifyToolListChanged(conn);
    }
    this.scheduleRetry(conn);
  }
}

function toolsFingerprint(tools: UpstreamTool[]): string {
  return tools
    .map((tool) => `${tool.name}\u0000${JSON.stringify(tool.inputSchema)}`)
    .sort()
    .join("\u0001");
}
