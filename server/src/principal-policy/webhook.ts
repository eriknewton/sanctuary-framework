/**
 * Sanctuary MCP Server — Webhook Approval Channel
 *
 * Sends approval requests to an external webhook URL and listens for
 * callback responses. Enables integration with Slack, Discord, PagerDuty,
 * or any HTTP-based approval workflow.
 *
 * Architecture:
 * - Outbound: POST approval request to configured webhook_url
 * - Inbound: HTTP callback server listens for POST /webhook/respond/:id
 * - HMAC-SHA256 signatures on both outbound and inbound payloads
 * - Timeout fallback: auto-deny (or auto-approve) if no callback received
 *
 * Security invariants:
 * - All outbound payloads signed with HMAC-SHA256 (webhook_secret)
 * - All inbound callbacks verified with same HMAC-SHA256 signature
 * - Callback server binds to configurable host (default 127.0.0.1)
 * - Replay protection via request ID + pending map (can't approve twice)
 * - All decisions are audit-logged
 */

import {
  createServer as createHttpServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { createHmac, randomBytes } from "node:crypto";
import type { ApprovalChannel } from "./approval-channel.js";
import type { ApprovalRequest, ApprovalResponse } from "./types.js";

// ── Types ───────────────────────────────────────────────────────────────

export interface WebhookConfig {
  /** URL to POST approval requests to */
  webhook_url: string;
  /** Shared secret for HMAC-SHA256 signatures */
  webhook_secret: string;
  /** Port for the callback listener */
  callback_port: number;
  /** Host for the callback listener (default: 127.0.0.1) */
  callback_host: string;
  /** Seconds to wait for a callback before timeout */
  timeout_seconds: number;
  /** SEC-002: auto_deny is always true. Field retained for interface compat but ignored. */
  auto_deny?: boolean;
}

interface PendingWebhookRequest {
  id: string;
  request: ApprovalRequest;
  resolve: (response: ApprovalResponse) => void;
  timer: ReturnType<typeof setTimeout>;
  created_at: string;
}

/** Outbound webhook payload */
export interface WebhookPayload {
  /** Unique request ID */
  request_id: string;
  /** The approval request details */
  operation: string;
  tier: 1 | 2;
  reason: string;
  context: Record<string, unknown>;
  timestamp: string;
  /** URL to POST the response back to */
  callback_url: string;
  /** Seconds until auto-resolution */
  timeout_seconds: number;
}

/** Inbound callback payload */
export interface WebhookCallbackPayload {
  /** The request ID being responded to */
  request_id: string;
  /** The decision */
  decision: "approve" | "deny";
}

// ── HMAC Helpers ────────────────────────────────────────────────────────

/**
 * Generate HMAC-SHA256 signature for a payload.
 */
export function signPayload(body: string, secret: string): string {
  return createHmac("sha256", secret).update(body).digest("hex");
}

/**
 * Verify HMAC-SHA256 signature. Uses timing-safe comparison.
 */
export function verifySignature(
  body: string,
  signature: string,
  secret: string
): boolean {
  const expected = signPayload(body, secret);
  if (expected.length !== signature.length) return false;
  // Constant-time comparison
  let mismatch = 0;
  for (let i = 0; i < expected.length; i++) {
    mismatch |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  }
  return mismatch === 0;
}

// ── Webhook Approval Channel ────────────────────────────────────────────

export class WebhookApprovalChannel implements ApprovalChannel {
  private config: WebhookConfig;
  private pending: Map<string, PendingWebhookRequest> = new Map();
  private callbackServer: ReturnType<typeof createHttpServer> | null = null;

  constructor(config: WebhookConfig) {
    this.config = config;
  }

  /**
   * Start the callback listener server.
   */
  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.callbackServer = createHttpServer((req, res) =>
        this.handleCallback(req, res)
      );
      this.callbackServer.listen(
        this.config.callback_port,
        this.config.callback_host,
        () => {
          process.stderr.write(
            `\n  Sanctuary Webhook Callback: http://${this.config.callback_host}:${this.config.callback_port}\n` +
              `  Webhook target: ${this.config.webhook_url}\n\n`
          );
          resolve();
        }
      );
      this.callbackServer.on("error", reject);
    });
  }

  /**
   * Stop the callback server and clean up pending requests.
   */
  async stop(): Promise<void> {
    // Resolve all pending as deny
    for (const [, pending] of this.pending) {
      clearTimeout(pending.timer);
      pending.resolve({
        decision: "deny",
        decided_at: new Date().toISOString(),
        decided_by: "auto",
      });
    }
    this.pending.clear();

    if (this.callbackServer) {
      return new Promise((resolve) => {
        this.callbackServer!.close(() => resolve());
      });
    }
  }

  /**
   * Request approval by POSTing to the webhook and waiting for a callback.
   */
  async requestApproval(request: ApprovalRequest): Promise<ApprovalResponse> {
    const id = randomBytes(8).toString("hex");

    // Also write to stderr as notification
    process.stderr.write(
      `[Sanctuary] Webhook approval sent: ${request.operation} (Tier ${request.tier}) — awaiting callback\n`
    );

    return new Promise<ApprovalResponse>((resolve) => {
      // Set up timeout
      const timer = setTimeout(() => {
        this.pending.delete(id);
        const response: ApprovalResponse = {
          // SEC-002: Timeout ALWAYS denies. No configuration can change this.
          decision: "deny",
          decided_at: new Date().toISOString(),
          decided_by: "timeout",
        };
        resolve(response);
      }, this.config.timeout_seconds * 1000);

      // Store pending request
      const pending: PendingWebhookRequest = {
        id,
        request,
        resolve,
        timer,
        created_at: new Date().toISOString(),
      };
      this.pending.set(id, pending);

      // Build outbound payload
      const callbackUrl = `http://${this.config.callback_host}:${this.config.callback_port}/webhook/respond/${id}`;
      const payload: WebhookPayload = {
        request_id: id,
        operation: request.operation,
        tier: request.tier,
        reason: request.reason,
        context: request.context,
        timestamp: request.timestamp,
        callback_url: callbackUrl,
        timeout_seconds: this.config.timeout_seconds,
      };

      // Send the webhook (fire-and-forget — errors logged, not thrown)
      this.sendWebhook(payload).catch((err) => {
        process.stderr.write(
          `[Sanctuary] Webhook delivery failed: ${err instanceof Error ? err.message : String(err)}\n`
        );
      });
    });
  }

  // ── Outbound Webhook ──────────────────────────────────────────────────

  private async sendWebhook(payload: WebhookPayload): Promise<void> {
    const body = JSON.stringify(payload);
    const signature = signPayload(body, this.config.webhook_secret);

    const response = await fetch(this.config.webhook_url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Sanctuary-Signature": signature,
        "X-Sanctuary-Request-Id": payload.request_id,
      },
      body,
    });

    if (!response.ok) {
      throw new Error(
        `Webhook returned ${response.status}: ${await response.text().catch(() => "")}`
      );
    }
  }

  // ── Inbound Callback Handler ──────────────────────────────────────────

  private handleCallback(req: IncomingMessage, res: ServerResponse): void {
    const url = new URL(
      req.url ?? "/",
      `http://${req.headers.host ?? "localhost"}`
    );
    const method = req.method ?? "GET";

    // CORS
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, X-Sanctuary-Signature"
    );

    if (method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    // Health check
    if (method === "GET" && url.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          status: "ok",
          pending_count: this.pending.size,
        })
      );
      return;
    }

    // Only accept POST /webhook/respond/:id
    const match = url.pathname.match(/^\/webhook\/respond\/([a-f0-9]+)$/);
    if (method !== "POST" || !match) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not found" }));
      return;
    }

    const requestId = match[1];

    // Read and verify the body
    const bodyChunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => bodyChunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(bodyChunks).toString("utf-8");

      // Verify HMAC signature
      const signature = req.headers["x-sanctuary-signature"];
      if (
        typeof signature !== "string" ||
        !verifySignature(body, signature, this.config.webhook_secret)
      ) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({ error: "Invalid signature" })
        );
        return;
      }

      // Parse payload
      let callbackPayload: WebhookCallbackPayload;
      try {
        callbackPayload = JSON.parse(body);
      } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid JSON" }));
        return;
      }

      // Validate decision
      if (
        callbackPayload.decision !== "approve" &&
        callbackPayload.decision !== "deny"
      ) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            error: 'Decision must be "approve" or "deny"',
          })
        );
        return;
      }

      // Validate request_id matches URL
      if (callbackPayload.request_id !== requestId) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({ error: "Request ID mismatch" })
        );
        return;
      }

      // Find the pending request
      const pending = this.pending.get(requestId);
      if (!pending) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            error: "Request not found or already resolved",
          })
        );
        return;
      }

      // Clear timeout and resolve
      clearTimeout(pending.timer);
      this.pending.delete(requestId);

      const response: ApprovalResponse = {
        decision: callbackPayload.decision,
        decided_at: new Date().toISOString(),
        decided_by: "human",
      };

      pending.resolve(response);

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          success: true,
          decision: callbackPayload.decision,
        })
      );
    });
  }

  /** Get the number of pending requests */
  get pendingCount(): number {
    return this.pending.size;
  }
}
