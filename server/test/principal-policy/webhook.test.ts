/**
 * Sanctuary MCP Server — Webhook Approval Channel Tests
 *
 * Tests the WebhookApprovalChannel: outbound webhook delivery,
 * inbound callback handling, HMAC signatures, and timeout behavior.
 *
 * Strategy: We spin up a mock webhook receiver alongside the callback server,
 * so both sides of the flow are tested end-to-end.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import {
  WebhookApprovalChannel,
  signPayload,
  verifySignature,
} from "../../src/principal-policy/webhook.js";
import type { ApprovalRequest } from "../../src/principal-policy/types.js";

const WEBHOOK_SECRET = "test-webhook-secret-abc123";

function randomPort(): number {
  return 10000 + Math.floor(Math.random() * 50000);
}

// ── Mock Webhook Receiver ──────────────────────────────────────────────

interface ReceivedPayload {
  body: string;
  signature: string | undefined;
  requestId: string | undefined;
  parsed: Record<string, unknown>;
}

function createMockReceiver(port: number): {
  server: ReturnType<typeof createServer>;
  received: ReceivedPayload[];
  start: () => Promise<void>;
  stop: () => Promise<void>;
} {
  const received: ReceivedPayload[] = [];

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    let chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf-8");
      received.push({
        body,
        signature: req.headers["x-sanctuary-signature"] as string | undefined,
        requestId: req.headers["x-sanctuary-request-id"] as string | undefined,
        parsed: JSON.parse(body),
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
  });

  return {
    server,
    received,
    start: () =>
      new Promise((resolve) => {
        server.listen(port, "127.0.0.1", () => resolve());
      }),
    stop: () =>
      new Promise((resolve) => {
        server.close(() => resolve());
      }),
  };
}

// ── Tests ───────────────────────────────────────────────────────────────

describe("Webhook Approval Channel", () => {
  // ── HMAC Signature Helpers ─────────────────────────────────────────

  describe("HMAC Signatures", () => {
    it("signPayload produces hex string", () => {
      const sig = signPayload('{"test":true}', "secret");
      expect(sig).toMatch(/^[a-f0-9]{64}$/);
    });

    it("verifySignature accepts valid signature", () => {
      const body = '{"operation":"state_export"}';
      const sig = signPayload(body, "mysecret");
      expect(verifySignature(body, sig, "mysecret")).toBe(true);
    });

    it("verifySignature rejects wrong signature", () => {
      const body = '{"operation":"state_export"}';
      const sig = signPayload(body, "mysecret");
      expect(verifySignature(body, sig, "wrongsecret")).toBe(false);
    });

    it("verifySignature rejects tampered body", () => {
      const body = '{"operation":"state_export"}';
      const sig = signPayload(body, "mysecret");
      expect(verifySignature('{"operation":"state_delete"}', sig, "mysecret")).toBe(false);
    });
  });

  // ── Webhook Delivery ──────────────────────────────────────────────

  describe("Webhook Delivery", () => {
    let webhook: WebhookApprovalChannel;
    let receiver: ReturnType<typeof createMockReceiver>;
    let receiverPort: number;
    let callbackPort: number;

    beforeEach(async () => {
      receiverPort = randomPort();
      callbackPort = randomPort();

      receiver = createMockReceiver(receiverPort);
      await receiver.start();

      webhook = new WebhookApprovalChannel({
        webhook_url: `http://127.0.0.1:${receiverPort}/webhook`,
        webhook_secret: WEBHOOK_SECRET,
        callback_port: callbackPort,
        callback_host: "127.0.0.1",
        timeout_seconds: 2,
        auto_deny: true,
      });
      await webhook.start();
    });

    afterEach(async () => {
      await webhook.stop();
      await receiver.stop();
    });

    const makeRequest = (): ApprovalRequest => ({
      operation: "state_export",
      tier: 1,
      reason: "Tier 1 operation requires approval",
      context: { namespace: "test" },
      timestamp: new Date().toISOString(),
    });

    it("POSTs approval request to webhook URL", async () => {
      const request = makeRequest();
      // Start approval (will timeout, but we just check the outbound)
      const approvalPromise = webhook.requestApproval(request);

      // Wait briefly for the outbound POST
      await new Promise((r) => setTimeout(r, 200));

      expect(receiver.received).toHaveLength(1);
      const payload = receiver.received[0];
      expect(payload.parsed.operation).toBe("state_export");
      expect(payload.parsed.tier).toBe(1);
      expect(payload.parsed.callback_url).toContain(`/webhook/respond/`);
      expect(payload.parsed.timeout_seconds).toBe(2);

      // Let it timeout
      await approvalPromise;
    }, 5000);

    it("signs outbound payload with HMAC-SHA256", async () => {
      const request = makeRequest();
      const approvalPromise = webhook.requestApproval(request);

      await new Promise((r) => setTimeout(r, 200));

      expect(receiver.received).toHaveLength(1);
      const payload = receiver.received[0];
      expect(payload.signature).toBeDefined();
      expect(
        verifySignature(payload.body, payload.signature!, WEBHOOK_SECRET)
      ).toBe(true);

      await approvalPromise;
    }, 5000);

    it("includes X-Sanctuary-Request-Id header", async () => {
      const request = makeRequest();
      const approvalPromise = webhook.requestApproval(request);

      await new Promise((r) => setTimeout(r, 200));

      expect(receiver.received[0].requestId).toBeDefined();
      expect(receiver.received[0].requestId).toBe(
        receiver.received[0].parsed.request_id
      );

      await approvalPromise;
    }, 5000);

    it("auto-denies on timeout", async () => {
      const request = makeRequest();
      const response = await webhook.requestApproval(request);
      expect(response.decision).toBe("deny");
      expect(response.decided_by).toBe("timeout");
    }, 5000);
  });

  // ── Callback Handling ─────────────────────────────────────────────

  describe("Callback Handling", () => {
    let webhook: WebhookApprovalChannel;
    let receiver: ReturnType<typeof createMockReceiver>;
    let receiverPort: number;
    let callbackPort: number;

    beforeEach(async () => {
      receiverPort = randomPort();
      callbackPort = randomPort();

      receiver = createMockReceiver(receiverPort);
      await receiver.start();

      webhook = new WebhookApprovalChannel({
        webhook_url: `http://127.0.0.1:${receiverPort}/webhook`,
        webhook_secret: WEBHOOK_SECRET,
        callback_port: callbackPort,
        callback_host: "127.0.0.1",
        timeout_seconds: 5,
        auto_deny: true,
      });
      await webhook.start();
    });

    afterEach(async () => {
      await webhook.stop();
      await receiver.stop();
    });

    const makeRequest = (): ApprovalRequest => ({
      operation: "state_export",
      tier: 1,
      reason: "Test",
      context: {},
      timestamp: new Date().toISOString(),
    });

    async function sendCallback(
      requestId: string,
      decision: "approve" | "deny",
      secret: string = WEBHOOK_SECRET
    ): Promise<Response> {
      const body = JSON.stringify({ request_id: requestId, decision });
      const signature = signPayload(body, secret);
      return fetch(
        `http://127.0.0.1:${callbackPort}/webhook/respond/${requestId}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Sanctuary-Signature": signature,
          },
          body,
        }
      );
    }

    it("resolves approval on valid callback with approve", async () => {
      const request = makeRequest();
      const approvalPromise = webhook.requestApproval(request);

      // Wait for outbound delivery
      await new Promise((r) => setTimeout(r, 200));
      const requestId = receiver.received[0].parsed.request_id as string;

      // Send approve callback
      const res = await sendCallback(requestId, "approve");
      expect(res.status).toBe(200);

      const response = await approvalPromise;
      expect(response.decision).toBe("approve");
      expect(response.decided_by).toBe("human");
    });

    it("resolves approval on valid callback with deny", async () => {
      const request = makeRequest();
      const approvalPromise = webhook.requestApproval(request);

      await new Promise((r) => setTimeout(r, 200));
      const requestId = receiver.received[0].parsed.request_id as string;

      const res = await sendCallback(requestId, "deny");
      expect(res.status).toBe(200);

      const response = await approvalPromise;
      expect(response.decision).toBe("deny");
      expect(response.decided_by).toBe("human");
    });

    it("rejects callback with wrong signature", async () => {
      const request = makeRequest();
      const approvalPromise = webhook.requestApproval(request);

      await new Promise((r) => setTimeout(r, 200));
      const requestId = receiver.received[0].parsed.request_id as string;

      // Send with wrong secret
      const res = await sendCallback(requestId, "approve", "wrong-secret");
      expect(res.status).toBe(401);
      const data = await res.json();
      expect(data.error).toContain("Invalid signature");

      // Should still be pending (will timeout)
      expect(webhook.pendingCount).toBe(1);

      // Let it timeout
      const response = await approvalPromise;
      expect(response.decided_by).toBe("timeout");
    }, 10000);

    it("rejects callback for non-existent request ID", async () => {
      const body = JSON.stringify({
        request_id: "nonexistent",
        decision: "approve",
      });
      const signature = signPayload(body, WEBHOOK_SECRET);
      const res = await fetch(
        `http://127.0.0.1:${callbackPort}/webhook/respond/nonexistent`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Sanctuary-Signature": signature,
          },
          body,
        }
      );
      expect(res.status).toBe(404);
    });

    it("rejects callback with mismatched request_id in body vs URL", async () => {
      const request = makeRequest();
      const approvalPromise = webhook.requestApproval(request);

      await new Promise((r) => setTimeout(r, 200));
      const requestId = receiver.received[0].parsed.request_id as string;

      // Send with wrong request_id in body
      const body = JSON.stringify({
        request_id: "different-id",
        decision: "approve",
      });
      const signature = signPayload(body, WEBHOOK_SECRET);
      const res = await fetch(
        `http://127.0.0.1:${callbackPort}/webhook/respond/${requestId}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Sanctuary-Signature": signature,
          },
          body,
        }
      );
      expect(res.status).toBe(400);

      const response = await approvalPromise;
      expect(response.decided_by).toBe("timeout");
    }, 10000);

    it("health endpoint returns status", async () => {
      const res = await fetch(
        `http://127.0.0.1:${callbackPort}/health`
      );
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.status).toBe("ok");
      expect(typeof data.pending_count).toBe("number");
    });
  });

  // ── Auto-approve mode ─────────────────────────────────────────────

  describe("Auto-approve mode", () => {
    let webhook: WebhookApprovalChannel;
    let receiver: ReturnType<typeof createMockReceiver>;
    let receiverPort: number;
    let callbackPort: number;

    beforeEach(async () => {
      receiverPort = randomPort();
      callbackPort = randomPort();

      receiver = createMockReceiver(receiverPort);
      await receiver.start();

      webhook = new WebhookApprovalChannel({
        webhook_url: `http://127.0.0.1:${receiverPort}/webhook`,
        webhook_secret: WEBHOOK_SECRET,
        callback_port: callbackPort,
        callback_host: "127.0.0.1",
        timeout_seconds: 1,
        auto_deny: false, // auto-approve on timeout
      });
      await webhook.start();
    });

    afterEach(async () => {
      await webhook.stop();
      await receiver.stop();
    });

    it("auto-approves on timeout when auto_deny is false", async () => {
      const request: ApprovalRequest = {
        operation: "state_export",
        tier: 1,
        reason: "Test",
        context: {},
        timestamp: new Date().toISOString(),
      };
      const response = await webhook.requestApproval(request);
      expect(response.decision).toBe("approve");
      expect(response.decided_by).toBe("timeout");
    }, 5000);
  });

  // ── Cleanup ───────────────────────────────────────────────────────

  describe("Cleanup", () => {
    it("stop() resolves all pending as deny", async () => {
      const receiverPort = randomPort();
      const callbackPort = randomPort();

      const receiver = createMockReceiver(receiverPort);
      await receiver.start();

      const webhook = new WebhookApprovalChannel({
        webhook_url: `http://127.0.0.1:${receiverPort}/webhook`,
        webhook_secret: WEBHOOK_SECRET,
        callback_port: callbackPort,
        callback_host: "127.0.0.1",
        timeout_seconds: 10,
        auto_deny: true,
      });
      await webhook.start();

      const request: ApprovalRequest = {
        operation: "state_export",
        tier: 1,
        reason: "Test",
        context: {},
        timestamp: new Date().toISOString(),
      };
      const approvalPromise = webhook.requestApproval(request);

      // Wait for outbound
      await new Promise((r) => setTimeout(r, 200));
      expect(webhook.pendingCount).toBe(1);

      // Stop should resolve as deny
      await webhook.stop();
      const response = await approvalPromise;
      expect(response.decision).toBe("deny");
      expect(response.decided_by).toBe("auto");

      await receiver.stop();
    });
  });
});
