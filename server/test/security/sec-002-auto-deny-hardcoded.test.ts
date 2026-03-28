/**
 * Sanctuary MCP Server — SEC-002 Regression Test
 *
 * SEC-002: Webhook/Dashboard auto_deny: false inverts the approval gate.
 *
 * This test verifies that ALL approval channels unconditionally deny on
 * timeout, regardless of any configuration. No code path should allow
 * timeout to resolve as "approve."
 *
 * These tests would have FAILED before the SEC-002 fix was applied.
 */

import { describe, it, expect, afterEach } from "vitest";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { StderrApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import { WebhookApprovalChannel } from "../../src/principal-policy/webhook.js";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { parsePolicy, DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import type { ApprovalRequest } from "../../src/principal-policy/types.js";

function randomPort(): number {
  return 10000 + Math.floor(Math.random() * 50000);
}

const TIER_1_REQUEST: ApprovalRequest = {
  operation: "state_export",
  tier: 1,
  reason: "SEC-002 regression test",
  context: {},
  timestamp: new Date().toISOString(),
};

// ── Mock webhook receiver that never responds (forces timeout) ──────────

function createSilentReceiver(port: number) {
  const connections = new Set<import("node:net").Socket>();
  const server = createServer((_req: IncomingMessage, _res: ServerResponse) => {
    // Intentionally never respond — forces timeout
  });
  server.on("connection", (socket) => {
    connections.add(socket);
    socket.on("close", () => connections.delete(socket));
  });
  return {
    start: () => new Promise<void>((resolve) => server.listen(port, "127.0.0.1", resolve)),
    stop: () => new Promise<void>((resolve) => {
      // Destroy all open connections so close() can complete promptly
      for (const socket of connections) socket.destroy();
      server.close(() => resolve());
    }),
  };
}

// ── Tests ────────────────────────────────────────────────────────────────

describe("SEC-002: Approval gate timeout always denies", () => {

  // ── Stderr Channel ──────────────────────────────────────────────────

  describe("StderrApprovalChannel", () => {
    it("denies on timeout with default config", async () => {
      const channel = new StderrApprovalChannel({
        type: "stderr",
        timeout_seconds: 1,
      });
      const response = await channel.requestApproval(TIER_1_REQUEST);
      expect(response.decision).toBe("deny");
      expect(response.decided_by).toBe("timeout");
    });

    it("denies on timeout even if auto_deny is explicitly set to false", async () => {
      // Before SEC-002 fix, this would have returned "approve"
      const channel = new StderrApprovalChannel({
        type: "stderr",
        timeout_seconds: 1,
        auto_deny: false, // This must be ignored
      });
      const response = await channel.requestApproval(TIER_1_REQUEST);
      expect(response.decision).toBe("deny");
      expect(response.decided_by).toBe("timeout");
    });
  });

  // ── Webhook Channel ─────────────────────────────────────────────────

  describe("WebhookApprovalChannel", () => {
    let receiver: ReturnType<typeof createSilentReceiver>;
    let webhook: WebhookApprovalChannel;

    afterEach(async () => {
      if (webhook) await webhook.stop();
      if (receiver) await receiver.stop();
    }, 15000);

    it("denies on timeout even when auto_deny was historically false", async () => {
      const receiverPort = randomPort();
      const callbackPort = randomPort();

      receiver = createSilentReceiver(receiverPort);
      await receiver.start();

      // Before SEC-002 fix, passing auto_deny: false here would
      // cause timeout to resolve as "approve"
      webhook = new WebhookApprovalChannel({
        webhook_url: `http://127.0.0.1:${receiverPort}/webhook`,
        webhook_secret: "test-secret",
        callback_port: callbackPort,
        callback_host: "127.0.0.1",
        timeout_seconds: 1,
        auto_deny: false, // Must be ignored
      });
      await webhook.start();

      const response = await webhook.requestApproval(TIER_1_REQUEST);
      expect(response.decision).toBe("deny");
      expect(response.decided_by).toBe("timeout");
    }, 10000);

    it("denies on timeout with no auto_deny field", async () => {
      const receiverPort = randomPort();
      const callbackPort = randomPort();

      receiver = createSilentReceiver(receiverPort);
      await receiver.start();

      webhook = new WebhookApprovalChannel({
        webhook_url: `http://127.0.0.1:${receiverPort}/webhook`,
        webhook_secret: "test-secret",
        callback_port: callbackPort,
        callback_host: "127.0.0.1",
        timeout_seconds: 1,
      });
      await webhook.start();

      const response = await webhook.requestApproval(TIER_1_REQUEST);
      expect(response.decision).toBe("deny");
      expect(response.decided_by).toBe("timeout");
    }, 10000);
  });

  // ── Dashboard Channel ───────────────────────────────────────────────

  describe("DashboardApprovalChannel", () => {
    let dashboard: DashboardApprovalChannel;

    afterEach(async () => {
      if (dashboard) await dashboard.stop();
    });

    it("denies on timeout even when auto_deny was historically false", async () => {
      const port = randomPort();
      // Before SEC-002 fix, passing auto_deny: false would cause
      // timeout to resolve as "approve"
      dashboard = new DashboardApprovalChannel({
        port,
        host: "127.0.0.1",
        timeout_seconds: 1,
        auto_deny: false, // Must be ignored
      });
      await dashboard.start();

      const response = await dashboard.requestApproval(TIER_1_REQUEST);
      expect(response.decision).toBe("deny");
      expect(response.decided_by).toBe("timeout");
    }, 10000);

    it("denies on timeout with no auto_deny field", async () => {
      const port = randomPort();
      dashboard = new DashboardApprovalChannel({
        port,
        host: "127.0.0.1",
        timeout_seconds: 1,
      });
      await dashboard.start();

      const response = await dashboard.requestApproval(TIER_1_REQUEST);
      expect(response.decision).toBe("deny");
      expect(response.decided_by).toBe("timeout");
    }, 10000);
  });

  // ── Policy Parser ───────────────────────────────────────────────────

  describe("Policy parser strips auto_deny", () => {
    it("ignores auto_deny: false in YAML policy", () => {
      const yaml = `
version: 1
tier1_always_approve:
  - state_export
approval_channel:
  type: stderr
  timeout_seconds: 60
  auto_deny: false
`;
      const policy = parsePolicy(yaml);
      // auto_deny should be undefined (stripped) or true
      expect(policy.approval_channel.auto_deny).toBeUndefined();
    });

    it("ignores auto_deny: false in JSON policy", () => {
      const json = JSON.stringify({
        version: 1,
        tier1_always_approve: ["state_export"],
        approval_channel: { type: "stderr", auto_deny: false },
      });
      const policy = parsePolicy(json);
      expect(policy.approval_channel.auto_deny).toBeUndefined();
    });

    it("DEFAULT_POLICY does not set auto_deny", () => {
      // auto_deny should be absent from the default policy
      expect(DEFAULT_POLICY.approval_channel.auto_deny).toBeUndefined();
    });
  });
});
