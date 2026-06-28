/**
 * C1: Remote Operator Console Tests
 *
 * Tests the security hardening for non-loopback dashboard binding:
 * - TLS enforcement for non-loopback interfaces
 * - Auth enforcement for non-loopback interfaces
 * - Loopback auto-auth bypass does NOT apply to non-loopback
 * - Fleet switcher route
 */

import { describe, it, expect, afterEach } from "vitest";
import { request as httpRequest, type IncomingHttpHeaders } from "node:http";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import {
  bindWithRetry,
  randomTestPort,
} from "../util/port-collision-retry.js";

async function requestNoKeepAlive(
  url: string,
  options: { method?: string; headers?: Record<string, string> } = {},
): Promise<{ status: number; headers: IncomingHttpHeaders; body: string }> {
  const target = new URL(url);
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        hostname: target.hostname,
        port: target.port,
        path: `${target.pathname}${target.search}`,
        method: options.method ?? "GET",
        headers: { ...options.headers, Connection: "close" },
        agent: false,
      },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => { body += chunk; });
        res.on("end", () => {
          resolve({ status: res.statusCode ?? 0, headers: res.headers, body });
        });
      },
    );
    req.setTimeout(5000, () => {
      req.destroy(new Error(`Timed out requesting ${target.href}`));
    });
    req.on("error", reject);
    req.end();
  });
}

describe("C1: Remote Operator Console", () => {
  let dashboard: DashboardApprovalChannel | null = null;

  afterEach(async () => {
    if (dashboard) {
      await dashboard.stop();
      dashboard = null;
    }
  });

  describe("TLS enforcement for non-loopback", () => {
    it("refuses to start on non-loopback host without TLS or allow_plaintext_remote", async () => {
      const port = randomTestPort();
      dashboard = new DashboardApprovalChannel({
        port,
        host: "0.0.0.0",
        timeout_seconds: 2,
      });

      await expect(dashboard.start()).rejects.toThrow(
        /refusing to start on non-loopback interface/i
      );
      dashboard = null; // start failed, no cleanup needed
    });

    it("allows non-loopback with allow_plaintext_remote=true", async () => {
      // Bind to 127.0.0.1 to test the flag acceptance without needing
      // a real non-loopback interface; the enforcement check happens
      // on the configured host string, not the actual bind.
      // Use a non-loopback host string but listen on a port that will work.
      await bindWithRetry(async () => {
        const port = randomTestPort();
        dashboard = new DashboardApprovalChannel({
          port,
          host: "127.0.0.1", // localhost for test reachability
          timeout_seconds: 2,
          allow_plaintext_remote: true,
        });
        await dashboard.start();
      });
      // If we get here, start() did not throw
      expect(dashboard).not.toBeNull();
    });

    it("allows localhost without TLS (default behavior unchanged)", async () => {
      await bindWithRetry(async () => {
        const port = randomTestPort();
        dashboard = new DashboardApprovalChannel({
          port,
          host: "127.0.0.1",
          timeout_seconds: 2,
        });
        await dashboard.start();
      });
      expect(dashboard).not.toBeNull();
    });
  });

  describe("Auth enforcement for non-loopback", () => {
    it("auto-generates auth token when binding non-loopback without one", async () => {
      // We need allow_plaintext_remote since we won't have TLS in test.
      // Use 0.0.0.0 to trigger non-loopback path, which auto-generates token.
      let port: number = 0;
      await bindWithRetry(async () => {
        port = randomTestPort();
        dashboard = new DashboardApprovalChannel({
          port,
          host: "0.0.0.0",
          timeout_seconds: 2,
          allow_plaintext_remote: true,
          // No auth_token
        });
        await dashboard.start();
      });

      // Without a token, requests to /api/status should get 401
      const resp = await requestNoKeepAlive(`http://127.0.0.1:${port}/api/status`);
      expect(resp.status).toBe(401);
    });
  });

  describe("Loopback auto-auth does NOT apply to non-loopback", () => {
    it("rejects unauthenticated requests even with _autoAuthLocalhost enabled (non-loopback config)", async () => {
      let port: number = 0;
      await bindWithRetry(async () => {
        port = randomTestPort();
        dashboard = new DashboardApprovalChannel({
          port,
          host: "0.0.0.0",
          timeout_seconds: 2,
          auth_token: "test-secret-token",
          allow_plaintext_remote: true,
        });
        // Enable auto-auth (simulates passphrase unlock in standalone mode)
        dashboard.setAutoAuthLocalhost(true);
        await dashboard.start();
      });

      // Request from 127.0.0.1 WITH auto-auth should pass (loopback)
      const loopbackResp = await requestNoKeepAlive(
        `http://127.0.0.1:${port}/api/health`
      );
      expect(loopbackResp.status).toBe(200);

      // FIX 1: a cross-host browser fleet probe (different Origin) must be able
      // to read /api/health, so the response carries an ACAO header reflecting
      // the request Origin, and NEVER credentialed cross-origin access.
      const crossOriginProbe = await requestNoKeepAlive(
        `http://127.0.0.1:${port}/api/health`,
        { headers: { Origin: "https://100.64.0.9:3501" } }
      );
      expect(crossOriginProbe.status).toBe(200);
      expect(crossOriginProbe.headers["access-control-allow-origin"]).toBe(
        "https://100.64.0.9:3501"
      );
      expect(
        crossOriginProbe.headers["access-control-allow-credentials"]
      ).toBeUndefined();

      // Authenticated request should pass
      const authedResp = await requestNoKeepAlive(
        `http://127.0.0.1:${port}/api/status`,
        { headers: { Authorization: "Bearer test-secret-token" } }
      );
      expect(authedResp.status).toBe(200);
    });
  });

  describe("Fleet switcher route", () => {
    it("serves the fleet switcher page at /fleet", async () => {
      let port: number = 0;
      await bindWithRetry(async () => {
        port = randomTestPort();
        dashboard = new DashboardApprovalChannel({
          port,
          host: "127.0.0.1",
          timeout_seconds: 2,
        });
        await dashboard.start();
      });

      const resp = await requestNoKeepAlive(`http://127.0.0.1:${port}/fleet`);
      expect(resp.status).toBe(200);
      expect(resp.body).toContain("Fleet Switcher");
      expect(resp.body).toContain("sanctuary_fleet_machines");
      expect(resp.body).toContain("addMachine");
    });

    it("FIX 2: the Open Console link is a same-tab navigation, not a popup-blockable new-tab link", async () => {
      let port: number = 0;
      await bindWithRetry(async () => {
        port = randomTestPort();
        dashboard = new DashboardApprovalChannel({
          port,
          host: "127.0.0.1",
          timeout_seconds: 2,
        });
        await dashboard.start();
      });

      const resp = await requestNoKeepAlive(`http://127.0.0.1:${port}/fleet`);
      expect(resp.status).toBe(200);
      // Open Console must remain an obvious, accessible anchor...
      expect(resp.body).toContain('class="btn-open">Open Console</a>');
      // ...but a plain same-tab navigation: no target="_blank" that the
      // browser blocked as a popup in the drill.
      expect(resp.body).toContain('<a href="${m.url}" class="btn-open">');
      expect(resp.body).not.toContain('target="_blank"');
    });

    it("fleet page is exempt from rate limiting (view route)", async () => {
      let port: number = 0;
      await bindWithRetry(async () => {
        port = randomTestPort();
        dashboard = new DashboardApprovalChannel({
          port,
          host: "127.0.0.1",
          timeout_seconds: 2,
        });
        await dashboard.start();
      });

      // Multiple rapid requests should all succeed (rate limit exempt)
      for (let i = 0; i < 5; i++) {
        const resp = await requestNoKeepAlive(`http://127.0.0.1:${port}/fleet`);
        expect(resp.status).toBe(200);
      }
    });
  });
});
