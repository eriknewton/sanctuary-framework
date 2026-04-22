/**
 * WP-MVP-11 Follow-up #1 — X-Miner 10-minute SLA acceptance test.
 *
 * Exercises the full operator-visible scaffolding path:
 *   1. Boot the dashboard against a clean fortress
 *   2. Fetch GET /api/templates (template picker)
 *   3. Pick X-Miner: GET /api/templates/x-miner
 *   4. POST /api/templates/x-miner/init with realistic payload
 *   5. Assert: agent scaffolds, signed policy_update event emits,
 *      response includes attestation panel URL
 *   6. Entire path under 600 seconds wall clock
 */

import { describe, it, expect } from "vitest";
import { createServer, type Server } from "node:http";
import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "@noble/hashes/utils";
import { handleRequest, type APIDeps } from "../../src/dashboard/api.js";
import { getProtectionSnapshot } from "../../src/dashboard/aggregator.js";

// ── Test fixtures ────────────────────────────────────────────────────

function makeNodeKey() {
  const priv = ed25519.utils.randomPrivateKey();
  return { privateKey: priv, publicKey: ed25519.getPublicKey(priv) };
}

const NODE_KEY = makeNodeKey();
const TEST_FORTRESS = "fortress-sla-" + randomBytes(4).reduce((s, b) => s + b.toString(16).padStart(2, "0"), "");

function makeDeps(): APIDeps {
  return {
    sources: {
      mode: "tier_1_private" as const,
    } as APIDeps["sources"],
    nodeId: "sla-test-node",
    nodePrivateKey: NODE_KEY.privateKey,
    principalId: "sla-test-principal",
    fortressId: TEST_FORTRESS,
  };
}

// ── Lightweight HTTP test helper ─────────────────────────────────────

async function startServer(deps: APIDeps): Promise<{ server: Server; port: number }> {
  return new Promise((resolve) => {
    const server = createServer(async (req, res) => {
      const handled = await handleRequest(deps, req, res);
      if (!handled) {
        res.writeHead(404);
        res.end();
      }
    });
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      resolve({ server, port });
    });
  });
}

async function fetchJSON(port: number, path: string, options?: RequestInit) {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, options);
  return { status: res.status, body: await res.json() };
}

// ── SLA test ─────────────────────────────────────────────────────────

describe("WP-MVP-11 Follow-up #1: X-Miner 10-minute SLA", () => {
  it("full scaffolding path completes under 600 seconds", async () => {
    const startTime = Date.now();
    const deps = makeDeps();
    const { server, port } = await startServer(deps);

    try {
      // Step 1: Fetch template list (template picker)
      const listRes = await fetchJSON(port, "/api/templates");
      expect(listRes.status).toBe(200);
      expect(listRes.body.templates).toBeDefined();
      expect(Array.isArray(listRes.body.templates)).toBe(true);

      // Verify x-miner is in the list
      const xMiner = listRes.body.templates.find(
        (t: { metadata: { name: string } }) => t.metadata.name === "x-miner"
      );
      expect(xMiner).toBeDefined();
      expect(xMiner.metadata.channel).toBe("read-outputs-only");
      expect(xMiner.metadata.tier).toBe("B");

      // Step 2: Fetch X-Miner details (scaffold-config form)
      const detailRes = await fetchJSON(port, "/api/templates/x-miner");
      expect(detailRes.status).toBe(200);
      expect(detailRes.body.metadata.name).toBe("x-miner");
      expect(detailRes.body.onboarding).toContain("xAI Grok API");

      // Step 3: POST init (scaffold button)
      const initRes = await fetchJSON(port, "/api/templates/x-miner/init", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          agent_name: "my-x-miner",
          model_provider: "xai",
        }),
      });
      expect(initRes.status).toBe(200);
      expect(initRes.body.agent_id).toBe("my-x-miner");
      expect(initRes.body.signed_event_id).toBeDefined();
      expect(initRes.body.signed_event_id.length).toBeGreaterThan(0);
      expect(initRes.body.policy_version).toBe(1);
      expect(initRes.body.template_name).toBe("x-miner");
      expect(initRes.body.attestation_panel_url).toContain("agent_roster");

      // Step 4: Wall-clock assertion
      const elapsed = Date.now() - startTime;
      expect(elapsed).toBeLessThan(600_000);
    } finally {
      server.close();
    }
  });

  it("github-miner also scaffolds through the same path", async () => {
    const deps = makeDeps();
    const { server, port } = await startServer(deps);

    try {
      const initRes = await fetchJSON(port, "/api/templates/github-miner/init", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          agent_name: "my-github-miner",
          model_provider: "anthropic",
        }),
      });
      expect(initRes.status).toBe(200);
      expect(initRes.body.agent_id).toBe("my-github-miner");
      expect(initRes.body.signed_event_id).toBeDefined();
      expect(initRes.body.template_name).toBe("github-miner");
    } finally {
      server.close();
    }
  });

  it("rejects init with missing agent_name", async () => {
    const deps = makeDeps();
    const { server, port } = await startServer(deps);

    try {
      const res = await fetchJSON(port, "/api/templates/x-miner/init", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model_provider: "xai" }),
      });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("validation_error");
    } finally {
      server.close();
    }
  });

  it("rejects init with invalid agent_name characters", async () => {
    const deps = makeDeps();
    const { server, port } = await startServer(deps);

    try {
      const res = await fetchJSON(port, "/api/templates/x-miner/init", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          agent_name: "bad agent name!",
          model_provider: "xai",
        }),
      });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("validation_error");
    } finally {
      server.close();
    }
  });

  it("returns 404 for unknown template init", async () => {
    const deps = makeDeps();
    const { server, port } = await startServer(deps);

    try {
      const res = await fetchJSON(port, "/api/templates/nonexistent/init", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent_name: "test", model_provider: "xai" }),
      });
      expect(res.status).toBe(404);
      expect(res.body.error).toBe("template_not_found");
    } finally {
      server.close();
    }
  });
});
