import { randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { IdentityManager } from "../../src/cognitive/tools.js";
import { buildV11Bindings } from "../../src/dashboard/v1_1/wiring.js";
import { handleHubRoute } from "../../src/hub/api-router.js";
import type { SubstrateSelector } from "../../src/intelligence/selector.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";

describe("daemon hub stateless concierge production graph", () => {
  let server: Server;
  let baseUrl: string;
  let invokeSummarize: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    const storage = new MemoryStorage();
    const masterKey = randomBytes(32);
    const auditLog = new AuditLog(storage, masterKey);
    invokeSummarize = vi.fn(async () => ({
      servedBy: "local" as const,
      failureClass: null,
      body: { kind: "summarize" as const, text: "The selector-backed hub answered." },
      completedAt: new Date().toISOString(),
      latencyMs: 2,
    }));
    const selector = {
      getSubstrate: vi.fn(async () => ({
        surface: "concierge" as const,
        substrate: "local" as const,
        badge: { surface: "concierge" as const, substrate: "local" as const, labelKey: "local", tradeoffKey: "local", status: "green" as const },
        capability: { summarize: true, classify: true, redact: true },
        displayLabel: "Local model - test",
      })),
      invokeSummarize,
      getOperatorVisibleStatus: vi.fn(async () => ({
        version: "1.2" as const,
        generatedAt: new Date().toISOString(),
        surfaces: [{
          surface: "concierge" as const,
          chosen: "local" as const,
          badge: { surface: "concierge" as const, substrate: "local" as const, labelKey: "local", tradeoffKey: "local", status: "green" as const },
          health: "ok" as const,
          failureClass: null,
          recentFailures: [],
        }],
        hardware: { totalRamGb: 16, cpuArch: "other" as const, tier: "mid" as const, recommendedLocalModel: "phi-4-mini" as const, ollamaReachable: true, ollamaModels: ["test"] },
      })),
      getConfig: () => ({ fallback: {
        concierge: "degrade-silent" as const,
        "direct-agent-gate-advisor": "conservative-deny" as const,
        "sentinel-scoring": "conservative-deny" as const,
        "gate-explanation": "degrade-silent" as const,
        "privacy-filter-tier-2": "degrade-silent" as const,
        "template-suggestion": "degrade-silent" as const,
      } }),
    } as unknown as SubstrateSelector;
    const identityManager = {
      listWithRotationCount: () => [],
      list: () => [],
    } as unknown as IdentityManager;
    const { hubService } = buildV11Bindings({
      identityId: "operator",
      fortressId: "fortress-test",
      auditLog,
      storagePath: "/tmp/concierge-selector-production-graph",
      storage,
      masterKey,
      identityManager,
      intelligenceSelector: selector,
    });

    server = createServer(async (req, res) => {
      const handled = await handleHubRoute(
        { authConfig: { loopbackAutoAuth: true }, service: hubService },
        req,
        res,
      );
      if (!handled) res.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("no address");
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  afterEach(async () => {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  });

  it("POST /api/hub/concierge/ask reaches selector.invokeSummarize without changing the envelope", async () => {
    const response = await fetch(`${baseUrl}/api/hub/concierge/ask`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question: "what is pending?", stream: false }),
    });
    const body = await response.json() as any;

    expect(response.status).toBe(200);
    expect(body).toMatchObject({
      ok: true,
      data: { response: { answer: "The selector-backed hub answered.", provider: "local", model: "Local model - test" } },
    });
    expect(invokeSummarize).toHaveBeenCalledWith(
      "concierge",
      expect.objectContaining({ kind: "summarize", query: "what is pending?" }),
    );
  });

  it("GET /api/hub/concierge/status preserves the status envelope with honest selector state", async () => {
    const response = await fetch(`${baseUrl}/api/hub/concierge/status`);
    const body = await response.json() as any;

    expect(response.status).toBe(200);
    expect(body.data.status).toMatchObject({
      provider: "local",
      configured: true,
      reachable: true,
      fallback: "degrade-silent",
      model: "Local model - test",
    });
  });
});
