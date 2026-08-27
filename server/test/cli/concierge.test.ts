import { Writable } from "node:stream";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runConciergeCommand } from "../../src/cli/concierge.js";
import { writeTenantRuntime } from "../../src/cli/agents/runtime.js";
import { ConciergeService, type ConciergeContextBundle } from "../../src/concierge/index.js";

class CaptureStream extends Writable {
  value = "";
  override _write(chunk: Buffer | string, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.value += chunk.toString();
    callback();
  }
}

describe("sanctuary concierge CLI", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.SANCTUARY_DASHBOARD_URL;
    delete process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
  });

  it("prints a non-streaming ask response from the hub route", async () => {
    process.env.SANCTUARY_DASHBOARD_URL = "http://127.0.0.1:3502";
    vi.stubGlobal("fetch", vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      expect(JSON.parse(String(init!.body)).question).toBe("how many pending approvals?");
      return new Response(JSON.stringify({
        ok: true,
        data: {
          response: {
            answer: "There are 2 pending approvals.",
            model: "venice-test",
            provider: "venice",
            read_surfaces: ["audit_log"],
            context: {},
          },
        },
      }), { status: 200 });
    }));
    const out = new CaptureStream();
    const err = new CaptureStream();

    const code = await runConciergeCommand({
      argv: ["ask", "how many pending approvals?", "--no-stream"],
      out,
      err,
    });

    expect(code).toBe(0);
    expect(out.value).toContain("There are 2 pending approvals.");
    expect(err.value).toBe("");
  });

  it("prints status as JSON", async () => {
    process.env.SANCTUARY_DASHBOARD_URL = "http://127.0.0.1:3502";
    vi.stubGlobal("fetch", vi.fn(async () =>
      new Response(JSON.stringify({
        ok: true,
        data: {
          status: {
            provider: "venice",
            configured: true,
            reachable: true,
            model: "venice-test",
            read_surfaces: ["audit_log"],
            fallback: "none",
            message: "ok",
          },
        },
      }), { status: 200 }),
    ));
    const out = new CaptureStream();

    const code = await runConciergeCommand({
      argv: ["status", "--json"],
      out,
      err: new CaptureStream(),
    });

    expect(code).toBe(0);
    expect(JSON.parse(out.value).reachable).toBe(true);
  });

  it("routes --fortress=<path> through that fortress runtime", async () => {
    const scopedFortress = await mkdtemp(join(tmpdir(), "sanctuary-concierge-scoped-"));
    const originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    try {
      await writeTenantRuntime(scopedFortress, {
        version: "test",
        pid: process.pid,
        started_at: new Date().toISOString(),
        dashboard_host: "127.0.0.1",
        dashboard_port: 3503,
        mode: "standalone",
      });
      const fetchSpy = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
        expect(String(url)).toBe("http://127.0.0.1:3503/api/hub/concierge/ask");
        expect(JSON.parse(String(init!.body)).question).toBe("scoped?");
        return new Response(JSON.stringify({
          ok: true,
          data: {
            response: {
              answer: "Scoped runtime answered.",
              model: "venice-test",
              provider: "venice",
              read_surfaces: ["audit_log"],
              context: {},
            },
          },
        }), { status: 200 });
      });
      vi.stubGlobal("fetch", fetchSpy);
      const out = new CaptureStream();
      const err = new CaptureStream();

      const code = await runConciergeCommand({
        argv: ["ask", "scoped?", "--no-stream", `--fortress=${scopedFortress}`],
        out,
        err,
      });

      expect(code).toBe(0);
      expect(out.value).toContain("Scoped runtime answered.");
      expect(err.value).toBe("");
      expect(fetchSpy).toHaveBeenCalledOnce();
    } finally {
      if (originalStoragePath === undefined) {
        delete process.env.SANCTUARY_STORAGE_PATH;
      } else {
        process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
      }
      await rm(scopedFortress, { recursive: true, force: true });
    }
  });

  it("routes local mode through the selector-backed concierge service", async () => {
    const invokeSummarize = vi.fn(async () => ({
      servedBy: "local" as const,
      failureClass: null,
      body: { kind: "summarize" as const, text: "Local selector answered." },
      completedAt: new Date().toISOString(),
      latencyMs: 1,
    }));
    const localContext: ConciergeContextBundle = {
      generated_at: new Date().toISOString(),
      read_surfaces: ["audit_log", "identity_registry", "approval_inbox", "sovereignty_profile", "task_state", "state_store"],
      audit_log: { total_matching: 0, entries: [], integrity_findings: [] },
      identity_registry: { identities: [] },
      approval_inbox: { pending_count: 1, items: [] },
      sovereignty_profile: { fortress_id: "local", tier_policy: "local", context_gating_state: "local", castle_wall: { dashboard_enabled: false } },
      task_state: { total: 0, status_counts: { pending: 0, in_progress: 0, blocked: 0, ready_for_review: 0, completed: 0, cancelled: 0 }, tasks: [], recent_activity: [] },
      state_store: { include_payloads: false, namespaces: [] },
    };
    const service = new ConciergeService({
      reader: { readContext: async () => localContext },
      selector: {
        getSubstrate: async () => ({ surface: "concierge", substrate: "local", badge: { surface: "concierge", substrate: "local", labelKey: "local", tradeoffKey: "local", status: "green" }, capability: { summarize: true, classify: true, redact: true }, displayLabel: "Local model - test" }),
        invokeSummarize,
        getOperatorVisibleStatus: async () => ({ version: "1.2", generatedAt: new Date().toISOString(), surfaces: [], hardware: { totalRamGb: 16, cpuArch: "other", tier: "mid", recommendedLocalModel: "phi-4-mini", ollamaReachable: true, ollamaModels: ["test"] } }),
        getConfig: () => ({ fallback: { concierge: "degrade-silent", "direct-agent-gate-advisor": "conservative-deny", "sentinel-scoring": "conservative-deny", "gate-explanation": "degrade-silent", "privacy-filter-tier-2": "degrade-silent", "template-suggestion": "degrade-silent" } }),
      },
    });
    const out = new CaptureStream();

    const code = await runConciergeCommand({
      argv: ["ask", "local status?", "--no-stream"],
      out,
      err: new CaptureStream(),
      localServiceFactory: async () => service,
    });

    expect(code).toBe(0);
    expect(out.value).toContain("Local selector answered.");
    expect(invokeSummarize).toHaveBeenCalledWith(
      "concierge",
      expect.objectContaining({ query: "local status?" }),
    );
  });
});
