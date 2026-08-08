import { Writable } from "node:stream";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runConciergeCommand } from "../../src/cli/concierge.js";
import { writeTenantRuntime } from "../../src/cli/agents/runtime.js";

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
});
