import { Writable } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runConciergeCommand } from "../../src/cli/concierge.js";

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
});
