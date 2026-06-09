import { afterEach, describe, expect, it, vi } from "vitest";

import { dashboardRequest } from "../../src/cli/dashboard-request.js";

function jsonResponse(
  status: number,
  body: unknown,
): Pick<Response, "ok" | "status" | "json"> {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  };
}

describe("dashboardRequest", () => {
  const originalDashboardUrl = process.env.SANCTUARY_DASHBOARD_URL;
  const originalDashboardToken = process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;

  afterEach(() => {
    vi.unstubAllGlobals();
    if (originalDashboardUrl === undefined) {
      delete process.env.SANCTUARY_DASHBOARD_URL;
    } else {
      process.env.SANCTUARY_DASHBOARD_URL = originalDashboardUrl;
    }
    if (originalDashboardToken === undefined) {
      delete process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
    } else {
      process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = originalDashboardToken;
    }
  });

  it("sends JSON requests to the configured dashboard with auth", async () => {
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "token-123";
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse(200, { ok: true, value: 42 }) as Response);
    vi.stubGlobal("fetch", fetchMock);

    const body = await dashboardRequest(
      "/api/task",
      {
        method: "POST",
        headers: { "X-Test": "kept" },
        body: JSON.stringify({ name: "demo" }),
      },
      { dashboardUrl: "http://127.0.0.1:4500/" },
    );

    expect(body).toEqual({ ok: true, value: 42 });
    expect(fetchMock).toHaveBeenCalledWith(
      "http://127.0.0.1:4500/api/task",
      expect.objectContaining({ method: "POST" }),
    );
    const headers = fetchMock.mock.calls[0]?.[1]?.headers as Headers;
    expect(headers.get("Accept")).toBe("application/json");
    expect(headers.get("Content-Type")).toBe("application/json");
    expect(headers.get("Authorization")).toBe("Bearer token-123");
    expect(headers.get("X-Test")).toBe("kept");
  });

  it("uses the environment dashboard URL when no context URL is provided", async () => {
    process.env.SANCTUARY_DASHBOARD_URL = "http://dashboard.local:7777/";
    delete process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse(200, { ok: true }) as Response);
    vi.stubGlobal("fetch", fetchMock);

    await dashboardRequest("/api/inbox");

    expect(fetchMock.mock.calls[0]?.[0]).toBe("http://dashboard.local:7777/api/inbox");
    const headers = fetchMock.mock.calls[0]?.[1]?.headers as Headers;
    expect(headers.get("Authorization")).toBeNull();
    expect(headers.get("Content-Type")).toBeNull();
  });

  it("classifies dashboard HTTP failures with endpoint-specific hints", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(
        jsonResponse(404, { ok: false, detail: "missing route" }) as Response,
      );
    vi.stubGlobal("fetch", fetchMock);

    await expect(dashboardRequest("/api/missing")).rejects.toThrow(
      "endpoint not implemented in this build (HTTP 404): missing route. Hint: verify the dashboard exposes /api/missing, or upgrade/restart Sanctuary dashboard.",
    );
  });

  it("wraps network failures with setup guidance and nested cause detail", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockRejectedValue(
      new Error("fetch failed", { cause: new Error("ECONNREFUSED") }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(dashboardRequest("/api/task")).rejects.toThrow(
      "network/connection failure: fetch failed; cause: ECONNREFUSED. Hint: start the Sanctuary dashboard, verify --fortress runtime, or set SANCTUARY_DASHBOARD_URL to a reachable endpoint.",
    );
  });
});
