import type { IncomingMessage, ServerResponse } from "node:http";
import { describe, expect, it, vi } from "vitest";

import { handleDashboardV11Route } from "../../../src/dashboard/v1_1/routes.js";

function mockRequest(method?: string): IncomingMessage {
  return { method } as IncomingMessage;
}

function mockResponse(): ServerResponse {
  return {
    writeHead: vi.fn(),
    end: vi.fn(),
  } as unknown as ServerResponse;
}

describe("handleDashboardV11Route", () => {
  it("renders the v1.1 dashboard shell for GET requests", () => {
    const res = mockResponse();

    const served = handleDashboardV11Route(
      { sanctuaryVersion: "9.9.9-route-test", embedClient: false },
      mockRequest("GET"),
      res,
    );

    expect(served).toBe(true);
    expect(res.writeHead).toHaveBeenCalledWith(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    });
    expect(res.end).toHaveBeenCalledTimes(1);
    const html = vi.mocked(res.end).mock.calls[0]?.[0];
    expect(String(html)).toContain("<!doctype html>");
    expect(String(html)).toContain("9.9.9-route-test");
  });

  it("treats a missing method as GET", () => {
    const res = mockResponse();

    const served = handleDashboardV11Route(
      { embedClient: false },
      mockRequest(),
      res,
    );

    expect(served).toBe(true);
    expect(res.writeHead).toHaveBeenCalledOnce();
    expect(res.end).toHaveBeenCalledOnce();
  });

  it("declines non-GET requests without writing a response", () => {
    const res = mockResponse();

    const served = handleDashboardV11Route(
      { embedClient: false },
      mockRequest("POST"),
      res,
    );

    expect(served).toBe(false);
    expect(res.writeHead).not.toHaveBeenCalled();
    expect(res.end).not.toHaveBeenCalled();
  });
});
