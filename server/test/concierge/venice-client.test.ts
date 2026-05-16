import { describe, expect, it, vi } from "vitest";
import { ConciergeUnavailableError, VeniceClient } from "../../src/concierge/index.js";

describe("VeniceClient", () => {
  it("sends non-streaming chat completions without exposing the API key", async () => {
    const fetchImpl = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      expect((init!.headers as Headers).get("Authorization")).toBe("Bearer test-key");
      return new Response(JSON.stringify({
        choices: [{ message: { content: "There are 2 pending approvals." } }],
      }), { status: 200 });
    }) as unknown as typeof fetch;
    const client = new VeniceClient({ apiKey: "test-key", model: "venice-test", fetchImpl });

    await expect(client.complete({
      stream: false,
      messages: [{ role: "user", content: "hello" }],
    })).resolves.toBe("There are 2 pending approvals.");
  });

  it("throws a typed unavailable error when Venice is unreachable", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error("network down");
    }) as unknown as typeof fetch;
    const client = new VeniceClient({ apiKey: "test-key", fetchImpl, maxRetries: 0 });

    await expect(client.complete({
      stream: false,
      messages: [{ role: "user", content: "hello" }],
    })).rejects.toBeInstanceOf(ConciergeUnavailableError);
  });
});
