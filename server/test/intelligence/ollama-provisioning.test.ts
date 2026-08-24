import { describe, expect, it, vi } from "vitest";
import { OllamaClient } from "../../src/intelligence/substrates/local.js";

const HASH = "a".repeat(64);

describe("Ollama provisioning client", () => {
  it("pulls one exact tag with a bounded non-streaming request", async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ status: "success" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    }));
    const client = new OllamaClient({ endpoint: "http://127.0.0.1:11434/", fetchImpl: fetchImpl as typeof fetch });
    await expect(client.pull("qwen2.5:1.5b")).resolves.toEqual({ ok: true, failureClass: null });
    expect(fetchImpl).toHaveBeenCalledWith(
      "http://127.0.0.1:11434/api/pull",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ model: "qwen2.5:1.5b", stream: false }),
      }),
    );
  });

  it.each([
    [{ digest: `sha256:${HASH}` }, HASH],
    [{ details: { digest: HASH } }, HASH],
  ])("normalizes an exact SHA-256 show digest", async (body, expected) => {
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      fetchImpl: (async () => new Response(JSON.stringify(body), { status: 200 })) as typeof fetch,
    });
    await expect(client.show("qwen2.5:1.5b")).resolves.toEqual({
      ok: true,
      failureClass: null,
      digest: expected,
    });
  });

  it("reads the documented installed digest from the exact tags entry", async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ details: { format: "gguf" } }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        models: [
          { name: "other:latest", digest: "b".repeat(64) },
          { name: "qwen2.5:1.5b", model: "qwen2.5:1.5b", digest: HASH },
        ],
      }), { status: 200 }));
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      fetchImpl: fetchImpl as typeof fetch,
    });
    await expect(client.show("qwen2.5:1.5b")).resolves.toEqual({
      ok: true,
      failureClass: null,
      digest: HASH,
    });
    expect(fetchImpl).toHaveBeenNthCalledWith(
      2,
      "http://127.0.0.1:11434/api/tags",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("refuses a successful response that omits an exact digest", async () => {
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      fetchImpl: (async () => new Response(JSON.stringify({ details: {} }), { status: 200 })) as typeof fetch,
    });
    await expect(client.show("qwen2.5:1.5b")).resolves.toEqual({
      ok: false,
      failureClass: "substrate_misconfigured",
      digest: null,
    });
  });

  it("maps HTTP and transport failures without throwing", async () => {
    const httpClient = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      fetchImpl: (async () => new Response("model not found", { status: 404 })) as typeof fetch,
    });
    await expect(httpClient.show("missing:latest")).resolves.toMatchObject({
      ok: false,
      failureClass: "substrate_misconfigured",
    });
    const transportClient = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      fetchImpl: (async () => { throw new Error("offline"); }) as typeof fetch,
    });
    await expect(transportClient.pull("qwen2.5:1.5b")).resolves.toEqual({
      ok: false,
      failureClass: "substrate_unavailable",
    });
  });
});
