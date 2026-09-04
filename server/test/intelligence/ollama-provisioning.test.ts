import { describe, expect, it, vi } from "vitest";
import {
  OllamaClient,
  type OllamaPullProgress,
} from "../../src/intelligence/substrates/local.js";

const HASH = "a".repeat(64);

const encoder = new TextEncoder();

/** An NDJSON body that releases one line per read, `gapMs` after it is asked. */
function drippingNdjson(lines: readonly string[], gapMs: number): Response {
  let index = 0;
  // The client cancels the reader on every exit path, so a line still in flight
  // when it refuses must not be pushed into an already-closed controller.
  let cancelled = false;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      return new Promise<void>((resolve) => {
        setTimeout(() => {
          if (!cancelled) {
            if (index >= lines.length) controller.close();
            else controller.enqueue(encoder.encode(`${lines[index++]}\n`));
          }
          resolve();
        }, gapMs);
      });
    },
    cancel() {
      cancelled = true;
    },
  });
  return new Response(body, { status: 200 });
}

/** An NDJSON body that emits `lines`, then stalls without ever closing. */
function stallingNdjson(lines: readonly string[]): Response {
  let emitted = false;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (emitted) return new Promise<void>(() => {});
      emitted = true;
      for (const line of lines) controller.enqueue(encoder.encode(`${line}\n`));
      return Promise.resolve();
    },
  });
  return new Response(body, { status: 200 });
}

describe("Ollama provisioning client", () => {
  it("pulls one exact tag as a stream and is not bounded by the request timeout", async () => {
    // The per-invocation timeout is set below any plausible pull duration: a
    // multi-gigabyte download must outlive it, which is exactly what a fixed
    // request wall clock on the pull would abort.
    const lines = [
      JSON.stringify({ status: "pulling manifest" }),
      JSON.stringify({ status: "pulling 12345", total: 1000, completed: 250 }),
      JSON.stringify({ status: "verifying sha256 digest" }),
      JSON.stringify({ status: "success" }),
    ];
    const fetchImpl = vi.fn(async () => drippingNdjson(lines, 25));
    const progress: OllamaPullProgress[] = [];
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434/",
      timeoutMs: 5,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    await expect(
      client.pull("qwen2.5:1.5b", { onProgress: (line) => progress.push(line) }),
    ).resolves.toEqual({ ok: true, failureClass: null });
    expect(fetchImpl).toHaveBeenCalledWith(
      "http://127.0.0.1:11434/api/pull",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ model: "qwen2.5:1.5b", stream: true }),
      }),
    );
    expect(progress.map((line) => line.status)).toEqual([
      "pulling manifest",
      "pulling 12345",
      "verifying sha256 digest",
      "success",
    ]);
    expect(progress[1]).toMatchObject({ total: 1000, completed: 250 });
  });

  it("refuses a stream that stops emitting progress lines", async () => {
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      pullInactivityTimeoutMs: 40,
      fetchImpl: (async () =>
        stallingNdjson([JSON.stringify({ status: "pulling manifest" })])) as unknown as typeof fetch,
    });
    await expect(client.pull("qwen2.5:1.5b")).resolves.toEqual({
      ok: false,
      failureClass: "substrate_timeout",
    });
  });

  it("refuses a stream that keeps reporting progress past the absolute ceiling", async () => {
    const forever = Array.from({ length: 1000 }, () => JSON.stringify({ status: "pulling 1" }));
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      pullInactivityTimeoutMs: 1_000,
      pullCeilingMs: 60,
      fetchImpl: (async () => drippingNdjson(forever, 5)) as unknown as typeof fetch,
    });
    await expect(client.pull("qwen2.5:1.5b")).resolves.toEqual({
      ok: false,
      failureClass: "substrate_timeout",
    });
  });

  it.each([
    ["pull model manifest: file does not exist", "substrate_misconfigured"],
    ["rate limit exceeded", "substrate_rate_limited"],
    ["registry connection reset", "substrate_unavailable"],
  ] as const)("fails closed on an in-stream error line (%s)", async (message, failureClass) => {
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      fetchImpl: (async () => drippingNdjson([
        JSON.stringify({ status: "pulling manifest" }),
        JSON.stringify({ error: message }),
        JSON.stringify({ status: "success" }),
      ], 0)) as unknown as typeof fetch,
    });
    await expect(client.pull("qwen2.5:1.5b")).resolves.toEqual({ ok: false, failureClass });
  });

  it("refuses a progress line past the reviewed byte cap", async () => {
    // 64 KiB is the reviewed per-line cap; one byte over it, with no newline, is
    // a runtime that is not speaking the NDJSON protocol this client reviewed.
    const oversized = `{"status":"${"p".repeat(64 * 1024 + 1)}"}`;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode(oversized));
      },
      pull() {
        return new Promise<void>(() => {});
      },
    });
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      pullInactivityTimeoutMs: 2_000,
      fetchImpl: (async () => new Response(body, { status: 200 })) as unknown as typeof fetch,
    });
    await expect(client.pull("qwen2.5:1.5b")).resolves.toEqual({
      ok: false,
      failureClass: "substrate_misconfigured",
    });
  });

  it("refuses a stream that ends without the runtime's own success line", async () => {
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      fetchImpl: (async () => drippingNdjson([
        JSON.stringify({ status: "pulling manifest" }),
        JSON.stringify({ status: "pulling 12345", total: 1000, completed: 400 }),
      ], 0)) as unknown as typeof fetch,
    });
    await expect(client.pull("qwen2.5:1.5b")).resolves.toEqual({
      ok: false,
      failureClass: "substrate_unavailable",
    });
  });

  it("refuses a line that is not the reviewed NDJSON shape", async () => {
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      fetchImpl: (async () => drippingNdjson([
        "not json at all",
        JSON.stringify({ status: "success" }),
      ], 0)) as unknown as typeof fetch,
    });
    await expect(client.pull("qwen2.5:1.5b")).resolves.toEqual({
      ok: false,
      failureClass: "substrate_misconfigured",
    });
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
