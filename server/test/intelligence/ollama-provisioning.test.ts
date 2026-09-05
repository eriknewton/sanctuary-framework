import { describe, expect, it, vi } from "vitest";
import {
  OllamaClient,
  type OllamaPullProgress,
} from "../../src/intelligence/substrates/local.js";
import { SubstrateSelector } from "../../src/intelligence/selector.js";
import { INTEL_OPS } from "../../src/intelligence/audit-events.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

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

  it.each([
    ["a partial line past the cap", false],
    // A newline does not exempt a line from the cap: without the terminated-line
    // check such a line is parsed as progress, refreshes the inactivity
    // deadline, and can repeat up to the whole-response cap.
    ["a newline-terminated line past the cap", true],
  ])("refuses %s", async (_label, terminated) => {
    // 100 KiB of status text is well past the 64 KiB reviewed per-line cap.
    const oversized = `{"status":"${"p".repeat(100 * 1024)}"}${terminated ? "\n" : ""}`;
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

  it("refuses one chunk larger than the pending-buffer cap before decoding it", async () => {
    // 2 MiB in a single chunk exceeds the 1 MiB pending-buffer bound, so it is
    // refused before it is ever decoded or appended.
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(2 * 1024 * 1024).fill(0x61));
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

  it("accepts one chunk carrying many complete lines at once", async () => {
    // The per-line cap must not become a per-CHUNK cap: a transport read can
    // legitimately deliver a burst of complete lines in one chunk.
    const burst = Array.from(
      { length: 500 },
      (_v, index) => JSON.stringify({ status: `pulling ${index}`, total: 500, completed: index }),
    ).join("\n");
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode(`${burst}\n`));
        controller.enqueue(encoder.encode(`${JSON.stringify({ status: "success" })}\n`));
        controller.close();
      },
    });
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      fetchImpl: (async () => new Response(body, { status: 200 })) as unknown as typeof fetch,
    });
    await expect(client.pull("qwen2.5:1.5b")).resolves.toEqual({
      ok: true,
      failureClass: null,
    });
  });

  it("refuses an HTTP error whose body never ends, inside the inactivity deadline", async () => {
    // `res.text()` on an error body the runtime never ends would hold the pull,
    // and the provisioning lock it runs under, open forever.
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode("internal error: "));
      },
      pull() {
        return new Promise<void>(() => {});
      },
      cancel() {
        cancelled = true;
      },
    });
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      pullInactivityTimeoutMs: 60,
      fetchImpl: (async () => new Response(body, { status: 500 })) as unknown as typeof fetch,
    });
    const startedAt = Date.now();
    await expect(client.pull("qwen2.5:1.5b")).resolves.toEqual({
      ok: false,
      failureClass: "substrate_unavailable",
    });
    // Bounded by the inactivity deadline (60 ms), with generous slack for a
    // loaded machine; the pre-fix path never returned at all.
    expect(Date.now() - startedAt).toBeLessThan(5_000);
    expect(cancelled).toBe(true);
  });

  it("reads a bounded error snippet and still classifies a model-not-found refusal", async () => {
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      pullInactivityTimeoutMs: 2_000,
      fetchImpl: (async () =>
        new Response("model \'missing\' not found", { status: 404 })) as unknown as typeof fetch,
    });
    await expect(client.pull("missing:latest")).resolves.toEqual({
      ok: false,
      failureClass: "substrate_misconfigured",
    });
  });

  it("flushes the decoder so truncated trailing bytes cannot read as success", async () => {
    // The stream ends with a complete success line followed by the first two
    // bytes of a three-byte UTF-8 sequence. Dropping that unflushed remainder
    // would leave a syntactically perfect success line and report a TRUNCATED
    // stream as a finished pull; flushing surfaces the replacement character,
    // the line fails the parser, and the pull fails closed.
    const head = encoder.encode(`${JSON.stringify({ status: "success" })}`);
    const truncated = new Uint8Array([...head, 0xe2, 0x82]);
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(truncated);
        controller.close();
      },
    });
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      fetchImpl: (async () => new Response(body, { status: 200 })) as unknown as typeof fetch,
    });
    await expect(client.pull("qwen2.5:1.5b")).resolves.toEqual({
      ok: false,
      failureClass: "substrate_misconfigured",
    });
  });

  it("caps an enormous error body before decoding it", async () => {
    // 4 MiB in the FIRST read, with the classifying phrase placed a megabyte in,
    // far past the 8 KiB snippet cap. The snippet is not directly observable, so
    // the cap is proven through the classification: if the whole chunk were
    // decoded before the cap was noticed, the phrase would be in the snippet and
    // the refusal would read `substrate_misconfigured`.
    const filler = "x".repeat(1024 * 1024);
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode(`${filler}model 'missing' not found${"y".repeat(3 * 1024 * 1024)}`));
        controller.close();
      },
    });
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      pullInactivityTimeoutMs: 2_000,
      fetchImpl: (async () => new Response(body, { status: 404 })) as unknown as typeof fetch,
    });
    await expect(client.pull("missing:latest")).resolves.toEqual({
      ok: false,
      failureClass: "substrate_capability_unsupported",
    });

    // Control: the same phrase INSIDE the cap is still read, so the cap is a
    // bound on the snippet, not a refusal to classify.
    const shortBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode("model 'missing' not found"));
        controller.close();
      },
    });
    const shortClient = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      pullInactivityTimeoutMs: 2_000,
      fetchImpl: (async () => new Response(shortBody, { status: 404 })) as unknown as typeof fetch,
    });
    await expect(shortClient.pull("missing:latest")).resolves.toEqual({
      ok: false,
      failureClass: "substrate_misconfigured",
    });
  });

  it("flushes the error-body decoder so a truncated tail cannot vanish", async () => {
    // The body ends on the first byte of a two-byte sequence, and the cap can
    // truncate mid-sequence too. Flushing keeps the snippet equal to the bytes
    // that arrived (with a replacement character for the incomplete tail)
    // instead of silently dropping them.
    const head = encoder.encode("model 'missing' not found: caf");
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([...head, 0xc3]));
        controller.close();
      },
    });
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      pullInactivityTimeoutMs: 2_000,
      fetchImpl: (async () => new Response(body, { status: 404 })) as unknown as typeof fetch,
    });
    await expect(client.pull("missing:latest")).resolves.toEqual({
      ok: false,
      failureClass: "substrate_misconfigured",
    });
  });

  it("bounds a dripped error body by one cumulative deadline, not per read", async () => {
    // One byte per read, each arriving just inside the per-read budget. Under a
    // per-read deadline this body never times out and holds the provisioning
    // lock for as long as the runtime keeps dripping.
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        return new Promise<void>((resolve) => {
          setTimeout(() => {
            if (!cancelled) controller.enqueue(encoder.encode("e"));
            resolve();
          }, 15);
        });
      },
      cancel() {
        cancelled = true;
      },
    });
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      pullInactivityTimeoutMs: 100,
      fetchImpl: (async () => new Response(body, { status: 500 })) as unknown as typeof fetch,
    });
    const startedAt = Date.now();
    await expect(client.pull("qwen2.5:1.5b")).resolves.toEqual({
      ok: false,
      failureClass: "substrate_unavailable",
    });
    const elapsed = Date.now() - startedAt;
    // One 100 ms budget covers the whole snippet read; the 8 KiB cap alone
    // would need 8192 x 15 ms (about two minutes) of drip to trip.
    expect(elapsed).toBeLessThan(5_000);
    expect(cancelled).toBe(true);
  });

  it("returns as soon as the runtime reports success instead of reading on", async () => {
    // A runtime that sends `success` and never closes would otherwise hold the
    // pull to the absolute ceiling and then discard the witnessed success as a
    // timeout, with the provisioning lock held the whole time.
    let cancelled = false;
    const progress: OllamaPullProgress[] = [];
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode(`${JSON.stringify({ status: "success" })}\n`));
      },
      pull(controller) {
        // Keeps sending more success lines and never closes.
        return new Promise<void>((resolve) => {
          setTimeout(() => {
            if (!cancelled) {
              controller.enqueue(encoder.encode(`${JSON.stringify({ status: "success" })}\n`));
            }
            resolve();
          }, 5);
        });
      },
      cancel() {
        cancelled = true;
      },
    });
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      pullInactivityTimeoutMs: 10_000,
      pullCeilingMs: 10_000,
      fetchImpl: (async () => new Response(body, { status: 200 })) as unknown as typeof fetch,
    });
    const startedAt = Date.now();
    await expect(
      client.pull("qwen2.5:1.5b", { onProgress: (line) => progress.push(line) }),
    ).resolves.toEqual({ ok: true, failureClass: null });
    expect(Date.now() - startedAt).toBeLessThan(5_000);
    // Exactly one terminal line was reported, so a reporter that exempts the
    // terminal line from its rate limit cannot be driven by repeats.
    expect(progress).toEqual([{ status: "success" }]);
    expect(cancelled).toBe(true);
  });

  it("keeps work bounded under many tiny lines and under a byte-at-a-time drip", async () => {
    // Adversarial complexity (AGENTS.md rule 8), the two schedules the earlier
    // shape was quadratic under: chunks packed with tiny PARSEABLE lines (a
    // per-line buffer copy each) and a one-byte-per-read drip with no newline
    // (re-encoding the residual on every read). Each chunk stays just under the
    // 1 MiB pending-buffer bound so the scan itself is what is exercised.
    const line = JSON.stringify({ status: "p" });
    const linesPerChunk = Math.floor((900 * 1024) / (line.length + 1));
    const chunkText = `${Array.from({ length: linesPerChunk }, () => line).join("\n")}\n`;
    let chunksLeft = 3;
    const burstBody = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (chunksLeft > 0) {
          chunksLeft -= 1;
          controller.enqueue(encoder.encode(chunkText));
          return;
        }
        controller.enqueue(encoder.encode(`${JSON.stringify({ status: "success" })}\n`));
        controller.close();
      },
    });
    const burstClient = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      pullInactivityTimeoutMs: 20_000,
      fetchImpl: (async () => new Response(burstBody, { status: 200 })) as unknown as typeof fetch,
    });
    const burstStartedAt = Date.now();
    await expect(burstClient.pull("qwen2.5:1.5b")).resolves.toEqual({
      ok: true,
      failureClass: null,
    });
    expect(Date.now() - burstStartedAt).toBeLessThan(5_000);

    // A 64 KiB unterminated line delivered one byte per read: refused by the
    // per-line cap, and the residual must not be re-encoded on every read.
    const dripBytes = 64 * 1024 + 1;
    let sent = 0;
    const dripBody = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (sent >= dripBytes) {
          controller.close();
          return;
        }
        sent += 1;
        controller.enqueue(encoder.encode("a"));
      },
    });
    const dripClient = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      pullInactivityTimeoutMs: 20_000,
      fetchImpl: (async () => new Response(dripBody, { status: 200 })) as unknown as typeof fetch,
    });
    const dripStartedAt = Date.now();
    await expect(dripClient.pull("qwen2.5:1.5b")).resolves.toEqual({
      ok: false,
      failureClass: "substrate_misconfigured",
    });
    expect(Date.now() - dripStartedAt).toBeLessThan(5_000);
  });

  it("has no observable effect when a read settles after the pull returned", async () => {
    // Rule 12 (fault scheduling): the deadline race does not depend on the fetch
    // honoring `signal`, and the reader is cancelled without awaiting, so a read
    // can settle late. It must not report progress or change the verdict.
    const progress: OllamaPullProgress[] = [];
    let releaseLateRead: (() => void) | undefined;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode(`${JSON.stringify({ status: "pulling manifest" })}\n`));
      },
      pull(controller) {
        return new Promise<void>((resolve) => {
          releaseLateRead = () => {
            try {
              controller.enqueue(encoder.encode(`${JSON.stringify({ status: "success" })}\n`));
            } catch {
              // The controller is already closed by the client's cancel; that IS
              // the property under test.
            }
            resolve();
          };
        });
      },
    });
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      pullInactivityTimeoutMs: 40,
      fetchImpl: (async () => new Response(body, { status: 200 })) as unknown as typeof fetch,
    });
    const result = await client.pull("qwen2.5:1.5b", {
      onProgress: (line) => progress.push(line),
    });
    expect(result).toEqual({ ok: false, failureClass: "substrate_timeout" });
    const progressAtReturn = [...progress];
    releaseLateRead?.();
    await new Promise((resolve) => setTimeout(resolve, 50));
    // The late read produced no further progress and could not turn a refused
    // pull into a success after the fact.
    expect(progress).toEqual(progressAtReturn);
    expect(progress.map((line) => line.status)).toEqual(["pulling manifest"]);
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

describe("Ollama generation client", () => {
  it("sends think:false so thinking-mode models produce visible text", async () => {
    let capturedBody: string | undefined;
    const fetchImpl = vi.fn(async (_url: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
      capturedBody = typeof init?.body === "string" ? init.body : undefined;
      return new Response(
        JSON.stringify({ response: "Four." }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    const resp = await client.generate({ model: "qwen3:14b", prompt: "What is 2+2?" });
    expect(resp.failureClass).toBeNull();
    expect(resp.body.kind).toBe("summarize");
    if (resp.body.kind === "summarize") expect(resp.body.text).toBe("Four.");

    // The request body MUST contain think:false so thinking-mode models
    // (qwen3 family) answer directly instead of consuming num_predict on
    // a thinking chain that leaves response:"".
    // MUST MATCH the enforcement site in `substrates/local.ts` generate().
    expect(capturedBody).toBeDefined();
    const parsed = JSON.parse(capturedBody!);
    expect(parsed.think).toBe(false);
    expect(parsed.stream).toBe(false);
  });

  it("fails closed on empty response text instead of returning a blank answer", async () => {
    // Simulates a model that returns response:"" (e.g. thinking consumed all tokens).
    const fetchImpl = vi.fn(async () =>
      new Response(
        JSON.stringify({ response: "", thinking: "I was just thinking..." }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    const resp = await client.generate({ model: "qwen3:14b", prompt: "What is 2+2?" });
    expect(resp.failureClass).toBe("substrate_capability_unsupported");
    expect(resp.body.kind).toBe("failure");
  });

  it("fails closed on whitespace-only response text", async () => {
    const fetchImpl = vi.fn(async () =>
      new Response(
        JSON.stringify({ response: "   \n  " }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    const resp = await client.generate({ model: "qwen3:14b", prompt: "What is 2+2?" });
    expect(resp.failureClass).toBe("substrate_capability_unsupported");
    expect(resp.body.kind).toBe("failure");
  });

  it("uses the longer generation timeout, not the 30s show timeout", async () => {
    // Fetch resolves after 20ms — longer than timeoutMs=5ms (the show timeout)
    // but well within generateTimeoutMs=500ms.  If generate() used the show
    // timeout, the AbortController would fire first (at 5ms) and the call
    // would return substrate_timeout; the successful response proves generate
    // arms its own longer deadline.
    const fetchImpl = vi.fn((_, init?: { signal?: AbortSignal | null }) =>
      new Promise<Response>((resolve, reject) => {
        const timer = setTimeout(() => {
          resolve(new Response(
            JSON.stringify({ response: "A valid answer." }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          ));
        }, 20);
        init?.signal?.addEventListener("abort", () => {
          clearTimeout(timer);
          const err = new Error("aborted");
          err.name = "AbortError";
          reject(err);
        });
      }),
    );
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      timeoutMs: 5,           // show timeout — generate MUST NOT use this
      generateTimeoutMs: 500, // generate timeout — accommodates the 20ms delay
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    const resp = await client.generate({ model: "qwen3:14b", prompt: "test" });
    expect(resp.failureClass).toBeNull();
    expect(resp.body.kind).toBe("summarize");
    if (resp.body.kind === "summarize") expect(resp.body.text).toBe("A valid answer.");
  });

  it("times out at generateTimeoutMs, not the default show timeout", async () => {
    const fetchImpl = vi.fn(async (_url: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
      // Wait for the abort signal to fire.
      return new Promise<Response>((_, reject) => {
        const onAbort = () => {
          const err = new Error("aborted");
          err.name = "AbortError";
          reject(err);
        };
        if (init?.signal?.aborted) return onAbort();
        init?.signal?.addEventListener("abort", onAbort);
      });
    });
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      generateTimeoutMs: 50,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    const resp = await client.generate({ model: "qwen3:14b", prompt: "slow" });
    expect(resp.failureClass).toBe("substrate_timeout");
    expect(resp.body.kind).toBe("failure");
  });

  it("passes maxTokens as num_predict in options", async () => {
    let capturedBody: string | undefined;
    const fetchImpl = vi.fn(async (_url: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
      capturedBody = typeof init?.body === "string" ? init.body : undefined;
      return new Response(
        JSON.stringify({ response: "ok" }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    await client.generate({ model: "qwen3:14b", prompt: "test", maxTokens: 512 });
    const parsed = JSON.parse(capturedBody!);
    expect(parsed.options.num_predict).toBe(512);
  });

  it("preserves an explicit legacy timeoutMs when no generation override is given", async () => {
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      timeoutMs: 5,
      fetchImpl: ((_url, init) => new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
        });
      })) as typeof fetch,
    });
    const response = await client.generate({ model: "qwen3:14b", prompt: "test" });
    expect(response.failureClass).toBe("substrate_timeout");
  });

  it("preserves whitespace surrounding a nonempty completion", async () => {
    const text = "  indented answer\n";
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      fetchImpl: (async () => new Response(JSON.stringify({ response: text }))) as typeof fetch,
    });
    const response = await client.generate({ model: "qwen3:14b", prompt: "test" });
    expect(response.failureClass).toBeNull();
    expect(response.body).toMatchObject({ kind: "summarize", text });
  });

  it("classifies HTTP 500 from Ollama as substrate_unavailable", async () => {
    const fetchImpl = vi.fn(async () =>
      new Response("internal server error", { status: 500 }),
    );
    const client = new OllamaClient({
      endpoint: "http://127.0.0.1:11434",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    const resp = await client.generate({ model: "qwen3:14b", prompt: "fail" });
    expect(resp.failureClass).toBe("substrate_unavailable");
    expect(resp.body.kind).toBe("failure");
  });
});

describe("Selector audit persistence", () => {
  // Queue operation names alongside the real append queue so storage faults
  // target one event, even when earlier configuration/transport rows exist.
  async function buildAuditFixture(operation: string, rejectWrite = false) {
    let release!: () => void;
    const barrier = new Promise<void>((resolve) => { release = resolve; });
    const queuedOperations: string[] = [];
    class ControlledStorage extends MemoryStorage {
      blocked = false;
      persistedTarget = false;
      override async write(ns: string, key: string, data: Uint8Array): Promise<void> {
        const target = ns === "_audit" && queuedOperations.shift() === operation;
        if (target) {
          this.blocked = true;
          if (rejectWrite) throw new Error("simulated private storage failure");
          await barrier;
        }
        await super.write(ns, key, data);
        if (target) this.persistedTarget = true;
      }
    }
    const storage = new ControlledStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const fetchImpl = vi.fn(async (_url: Parameters<typeof fetch>[0], _init?: Parameters<typeof fetch>[1]) =>
      operation === INTEL_OPS.SUBSTRATE_FAILURE
        ? new Response("server error", { status: 500 })
        : new Response(JSON.stringify({ response: "local answer" })),
    );
    const selector = new SubstrateSelector({
      storage: new MemoryStorage(), masterKey, auditLog,
      identityId: "audit-test", fetchImpl: fetchImpl as typeof fetch,
    });
    await selector.load();
    await auditLog.flush();
    const append = auditLog.append.bind(auditLog);
    vi.spyOn(auditLog, "append").mockImplementation((...args) => {
      queuedOperations.push(args[1]);
      return append(...args);
    });
    const invoke = () => selector.invokeSummarize("concierge", {
      kind: "summarize", context: "test context", query: "test query",
    });
    const assertLocalFetch = () => {
      expect(fetchImpl).toHaveBeenCalledOnce();
      expect(String(fetchImpl.mock.calls[0]![0])).toMatch(/\/api\/generate$/);
    };
    return { storage, auditLog, invoke, release, assertLocalFetch };
  }

  it.each([INTEL_OPS.SUBSTRATE_INVOKED, INTEL_OPS.SUBSTRATE_FAILURE])(
    "waits for %s storage before completing local invocation",
    async (operation) => {
      const fixture = await buildAuditFixture(operation);
      let settled = false;
      const pending = fixture.invoke();
      // Attach both handlers immediately, including when testing older code.
      void pending.then(() => { settled = true; }, () => { settled = true; });
      try {
        await vi.waitFor(() => expect(fixture.storage.blocked).toBe(true));
        await new Promise<void>((resolve) => setImmediate(resolve));
        fixture.assertLocalFetch();
        expect(fixture.storage.persistedTarget).toBe(false);
        // Check caller completion BEFORE query(): query itself drains appends.
        expect(settled).toBe(false);
      } finally {
        fixture.release();
        await pending.catch(() => undefined);
        await fixture.auditLog.flush();
      }
      const response = await pending;
      expect(response.failureClass === null).toBe(operation === INTEL_OPS.SUBSTRATE_INVOKED);
      if (operation === INTEL_OPS.SUBSTRATE_INVOKED) expect(response.servedBy).toBe("local");
      expect(fixture.storage.persistedTarget).toBe(true);
      const events = await fixture.auditLog.query({ operation_type: operation });
      expect(events.entries).toHaveLength(1);
      expect(events.entries[0]!.result).toBe(operation === INTEL_OPS.SUBSTRATE_INVOKED ? "success" : "failure");
    },
  );

  it.each([INTEL_OPS.SUBSTRATE_INVOKED, INTEL_OPS.SUBSTRATE_FAILURE])(
    "propagates %s storage rejection without private details",
    async (operation) => {
      const fixture = await buildAuditFixture(operation, true);
      try {
        await expect(fixture.invoke()).rejects.toThrow(/^intelligence audit persistence failed$/);
        fixture.assertLocalFetch();
        expect(fixture.storage.blocked).toBe(true);
        expect(fixture.storage.persistedTarget).toBe(false);
      } finally {
        fixture.release();
        await fixture.auditLog.flush().catch(() => undefined);
      }
    },
  );
});
