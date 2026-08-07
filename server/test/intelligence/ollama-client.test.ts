import { describe, it, expect } from "vitest";
import { OllamaClient } from "../../src/intelligence/substrates/local.js";

const MANIFEST_DIGEST =
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BLOB_ONE =
  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const BLOB_TWO =
  "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

function fetchStub(
  handler: (url: string, init?: Parameters<typeof fetch>[1]) => Response,
): typeof fetch {
  return (async (
    input: Parameters<typeof fetch>[0],
    init?: Parameters<typeof fetch>[1],
  ): Promise<Response> => {
    const url = input instanceof Request ? input.url : input.toString();
    return handler(url, init);
  }) as typeof fetch;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("OllamaClient model digest primitives", () => {
  it("showModel POSTs /api/show with verbose metadata and normalizes digests", async () => {
    let requestBody: unknown = null;
    const client = new OllamaClient({
      endpoint: "http://localhost:11434/",
      fetchImpl: fetchStub((url, init) => {
        expect(url).toBe("http://localhost:11434/api/show");
        expect(init?.method).toBe("POST");
        requestBody = JSON.parse(String(init?.body));
        return jsonResponse({
          digest: `sha256:${MANIFEST_DIGEST.toUpperCase()}`,
          layers: [
            { digest: `sha256-${BLOB_ONE}` },
            { digest: `sha256:${BLOB_TWO.toUpperCase()}` },
            { digest: `sha256-${BLOB_ONE}` },
          ],
        });
      }),
    });

    const report = await client.showModel("qwen2.5:1.5b");

    expect(requestBody).toEqual({ model: "qwen2.5:1.5b", verbose: true });
    expect(report).toEqual({
      model: "qwen2.5:1.5b",
      manifestDigestSha256: MANIFEST_DIGEST,
      blobSha256: [BLOB_ONE, BLOB_TWO],
    });
  });

  it("showModel extracts content-addressed blob filenames from nested metadata", async () => {
    const client = new OllamaClient({
      endpoint: "http://localhost:11434",
      fetchImpl: fetchStub(() =>
        jsonResponse({
          manifest_digest: `sha256-${MANIFEST_DIGEST}`,
          model_info: {
            files: [
              `/Users/example/.ollama/models/blobs/sha256-${BLOB_ONE}`,
              "not a digest",
            ],
            nested: { blob: `sha256:${BLOB_TWO}` },
          },
        }),
      ),
    });

    const report = await client.showModel("phi4-mini");

    expect(report?.manifestDigestSha256).toBe(MANIFEST_DIGEST);
    expect(report?.blobSha256).toEqual([BLOB_ONE, BLOB_TWO]);
  });

  it("showModel returns null on daemon refusal or unreachable daemon", async () => {
    const refused = new OllamaClient({
      endpoint: "http://localhost:11434",
      fetchImpl: fetchStub(() => new Response("missing", { status: 404 })),
    });
    await expect(refused.showModel("missing")).resolves.toBeNull();

    const unreachable = new OllamaClient({
      endpoint: "http://localhost:11434",
      fetchImpl: (async () => {
        throw new Error("offline");
      }) as typeof fetch,
    });
    await expect(unreachable.showModel("missing")).resolves.toBeNull();
  });

  it("pullModel POSTs /api/pull with stream disabled and returns daemon status", async () => {
    let requestBody: unknown = null;
    const client = new OllamaClient({
      endpoint: "http://localhost:11434/",
      fetchImpl: fetchStub((url, init) => {
        expect(url).toBe("http://localhost:11434/api/pull");
        expect(init?.method).toBe("POST");
        requestBody = JSON.parse(String(init?.body));
        return jsonResponse({ status: "success" });
      }),
    });

    const result = await client.pullModel("qwen2.5:1.5b");

    expect(requestBody).toEqual({ model: "qwen2.5:1.5b", stream: false });
    expect(result).toMatchObject({ ok: true, status: "success" });
  });

  it("pullModel maps daemon HTTP and JSON errors to explicit failures", async () => {
    const httpFailure = new OllamaClient({
      endpoint: "http://localhost:11434",
      fetchImpl: fetchStub(() => new Response("model not found", { status: 404 })),
    });
    const missing = await httpFailure.pullModel("missing");
    expect(missing).toMatchObject({
      ok: false,
      failureClass: "substrate_misconfigured",
      statusCode: 404,
    });

    const daemonError = new OllamaClient({
      endpoint: "http://localhost:11434",
      fetchImpl: fetchStub(() => jsonResponse({ error: "pull failed" })),
    });
    const refused = await daemonError.pullModel("qwen2.5:1.5b");
    expect(refused).toMatchObject({
      ok: false,
      failureClass: "substrate_misconfigured",
      message: "ollama pull failed",
    });
  });
});
