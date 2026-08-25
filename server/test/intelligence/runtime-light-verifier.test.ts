import { describe, expect, it, vi } from "vitest";
import * as intelligence from "../../src/intelligence/index.js";
import {
  LIGHT_RUNTIME_SINGLE_FLIGHT_MAX_ENTRIES,
  OLLAMA_RUNTIME_EVIDENCE_MAX_MODELS,
  OLLAMA_RUNTIME_EVIDENCE_MAX_RESPONSE_BYTES,
  OllamaRuntimeEvidenceClient,
  createSingleFlightLightRuntimeVerifier,
  inspectOllamaShowPayload,
  inspectOllamaTagsDigest,
  type RuntimeLightProtocolState,
  type RuntimeLightVerificationRequest,
  type RuntimeLightVerificationResult,
  type RuntimeLightVerifier,
} from "../../src/intelligence/runtime-light-verifier.js";

const EXPECTED_DIGEST = "a".repeat(64);
const OTHER_DIGEST = "b".repeat(64);
const RUNTIME_TAG = "qwen2.5:1.5b";

function request(
  overrides: Partial<RuntimeLightVerificationRequest> = {},
): RuntimeLightVerificationRequest {
  return {
    rootReal: "/var/lib/ollama/models",
    binding: {
      model_id: "qwen2.5-1.5b",
      runtime_tag: RUNTIME_TAG,
      ollama_identity: {
        registry: "registry.ollama.ai",
        namespace: "library",
        model: "qwen2.5",
        tag: "1.5b",
        ollama_manifest_sha256: EXPECTED_DIGEST,
      },
      assurance: "light",
      manifest_version: 9,
    },
    ...overrides,
  };
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function evidenceFetch(showBody: unknown, tagsBody: unknown) {
  return vi.fn(async (input: string | URL | Request) => {
    const pathname = new URL(
      typeof input === "string" ? input : input instanceof URL ? input : input.url,
    ).pathname;
    if (pathname === "/api/show") return jsonResponse(showBody);
    if (pathname === "/api/tags") return jsonResponse(tagsBody);
    throw new Error(`unexpected request: ${pathname}`);
  });
}

function client(fetchImpl: ReturnType<typeof vi.fn>, timeoutMs?: number) {
  return new OllamaRuntimeEvidenceClient({
    endpoint: "http://127.0.0.1:11434/",
    fetchImpl: fetchImpl as typeof fetch,
    timeoutMs,
  });
}

function failure(
  state: Exclude<RuntimeLightProtocolState, "runtime_manifest_match">,
): RuntimeLightVerificationResult {
  return {
    ok: false,
    state,
    reason: "integrity_io_unavailable",
    runtimeTag: RUNTIME_TAG,
  };
}

describe("Q5B runtime-reported light verifier", () => {
  it("exports the inert Q5B module through the intelligence barrel", () => {
    expect(intelligence.OllamaRuntimeEvidenceClient).toBe(OllamaRuntimeEvidenceClient);
    expect(intelligence.createSingleFlightLightRuntimeVerifier).toBe(
      createSingleFlightLightRuntimeVerifier,
    );
  });

  it.each([
    EXPECTED_DIGEST,
    `sha256:${EXPECTED_DIGEST}`,
  ])("accepts one exact /api/tags name and lowercase digest (%s)", async (digest) => {
    const fetchImpl = evidenceFetch(
      { details: { format: "gguf" } },
      { models: [{ name: RUNTIME_TAG, digest }] },
    );
    await expect(client(fetchImpl).verify(request())).resolves.toEqual({
      ok: true,
      state: "runtime_manifest_match",
      runtimeTag: RUNTIME_TAG,
      observedManifestDigest: EXPECTED_DIGEST,
    });
    expect(fetchImpl).toHaveBeenNthCalledWith(
      1,
      "http://127.0.0.1:11434/api/show",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ model: RUNTIME_TAG }),
      }),
    );
    expect(fetchImpl).toHaveBeenNthCalledWith(
      2,
      "http://127.0.0.1:11434/api/tags",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("treats a digest-free /api/show object as existence evidence only", async () => {
    const fetchImpl = evidenceFetch(
      {},
      { models: [{ name: RUNTIME_TAG, digest: EXPECTED_DIGEST }] },
    );
    await expect(client(fetchImpl).verify(request())).resolves.toMatchObject({
      ok: true,
      observedManifestDigest: EXPECTED_DIGEST,
    });
    expect(inspectOllamaShowPayload({ details: {} })).toEqual({
      ok: true,
      state: "show_exists",
    });
  });

  it("refuses a forged /api/show digest when the sole /api/tags digest diverges", async () => {
    const fetchImpl = evidenceFetch(
      { digest: EXPECTED_DIGEST, details: { digest: EXPECTED_DIGEST } },
      { models: [{ name: RUNTIME_TAG, digest: OTHER_DIGEST }] },
    );
    await expect(client(fetchImpl).verify(request())).resolves.toEqual({
      ok: false,
      state: "tags_digest_mismatch",
      reason: "runtime_manifest_digest_mismatch",
      runtimeTag: RUNTIME_TAG,
      observedManifestDigest: OTHER_DIGEST,
    });
    expect(fetchImpl.mock.calls.map(([url]) => new URL(String(url)).pathname)).toEqual([
      "/api/show",
      "/api/tags",
    ]);
    expect(fetchImpl.mock.calls.some(([url]) => String(url).includes("/api/generate"))).toBe(false);
  });

  it.each([
    ["missing exact name", { models: [{ name: "other:latest", digest: EXPECTED_DIGEST }] }, "tags_model_absent"],
    ["entry.model alias only", { models: [{ name: "other:latest", model: RUNTIME_TAG, digest: EXPECTED_DIGEST }] }, "tags_model_absent"],
    ["implicit latest", { models: [{ name: "qwen2.5", digest: EXPECTED_DIGEST }] }, "tags_model_absent"],
    ["duplicate exact name", { models: [
      { name: RUNTIME_TAG, digest: EXPECTED_DIGEST },
      { name: RUNTIME_TAG, digest: EXPECTED_DIGEST },
    ] }, "tags_exact_match_ambiguous"],
  ])("refuses %s rather than normalizing or selecting an alias", async (_label, tags, state) => {
    const result = await client(evidenceFetch({}, tags)).verify(request());
    expect(result).toMatchObject({ ok: false, state });
  });

  it.each([
    ["missing", undefined, "tags_digest_invalid"],
    ["uppercase", "A".repeat(64), "tags_digest_invalid"],
    ["uppercase prefix", `SHA256:${EXPECTED_DIGEST}`, "tags_digest_invalid"],
    ["zero", "0".repeat(64), "tags_digest_invalid"],
    ["incorrect", OTHER_DIGEST, "tags_digest_mismatch"],
  ])("refuses a %s exact-entry digest", async (_label, digest, state) => {
    const tags = { models: [{ name: RUNTIME_TAG, digest }] };
    const result = await client(evidenceFetch({}, tags)).verify(request());
    expect(result).toMatchObject({ ok: false, state });
  });

  it("refuses malformed typed payloads and strict-JSON ambiguity", async () => {
    expect(inspectOllamaShowPayload([])).toEqual({
      ok: false,
      state: "show_response_invalid",
    });
    expect(inspectOllamaTagsDigest({ models: [null] }, RUNTIME_TAG)).toEqual({
      ok: false,
      state: "tags_response_invalid",
    });

    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse({}))
      .mockResolvedValueOnce(new Response(
        `{"models":[{"name":"${RUNTIME_TAG}","digest":"${EXPECTED_DIGEST}","digest":"${OTHER_DIGEST}"}]}`,
        { status: 200 },
      ));
    await expect(client(fetchImpl).verify(request())).resolves.toMatchObject({
      ok: false,
      state: "tags_response_invalid",
    });
  });

  it("refuses malformed JSON from either endpoint", async () => {
    const showMalformed = vi.fn().mockResolvedValue(new Response("{"));
    await expect(client(showMalformed).verify(request())).resolves.toMatchObject({
      ok: false,
      state: "show_response_invalid",
    });

    const tagsMalformed = vi.fn()
      .mockResolvedValueOnce(jsonResponse({}))
      .mockResolvedValueOnce(new Response("{"));
    await expect(client(tagsMalformed).verify(request())).resolves.toMatchObject({
      ok: false,
      state: "tags_response_invalid",
    });
  });

  it("refuses HTTP errors from /api/show and /api/tags", async () => {
    const showError = vi.fn().mockResolvedValue(new Response("missing", { status: 404 }));
    await expect(client(showError).verify(request())).resolves.toMatchObject({
      ok: false,
      state: "show_http_refused",
      reason: "runtime_model_absent",
    });

    const showUnavailable = vi.fn().mockResolvedValue(
      new Response("offline", { status: 503 }),
    );
    await expect(client(showUnavailable).verify(request())).resolves.toMatchObject({
      ok: false,
      state: "show_http_refused",
      reason: "integrity_io_unavailable",
    });

    const tagsError = vi.fn()
      .mockResolvedValueOnce(jsonResponse({}))
      .mockResolvedValueOnce(new Response("offline", { status: 503 }));
    await expect(client(tagsError).verify(request())).resolves.toMatchObject({
      ok: false,
      state: "tags_http_refused",
    });
  });

  it("refuses transport errors and request timeouts", async () => {
    const transport = vi.fn(async () => {
      throw new Error("offline");
    });
    await expect(client(transport).verify(request())).resolves.toMatchObject({
      ok: false,
      state: "show_transport_refused",
    });

    const timeout = vi.fn(async (_url: unknown, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          const error = new Error("aborted");
          error.name = "AbortError";
          reject(error);
        });
      }));
    await expect(client(timeout, 1).verify(request())).resolves.toMatchObject({
      ok: false,
      state: "show_timeout",
    });
  });

  it("refuses the model collection immediately above its named cap", async () => {
    const models = Array.from(
      { length: OLLAMA_RUNTIME_EVIDENCE_MAX_MODELS + 1 },
      (_unused, index) => ({ name: `other-${index}:latest` }),
    );
    await expect(client(evidenceFetch({}, { models })).verify(request())).resolves.toMatchObject({
      ok: false,
      state: "tags_collection_too_large",
    });
  });

  it("refuses declared and streamed response bodies above the named byte cap", async () => {
    const declaredOversize = vi.fn().mockResolvedValue(new Response("{}", {
      headers: {
        "content-length": String(OLLAMA_RUNTIME_EVIDENCE_MAX_RESPONSE_BYTES + 1),
      },
    }));
    await expect(client(declaredOversize).verify(request())).resolves.toMatchObject({
      ok: false,
      state: "show_response_too_large",
    });

    const streamedOversize = vi.fn()
      .mockResolvedValueOnce(jsonResponse({}))
      .mockResolvedValueOnce(new Response(
        " ".repeat(OLLAMA_RUNTIME_EVIDENCE_MAX_RESPONSE_BYTES + 1),
      ));
    await expect(client(streamedOversize).verify(request())).resolves.toMatchObject({
      ok: false,
      state: "tags_response_too_large",
    });
  });

  it("refuses a binding whose runtime tag diverges from its signed identity", async () => {
    const fetchImpl = evidenceFetch({}, { models: [] });
    const divergent = request();
    divergent.binding.runtime_tag = "attacker:latest";
    await expect(client(fetchImpl).verify(divergent)).resolves.toMatchObject({
      ok: false,
      state: "request_invalid",
    });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("single-flights the reviewed tuple and retries after a settled failure", async () => {
    let release: ((value: RuntimeLightVerificationResult) => void) | undefined;
    let calls = 0;
    const delegate: RuntimeLightVerifier = {
      verify: vi.fn((_request): Promise<RuntimeLightVerificationResult> => {
        calls += 1;
        if (calls > 1) return Promise.resolve(failure("show_transport_refused"));
        return new Promise((resolve) => {
          release = resolve;
        });
      }),
    };
    const verifier = createSingleFlightLightRuntimeVerifier(delegate);
    const first = verifier.verify(request());
    const concurrent = verifier.verify(request());
    expect(concurrent).toBe(first);
    await Promise.resolve();
    expect(delegate.verify).toHaveBeenCalledTimes(1);
    release?.(failure("show_transport_refused"));
    await expect(first).resolves.toMatchObject({ ok: false });

    await verifier.verify(request());
    expect(delegate.verify).toHaveBeenCalledTimes(2);
  });

  it("caps pending single-flight tuples without evicting an unsettled gate", async () => {
    const delegate: RuntimeLightVerifier = {
      verify: vi.fn((_request): Promise<RuntimeLightVerificationResult> =>
        new Promise(() => undefined)),
    };
    const verifier = createSingleFlightLightRuntimeVerifier(delegate);
    const pending = Array.from(
      { length: LIGHT_RUNTIME_SINGLE_FLIGHT_MAX_ENTRIES },
      (_unused, index) => verifier.verify(request({ rootReal: `/models/${index}` })),
    );
    expect(pending).toHaveLength(LIGHT_RUNTIME_SINGLE_FLIGHT_MAX_ENTRIES);
    await expect(
      verifier.verify(request({ rootReal: "/models/overflow" })),
    ).resolves.toMatchObject({
      ok: false,
      state: "single_flight_capacity_refused",
    });
    expect(delegate.verify).toHaveBeenCalledTimes(LIGHT_RUNTIME_SINGLE_FLIGHT_MAX_ENTRIES);
  });
});
