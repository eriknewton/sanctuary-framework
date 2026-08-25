/**
 * Q5B: inert runtime-reported Ollama manifest verifier.
 *
 * This module performs bounded `/api/show` and `/api/tags` reads only when an
 * explicit caller invokes it. It is not wired to provisioning, the selector,
 * generation, config persistence, audit, or host-file inspection.
 * Design section 5.3 loopback-endpoint enforcement is the caller's obligation;
 * this inert slice does not implement it.
 */

import { timingSafeEqual } from "node:crypto";
import { isAbsolute } from "node:path";
import { parseStrictJson } from "../substrate/strict-json.js";
import {
  deriveOllamaRuntimeTag,
  type VerifiedLocalBindingV2,
} from "./model-manifest-v2.js";

const KIBIBYTE_BYTES = 1_024;
// Must match IDENTITY_COMPONENT `{0,63}` in server/src/intelligence/model-manifest-v2.ts.
const OLLAMA_IDENTITY_COMPONENT_MAX_CHARS = 64;
const RUNTIME_TAG_SEPARATORS = 2;
const SHA256_BYTES = 32;

/** 256 KiB bounds every `/api/show` and `/api/tags` body before JSON parsing. */
export const OLLAMA_RUNTIME_EVIDENCE_MAX_RESPONSE_BYTES =
  256 * KIBIBYTE_BYTES;
/** A bounded inventory permits substantial non-catalog models without an unbounded walk. */
export const OLLAMA_RUNTIME_EVIDENCE_MAX_MODELS = 256;
/** Must remain the exact three V2 identity components plus `/` and `:`. */
export const OLLAMA_RUNTIME_TAG_MAX_CHARS =
  3 * OLLAMA_IDENTITY_COMPONENT_MAX_CHARS + RUNTIME_TAG_SEPARATORS;
export const OLLAMA_RUNTIME_EVIDENCE_DEFAULT_TIMEOUT_MS = 5_000;
/** Design section 7.3 caps pending per-tuple single-flight entries at 32. */
export const LIGHT_RUNTIME_SINGLE_FLIGHT_MAX_ENTRIES = 32;

const SHA256_HEX = /^[0-9a-f]{64}$/;
const SHA256_WITH_OPTIONAL_PREFIX = /^(?:sha256:)?([0-9a-f]{64})$/;
const ALL_ZERO_SHA256 = "0".repeat(SHA256_BYTES * 2);

export const RUNTIME_LIGHT_PROTOCOL_STATES = [
  "runtime_manifest_match",
  "request_invalid",
  "show_timeout",
  "show_transport_refused",
  "show_http_refused",
  "show_response_too_large",
  "show_response_invalid",
  "tags_timeout",
  "tags_transport_refused",
  "tags_http_refused",
  "tags_response_too_large",
  "tags_response_invalid",
  "tags_collection_too_large",
  "tags_model_absent",
  "tags_exact_match_ambiguous",
  "tags_digest_invalid",
  "tags_digest_mismatch",
  "single_flight_capacity_refused",
  "verifier_exception",
] as const;

export type RuntimeLightProtocolState =
  (typeof RUNTIME_LIGHT_PROTOCOL_STATES)[number];

export type RuntimeLightRefusalReason =
  | "binding_mismatch"
  | "model_root_invalid"
  | "runtime_model_absent"
  | "runtime_manifest_digest_invalid"
  | "runtime_manifest_digest_mismatch"
  | "integrity_io_unavailable";

export interface RuntimeLightVerificationRequest {
  /** Included in the reviewed single-flight tuple; Q5B never reads this path. */
  rootReal: string;
  /** The caller supplies a binding accepted by the Q5A armed-state validator. */
  binding: VerifiedLocalBindingV2;
}

export type RuntimeLightVerificationResult =
  | {
    ok: true;
    state: "runtime_manifest_match";
    runtimeTag: string;
    observedManifestDigest: string;
  }
  | {
    ok: false;
    state: Exclude<RuntimeLightProtocolState, "runtime_manifest_match">;
    reason: RuntimeLightRefusalReason;
    runtimeTag: string | null;
    observedManifestDigest?: string;
  };

export interface RuntimeLightVerifier {
  verify(
    request: RuntimeLightVerificationRequest,
  ): Promise<RuntimeLightVerificationResult>;
}

export interface OllamaRuntimeEvidenceClientConfig {
  endpoint: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

export type OllamaShowInspectionResult =
  | { ok: true; state: "show_exists" }
  | { ok: false; state: "show_response_invalid" };

export type OllamaTagsDigestInspectionResult =
  | {
    ok: true;
    state: "tags_exact_digest";
    observedManifestDigest: string;
  }
  | {
    ok: false;
    state:
      | "tags_response_invalid"
      | "tags_collection_too_large"
      | "tags_model_absent"
      | "tags_exact_match_ambiguous"
      | "tags_digest_invalid";
  };

type FetchStage = "show" | "tags";
type FetchJsonResult =
  | { ok: true; value: unknown }
  | {
    ok: false;
    state:
      | `${FetchStage}_timeout`
      | `${FetchStage}_transport_refused`
      | `${FetchStage}_http_refused`
      | `${FetchStage}_response_too_large`
      | `${FetchStage}_response_invalid`;
    httpStatus?: number;
  };

class CappedResponseError extends Error {
  constructor(readonly kind: "too_large" | "invalid") {
    super(kind);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function refusal(
  state: Exclude<RuntimeLightProtocolState, "runtime_manifest_match">,
  reason: RuntimeLightRefusalReason,
  runtimeTag: string | null,
  observedManifestDigest?: string,
): RuntimeLightVerificationResult {
  return observedManifestDigest === undefined
    ? { ok: false, state, reason, runtimeTag }
    : { ok: false, state, reason, runtimeTag, observedManifestDigest };
}

function normalizeDigest(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const match = SHA256_WITH_OPTIONAL_PREFIX.exec(raw);
  if (match === null || match[1] === ALL_ZERO_SHA256) return null;
  return match[1] ?? null;
}

function constantTimeDigestEqual(left: string, right: string): boolean {
  if (!SHA256_HEX.test(left) || !SHA256_HEX.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

/**
 * `/api/show` is existence evidence only; every digest-like field is ignored.
 * A 200 error object still establishes existence because tags is the sole digest authority.
 */
export function inspectOllamaShowPayload(
  payload: unknown,
): OllamaShowInspectionResult {
  return isRecord(payload)
    ? { ok: true, state: "show_exists" }
    : { ok: false, state: "show_response_invalid" };
}

/** Inspect exactly one `name` match; the optional `model` alias carries no authority. */
export function inspectOllamaTagsDigest(
  payload: unknown,
  runtimeTag: string,
): OllamaTagsDigestInspectionResult {
  if (!isRecord(payload) || !Array.isArray(payload.models)) {
    return { ok: false, state: "tags_response_invalid" };
  }
  if (payload.models.length > OLLAMA_RUNTIME_EVIDENCE_MAX_MODELS) {
    return { ok: false, state: "tags_collection_too_large" };
  }

  const exactMatches: Record<string, unknown>[] = [];
  for (const entry of payload.models) {
    if (!isRecord(entry) || typeof entry.name !== "string") {
      return { ok: false, state: "tags_response_invalid" };
    }
    if (entry.name === runtimeTag) exactMatches.push(entry);
  }

  if (exactMatches.length === 0) {
    return { ok: false, state: "tags_model_absent" };
  }
  // Ambiguity is refused before digest inspection so identical duplicates cannot authorize.
  if (exactMatches.length !== 1) {
    return { ok: false, state: "tags_exact_match_ambiguous" };
  }
  const observedManifestDigest = normalizeDigest(exactMatches[0]?.digest);
  if (observedManifestDigest === null) {
    return { ok: false, state: "tags_digest_invalid" };
  }
  return {
    ok: true,
    state: "tags_exact_digest",
    observedManifestDigest,
  };
}

async function readCappedStrictJson(response: Response): Promise<unknown> {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null) {
    if (!/^(?:0|[1-9][0-9]*)$/.test(contentLength)) {
      throw new CappedResponseError("invalid");
    }
    const parsedLength = Number(contentLength);
    if (!Number.isSafeInteger(parsedLength)) {
      throw new CappedResponseError("invalid");
    }
    if (parsedLength > OLLAMA_RUNTIME_EVIDENCE_MAX_RESPONSE_BYTES) {
      throw new CappedResponseError("too_large");
    }
  }

  if (response.body === null) throw new CappedResponseError("invalid");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) continue;
      totalBytes += value.byteLength;
      if (totalBytes > OLLAMA_RUNTIME_EVIDENCE_MAX_RESPONSE_BYTES) {
        await reader.cancel().catch(() => undefined);
        throw new CappedResponseError("too_large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return parseStrictJson(text);
  } catch {
    throw new CappedResponseError("invalid");
  }
}

export class OllamaRuntimeEvidenceClient implements RuntimeLightVerifier {
  private readonly endpoint: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(config: OllamaRuntimeEvidenceClientConfig) {
    this.endpoint = config.endpoint.replace(/\/+$/, "");
    this.timeoutMs = config.timeoutMs ?? OLLAMA_RUNTIME_EVIDENCE_DEFAULT_TIMEOUT_MS;
    this.fetchImpl = config.fetchImpl ?? fetch;
    if (this.endpoint.length === 0) throw new Error("Ollama endpoint is required");
    if (!Number.isFinite(this.timeoutMs) || this.timeoutMs <= 0) {
      throw new Error("Ollama evidence timeout must be positive");
    }
  }

  async verify(
    request: RuntimeLightVerificationRequest,
  ): Promise<RuntimeLightVerificationResult> {
    const runtimeTag = deriveOllamaRuntimeTag(request.binding.ollama_identity);
    const expectedManifestDigest =
      request.binding.ollama_identity.ollama_manifest_sha256;
    if (!isAbsolute(request.rootReal)) {
      return refusal("request_invalid", "model_root_invalid", runtimeTag || null);
    }
    if (
      request.binding.runtime_tag !== runtimeTag ||
      runtimeTag.length === 0 ||
      runtimeTag.length > OLLAMA_RUNTIME_TAG_MAX_CHARS
    ) {
      return refusal("request_invalid", "binding_mismatch", runtimeTag || null);
    }
    if (
      !SHA256_HEX.test(expectedManifestDigest) ||
      expectedManifestDigest === ALL_ZERO_SHA256
    ) {
      return refusal("request_invalid", "runtime_manifest_digest_invalid", runtimeTag);
    }

    const show = await this.fetchJson(
      "show",
      `${this.endpoint}/api/show`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model: runtimeTag }),
      },
    );
    if (!show.ok) {
      return refusal(
        show.state,
        show.state === "show_http_refused" && show.httpStatus === 404
          ? "runtime_model_absent"
          : "integrity_io_unavailable",
        runtimeTag,
      );
    }
    const showInspection = inspectOllamaShowPayload(show.value);
    if (!showInspection.ok) {
      return refusal(
        showInspection.state,
        "integrity_io_unavailable",
        runtimeTag,
      );
    }

    const tags = await this.fetchJson(
      "tags",
      `${this.endpoint}/api/tags`,
      { method: "GET" },
    );
    if (!tags.ok) {
      // Show shapes stay retryable because show carries no digest authority; identical tags shapes are content failures because tags is the sole digest evidence.
      return refusal(
        tags.state,
        tags.state === "tags_response_too_large" ||
            tags.state === "tags_response_invalid"
          ? "runtime_manifest_digest_invalid"
          : "integrity_io_unavailable",
        runtimeTag,
      );
    }
    const tagsInspection = inspectOllamaTagsDigest(tags.value, runtimeTag);
    if (!tagsInspection.ok) {
      const reason: RuntimeLightRefusalReason =
        tagsInspection.state === "tags_model_absent"
          ? "runtime_model_absent"
          : "runtime_manifest_digest_invalid";
      return refusal(tagsInspection.state, reason, runtimeTag);
    }

    if (!constantTimeDigestEqual(
      tagsInspection.observedManifestDigest,
      expectedManifestDigest,
    )) {
      return refusal(
        "tags_digest_mismatch",
        "runtime_manifest_digest_mismatch",
        runtimeTag,
        tagsInspection.observedManifestDigest,
      );
    }
    return {
      ok: true,
      state: "runtime_manifest_match",
      runtimeTag,
      observedManifestDigest: tagsInspection.observedManifestDigest,
    };
  }

  private async fetchJson(
    stage: FetchStage,
    url: string,
    init: RequestInit,
  ): Promise<FetchJsonResult> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      let response: Response;
      try {
        response = await this.fetchImpl(url, {
          ...init,
          redirect: "error",
          signal: controller.signal,
        });
      } catch {
        return {
          ok: false,
          state: controller.signal.aborted
            ? `${stage}_timeout`
            : `${stage}_transport_refused`,
        };
      }
      if (!response.ok) {
        await response.body?.cancel().catch(() => undefined);
        return {
          ok: false,
          state: `${stage}_http_refused`,
          httpStatus: response.status,
        };
      }
      try {
        return { ok: true, value: await readCappedStrictJson(response) };
      } catch (error) {
        return {
          ok: false,
          state: controller.signal.aborted
            ? `${stage}_timeout`
            : error instanceof CappedResponseError && error.kind === "too_large"
              ? `${stage}_response_too_large`
              : `${stage}_response_invalid`,
        };
      }
    } finally {
      clearTimeout(timeout);
    }
  }
}

function singleFlightKey(request: RuntimeLightVerificationRequest): string {
  const { binding } = request;
  const parts = [
    request.rootReal,
    binding.runtime_tag,
    binding.ollama_identity.ollama_manifest_sha256,
    binding.assurance,
  ];
  // Length-prefixing keeps the reviewed tuple unambiguous without a forbidden delimiter alphabet.
  return parts.map((part) => `${part.length}:${part}`).join("");
}

/** Coalesce only concurrent checks; no success or failure survives settlement. */
export function createSingleFlightLightRuntimeVerifier(
  delegate: RuntimeLightVerifier,
): RuntimeLightVerifier {
  const inFlight = new Map<string, Promise<RuntimeLightVerificationResult>>();
  return {
    verify(request) {
      const key = singleFlightKey(request);
      const existing = inFlight.get(key);
      if (existing !== undefined) return existing;
      // The map never evicts a pending gate because doing so would let a caller bypass it.
      if (inFlight.size >= LIGHT_RUNTIME_SINGLE_FLIGHT_MAX_ENTRIES) {
        return Promise.resolve(refusal(
          "single_flight_capacity_refused",
          "integrity_io_unavailable",
          request.binding.runtime_tag || null,
        ));
      }

      const pending = Promise.resolve()
        .then(() => delegate.verify(request))
        .catch(() => refusal(
          "verifier_exception",
          "integrity_io_unavailable",
          request.binding.runtime_tag || null,
        ));
      inFlight.set(key, pending);
      void pending.then(
        () => {
          if (inFlight.get(key) === pending) inFlight.delete(key);
        },
        () => {
          if (inFlight.get(key) === pending) inFlight.delete(key);
        },
      );
      return pending;
    },
  };
}
