/**
 * Sanctuary MCP Server — Local Substrate (Ollama)
 *
 * Minimal HTTP client against Ollama's REST API at `http://localhost:11434`
 * (configurable). Used by the intelligence substrate selector when the
 * operator picks `local` for any surface.
 *
 * Hardware-capability checks fire at selector init time and on operator
 * configuration save. The dashboard transparency UI surfaces install
 * guidance when Ollama is unreachable or the chosen model is not present;
 * v1.2 ships clear setup docs (no auto-installer).
 *
 * Per position paper §5: Gemma 2 2B for concierge / direct-agent / template
 * suggestion (latency budget: <500ms first token; ~10-15ms subsequent).
 * Phi-4 Mini for sentinel scoring escalation + privacy filter Tier 2.
 *
 * Cold-start handling: first-token latency 500-1000ms; subsequent ~10-15ms.
 * The dashboard chat surface should render a "warming up" indicator when
 * latency exceeds 800ms on the first invocation.
 *
 * Error shape: every failure returns a `SubstrateResponse` with body kind
 * `failure` and a stable `failureClass` enum. The selector wraps this and
 * emits the audit event; surfaces never see raw HTTP errors.
 */

import type {
  ClassifyRequest,
  LocalModelPick,
  RedactRequest,
  SubstrateCapability,
  SubstrateResponse,
  SummarizeRequest,
} from "../types.js";
import { LOCAL_MODEL_TAGS } from "../types.js";
import { stripTrailingSlashes } from "../../strings.js";

export const LOCAL_CAPABILITY: SubstrateCapability = {
  summarize: true,
  classify: true,
  redact: true,
};

const DEFAULT_TIMEOUT_MS = 30_000;
const HARDWARE_PROBE_TIMEOUT_MS = 1_500;

// A model pull moves gigabytes, so it is bounded by evidence of progress plus a
// generous absolute ceiling, never by the per-invocation request timeout above:
// a fixed wall clock aborts a healthy multi-gigabyte download mid-transfer and
// leaves partial blobs behind.
// 120_000 ms = 120 s x 1000 ms/s. Ollama emits a progress line several times a
// second while a layer moves and recovers a stalled registry connection well
// inside two minutes, so a longer silence means the transfer has stopped.
const PULL_INACTIVITY_TIMEOUT_MS = 120_000;
// 14_400_000 ms = 4 h x 60 min/h x 60 s/min x 1000 ms/s. The largest
// signed-catalog model is on the order of 6 GB; at 0.5 MB/s (a 4 Mbit/s link)
// that is about 3.4 h, so the ceiling clears the slowest link this ceremony is
// meant to serve while still bounding a runtime that streams without ever
// finishing.
const PULL_ABSOLUTE_CEILING_MS = 4 * 60 * 60 * 1_000;
// 65_536 bytes = 64 x 1024. An Ollama NDJSON status line is roughly 200 bytes;
// the cap sits two orders of magnitude above that, so no legitimate line is
// clipped, while a runtime that never emits a newline cannot grow the pending
// buffer without bound.
const PULL_PROGRESS_LINE_MAX_BYTES = 64 * 1024;
// 67_108_864 bytes = 64 x 1024 x 1024, roughly 335_000 of the ~200-byte lines
// above: far more than a full-ceiling pull produces, so the whole stream stays
// bounded even when every individual line is well formed.
const PULL_RESPONSE_MAX_BYTES = 64 * 1024 * 1024;
// 1_048_576 bytes = 16 x PULL_PROGRESS_LINE_MAX_BYTES: room for one
// maximum-length partial line plus the burst of complete ~200-byte lines a
// single transport read can deliver (about 5_000 of them). Checked BEFORE a
// chunk is decoded, so a runtime that sends one enormous chunk is refused
// without it ever being buffered as a string.
const PULL_PENDING_BUFFER_MAX_BYTES = 16 * PULL_PROGRESS_LINE_MAX_BYTES;
// 8_192 bytes = 8 x 1024. An error body is read only to classify the failure
// (`classifyHttpError` looks for a model-not-found phrase), so it is read
// through the same bounded reader as the stream and truncated well below the
// line cap; a runtime that never ends its error body cannot hold the pull, and
// therefore the provisioning lock, open.
const PULL_ERROR_BODY_MAX_BYTES = 8 * 1024;

const PULL_LINE_ENCODER = new TextEncoder();

export interface OllamaClientConfig {
  endpoint: string;
  /** Per-invocation timeout in ms; defaults to 30s. Never bounds `pull`. */
  timeoutMs?: number;
  /**
   * Silence (no NDJSON progress line) that ends a streaming pull; defaults to
   * `PULL_INACTIVITY_TIMEOUT_MS`.
   */
  pullInactivityTimeoutMs?: number;
  /** Absolute ceiling for one streaming pull; defaults to `PULL_ABSOLUTE_CEILING_MS`. */
  pullCeilingMs?: number;
  /** Optional fetch implementation override for tests. */
  fetchImpl?: typeof fetch;
}

/**
 * One NDJSON line from `POST /api/pull`. Ollama reports a coarse `status`
 * (`pulling manifest`, `pulling <digest>`, `verifying sha256 digest`,
 * `success`) plus byte counters while a layer downloads.
 */
export interface OllamaPullProgress {
  status: string;
  digest?: string;
  total?: number;
  completed?: number;
}

export interface OllamaPullOptions {
  /**
   * Invoked once per NDJSON line, including the terminal `success` line, so a
   * caller can report movement on its own operator channel. A throw from this
   * callback is the caller's defect and is never allowed to abort the pull.
   */
  onProgress?: (progress: OllamaPullProgress) => void;
}

export interface OllamaTagsResponse {
  models: Array<{
    name: string;
    model?: string;
    digest?: string;
    /** ISO8601 timestamp; not consumed by the selector. */
    modified_at?: string;
    size?: number;
  }>;
}

export interface OllamaMutationResult {
  ok: boolean;
  failureClass: SubstrateResponse["failureClass"];
}

export interface OllamaShowResult extends OllamaMutationResult {
  /** Lowercase SHA-256 hex observed from Ollama, or null on refusal. */
  digest: string | null;
}

const SHA256_DIGEST = /^(?:sha256:)?([0-9a-f]{64})$/;

export class OllamaClient {
  private endpoint: string;
  private timeoutMs: number;
  private pullInactivityTimeoutMs: number;
  private pullCeilingMs: number;
  private fetchImpl: typeof fetch;

  constructor(config: OllamaClientConfig) {
    this.endpoint = stripTrailingSlashes(config.endpoint);
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.pullInactivityTimeoutMs = config.pullInactivityTimeoutMs ??
      PULL_INACTIVITY_TIMEOUT_MS;
    this.pullCeilingMs = config.pullCeilingMs ?? PULL_ABSOLUTE_CEILING_MS;
    this.fetchImpl = config.fetchImpl ?? fetch;
    // A non-positive or non-finite pull bound would disable the deadline that
    // keeps a stalled pull from hanging the ceremony forever; refuse the client
    // rather than run one unbounded.
    if (!Number.isFinite(this.pullInactivityTimeoutMs) || this.pullInactivityTimeoutMs <= 0) {
      throw new Error("Ollama pull inactivity timeout must be positive");
    }
    if (!Number.isFinite(this.pullCeilingMs) || this.pullCeilingMs <= 0) {
      throw new Error("Ollama pull ceiling must be positive");
    }
  }

  /**
   * Probe Ollama at `/api/tags`. Returns `null` if unreachable; the selector
   * surfaces install guidance to the operator on null.
   */
  async listModels(): Promise<string[] | null> {
    try {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), HARDWARE_PROBE_TIMEOUT_MS);
      try {
        const res = await this.fetchImpl(`${this.endpoint}/api/tags`, {
          method: "GET",
          signal: ctl.signal,
        });
        if (!res.ok) return null;
        const body = (await res.json()) as OllamaTagsResponse;
        return body.models?.map((m) => m.name) ?? [];
      } finally {
        clearTimeout(timer);
      }
    } catch {
      return null;
    }
  }

  /**
   * Pull one manifest-approved runtime tag.
   *
   * `stream:true` is what makes a multi-gigabyte download completable: the
   * request is bounded by silence between NDJSON progress lines and by an
   * absolute ceiling, never by `timeoutMs`, which a healthy pull exceeds by
   * orders of magnitude. The pull counts as done only when the runtime's own
   * final line says `success`; an inline `error` line, a stream that ends
   * without that line, a line or response past the reviewed byte caps, and a
   * deadline are all refusals, because a half-finished download that reported
   * "ok" would carry a partial blob into the digest check. Callers still verify
   * `/api/show` against the signed manifest before trusting the result.
   */
  async pull(
    model: string,
    options: OllamaPullOptions = {},
  ): Promise<OllamaMutationResult> {
    const ctl = new AbortController();
    const startedAt = Date.now();
    let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
    try {
      const res = await raceDeadline(
        this.fetchImpl(`${this.endpoint}/api/pull`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ model, stream: true }),
          signal: ctl.signal,
        }),
        this.pullInactivityTimeoutMs,
      );
      if (!res.ok) {
        // `res.text()` would await a body the runtime controls and may never
        // end, holding this pull -- and the provisioning lock it runs under --
        // open indefinitely. The classifying snippet is read through the same
        // bounded reader as the stream: byte cap, inactivity deadline, and the
        // abort/cancel in the finally below.
        reader = res.body === null ? null : res.body.getReader();
        const snippet = reader === null
          ? ""
          : await readBoundedText(
            reader,
            PULL_ERROR_BODY_MAX_BYTES,
            this.pullInactivityTimeoutMs,
          );
        return { ok: false, failureClass: classifyHttpError(res.status, snippet) };
      }
      if (res.body === null) {
        // Without a body there can be no terminal `success` line, so there is no
        // evidence the model landed; never report an unwitnessed pull as done.
        return { ok: false, failureClass: "substrate_unavailable" };
      }
      reader = res.body.getReader();
      const decoder = new TextDecoder();
      let pending = "";
      let responseBytes = 0;
      let lastProgressAt = Date.now();
      let sawSuccess = false;
      for (;;) {
        const now = Date.now();
        const budgetMs = Math.min(
          this.pullCeilingMs - (now - startedAt),
          this.pullInactivityTimeoutMs - (now - lastProgressAt),
        );
        if (budgetMs <= 0) return { ok: false, failureClass: "substrate_timeout" };
        const chunk = await raceDeadline(reader.read(), budgetMs);
        if (chunk.done) break;
        // Both caps are checked BEFORE the chunk is decoded or appended, so an
        // over-cap stream is refused without ever being buffered as a string.
        // A stream past either reviewed bound is a runtime not speaking the
        // protocol this client reviewed; refuse instead of reading on.
        responseBytes += chunk.value.byteLength;
        if (responseBytes > PULL_RESPONSE_MAX_BYTES) {
          return { ok: false, failureClass: "substrate_misconfigured" };
        }
        if (
          utf8ByteLength(pending) + chunk.value.byteLength >
            PULL_PENDING_BUFFER_MAX_BYTES
        ) {
          return { ok: false, failureClass: "substrate_misconfigured" };
        }
        pending += decoder.decode(chunk.value, { stream: true });
        let newlineAt = pending.indexOf("\n");
        while (newlineAt !== -1) {
          const line = pending.slice(0, newlineAt);
          pending = pending.slice(newlineAt + 1);
          // The per-line cap binds a TERMINATED line too. Checking only the
          // unterminated remainder would let a runtime send one arbitrarily
          // long line, end it with a newline, and have it parsed as progress
          // (refreshing the inactivity deadline) all the way to the response
          // cap.
          if (utf8ByteLength(line) > PULL_PROGRESS_LINE_MAX_BYTES) {
            return { ok: false, failureClass: "substrate_misconfigured" };
          }
          const verdict = parsePullLine(line);
          if (verdict.kind === "refused") {
            return { ok: false, failureClass: verdict.failureClass };
          }
          if (verdict.kind !== "blank") {
            // Only a parsed line is evidence of progress, so only a parsed line
            // refreshes the inactivity deadline; a drip of bytes carrying no
            // line must not hold the pull open.
            lastProgressAt = Date.now();
            reportProgress(options.onProgress, verdict.progress);
            if (verdict.kind === "success") sawSuccess = true;
          }
          newlineAt = pending.indexOf("\n");
        }
        // The remainder is one unterminated line, so the same per-line cap
        // binds it: a runtime that never emits a newline is refused here.
        if (utf8ByteLength(pending) > PULL_PROGRESS_LINE_MAX_BYTES) {
          return { ok: false, failureClass: "substrate_misconfigured" };
        }
      }
      // Flushing the decoder emits the replacement character for a truncated
      // multibyte sequence rather than dropping it, so a mangled final line
      // fails the parser instead of vanishing.
      pending += decoder.decode();
      // Ollama terminates the stream with a newline, but a final line without
      // one is still the runtime's verdict and is judged by the same parser.
      if (pending.trim().length > 0) {
        if (utf8ByteLength(pending) > PULL_PROGRESS_LINE_MAX_BYTES) {
          return { ok: false, failureClass: "substrate_misconfigured" };
        }
        const verdict = parsePullLine(pending);
        if (verdict.kind === "refused") {
          return { ok: false, failureClass: verdict.failureClass };
        }
        if (verdict.kind !== "blank") {
          reportProgress(options.onProgress, verdict.progress);
          if (verdict.kind === "success") sawSuccess = true;
        }
      }
      // A stream that ended without the runtime's own `success` line proves
      // nothing about what is on disk, so it fails closed.
      return sawSuccess
        ? { ok: true, failureClass: null }
        : { ok: false, failureClass: "substrate_unavailable" };
    } catch (err) {
      if (err instanceof PullDeadlineError) {
        return { ok: false, failureClass: "substrate_timeout" };
      }
      const aborted = err instanceof Error && err.name === "AbortError";
      return {
        ok: false,
        failureClass: aborted ? "substrate_timeout" : "substrate_unavailable",
      };
    } finally {
      // Every exit path releases the connection, so a refused or deadlined pull
      // cannot leave a download running behind the ceremony's back.
      if (reader !== null) void reader.cancel().catch(() => undefined);
      ctl.abort();
    }
  }

  /**
   * Observe one exact installed runtime tag, then return its registry digest.
   * Current Ollama `/api/show` proves the model exists but exposes the digest
   * through `/api/tags`; older/future compatible digest fields are accepted
   * directly. A missing or malformed SHA-256 is always a refusal.
   */
  async show(model: string): Promise<OllamaShowResult> {
    try {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), this.timeoutMs);
      try {
        const res = await this.fetchImpl(`${this.endpoint}/api/show`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ model }),
          signal: ctl.signal,
        });
        if (!res.ok) {
          const text = await res.text().catch(() => "");
          return {
            ok: false,
            failureClass: classifyHttpError(res.status, text),
            digest: null,
          };
        }
        const body = (await res.json()) as {
          digest?: unknown;
          details?: { digest?: unknown };
        };
        const raw = typeof body.digest === "string"
          ? body.digest
          : typeof body.details?.digest === "string"
            ? body.details.digest
            : null;
        let match = raw?.toLowerCase().match(SHA256_DIGEST) ?? null;
        if (!match) {
          const tagsResponse = await this.fetchImpl(`${this.endpoint}/api/tags`, {
            method: "GET",
            signal: ctl.signal,
          });
          if (!tagsResponse.ok) {
            const text = await tagsResponse.text().catch(() => "");
            return {
              ok: false,
              failureClass: classifyHttpError(tagsResponse.status, text),
              digest: null,
            };
          }
          const tags = (await tagsResponse.json()) as OllamaTagsResponse;
          const installed = tags.models?.find(
            (entry) => entry.name === model || entry.model === model,
          );
          match = installed?.digest?.toLowerCase().match(SHA256_DIGEST) ?? null;
        }
        if (!match) {
          return {
            ok: false,
            failureClass: "substrate_misconfigured",
            digest: null,
          };
        }
        return { ok: true, failureClass: null, digest: match[1]! };
      } finally {
        clearTimeout(timer);
      }
    } catch (err) {
      const aborted = err instanceof Error && err.name === "AbortError";
      return {
        ok: false,
        failureClass: aborted ? "substrate_timeout" : "substrate_unavailable",
        digest: null,
      };
    }
  }

  /**
   * Generate a completion. Maps to `POST /api/generate` with `stream: false`
   * for v1.2; streaming is a v1.3+ enhancement (the chat surface will need
   * SSE forwarding then).
   */
  async generate(args: {
    model: string;
    prompt: string;
    system?: string;
    maxTokens?: number;
  }): Promise<SubstrateResponse> {
    const startedAt = Date.now();
    try {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), this.timeoutMs);
      try {
        const res = await this.fetchImpl(`${this.endpoint}/api/generate`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            model: args.model,
            prompt: args.prompt,
            system: args.system,
            stream: false,
            options: args.maxTokens ? { num_predict: args.maxTokens } : undefined,
          }),
          signal: ctl.signal,
        });
        if (!res.ok) {
          const text = await res.text().catch(() => "");
          return failure({
            startedAt,
            class: classifyHttpError(res.status, text),
            message: `ollama HTTP ${res.status}`,
          });
        }
        const body = (await res.json()) as { response?: string };
        const text = body.response ?? "";
        return {
          servedBy: "local",
          failureClass: null,
          body: { kind: "summarize", text },
          completedAt: new Date().toISOString(),
          latencyMs: Date.now() - startedAt,
        };
      } finally {
        clearTimeout(timer);
      }
    } catch (err) {
      const aborted = err instanceof Error && err.name === "AbortError";
      return failure({
        startedAt,
        class: aborted ? "substrate_timeout" : "substrate_unavailable",
        message: aborted ? "ollama timeout" : "ollama unreachable",
      });
    }
  }

}

/** Raised when a pull's inactivity or absolute deadline elapses first. */
class PullDeadlineError extends Error {
  constructor() {
    super("ollama pull deadline");
    this.name = "PullDeadlineError";
  }
}

/**
 * Bound `work` by `budgetMs` without depending on the fetch implementation to
 * honor an abort signal: a runtime (or a seam) that ignores `signal` would
 * otherwise let a stalled read hang the ceremony forever.
 */
async function raceDeadline<T>(work: Promise<T>, budgetMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  // The losing side of the race still settles; this handler keeps its rejection
  // from surfacing as an unhandled rejection after the deadline wins.
  void work.catch(() => undefined);
  try {
    return await Promise.race([
      work,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new PullDeadlineError()), budgetMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function utf8ByteLength(text: string): number {
  // The caps are byte caps; a UTF-16 length would under-count a multibyte line
  // by up to a factor of three and let it past a bound stated in bytes.
  return text.length === 0 ? 0 : PULL_LINE_ENCODER.encode(text).length;
}

/**
 * Read at most `maxBytes` from an already-open body reader, bounded by the same
 * deadline the stream uses. Used only for an error snippet the caller passes to
 * `classifyHttpError`, so a read failure or a body that never ends yields the
 * bytes seen so far and lets the HTTP status carry the classification; the
 * caller's `finally` cancels the reader and aborts the request.
 */
async function readBoundedText(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  maxBytes: number,
  budgetMs: number,
): Promise<string> {
  const decoder = new TextDecoder();
  let text = "";
  let bytes = 0;
  try {
    for (;;) {
      const chunk = await raceDeadline(reader.read(), budgetMs);
      if (chunk.done) break;
      bytes += chunk.value.byteLength;
      text += decoder.decode(chunk.value, { stream: true });
      if (bytes >= maxBytes) break;
    }
  } catch {
    // A stalled or failed error body is not itself the verdict; the status code
    // is. Returning what was read keeps this path bounded and fail-closed.
  }
  return text;
}

type PullLineVerdict =
  | { kind: "blank" }
  | { kind: "progress"; progress: OllamaPullProgress }
  | { kind: "success"; progress: OllamaPullProgress }
  | { kind: "refused"; failureClass: SubstrateResponse["failureClass"] };

/**
 * Judge one NDJSON line. Every state is named here rather than defaulting to
 * "keep going": a line this parser does not model is a refusal, so a runtime
 * that stops speaking the reviewed protocol can never be read as progress.
 */
function parsePullLine(raw: string): PullLineVerdict {
  const text = raw.trim();
  if (text.length === 0) return { kind: "blank" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { kind: "refused", failureClass: "substrate_misconfigured" };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { kind: "refused", failureClass: "substrate_misconfigured" };
  }
  const record = parsed as {
    status?: unknown;
    error?: unknown;
    digest?: unknown;
    total?: unknown;
    completed?: unknown;
  };
  if (record.error !== undefined) {
    // Ollama reports a registry or model failure inline on an HTTP 200 stream;
    // failing closed here is what stops a refused pull from reaching the digest
    // check as a success.
    return {
      kind: "refused",
      failureClass: typeof record.error === "string"
        ? classifyPullErrorLine(record.error)
        : "substrate_misconfigured",
    };
  }
  if (typeof record.status !== "string" || record.status.length === 0) {
    return { kind: "refused", failureClass: "substrate_misconfigured" };
  }
  const progress: OllamaPullProgress = {
    status: record.status,
    ...(typeof record.digest === "string" ? { digest: record.digest } : {}),
    ...(typeof record.total === "number" ? { total: record.total } : {}),
    ...(typeof record.completed === "number" ? { completed: record.completed } : {}),
  };
  return record.status === "success"
    ? { kind: "success", progress }
    : { kind: "progress", progress };
}

/** Same intent as `classifyHttpError`, applied to an in-stream error string. */
function classifyPullErrorLine(
  message: string,
): "substrate_misconfigured" | "substrate_rate_limited" | "substrate_unavailable" {
  if (/rate limit|too many requests/i.test(message)) return "substrate_rate_limited";
  if (/not found|does not exist|unknown model|no such/i.test(message)) {
    return "substrate_misconfigured";
  }
  return "substrate_unavailable";
}

function reportProgress(
  onProgress: OllamaPullOptions["onProgress"],
  progress: OllamaPullProgress,
): void {
  if (onProgress === undefined) return;
  try {
    onProgress(progress);
  } catch {
    // Reporting is an operator-channel convenience; a reporter defect must never
    // turn a live download into a refusal.
  }
}

/**
 * Local substrate adapter — translates Surface request shape into Ollama
 * generate calls.
 */
export class LocalSubstrate {
  private client: OllamaClient;
  private model: string;

  constructor(client: OllamaClient, model: string) {
    this.client = client;
    this.model = model;
  }

  static fromPick(client: OllamaClient, pick: LocalModelPick, customTag?: string): LocalSubstrate {
    // The custom tag wins on both sides: the unarmed badge label in
    // `intelligence/selector.ts` (`gatedLocalHandle`) must prefer the same
    // `customTag` this constructor does, or the operator is shown the name of
    // a model this substrate never calls. Past that one shared arm the two
    // diverge on purpose, the label naming the pick for a human and this
    // constructor naming the tag for Ollama.
    return new LocalSubstrate(client, customTag ?? LOCAL_MODEL_TAGS[pick]);
  }

  async summarize(req: SummarizeRequest): Promise<SubstrateResponse> {
    const prompt = `Context:\n${req.context}\n\nQuestion: ${req.query}\n\nAnswer concisely:`;
    return this.client.generate({
      model: this.model,
      prompt,
      maxTokens: req.maxTokens,
    });
  }

  async classify(req: ClassifyRequest): Promise<SubstrateResponse> {
    const startedAt = Date.now();
    const promptParts: string[] = [];
    promptParts.push(`Categories: ${req.categories.join(", ")}`);
    promptParts.push("Items:");
    for (const item of req.items) promptParts.push(`- ${item}`);
    promptParts.push(
      "Return JSON array of {category, confidence} per item, in order. Confidence is 0.0-1.0."
    );
    const llm = await this.client.generate({
      model: this.model,
      prompt: promptParts.join("\n"),
      maxTokens: req.maxTokens ?? 512,
    });
    if (llm.failureClass) return llm;
    const text = (llm.body.kind === "summarize" ? llm.body.text : "").trim();
    const parsed = tryParseClassification(text);
    if (!parsed) {
      return failure({
        startedAt,
        class: "substrate_capability_unsupported",
        message: "ollama returned non-JSON classification",
      });
    }
    return {
      servedBy: "local",
      failureClass: null,
      body: { kind: "classify", results: parsed },
      completedAt: new Date().toISOString(),
      latencyMs: Date.now() - startedAt,
    };
  }

  async redact(req: RedactRequest): Promise<SubstrateResponse> {
    const startedAt = Date.now();
    const llm = await this.client.generate({
      model: this.model,
      prompt:
        "You are a PII redaction filter. Replace every PII span (names, addresses, emails, phone numbers, IDs) with [REDACTED:N] markers, where N is a stable counter. Return only the redacted text.\n\n" +
        req.text,
      maxTokens: 1024,
    });
    if (llm.failureClass) return llm;
    const redacted = (llm.body.kind === "summarize" ? llm.body.text : "").trim();
    return {
      servedBy: "local",
      failureClass: null,
      body: { kind: "redact", redacted, placeholders: {} },
      completedAt: new Date().toISOString(),
      latencyMs: Date.now() - startedAt,
    };
  }
}

function classifyHttpError(
  status: number,
  body: string,
): "substrate_unavailable" | "substrate_misconfigured" | "substrate_rate_limited" | "substrate_capability_unsupported" {
  if (status === 429) return "substrate_rate_limited";
  if (status === 404 && /model.*not found/i.test(body)) return "substrate_misconfigured";
  if (status >= 500) return "substrate_unavailable";
  return "substrate_capability_unsupported";
}

function failure(args: {
  startedAt: number;
  class: SubstrateResponse["failureClass"];
  message: string;
}): SubstrateResponse {
  return {
    servedBy: "local",
    failureClass: args.class,
    body: { kind: "failure", message: args.message },
    completedAt: new Date().toISOString(),
    latencyMs: Date.now() - args.startedAt,
  };
}

function tryParseClassification(
  text: string,
): { category: string; confidence: number }[] | null {
  // Strip Markdown code fences if present.
  const stripped = text
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```\s*$/i, "")
    .trim();
  try {
    const parsed = JSON.parse(stripped);
    if (!Array.isArray(parsed)) return null;
    const out: { category: string; confidence: number }[] = [];
    for (const entry of parsed) {
      if (
        typeof entry === "object" &&
        entry !== null &&
        typeof (entry as { category?: unknown }).category === "string" &&
        typeof (entry as { confidence?: unknown }).confidence === "number"
      ) {
        out.push({
          category: (entry as { category: string }).category,
          confidence: (entry as { confidence: number }).confidence,
        });
      }
    }
    return out.length === 0 ? null : out;
  } catch {
    return null;
  }
}
