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

export const LOCAL_CAPABILITY: SubstrateCapability = {
  summarize: true,
  classify: true,
  redact: true,
};

const DEFAULT_TIMEOUT_MS = 30_000;
const HARDWARE_PROBE_TIMEOUT_MS = 1_500;

export interface OllamaClientConfig {
  endpoint: string;
  /** Per-invocation timeout in ms; defaults to 30s. */
  timeoutMs?: number;
  /** Optional fetch implementation override for tests. */
  fetchImpl?: typeof fetch;
}

export interface OllamaTagsResponse {
  models: Array<{
    name: string;
    /** ISO8601 timestamp; not consumed by the selector. */
    modified_at?: string;
    size?: number;
  }>;
}

export class OllamaClient {
  private endpoint: string;
  private timeoutMs: number;
  private fetchImpl: typeof fetch;

  constructor(config: OllamaClientConfig) {
    this.endpoint = config.endpoint.replace(/\/+$/, "");
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchImpl = config.fetchImpl ?? fetch;
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
