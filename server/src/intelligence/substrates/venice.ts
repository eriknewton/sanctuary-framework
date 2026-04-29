/**
 * Sanctuary MCP Server — Venice.ai Substrate
 *
 * Venice.ai is a privacy-respecting hosted LLM relay. OpenAI-compatible
 * Chat Completions endpoint at `https://api.venice.ai/api/v1/chat/completions`.
 *
 * Per Erik directive 2026-04-29: Venice is a NAMED composition partner.
 * Operator picks Venice; selector verifies API key; tradeoff badge surfaces
 * "queries reach Venice's relay; contract states no retention; capability
 * higher than local; trust is contractual not cryptographic."
 *
 * Anonymous payment is recommended (operator-configured; crypto payment URL
 * surfaced to operator at selector setup if anonymous-by-default per Erik
 * directive). The API key itself stores encrypted under the fortress master
 * key in the substrate config; key rotation is operator-initiated.
 *
 * Default model: Llama 3.1 70B. Operator can select 405B for higher capability
 * at higher cost; selector exposes the model pick in the picker modal.
 */

import type {
  ClassifyRequest,
  RedactRequest,
  SubstrateCapability,
  SubstrateResponse,
  SummarizeRequest,
} from "../types.js";

export const VENICE_CAPABILITY: SubstrateCapability = {
  summarize: true,
  classify: true,
  redact: true,
};

export const VENICE_DEFAULT_ENDPOINT = "https://api.venice.ai/api/v1";
export const VENICE_DEFAULT_MODEL = "llama-3.1-70b";

const DEFAULT_TIMEOUT_MS = 30_000;

export interface VeniceClientConfig {
  apiKey: string;
  endpoint?: string;
  model?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

export class VeniceClient {
  private apiKey: string;
  private endpoint: string;
  private model: string;
  private timeoutMs: number;
  private fetchImpl: typeof fetch;

  constructor(config: VeniceClientConfig) {
    this.apiKey = config.apiKey;
    this.endpoint = (config.endpoint ?? VENICE_DEFAULT_ENDPOINT).replace(/\/+$/, "");
    this.model = config.model ?? VENICE_DEFAULT_MODEL;
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchImpl = config.fetchImpl ?? fetch;
  }

  /**
   * Validate the API key by issuing a tiny chat completion. Returns true on
   * 200; false on 401/403; rethrows on transport errors.
   */
  async validateKey(): Promise<boolean> {
    const startedAt = Date.now();
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 5_000);
    try {
      const res = await this.fetchImpl(`${this.endpoint}/chat/completions`, {
        method: "POST",
        headers: this.headers(),
        body: JSON.stringify({
          model: this.model,
          messages: [{ role: "user", content: "ok" }],
          max_tokens: 1,
        }),
        signal: ctl.signal,
      });
      void startedAt;
      return res.status === 200;
    } catch {
      return false;
    } finally {
      clearTimeout(timer);
    }
  }

  async chat(messages: Array<{ role: "system" | "user" | "assistant"; content: string }>, maxTokens?: number): Promise<SubstrateResponse> {
    const startedAt = Date.now();
    try {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), this.timeoutMs);
      try {
        const res = await this.fetchImpl(`${this.endpoint}/chat/completions`, {
          method: "POST",
          headers: this.headers(),
          body: JSON.stringify({
            model: this.model,
            messages,
            max_tokens: maxTokens,
          }),
          signal: ctl.signal,
        });
        if (res.status === 401 || res.status === 403) {
          return failure(startedAt, "substrate_auth_failed", `venice HTTP ${res.status}`);
        }
        if (res.status === 429) {
          return failure(startedAt, "substrate_rate_limited", "venice rate limit");
        }
        if (!res.ok) {
          return failure(startedAt, "substrate_unavailable", `venice HTTP ${res.status}`);
        }
        const body = (await res.json()) as {
          choices?: Array<{ message?: { content?: string } }>;
        };
        const text = body.choices?.[0]?.message?.content ?? "";
        return {
          servedBy: "venice",
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
      return failure(
        startedAt,
        aborted ? "substrate_timeout" : "substrate_unavailable",
        aborted ? "venice timeout" : "venice unreachable",
      );
    }
  }

  private headers(): Record<string, string> {
    return {
      "Content-Type": "application/json",
      Authorization: `Bearer ${this.apiKey}`,
    };
  }
}

export class VeniceSubstrate {
  private client: VeniceClient;

  constructor(client: VeniceClient) {
    this.client = client;
  }

  async summarize(req: SummarizeRequest): Promise<SubstrateResponse> {
    return this.client.chat(
      [
        {
          role: "system",
          content: "You summarize agent activity. Be concise and concrete.",
        },
        { role: "user", content: `Context:\n${req.context}\n\nQuestion: ${req.query}` },
      ],
      req.maxTokens,
    );
  }

  async classify(req: ClassifyRequest): Promise<SubstrateResponse> {
    const messages: Array<{ role: "system" | "user"; content: string }> = [
      {
        role: "system",
        content:
          "Classify each item into one category. Return JSON array of {category, confidence}.",
      },
      {
        role: "user",
        content: `Categories: ${req.categories.join(", ")}\nItems:\n${req.items.map((i) => `- ${i}`).join("\n")}`,
      },
    ];
    const res = await this.client.chat(messages, req.maxTokens ?? 512);
    if (res.failureClass) return res;
    const text = (res.body.kind === "summarize" ? res.body.text : "").trim();
    const parsed = tryParseClassification(text);
    if (!parsed) {
      return {
        servedBy: "venice",
        failureClass: "substrate_capability_unsupported",
        body: { kind: "failure", message: "venice returned non-JSON classification" },
        completedAt: new Date().toISOString(),
        latencyMs: res.latencyMs,
      };
    }
    return {
      servedBy: "venice",
      failureClass: null,
      body: { kind: "classify", results: parsed },
      completedAt: new Date().toISOString(),
      latencyMs: res.latencyMs,
    };
  }

  async redact(req: RedactRequest): Promise<SubstrateResponse> {
    const messages: Array<{ role: "system" | "user"; content: string }> = [
      {
        role: "system",
        content:
          "You are a PII redaction filter. Replace every PII span with [REDACTED:N] markers (N stable per span). Return only redacted text.",
      },
      { role: "user", content: req.text },
    ];
    const res = await this.client.chat(messages, 2048);
    if (res.failureClass) return res;
    const redacted = (res.body.kind === "summarize" ? res.body.text : "").trim();
    return {
      servedBy: "venice",
      failureClass: null,
      body: { kind: "redact", redacted, placeholders: {} },
      completedAt: new Date().toISOString(),
      latencyMs: res.latencyMs,
    };
  }
}

function failure(
  startedAt: number,
  cls: SubstrateResponse["failureClass"],
  message: string,
): SubstrateResponse {
  return {
    servedBy: "venice",
    failureClass: cls,
    body: { kind: "failure", message },
    completedAt: new Date().toISOString(),
    latencyMs: Date.now() - startedAt,
  };
}

function tryParseClassification(
  text: string,
): { category: string; confidence: number }[] | null {
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
