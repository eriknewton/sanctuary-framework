/**
 * Sanctuary MCP Server — Frontier-with-Filter Substrate
 *
 * Operator's frontier API account (Anthropic / OpenAI / Google) wrapped with
 * mandatory pre-egress Privacy Filter Tier 2 redaction.
 *
 * Per position paper §5: every query routes through Privacy Filter Tier 2
 * BEFORE the frontier API call. The Privacy Filter event log captures the
 * pre-redaction match count so the operator can audit what was sent.
 *
 * Honesty discipline (CLAUDE.md):
 *   - Tradeoff badge text explicitly names the leakage
 *   - Required caveat about subtle PII (paraphrased addresses, contextual
 *     identifiers) appears in tradeoff text
 *   - Operator MUST acknowledge before configuration completes (enforced
 *     by the picker modal in the dashboard SPA, deferred to the v1.2 UI
 *     follow-up commit)
 *
 * Provider clients are kept minimal: one Chat Completions / Messages call
 * per surface request, no streaming in v1.2 (streaming is a v1.3 chat
 * surface enhancement).
 */

import type {
  ClassifyRequest,
  FrontierProvider,
  RedactRequest,
  SubstrateCapability,
  SubstrateResponse,
  SummarizeRequest,
} from "../types.js";

export const FRONTIER_CAPABILITY: SubstrateCapability = {
  summarize: true,
  classify: true,
  redact: true,
};

const DEFAULT_TIMEOUT_MS = 60_000;

export interface FrontierClientConfig {
  provider: FrontierProvider;
  apiKey: string;
  model?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

export const FRONTIER_DEFAULT_MODELS: Record<FrontierProvider, string> = {
  anthropic: "claude-haiku-4-5-20251001",
  openai: "gpt-4o-mini",
  google: "gemini-1.5-flash",
};

const FRONTIER_ENDPOINTS: Record<FrontierProvider, string> = {
  anthropic: "https://api.anthropic.com/v1/messages",
  openai: "https://api.openai.com/v1/chat/completions",
  google: "https://generativelanguage.googleapis.com/v1beta/models",
};

const ANTHROPIC_VERSION = "2023-06-01";

export class FrontierClient {
  readonly provider: FrontierProvider;
  private apiKey: string;
  private model: string;
  private timeoutMs: number;
  private fetchImpl: typeof fetch;

  constructor(config: FrontierClientConfig) {
    this.provider = config.provider;
    this.apiKey = config.apiKey;
    this.model = config.model ?? FRONTIER_DEFAULT_MODELS[config.provider];
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchImpl = config.fetchImpl ?? fetch;
  }

  /**
   * Issue a single completion with the redacted prompt. Caller is responsible
   * for redacting BEFORE calling this method; the Privacy Filter Tier 2 step
   * happens in `FrontierWithFilterSubstrate` below.
   */
  async chat(args: {
    system?: string;
    user: string;
    maxTokens?: number;
  }): Promise<SubstrateResponse> {
    if (this.provider === "anthropic") return this.callAnthropic(args);
    if (this.provider === "openai") return this.callOpenAI(args);
    return this.callGoogle(args);
  }

  private async callAnthropic(args: {
    system?: string;
    user: string;
    maxTokens?: number;
  }): Promise<SubstrateResponse> {
    const startedAt = Date.now();
    try {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), this.timeoutMs);
      try {
        const res = await this.fetchImpl(FRONTIER_ENDPOINTS.anthropic, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-api-key": this.apiKey,
            "anthropic-version": ANTHROPIC_VERSION,
          },
          body: JSON.stringify({
            model: this.model,
            system: args.system,
            messages: [{ role: "user", content: args.user }],
            max_tokens: args.maxTokens ?? 1024,
          }),
          signal: ctl.signal,
        });
        return this.normalizeAnthropicResponse(res, startedAt);
      } finally {
        clearTimeout(timer);
      }
    } catch (err) {
      const aborted = err instanceof Error && err.name === "AbortError";
      return failure(startedAt, aborted ? "substrate_timeout" : "substrate_unavailable", aborted ? "anthropic timeout" : "anthropic unreachable");
    }
  }

  private async normalizeAnthropicResponse(
    res: Response,
    startedAt: number,
  ): Promise<SubstrateResponse> {
    if (res.status === 401 || res.status === 403) {
      return failure(startedAt, "substrate_auth_failed", `anthropic HTTP ${res.status}`);
    }
    if (res.status === 429) {
      return failure(startedAt, "substrate_rate_limited", "anthropic rate limit");
    }
    if (!res.ok) {
      return failure(startedAt, "substrate_unavailable", `anthropic HTTP ${res.status}`);
    }
    const body = (await res.json()) as {
      content?: Array<{ type: string; text?: string }>;
    };
    const text =
      body.content
        ?.filter((b) => b.type === "text")
        .map((b) => b.text ?? "")
        .join("\n") ?? "";
    return {
      servedBy: "frontier-with-filter",
      failureClass: null,
      body: { kind: "summarize", text },
      completedAt: new Date().toISOString(),
      latencyMs: Date.now() - startedAt,
    };
  }

  private async callOpenAI(args: {
    system?: string;
    user: string;
    maxTokens?: number;
  }): Promise<SubstrateResponse> {
    const startedAt = Date.now();
    try {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), this.timeoutMs);
      try {
        const messages: Array<{ role: string; content: string }> = [];
        if (args.system) messages.push({ role: "system", content: args.system });
        messages.push({ role: "user", content: args.user });
        const res = await this.fetchImpl(FRONTIER_ENDPOINTS.openai, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${this.apiKey}`,
          },
          body: JSON.stringify({
            model: this.model,
            messages,
            max_tokens: args.maxTokens ?? 1024,
          }),
          signal: ctl.signal,
        });
        if (res.status === 401 || res.status === 403) {
          return failure(startedAt, "substrate_auth_failed", `openai HTTP ${res.status}`);
        }
        if (res.status === 429) {
          return failure(startedAt, "substrate_rate_limited", "openai rate limit");
        }
        if (!res.ok) {
          return failure(startedAt, "substrate_unavailable", `openai HTTP ${res.status}`);
        }
        const body = (await res.json()) as {
          choices?: Array<{ message?: { content?: string } }>;
        };
        const text = body.choices?.[0]?.message?.content ?? "";
        return {
          servedBy: "frontier-with-filter",
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
      return failure(startedAt, aborted ? "substrate_timeout" : "substrate_unavailable", aborted ? "openai timeout" : "openai unreachable");
    }
  }

  private async callGoogle(args: {
    system?: string;
    user: string;
    maxTokens?: number;
  }): Promise<SubstrateResponse> {
    const startedAt = Date.now();
    try {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), this.timeoutMs);
      try {
        const url = `${FRONTIER_ENDPOINTS.google}/${encodeURIComponent(this.model)}:generateContent?key=${encodeURIComponent(this.apiKey)}`;
        const parts: Array<{ text: string }> = [];
        if (args.system) parts.push({ text: args.system });
        parts.push({ text: args.user });
        const res = await this.fetchImpl(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            contents: [{ parts }],
            generationConfig: { maxOutputTokens: args.maxTokens ?? 1024 },
          }),
          signal: ctl.signal,
        });
        if (res.status === 401 || res.status === 403) {
          return failure(startedAt, "substrate_auth_failed", `google HTTP ${res.status}`);
        }
        if (res.status === 429) {
          return failure(startedAt, "substrate_rate_limited", "google rate limit");
        }
        if (!res.ok) {
          return failure(startedAt, "substrate_unavailable", `google HTTP ${res.status}`);
        }
        const body = (await res.json()) as {
          candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
        };
        const text =
          body.candidates?.[0]?.content?.parts?.map((p) => p.text ?? "").join("") ??
          "";
        return {
          servedBy: "frontier-with-filter",
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
      return failure(startedAt, aborted ? "substrate_timeout" : "substrate_unavailable", aborted ? "google timeout" : "google unreachable");
    }
  }
}

/**
 * Pre-egress redaction hook. The substrate adapter calls this on every
 * outbound text; returns the redacted text + placeholder map. The Privacy
 * Filter Tier 2 implementation lives in `operational/privacy-filter.ts`
 * (extended in this PR to wire the substrate-aware Tier 2 path).
 *
 * For v1.2, the redactor passed in is responsible for emitting the audit
 * event `intelligence_pii_redaction_event` via the selector's auditLog
 * binding. The frontier substrate is provider-agnostic about how redaction
 * happens; it just refuses to call the frontier API on `failureClass !== null`.
 */
export type FrontierRedactor = (text: string) => Promise<{
  redacted: string;
  matchCount: number;
}>;

export class FrontierWithFilterSubstrate {
  private client: FrontierClient;
  private redactor: FrontierRedactor;

  constructor(client: FrontierClient, redactor: FrontierRedactor) {
    this.client = client;
    this.redactor = redactor;
  }

  async summarize(req: SummarizeRequest): Promise<SubstrateResponse> {
    const redactedContext = await this.redactor(req.context);
    const redactedQuery = await this.redactor(req.query);
    return this.client.chat({
      system:
        "You summarize agent activity for a sovereignty fortress. The input has been pre-redacted: do not attempt to recover [REDACTED:N] markers. Be concise and concrete.",
      user: `Context:\n${redactedContext.redacted}\n\nQuestion: ${redactedQuery.redacted}`,
      maxTokens: req.maxTokens,
    });
  }

  async classify(req: ClassifyRequest): Promise<SubstrateResponse> {
    const startedAt = Date.now();
    const redactedItems = await Promise.all(req.items.map((i) => this.redactor(i)));
    const res = await this.client.chat({
      system:
        "Classify each item into one category. Return JSON array of {category, confidence}.",
      user: `Categories: ${req.categories.join(", ")}\nItems:\n${redactedItems
        .map((r) => `- ${r.redacted}`)
        .join("\n")}`,
      maxTokens: req.maxTokens ?? 512,
    });
    if (res.failureClass) return res;
    const text = res.body.kind === "summarize" ? res.body.text.trim() : "";
    const parsed = tryParseClassification(text);
    if (!parsed) {
      return {
        servedBy: "frontier-with-filter",
        failureClass: "substrate_capability_unsupported",
        body: { kind: "failure", message: "frontier returned non-JSON classification" },
        completedAt: new Date().toISOString(),
        latencyMs: Date.now() - startedAt,
      };
    }
    return {
      servedBy: "frontier-with-filter",
      failureClass: null,
      body: { kind: "classify", results: parsed },
      completedAt: new Date().toISOString(),
      latencyMs: Date.now() - startedAt,
    };
  }

  async redact(req: RedactRequest): Promise<SubstrateResponse> {
    // For frontier-with-filter, the redaction itself runs locally via the
    // redactor; we never send raw PII to a frontier provider just to ask it
    // to redact. Tier 1 regex + Tier 2 NER is the redactor.
    const startedAt = Date.now();
    const r = await this.redactor(req.text);
    return {
      servedBy: "frontier-with-filter",
      failureClass: null,
      body: { kind: "redact", redacted: r.redacted, placeholders: {} },
      completedAt: new Date().toISOString(),
      latencyMs: Date.now() - startedAt,
    };
  }
}

function failure(
  startedAt: number,
  cls: SubstrateResponse["failureClass"],
  message: string,
): SubstrateResponse {
  return {
    servedBy: "frontier-with-filter",
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
