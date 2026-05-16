import {
  CONCIERGE_READ_SURFACES,
  ConciergeUnavailableError,
  type ConciergeStatus,
  type VeniceClientLike,
  type VeniceCompleteRequest,
} from "./concierge-types.js";

export interface VeniceClientOptions {
  apiKey?: string;
  model?: string;
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  maxRetries?: number;
  circuitBreakerFailures?: number;
}

type VeniceChatResponse = {
  choices?: Array<{
    message?: { content?: string };
    delta?: { content?: string };
  }>;
};

const DEFAULT_BASE_URL = "https://api.venice.ai/api/v1";
const DEFAULT_MODEL = "venice-uncensored";
const TRANSIENT_STATUS = new Set([408, 409, 425, 429, 500, 502, 503, 504]);

export class VeniceClient implements VeniceClientLike {
  private readonly apiKey?: string;
  private readonly modelName: string;
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly maxRetries: number;
  private readonly circuitBreakerFailures: number;
  private failures = 0;

  constructor(options: VeniceClientOptions = {}) {
    this.apiKey = options.apiKey ?? process.env.VENICE_API_KEY;
    this.modelName = options.model ?? process.env.VENICE_MODEL ?? DEFAULT_MODEL;
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, "");
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.maxRetries = options.maxRetries ?? 2;
    this.circuitBreakerFailures = options.circuitBreakerFailures ?? 3;
  }

  model(): string {
    return this.modelName;
  }

  async checkStatus(): Promise<ConciergeStatus> {
    if (!this.apiKey) {
      return {
        provider: "venice",
        configured: false,
        reachable: false,
        model: this.modelName,
        read_surfaces: [...CONCIERGE_READ_SURFACES],
        fallback: "none",
        message: "VENICE_API_KEY is not configured",
      };
    }

    try {
      const res = await this.fetchImpl(`${this.baseUrl}/models`, {
        method: "GET",
        headers: this.authHeaders(),
      });
      return {
        provider: "venice",
        configured: true,
        reachable: res.ok,
        model: this.modelName,
        read_surfaces: [...CONCIERGE_READ_SURFACES],
        fallback: "none",
        message: res.ok ? "Venice reachable" : `Venice returned HTTP ${res.status}`,
      };
    } catch (cause) {
      return {
        provider: "venice",
        configured: true,
        reachable: false,
        model: this.modelName,
        read_surfaces: [...CONCIERGE_READ_SURFACES],
        fallback: "none",
        message: cause instanceof Error ? cause.message : String(cause),
      };
    }
  }

  async complete(request: VeniceCompleteRequest): Promise<string> {
    if (!this.apiKey) {
      throw new ConciergeUnavailableError("VENICE_API_KEY is not configured");
    }
    if (this.failures >= this.circuitBreakerFailures) {
      throw new ConciergeUnavailableError(
        "Venice is temporarily unavailable after repeated failures",
      );
    }

    const body = {
      model: request.model ?? this.modelName,
      messages: request.messages,
      stream: request.stream === true,
    };

    try {
      const answer = request.stream
        ? await this.completeStreaming(body, request.onToken)
        : await this.completeBuffered(body);
      this.failures = 0;
      return answer;
    } catch (cause) {
      this.failures++;
      if (cause instanceof ConciergeUnavailableError) throw cause;
      throw new ConciergeUnavailableError("Venice request failed", cause);
    }
  }

  private async completeBuffered(body: unknown): Promise<string> {
    const res = await this.fetchWithRetry(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: this.jsonHeaders(),
      body: JSON.stringify(body),
    });
    const json = (await res.json()) as VeniceChatResponse;
    const content = json.choices?.[0]?.message?.content;
    if (typeof content !== "string") {
      throw new ConciergeUnavailableError("Venice returned an empty response");
    }
    return content;
  }

  private async completeStreaming(
    body: unknown,
    onToken?: (token: string) => void,
  ): Promise<string> {
    const res = await this.fetchWithRetry(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: this.jsonHeaders(),
      body: JSON.stringify(body),
    });
    if (!res.body) return "";

    const decoder = new TextDecoder();
    const reader = res.body.getReader();
    let pending = "";
    let answer = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      pending += decoder.decode(value, { stream: true });
      const lines = pending.split(/\r?\n/);
      pending = lines.pop() ?? "";
      for (const line of lines) {
        const token = parseSseToken(line);
        if (!token) continue;
        answer += token;
        onToken?.(token);
      }
    }
    return answer;
  }

  private async fetchWithRetry(url: string, init: RequestInit): Promise<Response> {
    let lastError: unknown;
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      try {
        const res = await this.fetchImpl(url, init);
        if (res.ok) return res;
        if (!TRANSIENT_STATUS.has(res.status) || attempt === this.maxRetries) {
          throw new ConciergeUnavailableError(`Venice returned HTTP ${res.status}`);
        }
      } catch (cause) {
        lastError = cause;
        if (cause instanceof ConciergeUnavailableError || attempt === this.maxRetries) {
          throw cause;
        }
      }
      await delay(50 * 2 ** attempt);
    }
    throw new ConciergeUnavailableError("Venice request failed", lastError);
  }

  private jsonHeaders(): Headers {
    const headers = this.authHeaders();
    headers.set("Content-Type", "application/json");
    headers.set("Accept", "application/json");
    return headers;
  }

  private authHeaders(): Headers {
    const headers = new Headers();
    headers.set("Authorization", `Bearer ${this.apiKey ?? ""}`);
    return headers;
  }
}

function parseSseToken(line: string): string | null {
  const trimmed = line.trim();
  if (!trimmed.startsWith("data:")) return null;
  const data = trimmed.slice("data:".length).trim();
  if (!data || data === "[DONE]") return null;
  try {
    const parsed = JSON.parse(data) as VeniceChatResponse;
    return parsed.choices?.[0]?.delta?.content ?? null;
  } catch {
    return null;
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
