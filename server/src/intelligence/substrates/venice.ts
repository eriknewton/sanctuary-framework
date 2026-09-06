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
 * Default model: Llama 3.3 70B. Operator can select 405B for higher capability
 * at higher cost; selector exposes the model pick in the picker modal.
 *
 * Drift-resistance (v1.2.0-rc.1, Finding TT): Venice rotates model identifiers
 * without backwards-compat aliases. The substrate ships the current default,
 * `validateKey()` distinguishes auth-failure from model-not-found, and the
 * status badge surfaces invalid-model so operators see the actual cause when
 * the default eventually drifts again.
 */

import type {
  ClassifyRequest,
  RedactRequest,
  SubstrateCapability,
  SubstrateResponse,
  SummarizeRequest,
} from "../types.js";
import { stripTrailingSlashes } from "../../strings.js";

export const VENICE_CAPABILITY: SubstrateCapability = {
  summarize: true,
  classify: true,
  redact: true,
};

export const VENICE_DEFAULT_ENDPOINT = "https://api.venice.ai/api/v1";

/**
 * Default Venice model identifier. Reads `VENICE_DEFAULT_MODEL` from the
 * environment at module load so operators can override the shipped default
 * without a source patch (Finding YY, v1.2.0-rc.2). The acceptance-drill
 * "force runtime failure" path documents `VENICE_DEFAULT_MODEL=this-model-does-not-exist`
 * as the deliberate trigger; without this read, that path silently no-ops.
 *
 * Empty-string env value falls back to the shipped default rather than
 * propagating an obviously broken model identifier.
 */
function resolveVeniceDefaultModel(): string {
  const fromEnv = process.env.VENICE_DEFAULT_MODEL;
  if (typeof fromEnv === "string" && fromEnv.length > 0) {
    return fromEnv;
  }
  return "llama-3.3-70b";
}

export const VENICE_DEFAULT_MODEL = resolveVeniceDefaultModel();

const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * Result of `VeniceClient.validateKey`. Distinguishes the four meaningful
 * outcomes operators care about so the Intelligence panel badge can show
 * the actual cause instead of "auth failure" for any non-200.
 *
 *   ok            : auth + model both valid; substrate is callable
 *   invalid-key   : 401 / 403; operator's API key is wrong or revoked
 *   invalid-model : 404 + body matches model-not-found shape; operator's
 *                   key is fine but the configured model identifier has
 *                   drifted (Venice deprecates model IDs without alias).
 *                   The body usually names the replacement.
 *   unreachable   : transport error / non-200/401/403/404; treat as
 *                   substrate currently unavailable; operator may be
 *                   offline or Venice may be down.
 */
export type VeniceValidateResult =
  | "ok"
  | "invalid-key"
  | "invalid-model"
  | "unreachable";

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
    this.endpoint = stripTrailingSlashes(config.endpoint ?? VENICE_DEFAULT_ENDPOINT);
    this.model = config.model ?? VENICE_DEFAULT_MODEL;
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchImpl = config.fetchImpl ?? fetch;
  }

  /**
   * Validate the API key by issuing a tiny chat completion. Returns one of
   * the four `VeniceValidateResult` outcomes so the Intelligence panel
   * badge can distinguish auth-failure from model-drift (Finding TT,
   * v1.2.0-rc.1). Green badge requires `"ok"` (both auth AND model valid);
   * any other value flips the surface to a non-green state with a real
   * failure reason.
   */
  async validateKey(): Promise<VeniceValidateResult> {
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
      if (res.status === 200) return "ok";
      if (res.status === 401 || res.status === 403) return "invalid-key";
      if (res.status === 404 && (await isModelNotFound(res))) return "invalid-model";
      return "unreachable";
    } catch {
      return "unreachable";
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
        if (res.status === 404 && (await isModelNotFound(res.clone()))) {
          // Venice returns 404 with "Specified model not found: <id>. Did
          // you mean: <suggestion>" when the substrate's configured model
          // identifier has drifted. Surface as misconfigured so the
          // operator badge degrades to a real cause rather than a generic
          // unavailable. The body reads suggestions but we do not silently
          // switch models; operator picks the new model in the picker.
          return failure(
            startedAt,
            "substrate_misconfigured",
            `venice configured model "${this.model}" not found`,
          );
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

/**
 * Best-effort detection of Venice's "model not found" 404 shape. Venice's
 * actual response body looks like:
 *
 *   {"error":"Specified model not found: llama-3.1-70b. Did you mean: llama-3.3-70b, ..."}
 *
 * Some response bodies use `message` instead of `error`, and the leading
 * substring may shift across API versions. Match defensively on the
 * canonical "model not found" phrase, case-insensitive, and tolerate body
 * read failures (treat as unreachable, not as model-not-found, so the
 * operator does not get a misleading "your model is wrong" badge when the
 * real cause was a transport issue).
 */
async function isModelNotFound(res: Response): Promise<boolean> {
  try {
    const body = await res.text();
    return /model not found/i.test(body);
  } catch {
    return false;
  }
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
