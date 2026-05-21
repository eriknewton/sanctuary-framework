import {
  CONCIERGE_PROMPT_DOMAIN,
  type ConciergeContextBundle,
  type VeniceMessage,
} from "./concierge-types.js";

/**
 * ZZZZ: heuristic for summarization-class queries. These are the query
 * shapes most likely to produce hallucination when the context is empty,
 * because the model fills void with plausible-sounding fabrications.
 */
const SUMMARIZATION_TRIGGERS = [
  "summarize",
  "summary",
  "what happened",
  "recent activity",
  "activity over the last",
  "activity in the last",
  "overview",
  "what has been going on",
  "what's been happening",
  "fortress activity",
  "describe the activity",
];

export function isSummarizationQuery(question: string): boolean {
  const lower = question.toLowerCase();
  return SUMMARIZATION_TRIGGERS.some((trigger) => lower.includes(trigger));
}

export function buildConciergePrompt(args: {
  question: string;
  context: ConciergeContextBundle;
}): VeniceMessage[] {
  const safeContext = scrubSensitive(args.context);
  const isSummarization = isSummarizationQuery(args.question);

  // ZZZZ: summarization-specific anti-hallucination clause. Appended to
  // the base system prompt when the operator's question is a summarization
  // query. This tightens the instruction beyond the generic "do not
  // speculate" baseline to explicitly forbid inventing activities from
  // the absence of data.
  const summarizationClause = isSummarization
    ? "\n\nFor summarization queries: if the supplied context contains no concrete events, audit entries, or activity records, respond literally: 'No fortress activity recorded in the requested window.' Do not invent activities. Do not infer activities from the absence of data. Do not describe placeholder or example activity types."
    : "";

  return [
    {
      role: "system",
      content:
        CONCIERGE_PROMPT_DOMAIN +
        "You are the Sanctuary concierge. You answer the operator's questions about the state and activities of this sanctuary. You have read-only access to the audit log, identity registry, approval inbox, sovereignty profile, task state, and state-store summaries. You do NOT take actions. You do NOT speculate. If you don't know, say so." +
        summarizationClause,
    },
    {
      role: "user",
      content: JSON.stringify(
        {
          question: args.question,
          context: safeContext,
          instructions: [
            "Answer only from the supplied context.",
            "Do not claim that any action was taken.",
            "Call out missing context plainly.",
          ],
        },
        null,
        2,
      ),
    },
  ];
}

export function scrubSensitive<T>(value: T): T {
  return scrub(value) as T;
}

function scrub(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(scrub);
  if (!value || typeof value !== "object") return value;
  const record = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(record)) {
    if (isSensitiveKey(key)) {
      out[key] = "[redacted]";
    } else {
      out[key] = scrub(item);
    }
  }
  return out;
}

function isSensitiveKey(key: string): boolean {
  const normalized = key.toLowerCase();
  return (
    normalized.includes("private") ||
    normalized.includes("secret") ||
    normalized.includes("token") ||
    normalized.includes("passphrase") ||
    normalized.includes("api_key") ||
    normalized.includes("authorization")
  );
}
