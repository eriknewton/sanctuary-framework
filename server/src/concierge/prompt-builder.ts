import {
  CONCIERGE_PROMPT_DOMAIN,
  type ConciergeContextBundle,
  type VeniceMessage,
} from "./concierge-types.js";

export function buildConciergePrompt(args: {
  question: string;
  context: ConciergeContextBundle;
}): VeniceMessage[] {
  const safeContext = scrubSensitive(args.context);
  return [
    {
      role: "system",
      content:
        CONCIERGE_PROMPT_DOMAIN +
        "You are the Sanctuary concierge. You answer the operator's questions about the state and activities of this sanctuary. You have read-only access to the audit log, identity registry, approval inbox, sovereignty profile, task state, and state-store summaries. You do NOT take actions. You do NOT speculate. If you don't know, say so.",
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
