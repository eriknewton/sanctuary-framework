/**
 * Lightweight local privacy filter for outbound context.
 *
 * This is not a replacement for a full detector such as OpenAI privacy-filter.
 * It gives Sanctuary a deterministic baseline that catches common high-risk
 * spans inside otherwise-allowed fields, so policy gates are not limited to
 * top-level field names.
 */

export type PrivacySpanClass =
  | "email"
  | "phone"
  | "ssn"
  | "credit_card"
  | "secret_assignment";

export interface PrivacyFinding {
  path: string;
  class: PrivacySpanClass;
  action: "redact";
}

export interface PrivacyFilterResult<T = unknown> {
  value: T;
  findings: PrivacyFinding[];
}

interface SpanPattern {
  class: PrivacySpanClass;
  pattern: RegExp;
  replacement: string;
}

const SPAN_PATTERNS: SpanPattern[] = [
  {
    class: "email",
    pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    replacement: "[EMAIL_REDACTED]",
  },
  {
    class: "ssn",
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    replacement: "[SSN_REDACTED]",
  },
  {
    class: "credit_card",
    pattern: /\b(?:\d[ -]*?){13,19}\b/g,
    replacement: "[CARD_REDACTED]",
  },
  {
    class: "phone",
    pattern: /\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b/g,
    replacement: "[PHONE_REDACTED]",
  },
  {
    class: "secret_assignment",
    pattern: /\b(api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret)\s*[:=]\s*["']?[^"',\s}]+/gi,
    replacement: "$1=[SECRET_REDACTED]",
  },
];

const MAX_DEPTH = 20;

export function applyLocalPrivacyFilter<T = unknown>(
  value: T,
  path = "$"
): PrivacyFilterResult<T> {
  const findings: PrivacyFinding[] = [];
  const filtered = filterValue(value, path, findings, 0) as T;
  return { value: filtered, findings };
}

function filterValue(
  value: unknown,
  path: string,
  findings: PrivacyFinding[],
  depth: number
): unknown {
  if (depth > MAX_DEPTH) return value;

  if (typeof value === "string") {
    return filterString(value, path, findings);
  }

  if (Array.isArray(value)) {
    return value.map((item, index) =>
      filterValue(item, `${path}[${index}]`, findings, depth + 1)
    );
  }

  if (value && typeof value === "object") {
    const filtered: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      filtered[key] = filterValue(child, `${path}.${key}`, findings, depth + 1);
    }
    return filtered;
  }

  return value;
}

function filterString(
  input: string,
  path: string,
  findings: PrivacyFinding[]
): string {
  let output = input;

  for (const span of SPAN_PATTERNS) {
    const before = output;
    output = output.replace(span.pattern, span.replacement);
    if (output !== before) {
      findings.push({ path, class: span.class, action: "redact" });
    }
  }

  return output;
}

