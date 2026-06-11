/**
 * Operator baseline validation.
 *
 * The baseline is operator-authored fortress state (`policy/egress/
 * operator-baseline.json`) that the daemon validates and signs into the
 * manifest. A malformed baseline is omitted so the extension falls back to the
 * UID-only baseline path instead of trusting partially parsed policy.
 */

import type { OperatorBaseline, OperatorBaselineEssential } from "./manifest.js";

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function normalizeName(value: string): string | null {
  const normalized = value.trim().toLowerCase();
  return /^[a-z0-9][a-z0-9_-]{0,63}$/.test(normalized) ? normalized : null;
}

function validateEssential(candidate: unknown): OperatorBaselineEssential | null {
  if (candidate === null || typeof candidate !== "object") {
    return null;
  }
  const c = candidate as Record<string, unknown>;
  if (!isNonEmptyString(c.name)) {
    return null;
  }
  const name = normalizeName(c.name);
  if (name === null) {
    return null;
  }
  const out: OperatorBaselineEssential = { name };
  if (isNonEmptyString(c.signing_id)) {
    out.signing_id = c.signing_id.trim();
  }
  if (isNonEmptyString(c.team_id)) {
    out.team_id = c.team_id.trim();
  }
  if (isNonEmptyString(c.source_app_identifier)) {
    out.source_app_identifier = c.source_app_identifier.trim();
  }
  if (!out.signing_id && !out.team_id && !out.source_app_identifier) {
    return null;
  }
  return out;
}

export function validateOperatorBaseline(candidate: unknown): OperatorBaseline | null {
  if (candidate === null || typeof candidate !== "object") {
    return null;
  }
  const c = candidate as Record<string, unknown>;
  if (!Array.isArray(c.essentials)) {
    return null;
  }

  const seen = new Set<string>();
  const essentials: OperatorBaselineEssential[] = [];
  for (const raw of c.essentials) {
    const entry = validateEssential(raw);
    if (entry === null || seen.has(entry.name)) {
      return null;
    }
    seen.add(entry.name);
    essentials.push(entry);
  }
  essentials.sort((a, b) => a.name.localeCompare(b.name));
  return { essentials };
}
