/**
 * Rho-3 Tier B smart-mode intent classifier.
 *
 * Castle Layer 1: no new outbound surface. The classifier uses the
 * existing substrate-selector classify method on the Tier B privacy
 * filter surface.
 */

import type { SubstrateSelector } from "../intelligence/selector.js";
import type { Surface } from "../intelligence/types.js";
import {
  PII_CATEGORIES,
  rewritePiiRegexOnly,
  type PiiCategory,
} from "./pii-rewrite.js";

export type QueryIntentCategory =
  | "location_grounded"
  | "identity_grounded"
  | "temporal_grounded"
  | "generic";

export type PiiClass = PiiCategory;

export interface QueryIntent {
  intent_category: QueryIntentCategory;
  preserve_pii_classes: PiiClass[];
  confidence: number;
  reasoning: string;
}

export interface IntentClassifier {
  classify(query: string): Promise<QueryIntent>;
}

export interface QueryIntentSelector {
  invokeClassify: SubstrateSelector["invokeClassify"];
}

export const QUERY_INTENT_CLASSIFIER_SURFACE: Surface =
  "privacy-filter-tier-2";

export const QUERY_INTENT_CATEGORIES: readonly QueryIntentCategory[] = [
  "location_grounded",
  "identity_grounded",
  "temporal_grounded",
  "generic",
] as const;

export const SMART_MODE_CONFIDENCE_FLOOR = 0.6;

export async function classifyQueryIntent(
  query: string,
  selector: QueryIntentSelector,
): Promise<QueryIntent> {
  // The classify surface (`privacy-filter-tier-2`) is pinned local-only
  // (ratified 2026-07-23; `TIER2_PINNED_SURFACE` in
  // intelligence/types.ts), and the RAW query is still not embedded in
  // the prompt: defense in depth costs nothing here, and intent
  // classification keys on query STRUCTURE ("who is [NAME_0]?",
  // "restaurants near [STREET_ADDRESS_0]"), which the category-stable
  // placeholders preserve.
  const scrubbedQuery = rewritePiiRegexOnly(query).rewritten;
  const prompt = [
    "Classify the operator query for Rho-3 query anonymity smart mode.",
    `PII classes: ${PII_CATEGORIES.join(", ")}.`,
    "Return the intent category whose original PII is needed for a useful answer.",
    `Query: ${scrubbedQuery}`,
  ].join("\n");
  const response = await selector.invokeClassify(QUERY_INTENT_CLASSIFIER_SURFACE, {
    kind: "classify",
    items: [prompt],
    categories: [...QUERY_INTENT_CATEGORIES],
    maxTokens: 96,
  });
  if (response.failureClass || response.body.kind !== "classify") {
    throw new Error(response.failureClass ?? "intent classifier failed");
  }
  const best = response.body.results
    .filter((r) => isQueryIntentCategory(r.category))
    .sort((a, b) => b.confidence - a.confidence)[0];
  if (!best) throw new Error("intent classifier returned no supported category");
  const intentCategory = best.category as QueryIntentCategory;
  return {
    intent_category: intentCategory,
    preserve_pii_classes: inferPreservedClasses(query, intentCategory),
    confidence: normalizeConfidence(best.confidence),
    reasoning: reasoningFor(intentCategory),
  };
}

export function inferPreservedClasses(
  query: string,
  category: QueryIntentCategory,
): PiiClass[] {
  if (category === "generic") return [];
  if (category === "identity_grounded") return ["name", "email", "phone"];
  if (category === "location_grounded") {
    void query;
    return ["street_address"];
  }
  return [];
}

function isQueryIntentCategory(value: string): value is QueryIntentCategory {
  return (QUERY_INTENT_CATEGORIES as readonly string[]).includes(value);
}

function normalizeConfidence(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return value > 1 ? Math.max(0, Math.min(1, value / 100)) : Math.max(0, Math.min(1, value));
}

function reasoningFor(category: QueryIntentCategory): string {
  if (category === "location_grounded") {
    return "The query asks for location-specific results, so location terms are preserved.";
  }
  if (category === "identity_grounded") {
    return "The query asks about a specific person or identity, so identity terms are preserved.";
  }
  if (category === "temporal_grounded") {
    return "The query depends on time, but no personal data class is required.";
  }
  return "The query can be answered without preserving personal data classes.";
}
