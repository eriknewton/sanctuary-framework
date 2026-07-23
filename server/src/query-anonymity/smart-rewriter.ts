/**
 * Rho-3 Tier B smart-mode rewriter.
 *
 * Combines Rho-2 PII detection with a per-query intent decision. PII
 * classes required by intent stay in the substrate query; all others
 * remain placeholders and are available for server-side render-time
 * restoration.
 */

import type { AuditLog } from "../operational/audit-log.js";
import {
  PII_CATEGORIES,
  rewritePiiWithLlm,
  type PiiCategory,
  type PiiRewriteResult,
  type PiiRewriteSelector,
} from "./pii-rewrite.js";
import {
  SMART_MODE_CONFIDENCE_FLOOR,
  type IntentClassifier,
  type PiiClass,
  type QueryIntent,
} from "./intent-classifier.js";

export interface SmartRewriteResult {
  rewritten_query: string;
  reverse_map: ReverseMapping[];
  intent: QueryIntent;
  anonymized_classes: PiiClass[];
  preserved_classes: PiiClass[];
  fallback_reason?: "classifier_failed" | "low_confidence";
  /**
   * Stats from the underlying Rho-2 PII pass, carried so the live
   * concierge path (Rho-2.5 wiring) can emit the
   * `query_anonymity_pii_rewritten` audit event without re-running
   * the rewrite. `redaction_counts` reflects redactions that SURVIVED
   * to the outbound query: intent-preserved classes were restored to
   * originals, so their counts are zeroed here (the audit record must
   * never claim a redaction that was restored; the preserved classes
   * are reported separately via `preserved_classes`).
   */
  pii_rewrite: Pick<
    PiiRewriteResult,
    "redaction_counts" | "llm_assist_ran" | "llm_residual_count"
  >;
}

export interface ReverseMapping {
  placeholder: string;
  original: string;
  pii_class: PiiClass;
  observed_at: string;
}

export const SMART_REWRITE_AUDIT_OPS = {
  INTENT_CLASSIFIED: "query_anonymity_intent_classified",
  SMART_REWRITE_APPLIED: "query_anonymity_smart_rewrite_applied",
  SMART_MODE_FALLBACK: "query_anonymity_smart_mode_fallback",
  REVERSE_MAPPING_USED: "query_anonymity_reverse_mapping_used",
} as const;

export async function smartRewrite(
  query: string,
  opts: { selector: PiiRewriteSelector; classifier: IntentClassifier },
): Promise<SmartRewriteResult> {
  const pii = await rewritePiiWithLlm(query, opts.selector, {
    identityId: "query-anonymity-smart-mode",
  });
  let intent: QueryIntent;
  try {
    intent = await opts.classifier.classify(query);
  } catch {
    return anonymizeAll(pii, "classifier_failed");
  }
  if (intent.confidence < SMART_MODE_CONFIDENCE_FLOOR) {
    return anonymizeAll(pii, "low_confidence");
  }

  const preserved = new Set<PiiClass>(intent.preserve_pii_classes);
  let rewritten = pii.rewritten;
  const reverseMap: ReverseMapping[] = [];
  const anonymized = new Set<PiiClass>();
  const observedAt = new Date().toISOString();

  for (const [placeholder, original] of Object.entries(pii.placeholders)) {
    const piiClass = classFromPlaceholder(placeholder);
    if (!piiClass) continue;
    if (preserved.has(piiClass)) {
      rewritten = replaceAllLiteral(rewritten, placeholder, original);
    } else {
      anonymized.add(piiClass);
      reverseMap.push({
        placeholder,
        original,
        pii_class: piiClass,
        observed_at: observedAt,
      });
    }
  }

  return {
    rewritten_query: rewritten,
    reverse_map: reverseMap,
    intent,
    anonymized_classes: [...anonymized],
    preserved_classes: [...preserved],
    pii_rewrite: piiStats(pii, preserved),
  };
}

export function restoreReverseMappings(
  text: string,
  mappings: readonly ReverseMapping[],
): { text: string; replacements: number } {
  let out = text;
  let replacements = 0;
  for (const mapping of mappings) {
    const before = out;
    out = replaceAllLiteral(out, mapping.placeholder, mapping.original);
    if (out !== before) {
      replacements += before.split(mapping.placeholder).length - 1;
    }
  }
  return { text: out, replacements };
}

export function emitSmartRewriteAudit(opts: {
  auditLog: AuditLog;
  identityId: string;
  fortressId: string;
  queryId: string;
  result: SmartRewriteResult;
}): void {
  void opts.auditLog.append("l2", SMART_REWRITE_AUDIT_OPS.INTENT_CLASSIFIED, opts.identityId, {
    fortress_id: opts.fortressId,
    query_id: opts.queryId,
    intent_category: opts.result.intent.intent_category,
    confidence: opts.result.intent.confidence,
    preserve_pii_classes: opts.result.intent.preserve_pii_classes,
    reasoning: opts.result.intent.reasoning,
  });
  void opts.auditLog.append("l2", SMART_REWRITE_AUDIT_OPS.SMART_REWRITE_APPLIED, opts.identityId, {
    fortress_id: opts.fortressId,
    query_id: opts.queryId,
    anonymized_classes: opts.result.anonymized_classes,
    preserved_classes: opts.result.preserved_classes,
    reverse_mapping_count: opts.result.reverse_map.length,
  });
}

export function emitSmartModeFallbackAudit(opts: {
  auditLog: AuditLog;
  identityId: string;
  fortressId: string;
  queryId: string;
  reason: "classifier_failed" | "low_confidence";
}): void {
  void opts.auditLog.append("l2", SMART_REWRITE_AUDIT_OPS.SMART_MODE_FALLBACK, opts.identityId, {
    fortress_id: opts.fortressId,
    query_id: opts.queryId,
    reason: opts.reason,
  }, "failure");
}

export function emitReverseMappingUsedAudit(opts: {
  auditLog: AuditLog;
  identityId: string;
  fortressId: string;
  queryId: string;
  replacements: number;
  fallbackNotice: boolean;
}): void {
  void opts.auditLog.append("l2", SMART_REWRITE_AUDIT_OPS.REVERSE_MAPPING_USED, opts.identityId, {
    fortress_id: opts.fortressId,
    query_id: opts.queryId,
    replacements: opts.replacements,
    fallback_notice: opts.fallbackNotice,
  }, opts.fallbackNotice ? "failure" : "success");
}

function anonymizeAll(
  pii: Awaited<ReturnType<typeof rewritePiiWithLlm>>,
  reason: "classifier_failed" | "low_confidence",
): SmartRewriteResult {
  const reverseMap: ReverseMapping[] = [];
  const anonymized = new Set<PiiClass>();
  const observedAt = new Date().toISOString();
  for (const [placeholder, original] of Object.entries(pii.placeholders)) {
    const piiClass = classFromPlaceholder(placeholder);
    if (!piiClass) continue;
    anonymized.add(piiClass);
    reverseMap.push({ placeholder, original, pii_class: piiClass, observed_at: observedAt });
  }
  return {
    rewritten_query: pii.rewritten,
    reverse_map: reverseMap,
    intent: {
      intent_category: "generic",
      preserve_pii_classes: [],
      confidence: 0,
      reasoning:
        reason === "classifier_failed"
          ? "Smart-mode classifier failed; fell back to basic Tier B anonymize-all behavior."
          : "Smart-mode classifier confidence was below 60%; fell back to basic Tier B anonymize-all behavior.",
    },
    anonymized_classes: [...anonymized],
    preserved_classes: [],
    fallback_reason: reason,
    pii_rewrite: piiStats(pii),
  };
}

function piiStats(
  pii: PiiRewriteResult,
  preserved?: ReadonlySet<PiiClass>,
): SmartRewriteResult["pii_rewrite"] {
  // Zero out classes whose placeholders were restored to originals:
  // those redactions did NOT survive to the outbound query, and the
  // audit record must not claim them.
  const counts = { ...pii.redaction_counts };
  if (preserved) {
    for (const cls of preserved) {
      if (cls in counts) counts[cls] = 0;
    }
  }
  return {
    redaction_counts: counts,
    llm_assist_ran: pii.llm_assist_ran,
    llm_residual_count: pii.llm_residual_count,
  };
}

function classFromPlaceholder(placeholder: string): PiiClass | null {
  const match = /^\[([A-Z_]+)_\d+\]$/.exec(placeholder);
  if (!match) return null;
  const normalized = match[1]!.toLowerCase() as PiiCategory;
  return (PII_CATEGORIES as readonly string[]).includes(normalized)
    ? normalized
    : null;
}

function replaceAllLiteral(text: string, search: string, replacement: string): string {
  return text.split(search).join(replacement);
}
