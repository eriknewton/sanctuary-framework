/**
 * Sanctuary v1.3 WP-V1.3-3 Omega-2 Context-Transfer Extractor.
 *
 * Decomposes a handoff into the structured TRANSFERRED-vs-WITHHELD
 * breakdown the operator's Coordination view renders. Operates on a
 * `HandoffEntryDetail` (Omega-1 surface) and returns a
 * `ContextTransferBreakdown`.
 *
 * Why this matters: the operator needs to know not just THAT a
 * handoff happened, but WHAT crossed the boundary. Per-handoff
 * context-transfer breakdown makes Castle Layer 3 cooperative-MCP
 * integrity legible at the operator UX layer.
 *
 * Three resolution paths in fixed order; first one that produces
 * usable output wins. Higher paths produce higher confidence.
 *
 * Path A: structured-source events. Triggered when the source audit
 * details payload carries explicit `transferred` and / or `withheld`
 * arrays / objects. Future Tau-X work will wire the coordinator to
 * emit these explicitly; the extractor handles them today so when
 * those emissions arrive, no further code change is needed. Ships
 * with confidence 1.0.
 *
 * Path B: composition events. Triggered when the source audit
 * operation matches `composition_completed` (Concordia bridge).
 * Decomposes via the receipt-references graph: items in the receipt
 * are transferred; items in the source-state-snapshot but not in the
 * receipt are withheld. Composition events do not flow through the
 * audit log today (mesh-only signed envelopes; same finding as Phi-3
 * cross-agent-chatter watcher and Omega-1's HandoffLog union scope);
 * Path B is scaffolded so when composition wires audit emissions,
 * extraction extends. Ships with confidence 0.9 when present.
 *
 * Path C: heuristic fallback. Triggered when neither A nor B fires
 * (the common case at v1.3 Omega-2 since current Tau-3 audit
 * emissions are minimal and composition is mesh-only). Derives
 * transferred from the policy_rule_id (cross_harness_approval) or
 * task-scope category (v1.1_local_handoff via the source audit
 * payload's reason_class + status). Ships with confidence 0.5.
 *
 * LLM-assist fallback. Optional. Triggered when Path C returns a
 * low-confidence result (no clear category match) AND a substrate
 * selector is supplied. Routes through `selector.invokeClassify` on
 * the coordination surface. Failure is silent (degrade-not-destroy);
 * the caller still gets the heuristic Path C result with confidence
 * 0.3. Ships with confidence 0.6 on success.
 *
 * Castle-walking discipline:
 *  - No new outbound surface. The substrate selector is the only
 *    LLM-capable channel and is opt-in via dependency injection.
 *  - Reads server-local audit log + Concordia receipts only.
 *  - Encryption boundary holds.
 *  - Multi-fortress isolation preserved by the caller-supplied
 *    HandoffEntryDetail (which is fortress-scoped via Omega-1).
 */

import type { SubstrateSelector } from "../intelligence/selector.js";
import type {
  HandoffEntry,
  HandoffEntryDetail,
} from "./handoff-log.js";
import type { AuditEntry } from "../l2-operational/audit-log.js";

/** Stable category enum. Mirrors the four canonical policy slots. */
export type ContextItemCategory =
  | "memory"
  | "credentials"
  | "plans"
  | "outputs"
  | "audit-refs"
  | "other";

export type ContextItemSizeHint =
  | "minimal"
  | "small"
  | "medium"
  | "large";

/**
 * One decomposed context item. The operator UI renders these grouped
 * by category. Names + size hints are derived; raw content does NOT
 * appear here.
 */
export interface ContextItem {
  category: ContextItemCategory;
  /** Operator-friendly one-liner. Truncated to 240 chars on emit. */
  summary: string;
  size_hint: ContextItemSizeHint;
}

/**
 * Per-handoff transferred-vs-withheld decomposition.
 */
export interface ContextTransferBreakdown {
  handoff_entry_id: string;
  transferred: ContextItem[];
  withheld: ContextItem[];
  /** Which extraction path produced this breakdown. */
  source: "structured" | "composition" | "heuristic" | "llm-assist";
  /**
   * Confidence in [0,1]. 1.0 for explicit structured-source fields;
   * 0.9 for composition-receipt decomposition; 0.6 for LLM-assist;
   * 0.5 for heuristic with category match; 0.3 for heuristic with
   * no clear match.
   */
  confidence: number;
}

/** Extractor dependency contract. */
export interface ContextTransferExtractorDeps {
  /** Optional LLM-assist substrate selector. Off by default. */
  substrateSelector?: SubstrateSelector;
}

/** Hard cap on per-summary length (bytes-ish; chars is fine for v1.3). */
const SUMMARY_MAX_CHARS = 240;

const CATEGORY_VALUES: readonly ContextItemCategory[] = [
  "memory",
  "credentials",
  "plans",
  "outputs",
  "audit-refs",
  "other",
];

/**
 * Top-level extractor. Tries Path A, then Path B, then Path C; calls
 * the LLM-assist fallback when Path C is low-confidence and a
 * substrate selector is available. Always returns a breakdown.
 */
export async function extractContextTransferBreakdown(
  detail: HandoffEntryDetail,
  deps: ContextTransferExtractorDeps = {},
): Promise<ContextTransferBreakdown> {
  const pathA = tryStructuredPath(detail);
  if (pathA) return pathA;

  const pathB = tryCompositionPath(detail);
  if (pathB) return pathB;

  const pathC = tryHeuristicPath(detail);
  if (pathC.confidence >= 0.5 || !deps.substrateSelector) {
    return pathC;
  }

  // Low-confidence heuristic + selector available -> LLM-assist.
  const assist = await tryLlmAssistPath(detail, deps.substrateSelector);
  return assist ?? pathC;
}

/**
 * Path A. Triggered when the source audit details payload carries
 * explicit `transferred` and / or `withheld` arrays. Returns null
 * when no such fields exist.
 */
function tryStructuredPath(
  detail: HandoffEntryDetail,
): ContextTransferBreakdown | null {
  const details = sourceDetails(detail.source_audit_entry);
  if (!details) return null;
  const transferredRaw = details["transferred"];
  const withheldRaw = details["withheld"];
  if (transferredRaw === undefined && withheldRaw === undefined) return null;

  const transferred = parseExplicitContextItems(transferredRaw);
  const withheld = parseExplicitContextItems(withheldRaw);
  return {
    handoff_entry_id: detail.entry.entry_id,
    transferred,
    withheld,
    source: "structured",
    confidence: 1.0,
  };
}

/**
 * Path B. Triggered when the audit operation is a composition event
 * carrying receipt-references. Decomposes via the receipt graph.
 *
 * v1.3 Omega-2: composition events do not flow through audit log
 * today; this path is scaffolded for the future composition-emission
 * PR that wires `auditLog.append` for `composition_*` events. When
 * the audit op matches but the payload lacks receipt fields, returns
 * null and the heuristic path takes over.
 */
function tryCompositionPath(
  detail: HandoffEntryDetail,
): ContextTransferBreakdown | null {
  const op = detail.source_audit_entry.operation;
  if (!op.startsWith("composition_completed")) return null;
  const details = sourceDetails(detail.source_audit_entry);
  if (!details) return null;
  const receiptRaw = details["receipt"];
  const sourceStateRaw = details["source_state_snapshot"];
  if (receiptRaw === undefined) return null;

  const transferred = parseExplicitContextItems(receiptRaw);
  const withheld: ContextItem[] = [];
  if (Array.isArray(sourceStateRaw)) {
    const transferredKeys = new Set(
      transferred.map((t) => `${t.category}:${t.summary}`),
    );
    for (const item of parseExplicitContextItems(sourceStateRaw)) {
      const key = `${item.category}:${item.summary}`;
      if (!transferredKeys.has(key)) withheld.push(item);
    }
  }
  return {
    handoff_entry_id: detail.entry.entry_id,
    transferred,
    withheld,
    source: "composition",
    confidence: 0.9,
  };
}

/**
 * Path C. The common path at v1.3 Omega-2. Derives transferred items
 * from the entry's stable fields (event_class, source_audit_entry
 * details), and produces a withheld inference based on observable
 * signals.
 */
function tryHeuristicPath(
  detail: HandoffEntryDetail,
): ContextTransferBreakdown {
  const entry = detail.entry;
  const audit = detail.source_audit_entry;
  const details = sourceDetails(audit);

  // cross_harness_approval_aggregated -> map policy_rule_id to a
  // single transferred ContextItem; nothing observable as withheld.
  if (audit.operation === "cross_harness_approval_aggregated") {
    const ruleId = optString(details, "policy_rule_id");
    if (ruleId) {
      const category = categoryFromPolicyRuleId(ruleId);
      const summary = `${ruleId} (${entry.source_agent_id} -> operator)`;
      return {
        handoff_entry_id: entry.entry_id,
        transferred: [
          {
            category,
            summary: truncate(summary, SUMMARY_MAX_CHARS),
            size_hint: "minimal",
          },
        ],
        withheld: [],
        source: "heuristic",
        confidence: 0.5,
      };
    }
  }

  // v1.1_local_handoff (Tau-3) -> derive from reason_class + status.
  if (audit.operation === "v1.1_local_handoff") {
    const reasonClass = optString(details, "reason_class");
    const newStatus = optString(details, "new_status");
    const previousStatus = optString(details, "previous_status");
    const transferred: ContextItem[] = [];
    const withheld: ContextItem[] = [];
    if (newStatus === "denied" || newStatus === "failed") {
      withheld.push({
        category: "other",
        summary: truncate(
          `handoff ${newStatus}${reasonClass ? ` (${reasonClass})` : ""}: ${entry.source_agent_id} -> ${entry.target_agent_id}`,
          SUMMARY_MAX_CHARS,
        ),
        size_hint: "minimal",
      });
    } else if (newStatus === "accepted" || newStatus === "completed") {
      transferred.push({
        category: "other",
        summary: truncate(
          `handoff ${newStatus}${previousStatus ? ` (from ${previousStatus})` : ""}: ${entry.source_agent_id} -> ${entry.target_agent_id}`,
          SUMMARY_MAX_CHARS,
        ),
        size_hint: "small",
      });
    } else {
      transferred.push({
        category: "other",
        summary: truncate(
          `handoff ${entry.source_agent_id} -> ${entry.target_agent_id}${newStatus ? ` (${newStatus})` : ""}`,
          SUMMARY_MAX_CHARS,
        ),
        size_hint: "minimal",
      });
    }
    return {
      handoff_entry_id: entry.entry_id,
      transferred,
      withheld,
      source: "heuristic",
      confidence: reasonClass || newStatus ? 0.5 : 0.3,
    };
  }

  // Unknown shape. Surface a low-confidence minimal entry so the UI
  // can still render something rather than crashing on null.
  return {
    handoff_entry_id: entry.entry_id,
    transferred: [
      {
        category: "other",
        summary: truncate(
          `handoff ${entry.source_agent_id} -> ${entry.target_agent_id}`,
          SUMMARY_MAX_CHARS,
        ),
        size_hint: "minimal",
      },
    ],
    withheld: [],
    source: "heuristic",
    confidence: 0.3,
  };
}

/**
 * LLM-assist fallback. Routes through the substrate selector's
 * classify surface; failure is silent (caller falls back to the
 * Path C heuristic). v1.3 Omega-2 ships the wiring; production
 * deployments opt in by passing a SubstrateSelector to the extractor.
 */
async function tryLlmAssistPath(
  detail: HandoffEntryDetail,
  selector: SubstrateSelector,
): Promise<ContextTransferBreakdown | null> {
  const entry = detail.entry;
  const audit = detail.source_audit_entry;
  const probe = `event=${audit.operation} sender=${entry.source_agent_id} target=${entry.target_agent_id} summary=${entry.context_transfer_summary}`;
  try {
    // Reuse the `sentinel-scoring` substrate surface: same shape
    // (classify-from-text against a closed enum), same Castle Layer 2
    // sibling-observability concern. A dedicated `coordination`
    // surface would require expanding the Surface union plus
    // selector-config plumbing; that is a v1.4+ refinement once
    // this surface accumulates real production traffic.
    const response = await selector.invokeClassify("sentinel-scoring", {
      kind: "classify",
      items: [probe],
      categories: [...CATEGORY_VALUES],
    });
    if (response.body.kind !== "classify") return null;
    const top = response.body.results[0];
    if (!top || !isCategory(top.category) || top.confidence < 0.4) {
      return null;
    }
    return {
      handoff_entry_id: entry.entry_id,
      transferred: [
        {
          category: top.category,
          summary: truncate(
            `LLM-classified handoff ${entry.source_agent_id} -> ${entry.target_agent_id}: ${top.category} (confidence ${top.confidence.toFixed(2)})`,
            SUMMARY_MAX_CHARS,
          ),
          size_hint: "minimal",
        },
      ],
      withheld: [],
      source: "llm-assist",
      confidence: 0.6,
    };
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------ */

function sourceDetails(
  audit: AuditEntry,
): Record<string, unknown> | undefined {
  return audit.details as Record<string, unknown> | undefined;
}

function optString(
  details: Record<string, unknown> | undefined,
  key: string,
): string | null {
  if (!details) return null;
  const value = details[key];
  if (typeof value !== "string" || value.length === 0) return null;
  return value;
}

function isCategory(value: string): value is ContextItemCategory {
  return (CATEGORY_VALUES as readonly string[]).includes(value);
}

function truncate(s: string, cap: number): string {
  return s.length <= cap ? s : `${s.slice(0, cap - 3)}...`;
}

/**
 * Parse a raw value into ContextItem[]. Accepts:
 *  - array of objects with `category`, `summary`, optional `size_hint`
 *  - object map of category -> array of strings (each string becomes
 *    one ContextItem with `summary` = string, `size_hint` = 'minimal')
 *  - array of strings (each becomes category 'other')
 *
 * Anything else returns []. Permissive on input, strict on output.
 */
function parseExplicitContextItems(raw: unknown): ContextItem[] {
  if (raw === null || raw === undefined) return [];
  if (Array.isArray(raw)) {
    const out: ContextItem[] = [];
    for (const entry of raw) {
      if (typeof entry === "string") {
        out.push({
          category: "other",
          summary: truncate(entry, SUMMARY_MAX_CHARS),
          size_hint: "minimal",
        });
        continue;
      }
      if (entry && typeof entry === "object") {
        const obj = entry as Record<string, unknown>;
        const category = isCategoryValue(obj["category"])
          ? (obj["category"] as ContextItemCategory)
          : "other";
        const summary =
          typeof obj["summary"] === "string"
            ? truncate(obj["summary"] as string, SUMMARY_MAX_CHARS)
            : "(unspecified)";
        const sizeHint = isSizeHintValue(obj["size_hint"])
          ? (obj["size_hint"] as ContextItemSizeHint)
          : "minimal";
        out.push({ category, summary, size_hint: sizeHint });
      }
    }
    return out;
  }
  if (typeof raw === "object" && raw !== null) {
    const out: ContextItem[] = [];
    for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
      const category = isCategoryValue(k) ? (k as ContextItemCategory) : "other";
      if (Array.isArray(v)) {
        for (const item of v) {
          if (typeof item === "string") {
            out.push({
              category,
              summary: truncate(item, SUMMARY_MAX_CHARS),
              size_hint: "minimal",
            });
          }
        }
      }
    }
    return out;
  }
  return [];
}

function isCategoryValue(v: unknown): boolean {
  return typeof v === "string" && (CATEGORY_VALUES as readonly string[]).includes(v);
}

function isSizeHintValue(v: unknown): boolean {
  return (
    typeof v === "string" &&
    (v === "minimal" || v === "small" || v === "medium" || v === "large")
  );
}

/** Map a policy_rule_id like "tier1:state_export" to a category. */
function categoryFromPolicyRuleId(ruleId: string): ContextItemCategory {
  const lower = ruleId.toLowerCase();
  if (lower.includes("credential") || lower.includes("broker_secret")) {
    return "credentials";
  }
  if (lower.includes("memory") || lower.includes("state_read")) {
    return "memory";
  }
  if (lower.includes("plan")) {
    return "plans";
  }
  if (lower.includes("export") || lower.includes("output")) {
    return "outputs";
  }
  if (lower.includes("audit")) {
    return "audit-refs";
  }
  return "other";
}

/** Audit operation emitted when the extractor produces a breakdown. */
export const CONTEXT_TRANSFER_AUDIT_OPS = {
  DECODED: "operator_handoff_context_transfer_decoded",
} as const;

export type ContextTransferAuditOp =
  (typeof CONTEXT_TRANSFER_AUDIT_OPS)[keyof typeof CONTEXT_TRANSFER_AUDIT_OPS];

/** Public alias re-exported so route handlers can name the type cleanly. */
export type { HandoffEntry, HandoffEntryDetail };
