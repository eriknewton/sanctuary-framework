/**
 * Sanctuary WP-V1.3-6 Xi-1 English-Authored Policy Compiler.
 *
 * **Opens WP-V1.3-6.** Operator writes a custom policy in plain
 * English; the compiler translates to a structured rule shape +
 * synthesizes an operator-facing explanation. Compile output is
 * REVIEW-ONLY: no auto-activation; activation lifecycle (Xi-2) is a
 * separate operator-driven flow.
 *
 * Two compile paths:
 *
 *   1. Deterministic rule-based matcher (cheap, high-confidence)
 *      covers the common English shapes:
 *        "always require approval for <op>"
 *        "no agent should <op>"
 *        "allow <op> without approval"
 *        "set anomaly frequency multiplier to <N>"
 *        "auto-allow <op>"
 *
 *   2. Substrate-selector LLM-assist fallback for unrecognized
 *      patterns. Mirrors the Phi-4 / Chi-1 LLM-assist pattern:
 *      the deterministic path runs first; when it returns null the
 *      LLM is asked to emit a JSON-shaped rule + explanation. The
 *      compiler runs schema validation on the LLM output. Malformed
 *      JSON or schema-mismatched output -> compile_confidence
 *      "low" + warnings populated.
 *
 * Castle-walking discipline:
 *   - The substrate selector remains the only outbound LLM channel
 *     (Castle Layer 3 cooperative MCP path). No NEW outbound surface.
 *   - Rho-1's Tier A header-strip binds on every LLM call (the
 *     substrate selector wraps fetch with createAnonymizedFetch).
 *   - NO auto-activation. Activation is operator-driven and gated
 *     by the existing principal-policy approval pathway (Xi-2 wires
 *     this). The compiler only PRODUCES drafts; it does not mutate
 *     the active principal-policy.
 */

import { createHash } from "node:crypto";

import type { SubstrateSelector } from "../intelligence/selector.js";
import type { AuditLog } from "../operational/audit-log.js";
import type { AnomalyAction, Tier2Config } from "../principal-policy/types.js";

// ── Compiled-rule type space ─────────────────────────────────────────

/**
 * Shape of a single English-compiled rule. Xi-1 supports five kinds;
 * Xi-2+ may extend (e.g., per-agent scoped rules, time-windowed rules
 * with full sunrise/sunset, multi-step rule sets).
 *
 * Source vocabulary is the existing PrincipalPolicy shape: tier1 /
 * tier2 / tier3. The compiled rule names the kind + the payload the
 * activation step (Xi-2) will apply to the live policy.
 */
export type CompiledPolicyRuleKind =
  | "tier1_add_operation"
  | "tier1_remove_operation"
  | "tier3_add_operation"
  | "tier3_remove_operation"
  | "tier2_set_field";

export interface Tier2FieldUpdate {
  field: keyof Tier2Config;
  value: AnomalyAction | number;
}

export interface CompiledPolicyRule {
  kind: CompiledPolicyRuleKind;
  /** Operation name for tier1/tier3 add/remove kinds. */
  operation?: string;
  /** Field update for tier2_set_field kind. */
  tier2_update?: Tier2FieldUpdate;
  /** Optional operator-stated time window in 24h hours [0..23]. */
  active_window?: {
    start_hour?: number;
    end_hour?: number;
  };
  /** Optional operator-named agent the rule should be scoped to. */
  bound_to_agent_id?: string;
}

export type CompileConfidence = "high" | "medium" | "low";

export interface EnglishPolicyDraft {
  english_text: string;
  observed_at: string;
  operator_id: string;
}

export interface CompiledPolicy {
  /** SHA-256 hex of english_text + observed_at + operator_id. */
  draft_id: string;
  /** Verbatim operator input. */
  english_text: string;
  /** Structured rule. Always present (low-confidence drafts still
   *  produce a best-effort placeholder rule the operator can
   *  inspect; warnings explain why confidence is low). */
  compiled_rule: CompiledPolicyRule;
  /** Operator-facing prose explanation. */
  explanation_paragraph: string;
  compile_confidence: CompileConfidence;
  compile_warnings: string[];
  /** Which substrate (or "deterministic" for rule-path) produced this. */
  substrate_used: string;
  /** ISO 8601 timestamp at compile. */
  compiled_at: string;
  /** Operator id stamped at compile (multi-fortress isolation). */
  operator_id: string;
  /** Wall fortress id stamped at compile. */
  fortress_id: string;
}

export const ENGLISH_POLICY_AUDIT_OPS = {
  DRAFTED: "english_policy_drafted",
  COMPILED: "english_policy_compiled",
  COMPILE_FAILED: "english_policy_compile_failed",
} as const;

export type EnglishPolicyAuditOp =
  (typeof ENGLISH_POLICY_AUDIT_OPS)[keyof typeof ENGLISH_POLICY_AUDIT_OPS];

export const ENGLISH_POLICY_MAX_TEXT_CHARS = 2_000;

// ── Compiler dependencies + entry point ─────────────────────────────

export interface EnglishPolicyCompilerDeps {
  auditLog: AuditLog;
  fortressId: string;
  /**
   * Substrate selector handle. The compiler uses
   * `selector.invokeSummarize` on the `gate-explanation` surface for
   * the LLM-assist path. Mirrors the Phi-4 / Chi-1 LLM-assist shape.
   * Pass `null` to disable the LLM fallback; the deterministic path
   * still works and yields low-confidence drafts for unrecognized
   * English instead.
   */
  selector?: SubstrateSelector | null;
  /** Wall-clock provider for deterministic tests. */
  now?: () => Date;
}

export class EnglishPolicyCompiler {
  private readonly auditLog: AuditLog;
  private readonly fortressId: string;
  private readonly selector: SubstrateSelector | null;
  private readonly now: () => Date;

  constructor(deps: EnglishPolicyCompilerDeps) {
    this.auditLog = deps.auditLog;
    this.fortressId = deps.fortressId;
    this.selector = deps.selector ?? null;
    this.now = deps.now ?? (() => new Date());
  }

  async compile(draft: EnglishPolicyDraft): Promise<CompiledPolicy> {
    const draftId = computeDraftId(draft);
    await this.auditLog.append(
      "l2",
      ENGLISH_POLICY_AUDIT_OPS.DRAFTED,
      draft.operator_id,
      {
        draft_id: draftId,
        text_length: draft.english_text.length,
        fortress_id: this.fortressId,
      },
    );

    if (draft.english_text.length === 0) {
      return this.buildLowConfidence(
        draft,
        draftId,
        "Operator provided empty text.",
        "deterministic",
        ["empty input"],
      );
    }
    if (draft.english_text.length > ENGLISH_POLICY_MAX_TEXT_CHARS) {
      return this.buildLowConfidence(
        draft,
        draftId,
        `Operator text exceeded ${ENGLISH_POLICY_MAX_TEXT_CHARS} chars; refusing to compile to avoid prompt blowback.`,
        "deterministic",
        [`text exceeds ${ENGLISH_POLICY_MAX_TEXT_CHARS} chars`],
      );
    }

    // Path 1: deterministic rule-based matcher.
    const deterministic = compileDeterministic(draft.english_text);
    if (deterministic !== null) {
      const compiled = this.buildCompiled(
        draft,
        draftId,
        deterministic.rule,
        deterministic.explanation,
        deterministic.confidence,
        deterministic.warnings,
        "deterministic",
      );
      this.auditCompiled(compiled);
      return compiled;
    }

    // Path 2: LLM-assist fallback via substrate selector.
    if (this.selector === null) {
      const low = this.buildLowConfidence(
        draft,
        draftId,
        "No deterministic match; LLM-assist disabled.",
        "deterministic",
        ["no deterministic match", "LLM-assist disabled"],
      );
      this.auditCompileFailed(low, "no_llm_substrate");
      return low;
    }

    try {
      const resp = await this.selector.invokeSummarize("gate-explanation", {
        kind: "summarize",
        context: buildLlmPromptContext(),
        query: buildLlmPromptQuery(draft.english_text),
        maxTokens: 600,
      });
      if (resp.failureClass) {
        const low = this.buildLowConfidence(
          draft,
          draftId,
          `LLM substrate failure: ${resp.failureClass}`,
          resp.servedBy,
          [`substrate failure: ${resp.failureClass}`],
        );
        this.auditCompileFailed(low, "substrate_failure");
        return low;
      }
      if (resp.body.kind !== "summarize") {
        const low = this.buildLowConfidence(
          draft,
          draftId,
          "LLM substrate returned a non-summarize response.",
          resp.servedBy,
          [`unexpected body kind: ${resp.body.kind}`],
        );
        this.auditCompileFailed(low, "unexpected_body");
        return low;
      }
      const parsed = parseLlmOutput(resp.body.text);
      if (!parsed.ok) {
        const low = this.buildLowConfidence(
          draft,
          draftId,
          `LLM output failed schema validation: ${parsed.reason}.`,
          resp.servedBy,
          [`schema validation failed: ${parsed.reason}`],
        );
        this.auditCompileFailed(low, "schema_validation_failed");
        return low;
      }
      const compiled = this.buildCompiled(
        draft,
        draftId,
        parsed.rule,
        parsed.explanation,
        parsed.confidence,
        parsed.warnings,
        resp.servedBy,
      );
      this.auditCompiled(compiled);
      return compiled;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const low = this.buildLowConfidence(
        draft,
        draftId,
        `LLM-assist threw: ${msg}`,
        "unknown",
        [msg],
      );
      this.auditCompileFailed(low, "llm_threw");
      return low;
    }
  }

  // ── helpers ────────────────────────────────────────────────────────

  private buildCompiled(
    draft: EnglishPolicyDraft,
    draftId: string,
    rule: CompiledPolicyRule,
    explanation: string,
    confidence: CompileConfidence,
    warnings: string[],
    substrateUsed: string,
  ): CompiledPolicy {
    return {
      draft_id: draftId,
      english_text: draft.english_text,
      compiled_rule: rule,
      explanation_paragraph: explanation,
      compile_confidence: confidence,
      compile_warnings: warnings,
      substrate_used: substrateUsed,
      compiled_at: this.now().toISOString(),
      operator_id: draft.operator_id,
      fortress_id: this.fortressId,
    };
  }

  private buildLowConfidence(
    draft: EnglishPolicyDraft,
    draftId: string,
    explanation: string,
    substrateUsed: string,
    warnings: string[],
  ): CompiledPolicy {
    return this.buildCompiled(
      draft,
      draftId,
      // Placeholder rule; operator inspects the draft + decides whether
      // to discard or re-author. Xi-2's activation flow refuses to
      // activate compile_confidence "low" without explicit operator
      // override.
      { kind: "tier1_add_operation", operation: "__low_confidence_placeholder__" },
      explanation,
      "low",
      warnings,
      substrateUsed,
    );
  }

  private auditCompiled(compiled: CompiledPolicy): void {
    void this.auditLog.append(
      "l2",
      ENGLISH_POLICY_AUDIT_OPS.COMPILED,
      compiled.operator_id,
      {
        draft_id: compiled.draft_id,
        compile_confidence: compiled.compile_confidence,
        rule_kind: compiled.compiled_rule.kind,
        warnings_count: compiled.compile_warnings.length,
        substrate_used: compiled.substrate_used,
        fortress_id: compiled.fortress_id,
      },
    );
  }

  private auditCompileFailed(compiled: CompiledPolicy, reason: string): void {
    void this.auditLog.append(
      "l2",
      ENGLISH_POLICY_AUDIT_OPS.COMPILE_FAILED,
      compiled.operator_id,
      {
        draft_id: compiled.draft_id,
        reason,
        warnings: compiled.compile_warnings,
        fortress_id: compiled.fortress_id,
      },
      "failure",
    );
  }
}

// ── Pure helpers (exported for tests) ────────────────────────────────

export function computeDraftId(draft: EnglishPolicyDraft): string {
  return createHash("sha256")
    .update(`${draft.english_text}|${draft.observed_at}|${draft.operator_id}`)
    .digest("hex");
}

interface DeterministicResult {
  rule: CompiledPolicyRule;
  explanation: string;
  confidence: CompileConfidence;
  warnings: string[];
}

/**
 * Rule-based English -> CompiledPolicyRule for common shapes. Returns
 * null when no pattern matches.
 *
 * The matcher is intentionally conservative: a pattern only fires when
 * the operator's text closely matches one of the listed shapes. Anything
 * else falls through to the LLM-assist path.
 */
export function compileDeterministic(
  text: string,
): DeterministicResult | null {
  const normalized = text.trim().toLowerCase();

  // Pattern: "always require approval for <op>"  /  "require approval for <op>"
  const requireMatch = normalized.match(
    /^(always\s+)?require approval (?:for|on) ([a-z][a-z0-9_]*)\.?$/,
  );
  if (requireMatch) {
    const op = requireMatch[2]!;
    return {
      rule: { kind: "tier1_add_operation", operation: op },
      explanation: `Adds "${op}" to the Tier 1 always-approve list. Every call to ${op} will require explicit human approval before it executes.`,
      confidence: "high",
      warnings: [],
    };
  }

  // Pattern: "no agent should <op>"
  const noAgentMatch = normalized.match(
    /^no agent should ([a-z][a-z0-9_]*)\.?$/,
  );
  if (noAgentMatch) {
    const op = noAgentMatch[1]!;
    return {
      rule: { kind: "tier1_add_operation", operation: op },
      explanation: `Adds "${op}" to the Tier 1 always-approve list. The operator must approve every ${op} call before it executes.`,
      confidence: "high",
      warnings: [],
    };
  }

  // Pattern: "allow <op> without approval"  /  "auto-allow <op>"
  const allowMatch = normalized.match(
    /^(?:allow ([a-z][a-z0-9_]*) without approval|auto-allow ([a-z][a-z0-9_]*))\.?$/,
  );
  if (allowMatch) {
    const op = (allowMatch[1] ?? allowMatch[2])!;
    return {
      rule: { kind: "tier3_add_operation", operation: op },
      explanation: `Adds "${op}" to the Tier 3 always-allow list. Calls to ${op} will be audit-logged but never block on approval.`,
      confidence: "high",
      warnings: [],
    };
  }

  // Pattern: "remove <op> from approval list" / "stop requiring approval for <op>"
  const removeMatch = normalized.match(
    /^(?:remove ([a-z][a-z0-9_]*) from approval list|stop requiring approval for ([a-z][a-z0-9_]*))\.?$/,
  );
  if (removeMatch) {
    const op = (removeMatch[1] ?? removeMatch[2])!;
    return {
      rule: { kind: "tier1_remove_operation", operation: op },
      explanation: `Removes "${op}" from the Tier 1 always-approve list. Future calls will fall through to Tier 2 anomaly evaluation or Tier 3 if explicitly listed.`,
      confidence: "high",
      warnings: [],
    };
  }

  // Pattern: "set anomaly frequency multiplier to <N>"
  const tier2Multiplier = normalized.match(
    /^set anomaly frequency multiplier to (\d+(?:\.\d+)?)\.?$/,
  );
  if (tier2Multiplier) {
    const value = Number.parseFloat(tier2Multiplier[1]!);
    return {
      rule: {
        kind: "tier2_set_field",
        tier2_update: { field: "frequency_spike_multiplier", value },
      },
      explanation: `Sets the Tier 2 anomaly frequency multiplier to ${value}. Tool calls that exceed the rolling baseline by more than this multiple will fire an anomaly evaluation.`,
      confidence: "high",
      warnings: [],
    };
  }

  // Pattern: "set max signs per minute to <N>"
  const tier2MaxSigns = normalized.match(
    /^set max signs per minute to (\d+)\.?$/,
  );
  if (tier2MaxSigns) {
    const value = Number.parseInt(tier2MaxSigns[1]!, 10);
    return {
      rule: {
        kind: "tier2_set_field",
        tier2_update: { field: "max_signs_per_minute", value },
      },
      explanation: `Caps Tier 2 signing operations at ${value} per minute. Crossing the cap fires an anomaly evaluation.`,
      confidence: "high",
      warnings: [],
    };
  }

  return null;
}

interface ParsedLlmOutput {
  ok: true;
  rule: CompiledPolicyRule;
  explanation: string;
  confidence: CompileConfidence;
  warnings: string[];
}

interface ParsedLlmFailure {
  ok: false;
  reason: string;
}

/**
 * Parse + schema-validate an LLM `summarize.text` response. The
 * convention: the LLM emits a JSON object with `rule`, `explanation`,
 * `confidence`, `warnings` fields. Any deviation falls to a structured
 * failure that the caller converts to a low-confidence draft.
 *
 * Exported for tests so the parse path can be exercised against
 * fixture strings without standing up a real substrate.
 */
export function parseLlmOutput(
  text: string,
): ParsedLlmOutput | ParsedLlmFailure {
  let parsed: unknown;
  try {
    // Strip an optional Markdown code fence wrapper.
    const stripped = text
      .replace(/^```(?:json)?\n?/, "")
      .replace(/\n?```$/, "")
      .trim();
    parsed = JSON.parse(stripped);
  } catch (err) {
    return {
      ok: false,
      reason: `not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  if (!parsed || typeof parsed !== "object") {
    return { ok: false, reason: "top-level is not an object" };
  }
  const obj = parsed as Record<string, unknown>;
  const ruleObj = obj["rule"];
  if (!ruleObj || typeof ruleObj !== "object") {
    return { ok: false, reason: "missing or non-object rule" };
  }
  const rule = ruleObj as Record<string, unknown>;
  const kindRaw = rule["kind"];
  if (typeof kindRaw !== "string" || !isValidKind(kindRaw)) {
    return { ok: false, reason: `invalid rule.kind: ${String(kindRaw)}` };
  }
  const compiledRule: CompiledPolicyRule = { kind: kindRaw as CompiledPolicyRuleKind };
  if (typeof rule["operation"] === "string") {
    compiledRule.operation = rule["operation"];
  }
  const tier2 = rule["tier2_update"];
  if (tier2 && typeof tier2 === "object") {
    const fld = (tier2 as Record<string, unknown>)["field"];
    const val = (tier2 as Record<string, unknown>)["value"];
    if (typeof fld === "string" && (typeof val === "number" || typeof val === "string")) {
      compiledRule.tier2_update = {
        field: fld as keyof Tier2Config,
        value: val as AnomalyAction | number,
      };
    }
  }

  if (kindRaw === "tier1_add_operation" || kindRaw === "tier1_remove_operation" ||
      kindRaw === "tier3_add_operation" || kindRaw === "tier3_remove_operation") {
    if (typeof compiledRule.operation !== "string" || compiledRule.operation.length === 0) {
      return { ok: false, reason: `${kindRaw} requires operation` };
    }
  }
  if (kindRaw === "tier2_set_field" && compiledRule.tier2_update === undefined) {
    return { ok: false, reason: "tier2_set_field requires tier2_update" };
  }

  const explanation = typeof obj["explanation"] === "string"
    ? (obj["explanation"] as string)
    : "";
  if (!explanation) return { ok: false, reason: "missing explanation" };

  let confidence: CompileConfidence = "medium";
  const confRaw = obj["confidence"];
  if (confRaw === "high" || confRaw === "medium" || confRaw === "low") {
    confidence = confRaw;
  }

  const warnings: string[] = [];
  const warnRaw = obj["warnings"];
  if (Array.isArray(warnRaw)) {
    for (const w of warnRaw) {
      if (typeof w === "string") warnings.push(w);
    }
  }

  return { ok: true, rule: compiledRule, explanation, confidence, warnings };
}

function isValidKind(s: string): s is CompiledPolicyRuleKind {
  return (
    s === "tier1_add_operation" ||
    s === "tier1_remove_operation" ||
    s === "tier3_add_operation" ||
    s === "tier3_remove_operation" ||
    s === "tier2_set_field"
  );
}

function buildLlmPromptContext(): string {
  return [
    "You compile a Sanctuary operator's plain-English policy statement into a structured rule.",
    "Output strictly a JSON object with these fields:",
    '  "rule": { "kind": "<one of tier1_add_operation | tier1_remove_operation | tier3_add_operation | tier3_remove_operation | tier2_set_field>", "operation": "<snake_case>"? , "tier2_update": { "field": "<keyof Tier2Config>", "value": <number|string> }? }',
    '  "explanation": "<operator-facing prose paragraph>"',
    '  "confidence": "high" | "medium" | "low"',
    '  "warnings": [ "<short warning string>" ]',
    "Do NOT include any text outside the JSON. Do NOT activate the rule; this is a draft for operator review.",
  ].join("\n");
}

function buildLlmPromptQuery(englishText: string): string {
  return `Compile this operator policy statement: ${englishText}`;
}
