/**
 * Sanctuary v1.3 WP-V1.3-5 Pi-1/Pi-2 Honeypot Compiler.
 *
 * Maps operator-supplied English to a structured TrapSpec via the
 * substrate selector. Pi-1 implemented the http_endpoint class; Pi-2
 * extends the same two-path compile flow to also produce filesystem
 * traps when the English describes a filesystem-shaped honeypot.
 *
 *   Path A (LLM): when a SubstrateSelector is wired, the compiler
 *     submits the English text on the `template-suggestion` surface
 *     (the canonical outbound LLM channel for template-shape
 *     generation), parses the response as JSON matching the TrapSpec
 *     shape, and validates against the schema. Path A produces
 *     `explanation_paragraph` from the LLM response. The LLM is
 *     allowed to return `trap_class: "filesystem"` along with an
 *     `ops` array; the parser routes to a FilesystemTrigger in that
 *     case and otherwise produces an HttpEndpointTrigger (default).
 *
 *   Path B (heuristic fallback): runs when no selector is wired OR
 *     Path A's LLM response fails schema validation. Extracts a
 *     `path_pattern` from the English text via canonical-phrase
 *     pattern matching ("honeypot at <path>", "trap at <path>",
 *     "deploy on <path>", etc.). The heuristic also detects
 *     filesystem-class signals ("filesystem honeypot", "file trap",
 *     "trap file reads/writes/deletes on <path>") and produces a
 *     FilesystemTrigger with an inferred `ops` set in that case.
 *     Heuristic-derived TrapSpecs carry a stub explanation_paragraph
 *     so consumers can branch on confidence at render time without
 *     parsing the text.
 *
 * Failure-mode handling is fail-soft: a malformed LLM response or
 * an unparseable English draft surfaces a TrapSpec with a stub
 * trigger AND warnings in the result; the caller decides whether to
 * deploy or rewrite the draft. This matches the operator-feedback
 * discipline from Phi-2 and Phi-3.
 *
 * Castle-walking discipline:
 *   - No new outbound surface. The substrate selector is the only
 *     outbound-capable channel; absent selector -> heuristic path
 *     only. Castle Wall enforcement at the kernel level is independent
 *     of this module.
 *   - Pure modulo the optional selector call. Tests inject a stub
 *     selector to exercise both paths deterministically.
 *   - Multi-fortress isolation: the compiler is stateless; the
 *     calling site is responsible for fortress scope (the trap
 *     registry instance is per-fortress).
 */

import { createHash, randomUUID } from "node:crypto";

import type { SubstrateSelector } from "../intelligence/selector.js";
import {
  FILESYSTEM_OPS,
  type FilesystemOp,
  type FilesystemTrigger,
  type HoneypotDraft,
  type HttpEndpointTrigger,
  type TrapClass,
  type TrapSpec,
  type TrapTrigger,
} from "./types.js";

/** Surface the compile call rides on. */
const COMPILE_SURFACE = "template-suggestion" as const;

/** Stable token budget for the compile call. */
const COMPILE_MAX_TOKENS = 800;

/** Default severity when the English text does not specify. */
const DEFAULT_SEVERITY = "alert" as const;

/**
 * Prompt prefix the LLM sees. Asks for a strict JSON payload so the
 * compiler can parse + validate. The prompt is deliberately small;
 * the LLM's job is shape-derivation, not creative composition.
 *
 * Pi-2 extends the schema: an optional `trap_class` field lets the
 * LLM declare a filesystem trap. When `trap_class` is "filesystem",
 * the `ops` array narrows which filesystem operations fire the trap.
 */
const COMPILE_PROMPT = `You are compiling a Sanctuary honeypot from an operator's plain-English description.
Return STRICT JSON with the following shape (no markdown, no commentary):
{
  "trap_class": "http_endpoint" | "filesystem",
  "path_pattern": "string (glob with * or **)",
  "method": "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "ANY",
  "ops": ["read", "write", "delete", "list"],
  "expected_caller_types": ["wrapped_agent" | "operator" | "external"],
  "finding_severity": "warn" | "alert",
  "explanation_paragraph": "one-sentence operator-friendly explanation"
}
Default trap_class to "http_endpoint" unless the operator clearly describes filesystem access (file reads/writes, directory access, path-on-disk monitoring). The "method" field applies only to http_endpoint traps; the "ops" field applies only to filesystem traps. Match the operator's stated severity if they gave one; otherwise default to "alert". If method is unspecified for http_endpoint, return "ANY". If ops is unspecified for filesystem, return ["read","write","delete","list"]. If caller-type is unspecified, return ["wrapped_agent"]. Keep the explanation_paragraph under 200 characters.`;

export interface CompileResult {
  spec: TrapSpec;
  /** "llm" when path A produced the spec; "heuristic" on fallback. */
  source: "llm" | "heuristic";
  /** Non-fatal advisories. Empty on a clean LLM compile. */
  warnings: string[];
}

export interface CompileOpts {
  /**
   * Optional SubstrateSelector. When wired, the compiler attempts
   * Path A (LLM) before falling back to Path B (heuristic). When
   * absent, the compiler runs Path B directly.
   */
  selector?: SubstrateSelector;
  /** Wall-clock provider for deterministic tests. */
  now?: () => Date;
  /** Deterministic id generator for tests; defaults to randomUUID. */
  trapIdFactory?: () => string;
}

/**
 * Compile an operator's English draft into a TrapSpec. Always returns
 * a usable spec; on LLM or heuristic failure, the spec carries a
 * stub trigger and the warnings array surfaces the failure mode.
 */
export async function compileHoneypot(
  draft: HoneypotDraft,
  opts?: CompileOpts,
): Promise<CompileResult> {
  const now = opts?.now ?? (() => new Date());
  const trapIdFactory = opts?.trapIdFactory ?? (() => randomUUID());

  const warnings: string[] = [];
  let trigger: TrapTrigger | null = null;
  let trapClass: TrapClass = "http_endpoint";
  let severity: "warn" | "alert" = DEFAULT_SEVERITY;
  let explanation = "";
  let source: "llm" | "heuristic" = "heuristic";

  // Path A: LLM compile via substrate selector.
  if (opts?.selector) {
    try {
      const handle = await opts.selector.getSubstrate(COMPILE_SURFACE);
      if (handle.capability.summarize) {
        const response = await opts.selector.invokeSummarize(
          COMPILE_SURFACE,
          {
            kind: "summarize",
            context: COMPILE_PROMPT,
            query: draft.english_text,
            maxTokens: COMPILE_MAX_TOKENS,
          },
        );
        if (response.body.kind === "summarize" && !response.failureClass) {
          const parsed = tryParseLlmResponse(response.body.text);
          if (parsed.ok) {
            trigger = parsed.trigger;
            trapClass = parsed.trapClass;
            severity = parsed.severity;
            explanation = parsed.explanation;
            source = "llm";
          } else {
            warnings.push(
              `LLM response failed validation (${parsed.failure}); falling back to heuristic compile`,
            );
          }
        } else {
          warnings.push(
            `LLM compile failed (${response.failureClass ?? "non_summarize_body"}); falling back to heuristic compile`,
          );
        }
      } else {
        warnings.push(
          "Substrate at template-suggestion surface does not support summarize; falling back to heuristic compile",
        );
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      warnings.push(
        `LLM compile threw (${message}); falling back to heuristic compile`,
      );
    }
  }

  // Path B: heuristic compile. Always runs when Path A did not
  // produce a usable trigger.
  if (trigger === null) {
    const heuristic = heuristicCompile(draft.english_text);
    trigger = heuristic.trigger;
    trapClass = heuristic.trapClass;
    if (heuristic.severity) severity = heuristic.severity;
    explanation = heuristic.explanation;
    if (heuristic.warning) warnings.push(heuristic.warning);
  }

  const spec: TrapSpec = {
    trap_id: trapIdFactory(),
    trap_class: trapClass,
    trigger,
    finding_severity: severity,
    english_text: draft.english_text,
    explanation_paragraph: explanation,
    compiled_at: now().toISOString(),
  };

  return { spec, source, warnings };
}

// ── Path A: LLM-response parser ──────────────────────────────────────────

interface ParseSuccess {
  ok: true;
  trapClass: TrapClass;
  trigger: TrapTrigger;
  severity: "warn" | "alert";
  explanation: string;
}

interface ParseFailure {
  ok: false;
  failure:
    | "invalid_json"
    | "missing_path_pattern"
    | "invalid_severity"
    | "invalid_caller_types"
    | "invalid_filesystem_ops";
}

function tryParseLlmResponse(text: string): ParseSuccess | ParseFailure {
  let body: unknown;
  try {
    // Strip code fences if the LLM ignored the prompt directive.
    const stripped = text.replace(/^```(?:json)?\s*|\s*```$/g, "").trim();
    body = JSON.parse(stripped);
  } catch {
    return { ok: false, failure: "invalid_json" };
  }
  if (!body || typeof body !== "object") {
    return { ok: false, failure: "invalid_json" };
  }
  const obj = body as Record<string, unknown>;
  const pathPattern = obj["path_pattern"];
  if (typeof pathPattern !== "string" || pathPattern.length === 0) {
    return { ok: false, failure: "missing_path_pattern" };
  }
  const callerTypes = Array.isArray(obj["expected_caller_types"])
    ? (obj["expected_caller_types"] as unknown[]).filter(
        (v): v is string => typeof v === "string" && v.length > 0,
      )
    : ["wrapped_agent"];
  if (callerTypes.length === 0) {
    return { ok: false, failure: "invalid_caller_types" };
  }
  const severityRaw = obj["finding_severity"];
  const severity: "warn" | "alert" =
    severityRaw === "warn"
      ? "warn"
      : severityRaw === "alert"
        ? "alert"
        : DEFAULT_SEVERITY;
  const explanationRaw = obj["explanation_paragraph"];
  const explanation =
    typeof explanationRaw === "string" && explanationRaw.length > 0
      ? explanationRaw
      : "Honeypot compiled from operator draft via LLM-assisted compile path.";

  const trapClassRaw = obj["trap_class"];
  const trapClass: TrapClass =
    trapClassRaw === "filesystem" ? "filesystem" : "http_endpoint";

  if (trapClass === "filesystem") {
    const opsParsed = parseFilesystemOps(obj["ops"]);
    if (opsParsed === null) {
      return { ok: false, failure: "invalid_filesystem_ops" };
    }
    const trigger: FilesystemTrigger = {
      kind: "filesystem",
      path_pattern: pathPattern,
      ops: opsParsed,
      expected_caller_types: callerTypes,
    };
    return { ok: true, trapClass, trigger, severity, explanation };
  }

  const method =
    typeof obj["method"] === "string" ? (obj["method"] as string) : "ANY";
  const trigger: HttpEndpointTrigger = {
    kind: "http_endpoint",
    path_pattern: pathPattern,
    ...(method !== "ANY" ? { method: method.toUpperCase() } : {}),
    expected_caller_types: callerTypes,
  };
  return { ok: true, trapClass, trigger, severity, explanation };
}

/**
 * Validate the LLM-supplied `ops` field. Accepts the canonical four
 * operations; rejects unknown entries. Missing or empty ops defaults
 * to all four (`FILESYSTEM_OPS`) so the operator's "watch this path
 * for any activity" intent compiles cleanly without forcing the LLM
 * to enumerate exhaustively.
 */
function parseFilesystemOps(raw: unknown): FilesystemOp[] | null {
  if (raw === undefined || raw === null) {
    return [...FILESYSTEM_OPS];
  }
  if (!Array.isArray(raw)) return null;
  if (raw.length === 0) return [...FILESYSTEM_OPS];
  const out: FilesystemOp[] = [];
  for (const entry of raw) {
    if (typeof entry !== "string") return null;
    if (!FILESYSTEM_OPS.includes(entry as FilesystemOp)) return null;
    if (!out.includes(entry as FilesystemOp)) out.push(entry as FilesystemOp);
  }
  return out;
}

// ── Path B: heuristic compile ────────────────────────────────────────────

interface HeuristicResult {
  trapClass: TrapClass;
  trigger: TrapTrigger;
  severity?: "warn" | "alert";
  explanation: string;
  warning?: string;
}

/** Patterns the heuristic walks for "honeypot at <path>" extractions. */
const HEURISTIC_PATH_PATTERNS: RegExp[] = [
  /honeypot\s+(?:at|on)\s+([\/][\w\/\-:*\.]+)/i,
  /trap\s+(?:at|on|for)\s+([\/][\w\/\-:*\.]+)/i,
  /deploy\s+(?:at|on)\s+([\/][\w\/\-:*\.]+)/i,
  /catch\s+(?:requests?\s+to|callers?\s+at)\s+([\/][\w\/\-:*\.]+)/i,
  /watch\s+(?:for\s+)?(?:requests?\s+(?:to|on))\s+([\/][\w\/\-:*\.]+)/i,
  /([\/][\w\/\-:*\.]+)\s+(?:endpoint|path|route)/i,
];

const SEVERITY_HINTS: Array<{ phrase: RegExp; severity: "warn" | "alert" }> = [
  { phrase: /\b(?:warn|warning|low\s+severity)\b/i, severity: "warn" },
  { phrase: /\b(?:alert|critical|high\s+severity)\b/i, severity: "alert" },
];

/**
 * Phrases that flip the heuristic from http_endpoint default to
 * filesystem class. The operator opts in by mentioning filesystem
 * concepts; otherwise Pi-1 drafts (which had no filesystem signal)
 * keep compiling as http_endpoint traps.
 */
const FILESYSTEM_CLASS_HINTS = [
  /\bfilesystem\b/i,
  /\bfile[-\s]?system\b/i,
  /\bfile\s+(?:read|write|delete|list|access|trap|honeypot)/i,
  /\b(?:read|write|delete|list)\s+file/i,
  /\bdirectory\b/i,
  /\bon[-\s]?disk\b/i,
  /\bpath\s+on\s+disk\b/i,
];

/**
 * Op-narrowing hints applied AFTER the class is established as
 * filesystem. The order matters: if no op-hint matches, we keep all
 * four ops (operator said "filesystem honeypot at /etc/secrets"
 * without narrowing which operation). If at least one matches, only
 * the matched ops fire.
 */
const FILESYSTEM_OP_HINTS: Array<{ phrase: RegExp; op: FilesystemOp }> = [
  { phrase: /\b(?:read|reads|reading|access(?:es|ed)?)\b/i, op: "read" },
  { phrase: /\b(?:write|writes|writing|modif(?:y|ies|ied)|edit)/i, op: "write" },
  { phrase: /\b(?:delete|deletes|deletion|remove|removal|unlink)/i, op: "delete" },
  { phrase: /\b(?:list|listing|enumerate|enumeration|directory\s+listing)/i, op: "list" },
];

function heuristicCompile(english: string): HeuristicResult {
  let pathPattern: string | null = null;
  for (const re of HEURISTIC_PATH_PATTERNS) {
    const match = english.match(re);
    if (match && match[1]) {
      pathPattern = match[1];
      break;
    }
  }
  const fallbackUsed = pathPattern === null;
  if (pathPattern === null) {
    pathPattern = "/honeypot-stub";
  }

  let severity: "warn" | "alert" | undefined;
  for (const hint of SEVERITY_HINTS) {
    if (hint.phrase.test(english)) {
      severity = hint.severity;
      break;
    }
  }

  const isFilesystem = FILESYSTEM_CLASS_HINTS.some((re) => re.test(english));

  if (isFilesystem) {
    const ops: FilesystemOp[] = [];
    for (const hint of FILESYSTEM_OP_HINTS) {
      if (hint.phrase.test(english) && !ops.includes(hint.op)) {
        ops.push(hint.op);
      }
    }
    const resolvedOps = ops.length > 0 ? ops : [...FILESYSTEM_OPS];
    const trigger: FilesystemTrigger = {
      kind: "filesystem",
      path_pattern: pathPattern,
      ops: resolvedOps,
      expected_caller_types: ["wrapped_agent"],
    };
    const opsRendered = resolvedOps.join(",");
    const explanation = fallbackUsed
      ? `Filesystem honeypot compiled from operator draft via heuristic fallback; the English description did not yield a clear path pattern, so the trap is stubbed at ${pathPattern} (ops=${opsRendered}). Operator should edit the path_pattern before deploy.`
      : `Filesystem honeypot compiled from operator draft via heuristic compile; trap fires on ${opsRendered} operations against ${pathPattern}.`;
    return {
      trapClass: "filesystem",
      trigger,
      ...(severity !== undefined ? { severity } : {}),
      explanation,
      ...(fallbackUsed
        ? {
            warning:
              "heuristic compile could not extract a path pattern from the filesystem draft; trap is stubbed at /honeypot-stub. Either rewrite the draft (e.g., 'filesystem honeypot at /etc/secrets for reads') or edit the spec's path_pattern before deploying",
          }
        : {}),
    };
  }

  const trigger: HttpEndpointTrigger = {
    kind: "http_endpoint",
    path_pattern: pathPattern,
    expected_caller_types: ["wrapped_agent"],
  };

  const explanation = fallbackUsed
    ? `Honeypot compiled from operator draft via heuristic fallback; the English description did not yield a clear path pattern, so the trap is stubbed at ${pathPattern}. Operator should edit the path_pattern before deploy.`
    : `Honeypot compiled from operator draft via heuristic compile; trap fires on requests to ${pathPattern}.`;

  return {
    trapClass: "http_endpoint",
    trigger,
    ...(severity !== undefined ? { severity } : {}),
    explanation,
    ...(fallbackUsed
      ? {
          warning:
            "heuristic compile could not extract a path pattern from the draft; trap is stubbed at /honeypot-stub. Either rewrite the draft (e.g., 'honeypot at /admin/secrets') or edit the spec's path_pattern before deploying",
        }
      : {}),
  };
}

// ── Public helper: hash an English draft for audit emission ──────────────

export function hashOfEnglishDraft(text: string): string {
  return createHash("sha256")
    .update(text, "utf8")
    .digest("hex")
    .slice(0, 32);
}
