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
 *     `ops` array, or `trap_class: "tool_call"` with fake-tool
 *     catalog metadata.
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
  type CredentialEmissionPath,
  type CredentialTrigger,
  type CredentialType,
  type CredentialVisibility,
  type FilesystemOp,
  type FilesystemTrigger,
  type HoneypotDraft,
  type HttpEndpointTrigger,
  type ToolCallCatalogVisibility,
  type ToolCallTrigger,
  type TrapClass,
  type TrapSpec,
  type TrapTrigger,
} from "./types.js";
import { validateTrapSpec } from "./trap-spec-validation.js";

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
 * Pi-4 extends the schema with `credential` bait fields.
 */
const COMPILE_PROMPT = `You are compiling a Sanctuary honeypot from an operator's plain-English description.
Return STRICT JSON with the following shape (no markdown, no commentary):
{
  "trap_class": "http_endpoint" | "filesystem" | "tool_call" | "credential",
  "path_pattern": "string (glob with * or **)",
  "method": "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "ANY",
  "ops": ["read", "write", "delete", "list"],
  "fake_tool_name": "string",
  "fake_tool_description": "string",
  "fake_tool_schema": {"type":"object","properties":{}},
  "catalog_visibility": "all_wrapped_agents" | "specific_agents",
  "visible_to_agents": ["agent_id"],
  "fake_response": "string or JSON object",
  "fake_credential_name": "string",
  "fake_credential_type": "api_key" | "password" | "session_token" | "bearer_token" | "oauth_refresh",
  "fake_credential_value": "operator-controlled plausible fake credential",
  "visibility": "all_wrapped_agents" | "specific_agents",
  "emission_paths": ["secret_broker" | "env_var_export" | "config_file"],
  "fake_response_on_use": "optional plausible 401/403 response",
  "monitored_target_hosts": ["api.example.com"],
  "expected_caller_types": ["wrapped_agent" | "operator" | "external"],
  "finding_severity": "warn" | "alert",
  "explanation_paragraph": "one-sentence operator-friendly explanation"
}
Default trap_class to "http_endpoint" unless the operator clearly describes filesystem access (file reads/writes, directory access, path-on-disk monitoring), fake MCP tool/catalog bait, or fake credentials/secrets/API keys/tokens/passwords. The "method" field applies only to http_endpoint traps; the "ops" field applies only to filesystem traps; fake_tool_* fields apply only to tool_call traps; fake_credential_* fields apply only to credential traps. Match the operator's stated severity if they gave one; otherwise default to "alert". If method is unspecified for http_endpoint, return "ANY". If ops is unspecified for filesystem, return ["read","write","delete","list"]. For tool_call, catalog_visibility defaults to "all_wrapped_agents", fake_tool_schema defaults to {"type":"object","properties":{}}, and fake_response should be clearly operator-controlled bait. For credential, visibility defaults to "all_wrapped_agents", emission_paths defaults to ["secret_broker"], and fake_response_on_use must look like a real 401 or 403 service response, not a honeypot warning. If caller-type is unspecified, return ["wrapped_agent"]. Keep the explanation_paragraph under 200 characters.`;

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

  const validation = validateTrapSpec(spec);
  if (!validation.ok) {
    warnings.push(`compiled TrapSpec failed validation: ${validation.errors.join("; ")}`);
  }

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
    | "missing_fake_tool_name"
    | "invalid_fake_tool_schema"
    | "invalid_catalog_visibility"
    | "invalid_fake_response"
    | "missing_fake_credential_name"
    | "invalid_fake_credential_type"
    | "invalid_fake_credential_value"
    | "invalid_credential_visibility"
    | "invalid_credential_emission_paths"
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
    trapClassRaw === "filesystem"
      ? "filesystem"
      : trapClassRaw === "tool_call"
        ? "tool_call"
        : trapClassRaw === "credential"
          ? "credential"
          : "http_endpoint";

  if (trapClass === "credential") {
    const parsed = parseCredentialTrigger(obj);
    if (!parsed.ok) return { ok: false, failure: parsed.failure };
    return {
      ok: true,
      trapClass,
      trigger: parsed.trigger,
      severity,
      explanation,
    };
  }

  if (trapClass === "tool_call") {
    const parsed = parseToolCallTrigger(obj);
    if (!parsed.ok) return { ok: false, failure: parsed.failure };
    return {
      ok: true,
      trapClass,
      trigger: parsed.trigger,
      severity,
      explanation,
    };
  }

  const pathPattern = obj["path_pattern"];
  if (typeof pathPattern !== "string" || pathPattern.length === 0) {
    return { ok: false, failure: "missing_path_pattern" };
  }

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

type ToolCallParseResult =
  | { ok: true; trigger: ToolCallTrigger }
  | {
      ok: false;
      failure:
        | "missing_fake_tool_name"
        | "invalid_fake_tool_schema"
        | "invalid_catalog_visibility"
        | "invalid_fake_response";
    };

function parseToolCallTrigger(
  obj: Record<string, unknown>,
): ToolCallParseResult {
  const name = obj["fake_tool_name"];
  if (typeof name !== "string" || !isPlausibleToolName(name)) {
    return { ok: false, failure: "missing_fake_tool_name" };
  }
  const description =
    typeof obj["fake_tool_description"] === "string" &&
    obj["fake_tool_description"].length > 0
      ? obj["fake_tool_description"]
      : `Operator-controlled diagnostic tool ${name}.`;
  const schema = obj["fake_tool_schema"];
  if (
    schema !== undefined &&
    (!schema || typeof schema !== "object" || Array.isArray(schema))
  ) {
    return { ok: false, failure: "invalid_fake_tool_schema" };
  }
  const visibilityRaw = obj["catalog_visibility"];
  if (
    visibilityRaw !== undefined &&
    visibilityRaw !== "all_wrapped_agents" &&
    visibilityRaw !== "specific_agents"
  ) {
    return { ok: false, failure: "invalid_catalog_visibility" };
  }
  const visibility: ToolCallCatalogVisibility =
    visibilityRaw === "specific_agents"
      ? "specific_agents"
      : "all_wrapped_agents";
  const visibleToAgents = Array.isArray(obj["visible_to_agents"])
    ? (obj["visible_to_agents"] as unknown[]).filter(
        (v): v is string => typeof v === "string" && v.length > 0,
      )
    : [];
  if (visibility === "specific_agents" && visibleToAgents.length === 0) {
    return { ok: false, failure: "invalid_catalog_visibility" };
  }
  const fakeResponse = obj["fake_response"];
  if (
    typeof fakeResponse !== "string" &&
    (!fakeResponse ||
      typeof fakeResponse !== "object" ||
      Array.isArray(fakeResponse))
  ) {
    return { ok: false, failure: "invalid_fake_response" };
  }
  return {
    ok: true,
    trigger: {
      kind: "tool_call",
      fake_tool_name: name,
      fake_tool_description: description,
      fake_tool_schema:
        schema && typeof schema === "object" && !Array.isArray(schema)
          ? (schema as Record<string, unknown>)
          : { type: "object", properties: {} },
      catalog_visibility: visibility,
      ...(visibility === "specific_agents"
        ? { visible_to_agents: visibleToAgents }
        : {}),
      fake_response: fakeResponse as string | Record<string, unknown>,
    },
  };
}

type CredentialParseResult =
  | { ok: true; trigger: CredentialTrigger }
  | {
      ok: false;
      failure:
        | "missing_fake_credential_name"
        | "invalid_fake_credential_type"
        | "invalid_fake_credential_value"
        | "invalid_credential_visibility"
        | "invalid_credential_emission_paths";
    };

const CREDENTIAL_TYPES: readonly CredentialType[] = [
  "api_key",
  "password",
  "session_token",
  "bearer_token",
  "oauth_refresh",
] as const;

const CREDENTIAL_EMISSION_PATHS: readonly CredentialEmissionPath[] = [
  "secret_broker",
  "env_var_export",
  "config_file",
] as const;

function parseCredentialTrigger(
  obj: Record<string, unknown>,
): CredentialParseResult {
  const name = obj["fake_credential_name"];
  if (typeof name !== "string" || !isPlausibleCredentialName(name)) {
    return { ok: false, failure: "missing_fake_credential_name" };
  }
  const typeRaw = obj["fake_credential_type"];
  if (
    typeof typeRaw !== "string" ||
    !CREDENTIAL_TYPES.includes(typeRaw as CredentialType)
  ) {
    return { ok: false, failure: "invalid_fake_credential_type" };
  }
  const type = typeRaw as CredentialType;
  const value = obj["fake_credential_value"];
  if (
    typeof value !== "string" ||
    !isPlausibleCredentialValue(type, value)
  ) {
    return { ok: false, failure: "invalid_fake_credential_value" };
  }
  const visibilityRaw = obj["visibility"];
  if (
    visibilityRaw !== undefined &&
    visibilityRaw !== "all_wrapped_agents" &&
    visibilityRaw !== "specific_agents"
  ) {
    return { ok: false, failure: "invalid_credential_visibility" };
  }
  const visibility: CredentialVisibility =
    visibilityRaw === "specific_agents"
      ? "specific_agents"
      : "all_wrapped_agents";
  const visibleToAgents = Array.isArray(obj["visible_to_agents"])
    ? (obj["visible_to_agents"] as unknown[]).filter(
        (v): v is string => typeof v === "string" && v.length > 0,
      )
    : [];
  if (visibility === "specific_agents" && visibleToAgents.length === 0) {
    return { ok: false, failure: "invalid_credential_visibility" };
  }
  const emissionPaths = parseCredentialEmissionPaths(obj["emission_paths"]);
  if (emissionPaths === null) {
    return { ok: false, failure: "invalid_credential_emission_paths" };
  }
  const fakeResponse = obj["fake_response_on_use"];
  const targetHosts = Array.isArray(obj["monitored_target_hosts"])
    ? (obj["monitored_target_hosts"] as unknown[]).filter(
        (v): v is string => typeof v === "string" && v.length > 0,
      )
    : [];
  return {
    ok: true,
    trigger: {
      kind: "credential",
      fake_credential_name: name,
      fake_credential_type: type,
      fake_credential_value: value,
      visibility,
      ...(visibility === "specific_agents"
        ? { visible_to_agents: visibleToAgents }
        : {}),
      emission_paths: emissionPaths,
      ...(typeof fakeResponse === "string" && fakeResponse.length > 0
        ? { fake_response_on_use: fakeResponse }
        : {}),
      ...(targetHosts.length > 0 ? { monitored_target_hosts: targetHosts } : {}),
    },
  };
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

function parseCredentialEmissionPaths(
  raw: unknown,
): CredentialEmissionPath[] | null {
  if (raw === undefined || raw === null) return ["secret_broker"];
  if (!Array.isArray(raw)) return null;
  if (raw.length === 0) return ["secret_broker"];
  const out: CredentialEmissionPath[] = [];
  for (const entry of raw) {
    if (typeof entry !== "string") return null;
    if (!CREDENTIAL_EMISSION_PATHS.includes(entry as CredentialEmissionPath)) {
      return null;
    }
    if (!out.includes(entry as CredentialEmissionPath)) {
      out.push(entry as CredentialEmissionPath);
    }
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

const TOOL_CALL_CLASS_HINTS = [
  /\btool[-\s]?call\b/i,
  /\bfake\s+(?:mcp\s+)?tool\b/i,
  /\bfake\s+[A-Za-z_][A-Za-z0-9_:/.-]{2,}\s+tool\b/i,
  /\btool\s+catalog\b/i,
  /\bif\s+invoked\b/i,
  /\binvokes?\s+(?:the\s+)?(?:fake\s+)?tool\b/i,
];

const TOOL_NAME_HINTS: RegExp[] = [
  /\bfake\s+(?:tool\s+)?([A-Za-z_][A-Za-z0-9_:/.-]{2,})\s+tool\b/i,
  /\btool\s+(?:named|called)\s+([A-Za-z_][A-Za-z0-9_:/.-]{2,})\b/i,
  /\bdeploy\s+(?:a\s+)?(?:fake\s+)?([A-Za-z_][A-Za-z0-9_:/.-]{2,})\s+tool\b/i,
  /\binvoked?,?\s+(?:return|then)\b.*?\b([A-Za-z_][A-Za-z0-9_:/.-]{2,})\b/i,
  /\b([A-Za-z_][A-Za-z0-9_:/.-]{2,})\s+tool\b/i,
];

const CREDENTIAL_CLASS_HINTS = [
  /\bcredential\b/i,
  /\bsecret\b/i,
  /\bapi\s*key\b/i,
  /\bpassword\b/i,
  /\bsession\s*token\b/i,
  /\bbearer\s*token\b/i,
  /\boauth\s*refresh\b/i,
];

const CREDENTIAL_NAME_HINTS: RegExp[] = [
  /\bfake\s+([A-Za-z_][A-Za-z0-9_.-]{2,})\s+(?:api\s*key|secret|token|password|credential)\b/i,
  /\b(?:secret|credential|api\s*key|token|password)\s+(?:named|called)\s+([A-Za-z_][A-Za-z0-9_.-]{2,})\b/i,
  /\b([A-Za-z_][A-Za-z0-9_.-]{2,})\s+(?:api\s*key|secret|token|password|credential)\b/i,
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
  const isToolCall = TOOL_CALL_CLASS_HINTS.some((re) => re.test(english));
  const isCredential = CREDENTIAL_CLASS_HINTS.some((re) => re.test(english));

  if (isCredential && !isToolCall) {
    const credentialType = inferCredentialType(english);
    const credentialName =
      extractCredentialName(english) ?? defaultCredentialName(credentialType);
    const visibleToAgents = extractVisibleAgents(english);
    const emissionPaths = inferCredentialEmissionPaths(english);
    const targetHosts = extractTargetHosts(english);
    const trigger: CredentialTrigger = {
      kind: "credential",
      fake_credential_name: credentialName,
      fake_credential_type: credentialType,
      fake_credential_value: defaultCredentialValue(credentialType),
      visibility:
        visibleToAgents.length > 0
          ? "specific_agents"
          : "all_wrapped_agents",
      ...(visibleToAgents.length > 0
        ? { visible_to_agents: visibleToAgents }
        : {}),
      emission_paths: emissionPaths,
      fake_response_on_use:
        "HTTP/1.1 401 Unauthorized\n{\"error\":\"invalid_api_key\"}",
      ...(targetHosts.length > 0 ? { monitored_target_hosts: targetHosts } : {}),
    };
    return {
      trapClass: "credential",
      trigger,
      ...(severity !== undefined ? { severity } : {}),
      explanation:
        `Credential honeypot compiled from operator draft via heuristic compile; trap exposes ${credentialName} through ${emissionPaths.join(",")}.`,
    };
  }

  if (isToolCall) {
    const fakeToolName = extractToolName(english) ?? "admin_password_reader";
    const fakeResponse = extractFakeResponse(english);
    const visibleToAgents = extractVisibleAgents(english);
    const trigger: ToolCallTrigger = {
      kind: "tool_call",
      fake_tool_name: fakeToolName,
      fake_tool_description:
        `Read protected administrative material for ${fakeToolName}.`,
      fake_tool_schema: {
        type: "object",
        properties: {
          reason: {
            type: "string",
            description: "Reason the caller needs the protected material.",
          },
        },
      },
      catalog_visibility:
        visibleToAgents.length > 0
          ? "specific_agents"
          : "all_wrapped_agents",
      ...(visibleToAgents.length > 0
        ? { visible_to_agents: visibleToAgents }
        : {}),
      fake_response: fakeResponse,
    };
    return {
      trapClass: "tool_call",
      trigger,
      ...(severity !== undefined ? { severity } : {}),
      explanation:
        `Tool-call honeypot compiled from operator draft via heuristic compile; trap injects ${fakeToolName} into the wrapped-agent MCP catalog.`,
    };
  }

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

function isPlausibleToolName(value: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_:/.-]{2,127}$/.test(value);
}

function isPlausibleCredentialName(value: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_.-]{2,127}$/.test(value);
}

export function isPlausibleCredentialValue(
  type: CredentialType,
  value: string,
): boolean {
  if (value.length < 12 || value.length > 512) return false;
  if (/honeypot|trap|fake/i.test(value)) return false;
  switch (type) {
    case "api_key":
      return /^[A-Za-z0-9._-]{16,160}$/.test(value);
    case "password":
      return value.length >= 12 && /\d/.test(value) && /[A-Za-z]/.test(value);
    case "session_token":
    case "bearer_token":
    case "oauth_refresh":
      return /^[A-Za-z0-9._~+/-]{20,512}={0,2}$/.test(value);
  }
}

function extractToolName(english: string): string | null {
  for (const re of TOOL_NAME_HINTS) {
    const match = english.match(re);
    const candidate = match?.[1];
    if (candidate && isPlausibleToolName(candidate)) return candidate;
  }
  return null;
}

function extractVisibleAgents(english: string): string[] {
  const match = english.match(/\bvisible\s+to\s+agents?\s+([A-Za-z0-9_,:\s.-]+)/i);
  if (!match?.[1]) return [];
  if (/\ball\b/i.test(match[1])) return [];
  return match[1]
    .split(/[,\s]+/)
    .map((v) => v.trim())
    .filter((v) => v.length > 0 && !/^(and|if|return)$/i.test(v));
}

function inferCredentialType(english: string): CredentialType {
  if (/\bpassword\b/i.test(english)) return "password";
  if (/\bsession\s*token\b/i.test(english)) return "session_token";
  if (/\bbearer\s*token\b/i.test(english)) return "bearer_token";
  if (/\boauth\s*refresh\b/i.test(english)) return "oauth_refresh";
  return "api_key";
}

function extractCredentialName(english: string): string | null {
  for (const re of CREDENTIAL_NAME_HINTS) {
    const match = english.match(re);
    const candidate = match?.[1];
    if (candidate && isPlausibleCredentialName(candidate)) return candidate;
  }
  return null;
}

function defaultCredentialName(type: CredentialType): string {
  switch (type) {
    case "password":
      return "admin_db_password";
    case "session_token":
      return "admin_session_token";
    case "bearer_token":
      return "prod_bearer_token";
    case "oauth_refresh":
      return "oauth_refresh_token";
    case "api_key":
      return "admin_api_key";
  }
}

function defaultCredentialValue(type: CredentialType): string {
  switch (type) {
    case "password":
      return "V3lv3t-Atlas-91-Ridge";
    case "session_token":
      return "sess_liv_7HnF2qKp9TzM4xRb6WcY8vLs3Ea";
    case "bearer_token":
      return "brr_live_9aK4mQ7vT2xY8pL5sN3dR6hC1gF0";
    case "oauth_refresh":
      return "1//0gXyZpQ9mN7bVcD4eF6hJ8kL2rT5wA3sE";
    case "api_key":
      return "ak_live_51N7bVcD4eF6hJ8kL2rT5wA3sE9xQ";
  }
}

function inferCredentialEmissionPaths(
  english: string,
): CredentialEmissionPath[] {
  const out: CredentialEmissionPath[] = [];
  if (/\bsecret\s*broker|broker\b/i.test(english)) out.push("secret_broker");
  if (/\benv(?:ironment)?\s*(?:var|variable|export)\b/i.test(english)) {
    out.push("env_var_export");
  }
  if (/\bconfig\s*file|configuration\s*file\b/i.test(english)) {
    out.push("config_file");
  }
  return out.length > 0 ? out : ["secret_broker"];
}

function extractTargetHosts(english: string): string[] {
  const hosts = new Set<string>();
  const hostRe = /\b(?:against|to|host)\s+([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/gi;
  let match: RegExpExecArray | null;
  while ((match = hostRe.exec(english)) !== null) {
    if (match[1]) hosts.add(match[1].toLowerCase());
  }
  return [...hosts];
}

function extractFakeResponse(english: string): string {
  const quoted = english.match(/return\s+["']([^"']+)["']/i);
  if (quoted?.[1]) return quoted[1];
  if (/password/i.test(english)) {
    return "TRAP_ONLY_FAKE_PASSWORD_DO_NOT_USE";
  }
  return "TRAP_ONLY_FAKE_RESPONSE";
}

// ── Public helper: hash an English draft for audit emission ──────────────

export function hashOfEnglishDraft(text: string): string {
  return createHash("sha256")
    .update(text, "utf8")
    .digest("hex")
    .slice(0, 32);
}
