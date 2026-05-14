import {
  FILESYSTEM_OPS,
  type CredentialEmissionPath,
  type CredentialTrigger,
  type CredentialType,
  type FilesystemOp,
  type TrapClass,
  type TrapSpec,
} from "./types.js";

export interface TrapSpecValidationResult {
  ok: boolean;
  errors: string[];
}

const TRAP_CLASSES: readonly TrapClass[] = [
  "http_endpoint",
  "filesystem",
  "tool_call",
  "credential",
] as const;

const HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] as const;
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

export function validateTrapSpec(spec: unknown): TrapSpecValidationResult {
  const errors: string[] = [];
  if (!isRecord(spec)) {
    return { ok: false, errors: ["spec must be an object"] };
  }

  const trapId = spec["trap_id"];
  if (typeof trapId !== "string" || !/^[A-Za-z0-9_.:-]{1,128}$/.test(trapId)) {
    errors.push("trap_id must be a non-empty stable id");
  }

  const trapClass = spec["trap_class"];
  if (typeof trapClass !== "string" || !TRAP_CLASSES.includes(trapClass as TrapClass)) {
    errors.push("trap_class must be a supported trap class");
  }

  const trigger = spec["trigger"];
  if (!isRecord(trigger)) {
    errors.push("trigger must be an object");
  } else if (typeof trapClass === "string") {
    validateTrigger(trigger, trapClass, errors);
  }

  const severity = spec["finding_severity"];
  if (severity !== "warn" && severity !== "alert") {
    errors.push("finding_severity must be warn or alert");
  }

  for (const field of ["english_text", "explanation_paragraph", "compiled_at"]) {
    if (typeof spec[field] !== "string" || spec[field].trim().length === 0) {
      errors.push(`${field} must be a non-empty string`);
    }
  }

  return { ok: errors.length === 0, errors };
}

function validateTrigger(
  trigger: Record<string, unknown>,
  trapClass: string,
  errors: string[],
): void {
  if (trigger["kind"] !== trapClass) {
    errors.push("trigger.kind must match trap_class");
    return;
  }

  switch (trapClass) {
    case "http_endpoint":
      validateHttpTrigger(trigger, errors);
      return;
    case "filesystem":
      validateFilesystemTrigger(trigger, errors);
      return;
    case "tool_call":
      validateToolCallTrigger(trigger, errors);
      return;
    case "credential":
      validateCredentialTrigger(trigger as Partial<CredentialTrigger>, errors);
      return;
    default:
      errors.push("unsupported trigger kind");
  }
}

function validateHttpTrigger(trigger: Record<string, unknown>, errors: string[]): void {
  validatePathPattern(trigger["path_pattern"], errors);
  if (
    trigger["method"] !== undefined &&
    (typeof trigger["method"] !== "string" ||
      !HTTP_METHODS.includes(trigger["method"].toUpperCase() as (typeof HTTP_METHODS)[number]))
  ) {
    errors.push("http_endpoint method must be a supported HTTP method");
  }
  validateStringArray(trigger["expected_caller_types"], "expected_caller_types", errors);
}

function validateFilesystemTrigger(trigger: Record<string, unknown>, errors: string[]): void {
  validatePathPattern(trigger["path_pattern"], errors);
  const ops = trigger["ops"];
  if (!Array.isArray(ops) || ops.length === 0) {
    errors.push("filesystem ops must be a non-empty array");
  } else {
    for (const op of ops) {
      if (typeof op !== "string" || !FILESYSTEM_OPS.includes(op as FilesystemOp)) {
        errors.push("filesystem ops must contain only supported operations");
        break;
      }
    }
  }
  validateStringArray(trigger["expected_caller_types"], "expected_caller_types", errors);
}

function validateToolCallTrigger(trigger: Record<string, unknown>, errors: string[]): void {
  if (
    typeof trigger["fake_tool_name"] !== "string" ||
    !/^[A-Za-z_][A-Za-z0-9_:/.-]{2,127}$/.test(trigger["fake_tool_name"])
  ) {
    errors.push("fake_tool_name must be a plausible tool name");
  }
  if (
    typeof trigger["fake_tool_description"] !== "string" ||
    trigger["fake_tool_description"].trim().length === 0
  ) {
    errors.push("fake_tool_description must be a non-empty string");
  }
  if (!isRecord(trigger["fake_tool_schema"])) {
    errors.push("fake_tool_schema must be an object");
  }
  if (
    trigger["catalog_visibility"] !== "all_wrapped_agents" &&
    trigger["catalog_visibility"] !== "specific_agents"
  ) {
    errors.push("catalog_visibility must be all_wrapped_agents or specific_agents");
  }
  validateVisibilityList(
    trigger["catalog_visibility"],
    trigger["visible_to_agents"],
    "visible_to_agents",
    errors,
  );
  const fakeResponse = trigger["fake_response"];
  if (
    typeof fakeResponse !== "string" &&
    !isRecord(fakeResponse)
  ) {
    errors.push("fake_response must be a string or object");
  }
}

function validateCredentialTrigger(
  trigger: Partial<CredentialTrigger>,
  errors: string[],
): void {
  if (
    typeof trigger.fake_credential_name !== "string" ||
    !/^[A-Za-z_][A-Za-z0-9_.-]{2,127}$/.test(trigger.fake_credential_name)
  ) {
    errors.push("fake_credential_name must be a plausible credential name");
  }
  if (!CREDENTIAL_TYPES.includes(trigger.fake_credential_type as CredentialType)) {
    errors.push("fake_credential_type must be supported");
  }
  if (
    typeof trigger.fake_credential_value !== "string" ||
    !isOperatorControlledCredentialValue(trigger.fake_credential_value)
  ) {
    errors.push("fake_credential_value must be operator-controlled bait, not a live credential shape");
  }
  if (
    trigger.visibility !== "all_wrapped_agents" &&
    trigger.visibility !== "specific_agents"
  ) {
    errors.push("visibility must be all_wrapped_agents or specific_agents");
  }
  validateVisibilityList(
    trigger.visibility,
    trigger.visible_to_agents,
    "visible_to_agents",
    errors,
  );
  if (!Array.isArray(trigger.emission_paths) || trigger.emission_paths.length === 0) {
    errors.push("emission_paths must be a non-empty array");
  } else {
    for (const path of trigger.emission_paths) {
      if (!CREDENTIAL_EMISSION_PATHS.includes(path)) {
        errors.push("emission_paths must contain only supported paths");
        break;
      }
    }
  }
}

function validatePathPattern(raw: unknown, errors: string[]): void {
  if (typeof raw !== "string" || raw.trim().length === 0 || !raw.startsWith("/")) {
    errors.push("path_pattern must be a non-empty absolute path glob");
  }
}

function validateVisibilityList(
  visibility: unknown,
  raw: unknown,
  field: string,
  errors: string[],
): void {
  if (visibility === "specific_agents") {
    validateStringArray(raw, field, errors);
  } else if (raw !== undefined) {
    validateStringArray(raw, field, errors);
  }
}

function validateStringArray(raw: unknown, field: string, errors: string[]): void {
  if (!Array.isArray(raw) || raw.length === 0) {
    errors.push(`${field} must be a non-empty string array`);
    return;
  }
  if (raw.some((value) => typeof value !== "string" || value.trim().length === 0)) {
    errors.push(`${field} must contain only non-empty strings`);
  }
}

function isOperatorControlledCredentialValue(value: string): boolean {
  if (value.length < 12 || value.length > 512) return false;
  if (/^(AKIA|ASIA)[A-Z0-9]{16}$/.test(value)) return false;
  if (/^sk-(?:live|test)-[A-Za-z0-9]{16,}$/.test(value)) return false;
  if (/^(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}$/.test(value)) return false;
  if (/^xox[baprs]-[A-Za-z0-9-]{20,}$/.test(value)) return false;
  return true;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function assertValidTrapSpec(spec: unknown): asserts spec is TrapSpec {
  const validation = validateTrapSpec(spec);
  if (!validation.ok) {
    throw new Error(`invalid TrapSpec: ${validation.errors.join("; ")}`);
  }
}
