/** Shared tool argument validation/normalization for execution and preflight. */

/** Maximum byte length for any single string argument (1 MB) */
const MAX_STRING_BYTES = 1_048_576;

/** Maximum byte length for base64 bundle arguments (5 MB) */
const MAX_BUNDLE_BYTES = 5_242_880;

/** Fields known to carry base64 bundles — get the larger size cap */
const BUNDLE_FIELDS = new Set(["bundle"]);

/**
 * Maximum serialized byte length for a nested object/array argument (LD3
 * BRIDGE-BP-01). The string-byte check below only ever covered top-level
 * STRING fields; a `type: "object"` or `type: "array"` schema property
 * (e.g. bridge_commit's `terms`) carried no size bound at all, so a caller
 * could smuggle an arbitrarily large payload through any tool's
 * object-typed argument, bypassing MAX_STRING_BYTES entirely. Reuses that
 * same 1 MB ceiling rather than a second derived number: it is already
 * generous for every legitimate structured argument in this tool surface
 * (none of which is a bulk-data transfer — those use string `bundle`
 * fields, capped separately above at the larger MAX_BUNDLE_BYTES). Checked
 * once here, at the shared validateArgs chokepoint, so every tool's
 * object/array arguments get the bound instead of each call site having to
 * remember to add its own (AGENTS.md rule 5: a shared parser is fixed once,
 * not per caller).
 */
const MAX_NESTED_VALUE_BYTES = MAX_STRING_BYTES;

export interface SchemaProperty {
  type?: string;
  properties?: Record<string, SchemaProperty>;
  required?: string[];
  items?: SchemaProperty;
  enum?: unknown[];
  default?: unknown;
}

export interface ValidationError {
  field: string;
  message: string;
}

export class ToolArgumentValidationError extends Error {
  readonly violations: ValidationError[];

  constructor(violations: ValidationError[]) {
    super("Tool arguments failed schema validation");
    this.name = "ToolArgumentValidationError";
    this.violations = violations;
  }
}

/**
 * Validate tool arguments against the tool's declared inputSchema.
 * Returns an array of validation errors (empty = valid).
 */
export function validateArgs(
  args: Record<string, unknown>,
  schema: Record<string, unknown>,
  extraAllowedFields: Record<string, SchemaProperty> = {}
): ValidationError[] {
  const errors: ValidationError[] = [];
  const properties = (schema.properties ?? {}) as Record<string, SchemaProperty>;
  const required = (schema.required ?? []) as string[];

  for (const field of required) {
    if (args[field] === undefined || args[field] === null) {
      errors.push({ field, message: `Required field "${field}" is missing` });
    }
  }

  const knownFields = new Set([
    ...Object.keys(properties),
    ...Object.keys(extraAllowedFields),
  ]);
  for (const field of Object.keys(args)) {
    if (!knownFields.has(field)) {
      errors.push({ field, message: `Unknown field "${field}"` });
    }
  }

  for (const [field, value] of Object.entries(args)) {
    if (value === undefined || value === null) continue;
    const propSchema = properties[field] ?? extraAllowedFields[field];
    if (!propSchema) continue;

    const typeError = checkType(field, value, propSchema);
    if (typeError) {
      errors.push(typeError);
      continue;
    }

    if (typeof value === "string") {
      const maxBytes = BUNDLE_FIELDS.has(field) ? MAX_BUNDLE_BYTES : MAX_STRING_BYTES;
      const byteLength = new TextEncoder().encode(value).length;
      if (byteLength > maxBytes) {
        errors.push({
          field,
          message: `Field "${field}" exceeds maximum size (${byteLength} bytes > ${maxBytes} bytes)`,
        });
      }
    }

    // LD3 BRIDGE-BP-01: nested object/array arguments bypassed the string
    // check above entirely. `typeof value === "object"` also matches arrays
    // (checkType already validated shape against the schema's declared
    // type), so one check here bounds both.
    if (typeof value === "object" && value !== null) {
      const byteLength = new TextEncoder().encode(JSON.stringify(value)).length;
      if (byteLength > MAX_NESTED_VALUE_BYTES) {
        errors.push({
          field,
          message:
            `Field "${field}" exceeds maximum size ` +
            `(${byteLength} bytes > ${MAX_NESTED_VALUE_BYTES} bytes)`,
        });
      }
    }

    if (propSchema.enum && !propSchema.enum.includes(value)) {
      errors.push({
        field,
        message: `Field "${field}" must be one of: ${propSchema.enum.join(", ")}`,
      });
    }
  }

  return errors;
}

function checkType(
  field: string,
  value: unknown,
  schema: SchemaProperty
): ValidationError | null {
  if (!schema.type) return null;

  switch (schema.type) {
    case "string":
      if (typeof value !== "string") {
        return { field, message: `Expected string for "${field}", got ${typeof value}` };
      }
      break;
    case "number":
      if (typeof value !== "number") {
        return { field, message: `Expected number for "${field}", got ${typeof value}` };
      }
      break;
    case "boolean":
      if (typeof value !== "boolean") {
        return { field, message: `Expected boolean for "${field}", got ${typeof value}` };
      }
      break;
    case "object":
      if (typeof value !== "object" || Array.isArray(value)) {
        return { field, message: `Expected object for "${field}", got ${typeof value}` };
      }
      break;
    case "array":
      if (!Array.isArray(value)) {
        return { field, message: `Expected array for "${field}", got ${typeof value}` };
      }
      break;
  }
  return null;
}

export function extraAllowedFieldsForTool(toolClass?: "read" | "write"): Record<string, SchemaProperty> {
  return {
    ...(toolClass === "write"
      ? { accept_broken_chain: { type: "boolean", default: false } }
      : {}),
    approval_ref: { type: "string" },
  };
}

export function normalizeToolArgsForValidation(params: {
  args: Record<string, unknown>;
  schema: Record<string, unknown>;
  toolClass?: "read" | "write";
}): { handlerArgs: Record<string, unknown>; approvalRef?: string } {
  const validationErrors = validateArgs(
    params.args,
    params.schema,
    extraAllowedFieldsForTool(params.toolClass)
  );
  if (validationErrors.length > 0) {
    throw new ToolArgumentValidationError(validationErrors);
  }

  const approvalRef =
    typeof params.args.approval_ref === "string"
      ? params.args.approval_ref
      : undefined;
  const handlerArgs = { ...params.args };
  delete handlerArgs.approval_ref;
  return { handlerArgs, approvalRef };
}
