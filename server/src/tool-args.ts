/** Shared tool argument validation/normalization for execution and preflight. */

/** Maximum byte length for any single string argument (1 MB) */
const MAX_STRING_BYTES = 1_048_576;

/** Maximum byte length for base64 bundle arguments (5 MB) */
const MAX_BUNDLE_BYTES = 5_242_880;

/** Fields known to carry base64 bundles — get the larger size cap */
const BUNDLE_FIELDS = new Set(["bundle"]);

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
