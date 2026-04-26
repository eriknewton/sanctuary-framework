/**
 * Sanctuary Composition v1.0 -- Runtime Shape Assertions
 *
 * Sidecar JSON-RPC responses cross a process boundary; tsc cannot prove
 * their structure. This module validates required fields and types
 * before the result enters typed code paths, closing the trust boundary
 * (Sanctuary Invariant #4).
 *
 * Helpers throw SidecarResponseShapeError on mismatch. Callers wrap this
 * in try/catch and degrade gracefully (per Invariant #5: degrade safely,
 * never silently fall back to unsafe behavior).
 */

import { SidecarResponseShapeError } from "./errors.js";

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function assertPlainObject(
  method: string,
  result: unknown
): Record<string, unknown> {
  if (!isPlainObject(result)) {
    throw new SidecarResponseShapeError(
      method,
      `expected object, got ${result === null ? "null" : typeof result}`
    );
  }
  return result;
}

export function assertNonEmptyString(
  method: string,
  obj: Record<string, unknown>,
  field: string
): string {
  const v = obj[field];
  if (typeof v !== "string" || v.length === 0) {
    throw new SidecarResponseShapeError(
      method,
      `field "${field}" must be a non-empty string`
    );
  }
  return v;
}

export function assertOptionalString(
  method: string,
  obj: Record<string, unknown>,
  field: string
): string | undefined {
  const v = obj[field];
  if (v === undefined) return undefined;
  if (typeof v !== "string") {
    throw new SidecarResponseShapeError(
      method,
      `field "${field}" must be a string when present`
    );
  }
  return v;
}

export function assertOptionalPlainObject(
  method: string,
  obj: Record<string, unknown>,
  field: string
): Record<string, unknown> | undefined {
  const v = obj[field];
  if (v === undefined) return undefined;
  if (!isPlainObject(v)) {
    throw new SidecarResponseShapeError(
      method,
      `field "${field}" must be a plain object when present`
    );
  }
  return v;
}

export function assertBoolean(
  method: string,
  obj: Record<string, unknown>,
  field: string
): boolean {
  const v = obj[field];
  if (typeof v !== "boolean") {
    throw new SidecarResponseShapeError(
      method,
      `field "${field}" must be a boolean`
    );
  }
  return v;
}

export function assertChecksRecord(
  method: string,
  obj: Record<string, unknown>,
  field: string,
  requiredFlags: readonly string[]
): Record<string, boolean> {
  const v = obj[field];
  if (!isPlainObject(v)) {
    throw new SidecarResponseShapeError(
      method,
      `field "${field}" must be a plain object`
    );
  }
  const out: Record<string, boolean> = {};
  for (const flag of requiredFlags) {
    const cell = v[flag];
    if (typeof cell !== "boolean") {
      throw new SidecarResponseShapeError(
        method,
        `field "${field}.${flag}" must be a boolean`
      );
    }
    out[flag] = cell;
  }
  return out;
}
