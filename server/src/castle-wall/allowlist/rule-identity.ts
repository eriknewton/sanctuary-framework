/**
 * Stable rule identity and manifest filename contract.
 *
 * MANIFEST-RULEID-PATH-01: the producer (manifest-publisher.ts) writes
 * encoded_v1 filenames (rid1_<base64url(id)>.json). Readers accept both
 * encoded_v1 and legacy_safe for backward compatibility with already-persisted
 * manifests.
 */

import { bytesToString, fromBase64urlStrict, stringToBytes, toBase64url } from "../../core/encoding.js";

declare const ruleIdBrand: unique symbol;
declare const ruleFilenameBrand: unique symbol;

export type RuleId = string & { readonly [ruleIdBrand]: "RuleId" };
export type RuleFilename = string & { readonly [ruleFilenameBrand]: "RuleFilename" };

export const RULE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$/;
export const RULE_ID_MAX_LENGTH = 120;
export const ENCODED_RULE_FILENAME_PREFIX = "rid1_";
export const RULE_FILENAME_SUFFIX = ".json";

export type RuleFilenameRelation = "encoded_v1" | "legacy_safe";

export interface ManifestRuleIdentityEntry {
  rule_id: unknown;
  file: unknown;
}

export type RuleIdentityResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: string };

export function parseRuleId(value: unknown): RuleIdentityResult<RuleId> {
  if (typeof value !== "string") return { ok: false, error: "rule id must be a string" };
  if (!RULE_ID_PATTERN.test(value)) {
    return {
      ok: false,
      error: `rule id must match ${RULE_ID_PATTERN.source} and be at most ${RULE_ID_MAX_LENGTH} ASCII characters`,
    };
  }
  return { ok: true, value: value as RuleId };
}

export function validateRuleId(value: unknown): string | null {
  const result = parseRuleId(value);
  return result.ok ? null : result.error;
}

export function encodeRuleFilename(ruleId: RuleId): RuleFilename {
  return `${ENCODED_RULE_FILENAME_PREFIX}${toBase64url(stringToBytes(ruleId))}${RULE_FILENAME_SUFFIX}` as RuleFilename;
}

function parseEncodedRuleFilename(filename: string): RuleIdentityResult<RuleFilename> {
  if (!filename.startsWith(ENCODED_RULE_FILENAME_PREFIX) || !filename.endsWith(RULE_FILENAME_SUFFIX)) {
    return { ok: false, error: "not an encoded-v1 rule filename" };
  }
  const payload = filename.slice(ENCODED_RULE_FILENAME_PREFIX.length, -RULE_FILENAME_SUFFIX.length);
  if (payload.length === 0 || !/^[A-Za-z0-9_-]+$/.test(payload)) {
    return { ok: false, error: "encoded-v1 rule filename has a non-canonical base64url payload" };
  }
  try {
    const decoded = bytesToString(fromBase64urlStrict(payload));
    const ruleId = parseRuleId(decoded);
    if (!ruleId.ok || encodeRuleFilename(ruleId.value) !== filename) {
      return { ok: false, error: "encoded-v1 rule filename does not round-trip canonically" };
    }
  } catch {
    return { ok: false, error: "encoded-v1 rule filename has an invalid base64url payload" };
  }
  return { ok: true, value: filename as RuleFilename };
}

/** Classify an exact persisted `(rule_id, file)` relation. */
export function classifyManifestRuleFilename(
  ruleIdValue: unknown,
  filenameValue: unknown,
): RuleIdentityResult<RuleFilenameRelation> {
  const parsedRuleId = parseRuleId(ruleIdValue);
  if (!parsedRuleId.ok) return parsedRuleId;
  if (typeof filenameValue !== "string") return { ok: false, error: "rule filename must be a string" };

  const expectedEncoded = encodeRuleFilename(parsedRuleId.value);
  if (filenameValue === expectedEncoded) return { ok: true, value: "encoded_v1" };
  if (filenameValue === `${parsedRuleId.value}${RULE_FILENAME_SUFFIX}`) {
    return { ok: true, value: "legacy_safe" };
  }

  const encoded = parseEncodedRuleFilename(filenameValue);
  return encoded.ok
    ? { ok: false, error: "encoded-v1 rule filename does not match rule id" }
    : { ok: false, error: "rule filename is neither encoded-v1 nor the exact legacy-safe relation" };
}

/**
 * Read-only phase-one manifest scan. It intentionally consumes no referenced
 * filename and reports every malformed relation or full-set collision.
 */
export function preflightManifestRuleEntries(entriesValue: unknown): string[] {
  const issues: string[] = [];
  if (!Array.isArray(entriesValue)) return ["manifest rules must be an array"];
  const ruleIds = new Set<string>();
  const filenames = new Set<string>();
  for (const [index, entryValue] of entriesValue.entries()) {
    if (entryValue === null || typeof entryValue !== "object") {
      issues.push(`manifest rule ${index}: entry must be an object`);
      continue;
    }
    const entry = entryValue as ManifestRuleIdentityEntry;
    if (typeof entry.rule_id === "string") {
      if (ruleIds.has(entry.rule_id)) issues.push(`manifest rule ${index}: duplicate rule id`);
      ruleIds.add(entry.rule_id);
    }
    if (typeof entry.file === "string") {
      if (filenames.has(entry.file)) issues.push(`manifest rule ${index}: duplicate rule filename`);
      filenames.add(entry.file);
    }
    const relation = classifyManifestRuleFilename(entry.rule_id, entry.file);
    if (!relation.ok) {
      issues.push(`manifest rule ${index}: ${relation.error}`);
    }
  }
  return issues;
}
