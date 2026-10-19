import { createHash } from "node:crypto";
import { parseStrictJsonObject, isRecord } from "../hermes-memory-bridge/strict-json.js";
import {
  HERMES_APPROVAL_DEADLINE_MS,
  MAX_PUBLIC_FRAME_BYTES,
} from "../hermes-memory-bridge/constants.js";
import { enforceForcedTiers } from "./loader.js";
import type { PrincipalPolicy } from "./types.js";

// The first authority profile uses the existing bounded frame allocation ceiling.
export const AUTHORITY_PROFILE_VERSION = 1;
export const MAX_POLICY_BYTES = MAX_PUBLIC_FRAME_BYTES;
const MILLISECONDS_PER_SECOND = 1_000;

// Must match the complete profile fixture in test/principal-policy/authority-profile.test.ts.
const PROFILE: PrincipalPolicy = {
  version: AUTHORITY_PROFILE_VERSION,
  tier1_always_approve: ["memory_insert"],
  tier3_always_allow: ["memory_get", "memory_search"],
  approval_channel: {
    type: "callback",
    timeout_seconds: HERMES_APPROVAL_DEADLINE_MS / MILLISECONDS_PER_SECOND,
  },
  tier2_anomaly: {
    new_namespace_access: "approve",
    new_counterparty: "approve",
    frequency_spike_multiplier: 5, // Profile requires a fivefold frequency increase.
    max_signs_per_minute: 10, // Profile signing ceiling per minute.
    bulk_read_threshold: 20, // Profile bulk-read ceiling per minute.
    first_session_policy: "approve",
  },
};

function matchesProfile(value: unknown, expected: unknown): boolean {
  if (Array.isArray(expected)) {
    // Tier lists are exact sets: duplicate entries cannot substitute for a missing operation.
    return Array.isArray(value) && value.length === expected.length &&
      new Set(value).size === value.length && expected.every((item) => value.includes(item));
  }
  if (isRecord(expected)) {
    // Complete own-key equality rejects omissions and extensions before forced tiers can repair intent.
    return isRecord(value) && Object.keys(value).length === Object.keys(expected).length &&
      Object.keys(expected).every((key) => Object.hasOwn(value, key) && matchesProfile(value[key], expected[key]));
  }
  return value === expected;
}

function freezeRecursively<T>(value: T): T {
  if (typeof value === "object" && value !== null) {
    for (const child of Object.values(value)) freezeRecursively(child);
    Object.freeze(value);
  }
  return value;
}

/**
 * Validate already custody-checked policy bytes against a required protected
 * sha256:<hex> digest and the complete authority profile, then freeze the
 * effective policy. This pure preparatory parser does no file I/O or activation;
 * its future caller must establish file custody and ongoing integrity separately.
 */
export function parseStrictAuthorityPolicy(bytes: Uint8Array, expectedDigest: string): PrincipalPolicy {
  // Bound work before hashing or parsing; an oversized policy is never truncated into acceptable input.
  if (bytes.byteLength > MAX_POLICY_BYTES) throw new Error("Invalid authority policy");
  // The protected digest binds exact source bytes, not a reserialized or default-merged interpretation.
  const digest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  if (digest !== expectedDigest) throw new Error("Invalid authority policy");
  // AB4: decoded duplicate keys must be rejected before any schema or forced-tier normalization.
  const parsed = parseStrictJsonObject(bytes);
  if (!matchesProfile(parsed, PROFILE)) throw new Error("Invalid authority policy");
  // Validation above established the complete shape; only the shared forced-tier function may add operations.
  const policy = enforceForcedTiers(parsed as unknown as PrincipalPolicy);
  // No nested array or channel object can become a mutable route around the validated profile.
  return freezeRecursively(policy);
}
