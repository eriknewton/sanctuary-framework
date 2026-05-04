/**
 * Curated allowlist of well-known agent endpoints (E6.1 default).
 *
 * Per scope-lock §6 amendment E6.1: Sanctuary ships a small curated
 * allowlist the operator opts into at install time. None of these are
 * auto-enabled; the installer prompts the operator to enable each entry
 * and the manifest written to disk reflects only the operator's choices.
 *
 * Entries here are well-known agent provider endpoints. Operators may add
 * their own rules later through the dashboard surface (PR 5 ships the UI).
 */

import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../constants.js";
import type {
  AllowlistRule,
  RuleDisposition,
  RuleProtocol,
} from "../allowlist/schema.js";

const TCP: RuleProtocol = "tcp";
const ALLOW: RuleDisposition = "allow";

/** A curated entry presented to the operator at install time. */
export interface CuratedAllowlistEntry {
  rule_id: string;
  description: string;
  rule: AllowlistRule;
  default_enabled: false;
}

/** v1.0 curated allowlist. Frozen so callers cannot mutate the canonical set. */
export const CURATED_ALLOWLIST: ReadonlyArray<CuratedAllowlistEntry> = Object.freeze([
  Object.freeze({
    rule_id: "curated-anthropic-api",
    description: "Anthropic API (api.anthropic.com over TLS)",
    rule: {
      id: "curated-anthropic-api",
      schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
      created_at: "2026-05-04T00:00:00Z",
      description: "Anthropic API (api.anthropic.com over TLS)",
      match: { host: ["api.anthropic.com"], port: [443], protocol: TCP },
      scope: {},
      disposition: ALLOW,
    },
    default_enabled: false,
  }),
  Object.freeze({
    rule_id: "curated-openai-api",
    description: "OpenAI API (api.openai.com over TLS)",
    rule: {
      id: "curated-openai-api",
      schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
      created_at: "2026-05-04T00:00:00Z",
      description: "OpenAI API (api.openai.com over TLS)",
      match: { host: ["api.openai.com"], port: [443], protocol: TCP },
      scope: {},
      disposition: ALLOW,
    },
    default_enabled: false,
  }),
  Object.freeze({
    rule_id: "curated-xai-api",
    description: "xAI API (api.x.ai over TLS)",
    rule: {
      id: "curated-xai-api",
      schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
      created_at: "2026-05-04T00:00:00Z",
      description: "xAI API (api.x.ai over TLS)",
      match: { host: ["api.x.ai"], port: [443], protocol: TCP },
      scope: {},
      disposition: ALLOW,
    },
    default_enabled: false,
  }),
  Object.freeze({
    rule_id: "curated-github-api",
    description: "GitHub API (api.github.com over TLS)",
    rule: {
      id: "curated-github-api",
      schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
      created_at: "2026-05-04T00:00:00Z",
      description: "GitHub API (api.github.com over TLS)",
      match: { host: ["api.github.com"], port: [443], protocol: TCP },
      scope: {},
      disposition: ALLOW,
    },
    default_enabled: false,
  }),
  Object.freeze({
    rule_id: "curated-npm-registry",
    description: "npm registry (registry.npmjs.org over TLS)",
    rule: {
      id: "curated-npm-registry",
      schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
      created_at: "2026-05-04T00:00:00Z",
      description: "npm registry (registry.npmjs.org over TLS)",
      match: { host: ["registry.npmjs.org"], port: [443], protocol: TCP },
      scope: {},
      disposition: ALLOW,
    },
    default_enabled: false,
  }),
  Object.freeze({
    rule_id: "curated-pypi",
    description: "Python Package Index (pypi.org + files.pythonhosted.org over TLS)",
    rule: {
      id: "curated-pypi",
      schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
      created_at: "2026-05-04T00:00:00Z",
      description: "Python Package Index (pypi.org + files.pythonhosted.org over TLS)",
      match: {
        host: ["pypi.org", "files.pythonhosted.org"],
        port: [443],
        protocol: TCP,
      },
      scope: {},
      disposition: ALLOW,
    },
    default_enabled: false,
  }),
]);

/**
 * Resolve the rules the operator selected from the curated set. Used by
 * the installer + manifest publisher to write only enabled entries to disk.
 */
export function resolveCuratedRules(
  enabledRuleIds: ReadonlyArray<string>
): ReadonlyArray<AllowlistRule> {
  const enabledSet = new Set(enabledRuleIds);
  return CURATED_ALLOWLIST.filter((entry) => enabledSet.has(entry.rule_id)).map(
    (entry) => entry.rule
  );
}
