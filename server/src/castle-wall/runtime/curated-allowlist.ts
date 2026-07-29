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
 *
 * Exfil-hardening posture (competitor-readiness item 5, 2026-06-29):
 * the curated default deliberately EXCLUDES messaging-platform API hosts
 * (Slack, Discord, Telegram, and obvious siblings). A messaging webhook or
 * bot API is one of the lowest-friction exfiltration channels an agent can
 * reach: a single authenticated POST ships state out as a "chat message"
 * that reads as benign traffic. Keeping these out of the out-of-box curated
 * set means an operator never silently ships a default-suggested exfil lane.
 * This is a DEFAULT-only tightening, not a hard block: an operator who needs
 * a messaging channel adds an explicit AllowlistRule for that host through
 * the dashboard / manifest surface exactly as they would for any other host,
 * and that operator-authored rule is honored unchanged. The curated list is
 * a set of suggestions, never the ceiling on what an operator may allow.
 * MESSAGING_HOST_DENYLIST below is the canonical record of which host
 * families are kept out of the default; the regression guard in
 * test/castle-wall/runtime/curated-allowlist.test.ts pins it so a future
 * contributor cannot quietly re-introduce a messaging host into the default.
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
 * Messaging-platform API host families kept OUT of the curated default for
 * exfil-hardening (see the module header). These are the lowest-friction
 * exfiltration channels: a single authenticated POST to a webhook or bot API
 * ships state out as a chat message. This is a denylist for the DEFAULT
 * SUGGESTION set only; it does NOT block an operator from explicitly
 * authoring an AllowlistRule for any of these hosts; it only guarantees none
 * are pre-suggested out of the box. Substring match (case-insensitive) so a
 * regional or versioned sibling (e.g. discordapp.com, t.me, api2.telegram.org)
 * is caught by the guard as well. Keep this list and the curated set disjoint;
 * the regression test enforces that invariant.
 */
export const MESSAGING_HOST_DENYLIST: ReadonlyArray<string> = Object.freeze([
  "slack.com",
  "slack-edge.com",
  "discord.com",
  "discordapp.com",
  "discord.gg",
  "telegram.org",
  "telegram.me",
  "t.me",
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
