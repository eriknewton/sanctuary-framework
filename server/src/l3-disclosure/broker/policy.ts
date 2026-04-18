/**
 * Sanctuary MCP Server — L3 Secret Broker: Policy Schema Extension
 *
 * Additive layer on top of the existing Principal Policy YAML: a new
 * optional top-level `skills:` section declares which skills may access
 * which secrets from the broker, at what scope, and with what TTL.
 *
 * Design (see Spike 2 for rationale):
 * - Absence of `skills:` means NO skill has broker access. Safe default.
 * - Scope values: "read" | "rotate" (rotate implies read).
 * - TTL optional; falls back to broker default (15 min) if unset.
 *
 * This module only parses/validates. The Broker/TokenIssuer enforces.
 */

import type { SecretScope } from "./backend-interface.js";
import type { SkillSecretGrant } from "./token-issuer.js";

export interface SkillSecretsPolicy {
  /** Skill name — must match the `skill` field a skill self-declares when requesting a token. */
  name: string;
  /** Secret grants this skill is authorized for. */
  secrets: SecretGrantPolicy[];
}

export interface SecretGrantPolicy {
  /** Secret name as stored in the broker backend. */
  name: string;
  /** Requested access scope. Defaults to "read" if omitted. */
  scope?: SecretScope;
  /** TTL cap in seconds. Broker still clamps at MAX_TOKEN_TTL_SECONDS. */
  ttl?: number;
}

export interface BrokerPolicySection {
  /** Optional; absence means no grants. */
  skills?: SkillSecretsPolicy[];
}

/** Valid scope strings per v0.10.0. Keep in sync with `SecretScope`. */
const VALID_SCOPES = new Set<string>(["read", "rotate"]);

/**
 * Parse and validate the `skills:` section of a loaded policy object.
 * Returns a flat list of grants ready for `TokenIssuer.setGrant`. Throws
 * with a descriptive message on malformed input.
 */
export function parseBrokerPolicy(raw: unknown): SkillSecretGrant[] {
  if (raw === undefined || raw === null) return [];
  if (typeof raw !== "object") {
    throw new Error("Broker policy root must be an object");
  }
  const section = raw as BrokerPolicySection;
  if (section.skills === undefined) return [];
  if (!Array.isArray(section.skills)) {
    throw new Error("Broker policy `skills` must be an array");
  }

  const grants: SkillSecretGrant[] = [];
  const seen = new Set<string>();
  for (const [i, skillEntry] of section.skills.entries()) {
    if (!skillEntry || typeof skillEntry !== "object") {
      throw new Error(`skills[${i}] must be an object`);
    }
    const skillName = (skillEntry as SkillSecretsPolicy).name;
    if (typeof skillName !== "string" || skillName.length === 0) {
      throw new Error(`skills[${i}].name must be a non-empty string`);
    }
    if (!/^[A-Za-z0-9._\-:]+$/.test(skillName)) {
      throw new Error(
        `skills[${i}].name contains invalid characters: ${JSON.stringify(skillName)}`
      );
    }
    const secrets = (skillEntry as SkillSecretsPolicy).secrets;
    if (!Array.isArray(secrets)) {
      throw new Error(`skills[${i}].secrets must be an array`);
    }
    for (const [j, secretEntry] of secrets.entries()) {
      if (!secretEntry || typeof secretEntry !== "object") {
        throw new Error(`skills[${i}].secrets[${j}] must be an object`);
      }
      const sg = secretEntry as SecretGrantPolicy;
      if (typeof sg.name !== "string" || sg.name.length === 0) {
        throw new Error(
          `skills[${i}].secrets[${j}].name must be a non-empty string`
        );
      }
      if (!/^[A-Za-z0-9._\-:/]+$/.test(sg.name)) {
        throw new Error(
          `skills[${i}].secrets[${j}].name contains invalid characters: ${JSON.stringify(sg.name)}`
        );
      }
      const scope: SecretScope = sg.scope ?? "read";
      if (!VALID_SCOPES.has(scope)) {
        throw new Error(
          `skills[${i}].secrets[${j}].scope must be one of "read" | "rotate" (got ${JSON.stringify(sg.scope)})`
        );
      }
      if (sg.ttl !== undefined) {
        if (typeof sg.ttl !== "number" || !Number.isFinite(sg.ttl) || sg.ttl <= 0) {
          throw new Error(
            `skills[${i}].secrets[${j}].ttl must be a positive number of seconds`
          );
        }
      }
      const key = `${skillName}\u0000${sg.name}`;
      if (seen.has(key)) {
        throw new Error(
          `Duplicate grant for skill ${JSON.stringify(skillName)} secret ${JSON.stringify(sg.name)}`
        );
      }
      seen.add(key);
      grants.push({
        skill: skillName,
        secret: sg.name,
        scope,
        ttlSeconds: sg.ttl,
      });
    }
  }
  return grants;
}
